#!/usr/bin/env node
// Agent-loop eval: multi-step tasks, each in a fresh scratch dir, driven by the
// same loop the app runs (agent_loop in src-tauri/src/lib.rs) — same system
// prompt (extracted, not copied), same transcript, same reply parsing, same
// 12-step cap and 2000-char output truncation. Success is decided by declarative
// checks on the scratch dir, never by the model saying DONE.
//
// Usage:
//   node evals/agent.mjs                       # every keyed provider, every task
//   node evals/agent.mjs --provider groq --limit 3
//   node evals/agent.mjs --provider groq --models openai/gpt-oss-120b,openai/gpt-oss-20b
//   node evals/agent.mjs --baseline evals/baseline/agent-groq-openai-gpt-oss-120b.json   # per-task diff
//   node evals/agent.mjs --write               # promote to evals/baseline/, re-render the README block
//   node evals/agent.mjs --mock                # scripted fake model, no key, no network
//   node evals/agent.mjs --mock --selftest     # …and assert the expected outcomes (CI)
//
// SANDBOX: this executes model-written shell on a real machine with every step
// auto-approved, so anything that leaves the scratch dir is refused (blockReason)
// and, on macOS, the shell also runs under a sandbox-exec profile that denies
// network, writes outside the scratch dir, and reads of the real home directory.

import { spawnSync } from "node:child_process";
import { closeSync, existsSync, mkdirSync, mkdtempSync, openSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { isDangerous } from "./danger.mjs";
import { DIR, argValue, artifactName, costUsd, failIfAllErrored, flag, generate, loadProviders, oneLine, sha256, stripFences, writeArtifact } from "./lib.mjs";
import { printBaselineDiff, renderAgent, writeReadme } from "./report.mjs";
import { AI_AGENT } from "./rust-source.mjs";

const MAX_STEPS = 12; // `for step in 1..=12` in agent_loop
const STEP_TIMEOUT_MS = 20000; // AGENT_STEP_TIMEOUT
const OUTPUT_CHARS = 2000; // truncate_chars(&output, 2000)

// port of parse_agent_reply. TOOL: is always invalid here — the eval has no MCP
// servers, so the system prompt never offers tools.
function parseAgentReply(reply) {
  reply = reply.trim();
  const after = (prefix) => (reply.slice(0, prefix.length).toUpperCase() === prefix ? reply.slice(prefix.length) : null);
  if (after("DONE:") != null) return { kind: "done", text: after("DONE:").trim() };
  if (after("TOOL:") != null) return { kind: "invalid", text: reply };
  const cmd = oneLine(stripFences(after("RUN:") ?? reply));
  return cmd ? { kind: "run", text: cmd } : { kind: "done", text: "no command returned" };
}

// Top-level directories a real absolute path starts with, on either OS. Fixed on purpose —
// see the note in blockReason. Superset of macOS and Linux; unknown roots are treated as not
// a path, which is why `awk '/ERROR/'` still runs.
const SYSTEM_ROOTS = new Set(
  ("bin boot dev etc home lib lib64 media mnt opt private proc root run sbin srv sys tmp usr var " +
   "Applications Library System Users Volumes data").split(" ").map((d) => `/${d}`),
);

// Why a command may not run, or null. Textual, so deliberately over-strict
// (`git log HEAD~1` and `{1..3}` are refused too): a false block costs the model
// one step, a false allow touches the user's machine.
// ponytail: string matching can't see through `eval`/variable tricks — the
// sandbox-exec profile below is the backstop; a container/VM is the upgrade.
function blockReason(cmd, scratch) {
  if (isDangerous(cmd)) return "danger gate";
  if (/\bsudo\b/.test(cmd)) return "sudo";
  if (/~|\$\{?HOME\b/.test(cmd)) return "home directory reference";
  if (cmd.includes("..")) return "parent directory reference";
  // a `/` that starts a word: an absolute path (not src/a.c, s/x/y/, #!/bin/sh)
  for (const [, p] of cmd.matchAll(/(?:^|[\s=<>('"`:,{])(\/[^\s'"`;|&<>(){},:]*)/g)) {
    if (p === "/dev/null" || p === scratch || p.startsWith(scratch + "/")) continue;
    // awk '/ERROR/' looks like a path. Discriminate on a FIXED list of system roots, not on
    // what exists on this host: existsSync made the verdict machine-dependent, so
    // `/private/tmp/...` was blocked on macOS and allowed on Linux, which is exactly the kind
    // of difference a security control must not have. Globs/vars could build a path.
    const top = "/" + p.split("/")[1];
    if (top === "/" || SYSTEM_ROOTS.has(top) || /[*?[\]$\\]/.test(p)) return "absolute path outside the scratch dir";
  }
  return null;
}

const HAS_SANDBOX =
  process.platform === "darwin" && spawnSync("/usr/bin/sandbox-exec", ["-p", "(version 1)(allow default)", "/usr/bin/true"]).status === 0;
if (!HAS_SANDBOX) console.error("note: sandbox-exec unavailable — commands are confined by the textual policy only");

// zsh -f -c in the scratch dir, stdout+stderr interleaved like a pty, with an
// env that carries no secrets (the parent's may hold API keys).
function sh(cmd, scratch) {
  const q = JSON.stringify;
  const profile =
    `(version 1)(allow default)(deny network*)(deny file-write*)(deny file-read* (subpath ${q(os.homedir())}))` +
    `(allow file-read* file-write* (subpath ${q(scratch)}))(allow file-write* (literal "/dev/null") (literal "/dev/tty") (literal "/dev/dtracehelper"))`;
  const log = path.join(scratch, "../output.log");
  const fd = openSync(log, "w");
  const r = spawnSync(HAS_SANDBOX ? "/usr/bin/sandbox-exec" : "/bin/zsh", [...(HAS_SANDBOX ? ["-p", profile, "/bin/zsh"] : []), "-f", "-c", cmd], {
    cwd: scratch,
    stdio: ["ignore", fd, fd],
    timeout: STEP_TIMEOUT_MS, // ponytail: kills zsh only; a backgrounded grandchild outlives it (still sandboxed)
    killSignal: "SIGKILL",
    env: {
      PATH: "/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin:/usr/local/bin",
      HOME: scratch,
      TMPDIR: scratch,
      LANG: "en_US.UTF-8",
      // HOME has no .gitconfig; without an identity every `git commit` task would
      // spend steps on setup the app's real shell never needs
      GIT_AUTHOR_NAME: "eval",
      GIT_AUTHOR_EMAIL: "eval@example.com",
      GIT_COMMITTER_NAME: "eval",
      GIT_COMMITTER_EMAIL: "eval@example.com",
      GIT_CONFIG_NOSYSTEM: "1",
    },
  });
  closeSync(fd);
  return { code: r.status ?? -1, out: readFileSync(log, "utf8") };
}

function checkPasses(c, scratch) {
  if (c.exists) return existsSync(path.join(scratch, c.exists));
  if (c.contains) {
    const file = path.join(scratch, c.contains[0]);
    return existsSync(file) && readFileSync(file, "utf8").includes(c.contains[1]);
  }
  if (c.cmd) return sh(c.cmd, scratch).code === 0; // sandboxed too: checks may execute model-written files
  throw new Error(`unknown check ${JSON.stringify(c)}`);
}

// `reply(transcript)` → { text, usage }: a provider call, or the task's canned script
async function runTask(t, reply) {
  const base = realpathSync(mkdtempSync(path.join(os.tmpdir(), "tachyon-agent-")));
  const scratch = path.join(base, "work"); // one level down so output.log stays out of the model's `ls`
  const r = { id: t.id, completed: false, ended: "step limit", steps: 0, invalid: 0, blocked: 0, tokensIn: 0, tokensOut: 0, log: [] };
  const t0 = performance.now();
  try {
    mkdirSync(scratch);
    for (const [file, content] of Object.entries(t.setup ?? {})) {
      mkdirSync(path.dirname(path.join(scratch, file)), { recursive: true });
      writeFileSync(path.join(scratch, file), content);
    }
    r.precheck = t.checks.every((c) => checkPasses(c, scratch)); // true = the task is already done before step 1

    // transcript seed as in agent_loop: shell_context_line + journal_context of a fresh session
    let transcript = `Task: ${t.task}\n\nContext:\ncwd: ${scratch}\ngit: none\n(no recent commands)\n`;
    for (let step = 1; step <= MAX_STEPS; step++) {
      let res;
      try {
        res = await reply(transcript);
      } catch (e) {
        r.ended = "error";
        r.error = e.message;
        break;
      }
      r.steps = step;
      r.tokensIn += res.usage.in ?? 0;
      r.tokensOut += res.usage.out ?? 0;
      const action = parseAgentReply(res.text);
      const entry = { step, reply: res.text, action: action.kind };
      r.log.push(entry);
      if (action.kind === "done") {
        r.ended = "done";
        r.summary = action.text;
        break;
      }
      if (action.kind === "invalid") {
        r.invalid++;
        transcript += `\nInvalid tool call: ${action.text}\n`;
        continue;
      }
      const cmd = action.text;
      entry.blocked = blockReason(cmd, scratch);
      let code = 126,
        out = "command blocked by eval sandbox";
      if (entry.blocked) r.blocked++;
      else {
        ({ code, out } = sh(cmd, scratch));
        out = code === -1 && out === "" ? "(no exit marker)" : [...out].slice(0, OUTPUT_CHARS).join("");
      }
      entry.code = code;
      transcript += `\nCommand: ${cmd}\nExit code: ${code}\nOutput:\n${out}\n`;
      console.error(`  ${step}. ${entry.blocked ? `BLOCKED (${entry.blocked})` : `exit ${code}`}  ${cmd.replace(/\s+/g, " ").slice(0, 80)}`);
    }
    r.completed = t.checks.every((c) => checkPasses(c, scratch));
    r.transcript = transcript;
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
  r.ms = Math.round(performance.now() - t0);
  console.error(`${r.completed ? "pass" : "FAIL"}  ${t.id}  ${r.steps} steps, ${r.ended}${r.error ? `: ${r.error}` : ""}`);
  return r;
}

const runMock = (t) => {
  const script = [...(t.mock ?? [])];
  return runTask(t, async () => ({ text: script.shift() ?? "DONE: mock script exhausted", usage: {} }));
};

// ---- run ----
let tasks = JSON.parse(readFileSync(DIR + "agent-tasks.json", "utf8"));
const limit = Number(argValue("--limit"));
if (limit > 0) tasks = tasks.slice(0, limit);

const mock = flag("--mock");
if (flag("--selftest") && !mock) throw new Error("--selftest needs --mock");
// --write promotes this run over the committed baseline and onto the README:
// never a partial run, never the scripted mock
if (flag("--write") && (mock || argValue("--limit"))) {
  console.error("--write refused with --mock or --limit: the baseline and the README must hold a full, real run");
  process.exit(1);
}
const bench = mock ? [{ id: "mock", model: "scripted" }] : loadProviders("For a keyless run: node evals/agent.mjs --mock");

// Baselines get committed to a public repo, and a transcript holds real command
// output — `ls -l` prints the local account name. Replaced per string value (not
// on the serialized JSON), so an escape like \n can never be mangled.
const ME = new RegExp(`\\b${os.userInfo().username.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\b`, "g");
const scrubUser = (data) => JSON.parse(JSON.stringify(data, (_, v) => (typeof v === "string" ? v.replace(ME, "user") : v)));

const arts = []; // artifact-shaped, one per benchmarked model — what report.mjs renders
let mockRun;
for (const p of bench) {
  console.error(`\n=== ${p.id} (${p.model}) — ${tasks.length} tasks ===`);
  const runs = [];
  for (const t of tasks) runs.push(await (mock ? runMock(t) : runTask(t, (transcript) => generate(p, AI_AGENT, transcript))));
  mockRun = runs;

  const sum = (k) => runs.reduce((a, r) => a + r[k], 0);
  const n = runs.length;
  const totals = {
    tasks: n,
    completed: runs.filter((r) => r.completed).length,
    meanSteps: sum("steps") / n,
    replies: sum("steps"),
    invalid: sum("invalid"),
    blocked: sum("blocked"),
    errors: runs.filter((r) => r.error).length,
    tokensIn: sum("tokensIn"),
    tokensOut: sum("tokensOut"),
    costUsd: costUsd(p.model, sum("tokensIn"), sum("tokensOut")),
    wallMs: sum("ms"),
  };
  // a run where every task errored is not a score: keep it for debugging, never promote it
  const noResult = failIfAllErrored(`${p.id} (${p.model})`, totals.errors, n);
  // maxSteps / sandbox: the conditions the completion rate was earned under
  const data = { at: new Date().toISOString(), harness: "agent", provider: p.id, model: p.model, promptSha256: sha256(AI_AGENT), maxSteps: MAX_STEPS, sandbox: HAS_SANDBOX, totals, tasks: runs };
  // written per model as it finishes, so a later model's failure cannot cost this one
  arts.push(mock ? data : writeArtifact(`agent-${artifactName(p.id, p.model)}`, scrubUser(data), flag("--write") && !noResult));
}

console.log("\n" + renderAgent(arts));

// ---- --baseline: per-task diff against a committed artifact ----
const baselinePath = argValue("--baseline");
if (baselinePath) {
  const base = JSON.parse(readFileSync(baselinePath, "utf8"));
  // the same model if this run has it; else the provider's row, with the mismatch noted below
  const now = arts.find((a) => a.provider === base.provider && a.model === base.model) ?? arts.find((a) => a.provider === base.provider);
  if (base.harness !== "agent" || !now) {
    console.error(`--baseline: ${baselinePath} is ${base.harness !== "agent" ? "not an agent.mjs artifact" : `for provider "${base.provider}", which is not in this run`}`);
    process.exitCode = 1;
  } else {
    console.log(`\n${now.provider} (${now.model}) vs baseline ${baselinePath} (${base.model}, ${base.at})`);
    if (base.promptSha256 !== now.promptSha256) console.log("note: AI_AGENT changed since the baseline");
    if (base.model !== now.model) console.log("note: model differs from the baseline");
    printBaselineDiff(base.tasks, now.tasks, (r) => r.completed, (r) => `${r.completed ? "pass" : "FAIL"} (${r.ended}, ${r.steps} steps)`);
  }
}

if (flag("--write")) writeReadme();

// ---- --mock --selftest: the loop, parser, sandbox policy and checks, asserted ----
if (flag("--selftest")) {
  let bad = 0;
  const check = (ok, label) => {
    if (!ok) bad++;
    console.log(`${ok ? "PASS" : "FAIL"}  ${label}`);
  };
  const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);

  // hand-copied from the parse_agent_reply unit tests in lib.rs (not extractable:
  // they are assert_eq! calls, not a literal list)
  for (const [reply, want] of [
    ["DONE: all set", { kind: "done", text: "all set" }],
    ["  done: finished  ", { kind: "done", text: "finished" }],
    ["DONE:", { kind: "done", text: "" }],
    ["RUN: ls -la", { kind: "run", text: "ls -la" }],
    ["run: git status", { kind: "run", text: "git status" }],
    ["echo hi", { kind: "run", text: "echo hi" }],
    ["RUN: ```zsh\nls\n```", { kind: "run", text: "ls" }],
    ["", { kind: "done", text: "no command returned" }],
    ["RUN: ```\n```", { kind: "done", text: "no command returned" }],
    // one_line: lines 2+ must not hide behind line 1 of a single-line approval bar
    ["RUN: ls\nrm -rf ~", { kind: "run", text: "ls; rm -rf ~" }],
    ['TOOL: srv.echo {"a":1}', { kind: "invalid", text: 'TOOL: srv.echo {"a":1}' }],
  ])
    check(same(parseAgentReply(reply), want), `parse   ${JSON.stringify(reply)}`);

  const S = "/private/tmp/scratch/work";
  for (const cmd of ["rm -rf build", "sudo ls", "ls ~", "cat $HOME/x", "echo ${HOME}", "cd ..", "cat /etc/passwd", "cat '/etc/passwd'", "ls /", "echo hi > /tmp/x", "x=/etc; ls $x", "cat /e*c/passwd", "cat /private/tmp/scratch/other", "cat /tmp/other/x", "cat /home/someone/.ssh/id_rsa", "cat /Users/someone/.aws/credentials"])
    check(blockReason(cmd, S) != null, `blocks  ${cmd}`);
  for (const cmd of ["ls -la", "cat a.txt > /dev/null", "awk '/ERROR/ {n++} END {print n}' app.log", "sed 's/a/b/' f.txt", `cat ${S}/a.txt`, "printf '#!/bin/sh\\n' > x.sh", "tar -czf src.tar.gz src/", "./hello.sh"])
    check(blockReason(cmd, S) == null, `allows  ${cmd}`);
  // the verdict must not depend on which OS is running the harness
  check(blockReason("cat /private/tmp/scratch/other", S) === blockReason("cat /tmp/other/x", S), "policy  macOS- and Linux-shaped paths are judged the same");

  for (const r of mockRun) {
    check(!r.precheck, `task    ${r.id}: checks fail before the agent runs`);
    check(r.completed && r.ended === "done", `task    ${r.id}: mock script completes it`);
  }
  const total = (k) => mockRun.reduce((a, r) => a + r[k], 0);
  check(total("invalid") === 1, "loop    exactly one invalid reply (the TOOL: call) across the mock scripts");
  check(total("blocked") === 1, "loop    exactly one blocked command across the mock scripts");
  const blockedRun = mockRun.find((r) => r.blocked);
  check(blockedRun?.transcript.includes("Exit code: 126\nOutput:\ncommand blocked by eval sandbox\n"), "loop    a blocked command is reported back, not run");

  const cap = await runMock({ id: "selftest-step-cap", task: "never finishes", checks: [{ exists: "never" }], mock: ["RUN: seq 1 3000", ...Array(20).fill("RUN: true")] });
  check(cap.steps === MAX_STEPS && cap.ended === "step limit" && !cap.completed, `loop    stops at the ${MAX_STEPS}-step cap and fails the task`);
  check(cap.transcript.includes("\n400\n") && !cap.transcript.includes("\n600\n"), `loop    output truncated to ${OUTPUT_CHARS} chars`);
  check(cap.transcript.startsWith("Task: never finishes\n\nContext:\ncwd: /") && cap.transcript.includes("\nCommand: true\nExit code: 0\nOutput:\n\n"), "loop    transcript format matches agent_loop");

  if (HAS_SANDBOX) {
    const outside = path.join(os.tmpdir(), `tachyon-escape-${process.pid}`);
    const esc = await runMock({ id: "selftest-escape", task: "", checks: [{ exists: "inside" }], mock: [`RUN: touch inside; p=$(printf '\\x2f'); touch "$\{p}${outside.slice(1)}"`] });
    check(esc.completed && esc.transcript.includes("Operation not permitted") && !existsSync(outside), "sandbox a write that slips past the textual policy is denied by the kernel");
    rmSync(outside, { force: true });
  }

  console.log(bad === 0 ? "\nagent self-test OK" : `\nagent self-test FAILED: ${bad} check(s)`);
  process.exit(bad === 0 ? 0 : 1);
}
