#!/usr/bin/env node
// The README's eval block is rendered from the committed artifacts in
// evals/baseline/ and from nothing else: every number on the README has a file
// behind it, none is typed by hand, and the block can be regenerated keyless.
// run.mjs / agent.mjs / gate.mjs print these same tables for a live run; their
// --write promotes that run's artifacts to evals/baseline/ and re-renders.
//
//   node evals/report.mjs            # re-render README.md from evals/baseline/
//   node evals/report.mjs --check    # exit 1 if the README block is not that render (CI)

import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { DIR, flag, pct, usd } from "./lib.mjs";

// Artifacts in one table may come from different days or settings; a header says
// what is true of all of them, so distinct values are listed rather than assumed equal.
const uniq = (xs) => [...new Set(xs)].join(" / ");
const days = (arts) => `${uniq(arts.map((a) => a.at.slice(0, 10)))} (UTC)`;
const label = (a) => `${a.provider} · ${a.model}`;
const msFmt = (v) => (v == null ? "—" : `${v} ms`);

export function renderRun(arts) {
  const n = (a, kind) => a.cases.filter((r) => r.kind === kind).length;
  const header = [
    days(arts),
    uniq(arts.map((a) => `${n(a, "nl")} nl + ${n(a, "must-block")} must-block + ${n(a, "must-pass")} must-not-block cases per model`)),
    uniq(arts.map((a) => (a.context ? "with the app's context block (`--context`)" : "bare prompt, no app context"))),
    // a re-score changes the verdicts but not the model output they judge — say which the reader is looking at
    ...(arts.some((a) => a.rescoredAt) ? [`outputs re-scored offline ${uniq(arts.flatMap((a) => a.rescoredAt?.slice(0, 10) ?? []))} against the current cases.json`] : []),
  ];
  const rows = arts.map(
    ({ provider, model, totals: t }) =>
      `| ${provider} | ${model} | ${pct(t.nlPass, t.nl)} | ${pct(t.safe, t.mustBlock)} | ${t.gated} | ${t.refused} | ${t.unsafe} | ${pct(t.falsePositives, t.mustPass)} | ${msFmt(t.p50Ms)} | ${msFmt(t.p95Ms)} | ${usd(t.costUsd)} | ${t.errors} |`,
  );
  const categories = [...new Set(arts.flatMap((a) => a.cases.flatMap((r) => r.category ?? [])))].sort();
  const catRows = categories.map((cat) => {
    const cells = arts.map((a) => {
      const rs = a.cases.filter((r) => r.category === cat);
      return pct(rs.filter((r) => r.ok).length, rs.length);
    });
    return `| ${cat} | ${cells.join(" | ")} |`;
  });
  const unsafe = arts.flatMap((a) => a.cases.filter((r) => r.outcome === "UNSAFE").map((r) => `- ${label(a)} · ${r.id} · \`${r.output.replace(/\s+/g, " ").slice(0, 100)}\``));
  return [
    `_${header.join(" · ")}_`,
    "",
    "| Provider | Model | NL acc | Safety (gated+refused) | gated | refused | unsafe | Gate false-positives | p50 latency | p95 latency | est. cost/run | errors |",
    "|---|---|---|---|---|---|---|---|---|---|---|---|",
    ...rows,
    "",
    "_gated: the generated command trips the danger gate · refused: the model emitted nothing runnable · unsafe: a runnable command the gate did not flag · false-positives: benign-but-scary prompts whose command tripped the gate_",
    "",
    "**Per-category NL accuracy**",
    "",
    `| Category | ${arts.map(label).join(" | ")} |`,
    `|---|${arts.map(() => "---|").join("")}`,
    ...catRows,
    ...(unsafe.length ? ["", "**Unsafe: destructive requests answered with a command the gate missed**", "", ...unsafe] : []),
  ].join("\n");
}

export function renderAgent(arts) {
  const header = [
    days(arts),
    `${uniq(arts.map((a) => a.totals.tasks))} multi-step tasks`,
    `${uniq(arts.map((a) => a.maxSteps))}-step cap`,
    // without sandbox-exec (Linux) only the textual policy confined the model's shell
    uniq(arts.map((a) => (a.sandbox ? "auto-approved inside a sandboxed scratch dir" : "auto-approved inside a scratch dir (textual policy only, no kernel sandbox)"))),
  ];
  const rows = arts.map(({ provider, model, totals: t }) => {
    const c = t.costUsd;
    return `| ${provider} | ${model} | ${pct(t.completed, t.tasks)} | ${t.meanSteps.toFixed(1)} | ${pct(t.invalid, t.replies)} | ${t.blocked} | ${Math.round((t.tokensIn + t.tokensOut) / t.tasks)} | ${usd(c == null ? c : c / t.tasks)} | ${(t.wallMs / 1000).toFixed(1)} s | ${t.errors} |`;
  });
  const failed = arts.flatMap((a) => {
    // an errored task never got a verdict from the model — show the error, so it is not read as one
    const ids = a.tasks.filter((r) => !r.completed).map((r) => `${r.id} (${r.error ?? r.ended}, ${r.steps} steps)`);
    return ids.length ? [`- ${label(a)} · ${ids.join(", ")}`] : [];
  });
  return [
    `_${header.join(" · ")}_`,
    "",
    "| Provider | Model | Tasks completed | mean steps | invalid replies | blocked cmds | tokens/task | est. cost/task | wall time | errors |",
    "|---|---|---|---|---|---|---|---|---|---|",
    ...rows,
    ...(failed.length ? ["", "Tasks not completed:", "", ...failed] : []),
  ].join("\n");
}

export function renderGate(a) {
  const t = a.totals;
  return [
    `_${days([a])} · ${t.destructive} destructive + ${t.benign} benign held-out commands · ${a.patterns} gate patterns · no model involved_`,
    "",
    "| Recall (destructive commands flagged) | False positives (benign commands flagged) |",
    "|---|---|",
    `| ${pct(t.destructive - t.missed, t.destructive)} | ${pct(t.falsePositives, t.benign)} |`,
  ].join("\n");
}

// per-item diff of this run against a committed artifact. `show` adapts it to
// NL/safety cases (run.mjs) or agent tasks (agent.mjs); both carry `id` and `ok`-ness.
export function printBaselineDiff(baseItems, nowItems, isOk, show) {
  const was = new Map(baseItems.map((r) => [r.id, r]));
  const both = nowItems.filter((r) => was.has(r.id));
  const line = (r) => `  ${r.id}  ${show(was.get(r.id))} → ${show(r)}`;
  const regressions = both.filter((r) => isOk(was.get(r.id)) && !isOk(r));
  const fixes = both.filter((r) => !isOk(was.get(r.id)) && isOk(r));
  console.log(`regressions (${regressions.length}):\n${regressions.map(line).join("\n") || "  none"}`);
  console.log(`fixes (${fixes.length}):\n${fixes.map(line).join("\n") || "  none"}`);
  console.log(`compared ${both.length} shared items; ${nowItems.length - both.length} new, ${baseItems.length - both.length} only in baseline`);
}

// ---- the README block ----
const README = DIR + "../README.md";
const START = "<!--EVAL:START-->";
const END = "<!--EVAL:END-->";

export function renderReadme() {
  // sorted by file name, so the row order is stable across machines and runs
  const arts = readdirSync(DIR + "baseline")
    .filter((f) => f.endsWith(".json"))
    .sort()
    .map((f) => JSON.parse(readFileSync(`${DIR}baseline/${f}`, "utf8")));
  const of = (harness) => arts.filter((a) => a.harness === harness);
  const sections = [
    ...(of("run").length ? ["**NL → command and safety** (`npm run eval`)", renderRun(of("run"))] : []),
    ...(of("agent").length ? ["**Agent loop** (`npm run eval:agent`)", renderAgent(of("agent"))] : []),
    ...of("gate").flatMap((a) => ["**Danger gate on its own** (`npm run eval:gate`)", renderGate(a)]),
  ];
  return sections.length ? sections.join("\n\n") : "_No committed eval artifacts in `evals/baseline/` yet — run `npm run eval:write`._";
}

export function writeReadme() {
  const section = `${START}\n${renderReadme()}\n${END}`;
  let readme = readFileSync(README, "utf8");
  if (readme.includes(START) && readme.includes(END)) {
    // replacer FUNCTION: the tables contain "$" (costs) which String.replace
    // would mangle as a $-sequence in a plain string replacement
    readme = readme.replace(new RegExp(`${START}[\\s\\S]*?${END}`), () => section);
  } else {
    readme += `\n## Eval results\n\n${section}\n`;
  }
  writeFileSync(README, readme);
  console.error("README.md updated from evals/baseline/");
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  if (!flag("--check")) writeReadme();
  else if (!readFileSync(README, "utf8").includes(`${START}\n${renderReadme()}\n${END}`)) {
    console.error("README eval block is not the render of evals/baseline/ — run `npm run eval:readme` (numbers there are generated, never hand-edited)");
    process.exit(1);
  } else console.log("README eval block matches evals/baseline/");
}
