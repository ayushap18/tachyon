// loadProviders' --route resolution, against a synthetic providers.json in a temp HOME.
// No network, no keys, no deps. Every case runs in a CHILD process: lib.mjs freezes
// process.argv at import time, so flags cannot be varied in-process.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, test } from "node:test";

const KEY = "sk-fixture-must-never-be-printed";
const CONFIG = {
  active: "groq",
  providers: [
    { id: "groq", kind: "openai", base_url: "https://api.groq.com/openai/v1", model: "m-groq", key: KEY },
    { id: "claude", kind: "anthropic", model: "m-claude", key: KEY },
    { id: "keyless", kind: "openai", base_url: "https://example.invalid/v1", model: "m-keyless" },
  ],
  routes: {
    command: { provider: "claude", model: "m-route" },
    agent: { provider: "gone" }, // dangling: `/remove claude` cannot reach a hand-edited id
    explain: { provider: "keyless" },
  },
};

const home = mkdtempSync(path.join(os.tmpdir(), "tachyon-evals-"));
mkdirSync(path.join(home, ".config/tachyon"), { recursive: true });
writeFileSync(path.join(home, ".config/tachyon/providers.json"), JSON.stringify(CONFIG));
const probe = path.join(home, "probe.mjs");
writeFileSync(
  probe,
  `import { loadProviders } from ${JSON.stringify(new URL("./lib.mjs", import.meta.url).href)};\n` +
    `console.log(JSON.stringify(loadProviders("hint").map((p) => ({ id: p.id, model: p.model }))));\n`,
);
after(() => rmSync(home, { recursive: true, force: true }));

const seen = []; // every byte the child wrote, for the no-key-printed assertion
// Deliberately NOT process.env: GROQ_API_KEY / ANTHROPIC_API_KEY in the developer's
// shell would inject real providers and make these assertions machine-dependent.
function run(...args) {
  const r = spawnSync(process.execPath, [probe, ...args], {
    encoding: "utf8",
    env: { PATH: process.env.PATH, HOME: home, XDG_CONFIG_HOME: path.join(home, ".config") },
  });
  seen.push(r.stdout, r.stderr);
  return { ...r, bench: r.stdout.trim() ? JSON.parse(r.stdout) : null };
}

test("route flag resolves the routed provider and model", () => {
  const r = run("--route", "command");
  assert.equal(r.status, 0);
  assert.deepEqual(r.bench, [{ id: "claude", model: "m-route" }]);
  assert.equal(r.stderr, "");
});

test("route flag falls back to active when unset or dangling", () => {
  const unset = run("--route", "nosuchtask");
  assert.equal(unset.status, 0);
  assert.deepEqual(unset.bench, [{ id: "groq", model: "m-groq" }]);
  assert.match(unset.stderr, /unset — using active groq/);

  // dangling must land on active with active's OWN model, not the dead route's
  const dangling = run("--route", "agent");
  assert.equal(dangling.status, 0);
  assert.deepEqual(dangling.bench, [{ id: "groq", model: "m-groq" }]);
  assert.match(dangling.stderr, /provider gone is gone — using active groq/);
});

test("route flag is exclusive with --provider", () => {
  const r = run("--route", "command", "--provider", "groq");
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /exclusive/);
});

test("route to a keyless provider fails rather than silently benchmarking another", () => {
  const r = run("--route", "explain");
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /keyless has no key/);
});

test("no key is printed", () => {
  assert.ok(seen.length, "no output captured — the cases above must run first");
  for (const out of seen) assert.ok(!out.includes(KEY), "a provider key reached stdout/stderr");
});
