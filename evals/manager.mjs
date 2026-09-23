#!/usr/bin/env node
// The manager's keyless self-test. evals/manager-runs.json is the spec: scripted board changes
// and scripted model replies, each with the log and the report the run must end with. The
// executor is Rust — `the_scripted_runs` in src-tauri/src/manager.rs drives the real
// `Supervisor` over the file — because a JS port of the state machine would test the port.
// This script checks the file still says what it must, then runs that test.
//
//   node evals/manager.mjs --mock --selftest
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { flag } from "./lib.mjs";

if (!(flag("--mock") && flag("--selftest"))) {
  console.error("usage: node evals/manager.mjs --mock --selftest  (a live manager run needs the app)");
  process.exit(1);
}

const read = (rel) => readFileSync(new URL(rel, import.meta.url), "utf8");
const { runs } = JSON.parse(read("manager-runs.json"));
const src = read("../src-tauri/src/manager.rs").split("#[cfg(test)]")[0];

// The budgets are read out of manager.rs, so a budget added there without a run here fails.
const fields = /pub\(crate\) struct Budgets \{([\s\S]*?)\n\}/.exec(src)?.[1];
const defaults = /Budgets \{ (max_tasks: \d+[^}]*) \}/.exec(src)?.[1];
if (!fields || !defaults) throw new Error("manager.rs: cannot find Budgets or its defaults — update evals/manager.mjs");
const DEFAULT = Object.fromEntries(defaults.split(", ").map((kv) => kv.split(": ")).map(([k, v]) => [k, Number(v)]));
const KEYS = [...fields.matchAll(/pub\(crate\) (\w+):/g)].map((m) => m[1]);
if (KEYS.join() !== Object.keys(DEFAULT).join()) throw new Error(`Budgets fields ${KEYS} and defaults ${Object.keys(DEFAULT)} disagree`);

const STATES = ["open", "claimed", "done", "failed", "cancelled"];
const REPORT = /^finished: (\d+) verified, (\d+) unverified, (\d+) dropped; \d+ model calls; (\d+)m(\d\d)s elapsed; stopped by: (.+)$/;
let bad = 0;
const check = (ok, what) => {
  console.log(`${ok ? "ok  " : "FAIL"}  ${what}`);
  if (!ok) bad++;
};

const covered = new Map();
for (const r of runs) {
  const name = r.name;
  const at = r.script.map((s) => s.at);
  const [, verified, unverified, dropped, min, sec, stoppedBy] = REPORT.exec(r.report) ?? [];
  check(
    Object.keys(r.budgets).every((k) => KEYS.includes(k) && Number.isInteger(r.budgets[k]) && r.budgets[k] >= 0) &&
      at.every((t, i) => Number.isInteger(t) && (i === 0 || t > at[i - 1])) &&
      r.script.every((s) => (s.set ?? []).every(([id, state, who]) => /^t_\d+$/.test(id) && STATES.includes(state) && who)),
    `shape   ${name}`,
  );
  // the report is the run's last word, at its last step, and accounts for every planned task
  check(
    stoppedBy !== undefined && Number(min) * 60 + Number(sec) === at.at(-1) && +verified + +unverified + +dropped === r.tasks,
    `report  ${name}`,
  );
  for (const c of r.covers) covered.set(c, r);
  // a tripped budget stops the run by name, or drops the task that tripped it and says so
  for (const key of r.covers.filter((c) => c.startsWith("budget:")).map((c) => c.slice(7))) {
    const named = stoppedBy?.includes(`the ${key} budget`) || (stoppedBy === "completed" && r.log.some((l) => l.includes(`the ${key} budget`)));
    check(named, `budget  ${key} is named where "${name}" ends`);
  }
}

for (const key of KEYS) check(covered.has(`budget:${key}`), `covers  budget ${key}`);

const nothing = covered.get("done-having-run-nothing");
check(
  nothing !== undefined &&
    nothing.script.some((s) => s.set?.some(([, state]) => state === "done")) &&
    nothing.script.every((s) => s.check === undefined || s.check !== 0) &&
    / 0 verified, [1-9]\d* unverified,/.test(nothing.report),
  "covers  a worker that reports done having run nothing ends unverified",
);

const never = covered.get("never-claimed");
const max = never && { ...DEFAULT, ...never.budgets }.max_reassignments;
check(
  never !== undefined &&
    never.script.every((s) => !s.set) &&
    never.log.filter((l) => l.includes(" put out again as ")).length === max &&
    never.log.at(-1).endsWith(`dropped: the max_reassignments budget (${max}) is spent`),
  `covers  a never-claiming worker is put out again exactly max_reassignments (${max}) times, then dropped`,
);

// The executor. `--exact` with a filter that matches nothing still exits 0, hence "1 passed".
const test = "manager::tests::the_scripted_runs";
const cargo = spawnSync("cargo", ["test", "--lib", test, "--", "--exact"], {
  cwd: new URL("../src-tauri/", import.meta.url),
  encoding: "utf8",
});
const out = `${cargo.stdout ?? ""}${cargo.stderr ?? ""}`;
const ran = cargo.status === 0 && / 1 passed; 0 failed/.test(out);
if (!ran) console.log(cargo.error ? String(cargo.error) : out);
check(ran, `run     ${test} over ${runs.length} scripted runs`);

process.exit(bad === 0 ? 0 : 1);
