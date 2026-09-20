#!/usr/bin/env node
// How good is the danger gate on its own? Runs is_dangerous (patterns extracted
// from lib.rs) over a held-out corpus of destructive and benign commands and
// prints recall, false-positive rate, and every miss. Keyless.
//
// Misses do NOT fail this script: the gate is a warn-only substring scan by
// design, and low recall is a finding to report, not a build breakage. It exits
// non-zero only when the corpus or the extraction is broken.
//
//   node evals/gate.mjs            # print; write evals/results/<timestamp>-gate.json
//   node evals/gate.mjs --write    # …and promote it to evals/baseline/gate.json + re-render the README
import { existsSync, readFileSync } from "node:fs";
import { isDangerous } from "./danger.mjs";
import { DIR, flag, pct, sha256, writeArtifact } from "./lib.mjs";
import { writeReadme } from "./report.mjs";
import { DANGER_PATTERNS } from "./rust-source.mjs";

const { destructive, benign } = JSON.parse(readFileSync(new URL("gate-corpus.json", import.meta.url), "utf8"));
const all = [destructive, benign].flat();
if (!(destructive?.length && benign?.length) || all.some((c) => typeof c !== "string" || !c.trim()) || new Set(all).size !== all.length) {
  console.error("gate-corpus.json: need non-empty `destructive` and `benign` arrays of unique, non-blank strings");
  process.exit(1);
}

const missed = destructive.filter((c) => !isDangerous(c));
const flagged = benign.filter(isDangerous);
console.log(`recall           ${pct(destructive.length - missed.length, destructive.length)}  destructive commands flagged`);
console.log(`false positives  ${pct(flagged.length, benign.length)}  benign commands flagged`);
console.log(`\nmissed (destructive, not flagged):\n${missed.map((c) => `  ${c}`).join("\n") || "  none"}`);
console.log(`\nfalse positives (benign, flagged):\n${flagged.map((c) => `  ${c}`).join("\n") || "  none"}`);

// patternsSha256: the pattern list these numbers were measured on
const patternsSha256 = sha256(JSON.stringify(DANGER_PATTERNS));
writeArtifact(
  "gate",
  {
    harness: "gate",
    patterns: DANGER_PATTERNS.length,
    patternsSha256,
    totals: { destructive: destructive.length, missed: missed.length, benign: benign.length, falsePositives: flagged.length },
    missed,
    falsePositives: flagged,
  },
  flag("--write"),
);
if (flag("--write")) writeReadme();

// The README's gate numbers are the committed artifact's, not this run's: say so
// when lib.rs has moved on. A note, not a failure — whoever edits DANGER_PATTERNS
// should not have their build broken by a README table.
const committed = `${DIR}baseline/gate.json`;
if (existsSync(committed) && JSON.parse(readFileSync(committed, "utf8")).patternsSha256 !== patternsSha256)
  console.error("\nnote: DANGER_PATTERNS changed since evals/baseline/gate.json — `npm run eval:gate -- --write` refreshes the README's gate numbers");
