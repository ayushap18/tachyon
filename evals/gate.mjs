#!/usr/bin/env node
// How good is the danger gate on its own? Runs is_dangerous (patterns extracted
// from lib.rs) over a held-out corpus of destructive and benign commands and
// prints recall, false-positive rate, and every miss. Keyless.
//
// Misses do NOT fail this script: the gate is a warn-only substring scan by
// design, and low recall is a finding to report, not a build breakage. It exits
// non-zero only when the corpus or the extraction is broken.
import { readFileSync } from "node:fs";
import { isDangerous } from "./danger.mjs";
import { pct } from "./lib.mjs";

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
