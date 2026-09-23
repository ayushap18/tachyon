#!/usr/bin/env node
// JS port of redact() in src-tauri/src/lib.rs, run over evals/redaction-corpus.json — the
// same file lib.rs's `redact_meets_the_corpus` reads, so a shape changed in one language and
// not the other turns one of the two red. Keyless; exits non-zero on any mismatch, because
// unlike the danger gate the corpus is the spec, not a benchmark.
//
//   npm run eval:redact
import { readFileSync } from "node:fs";

const PREFIXES = [
  ["sk-ant-", "anthropic"], ["sk-", "openai"], ["gsk_", "groq"], ["github_pat_", "github"], ["ghp_", "github"],
  ["gho_", "github"], ["ghs_", "github"], ["ghu_", "github"], ["ghr_", "github"], ["xoxb-", "slack"],
  ["xoxp-", "slack"], ["xoxa-", "slack"], ["xapp-", "slack"], ["AIza", "google"],
];
const NAMES = [
  ["password", "password"], ["passwd", "password"], ["token", "token"], ["secret", "secret"], ["secret_key", "secret"],
  ["secret_access_key", "secret"], ["api_key", "api_key"], ["apikey", "api_key"],
];
const alnum = (c) => /^[A-Za-z0-9]$/.test(c ?? "");
const tok = (c) => alnum(c) || c === "_" || c === "-";
const digit = (s) => /[0-9]/.test(s);
const ws = (c) => " \t\n\f\r".includes(c);
const runEnd = (s, i, ok) => {
  while (i < s.length && ok(s[i])) i++;
  return i;
};
const runBack = (s, end, ok) => {
  let n = 0;
  while (end - n > 0 && ok(s[end - n - 1])) n++;
  return n;
};

// word_start in lib.rs: a word start, or the tail of an escape glued to one.
const wordStart = (s, i) => {
  const pre = s.slice(0, i);
  return i === 0 || !alnum(s[i - 1]) || /(\\[ntr]|\(B|%[0-9A-Fa-f]{2}|\[[0-9;:]*m)$/.test(pre);
};

function secretAt(s, i, floor) {
  const rest = s.slice(i);
  if (ws(s[i])) return null;
  if (wordStart(s, i)) {
    for (const [p, kind] of PREFIXES) {
      if (!rest.startsWith(p)) continue;
      const end = runEnd(s, i + p.length, tok);
      if (end - i - p.length >= 16 && digit(s.slice(i + p.length, end))) return [i, end, kind];
    }
    if (rest.startsWith("AKIA") || rest.startsWith("ASIA")) {
      const end = runEnd(s, i + 4, (c) => /^[A-Z0-9]$/.test(c));
      if (end - i - 4 >= 16) return [i, end, "aws"];
    }
    if (rest.startsWith("eyJ")) {
      let end = runEnd(s, i, (c) => tok(c) || c === ".");
      while (s[end - 1] === ".") end--;
      const parts = s.slice(i, end).split(".");
      if (parts.length === 3 && parts.every(Boolean)) return [i, end, "jwt"];
    }
  }
  const pem = (at) => {
    const close = s.indexOf("-----", at);
    if (close < 0) return null;
    const header = s.slice(at, close);
    return !header.includes("\n") && header.includes("PRIVATE KEY") ? close + 5 : null;
  };
  if (rest.startsWith("-----BEGIN ")) {
    const headerEnd = pem(i + 11);
    if (headerEnd !== null) {
      const e = s.indexOf("-----END ", headerEnd);
      return [i, (e >= 0 ? pem(e + 9) : null) ?? s.length, "private-key"];
    }
  }
  if (rest.startsWith("-----END ")) {
    const end = pem(i + 9);
    if (end !== null) {
      let start = i;
      while (start > floor && s[start - 1] === "\n") {
        const nl = s.lastIndexOf("\n", start - 2);
        const lineStart = nl >= floor ? nl + 1 : floor;
        const line = s.slice(lineStart, start - 1).replace(/\r$/, "");
        if (!line || !/^[A-Za-z0-9+/=]+$/.test(line)) break;
        start = lineStart;
      }
      return [start, end, "private-key"];
    }
  }
  if (s[i] === "$") return null;
  const pre = s.slice(0, i);
  const named = pre.slice(0, i - runBack(s, i, (c) => c === " "));
  const spaces = i - named.length;
  if (named.toLowerCase().endsWith("authorization:")) return [i, runEnd(s, i, (c) => !"\r\n\"'".includes(c)), "authorization"];
  if (spaces > 0 && named.toLowerCase().endsWith("bearer") && !alnum(named[named.length - 7])) {
    const end = runEnd(s, i, (c) => tok(c) || "._~+/=".includes(c));
    if (end - i >= 8 && digit(s.slice(i, end))) return [i, end, "bearer"];
  }
  let quote = null;
  let nameEnd;
  if (pre.endsWith("=")) nameEnd = i - 1;
  else if (/=["']$/.test(pre)) [quote, nameEnd] = [pre[i - 1], i - 2];
  else if (pre.endsWith(":")) {
    const userStart = i - 1 - runBack(s, i - 1, (c) => !"/@: \t\r\n".includes(c));
    const end = runEnd(s, i, (c) => !"@/ \t\r\n".includes(c));
    return pre.slice(0, userStart).endsWith("://") && s[end] === "@" ? [i, end, "url-password"] : null;
  } else return null;
  const name = s.slice(nameEnd - runBack(s, nameEnd, tok), nameEnd).toLowerCase().replaceAll("-", "_");
  const hit = NAMES.find(([n]) => name === n || name.endsWith(`_${n}`));
  if (!hit) return null;
  const end = quote ? runEnd(s, i, (c) => c !== quote && c !== "\n") : runEnd(s, i, (c) => !ws(c) && !"&;\"'`".includes(c));
  return [i, end, hit[1]];
}

function redact(s) {
  let [out, copied, i] = ["", 0, 0];
  while (i < s.length) {
    const m = secretAt(s, i, copied);
    if (m && m[1] > i) {
      out += `${s.slice(copied, m[0])}[redacted:${m[2]}]`;
      copied = i = m[1];
    } else i++;
  }
  return out + s.slice(copied);
}

const { positive, negative } = JSON.parse(readFileSync(new URL("redaction-corpus.json", import.meta.url), "utf8"));
const wrong = [
  ...positive.filter((c) => redact(c.text) !== c.expect).map((c) => ({ text: c.text, expect: c.expect, got: redact(c.text) })),
  ...negative.filter((t) => redact(t) !== t).map((t) => ({ text: t, expect: t, got: redact(t) })),
];
console.log(`redaction corpus  ${positive.length} positive, ${negative.length} negative, ${wrong.length} wrong`);
for (const w of wrong) console.log(`\n  text   ${JSON.stringify(w.text)}\n  expect ${JSON.stringify(w.expect)}\n  got    ${JSON.stringify(w.got)}`);
process.exit(wrong.length ? 1 : 0);
