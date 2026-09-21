// Single source of truth: the prompts and the danger gate are read straight out
// of src-tauri/src/lib.rs, so the evals can never drift from what the app ships.
// Anything that can't be found THROWS — a stale fallback copy would produce
// confident numbers about code that no longer exists.
import { readFileSync } from "node:fs";

const FILE = new URL("../src-tauri/src/lib.rs", import.meta.url);
const SRC = readFileSync(FILE, "utf8");

// The app substitutes the detected shell/OS for this placeholder at call time;
// the evals pin it so runs stay comparable across machines.
const ENV = "zsh on macOS";

const fail = (what) => {
  throw new Error(`rust-source: cannot extract ${what} from ${FILE.pathname} — update evals/rust-source.mjs`);
};

// body of a normal "..." literal → the string rustc would produce
function unescape(body) {
  return body.replace(/\\(\r?\n\s*|u\{([0-9a-fA-F_]+)\}|x([0-9a-fA-F]{2})|[\s\S])/g, (m, e, u, x) => {
    if (u) return String.fromCodePoint(parseInt(u.replace(/_/g, ""), 16));
    if (x) return String.fromCharCode(parseInt(x, 16));
    if (/^\r?\n/.test(e)) return ""; // `\`+newline continuation eats the following indent too
    const simple = { n: "\n", r: "\r", t: "\t", 0: "\0", "\\": "\\", '"': '"', "'": "'" };
    return e in simple ? simple[e] : fail(`string escape ${m}`);
  });
}

// sticky matchers for one literal at a given offset: "..." and r#"..."#
const STR = /"((?:[^"\\]|\\[\s\S])*)"/y;
const RAW = /r(#*)"([\s\S]*?)"\1/y;

function constStr(name) {
  const m = new RegExp(`const ${name}: &str =\\s*`).exec(SRC);
  if (!m) fail(name);
  STR.lastIndex = m.index + m[0].length;
  const lit = STR.exec(SRC);
  if (!lit) fail(`${name} (not a plain string literal)`);
  const s = unescape(lit[1]).replaceAll("{env}", ENV);
  if (!s.trim()) fail(`${name} (empty)`);
  return s;
}

// A plain numeric const. The eval harness must send the request shape the app sends;
// a hardcoded copy here would silently measure a different one.
function constNum(name) {
  const m = new RegExp(`const ${name}: u32 = (\\d+);`).exec(SRC);
  return m ? Number(m[1]) : fail(name);
}

// every string literal between the `[` that ends `anchor` and its closing `]`
function strList(anchor, what) {
  const m = anchor.exec(SRC);
  if (!m) fail(what);
  const out = [];
  for (let i = m.index + m[0].length; i < SRC.length; ) {
    if (SRC[i] === "]") return out.length ? out : fail(`${what} (empty list)`);
    if (SRC.startsWith("//", i)) {
      i = SRC.indexOf("\n", i) + 1 || SRC.length;
      continue;
    }
    STR.lastIndex = RAW.lastIndex = i;
    const lit = STR.exec(SRC) ?? RAW.exec(SRC);
    if (lit) {
      out.push(lit[2] ?? unescape(lit[1]));
      i += lit[0].length;
    } else if (/[\s,]/.test(SRC[i])) i++;
    else break; // not a plain literal list any more (a const, a macro…)
  }
  fail(`${what} (unexpected list syntax)`);
}

export const AI_SYSTEM = constStr("AI_SYSTEM");
export const AI_AGENT = constStr("AI_AGENT");
export const AI_MAX_TOKENS = constNum("AI_MAX_TOKENS");
export const DANGER_PATTERNS = strList(/const DANGER_PATTERNS: &\[&str\] = &\[/, "DANGER_PATTERNS");

// The Rust unit-test vectors for is_dangerous. A function, not a const: only the
// self-test needs them, and a test refactor in lib.rs shouldn't take live runs down.
export const dangerVectors = () => ({
  dangerous: strList(/fn dangerous_positives\(\)\s*\{\s*for \w+ in \[/, "dangerous_positives vectors"),
  safe: strList(/fn dangerous_negatives\(\)\s*\{\s*for \w+ in \[/, "dangerous_negatives vectors"),
});
