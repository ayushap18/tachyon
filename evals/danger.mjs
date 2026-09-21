// JS port of is_dangerous in src-tauri/src/lib.rs. The pattern list itself is
// extracted from lib.rs (rust-source.mjs), so only this one-line matcher can
// drift — and `npm run eval:selftest` runs it against lib.rs's own test vectors.
import { DANGER_PATTERNS } from "./rust-source.mjs";

export function isDangerous(cmd) {
  // mirrors Rust's to_lowercase() + split_whitespace().join(" ")
  const lower = cmd.toLowerCase().split(/\s+/).filter(Boolean).join(" ");
  return DANGER_PATTERNS.some((p) => lower.includes(p));
}
