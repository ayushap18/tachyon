// MUST stay in sync with DANGER_PATTERNS + is_dangerous in src-tauri/src/lib.rs.
// This is the JS mirror of the Rust trust boundary — if you edit one, edit both.
// `npm run eval:selftest` checks this mirror against lib.rs's own test vectors.
export const DANGER_PATTERNS = [
  "rm -rf",
  "rm -fr",
  "sudo rm",
  "of=/dev",
  "mkfs",
  "> /dev/sd",
  "chmod -r 777 /",
  ":(){",
  "shutdown",
  "reboot",
];

export function isDangerous(cmd) {
  const lower = cmd.toLowerCase();
  return DANGER_PATTERNS.some((p) => lower.includes(p));
}
