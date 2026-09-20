# Security policy

Tachyon drives a real shell and lets a language model propose commands for it. The design,
and a candid list of its current weaknesses, is in [docs/danger-gate.md](docs/danger-gate.md).
Read that first: several things that look like vulnerabilities are documented limitations,
and improvements to them are welcome as ordinary issues and PRs.

## Reporting

Use GitHub's private reporting: **Security → Report a vulnerability** on
<https://github.com/ayushap18/tachyon>. Please do not open a public issue for anything that
lets a command run without approval or exposes an API key.

Include the version or commit, the OS and shell, and the smallest reproduction you have — a
model reply, an MCP response, or a byte sequence is ideal. This is a one-maintainer project:
expect an acknowledgement within a week. Fixes land on `main` and in the next tagged release;
there are no backports.

## In scope

- Any path from model output, command output, or an MCP server response to the PTY that does
  not pass through an explicit `agent_decide(true)`.
- Approval-gate failures that resolve to "approved": stale or replayed decisions, races
  between abort and write, a keypress approving a proposal the user did not see.
- API key exposure: a key crossing IPC, or appearing in an error, a log, the terminal, or
  eval output.
- Config handling that loses or exposes `providers.json` (permissions, non-atomic writes,
  silent resets).
- Escape-sequence or OSC 133 forgery that changes what the agent or the user believes ran.
- Script or content injection into the webview. IPC is not capability-scoped, so this is
  equivalent to command execution.

## Known and documented, not new reports

- `is_dangerous` is a lowercase substring match and is trivially evadable. It is warn-only.
  New evasions belong in `evals/gate-corpus.json` — send a PR.
- `pty_write`, `mcp_call` and `ai_complete` are callable by any script already running in the
  webview (`withGlobalTauri: true`, `csp: null`).
- MCP tool proposals are never flagged as dangerous.
- Approved commands run unsandboxed with the user's privileges.
- API keys are stored in plaintext (mode 0600) in `~/.config/tachyon/providers.json`.
- Release builds are unsigned.

## Out of scope

A malicious local user or process running as you, the behaviour of third-party model
providers and MCP servers with data you chose to send them, and vulnerabilities in the
system webview, Tauri, or the shell itself (report those upstream).
