# The danger gate: why the safety boundary is in Rust, not in the prompt

Tachyon lets a language model propose commands for a real shell. This document says what
stops a proposal from becoming an execution, where that is enforced, and where it is not.
Function names refer to `src-tauri/src/lib.rs` unless noted. The
[limitations](#limitations) are the part to read first.

## Threat model

1. **The model emits a destructive command** — `rm -rf ~`, `dd of=/dev/disk2`, a fork bomb.
   A system prompt lowers the rate; it does not make it zero.
2. **Prompt injection through the transcript.** `agent_loop` appends every command's output
   and every MCP tool result to the transcript for the next model call. Anything that can put
   text there — a file the agent `cat`s, a page behind `curl`, a hostile MCP server — can
   instruct the model. The journal is forgeable too: OSC 133 marks are read off the raw PTY
   stream, so a program can print a fake `D;0` and misreport its exit code.

So **model output is untrusted input**. A rule written in the prompt ("always ask first") is
enforced by the component under attack. The rule that matters — nothing reaches the shell
without a human keypress — has to live in code the model cannot address.

Out of scope: a malicious local user, a provider misusing what you send it, and whatever an
approved command goes on to do.

## What is enforced, and where

**One PTY write in the agent path.** `pty_write_internal` is the only function that writes to
the shell, and it has two callers: the `pty_write` command (keystrokes, paste, prefill) and
one line in `agent_loop`. That line is lexically inside the `AgentAction::Run` arm, after
`if !approved { …; continue; }`. One grep confirms there is no other route from a model reply
to the PTY. (`pty_spawn` also writes the static shell-integration script straight to the
writer at startup; it contains no model- or user-controlled data.)

**Approval is a fail-closed oneshot.** `agent_propose` parks a `oneshot::Sender<bool>` in
`AgentState.decision`, emits `agent-propose`, and returns `rx.await.unwrap_or(false)`. The
webview answers with a boolean only; the command that runs is the string Rust is holding.
Every way of not answering is a denial:

- `agent_decide` `take()`s the sender, so a double decide cannot approve a later step.
- `agent_abort` sets the flag and drops the sender (`Err` → `false`); the loop re-checks the
  flag between the await and the write.
- `agent_start` drops any stale sender; `AgentRunGuard` drops it on return or panic.
- There is no approval timeout. Auto-approve is unsafe; auto-deny races the person reading.

**The UI resolves a proposal from one place.** In `ui/src/ai_bar.rs`, `agent_decide` is
invoked only from the `#ai-input` key handler while `pending_gate` is set: Enter approves,
Escape denies. Both `stop_propagation()`, so the approving Enter is not also sent to the
shell as a carriage return, and the global handler in `ui/src/app.rs` never closes the bar
on Escape.

**⌘K never executes.** `nl_to_command` returns `{command, danger}` and the bar writes the
command to the PTY without a trailing newline. It waits at the prompt, editable.

**Display and execution are separate paths.** Model prose (⌘E, agent narrative, slash
output) goes through `term_write`, which feeds the vt100 display engine. The engine holds no
PTY writer, so painted text cannot run.

**API keys do not cross IPC.** Provider commands return `PublicProvider` (`has_key: bool`,
no `key`). `ai_call` is the single HTTP path; the key appears only in request headers, and
errors are built from `without_url()` plus a truncated body.

**The lexical check.** `is_dangerous` lowercases the command and looks for any substring in
`DANGER_PATTERNS`. `nl_to_command` and `agent_loop` attach the result as `danger`; the UI
turns the bar red and shows `⚠ destructive`. It runs in Rust so the webview cannot skip it.
`TOOL:` proposals get the same flag from `tool_is_dangerous`: a destructive-sounding tool
name (`write`, `delete`, `exec`, `run`, `shell`, `kill`, …) or arguments that trip
`is_dangerous`.
The evals extract `DANGER_PATTERNS` from `lib.rs` at run time, so they measure the shipped list.

## Limitations

- **The gate warns; it does not block.** A flagged command is approved with the same single
  Enter as any other. Nothing is ever refused.
- **The match is trivially evadable.** `rm -r -f ~`, `rm  -rf` with two spaces,
  `find . -delete`, `git clean -fdx`, `curl … | sh`, `$(echo cm0gLXJm | base64 -d) ~`, and any
  alias or variable indirection pass unflagged. It also false-positives: `echo "rm -rf"` and
  `grep reboot syslog` are flagged. `npm run eval:gate` measures both rates on a held-out
  corpus; that number, not this list, is the gate's quality.
- **`pty_write` is ungated IPC.** `tauri.conf.json` sets `withGlobalTauri: true` and
  `csp: null`, and app commands are not capability-scoped. Any script running in the webview
  can call `window.__TAURI__.core.invoke("pty_write", {data: "…\n"})` and execute a command
  with no approval. The same goes for `mcp_call`, and for `ai_complete`, which spends the
  stored key on any prompt. The webview loads only the bundled WASM today, so this needs an
  injection bug first — but the invariant above defends against the model, not the webview.
- **⌘K does not strip embedded newlines.** `strip_fences` trims only the ends, so a two-line
  model reply executes its first line on arrival. The ⌘B rerun button strips `\r`/`\n`; this
  path does not yet.
- **The MCP tool check is a name heuristic.** `tool_is_dangerous` substring-matches the tool
  name, so a destructive tool called `apply` is unflagged and `list_skills` is flagged. Like
  the shell check it only colours the gate.
- **MCP servers are an injection surface.** Tool names, descriptions and schemas enter the
  system prompt; tool results and tool errors enter the transcript. `render_tools` bounds
  them (one line per tool, capped description, signature, count and total size) and labels
  the section as data, which limits prompt flooding and forged `TOOL` lines — it does not
  stop a description or a result from instructing the model.
- **A stdio MCP server is a program you told Tachyon to run.** `/mcp add <name> -- <command>`
  executes `<command>` as you, unsandboxed, on every tool listing and call, without a gate —
  the gate covers tool *calls*, not server start-up. `/mcp list` prints the full command
  line. Because `run_slash` is IPC, this is reachable from webview script exactly as
  `pty_write` is (above).
- **MCP auth headers are plaintext in `mcp.json`** (0600, like API keys). They are kept out of
  `/mcp list`, IPC and error strings, not off the disk.
- **Painted text is not sanitised.** `term_write` interprets escape sequences, so model or
  tool text can overwrite what is on screen. It cannot execute; it can mislead the approver.
- **The proposal is a single-line input.** A long command is not fully visible without scrolling.
- **Approval is human-in-the-loop, not a sandbox.** An approved command runs as you, with your
  credentials. The 20-second step timeout stops the agent waiting; it does not kill the
  command. Approval fatigue over a 12-step run is a real failure mode.

## What would make it stronger

1. Lex the command (flags, pipelines, `$(…)`) and classify by effect instead of substring.
2. Make a dangerous approval a different action from an ordinary one, not the same Enter.
3. A dedicated prefill command that strips control characters, so no model text containing
   `\n` reaches the PTY.
4. A CSP, `withGlobalTauri` off, and per-command capabilities, so webview script cannot reach
   `pty_write`, `mcp_call` or `ai_complete` by name.
5. Run agent commands in a constrained child (own PTY, container or read-only mounts, no
   inherited credentials) so approval is not the only control.
6. Per-tool MCP policy, with destructive-hint annotations shown in the gate.
7. Strip escape sequences before `term_write`, and delimit tool output in the transcript as data.

Bypass reports are welcome — see [SECURITY.md](../SECURITY.md).
