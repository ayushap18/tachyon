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

**One PTY write per agent path.** `pty_write_internal` is the only function that writes to
the shell, and it has three callers: the `pty_write` command (keystrokes, paste, prefill),
one line in `agent_loop`, and one line in `mcp_server::run_gated`. The `agent_loop` line is
lexically inside the `AgentAction::Run` arm, after `if !approved { …; continue; }`. The
`run_gated` line — an external agent's `run_command`, see
[below](#threat-model-tachyon-as-an-mcp-server) — is after
`if !approved || aborted() { return Err(…) }`, and `approved` comes from the same
`agent_propose`. It was two callers until server mode existed; the third is a second
*proposer* behind the same gate, not a second route around it. One grep still confirms there
is no other route from a model reply, or an HTTP request, to the PTY. (`pty_spawn` also writes
the static shell-integration script straight to the writer at startup; it contains no model-
or user-controlled data.)

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

**The updater cannot be driven from the webview** (`src-tauri/src/update.rs`). An updater is
remote code execution, so:

- *The trust anchor is compiled in.* The endpoint and the minisign public key reach the binary
  from `tauri.conf.json` through `generate_context!`. The plugin's one runtime override
  (`updater_builder`) and any custom version comparator are forbidden by a test that greps the
  source; every endpoint must be `https://`.
- *No updater command exists on the IPC surface at all.* `generate_handler!` names nothing from
  `update.rs`; the background check is a Rust task that does an HTTPS GET and a version compare
  and reports what it found as an event. `/update install` returns a usage string. Installing starts only from a native menu
  item (⌘U / Ctrl+U), which AppKit/GTK deliver straight to Rust — webview script cannot
  synthesize it. A test proves no handler name reaches the install path.
- *The plugin is not granted to the webview.* `capabilities/default.json` is the members of
  `core:default` minus `core:menu` and `core:tray`, plus `opener:default`. Plugin commands,
  unlike app commands, *are* ACL-scoped, so `invoke("plugin:updater|download_and_install")` is
  refused in Rust. Menu is excluded because menu events reach Rust by id string alone: a
  webview allowed to build menus could create its own `tachyon:update` item.
- *Only the artifact is signed, not `latest.json`.* Whoever can serve the manifest cannot make
  Tachyon install an unsigned build, but could pair an inflated version with an older release's
  real url and signature. `requireSignedVersion` makes the plugin compare the announced version
  against the one inside the signature's trusted comment, so that rollback fails; the monotonic
  version compare (never overridden) refuses a replayed old manifest. Freezing users on their
  current version is not stopped. Release signatures must carry `version:` in the trusted
  comment, or every install fails closed.

This is defense in depth, not the boundary. Webview script already holds a strictly stronger
capability — `pty_write` and `/mcp add … -- <cmd>` run arbitrary shell as you (see
[Limitations](#limitations)) — and a webview-triggered install of a signature-checked,
version-monotonic official build would not be an escalation over that.

**The lexical check.** `is_dangerous` lowercases the command, collapses runs of whitespace to
one space, and looks for any substring in `DANGER_PATTERNS`. Normalizing first means `rm  -rf`
with two spaces cannot slip past a pattern written with one. The patterns that would otherwise
match prose are anchored (`sudo shutdown`, `shutdown -`, not bare `shutdown`), because a gate
that flags `man shutdown` teaches people to ignore red. `nl_to_command` and `agent_loop` attach the result as `danger`; the UI
turns the bar red and shows `⚠ destructive`. It runs in Rust so the webview cannot skip it.
`TOOL:` proposals get the same flag from `tool_is_dangerous`: a destructive-sounding tool
name (`write`, `delete`, `exec`, `run`, `shell`, `kill`, …) or arguments that trip
`is_dangerous`.
The evals extract `DANGER_PATTERNS` from `lib.rs` at run time, so they measure the shipped list.

## Limitations

- **The gate warns; it does not block.** A flagged command is approved with the same single
  Enter as any other. Nothing is ever refused.
- **The match is still evadable, because it is substrings and not a shell parser.** Anything
  that hides the verb from a literal scan passes: `$(echo cm0gLXJm | base64 -d) ~`, `r\m -rf ~`,
  `curl … | sh` without `sudo`, and any alias or variable indirection. Effects the gate has no
  word for — `mv ~ /dev/null`, `> important.file`, `dropdb production` — pass too. It still
  false-positives on commands that merely *contain* a dangerous string: `echo 'never run rm -rf /'`
  and `grep -rn 'rm -rf' scripts/`. Lexing the command (Limitation 1 below) is the fix; until
  then `npm run eval:gate` measures both rates on a held-out corpus, and that number, not this
  list, is the gate's quality.
- **`pty_write` is ungated IPC.** `tauri.conf.json` sets `withGlobalTauri: true` and
  `csp: null`, and app commands are not capability-scoped. Any script running in the webview
  can call `window.__TAURI__.core.invoke("pty_write", {data: "…\n"})` and execute a command
  with no approval. The same goes for `mcp_call`, and for `ai_complete`, which spends the
  stored key on any prompt. The webview loads only the bundled WASM today, so this needs an
  injection bug first — but the invariant above defends against the model, not the webview.
- ⌘K and agent proposals are folded to one line by `one_line`, so `\n`, bare `\r`, tabs and
  invisible format characters cannot reach the PTY unseen; what the approver reads is what is
  written.
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
- **A proposal past `MAX_COMMAND_CHARS` is shown cut.** The proposal is rendered above the
  bar in a read-only block, wrapped, so a long command is readable in full — to 4096
  characters. The server refuses a longer `command` outright; a built-in-agent proposal over
  the cap is shown cut and says so, and approving it still runs the part that was not shown.
- **Approval is human-in-the-loop, not a sandbox.** An approved command runs as you, with your
  credentials. The 20-second step timeout stops the agent waiting; it does not kill the
  command. Approval fatigue over a 12-step run is a real failure mode.
- **The route table is webview-writable.** `run_slash("/route agent claude")` changes which
  provider receives the agent transcript, exactly as `run_slash("/use …")` already changes
  the active provider — `run_slash` is ungated IPC like `pty_write`. Not a regression, and not
  claimed away. What routing never does is fall back: a missing or dangling route resolves to
  the active provider, never to a second one the user did not name.
- **A compromised CI can sign an update every installed Tachyon will accept.** The minisign key
  lives in GitHub Actions secrets; signature checking proves that key signed the build and
  nothing more. Holding the key behind a reviewed GitHub Environment, or signing offline, is
  the mitigation, and neither is in place yet.
- **Each update is a new ad-hoc code signature.** `tauri.conf.json` signs with the ad-hoc
  identity `-`, so every build has a fresh cdhash and macOS privacy grants (file access and
  the like) tied to the old one **may** prompt again once after an update. That is the
  mechanism, not a measured result; the install message warns about it.
- **A `workflow_dispatch` repair does not reach the updater.** The updater reads
  `releases/latest/download/latest.json`, and `release.yml` marks a release `latest` only on a
  tag push. Repairing an existing tag replaces its assets without moving that pointer, so a
  fix that must reach installed copies is cut as a new tag.

## Threat model: Tachyon as an MCP server

`/mcp serve on` (off by default) starts an HTTP listener in `src-tauri/src/mcp_server.rs` so
external agents can use the terminal. It adds a new kind of untrusted input — a network
request — so it gets its own model. Two adversaries:

1. **A web page in the user's browser.** It can make the browser send requests to
   `127.0.0.1`, directly or by DNS rebinding.
2. **A local process running as the user** — a malicious npm postinstall script, a
   compromised MCP client, or a legitimate client whose model has been prompt-injected.

**What stops the web page** (`admit`, run before the request body is read): the socket is
bound to the literal `127.0.0.1`; every `Host` header must be `localhost`, `127.0.0.1` or
`[::1]` with an optional port, matched exactly, so a rebound `evil.com:47600` is a 403; any
`Origin` header must be a local one, so a cross-origin `fetch` is a 403 (`null` included);
and no `Access-Control-*` header is ever sent, so the preflight that an `Authorization`
header forces fails in the browser. Under all of that the page still needs the bearer token,
which it has no way to read. A page served from `http://localhost:*` passes the Origin check
and is stopped only by the token.

**What the local process can and cannot do.** Every registered agent has its own token, and
they all live in `mcp-server.json`, mode 0600. Any process running as the user can read that
file — so treat a token as keeping out *other users and the browser*, not the user's own
processes. What a token buys is decided by the scopes recorded beside it, enforced in Rust at
one table (`TOOL_SCOPES`), and asked both when the tools are listed and when one is called: a
tool the caller has no scope for is answered exactly like a tool that does not exist, so a
refusal never reveals what else is there. A process that holds a token can:

- call `get_context` with **no approval** (scope `read`, granted by default): the `cwd`, the
  git `branch` and `dirty` count, and the shell's pid (`shell_pid`) and name (`shell`).
- call `read_journal` with **no approval** *if* the agent was granted the `journal` scope —
  the last 50 commands and up to 4000 characters of each one's output, with known credential
  shapes replaced by `[redacted:<kind>]`. It is **not** in the default grant, because it is
  the feature's largest unguarded surface: if you `cat .env` with the server on, an agent
  holding `journal` reads every line redaction does not recognise (item 8 below says which).
  The `default` agent migrated from a 0.2.9 single token keeps it, because that token already
  had it.
- **propose** commands (scope `propose`, granted by default). It cannot run them.
  `run_command` reaches the PTY only through `open_gate` → `run_gated` → `agent_propose` → a
  human ⌘⏎; there is no allowlist, no trusted-client mode, no auto-approve, and no timeout
  that approves. A process running as you could already run commands as you — what it gains
  here is the chance to do so with your approval, in your live shell, which matters for a
  sandboxed or remote-driven client.
- use the **message board** (scope `message`, granted by default): `post_message`,
  `read_messages` and `list_agents`. A message is attributed to the name the token bought —
  no tool takes a `from`, and one sent anyway is ignored — and every string passes the
  validator `run_command` uses (`parse_text_arg`: no control or bidi characters, not empty,
  capped), minus the newline folding only a command gets. `list_agents` returns names, scopes and
  last-seen, never a token or whether one exists. The task board (`create_task`,
  `claim_task`, `update_task`, `list_tasks`) is the same scope on the same terms: the creator and
  holder are token names, `update_task` takes no `assignee`, a task the caller may not touch
  answers exactly like an unknown id, and every change is announced on the message board as
  `system`, a reserved name. `run_command`'s optional `task_id` spends one of that task's 20
  proposals; the 21st, or a task the caller does not hold, is refused in SEC-7's check with the
  same words, before anything reaches the bar. Board text is one agent's claim landing in
  another's context; it reaches the shell only through the same human keypress as anything else.

Revoking one agent (`/mcp agent revoke <name>`) takes effect on that agent's next request and
touches nobody else's. It also drops that name's settled proposals, so re-adding the name
(the way a token is rotated) does not hand the new holder the old one's verdicts and output.
A proposal already on the bar is left alone — it still owns the approval slot, and the user
answers it as they would any other.

**What is enforced, and where** (all in `mcp_server.rs` unless noted):

- *Shown is run.* `parse_run_args` folds the command with `one_line`, then **refuses** any
  remaining control character or bidi override. `one_line` folds `\n` but not a bare `\r`,
  which an `<input>` strips from display while a PTY treats it as Enter — `echo hi\rrm -rf ~`
  would show one command and run two. The validated string is the one proposed and the one
  written; `is_dangerous` runs on it. Commands over 4096 characters are refused.
- *One driver at a time.* `agent_claim` (`lib.rs`) is the single way to take
  `AgentState.running`, used by `agent_start` and `run_gated` alike. While the built-in agent
  runs or another `run_command` is pending, a new one fails immediately with `isError` — it
  never queues and never overwrites the parked sender. `AgentRunGuard` is constructed only
  after the claim is won, so the busy path cannot release someone else's claim, and every
  exit including a panic frees ⌘J.
- *The requester is named.* The proposal carries `external: true` and the agent name its
  **token** bought — never anything the client said about itself — so the bar reads
  `codex · run? ⌘⏎ approve · esc deny` (`Ctrl+⏎` off macOS). An external proposal that
  arrives with no name is fail-closed: `approvable` in `ui/src/ai_bar.rs` renders it for
  denial only and the key handler refuses to approve it, so an unidentified requester cannot
  be waved through by a chord.
- *A denial quiets the bar.* After any denial nothing reaches the bar for 30 s — not the agent
  that was refused, and not any other. The refusal carries `retry_after_ms` and tells the
  denied agent not to re-send. One agent may hold one undecided proposal, the hub four; all of
  it is decided in `proposals::budget`, above the `Backend`, so a refused proposal never
  reaches a terminal and never raises a bar.
- *A stray keystroke is not a decision.* External proposals are unsolicited: the bar takes
  focus while you are typing in the shell, so the Enter meant for your own command would
  otherwise approve one you never read. They therefore need a deliberate chord — ⌘⏎ /
  Ctrl+⏎ — and a bare Enter is swallowed without deciding anything (`enter_approves` in
  `ui/src/ai_bar.rs`). The built-in agent keeps plain Enter, because its proposals are
  solicited. As a second layer, an approval arriving within `MIN_REVIEW` (1 s) of the bar
  appearing is discarded backend-side and the proposal is shown again.
- *No proposal without a shell.* Until `pty_spawn` has run there is no webview listening, so
  `run_gated` refuses rather than park a proposal nobody can answer.
- *The tokens stay put.* Generated from `/dev/urandom`, compared with `ct_eq`, rendered only
  by `render_agent_config` for `/mcp agent show <name>` and only while the listener is up —
  through `term_write`, so a token reaches the display engine and never the PTY, the journal
  or a model transcript. `/mcp serve status` lists who may connect and prints no secret.
  Neither `ServeConfig` nor `AgentToken` has a `Debug` impl, and `hub_state` — the webview's
  whole view of the hub — carries no token and no command text. Nothing in the module logs,
  and no response or error echoes request headers.

**Limitations specific to server mode:**

- **It is still human-in-the-loop, not a sandbox.** Everything under [Limitations](#limitations)
  applies to external proposals unchanged: the lexical check warns and does not block, and
  an approved command runs as you.
- **Approval fatigue is worse here.** The built-in agent stops after 12 steps; an external
  client can propose for ever. The 30 s denial cooldown and the one-live-proposal cap slow a
  re-sending loop down; neither stops a client that simply keeps asking, and `MIN_REVIEW`
  defeats an Enter already in flight, not a person typing blind for longer than a second.
- **A pending proposal outlives its client.** `run_command` now answers within 25 s with a
  `proposal_id` rather than holding the client's HTTP call, so the proposal normally outlives
  the request that made it; and if the client gives up or disconnects entirely, the proposal
  still stays in the bar until you decide. Approve it and the command runs with nobody
  reading the result.
- **The 20-second wait does not kill the command.** The proposal then settles as
  `Exit code: unknown` and releases the slot, and the next approved command is written into
  whatever is still running in the foreground.
- **Plain HTTP on loopback.** A process that can sniff `lo0` sees a token; one that can do
  that can usually read the file anyway.
- **`run_gated` has no behavioural test.** It needs an `AppHandle`. Its parts are tested
  (`agent_claim`, `parse_run_args`, `wait_block`, `admit`, the proposal store, the HTTP server
  against a stub); that the PTY write still sits after the `!approved` return, and that
  `agent_propose`, `MIN_REVIEW`, `decision_stands` and `agent_decide(bool)` are unchanged, is
  asserted by grep in `the_approval_gate_is_unchanged`.

## What would make it stronger

1. Lex the command (flags, pipelines, `$(…)`) and classify by effect instead of substring.
2. Make a dangerous approval a different action from an ordinary one, not the same Enter.
3. ~~A dedicated prefill command that strips control characters, so no model text containing
   `\n` reaches the PTY.~~ Done — `one_line` does the stripping in `nl_to_command` and
   `parse_agent_reply`. The residual is only that it lives in those two call sites rather than
   in one prefill command both go through.
4. A CSP, `withGlobalTauri` off, and per-command capabilities, so webview script cannot reach
   `pty_write`, `mcp_call` or `ai_complete` by name.
5. Run agent commands in a constrained child (own PTY, container or read-only mounts, no
   inherited credentials) so approval is not the only control.
6. Per-tool MCP policy, with destructive-hint annotations shown in the gate.
7. Strip escape sequences before `term_write`, and delimit tool output in the transcript as data.
8. For server mode: ~~scope tokens per client, with a read-only scope; gate `read_journal`~~ —
   done: one token per agent, `TOOL_SCOPES` enforced in Rust, and `journal` off by default.
   ~~rate-limit proposals after a denial~~ — done: `DENY_COOLDOWN`. ~~Redact `read_journal`'s
   output for an agent that does hold the scope~~ — done: `redact` (`lib.rs`) on `read_journal`,
   `get_context`, `run_command`'s result, board messages and task text, and nowhere on the
   human's side; task text may not hold a 64-hex run (a token's shape) at all. The residual is
   that it knows shapes, not secrets: a key with no known prefix and no `password=`-style name
   in front of it (a bare AWS secret key, a `password: x` YAML line, a JSON `"token": "…"`)
   goes through; so does a key that lost its prefix (folded across lines, cut by the 8 KiB
   output cap, split by shell quoting), and the base64 lines of a private key whose BEGIN and
   END lines both fell outside the kept output.
   An entropy pass over long base64 runs, tuned on the corpus's negatives, is the next step.

Bypass reports are welcome — see [SECURITY.md](../SECURITY.md).
