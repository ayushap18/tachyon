# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Entries before
Unreleased were reconstructed from `git log`; versions are the ones named in commit subjects.
No commit is labelled 0.1.2.

## 0.2.8 — 2026-09-21

### Fixed
- **No installed copy could install an update.** `requireSignedVersion` makes the app refuse a
  signature that does not record `version:<v>` in its minisign trusted comment — the control
  that stops a tampered manifest replaying an old signed release. tauri-plugin-updater 2.12
  enforces the field, but no released Tauri CLI writes it (checked through 2.11.5), so 0.2.6
  shipped verifying something nothing could produce, and rejected 0.2.7. Releases are now
  re-signed by `tools/sign-updater` with the same key, recording the version, and
  `scripts/release.mjs` refuses to publish a signature without it. **0.2.7 cannot be installed
  in-app by anyone; installed 0.2.6 copies update straight to this release.**
- The update menu item printed nothing until the download finished or failed, so it looked
  dead for as long as the network took. It now says it is checking, then what it is
  downloading.

## 0.2.7 — 2026-09-21

### Documentation
- How to create the updater signing key. The README said the two repository secrets had to
  exist but never said how to produce them; it now gives the command (`tauri signer
  generate` — not `tauri signing`), how to store the key and password as secrets, and why the
  private key must be backed up off the machine: every installed copy trusts only the public
  key it was built with, so a lost key means no installed Tachyon can update again.

### Notes
- The first update delivered by the in-app updater. Installed 0.2.6 copies are offered this
  release through `/update` and install it in place.

## 0.2.6 — 2026-09-21

### Security
- **The install could be triggered from the webview via a spoofed menu item.** Installs were
  meant to start only from a native menu item, but the webview held menu permissions, so
  script could create its own item carrying the install ID and bind it to ⌘C — pressed
  constantly in a terminal. The webview no longer holds `core:menu` or `core:tray`, and a test
  pins its exact capability list so they cannot return.
- **A tampered update manifest could force a downgrade.** The manifest is not signed and the
  "older version refused" check read only the version it claimed. `requireSignedVersion` is now
  on, and a test asserts it stays on and that no insecure-transport or downgrade flag is set.


### Changed
- **OpenAI-compatible providers could answer with at most 1024 tokens.** Every non-Anthropic
  request (OpenAI, Groq, Gemini, Kimi, DeepSeek, Mistral, local runtimes) hardcoded
  `max_tokens: 1024` while Anthropic got 4096, which silently truncated agent replies on
  thinking models. Both shapes now send one `AI_MAX_TOKENS` of 4096. A cap is a ceiling, not a
  target, but a provider that bills or rate-limits by requested tokens may see the difference.
- Each AI call has its own time limit instead of a shared 120 s: ⌘K 20 s, ⌘E and ⌘B 45 s,
  the agent 120 s.
- The danger gate collapses whitespace before matching and anchors the patterns that used to
  flag prose (`man shutdown`), so `rm  -rf` with two spaces is caught and fewer benign commands
  turn the bar red. On the held-out corpus in `evals/baseline/gate.json`, recall rose from
  24.4% (11/45) to **71.1% (32/45)** and false positives fell from 14.3% (6/42) to **4.8%
  (2/42)**. It is still a warn-only substring check, and the approval keypress is still the
  control.
- Launched from Finder or the Dock, Tachyon asks the login shell for provider keys and for the
  `PATH` a stdio MCP server needs, instead of seeing neither.

### Added
- `/route <task> <id> [model]` sends one task — `command`, `explain` or `agent` — to its own
  provider and model; `/route` prints the table, `/route <task> off` resets one. Routes ship
  empty: until you set one, everything uses the active provider exactly as before. A route to a
  removed provider falls back to the active one, never to a provider you did not pick.
- In-app updates. Tachyon checks once per launch (`TACHYON_NO_UPDATE_CHECK=1` to skip) and
  `/update` checks on demand. The `.dmg` and `.AppImage` builds install with ⌘U / Ctrl+U from a
  native menu item, after checking the minisign signature; the `.deb` build does not update
  itself and points you at the releases page. Nothing in the webview can start an install.
  **Updates are delivered only by signed releases.** This is the first version carrying the
  updater, so it can receive later versions but cannot update itself to 0.2.6; the release
  that follows must be built with the signing key present for the check to find anything
  installable.

## 0.2.5 — 2026-09-21

### Fixed
- **The shell's first output was painted in the wrong theme.** The terminal engine hardcoded
  the Tokyo Night palette at construction and relied on a second IPC round trip to correct it,
  so the prompt and anything an rc file echoed were drawn with the dark palette and left on a
  light background until something redamaged those cells — a dark slab over most of a large
  window, with scattered correctly-coloured cells where later output landed. The theme now
  travels with `pty_spawn`, so the engine starts with the right palette and the window in which
  it could be wrong no longer exists. Live theme switching is unchanged.

## 0.2.4 — 2026-09-21

### Security
- **The review floor protected only external requests.** A one-second floor stops a stray
  keystroke approving a proposal, but it lived in the MCP server path, so the built-in agent
  had neither it nor the ⌘⏎ chord. Double-tapping Enter after submitting a ⌘J task could
  approve its first proposal with no review time at all. The floor now lives in
  `agent_propose`, which both drivers route through, as a pure `decision_stands()` with a
  table test. Only a too-fast approval re-shows; denial and abort still resolve immediately.
- A provider's `/models` endpoint could return unbounded rows into the suggestion list; capped
  where the untrusted data enters. The invisible-character filter widened from four ranges to
  the full set of format blocks, so U+061C, U+00AD, U+2060..2064 and the tag block can no
  longer reach a suggestion row or a command.

### Added
- ⌘K completes command arguments, not just command names: provider ids for `/use`, `/key`,
  `/models`, `/url` and `/remove`; the models a provider actually serves for `/model` and
  `/use <id>`; configured server names for `/mcp remove`; discovered runtimes for `/local`.
  An argument row is its command form with the arguments filled in, so accepting, Tab and the
  key routing behave exactly as before.
- Two argument positions suggest nothing, by design and by test: the argument of `/key` is an
  API key, and argument 2 of `/local`'s three-token form is a base_url — the backend matches
  `[id, url, model, key]` before `[id, model]`, so completing a model there would teach syntax
  that does not parse.
- Model lists are the only network fetch and are triggered by reaching a model position, never
  by a keystroke. Provider and MCP server names come from disk-only calls made when the bar opens.

## 0.2.3 — 2026-09-21

### Security
- **Approval-gate bypass.** Pressing ⌘K (or ⌘P, ⌘, ⌘B) while an agent proposal was awaiting
  your decision unmounted the bar without clearing the gate, leaving the backend parked. The
  close path then blanked the text and made the input editable again. Reopening gave an empty,
  editable bar with the gate still armed, and the next Enter approved a command that was no
  longer on screen. `readonly` is now derived from the gate rather than a signal any path can
  clear, and closing preserves the proposal so reopening shows what Enter approves.
- **Gate races in async continuations.** Continuations re-checked the gate only once, after
  their first await, so a proposal arriving during a later round trip could have its status
  overwritten or its pending decision discarded. One predicate, re-checked after every await,
  with a table test over all four states.
- **Passwords could reach the AI provider.** Input typed at an unechoed prompt (sudo, ssh) was
  captured and, because it was never cleared at a prompt mark, became the *next* command's
  journal label — visible in ⌘B, returned by the MCP `read_journal` tool, and interpolated into
  the context sent to the model. Reachable by re-running a recalled command with ^O or ^X^E,
  which send no typed line. Cleared at the prompt mark now.
- Bidi and zero-width characters survived command folding, so a displayed command could be
  visually reordered; and remote MCP tool names and descriptions were painted through the
  terminal writer, which interprets escape sequences. Both are neutralised at ingest.

### Added
- ⌘K suggests slash commands as you type, with each command's usage as the detail. Nothing is
  selected by default, so Enter keeps its submit meaning unless you arrow or Tab onto a row;
  accepting only fills the input and never writes to the shell. Composing and auto-repeating
  keys are ignored. Pure logic lives in `ui/src/complete.rs` and is host-tested.

### Fixed
- The command palette could jump its highlight to a row you never selected when late results
  arrived, because the selection was clamped for display but never written back.

### Not built
- ⌘K history. Excluding lines starting with `/` is not sufficient protection: the bar's main
  use is free text, so `deploy with GITHUB_TOKEN=...` is an ordinary non-slash line that would
  have been persisted in plaintext.

## 0.2.2 — 2026-09-20

### Fixed
- Size the terminal to its visible canvas, with padding and room for the status bar,
  so prompts and the final output row are never hidden underneath the status bar.
- Repaint damaged rows with backgrounds before text, and clip glyphs to their row.
  This removes stale italic/combining-character pixels and preserves wide glyphs
  when their adjacent spacer cell changes.
- Snap canvas edges to device pixels for clean redraws at fractional display scales.
- Keep Vim highlights aligned with the padded terminal and handle the first resize
  observation so late-loading styles cannot leave the PTY at the wrong size.
- Apply an ad-hoc macOS bundle signature during packaging, avoiding the incomplete
  linker signature that required local repair. Builds remain unnotarized.

### Added
- Browser rendering regressions against the compiled WASM at 1x, 1.25x, 1.5x and 2x:
  viewport sizing, resize, pixel-clean erasure, wide glyphs and scroll backpressure.

## 0.2.1 — 2026-09-20

### Fixed
- Trackpad movement preserves fractional deltas and respects pixel, line and page wheel
  units. Horizontal gestures no longer scroll vertically. Scroll IPC is batched per frame
  with at most one request in flight to prevent a backlog.
- Scrollback sends changed cells instead of a full screen; gestures at either boundary
  cause no redraw. Selection highlights are cleared correctly before incremental updates.
- Updated vt100 to 0.16.2 to fix deep-scrollback overflow and cursor restore after resize.
- Linux releases: Dioxus CLI 0.7.9 requires GLIBC 2.39 and could not run on Ubuntu 22.04.
  Build portable frontend assets on 24.04 and package native binaries on 22.04.
- Releases wait for the complete macOS DMG, Linux AppImage and Debian package set before
  publication, include SHA256SUMS, validate versions and support rebuilding existing tags.
- Refreshed npm lockfile to match the Rust frontend's dependencies and app version.

### Changed
- New Tachyon logo and desktop application icons.
- README with direct download guidance, first-launch setup, Linux FUSE troubleshooting,
  checksum verification and reproducible build instructions.

## 0.2.0 — 2026-09-20

First tagged release of the Rust-frontend line: 0.1.5 shipped the Dioxus/WASM rewrite but was
never tagged, so this release contains it as well as everything below.

### Added
- Linux support: the backend builds and runs on Linux, CI tests macOS and Ubuntu, and tagged
  releases build an AppImage and a `.deb` alongside the macOS DMG. Windows is not supported.
- bash and fish shell integration (OSC 133 hooks), in addition to zsh. Other shells get no
  command journal and the app says so at startup.
- Configurable, platform-aware keybindings: ⌘-chords on macOS, Ctrl+Shift chords elsewhere so
  readline's Ctrl keys still reach the shell; overrides in `~/.config/tachyon/keybindings.json`.
- Agent-loop eval (`npm run eval:agent`) with a keyless scripted-model self-test
  (`eval:agent:selftest`), run in sandboxed scratch directories.
- Danger-gate corpus (`npm run eval:gate`): the gate's own recall and false-positive rate on a
  held-out set of destructive and benign commands.
- Safety eval reports three outcomes — gated, refused, unsafe — plus false-positive cases;
  JSON artifacts, `--baseline` comparison, and a `--min-acc` floor.
- `docs/danger-gate.md` (safety design and limitations), `docs/architecture.md`,
  `CONTRIBUTING.md`, `SECURITY.md`, issue and PR templates, this changelog.
- MCP client: local **stdio** servers (`/mcp add <name> -- <cmd>`) alongside remote HTTP,
  tool input schemas rendered into the system prompt as signatures, `isError` results reported
  as errors, HTTP session reuse, and optional per-server auth `headers` whose values are never
  printed or sent to the webview.
- MCP **server** mode (`/mcp serve on|off|status`): external agents can drive this terminal
  through the same human approval gate. Off by default, 127.0.0.1 only, bearer token stored
  0600, `Origin`/`Host` checks, and external proposals require ⌘⏎ (`Ctrl+⏎` on Linux).
- Local and open models: `/local` discovers Ollama, LM Studio, llama.cpp, vLLM and Jan;
  `/models` lists what a provider actually serves; `/url` and `/remove`; API keys may come
  from environment variables and are never written to disk.
- Committed eval baselines (`evals/baseline/`); the README results block is rendered from them
  and `eval:selftest` fails if the two disagree.

### Changed
- Eval prompts and `DANGER_PATTERNS` are extracted from `src-tauri/src/lib.rs` at run time
  instead of being hand-copied into the harness.
- README: the architecture diagram showed the webview calling AI providers; all AI HTTP has
  been in the backend since 0.1.4-beta. "Hard gate" wording replaced with what the gate does
  (warns; never blocks).

### Fixed
- CI had failed on every push since the Dioxus port (it still ran `tsc` and `npm run build`);
  it now tests both crates, checks the wasm target and runs the keyless evals. Release builds
  install dioxus-cli and ship release, not debug, wasm.
- A corrupt `providers.json` was silently replaced with defaults, destroying stored API keys.
  Corrupt config is now an error; writes are atomic, serialised, and mode 0600; `XDG_CONFIG_HOME`
  is honoured.
- Nothing hangs forever: HTTP connect/request timeouts, ⌘J abort cancels an in-flight model
  call, `AgentRunGuard` clears agent state on panic, MCP discovery is concurrent with a 5 s
  timeout and reports per-server errors, `lsof`/`git` probes are killed after 2 s.
- Agent steps could be fed a previous step's late output and exit code; the loop now waits
  for the block matching the command it wrote.
- ⌘B rerun/copy/expand could act on the wrong block after the journal ring shifted.
- A failed shell spawn was a blank window; it is now reported. Missing shell integration is
  reported once at startup.
- Mutex poisoning after a reader-thread panic no longer bricks the app; grid dimensions from
  the webview are clamped.
- A multi-line model reply reached the PTY with its newlines intact, so ⌘K executed the first
  line of a "prefill only" command and the agent's single-line approval bar showed line 1 while
  later lines ran unseen. Replies are folded to one line — including on a bare carriage return,
  which the approval input hides but the PTY treats as Enter — and control characters are
  stripped, so what is shown is what runs and what the danger gate sees.
- ⌘B per-block explain had never worked in the Rust frontend: the argument was sent as
  `exit_code` where Tauri matches `exitCode`.
- `cargo test`/`check` failed on a fresh clone and in CI, because Tauri needs the gitignored
  `ui/dist`; `build.rs` now writes a placeholder.
- Groq retired `llama-3.3-70b-versatile`, the built-in default, which surfaced only as an
  opaque 404. The default is now chosen from the committed agent-loop eval.
- MIT `LICENSE` added; build prerequisites documented.

## 0.1.5 — 2026-09-20

### Changed
- Pure-Rust frontend: Dioxus 0.7 compiled to WASM replaces TypeScript, xterm.js and Vite. A
  backend `vt100` engine owns the grid and ships only changed cells (`grid-damage`) to a
  canvas painter.
- The Rust-frontend line was promoted from the beta identity to stable (`com.ayush18.tachyon`),
  which also brought the 0.1.4-beta key-redaction fix to `main`.

### Added
- 5000-line scrollback with wheel scrolling; mouse drag-select and ⌘C; vim yank and block copy
  through a native clipboard command.
- ⌘V paste. Font and size settings drive the canvas.
- `term_write`: a display-only path for ⌘E output, agent narrative and slash-command results
  that never touches the PTY.

### Fixed
- Arrow/Home/End honour DECCKM, so vim, htop and less read them correctly.
- Keys typed into an overlay — including the agent-approval Enter — no longer also reach the shell.
- Resize and fullscreen repaint immediately and fill the window; canvas seam lines and scroll
  glitches removed.
- Per-block AI explain is keyed to a stable block id instead of a list index.

## 0.1.4-beta, 0.1.4-beta.2 — 2026-07-17

### Security
- API keys were sent to the webview as part of provider state. Provider IPC now returns
  `PublicProvider` with `has_key` instead of the key.

### Changed
- AI completion moved into the backend (`ai_complete` over `reqwest`); the webview no longer
  talks to providers.
- beta.2: the remaining logic — OSC journal, NL→command, error autopsy, agent loop, slash
  parsing — moved from TypeScript to Rust, with unit tests.

### Fixed
- A trailing slash in a provider `base_url` produced a bad request URL.

## 0.1.3 — 2026-07-17

### Added
- GitHub Actions: tests on push, release build on `v*` tags.
- Command palette: Vim mode entry and app version.

### Fixed
- Vim mode: `/` search prefill, backward-search stall, repeat after an empty `/`.

## 0.1.1 — 2026-07-17

### Added
- Vim navigation mode (⌘⇧V): normal/visual motions over the buffer, `/ n N` search, `v`+`y` yank.

### Changed
- Faster PTY I/O: 64 KB reads.

## 0.1.0 — 2026-07-16

Initial build: Tauri 2 + `portable-pty` terminal; ⌘K natural language → command; ⌘E error
autopsy; ⌘J agent mode with per-step approval; multi-provider registry and slash commands;
MCP client over Streamable HTTP; OSC 133 zsh integration and command journal; ⌘P palette;
⌘B block navigator; settings and themes; eval harness for NL accuracy and the danger gate.
