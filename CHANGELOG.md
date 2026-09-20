# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Entries before
Unreleased were reconstructed from `git log`; versions are the ones named in commit subjects.
Only `v0.1.3` exists as a git tag, and no commit is labelled 0.1.2.

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
