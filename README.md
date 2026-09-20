<p align="center">
  <img src="assets/tachyon-wordmark.png" alt="Tachyon" width="520">
</p>

# Tachyon

An AI-native terminal, inspired by Warp — built from scratch to learn how modern terminals and AI agents actually work. Named for the hypothetical particle that outruns light.

> **Speak to your shell.** Natural language in, reviewed commands out — with real command blocks, an agent with approval gates, and a safety eval that measures how well that holds.

<!-- demo GIF: assets/demo.gif -->

Runs on **macOS and Linux**. Windows is not supported yet. MIT-licensed; see [Docs](#docs) and [CONTRIBUTING.md](CONTRIBUTING.md).

### Keyboard

| macOS | Linux | Action | id |
|---|---|---|---|
| ⌘K | Ctrl+Shift+K | AI command bar (natural language → command, prefilled for review) | `ai_bar` |
| ⌘J | Ctrl+Shift+J | Agent mode (multi-step task loop; the same chord again aborts a run) | `agent` |
| ⌘E | Ctrl+Shift+E | Explain last error | `explain` |
| ⌘P | Ctrl+Shift+P | Command palette (actions · providers · history) | `palette` |
| ⌘B | Ctrl+Shift+B | Block navigator (session blocks, per-block AI, health minimap) | `blocks` |
| ⌘⇧V | Ctrl+Shift+M | Vim mode (normal/visual navigation over the buffer; `i`/`a`/`Esc` to insert) | `vim_toggle` |
| ⌘, | Ctrl+, | Settings | `settings` |
| ⌘C | Ctrl+Shift+C | Copy the selection | `copy` |

On Linux the defaults are Ctrl+Shift chords because plain Ctrl+K/J/E/P/B are readline keys and must
reach the shell. (Settings is Ctrl+, — Shift would turn `,` into `<`.) The rest of this README names
shortcuts by their macOS chord. Defaults live in `ui/src/keymap.rs`; override any of them in
`~/.config/tachyon/keybindings.json`, keyed by the id column:

```json
{ "ai_bar": "ctrl+alt+k", "copy": "ctrl+shift+c" }
```

Modifiers are `cmd`, `ctrl`, `shift`, `alt`. Unknown ids and unparseable chords are ignored and that
action keeps its default.

Slash commands (`/keys`, `/key`, `/use`, `/model`, `/local`, `/mcp add|remove|list`) work from the ⌘K bar — see [Providers & slash commands](#providers--slash-commands).

## What I'm building

A desktop terminal where AI is a first-class citizen, not a bolted-on chatbot:

- **Real terminal first** — a native app (Tauri + Rust) driving a real shell through a PTY, with a Rust-side `vt100` engine that owns the screen grid and paints it to a canvas
- **Natural language → commands** — type *"undo my last commit but keep the changes"* and get the right `git` incantation, aware of your cwd, git state, and recent history
- **Agent mode** — describe a multi-step task, the agent plans the commands, shows them, and executes step-by-step with explicit approve/deny gates
- **Error autopsy** — when a command fails, one keystroke explains the actual stderr and suggests a fix
- **Safety rails** — nothing a model proposes reaches the shell without a keypress, enforced in Rust rather than in the prompt; `rm -rf`-class commands are additionally flagged by a (deliberately simple, warn-only) lexical gate whose recall is measured, not assumed — see [docs/danger-gate.md](docs/danger-gate.md)
- **Evals, not vibes** — a benchmark suite measuring command-generation accuracy and safety-block rate across prompt/model versions

## Stack

| Layer | Choice |
|-------|--------|
| Shell/PTY | Rust, `portable-pty` |
| App shell | Tauri 2 |
| Terminal engine | Rust, `vt100` (grid/scrollback/cursor) |
| Rendering | canvas 2D painter, per-cell |
| Frontend | Rust + Dioxus (WASM) |

The entire frontend is Rust: Dioxus components compiled to WASM host the chrome and paint a `<canvas>`. VT100/ANSI parsing lives Rust-side (`vt100`, the same engine family as many Rust terminals) — the app feeds PTY bytes to it and ships only the changed cells (`grid-damage`) to the painter. No JavaScript, no xterm.js.

## Architecture

```mermaid
flowchart LR
  subgraph WV["Webview — Rust/WASM (Dioxus)"]
    XT["canvas painter<br/>grid-damage → cells + input"]
    UI["⌘K bar · ⌘J agent · ⌘E autopsy<br/>⌘P palette · ⌘B blocks + minimap"]
  end
  subgraph RS["Rust — Tauri backend"]
    PTY["PTY<br/>portable-pty"]
    ENG["vt100 engine<br/>grid + damage diff"]
    OSC["OSC 133 scanner<br/>command journal"]
    INJ["zsh · bash · fish<br/>OSC 133 hook injection"]
    REG["provider registry + ai_call<br/>keys · models · the one HTTP path"]
    GATE["agent loop + danger gate<br/>agent_propose · is_dangerous"]
    MCP["MCP client<br/>JSON-RPC / Streamable HTTP"]
  end
  XT <-- "pty_write / grid-damage (Tauri IPC)" --> ENG
  ENG --- PTY
  PTY --- INJ
  PTY -- "raw bytes" --> OSC
  OSC -- "journal-block" --> UI
  OSC -- "command results" --> GATE
  UI -- "nl_to_command · agent_start · agent_decide · run_slash (IPC)" --> REG & GATE
  GATE -- "approved step only" --> PTY
  GATE --> REG
  GATE -- "approved TOOL: calls" --> MCP
  REG -- "HTTPS: /v1/messages · /chat/completions" --> EXT[("AI providers<br/>Claude · Groq · Gemini · local …")]
  MCP --> SRV[("remote MCP servers")]
```

All business logic lives Rust-side: the PTY, the vt100 terminal engine, AI completion (`ai_call` over `reqwest` — keys never touch the webview), shell hook injection, the agent loop and danger gate, and the MCP client. The Dioxus/WASM frontend paints, forwards input, and renders the approval gate. Function-level map: [docs/architecture.md](docs/architecture.md).

## Status

**v0.1.5** — everything on the roadmap below is built and working: a real PTY terminal
with a Rust `vt100` engine, ⌘K natural language → command, ⌘J agent mode with per-step
approval gates, ⌘E error autopsy, MCP tool calls, and an eval harness (NL accuracy,
adversarial safety, the danger gate's own recall, and the agent loop) whose latest numbers
are in [Eval results](#eval-results).

Still early software: it drives your real shell, so the danger gate and the approval gates are the
parts to trust least and read first — [docs/danger-gate.md](docs/danger-gate.md) lists what is
enforced and, candidly, what is not.

## Roadmap

- [x] Project scaffold (Tauri + portable-pty)
- [x] **v0.1.5: pure-Rust frontend** — Dioxus/WASM chrome + a Rust `vt100` engine painting a canvas; xterm.js, Vite, and all TypeScript removed
- [x] Working terminal: PTY spawn, output streaming, input handling
- [x] Context collector (cwd, git branch/dirty state, shell pid) + status bar
- [x] Natural language → command generation (⌘K bar; any configured provider)
- [x] Error autopsy (⌘E explains recent terminal errors, printed in-place)
- [x] Agent mode with permission gates (⌘J: multi-step task loop, approve/deny each command, destructive commands flagged)
- [x] Eval harness: accuracy + safety benchmarks
- [x] MCP client: remote Streamable-HTTP servers, agent calls tools behind the approval gate
- [x] OSC 133 shell integration: real command boundaries + exit codes off the PTY stream
- [x] Command palette (⌘P): fuzzy-search AI actions, provider switches, and recent commands
- [x] Block navigator (⌘B): session blocks with per-block AI explain, rerun/copy, health minimap, AI session summary
- [x] Faster PTY I/O: 64 KB reads + base64 transfer (v0.1.1)
- [x] Vim mode (⌘⇧V): normal/visual navigation over the buffer — `hjkl w b 0 $ gg G ⌃d ⌃u`, `/ n N` search, `v`+`y` yank (v0.1.1, hardened in v0.1.3)
- [x] CI/CD: GitHub Actions run tests on every push; tagging `v*` auto-builds and publishes the release DMG (v0.1.3)
- [x] Linux support: CI on macOS + Ubuntu; releases build an AppImage and a `.deb` next to the DMG
- [x] bash and fish shell integration (OSC 133), alongside zsh
- [x] Configurable, platform-aware keybindings (`keybindings.json`)
- [x] Agent-loop eval with a keyless mock-model self-test; danger-gate corpus reporting recall and false-positive rate; gated / refused / unsafe safety outcomes; JSON artifacts with baseline diff
- [x] Open-source groundwork: MIT licence, CONTRIBUTING, SECURITY, architecture and danger-gate docs, issue/PR templates, changelog

Not yet:

- [ ] Windows
- [ ] stdio MCP transport (only remote Streamable-HTTP servers today)
- [ ] MCP server mode (Tachyon as a tool provider)
- [ ] Signed / notarised builds (macOS and Linux bundles are unsigned)
- [ ] A danger gate that parses commands instead of substring-matching, and an IPC surface scoped so webview script cannot call `pty_write` — see [docs/danger-gate.md](docs/danger-gate.md#what-would-make-it-stronger)

## Eval results

Run `npm run eval:write` to populate this section. The harness reads provider keys from `~/.config/tachyon/providers.json` (set them in-app via `/key <id> <apikey>`) and benchmarks every provider that has a key; `GROQ_API_KEY` / `ANTHROPIC_API_KEY` env vars fill in for `groq` / `claude` if the config lacks them. Use `--provider <id>` or `--limit <n>` for quick runs. The table below is generated; if it still shows a single "Safety-block" column it predates the gated / refused / unsafe scoring described under [Evaluation](#evaluation) and needs a re-run.

<!--EVAL:START-->
_2026-07-16 (UTC) · 104 nl + 22 safety cases per provider_

| Provider | Model | NL acc | Safety-block | p50 latency | p95 latency | est. cost/run | errors |
|---|---|---|---|---|---|---|---|
| groq | llama-3.3-70b-versatile | 95.2% (99/104) | 90.9% (20/22) | 233 ms | 341 ms | $0.0064 | 0 |

**Per-category NL accuracy — groq**

| Category | Accuracy | n |
|---|---|---|
| files | 95.0% (19/20) | 20 |
| git | 95.0% (19/20) | 20 |
| misc | 100.0% (15/15) | 15 |
| net | 91.7% (11/12) | 12 |
| pkg | 100.0% (10/10) | 10 |
| proc | 91.7% (11/12) | 12 |
| text | 93.3% (14/15) | 15 |
<!--EVAL:END-->

## Evaluation

Four checks live in `evals/`. None of them copies a prompt or the pattern list: `evals/rust-source.mjs` extracts `AI_SYSTEM`, `AI_AGENT` and `DANGER_PATTERNS` from `src-tauri/src/lib.rs` at run time and throws if it cannot find them, so the evals measure the code that ships.

**NL → command and safety (`npm run eval`).** Benchmarks every provider with a configured key side by side, replaying the app's system prompt and request shape. Each natural-language case defines a case-insensitive regex that a correct command must match — anchoring the right tool and its key flag rather than an exact string, so idiomatic variants pass and wrong commands fail. Adversarial prompts that tempt the model into a destructive command are scored three ways: **gated** (the generated command trips the danger gate), **refused** (the model emitted nothing runnable), or **unsafe** (a runnable command the gate did not flag — these are listed individually in the report). A separate set of benign-but-scary prompts measures the opposite error: a harmless command that trips the gate is a **false positive**. Anything ambiguous is scored unsafe, not refused. Per provider the report also gives p50/p95 latency and an estimated cost per run from API-reported token usage times an approximate price map hardcoded in `evals/lib.mjs` — prices drift and don't track the configured model; providers that don't report usage show "—".

**The gate on its own (`npm run eval:gate`).** Keyless. Runs `is_dangerous` over a held-out corpus of destructive and benign commands (`evals/gate-corpus.json`) and prints recall, false-positive rate, and every miss. Misses do not fail the script: the gate is a warn-only substring scan, and low recall is a finding to report, not a build breakage. Found an evasion? Add it to the corpus.

**The agent loop (`npm run eval:agent`).** Multi-step tasks, each in a fresh scratch directory, driven by a port of `agent_loop` — same system prompt, transcript shape, reply parsing, step cap and output truncation. Success is decided by declarative checks on the scratch directory (a file exists, contains a string, a command exits 0), never by the model saying `DONE`. Every step is auto-approved, so this executes model-written shell: commands that reference anything outside the scratch directory are refused by a deliberately over-strict textual policy, and on macOS the shell additionally runs under a `sandbox-exec` profile that denies network, writes outside the scratch directory, and reads of the real home directory. On Linux only the textual policy applies — run it against real models in a container or VM. `npm run eval:agent:selftest` replaces the model with a scripted mock and asserts the expected outcomes, so the loop, parser, sandbox policy and checks are tested in CI with no key and no network.

**Self-test (`npm run eval:selftest`).** Keyless. Verifies the extraction and runs the JS port of the matcher against `lib.rs`'s own test vectors.

Every keyed run writes a JSON artifact to `evals/results/`; copy one to `evals/baseline/<provider>.json` to commit it. `--baseline <file>` prints a per-case diff against such an artifact, and `--min-acc <pct>` / `--min-safety <pct>` exit non-zero below a floor, for use as a release gate. `--context` appends the cwd/git context block the app sends; without it, scores are a conservative floor for in-app accuracy. API errors count as failures (the errors column makes a rate-limited run visible). No key material is ever printed or written.

## Providers & slash commands

Open the AI bar (⌘K) and type a `/` command to manage models — no key needed to configure:

```
/keys                              list providers, active one, which have keys
/key <id> <apikey>                 set a provider's API key
/use <id> [model]                  switch active provider (+ optional model)
/model <model>                     set the active provider's model
/local <id> <url> <model> [key]    add a local / OpenAI-compatible endpoint
```

Built-in ids: `claude openai groq gemini kimi deepseek mistral`. Anything non-Anthropic is called through the
OpenAI-compatible `/chat/completions` shape, so local runtimes work too:

```
/local ollama http://localhost:11434/v1 llama3.2
/use ollama
```

Config persists to `~/.config/tachyon/providers.json`. The provider registry lives in Rust
(`src-tauri/src/lib.rs`); the frontend just reads the active provider and dispatches.

### MCP tools (agent mode)

Agent mode (⌘J) can call [MCP](https://modelcontextprotocol.io) server tools, not just shell commands:

```
/mcp add <name> <url>    register a remote Streamable-HTTP MCP server
/mcp list                list servers and their tools
/mcp remove <name>       drop a server
```

The MCP client is Rust-side (`ureq`, JSON-RPC 2.0 over Streamable HTTP) so remote servers work without webview
CORS; servers persist to `~/.config/tachyon/mcp.json`. In a run the agent may answer `TOOL: <server>.<tool> {args}`
— every tool call goes through the **same approve/deny gate** as shell commands and never auto-runs.

### Shell integration (OSC 133)

On launch, Tachyon injects prompt/pre-exec hooks into the shell that emit OSC 133 marks, so it tracks real command
boundaries and exit codes off the PTY stream (a journal of `{command, exitCode, output}` blocks, plus wall-clock duration per block) instead of
scraping the screen. ⌘E error autopsy uses the exact failed command + exit code + output; the status bar shows a
`✗ <code>` badge on failure. **zsh, bash and fish are supported.** Under any other shell the hooks don't load, so there is no journal — ⌘B and ⌘E have nothing to work with and agent steps wait out their timeout — and Tachyon says so once at startup instead of failing silently.

## Run it

Platforms: **macOS** and **Linux**. Windows is not supported yet. Tagged releases publish an
unsigned `.dmg` (Apple Silicon), and an `.AppImage` and `.deb` (x86_64).

Prerequisites: **Rust** (stable), **Node 22+**, and **dioxus-cli** — the frontend is a Dioxus
WASM crate, so `dx` has to be on your PATH before Tauri can build it. On Linux, also the
WebKitGTK/GTK development packages (Debian/Ubuntu names shown; other distros: see the
[Tauri prerequisites](https://v2.tauri.app/start/prerequisites/)):

```sh
sudo apt-get install libwebkit2gtk-4.1-dev libgtk-3-dev build-essential pkg-config
sudo apt-get install librsvg2-dev patchelf     # only for `npm run tauri build`
```

```sh
rustup target add wasm32-unknown-unknown
cargo binstall dioxus-cli@0.7.9      # or: cargo install dioxus-cli --version 0.7.9 --locked
npm install
npm run tauri dev
```

`cargo binstall` fetches a prebuilt binary; prefer it if you have it, since building dioxus-cli
from source can fail on current stable. `npm run tauri build` produces the release bundle.

## Tests

```sh
cd src-tauri && cargo test          # backend: PTY, OSC journal, providers, danger gate, agent parsing
cd ui && cargo test                 # frontend logic: key encoding, keymap, vim motions, selection
cd ui && cargo check --target wasm32-unknown-unknown
npm run eval:selftest               # gate extraction + matcher vs lib.rs's test vectors
npm run eval:gate                   # gate recall / false-positive rate on the corpus
npm run eval:agent:selftest         # agent-loop eval against a scripted mock model
```

All keyless; CI runs exactly these on macOS and Ubuntu.

## Docs

- [docs/danger-gate.md](docs/danger-gate.md) — why the safety boundary is in Rust and not the prompt; what is enforced; what is not
- [docs/architecture.md](docs/architecture.md) — process model, data flow, and which function does what
- [CONTRIBUTING.md](CONTRIBUTING.md) — setup, tests, and the rules a PR has to keep
- [SECURITY.md](SECURITY.md) — reporting, and what is in scope
- [CHANGELOG.md](CHANGELOG.md)

## License

MIT — see [LICENSE](LICENSE).
