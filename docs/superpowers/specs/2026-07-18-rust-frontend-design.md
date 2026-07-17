# Tachyon v0.1.5-beta — Pure-Rust Frontend (Dioxus + alacritty_terminal)

**Status:** approved 2026-07-18. Branch `v0.1.5-rust-frontend`.

## Goal
Replace the TypeScript/xterm.js frontend with a pure-Rust one: a Dioxus (0.7,
WASM) app hosting the chrome, and Alacritty's terminal engine
(`alacritty_terminal` + `vte`) running in **native** Rust owning the grid.
Delete xterm.js, Vite, TypeScript, npm. The webview stays (Tauri needs it).

Non-goal: rewriting business logic — it already moved to native Rust in
v0.1.4-beta.2. This is a frontend + terminal-render swap only.

## Architecture
```
PTY bytes ─▶ [native Rust / src-tauri]
                alacritty_terminal::Term  ← grid, scrollback, selection, cursor
                │  emits "grid-damage" (changed cells + cursor) over Tauri IPC
                ▼
             [Dioxus WASM frontend]  ← paints <canvas>, hosts chrome as RSX
                │  keystrokes ─▶ invoke("pty_write")
                ▼
             existing 16 Rust commands (unchanged)
```

## Contract that MUST NOT change
16 commands stay byte-identical (signatures + behavior):
`pty_spawn, pty_write, pty_resize, set_typed_command, provider_active,
provider_state, provider_use, ai_complete, nl_to_command, explain_last_error,
run_slash, agent_start, agent_decide, agent_abort, journal_blocks, get_context`.

7 events stay: `pty-exit, agent-status, agent-output, agent-done,
agent-propose, journal-block` unchanged. **Only `pty-output` changes**: today
it ships base64 raw bytes for xterm to parse; now native Rust feeds those bytes
into `alacritty_terminal` and emits `grid-damage` instead. `agent-output` /
`explain_last_error` text that today is `term.write`-n with ANSI must instead be
injected into the same grid (write to a synthetic line or into the PTY-echo
path) so it still renders.

## Native engine changes (src-tauri)
- Add deps: `alacritty_terminal`, `vte` (its re-export is fine).
- PTY reader thread: keep reading raw bytes and keep the OSC-133 journal scan
  (untouched). ADD: feed the same bytes into a `Term` via its `Processor`.
- After each read, compute damage (Alacritty's `Term::damage()` or a full-grid
  snapshot on first paint) and `emit("grid-damage", GridDamage)`.
- `GridDamage`: `{ cols, rows, cursor: {line,col,shape,visible}, cells: [{line,
  col, c, fg, bg, flags}] }`. Colors resolved to rgb via the active theme's
  Alacritty `Colors`. Keep it compact — only changed cells.
- `pty_resize` also resizes the `Term`.
- Theme: map the 6 existing themes (Tokyo Night, Dracula, Nord, Solarized
  Dark/Light, Matrix) to Alacritty `Colors` (16 ANSI + fg/bg/cursor).

## Dioxus frontend (new crate `ui/`)
Builds with `dx build` → static assets; Tauri `frontendDist` points there.
Components (each its own module, one purpose):
- `terminal.rs` — `<canvas>`; `use_effect` paints the grid from `grid-damage`
  events; keydown → encode → `pty_write`; reconstructs `typedLine` for
  `set_typed_command` exactly as the TS did (lines 673-695); resize →
  `pty_resize`; ⌘⇧V toggles vim.
- `settings.rs` — theme/font/size panel; persists to localStorage; ⌘,.
- `ai_bar.rs` — ⌘K command / ⌘J agent, the approval gate (agent-propose /
  agent_decide), ⌘E explain. Port lines 179-385 faithfully — the gate is the
  trust boundary, do not weaken it.
- `blocks.rs` — ⌘B navigator + minimap + per-block explain/rerun/copy/summary.
- `palette.rs` — ⌘P fuzzy launcher (subsequence match, history from journal).
- `status.rs` — cwd/git/vim status bar; `get_context` on a 300ms debounce.
- `vim.rs` — port of src/vim.ts (270 lines) navigation + search.
- `theme.rs` — 6 themes → chrome tokens (accent/surface/border/…) as today.
- `app.rs` — wires them, owns the journal mirror (seed via `journal_blocks`,
  append via `journal-block`), global keybindings.

## Build / toolchain
- `dx` 0.7.9 (prebuilt, installed to ~/.cargo/bin). wasm32 target added.
- `tauri.conf.json`: `beforeDevCommand` → `dx serve` (or dev asset dir),
  `beforeBuildCommand` → `dx build --release`, `frontendDist` → dx output dir,
  `devUrl` → dx dev server.
- Delete: `package.json`, `package-lock.json`, `node_modules`, `vite.config.ts`,
  `tsconfig.json`, `index.html` (Vite one), `src/*.ts`, `@xterm/*`.

## Testing (zero-errors bar)
1. Native unit tests (extend the 54): grid-damage diff correctness, keystroke
   encoding, theme→Colors mapping, resize.
2. `wasm-bindgen-test` for chrome components (fuzzy match, palette filtering).
3. **Golden-master parity harness**: recorded PTY byte streams (vim, htop, ls
   --color, wide/CJK, cursor moves, resize) → assert the Alacritty grid matches
   the expected cell grid. This catches the ANSI edge-case regressions.
4. `cargo build` + `cargo clippy -- -D warnings` + `dx build` all clean; app
   launches and renders a real shell.

## Known ceiling (flagged)
`alacritty_terminal` grid ≠ xterm pixel rendering. Ligatures, some Powerline
glyphs, sixel/image protocols may differ or drop.
`// ponytail: canvas 2D cell painter; swap to WebGL only if paint latency shows under load`

## Out of scope
- No new terminal features. Parity with v0.1.4 chrome, new render engine.
- No merge to main in this branch; ship as v0.1.5-beta, push, decide later.
