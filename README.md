# ⚡ Tachyon

An AI-native terminal, inspired by Warp — built from scratch to learn how modern terminals and AI agents actually work.

## What I'm building

A desktop terminal where AI is a first-class citizen, not a bolted-on chatbot:

- **Real terminal first** — a native app (Tauri + Rust) driving a real shell through a PTY, rendered with xterm.js
- **Natural language → commands** — type *"undo my last commit but keep the changes"* and get the right `git` incantation, aware of your cwd, git state, and recent history
- **Agent mode** — describe a multi-step task, the agent plans the commands, shows them, and executes step-by-step with explicit approve/deny gates
- **Error autopsy** — when a command fails, one keystroke explains the actual stderr and suggests a fix
- **Safety rails** — destructive commands (`rm -rf`-class) are detected and always require confirmation, backed by an adversarial safety eval
- **Evals, not vibes** — a benchmark suite measuring command-generation accuracy and safety-block rate across prompt/model versions

## Stack

| Layer | Choice |
|-------|--------|
| Shell/PTY | Rust, `portable-pty` |
| App shell | Tauri 2 |
| Rendering | xterm.js |
| Frontend | TypeScript + Vite |

The terminal emulator layer deliberately reuses xterm.js instead of a custom GPU renderer — the interesting problems here are the AI layer, context management, and safety, not reimplementing VT100 parsing.

## Status

🚧 Early days — it's a working terminal; AI layer up next.

## Roadmap

- [x] Project scaffold (Tauri + xterm.js + portable-pty)
- [x] Working terminal: PTY spawn, output streaming, input handling
- [x] Context collector (cwd, git branch/dirty state, shell pid) + status bar
- [x] Natural language → command generation (⌘K bar; Claude or Groq via API key)
- [x] Error autopsy (⌘E explains recent terminal errors, printed in-place)
- [x] Agent mode with permission gates (⌘J: multi-step task loop, approve/deny each command, danger hard-gated)
- [x] Eval harness: accuracy + safety benchmarks

## Eval results

Run with `GROQ_API_KEY=gsk_... npm run eval -- --write` (or `ANTHROPIC_API_KEY=...`) to populate this section.

<!--EVAL:START-->
_run `npm run eval` to populate_
<!--EVAL:END-->

## Evaluation

The harness (`evals/`) replays the app's exact system prompt against 100+ natural-language cases; each case defines a case-insensitive regex that a correct command must match — anchoring the right tool and its key flag rather than an exact command string, so idiomatic variants pass while wrong commands fail. A second set of 20+ adversarial prompts tempts the model into destructive commands and scores whether the generated command trips the danger gate (the safety-block rate). The JS detector in `evals/danger.mjs` is an exact mirror of the Rust `is_dangerous` gate in `src-tauri/src/lib.rs`; `npm run eval:selftest` verifies the mirror against known-dangerous/known-safe commands with no API key. Caveats, honestly stated: a dangerous command that evades the substring gate counts as a miss (the gate is naive by design), and eval prompts are sent without the app's cwd/git context block, so scores are a conservative floor for in-app accuracy.

## Run it

```sh
npm install
npm run tauri dev
```
