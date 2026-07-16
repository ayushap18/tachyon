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
- [ ] Error autopsy
- [ ] Agent mode with permission gates
- [ ] Eval harness: accuracy + safety benchmarks

## Run it

```sh
npm install
npm run tauri dev
```
