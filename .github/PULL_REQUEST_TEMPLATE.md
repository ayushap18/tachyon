**What and why**
<!-- The mechanism of the bug, or the reason for the design. Link the issue. -->

**How it was tested**
<!-- Commands run; for ui/ changes, what you exercised in the running app and on which OS. -->

**Checklist**
- [ ] `cargo test` passes in each crate I touched (`src-tauri/`, `ui/`)
- [ ] `ui/` still passes `cargo check --target wasm32-unknown-unknown`
- [ ] `npm run eval:selftest`, `eval:gate` and `eval:agent:selftest` pass if I touched prompts, the danger gate, or the agent loop
- [ ] No new caller of `pty_write_internal`; nothing model-controlled reaches the PTY with a newline
- [ ] No API key in an IPC return value, error string, or log
- [ ] New network call, subprocess or wait has a timeout or abort path
- [ ] CHANGELOG.md updated under Unreleased, if user-visible
