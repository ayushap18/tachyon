# Contributing to Tachyon

Bug reports, fixes and bypass reports are all welcome. For anything larger than a fix, open
an issue first so the design is agreed before the code is written. Start with
[docs/architecture.md](docs/architecture.md) for where things live.

## Prerequisites

- Rust stable, plus the wasm target: `rustup target add wasm32-unknown-unknown`
- dioxus-cli **0.7.9**: `cargo binstall dioxus-cli@0.7.9`
  (a source build — `cargo install dioxus-cli --version 0.7.9 --locked` — can fail on current stable)
- Node 22+ (`npm install` fetches the Tauri CLI; the eval scripts themselves use only the node stdlib)
- macOS: Xcode command line tools
- Linux (Debian/Ubuntu):

  ```sh
  sudo apt-get install libwebkit2gtk-4.1-dev libgtk-3-dev build-essential pkg-config
  # only for `npm run tauri build` (AppImage/.deb bundling):
  sudo apt-get install librsvg2-dev patchelf
  ```

  Other distros: the WebKitGTK 4.1 and GTK 3 development packages from the
  [Tauri v2 prerequisites](https://v2.tauri.app/start/prerequisites/). The clipboard uses X11
  via a pure-Rust client, so no xcb headers are needed.
- Windows is not supported yet.

## Run and test

```sh
npm install
npm run tauri dev                      # builds ui/ with dx, then runs the app

cd src-tauri && cargo test             # backend
cd ui && cargo test                    # frontend logic, on the host
cd ui && cargo check --target wasm32-unknown-unknown
npm run eval:selftest                  # danger gate vs. lib.rs's own test vectors
npm run eval:gate                      # gate recall / false-positive rate on the corpus
npm run eval:agent:selftest            # agent-loop eval with a scripted mock model
```

All of the above are keyless and are exactly what CI runs on macOS and Ubuntu. `npm run eval`
and `npm run eval:agent` call real providers and need a key in `~/.config/tachyon/providers.json`.
Nothing tests the webview end to end: if you touch `ui/`, run the app and say in the PR what
you exercised.

`src-tauri/` and `ui/` are separate Cargo workspaces. Run `cargo` from inside each.

## Rules that are not negotiable

1. **Nothing writes to the PTY except through the approved path.** `pty_write_internal` has
   two callers: the `pty_write` command (user input, prefill without a newline) and the single
   line inside the approved branch of `agent_loop`. Do not add a third. Text for the user to
   read goes through `term_write`, which only paints. A feature that offers a command
   prefills it without `\n` and strips embedded newlines. See [docs/danger-gate.md](docs/danger-gate.md).
2. **Every failure of the approval gate is a denial.** Dropped sender, abort, panic, stale
   decision — all resolve to `false`. No approval timeouts, no "remember this choice".
3. **API keys never cross IPC and never appear in a string.** Return `PublicProvider`, not
   `Provider`. Keys go in request headers only — not in errors, logs, or eval output.
4. **A config file that does not parse is an error, not a reset.** Use `read_config` /
   `write_config`; do not call `fs::write` on anything in `config_dir()`.
5. **Nothing may hang forever.** Network calls, subprocesses and waits get a timeout or an
   abort path.
6. **Evals read the shipped code.** Prompts and `DANGER_PATTERNS` are extracted from
   `src-tauri/src/lib.rs` by `evals/rust-source.mjs`. If you rename them, update the extractor
   in the same PR. Do not hand-edit the README block between `<!--EVAL:START-->` and
   `<!--EVAL:END-->`; `npm run eval:write` generates it.

## Code style

- The tree is not rustfmt-normalised (there is no `rustfmt.toml` and many lines exceed the
  default width). Match the surrounding style and do not reformat lines you are not changing;
  a whole-file `cargo fmt` buries the real diff. No new `cargo clippy` warnings.
- Prefer the smaller change: the standard library, an existing helper, or a dependency
  already in `Cargo.toml` before a new one.
- A deliberate shortcut with a known ceiling gets a `// ponytail:` comment naming the ceiling
  and the upgrade path. Grep for existing examples.
- Comments explain why, and what broke before. Non-trivial logic gets a unit test next to it
  in the same file's `mod tests`.

## Commits and pull requests

Commit subjects follow the existing log: `<area or version>: <what changed, in plain words>` —
for example `Phase 1.3: nothing may hang forever` or
`OSC 133 shell integration: zsh hooks + PTY-stream journal`. The body explains the mechanism
of the bug or the reason for the design, and lists anything deliberately left undone. No
tool or assistant attribution trailers.

One logical change per PR. Fill in the PR template; add a line under **Unreleased** in
[CHANGELOG.md](CHANGELOG.md) for anything a user would notice.

## Cutting a beta

A tag with a hyphen is a prerelease — `v0.3.0-beta.0`. There is no separate workflow or branch:
the same `.github/workflows/release.yml` builds it, and `npm run test:release` pins the shape.

1. In one commit set the same version string in `package.json`, `src-tauri/tauri.conf.json`,
   `src-tauri/Cargo.toml`, `ui/Cargo.toml` and the `Tachyon_<version>_*` filenames in README.md.
   The workflow refuses a tag that disagrees with the first four; `npm run test:release` refuses
   a README that names a different version.
2. Tag that commit and push the tag — `tags: ['v*']` starts the build.
3. The workflow marks any hyphenated tag `--prerelease` and skips `--latest`. That is the whole
   safeguard: the updater endpoint is `releases/latest/download/latest.json`, and GitHub never
   resolves `releases/latest` to a prerelease, so installed stable copies are not offered the
   beta — ⌘U keeps waiting for the next stable release. Never hand-edit a beta on GitHub to
   "Set as the latest release"; that alone would push it to every user.
4. Installers carry the suffix verbatim (`Tachyon_0.3.0-beta.0_aarch64.dmg`) because the bundler
   interpolates `tauri.conf.json`'s version into `<productName>_<version>_<arch>`. The macOS
   updater tarball `Tachyon.app.tar.gz` is unversioned, so it is the same name on every channel.
   A name the bundler spells differently fails the publish with `Expected exactly one …` rather
   than shipping a partial release.
5. Testers install the beta by hand. To retire it, delete the GitHub release and the tag —
   nothing else points at either.

## Security issues

Do not open a public issue for a vulnerability. See [SECURITY.md](SECURITY.md).

## Licence

Contributions are accepted under the [MIT licence](LICENSE).
