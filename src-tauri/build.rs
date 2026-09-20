fn main() {
    // tauri's context macro refuses to compile when `frontendDist` (../ui/dist) is missing.
    // That directory is a gitignored build product of `ui/build-web.sh`, so on a fresh clone
    // — and in CI, which never runs dx — `cargo check`/`cargo test` failed before reaching
    // any Rust. A placeholder is enough to compile and test; `tauri dev`/`tauri build`
    // overwrite it with the real frontend via beforeDev/beforeBuildCommand.
    let index = std::path::Path::new("../ui/dist/index.html");
    if !index.exists() {
        if let Some(dir) = index.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let _ = std::fs::write(index, "<!-- placeholder: run ui/build-web.sh for the real frontend -->\n");
    }
    tauri_build::build()
}
