//! Status bar — always visible. cwd (~-abbreviated via homeDir), git branch/dirty,
//! last command exit, and the vim indicator. Mirrors main.ts refreshContext
//! (lines 699-732): refetch get_context after each finished command; the vim
//! indicator maps `state.vim_mode` to a class.

use dioxus::prelude::*;
use serde::Deserialize;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::spawn_local;

use crate::app::{AppState, VimMode};
use crate::bridge::{invoke, NoArgs};

#[wasm_bindgen]
extern "C" {
    // window.__TAURI__.path.homeDir() -> Promise<string>
    #[wasm_bindgen(js_namespace = ["window", "__TAURI__", "path"], js_name = homeDir, catch)]
    async fn tauri_home_dir() -> Result<JsValue, JsValue>;
}

#[derive(Deserialize, Default)]
struct ShellContext {
    #[serde(default)]
    cwd: Option<String>,
    #[serde(default)]
    branch: Option<String>,
    #[serde(default)]
    dirty: i64,
}

/// `~`-abbreviate an absolute cwd, mirroring main.ts (cwd==home → "~";
/// under home → "~/rest"; else the raw path).
fn abbrev(cwd: &str, home: &str) -> String {
    if cwd.is_empty() {
        return String::new();
    }
    if !home.is_empty() {
        if cwd == home {
            return "~".into();
        }
        if let Some(rest) = cwd.strip_prefix(home).filter(|r| r.starts_with('/')) {
            return format!("~{rest}");
        }
    }
    cwd.to_string()
}

#[component]
pub fn StatusBar() -> Element {
    let state = use_context::<AppState>();
    let mut cwd = use_signal(String::new);
    let mut git = use_signal(String::new);
    let mut home = use_signal(String::new);

    // home dir once (trailing slash stripped like main.ts). Best-effort.
    use_effect(move || {
        spawn_local(async move {
            if let Ok(h) = tauri_home_dir().await {
                if let Some(h) = h.as_string() {
                    home.set(h.trim_end_matches('/').to_string());
                }
            }
        });
    });

    // Refetch cwd/branch/dirty on mount, whenever a command finishes (journal grows
    // → cwd/git may have moved), and once home resolves so the path re-abbreviates.
    // ponytail: no 300ms debounce — journal-block events don't burst like keystrokes.
    use_effect(move || {
        let _ = state.journal.read(); // reactive dep: refetch after each command
        let home = home.read().clone(); // reactive dep: re-abbreviate once home lands
        spawn_local(async move {
            if let Ok(v) = invoke("get_context", NoArgs {}).await {
                if let Ok(ctx) = serde_wasm_bindgen::from_value::<ShellContext>(v) {
                    cwd.set(abbrev(&ctx.cwd.unwrap_or_default(), &home));
                    git.set(match ctx.branch {
                        Some(b) if !b.is_empty() && ctx.dirty > 0 => format!("⎇ {b} ±{}", ctx.dirty),
                        Some(b) if !b.is_empty() => format!("⎇ {b}"),
                        _ => String::new(),
                    });
                }
            }
        });
    });

    // last-exit is derived from the journal directly (main.ts lastBlock()).
    let exit_part = match state.journal.read().last() {
        Some(b) if b.exit_code != 0 => format!(" ✗ {}", b.exit_code),
        _ => String::new(),
    };

    let vim_class = match *state.vim_mode.read() {
        VimMode::Insert => "",
        VimMode::Normal => "normal",
        VimMode::Visual => "visual",
    };

    rsx! {
        div { id: "status-bar",
            span { id: "status-cwd", "{cwd}" }
            span { id: "status-git", "{git}{exit_part}" }
            span { id: "status-vim", class: "{vim_class}" }
        }
    }
}
