//! Status bar — always visible. cwd (~-abbreviated via homeDir), git branch/dirty,
//! last command exit, and the vim indicator. get_context is refetched after each
//! finished command; the vim indicator maps `state.vim_mode` to a class.

use dioxus::prelude::*;
use serde::Deserialize;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::spawn_local;

use crate::app::{AppState, VimMode};
use crate::bridge::{invoke, listen, NoArgs};

/// What the Rust-side periodic check emits. The notes are already sanitised and capped
/// there (`update::notes`); rendering them as a text node escapes them a second time.
#[derive(Deserialize)]
struct UpdateAvailable {
    version: String,
    #[serde(default)]
    notes: String,
}

const SKIP_KEY: &str = "tachyon.skip-update";

fn skipped() -> Option<String> {
    web_sys::window()?.local_storage().ok()??.get_item(SKIP_KEY).ok()?
}

/// The skip list is frontend state and can suppress a notification, nothing else.
fn should_show(version: &str, skipped: Option<&str>) -> bool {
    Some(version) != skipped
}

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

/// `~`-abbreviate an absolute cwd (cwd==home → "~";
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
    let mut update = use_signal(|| None::<(String, String)>);
    let mut notes_open = use_signal(|| false);

    use_effect(move || {
        listen("update-available", move |payload| {
            if let Ok(u) = serde_wasm_bindgen::from_value::<UpdateAvailable>(payload) {
                if should_show(&u.version, skipped().as_deref()) {
                    update.set(Some((u.version, u.notes)));
                }
            }
        });
    });

    // home dir once, trailing slash stripped. Best-effort.
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
    // ponytail: no debounce — mount, home and a journal block do land together, but
    // get_context runs its probes off the async runtime, so the calls overlap instead of
    // queueing. Add one if the probe spawns themselves get expensive.
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

    // last-exit is derived from the journal directly.
    let exit_part = match state.journal.read().last() {
        Some(b) if b.exit_code != 0 => format!(" ✗ {}", b.exit_code),
        _ => String::new(),
    };

    let vim_class = match *state.vim_mode.read() {
        VimMode::Insert => "",
        VimMode::Normal => "normal",
        VimMode::Visual => "visual",
    };

    // The pill is built outside rsx so the version can be cloned into the skip handler.
    let pill = update.read().clone().map(|(version, notes)| {
        let skip = version.clone();
        rsx! {
            span { id: "status-update",
                span {
                    title: "Release notes",
                    onclick: move |_| notes_open.set(!notes_open()),
                    "\u{21e7} {version}"
                }
                if notes_open() && !notes.is_empty() {
                    span { class: "note", " \u{2014} {notes}" }
                }
                span {
                    class: "skip",
                    onclick: move |_| {
                        if let Some(ls) = web_sys::window().and_then(|w| w.local_storage().ok().flatten()) {
                            let _ = ls.set_item(SKIP_KEY, &skip);
                        }
                        update.set(None);
                    },
                    " skip"
                }
            }
        }
    });

    rsx! {
        div { id: "status-bar",
            span { id: "status-cwd", "{cwd}" }
            span { id: "status-git", "{git}{exit_part}" }
            span { id: "status-vim", class: "{vim_class}" }
            {pill}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::should_show;

    #[test]
    fn skip_suppresses_only_the_skipped_version() {
        assert!(should_show("0.2.9", None));
        assert!(!should_show("0.2.9", Some("0.2.9")));
        // The next release is news again, and a stale entry never hides it.
        assert!(should_show("0.3.0", Some("0.2.9")));
    }
}
