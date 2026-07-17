//! Command palette (⌘P). Ported from src/main.ts lines 387-502: a subsequence
//! fuzzy filter over static actions + provider switches (from `provider_state`)
//! + recent journal commands, with arrow/enter/esc navigation.

use std::collections::HashSet;

use dioxus::prelude::*;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::{spawn_local, JsFuture};

use crate::app::{AppState, Overlay, VimMode};
use crate::bridge::invoke;

#[wasm_bindgen]
extern "C" {
    // window.__TAURI__.app.getVersion() -> Promise<string>
    #[wasm_bindgen(js_namespace = ["window", "__TAURI__", "app"], js_name = getVersion)]
    fn tauri_get_version() -> js_sys::Promise;
}

#[derive(Serialize)]
struct NoArgs {}
#[derive(Serialize)]
struct IdArgs {
    id: String,
}
#[derive(Serialize)]
struct WriteArgs {
    data: String,
}

#[derive(Deserialize)]
struct ProviderInfo {
    id: String,
    #[serde(default)]
    model: String,
}
#[derive(Deserialize)]
struct ProviderState {
    #[serde(default)]
    active: String,
    #[serde(default)]
    providers: Vec<ProviderInfo>,
}

/// What a palette entry does when selected.
#[derive(Clone, PartialEq)]
enum Act {
    AiBar,
    Agent,
    Explain,
    Blocks,
    Vim,
    Settings,
    Provider(String),
    Run(String),
}

/// subsequence fuzzy match (needle chars appear in order within label).
fn fuzzy(label: &str, needle: &str) -> bool {
    let n: Vec<char> = needle.to_lowercase().chars().collect();
    let mut i = 0;
    for ch in label.to_lowercase().chars() {
        if i < n.len() && ch == n[i] {
            i += 1;
        }
    }
    i == n.len()
}

/// Close the palette and run the action (mirrors closePalette() + entry.run()).
fn run(state: AppState, act: Act) {
    match act {
        Act::AiBar => state.overlay.clone().set(Overlay::AiBar),
        Act::Agent => state.overlay.clone().set(Overlay::Agent),
        Act::Blocks => state.overlay.clone().set(Overlay::Blocks),
        Act::Settings => state.overlay.clone().set(Overlay::Settings),
        Act::Vim => {
            state.vim_mode.clone().set(VimMode::Normal);
            state.close();
        }
        Act::Explain => {
            spawn_local(async move {
                let _ = invoke("explain_last_error", NoArgs {}).await;
            });
            state.close();
        }
        Act::Provider(id) => {
            state.provider_active.clone().set(id.clone());
            spawn_local(async move {
                let _ = invoke("provider_use", IdArgs { id }).await;
            });
            // ponytail: skipped the cyan "active provider" echo to the terminal —
            // no term-write API exists on the Rust side (main.ts used term.write).
            state.close();
        }
        Act::Run(cmd) => {
            spawn_local(async move {
                let _ = invoke("pty_write", WriteArgs { data: cmd }).await;
            });
            state.close();
        }
    }
}

#[component]
pub fn Palette() -> Element {
    let state = use_context::<AppState>();
    let mut query = use_signal(String::new);
    let mut sel = use_signal(|| 0usize);
    let mut providers = use_signal(Vec::<(String, String, bool)>::new);
    let mut version = use_signal(String::new);

    // App version (bottom-right), fetched once — best-effort cosmetic.
    use_effect(move || {
        spawn_local(async move {
            if let Ok(v) = JsFuture::from(tauri_get_version()).await {
                if let Some(s) = v.as_string() {
                    version.set(format!("v{s}"));
                }
            }
        });
    });

    // On open: reset query/selection and (re)fetch the provider list.
    use_effect(move || {
        if state.is_open(Overlay::Palette) {
            query.set(String::new());
            sel.set(0);
            spawn_local(async move {
                if let Ok(v) = invoke("provider_state", NoArgs {}).await {
                    if let Ok(ps) = serde_wasm_bindgen::from_value::<ProviderState>(v) {
                        let list = ps
                            .providers
                            .into_iter()
                            .map(|p| {
                                let active = p.id == ps.active;
                                (p.id, p.model, active)
                            })
                            .collect();
                        providers.set(list);
                    }
                }
            });
        }
    });

    if !state.is_open(Overlay::Palette) {
        return rsx! {};
    }

    // ---- build the entry list (static + providers + recent commands) ----
    let mut entries: Vec<(String, String, Act)> = vec![
        ("AI command".into(), "⌘K".into(), Act::AiBar),
        ("Agent: run a task".into(), "⌘J".into(), Act::Agent),
        ("Explain last error".into(), "⌘E".into(), Act::Explain),
        ("Blocks: session navigator".into(), "⌘B".into(), Act::Blocks),
        ("Vim mode".into(), "⌘⇧V".into(), Act::Vim),
        ("Settings".into(), "⌘,".into(), Act::Settings),
    ];
    for (id, model, active) in providers.read().iter() {
        let hint = if *active { "active".to_string() } else { model.clone() };
        entries.push((format!("Use provider: {id}"), hint, Act::Provider(id.clone())));
    }
    // recent commands from the journal (deduped, newest first, skipping noise)
    let mut seen: HashSet<String> = HashSet::new();
    for b in state.journal.read().iter().rev() {
        if seen.len() >= 15 {
            break;
        }
        let c = b.command.trim();
        let noise = c.is_empty()
            || c.contains("_tachyon")
            || c.contains("print -n")
            || c.ends_with('%')
            || c.len() > 120;
        if !noise && seen.insert(c.to_string()) {
            entries.push((c.to_string(), "history".into(), Act::Run(c.to_string())));
        }
    }

    // filter by fuzzy match on the label
    let q = query.read().trim().to_string();
    let shown: Vec<(String, String, Act)> = if q.is_empty() {
        entries
    } else {
        entries.into_iter().filter(|(label, _, _)| fuzzy(label, &q)).collect()
    };

    // clamp selection into range
    let sel_val = (*sel.read()).min(shown.len().saturating_sub(1));

    let shown_for_key = shown.clone();
    rsx! {
        div { id: "palette",
            input {
                id: "palette-input",
                value: "{query}",
                autofocus: true,
                onmounted: move |e| {
                    spawn(async move {
                        let _ = e.set_focus(true).await;
                    });
                },
                oninput: move |e| {
                    query.set(e.value());
                    sel.set(0);
                },
                onkeydown: move |e| {
                    match e.key().to_string().as_str() {
                        "Escape" => {
                            e.prevent_default();
                            state.close();
                        }
                        "ArrowDown" => {
                            e.prevent_default();
                            let n = shown_for_key.len();
                            sel.set((sel_val + 1).min(n.saturating_sub(1)));
                        }
                        "ArrowUp" => {
                            e.prevent_default();
                            sel.set(sel_val.saturating_sub(1));
                        }
                        "Enter" => {
                            e.prevent_default();
                            if let Some(entry) = shown_for_key.get(sel_val) {
                                run(state, entry.2.clone());
                            }
                        }
                        _ => {}
                    }
                },
            }
            ul { id: "palette-list",
                for (i , (label , hint , act)) in shown.into_iter().enumerate() {
                    li {
                        key: "{i}-{label}",
                        class: if i == sel_val { "sel" } else { "" },
                        onclick: move |_| run(state, act.clone()),
                        span { class: "label", "{label}" }
                        span { class: "hint", "{hint}" }
                    }
                }
            }
            div { id: "palette-version", "{version}" }
        }
    }
}
