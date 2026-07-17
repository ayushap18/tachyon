//! Settings panel (⌘,) — theme/font/size controls (main.ts 117-143 + applySettings
//! 93-114). The gear button is always visible; the panel renders when
//! Overlay::Settings is open. Writing `state.settings` triggers the app.rs effect
//! that applies the theme + persists to localStorage — we only additionally repaint
//! the native terminal on theme change (main.ts's `term.options.theme = ...`).

use dioxus::prelude::*;
use serde::Serialize;
use wasm_bindgen_futures::spawn_local;

use crate::app::{AppState, Overlay};
use crate::bridge::invoke;
use crate::theme::{FONTS, THEME_NAMES};

#[derive(Serialize)]
struct ThemeArg {
    name: String,
}

#[component]
pub fn SettingsPanel() -> Element {
    let state = use_context::<AppState>();
    let cur = state.settings.read().clone();

    rsx! {
        button {
            id: "settings-btn",
            title: "Settings (⌘,)",
            onclick: move |_| state.toggle(Overlay::Settings),
            "⚙"
        }
        if state.is_open(Overlay::Settings) {
            div { id: "settings",
                label {
                    "Theme "
                    select {
                        onchange: move |e| {
                            let name = e.value();
                            let mut s = state.settings;
                            s.write().theme = name.clone();
                            spawn_local(async move {
                                let _ = invoke("term_set_theme", ThemeArg { name }).await;
                            });
                        },
                        for t in THEME_NAMES {
                            option { selected: t == cur.theme, "{t}" }
                        }
                    }
                }
                label {
                    "Font "
                    select {
                        onchange: move |e| {
                            let mut s = state.settings;
                            s.write().font = e.value();
                        },
                        for f in FONTS {
                            option { selected: f == cur.font, "{f}" }
                        }
                    }
                }
                label {
                    "Size "
                    input {
                        r#type: "number",
                        min: "9",
                        max: "28",
                        value: "{cur.size}",
                        onchange: move |e| {
                            let n = e.value().parse::<u32>().unwrap_or(14).clamp(9, 28);
                            let mut s = state.settings;
                            s.write().size = n;
                        },
                    }
                }
            }
        }
    }
}
