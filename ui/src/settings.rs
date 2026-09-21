//! Settings panel (⌘,) — theme/font/size/opacity controls. The gear button is
//! always visible; the panel renders when
//! Overlay::Settings is open. Every control only writes `state.settings`; the app.rs
//! effect applies the theme, persists to localStorage and repaints the native terminal.

use dioxus::prelude::*;

use crate::app::{AppState, Overlay};
use crate::keymap::{self, Action};
use crate::theme::{fonts, THEME_NAMES};

#[component]
pub fn SettingsPanel() -> Element {
    let state = use_context::<AppState>();
    let cur = state.settings.read().clone();
    let _ = state.keys_loaded.read(); // reactive dep: the tooltip shows the active binding
    let title = format!("Settings ({})", keymap::label(Action::Settings));

    rsx! {
        button {
            id: "settings-btn",
            title: "{title}",
            onclick: move |_| state.toggle(Overlay::Settings),
            "⚙"
        }
        if state.is_open(Overlay::Settings) {
            div { id: "settings",
                label {
                    "Theme "
                    select {
                        onchange: move |e| {
                            let mut s = state.settings;
                            s.write().theme = e.value();
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
                        for f in fonts().iter().copied() {
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
                label {
                    title: "See-through window. Anything behind Tachyon is visible in a screen share.",
                    "Opacity "
                    input {
                        r#type: "range",
                        min: "40",
                        max: "100",
                        step: "5",
                        value: "{cur.opacity}",
                        // oninput, not onchange: the app.rs effect carries every step to
                        // term_set_theme, so the window fades as the slider moves.
                        oninput: move |e| {
                            let n = e.value().parse::<u8>().unwrap_or(100).clamp(40, 100);
                            let mut s = state.settings;
                            s.write().opacity = n;
                        },
                    }
                }
            }
        }
    }
}
