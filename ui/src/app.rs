//! Shared chrome scaffold: app-wide state (a Dioxus context), the global
//! keybinding handler, theme application, and the journal mirror. Overlay
//! bodies live in their own modules (settings/ai_bar/blocks/palette/status/vim)
//! and read this context.

use dioxus::prelude::*;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::spawn_local;
use web_sys::KeyboardEvent;

use crate::ai_bar::AiBar;
use crate::blocks::BlocksPanel;
use crate::bridge::{invoke, listen};
use crate::palette::Palette;
use crate::settings::SettingsPanel;
use crate::status::StatusBar;
use crate::terminal::Terminal;
use crate::theme;
use crate::vim::VimSearch;

const MAIN_CSS: Asset = asset!("/assets/main.css");

// ---- shared data types ----

/// User settings; seeded from localStorage "tachyon-settings" (partial JSON is
/// fine — each field defaults, mirroring main.ts's spread over defaults).
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct Settings {
    #[serde(default = "default_theme")]
    pub theme: String,
    #[serde(default = "default_font")]
    pub font: String,
    #[serde(default = "default_size")]
    pub size: u32,
}

fn default_theme() -> String { "Tokyo Night".into() }
fn default_font() -> String { "Menlo".into() }
fn default_size() -> u32 { 14 }

impl Default for Settings {
    fn default() -> Self {
        Settings { theme: default_theme(), font: default_font(), size: default_size() }
    }
}

/// Which single overlay is currently open.
#[derive(Clone, Copy, PartialEq)]
pub enum Overlay {
    None,
    Settings,
    AiBar,
    Agent,
    Blocks,
    Palette,
}

/// Vim navigation mode (over the terminal scrollback).
#[derive(Clone, Copy, PartialEq)]
pub enum VimMode {
    Insert,
    Normal,
    Visual,
}

/// One finalized OSC-133 command block. The native side sends command/exit_code/
/// output/duration_ms; ai/ai_pending/expanded are per-card UI state added here.
#[derive(Clone, PartialEq, Default, Deserialize)]
pub struct JournalBlock {
    /// Client-assigned stable id (the native payload has none). Lets async work — e.g.
    /// per-block AI explain — reattach to the right block after a ring shift, instead of
    /// re-indexing by a Vec position that eviction may have moved.
    #[serde(skip)]
    pub id: u64,
    #[serde(default)]
    pub command: String,
    #[serde(default)]
    pub exit_code: i32,
    #[serde(default)]
    pub output: String,
    #[serde(default)]
    pub duration_ms: f64,
    #[serde(default)]
    pub ai: Option<String>,
    #[serde(default)]
    pub ai_pending: bool,
    #[serde(default)]
    pub expanded: bool,
}

/// App-wide state, provided once at the root via `use_context_provider` and read
/// by every overlay via `use_context::<AppState>()`. `Signal` is `Copy`, so this
/// whole struct is `Copy` and can be captured into event closures.
#[derive(Clone, Copy)]
pub struct AppState {
    pub settings: Signal<Settings>,
    pub overlay: Signal<Overlay>,
    /// Mirror of the Rust journal ring (last 50 finalized blocks).
    pub journal: Signal<Vec<JournalBlock>>,
    /// Active provider id (for status/ai-bar display).
    pub provider_active: Signal<String>,
    pub vim_mode: Signal<VimMode>,
    /// Mirror of the Rust AgentState.running — driven by the ai_bar (agent) module.
    pub agent_running: Signal<bool>,
}

impl AppState {
    /// Toggle a plain overlay (Settings/Blocks/Palette): open it, or close if it's already open.
    pub fn toggle(self, o: Overlay) {
        let mut ov = self.overlay;
        if *ov.read() == o { ov.set(Overlay::None); } else { ov.set(o); }
    }

    /// The ai bar is one panel with two modes. ⌘K/⌘J: if the bar is showing (either
    /// mode) close it, else open it in the requested mode. Mirrors main.ts K/J.
    pub fn toggle_bar(self, mode: Overlay) {
        let mut ov = self.overlay;
        if matches!(*ov.read(), Overlay::AiBar | Overlay::Agent) {
            ov.set(Overlay::None);
        } else {
            ov.set(mode);
        }
    }

    pub fn close(self) {
        let mut ov = self.overlay;
        ov.set(Overlay::None);
    }

    pub fn is_open(self, o: Overlay) -> bool {
        *self.overlay.read() == o
    }
}

// ---- invoke arg shape ----

#[derive(Serialize)]
struct NoArgs {}

fn local_storage() -> Option<web_sys::Storage> {
    web_sys::window().and_then(|w| w.local_storage().ok().flatten())
}

thread_local! {
    static NEXT_BLOCK_ID: std::cell::Cell<u64> = const { std::cell::Cell::new(1) };
}

/// Monotonic block id (WASM is single-threaded, so a Cell is enough).
pub fn next_block_id() -> u64 {
    NEXT_BLOCK_ID.with(|c| {
        let id = c.get();
        c.set(id + 1);
        id
    })
}

fn load_settings() -> Settings {
    local_storage()
        .and_then(|ls| ls.get_item("tachyon-settings").ok().flatten())
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

/// Fire a no-arg native command, ignoring the result. Used for ⌘J abort and ⌘E explain.
fn fire(cmd: &'static str) {
    spawn_local(async move {
        let _ = invoke(cmd, NoArgs {}).await;
    });
}

/// Global document keydown → overlay routing (main.ts lines 144-177).
/// ⌘-chords route to overlay state; bare Esc closes plain overlays. The ai bar
/// (command/agent) owns its own Esc — the agent approval gate is the trust
/// boundary, so this handler never closes AiBar/Agent on Esc.
fn handle_global_key(state: AppState, ev: KeyboardEvent) {
    if ev.meta_key() {
        match ev.key().as_str() {
            "," => { ev.prevent_default(); state.toggle(Overlay::Settings); }
            "k" => { ev.prevent_default(); state.toggle_bar(Overlay::AiBar); }
            "j" => {
                ev.prevent_default();
                if *state.agent_running.read() {
                    fire("agent_abort"); // ⌘J while running = dedicated abort
                } else {
                    state.toggle_bar(Overlay::Agent);
                }
            }
            // ponytail: fire-and-forget; explain output rendering is the ai/terminal
            // module's job (main.ts prints cyan to the term). Wire result there.
            "e" => { ev.prevent_default(); fire("explain_last_error"); }
            "p" => { ev.prevent_default(); state.toggle(Overlay::Palette); }
            "b" => { ev.prevent_default(); state.toggle(Overlay::Blocks); }
            _ => {}
        }
        return;
    }
    if ev.key() == "Escape"
        && matches!(*state.overlay.read(), Overlay::Settings | Overlay::Blocks | Overlay::Palette)
    {
        ev.prevent_default();
        state.close();
    }
}

#[component]
pub fn App() -> Element {
    let state = use_context_provider(|| AppState {
        settings: Signal::new(load_settings()),
        overlay: Signal::new(Overlay::None),
        journal: Signal::new(Vec::new()),
        provider_active: Signal::new(String::new()),
        vim_mode: Signal::new(VimMode::Insert),
        agent_running: Signal::new(false),
    });

    // Apply theme + persist settings whenever they change (runs on mount too).
    use_effect(move || {
        let s = state.settings.read();
        theme::apply_theme(&s.theme);
        if let Some(ls) = local_storage() {
            if let Ok(json) = serde_json::to_string(&*s) {
                let _ = ls.set_item("tachyon-settings", &json);
            }
        }
        // Notify the canvas terminal to re-read font/size from the just-persisted settings.
        // Fired post-persist so terminal.rs sees current values (mirrors main.ts applySettings
        // driving term.options.fontFamily/fontSize).
        if let Some(win) = web_sys::window() {
            if let Ok(ev) = web_sys::Event::new("tachyon-font") {
                let _ = win.dispatch_event(&ev);
            }
        }
    });

    // Journal mirror + provider seed + global keybindings — once on mount.
    use_effect(move || {
        // listener BEFORE seed so no block slips between (main.ts line 652).
        let journal = state.journal;
        listen("journal-block", move |payload| {
            if let Ok(mut b) = serde_wasm_bindgen::from_value::<JournalBlock>(payload) {
                b.id = next_block_id();
                let mut j = journal;
                j.write().push(b);
                if j.read().len() > 50 {
                    j.write().remove(0); // cap 50, mirror of the Rust ring
                }
            }
        });

        let journal = state.journal;
        let provider = state.provider_active;
        spawn_local(async move {
            if let Ok(v) = invoke("journal_blocks", NoArgs {}).await {
                if let Ok(mut seed) = serde_wasm_bindgen::from_value::<Vec<JournalBlock>>(v) {
                    let mut j = journal;
                    if j.read().is_empty() && !seed.is_empty() {
                        for b in &mut seed {
                            b.id = next_block_id(); // stable ids for the hot-reload seed too
                        }
                        j.set(seed); // hot-reload: the Rust journal survives the webview
                    }
                }
            }
            if let Ok(v) = invoke("provider_active", NoArgs {}).await {
                if let Some(id) = js_sys::Reflect::get(&v, &JsValue::from_str("id"))
                    .ok()
                    .and_then(|x| x.as_string())
                {
                    let mut p = provider;
                    p.set(id);
                }
            }
        });

        // global keybindings (document keydown)
        if let Some(doc) = web_sys::window().and_then(|w| w.document()) {
            let cb = Closure::wrap(Box::new(move |ev: KeyboardEvent| {
                handle_global_key(state, ev);
            }) as Box<dyn FnMut(KeyboardEvent)>);
            let _ = doc.add_event_listener_with_callback("keydown", cb.as_ref().unchecked_ref());
            cb.forget(); // ponytail: single global listener, app lifetime
        }
    });

    rsx! {
        document::Link { rel: "stylesheet", href: MAIN_CSS }
        Terminal {}
        StatusBar {}
        VimSearch {}
        SettingsPanel {}
        AiBar {}
        BlocksPanel {}
        Palette {}
    }
}
