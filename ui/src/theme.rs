//! The 6 themes -> chrome tokens, ported from src/main.ts THEMES + CHROME maps.
//! `apply_theme` sets them as CSS variables on :root (mirroring main.ts
//! applySettings lines 93-113) and returns the resolved tokens.

use wasm_bindgen::JsCast;
use web_sys::HtmlElement;

/// Font choices for the settings dropdown (main.ts line 52).
pub const FONTS: [&str; 6] = [
    "Menlo",
    "Monaco",
    "SF Mono",
    "Courier New",
    "JetBrains Mono",
    "Fira Code",
];

/// Theme names in display order (keys of THEMES in main.ts).
pub const THEME_NAMES: [&str; 6] = [
    "Tokyo Night",
    "Dracula",
    "Nord",
    "Solarized Dark",
    "Solarized Light",
    "Matrix",
];

/// Resolved chrome tokens for a theme: terminal bg/fg plus the 7 CHROME layers.
#[derive(Clone, Copy)]
pub struct ThemeTokens {
    pub bg: &'static str,
    pub fg: &'static str,
    pub accent: &'static str,
    pub surface: &'static str,
    pub surface_alt: &'static str,
    pub border: &'static str,
    pub muted: &'static str,
    pub ok: &'static str,
    pub err: &'static str,
}

/// Look up tokens by theme name, falling back to Tokyo Night (main.ts `?? THEMES[...]`).
pub fn tokens(name: &str) -> ThemeTokens {
    match name {
        "Dracula" => ThemeTokens {
            bg: "#282a36", fg: "#f8f8f2",
            accent: "#bd93f9", surface: "#21222c", surface_alt: "#343746",
            border: "#44475a", muted: "#8a8fa8", ok: "#50fa7b", err: "#ff5555",
        },
        "Nord" => ThemeTokens {
            bg: "#2e3440", fg: "#d8dee9",
            accent: "#88c0d0", surface: "#2b303b", surface_alt: "#3b4252",
            border: "#434c5e", muted: "#7b869c", ok: "#a3be8c", err: "#bf616a",
        },
        "Solarized Dark" => ThemeTokens {
            bg: "#002b36", fg: "#839496",
            accent: "#268bd2", surface: "#073642", surface_alt: "#0a4a5a",
            border: "#0f4b59", muted: "#657b83", ok: "#859900", err: "#dc322f",
        },
        "Solarized Light" => ThemeTokens {
            bg: "#fdf6e3", fg: "#586e75",
            accent: "#268bd2", surface: "#eee8d5", surface_alt: "#e3dcc6",
            border: "#d3cbb3", muted: "#93a1a1", ok: "#859900", err: "#dc322f",
        },
        "Matrix" => ThemeTokens {
            bg: "#000000", fg: "#00ff41",
            accent: "#00ff41", surface: "#0a0f0a", surface_alt: "#0f1a0f",
            border: "#1c3a1c", muted: "#4a7a4a", ok: "#00ff41", err: "#ff5555",
        },
        // "Tokyo Night" and anything unknown
        _ => ThemeTokens {
            bg: "#16161e", fg: "#c0caf5",
            accent: "#7aa2f7", surface: "#1a1b26", surface_alt: "#24283b",
            border: "#2a2e42", muted: "#7b849c", ok: "#9ece6a", err: "#f7768e",
        },
    }
}

/// Apply the theme's tokens as CSS variables on :root and set the body
/// background, then return them. Mirrors main.ts applySettings lines 93-113
/// (the CSS-variable + body-bg half; canvas font/size wiring lives elsewhere).
pub fn apply_theme(name: &str) -> ThemeTokens {
    let t = tokens(name);
    let Some(doc) = web_sys::window().and_then(|w| w.document()) else {
        return t;
    };
    if let Some(root) = doc
        .document_element()
        .and_then(|e| e.dyn_into::<HtmlElement>().ok())
    {
        let s = root.style();
        let _ = s.set_property("--bg", t.bg);
        let _ = s.set_property("--fg", t.fg);
        let _ = s.set_property("--accent", t.accent);
        let _ = s.set_property("--surface", t.surface);
        let _ = s.set_property("--surface-alt", t.surface_alt);
        let _ = s.set_property("--border", t.border);
        let _ = s.set_property("--muted", t.muted);
        let _ = s.set_property("--ok", t.ok);
        let _ = s.set_property("--err", t.err);
    }
    if let Some(body) = doc.body() {
        let _ = body.style().set_property("background", t.bg);
    }
    t
}
