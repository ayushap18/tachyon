//! The 6 themes -> chrome tokens. `apply_theme` sets them as CSS variables on
//! :root. This table and engine.rs's `theme_colors` are the only two places in
//! the tree that may name a colour.

use wasm_bindgen::JsCast;
use web_sys::HtmlElement;

/// Font choices for the settings dropdown. The first entry is the
/// platform default.
const FONTS_MAC: [&str; 6] = [
    "Menlo",
    "Monaco",
    "SF Mono",
    "Courier New",
    "JetBrains Mono",
    "Fira Code",
];

/// Menlo/Monaco/SF Mono only ship with macOS. The canvas font string always ends in the
/// generic `monospace`, so a listed family that isn't installed still measures as a
/// fixed-width cell.
const FONTS_OTHER: [&str; 6] = [
    "DejaVu Sans Mono",
    "Liberation Mono",
    "Ubuntu Mono",
    "JetBrains Mono",
    "Fira Code",
    "monospace",
];

pub fn fonts() -> &'static [&'static str] {
    if crate::keymap::is_mac() { &FONTS_MAC } else { &FONTS_OTHER }
}

pub fn default_font() -> &'static str {
    fonts()[0]
}

/// A saved font that isn't offered on this platform (settings carried over from another
/// OS, or hand-edited) falls back to the default, so the dropdown and the canvas agree.
pub fn resolve_font(name: &str) -> &'static str {
    fonts().iter().copied().find(|f| *f == name).unwrap_or_else(default_font)
}

/// Theme names in display order.
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

/// Look up tokens by theme name, falling back to Tokyo Night.
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

/// Apply the theme's tokens as CSS variables on :root. The page paints no backing of its
/// own: `html, body` are transparent and the native window carries the theme colour, so
/// the webview never composites a second layer over it.
pub fn apply_theme(name: &str) {
    let t = tokens(name);
    let Some(root) = web_sys::window()
        .and_then(|w| w.document())
        .and_then(|d| d.document_element())
        .and_then(|e| e.dyn_into::<HtmlElement>().ok())
    else {
        return;
    };
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

#[cfg(test)]
mod tests {
    /// The canvas is measured in Terminal's mount effect. A linked stylesheet may still be
    /// loading then, which is what made the PTY spawn at roughly 35x8 and reflow.
    #[test]
    fn stylesheet_is_inlined_not_linked() {
        let src = include_str!("app.rs");
        assert!(!src.contains("document::Link"), "app.rs still links the stylesheet");
        assert!(src.contains(r#"include_str!("../assets/main.css")"#), "app.rs does not inline it");
    }

    /// Only default-background canvas cells go see-through. Chrome paints on top of a
    /// window the user can dial down to 40%, and a security control — the approval bar
    /// above all — must never be hard to read against whatever is behind the window.
    /// `#palette` is excluded on purpose: it is the dimming scrim over the terminal, and
    /// the palette's readable surfaces are its input and its list.
    #[test]
    fn chrome_surfaces_stay_opaque() {
        // Strip comments first, so a commented-out declaration cannot hide a live one.
        let mut css = String::new();
        let mut rest = include_str!("../assets/main.css");
        while let Some(i) = rest.find("/*") {
            css.push_str(&rest[..i]);
            rest = rest[i..].split_once("*/").map_or("", |(_, r)| r);
        }
        css.push_str(rest);

        for sel in ["#ai-bar", "#status-bar", "#settings", "#palette-input", "#palette-list", "#blocks"] {
            let head = format!("\n{sel} {{\n");
            let at = css.find(&head).unwrap_or_else(|| panic!("{sel} is gone from main.css")) + head.len();
            let block = &css[at..][..css[at..].find("\n}").expect("unterminated block")];
            let mut opaque = false;
            for decl in block.split(';') {
                let Some((prop, value)) = decl.split_once(':') else { continue };
                let (prop, value) = (prop.trim(), value.trim());
                assert!(prop != "opacity" && prop != "backdrop-filter", "{sel} fades itself: {prop}");
                if prop.starts_with("background") {
                    assert!(
                        !value.contains("rgba(") && !value.contains("hsla(") && !value.contains("transparent"),
                        "{sel} has a see-through background: {value}"
                    );
                    opaque |= value == "var(--surface)" || value == "var(--surface-alt)";
                }
            }
            assert!(opaque, "{sel} has no opaque token background");
        }
    }

    /// The TypeScript prototype these modules were ported from is gone from the tree, so a
    /// comment citing it by file and line sends a reader to nothing. Needles are built from
    /// fragments so this test does not match itself.
    #[test]
    fn no_comment_cites_a_deleted_file() {
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut seen = 0;
        for f in std::fs::read_dir(&src).unwrap() {
            let path = f.unwrap().path();
            if path.extension().is_none_or(|e| e != "rs") {
                continue;
            }
            seen += 1;
            let text = std::fs::read_to_string(&path).unwrap();
            for gone in [concat!("main", ".ts"), concat!("vim", ".ts")] {
                assert!(!text.contains(gone), "{} cites {gone}", path.display());
            }
        }
        // Reading the directory is what subjects a file added later to this too.
        assert!(seen >= 13, "only {seen} rust files scanned");
    }
}
