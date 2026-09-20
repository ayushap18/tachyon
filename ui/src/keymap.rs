//! Keymap: the single table of app actions → default chord per platform, user
//! overrides from the backend `keybindings` command, a pure matcher, and the
//! display label for the ACTIVE binding. ⌘ is only a usable modifier on macOS —
//! elsewhere `meta_key()` is Super and the window manager eats it.

use std::cell::RefCell;

use web_sys::KeyboardEvent;

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Action {
    AiBar,
    Agent,
    Explain,
    Palette,
    Blocks,
    Settings,
    VimToggle,
    Copy,
}

/// (action, id in the user's keybindings file, macOS default, default elsewhere).
/// Non-mac defaults are ctrl+shift+<key>, never plain ctrl+<key>: Ctrl-K/J/E/P/B are
/// readline keys (kill-line, newline, end-of-line, previous-history, back-char) and must
/// keep reaching the shell. Exceptions: settings is ctrl+, because Shift turns `,` into
/// `<` (and Ctrl+, means nothing to a shell); vim_toggle is ctrl+shift+m ("mode") because
/// Ctrl+Shift+V is the terminal paste convention.
const TABLE: [(Action, &str, &str, &str); 8] = [
    (Action::AiBar, "ai_bar", "cmd+k", "ctrl+shift+k"),
    (Action::Agent, "agent", "cmd+j", "ctrl+shift+j"),
    (Action::Explain, "explain", "cmd+e", "ctrl+shift+e"),
    (Action::Palette, "palette", "cmd+p", "ctrl+shift+p"),
    (Action::Blocks, "blocks", "cmd+b", "ctrl+shift+b"),
    (Action::Settings, "settings", "cmd+,", "ctrl+,"),
    (Action::VimToggle, "vim_toggle", "cmd+shift+v", "ctrl+shift+m"),
    (Action::Copy, "copy", "cmd+c", "ctrl+shift+c"),
];

#[derive(Clone, PartialEq, Debug, Default)]
pub struct Chord {
    /// Lowercased `KeyboardEvent.key` ("k", ",", "escape", "f5").
    key: String,
    meta: bool,
    ctrl: bool,
    shift: bool,
    alt: bool,
}

/// Parse "cmd+k" / "ctrl+shift+k" / "ctrl+,". Modifiers: cmd|meta, ctrl, shift, alt;
/// case-insensitive. None for anything malformed, and for a chord without cmd/ctrl/alt
/// (function keys excepted) — binding a bare "k" would make that letter untypeable.
pub fn parse(s: &str) -> Option<Chord> {
    let s = s.trim().to_lowercase();
    let mut parts: Vec<&str> = s.split('+').map(str::trim).collect();
    let key = parts.pop().filter(|k| !k.is_empty())?;
    let mut c = Chord { key: if key == "space" { " ".into() } else { key.into() }, ..Default::default() };
    for m in parts {
        match m {
            "cmd" | "meta" => c.meta = true,
            "ctrl" => c.ctrl = true,
            "shift" => c.shift = true,
            "alt" => c.alt = true,
            _ => return None,
        }
    }
    let is_modifier = matches!(key, "cmd" | "meta" | "ctrl" | "shift" | "alt");
    let is_fkey = key.len() > 1 && key.starts_with('f') && key[1..].parse::<u8>().is_ok();
    (!is_modifier && (c.meta || c.ctrl || c.alt || is_fkey)).then_some(c)
}

impl Chord {
    /// Pure match against a keydown's plain values. Modifiers must match exactly (so
    /// cmd+v ≠ cmd+shift+v); the key compares case-insensitively because Shift (and
    /// Caps Lock) change `ev.key()` casing — "K" vs "k".
    pub fn matches(&self, key: &str, meta: bool, ctrl: bool, shift: bool, alt: bool) -> bool {
        (self.meta, self.ctrl, self.shift, self.alt) == (meta, ctrl, shift, alt)
            && self.key == key.to_lowercase()
    }
}

/// The key to match on. Option on macOS composes a different character (⌥K → "˚"), so
/// with Alt held trust the physical key for letters/digits instead of `ev.key()`.
fn event_key(key: &str, code: &str, alt: bool) -> String {
    let physical = code.strip_prefix("Key").or_else(|| code.strip_prefix("Digit"));
    match physical {
        Some(p) if alt => p.to_lowercase(),
        _ => key.to_string(),
    }
}

pub struct Keymap {
    is_mac: bool,
    chords: Vec<(Action, Chord)>,
}

impl Keymap {
    pub fn defaults(is_mac: bool) -> Self {
        let chords = TABLE
            .iter()
            .map(|&(a, _, mac, other)| (a, parse(if is_mac { mac } else { other }).expect("default chord parses")))
            .collect();
        Keymap { is_mac, chords }
    }

    /// Merge `{action id: chord}` over the current bindings. Unknown ids, non-string
    /// values and unparseable chords are ignored — that action keeps its binding.
    pub fn merge(&mut self, overrides: &serde_json::Value) {
        let Some(map) = overrides.as_object() else { return };
        for (id, v) in map {
            let action = TABLE.iter().find(|t| t.1 == id).map(|t| t.0);
            if let (Some(action), Some(chord)) = (action, v.as_str().and_then(parse)) {
                if let Some(slot) = self.chords.iter_mut().find(|(a, _)| *a == action) {
                    slot.1 = chord;
                }
            }
        }
    }

    /// The action bound to this key event, if any (first in table order wins a clash).
    pub fn action(&self, key: &str, meta: bool, ctrl: bool, shift: bool, alt: bool) -> Option<Action> {
        self.chords.iter().find(|(_, c)| c.matches(key, meta, ctrl, shift, alt)).map(|(a, _)| *a)
    }

    /// Human label for the active binding: "⌘K" on macOS, "Ctrl+Shift+K" elsewhere.
    pub fn label(&self, action: Action) -> String {
        let Some((_, c)) = self.chords.iter().find(|(a, _)| *a == action) else {
            return String::new();
        };
        let names = if self.is_mac { ["⌘", "⌃", "⌥", "⇧"] } else { ["Super+", "Ctrl+", "Alt+", "Shift+"] };
        let mut out = String::new();
        for (on, name) in [c.meta, c.ctrl, c.alt, c.shift].into_iter().zip(names) {
            if on {
                out.push_str(name);
            }
        }
        if c.key == " " {
            out.push_str("Space");
        } else {
            // "k" → "K", "escape" → "Escape"
            let mut chars = c.key.chars();
            out.extend(chars.next().map(|f| f.to_ascii_uppercase()));
            out.push_str(chars.as_str());
        }
        out
    }
}

// ---- the active keymap (browser side) ----

fn detect_mac() -> bool {
    web_sys::window().map(|w| w.navigator()).is_some_and(|n| {
        n.platform().is_ok_and(|p| p.contains("Mac")) || n.user_agent().is_ok_and(|u| u.contains("Mac"))
    })
}

thread_local! {
    // Platform is detected once, on first use (WASM is single-threaded, like OVERLAY_OPEN).
    static ACTIVE: RefCell<Keymap> = RefCell::new(Keymap::defaults(detect_mac()));
}

pub fn is_mac() -> bool {
    ACTIVE.with(|k| k.borrow().is_mac)
}

pub fn action_for(ev: &KeyboardEvent) -> Option<Action> {
    let key = event_key(&ev.key(), &ev.code(), ev.alt_key());
    ACTIVE.with(|k| k.borrow().action(&key, ev.meta_key(), ev.ctrl_key(), ev.shift_key(), ev.alt_key()))
}

pub fn label(action: Action) -> String {
    ACTIVE.with(|k| k.borrow().label(action))
}

/// Fetch the user's overrides from the backend and merge them over the defaults.
/// Returns the error to show when the file is corrupt (defaults stay in force).
pub async fn load() -> Option<String> {
    match crate::bridge::invoke("keybindings", crate::bridge::NoArgs {}).await {
        Ok(v) => {
            // Via JSON text so one junk (non-string) value can't fail the whole object.
            let json = js_sys::JSON::stringify(&v).ok().and_then(|s| s.as_string()).unwrap_or_default();
            if let Ok(overrides) = serde_json::from_str(&json) {
                ACTIVE.with(|k| k.borrow_mut().merge(&overrides));
            }
            None
        }
        Err(e) => Some(e.as_string().unwrap_or_else(|| "could not load keybindings".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_good() {
        let k = parse("cmd+k").unwrap();
        assert_eq!((k.key.as_str(), k.meta, k.ctrl, k.shift, k.alt), ("k", true, false, false, false));
        assert_eq!(parse("meta+k"), parse("cmd+k"));
        assert_eq!(parse(" Ctrl+SHIFT+K "), parse("ctrl+shift+k"));
        assert_eq!(parse("ctrl+,").unwrap().key, ",");
        assert_eq!(parse("ctrl+alt+space").unwrap().key, " ");
        assert_eq!(parse("alt+Escape").unwrap().key, "escape");
        assert!(parse("f5").is_some()); // function keys may stand alone
    }

    #[test]
    fn parse_bad() {
        for s in ["", "+", "ctrl+", "ctrl", "cmd+shift", "hyper+k", "ctrl++k", "k", "shift+k", "enter", "fn"] {
            assert_eq!(parse(s), None, "{s:?}");
        }
    }

    #[test]
    fn matching() {
        let c = parse("ctrl+shift+k").unwrap();
        assert!(c.matches("K", false, true, true, false)); // Shift upcases ev.key()
        assert!(c.matches("k", false, true, true, false)); // …unless Caps Lock is also on
        assert!(!c.matches("k", false, true, false, false)); // plain Ctrl-K stays readline's
        assert!(!c.matches("K", true, true, true, false)); // extra modifier
        assert!(!c.matches("j", false, true, true, false));
        assert!(parse("cmd+,").unwrap().matches(",", true, false, false, false));
        // Option composes on macOS: fall back to the physical key
        assert_eq!(event_key("˚", "KeyK", true), "k");
        assert_eq!(event_key("K", "KeyK", false), "K");
        assert_eq!(event_key(",", "Comma", true), ",");
    }

    #[test]
    fn defaults_per_platform() {
        let mac = Keymap::defaults(true);
        assert_eq!(mac.action("k", true, false, false, false), Some(Action::AiBar));
        assert_eq!(mac.action("j", true, false, false, false), Some(Action::Agent));
        assert_eq!(mac.action("e", true, false, false, false), Some(Action::Explain));
        assert_eq!(mac.action("p", true, false, false, false), Some(Action::Palette));
        assert_eq!(mac.action("b", true, false, false, false), Some(Action::Blocks));
        assert_eq!(mac.action(",", true, false, false, false), Some(Action::Settings));
        assert_eq!(mac.action("V", true, false, true, false), Some(Action::VimToggle));
        assert_eq!(mac.action("c", true, false, false, false), Some(Action::Copy));
        assert_eq!(mac.action("v", true, false, false, false), None); // ⌘V is paste, not vim

        let other = Keymap::defaults(false);
        for (key, action) in [("K", Action::AiBar), ("J", Action::Agent), ("E", Action::Explain),
            ("P", Action::Palette), ("B", Action::Blocks), ("M", Action::VimToggle), ("C", Action::Copy)]
        {
            assert_eq!(other.action(key, false, true, true, false), Some(action));
            // the readline / SIGINT keys must fall through to encode_key
            assert_eq!(other.action(&key.to_lowercase(), false, true, false, false), None);
        }
        assert_eq!(other.action(",", false, true, false, false), Some(Action::Settings));
        assert_eq!(other.action("V", false, true, true, false), None); // left for paste
        assert_eq!(other.action("k", true, false, false, false), None); // Super is the WM's
    }

    #[test]
    fn merge_ignores_junk() {
        let mut km = Keymap::defaults(false);
        km.merge(&json!({
            "ai_bar": "ctrl+alt+k",
            "palette": "not a chord",
            "blocks": 7,
            "bogus_action": "ctrl+alt+x",
        }));
        assert_eq!(km.action("k", false, true, false, true), Some(Action::AiBar));
        assert_eq!(km.action("K", false, true, true, false), None); // old binding replaced
        assert_eq!(km.action("P", false, true, true, false), Some(Action::Palette));
        assert_eq!(km.action("B", false, true, true, false), Some(Action::Blocks));
        assert_eq!(km.action("x", false, true, false, true), None);
        km.merge(&json!("not an object")); // no panic, no change
        km.merge(&json!({}));
        assert_eq!(km.label(Action::AiBar), "Ctrl+Alt+K");
    }

    #[test]
    fn labels() {
        let mac = Keymap::defaults(true);
        assert_eq!(mac.label(Action::AiBar), "⌘K");
        assert_eq!(mac.label(Action::VimToggle), "⌘⇧V");
        assert_eq!(mac.label(Action::Settings), "⌘,");
        let other = Keymap::defaults(false);
        assert_eq!(other.label(Action::AiBar), "Ctrl+Shift+K");
        assert_eq!(other.label(Action::Settings), "Ctrl+,");
        assert_eq!(other.label(Action::Copy), "Ctrl+Shift+C");
        let mut km = Keymap::defaults(true);
        km.merge(&json!({"explain": "ctrl+alt+escape", "agent": "cmd+space"}));
        assert_eq!(km.label(Action::Explain), "⌃⌥Escape");
        assert_eq!(km.label(Action::Agent), "⌘Space");
    }
}
