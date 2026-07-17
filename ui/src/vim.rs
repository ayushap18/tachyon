//! Vim navigation over the visible terminal grid — ported from src/vim.ts.
//! INSERT (default, keys pass to the pty) ⇄ NORMAL (⌘⇧V; i/a/Esc exit) ⇄ VISUAL (v).
//! Motions h/j/k/l/w/b/0/$/gg/G, Ctrl-D/U, / n N search, y yank (visual).
//!
//! Rendering: instead of xterm's term.select(), we paint a DOM overlay of
//! highlight boxes positioned from the grid's cell metrics (terminal.rs owns the
//! canvas and repaints it on every frame, so a DOM overlay avoids fighting it).
//!
//! Key routing: terminal.rs registers a bubble-phase document keydown listener
//! that forwards to the pty. We register a CAPTURE-phase listener so we run first
//! and stop_immediate_propagation() in NORMAL/VISUAL, keeping keys off the shell.

use dioxus::prelude::*;
use wasm_bindgen::{prelude::*, JsCast};
use web_sys::{HtmlElement, KeyboardEvent};

use crate::app::{AppState, VimMode};
use crate::bridge::clipboard_write;
use crate::terminal::{grid_view, GridView};

// ---- grid text helpers (pure) ----

fn line_text(v: &GridView, r: i32) -> String {
    if r < 0 {
        return String::new();
    }
    v.lines.get(r as usize).cloned().unwrap_or_default()
}

fn line_len(v: &GridView, r: i32) -> i32 {
    line_text(v, r).chars().count() as i32
}

fn clamp_col(v: &GridView, r: i32, c: i32) -> i32 {
    c.max(0).min((line_len(v, r) - 1).max(0))
}

/// Char-index start of every whitespace-delimited word in `s` (mirrors /\S+/g).
fn word_starts(s: &str) -> Vec<i32> {
    let mut out = Vec::new();
    let mut prev_ws = true;
    for (i, ch) in s.chars().enumerate() {
        let ws = ch.is_whitespace();
        if !ws && prev_ws {
            out.push(i as i32);
        }
        prev_ws = ws;
    }
    out
}

/// First index >= `start` where `needle` occurs in `hay` (JS indexOf semantics).
fn index_of(hay: &[char], needle: &[char], start: i32) -> Option<i32> {
    if needle.is_empty() || needle.len() > hay.len() {
        return None;
    }
    let last = hay.len() - needle.len();
    (start.max(0) as usize..=last).find(|&i| &hay[i..i + needle.len()] == needle).map(|i| i as i32)
}

/// Greatest index <= `from` where `needle` occurs (JS lastIndexOf(needle, from)).
fn last_index_of(hay: &[char], needle: &[char], from: i64) -> Option<i32> {
    if needle.is_empty() || needle.len() > hay.len() {
        return None;
    }
    let max_start = (hay.len() - needle.len()) as i64;
    let from = from.min(max_start);
    if from < 0 {
        return None;
    }
    (0..=from as usize).rev().find(|&i| &hay[i..i + needle.len()] == needle).map(|i| i as i32)
}

/// Case-insensitive search from (row,col) in `dir` (+1 down, -1 up). Ported from findFrom().
fn find_from(v: &GridView, q: &str, mut row: i32, mut col: i32, dir: i32) -> Option<(i32, i32)> {
    let needle: Vec<char> = q.to_lowercase().chars().collect();
    if needle.is_empty() {
        return None;
    }
    let last = v.rows as i32 - 1;
    if dir == -1 && col < 0 {
        // cursor at col 0: continue from the end of the previous line
        row -= 1;
        col = i32::MAX;
    }
    if dir == 1 {
        let mut r = row;
        while r <= last {
            let hay: Vec<char> = line_text(v, r).to_lowercase().chars().collect();
            let start = if r == row { col } else { 0 };
            if let Some(i) = index_of(&hay, &needle, start) {
                return Some((r, i));
            }
            r += 1;
        }
    } else {
        let mut r = row;
        while r >= 0 {
            let hay: Vec<char> = line_text(v, r).to_lowercase().chars().collect();
            let from = if r == row { col as i64 } else { i64::MAX };
            if let Some(i) = last_index_of(&hay, &needle, from) {
                return Some((r, i));
            }
            r -= 1;
        }
    }
    None
}

fn motion_w(v: &GridView, r: i32, c: i32, last: i32) -> (i32, i32) {
    let here: Vec<i32> = word_starts(&line_text(v, r)).into_iter().filter(|&i| i > c).collect();
    if let Some(&f) = here.first() {
        (r, f)
    } else if r < last {
        let nr = r + 1;
        (nr, *word_starts(&line_text(v, nr)).first().unwrap_or(&0))
    } else {
        (r, c)
    }
}

fn motion_b(v: &GridView, r: i32, c: i32) -> (i32, i32) {
    let here: Vec<i32> = word_starts(&line_text(v, r)).into_iter().filter(|&i| i < c).collect();
    if let Some(&l) = here.last() {
        (r, l)
    } else if r > 0 {
        let pr = r - 1;
        (pr, *word_starts(&line_text(v, pr)).last().unwrap_or(&0))
    } else {
        (r, c)
    }
}

/// Linear selection text between anchor `a` and cursor `b` (for `y` yank).
/// ponytail: newline-joins wrapped rows; xterm's exact wrap handling isn't reachable.
fn selection_text(v: &GridView, a: (i32, i32), b: (i32, i32)) -> String {
    let fwd = a.0 < b.0 || (a.0 == b.0 && a.1 <= b.1);
    let (s, e) = if fwd { (a, b) } else { (b, a) };
    let slice = |r: i32, from: i32, to: Option<i32>| -> String {
        let line: Vec<char> = line_text(v, r).chars().collect();
        let from = (from.max(0) as usize).min(line.len());
        let to = to.map(|t| ((t + 1).max(0) as usize).min(line.len())).unwrap_or(line.len());
        line[from..to.max(from)].iter().collect()
    };
    if s.0 == e.0 {
        return slice(s.0, s.1, Some(e.1));
    }
    (s.0..=e.0)
        .map(|r| {
            if r == s.0 {
                slice(r, s.1, None)
            } else if r == e.0 {
                slice(r, 0, Some(e.1))
            } else {
                slice(r, 0, None)
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

// ---- DOM / clipboard glue (Reflect avoids extra web-sys features) ----

fn search_el() -> Option<HtmlElement> {
    web_sys::window()?.document()?.get_element_by_id("vim-search")?.dyn_into().ok()
}

fn search_value() -> String {
    search_el()
        .and_then(|el| js_sys::Reflect::get(el.as_ref(), &JsValue::from_str("value")).ok())
        .and_then(|v| v.as_string())
        .unwrap_or_default()
}

// ---- mode transitions ----

fn set_mode(state: AppState, search_open: Signal<bool>, m: VimMode) {
    let mut vm = state.vim_mode;
    vm.set(m);
    if m == VimMode::Insert {
        let mut so = search_open;
        so.set(false);
    }
}

fn enter_normal(state: AppState, cursor: Signal<(i32, i32)>) {
    let v = grid_view();
    if v.rows == 0 {
        return;
    }
    let r = v.cursor_line as i32;
    let c = clamp_col(&v, r, v.cursor_col as i32);
    let mut cursor = cursor;
    cursor.set((r, c));
    let mut vm = state.vim_mode;
    vm.set(VimMode::Normal);
}

fn do_search(v: &GridView, dir: i32, cursor: Signal<(i32, i32)>, last_search: Signal<String>) {
    let q = last_search.read().clone();
    if q.is_empty() {
        return;
    }
    let (r, c) = *cursor.read();
    let hit = find_from(v, &q, r, if dir == 1 { c + 1 } else { c - 1 }, dir);
    if let Some(h) = hit {
        let mut cursor = cursor;
        cursor.set(h);
    }
}

/// NORMAL/VISUAL key dispatch — ported from src/vim.ts handleKey().
#[allow(clippy::too_many_arguments)]
fn nav_key(
    state: AppState,
    key: &str,
    ctrl: bool,
    cursor: Signal<(i32, i32)>,
    anchor: Signal<(i32, i32)>,
    pending_g: Signal<bool>,
    search_open: Signal<bool>,
    last_search: Signal<String>,
) {
    let v = grid_view();
    let mode = *state.vim_mode.read();
    let last = (v.rows as i32 - 1).max(0);
    let (mut r, mut c) = *cursor.read();
    let mut cursor = cursor;
    let mut anchor = anchor;
    let mut pending_g = pending_g;
    let mut search_open_m = search_open;

    // Ctrl-D / Ctrl-U: half-page cursor move (ponytail: no scrollback to scroll here).
    if ctrl && (key == "d" || key == "u") {
        let half = (v.rows as i32 / 2) * if key == "d" { 1 } else { -1 };
        r = (r + half).clamp(0, last);
        cursor.set((r, clamp_col(&v, r, c)));
        return;
    }
    if *pending_g.read() {
        pending_g.set(false);
        if key == "g" {
            cursor.set((0, 0));
            return;
        }
    }
    match key {
        "Escape" => {
            if mode == VimMode::Visual {
                set_mode(state, search_open, VimMode::Normal);
            } else {
                set_mode(state, search_open, VimMode::Insert);
            }
            return;
        }
        "i" | "a" => {
            set_mode(state, search_open, VimMode::Insert);
            return;
        }
        "v" => {
            if mode == VimMode::Visual {
                set_mode(state, search_open, VimMode::Normal);
            } else {
                anchor.set((r, c));
                set_mode(state, search_open, VimMode::Visual);
            }
            return;
        }
        "y" => {
            if mode == VimMode::Visual {
                clipboard_write(&selection_text(&v, *anchor.read(), (r, c)));
                set_mode(state, search_open, VimMode::Insert);
            }
            return;
        }
        "h" => c = (c - 1).max(0),
        "l" => c = clamp_col(&v, r, c + 1),
        "j" => {
            r = (r + 1).min(last);
            c = clamp_col(&v, r, c);
        }
        "k" => {
            r = (r - 1).max(0);
            c = clamp_col(&v, r, c);
        }
        "0" => c = 0,
        "$" => c = (line_len(&v, r) - 1).max(0),
        "w" => (r, c) = motion_w(&v, r, c, last),
        "b" => (r, c) = motion_b(&v, r, c),
        "g" => {
            pending_g.set(true);
            return;
        }
        "G" => {
            r = last;
            c = clamp_col(&v, r, c);
        }
        "/" => {
            search_open_m.set(true);
            return;
        }
        "n" => {
            do_search(&v, 1, cursor, last_search);
            return;
        }
        "N" => {
            do_search(&v, -1, cursor, last_search);
            return;
        }
        _ => return, // unknown keys swallowed
    }
    cursor.set((r, c));
}

#[component]
pub fn VimSearch() -> Element {
    let state = use_context::<AppState>();
    let cursor = use_signal(|| (0i32, 0i32));
    let anchor = use_signal(|| (0i32, 0i32));
    let pending_g = use_signal(|| false);
    let search_open = use_signal(|| false);
    let last_search = use_signal(String::new);

    // Capture-phase document keydown: runs before terminal.rs's bubble listener so
    // we can keep NORMAL/VISUAL keys off the pty. Registered once (no reactive reads).
    use_effect(move || {
        let Some(doc) = web_sys::window().and_then(|w| w.document()) else { return };
        let cb = Closure::wrap(Box::new(move |ev: KeyboardEvent| {
            let key = ev.key();
            let is_toggle = ev.meta_key() && ev.shift_key() && key.eq_ignore_ascii_case("v");
            let mode = *state.vim_mode.read();

            if is_toggle {
                ev.prevent_default();
                ev.stop_immediate_propagation();
                if mode == VimMode::Insert {
                    enter_normal(state, cursor);
                } else {
                    set_mode(state, search_open, VimMode::Insert);
                }
                return;
            }
            // Other ⌘-chords pass through to the app/terminal shortcut handlers.
            if ev.meta_key() {
                return;
            }
            // Search box (`/`) owns Enter/Escape; other keys type into it but must
            // not reach terminal.rs (which would prevent_default the character).
            if *search_open.read() {
                match key.as_str() {
                    "Enter" => {
                        ev.prevent_default();
                        ev.stop_immediate_propagation();
                        let val = search_value();
                        if !val.is_empty() {
                            let mut ls = last_search;
                            ls.set(val); // empty '/' repeats the last pattern
                        }
                        let mut so = search_open;
                        so.set(false);
                        do_search(&grid_view(), 1, cursor, last_search);
                    }
                    "Escape" => {
                        ev.prevent_default();
                        ev.stop_immediate_propagation();
                        let mut so = search_open;
                        so.set(false);
                    }
                    _ => ev.stop_immediate_propagation(),
                }
                return;
            }
            if mode == VimMode::Insert {
                return; // INSERT: everything goes to the pty
            }
            // NORMAL / VISUAL: nothing reaches the shell.
            ev.prevent_default();
            ev.stop_immediate_propagation();
            nav_key(state, key.as_str(), ev.ctrl_key(), cursor, anchor, pending_g, search_open, last_search);
        }) as Box<dyn FnMut(KeyboardEvent)>);
        let _ = doc.add_event_listener_with_callback_and_bool(
            "keydown",
            cb.as_ref().unchecked_ref(),
            true, // capture
        );
        cb.forget(); // ponytail: single listener, app lifetime
    });

    // Clear + focus the search box when it opens.
    use_effect(move || {
        if *search_open.read() {
            if let Some(el) = search_el() {
                let _ = js_sys::Reflect::set(el.as_ref(), &JsValue::from_str("value"), &JsValue::from_str(""));
                let _ = el.focus();
            }
        }
    });

    // Overlay highlight boxes (cursor cell in NORMAL; selection rows in VISUAL).
    let mode = *state.vim_mode.read();
    let (cr, cc) = *cursor.read();
    let v = grid_view();
    let (cw, chh, cols) = (v.cell_w, v.cell_h, v.cols as i32);
    let boxes: Vec<(f64, f64, f64)> = match mode {
        VimMode::Insert => Vec::new(),
        VimMode::Normal => vec![(cr as f64 * chh, cc as f64 * cw, cw)],
        VimMode::Visual => {
            let (ar, ac) = *anchor.read();
            let fwd = ar < cr || (ar == cr && ac <= cc);
            let (s, e) = if fwd { ((ar, ac), (cr, cc)) } else { ((cr, cc), (ar, ac)) };
            (s.0..=e.0)
                .map(|r| {
                    let sc = if r == s.0 { s.1 } else { 0 };
                    let ec = if r == e.0 { e.1 } else { cols - 1 };
                    (r as f64 * chh, sc as f64 * cw, (ec - sc + 1).max(1) as f64 * cw)
                })
                .collect()
        }
    };

    rsx! {
        input {
            id: "vim-search",
            hidden: !*search_open.read(),
            autocomplete: "off",
            autocapitalize: "off",
            spellcheck: "false",
        }
        if mode != VimMode::Insert {
            div { id: "vim-overlay",
                for (top, left, w) in boxes {
                    div {
                        class: "vim-cell",
                        style: "top:{top}px;left:{left}px;width:{w}px;height:{chh}px;",
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grid(lines: &[&str]) -> GridView {
        GridView {
            cols: 80,
            rows: lines.len() as u16,
            cell_w: 8.0,
            cell_h: 16.0,
            cursor_line: 0,
            cursor_col: 0,
            lines: lines.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn search_and_motions() {
        let v = grid(&["foo bar baz", "qux Foo end"]);
        // forward search wraps to next line, case-insensitive
        assert_eq!(find_from(&v, "foo", 0, 1, 1), Some((1, 4)));
        // backward search from a later position finds the earlier match
        assert_eq!(find_from(&v, "foo", 1, 3, -1), Some((0, 0)));
        // word motions
        assert_eq!(word_starts("foo bar baz"), vec![0, 4, 8]);
        assert_eq!(motion_w(&v, 0, 0, 1), (0, 4));
        assert_eq!(motion_b(&v, 0, 5), (0, 4));
        // clamp keeps the cursor on the last real column
        assert_eq!(clamp_col(&v, 0, 99), 10);
        // visual yank across rows
        assert_eq!(selection_text(&v, (0, 8), (1, 2)), "baz\nqux");
    }
}
