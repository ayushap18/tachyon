//! Canvas terminal: consumes the native "grid-damage" contract and paints it,
//! and encodes keystrokes back to the PTY.

use std::cell::RefCell;
use std::rc::Rc;

use dioxus::prelude::*;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use web_sys::{CanvasRenderingContext2d, HtmlCanvasElement, KeyboardEvent};

use crate::bridge::{invoke, listen, WriteArgs};

const FONT_PX: f64 = 14.0;
const DEFAULT_FG: [u8; 3] = [0xc0, 0xc6, 0xc6];
const DEFAULT_BG: [u8; 3] = [0x16, 0x16, 0x1e];
const CURSOR_COLOR: [u8; 3] = [0xc0, 0xc6, 0xc6];

// ---- grid-damage contract (mirrors src-tauri/src/engine.rs) ----

#[derive(Deserialize, Clone)]
struct Cursor {
    line: u16,
    col: u16,
    #[allow(dead_code)]
    shape: String,
    visible: bool,
}

#[derive(Deserialize, Clone)]
struct Cell {
    line: u16,
    col: u16,
    ch: String,
    fg: [u8; 3],
    bg: [u8; 3],
    bold: bool,
    italic: bool,
    inverse: bool,
    underline: bool,
}

#[derive(Deserialize)]
struct GridDamage {
    cols: u16,
    rows: u16,
    cursor: Cursor,
    #[serde(default)]
    application_cursor: bool,
    cells: Vec<Cell>,
}

fn blank_cell() -> Cell {
    Cell {
        line: 0,
        col: 0,
        ch: " ".into(),
        fg: DEFAULT_FG,
        bg: DEFAULT_BG,
        bold: false,
        italic: false,
        inverse: false,
        underline: false,
    }
}

struct Term {
    ctx: CanvasRenderingContext2d,
    canvas: HtmlCanvasElement,
    dpr: f64,
    font_px: f64,
    font_family: String,
    cell_w: f64,
    cell_h: f64,
    cols: u16,
    rows: u16,
    buf: Vec<Cell>,
    cursor: Cursor,
    /// Mouse text selection as (anchor, focus) cells, each (row, col). None = no selection.
    sel: Option<((u16, u16), (u16, u16))>,
    selecting: bool,
}

thread_local! {
    // DECCKM state from the latest grid-damage; read by the keydown handler (which doesn't
    // hold the Term) to pick SS3 vs CSI arrow encoding. Cell, not RefCell — it's a Copy bool.
    static APP_CURSOR: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Font family + pixel size from the persisted settings (localStorage "tachyon-settings").
/// Falls back to the defaults when unset/unparseable — mirrors settings.rs's seed.
fn settings_font() -> (f64, String) {
    let mut px = FONT_PX;
    let mut family = "Menlo".to_string();
    if let Some(raw) = web_sys::window()
        .and_then(|w| w.local_storage().ok().flatten())
        .and_then(|s| s.get_item("tachyon-settings").ok().flatten())
    {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&raw) {
            if let Some(s) = v.get("size").and_then(|s| s.as_f64()) {
                px = s.clamp(9.0, 28.0);
            }
            if let Some(f) = v.get("font").and_then(|f| f.as_str()) {
                family = f.to_string();
            }
        }
    }
    (px, format!("\"{family}\", monospace"))
}

fn css(c: [u8; 3]) -> String {
    format!("rgb({},{},{})", c[0], c[1], c[2])
}

fn parse_hex(s: &str) -> Option<[u8; 3]> {
    let s = s.trim().strip_prefix('#')?;
    if s.len() != 6 {
        return None;
    }
    Some([
        u8::from_str_radix(&s[0..2], 16).ok()?,
        u8::from_str_radix(&s[2..4], 16).ok()?,
        u8::from_str_radix(&s[4..6], 16).ok()?,
    ])
}

/// The active theme's terminal background, read from the `--bg` CSS variable that
/// theme::apply_theme sets on :root. Used to fill the full canvas so the sub-cell
/// margin (and any resize flash) matches the theme instead of a hardcoded color.
fn doc_bg() -> [u8; 3] {
    web_sys::window()
        .and_then(|w| {
            let el = w.document()?.document_element()?;
            w.get_computed_style(&el).ok().flatten()
        })
        .and_then(|s| s.get_property_value("--bg").ok())
        .and_then(|v| parse_hex(&v))
        .unwrap_or(DEFAULT_BG)
}

/// Row-major linear selection text over trailing-trimmed row strings, between
/// anchor `a` and focus `b` (each (row, col)). Mirrors vim.rs selection_text ordering.
fn linear_selection(lines: &[String], a: (u16, u16), b: (u16, u16)) -> String {
    let fwd = a.0 < b.0 || (a.0 == b.0 && a.1 <= b.1);
    let (s, e) = if fwd { (a, b) } else { (b, a) };
    let slice = |r: u16, from: u16, to: Option<u16>| -> String {
        let line: Vec<char> = lines.get(r as usize).map(|l| l.chars().collect()).unwrap_or_default();
        let from = (from as usize).min(line.len());
        let to = to.map(|t| (t as usize + 1).min(line.len())).unwrap_or(line.len());
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

impl Term {
    fn idx(&self, line: u16, col: u16) -> Option<usize> {
        if line < self.rows && col < self.cols {
            Some(line as usize * self.cols as usize + col as usize)
        } else {
            None
        }
    }

    /// Cell rect snapped to integer CSS px so a cell's right/bottom edge equals the
    /// next cell's left/top edge exactly (no anti-aliasing seam). Returns (x, y, w, h).
    fn cell_px(&self, col: u16, line: u16) -> (f64, f64, f64, f64) {
        let x0 = (col as f64 * self.cell_w).round();
        let x1 = ((col + 1) as f64 * self.cell_w).round();
        let y0 = (line as f64 * self.cell_h).round();
        let y1 = ((line + 1) as f64 * self.cell_h).round();
        (x0, y0, x1 - x0, y1 - y0)
    }

    /// Size the canvas to the window, paint it the theme bg, and return the grid
    /// (cols, rows) that fit. The <1-cell right/bottom remainder stays theme bg.
    fn fit(&mut self) -> (u16, u16) {
        // Re-read DPR each fit so moving to a different-density display stays crisp.
        self.dpr = win().device_pixel_ratio();
        let w = win().inner_width().ok().and_then(|v| v.as_f64()).unwrap_or(800.0);
        let h = win().inner_height().ok().and_then(|v| v.as_f64()).unwrap_or(600.0);
        self.canvas.set_width((w * self.dpr).round() as u32);
        self.canvas.set_height((h * self.dpr).round() as u32);
        let style = self.canvas.style();
        let _ = style.set_property("width", &format!("{}px", w));
        let _ = style.set_property("height", &format!("{}px", h));
        // canvas resize resets the transform; re-apply DPR scaling + baseline.
        let _ = self.ctx.scale(self.dpr, self.dpr);
        self.ctx.set_text_baseline("top");
        self.ctx.set_fill_style_str(&css(doc_bg()));
        self.ctx.fill_rect(0.0, 0.0, w, h);
        let cols = (w / self.cell_w).floor().max(1.0) as u16;
        let rows = (h / self.cell_h).floor().max(1.0) as u16;
        (cols, rows)
    }

    /// Reallocate the buffer for a fresh full frame. The canvas element size is
    /// owned by `fit`; here we just repaint the whole window-sized canvas to theme
    /// bg so a shrunk grid leaves no stale cells and the margin stays bg.
    fn resize(&mut self, cols: u16, rows: u16) {
        self.cols = cols;
        self.rows = rows;
        self.buf = vec![blank_cell(); cols as usize * rows as usize];
        let w = win().inner_width().ok().and_then(|v| v.as_f64()).unwrap_or(800.0);
        let h = win().inner_height().ok().and_then(|v| v.as_f64()).unwrap_or(600.0);
        self.ctx.set_fill_style_str(&css(doc_bg()));
        self.ctx.fill_rect(0.0, 0.0, w, h);
    }

    fn draw_cell(&self, line: u16, col: u16, cell: &Cell) {
        let (x, y, w, h) = self.cell_px(col, line);
        let (fg, bg) = if cell.inverse {
            (cell.bg, cell.fg)
        } else {
            (cell.fg, cell.bg)
        };
        self.ctx.set_fill_style_str(&css(bg));
        self.ctx.fill_rect(x, y, w, h);
        if cell.ch != " " && !cell.ch.is_empty() {
            let font = format!(
                "{}{}{}px {}",
                if cell.italic { "italic " } else { "" },
                if cell.bold { "bold " } else { "" },
                self.font_px,
                self.font_family,
            );
            self.ctx.set_font(&font);
            self.ctx.set_fill_style_str(&css(fg));
            let _ = self.ctx.fill_text(&cell.ch, x, y);
        }
        if cell.underline {
            self.ctx.set_fill_style_str(&css(fg));
            self.ctx.fill_rect(x, y + h - 1.0, w, 1.0);
        }
    }

    fn repaint(&self, line: u16, col: u16) {
        if let Some(i) = self.idx(line, col) {
            let cell = self.buf[i].clone();
            self.draw_cell(line, col, &cell);
        }
    }

    fn draw_cursor(&self) {
        if !self.cursor.visible {
            return;
        }
        let (line, col) = (self.cursor.line, self.cursor.col);
        if self.idx(line, col).is_none() {
            return;
        }
        let (x, y, w, h) = self.cell_px(col, line);
        self.ctx.set_fill_style_str(&css(CURSOR_COLOR));
        self.ctx.fill_rect(x, y, w, h);
        if let Some(i) = self.idx(line, col) {
            let cell = &self.buf[i];
            if cell.ch != " " && !cell.ch.is_empty() {
                let font = format!("{}px {}", self.font_px, self.font_family);
                self.ctx.set_font(&font);
                self.ctx.set_fill_style_str(&css(cell.bg));
                let _ = self.ctx.fill_text(&cell.ch, x, y);
            }
        }
    }

    /// Pixel (canvas-relative CSS px) -> (row, col), clamped to the grid.
    fn cell_at(&self, ox: f64, oy: f64) -> (u16, u16) {
        let col = (ox / self.cell_w).floor().max(0.0) as u16;
        let row = (oy / self.cell_h).floor().max(0.0) as u16;
        (row.min(self.rows.saturating_sub(1)), col.min(self.cols.saturating_sub(1)))
    }

    /// Trailing-trimmed row strings of the visible buffer (for selection extraction).
    fn rows_text(&self) -> Vec<String> {
        (0..self.rows)
            .map(|r| {
                let mut s = String::with_capacity(self.cols as usize);
                for c in 0..self.cols {
                    if let Some(i) = self.idx(r, c) {
                        s.push_str(&self.buf[i].ch);
                    }
                }
                s.trim_end().to_string()
            })
            .collect()
    }

    /// Extract the current selection's text (None if nothing selected).
    fn selection_text(&self) -> Option<String> {
        let (a, b) = self.sel?;
        Some(linear_selection(&self.rows_text(), a, b))
    }

    /// Overlay a translucent highlight on the cells inside the linear selection.
    fn overlay_selection(&self) {
        let Some((a, b)) = self.sel else { return };
        let (s, e) = if a.0 < b.0 || (a.0 == b.0 && a.1 <= b.1) { (a, b) } else { (b, a) };
        self.ctx.set_fill_style_str("rgba(120,150,220,0.35)");
        for r in s.0..=e.0 {
            let sc = if r == s.0 { s.1 } else { 0 };
            let ec = if r == e.0 { e.1 } else { self.cols.saturating_sub(1) };
            let (x, y, _, h) = self.cell_px(sc, r);
            let (x1, _, w1, _) = self.cell_px(ec, r);
            self.ctx.fill_rect(x, y, x1 + w1 - x, h);
        }
    }

    /// Full repaint of the visible buffer, then selection overlay, then cursor.
    fn redraw(&self) {
        for r in 0..self.rows {
            for c in 0..self.cols {
                if let Some(i) = self.idx(r, c) {
                    let cell = self.buf[i].clone();
                    self.draw_cell(r, c, &cell);
                }
            }
        }
        self.overlay_selection();
        self.draw_cursor();
    }

    fn apply(&mut self, d: GridDamage) {
        // Dimension change => this is a full frame (mount / resize repaint).
        if d.cols != self.cols || d.rows != self.rows || self.buf.is_empty() {
            self.resize(d.cols, d.rows);
        } else {
            // erase the previous cursor by repainting its underlying cell.
            self.repaint(self.cursor.line, self.cursor.col);
        }
        for cell in &d.cells {
            if let Some(i) = self.idx(cell.line, cell.col) {
                self.buf[i] = cell.clone();
                self.draw_cell(cell.line, cell.col, cell);
            }
        }
        self.cursor = d.cursor;
        APP_CURSOR.with(|a| a.set(d.application_cursor));
        self.draw_cursor();
        // A selection's (row,col) coords are screen-relative and become meaningless once new
        // content is painted (or the view scrolls), so drop it rather than highlight stale cells.
        self.sel = None;
        self.publish();
    }

    /// Change the font (from a settings update) and re-measure the cell box. The caller
    /// then recomputes cols/rows and resizes the PTY, which triggers a full repaint.
    fn set_font(&mut self, px: f64, family: String) {
        self.font_px = px;
        self.font_family = family;
        self.ctx.set_font(&format!("{}px {}", self.font_px, self.font_family));
        self.cell_w = self.ctx.measure_text("M").map(|m| m.width()).unwrap_or(px * 0.6).max(1.0);
        self.cell_h = (px * 1.2).round();
    }

    /// Publish a read-only snapshot of the visible grid for the vim module.
    /// ponytail: visible viewport only — the native side owns scrollback and
    /// there's no scroll command, so vim navigates the painted rows.
    fn publish(&self) {
        let mut lines = Vec::with_capacity(self.rows as usize);
        for r in 0..self.rows {
            let mut s = String::with_capacity(self.cols as usize);
            for c in 0..self.cols {
                if let Some(i) = self.idx(r, c) {
                    s.push_str(&self.buf[i].ch);
                }
            }
            lines.push(s.trim_end().to_string());
        }
        GRID.with(|g| {
            *g.borrow_mut() = GridView {
                cols: self.cols,
                rows: self.rows,
                cell_w: self.cell_w,
                cell_h: self.cell_h,
                cursor_line: self.cursor.line,
                cursor_col: self.cursor.col,
                lines,
            };
        });
    }
}

// ---- read-only grid snapshot (consumed by the vim module) ----

/// A clone-on-read view of the currently painted terminal grid.
#[derive(Clone, Default)]
pub struct GridView {
    pub cols: u16,
    pub rows: u16,
    pub cell_w: f64,
    pub cell_h: f64,
    pub cursor_line: u16,
    pub cursor_col: u16,
    /// One trailing-trimmed string per visible row (mirrors xterm translateToString(true)).
    pub lines: Vec<String>,
}

thread_local! {
    static GRID: RefCell<GridView> = RefCell::new(GridView::default());
}

/// Snapshot the current visible grid. Cheap enough (a handful of KB) to clone per keypress.
pub fn grid_view() -> GridView {
    GRID.with(|g| g.borrow().clone())
}

// ---- key encoding (pure, tested below) ----

/// Encode a KeyboardEvent into the bytes a PTY expects, as a UTF-8 string
/// (control bytes ride as chars — the native `pty_write` takes a String and
/// the typed-line reconstruction walks the same chars). Returns None for keys
/// we don't handle (leave the browser's default).
fn encode_key(key: &str, ctrl: bool, alt: bool, app_cursor: bool) -> Option<String> {
    // Cursor keys: in DECCKM (application cursor) mode, curses apps (vim/htop/less) expect
    // SS3 (ESC O x); otherwise CSI (ESC [ x). PageUp/Down/Delete are the same in both modes.
    let ck = if app_cursor { '\u{4f}' } else { '[' }; // 'O' vs '['
    let cursor = match key {
        "ArrowUp" => Some(format!("\x1b{ck}A")),
        "ArrowDown" => Some(format!("\x1b{ck}B")),
        "ArrowRight" => Some(format!("\x1b{ck}C")),
        "ArrowLeft" => Some(format!("\x1b{ck}D")),
        "Home" => Some(format!("\x1b{ck}H")),
        "End" => Some(format!("\x1b{ck}F")),
        _ => None,
    };
    if let Some(s) = cursor {
        return Some(s);
    }
    let named = match key {
        "Enter" => Some("\r"),
        "Backspace" => Some("\x7f"),
        "Tab" => Some("\t"),
        "Escape" => Some("\x1b"),
        "PageUp" => Some("\x1b[5~"),
        "PageDown" => Some("\x1b[6~"),
        "Delete" => Some("\x1b[3~"),
        _ => None,
    };
    if let Some(s) = named {
        return Some(s.to_string());
    }

    // Single printable character.
    let mut chars = key.chars();
    let c = chars.next()?;
    if chars.next().is_some() {
        return None; // multi-char key name we don't handle (Shift, F1, ...)
    }

    if ctrl && c.is_ascii_alphabetic() {
        // Ctrl-<letter> -> control code (Ctrl-A = 0x01 ... Ctrl-Z = 0x1a).
        let code = (c.to_ascii_uppercase() as u8) & 0x1f;
        return Some((code as char).to_string());
    }
    if ctrl {
        return None; // other ctrl combos: leave to the browser
    }
    if alt {
        // Meta/Alt prefix: ESC then the char.
        return Some(format!("\x1b{}", c));
    }
    Some(c.to_string())
}

// ---- invoke argument shapes ----

#[derive(Serialize)]
struct SpawnArgs {
    rows: u16,
    cols: u16,
}
#[derive(Serialize)]
struct TypedArgs {
    line: String,
}
#[derive(Serialize)]
struct ThemeArgs {
    name: String,
}
#[derive(Serialize)]
struct ScrollArgs {
    delta: i32,
}

/// Persisted terminal theme name (localStorage "tachyon-settings"), default Tokyo Night.
fn settings_theme() -> String {
    web_sys::window()
        .and_then(|w| w.local_storage().ok().flatten())
        .and_then(|s| s.get_item("tachyon-settings").ok().flatten())
        .and_then(|raw| serde_json::from_str::<serde_json::Value>(&raw).ok())
        .and_then(|v| v.get("theme").and_then(|t| t.as_str()).map(String::from))
        .unwrap_or_else(|| "Tokyo Night".into())
}

fn win() -> web_sys::Window {
    web_sys::window().expect("no window")
}

/// True when the focused element is a text input (any overlay: ai-bar, palette, settings,
/// vim search). The terminal's document-level key/paste handlers defer to it in that case.
fn editable_focused() -> bool {
    win()
        .document()
        .and_then(|d| d.active_element())
        .map(|el| matches!(el.tag_name().as_str(), "INPUT" | "TEXTAREA" | "SELECT"))
        .unwrap_or(false)
}

fn setup() {
    let document = win().document().expect("no document");
    let canvas: HtmlCanvasElement = document
        .get_element_by_id("term")
        .expect("no #term canvas")
        .dyn_into()
        .expect("not a canvas");
    let ctx: CanvasRenderingContext2d = canvas
        .get_context("2d")
        .expect("get_context failed")
        .expect("no 2d context")
        .dyn_into()
        .expect("not a 2d context");

    let dpr = win().device_pixel_ratio();
    // measure a monospace cell at the persisted font/size.
    let (font_px, font_family) = settings_font();
    ctx.set_font(&format!("{}px {}", font_px, font_family));
    let cell_w = ctx
        .measure_text("M")
        .map(|m| m.width())
        .unwrap_or(font_px * 0.6)
        .max(1.0);
    let cell_h = (font_px * 1.2).round();

    let term = Rc::new(RefCell::new(Term {
        ctx,
        canvas,
        dpr,
        font_px,
        font_family,
        cell_w,
        cell_h,
        cols: 0,
        rows: 0,
        buf: Vec::new(),
        cursor: Cursor {
            line: 0,
            col: 0,
            shape: "block".into(),
            visible: false,
        },
        sel: None,
        selecting: false,
    }));

    // --- grid-damage listener ---
    {
        let term = term.clone();
        listen("grid-damage", move |payload| {
            if let Ok(d) = serde_wasm_bindgen::from_value::<GridDamage>(payload) {
                term.borrow_mut().apply(d);
            }
        });
    }

    // --- pty-exit listener ---
    {
        let term = term.clone();
        listen("pty-exit", move |_| {
            let t = term.borrow();
            let row = (t.cursor.line + 1).min(t.rows.saturating_sub(1));
            let (x, y, _, _) = t.cell_px(0, row);
            t.ctx.set_font(&format!("{}px {}", t.font_px, t.font_family));
            t.ctx.set_fill_style_str(&css([0xff, 0x6b, 0x6b]));
            let _ = t.ctx.fill_text("[process exited]", x, y);
        });
    }

    // --- spawn the PTY, then request the initial full grid ---
    let (cols, rows) = term.borrow_mut().fit();
    let theme = settings_theme();
    wasm_bindgen_futures::spawn_local(async move {
        let _ = invoke("pty_spawn", SpawnArgs { rows, cols }).await;
        // Apply the persisted theme to the engine now that it exists (fixes the grid rendering
        // default colors until the user re-touches the theme select). term_set_theme also emits
        // the initial full grid-damage repaint, so no separate term_full_repaint is needed.
        let _ = invoke("term_set_theme", ThemeArgs { name: theme }).await;
    });

    // --- keyboard input ---
    let typed = Rc::new(RefCell::new(String::new()));
    {
        let typed = typed.clone();
        let term = term.clone();
        let cb = Closure::wrap(Box::new(move |ev: KeyboardEvent| {
            // ⌘C with an active selection: copy it, don't fall through to the shell.
            if ev.meta_key() && ev.key() == "c" {
                if let Some(text) = term.borrow().selection_text() {
                    crate::bridge::clipboard_write(&text);
                    ev.prevent_default();
                    return;
                }
                // no selection: fall through to the ⌘-chord return below (⌘C = default/no-op).
            }
            // ⌘-chords are app shortcuts (settings/ai-bar/palette/…) — never PTY input.
            if ev.meta_key() {
                return;
            }
            // An overlay input (ai-bar / palette / settings / vim search) is focused: its own
            // handler owns the key. This document-level listener must NOT also write it to the
            // PTY — otherwise typing (and the agent-approval Enter) leaks straight to the shell.
            if editable_focused() {
                return;
            }
            let app_cursor = APP_CURSOR.with(|a| a.get());
            let Some(data) = encode_key(&ev.key(), ev.ctrl_key(), ev.alt_key(), app_cursor) else {
                return;
            };
            ev.prevent_default();
            reconstruct_typed_line(&typed, &data);
            let payload = data.clone();
            wasm_bindgen_futures::spawn_local(async move {
                let _ = invoke("pty_write", WriteArgs { data: payload }).await;
            });
        }) as Box<dyn FnMut(KeyboardEvent)>);
        let _ = document
            .add_event_listener_with_callback("keydown", cb.as_ref().unchecked_ref());
        cb.forget();
    }

    // --- paste (Cmd+V): the native `paste` event fires even though keydown ignores ⌘-chords;
    // forward the clipboard text to the PTY, but not while an overlay input is focused. ---
    {
        let typed = typed.clone();
        let cb = Closure::wrap(Box::new(move |ev: web_sys::ClipboardEvent| {
            if editable_focused() {
                return;
            }
            let Some(text) = ev.clipboard_data().and_then(|d| d.get_data("text/plain").ok()) else {
                return;
            };
            if text.is_empty() {
                return;
            }
            ev.prevent_default();
            reconstruct_typed_line(&typed, &text);
            wasm_bindgen_futures::spawn_local(async move {
                let _ = invoke("pty_write", WriteArgs { data: text }).await;
            });
        }) as Box<dyn FnMut(web_sys::ClipboardEvent)>);
        let _ = document.add_event_listener_with_callback("paste", cb.as_ref().unchecked_ref());
        cb.forget();
    }

    // --- mouse wheel: scroll native scrollback. Up (delta_y<0) goes BACK in history. ---
    {
        let term = term.clone();
        let canvas_el = term.borrow().canvas.clone();
        let cb = Closure::wrap(Box::new(move |ev: web_sys::WheelEvent| {
            ev.prevent_default();
            let dy = ev.delta_y();
            let ch = term.borrow().cell_h; // live: stays correct after a font-size change
            let lines = (dy / ch).round().abs().max(1.0) as i32;
            let delta = if dy < 0.0 { lines } else { -lines };
            wasm_bindgen_futures::spawn_local(async move {
                let _ = invoke("term_scroll", ScrollArgs { delta }).await;
            });
        }) as Box<dyn FnMut(web_sys::WheelEvent)>);
        let _ = canvas_el.add_event_listener_with_callback("wheel", cb.as_ref().unchecked_ref());
        cb.forget();
    }

    // --- mouse selection: mousedown (canvas) anchors; mousemove/mouseup (document) drag/end ---
    {
        let term = term.clone();
        let canvas_el = term.borrow().canvas.clone();
        let cb = Closure::wrap(Box::new(move |ev: web_sys::MouseEvent| {
            let mut t = term.borrow_mut();
            let cell = t.cell_at(ev.offset_x() as f64, ev.offset_y() as f64);
            t.sel = Some((cell, cell));
            t.selecting = true;
            t.redraw();
        }) as Box<dyn FnMut(web_sys::MouseEvent)>);
        let _ = canvas_el.add_event_listener_with_callback("mousedown", cb.as_ref().unchecked_ref());
        cb.forget();
    }
    {
        let term = term.clone();
        let canvas_el = term.borrow().canvas.clone();
        let cb = Closure::wrap(Box::new(move |ev: web_sys::MouseEvent| {
            let mut t = term.borrow_mut();
            if !t.selecting {
                return;
            }
            // mousemove is on `document` so the drag can continue past the canvas edges, but
            // offset_x/offset_y would then be relative to whatever element is under the pointer
            // (a status/ai bar). Use client coords minus the canvas rect; cell_at clamps.
            let rect = canvas_el.get_bounding_client_rect();
            let x = ev.client_x() as f64 - rect.left();
            let y = ev.client_y() as f64 - rect.top();
            let anchor = t.sel.map(|(a, _)| a).unwrap_or_default();
            let focus = t.cell_at(x, y);
            t.sel = Some((anchor, focus));
            t.redraw();
        }) as Box<dyn FnMut(web_sys::MouseEvent)>);
        let _ = document.add_event_listener_with_callback("mousemove", cb.as_ref().unchecked_ref());
        cb.forget();
    }
    {
        let term = term.clone();
        let cb = Closure::wrap(Box::new(move |_ev: web_sys::MouseEvent| {
            let mut t = term.borrow_mut();
            // A plain click (no drag) leaves a 1-cell anchor==focus selection; clear it so it
            // doesn't linger as a stray highlight.
            if t.sel.map(|(a, b)| a == b).unwrap_or(false) {
                t.sel = None;
                t.redraw();
            }
            t.selecting = false;
        }) as Box<dyn FnMut(web_sys::MouseEvent)>);
        let _ = document.add_event_listener_with_callback("mouseup", cb.as_ref().unchecked_ref());
        cb.forget();
    }

    // --- live font/size changes from the settings panel (dispatches "tachyon-font") ---
    {
        let term = term.clone();
        let cb = Closure::wrap(Box::new(move |_ev: web_sys::Event| {
            let (px, family) = settings_font();
            let (cols, rows) = {
                let mut t = term.borrow_mut();
                t.set_font(px, family);
                t.fit()
            };
            // resizing the PTY makes the native side emit a full grid-damage repaint.
            wasm_bindgen_futures::spawn_local(async move {
                let _ = invoke("pty_resize", SpawnArgs { rows, cols }).await;
            });
        }) as Box<dyn FnMut(web_sys::Event)>);
        let _ = win().add_event_listener_with_callback("tachyon-font", cb.as_ref().unchecked_ref());
        cb.forget();
    }

    // --- resize: a ResizeObserver on <html> refits the canvas and resizes the PTY.
    // More reliable than the window "resize" event across the macOS fullscreen settle. ---
    {
        let term = term.clone();
        // ResizeObserver fires once automatically on observe(); setup() already did the initial
        // fit(), so skip that first callback to avoid a redundant wipe-repaint flicker at launch.
        let first = std::rc::Rc::new(std::cell::Cell::new(true));
        let cb = Closure::wrap(Box::new(move |_: js_sys::Array, _: web_sys::ResizeObserver| {
            if first.replace(false) {
                return;
            }
            let (cols, rows) = term.borrow_mut().fit();
            // pty_resize emits a full grid-damage repaint from the native side.
            wasm_bindgen_futures::spawn_local(async move {
                let _ = invoke("pty_resize", SpawnArgs { rows, cols }).await;
            });
        })
            as Box<dyn FnMut(js_sys::Array, web_sys::ResizeObserver)>);
        if let Ok(observer) = web_sys::ResizeObserver::new(cb.as_ref().unchecked_ref()) {
            if let Some(root) = document.document_element() {
                observer.observe(&root);
            }
            std::mem::forget(observer);
        }
        cb.forget();
    }
}

/// Mirror of src/main.ts:673-695 — rebuild the typed command line for the
/// journal. On a completed line, tell the native side via `set_typed_command`.
fn reconstruct_typed_line(typed: &Rc<RefCell<String>>, data: &str) {
    if data.starts_with('\x1b') {
        typed.borrow_mut().clear();
        return;
    }
    for ch in data.chars() {
        if ch == '\r' || ch == '\n' {
            let line = std::mem::take(&mut *typed.borrow_mut());
            wasm_bindgen_futures::spawn_local(async move {
                let _ = invoke("set_typed_command", TypedArgs { line }).await;
            });
        } else if ch == '\x7f' || ch == '\x08' {
            typed.borrow_mut().pop();
        } else if ch == '\x15' || ch == '\x03' {
            typed.borrow_mut().clear();
        } else if ch >= ' ' {
            typed.borrow_mut().push(ch);
        }
    }
}

#[component]
pub fn Terminal() -> Element {
    // use_effect runs after the canvas is mounted; no reactive reads => once.
    use_effect(setup);
    rsx! {
        canvas { id: "term" }
    }
}

#[cfg(test)]
mod tests {
    use super::{encode_key, linear_selection};

    #[test]
    fn selection_extraction() {
        let lines = ["foo bar baz".to_string(), "qux Foo end".to_string()];
        // row-major across two rows: (row,col) from (0,8) to (1,2) => "baz\nqux"
        assert_eq!(linear_selection(&lines, (0, 8), (1, 2)), "baz\nqux");
        // reversed anchor/focus yields the same text
        assert_eq!(linear_selection(&lines, (1, 2), (0, 8)), "baz\nqux");
        // single-row inclusive slice
        assert_eq!(linear_selection(&lines, (0, 0), (0, 2)), "foo");
    }

    #[test]
    fn key_encoding() {
        // normal-cursor (CSI) mode
        assert_eq!(encode_key("a", false, false, false).as_deref(), Some("a"));
        assert_eq!(encode_key("Enter", false, false, false).as_deref(), Some("\r"));
        assert_eq!(encode_key("Backspace", false, false, false).as_deref(), Some("\x7f"));
        assert_eq!(encode_key("Tab", false, false, false).as_deref(), Some("\t"));
        assert_eq!(encode_key("Escape", false, false, false).as_deref(), Some("\x1b"));
        assert_eq!(encode_key("ArrowUp", false, false, false).as_deref(), Some("\x1b[A"));
        assert_eq!(encode_key("ArrowDown", false, false, false).as_deref(), Some("\x1b[B"));
        assert_eq!(encode_key("ArrowRight", false, false, false).as_deref(), Some("\x1b[C"));
        assert_eq!(encode_key("ArrowLeft", false, false, false).as_deref(), Some("\x1b[D"));
        assert_eq!(encode_key("Home", false, false, false).as_deref(), Some("\x1b[H"));
        assert_eq!(encode_key("End", false, false, false).as_deref(), Some("\x1b[F"));
        assert_eq!(encode_key("PageUp", false, false, false).as_deref(), Some("\x1b[5~"));
        // application-cursor (DECCKM) mode: SS3 (ESC O x) for cursor keys
        assert_eq!(encode_key("ArrowUp", false, false, true).as_deref(), Some("\x1bOA"));
        assert_eq!(encode_key("End", false, false, true).as_deref(), Some("\x1bOF"));
        // PageUp is mode-independent
        assert_eq!(encode_key("PageUp", false, false, true).as_deref(), Some("\x1b[5~"));
        // Ctrl-C = 0x03, Ctrl-U = 0x15, Ctrl-A = 0x01
        assert_eq!(encode_key("c", true, false, false).as_deref(), Some("\x03"));
        assert_eq!(encode_key("u", true, false, false).as_deref(), Some("\x15"));
        assert_eq!(encode_key("A", true, false, false).as_deref(), Some("\x01"));
        // Alt/meta prefix
        assert_eq!(encode_key("b", false, true, false).as_deref(), Some("\x1bb"));
        // Unhandled modifiers/keys
        assert_eq!(encode_key("Shift", false, false, false), None);
        assert_eq!(encode_key("F5", false, false, false), None);
    }
}
