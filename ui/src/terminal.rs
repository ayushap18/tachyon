//! Canvas terminal: consumes the native "grid-damage" contract and paints it,
//! and encodes keystrokes back to the PTY.

use std::cell::RefCell;
use std::rc::Rc;

use dioxus::prelude::*;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use web_sys::{CanvasRenderingContext2d, HtmlCanvasElement, KeyboardEvent};

use crate::bridge::{invoke, listen, NoArgs, WriteArgs};

const FONT_PX: f64 = 14.0;

// ---- grid-damage contract (mirrors src-tauri/src/engine.rs) ----

#[derive(Deserialize, Clone)]
struct Cursor {
    line: u16,
    col: u16,
    color: [u8; 3],
    visible: bool,
}

/// The wire shape of a cell: [line, col, ch, fg, bg, flags], with the colours packed into a
/// u32 and bold/italic/inverse/underline into one bitfield. See the `Serialize` impl in
/// src-tauri/src/engine.rs — the two must change together.
#[derive(Deserialize)]
struct WireCell(u16, u16, String, u32, u32, u8);

impl From<WireCell> for Cell {
    fn from(w: WireCell) -> Self {
        let unpack = |v: u32| [(v >> 16) as u8, (v >> 8) as u8, v as u8];
        Cell {
            line: w.0,
            col: w.1,
            ch: w.2,
            fg: unpack(w.3),
            bg: unpack(w.4),
            bold: w.5 & 1 != 0,
            italic: w.5 & 2 != 0,
            inverse: w.5 & 4 != 0,
            underline: w.5 & 8 != 0,
        }
    }
}

#[derive(Deserialize, Clone)]
#[serde(from = "WireCell")]
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

fn blank_cell(bg: [u8; 3], fg: [u8; 3]) -> Cell {
    Cell {
        line: 0,
        col: 0,
        ch: " ".into(),
        fg,
        bg,
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
    /// The geometry `fit` last measured, which is what the native side was asked for.
    /// `cols`/`rows` above are what came back, and the native area clamp may have cut them —
    /// comparing a fresh fit against those would make every resize event look like a change
    /// and re-send pty_resize 60x a second for the whole drag.
    asked: (u16, u16),
    /// The active theme's terminal background and foreground. `bg` is the colour the
    /// native window is painted, so cells carrying it are cleared rather than filled.
    bg: [u8; 3],
    fg: [u8; 3],
    /// Selection tint, drawn translucent over the cells it covers.
    accent: [u8; 3],
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
    // True while any chrome overlay (ai-bar/palette/settings/blocks) is open. Set from app.rs's
    // overlay effect. Defense-in-depth: the document key/paste handlers early-return on it so a
    // focus miss can never leak the user's typing to the shell.
    static OVERLAY_OPEN: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Tell the terminal an overlay is (or isn't) open — see OVERLAY_OPEN.
pub fn set_overlay_open(open: bool) {
    OVERLAY_OPEN.with(|o| o.set(open));
}

/// Font family + pixel size from the persisted settings (localStorage "tachyon-settings").
/// Falls back to the defaults when unset/unparseable — mirrors settings.rs's seed.
fn settings_font() -> (f64, String) {
    let mut px = FONT_PX;
    let mut family = crate::theme::default_font();
    if let Some(raw) = web_sys::window()
        .and_then(|w| w.local_storage().ok().flatten())
        .and_then(|s| s.get_item("tachyon-settings").ok().flatten())
    {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&raw) {
            if let Some(s) = v.get("size").and_then(|s| s.as_f64()) {
                px = s.clamp(9.0, 28.0);
            }
            if let Some(f) = v.get("font").and_then(|f| f.as_str()) {
                family = crate::theme::resolve_font(f);
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

/// The saved theme's terminal (background, foreground) as canvas bytes. Read from the
/// theme table rather than the computed `--bg`, which is unset until app.rs's first effect.
fn theme_rgb() -> ([u8; 3], [u8; 3], [u8; 3]) {
    let t = crate::theme::tokens(&settings_theme());
    let rgb = |h| parse_hex(h).unwrap_or_default();
    (rgb(t.bg), rgb(t.fg), rgb(t.accent))
}

/// Maximal spans of adjacent cells sharing a font and a fill colour, as half-open
/// `(start, end)` column ranges.
fn style_runs(row: &[Cell]) -> Vec<(usize, usize)> {
    let key = |c: &Cell| (c.italic, c.bold, if c.inverse { c.bg } else { c.fg });
    let mut runs = Vec::new();
    let mut start = 0;
    while start < row.len() {
        let k = key(&row[start]);
        let mut end = start + 1;
        while end < row.len() && key(&row[end]) == k {
            end += 1;
        }
        runs.push((start, end));
        start = end;
    }
    runs
}

/// Trailing-trimmed row strings of a visible buffer (mirrors xterm translateToString(true)).
fn rows_text(buf: &[Cell], rows: u16, cols: u16) -> Vec<String> {
    let cols = cols as usize;
    (0..rows as usize)
        .map(|r| {
            let mut s = String::with_capacity(cols);
            for c in 0..cols {
                if let Some(cell) = buf.get(r * cols + c) {
                    s.push_str(&cell.ch);
                }
            }
            s.trim_end().to_string()
        })
        .collect()
}

/// Grid size for a canvas box: whole cells only, and never zero (a PTY rejects a 0 dimension).
fn grid_dims(w: f64, h: f64, cell_w: f64, cell_h: f64) -> (u16, u16) {
    let n = |px: f64, cell: f64| (px / cell).floor().max(1.0) as u16;
    (n(w, cell_w), n(h, cell_h))
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

    /// Snap shared cell edges to physical pixels, including fractional display scales.
    fn cell_px(&self, col: u16, line: u16) -> (f64, f64, f64, f64) {
        let snap = |v: f64| (v * self.dpr).round() / self.dpr;
        let x0 = snap(col as f64 * self.cell_w);
        let x1 = snap((col + 1) as f64 * self.cell_w);
        let y0 = snap(line as f64 * self.cell_h);
        let y1 = snap((line + 1) as f64 * self.cell_h);
        (x0, y0, x1 - x0, y1 - y0)
    }

    /// Size the grid to the actual canvas box. CSS reserves space for the status
    /// bar and padding; using window.innerHeight would hide the last shell rows.
    fn fit(&mut self) -> (u16, u16) {
        self.dpr = win().device_pixel_ratio().max(1.0);
        let rect = self.canvas.get_bounding_client_rect();
        let (w, h) = (rect.width().max(1.0), rect.height().max(1.0));
        self.canvas.set_width((w * self.dpr).round() as u32);
        self.canvas.set_height((h * self.dpr).round() as u32);
        let _ = self.ctx.scale(self.dpr, self.dpr);
        self.ctx.set_text_baseline("top");
        self.clear();
        self.asked = grid_dims(w, h, self.cell_w, self.cell_h);
        self.asked
    }

    fn clear(&self) {
        self.ctx.clear_rect(
            0.0, 0.0,
            self.canvas.width() as f64 / self.dpr,
            self.canvas.height() as f64 / self.dpr,
        );
    }

    fn resize(&mut self, cols: u16, rows: u16) {
        self.cols = cols;
        self.rows = rows;
        self.buf = vec![blank_cell(self.bg, self.fg); cols as usize * rows as usize];
        self.clear();
    }

    /// Repaint a damaged row in two passes: all backgrounds, then all glyphs.
    /// A glyph can overhang its own cell (italic, bold, combining or wide text).
    /// Clearing only changed cells leaves those pixels behind; drawing the next
    /// cell's background after a wide glyph also erases half of that glyph.
    fn draw_row(&self, line: u16) {
        if line >= self.rows || self.cols == 0 {
            return;
        }
        let (_, y, _, h) = self.cell_px(0, line);
        let (last_x, _, last_w, _) = self.cell_px(self.cols - 1, line);
        self.ctx.save();
        self.ctx.begin_path();
        self.ctx.rect(0.0, y, last_x + last_w, h);
        self.ctx.clip();

        // Adjacent equal backgrounds are one fill, so an ordinary row is cheap. A run in the
        // theme background is cleared instead: the native window already carries that colour,
        // at the user's opacity, and filling it would composite a second opaque layer.
        // ponytail: this keys on the colour, so an explicit background that happens to equal
        // the theme's (ANSI black under Matrix) also goes see-through. Upgrade path is an
        // is_default flag on the wire cell.
        let start = line as usize * self.cols as usize;
        let row = &self.buf[start..start + self.cols as usize];
        let background = |c: &Cell| if c.inverse { c.fg } else { c.bg };
        let mut col = 0usize;
        while col < row.len() {
            let bg = background(&row[col]);
            let mut end = col + 1;
            while end < row.len() && background(&row[end]) == bg {
                end += 1;
            }
            let (x, _, _, _) = self.cell_px(col as u16, line);
            let (ex, _, ew, _) = self.cell_px((end - 1) as u16, line);
            if bg == self.bg {
                self.ctx.clear_rect(x, y, ex + ew - x, h);
            } else {
                self.ctx.set_fill_style_str(&css(bg));
                self.ctx.fill_rect(x, y, ex + ew - x, h);
            }
            col = end;
        }
        // set_font reparses a CSS font string, so the four variants are built once per row
        // and the canvas state is set per run of same-styled cells, not per glyph.
        let fonts: [String; 4] = std::array::from_fn(|i| {
            format!(
                "{}{}{}px {}",
                if i & 2 != 0 { "italic " } else { "" },
                if i & 1 != 0 { "bold " } else { "" },
                self.font_px, self.font_family,
            )
        });
        let (mut last_font, mut last_fg) = (usize::MAX, None);
        for (start, end) in style_runs(row) {
            let head = &row[start];
            let f = (usize::from(head.italic) << 1) | usize::from(head.bold);
            let fg = if head.inverse { head.bg } else { head.fg };
            if f != last_font {
                self.ctx.set_font(&fonts[f]);
                last_font = f;
            }
            if last_fg != Some(fg) {
                self.ctx.set_fill_style_str(&css(fg));
                last_fg = Some(fg);
            }
            for (col, cell) in (start..end).zip(&row[start..end]) {
                let (x, _, w, _) = self.cell_px(col as u16, line);
                if cell.ch != " " && !cell.ch.is_empty() {
                    let _ = self.ctx.fill_text(&cell.ch, x, y);
                }
                if cell.underline {
                    self.ctx.fill_rect(x, y + h - 1.0, w, 1.0);
                }
            }
        }
        self.ctx.restore();
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
        self.ctx.save();
        self.ctx.begin_path();
        self.ctx.rect(x, y, w, h);
        self.ctx.clip();
        self.ctx.set_fill_style_str(&css(self.cursor.color));
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
        self.ctx.restore();
    }

    /// Pixel (canvas-relative CSS px) -> (row, col), clamped to the grid.
    fn cell_at(&self, ox: f64, oy: f64) -> (u16, u16) {
        let col = (ox / self.cell_w).floor().max(0.0) as u16;
        let row = (oy / self.cell_h).floor().max(0.0) as u16;
        (row.min(self.rows.saturating_sub(1)), col.min(self.cols.saturating_sub(1)))
    }

    /// Extract the current selection's text (None if nothing selected).
    fn selection_text(&self) -> Option<String> {
        let (a, b) = self.sel?;
        Some(linear_selection(&rows_text(&self.buf, self.rows, self.cols), a, b))
    }

    /// Overlay a translucent highlight on the cells inside the linear selection.
    fn overlay_selection(&self) {
        let Some((a, b)) = self.sel else { return };
        let (s, e) = if a.0 < b.0 || (a.0 == b.0 && a.1 <= b.1) { (a, b) } else { (b, a) };
        let [r, g, b] = self.accent;
        self.ctx.set_fill_style_str(&format!("rgba({r},{g},{b},0.35)"));
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
        self.clear();
        for row in 0..self.rows {
            self.draw_row(row);
        }
        self.overlay_selection();
        self.draw_cursor();
    }

    fn apply(&mut self, d: GridDamage) {
        let clear_selection = self.sel.take().is_some();
        let resized = d.cols != self.cols || d.rows != self.rows || self.buf.is_empty();
        if resized {
            self.resize(d.cols, d.rows);
        }
        let mut dirty = vec![resized || clear_selection; self.rows as usize];
        if self.cursor.visible {
            if let Some(row) = dirty.get_mut(self.cursor.line as usize) {
                *row = true;
            }
        }
        for cell in d.cells {
            if let Some(i) = self.idx(cell.line, cell.col) {
                dirty[cell.line as usize] = true;
                self.buf[i] = cell;
            }
        }
        for (row, changed) in dirty.into_iter().enumerate() {
            if changed {
                self.draw_row(row as u16);
            }
        }
        self.cursor = d.cursor;
        APP_CURSOR.with(|a| a.set(d.application_cursor));
        self.draw_cursor();
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
    // The live terminal, so the vim module can read the painted viewport on demand.
    static TERM: RefCell<Option<Rc<RefCell<Term>>>> = const { RefCell::new(None) };
}

/// Snapshot the current visible grid. Built on demand — vim navigation follows the
/// currently painted viewport. Returns the default if the terminal is mid-repaint.
pub fn grid_view() -> GridView {
    TERM.with(|slot| {
        let Ok(slot) = slot.try_borrow() else { return GridView::default() };
        let Some(term) = slot.as_ref().and_then(|t| t.try_borrow().ok()) else {
            return GridView::default();
        };
        GridView {
            cols: term.cols,
            rows: term.rows,
            cell_w: term.cell_w,
            cell_h: term.cell_h,
            cursor_line: term.cursor.line,
            cursor_col: term.cursor.col,
            lines: rows_text(&term.buf, term.rows, term.cols),
        }
    })
}

/// Batch wheel events at display cadence, and wait for each native scroll to
/// finish before submitting the next. The accumulator remains live while waiting.
fn schedule_scroll(
    pending: Rc<RefCell<crate::scroll::ScrollAccumulator>>,
    scheduled: Rc<std::cell::Cell<bool>>,
) {
    if !pending.borrow().has_rows() || scheduled.replace(true) {
        return;
    }
    let scheduled_on_error = scheduled.clone();
    let flush = Closure::once_into_js(move || {
        let delta = pending.borrow_mut().take();
        wasm_bindgen_futures::spawn_local(async move {
            if delta != 0 {
                let _ = invoke("term_scroll", ScrollArgs { delta }).await;
            }
            scheduled.set(false);
            schedule_scroll(pending, scheduled);
        });
    });
    if win().request_animation_frame(flush.as_ref().unchecked_ref()).is_err() {
        scheduled_on_error.set(false);
    }
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
struct ResizeArgs {
    rows: u16,
    cols: u16,
}
/// pty_spawn only. The engine is built with this theme so the shell's first output is painted
/// in the user's palette; it used to be born dark and corrected by a second round trip.
#[derive(Serialize)]
struct SpawnThemeArgs {
    rows: u16,
    cols: u16,
    theme: String,
}
#[derive(Serialize)]
struct TypedArgs {
    line: String,
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

/// Re-fit the canvas to the current viewport. fit() runs every call (it resizes the backing store
/// to match the display size, so the canvas never stretches a stale frame during a maximize/resize
/// animation); pty_resize only fires when the grid dimensions actually changed, so we don't spam
/// the native side per animation frame.
fn refit(term: &Rc<RefCell<Term>>) {
    let (cols, rows, changed) = {
        let mut t = term.borrow_mut();
        let prev = t.asked;
        let (cols, rows) = t.fit(); // resizes the backing store, which CLEARS the canvas
        let changed = (cols, rows) != prev;
        t.redraw(); // repaint current content so a no-grid-change resize doesn't blank the screen
        (cols, rows, changed)
    };
    // Only round-trip to the native side when the grid actually changed (a real reflow); the
    // full grid-damage it emits then repaints the new dimensions.
    if changed {
        wasm_bindgen_futures::spawn_local(async move {
            let _ = invoke("pty_resize", ResizeArgs { rows, cols }).await;
        });
    }
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

fn setup(mut keys_loaded: Signal<bool>) {
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
    let (bg, fg, accent) = theme_rgb();

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
        asked: (0, 0),
        bg,
        fg,
        accent,
        buf: Vec::new(),
        cursor: Cursor {
            line: 0,
            col: 0,
            color: fg,
            visible: false,
        },
        sel: None,
        selecting: false,
    }));
    TERM.with(|slot| *slot.borrow_mut() = Some(term.clone()));

    // --- grid-damage listener ---
    {
        let term = term.clone();
        listen("grid-damage", move |payload| {
            if let Ok(d) = serde_wasm_bindgen::from_value::<GridDamage>(payload) {
                term.borrow_mut().apply(d);
            }
        });
    }

    // --- dead-backend-thread banners ---
    // Both events fire from a Drop guard on a pty_spawn thread, so they also arrive when that
    // thread panicked. paint-dead means nothing will repaint over this line ever again.
    for (event, text) in [
        ("pty-exit", "[process exited]"),
        ("paint-dead", "[tachyon] repaint thread died — the screen is frozen; restart tachyon"),
    ] {
        let term = term.clone();
        listen(event, move |_| {
            let t = term.borrow();
            let row = (t.cursor.line + 1).min(t.rows.saturating_sub(1));
            let (x, y, _, _) = t.cell_px(0, row);
            t.ctx.set_font(&format!("{}px {}", t.font_px, t.font_family));
            t.ctx.set_fill_style_str(crate::theme::tokens(&settings_theme()).err);
            let _ = t.ctx.fill_text(text, x, y);
        });
    }

    // --- spawn the PTY, then request the initial full grid ---
    let (cols, rows) = term.borrow_mut().fit();
    let theme = settings_theme();
    wasm_bindgen_futures::spawn_local(async move {
        // Keybinding overrides load here, not in app.rs: a corrupt file is reported on the
        // canvas, and term_write paints nothing until pty_spawn has created the engine.
        let key_err = crate::keymap::load().await;
        keys_loaded.set(true);
        // pty_spawn's Result used to be discarded: a failed shell spawn left a blank canvas
        // with no feedback anywhere. It also returns an optional warning (no shell
        // integration => no command journal), which is otherwise invisible.
        match invoke("pty_spawn", SpawnThemeArgs { rows, cols, theme }).await {
            Err(e) => {
                let msg = e.as_string().unwrap_or_else(|| "failed to start the shell".into());
                crate::bridge::term_write(format!("\r\n\x1b[31m[tachyon] {msg}\x1b[0m\r\n"));
                return;
            }
            Ok(v) => {
                if let Some(warning) = v.as_string() {
                    crate::bridge::term_write(format!("\r\n\x1b[33m[tachyon] {warning}\x1b[0m\r\n"));
                }
            }
        }
        if let Some(e) = key_err {
            crate::bridge::term_write(format!("\r\n\x1b[33m[tachyon] keybindings: {e} — using defaults\x1b[0m\r\n"));
        }
        // The engine already has this theme (passed to pty_spawn), so all this asks for is
        // the initial full frame; it is idempotent with the shell's first output.
        let _ = invoke("term_full_repaint", NoArgs {}).await;
    });

    // --- keyboard input ---
    let typed = Rc::new(RefCell::new(String::new()));
    {
        let typed = typed.clone();
        let term = term.clone();
        let cb = Closure::wrap(Box::new(move |ev: KeyboardEvent| {
            let action = crate::keymap::action_for(&ev);
            let is_mac = crate::keymap::is_mac();
            // Copy chord with an active selection: copy it, don't fall through to the shell.
            if action == Some(crate::keymap::Action::Copy) {
                if let Some(text) = term.borrow().selection_text() {
                    crate::bridge::clipboard_write(&text);
                    ev.prevent_default();
                    return;
                }
                // no selection: fall through to the app-chord return below (default/no-op).
            }
            // Keymap chords are app shortcuts (settings/ai-bar/palette/…) — never PTY input.
            // On macOS that covers every ⌘-chord; elsewhere only what the keymap binds is
            // swallowed, so plain Ctrl+<key> still reaches the shell through encode_key.
            if action.is_some() || (is_mac && ev.meta_key()) {
                return;
            }
            // Ctrl+Shift+V is paste off macOS: leave it to the webview so its native `paste`
            // event (handled below) fires, instead of encoding it as ^V.
            if !is_mac && ev.ctrl_key() && ev.shift_key() && ev.key().eq_ignore_ascii_case("v") {
                return;
            }
            // An overlay input (ai-bar / palette / settings / vim search) is focused: its own
            // handler owns the key. This document-level listener must NOT also write it to the
            // PTY — otherwise typing (and the agent-approval Enter) leaks straight to the shell.
            if editable_focused() || OVERLAY_OPEN.with(|o| o.get()) {
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

    // --- paste (⌘V / Ctrl+Shift+V): the native `paste` event fires because keydown leaves those alone;
    // forward the clipboard text to the PTY, but not while an overlay input is focused. ---
    {
        let typed = typed.clone();
        let cb = Closure::wrap(Box::new(move |ev: web_sys::ClipboardEvent| {
            if editable_focused() || OVERLAY_OPEN.with(|o| o.get()) {
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

    // Keep fractional trackpad motion and respect pixel/line/page wheel units.
    // One outstanding IPC request prevents a slow backend building a stale queue.
    {
        let term = term.clone();
        let canvas_el = term.borrow().canvas.clone();
        let pending = Rc::new(RefCell::new(crate::scroll::ScrollAccumulator::default()));
        let scheduled = Rc::new(std::cell::Cell::new(false));
        let cb = Closure::wrap(Box::new(move |ev: web_sys::WheelEvent| {
            ev.prevent_default();
            if ev.delta_y() == 0.0 || ev.ctrl_key() || OVERLAY_OPEN.with(|o| o.get()) {
                return;
            }
            let t = term.borrow();
            pending.borrow_mut().push(ev.delta_y(), ev.delta_mode(), t.cell_h, t.rows);
            drop(t);
            schedule_scroll(pending.clone(), scheduled.clone());
        }) as Box<dyn FnMut(web_sys::WheelEvent)>);
        let options = web_sys::AddEventListenerOptions::new();
        options.set_passive(false);
        let _ = canvas_el.add_event_listener_with_callback_and_add_event_listener_options(
            "wheel", cb.as_ref().unchecked_ref(), &options,
        );
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

    // --- live font/size/theme changes from the settings panel (dispatches "tachyon-font") ---
    {
        let term = term.clone();
        let cb = Closure::wrap(Box::new(move |_ev: web_sys::Event| {
            let (px, family) = settings_font();
            let (cols, rows) = {
                let mut t = term.borrow_mut();
                (t.bg, t.fg, t.accent) = theme_rgb();
                t.set_font(px, family);
                t.fit()
            };
            // resizing the PTY makes the native side emit a full grid-damage repaint.
            wasm_bindgen_futures::spawn_local(async move {
                let _ = invoke("pty_resize", ResizeArgs { rows, cols }).await;
            });
        }) as Box<dyn FnMut(web_sys::Event)>);
        let _ = win().add_event_listener_with_callback("tachyon-font", cb.as_ref().unchecked_ref());
        cb.forget();
    }

    // --- resize: a ResizeObserver refits the canvas and resizes the PTY.
    // More reliable than the window "resize" event across the macOS fullscreen settle. ---
    {
        let term = term.clone();
        let canvas_obs = term.borrow().canvas.clone();
        let cb = Closure::wrap(Box::new(move |_: js_sys::Array, _: web_sys::ResizeObserver| {
            refit(&term);
        })
            as Box<dyn FnMut(js_sys::Array, web_sys::ResizeObserver)>);
        if let Ok(observer) = web_sys::ResizeObserver::new(cb.as_ref().unchecked_ref()) {
            observer.observe(canvas_obs.unchecked_ref());
            std::mem::forget(observer);
        }
        cb.forget();
    }

    // --- window "resize": fires per-frame during a maximize/drag animation, so refit here keeps
    // the backing store synced with the display size and the canvas never stretches a stale frame
    // (the ResizeObserver above still catches the macOS fullscreen settle the resize event misses). ---
    {
        let term = term.clone();
        let cb = Closure::wrap(Box::new(move |_: web_sys::Event| {
            refit(&term);
        }) as Box<dyn FnMut(web_sys::Event)>);
        let _ = win().add_event_listener_with_callback("resize", cb.as_ref().unchecked_ref());
        cb.forget();
    }
}

/// Rebuild the typed command line for the journal. On a completed line, tell the native side via `set_typed_command`.
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
    let keys_loaded = use_context::<crate::app::AppState>().keys_loaded;
    use_effect(move || setup(keys_loaded));
    rsx! {
        canvas { id: "term" }
    }
}

#[cfg(test)]
mod tests {
    use super::{blank_cell, encode_key, grid_dims, linear_selection, rows_text, style_runs, Cell};

    fn styled(ch: &str, fg: [u8; 3], bold: bool) -> Cell {
        Cell { ch: ch.into(), fg, bold, ..blank_cell([0; 3], [0; 3]) }
    }

    // Guards the painter's canvas-state budget: set_font/set_fill_style_str run per run,
    // so a run that fails to coalesce is a per-glyph font reparse again.
    #[test]
    fn style_runs_coalesces_adjacent_identical_styles() {
        let red = [0xff, 0, 0];
        let row = [
            styled("a", red, false),
            styled("b", red, false),
            styled("c", red, true),
            styled("d", [0, 0xff, 0], true),
        ];
        assert_eq!(style_runs(&row), [(0, 2), (2, 3), (3, 4)]);
        assert_eq!(style_runs(&[]), []);

        // inverse swaps fg/bg, so it coalesces with a plain cell of the same painted colour.
        let mut inv = styled("e", [0, 0, 0], false);
        inv.bg = red;
        inv.inverse = true;
        assert_eq!(style_runs(&[styled("a", red, false), inv]), [(0, 2)]);
    }

    #[test]
    fn rows_text_trims_trailing_blanks() {
        let mut buf = vec![blank_cell([0; 3], [0; 3]); 6];
        buf[0].ch = "h".into();
        buf[1].ch = "i".into();
        buf[3].ch = "y".into();
        assert_eq!(rows_text(&buf, 2, 3), ["hi", "y"]);
        // a buffer shorter than rows*cols yields empty rows rather than panicking
        assert_eq!(rows_text(&[], 2, 3), ["", ""]);
    }

    #[test]
    fn grid_dims_floors_and_never_returns_zero() {
        assert_eq!(grid_dims(801.5, 600.0, 8.0, 17.0), (100, 35));
        // a canvas smaller than one cell still has to spawn a 1x1 PTY
        assert_eq!(grid_dims(1.0, 1.0, 8.0, 17.0), (1, 1));
    }

    // Pins the tuple wire format against src-tauri/src/engine.rs's Serialize impl: the two
    // sides are hand-written mirrors, and a silent drift would repaint the grid wrong.
    #[test]
    fn wire_cell_fixture_round_trips() {
        let c: Cell = serde_json::from_str(r#"[3,7,"a",12634869,1447454,5]"#).unwrap();
        assert_eq!((c.line, c.col), (3, 7));
        assert_eq!(c.ch, "a");
        assert_eq!(c.fg, [0xc0, 0xca, 0xf5]);
        assert_eq!(c.bg, [0x16, 0x16, 0x1e]);
        assert!(c.bold && !c.italic && c.inverse && !c.underline);
    }

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
