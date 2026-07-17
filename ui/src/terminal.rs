//! Canvas terminal: consumes the native "grid-damage" contract and paints it,
//! and encodes keystrokes back to the PTY.

use std::cell::RefCell;
use std::rc::Rc;

use dioxus::prelude::*;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use web_sys::{CanvasRenderingContext2d, HtmlCanvasElement, KeyboardEvent};

use crate::bridge::{invoke, listen};

const FONT_PX: f64 = 14.0;
const FONT_FAMILY: &str = "Menlo, monospace";
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
    cell_w: f64,
    cell_h: f64,
    cols: u16,
    rows: u16,
    buf: Vec<Cell>,
    cursor: Cursor,
}

fn css(c: [u8; 3]) -> String {
    format!("rgb({},{},{})", c[0], c[1], c[2])
}

impl Term {
    fn idx(&self, line: u16, col: u16) -> Option<usize> {
        if line < self.rows && col < self.cols {
            Some(line as usize * self.cols as usize + col as usize)
        } else {
            None
        }
    }

    /// Reallocate the buffer and resize the canvas to a fresh full frame.
    fn resize(&mut self, cols: u16, rows: u16) {
        self.cols = cols;
        self.rows = rows;
        self.buf = vec![blank_cell(); cols as usize * rows as usize];
        let px_w = self.cell_w * cols as f64;
        let px_h = self.cell_h * rows as f64;
        self.canvas.set_width((px_w * self.dpr) as u32);
        self.canvas.set_height((px_h * self.dpr) as u32);
        let style = self.canvas.style();
        let _ = style.set_property("width", &format!("{}px", px_w));
        let _ = style.set_property("height", &format!("{}px", px_h));
        // canvas resize resets the transform; re-apply DPR scaling.
        let _ = self.ctx.scale(self.dpr, self.dpr);
        self.ctx.set_text_baseline("top");
        // clear to default background
        self.ctx.set_fill_style_str(&css(DEFAULT_BG));
        self.ctx.fill_rect(0.0, 0.0, px_w, px_h);
    }

    fn draw_cell(&self, line: u16, col: u16, cell: &Cell) {
        let x = col as f64 * self.cell_w;
        let y = line as f64 * self.cell_h;
        let (fg, bg) = if cell.inverse {
            (cell.bg, cell.fg)
        } else {
            (cell.fg, cell.bg)
        };
        self.ctx.set_fill_style_str(&css(bg));
        self.ctx.fill_rect(x, y, self.cell_w, self.cell_h);
        if cell.ch != " " && !cell.ch.is_empty() {
            let font = format!(
                "{}{}{}px {}",
                if cell.italic { "italic " } else { "" },
                if cell.bold { "bold " } else { "" },
                FONT_PX,
                FONT_FAMILY,
            );
            self.ctx.set_font(&font);
            self.ctx.set_fill_style_str(&css(fg));
            let _ = self.ctx.fill_text(&cell.ch, x, y);
        }
        if cell.underline {
            self.ctx.set_fill_style_str(&css(fg));
            self.ctx.fill_rect(x, y + self.cell_h - 1.0, self.cell_w, 1.0);
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
        let x = col as f64 * self.cell_w;
        let y = line as f64 * self.cell_h;
        self.ctx.set_fill_style_str(&css(CURSOR_COLOR));
        self.ctx.fill_rect(x, y, self.cell_w, self.cell_h);
        if let Some(i) = self.idx(line, col) {
            let cell = &self.buf[i];
            if cell.ch != " " && !cell.ch.is_empty() {
                let font = format!("{}px {}", FONT_PX, FONT_FAMILY);
                self.ctx.set_font(&font);
                self.ctx.set_fill_style_str(&css(cell.bg));
                let _ = self.ctx.fill_text(&cell.ch, x, y);
            }
        }
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
        self.draw_cursor();
    }
}

// ---- key encoding (pure, tested below) ----

/// Encode a KeyboardEvent into the bytes a PTY expects, as a UTF-8 string
/// (control bytes ride as chars — the native `pty_write` takes a String and
/// the typed-line reconstruction walks the same chars). Returns None for keys
/// we don't handle (leave the browser's default).
fn encode_key(key: &str, ctrl: bool, alt: bool) -> Option<String> {
    let named = match key {
        "Enter" => Some("\r"),
        "Backspace" => Some("\x7f"),
        "Tab" => Some("\t"),
        "Escape" => Some("\x1b"),
        "ArrowUp" => Some("\x1b[A"),
        "ArrowDown" => Some("\x1b[B"),
        "ArrowRight" => Some("\x1b[C"),
        "ArrowLeft" => Some("\x1b[D"),
        "Home" => Some("\x1b[H"),
        "End" => Some("\x1b[F"),
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
struct Empty {}
#[derive(Serialize)]
struct SpawnArgs {
    rows: u16,
    cols: u16,
}
#[derive(Serialize)]
struct WriteArgs {
    data: String,
}
#[derive(Serialize)]
struct TypedArgs {
    line: String,
}

fn win() -> web_sys::Window {
    web_sys::window().expect("no window")
}

fn grid_dims(cell_w: f64, cell_h: f64) -> (u16, u16) {
    let w = win().inner_width().ok().and_then(|v| v.as_f64()).unwrap_or(800.0);
    let h = win().inner_height().ok().and_then(|v| v.as_f64()).unwrap_or(600.0);
    let cols = (w / cell_w).floor().max(1.0) as u16;
    let rows = (h / cell_h).floor().max(1.0) as u16;
    (cols, rows)
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
    // measure a monospace cell.
    ctx.set_font(&format!("{}px {}", FONT_PX, FONT_FAMILY));
    let cell_w = ctx
        .measure_text("M")
        .map(|m| m.width())
        .unwrap_or(FONT_PX * 0.6)
        .max(1.0);
    let cell_h = (FONT_PX * 1.2).round();

    let term = Rc::new(RefCell::new(Term {
        ctx,
        canvas,
        dpr,
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
            let x = 0.0;
            let y = (t.cursor.line as f64 + 1.0).min(t.rows.saturating_sub(1) as f64) * t.cell_h;
            t.ctx.set_font(&format!("{}px {}", FONT_PX, FONT_FAMILY));
            t.ctx.set_fill_style_str(&css([0xff, 0x6b, 0x6b]));
            let _ = t.ctx.fill_text("[process exited]", x, y);
        });
    }

    // --- spawn the PTY, then request the initial full grid ---
    let (cols, rows) = grid_dims(cell_w, cell_h);
    wasm_bindgen_futures::spawn_local(async move {
        let _ = invoke("pty_spawn", SpawnArgs { rows, cols }).await;
        let _ = invoke("term_full_repaint", Empty {}).await;
    });

    // --- keyboard input ---
    let typed = Rc::new(RefCell::new(String::new()));
    {
        let typed = typed.clone();
        let cb = Closure::wrap(Box::new(move |ev: KeyboardEvent| {
            let Some(data) = encode_key(&ev.key(), ev.ctrl_key(), ev.alt_key()) else {
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

    // --- window resize: recompute grid, resize PTY, force a full repaint ---
    {
        let term = term.clone();
        let cb = Closure::wrap(Box::new(move |_ev: web_sys::Event| {
            let (cell_w, cell_h) = {
                let t = term.borrow();
                (t.cell_w, t.cell_h)
            };
            let (cols, rows) = grid_dims(cell_w, cell_h);
            wasm_bindgen_futures::spawn_local(async move {
                let _ = invoke("pty_resize", SpawnArgs { rows, cols }).await;
                let _ = invoke("term_full_repaint", Empty {}).await;
            });
        }) as Box<dyn FnMut(web_sys::Event)>);
        let _ = win().add_event_listener_with_callback("resize", cb.as_ref().unchecked_ref());
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
    use super::encode_key;

    #[test]
    fn key_encoding() {
        assert_eq!(encode_key("a", false, false).as_deref(), Some("a"));
        assert_eq!(encode_key("Enter", false, false).as_deref(), Some("\r"));
        assert_eq!(encode_key("Backspace", false, false).as_deref(), Some("\x7f"));
        assert_eq!(encode_key("Tab", false, false).as_deref(), Some("\t"));
        assert_eq!(encode_key("Escape", false, false).as_deref(), Some("\x1b"));
        assert_eq!(encode_key("ArrowUp", false, false).as_deref(), Some("\x1b[A"));
        assert_eq!(encode_key("ArrowDown", false, false).as_deref(), Some("\x1b[B"));
        assert_eq!(encode_key("ArrowRight", false, false).as_deref(), Some("\x1b[C"));
        assert_eq!(encode_key("ArrowLeft", false, false).as_deref(), Some("\x1b[D"));
        assert_eq!(encode_key("Home", false, false).as_deref(), Some("\x1b[H"));
        assert_eq!(encode_key("End", false, false).as_deref(), Some("\x1b[F"));
        assert_eq!(encode_key("PageUp", false, false).as_deref(), Some("\x1b[5~"));
        // Ctrl-C = 0x03, Ctrl-U = 0x15, Ctrl-A = 0x01
        assert_eq!(encode_key("c", true, false).as_deref(), Some("\x03"));
        assert_eq!(encode_key("u", true, false).as_deref(), Some("\x15"));
        assert_eq!(encode_key("A", true, false).as_deref(), Some("\x01"));
        // Alt/meta prefix
        assert_eq!(encode_key("b", false, true).as_deref(), Some("\x1bb"));
        // Unhandled modifiers/keys
        assert_eq!(encode_key("Shift", false, false), None);
        assert_eq!(encode_key("F5", false, false), None);
    }
}
