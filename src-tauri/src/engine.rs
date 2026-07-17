// Native terminal engine: wraps a vt100 `Parser` (bytes -> screen grid). We feed it PTY
// bytes, then hand the frontend only the changed cells ("grid-damage") to paint on a canvas.
//
// vt100 owns the ANSI parsing + grid/scrollback/cursor; we resolve each cell's color against
// the active theme table and diff against the last emitted snapshot so only changed cells ship.
//
// ponytail: color resolution ignores OSC-set dynamic palette — uses the active theme table only;
// add a runtime palette override if apps need OSC 4/10/11 color changes.
// ponytail: wide-char spacer cells are sent as a blank; combining marks ride on cell.contents();
// upgrade only if CJK/emoji rendering shows gaps.

use serde::Serialize;
use vt100::{Color, Parser};

// ---- IPC payload (must match the grid-damage contract byte-for-byte) ----

#[derive(Serialize, Clone)]
pub struct CursorPayload {
    pub line: u16,
    pub col: u16,
    pub shape: &'static str, // vt100 exposes no shape -> always "block"
    pub visible: bool,
}

#[derive(Serialize, Clone, PartialEq)]
pub struct CellPayload {
    pub line: u16,
    pub col: u16,
    pub ch: String,
    pub fg: [u8; 3],
    pub bg: [u8; 3],
    pub bold: bool,
    pub italic: bool,
    pub inverse: bool,
    pub underline: bool,
}

#[derive(Serialize, Clone)]
pub struct GridDamage {
    pub cols: u16,
    pub rows: u16,
    pub cursor: CursorPayload,
    // DECCKM: when true, arrow/Home/End keys must be encoded as SS3 (ESC O x) not CSI (ESC [ x),
    // else curses apps (vim/htop/less) misread them. The frontend key encoder reads this.
    pub application_cursor: bool,
    pub cells: Vec<CellPayload>,
}

// ---- theme -> color table ----
//
// Table layout: 0..16 ANSI, 16..232 color cube, 232..256 grayscale ramp, 256 fg, 257 bg, 258 cursor.
// We resolve every cell against this ourselves (vt100 hands us Default | Idx(u8) | Rgb).
struct ColorTable {
    slots: [[u8; 3]; 259],
}

const fn rgb(r: u8, g: u8, b: u8) -> [u8; 3] {
    [r, g, b]
}

impl ColorTable {
    // ansi: the 16 ANSI colors; fg/bg/cursor round out the table. 16..256 are the standard
    // xterm-256 cube + grayscale ramp (deterministic, theme-independent).
    fn new(ansi: [[u8; 3]; 16], fg: [u8; 3], bg: [u8; 3], cursor: [u8; 3]) -> Self {
        let mut slots = [rgb(0, 0, 0); 259];
        let mut i = 0;
        while i < 16 {
            slots[i] = ansi[i];
            i += 1;
        }
        // 6x6x6 color cube: indices 16..232
        let level = |c: u8| -> u8 {
            if c == 0 {
                0
            } else {
                55 + c * 40
            }
        };
        for i in 0..216u16 {
            let r = (i / 36) % 6;
            let g = (i / 6) % 6;
            let b = i % 6;
            slots[16 + i as usize] = rgb(level(r as u8), level(g as u8), level(b as u8));
        }
        // grayscale ramp: indices 232..256
        for i in 0..24u16 {
            let v = 8 + 10 * i as u8;
            slots[232 + i as usize] = rgb(v, v, v);
        }
        slots[256] = fg;
        slots[257] = bg;
        slots[258] = cursor;
        Self { slots }
    }

    // `default` is the fg or bg the caller wants for vt100's Color::Default in this context.
    fn resolve(&self, color: Color, default: [u8; 3]) -> [u8; 3] {
        match color {
            Color::Default => default,
            Color::Rgb(r, g, b) => [r, g, b],
            Color::Idx(i) => self.slots.get(i as usize).copied().unwrap_or(default),
        }
    }
}

// hex helper so the theme table reads like the CSS values in main.ts
const fn h(v: u32) -> [u8; 3] {
    [(v >> 16) as u8, (v >> 8) as u8, v as u8]
}

fn theme_colors(name: &str) -> ColorTable {
    // ANSI order: black,red,green,yellow,blue,magenta,cyan,white, then bright variants.
    // NOTE: beta (xterm.js) only themed bg/fg/cursor and used xterm's stock 16-color ANSI palette;
    // these per-theme ANSI tables are a NEW, intentional addition so colored program output
    // (ls --color, git diff, vim syntax) matches each theme rather than a fixed default set.
    match name {
        "Dracula" => ColorTable::new(
            [
                h(0x21222c), h(0xff5555), h(0x50fa7b), h(0xf1fa8c),
                h(0xbd93f9), h(0xff79c6), h(0x8be9fd), h(0xf8f8f2),
                h(0x6272a4), h(0xff6e6e), h(0x69ff94), h(0xffffa5),
                h(0xd6acff), h(0xff92df), h(0xa4ffff), h(0xffffff),
            ],
            h(0xf8f8f2), h(0x282a36), h(0xf8f8f2),
        ),
        "Nord" => ColorTable::new(
            [
                h(0x3b4252), h(0xbf616a), h(0xa3be8c), h(0xebcb8b),
                h(0x81a1c1), h(0xb48ead), h(0x88c0d0), h(0xe5e9f0),
                h(0x4c566a), h(0xbf616a), h(0xa3be8c), h(0xebcb8b),
                h(0x81a1c1), h(0xb48ead), h(0x8fbcbb), h(0xeceff4),
            ],
            h(0xd8dee9), h(0x2e3440), h(0xd8dee9),
        ),
        "Solarized Dark" => ColorTable::new(
            [
                h(0x073642), h(0xdc322f), h(0x859900), h(0xb58900),
                h(0x268bd2), h(0xd33682), h(0x2aa198), h(0xeee8d5),
                h(0x002b36), h(0xcb4b16), h(0x586e75), h(0x657b83),
                h(0x839496), h(0x6c71c4), h(0x93a1a1), h(0xfdf6e3),
            ],
            h(0x839496), h(0x002b36), h(0x839496),
        ),
        "Solarized Light" => ColorTable::new(
            [
                h(0x073642), h(0xdc322f), h(0x859900), h(0xb58900),
                h(0x268bd2), h(0xd33682), h(0x2aa198), h(0xeee8d5),
                h(0x002b36), h(0xcb4b16), h(0x586e75), h(0x657b83),
                h(0x839496), h(0x6c71c4), h(0x93a1a1), h(0xfdf6e3),
            ],
            h(0x586e75), h(0xfdf6e3), h(0x586e75),
        ),
        "Matrix" => ColorTable::new(
            [
                h(0x000000), h(0x008f11), h(0x00ff41), h(0x00b82c),
                h(0x003b00), h(0x00ff41), h(0x00cc35), h(0x00ff41),
                h(0x005500), h(0x00b82c), h(0x00ff41), h(0x00ff41),
                h(0x008f11), h(0x00ff41), h(0x00ff41), h(0x00ff41),
            ],
            h(0x00ff41), h(0x000000), h(0x00ff41),
        ),
        // default: Tokyo Night (values from src/main.ts)
        _ => ColorTable::new(
            [
                h(0x15161e), h(0xf7768e), h(0x9ece6a), h(0xe0af68),
                h(0x7aa2f7), h(0xbb9af7), h(0x7dcfff), h(0xa9b1d6),
                h(0x414868), h(0xf7768e), h(0x9ece6a), h(0xe0af68),
                h(0x7aa2f7), h(0xbb9af7), h(0x7dcfff), h(0xc0caf5),
            ],
            h(0xc0caf5), h(0x16161e), h(0xc0caf5),
        ),
    }
}

pub struct TerminalEngine {
    parser: Parser,
    colors: ColorTable,
    cols: u16,
    rows: u16,
    // last emitted resolved cell per position (row-major); None forces a full emit for that cell.
    snapshot: Vec<Option<CellPayload>>,
}

impl TerminalEngine {
    pub fn new(cols: u16, rows: u16) -> Self {
        Self {
            parser: Parser::new(rows, cols, 0), // note: vt100 takes (rows, cols, scrollback)
            colors: theme_colors("Tokyo Night"),
            cols,
            rows,
            snapshot: vec![None; rows as usize * cols as usize],
        }
    }

    pub fn feed(&mut self, bytes: &[u8]) {
        self.parser.process(bytes);
    }

    pub fn resize(&mut self, cols: u16, rows: u16) {
        self.cols = cols;
        self.rows = rows;
        self.parser.set_size(rows, cols);
        self.snapshot = vec![None; rows as usize * cols as usize]; // force full repaint next
    }

    pub fn set_theme(&mut self, name: &str) {
        self.colors = theme_colors(name);
        for s in &mut self.snapshot {
            *s = None; // colors changed -> re-emit everything
        }
    }

    /// Resolve one screen cell to a paint-ready CellPayload.
    fn cell_at(&self, line: u16, col: u16) -> CellPayload {
        let default_fg = self.colors.slots[256];
        let default_bg = self.colors.slots[257];
        let screen = self.parser.screen();
        let (ch, fg, bg, bold, italic, inverse, underline) = match screen.cell(line, col) {
            Some(c) => {
                let s = c.contents();
                (
                    if s.is_empty() { " ".to_string() } else { s },
                    self.colors.resolve(c.fgcolor(), default_fg),
                    self.colors.resolve(c.bgcolor(), default_bg),
                    c.bold(),
                    c.italic(),
                    c.inverse(),
                    c.underline(),
                )
            }
            None => (" ".to_string(), default_fg, default_bg, false, false, false, false),
        };
        CellPayload { line, col, ch, fg, bg, bold, italic, inverse, underline }
    }

    fn cursor(&self) -> CursorPayload {
        let screen = self.parser.screen();
        let (line, col) = screen.cursor_position();
        CursorPayload { line, col, shape: "block", visible: !screen.hide_cursor() }
    }

    /// Emit only the cells that changed since the last emit, updating the snapshot.
    // ponytail: O(rows*cols) scan per output chunk; fine to ~200x50. If paint latency shows,
    // gate on vt100's screen dirty state instead of a full rescan.
    pub fn take_damage(&mut self) -> GridDamage {
        let mut cells = Vec::new();
        for line in 0..self.rows {
            for col in 0..self.cols {
                let cur = self.cell_at(line, col);
                let idx = line as usize * self.cols as usize + col as usize;
                if self.snapshot[idx].as_ref() != Some(&cur) {
                    self.snapshot[idx] = Some(cur.clone());
                    cells.push(cur);
                }
            }
        }
        GridDamage { cols: self.cols, rows: self.rows, cursor: self.cursor(), application_cursor: self.parser.screen().application_cursor(), cells }
    }

    /// Full snapshot of every cell — the frontend calls this on mount (term_full_repaint).
    pub fn full_repaint(&mut self) -> GridDamage {
        let mut cells = Vec::with_capacity(self.rows as usize * self.cols as usize);
        for line in 0..self.rows {
            for col in 0..self.cols {
                let cur = self.cell_at(line, col);
                let idx = line as usize * self.cols as usize + col as usize;
                self.snapshot[idx] = Some(cur.clone());
                cells.push(cur);
            }
        }
        GridDamage { cols: self.cols, rows: self.rows, cursor: self.cursor(), application_cursor: self.parser.screen().application_cursor(), cells }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn feed_and_full_repaint_reads_written_cells() {
        let mut e = TerminalEngine::new(20, 5);
        e.feed(b"hi");
        let d = e.full_repaint();
        assert_eq!(d.cols, 20);
        assert_eq!(d.rows, 5);
        // every cell of a 20x5 grid is present on a full snapshot
        assert_eq!(d.cells.len(), 100);
        let h = d.cells.iter().find(|c| c.line == 0 && c.col == 0).unwrap();
        assert_eq!(h.ch, "h");
        let i = d.cells.iter().find(|c| c.line == 0 && c.col == 1).unwrap();
        assert_eq!(i.ch, "i");
        assert!(d.cursor.visible);
        assert_eq!(d.cursor.col, 2);
    }

    #[test]
    fn partial_damage_only_reports_changed_cells() {
        let mut e = TerminalEngine::new(20, 5);
        let _ = e.full_repaint(); // seed the snapshot
        let _ = e.take_damage(); // nothing changed since -> drains to empty
        e.feed(b"x");
        let d = e.take_damage();
        // only the freshly written cell(s) on line 0 changed; nowhere near the full 100
        assert!(d.cells.iter().all(|c| c.line == 0));
        assert!(d.cells.iter().any(|c| c.ch == "x"));
        assert!(d.cells.len() < 5);
    }

    #[test]
    fn take_damage_is_empty_when_nothing_changes() {
        let mut e = TerminalEngine::new(10, 3);
        e.feed(b"abc");
        let _ = e.take_damage(); // absorb the write
        let d = e.take_damage(); // no new bytes
        assert_eq!(d.cells.len(), 0);
    }

    #[test]
    fn theme_switch_changes_default_bg() {
        let mut e = TerminalEngine::new(4, 2);
        e.set_theme("Matrix");
        let d = e.full_repaint();
        // Matrix bg is pure black
        let cell = &d.cells[0];
        assert_eq!(cell.bg, [0, 0, 0]);
    }

    #[test]
    fn resize_updates_dimensions() {
        let mut e = TerminalEngine::new(20, 5);
        e.resize(40, 10);
        let d = e.full_repaint();
        assert_eq!(d.cols, 40);
        assert_eq!(d.rows, 10);
        assert_eq!(d.cells.len(), 400);
    }
}
