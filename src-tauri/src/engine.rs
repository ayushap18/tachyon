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

use serde::ser::SerializeTuple;
use serde::{Serialize, Serializer};
use vt100::{Color, Parser};

// ---- IPC payload (must match the grid-damage contract byte-for-byte) ----

#[derive(Serialize, Clone)]
pub struct CursorPayload {
    pub line: u16,
    pub col: u16,
    pub color: [u8; 3],
    pub visible: bool,
}

#[derive(Clone, PartialEq)]
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

// A grid frame is thousands of cells, and Tauri's `emit` serialises it and then copies the
// result again into a JS source string, so the field names cost more than the data: as a
// named-field object this was 127 B/cell. On the wire a cell is
// [line, col, ch, fg, bg, flags] with the colours packed into a u32 and the four attributes
// into one bitfield. ui/src/terminal.rs::WireCell is the other half of this contract.
impl Serialize for CellPayload {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let pack = |c: [u8; 3]| (c[0] as u32) << 16 | (c[1] as u32) << 8 | c[2] as u32;
        let flags = self.bold as u8
            | (self.italic as u8) << 1
            | (self.inverse as u8) << 2
            | (self.underline as u8) << 3;
        let mut t = s.serialize_tuple(6)?;
        t.serialize_element(&self.line)?;
        t.serialize_element(&self.col)?;
        t.serialize_element(&self.ch)?;
        t.serialize_element(&pack(self.fg))?;
        t.serialize_element(&pack(self.bg))?;
        t.serialize_element(&flags)?;
        t.end()
    }
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

impl ColorTable {
    // ansi: the 16 ANSI colors; fg/bg/cursor round out the table. 16..256 are the standard
    // xterm-256 cube + grayscale ramp (deterministic, theme-independent).
    fn new(ansi: [[u8; 3]; 16], fg: [u8; 3], bg: [u8; 3], cursor: [u8; 3]) -> Self {
        let mut slots = [[0, 0, 0]; 259];
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
            slots[16 + i as usize] = [level(r as u8), level(g as u8), level(b as u8)];
        }
        // grayscale ramp: indices 232..256
        for i in 0..24u16 {
            let v = 8 + 10 * i as u8;
            slots[232 + i as usize] = [v, v, v];
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

// hex helper so the theme table reads like the CSS values
const fn h(v: u32) -> [u8; 3] {
    [(v >> 16) as u8, (v >> 8) as u8, v as u8]
}

/// A theme's terminal background, for the native window backing the webview paints over.
pub(crate) fn theme_bg(name: &str) -> [u8; 3] {
    theme_colors(name).slots[257]
}

fn theme_colors(name: &str) -> ColorTable {
    // ANSI order: black,red,green,yellow,blue,magenta,cyan,white, then bright variants.
    // The per-theme ANSI tables are intentional: colored program output (ls --color,
    // git diff, vim syntax) matches each theme rather than a fixed default set.
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
        // default: Tokyo Night
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
    /// `theme` is the user's saved theme, passed in at spawn. It used to be hardcoded to
    /// Tokyo Night and corrected by a second IPC call (term_set_theme) right after — so every
    /// cell the shell printed in that window was painted with the DARK palette and left on a
    /// light background until something redamaged it. Unknown names fall back to Tokyo Night.
    pub fn new(cols: u16, rows: u16, theme: &str) -> Self {
        Self {
            parser: Parser::new(rows, cols, 5000), // note: vt100 takes (rows, cols, scrollback)
            colors: theme_colors(theme),
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
        self.parser.screen_mut().set_size(rows, cols);
        self.snapshot = vec![None; rows as usize * cols as usize]; // force full repaint next
    }

    pub fn set_theme(&mut self, name: &str) {
        self.colors = theme_colors(name);
        for s in &mut self.snapshot {
            *s = None; // colors changed -> re-emit everything
        }
    }

    /// Scroll the view by `delta` rows: delta > 0 scrolls UP into history, delta < 0 toward the
    /// live bottom. Keep the snapshot so scrolling ships only changed cells.
    /// Return false at either boundary, where no repaint is necessary.
    pub fn scroll_by(&mut self, delta: i32) -> bool {
        let cur = self.parser.screen().scrollback() as i32;
        let next = cur.saturating_add(delta).max(0) as usize;
        self.parser.screen_mut().set_scrollback(next);
        self.parser.screen().scrollback() != cur as usize
    }

    /// Current scrollback offset (0 = live bottom).
    pub fn scrollback(&self) -> usize {
        self.parser.screen().scrollback()
    }

    /// Snap back to the live bottom (offset 0). The snapshot mirrors what the frontend has
    /// painted, so it stays valid across the jump and the following `take_damage` ships only
    /// the rows that actually differ.
    pub fn scroll_to_bottom(&mut self) {
        self.parser.screen_mut().set_scrollback(0);
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
                    if s.is_empty() { " ".to_string() } else { s.to_string() },
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
        // Hide the cursor while scrolled into history — its live position would land on
        // unrelated historical text.
        let visible = !screen.hide_cursor() && screen.scrollback() == 0;
        CursorPayload { line, col, color: self.colors.slots[258], visible }
    }

    /// Emit only the cells that changed since the last emit, updating the snapshot.
    // ponytail: O(rows*cols) scan per output chunk; fine to ~200x50. If paint latency shows,
    // gate on vt100's screen dirty state instead of a full rescan.
    pub fn take_damage(&mut self) -> GridDamage {
        let default_fg = self.colors.slots[256];
        let default_bg = self.colors.slots[257];
        let mut cells = Vec::new();
        for line in 0..self.rows {
            for col in 0..self.cols {
                // Compare against the borrowed cell contents first: building a CellPayload per
                // position (as cell_at does) allocated a String for all rows*cols cells on every
                // scan, changed or not.
                let (ch, fg, bg, bold, italic, inverse, underline) =
                    match self.parser.screen().cell(line, col) {
                        Some(c) => {
                            let s = c.contents();
                            (
                                if s.is_empty() { " " } else { s },
                                self.colors.resolve(c.fgcolor(), default_fg),
                                self.colors.resolve(c.bgcolor(), default_bg),
                                c.bold(),
                                c.italic(),
                                c.inverse(),
                                c.underline(),
                            )
                        }
                        None => (" ", default_fg, default_bg, false, false, false, false),
                    };
                let idx = line as usize * self.cols as usize + col as usize;
                if let Some(p) = &self.snapshot[idx] {
                    if p.ch == ch
                        && p.fg == fg
                        && p.bg == bg
                        && p.bold == bold
                        && p.italic == italic
                        && p.inverse == inverse
                        && p.underline == underline
                    {
                        continue;
                    }
                }
                let cur = CellPayload {
                    line,
                    col,
                    ch: ch.to_string(),
                    fg,
                    bg,
                    bold,
                    italic,
                    inverse,
                    underline,
                };
                self.snapshot[idx] = Some(cur.clone());
                cells.push(cur);
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

    // Allocation counter for the damage-scan acceptance test. Armed per-thread around the
    // call under test so the other tests (and the harness threads) do not pollute the count.
    mod counting {
        use std::alloc::{GlobalAlloc, Layout, System};
        use std::cell::Cell;

        thread_local! {
            static LIVE: Cell<Option<usize>> = const { Cell::new(None) };
        }

        pub struct Counting;

        unsafe impl GlobalAlloc for Counting {
            unsafe fn alloc(&self, l: Layout) -> *mut u8 {
                let _ = LIVE.try_with(|c| c.set(c.get().map(|n| n + 1)));
                unsafe { System.alloc(l) }
            }
            unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
                unsafe { System.dealloc(p, l) }
            }
        }

        pub fn allocations(f: impl FnOnce()) -> usize {
            LIVE.with(|c| c.set(Some(0)));
            f();
            LIVE.with(|c| c.take()).unwrap_or(0)
        }
    }

    #[global_allocator]
    static ALLOC: counting::Counting = counting::Counting;

    /// 200x50 with 4000 lines of varied coloured history — the geometry every performance
    /// number in the release acceptance table is quoted for.
    fn busy_engine() -> TerminalEngine {
        let mut e = TerminalEngine::new(200, 50, "Tokyo Night");
        let words = ["alpha", "beta", "gamma", "delta", "epsilon", "zeta"];
        for n in 0..4000usize {
            let mut line = String::new();
            while line.len() < 40 + (n * 37) % 121 {
                line.push_str(words[(n + line.len()) % words.len()]);
                line.push(' ');
            }
            e.feed(format!("\x1b[3{}m{line}\x1b[0m\r\n", n % 8).as_bytes());
        }
        e
    }

    // The grid crosses IPC as JSON that Tauri then copies again into a JS source string, so
    // bytes per cell is the scroll budget.
    #[test]
    fn grid_damage_stays_under_40_bytes_per_cell() {
        let mut e = busy_engine();
        let full = e.full_repaint();
        let bytes = serde_json::to_string(&full).unwrap().len();
        assert!(
            bytes < full.cells.len() * 40,
            "{} B for {} cells = {} B/cell",
            bytes,
            full.cells.len(),
            bytes / full.cells.len()
        );
        // the frame that actually ships on a scroll pays the same per-cell budget
        assert!(e.scroll_by(1));
        let damage = e.take_damage();
        let frame = serde_json::to_string(&damage).unwrap().len();
        assert!(
            frame < damage.cells.len() * 40,
            "one-row scroll frame is {frame} B for {} cells",
            damage.cells.len()
        );
    }

    #[test]
    fn take_damage_allocates_nothing_when_unchanged() {
        let mut e = busy_engine();
        let _ = e.full_repaint();
        let _ = e.take_damage();
        let n = counting::allocations(|| {
            let d = e.take_damage();
            assert!(d.cells.is_empty());
        });
        assert_eq!(n, 0, "unchanged 200x50 damage scan allocated {n} times");
    }

    // The engine used to hardcode Tokyo Night and rely on a second IPC call to correct it,
    // so everything the shell printed before that call landed was painted with the dark
    // palette on a light background. The theme now arrives at construction; if this ever
    // regresses to a fixed default, a light theme's first paint goes dark again.
    #[test]
    fn new_honours_the_theme_it_is_given() {
        let light = TerminalEngine::new(8, 2, "Solarized Light").full_repaint();
        let dark = TerminalEngine::new(8, 2, "Tokyo Night").full_repaint();
        let bg = |d: &GridDamage| d.cells.first().map(|c| c.bg).unwrap();
        assert_ne!(bg(&light), bg(&dark), "a light theme must not paint the dark background");
        assert_eq!(bg(&light), theme_colors("Solarized Light").slots[257]);
        // an unknown name still falls back rather than panicking
        assert_eq!(bg(&TerminalEngine::new(8, 2, "nope").full_repaint()), bg(&dark));
    }

    #[test]
    fn feed_and_full_repaint_reads_written_cells() {
        let mut e = TerminalEngine::new(20, 5, "Tokyo Night");
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

    // The `term_write` display path (slash results, ⌘E autopsy, agent narrative) paints by
    // feeding pre-formatted ANSI straight into this engine — it never touches the pty. Guards
    // that such a payload actually lands on the grid, colored, and is reported as damage.
    #[test]
    fn feed_ansi_paints_colored_text_as_damage() {
        let mut e = TerminalEngine::new(40, 5, "Tokyo Night");
        let _ = e.full_repaint();
        let _ = e.take_damage();
        // exactly the shape run_slash / explain_and_paint emit: CRLF + cyan + text + reset
        e.feed(b"\r\n\x1b[36m[tachyon] ok\x1b[0m\r\n");
        let d = e.take_damage();
        let t = d.cells.iter().find(|c| c.ch == "t").expect("painted text is on the grid");
        // cyan, not the default foreground — the SGR travelled with the text
        let table = theme_colors("Tokyo Night");
        assert_eq!(t.fg, table.slots[6]);
        assert_ne!(t.fg, table.slots[256]);
    }

    #[test]
    fn partial_damage_only_reports_changed_cells() {
        let mut e = TerminalEngine::new(20, 5, "Tokyo Night");
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
        let mut e = TerminalEngine::new(10, 3, "Tokyo Night");
        e.feed(b"abc");
        let _ = e.take_damage(); // absorb the write
        let d = e.take_damage(); // no new bytes
        assert_eq!(d.cells.len(), 0);
    }

    #[test]
    fn theme_switch_changes_default_bg() {
        let mut e = TerminalEngine::new(4, 2, "Tokyo Night");
        e.set_theme("Matrix");
        let d = e.full_repaint();
        // Matrix bg is pure black
        let cell = &d.cells[0];
        assert_eq!(cell.bg, [0, 0, 0]);
    }

    #[test]
    fn scroll_by_clamps_at_zero() {
        let mut e = TerminalEngine::new(20, 5, "Tokyo Night");
        e.feed(b"hello");
        // already at the live bottom; scrolling further toward bottom stays at 0.
        e.scroll_by(-100);
        assert_eq!(e.parser.screen().scrollback(), 0);
    }

    #[test]
    fn scrolling_diffs_match_full_frames_and_boundaries_are_noops() {
        let mut e = TerminalEngine::new(80, 6, "Tokyo Night");
        for n in 0..40 {
            e.feed(format!("line {n}\r\n").as_bytes());
        }
        let mut frame = e.full_repaint().cells;
        for delta in [1, 3, -2, i32::MAX, i32::MAX, i32::MIN, -1] {
            let moved = e.scroll_by(delta);
            let damage = e.take_damage();
            if !moved {
                assert!(damage.cells.is_empty());
            }
            // Blank columns should not be resent on every scroll.
            assert!(damage.cells.len() < 80 * 6);
            for cell in damage.cells {
                let idx = cell.line as usize * 80 + cell.col as usize;
                frame[idx] = cell;
            }
            let expected = e.full_repaint();
            assert!(frame == expected.cells);
            assert_eq!(expected.cursor.visible, e.scrollback() == 0);
        }
        // Snapping to the live bottom keeps the snapshot, so only the rows that differ ship.
        assert!(e.scroll_by(300));
        for cell in e.take_damage().cells {
            let idx = cell.line as usize * 80 + cell.col as usize;
            frame[idx] = cell;
        }
        e.scroll_to_bottom();
        let snap = e.take_damage();
        assert!(snap.cells.len() < 80 * 6, "snap to bottom resent {} cells", snap.cells.len());
        for cell in snap.cells {
            let idx = cell.line as usize * 80 + cell.col as usize;
            frame[idx] = cell;
        }
        assert!(frame == e.full_repaint().cells);
    }

    // The painter thread takes damage once per frame however many chunks the reader fed, so a
    // dropped cell would leave text on screen that the user can read and act on.
    #[test]
    fn coalesced_damage_is_lossless() {
        let mut e = TerminalEngine::new(80, 6, "Tokyo Night");
        let mut frame = e.full_repaint().cells;
        for n in 0..50 {
            e.feed(format!("chunk {n} \x1b[32mgreen\x1b[0m\r\n").as_bytes());
        }
        for cell in e.take_damage().cells {
            let idx = cell.line as usize * 80 + cell.col as usize;
            frame[idx] = cell;
        }
        assert!(frame == e.full_repaint().cells);
    }

    #[test]
    fn a_one_char_change_damages_exactly_one_cell() {
        let mut e = TerminalEngine::new(20, 5, "Tokyo Night");
        e.feed(b"abc");
        let _ = e.full_repaint();
        // overwrite the middle glyph in place and leave the cursor where it was
        e.feed(b"\r\x1b[1CX\x1b[C");
        let d = e.take_damage();
        assert_eq!(d.cells.len(), 1);
        assert_eq!(d.cells[0].col, 1);
        assert_eq!(d.cells[0].ch, "X");
    }

    #[test]
    fn the_cursor_carries_the_theme_colour() {
        for name in ["Matrix", "Solarized Light"] {
            let d = TerminalEngine::new(8, 2, name).full_repaint();
            assert_eq!(d.cursor.color, theme_colors(name).slots[258]);
        }
        let colour = |name| TerminalEngine::new(8, 2, name).full_repaint().cursor.color;
        assert_ne!(colour("Matrix"), colour("Solarized Light"));
    }

    // Timing is flaky on a loaded box, so it is opt-in: cargo test --release -- --ignored perf_
    #[test]
    #[ignore]
    fn perf_unchanged_take_damage_under_150us() {
        let mut e = busy_engine();
        let _ = e.full_repaint();
        let _ = e.take_damage();
        // best of five passes: the first is cold, and a loaded box would otherwise flake
        let per = (0..5)
            .map(|_| {
                let started = std::time::Instant::now();
                for _ in 0..100 {
                    assert!(e.take_damage().cells.is_empty());
                }
                started.elapsed() / 100
            })
            .min()
            .unwrap();
        assert!(per < std::time::Duration::from_micros(150), "unchanged take_damage took {per:?}");
    }

    #[test]
    fn resize_updates_dimensions() {
        let mut e = TerminalEngine::new(20, 5, "Tokyo Night");
        e.resize(40, 10);
        let d = e.full_repaint();
        assert_eq!(d.cols, 40);
        assert_eq!(d.rows, 10);
        assert_eq!(d.cells.len(), 400);
    }
}
