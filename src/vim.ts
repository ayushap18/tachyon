// Vim navigation mode over the terminal scrollback buffer.
// INSERT (default, keys pass to pty) ⇄ NORMAL (⌘⇧V; i/a/Esc exit) ⇄ VISUAL (v).
import type { Terminal } from "@xterm/xterm";

export interface VimOptions {
  term: Terminal;
  statusEl: HTMLElement; // #status-vim
  searchEl: HTMLInputElement; // #vim-search
}

type Mode = "insert" | "normal" | "visual";

export function initVim({ term, statusEl, searchEl }: VimOptions): void {
  let mode: Mode = "insert";
  let cur = { row: 0, col: 0 }; // absolute buffer coords
  let anchor = { row: 0, col: 0 }; // visual selection anchor
  let lastSearch = "";
  let pendingG = false; // 'g' prefix for gg

  const buf = () => term.buffer.active;
  const lineText = (r: number) => buf().getLine(r)?.translateToString(true) ?? "";
  const lastRow = () => buf().length - 1;
  const clampCol = (r: number, c: number) =>
    Math.max(0, Math.min(c, Math.max(0, lineText(r).length - 1)));

  function setMode(m: Mode) {
    mode = m;
    pendingG = false;
    statusEl.textContent = m === "insert" ? "" : m === "normal" ? "-- NORMAL --" : "-- VISUAL --";
    statusEl.className = m === "insert" ? "" : m;
    if (m === "insert") {
      term.clearSelection();
      searchEl.hidden = true;
      term.focus();
    }
  }

  function enterNormal() {
    const b = buf();
    const row = b.baseY + b.cursorY;
    cur = { row, col: clampCol(row, b.cursorX) };
    setMode("normal");
    render();
  }

  function ensureVisible() {
    const vy = buf().viewportY;
    if (cur.row < vy) term.scrollLines(cur.row - vy);
    else if (cur.row >= vy + term.rows) term.scrollLines(cur.row - (vy + term.rows - 1));
  }

  function render() {
    ensureVisible();
    if (mode === "visual") {
      const fwd = anchor.row < cur.row || (anchor.row === cur.row && anchor.col <= cur.col);
      const s = fwd ? anchor : cur;
      const e = fwd ? cur : anchor;
      // ponytail: linear cols-width approximation — includes trailing cells on wrapped rows
      const len = (e.row - s.row) * term.cols + (e.col - s.col) + 1;
      term.select(s.col, s.row, Math.max(1, len));
    } else {
      term.select(cur.col, cur.row, 1);
    }
  }

  function wordStarts(r: number): number[] {
    const out: number[] = [];
    const re = /\S+/g;
    let m: RegExpExecArray | null;
    while ((m = re.exec(lineText(r)))) out.push(m.index);
    return out;
  }
  function motionW() {
    const ws = wordStarts(cur.row).filter((i) => i > cur.col);
    if (ws.length) cur.col = ws[0];
    else if (cur.row < lastRow()) {
      cur.row++;
      cur.col = wordStarts(cur.row)[0] ?? 0;
    }
  }
  function motionB() {
    const ws = wordStarts(cur.row).filter((i) => i < cur.col);
    if (ws.length) cur.col = ws[ws.length - 1];
    else if (cur.row > 0) {
      cur.row--;
      const p = wordStarts(cur.row);
      cur.col = p[p.length - 1] ?? 0;
    }
  }

  function findFrom(q: string, row: number, col: number, dir: 1 | -1) {
    const n = q.toLowerCase();
    if (!n) return null;
    if (dir === 1) {
      for (let r = row; r <= lastRow(); r++) {
        const i = lineText(r).toLowerCase().indexOf(n, r === row ? col : 0);
        if (i !== -1) return { row: r, col: i };
      }
    } else {
      for (let r = row; r >= 0; r--) {
        const hay = lineText(r).toLowerCase();
        const i = r === row ? hay.lastIndexOf(n, col) : hay.lastIndexOf(n);
        if (i !== -1) return { row: r, col: i };
      }
    }
    return null;
  }
  function doSearch(dir: 1 | -1) {
    if (!lastSearch) return;
    const hit =
      dir === 1
        ? findFrom(lastSearch, cur.row, cur.col + 1, 1)
        : findFrom(lastSearch, cur.row, cur.col - 1, -1);
    if (hit) {
      cur = hit;
      render();
    }
  }

  searchEl.onkeydown = (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      lastSearch = searchEl.value;
      searchEl.hidden = true;
      term.focus();
      doSearch(1);
    } else if (e.key === "Escape") {
      e.preventDefault();
      searchEl.hidden = true;
      term.focus();
      render();
    }
  };
  function openSearch() {
    searchEl.value = "";
    searchEl.hidden = false;
    searchEl.focus();
  }

  term.attachCustomKeyEventHandler((e: KeyboardEvent): boolean => {
    const isToggle = e.metaKey && e.shiftKey && e.key.toLowerCase() === "v";
    if (mode === "insert") {
      if (isToggle && e.type === "keydown") {
        e.preventDefault();
        enterNormal();
        return false;
      }
      return true; // INSERT: everything goes to the pty
    }
    // NORMAL / VISUAL
    if (e.metaKey) {
      if (isToggle && e.type === "keydown") {
        e.preventDefault();
        setMode("insert");
        return false;
      }
      return true; // other ⌘-chords pass so app shortcuts keep working
    }
    if (e.type !== "keydown") return false; // swallow keypress/keyup twins
    handleKey(e);
    return false; // nothing reaches the shell in NORMAL/VISUAL
  });

  function handleKey(e: KeyboardEvent) {
    const k = e.key;
    if (e.ctrlKey && (k === "d" || k === "u")) {
      const half = Math.floor(term.rows / 2) * (k === "d" ? 1 : -1);
      cur.row = Math.max(0, Math.min(lastRow(), cur.row + half));
      cur.col = clampCol(cur.row, cur.col);
      term.scrollLines(half);
      render();
      return;
    }
    if (pendingG) {
      pendingG = false;
      if (k === "g") {
        cur = { row: 0, col: 0 };
        render();
        return;
      }
    }
    switch (k) {
      case "Escape":
        if (mode === "visual") {
          setMode("normal");
          render();
        } else setMode("insert");
        return;
      case "i":
      case "a":
        setMode("insert");
        return;
      case "v":
        if (mode === "visual") setMode("normal");
        else {
          anchor = { ...cur };
          setMode("visual");
        }
        render();
        return;
      case "y":
        if (mode === "visual") {
          navigator.clipboard.writeText(term.getSelection()).catch(() => {});
          setMode("insert");
        }
        return;
      case "h":
        cur.col = Math.max(0, cur.col - 1);
        break;
      case "l":
        cur.col = clampCol(cur.row, cur.col + 1);
        break;
      case "j":
        cur.row = Math.min(lastRow(), cur.row + 1);
        cur.col = clampCol(cur.row, cur.col);
        break;
      case "k":
        cur.row = Math.max(0, cur.row - 1);
        cur.col = clampCol(cur.row, cur.col);
        break;
      case "0":
        cur.col = 0;
        break;
      case "$":
        cur.col = Math.max(0, lineText(cur.row).length - 1);
        break;
      case "w":
        motionW();
        break;
      case "b":
        motionB();
        break;
      case "g":
        pendingG = true;
        return;
      case "G":
        cur.row = lastRow();
        cur.col = clampCol(cur.row, cur.col);
        break;
      case "/":
        openSearch();
        return;
      case "n":
        doSearch(1);
        return;
      case "N":
        doSearch(-1);
        return;
      default:
        return; // unknown keys swallowed
    }
    render();
  }

  setMode("insert");
}
