// Browser regression checks against the actual compiled Rust/WASM frontend.
// Supply an existing Playwright install through PLAYWRIGHT_PATH, or install it locally.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import assert from 'node:assert/strict';
const { chromium } = await import(process.env.PLAYWRIGHT_PATH
  ? pathToFileURL(path.join(process.env.PLAYWRIGHT_PATH, 'index.mjs')).href
  : 'playwright');
const root = fileURLToPath(new URL('../ui/dist/', import.meta.url));
const browser = await chromium.launch({ channel: process.env.PLAYWRIGHT_CHANNEL || 'chrome', headless: true });
try {
  for (const dpr of [1, 1.25, 1.5, 2]) {
    const page = await browser.newPage({ viewport: { width: 1000, height: 700 }, deviceScaleFactor: dpr });
    const errors = [];
    page.on('pageerror', e => errors.push(e.message));
    await page.route('**/*', async route => {
      const url = new URL(route.request().url());
      if (url.hostname !== 'tachyon.test') return route.abort();
      const file = path.join(root, url.pathname === '/' ? 'index.html' : url.pathname);
      await route.fulfill({ body: fs.readFileSync(file), contentType: ({
        '.html': 'text/html', '.js': 'application/javascript', '.wasm': 'application/wasm', '.css': 'text/css',
      })[path.extname(file)] ?? 'application/octet-stream' });
    });
    await page.addInitScript(() => {
      localStorage.setItem('tachyon-settings', JSON.stringify({ theme: 'Solarized Light', font: 'Menlo', size: 14 }));
      const listeners = {};
      window.scrollCalls = [];
      window.inFlight = 0;
      window.maxInFlight = 0;
      window.delay = 0;
      window.grid = { cols: 80, rows: 30 };
      window.makeCell = (line, col, ch = ' ', extra = {}) => ({
        line, col, ch, fg: [88, 110, 117], bg: [253, 246, 227],
        bold: false, italic: false, inverse: false, underline: false, ...extra,
      });
      window.blankFrame = () => Array.from({ length: grid.rows * grid.cols }, (_, i) => makeCell(Math.floor(i / grid.cols), i % grid.cols));
      window.emitDamage = (cells, cursor = { line: 0, col: 0, shape: 'block', visible: false }) => {
        for (const fn of listeners['grid-damage'] ?? []) fn({ payload: { ...grid, cursor, application_cursor: false, cells } });
      };
      window.__TAURI__ = {
        path: { homeDir: async () => '/tmp' },
        event: { listen: async (name, fn) => { (listeners[name] ??= []).push(fn); return () => {}; } },
        core: { invoke: async (cmd, args) => {
          if (cmd === 'keybindings') return {};
          if (cmd === 'journal_blocks') return [];
          if (cmd === 'provider_active') return 'groq';
          if (cmd === 'get_context') return { cwd: '/tmp', branch: null, dirty: 0 };
          if (cmd === 'pty_spawn' || cmd === 'pty_resize') window.grid = args;
          if (cmd === 'term_set_theme' || cmd === 'pty_resize') emitDamage(blankFrame());
          if (cmd === 'term_scroll') {
            scrollCalls.push(args.delta);
            inFlight++;
            maxInFlight = Math.max(maxInFlight, inFlight);
            await new Promise(resolve => setTimeout(resolve, delay));
            inFlight--;
          }
          return null;
        } },
      };
    });
    await page.goto('http://tachyon.test/');
    await page.waitForSelector('#term');
    await page.waitForFunction(() => grid.cols > 80);
    const checkLayout = async () => {
      const box = await page.evaluate(() => {
        const canvas = document.querySelector('#term');
        const rect = canvas.getBoundingClientRect();
        return { bottom: rect.bottom, top: rect.top, left: rect.left, height: rect.height,
          statusTop: document.querySelector('#status-bar').getBoundingClientRect().top,
          rows: grid.rows, backingHeight: canvas.height, dpr: devicePixelRatio };
      });
      assert.ok(box.top >= 8 && box.left >= 8, 'terminal text needs an inset from the window edges');
      assert.ok(box.bottom <= box.statusTop - 8, 'status bar must not obscure terminal rows');
      assert.ok(box.rows * 17 <= box.height, 'PTY must fit entirely inside the visible canvas');
      assert.equal(box.backingHeight, Math.round(box.height * box.dpr));
    };
    await checkLayout();
    // Incremental erasure must be pixel-identical to a clean frame, including
    // glyphs whose italic/combining strokes extend beyond their nominal cell.
    const pixels = await page.evaluate(() => {
      const canvas = document.querySelector('#term');
      emitDamage(blankFrame());
      const blank = canvas.toDataURL();
      for (const ch of ['W', 'f', 'j\u0301', '界', '█']) {
        emitDamage([makeCell(2, 4, ch, { bold: true, italic: true })]);
        emitDamage([makeCell(2, 4)]);
        if (canvas.toDataURL() !== blank) return { clean: false, ch };
      }
      // A changed neighboring background must not erase a wide glyph's overhang.
      const frame = blankFrame();
      frame[grid.cols * 3 + 5] = makeCell(3, 5, '界');
      emitDamage(frame);
      const wide = canvas.toDataURL();
      emitDamage([makeCell(3, 6)]);
      return { clean: true, wide: wide === canvas.toDataURL() };
    });
    assert.equal(pixels.clean, true, `stale pixels after erasing ${pixels.ch} at DPR ${dpr}`);
    assert.equal(pixels.wide, true, 'repainting a spacer must preserve its wide glyph');
    await page.setViewportSize({ width: 1200, height: 453 });
    await page.waitForFunction(() => grid.rows === Math.floor((453 - 26 - 16) / 17));
    await checkLayout();
    await page.evaluate(() => {
      emitDamage(blankFrame());
      emitDamage(Array.from('ayush18 ~ % ready', (ch, col) => makeCell(grid.rows - 1, col, ch)));
    });
    if (process.env.TACHYON_SCREENSHOT && dpr === 2) await page.screenshot({ path: process.env.TACHYON_SCREENSHOT });
    if (dpr === 1) {
      const wheel = (dy, mode = 0, count = 1) => page.evaluate(({ dy, mode, count }) => {
        for (let i = 0; i < count; i++) document.querySelector('#term').dispatchEvent(new WheelEvent('wheel', { deltaY: dy, deltaMode: mode, cancelable: true }));
      }, { dy, mode, count });
      await wheel(-1, 0, 8);
      await page.waitForTimeout(60);
      assert.deepEqual(await page.evaluate(() => scrollCalls), []);
      await wheel(-1, 0, 9);
      await page.waitForTimeout(60);
      assert.deepEqual(await page.evaluate(() => scrollCalls), [1]);
      await wheel(0, 0, 20);
      await wheel(3, 1);
      await page.waitForTimeout(60);
      assert.deepEqual(await page.evaluate(() => scrollCalls), [1, -3]);
      await page.evaluate(() => {
        for (const deltaY of [17, -17]) document.querySelector('#term').dispatchEvent(new WheelEvent('wheel', { deltaY, cancelable: true }));
      });
      await page.waitForTimeout(60);
      assert.deepEqual(await page.evaluate(() => scrollCalls), [1, -3]);
      await page.evaluate(() => { scrollCalls = []; delay = 100; maxInFlight = 0; });
      for (let i = 0; i < 8; i++) { await wheel(-17); await page.waitForTimeout(20); }
      await page.waitForTimeout(350);
      assert.equal(await page.evaluate(() => maxInFlight), 1);
      assert.equal(await page.evaluate(() => scrollCalls.reduce((a, b) => a + b, 0)), 8);
    }
    assert.deepEqual(errors, []);
    console.log(`PASS DPR ${dpr}: visible last row, resize, clean glyph erasure, wide glyph preservation`);
    await page.close();
  }
  console.log('PASS wheel input and slow-IPC backpressure');
} finally {
  await browser.close();
}
