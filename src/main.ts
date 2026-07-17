import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { homeDir } from "@tauri-apps/api/path";
import { Terminal, type ITheme } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import { getVersion } from "@tauri-apps/api/app";
import { initVim, type VimApi } from "./vim";
import "@xterm/xterm/css/xterm.css";

const AI_EXPLAIN =
  "You are a terminal assistant. Given recent terminal output, explain the most recent error " +
  "or failure in 1-3 short sentences and suggest a fix. If there is no error, say so briefly. " +
  "You may instead be given the exact failing command, its exit code, and its output. " +
  "Plain text only, no markdown.";
const AI_SUMMARY =
  "Summarize what this terminal session accomplished and flag any failures, " +
  "in 2-4 sentences. Plain text only, no markdown.";
const THEMES: Record<string, ITheme> = {
  "Tokyo Night": { background: "#16161e", foreground: "#c0caf5", cursor: "#c0caf5" },
  Dracula: { background: "#282a36", foreground: "#f8f8f2", cursor: "#f8f8f2" },
  Nord: { background: "#2e3440", foreground: "#d8dee9", cursor: "#d8dee9" },
  "Solarized Dark": { background: "#002b36", foreground: "#839496", cursor: "#839496" },
  "Solarized Light": {
    background: "#fdf6e3",
    foreground: "#586e75",
    cursor: "#586e75",
    selectionBackground: "#eee8d5",
  },
  Matrix: { background: "#000000", foreground: "#00ff41", cursor: "#00ff41" },
};

// Chrome tokens per theme (accent + surface layers + status colors) — the terminal itself
// uses THEMES above; these drive every overlay/bar so the whole UI matches the active theme.
interface Chrome {
  accent: string;
  surface: string;
  surfaceAlt: string;
  border: string;
  muted: string;
  ok: string;
  err: string;
}
const CHROME: Record<string, Chrome> = {
  "Tokyo Night": { accent: "#7aa2f7", surface: "#1a1b26", surfaceAlt: "#24283b", border: "#2a2e42", muted: "#7b849c", ok: "#9ece6a", err: "#f7768e" },
  Dracula: { accent: "#bd93f9", surface: "#21222c", surfaceAlt: "#343746", border: "#44475a", muted: "#8a8fa8", ok: "#50fa7b", err: "#ff5555" },
  Nord: { accent: "#88c0d0", surface: "#2b303b", surfaceAlt: "#3b4252", border: "#434c5e", muted: "#7b869c", ok: "#a3be8c", err: "#bf616a" },
  "Solarized Dark": { accent: "#268bd2", surface: "#073642", surfaceAlt: "#0a4a5a", border: "#0f4b59", muted: "#657b83", ok: "#859900", err: "#dc322f" },
  "Solarized Light": { accent: "#268bd2", surface: "#eee8d5", surfaceAlt: "#e3dcc6", border: "#d3cbb3", muted: "#93a1a1", ok: "#859900", err: "#dc322f" },
  Matrix: { accent: "#00ff41", surface: "#0a0f0a", surfaceAlt: "#0f1a0f", border: "#1c3a1c", muted: "#4a7a4a", ok: "#00ff41", err: "#ff5555" },
};

const FONTS = ["Menlo", "Monaco", "SF Mono", "Courier New", "JetBrains Mono", "Fira Code"];

interface Settings {
  theme: string;
  font: string;
  size: number;
}

interface ShellContext {
  cwd: string | null;
  branch: string | null;
  dirty: number;
  shell_pid: number | null;
}

interface Provider {
  id: string;
  kind: string;
  base_url: string;
  model: string;
  has_key: boolean;
}

interface ProviderState {
  active: string;
  providers: Provider[];
}

const settings: Settings = {
  theme: "Tokyo Night",
  font: "Menlo",
  size: 14,
  ...JSON.parse(localStorage.getItem("tachyon-settings") ?? "{}"),
};

window.addEventListener("DOMContentLoaded", async () => {
  const term = new Terminal({ cursorBlink: true });
  const fit = new FitAddon();
  term.loadAddon(fit);
  term.open(document.getElementById("terminal")!);

  function applySettings() {
    const theme = THEMES[settings.theme] ?? THEMES["Tokyo Night"];
    const chrome = CHROME[settings.theme] ?? CHROME["Tokyo Night"];
    term.options.theme = theme;
    term.options.fontFamily = `"${settings.font}", monospace`;
    term.options.fontSize = settings.size;
    document.body.style.background = theme.background!;
    // drive every overlay/bar off the active theme via CSS variables
    const root = document.documentElement.style;
    root.setProperty("--bg", theme.background!);
    root.setProperty("--fg", theme.foreground!);
    root.setProperty("--accent", chrome.accent);
    root.setProperty("--surface", chrome.surface);
    root.setProperty("--surface-alt", chrome.surfaceAlt);
    root.setProperty("--border", chrome.border);
    root.setProperty("--muted", chrome.muted);
    root.setProperty("--ok", chrome.ok);
    root.setProperty("--err", chrome.err);
    fit.fit();
    localStorage.setItem("tachyon-settings", JSON.stringify(settings));
  }
  applySettings();
  term.focus();

  // settings panel
  const panel = document.getElementById("settings")!;
  const themeSel = document.getElementById("theme-select") as HTMLSelectElement;
  const fontSel = document.getElementById("font-select") as HTMLSelectElement;
  const sizeInput = document.getElementById("font-size") as HTMLInputElement;

  themeSel.innerHTML = Object.keys(THEMES)
    .map((t) => `<option${t === settings.theme ? " selected" : ""}>${t}</option>`)
    .join("");
  fontSel.innerHTML = FONTS.map(
    (f) => `<option${f === settings.font ? " selected" : ""}>${f}</option>`,
  ).join("");
  sizeInput.value = String(settings.size);

  themeSel.onchange = () => ((settings.theme = themeSel.value), applySettings());
  fontSel.onchange = () => ((settings.font = fontSel.value), applySettings());
  sizeInput.onchange = () => {
    settings.size = Math.min(28, Math.max(9, Number(sizeInput.value) || 14));
    sizeInput.value = String(settings.size);
    applySettings();
  };

  function togglePanel() {
    panel.hidden = !panel.hidden;
    if (panel.hidden) term.focus();
  }
  document.getElementById("settings-btn")!.onclick = togglePanel;
  window.addEventListener("keydown", (e) => {
    if (e.metaKey && e.key === ",") {
      e.preventDefault();
      togglePanel();
    }
    if (e.metaKey && e.key === "k") {
      e.preventDefault();
      aiBar.hidden ? openAiBar() : closeAiBar();
    }
    if (e.metaKey && e.key === "j") {
      e.preventDefault();
      if (agentRunning) {
        void invoke("agent_abort"); // ⌘J while running = dedicated abort
        return;
      }
      aiBar.hidden ? openAgentBar() : closeAiBar();
    }
    if (e.metaKey && e.key === "e") {
      e.preventDefault();
      explainError();
    }
    if (e.metaKey && e.key === "p") {
      e.preventDefault();
      palette.hidden ? openPalette() : closePalette();
    }
    if (e.metaKey && e.key === "b") {
      e.preventDefault();
      blocks.hidden ? openBlocks() : closeBlocks();
    }
    if (e.key === "Escape" && !blocks.hidden) {
      e.preventDefault();
      closeBlocks();
    }
  });

  // AI command bar
  const aiBar = document.getElementById("ai-bar")!;
  const aiInput = document.getElementById("ai-input") as HTMLInputElement;
  const aiStatus = document.getElementById("ai-status")!;
  const aiIcon = document.getElementById("ai-icon")!;

  // agent mode state — the loop itself lives in Rust; TS only renders the approval gate
  let barMode: "command" | "agent" = "command";
  let agentRunning = false; // mirror of the Rust AgentState.running
  let pendingGate = false; // an agent-propose is awaiting Enter/Esc

  // ---- OSC 133 command journal (mirror) ----
  // The scanner + 50-block ring live in Rust, in the pty reader thread. TS keeps a
  // render mirror: seeded via journal_blocks(), appended via "journal-block" events.
  interface JBlock {
    command: string;
    exit_code: number;
    output: string;
    duration_ms: number;
    // per-card UI state — lives on the block so re-renders and ring shifts keep/GC it
    ai?: string;
    aiPending?: boolean;
    expanded?: boolean;
  }
  const journal: JBlock[] = []; // mirror of the Rust ring (last 50 finalized blocks)
  let oscReady = false; // true once a finalized block proves the zsh hooks loaded
  // clean command source: what the user actually typed (from term.onData) — forwarded
  // to Rust on Enter (set_typed_command) so the journal label isn't scraped from the echo.
  let typedLine = "";

  function lastBlock(): JBlock | null {
    return journal[journal.length - 1] ?? null;
  }

  async function openAiBar() {
    aiBar.hidden = false;
    fit.fit();
    const p = await invoke<Provider>("provider_active");
    aiStatus.textContent = `${p.id} · ${p.model}${p.has_key || p.kind !== "anthropic" ? "" : " · no key"}`;
    aiInput.focus();
  }

  function openAgentBar() {
    barMode = "agent";
    aiBar.classList.add("agent");
    aiIcon.textContent = "⚡";
    aiInput.placeholder = "Describe a task…";
    openAiBar();
  }

  function closeAiBar() {
    aiBar.hidden = true;
    aiBar.classList.remove("danger");
    aiBar.classList.remove("agent");
    aiIcon.textContent = "✦";
    aiInput.placeholder = "Describe a command…";
    aiInput.readOnly = false;
    barMode = "command";
    aiInput.value = "";
    aiStatus.textContent = "";
    fit.fit();
    term.focus();
  }

  async function askAi(system: string, userMsg: string): Promise<string> {
    try {
      return await invoke<string>("ai_complete", { system, user: userMsg });
    } catch (e) {
      // Tauri rejects invoke with the plain Err string; callers read (e as Error).message
      throw e instanceof Error ? e : new Error(String(e));
    }
  }

  async function runAi(request: string) {
    if (!request) return;
    aiStatus.textContent = "thinking…";
    aiBar.classList.remove("danger");
    try {
      // prompt assembly, fence stripping, and the danger check all live in Rust
      const { command, danger } = await invoke<{ command: string; danger: boolean }>(
        "nl_to_command",
        { request },
      );
      await invoke("pty_write", { data: command }); // no trailing newline — never auto-execute
      if (danger) {
        aiBar.classList.add("danger");
        aiStatus.textContent = "⚠ destructive — review carefully";
        term.focus();
      } else {
        closeAiBar();
      }
    } catch (e) {
      // invoke rejects with the plain Err string, not an Error
      aiStatus.textContent = e instanceof Error ? e.message : String(e);
    }
  }

  // ---- Agent mode (loop lives in Rust; TS renders the gate) ----

  async function startAgent(task: string) {
    if (!task || agentRunning) return;
    agentRunning = true;
    aiInput.readOnly = true;
    aiStatus.textContent = "starting…";
    try {
      await invoke("agent_start", { task });
    } catch (e) {
      aiStatus.textContent = e instanceof Error ? e.message : String(e);
      agentRunning = false;
      aiInput.readOnly = false;
    }
  }

  interface AgentPropose {
    step: number;
    kind: "run" | "tool";
    text: string;
    args?: unknown;
    danger: boolean;
  }
  await listen<AgentPropose>("agent-propose", (e) => {
    const p = e.payload;
    agentRunning = true;
    if (aiBar.hidden) {
      aiBar.hidden = false;
      fit.fit();
    }
    aiInput.value = p.text;
    aiInput.readOnly = true;
    aiBar.classList.toggle("danger", p.danger);
    aiStatus.textContent = (p.danger ? "⚠ destructive · " : "") + "run? ⏎ approve · esc deny";
    pendingGate = true;
    aiInput.focus();
  });
  await listen<{ step: number; status: string }>("agent-status", (e) => {
    const { step, status } = e.payload;
    aiStatus.textContent = status === "thinking" ? `thinking… (${step}/12)` : status;
  });
  await listen<{ step: number; text: string }>("agent-output", (e) => {
    term.write(`\r\n\x1b[36m[agent] ${e.payload.text.replace(/\n/g, "\r\n")}\x1b[0m\r\n`);
  });
  await listen<{ summary: string }>("agent-done", (e) => {
    term.write(`\r\n\x1b[36m[agent] ${e.payload.summary.replace(/\n/g, "\r\n")}\x1b[0m\r\n`);
    agentRunning = false;
    pendingGate = false;
    closeAiBar();
  });

  aiInput.onkeydown = (e) => {
    if (pendingGate) {
      // THE explicit approval keypress — nothing else may resolve a proposal
      if (e.key === "Enter") {
        e.preventDefault();
        pendingGate = false;
        aiBar.classList.remove("danger");
        void invoke("agent_decide", { approved: true });
      } else if (e.key === "Escape") {
        e.preventDefault();
        pendingGate = false;
        aiBar.classList.remove("danger");
        void invoke("agent_decide", { approved: false });
      }
      return;
    }
    if (agentRunning) {
      // mid-run (thinking/running): Esc aborts, Enter ignored
      if (e.key === "Escape") {
        e.preventDefault();
        void invoke("agent_abort");
      }
      return;
    }
    if (e.key === "Escape") {
      e.preventDefault();
      closeAiBar();
    } else if (e.key === "Enter") {
      e.preventDefault();
      const v = aiInput.value.trim();
      if (v.startsWith("/")) handleSlash(v);
      else if (barMode === "agent") void startAgent(v);
      else runAi(v);
    }
  };

  // Slash commands: parsed and executed in Rust (run_slash); we just print the result.
  async function handleSlash(input: string) {
    term.write(await invoke<string>("run_slash", { input }));
    closeAiBar();
  }

  // Error autopsy (⌘E): Rust picks the failed block and builds the prompt;
  // the returned text is printed display-only (cyan)
  let explaining = false;
  async function explainError() {
    if (explaining) return;
    explaining = true;
    term.write("\r\n\x1b[90m[tachyon] explaining…\x1b[0m");
    try {
      const out = await invoke<string>("explain_last_error");
      const body = out.trim().replace(/\n/g, "\r\n");
      term.write(`\r\x1b[2K\x1b[36m${body}\x1b[0m\r\n`);
    } catch (e) {
      term.write(`\r\x1b[2K\x1b[31m[tachyon] ${e instanceof Error ? e.message : String(e)}\x1b[0m\r\n`);
    } finally {
      explaining = false;
    }
  }

  // ---- Command palette (⌘P) ----
  const palette = document.getElementById("palette")!;
  const paletteInput = document.getElementById("palette-input") as HTMLInputElement;
  const paletteList = document.getElementById("palette-list")!;
  const paletteVersion = document.getElementById("palette-version")!;
  let vim: VimApi | null = null;
  interface PaletteEntry {
    label: string;
    hint: string;
    run: () => void;
  }
  let paletteEntries: PaletteEntry[] = [];
  let paletteShown: PaletteEntry[] = [];
  let paletteSel = 0;

  const escapeHtml = (s: string) =>
    s.replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]!);

  // subsequence fuzzy match (needle chars appear in order within label)
  function fuzzy(label: string, needle: string): boolean {
    const h = label.toLowerCase();
    const n = needle.toLowerCase();
    let i = 0;
    for (const ch of h) if (ch === n[i]) i++;
    return i === n.length;
  }

  async function buildPaletteEntries(): Promise<PaletteEntry[]> {
    const e: PaletteEntry[] = [
      { label: "AI command", hint: "⌘K", run: () => (closePalette(), openAiBar()) },
      { label: "Agent: run a task", hint: "⌘J", run: () => (closePalette(), openAgentBar()) },
      { label: "Explain last error", hint: "⌘E", run: () => (closePalette(), explainError()) },
      { label: "Blocks: session navigator", hint: "⌘B", run: () => (closePalette(), openBlocks()) },
      { label: "Vim mode", hint: "⌘⇧V", run: () => (closePalette(), vim?.enterNormal()) },
      { label: "Settings", hint: "⌘,", run: () => (closePalette(), togglePanel()) },
    ];
    try {
      const st = await invoke<ProviderState>("provider_state");
      for (const p of st.providers) {
        e.push({
          label: `Use provider: ${p.id}`,
          hint: p.id === st.active ? "active" : p.model,
          run: async () => {
            closePalette();
            await invoke("provider_use", { id: p.id });
            term.write(`\r\n\x1b[36m[tachyon] active provider: ${p.id}\x1b[0m\r\n`);
          },
        });
      }
    } catch {
      /* provider list is best-effort */
    }
    // recent commands from the OSC 133 journal (deduped, newest first)
    const seen = new Set<string>();
    for (let i = journal.length - 1; i >= 0 && seen.size < 15; i--) {
      const c = journal[i].command.trim();
      // skip empty, dupes, and OSC-133 capture noise (prompt fragments, the injected hooks)
      const noise = !c || c.includes("_tachyon") || c.includes("print -n") || /%\s*$/.test(c) || c.length > 120;
      if (!noise && !seen.has(c)) {
        seen.add(c);
        e.push({ label: c, hint: "history", run: () => (closePalette(), void invoke("pty_write", { data: c })) });
      }
    }
    return e;
  }

  function renderPalette() {
    const q = paletteInput.value.trim();
    paletteShown = q ? paletteEntries.filter((x) => fuzzy(x.label, q)) : paletteEntries;
    if (paletteSel >= paletteShown.length) paletteSel = Math.max(0, paletteShown.length - 1);
    paletteList.innerHTML = paletteShown
      .map(
        (x, i) =>
          `<li class="${i === paletteSel ? "sel" : ""}"><span class="label">${escapeHtml(x.label)}</span><span class="hint">${escapeHtml(x.hint)}</span></li>`,
      )
      .join("");
    paletteList.children[paletteSel]?.scrollIntoView({ block: "nearest" });
  }

  async function openPalette() {
    paletteEntries = await buildPaletteEntries();
    paletteSel = 0;
    paletteInput.value = "";
    palette.hidden = false;
    renderPalette();
    paletteInput.focus();
  }
  function closePalette() {
    palette.hidden = true;
    term.focus();
  }

  paletteInput.oninput = () => ((paletteSel = 0), renderPalette());
  paletteInput.onkeydown = (e) => {
    if (e.key === "Escape") {
      e.preventDefault();
      closePalette();
    } else if (e.key === "ArrowDown") {
      e.preventDefault();
      paletteSel = Math.min(paletteShown.length - 1, paletteSel + 1);
      renderPalette();
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      paletteSel = Math.max(0, paletteSel - 1);
      renderPalette();
    } else if (e.key === "Enter") {
      e.preventDefault();
      paletteShown[paletteSel]?.run();
    }
  };
  paletteList.onclick = (ev) => {
    const li = (ev.target as HTMLElement).closest("li");
    if (!li) return;
    const idx = [...paletteList.children].indexOf(li);
    paletteShown[idx]?.run();
  };

  // ---- Block navigator (⌘B) + session-health minimap ----
  const blocks = document.getElementById("blocks")!;
  const blocksList = document.getElementById("blocks-list")!;
  const blocksSummary = document.getElementById("blocks-summary")!;
  const minimap = document.getElementById("minimap")!;

  function fmtDuration(ms: number): string {
    if (ms < 1000) return `${Math.round(ms)}ms`;
    if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
    return `${Math.round(ms / 1000)}s`;
  }

  function blockClass(code: number): string {
    return code === 0 ? "ok" : code < 0 ? "unk" : "err";
  }

  function renderBlocks() {
    if (journal.length === 0) {
      blocksList.innerHTML = `<div class="block-empty">${
        oscReady ? "no commands yet — run something" : "waiting for shell integration (zsh OSC 133 handshake)…"
      }</div>`;
      return;
    }
    let html = "";
    for (let i = journal.length - 1; i >= 0; i--) {
      const b = journal[i];
      const lines = b.output.split("\n").filter((l) => l.trim());
      const moreLines = lines.length > 3 || b.output.length > 4000;
      const preview = b.expanded ? b.output.slice(0, 4000) : lines.slice(0, 3).join("\n");
      html +=
        `<div class="block-card ${blockClass(b.exit_code)}" id="block-${i}">` +
        `<div class="block-stripe"></div><div class="block-body">` +
        `<div class="block-cmd">${escapeHtml(b.command || `command ${i + 1}`)}</div>` +
        `<div class="block-meta">exit ${b.exit_code} · ${fmtDuration(b.duration_ms)}</div>` +
        (preview ? `<div class="block-out">${escapeHtml(preview)}</div>` : "") +
        (moreLines
          ? `<button class="block-expand" data-action="toggle" data-idx="${i}">${b.expanded ? "▾ collapse" : "▸ expand"}</button>`
          : "") +
        (b.ai ? `<div class="block-ai">${escapeHtml(b.ai)}</div>` : "") +
        `<div class="block-actions">` +
        `<button data-action="explain" data-idx="${i}"${b.aiPending ? " disabled" : ""}>✦ explain</button>` +
        `<button data-action="rerun" data-idx="${i}"${b.command.trim() ? "" : " disabled"}>⟳ rerun</button>` +
        `<button data-action="copy" data-idx="${i}">⎘ copy</button>` +
        `</div></div></div>`;
    }
    blocksList.innerHTML = html;
  }

  function renderMinimap() {
    minimap.hidden = journal.length === 0;
    minimap.innerHTML = journal
      .map(
        (b, i) =>
          `<div class="mm-seg ${blockClass(b.exit_code)}" data-idx="${i}" title="${escapeHtml(b.command || `command ${i + 1}`)}"></div>`,
      )
      .join("");
  }

  function openBlocks(scrollTo?: number) {
    renderBlocks();
    blocks.hidden = false;
    (blocks as HTMLElement).focus(); // keeps Esc away from xterm's textarea
    if (scrollTo != null) document.getElementById(`block-${scrollTo}`)?.scrollIntoView({ block: "center" });
  }

  function closeBlocks() {
    blocks.hidden = true;
    term.focus();
  }

  async function explainBlock(i: number) {
    const b = journal[i];
    if (!b || b.aiPending) return;
    b.aiPending = true;
    b.ai = "thinking…";
    renderBlocks();
    try {
      b.ai = await askAi(
        AI_EXPLAIN,
        `$ ${b.command || "(unknown)"}\nexit ${b.exit_code}\nOutput:\n${b.output.slice(0, 2000)}`,
      );
    } catch (e) {
      b.ai = (e as Error).message;
    } finally {
      b.aiPending = false;
    }
    if (!blocks.hidden) renderBlocks();
  }

  async function summarizeSession() {
    blocksSummary.hidden = false;
    blocksSummary.textContent = "thinking…";
    const transcript = journal
      .slice(-20)
      .map(
        (b) =>
          `$ ${b.command || "(command)"} (exit ${b.exit_code})\n${b.output.split("\n").filter(Boolean).slice(0, 2).join("\n")}`,
      )
      .join("\n");
    try {
      blocksSummary.textContent = transcript
        ? await askAi(AI_SUMMARY, transcript)
        : "nothing to summarize yet";
    } catch (e) {
      blocksSummary.textContent = (e as Error).message;
    }
  }

  blocksList.onclick = (ev) => {
    const btn = (ev.target as HTMLElement).closest("button");
    if (!btn) return;
    const i = Number(btn.dataset.idx);
    const b = journal[i];
    if (!b) return;
    if (btn.dataset.action === "toggle") {
      b.expanded = !b.expanded;
      renderBlocks();
    } else if (btn.dataset.action === "explain") {
      void explainBlock(i);
    } else if (btn.dataset.action === "rerun") {
      const cmd = b.command.replace(/[\r\n]/g, " ").trim();
      if (!cmd) return;
      closeBlocks();
      void invoke("pty_write", { data: cmd }); // no trailing newline — prefill only, never auto-execute
    } else if (btn.dataset.action === "copy") {
      navigator.clipboard.writeText(b.output).then(
        () => {
          btn.textContent = "copied";
          setTimeout(() => (btn.textContent = "⎘ copy"), 900);
        },
        () => (btn.textContent = "copy failed"),
      );
    }
  };
  document.getElementById("blocks-summarize")!.onclick = () => void summarizeSession();
  document.getElementById("blocks-close")!.onclick = closeBlocks;
  minimap.onclick = (ev) => {
    const seg = (ev.target as HTMLElement).closest(".mm-seg") as HTMLElement | null;
    if (seg) openBlocks(Number(seg.dataset.idx));
  };

  // pty bridge — payload is base64 (STANDARD, padded) from the Rust reader thread
  function b64ToBytes(s: string): Uint8Array {
    const bin = atob(s);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  }
  // journal mirror: listener installed BEFORE the seed so no block slips between
  await listen<JBlock>("journal-block", (e) => {
    journal.push(e.payload);
    if (journal.length > 50) journal.shift();
    oscReady = true;
    renderMinimap();
    if (!blocks.hidden) renderBlocks();
  });
  const seed = await invoke<JBlock[]>("journal_blocks");
  if (journal.length === 0 && seed.length > 0) {
    // hot-reload: the Rust journal survives the webview
    journal.push(...seed);
    oscReady = true;
    renderMinimap();
  }
  await listen<string>("pty-output", (e) => {
    term.write(b64ToBytes(e.payload)); // live output — never gated, never stripped
  });
  await listen("pty-exit", () => term.write("\r\n[process exited]\r\n"));
  await invoke("pty_spawn", { rows: term.rows, cols: term.cols });

  term.onData((data) => {
    invoke("pty_write", { data });
    // reconstruct the typed command line for a clean journal label. Escape sequences
    // (arrows/history/completion) can't be tracked reliably → drop the line so the C-mark
    // handler falls back to echo-scraping for that command.
    if (data.startsWith("\x1b")) {
      typedLine = "";
    } else {
      for (const ch of data) {
        if (ch === "\r" || ch === "\n") {
          void invoke("set_typed_command", { line: typedLine });
          typedLine = "";
        } else if (ch === "\x7f" || ch === "\x08") {
          typedLine = typedLine.slice(0, -1); // backspace
        } else if (ch === "\x15" || ch === "\x03") {
          typedLine = ""; // Ctrl-U / Ctrl-C
        } else if (ch >= " ") {
          typedLine += ch;
        }
      }
    }
    if (data.includes("\r")) scheduleContextRefresh();
  });
  term.onResize(({ rows, cols }) => invoke("pty_resize", { rows, cols }));
  window.addEventListener("resize", () => fit.fit());

  // status bar
  const statusCwd = document.getElementById("status-cwd")!;
  const statusGit = document.getElementById("status-git")!;
  vim = initVim({
    term,
    statusEl: document.getElementById("status-vim")!,
    searchEl: document.getElementById("vim-search") as HTMLInputElement,
  });
  getVersion()
    .then((v) => (paletteVersion.textContent = `v${v}`))
    .catch(() => {});
  const home = (await homeDir()).replace(/\/$/, "");
  let ctxTimer: number | undefined;

  async function refreshContext() {
    const ctx = await invoke<ShellContext>("get_context");
    statusCwd.textContent = ctx.cwd
      ? ctx.cwd === home
        ? "~"
        : ctx.cwd.startsWith(home + "/")
          ? "~" + ctx.cwd.slice(home.length)
          : ctx.cwd
      : "";
    const lb = lastBlock();
    statusGit.textContent =
      (ctx.branch ? `⎇ ${ctx.branch}${ctx.dirty > 0 ? ` ±${ctx.dirty}` : ""}` : "") +
      (lb && lb.exit_code !== 0 ? ` ✗ ${lb.exit_code}` : "");
  }

  function scheduleContextRefresh() {
    clearTimeout(ctxTimer);
    ctxTimer = window.setTimeout(refreshContext, 300);
  }
  scheduleContextRefresh();
});
