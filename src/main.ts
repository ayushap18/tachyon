import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { homeDir } from "@tauri-apps/api/path";
import { Terminal, type ITheme } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import Anthropic from "@anthropic-ai/sdk";
import { getVersion } from "@tauri-apps/api/app";
import { initVim, type VimApi } from "./vim";
import "@xterm/xterm/css/xterm.css";

const AI_SYSTEM =
  "You translate natural-language requests into a single shell command for zsh on macOS. " +
  "Output ONLY the command — no markdown fences, no explanation, no commentary.";
const AI_EXPLAIN =
  "You are a terminal assistant. Given recent terminal output, explain the most recent error " +
  "or failure in 1-3 short sentences and suggest a fix. If there is no error, say so briefly. " +
  "You may instead be given the exact failing command, its exit code, and its output. " +
  "Plain text only, no markdown.";
const AI_SUMMARY =
  "Summarize what this terminal session accomplished and flag any failures, " +
  "in 2-4 sentences. Plain text only, no markdown.";
const AI_AGENT =
  "You drive a macOS zsh terminal to accomplish the user's task step by step. " +
  "Respond with EXACTLY ONE line: either 'RUN: <single shell command>' to execute a command, " +
  "or 'DONE: <one-sentence summary>' when the task is complete or cannot proceed. " +
  "No markdown, no prose, no multiple commands, no explanation. " +
  "You are given each command's output before deciding the next step.";

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
  key: string;
}

interface ProviderState {
  active: string;
  providers: Provider[];
}

interface McpServer {
  name: string;
  url: string;
}

interface McpServerTool {
  server: string;
  name: string;
  description: string;
  input_schema: unknown;
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
        abortAgent(); // ⌘J while running = dedicated abort
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

  // agent mode state
  let barMode: "command" | "agent" = "command";
  let agentRunning = false;
  let agentAbort = false;
  let gateResolve: ((approved: boolean) => void) | null = null;
  let captureResolve: ((r: { output: string; code: number }) => void) | null = null;
  let captureBuf = "";
  let captureNonce = "";
  const dec = new TextDecoder();

  // ---- OSC 133 command journal ----
  // The injected zsh hooks (see Rust shell_integration_script) emit
  // ESC]133;A (prompt start), C (output start), D;<code> (command end).
  // We scan a decoded COPY of the pty stream — term.write stays byte-identical.
  interface CommandBlock {
    command: string;
    exitCode: number;
    output: string;
    startedAt?: number;
    durationMs?: number;
    // per-card UI state — lives on the block so re-renders and ring shifts keep/GC it
    ai?: string;
    aiPending?: boolean;
    expanded?: boolean;
  }
  const journal: CommandBlock[] = []; // ring of last 50 finalized blocks
  let oscReady = false; // true once a D mark proves the hooks loaded
  let oscCarry = ""; // partial mark split across pty chunks
  let oscCapturing = false;
  let oscOutput = ""; // current block output (tail-capped)
  let oscPreCmd = ""; // text between A and C — fallback command source (echo scrape)
  let oscCommand = "";
  // clean command source: what the user actually typed (from term.onData), not the echoed
  // stream — avoids the doubled-first-char that shell-plugin line redraws leave in the echo.
  let typedLine = "";
  let pendingTyped: string | null = null;
  let oscStartedAt = 0;
  const OSC133 = /\x1b\]133;([ABCD])(?:;(\d+))?(?:\x07|\x1b\\)/g;
  const stripAnsi = (s: string) =>
    s
      .replace(/\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?/g, "")
      .replace(/\x1b\[[0-9;?]*[A-Za-z]/g, "")
      .replace(/[\x00-\x08\x0b-\x1f]/g, "");

  function feedOsc(text: string): void {
    let s = oscCarry + text;
    oscCarry = "";
    // hold back a mark that may be split across chunks
    const j = s.lastIndexOf("\x1b]133;");
    const tail = j >= 0 ? s.slice(j) : "";
    if (j >= 0 && !tail.includes("\x07") && !tail.includes("\x1b\\")) {
      if (tail.length <= 64) oscCarry = tail; // longer means it's not our mark
      s = s.slice(0, j);
    } else {
      // a bare prefix of the header at the very end ("\x1b", "\x1b]1", …)
      for (let k = Math.min(5, s.length); k > 0; k--) {
        if (s.endsWith("\x1b]133;".slice(0, k))) {
          oscCarry = s.slice(s.length - k);
          s = s.slice(0, s.length - k);
          break;
        }
      }
    }
    OSC133.lastIndex = 0;
    let idx = 0;
    let m: RegExpExecArray | null;
    const feed = (seg: string) => {
      if (oscCapturing) oscOutput = (oscOutput + seg).slice(-8192);
      else oscPreCmd = (oscPreCmd + seg).slice(-512);
    };
    while ((m = OSC133.exec(s))) {
      feed(s.slice(idx, m.index));
      idx = OSC133.lastIndex;
      const mark = m[1];
      if (mark === "A" || mark === "B") {
        oscPreCmd = "";
      } else if (mark === "C") {
        // prefer what the user actually typed (clean); fall back to scraping the echo
        // (agent-injected commands and history/completion recalls have no typed line)
        if (pendingTyped != null && pendingTyped !== "") {
          oscCommand = pendingTyped;
        } else {
          const lines = stripAnsi(oscPreCmd)
            .split("\n")
            .map((l) => l.trim())
            .filter(Boolean);
          // naive prompt strip (no B mark) — drop through the last space-delimited sigil
          oscCommand = (lines[lines.length - 1] ?? "").replace(/^.*\s[%$#>]\s+/, "");
        }
        pendingTyped = null;
        oscOutput = "";
        oscStartedAt = Date.now();
        oscCapturing = true;
      } else {
        // D;<code> — command end. First D (no prior C) is just the handshake.
        oscReady = true;
        if (oscCapturing) {
          journal.push({
            command: oscCommand,
            exitCode: Number(m[2] ?? 0),
            output: stripAnsi(oscOutput).trim(),
            startedAt: oscStartedAt || undefined,
            durationMs: oscStartedAt ? Date.now() - oscStartedAt : undefined,
          });
          if (journal.length > 50) journal.shift();
          renderMinimap();
          if (!blocks.hidden) renderBlocks();
        }
        oscCapturing = false;
      }
    }
    feed(s.slice(idx));
  }

  function lastBlock(): CommandBlock | null {
    return journal[journal.length - 1] ?? null;
  }

  function lastFailedBlock(): CommandBlock | null {
    for (let i = journal.length - 1; i >= 0; i--) {
      if (journal[i].exitCode !== 0) return journal[i];
    }
    return null;
  }

  function recentBlocksText(n = 5): string {
    return journal
      .slice(-n)
      .map((b) => `$ ${b.command || "(command)"} (exit ${b.exitCode})\n${b.output.slice(-500)}`)
      .join("\n");
  }

  // journal-first terminal context; falls back to buffer scraping pre-handshake
  function recentContext(maxLines = 30): string {
    return oscReady && journal.length > 0
      ? `Recent commands:\n${recentBlocksText(5)}`
      : `Recent terminal output:\n${lastTerminalLines(maxLines)}`;
  }

  async function openAiBar() {
    aiBar.hidden = false;
    fit.fit();
    const p = await invoke<Provider>("provider_active");
    aiStatus.textContent = `${p.id} · ${p.model}${p.key || p.kind !== "anthropic" ? "" : " · no key"}`;
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

  function lastTerminalLines(max = 30): string {
    const buf = term.buffer.active;
    const lines: string[] = [];
    for (let i = 0; i < buf.length; i++) {
      const text = buf.getLine(i)?.translateToString(true).trim();
      if (text) lines.push(text);
    }
    return lines.slice(-max).join("\n");
  }

  async function askAi(system: string, userMsg: string): Promise<string> {
    const p = await invoke<Provider>("provider_active");
    if (p.kind === "anthropic") {
      if (!p.key) throw new Error(`no key for ${p.id} — set with /key ${p.id} <key>`);
      const client = new Anthropic({ apiKey: p.key, dangerouslyAllowBrowser: true });
      const msg = await client.messages.create({
        model: p.model,
        max_tokens: 1024,
        system,
        messages: [{ role: "user", content: userMsg }],
      });
      const block = msg.content.find((b) => b.type === "text");
      return block?.type === "text" ? block.text : "";
    }
    // OpenAI-compatible (openai, groq, gemini, kimi, deepseek, mistral, local). Local may have no key.
    const headers: Record<string, string> = { "content-type": "application/json" };
    if (p.key) headers.authorization = `Bearer ${p.key}`;
    const r = await fetch(`${p.base_url}/chat/completions`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        model: p.model,
        max_tokens: 1024,
        messages: [
          { role: "system", content: system },
          { role: "user", content: userMsg },
        ],
      }),
    });
    if (!r.ok) throw new Error(`${p.id} ${r.status}: ${(await r.text()).slice(0, 120)}`);
    return (await r.json()).choices?.[0]?.message?.content ?? "";
  }

  function stripFences(s: string): string {
    return s
      .trim()
      .replace(/^```[a-z]*\s*/i, "")
      .replace(/```$/, "")
      .trim();
  }

  async function runAi(request: string) {
    if (!request) return;
    aiStatus.textContent = "thinking…";
    aiBar.classList.remove("danger");
    try {
      const ctx = await invoke<ShellContext>("get_context");
      const userMsg =
        `${request}\n\nContext:\ncwd: ${ctx.cwd ?? "unknown"}\n` +
        `git: ${ctx.branch ? `${ctx.branch}${ctx.dirty > 0 ? ` (${ctx.dirty} dirty)` : ""}` : "none"}\n` +
        recentContext();
      const cmd = stripFences(await askAi(AI_SYSTEM, userMsg));
      if (!cmd) {
        aiStatus.textContent = "no command returned";
        return;
      }
      const danger = await invoke<boolean>("check_dangerous", { cmd });
      await invoke("pty_write", { data: cmd }); // no trailing newline — never auto-execute
      if (danger) {
        aiBar.classList.add("danger");
        aiStatus.textContent = "⚠ destructive — review carefully";
        term.focus();
      } else {
        closeAiBar();
      }
    } catch (e) {
      aiStatus.textContent = (e as Error).message;
    }
  }

  // ---- Agent mode ----

  function gate(cmd: string, danger: boolean): Promise<boolean> {
    aiInput.value = cmd;
    aiInput.readOnly = true;
    aiBar.classList.toggle("danger", danger);
    aiStatus.textContent = (danger ? "⚠ destructive · " : "") + "run? ⏎ approve · esc deny";
    return new Promise((res) => (gateResolve = res));
  }

  function runCaptured(cmd: string, nonce: string): Promise<{ output: string; code: number }> {
    captureBuf = "";
    captureNonce = nonce;
    return new Promise((res) => {
      // ponytail: 20s wall-clock timeout — resolves with code -1 if the marker never
      // arrives (interactive/hung program owns the pty). Bounds the loop; abort still works.
      const timer = window.setTimeout(() => {
        if (captureResolve) {
          captureResolve = null;
          res({ output: captureBuf, code: -1 });
        }
      }, 20000);
      captureResolve = (r) => {
        clearTimeout(timer);
        res(r);
      };
      void invoke("pty_write", {
        data: `${cmd}; printf '\\n__TACHYON_${nonce}_%d__\\n' $?\n`,
      });
    });
  }

  function endAgent() {
    agentRunning = false;
    gateResolve = null;
    captureResolve = null;
    aiInput.readOnly = false;
    closeAiBar();
  }

  function abortAgent() {
    if (!agentRunning) return;
    agentAbort = true;
    if (gateResolve) {
      const r = gateResolve;
      gateResolve = null;
      r(false);
    }
    if (captureResolve) {
      const r = captureResolve;
      captureResolve = null;
      r({ output: "", code: -1 });
    }
    term.write("\r\n\x1b[36m[agent] aborted\x1b[0m\r\n");
  }

  async function runAgent(task: string) {
    if (!task || agentRunning) return;
    agentRunning = true;
    agentAbort = false;
    aiInput.readOnly = true;
    let completed = false;
    try {
      const ctx = await invoke<ShellContext>("get_context");
      let transcript =
        `Task: ${task}\n\nContext:\ncwd: ${ctx.cwd ?? "unknown"}\n` +
        `git: ${ctx.branch ? `${ctx.branch}${ctx.dirty > 0 ? ` (${ctx.dirty} dirty)` : ""}` : "none"}\n` +
        recentContext(20) +
        "\n";
      let tools: McpServerTool[] = [];
      try {
        tools = await invoke<McpServerTool[]>("mcp_list_tools");
      } catch {
        // all servers failed — agent runs shell-only
      }
      const system =
        tools.length === 0
          ? AI_AGENT
          : AI_AGENT +
            " You may also call a tool: respond with EXACTLY 'TOOL: <server>.<name> {json arguments}' (one line).\n" +
            "TOOLS:\n" +
            tools.map((t) => `TOOL ${t.server}.${t.name} — ${t.description}`).join("\n");
      for (let step = 1; step <= 12; step++) {
        if (agentAbort) break;
        aiStatus.textContent = `thinking… (${step}/12)`;
        const reply = (await askAi(system, transcript)).trim();
        if (agentAbort) break;
        if (/^DONE:/i.test(reply)) {
          term.write(`\r\n\x1b[36m[agent] ${reply.replace(/^DONE:/i, "").trim()}\x1b[0m\r\n`);
          completed = true;
          break;
        }
        if (/^TOOL:/i.test(reply)) {
          const rest = reply.replace(/^TOOL:/i, "").trim();
          const sp = rest.indexOf(" ");
          const ref = sp === -1 ? rest : rest.slice(0, sp);
          const dot = ref.indexOf(".");
          if (dot < 1) {
            transcript += `\nInvalid tool call: ${reply}\n`;
            continue;
          }
          const server = ref.slice(0, dot);
          const tool = ref.slice(dot + 1);
          let args: unknown = {};
          try {
            args = JSON.parse(sp === -1 ? "{}" : rest.slice(sp + 1));
          } catch {
            args = {};
          }
          // same explicit-approval gate as RUN — tools never auto-call
          const approved = await gate(`call ${server}.${tool}(${JSON.stringify(args)})`, false);
          aiInput.readOnly = true;
          aiBar.classList.remove("danger");
          if (agentAbort) break;
          if (!approved) {
            transcript += `\nThe user denied tool call ${server}.${tool}. Suggest an alternative or DONE.\n`;
            aiStatus.textContent = "denied";
            continue;
          }
          aiStatus.textContent = "running tool…";
          term.write(`\r\n\x1b[36m[agent] tool ${server}.${tool}…\x1b[0m\r\n`);
          try {
            const result = await invoke<string>("mcp_call", { server, tool, args });
            transcript += `\nTool: ${server}.${tool}\nResult:\n${result.slice(0, 2000)}\n`;
          } catch (e) {
            transcript += `\nTool error: ${(e as Error).message ?? String(e)}\n`;
          }
          if (agentAbort) break;
          continue;
        }
        const cmd = stripFences(reply.replace(/^RUN:/i, "").trim());
        if (!cmd) {
          term.write("\r\n\x1b[36m[agent] no command returned\x1b[0m\r\n");
          completed = true;
          break;
        }
        const danger = await invoke<boolean>("check_dangerous", { cmd });
        const approved = await gate(cmd, danger);
        aiInput.readOnly = true;
        aiBar.classList.remove("danger");
        if (agentAbort) break;
        if (!approved) {
          transcript += `\nThe user denied running: ${cmd}. Suggest an alternative or DONE.\n`;
          aiStatus.textContent = "denied";
          continue;
        }
        aiStatus.textContent = "running…";
        const { output, code } = await runCaptured(cmd, "s" + step);
        if (agentAbort) break;
        const clean = output
          .replace(/\x1b\[[0-9;?]*[A-Za-z]/g, "")
          .replace(cmd, "")
          .trim()
          .slice(0, 2000);
        transcript += `\nCommand: ${cmd}\nExit code: ${code}\nOutput:\n${clean}\n`;
      }
      if (!completed && !agentAbort) term.write("\r\n\x1b[36m[agent] step limit reached\x1b[0m\r\n");
    } catch (e) {
      aiStatus.textContent = (e as Error).message;
    } finally {
      endAgent();
    }
  }

  aiInput.onkeydown = (e) => {
    if (gateResolve) {
      // permission gate: Enter approves, Esc denies this step
      if (e.key === "Enter") {
        e.preventDefault();
        const r = gateResolve;
        gateResolve = null;
        r(true);
      } else if (e.key === "Escape") {
        e.preventDefault();
        const r = gateResolve;
        gateResolve = null;
        r(false);
      }
      return;
    }
    if (agentRunning) {
      // mid-run (thinking/capturing): Esc aborts, Enter ignored
      if (e.key === "Escape") {
        e.preventDefault();
        abortAgent();
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
      else if (barMode === "agent") runAgent(v);
      else runAi(v);
    }
  };

  // Slash commands: manage AI providers/keys/models. Work with or without a key set.
  const SLASH_HELP =
    "\r\n\x1b[36m/keys\x1b[0m                       list providers, active, which have keys\r\n" +
    "\x1b[36m/key <id> <apikey>\x1b[0m          set a provider's API key\r\n" +
    "\x1b[36m/use <id> [model]\x1b[0m           switch active provider (+ optional model)\r\n" +
    "\x1b[36m/model <model>\x1b[0m              set the active provider's model\r\n" +
    "\x1b[36m/local <id> <url> <model> [key]\x1b[0m  add a local/OpenAI-compatible endpoint\r\n" +
    "\x1b[36m/mcp add <name> <url>\x1b[0m       add a remote MCP server (Streamable HTTP)\r\n" +
    "\x1b[36m/mcp remove <name>\x1b[0m          remove an MCP server\r\n" +
    "\x1b[36m/mcp list\x1b[0m                   list MCP servers and their tools\r\n" +
    "\x1b[90mbuilt-in ids: claude openai groq gemini kimi deepseek mistral\x1b[0m\r\n" +
    "\x1b[90me.g. /local ollama http://localhost:11434/v1 llama3.2\x1b[0m\r\n";

  function printProviders(st: ProviderState) {
    let out = "\r\n\x1b[36m[tachyon] providers\x1b[0m\r\n";
    for (const p of st.providers) {
      const mark = p.id === st.active ? "\x1b[32m●\x1b[0m" : " ";
      const keyed = p.key ? "\x1b[32m✓key\x1b[0m" : p.kind === "anthropic" ? "\x1b[90m—\x1b[0m" : "\x1b[90mno key\x1b[0m";
      out += `${mark} ${p.id.padEnd(9)} ${keyed}  \x1b[90m${p.model}\x1b[0m\r\n`;
    }
    term.write(out);
  }

  async function handleSlash(input: string) {
    const parts = input.slice(1).split(/\s+/).filter(Boolean);
    const cmd = (parts.shift() ?? "").toLowerCase();
    try {
      if (cmd === "help" || cmd === "") {
        term.write(SLASH_HELP);
      } else if (cmd === "keys" || cmd === "providers") {
        printProviders(await invoke<ProviderState>("provider_state"));
      } else if (cmd === "key") {
        const [id, ...rest] = parts;
        if (!id || rest.length === 0) throw new Error("usage: /key <id> <apikey>");
        await invoke("provider_set_key", { id, key: rest.join(" ") });
        term.write(`\r\n\x1b[36m[tachyon] key set for ${id}\x1b[0m\r\n`);
      } else if (cmd === "use") {
        const [id, model] = parts;
        if (!id) throw new Error("usage: /use <id> [model]");
        await invoke("provider_use", { id });
        if (model) await invoke("provider_set_model", { id, model });
        term.write(`\r\n\x1b[36m[tachyon] active provider: ${id}${model ? ` · ${model}` : ""}\x1b[0m\r\n`);
      } else if (cmd === "model") {
        if (parts.length === 0) throw new Error("usage: /model <model>");
        const st = await invoke<ProviderState>("provider_state");
        await invoke("provider_set_model", { id: st.active, model: parts.join(" ") });
        term.write(`\r\n\x1b[36m[tachyon] ${st.active} model: ${parts.join(" ")}\x1b[0m\r\n`);
      } else if (cmd === "local") {
        const [id, baseUrl, model, ...key] = parts;
        if (!id || !baseUrl || !model) throw new Error("usage: /local <id> <base_url> <model> [key]");
        await invoke("provider_add_local", { id, baseUrl, model, key: key.join(" ") });
        term.write(`\r\n\x1b[36m[tachyon] added local provider ${id} → ${baseUrl}\x1b[0m\r\n`);
      } else if (cmd === "mcp") {
        const sub = (parts.shift() ?? "").toLowerCase();
        if (sub === "add") {
          const [name, url] = parts;
          if (!name || !url) throw new Error("usage: /mcp add <name> <url>");
          await invoke("mcp_add", { name, url });
          term.write(`\r\n\x1b[36m[tachyon] mcp server ${name} → ${url}\x1b[0m\r\n`);
        } else if (sub === "remove") {
          const [name] = parts;
          if (!name) throw new Error("usage: /mcp remove <name>");
          await invoke("mcp_remove", { name });
          term.write(`\r\n\x1b[36m[tachyon] removed mcp server ${name}\x1b[0m\r\n`);
        } else if (sub === "list") {
          const servers = await invoke<McpServer[]>("mcp_servers");
          if (servers.length === 0) {
            term.write("\r\n\x1b[36m[tachyon] no mcp servers — /mcp add <name> <url>\x1b[0m\r\n");
          } else {
            let tools: McpServerTool[] = [];
            let toolErr = "";
            try {
              tools = await invoke<McpServerTool[]>("mcp_list_tools");
            } catch (e) {
              toolErr = (e as Error).message ?? String(e);
            }
            let out = "\r\n\x1b[36m[tachyon] mcp servers\x1b[0m\r\n";
            for (const s of servers) {
              out += `  ${s.name.padEnd(12)} \x1b[90m${s.url}\x1b[0m\r\n`;
              for (const t of tools.filter((t) => t.server === s.name)) {
                out += `    \x1b[36m${t.server}.${t.name}\x1b[0m  \x1b[90m${t.description}\x1b[0m\r\n`;
              }
            }
            if (toolErr) out += `\x1b[31m[tachyon] ${toolErr}\x1b[0m\r\n`;
            term.write(out);
          }
        } else {
          throw new Error("usage: /mcp add|remove|list");
        }
      } else {
        throw new Error(`unknown command: /${cmd} — try /help`);
      }
    } catch (e) {
      term.write(`\r\n\x1b[31m[tachyon] ${(e as Error).message}\x1b[0m\r\n`);
    }
    closeAiBar();
  }

  // Error autopsy (⌘E): explain the recent terminal output, printed display-only
  let explaining = false;
  async function explainError() {
    if (explaining) return;
    explaining = true;
    term.write("\r\n\x1b[90m[tachyon] explaining…\x1b[0m");
    try {
      const fb = oscReady ? lastFailedBlock() : null;
      const prompt = fb
        ? `Command: ${fb.command || "(unknown)"}\nExit code: ${fb.exitCode}\nOutput:\n${fb.output.slice(-3000)}`
        : `Recent terminal output:\n${lastTerminalLines()}`;
      const out = await askAi(AI_EXPLAIN, prompt);
      const body = out.trim().replace(/\n/g, "\r\n");
      term.write(`\r\x1b[2K\x1b[36m${body}\x1b[0m\r\n`);
    } catch (e) {
      term.write(`\r\x1b[2K\x1b[31m[tachyon] ${(e as Error).message}\x1b[0m\r\n`);
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
        `<div class="block-card ${blockClass(b.exitCode)}" id="block-${i}">` +
        `<div class="block-stripe"></div><div class="block-body">` +
        `<div class="block-cmd">${escapeHtml(b.command || `command ${i + 1}`)}</div>` +
        `<div class="block-meta">exit ${b.exitCode}${b.durationMs != null ? ` · ${fmtDuration(b.durationMs)}` : ""}</div>` +
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
          `<div class="mm-seg ${blockClass(b.exitCode)}" data-idx="${i}" title="${escapeHtml(b.command || `command ${i + 1}`)}"></div>`,
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
        `$ ${b.command || "(unknown)"}\nexit ${b.exitCode}\nOutput:\n${b.output.slice(0, 2000)}`,
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
          `$ ${b.command || "(command)"} (exit ${b.exitCode})\n${b.output.split("\n").filter(Boolean).slice(0, 2).join("\n")}`,
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
  await listen<string>("pty-output", (e) => {
    const bytes = b64ToBytes(e.payload);
    term.write(bytes); // live output — always first, never gated, never stripped
    const text = dec.decode(bytes, { stream: true });
    feedOsc(text); // OSC 133 scanner works on a decoded copy
    if (!captureResolve) return;
    captureBuf += text;
    const m = captureBuf.match(new RegExp(`__TACHYON_${captureNonce}_(\\d+)__`));
    if (m) {
      const r = captureResolve;
      captureResolve = null;
      r({ output: captureBuf.slice(0, m.index), code: parseInt(m[1], 10) });
    }
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
          pendingTyped = typedLine;
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
      (lb && lb.exitCode !== 0 ? ` ✗ ${lb.exitCode}` : "");
  }

  function scheduleContextRefresh() {
    clearTimeout(ctxTimer);
    ctxTimer = window.setTimeout(refreshContext, 300);
  }
  scheduleContextRefresh();
});
