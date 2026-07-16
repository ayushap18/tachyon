import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { homeDir } from "@tauri-apps/api/path";
import { Terminal, type ITheme } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import Anthropic from "@anthropic-ai/sdk";
import "@xterm/xterm/css/xterm.css";

const AI_MODEL = "claude-opus-4-8";
const GROQ_MODEL = "llama-3.3-70b-versatile";
const AI_SYSTEM =
  "You translate natural-language requests into a single shell command for zsh on macOS. " +
  "Output ONLY the command — no markdown fences, no explanation, no commentary.";
const AI_EXPLAIN =
  "You are a terminal assistant. Given recent terminal output, explain the most recent error " +
  "or failure in 1-3 short sentences and suggest a fix. If there is no error, say so briefly. " +
  "Plain text only, no markdown.";
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

const FONTS = ["Menlo", "Monaco", "SF Mono", "Courier New", "JetBrains Mono", "Fira Code"];

interface Settings {
  theme: string;
  font: string;
  size: number;
  apiKey?: string;
}

interface ShellContext {
  cwd: string | null;
  branch: string | null;
  dirty: number;
  shell_pid: number | null;
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
    term.options.theme = theme;
    term.options.fontFamily = `"${settings.font}", monospace`;
    term.options.fontSize = settings.size;
    document.body.style.background = theme.background!;
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
  const keyInput = document.getElementById("api-key") as HTMLInputElement;

  themeSel.innerHTML = Object.keys(THEMES)
    .map((t) => `<option${t === settings.theme ? " selected" : ""}>${t}</option>`)
    .join("");
  fontSel.innerHTML = FONTS.map(
    (f) => `<option${f === settings.font ? " selected" : ""}>${f}</option>`,
  ).join("");
  sizeInput.value = String(settings.size);
  keyInput.value = settings.apiKey ?? "";

  themeSel.onchange = () => ((settings.theme = themeSel.value), applySettings());
  fontSel.onchange = () => ((settings.font = fontSel.value), applySettings());
  keyInput.onchange = () => ((settings.apiKey = keyInput.value.trim() || undefined), applySettings());
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
  });

  // AI command bar
  const aiBar = document.getElementById("ai-bar")!;
  const aiInput = document.getElementById("ai-input") as HTMLInputElement;
  const aiStatus = document.getElementById("ai-status")!;
  const aiIcon = document.getElementById("ai-icon")!;
  let aiKey: string | null = null;

  // agent mode state
  let barMode: "command" | "agent" = "command";
  let agentRunning = false;
  let agentAbort = false;
  let gateResolve: ((approved: boolean) => void) | null = null;
  let captureResolve: ((r: { output: string; code: number }) => void) | null = null;
  let captureBuf = "";
  let captureNonce = "";
  const dec = new TextDecoder();

  async function openAiBar() {
    aiBar.hidden = false;
    fit.fit();
    aiKey = settings.apiKey ?? (await invoke<string | null>("get_env_api_key"));
    aiStatus.textContent = aiKey ? "" : "Set API key in settings (⌘,)";
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

  async function askAi(key: string, system: string, userMsg: string): Promise<string> {
    if (key.startsWith("gsk_")) {
      const r = await fetch("https://api.groq.com/openai/v1/chat/completions", {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${key}` },
        body: JSON.stringify({
          model: GROQ_MODEL,
          max_tokens: 1024,
          messages: [
            { role: "system", content: system },
            { role: "user", content: userMsg },
          ],
        }),
      });
      if (!r.ok) throw new Error(`Groq ${r.status}: ${(await r.text()).slice(0, 120)}`);
      return (await r.json()).choices?.[0]?.message?.content ?? "";
    }
    const client = new Anthropic({ apiKey: key, dangerouslyAllowBrowser: true });
    const msg = await client.messages.create({
      model: AI_MODEL,
      max_tokens: 1024,
      system,
      messages: [{ role: "user", content: userMsg }],
    });
    const block = msg.content.find((b) => b.type === "text");
    return block?.type === "text" ? block.text : "";
  }

  function stripFences(s: string): string {
    return s
      .trim()
      .replace(/^```[a-z]*\s*/i, "")
      .replace(/```$/, "")
      .trim();
  }

  async function runAi(request: string) {
    if (!aiKey || !request) return;
    aiStatus.textContent = "thinking…";
    aiBar.classList.remove("danger");
    try {
      const ctx = await invoke<ShellContext>("get_context");
      const userMsg =
        `${request}\n\nContext:\ncwd: ${ctx.cwd ?? "unknown"}\n` +
        `git: ${ctx.branch ? `${ctx.branch}${ctx.dirty > 0 ? ` (${ctx.dirty} dirty)` : ""}` : "none"}\n` +
        `Recent terminal output:\n${lastTerminalLines()}`;
      const cmd = stripFences(await askAi(aiKey, AI_SYSTEM, userMsg));
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
    if (!aiKey || !task || agentRunning) return;
    agentRunning = true;
    agentAbort = false;
    aiInput.readOnly = true;
    let completed = false;
    try {
      const ctx = await invoke<ShellContext>("get_context");
      let transcript =
        `Task: ${task}\n\nContext:\ncwd: ${ctx.cwd ?? "unknown"}\n` +
        `git: ${ctx.branch ? `${ctx.branch}${ctx.dirty > 0 ? ` (${ctx.dirty} dirty)` : ""}` : "none"}\n` +
        `Recent terminal output:\n${lastTerminalLines(20)}\n`;
      for (let step = 1; step <= 12; step++) {
        if (agentAbort) break;
        aiStatus.textContent = `thinking… (${step}/12)`;
        const reply = (await askAi(aiKey, AI_AGENT, transcript)).trim();
        if (agentAbort) break;
        if (/^DONE:/i.test(reply)) {
          term.write(`\r\n\x1b[36m[agent] ${reply.replace(/^DONE:/i, "").trim()}\x1b[0m\r\n`);
          completed = true;
          break;
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
      barMode === "agent" ? runAgent(v) : runAi(v);
    }
  };

  // Error autopsy (⌘E): explain the recent terminal output, printed display-only
  let explaining = false;
  async function explainError() {
    if (explaining) return;
    const key = settings.apiKey ?? (await invoke<string | null>("get_env_api_key"));
    if (!key) {
      term.write("\r\n\x1b[90m[tachyon] set an API key in settings (⌘,) to use ⌘E\x1b[0m\r\n");
      return;
    }
    explaining = true;
    term.write("\r\n\x1b[90m[tachyon] explaining…\x1b[0m");
    try {
      const out = await askAi(key, AI_EXPLAIN, `Recent terminal output:\n${lastTerminalLines()}`);
      const body = out.trim().replace(/\n/g, "\r\n");
      term.write(`\r\x1b[2K\x1b[36m${body}\x1b[0m\r\n`);
    } catch (e) {
      term.write(`\r\x1b[2K\x1b[31m[tachyon] ${(e as Error).message}\x1b[0m\r\n`);
    } finally {
      explaining = false;
    }
  }

  // pty bridge
  await listen<number[]>("pty-output", (e) => {
    const bytes = new Uint8Array(e.payload);
    term.write(bytes); // live output — always first, never gated
    if (!captureResolve) return;
    captureBuf += dec.decode(bytes, { stream: true });
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
    if (data.includes("\r")) scheduleContextRefresh();
  });
  term.onResize(({ rows, cols }) => invoke("pty_resize", { rows, cols }));
  window.addEventListener("resize", () => fit.fit());

  // status bar
  const statusCwd = document.getElementById("status-cwd")!;
  const statusGit = document.getElementById("status-git")!;
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
    statusGit.textContent = ctx.branch
      ? `⎇ ${ctx.branch}${ctx.dirty > 0 ? ` ±${ctx.dirty}` : ""}`
      : "";
  }

  function scheduleContextRefresh() {
    clearTimeout(ctxTimer);
    ctxTimer = window.setTimeout(refreshContext, 300);
  }
  scheduleContextRefresh();
});
