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
  });

  // AI command bar
  const aiBar = document.getElementById("ai-bar")!;
  const aiInput = document.getElementById("ai-input") as HTMLInputElement;
  const aiStatus = document.getElementById("ai-status")!;
  let aiKey: string | null = null;

  async function openAiBar() {
    aiBar.hidden = false;
    fit.fit();
    aiKey = settings.apiKey ?? (await invoke<string | null>("get_env_api_key"));
    aiStatus.textContent = aiKey ? "" : "Set API key in settings (⌘,)";
    aiInput.focus();
  }

  function closeAiBar() {
    aiBar.hidden = true;
    aiBar.classList.remove("danger");
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

  async function generateCommand(key: string, userMsg: string): Promise<string> {
    if (key.startsWith("gsk_")) {
      const r = await fetch("https://api.groq.com/openai/v1/chat/completions", {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${key}` },
        body: JSON.stringify({
          model: GROQ_MODEL,
          max_tokens: 1024,
          messages: [
            { role: "system", content: AI_SYSTEM },
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
      system: AI_SYSTEM,
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
      const cmd = stripFences(await generateCommand(aiKey, userMsg));
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

  aiInput.onkeydown = (e) => {
    if (e.key === "Escape") closeAiBar();
    if (e.key === "Enter") runAi(aiInput.value.trim());
  };

  // pty bridge
  await listen<number[]>("pty-output", (e) => term.write(new Uint8Array(e.payload)));
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
