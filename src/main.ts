import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { homeDir } from "@tauri-apps/api/path";
import { Terminal, type ITheme } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import Anthropic from "@anthropic-ai/sdk";
import "@xterm/xterm/css/xterm.css";

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
        `Recent terminal output:\n${lastTerminalLines()}`;
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
        `Recent terminal output:\n${lastTerminalLines(20)}\n`;
      for (let step = 1; step <= 12; step++) {
        if (agentAbort) break;
        aiStatus.textContent = `thinking… (${step}/12)`;
        const reply = (await askAi(AI_AGENT, transcript)).trim();
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
      const out = await askAi(AI_EXPLAIN, `Recent terminal output:\n${lastTerminalLines()}`);
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
