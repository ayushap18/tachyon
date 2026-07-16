import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import "@xterm/xterm/css/xterm.css";

window.addEventListener("DOMContentLoaded", async () => {
  const term = new Terminal({
    fontFamily: "Menlo, Monaco, monospace",
    fontSize: 14,
    cursorBlink: true,
    theme: {
      background: "#16161e",
      foreground: "#c0caf5",
      cursor: "#c0caf5",
    },
  });
  const fit = new FitAddon();
  term.loadAddon(fit);
  term.open(document.getElementById("terminal")!);
  fit.fit();
  term.focus();

  await listen<number[]>("pty-output", (e) => term.write(new Uint8Array(e.payload)));
  await listen("pty-exit", () => term.write("\r\n[process exited]\r\n"));
  await invoke("pty_spawn", { rows: term.rows, cols: term.cols });

  term.onData((data) => invoke("pty_write", { data }));
  term.onResize(({ rows, cols }) => invoke("pty_resize", { rows, cols }));
  window.addEventListener("resize", () => fit.fit());
});
