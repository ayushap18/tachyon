//! AI command bar + agent gate (⌘K command / ⌘J agent). Ported from
//! src/main.ts lines 179-385. One panel, two modes, keyed off Overlay::AiBar
//! (command) vs Overlay::Agent, plus the agent approval gate.
//!
//! SECURITY: this component owns the agent approval gate — the trust boundary.
//! A proposal (`agent-propose`) resolves ONLY via an explicit Enter (approve) /
//! Esc (deny) keypress on #ai-input, invoking `agent_decide`. The global keydown
//! handler deliberately never closes AiBar/Agent on Esc. Handled keys call
//! stop_propagation so the terminal's document keydown listener can't also encode
//! them to the PTY (an approval Enter must NOT double as a shell carriage return).
//! This module also owns `state.agent_running` (propose/done drive it).

use dioxus::prelude::*;
use serde::{Deserialize, Serialize};
use wasm_bindgen::JsValue;
use wasm_bindgen_futures::spawn_local;

use crate::app::{AppState, Overlay};
use crate::bridge::{invoke, listen};

// ---- invoke arg shapes ----
#[derive(Serialize)]
struct NoArgs {}
#[derive(Serialize)]
struct RequestArgs {
    request: String,
}
#[derive(Serialize)]
struct WriteArgs {
    data: String,
}
#[derive(Serialize)]
struct TaskArgs {
    task: String,
}
#[derive(Serialize)]
struct DecideArgs {
    approved: bool,
}
#[derive(Serialize)]
struct SlashArgs {
    input: String,
}

// ---- response / event shapes ----
#[derive(Deserialize)]
struct NlResult {
    #[serde(default)]
    command: String,
    #[serde(default)]
    danger: bool,
}
#[derive(Deserialize)]
struct Provider {
    #[serde(default)]
    id: String,
    #[serde(default)]
    model: String,
    #[serde(default)]
    has_key: bool,
    #[serde(default)]
    kind: String,
}
#[derive(Deserialize)]
struct AgentPropose {
    #[serde(default)]
    text: String,
    #[serde(default)]
    danger: bool,
}
#[derive(Deserialize)]
struct AgentStatus {
    #[serde(default)]
    step: i64,
    #[serde(default)]
    status: String,
}

/// Tauri rejects invoke with the plain Err string as a JS string.
fn err_str(e: JsValue) -> String {
    e.as_string().unwrap_or_else(|| "error".to_string())
}

/// Mirror of closeAiBar() (main.ts 234-248): clear the bar and drop the overlay.
fn reset_and_close(
    state: AppState,
    mut input: Signal<String>,
    mut status: Signal<String>,
    mut danger: Signal<bool>,
    mut readonly: Signal<bool>,
    mut pending_gate: Signal<bool>,
    mut agent_running: Signal<bool>,
) {
    input.set(String::new());
    status.set(String::new());
    danger.set(false);
    readonly.set(false);
    pending_gate.set(false);
    agent_running.set(false);
    state.close();
}

#[component]
pub fn AiBar() -> Element {
    let state = use_context::<AppState>();
    let mut input = use_signal(String::new);
    let mut status = use_signal(String::new);
    let mut danger = use_signal(|| false);
    let mut readonly = use_signal(|| false);
    let mut pending_gate = use_signal(|| false);
    // agent_running is shared state (⌘J abort reads it) — this module owns writes.
    let mut agent_running = state.agent_running;

    // --- register the agent event listeners once (loop lives in Rust) ---
    use_effect(move || {
        // agent-propose: the gate. Open the bar, show the proposed action, arm Enter/Esc.
        listen("agent-propose", move |payload| {
            if let Ok(p) = serde_wasm_bindgen::from_value::<AgentPropose>(payload) {
                agent_running.set(true);
                if !matches!(*state.overlay.read(), Overlay::AiBar | Overlay::Agent) {
                    state.overlay.clone().set(Overlay::Agent);
                }
                input.set(p.text);
                readonly.set(true);
                danger.set(p.danger);
                let prefix = if p.danger { "⚠ destructive · " } else { "" };
                status.set(format!("{prefix}run? ⏎ approve · esc deny"));
                pending_gate.set(true);
            }
        });
        // agent-status: progress line.
        listen("agent-status", move |payload| {
            if let Ok(a) = serde_wasm_bindgen::from_value::<AgentStatus>(payload) {
                status.set(if a.status == "thinking" {
                    format!("thinking… ({}/12)", a.step)
                } else {
                    a.status
                });
            }
        });
        // agent-output: cyan `[agent] …` lines. ponytail: no client→grid write path
        // exists (canvas is painted only from native grid-damage; palette hit the same
        // wall). Deferred to the terminal module; the agent's real shell output still
        // shows via the PTY. Not registered — nothing to render.
        // agent-done: finish → clear running flag, close the bar.
        listen("agent-done", move |_| {
            reset_and_close(state, input, status, danger, readonly, pending_gate, agent_running);
        });
    });

    // --- open/close cosmetic sync (mirrors openAiBar/closeAiBar visible reset) ---
    use_effect(move || {
        match *state.overlay.read() {
            Overlay::AiBar | Overlay::Agent => {
                // Fresh user open: reset + show active provider. A live gate/run
                // (bar opened by agent-propose) keeps its own status/input — skip.
                if !*pending_gate.peek() && !*agent_running.peek() {
                    input.set(String::new());
                    danger.set(false);
                    readonly.set(false);
                    let mut status = status;
                    spawn_local(async move {
                        if let Ok(v) = invoke("provider_active", NoArgs {}).await {
                            if let Ok(p) = serde_wasm_bindgen::from_value::<Provider>(v) {
                                let suffix = if p.has_key || p.kind != "anthropic" {
                                    ""
                                } else {
                                    " · no key"
                                };
                                status.set(format!("{} · {}{}", p.id, p.model, suffix));
                            }
                        }
                    });
                }
            }
            _ => {
                input.set(String::new());
                status.set(String::new());
                danger.set(false);
                readonly.set(false);
            }
        }
    });

    let overlay = *state.overlay.read();
    if !matches!(overlay, Overlay::AiBar | Overlay::Agent) {
        return rsx! {};
    }
    let agent = overlay == Overlay::Agent;
    let class = match (agent, *danger.read()) {
        (true, true) => "agent danger",
        (true, false) => "agent",
        (false, true) => "danger",
        (false, false) => "",
    };

    rsx! {
        div { id: "ai-bar", class,
            span { id: "ai-icon", if agent { "⚡" } else { "✦" } }
            input {
                id: "ai-input",
                value: "{input}",
                readonly: readonly(),
                placeholder: if agent { "Describe a task…" } else { "Describe a command…" },
                onmounted: move |e| {
                    spawn(async move {
                        let _ = e.set_focus(true).await;
                    });
                },
                oninput: move |e| input.set(e.value()),
                onkeydown: move |e| {
                    let key = e.key().to_string();
                    // ---- approval gate: the ONLY place a proposal resolves ----
                    if *pending_gate.read() {
                        if key == "Enter" {
                            e.prevent_default();
                            e.stop_propagation();
                            pending_gate.set(false);
                            danger.set(false);
                            spawn_local(async move {
                                let _ = invoke("agent_decide", DecideArgs { approved: true }).await;
                            });
                        } else if key == "Escape" {
                            e.prevent_default();
                            e.stop_propagation();
                            pending_gate.set(false);
                            danger.set(false);
                            spawn_local(async move {
                                let _ = invoke("agent_decide", DecideArgs { approved: false }).await;
                            });
                        }
                        return;
                    }
                    // ---- mid-run: Esc aborts, Enter ignored ----
                    if *agent_running.read() {
                        if key == "Escape" {
                            e.prevent_default();
                            e.stop_propagation();
                            spawn_local(async move {
                                let _ = invoke("agent_abort", NoArgs {}).await;
                            });
                        }
                        return;
                    }
                    // ---- idle: Esc closes, Enter submits ----
                    if key == "Escape" {
                        e.prevent_default();
                        e.stop_propagation();
                        reset_and_close(state, input, status, danger, readonly, pending_gate, agent_running);
                    } else if key == "Enter" {
                        e.prevent_default();
                        e.stop_propagation();
                        let v = input.read().trim().to_string();
                        if v.starts_with('/') {
                            // slash command: run_slash executes in Rust; result print
                            // is a term-write (deferred, see above). Close the bar.
                            let cmd = v.clone();
                            spawn_local(async move {
                                let _ = invoke("run_slash", SlashArgs { input: cmd }).await;
                            });
                            reset_and_close(state, input, status, danger, readonly, pending_gate, agent_running);
                        } else if agent {
                            if !v.is_empty() && !*agent_running.read() {
                                agent_running.set(true);
                                readonly.set(true);
                                status.set("starting…".to_string());
                                spawn_local(async move {
                                    if let Err(err) = invoke("agent_start", TaskArgs { task: v }).await {
                                        status.set(err_str(err));
                                        agent_running.set(false);
                                        readonly.set(false);
                                    }
                                });
                            }
                        } else if !v.is_empty() {
                            status.set("thinking…".to_string());
                            danger.set(false);
                            spawn_local(async move {
                                match invoke("nl_to_command", RequestArgs { request: v }).await {
                                    Ok(val) => {
                                        if let Ok(nl) = serde_wasm_bindgen::from_value::<NlResult>(val) {
                                            // no trailing newline — never auto-execute.
                                            let _ = invoke("pty_write", WriteArgs { data: nl.command }).await;
                                            if nl.danger {
                                                danger.set(true);
                                                status.set("⚠ destructive — review carefully".to_string());
                                            } else {
                                                reset_and_close(state, input, status, danger, readonly, pending_gate, agent_running);
                                            }
                                        }
                                    }
                                    Err(err) => status.set(err_str(err)),
                                }
                            });
                        }
                    }
                },
            }
            span { id: "ai-status", "{status}" }
        }
    }
}
