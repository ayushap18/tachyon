//! AI command bar + agent gate (⌘K command / ⌘J agent). Ported from
//! src/main.ts lines 179-385. One panel, two modes, keyed off Overlay::AiBar
//! (command) vs Overlay::Agent, plus the agent approval gate.
//!
//! SECURITY: this component owns the agent approval gate — the trust boundary.
//! A proposal (`agent-propose`) resolves ONLY via an explicit Enter (approve) /
//! Esc (deny) keypress on #ai-input, invoking the decide command. The global keydown
//! handler deliberately never closes AiBar/Agent on Esc. Handled keys call
//! stop_propagation so the terminal's document keydown listener can't also encode
//! them to the PTY (an approval Enter must NOT double as a shell carriage return).
//! This module also owns `state.agent_running` (propose/done drive it).

use dioxus::prelude::*;
use serde::{Deserialize, Serialize};
use wasm_bindgen::JsValue;
use wasm_bindgen_futures::spawn_local;

use crate::app::{AppState, Overlay};
use crate::bridge::{invoke, listen, term_write, NoArgs, WriteArgs};
use crate::complete::{accept_text, list_key, list_open, rows, tab_prefix, wants_models, Ctx, ListOp};

// ---- invoke arg shapes ----
#[derive(Serialize)]
struct RequestArgs {
    request: String,
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
/// one word, so serde's camelCase mapping is a no-op
#[derive(Serialize)]
struct IdArgs {
    id: String,
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
/// PublicProviderState: ids only. `hidden` holds removed built-ins, which `/use` revives.
#[derive(Deserialize)]
struct ProviderList {
    #[serde(default)]
    active: String,
    #[serde(default)]
    providers: Vec<Provider>,
    #[serde(default)]
    hidden: Vec<String>,
}
#[derive(Deserialize)]
struct AgentOutput {
    #[serde(default)]
    text: String,
}
#[derive(Deserialize)]
struct AgentPropose {
    #[serde(default)]
    text: String,
    #[serde(default)]
    danger: bool,
    // true when the proposal came in over Tachyon's MCP server, not from the built-in agent
    #[serde(default)]
    external: bool,
}

/// The gate's status line. The approver must be able to tell a command THEY asked the
/// built-in agent for from one an outside process is asking to run.
fn gate_status(danger: bool, external: bool, is_mac: bool) -> String {
    let who = if external { "external agent · " } else { "" };
    let warn = if danger { "⚠ destructive · " } else { "" };
    // External proposals are UNSOLICITED: the bar takes focus while the user may be typing
    // in their shell, so a plain Enter meant for their own command must never approve one.
    let approve = if !external {
        "⏎"
    } else if is_mac {
        "⌘⏎"
    } else {
        "Ctrl+⏎"
    };
    format!("{who}{warn}run? {approve} approve · esc deny")
}

/// Does this Enter approve the pending proposal? The built-in agent's proposals are
/// solicited (the user just asked for them), so Enter is enough. An external agent's arrive
/// uninvited and steal focus, so they need a deliberate chord.
fn enter_approves(external: bool, meta: bool, ctrl: bool) -> bool {
    !external || meta || ctrl
}

/// Does an agent own the bar (and the pty)? Every async continuation re-checks this after
/// EACH await, not just the first: a proposal or a ⌘J start can land during any IPC round
/// trip, and from then on only the gate branch and agent-done may touch input/status/danger.
fn agent_owns_bar(pending_gate: bool, agent_running: bool) -> bool {
    pending_gate || agent_running
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
    mut sel: Signal<Option<usize>>,
    mut pending_gate: Signal<bool>,
    mut agent_running: Signal<bool>,
) {
    input.set(String::new());
    status.set(String::new());
    danger.set(false);
    sel.set(None);
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
    // highlighted suggestion row. None by default and on every edit, so Enter keeps its
    // submit meaning unless the user deliberately arrowed/tabbed onto a row.
    let mut sel = use_signal(|| None::<usize>);
    // everything the completer may know: ids only, filled on open from two disk reads.
    let mut ctx = use_signal(Ctx::default);
    // one model fetch in flight at a time — Tab repeats must not fan out into N requests.
    let mut models_busy = use_signal(|| false);
    // the input's editability is derived from pending_gate || agent_running at render —
    // never a separate signal, so no code path can leave an armed gate editable.
    let mut pending_gate = use_signal(|| false);
    let mut gate_external = use_signal(|| false);
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
                danger.set(p.danger);
                status.set(gate_status(p.danger, p.external, crate::keymap::is_mac()));
                gate_external.set(p.external);
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
        // agent-output: cyan `[agent] …` narrative (exit codes, MCP tool results). Shell
        // output itself still arrives via the PTY; this is the part that has no other
        // path to the screen, so it is painted display-only via term_write.
        listen("agent-output", move |payload| {
            if let Ok(o) = serde_wasm_bindgen::from_value::<AgentOutput>(payload) {
                if !o.text.is_empty() {
                    term_write(format!("\r\n\x1b[36m[agent] {}\x1b[0m\r\n", o.text));
                }
            }
        });
        // agent-done: finish → clear running flag, close the bar.
        listen("agent-done", move |_| {
            reset_and_close(state, input, status, danger, sel, pending_gate, agent_running);
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
                    let mut status = status;
                    spawn_local(async move {
                        // provider_active now fails loudly on a corrupt providers.json
                        // rather than silently handing back defaults — show that here,
                        // since this bar is where the user looks for provider state.
                        let r = invoke("provider_active", NoArgs {}).await;
                        // a proposal or run may have taken the bar during the round trip —
                        // its status line must not be overwritten
                        if agent_owns_bar(*pending_gate.peek(), *agent_running.peek()) {
                            return;
                        }
                        match r {
                            Ok(v) => {
                                if let Ok(p) = serde_wasm_bindgen::from_value::<Provider>(v) {
                                    let suffix = if p.has_key || p.kind != "anthropic" {
                                        ""
                                    } else {
                                        " · no key"
                                    };
                                    status.set(format!("{} · {}{}", p.id, p.model, suffix));
                                }
                            }
                            Err(e) => status.set(err_str(e)),
                        }
                    });
                    // the component stays mounted across close/open, so the model cache
                    // MUST be cleared here or a stale provider's models outlive their slot
                    ctx.set(Ctx::default());
                    spawn_local(async move {
                        // both are disk reads (load_state / load_mcp): no network on bar
                        // open, and none on a keystroke. Errors are ignored, as in
                        // palette.rs — the status line belongs to the gate, not to this.
                        let mut c = Ctx::default();
                        if let Ok(v) = invoke("provider_state", NoArgs {}).await {
                            if let Ok(ps) = serde_wasm_bindgen::from_value::<ProviderList>(v) {
                                c.active = ps.active;
                                c.providers = ps.providers.into_iter().map(|p| p.id).collect();
                                c.hidden = ps.hidden;
                            }
                        }
                        if let Ok(v) = invoke("mcp_names", NoArgs {}).await {
                            if let Ok(n) = serde_wasm_bindgen::from_value::<Vec<String>>(v) {
                                c.mcp = n;
                            }
                        }
                        ctx.set(c);
                        // the rows under the cursor may have just been replaced by argument
                        // rows: a highlight from before would now point at a different
                        // command, so it is dropped rather than moved. Same rule as the
                        // model fetch below; Enter falls back to submitting.
                        sel.set(None);
                    });
                }
            }
            _ => {
                // ⌘K/⌘P/⌘,/⌘B during a gate or run only HIDES the bar — the proposal
                // text and gate status must survive so reopening shows what Enter approves.
                if !*pending_gate.peek() && !*agent_running.peek() {
                    input.set(String::new());
                    status.set(String::new());
                    danger.set(false);
                }
                // a highlight never survives a hide, gate or not — nothing is at stake in
                // dropping it, and a stale one would steal the next session's Enter
                sel.set(None);
            }
        }
    });

    let overlay = *state.overlay.read();
    if !matches!(overlay, Overlay::AiBar | Overlay::Agent) {
        return rsx! {};
    }
    let agent = overlay == Overlay::Agent;
    // plain values, not guards: a read()/peek() guard alive across a .set panics, and the
    // key branch below writes input/sel
    let rows = rows(&input.read(), &ctx.read());
    let open = list_open(*pending_gate.read(), *agent_running.read(), rows.len());
    let sel_eff = (*sel.read()).filter(|i| *i < rows.len());
    let rows_for_key = rows.clone();
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
                readonly: *pending_gate.read() || *agent_running.read(),
                placeholder: if agent { "Describe a task…" } else { "Describe a command…" },
                onmounted: move |e| {
                    spawn(async move {
                        let _ = e.set_focus(true).await;
                    });
                },
                oninput: move |e| {
                    input.set(e.value());
                    sel.set(None);
                },
                onkeydown: move |e| {
                    let key = e.key().to_string();
                    // Tab must never move focus off #ai-input: it is the only element that
                    // resolves a gate, and a focus-less gate cannot be denied.
                    if key == "Tab" {
                        e.prevent_default();
                    }
                    // IME commit / held key: not a deliberate decision — decide nothing.
                    if e.is_composing() || e.is_auto_repeating() {
                        return;
                    }
                    // ---- approval gate: the ONLY place a proposal resolves ----
                    if *pending_gate.read() {
                        let mods = e.modifiers();
                        if key == "Enter" && !enter_approves(*gate_external.peek(), mods.meta(), mods.ctrl()) {
                            // a stray Enter on an external proposal: swallow it, decide nothing
                            e.prevent_default();
                            e.stop_propagation();
                        } else if key == "Enter" {
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
                    // ---- suggestion list: lexically after both returns above AND
                    // list_open is false under a gate/run — belt and braces. Accept and
                    // Prefix write the input signal only: never the pty, never a submit.
                    if open {
                        let cur = input.peek().clone();
                        match list_key(&key, sel_eff, rows_for_key.len()) {
                            ListOp::Sel(s) => {
                                e.prevent_default();
                                e.stop_propagation();
                                sel.set(s);
                                return;
                            }
                            ListOp::Accept(i) => {
                                e.prevent_default();
                                e.stop_propagation();
                                if let Some(a) = accept_text(&rows_for_key[i].0, &cur) {
                                    input.set(a);
                                }
                                sel.set(None);
                                return;
                            }
                            ListOp::Prefix => {
                                e.prevent_default();
                                e.stop_propagation();
                                // the ONLY network path in this feature, and it is a
                                // deliberate Tab — never a keystroke, never oninput.
                                if let Some(id) = wants_models(&cur, &ctx.peek()) {
                                    if !*models_busy.peek() {
                                        models_busy.set(true);
                                        let prev = status.peek().to_string();
                                        let mine = format!("listing models from {id}…");
                                        status.set(mine.clone());
                                        spawn_local(async move {
                                            let got = invoke("provider_models", IdArgs { id: id.clone() }).await;
                                            let list = got
                                                .ok()
                                                .and_then(|v| serde_wasm_bindgen::from_value::<Vec<String>>(v).ok())
                                                .unwrap_or_default();
                                            ctx.with_mut(|c| c.models = Some((id, list)));
                                            models_busy.set(false);
                                            sel.set(None); // the row count just changed under the user
                                            // a gate or run that began during the round trip
                                            // owns the status line — leave it theirs. So does
                                            // a NEW bar session: `prev` is a provider line
                                            // captured before the close, so restore it only if
                                            // our own "listing…" is still the thing on screen.
                                            if !agent_owns_bar(*pending_gate.peek(), *agent_running.peek())
                                                && *status.peek() == mine
                                            {
                                                status.set(prev);
                                            }
                                        });
                                    }
                                    return;
                                }
                                match tab_prefix(&rows_for_key, &cur) {
                                    Some(p) => {
                                        input.set(p);
                                        sel.set(None);
                                    }
                                    None => sel.set(Some(0)),
                                }
                                return;
                            }
                            ListOp::Pass => {}
                        }
                    }
                    // ---- idle: Esc closes, Enter submits ----
                    if key == "Escape" {
                        e.prevent_default();
                        e.stop_propagation();
                        reset_and_close(state, input, status, danger, sel, pending_gate, agent_running);
                    } else if key == "Enter" {
                        e.prevent_default();
                        e.stop_propagation();
                        let v = input.read().trim().to_string();
                        if v.starts_with('/') {
                            // slash command: run_slash executes in Rust and returns its
                            // already-ANSI-formatted output; paint it on the canvas
                            // (display-only term_write, never the pty). Close the bar.
                            let cmd = v.clone();
                            spawn_local(async move {
                                if let Ok(out) = invoke("run_slash", SlashArgs { input: cmd }).await {
                                    if let Some(text) = out.as_string() {
                                        term_write(text);
                                    }
                                }
                            });
                            reset_and_close(state, input, status, danger, sel, pending_gate, agent_running);
                        } else if agent {
                            if !v.is_empty() && !*agent_running.read() {
                                agent_running.set(true);
                                status.set("starting…".to_string());
                                spawn_local(async move {
                                    if let Err(err) = invoke("agent_start", TaskArgs { task: v }).await {
                                        // an external proposal may have armed the gate meanwhile
                                        if *pending_gate.peek() {
                                            return;
                                        }
                                        // "terminal busy" means the claim went to SOMEONE ELSE,
                                        // who may already be past their gate and writing to the
                                        // pty. Clearing agent_running here would re-open the
                                        // list, un-readonly the input and turn ⌘J back from
                                        // abort into toggle mid-run. Their agent-done resets us.
                                        let msg = err_str(err);
                                        if msg.starts_with("terminal busy") {
                                            return;
                                        }
                                        status.set(msg);
                                        agent_running.set(false);
                                    }
                                });
                            }
                        } else if !v.is_empty() {
                            status.set("thinking…".to_string());
                            danger.set(false);
                            spawn_local(async move {
                                let r = invoke("nl_to_command", RequestArgs { request: v }).await;
                                // a gate or run that began during the round trip owns the bar
                                // and the pty: no prefill, no status overwrite, and above all
                                // no reset_and_close (which would clear agent_running).
                                if agent_owns_bar(*pending_gate.peek(), *agent_running.peek()) {
                                    return;
                                }
                                match r {
                                    Ok(val) => {
                                        if let Ok(nl) = serde_wasm_bindgen::from_value::<NlResult>(val) {
                                            // no trailing newline — never auto-execute.
                                            let _ = invoke("pty_write", WriteArgs { data: nl.command }).await;
                                            // the prefill is a second round trip; same rule again
                                            if agent_owns_bar(*pending_gate.peek(), *agent_running.peek()) {
                                                return;
                                            }
                                            if nl.danger {
                                                danger.set(true);
                                                status.set("⚠ destructive — review carefully".to_string());
                                            } else {
                                                reset_and_close(state, input, status, danger, sel, pending_gate, agent_running);
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
            // keyboard only: no onclick, so the sole way onto a row is an arrow/Tab press
            if open {
                ul { id: "ai-list",
                    for (i, (form, detail)) in rows.into_iter().enumerate() {
                        // a hand-edited providers.json can hold two entries with the same
                        // id, so the row text alone is not a unique key
                        li { key: "{i}-{form}", class: if Some(i) == sel_eff { "sel" } else { "" },
                            span { class: "label", "{form}" }
                            span { class: "hint", "{detail}" }
                        }
                    }
                }
            }
            span { id: "ai-status", "{status}" }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{agent_owns_bar, enter_approves, gate_status};

    #[test]
    fn a_continuation_stands_down_under_a_gate_or_run() {
        assert!(!agent_owns_bar(false, false));
        assert!(agent_owns_bar(true, false)); // armed gate
        assert!(agent_owns_bar(false, true)); // ⌘J started, no proposal yet
        assert!(agent_owns_bar(true, true));
    }

    #[test]
    fn gate_status_names_an_external_requester() {
        assert_eq!(gate_status(false, false, true), "run? ⏎ approve · esc deny");
        assert_eq!(gate_status(true, false, true), "⚠ destructive · run? ⏎ approve · esc deny");
        assert!(gate_status(false, true, true).starts_with("external agent · run? "));
        assert!(gate_status(false, true, true).contains("⌘⏎ approve"));
        assert!(gate_status(false, true, false).contains("Ctrl+⏎ approve"));
        assert!(!gate_status(false, true, false).contains("run? ⏎ approve"), "external must not advertise a bare Enter");
        assert!(gate_status(true, true, true).starts_with("external agent · ⚠ destructive"));
    }

    #[test]
    fn a_bare_enter_never_approves_an_external_proposal() {
        assert!(enter_approves(false, false, false)); // built-in agent: Enter, as before
        assert!(!enter_approves(true, false, false)); // external: the stray Enter decides nothing
        assert!(enter_approves(true, true, false)); // ⌘⏎
        assert!(enter_approves(true, false, true)); // Ctrl+⏎
    }
}
