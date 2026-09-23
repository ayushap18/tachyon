//! AI command bar + agent gate (⌘K command / ⌘J agent). One panel, two modes,
//! keyed off Overlay::AiBar (command) vs Overlay::Agent, plus the agent approval
//! gate.
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
use crate::bridge::{invoke, listen, term_write, IdArgs, NoArgs, WriteArgs};
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
/// `hub_state` carries more than this (scopes, has_token, worktree, last_seen, the pending
/// proposal); naming only `name` is what keeps the rest out of the completer's state. There
/// is deliberately no field a token could land in — the command does not send one.
#[derive(Deserialize)]
struct HubState {
    #[serde(default)]
    agents: Vec<HubAgent>,
}
#[derive(Deserialize)]
struct HubAgent {
    #[serde(default)]
    name: String,
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
    /// Which registered agent asked, derived server-side from its bearer token alone. Empty
    /// for the built-in agent — and for an external proposal that is why it is refused.
    #[serde(default)]
    agent: String,
    /// The record an external proposal lives under. None for the built-in agent, whose
    /// payload never carried one.
    #[serde(default)]
    proposal_id: Option<String>,
}
/// `agent-done`. Only the id is read: it is what says WHICH bar this done may clear.
#[derive(Deserialize)]
struct AgentDone {
    #[serde(default)]
    proposal_id: Option<String>,
}

/// Mirrors `MAX_COMMAND_CHARS` in src-tauri/src/mcp_server.rs — ui is outside that
/// workspace, so nothing links the two and a test below compares the source text.
const MAX_COMMAND_CHARS: usize = 4096;

/// The pending command, for the read-only block above the bar. Verbatim: this is the exact
/// string the pty will be given (`one_line` has already folded it, `; ` and all), so
/// re-splitting or prettifying it here would show the approver something else.
///
/// Capped because the built-in agent's proposals come from a model and are bounded by
/// nothing — the MCP path refuses a longer `command` outright. The cut is stated in the
/// block, since what runs is still the whole thing.
fn proposal_block(text: &str) -> String {
    match text.char_indices().nth(MAX_COMMAND_CHARS) {
        None => text.to_string(),
        Some((i, _)) => format!("{}\n… cut at {MAX_COMMAND_CHARS} characters — the rest runs unseen", &text[..i]),
    }
}

/// May this proposal be approved at all? An external proposal is approved on the strength of
/// WHO is asking, so one that names nobody cannot be: it is shown for denial only. Fail
/// closed, the same posture as agent_propose's `rx.await.unwrap_or(false)`.
fn approvable(external: bool, agent: &str) -> bool {
    !external || !agent.is_empty()
}

/// The gate's status line. The approver must be able to tell a command THEY asked the
/// built-in agent for from one an outside process is asking to run — and, among outside
/// processes, WHICH one.
fn gate_status(danger: bool, external: bool, agent: &str, is_mac: bool) -> String {
    let warn = if danger { "⚠ destructive · " } else { "" };
    if !approvable(external, agent) {
        // No affordance to approve is offered, because there is none: the key handler
        // swallows Enter for this proposal however it is chorded.
        return format!("unidentified agent · {warn}cannot approve · esc deny");
    }
    let who = if external { format!("{agent} · ") } else { String::new() };
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

/// May this `agent-done` clear the bar? Only if it is for the proposal the bar shows. With
/// turns, one agent's done can land after the next agent's proposal is already up, and must
/// not wipe it. The built-in agent names no proposal on either event, so None == None.
fn done_clears(owner: Option<&str>, done: Option<&str>) -> bool {
    owner == done
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

/// Clear the bar and drop the overlay.
#[allow(clippy::too_many_arguments)] // one per bar signal: they are cleared together or not at all
fn reset_and_close(
    state: AppState,
    mut input: Signal<String>,
    mut status: Signal<String>,
    mut danger: Signal<bool>,
    mut sel: Signal<Option<usize>>,
    mut pending_gate: Signal<bool>,
    mut agent_running: Signal<bool>,
    mut gate_owner: Signal<Option<String>>,
) {
    input.set(String::new());
    status.set(String::new());
    danger.set(false);
    sel.set(None);
    pending_gate.set(false);
    agent_running.set(false);
    gate_owner.set(None);
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
    // The proposal the bar is showing (or running), so only ITS agent-done clears it.
    let mut gate_owner = use_signal(|| None::<String>);
    // Decided when the proposal lands, from the payload that named (or failed to name) the
    // agent — so the key handler cannot approve one the status line called unidentified.
    let mut gate_approvable = use_signal(|| false);
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
                status.set(gate_status(p.danger, p.external, &p.agent, crate::keymap::is_mac()));
                gate_external.set(p.external);
                gate_owner.set(p.proposal_id);
                gate_approvable.set(approvable(p.external, &p.agent));
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
        // agent-done: finish → clear running flag, close the bar — if the done is this bar's.
        listen("agent-done", move |payload| {
            let done = serde_wasm_bindgen::from_value::<AgentDone>(payload).map(|d| d.proposal_id).unwrap_or_default();
            if done_clears(gate_owner.peek().as_deref(), done.as_deref()) {
                reset_and_close(state, input, status, danger, sel, pending_gate, agent_running, gate_owner);
            }
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
                        // Names only, for `/mcp agent show|revoke <Tab>`. Same disk read as
                        // the two above, and the only reason the webview asks for the hub at
                        // all — there is no command that would hand it a token.
                        if let Ok(v) = invoke("hub_state", NoArgs {}).await {
                            if let Ok(h) = serde_wasm_bindgen::from_value::<HubState>(v) {
                                c.agents = h.agents.into_iter().map(|a| a.name).collect();
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
    let gate = *pending_gate.read();
    // Under a gate the command belongs to the block above the bar, which shows it whole and
    // wrapped. The <input> is then a focus holder only: leaving the text in it too would
    // paint a second copy of the same command clipped to its first line's worth.
    let (typed, proposal) = if gate {
        (String::new(), proposal_block(&input.read()))
    } else {
        (input.read().clone(), String::new())
    };
    let open = list_open(gate, *agent_running.read(), rows.len());
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
                value: "{typed}",
                readonly: *pending_gate.read() || *agent_running.read(),
                // no placeholder under a gate: an empty input inviting a description would
                // be an affordance to type where the only keys that do anything are ⏎/esc.
                placeholder: if gate {
                    ""
                } else if agent {
                    "Describe a task…"
                } else {
                    "Describe a command…"
                },
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
                        if key == "Enter"
                            && !(*gate_approvable.peek()
                                && enter_approves(*gate_external.peek(), mods.meta(), mods.ctrl()))
                        {
                            // a stray Enter on an external proposal, or any Enter on one that
                            // named no agent: swallow it, decide nothing
                            e.prevent_default();
                            e.stop_propagation();
                        } else if key == "Enter" {
                            e.prevent_default();
                            e.stop_propagation();
                            pending_gate.set(false);
                            danger.set(false);
                            // the approve line would otherwise stay up while the command runs;
                            // an external run sends no agent-status to replace it
                            status.set("running…".to_string());
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
                        reset_and_close(state, input, status, danger, sel, pending_gate, agent_running, gate_owner);
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
                            reset_and_close(state, input, status, danger, sel, pending_gate, agent_running, gate_owner);
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
                                                reset_and_close(state, input, status, danger, sel, pending_gate, agent_running, gate_owner);
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
            // The proposal, in full, above the bar. A <pre> with no handlers and no
            // contenteditable: it is a thing to read, and every key still reaches #ai-input,
            // which keeps focus. Never shares the space with #ai-list — list_open is false
            // while a gate is pending.
            if gate {
                pre { id: "ai-proposal", "{proposal}" }
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
    use super::{agent_owns_bar, approvable, done_clears, enter_approves, gate_status, proposal_block, MAX_COMMAND_CHARS};

    #[test]
    fn a_continuation_stands_down_under_a_gate_or_run() {
        assert!(!agent_owns_bar(false, false));
        assert!(agent_owns_bar(true, false)); // armed gate
        assert!(agent_owns_bar(false, true)); // ⌘J started, no proposal yet
        assert!(agent_owns_bar(true, true));
    }

    /// A done clears only the bar of the proposal it is for. With turns, agent A's done can
    /// land after agent B's proposal is already on screen; clearing it would take down a gate
    /// the human is reading and hand the input back mid-decision.
    #[test]
    fn a_done_clears_only_its_own_proposal() {
        assert!(done_clears(Some("p_1"), Some("p_1")));
        assert!(!done_clears(Some("p_2"), Some("p_1")), "a late done for p_1 cleared p_2's bar");
        // the built-in agent names no proposal on either event
        assert!(done_clears(None, None));
        // ...so neither side can clear the other's bar
        assert!(!done_clears(Some("p_2"), None), "⌘J's done cleared an external proposal");
        assert!(!done_clears(None, Some("p_1")), "a late external done cleared a ⌘J run");
    }

    #[test]
    fn gate_status_names_an_external_requester() {
        // the built-in agent (⌘J) is untouched: no name, plain Enter
        assert_eq!(gate_status(false, false, "", true), "run? ⏎ approve · esc deny");
        assert_eq!(gate_status(true, false, "", true), "⚠ destructive · run? ⏎ approve · esc deny");
        assert_eq!(gate_status(false, true, "codex", true), "codex · run? ⌘⏎ approve · esc deny");
        assert!(gate_status(false, true, "codex", false).contains("Ctrl+⏎ approve"));
        assert!(
            !gate_status(false, true, "codex", false).contains("run? ⏎ approve"),
            "external must not advertise a bare Enter"
        );
        assert!(gate_status(true, true, "codex", true).starts_with("codex · ⚠ destructive"));
    }

    /// Approving an external proposal is a judgement about WHO asked. A payload that names
    /// nobody (an older backend, a field lost in transit) cannot be judged, so the bar shows
    /// it for denial only — and says so, rather than offering a chord that decides nothing.
    #[test]
    fn an_unidentified_external_proposal_is_not_approvable() {
        assert!(!approvable(true, ""));
        assert!(approvable(true, "codex"));
        assert!(approvable(false, ""), "the built-in agent has no registry name and never did");

        let line = gate_status(false, true, "", true);
        assert!(line.starts_with("unidentified agent · "), "{line}");
        // no key is offered that would approve it — not ⏎, not the chord
        assert!(!line.contains('⏎'), "{line}");
        assert!(line.contains("cannot approve") && line.ends_with("esc deny"), "{line}");
        assert!(gate_status(true, true, "", true).contains("⚠ destructive"));
    }

    #[test]
    fn a_bare_enter_never_approves_an_external_proposal() {
        assert!(enter_approves(false, false, false)); // built-in agent: Enter, as before
        assert!(!enter_approves(true, false, false)); // external: the stray Enter decides nothing
        assert!(enter_approves(true, true, false)); // ⌘⏎
        assert!(enter_approves(true, false, true)); // Ctrl+⏎
    }

    /// `enter_approves` is the chord rule itself: M1 puts an agent name in the bar and a
    /// second condition in front of this call, and neither may quietly relax it. Pinned by
    /// source text, the way lib.rs pins the approval gate's own lines.
    #[test]
    fn the_chord_rule_is_byte_identical() {
        // The production half only: include_str! reads this test too, and a needle written
        // whole would match its own source line and pass however the bar actually behaves.
        let src = include_str!("ai_bar.rs").split("#[cfg(test)]").next().expect("the file is not empty");
        let needle = concat!(
            "fn enter_approves(external: bool, meta: bool, ctrl: bool) -> bool {\n",
            "    !external || meta || ctrl\n",
            "}",
        );
        assert!(src.contains(needle), "enter_approves changed");
        // ...and the gate branch still asks BOTH questions before deciding anything: the chord,
        // and whether this proposal named an agent at all. Dropping either half approves a
        // command the status line is at the same moment calling unapprovable.
        assert!(
            src.contains("!(*gate_approvable.peek()\n                                && enter_approves(*gate_external.peek(), mods.meta(), mods.ctrl()))"),
            "the gate branch no longer requires both the chord and an identified agent"
        );
    }

    /// What is shown is what runs. `one_line` has already folded the command, so the block
    /// must hand the string on untouched — and when it cannot show all of it, say so
    /// instead of letting the tail run unseen (the whole point of the block).
    #[test]
    fn the_proposal_block_shows_the_command_verbatim_or_says_it_cut_it() {
        assert_eq!(proposal_block("rm -rf /tmp/x; echo done"), "rm -rf /tmp/x; echo done");
        assert_eq!(proposal_block(""), "");
        // a line break can only reach here from a future backend, but pre-wrap renders it
        assert_eq!(proposal_block("a\nb"), "a\nb");
        assert_eq!(proposal_block(&"x".repeat(MAX_COMMAND_CHARS)), "x".repeat(MAX_COMMAND_CHARS));

        let long = "y".repeat(MAX_COMMAND_CHARS + 1);
        let cut = proposal_block(&long);
        let (head, tail) = cut.split_once('\n').expect("a cut block must carry its notice");
        assert_eq!(head, "y".repeat(MAX_COMMAND_CHARS));
        assert!(tail.contains("cut at 4096 characters") && tail.contains("runs unseen"), "{tail}");

        // the cap counts characters, and the cut must not land inside one
        let wide = "é".repeat(MAX_COMMAND_CHARS + 5);
        assert!(proposal_block(&wide).starts_with(&"é".repeat(MAX_COMMAND_CHARS)));
        assert_eq!(proposal_block(&wide).chars().filter(|c| *c == 'é').count(), MAX_COMMAND_CHARS);
    }

    /// The block is a thing to READ: no handler, no contenteditable, nothing that could turn
    /// the text the user is judging into text they (or a script) edited first. And it must
    /// not be able to take focus from #ai-input, which is the only element that can deny.
    #[test]
    fn the_proposal_block_is_read_only() {
        let src = include_str!("ai_bar.rs");
        let at = src.find(r#"pre { id: "ai-proposal""#).expect("the proposal block is gone");
        let el = &src[at..][..src[at..].find('\n').unwrap()];
        for forbidden in ["contenteditable", "oninput", "onkeydown", "tabindex", "onclick"] {
            assert!(!el.contains(forbidden), "{forbidden} on the proposal block: {el}");
        }
        // it renders the capped text, never the raw signal — and while it is up, #ai-input
        // renders nothing, so there is exactly one copy of the command on screen. Needles
        // are joined from fragments: include_str! reads this test too, and a whole one
        // would match itself and pass however the bar actually renders.
        assert!(el.contains("\"{proposal}\""), "{el}");
        for needle in [["let (", "typed, proposal) = if gate {"].concat(), ["value: \"{", "typed}\""].concat()] {
            assert!(src.contains(&needle), "the gate no longer owns what #ai-input shows: {needle}");
        }
    }

    /// The cap mirrors a const in the other crate (ui is outside that workspace, so nothing
    /// links them). Same trick as complete.rs's `surfaces_agree_with_the_backend`.
    #[test]
    fn the_cap_agrees_with_the_backend() {
        const MCP: &str = include_str!("../../src-tauri/src/mcp_server.rs");
        let decl = MCP
            .split_once("const MAX_COMMAND_CHARS: usize = ")
            .expect("MAX_COMMAND_CHARS is gone from mcp_server.rs")
            .1;
        let n: usize = decl.split(';').next().unwrap().trim().parse().unwrap();
        assert_eq!(n, MAX_COMMAND_CHARS, "the block's cap and the server's have drifted");
    }
}
