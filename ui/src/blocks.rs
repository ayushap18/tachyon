//! Block navigator (⌘B) + session-health minimap (main.ts 504-643). Cards from
//! the journal mirror, newest-first; per-block explain/rerun/copy/expand; a
//! session-summarize header action; and an always-visible minimap rail whose
//! segments open the panel scrolled to the clicked block.

use dioxus::prelude::*;
use serde::Serialize;
use wasm_bindgen_futures::spawn_local;

use crate::app::{AppState, Overlay};
use crate::bridge::{clipboard_write, invoke, WriteArgs};

// AI_EXPLAIN lives Rust-side (lib.rs) behind the `explain_output` command — not duplicated here.
const AI_SUMMARY: &str =
    "Summarize what this terminal session accomplished and flag any failures, \
     in 2-4 sentences. Plain text only, no markdown.";

#[derive(Serialize)]
struct AiArgs {
    system: &'static str,
    user: String,
}

#[derive(Serialize)]
struct ExplainArgs {
    command: String,
    exit_code: i64,
    output: String,
}

fn fmt_duration(ms: f64) -> String {
    if ms < 1000.0 {
        format!("{}ms", ms.round() as i64)
    } else if ms < 60000.0 {
        format!("{:.1}s", ms / 1000.0)
    } else {
        format!("{}s", (ms / 1000.0).round() as i64)
    }
}

fn block_class(code: i32) -> &'static str {
    if code == 0 {
        "ok"
    } else if code < 0 {
        "unk"
    } else {
        "err"
    }
}

/// Ask the native `explain_output` command and stash the reply at the block with this id.
/// Keyed by stable block id (not Vec index) so a journal ring-shift during the async call
/// can't misattribute the reply — main.ts held a direct object reference for the same reason.
fn explain(state: AppState, id: u64) {
    let mut j = state.journal;
    let (cmd, code, out) = {
        let mut w = j.write();
        let Some(b) = w.iter_mut().find(|b| b.id == id) else { return };
        if b.ai_pending {
            return;
        }
        b.ai_pending = true;
        b.ai = Some("thinking…".into());
        (
            b.command.clone(),
            b.exit_code as i64,
            b.output.chars().take(2000).collect::<String>(),
        )
    };
    spawn_local(async move {
        let args = ExplainArgs { command: cmd, exit_code: code, output: out };
        let reply = match invoke("explain_output", args).await {
            Ok(v) => v.as_string().unwrap_or_default(),
            Err(e) => e.as_string().unwrap_or_else(|| "ai error".into()),
        };
        if let Some(b) = j.write().iter_mut().find(|b| b.id == id) {
            b.ai = Some(reply);
            b.ai_pending = false;
        }
    });
}

#[component]
pub fn BlocksPanel() -> Element {
    let state = use_context::<AppState>();
    let journal = state.journal.read().clone();
    let mut summary = use_signal(|| Option::<String>::None);
    // ponytail: no revert timer (no gloo/timer dep) — the label stays "copied"
    // until the next copy. Add a set_timeout closure if the flash matters.
    let mut copied = use_signal(|| Option::<usize>::None);
    let mut scroll_to = use_signal(|| Option::<usize>::None);

    // Scroll the clicked minimap block into view once the panel has rendered.
    use_effect(move || {
        if let Some(i) = *scroll_to.read() {
            if let Some(doc) = web_sys::window().and_then(|w| w.document()) {
                if let Some(el) = doc.get_element_by_id(&format!("block-{i}")) {
                    el.scroll_into_view();
                }
            }
        }
    });

    let is_open = state.is_open(Overlay::Blocks);

    let cards = journal.iter().enumerate().rev().map(|(i, b)| {
        let lines: Vec<&str> = b.output.split('\n').filter(|l| !l.trim().is_empty()).collect();
        let more = lines.len() > 3 || b.output.len() > 4000;
        let preview = if b.expanded {
            b.output.chars().take(4000).collect::<String>()
        } else {
            lines.iter().take(3).copied().collect::<Vec<_>>().join("\n")
        };
        let cmd_disp = if b.command.is_empty() { format!("command {}", i + 1) } else { b.command.clone() };
        let has_cmd = !b.command.trim().is_empty();
        let ai = b.ai.clone();
        let ai_pending = b.ai_pending;
        let expanded = b.expanded;
        let bid = b.id;
        let copied_now = *copied.read() == Some(i);
        rsx! {
            div { class: "block-card {block_class(b.exit_code)}", id: "block-{i}",
                div { class: "block-stripe" }
                div { class: "block-body",
                    div { class: "block-cmd", "{cmd_disp}" }
                    div { class: "block-meta", "exit {b.exit_code} · {fmt_duration(b.duration_ms)}" }
                    if !preview.is_empty() {
                        div { class: "block-out", "{preview}" }
                    }
                    if more {
                        button {
                            class: "block-expand",
                            onclick: move |_| { let mut j = state.journal; if let Some(b) = j.write().get_mut(i) { b.expanded = !b.expanded; }; },
                            if expanded { "▾ collapse" } else { "▸ expand" }
                        }
                    }
                    if let Some(ai) = ai {
                        div { class: "block-ai", "{ai}" }
                    }
                    div { class: "block-actions",
                        button {
                            disabled: ai_pending,
                            onclick: move |_| explain(state, bid),
                            "✦ explain"
                        }
                        button {
                            disabled: !has_cmd,
                            onclick: move |_| {
                                let cmd = state.journal.read().get(i).map(|b| b.command.clone()).unwrap_or_default();
                                let cmd = cmd.replace(['\r', '\n'], " ").trim().to_string();
                                if cmd.is_empty() { return; }
                                state.close();
                                // no trailing newline — prefill only, never auto-execute
                                spawn_local(async move { let _ = invoke("pty_write", WriteArgs { data: cmd }).await; });
                            },
                            "⟳ rerun"
                        }
                        button {
                            onclick: move |_| {
                                let out = state.journal.read().get(i).map(|b| b.output.clone()).unwrap_or_default();
                                clipboard_write(&out);
                                copied.set(Some(i));
                            },
                            if copied_now { "copied" } else { "⎘ copy" }
                        }
                    }
                }
            }
        }
    });

    // Minimap segments in journal order (oldest at top); click opens+scrolls.
    let segs = journal.iter().enumerate().map(|(i, b)| {
        let title = if b.command.is_empty() { format!("command {}", i + 1) } else { b.command.clone() };
        rsx! {
            div {
                class: "mm-seg {block_class(b.exit_code)}",
                title: "{title}",
                onclick: move |_| {
                    let mut ov = state.overlay;
                    ov.set(Overlay::Blocks);
                    scroll_to.set(Some(i));
                },
            }
        }
    });

    let summ = summary.read().clone();

    rsx! {
        if !journal.is_empty() {
            div { id: "minimap", {segs} }
        }
        if is_open {
            // tabindex keeps Esc off the canvas terminal (main.ts openBlocks focus)
            div { id: "blocks", tabindex: "0",
                div { id: "blocks-header",
                    span { id: "blocks-title", "Blocks" }
                    button {
                        id: "blocks-summarize",
                        onclick: move |_| {
                            summary.set(Some("thinking…".into()));
                            let jr = state.journal.read();
                            let start = jr.len().saturating_sub(20);
                            let transcript = jr[start..]
                                .iter()
                                .map(|b| {
                                    let cmd = if b.command.is_empty() { "(command)" } else { &b.command };
                                    let out = b.output.lines().filter(|l| !l.is_empty()).take(2).collect::<Vec<_>>().join("\n");
                                    format!("$ {cmd} (exit {})\n{out}", b.exit_code)
                                })
                                .collect::<Vec<_>>()
                                .join("\n");
                            drop(jr);
                            if transcript.trim().is_empty() {
                                summary.set(Some("nothing to summarize yet".into()));
                                return;
                            }
                            spawn_local(async move {
                                let reply = match invoke("ai_complete", AiArgs { system: AI_SUMMARY, user: transcript }).await {
                                    Ok(v) => v.as_string().unwrap_or_default(),
                                    Err(e) => e.as_string().unwrap_or_else(|| "ai error".into()),
                                };
                                summary.set(Some(reply));
                            });
                        },
                        "✦ summarize session"
                    }
                    button { id: "blocks-close", title: "Close (Esc)", onclick: move |_| state.close(), "×" }
                }
                if let Some(s) = summ {
                    div { id: "blocks-summary", "{s}" }
                }
                div { id: "blocks-list",
                    if journal.is_empty() {
                        div { class: "block-empty", "waiting for shell integration (zsh OSC 133 handshake)…" }
                    }
                    {cards}
                }
            }
        }
    }
}
