//! ⌘K suggestion rows and the list's key verdicts — pure functions only.
//!
//! No UI, DOM or signal imports at all (the §5 grep enforces it): the bar owns state, this
//! module only answers "which rows", "what text does accepting produce" and "what does
//! this key mean to the list". That is what makes it host-testable like keymap.rs, and
//! it is why `list_open` lives here — render, the oninput-derived rows and the keydown
//! branch must all consume the SAME visibility predicate, or the list can be acted on
//! while an approval gate owns the bar.
//!
//! Matching is prefix-only, never subsequence: `/mo` must not offer `/mcp remove`, and a
//! subsequence match would also shrink Tab's common prefix to uselessness.

// ponytail: blanket allow because nothing outside the tests calls this yet — drop it the
// moment ai_bar.rs wires the list up, or a genuinely dead helper here goes unnoticed.
#![allow(dead_code)]

/// KEEP IN SYNC BY HAND with SLASH_HELP, src-tauri/src/lib.rs:1635-1649 — separate
/// crates (ui is deliberately outside the src-tauri workspace), so no test can compare
/// them. Drift shows up as a row missing from the list, never as a wrong command.
pub const SLASH_ROWS: [(&str, &str); 16] = [
    ("/keys", "list providers, active, key source"),
    ("/key <id> <apikey>", "set a provider's API key"),
    ("/use <id> [model]", "switch active provider (+ optional model)"),
    ("/model <model>", "set the active provider's model"),
    ("/models [id]", "list the models a provider actually serves"),
    ("/local", "find local runtimes: ollama lmstudio llamacpp vllm jan"),
    ("/local <id> [model]", "register a discovered runtime"),
    ("/local <id> <url> <model> [key]", "add any OpenAI-compatible endpoint"),
    ("/url <id> <base_url>", "point a provider at a proxy/gateway"),
    ("/remove <id>", "remove a provider"),
    ("/mcp add <name> <url>", "add a remote MCP server"),
    ("/mcp add <name> -- <cmd> [args]", "add a local MCP server (Tachyon will run <cmd>)"),
    ("/mcp remove <name>", "remove an MCP server"),
    ("/mcp list", "list MCP servers and their tools"),
    ("/mcp serve on|off|status", "let external agents use this terminal"),
    ("/help", "this list"),
];

/// The literal part of a form: everything before the first placeholder token (one holding
/// `<`, `[` or `|`). "/mcp add <name> -- <cmd> [args]" → "/mcp add".
pub fn fixed_prefix(form: &str) -> &str {
    let cut = form
        .split(' ')
        .scan(0usize, |off, t| {
            let start = *off;
            *off += t.len() + 1;
            Some((start, t))
        })
        .find(|(_, t)| t.contains(['<', '[', '|']))
        .map_or(form.len(), |(start, _)| start);
    form[..cut].trim()
}

/// Has the typed text already reached (or passed) this form's literal part? Used both to
/// keep a row listed while its arguments are being typed and to refuse to re-accept it.
fn at_or_past(t: &str, fixed: &str) -> bool {
    t == fixed || t.strip_prefix(fixed).is_some_and(|rest| rest.starts_with(' '))
}

/// Rows for the current input, in table order. Empty unless the input starts with '/'.
pub fn slash_rows(input: &str) -> Vec<(&'static str, &'static str)> {
    let t = input.trim_start().to_lowercase();
    if !t.starts_with('/') {
        return Vec::new();
    }
    SLASH_ROWS
        .iter()
        .copied()
        .filter(|(form, _)| form.starts_with(&t) || at_or_past(&t, fixed_prefix(form)))
        .collect()
}

/// Text that accepting `form` should put in the bar, or None when the user has already
/// typed past its literal part — accepting must never delete arguments they typed.
/// A form with placeholders gets a trailing space so the next token can just be typed.
pub fn accept_text(form: &str, input: &str) -> Option<String> {
    let t = input.trim_start().to_lowercase();
    let fixed = fixed_prefix(form);
    if at_or_past(&t, fixed) {
        return None;
    }
    Some(if fixed.len() < form.len() { format!("{fixed} ") } else { fixed.to_string() })
}

/// Longest literal prefix shared by every row — Tab's completion. None unless it is
/// strictly longer than what is typed, so Tab can only ever extend the input.
pub fn tab_prefix(rows: &[(&str, &str)], input: &str) -> Option<String> {
    let t = input.trim_start().to_lowercase();
    let mut fixed = rows.iter().map(|(form, _)| fixed_prefix(form));
    let common = fixed.next()?.to_string();
    let common = fixed.fold(common, |acc, f| {
        acc.chars().zip(f.chars()).take_while(|(a, b)| a == b).map(|(a, _)| a).collect()
    });
    (common.chars().count() > t.chars().count()).then_some(common)
}

/// THE list visibility predicate. A pending gate or a running agent owns the bar, so the
/// list is not merely hidden: every consumer reads this, which is what keeps a key from
/// being routed to the list while a proposal is waiting to be approved.
pub fn list_open(pending_gate: bool, agent_running: bool, n: usize) -> bool {
    !pending_gate && !agent_running && n > 0
}

/// What a key means to an open list. `Pass` = the bar's existing handling is unchanged.
#[derive(Debug, PartialEq)]
pub enum ListOp {
    Sel(Option<usize>),
    Accept(usize),
    Prefix,
    Pass,
}

/// Enter with nothing selected submits as it always did; Escape is never ours (the list
/// dies with the bar). Up off the first row deselects rather than wrapping, so one more
/// Up hands Enter back to submit.
pub fn list_key(key: &str, sel: Option<usize>, n: usize) -> ListOp {
    if n == 0 {
        return ListOp::Pass;
    }
    match key {
        "ArrowDown" => ListOp::Sel(Some(sel.map_or(0, |i| (i + 1).min(n - 1)))),
        "ArrowUp" => match sel {
            None => ListOp::Pass,
            Some(0) => ListOp::Sel(None),
            Some(i) => ListOp::Sel(Some(i - 1)),
        },
        "Tab" => sel.map_or(ListOp::Prefix, ListOp::Accept),
        "Enter" => sel.map_or(ListOp::Pass, ListOp::Accept),
        _ => ListOp::Pass,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn forms(input: &str) -> Vec<&'static str> {
        slash_rows(input).into_iter().map(|(f, _)| f).collect()
    }

    #[test]
    fn slash_rows_needs_a_slash() {
        for input in ["", "hi", "ls /tmp"] {
            assert!(slash_rows(input).is_empty(), "{input}");
        }
        for input in ["/", "  /"] {
            assert_eq!(forms(input), SLASH_ROWS.iter().map(|(f, _)| *f).collect::<Vec<_>>(), "{input}");
        }
    }

    #[test]
    fn slash_rows_prefix_and_usage() {
        assert_eq!(forms("/k"), ["/keys", "/key <id> <apikey>"]);
        assert_eq!(forms("/keys"), ["/keys"]);
        assert_eq!(forms("/KEY groq sk-x"), ["/key <id> <apikey>"]);
        assert_eq!(
            forms("/local ollama"),
            ["/local", "/local <id> [model]", "/local <id> <url> <model> [key]"]
        );
        assert_eq!(forms("/mcp a"), ["/mcp add <name> <url>", "/mcp add <name> -- <cmd> [args]"]);
        assert_eq!(forms("/mcp serve on"), ["/mcp serve on|off|status"]);
        // prefix, not subsequence: /mcp remove must not match /mo
        assert_eq!(forms("/mo"), ["/model <model>", "/models [id]"]);
        assert!(forms("/zzz").is_empty());
    }

    #[test]
    fn slash_rows_covers_every_verb() {
        let mut verbs: Vec<&str> =
            SLASH_ROWS.iter().map(|(f, _)| f.split(' ').next().unwrap()).collect();
        verbs.sort_unstable();
        verbs.dedup();
        // the arms of run_slash_inner, lib.rs:1679-1789; the `providers` alias is
        // deliberately absent (one row per thing, /keys already shows it)
        assert_eq!(
            verbs,
            ["/help", "/key", "/keys", "/local", "/mcp", "/model", "/models", "/remove", "/url", "/use"]
        );
    }

    #[test]
    fn accept_text_is_prefix_only_and_never_deletes_args() {
        assert_eq!(accept_text("/keys", "/k").as_deref(), Some("/keys"));
        assert_eq!(accept_text("/key <id> <apikey>", "/k").as_deref(), Some("/key "));
        assert_eq!(accept_text("/mcp serve on|off|status", "/mcp s").as_deref(), Some("/mcp serve "));
        assert_eq!(accept_text("/local", "/l").as_deref(), Some("/local"));
        assert_eq!(accept_text("/key <id> <apikey>", "/key groq sk-x"), None);
        assert_eq!(accept_text("/keys", "/keys"), None);

        for (form, _) in SLASH_ROWS {
            let it = accept_text(form, "/").unwrap();
            assert!(!it.contains(['<', '[', '|', '\n']), "{form} -> {it}");
            // accepting a row must not filter that row out from under the user
            assert!(forms(&it).contains(&form), "{form} -> {it}");
        }
    }

    #[test]
    fn tab_prefix_never_shortens_input() {
        for (input, want) in [("/k", Some("/key")), ("/mo", Some("/model"))] {
            assert_eq!(tab_prefix(&slash_rows(input), input).as_deref(), want, "{input}");
        }
        for input in ["/", "/u", "/key", "/model"] {
            assert_eq!(tab_prefix(&slash_rows(input), input), None, "{input}");
        }
    }

    #[test]
    fn list_open_is_false_during_gate_or_run() {
        for (gate, running, n) in [(true, false, 5), (false, true, 5), (true, true, 5), (false, false, 0)] {
            assert!(!list_open(gate, running, n), "{gate} {running} {n}");
        }
        assert!(list_open(false, false, 1));
    }

    /// I4/I5: while a proposal is pending, no key may reach the list — not by verdict and
    /// not by visibility. Loops every key the bar can see.
    #[test]
    fn a_pending_gate_never_yields_a_list_action() {
        let keys = [
            "Enter", "Escape", "Tab", "ArrowDown", "ArrowUp", "ArrowLeft", "ArrowRight",
            "Backspace", "Delete", "Home", "End", "PageUp", "PageDown", "a", "/", " ", "Unidentified",
        ];
        for key in keys {
            for running in [false, true] {
                for n in [0, 1, 5] {
                    assert!(!list_open(true, running, n), "gate open with {key}");
                    // and with no rows the router itself is inert whatever the selection
                    for sel in [None, Some(0), Some(4)] {
                        assert_eq!(list_key(key, sel, 0), ListOp::Pass, "{key} {sel:?}");
                    }
                }
            }
        }
    }

    #[test]
    fn enter_submits_unless_a_row_was_chosen() {
        assert_eq!(list_key("Enter", None, 5), ListOp::Pass);
        assert_eq!(list_key("Enter", Some(2), 5), ListOp::Accept(2));
        assert_eq!(list_key("Enter", Some(0), 0), ListOp::Pass);
        assert_eq!(list_key("Tab", None, 5), ListOp::Prefix);
        assert_eq!(list_key("Tab", Some(1), 5), ListOp::Accept(1));
        assert_eq!(list_key("Tab", None, 0), ListOp::Pass);
    }

    #[test]
    fn arrows_clamp_and_deselect_escape_passes() {
        assert_eq!(list_key("ArrowDown", None, 5), ListOp::Sel(Some(0)));
        assert_eq!(list_key("ArrowDown", Some(4), 5), ListOp::Sel(Some(4)));
        assert_eq!(list_key("ArrowUp", Some(0), 5), ListOp::Sel(None));
        assert_eq!(list_key("ArrowUp", Some(2), 5), ListOp::Sel(Some(1)));
        assert_eq!(list_key("ArrowUp", None, 5), ListOp::Pass);
        assert_eq!(list_key("Escape", Some(1), 5), ListOp::Pass);
        assert_eq!(list_key("a", Some(1), 5), ListOp::Pass);
    }
}
