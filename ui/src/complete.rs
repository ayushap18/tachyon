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

/// The form column must match SLASH_HELP in src-tauri/src/lib.rs; the test
/// `surfaces_agree_with_the_backend` parses that file and fails if they drift.
pub const SLASH_ROWS: [(&str, &str); 20] = [
    ("/keys", "list providers, active, key source"),
    ("/providers", "same table as /keys"),
    ("/key <id> <apikey>", "set a provider's API key"),
    ("/use <id> [model]", "switch active provider (+ optional model)"),
    ("/model <model>", "set the active provider's model"),
    ("/models [id]", "list the models a provider actually serves"),
    ("/local", "find local runtimes: ollama lmstudio llamacpp vllm jan"),
    ("/local <id> [model]", "register a discovered runtime"),
    ("/local <id> <url> <model> [key]", "add any OpenAI-compatible endpoint"),
    ("/url <id> <base_url>", "point a provider at a proxy/gateway"),
    ("/remove <id>", "remove a provider"),
    ("/route", "which provider+model each task uses"),
    ("/route <task> <id> [model]", "route a task: command explain agent (off resets)"),
    ("/mcp add <name> <url>", "add a remote MCP server"),
    ("/mcp add <name> -- <cmd> [args]", "add a local MCP server (Tachyon will run <cmd>)"),
    ("/mcp remove <name>", "remove an MCP server"),
    ("/mcp list", "list MCP servers and their tools"),
    ("/mcp serve on|off|status", "let external agents use this terminal (on <port> to pick one)"),
    ("/update", "check for a newer Tachyon"),
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
///
/// Generic over the row's text so the same helper takes the borrowed form rows and the
/// owned argument rows — the alternative is a second copy of the same four lines.
pub fn tab_prefix<S: AsRef<str>>(rows: &[(S, &'static str)], input: &str) -> Option<String> {
    let t = input.trim_start().to_lowercase();
    let mut fixed = rows.iter().map(|(form, _)| fixed_prefix(form.as_ref()));
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

// ---- argument-aware completion ----

/// Mirrors LOCAL_RUNTIMES in src-tauri/src/local_models.rs — `surfaces_agree_with_the_backend`.
pub const LOCAL_IDS: [&str; 5] = ["ollama", "lmstudio", "llamacpp", "vllm", "jan"];

/// Mirrors Task::name in src-tauri/src/lib.rs — `surfaces_agree_with_the_backend`.
pub const TASK_IDS: [&str; 3] = ["command", "explain", "agent"];

/// SLASH_ROWS advertises on|off|status; parse_serve also takes `on <port>`, and a port is
/// never suggestible (`parse_serve` in mcp_server.rs).
const SERVE_WORDS: [&str; 3] = ["on", "off", "status"];

/// What may be suggested for the token under the cursor.
#[derive(Debug, Clone, PartialEq)]
pub enum Slot {
    Verb,
    Provider { revivable: bool },
    Model(Option<String>), // None = the active provider (/model)
    Runtime,
    Task, // command | explain | agent
    McpName,
    Serve,
    Nothing, // API key, base_url, port, a NEW mcp name, free text
}

/// A slot plus what the form still owes after it, so an accepted row teaches the next
/// argument: "/use groq [model]", "/key groq <apikey>".
#[derive(Debug, Clone, PartialEq)]
pub struct Spot {
    pub slot: Slot,
    pub tail: &'static str,
}

/// Everything the completer is allowed to know. Filled ONCE on bar open (provider_state +
/// mcp_names, both disk reads); `models` only ever by a deliberate Tab. Ids only — there is
/// no field here a key, base_url or header value could occupy.
#[derive(Default, Clone, PartialEq)]
pub struct Ctx {
    pub active: String,
    pub providers: Vec<String>,
    pub hidden: Vec<String>,
    pub mcp: Vec<String>,
    pub models: Option<(String, Vec<String>)>, // (provider id, its model ids)
}

/// "/use groq mod" -> ("use", ["groq"], "mod"). `typing` is NOT in `args`, so args.len()
/// IS the zero-based argument position being completed. None unless input starts with '/'.
/// An empty verb means the verb itself is the token under the cursor ("/us").
fn split(input: &str) -> Option<(String, Vec<&str>, &str)> {
    let rest = input.trim_start().strip_prefix('/')?;
    let mut toks: Vec<&str> = rest.split_whitespace().collect();
    // a trailing space means the cursor sits on a fresh, still-empty token
    let typing = if rest.ends_with(char::is_whitespace) { "" } else { toks.pop().unwrap_or("") };
    let verb = if toks.is_empty() { String::new() } else { toks.remove(0).to_lowercase() };
    Some((verb, toks, typing))
}

/// THE grammar. Pure. One arm per verb, one case per position.
pub fn spot(input: &str) -> Spot {
    let Some((verb, args, _)) = split(input) else { return Spot { slot: Slot::Verb, tail: "" } };
    let nothing = Spot { slot: Slot::Nothing, tail: "" };
    let at = |slot, tail| Spot { slot, tail };
    match (verb.as_str(), args.len()) {
        ("", _) => at(Slot::Verb, ""),
        ("key", 0) => at(Slot::Provider { revivable: false }, " <apikey>"),
        ("use", 0) => at(Slot::Provider { revivable: true }, " [model]"),
        ("use", 1) => at(Slot::Model(Some(args[0].into())), ""),
        ("model", 0) => at(Slot::Model(None), ""),
        ("models", 0) => at(Slot::Provider { revivable: false }, ""),
        ("url", 0) => at(Slot::Provider { revivable: false }, " <base_url>"),
        ("remove", 0) => at(Slot::Provider { revivable: false }, ""),
        ("local", 0) => at(Slot::Runtime, " [model]"),
        // THE hazard: run_slash_inner's local arm matches [id, url, model, key @ ..] BEFORE
        // [id, model @ ..], so position 1 is a model ONLY if this id resolves at its
        // HARDCODED LOCAL_RUNTIMES port (`resolve_runtime` in local_models.rs). A name in
        // LOCAL_IDS does not prove that: `/local lmstudio http://localhost:1235/v1 m` registers
        // the name at a different endpoint, and provider_models reads THAT base_url — two endpoints
        // we cannot compare, because Ctx must never carry a base_url (non-negotiable).
        // Unprovable here => never offered. The model argument is optional anyway
        // (resolve_runtime picks the first model when it is None), so this costs nothing.
        ("local", 1) => nothing,
        ("route", 0) => at(Slot::Task, " <id>"),
        ("route", 1) => at(Slot::Provider { revivable: false }, " [model]"),
        // `/route <task> off` takes no third argument — do not fire the provider_models
        // round trip (wants_models, below) on a word that is not a provider id.
        ("route", 2) if !args[1].eq_ignore_ascii_case("off") =>
            at(Slot::Model(Some(args[1].into())), ""),
        ("mcp", 1) => match args[0].to_lowercase().as_str() {
            "remove" => at(Slot::McpName, ""),
            "serve" => at(Slot::Serve, ""),
            _ => nothing, // `add` takes a NEW name; `list` takes nothing
        },
        _ => nothing,
    }
}

/// A candidate that may be shown and inserted. Rejects control chars, EVERY Cf block (copy
/// of is_invisible, src-tauri/src/lib.rs — ui is outside that workspace; two ids that render
/// identically but differ by an invisible codepoint means the user accepts the row they can
/// see and Enter sends the other one), whitespace (run_slash_inner splits on it, so it could
/// never round-trip), `<[|` (fixed_prefix reads them as the placeholder token, so the row
/// they build is one accept_text can only answer None for — an inert row the user presses
/// Enter on twice) and anything over 64 chars. DROP, never strip: a mangled id is a wrong id.
pub fn safe_row(s: &str) -> bool {
    !s.is_empty()
        && s.chars().count() <= 64
        && !s.chars().any(|c| {
            c.is_control()
                || c.is_whitespace()
                || matches!(c, '<' | '[' | '|')
                || matches!(
                    c,
                    '\u{00AD}'
                        | '\u{061C}'
                        | '\u{180E}'
                        | '\u{200B}'..='\u{200F}'
                        | '\u{202A}'..='\u{202E}'
                        | '\u{2060}'..='\u{2064}'
                        | '\u{2066}'..='\u{206F}'
                        | '\u{FEFF}'
                        | '\u{FFF9}'..='\u{FFFB}'
                        | '\u{1D173}'..='\u{1D17A}'
                        | '\u{E0000}'..='\u{E007F}'
                )
        })
}

/// Rows the list will ever build. rows() runs on EVERY render, i.e. every keystroke, and a
/// hostile /models endpoint controls both the count and the shared prefix that would defeat
/// the typed-prefix filter — so the ceiling has to be here, not in the CSS max-height.
/// ponytail: linear scan + linear dedup under this cap; a prefix index if anyone needs more.
const MAX_ROWS: usize = 50;

/// Candidate rows for the token being typed, already whole command lines. Empty whenever
/// the grammar forbids a suggestion or the source is empty.
pub fn arg_rows(input: &str, cx: &Ctx) -> Vec<(String, &'static str)> {
    let Some((verb, args, typing)) = split(input) else { return Vec::new() };
    let Spot { slot, tail } = spot(input);
    // hint column is ids-only by construction: never base_url, key_source or has_key
    let (cands, hint): (Vec<String>, &'static str) = match slot {
        Slot::Verb | Slot::Nothing => return Vec::new(),
        Slot::Provider { revivable } => {
            let mut v = cx.providers.clone();
            // every mutator but use_provider routes through find_mut and errors on a hidden
            // id (`find_mut` in lib.rs), so offering one there would teach a guaranteed error
            if revivable {
                v.extend(cx.hidden.iter().cloned());
            }
            (v, "provider")
        }
        Slot::Model(id) => {
            let want = id.unwrap_or_else(|| cx.active.clone());
            match &cx.models {
                Some((got, ms)) if *got == want => (ms.clone(), "model"),
                _ => return Vec::new(),
            }
        }
        Slot::Runtime => (LOCAL_IDS.iter().map(|s| (*s).to_string()).collect(), "runtime"),
        Slot::Task => (TASK_IDS.iter().map(|s| (*s).to_string()).collect(), "task"),
        Slot::McpName => (cx.mcp.clone(), "mcp"),
        Slot::Serve => (SERVE_WORDS.iter().map(|s| (*s).to_string()).collect(), ""),
    };
    let lower = typing.to_lowercase();
    let head =
        if args.is_empty() { format!("/{verb}") } else { format!("/{verb} {}", args.join(" ")) };
    let mut out: Vec<(String, &'static str)> = Vec::new();
    for c in cands.iter().filter(|c| safe_row(c) && c.to_lowercase().starts_with(&lower)).take(MAX_ROWS)
    {
        let line = format!("{head} {c}{tail}");
        // providers.json is hand-editable and hidden ids can echo a live one: same line twice
        // would collide in the render key and duplicate the row
        if !out.iter().any(|(l, _)| *l == line) {
            out.push((line, if hint == "provider" && *c == cx.active { "active" } else { hint }));
        }
    }
    out
}

/// THE list. Argument rows when there are any, otherwise the form rows. Never both.
pub fn rows(input: &str, cx: &Ctx) -> Vec<(String, &'static str)> {
    let args = arg_rows(input, cx);
    if args.is_empty() {
        slash_rows(input).into_iter().map(|(f, d)| (f.to_string(), d)).collect()
    } else {
        args
    }
}

/// The provider whose model list is needed, if the cursor is in a model slot and the cache
/// does not already hold it. The ONLY thing that may trigger a network fetch, and the bar
/// calls it from the Tab branch only — never from oninput.
pub fn wants_models(input: &str, cx: &Ctx) -> Option<String> {
    let id = match spot(input).slot {
        Slot::Model(Some(id)) => id,
        Slot::Model(None) => cx.active.clone(),
        _ => return None,
    };
    match &cx.models {
        _ if id.is_empty() => None,
        Some((got, _)) if *got == id => None,
        _ => Some(id),
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
        assert_eq!(forms("/r"), ["/remove <id>", "/route", "/route <task> <id> [model]"]);
        assert_eq!(forms("/u"), ["/use <id> [model]", "/url <id> <base_url>", "/update"]);
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
        // the arms of run_slash_inner in lib.rs, plus `/update` which run_slash peels off
        // first. `/providers` is an alias the parser accepts, so it is listed like any other
        // verb — an accepted command the completer denies is worse than a duplicate row.
        assert_eq!(
            verbs,
            [
                "/help", "/key", "/keys", "/local", "/mcp", "/model", "/models", "/providers",
                "/remove", "/route", "/update", "/url", "/use"
            ]
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

    // ---- argument-aware completion ----

    fn provider(revivable: bool) -> Slot {
        Slot::Provider { revivable }
    }

    fn model(id: &str) -> Slot {
        Slot::Model(Some(id.to_string()))
    }

    /// Fully populated: every source non-empty and the model cache filled, so a test that
    /// asserts "no rows" is proving the grammar, not an empty Ctx.
    fn cx() -> Ctx {
        Ctx {
            active: "groq".into(),
            providers: vec!["groq".into(), "gemini".into(), "openai".into()],
            hidden: vec!["anthropic".into()],
            mcp: vec!["fs".into(), "gh".into()],
            models: Some(("groq".into(), vec!["llama3.2".into(), "llama-guard".into()])),
        }
    }

    /// One input per cell of the grammar table.
    const SPREAD: [&str; 22] = [
        "/", "/us", "/keys ", "/help ", "/key ", "/key gr", "/key groq ", "/use ", "/use gr",
        "/use groq ", "/model ", "/models ", "/url ", "/url groq ", "/remove ", "/local ",
        "/local ollama ", "/local mybox ", "/mcp ", "/mcp remove ", "/mcp serve ", "/zzz ",
    ];

    #[test]
    fn grammar_table() {
        let table: &[(&str, Slot, &str)] = &[
            ("hello", Slot::Verb, ""),
            ("/", Slot::Verb, ""),
            ("/use", Slot::Verb, ""),
            ("/keys ", Slot::Nothing, ""),
            ("/keys x ", Slot::Nothing, ""),
            ("/help ", Slot::Nothing, ""),
            ("/key ", provider(false), " <apikey>"),
            ("/key groq ", Slot::Nothing, ""),
            ("/key groq sk-x ", Slot::Nothing, ""),
            ("/use ", provider(true), " [model]"),
            ("/use groq ", model("groq"), ""),
            ("/use groq llama3.2 ", Slot::Nothing, ""),
            ("/model ", Slot::Model(None), ""),
            ("/model llama3.2 ", Slot::Nothing, ""),
            ("/models ", provider(false), ""),
            ("/models groq ", Slot::Nothing, ""),
            ("/url ", provider(false), " <base_url>"),
            ("/url groq ", Slot::Nothing, ""),
            ("/remove ", provider(false), ""),
            ("/remove groq ", Slot::Nothing, ""),
            ("/local ", Slot::Runtime, " [model]"),
            ("/local ollama ", Slot::Nothing, ""),
            ("/local ollama x y ", Slot::Nothing, ""),
            ("/mcp ", Slot::Nothing, ""),
            ("/mcp add ", Slot::Nothing, ""),
            ("/mcp remove ", Slot::McpName, ""),
            ("/mcp remove fs ", Slot::Nothing, ""),
            ("/mcp list ", Slot::Nothing, ""),
            ("/mcp serve ", Slot::Serve, ""),
            ("/mcp serve on ", Slot::Nothing, ""),
            ("/zzz ", Slot::Nothing, ""),
            ("/zzz a ", Slot::Nothing, ""),
        ];
        for (input, slot, tail) in table {
            assert_eq!(spot(input), Spot { slot: slot.clone(), tail }, "{input}");
        }
    }

    /// The non-negotiable: an API key, a base_url and a port are never suggested, and the
    /// grammar says so — not a downstream filter.
    #[test]
    fn no_argument_of_key_is_ever_suggested() {
        for input in [
            "/key groq ",
            "/key groq sk-",
            "/key groq sk-abc ",
            "/key groq sk-abc def",
            "/url groq ",
            "/url groq http",
            "/local ollama http://x ",
            "/local ollama http://x m ",
            "/mcp serve on ",
            "/mcp add srv ",
        ] {
            assert_eq!(spot(input).slot, Slot::Nothing, "{input}");
            assert!(arg_rows(input, &cx()).is_empty(), "{input}");
        }
    }

    /// run_slash_inner's `local` arm matches [id, url, model, key @ ..] BEFORE [id, model @ ..],
    /// so argument 1 is a URL for any id NOT answering at its hardcoded LOCAL_RUNTIMES port —
    /// which a name in LOCAL_IDS does not prove (`/local lmstudio http://localhost:1235/v1 m`
    /// registers the name off-port). Position 1 is therefore never a model slot.
    #[test]
    fn local_arity_hazard() {
        let cx = Ctx { models: Some(("ollama".into(), vec!["llama3.2".into()])), ..cx() };
        assert_eq!(spot("/local ").slot, Slot::Runtime);
        assert_eq!(spot("/local oll").slot, Slot::Runtime);
        assert_eq!(spot("/local ollama ").slot, Slot::Nothing);
        assert_eq!(spot("/local lmstudio ").slot, Slot::Nothing);
        assert_eq!(spot("/local mybox ").slot, Slot::Nothing);
        assert_eq!(spot("/local ollama llama3.2 ").slot, Slot::Nothing);
        assert_eq!(spot("/local ollama llama3.2 extra").slot, Slot::Nothing);
        // past the verb, /local offers nothing at all — not a url, and not a model either
        for input in [
            "/local ollama ", "/local lmstudio ", "/local ollama ll", "/local mybox ",
            "/local ollama llama3.2 ", "/local ollama llama3.2 extra",
        ] {
            assert!(arg_rows(input, &cx).is_empty(), "{input}");
        }
        for input in ["/local", "/local ", "/local oll"] {
            for (row, _) in rows(input, &cx) {
                assert!(!row.contains("://"), "{input} -> {row}");
            }
        }
    }

    /// A hostile /models endpoint controls the count AND the shared prefix, so the typed
    /// prefix is no filter at all. rows() runs on every keystroke: it must stay bounded.
    #[test]
    fn rows_are_capped_however_many_candidates() {
        let many: Vec<String> = (0..100_000).map(|i| format!("m{i:06}")).collect();
        let cx = Ctx { active: "groq".into(), models: Some(("groq".into(), many)), ..Ctx::default() };
        assert_eq!(rows("/model ", &cx).len(), MAX_ROWS);
        assert_eq!(rows("/model m0000", &cx).len(), MAX_ROWS);
    }

    #[test]
    fn arg_rows_and_form_rows_never_coexist() {
        let cx = cx();
        for input in SPREAD {
            let got = rows(input, &cx);
            let forms: Vec<(String, &str)> =
                slash_rows(input).into_iter().map(|(f, d)| (f.to_string(), d)).collect();
            let args = arg_rows(input, &cx);
            assert!(got == forms || got == args, "{input}");
            assert!(!(args.is_empty() && got != forms), "{input}");
            let mut labels: Vec<&str> = got.iter().map(|(l, _)| l.as_str()).collect();
            labels.sort_unstable();
            let n = labels.len();
            labels.dedup();
            assert_eq!(labels.len(), n, "duplicate row for {input}");
        }
    }

    #[test]
    fn accepting_an_argument_row_only_extends() {
        let cx = cx();
        let mut checked = 0;
        for input in SPREAD {
            for (row, _) in rows(input, &cx) {
                let Some(a) = accept_text(&row, input) else { continue };
                assert!(!a.contains(['<', '[', '|', '\n']), "{input} -> {a}");
                // everything up to the last space is an argument the user already typed
                let done = &input[..input.rfind(' ').map_or(0, |i| i + 1)];
                assert!(a.to_lowercase().starts_with(&done.to_lowercase()), "{input} -> {a}");
                assert!(!rows(&a, &cx).is_empty(), "{input} -> {a} killed the list");
                for (next, _) in arg_rows(&a, &cx) {
                    assert!(next.to_lowercase().starts_with(a.trim_end()), "{a} -> {next}");
                }
                checked += 1;
            }
        }
        assert!(checked > 40, "the loop went vacuous: only {checked} accepts"); // 87 today
    }

    #[test]
    fn every_verb_has_a_grammar_arm() {
        let mut verbs: Vec<&str> = SLASH_ROWS
            .iter()
            .filter(|(f, _)| f.contains(['<', '[', '|']))
            .map(|(f, _)| f.split(' ').next().unwrap())
            .collect();
        verbs.sort_unstable();
        verbs.dedup();
        for v in verbs {
            assert_ne!(spot(&format!("{v} ")).slot, Slot::Verb, "{v}");
        }
    }

    #[test]
    fn tab_prefix_over_argument_rows() {
        let cx = Ctx { providers: vec!["groq".into(), "gemini".into()], ..Ctx::default() };
        assert_eq!(tab_prefix(&rows("/use gr", &cx), "/use gr").as_deref(), Some("/use groq"));
        assert_eq!(tab_prefix(&rows("/use g", &cx), "/use g"), None);
    }

    #[test]
    fn safe_row_drops_invisible_and_split_hostile() {
        for bad in [
            "a\u{202E}b", "a\u{200B}b", "a b", "a\nb", "\u{1b}[2J", &"x".repeat(65), "",
            // the Cf blocks a hand-written four-range list kept missing: two ids that paint
            // identically must not both be offerable
            "a\u{061C}b", "a\u{00AD}b", "a\u{2060}b", "a\u{E0041}b", "\u{FFF9}a\u{FFFB}",
            // fixed_prefix's placeholder markers: a candidate carrying one builds an
            // unacceptable row (every_listed_row_is_acceptable)
            "gpt|4", "a<b>", "my[srv]",
        ] {
            assert!(!safe_row(bad), "{bad:?}");
        }
        assert!(safe_row("groq"));
        assert!(safe_row("llama3.2:8b"));
        assert!(safe_row("qwen/qwen3.8-27b"));
    }

    /// A row the list offers and Enter cannot accept is worse than no row: the bar clears
    /// the selection, the next Enter submits the half-typed text, and `/model gp` writes
    /// `gp` as the active provider's model. Nothing listed may answer None.
    #[test]
    fn every_listed_row_is_acceptable() {
        let cx = Ctx {
            active: "groq".into(),
            providers: vec!["groq".into(), "gemini".into(), "gpt|4".into()],
            hidden: vec!["a<b>".into()],
            mcp: vec!["fs".into(), "my[srv]".into()],
            models: Some(("groq".into(), vec!["gpt|4".into(), "ok-model".into(), "ok-2".into()])),
        };
        let mut checked = 0;
        for input in ["/model ", "/model g", "/use ", "/key ", "/mcp remove ", "/route command "] {
            for (row, _) in arg_rows(input, &cx) {
                assert!(accept_text(&row, input).is_some(), "{input} -> {row} cannot be accepted");
                checked += 1;
            }
        }
        assert!(checked > 5, "the loop went vacuous: only {checked} rows");
    }

    /// The three tables above mirror declarations in the other crate. ui is deliberately
    /// outside the src-tauri workspace so nothing links them — but the source is on disk and
    /// all three are `const`s, so a drift is a text comparison away. Three releases of
    /// hand-syncing produced four stale line numbers; this is what replaced the prose.
    #[test]
    fn surfaces_agree_with_the_backend() {
        const LIB: &str = include_str!("../../src-tauri/src/lib.rs");
        const LOCAL: &str = include_str!("../../src-tauri/src/local_models.rs");

        fn between<'a>(src: &'a str, open: &str, close: &str) -> &'a str {
            let rest = src.split_once(open).unwrap_or_else(|| panic!("`{open}` is gone")).1;
            rest.split_once(close).unwrap().0
        }

        // each help line is `\x1b[36m<form>\x1b[0m<description>`, written as escapes in the source
        let help = between(LIB, "const SLASH_HELP: &str = concat!(", "\n);");
        let mut forms: Vec<&str> =
            help.split("\\x1b[36m").skip(1).map(|s| s.split("\\x1b[0m").next().unwrap()).collect();
        let mut rows: Vec<&str> = SLASH_ROWS.iter().map(|(f, _)| *f).collect();
        forms.sort_unstable();
        rows.sort_unstable();
        assert_eq!(forms, rows, "SLASH_HELP and SLASH_ROWS have drifted");

        // The README is the fourth surface and was the only one nothing read. Its block is a
        // fenced form/description table, two-or-more spaces between the columns.
        const RM: &str = include_str!("../../README.md");
        let mut readme: Vec<&str> = between(RM, "```\n/keys", "```")
            .lines()
            .filter(|l| l.starts_with('/'))
            .map(|l| l.split("  ").next().unwrap().trim())
            .collect();
        readme.push("/keys"); // consumed by the opening delimiter
        readme.sort_unstable();
        assert_eq!(readme, rows, "README.md and SLASH_ROWS have drifted");

        let runtimes = between(LOCAL, "LOCAL_RUNTIMES: &[(&str, &str)] = &[", "];");
        let ids: Vec<&str> = runtimes
            .lines()
            .filter_map(|l| l.split_once("(\""))
            .map(|(_, id)| id.split('"').next().unwrap())
            .collect();
        assert_eq!(ids, LOCAL_IDS, "LOCAL_RUNTIMES and LOCAL_IDS have drifted");

        let arms = between(LIB, "fn name(self) -> &'static str {", "}");
        let names: Vec<&str> =
            arms.split("=> \"").skip(1).map(|s| s.split('"').next().unwrap()).collect();
        assert_eq!(names, TASK_IDS, "Task::name and TASK_IDS have drifted");
    }

    /// The port lives in the description column. In the form column `on [port]` would move
    /// fixed_prefix's cut to `/mcp serve on`, so accepting the row would pick `on` for the user.
    #[test]
    fn serve_port_is_described_not_in_the_form() {
        let (form, desc) = SLASH_ROWS.iter().find(|(f, _)| f.starts_with("/mcp serve")).unwrap();
        assert!(desc.contains("<port>"), "{desc}");
        assert!(!form.contains("port"), "{form}");
        assert_eq!(accept_text(form, "/mcp s").as_deref(), Some("/mcp serve "));
    }

    #[test]
    fn route_slots_follow_position() {
        assert_eq!(spot("/route ").slot, Slot::Task);
        assert_eq!(spot("/route command ").slot, Slot::Provider { revivable: false });
        assert_eq!(spot("/route command groq ").slot, Slot::Model(Some("groq".into())));
        assert_eq!(spot("/route command off ").slot, Slot::Nothing);
    }

    #[test]
    fn route_never_fires_models_for_off() {
        assert_eq!(wants_models("/route command off ", &cx()), None);
        // the reset word is not a provider id, so it must not become one on the next token
        assert!(arg_rows("/route command off ", &cx()).is_empty());
    }

    #[test]
    fn wants_models_is_the_only_network_trigger() {
        let empty = Ctx { active: "groq".into(), ..Ctx::default() };
        assert_eq!(wants_models("/use groq ", &empty).as_deref(), Some("groq"));
        assert_eq!(wants_models("/model ", &empty).as_deref(), Some("groq"));
        for input in [
            "/key groq ",
            "/key groq sk-",
            "/key groq sk-abc ",
            "/key groq sk-abc def",
            "/url groq ",
            "/url groq http",
            "/local ollama http://x ",
            "/local ollama http://x m ",
            "/mcp serve on ",
            "/mcp add srv ",
            "/local mybox ",
            "/local ollama ",
            "/local lmstudio ",
            "/local ollama llama3.2 ",
            "/route ",
            "/route command ",
            "/route command off ",
        ] {
            assert_eq!(wants_models(input, &empty), None, "{input}");
        }
        // already cached: no second fetch
        assert_eq!(wants_models("/use groq ", &cx()), None);
        assert_eq!(wants_models("/model ", &cx()), None);
        // no active provider yet: nothing to ask for
        assert_eq!(wants_models("/model ", &Ctx::default()), None);
    }
}
