//! Local and open models: runtime discovery, model listing, env-var keys, and the error
//! hints that turn an opaque "groq 404: …" into something the user can act on.
//!
//! Blocking `ureq` like the MCP client, not the async `reqwest` client: every caller is a
//! slash command or an `(async)` Tauri command, already off the main thread, and the shared
//! client's 10 s connect timeout is wrong for a localhost probe anyway.

use std::time::Duration;

use crate::{truncate_chars, Provider, ProviderState};

/// (provider id, OpenAI-compatible base URL) of the runtimes worth probing.
pub(crate) const LOCAL_RUNTIMES: &[(&str, &str)] = &[
    ("ollama", "http://localhost:11434/v1"),
    ("lmstudio", "http://localhost:1234/v1"),
    ("llamacpp", "http://localhost:8080/v1"),
    ("vllm", "http://localhost:8000/v1"),
    ("jan", "http://localhost:1337/v1"),
];

// Localhost either answers at once or is not there; the total bound is for a wedged
// runtime that accepts the connection and never replies.
const PROBE_CONNECT: Duration = Duration::from_millis(600);
const PROBE_TOTAL: Duration = Duration::from_secs(2);
const LIST_CONNECT: Duration = Duration::from_secs(10);
const LIST_TOTAL: Duration = Duration::from_secs(15);

// ---- keys ----

/// The conventional env var for a provider id. Custom ids get `<ID>_API_KEY`.
pub(crate) fn env_key_name(id: &str) -> String {
    match id {
        "claude" => "ANTHROPIC_API_KEY".into(),
        "kimi" => "MOONSHOT_API_KEY".into(),
        _ => format!("{}_API_KEY", id.to_uppercase().replace(|c: char| !c.is_ascii_alphanumeric(), "_")),
    }
}

/// (key, source) with source one of `saved` / `env` / `none`. A saved key wins. The env
/// key is returned to the caller for ONE request and never written into `Provider`, so it
/// cannot reach providers.json or the webview. `env` is injected so tests need no set_var.
pub(crate) fn resolve_key(p: &Provider, env: impl Fn(&str) -> Option<String>) -> (String, &'static str) {
    if !p.key.is_empty() {
        return (p.key.clone(), "saved");
    }
    match env(&env_key_name(&p.id)).map(|k| k.trim().to_string()).filter(|k| !k.is_empty()) {
        Some(k) => (k, "env"),
        None => (String::new(), "none"),
    }
}

pub(crate) fn key_for(p: &Provider) -> (String, &'static str) {
    resolve_key(p, |name| std::env::var(name).ok())
}

// ---- URLs ----

/// Anthropic endpoint honouring a proxy/gateway `base_url`; empty means the official API.
/// A trailing `/v1` is tolerated because every other provider's base_url is written with one.
pub(crate) fn anthropic_url(base_url: &str, path: &str) -> String {
    let base = base_url.trim().trim_end_matches('/');
    let base = base.strip_suffix("/v1").unwrap_or(base);
    let base = if base.is_empty() { "https://api.anthropic.com" } else { base };
    format!("{base}/v1/{path}")
}

// ---- model listing ----

/// Model ids from an OpenAI-style `{data:[{id}]}` or an Ollama-style `{models:[{name}]}` body.
pub(crate) fn parse_models(body: &str) -> Result<Vec<String>, String> {
    let v: serde_json::Value = serde_json::from_str(body).map_err(|_| "response is not JSON".to_string())?;
    let (list, field) = match (v.get("data").and_then(|d| d.as_array()), v.get("models").and_then(|m| m.as_array())) {
        (Some(d), _) => (d, "id"),
        (None, Some(m)) => (m, "name"),
        _ => return Err("no model list in response".into()),
    };
    Ok(list.iter().filter_map(|m| m.get(field).and_then(|s| s.as_str()).map(String::from)).collect())
}

// Errors name the provider id and the HTTP status or transport error KIND only — never the
// URL (a base_url can carry a token in its query string) and never a header.
fn fetch_models(p: &Provider, key: &str, connect: Duration, total: Duration) -> Result<Vec<String>, String> {
    let agent = ureq::AgentBuilder::new().timeout_connect(connect).timeout(total).build();
    let req = if p.kind == "anthropic" {
        if key.is_empty() {
            return Err(no_key_message(&p.id));
        }
        agent
            .get(&anthropic_url(&p.base_url, "models?limit=100"))
            .set("x-api-key", key)
            .set("anthropic-version", "2023-06-01")
    } else {
        let r = agent.get(&format!("{}/models", p.base_url.trim_end_matches('/')));
        if key.is_empty() { r } else { r.set("Authorization", &format!("Bearer {key}")) }
    };
    let body = match req.call() {
        Ok(resp) => resp.into_string().map_err(|e| format!("{}: {}", p.id, e.kind()))?,
        Err(ureq::Error::Status(code, resp)) => {
            let body = resp.into_string().unwrap_or_default();
            return Err(format!("{} {code}: {}", p.id, error_detail(&body, key)));
        }
        Err(ureq::Error::Transport(t)) => return Err(format!("{}: {}", p.id, t.kind())),
    };
    parse_models(&body).map_err(|e| format!("{}: {e}", p.id))
}

pub(crate) fn list_models(p: &Provider) -> Result<Vec<String>, String> {
    fetch_models(p, &key_for(p).0, LIST_CONNECT, LIST_TOTAL)
}

// Gemini's OpenAI-compatible endpoint lists "models/gemini-2.0-flash" but accepts the bare id.
fn same_model(listed: &str, configured: &str) -> bool {
    listed == configured || listed.strip_prefix("models/") == Some(configured)
}

// ponytail: first 50 only — an aggregator (OpenRouter) lists hundreds; add a filter argument
// to /models if anyone needs to search them.
const MODELS_SHOWN: usize = 50;

pub(crate) fn render_models(p: &Provider, models: &[String], active: bool) -> String {
    let mut out = format!("\r\n\x1b[36m[tachyon] {} serves {} models\x1b[0m\r\n", p.id, models.len());
    for m in models.iter().take(MODELS_SHOWN) {
        let mark = if same_model(m, &p.model) { "\x1b[32m●\x1b[0m" } else { " " };
        out.push_str(&format!("{mark} {m}\r\n"));
    }
    if models.len() > MODELS_SHOWN {
        out.push_str(&format!("\x1b[90m  … and {} more\x1b[0m\r\n", models.len() - MODELS_SHOWN));
    }
    if !models.iter().any(|m| same_model(m, &p.model)) {
        // /model only ever edits the ACTIVE provider
        let fix = if active { "/model <model>".to_string() } else { format!("/use {} <model>", p.id) };
        out.push_str(&format!(
            "\x1b[31m[tachyon] configured model \"{}\" is NOT served by {} \u{2014} pick one with {fix}\x1b[0m\r\n",
            p.model, p.id
        ));
    }
    out
}

// ---- discovery ----

#[derive(Clone, Debug, PartialEq, serde::Serialize)]
pub(crate) struct LocalRuntime {
    pub id: String,
    pub base_url: String,
    pub models: Vec<String>,
}

/// Probe every `(id, base_url)` concurrently; return the ones that answered `GET /models`
/// with a model list. The probe list is a parameter so tests never touch a real Ollama.
pub(crate) fn discover(probes: &[(&str, &str)]) -> Vec<LocalRuntime> {
    std::thread::scope(|scope| {
        let handles: Vec<_> = probes
            .iter()
            .map(|(id, url)| {
                scope.spawn(move || {
                    let p = Provider {
                        id: id.to_string(),
                        kind: "openai".into(),
                        base_url: url.to_string(),
                        model: String::new(),
                        key: String::new(),
                    };
                    let models = fetch_models(&p, "", PROBE_CONNECT, PROBE_TOTAL).ok()?;
                    Some(LocalRuntime { id: p.id, base_url: p.base_url, models })
                })
            })
            .collect();
        handles.into_iter().filter_map(|h| h.join().ok().flatten()).collect()
    })
}

pub(crate) fn render_discovery(found: &[LocalRuntime]) -> String {
    if found.is_empty() {
        let names: Vec<&str> = LOCAL_RUNTIMES.iter().map(|(id, _)| *id).collect();
        return format!(
            "\r\n\x1b[36m[tachyon] no local runtime answered\x1b[0m \x1b[90m(probed {})\x1b[0m\r\n\
             \x1b[90mstart one, or add any endpoint: /local <id> <base_url> <model> [key]\x1b[0m\r\n",
            names.join(" ")
        );
    }
    let mut out = String::from("\r\n\x1b[36m[tachyon] local runtimes\x1b[0m\r\n");
    for r in found {
        let models = if r.models.is_empty() {
            "up, but no models loaded".to_string()
        } else {
            truncate_chars(&r.models.join(" "), 160)
        };
        out.push_str(&format!("\x1b[32m●\x1b[0m {:<9} \x1b[90m{}\x1b[0m  {models}\r\n", r.id, r.base_url));
    }
    out.push_str("\x1b[90mregister one: /local <id> [model]   then /use <id>\x1b[0m\r\n");
    out
}

/// `/local <id> [model]`: probe that one runtime and pick the model to register.
pub(crate) fn resolve_runtime(probes: &[(&str, &str)], id: &str, model: Option<&str>) -> Result<(String, String), String> {
    let probe = probes.iter().find(|(pid, _)| *pid == id).ok_or("usage: /local <id> <base_url> <model> [key]")?;
    let rt = discover(&[*probe])
        .pop()
        .ok_or_else(|| format!("{id} is not answering at {} \u{2014} is it running?", probe.1))?;
    let model = match model {
        Some(m) if rt.models.iter().any(|x| x == m) => m.to_string(),
        Some(m) => return Err(format!("{id} does not serve {m} \u{2014} it has: {}", truncate_chars(&rt.models.join(" "), 160))),
        None => rt.models.first().cloned().ok_or_else(|| format!("{id} is up but has no models loaded"))?,
    };
    Ok((rt.base_url, model))
}

/// Discovered runtimes the palette should offer: not already registered, and usable.
pub(crate) fn unregistered(found: Vec<LocalRuntime>, st: &ProviderState) -> Vec<LocalRuntime> {
    found
        .into_iter()
        .filter(|r| !r.models.is_empty() && !st.providers.iter().any(|p| p.id == r.id || p.base_url == r.base_url))
        .collect()
}

// (async): blocking probes must not run on the main thread
#[tauri::command(async)]
pub(crate) fn local_discover() -> Result<Vec<LocalRuntime>, String> {
    Ok(unregistered(discover(LOCAL_RUNTIMES), &crate::load_state()?))
}

// ---- error messages ----

// What to show of an error body: the provider's own `error.message` (OpenAI, Anthropic, Groq)
// or `error` string (Ollama) when it is JSON, else the raw text — with the key scrubbed in
// case the server echoed it, and short enough for the one-line ⌘K bar.
fn error_detail(body: &str, key: &str) -> String {
    let msg = serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.pointer("/error/message").or_else(|| v.get("error")).and_then(|m| m.as_str()).map(String::from))
        .unwrap_or_else(|| body.to_string());
    let msg = if key.is_empty() { msg } else { msg.replace(key, "***") };
    truncate_chars(&msg, 120)
}

pub(crate) fn no_key_message(id: &str) -> String {
    format!("no key for {id} \u{2014} /key {id} <key>, or export {} before launching from a shell", env_key_name(id))
}

// 404 is how OpenAI, Anthropic and Ollama report an unknown model; Groq reports a retired
// one as 400 model_decommissioned. A wrong base_url also 404s, hence "or the base_url".
fn model_unavailable(status: u16, body: &str) -> bool {
    let b = body.to_lowercase();
    status == 404 || ["model_not_found", "model_decommissioned"].iter().any(|m| b.contains(m))
}

/// The message for a failed completion. Decided from the status and body already in hand —
/// no second request on the failure path.
pub(crate) fn completion_error(p: &Provider, key: &str, status: u16, body: &str) -> String {
    let detail = error_detail(body, key);
    if model_unavailable(status, body) {
        return format!(
            "{}: model \"{}\" looks unavailable ({status}) \u{2014} run /models to see what {} serves, then /model <id> (or check the base_url). {detail}",
            p.id, p.model, p.id
        );
    }
    if (status == 401 || status == 403) && key.is_empty() {
        return format!("{} {status}: {}", p.id, no_key_message(&p.id));
    }
    format!("{} {status}: {detail}", p.id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    fn provider(id: &str, kind: &str, base_url: &str, model: &str, key: &str) -> Provider {
        Provider { id: id.into(), kind: kind.into(), base_url: base_url.into(), model: model.into(), key: key.into() }
    }

    /// Throwaway HTTP server on an ephemeral port: answers every request with `status` +
    /// `body` and reports each raw request on the channel. Returns its `/v1` base URL.
    fn stub(status: &'static str, body: &'static str) -> (String, std::sync::mpsc::Receiver<String>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/v1", listener.local_addr().unwrap());
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for mut s in listener.incoming().flatten() {
                let mut req = Vec::new();
                let mut buf = [0u8; 1024];
                while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => req.extend_from_slice(&buf[..n]),
                    }
                }
                let _ = tx.send(String::from_utf8_lossy(&req).into_owned());
                let _ = write!(s, "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
            }
        });
        (url, rx)
    }

    // a port that was just free: bind, read it, drop the listener
    fn dead_url() -> String {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        format!("http://{}/v1", l.local_addr().unwrap())
    }

    #[test]
    fn env_key_names() {
        for (id, var) in [
            ("claude", "ANTHROPIC_API_KEY"),
            ("openai", "OPENAI_API_KEY"),
            ("groq", "GROQ_API_KEY"),
            ("gemini", "GEMINI_API_KEY"),
            ("deepseek", "DEEPSEEK_API_KEY"),
            ("mistral", "MISTRAL_API_KEY"),
            ("kimi", "MOONSHOT_API_KEY"),
            ("my-proxy.2", "MY_PROXY_2_API_KEY"),
        ] {
            assert_eq!(env_key_name(id), var);
        }
    }

    #[test]
    fn saved_key_wins_and_env_key_is_never_persisted() {
        let env = |name: &str| (name == "GROQ_API_KEY").then(|| " gsk_from_env\n".to_string());
        let mut st = ProviderState::defaults();

        let groq = st.providers.iter().find(|p| p.id == "groq").unwrap().clone();
        assert_eq!(resolve_key(&groq, env), ("gsk_from_env".to_string(), "env"));
        let openai = st.providers.iter().find(|p| p.id == "openai").unwrap().clone();
        assert_eq!(resolve_key(&openai, env), (String::new(), "none"));
        // resolving hands the key to the caller only — what would be written to disk has none
        let json = serde_json::to_string(&st).unwrap();
        assert!(!json.contains("gsk_from_env"));
        assert!(st.providers.iter().all(|p| p.key.is_empty()));

        st.set_key("groq", "gsk_saved".into()).unwrap();
        let groq = st.providers.iter().find(|p| p.id == "groq").unwrap().clone();
        assert_eq!(resolve_key(&groq, env), ("gsk_saved".to_string(), "saved"));
    }

    #[test]
    fn anthropic_url_honours_base_url() {
        assert_eq!(anthropic_url("", "messages"), "https://api.anthropic.com/v1/messages");
        assert_eq!(anthropic_url("  ", "models"), "https://api.anthropic.com/v1/models");
        assert_eq!(anthropic_url("https://gw.corp/anthropic/", "messages"), "https://gw.corp/anthropic/v1/messages");
        assert_eq!(anthropic_url("https://gw.corp/v1", "messages"), "https://gw.corp/v1/messages");
    }

    #[test]
    fn parse_models_both_shapes() {
        let openai = r#"{"object":"list","data":[{"id":"gpt-4o","object":"model"},{"id":"o3"}]}"#;
        assert_eq!(parse_models(openai).unwrap(), ["gpt-4o", "o3"]);
        let ollama = r#"{"models":[{"name":"llama3.2:latest","size":1},{"name":"qwen3:8b"}]}"#;
        assert_eq!(parse_models(ollama).unwrap(), ["llama3.2:latest", "qwen3:8b"]);
        assert_eq!(parse_models(r#"{"data":[]}"#).unwrap(), Vec::<String>::new());
        assert!(parse_models("<html>dev server</html>").is_err());
        assert!(parse_models(r#"{"error":"nope"}"#).is_err());
    }

    #[test]
    fn render_models_marks_configured_and_flags_missing() {
        let models = vec!["llama3.2".to_string(), "models/gemini-2.0-flash".to_string()];
        let ok = render_models(&provider("ollama", "openai", "", "llama3.2", "sk-secret"), &models, true);
        assert!(ok.contains("\x1b[32m●\x1b[0m llama3.2"));
        assert!(!ok.contains("NOT served") && !ok.contains("sk-secret"));
        // Gemini lists a "models/" prefix the config does not carry
        assert!(!render_models(&provider("gemini", "openai", "", "gemini-2.0-flash", ""), &models, true).contains("NOT served"));

        let groq = provider("groq", "openai", "", "llama-3.3-70b-versatile", "");
        let missing = render_models(&groq, &models, true);
        assert!(missing.contains("configured model \"llama-3.3-70b-versatile\" is NOT served by groq"));
        assert!(missing.contains("/model <model>"));
        assert!(render_models(&groq, &models, false).contains("/use groq <model>"));

        let many: Vec<String> = (0..60).map(|i| format!("m{i}")).collect();
        assert!(render_models(&provider("x", "openai", "", "m0", ""), &many, true).contains("and 10 more"));
    }

    #[test]
    fn discover_reports_only_runtimes_that_answer() {
        let (up, _) = stub("200 OK", r#"{"data":[{"id":"llama3.2"},{"id":"qwen3:8b"}]}"#);
        let (not_llm, _) = stub("404 Not Found", "<html>some dev server on :8080</html>");
        let dead = dead_url();
        let found = discover(&[("ollama", &up), ("llamacpp", &not_llm), ("vllm", &dead)]);
        assert_eq!(found, [LocalRuntime { id: "ollama".into(), base_url: up.clone(), models: vec!["llama3.2".into(), "qwen3:8b".into()] }]);

        let text = render_discovery(&found);
        assert!(text.contains("ollama") && text.contains("llama3.2 qwen3:8b") && !text.contains("vllm"));
        assert!(render_discovery(&[]).contains("no local runtime answered"));
    }

    #[test]
    fn resolve_runtime_picks_first_or_named_model() {
        let (up, _) = stub("200 OK", r#"{"models":[{"name":"llama3.2"},{"name":"qwen3:8b"}]}"#);
        let (empty, _) = stub("200 OK", r#"{"data":[]}"#);
        let dead = dead_url();
        let probes = [("ollama", up.as_str()), ("jan", empty.as_str()), ("vllm", dead.as_str())];

        assert_eq!(resolve_runtime(&probes, "ollama", None).unwrap(), (up.clone(), "llama3.2".to_string()));
        assert_eq!(resolve_runtime(&probes, "ollama", Some("qwen3:8b")).unwrap().1, "qwen3:8b");
        assert!(resolve_runtime(&probes, "ollama", Some("gpt-4o")).unwrap_err().contains("it has: llama3.2 qwen3:8b"));
        assert!(resolve_runtime(&probes, "jan", None).unwrap_err().contains("no models loaded"));
        assert!(resolve_runtime(&probes, "vllm", None).unwrap_err().contains("is it running?"));
        assert!(resolve_runtime(&probes, "nope", None).unwrap_err().starts_with("usage:"));
    }

    #[test]
    fn unregistered_hides_known_and_empty_runtimes() {
        let rt = |id: &str, url: &str, models: &[&str]| LocalRuntime {
            id: id.into(),
            base_url: url.into(),
            models: models.iter().map(|m| m.to_string()).collect(),
        };
        let mut st = ProviderState::defaults();
        st.add_local("mine".into(), "http://localhost:1234/v1".into(), "qwen".into(), String::new());
        let found = vec![
            rt("ollama", "http://localhost:11434/v1", &["llama3.2"]),
            rt("lmstudio", "http://localhost:1234/v1", &["qwen"]), // registered under another id
            rt("jan", "http://localhost:1337/v1", &[]),            // nothing to use
        ];
        let ids: Vec<String> = unregistered(found, &st).into_iter().map(|r| r.id).collect();
        assert_eq!(ids, ["ollama"]);
    }

    #[test]
    fn fetch_models_sends_auth_and_never_leaks_the_key() {
        // OpenAI-compatible: bearer header, {base}/models
        let (url, rx) = stub("200 OK", r#"{"data":[{"id":"m1"}]}"#);
        let p = provider("custom", "openai", &url, "m1", "sk-listing-secret");
        assert_eq!(fetch_models(&p, &p.key, PROBE_CONNECT, PROBE_TOTAL).unwrap(), ["m1"]);
        let req = rx.recv().unwrap().to_lowercase();
        assert!(req.starts_with("get /v1/models "), "{req}");
        assert!(req.contains("authorization: bearer sk-listing-secret"));

        // keyless local runtime: no auth header at all
        let (url, rx) = stub("200 OK", r#"{"data":[]}"#);
        fetch_models(&provider("ollama", "openai", &url, "", ""), "", PROBE_CONNECT, PROBE_TOTAL).unwrap();
        assert!(!rx.recv().unwrap().to_lowercase().contains("authorization"));

        // anthropic kind through a gateway base_url: x-api-key + version, /v1/models
        let (url, rx) = stub("200 OK", r#"{"data":[{"id":"claude-opus-5"}]}"#);
        let p = provider("claude", "anthropic", &url, "claude-opus-5", "sk-ant-secret");
        assert_eq!(fetch_models(&p, &p.key, PROBE_CONNECT, PROBE_TOTAL).unwrap(), ["claude-opus-5"]);
        let req = rx.recv().unwrap().to_lowercase();
        assert!(req.starts_with("get /v1/models?limit=100 "), "{req}");
        assert!(req.contains("x-api-key: sk-ant-secret") && req.contains("anthropic-version: 2023-06-01"));
        assert!(fetch_models(&p, "", PROBE_CONNECT, PROBE_TOTAL).unwrap_err().contains("ANTHROPIC_API_KEY"));

        // every failure mode: the key is in no error string, even when the server echoes it
        let (echo, _) = stub("401 Unauthorized", r#"{"error":"bad key sk-listing-secret"}"#);
        let (html, _) = stub("200 OK", "<html>");
        for url in [echo, html, dead_url(), "http://[::1".to_string()] {
            let p = provider("custom", "openai", &url, "m1", "sk-listing-secret");
            let err = fetch_models(&p, &p.key, PROBE_CONNECT, PROBE_TOTAL).unwrap_err();
            assert!(err.starts_with("custom"), "{err}");
            assert!(!err.contains("sk-listing-secret"), "{err}");
        }
    }

    #[test]
    fn completion_error_hints_and_never_leaks_the_key() {
        let p = provider("groq", "openai", "https://api.groq.com/openai/v1", "llama-3.3-70b-versatile", "gsk_supersecret");
        let long = format!(
            r#"{{"error":{{"message":"The model `llama-3.3-70b-versatile` does not exist, key gsk_supersecret {}","code":"model_not_found"}}}}"#,
            "x".repeat(500)
        );
        let e = completion_error(&p, &p.key, 404, &long);
        assert!(e.contains("model \"llama-3.3-70b-versatile\" looks unavailable (404)"));
        assert!(e.contains("/models") && e.contains("/model <id>"));
        assert!(!e.contains("gsk_supersecret"));
        assert!(e.chars().count() < 320, "body must stay truncated: {}", e.chars().count());
        assert!(e.contains("The model `llama-3.3-70b-versatile` does not exist") && !e.contains("{\"error\""));
        // Ollama's flat {"error": "..."} shape
        assert!(completion_error(&p, "", 404, r#"{"error":"model 'x' not found, try pulling it first"}"#).ends_with("try pulling it first"));

        // Groq retires models with a 400, not a 404
        assert!(completion_error(&p, &p.key, 400, r#"{"error":{"code":"model_decommissioned"}}"#).contains("looks unavailable"));
        // an ordinary failure keeps the old shape and gets no model hint
        let e = completion_error(&p, &p.key, 500, "upstream exploded gsk_supersecret");
        assert_eq!(e, "groq 500: upstream exploded ***");
        // 401 with no key at all: say how to supply one
        let e = completion_error(&p, "", 401, "unauthorized");
        assert!(e.contains("/key groq <key>") && e.contains("GROQ_API_KEY"));
    }
}
