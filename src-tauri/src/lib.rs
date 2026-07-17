use std::io::{Read, Write};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use std::path::PathBuf;
use std::sync::Mutex;

use portable_pty::{native_pty_system, Child, CommandBuilder, MasterPty, PtySize};
use tauri::{AppHandle, Emitter, Manager, State};

#[derive(Default)]
struct PtyState {
    master: Mutex<Option<Box<dyn MasterPty + Send>>>,
    writer: Mutex<Option<Box<dyn Write + Send>>>,
    child: Mutex<Option<Box<dyn Child + Send + Sync>>>,
    shell_pid: Mutex<Option<u32>>,
}

#[derive(serde::Serialize)]
struct ShellContext {
    cwd: Option<String>,
    branch: Option<String>,
    dirty: u32,
    shell_pid: Option<u32>,
}

fn parse_lsof_cwd(output: &str) -> Option<String> {
    output.lines().find(|l| l.starts_with('n')).map(|l| l[1..].to_string())
}

fn cwd_of_pid(pid: u32) -> Option<String> {
    let out = std::process::Command::new("lsof")
        .args(["-a", "-p", &pid.to_string(), "-d", "cwd", "-Fn"])
        .output()
        .ok()?;
    parse_lsof_cwd(&String::from_utf8_lossy(&out.stdout))
}

fn git_info(cwd: &str) -> (Option<String>, u32) {
    let branch = std::process::Command::new("git")
        .args(["-C", cwd, "rev-parse", "--abbrev-ref", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());
    let dirty = if branch.is_some() {
        std::process::Command::new("git")
            .args(["-C", cwd, "status", "--porcelain"])
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).lines().count() as u32)
            .unwrap_or(0)
    } else {
        0
    };
    (branch, dirty)
}

// OSC 133 shell integration: zsh hooks marking prompt/exec boundaries.
// \e / \a are text escapes interpreted by zsh's `print -n`, not raw bytes.
// precmd emits D;<prev exit> + A (prompt start); preexec emits C (output start).
// add-zsh-hook is idempotent, so re-injection would be harmless; the trailing
// `clear` erases the echoed injection line so the user sees a clean prompt.
fn shell_integration_script() -> String {
    concat!(
        "_tachyon_precmd(){ print -n \"\\e]133;D;$?\\a\\e]133;A\\a\"; }; ",
        "_tachyon_preexec(){ print -n \"\\e]133;C\\a\"; }; ",
        "autoload -Uz add-zsh-hook && add-zsh-hook precmd _tachyon_precmd && add-zsh-hook preexec _tachyon_preexec; clear\n"
    )
    .into()
}

#[tauri::command]
fn pty_spawn(app: AppHandle, state: State<PtyState>, rows: u16, cols: u16) -> Result<(), String> {
    let mut master_slot = state.master.lock().unwrap();
    if master_slot.is_some() {
        return Ok(()); // already running (e.g. frontend hot-reload)
    }

    let pair = native_pty_system()
        .openpty(PtySize { rows, cols, pixel_width: 0, pixel_height: 0 })
        .map_err(|e| e.to_string())?;

    let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/zsh".into());
    let mut cmd = CommandBuilder::new(&shell);
    cmd.env("TERM", "xterm-256color");
    if let Ok(home) = std::env::var("HOME") {
        cmd.cwd(home);
    }

    let child = pair.slave.spawn_command(cmd).map_err(|e| e.to_string())?;
    let mut reader = pair.master.try_clone_reader().map_err(|e| e.to_string())?;

    let mut writer = pair.master.take_writer().map_err(|e| e.to_string())?;
    if shell.ends_with("zsh") {
        // best-effort: frontend falls back to buffer scraping if hooks never load
        let _ = writer.write_all(shell_integration_script().as_bytes());
    }
    *state.writer.lock().unwrap() = Some(writer);
    *state.shell_pid.lock().unwrap() = child.process_id();
    *state.child.lock().unwrap() = Some(child);
    *master_slot = Some(pair.master);

    std::thread::spawn(move || {
        let mut buf = [0u8; 65536];
        loop {
            match reader.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let _ = app.emit("pty-output", STANDARD.encode(&buf[..n]));
                }
            }
        }
        let _ = app.emit("pty-exit", ());
    });

    Ok(())
}

#[tauri::command]
fn pty_write(state: State<PtyState>, data: String) -> Result<(), String> {
    match state.writer.lock().unwrap().as_mut() {
        Some(w) => w.write_all(data.as_bytes()).map_err(|e| e.to_string()),
        None => Err("pty not spawned".into()),
    }
}

#[tauri::command]
fn pty_resize(state: State<PtyState>, rows: u16, cols: u16) -> Result<(), String> {
    match state.master.lock().unwrap().as_ref() {
        Some(m) => m
            .resize(PtySize { rows, cols, pixel_width: 0, pixel_height: 0 })
            .map_err(|e| e.to_string()),
        None => Err("pty not spawned".into()),
    }
}

const DANGER_PATTERNS: &[&str] = &[
    "rm -rf",
    "rm -fr",
    "sudo rm",
    "of=/dev",
    "mkfs",
    "> /dev/sd",
    "chmod -r 777 /",
    ":(){",
    "shutdown",
    "reboot",
];

// ponytail: lowercase substring scan — warn-only UI, false positives accepted by design
pub fn is_dangerous(cmd: &str) -> bool {
    let lower = cmd.to_lowercase();
    DANGER_PATTERNS.iter().any(|p| lower.contains(p))
}

#[tauri::command]
fn check_dangerous(cmd: String) -> bool {
    is_dangerous(&cmd)
}

// ---- Provider registry ----
// All AI HTTP happens in Rust via ai_complete below (anthropic → /v1/messages, anything else
// is OpenAI-compatible → `${base_url}/chat/completions`). Keys never reach the webview.
// Config persists to ~/.config/tachyon/providers.json.

#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct Provider {
    id: String,
    kind: String,
    base_url: String,
    model: String,
    #[serde(default)]
    key: String,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct ProviderState {
    active: String,
    providers: Vec<Provider>,
}

fn builtin(id: &str, kind: &str, base_url: &str, model: &str) -> Provider {
    Provider { id: id.into(), kind: kind.into(), base_url: base_url.into(), model: model.into(), key: String::new() }
}

impl ProviderState {
    fn defaults() -> Self {
        ProviderState {
            active: "claude".into(),
            providers: vec![
                builtin("claude", "anthropic", "", "claude-opus-4-8"),
                builtin("openai", "openai", "https://api.openai.com/v1", "gpt-4o"),
                builtin("groq", "openai", "https://api.groq.com/openai/v1", "llama-3.3-70b-versatile"),
                builtin("gemini", "openai", "https://generativelanguage.googleapis.com/v1beta/openai", "gemini-2.0-flash"),
                builtin("kimi", "openai", "https://api.moonshot.ai/v1", "moonshot-v1-8k"),
                builtin("deepseek", "openai", "https://api.deepseek.com", "deepseek-chat"),
                builtin("mistral", "openai", "https://api.mistral.ai/v1", "mistral-large-latest"),
            ],
        }
    }

    // add any built-in providers a saved config predates, keeping user keys/models
    fn merge_defaults(&mut self) {
        for d in ProviderState::defaults().providers {
            if !self.providers.iter().any(|p| p.id == d.id) {
                self.providers.push(d);
            }
        }
    }

    fn find_mut(&mut self, id: &str) -> Result<&mut Provider, String> {
        self.providers.iter_mut().find(|p| p.id == id).ok_or_else(|| format!("unknown provider: {id}"))
    }

    fn set_key(&mut self, id: &str, key: String) -> Result<(), String> {
        self.find_mut(id)?.key = key;
        Ok(())
    }

    fn set_model(&mut self, id: &str, model: String) -> Result<(), String> {
        self.find_mut(id)?.model = model;
        Ok(())
    }

    fn use_provider(&mut self, id: &str) -> Result<(), String> {
        self.find_mut(id)?; // validate exists
        self.active = id.into();
        Ok(())
    }

    fn add_local(&mut self, id: String, base_url: String, model: String, key: String) {
        let p = Provider { id: id.clone(), kind: "openai".into(), base_url, model, key };
        match self.providers.iter_mut().find(|x| x.id == id) {
            Some(existing) => *existing = p,
            None => self.providers.push(p),
        }
    }

    fn active_provider(&self) -> Provider {
        self.providers
            .iter()
            .find(|p| p.id == self.active)
            .cloned()
            .unwrap_or_else(|| ProviderState::defaults().providers.remove(0))
    }
}

fn providers_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_default();
    PathBuf::from(home).join(".config/tachyon/providers.json")
}

fn load_state() -> ProviderState {
    let mut state = std::fs::read_to_string(providers_path())
        .ok()
        .and_then(|s| serde_json::from_str::<ProviderState>(&s).ok())
        .unwrap_or_else(ProviderState::defaults);
    state.merge_defaults();
    state
}

fn save_state(state: &ProviderState) -> Result<(), String> {
    let path = providers_path();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    let json = serde_json::to_string_pretty(state).map_err(|e| e.to_string())?;
    std::fs::write(path, json).map_err(|e| e.to_string())
}

fn mutate<F: FnOnce(&mut ProviderState) -> Result<(), String>>(f: F) -> Result<ProviderState, String> {
    let mut state = load_state();
    f(&mut state)?;
    save_state(&state)?;
    Ok(state)
}

#[tauri::command]
fn provider_state() -> ProviderState {
    load_state()
}

#[tauri::command]
fn provider_active() -> Provider {
    load_state().active_provider()
}

#[tauri::command]
fn provider_set_key(id: String, key: String) -> Result<ProviderState, String> {
    mutate(|s| s.set_key(&id, key))
}

#[tauri::command]
fn provider_set_model(id: String, model: String) -> Result<ProviderState, String> {
    mutate(|s| s.set_model(&id, model))
}

#[tauri::command]
fn provider_use(id: String) -> Result<ProviderState, String> {
    mutate(|s| s.use_provider(&id))
}

#[tauri::command]
fn provider_add_local(id: String, base_url: String, model: String, key: String) -> Result<ProviderState, String> {
    mutate(|s| {
        s.add_local(id, base_url, model, key);
        Ok(())
    })
}

// ---- AI completion ----
// Request/response shaping lives in pure helpers so they unit-test without a network.

fn build_anthropic_body(model: &str, system: &str, user: &str) -> serde_json::Value {
    serde_json::json!({
        "model": model,
        "max_tokens": 1024,
        "system": system,
        "messages": [{"role": "user", "content": user}]
    })
}

fn build_openai_body(model: &str, system: &str, user: &str) -> serde_json::Value {
    serde_json::json!({
        "model": model,
        "max_tokens": 1024,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user}
        ]
    })
}

// first content block of type "text" wins — tolerates a leading thinking block
fn parse_anthropic_response(body: &str) -> Result<String, String> {
    let v: serde_json::Value = serde_json::from_str(body).map_err(|e| e.to_string())?;
    v.get("content")
        .and_then(|c| c.as_array())
        .and_then(|arr| arr.iter().find(|b| b.get("type").and_then(|t| t.as_str()) == Some("text")))
        .and_then(|b| b.get("text"))
        .and_then(|t| t.as_str())
        .map(String::from)
        .ok_or_else(|| "no text content in response".into())
}

fn parse_openai_response(body: &str) -> Result<String, String> {
    let v: serde_json::Value = serde_json::from_str(body).map_err(|e| e.to_string())?;
    v.pointer("/choices/0/message/content")
        .and_then(|c| c.as_str())
        .map(String::from)
        .ok_or_else(|| "no choices[0].message.content in response".into())
}

// The key appears ONLY in request headers — never in any error/log string.
#[tauri::command]
async fn ai_complete(system: String, user: String) -> Result<String, String> {
    let p = load_state().active_provider();
    let client = reqwest::Client::new(); // ponytail: per-call client; OnceLock<Client> if profiling ever cares
    let is_anthropic = p.kind == "anthropic";
    let req = if is_anthropic {
        if p.key.is_empty() {
            return Err(format!("no key for {} — set with /key {} <key>", p.id, p.id));
        }
        client
            .post("https://api.anthropic.com/v1/messages")
            .header("x-api-key", &p.key)
            .header("anthropic-version", "2023-06-01")
            .json(&build_anthropic_body(&p.model, &system, &user))
    } else {
        // OpenAI-compatible (openai, groq, gemini, kimi, deepseek, mistral, local). Local may have no key.
        let mut r = client
            .post(format!("{}/chat/completions", p.base_url))
            .json(&build_openai_body(&p.model, &system, &user));
        if !p.key.is_empty() {
            r = r.bearer_auth(&p.key);
        }
        r
    };
    let resp = req.send().await.map_err(|e| format!("{}: {}", p.id, e.without_url()))?;
    let status = resp.status();
    let body = resp.text().await.map_err(|e| format!("{}: {}", p.id, e.without_url()))?;
    if !status.is_success() {
        return Err(format!("{} {}: {}", p.id, status.as_u16(), truncate_chars(&body, 120)));
    }
    if is_anthropic { parse_anthropic_response(&body) } else { parse_openai_response(&body) }
}

// ---- MCP client (Streamable HTTP) ----
// Remote MCP servers only: JSON-RPC 2.0 over HTTP POST (no stdio). Config persists
// to ~/.config/tachyon/mcp.json, separate from providers.json.

#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct McpServer {
    name: String,
    url: String,
}

#[derive(Clone, Default, serde::Serialize, serde::Deserialize)]
struct McpConfig {
    servers: Vec<McpServer>,
}

#[derive(Clone, serde::Serialize)]
struct McpTool {
    name: String,
    description: String,
    input_schema: serde_json::Value,
}

#[derive(Clone, serde::Serialize)]
struct McpServerTool {
    server: String,
    name: String,
    description: String,
    input_schema: serde_json::Value,
}

fn mcp_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_default();
    PathBuf::from(home).join(".config/tachyon/mcp.json")
}

fn load_mcp() -> McpConfig {
    std::fs::read_to_string(mcp_path())
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_mcp(cfg: &McpConfig) -> Result<(), String> {
    let path = mcp_path();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    let json = serde_json::to_string_pretty(cfg).map_err(|e| e.to_string())?;
    std::fs::write(path, json).map_err(|e| e.to_string())
}

fn jsonrpc_request(id: u64, method: &str, params: serde_json::Value) -> serde_json::Value {
    serde_json::json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params })
}

// ponytail: SSE parsing takes the last "data:" line — fine for single-response
// streams; match on .id + join continuation lines if a real server needs it
fn parse_rpc_result(body: &str, content_type: &str) -> Result<serde_json::Value, String> {
    let payload = if content_type.contains("text/event-stream") {
        body.lines()
            .filter_map(|l| l.strip_prefix("data:"))
            .last()
            .ok_or("no data line in SSE response")?
            .trim()
            .to_string()
    } else {
        body.to_string()
    };
    let v: serde_json::Value = serde_json::from_str(&payload).map_err(|e| e.to_string())?;
    if let Some(err) = v.get("error") {
        return Err(err.get("message").and_then(|m| m.as_str()).map(String::from).unwrap_or_else(|| err.to_string()));
    }
    v.get("result").cloned().ok_or_else(|| "no result in response".into())
}

fn parse_tools(result: &serde_json::Value) -> Vec<McpTool> {
    result
        .get("tools")
        .and_then(|t| t.as_array())
        .map(|arr| {
            arr.iter()
                .map(|t| McpTool {
                    name: t.get("name").and_then(|v| v.as_str()).unwrap_or_default().into(),
                    description: t.get("description").and_then(|v| v.as_str()).unwrap_or_default().into(),
                    input_schema: match t.get("inputSchema") {
                        Some(s) if !s.is_null() => s.clone(),
                        _ => serde_json::json!({}),
                    },
                })
                .collect()
        })
        .unwrap_or_default()
}

fn truncate_chars(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

// one POST; returns (body, content_type, mcp-session-id header)
fn mcp_post(
    agent: &ureq::Agent,
    url: &str,
    session: Option<&str>,
    body: &serde_json::Value,
) -> Result<(String, String, Option<String>), String> {
    let mut req = agent
        .post(url)
        .set("Content-Type", "application/json")
        .set("Accept", "application/json, text/event-stream");
    if let Some(sid) = session {
        req = req.set("Mcp-Session-Id", sid);
    }
    match req.send_json(body) {
        Ok(resp) => {
            let sid = resp.header("mcp-session-id").map(String::from);
            let ct = resp.header("content-type").unwrap_or("application/json").to_string();
            let body = resp.into_string().map_err(|e| e.to_string())?;
            Ok((body, ct, sid))
        }
        Err(ureq::Error::Status(code, resp)) => {
            let body = resp.into_string().unwrap_or_default();
            Err(format!("{url} HTTP {code}: {}", truncate_chars(&body, 200)))
        }
        Err(e) => Err(e.to_string()),
    }
}

// Streamable HTTP handshake: initialize → notifications/initialized → the actual request.
// ponytail: fresh 3-POST session per call, no session cache — add one if latency matters
fn mcp_rpc_session(url: &str, method: &str, params: serde_json::Value) -> Result<serde_json::Value, String> {
    let agent = ureq::AgentBuilder::new().timeout(std::time::Duration::from_secs(15)).build();
    let init = jsonrpc_request(
        1,
        "initialize",
        serde_json::json!({
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": { "name": "tachyon", "version": "0.1" }
        }),
    );
    let (body, ct, session) = mcp_post(&agent, url, None, &init)?;
    parse_rpc_result(&body, &ct)?; // surface initialize errors early
    // notification (no id); response ignored, never fatal
    let _ = mcp_post(
        &agent,
        url,
        session.as_deref(),
        &serde_json::json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
    );
    let (body, ct, _) = mcp_post(&agent, url, session.as_deref(), &jsonrpc_request(2, method, params))?;
    parse_rpc_result(&body, &ct)
}

#[tauri::command]
fn mcp_add(name: String, url: String) -> Result<(), String> {
    let mut cfg = load_mcp();
    let s = McpServer { name: name.clone(), url };
    match cfg.servers.iter_mut().find(|x| x.name == name) {
        Some(existing) => *existing = s,
        None => cfg.servers.push(s),
    }
    save_mcp(&cfg)
}

#[tauri::command]
fn mcp_remove(name: String) -> Result<(), String> {
    let mut cfg = load_mcp();
    let before = cfg.servers.len();
    cfg.servers.retain(|s| s.name != name);
    if cfg.servers.len() == before {
        return Err(format!("unknown server: {name}"));
    }
    save_mcp(&cfg)
}

#[tauri::command]
fn mcp_servers() -> Vec<McpServer> {
    load_mcp().servers
}

// (async): blocking HTTP must not run on the main thread
#[tauri::command(async)]
fn mcp_list_tools() -> Result<Vec<McpServerTool>, String> {
    let servers = load_mcp().servers;
    let mut out = Vec::new();
    let mut errs = Vec::new();
    for s in &servers {
        match mcp_rpc_session(&s.url, "tools/list", serde_json::json!({})) {
            Ok(result) => out.extend(parse_tools(&result).into_iter().map(|t| McpServerTool {
                server: s.name.clone(),
                name: t.name,
                description: t.description,
                input_schema: t.input_schema,
            })),
            Err(e) => errs.push(format!("{}: {e}", s.name)), // one bad server doesn't break the list
        }
    }
    if out.is_empty() && !errs.is_empty() && !servers.is_empty() {
        return Err(errs.join("; "));
    }
    Ok(out)
}

#[tauri::command(async)]
fn mcp_call(server: String, tool: String, args: serde_json::Value) -> Result<String, String> {
    let url = load_mcp()
        .servers
        .iter()
        .find(|s| s.name == server)
        .map(|s| s.url.clone())
        .ok_or_else(|| format!("unknown server: {server}"))?;
    let result = mcp_rpc_session(&url, "tools/call", serde_json::json!({ "name": tool, "arguments": args }))?;
    let text = result
        .get("content")
        .and_then(|c| c.as_array())
        .map(|blocks| {
            blocks
                .iter()
                .filter(|b| b.get("type").and_then(|t| t.as_str()) == Some("text"))
                .filter_map(|b| b.get("text").and_then(|t| t.as_str()))
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_default();
    let text = if text.is_empty() { result.to_string() } else { text };
    Ok(truncate_chars(&text, 4000))
}

#[tauri::command]
async fn get_context(state: State<'_, PtyState>) -> Result<ShellContext, String> {
    let pid = *state.shell_pid.lock().unwrap();
    let cwd = pid.and_then(cwd_of_pid);
    let (branch, dirty) = cwd.as_deref().map(git_info).unwrap_or((None, 0));
    Ok(ShellContext { cwd, branch, dirty, shell_pid: pid })
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            app.manage(PtyState::default());
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            pty_spawn,
            pty_write,
            pty_resize,
            get_context,
            check_dangerous,
            provider_state,
            provider_active,
            provider_set_key,
            provider_set_model,
            provider_use,
            provider_add_local,
            ai_complete,
            mcp_add,
            mcp_remove,
            mcp_servers,
            mcp_list_tools,
            mcp_call
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[cfg(test)]
mod tests {
    use super::*;

    // captured from real `lsof -a -p <pid> -d cwd -Fn` on this machine
    const LSOF_SAMPLE: &str = "p86425\nfcwd\nn/Users/ayush18/tachyon\n";

    #[test]
    fn parse_lsof_cwd_sample() {
        assert_eq!(parse_lsof_cwd(LSOF_SAMPLE), Some("/Users/ayush18/tachyon".into()));
    }

    #[test]
    fn parse_lsof_cwd_garbage() {
        assert_eq!(parse_lsof_cwd("total garbage\nxyz 123"), None);
        assert_eq!(parse_lsof_cwd(""), None);
    }

    #[test]
    fn cwd_of_self_matches_current_dir() {
        let cwd = cwd_of_pid(std::process::id()).expect("lsof gave no cwd");
        assert_eq!(std::path::PathBuf::from(cwd), std::env::current_dir().unwrap());
    }

    #[test]
    fn git_info_this_repo() {
        // run against this crate's own directory (a git repo) so the test is
        // machine-independent — CARGO_MANIFEST_DIR resolves on any checkout, incl. CI.
        // Detached-HEAD checkouts (tags/PRs) yield "HEAD", so assert only that a branch resolved.
        let (branch, _dirty) = git_info(env!("CARGO_MANIFEST_DIR"));
        assert!(branch.is_some(), "expected a git branch, got None");
    }

    #[test]
    fn git_info_non_git_dir() {
        assert_eq!(git_info("/"), (None, 0));
    }

    #[test]
    fn shell_integration_script_shape() {
        let s = shell_integration_script();
        for needle in [
            "add-zsh-hook precmd",
            "add-zsh-hook preexec",
            "print -n",
            "\\e]133;D;$?\\a",
            "\\e]133;A\\a",
            "\\e]133;C\\a",
        ] {
            assert!(s.contains(needle), "missing {needle}");
        }
        assert!(s.ends_with('\n'));
    }

    #[test]
    fn dangerous_positives() {
        for cmd in [
            "rm -rf /tmp/x",
            "rm -fr .",
            "sudo rm file",
            "dd if=/dev/zero of=/dev/disk2",
            "mkfs.ext4 /dev/sdb1",
            ":(){ :|:& };:",
            "RM -RF /",
            "shutdown -h now",
            "sudo reboot",
            "chmod -R 777 /",
        ] {
            assert!(is_dangerous(cmd), "{cmd}");
        }
    }

    #[test]
    fn dangerous_negatives() {
        for cmd in ["ls -la", "git status", "npm run dev", "rm file.txt", "grep -rf pattern .", "mkdir -p src"] {
            assert!(!is_dangerous(cmd), "{cmd}");
        }
    }

    #[test]
    fn provider_defaults_cover_expected() {
        let s = ProviderState::defaults();
        for id in ["claude", "openai", "groq", "gemini", "kimi", "deepseek", "mistral"] {
            assert!(s.providers.iter().any(|p| p.id == id), "missing {id}");
        }
        assert_eq!(s.active_provider().id, "claude");
    }

    #[test]
    fn provider_set_and_use() {
        let mut s = ProviderState::defaults();
        s.set_key("groq", "gsk_test".into()).unwrap();
        s.set_model("groq", "llama-3.1-8b-instant".into()).unwrap();
        s.use_provider("groq").unwrap();
        let a = s.active_provider();
        assert_eq!(a.id, "groq");
        assert_eq!(a.key, "gsk_test");
        assert_eq!(a.model, "llama-3.1-8b-instant");
    }

    #[test]
    fn provider_unknown_id_errors() {
        let mut s = ProviderState::defaults();
        assert!(s.use_provider("nope").is_err());
        assert!(s.set_key("nope", "x".into()).is_err());
    }

    #[test]
    fn provider_add_local_upserts() {
        let mut s = ProviderState::defaults();
        s.add_local("ollama".into(), "http://localhost:11434/v1".into(), "llama3.2".into(), String::new());
        s.use_provider("ollama").unwrap();
        assert_eq!(s.active_provider().base_url, "http://localhost:11434/v1");
        // second add with same id replaces, not duplicates
        s.add_local("ollama".into(), "http://localhost:1234/v1".into(), "qwen".into(), String::new());
        assert_eq!(s.providers.iter().filter(|p| p.id == "ollama").count(), 1);
        assert_eq!(s.active_provider().model, "qwen");
    }

    #[test]
    fn jsonrpc_request_shape() {
        assert_eq!(
            jsonrpc_request(1, "tools/list", serde_json::json!({})),
            serde_json::json!({"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}})
        );
    }

    #[test]
    fn parse_rpc_result_json() {
        let body = r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}"#;
        let r = parse_rpc_result(body, "application/json").unwrap();
        assert_eq!(r, serde_json::json!({"tools":[]}));
    }

    #[test]
    fn parse_rpc_result_sse() {
        let body = "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[]}}\n\n";
        let r = parse_rpc_result(body, "text/event-stream").unwrap();
        assert_eq!(r, serde_json::json!({"tools":[]}));
        // last data line wins
        let two = "data: {\"jsonrpc\":\"2.0\",\"result\":{\"n\":1}}\n\ndata: {\"jsonrpc\":\"2.0\",\"result\":{\"n\":2}}\n\n";
        assert_eq!(parse_rpc_result(two, "text/event-stream").unwrap(), serde_json::json!({"n":2}));
    }

    #[test]
    fn parse_rpc_result_error() {
        let body = r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32600,"message":"bad"}}"#;
        let err = parse_rpc_result(body, "application/json").unwrap_err();
        assert!(err.contains("bad"), "{err}");
    }

    #[test]
    fn parse_tools_sample() {
        let result = serde_json::json!({"tools":[
            {"name":"echo","description":"Echoes","inputSchema":{"type":"object"}},
            {"name":"nodesc"}
        ]});
        let tools = parse_tools(&result);
        assert_eq!(tools.len(), 2);
        assert_eq!(tools[0].name, "echo");
        assert_eq!(tools[0].description, "Echoes");
        assert_eq!(tools[0].input_schema, serde_json::json!({"type":"object"}));
        assert_eq!(tools[1].description, "");
        assert_eq!(tools[1].input_schema, serde_json::json!({}));
    }

    #[test]
    fn merge_defaults_keeps_user_and_adds_missing() {
        let mut s = ProviderState { active: "groq".into(), providers: vec![builtin("groq", "openai", "x", "m")] };
        s.providers[0].key = "keep".into();
        s.merge_defaults();
        assert_eq!(s.providers.iter().find(|p| p.id == "groq").unwrap().key, "keep");
        assert!(s.providers.iter().any(|p| p.id == "mistral"));
    }

    #[test]
    fn anthropic_body_shape() {
        assert_eq!(
            build_anthropic_body("m", "sys", "hi"),
            serde_json::json!({
                "model": "m", "max_tokens": 1024, "system": "sys",
                "messages": [{"role": "user", "content": "hi"}]
            })
        );
    }

    #[test]
    fn openai_body_shape() {
        assert_eq!(
            build_openai_body("m", "sys", "hi"),
            serde_json::json!({
                "model": "m", "max_tokens": 1024,
                "messages": [{"role": "system", "content": "sys"}, {"role": "user", "content": "hi"}]
            })
        );
    }

    #[test]
    fn parse_anthropic_ok_and_skips_non_text() {
        let body = r#"{"content":[{"type":"thinking","thinking":"..."},{"type":"text","text":"hello"}]}"#;
        assert_eq!(parse_anthropic_response(body).unwrap(), "hello");
    }

    #[test]
    fn parse_anthropic_error_payload() {
        assert!(parse_anthropic_response(r#"{"type":"error","error":{"type":"authentication_error","message":"x"}}"#).is_err());
        assert!(parse_anthropic_response("not json").is_err());
        assert!(parse_anthropic_response(r#"{"content":[]}"#).is_err());
    }

    #[test]
    fn parse_openai_ok() {
        let body = r#"{"choices":[{"message":{"role":"assistant","content":"hi"}}]}"#;
        assert_eq!(parse_openai_response(body).unwrap(), "hi");
    }

    #[test]
    fn parse_openai_missing_or_error() {
        assert!(parse_openai_response(r#"{"error":{"message":"bad key"}}"#).is_err());
        assert!(parse_openai_response(r#"{"choices":[]}"#).is_err());
        assert!(parse_openai_response("not json").is_err());
    }

    #[test]
    fn pty_output_base64_roundtrip() {
        // bytes exercise non-ASCII + padding, like real pty chunks
        let bytes: &[u8] = b"hi\x1b]133;A\x07\xff\x00";
        let enc = STANDARD.encode(bytes);
        assert_eq!(enc, "aGkbXTEzMztBB/8A");
        assert_eq!(STANDARD.decode(&enc).unwrap(), bytes);
    }
}
