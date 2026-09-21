//! Tachyon as an MCP *server* (Streamable HTTP, plain JSON responses): external agents get
//! the user's live terminal, through the same human approval gate as the built-in agent.
//!
//! SECURITY — this is the most exposed surface in the app. What holds, and where:
//!   * off by default; `/mcp serve on` is the only switch (`slash`), persisted in
//!     mcp-server.json via write_config (0600, atomic);
//!   * the listener binds the literal 127.0.0.1 (`start`), never a wildcard;
//!   * every request passes `admit` BEFORE its body is read: Host must be local (DNS
//!     rebinding), any Origin must be local (a web page must not drive the terminal),
//!     and the bearer token must match in constant time;
//!   * `run_command` never writes to the PTY itself — `run_gated` claims the single approval
//!     slot, shows the exact string in the approval bar via `agent_propose`, and writes that
//!     same string only after a human Enter. No allowlist, no trusted client, no timeout
//!     that approves;
//!   * the token is printed by `/mcp serve status` and nowhere else: no error, response or
//!     event carries it, and nothing here logs.
//!
//! See docs/danger-gate.md → "Threat model: Tachyon as an MCP server".

use super::*;
use serde_json::{json, Value};
use std::sync::Arc;

// Below macOS's and Linux's ephemeral ranges, so an outbound connection never squats on it.
const DEFAULT_PORT: u16 = 47600;
const MAX_BODY: u64 = 1 << 20;
// The approval bar is a single-line input; a command the user cannot read is not approved
// in any meaningful sense.
const MAX_COMMAND_CHARS: usize = 4096;
const OUTPUT_CHARS: usize = 4000;
// newest first: an unknown requested version is answered with our latest, per the spec
const PROTOCOL_VERSIONS: &[&str] = &["2025-06-18", "2025-03-26", "2024-11-05"];
const BUSY: &str = "terminal busy: the built-in agent is running or another run_command is awaiting approval \u{2014} retry when it finishes";
const DENIED: &str = "the user denied this command";

// ---- config (mcp-server.json) ----

// No Debug: a derived one would put the token into any assert or panic message.
#[derive(serde::Serialize, serde::Deserialize, Clone)]
#[serde(default)]
struct ServeConfig {
    enabled: bool,
    port: u16,
    token: String,
}

impl Default for ServeConfig {
    fn default() -> Self {
        ServeConfig { enabled: false, port: DEFAULT_PORT, token: String::new() }
    }
}

fn serve_path() -> Result<PathBuf, String> {
    Ok(config_dir()?.join("mcp-server.json"))
}

fn load_serve(path: &std::path::Path) -> Result<ServeConfig, String> {
    Ok(read_config::<ServeConfig>(path)?.unwrap_or_default())
}

// ponytail: /dev/urandom — Tachyon ships for macOS and Linux only (see the CI matrix). A
// Windows port needs the `getrandom` crate here. Failing is deliberate: no weak fallback.
fn generate_token() -> Result<String, String> {
    let mut buf = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut buf))
        .map_err(|e| format!("no secure random source: {e}"))?;
    Ok(buf.iter().map(|b| format!("{b:02x}")).collect())
}

/// Turn the server on in the config: keep an existing token (clients are configured with
/// it), mint one on first enable, optionally move the port.
fn enable(path: &std::path::Path, port: Option<u16>) -> Result<ServeConfig, String> {
    let mut cfg = load_serve(path)?;
    if cfg.token.is_empty() {
        cfg.token = generate_token()?;
    }
    if let Some(p) = port {
        cfg.port = p;
    }
    cfg.enabled = true;
    Ok(cfg)
}

// ---- admission: Host, Origin, bearer token ----

// black_box keeps the fold from being optimised into an early-exit compare. Length is not
// secret: the token is always 64 hex chars.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && std::hint::black_box(a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y))) == 0
}

// Exact host match after splitting an all-digit port, so `localhost.evil.com`,
// `localhost@evil.com` and `127.0.0.1.evil.com` all fail.
fn is_local_host(hostport: &str) -> bool {
    let host = match hostport.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => h,
        _ => hostport,
    };
    matches!(host.to_ascii_lowercase().as_str(), "localhost" | "127.0.0.1" | "[::1]")
}

// `null` (sandboxed iframe, file://) is not local.
fn origin_ok(origin: &str) -> bool {
    origin.strip_prefix("http://").or_else(|| origin.strip_prefix("https://")).is_some_and(is_local_host)
}

fn bearer_ok(header: Option<&str>, token: &str) -> bool {
    let Some(given) = header.and_then(|h| strip_prefix_ci(h, "Bearer ")) else {
        return false;
    };
    // an empty configured token must never match an empty presented one
    !token.is_empty() && ct_eq(given.trim().as_bytes(), token.as_bytes())
}

/// `Err(http status)`. Takes every Host/Origin header, not the first: a request smuggling a
/// second, hostile one is rejected rather than half-trusted. Origin before auth so a browser
/// learns nothing about the token.
fn admit(hosts: &[&str], origins: &[&str], auth: Option<&str>, token: &str) -> Result<(), u16> {
    if hosts.is_empty() || !hosts.iter().all(|h| is_local_host(h)) {
        return Err(403);
    }
    if !origins.iter().all(|o| origin_ok(o)) {
        return Err(403);
    }
    if !bearer_ok(auth, token) {
        return Err(401);
    }
    Ok(())
}

// ---- JSON-RPC / MCP dispatch (pure: the terminal is behind `Backend`) ----

/// The one seam in this module: the live terminal in the app, a stub in tests.
pub(crate) trait Backend: Send + Sync {
    /// `Ok` = the command ran (whatever its exit code). `Err` = it did not run.
    fn run_command(&self, command: &str) -> Result<String, String>;
    fn read_journal(&self, limit: usize) -> String;
    fn get_context(&self) -> Result<String, String>;
}

fn rpc_error(id: Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

fn tool_list() -> Value {
    json!({ "tools": [
        {
            "name": "run_command",
            "description": "Run one shell command in the user's live Tachyon terminal. The user sees the exact command and must approve it with a keypress; a denial is returned as an error. Returns the exit code and truncated output. One command at a time.",
            "inputSchema": {
                "type": "object",
                "properties": { "command": { "type": "string", "description": "A single shell command. Line breaks are folded to `; `; control characters are rejected." } },
                "required": ["command"],
                "additionalProperties": false
            },
            "annotations": { "readOnlyHint": false, "destructiveHint": true, "openWorldHint": true }
        },
        {
            "name": "read_journal",
            "description": "Recent commands from the terminal's journal: command, exit code, truncated output. Read-only.",
            "inputSchema": {
                "type": "object",
                "properties": { "limit": { "type": "integer", "minimum": 1, "maximum": 50, "description": "How many of the most recent commands (default 10)." } },
                "additionalProperties": false
            },
            "annotations": { "readOnlyHint": true }
        },
        {
            "name": "get_context",
            "description": "The terminal's working directory, git branch and dirty-file count, and shell. Read-only.",
            "inputSchema": { "type": "object", "properties": {}, "additionalProperties": false },
            "annotations": { "readOnlyHint": true }
        }
    ] })
}

/// The string returned here is the string shown in the approval bar AND the string written
/// to the PTY, so everything that could make those differ is settled now. `one_line` folds
/// `\n`; it does not fold a bare `\r`, which an <input> strips from display but a PTY treats
/// as Enter — so any control character left after folding is refused, as are the bidi
/// overrides that reorder what the approver reads.
fn parse_run_args(args: &Value) -> Result<String, String> {
    let raw = args.get("command").and_then(Value::as_str).ok_or("run_command: `command` (string) is required")?;
    // Checked on the RAW input, before one_line: one_line sanitizes control characters out of
    // a model's reply (a model cannot be refused), but an external client that sends a bare
    // CR, a tab or an escape sequence is refused outright rather than quietly cleaned up.
    // Line breaks (\n, \r\n) are legitimate — they are folded and shown, like the agent's.
    if raw.replace("\r\n", "\n").chars().any(|c| (c.is_control() && c != '\n') || crate::is_invisible(c)) {
        return Err("run_command: `command` contains control or bidi-override characters".into());
    }
    let cmd = one_line(raw);
    if cmd.is_empty() {
        return Err("run_command: `command` is empty".into());
    }
    if cmd.chars().count() > MAX_COMMAND_CHARS {
        return Err(format!("run_command: `command` is longer than {MAX_COMMAND_CHARS} characters"));
    }
    // Unreachable while one_line drops both classes — kept so a change there cannot open the
    // external path silently.
    if cmd.chars().any(|c| c.is_control() || crate::is_invisible(c)) {
        return Err("run_command: `command` contains control or bidi-override characters".into());
    }
    Ok(cmd)
}

fn parse_limit(args: &Value) -> Result<usize, String> {
    match args.get("limit") {
        None | Some(Value::Null) => Ok(10),
        Some(v) => match v.as_u64() {
            Some(n @ 1..=50) => Ok(n as usize),
            _ => Err("read_journal: `limit` must be an integer from 1 to 50".into()),
        },
    }
}

fn tool_result(text: String, is_error: bool) -> Value {
    json!({ "content": [{ "type": "text", "text": text }], "isError": is_error })
}

/// `Err` = protocol error (-32602: unknown tool, bad arguments). A tool that was validly
/// called and failed — denied, busy — is an `Ok` result with `isError: true`.
fn call_tool(params: &Value, backend: &dyn Backend) -> Result<Value, String> {
    let name = params.get("name").and_then(Value::as_str).ok_or("tools/call: `name` is required")?;
    let empty = json!({});
    let args = params.get("arguments").unwrap_or(&empty);
    let outcome = match name {
        "run_command" => backend.run_command(&parse_run_args(args)?),
        "read_journal" => Ok(backend.read_journal(parse_limit(args)?)),
        "get_context" => backend.get_context(),
        other => return Err(format!("unknown tool: {other}")),
    };
    Ok(match outcome {
        Ok(text) => tool_result(text, false),
        Err(text) => tool_result(text, true),
    })
}

/// One JSON-RPC message in, one out. `None` = a notification: the HTTP layer answers 202.
// ponytail: no batch arrays (dropped from MCP in 2025-06-18) — an array is -32600.
fn handle_rpc(body: &str, backend: &dyn Backend) -> Option<Value> {
    let Ok(msg) = serde_json::from_str::<Value>(body) else {
        return Some(rpc_error(Value::Null, -32700, "parse error"));
    };
    let id = msg.get("id").cloned();
    let Some(method) = msg.get("method").and_then(Value::as_str) else {
        return Some(rpc_error(id.unwrap_or(Value::Null), -32600, "invalid request"));
    };
    let id = id?; // no id → notification (notifications/initialized and anything else)
    let empty = json!({});
    let params = msg.get("params").unwrap_or(&empty);
    let result = match method {
        "initialize" => {
            let asked = params.get("protocolVersion").and_then(Value::as_str).unwrap_or("");
            let version = PROTOCOL_VERSIONS.iter().find(|v| **v == asked).unwrap_or(&PROTOCOL_VERSIONS[0]);
            Ok(json!({
                "protocolVersion": version,
                "capabilities": { "tools": {} },
                "serverInfo": { "name": "tachyon", "version": env!("CARGO_PKG_VERSION") },
                "instructions": "Every run_command is shown to the user for approval before it runs; expect it to block until they decide."
            }))
        }
        "ping" => Ok(json!({})),
        "tools/list" => Ok(tool_list()),
        "tools/call" => call_tool(params, backend).map_err(|m| (-32602, m)),
        _ => Err((-32601, "method not found".to_string())),
    };
    Some(match result {
        Ok(r) => json!({ "jsonrpc": "2.0", "id": id, "result": r }),
        Err((code, m)) => rpc_error(id, code, &m),
    })
}

// ---- HTTP ----

fn respond(rq: tiny_http::Request, status: u16, body: Option<&Value>) {
    let header = |k: &str, v: &str| tiny_http::Header::from_bytes(k, v).expect("static ascii header");
    // No Access-Control-* header is ever sent: a browser preflight must fail.
    let resp = tiny_http::Response::from_string(body.map(Value::to_string).unwrap_or_default())
        .with_status_code(status)
        .with_header(header("Content-Type", "application/json"));
    let resp = match status {
        401 => resp.with_header(header("WWW-Authenticate", "Bearer")),
        405 => resp.with_header(header("Allow", "POST")),
        _ => resp,
    };
    let _ = rq.respond(resp); // the client hung up — nothing to do
}

fn handle(mut rq: tiny_http::Request, backend: &dyn Backend) {
    if rq.url().split('?').next() != Some("/mcp") {
        return respond(rq, 404, None);
    }
    // GET would open an SSE stream; this server has nothing to push, and the spec allows 405.
    if *rq.method() != tiny_http::Method::Post {
        return respond(rq, 405, None);
    }
    let mut body = String::new();
    match rq.as_reader().take(MAX_BODY + 1).read_to_string(&mut body) {
        Ok(n) if n as u64 <= MAX_BODY => {}
        Ok(_) => return respond(rq, 413, None),
        Err(_) => return respond(rq, 400, None),
    }
    match handle_rpc(&body, backend) {
        Some(v) => respond(rq, 200, Some(&v)),
        None => respond(rq, 202, None),
    }
}

/// The accept loop. Ends when `unblock()` is called or tiny_http's listener dies.
fn serve(server: &tiny_http::Server, token: &str, backend: Arc<dyn Backend>) {
    for rq in server.incoming_requests() {
        let all = |name: &'static str| -> Vec<&str> {
            rq.headers().iter().filter(|h| h.field.equiv(name)).map(|h| h.value.as_str()).collect()
        };
        let verdict = admit(&all("Host"), &all("Origin"), all("Authorization").first().copied(), token);
        if let Err(status) = verdict {
            respond(rq, status, None);
            continue;
        }
        // A run_command blocks for as long as the human takes to decide, so it cannot run on
        // the accept thread: ping, the read-only tools and the fail-fast "busy" answer must
        // stay responsive meanwhile.
        // ponytail: one unpooled thread per ADMITTED request. Only a token holder can spawn
        // them; cap with a semaphore if a client ever proves abusive.
        let backend = backend.clone();
        std::thread::spawn(move || handle(rq, &*backend));
    }
}

static SERVER: Mutex<Option<Arc<tiny_http::Server>>> = Mutex::new(None);

fn start(port: u16, token: String, backend: Arc<dyn Backend>) -> Result<Arc<tiny_http::Server>, String> {
    // The literal loopback address, never 0.0.0.0 or a hostname that could resolve elsewhere:
    // the bearer token is the second line of defence, not the first.
    let server = tiny_http::Server::http(("127.0.0.1", port)).map_err(|e| format!("cannot listen on 127.0.0.1:{port}: {e}"))?;
    let server = Arc::new(server);
    let s = server.clone();
    std::thread::Builder::new()
        .name("mcp-server".into())
        .spawn(move || {
            serve(&s, &token, backend);
            // if the listener died on its own, stop `/mcp serve status` claiming it is up
            let mut cur = SERVER.lock().unwrap_or_else(|e| e.into_inner());
            if cur.as_ref().is_some_and(|c| Arc::ptr_eq(c, &s)) {
                *cur = None;
            }
        })
        .map_err(|e| e.to_string())?;
    Ok(server)
}

fn stop() {
    if let Some(s) = SERVER.lock().unwrap_or_else(|e| e.into_inner()).take() {
        s.unblock(); // the accept thread drops the last Arc, which closes the socket
    }
}

// ---- the live terminal ----

struct Live(AppHandle);

/// Wait for the journal block of the command just written. Same correlation as agent_loop —
/// match on command text, resync on `Lagged` — plus an abort check, because here Esc must
/// release the HTTP client as well as the bar. `None` = deadline, abort, or channel closed.
// ponytail: second copy of agent_loop's wait (that one has no abort). Fold them together
// once the parallel branches touching agent_loop have merged.
async fn wait_block(
    rx: &mut tokio::sync::broadcast::Receiver<Block>,
    want: &str,
    timeout: std::time::Duration,
    aborted: impl Fn() -> bool,
) -> Option<Block> {
    use tokio::sync::broadcast::error::RecvError;
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        // ponytail: 100ms abort poll, the same trade ai_call_abortable makes
        let tick = (tokio::time::Instant::now() + std::time::Duration::from_millis(100)).min(deadline);
        match tokio::time::timeout_at(tick, rx.recv()).await {
            Ok(Ok(b)) if b.command.trim() == want => return Some(b),
            Ok(Ok(_)) | Ok(Err(RecvError::Lagged(_))) => continue,
            Ok(Err(RecvError::Closed)) => return None,
            Err(_) if aborted() || tokio::time::Instant::now() >= deadline => return None,
            Err(_) => continue,
        }
    }
}

/// The external agent's only road to the PTY. `cmd` is already validated by `parse_run_args`
/// and is used verbatim for the proposal and for the write — shown == run.
async fn run_gated(app: &AppHandle, cmd: &str) -> Result<String, String> {
    // No PTY means the webview has not mounted yet (it is what calls pty_spawn), so an
    // `agent-propose` emitted now would reach no listener: the proposal could never be
    // answered and `running` would stay claimed with no bar on screen to release it.
    if app.state::<PtyState>().writer.lock().unwrap_or_else(|e| e.into_inner()).is_none() {
        return Err("terminal not ready: no shell has been spawned yet".into());
    }
    // One approval slot, one PTY: fail fast rather than queue behind, or clobber the parked
    // sender of, the built-in agent or another run_command.
    agent_claim(&app.state::<AgentState>()).map_err(|_| BUSY.to_string())?;
    // Built only AFTER the claim is won — dropping it on the busy path above would clear
    // the flag out from under whoever does hold it. From here every exit, panics included,
    // releases ⌘J.
    let _release = AgentRunGuard(app.clone());
    let aborted = || app.state::<AgentState>().abort.load(SeqCst);

    // Unlike the built-in agent's, these proposals are UNSOLICITED: the bar takes focus while
    // the user is typing in the shell, so the Enter that ends their own command would land
    // on it and approve a command they never read. `external: true` makes the bar demand a
    // chord instead of a bare Enter; the MIN_REVIEW floor that used to loop here now lives
    // in agent_propose itself, so the built-in agent's proposals get it too.
    let approved = agent_propose(
        app,
        json!({ "step": 0, "kind": "run", "text": cmd, "args": null, "danger": is_dangerous(cmd), "external": true }),
    )
    .await;

    let result = async {
        // re-check abort between the await and the write, as agent_loop does
        if !approved || aborted() {
            return Err(DENIED.to_string());
        }
        // subscribe BEFORE writing, then drop stragglers — see agent_loop for both reasons
        let mut rx = app.state::<JournalState>().tx.subscribe();
        while rx.try_recv().is_ok() {}
        app.state::<JournalState>().scanner.lock().unwrap_or_else(|e| e.into_inner()).set_typed(cmd.to_string());
        let _ = app.emit("agent-status", json!({ "step": 0, "status": "running" }));
        // INVARIANT: the ONLY pty write in the MCP-server path — lexically after the
        // `!approved` return above, reachable only via agent_decide(true).
        pty_write_internal(&app.state::<PtyState>(), &format!("{cmd}\n"))?;
        Ok(match wait_block(&mut rx, cmd, AGENT_STEP_TIMEOUT, aborted).await {
            Some(b) => format!("Exit code: {}\nOutput (last {OUTPUT_CHARS} chars):\n{}", b.exit_code, tail_chars(&b.output, OUTPUT_CHARS)),
            // Not an error: the command was approved and started. The ceiling stops the wait,
            // it does not kill the command.
            None => format!(
                "Exit code: unknown\nNo exit marker within {}s (or the user stopped waiting). The command may still be running; read_journal will show it once it ends.",
                AGENT_STEP_TIMEOUT.as_secs()
            ),
        })
    }
    .await;

    // The bar stays in its "agent running" state until agent-done, on every path.
    let line = match &result {
        Ok(text) => text.lines().next().unwrap_or_default().to_lowercase(),
        Err(_) => "denied".into(),
    };
    let _ = app.emit("agent-output", json!({ "step": 0, "text": format!("external run_command \u{2192} {line}") }));
    let _ = app.emit("agent-done", json!({ "summary": "external command finished" }));
    result
}

fn journal_json(q: &VecDeque<Block>, limit: usize) -> String {
    let recent: Vec<Value> = q
        .iter()
        .skip(q.len().saturating_sub(limit))
        .map(|b| json!({ "command": b.command, "exit_code": b.exit_code, "output": tail_chars(&b.output, OUTPUT_CHARS), "duration_ms": b.duration_ms }))
        .collect();
    Value::from(recent).to_string()
}

impl Backend for Live {
    // Called on a plain server thread, never inside the runtime, so block_on cannot nest.
    fn run_command(&self, command: &str) -> Result<String, String> {
        tauri::async_runtime::block_on(run_gated(&self.0, command))
    }

    fn read_journal(&self, limit: usize) -> String {
        journal_json(&self.0.state::<JournalState>().blocks.lock().unwrap_or_else(|e| e.into_inner()), limit)
    }

    fn get_context(&self) -> Result<String, String> {
        let ctx = tauri::async_runtime::block_on(super::get_context(self.0.state()))?;
        let mut v = serde_json::to_value(ctx).map_err(|e| e.to_string())?;
        v["shell"] = shell_name(&shell_path()).into();
        Ok(v.to_string())
    }
}

// ---- /mcp serve on|off|status ----

#[derive(Debug, PartialEq)]
enum ServeCmd {
    On(Option<u16>),
    Off,
    Status,
}

/// `None` = not a `/mcp serve` command; run_slash falls through to run_slash_inner.
fn parse_serve(input: &str) -> Option<Result<ServeCmd, String>> {
    let lower = input.strip_prefix('/').unwrap_or(input).to_lowercase();
    let words: Vec<&str> = lower.split_whitespace().collect();
    let ["mcp", "serve", rest @ ..] = words.as_slice() else {
        return None;
    };
    Some(match rest {
        ["on"] => Ok(ServeCmd::On(None)),
        // below 1024 needs root and collides with real services
        ["on", p] => match p.parse::<u16>() {
            Ok(p) if p >= 1024 => Ok(ServeCmd::On(Some(p))),
            _ => Err("port must be 1024\u{2013}65535".into()),
        },
        ["off"] => Ok(ServeCmd::Off),
        [] | ["status"] => Ok(ServeCmd::Status),
        _ => Err("usage: /mcp serve on [port] | off | status".into()),
    })
}

/// The ONLY place the token is rendered. It goes out through `term_write` (display engine
/// only), so it never reaches the PTY, the journal, or a model transcript.
fn render_status(cfg: &ServeConfig, listening: bool) -> String {
    if !cfg.enabled {
        return "\r\n\x1b[36m[tachyon] mcp server: off \x1b[90m\u{2014} /mcp serve on\x1b[0m\r\n".into();
    }
    let url = format!("http://127.0.0.1:{}/mcp", cfg.port);
    if !listening {
        return format!("\r\n\x1b[31m[tachyon] mcp server: enabled but NOT listening on {url} \u{2014} /mcp serve on to retry\x1b[0m\r\n");
    }
    let snippet = json!({ "mcpServers": { "tachyon": {
        "type": "http",
        "url": url,
        "headers": { "Authorization": format!("Bearer {}", cfg.token) }
    } } });
    format!(
        concat!(
            "\r\n\x1b[36m[tachyon] mcp server: on \x1b[0m{url}\r\n",
            "\x1b[90mevery run_command waits for your \u{23ce} in the approval bar; the token below lets a client PROPOSE, never run\x1b[0m\r\n",
            "\x1b[90mClaude Code:\x1b[0m\r\n",
            "claude mcp add --transport http tachyon {url} --header \"Authorization: Bearer {token}\"\r\n",
            "\x1b[90mor as JSON (.mcp.json):\x1b[0m\r\n",
            "{snippet}\r\n",
        ),
        url = url,
        token = cfg.token,
        snippet = snippet,
    )
}

fn listening_port() -> Option<u16> {
    let cur = SERVER.lock().unwrap_or_else(|e| e.into_inner());
    cur.as_ref().and_then(|s| s.server_addr().to_ip()).map(|a| a.port())
}

fn run_serve(app: &AppHandle, cmd: ServeCmd) -> Result<String, String> {
    let path = serve_path()?;
    // same lock as providers.json: run_slash is async, so two /mcp serve calls can race
    let _guard = CONFIG_WRITE.lock().unwrap_or_else(|e| e.into_inner());
    match cmd {
        ServeCmd::Status => Ok(render_status(&load_serve(&path)?, listening_port().is_some())),
        ServeCmd::Off => {
            let mut cfg = load_serve(&path)?;
            cfg.enabled = false;
            write_config(&path, &cfg)?;
            stop();
            Ok("\r\n\x1b[36m[tachyon] mcp server: off\x1b[0m\r\n".into())
        }
        ServeCmd::On(port) => {
            let cfg = enable(&path, port)?;
            // Already up on this port → leave it alone. A stop-then-start on the SAME port
            // would race the old listener's close and fail with "address in use".
            if listening_port() != Some(cfg.port) {
                stop();
                // Bind first, persist second: a port that cannot be bound must not leave
                // `enabled: true` behind to fail again, silently, at the next launch.
                let server = start(cfg.port, cfg.token.clone(), Arc::new(Live(app.clone())))?;
                *SERVER.lock().unwrap_or_else(|e| e.into_inner()) = Some(server);
            }
            write_config(&path, &cfg)?;
            Ok(format!(
                "\r\n\x1b[36m[tachyon] mcp server: on \x1b[0mhttp://127.0.0.1:{}/mcp \x1b[90m\u{2014} /mcp serve status prints the client config\x1b[0m\r\n",
                cfg.port
            ))
        }
    }
}

/// Hooked in front of run_slash_inner, which has no AppHandle to start a server with.
pub(crate) fn slash(app: &AppHandle, input: &str) -> Option<Result<String, String>> {
    Some(parse_serve(input)?.and_then(|cmd| run_serve(app, cmd)))
}

/// App launch: bring the server back if the user left it on. A failure (port taken) is
/// reported by `/mcp serve status`; there is no terminal to print to yet.
pub(crate) fn autostart(app: &AppHandle) {
    let Ok(cfg) = serve_path().and_then(|p| load_serve(&p)) else { return };
    if cfg.enabled && !cfg.token.is_empty() {
        if let Ok(server) = start(cfg.port, cfg.token, Arc::new(Live(app.clone()))) {
            *SERVER.lock().unwrap_or_else(|e| e.into_inner()) = Some(server);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    /// Records what reached the "terminal" and answers like a user who denies `rm`.
    #[derive(Default)]
    struct Stub(Mutex<Vec<String>>);

    impl Backend for Stub {
        fn run_command(&self, command: &str) -> Result<String, String> {
            self.0.lock().unwrap().push(command.to_string());
            if command.starts_with("rm") {
                Err(DENIED.into())
            } else {
                Ok(format!("Exit code: 0\nOutput:\nran {command}"))
            }
        }
        fn read_journal(&self, limit: usize) -> String {
            format!("[\"last {limit}\"]")
        }
        fn get_context(&self) -> Result<String, String> {
            Ok("{\"cwd\":\"/tmp\"}".into())
        }
    }

    fn rpc(stub: &Stub, body: Value) -> Value {
        handle_rpc(&body.to_string(), stub).expect("a request gets a response")
    }

    #[test]
    fn constant_time_eq() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
        assert!(ct_eq(b"", b""));
    }

    #[test]
    fn bearer_auth() {
        assert!(bearer_ok(Some(&format!("Bearer {TOKEN}")), TOKEN));
        assert!(bearer_ok(Some(&format!("bearer {TOKEN}")), TOKEN)); // scheme is case-insensitive
        assert!(!bearer_ok(None, TOKEN));
        assert!(!bearer_ok(Some("Bearer wrong"), TOKEN));
        assert!(!bearer_ok(Some(TOKEN), TOKEN)); // no scheme
        assert!(!bearer_ok(Some(&format!("Basic {TOKEN}")), TOKEN));
        // an unset token must not be matched by an empty credential
        assert!(!bearer_ok(Some("Bearer "), ""));
    }

    #[test]
    fn host_and_origin_validation() {
        for ok in ["localhost", "localhost:47600", "127.0.0.1:47600", "LOCALHOST:1", "[::1]", "[::1]:80"] {
            assert!(is_local_host(ok), "{ok}");
        }
        for bad in ["evil.com", "evil.com:47600", "localhost.evil.com", "127.0.0.1.evil.com", "localhost@evil.com", "localhost:", "0.0.0.0:47600", ""] {
            assert!(!is_local_host(bad), "{bad}");
        }
        assert!(origin_ok("http://localhost:3000"));
        assert!(origin_ok("https://127.0.0.1"));
        for bad in ["https://evil.com", "http://localhost.evil.com", "http://localhost@evil.com", "null", "localhost", "file://"] {
            assert!(!origin_ok(bad), "{bad}");
        }
    }

    #[test]
    fn admission_order_and_duplicates() {
        let auth = format!("Bearer {TOKEN}");
        assert_eq!(admit(&["127.0.0.1:47600"], &[], Some(&auth), TOKEN), Ok(()));
        assert_eq!(admit(&["localhost:47600"], &["http://localhost:5173"], Some(&auth), TOKEN), Ok(()));
        assert_eq!(admit(&["127.0.0.1:47600"], &[], None, TOKEN), Err(401));
        assert_eq!(admit(&["127.0.0.1:47600"], &[], Some("Bearer nope"), TOKEN), Err(401));
        // a browser page: right token or not, it is refused — and before auth is looked at
        assert_eq!(admit(&["127.0.0.1:47600"], &["https://evil.com"], Some(&auth), TOKEN), Err(403));
        assert_eq!(admit(&["127.0.0.1:47600"], &["https://evil.com"], None, TOKEN), Err(403));
        // DNS rebinding: the socket is local but the browser still says who it thinks it called
        assert_eq!(admit(&["evil.com:47600"], &[], Some(&auth), TOKEN), Err(403));
        assert_eq!(admit(&[], &[], Some(&auth), TOKEN), Err(403));
        // a second, hostile header does not ride in behind a good one
        assert_eq!(admit(&["127.0.0.1", "evil.com"], &[], Some(&auth), TOKEN), Err(403));
        assert_eq!(admit(&["127.0.0.1"], &["http://localhost", "https://evil.com"], Some(&auth), TOKEN), Err(403));
    }

    #[test]
    fn config_roundtrip_and_token_generation() {
        let dir = std::env::temp_dir().join(format!("tachyon-mcpserve-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("mcp-server.json");

        // missing file → off, default port, no token
        let cfg = load_serve(&path).unwrap();
        assert!(!cfg.enabled && cfg.token.is_empty());
        assert_eq!(cfg.port, DEFAULT_PORT);

        let on = enable(&path, None).unwrap();
        assert!(on.enabled);
        assert_eq!(on.token.len(), 64);
        assert!(on.token.bytes().all(|b| b.is_ascii_hexdigit()));
        write_config(&path, &on).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        }

        // re-enabling keeps the token clients already hold, and can move the port
        let again = enable(&path, Some(5000)).unwrap();
        assert!(again.token == on.token);
        assert_eq!(again.port, 5000);
        assert!(generate_token().unwrap() != on.token);

        // a corrupt file is an error, never a silent reset (which would mint a new token)
        std::fs::write(&path, "{not json").unwrap();
        assert!(load_serve(&path).is_err());
        assert!(enable(&path, None).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rpc_initialize_negotiates_version() {
        let stub = Stub::default();
        let r = rpc(&stub, json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": { "protocolVersion": "2025-03-26" } }));
        assert_eq!(r["id"], 1);
        assert_eq!(r["result"]["protocolVersion"], "2025-03-26");
        assert_eq!(r["result"]["serverInfo"]["name"], "tachyon");
        assert!(r["result"]["capabilities"]["tools"].is_object());
        // unknown version → ours, newest
        let r = rpc(&stub, json!({ "jsonrpc": "2.0", "id": "a", "method": "initialize", "params": { "protocolVersion": "1999-01-01" } }));
        assert_eq!(r["id"], "a");
        assert_eq!(r["result"]["protocolVersion"], PROTOCOL_VERSIONS[0]);
    }

    #[test]
    fn rpc_tools_list_has_schemas() {
        let r = rpc(&Stub::default(), json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" }));
        let tools = r["result"]["tools"].as_array().unwrap();
        let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert_eq!(names, ["run_command", "read_journal", "get_context"]);
        for t in tools {
            assert_eq!(t["inputSchema"]["type"], "object", "{}", t["name"]);
        }
        assert_eq!(tools[0]["inputSchema"]["required"], json!(["command"]));
    }

    #[test]
    fn rpc_errors_and_notifications() {
        let stub = Stub::default();
        let r = handle_rpc("{not json", &stub).unwrap();
        assert_eq!(r["error"]["code"], -32700);
        assert!(r["id"].is_null());
        assert_eq!(rpc(&stub, json!({ "jsonrpc": "2.0", "id": 3, "method": "resources/list" }))["error"]["code"], -32601);
        assert_eq!(rpc(&stub, json!({ "jsonrpc": "2.0", "id": 4 }))["error"]["code"], -32600);
        assert_eq!(rpc(&stub, json!([{ "jsonrpc": "2.0", "id": 5, "method": "ping" }]))["error"]["code"], -32600);
        assert_eq!(rpc(&stub, json!({ "jsonrpc": "2.0", "id": 6, "method": "ping" }))["result"], json!({}));
        // notifications — known or not — get no body, and never reach a tool
        assert!(handle_rpc(&json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }).to_string(), &stub).is_none());
        let sneaky = json!({ "jsonrpc": "2.0", "method": "tools/call", "params": { "name": "run_command", "arguments": { "command": "ls" } } });
        assert!(handle_rpc(&sneaky.to_string(), &stub).is_none());
        assert!(stub.0.lock().unwrap().is_empty());
    }

    #[test]
    fn run_command_input_validation() {
        assert_eq!(parse_run_args(&json!({ "command": "  ls -la  " })).unwrap(), "ls -la");
        // folded exactly as the built-in agent's commands are: line 2 is visible, not hidden
        assert_eq!(parse_run_args(&json!({ "command": "echo hi\nrm -rf ~" })).unwrap(), "echo hi; rm -rf ~");
        assert!(is_dangerous(&parse_run_args(&json!({ "command": "echo hi\nrm -rf ~" })).unwrap()));
        assert!(parse_run_args(&json!({})).is_err());
        assert!(parse_run_args(&json!({ "command": 7 })).is_err());
        assert!(parse_run_args(&json!({ "command": " \n " })).is_err());
        // a bare CR is Enter to the PTY but invisible in the approval <input>
        assert!(parse_run_args(&json!({ "command": "echo hi\rrm -rf ~" })).is_err());
        assert!(parse_run_args(&json!({ "command": "ls\u{1b}[2J" })).is_err());
        assert!(parse_run_args(&json!({ "command": "ls\tsrc" })).is_err()); // tab = completion
        assert!(parse_run_args(&json!({ "command": "ls\t" })).is_err()); // even at the edge: refused, not trimmed
        assert_eq!(parse_run_args(&json!({ "command": "echo a\r\necho b" })).unwrap(), "echo a; echo b"); // CRLF is a line break
        assert!(parse_run_args(&json!({ "command": "ls \u{202e}~ fr- mr" })).is_err());
        // zero-width is as invisible as a bidi override, and hides inside a danger pattern
        assert!(parse_run_args(&json!({ "command": "r\u{200B}m -rf ~" })).is_err());
        assert!(parse_run_args(&json!({ "command": "x".repeat(MAX_COMMAND_CHARS + 1) })).is_err());
        assert!(parse_run_args(&json!({ "command": "x".repeat(MAX_COMMAND_CHARS) })).is_ok());

        assert_eq!(parse_limit(&json!({})).unwrap(), 10);
        assert_eq!(parse_limit(&json!({ "limit": 50 })).unwrap(), 50);
        for bad in [json!(0), json!(51), json!(-1), json!("5"), json!(1.5)] {
            assert!(parse_limit(&json!({ "limit": bad })).is_err());
        }
    }

    #[test]
    fn tools_call_results() {
        let stub = Stub::default();
        let call = |name: &str, args: Value| rpc(&stub, json!({ "jsonrpc": "2.0", "id": 9, "method": "tools/call", "params": { "name": name, "arguments": args } }));

        let ok = call("run_command", json!({ "command": "ls" }));
        assert_eq!(ok["result"]["isError"], false);
        assert!(ok["result"]["content"][0]["text"].as_str().unwrap().contains("ran ls"));

        let denied = call("run_command", json!({ "command": "rm -rf build" }));
        assert_eq!(denied["result"]["isError"], true);
        assert_eq!(denied["result"]["content"][0]["text"], DENIED);

        // invalid input never reaches the terminal
        assert_eq!(call("run_command", json!({ "command": "a\rb" }))["error"]["code"], -32602);
        assert_eq!(call("launch_missiles", json!({}))["error"]["code"], -32602);
        assert_eq!(*stub.0.lock().unwrap(), ["ls", "rm -rf build"]);

        assert_eq!(call("read_journal", json!({ "limit": 3 }))["result"]["content"][0]["text"], "[\"last 3\"]");
        assert_eq!(call("get_context", json!({}))["result"]["isError"], false);
    }

    #[test]
    fn journal_json_takes_the_newest_and_truncates() {
        let mut q = VecDeque::new();
        for i in 0..5 {
            q.push_back(Block { command: format!("c{i}"), exit_code: i, output: "y".repeat(OUTPUT_CHARS + 100), duration_ms: 1 });
        }
        let v: Value = serde_json::from_str(&journal_json(&q, 2)).unwrap();
        let a = v.as_array().unwrap();
        assert_eq!(a.len(), 2);
        assert_eq!(a[0]["command"], "c3");
        assert_eq!(a[1]["exit_code"], 4);
        assert_eq!(a[1]["output"].as_str().unwrap().len(), OUTPUT_CHARS);
        assert_eq!(journal_json(&VecDeque::new(), 10), "[]");
    }

    #[test]
    fn wait_block_matches_by_command_and_survives_lag() {
        let block = |c: &str, code: i32| Block { command: c.into(), exit_code: code, output: String::new(), duration_ms: 0 };
        let secs = std::time::Duration::from_secs;
        tauri::async_runtime::block_on(async {
            // capacity 2, five stragglers, then ours: the receiver lags, resyncs, and still
            // returns the block whose command matches — not the first one to arrive
            let (tx, mut rx) = tokio::sync::broadcast::channel(2);
            for i in 0..5 {
                assert!(tx.send(block(&format!("old{i}"), 1)).is_ok());
            }
            assert!(tx.send(block(" make test ", 7)).is_ok());
            assert_eq!(wait_block(&mut rx, "make test", secs(5), || false).await.unwrap().exit_code, 7);

            // nothing matching → None at the deadline, not a hang and not the wrong block
            assert!(tx.send(block("other", 0)).is_ok());
            assert!(wait_block(&mut rx, "make test", std::time::Duration::from_millis(250), || false).await.is_none());

            // abort releases the waiter long before the deadline
            let t = std::time::Instant::now();
            assert!(wait_block(&mut rx, "make test", secs(30), || true).await.is_none());
            assert!(t.elapsed() < secs(5));
        });
    }

    #[test]
    fn one_driver_at_a_time() {
        let a = AgentState::default();
        assert!(agent_claim(&a).is_ok());
        // built-in agent running, or a run_command pending: the next one fails fast and
        // leaves the holder's parked sender alone
        let (tx, mut rx) = tokio::sync::oneshot::channel::<bool>();
        *a.decision.lock().unwrap() = Some(tx);
        assert!(agent_claim(&a).is_err());
        assert!(a.decision.lock().unwrap().is_some());
        assert!(rx.try_recv().is_err()); // still pending — not resolved, not dropped

        // released (AgentRunGuard's Drop does exactly this) → claimable again, and a stale
        // sender or abort flag from the previous holder cannot leak into the new claim
        a.running.store(false, SeqCst);
        a.abort.store(true, SeqCst);
        assert!(agent_claim(&a).is_ok());
        assert!(!a.abort.load(SeqCst));
        assert!(a.decision.lock().unwrap().is_none());
    }

    #[test]
    fn serve_command_parsing() {
        assert_eq!(parse_serve("/mcp serve on"), Some(Ok(ServeCmd::On(None))));
        assert_eq!(parse_serve("/MCP Serve ON 5000"), Some(Ok(ServeCmd::On(Some(5000)))));
        assert_eq!(parse_serve("/mcp serve off"), Some(Ok(ServeCmd::Off)));
        assert_eq!(parse_serve("/mcp serve status"), Some(Ok(ServeCmd::Status)));
        assert_eq!(parse_serve("/mcp serve"), Some(Ok(ServeCmd::Status)));
        assert!(matches!(parse_serve("/mcp serve on 80"), Some(Err(_))));
        assert!(matches!(parse_serve("/mcp serve on 99999"), Some(Err(_))));
        assert!(matches!(parse_serve("/mcp serve bogus"), Some(Err(_))));
        assert!(matches!(parse_serve("/mcp serve off now"), Some(Err(_))));
        // everything else still belongs to run_slash_inner
        assert_eq!(parse_serve("/mcp list"), None);
        assert_eq!(parse_serve("/mcp add serve http://x"), None);
        assert_eq!(parse_serve("/keys"), None);
    }

    #[test]
    fn status_shows_the_token_only_when_listening() {
        let cfg = ServeConfig { enabled: true, port: 47600, token: TOKEN.into() };
        let on = render_status(&cfg, true);
        assert!(on.contains("http://127.0.0.1:47600/mcp"));
        assert!(on.contains(&format!("Bearer {TOKEN}")));
        assert!(!render_status(&cfg, false).contains(TOKEN));
        assert!(!render_status(&ServeConfig { enabled: false, ..cfg }, false).contains(TOKEN));
    }

    // ---- real HTTP, stubbed terminal ----

    fn post(url: &str, auth: Option<&str>, origin: Option<&str>, body: &Value) -> (u16, String) {
        let mut req = ureq::post(url).set("Content-Type", "application/json");
        if let Some(a) = auth {
            req = req.set("Authorization", a);
        }
        if let Some(o) = origin {
            req = req.set("Origin", o);
        }
        match req.send_string(&body.to_string()) {
            Ok(r) => (r.status(), r.into_string().unwrap()),
            Err(ureq::Error::Status(code, r)) => (code, r.into_string().unwrap_or_default()),
            Err(e) => panic!("transport: {e}"),
        }
    }

    #[test]
    fn http_end_to_end() {
        let stub = Arc::new(Stub::default());
        let server = start(0, TOKEN.into(), stub.clone()).unwrap();
        let addr = server.server_addr().to_ip().unwrap();
        assert!(addr.ip().is_loopback());
        let url = format!("http://{addr}/mcp");
        let auth = format!("Bearer {TOKEN}");
        let ping = json!({ "jsonrpc": "2.0", "id": 1, "method": "ping" });

        // the gate, over the wire
        assert_eq!(post(&url, None, None, &ping).0, 401);
        assert_eq!(post(&url, Some("Bearer wrong"), None, &ping).0, 401);
        assert_eq!(post(&url, Some(&auth), Some("https://evil.com"), &ping).0, 403);
        let run = json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": { "name": "run_command", "arguments": { "command": "ls" } } });
        assert_eq!(post(&url, None, None, &run).0, 401);
        assert_eq!(post(&url, Some(&auth), Some("https://evil.com"), &run).0, 403);
        assert!(stub.0.lock().unwrap().is_empty(), "a rejected request reached the terminal");
        // no response, rejected or not, echoes the token or grants CORS
        let (_, body) = post(&url, Some("Bearer wrong"), None, &ping);
        assert!(!body.contains(TOKEN));

        // initialize → initialized → tools/list → tools/call
        let (status, body) = post(&url, Some(&auth), None, &json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": { "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": { "name": "t", "version": "0" } } }));
        assert_eq!(status, 200);
        let v: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["result"]["protocolVersion"], "2025-06-18");

        let (status, body) = post(&url, Some(&auth), None, &json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }));
        assert_eq!((status, body.as_str()), (202, ""));

        let (_, body) = post(&url, Some(&auth), Some("http://localhost:5173"), &json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" }));
        assert_eq!(serde_json::from_str::<Value>(&body).unwrap()["result"]["tools"].as_array().unwrap().len(), 3);

        let (status, body) = post(&url, Some(&auth), None, &run);
        assert_eq!(status, 200);
        let v: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["result"]["isError"], false);
        assert_eq!(*stub.0.lock().unwrap(), ["ls"]);

        // wrong path / method, authenticated
        assert_eq!(post(&format!("http://{addr}/"), Some(&auth), None, &ping).0, 404);
        let get = ureq::get(&url).set("Authorization", &auth).call();
        assert!(matches!(get, Err(ureq::Error::Status(405, _))));

        // off means off: after unblock the port stops answering
        server.unblock();
        drop(server);
        std::thread::sleep(std::time::Duration::from_millis(300));
        let gone = ureq::post(&url).timeout(std::time::Duration::from_secs(2)).set("Authorization", &auth).send_string(&ping.to_string());
        assert!(matches!(gone, Err(ureq::Error::Transport(_))));
    }

    /// `get_context` is the unapproved read surface, so the threat model is only worth
    /// reading if its field list is exhaustive. `Live::get_context` serialises a whole
    /// `ShellContext` and adds `shell`, so a field added to that struct silently widens
    /// what a token holder can read — this fails until the doc names it.
    #[test]
    fn get_context_tool_fields_are_documented() {
        let mut v = serde_json::to_value(ShellContext::default()).unwrap();
        v["shell"] = "zsh".into();
        let keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(keys, ["branch", "cwd", "dirty", "shell", "shell_pid"]);

        let doc = include_str!("../../docs/danger-gate.md");
        let at = doc.find("with **no approval**").expect("the unapproved-reads bullet is gone");
        let bullet = &doc[at..][..doc[at..].find("\n\n").unwrap()];
        for k in keys {
            assert!(bullet.contains(k), "danger-gate.md does not name {k}");
        }
    }
}
