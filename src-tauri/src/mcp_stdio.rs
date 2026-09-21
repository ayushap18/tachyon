//! MCP stdio transport: a local server process speaking newline-delimited JSON-RPC 2.0 on
//! its stdin/stdout. Most published MCP servers ship this way (`npx …`, `uvx …`), not as an
//! HTTP endpoint.
//!
//! SECURITY: opening a connection EXECUTES the configured program as the user, with the
//! user's environment and no sandbox. That is inherent to stdio MCP. The controls are that
//! the command line only ever comes from mcp.json (`/mcp add <name> -- <command>`), never
//! from a model or a server, and that `/mcp list` prints it in full.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

use serde_json::Value;

// `npx -y <pkg>` / `uvx <pkg>` download the package on first run, so the handshake is
// allowed far longer than a tool call. Still finite: a wedged server costs this once.
pub const START_TIMEOUT: Duration = Duration::from_secs(30);

pub struct StdioConn {
    child: Child,
    // None once the child has been killed — the conn is then dead for good
    stdin: Option<ChildStdin>,
    lines: Receiver<String>,
    next_id: u64,
}

impl StdioConn {
    /// Spawn the server and do the MCP handshake. Any failure kills and reaps the child.
    pub fn open(command: &str, args: &[String], start_timeout: Duration) -> Result<Self, String> {
        let mut conn = Self::spawn(command, args)?;
        conn.request("initialize", crate::mcp_init_params(), start_timeout)?;
        conn.send(&serde_json::json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }))?;
        Ok(conn)
    }

    fn spawn(command: &str, args: &[String]) -> Result<Self, String> {
        let mut child = Command::new(command)
            .args(args)
            // A Finder/Dock or .desktop launch gives us the minimal system PATH, in which a
            // bare `npx` does not resolve. The login shell's PATH is the one the user's
            // `/mcp add … -- <cmd>` was written against. Absent (probe failed), we inherit
            // Tachyon's, exactly as before.
            .envs(crate::login_env().get("PATH").map(|p| ("PATH", p)))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            // servers log to stderr by convention; inherited, that lands on whatever
            // terminal launched Tachyon
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("cannot start {command}: {e}"))?;
        let stdin = child.stdin.take();
        let stdout = child.stdout.take();
        let (tx, lines) = std::sync::mpsc::channel();
        // built before the `?` below so an early return still kills and reaps via Drop
        let conn = StdioConn { child, stdin, lines, next_id: 0 };
        let stdout = stdout.ok_or("no stdout pipe")?;
        // A blocking read cannot take a deadline, so it lives on its own thread and the
        // deadline is enforced on the channel. The thread ends at EOF (the child died or was
        // killed) or on the first send after the conn is dropped.
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        Ok(conn)
    }

    /// One request/response. A JSON-RPC `error` reply is an Err but leaves the server
    /// running; a transport failure (timeout, exit, closed pipe) kills and reaps it — a
    /// server that blew its deadline is wedged as far as we can tell, and leaving it
    /// running would leak one process per agent run.
    pub fn request(&mut self, method: &str, params: Value, timeout: Duration) -> Result<Value, String> {
        match self.exchange(method, params, timeout) {
            Ok(reply) => crate::rpc_result(&reply),
            Err(e) => {
                self.kill();
                Err(e)
            }
        }
    }

    pub fn is_dead(&self) -> bool {
        self.stdin.is_none()
    }

    fn send(&mut self, msg: &Value) -> Result<(), String> {
        let stdin = self.stdin.as_mut().ok_or("server is not running")?;
        // One message per line. serde_json escapes newlines, so the framing cannot break.
        // ponytail: writes have no deadline — a server that stops reading stdin blocks us
        // once the pipe buffer (16–64 KB) fills. Model-written arguments are far smaller.
        writeln!(stdin, "{msg}").and_then(|_| stdin.flush()).map_err(|e| format!("server closed its stdin: {e}"))
    }

    fn exchange(&mut self, method: &str, params: Value, timeout: Duration) -> Result<Value, String> {
        self.next_id += 1;
        let id = self.next_id;
        self.send(&crate::jsonrpc_request(id, method, params))?;
        let deadline = Instant::now() + timeout;
        loop {
            let line = match self.lines.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
                Ok(l) => l,
                Err(RecvTimeoutError::Timeout) => return Err(format!("no reply to {method} within {timeout:?}")),
                Err(RecvTimeoutError::Disconnected) => return Err(format!("server exited before replying to {method}")),
            };
            // Everything that is not OUR reply is skipped: log lines a sloppy server prints
            // to stdout, notifications, and server→client requests (they carry a `method`).
            // ponytail: server requests (ping, roots, sampling) go unanswered — we advertise
            // no capabilities, so a conforming server does not depend on them.
            match serde_json::from_str::<Value>(&line) {
                Ok(v) if v.get("id").and_then(Value::as_u64) == Some(id) && v.get("method").is_none() => return Ok(v),
                _ => continue,
            }
        }
    }

    fn kill(&mut self) {
        // stdin first: a wrapper's grandchild (npx → node) survives the kill below, but a
        // conforming server exits when its stdin reaches EOF.
        // ponytail: a grandchild that ignores EOF is orphaned — spawn in its own process
        // group and kill the group if that shows up.
        self.stdin = None;
        let _ = self.child.kill();
        let _ = self.child.wait(); // reap, don't leave a zombie
    }
}

impl Drop for StdioConn {
    fn drop(&mut self) {
        self.kill();
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    // A fake MCP server in POSIX sh. It also prints a log line and a notification on stdout
    // before each reply and chatters on stderr — the client has to ignore all three.
    const FAKE_SERVER: &str = r#"
while IFS= read -r line; do
  id=$(printf '%s' "$line" | sed -n 's/.*"id":\([0-9]*\).*/\1/p')
  echo "log line, not json"
  echo '{"jsonrpc":"2.0","method":"notifications/message","params":{"data":"hi"}}'
  echo "stderr chatter" >&2
  case "$line" in
    *notifications/initialized*) ;;
    *'"initialize"'*) printf '{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-06-18","capabilities":{},"serverInfo":{"name":"fake","version":"0"}}}\n' "$id" ;;
    *'"tools/list"'*) printf '{"jsonrpc":"2.0","id":%s,"result":{"tools":[{"name":"echo","description":"Echoes","inputSchema":{"type":"object","properties":{"text":{"type":"string"}},"required":["text"]}}]}}\n' "$id" ;;
    *'"boom"'*) printf '{"jsonrpc":"2.0","id":%s,"result":{"isError":true,"content":[{"type":"text","text":"disk on fire"}]}}\n' "$id" ;;
    *'"tools/call"'*) printf '{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":"echoed"}]}}\n' "$id" ;;
    *) printf '{"jsonrpc":"2.0","id":%s,"error":{"code":-32601,"message":"method not found"}}\n' "$id" ;;
  esac
done
"#;

    // completes the handshake, then exits on the first real request
    const DYING_SERVER: &str = r#"
while IFS= read -r line; do
  case "$line" in
    *notifications/initialized*) ;;
    *'"initialize"'*) echo '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","capabilities":{}}}' ;;
    *) exit 1 ;;
  esac
done
"#;

    const T: Duration = Duration::from_secs(10); // generous: CI machines stall
    const SHORT: Duration = Duration::from_millis(300);

    fn sh(script: &str) -> Vec<String> {
        vec!["-c".into(), script.into()]
    }

    // kill -0 succeeds for a zombie too, so failure means killed AND reaped
    fn alive(pid: u32) -> bool {
        Command::new("kill").args(["-0", &pid.to_string()]).stderr(Stdio::null()).status().unwrap().success()
    }

    #[test]
    fn happy_path_list_call_and_rpc_error() {
        let mut c = StdioConn::open("sh", &sh(FAKE_SERVER), T).unwrap();
        let tools = crate::parse_tools(&c.request("tools/list", serde_json::json!({}), T).unwrap());
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name, "echo");
        assert_eq!(tools[0].input_schema["required"][0], "text");

        let call = |c: &mut StdioConn, name: &str| {
            c.request("tools/call", serde_json::json!({ "name": name, "arguments": { "text": "hi" } }), T)
        };
        assert_eq!(crate::tool_result_text(&call(&mut c, "echo").unwrap()).unwrap(), "echoed");
        // isError comes back as a normal result; tool_result_text is what makes it an Err
        assert_eq!(crate::tool_result_text(&call(&mut c, "boom").unwrap()).unwrap_err(), "disk on fire");

        // a JSON-RPC error is an Err, but the server is still usable afterwards
        assert!(c.request("nope", serde_json::json!({}), T).unwrap_err().contains("method not found"));
        assert!(!c.is_dead());
        assert!(c.request("tools/list", serde_json::json!({}), T).is_ok());

        let pid = c.child.id();
        drop(c);
        assert!(!alive(pid), "drop must kill and reap the server");
    }

    // The path the agent takes: McpPool::call. An isError result must be an Err (the loop
    // records it as "Tool error:"), and must NOT cost the connection.
    #[test]
    fn pool_call_surfaces_is_error_and_evicts_dead_servers() {
        let mut pool = crate::McpPool::default();
        let conn = StdioConn::open("sh", &sh(FAKE_SERVER), T).unwrap();
        pool.conns.insert("fake".into(), crate::McpConn::Stdio(conn));
        assert_eq!(pool.call("fake", "echo", serde_json::json!({})).unwrap(), "echoed");
        assert_eq!(pool.call("fake", "boom", serde_json::json!({})).unwrap_err(), "disk on fire");
        assert!(pool.conns.contains_key("fake"));

        // a server that dies mid-run is dropped from the pool so the next call respawns it
        let dying = StdioConn::open("sh", &sh(DYING_SERVER), T).unwrap();
        pool.conns.insert("dying".into(), crate::McpConn::Stdio(dying));
        assert!(pool.call("dying", "boom", serde_json::json!({})).unwrap_err().contains("exited"));
        assert!(!pool.conns.contains_key("dying"));
    }

    #[test]
    fn server_that_exits_immediately() {
        let err = StdioConn::open("sh", &sh("exit 0"), T).err().unwrap();
        assert!(err.contains("exited") || err.contains("closed its stdin"), "{err}");
        let err = StdioConn::open("/nonexistent/tachyon-mcp", &[], T).err().unwrap();
        assert!(err.starts_with("cannot start /nonexistent/tachyon-mcp"), "{err}");
    }

    #[test]
    fn silent_server_times_out_and_is_reaped() {
        // `exec` so the pid we hold IS the sleeper: no reply, and no exit on stdin EOF
        let mut c = StdioConn::spawn("sh", &sh("exec sleep 600")).unwrap();
        let pid = c.child.id();
        assert!(alive(pid));
        let started = Instant::now();
        let err = c.request("initialize", crate::mcp_init_params(), SHORT).unwrap_err();
        assert!(err.contains("no reply to initialize within 300ms"), "{err}");
        assert!(started.elapsed() < T, "the read must honour its deadline");
        assert!(c.is_dead());
        assert!(!alive(pid), "a timed-out server must be killed and reaped");
        // a dead conn refuses further use instead of hanging
        assert!(c.request("tools/list", serde_json::json!({}), SHORT).is_err());

        // same through the public entry point
        assert!(StdioConn::open("sh", &sh("exec sleep 600"), SHORT).is_err());
    }
}
