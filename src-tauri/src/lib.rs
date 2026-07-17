use std::collections::VecDeque;
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

// ---- OSC 133 journal ----
// The pty reader thread scans the RAW bytes (an ADDITIONAL consumer — the base64
// pty-output emission is untouched, term.write stays byte-identical) for the OSC 133
// marks the injected zsh hooks emit: A (prompt start), C (output start), D;<code>
// (command end). Finalized blocks live in a ring of 50 and are pushed to the webview
// via "journal-block" events.

#[derive(Clone, serde::Serialize)]
struct Block {
    command: String,
    exit_code: i32,
    output: String,
    duration_ms: u64,
}

const OSC_HDR: &[u8] = b"\x1b]133;";

#[derive(Default)]
struct OscScanner {
    carry: Vec<u8>, // partial mark split across pty chunks (capped 64)
    capturing: bool,
    output: String,  // current block output (tail-capped 8192)
    pre_cmd: String, // text between A and C — echo-scrape fallback (tail-capped 512)
    command: String,
    started: Option<std::time::Instant>,
    pending_typed: Option<String>, // clean command label from set_typed_command
}

// keep only the last `max` bytes, trimmed forward to a char boundary
fn tail_cap(s: &mut String, max: usize) {
    if s.len() > max {
        let mut cut = s.len() - max;
        while !s.is_char_boundary(cut) {
            cut += 1;
        }
        s.drain(..cut);
    }
}

// remove OSC sequences, CSI sequences, and control chars (keeps \t and \n)
fn strip_ansi(s: &str) -> String {
    let b = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == 0x1b && i + 1 < b.len() && b[i + 1] == b']' {
            // OSC: skip to BEL or ST (\x1b\\); a bare ESC ends the body unconsumed
            let mut j = i + 2;
            while j < b.len() && b[j] != 0x07 && b[j] != 0x1b {
                j += 1;
            }
            if j < b.len() {
                if b[j] == 0x07 {
                    j += 1;
                } else if j + 1 < b.len() && b[j + 1] == b'\\' {
                    j += 2;
                }
            }
            i = j;
        } else if b[i] == 0x1b && i + 1 < b.len() && b[i + 1] == b'[' {
            // CSI: params [0-9;?]* then one letter; anything else → drop the ESC only
            let mut j = i + 2;
            while j < b.len() && (b[j].is_ascii_digit() || b[j] == b';' || b[j] == b'?') {
                j += 1;
            }
            if j < b.len() && b[j].is_ascii_alphabetic() {
                i = j + 1;
            } else {
                i += 1;
            }
        } else if b[i] <= 0x08 || (0x0b..=0x1f).contains(&b[i]) {
            i += 1; // control char
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    // only ASCII bytes were removed, so this stays valid UTF-8; lossy = panic-free
    String::from_utf8_lossy(&out).into_owned()
}

// naive prompt strip (no B mark): drop through the LAST space-delimited sigil,
// port of the TS regex ^.*\s[%$#>]\s+
fn strip_prompt_sigil(line: &str) -> String {
    let b = line.as_bytes();
    let mut start = 0usize;
    let mut i = 0;
    while i + 2 < b.len() {
        if b[i].is_ascii_whitespace()
            && matches!(b[i + 1], b'%' | b'$' | b'#' | b'>')
            && b[i + 2].is_ascii_whitespace()
        {
            let mut j = i + 3;
            while j < b.len() && b[j].is_ascii_whitespace() {
                j += 1;
            }
            start = j;
            i = j;
        } else {
            i += 1;
        }
    }
    line[start..].to_string()
}

// parses "\x1b]133;<A|B|C|D>[;<digits>](\x07|\x1b\\)" at the start of s
// → (mark, exit code, total mark length)
fn parse_osc_mark(s: &[u8]) -> Option<(u8, Option<i32>, usize)> {
    let mut i = OSC_HDR.len();
    let mark = *s.get(i)?;
    if !matches!(mark, b'A' | b'B' | b'C' | b'D') {
        return None;
    }
    i += 1;
    let mut code = None;
    if s.get(i) == Some(&b';') {
        let start = i + 1;
        let mut j = start;
        while s.get(j).is_some_and(|b| b.is_ascii_digit()) {
            j += 1;
        }
        if j > start {
            // exit codes are 0-255 in practice; saturate absurd digit runs
            code = Some(std::str::from_utf8(&s[start..j]).ok()?.parse::<i32>().unwrap_or(i32::MAX));
            i = j;
        }
    }
    match (s.get(i), s.get(i + 1)) {
        (Some(&0x07), _) => Some((mark, code, i + 1)),
        (Some(&0x1b), Some(&b'\\')) => Some((mark, code, i + 2)),
        _ => None,
    }
}

impl OscScanner {
    fn set_typed(&mut self, line: String) {
        self.pending_typed = Some(line);
    }

    // Scan raw pty bytes; returns blocks finalized by D marks in this chunk.
    // Runs on the pty reader thread — panic-free by construction.
    fn feed(&mut self, bytes: &[u8]) -> Vec<Block> {
        let mut s = std::mem::take(&mut self.carry);
        s.extend_from_slice(bytes);

        // hold back an unterminated mark that may be split across chunks
        let j = s.windows(OSC_HDR.len()).rposition(|w| w == OSC_HDR);
        let unterminated = j
            .map(|j| {
                let tail = &s[j..];
                !tail.contains(&0x07) && !tail.windows(2).any(|w| w == b"\x1b\\")
            })
            .unwrap_or(false);
        if unterminated {
            let j = j.unwrap();
            if s.len() - j <= 64 {
                self.carry = s[j..].to_vec(); // longer means it's not our mark — drop from scan
            }
            s.truncate(j);
        } else {
            // a bare prefix of the header at the very end ("\x1b", "\x1b]1", …)
            for k in (1..=(OSC_HDR.len() - 1).min(s.len())).rev() {
                if s.ends_with(&OSC_HDR[..k]) {
                    self.carry = s[s.len() - k..].to_vec();
                    s.truncate(s.len() - k);
                    break;
                }
            }
        }

        let mut blocks = Vec::new();
        let mut idx = 0; // start of unfed text
        let mut pos = 0; // scan cursor
        while let Some(off) = s[pos..].windows(OSC_HDR.len()).position(|w| w == OSC_HDR) {
            let p = pos + off;
            let Some((mark, code, len)) = parse_osc_mark(&s[p..]) else {
                pos = p + 1; // not a valid mark — the header text flows into the segment
                continue;
            };
            self.feed_segment(&s[idx..p]);
            idx = p + len;
            pos = idx;
            match mark {
                b'A' | b'B' => self.pre_cmd.clear(),
                b'C' => {
                    // prefer what the user actually typed (clean); fall back to scraping
                    // the echo (agent-injected commands and history recalls have no typed line)
                    self.command = match self.pending_typed.take() {
                        Some(t) if !t.is_empty() => t,
                        _ => {
                            let cleaned = strip_ansi(&self.pre_cmd);
                            let last = cleaned.lines().map(str::trim).rfind(|l| !l.is_empty()).unwrap_or("");
                            strip_prompt_sigil(last)
                        }
                    };
                    self.output.clear();
                    self.started = Some(std::time::Instant::now());
                    self.capturing = true;
                }
                _ => {
                    // D;<code> — command end. First D (no prior C) is just the handshake.
                    if self.capturing {
                        blocks.push(Block {
                            command: self.command.clone(),
                            exit_code: code.unwrap_or(0),
                            output: strip_ansi(&self.output).trim().to_string(),
                            duration_ms: self.started.take().map(|t| t.elapsed().as_millis() as u64).unwrap_or(0),
                        });
                    }
                    self.capturing = false;
                }
            }
        }
        self.feed_segment(&s[idx..]);
        blocks
    }

    fn feed_segment(&mut self, seg: &[u8]) {
        if seg.is_empty() {
            return;
        }
        // chunk boundaries can split UTF-8 codepoints — decode lossily, never panic
        let text = String::from_utf8_lossy(seg);
        if self.capturing {
            self.output.push_str(&text);
            tail_cap(&mut self.output, 8192);
        } else {
            self.pre_cmd.push_str(&text);
            tail_cap(&mut self.pre_cmd, 512);
        }
    }
}

struct JournalState {
    blocks: Mutex<VecDeque<Block>>, // ring of last 50 finalized blocks
    scanner: Mutex<OscScanner>,
    // live feed of finalized blocks — the agent loop subscribes to capture command output
    tx: tokio::sync::broadcast::Sender<Block>,
}

impl Default for JournalState {
    fn default() -> Self {
        JournalState {
            blocks: Mutex::default(),
            scanner: Mutex::default(),
            tx: tokio::sync::broadcast::channel(16).0,
        }
    }
}

fn journal_push(blocks: &Mutex<VecDeque<Block>>, block: &Block) {
    let mut q = blocks.lock().unwrap();
    q.push_back(block.clone());
    if q.len() > 50 {
        q.pop_front();
    }
}

fn last_failed(q: &VecDeque<Block>) -> Option<Block> {
    q.iter().rev().find(|b| b.exit_code != 0).cloned()
}

#[tauri::command]
fn set_typed_command(journal: State<JournalState>, line: String) {
    journal.scanner.lock().unwrap().set_typed(line);
}

#[tauri::command]
fn journal_blocks(journal: State<JournalState>) -> Vec<Block> {
    journal.blocks.lock().unwrap().iter().cloned().collect()
}

#[tauri::command]
fn last_failed_block(journal: State<JournalState>) -> Option<Block> {
    last_failed(&journal.blocks.lock().unwrap())
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
        let journal = app.state::<JournalState>();
        let mut buf = [0u8; 65536];
        loop {
            match reader.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    // live output — always first, base64, byte-identical; the OSC scan
                    // below is an ADDITIONAL consumer of the same immutable slice
                    let _ = app.emit("pty-output", STANDARD.encode(&buf[..n]));
                    let finalized = journal.scanner.lock().unwrap().feed(&buf[..n]);
                    for block in finalized {
                        journal_push(&journal.blocks, &block); // no lock held across emit
                        let _ = journal.tx.send(block.clone()); // agent output capture (sync, no subscribers = Err, fine)
                        let _ = app.emit("journal-block", &block);
                    }
                }
            }
        }
        let _ = app.emit("pty-exit", ());
    });

    Ok(())
}

// The ONLY two callers: the pty_write command (user keystrokes / prefill without newline)
// and the agent loop's approved==true branch. Nothing else may write to the pty.
fn pty_write_internal(state: &PtyState, data: &str) -> Result<(), String> {
    match state.writer.lock().unwrap().as_mut() {
        Some(w) => w.write_all(data.as_bytes()).map_err(|e| e.to_string()),
        None => Err("pty not spawned".into()),
    }
}

#[tauri::command]
fn pty_write(state: State<PtyState>, data: String) -> Result<(), String> {
    pty_write_internal(&state, &data)
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

// IPC-safe views: never carry the raw key across the Tauri bridge into the webview.
#[derive(Clone, serde::Serialize)]
struct PublicProvider {
    id: String,
    kind: String,
    base_url: String,
    model: String,
    has_key: bool,
}

impl From<&Provider> for PublicProvider {
    fn from(p: &Provider) -> Self {
        PublicProvider {
            id: p.id.clone(),
            kind: p.kind.clone(),
            base_url: p.base_url.clone(),
            model: p.model.clone(),
            has_key: !p.key.is_empty(),
        }
    }
}

#[derive(Clone, serde::Serialize)]
struct PublicProviderState {
    active: String,
    providers: Vec<PublicProvider>,
}

impl From<&ProviderState> for PublicProviderState {
    fn from(s: &ProviderState) -> Self {
        PublicProviderState { active: s.active.clone(), providers: s.providers.iter().map(PublicProvider::from).collect() }
    }
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
fn provider_state() -> PublicProviderState {
    (&load_state()).into()
}

#[tauri::command]
fn provider_active() -> PublicProvider {
    (&load_state().active_provider()).into()
}

#[tauri::command]
fn provider_set_key(id: String, key: String) -> Result<PublicProviderState, String> {
    mutate(|s| s.set_key(&id, key)).map(|s| (&s).into())
}

#[tauri::command]
fn provider_set_model(id: String, model: String) -> Result<PublicProviderState, String> {
    mutate(|s| s.set_model(&id, model)).map(|s| (&s).into())
}

#[tauri::command]
fn provider_use(id: String) -> Result<PublicProviderState, String> {
    mutate(|s| s.use_provider(&id)).map(|s| (&s).into())
}

#[tauri::command]
fn provider_add_local(id: String, base_url: String, model: String, key: String) -> Result<PublicProviderState, String> {
    mutate(|s| {
        s.add_local(id, base_url, model, key);
        Ok(())
    })
    .map(|s| (&s).into())
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
// Shared core for ai_complete / nl_to_command / explain_last_error — one HTTP path.
async fn ai_call(system: &str, user: &str) -> Result<String, String> {
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
            .json(&build_anthropic_body(&p.model, system, user))
    } else {
        // OpenAI-compatible (openai, groq, gemini, kimi, deepseek, mistral, local). Local may have no key.
        let mut r = client
            .post(format!("{}/chat/completions", p.base_url.trim_end_matches('/')))
            .json(&build_openai_body(&p.model, system, user));
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

#[tauri::command]
async fn ai_complete(system: String, user: String) -> Result<String, String> {
    ai_call(&system, &user).await
}

// ---- NL→command (⌘K) + error autopsy (⌘E) ----
// Prompt assembly, fence stripping, and the danger check live here — the webview
// only sends the raw request and renders the result.

const AI_SYSTEM: &str = "You translate natural-language requests into a single shell command for zsh on macOS. \
Output ONLY the command — no markdown fences, no explanation, no commentary.";
const AI_EXPLAIN: &str = "You are a terminal assistant. Given recent terminal output, explain the most recent error \
or failure in 1-3 short sentences and suggest a fix. If there is no error, say so briefly. \
You may instead be given the exact failing command, its exit code, and its output. \
Plain text only, no markdown.";

// port of the TS: trim, strip a leading ```lang fence, strip a trailing ```
fn strip_fences(s: &str) -> String {
    let mut s = s.trim();
    if let Some(rest) = s.strip_prefix("```") {
        s = rest.trim_start_matches(|c: char| c.is_ascii_alphabetic()).trim_start();
    }
    s.trim_end_matches("```").trim().to_string()
}

// last `max` chars (not bytes — slicing bytes could split a codepoint and panic)
fn tail_chars(s: &str, max: usize) -> &str {
    match s.char_indices().rev().nth(max.saturating_sub(1)) {
        Some((i, _)) => &s[i..],
        None => s,
    }
}

// last 5 journal blocks as prompt context (~20 lines)
fn journal_context(q: &VecDeque<Block>) -> String {
    if q.is_empty() {
        return "(no recent commands)".into();
    }
    let mut out = String::from("Recent commands:");
    for b in q.iter().skip(q.len().saturating_sub(5)) {
        let cmd = if b.command.is_empty() { "(command)" } else { &b.command };
        out.push_str(&format!("\n$ {cmd} (exit {})\n{}", b.exit_code, tail_chars(&b.output, 500)));
    }
    out
}

// same data as get_context, rendered as prompt lines
fn shell_context_line(pid: Option<u32>) -> String {
    let cwd = pid.and_then(cwd_of_pid);
    let (branch, dirty) = cwd.as_deref().map(git_info).unwrap_or((None, 0));
    let git = match branch {
        Some(b) if dirty > 0 => format!("{b} ({dirty} dirty)"),
        Some(b) => b,
        None => "none".into(),
    };
    format!("cwd: {}\ngit: {git}", cwd.as_deref().unwrap_or("unknown"))
}

#[derive(serde::Serialize)]
struct NlCommand {
    command: String,
    danger: bool,
}

#[tauri::command]
async fn nl_to_command(
    pty: State<'_, PtyState>,
    journal: State<'_, JournalState>,
    request: String,
) -> Result<NlCommand, String> {
    // extract everything guarded before the first .await — MutexGuard is !Send
    let pid = *pty.shell_pid.lock().unwrap();
    let jctx = journal_context(&journal.blocks.lock().unwrap());
    let user = format!("{request}\n\nContext:\n{}\n{jctx}", shell_context_line(pid));
    let command = strip_fences(&ai_call(AI_SYSTEM, &user).await?);
    if command.is_empty() {
        return Err("no command returned".into());
    }
    let danger = is_dangerous(&command);
    Ok(NlCommand { command, danger })
}

#[tauri::command]
async fn explain_last_error(journal: State<'_, JournalState>) -> Result<String, String> {
    // clone the block and drop the guard before the .await
    let block = {
        let q = journal.blocks.lock().unwrap();
        last_failed(&q).or_else(|| q.back().cloned())
    };
    let Some(b) = block else {
        return Ok("no recent error to explain".into());
    };
    let cmd = if b.command.is_empty() { "(unknown)" } else { &b.command };
    let prompt = format!("Command: {cmd}\nExit code: {}\nOutput:\n{}", b.exit_code, tail_chars(&b.output, 3000));
    ai_call(AI_EXPLAIN, &prompt).await
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

// blocking (ureq) — call from a command thread or spawn_blocking, never the main thread
fn mcp_list_tools_inner() -> Result<Vec<McpServerTool>, String> {
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

// (async): blocking HTTP must not run on the main thread
#[tauri::command(async)]
fn mcp_list_tools() -> Result<Vec<McpServerTool>, String> {
    mcp_list_tools_inner()
}

// blocking (ureq) — call from a command thread or spawn_blocking, never the main thread
fn mcp_call_inner(server: &str, tool: &str, args: serde_json::Value) -> Result<String, String> {
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

#[tauri::command(async)]
fn mcp_call(server: String, tool: String, args: serde_json::Value) -> Result<String, String> {
    mcp_call_inner(&server, &tool, args)
}

// ---- Slash commands (⌘K "/…") ----
// Parsing + registry mutation live here; TS only prints the returned ANSI string.
// Provider display goes through PublicProvider (has_key), so a raw key structurally
// cannot appear in the output, and /key never echoes its argument.

const SLASH_HELP: &str = concat!(
    "\r\n\x1b[36m/keys\x1b[0m                       list providers, active, which have keys\r\n",
    "\x1b[36m/key <id> <apikey>\x1b[0m          set a provider's API key\r\n",
    "\x1b[36m/use <id> [model]\x1b[0m           switch active provider (+ optional model)\r\n",
    "\x1b[36m/model <model>\x1b[0m              set the active provider's model\r\n",
    "\x1b[36m/local <id> <url> <model> [key]\x1b[0m  add a local/OpenAI-compatible endpoint\r\n",
    "\x1b[36m/mcp add <name> <url>\x1b[0m       add a remote MCP server (Streamable HTTP)\r\n",
    "\x1b[36m/mcp remove <name>\x1b[0m          remove an MCP server\r\n",
    "\x1b[36m/mcp list\x1b[0m                   list MCP servers and their tools\r\n",
    "\x1b[90mbuilt-in ids: claude openai groq gemini kimi deepseek mistral\x1b[0m\r\n",
    "\x1b[90me.g. /local ollama http://localhost:11434/v1 llama3.2\x1b[0m\r\n",
);

fn render_providers(st: &ProviderState) -> String {
    let st: PublicProviderState = st.into(); // key field dropped here — has_key only
    let mut out = String::from("\r\n\x1b[36m[tachyon] providers\x1b[0m\r\n");
    for p in &st.providers {
        let mark = if p.id == st.active { "\x1b[32m●\x1b[0m" } else { " " };
        let keyed = if p.has_key {
            "\x1b[32m✓key\x1b[0m"
        } else if p.kind == "anthropic" {
            "\x1b[90m—\x1b[0m"
        } else {
            "\x1b[90mno key\x1b[0m"
        };
        out.push_str(&format!("{mark} {:<9} {keyed}  \x1b[90m{}\x1b[0m\r\n", p.id, p.model));
    }
    out
}

// blocking on /mcp list (ureq) — run_slash is (async) so this stays off the main thread
fn run_slash_inner(input: &str) -> Result<String, String> {
    let mut parts = input.strip_prefix('/').unwrap_or(input).split_whitespace();
    let cmd = parts.next().unwrap_or("").to_lowercase();
    let rest: Vec<&str> = parts.collect();
    match cmd.as_str() {
        "" | "help" => Ok(SLASH_HELP.into()),
        "keys" | "providers" => Ok(render_providers(&load_state())),
        "key" => match rest.split_first() {
            Some((id, key)) if !key.is_empty() => {
                mutate(|s| s.set_key(id, key.join(" ")))?;
                Ok(format!("\r\n\x1b[36m[tachyon] key set for {id}\x1b[0m\r\n"))
            }
            _ => Err("usage: /key <id> <apikey>".into()),
        },
        "use" => {
            let id = *rest.first().ok_or("usage: /use <id> [model]")?;
            let model = rest.get(1).copied();
            mutate(|s| {
                s.use_provider(id)?;
                if let Some(m) = model {
                    s.set_model(id, m.into())?;
                }
                Ok(())
            })?;
            let suffix = model.map(|m| format!(" · {m}")).unwrap_or_default();
            Ok(format!("\r\n\x1b[36m[tachyon] active provider: {id}{suffix}\x1b[0m\r\n"))
        }
        "model" => {
            if rest.is_empty() {
                return Err("usage: /model <model>".into());
            }
            let model = rest.join(" ");
            let active = load_state().active;
            mutate(|s| s.set_model(&active, model.clone()))?;
            Ok(format!("\r\n\x1b[36m[tachyon] {active} model: {model}\x1b[0m\r\n"))
        }
        "local" => match rest.as_slice() {
            [id, url, model, key @ ..] => {
                let (id, url) = (id.to_string(), url.to_string());
                let (model, key) = (model.to_string(), key.join(" "));
                mutate(|s| {
                    s.add_local(id.clone(), url.clone(), model, key);
                    Ok(())
                })?;
                Ok(format!("\r\n\x1b[36m[tachyon] added local provider {id} → {url}\x1b[0m\r\n"))
            }
            _ => Err("usage: /local <id> <base_url> <model> [key]".into()),
        },
        "mcp" => {
            let sub = rest.first().map(|s| s.to_lowercase()).unwrap_or_default();
            match sub.as_str() {
                "add" => match rest[1..] {
                    [name, url, ..] => {
                        mcp_add(name.into(), url.into())?;
                        Ok(format!("\r\n\x1b[36m[tachyon] mcp server {name} → {url}\x1b[0m\r\n"))
                    }
                    _ => Err("usage: /mcp add <name> <url>".into()),
                },
                "remove" => {
                    let name = *rest.get(1).ok_or("usage: /mcp remove <name>")?;
                    mcp_remove(name.into())?;
                    Ok(format!("\r\n\x1b[36m[tachyon] removed mcp server {name}\x1b[0m\r\n"))
                }
                "list" => {
                    let servers = load_mcp().servers;
                    if servers.is_empty() {
                        return Ok("\r\n\x1b[36m[tachyon] no mcp servers — /mcp add <name> <url>\x1b[0m\r\n".into());
                    }
                    let (tools, tool_err) = match mcp_list_tools_inner() {
                        Ok(t) => (t, String::new()),
                        Err(e) => (Vec::new(), e), // per-server errors; never blanks the list
                    };
                    let mut out = String::from("\r\n\x1b[36m[tachyon] mcp servers\x1b[0m\r\n");
                    for s in &servers {
                        out.push_str(&format!("  {:<12} \x1b[90m{}\x1b[0m\r\n", s.name, s.url));
                        for t in tools.iter().filter(|t| t.server == s.name) {
                            out.push_str(&format!(
                                "    \x1b[36m{}.{}\x1b[0m  \x1b[90m{}\x1b[0m\r\n",
                                t.server, t.name, t.description
                            ));
                        }
                    }
                    if !tool_err.is_empty() {
                        out.push_str(&format!("\x1b[31m[tachyon] {tool_err}\x1b[0m\r\n"));
                    }
                    Ok(out)
                }
                _ => Err("usage: /mcp add|remove|list".into()),
            }
        }
        other => Err(format!("unknown command: /{other} — try /help")),
    }
}

// (async): /mcp list does blocking HTTP — must not run on the main thread.
// Never rejects: errors come back as printable red ANSI text.
#[tauri::command(async)]
fn run_slash(input: String) -> String {
    run_slash_inner(&input).unwrap_or_else(|e| format!("\r\n\x1b[31m[tachyon] {e}\x1b[0m\r\n"))
}

// ---- Agent loop (⌘J) ----
// The full orchestration runs here on a background task; the webview only renders
// the approval gate. INVARIANT: no command or tool ever runs without an explicit
// agent_decide(true), which TS invokes only from a literal Enter keypress.

const AI_AGENT: &str = "You drive a macOS zsh terminal to accomplish the user's task step by step. \
Respond with EXACTLY ONE line: either 'RUN: <single shell command>' to execute a command, \
or 'DONE: <one-sentence summary>' when the task is complete or cannot proceed. \
No markdown, no prose, no multiple commands, no explanation. \
You are given each command's output before deciding the next step.";

#[derive(Debug, PartialEq)]
enum AgentAction {
    Done(String),
    Run(String),
    Tool { server: String, tool: String, args: serde_json::Value },
    Invalid(String),
}

fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    s.get(..prefix.len()).filter(|p| p.eq_ignore_ascii_case(prefix)).map(|_| &s[prefix.len()..])
}

// one-line agent reply → action. Port of the TS RUN/DONE/TOOL parsing.
fn parse_agent_reply(reply: &str) -> AgentAction {
    let reply = reply.trim();
    if let Some(rest) = strip_prefix_ci(reply, "DONE:") {
        return AgentAction::Done(rest.trim().to_string());
    }
    if let Some(rest) = strip_prefix_ci(reply, "TOOL:") {
        let rest = rest.trim();
        let (tool_ref, args_str) = match rest.find(' ') {
            Some(sp) => (&rest[..sp], rest[sp + 1..].trim()),
            None => (rest, ""),
        };
        let Some(dot) = tool_ref.find('.').filter(|&d| d >= 1) else {
            return AgentAction::Invalid(reply.to_string());
        };
        let args = serde_json::from_str(args_str).unwrap_or_else(|_| serde_json::json!({}));
        return AgentAction::Tool {
            server: tool_ref[..dot].to_string(),
            tool: tool_ref[dot + 1..].to_string(),
            args,
        };
    }
    let cmd = strip_fences(strip_prefix_ci(reply, "RUN:").unwrap_or(reply));
    if cmd.is_empty() {
        AgentAction::Done("no command returned".into())
    } else {
        AgentAction::Run(cmd)
    }
}

#[derive(Default)]
struct AgentState {
    // one oneshot Sender parked per proposal; agent_decide take()s it (double-decide = no-op)
    decision: Mutex<Option<tokio::sync::oneshot::Sender<bool>>>,
    abort: std::sync::atomic::AtomicBool,
    running: std::sync::atomic::AtomicBool,
}

use std::sync::atomic::Ordering::SeqCst;

#[tauri::command]
fn agent_start(app: AppHandle, task: String) -> Result<(), String> {
    {
        let a = app.state::<AgentState>();
        if a.running.swap(true, SeqCst) {
            return Err("agent already running".into());
        }
        a.abort.store(false, SeqCst);
        // drop any stale sender — a decision from a previous run must never approve this one
        a.decision.lock().unwrap().take();
    }
    tauri::async_runtime::spawn(agent_loop(app, task));
    Ok(())
}

#[tauri::command]
fn agent_decide(agent: State<AgentState>, approved: bool) {
    if let Some(tx) = agent.decision.lock().unwrap().take() {
        let _ = tx.send(approved);
    }
}

#[tauri::command]
fn agent_abort(agent: State<AgentState>) {
    agent.abort.store(true, SeqCst);
    // dropping the parked sender resolves the pending rx as Err → deny (fail-closed)
    agent.decision.lock().unwrap().take();
}

// park a fresh oneshot, emit the proposal, block until agent_decide. Every failure
// mode (dropped sender, abort) resolves to false — fail-closed.
async fn agent_propose(app: &AppHandle, payload: serde_json::Value) -> bool {
    let (tx, rx) = tokio::sync::oneshot::channel::<bool>();
    *app.state::<AgentState>().decision.lock().unwrap() = Some(tx);
    let _ = app.emit("agent-propose", payload);
    rx.await.unwrap_or(false)
}

async fn agent_loop(app: AppHandle, task: String) {
    let aborted = |app: &AppHandle| app.state::<AgentState>().abort.load(SeqCst);

    // transcript seed: same shape as the old TS runAgent (context + recent journal)
    let pid = *app.state::<PtyState>().shell_pid.lock().unwrap();
    let jctx = journal_context(&app.state::<JournalState>().blocks.lock().unwrap());
    let mut transcript = format!("Task: {task}\n\nContext:\n{}\n{jctx}\n", shell_context_line(pid));

    // tool discovery is best-effort; ureq is blocking → spawn_blocking
    let tools = tauri::async_runtime::spawn_blocking(mcp_list_tools_inner)
        .await
        .ok()
        .and_then(Result::ok)
        .unwrap_or_default();
    let system = if tools.is_empty() {
        AI_AGENT.to_string()
    } else {
        format!(
            "{AI_AGENT} You may also call a tool: respond with EXACTLY 'TOOL: <server>.<name> {{json arguments}}' (one line).\nTOOLS:\n{}",
            tools.iter().map(|t| format!("TOOL {}.{} — {}", t.server, t.name, t.description)).collect::<Vec<_>>().join("\n")
        )
    };

    let mut done = false;
    for step in 1..=12u32 {
        if aborted(&app) {
            break;
        }
        let _ = app.emit("agent-status", serde_json::json!({ "step": step, "status": "thinking" }));
        let reply = match ai_call(&system, &transcript).await {
            Ok(r) => r,
            Err(e) => {
                let _ = app.emit("agent-done", serde_json::json!({ "summary": e }));
                done = true;
                break;
            }
        };
        if aborted(&app) {
            break;
        }
        match parse_agent_reply(&reply) {
            AgentAction::Done(msg) => {
                let _ = app.emit("agent-done", serde_json::json!({ "summary": msg }));
                done = true;
                break;
            }
            AgentAction::Invalid(r) => {
                transcript.push_str(&format!("\nInvalid tool call: {r}\n"));
            }
            AgentAction::Run(cmd) => {
                let danger = is_dangerous(&cmd);
                let approved = agent_propose(
                    &app,
                    serde_json::json!({ "step": step, "kind": "run", "text": cmd, "args": null, "danger": danger }),
                )
                .await;
                if aborted(&app) {
                    break;
                }
                if !approved {
                    transcript.push_str(&format!("\nThe user denied running: {cmd}. Suggest an alternative or DONE.\n"));
                    let _ = app.emit("agent-status", serde_json::json!({ "step": step, "status": "denied" }));
                    continue;
                }
                // subscribe BEFORE writing so the finalized block can't slip past
                let mut rx_block = app.state::<JournalState>().tx.subscribe();
                // clean journal label — agent commands have no typed line to scrape
                app.state::<JournalState>().scanner.lock().unwrap().set_typed(cmd.clone());
                let _ = app.emit("agent-status", serde_json::json!({ "step": step, "status": "running" }));
                // INVARIANT: the ONLY pty write in the agent path — lexically inside the
                // approved==true branch, reachable only via agent_decide(true).
                let write = pty_write_internal(&app.state::<PtyState>(), &format!("{cmd}\n"));
                if let Err(e) = write {
                    let _ = app.emit("agent-done", serde_json::json!({ "summary": e }));
                    done = true;
                    break;
                }
                // output + exit come from the L1 OSC journal; 20s ceiling like the old sentinel
                let (output, code) =
                    match tokio::time::timeout(std::time::Duration::from_secs(20), rx_block.recv()).await {
                        Ok(Ok(b)) => (b.output, b.exit_code),
                        _ => (String::new(), -1),
                    };
                let _ = app.emit("agent-output", serde_json::json!({ "step": step, "text": format!("exit {code}") }));
                let out = if code == -1 && output.is_empty() { "(no exit marker)".into() } else { truncate_chars(&output, 2000) };
                transcript.push_str(&format!("\nCommand: {cmd}\nExit code: {code}\nOutput:\n{out}\n"));
            }
            AgentAction::Tool { server, tool, args } => {
                let approved = agent_propose(
                    &app,
                    serde_json::json!({
                        "step": step, "kind": "tool",
                        "text": format!("call {server}.{tool}({args})"),
                        "args": args, "danger": false
                    }),
                )
                .await;
                if aborted(&app) {
                    break;
                }
                if !approved {
                    transcript.push_str(&format!("\nThe user denied tool call {server}.{tool}. Suggest an alternative or DONE.\n"));
                    let _ = app.emit("agent-status", serde_json::json!({ "step": step, "status": "denied" }));
                    continue;
                }
                let _ = app.emit("agent-status", serde_json::json!({ "step": step, "status": "tool" }));
                let (s, t) = (server.clone(), tool.clone());
                let result = tauri::async_runtime::spawn_blocking(move || mcp_call_inner(&s, &t, args)).await;
                match result.map_err(|e| e.to_string()).and_then(|r| r) {
                    Ok(out) => {
                        let _ = app.emit(
                            "agent-output",
                            serde_json::json!({ "step": step, "text": format!("tool {server}.{tool} → {}", truncate_chars(&out, 500)) }),
                        );
                        transcript.push_str(&format!("\nTool: {server}.{tool}\nResult:\n{}\n", truncate_chars(&out, 2000)));
                    }
                    Err(e) => {
                        let _ = app.emit("agent-output", serde_json::json!({ "step": step, "text": format!("tool error: {e}") }));
                        transcript.push_str(&format!("\nTool error: {}\n", truncate_chars(&e, 2000)));
                    }
                }
            }
        }
    }
    if !done {
        // aborted mid-run or hit the step ceiling — either way tell the webview to reset
        let summary = if aborted(&app) { "aborted" } else { "step limit reached" };
        let _ = app.emit("agent-done", serde_json::json!({ "summary": summary }));
    }
    let a = app.state::<AgentState>();
    a.running.store(false, SeqCst);
    a.decision.lock().unwrap().take();
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
            app.manage(JournalState::default());
            app.manage(AgentState::default());
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            pty_spawn,
            pty_write,
            pty_resize,
            set_typed_command,
            journal_blocks,
            last_failed_block,
            get_context,
            check_dangerous,
            provider_state,
            provider_active,
            provider_set_key,
            provider_set_model,
            provider_use,
            provider_add_local,
            ai_complete,
            nl_to_command,
            explain_last_error,
            agent_start,
            agent_decide,
            agent_abort,
            mcp_add,
            mcp_remove,
            mcp_servers,
            mcp_list_tools,
            mcp_call,
            run_slash
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
    fn slash_usage_and_unknown_errors() {
        assert_eq!(run_slash_inner("/key groq").unwrap_err(), "usage: /key <id> <apikey>");
        assert_eq!(run_slash_inner("/foo").unwrap_err(), "unknown command: /foo — try /help");
        assert_eq!(run_slash_inner("/mcp frobnicate").unwrap_err(), "usage: /mcp add|remove|list");
        assert_eq!(run_slash_inner("/help").unwrap(), SLASH_HELP);
        assert_eq!(run_slash_inner("/").unwrap(), SLASH_HELP);
    }

    #[test]
    fn slash_providers_redact_keys() {
        let mut s = ProviderState::defaults();
        s.set_key("groq", "gsk_supersecret".into()).unwrap();
        s.use_provider("groq").unwrap();
        let out = render_providers(&s);
        assert!(out.contains("✓key"));
        assert!(!out.contains("gsk_supersecret"));
        assert!(out.contains("\x1b[32m●\x1b[0m groq"));
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

    // Adversarial tests for parse_anthropic_response
    #[test]
    fn parse_anthropic_empty_text() {
        // valid structure but empty text string
        let body = r#"{"content":[{"type":"text","text":""}]}"#;
        assert_eq!(parse_anthropic_response(body).unwrap(), "");
    }

    #[test]
    fn parse_anthropic_unicode_content() {
        // valid unicode including emoji, non-Latin scripts, etc.
        let body = r#"{"content":[{"type":"text","text":"Hello 世界 🚀 مرحبا"}]}"#;
        assert_eq!(parse_anthropic_response(body).unwrap(), "Hello 世界 🚀 مرحبا");
    }

    #[test]
    fn parse_anthropic_no_content_array() {
        // missing "content" field entirely
        let body = r#"{"message":"no content field"}"#;
        assert!(parse_anthropic_response(body).is_err());
    }

    #[test]
    fn parse_anthropic_null_content() {
        // "content" is null
        let body = r#"{"content":null}"#;
        assert!(parse_anthropic_response(body).is_err());
    }

    // Adversarial tests for parse_openai_response
    #[test]
    fn parse_openai_empty_content() {
        // valid structure but empty content string
        let body = r#"{"choices":[{"message":{"role":"assistant","content":""}}]}"#;
        assert_eq!(parse_openai_response(body).unwrap(), "");
    }

    #[test]
    fn parse_openai_unicode_content() {
        // valid unicode including emoji, RTL, CJK
        let body = r#"{"choices":[{"message":{"role":"assistant","content":"Привет 🌍 العالم こんにちは"}}]}"#;
        assert_eq!(parse_openai_response(body).unwrap(), "Привет 🌍 العالم こんにちは");
    }

    #[test]
    fn parse_openai_no_choices() {
        // missing "choices" field
        let body = r#"{"message":"missing choices"}"#;
        assert!(parse_openai_response(body).is_err());
    }

    #[test]
    fn parse_openai_null_choices() {
        // "choices" is null
        let body = r#"{"choices":null}"#;
        assert!(parse_openai_response(body).is_err());
    }

    // ---- OSC 133 scanner ----

    #[test]
    fn osc_full_cycle_bel_form() {
        let mut sc = OscScanner::default();
        // handshake D (no prior C) yields no block, then a real A/C/D cycle
        let blocks = sc.feed(b"\x1b]133;D;0\x07\x1b]133;A\x07prompt % echo hi\x1b]133;C\x07hi\n\x1b]133;D;0\x07");
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].command, "echo hi"); // echo-scrape, prompt sigil stripped
        assert_eq!(blocks[0].output, "hi");
        assert_eq!(blocks[0].exit_code, 0);
    }

    #[test]
    fn osc_st_terminator_form() {
        let mut sc = OscScanner::default();
        let blocks = sc.feed(b"\x1b]133;C\x1b\\out\x1b]133;D;2\x1b\\");
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].output, "out");
        assert_eq!(blocks[0].exit_code, 2);
    }

    #[test]
    fn osc_split_at_every_offset() {
        for seq in [
            b"\x1b]133;A\x07p % echo hi\x1b]133;C\x07hi\n\x1b]133;D;0\x07".as_slice(),
            b"\x1b]133;A\x1b\\p % echo hi\x1b]133;C\x1b\\hi\n\x1b]133;D;0\x1b\\".as_slice(),
        ] {
            for split in 0..=seq.len() {
                let mut sc = OscScanner::default();
                let mut blocks = sc.feed(&seq[..split]);
                blocks.extend(sc.feed(&seq[split..]));
                assert_eq!(blocks.len(), 1, "split at {split}");
                assert_eq!(blocks[0].command, "echo hi", "split at {split}");
                assert_eq!(blocks[0].output, "hi", "split at {split}");
            }
        }
    }

    #[test]
    fn osc_typed_label_beats_echo_scrape_and_is_consumed_once() {
        let mut sc = OscScanner::default();
        sc.set_typed("ls -la".into());
        let b1 = sc.feed(b"\x1b]133;A\x07p % garbled echo\x1b]133;C\x07f\x1b]133;D;0\x07");
        assert_eq!(b1[0].command, "ls -la");
        // no typed line for the next command → echo scrape
        let b2 = sc.feed(b"\x1b]133;A\x07p % cat foo\x1b]133;C\x07x\x1b]133;D;1\x07");
        assert_eq!(b2[0].command, "cat foo");
        assert_eq!(b2[0].exit_code, 1);
    }

    #[test]
    fn osc_first_d_is_handshake_only() {
        let mut sc = OscScanner::default();
        assert!(sc.feed(b"\x1b]133;D;0\x07\x1b]133;A\x07").is_empty());
    }

    #[test]
    fn osc_d_127_exit_parse() {
        let mut sc = OscScanner::default();
        let blocks = sc.feed(b"\x1b]133;C\x07zsh: command not found\x1b]133;D;127\x07");
        assert_eq!(blocks[0].exit_code, 127);
    }

    #[test]
    fn osc_unterminated_long_header_no_stall() {
        let mut sc = OscScanner::default();
        let mut noise = b"\x1b]133;".to_vec();
        noise.extend(std::iter::repeat(b'x').take(100)); // >64: not our mark, dropped from scan
        assert!(sc.feed(&noise).is_empty());
        assert!(sc.carry.is_empty());
        let blocks = sc.feed(b"\x1b]133;C\x07ok\x1b]133;D;0\x07");
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].output, "ok");
    }

    #[test]
    fn osc_output_strips_ansi_and_caps_tail() {
        let mut sc = OscScanner::default();
        sc.feed(b"\x1b]133;C\x07\x1b[31mred\x1b[0m\n");
        let big = vec![b'a'; 9000];
        sc.feed(&big);
        let blocks = sc.feed(b"\x1b]133;D;0\x07");
        assert!(blocks[0].output.len() <= 8192);
        assert!(!blocks[0].output.contains('\x1b'));
    }

    #[test]
    fn journal_ring_caps_at_50() {
        let blocks = Mutex::new(VecDeque::new());
        for i in 0..55 {
            let b = Block { command: format!("c{i}"), exit_code: 0, output: String::new(), duration_ms: 0 };
            journal_push(&blocks, &b);
        }
        let q = blocks.lock().unwrap();
        assert_eq!(q.len(), 50);
        assert_eq!(q.front().unwrap().command, "c5");
        assert_eq!(q.back().unwrap().command, "c54");
    }

    #[test]
    fn last_failed_picks_most_recent_nonzero() {
        let mut q = VecDeque::new();
        for (i, code) in [0, 1, 0, 2, 0].iter().enumerate() {
            q.push_back(Block { command: format!("c{i}"), exit_code: *code, output: String::new(), duration_ms: 0 });
        }
        assert_eq!(last_failed(&q).unwrap().command, "c3");
        assert!(last_failed(&VecDeque::new()).is_none());
    }

    // ---- ⌘K / ⌘E helpers ----

    #[test]
    fn strip_fences_variants() {
        assert_eq!(strip_fences("```zsh\nls -la\n```"), "ls -la");
        assert_eq!(strip_fences("```\nls\n```"), "ls");
        assert_eq!(strip_fences("ls -la"), "ls -la");
        assert_eq!(strip_fences("ls -la\n```"), "ls -la"); // trailing-only
        assert_eq!(strip_fences("  echo hi  "), "echo hi");
        assert_eq!(strip_fences(""), "");
    }

    #[test]
    fn tail_chars_boundaries() {
        assert_eq!(tail_chars("hello", 500), "hello");
        assert_eq!(tail_chars("hello", 2), "lo");
        assert_eq!(tail_chars("héllo", 4), "éllo"); // no mid-codepoint panic
        assert_eq!(tail_chars("", 5), "");
    }

    #[test]
    fn journal_context_formats_last_five() {
        let mut q = VecDeque::new();
        for i in 0..7 {
            q.push_back(Block {
                command: format!("cmd{i}"),
                exit_code: i,
                output: format!("out{i}"),
                duration_ms: 0,
            });
        }
        let ctx = journal_context(&q);
        assert!(ctx.starts_with("Recent commands:"));
        assert!(!ctx.contains("cmd1")); // only the last 5
        assert!(ctx.contains("$ cmd2 (exit 2)\nout2"));
        assert!(ctx.contains("$ cmd6 (exit 6)\nout6"));
    }

    #[test]
    fn journal_context_empty_and_unnamed() {
        assert_eq!(journal_context(&VecDeque::new()), "(no recent commands)");
        let mut q = VecDeque::new();
        q.push_back(Block { command: String::new(), exit_code: 0, output: "x".into(), duration_ms: 0 });
        assert!(journal_context(&q).contains("$ (command) (exit 0)"));
    }

    // ---- agent reply parser ----

    #[test]
    fn agent_done_and_case_insensitive() {
        assert_eq!(parse_agent_reply("DONE: all set"), AgentAction::Done("all set".into()));
        assert_eq!(parse_agent_reply("  done: finished  "), AgentAction::Done("finished".into()));
        assert_eq!(parse_agent_reply("DONE:"), AgentAction::Done("".into()));
    }

    #[test]
    fn agent_run_variants() {
        assert_eq!(parse_agent_reply("RUN: ls -la"), AgentAction::Run("ls -la".into()));
        assert_eq!(parse_agent_reply("run: git status"), AgentAction::Run("git status".into()));
        // bare command without a RUN: prefix
        assert_eq!(parse_agent_reply("echo hi"), AgentAction::Run("echo hi".into()));
        // fenced reply
        assert_eq!(parse_agent_reply("RUN: ```zsh\nls\n```"), AgentAction::Run("ls".into()));
        // empty command → Done, never a blank pty write
        assert_eq!(parse_agent_reply(""), AgentAction::Done("no command returned".into()));
        assert_eq!(parse_agent_reply("RUN: ```\n```"), AgentAction::Done("no command returned".into()));
    }

    #[test]
    fn agent_tool_variants() {
        assert_eq!(
            parse_agent_reply(r#"TOOL: srv.echo {"a":1}"#),
            AgentAction::Tool { server: "srv".into(), tool: "echo".into(), args: serde_json::json!({"a":1}) }
        );
        // no args → {}
        assert_eq!(
            parse_agent_reply("tool: srv.echo"),
            AgentAction::Tool { server: "srv".into(), tool: "echo".into(), args: serde_json::json!({}) }
        );
        // malformed JSON args → {}
        assert_eq!(
            parse_agent_reply("TOOL: srv.echo not-json"),
            AgentAction::Tool { server: "srv".into(), tool: "echo".into(), args: serde_json::json!({}) }
        );
        // dotted tool name keeps the first dot as the server split
        assert_eq!(
            parse_agent_reply("TOOL: srv.ns.echo {}"),
            AgentAction::Tool { server: "srv".into(), tool: "ns.echo".into(), args: serde_json::json!({}) }
        );
    }

    #[test]
    fn agent_tool_dotless_is_invalid() {
        assert_eq!(parse_agent_reply("TOOL: echo {}"), AgentAction::Invalid("TOOL: echo {}".into()));
        assert_eq!(parse_agent_reply("TOOL: .echo {}"), AgentAction::Invalid("TOOL: .echo {}".into()));
    }

    #[test]
    fn agent_multibyte_reply_no_panic() {
        // strip_prefix_ci must not slice mid-codepoint
        assert_eq!(parse_agent_reply("échо"), AgentAction::Run("échо".into()));
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
