use std::io::{Read, Write};
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
    let mut cmd = CommandBuilder::new(shell);
    cmd.env("TERM", "xterm-256color");
    if let Ok(home) = std::env::var("HOME") {
        cmd.cwd(home);
    }

    let child = pair.slave.spawn_command(cmd).map_err(|e| e.to_string())?;
    let mut reader = pair.master.try_clone_reader().map_err(|e| e.to_string())?;

    *state.writer.lock().unwrap() = Some(pair.master.take_writer().map_err(|e| e.to_string())?);
    *state.shell_pid.lock().unwrap() = child.process_id();
    *state.child.lock().unwrap() = Some(child);
    *master_slot = Some(pair.master);

    std::thread::spawn(move || {
        let mut buf = [0u8; 8192];
        loop {
            match reader.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let _ = app.emit("pty-output", buf[..n].to_vec());
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
// kind == "anthropic" → called via @anthropic-ai/sdk; anything else is OpenAI-compatible:
// the frontend POSTs `${base_url}/chat/completions`. Config persists to ~/.config/tachyon/providers.json.

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
            provider_add_local
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
    fn git_info_tachyon_repo() {
        let (branch, _dirty) = git_info("/Users/ayush18/tachyon");
        assert_eq!(branch.as_deref(), Some("main"));
    }

    #[test]
    fn git_info_non_git_dir() {
        assert_eq!(git_info("/"), (None, 0));
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
    fn merge_defaults_keeps_user_and_adds_missing() {
        let mut s = ProviderState { active: "groq".into(), providers: vec![builtin("groq", "openai", "x", "m")] };
        s.providers[0].key = "keep".into();
        s.merge_defaults();
        assert_eq!(s.providers.iter().find(|p| p.id == "groq").unwrap().key, "keep");
        assert!(s.providers.iter().any(|p| p.id == "mistral"));
    }
}
