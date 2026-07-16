use std::io::{Read, Write};
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
        .invoke_handler(tauri::generate_handler![pty_spawn, pty_write, pty_resize, get_context])
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
}
