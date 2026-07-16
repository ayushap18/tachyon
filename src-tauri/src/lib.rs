use std::io::{Read, Write};
use std::sync::Mutex;

use portable_pty::{native_pty_system, Child, CommandBuilder, MasterPty, PtySize};
use tauri::{AppHandle, Emitter, Manager, State};

#[derive(Default)]
struct PtyState {
    master: Mutex<Option<Box<dyn MasterPty + Send>>>,
    writer: Mutex<Option<Box<dyn Write + Send>>>,
    child: Mutex<Option<Box<dyn Child + Send + Sync>>>,
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

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            app.manage(PtyState::default());
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![pty_spawn, pty_write, pty_resize])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
