//! In-app update: a check that only reads, and an install that only a native menu can start.
//!
//! SECURITY — an updater is remote code execution, so the boundaries are:
//!   * the endpoint and the minisign public key reach the binary through `generate_context!`
//!     at COMPILE time (`tauri.conf.json` -> `plugins.updater`). The one runtime override
//!     the plugin offers is forbidden here and pinned by a test in lib.rs;
//!   * `capabilities/default.json` never grants `updater:*`. Plugin commands ARE ACL-scoped
//!     in Tauri 2, so `invoke("plugin:updater|download_and_install")` is rejected in Rust
//!     before any handler runs;
//!   * app commands are NOT ACL-scoped (docs/danger-gate.md), which is exactly why the
//!     install path registers no `#[tauri::command]` at all. `update_check` is the only new
//!     handler entry in this release and it downloads nothing, writes nothing, runs nothing;
//!   * installing is reached only from a native menu activation, which AppKit/GTK deliver
//!     straight to Rust. `/update install` returns a usage string, never an install.

use std::path::Path;

use tauri::menu::{Menu, MenuItem, MenuItemKind, Submenu};
use tauri_plugin_updater::UpdaterExt;

use super::*;

/// Menu item id. Also the grep S5 uses to prove no IPC handler carries it.
const MENU_ID: &str = "tachyon:update";
const RELEASES: &str = "https://github.com/ayushap18/tachyon/releases/latest";
const USAGE: &str = "usage: /update \u{2014} to install, press \u{2318}U (Ctrl+U off macOS)";

/// The accelerator as the user reads it. `CmdOrCtrl+U` is what the menu is registered with.
const ACC: &str = if cfg!(target_os = "macos") { "\u{2318}U" } else { "Ctrl+U" };

// ---- U3: can this installation replace itself in place? ----

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InstallTarget {
    /// macOS .app outside AppTranslocation, or a writable $APPIMAGE.
    Replaceable,
    /// macOS, running from a read-only AppTranslocation image (i.e. straight off the .dmg).
    Translocated,
    /// Linux, installed from .deb / built from source / extracted — nothing to replace.
    NotAppImage,
    Unsupported,
}

/// Pure, so it is testable without env vars or a real bundle. Branching on the RUNNING
/// PROCESS rather than on the packaging format is what collapses .deb, source builds,
/// read-only mounts AND `--appimage-extract-and-run` (which release.mjs tells FUSE-less
/// users to run) into one correct answer.
pub(crate) fn install_target(
    os: &str,
    appimage: Option<&Path>,
    appimage_writable: bool,
    exe: &Path,
) -> InstallTarget {
    match os {
        "macos" => match exe.components().any(|c| c.as_os_str() == "AppTranslocation") {
            true => InstallTarget::Translocated,
            false => InstallTarget::Replaceable,
        },
        "linux" => match appimage {
            Some(p) if p.exists() && appimage_writable => InstallTarget::Replaceable,
            _ => InstallTarget::NotAppImage,
        },
        _ => InstallTarget::Unsupported,
    }
}

/// The env/filesystem wrapper. One line of impurity, no logic.
pub(crate) fn current_target() -> InstallTarget {
    let appimage = std::env::var_os("APPIMAGE").map(std::path::PathBuf::from);
    let exe = std::env::current_exe().unwrap_or_default();
    install_target(
        std::env::consts::OS,
        appimage.as_deref(),
        appimage.as_deref().is_some_and(can_replace),
        &exe,
    )
}

/// The plugin installs an AppImage by renaming the old file aside and writing the new one
/// at the same path, so the permission that decides the outcome is on the PARENT DIRECTORY.
/// Probing the AppImage itself would be wrong twice over: opening the running executable
/// for writing fails ETXTBSY on Linux even when the update would have succeeded.
/// ponytail: create-and-delete probe, ~2 per launch on Linux only. A real capability check
/// means libc/faccessat, which is a dependency for one boolean.
fn can_replace(appimage: &Path) -> bool {
    let Some(dir) = appimage.parent() else { return false };
    let probe = dir.join(".tachyon-update-probe");
    let ok = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe)
        .is_ok();
    // Unconditional, so a probe left by a crash heals itself on the next launch.
    let _ = std::fs::remove_file(&probe);
    ok
}

// ---- U4: the notice ----

/// One line, or None when there is nothing worth saying. `latest` is None when the check
/// failed, was opted out of, or the running version is current. The line NEVER says
/// "verified by Apple" or anything a user reads that way — tauri.conf.json's signing
/// identity is ad-hoc and Apple verified nothing.
pub(crate) fn notice(current: &str, latest: Option<&str>, target: InstallTarget) -> Option<String> {
    let v = latest?;
    let tail = match target {
        InstallTarget::Replaceable => format!("Press {ACC} to update in place."),
        InstallTarget::NotAppImage => {
            format!("This build updates through your package manager: {RELEASES}")
        }
        InstallTarget::Translocated => {
            format!("Move Tachyon to /Applications and relaunch, then press {ACC}.")
        }
        // Nothing here can update itself, so an unprompted line would only nag.
        InstallTarget::Unsupported => return None,
    };
    Some(format!(
        "\r\n\x1b[36m[tachyon] Tachyon {v} is available \u{2014} you have {current}. {tail}\x1b[0m\r\n"
    ))
}

/// Every failure is None: a check the user did not ask for must not surface an error.
/// Uses `app.updater()`, never the runtime override — the compiled-in endpoint and public
/// key are the whole security model.
async fn latest_version(app: &AppHandle) -> Option<String> {
    let update = app.updater().ok()?.check().await.ok()??;
    Some(update.version)
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum UpdateCmd {
    Check,
    Install,
}

/// Pure, mirrors `mcp_server::parse_serve` so `slash` stays a two-liner.
pub(crate) fn parse_update(input: &str) -> Option<Result<UpdateCmd, String>> {
    let lower = input.strip_prefix('/').unwrap_or(input).to_lowercase();
    let words: Vec<&str> = lower.split_whitespace().collect();
    let ["update", rest @ ..] = words.as_slice() else {
        return None;
    };
    Some(match rest {
        [] => Ok(UpdateCmd::Check),
        ["install"] => Ok(UpdateCmd::Install),
        _ => Err(USAGE.into()),
    })
}

/// Peeled off run_slash exactly like `mcp_server::slash`, which has no AppHandle.
pub(crate) async fn slash(app: &AppHandle, input: &str) -> Option<Result<String, String>> {
    Some(match parse_update(input)? {
        Ok(UpdateCmd::Check) => Ok(check_line(app).await),
        // `/update` is ungated IPC like every slash command, so this arm must stay a string.
        Ok(UpdateCmd::Install) => Err(USAGE.into()),
        Err(e) => Err(e),
    })
}

/// `/update` asked a direct question, so unlike the startup notice it always answers.
async fn check_line(app: &AppHandle) -> String {
    let cur = app.package_info().version.to_string();
    let latest = latest_version(app).await;
    let line = notice(&cur, latest.as_deref(), current_target());
    line.unwrap_or_else(|| match latest {
        Some(v) => format!(
            "\r\n\x1b[36m[tachyon] Tachyon {v} is available \u{2014} you have {cur}: {RELEASES}\x1b[0m\r\n"
        ),
        None => format!("\r\n\x1b[36m[tachyon] Tachyon {cur} is the latest version\x1b[0m\r\n"),
    })
}

/// IPC. An https GET of the compile-time endpoint, a version compare, one string back.
/// Downloads nothing, writes nothing, executes nothing — reachable from webview script
/// exactly like `run_slash`, and that is acceptable and stated in danger-gate.md.
// ponytail: one check per process launch, no cache file. A terminal is not launched in a
// loop; add config_dir()/update.json only if telemetry ever shows the GET is a nuisance.
#[tauri::command]
pub(crate) async fn update_check(app: AppHandle) -> Option<String> {
    // An env var, not a fifth JSON file under config_dir() for one boolean.
    if std::env::var("TACHYON_NO_UPDATE_CHECK").is_ok_and(|v| v == "1") {
        return None;
    }
    let cur = app.package_info().version.to_string();
    notice(&cur, latest_version(&app).await.as_deref(), current_target())
}

// ---- U5: the install ----

/// Builds the "Check for Updates…" item onto the app menu and registers the handler.
/// Installed ONLY when `current_target() == Replaceable`, so a .deb user gets no row and a
/// translocated macOS app gets the notice line instead of a button that cannot work.
///
/// WHY A MENU AND NOT A COMMAND: app commands registered in `generate_handler!` are NOT
/// ACL-scoped (docs/danger-gate.md), so any install command would be callable as
/// `window.__TAURI__.core.invoke("…")`. A native menu activation is delivered by AppKit/GTK
/// straight to Rust and never crosses the bridge.
pub(crate) fn install_menu(app: &AppHandle) -> tauri::Result<()> {
    if current_target() != InstallTarget::Replaceable {
        return Ok(());
    }
    let item = MenuItem::with_id(app, MENU_ID, "Check for Updates\u{2026}", true, Some("CmdOrCtrl+U"))?;
    match app.menu() {
        // macOS: extend the default app submenu, just under About. Costs no pixels.
        Some(menu) => match menu.items()?.first() {
            Some(MenuItemKind::Submenu(s)) => s.insert(&item, 1)?,
            _ => menu.append(&item)?,
        },
        // Linux has no default menubar; only an AppImage user ever reaches this.
        None => {
            let sub = Submenu::with_items(app, "Tachyon", true, &[&item])?;
            app.set_menu(Menu::with_items(app, &[&sub])?)?;
        }
    }
    app.on_menu_event(|app, ev| {
        if ev.id() == MENU_ID {
            tauri::async_runtime::spawn(run_install(app.clone()));
        }
    });
    Ok(())
}

/// NOT a `#[tauri::command]`. NOT in `generate_handler!`. Reached only from the menu event.
/// Never calls `app.restart()`: a live PTY holds the user's shell, so the user decides when
/// to quit.
async fn run_install(app: AppHandle) {
    let cur = app.package_info().version.to_string();
    // Say something IMMEDIATELY. This used to print nothing until the download finished or
    // failed, so the menu item looked dead for as long as the network took.
    say(&app, "\r\n\x1b[36m[tachyon] checking for updates\u{2026}\x1b[0m\r\n".into());
    let msg = match install(&app).await {
        Ok(Some(v)) => format!(
            "\r\n\x1b[36m[tachyon] Tachyon {v} installed \u{2014} signature checked. Quit and reopen Tachyon to use it. macOS may ask again for file-access permissions.\x1b[0m\r\n"
        ),
        Ok(None) => format!("\r\n\x1b[36m[tachyon] Tachyon {cur} is the latest version\x1b[0m\r\n"),
        Err(e) => format!("\r\n\x1b[31m[tachyon] update failed: {e}\x1b[0m\r\n"),
    };
    say(&app, msg);
}

/// term_write feeds the DISPLAY engine only; it holds no PTY writer.
fn say(app: &AppHandle, msg: String) {
    term_write(app.clone(), app.state::<PtyState>(), msg);
}

/// Ok(None) = already current. The plugin does the GET, the manifest parse, the monotonic
/// version compare and the minisign verification; none of that is overridden here.
async fn install(app: &AppHandle) -> Result<Option<String>, String> {
    let updater = app.updater().map_err(|e| e.to_string())?;
    let Some(update) = updater.check().await.map_err(|e| e.to_string())? else {
        return Ok(None);
    };
    say(app, format!(
        "\x1b[36m[tachyon] downloading Tachyon {} \u{2014} the signature is checked before anything is installed\u{2026}\x1b[0m\r\n",
        update.version
    ));
    // No progress bar: the closures are deliberately empty.
    update
        .download_and_install(|_, _| {}, || {})
        .await
        .map_err(|e| e.to_string())?;
    Ok(Some(update.version.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn exe() -> PathBuf {
        PathBuf::from("/Applications/Tachyon.app/Contents/MacOS/Tachyon")
    }

    /// A path that certainly exists, without touching the environment.
    fn real_file() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml")
    }

    #[test]
    fn macos_in_applications_is_replaceable() {
        assert_eq!(
            install_target("macos", None, false, &exe()),
            InstallTarget::Replaceable
        );
    }

    #[test]
    fn macos_translocated_is_detected() {
        // The literal shape of a Gatekeeper-translocated launch, kept verbatim as
        // documentation of what the guard actually reads.
        let p = PathBuf::from(
            "/private/var/folders/xy/abc/T/AppTranslocation/1E2D-4F5A/d/Tachyon.app/Contents/MacOS/Tachyon",
        );
        assert_eq!(
            install_target("macos", None, false, &p),
            InstallTarget::Translocated
        );
    }

    #[test]
    fn linux_without_appimage_is_not_updatable() {
        assert_eq!(
            install_target("linux", None, true, &exe()),
            InstallTarget::NotAppImage
        );
        // $APPIMAGE set but stale (extracted tree deleted) is the same case.
        assert_eq!(
            install_target("linux", Some(Path::new("/nope/Tachyon.AppImage")), true, &exe()),
            InstallTarget::NotAppImage
        );
    }

    #[test]
    fn linux_read_only_appimage_is_not_updatable() {
        assert_eq!(
            install_target("linux", Some(&real_file()), false, &exe()),
            InstallTarget::NotAppImage
        );
    }

    #[test]
    fn linux_writable_appimage_is_replaceable() {
        assert_eq!(
            install_target("linux", Some(&real_file()), true, &exe()),
            InstallTarget::Replaceable
        );
    }

    #[test]
    fn other_os_is_unsupported() {
        for os in ["windows", "freebsd"] {
            assert_eq!(install_target(os, None, true, &exe()), InstallTarget::Unsupported);
        }
    }

    #[test]
    fn notice_is_silent_when_current() {
        assert_eq!(notice("0.2.6", None, InstallTarget::Replaceable), None);
    }

    #[test]
    fn notice_offers_the_chord_when_replaceable() {
        let s = notice("0.2.6", Some("0.2.7"), InstallTarget::Replaceable).unwrap();
        assert!(s.contains("0.2.7 is available") && s.contains("you have 0.2.6"), "{s}");
        assert!(s.contains(ACC) && s.contains("update in place"), "{s}");
    }

    #[test]
    fn notice_sends_deb_users_to_the_download_page() {
        let s = notice("0.2.6", Some("0.2.7"), InstallTarget::NotAppImage).unwrap();
        assert!(s.contains(RELEASES), "{s}");
        // A row that cannot work must not be advertised.
        assert!(!s.contains(ACC) && !s.contains("in place"), "{s}");
    }

    #[test]
    fn notice_tells_a_translocated_app_to_move_itself() {
        let s = notice("0.2.6", Some("0.2.7"), InstallTarget::Translocated).unwrap();
        assert!(s.contains("/Applications") && s.contains(ACC), "{s}");
    }

    #[test]
    fn notice_is_silent_on_an_unsupported_os() {
        assert_eq!(notice("0.2.6", Some("0.2.7"), InstallTarget::Unsupported), None);
    }

    /// The bundle is ad-hoc signed; Apple verified nothing, so no line may imply it did.
    #[test]
    fn notice_never_claims_apple_verified_anything() {
        for t in [
            InstallTarget::Replaceable,
            InstallTarget::NotAppImage,
            InstallTarget::Translocated,
            InstallTarget::Unsupported,
        ] {
            let s = notice("0.2.6", Some("0.2.7"), t).unwrap_or_default();
            for bad in ["verified by Apple", "Apple", "notarized"] {
                assert!(!s.contains(bad), "{t:?} line says {bad}: {s}");
            }
        }
    }

    #[test]
    fn parse_update_does_not_swallow_a_future_command() {
        assert_eq!(parse_update("/update"), Some(Ok(UpdateCmd::Check)));
        assert_eq!(parse_update("/update install"), Some(Ok(UpdateCmd::Install)));
        assert_eq!(parse_update("/updated"), None);
        assert_eq!(parse_update("/use groq"), None);
        assert_eq!(parse_update("/update bogus"), Some(Err(USAGE.into())));
    }
}
