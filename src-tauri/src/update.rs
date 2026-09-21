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
//!     install path registers no `#[tauri::command]` at all. This module registers none
//!     either: the periodic check runs in Rust and reaches the webview as an event;
//!   * installing is reached only from a native menu activation, which AppKit/GTK deliver
//!     straight to Rust. `/update install` returns a usage string, never an install.

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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

/// One line, or None when there is nothing worth saying: `newer` is None when this copy is
/// current, and an Unsupported target has nothing to offer. A failed check is NOT None here
/// — `check_line` reports that in words. The line NEVER says "verified by Apple" or anything
/// a user reads that way — tauri.conf.json's signing identity is ad-hoc and Apple verified
/// nothing.
pub(crate) fn notice(current: &str, newer: Option<&str>, target: InstallTarget) -> Option<String> {
    let v = newer?;
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

/// Uses `app.updater()`, never the runtime override — the compiled-in endpoint and public
/// key are the whole security model. `Ok(None)` means the check completed and this copy is
/// current; a transport or manifest failure is `Err`, never folded into `Ok(None)`.
async fn latest(app: &AppHandle) -> Result<Option<String>, String> {
    let updater = app.updater().map_err(|e| e.to_string())?;
    let found = updater.check().await.map_err(|e| e.to_string())?;
    Ok(found.map(|u| version(&u.version)))
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
        Ok(UpdateCmd::Check) => {
            let found = latest(app).await;
            Ok(check_line(
                &app.package_info().version.to_string(),
                found.as_ref().map(Option::as_deref).map_err(String::as_str),
                current_target(),
            ))
        }
        // `/update` is ungated IPC like every slash command, so this arm must stay a string.
        Ok(UpdateCmd::Install) => Err(USAGE.into()),
        Err(e) => Err(e),
    })
}

/// `/update` asked a direct question, so unlike the ambient check it always answers — and
/// only a check that actually completed may answer "latest version".
fn check_line(cur: &str, res: Result<Option<&str>, &str>, target: InstallTarget) -> String {
    match res {
        Ok(Some(v)) => notice(cur, Some(v), target).unwrap_or_else(|| format!(
            "\r\n\x1b[36m[tachyon] Tachyon {v} is available \u{2014} you have {cur}: {RELEASES}\x1b[0m\r\n"
        )),
        Ok(None) => format!("\r\n\x1b[36m[tachyon] Tachyon {cur} is the latest version\x1b[0m\r\n"),
        Err(e) => format!(
            "\r\n\x1b[31m[tachyon] could not reach the update server \u{2014} {e}. Download by hand: {RELEASES}\x1b[0m\r\n"
        ),
    }
}

// ---- the ambient check ----

/// Long enough for the frontend to have mounted and called `pty_spawn`.
const SETTLE: Duration = Duration::from_secs(20);
const INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);
/// `latest.json` is fetched over TLS but is NOT signed, so the notes are attacker-influenceable
/// text. They are sanitised and capped before they cross the bridge.
const NOTES_MAX: usize = 300;

/// Spread the herd: a shared release moment must not become a spike on the endpoint. This
/// only has to be uneven, not unpredictable, so the clock is enough and `rand` is not.
fn jitter() -> Duration {
    let n = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.subsec_nanos()) % 1000;
    INTERVAL / 10 * n / 1000
}

/// One line of release notes, stripped of every control and invisible codepoint by the same
/// `one_line` the approval gate uses, so the text cannot carry an escape sequence into the
/// vt100 engine or a bidi override into what the user reads.
fn notes(body: &str) -> String {
    truncate_chars(&one_line(body), NOTES_MAX)
}

/// No real semver comes near this. The version is the notes' sibling in the same unsigned
/// `latest.json`, and it reaches the same two sinks — the vt100 engine and the status bar —
/// but semver puts no length limit on a pre-release identifier, so a manifest can carry
/// megabytes here. Its grammar already restricts the charset to [0-9A-Za-z-.+], so length is
/// the only thing left to enforce.
const VERSION_MAX: usize = 64;

fn version(v: &str) -> String {
    truncate_chars(v, VERSION_MAX)
}

/// One check after SETTLE, then one every INTERVAL. It only ASKS: the answer becomes an
/// event the status bar renders, and nothing here fetches an artifact or touches the bundle.
/// An event rather than a printed line, because `term_write` is a silent no-op until the
/// frontend has called `pty_spawn`, so a line painted at launch would be lost.
pub(crate) fn watch(app: &AppHandle) {
    // An env var, not a fifth JSON file under config_dir() for one boolean.
    if std::env::var("TACHYON_NO_UPDATE_CHECK").is_ok_and(|v| v == "1") {
        return;
    }
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(SETTLE).await;
        loop {
            if let Ok(up) = app.updater() {
                if let Ok(Some(u)) = up.check().await {
                    let _ = app.emit(
                        "update-available",
                        serde_json::json!({
                            "version": version(&u.version),
                            "notes": notes(u.body.as_deref().unwrap_or_default()),
                        }),
                    );
                }
            }
            tokio::time::sleep(INTERVAL + jitter()).await;
        }
    });
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
            match claim() {
                Some(guard) => {
                    tauri::async_runtime::spawn(run_install(app.clone(), guard));
                }
                None => say(app, "\r\n\x1b[33m[tachyon] an update is already downloading\x1b[0m\r\n".into()),
            }
        }
    });
    Ok(())
}

/// The accelerator is one keystroke and the handler returns as soon as it has spawned, so
/// two presses would each pull the whole bundle and each run the plugin's rename-swap of the
/// .app — interleaved, the second moves the first's freshly installed bundle into a TempDir
/// that is deleted on drop. The second press is REFUSED, not queued.
static INSTALLING: AtomicBool = AtomicBool::new(false);

struct InstallGuard;

impl Drop for InstallGuard {
    fn drop(&mut self) {
        INSTALLING.store(false, Ordering::Release);
    }
}

/// ponytail: an install that hangs forever holds the flag for the process lifetime. The
/// plugin's http client has its own timeouts, and a release-on-timeout is a second failure
/// mode to get wrong.
fn claim() -> Option<InstallGuard> {
    INSTALLING
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .ok()
        .map(|_| InstallGuard)
}

/// NOT a `#[tauri::command]`. NOT in `generate_handler!`. Reached only from the menu event.
/// Never calls `app.restart()`: a live PTY holds the user's shell, so the user decides when
/// to quit. The guard is released here, on every exit path including a panic.
async fn run_install(app: AppHandle, _guard: InstallGuard) {
    let cur = app.package_info().version.to_string();
    // Say something IMMEDIATELY. This used to print nothing until the download finished or
    // failed, so the menu item looked dead for as long as the network took.
    say(&app, "\r\n\x1b[36m[tachyon] checking for updates\u{2026}\x1b[0m\r\n".into());
    let msg = match install(&app).await {
        Ok(Some(v)) => format!(
            "\r\n\x1b[36m[tachyon] Tachyon {v} installed \u{2014} signature checked. Quit and reopen Tachyon to use it. macOS may ask again for file-access permissions.\x1b[0m\r\n"
        ),
        Ok(None) => format!("\r\n\x1b[36m[tachyon] Tachyon {cur} is the latest version\x1b[0m\r\n"),
        Err(e) => format!(
            "\r\n\x1b[31m[tachyon] update failed: {}\x1b[0m\r\n",
            failure_text(&e, current_target())
        ),
    };
    say(&app, msg);
}

/// Pure, and it matches the ENUM rather than the plugin's Display text, so a rewording
/// upstream cannot silently turn a refused signature into a generic failure.
fn failure_text(e: &tauri_plugin_updater::Error, target: InstallTarget) -> String {
    use tauri_plugin_updater::Error as E;
    // Where to get the build by hand depends on how this copy is installed.
    let by_hand = match target {
        InstallTarget::NotAppImage => format!("update through your package manager: {RELEASES}"),
        InstallTarget::Translocated => {
            format!("move Tachyon to /Applications and retry, or download it: {RELEASES}")
        }
        _ => format!("download it by hand: {RELEASES}"),
    };
    match e {
        E::MissingSignedVersion | E::SignedVersionMismatch { .. } | E::Minisign(_) => {
            format!("the download's signature was refused \u{2014} nothing was installed. {by_hand}")
        }
        E::Io(io) if io.kind() == std::io::ErrorKind::StorageFull => {
            "not enough disk space \u{2014} nothing was installed".into()
        }
        E::Reqwest(_) | E::Network(_) => {
            "could not reach the download \u{2014} check your connection".into()
        }
        E::TargetNotFound(_) | E::TargetsNotFound(_) => format!("no build for this platform. {by_hand}"),
        E::AuthenticationFailed => "the admin prompt was cancelled \u{2014} nothing was installed".into(),
        E::DebInstallFailed | E::PackageInstallFailed => format!("the package install failed. {by_hand}"),
        // The enum is #[non_exhaustive] and most of its variants have no advice to add.
        _ => e.to_string(),
    }
}

/// term_write feeds the DISPLAY engine only; it holds no PTY writer.
fn say(app: &AppHandle, msg: String) {
    term_write(app.clone(), app.state::<PtyState>(), msg);
}

/// Ok(None) = already current. The plugin does the GET, the manifest parse, the monotonic
/// version compare and the minisign verification; none of that is overridden here.
async fn install(app: &AppHandle) -> Result<Option<String>, tauri_plugin_updater::Error> {
    let Some(update) = app.updater()?.check().await? else {
        return Ok(None);
    };
    say(app, format!(
        "\x1b[36m[tachyon] downloading Tachyon {} \u{2014} the signature is checked before anything is installed\u{2026}\x1b[0m\r\n",
        version(&update.version)
    ));
    let (mut done, mut last) = (0usize, None);
    update
        .download_and_install(
            |chunk, total| {
                done += chunk;
                if let Some(p) = pct(done, total, &mut last) {
                    // A leading \r with no newline repaints the same line in place.
                    say(app, format!("\r\x1b[36m[tachyon] downloading \u{2014} {p}%\x1b[0m"));
                }
            },
            || {},
        )
        .await?;
    Ok(Some(version(&update.version)))
}

/// Some only when the whole-percent value CHANGED, and only when the total is known.
/// Without the throttle every network chunk becomes a `term_write` plus a `grid-damage`
/// emit, which is the webview flood the scroll work exists to stop.
fn pct(done: usize, total: Option<u64>, last: &mut Option<u8>) -> Option<u8> {
    let total = total.filter(|t| *t > 0)?;
    let p = (done as u64 * 100 / total).min(100) as u8;
    (*last != Some(p)).then(|| {
        *last = Some(p);
        p
    })
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

    /// Offline, behind a captive portal or against a corrupt manifest, `/update` used to
    /// answer "is the latest version" — an assertion it had not earned.
    #[test]
    fn check_line_never_claims_latest_on_error() {
        let failed = check_line("0.2.8", Err("dns error"), InstallTarget::Replaceable);
        assert!(failed.contains("could not reach") && failed.contains("dns error"), "{failed}");
        assert!(!failed.contains("latest version"), "{failed}");
        assert!(failed.contains(RELEASES), "{failed}");

        let current = check_line("0.2.8", Ok(None), InstallTarget::Replaceable);
        assert!(current.contains("0.2.8 is the latest version"), "{current}");

        let newer = check_line("0.2.8", Ok(Some("0.2.9")), InstallTarget::Replaceable);
        assert!(newer.contains("0.2.9 is available") && newer.contains(ACC), "{newer}");
        // Nothing here can update in place, so the answer is the download page, not silence.
        let unsupported = check_line("0.2.8", Ok(Some("0.2.9")), InstallTarget::Unsupported);
        assert!(unsupported.contains("0.2.9 is available") && unsupported.contains(RELEASES), "{unsupported}");
    }

    #[test]
    fn install_claim_is_single_flight() {
        let first = claim().expect("nothing else holds it");
        assert!(claim().is_none(), "a second \u{2318}U must be refused, not queued");
        drop(first);
        assert!(claim().is_some(), "the flag must clear when the install returns");
    }

    #[test]
    fn pct_only_fires_on_a_whole_percent_change() {
        let mut last = None;
        // A server that sends no content-length gives no percentage rather than a wrong one.
        assert_eq!(pct(0, None, &mut last), None);
        assert_eq!(pct(1, Some(100), &mut last), Some(1));
        assert_eq!(pct(1, Some(100), &mut last), None);
        // Sub-percent progress paints nothing; crossing the boundary paints once.
        assert_eq!(pct(19, Some(1000), &mut last), None);
        assert_eq!(pct(20, Some(1000), &mut last), Some(2));
        // A total that lies short must not produce 3200%.
        assert_eq!(pct(32, Some(1), &mut last), Some(100));
    }

    #[test]
    fn failure_text_names_the_signature_refusal() {
        use tauri_plugin_updater::Error as E;
        let refused = failure_text(&E::MissingSignedVersion, InstallTarget::Replaceable);
        assert!(refused.contains("signature was refused"), "{refused}");
        assert!(refused.contains("nothing was installed") && refused.contains(RELEASES), "{refused}");
        // The typed arms must not leak the plugin's raw Debug/Display text.
        assert!(!refused.contains("requireSignedVersion"), "{refused}");

        let mismatch = E::SignedVersionMismatch {
            signed: "0.2.6".into(),
            announced: "0.2.9".into(),
        };
        assert_eq!(failure_text(&mismatch, InstallTarget::Replaceable), refused);

        let offline = failure_text(&E::Network("connect refused".into()), InstallTarget::Replaceable);
        assert!(offline.contains("check your connection"), "{offline}");

        // The tail is what the user can actually do, so it follows the install target.
        let deb = failure_text(&E::DebInstallFailed, InstallTarget::NotAppImage);
        assert!(deb.contains("package manager"), "{deb}");
        assert!(failure_text(&E::AuthenticationFailed, InstallTarget::Translocated).contains("cancelled"));
        // Unmatched variants still say something rather than nothing.
        assert!(!failure_text(&E::UnsupportedArch, InstallTarget::Replaceable).is_empty());
    }

    #[test]
    fn notes_are_sanitised_before_they_cross_ipc() {
        let raw = format!(
            "\u{1b}]0;pwn\u{7}line1\r\nline2\u{202e}evil\u{2028}sep\u{2029}para{}",
            "filler ".repeat(600)
        );
        let out = notes(&raw);
        assert!(!out.chars().any(|c| c.is_control() || is_invisible(c)), "{out}");
        assert!(!out.contains('\n') && !out.contains('\r'), "{out}");
        // Zl/Zp are neither, and CSS breaks the status bar's single line on both.
        assert!(!out.contains('\u{2028}') && !out.contains('\u{2029}'), "{out}");
        assert!(out.chars().count() <= NOTES_MAX, "{} chars", out.chars().count());
        assert!(out.contains("line1; line2"), "{out}");
    }

    /// The version is the notes' sibling in the same unsigned document and lands in the same
    /// two sinks, but semver accepts a pre-release identifier of any length.
    #[test]
    fn a_long_version_is_capped_before_it_crosses_ipc() {
        // A valid semver: the plugin's `parse_version` accepts a pre-release of any length.
        let raw = format!("9.9.9-{}", "a".repeat(100_000));
        assert!(version(&raw).chars().count() <= VERSION_MAX);
        let line = check_line("0.2.9", Ok(Some(&version(&raw))), InstallTarget::Replaceable);
        assert!(line.chars().count() < 400, "{} chars reach the vt100 engine", line.chars().count());

        // and no manifest version reaches a sink without going through it
        let live = include_str!("update.rs").split("#[cfg(test)]").next().unwrap();
        for needle in [concat!("u.ver", "sion"), concat!("update.ver", "sion")] {
            let total = live.matches(needle).count();
            let capped = live.matches(&format!("version(&{needle})")).count();
            assert_eq!(capped, total, "{} uncapped {needle} in update.rs", total - capped);
        }
    }

    /// The periodic task must be provably incapable of fetching an artifact.
    #[test]
    fn the_check_path_never_downloads() {
        let src = include_str!("update.rs");
        let start = src.find("pub(crate) fn watch").unwrap();
        let body = &src[start..start + src[start..].find("\n}\n").unwrap()];
        for bad in [concat!("down", "load"), concat!("ins", "tall")] {
            assert!(!body.contains(bad), "the check path names {bad}:\n{body}");
        }
        assert!(body.contains("check()"), "the slice missed the body of watch");
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
