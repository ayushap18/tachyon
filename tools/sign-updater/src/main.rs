//! Re-signs an updater artifact so its minisign trusted comment records the release version.
//!
//! WHY THIS EXISTS: tauri.conf.json sets `requireSignedVersion`, which makes the installed app
//! refuse any update whose signature does not carry `version:<v>` — that is what stops a
//! tampered manifest replaying an old signed release as a "new" one. tauri-plugin-updater
//! 2.12 enforces the field, but no released Tauri CLI writes it yet (checked through
//! @tauri-apps/cli 2.11.5): its signatures stop at `timestamp:…\tfile:…`. So 0.2.6 shipped
//! able to verify a field nothing could produce, and rejected its first real update.
//! This tool produces it, with the same key, in the same format.
// ponytail: delete this tool and its workflow step once the Tauri CLI records the version
// itself — scripts/release.mjs asserts the field either way, so the swap cannot go unnoticed.
//!
//! usage: sign-updater <artifact> <version> <pubkey-b64>
//!   key and password come from TAURI_SIGNING_PRIVATE_KEY / TAURI_SIGNING_PRIVATE_KEY_PASSWORD,
//!   the same two secrets the Tauri bundler reads. Writes <artifact>.sig, then verifies it
//!   against <pubkey-b64> exactly as the updater will, so a wrong key fails HERE, at release
//!   time, not on a user's machine.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use std::io::Cursor;

type Res<T> = Result<T, String>;

fn b64_text(s: &str, what: &str) -> Res<String> {
    let bytes = STANDARD.decode(s.trim()).map_err(|e| format!("{what}: not base64 ({e})"))?;
    String::from_utf8(bytes).map_err(|_| format!("{what}: not utf-8"))
}

/// The Tauri key file is base64 of the minisign secret-key box; the password unlocks it.
fn secret_key(key_b64: &str, password: &str) -> Res<minisign::SecretKey> {
    minisign::SecretKeyBox::from_string(&b64_text(key_b64, "private key")?)
        .and_then(|b| b.into_secret_key(Some(password.to_string())))
        .map_err(|e| format!("private key: {e}"))
}

/// Same fields the Tauri CLI writes, plus the one `requireSignedVersion` reads.
fn trusted_comment(timestamp: u64, file: &str, version: &str) -> String {
    format!("timestamp:{timestamp}\tfile:{file}\tversion:{version}")
}

/// Base64 of the signature box text — the exact shape latest.json's `signature` holds.
fn sign(sk: &minisign::SecretKey, data: &[u8], comment: &str) -> Res<String> {
    let sig = minisign::sign(None, sk, Cursor::new(data), Some(comment), Some("signature from tauri secret key"))
        .map_err(|e| format!("sign: {e}"))?;
    Ok(STANDARD.encode(sig.to_string()))
}

/// What the installed app will do: minisign-verify against the compiled-in key, then read
/// `version:` out of the trusted comment and compare.
fn verify(pubkey_b64: &str, data: &[u8], sig_b64: &str, version: &str) -> Res<()> {
    let pk = minisign_verify::PublicKey::decode(&b64_text(pubkey_b64, "public key")?)
        .map_err(|e| format!("public key: {e}"))?;
    let sig = minisign_verify::Signature::decode(&b64_text(sig_b64, "signature")?)
        .map_err(|e| format!("signature: {e}"))?;
    pk.verify(data, &sig, true).map_err(|e| format!("signature does not verify against the app's public key: {e}"))?;
    match sig.trusted_comment().split('\t').find_map(|f| f.strip_prefix("version:")) {
        Some(v) if v == version => Ok(()),
        Some(v) => Err(format!("signed version {v} != {version}")),
        None => Err("trusted comment carries no version".into()),
    }
}

fn run() -> Res<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [artifact, version, pubkey] = args.as_slice() else {
        return Err("usage: sign-updater <artifact> <version> <pubkey-b64>".into());
    };
    let env = |k: &str| std::env::var(k).map_err(|_| format!("{k} is not set"));
    let sk = secret_key(&env("TAURI_SIGNING_PRIVATE_KEY")?, &env("TAURI_SIGNING_PRIVATE_KEY_PASSWORD")?)?;
    let data = std::fs::read(artifact).map_err(|e| format!("{artifact}: {e}"))?;
    let name = std::path::Path::new(artifact).file_name().ok_or("artifact has no file name")?.to_string_lossy();
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_err(|e| e.to_string())?.as_secs();
    let sig = sign(&sk, &data, &trusted_comment(now, &name, version))?;
    verify(pubkey, &data, &sig, version)?;
    std::fs::write(format!("{artifact}.sig"), &sig).map_err(|e| format!("{artifact}.sig: {e}"))?;
    println!("signed {name} for {version}");
    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("sign-updater: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A throwaway keypair per test run — the real key never appears in a test.
    fn keys() -> (minisign::SecretKey, String) {
        let kp = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
        let pub_b64 = STANDARD.encode(kp.pk.to_box().unwrap().to_string());
        (kp.sk, pub_b64)
    }

    #[test]
    fn a_signature_carries_the_version_and_verifies_like_the_updater() {
        let (sk, pk) = keys();
        let sig = sign(&sk, b"payload", &trusted_comment(1, "Tachyon.app.tar.gz", "0.2.8")).unwrap();
        verify(&pk, b"payload", &sig, "0.2.8").unwrap();
        let text = b64_text(&sig, "sig").unwrap();
        assert!(text.contains("trusted comment: timestamp:1\tfile:Tachyon.app.tar.gz\tversion:0.2.8"));
    }

    #[test]
    fn tampered_data_a_wrong_version_and_a_foreign_key_all_fail() {
        let (sk, pk) = keys();
        let sig = sign(&sk, b"payload", &trusted_comment(1, "f", "0.2.8")).unwrap();
        assert!(verify(&pk, b"payloaD", &sig, "0.2.8").is_err());
        // the replay this whole tool exists to stop: an old signature offered as a new version
        assert!(verify(&pk, b"payload", &sig, "0.2.9").unwrap_err().contains("0.2.8 != 0.2.9"));
        let (_, other_pk) = keys();
        assert!(verify(&other_pk, b"payload", &sig, "0.2.8").is_err());
    }

    #[test]
    fn a_stock_tauri_signature_without_the_field_is_refused() {
        let (sk, pk) = keys();
        let stock = sign(&sk, b"payload", "timestamp:1\tfile:f").unwrap();
        assert!(verify(&pk, b"payload", &stock, "0.2.8").unwrap_err().contains("no version"));
    }
}
