//! End-to-end interop with `ssh-keygen -Y verify`: a signature this crate
//! produces, checked against a trusted-signers file this crate serializes, must
//! be accepted by OpenSSH's own verifier. Skips cleanly where `ssh-keygen` is
//! not on PATH (CI installs it; a dev box may not).
//!
//! The reverse direction — verifying an `ssh-keygen`-made signature — is covered
//! by the unit tests in `src/signing/mod.rs` against committed `.sig` fixtures.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use agepony_core::signing::{self, allowed_signers};
use std::io::Write;
use std::process::{Command, Stdio};

const MSG: &[u8] = include_bytes!("fixtures/sshsig_message.txt");
const ED_KEY: &str = include_str!("fixtures/sshsig_ed25519_key");
const ED_PUB: &str = include_str!("fixtures/sshsig_ed25519_key.pub");
const RSA_KEY: &str = include_str!("fixtures/sshsig_rsa_key");
const RSA_PUB: &str = include_str!("fixtures/sshsig_rsa_key.pub");

fn have_ssh_keygen() -> bool {
    // Look for the binary on PATH rather than running it. Running `ssh-keygen`
    // with no arguments prints usage and exits on Linux, but on macOS it drops
    // into an interactive prompt and blocks on stdin — which would hang the
    // test. A PATH lookup has neither the hang nor any side effect.
    std::env::var_os("PATH").is_some_and(|paths| {
        std::env::split_paths(&paths).any(|dir| {
            dir.join("ssh-keygen").is_file() || dir.join("ssh-keygen.exe").is_file()
        })
    })
}

/// `ssh-keygen -Y verify` accepts our signature against an allowed_signers file
/// we built with `signing::allowed_signers`.
fn interop_roundtrip(key: &str, pub_line: &str, principal: &str) {
    if !have_ssh_keygen() {
        eprintln!("skipping: ssh-keygen not available");
        return;
    }

    let dir = std::env::temp_dir().join(format!("agepony-sshsig-interop-{principal}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    // Our signature.
    let armored = signing::sign_detached(key, MSG, signing::NAMESPACE).unwrap();
    let sig_path = dir.join("msg.sig");
    std::fs::write(&sig_path, &armored).unwrap();

    // An allowed_signers file we serialize from the public-key line.
    let signer = allowed_signers::make_signer(&[principal.to_owned()], pub_line, false)
        .expect("make signer");
    let allowed_path = dir.join("allowed_signers");
    std::fs::write(&allowed_path, allowed_signers::serialize(&[signer])).unwrap();

    let msg_path = dir.join("msg.txt");
    std::fs::write(&msg_path, MSG).unwrap();

    let mut child = Command::new("ssh-keygen")
        .args([
            "-Y",
            "verify",
            "-f",
            allowed_path.to_str().unwrap(),
            "-I",
            principal,
            "-n",
            signing::NAMESPACE,
            "-s",
            sig_path.to_str().unwrap(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(MSG).unwrap();
    let out = child.wait_with_output().unwrap();

    assert!(
        out.status.success(),
        "ssh-keygen rejected our signature ({principal}): {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn ssh_keygen_accepts_our_ed25519_signature_and_allowed_signers() {
    interop_roundtrip(ED_KEY, ED_PUB, "kevin@agepony");
}

#[test]
fn ssh_keygen_accepts_our_rsa_signature_and_allowed_signers() {
    interop_roundtrip(RSA_KEY, RSA_PUB, "kevin-rsa@agepony");
}
