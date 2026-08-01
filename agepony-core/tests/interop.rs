#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! Round trips against a reference implementation, if one is on PATH.
//!
//! Skips cleanly when absent, so CI on a bare runner still passes. Prefers
//! `rage`; falls back to Go `age`.

use std::path::PathBuf;
use std::process::Command;

fn reference_binary() -> Option<(&'static str, &'static str)> {
    for (enc, keygen) in [("rage", "rage-keygen"), ("age", "age-keygen")] {
        if Command::new(enc).arg("--version").output().is_ok() {
            return Some((enc, keygen));
        }
    }
    None
}

fn scratch(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join("agepony-interop");
    let _ = std::fs::create_dir_all(&d);
    let p = d.join(name);
    // `age-keygen -o` and friends refuse to overwrite, so a leftover file from
    // a previous run would fail the test for the wrong reason.
    let _ = std::fs::remove_file(&p);
    p
}

#[test]
fn our_ciphertext_opens_under_the_reference_cli() {
    let Some((cli, _)) = reference_binary() else {
        eprintln!("skipping: neither rage nor age found on PATH");
        return;
    };

    let id = agepony_core::identity::generate_x25519();
    let recipients =
        agepony_core::recipient::parse_all([id.to_public().to_string()]).expect("parse");

    let id_file = scratch("ours.key");
    let plain = scratch("ours.txt");
    let ct = scratch("ours.txt.age");
    let out = scratch("ours.out");

    {
        use age::secrecy::ExposeSecret as _;
        agepony_core::identity::save_identity_file(&id_file, id.to_string().expose_secret())
            .expect("write identity");
    }
    std::fs::write(&plain, b"round trip from rust").expect("write plaintext");

    agepony_core::encrypt::encrypt_file(
        &plain,
        &ct,
        agepony_core::encrypt::To::Recipients(&recipients),
        false,
        &mut |_| true,
    )
    .expect("encrypt");

    let status = Command::new(cli)
        .args(["--decrypt", "-i"])
        .arg(&id_file)
        .arg("-o")
        .arg(&out)
        .arg(&ct)
        .status()
        .expect("run reference cli");

    assert!(status.success(), "{cli} failed to decrypt our output");
    assert_eq!(
        std::fs::read(&out).expect("read reference output"),
        b"round trip from rust"
    );
}

#[test]
fn reference_ciphertext_opens_under_our_core() {
    let Some((cli, keygen)) = reference_binary() else {
        eprintln!("skipping: neither rage nor age found on PATH");
        return;
    };

    let id_file = scratch("theirs.key");
    let plain = scratch("theirs.txt");
    let ct = scratch("theirs.txt.age");
    let out = scratch("theirs.out");

    let keygen_out = Command::new(keygen)
        .arg("-o")
        .arg(&id_file)
        .output()
        .expect("run keygen");
    assert!(keygen_out.status.success(), "{keygen} failed");

    let text = std::fs::read_to_string(&id_file).expect("read identity");
    let public = text
        .lines()
        .find_map(|l| l.strip_prefix("# public key: "))
        .expect("keygen wrote a public key comment")
        .trim()
        .to_owned();

    std::fs::write(&plain, b"round trip from the reference").expect("write plaintext");
    let status = Command::new(cli)
        .args(["-r", &public, "-o"])
        .arg(&ct)
        .arg(&plain)
        .status()
        .expect("run reference cli");
    assert!(status.success(), "{cli} failed to encrypt");

    let ids = agepony_core::identity::parse_identities(&text).expect("parse identity");
    agepony_core::decrypt::decrypt_file(
        &ct,
        &out,
        agepony_core::decrypt::With::Identities(&ids),
        &mut |_| true,
    )
    .expect("our core decrypts the reference output");

    assert_eq!(
        std::fs::read(&out).expect("read"),
        b"round trip from the reference"
    );
}
