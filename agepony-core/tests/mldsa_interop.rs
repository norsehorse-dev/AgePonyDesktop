//! Interop for the native `mldsa44-ed25519` composite signature (issue #6).
//!
//! `fixtures/mldsa44_ed25519.sig` is real OpenSSH 10.4 `ssh-keygen -Y sign`
//! output over [`MSG`] under the `agepony` namespace. Verifying it proves the
//! reverse direction (ssh-keygen -> AgePony). A generate/sign/verify round-trip
//! proves the forward one. The `ssh-keygen`-verifies-our-output direction needs
//! OpenSSH >= 10.4, which no CI image has yet, so it is checked out of band.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use agepony_core::signing::{mldsa, verify_detached_any};

const SIG: &str = include_str!("fixtures/mldsa44_ed25519.sig");
const MSG: &[u8] = b"agepony interop fixture v1";

#[test]
fn verifies_ssh_keygen_mldsa44_ed25519_signature() {
    let v = verify_detached_any(SIG.as_bytes(), MSG, &["agepony"]).unwrap();
    assert!(v.valid, "expected valid, reason: {:?}", v.reason);
    assert_eq!(v.key_type, mldsa::ALG_NAME);
}

#[test]
fn tampered_message_is_rejected() {
    let v = verify_detached_any(SIG.as_bytes(), b"not the message", &["agepony"]).unwrap();
    assert!(!v.valid);
}

#[test]
fn wrong_namespace_is_rejected() {
    let v = verify_detached_any(SIG.as_bytes(), MSG, &["not-agepony"]).unwrap();
    assert!(!v.valid);
}

#[test]
fn generate_sign_verify_round_trip() {
    let g = mldsa::generate().unwrap();
    assert!(g.public_line.starts_with(mldsa::ALG_NAME));
    assert!(g.fingerprint.starts_with("SHA256:"));
    let sig = mldsa::sign(&g.secret, b"round trip", "agepony").unwrap();
    let v = verify_detached_any(sig.as_bytes(), b"round trip", &["agepony"]).unwrap();
    assert!(v.valid, "round-trip should verify, reason: {:?}", v.reason);
}

#[test]
fn round_trip_signature_is_signer_bound() {
    // A signature from one key must not verify as another key's.
    let a = mldsa::generate().unwrap();
    let b = mldsa::generate().unwrap();
    let sig_a = mldsa::sign(&a.secret, b"m", "agepony").unwrap();
    let sig_b = mldsa::sign(&b.secret, b"m", "agepony").unwrap();
    let va = verify_detached_any(sig_a.as_bytes(), b"m", &["agepony"]).unwrap();
    let vb = verify_detached_any(sig_b.as_bytes(), b"m", &["agepony"]).unwrap();
    assert!(va.valid && vb.valid);
    assert_ne!(va.signer_wire, vb.signer_wire);
}

#[test]
fn imported_mldsa_pubkey_matches_its_signature() {
    // Regression for #6: an external mldsa44-ed25519 public key must import as a
    // trusted signer, and the key embedded in a signature must resolve to it.
    use agepony_core::signing::signers::{SignerSource, Signers};
    const PUB: &str = include_str!("fixtures/mldsa44_ed25519.pub");

    let mut signers = Signers::default();
    let s = signers
        .add_from_public_line("sectec@example.com", PUB, SignerSource::PasteKey)
        .expect("an mldsa44-ed25519 public key should import as a trusted signer");
    assert_eq!(s.key_type, mldsa::ALG_NAME);
    assert!(
        s.fingerprint().is_some(),
        "an imported mldsa signer should show a fingerprint"
    );

    let v = verify_detached_any(SIG.as_bytes(), MSG, &["agepony"]).unwrap();
    assert!(v.valid, "reason: {:?}", v.reason);
    let matched = signers
        .matching(&v.signer_wire)
        .expect("the signature's key must resolve to the imported signer");
    assert_eq!(matched.name, "sectec@example.com");
}
