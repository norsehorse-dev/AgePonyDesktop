#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! Shared cross-platform vectors.
//!
//! Everything here reads `vectors/agepony-vectors.json` at the workspace root,
//! which is the same file the iOS and Android suites are meant to load. Adding
//! a vector there should add a test on all three platforms.

use serde_json::Value;
use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    // CARGO_MANIFEST_DIR is agepony-core/; the vectors live one level up.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("agepony-core has a parent")
        .to_path_buf()
}

fn vectors() -> Value {
    let path = workspace_root().join("vectors/agepony-vectors.json");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    serde_json::from_str(&text).expect("vectors file is valid JSON")
}

fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn hex_len(v: &Value, ptr: &str) -> usize {
    v.pointer(ptr)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("missing {ptr}"))
        .len()
        / 2
}

#[test]
fn pq_constants_match_the_shared_vectors() {
    let v = vectors();
    let pq = &v["mlkem768x25519"];

    assert_eq!(pq["stanza_tag"], agepony_core::pq::STANZA_TAG);
    assert_eq!(
        pq["hpke_info"].as_str().expect("hpke_info"),
        std::str::from_utf8(agepony_core::pq::HPKE_INFO).expect("utf8")
    );
    assert_eq!(pq["recipient_hrp"], agepony_core::pq::RECIPIENT_HRP);
    assert_eq!(pq["identity_hrp"], agepony_core::pq::IDENTITY_HRP);
    assert_eq!(
        pq["sizes"]["public_key"].as_u64().expect("size"),
        agepony_core::pq::PUBLIC_KEY_SIZE as u64
    );
    assert_eq!(
        pq["sizes"]["enc"].as_u64().expect("size"),
        agepony_core::pq::ENC_SIZE as u64
    );
}

#[test]
fn pq_known_answer_vector_is_well_formed() {
    // This runs today. It does not test our crypto -- it tests that the vector
    // we are going to be graded against in Phase 4 is intact and the right
    // shape. If someone mangles the JSON, this fails now rather than in Phase 4.
    let v = vectors();
    assert_eq!(hex_len(&v, "/mlkem768x25519/kat/seed"), 32);
    assert_eq!(hex_len(&v, "/mlkem768x25519/kat/expected_public_key"), 1216);
    assert_eq!(hex_len(&v, "/mlkem768x25519/kat/file_key"), 16);
    assert_eq!(hex_len(&v, "/mlkem768x25519/kat/encap_randomness"), 64);
    assert_eq!(hex_len(&v, "/mlkem768x25519/kat/expected_enc"), 1120);
    assert_eq!(hex_len(&v, "/mlkem768x25519/kat/expected_stanza_body"), 32);
}

fn kat(field: &str) -> Vec<u8> {
    let v = vectors();
    let s = v
        .pointer(&format!("/mlkem768x25519/kat/{field}"))
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("missing kat field {field}"));
    hex::decode(s).expect("kat field is valid hex")
}

#[test]
fn pq_public_key_derives_from_seed() {
    // Mirrors HybridRecipientTests.publicKeyDerivedFromSeedMatchesReference.
    //
    // This is also the FIPS 203 canary. ML-KEM draft (IPD) and final derive
    // DIFFERENT keys from the same seed, so if the `ml-kem` crate were ever
    // built against the draft, this fails immediately and unmistakably rather
    // than producing files the phones cannot open.
    let seed: [u8; 32] = kat("seed").try_into().expect("32-byte seed");
    let key = agepony_core::pq::xwing::PrivateKey::from_seed(&seed);
    assert_eq!(
        key.public_key().as_slice(),
        kat("expected_public_key").as_slice(),
        "hybrid public key does not match the reference"
    );
}

#[test]
fn pq_deterministic_wrap_matches_the_reference_stanza() {
    // Mirrors HybridRecipientTests.deterministicWrapMatchesReferenceVector.
    use agepony_core::pq;

    let public = kat("expected_public_key");
    let pk = pq::xwing::PublicKey::from_bytes(&public).expect("parse public key");

    let (enc, shared) = pk
        .encapsulate_with(&kat("encap_randomness"))
        .expect("deterministic encapsulation");
    assert_eq!(
        enc.as_slice(),
        kat("expected_enc").as_slice(),
        "encapsulation does not match the reference"
    );

    let body = pq::hpke::seal(shared.as_ref(), pq::HPKE_INFO, &kat("file_key")).expect("seal");
    assert_eq!(
        body.as_slice(),
        kat("expected_stanza_body").as_slice(),
        "stanza body does not match the reference"
    );
}

#[test]
fn pq_identity_unwraps_the_reference_stanza() {
    // Mirrors HybridRecipientTests.identityUnwrapsReferenceStanza. Builds the
    // stanza from the reference bytes -- not from our own wrap -- so this
    // proves we can read what the phones write.
    use age::Identity as _;
    use age::secrecy::ExposeSecret as _;
    use base64::Engine as _;

    let seed: [u8; 32] = kat("seed").try_into().expect("32-byte seed");
    let identity = agepony_core::pq::Identity::from_seed(&seed).expect("identity from seed");

    let stanza = age_core::format::Stanza {
        tag: agepony_core::pq::STANZA_TAG.to_owned(),
        args: vec![base64::engine::general_purpose::STANDARD_NO_PAD.encode(kat("expected_enc"))],
        body: kat("expected_stanza_body"),
    };

    let recovered = identity
        .unwrap_stanza(&stanza)
        .expect("the reference stanza is ours")
        .expect("it unwraps");
    assert_eq!(
        recovered.expose_secret().as_slice(),
        kat("file_key").as_slice()
    );
}

#[test]
fn pq_round_trips_a_real_file() {
    let identity = agepony_core::pq::Identity::generate().expect("generate");
    let recipient = identity.to_public().expect("public");
    let parsed = agepony_core::recipient::parse_all([recipient.to_string()]).expect("parse");
    assert!(parsed[0].kind.is_post_quantum());

    let dir = std::env::temp_dir().join("agepony-pq-round-trip");
    std::fs::create_dir_all(&dir).expect("mkdir");
    let plain = dir.join("pq.txt");
    let ct = dir.join("pq.txt.age");
    let back = dir.join("pq.back.txt");
    std::fs::write(&plain, b"hello post-quantum age").expect("write");

    agepony_core::encrypt::encrypt_file(
        &plain,
        &ct,
        agepony_core::encrypt::To::Recipients(&parsed),
        false,
        &mut |_| true,
    )
    .expect("encrypt to a PQ recipient");

    let ids: Vec<Box<dyn age::Identity + Send + Sync>> = vec![Box::new(identity)];
    agepony_core::decrypt::decrypt_file(
        &ct,
        &back,
        agepony_core::decrypt::With::Identities(&ids),
        &mut |_| true,
    )
    .expect("decrypt with the PQ identity");

    assert_eq!(
        std::fs::read(&back).expect("read"),
        b"hello post-quantum age"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_pq_recipient_cannot_share_a_file_with_a_classical_one() {
    // age enforces this via stanza labels; we reject it earlier so the message
    // is legible. Either way it must not be possible -- the weakest recipient
    // sets the security bar.
    let pq = agepony_core::pq::Identity::generate()
        .expect("generate")
        .to_public()
        .expect("public")
        .to_string();
    let classical = age::x25519::Identity::generate().to_public().to_string();

    assert!(matches!(
        agepony_core::recipient::parse_all([pq, classical]),
        Err(agepony_core::CoreError::MixedPostQuantum)
    ));
}

#[test]
fn x25519_cross_impl_fixture_decrypts() {
    let dir = fixtures_dir();
    let id_path = dir.join("x25519_identity.txt");
    let ct_path = dir.join("x25519_hello.age");
    if !id_path.exists() || !ct_path.exists() {
        eprintln!("skipping: fixtures absent -- run generate-fixtures.sh");
        return;
    }

    let expected = vectors()["cross_impl_files"]["plaintext"]
        .as_str()
        .expect("plaintext")
        .to_owned();

    let text = std::fs::read_to_string(&id_path).expect("read identity");
    let ids = agepony_core::identity::parse_identities(&text).expect("parse identity");

    let out = std::env::temp_dir().join("agepony-x25519-fixture.txt");
    agepony_core::decrypt::decrypt_file(
        &ct_path,
        &out,
        agepony_core::decrypt::With::Identities(&ids),
        &mut |_| true,
    )
    .expect("decrypts");

    assert_eq!(
        std::fs::read_to_string(&out).expect("read output"),
        expected
    );
    let _ = std::fs::remove_file(&out);
}

#[test]
fn round_trip_through_our_own_encrypt_and_decrypt() {
    let id = agepony_core::identity::generate_x25519();
    let recipients =
        agepony_core::recipient::parse_all([id.to_public().to_string()]).expect("parse recipient");

    let dir = std::env::temp_dir().join("agepony-round-trip");
    std::fs::create_dir_all(&dir).expect("mkdir");
    let plain = dir.join("plain.bin");
    let ct = dir.join("plain.bin.age");
    let back = dir.join("back.bin");

    // Sizes that historically break streaming AEAD: empty, one chunk exactly,
    // one chunk plus a byte, several chunks.
    for size in [
        0_usize,
        1,
        agepony_core::CHUNK,
        agepony_core::CHUNK + 1,
        agepony_core::CHUNK * 3,
    ] {
        let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        std::fs::write(&plain, &data).expect("write plaintext");

        agepony_core::encrypt::encrypt_file(
            &plain,
            &ct,
            agepony_core::encrypt::To::Recipients(&recipients),
            false,
            &mut |_| true,
        )
        .unwrap_or_else(|e| panic!("encrypt {size} bytes: {e}"));

        let ids: Vec<Box<dyn age::Identity + Send + Sync>> = vec![Box::new(id.clone())];
        agepony_core::decrypt::decrypt_file(
            &ct,
            &back,
            agepony_core::decrypt::With::Identities(&ids),
            &mut |_| true,
        )
        .unwrap_or_else(|e| panic!("decrypt {size} bytes: {e}"));

        assert_eq!(
            std::fs::read(&back).expect("read back"),
            data,
            "size {size}"
        );
    }

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn armored_round_trip() {
    let id = agepony_core::identity::generate_x25519();
    let recipients =
        agepony_core::recipient::parse_all([id.to_public().to_string()]).expect("parse recipient");

    let dir = std::env::temp_dir().join("agepony-armor");
    std::fs::create_dir_all(&dir).expect("mkdir");
    let plain = dir.join("note.txt");
    let ct = dir.join("note.txt.age");
    let back = dir.join("note.back.txt");
    std::fs::write(&plain, b"armored hello").expect("write");

    agepony_core::encrypt::encrypt_file(
        &plain,
        &ct,
        agepony_core::encrypt::To::Recipients(&recipients),
        true,
        &mut |_| true,
    )
    .expect("encrypt armored");

    let armored = std::fs::read_to_string(&ct).expect("read armored");
    assert!(armored.starts_with("-----BEGIN AGE ENCRYPTED FILE-----"));

    let ids: Vec<Box<dyn age::Identity + Send + Sync>> = vec![Box::new(id)];
    agepony_core::decrypt::decrypt_file(
        &ct,
        &back,
        agepony_core::decrypt::With::Identities(&ids),
        &mut |_| true,
    )
    .expect("decrypt armored");
    assert_eq!(std::fs::read(&back).expect("read"), b"armored hello");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_failed_decrypt_leaves_no_output_file() {
    let good = agepony_core::identity::generate_x25519();
    let wrong = agepony_core::identity::generate_x25519();
    let recipients =
        agepony_core::recipient::parse_all([good.to_public().to_string()]).expect("parse");

    let dir = std::env::temp_dir().join("agepony-failure");
    std::fs::create_dir_all(&dir).expect("mkdir");
    let plain = dir.join("secret.txt");
    let ct = dir.join("secret.txt.age");
    let out = dir.join("secret.out");
    std::fs::write(&plain, b"do not leak me").expect("write");

    agepony_core::encrypt::encrypt_file(
        &plain,
        &ct,
        agepony_core::encrypt::To::Recipients(&recipients),
        false,
        &mut |_| true,
    )
    .expect("encrypt");

    let ids: Vec<Box<dyn age::Identity + Send + Sync>> = vec![Box::new(wrong)];
    let err = agepony_core::decrypt::decrypt_file(
        &ct,
        &out,
        agepony_core::decrypt::With::Identities(&ids),
        &mut |_| true,
    );
    assert!(err.is_err(), "the wrong identity must not decrypt");
    assert!(!out.exists(), "no output file may survive a failed decrypt");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_flipped_payload_byte_is_detected_and_leaves_no_output() {
    let id = agepony_core::identity::generate_x25519();
    let recipients =
        agepony_core::recipient::parse_all([id.to_public().to_string()]).expect("parse");

    let dir = std::env::temp_dir().join("agepony-tamper");
    std::fs::create_dir_all(&dir).expect("mkdir");
    let plain = dir.join("t.bin");
    let ct = dir.join("t.bin.age");
    let out = dir.join("t.out");
    std::fs::write(&plain, vec![7_u8; 4096]).expect("write");

    agepony_core::encrypt::encrypt_file(
        &plain,
        &ct,
        agepony_core::encrypt::To::Recipients(&recipients),
        false,
        &mut |_| true,
    )
    .expect("encrypt");

    let mut bytes = std::fs::read(&ct).expect("read ct");
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    std::fs::write(&ct, &bytes).expect("write tampered");

    let ids: Vec<Box<dyn age::Identity + Send + Sync>> = vec![Box::new(id)];
    let err = agepony_core::decrypt::decrypt_file(
        &ct,
        &out,
        agepony_core::decrypt::With::Identities(&ids),
        &mut |_| true,
    );
    assert!(err.is_err(), "a flipped payload byte must fail");
    assert!(!out.exists(), "no plaintext may survive a tampered payload");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn passphrase_round_trip() {
    use age::secrecy::SecretString;

    let dir = std::env::temp_dir().join("agepony-passphrase");
    std::fs::create_dir_all(&dir).expect("mkdir");
    let plain = dir.join("p.txt");
    let ct = dir.join("p.txt.age");
    let back = dir.join("p.back.txt");
    std::fs::write(&plain, b"passphrase hello").expect("write");

    agepony_core::encrypt::encrypt_file(
        &plain,
        &ct,
        agepony_core::encrypt::To::Passphrase(SecretString::from("correct horse battery staple")),
        false,
        &mut |_| true,
    )
    .expect("encrypt");

    agepony_core::decrypt::decrypt_file(
        &ct,
        &back,
        agepony_core::decrypt::With::Passphrase(SecretString::from("correct horse battery staple")),
        &mut |_| true,
    )
    .expect("decrypt");
    assert_eq!(std::fs::read(&back).expect("read"), b"passphrase hello");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn pq_fixture_decrypts() {
    // Self-consistency and regression: the committed PQ fixture must keep
    // opening as the implementation evolves. This does NOT prove interop --
    // the fixture was produced by this crate, because no CLI implements
    // mlkem768x25519. The byte-level proof is the known-answer tests above;
    // the on-device proof is opening this file on the phone.
    let dir = fixtures_dir();
    let id_path = dir.join("pq_identity.txt");
    let ct_path = dir.join("pq_hello.age");
    if !id_path.exists() || !ct_path.exists() {
        eprintln!("skipping: PQ fixture absent -- run the make_pq_fixture example");
        return;
    }

    let text = std::fs::read_to_string(&id_path).expect("read identity");
    let ids = agepony_core::identity::parse_identities(&text).expect("parse PQ identity");

    let out = std::env::temp_dir().join("agepony-pq-fixture.txt");
    agepony_core::decrypt::decrypt_file(
        &ct_path,
        &out,
        agepony_core::decrypt::With::Identities(&ids),
        &mut |_| true,
    )
    .expect("decrypts");

    let expected = vectors()["cross_impl_files"]["plaintext"]
        .as_str()
        .expect("plaintext")
        .to_owned();
    assert_eq!(std::fs::read_to_string(&out).expect("read"), expected);
    let _ = std::fs::remove_file(&out);
}
