//! End-to-end multi-file bundling: several files → one compact tar → encrypted
//! to a `.tar.age` → decrypted → extracted → identical bytes back.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use agepony_core::archive::tar::{self, Entry};
use agepony_core::decrypt::{With, decrypt_file};
use agepony_core::encrypt::{To, encrypt_bytes_to_file};
use agepony_core::recipient;

#[test]
fn a_bundle_of_files_survives_encrypt_decrypt_extract() {
    let id = age::x25519::Identity::generate();
    let parsed = recipient::parse(&id.to_public().to_string()).unwrap();
    let ids: Vec<Box<dyn age::Identity + Send + Sync>> = vec![Box::new(id)];

    let dir = std::env::temp_dir().join("agepony-bundle-roundtrip");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let entries = vec![
        Entry {
            name: "notes.txt".to_owned(),
            data: b"remember the horseshoes".to_vec(),
        },
        Entry {
            name: "photo.bin".to_owned(),
            data: vec![9_u8; 3000],
        },
    ];
    let tarball = tar::create(&entries).unwrap();

    // Encrypt the in-memory tar straight to a .tar.age (no plaintext temp file).
    let ct = dir.join("bundle.tar.age");
    encrypt_bytes_to_file(
        &tarball,
        &ct,
        To::Recipients(std::slice::from_ref(&parsed)),
        false,
        &mut |_| true,
    )
    .unwrap();

    // Decrypt back to the tar, then extract.
    let out_tar = dir.join("bundle.tar");
    decrypt_file(&ct, &out_tar, With::Identities(&ids), &mut |_| true).unwrap();
    let recovered = tar::extract(&std::fs::read(&out_tar).unwrap()).unwrap();

    assert_eq!(recovered, entries, "the bundle round-trips exactly");

    let _ = std::fs::remove_dir_all(&dir);
}
