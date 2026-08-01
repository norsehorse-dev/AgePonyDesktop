#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! The Phase 3 gate, as a test.
//!
//! "The app is usable without touching the filesystem manually" means: generate
//! an identity, put its recipient in the book, encrypt to it by name, and
//! decrypt with the active identity — without the caller ever constructing a
//! key path. Everything below goes through the store and the book.

use age::secrecy::SecretString;
use agepony_core::book::Book;
use agepony_core::store::{Kind, Store};
use std::path::PathBuf;

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join("agepony-workflow").join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    dir
}

fn round_trip(config: &std::path::Path, kind: Kind, passphrase: Option<&SecretString>) {
    let mut store = Store::open(config).expect("open store");
    let mut book = Book::default();

    // 1. Generate an identity through the store.
    let entry = store
        .generate("Laptop", kind, passphrase)
        .expect("generate");
    assert!(store.active_id() == Some(entry.id.as_str()));

    // 2. Put its public recipient in the book, by name.
    book.add("My laptop", &entry.recipient, None)
        .expect("add to book");

    // 3. Encrypt to it, looked up by name rather than by pasting a key.
    let picked = book
        .search("laptop")
        .into_iter()
        .map(|e| e.recipient.clone())
        .collect::<Vec<_>>();
    assert_eq!(picked.len(), 1);
    let recipients = agepony_core::recipient::parse_all(&picked).expect("parse");
    assert_eq!(recipients[0].kind.is_post_quantum(), kind.is_post_quantum());

    let plain = config.join("memo.txt");
    let ct = config.join("memo.txt.age");
    let back = config.join("memo.back.txt");
    std::fs::write(&plain, b"the whole point of the app").expect("write");

    agepony_core::encrypt::encrypt_file(
        &plain,
        &ct,
        agepony_core::encrypt::To::Recipients(&recipients),
        false,
        &mut |_| true,
    )
    .expect("encrypt");

    // 4. Decrypt with the active identity, loaded by the store.
    let active = store.active().expect("an active identity").clone();
    let identities = store.load(&active.id, passphrase).expect("load active");

    agepony_core::decrypt::decrypt_file(
        &ct,
        &back,
        agepony_core::decrypt::With::Identities(&identities),
        &mut |_| true,
    )
    .expect("decrypt");

    assert_eq!(
        std::fs::read(&back).expect("read"),
        b"the whole point of the app"
    );
}

#[test]
fn classic_identity_end_to_end() {
    round_trip(&scratch("classic"), Kind::X25519, None);
}

#[test]
fn post_quantum_identity_end_to_end() {
    round_trip(&scratch("pq"), Kind::PostQuantum, None);
}

#[test]
fn passphrase_protected_identity_end_to_end() {
    let pass = SecretString::from("a passphrase the user will remember");
    round_trip(&scratch("protected"), Kind::X25519, Some(&pass));
}

#[test]
fn passphrase_protected_post_quantum_identity_end_to_end() {
    let pass = SecretString::from("another passphrase");
    round_trip(&scratch("protected-pq"), Kind::PostQuantum, Some(&pass));
}

#[test]
fn the_store_survives_a_restart() {
    let config = scratch("restart");
    let pass = SecretString::from("persisted");

    let (id, recipient) = {
        let mut store = Store::open(&config).expect("open");
        store.generate("Classic", Kind::X25519, None).expect("one");
        let pq = store
            .generate("Quantum", Kind::PostQuantum, Some(&pass))
            .expect("two");
        store.set_active(&pq.id).expect("set active");
        (pq.id, pq.recipient)
    };

    // Reopen from scratch, as a fresh launch of the app would.
    let store = Store::open(&config).expect("reopen");
    assert_eq!(store.entries().len(), 2);
    let active = store.active().expect("active survived");
    assert_eq!(active.id, id);
    assert_eq!(active.recipient, recipient);
    assert!(active.encrypted);
    assert!(active.kind.is_post_quantum());
    assert_eq!(store.load(&id, Some(&pass)).expect("load").len(), 1);
}

#[test]
fn an_exported_identity_can_be_imported_into_a_second_machine() {
    // This is the shape the Phase 5 porting flow needs: an identity file moves
    // between two stores and still decrypts what it could before.
    let laptop = scratch("laptop");
    let desktop = scratch("desktop");

    let mut a = Store::open(&laptop).expect("open a");
    let entry = a
        .generate("Portable", Kind::PostQuantum, None)
        .expect("generate");

    let exported = laptop.join("portable.txt");
    a.export(&entry.id, &exported).expect("export");

    let mut b = Store::open(&desktop).expect("open b");
    let imported = b
        .import("Ported", &exported, None, None)
        .expect("import into the second store");
    assert_eq!(imported.recipient, entry.recipient);

    // A file encrypted on the first machine opens on the second.
    let recipients = agepony_core::recipient::parse_all([entry.recipient.as_str()]).expect("parse");
    let plain = laptop.join("secret.txt");
    let ct = laptop.join("secret.txt.age");
    let back = desktop.join("secret.txt");
    std::fs::write(&plain, b"carried across").expect("write");

    agepony_core::encrypt::encrypt_file(
        &plain,
        &ct,
        agepony_core::encrypt::To::Recipients(&recipients),
        false,
        &mut |_| true,
    )
    .expect("encrypt on the laptop");

    let identities = b.load(&imported.id, None).expect("load on the desktop");
    agepony_core::decrypt::decrypt_file(
        &ct,
        &back,
        agepony_core::decrypt::With::Identities(&identities),
        &mut |_| true,
    )
    .expect("decrypt on the desktop");

    assert_eq!(std::fs::read(&back).expect("read"), b"carried across");
}

#[test]
fn nothing_secret_reaches_the_index_or_the_book() {
    // The one invariant that must never quietly break: the two JSON files the
    // app writes are safe to sync, back up or paste into a bug report.
    let config = scratch("no-secrets");
    let mut store = Store::open(&config).expect("open");
    let a = store.generate("Classic", Kind::X25519, None).expect("a");
    let b = store
        .generate("Quantum", Kind::PostQuantum, None)
        .expect("b");

    let mut book = Book::default();
    book.add("A", &a.recipient, None).expect("add a");
    book.add("B", &b.recipient, None).expect("add b");
    let book_path = config.join("recipients.json");
    book.save(&book_path).expect("save book");

    for path in [config.join("identities.json"), book_path] {
        let text = std::fs::read_to_string(&path).expect("read");
        assert!(
            !text.contains("AGE-SECRET-KEY-"),
            "{} leaked key material",
            path.display()
        );
    }
}

#[test]
fn an_identity_ported_from_a_phone_can_decrypt_what_that_phone_could() {
    // The Phase 5 porting flow, end to end. "The phone" here is a second store;
    // what matters is that only the desktop's private key opens the transfer,
    // and that the ported identity works afterwards.
    let desktop_dir = scratch("port-desktop");
    let phone_dir = scratch("port-phone");

    let mut desktop = Store::open(&desktop_dir).expect("open desktop");
    let mut phone = Store::open(&phone_dir).expect("open phone");

    // The desktop shows this recipient; the phone scans it.
    let laptop = desktop
        .generate("Laptop", Kind::PostQuantum, None)
        .expect("desktop identity");

    // Someone had already encrypted a file to the phone before the transfer.
    let phone_identity = phone
        .generate("Phone key", Kind::PostQuantum, None)
        .expect("phone identity");
    let recipients =
        agepony_core::recipient::parse_all([phone_identity.recipient.as_str()]).expect("parse");
    let plain = phone_dir.join("old.txt");
    let ct = phone_dir.join("old.txt.age");
    std::fs::write(&plain, b"encrypted to the phone months ago").expect("write");
    agepony_core::encrypt::encrypt_file(
        &plain,
        &ct,
        agepony_core::encrypt::To::Recipients(&recipients),
        false,
        &mut |_| true,
    )
    .expect("encrypt to the phone");

    // The phone encrypts its identity to the desktop recipient.
    let phone_secret = std::fs::read_to_string(phone.path_for(&phone_identity))
        .expect("read")
        .lines()
        .find(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .expect("secret line")
        .to_owned();
    let payload = agepony_core::porting::payload("Phone key", &phone_secret);
    let payload_path = phone_dir.join("payload.txt");
    let transfer = phone_dir.join("transfer.age");
    std::fs::write(&payload_path, payload.as_bytes()).expect("write payload");
    let to_desktop =
        agepony_core::recipient::parse_all([laptop.recipient.as_str()]).expect("parse desktop");
    agepony_core::encrypt::encrypt_file(
        &payload_path,
        &transfer,
        agepony_core::encrypt::To::Recipients(&to_desktop),
        false,
        &mut |_| true,
    )
    .expect("phone encrypts its identity");

    // The desktop opens it and installs it.
    let laptop_keys = desktop.load(&laptop.id, None).expect("load laptop");
    let ported = agepony_core::porting::open(&transfer, &laptop_keys).expect("open transfer");
    assert_eq!(ported.suggested_label.as_deref(), Some("Phone key"));
    assert!(desktop.find_by_recipient(&ported.recipient).is_none());

    let installed = desktop
        .install_ported(&ported, "Phone key", None)
        .expect("install");
    assert_eq!(installed.recipient, phone_identity.recipient);
    assert!(
        desktop
            .find_by_recipient(&phone_identity.recipient)
            .is_some()
    );

    // And the ported identity opens the file that was encrypted to the phone.
    let back = desktop_dir.join("old.txt");
    let keys = desktop.load(&installed.id, None).expect("load ported");
    agepony_core::decrypt::decrypt_file(
        &ct,
        &back,
        agepony_core::decrypt::With::Identities(&keys),
        &mut |_| true,
    )
    .expect("the ported identity decrypts the phone's old file");
    assert_eq!(
        std::fs::read(&back).expect("read"),
        b"encrypted to the phone months ago"
    );
}
