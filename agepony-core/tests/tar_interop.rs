//! The compact USTAR archive must be readable by the standard `tar` tool, not
//! just by our own extractor. Skips where `tar` is not on PATH.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use agepony_core::archive::tar::{self, Entry};
use std::process::{Command, Stdio};

fn have_tar() -> bool {
    Command::new("tar")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

#[test]
fn gnu_tar_lists_and_extracts_our_archive() {
    if !have_tar() {
        eprintln!("skipping: tar not available");
        return;
    }

    let dir = std::env::temp_dir().join("agepony-tar-interop");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let entries = vec![
        Entry {
            name: "one.txt".to_owned(),
            data: b"first file".to_vec(),
        },
        Entry {
            name: "two.bin".to_owned(),
            data: vec![42_u8; 1000],
        },
    ];
    let archive = tar::create(&entries).unwrap();
    let archive_path = dir.join("bundle.tar");
    std::fs::write(&archive_path, &archive).unwrap();

    // tar tf lists exactly our entries.
    let listed = Command::new("tar")
        .arg("tf")
        .arg(&archive_path)
        .output()
        .unwrap();
    assert!(
        listed.status.success(),
        "tar tf failed: {}",
        String::from_utf8_lossy(&listed.stderr)
    );
    let names = String::from_utf8_lossy(&listed.stdout);
    assert!(
        names.contains("one.txt"),
        "listing missing one.txt: {names}"
    );
    assert!(
        names.contains("two.bin"),
        "listing missing two.bin: {names}"
    );

    // tar xf extracts identical bytes.
    let extract_dir = dir.join("out");
    std::fs::create_dir_all(&extract_dir).unwrap();
    let extracted = Command::new("tar")
        .arg("xf")
        .arg(&archive_path)
        .arg("-C")
        .arg(&extract_dir)
        .status()
        .unwrap();
    assert!(extracted.success(), "tar xf failed");
    assert_eq!(
        std::fs::read(extract_dir.join("one.txt")).unwrap(),
        b"first file"
    );
    assert_eq!(
        std::fs::read(extract_dir.join("two.bin")).unwrap(),
        vec![42_u8; 1000]
    );

    let _ = std::fs::remove_dir_all(&dir);
}
