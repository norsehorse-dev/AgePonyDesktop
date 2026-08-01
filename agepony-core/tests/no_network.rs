#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! The binary must make zero outbound connections. The cheapest way to keep
//! that true is to assert no networking crate is in the dependency tree at all,
//! so a transitive dependency cannot quietly add one.
//!
//! Skips cleanly if `cargo` is not on PATH.

use std::process::Command;

/// Crates that speak to a network, or pull in something that does.
const FORBIDDEN: &[&str] = &[
    "reqwest",
    "hyper",
    "ureq",
    "curl",
    "isahc",
    "surf",
    "attohttpc",
    "tonic",
    "native-tls",
    "rustls",
    "openssl",
    "tokio-tungstenite",
    "tungstenite",
    "quinn",
    "trust-dns-resolver",
    "hickory-resolver",
];

fn tree(package: &str) -> Option<String> {
    let out = Command::new(env!("CARGO"))
        .args([
            "tree",
            "-p",
            package,
            "--prefix",
            "none",
            "--no-dedupe",
            "-e",
            "normal",
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8(out.stdout).ok()
}

fn assert_clean(package: &str) {
    let Some(text) = tree(package) else {
        eprintln!("skipping {package}: could not run `cargo tree`");
        return;
    };

    let names: Vec<&str> = text
        .lines()
        .filter_map(|l| l.split_whitespace().next())
        .collect();

    let found: Vec<&str> = FORBIDDEN
        .iter()
        .copied()
        .filter(|bad| names.iter().any(|n| n == bad))
        .collect();

    assert!(
        found.is_empty(),
        "{package} pulls in networking crates: {found:?}. \
         AgePony makes no outbound connections; find which dependency added these."
    );
}

#[test]
fn core_has_no_networking_crates() {
    assert_clean("agepony-core");
}

#[test]
fn desktop_has_no_networking_crates() {
    assert_clean("agepony-desktop");
}
