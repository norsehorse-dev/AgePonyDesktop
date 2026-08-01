//! Stamp the build with the toolchain that produced it.
//!
//! BurnPony shipped a macOS DMG bundling a different runtime from the one its
//! CI artifacts carried, from the same commit — one source, one version string,
//! two runtimes, and the platform smoke-tested by hand was the one no CI job
//! had exercised. It was found by reading the first line of `selftest` output
//! on a build already declared good.
//!
//! `rust-toolchain.toml` makes the equivalent unconstructible here, because it
//! applies to local builds and CI alike. This makes it *checkable*: the binary
//! reports the compiler that built it, so CI asserts on the artifact rather
//! than inferring from the runner.

use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_owned());
    let version = Command::new(rustc)
        .arg("--version")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map_or_else(|| "unknown".to_owned(), |s| s.trim().to_owned());

    println!("cargo:rustc-env=AGEPONY_RUSTC={version}");
    println!(
        "cargo:rustc-env=AGEPONY_TARGET={}",
        std::env::var("TARGET").unwrap_or_else(|_| "unknown".to_owned())
    );
}
