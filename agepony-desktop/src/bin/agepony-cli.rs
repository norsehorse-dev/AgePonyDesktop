//! AgePony Desktop — the console binary.
//!
//! Identical verbs to `agepony`, deliberately without
//! `windows_subsystem = "windows"`. That single missing attribute is the whole
//! reason this file exists: a GUI-subsystem process on Windows has no stdout,
//! so `agepony.exe selftest` runs every check and discards every line of the
//! result. PGPony 1.0.0 shipped precisely that, on one of three platforms, and
//! no release check noticed.
//!
//! Making the GUI binary console-subsystem instead would flash a black window
//! behind the app on every launch, which is worse than the bug.
//!
//! It is built and shipped on Windows only. On macOS and Linux the GUI binary
//! prints perfectly well and a second file would be noise.

#![forbid(unsafe_code)]

fn main() {
    let args = agepony_desktop::args();
    if args.is_empty() {
        println!("{}", agepony_desktop::cli::version_line());
        println!("\nRun `agepony-cli help` for the available verbs, or open AgePony itself.");
        return;
    }
    std::process::exit(agepony_desktop::cli::run(&args).unwrap_or(0));
}
