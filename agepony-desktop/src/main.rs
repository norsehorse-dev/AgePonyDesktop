//! AgePony Desktop — the GUI binary.
//!
//! Run with no arguments it opens the window. Run with a verb it behaves like
//! `agepony-cli`, which is what lets CI verify a packaged build on macOS and
//! Linux without shipping a second file there.
//!
//! On Windows this binary is GUI-subsystem and therefore has **no stdout**, so
//! the verbs would run and silently discard their output. That is why
//! `agepony-cli.exe` exists; see `src/bin/agepony-cli.rs`.

#![forbid(unsafe_code)]
// Do not pop a console window alongside the GUI on Windows release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() -> eframe::Result {
    if let Some(code) = agepony_desktop::cli::run(&agepony_desktop::args()) {
        std::process::exit(code);
    }
    agepony_desktop::run_gui()
}
