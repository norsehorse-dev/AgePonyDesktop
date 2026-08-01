//! AgePony Desktop.
//!
//! A library so the GUI binary and the console binary can share it. On macOS
//! and Linux one binary does both jobs; on Windows a GUI-subsystem process has
//! no stdout, so `agepony-cli` exists as a second, console-subsystem binary
//! over exactly this code.

#![forbid(unsafe_code)]

pub mod app;
pub mod cli;
pub mod mark;
pub mod panels;
pub mod qr;
pub mod tasks;
pub mod theme;

/// Open the window.
///
/// # Errors
///
/// Whatever `eframe` returns if the window cannot be created.
pub fn run_gui() -> eframe::Result {
    // The dock, taskbar and Alt-Tab icon, rendered from the same vertex data
    // the UI draws — so it can never drift from the mark on screen.
    //
    // On macOS this is not the Dock icon: that comes from the .app bundle's
    // .icns, which is inset to Apple's 824/1024 grid because macOS does not
    // mask icons. See tools/make-icons.py.
    const ICON: usize = 256;
    let icon = egui::IconData {
        rgba: mark::rasterise(ICON),
        width: ICON as u32,
        height: ICON as u32,
    };

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1020.0, 700.0])
            .with_min_inner_size([760.0, 500.0])
            .with_title("AgePony")
            .with_icon(icon),
        ..Default::default()
    };

    eframe::run_native(
        "AgePony",
        options,
        Box::new(|cc| {
            theme::install(&cc.egui_ctx);
            Ok(Box::new(app::App::new(cc)))
        }),
    )
}

/// Arguments, minus the program name.
#[must_use]
pub fn args() -> Vec<String> {
    std::env::args().skip(1).collect()
}
