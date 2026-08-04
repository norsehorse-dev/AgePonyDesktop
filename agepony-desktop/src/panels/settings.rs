//! The Settings screen: appearance, storage, and what this build is.
//!
//! Everything here used to live in a corner somewhere. Appearance was a
//! control wedged into the sidebar foot, which clipped its labels the moment
//! the rail narrowed; the storage path only appeared in a status line on the
//! Identities screen; the version existed only on the command line. A settings
//! screen is where people look for all three, so that is where they are.

use crate::app::{App, ThemeChoice};
use crate::{tasks, theme};

/// Draw the screen.
pub fn show(app: &mut App, ui: &mut egui::Ui) {
    theme::screen_head(
        ui,
        "Settings",
        "Appearance, where your keys live, and what this build is.",
        |_ui| {},
    );

    // ---- appearance ------------------------------------------------------
    theme::card(ui, |ui| {
        theme::section(ui, "Appearance");
        ui.add_space(theme::space::SM);
        ui.scope(|ui| {
            ui.set_max_width(340.0);
            let selected = ThemeChoice::ALL
                .iter()
                .position(|c| *c == app.theme)
                .unwrap_or(0);
            let labels: Vec<&str> = ThemeChoice::ALL.iter().map(|c| c.label()).collect();
            if let Some(i) = theme::segmented(ui, &labels, selected) {
                if let Some(choice) = ThemeChoice::ALL.get(i) {
                    app.theme = *choice;
                    choice.apply(ui.ctx());
                }
            }
        });
        ui.add_space(theme::space::TIGHT);
        ui.weak("Auto follows the system. The choice is remembered.");
    });

    // ---- storage ---------------------------------------------------------
    theme::card(ui, |ui| {
        theme::section(ui, "Storage");
        ui.add_space(theme::space::SM);
        ui.label(
            egui::RichText::new(app.config_dir.display().to_string())
                .font(egui::FontId::new(12.0, egui::FontFamily::Monospace))
                .color(theme::ink(ui)),
        );
        ui.add_space(theme::space::TIGHT);
        ui.weak(
            "Identity files, the identity index, the recipient book, and the window \
             preferences. Identity files are written readable by you alone; back this \
             folder up and you have backed up your keys.",
        );
        ui.add_space(theme::space::SM);
        if theme::secondary_button(ui, "Show in folder").clicked() {
            tasks::reveal(&app.config_dir.join("identities.json"));
        }
    });

    // ---- about -----------------------------------------------------------
    theme::card(ui, |ui| {
        theme::section(ui, "About");
        ui.add_space(theme::space::SM);
        ui.label(
            egui::RichText::new(format!("AgePony Desktop {}", env!("CARGO_PKG_VERSION")))
                .font(theme::semibold(14.0))
                .color(theme::ink(ui)),
        );
        ui.add_space(theme::space::TIGHT);
        ui.weak(
            "age encryption with post-quantum recipients, interoperable with AgePony \
             on iOS and Android, with rage, and with the reference age CLI.",
        );
        ui.add_space(theme::space::SM);
        ui.horizontal(|ui| {
            ui.hyperlink_to("agepony.com/desktop", "https://agepony.com/desktop");
            ui.label("·");
            ui.hyperlink_to(
                "Source on GitHub",
                "https://github.com/norsehorse-dev/AgePonyDesktop",
            );
        });
        ui.add_space(theme::space::TIGHT);
        ui.weak(
            "Apache-2.0. The only two links in the app, and the app never follows \
             either on its own: it has no network access at all.",
        );
    });
}
