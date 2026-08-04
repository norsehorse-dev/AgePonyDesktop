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
        ui.weak("Apache-2.0.");
    });

    // ---- the family ------------------------------------------------------
    theme::card(ui, |ui| {
        theme::section(ui, "More from NorseHorse");
        ui.add_space(theme::space::SM);
        for app_link in FAMILY {
            family_row(ui, app_link);
        }
        ui.add_space(theme::space::SM);
        ui.horizontal(|ui| {
            ui.label(
                egui::RichText::new("Every Pony app on one page:")
                    .font(egui::FontId::proportional(12.5))
                    .color(ui.visuals().weak_text_color()),
            );
            ui.hyperlink_to("pony.norsehor.se", "https://pony.norsehor.se");
        });
        ui.add_space(theme::space::TIGHT);
        ui.weak(
            "Links open in your browser. The app itself never makes a network \
             request — these are addresses, not connections.",
        );
    });
}

/// One sibling app: name, what it does, where it runs, where it lives, and the
/// accent its own site uses.
struct PonyApp {
    name: &'static str,
    tagline: &'static str,
    platforms: &'static str,
    url: &'static str,
    accent: egui::Color32,
}

/// The rest of the family, ordered by how close each sits to what someone in a
/// file-encryption app is already doing — the same principle PGPony Desktop's
/// list uses. Names and platform strings are product names and OS names, left
/// exactly as they are everywhere else; the accents are each app's own, lifted
/// from the family band on agepony.com so the two lists agree.
const FAMILY: &[PonyApp] = &[
    PonyApp {
        name: "PGPony",
        tagline: "OpenPGP encryption for your messages and files.",
        platforms: "iPhone · Android · macOS · Windows · Linux",
        url: "https://pgpony.app",
        accent: egui::Color32::from_rgb(0x5F, 0xFF, 0xAF),
    },
    PonyApp {
        name: "QuorumPony",
        tagline: "Split a secret into cards. Any few rebuild it. One alone reveals nothing.",
        platforms: "iPhone",
        url: "https://quorumpony.com",
        accent: egui::Color32::from_rgb(0xC8, 0x97, 0x3A),
    },
    PonyApp {
        name: "ScrubPony",
        tagline: "Strips identifying metadata out of JPEGs without touching a pixel.",
        platforms: "macOS · Linux",
        url: "https://scrubpony.app",
        accent: egui::Color32::from_rgb(0x9D, 0x7C, 0xF5),
    },
    PonyApp {
        name: "RelayPony",
        tagline: "Encrypted file transfer, phone to phone.",
        platforms: "iPhone · Android · macOS · Windows · Linux",
        url: "https://relaypony.app",
        accent: egui::Color32::from_rgb(0x1F, 0x9C, 0xF0),
    },
    PonyApp {
        name: "CarrierPony",
        tagline: "Private messaging and file transfer, sealed end to end.",
        platforms: "iPhone · Android",
        url: "https://carrierpony.com",
        accent: egui::Color32::from_rgb(0xF1, 0x66, 0x7B),
    },
    PonyApp {
        name: "BurnPony",
        tagline: "Send a secret. Encrypted on your phone, burned after reading.",
        platforms: "iPhone",
        url: "https://burnpony.app",
        accent: egui::Color32::from_rgb(0xF6, 0x75, 0x29),
    },
];

/// One row of the family list: the app's accent as a dot, its name as the
/// link, where it runs, and one sentence on what it does.
fn family_row(ui: &mut egui::Ui, app_link: &PonyApp) {
    ui.horizontal(|ui| {
        let (dot, _) = ui.allocate_exact_size(egui::Vec2::splat(9.0), egui::Sense::hover());
        ui.painter()
            .circle_filled(dot.center(), 4.0, app_link.accent);
        ui.hyperlink_to(app_link.name, app_link.url);
        ui.label(
            egui::RichText::new(app_link.platforms)
                .font(egui::FontId::new(10.5, egui::FontFamily::Monospace))
                .color(ui.visuals().weak_text_color()),
        );
    });
    ui.horizontal(|ui| {
        ui.add_space(9.0 + theme::space::SM);
        ui.weak(app_link.tagline);
    });
    ui.add_space(theme::space::SM);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_family_list_is_the_others_and_only_the_others() {
        // AgePony linking to itself would be silly, a duplicate URL means a
        // copy-paste slip, and every link must be https to a norsehorse site.
        let mut seen = std::collections::HashSet::new();
        for app_link in FAMILY {
            assert!(
                !app_link.url.contains("agepony.com"),
                "the family list must not contain this app itself"
            );
            assert!(
                app_link.url.starts_with("https://"),
                "{} is not https",
                app_link.name
            );
            assert!(seen.insert(app_link.url), "{} appears twice", app_link.name);
        }
        assert_eq!(FAMILY.len(), 6, "the family has six other members");
    }
}
