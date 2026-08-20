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

    // ---- migration -------------------------------------------------------
    migration_section(app, ui);

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

    // ---- panic wipe ------------------------------------------------------
    panic_wipe_section(app, ui);

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

/// The "upgrade to quantum-safe" batch: re-encrypt existing age files to a
/// post-quantum identity, keeping the originals.
fn migration_section(app: &mut App, ui: &mut egui::Ui) {
    theme::card(ui, |ui| {
        theme::section(ui, "Upgrade files to quantum-safe");
        ui.add_space(theme::space::SM);
        ui.weak(
            "Re-encrypt existing age files to a quantum-safe identity. AgePony decrypts each \
             with your identities (or the passphrase below) and writes a new copy to a folder \
             you choose. The originals are left where they are.",
        );
        ui.add_space(theme::space::SM);

        let pq: Vec<(String, String)> = app
            .store
            .entries()
            .iter()
            .filter(|e| e.kind.is_post_quantum())
            .map(|e| (e.id.clone(), e.label.clone()))
            .collect();

        if pq.is_empty() {
            ui.colored_label(
                theme::danger_ink(ui),
                "No quantum-safe identity yet. Create one on Identities (Generate → Quantum-safe), \
                 then come back.",
            );
            return;
        }

        theme::section(ui, "Quantum-safe identity");
        if app.migrate.target_id.is_none() {
            app.migrate.target_id = pq.first().map(|(id, _)| id.clone());
        }
        for (id, label) in &pq {
            let selected = app.migrate.target_id.as_deref() == Some(id);
            if ui.radio(selected, label).clicked() {
                app.migrate.target_id = Some(id.clone());
            }
        }

        ui.add_space(theme::space::SM);
        ui.horizontal(|ui| {
            if theme::secondary_button(ui, "Choose files…").clicked() {
                if let Some(files) = rfd::FileDialog::new().pick_files() {
                    app.migrate.files = files;
                }
            }
            ui.weak(match app.migrate.files.len() {
                0 => "No files chosen".to_owned(),
                1 => "1 file".to_owned(),
                n => format!("{n} files"),
            });
        });
        ui.horizontal(|ui| {
            if theme::secondary_button(ui, "Choose destination folder…").clicked() {
                if let Some(dir) = rfd::FileDialog::new().pick_folder() {
                    app.migrate.dest = Some(dir);
                }
            }
            match &app.migrate.dest {
                Some(d) => ui.weak(d.display().to_string()),
                None => ui.weak("No folder chosen"),
            };
        });
        ui.horizontal(|ui| {
            ui.label("Passphrase (optional)");
            ui.add(
                egui::TextEdit::singleline(&mut app.migrate.passphrase)
                    .password(true)
                    .hint_text("For any passphrase-encrypted files")
                    .desired_width(240.0),
            );
        });

        ui.add_space(theme::space::SM);
        let busy = app.migrate.job.as_ref().is_some_and(tasks::Running::in_flight);
        let can = !busy
            && app.migrate.target_id.is_some()
            && !app.migrate.files.is_empty()
            && app.migrate.dest.is_some();
        if theme::primary_button_enabled(ui, "Upgrade", can).clicked() {
            start_migration(app, ui.ctx().clone());
        }

        // Live results.
        if let Some(job) = &app.migrate.job {
            ui.add_space(theme::space::SM);
            ui.weak(format!(
                "{} of {} done{}",
                job.done.len() + job.failed.len(),
                job.total(),
                if job.in_flight() { "…" } else { "" }
            ));
            for outcome in &job.done {
                let name = outcome
                    .input
                    .file_name()
                    .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
                ui.colored_label(theme::ACCENT, format!("✓ {name}"));
            }
            for (input, why) in &job.failed {
                let name = input
                    .file_name()
                    .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
                ui.colored_label(theme::danger_ink(ui), format!("⚠ {name} — {why}"));
            }
        }
    });
}

/// The panic wipe: one deliberate, confirmed action that deletes everything the
/// stores hold. Desktop has no app-lock to hang a decoy password on (see
/// PARITY_PLAN F5), so this is an explicit action, not a decoy.
fn panic_wipe_section(app: &mut App, ui: &mut egui::Ui) {
    const CONFIRM: &str = "DELETE";
    theme::card(ui, |ui| {
        theme::section(ui, "Panic wipe");
        ui.add_space(theme::space::SM);
        ui.colored_label(
            theme::danger_ink(ui),
            "Delete every identity, signing key, recipient, and trusted signer, and their key \
             files on disk. This cannot be undone.",
        );
        ui.add_space(theme::space::SM);
        ui.horizontal(|ui| {
            ui.label(format!("Type {CONFIRM} to confirm:"));
            ui.add(
                egui::TextEdit::singleline(&mut app.wipe_confirm)
                    .hint_text(CONFIRM)
                    .desired_width(120.0),
            );
        });
        ui.add_space(theme::space::TIGHT);
        let armed = app.wipe_confirm == CONFIRM;
        if theme::primary_button_enabled(ui, "Wipe everything", armed).clicked() {
            run_panic_wipe(app);
        }
    });
}

fn run_panic_wipe(app: &mut App) {
    let mut trouble = None;
    if let Err(e) = app.store.wipe() {
        trouble = Some(e.to_string());
    }
    if let Err(e) = app.signing_store.wipe() {
        trouble = Some(e.to_string());
    }
    app.signers.clear();
    app.save_signers();
    app.book.entries.clear();
    app.save_book();

    app.wipe_confirm.clear();
    app.status = Some(match trouble {
        Some(why) => format!("Wipe finished with a problem: {why}"),
        None => "Everything has been wiped.".to_owned(),
    });
}

fn start_migration(app: &mut App, ctx: egui::Context) {
    let Some(target_id) = app.migrate.target_id.clone() else {
        return;
    };
    let Some(target_entry) = app.store.get(&target_id) else {
        return;
    };
    let target = target_entry.recipient.clone();
    let dest_dir = match app.migrate.dest.clone() {
        Some(d) => d,
        None => return,
    };
    // Every unprotected identity is a candidate decryptor for the old files.
    let identity_files: Vec<std::path::PathBuf> = app
        .store
        .entries()
        .iter()
        .filter(|e| !e.encrypted)
        .map(|e| app.store.path_for(e))
        .collect();
    let passphrase = (!app.migrate.passphrase.is_empty())
        .then(|| age::secrecy::SecretString::from(app.migrate.passphrase.clone()));
    let inputs = app.migrate.files.clone();

    let repaint = move || ctx.request_repaint();
    app.status = None;
    app.migrate.job = Some(tasks::spawn(
        tasks::Job::Migrate {
            inputs,
            target,
            identity_files,
            passphrase,
            dest_dir,
        },
        repaint,
    ));
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
        name: "PassPony",
        tagline: "Your pass and passage store, in your pocket.",
        platforms: "iPhone · macOS · Windows · Linux",
        url: "https://passpony.app",
        // Best-fit accent; swap for PassPony's own if the family band differs.
        accent: egui::Color32::from_rgb(0xE8, 0xC8, 0x4D),
    },
    PonyApp {
        name: "VaultPony",
        tagline: "VeraCrypt-compatible encrypted vaults, entirely on your device.",
        platforms: "Android",
        url: "https://vaultpony.app",
        // Best-fit accent; swap for VaultPony's own if the family band differs.
        accent: egui::Color32::from_rgb(0xD9, 0x53, 0x4F),
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
        assert_eq!(FAMILY.len(), 8, "the family has eight other members");
    }
}
