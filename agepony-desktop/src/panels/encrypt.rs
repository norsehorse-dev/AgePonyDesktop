//! Encrypt panel.

use crate::app::App;
use crate::{tasks, theme};
use age::secrecy::SecretString;

/// Draw the panel.
pub fn show(app: &mut App, ui: &mut egui::Ui) {
    theme::heading(ui, "Encrypt");
    ui.add_space(8.0);

    ui.horizontal(|ui| {
        if theme::secondary_button(ui, "Choose files…").clicked() {
            if let Some(files) = rfd::FileDialog::new().pick_files() {
                app.encrypt.inputs.extend(files);
                app.encrypt.inputs.dedup();
            }
        }
        if !app.encrypt.inputs.is_empty() && theme::secondary_button(ui, "Clear").clicked() {
            app.encrypt.inputs.clear();
        }
    });

    crate::panels::file_list(ui, &mut app.encrypt.inputs, "encrypt");

    ui.add_space(8.0);
    ui.checkbox(
        &mut app.encrypt.use_passphrase,
        "Use a passphrase instead of recipients",
    );

    if app.encrypt.use_passphrase {
        ui.add(
            egui::TextEdit::singleline(&mut app.encrypt.passphrase)
                .password(true)
                .hint_text("Passphrase")
                .desired_width(280.0),
        );
    } else {
        recipient_picker(app, ui);
    }

    ui.add_space(8.0);
    ui.checkbox(&mut app.encrypt.armor, "ASCII armor the output");
    ui.add_space(8.0);

    let label = match app.encrypt.inputs.len() {
        0 | 1 => "Encrypt".to_owned(),
        n => format!("Encrypt {n} files"),
    };
    if theme::primary_button_enabled(ui, &label, can_start(app)).clicked() {
        start(app, ui.ctx().clone());
    }

    crate::panels::job_view(app, ui, true);
}

/// Whether the Encrypt action is available. Shared with the keyboard shortcut,
/// so the two cannot disagree about when it is legal to press.
pub fn can_start(app: &App) -> bool {
    let busy = app
        .encrypt
        .job
        .as_ref()
        .is_some_and(tasks::Running::in_flight);
    !busy && !app.encrypt.inputs.is_empty()
}

fn recipient_picker(app: &mut App, ui: &mut egui::Ui) {
    theme::section(ui, "Recipients");

    if app.book.entries.is_empty() {
        ui.weak("The recipient book is empty. Generate an identity, or add recipients on the Recipients tab, or paste one below.");
    } else {
        theme::card(ui, |ui| {
            let entries: Vec<_> = app.book.sorted().into_iter().cloned().collect();
            for entry in entries {
                let mut ticked = app.encrypt.picked.contains(&entry.name);
                ui.horizontal(|ui| {
                    if ui.checkbox(&mut ticked, &entry.name).changed() {
                        if ticked {
                            app.encrypt.picked.insert(entry.name.clone());
                        } else {
                            app.encrypt.picked.remove(&entry.name);
                        }
                    }
                    if entry.is_own() {
                        theme::capsule(ui, "Yours", theme::ACCENT);
                    }
                    if agepony_core::recipient::parse(&entry.recipient)
                        .is_ok_and(|p| p.kind.is_post_quantum())
                    {
                        ui.colored_label(theme::PQ_BADGE, "◆");
                    }
                    if let Some(note) = entry.note.as_deref().filter(|n| !n.trim().is_empty()) {
                        ui.weak(note);
                    }
                });
            }
        });
    }

    ui.label("Or paste recipients, one per line:");
    ui.add(
        egui::TextEdit::multiline(&mut app.encrypt.extra)
            .hint_text("age1… or age1pq… or ssh-ed25519 …")
            .desired_rows(2)
            .desired_width(440.0),
    );

    // Tell the user what will happen before they press the button, including
    // the mixed-recipient rule, which is otherwise a surprise at encrypt time.
    match collect(app) {
        Ok(list) if list.is_empty() => {
            ui.weak("No recipients selected.");
        }
        Ok(list) => match agepony_core::recipient::parse_all(&list) {
            Ok(parsed) => {
                if parsed.iter().all(|p| p.kind.is_post_quantum()) {
                    ui.colored_label(
                        theme::PQ_BADGE,
                        format!("◆ {} recipient(s), all quantum-safe", parsed.len()),
                    );
                } else {
                    ui.weak(format!("{} recipient(s)", parsed.len()));
                }
            }
            Err(e) => {
                ui.colored_label(theme::DANGER, e.to_string());
            }
        },
        Err(e) => {
            ui.colored_label(theme::DANGER, e.to_string());
        }
    }
}

/// Every recipient string the user has selected or typed.
fn collect(app: &App) -> agepony_core::Result<Vec<String>> {
    let mut out: Vec<String> = Vec::new();
    for name in &app.encrypt.picked {
        if let Some(entry) = app.book.entries.iter().find(|e| &e.name == name) {
            out.push(entry.recipient.clone());
        }
    }
    out.extend(
        app.encrypt
            .extra
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(str::to_owned),
    );
    out.sort();
    out.dedup();
    Ok(out)
}

/// Kick off the batch.
pub fn start(app: &mut App, ctx: egui::Context) {
    if !can_start(app) {
        return;
    }
    let inputs = app.encrypt.inputs.clone();
    let repaint = move || ctx.request_repaint();

    let lock = if app.encrypt.use_passphrase {
        if app.encrypt.passphrase.is_empty() {
            app.status = Some("Enter a passphrase first.".to_owned());
            return;
        }
        tasks::Lock::Passphrase(SecretString::from(app.encrypt.passphrase.clone()))
    } else {
        let strings = match collect(app) {
            Ok(s) => s,
            Err(e) => {
                app.status = Some(e.to_string());
                return;
            }
        };
        match agepony_core::recipient::parse_all(&strings) {
            Ok(recipients) => tasks::Lock::Recipients(recipients),
            Err(e) => {
                app.status = Some(e.to_string());
                return;
            }
        }
    };

    app.status = None;
    app.encrypt.job = Some(tasks::spawn(
        tasks::Job::Encrypt {
            inputs,
            lock,
            armor: app.encrypt.armor,
        },
        repaint,
    ));
}
