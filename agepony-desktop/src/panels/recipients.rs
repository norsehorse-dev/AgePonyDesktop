//! Recipient book panel.
//!
//! Public key material only. Nothing written here is secret, which is why the
//! file can be exported, synced or emailed without a second thought.

use crate::app::App;
use crate::theme;

/// Draw the panel.
pub fn show(app: &mut App, ui: &mut egui::Ui) {
    theme::heading(ui, "Recipients");
    ui.weak(format!("Stored in {}", app.book_path.display()));
    ui.add_space(8.0);

    toolbar(app, ui);

    if app.recipients.form_open {
        ui.add_space(8.0);
        form(app, ui);
    }

    ui.add_space(8.0);
    ui.separator();
    ui.add_space(8.0);

    if app.book.entries.is_empty() {
        theme::empty_state(
            ui,
            "No recipients yet. Add one above, or import an age recipients file.",
        );
        return;
    }

    table(app, ui);
}

fn toolbar(app: &mut App, ui: &mut egui::Ui) {
    ui.horizontal(|ui| {
        ui.label("Search");
        ui.add(
            egui::TextEdit::singleline(&mut app.recipients.search)
                .hint_text("name, recipient or note")
                .desired_width(240.0),
        );
        if theme::primary_button(ui, "Add…").clicked() {
            app.recipients.editing = None;
            app.recipients.name.clear();
            app.recipients.recipient.clear();
            app.recipients.note.clear();
            app.recipients.form_open = true;
        }
        if theme::secondary_button(ui, "Import…").clicked() {
            import(app);
        }
        if theme::secondary_button(ui, "Export…").clicked() {
            export(app);
        }
    });
}

fn form(app: &mut App, ui: &mut egui::Ui) {
    let editing = app.recipients.editing.clone();

    theme::card(ui, |ui| {
        ui.strong(match editing.as_deref() {
            Some(name) => format!("Editing {name}"),
            None => "New recipient".to_owned(),
        });

        egui::Grid::new("recipient-form")
            .num_columns(2)
            .spacing([8.0, 6.0])
            .show(ui, |ui| {
                ui.label("Name");
                ui.add(
                    egui::TextEdit::singleline(&mut app.recipients.name)
                        .hint_text("Ada's laptop")
                        .desired_width(320.0),
                );
                ui.end_row();

                ui.label("Recipient");
                ui.add(
                    egui::TextEdit::multiline(&mut app.recipients.recipient)
                        .hint_text("age1… or age1pq… or ssh-ed25519 …")
                        .desired_rows(2)
                        .desired_width(420.0),
                );
                ui.end_row();

                ui.label("Note");
                ui.add(
                    egui::TextEdit::singleline(&mut app.recipients.note)
                        .hint_text("optional")
                        .desired_width(320.0),
                );
                ui.end_row();
            });

        // Validate as the user types, so a bad paste is obvious before saving
        // rather than at encrypt time.
        let typed = app.recipients.recipient.trim();
        if !typed.is_empty() {
            match agepony_core::recipient::parse(typed) {
                Ok(parsed) => {
                    if parsed.kind.is_post_quantum() {
                        ui.colored_label(theme::PQ_BADGE, "◆ post-quantum recipient");
                    } else {
                        ui.weak("valid recipient");
                    }
                }
                Err(e) => {
                    ui.colored_label(theme::DANGER, e.to_string());
                }
            }
        }

        ui.horizontal(|ui| {
            if theme::primary_button(ui, "Save").clicked() {
                save(app);
            }
            if theme::secondary_button(ui, "Cancel").clicked() {
                app.recipients.form_open = false;
                app.recipients.editing = None;
            }
        });
    });
}

fn table(app: &mut App, ui: &mut egui::Ui) {
    let matches: Vec<_> = app
        .book
        .search(&app.recipients.search)
        .into_iter()
        .cloned()
        .collect();

    ui.weak(format!(
        "{} of {} shown",
        matches.len(),
        app.book.entries.len()
    ));
    ui.add_space(4.0);

    for entry in matches {
        let kind = agepony_core::recipient::parse(&entry.recipient)
            .ok()
            .map(|p| p.kind);

        theme::card(ui, |ui| {
            ui.horizontal(|ui| {
                ui.strong(&entry.name);
                if entry.is_own() {
                    theme::capsule(ui, "Yours", theme::ACCENT);
                }
                match kind {
                    Some(k) if k.is_post_quantum() => {
                        theme::pq_badge(ui);
                    }
                    Some(_) => {}
                    None => {
                        ui.colored_label(theme::DANGER, "unrecognised recipient");
                    }
                }
            });

            if let Some(note) = entry.note.as_deref().filter(|n| !n.trim().is_empty()) {
                ui.weak(note);
            }
            if theme::key_block(ui, None, &entry.recipient) {
                app.status = Some(format!("Copied {}", entry.name));
            }

            ui.horizontal(|ui| {
                if theme::secondary_button(ui, "Edit").clicked() {
                    app.recipients.editing = Some(entry.name.clone());
                    app.recipients.name = entry.name.clone();
                    app.recipients.recipient = entry.recipient.clone();
                    app.recipients.note = entry.note.clone().unwrap_or_default();
                    app.recipients.form_open = true;
                }
                if entry.is_own() {
                    // Removing this would only make it come back on the next
                    // launch, since it belongs to an identity that still
                    // exists. Deleting the identity is the real action, and it
                    // takes the recipient with it.
                    ui.add_enabled(false, egui::Button::new("Remove"))
                        .on_disabled_hover_text(
                            "This is your own key. Delete the identity on the Identities tab to remove it.",
                        );
                } else if theme::destructive_button(ui, "Remove").clicked() {
                    // No typed confirmation, unlike deleting an identity: this
                    // destroys a public key that can be pasted back in a
                    // second, not key material.
                    app.book.remove(&entry.name);
                    app.save_book();
                    app.status = Some(format!("Removed {}", entry.name));
                }
            });
        });
        ui.add_space(4.0);
    }
}

fn save(app: &mut App) {
    let name = app.recipients.name.clone();
    let recipient = app.recipients.recipient.clone();
    let note = Some(app.recipients.note.clone()).filter(|n| !n.trim().is_empty());

    let result = match app.recipients.editing.clone() {
        Some(current) => app
            .book
            .update(&current, &name, &recipient, note)
            .map(|()| format!("Updated {name}")),
        None => app
            .book
            .add(&name, &recipient, note)
            .map(|()| format!("Added {name}")),
    };

    if result.is_ok() {
        app.recipients.form_open = false;
        app.recipients.editing = None;
        app.save_book();
    }
    app.report(result);
}

fn import(app: &mut App) {
    let Some(path) = rfd::FileDialog::new().pick_file() else {
        return;
    };
    let result = app
        .book
        .import_recipients_file(&path)
        .map(|n| format!("Imported {n} recipient(s)"));
    if result.is_ok() {
        app.save_book();
    }
    app.report(result);
}

fn export(app: &mut App) {
    let Some(path) = rfd::FileDialog::new()
        .set_file_name("agepony-recipients.txt")
        .save_file()
    else {
        return;
    };
    let result = app
        .book
        .export_recipients_file(&path)
        .map(|()| format!("Exported to {}", path.display()));
    app.report(result);
}
