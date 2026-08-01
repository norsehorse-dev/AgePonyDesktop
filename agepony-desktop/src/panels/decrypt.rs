//! Decrypt panel.

use crate::app::{App, DecryptSource};
use crate::{tasks, theme};
use age::secrecy::SecretString;

/// Draw the panel.
pub fn show(app: &mut App, ui: &mut egui::Ui) {
    theme::heading(ui, "Decrypt");
    ui.add_space(8.0);

    ui.horizontal(|ui| {
        if theme::secondary_button(ui, "Choose encrypted files…").clicked() {
            if let Some(files) = rfd::FileDialog::new()
                .add_filter("age files", &["age", "txt"])
                .pick_files()
            {
                app.decrypt.inputs.extend(files);
                app.decrypt.inputs.dedup();
            }
        }
        if !app.decrypt.inputs.is_empty() && theme::secondary_button(ui, "Clear").clicked() {
            app.decrypt.inputs.clear();
        }
    });

    crate::panels::file_list(ui, &mut app.decrypt.inputs, "decrypt");

    ui.add_space(8.0);
    theme::section(ui, "Unlock with");
    const SOURCES: [(DecryptSource, &str); 3] = [
        (DecryptSource::Active, "Active identity"),
        (DecryptSource::File, "An identity file"),
        (DecryptSource::Passphrase, "A passphrase"),
    ];
    let selected = SOURCES
        .iter()
        .position(|(s, _)| *s == app.decrypt.source)
        .unwrap_or(0);
    let labels: Vec<&str> = SOURCES.iter().map(|(_, l)| *l).collect();
    // Width-constrained: a segmented picker reads as one group, and a very wide
    // one stops doing that.
    ui.scope(|ui| {
        ui.set_max_width(420.0);
        if let Some(i) = theme::segmented(ui, &labels, selected) {
            if let Some((source, _)) = SOURCES.get(i) {
                app.decrypt.source = *source;
            }
        }
    });

    match app.decrypt.source {
        DecryptSource::Active => active_source(app, ui),
        DecryptSource::File => file_source(app, ui),
        DecryptSource::Passphrase => {
            ui.add(
                egui::TextEdit::singleline(&mut app.decrypt.passphrase)
                    .password(true)
                    .hint_text("Passphrase")
                    .desired_width(280.0),
            );
        }
    }

    ui.add_space(8.0);
    let label = match app.decrypt.inputs.len() {
        0 | 1 => "Decrypt".to_owned(),
        n => format!("Decrypt {n} files"),
    };
    if theme::primary_button_enabled(ui, &label, can_start(app)).clicked() {
        start(app, ui.ctx().clone());
    }

    crate::panels::job_view(app, ui, false);
}

/// Whether the Decrypt action is available. Shared with the shortcut.
pub fn can_start(app: &App) -> bool {
    let busy = app
        .decrypt
        .job
        .as_ref()
        .is_some_and(tasks::Running::in_flight);
    !busy && !app.decrypt.inputs.is_empty()
}

fn active_source(app: &mut App, ui: &mut egui::Ui) {
    let Some(entry) = app.store.active().cloned() else {
        ui.colored_label(
            theme::DANGER,
            "No active identity. Generate or import one on the Identities tab.",
        );
        return;
    };

    ui.horizontal(|ui| {
        ui.strong(&entry.label);
        if entry.kind.is_post_quantum() {
            theme::pq_badge(ui);
        }
    });

    if entry.encrypted {
        ui.horizontal(|ui| {
            ui.label("Passphrase for this identity");
            ui.add(
                egui::TextEdit::singleline(&mut app.decrypt.identity_passphrase)
                    .password(true)
                    .desired_width(240.0),
            );
        });
    }
}

fn file_source(app: &mut App, ui: &mut egui::Ui) {
    if theme::secondary_button(ui, "Choose identity file…").clicked() {
        if let Some(files) = rfd::FileDialog::new().pick_files() {
            app.decrypt.identity_files = files;
        }
    }
    for f in &app.decrypt.identity_files {
        ui.weak(f.display().to_string());
    }

    let any_encrypted = app
        .decrypt
        .identity_files
        .iter()
        .any(|p| std::fs::read(p).is_ok_and(|b| agepony_core::identity::looks_encrypted(&b)));
    if any_encrypted {
        ui.horizontal(|ui| {
            ui.label("Passphrase for the identity file");
            ui.add(
                egui::TextEdit::singleline(&mut app.decrypt.identity_passphrase)
                    .password(true)
                    .desired_width(240.0),
            );
        });
    }
}

/// Kick off the batch.
pub fn start(app: &mut App, ctx: egui::Context) {
    if !can_start(app) {
        return;
    }
    let inputs = app.decrypt.inputs.clone();
    let repaint = move || ctx.request_repaint();

    let identity_passphrase = (!app.decrypt.identity_passphrase.is_empty())
        .then(|| SecretString::from(app.decrypt.identity_passphrase.clone()));

    let unlock = match app.decrypt.source {
        DecryptSource::Passphrase => {
            if app.decrypt.passphrase.is_empty() {
                app.status = Some("Enter the file's passphrase first.".to_owned());
                return;
            }
            tasks::Unlock::Passphrase(SecretString::from(app.decrypt.passphrase.clone()))
        }
        DecryptSource::Active => {
            let Some(entry) = app.store.active().cloned() else {
                app.status = Some("No active identity. Set one on the Identities tab.".to_owned());
                return;
            };
            if entry.encrypted && identity_passphrase.is_none() {
                app.status = Some(format!(
                    "{} is passphrase protected. Enter its passphrase.",
                    entry.label
                ));
                return;
            }
            tasks::Unlock::Identities {
                files: vec![app.store.path_for(&entry)],
                passphrase: identity_passphrase,
            }
        }
        DecryptSource::File => {
            if app.decrypt.identity_files.is_empty() {
                app.status = Some("Choose an identity file first.".to_owned());
                return;
            }
            tasks::Unlock::Identities {
                files: app.decrypt.identity_files.clone(),
                passphrase: identity_passphrase,
            }
        }
    };

    app.status = None;
    app.decrypt.job = Some(tasks::spawn(
        tasks::Job::Decrypt { inputs, unlock },
        repaint,
    ));
}
