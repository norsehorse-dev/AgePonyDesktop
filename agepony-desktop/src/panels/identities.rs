//! Identities panel: the store, rendered.

use crate::app::App;
use crate::theme;
use age::secrecy::SecretString;
use agepony_core::signing::store::SigningKind;
use agepony_core::store::Kind;

/// Draw the panel.
pub fn show(app: &mut App, ui: &mut egui::Ui) {
    theme::heading(ui, "Identities");
    ui.weak(format!("Stored in {}", app.config_dir.display()));
    ui.add_space(8.0);

    create_row(app, ui);
    ui.add_space(12.0);
    ui.separator();
    ui.add_space(8.0);

    if app.store.entries().is_empty() {
        theme::empty_state(
            ui,
            "No identities yet. Generate one above, or import an existing identity file.",
        );
    } else {
        list(app, ui);
    }

    ssh_list(app, ui);

    ui.add_space(12.0);
    ui.separator();
    ui.add_space(8.0);
    porting(app, ui);
}

/// Move an identity from a phone onto this machine.
///
/// The desktop's own identity is the channel: only the machine holding that
/// private key can read what the phone sends. No OTP, no server, no pairing.
fn porting(app: &mut App, ui: &mut egui::Ui) {
    theme::heading(ui, "Port an identity from your phone");
    ui.add_space(4.0);

    let Some(active) = app.store.active().cloned() else {
        ui.weak("Generate or import an identity first — this machine needs one to receive with.");
        return;
    };

    ui.horizontal_wrapped(|ui| {
        ui.weak("Show this to your phone, encrypt the phone's identity to it, then bring the file back here.");
    });
    ui.add_space(4.0);

    ui.horizontal(|ui| {
        ui.label("Receiving as");
        ui.strong(&active.label);
        if active.kind.is_post_quantum() {
            ui.colored_label(theme::PQ_BADGE, "◆ quantum-safe transfer");
        }
    });

    if !active.kind.is_post_quantum() {
        ui.horizontal_wrapped(|ui| {
            ui.colored_label(theme::DANGER, "⚠");
            ui.weak(
                "This transfer is only classically protected. Anyone who records the file \
                 today could read it with a quantum computer later — and it contains a \
                 private key. Set a post-quantum identity active before porting.",
            );
        });
    }

    if theme::key_block(ui, Some("This machine's recipient"), &active.recipient) {
        app.status = Some("Recipient copied".to_owned());
    }

    ui.horizontal(|ui| {
        if theme::secondary_button(ui, "Save to file…").clicked() {
            save_recipient(app, &active.label, &active.recipient);
        }
        let label = if app.identities.show_qr {
            "Hide QR code"
        } else {
            "Show QR code"
        };
        if theme::secondary_button(ui, label).clicked() {
            app.identities.show_qr = !app.identities.show_qr;
        }
        if theme::primary_button(ui, "Import ported file…").clicked() {
            receive(app, &active.id);
        }
    });

    if app.identities.show_qr {
        qr_code(app, ui, &active.recipient);
    }

    pending(app, ui);
}

fn qr_code(app: &mut App, ui: &mut egui::Ui, recipient: &str) {
    // Rebuild only when the recipient changes.
    let stale = app
        .identities
        .qr
        .as_ref()
        .is_none_or(|(cached, _)| cached != recipient);
    if stale {
        app.identities.qr =
            crate::qr::render(ui.ctx(), "porting-qr", recipient).map(|r| (recipient.to_owned(), r));
    }

    let Some((_, rendered)) = app.identities.qr.as_ref() else {
        ui.colored_label(
            theme::DANGER,
            "That recipient is too long to fit in a QR code.",
        );
        return;
    };

    ui.add_space(6.0);
    let size = rendered.preferred_size();
    ui.add(
        egui::Image::new(&rendered.texture)
            .fit_to_exact_size(egui::vec2(size, size))
            .texture_options(egui::TextureOptions::NEAREST),
    );
    ui.weak(format!(
        "{} modules square · {} characters encoded",
        rendered.modules,
        rendered.encoded.len()
    ));

    if rendered.is_dense() {
        ui.horizontal_wrapped(|ui| {
            ui.weak(
                "That is a dense code — a post-quantum public key is 1216 bytes. Hold the \
                 phone steady and close, or use Save to file and send it across another way.",
            );
        });
    }
}

fn save_recipient(app: &mut App, label: &str, recipient: &str) {
    let Some(path) = rfd::FileDialog::new()
        .set_file_name(format!("{label}-recipient.txt"))
        .save_file()
    else {
        return;
    };
    let body = format!("# AgePony Desktop — {label}\n{recipient}\n");
    app.status = Some(match std::fs::write(&path, body) {
        Ok(()) => format!("Wrote {}", path.display()),
        Err(e) => e.to_string(),
    });
}

fn receive(app: &mut App, active_id: &str) {
    let Some(path) = rfd::FileDialog::new()
        .add_filter("age files", &["age", "txt"])
        .pick_file()
    else {
        return;
    };

    // The active identity may itself be passphrase protected; reuse the field
    // already on this panel rather than inventing a second prompt.
    let passphrase = (!app.identities.passphrase.is_empty())
        .then(|| SecretString::from(app.identities.passphrase.clone()));

    let identities = match app.store.load(active_id, passphrase.as_ref()) {
        Ok(k) => k,
        Err(e) => {
            app.status = Some(format!(
                "Could not unlock the receiving identity: {e}. Tick “Protect with a passphrase” above and enter it, then try again."
            ));
            return;
        }
    };

    match agepony_core::porting::open(&path, &identities) {
        Ok(ported) => {
            if let Some(existing) = app.store.find_by_recipient(&ported.recipient) {
                app.status = Some(format!(
                    "That identity is already here, stored as “{}”.",
                    existing.label
                ));
                return;
            }
            let label = ported
                .suggested_label
                .clone()
                .unwrap_or_else(|| "Ported identity".to_owned());
            app.status = None;
            app.identities.pending_port = Some(crate::app::PendingPort { ported, label });
        }
        Err(e) => {
            app.status = Some(format!(
                "Could not open that file: {e}. Check the phone encrypted it to the recipient shown above."
            ));
        }
    }
}

fn pending(app: &mut App, ui: &mut egui::Ui) {
    if app.identities.pending_port.is_none() {
        return;
    }

    let mut install = false;
    let mut cancel = false;

    if let Some(port) = app.identities.pending_port.as_mut() {
        ui.add_space(8.0);
        theme::card(ui, |ui| {
            ui.strong("An identity arrived");
            ui.horizontal(|ui| {
                ui.weak(crate::app::kind_label(port.ported.kind));
                if port.ported.kind.is_post_quantum() {
                    theme::pq_badge(ui);
                }
            });
            theme::key_block(ui, Some("Recipient"), &port.ported.recipient);
            ui.horizontal(|ui| {
                ui.label("Store it as");
                ui.add(egui::TextEdit::singleline(&mut port.label).desired_width(220.0));
            });
            ui.horizontal(|ui| {
                install =
                    theme::primary_button_enabled(ui, "Install", !port.label.trim().is_empty())
                        .clicked();
                cancel = theme::destructive_button(ui, "Discard").clicked();
            });
            ui.weak(
                "Delete the transfer file once this is installed — it holds a private key, \
                 readable by this machine.",
            );
        });
    }

    if install {
        if let Some(port) = app.identities.pending_port.take() {
            let protect = app
                .identities
                .protect
                .then(|| SecretString::from(app.identities.passphrase.clone()));
            let result = agepony_core::vault::install_ported(
                &mut app.store,
                &mut app.book,
                &port.ported,
                &port.label,
                protect.as_ref(),
            )
            .map(|e| format!("Installed {}", e.label));
            app.save_book();
            app.report(result);
        }
    } else if cancel {
        // Dropping it zeroizes the key material it was holding.
        app.identities.pending_port = None;
        app.status = Some("Discarded".to_owned());
    }
}

fn create_row(app: &mut App, ui: &mut egui::Ui) {
    ui.horizontal(|ui| {
        ui.label("Label");
        ui.add(
            egui::TextEdit::singleline(&mut app.identities.label)
                .hint_text("Laptop")
                .desired_width(200.0),
        );
    });

    ui.horizontal(|ui| {
        ui.checkbox(&mut app.identities.protect, "Protect with a passphrase");
        if app.identities.protect {
            ui.add(
                egui::TextEdit::singleline(&mut app.identities.passphrase)
                    .password(true)
                    .hint_text("Passphrase")
                    .desired_width(220.0),
            );
        }
    });

    let named = !app.identities.label.trim().is_empty();
    let ready = named && (!app.identities.protect || !app.identities.passphrase.is_empty());

    ui.horizontal(|ui| {
        if theme::primary_button_enabled(ui, "Generate classic", ready).clicked() {
            generate(app, Kind::X25519);
        }
        if theme::primary_button_enabled(ui, "Generate post-quantum", ready).clicked() {
            generate(app, Kind::PostQuantum);
        }
        if theme::primary_button_enabled(ui, "Import from file…", named).clicked() {
            import(app);
        }
    });

    // SSH signing keys live here too — they are keys you hold, generated and
    // imported the same way, and used to sign on the Sign screen.
    ui.add_space(theme::space::SM);
    ui.horizontal(|ui| {
        if theme::primary_button_enabled(ui, "Generate SSH · Ed25519", ready).clicked() {
            generate_ssh(app, SigningKind::Ed25519);
        }
        if theme::primary_button_enabled(ui, "Generate SSH · RSA", ready).clicked() {
            generate_ssh(app, SigningKind::Rsa);
        }
        if theme::primary_button_enabled(ui, "Import SSH key…", named).clicked() {
            import_ssh(app);
        }
    });

    if !named {
        ui.weak("Give the identity a label first.");
    }

    ui.horizontal_wrapped(|ui| {
        ui.colored_label(theme::PQ_BADGE, "◆");
        ui.weak(
            "Post-quantum identities use the mlkem768x25519 recipient, the same one AgePony \
             on iOS and Android uses. A file encrypted to one cannot also carry a classic \
             recipient — the weakest recipient would set the bar.",
        );
    });

    if app.identities.protect {
        ui.horizontal_wrapped(|ui| {
            ui.weak(
                "A protected identity file is an ordinary age file, so `age -d` and the \
                 mobile apps can open it. There is no recovery if you forget the passphrase.",
            );
        });
    }

    if !app.identities.import_passphrase.is_empty() {
        ui.horizontal(|ui| {
            ui.label("Passphrase for the file being imported");
            ui.add(
                egui::TextEdit::singleline(&mut app.identities.import_passphrase)
                    .password(true)
                    .desired_width(220.0),
            );
        });
    }
}

fn list(app: &mut App, ui: &mut egui::Ui) {
    // Collect first: the loop mutates the store, and holding a borrow across
    // that is exactly the thing the borrow checker exists to stop.
    let entries: Vec<_> = app.store.entries().to_vec();
    let active = app.store.active_id().map(str::to_owned);

    for entry in entries {
        let is_active = active.as_deref() == Some(entry.id.as_str());

        theme::card(ui, |ui| {
            ui.horizontal(|ui| {
                ui.strong(&entry.label);
                if entry.kind.is_post_quantum() {
                    theme::pq_badge(ui);
                }
                if entry.encrypted {
                    theme::passphrase_badge(ui);
                }
                if is_active {
                    ui.colored_label(theme::ACCENT, "active");
                }
            });

            ui.weak(format!(
                "{} · created {}",
                crate::app::kind_label(entry.kind),
                entry.created
            ));

            if theme::key_block(ui, Some("Recipient"), &entry.recipient) {
                app.status = Some(format!("Copied the recipient for {}", entry.label));
            }

            ui.horizontal(|ui| {
                if !is_active && theme::secondary_button(ui, "Set active").clicked() {
                    let result = app
                        .store
                        .set_active(&entry.id)
                        .map(|()| format!("{} is now the active identity", entry.label));
                    app.report(result);
                }
                if theme::secondary_button(ui, "Rename").clicked() {
                    app.identities.renaming = Some((entry.id.clone(), entry.label.clone()));
                }
                if theme::secondary_button(ui, "Export…").clicked() {
                    export(app, &entry.id, &entry.label, entry.encrypted);
                }
                if theme::destructive_button(ui, "Delete…").clicked() {
                    app.identities.deleting = Some((entry.id.clone(), String::new()));
                }
            });

            rename_row(app, ui, &entry.id);
            delete_row(app, ui, &entry.id, &entry.label);
        });
        ui.add_space(4.0);
    }
}

fn rename_row(app: &mut App, ui: &mut egui::Ui, id: &str) {
    let Some((renaming_id, _)) = app.identities.renaming.as_ref() else {
        return;
    };
    if renaming_id != id {
        return;
    }

    let mut commit = false;
    let mut cancel = false;
    if let Some((_, text)) = app.identities.renaming.as_mut() {
        ui.horizontal(|ui| {
            ui.label("New label");
            ui.add(egui::TextEdit::singleline(text).desired_width(200.0));
            commit = theme::primary_button(ui, "Save").clicked();
            cancel = theme::secondary_button(ui, "Cancel").clicked();
        });
    }

    if commit {
        if let Some((id, text)) = app.identities.renaming.take() {
            let result = app
                .store
                .rename(&id, &text)
                .map(|()| format!("Renamed to {text}"));
            app.report(result);
        }
    } else if cancel {
        app.identities.renaming = None;
    }
}

fn delete_row(app: &mut App, ui: &mut egui::Ui, id: &str, label: &str) {
    let Some((deleting_id, _)) = app.identities.deleting.as_ref() else {
        return;
    };
    if deleting_id != id {
        return;
    }

    let mut confirmed = false;
    let mut cancel = false;
    if let Some((_, typed)) = app.identities.deleting.as_mut() {
        ui.colored_label(
            theme::DANGER,
            format!(
                "Deleting an identity destroys its key material. Anything encrypted only to {label} becomes unreadable, permanently. Its recipient is removed from your book too, so you cannot encrypt to a key you no longer hold."
            ),
        );
        ui.horizontal(|ui| {
            ui.label(format!("Type “{label}” to confirm"));
            ui.add(egui::TextEdit::singleline(typed).desired_width(200.0));
            confirmed = typed.trim() == label && theme::destructive_button(ui, "Delete").clicked();
            cancel = theme::secondary_button(ui, "Cancel").clicked();
        });
    }

    if confirmed {
        if let Some((id, _)) = app.identities.deleting.take() {
            let result = agepony_core::vault::delete(&mut app.store, &mut app.book, &id)
                .map(|()| format!("Deleted {label}, and removed its recipient"));
            app.save_book();
            app.report(result);
        }
    } else if cancel {
        app.identities.deleting = None;
    }
}

/// The SSH signing keys, listed below the age identities.
fn ssh_list(app: &mut App, ui: &mut egui::Ui) {
    let entries = app.signing_store.entries().to_vec();
    if entries.is_empty() {
        return;
    }
    ui.add_space(12.0);
    theme::heading(ui, "SSH signing keys");
    ui.weak("For signing files on the Sign screen. These cannot decrypt.");
    ui.add_space(8.0);

    for entry in entries {
        theme::card(ui, |ui| {
            ui.horizontal(|ui| {
                ui.strong(&entry.label);
                theme::capsule(ui, entry.kind.label(), theme::ACCENT);
                if entry.encrypted {
                    theme::passphrase_badge(ui);
                }
            });
            ui.weak(format!("created {}", entry.created));
            ui.add(
                egui::Label::new(
                    egui::RichText::new(&entry.fingerprint)
                        .monospace()
                        .size(11.0),
                )
                .wrap(),
            );
            ui.horizontal(|ui| {
                if theme::secondary_button(ui, "Rename").clicked() {
                    app.identities.ssh_renaming = Some((entry.id.clone(), entry.label.clone()));
                }
                if theme::destructive_button(ui, "Delete…").clicked() {
                    app.identities.ssh_deleting = Some((entry.id.clone(), String::new()));
                }
            });
            ssh_rename_row(app, ui, &entry.id);
            ssh_delete_row(app, ui, &entry.id, &entry.label);
        });
        ui.add_space(4.0);
    }
}

fn ssh_rename_row(app: &mut App, ui: &mut egui::Ui, id: &str) {
    let Some((renaming_id, _)) = app.identities.ssh_renaming.as_ref() else {
        return;
    };
    if renaming_id != id {
        return;
    }
    let mut commit = false;
    let mut cancel = false;
    if let Some((_, text)) = app.identities.ssh_renaming.as_mut() {
        ui.horizontal(|ui| {
            ui.label("New label");
            ui.add(egui::TextEdit::singleline(text).desired_width(200.0));
            commit = theme::primary_button(ui, "Save").clicked();
            cancel = theme::secondary_button(ui, "Cancel").clicked();
        });
    }
    if commit {
        if let Some((id, text)) = app.identities.ssh_renaming.take() {
            let result = app
                .signing_store
                .rename(&id, &text)
                .map(|()| format!("Renamed to {text}"));
            app.report(result);
        }
    } else if cancel {
        app.identities.ssh_renaming = None;
    }
}

fn ssh_delete_row(app: &mut App, ui: &mut egui::Ui, id: &str, label: &str) {
    let Some((deleting_id, _)) = app.identities.ssh_deleting.as_ref() else {
        return;
    };
    if deleting_id != id {
        return;
    }
    let mut confirmed = false;
    let mut cancel = false;
    if let Some((_, typed)) = app.identities.ssh_deleting.as_mut() {
        ui.colored_label(
            theme::DANGER,
            format!("Deleting {label} removes its private key. You will not be able to sign with it again."),
        );
        ui.horizontal(|ui| {
            ui.label(format!("Type “{label}” to confirm"));
            ui.add(egui::TextEdit::singleline(typed).desired_width(200.0));
            confirmed = typed.trim() == label && theme::destructive_button(ui, "Delete").clicked();
            cancel = theme::secondary_button(ui, "Cancel").clicked();
        });
    }
    if confirmed {
        if let Some((id, _)) = app.identities.ssh_deleting.take() {
            let result = app
                .signing_store
                .delete(&id)
                .map(|()| format!("Deleted {label}"));
            app.report(result);
        }
    } else if cancel {
        app.identities.ssh_deleting = None;
    }
}

fn generate_ssh(app: &mut App, kind: SigningKind) {
    let label = app.identities.label.trim().to_owned();
    let passphrase = app
        .identities
        .protect
        .then(|| SecretString::from(app.identities.passphrase.clone()));

    // RSA generation takes a moment; ed25519 is instant.
    let result = app
        .signing_store
        .generate(&label, kind, passphrase.as_ref())
        .map(|e| format!("Generated {} ({})", e.label, e.kind.label()));

    if result.is_ok() {
        app.identities.label.clear();
        app.identities.passphrase.clear();
        app.identities.protect = false;
    }
    app.report(result);
}

fn import_ssh(app: &mut App) {
    let Some(source) = rfd::FileDialog::new().pick_file() else {
        return;
    };
    let text = match std::fs::read_to_string(&source) {
        Ok(t) => t,
        Err(e) => {
            app.status = Some(format!("Couldn't read the key file: {e}"));
            return;
        }
    };

    let label = app.identities.label.trim().to_owned();
    let source_pass = (!app.identities.import_passphrase.trim().is_empty())
        .then(|| SecretString::from(app.identities.import_passphrase.trim().to_owned()));
    let protect = app
        .identities
        .protect
        .then(|| SecretString::from(app.identities.passphrase.clone()));

    match app
        .signing_store
        .import(&label, &text, source_pass.as_ref(), protect.as_ref())
    {
        Ok(e) => {
            app.identities.label.clear();
            app.identities.passphrase.clear();
            app.identities.import_passphrase.clear();
            app.identities.protect = false;
            app.status = Some(format!("Imported {} ({})", e.label, e.kind.label()));
        }
        Err(agepony_core::CoreError::PassphraseRequired) => {
            // Surface the passphrase field (create_row shows it when non-empty).
            if app.identities.import_passphrase.is_empty() {
                app.identities.import_passphrase = " ".to_owned();
            }
            app.status = Some(
                "That key is passphrase protected. Enter its passphrase, then import again."
                    .to_owned(),
            );
        }
        Err(e) => app.status = Some(e.to_string()),
    }
}

fn generate(app: &mut App, kind: Kind) {
    let label = app.identities.label.trim().to_owned();
    let passphrase = app
        .identities
        .protect
        .then(|| SecretString::from(app.identities.passphrase.clone()));

    let result = agepony_core::vault::generate(
        &mut app.store,
        &mut app.book,
        &label,
        kind,
        passphrase.as_ref(),
    )
    .map(|e| {
        format!(
            "Created {} ({}) — its recipient is in your book, so you can encrypt to yourself",
            e.label,
            crate::app::kind_label(e.kind)
        )
    });
    app.save_book();

    if result.is_ok() {
        app.identities.label.clear();
        app.identities.passphrase.clear();
        app.identities.protect = false;
    }
    app.report(result);
}

fn import(app: &mut App) {
    let Some(source) = rfd::FileDialog::new().pick_file() else {
        return;
    };

    // Peek first so the passphrase field only appears when it is actually
    // needed, rather than asking everyone for a passphrase just in case.
    let needs_passphrase = std::fs::read(&source)
        .map(|b| agepony_core::identity::looks_encrypted(&b))
        .unwrap_or(false);

    if needs_passphrase && app.identities.import_passphrase.is_empty() {
        app.identities.import_passphrase = " ".to_owned();
        app.status = Some(
            "That identity file is passphrase protected. Enter its passphrase, then import again."
                .to_owned(),
        );
        return;
    }

    let source_passphrase = needs_passphrase
        .then(|| SecretString::from(app.identities.import_passphrase.trim().to_owned()));
    let passphrase = app
        .identities
        .protect
        .then(|| SecretString::from(app.identities.passphrase.clone()));

    let label = app.identities.label.trim().to_owned();
    let result = app
        .store
        .import(
            &label,
            &source,
            source_passphrase.as_ref(),
            passphrase.as_ref(),
        )
        .map(|e| format!("Imported {} ({})", e.label, crate::app::kind_label(e.kind)));

    if result.is_ok() {
        app.identities.label.clear();
        app.identities.passphrase.clear();
        app.identities.import_passphrase.clear();
        app.identities.protect = false;
    }
    app.report(result);
}

fn export(app: &mut App, id: &str, label: &str, encrypted: bool) {
    let suggested = if encrypted {
        format!("{label}.age")
    } else {
        format!("{label}.txt")
    };
    let Some(destination) = rfd::FileDialog::new().set_file_name(&suggested).save_file() else {
        return;
    };

    let result = app.store.export(id, &destination).map(|()| {
        if encrypted {
            format!("Exported {label}, still passphrase protected")
        } else {
            format!("Exported {label} — this file contains an unprotected secret key")
        }
    });
    app.report(result);
}
