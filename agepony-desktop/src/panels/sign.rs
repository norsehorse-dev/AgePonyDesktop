//! The Sign screen: sign files, verify files, and manage signing keys and
//! trusted signers.
//!
//! The desktop counterpart of Android's Sign tab (`ui/sign/`). Three sub-screens
//! behind a segmented control:
//!
//! - **Sign** — a detached SSHSIG (`<name>.sig`) over each chosen file, with a
//!   stored signing key.
//! - **Verify** — a file against its `.sig`, showing whether the signer is one
//!   you know (your own key or a trusted signer), cryptographically valid but
//!   unknown, or invalid.
//! - **Keys** — import OpenSSH signing keys, and manage the trusted-signers
//!   list (which round-trips through the OpenSSH `allowed_signers` format).

use crate::app::{App, SignMode, Trust, VerifyOutcome};
use crate::theme;
use agepony_core::signing;
use std::path::PathBuf;

/// Draw the screen.
pub fn show(app: &mut App, ui: &mut egui::Ui) {
    theme::screen_head(
        ui,
        "Sign",
        "Sign files with an SSH key, or verify a signature against the people you trust.",
        |_ui| {},
    );

    ui.push_id("sshsig-mode", |ui| {
        ui.set_max_width(360.0);
        let selected = match app.sign.mode {
            SignMode::Sign => 0,
            SignMode::Verify => 1,
        };
        if let Some(i) = theme::segmented(ui, &["Sign", "Verify"], selected) {
            app.sign.mode = if i == 1 {
                SignMode::Verify
            } else {
                SignMode::Sign
            };
        }
    });
    ui.add_space(theme::space::MD);

    match app.sign.mode {
        SignMode::Sign => sign_screen(app, ui),
        SignMode::Verify => verify_screen(app, ui),
    }
}

// -------------------------------------------------------------------- sign ---

fn sign_screen(app: &mut App, ui: &mut egui::Ui) {
    if app.signing_store.entries().is_empty() {
        theme::card(ui, |ui| {
            ui.weak(
                "You have no signing keys yet. Go to Keys and import an OpenSSH private key \
                 (ssh-ed25519 or ssh-rsa) to sign with.",
            );
        });
        return;
    }

    let mut run_files = false;
    let mut run_text = false;
    theme::card(ui, |ui| {
        theme::section(ui, "Signing key");
        let keys: Vec<(String, String, bool)> = app
            .signing_store
            .entries()
            .iter()
            .map(|e| {
                (
                    e.id.clone(),
                    format!("{} · {}", e.label, e.kind.label()),
                    e.encrypted,
                )
            })
            .collect();
        if app.sign.sign_key_id.is_none() {
            app.sign.sign_key_id = keys.first().map(|(id, _, _)| id.clone());
        }
        for (id, label, _) in &keys {
            let selected = app.sign.sign_key_id.as_deref() == Some(id);
            if ui.selectable_label(selected, label).clicked() {
                app.sign.sign_key_id = Some(id.clone());
            }
        }

        let needs_pass = app
            .sign
            .sign_key_id
            .as_deref()
            .and_then(|id| app.signing_store.get(id))
            .is_some_and(|e| e.encrypted);
        if needs_pass {
            ui.add_space(theme::space::SM);
            ui.horizontal(|ui| {
                ui.label("Passphrase for this key");
                ui.add(
                    egui::TextEdit::singleline(&mut app.sign.sign_passphrase)
                        .password(true)
                        .desired_width(240.0),
                );
            });
        }

        ui.add_space(theme::space::SM);
        theme::section(ui, "Namespace");
        if app.sign.sign_namespace.is_empty() {
            app.sign.sign_namespace = signing::NAMESPACE.to_owned();
        }
        ui.add(
            egui::TextEdit::singleline(&mut app.sign.sign_namespace)
                .hint_text(signing::NAMESPACE)
                .desired_width(280.0),
        );
        ui.weak(
            "Advanced. Leave as agepony for AgePony-to-AgePony signatures; change it \
             only to match another tool's ssh-keygen namespace.",
        );

        ui.add_space(theme::space::SM);
        let selected = usize::from(app.sign.sign_text_mode);
        let picked = ui
            .push_id("sign-filetext", |ui| theme::segmented(ui, &["Files", "Text"], selected))
            .inner;
        if let Some(i) = picked {
            app.sign.sign_text_mode = i == 1;
        }
        let key_ready = app.sign.sign_key_id.is_some();

        if app.sign.sign_text_mode {
            ui.add_space(theme::space::SM);
            theme::section(ui, "Text");
            ui.add(
                egui::TextEdit::multiline(&mut app.sign.sign_text)
                    .hint_text("Type or paste text to sign")
                    .desired_rows(6)
                    .desired_width(f32::INFINITY),
            );

            ui.add_space(theme::space::SM);
            let enabled = key_ready && !app.sign.sign_text.trim().is_empty();
            if theme::primary_button_enabled(ui, "Sign", enabled).clicked() {
                run_text = true;
            }

            if !app.sign.sign_text_output.is_empty() {
                ui.add_space(theme::space::SM);
                theme::section(ui, "Signature");
                ui.add(
                    egui::TextEdit::multiline(&mut app.sign.sign_text_output)
                        .desired_rows(6)
                        .desired_width(f32::INFINITY),
                );
                if theme::secondary_button(ui, "Copy").clicked() {
                    ui.ctx().copy_text(app.sign.sign_text_output.clone());
                    app.status = Some("Signature copied.".to_owned());
                }
            }
        } else {
            ui.add_space(theme::space::SM);
            theme::section(ui, "Files");
            if theme::secondary_button(ui, "Choose files…").clicked() {
                if let Some(files) = rfd::FileDialog::new().pick_files() {
                    app.sign.sign_files = files;
                }
            }
            for f in &app.sign.sign_files {
                ui.weak(f.display().to_string());
            }

            ui.add_space(theme::space::SM);
            let enabled = key_ready && !app.sign.sign_files.is_empty();
            if theme::primary_button_enabled(ui, "Sign", enabled).clicked() {
                run_files = true;
            }
        }
    });

    if run_files {
        run_sign(app);
    }
    if run_text {
        run_sign_text(app);
    }
}

fn run_sign_text(app: &mut App) {
    let Some(id) = app.sign.sign_key_id.clone() else {
        return;
    };
    let passphrase = (!app.sign.sign_passphrase.is_empty())
        .then(|| age::secrecy::SecretString::from(app.sign.sign_passphrase.clone()));
    let namespace = {
        let n = app.sign.sign_namespace.trim();
        if n.is_empty() {
            signing::NAMESPACE.to_owned()
        } else {
            n.to_owned()
        }
    };
    let message = app.sign.sign_text.as_bytes().to_vec();

    match app
        .signing_store
        .sign_with_namespace(&id, &message, &namespace, passphrase.as_ref())
    {
        Ok(armored) => {
            app.sign.sign_text_output = armored;
            app.status = Some("Signed. The signature is below, ready to copy.".to_owned());
        }
        Err(e) => {
            app.sign.sign_text_output.clear();
            app.status = Some(format!("Signing failed: {e}"));
        }
    }
}

fn run_sign(app: &mut App) {
    let Some(id) = app.sign.sign_key_id.clone() else {
        return;
    };
    let passphrase = (!app.sign.sign_passphrase.is_empty())
        .then(|| age::secrecy::SecretString::from(app.sign.sign_passphrase.clone()));
    let files = app.sign.sign_files.clone();
    let namespace = {
        let n = app.sign.sign_namespace.trim();
        if n.is_empty() {
            signing::NAMESPACE.to_owned()
        } else {
            n.to_owned()
        }
    };

    let mut ok = 0;
    let mut failed = 0;
    let mut last_err = None;
    for path in files {
        let message = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) => {
                failed += 1;
                last_err = Some(e.to_string());
                continue;
            }
        };
        match app
            .signing_store
            .sign_with_namespace(&id, &message, &namespace, passphrase.as_ref())
        {
            Ok(armored) => {
                let mut out = path.clone().into_os_string();
                out.push(".sig");
                let out = agepony_core::encrypt::unique_path(std::path::Path::new(&out));
                if let Err(e) = std::fs::write(&out, armored) {
                    failed += 1;
                    last_err = Some(e.to_string());
                } else {
                    ok += 1;
                }
            }
            Err(e) => {
                failed += 1;
                last_err = Some(e.to_string());
            }
        }
    }

    app.status = Some(match (ok, failed) {
        (n, 0) => format!("Signed {n} file(s). The .sig files are next to the originals."),
        (0, _) => format!(
            "Signing failed: {}",
            last_err.unwrap_or_else(|| "unknown error".to_owned())
        ),
        (n, f) => format!("Signed {n}, {f} failed ({})", last_err.unwrap_or_default()),
    });
}

// ------------------------------------------------------------------ verify ---

/// The trusted-signer picker on the Verify screen: leave all unchecked to
/// accept any trusted signer, or name who you expect signed (issue #5).
fn verify_signer_picker(app: &mut App, ui: &mut egui::Ui) {
    theme::section(ui, "Expected signer");
    if app.signers.is_empty() {
        ui.weak(
            "No trusted signers yet. Add them under Identities \u{203a} SSHSIG \u{203a} Signers, \
             then pick who you expect signed this.",
        );
        return;
    }
    ui.weak("Leave unchecked to accept any trusted signer, or pick who you expect signed this.");
    let signers: Vec<(String, String, String)> = app
        .signers
        .all()
        .iter()
        .map(|s| (s.id.clone(), s.name.clone(), s.key_type.clone()))
        .collect();
    for (id, name, key_type) in signers {
        let mut on = app.sign.verify_expect.contains(&id);
        if ui
            .checkbox(&mut on, format!("{name}  \u{b7}  {key_type}"))
            .changed()
        {
            if on {
                app.sign.verify_expect.insert(id);
            } else {
                app.sign.verify_expect.remove(&id);
            }
            app.sign.verify_result = None;
        }
    }
}

fn verify_screen(app: &mut App, ui: &mut egui::Ui) {
    let mut run_files = false;
    let mut run_text = false;
    theme::card(ui, |ui| {
        ui.add_space(theme::space::SM);
        let selected = usize::from(app.sign.verify_text_mode);
        let picked = ui
            .push_id("verify-filetext", |ui| theme::segmented(ui, &["Files", "Text"], selected))
            .inner;
        if let Some(i) = picked {
            app.sign.verify_text_mode = i == 1;
            app.sign.verify_result = None;
        }

        verify_signer_picker(app, ui);

        if app.sign.verify_text_mode {
            ui.add_space(theme::space::SM);
            theme::section(ui, "Text");
            if ui
                .add(
                    egui::TextEdit::multiline(&mut app.sign.verify_text)
                        .hint_text("The exact text that was signed")
                        .desired_rows(5)
                        .desired_width(f32::INFINITY),
                )
                .changed()
            {
                app.sign.verify_result = None;
            }

            theme::section(ui, "Signature");
            if ui
                .add(
                    egui::TextEdit::multiline(&mut app.sign.verify_sig_text)
                        .hint_text("-----BEGIN SSH SIGNATURE-----")
                        .desired_rows(5)
                        .desired_width(f32::INFINITY),
                )
                .changed()
            {
                app.sign.verify_result = None;
            }

            theme::section(ui, "Namespace");
            ui.add(
                egui::TextEdit::singleline(&mut app.sign.verify_namespace)
                    .hint_text("optional: an extra namespace to accept")
                    .desired_width(280.0),
            );

            ui.add_space(theme::space::SM);
            let enabled =
                !app.sign.verify_text.is_empty() && !app.sign.verify_sig_text.trim().is_empty();
            if theme::primary_button_enabled(ui, "Verify", enabled).clicked() {
                run_text = true;
            }
        } else {
            theme::section(ui, "File");
            ui.horizontal(|ui| {
                if theme::secondary_button(ui, "Choose file…").clicked() {
                    if let Some(f) = rfd::FileDialog::new().pick_file() {
                        app.sign.verify_file = Some(f);
                        app.sign.verify_result = None;
                    }
                }
                if let Some(f) = &app.sign.verify_file {
                    ui.weak(f.display().to_string());
                }
            });

            theme::section(ui, "Signature");
            ui.horizontal(|ui| {
                if theme::secondary_button(ui, "Choose .sig…").clicked() {
                    if let Some(f) = rfd::FileDialog::new().pick_file() {
                        app.sign.verify_sig = Some(f);
                        app.sign.verify_result = None;
                    }
                }
                if let Some(f) = &app.sign.verify_sig {
                    ui.weak(f.display().to_string());
                }
            });

            theme::section(ui, "Namespace");
            ui.add(
                egui::TextEdit::singleline(&mut app.sign.verify_namespace)
                    .hint_text("optional: an extra namespace to accept")
                    .desired_width(280.0),
            );
            ui.weak(
                "AgePony's own namespaces are always accepted. Add one here to verify a \
                 signature made under a different ssh-keygen namespace.",
            );

            ui.add_space(theme::space::SM);
            let enabled = app.sign.verify_file.is_some() && app.sign.verify_sig.is_some();
            if theme::primary_button_enabled(ui, "Verify", enabled).clicked() {
                run_files = true;
            }
        }
    });

    if run_files {
        run_verify(app);
    }
    if run_text {
        run_verify_text(app);
    }

    show_verdict(app, ui);
}

fn run_verify(app: &mut App) {
    let (Some(file), Some(sig_path)) = (app.sign.verify_file.clone(), app.sign.verify_sig.clone())
    else {
        return;
    };
    let message = match std::fs::read(&file) {
        Ok(b) => b,
        Err(e) => {
            app.status = Some(format!("Couldn't read the file: {e}"));
            return;
        }
    };
    let sig = match std::fs::read(&sig_path) {
        Ok(b) => b,
        Err(e) => {
            app.status = Some(format!("Couldn't read the signature: {e}"));
            return;
        }
    };
    apply_verdict(app, &sig, &message);
}

fn run_verify_text(app: &mut App) {
    let message = app.sign.verify_text.as_bytes().to_vec();
    let sig = app.sign.verify_sig_text.as_bytes().to_vec();
    apply_verdict(app, &sig, &message);
}

fn apply_verdict(app: &mut App, sig: &[u8], message: &[u8]) {
    let extra = app.sign.verify_namespace.trim().to_owned();
    let mut namespaces: Vec<&str> = Vec::new();
    if !extra.is_empty() {
        namespaces.push(extra.as_str());
    }
    namespaces.extend_from_slice(signing::ACCEPTED_NAMESPACES);

    match signing::verify_detached_any(sig, message, &namespaces) {
        Ok(verdict) => {
            let fingerprint = signing::fingerprint(&verdict.signer_wire).ok();
            let matched = app
                .signers
                .matching(&verdict.signer_wire)
                .map(|s| (s.id.clone(), s.name.clone()));
            let own_label = app
                .signing_store
                .entries()
                .iter()
                .find(|e| e.public_wire().as_deref() == Some(verdict.signer_wire.as_slice()))
                .map(|e| e.label.clone());
            let trust = if !verdict.valid {
                Trust::Invalid(
                    verdict
                        .reason
                        .clone()
                        .unwrap_or_else(|| "did not verify".to_owned()),
                )
            } else if !app.sign.verify_expect.is_empty() {
                match &matched {
                    Some((id, name)) if app.sign.verify_expect.contains(id) => {
                        Trust::Known(name.clone())
                    }
                    Some((_, name)) => Trust::Unexpected(name.clone()),
                    None => Trust::Unexpected(
                        own_label
                            .clone()
                            .map(|l| format!("{l} (your key)"))
                            .unwrap_or_else(|| "an unknown key".to_owned()),
                    ),
                }
            } else if let Some(label) = &own_label {
                Trust::Known(format!("{label} (your key)"))
            } else if let Some((_, name)) = &matched {
                Trust::Known(name.clone())
            } else {
                Trust::ValidUnknown(verdict.signer_wire.clone())
            };
            app.sign.trust_name.clear();
            app.sign.verify_result = Some(VerifyOutcome {
                trust,
                key_type: verdict.key_type,
                fingerprint,
            });
            app.status = None;
        }
        Err(e) => {
            app.sign.verify_result = None;
            app.status = Some(e.to_string());
        }
    }
}

fn show_verdict(app: &mut App, ui: &mut egui::Ui) {
    let Some(outcome) = app.sign.verify_result.clone() else {
        return;
    };
    ui.add_space(theme::space::MD);
    theme::card(ui, |ui| {
        match &outcome.trust {
            Trust::Known(name) => {
                ui.colored_label(theme::ACCENT, format!("✓ Trusted signer: {name}"));
            }
            Trust::ValidUnknown(_) => {
                ui.colored_label(
                    theme::PQ_BADGE,
                    "✓ Valid signature, but the signer is not in your trusted list.",
                );
            }
            Trust::Unexpected(who) => {
                ui.colored_label(
                    theme::PQ_BADGE,
                    format!("⚠ Signed by {who}, not one of the signers you selected."),
                );
            }
            Trust::Invalid(reason) => {
                ui.colored_label(theme::danger_ink(ui), format!("⚠ Not valid: {reason}"));
            }
        }
        ui.weak(format!("Key type: {}", outcome.key_type));
        if let Some(fp) = &outcome.fingerprint {
            ui.horizontal(|ui| {
                ui.weak("Fingerprint:");
                ui.add(egui::Label::new(egui::RichText::new(fp).monospace()).wrap());
            });
        }

        if let Trust::ValidUnknown(wire) = &outcome.trust {
            ui.add_space(theme::space::SM);
            ui.separator();
            ui.label("Trust this signer:");
            ui.horizontal(|ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut app.sign.trust_name)
                        .hint_text("A name for them, e.g. alice@example.com")
                        .desired_width(300.0),
                );
                let can = !app.sign.trust_name.trim().is_empty();
                if theme::primary_button_enabled(ui, "Trust", can).clicked() {
                    let name = app.sign.trust_name.trim().to_owned();
                    match app.signers.add_from_wire(
                        &name,
                        wire,
                        signing::signers::SignerSource::FromVerification,
                    ) {
                        Ok(_) => {
                            app.save_signers();
                            // Reflect the new trust immediately.
                            if let Some(r) = app.sign.verify_result.as_mut() {
                                r.trust = Trust::Known(name);
                            }
                            app.status = Some("Signer added to your trusted list.".to_owned());
                        }
                        Err(e) => app.status = Some(e.to_string()),
                    }
                }
            });
        }
    });
}

// -------------------------------------------------------------------- keys ---

/// The trusted-signers manager, shown under Identities > SSHSIG > Signers.
pub fn signers_screen(app: &mut App, ui: &mut egui::Ui) {
    theme::section(ui, "Trusted signers");
    theme::card(ui, |ui| {
        ui.label("People whose signatures you recognise. Add one by pasting their SSH public key.");
        ui.add_space(theme::space::SM);
        ui.horizontal(|ui| {
            ui.label("Name");
            ui.add(
                egui::TextEdit::singleline(&mut app.sign.new_signer_name)
                    .hint_text("e.g. alice@example.com")
                    .desired_width(220.0),
            );
        });
        ui.add(
            egui::TextEdit::multiline(&mut app.sign.new_signer_line)
                .hint_text("ssh-ed25519 AAAA… comment")
                .desired_rows(2)
                .desired_width(f32::INFINITY),
        );
        ui.horizontal(|ui| {
            let can = !app.sign.new_signer_name.trim().is_empty()
                && !app.sign.new_signer_line.trim().is_empty();
            if theme::primary_button_enabled(ui, "Add signer", can).clicked() {
                add_signer(app);
            }
            if theme::secondary_button(ui, "Import allowed_signers…").clicked() {
                import_allowed_signers(app);
            }
            if !app.signers.is_empty()
                && theme::secondary_button(ui, "Export allowed_signers…").clicked()
            {
                export_allowed_signers(app);
            }
        });
    });

    ui.add_space(theme::space::SM);
    let mut delete: Option<String> = None;
    for s in app.signers.all() {
        theme::card(ui, |ui| {
            ui.horizontal(|ui| {
                ui.strong(&s.name);
                theme::capsule(ui, &s.key_type, theme::ACCENT);
            });
            if let Some(fp) = s.fingerprint() {
                ui.add(egui::Label::new(egui::RichText::new(fp).monospace().size(11.0)).wrap());
            }
            if theme::secondary_button(ui, "Remove").clicked() {
                delete = Some(s.id.clone());
            }
        });
    }
    if let Some(id) = delete {
        app.signers.remove(&id);
        app.save_signers();
        app.status = Some("Signer removed.".to_owned());
    }
}

fn add_signer(app: &mut App) {
    let name = app.sign.new_signer_name.trim().to_owned();
    let line = app.sign.new_signer_line.trim().to_owned();
    match app
        .signers
        .add_from_public_line(&name, &line, signing::signers::SignerSource::PasteKey)
    {
        Ok(_) => {
            app.save_signers();
            app.sign.new_signer_name.clear();
            app.sign.new_signer_line.clear();
            app.status = Some("Signer added.".to_owned());
        }
        Err(e) => app.status = Some(e.to_string()),
    }
}

fn import_allowed_signers(app: &mut App) {
    let Some(path) = rfd::FileDialog::new().pick_file() else {
        return;
    };
    match std::fs::read_to_string(&path) {
        Ok(text) => {
            let n = app.signers.import_allowed_signers(&text);
            app.save_signers();
            app.status = Some(format!("Imported {n} signer(s)."));
        }
        Err(e) => app.status = Some(format!("Couldn't read the file: {e}")),
    }
}

fn export_allowed_signers(app: &mut App) {
    let Some(path): Option<PathBuf> = rfd::FileDialog::new()
        .set_file_name("allowed_signers")
        .save_file()
    else {
        return;
    };
    let body = app.signers.export_allowed_signers(false);
    match std::fs::write(&path, body) {
        Ok(()) => app.status = Some(format!("Exported to {}", path.display())),
        Err(e) => app.status = Some(format!("Couldn't write the file: {e}")),
    }
}
