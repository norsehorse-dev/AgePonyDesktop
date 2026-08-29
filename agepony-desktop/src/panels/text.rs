//! The Text screen: encrypt and decrypt pasted text, not files.
//!
//! The counterpart to Android's Text tab. The file path never holds plaintext —
//! it streams straight to disk — but text mode necessarily shows a note on
//! screen, so this screen is the one deliberate place a secret lives in the UI.
//! Both the input and the decrypted output are cleared on Escape, on leaving the
//! tab (`App::wipe_text_plaintext_off_tab`), and by the Clear button, and the
//! decrypted output is held in a `Zeroizing` buffer (`app::TextOutput`).
//!
//! Text is small, so unlike Files this runs synchronously on the UI thread
//! rather than through the worker.

use crate::app::{App, DecryptSource, TextOutput};
use crate::theme;
use age::secrecy::SecretString;

/// Draw the screen.
pub fn show(app: &mut App, ui: &mut egui::Ui) {
    let subtitle = if app.text.decrypt {
        "Paste an armored age message and open it with an identity or a passphrase."
    } else {
        "Type or paste text and seal it to recipients or a passphrase. \
         The output is armored, ready to copy."
    };

    let mut want_clear = false;
    let has_content = !app.text.input.is_empty() || app.text.output.as_str().is_some();
    theme::screen_head(ui, "Text", subtitle, |ui| {
        if has_content && theme::secondary_button(ui, "Clear").clicked() {
            want_clear = true;
        }
    });
    if want_clear {
        app.text.clear_secrets();
    }

    // Encrypt vs decrypt is chosen by the AGE rail tab now, not here; this
    // screen reads app.text.decrypt, which the tab sets (issue #5).

    if app.text.decrypt {
        decrypt_options(app, ui);
    } else {
        encrypt_options(app, ui);
    }
    ui.add_space(theme::space::MD);

    theme::section(ui, if app.text.decrypt { "Message" } else { "Text" });
    ui.add(
        egui::TextEdit::multiline(&mut app.text.input)
            .hint_text(if app.text.decrypt {
                "-----BEGIN AGE ENCRYPTED FILE-----"
            } else {
                "Type or paste text to encrypt"
            })
            .desired_rows(6)
            .desired_width(f32::INFINITY),
    );
    ui.add_space(theme::space::SM);

    let verb = if app.text.decrypt {
        "Decrypt"
    } else {
        "Encrypt"
    };
    let enabled = !app.text.input.trim().is_empty();
    if theme::primary_button_enabled(ui, verb, enabled).clicked() {
        run(app);
    }

    output(app, ui);
}

/// Perform the current operation. Shared by the button and `⌘Enter`.
pub fn run(app: &mut App) {
    if app.text.decrypt {
        run_decrypt(app);
    } else {
        run_encrypt(app);
    }
}

// --------------------------------------------------------------- encrypt ---

fn encrypt_options(app: &mut App, ui: &mut egui::Ui) {
    theme::card(ui, |ui| {
        ui.scope(|ui| {
            ui.set_max_width(260.0);
            let selected = usize::from(app.text.use_passphrase);
            if let Some(i) = theme::segmented(ui, &["Recipients", "Passphrase"], selected) {
                app.text.use_passphrase = i == 1;
            }
        });
        ui.add_space(theme::space::SM);

        if app.text.use_passphrase {
            ui.add(
                egui::TextEdit::singleline(&mut app.text.passphrase)
                    .password(true)
                    .hint_text("Passphrase")
                    .desired_width(280.0),
            );
        } else {
            recipient_picker(app, ui);
        }
    });
}

fn recipient_picker(app: &mut App, ui: &mut egui::Ui) {
    if app.book.entries.is_empty() {
        ui.weak(
            "The recipient book is empty. Generate an identity, or add recipients \
             on the Recipients tab, or paste one below.",
        );
    } else {
        let entries: Vec<_> = app.book.sorted().into_iter().cloned().collect();
        for entry in entries {
            let mut ticked = app.text.picked.contains(&entry.name);
            ui.horizontal(|ui| {
                if ui.checkbox(&mut ticked, &entry.name).changed() {
                    if ticked {
                        app.text.picked.insert(entry.name.clone());
                    } else {
                        app.text.picked.remove(&entry.name);
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
            });
        }
    }

    ui.add_space(theme::space::TIGHT);
    ui.add(
        egui::TextEdit::multiline(&mut app.text.extra)
            .hint_text("Or paste recipients, one per line: age1… or age1pq… or ssh-ed25519 …")
            .desired_rows(2)
            .desired_width(f32::INFINITY),
    );

    let strings = collect_recipients(app);
    if strings.is_empty() {
        ui.weak("No recipients selected.");
    } else {
        match agepony_core::recipient::parse_all(&strings) {
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
                ui.colored_label(theme::danger_ink(ui), e.to_string());
            }
        }
    }
}

fn run_encrypt(app: &mut App) {
    let input = app.text.input.clone();

    let result = if app.text.use_passphrase {
        if app.text.passphrase.is_empty() {
            app.status = Some("Enter a passphrase first.".to_owned());
            return;
        }
        agepony_core::encrypt::encrypt_bytes(
            input.as_bytes(),
            agepony_core::encrypt::To::Passphrase(SecretString::from(app.text.passphrase.clone())),
            true,
        )
    } else {
        let strings = collect_recipients(app);
        if strings.is_empty() {
            app.status = Some("Pick or paste at least one recipient first.".to_owned());
            return;
        }
        match agepony_core::recipient::parse_all(&strings) {
            Ok(parsed) => agepony_core::encrypt::encrypt_bytes(
                input.as_bytes(),
                agepony_core::encrypt::To::Recipients(&parsed),
                true,
            ),
            Err(e) => {
                app.status = Some(e.to_string());
                return;
            }
        }
    };

    match result {
        // Armored output is ASCII by construction, so this never loses data.
        Ok(bytes) => match String::from_utf8(bytes) {
            Ok(s) => {
                app.text.output = TextOutput::Ciphertext(s);
                app.status = Some("Encrypted. Copy the armored text below.".to_owned());
            }
            Err(_) => app.status = Some("Encryption produced non-text output.".to_owned()),
        },
        Err(e) => app.status = Some(e.to_string()),
    }
}

// --------------------------------------------------------------- decrypt ---

fn decrypt_options(app: &mut App, ui: &mut egui::Ui) {
    theme::card(ui, |ui| {
        const SOURCES: [(DecryptSource, &str); 2] = [
            (DecryptSource::Active, "My identity"),
            (DecryptSource::Passphrase, "Passphrase"),
        ];
        // Text mode offers the two common sources; an identity file is a Files
        // affair. Anything other than these two falls back to the active one.
        if app.text.source == DecryptSource::File {
            app.text.source = DecryptSource::Active;
        }
        ui.scope(|ui| {
            ui.set_max_width(300.0);
            let selected = SOURCES
                .iter()
                .position(|(s, _)| *s == app.text.source)
                .unwrap_or(0);
            let labels: Vec<&str> = SOURCES.iter().map(|(_, l)| *l).collect();
            if let Some(i) = theme::segmented(ui, &labels, selected) {
                if let Some((source, _)) = SOURCES.get(i) {
                    app.text.source = *source;
                }
            }
        });
        ui.add_space(theme::space::SM);

        match app.text.source {
            DecryptSource::Active => {
                let Some(entry) = app.store.active().cloned() else {
                    ui.colored_label(
                        theme::danger_ink(ui),
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
                            egui::TextEdit::singleline(&mut app.text.identity_passphrase)
                                .password(true)
                                .desired_width(240.0),
                        );
                    });
                }
            }
            DecryptSource::Passphrase | DecryptSource::File => {
                ui.add(
                    egui::TextEdit::singleline(&mut app.text.open_passphrase)
                        .password(true)
                        .hint_text("Passphrase")
                        .desired_width(280.0),
                );
            }
        }
    });
}

fn run_decrypt(app: &mut App) {
    let input = app.text.input.clone();
    let bytes = input.as_bytes();

    let identity_passphrase = (!app.text.identity_passphrase.is_empty())
        .then(|| SecretString::from(app.text.identity_passphrase.clone()));

    let result = match app.text.source {
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
            let path = app.store.path_for(&entry);
            match agepony_core::identity::load_file_maybe_encrypted(
                &path,
                identity_passphrase.as_ref(),
            ) {
                Ok(ids) => agepony_core::decrypt::decrypt_bytes(
                    bytes,
                    agepony_core::decrypt::With::Identities(&ids),
                ),
                Err(e) => {
                    app.status = Some(e.to_string());
                    return;
                }
            }
        }
        DecryptSource::Passphrase | DecryptSource::File => {
            if app.text.open_passphrase.is_empty() {
                app.status = Some("Enter the message's passphrase first.".to_owned());
                return;
            }
            agepony_core::decrypt::decrypt_bytes(
                bytes,
                agepony_core::decrypt::With::Passphrase(SecretString::from(
                    app.text.open_passphrase.clone(),
                )),
            )
        }
    };

    match result {
        Ok(plain) => match std::str::from_utf8(&plain) {
            Ok(s) => {
                app.text.output = TextOutput::Plaintext(zeroize::Zeroizing::new(s.to_owned()));
                app.status = Some("Decrypted.".to_owned());
            }
            Err(_) => {
                app.status =
                    Some("The message decrypted, but its contents are not text.".to_owned());
            }
        },
        Err(e) => app.status = Some(e.to_string()),
    }
}

// ---------------------------------------------------------------- output ---

fn output(app: &mut App, ui: &mut egui::Ui) {
    if app.text.output.as_str().is_none() {
        return;
    }
    ui.add_space(theme::space::SECTION);

    let is_plaintext = app.text.output.is_plaintext();
    theme::section(
        ui,
        if is_plaintext {
            "Decrypted text"
        } else {
            "Armored ciphertext"
        },
    );
    if is_plaintext {
        ui.weak("Shown here only — cleared when you leave this screen or press Escape.");
        ui.add_space(theme::space::TIGHT);
    }

    // Bind the read-only editor to the real buffer so the plaintext is not
    // copied into a second, non-zeroizing string that would outlive it.
    match &mut app.text.output {
        TextOutput::Ciphertext(s) => {
            ui.add(
                egui::TextEdit::multiline(s)
                    .interactive(false)
                    .code_editor()
                    .desired_rows(6)
                    .desired_width(f32::INFINITY),
            );
        }
        TextOutput::Plaintext(z) => {
            let s: &mut String = z;
            ui.add(
                egui::TextEdit::multiline(s)
                    .interactive(false)
                    .desired_rows(6)
                    .desired_width(f32::INFINITY),
            );
        }
        TextOutput::Empty => {}
    }

    ui.add_space(theme::space::SM);
    if theme::secondary_button(ui, "Copy").clicked() {
        if let Some(s) = app.text.output.as_str() {
            ui.ctx().copy_text(s.to_owned());
            app.status = Some("Copied to the clipboard.".to_owned());
        }
    }
}

// ----------------------------------------------------------------- shared ---

fn collect_recipients(app: &App) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for name in &app.text.picked {
        if let Some(entry) = app.book.entries.iter().find(|e| &e.name == name) {
            out.push(entry.recipient.clone());
        }
    }
    out.extend(
        app.text
            .extra
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(str::to_owned),
    );
    out.sort();
    out.dedup();
    out
}
