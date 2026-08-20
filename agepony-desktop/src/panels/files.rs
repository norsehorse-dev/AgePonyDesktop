//! The Files screen: one destination for sealing and opening.
//!
//! Encrypt and Decrypt used to be separate tabs, which forced a decision — pick
//! a mode — before the app had been told anything. But the app can *read* what
//! a file is: [`agepony_core::decrypt::looks_like_age_file`] checks the header,
//! binary or armored, so a drop is grouped by fact rather than by mode or by
//! filename. An age file someone renamed still opens; a text file someone
//! called `notes.age` gets sealed rather than fed to the decryptor.
//!
//! A mixed drop shows both groups on one screen, each with its own options and
//! its own worker, and "Run all" runs whichever have work. One bad file fails
//! its own row; results are folded back into the rows when a job finishes, so
//! running again only touches what is still unsettled.

use crate::app::{App, DecryptSource, FileAction, QueuedFile};
use crate::{tasks, theme};
use age::secrecy::SecretString;
use std::path::{Path, PathBuf};

/// Add files to the queue, grouping each by its header. Returns how many were
/// new; a path already queued is left alone rather than duplicated.
pub fn add_paths(app: &mut App, paths: Vec<PathBuf>) -> usize {
    let mut added = 0;
    for path in paths {
        if app.files.queue.iter().any(|q| q.path == path) {
            continue;
        }
        let action = if agepony_core::decrypt::looks_like_age_file(&path) {
            FileAction::Open
        } else {
            FileAction::Seal
        };
        let size = std::fs::metadata(&path).ok().map(|m| m.len());
        app.files.queue.push(QueuedFile {
            path,
            action,
            size,
            outcome: None,
        });
        added += 1;
    }
    added
}

/// Draw the screen.
pub fn show(app: &mut App, ui: &mut egui::Ui) {
    let seal_count = count(app, FileAction::Seal);
    let open_count = count(app, FileAction::Open);

    let subtitle = if app.files.queue.is_empty() {
        "Drop anything in. AgePony reads each file to decide whether it is \
         sealing or opening — the name is not trusted."
            .to_owned()
    } else {
        let mut parts = Vec::new();
        if seal_count > 0 {
            parts.push(format!("{seal_count} to seal"));
        }
        if open_count > 0 {
            parts.push(format!("{open_count} to open"));
        }
        format!(
            "{} file{} queued: {}.",
            app.files.queue.len(),
            if app.files.queue.len() == 1 { "" } else { "s" },
            parts.join(", ")
        )
    };

    let busy = app.files.busy();
    let runnable = unsettled(app, FileAction::Seal) > 0 || unsettled(app, FileAction::Open) > 0;
    let mut want_run = false;
    let mut want_cancel = false;
    let mut want_clear = false;
    let mut want_choose = false;

    theme::screen_head(ui, "Files", &subtitle, |ui| {
        if busy {
            if theme::secondary_button(ui, "Cancel").clicked() {
                want_cancel = true;
            }
        } else {
            if theme::primary_button_enabled(ui, "Run all", runnable).clicked() {
                want_run = true;
            }
            if !app.files.queue.is_empty() && theme::secondary_button(ui, "Clear").clicked() {
                want_clear = true;
            }
            if theme::secondary_button(ui, "Choose files…").clicked() {
                want_choose = true;
            }
        }
    });

    if want_cancel {
        for job in [app.files.seal_job.as_ref(), app.files.open_job.as_ref()]
            .into_iter()
            .flatten()
        {
            job.cancel();
        }
    }
    if want_clear {
        app.files.queue.clear();
        app.files.seal_job = None;
        app.files.open_job = None;
        app.status = None;
    }
    if want_choose {
        app.choose_files();
    }
    if want_run {
        run_all(app, ui.ctx().clone());
    }

    if app.files.queue.is_empty() {
        let hot = ui.ctx().input(|i| !i.raw.hovered_files.is_empty());
        if theme::drop_zone(ui, hot) {
            app.choose_files();
        }
        ui.add_space(theme::space::MD);
        ui.vertical_centered(|ui| {
            ui.weak(format!(
                "{cmd}O to browse · {cmd}Enter to run",
                cmd = crate::app::command_symbol()
            ));
        });
        return;
    }

    if seal_count > 0 {
        group_label(ui, &format!("Seal · {seal_count}"));
        seal_options(app, ui);
        ui.add_space(theme::space::SM);
        rows(app, ui, FileAction::Seal);
        ui.add_space(theme::space::SECTION);
    }

    if open_count > 0 {
        group_label(ui, &format!("Open · {open_count}"));
        open_options(app, ui);
        ui.add_space(theme::space::SM);
        rows(app, ui, FileAction::Open);
    }
}

/// Start whichever groups have unsettled rows and are not already running.
///
/// The two groups are independent: a validation problem on one — no recipients
/// picked, say — stops that group and reports why, while the other still runs.
pub fn run_all(app: &mut App, ctx: egui::Context) {
    run_seal(app, &ctx);
    run_open(app, &ctx);
}

fn run_seal(app: &mut App, ctx: &egui::Context) {
    if app
        .files
        .seal_job
        .as_ref()
        .is_some_and(tasks::Running::in_flight)
    {
        return;
    }
    let inputs = unsettled_paths(app, FileAction::Seal);
    if inputs.is_empty() {
        return;
    }

    let lock = if app.files.use_passphrase {
        if app.files.passphrase.is_empty() {
            app.status = Some("Enter a passphrase first.".to_owned());
            return;
        }
        tasks::Lock::Passphrase(SecretString::from(app.files.passphrase.clone()))
    } else {
        let strings = collect_recipients(app);
        if strings.is_empty() {
            app.status = Some("Pick or paste at least one recipient first.".to_owned());
            return;
        }
        match agepony_core::recipient::parse_all(&strings) {
            Ok(recipients) => tasks::Lock::Recipients(recipients),
            Err(e) => {
                app.status = Some(e.to_string());
                return;
            }
        }
    };

    let repaint = {
        let ctx = ctx.clone();
        move || ctx.request_repaint()
    };
    app.status = None;

    // Bundling only applies to more than one file; with one it is a plain seal.
    let job = if app.files.bundle && inputs.len() > 1 {
        let dir = inputs
            .first()
            .and_then(|p| p.parent())
            .map_or_else(|| std::path::PathBuf::from("."), Path::to_path_buf);
        tasks::Job::EncryptBundle {
            inputs,
            lock,
            armor: app.files.armor,
            output: dir.join("bundle.tar.age"),
        }
    } else {
        tasks::Job::Encrypt {
            inputs,
            lock,
            armor: app.files.armor,
        }
    };
    app.files.seal_job = Some(tasks::spawn(job, repaint));
}

fn run_open(app: &mut App, ctx: &egui::Context) {
    if app
        .files
        .open_job
        .as_ref()
        .is_some_and(tasks::Running::in_flight)
    {
        return;
    }
    let inputs = unsettled_paths(app, FileAction::Open);
    if inputs.is_empty() {
        return;
    }

    let identity_passphrase = (!app.files.identity_passphrase.is_empty())
        .then(|| SecretString::from(app.files.identity_passphrase.clone()));

    let unlock = match app.files.source {
        DecryptSource::Passphrase => {
            if app.files.open_passphrase.is_empty() {
                app.status = Some("Enter the file's passphrase first.".to_owned());
                return;
            }
            tasks::Unlock::Passphrase(SecretString::from(app.files.open_passphrase.clone()))
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
            if app.files.identity_files.is_empty() {
                app.status = Some("Choose an identity file first.".to_owned());
                return;
            }
            tasks::Unlock::Identities {
                files: app.files.identity_files.clone(),
                passphrase: identity_passphrase,
            }
        }
    };

    let repaint = {
        let ctx = ctx.clone();
        move || ctx.request_repaint()
    };
    app.status = None;
    app.files.open_job = Some(tasks::spawn(
        tasks::Job::Decrypt { inputs, unlock },
        repaint,
    ));
}

// ---------------------------------------------------------------- pieces ---

fn group_label(ui: &mut egui::Ui, text: &str) {
    ui.horizontal(|ui| {
        ui.label(
            egui::RichText::new(text.to_uppercase())
                .font(theme::semibold(11.0))
                .color(ui.visuals().weak_text_color()),
        );
        let rect = egui::Rect::from_min_size(
            ui.cursor().min + egui::vec2(theme::space::SM, 8.0),
            egui::vec2(
                (ui.available_width() - theme::space::SM * 2.0).max(0.0),
                1.0,
            ),
        );
        ui.painter().rect_filled(
            rect,
            egui::CornerRadius::ZERO,
            ui.visuals().widgets.noninteractive.bg_stroke.color,
        );
    });
    ui.add_space(theme::space::SM);
}

fn seal_options(app: &mut App, ui: &mut egui::Ui) {
    theme::card(ui, |ui| {
        ui.horizontal(|ui| {
            ui.scope(|ui| {
                ui.set_max_width(260.0);
                let selected = usize::from(app.files.use_passphrase);
                if let Some(i) = theme::segmented(ui, &["Recipients", "Passphrase"], selected) {
                    app.files.use_passphrase = i == 1;
                }
            });
            ui.add_space(theme::space::LG);
            ui.checkbox(&mut app.files.armor, "ASCII armor");
            // Bundling only means something for more than one file.
            if count(app, FileAction::Seal) > 1 {
                ui.add_space(theme::space::LG);
                ui.checkbox(&mut app.files.bundle, "Bundle into one archive")
                    .on_hover_text("Pack all the files into a single .tar.age");
            }
        });
        ui.add_space(theme::space::SM);

        if app.files.use_passphrase {
            ui.add(
                egui::TextEdit::singleline(&mut app.files.passphrase)
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
            let mut ticked = app.files.picked.contains(&entry.name);
            ui.horizontal(|ui| {
                if ui.checkbox(&mut ticked, &entry.name).changed() {
                    if ticked {
                        app.files.picked.insert(entry.name.clone());
                    } else {
                        app.files.picked.remove(&entry.name);
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
    }

    ui.add_space(theme::space::TIGHT);
    ui.add(
        egui::TextEdit::multiline(&mut app.files.extra)
            .hint_text("Or paste recipients, one per line: age1… or age1pq… or ssh-ed25519 …")
            .desired_rows(2)
            .desired_width(f32::INFINITY),
    );

    // Say what will happen before the button is pressed, including the
    // mixed-recipient rule, which is otherwise a surprise at run time.
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

fn open_options(app: &mut App, ui: &mut egui::Ui) {
    theme::card(ui, |ui| {
        const SOURCES: [(DecryptSource, &str); 3] = [
            (DecryptSource::Active, "My identity"),
            (DecryptSource::File, "Identity file"),
            (DecryptSource::Passphrase, "Passphrase"),
        ];
        ui.scope(|ui| {
            ui.set_max_width(390.0);
            let selected = SOURCES
                .iter()
                .position(|(s, _)| *s == app.files.source)
                .unwrap_or(0);
            let labels: Vec<&str> = SOURCES.iter().map(|(_, l)| *l).collect();
            if let Some(i) = theme::segmented(ui, &labels, selected) {
                if let Some((source, _)) = SOURCES.get(i) {
                    app.files.source = *source;
                }
            }
        });
        ui.add_space(theme::space::SM);

        match app.files.source {
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
                            egui::TextEdit::singleline(&mut app.files.identity_passphrase)
                                .password(true)
                                .desired_width(240.0),
                        );
                    });
                }
            }
            DecryptSource::File => {
                if theme::secondary_button(ui, "Choose identity file…").clicked() {
                    if let Some(files) = rfd::FileDialog::new().pick_files() {
                        app.files.identity_files = files;
                    }
                }
                for f in &app.files.identity_files {
                    ui.weak(f.display().to_string());
                }
                let any_encrypted = app.files.identity_files.iter().any(|p| {
                    std::fs::read(p).is_ok_and(|b| agepony_core::identity::looks_encrypted(&b))
                });
                if any_encrypted {
                    ui.horizontal(|ui| {
                        ui.label("Passphrase for the identity file");
                        ui.add(
                            egui::TextEdit::singleline(&mut app.files.identity_passphrase)
                                .password(true)
                                .desired_width(240.0),
                        );
                    });
                }
            }
            DecryptSource::Passphrase => {
                ui.add(
                    egui::TextEdit::singleline(&mut app.files.open_passphrase)
                        .password(true)
                        .hint_text("Passphrase")
                        .desired_width(280.0),
                );
            }
        }
    });
}

fn rows(app: &mut App, ui: &mut egui::Ui, action: FileAction) {
    let job = match action {
        FileAction::Seal => app.files.seal_job.as_ref(),
        FileAction::Open => app.files.open_job.as_ref(),
    };
    let busy = job.is_some_and(tasks::Running::in_flight);

    let mut remove: Option<usize> = None;
    let mut reveal: Option<PathBuf> = None;

    for (i, row) in app
        .files
        .queue
        .iter()
        .enumerate()
        .filter(|(_, q)| q.action == action)
    {
        let name = row.path.file_name().map_or_else(
            || row.path.display().to_string(),
            |n| n.to_string_lossy().into_owned(),
        );
        let (state, detail) = row_presentation(row, job);
        let glyph = match action {
            FileAction::Seal => theme::icon::LOCK,
            FileAction::Open => theme::icon::LOCK_OPEN,
        };
        let revealable = matches!(row.outcome, Some(Ok(_)));

        let response = ui
            .push_id(("files-row", i), |ui| {
                theme::queue_row(ui, glyph, &name, &detail, state, revealable)
            })
            .inner;
        // Rows in a running group keep their ×: dismissing a Queued row cannot
        // unqueue it from the worker, which owns its input list, so during a
        // run the × is simply not drawn for rows the job will still reach.
        if response.dismissed && !busy {
            remove = Some(i);
        }
        if response.opened {
            if let Some(Ok(output)) = &row.outcome {
                reveal = Some(output.clone());
            }
        }
        ui.add_space(theme::space::SM);
    }

    if let Some(i) = remove {
        app.files.queue.remove(i);
    }
    if let Some(output) = reveal {
        tasks::reveal(&output);
    }
}

/// A row's display state and detail line, derived from its stored outcome and
/// whatever the group's job says about it right now.
fn row_presentation(row: &QueuedFile, job: Option<&tasks::Running>) -> (theme::RowState, String) {
    match &row.outcome {
        Some(Ok(output)) => {
            let name = output.file_name().map_or_else(
                || output.display().to_string(),
                |n| n.to_string_lossy().into_owned(),
            );
            (theme::RowState::Done, format!("→ {name}"))
        }
        Some(Err(why)) => (theme::RowState::Failed, why.clone()),
        None => {
            if let Some(job) = job {
                if job.current.as_deref() == Some(row.path.as_path()) {
                    return (
                        theme::RowState::Running(job.file_progress),
                        pending_detail(row),
                    );
                }
                if let Some(done) = job.done.iter().find(|o| o.input == row.path) {
                    let name = done.output.file_name().map_or_else(
                        || done.output.display().to_string(),
                        |n| n.to_string_lossy().into_owned(),
                    );
                    return (theme::RowState::Done, format!("→ {name}"));
                }
                if let Some((_, why)) = job.failed.iter().find(|(p, _)| *p == row.path) {
                    return (theme::RowState::Failed, why.clone());
                }
            }
            (theme::RowState::Queued, pending_detail(row))
        }
    }
}

/// "4.2 MB → report.pdf.age", before anything has run.
fn pending_detail(row: &QueuedFile) -> String {
    let target = match row.action {
        FileAction::Seal => {
            let mut n = row.path.file_name().map_or_else(
                || row.path.display().to_string(),
                |n| n.to_string_lossy().into_owned(),
            );
            n.push_str(".age");
            n
        }
        FileAction::Open => {
            let out = agepony_core::decrypt::default_output_path(&row.path);
            out.file_name().map_or_else(
                || out.display().to_string(),
                |n| n.to_string_lossy().into_owned(),
            )
        }
    };
    match row.size {
        Some(bytes) => format!("{} → {target}", human_size(bytes)),
        None => format!("→ {target}"),
    }
}

/// Bytes as people read them. Binary units, one decimal above KB.
#[must_use]
pub fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    #[allow(clippy::cast_precision_loss)]
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.1} {}", UNITS[unit])
}

fn count(app: &App, action: FileAction) -> usize {
    app.files
        .queue
        .iter()
        .filter(|q| q.action == action)
        .count()
}

fn unsettled(app: &App, action: FileAction) -> usize {
    app.files
        .queue
        .iter()
        .filter(|q| q.action == action && q.outcome.is_none())
        .count()
}

fn unsettled_paths(app: &App, action: FileAction) -> Vec<PathBuf> {
    app.files
        .queue
        .iter()
        .filter(|q| q.action == action && q.outcome.is_none())
        .map(|q| q.path.clone())
        .collect()
}

fn collect_recipients(app: &App) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for name in &app.files.picked {
        if let Some(entry) = app.book.entries.iter().find(|e| &e.name == name) {
            out.push(entry.recipient.clone());
        }
    }
    out.extend(
        app.files
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_read_like_a_person_wrote_them() {
        assert_eq!(human_size(0), "0 B");
        assert_eq!(human_size(1023), "1023 B");
        assert_eq!(human_size(1024), "1.0 KiB");
        assert_eq!(human_size(4_400_000), "4.2 MiB");
        assert_eq!(human_size(1_500_000_000), "1.4 GiB");
    }

    #[test]
    fn the_pending_detail_states_the_output_before_anything_runs() {
        let seal = QueuedFile {
            path: PathBuf::from("/tmp/report.pdf"),
            action: FileAction::Seal,
            size: Some(4_400_000),
            outcome: None,
        };
        assert_eq!(pending_detail(&seal), "4.2 MiB → report.pdf.age");

        let open = QueuedFile {
            path: PathBuf::from("/tmp/report.pdf.age"),
            action: FileAction::Open,
            size: None,
            outcome: None,
        };
        assert_eq!(pending_detail(&open), "→ report.pdf");
    }
}
