//! The four panels. Each is a free function taking `&mut App` and `&mut Ui`.

pub mod decrypt;
pub mod encrypt;
pub mod identities;
pub mod recipients;

use crate::app::App;
use crate::{tasks, theme};
use std::path::PathBuf;

/// A file list with a remove button per row, plus a drop hint.
///
/// Shared because Encrypt and Decrypt want exactly the same affordance and
/// there is no reason for them to drift apart.
pub fn file_list(ui: &mut egui::Ui, files: &mut Vec<PathBuf>, verb: &str) {
    if files.is_empty() {
        // A dashed target rather than a sentence: this is the primary way files
        // get into the app, and it should look like somewhere you can put one.
        let (rect, _) =
            ui.allocate_exact_size(egui::vec2(ui.available_width(), 58.0), egui::Sense::hover());
        ui.painter().rect_stroke(
            rect,
            egui::CornerRadius::same(10),
            egui::Stroke::new(1.0, theme::TEAL_CORE.linear_multiply(0.35)),
            egui::StrokeKind::Inside,
        );
        let inner = egui::Rect::from_center_size(
            rect.center() - egui::vec2(rect.width() / 2.0 - 40.0, 0.0),
            egui::Vec2::splat(30.0),
        );
        theme::draw_mark(
            ui,
            inner,
            theme::TEAL_CORE.linear_multiply(0.35),
            ui.visuals().panel_fill,
        );
        ui.painter().text(
            egui::pos2(inner.right() + 14.0, rect.center().y),
            egui::Align2::LEFT_CENTER,
            format!("Drop files here to {verb}"),
            egui::FontId::proportional(13.5),
            ui.visuals().weak_text_color(),
        );
        return;
    }

    let mut remove = None;
    for (i, f) in files.iter().enumerate() {
        ui.horizontal(|ui| {
            // × (U+00D7), not ✕ (U+2715): Inter has the former and not the
            // latter, and a missing glyph renders as an empty box.
            if ui.small_button("×").clicked() {
                remove = Some(i);
            }
            let name = f.file_name().map_or_else(
                || f.display().to_string(),
                |n| n.to_string_lossy().into_owned(),
            );
            ui.label(name).on_hover_text(f.display().to_string());
        });
    }
    if let Some(i) = remove {
        files.remove(i);
    }
}

/// Progress and results for a running or finished batch.
pub fn job_view(app: &mut App, ui: &mut egui::Ui, encrypting: bool) {
    let job = if encrypting {
        app.encrypt.job.as_ref()
    } else {
        app.decrypt.job.as_ref()
    };
    let Some(job) = job else {
        return;
    };

    ui.add_space(6.0);

    if job.in_flight() {
        let label = match job.current.as_ref() {
            Some(p) => p
                .file_name()
                .map_or_else(String::new, |n| n.to_string_lossy().into_owned()),
            None => String::new(),
        };
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let pct = (job.progress * 100.0) as u32;
        let caption = if label.is_empty() {
            format!("{pct}%")
        } else {
            format!("{label} — {pct}%")
        };
        theme::progress(ui, job.progress, &caption);
        if job.total() > 1 {
            ui.weak(format!(
                "{} of {} done",
                job.done.len() + job.failed.len(),
                job.total()
            ));
        }
        if theme::secondary_button(ui, "Cancel").clicked() {
            job.cancel();
        }
        return;
    }

    ui.strong(job.summary());

    let outputs: Vec<PathBuf> = job.done.iter().map(|o| o.output.clone()).collect();
    let failures: Vec<(PathBuf, String)> = job.failed.clone();

    for output in &outputs {
        ui.horizontal(|ui| {
            let name = output.file_name().map_or_else(
                || output.display().to_string(),
                |n| n.to_string_lossy().into_owned(),
            );
            ui.label(name).on_hover_text(output.display().to_string());
            if theme::secondary_button(ui, "Show in folder").clicked() {
                tasks::reveal(output);
            }
        });
    }

    for (input, why) in &failures {
        let name = input.file_name().map_or_else(
            || input.display().to_string(),
            |n| n.to_string_lossy().into_owned(),
        );
        ui.colored_label(theme::DANGER, format!("{name}: {why}"));
    }
}
