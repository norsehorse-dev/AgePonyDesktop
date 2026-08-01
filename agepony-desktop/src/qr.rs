//! QR codes for the porting flow.
//!
//! # Why the recipient is uppercased
//!
//! Bech32 is case-insensitive, and QR has an *alphanumeric* mode covering
//! `0-9 A-Z` and a few symbols that packs 5.5 bits per character against byte
//! mode's 8. An uppercase age recipient is pure `A-Z0-9`, so it qualifies.
//!
//! That is not a micro-optimisation here. Measured on a real post-quantum
//! recipient — 1960 characters, because the hybrid public key is 1216 bytes:
//!
//! | | QR version | modules |
//! |---|---|---|
//! | as-is, byte mode | 33 | 149 × 149 |
//! | uppercased, alphanumeric | 26 | 121 × 121 |
//!
//! Two whole versions, for free, on the one case where it matters. A classic
//! `age1…` recipient is 62 characters and lands at version 3 either way.
//!
//! A 121-module code is still dense. [`Rendered::is_dense`] says so, and the
//! panel offers saving the recipient to a file as the alternative.

use egui::{Color32, ColorImage, Context, TextureHandle, TextureOptions};

/// A QR code ready to draw.
pub struct Rendered {
    /// The texture, one pixel per module plus a quiet zone.
    pub texture: TextureHandle,
    /// Modules across, excluding the quiet zone.
    pub modules: usize,
    /// The exact string encoded — uppercased, so it can be shown as the
    /// scanned value rather than something subtly different.
    pub encoded: String,
}

impl Rendered {
    /// Whether this code is dense enough that scanning may be fiddly.
    ///
    /// Version 10 is 57 modules; past roughly that, a phone needs the code
    /// displayed large and held steady.
    #[must_use]
    pub fn is_dense(&self) -> bool {
        self.modules > 57
    }

    /// A sensible on-screen size in points: enough pixels per module to scan.
    #[must_use]
    pub fn preferred_size(&self) -> f32 {
        // Roughly 3 points per module, clamped so a tiny code is not enormous
        // and a huge one still fits a window.
        #[allow(clippy::cast_precision_loss)]
        let ideal = self.modules as f32 * 3.0;
        ideal.clamp(180.0, 460.0)
    }
}

/// Encode `text` as a QR code and upload it as a texture.
///
/// Returns `None` if the string is too long for any QR version, which for age
/// recipients cannot happen — the largest is ~1960 characters against a
/// 4296-character alphanumeric ceiling — but is not worth a panic.
#[must_use]
pub fn render(ctx: &Context, name: &str, text: &str) -> Option<Rendered> {
    // Uppercase to reach alphanumeric mode. Safe: Bech32 decoding is
    // case-insensitive, and `agepony_core::recipient::parse` accepts either
    // case precisely so this round-trips.
    let encoded = text.to_uppercase();

    let code =
        qrcode::QrCode::with_error_correction_level(encoded.as_bytes(), qrcode::EcLevel::L).ok()?;
    let modules = code.width();
    let colors = code.to_colors();

    // The quiet zone is part of the spec, not decoration: scanners need four
    // clear modules of margin to find the code at all.
    const QUIET: usize = 4;
    let side = modules + QUIET * 2;

    let mut pixels = vec![Color32::WHITE; side * side];
    for (i, color) in colors.iter().enumerate() {
        if matches!(color, qrcode::Color::Dark) {
            let (x, y) = (i % modules + QUIET, i / modules + QUIET);
            if let Some(px) = pixels.get_mut(y * side + x) {
                *px = Color32::BLACK;
            }
        }
    }

    let image = ColorImage {
        size: [side, side],
        pixels,
        ..Default::default()
    };

    // NEAREST, or the scaled-up code turns into a blur no camera can read.
    let texture = ctx.load_texture(name, image, TextureOptions::NEAREST);

    Some(Rendered {
        texture,
        modules,
        encoded,
    })
}
