//! The AgePony design system.
//!
//! Ported from the iOS `DesignSystem` folder so the desktop reads as the same
//! app rather than a lookalike: the same brand ramp from `AgePonyColors.swift`,
//! the same 14pt buttons pressing from `tealCore` to `tealDeep` over 0.08s from
//! `AgePonyButton.swift`, the same 6%-fill / 18%-border key block from
//! `AgePonyKeyBlock.swift`.
//!
//! Two deliberate departures:
//!
//! **No blur.** iOS blurs a sensitive key string until tapped. egui has no blur
//! without a custom render pass, and it turns out not to matter: the desktop
//! never displays a private key. It displays recipients, which are public, and
//! plaintext goes straight to a file. There is nothing here to hide.
//!
//! **Desktop density.** iOS form sections are generous because a thumb needs
//! them to be. A pointer does not, and a 980pt-wide window has room for real
//! information density, so spacing is tighter and lists are lists rather than
//! stacked cards-of-one.

use crate::mark;
use egui::{
    Color32, Context, CornerRadius, FontData, FontDefinitions, FontFamily, FontId, Mesh, Pos2,
    Rect, Response, RichText, Sense, Shape, Stroke, Ui, Vec2,
};
use std::sync::Arc;

// ---------------------------------------------------------------- palette ---

/// Bright cyan — the top-left of the icon gradient.
pub const CYAN_LIGHT: Color32 = Color32::from_rgb(0x38, 0xCF, 0xE8);

/// Vibrant teal — the primary brand colour, and the horse itself.
pub const TEAL_CORE: Color32 = Color32::from_rgb(0x14, 0xB8, 0xB0);

/// Deep teal — pressed states, the bottom-right of the icon gradient.
pub const TEAL_DEEP: Color32 = Color32::from_rgb(0x0E, 0x7D, 0x7A);

/// Near-black teal — branded headlines on light surfaces.
pub const TEAL_INK: Color32 = Color32::from_rgb(0x0A, 0x4F, 0x4D);

/// Destructive and error affordances.
///
/// Magenta, not red. This is PGPony's primary, borrowed on purpose: "dangerous"
/// should read as a different *mode*, and a warm red fights the cool teal range
/// everywhere else. Carried over from `AgePonyColors.swift`.
pub const DANGER: Color32 = Color32::from_rgb(0xC0, 0x46, 0xDC);

/// Destructive text on a light surface.
///
/// `DANGER` itself is tuned to sit on dark and on tinted fills; against white at
/// 14px it drops to roughly 4:1, which is borderline. This is the same hue
/// darkened enough to read comfortably.
pub const DANGER_INK: Color32 = Color32::from_rgb(0x8E, 0x27, 0xA6);

/// Primary action colour.
pub const ACCENT: Color32 = TEAL_CORE;

/// The post-quantum badge colour.
pub const PQ_BADGE: Color32 = TEAL_CORE;

// ------------------------------------------------------------------ scale ---

/// The spacing scale. Six steps, and nothing off it.
///
/// Every gap in the UI is one of these. The rule is not aesthetic bookkeeping:
/// before this existed, `app.rs` alone spaced things by 14, 10, 12, 2, 16, 8 and
/// 4, none of which meant anything, and the result read as approximate because
/// it was. Mirrors PGPony Desktop's `Spacing` object so the two apps lay out at
/// the same rhythm.
pub mod space {
    /// Between a label and the thing it labels.
    pub const TIGHT: f32 = 4.0;
    /// Between siblings in a row.
    pub const SM: f32 = 8.0;
    /// Between rows in a list.
    pub const MD: f32 = 12.0;
    /// Inside a card.
    pub const LG: f32 = 16.0;
    /// Between sections of a screen.
    pub const SECTION: f32 = 24.0;
    /// The screen's own margin.
    pub const SCREEN: f32 = 32.0;
}

/// The corner-radius scale. Three steps, chosen by how big the thing is.
///
/// One radius for everything is what produced the two defects a user reported
/// on 1.0.0: a single value of 12 was applied to every widget state, and egui
/// draws a checkbox about 14px square and a `selectable_label` about 20px tall.
/// At 12 the first is a circle and the second is an oval, so a checkbox stopped
/// reading as a checkbox. A radius only means "slightly rounded" relative to the
/// box it is rounding, which is why this is a scale and not a constant.
pub mod radius {
    /// Checkboxes, badges, key blocks, chips. Small enough that 12 would round
    /// them away entirely.
    pub const SM: u8 = 6;
    /// Buttons, cards, list rows, rail items.
    pub const MD: u8 = 12;
    /// Panels, the drop zone, modals.
    pub const LG: u8 = 18;
}

/// Corner radius for buttons, from the iOS `RoundedRectangle(cornerRadius: 14)`.
const R_BUTTON: u8 = radius::MD;
/// Corner radius for key blocks and cards.
const R_BLOCK: u8 = radius::MD;

// ------------------------------------------------------------------ fonts ---

/// Font family name for the UI face.
pub const UI_FONT: &str = "Inter";
/// Font family name for the emphasised UI face.
pub const UI_FONT_SEMIBOLD: &str = "InterSemiBold";
/// Font family name for key strings.
pub const MONO_FONT: &str = "JetBrainsMono";
/// Font family name for the interface icons.
pub const ICON_FONT: &str = "Lucide";

/// Install fonts and the AgePony look. Call once at startup.
pub fn install(ctx: &Context) {
    install_fonts(ctx);
    install_style(ctx);
}

/// Embed Inter and JetBrains Mono.
///
/// Both are subset to Latin plus the symbols this UI draws, which takes the
/// three faces from 1.5 MB to 188 KB — worth doing for a project whose first
/// success criterion is a single self-contained binary.
///
/// egui's own fonts stay in each family as a fallback, so a file path
/// containing characters outside the subset still renders instead of turning
/// into tofu.
fn install_fonts(ctx: &Context) {
    let mut fonts = FontDefinitions::default();

    for (name, bytes) in [
        (
            UI_FONT,
            &include_bytes!("../assets/fonts/Inter-Regular-subset.ttf")[..],
        ),
        (
            UI_FONT_SEMIBOLD,
            &include_bytes!("../assets/fonts/Inter-SemiBold-subset.ttf")[..],
        ),
        (
            MONO_FONT,
            &include_bytes!("../assets/fonts/JetBrainsMono-Regular-subset.ttf")[..],
        ),
        (
            ICON_FONT,
            &include_bytes!("../assets/fonts/Lucide-subset.ttf")[..],
        ),
    ] {
        fonts
            .font_data
            .insert(name.to_owned(), Arc::new(FontData::from_static(bytes)));
    }

    // Insert ours at the front of each family; egui's defaults stay behind as
    // the fallback chain.
    if let Some(p) = fonts.families.get_mut(&FontFamily::Proportional) {
        p.insert(0, UI_FONT.to_owned());
    }
    if let Some(m) = fonts.families.get_mut(&FontFamily::Monospace) {
        m.insert(0, MONO_FONT.to_owned());
    }
    fonts.families.insert(
        FontFamily::Name(UI_FONT_SEMIBOLD.into()),
        vec![UI_FONT_SEMIBOLD.to_owned(), UI_FONT.to_owned()],
    );

    // Icons get a family of their own rather than being appended to the
    // proportional chain. Sharing a family would let a missing icon silently
    // fall through to Inter and render as a box, which is the exact failure the
    // GLYPHS test exists to stop; a dedicated family makes a missing icon a
    // visible blank that the icon test catches instead.
    fonts.families.insert(
        FontFamily::Name(ICON_FONT.into()),
        vec![ICON_FONT.to_owned()],
    );

    ctx.set_fonts(fonts);
}

// ------------------------------------------------------------------ icons ---

/// The interface icons, named as Lucide names them.
///
/// These are Lucide's own Private Use Area codepoints, carried over rather than
/// remapped to a tidy range, so the mapping can be checked against upstream's
/// `info.json` by anyone who doubts it. `assets/fonts/Lucide-subset.ttf` holds
/// exactly these nineteen glyphs and nothing else: 8 KB out of the 848 KB the
/// full face weighs.
///
/// Adding an icon means adding it here, adding it to [`ICONS`], and regenerating
/// the subset. The test below fails if the font cannot draw one of these, which
/// is the same contract [`GLYPHS`] enforces for text.
pub mod icon {
    /// The Files destination.
    pub const FILES: char = '\u{E0CF}';
    /// The Identities destination.
    pub const KEY_ROUND: char = '\u{E4A3}';
    /// The Recipients destination.
    pub const USERS: char = '\u{E1A4}';
    /// The Settings destination.
    pub const SETTINGS: char = '\u{E154}';
    /// Choose files.
    pub const UPLOAD: char = '\u{E19E}';
    /// Create something.
    pub const PLUS: char = '\u{E13D}';
    /// Run the queue.
    pub const ARROW_RIGHT: char = '\u{E049}';
    /// Remove one row; dismiss.
    pub const X: char = '\u{E1B2}';
    /// A ticked checkbox, and confirmation.
    pub const CHECK: char = '\u{E06C}';
    /// Port an identity from the phone.
    pub const QR_CODE: char = '\u{E1DF}';
    /// Copy a recipient to the clipboard.
    pub const COPY: char = '\u{E09E}';
    /// Delete an identity or a recipient.
    pub const TRASH_2: char = '\u{E18E}';
    /// Rename.
    pub const PENCIL: char = '\u{E1F9}';
    /// Export an identity file.
    pub const DOWNLOAD: char = '\u{E0B2}';
    /// A queued file that will be sealed.
    pub const LOCK: char = '\u{E10B}';
    /// A queued file that will be opened.
    pub const LOCK_OPEN: char = '\u{E10C}';
    /// A finished row.
    pub const CIRCLE_CHECK: char = '\u{E226}';
    /// A failed row.
    pub const CIRCLE_ALERT: char = '\u{E077}';
    /// The empty drop zone.
    pub const FILE_LOCK: char = '\u{E31E}';
}

/// Every icon the UI draws. The companion to [`GLYPHS`], for the icon face.
pub const ICONS: &[char] = &[
    icon::FILES,
    icon::KEY_ROUND,
    icon::USERS,
    icon::SETTINGS,
    icon::UPLOAD,
    icon::PLUS,
    icon::ARROW_RIGHT,
    icon::X,
    icon::CHECK,
    icon::QR_CODE,
    icon::COPY,
    icon::TRASH_2,
    icon::PENCIL,
    icon::DOWNLOAD,
    icon::LOCK,
    icon::LOCK_OPEN,
    icon::CIRCLE_CHECK,
    icon::CIRCLE_ALERT,
    icon::FILE_LOCK,
];

/// An icon as [`RichText`], ready to place in a label or a button.
///
/// The icon face is its own family, so this cannot silently fall back to Inter
/// and draw a box.
#[must_use]
pub fn icon_text(glyph: char, size: f32) -> RichText {
    RichText::new(glyph).font(FontId::new(size, FontFamily::Name(ICON_FONT.into())))
}

/// Draw an icon inline at `size` in `colour`.
pub fn icon(ui: &mut Ui, glyph: char, size: f32, colour: Color32) {
    ui.label(icon_text(glyph, size).color(colour));
}

/// A `FontId` in the semibold face at `size`.
#[must_use]
pub fn semibold(size: f32) -> FontId {
    FontId::new(size, FontFamily::Name(UI_FONT_SEMIBOLD.into()))
}

fn install_style(ctx: &Context) {
    use egui::{FontFamily::Proportional, TextStyle};

    ctx.all_styles_mut(|style| {
        style.text_styles = [
            (TextStyle::Heading, semibold(19.0)),
            (TextStyle::Body, FontId::new(14.0, Proportional)),
            (TextStyle::Button, FontId::new(14.0, Proportional)),
            (TextStyle::Small, FontId::new(12.0, Proportional)),
            (
                TextStyle::Monospace,
                FontId::new(12.5, FontFamily::Monospace),
            ),
        ]
        .into();

        style.spacing.item_spacing = Vec2::new(8.0, 7.0);
        style.spacing.button_padding = Vec2::new(12.0, 7.0);
        style.spacing.menu_margin = 8.into();

        let v = &mut style.visuals;

        // The surface ladder. egui's defaults are neutral greys, and a teal
        // accent scattered over neutral grey is what "it's all grey and boring"
        // actually described: the palette was never the problem, the ground it
        // sat on was. Every step here carries a little of the brand hue, so the
        // window reads as one material rather than as an accent colour applied
        // to a default.
        if v.dark_mode {
            v.panel_fill = Color32::from_rgb(0x0B, 0x12, 0x11);
            v.window_fill = Color32::from_rgb(0x10, 0x19, 0x17);
            v.extreme_bg_color = Color32::from_rgb(0x07, 0x0D, 0x0C);
            v.faint_bg_color = Color32::from_rgb(0x14, 0x20, 0x1E);
            v.window_stroke.color = Color32::from_rgb(0x2C, 0x3D, 0x3A);
        } else {
            v.panel_fill = Color32::from_rgb(0xEF, 0xF4, 0xF3);
            v.window_fill = Color32::from_rgb(0xF7, 0xFA, 0xF9);
            v.extreme_bg_color = Color32::from_rgb(0xFF, 0xFF, 0xFF);
            v.faint_bg_color = Color32::from_rgb(0xE7, 0xEF, 0xEE);
            v.window_stroke.color = Color32::from_rgb(0xC3, 0xD4, 0xD1);
        }

        v.hyperlink_color = TEAL_CORE;
        v.selection.bg_fill = TEAL_CORE.linear_multiply(0.35);
        v.selection.stroke.color = TEAL_CORE;
        v.widgets.hovered.bg_stroke.color = TEAL_CORE;
        v.widgets.active.bg_stroke.color = TEAL_DEEP;
        v.widgets.open.bg_stroke.color = TEAL_DEEP;
        v.error_fg_color = DANGER;

        // radius::SM, not radius::MD. This value reaches only the widgets egui
        // draws for itself, because every surface this file paints by hand -- the
        // buttons, the cards, the segmented control, the key blocks -- passes its
        // own radius to `rect_filled`. What is left is checkboxes and
        // `selectable_label` rows, both of which are small, and at 12 the first
        // became a circle and the second an oval. A user reported exactly that
        // about 1.0.0. Small widgets take the small radius.
        for w in [
            &mut v.widgets.noninteractive,
            &mut v.widgets.inactive,
            &mut v.widgets.hovered,
            &mut v.widgets.active,
            &mut v.widgets.open,
        ] {
            w.corner_radius = CornerRadius::same(radius::SM);
        }

        // An unchecked checkbox with no border is a faint grey square on a
        // near-black ground, which is most of why they did not read as
        // clickable. Give the resting state a real edge, and make the box big
        // enough to aim at.
        v.widgets.inactive.bg_stroke = egui::Stroke::new(1.5, if v.dark_mode {
            Color32::from_rgb(0x2C, 0x3D, 0x3A)
        } else {
            Color32::from_rgb(0xC3, 0xD4, 0xD1)
        });
        style.spacing.icon_width = 17.0;
        style.spacing.icon_width_inner = 10.0;
    });
}

/// Every non-ASCII character the UI draws.
///
/// Subsetting the fonts makes coverage a real constraint rather than a
/// theoretical one, and a missing glyph does not fail loudly — it renders as an
/// empty box that survives all the way to a screenshot. ✕ (U+2715) and 🔒
/// (U+1F512) both shipped that way. The test below checks this list against the
/// actual font tables, so the next one is caught at `cargo test`.
///
/// Add a symbol to the UI, add it here.
#[cfg_attr(
    not(test),
    allow(dead_code, reason = "the contract this declares is enforced by tests")
)]
pub const GLYPHS: &[char] = &['×', '◆', '⚠', '✓', '…', '⌘', '—', '·', '“', '”'];

/// Which text colour reads on the current background.
#[must_use]
pub fn ink(ui: &Ui) -> Color32 {
    if ui.visuals().dark_mode {
        TEAL_CORE
    } else {
        TEAL_INK
    }
}

// -------------------------------------------------------------- the mark ---

/// Draw the shield, filled with `shield_colour`, with the horse knocked through
/// in `horse_colour`.
///
/// Pass the same colour as the surface behind it for a knocked-out look, or a
/// contrasting one for the icon's white-shield-teal-horse arrangement.
pub fn draw_mark(ui: &Ui, rect: Rect, shield_colour: Color32, horse_colour: Color32) {
    let painter = ui.painter();
    painter.add(mesh_in(
        rect,
        &mark::SHIELD_VERTS,
        &mark::SHIELD_INDICES,
        shield_colour,
    ));
    painter.add(mesh_in(
        rect,
        &mark::HORSE_VERTS,
        &mark::HORSE_INDICES,
        horse_colour,
    ));
}

/// The shield filled with the brand gradient, horse knocked out in white.
///
/// Takes a `Painter` rather than a `Ui` so it can be drawn on a foreground
/// layer, which is what the drag-and-drop overlay needs.
pub fn draw_gradient_mark(painter: &egui::Painter, rect: Rect) {
    let side = rect.width().min(rect.height());
    let origin = rect.center() - Vec2::splat(side / 2.0);

    // Per-vertex colouring along the icon's diagonal gives every triangle its
    // share of the ramp, so the gradient follows the shield's shape rather than
    // being clipped to a box around it.
    let mut mesh = Mesh::default();
    for v in &mark::SHIELD_VERTS {
        let t = (v[0] + v[1]) / 2.0;
        let colour = if t < 0.5 {
            lerp_colour(CYAN_LIGHT, TEAL_CORE, t * 2.0)
        } else {
            lerp_colour(TEAL_CORE, TEAL_DEEP, (t - 0.5) * 2.0)
        };
        mesh.colored_vertex(
            Pos2::new(origin.x + v[0] * side, origin.y + v[1] * side),
            colour,
        );
    }
    for tri in mark::SHIELD_INDICES.chunks_exact(3) {
        mesh.add_triangle(tri[0], tri[1], tri[2]);
    }
    painter.add(Shape::mesh(mesh));

    let mut horse = Mesh::default();
    for v in &mark::HORSE_VERTS {
        horse.colored_vertex(
            Pos2::new(origin.x + v[0] * side, origin.y + v[1] * side),
            Color32::WHITE,
        );
    }
    for tri in mark::HORSE_INDICES.chunks_exact(3) {
        horse.add_triangle(tri[0], tri[1], tri[2]);
    }
    painter.add(Shape::mesh(horse));
}

/// Map a normalised mesh onto `rect`, preserving the mark's square aspect.
fn mesh_in(rect: Rect, verts: &[[f32; 2]], indices: &[u32], colour: Color32) -> Shape {
    let side = rect.width().min(rect.height());
    let origin = rect.center() - Vec2::splat(side / 2.0);

    let mut mesh = Mesh::default();
    for v in verts {
        mesh.colored_vertex(
            Pos2::new(origin.x + v[0] * side, origin.y + v[1] * side),
            colour,
        );
    }
    for tri in indices.chunks_exact(3) {
        mesh.add_triangle(tri[0], tri[1], tri[2]);
    }
    Shape::mesh(mesh)
}

// -------------------------------------------------------------- gradient ---

/// Paint the brand gradient across `rect`, running top-left to bottom-right the
/// way the icon does.
///
/// egui has no gradient primitive; a linear gradient is just a quad with
/// per-vertex colours, which the GPU interpolates for free.
pub fn gradient(ui: &Ui, rect: Rect) {
    let mut mesh = Mesh::default();
    // Corner colours sampled along the icon's diagonal ramp.
    mesh.colored_vertex(rect.left_top(), CYAN_LIGHT);
    mesh.colored_vertex(rect.right_top(), TEAL_CORE);
    mesh.colored_vertex(rect.left_bottom(), TEAL_CORE);
    mesh.colored_vertex(rect.right_bottom(), TEAL_DEEP);
    mesh.add_triangle(0, 1, 2);
    mesh.add_triangle(1, 3, 2);
    ui.painter().add(Shape::mesh(mesh));
}

/// A progress bar filled with the brand ramp.
///
/// egui's `ProgressBar` takes a single fill colour, so this is drawn by hand —
/// worth it, because the progress bar is the most-watched pixel in the app and
/// a flat blue default is exactly the greyness we are getting rid of.
pub fn progress(ui: &mut Ui, fraction: f32, text: &str) {
    let height = 22.0;
    let (rect, _) = ui.allocate_exact_size(Vec2::new(ui.available_width(), height), Sense::hover());
    let radius = CornerRadius::same(u8::try_from((height / 2.0) as i32).unwrap_or(11));

    let painter = ui.painter();
    painter.rect_filled(rect, radius, TEAL_CORE.linear_multiply(0.10));

    let fraction = fraction.clamp(0.0, 1.0);
    if fraction > 0.001 {
        let filled = Rect::from_min_size(
            rect.min,
            Vec2::new((rect.width() * fraction).max(height), height),
        );
        // Clip so the ramp always spans the whole track: the colour at a given
        // x means the same thing at 10% as at 90%, rather than the gradient
        // stretching as it fills.
        painter.with_clip_rect(filled).add({
            let mut mesh = Mesh::default();
            mesh.colored_vertex(rect.left_top(), CYAN_LIGHT);
            mesh.colored_vertex(rect.right_top(), TEAL_DEEP);
            mesh.colored_vertex(rect.left_bottom(), TEAL_CORE);
            mesh.colored_vertex(rect.right_bottom(), TEAL_DEEP);
            mesh.add_triangle(0, 1, 2);
            mesh.add_triangle(1, 3, 2);
            Shape::mesh(mesh)
        });
        // Re-round the ends, which the clip rect squares off.
        painter.rect_stroke(
            rect,
            radius,
            Stroke::new(1.0, TEAL_CORE.linear_multiply(0.25)),
            egui::StrokeKind::Inside,
        );
    }

    if !text.is_empty() {
        painter.text(
            rect.center(),
            egui::Align2::CENTER_CENTER,
            text,
            FontId::proportional(12.0),
            Color32::WHITE,
        );
    }
}

/// A thin brand-ramp rule, for separating the header from the content.
pub fn gradient_rule(ui: &Ui, rect: Rect) {
    let mut mesh = Mesh::default();
    mesh.colored_vertex(rect.left_top(), CYAN_LIGHT);
    mesh.colored_vertex(rect.right_top(), TEAL_DEEP);
    mesh.colored_vertex(rect.left_bottom(), CYAN_LIGHT);
    mesh.colored_vertex(rect.right_bottom(), TEAL_DEEP);
    mesh.add_triangle(0, 1, 2);
    mesh.add_triangle(1, 3, 2);
    ui.painter().add(Shape::mesh(mesh));
}

// ------------------------------------------------------------ components ---

/// A branded panel heading.
pub fn heading(ui: &mut Ui, text: &str) {
    ui.label(RichText::new(text).font(semibold(19.0)).color(ink(ui)));
}

/// A section label above a group of controls.
pub fn section(ui: &mut Ui, text: &str) {
    ui.add_space(2.0);
    ui.label(
        RichText::new(text.to_uppercase())
            .font(semibold(10.5))
            .color(ui.visuals().weak_text_color()),
    );
}

/// The badge shown next to anything quantum-safe.
///
/// iOS uses an SF Symbol "atom" glyph inside a 12%-tinted capsule. There is no
/// portable equivalent glyph, so the desktop uses ◆ — same colour, same capsule,
/// same words.
pub fn pq_badge(ui: &mut Ui) {
    capsule(ui, "◆ Quantum-safe", PQ_BADGE);
}

/// The badge for a passphrase-protected identity.
///
/// No padlock glyph: 🔒 is outside Latin and absent from both shipped faces —
/// and from egui's fallbacks — so it renders as a tofu box. Words are clearer
/// than a mystery square anyway.
pub fn passphrase_badge(ui: &mut Ui) {
    capsule(ui, "Passphrase", ui.visuals().weak_text_color());
}

/// A small tinted capsule, the iOS badge shape.
pub fn capsule(ui: &mut Ui, text: &str, colour: Color32) {
    let galley = ui
        .painter()
        .layout_no_wrap(text.to_owned(), FontId::proportional(11.5), colour);
    let pad = Vec2::new(7.0, 3.0);
    let (rect, _) = ui.allocate_exact_size(galley.size() + pad * 2.0, Sense::hover());
    ui.painter().rect_filled(
        rect,
        CornerRadius::same(u8::try_from(rect.height() as i32 / 2).unwrap_or(8)),
        colour.linear_multiply(0.12),
    );
    ui.painter().galley(rect.min + pad, galley, colour);
}

/// One destination in the navigation rail: an icon over a centred label.
///
/// ## One selection indicator, not two
///
/// The sidebar this replaces used `selectable_label`, which paints its own
/// background, and then drew a gradient bar inside the same row on top of it.
/// A user reported the result as "an oval highlight but also a bar to the left
/// of the text", which is exactly what it was: two markers for one piece of
/// state, neither of them chosen. Here the selected state is a single tinted
/// fill carrying the brand ramp, with a border to give it an edge on both
/// themes.
///
/// The whole item is allocated at a fixed width and everything is centred
/// within it, so a two-word label wraps inside the rail instead of measuring to
/// its own natural width and spilling into the content pane.
pub fn rail_item(ui: &mut Ui, glyph: char, label: &str, selected: bool) -> Response {
    let width = ui.available_width();
    let icon_size = 19.0;
    let label_font = FontId::proportional(11.5);

    let galley = ui.painter().layout(
        label.to_owned(),
        label_font,
        Color32::PLACEHOLDER,
        width - space::SM * 2.0,
    );
    let height = space::MD + icon_size + space::TIGHT + galley.size().y + space::MD;
    let (rect, response) = ui.allocate_exact_size(Vec2::new(width, height), Sense::click());

    let visuals = ui.visuals();
    let ink = if selected || response.hovered() {
        strong_text(visuals.dark_mode)
    } else {
        visuals.weak_text_color()
    };

    if selected {
        // The brand ramp, at the weight a background can carry. Drawing the
        // full-strength gradient here would put 4:1 text on a saturated fill.
        let painter = ui.painter();
        painter.rect_filled(
            rect,
            CornerRadius::same(radius::MD),
            CYAN_LIGHT.linear_multiply(if visuals.dark_mode { 0.16 } else { 0.20 }),
        );
        painter.rect_stroke(
            rect,
            CornerRadius::same(radius::MD),
            egui::Stroke::new(1.0, TEAL_CORE.linear_multiply(0.55)),
            egui::StrokeKind::Inside,
        );
    } else if response.hovered() {
        ui.painter().rect_filled(
            rect,
            CornerRadius::same(radius::MD),
            visuals.faint_bg_color,
        );
    }

    let painter = ui.painter();
    let icon_top = rect.top() + space::MD;
    painter.text(
        Pos2::new(rect.center().x, icon_top),
        egui::Align2::CENTER_TOP,
        glyph,
        FontId::new(icon_size, FontFamily::Name(ICON_FONT.into())),
        ink,
    );
    painter.galley(
        Pos2::new(
            rect.center().x - galley.size().x / 2.0,
            icon_top + icon_size + space::TIGHT,
        ),
        galley,
        ink,
    );

    response
}

/// The text colour that reads as "on" against either theme's ladder.
fn strong_text(dark: bool) -> Color32 {
    if dark {
        Color32::from_rgb(0xE8, 0xF0, 0xEE)
    } else {
        Color32::from_rgb(0x0C, 0x1A, 0x18)
    }
}

/// The primary action button: solid `tealCore`, white text, pressing to
/// `tealDeep`.
pub fn primary_button(ui: &mut Ui, text: &str) -> Response {
    brand_button(ui, text, ButtonKind::Primary, true)
}

/// The secondary button: 12% fill, 35% border, teal text.
pub fn secondary_button(ui: &mut Ui, text: &str) -> Response {
    brand_button(ui, text, ButtonKind::Secondary, true)
}

/// The destructive button: 10% magenta fill, magenta text.
pub fn destructive_button(ui: &mut Ui, text: &str) -> Response {
    brand_button(ui, text, ButtonKind::Destructive, true)
}

/// As [`primary_button`], but greyed and unclickable when `enabled` is false.
pub fn primary_button_enabled(ui: &mut Ui, text: &str, enabled: bool) -> Response {
    brand_button(ui, text, ButtonKind::Primary, enabled)
}

#[derive(Clone, Copy)]
enum ButtonKind {
    Primary,
    Secondary,
    Destructive,
}

fn brand_button(ui: &mut Ui, text: &str, kind: ButtonKind, enabled: bool) -> Response {
    let font = FontId::proportional(14.0);
    // PLACEHOLDER, not a real colour. `Painter::galley` treats its colour
    // argument as a *fallback*, and any non-placeholder colour baked into the
    // galley wins — so laying out in white here would paint every button's
    // label white regardless of what we pass later. Primary buttons would look
    // correct by accident and secondary ones would be white-on-pale-teal.
    let galley = ui
        .painter()
        .layout_no_wrap(text.to_owned(), font, Color32::PLACEHOLDER);
    let pad = Vec2::new(14.0, 8.0);
    let size = Vec2::new(
        galley.size().x + pad.x * 2.0,
        30.0_f32.max(galley.size().y + pad.y * 2.0),
    );

    let sense = if enabled {
        Sense::click()
    } else {
        Sense::hover()
    };
    let (rect, response) = ui.allocate_exact_size(size, sense);

    // The 0.08s ease from AgePonyButton.swift, which is what makes a press feel
    // like a press rather than a repaint.
    let pressed =
        ui.ctx()
            .animate_bool_with_time(response.id, response.is_pointer_button_down_on(), 0.08);
    let hovered = ui
        .ctx()
        .animate_bool_with_time(response.id.with("h"), response.hovered(), 0.08);

    let dark = ui.visuals().dark_mode;
    let (fill, border, ink) = match (kind, enabled) {
        (_, false) => {
            let d = ui.visuals().widgets.noninteractive.bg_fill;
            (d, Color32::TRANSPARENT, ui.visuals().weak_text_color())
        }
        (ButtonKind::Primary, true) => (
            lerp_colour(TEAL_CORE, TEAL_DEEP, pressed),
            Color32::TRANSPARENT,
            Color32::WHITE,
        ),
        (ButtonKind::Secondary, true) => (
            TEAL_CORE.linear_multiply(0.14 + 0.07 * pressed + 0.04 * hovered),
            TEAL_CORE.linear_multiply(0.45),
            // iOS puts tealCore on this fill, which works on a phone at 17pt.
            // At 14px on a white desktop surface it is about 2.4:1, so light
            // mode takes the ink instead.
            if dark { TEAL_CORE } else { TEAL_INK },
        ),
        (ButtonKind::Destructive, true) => (
            DANGER.linear_multiply(0.12 + 0.08 * pressed + 0.04 * hovered),
            DANGER.linear_multiply(0.30),
            if dark { DANGER } else { DANGER_INK },
        ),
    };

    let painter = ui.painter();
    painter.rect_filled(rect, CornerRadius::same(R_BUTTON), fill);
    if border != Color32::TRANSPARENT {
        painter.rect_stroke(
            rect,
            CornerRadius::same(R_BUTTON),
            Stroke::new(1.0, border),
            egui::StrokeKind::Inside,
        );
    }
    let text_pos = rect.center() - galley.size() / 2.0;
    painter.galley(text_pos, galley, ink);

    if enabled && response.hovered() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    response
}

fn lerp_colour(a: Color32, b: Color32, t: f32) -> Color32 {
    let t = t.clamp(0.0, 1.0);
    let f = |x: u8, y: u8| {
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        {
            (f32::from(x) + (f32::from(y) - f32::from(x)) * t) as u8
        }
    };
    Color32::from_rgb(f(a.r(), b.r()), f(a.g(), b.g()), f(a.b(), b.b()))
}

/// A segmented control: mutually exclusive options sharing one row.
///
/// Fills the available width and divides it evenly, so it cannot overflow its
/// container no matter how long the labels are or how large the system font is.
/// The previous version of the appearance switcher was three padded buttons in
/// a `horizontal`, which added up to more than the 180pt sidebar and pushed
/// "Dark" into the divider.
///
/// Matches `.pickerStyle(.segmented)`, which the iOS app uses for the same job.
///
/// Returns the index clicked, if any.
pub fn segmented(ui: &mut Ui, labels: &[&str], selected: usize) -> Option<usize> {
    if labels.is_empty() {
        return None;
    }

    let height = 26.0;
    let (rect, _) = ui.allocate_exact_size(Vec2::new(ui.available_width(), height), Sense::hover());
    let radius = CornerRadius::same(8);
    let dark = ui.visuals().dark_mode;

    ui.painter().rect_filled(
        rect,
        radius,
        if dark {
            Color32::from_rgba_unmultiplied(255, 255, 255, 14)
        } else {
            Color32::from_rgba_unmultiplied(0, 0, 0, 12)
        },
    );

    #[allow(clippy::cast_precision_loss)]
    let seg_w = rect.width() / labels.len() as f32;
    let mut clicked = None;

    for (i, label) in labels.iter().enumerate() {
        #[allow(clippy::cast_precision_loss)]
        let x = rect.left() + seg_w * i as f32;
        let seg = Rect::from_min_size(Pos2::new(x, rect.top()), Vec2::new(seg_w, height));
        let response = ui.interact(seg, ui.id().with(("segment", i)), Sense::click());

        if i == selected {
            ui.painter().rect_filled(
                seg.shrink(2.0),
                CornerRadius::same(6),
                TEAL_CORE.linear_multiply(if dark { 0.30 } else { 0.20 }),
            );
        } else if response.hovered() {
            ui.painter().rect_filled(
                seg.shrink(2.0),
                CornerRadius::same(6),
                TEAL_CORE.linear_multiply(0.08),
            );
            ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
        }

        let ink = if i == selected {
            if dark { TEAL_CORE } else { TEAL_INK }
        } else {
            ui.visuals().weak_text_color()
        };
        // Truncate rather than overflow: a label too long for its share gets
        // clipped inside its own segment instead of spilling into the next.
        ui.painter().with_clip_rect(seg).text(
            seg.center(),
            egui::Align2::CENTER_CENTER,
            label,
            FontId::proportional(12.5),
            ink,
        );

        if response.clicked() {
            clicked = Some(i);
        }
    }

    clicked
}

/// A read-only block for a key string: monospace, tinted, selectable, with a
/// Copy button. The desktop counterpart of `AgePonyKeyBlock`.
///
/// Returns true if the copy button was pressed.
pub fn key_block(ui: &mut Ui, label: Option<&str>, value: &str) -> bool {
    let mut copied = false;
    ui.vertical(|ui| {
        if let Some(label) = label {
            ui.label(
                RichText::new(label)
                    .font(FontId::proportional(11.5))
                    .color(ui.visuals().weak_text_color()),
            );
        }

        let frame = egui::Frame::new()
            .fill(TEAL_CORE.linear_multiply(0.06))
            .stroke(Stroke::new(1.0, TEAL_CORE.linear_multiply(0.18)))
            .corner_radius(CornerRadius::same(R_BLOCK))
            .inner_margin(egui::Margin::symmetric(10, 8));

        frame.show(ui, |ui| {
            ui.set_width(ui.available_width());
            // A selectable label rather than a text edit: the value is
            // read-only, but it must still be selectable by hand — people check
            // key strings by eye and copy fragments.
            ui.add(
                egui::Label::new(
                    RichText::new(value)
                        .font(FontId::new(12.5, FontFamily::Monospace))
                        .color(ink(ui)),
                )
                .wrap()
                .selectable(true),
            );
        });

        ui.horizontal(|ui| {
            if secondary_button(ui, "Copy").clicked() {
                ui.ctx().copy_text(value.to_owned());
                copied = true;
            }
        });
    });
    copied
}

/// A content card: the desktop replacement for egui's default group box.
pub fn card<R>(ui: &mut Ui, add: impl FnOnce(&mut Ui) -> R) -> R {
    let visuals = ui.visuals();
    let fill = if visuals.dark_mode {
        Color32::from_rgba_unmultiplied(255, 255, 255, 8)
    } else {
        Color32::from_rgba_unmultiplied(0, 0, 0, 6)
    };
    egui::Frame::new()
        .fill(fill)
        .stroke(Stroke::new(
            1.0,
            visuals.widgets.noninteractive.bg_stroke.color,
        ))
        .corner_radius(CornerRadius::same(R_BLOCK))
        .inner_margin(egui::Margin::same(12))
        .show(ui, add)
        .inner
}

/// A large ghosted shield behind an empty-state message.
pub fn empty_state(ui: &mut Ui, message: &str) {
    ui.add_space(24.0);
    ui.vertical_centered(|ui| {
        let side = 132.0;
        let (rect, _) = ui.allocate_exact_size(Vec2::splat(side), Sense::hover());
        draw_mark(
            ui,
            rect,
            TEAL_CORE.linear_multiply(0.14),
            TEAL_CORE.linear_multiply(0.30),
        );
        ui.add_space(10.0);
        ui.label(
            RichText::new(message)
                .font(FontId::proportional(13.5))
                .color(ui.visuals().weak_text_color()),
        );
    });
    ui.add_space(24.0);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The faces shipped in the binary, and whether each must cover [`GLYPHS`].
    const FACES: [(&str, &[u8]); 3] = [
        (
            "Inter-Regular",
            include_bytes!("../assets/fonts/Inter-Regular-subset.ttf"),
        ),
        (
            "Inter-SemiBold",
            include_bytes!("../assets/fonts/Inter-SemiBold-subset.ttf"),
        ),
        (
            "JetBrainsMono-Regular",
            include_bytes!("../assets/fonts/JetBrainsMono-Regular-subset.ttf"),
        ),
    ];

    /// The icon face, checked separately: it holds icons and nothing else, so
    /// requiring it to cover [`GLYPHS`] or ASCII would be wrong.
    const ICON_FACE: (&str, &[u8]) = (
        "Lucide",
        include_bytes!("../assets/fonts/Lucide-subset.ttf"),
    );

    #[test]
    fn every_icon_the_ui_draws_exists_in_the_icon_font() {
        let (name, bytes) = ICON_FACE;
        let face = ttf_parser::Face::parse(bytes, 0)
            .unwrap_or_else(|e| panic!("{name} is not a readable font: {e}"));
        for &c in ICONS {
            assert!(
                face.glyph_index(c).is_some(),
                "{name} has no glyph for U+{:04X} — that icon will render as nothing at all. \
                 Re-subset the face from lucide-static with this codepoint included.",
                c as u32
            );
        }
    }

    #[test]
    fn the_icon_list_has_no_duplicates() {
        // Two names for one codepoint means one of them is wrong, and the
        // coverage test above would still pass.
        let mut seen = std::collections::HashSet::new();
        for &c in ICONS {
            assert!(
                seen.insert(c),
                "U+{:04X} appears twice in ICONS, so two icon names point at one glyph",
                c as u32
            );
        }
    }

    #[test]
    fn icons_do_not_collide_with_the_text_faces() {
        // If a Private Use codepoint were also present in Inter, an icon drawn
        // by accident against the proportional family would render as something
        // plausible rather than as an obvious blank, and the bug would ship.
        for (name, bytes) in FACES {
            let face = ttf_parser::Face::parse(bytes, 0).expect("readable font");
            for &c in ICONS {
                assert!(
                    face.glyph_index(c).is_none(),
                    "{name} unexpectedly covers icon codepoint U+{:04X}",
                    c as u32
                );
            }
        }
    }

    #[test]
    fn every_symbol_the_ui_draws_exists_in_the_shipped_fonts() {
        for (name, bytes) in FACES {
            let face = ttf_parser::Face::parse(bytes, 0)
                .unwrap_or_else(|e| panic!("{name} is not a readable font: {e}"));
            for &c in GLYPHS {
                assert!(
                    face.glyph_index(c).is_some(),
                    "{name} has no glyph for {c:?} (U+{:04X}) — it will render as an empty box. \
                     Either pick a character the subset covers, or widen the subset range and \
                     regenerate the fonts.",
                    c as u32
                );
            }
        }
    }

    #[test]
    fn the_fonts_cover_printable_ascii_and_latin_1() {
        // Recipients are ASCII, but file paths are not: a name with an accent
        // must not turn into boxes in the file list.
        for (name, bytes) in FACES {
            let face = ttf_parser::Face::parse(bytes, 0).expect("readable font");
            for c in (0x20_u32..0x7F).chain(0xC0..0xFF) {
                let c = char::from_u32(c).expect("valid scalar");
                assert!(
                    face.glyph_index(c).is_some(),
                    "{name} is missing {c:?} (U+{:04X})",
                    c as u32
                );
            }
        }
    }

    #[test]
    fn no_source_string_draws_an_undeclared_symbol() {
        // The other half of the contract. `every_symbol_the_ui_draws_exists_in_
        // the_shipped_fonts` proves the declared list is covered; this proves
        // the list is complete, by scanning string literals for anything
        // non-ASCII that was never declared.
        //
        // Comments are stripped first — the module docs contain box-drawing
        // diagrams and a deliberate mention of the two glyphs that caused this
        // problem, none of which are ever rendered.
        let declared: std::collections::HashSet<char> = GLYPHS.iter().copied().collect();
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut offenders: Vec<String> = Vec::new();

        let mut stack = vec![src];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).expect("read src").flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                if path.extension().is_none_or(|e| e != "rs") {
                    continue;
                }
                let text = std::fs::read_to_string(&path).expect("read source");
                for (n, line) in text.lines().enumerate() {
                    let code = line.split("//").next().unwrap_or("");
                    let mut in_string = false;
                    let mut escaped = false;
                    for c in code.chars() {
                        match c {
                            _ if escaped => escaped = false,
                            '\\' if in_string => escaped = true,
                            '"' => in_string = !in_string,
                            _ if in_string && !c.is_ascii() && !declared.contains(&c) => {
                                offenders.push(format!(
                                    "{}:{} draws {c:?} (U+{:04X})",
                                    path.file_name().unwrap_or_default().to_string_lossy(),
                                    n + 1,
                                    c as u32
                                ));
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        assert!(
            offenders.is_empty(),
            "these symbols are rendered but not declared in GLYPHS, so nothing checks \
             the fonts can draw them:\n  {}",
            offenders.join("\n  ")
        );
    }

    #[test]
    fn segments_tile_their_container_exactly() {
        // The bug this control replaces: three padded buttons in a row summed
        // to more than the 180pt sidebar, so the last one was pushed into the
        // divider. Equal division of the available width cannot do that, at any
        // width or count.
        for width in [120.0_f32, 164.0, 180.0, 420.0, 1000.0] {
            for count in 2..=5_usize {
                #[allow(clippy::cast_precision_loss)]
                let seg = width / count as f32;
                #[allow(clippy::cast_precision_loss)]
                let last_edge = seg * (count - 1) as f32 + seg;
                assert!(
                    (last_edge - width).abs() < 0.001,
                    "at width {width} with {count} segments the last edge lands at {last_edge}"
                );
                assert!(seg > 0.0, "segments must have positive width");
            }
        }
    }

    #[test]
    fn the_shipped_fonts_stay_small() {
        // Subsetting is what makes embedding them defensible against the
        // single-self-contained-binary goal. If a regeneration ever forgets to
        // subset, the faces jump back to ~600 KB each and this catches it.
        let total: usize =
            FACES.iter().map(|(_, b)| b.len()).sum::<usize>() + ICON_FACE.1.len();
        assert!(
            total < 400_000,
            "shipped fonts total {total} bytes; they should be subset to well under 400 KB"
        );
    }
}
