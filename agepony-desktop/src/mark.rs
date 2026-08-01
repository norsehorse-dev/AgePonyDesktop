//! The AgePony mark, as vector meshes.
//!
//! Traced from `Media.xcassets/AppIcon.appiconset/agepony.png` — the shield
//! silhouette and the horse head, each simplified to a polygon and triangulated
//! ahead of time. Drawing them is then a plain `egui::Mesh`: crisp at any size,
//! any colour, no image decoding, no raster to scale badly.
//!
//! Coordinates are normalised into the unit square with the origin top-left, so
//! they map onto any `Rect` by multiply-and-offset.
//!
//! The horse has two rings — the outline and the eye. The eye is a hole, and it
//! matters more than its size suggests: without it the head reads as a blob at
//! sidebar scale. The triangulation already accounts for it, so drawing the
//! horse over the shield gives the correct result with no masking.
//!
//! Regenerate by re-running the tracing script against the icon; the numbers
//! below are generated, not hand-tuned.

/// shield vertices, normalised into a unit square.
pub const SHIELD_VERTS: [[f32; 2]; 28] = [
    [0.50195, 0.89404],
    [0.45996, 0.87646],
    [0.41895, 0.85205],
    [0.36816, 0.81592],
    [0.33398, 0.78662],
    [0.29736, 0.75000],
    [0.26025, 0.70508],
    [0.22803, 0.65527],
    [0.21045, 0.62109],
    [0.19287, 0.57910],
    [0.18018, 0.53809],
    [0.16650, 0.45312],
    [0.16553, 0.18555],
    [0.16650, 0.17773],
    [0.17090, 0.17432],
    [0.81641, 0.17334],
    [0.82520, 0.17432],
    [0.82861, 0.17871],
    [0.82764, 0.47461],
    [0.81396, 0.55176],
    [0.79248, 0.61230],
    [0.77002, 0.65625],
    [0.73975, 0.70312],
    [0.70557, 0.74609],
    [0.66504, 0.78760],
    [0.62891, 0.81885],
    [0.58105, 0.85303],
    [0.53418, 0.88037],
];

/// shield triangle indices.
pub const SHIELD_INDICES: [u32; 78] = [
    26, 27, 0, 0, 1, 2, 2, 3, 4, 4, 5, 6, 6, 7, 8, 8, 9, 10, 10, 11, 12, 12, 13, 14, 14, 15, 16,
    16, 17, 18, 18, 19, 20, 20, 21, 22, 22, 23, 24, 24, 25, 26, 26, 0, 2, 2, 4, 6, 6, 8, 10, 10,
    12, 14, 14, 16, 18, 18, 20, 22, 22, 24, 26, 26, 2, 6, 6, 10, 14, 14, 18, 22, 22, 26, 6, 6, 14,
    22,
];

/// horse vertices, normalised into a unit square.
pub const HORSE_VERTS: [[f32; 2]; 74] = [
    [0.49902, 0.85498],
    [0.45312, 0.83545],
    [0.40918, 0.80908],
    [0.37012, 0.77783],
    [0.33936, 0.74316],
    [0.31885, 0.70898],
    [0.30518, 0.67188],
    [0.29736, 0.62500],
    [0.29688, 0.57764],
    [0.23730, 0.60303],
    [0.23389, 0.60156],
    [0.24365, 0.57227],
    [0.26123, 0.54004],
    [0.28467, 0.51172],
    [0.30518, 0.49316],
    [0.22559, 0.49365],
    [0.22510, 0.49121],
    [0.23877, 0.47461],
    [0.27051, 0.44482],
    [0.31348, 0.41650],
    [0.34277, 0.40283],
    [0.35596, 0.39160],
    [0.35254, 0.39014],
    [0.27637, 0.39990],
    [0.27197, 0.39844],
    [0.29688, 0.37256],
    [0.31934, 0.35400],
    [0.35645, 0.32959],
    [0.40625, 0.30713],
    [0.44336, 0.29639],
    [0.49414, 0.29150],
    [0.51904, 0.26172],
    [0.55078, 0.23096],
    [0.56152, 0.22412],
    [0.56104, 0.24316],
    [0.55225, 0.30273],
    [0.57910, 0.31885],
    [0.60693, 0.34277],
    [0.67041, 0.41992],
    [0.74072, 0.49609],
    [0.74951, 0.50879],
    [0.75342, 0.51953],
    [0.75439, 0.53809],
    [0.74756, 0.56152],
    [0.73291, 0.58594],
    [0.71680, 0.59912],
    [0.70117, 0.60400],
    [0.68945, 0.60303],
    [0.67480, 0.59717],
    [0.64551, 0.57275],
    [0.56738, 0.55908],
    [0.54004, 0.55127],
    [0.51416, 0.54004],
    [0.52197, 0.59473],
    [0.54346, 0.65918],
    [0.57471, 0.72070],
    [0.61963, 0.78809],
    [0.55664, 0.82764],
    [0.56445, 0.42725],
    [0.55762, 0.42725],
    [0.54785, 0.42334],
    [0.54150, 0.41602],
    [0.53955, 0.41113],
    [0.53955, 0.40137],
    [0.54443, 0.39258],
    [0.54980, 0.38818],
    [0.55957, 0.38525],
    [0.56641, 0.38623],
    [0.57227, 0.38916],
    [0.57666, 0.39355],
    [0.58057, 0.40137],
    [0.58057, 0.41211],
    [0.57764, 0.41797],
    [0.57227, 0.42334],
];

/// horse triangle indices.
pub const HORSE_INDICES: [u32; 222] = [
    20, 63, 62, 64, 63, 20, 22, 23, 24, 24, 25, 26, 26, 27, 28, 28, 29, 30, 30, 31, 32, 32, 33, 34,
    35, 36, 37, 38, 39, 40, 40, 41, 42, 42, 43, 44, 44, 45, 46, 46, 47, 48, 49, 50, 51, 55, 56, 57,
    57, 0, 1, 1, 2, 3, 3, 4, 5, 5, 6, 7, 8, 9, 10, 10, 11, 12, 12, 13, 14, 14, 15, 16, 16, 17, 18,
    18, 19, 20, 20, 62, 61, 65, 64, 20, 22, 24, 26, 26, 28, 30, 30, 32, 34, 35, 37, 38, 38, 40, 42,
    42, 44, 46, 46, 48, 49, 49, 51, 52, 54, 55, 57, 57, 1, 3, 3, 5, 7, 8, 10, 12, 14, 16, 18, 18,
    20, 61, 66, 65, 20, 21, 22, 26, 30, 34, 35, 35, 38, 42, 42, 46, 49, 53, 54, 57, 57, 3, 7, 8,
    12, 14, 14, 18, 61, 66, 20, 21, 21, 26, 30, 30, 35, 42, 42, 49, 52, 53, 57, 7, 7, 8, 14, 14,
    61, 60, 66, 21, 30, 52, 53, 7, 7, 14, 60, 67, 66, 30, 52, 7, 60, 68, 67, 30, 42, 52, 60, 69,
    68, 30, 42, 60, 59, 69, 30, 42, 42, 59, 58, 70, 69, 42, 42, 58, 73, 71, 70, 42, 42, 73, 72, 72,
    71, 42,
];

/// Rasterise the full icon — brand gradient, white shield, teal horse — into
/// RGBA pixels.
///
/// Generated from the same vertex data the UI draws, rather than embedding the
/// PNG: one source of truth, no image decoding at startup, nothing to fall out
/// of step if the mark is ever retraced. Called once to build the window icon,
/// so the per-pixel triangle test is not worth optimising.
#[must_use]
pub fn rasterise(size: usize) -> Vec<u8> {
    const CYAN: [f32; 3] = [0x38 as f32, 0xCF as f32, 0xE8 as f32];
    const TEAL: [f32; 3] = [0x14 as f32, 0xB8 as f32, 0xB0 as f32];
    const DEEP: [f32; 3] = [0x0E as f32, 0x7D as f32, 0x7A as f32];

    let mut out = vec![0_u8; size * size * 4];
    #[allow(clippy::cast_precision_loss)]
    let n = size as f32;

    for y in 0..size {
        for x in 0..size {
            #[allow(clippy::cast_precision_loss)]
            let (fx, fy) = ((x as f32 + 0.5) / n, (y as f32 + 0.5) / n);

            // The icon's diagonal ramp: cyan at top-left through teal to deep.
            let t = (fx + fy) / 2.0;
            let (a, b, k) = if t < 0.5 {
                (CYAN, TEAL, t * 2.0)
            } else {
                (TEAL, DEEP, (t - 0.5) * 2.0)
            };
            let mut rgb = [
                a[0] + (b[0] - a[0]) * k,
                a[1] + (b[1] - a[1]) * k,
                a[2] + (b[2] - a[2]) * k,
            ];

            if inside(fx, fy, &SHIELD_VERTS, &SHIELD_INDICES) {
                rgb = [255.0, 255.0, 255.0];
            }
            if inside(fx, fy, &HORSE_VERTS, &HORSE_INDICES) {
                rgb = TEAL;
            }

            let i = (y * size + x) * 4;
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            {
                out[i] = rgb[0] as u8;
                out[i + 1] = rgb[1] as u8;
                out[i + 2] = rgb[2] as u8;
                out[i + 3] = 255;
            }
        }
    }
    out
}

/// Whether a normalised point falls inside a triangulated mesh.
fn inside(px: f32, py: f32, verts: &[[f32; 2]], indices: &[u32]) -> bool {
    indices.chunks_exact(3).any(|t| {
        let (a, b, c) = (
            verts[t[0] as usize],
            verts[t[1] as usize],
            verts[t[2] as usize],
        );
        let sign = |p: [f32; 2], q: [f32; 2], r: [f32; 2]| {
            (p[0] - r[0]) * (q[1] - r[1]) - (q[0] - r[0]) * (p[1] - r[1])
        };
        let p = [px, py];
        let (d1, d2, d3) = (sign(p, a, b), sign(p, b, c), sign(p, c, a));
        let neg = d1 < 0.0 || d2 < 0.0 || d3 < 0.0;
        let pos = d1 > 0.0 || d2 > 0.0 || d3 > 0.0;
        !(neg && pos)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_mesh_data_is_well_formed() {
        assert_eq!(SHIELD_INDICES.len() % 3, 0);
        assert_eq!(HORSE_INDICES.len() % 3, 0);
        assert!(
            SHIELD_INDICES
                .iter()
                .all(|&i| (i as usize) < SHIELD_VERTS.len())
        );
        assert!(
            HORSE_INDICES
                .iter()
                .all(|&i| (i as usize) < HORSE_VERTS.len())
        );
        assert!(
            SHIELD_VERTS
                .iter()
                .chain(HORSE_VERTS.iter())
                .all(|v| (0.0..=1.0).contains(&v[0]) && (0.0..=1.0).contains(&v[1])),
            "vertices must stay inside the unit square"
        );
    }

    #[test]
    fn the_horse_sits_inside_the_shield() {
        // Every horse vertex must fall within the shield, or drawing the horse
        // over the shield would spill onto whatever is behind it.
        for v in &HORSE_VERTS {
            assert!(
                inside(v[0], v[1], &SHIELD_VERTS, &SHIELD_INDICES),
                "horse vertex {v:?} escapes the shield"
            );
        }
    }

    #[test]
    fn the_rasterised_icon_looks_like_the_icon() {
        let size = 64;
        let px = rasterise(size);
        assert_eq!(px.len(), size * size * 4);
        assert!(
            px.chunks_exact(4).all(|p| p[3] == 255),
            "icon must be opaque"
        );

        // A corner is gradient, the centre-ish is horse, and some white shield
        // exists between them. Cheap, but it catches a mesh that failed to load
        // or a rasteriser that filled everything one colour.
        let at = |x: usize, y: usize| {
            let i = (y * size + x) * 4;
            [px[i], px[i + 1], px[i + 2]]
        };
        let white = px
            .chunks_exact(4)
            .filter(|p| p[0] > 240 && p[1] > 240 && p[2] > 240)
            .count();
        assert!(white > size * size / 20, "expected a visible white shield");
        assert_ne!(at(1, 1), [255, 255, 255], "the corner should be gradient");
    }
}
