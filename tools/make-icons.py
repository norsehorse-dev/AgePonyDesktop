#!/usr/bin/env python3
"""make-icons.py -- generate AgePony Desktop's icon set from the 1024px master.

    tools/make-icons.py                  # uses the iOS asset catalogue, else the in-repo copy
    tools/make-icons.py path/to/1024.png # any square master, 512px or larger

Outputs, all regenerated from scratch and all safe to delete and re-run:

    packaging/agepony.png       Linux, cargo-deb and the AppImage
    packaging/agepony.ico       Windows, the AppImage-adjacent copy (7 sizes in one file)
    agepony-desktop/wix/Product.ico   Windows, what cargo-wix embeds in the MSI
    packaging/agepony.icns      macOS, the .app bundle (10 chunks, Retina pairs)

This is BurnPonyDesktop's `tools/make-icons.py`, adapted. The macOS grid work and
the ICNS container writer are unchanged, because they encode knowledge that took
a shipped release to learn. What changed: the master candidates point at the
AgePony iOS checkout, the outputs drop the `src/main/resources` path a Gradle
project needs, and there is no cross-promo avatar rule to enforce.

WHY THE MACOS OUTPUT IS NOT THE MASTER
======================================
The master is the iOS shape: a full-bleed opaque square. iOS masks app icons
itself, so that is correct there and wrong everywhere else. **macOS does not
mask.** Ship the master as an .icns and the Dock shows a hard-edged square
sitting noticeably larger than every neighbour, because macOS draws icons inside
a fixed grid: on a 1024 canvas the rounded square occupies 824px and the rest is
transparent margin the system fills with its own drop shadow.

So the .icns is inset to that grid and the corners are cut with a SUPERELLIPSE,
not a circular arc. Apple's continuous corner curve ramps its curvature in rather
than switching on at the tangent point, and a plain rounded rectangle reads as
visibly "pillowed" beside real macOS icons. Windows and Linux do not inset --
their icons are full-bleed -- so those outputs get the squircle without the
margin.

NOTE ON THE RUNTIME ICON
========================
AgePony Desktop also draws its own window icon at startup, from the traced vector
mark in `agepony-desktop/src/mark.rs`, and that is deliberate rather than
redundant. The runtime icon is what Windows and Linux show in the taskbar; it
cannot drift from the mark on screen because it is the same vertex data. On macOS
the Dock icon comes from the .app bundle's .icns instead, which is why that one
has to exist as a file and has to be inset. Different surfaces, different
requirements, neither is dead weight.
"""

import io
import os
import struct
import sys

from PIL import Image, ImageDraw

try:
    import numpy as np
except ImportError:  # pragma: no cover - exercised only on a numpy-less box
    np = None

# Apple's continuous corner curve. Exponent 5 is the usual fit for the
# superellipse; 0.2237 is the corner-radius ratio Apple's own icon template uses.
SQUIRCLE_EXPONENT = 5.0
CORNER_RATIO = 0.2237

# 824 of 1024. Skip it and AgePony sits visibly larger than everything else in
# the Dock.
MACOS_CONTENT_RATIO = 824.0 / 1024.0

ICO_SIZES = (16, 24, 32, 48, 64, 128, 256)

# ICNS chunk types. The ic07.. family is PNG-in-container, which every macOS this
# app supports understands; icp4/icp5 keep Finder happy at the smallest sizes.
ICNS_CHUNKS = (
    (b"icp4", 16),
    (b"icp5", 32),
    (b"ic11", 32),    # 16pt @2x
    (b"ic12", 64),    # 32pt @2x
    (b"ic07", 128),
    (b"ic13", 256),   # 128pt @2x
    (b"ic08", 256),
    (b"ic14", 512),   # 256pt @2x
    (b"ic09", 512),
    (b"ic10", 1024),  # 512pt @2x
)

# Where the artwork lives, in priority order.
#
# THE CANONICAL MASTER IS THE iOS ASSET CATALOGUE. This repo's copy is downstream
# by definition -- the phone and the App Store listing ship the same artwork, and
# making the desktop repo its owner is how two copies with no owner start.
#
# The in-repo copy stays as a committed fallback so this script and the build work
# on a machine that has only this repo checked out (CI, a fresh clone). If BOTH
# are present and differ, the iOS one wins and the run says so.
MASTER_CANDIDATES = (
    os.path.join("..", "AgePony", "Media.xcassets", "AppIcon.appiconset", "agepony.png"),
    os.path.join("..", "AgePony", "AgePony", "Assets.xcassets", "AppIcon.appiconset",
                 "agepony.png"),
    os.path.join("packaging", "agepony-master-1024.png"),
)


def default_master():
    """The canonical master if the iOS checkout is here, else the committed copy."""
    present = [p for p in MASTER_CANDIDATES if os.path.isfile(p)]
    if not present:
        return MASTER_CANDIDATES[-1]
    chosen = present[0]
    committed = MASTER_CANDIDATES[-1]
    if chosen != committed and os.path.isfile(committed):
        if open(chosen, "rb").read() != open(committed, "rb").read():
            print("  NOTE the committed copy differs from the iOS master; using the iOS one.")
            print("       refresh %s from:" % committed)
            print("         %s" % chosen)
    return chosen


def squircle_mask(size):
    """An 8-bit alpha mask: opaque inside the superellipse, transparent outside."""
    radius = size * CORNER_RATIO
    if np is not None:
        # Distance from each pixel centre to the nearest edge, clamped into the
        # corner box. Along the straight runs one axis is zero and the test always
        # passes, so one expression covers edges and corners with no special case.
        axis = (np.arange(size, dtype=np.float64) + 0.5)
        dx = np.maximum(radius - axis, axis - (size - radius))
        dy = dx.reshape(-1, 1)
        dx = np.maximum(dx, 0.0) / radius
        dy = np.maximum(dy, 0.0) / radius
        field = dx ** SQUIRCLE_EXPONENT + dy ** SQUIRCLE_EXPONENT
        # A one-pixel linear ramp across the boundary instead of a hard cut, so the
        # corners are antialiased rather than stair-stepped.
        edge = np.clip((1.0 - field) * size * 0.5 + 0.5, 0.0, 1.0)
        return Image.fromarray((edge * 255.0).round().astype("uint8"), mode="L")

    scale = 4
    big = size * scale
    mask = Image.new("L", (big, big), 0)
    ImageDraw.Draw(mask).rounded_rectangle(
        (0, 0, big - 1, big - 1), radius=radius * scale, fill=255
    )
    return mask.resize((size, size), Image.LANCZOS)


def rounded(master, size):
    """The master resampled to `size` with the squircle mask applied, full-bleed."""
    art = master.resize((size, size), Image.LANCZOS).convert("RGBA")
    art.putalpha(squircle_mask(size))
    return art


def macos_tile(master, size):
    """`rounded`, inset into a transparent canvas on the macOS icon grid."""
    content = max(1, int(round(size * MACOS_CONTENT_RATIO)))
    canvas = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    offset = (size - content) // 2
    canvas.paste(rounded(master, content), (offset, offset))
    return canvas


def png_bytes(image):
    buffer = io.BytesIO()
    image.save(buffer, format="PNG", optimize=True)
    return buffer.getvalue()


def write_png(image, path):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    image.save(path, format="PNG", optimize=True)
    print("  {:<44} {}x{}".format(path, image.width, image.height))


def write_icns(master, path):
    """Build the ICNS container by hand.

    Pillow can read ICNS and can only WRITE it on macOS, where it shells out to
    `iconutil`. The container itself is trivial -- a magic word, a big-endian total
    length, then typed chunks that are each a 4-byte type, a big-endian length
    INCLUDING its own 8-byte header, and the payload -- so writing it directly
    keeps this script behaving identically on every machine, CI included.
    """
    body = b""
    for chunk_type, size in ICNS_CHUNKS:
        png = png_bytes(macos_tile(master, size))
        body += chunk_type + struct.pack(">I", len(png) + 8) + png
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "wb") as handle:
        handle.write(b"icns" + struct.pack(">I", len(body) + 8) + body)
    print("  {:<44} {} chunks, {} bytes".format(path, len(ICNS_CHUNKS), len(body) + 8))


def write_ico(master, path):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    rounded(master, max(ICO_SIZES)).save(
        path, format="ICO", sizes=[(s, s) for s in ICO_SIZES]
    )
    print("  {:<44} {}".format(path, ", ".join("{}px".format(s) for s in ICO_SIZES)))


def verify(icns_path, ico_path):
    """Re-read what was just written.

    Structure, not bytes: PNG encoders are not byte-stable across Pillow versions,
    so a golden-file comparison would fail on an upgrade for no reason. What CAN be
    checked is that the container parses and holds what it claims -- which is the
    failure that actually matters, because a malformed .icns does not stop the
    build, it just makes the installer fall back to the default icon and nobody
    notices until a screenshot.
    """
    with open(icns_path, "rb") as handle:
        blob = handle.read()
    assert blob[:4] == b"icns", "not an ICNS: bad magic"
    assert struct.unpack(">I", blob[4:8])[0] == len(blob), "ICNS length header disagrees with the file"
    offset, found = 8, []
    while offset < len(blob):
        chunk_type = blob[offset:offset + 4]
        length = struct.unpack(">I", blob[offset + 4:offset + 8])[0]
        assert length >= 8 and offset + length <= len(blob), "ICNS chunk %r overruns" % chunk_type
        found.append(chunk_type)
        offset += length
    expected = [c for c, _ in ICNS_CHUNKS]
    assert found == expected, "ICNS chunks %r, expected %r" % (found, expected)

    with Image.open(ico_path) as ico:
        sizes = sorted(ico.info.get("sizes", []))
    assert sizes == sorted((s, s) for s in ICO_SIZES), "ICO holds %r" % (sizes,)
    print("  verified: {} ICNS chunks parse, ICO holds {} sizes".format(len(found), len(sizes)))


def main(argv):
    master_path = argv[1] if len(argv) == 2 else default_master()
    if len(argv) > 2:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    if not os.path.isfile(master_path):
        print("master not found: %s\n(run from the repo root)" % master_path, file=sys.stderr)
        return 1

    master = Image.open(master_path).convert("RGBA")
    if master.width != master.height:
        print("master must be square, got %dx%d" % (master.width, master.height), file=sys.stderr)
        return 1
    if master.width < 512:
        print("master is %dpx -- expected the 1024px source" % master.width, file=sys.stderr)
        return 1

    print("master  %s (%dx%d)" % (master_path, master.width, master.height))
    write_png(rounded(master, 512), os.path.join("packaging", "agepony.png"))
    write_ico(master, os.path.join("packaging", "agepony.ico"))
    # cargo-wix's template references wix\\Product.ico by default; writing it here
    # means the generated main.wxs needs no path edit.
    write_ico(master, os.path.join("agepony-desktop", "wix", "Product.ico"))
    write_icns(master, os.path.join("packaging", "agepony.icns"))
    verify(os.path.join("packaging", "agepony.icns"), os.path.join("packaging", "agepony.ico"))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
