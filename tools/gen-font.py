#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Generate the Bhaskix 8x16 console font table.

The kernel console needs a bitmap font before any allocator or filesystem
exists, so the glyphs are baked into the binary as a static table. This script
renders that table from a TrueType font and emits Rust source.

The output is committed to the repository (kernel/src/font.rs) rather than
generated at build time: contributors must not need Python, PIL, or a
particular system font installed to build the kernel, and the rendering must
be identical on every machine.

Provenance is recorded in NOTICE. Re-run only when the font or metrics change,
and commit the result in the same change.

Usage:
    tools/gen-font.py                     # write kernel/src/font.rs
    tools/gen-font.py --preview 'Bhaskix'    # ASCII-art preview, writes nothing
"""

from __future__ import annotations

import argparse
import pathlib
import sys

try:
    from PIL import Image, ImageDraw, ImageFont
except ImportError:
    sys.exit("error: Pillow is required to regenerate the font: pip install Pillow")

# --- Rendering parameters -------------------------------------------------
#
# GLYPH_W is fixed at 8 so that one row of a glyph is exactly one byte, which
# keeps the blitter a shift-and-test loop with no bit juggling across bytes.
#
# DejaVu Sans Mono has an advance width of 0.602 em, so a 13px size gives a
# ~7.8px advance -- the closest fit to an 8px cell without clipping.
GLYPH_W = 8
GLYPH_H = 16
FONT_PATH = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
FONT_SIZE = 13
BASELINE = 12          # pixel row of the baseline within the 16px cell
X_OFFSET = 0
THRESHOLD = 110        # >= this alpha counts as ink

FIRST_CHAR = 0x20      # space
LAST_CHAR = 0x7E       # tilde

REPO = pathlib.Path(__file__).resolve().parent.parent
OUT = REPO / "kernel" / "src" / "font.rs"


def render_glyph(font: ImageFont.FreeTypeFont, ch: str) -> list[int]:
    """Render one character to GLYPH_H rows of GLYPH_W bits, MSB leftmost."""
    img = Image.new("L", (GLYPH_W, GLYPH_H), 0)
    draw = ImageDraw.Draw(img)
    # Pillow 7 has no `anchor` argument, so position by metrics instead:
    # draw.text() places the ASCENDER line at the given y, so subtracting the
    # ascent puts the baseline exactly at BASELINE. This also works on newer
    # Pillow, which keeps the same default anchor.
    ascent, _descent = font.getmetrics()
    draw.text((X_OFFSET, BASELINE - ascent), ch, font=font, fill=255)

    rows = []
    px = img.load()
    for y in range(GLYPH_H):
        bits = 0
        for x in range(GLYPH_W):
            if px[x, y] >= THRESHOLD:
                bits |= 1 << (7 - x)
        rows.append(bits)
    return rows


def build() -> dict[int, list[int]]:
    font = ImageFont.truetype(FONT_PATH, FONT_SIZE)
    return {c: render_glyph(font, chr(c)) for c in range(FIRST_CHAR, LAST_CHAR + 1)}


def preview(glyphs: dict[int, list[int]], text: str) -> None:
    """Print the rendered text as ASCII art so glyph quality is reviewable."""
    for y in range(GLYPH_H):
        line = []
        for ch in text:
            rows = glyphs.get(ord(ch), glyphs[ord("?")])
            line.append("".join("#" if rows[y] & (1 << (7 - x)) else "." for x in range(GLYPH_W)))
        print(" ".join(line))


def emit(glyphs: dict[int, list[int]]) -> str:
    count = LAST_CHAR - FIRST_CHAR + 1
    out = [
        "// SPDX-License-Identifier: Apache-2.0",
        "//! Bitmap console font, 8x16, printable ASCII.",
        "//!",
        "//! GENERATED FILE -- do not edit by hand.",
        "//! Regenerate with `tools/gen-font.py` and commit the result.",
        "//!",
        "//! Rendered from DejaVu Sans Mono; see NOTICE for provenance and",
        "//! licensing. Glyphs are stored one byte per row, MSB leftmost, so a",
        "//! row can be blitted with a shift-and-test loop.",
        "",
        "/// Width of one glyph cell, in pixels.",
        f"pub const GLYPH_WIDTH: usize = {GLYPH_W};",
        "",
        "/// Height of one glyph cell, in pixels.",
        f"pub const GLYPH_HEIGHT: usize = {GLYPH_H};",
        "",
        "/// First character present in [`GLYPHS`].",
        f"pub const FIRST_CHAR: u8 = {FIRST_CHAR:#04x};",
        "",
        "/// Last character present in [`GLYPHS`].",
        f"pub const LAST_CHAR: u8 = {LAST_CHAR:#04x};",
        "",
        "/// Glyph bitmaps for printable ASCII, indexed by `c - FIRST_CHAR`.",
        f"pub static GLYPHS: [[u8; GLYPH_HEIGHT]; {count}] = [",
    ]
    for c in range(FIRST_CHAR, LAST_CHAR + 1):
        rows = ", ".join(f"0x{b:02x}" for b in glyphs[c])
        name = {0x20: "space", 0x27: "apostrophe", 0x5c: "backslash"}.get(c, chr(c))
        out.append(f"    [{rows}], // {c:#04x} {name}")
    out.append("];")
    out.append("")
    out.append("/// Returns the bitmap for `c`, or the bitmap for `?` if `c` is not printable.")
    out.append("#[must_use]")
    out.append("pub fn glyph(c: u8) -> &'static [u8; GLYPH_HEIGHT] {")
    out.append("    let index = if (FIRST_CHAR..=LAST_CHAR).contains(&c) {")
    out.append("        (c - FIRST_CHAR) as usize")
    out.append("    } else {")
    out.append("        (b'?' - FIRST_CHAR) as usize")
    out.append("    };")
    out.append("    &GLYPHS[index]")
    out.append("}")
    out.append("")
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--preview", metavar="TEXT", help="ASCII-art preview; writes nothing")
    args = ap.parse_args()

    glyphs = build()

    if args.preview:
        preview(glyphs, args.preview)
        return 0

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(emit(glyphs))
    print(f"wrote {OUT.relative_to(REPO)} ({LAST_CHAR - FIRST_CHAR + 1} glyphs)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
