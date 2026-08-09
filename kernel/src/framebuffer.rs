// SPDX-License-Identifier: Apache-2.0
//! Text console on a linear framebuffer.
//!
//! The second output path after serial, and the one a person sitting at the
//! machine can actually see. It is deliberately simple: no acceleration, no
//! double buffering, no damage tracking. Those are worth having once there is
//! a compositor to justify them; before then they are complexity in the path
//! that has to work when nothing else does.
//!
//! Every write is bounds-checked through [`bhaskix_boot::Framebuffer::offset_of`],
//! so a wrong cursor position produces a missing glyph rather than memory
//! corruption somewhere else in the address space.

use bhaskix_boot::Framebuffer;

use crate::font;

/// Foreground colour: near-white, slightly warm.
const DEFAULT_FG: (u8, u8, u8) = (0xe8, 0xe8, 0xe4);

/// Background colour: near-black, slightly blue.
const DEFAULT_BG: (u8, u8, u8) = (0x0a, 0x0c, 0x10);

/// A character cell console drawn onto a linear framebuffer.
pub struct FbConsole {
    fb: Framebuffer,
    columns: usize,
    rows: usize,
    column: usize,
    row: usize,
    foreground: u32,
    background: u32,
    /// Where the parser is inside an escape sequence, if it is inside one.
    escape: Escape,
    /// Digits of the parameter being accumulated inside a CSI sequence.
    param: u32,
}

/// Where [`FbConsole::write_byte`] is within an ANSI escape sequence.
///
/// **Needed because the two console sinks disagree about escapes.** A serial
/// terminal interprets them; a framebuffer draws whatever glyph it is handed,
/// so an unparsed `\x1b[1;33m` appears on screen as literal rubbish next to the
/// text it was meant to colour. Kernel output carried no escapes at all until
/// the boot banner wanted them, and the choice was to parse them here or to
/// give the screen a worse boot than the serial line.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Escape {
    /// Not in a sequence.
    None,
    /// Seen `ESC`, waiting for `[`.
    Seen,
    /// Inside `ESC [`, accumulating parameters.
    Csi,
}

impl FbConsole {
    /// Creates a console covering `fb` and clears the screen.
    ///
    /// Returns `None` if the framebuffer is too small for even one character
    /// cell, or uses a pixel format the blitter does not support.
    #[must_use]
    pub fn new(fb: Framebuffer) -> Option<Self> {
        // 32 and 24 bits per pixel cover every UEFI GOP mode we have seen.
        // Rejecting anything else is better than silently rendering garbage:
        // the caller falls back to serial and says why.
        if !matches!(fb.bpp, 24 | 32) {
            return None;
        }

        let columns = (fb.width as usize) / font::GLYPH_WIDTH;
        let rows = (fb.height as usize) / font::GLYPH_HEIGHT;
        if columns == 0 || rows == 0 {
            return None;
        }

        let mut console = Self {
            foreground: fb.format.encode(DEFAULT_FG.0, DEFAULT_FG.1, DEFAULT_FG.2),
            background: fb.format.encode(DEFAULT_BG.0, DEFAULT_BG.1, DEFAULT_BG.2),
            fb,
            columns,
            rows,
            column: 0,
            row: 0,
            escape: Escape::None,
            param: 0,
        };
        console.clear();
        Some(console)
    }

    /// Number of character columns.
    #[must_use]
    pub const fn columns(&self) -> usize {
        self.columns
    }

    /// Number of character rows.
    #[must_use]
    pub const fn rows(&self) -> usize {
        self.rows
    }

    /// Writes one pixel, ignoring out-of-bounds coordinates.
    fn put_pixel(&self, x: u64, y: u64, colour: u32) {
        let Some(offset) = self.fb.offset_of(x, y) else {
            return;
        };
        let base = self.fb.address.as_u64() as *mut u8;

        // SAFETY: `offset_of` returned `Some`, so `offset` addresses a pixel
        // inside the visible area of the mapping the bootloader gave us, and
        // `bytes_per_pixel` bytes from there are still within that pixel.
        // The framebuffer is device memory, so every store is volatile: the
        // compiler must not merge, reorder, or elide writes whose only effect
        // is visible on a screen.
        unsafe {
            let pixel = base.add(offset);
            match self.fb.bytes_per_pixel() {
                4 => pixel.cast::<u32>().write_volatile(colour),
                3 => {
                    // Byte-wise, because a 24-bit pixel is not aligned for a
                    // 32-bit store and reading the neighbouring byte to do a
                    // read-modify-write would be both slower and wrong at the
                    // last pixel of the last row.
                    pixel.write_volatile(colour as u8);
                    pixel.add(1).write_volatile((colour >> 8) as u8);
                    pixel.add(2).write_volatile((colour >> 16) as u8);
                }
                // `new` rejected every other depth.
                _ => {}
            }
        }
    }

    /// Fills the whole framebuffer with the background colour.
    pub fn clear(&mut self) {
        for y in 0..self.fb.height {
            for x in 0..self.fb.width {
                self.put_pixel(x, y, self.background);
            }
        }
        self.column = 0;
        self.row = 0;
    }

    /// Draws one glyph at character cell `(column, row)`.
    fn draw_glyph(&self, byte: u8, column: usize, row: usize) {
        let bitmap = font::glyph(byte);
        let origin_x = (column * font::GLYPH_WIDTH) as u64;
        let origin_y = (row * font::GLYPH_HEIGHT) as u64;

        for (dy, bits) in bitmap.iter().enumerate() {
            for dx in 0..font::GLYPH_WIDTH {
                // Glyph rows are stored MSB-leftmost, so bit 7 is the leftmost
                // pixel; see tools/gen-font.py.
                let lit = bits & (0x80 >> dx) != 0;
                let colour = if lit {
                    self.foreground
                } else {
                    self.background
                };
                self.put_pixel(origin_x + dx as u64, origin_y + dy as u64, colour);
            }
        }
    }

    /// Scrolls the display up by one character row.
    fn scroll(&mut self) {
        let row_bytes = self.fb.pitch as usize * font::GLYPH_HEIGHT;
        let visible_bytes = self.fb.pitch as usize * self.fb.height as usize;
        let base = self.fb.address.as_u64() as *mut u8;

        // SAFETY: `base` maps at least `pitch * height` bytes -- that is what a
        // linear framebuffer of this geometry is. The copy moves
        // `visible_bytes - row_bytes` bytes from `base + row_bytes` down to
        // `base`, so both ranges lie entirely inside the mapping. `copy` has
        // memmove semantics, which is required because the ranges overlap.
        //
        // This is a non-volatile copy on purpose: it is a bulk move within
        // device memory where only the final state matters, and letting the
        // compiler emit a real `memcpy` is the difference between a scroll
        // that is instant and one that is visibly slow.
        unsafe {
            core::ptr::copy(base.add(row_bytes), base, visible_bytes - row_bytes);
        }

        // Clear the row that scrolled into view at the bottom.
        let first_blank_y = (self.rows - 1) * font::GLYPH_HEIGHT;
        for y in first_blank_y..self.fb.height as usize {
            for x in 0..self.fb.width {
                self.put_pixel(x, y as u64, self.background);
            }
        }
    }

    /// Moves the cursor to the start of the next line, scrolling if needed.
    fn newline(&mut self) {
        self.column = 0;
        if self.row + 1 < self.rows {
            self.row += 1;
        } else {
            self.scroll();
        }
    }

    /// Maps an SGR foreground code to a pixel colour.
    ///
    /// Only the eight normal and eight bright foregrounds, which is what the
    /// kernel emits. Anything else leaves the colour alone rather than
    /// guessing, so an unrecognised sequence is invisible instead of wrong.
    fn sgr(&mut self, code: u32) {
        let (r, g, b) = match code {
            0 => DEFAULT_FG,
            30 | 90 => (0x6c, 0x66, 0x5c),
            31 => (0xc8, 0x40, 0x2f),
            91 => (0xff, 0x6b, 0x52),
            32 => (0x4f, 0x9d, 0x3a),
            92 => (0x79, 0xd4, 0x5c),
            33 => (0xc8, 0x8a, 0x2f),
            93 => (0xff, 0xc9, 0x5c),
            34 => (0x3a, 0x7b, 0xd5),
            94 => (0x6a, 0xa8, 0xff),
            35 => (0x9d, 0x5c, 0xd4),
            95 => (0xc9, 0x8c, 0xff),
            36 => (0x38, 0x9d, 0x9d),
            96 => (0x5c, 0xd4, 0xd4),
            37 => (0xc8, 0xc4, 0xbd),
            97 => (0xff, 0xff, 0xff),
            _ => return,
        };
        self.foreground = self.fb.format.encode(r, g, b);
    }

    /// Writes one byte, handling `\n`, `\r`, `\t`, backspace, and the subset
    /// of ANSI escapes the kernel emits.
    pub fn write_byte(&mut self, byte: u8) {
        // Escapes first: a sequence's bytes are not text and must never reach
        // the glyph blitter.
        match self.escape {
            Escape::None => {
                if byte == 0x1b {
                    self.escape = Escape::Seen;
                    return;
                }
            }
            Escape::Seen => {
                self.escape = if byte == b'[' {
                    Escape::Csi
                } else {
                    Escape::None
                };
                self.param = 0;
                return;
            }
            Escape::Csi => {
                match byte {
                    b'0'..=b'9' => {
                        self.param = self.param.saturating_mul(10) + u32::from(byte - b'0')
                    }
                    b';' => {
                        self.sgr(self.param);
                        self.param = 0;
                    }
                    // Any final byte ends the sequence. `m` is the only one
                    // that means anything here; the rest are consumed so they
                    // cannot be drawn.
                    0x40..=0x7e => {
                        if byte == b'm' {
                            self.sgr(self.param);
                        }
                        self.escape = Escape::None;
                        self.param = 0;
                    }
                    _ => {}
                }
                return;
            }
        }

        match byte {
            b'\n' => self.newline(),
            b'\r' => self.column = 0,
            b'\t' => {
                // Advance to the next multiple of 8, and wrap if that would
                // run off the right edge.
                let next = (self.column + 8) & !7;
                if next >= self.columns {
                    self.newline();
                } else {
                    self.column = next;
                }
            }
            0x08 => {
                if self.column > 0 {
                    self.column -= 1;
                    self.draw_glyph(b' ', self.column, self.row);
                }
            }
            _ => {
                if self.column >= self.columns {
                    self.newline();
                }
                self.draw_glyph(byte, self.column, self.row);
                self.column += 1;
            }
        }
    }

    /// Writes a string.
    pub fn write_str(&mut self, s: &str) {
        for byte in s.bytes() {
            self.write_byte(byte);
        }
    }
}
