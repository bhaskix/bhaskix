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
//!
//! **A scroll never reads the screen back** (2026-10-12). It used to move the
//! whole visible frame up one row with a `memcpy` inside video memory -- about
//! 3 MiB read and written per line at 1024x768 -- which is instant where the
//! framebuffer is ordinary memory, as under QEMU, and on the SR550, whose
//! framebuffer is the BMC's video memory across PCIe, paced the entire boot
//! report at about 100--160 bytes a second: 589 s to services up. The console
//! now keeps its text in a [`Grid`] in RAM, and a scroll shifts the grid and
//! redraws only the cells whose character or colour changed -- writes only.
//! Every scroll is timed, and the boot report says what one costs.

use core::sync::atomic::{AtomicU64, Ordering};

use bhaskix_boot::Framebuffer;

use crate::font;

/// Cells the [`Grid`] holds: 256 columns by 128 rows, a 2048x2048 screen in
/// the 8x16 font. A larger screen falls back to scrolling in video memory.
pub const GRID_CELLS: usize = 256 * 128;

/// One character cell as the console remembers it: the byte drawn and the
/// palette index it was drawn in. A zero byte is a blank cell, so a grid of
/// zeros is an empty screen and costs nothing in the image.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cell {
    byte: u8,
    colour: u8,
}

impl Cell {
    /// The empty cell.
    pub const BLANK: Self = Self { byte: 0, colour: 0 };

    /// Whether drawing this cell paints only background: a blank or a space,
    /// whatever its colour.
    const fn is_blank(self) -> bool {
        self.byte == 0 || self.byte == b' '
    }

    /// Whether two cells look the same on screen.
    fn looks_like(self, other: Self) -> bool {
        (self.is_blank() && other.is_blank()) || self == other
    }
}

/// The text on screen, kept in RAM so a scroll can be redrawn from it.
pub struct Grid {
    cells: [Cell; GRID_CELLS],
}

impl Grid {
    /// An empty screen.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            cells: [Cell::BLANK; GRID_CELLS],
        }
    }
}

impl Default for Grid {
    fn default() -> Self {
        Self::new()
    }
}

/// Shifts `cells` -- `columns` by `rows`, row-major -- up by one row, blanks
/// the last, and calls `draw` for every cell whose look changed, with its
/// column, row and new content. Pure: what reaches the screen is `draw`'s.
fn scroll_cells(
    cells: &mut [Cell],
    columns: usize,
    rows: usize,
    mut draw: impl FnMut(usize, usize, Cell),
) {
    for row in 0..rows {
        for column in 0..columns {
            let here = row * columns + column;
            let next = if row + 1 < rows {
                cells[here + columns]
            } else {
                Cell::BLANK
            };
            if !cells[here].looks_like(next) {
                draw(column, row, next);
            }
            cells[here] = next;
        }
    }
}

/// Scrolls so far: how many, their total and worst cost in TSC ticks, and how
/// many were redrawn from the grid rather than moved in video memory.
static SCROLLS: AtomicU64 = AtomicU64::new(0);
static SCROLL_TICKS: AtomicU64 = AtomicU64::new(0);
static SCROLL_WORST: AtomicU64 = AtomicU64::new(0);
static SCROLLS_FROM_GRID: AtomicU64 = AtomicU64::new(0);

/// `(scrolls, total ticks, worst ticks, scrolls redrawn from the grid)`.
#[must_use]
pub fn scroll_statistics() -> (u64, u64, u64, u64) {
    (
        SCROLLS.load(Ordering::Relaxed),
        SCROLL_TICKS.load(Ordering::Relaxed),
        SCROLL_WORST.load(Ordering::Relaxed),
        SCROLLS_FROM_GRID.load(Ordering::Relaxed),
    )
}

/// Foreground colour: near-white, slightly warm.
const DEFAULT_FG: (u8, u8, u8) = (0xe8, 0xe8, 0xe4);

/// Background colour: near-black, slightly blue.
const DEFAULT_BG: (u8, u8, u8) = (0x0a, 0x0c, 0x10);

/// The SGR foregrounds this console draws -- the eight normal and eight
/// bright, which is what the kernel emits -- each with its colour. A
/// [`Cell`]'s palette index is one past its place here; zero is the default.
const SGR: [(u8, (u8, u8, u8)); 16] = [
    (30, (0x6c, 0x66, 0x5c)),
    (90, (0x6c, 0x66, 0x5c)),
    (31, (0xc8, 0x40, 0x2f)),
    (91, (0xff, 0x6b, 0x52)),
    (32, (0x4f, 0x9d, 0x3a)),
    (92, (0x79, 0xd4, 0x5c)),
    (33, (0xc8, 0x8a, 0x2f)),
    (93, (0xff, 0xc9, 0x5c)),
    (34, (0x3a, 0x7b, 0xd5)),
    (94, (0x6a, 0xa8, 0xff)),
    (35, (0x9d, 0x5c, 0xd4)),
    (95, (0xc9, 0x8c, 0xff)),
    (36, (0x38, 0x9d, 0x9d)),
    (96, (0x5c, 0xd4, 0xd4)),
    (37, (0xc8, 0xc4, 0xbd)),
    (97, (0xff, 0xff, 0xff)),
];

/// A character cell console drawn onto a linear framebuffer.
pub struct FbConsole {
    fb: Framebuffer,
    columns: usize,
    rows: usize,
    column: usize,
    row: usize,
    foreground: u32,
    background: u32,
    /// The palette index `foreground` came from, which is what a [`Cell`]
    /// remembers.
    colour: u8,
    /// Every palette colour, encoded for this framebuffer: the default, then
    /// the sixteen SGR foregrounds in [`SGR`]'s order.
    palette: [u32; 17],
    /// Whether the screen fits the [`Grid`]; if not, scrolls move video memory.
    gridded: bool,
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

        let mut palette = [0u32; 17];
        palette[0] = fb.format.encode(DEFAULT_FG.0, DEFAULT_FG.1, DEFAULT_FG.2);
        for (slot, &(_, (r, g, b))) in palette[1..].iter_mut().zip(SGR.iter()) {
            *slot = fb.format.encode(r, g, b);
        }
        let mut console = Self {
            foreground: palette[0],
            background: fb.format.encode(DEFAULT_BG.0, DEFAULT_BG.1, DEFAULT_BG.2),
            colour: 0,
            palette,
            gridded: columns * rows <= GRID_CELLS,
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

    /// Draws through `address` from now on: another mapping of the same
    /// pixels, made after this console was.
    pub fn move_to(&mut self, address: u64) {
        self.fb.address = bhaskix_boot::VirtAddr(address);
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

    /// Draws one glyph at character cell `(column, row)` in the current colour.
    fn draw_glyph(&self, byte: u8, column: usize, row: usize) {
        self.draw_glyph_in(byte, column, row, self.foreground);
    }

    /// Draws one glyph at character cell `(column, row)` in `foreground`.
    fn draw_glyph_in(&self, byte: u8, column: usize, row: usize, foreground: u32) {
        let bitmap = font::glyph(byte);
        let origin_x = (column * font::GLYPH_WIDTH) as u64;
        let origin_y = (row * font::GLYPH_HEIGHT) as u64;

        for (dy, bits) in bitmap.iter().enumerate() {
            for dx in 0..font::GLYPH_WIDTH {
                // Glyph rows are stored MSB-leftmost, so bit 7 is the leftmost
                // pixel; see tools/gen-font.py.
                let lit = bits & (0x80 >> dx) != 0;
                let colour = if lit { foreground } else { self.background };
                self.put_pixel(origin_x + dx as u64, origin_y + dy as u64, colour);
            }
        }
    }

    /// Draws `byte` at the cursor's cell and remembers it in `grid`.
    fn put(&self, grid: &mut Grid, byte: u8, column: usize, row: usize) {
        self.draw_glyph(byte, column, row);
        if self.gridded {
            grid.cells[row * self.columns + column] = Cell {
                byte,
                colour: self.colour,
            };
        }
    }

    /// Scrolls the display up by one character row, and times it.
    fn scroll(&mut self, grid: &mut Grid) {
        let started = bhaskix_arch::tsc::read();
        if self.gridded {
            let (columns, rows) = (self.columns, self.rows);
            let cells = &mut grid.cells[..columns * rows];
            scroll_cells(cells, columns, rows, |column, row, cell| {
                let foreground = self
                    .palette
                    .get(usize::from(cell.colour))
                    .copied()
                    .unwrap_or(self.palette[0]);
                let byte = if cell.byte == 0 { b' ' } else { cell.byte };
                self.draw_glyph_in(byte, column, row, foreground);
            });
            SCROLLS_FROM_GRID.fetch_add(1, Ordering::Relaxed);
        } else {
            self.scroll_in_video_memory();
        }
        let spent = bhaskix_arch::tsc::read().saturating_sub(started);
        SCROLLS.fetch_add(1, Ordering::Relaxed);
        SCROLL_TICKS.fetch_add(spent, Ordering::Relaxed);
        SCROLL_WORST.fetch_max(spent, Ordering::Relaxed);
    }

    /// Scrolls by moving the frame in video memory -- for a screen too large
    /// for the [`Grid`]. Reads video memory back, which is what makes it slow
    /// where that memory is across a bus.
    fn scroll_in_video_memory(&mut self) {
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
    fn newline(&mut self, grid: &mut Grid) {
        self.column = 0;
        if self.row + 1 < self.rows {
            self.row += 1;
        } else {
            self.scroll(grid);
        }
    }

    /// Maps an SGR foreground code to a pixel colour.
    ///
    /// Only the eight normal and eight bright foregrounds, which is what the
    /// kernel emits. Anything else leaves the colour alone rather than
    /// guessing, so an unrecognised sequence is invisible instead of wrong.
    fn sgr(&mut self, code: u32) {
        if code == 0 {
            self.colour = 0;
            self.foreground = self.palette[0];
            return;
        }
        let Some(index) = SGR.iter().position(|&(sgr, _)| u32::from(sgr) == code) else {
            return;
        };
        self.colour = index as u8 + 1;
        self.foreground = self.palette[index + 1];
    }

    /// Writes one byte, handling `\n`, `\r`, `\t`, backspace, and the subset
    /// of ANSI escapes the kernel emits.
    pub fn write_byte(&mut self, grid: &mut Grid, byte: u8) {
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
            b'\n' => self.newline(grid),
            b'\r' => self.column = 0,
            b'\t' => {
                // Advance to the next multiple of 8, and wrap if that would
                // run off the right edge.
                let next = (self.column + 8) & !7;
                if next >= self.columns {
                    self.newline(grid);
                } else {
                    self.column = next;
                }
            }
            0x08 => {
                if self.column > 0 {
                    self.column -= 1;
                    self.put(grid, b' ', self.column, self.row);
                }
            }
            _ => {
                if self.column >= self.columns {
                    self.newline(grid);
                }
                self.put(grid, byte, self.column, self.row);
                self.column += 1;
            }
        }
    }

    /// Writes a string.
    pub fn write_str(&mut self, grid: &mut Grid, s: &str) {
        for byte in s.bytes() {
            self.write_byte(grid, byte);
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::{Cell, scroll_cells};
    use std::vec::Vec;

    fn cell(byte: u8, colour: u8) -> Cell {
        Cell { byte, colour }
    }

    /// A scroll shifts every row up, blanks the last, and redraws exactly the
    /// cells whose look changed -- a blank and a space look alike, and so do
    /// two blanks of different colours.
    #[test]
    fn a_scroll_redraws_only_what_changed() {
        // Three columns, three rows:
        //   "ab "      row 0
        //   "a c"      row 1  (the 'a' is the same as above; the space is blank)
        //   "xyz"      row 2, 'z' in colour 3
        let mut cells = Vec::from([
            cell(b'a', 0),
            cell(b'b', 0),
            cell(0, 0),
            cell(b'a', 0),
            cell(b' ', 2),
            cell(b'c', 0),
            cell(b'x', 0),
            cell(b'y', 0),
            cell(b'z', 3),
        ]);
        let mut drawn = Vec::new();
        scroll_cells(&mut cells, 3, 3, |column, row, new| {
            drawn.push((column, row, new))
        });
        assert_eq!(
            cells,
            [
                cell(b'a', 0),
                cell(b' ', 2),
                cell(b'c', 0),
                cell(b'x', 0),
                cell(b'y', 0),
                cell(b'z', 3),
                Cell::BLANK,
                Cell::BLANK,
                Cell::BLANK,
            ]
        );
        assert_eq!(
            drawn,
            [
                // Row 0: 'a' stays 'a'; 'b' becomes a space; blank becomes 'c'.
                (1, 0, cell(b' ', 2)),
                (2, 0, cell(b'c', 0)),
                // Row 1: every cell changes.
                (0, 1, cell(b'x', 0)),
                (1, 1, cell(b'y', 0)),
                (2, 1, cell(b'z', 3)),
                // Row 2: every cell had text and is blanked.
                (0, 2, Cell::BLANK),
                (1, 2, Cell::BLANK),
                (2, 2, Cell::BLANK),
            ]
        );
    }

    /// The same character in another colour is a change; a blank that stays
    /// blank is not, so a mostly empty screen scrolls for almost nothing.
    #[test]
    fn colour_counts_and_blank_rows_cost_nothing() {
        let mut cells = Vec::from([cell(b'q', 1), cell(b'q', 2), Cell::BLANK, Cell::BLANK]);
        let mut drawn = Vec::new();
        scroll_cells(&mut cells, 1, 4, |column, row, new| {
            drawn.push((column, row, new))
        });
        assert_eq!(drawn, [(0, 0, cell(b'q', 2)), (0, 1, Cell::BLANK)]);
    }
}
