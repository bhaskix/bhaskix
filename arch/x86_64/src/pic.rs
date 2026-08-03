// SPDX-License-Identifier: Apache-2.0
//! The legacy 8259 programmable interrupt controller.
//!
//! Bhaskix does not use the PIC — the Local APIC replaces it entirely. This
//! module exists only to shut it down safely, which is not the same as
//! ignoring it.
//!
//! # Why it must be remapped before it is masked
//!
//! The PIC powers up mapped to vectors 0x08-0x0F and 0x70-0x77. Those overlap
//! the CPU's architectural exceptions: IRQ0 (the timer) arrives on vector 8,
//! which is the double fault. An interrupt on that vector would be reported as
//! a double fault, with an error code that is really a timer tick, and the
//! resulting diagnostic would be confidently wrong — the worst kind.
//!
//! Masking alone does not fix this, because the PIC can still deliver
//! **spurious interrupts**. When an IRQ line drops between the CPU
//! acknowledging it and the PIC identifying it, the PIC reports IRQ7 (or IRQ15
//! on the slave) anyway. That happens regardless of the mask, so a masked but
//! unremapped PIC can still deliver vector 0x0F — an exception vector — at any
//! time.
//!
//! So: remap to 0x20-0x2F first, *then* mask. The spurious interrupts still
//! occur, but they land on vectors the kernel owns and can identify.

use crate::port::Port;

const PIC1_COMMAND: u16 = 0x20;
const PIC1_DATA: u16 = 0x21;
const PIC2_COMMAND: u16 = 0xa0;
const PIC2_DATA: u16 = 0xa1;

/// Vector the master PIC is remapped to. Its IRQ7 spurious vector is
/// `PIC1_OFFSET + 7`.
pub const PIC1_OFFSET: u8 = 0x20;
/// Vector the slave PIC is remapped to.
pub const PIC2_OFFSET: u8 = 0x28;

/// Begin initialisation, and expect an ICW4.
const ICW1_INIT: u8 = 0x11;
/// 8086/88 mode.
const ICW4_8086: u8 = 0x01;

/// A port write to an unused port, used to waste time.
///
/// The 8259 needs a short settling delay between initialisation words on
/// genuinely old hardware. Port 0x80 is the POST diagnostic port: writing to
/// it is harmless everywhere and takes roughly a microsecond on the ISA bus.
/// Modern machines do not need this, but it costs nanoseconds and the
/// alternative is a rare, unreproducible bring-up failure on old hardware.
fn io_wait() {
    let scratch: Port<u8> = Port::new(0x80);
    // SAFETY: port 0x80 is the POST code port. Writing to it has no effect on
    // any system Bhaskix targets; it is the conventional I/O delay.
    unsafe { scratch.write(0) };
}

/// Remaps both PICs clear of the exception vectors and masks every line.
///
/// # Safety
///
/// Must be called once, during boot, with interrupts disabled. Reprogramming
/// the PIC while an interrupt is in flight leaves it in an undefined state.
pub unsafe fn remap_and_mask() {
    let pic1_command: Port<u8> = Port::new(PIC1_COMMAND);
    let pic1_data: Port<u8> = Port::new(PIC1_DATA);
    let pic2_command: Port<u8> = Port::new(PIC2_COMMAND);
    let pic2_data: Port<u8> = Port::new(PIC2_DATA);

    // SAFETY: this is the documented 8259 initialisation sequence, written to
    // the architectural PIC ports. The caller guarantees interrupts are
    // disabled and that this runs once.
    unsafe {
        // ICW1: start initialisation on both chips.
        pic1_command.write(ICW1_INIT);
        io_wait();
        pic2_command.write(ICW1_INIT);
        io_wait();

        // ICW2: the vector offsets. This is the step that matters.
        pic1_data.write(PIC1_OFFSET);
        io_wait();
        pic2_data.write(PIC2_OFFSET);
        io_wait();

        // ICW3: how the two chips are wired. The slave hangs off the master's
        // IRQ2 line, expressed as a bitmask to the master and as a number to
        // the slave -- an asymmetry in the hardware, not a mistake here.
        pic1_data.write(1 << 2);
        io_wait();
        pic2_data.write(2);
        io_wait();

        // ICW4: 8086 mode rather than the original 8080 mode.
        pic1_data.write(ICW4_8086);
        io_wait();
        pic2_data.write(ICW4_8086);
        io_wait();

        // Mask every line. The Local APIC handles interrupt delivery from
        // here; nothing should arrive through the PIC again.
        pic1_data.write(0xff);
        pic2_data.write(0xff);
    }
}

/// Whether `vector` is one of the two spurious vectors the masked PICs can
/// still deliver.
///
/// A spurious interrupt must **not** be acknowledged with an end-of-interrupt:
/// the PIC never raised a real in-service bit for it, so an EOI would clear
/// some other interrupt's. Silently ignoring it is correct.
#[must_use]
pub const fn is_spurious(vector: u64) -> bool {
    vector == (PIC1_OFFSET + 7) as u64 || vector == (PIC2_OFFSET + 7) as u64
}
