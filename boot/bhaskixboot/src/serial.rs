// SPDX-License-Identifier: Apache-2.0
//! The loader's words, through the firmware's serial port where there is one
//! and COM1's registers where there is not.
//!
//! The harness reads the serial line — the same wire every kernel report
//! travels — so the loader's words go where every later gate will look. The
//! number formatters are hand-rolled rather than `core::fmt` because the
//! loader's whole vocabulary is "a name, a number, a sentence", and the
//! formatting machinery would be the largest thing in the binary.
//!
//! # Whose port it is
//!
//! **Until `ExitBootServices` the serial port belongs to the firmware**, which
//! may have a driver on it, may be redirecting a console through it, and on a
//! server may be trapping its I/O ports into SMM for a service processor. This
//! module wrote the registers underneath all of that until 2026-08-22, which
//! works on QEMU and is not what the specification describes: UEFI §12 provides
//! `EFI_SERIAL_IO_PROTOCOL` for exactly this, and it is what loaders on EFI use.
//!
//! So: [`adopt_firmware_port`] once the system table is validated, and
//! [`release_firmware_port`] before boot services end, after which the protocol
//! is gone and the registers are ours. Before the first and after the second,
//! the port is written directly — there is no alternative in either window, and
//! both are short.

use core::sync::atomic::{AtomicUsize, Ordering};

const COM1: u16 = 0x3F8;

/// The firmware's serial protocol, or zero while the port is ours to write.
static FIRMWARE_PORT: AtomicUsize = AtomicUsize::new(0);

/// Uses the firmware's serial port for everything written from now on.
pub fn adopt_firmware_port(protocol: *mut core::ffi::c_void) {
    FIRMWARE_PORT.store(protocol as usize, Ordering::Relaxed);
}

/// Gives the firmware's port back, before its boot services end.
///
/// **Not optional.** The protocol's function pointers live in memory the
/// firmware reclaims at `ExitBootServices`; calling one afterwards is a jump
/// into whatever replaced it.
pub fn release_firmware_port() {
    FIRMWARE_PORT.store(0, Ordering::Relaxed);
}

fn outb(port: u16, value: u8) {
    // SAFETY: a write to a legacy I/O port, which a UEFI application is
    // privileged for; the ports written are COM1's, whose registers this
    // module owns for the loader's lifetime.
    unsafe {
        core::arch::asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack));
    }
}

fn inb(port: u16) -> u8 {
    let value: u8;
    // SAFETY: as in `outb` — a privileged read of COM1's line-status
    // register.
    unsafe {
        core::arch::asm!("in al, dx", in("dx") port, out("al") value, options(nomem, nostack));
    }
    value
}

/// 115200 8n1, FIFOs on — the same shape the kernel programs, so the wire
/// does not change dialect between loader and kernel.
pub fn init() {
    outb(COM1 + 1, 0x00);
    outb(COM1 + 3, 0x80);
    outb(COM1, 0x01);
    outb(COM1 + 1, 0x00);
    outb(COM1 + 3, 0x03);
    outb(COM1 + 2, 0xC7);
    outb(COM1 + 4, 0x0B);
}

/// Writes one byte, waiting for the transmitter, bounded so a machine with
/// no COM1 cannot hang the boot on a banner.
pub fn write_byte(byte: u8) {
    for _ in 0..100_000u32 {
        if inb(COM1 + 5) & 0x20 != 0 {
            break;
        }
    }
    outb(COM1, byte);
}

/// Writes a string, through the firmware's port when it has been adopted.
pub fn write(text: &str) {
    let firmware = FIRMWARE_PORT.load(Ordering::Relaxed);
    if firmware != 0 {
        crate::efi::serial_io_write(firmware as *mut core::ffi::c_void, text.as_bytes());
        return;
    }
    for byte in text.bytes() {
        write_byte(byte);
    }
}

/// Writes a decimal number.
pub fn write_dec(mut value: u64) {
    let mut digits = [0u8; 20];
    let mut at = digits.len();
    loop {
        at -= 1;
        digits[at] = b'0' + (value % 10) as u8;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    for digit in &digits[at..] {
        write_byte(*digit);
    }
}

/// Writes a number as `0x` and sixteen hex digits, fixed width so the
/// harness's comparison is a string equality and not a parse.
pub fn write_hex(value: u64) {
    write("0x");
    for shift in (0..16).rev() {
        let nibble = ((value >> (shift * 4)) & 0xF) as u8;
        write_byte(if nibble < 10 {
            b'0' + nibble
        } else {
            b'a' + nibble - 10
        });
    }
}
