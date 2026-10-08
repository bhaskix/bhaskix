// SPDX-License-Identifier: Apache-2.0
//! The loader's words, through the firmware's serial port where there is one
//! and the UARTs' registers where there is not.
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
//!
//! # Which port
//!
//! **COM1, and COM2 as well when COM2 is there.** Until 2026-10-08 this module
//! wrote COM1 only — and the SR550, the one physical machine the loader has
//! met, carries COM2 to its service processor and not COM1. The kernel learned
//! that on 2026-08-23 and writes both; the loader never did, so on that machine
//! everything it wrote to the registers after its banner went to a port nobody
//! was reading. COM2 is found by its scratch register and is **not
//! reprogrammed**: on a server the firmware configured it for the service
//! processor, and the loader has no better settings to offer it.

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

const COM1: u16 = 0x3F8;
/// The second UART, the one a service processor carries on the SR550.
const COM2: u16 = 0x2F8;
/// A UART's scratch register: no function, so what is written comes back
/// only if a UART is there to hold it.
const SCRATCH: u16 = 7;

/// The firmware's serial protocol, or zero while the port is ours to write.
static FIRMWARE_PORT: AtomicUsize = AtomicUsize::new(0);

/// Whether COM2's scratch register answered at [`init`].
static SECOND: AtomicBool = AtomicBool::new(false);

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
    // privileged for; the ports written are COM1's and COM2's, whose
    // registers this module writes only while no firmware protocol is
    // adopted.
    unsafe {
        core::arch::asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack));
    }
}

fn inb(port: u16) -> u8 {
    let value: u8;
    // SAFETY: as in `outb` — a privileged read of a UART register.
    unsafe {
        core::arch::asm!("in al, dx", in("dx") port, out("al") value, options(nomem, nostack));
    }
    value
}

/// Whether a UART answers at `base`: two patterns through its scratch
/// register, and the register put back as it was found.
fn answers(base: u16) -> bool {
    let found = inb(base + SCRATCH);
    let mut answered = true;
    for pattern in [0xA5, 0x5A] {
        outb(base + SCRATCH, pattern);
        answered &= inb(base + SCRATCH) == pattern;
    }
    outb(base + SCRATCH, found);
    answered
}

/// 115200 8n1, FIFOs on — the same shape the kernel programs, so the wire
/// does not change dialect between loader and kernel. COM2 is probed and left
/// as the firmware set it.
pub fn init() {
    outb(COM1 + 1, 0x00);
    outb(COM1 + 3, 0x80);
    outb(COM1, 0x01);
    outb(COM1 + 1, 0x00);
    outb(COM1 + 3, 0x03);
    outb(COM1 + 2, 0xC7);
    outb(COM1 + 4, 0x0B);
    SECOND.store(answers(COM2), Ordering::Relaxed);
}

/// Writes one byte to the UART at `base`, waiting for the transmitter,
/// bounded so a machine with no UART there cannot hang the boot on a banner.
fn put(base: u16, byte: u8) {
    for _ in 0..100_000u32 {
        if inb(base + 5) & 0x20 != 0 {
            break;
        }
    }
    outb(base, byte);
}

/// Writes one byte to COM1, and to COM2 when it answered.
fn write_byte(byte: u8) {
    put(COM1, byte);
    if SECOND.load(Ordering::Relaxed) {
        put(COM2, byte);
    }
}

/// Writes a string, through the firmware's port when it has been adopted.
pub fn write(text: &str) {
    write_bytes(text.as_bytes());
}

/// Writes bytes, through the firmware's port when it has been adopted.
///
/// **The one place the choice is made.** Until 2026-10-08 the number writers
/// below wrote the registers directly whatever was adopted, so every number
/// printed during boot services went underneath the firmware's own driver.
fn write_bytes(bytes: &[u8]) {
    let firmware = FIRMWARE_PORT.load(Ordering::Relaxed);
    if firmware != 0 {
        crate::efi::serial_io_write(firmware as *mut core::ffi::c_void, bytes);
        return;
    }
    for byte in bytes {
        write_byte(*byte);
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
    write_bytes(&digits[at..]);
}

/// Writes a number as `0x` and sixteen hex digits, fixed width so the
/// harness's comparison is a string equality and not a parse.
pub fn write_hex(value: u64) {
    let mut digits = *b"0x0000000000000000";
    for (at, shift) in (0..16).rev().enumerate() {
        let nibble = ((value >> (shift * 4)) & 0xF) as u8;
        digits[2 + at] = if nibble < 10 {
            b'0' + nibble
        } else {
            b'a' + nibble - 10
        };
    }
    write_bytes(&digits);
}
