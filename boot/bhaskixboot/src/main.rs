// SPDX-License-Identifier: Apache-2.0
//! `bhaskixboot.efi` — the native UEFI loader, RFC 0028.
//!
//! Step 1 is a skeleton with a pulse: enter from the firmware, say who we
//! are on both consoles — the firmware's text output and the serial port
//! the harness reads — and return control cleanly. Every later step grows
//! from here, and the lane's gate list grows with it; what this step
//! proves is the toolchain, the entry convention, and that the first words
//! on the wire are ours.
//!
//! # The bindings are hand-rolled, and hostile
//!
//! No external UEFI crate: the dependency allowlist is empty on purpose,
//! and a boot loader is the worst possible place for the first exception
//! (`docs/security.md` §1). This file defines exactly the slice of the
//! UEFI surface it consumes — a table header, the text-output protocol's
//! first two function slots, the system table down to `con_out` — and
//! treats every firmware answer as hostile input: checked before use,
//! refused with a printed sentence rather than trusted.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

/// The UEFI system table's signature, `IBI SYST` little-endian. A table
/// that does not open with it is not a system table, whatever handed it
/// over.
const SYSTEM_TABLE_SIGNATURE: u64 = 0x5453_5953_2049_4249;

/// `EFI_SUCCESS`.
const SUCCESS: usize = 0;

/// The common header every UEFI table opens with.
#[repr(C)]
struct TableHeader {
    signature: u64,
    revision: u32,
    header_size: u32,
    crc32: u32,
    reserved: u32,
}

/// The simple-text-output protocol, down to the one slot this step calls.
///
/// The layout is fixed by the UEFI specification: a `Reset` function
/// pointer first, `OutputString` second. Nothing past the slots consumed
/// is declared, so nothing past them can be misused by accident.
#[repr(C)]
struct SimpleTextOutput {
    reset: usize,
    output_string:
        unsafe extern "efiapi" fn(this: *mut SimpleTextOutput, string: *const u16) -> usize,
}

/// The system table, down to `con_out`. Later steps extend this struct as
/// they consume more of it — boot services arrive with the memory map
/// step, the configuration tables with ACPI's — and each extension is a
/// reviewed line, not a vendored crate.
#[repr(C)]
struct SystemTable {
    hdr: TableHeader,
    firmware_vendor: *const u16,
    firmware_revision: u32,
    console_in_handle: usize,
    con_in: usize,
    console_out_handle: usize,
    con_out: *mut SimpleTextOutput,
}

/// The banner, and the line the harness's gate demands verbatim.
const BANNER: &str = "bhaskixboot 0.0.0: the machine entered through our own door\r\n";

/// COM1, spoken directly. A UEFI application runs with I/O privilege, and
/// the harness reads the serial line — the same wire every kernel report
/// travels — so the loader's first words go where every later gate will
/// look.
mod serial {
    const COM1: u16 = 0x3F8;

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

    /// 115200 8n1, FIFOs on — the same shape the kernel programs, so the
    /// wire does not change dialect between loader and kernel.
    pub fn init() {
        outb(COM1 + 1, 0x00);
        outb(COM1 + 3, 0x80);
        outb(COM1, 0x01);
        outb(COM1 + 1, 0x00);
        outb(COM1 + 3, 0x03);
        outb(COM1 + 2, 0xC7);
        outb(COM1 + 4, 0x0B);
    }

    /// Writes one byte, waiting for the transmitter, bounded so a machine
    /// with no COM1 cannot hang the boot on a banner.
    pub fn write_byte(byte: u8) {
        for _ in 0..100_000u32 {
            if inb(COM1 + 5) & 0x20 != 0 {
                break;
            }
        }
        outb(COM1, byte);
    }

    /// Writes a string.
    pub fn write(text: &str) {
        for byte in text.bytes() {
            write_byte(byte);
        }
    }
}

/// Prints `text` on the firmware console, UCS-2 encoded in bounded chunks.
///
/// Best-effort by design: a firmware whose console refuses loses the
/// pretty copy, and the serial copy — the one the gates read — has already
/// gone out.
fn console_write(con_out: *mut SimpleTextOutput, text: &str) {
    let mut buffer = [0u16; 64];
    let mut at = 0;
    for byte in text.bytes() {
        buffer[at] = u16::from(byte);
        at += 1;
        if at == buffer.len() - 1 {
            buffer[at] = 0;
            // SAFETY: `con_out` was validated non-null by the caller and the
            // buffer is NUL-terminated; the call follows the protocol's own
            // signature.
            unsafe { ((*con_out).output_string)(con_out, buffer.as_ptr()) };
            at = 0;
        }
    }
    if at > 0 {
        buffer[at] = 0;
        // SAFETY: as above.
        unsafe { ((*con_out).output_string)(con_out, buffer.as_ptr()) };
    }
}

/// The entry point the UEFI firmware calls, by the target's convention.
///
/// Not `pub`: the firmware finds it by the PE entry address, not by Rust
/// visibility, and keeping it private keeps the table types private too.
#[unsafe(no_mangle)]
extern "efiapi" fn efi_main(_image_handle: usize, system_table: *mut SystemTable) -> usize {
    serial::init();
    serial::write(BANNER);

    // The firmware's own console gets the banner too — but only after the
    // table proves it is one. A null or mis-signed table loses the pretty
    // copy and is *said* on serial, because a loader that trusts the first
    // pointer it is handed has already lost the argument this project
    // makes about hostile input.
    if system_table.is_null() {
        serial::write("bhaskixboot: the firmware handed no system table\r\n");
        return SUCCESS;
    }
    // SAFETY: non-null, and read before any deeper field is trusted; the
    // signature check below is what earns the rest of the struct.
    let signature = unsafe { (*system_table).hdr.signature };
    if signature != SYSTEM_TABLE_SIGNATURE {
        serial::write("bhaskixboot: the system table's signature is wrong; not touching it\r\n");
        return SUCCESS;
    }
    // SAFETY: signature-checked table; `con_out` is the field the
    // specification puts seventh, and null is checked before use.
    let con_out = unsafe { (*system_table).con_out };
    if !con_out.is_null() {
        console_write(con_out, BANNER);
    }

    // Step 1 ends here: control goes back to the firmware, cleanly. The
    // payload, the machine's shape, the tables and the jump are the steps
    // that grow from this line.
    SUCCESS
}

/// There is nowhere to unwind to and no kernel to report through.
#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    serial::write("bhaskixboot: panic\r\n");
    loop {
        // SAFETY: `hlt` with interrupts as the firmware left them; a wedged
        // loader parks instead of spinning a core hot.
        unsafe { core::arch::asm!("hlt", options(nomem, nostack)) };
    }
}
