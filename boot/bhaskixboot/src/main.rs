// SPDX-License-Identifier: Apache-2.0
//! `bhaskixboot.efi` — the native UEFI loader, RFC 0028.
//!
//! Steps 1 and 2: enter from the firmware, say who we are on both consoles,
//! then read the payload — the kernel, the initrd and the configuration —
//! off the boot volume, and print each one's size and checksum for the
//! lane's gate to compare against the build's own. Nothing is loaded into
//! place yet; step 2's whole claim is *integrity*: the bytes the firmware
//! serves us are the bytes the build produced, proven before any of them
//! is trusted to run.
//!
//! # The bindings are hand-rolled, and hostile
//!
//! No external UEFI crate: the dependency allowlist is empty on purpose,
//! and a boot loader is the worst possible place for the first exception
//! (`docs/security.md` §1). This file defines exactly the slice of the
//! UEFI surface it consumes, and treats every firmware answer as hostile
//! input: checked before use, refused with a printed sentence rather than
//! trusted. The struct layouts transcribe the UEFI specification's tables;
//! the lane is what verifies the transcription — a wrong offset produces a
//! wrong banner or a refused file, never a silent pass.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

mod efi;
mod serial;

use efi::{File, SimpleTextOutput, SystemTable};

/// The banner, and the line the harness's gate demands verbatim.
const BANNER: &str = "bhaskixboot 0.0.0: the machine entered through our own door\r\n";

/// Where the payload lives on the boot volume, beside `EFI\BOOT`. The
/// harness stages the same three files; the kernel and the initrd are
/// required, the configuration is optional and an absent one is an empty
/// command line, said out loud.
const KERNEL_PATH: &str = "bhaskix\\kernel";
const INITRD_PATH: &str = "bhaskix\\initrd.tar";
const CONFIG_PATH: &str = "bhaskix\\boot.conf";

/// FNV-1a, 64-bit — the same arithmetic the telemetry registry hash uses,
/// chosen for the same reason: trivial to state, trivial for the harness
/// to recompute, and any single flipped bit moves it.
struct Fnv(u64);

impl Fnv {
    const fn new() -> Self {
        Self(0xcbf2_9ce4_8422_2325)
    }

    fn eat(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.0 ^= u64::from(*byte);
            self.0 = self.0.wrapping_mul(0x0000_0100_0000_01B3);
        }
    }
}

/// Streams one file through the checksum: read in page-sized chunks, hash
/// and count, never allocate. Returns `(bytes, fnv)`, or the refusing
/// status.
fn digest(root: *mut File, path: &str) -> Result<(u64, u64), usize> {
    let file = efi::open_read_only(root, path)?;
    let mut hash = Fnv::new();
    let mut total = 0u64;
    let mut buffer = [0u8; 4096];
    loop {
        let got = match efi::read(file, &mut buffer) {
            Ok(got) => got,
            Err(status) => {
                efi::close(file);
                return Err(status);
            }
        };
        if got == 0 {
            break;
        }
        hash.eat(&buffer[..got]);
        total += got as u64;
    }
    efi::close(file);
    Ok((total, hash.0))
}

/// Prints one payload line in the exact shape the gate greps:
/// `bhaskixboot: payload <name> <bytes> bytes fnv <hex>`.
fn report_payload(name: &str, bytes: u64, fnv: u64) {
    serial::write("bhaskixboot: payload ");
    serial::write(name);
    serial::write(" ");
    serial::write_dec(bytes);
    serial::write(" bytes fnv ");
    serial::write_hex(fnv);
    serial::write("\r\n");
}

/// The entry point the UEFI firmware calls, by the target's convention.
///
/// Not `pub`: the firmware finds it by the PE entry address, not by Rust
/// visibility, and keeping it private keeps the table types private too.
#[unsafe(no_mangle)]
extern "efiapi" fn efi_main(image_handle: usize, system_table: *mut SystemTable) -> usize {
    serial::init();
    serial::write(BANNER);

    // The firmware's own console gets the banner too — but only after the
    // table proves it is one. A null or mis-signed table loses the pretty
    // copy and is *said* on serial, because a loader that trusts the first
    // pointer it is handed has already lost the argument this project
    // makes about hostile input.
    let Some(table) = efi::validate(system_table) else {
        serial::write("bhaskixboot: no valid system table; stopping at the banner\r\n");
        return efi::SUCCESS;
    };
    let con_out = efi::con_out(table);
    if let Some(con_out) = con_out {
        console_write(con_out, BANNER);
    }

    // Step 2: the payload's integrity. The volume this image booted from is
    // found through the image's own handle — the loaded-image protocol
    // names the device, the device serves a filesystem — and each hop is a
    // firmware answer that can refuse, with the refusal printed.
    let root = match efi::open_boot_volume(table, image_handle) {
        Ok(root) => root,
        Err(status) => {
            serial::write("bhaskixboot: the boot volume would not open, status ");
            serial::write_hex(status as u64);
            serial::write("\r\n");
            return efi::SUCCESS;
        }
    };

    for (name, path, required) in [
        ("kernel", KERNEL_PATH, true),
        ("initrd", INITRD_PATH, true),
        ("conf", CONFIG_PATH, false),
    ] {
        match digest(root, path) {
            Ok((bytes, fnv)) => report_payload(name, bytes, fnv),
            Err(status) if !required => {
                let _ = status;
                serial::write("bhaskixboot: payload conf absent; the command line is empty\r\n");
            }
            Err(status) => {
                serial::write("bhaskixboot: payload ");
                serial::write(name);
                serial::write(" REFUSED, status ");
                serial::write_hex(status as u64);
                serial::write("\r\n");
            }
        }
    }
    efi::close(root);

    // Step 2 ends here: control goes back to the firmware, cleanly. The
    // machine's shape, the tables and the jump are the steps that grow
    // from this line.
    efi::SUCCESS
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
            efi::output_string(con_out, &buffer);
            at = 0;
        }
    }
    if at > 0 {
        buffer[at] = 0;
        efi::output_string(con_out, &buffer);
    }
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
