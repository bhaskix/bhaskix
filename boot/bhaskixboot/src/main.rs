// SPDX-License-Identifier: Apache-2.0
//! `bhaskixboot.efi` — the native UEFI loader, RFC 0028.
//!
//! Steps 1 through 5: enter from the firmware and say so; read the kernel,
//! the initrd and the configuration into memory the loader owns, proving
//! every byte; take the machine's shape; exit boot services; then build
//! the world the kernel will be entered under — the identity and
//! higher-half maps, the kernel's segments placed W^X at their linked
//! addresses, and the `Handoff` assembled in reclaimable memory. The one
//! thing this step does not do is jump: step 6 opens the shim's second
//! door, and until then the loader parks on a machine it fully owns, with
//! everything the jump needs already standing.
//!
//! # The bindings are hand-rolled, and hostile
//!
//! No external UEFI crate: the dependency allowlist is empty on purpose,
//! and a boot loader is the worst possible place for the first exception
//! (`docs/security.md` §1). Every firmware answer is checked before use
//! and refused with a printed sentence rather than trusted; the kernel ELF
//! is parsed by the same fuzz-hardened `bhaskix-elf` the kernel itself
//! loads programs with.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

mod efi;
mod handoff;
mod paging;
mod serial;

use bhaskix_elf::{AddressHalf, PAGE_SIZE, page_span, parse_in};
use efi::{File, SimpleTextOutput, SystemTable};

/// The banner, and the line the harness's gate demands verbatim.
const BANNER: &str = "bhaskixboot 0.0.0: the machine entered through our own door\r\n";

/// Where the payload lives on the boot volume, beside `EFI\BOOT`.
const KERNEL_PATH: &str = "bhaskix\\kernel";
const INITRD_PATH: &str = "bhaskix\\initrd.tar";
const CONFIG_PATH: &str = "bhaskix\\boot.conf";

/// Pages allocated for each payload buffer: sixteen MiB for the kernel,
/// four for the initrd. A payload past its cap is a printed refusal, not a
/// silent truncation.
const KERNEL_BUFFER_PAGES: usize = 4096;
const INITRD_BUFFER_PAGES: usize = 1024;

/// Frames pre-allocated for the page tables. The builder counts what it
/// uses and refuses when the pool runs dry; the count is printed so the
/// guess is checked by every boot.
const TABLE_POOL_FRAMES: u64 = 128;

/// FNV-1a, 64-bit — the same arithmetic the harness recomputes.
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

/// Reads a whole file into `buffer`, returning how many bytes arrived.
///
/// A file that fills the buffer with more to come is refused — the caller
/// sized the buffer as a stated cap, and a payload past it is a different
/// payload than the build produced.
fn read_fully(root: *mut File, path: &str, buffer: &mut [u8]) -> Result<usize, usize> {
    let file = efi::open_read_only(root, path)?;
    let mut total = 0usize;
    loop {
        if total == buffer.len() {
            let mut probe = [0u8; 1];
            let more = efi::read(file, &mut probe).unwrap_or(0);
            efi::close(file);
            return if more == 0 {
                Ok(total)
            } else {
                Err(usize::MAX)
            };
        }
        let got = match efi::read(file, &mut buffer[total..]) {
            Ok(got) => got,
            Err(status) => {
                efi::close(file);
                return Err(status);
            }
        };
        if got == 0 {
            break;
        }
        total += got;
    }
    efi::close(file);
    Ok(total)
}

/// Prints one payload line in the exact shape the gate greps.
fn report_payload(name: &str, bytes: &[u8]) {
    let mut hash = Fnv::new();
    hash.eat(bytes);
    serial::write("bhaskixboot: payload ");
    serial::write(name);
    serial::write(" ");
    serial::write_dec(bytes.len() as u64);
    serial::write(" bytes fnv ");
    serial::write_hex(hash.0);
    serial::write("\r\n");
}

/// A refusal, printed with its status, and the park that follows every one
/// of them: past the exit there is nowhere to return a status to, and
/// before it an inconsistent loader has no business handing control back.
fn refuse(what: &str, status: u64) -> ! {
    serial::write("bhaskixboot: ");
    serial::write(what);
    serial::write(", status ");
    serial::write_hex(status);
    serial::write("\r\n");
    park()
}

fn park() -> ! {
    loop {
        // SAFETY: `hlt` parks the machine; the harness reads the wire and
        // ends the run.
        unsafe { core::arch::asm!("hlt", options(nomem, nostack)) };
    }
}

/// A view of pages the firmware allocated to this loader.
///
/// # Safety
///
/// `base` must be the address `allocate_pages` returned, `pages` its size.
unsafe fn pages_as_slice(base: u64, pages: usize) -> &'static mut [u8] {
    // SAFETY: the caller's contract — pages the firmware allocated to this
    // image, identity-mapped, exclusively the loader's.
    unsafe { core::slice::from_raw_parts_mut(base as *mut u8, pages * PAGE_SIZE as usize) }
}

/// The entry point the UEFI firmware calls, by the target's convention.
///
/// Not `pub`: the firmware finds it by the PE entry address, not by Rust
/// visibility, and keeping it private keeps the table types private too.
#[unsafe(no_mangle)]
extern "efiapi" fn efi_main(image_handle: usize, system_table: *mut SystemTable) -> usize {
    serial::init();
    serial::write(BANNER);

    let Some(table) = efi::validate(system_table) else {
        serial::write("bhaskixboot: no valid system table; stopping at the banner\r\n");
        return efi::SUCCESS;
    };
    if let Some(con_out) = efi::con_out(table) {
        console_write(con_out, BANNER);
    }

    // The payload, read whole into pages the loader owns. The kernel and
    // the initrd are allocated as `LoaderCode` — the label the region
    // translation turns into `KernelAndModules` — and their checksums are
    // printed for the gate exactly as when they were streamed.
    let root = match efi::open_boot_volume(table, image_handle) {
        Ok(root) => root,
        Err(status) => refuse("the boot volume would not open", status as u64),
    };
    let kernel_base = match efi::allocate_pages(table, efi::LOADER_CODE, KERNEL_BUFFER_PAGES) {
        Ok(base) => base,
        Err(status) => refuse("the kernel buffer would not allocate", status as u64),
    };
    // SAFETY: just allocated, sized as passed.
    let kernel_buffer = unsafe { pages_as_slice(kernel_base, KERNEL_BUFFER_PAGES) };
    let kernel_len = match read_fully(root, KERNEL_PATH, kernel_buffer) {
        Ok(len) => len,
        Err(status) => refuse("payload kernel REFUSED", status as u64),
    };
    report_payload("kernel", &kernel_buffer[..kernel_len]);

    let initrd_base = match efi::allocate_pages(table, efi::LOADER_CODE, INITRD_BUFFER_PAGES) {
        Ok(base) => base,
        Err(status) => refuse("the initrd buffer would not allocate", status as u64),
    };
    // SAFETY: just allocated, sized as passed.
    let initrd_buffer = unsafe { pages_as_slice(initrd_base, INITRD_BUFFER_PAGES) };
    let initrd_len = match read_fully(root, INITRD_PATH, initrd_buffer) {
        Ok(len) => len,
        Err(status) => refuse("payload initrd REFUSED", status as u64),
    };
    report_payload("initrd", &initrd_buffer[..initrd_len]);

    let mut conf = [0u8; 4096];
    let cmdline: &str = match read_fully(root, CONFIG_PATH, &mut conf) {
        Ok(len) => {
            report_payload("conf", &conf[..len]);
            // One line, `cmdline=<rest>`; anything else is an empty
            // command line, from the shape of the parse rather than a
            // guess.
            core::str::from_utf8(&conf[..len])
                .ok()
                .and_then(|text| text.lines().next())
                .and_then(|line| line.strip_prefix("cmdline="))
                .unwrap_or("")
        }
        Err(_) => {
            serial::write("bhaskixboot: payload conf absent; the command line is empty\r\n");
            ""
        }
    };
    efi::close(root);

    // The kernel, parsed by the crate the kernel itself loads with — told
    // it is validating for the high half, which is the only thing that
    // differs from a ring 3 load.
    let image = match parse_in(&kernel_buffer[..kernel_len], AddressHalf::Kernel) {
        Ok(image) => image,
        Err(_) => refuse("the kernel image failed the parser it was built against", 0),
    };
    serial::write("bhaskixboot: kernel parsed: ");
    serial::write_dec(image.segment_count() as u64);
    serial::write(" loadable segments, entry ");
    serial::write_hex(image.entry);
    serial::write("\r\n");

    // Placement: one physically contiguous span covering every segment,
    // zeroed — the zero-fill tails are part of the contract — then each
    // segment's file bytes copied to its offset within the span.
    let mut virt_base = u64::MAX;
    let mut virt_end = 0u64;
    for segment in image.segments() {
        let Some((start, end)) = page_span(segment) else {
            refuse("a segment span wrapped", 0);
        };
        virt_base = virt_base.min(start);
        virt_end = virt_end.max(end);
    }
    let span_pages = ((virt_end - virt_base) / PAGE_SIZE) as usize;
    let kernel_phys = match efi::allocate_pages(table, efi::LOADER_CODE, span_pages) {
        Ok(base) => base,
        Err(status) => refuse("the kernel span would not allocate", status as u64),
    };
    // SAFETY: just allocated, sized as passed.
    let span = unsafe { pages_as_slice(kernel_phys, span_pages) };
    span.fill(0);
    for segment in image.segments() {
        let at = (segment.address - virt_base) as usize;
        span[at..at + segment.file_size].copy_from_slice(
            &kernel_buffer[segment.file_offset..segment.file_offset + segment.file_size],
        );
    }
    // A relocatable kernel's fixups, applied at slide zero — the value
    // written is exactly the addend, and the day KASLR arrives the slide
    // joins the sum and nothing else changes. Any relocation kind the
    // loader cannot express refuses the whole image, in the crate, before
    // a single byte is patched.
    let applied = match bhaskix_elf::for_each_relative_relocation(
        &kernel_buffer[..kernel_len],
        &image,
        |address, addend| {
            let at = (address - virt_base) as usize;
            span[at..at + 8].copy_from_slice(&(addend as u64).to_le_bytes());
        },
    ) {
        Ok(applied) => applied,
        Err(_) => refuse("a relocation the loader cannot express", 0),
    };
    serial::write("bhaskixboot: relative relocations applied: ");
    serial::write_dec(applied as u64);
    serial::write(", slide ");
    serial::write_hex(0);
    serial::write("\r\n");
    serial::write("bhaskixboot: kernel placed at ");
    serial::write_hex(kernel_phys);
    serial::write(", virt base ");
    serial::write_hex(virt_base);
    serial::write(", span ");
    serial::write_dec((virt_end - virt_base) / 1024);
    serial::write(" KiB, W^X per segment\r\n");

    // The scaffolding: the table pool and the handoff block, both
    // `LoaderData` — `BootloaderReclaimable` in the kernel's map.
    let pool_base = match efi::allocate_pages(table, efi::LOADER_DATA, TABLE_POOL_FRAMES as usize) {
        Ok(base) => base,
        Err(status) => refuse("the table pool would not allocate", status as u64),
    };
    let block = match efi::allocate_pages(table, efi::LOADER_DATA, handoff::BLOCK_PAGES) {
        Ok(base) => base,
        Err(status) => refuse("the handoff block would not allocate", status as u64),
    };

    // The machine's shape, while the firmware still answers.
    let (rsdp, smbios) = efi::find_tables(table);
    match rsdp {
        Some(address) => {
            serial::write("bhaskixboot: acpi rsdp ");
            serial::write_hex(address);
            serial::write("\r\n");
        }
        None => serial::write("bhaskixboot: acpi rsdp absent\r\n"),
    }
    match smbios {
        Some(address) => {
            serial::write("bhaskixboot: smbios ");
            serial::write_hex(address);
            serial::write("\r\n");
        }
        None => serial::write("bhaskixboot: smbios absent\r\n"),
    }
    let framebuffer = efi::framebuffer(table);
    match framebuffer {
        Some((width, height, stride, base, _bgr)) => {
            serial::write("bhaskixboot: framebuffer ");
            serial::write_dec(u64::from(width));
            serial::write("x");
            serial::write_dec(u64::from(height));
            serial::write(" stride ");
            serial::write_dec(u64::from(stride));
            serial::write(" at ");
            serial::write_hex(base);
            serial::write("\r\n");
        }
        None => serial::write("bhaskixboot: framebuffer absent; serial-only is a state\r\n"),
    }
    let bsp_lapic_id = (core::arch::x86_64::__cpuid(1).ebx >> 24) & 0xff;

    // The exit: the map and the goodbye, in one held breath.
    let map = match efi::take_map_and_exit(table, image_handle) {
        Ok(map) if map.is_empty() => {
            // A firmware that exits successfully while handing over an
            // empty map is lying about something; park loudly.
            serial::write(
                "bhaskixboot: the exit succeeded with an empty memory map
",
            );
            park()
        }
        Ok(map) => map,
        Err((status, dropped)) => {
            serial::write("bhaskixboot: the exit was refused, status ");
            serial::write_hex(status as u64);
            if dropped != 0 {
                serial::write(", ");
                serial::write_dec(dropped as u64);
                serial::write(" descriptors past the buffer");
            }
            serial::write("\r\n");
            park()
        }
    };
    serial::write("bhaskixboot: memory map ");
    serial::write_dec(map.len() as u64);
    serial::write(" descriptors, ");
    serial::write_dec(map.usable_bytes() / 1024);
    serial::write(" KiB usable, ");
    serial::write_dec(map.reclaimable_bytes() / 1024);
    serial::write(" KiB reclaimable; truncated: no\r\n");
    serial::write("bhaskixboot: boot services exited; the machine is ours\r\n");

    // Step 5's second half, on a machine the loader owns: the tables, then
    // the handoff. RAM's top is the highest end over the kinds that are
    // memory; the device windows past it are not the direct map's business.
    let mut physical_top = 0u64;
    map.regions(|kind, base, bytes| {
        if (1..=9).contains(&kind) {
            physical_top = physical_top.max(base + bytes);
        }
    });
    let mut pool = paging::TablePool::new(pool_base, TABLE_POOL_FRAMES);
    let framebuffer_span = framebuffer
        .map(|(_, height, stride, base, _)| (base, u64::from(height) * u64::from(stride) * 4));
    let Some(world) = paging::build(
        &mut pool,
        physical_top,
        framebuffer_span,
        &image,
        kernel_phys,
        virt_base,
    ) else {
        serial::write("bhaskixboot: the table pool ran dry; the guess is now a measurement\r\n");
        park()
    };
    serial::write("bhaskixboot: tables built: ");
    serial::write_dec(pool.used());
    serial::write(" frames; identity and hhdm to ");
    serial::write_hex(physical_top);
    serial::write(", kernel in the high half, cr3 ");
    serial::write_hex(world.root);
    serial::write("\r\n");

    let findings = handoff::Findings {
        map: &map,
        kernel_phys,
        kernel_virt: virt_base,
        framebuffer,
        rsdp,
        smbios,
        cmdline,
        initrd: (initrd_base, initrd_len),
        bsp_lapic_id,
    };
    let (built, stack_top) = match handoff::assemble(block, &findings) {
        Ok(built) => built,
        Err(count) => refuse("the handoff would not assemble", count as u64),
    };
    serial::write("bhaskixboot: handoff assembled: version ");
    serial::write_dec(u64::from(built.version));
    serial::write(", ");
    serial::write_dec(built.memory_map.len() as u64);
    serial::write(" regions, initrd ");
    serial::write_dec(built.initrd.map_or(0, <[u8]>::len) as u64);
    serial::write(" bytes, stack top ");
    serial::write_hex(stack_top);
    serial::write("\r\n");

    // Step 5 ends parked: everything the jump needs is standing, and the
    // jump itself is step 6 — the shim's second door, entered with EFER.NXE
    // set and this world's root in CR3.
    serial::write("bhaskixboot: the world is built; the jump is step 6\r\n");
    park()
}

/// Prints `text` on the firmware console, UCS-2 encoded in bounded chunks.
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
    park()
}
