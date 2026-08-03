// SPDX-License-Identifier: Apache-2.0
//! The Bhaskix nucleus.
//!
//! At M1 this is the kernel's entry point, its console, and nothing else.
//! Descriptor tables and interrupts arrive in M2, memory management in M3, and
//! threads in M4; see `docs/roadmap.md`.
//!
//! The nucleus is entered through [`kernel_main`], which receives a
//! [`Handoff`] built by the boot shim. It never sees the bootloader.

#![cfg_attr(not(test), no_std)]

pub mod console;
pub mod faultinject;
pub mod font;
pub mod framebuffer;
pub mod panic;
pub mod sync;
pub mod trap;

use bhaskix_arch::cpu;
use bhaskix_arch::serial::COM1;
use bhaskix_boot::{Handoff, MemoryKind};

/// Version string reported at boot.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Kernel entry point.
///
/// Called by the boot shim with a validated handoff. Never returns: at M1
/// there is nothing to schedule, so it halts.
///
/// # Panics
///
/// Does not panic. A malformed handoff is reported and halts, because a panic
/// this early would have nowhere useful to print to.
pub fn kernel_main(handoff: &Handoff) -> ! {
    // Serial first, before anything else can go wrong. It is the only sink
    // that works with no framebuffer, no memory manager, and a corrupt heap.
    let serial_present = console::init_serial(COM1);

    let framebuffer_present = match handoff.framebuffer {
        Some(fb) => console::init_framebuffer(fb),
        None => false,
    };

    banner();

    // Descriptor tables before anything else can fault. Until the IDT is
    // loaded, any exception is a triple fault and a silent reboot -- which is
    // the single worst position to debug from, so this comes first.
    //
    // SAFETY: this is the bootstrap CPU, running once, with interrupts
    // disabled -- exactly what these require. The order matters: the IDT's
    // gates reference the kernel code selector, which only means anything
    // after the GDT is loaded.
    unsafe {
        bhaskix_arch::gdt::init();
        bhaskix_arch::idt::init();
    }
    trap::init();
    println!("  cpu");
    println!("    gdt + tss      loaded (double fault and NMI on dedicated stacks)");
    println!("    idt            loaded (256 vectors)");
    println!();

    if let Err(error) = handoff.validate() {
        println!();
        println!("  FATAL: the boot handoff is invalid: {error}");
        println!("  This is a bootloader or shim bug, not a configuration problem.");
        println!("  Halting rather than continuing into undefined behaviour.");
        cpu::halt_forever();
    }

    report_boot_state(handoff, serial_present, framebuffer_present);
    report_memory(handoff);

    if let Some(fault) = faultinject::from_cmdline(handoff.cmdline) {
        faultinject::trigger(fault);
        // Reaching here means the exception was swallowed rather than
        // reported -- a failure the test harness detects by its absence.
        println!();
        println!("  FAULT INJECTION RETURNED: the exception was not delivered.");
        cpu::halt_forever();
    }

    println!();
    println!("  M1 complete. Nothing left to do at this milestone -- halting.");
    println!("  Next: M2, descriptor tables and interrupts (docs/roadmap.md).");

    cpu::halt_forever()
}

/// Prints the greeting.
///
/// The exact string `Hello from Bhaskix` is the M1 exit criterion and is
/// asserted by `tests/qemu/boot-test.sh`. Do not reword it without updating
/// that test and `docs/roadmap.md`.
fn banner() {
    println!();
    println!("  Hello from Bhaskix");
    println!("  version {VERSION} -- x86_64 -- Apache-2.0");
    println!();
}

fn report_boot_state(handoff: &Handoff, serial: bool, framebuffer: bool) {
    println!("  boot");
    println!("    loader          {}", handoff.loader);
    println!("    handoff version {}", handoff.version);
    println!(
        "    cmdline         {}",
        if handoff.cmdline.is_empty() {
            "(none)"
        } else {
            handoff.cmdline
        }
    );
    println!(
        "    serial          {}",
        if serial { "present" } else { "ABSENT" }
    );

    if handoff.regions_truncated {
        println!("    WARNING: the memory map was truncated by the boot shim.");
        println!("             Raise MAX_MEMORY_REGIONS. Memory beyond the cut is");
        println!("             invisible to the kernel and must not be allocated.");
    }

    match handoff.framebuffer {
        Some(fb) if framebuffer => {
            println!(
                "    framebuffer     {}x{} at {} bpp",
                fb.width, fb.height, fb.bpp
            );
        }
        Some(fb) => {
            println!(
                "    framebuffer     UNSUPPORTED format ({} bpp) -- serial only",
                fb.bpp
            );
        }
        None => println!("    framebuffer     ABSENT -- serial only"),
    }

    println!(
        "    kernel phys     {:#018x}",
        handoff.kernel_phys_base.as_u64()
    );
    println!(
        "    kernel virt     {:#018x}",
        handoff.kernel_virt_base.as_u64()
    );
    println!("    hhdm base       {:#018x}", handoff.hhdm_base.as_u64());

    match handoff.rsdp {
        Some(rsdp) => println!("    acpi rsdp       {:#018x}", rsdp.as_u64()),
        None => println!("    acpi rsdp       (none)"),
    }
    match handoff.smbios {
        Some(smbios) => println!("    smbios          {:#018x}", smbios.as_u64()),
        None => println!("    smbios          (none)"),
    }
}

fn report_memory(handoff: &Handoff) {
    let usable = handoff.usable_bytes();
    let highest = handoff.highest_address().as_u64();

    println!();
    println!("  memory");
    println!("    regions         {}", handoff.memory_map.len());
    println!(
        "    usable          {} MiB ({usable} bytes)",
        usable / (1024 * 1024)
    );
    println!("    highest address {highest:#018x}");

    // Summarise rather than dump: a real machine reports dozens of regions and
    // a wall of them buries the numbers that matter. The full map becomes
    // available through the telemetry plane in Phase 2
    // (docs/ai-native.md §2); until then, print the notable ones.
    println!();
    println!("    largest usable regions");
    let mut printed = 0;
    let mut threshold = u64::MAX;
    while printed < 4 {
        let mut best: Option<usize> = None;
        for (i, region) in handoff.memory_map.iter().enumerate() {
            if !region.kind.is_usable_now() || region.length >= threshold {
                continue;
            }
            let better = match best {
                None => true,
                Some(b) => region.length > handoff.memory_map[b].length,
            };
            if better {
                best = Some(i);
            }
        }
        let Some(index) = best else { break };
        let region = handoff.memory_map[index];
        println!(
            "      {:#014x}..{:#014x}  {:>7} KiB  {}",
            region.base.as_u64(),
            region.end().as_u64(),
            region.length / 1024,
            region.kind.label()
        );
        threshold = region.length;
        printed += 1;
    }

    let reclaimable: u64 = handoff
        .memory_map
        .iter()
        .filter(|r| r.kind == MemoryKind::BootloaderReclaimable)
        .map(|r| r.length)
        .sum();
    println!();
    println!(
        "    bootloader-reclaimable {} KiB -- NOT yet free (docs/memory.md §1)",
        reclaimable / 1024
    );
}
