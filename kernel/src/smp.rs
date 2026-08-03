// SPDX-License-Identifier: Apache-2.0
//! Secondary CPU bring-up.
//!
//! The bootloader takes each secondary processor from reset through real mode
//! and into long mode, then parks it spinning on a word. Writing that word
//! releases it into [`secondary_main`]. Doing the same by hand means a
//! real-mode trampoline and an INIT/SIPI/SIPI sequence with its own timing
//! requirements — worth owning eventually, and not worth owning before the
//! kernel can use more than one CPU for anything.
//!
//! # What a secondary CPU does, and what it deliberately does not
//!
//! It establishes its own identity and then **parks with interrupts
//! disabled**. It does not run threads, and that restraint is the point:
//!
//! - The **GDT and TSS are still shared**. A shared TSS means shared `IST`
//!   stacks, so two CPUs taking a double fault at once would land on the same
//!   stack and destroy each other's report. Per-CPU descriptor tables are a
//!   prerequisite for a secondary CPU taking any interrupt at all.
//! - **`unmap_page` invalidates only the local TLB.** With a second CPU
//!   running, another processor can keep using a translation this one has
//!   removed. That is a correctness bug, not a missing optimisation, and it
//!   has to be fixed before any CPU changes a shared mapping.
//! - **The scheduler takes raw pointers into a static thread table** on the
//!   assumption that one CPU is inside it.
//!
//! Bringing CPUs online while being explicit that they idle is more honest
//! than scheduling on them and discovering these three in production.

use bhaskix_arch::{apic, cpu, gdt, idt, percpu};

use crate::println;

/// Entry point for every secondary CPU.
///
/// Runs on a stack the bootloader provided. Never returns.
extern "C" fn secondary_main(lapic_id: u32) -> ! {
    // SAFETY: this CPU has just been released and is running alone in this
    // function. The bootstrap CPU built the GDT and IDT before releasing
    // anything, so both are complete.
    unsafe {
        gdt::load_on_secondary();
        idt::load_on_secondary();

        if percpu::install(lapic_id).is_none() {
            // More CPUs than the per-CPU table holds. Parking is the only safe
            // response: without an area, `gs:` reads address zero.
            cpu::halt_forever();
        }

        apic::enable_this_cpu();
    }

    // Park. Interrupts stay disabled for the reasons in the module header:
    // this CPU has no TSS of its own, so it has nowhere safe to take a fault.
    cpu::halt_forever()
}

/// Brings up every secondary CPU the loader reported.
///
/// Returns the number that came online, not counting the bootstrap CPU.
pub fn start_secondaries(handoff: &bhaskix_boot::Handoff) -> u32 {
    // SAFETY: the bootstrap CPU's own per-CPU area, installed before any
    // secondary exists.
    if unsafe { percpu::install(handoff.bsp_lapic_id) }.is_none() {
        println!("    smp            FAILED to install the bootstrap CPU area");
        return 0;
    }

    let Some(start) = handoff.start_secondaries else {
        println!("    smp            loader reported no way to start secondaries");
        return 0;
    };

    let requested = start(secondary_main);
    if requested == 0 {
        return 0;
    }

    // Wait for them to report in. Bounded: a CPU that never arrives must not
    // hang the boot, and reporting "3 of 7 came online" is far more useful
    // than a machine that stops with no explanation.
    let expected = percpu::online_count() + requested;
    let mut spins = 0u64;
    while percpu::online_count() < expected && spins < 2_000_000_000 {
        spins += 1;
        core::hint::spin_loop();
    }

    percpu::online_count().saturating_sub(1)
}

/// Prints what came online.
pub fn report(handoff: &bhaskix_boot::Handoff) {
    println!(
        "    cpus           {} online of {} reported (bsp lapic {})",
        percpu::online_count(),
        handoff.cpu_count,
        handoff.bsp_lapic_id
    );
    percpu::for_each_online(|cpu_id, lapic_id| {
        let role = if cpu_id == 0 {
            "bootstrap"
        } else {
            "secondary, parked"
        };
        println!("      cpu {cpu_id}  lapic {lapic_id}  {role}");
    });
}
