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
//! It establishes its own identity, builds **its own GDT, TSS and interrupt
//! stacks**, enables its Local APIC, and then idles with interrupts enabled so
//! it can answer inter-processor interrupts — which is what makes TLB
//! shootdown possible.
//!
//! It then registers its own runqueue, starts its own APIC timer, and idles.
//! From that point it is a full scheduling CPU: threads created on it are
//! preempted by its own timer, out of its own queue, with no lock shared with
//! any other processor.
//!
//! # Order matters here, in a way that is easy to get wrong
//!
//! A CPU must claim its per-CPU slot *before* building its descriptor tables,
//! because the dense identifier is what selects which GDT and TSS it builds —
//! get that backwards and every CPU builds table zero, and the second one to
//! arrive faults on `ltr` against a descriptor the first already marked busy.
//!
//! But it must point `GS` at that slot *after* loading the GDT, because
//! loading any selector into `GS` — including the null selector the GDT reload
//! writes — resets `GS.base` to zero. Doing it before means the base is
//! silently wiped and the next `gs:`-relative read dereferences address zero,
//! from inside whatever ran next.
//!
//! So: claim, build tables, activate. The two halves of per-CPU setup bracket
//! the GDT load rather than preceding it.

use bhaskix_arch::{apic, cpu, gdt, idt, percpu};

use crate::println;

/// Entry point for every secondary CPU.
///
/// Runs on a stack the bootloader provided. Never returns.
extern "C" fn secondary_main(lapic_id: u32) -> ! {
    // SAFETY: this CPU has just been released and is running alone in this
    // function; each step is called exactly once on it, with interrupts
    // disabled, and in the order the module header describes.
    unsafe {
        // Identity first -- everything below is indexed by it.
        let Some(cpu_id) = percpu::install(lapic_id) else {
            // More CPUs than the per-CPU table holds. Parking is the only safe
            // response: without an area, `gs:` reads address zero.
            cpu::halt_forever();
        };

        // This CPU's own descriptor tables, with its own IST stacks, so a
        // fault here cannot collide with one on another processor.
        gdt::init_cpu(cpu_id as usize);
        idt::load_on_secondary();

        // Only now: the GDT load above cleared GS.base, so pointing GS at the
        // per-CPU area has to happen after it rather than before.
        percpu::activate(cpu_id);

        apic::enable_this_cpu();

        // This CPU's runqueue, with the code currently executing as its first
        // thread -- otherwise the first preemption would have nowhere to save
        // the context it is running on.
        crate::sched::init_cpu("idle");

        // Its own timer. The tick rate was calibrated once by the bootstrap
        // CPU and applies here unchanged; what is per-CPU is the timer itself,
        // and therefore the preemption.
        apic::start_timer(crate::trap::TIMER_HZ);
        crate::sched::start();

        // Only now is it safe to take an interrupt at all.
        cpu::enable_interrupts();
    }

    // Idle, but interruptible. `hlt` with interrupts enabled is what lets this
    // CPU answer a shootdown IPI and be preempted into any thread its queue
    // holds; halting with them disabled -- which is what this did before it
    // had its own TSS -- makes the CPU unreachable entirely.
    loop {
        // SAFETY: interrupts are enabled, so this halt is woken by the timer
        // or by any IPI.
        unsafe { cpu::halt() };
    }
}

/// Establishes the bootstrap CPU's per-CPU area.
///
/// Must run **before interrupts are enabled**, not merely before secondaries
/// start. The timer interrupt calls into the scheduler, which asks which CPU
/// it is on — and asking that before a `GS` base exists dereferences address
/// zero, from inside an interrupt handler.
///
/// Returns whether it succeeded.
pub fn init_bsp(lapic_id: u32) -> bool {
    // SAFETY: called once, on the bootstrap CPU, after its GDT is loaded and
    // before any secondary exists. Activation follows the claim immediately
    // because nothing reloads GS in between.
    unsafe {
        match percpu::install(lapic_id) {
            Some(cpu_id) => {
                percpu::activate(cpu_id);
                true
            }
            None => false,
        }
    }
}

/// Brings up every secondary CPU the loader reported.
///
/// Returns the number that came online, not counting the bootstrap CPU.
pub fn start_secondaries(handoff: &bhaskix_boot::Handoff) -> u32 {
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
            "secondary, idle (answers IPIs)"
        };
        println!("      cpu {cpu_id}  lapic {lapic_id}  {role}");
    });
}

/// Exercises TLB shootdown across every online CPU.
///
/// A shootdown that silently reaches no one looks exactly like one that
/// works, so this checks the acknowledgement count rather than merely that the
/// call returned.
#[must_use]
pub fn shootdown_self_test() -> bool {
    let (completed_before, timed_out_before) = crate::tlb::statistics();

    // An arbitrary kernel address. Invalidating a translation that is not
    // cached is architecturally harmless -- `invlpg` on an unmapped address is
    // defined to do nothing -- so this measures the round trip, not the
    // mapping.
    const PROBE: u64 = 0xffff_a000_dead_0000;

    let mut acknowledged = 0;
    for _ in 0..8 {
        if crate::tlb::shootdown(PROBE) {
            acknowledged += 1;
        }
    }

    let (completed, timed_out) = crate::tlb::statistics();
    let new_completions = completed - completed_before;
    let new_timeouts = timed_out - timed_out_before;

    if acknowledged != 8 || new_timeouts > 0 {
        println!(
            "    tlb shootdown  FAILED ({acknowledged}/8 acknowledged, {new_timeouts} timed out)"
        );
        return false;
    }

    println!(
        "    tlb shootdown  {new_completions} completed across {} cpus, none timed out",
        percpu::online_count()
    );
    true
}
