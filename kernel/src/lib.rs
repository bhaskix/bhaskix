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
// Tests are exempt from the `unwrap`/`expect`/`panic` bans and from the
// SAFETY-comment requirement, as docs/coding-style.md §3 and §4 specify. The
// panic bans exist to stop a fallible operation taking down the nucleus, and a
// test that cannot panic cannot fail; the `unsafe` budget tracks the auditable
// surface of the kernel as deployed, and test code does not ship. The workspace
// lint table cannot express a cfg-conditional allow, so it is stated here.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::undocumented_unsafe_blocks
    )
)]

// The kernel heap makes `alloc` usable; see `heap`.
extern crate alloc;

pub mod console;
pub mod faultinject;
pub mod font;
pub mod framebuffer;
pub mod heap;
pub mod memory;
pub mod panic;
pub mod sched;
pub mod smp;
pub mod stack;
pub mod sync;
pub mod tlb;
pub mod trap;
pub mod vm;
pub mod wait;

use bhaskix_arch::cell::BootCell;
use bhaskix_arch::cpu;
use bhaskix_arch::serial::COM1;
use bhaskix_boot::{Handoff, MemoryKind, PhysAddr, VirtAddr};

/// A copy of the handoff that survives the stack switch.
///
/// `kernel_main` runs on the bootloader's stack and its `&Handoff` points into
/// the boot shim's frame there. Switching stacks does not invalidate that
/// memory -- nothing reuses it -- but relying on that is exactly the kind of
/// assumption that stops being true silently. Copying is two dozen bytes.
static HANDOFF: BootCell<Handoff> = BootCell::new(Handoff {
    version: 0,
    memory_map: &[],
    hhdm_base: VirtAddr(0),
    kernel_phys_base: PhysAddr(0),
    kernel_virt_base: VirtAddr(0),
    framebuffer: None,
    rsdp: None,
    smbios: None,
    cmdline: "",
    loader: "",
    cpu_count: 1,
    bsp_lapic_id: 0,
    start_secondaries: None,
    regions_truncated: false,
});

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

    // Per-CPU data before interrupts, not merely before secondaries: the timer
    // handler calls the scheduler, which asks which CPU it is running on, and
    // that question cannot be answered before a GS base exists.
    if !smp::init_bsp(handoff.bsp_lapic_id) {
        println!("  FATAL: could not establish per-CPU data for the bootstrap CPU");
        cpu::halt_forever();
    }

    println!("  cpu");
    println!("    gdt + tss      loaded (double fault and NMI on dedicated stacks)");
    println!("    idt            loaded (256 vectors)");
    report_cpu_features();

    // Interrupts. Everything up to this point ran with delivery disabled, so
    // this is the first time the kernel is re-entered asynchronously.
    //
    // The bump allocator exists only to back the one page table this may need
    // to build, on hardware without x2APIC. It is dropped immediately after.
    let mut frames = bhaskix_mm::BumpAllocator::new(handoff);

    // SAFETY: bootstrap CPU, called once, IDT loaded, interrupts still
    // disabled -- exactly what `enable` requires.
    match unsafe { trap::enable(handoff.hhdm_base, &mut frames) } {
        Ok(frequency) => {
            println!(
                "    local apic     enabled, timer calibrated to {}.{:03} MHz",
                frequency / 1_000_000,
                (frequency / 1000) % 1000
            );
            println!("    interrupts     ENABLED, timer at {} Hz", trap::TIMER_HZ);
            verify_timer();
        }
        Err(error) => {
            // Not fatal. A kernel with no clock cannot schedule, but it can
            // still report why -- which is more useful than halting.
            println!("    interrupts     UNAVAILABLE: {error:?}");
            println!("                   continuing without a timer");
        }
    }
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

    // Physical memory. The bump allocator is retired here: it carves out the
    // frame database, the buddy allocator is built over it, and everything the
    // bump handed out is then marked permanently reserved
    // (`docs/memory.md` §1).
    //
    // SAFETY: bootstrap CPU, called once, and the handoff is still valid --
    // nothing has reclaimed bootloader-reclaimable memory yet.
    match unsafe { memory::init(handoff, &mut frames) } {
        Ok(mut pmm) => {
            println!();
            println!("  physical memory");
            memory::report(&pmm);
            if memory::self_test(&mut pmm) {
                println!("    self test      passed, no frames leaked");
            } else {
                println!("    self test      FAILED");
            }

            // The heap takes ownership of the physical allocator. After this,
            // `alloc` types work.
            heap::init(pmm, handoff.hhdm_base.as_u64());
            memory::heap_self_test();

            // No-execute must be on before any mapping carrying the NX bit is
            // created, or the CPU treats bit 63 as reserved and the mapping
            // faults instead of being non-executable.
            //
            // SAFETY: bootstrap CPU during init, before the first mapping.
            if unsafe { bhaskix_arch::paging::enable_no_execute() } {
                println!("    no-execute     enabled (W^X enforceable)");
            } else {
                println!("    no-execute     UNAVAILABLE -- W^X cannot be enforced");
            }

            // SMEP stops the kernel executing user pages; SMAP stops it
            // reading or writing them except through `uaccess`, which lifts
            // the restriction for a few instructions at a time.
            //
            // SAFETY: init, and every deliberate access to user memory already
            // goes through `uaccess`.
            let (smep, smap) = unsafe { cpu::enable_supervisor_protections() };
            bhaskix_arch::uaccess::set_smap_enabled(smap);
            println!(
                "    supervisor     smep {}  smap {}  ({} exception-table {})",
                if smep { "on" } else { "--" },
                if smap { "on" } else { "--" },
                bhaskix_arch::uaccess::fixup_count(),
                if bhaskix_arch::uaccess::fixup_count() == 1 {
                    "entry"
                } else {
                    "entries"
                }
            );

            const LEAK_CYCLES: u32 = 1000;
            if vm::self_test(handoff.hhdm_base.as_u64(), LEAK_CYCLES) {
                println!(
                    "    address spaces {LEAK_CYCLES} created and destroyed, no frames leaked"
                );
            } else {
                println!("    address spaces FAILED");
            }
        }
        Err(error) => {
            println!();
            println!("  FATAL: physical memory bring-up failed: {error:?}");
            cpu::halt_forever();
        }
    }

    // Everything so far has run on the bootloader's stack, which has no guard
    // page: an overflow there scribbles over whatever is below it -- in
    // practice the page tables -- until the machine dies in a way no handler
    // can report. Move onto a guarded stack for the rest.
    //
    // SAFETY: bootstrap CPU during init with nothing else touching page
    // tables. The handoff is copied into a static first, so nothing on the
    // outgoing stack is referenced after the switch.
    unsafe {
        *HANDOFF.get_mut() = *handoff;

        match stack::allocate(handoff.hhdm_base.as_u64(), 0) {
            Ok(guarded) => {
                println!(
                    "    kernel stack   {} KiB, guard page at {:#018x}",
                    stack::STACK_PAGES * 4,
                    guarded.guard
                );
                stack::switch_and_continue(
                    guarded.top,
                    HANDOFF.as_ptr() as u64,
                    continue_on_guarded_stack,
                );
            }
            Err(error) => {
                // Not fatal, but the machine is now one runaway recursion away
                // from silent corruption, so say so plainly.
                println!("    kernel stack   NO GUARD PAGE: {error:?}");
                println!("                   continuing on the bootloader stack");
            }
        }
    }

    // Only reached when the guarded stack could not be allocated; the normal
    // path diverges inside the match above.
    continue_on_guarded_stack(HANDOFF.as_ptr() as u64)
}

/// Everything that runs after the switch to a guarded stack.
///
/// `handoff` is a pointer to the static copy made before the switch.
extern "C" fn continue_on_guarded_stack(handoff: u64) -> ! {
    // SAFETY: `handoff` is `HANDOFF.as_ptr()`, a static this crate owns, fully
    // written immediately before the switch.
    let handoff: &'static Handoff = unsafe { &*(handoff as *const Handoff) };

    verify_guard_page(handoff);

    // The first time the kernel runs in an address space it built itself, and
    // the first time a page fault is serviced rather than reported.
    if vm::demand_paging_self_test(handoff.hhdm_base.as_u64()) {
        println!("    demand paging  faults serviced from the region map; copy-on-write copies");
    } else {
        println!("    demand paging  FAILED");
    }

    let secondaries = smp::start_secondaries(handoff);
    smp::report(handoff);
    let _ = secondaries;

    // Reports its own failure in detail, so there is nothing useful to add
    // here -- a second, vaguer "FAILED" would only bury the first.
    let _ = smp::shootdown_self_test();

    if scheduling_self_test(handoff.hhdm_base.as_u64()) {
        println!("    scheduler      timer-driven preemption works");
    } else {
        println!("    scheduler      FAILED");
    }

    if !lock_ordering_self_test() {
        println!("    lock order     FAILED");
    }

    if let Some(fault) = faultinject::from_cmdline(handoff.cmdline) {
        faultinject::trigger(fault);
        println!();
        println!("  FAULT INJECTION RETURNED: the exception was not delivered.");
        cpu::halt_forever();
    }

    println!();
    println!("  M4 in progress. Nothing left to do at this milestone -- halting.");
    println!("  Next: the fair scheduling class and a reschedule IPI (docs/roadmap.md).");

    cpu::halt_forever()
}

/// Confirms lock ranking is declared, enforced, and currently clean.
///
/// Three separate claims, and reporting only the last would be the weakest
/// possible version of this: zero violations is exactly what a checker that
/// never ran also reports. So this states how many acquisitions were actually
/// checked, and then proves the detector fires by provoking an inversion on a
/// pair of locks created for the purpose.
fn lock_ordering_self_test() -> bool {
    use crate::sync::{Rank, SpinLock};

    let real = sync::violations();
    let checked = sync::acquisitions();

    // Two locks of this function's own, so provoking the inversion cannot
    // deadlock against anything: nobody else can hold them.
    let inner = SpinLock::new(Rank::AddressSpace, ());
    let outer = SpinLock::new(Rank::Heap, ());

    // Silence the report -- this violation is expected, and a kernel that
    // prints "LOCK ORDER" during a passing boot trains the reader to ignore
    // it. Save and clear the held set too, so the probe measures only what it
    // does itself.
    sync::set_reporting(false);
    let saved = sync::held_mask();
    sync::set_held_mask(0);
    {
        let _held = outer.lock(); // Heap
        let _bad = inner.lock(); // AddressSpace, which ranks above it
    }
    sync::set_held_mask(saved);
    sync::set_reporting(true);

    let detected = sync::violations() - real;
    // Drop the deliberate one; leaving it would fail the gate that exists to
    // catch real ones.
    sync::reset_violations();

    if real != 0 {
        println!("    lock order     FAILED: {real} real ordering violations before the probe");
        return false;
    }
    if detected != 1 {
        println!(
            "    lock order     FAILED: deliberate inversion produced {detected} reports, expected 1"
        );
        return false;
    }
    if checked == 0 {
        println!("    lock order     FAILED: no acquisition was ever rank-checked");
        return false;
    }

    println!("    lock order     {checked} acquisitions checked, detector verified, 0 violations");
    true
}

/// Confirms the guarded stack is really what it claims to be.
///
/// Asserting the guard is unmapped matters more than it looks: if the address
/// happened to be mapped already, the "guard" would be an ordinary writable
/// page and the whole mechanism would be a no-op that still prints success.
fn verify_guard_page(handoff: &Handoff) {
    // SAFETY: reads page table entries only.
    let root = unsafe { bhaskix_arch::paging::active_page_table() };
    let hhdm = handoff.hhdm_base.as_u64();
    let rsp = stack::current_stack_pointer();

    // Recompute the layout for the stack we are standing on.
    let slot = (stack::STACK_PAGES + 1) * 4096;
    let guard = 0xffff_a000_0000_0000u64;
    let bottom = guard + 4096;
    let top = bottom + stack::STACK_PAGES * 4096;
    let _ = slot;

    // SAFETY: reads page table entries only.
    let guard_mapped = unsafe { bhaskix_arch::paging::translate(root, guard, hhdm) }.is_some();
    // SAFETY: as above.
    let stack_mapped = unsafe { bhaskix_arch::paging::translate(root, bottom, hhdm) }.is_some();
    let on_new_stack = rsp > bottom && rsp <= top;

    if !guard_mapped && stack_mapped && on_new_stack {
        println!("    guard page     unmapped and below the stack; rsp {rsp:#018x}");
    } else {
        println!(
            "    guard page     WRONG (guard mapped {guard_mapped}, stack mapped {stack_mapped}, rsp in range {on_new_stack})"
        );
    }
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

/// Reports the hardware features the security model depends on.
///
/// Printed rather than assumed. `docs/security.md` §4 treats several of these
/// as load-bearing, and an operator should be able to see on the console which
/// guarantees the machine in front of them can actually provide.
fn report_cpu_features() {
    let f = bhaskix_arch::msr::features();
    let mark = |present: bool| if present { "yes" } else { " NO" };

    println!(
        "    features       apic {}  x2apic {}  nx {}  smep {}  smap {}",
        mark(f.apic),
        mark(f.x2apic),
        mark(f.nx),
        mark(f.smep),
        mark(f.smap)
    );
    println!(
        "                   umip {}  la57 {}  invariant-tsc {}",
        mark(f.umip),
        mark(f.la57),
        mark(f.invariant_tsc)
    );
}

/// Confirms timer interrupts are actually being delivered.
///
/// Two separate checks, because they can fail independently and the
/// distinction matters when debugging:
///
/// 1. **Delivery** — poll the tick counter. Bounded, so a timer that never
///    fires reports a dead timer rather than hanging the boot.
/// 2. **Wakeup** — `hlt` and confirm an interrupt resumes execution. This is
///    what the idle path in M4 depends on, and it is worth knowing now
///    whether it works. Only attempted once delivery is proven, because
///    halting on a machine whose timer is dead would hang forever.
fn verify_timer() {
    const TARGET_TICKS: u64 = 5;
    // Generous: enough that a slow emulator still reaches the target, small
    // enough that a dead timer is reported in well under a second.
    const SPIN_LIMIT: u64 = 500_000_000;

    let mut spins = 0u64;
    while trap::ticks() < TARGET_TICKS && spins < SPIN_LIMIT {
        spins += 1;
        core::hint::spin_loop();
    }

    if trap::ticks() < TARGET_TICKS {
        println!("    timer          NO TICKS -- interrupts are not being delivered");
        return;
    }
    println!(
        "    timer          delivering ({} ticks observed)",
        trap::ticks()
    );

    let before = trap::ticks();
    // SAFETY: interrupts are enabled and the timer has been observed
    // delivering, so this halt is guaranteed to be woken. Halting with a dead
    // timer would hang, which is why the delivery check runs first.
    unsafe { cpu::halt() };
    if trap::ticks() > before {
        println!("    timer          hlt wakes on interrupt (idle path works)");
    } else {
        println!("    timer          WARNING: hlt returned without a tick");
    }
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

    // The link script's *preferred* base. The kernel is a PIE, so the loader
    // slides the image away from it and fixes up the relocations it finds
    // through PT_DYNAMIC. A slide of zero means KASLR did not happen — worth
    // saying out loud, because either address looks equally plausible and the
    // difference is the whole protection.
    const LINK_BASE: u64 = 0xffff_ffff_8000_0000;
    let slide = handoff.kernel_virt_base.as_u64().wrapping_sub(LINK_BASE);
    if slide == 0 {
        println!("    kaslr           NOT APPLIED (image sits at its link-time base)");
    } else {
        println!("    kaslr           slid {slide:#x} bytes from {LINK_BASE:#018x}");
    }

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

/// Per-worker progress counters.
static WORK: [core::sync::atomic::AtomicU64; 4] = [
    core::sync::atomic::AtomicU64::new(0),
    core::sync::atomic::AtomicU64::new(0),
    core::sync::atomic::AtomicU64::new(0),
    core::sync::atomic::AtomicU64::new(0),
];

/// Which CPU each worker actually observed itself running on.
///
/// Recorded rather than assumed. A scheduler that dispatched every thread on
/// the bootstrap CPU would produce identical counters, so the counters alone
/// cannot distinguish per-CPU scheduling from a global queue.
static OBSERVED_CPU: [core::sync::atomic::AtomicU64; 4] = [
    core::sync::atomic::AtomicU64::new(u64::MAX),
    core::sync::atomic::AtomicU64::new(u64::MAX),
    core::sync::atomic::AtomicU64::new(u64::MAX),
    core::sync::atomic::AtomicU64::new(u64::MAX),
];

/// Which scheduler test phase is running.
///
/// Each generation of test threads retires when this moves past it. Phases
/// have to be separated rather than overlapped: the migration phase needs CPUs
/// that are genuinely idle, and the wait-queue phase needs CPUs that are not
/// saturated by spinners, so a worker left running from an earlier phase
/// quietly invalidates the next one.
static PHASE: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Phase numbers, in the order they run.
const PHASE_PINNING: u64 = 0;
const PHASE_MIGRATION: u64 = 1;
const PHASE_WAIT: u64 = 2;
const PHASE_CLASS: u64 = 3;

/// Spin counters for the scheduling-class phase, indexed by thread argument.
static CLASS_WORK: [core::sync::atomic::AtomicU64; 4] = [
    core::sync::atomic::AtomicU64::new(0),
    core::sync::atomic::AtomicU64::new(0),
    core::sync::atomic::AtomicU64::new(0),
    core::sync::atomic::AtomicU64::new(0),
];

/// Thread identifiers of the class-phase threads, for accounting lookups.
static CLASS_IDS: [core::sync::atomic::AtomicU64; 4] = [
    core::sync::atomic::AtomicU64::new(u64::MAX),
    core::sync::atomic::AtomicU64::new(u64::MAX),
    core::sync::atomic::AtomicU64::new(u64::MAX),
    core::sync::atomic::AtomicU64::new(u64::MAX),
];

/// A thread that burns CPU until the phase moves on. Used for both classes.
extern "C" fn burner(id: u64) -> ! {
    use core::sync::atomic::Ordering;
    loop {
        if PHASE.load(Ordering::Acquire) > PHASE_CLASS {
            sched::exit();
        }
        if let Some(counter) = CLASS_WORK.get(id as usize) {
            counter.fetch_add(1, Ordering::Relaxed);
        }
        core::hint::spin_loop();
    }
}

/// Wait queue for the real-time latency probe.
static RT_GATE: wait::WaitQueue = wait::WaitQueue::new();

/// Set when the waker releases the gate; read by the sleeper on arrival.
static RT_RELEASED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// TSC reading taken immediately before the wake.
static RT_WAKE_AT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Worst wakeup-to-run delay observed, in TSC ticks.
static RT_WORST: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Wakeups the probe completed.
static RT_ROUNDS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// A real-time thread that sleeps, and measures how long waking it took.
///
/// The number this produces is the one `docs/scheduler.md` §4 puts a budget
/// on. Measured rather than asserted, because a latency nobody measures is a
/// latency nobody meets.
extern "C" fn rt_probe(_argument: u64) -> ! {
    use core::sync::atomic::Ordering;
    loop {
        RT_GATE.wait_until(|| {
            RT_RELEASED.load(Ordering::Acquire) || PHASE.load(Ordering::Acquire) > PHASE_CLASS
        });
        if PHASE.load(Ordering::Acquire) > PHASE_CLASS {
            sched::exit();
        }

        // First instruction after being scheduled. The difference from the
        // timestamp the waker took is wakeup-to-run.
        let delay = bhaskix_arch::tsc::read().saturating_sub(RT_WAKE_AT.load(Ordering::Acquire));
        RT_WORST.fetch_max(delay, Ordering::Relaxed);
        RT_ROUNDS.fetch_add(1, Ordering::Relaxed);

        RT_RELEASED.store(false, Ordering::Release);
    }
}

/// A worker that never yields.
///
/// Never yielding is the point: if its counter advances, only its CPU's timer
/// can have put it there.
extern "C" fn worker(id: u64) -> ! {
    use core::sync::atomic::Ordering;
    loop {
        if PHASE.load(Ordering::Acquire) > PHASE_PINNING {
            sched::exit();
        }
        if let Some(counter) = WORK.get(id as usize) {
            counter.fetch_add(1, Ordering::Relaxed);
        }
        if let Some(slot) = OBSERVED_CPU.get(id as usize) {
            slot.store(u64::from(bhaskix_arch::percpu::cpu_id()), Ordering::Relaxed);
        }
        core::hint::spin_loop();
    }
}

/// Every CPU each migration worker has observed itself on, as a bitmask.
///
/// A set rather than a latest value, because the question is whether a thread
/// created on one CPU ever ran on another — and by the time the test reads
/// this, a migrated thread would look identical to one created where it ended
/// up.
///
/// Four entries for three migrants: the load-placement thread shares the same
/// worker body and needs a slot of its own. Giving it index 0 made it write
/// into migrant 0's set, which recorded a migration that never happened.
static MIGRANT_CPUS: [core::sync::atomic::AtomicU64; 4] = [
    core::sync::atomic::AtomicU64::new(0),
    core::sync::atomic::AtomicU64::new(0),
    core::sync::atomic::AtomicU64::new(0),
    core::sync::atomic::AtomicU64::new(0),
];

/// Index in [`MIGRANT_CPUS`] belonging to the load-placement thread.
const PLACED_SLOT: u64 = 3;

/// A worker for the migration phase. Records where it runs, never yields.
extern "C" fn migrant(id: u64) -> ! {
    use core::sync::atomic::Ordering;
    loop {
        if PHASE.load(Ordering::Acquire) > PHASE_MIGRATION {
            sched::exit();
        }
        if let Some(seen) = MIGRANT_CPUS.get(id as usize) {
            seen.fetch_or(1 << bhaskix_arch::percpu::cpu_id(), Ordering::Relaxed);
        }
        core::hint::spin_loop();
    }
}

/// Threads in the wait-queue ring.
const RING_SIZE: u64 = 4;

/// Whose turn it is. The condition every ring thread sleeps on.
static TOKEN: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// The queue they all sleep on.
static RING: wait::WaitQueue = wait::WaitQueue::new();

/// Times each ring thread has taken its turn.
static LAPS: [core::sync::atomic::AtomicU64; 4] = [
    core::sync::atomic::AtomicU64::new(0),
    core::sync::atomic::AtomicU64::new(0),
    core::sync::atomic::AtomicU64::new(0),
    core::sync::atomic::AtomicU64::new(0),
];

/// One station in the ring: sleep until the token arrives, pass it on, repeat.
///
/// Deliberately shaped so that a single lost wakeup stops *everything*. The
/// token can only move if the thread holding it is running, so a thread that
/// sleeps through its turn halts the whole ring rather than slowing it — which
/// makes the failure unmissable instead of statistical.
extern "C" fn ring_station(id: u64) -> ! {
    use core::sync::atomic::Ordering;
    loop {
        RING.wait_until(|| {
            TOKEN.load(Ordering::Acquire) == id || PHASE.load(Ordering::Acquire) > PHASE_WAIT
        });

        if PHASE.load(Ordering::Acquire) > PHASE_WAIT {
            sched::exit();
        }

        if let Some(laps) = LAPS.get(id as usize) {
            laps.fetch_add(1, Ordering::Relaxed);
        }

        // Publish *before* waking. This is the caller's half of the invariant
        // in `wait`: a waker that wakes first and publishes second reopens
        // exactly the race the wait queue closes.
        TOKEN.store((id + 1) % RING_SIZE, Ordering::Release);
        RING.wake_all();
    }
}

/// Checks the scheduling classes: strict priority, weighted fairness,
/// real-time wakeup latency, and admission control.
fn class_self_test(hhdm_base: u64, cpus: u32) -> bool {
    use core::sync::atomic::Ordering;
    use sched::{Policy, RtPolicy, SpawnOptions};

    if cpus < 2 {
        println!("    sched classes  skipped, needs a cpu that is not running the tests");
        return true;
    }

    // Everything runs on CPU 1 rather than the bootstrap CPU, so the thread
    // driving the test is not itself one of the competitors. All pinned: the
    // balancer would otherwise separate threads whose whole purpose is to
    // contend for one processor.
    const CPU: u32 = 1;
    let mut ok = true;

    // --- Weighted fairness ---------------------------------------------------
    // Three parts to one, which is the ratio `docs/scheduler.md` §10 names.
    let heavy = SpawnOptions::new()
        .policy(Policy::Fair {
            weight: (sched::BASE_WEIGHT * 3) as u32,
        })
        .pinned();
    let light = SpawnOptions::new().policy(Policy::fair()).pinned();

    let heavy_id = match sched::spawn_on_with(CPU, "fair-3x", burner, 0, hhdm_base, heavy) {
        Ok(id) => id,
        Err(error) => {
            println!("    sched classes  FAILED to spawn the heavy thread: {error:?}");
            return false;
        }
    };
    let light_id = match sched::spawn_on_with(CPU, "fair-1x", burner, 1, hhdm_base, light) {
        Ok(id) => id,
        Err(error) => {
            println!("    sched classes  FAILED to spawn the light thread: {error:?}");
            return false;
        }
    };
    CLASS_IDS[0].store(u64::from(heavy_id), Ordering::Relaxed);
    CLASS_IDS[1].store(u64::from(light_id), Ordering::Relaxed);

    wait_ticks(150);

    let heavy_cycles = sched::cycles_of(heavy_id).unwrap_or(0);
    let light_cycles = sched::cycles_of(light_id).unwrap_or(0);

    // Reported as a ratio in tenths, so "30" reads as 3.0x.
    let ratio_tenths = heavy_cycles
        .saturating_mul(10)
        .checked_div(light_cycles)
        .unwrap_or(0);

    // §10 asks for 3:1 within 2%. That is a budget for a quiet machine with a
    // long run; this is a 1.5 second sample inside an emulator, sharing the
    // CPU with a timer and a console. The band is therefore 2.4x-3.6x, and the
    // gap between that and the documented 2% is recorded in TRACKER.md rather
    // than hidden by quoting the looser number as if it were the target.
    if !(24..=36).contains(&ratio_tenths) {
        println!(
            "    sched classes  FAILED: weight 3:1 gave {}.{}x ({heavy_cycles} vs {light_cycles} ticks)",
            ratio_tenths / 10,
            ratio_tenths % 10
        );
        ok = false;
    }

    // --- Strict class priority ----------------------------------------------
    // An RT thread on the same CPU must take essentially all of it. That the
    // fair threads starve is the intended behaviour, not a defect.
    let before = [
        CLASS_WORK[0].load(Ordering::Relaxed),
        CLASS_WORK[1].load(Ordering::Relaxed),
    ];

    let rt = SpawnOptions::new()
        .policy(Policy::RealTime {
            priority: 50,
            policy: RtPolicy::RoundRobin,
            utilisation: 40,
        })
        .pinned();
    let rt_id = match sched::spawn_on_with(CPU, "rt-50", burner, 2, hhdm_base, rt) {
        Ok(id) => id,
        Err(error) => {
            println!("    sched classes  FAILED to spawn the rt thread: {error:?}");
            return false;
        }
    };

    wait_ticks(60);

    let fair_progress = (CLASS_WORK[0].load(Ordering::Relaxed) - before[0])
        + (CLASS_WORK[1].load(Ordering::Relaxed) - before[1]);
    let rt_progress = CLASS_WORK[2].load(Ordering::Relaxed);
    let rt_cycles = sched::cycles_of(rt_id).unwrap_or(0);

    if rt_progress == 0 {
        println!("    sched classes  FAILED: the real-time thread never ran");
        ok = false;
    } else if fair_progress * 4 > rt_progress {
        // Not zero: the fair threads are not *forbidden* to run, they are
        // outranked, and the timer interrupt still fires. What must not happen
        // is them getting a comparable share.
        println!(
            "    sched classes  FAILED: fair threads got {fair_progress} against the rt thread's {rt_progress}"
        );
        ok = false;
    }

    // --- Admission control ---------------------------------------------------
    // 40% is already admitted on this CPU; 60% more must be refused rather
    // than accepted and then missed.
    let greedy = SpawnOptions::new()
        .policy(Policy::RealTime {
            priority: 60,
            policy: RtPolicy::Fifo,
            utilisation: 60,
        })
        .pinned();
    let admission = match sched::spawn_on_with(CPU, "rt-greedy", burner, 3, hhdm_base, greedy) {
        Err(sched::SpawnError::RtOverCommitted { .. }) => true,
        Err(other) => {
            println!(
                "    sched classes  FAILED: over-commit rejected for the wrong reason: {other:?}"
            );
            ok = false;
            false
        }
        Ok(_) => {
            println!("    sched classes  FAILED: an over-committed rt thread was admitted");
            ok = false;
            false
        }
    };

    if ok {
        println!(
            "    sched classes  weight 3:1 measured {}.{}x; rt took {} ticks and starved fair {rt_progress}:{fair_progress}; over-commit {}",
            ratio_tenths / 10,
            ratio_tenths % 10,
            rt_cycles,
            if admission { "refused" } else { "ADMITTED" }
        );
    }

    ok
}

/// Measures wakeup-to-run for a real-time thread, the §4 budget.
fn rt_latency_self_test(hhdm_base: u64, cpus: u32) -> bool {
    use core::sync::atomic::Ordering;
    use sched::{Policy, RtPolicy, SpawnOptions};

    if cpus < 1 {
        return true;
    }

    // On *this* CPU deliberately. A wake to another processor has no IPI yet,
    // so it waits for that CPU's next tick and would measure the tick rate
    // rather than the scheduler. The local number is the one the design
    // controls today, and the cross-CPU gap is recorded as M4-09b.
    let cpu = bhaskix_arch::percpu::cpu_id();
    let options = SpawnOptions::new()
        .policy(Policy::RealTime {
            priority: 90,
            policy: RtPolicy::Fifo,
            utilisation: 5,
        })
        .slice_us(200)
        .pinned();

    if let Err(error) = sched::spawn_on_with(cpu, "rt-probe", rt_probe, 0, hhdm_base, options) {
        println!("    rt latency     FAILED to spawn the probe: {error:?}");
        return false;
    }

    // Let it reach the gate before the first measurement.
    wait_ticks(5);

    const ROUNDS: u64 = 50;
    for _ in 0..ROUNDS {
        RT_WAKE_AT.store(bhaskix_arch::tsc::read(), Ordering::Release);
        // Publish the condition before waking -- the invariant `wait` states.
        RT_RELEASED.store(true, Ordering::Release);
        RT_GATE.wake_all();

        // Wait for the probe to consume this round.
        let mut spins = 0u64;
        while RT_RELEASED.load(Ordering::Acquire) && spins < 10_000_000 {
            spins += 1;
            core::hint::spin_loop();
        }
    }

    let rounds = RT_ROUNDS.load(Ordering::Relaxed);
    let worst = RT_WORST.load(Ordering::Relaxed);
    let worst_ns = bhaskix_arch::tsc::to_nanos(worst);

    if rounds < ROUNDS / 2 {
        println!("    rt latency     FAILED: only {rounds} of {ROUNDS} wakeups completed");
        return false;
    }

    match worst_ns {
        Some(nanos) => println!(
            "    rt latency     {rounds} wakeups, worst {}.{:03} us on the waking cpu (target 50 us, docs/scheduler.md §4)",
            nanos / 1000,
            nanos % 1000
        ),
        None => {
            println!("    rt latency     {rounds} wakeups, worst {worst} ticks (tsc uncalibrated)")
        }
    }
    true
}

/// Checks that threads really sleep, and that no wakeup is ever lost.
///
/// Spinning would pass a weaker version of this test, so the numbers that
/// matter are the sleep and wake counts: a ring that ran without any thread
/// ever blocking has proved nothing about wait queues.
fn wait_queue_self_test(hhdm_base: u64) -> bool {
    use core::sync::atomic::Ordering;

    let blocks_before = sched::blocks();
    let wakeups_before = sched::wakeups();
    let races_before = sched::races();

    const NAMES: [&str; 4] = ["ring-0", "ring-1", "ring-2", "ring-3"];
    for (id, name) in NAMES.iter().enumerate() {
        // Placed by load, so the ring spans CPUs and the wakeups are genuinely
        // cross-processor. A ring confined to one CPU would never exercise the
        // window this test exists for.
        if let Err(error) = sched::spawn(name, ring_station, id as u64, hhdm_base) {
            println!("    wait queues    FAILED to spawn {name}: {error:?}");
            return false;
        }
    }

    // Generous, because the budget has to cover the slowest configuration
    // rather than the fastest. A cross-CPU wake waits for the target CPU's
    // next tick, and under UEFI the framebuffer console is slow enough that
    // the ring turns several times slower than it does under BIOS.
    wait_ticks(200);

    let blocks = sched::blocks() - blocks_before;
    let wakeups = sched::wakeups() - wakeups_before;
    let races = sched::races() - races_before;

    let laps: [u64; 4] = core::array::from_fn(|i| LAPS[i].load(Ordering::Relaxed));
    let slowest = laps.iter().copied().min().unwrap_or(0);
    let fastest = laps.iter().copied().max().unwrap_or(0);
    let total: u64 = laps.iter().sum();

    // Retire the ring: publish the phase, then wake, in that order.
    PHASE.store(PHASE_WAIT + 1, Ordering::Release);
    RING.wake_all();
    wait_ticks(20);

    let mut ok = true;

    // The real assertion. A lost wakeup does not slow the ring down, it stops
    // it -- so the slowest station having gone round at all, repeatedly, is
    // the property. Checking the total instead would let three fast threads
    // hide one that never woke.
    // Two assertions about shape rather than one about speed. How *fast* the
    // ring turns depends on the console, the firmware and the tick rate, and
    // tuning a threshold to the fastest configuration is how a test starts
    // failing on the slowest one. What does not vary is that a healthy ring is
    // even -- the token visits every station in turn, so no station can be
    // more than one lap ahead of another -- and that every station goes round
    // more than once. A lost wakeup breaks both at once: it leaves one station
    // behind for ever while the rest stop dead waiting for it.
    if slowest < 2 {
        // Print everything, because "stalled" has several causes that look
        // identical from one number: a lost wakeup leaves one station behind,
        // a ring that never slept shows no blocks, and a ring that slept but
        // was never woken shows blocks without wakeups.
        println!(
            "    wait queues    FAILED: a station stalled -- laps {laps:?}, {blocks} sleeps, {wakeups} wakeups, {races} races"
        );
        ok = false;
    } else if fastest - slowest > 1 {
        println!(
            "    wait queues    FAILED: ring uneven -- laps {laps:?}, so the token did not visit every station"
        );
        ok = false;
    }

    if blocks == 0 {
        println!("    wait queues    FAILED: no thread ever blocked -- the ring spun instead");
        ok = false;
    }
    if wakeups == 0 {
        println!("    wait queues    FAILED: no thread was ever woken");
        ok = false;
    }
    if RING.overflowed() > 0 {
        println!(
            "    wait queues    FAILED: {} sleepers overflowed the queue",
            RING.overflowed()
        );
        ok = false;
    }

    if ok {
        println!(
            "    wait queues    {total} laps around {RING_SIZE} cpus, slowest {slowest}; {blocks} sleeps, {wakeups} wakeups, {races} races caught in the window"
        );
    }

    ok
}

/// Spins until `ticks` timer interrupts have elapsed, or a wall-clock bound.
///
/// Both bounds are needed and they fail differently. The spin count limits
/// this thread; the wall clock limits everything else. A thread that is not
/// being scheduled spins zero times, so a spin bound alone never fires — and
/// the machine stops with no output at all, which is the least useful failure
/// a test can have. Reading the TSC gives a bound that holds even when this
/// thread is barely running, so a starved scheduler produces a report and a
/// thread table instead of silence.
fn wait_ticks(ticks: u64) {
    const WALL_CLOCK_LIMIT_US: u64 = 20_000_000;

    let deadline = trap::ticks() + ticks;
    let started = bhaskix_arch::tsc::read();
    let limit = bhaskix_arch::tsc::from_micros(WALL_CLOCK_LIMIT_US).unwrap_or(u64::MAX);
    let mut spins = 0u64;

    while trap::ticks() < deadline && spins < 2_000_000_000 {
        if bhaskix_arch::tsc::read().saturating_sub(started) > limit {
            println!(
                "    TIMEOUT        wait_ticks({ticks}) gave up; the scheduler is starving this thread"
            );
            return;
        }
        spins += 1;
        core::hint::spin_loop();
    }
}

/// Checks that work moves from a loaded CPU to idle ones.
///
/// Every worker is created on CPU 0 on purpose. Nothing balances at creation
/// here — the imbalance is the input. If the other CPUs stay idle while CPU 0
/// holds four runnable threads, there is no balancing, and the previous
/// milestone's test would not have noticed: a thread that never leaves the CPU
/// it was created on is exactly what that test asserts.
fn migration_self_test(hhdm_base: u64, cpus: u32) -> bool {
    use core::sync::atomic::Ordering;

    if cpus < 2 {
        println!("    migration      skipped, only one cpu online");
        return true;
    }

    // Sampled before the spawns, not after. Balancing is not deferred to the
    // wait below: the other CPUs are idle and their timers are running, so
    // they steal the first migrant while this CPU is still allocating a stack
    // for the second. Sampling after the spawns measured a window in which
    // everything had already happened, and reported zero.
    let steals_before = sched::steals();

    const NAMES: [&str; 3] = ["migrant-0", "migrant-1", "migrant-2"];
    for (id, name) in NAMES.iter().enumerate() {
        if let Err(error) = sched::spawn_on(0, name, migrant, id as u64, hhdm_base) {
            println!("    migration      FAILED to spawn on cpu 0: {error:?}");
            return false;
        }
    }

    // With CPU 0 now holding four runnable threads and every other CPU one,
    // load-aware placement has exactly one correct answer: not CPU 0. Checked
    // before anything runs, so this measures the placement decision rather
    // than whatever balancing happens afterwards.
    let placed = match sched::spawn("placed", migrant, PLACED_SLOT, hhdm_base) {
        Ok(id) => id,
        Err(error) => {
            println!("    migration      FAILED to place a thread: {error:?}");
            return false;
        }
    };
    let placed_on = sched::cpu_of(placed);

    wait_ticks(80);
    let steals = sched::steals() - steals_before;

    let mut ok = true;

    if steals == 0 {
        println!("    migration      FAILED: no thread was stolen");
        ok = false;
    }

    // Placement is reported, not asserted. It races with stealing by design:
    // the idle CPUs start taking work while this thread is still allocating
    // stacks for the threads it is about to place, so which CPU is least
    // loaded at the instant `spawn` looks is genuinely timing-dependent.
    // Asserting a particular answer measured that timing rather than the
    // policy, and failed about one run in three.

    // The property: at least one thread created on CPU 0 ran somewhere else.
    // The steal counter alone would not prove it -- a counter can be
    // incremented by a steal that moved a thread nowhere useful.
    let mut moved = 0u64;
    for (id, seen) in MIGRANT_CPUS.iter().enumerate().take(NAMES.len()) {
        let mask = seen.load(Ordering::Relaxed);
        if mask == 0 {
            println!("    migration      FAILED: migrant {id} never ran");
            ok = false;
        } else if mask & !1 != 0 {
            moved += 1;
        }
    }

    if moved == 0 {
        println!("    migration      FAILED: every migrant stayed on cpu 0 ({steals} steals)");
        ok = false;
    }

    // The counter and the per-thread flags are written together under the
    // same lock, so they cannot legitimately disagree. If they do, one of the
    // two is being updated on a path the other is not.
    if moved > steals {
        println!(
            "    migration      FAILED: {moved} threads moved but only {steals} steals counted"
        );
        ok = false;
    }

    if ok {
        println!(
            "    migration      {steals} threads stolen; {moved} of 3 ran off their creating cpu; placement chose cpu {}",
            placed_on.unwrap_or(u32::MAX)
        );
    }

    ok
}

/// Spawns one worker per CPU and checks each ran on the CPU it was created on.
fn scheduling_self_test(hhdm_base: u64) -> bool {
    use core::sync::atomic::Ordering;

    // The bootstrap CPU's own runqueue. Secondaries registered theirs during
    // bring-up.
    // Fair, not idle: this thread runs the rest of the boot and the tests,
    // which is real work and must compete on equal terms with what it spawns.
    sched::init_cpu("boot", sched::Policy::fair());

    let cpus = bhaskix_arch::percpu::online_count().min(WORK.len() as u32);
    const NAMES: [&str; 4] = ["worker-0", "worker-1", "worker-2", "worker-3"];

    for id in 0..cpus {
        if let Err(error) =
            sched::spawn_on(id, NAMES[id as usize], worker, u64::from(id), hhdm_base)
        {
            println!("    threads        FAILED to spawn on cpu {id}: {error:?}");
            return false;
        }
    }

    let switches_before = sched::switches();
    sched::start();

    // Run for a fixed number of ticks. Every CPU contributes to the counter,
    // so this is shorter in wall-clock terms on a bigger machine -- which is
    // fine, since what is being measured is progress rather than duration.
    wait_ticks(60);

    let switches = sched::switches() - switches_before;

    let mut ok = true;
    for id in 0..cpus as usize {
        let count = WORK[id].load(Ordering::Relaxed);
        let observed = OBSERVED_CPU[id].load(Ordering::Relaxed);

        if count == 0 {
            println!("    threads        FAILED: worker {id} never ran");
            ok = false;
        } else if observed != id as u64 {
            // The property that distinguishes per-CPU runqueues from a global
            // one: a thread created on CPU n must run on CPU n.
            println!("    threads        FAILED: worker {id} ran on cpu {observed}, expected {id}");
            ok = false;
        }
    }

    if switches == 0 {
        println!("    threads        FAILED: no context switches occurred");
        ok = false;
    }

    if ok {
        println!(
            "    threads        {switches} preemptions across {cpus} cpus; each worker ran on the cpu it was created on"
        );
    }

    // Retire the pinning workers before measuring migration. They are pinned
    // only by circumstance -- one per CPU, so no CPU is ever idle enough to
    // steal -- and leaving them running would mean the migration phase found
    // a perfectly balanced machine and correctly did nothing.
    PHASE.store(PHASE_MIGRATION, Ordering::Release);
    wait_ticks(30);

    ok &= migration_self_test(hhdm_base, cpus);

    // Retire the migration workers before the wait-queue phase. They never
    // sleep, so leaving them spinning would let the ring make progress by
    // being preempted onto rather than by being woken -- which is the one
    // thing that phase is trying to distinguish.
    PHASE.store(PHASE_WAIT, Ordering::Release);
    wait_ticks(30);

    ok &= wait_queue_self_test(hhdm_base);

    PHASE.store(PHASE_CLASS, Ordering::Release);
    wait_ticks(20);

    ok &= class_self_test(hhdm_base, cpus);
    ok &= rt_latency_self_test(hhdm_base, cpus);

    // Retire the class threads: publish, then wake, then let them exit.
    PHASE.store(PHASE_CLASS + 1, Ordering::Release);
    RT_GATE.wake_all();
    wait_ticks(30);

    sched::stop_all();

    sched::for_each(|cpu, id, name, state, runs, migrations, class| {
        let moved = if migrations > 0 { " (migrated)" } else { "" };
        println!(
            "      cpu {cpu}  thread {id}  {name:<9} {class:<4} {state:?}  {runs} runs{moved}"
        );
    });

    ok
}
