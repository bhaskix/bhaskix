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

pub mod cap;
pub mod console;
pub mod domain;
pub mod elf;
pub mod faultinject;
pub mod font;
pub mod framebuffer;
pub mod frames;
pub mod heap;
pub mod input;
pub mod iommu;
pub mod ipc;
pub mod irq;
pub mod memory;
pub mod mmio;
pub mod notify;
pub mod panic;
pub mod sched;
pub mod service;
pub mod shared;
pub mod shell;
pub mod smp;
pub mod stack;
pub mod sync;
pub mod syscall;
pub mod time;
pub mod tlb;
pub mod trap;
pub mod vectors;
pub mod virtio;
pub mod vm;

// The archive parser and the namespace over it live in the filesystem service
// crate as of RFC 0013 step 3, and are re-exported here because the kernel's
// own shell reads files too. The arrow points from the kernel to the service
// and never back: nothing in those modules can name anything in this crate,
// which is what let the service move out at all.
pub use bhaskix_service_vfs::{ustar, vfs};
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
    initrd: None,
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

    // Fast system-call entry, on the bootstrap CPU. MSRs only for now: the
    // stack the entry stub switches to needs a heap to allocate from, and is
    // set once there is one.
    //
    // SAFETY: bootstrap CPU, once, after its GDT is loaded, interrupts still
    // disabled, and the address is this CPU's own per-CPU area.
    if let Some(area) = bhaskix_arch::percpu::area_address() {
        // SAFETY: bootstrap CPU, once, after its GDT is loaded, with
        // interrupts still disabled, and `area` is this CPU's own per-CPU
        // area -- exactly what `swapgs` must find on kernel entry.
        unsafe { bhaskix_arch::syscall::init(area) };
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
            println!("\x1b[93m    interrupts     UNAVAILABLE: {error:?}\x1b[0m");
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
                println!("\x1b[91m    self test      FAILED\x1b[0m");
            }

            // The heap takes ownership of the physical allocator. After this,
            // `alloc` types work.
            heap::init(pmm, handoff.hhdm_base.as_u64());
            memory::heap_self_test();

            // Fill this CPU's fault-path reserve now rather than waiting for
            // the first timer tick to do it. A fault before the reserve has
            // anything in it is refused, and early boot is exactly when the
            // first demand-paged access happens.
            frames::refill();

            // No-execute must be on before any mapping carrying the NX bit is
            // created, or the CPU treats bit 63 as reserved and the mapping
            // faults instead of being non-executable.
            //
            // SAFETY: bootstrap CPU during init, before the first mapping.
            if unsafe { bhaskix_arch::paging::enable_no_execute() } {
                println!("    no-execute     enabled (W^X enforceable)");
            } else {
                println!("\x1b[93m    no-execute     UNAVAILABLE -- W^X cannot be enforced\x1b[0m");
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
                println!("\x1b[91m    address spaces FAILED\x1b[0m");
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
        println!("\x1b[91m    demand paging  FAILED\x1b[0m");
    }

    let secondaries = smp::start_secondaries(handoff);
    smp::report(handoff);
    let _ = secondaries;

    // Reports its own failure in detail, so there is nothing useful to add
    // here -- a second, vaguer "FAILED" would only bury the first.
    let _ = smp::shootdown_self_test();

    // Everything from here on spawns threads and expects them to run.
    //
    // `scheduling_self_test` ends by freezing the world so it can report a
    // stable thread table, and a thread spawned into a stopped scheduler is
    // created, is runnable, and is never chosen — which looks exactly like a
    // thread that failed to start. It cost two milestones to notice twice, so
    // the restart lives here, once, rather than inside whichever test happens
    // to need it next.
    if scheduling_self_test(handoff.hhdm_base.as_u64()) {
        println!("    scheduler      timer-driven preemption works");
    } else {
        println!("\x1b[91m    scheduler      FAILED\x1b[0m");
    }
    // Immediately, and before anything measures this machine. A stopped
    // scheduler is not a quiet one: `needs_preemption_tick` reads a stopped
    // queue as "not started yet" — early boot, keep ticking to prove the timer
    // works — so every frozen CPU arms a slice it has nothing to preempt to,
    // forever. The restart used to sit four tests further down, which put the
    // tickless measurement inside the frozen window and had it grading a state
    // the system is never in once it is running.
    sched::start_all();

    // Retire the class-phase threads before measuring idle CPUs, or the
    // "idle" window measures three spinning threads.
    PHASE.store(PHASE_TICKLESS, core::sync::atomic::Ordering::Release);
    wait_millis(200);

    if !tickless_self_test(
        handoff.hhdm_base.as_u64(),
        bhaskix_arch::percpu::online_count(),
    ) {
        println!("\x1b[91m    tickless       FAILED\x1b[0m");
    }
    // Armed as early as it safely can be, which is not as early as one would
    // like. Two things bound it:
    //
    // * **Not before `sched::start_all`.** It is a thread, and a thread spawned
    //   into a stopped scheduler is runnable and never chosen. Everything above
    //   that line -- including `demand paging`, where one stall has been seen
    //   -- is therefore outside the reach of any watchdog built this way. That
    //   is a real gap and catching it needs a mechanism that does not depend on
    //   the scheduler at all.
    // * **Not before `tickless_self_test`.** That test measures how few
    //   interrupts idle CPUs take, and a watchdog asleep on a timer is an
    //   outstanding deadline on whichever CPU it sits on. It would be grading
    //   this watchdog rather than the kernel.
    //
    // So: after the tickless measurement, before the first test that blocks on
    // a rendezvous with no deadline of its own.
    if bhaskix_arch::percpu::online_count() > 1 {
        // Not on the CPU running bring-up, and that is the whole point.
        //
        // The first version pinned it to CPU 0 beside the boot thread, and the
        // first stall it met went unreported: a boot thread spinning on a lock
        // -- or halted with interrupts off -- never reschedules, so a watchdog
        // pinned behind it never runs. It could only report the stalls that
        // left its own CPU free, which are the ones that need it least.
        let watcher_cpu = bhaskix_arch::percpu::online_count() - 1;
        let options = sched::SpawnOptions::new().pinned();
        if sched::spawn_on_with(
            watcher_cpu,
            "watchdog",
            bringup_watchdog,
            0,
            handoff.hhdm_base.as_u64(),
            options,
        )
        .is_err()
        {
            println!(
                "\x1b[91m    watchdog       FAILED to spawn; a bring-up stall will be silent\x1b[0m"
            );
        }
    }

    if !initrd_self_test(handoff) {
        println!("\x1b[91m    initrd         FAILED\x1b[0m");
    }
    // RFC 0012 step 4: the unit before the device. A `DmaWindow` names the
    // device it translates for, and the device must be programmed with
    // addresses from that window -- so the window has to exist first, and
    // translation has to be on before `DRIVER_OK` lets the device read a ring.
    let iommu_state = iommu_bringup(handoff);
    if !block_self_test(handoff) {
        println!("\x1b[91m    virtio-blk     FAILED\x1b[0m");
    }

    // What a device can reach, said once it is settled rather than before.
    iommu::report_dma(iommu_state.is_some());
    if let Some((found, _)) = iommu_state.as_ref() {
        // A fault here means a device reached for something nobody granted it,
        // during its own bring-up. RFC 0012 calls that the feature.
        // SAFETY: the unit `iommu_bringup` mapped and programmed.
        if let Some(fault) = unsafe { iommu::take_fault(found, handoff.hhdm_base.as_u64()) } {
            let (bus, slot, function) = fault.device;
            println!(
                "    iommu          FAULT {bus:02x}:{slot:02x}.{function} {} {:#x}, reason {:#04x}",
                if fault.read { "read" } else { "write" },
                fault.address,
                fault.reason
            );
        }
    }
    mount_root(handoff);
    if !vfs_self_test(handoff) {
        println!("\x1b[91m    vfs            FAILED\x1b[0m");
    }
    if !syscall_self_test(handoff.hhdm_base.as_u64()) {
        println!("\x1b[91m    syscall        FAILED\x1b[0m");
    }

    if !ipc_self_test(
        handoff.hhdm_base.as_u64(),
        bhaskix_arch::percpu::online_count(),
    ) {
        println!("\x1b[91m    ipc            FAILED\x1b[0m");
    }
    if !ring3_self_test(
        handoff.hhdm_base.as_u64(),
        bhaskix_arch::percpu::online_count(),
    ) {
        println!("\x1b[91m    ring 3         FAILED\x1b[0m");
    }
    if !capability_self_test() {
        println!("\x1b[91m    capabilities   FAILED\x1b[0m");
    }
    frames_report();
    tickless_report();

    if !lock_ordering_self_test() {
        println!("\x1b[91m    lock order     FAILED\x1b[0m");
    }
    // Everything from here to the end of bring-up is code the check above ran
    // too early to see. The count is taken now and compared at the end.
    let lock_violations_at_start = sync::violations();

    // Device interrupts, and with them a console that can be typed at. Last of
    // the bring-up, because everything above it works on a machine with no I/O
    // APIC and this is the first thing that does not.
    let input_ready = console_input(handoff);
    if input_ready && !shell_self_test() {
        println!("\x1b[91m    shell          FAILED\x1b[0m");
    }
    if input_ready && !block_interrupt_self_test(handoff) {
        println!("\x1b[91m    virtio-blk irq FAILED\x1b[0m");
    }
    // After the bus has been walked and the drivers are up, because this reads
    // every function on every bus twice and there is no reason to do that
    // before anything needs it.
    if !ecam_bringup(handoff) {
        println!("\x1b[91m    ecam           FAILED\x1b[0m");
    }
    if !journal_self_test() {
        println!("\x1b[91m    journal        FAILED\x1b[0m");
    }

    if !filesystem_self_test() {
        println!("\x1b[91m    filesystem     FAILED\x1b[0m");
    }
    if input_ready && !irq_teardown_self_test(handoff) {
        println!("\x1b[91m    irq teardown   FAILED\x1b[0m");
    }
    if input_ready {
        // Which notification each signal hit, and what its waiter slot held.
        // `UNWAITED` counts signals that found nobody; with a console and a
        // block device both signalling it cannot say which, and that is the
        // question.
        let (signals, unwaited, stranded) = notify::statistics();
        print!(
            "    notifications  {signals} signalled, {unwaited} found no waiter, {stranded} stranded;"
        );
        notify::replay_signals(|notification, waiter| {
            if waiter == 0 {
                print!(" n{notification}->nobody");
            } else {
                print!(" n{notification}->t{waiter}");
            }
        });
        println!();
    }

    if let Some(fault) = faultinject::from_cmdline(handoff.cmdline) {
        if faultinject::trigger(fault) {
            // Survivable by design: a fault in ring 3 ends one domain. The
            // machine carrying on from here *is* the assertion -- every line
            // printed below this point is evidence, and the harness expects
            // one of them.
            if !user_fault_self_test(
                handoff.hhdm_base.as_u64(),
                bhaskix_arch::percpu::online_count(),
            ) {
                println!("\x1b[91m    user fault     FAILED\x1b[0m");
            }
        } else {
            println!();
            println!("  FAULT INJECTION RETURNED: the exception was not delivered.");
            cpu::halt_forever();
        }
    }

    // The lock-order check again, at the end.
    //
    // The first one runs before the I/O APIC, the block driver's interrupt
    // path, memory objects and the services -- so it could not see a violation
    // any of them caused, and did not: M6-07 shipped an inversion in the block
    // driver that this second check is what found. A detector that only looks
    // once, early, verifies the code that runs before it.
    let late = sync::violations();
    if late > lock_violations_at_start {
        println!(
            "\x1b[91m    lock order     FAILED: {} violations after bring-up\x1b[0m",
            late - lock_violations_at_start
        );
    } else {
        println!(
            "    lock order     clean through bring-up too ({} acquisitions checked)",
            sync::acquisitions()
        );
    }

    // Reported on every boot, not only on the boot that stalls, because the
    // question is whether the window is entered *at all*. A stall is one boot
    // in 125; if this is non-zero on healthy boots too, the mechanism is
    // ordinary and the stall is the rare case where the descheduled thread
    // never runs again. If it is zero on 300 healthy boots and non-zero on a
    // stalled one, that is the stall's cause on the record.
    //
    // `held_mask` cannot see this: `try_lock` never joins the held set, so the
    // check in `preempt` that keeps lock holders on their CPU is blind to one,
    // and `exit` reaches two functions that `try_lock` every runqueue.
    let (remote_holds, _, _) = sched::remote_hold_preemptions();
    if remote_holds > 0 {
        println!(
            "    remote hold    {remote_holds} switches happened while holding another cpu's runqueue"
        );
    } else {
        println!("    remote hold    no thread was descheduled holding another cpu's runqueue");
    }

    // The voluntary half of the same question. `preempt` refuses to deschedule
    // a lock holder; `block_self` cannot refuse, so it reports instead — and
    // each report carries the call site that must release before it blocks.
    let blocked_holding = sched::blocked_holding();
    if blocked_holding > 0 {
        println!("    block holding  {blocked_holding} threads blocked while holding a lock");
    } else {
        println!("    block holding  no thread blocked while holding a lock");
    }

    // The question the other two leave open: whichever path did it, was a
    // thread ever *stored* carrying ranks? Zero here with a lock-order report
    // at `finish_switch` would mean the mask restored on resume was never
    // written by a switch — making it wrong rather than merely inconvenient.
    let (saved, mask, who) = sched::saved_holding();
    if saved > 0 {
        let who = who.unwrap_or(u32::MAX);
        println!(
            "    saved holding  {saved} switches carried held ranks; last thread {who}, mask {mask:#08b}"
        );
    } else {
        println!("    saved holding  no thread was switched out holding a rank");
    }

    // RFC 0011 step 6: an interrupt a domain holds. Before the DMA tests,
    // because it hands the block device's interrupt to a domain and puts it
    // back — and a device with no interrupt is a driver on the timer.
    if !irq_delegation_self_test(handoff) {
        println!("\x1b[91m    irq grant      FAILED\x1b[0m");
    }

    // RFC 0012 step 7, before the refusal test leaves the device unusable.
    if iommu::present() && !iommu_delegation_self_test(handoff.hhdm_base.as_u64()) {
        println!("\x1b[91m    iommu grant    FAILED\x1b[0m");
    }

    // Before the refusal test below, which leaves the device unable to answer:
    // this one needs two working reads.
    if let Some((found, _)) = iommu_state.as_ref()
        && !iommu_reuse_self_test(found, handoff, handoff.hhdm_base.as_u64())
    {
        println!("\x1b[91m    iommu reuse    FAILED\x1b[0m");
    }

    // RFC 0012 steps 4 and 5 in one demonstration, and it is deliberately one.
    //
    // A refused request never completes, so it leaves the queue unusable and
    // whichever of these ran second would find a device that no longer
    // answers -- reporting "nothing refused it" about a machine where nothing
    // had been *asked*. Merging them also makes the sharper test the only one:
    // an address the device *had* and lost isolates the page tables from every
    // other reason an access might fail, which an address that was never
    // mapped does not.
    //
    // Last thing done to the device.
    if let Some((found, _)) = iommu_state.as_ref()
        && !iommu_memory_self_test(found, handoff, handoff.hhdm_base.as_u64())
    {
        println!("\x1b[91m    iommu memory   FAILED\x1b[0m");
    }

    // Which shell the machine boots to. The user-mode one by default, because
    // it is the one that has to ask permission for everything it does;
    // `shell=kernel` on the command line selects the ring 0 one, which is a
    // debugging tool and says so when it starts.
    let kernel_shell = handoff
        .cmdline
        .split_ascii_whitespace()
        .any(|word| word == "shell=kernel");

    if !input_ready {
        // Say so rather than spawning a shell that would block for ever on a
        // console nothing can write to.
        BRINGUP_DONE.store(true, core::sync::atomic::Ordering::Release);
        println!("\x1b[92m  M6 in progress. Nothing left to do at this milestone.\x1b[0m");
        println!("  no console input on this machine, so no shell.");
    } else if kernel_shell {
        // On the CPU the serial interrupt is routed to. That pairing is
        // required rather than tidy: `input`'s wake-up argument depends on the
        // handler and the reader sharing a CPU.
        match sched::spawn_on_with(
            0,
            "shell",
            shell::main,
            0,
            handoff.hhdm_base.as_u64(),
            sched::SpawnOptions::new().pinned(),
        ) {
            Ok(_) => {
                println!("\x1b[92m  M6 in progress. Nothing left to do at this milestone.\x1b[0m")
            }
            Err(error) => println!("  the shell could not be spawned: {error:?}"),
        }
    } else {
        match user_shell(handoff) {
            Ok(()) => {
                // The two lines that used to be here -- the address-space count
                // and the console-drop check -- are printed inside `user_shell`
                // now, before it starts the shell. They were the last of the
                // kernel's output still racing the shell's first line, and they
                // tore it in exactly the way the comment beside that spawn
                // describes: `a user-mode s` ... two kernel lines ... `hell.`
                //
                // That comment says the fix is to stop overlapping rather than
                // to make the test cleverer. It was right, and it was applied
                // to two lines out of four.
                // The third figure RFC 0013 step 5 asks for: what the isolation
                // costs to *start*, stated once rather than argued about. From
                // the same clock the round trips are timed against, and taken
                // at the point every service is answering — a boot time that
                // stopped before the services were up would flatter whichever
                // placement started them more slowly.
                // Said inside `user_shell`, before the shell was started, so
                // that nothing is still being printed when it begins.
            }
            Err(reason) => {
                println!("  the user-mode shell could not be started: {reason}");
                println!("  falling back to the kernel shell.");
                let _ = sched::spawn_on_with(
                    0,
                    "shell",
                    shell::main,
                    0,
                    handoff.hhdm_base.as_u64(),
                    sched::SpawnOptions::new().pinned(),
                );
            }
        }
    }

    // Not `halt_forever`: the shell is a thread, and this CPU has to be
    // available to run it. Idling here keeps the bootstrap CPU in the
    // scheduler's hands.
    loop {
        sched::yield_now();
        // SAFETY: interrupts are enabled here -- the scheduler has been
        // running for the whole self-test above -- so this wakes on the next
        // one rather than stopping the CPU.
        unsafe { cpu::halt() };
    }
}

/// Reports what is keeping `cpu` awake, for either way the gate can fail.
///
/// A tick is armed on behalf of something, and which something it is decides
/// where to look: a slice is a scheduler question, a timer is a timer
/// question, and the backstop is neither. Printing the threads the CPU holds
/// alongside it is what turns "it still ticks" into a lead.
fn why_still_ticking(cpu: u32) {
    let (slice, timer, backstop) = time::arm_reasons(cpu);
    println!("      armed {slice} for a slice, {timer} for a timer, {backstop} for the backstop");
    let (reason, runnable) = sched::preemption_tick_reason(cpu as usize);
    println!("      it wants a preemption tick because {reason} ({runnable} schedulable)");
    sched::for_each(|on, id, name, state, runs, _migrations, class| {
        if on == cpu {
            println!("      cpu {on} holds thread {id} ({name}) {state:?} {class}, {runs} runs");
        }
    });
}

/// Measures the actual claim: an idle CPU stops taking timer interrupts.
///
/// Asked **per CPU**, which is the form the claim is really in: a processor
/// with nothing to run takes no timer interrupts, and the same processor given
/// something to run takes them. Each CPU that is meant to be idle is named and
/// checked on its own.
///
/// It was written the other way first — one counter for the whole machine,
/// compared between an idle window and a busy one, asserting a ratio — and it
/// failed about one run in four on a loaded host, at 165 idle against 327
/// busy, three ticks the wrong side of a 2× threshold.
///
/// **That was not flakiness, and the threshold was not the problem.** One CPU
/// was ticking flat out with nothing to run, every single boot; two CPUs'
/// worth of ticks in a window that should have held one is exactly the ratio
/// observed. A machine-wide count cannot say that, because it has no term for
/// *which* CPU — and a ratio against a busy baseline had just enough room to
/// swallow one broken processor in three and still pass. The gate was not
/// noisy. It was quietly reporting a real defect as a near-miss.
///
/// Counting per CPU removes the baseline, names the offender, and makes the
/// assertion an absolute bound. See `sched::start_all` for what the defect
/// turned out to be.
fn tickless_self_test(hhdm_base: u64, cpus: u32) -> bool {
    use bhaskix_arch::percpu::MAX_CPUS;
    use core::sync::atomic::Ordering;

    if cpus < 2 {
        println!(
            "\x1b[93m    tickless       skipped, needs a cpu that is not running the tests\x1b[0m"
        );
        return true;
    }

    const WINDOW_MS: u64 = 400;
    /// How many windows to allow a CPU before calling it un-quiet.
    ///
    /// The self-tests before this one leave threads finishing, and on a loaded
    /// host they take longer to drain. Retrying the measurement waits for the
    /// condition instead of sleeping a fixed time and measuring anyway, which
    /// is what makes this insensitive to what else the machine is doing.
    const TRIES: u32 = 5;
    /// Ticks an idle CPU is allowed in one window.
    ///
    /// Not zero, and the reason is design rather than tolerance: an idle CPU
    /// still arms the backstop, so it wakes once per `IDLE_BACKSTOP_MS`
    /// however idle it is. Two backstops cannot fall inside a window shorter
    /// than one, so this is a bound rather than a fudge factor -- and it is
    /// computed from the constant so that changing the backstop cannot leave a
    /// number here that used to be right.
    const ALLOWED: u64 = WINDOW_MS.div_ceil(time::IDLE_BACKSTOP_MS);

    let others = 1..cpus.min(MAX_CPUS as u32);
    let snapshot = |into: &mut [u64; MAX_CPUS]| {
        for cpu in others.clone() {
            into[cpu as usize] = trap::ticks_on(cpu);
        }
    };
    let mut mark = [0u64; MAX_CPUS];
    let mut now = [0u64; MAX_CPUS];
    let mut idle = [0u64; MAX_CPUS];

    // Every other CPU has only its idle thread, so none of them needs a tick.
    for attempt in 0..TRIES {
        snapshot(&mut mark);
        wait_millis(WINDOW_MS);
        snapshot(&mut now);
        for cpu in others.clone() {
            idle[cpu as usize] = now[cpu as usize] - mark[cpu as usize];
        }
        let Some(ticking) = others.clone().find(|&cpu| idle[cpu as usize] > ALLOWED) else {
            break;
        };
        if attempt + 1 == TRIES {
            println!(
                "\x1b[91m    tickless       FAILED: cpu {ticking} took {} ticks over {WINDOW_MS} ms with nothing to run, and at most {ALLOWED} is expected\x1b[0m",
                idle[ticking as usize]
            );
            why_still_ticking(ticking);
            return false;
        }
    }
    let idle_ticks: u64 = others.clone().map(|cpu| idle[cpu as usize]).sum();

    // Window two: give every other CPU a second runnable thread, so each of
    // them needs a tick to preempt with.
    const NAMES: [&str; 3] = ["busy-1", "busy-2", "busy-3"];
    let mut spawned = 0;
    for (index, name) in NAMES.iter().enumerate().take(cpus as usize - 1) {
        let target = index as u32 + 1;
        let options = sched::SpawnOptions::new().pinned();
        if sched::spawn_on_with(
            target,
            name,
            tickless_burner,
            index as u64,
            hhdm_base,
            options,
        )
        .is_ok()
        {
            spawned += 1;
        }
    }
    if spawned == 0 {
        println!("\x1b[91m    tickless       FAILED: could not make any cpu busy\x1b[0m");
        return false;
    }
    wait_millis(100);

    snapshot(&mut mark);
    wait_millis(WINDOW_MS);
    snapshot(&mut now);
    let mut busy = [0u64; MAX_CPUS];
    for cpu in others.clone() {
        busy[cpu as usize] = now[cpu as usize] - mark[cpu as usize];
    }

    // Retire the spinners: publish, then poke, then let them exit.
    PHASE.store(PHASE_TICKLESS + 1, Ordering::Release);
    wait_millis(100);

    // The other half of the claim, and the half that keeps the first half
    // honest: a CPU that stopped ticking because it was *broken* rather than
    // idle would sail through the check above. Only the CPUs that got a
    // spinner are asked -- `spawned` may be short of the full set.
    let asked = 1..=u32::try_from(spawned).unwrap_or(0);
    if let Some(silent) = asked.clone().find(|&cpu| busy[cpu as usize] == 0) {
        println!(
            "\x1b[91m    tickless       FAILED: cpu {silent} took no ticks over {WINDOW_MS} ms with a thread to preempt\x1b[0m"
        );
        return false;
    }
    let busy_ticks: u64 = asked.clone().map(|cpu| busy[cpu as usize]).sum();

    println!(
        "    tickless       {idle_ticks} ticks on {} idle cpus, {busy_ticks} on {spawned} of them busy, over {WINDOW_MS} ms each",
        cpus - 1
    );
    true
}

/// The endpoint the IPC self-test rendezvouses on.
static IPC_ENDPOINT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(u64::MAX);

/// Replies the client received, and how many carried the right answer.
static IPC_REPLIES: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static IPC_CORRECT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// Replies whose value was *not* what the service computed.
///
/// The assertion is that this is zero, which is the property. Comparing
/// `correct` against `replies` was the same property phrased as a race.
static IPC_WRONG: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// Badges the service observed, or-ed together.
static IPC_BADGES: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// The badges the two client threads present.
const BADGE_A: u64 = 0x0000_0000_a11c_e000;
const BADGE_B: u64 = 0x0000_0000_b0b0_0000;

/// Calls a service and checks the answer, through the system-call dispatcher.
///
/// Deliberately not `ipc::call` directly. Going through `syscall::dispatch`
/// exercises the whole path a user thread takes — domain lookup, CSpace
/// lookup, capability resolution, type check, badge extraction — rather than
/// only the rendezvous underneath it. The badge in particular is *not* passed
/// by this thread: it comes from the capability, and the point is that a
/// caller cannot choose it.
extern "C" fn ipc_client(which: u64) -> ! {
    use core::sync::atomic::Ordering;

    // The index in this domain's CSpace, not the endpoint: a client names a
    // capability it was given, and the two clients were given differently
    // badged capabilities to the same endpoint.
    let slot = which;

    // Unbounded rounds rather than a fixed count. A fixed count turns a slow
    // machine into a failed test: the assertion then has to be "did it finish
    // in time", which measures the host. Looping until the phase ends means
    // slowness costs *rounds*, and every round that happens is still checked
    // exactly.
    let mut round = 0u64;
    loop {
        if PHASE.load(Ordering::Acquire) > PHASE_IPC {
            sched::exit();
        }
        let request = which * 100 + round;
        round += 1;

        let mut frame = syscall::SyscallFrame {
            kind: syscall::Kind::Call as u64,
            capability: slot,
            method: request,
            arg0: request,
            ..syscall::SyscallFrame::default()
        };
        let outcome = syscall::dispatch(&mut frame);

        match outcome.status {
            syscall::Status::Ok => {
                // The service answers with the request doubled. Checking the
                // *value* rather than merely that a reply arrived is what
                // makes this a message and not a signal -- and it catches a
                // reply delivered to the wrong caller, which two clients
                // running at once makes possible.
                //
                // The verdict is recorded *before* the reply is counted, and
                // that order is the whole point. It used to be the other way,
                // and the test then compared two counters it had not sampled
                // together: a client preempted between its own two increments
                // gave `replies 9, correct 8` and the suite called a working
                // machine broken. It did that twice, and both times the
                // available explanation was "load".
                if outcome.value == request * 2 {
                    IPC_CORRECT.fetch_add(1, Ordering::Relaxed);
                } else {
                    IPC_WRONG.fetch_add(1, Ordering::Relaxed);
                }
                IPC_REPLIES.fetch_add(1, Ordering::Relaxed);
            }
            _ => sched::exit(),
        }
    }
}

/// Answers calls until the phase moves on.
extern "C" fn ipc_service(_argument: u64) -> ! {
    use core::sync::atomic::Ordering;

    let endpoint = ipc::EndpointId::from_u32(IPC_ENDPOINT.load(Ordering::Acquire) as u32);

    loop {
        if PHASE.load(Ordering::Acquire) > PHASE_IPC {
            sched::exit();
        }
        match ipc::recv(endpoint) {
            Ok((message, caller)) => {
                // The badge says which client this is, and the service never
                // asked the client who it was.
                IPC_BADGES.fetch_or(message.badge, Ordering::Relaxed);
                let answer = ipc::Message {
                    method: message.method,
                    args: [message.args[0] * 2, 0, 0, 0],
                    badge: message.badge,
                };
                let _ = ipc::reply(caller, answer);
            }
            // A service that stops receiving stops for a reason, and the
            // reason is the whole diagnosis. Recorded before leaving, because
            // from outside this is indistinguishable from a service that is
            // merely slow: the caller blocks, the counters stay put, and the
            // test says "reached a service" without saying what stopped it.
            Err(error) => {
                RING3_RECV_ERROR.store(error as u64 + 1, Ordering::Release);
                sched::exit()
            }
        }
    }
}

/// Checks that two threads can rendezvous, exchange a message, and that the
/// service can tell its callers apart without asking them.
/// Whether bring-up reached its end.
static BRINGUP_DONE: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// How long bring-up gets before the watchdog decides it is not coming back.
///
/// Bring-up takes about eight seconds on an idle emulated machine and rather
/// longer on a loaded one, so this is generous: what it has to separate is
/// "slow" from "stopped", and stopped is for ever.
const BRINGUP_WATCHDOG_MICROS: u64 = 45_000_000;

/// Says where bring-up got to, if it stops getting anywhere.
///
/// # Why a thread on a timer, and not a check somewhere
///
/// About one boot in seventy stops during bring-up and never prints again. The
/// machine is not spinning: every CPU is in `hlt` with interrupts enabled, and
/// the registers say so. Something was waiting for a wake that never arrived,
/// and every other thread eventually piled up behind it.
///
/// Nothing already in the tree can report that. Each self-test bounds its own
/// wait and reports its own failure, so a test that hangs has hung *below* the
/// place that would notice -- inside a blocking call that has no deadline,
/// which is most of them. And the reporter cannot be another check in the
/// bring-up sequence, because the bring-up sequence is the thing that stopped.
///
/// A thread asleep on a timer is the one thing that still runs. The timer
/// interrupt is independent of every lock and every rendezvous here, and the
/// idle backstop keeps the CPUs alive to service it, so this wakes whatever
/// else is stuck.
///
/// It prints and stops. It does not try to repair anything: a watchdog that
/// nudged the machine back into life would turn a reproducible fault into an
/// unreproducible one, and the fault is the thing worth having.
extern "C" fn bringup_watchdog(_: u64) -> ! {
    use core::sync::atomic::Ordering;

    time::sleep_micros(BRINGUP_WATCHDOG_MICROS);
    if BRINGUP_DONE.load(Ordering::Acquire) {
        sched::exit()
    }

    println!();
    println!("==================================================================");
    println!(
        "  BRING-UP STOPPED. {} seconds have passed and it has not finished.",
        BRINGUP_WATCHDOG_MICROS / 1_000_000
    );
    println!("  The last line above is the last thing that completed. Every thread");
    println!("  on this machine, and what it was doing:");

    // Printed from the walk, which holds a runqueue lock while it runs this.
    // Console is rank 16 and the runqueue is 10, so printing here is in
    // declared order -- but nothing that takes a runqueue lock may be asked
    // anything from inside it, which is why this only prints what it is given.
    sched::for_each(|cpu, id, name, state, runs, _migrations, class| {
        println!("    cpu {cpu}  thread {id}  {name}  {class}  {state:?}  {runs} runs");
    });

    // Said out loud, because the walk above cannot say it. `for_each` skips a
    // CPU whose runqueue it cannot read, and says nothing about the skip -- so
    // an unreadable CPU contributes no lines and looks exactly like a CPU with
    // no threads. Sampled repeatedly so "held throughout" is distinguished from
    // "held at the instant we looked".
    //
    // Every CPU is sampled in each round rather than one CPU being watched for
    // two seconds before moving to the next. Per-CPU windows would be two
    // seconds apart, so a lock released between them would read as never held
    // and one held in both as held continuously, and neither would be true of
    // the same instant. One window costs two seconds for the whole machine
    // instead of two seconds per CPU.
    const ROUNDS: u32 = 20;
    const ROUND_MICROS: u64 = 100_000;
    let online = bhaskix_arch::percpu::online_count() as usize;
    let mut readable = [0u32; bhaskix_arch::percpu::MAX_CPUS];
    for _ in 0..ROUNDS {
        for (cpu, count) in readable.iter_mut().enumerate().take(online) {
            if sched::runqueue_readable(cpu) {
                *count += 1;
            }
        }
        time::sleep_micros(ROUND_MICROS);
    }

    let window_secs = u64::from(ROUNDS) * ROUND_MICROS / 1_000_000;
    for (cpu, count) in readable.iter().enumerate().take(online) {
        // Printed for every CPU, including the healthy ones. A line that only
        // appears on the bad case cannot be told from a line that failed to
        // print -- and this dump exists because the last one conveyed its most
        // important fact by saying nothing at all.
        println!(
            "  cpu {cpu}: runqueue readable {count} of {ROUNDS} samples over {window_secs} seconds"
        );
        if *count == 0 {
            println!("           -- held for every sample. Nothing on this CPU could be listed");
            println!("           above, and nothing on it can run. Somebody holds this runqueue");
            println!("           and is not releasing it; it is not a thread here waiting for a");
            println!("           wake, because a wait leaves the lock free and the threads");
            println!("           readable.");
            // The lock records its taker, so this no longer has to be left to
            // the reader. `spawn_on` and the wake paths block on a remote
            // runqueue, so the holder genuinely need not be cpu {cpu} -- which
            // is why the answer is printed rather than assumed either way.
            match sched::runqueue_owner(cpu) {
                Some(owner) if owner as usize == cpu => {
                    println!(
                        "           HELD BY cpu {owner}, its own CPU. Whatever it is doing, it"
                    );
                    println!("           took this lock and stopped before releasing it.");
                }
                Some(owner) => {
                    println!(
                        "           HELD BY cpu {owner}, which is not this one. cpu {cpu} is the"
                    );
                    println!("           victim; look at cpu {owner} in the thread list above.");
                }
                // Unheld yet unreadable twenty times running is not a state
                // the protocol produces, so it is reported as the anomaly it
                // is rather than printed as "free" beside "never readable".
                None => {
                    println!("           BUT IT RECORDS NO OWNER, having just read as held twenty");
                    println!("           times. Suspect the owner bookkeeping here, not only the");
                    println!("           stall -- the two claims cannot both be right.");
                }
            }
        }
    }

    // Printed whichever way it reads. Zero here says the stall above is *not* a
    // thread descheduled holding somebody else's runqueue, which rules out a
    // hypothesis; a line that appeared only on the bad case would rule out
    // nothing, and this dump exists because of a fact once conveyed by silence.
    let (switches, stranded, holder) = sched::remote_hold_preemptions();
    println!("  {switches} switches happened while holding another cpu's runqueue.");
    if let (Some(stranded), Some(holder)) = (stranded, holder) {
        println!(
            "       The last stranded cpu {stranded}'s runqueue, held by cpu {holder}. It stays"
        );
        println!("       locked until that thread runs again, and a thread part-way through");
        println!("       `exit` may never be chosen again at all.");
    }

    let (dropped, wake_missed, received, replies_tried, no_caller, empty) = ipc::diagnostics();
    let (delivered, replied) = ipc::statistics();
    println!("  ipc: {delivered} delivered, {replied} replied, {received} receives returned,");
    println!(
        "       {replies_tried} replies tried, {no_caller} found no caller, {empty} empty checks."
    );
    println!(
        "\x1b[93m  {dropped} messages were DROPPED because a mailbox was already full, and\x1b[0m"
    );
    println!("  {wake_missed} wakes went missing. Either is enough to strand a caller for ever.");
    println!(
        "  {} deferred wakes were lost.",
        sched::deferred_wakes_lost()
    );
    println!("==================================================================");
    sched::exit()
}

fn ipc_self_test(hhdm_base: u64, cpus: u32) -> bool {
    use core::sync::atomic::Ordering;

    if cpus < 2 {
        println!(
            "\x1b[93m    ipc            skipped, needs a cpu that is not running the tests\x1b[0m"
        );
        return true;
    }

    let Ok(endpoint) = ipc::create() else {
        println!("\x1b[91m    ipc            FAILED to create an endpoint\x1b[0m");
        return false;
    };
    IPC_ENDPOINT.store(u64::from(endpoint.as_u32()), Ordering::Release);

    // A domain for the clients, holding two capabilities to the *same*
    // endpoint with *different* badges. That is the shape a service uses to
    // tell its clients apart: it hands each one a differently badged
    // capability, and thereafter neither can claim to be the other, because
    // neither can read or set its own badge.
    let Ok(clients) = domain::create("ipc-clients", domain::ResourceEnvelope::new()) else {
        println!("\x1b[91m    ipc            FAILED to create a client domain\x1b[0m");
        return false;
    };

    let installed = cap::with_arena(|arena| {
        let root = arena
            .insert_root(
                cap::ObjectRef::new(cap::ObjectKind::Endpoint, u64::from(endpoint.as_u32())),
                cap::Rights::ALL,
                0,
            )
            .ok()?;
        let a = arena.derive(root, cap::Rights::ALL, BADGE_A).ok()?;
        let b = arena.derive(root, cap::Rights::ALL, BADGE_B).ok()?;
        Some((a, b))
    });
    let Some((cap_a, cap_b)) = installed else {
        println!("\x1b[91m    ipc            FAILED to derive endpoint capabilities\x1b[0m");
        return false;
    };
    let placed = domain::with(clients, |owner| {
        owner.cspace.install_at(0, cap_a).is_ok() && owner.cspace.install_at(1, cap_b).is_ok()
    });
    if placed != Some(true) {
        println!("\x1b[91m    ipc            FAILED to install the endpoint capabilities\x1b[0m");
        return false;
    }

    let (delivered_before, replied_before) = ipc::statistics();

    // The service on one CPU and the clients on another, so the rendezvous is
    // genuinely cross-processor: a same-CPU version would pass with a wake
    // that never sends an IPI.
    let service = sched::SpawnOptions::new().pinned();
    let client = sched::SpawnOptions::new()
        .pinned()
        .in_domain(clients.as_u32());
    if sched::spawn_on_with(1, "ipc-svc", ipc_service, 0, hhdm_base, service).is_err()
        || sched::spawn_on_with(2, "ipc-cli-a", ipc_client, 0, hhdm_base, client).is_err()
        || sched::spawn_on_with(2, "ipc-cli-b", ipc_client, 1, hhdm_base, client).is_err()
    {
        println!("\x1b[91m    ipc            FAILED to spawn the participants\x1b[0m");
        return false;
    }

    // Wait for enough rounds to have happened, not for a duration. The clients
    // loop until the phase ends, so on a fast machine this returns at once and
    // on a slow one it waits -- and either way what is asserted afterwards is
    // that every reply was correct, which does not depend on how many there
    // were.
    wait_until(|| IPC_REPLIES.load(Ordering::Relaxed) >= 8, 8_000);

    let replies = IPC_REPLIES.load(Ordering::Relaxed);
    let correct = IPC_CORRECT.load(Ordering::Relaxed);
    let wrong = IPC_WRONG.load(Ordering::Relaxed);
    let badges = IPC_BADGES.load(Ordering::Relaxed);
    let (delivered, replied) = ipc::statistics();
    let delivered = delivered - delivered_before;
    let replied = replied - replied_before;

    // Sampled *before* the teardown below. Afterwards every participant has
    // been retired and its mailbox freed, so a reading taken then says only
    // that cleanup ran -- which is what the first version of this measured,
    // and it reported "no message anywhere" for a message that was sitting in
    // a mailbox at the moment the test gave up.
    let pending = sched::pending_mailboxes();
    //
    // Two passes, and it has to be two: `for_each` runs its callback holding a
    // runqueue lock, and `has_message` takes the same one. Asking inside the
    // walk deadlocks the CPU doing the asking.
    let mut resting = [(0u32, sched::State::Ready, false); 4];
    let mut resting_len = 0;
    sched::for_each(|_cpu, id, name, state, _runs, _migrations, _class| {
        if name.starts_with("ipc-") && resting_len < resting.len() {
            resting[resting_len] = (id, state, false);
            resting_len += 1;
        }
    });
    for entry in resting.iter_mut().take(resting_len) {
        entry.2 = sched::has_message(entry.0);
    }

    // Retire the service, then tear the endpoint down and confirm nothing is
    // left queued on it.
    PHASE.store(PHASE_IPC + 1, Ordering::Release);
    let stranded = ipc::destroy(endpoint);
    wait_millis(200);
    domain::destroy(clients);

    // A reply to a thread this one never heard from. Refused, or a service
    // could plant a message in any thread's mailbox and wake it holding what
    // looks like the answer it was waiting for -- which was reachable from
    // ring 3, because `Reply` is a system call and the caller used to be a
    // number in a register. Tried against every thread id the test knows of,
    // including ones that exist: the rule is not "that thread is gone", it is
    // "this thread is owed nothing".
    let forged = resting
        .iter()
        .take(resting_len)
        .all(|(id, _, _)| ipc::reply(*id, ipc::Message::default()).is_err())
        && ipc::reply(1, ipc::Message::default()).is_err();

    let mut ok = true;
    let checks = [
        // Named differently from the sentence the summary prints, and
        // deliberately: the gate greps for that sentence, and the first
        // version of this check spelled the two the same -- so a failure
        // printed `FAILED: <the sentence>` and the gate matched the failure.
        // Two identical strings, one of which is evidence, is not two strings.
        ("the forged-reply rule held", forged),
        // Correctness, not throughput. Every reply that arrived carried the
        // value the service computed for *that* request, which is what catches
        // a reply delivered to the wrong caller -- possible precisely because
        // two clients are in flight at once.
        // Not `correct == replies`: those are two counters and this is one
        // question, and asking it as a comparison made the answer depend on
        // when the sample was taken.
        ("every reply carried the right value", wrong == 0),
        ("the rendezvous made progress", replies >= 4),
        // Both badges seen, and neither client could have supplied its own:
        // the badge is a parameter only the caller of `ipc::call` can set, and
        // the clients pass the one they were given.
        (
            "the service told its two callers apart by badge",
            badges & BADGE_A != 0 && badges & BADGE_B != 0,
        ),
        ("the endpoint counted the rendezvous", delivered >= 8),
        ("the endpoint counted the replies", replied >= 8),
    ];

    // Reported from the result, not printed alongside it. The first version
    // of this line said "was refused" unconditionally, so the boot gate that
    // greps for it passed while the check underneath it failed -- a sentence
    // that is printed whatever happened is evidence of nothing.
    let forged_note = if forged {
        "a reply to a thread this one never heard from was refused"
    } else {
        "A REPLY TO A THREAD THIS ONE NEVER HEARD FROM WAS ACCEPTED"
    };

    let (dropped, wake_missed, received, replies_tried, no_caller, empty) = ipc::diagnostics();
    for (name, passed) in checks {
        if !passed {
            println!(
                "\x1b[91m    ipc            FAILED: {name} (replies {replies}, correct {correct}, wrong {wrong}, badges {badges:#x}, delivered {delivered}, replied {replied}, dropped {dropped}, wake missed {wake_missed}, mailboxes {pending}, recv returned {received}, reply tried {replies_tried}, no caller {no_caller}, empty checks {empty})\x1b[0m"
            );
            ok = false;
        }
    }

    if !ok {
        // The counters disagreed with each other, so print the order things
        // happened in. Thread names first: every trace line below is a pair of
        // thread ids, which mean nothing on their own.
        for (id, state, mail) in resting.iter().take(resting_len) {
            let mail = if *mail {
                "holding a message"
            } else {
                "no message"
            };
            println!("    ipc            thread {id} was {state}, {mail}, when the test gave up");
        }
        ipc::replay(|event, who, with| {
            println!("    ipc            trace: {event} {who} -> {with}");
        });
    }

    if ok {
        println!(
            "    ipc            {delivered} rendezvous, {replied} replies, {correct} correct and {wrong} wrong; two badges distinguished, {stranded} stranded on teardown; {forged_note}"
        );
    }
    ok
}

/// The endpoint the ring 3 probe calls, and the service that answers it.
static RING3_ENDPOINT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(u64::MAX);
static RING3_STOP: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
/// Calls the service received from ring 3.
static RING3_CALLS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// Badges the service saw on those calls, or-ed together.
static RING3_BADGE: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// Set if any message ever arrived carrying the badge ring 3 tried to invent.
///
/// A flag and not a mask. The first version of this check asked
/// `badge & BADGE_DERIVED != 0`, which is true whenever the *legitimate* badge
/// is present -- `0x1234_0000 & 0x5678_0000` is `0x1230_0000` -- so it
/// reported forgery on a machine where none had happened. Two badges that
/// share bits cannot be told apart by masking, and there was no reason to
/// believe they did not.
static RING3_FORGED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
/// The badge on the call the probe made through the capability it derived.
///
/// Recorded on its own, because the combined record cannot answer the question
/// this now asks: whether the *same* badge arrived through a different
/// capability.
static RING3_DELEGATED_BADGE: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// Set when ring 3 sent back the value it was told, proving it received it.
static RING3_ECHOED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
/// What the probe reports about its own segments; see [`SEGMENT_MAGIC`].
static RING3_SEGMENTS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// The value in the probe's read-only segment, as `user/probe/src/main.rs`
/// spells it: ASCII "SEGMENTS".
///
/// The probe reads it at an absolute address, checks that its writable segment
/// arrived zero-filled, stores the value there, reads it back, and sends what
/// it read. Receiving this number is evidence of four separate things, none of
/// which a `memcpy` of a flat blob could produce: the read-only segment's
/// contents came from the file, the writable segment was zero-filled, the
/// writable segment really is writable, and every one of them landed at the
/// address the file named rather than wherever the kernel felt like.
const SEGMENT_MAGIC: u64 = 0x5345_474d_454e_5453;
/// The method the probe reports that under.
const RING3_SEGMENT_METHOD: u64 = 11;

/// The badge on the capability the ring 3 probe holds.
const BADGE_RING3: u64 = 0x0000_0000_1234_0000;
/// The badge ring 3 *tries* to put on a capability it derives for itself.
///
/// It must never be seen. A badge is a statement the granter made, and a
/// holder that could change it could call a service as somebody else; the
/// probe asks for this one from raw ring 3 and the kernel refuses, so no
/// message ever arrives carrying it. RFC 0016 step 1.
const BADGE_DERIVED: u64 = 0x0000_0000_5678_0000;
/// The method the probe uses on the capability it derived legitimately.
const RING3_DELEGATED_METHOD: u64 = 9;
/// The method the probe reports its three `SPAWN` results on. RFC 0017 step 4.
const RING3_SPAWN_METHOD: u64 = 13;
/// The method it reports `GRANT` and `START` on. RFC 0017 step 5.
const RING3_START_METHOD: u64 = 14;
/// The method a program *started by* the probe calls, to prove it is running.
const RING3_STARTED_METHOD: u64 = 15;
/// The method the probe reports binding, `INFO` and reaping on. RFC 0017 step 6.
const RING3_REAP_METHOD: u64 = 17;
/// What the kernel answered the probe's watch, ask and reap.
static RING3_REAP: [core::sync::atomic::AtomicU64; 4] =
    [const { core::sync::atomic::AtomicU64::new(u64::MAX) }; 4];
/// What the kernel answered the probe's `GRANT` and `START`.
static RING3_GRANT_START: [core::sync::atomic::AtomicU64; 4] =
    [const { core::sync::atomic::AtomicU64::new(u64::MAX) }; 4];
/// What a program the probe started said, if it ran at all.
static RING3_STARTED: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(u64::MAX);
/// The domain the probe runs in, so the service can find its child.
static RING3_REALM: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(u64::MAX);
/// Threads plus capabilities the probe's child held the moment it was created.
static RING3_CHILD_HELD: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(u64::MAX);
/// Whether that child was named what ring 3 asked for, and what its creator was
/// charged. Snapshotted with the above, and for the same reason: by the end of
/// the test the child has ended and been reaped, and the honest answer to every
/// question about it is "there is no such domain".
static RING3_CHILD_NAMED: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(u64::MAX);
static RING3_CHILD_CHARGED: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(u64::MAX);
/// What the kernel answered each of the probe's three `SPAWN` attempts.
static RING3_SPAWN: [core::sync::atomic::AtomicU64; 3] =
    [const { core::sync::atomic::AtomicU64::new(u64::MAX) }; 3];
/// What the probe asks for, and what it must be told.
const RING3_REQUEST: u64 = 6;

/// Answers the ring 3 probe.
extern "C" fn ring3_service(_argument: u64) -> ! {
    use core::sync::atomic::Ordering;

    let endpoint = ipc::EndpointId::from_u32(RING3_ENDPOINT.load(Ordering::Acquire) as u32);

    loop {
        if RING3_STOP.load(Ordering::Acquire) {
            sched::exit();
        }
        match ipc::recv(endpoint) {
            Ok((message, caller)) => {
                RING3_CALLS.fetch_add(1, Ordering::Relaxed);
                RING3_BADGE.fetch_or(message.badge, Ordering::Relaxed);

                // Method 8 carries back whatever the probe was told last time.
                // Checking it here is what proves the reply reached ring 3 and
                // not merely that the kernel delivered one.
                if message.method == 8 && message.args[0] == RING3_REQUEST * 2 {
                    RING3_ECHOED.store(true, Ordering::Release);
                }

                // Method 11 carries what the probe found in its own segments.
                // Recorded verbatim, including a wrong value, so the test can
                // say which of the loader's obligations was not met.
                if message.method == RING3_SEGMENT_METHOD {
                    RING3_SEGMENTS.store(message.args[0], Ordering::Release);
                }

                // The three answers to "may I create a domain", recorded
                // together. One message rather than three, so a partial answer
                // cannot be read as a pass.
                if message.method == RING3_SPAWN_METHOD {
                    for (slot, answer) in RING3_SPAWN.iter().zip(message.args) {
                        slot.store(answer, Ordering::Release);
                    }
                    // The child, looked at *now*. This is a rendezvous: the
                    // probe is blocked in this call and cannot have granted or
                    // started anything yet, because both are the next things it
                    // does and it has not been replied to.
                    let realm = RING3_REALM.load(Ordering::Acquire);
                    if realm != u64::MAX
                        && let Some(child) =
                            domain::child_of(domain::DomainId::from_u32(realm as u32))
                        && let Some(held) = domain::with(child, |domain| {
                            u64::from(domain.threads()) + domain.cspace.occupied() as u64
                        })
                    {
                        RING3_CHILD_HELD.store(held, Ordering::Release);
                        RING3_CHILD_NAMED.store(
                            u64::from(
                                domain::name_of(child).is_some_and(|name| name.as_str() == "child"),
                            ),
                            Ordering::Release,
                        );
                        RING3_CHILD_CHARGED.store(
                            domain::with(domain::DomainId::from_u32(realm as u32), |owner| {
                                u64::from(owner.children())
                            })
                            .unwrap_or(u64::MAX),
                            Ordering::Release,
                        );
                    }
                }
                if message.method == RING3_START_METHOD {
                    for (slot, answer) in RING3_GRANT_START.iter().zip(message.args) {
                        slot.store(answer, Ordering::Release);
                    }
                }

                // A message from a program the probe created, granted and
                // started. It arrives on the same endpoint because that is the
                // capability it was given -- and it could arrive no other way,
                // which is the point.
                if message.method == RING3_REAP_METHOD {
                    for (slot, answer) in RING3_REAP.iter().zip(message.args) {
                        slot.store(answer, Ordering::Release);
                    }
                }
                if message.method == RING3_STARTED_METHOD {
                    RING3_STARTED.store(message.args[0], Ordering::Release);
                }

                // The badge on the call made through the capability ring 3
                // derived, recorded on its own rather than or-ed into the
                // rest. Or-ing was enough while the probe forged a *different*
                // badge; now that it delegates under the same one, a combined
                // record could not tell "the same badge arrived" from "only
                // the parent ever called", which is the whole question.
                if message.method == RING3_DELEGATED_METHOD {
                    RING3_DELEGATED_BADGE.store(message.badge, Ordering::Release);
                }
                if message.badge == BADGE_DERIVED {
                    RING3_FORGED.store(true, Ordering::Release);
                }

                let answer = ipc::Message {
                    method: message.method,
                    args: [message.args[0] * 2, 0, 0, 0],
                    badge: message.badge,
                };
                let _ = ipc::reply(caller, answer);
            }
            Err(_) => sched::exit(),
        }
    }
}

/// Why the ring 3 service stopped receiving, plus one so zero means "it did
/// not".
static RING3_RECV_ERROR: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Where the ring 3 probe's code and stack live in its address space.
///
/// `USER_CODE` is *not* the kernel's choice any more. It is where
/// `user/probe/link.ld` says the program goes, repeated here so the test can
/// check that a system call arrived from inside it. If the two ever disagree,
/// the ring 3 test fails rather than the loader silently relocating anything.
const USER_CODE: u64 = 0x0000_0000_1000_0000;
const USER_STACK: u64 = 0x0000_0000_1100_0000;
/// One page of stack is ample: the probe pushes nothing.
const USER_STACK_PAGES: u64 = 1;

/// Where the user program is in the filesystem.
const USER_PROGRAM: &[u8] = b"bin/probe";

/// Runs the probe program in ring 3, and never returns.
///
/// Everything here happens on this thread because entering user mode is a
/// one-way transition: the thread *becomes* the user thread, and comes back
/// only through a system call. It leaves by calling `Exit`, which ends it.
extern "C" fn ring3_probe(hhdm_base: u64) -> ! {
    ring3_program(hhdm_base, 0)
}

/// Where a started program's stack goes in its own address space.
///
/// The kernel's choice, not the image's. An ELF says where its code and data
/// belong and nothing about where it should be given room to push, so this is
/// one of the few addresses the loader picks rather than reads.
const STARTED_STACK: u64 = 0x0000_0000_1400_0000;
/// How many pages of it. Enough for a program with a few frames of locals.
const STARTED_STACK_PAGES: u64 = 4;
/// The largest image `START` will load.
///
/// A bound rather than a limit chosen for a reason: the copy below is a kernel
/// allocation sized by something a program supplied, and a program that could
/// name any size could ask the kernel to allocate until it stopped.
const STARTED_IMAGE_MAX: usize = 256 * 1024;

/// Loads and runs the program a `START` left waiting for this domain.
///
/// Runs as the domain's first thread rather than inside the system call, and
/// that is deliberate: it reads a page at a time, allocates, and parses
/// something a program supplied. Doing it in the call would make an untrusted
/// image's size the caller's syscall latency and put a parser on the dispatch
/// path.
///
/// Every failure ends the thread rather than the machine. A program that was
/// handed a broken image gets a domain with no threads in it, which its holder
/// can see; that is a better answer than a kernel that reports somebody else's
/// malformed ELF as its own bug.
pub extern "C" fn started_program(domain: u64) -> ! {
    use alloc::vec::Vec;
    use bhaskix_boot::VirtAddr;
    use bhaskix_mm::{Protection, VirtRange};
    use vm::AddressSpace;

    let id = domain::DomainId::from_u32(domain as u32);
    let Some((image, length, argument)) = domain::take_pending_start(id) else {
        sched::exit()
    };
    let length = length.min(STARTED_IMAGE_MAX);

    // Copied out of the caller's memory before anything is built from it.
    //
    // A copy rather than a borrow, and the reason is not tidiness: the object
    // belongs to the program that asked, which is still running and may write
    // to it. Parsing headers in memory a mutable third party can change is how
    // a checked bound becomes a stale one -- the loader would validate an
    // offset, the writer would move it, and the load would use the new value.
    let mut bytes = Vec::new();
    if bytes.try_reserve_exact(length).is_err() {
        sched::exit()
    }
    let taken = shared::drain_into(image, length, &mut |chunk: &[u8]| {
        bytes.extend_from_slice(chunk);
        chunk.len()
    });
    if taken.is_none() || bytes.is_empty() {
        sched::exit()
    }

    let Ok(parsed) = elf::parse(&bytes) else {
        sched::exit()
    };
    let Ok(mut space) = AddressSpace::new(shared::hhdm()) else {
        sched::exit()
    };
    let Some(stack) = VirtRange::from_pages(VirtAddr(STARTED_STACK), STARTED_STACK_PAGES) else {
        sched::exit()
    };
    if space.map_anonymous(stack, Protection::ReadWrite).is_err() {
        sched::exit()
    }
    let Ok(entry) = elf::load_into(&parsed, &bytes, &mut space, shared::hhdm()) else {
        sched::exit()
    };

    // SAFETY: the higher half is copied from the running page table, so
    // everything currently executing stays addressable.
    unsafe { vm::install(space) };

    let rsp = STARTED_STACK + STARTED_STACK_PAGES * bhaskix_mm::FRAME_SIZE;
    // SAFETY: `entry` is inside a user-executable segment of the space just
    // installed -- `elf::parse` refuses an entry point that is not, and every
    // segment it accepted was mapped above. `rsp` is one past user-writable
    // memory in the same space, and this thread was spawned pinned.
    unsafe { enter_user("started", entry, rsp, [argument, 0]) }
}

/// The same program, told to fault at entry. See `user/probe`.
extern "C" fn ring3_faulter(hhdm_base: u64) -> ! {
    ring3_program(hhdm_base, 1)
}

/// The same program, told to spin in ring 3 and never leave.
///
/// A thread that cannot end itself, so anything that stops it stopped it from
/// outside. That is the whole point of it: a sibling that exits on its own
/// would pass a test of thread ownership that owned nothing. It makes no
/// system call, so the only door it can be stopped at is an interrupt
/// returning to user mode.
extern "C" fn ring3_spinner(hhdm_base: u64) -> ! {
    ring3_program(hhdm_base, 2)
}

/// The same program, told to receive for ever and never answer.
///
/// The server side of RFC 0017 step 3. Once it has taken a call the kernel
/// records that it owes a reply, and it then goes straight back to waiting —
/// so the obligation is outstanding for as long as it lives, and killing it
/// strands whoever is waiting for that answer.
extern "C" fn ring3_server(hhdm_base: u64) -> ! {
    ring3_program(hhdm_base, 4)
}

/// Where a stranded caller's verdict is left: 0 nothing, 1 still waiting.
static STRANDED: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Calls the doomed domain's server and records what comes back.
///
/// It will not come back with an answer: the server receives and never replies.
/// What it must come back with is the *right refusal*, once that server dies.
/// Queues on an endpoint nobody serves, and waits there to be killed.
///
/// The call cannot succeed and is not meant to: with no receiver it queues this
/// thread as a *sender* and blocks, which is the state whose cleanup is under
/// test.
extern "C" fn queued_then_killed(endpoint: u64) -> ! {
    use core::sync::atomic::Ordering;

    QUEUED_KILLED.store(1, Ordering::Release);
    let _ = ipc::call(ipc::EndpointId::from_u32(endpoint as u32), 0, 7, [0; 4]);
    QUEUED_KILLED.store(2, Ordering::Release);
    sched::exit()
}

/// How far [`queued_then_killed`] got.
static QUEUED_KILLED: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// A thread killed while queued on an endpoint leaves no entry behind.
///
/// # Why this is a scenario and not a unit test
///
/// The mechanism -- taking a thread out of both queues -- was always there and
/// always correct. What was missing was anybody calling it for a thread that
/// *died*, and no unit test can find a missing call. Only running a thread into
/// that state and killing it can.
///
/// # Why it has to be built on purpose
///
/// Bring-up does not reach it. The `endpoint queues` line below reports the
/// truth of a quiescent machine -- two services blocked in `recv`, nothing
/// queued to send -- with or without the sweep, so it is a monitor and not a
/// gate. Nothing else in this kernel kills a thread while it is queued to send,
/// which is exactly why the entries could leak for three milestones with every
/// test passing.
fn queue_entry_released_on_death(cpu: u32, hhdm_base: u64) -> bool {
    let Ok(endpoint) = ipc::create() else {
        println!("\x1b[91m    queue cleanup  FAILED to create an endpoint\x1b[0m");
        return false;
    };
    let Ok(doomed) = domain::create("queued", domain::ResourceEnvelope::new()) else {
        println!("\x1b[91m    queue cleanup  FAILED to create a domain\x1b[0m");
        ipc::destroy(endpoint);
        return false;
    };

    QUEUED_KILLED.store(0, core::sync::atomic::Ordering::Release);
    let options = sched::SpawnOptions::new()
        .pinned()
        .in_domain(doomed.as_u32());
    if sched::spawn_on_with(
        cpu,
        "queued",
        queued_then_killed,
        u64::from(endpoint.as_u32()),
        hhdm_base,
        options,
    )
    .is_err()
    {
        println!("\x1b[91m    queue cleanup  FAILED to spawn the caller\x1b[0m");
        domain::destroy(doomed);
        ipc::destroy(endpoint);
        return false;
    }

    // Queued to send, not merely spawned. Killing it before it reached the
    // endpoint would leave nothing to clean up and the test would pass without
    // testing anything -- the failure this whole gate exists to avoid.
    let queued = wait_until(|| ipc::queued(endpoint) == Some((1, 0)), 4_000);
    if !queued {
        println!(
            "\x1b[91m    queue cleanup  FAILED: the caller never queued (got {:?})\x1b[0m",
            ipc::queued(endpoint)
        );
        domain::destroy(doomed);
        ipc::destroy(endpoint);
        return false;
    }

    domain::end(doomed, domain::Ending::Killed);
    let gone = wait_until(
        || ipc::queued(endpoint).is_none_or(|(senders, _)| senders == 0),
        8_000,
    );

    let depth = ipc::queued(endpoint);
    ipc::destroy(endpoint);
    domain::destroy(doomed);

    if gone {
        println!("    queue cleanup  a thread killed while queued to send left no entry behind");
        true
    } else {
        println!(
            "    queue cleanup  FAILED: the caller died and its entry stayed ({depth:?}); \
             {} of {} slots in that direction are gone for good",
            depth.map_or(0, |(senders, _)| senders),
            ipc::MAX_QUEUED
        );
        false
    }
}

extern "C" fn stranded_caller(endpoint: u64) -> ! {
    use core::sync::atomic::Ordering;

    STRANDED.store(1, Ordering::Release);
    let verdict = match ipc::call(ipc::EndpointId::from_u32(endpoint as u32), 0, 7, [0; 4]) {
        // The one right answer. The endpoint is still there and still valid --
        // what has gone is the thread that owed the reply.
        Err(ipc::IpcError::ServerGone) => 2,
        // Any other refusal is wrong in an interesting way: it would mean the
        // caller was told the endpoint had gone, which it has not, and a caller
        // that believed it would throw away a perfectly good capability.
        Err(_) => 3,
        Ok(_) => 4,
    };
    STRANDED.store(verdict, Ordering::Release);
    sched::exit()
}

/// The same program, told to yield for ever.
///
/// The mirror of [`ring3_spinner`], and it exists because the two safe points
/// are two separate pieces of code that can be wrong separately. This thread
/// is only ever in the kernel through a system call, so if it stops, it
/// stopped on the way back from one.
extern "C" fn ring3_yielder(hhdm_base: u64) -> ! {
    ring3_program(hhdm_base, 3)
}

/// Loads `bin/probe` into a fresh address space and enters ring 3 at it.
///
/// `mode` reaches the program in `rdi`, which is where `enter_ring3` puts the
/// first of its two entry arguments. A static would have been simpler and
/// wrong: two threads started moments apart would race to read it, and the
/// test below starts exactly two.
fn ring3_program(hhdm_base: u64, mode: u64) -> ! {
    use bhaskix_boot::VirtAddr;
    use bhaskix_mm::{Protection, VirtRange};
    use vm::AddressSpace;

    let stop = || -> ! {
        // Something in the setup failed. Ending the thread leaves the
        // counters at zero, which is what the test asserts on -- better than
        // halting the machine and losing every other result.
        sched::exit()
    };

    // The program comes out of the filesystem, and its own headers decide
    // where it is mapped and with what permissions. Nothing here chooses:
    // this thread reads a file and does what it says, within the bounds
    // `elf::parse` enforces.
    let Ok(file) = vfs::open(USER_PROGRAM) else {
        stop()
    };
    let Ok(image) = elf::parse(file.bytes()) else {
        stop()
    };

    let Ok(mut space) = AddressSpace::new(hhdm_base) else {
        stop()
    };

    // The stack is the kernel's business rather than the file's: an ELF says
    // where its code and data go and nothing about where it should be given
    // room to push.
    let Some(stack) = VirtRange::from_pages(VirtAddr(USER_STACK), USER_STACK_PAGES) else {
        stop()
    };
    if space.map_anonymous(stack, Protection::ReadWrite).is_err() {
        stop()
    }

    // Segments are mapped with the protections the file asked for, and their
    // contents written through the direct map rather than through the mapping
    // they will run from -- so a code page is never writable, not even for the
    // instant it is being filled.
    let Ok(entry) = elf::load_into(&image, file.bytes(), &mut space, hhdm_base) else {
        stop()
    };

    // SAFETY: the higher half is copied from the running page table, so
    // everything currently executing stays addressable.
    unsafe { vm::install(space) };

    let rsp = USER_STACK + USER_STACK_PAGES * bhaskix_mm::FRAME_SIZE;

    // SAFETY: `entry` is inside a user-executable segment of the space just
    // installed -- `elf::parse` refuses an entry point that is not, and every
    // segment it accepted was mapped above. `rsp` is one past user-writable
    // memory in the same space, and `RSP0` was set before this thread was
    // spawned.
    // SAFETY: `entry` is inside a user-executable segment of the space
    // just installed, and `rsp` is one past user-writable memory in it.
    unsafe { enter_user("ring 3", entry, rsp, [mode, 0]) }
}

/// A fault in ring 3 ends that domain, and nothing else.
///
/// [RFC 0017](../../docs/rfc/0017-process-management.md) step 1, and the M5
/// exit criterion that said a user program "is killed cleanly when it faults"
/// while the kernel called `halt_forever`. Nothing caught it because **no test
/// in this project had ever faulted from ring 3** — every case in
/// `tests/qemu/fault-test.sh` is injected from kernel mode.
///
/// The assertion is deliberately not "a report appeared". A report appeared
/// before this change too, and then the machine stopped. What is being checked
/// is that execution *continued*: the domain is gone, the domain table has its
/// slot back, and this function returns to a boot sequence that keeps printing
/// gates. Every line after this one is the evidence.
fn user_fault_self_test(hhdm_base: u64, cpus: u32) -> bool {
    // Runs on one CPU as happily as on four, and the single-CPU case is the
    // *harder* one: the faulting thread and the thread waiting for it share a
    // processor, so the machine only carries on if the dying thread actually
    // gives the CPU back. A version that needed a spare CPU would skip exactly
    // the arrangement most likely to hang.
    let cpu = cpus.saturating_sub(1);

    /// A privilege stack of its own, not the one `ring3_self_test` installed.
    /// Depending on another test's leftovers would make this pass or fail on
    /// the order the two happen to run in.
    const RSP0_SLOT: u64 = 2100;

    // SAFETY: a slot no thread or syscall stack uses.
    let Ok(privileged) = (unsafe { stack::allocate(hhdm_base, RSP0_SLOT + u64::from(cpu)) }) else {
        println!("\x1b[91m    user fault     FAILED to allocate a privilege stack\x1b[0m");
        return false;
    };
    // SAFETY: one past a freshly mapped guarded stack, set before anything
    // enters ring 3 on that CPU.
    unsafe { bhaskix_arch::gdt::set_privilege_stack(cpu as usize, privileged.top) };

    let Ok(doomed) = domain::create("faulter", domain::ResourceEnvelope::new()) else {
        println!("\x1b[91m    user fault     FAILED to create a domain\x1b[0m");
        return false;
    };
    let live_before = domain::live();

    let options = sched::SpawnOptions::new()
        .pinned()
        .in_domain(doomed.as_u32());

    // A sibling first, and it is the point of RFC 0017 step 2. It spins in
    // ring 3 for ever: it makes no system call, it never exits, and nothing
    // it does can end it. If it is still running after its domain is
    // destroyed, then "destroy" meant the accounting and not the program --
    // which is exactly what it used to mean.
    // An endpoint the doomed domain will serve, and a capability to it in its
    // CSpace at index 0. Without this its server has nothing to receive on and
    // the whole of step 3 is untested.
    let Ok(endpoint) = ipc::create() else {
        println!("\x1b[91m    user fault     FAILED to create an endpoint\x1b[0m");
        domain::destroy(doomed);
        return false;
    };
    let derived = cap::with_arena(|arena| {
        let root = arena
            .insert_root(
                cap::ObjectRef::new(cap::ObjectKind::Endpoint, u64::from(endpoint.as_u32())),
                cap::Rights::ALL,
                0,
            )
            .ok()?;
        arena.derive(root, cap::Rights::ALL, 0).ok()
    });
    let Some(granted) = derived else {
        println!("\x1b[91m    user fault     FAILED to derive an endpoint capability\x1b[0m");
        ipc::destroy(endpoint);
        domain::destroy(doomed);
        return false;
    };
    if domain::with(doomed, |owner| owner.cspace.install_at(0, granted).is_ok()) != Some(true) {
        println!("\x1b[91m    user fault     FAILED to install the endpoint capability\x1b[0m");
        ipc::destroy(endpoint);
        domain::destroy(doomed);
        return false;
    }

    for (name, entry) in [
        ("spinner", ring3_spinner as extern "C" fn(u64) -> !),
        ("yielder", ring3_yielder as extern "C" fn(u64) -> !),
        ("server", ring3_server as extern "C" fn(u64) -> !),
    ] {
        if let Err(error) = sched::spawn_on_with(cpu, name, entry, hhdm_base, hhdm_base, options) {
            println!("\x1b[91m    user fault     FAILED to spawn {name}: {error:?}\x1b[0m");
            domain::destroy(doomed);
            return false;
        }
    }
    // Let it reach ring 3 before the other one faults. Spawned and not yet
    // entered is a thread in kernel code, which is a different case from the
    // one being tested here.
    //
    // Asserted rather than merely waited for: if the sibling never ran, the
    // check that it stopped would pass by counting a thread that was never
    // there, which is the shape of a test that proves nothing.
    let sibling_ran = wait_until(|| sched::threads_in_domain(doomed.as_u32()) >= 3, 4_000);

    // A caller from *outside* the doomed domain, blocked on a reply its server
    // will never send. A kernel thread on purpose: what is under test is the
    // obligation, and putting the caller in a third domain would add another
    // thing that can fail without testing anything more.
    STRANDED.store(0, core::sync::atomic::Ordering::Release);
    let caller_options = sched::SpawnOptions::new().pinned();
    if sched::spawn_on_with(
        0,
        "stranded",
        stranded_caller,
        u64::from(endpoint.as_u32()),
        hhdm_base,
        caller_options,
    )
    .is_err()
    {
        println!("\x1b[91m    user fault     FAILED to spawn the stranded caller\x1b[0m");
        ipc::destroy(endpoint);
        domain::destroy(doomed);
        return false;
    }

    // Wait for the call to have been *taken*, not merely made. Until the server
    // has received it there is no obligation to lose, and killing the domain
    // before then would test the endpoint going away instead -- a different
    // mechanism, which already worked.
    let taken = wait_until(|| sched::owes_reply_in_domain(doomed.as_u32()), 4_000);

    if let Err(error) =
        sched::spawn_on_with(cpu, "faulter", ring3_faulter, hhdm_base, hhdm_base, options)
    {
        println!("\x1b[91m    user fault     FAILED to spawn the program: {error:?}\x1b[0m");
        domain::destroy(doomed);
        return false;
    }

    // Wait for the domain to stop existing rather than for a duration: the
    // fault happens in microseconds on an idle host and in rather longer on a
    // loaded one, and a fixed sleep would turn the host's mood into a verdict.
    let gone = wait_until(|| domain::with(doomed, |_| ()).is_none(), 8_000);

    // And then for the sibling, which is a *separate* wait on purpose. It does
    // not stop when the domain is destroyed; it stops at its next safe point,
    // which for a thread spinning in ring 3 is the next timer interrupt. One
    // wait covering both would not be able to tell "the sibling stopped" from
    // "the sibling was never running".
    let siblings_gone = wait_until(|| sched::threads_in_domain(doomed.as_u32()) == 0, 8_000);
    let left = sched::threads_in_domain(doomed.as_u32());

    // The caller must be told, and told the right thing. A separate wait
    // because it is released by its server's death rather than by the domain's:
    // the two happen in that order, and one wait could not tell them apart.
    let answered = wait_until(
        || STRANDED.load(core::sync::atomic::Ordering::Acquire) >= 2,
        8_000,
    );
    let verdict = STRANDED.load(core::sync::atomic::Ordering::Acquire);

    let live_after = domain::live();
    let checks = [
        ("a ring 3 fault ended its domain", gone),
        (
            "the domain table got its slot back",
            live_after + 1 == live_before,
        ),
        // Step 2. Before it, this domain's other thread carried on running
        // with no capabilities -- contained, and not stopped -- and nothing
        // in this system could tell you so.
        ("the domain had two more threads in ring 3", sibling_ran),
        (
            "a destroyed domain takes its threads with it",
            siblings_gone,
        ),
        // Step 3, in three parts: the call was taken, the caller was released
        // rather than left asleep, and it was told the *right* thing.
        ("the doomed domain took a call and owed a reply", taken),
        ("a caller whose server died was released", answered),
        (
            "it was told the server had gone, not the endpoint",
            verdict == 2,
        ),
        // The one that could not have passed before step 1, and the reason
        // the others are worth reading: if the machine had halted, nothing
        // would be here to check anything.
        ("the machine carried on afterwards", true),
    ];
    let _ = left;

    let mut ok = true;
    for (what, passed) in checks {
        if !passed {
            println!("\x1b[91m    user fault     FAILED: {what}\x1b[0m");
            ok = false;
        }
    }
    if !siblings_gone {
        // Which one survived is the diagnosis, not a detail: `spinner` never
        // makes a system call and `yielder` makes nothing but, so the name of
        // the one still running says which door is stuck.
        //
        // Matched by name rather than by asking `sched::domain_of`, which is
        // the version that was written first and printed nothing at all:
        // `for_each` runs its closure *holding* the runqueue lock, and
        // `domain_of` tries to take it again, fails its `try_lock`, and
        // answers `None` for every thread. A diagnostic that goes quiet
        // exactly when it is needed is worse than none.
        sched::for_each(|cpu, id, name, state, _, _, _| {
            if matches!(name, "spinner" | "yielder") && state != sched::State::Finished {
                println!("      still running: cpu {cpu} thread {id} ({name}) {state:?}");
            }
        });
    }
    ipc::destroy(endpoint);
    if ok {
        println!(
            "    user fault     a ring 3 fault ended its domain and nothing else, its siblings stopped and its caller was released; {live_after} domains live"
        );
    } else {
        domain::destroy(doomed);
    }
    ok
}

/// Runs a program in ring 3 and checks that it really was ring 3.
///
/// The evidence is where the kernel was entered *from*: a system call made by
/// user code arrives with a return address inside the user program's page and
/// a stack pointer inside the user stack. Both are addresses this kernel never
/// executes at and never uses as a stack, so a call that reports them cannot
/// have come from anywhere else. Counting system calls alone would look
/// identical to calling the dispatcher directly.
fn ring3_self_test(hhdm_base: u64, cpus: u32) -> bool {
    if cpus < 2 {
        println!(
            "\x1b[93m    ring 3         skipped, needs a cpu that is not running the tests\x1b[0m"
        );
        return true;
    }

    const CPU: u32 = 3;
    /// Slot base for the stack an interrupt from ring 3 lands on.
    const RSP0_SLOT: u64 = 2048;

    // The stack the CPU switches to when an interrupt arrives from ring 3.
    // Distinct from the syscall stack: an interrupt can arrive *during* a
    // system call, and sharing one would overwrite the frame that call is
    // standing on.
    //
    // SAFETY: a slot no thread or syscall stack uses.
    let Ok(privileged) = (unsafe { stack::allocate(hhdm_base, RSP0_SLOT + u64::from(CPU)) }) else {
        println!("\x1b[91m    ring 3         FAILED to allocate a privilege stack\x1b[0m");
        return false;
    };
    // SAFETY: `privileged.top` is one past a freshly mapped guarded stack, and
    // this is set before anything can enter ring 3 on that CPU.
    unsafe { bhaskix_arch::gdt::set_privilege_stack(CPU as usize, privileged.top) };

    // A domain for the probe, holding one badged capability to an endpoint at
    // index 0. Without this the probe has no CSpace, and a system call that
    // needs one is refused before it reaches the endpoint -- which is correct,
    // and is why a user thread could not do IPC until now.
    let Ok(endpoint) = ipc::create() else {
        println!("\x1b[91m    ring 3         FAILED to create an endpoint\x1b[0m");
        return false;
    };
    RING3_ENDPOINT.store(
        u64::from(endpoint.as_u32()),
        core::sync::atomic::Ordering::Release,
    );

    // One child, and exactly one. The probe asks twice: the second refusal is
    // the T10 check, and a budget of two would test nothing.
    let Ok(realm) = domain::create(
        "ring3",
        domain::ResourceEnvelope::new().max_child_domains(1),
    ) else {
        println!("\x1b[91m    ring 3         FAILED to create a domain\x1b[0m");
        return false;
    };

    let derived = cap::with_arena(|arena| {
        let root = arena
            .insert_root(
                cap::ObjectRef::new(cap::ObjectKind::Endpoint, u64::from(endpoint.as_u32())),
                cap::Rights::ALL,
                0,
            )
            .ok()?;
        arena.derive(root, cap::Rights::ALL, BADGE_RING3).ok()
    });
    let Some(granted) = derived else {
        println!("\x1b[91m    ring 3         FAILED to derive an endpoint capability\x1b[0m");
        return false;
    };
    if domain::with(realm, |owner| owner.cspace.install_at(0, granted).is_ok()) != Some(true) {
        println!("\x1b[91m    ring 3         FAILED to install the endpoint capability\x1b[0m");
        return false;
    }

    // A `DomainControl` at index 3. Holding it is the authority to create a
    // domain and nothing else -- and it is not sufficient on its own, which is
    // what the second of the probe's three asks demonstrates.
    let control = cap::with_arena(|arena| {
        let root = arena
            .insert_root(
                cap::ObjectRef::new(cap::ObjectKind::DomainControl, 0),
                cap::Rights::ALL,
                0,
            )
            .ok()?;
        arena.derive(root, cap::Rights::ALL, 0).ok()
    });
    let Some(control) = control else {
        println!("\x1b[91m    ring 3         FAILED to derive a DomainControl\x1b[0m");
        return false;
    };
    if domain::with(realm, |owner| owner.cspace.install_at(3, control).is_ok()) != Some(true) {
        println!("\x1b[91m    ring 3         FAILED to install the DomainControl\x1b[0m");
        return false;
    }
    for answer in RING3_SPAWN
        .iter()
        .chain(RING3_GRANT_START.iter())
        .chain(RING3_REAP.iter())
    {
        answer.store(u64::MAX, core::sync::atomic::Ordering::Release);
    }
    RING3_STARTED.store(u64::MAX, core::sync::atomic::Ordering::Release);
    RING3_CHILD_HELD.store(u64::MAX, core::sync::atomic::Ordering::Release);
    RING3_CHILD_NAMED.store(u64::MAX, core::sync::atomic::Ordering::Release);
    RING3_CHILD_CHARGED.store(u64::MAX, core::sync::atomic::Ordering::Release);
    RING3_REALM.store(
        u64::from(realm.as_u32()),
        core::sync::atomic::Ordering::Release,
    );

    // The image the probe will start its child with, in memory the probe
    // holds. Staged by the kernel because the probe has no filesystem -- but
    // handed over as a **capability**, so what the probe does with it is the
    // probe's own affair and the kernel never opens a file on its behalf.
    let staged = vfs::open(USER_PROGRAM).ok().and_then(|file| {
        let bytes = file.bytes();
        let pages = bytes.len().div_ceil(bhaskix_mm::FRAME_SIZE as usize).max(1);
        let object = shared::create(realm, pages as u64 * bhaskix_mm::FRAME_SIZE).ok()?;
        let mut written = 0;
        shared::fill_from(object, 0, bytes.len(), &mut |page: &mut [u8]| {
            let take = page.len().min(bytes.len() - written);
            page[..take].copy_from_slice(&bytes[written..written + take]);
            written += take;
            take
        })?;
        shared::name(object).ok()
    });
    let Some(staged) = staged else {
        println!("\x1b[91m    ring 3         FAILED to stage the program image\x1b[0m");
        return false;
    };
    if domain::with(realm, |owner| owner.cspace.install_at(4, staged).is_ok()) != Some(true) {
        println!("\x1b[91m    ring 3         FAILED to install the program image\x1b[0m");
        return false;
    }

    // A second capability to the same endpoint, at slot 5, for the probe to
    // give away.
    //
    // Not slot 0, which the probe revokes at the end of its run to prove
    // revocation is transitive — and it is: the first version of this granted
    // from slot 0, and the revocation took the child's copy with it, so the
    // program the probe had started found itself holding nothing and its call
    // reached nobody. That is the machinery working, and it is worth stating as
    // a property rather than as a bug: **what a program gives away, it can take
    // back**, because a grant is a derivation and revocation is transitive.
    //
    // Which also means a giver must keep a capability it does not intend to
    // revoke, if it wants what it gave to outlive its own housekeeping. Slot 5
    // is that capability.
    let giveable = cap::with_arena(|arena| {
        let root = arena
            .insert_root(
                cap::ObjectRef::new(cap::ObjectKind::Endpoint, u64::from(endpoint.as_u32())),
                cap::Rights::ALL,
                0,
            )
            .ok()?;
        arena.derive(root, cap::Rights::ALL, BADGE_RING3).ok()
    });
    let Some(giveable) = giveable else {
        println!("\x1b[91m    ring 3         FAILED to derive a capability to give away\x1b[0m");
        return false;
    };
    if domain::with(realm, |owner| owner.cspace.install_at(5, giveable).is_ok()) != Some(true) {
        println!("\x1b[91m    ring 3         FAILED to install the capability to give away\x1b[0m");
        return false;
    }

    // A notification at slot 9, for the probe to watch its child with.
    //
    // RFC 0017 step 6 does not invent a way to wait for a domain: a program
    // already knows how to wait on a notification, and binding one to a domain
    // is a smaller thing to add than a second blocking primitive with its own
    // queue, its own wakeup rules and its own way to lose an event.
    let watching = notify::create()
        .ok()
        .and_then(|id| notify::name(id).ok().map(|slot| (id, slot)));
    let Some((watch_id, watch_slot)) = watching else {
        println!("\x1b[91m    ring 3         FAILED to create a notification\x1b[0m");
        return false;
    };
    let _ = watch_id;
    if domain::with(realm, |owner| {
        owner.cspace.install_at(9, watch_slot).is_ok()
    }) != Some(true)
    {
        println!("\x1b[91m    ring 3         FAILED to install the notification\x1b[0m");
        return false;
    }

    let (calls_before, refused_before, revoked_before) = syscall::statistics();
    let interrupts_before = bhaskix_arch::trap::interrupts_from_user();

    // The service on a different CPU, so the probe's call genuinely blocks and
    // is woken across processors rather than handed straight back.
    let service = sched::SpawnOptions::new().pinned();
    if sched::spawn_on_with(1, "r3-svc", ring3_service, 0, hhdm_base, service).is_err() {
        println!("\x1b[91m    ring 3         FAILED to spawn the service\x1b[0m");
        return false;
    }

    let options = sched::SpawnOptions::new()
        .pinned()
        .in_domain(realm.as_u32());
    if let Err(error) =
        sched::spawn_on_with(CPU, "ring3", ring3_probe, hhdm_base, hhdm_base, options)
    {
        println!("\x1b[91m    ring 3         FAILED to spawn the probe: {error:?}\x1b[0m");
        return false;
    }

    // Three service calls and then the probe exits. Waiting for that rather
    // than for a duration means a slow host costs seconds, not a red gate.
    wait_until(
        || RING3_CALLS.load(core::sync::atomic::Ordering::Relaxed) >= 4,
        8_000,
    );
    // A moment more for the revoked call that must fail, which happens after
    // the third success and produces no counter of its own to wait on.
    wait_millis(300);

    // After the started program has had its say: it calls the same service,
    // and counting before it does would count six and expect seven.
    wait_until(
        || RING3_STARTED.load(core::sync::atomic::Ordering::Acquire) != u64::MAX,
        8_000,
    );
    wait_until(
        || RING3_REAP[2].load(core::sync::atomic::Ordering::Acquire) != u64::MAX,
        8_000,
    );
    let ring3_calls = RING3_CALLS.load(core::sync::atomic::Ordering::Relaxed);
    let ring3_badge = RING3_BADGE.load(core::sync::atomic::Ordering::Relaxed);
    let delegated_badge = RING3_DELEGATED_BADGE.load(core::sync::atomic::Ordering::Acquire);
    let forged = RING3_FORGED.load(core::sync::atomic::Ordering::Acquire);
    let echoed = RING3_ECHOED.load(core::sync::atomic::Ordering::Acquire);
    let segments = RING3_SEGMENTS.load(core::sync::atomic::Ordering::Acquire);
    let spawned = [
        RING3_SPAWN[0].load(core::sync::atomic::Ordering::Acquire),
        RING3_SPAWN[1].load(core::sync::atomic::Ordering::Acquire),
        RING3_SPAWN[2].load(core::sync::atomic::Ordering::Acquire),
    ];
    // The started program runs on another CPU and reports on its own account,
    // so this waits for it rather than assuming the probe's exit means it is
    // finished. A program that never started is the failure being tested for;
    // a program that started slowly is not.
    wait_until(
        || RING3_STARTED.load(core::sync::atomic::Ordering::Acquire) != u64::MAX,
        8_000,
    );
    let granted = RING3_GRANT_START[0].load(core::sync::atomic::Ordering::Acquire);
    let started = RING3_GRANT_START[1].load(core::sync::atomic::Ordering::Acquire);
    let ran = RING3_STARTED.load(core::sync::atomic::Ordering::Acquire);

    // Everything about the child, read *before* the parent is destroyed. After
    // that the answers would all be "gone", which is true and says nothing.
    let child = domain::child_of(realm);
    let _ = child;
    // What the child *holds*, not what it has been charged for.
    //
    // The first version asked `held_capabilities()`, which is a quota counter
    // that only the charging paths update — so a capability installed straight
    // into the child's CSpace left it reading zero. Watched failing by giving
    // the child a copy of its creator's endpoint, which is what inheriting a
    // capability space would do: the check passed, because it was measuring
    // the accounting rather than the contents.
    // Taken at the moment the child was created, not now.
    //
    // The service reads it while the probe is blocked in the call that reports
    // its `SPAWN` results — so the probe cannot yet have granted or started
    // anything, because both are the next things it does and it has not been
    // replied to. Reading it here instead would read it after the grant and
    // the start, and "holds nothing" would be false for the best of reasons.
    let child_empty = RING3_CHILD_HELD.load(core::sync::atomic::Ordering::Acquire) == 0;

    RING3_STOP.store(true, core::sync::atomic::Ordering::Release);
    ipc::destroy(endpoint);
    domain::destroy(realm);

    // And after: destroying the parent must take the child's charge with it.
    let charge_returned = child.is_none_or(|child| domain::with(child, |_| ()).is_none());

    let (calls, refused, revoked) = syscall::statistics();
    let calls = calls - calls_before;
    let refused = refused - refused_before;
    let revoked = revoked - revoked_before;
    let (rip, rsp) = syscall::last_user_context();
    let interrupts = bhaskix_arch::trap::interrupts_from_user() - interrupts_before;

    let stack_top = USER_STACK + USER_STACK_PAGES * bhaskix_mm::FRAME_SIZE;
    let checks = [
        // Ten: eight yields, one bad number, one exit.
        ("the probe made its system calls", calls >= 11),
        ("an unknown syscall number was refused", refused >= 1),
        (
            "the kernel was entered from the user code page",
            (USER_CODE..USER_CODE + bhaskix_mm::FRAME_SIZE).contains(&rip),
        ),
        // Either user stack. Since RFC 0017 step 5 there are two programs in
        // ring 3 here -- the probe, and the one it started -- and the last
        // system call is the started program's. That it arrives from a
        // *different* user stack is evidence for the step rather than against
        // the claim: what is being asserted is that the kernel was entered
        // from user memory, and both of these are addresses the kernel never
        // uses as a stack.
        (
            "the caller was on a user stack",
            (rsp > USER_STACK && rsp <= stack_top)
                || (rsp > STARTED_STACK
                    && rsp <= STARTED_STACK + STARTED_STACK_PAGES * bhaskix_mm::FRAME_SIZE),
        ),
        // Without this the probe only ever enters the kernel through
        // `SYSCALL`, and the interrupt entry path -- with its own `swapgs`,
        // its own stack switch through the TSS, and its own way to be wrong --
        // is never reached. Removing that `swapgs` passed a version of this
        // test that lacked this line.
        ("the probe was interrupted while in ring 3", interrupts > 0),
        // The IPC half. Four calls reach the service: the segment report and
        // two exchanges through the capability the kernel installed, and one
        // through the capability ring 3 derived for itself. The call through
        // the badge it *tried to forge* is not among them, and neither is the
        // one after revocation.
        ("ring 3 reached a service through IPC", ring3_calls == 8),
        // RFC 0017 step 4. A program with a `DomainControl` created a domain,
        // and the two refusals are worth as much as the success: one says the
        // envelope is checked as well as the capability, the other says the
        // *kind* is checked and not merely the rights.
        (
            "a program created a domain",
            spawned[0] == bhaskix_abi::status::OK,
        ),
        (
            "a second was refused by the creator's envelope",
            spawned[1] == bhaskix_abi::status::QUOTA_EXCEEDED,
        ),
        (
            "spawning on something that is not a DomainControl was refused",
            spawned[2] == bhaskix_abi::status::WRONG_OBJECT,
        ),
        // What came back is *empty*. This is the whole shape of the design: a
        // child holds only what it is granted afterwards, so a fresh one holds
        // nothing at all.
        ("the domain it created holds nothing", child_empty),
        (
            "it is named what ring 3 asked for",
            RING3_CHILD_NAMED.load(core::sync::atomic::Ordering::Acquire) == 1,
        ),
        (
            "the creator was charged for it",
            RING3_CHILD_CHARGED.load(core::sync::atomic::Ordering::Acquire) == 1,
        ),
        // RFC 0017 step 5, and the two steps that make step 4 worth anything.
        // A child that cannot be given a capability holds nothing for ever,
        // and a child that cannot be started never uses what it holds.
        (
            "ring 3 gave its child a capability",
            granted == bhaskix_abi::status::OK,
        ),
        (
            "ring 3 started a program in it",
            started == bhaskix_abi::status::OK,
        ),
        (
            "starting a program in something that is not a domain was refused",
            RING3_GRANT_START[2].load(core::sync::atomic::Ordering::Acquire)
                == bhaskix_abi::status::WRONG_OBJECT,
        ),
        (
            "giving away a capability it may only hold was refused",
            RING3_GRANT_START[3].load(core::sync::atomic::Ordering::Acquire)
                == bhaskix_abi::status::INSUFFICIENT_RIGHTS,
        ),
        // RFC 0017 step 6. A supervisor, in ring 3, in five system calls: it
        // asked to be told, waited on a notification it already knew how to
        // wait on, asked what happened, and gave the slot back.
        (
            "ring 3 asked to be told when its child ended",
            RING3_REAP[0].load(core::sync::atomic::Ordering::Acquire) == bhaskix_abi::status::OK,
        ),
        (
            "it was told the child had exited, not merely that it had gone",
            RING3_REAP[1].load(core::sync::atomic::Ordering::Acquire)
                == domain::Ending::Exited as u64,
        ),
        (
            "it reaped the child",
            RING3_REAP[2].load(core::sync::atomic::Ordering::Acquire) == bhaskix_abi::status::OK,
        ),
        // The reaping took the capability with it. A holder that could still
        // ask would be asking about whatever takes the slot next.
        (
            "asking after the reaping answers nothing",
            RING3_REAP[3].load(core::sync::atomic::Ordering::Acquire)
                == bhaskix_abi::status::NO_SUCH_CAPABILITY,
        ),
        // The one that cannot be faked. This message arrived from a program
        // the probe created, granted and started -- on an endpoint it could
        // only reach through the capability it was given.
        (
            "the program it started ran and used what it was given",
            ran == 0x53_5441_5254,
        ),
        (
            "destroying the creator took the child with it",
            charge_returned,
        ),
        (
            "the service saw the badge from the probe's capability",
            ring3_badge == BADGE_RING3,
        ),
        // The decisive one: user mode sent back the value it was told, so the
        // reply reached ring 3 rather than merely being delivered.
        ("the reply reached user mode", echoed),
        // Delegation, asked for by ring 3 rather than arranged for it: weaker
        // rights, and the capability works.
        (
            "ring 3 derived a capability and used it",
            delegated_badge == BADGE_RING3,
        ),
        // And the rule that makes a badge worth anything. The probe also asked
        // for a copy under a badge it invented; the kernel refused, so that
        // slot stayed empty, the call through it reached nobody, and no
        // message ever carried the badge. Both halves are asserted because
        // either alone would pass for the wrong reason -- a kernel that
        // refused *every* derivation would leave this badge unseen too, and
        // the check above is what rules that out.
        ("ring 3 could not choose its own badge", !forged),
        // And revocation, also asked for by ring 3. The slot is still in the
        // CSpace; the authority behind it is gone, so the call fails rather
        // than reaching a service that is still perfectly willing to answer.
        ("revoking from ring 3 stopped the next call", revoked >= 1),
        // The loader's obligations, reported by the program itself. Nothing
        // in the kernel put this number anywhere: it is in the file, in a
        // segment the loader had to map read-only at the address the file
        // named, and the probe reached it by absolute address. See
        // `SEGMENT_MAGIC`.
        (
            "the program read its own segments at the addresses its headers named",
            segments == SEGMENT_MAGIC,
        ),
    ];

    let mut ok = true;
    for (name, passed) in checks {
        if !passed {
            println!(
                "\x1b[91m    ring 3         FAILED: {name} (calls {calls}, refused {refused}, rip {rip:#x}, rsp {rsp:#x}, segments {segments:#x})\x1b[0m"
            );
            ok = false;
            // What the service did, and what the endpoint looked like when it
            // did it. Every one of these failures is a call that went
            // unanswered, and the three ways that happens -- the service left,
            // the message was never handed over, the wake found nobody -- are
            // told apart here and nowhere else.
            let left = RING3_RECV_ERROR.load(core::sync::atomic::Ordering::Acquire);
            if left != 0 {
                println!("      the service stopped receiving: error {}", left - 1);
            }
            let (dropped, wake_missed, received, tried, no_caller, empty) = ipc::diagnostics();
            println!(
                "      ipc: dropped {dropped}, wake missed {wake_missed}, recv returned \
                 {received}, reply tried {tried}, no caller {no_caller}, empty {empty}"
            );
            match syscall::last_recv_refusal() {
                Some((thread, status)) => {
                    println!("      the last refused receive was thread {thread}, status {status}");
                }
                None => println!("      no receive has been refused"),
            }
            // Where the two threads actually are. A probe that is `Blocked` is
            // waiting for an answer; one that is `Finished` gave up or was
            // stopped; and a service that is `Finished` is a service that will
            // never answer anybody again. Those are three different bugs and
            // they look identical in the counters.
            sched::for_each(|cpu, id, name, state, runs, _migrations, _class| {
                if matches!(name, "ring3" | "r3-svc") {
                    println!("      cpu {cpu} thread {id} ({name}) {state:?}, {runs} runs");
                }
            });
        }
    }

    if ok {
        println!(
            "    ring 3         {calls} syscalls, {interrupts} interrupts from user mode; {ring3_calls} ipc calls badged {ring3_badge:#x}; ring 3 derived, used and revoked its own capability ({revoked} refused after); loaded from bin/probe, three segments as its headers asked"
        );
    }
    ok
}

/// Reads the initial ramdisk and reports what is in it.
///
/// The bytes come from a file on the boot medium, so this is the first time
/// the kernel parses something an attacker controls end to end. What it
/// asserts is modest on purpose — that a known member is present with its
/// known contents — because the interesting property is not that a good
/// archive parses. It is that a bad one cannot make the parser misbehave, and
/// that is proved by a million mutated archives on the host, not here.
fn initrd_self_test(handoff: &Handoff) -> bool {
    let Some(bytes) = handoff.initrd else {
        println!("\x1b[91m    initrd         FAILED: the bootloader loaded no module\x1b[0m");
        return false;
    };

    let archive = ustar::Archive::new(bytes);
    let members = archive.members();

    let hostname = archive.lookup(b"etc/hostname").map(|entry| entry.data());
    let hello = archive.lookup(b"hello.txt").map(|entry| entry.data());
    let directories = ustar::Archive::new(bytes)
        .filter(|entry| entry.kind() == ustar::EntryKind::Directory)
        .count();

    let checks = [
        ("the archive has members", members >= 4),
        (
            "a file's contents came through byte for byte",
            hostname == Some(b"bhaskix\n".as_slice()),
        ),
        ("a file in the root was found", hello.is_some()),
        ("directories are distinguished from files", directories >= 1),
    ];

    let mut ok = true;
    for (name, passed) in checks {
        if !passed {
            println!(
                "\x1b[91m    initrd         FAILED: {name} ({members} members, {directories} dirs)\x1b[0m"
            );
            ok = false;
        }
    }

    if ok {
        println!(
            "    initrd         {} KiB, {members} members, {directories} directories; etc/hostname reads back",
            bytes.len() / 1024
        );
    }
    ok
}

/// Where the filesystem domain's stack, image and program live.
///
/// The same addresses the shell uses for the same things, because they never
/// share an address space and using different ones would suggest the kernel
/// keeps a map of who is where. It does not: each program says where it goes.
const VFSD_STACK: u64 = 0x0000_0000_1100_0000;
const VFSD_STACK_PAGES: u64 = 4;

/// Where the filesystem image is mapped in the domain that serves it.
///
/// Read-only, and the only memory in that domain it did not allocate itself.
/// A service in the nucleus reaches storage by calling into the kernel; a
/// service in a domain is *handed* exactly what it may read, at entry, and can
/// reach nothing else — which is the difference the placement is for.
const VFSD_IMAGE: u64 = 0x0000_0000_2000_0000;

/// Where the filesystem service's program is.
const VFSD_PROGRAM: &[u8] = b"bin/vfsd";

/// Loads `bin/vfsd` and becomes the filesystem service, in ring 3.
///
/// The domain placement of RFC 0013. The kernel reads the program and the
/// image with its own filesystem code — it still has some, for its own shell —
/// maps both, hands over the endpoint, and enters ring 3, after which every
/// `fs::` method in the system is answered by a program with no privilege at
/// all.
///
/// Two things are given and nothing else: an endpoint capability at slot 0,
/// and the image. A domain that could find its own storage would not be a
/// domain.
/// Where the console domain's stack and program live.
const CONSOLED_STACK: u64 = 0x0000_0000_1100_0000;
const CONSOLED_STACK_PAGES: u64 = 4;

/// Where the console service's program is.
const CONSOLED_PROGRAM: &[u8] = b"bin/consoled";

/// Where the supervisor's stack and program live.
const SUP_STACK: u64 = 0x0000_0000_1200_0000;
const SUP_STACK_PAGES: u64 = 4;
const SUP_PROGRAM: &[u8] = b"bin/sup";

/// How many bytes of `bin/probe` the supervisor's image object holds.
///
/// Passed to the program at entry, because `START` refuses a length of zero and
/// a supervisor cannot measure memory it was handed -- it holds a capability,
/// not a mapping, and there is no method that reports an object's size. Telling
/// it at entry is the same affordance `enter_ring3` documents: everything a
/// domain has arrives through its CSpace, and this is the one thing that
/// cannot.
static SUP_IMAGE_BYTES: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// The badge the supervisor's console capability carries.
///
/// Its own, not the shell's. A badge is what a service is told about a caller,
/// and two programs sharing one are two programs the console cannot tell apart
/// -- which is only a reporting nuisance here and is exactly the property a
/// badge exists to provide, so spending a distinct one is the honest default.
const BADGE_SUPERVISOR: u64 = 0x0000_0000_0050_0000;

/// The console object every `Console` capability names.
///
/// One, because there is one console. The identity is not used for anything —
/// the kernel prints to the machine's console either way — but it exists so
/// that a capability names an object rather than naming nothing, which is the
/// difference between a capability system and a permission bit.
const CONSOLE_OBJECT: u64 = 0;

/// Mounts an image in the new on-disk format, read-only, beside the archive.
///
/// RFC 0015 step 3, and "beside the archive" is literal: the image is a member
/// of it. The machine reads a file out of each, which is the smallest thing
/// that proves the format works *in a machine* rather than in a host test —
/// and it is read-only in that order deliberately, so that a bug in a writer
/// cannot be mistaken for a bug in the reader.
fn filesystem_self_test() -> bool {
    /// What `mkfs` put in the image, and nothing else on this machine has.
    const EXPECTED: &[u8] = b"a file in a filesystem this kernel defined\n";

    let Ok(image) = vfs::open(b"fs.img") else {
        println!("    filesystem     no fs.img in the archive; nothing to mount");
        return true;
    };

    let mut pages = bhaskix_fs::Image::new(image.bytes());
    let mut mounted = match bhaskix_fs::Filesystem::mount(&mut pages) {
        Ok(mounted) => mounted,
        Err(error) => {
            println!("\x1b[91m    filesystem     FAILED to mount: {error:?}\x1b[0m");
            return false;
        }
    };

    let Ok(root) = mounted.root() else {
        println!("\x1b[91m    filesystem     FAILED: the root is not a directory\x1b[0m");
        return false;
    };

    let mut names = 0;
    mounted.list(&root, |_| names += 1);

    let Ok((index, inode)) = mounted.lookup(&root, b"greeting") else {
        println!("\x1b[91m    filesystem     FAILED: no `greeting` in the root\x1b[0m");
        return false;
    };

    let mut contents = [0u8; 64];
    let read = mounted.read(&inode, 0, &mut contents);
    let matches = contents.get(..read) == Some(EXPECTED);

    // And the same bytes are *not* reachable through the archive, which is
    // what makes this two filesystems rather than one read twice.
    let separate = vfs::open(b"greeting").is_err();

    let ok = matches && separate && names >= 2;
    if ok {
        let superblock = mounted.superblock();
        println!(
            "    filesystem     bhfs mounted from the archive: {} blocks, {names} entries, \
             `greeting` is inode {index} and reads {read} bytes that the archive does not have",
            superblock.blocks
        );
    } else {
        println!(
            "    filesystem     FAILED: {read} bytes, contents match {matches}, \
             separate from the archive {separate}, {names} entries"
        );
    }
    ok
}

/// An image the machine formats and writes to, in memory.
///
/// Thirty-two blocks: a superblock, a bitmap, two of inode table, the
/// journal's nine, and room to write into. Sixteen left three data blocks,
/// which is fewer than a directory with a file in it needs. In `.bss` rather than on a stack, because
/// sixty-four kilobytes of stack is not a thing this kernel has, and rather
/// than on the heap because a self-test that can fail for want of memory is a
/// self-test that reports the wrong thing when it does.
static mut JOURNAL_IMAGE: [u8; 32 * bhaskix_fs::BLOCK] = [0; 32 * bhaskix_fs::BLOCK];

/// The pages that filesystem is cached in.
///
/// Eight, which is more than any one transaction needs and few enough that the
/// eviction path is exercised rather than merely present.
static mut JOURNAL_FRAMES: [u8; 8 * bhaskix_fs::BLOCK] = [0; 8 * bhaskix_fs::BLOCK];

/// A device that counts what it was asked to write, and can stop being one.
///
/// The interruption belongs at the device, which is why it lives here rather
/// than in the filesystem: a machine that loses power loses it between two
/// writes reaching a disk, not between two calls.
struct Watched<'a> {
    bytes: &'a mut [u8],
    seen: u32,
    limit: u32,
    commit_block: u32,
    commit_at: Option<u32>,
}

impl<'a> Watched<'a> {
    /// A device over `bytes` that stops after `limit` writes.
    fn new(bytes: &'a mut [u8], limit: u32, commit_block: u32) -> Self {
        Self {
            bytes,
            seen: 0,
            limit,
            commit_block,
            commit_at: None,
        }
    }
}

impl bhaskix_fs::Store for Watched<'_> {
    fn blocks(&self) -> u32 {
        u32::try_from(self.bytes.len() / bhaskix_fs::BLOCK).unwrap_or(u32::MAX)
    }

    fn read(&mut self, block: u32, into: &mut [u8]) -> Result<(), bhaskix_fs::FsError> {
        let at = (block as usize) * bhaskix_fs::BLOCK;
        let from = self
            .bytes
            .get(at..at + bhaskix_fs::BLOCK)
            .ok_or(bhaskix_fs::FsError::OutOfRange)?;
        into.get_mut(..bhaskix_fs::BLOCK)
            .ok_or(bhaskix_fs::FsError::OutOfRange)?
            .copy_from_slice(from);
        Ok(())
    }

    fn write(&mut self, block: u32, from: &[u8]) -> Result<(), bhaskix_fs::FsError> {
        if self.seen >= self.limit {
            return Err(bhaskix_fs::FsError::Interrupted);
        }
        let at = (block as usize) * bhaskix_fs::BLOCK;
        let into = self
            .bytes
            .get_mut(at..at + bhaskix_fs::BLOCK)
            .ok_or(bhaskix_fs::FsError::OutOfRange)?;
        into.copy_from_slice(
            from.get(..bhaskix_fs::BLOCK)
                .ok_or(bhaskix_fs::FsError::OutOfRange)?,
        );
        if block == self.commit_block && self.commit_at.is_none() {
            self.commit_at = Some(self.seen);
        }
        self.seen += 1;
        Ok(())
    }
}

/// A filesystem written, interrupted, and recovered — in the machine.
///
/// The host harness stops at every device write of every operation and is the
/// real proof; this is the part it cannot do, which is to show the same code
/// doing the same thing on this kernel, compiled for this target, with no
/// `std` underneath it and its pages in `.bss`. The interruption is the one
/// that matters most: the machine stopped *after* the commit and before
/// anything reached its home, which is the only interruption where recovery
/// has work to do.
fn journal_self_test() -> bool {
    use bhaskix_fs::{BLOCK, Cache, Filesystem, FsError, Image, Kind, Volume};

    // SAFETY: called once, from the boot CPU, before any other thread exists.
    // Neither buffer is reachable from anywhere else -- nothing else in this
    // kernel names them -- so these are the only references to them in
    // existence.
    let (image, frames) = unsafe {
        (
            &mut *core::ptr::addr_of_mut!(JOURNAL_IMAGE),
            &mut *core::ptr::addr_of_mut!(JOURNAL_FRAMES),
        )
    };
    if bhaskix_fs::format(image, 128).is_err() {
        println!("\x1b[91m    journal        FAILED to format an image in memory\x1b[0m");
        return false;
    }
    let Ok(superblock) = bhaskix_fs::Superblock::read(image) else {
        return false;
    };
    let commit_block = superblock.journal_start as u32;

    // A file, and something in it, uninterrupted.
    let (root, hits, misses) = {
        let Ok(cache) = Cache::new(frames, Watched::new(image, u32::MAX, commit_block)) else {
            println!("\x1b[91m    journal        FAILED: not enough frames to cache with\x1b[0m");
            return false;
        };
        let Ok((mut volume, replayed)) = Volume::mount(cache) else {
            println!(
                "\x1b[91m    journal        FAILED: a freshly formatted image will not mount\x1b[0m"
            );
            return false;
        };
        if replayed != 0 {
            println!(
                "\x1b[91m    journal        FAILED: a fresh image had {replayed} blocks to replay\x1b[0m"
            );
            return false;
        }
        let root = volume.superblock().root;
        let Ok(index) = volume.create(root, b"survivor", Kind::File) else {
            println!("\x1b[91m    journal        FAILED to create a file\x1b[0m");
            return false;
        };
        if volume.write(index, 0, b"written in a machine\n").is_err() {
            println!("\x1b[91m    journal        FAILED to write to it\x1b[0m");
            return false;
        }
        // Read it straight back, which is what makes the hit count mean
        // something: these pages are in frames, and the device is not asked.
        let mut reader = volume.reader();
        let Ok(inode) = reader.inode(index) else {
            return false;
        };
        let mut back = [0u8; 32];
        let read = reader.read(&inode, 0, &mut back);
        if back.get(..read) != Some(b"written in a machine\n".as_slice()) {
            println!(
                "\x1b[91m    journal        FAILED: it did not read back what was written\x1b[0m"
            );
            return false;
        }
        let (hits, misses, _) = volume.counted();
        (root, hits, misses)
    };

    // Where the commit is, so that the interruption is placed *just* after it
    // rather than at a number somebody guessed.
    let commit_at = {
        let Ok(cache) = Cache::new(frames, Watched::new(image, u32::MAX, commit_block)) else {
            return false;
        };
        let Ok((mut volume, _)) = Volume::mount(cache) else {
            return false;
        };
        // Counted on a name that is then removed again, so the image is back
        // where it started and the interrupted run below is the only one that
        // leaves anything behind.
        let _ = volume.create(root, b"counted", Kind::File);
        let at = volume.cache().store().commit_at;
        let _ = volume.remove(root, b"counted");
        match at {
            Some(at) => at,
            None => {
                println!("\x1b[91m    journal        FAILED: no commit block was written\x1b[0m");
                return false;
            }
        }
    };

    // The same operation, stopped one device write after its commit.
    let interrupted = {
        let Ok(cache) = Cache::new(frames, Watched::new(image, commit_at + 1, commit_block)) else {
            return false;
        };
        let Ok((mut volume, _)) = Volume::mount(cache) else {
            return false;
        };
        volume.create(root, b"recovered", Kind::File)
    };
    if interrupted != Err(FsError::Interrupted) {
        println!(
            "\x1b[91m    journal        FAILED: the interruption did not stop it: {interrupted:?}\x1b[0m"
        );
        return false;
    }

    // A read-only mount must refuse this image: it holds a transaction that
    // was acknowledged and not applied, and a reader that ignored it would
    // hand back the filesystem as it was before an operation that already
    // happened. Read through `Image` and not through the cache, because what a
    // cache remembers is exactly what must not count as durable.
    let refused = {
        let mut pages = Image::new(image);
        Filesystem::mount(&mut pages).err() == Some(FsError::NeedsRecovery)
    };

    // And mounting it for writing recovers it.
    let (replayed, found, kept) = {
        let Ok(cache) = Cache::new(frames, Watched::new(image, u32::MAX, commit_block)) else {
            return false;
        };
        let Ok((mut volume, replayed)) = Volume::mount(cache) else {
            println!(
                "\x1b[91m    journal        FAILED: an interrupted image will not mount\x1b[0m"
            );
            return false;
        };
        let found = volume.lookup(root, b"recovered").is_ok();
        let kept = volume.lookup(root, b"survivor").is_ok();
        (replayed, found, kept)
    };

    let ok = refused && found && kept && replayed > 0 && hits > 0;
    if ok {
        println!(
            "    journal        wrote a filesystem through {} cached pages ({hits} hits, \
             {misses} misses), stopped it one device write after the commit, and mounting \
             replayed {replayed} blocks: `recovered` is there and so is `survivor`",
            frames.len() / BLOCK
        );
    } else {
        println!(
            "    journal        FAILED: read-only refused {refused}, replayed {replayed}, \
             the interrupted file is present {found}, the earlier one {kept}, {hits} cache hits"
        );
    }
    ok
}

/// Where configuration space is, physically, once `MCFG` has been read.
static ECAM_REGION: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// The first bus that region covers.
static ECAM_FIRST_BUS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// The physical page holding one function's configuration space.
///
/// `None` before `MCFG` has been read, or on a machine without one — where
/// configuration is a pair of ports and cannot be handed to anybody, which is
/// the whole reason RFC 0013 step 6 said the bus stays in the kernel.
fn configuration_page(address: bhaskix_arch::pci::Address) -> Option<u64> {
    use core::sync::atomic::Ordering;

    let base = ECAM_REGION.load(Ordering::Acquire);
    if base == 0 {
        return None;
    }
    let first = ECAM_FIRST_BUS.load(Ordering::Relaxed);
    let bus = u64::from(address.bus);
    if bus < first {
        return None;
    }
    Some(
        base + ((bus - first) << 20)
            + ((u64::from(address.device) & 0x1f) << 15)
            + ((u64::from(address.function) & 0x07) << 12),
    )
}

/// Finds memory-mapped configuration space, maps it, and checks it agrees.
///
/// RFC 0014 step 4. `MCFG` says where configuration space is as memory; the
/// port pair at `0xcf8` says the same thing a word at a time. Both are kept,
/// and this is why: the port path is the **oracle**. "The new mechanism found
/// three devices" is not evidence that it found the right three, and the only
/// cheap way to know is to ask the old one and compare.
///
/// Every function on every bus is read both ways and the answers must match.
/// A single disagreement is reported with the address, because a mechanism
/// that is right about 255 devices and wrong about one is the worst case to
/// find later.
fn ecam_bringup(handoff: &Handoff) -> bool {
    let hhdm = handoff.hhdm_base.as_u64();
    let Some(rsdp) = handoff.rsdp else {
        println!("    ecam           no acpi tables, so the port pair it is");
        return true;
    };

    // SAFETY: the handoff's address, and `mmio::map` is the same mapper the
    // other table walkers here use.
    let found = unsafe {
        bhaskix_arch::acpi::mcfg(rsdp.as_u64(), hhdm, &mut |physical, length| {
            crate::mmio::map(physical, length as u64, hhdm).is_some()
        })
    };
    let Some(mcfg) = found else {
        // Not a failure. A machine with no MCFG is a machine that uses the
        // ports, which is every machine this kernel ran on until today.
        println!("    ecam           no MCFG; configuration stays on the port pair");
        return true;
    };

    let Some(region) = mcfg.regions().next() else {
        println!("    ecam           MCFG lists no usable region");
        return true;
    };

    let Some(mapped) = crate::mmio::map(region.base, region.length(), hhdm) else {
        println!(
            "\x1b[91m    ecam           FAILED to map {} KiB at {:#x}\x1b[0m",
            region.length() / 1024,
            region.base
        );
        return false;
    };

    // SAFETY: `mmio::map` returned a mapping of exactly the region `MCFG`
    // described, device-mapped and never unmapped.
    unsafe {
        bhaskix_arch::pci::use_ecam(mapped, region.start_bus, region.end_bus, region.length())
    };
    // Kept so a function's configuration page can be named later. It is a
    // page of ordinary memory now, which is what makes it something a
    // capability can hold — and the reason RFC 0014 had to decide how much of
    // it a domain may see.
    ECAM_REGION.store(region.base, core::sync::atomic::Ordering::Release);
    ECAM_FIRST_BUS.store(
        u64::from(region.start_bus),
        core::sync::atomic::Ordering::Relaxed,
    );

    // And now the comparison, which is the whole point of keeping both.
    let mut checked = 0u32;
    let mut present = 0u32;
    let mut disagreed = 0u32;
    let mut first_disagreement = None;
    for bus in region.start_bus..=region.end_bus {
        for device in 0..32u8 {
            for function in 0..8u8 {
                let address = bhaskix_arch::pci::Address::new(bus, device, function);
                // SAFETY: configuration reads on the bootstrap CPU during
                // boot; nothing else is driving a configuration cycle.
                let ports = unsafe { bhaskix_arch::pci::read32(address, 0x00) };
                checked += 1;
                let Some(memory) = bhaskix_arch::pci::read32_ecam(address, 0x00) else {
                    // In range by bus and refused anyway: the address the
                    // arithmetic produced is outside the mapping, which is a
                    // disagreement about *where a function is* rather than
                    // about what it says.
                    disagreed += 1;
                    if first_disagreement.is_none() {
                        first_disagreement = Some((address, ports, 0));
                    }
                    continue;
                };
                if ports != 0xffff_ffff {
                    present += 1;
                }
                if ports != memory {
                    disagreed += 1;
                    if first_disagreement.is_none() {
                        first_disagreement = Some((address, ports, memory));
                    }
                }
            }
        }
    }

    if let Some((address, ports, memory)) = first_disagreement {
        println!(
            "    ecam           FAILED: {:02x}:{:02x}.{} reads {ports:#010x} by port and \
             {memory:#010x} by memory ({disagreed} of {checked} disagree)",
            address.bus, address.device, address.function
        );
        return false;
    }

    println!(
        "    ecam           {:#x} for buses {}..={}, {checked} functions read both ways, \
         {present} present, none disagreed",
        region.base, region.start_bus, region.end_bus
    );
    true
}

/// Where the block driver's domain keeps its stack and its rings.
const BLKD_STACK: u64 = 0x0000_0000_1100_0000;
const BLKD_STACK_PAGES: u64 = 4;

/// Where the block driver's program is.
const BLKD_PROGRAM: &[u8] = b"bin/blkd";

/// Enters ring 3, refusing to do it from a thread that may migrate.
///
/// **A ring 3 thread in this kernel must be pinned**, and until now that was a
/// convention nobody had written down. Every user program happened to be
/// spawned pinned; the first one that was not corrupted two other domains and
/// took a day to find.
///
/// The reason is the privileged stack. `install_kernel_stack` sets `RSP0` from
/// the incoming thread's own `kernel_stack_top` on every switch — but it
/// returns early when that is zero, which it is for a thread whose kernel
/// stack was installed for a *specific CPU* rather than carried by the thread.
/// Such a thread moved to another CPU enters the kernel on **somebody else's
/// stack**, and what that looks like from outside is a null pointer in a
/// driver, a service that stops answering, and a shell that never starts.
///
/// So the rule is checked here, at the one door into ring 3, and a thread that
/// breaks it is stopped rather than allowed to corrupt whatever it lands on.
/// Refusing is not a fix for the underlying limit — a kernel stack that
/// travelled with its thread would be — and the refusal says so.
///
/// # Safety
///
/// As `enter_ring3`: `entry` must be user-executable and `rsp` user-writable in
/// the address space currently installed.
unsafe fn enter_user(who: &str, entry: u64, rsp: u64, arguments: [u64; 2]) -> ! {
    let pinned = sched::current_thread_id().and_then(sched::is_pinned);
    if pinned != Some(true) {
        println!(
            "    {who}          FAILED: a ring 3 thread must be pinned, and this one is not; \
             it would enter the kernel on another CPU's stack if it moved"
        );
        sched::exit()
    }
    // SAFETY: delegated to this function's own contract.
    unsafe { bhaskix_arch::syscall::enter_ring3(entry, rsp, arguments) }
}

/// Where the filesystem service's stack goes in its own address space.
/// Deliberately not the address every other program uses, for the reason its
/// code is not: a fault report gives `rip` and `rsp`, and when every program
/// has both the same, neither says which one faulted.
const FSD_STACK: u64 = 0x0000_0000_1300_0000;
/// How many pages of it.
const FSD_STACK_PAGES: u64 = 4;
/// The filesystem service, in the archive.
const FSD_PROGRAM: &[u8] = b"bin/fsd";
/// The badge on the filesystem service's capability to the block service.
const BADGE_FS_BLOCK: u64 = 0x0000_0000_00f5_b100;

/// Hands the *second* block device to a domain, and starts a driver for it.
///
/// The kernel drives the first and never touches this one. Two drivers on one
/// device would race resets and interleave rings; a driver in a domain gets a
/// device of its own, which is also how a real system would do it.
///
/// What the domain is given, and it is everything it gets:
///
/// - three `Frame` capabilities, one per structure the virtio 1.0 transport
///   defines — common configuration, queue notification, device configuration;
/// - a `Memory` object for its rings, which it maps for itself.
///
/// What it is *not* given is the bus. Finding those three structures means
/// reading PCI configuration space, which is port I/O: a domain holding that
/// would hold every device on the machine, so the kernel enumerates and the
/// domain drives. The split is not a convenience — it is where the hardware
/// puts the line.
pub fn start_block_domain(
    cpu: u32,
    hhdm_base: u64,
    apic_id: u32,
    rsdp: Option<bhaskix_boot::PhysAddr>,
) -> Result<(), &'static str> {
    let Some((address, _)) = virtio::find_nth(1) else {
        // One device, so nothing to delegate. Not an error: a machine with a
        // single disk is a machine the kernel drives, and saying so beats
        // failing to boot.
        println!("    block domain   no second device on the bus; nothing delegated");
        return Ok(());
    };
    let layout = virtio::layout(address).ok_or("the second block device is not a modern virtio")?;

    // Memory space, so its BARs answer. Bus mastering is *not* enabled here:
    // the driver asks for that itself once it has reset the device and built
    // its rings, and a device that could write to memory before its owner was
    // ready would do so with whatever the firmware left in its registers.
    // SAFETY: this device belongs to nobody yet -- the kernel's own driver
    // took the first one, and this is the second.
    unsafe { bhaskix_arch::pci::enable_memory(address) };

    let realm = domain::create("blk", domain::ResourceEnvelope::new())
        .map_err(|_| "the block domain would not be created")?;

    // One `Frame` per structure. A `Frame` names one page, so a structure
    // spanning two would need two capabilities -- which is worth knowing and
    // is why the length is checked rather than assumed.
    let windows = [layout.common, layout.notify, layout.device];
    for (slot, (base, length)) in windows.iter().enumerate() {
        if *length > bhaskix_mm::FRAME_SIZE {
            return Err("a virtio structure spans more than one page");
        }
        let window = cap::with_arena(|arena| {
            arena
                .insert_root(
                    cap::ObjectRef::new(
                        cap::ObjectKind::Frame,
                        base & !(bhaskix_mm::FRAME_SIZE - 1),
                    ),
                    // `DERIVE` too, so the driver may make itself weaker
                    // copies -- and, more to the point here, so that the one
                    // thing standing between it and *handing one away* is
                    // `GRANT`. Without `DERIVE` the refusal would come from
                    // the derive instead, and the test that watches `GRANT`
                    // hold would pass with `GRANT` deleted.
                    cap::Rights::READ
                        .union(cap::Rights::WRITE)
                        .union(cap::Rights::DERIVE),
                    0,
                )
                .ok()
        })
        .ok_or("a device window capability would not be created")?;
        if domain::with(realm, |owner| owner.cspace.install_at(slot, window).is_ok()) != Some(true)
        {
            return Err("a device window capability would not install");
        }
    }

    // Rings. Four pages, which is more than the descriptor table, available
    // and used rings need for a queue this small -- and the slack is where the
    // request headers and the sector go.
    // Owned by a domain that outlives the driver, not by the driver.
    //
    // `bin/blkd` exits when its endpoint stops answering, and since 2026-08-11
    // a domain ends when its last thread exits -- and ending destroys the
    // memory that domain owns. Rings owned by the driver would be freed the
    // moment it stopped, and the check that reads them afterwards would be
    // reading returned frames. `blk-keeper` runs nothing, so nothing ends it.
    let keeper = domain::create("blk-keeper", domain::ResourceEnvelope::new())
        .map_err(|_| "the block rings' owner would not be created")?;
    let rings = shared::create(keeper, 4 * bhaskix_mm::FRAME_SIZE)
        .map_err(|_| "the block domain's rings would not be created")?;
    let named = shared::name(rings).map_err(|_| "the rings would not be named")?;
    if domain::with(realm, |owner| owner.cspace.install_at(3, named).is_ok()) != Some(true) {
        return Err("the rings capability would not install");
    }

    // The authority to say what this *device* may reach, which is strictly
    // more than holding memory: a device writes with no page table and asks
    // nobody. Granted only when there is a unit to contain it — without one a
    // device address is a physical address, and a domain that could name one
    // could point its device at the kernel. A driver in a domain doing DMA
    // with nothing translating is not a smaller trusted base, it is the same
    // trusted base further away.
    let delegated = (address.bus, address.device, address.function);
    let contained = if iommu::present_for(delegated) {
        let window = iommu::name(delegated).map_err(|_| "the dma window would not be named")?;
        if domain::with(realm, |owner| owner.cspace.install_at(4, window).is_ok()) != Some(true) {
            return Err("the dma window capability would not install");
        }
        true
    } else {
        false
    };

    println!(
        "    block domain   {:02x}:{:02x}.{} delegated: common {:#x}, notify {:#x} x{}, device {:#x}",
        address.bus,
        address.device,
        address.function,
        layout.common.0,
        layout.notify.0,
        layout.notify_multiplier,
        layout.device.0
    );
    if contained {
        println!("    block domain   dma window granted; the device translates through its own");
    }

    // The endpoint this driver answers block requests on, at slot 8.
    //
    // RFC 0015 step 1: a driver nothing could ask for a block was a driver
    // with no interface. It is also what the driver hands back to fill a
    // caller's memory, so holding it is what says this program is the block
    // service rather than a program pretending to be.
    let block_endpoint = ipc::create().map_err(|_| "no endpoint for the block service")?;
    // Recorded only once it is known the driver can *serve*, which needs a DMA
    // window: without one it cannot read a sector, so an endpoint nobody
    // answers would make the self-test below wait for something that is never
    // coming. Stored after the window is granted, below.
    let served = cap::with_arena(|arena| {
        arena
            .insert_root(
                cap::ObjectRef::new(
                    cap::ObjectKind::Endpoint,
                    u64::from(block_endpoint.as_u32()),
                ),
                cap::Rights::ALL,
                0,
            )
            .ok()
    })
    .ok_or("the block endpoint capability would not be created")?;
    if domain::with(realm, |owner| owner.cspace.install_at(8, served).is_ok()) != Some(true) {
        return Err("the block endpoint capability would not install");
    }

    // The device's own configuration space, read-only, at slot 7.
    //
    // RFC 0014 decided this: **read-only, and the BARs are never writable at
    // all**. A BAR decides *where in physical address space a device answers*,
    // and an IOMMU governs what a device reads rather than where it responds,
    // so no amount of translation makes a writable BAR safe. A read-only page
    // gives that for nothing — reading a BAR grants no authority, and writing
    // anything is refused by the capability's rights.
    //
    // It also answers the question acceptance left open. The command register
    // was to be "mediated", meaning a system call per bus-master enable; there
    // is none, because the kernel already enables bus mastering at the one
    // moment it is safe to — after the device is reset and when the DMA window
    // is granted. A syscall whose only effect the kernel performs anyway, at a
    // better time, is a syscall with nothing to do.
    let identified = match configuration_page(address) {
        Some(page) => {
            let window = cap::with_arena(|arena| {
                arena
                    .insert_root(
                        cap::ObjectRef::new(cap::ObjectKind::Frame, page),
                        // `GRANT` and `DERIVE` as well as `READ`: this is the
                        // one thing the driver may pass on, and passing it on
                        // is a weaker act than reading it -- a page that says
                        // what device this is.
                        //
                        // Both rights, because they are different permissions
                        // and handing something over needs each: `DERIVE` is
                        // the right to make a weaker copy at all, `GRANT` is
                        // the right to give one to somebody else. A capability
                        // with `GRANT` alone can be given away only as itself,
                        // which `HAND` never does. Every other capability this
                        // driver holds has neither, so `HAND` refuses them --
                        // a refusal the shell asks for and watches.
                        cap::Rights::READ
                            .union(cap::Rights::GRANT)
                            .union(cap::Rights::DERIVE),
                        0,
                    )
                    .ok()
            })
            .ok_or("the configuration capability would not be created")?;
            domain::with(realm, |owner| owner.cspace.install_at(7, window).is_ok()) == Some(true)
        }
        // No ECAM: configuration is a pair of ports, which cannot be handed to
        // anybody. The driver asks the kernel nothing and identifies nothing.
        None => false,
    };

    // The device's interrupt, claimed by the kernel and handed over as two
    // capabilities: the handler, and the notification it signals.
    //
    // Programming an MSI-X table entry stays here and is not delegable, for
    // the reason `ObjectKind::IrqHandler` gives: an MSI is a memory write of
    // an arbitrary vector to an arbitrary CPU, so a holder that could write
    // its own entry would hold an interrupt-injection primitive. What the
    // domain gets is the authority to *wait* for one and to acknowledge it,
    // which is the whole of a driver's interrupt duty.
    //
    // Which table entry the queue uses is the driver's to say, in a register
    // it holds; what that entry contains is the kernel's. That is the same
    // split as everything else here: the domain chooses among what it was
    // given, and cannot widen it.
    const BLOCK_BADGE: u64 = 1 << 1;
    let signalled = match crate::notify::create() {
        Ok(notification) => {
            // SAFETY: `trap` dispatches claimed vectors to `irq::on_interrupt`,
            // which acknowledges the local APIC. This device is the block
            // domain's and nothing else claims its entries.
            let claimed = unsafe {
                irq::claim_for(
                    irq::Source::MessageSignalled {
                        device: address,
                        entry: 0,
                    },
                    realm.as_u32(),
                    "blkd",
                    apic_id,
                    rsdp,
                    hhdm_base,
                )
            };
            match claimed {
                Ok(handler) if irq::bind(handler, notification, BLOCK_BADGE).is_ok() => {
                    let named = (irq::name(handler), crate::notify::name(notification));
                    if let (Ok(handler_cap), Ok(notify_cap)) = named
                        && domain::with(realm, |owner| {
                            owner.cspace.install_at(5, handler_cap).is_ok()
                                && owner.cspace.install_at(6, notify_cap).is_ok()
                        }) == Some(true)
                    {
                        true
                    } else {
                        irq::release(handler);
                        crate::notify::destroy(notification);
                        false
                    }
                }
                Ok(handler) => {
                    irq::release(handler);
                    crate::notify::destroy(notification);
                    false
                }
                Err(_) => {
                    crate::notify::destroy(notification);
                    false
                }
            }
        }
        Err(_) => false,
    };

    // Bus mastering, last. A device that is not a bus master cannot write to
    // memory at all: its rings stay empty and every request times out, which
    // reads as a broken device rather than as a missing bit. It cost an
    // afternoon to find, and `pci::enable`'s own comment says exactly that --
    // the kernel's driver had learned it and this one had not read it.
    //
    // Safe to grant before the driver has reset the device *because the device
    // translates*: a stray DMA with the configuration firmware left behind
    // reaches nothing it was not given, and shows up as a fault rather than as
    // somebody else's memory. Without a unit this would be handing a domain
    // the ability to point a device anywhere, which is why the window is
    // granted first and this follows it.
    // SAFETY: this device is the block domain's; nothing else drives it.
    unsafe { bhaskix_arch::pci::enable(address) };

    if contained {
        // The service can only answer once it can read, and it can only read
        // where a unit contains the device.
        BLOCK_ENDPOINT.store(
            u64::from(block_endpoint.as_u32()),
            core::sync::atomic::Ordering::Release,
        );
    }
    if identified {
        println!(
            "    block domain   configuration space granted read-only; the driver can say \
             what it is driving"
        );
    }
    if signalled {
        println!(
            "    block domain   interrupt delegated: the kernel programmed the vector, \
             the driver waits for it"
        );
    } else {
        println!(
            "    block domain   no dma window: nothing would contain the device, so the \
             driver gets registers and no way to make it read"
        );
    }

    let options = sched::SpawnOptions::new()
        .pinned()
        .in_domain(realm.as_u32());
    sched::spawn_on_with(
        cpu,
        "blkd",
        block_domain_entry,
        hhdm_base,
        hhdm_base,
        options,
    )
    .map_err(|_| "the block domain would not spawn")?;

    BLOCK_RINGS.store(rings.as_u64(), core::sync::atomic::Ordering::Release);
    Ok(())
}

/// The endpoint the block service answers on, once it exists.
static BLOCK_ENDPOINT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(u64::MAX);

/// The block service's endpoint, if there is a block service.
fn block_service_endpoint() -> Option<ipc::EndpointId> {
    let raw = BLOCK_ENDPOINT.load(core::sync::atomic::Ordering::Acquire);
    (raw != u64::MAX).then(|| ipc::EndpointId::from_u32(raw as u32))
}

/// The rings the block domain was given, so its report can be read back.
static BLOCK_RINGS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(u64::MAX);

/// Asks the block *service* for a sector, and checks what came back.
///
/// RFC 0015 step 1's criterion. The oracle is the image itself: the Makefile
/// writes `BHASKIX-DOMAIN-DISK-SECTOR-0` into sector zero of the disk the
/// domain drives, so the kernel knows what must come back without being able
/// to read that disk itself — it drives the other one.
///
/// The caller is a domain with a `Memory` object, because that is what the
/// protocol requires: sector data never crosses in message registers, and the
/// caller names memory it already holds.
/// Runs [`journal_on_disk`] and says what it found.
fn disk_journal_self_test(hhdm: u64) -> bool {
    use core::sync::atomic::Ordering;

    let raw = BLOCK_ENDPOINT.load(Ordering::Acquire);
    if raw == u64::MAX {
        // No block service, so no disk to put a filesystem on. Said out loud
        // rather than returned quietly: a test that cannot tell "there was
        // nothing to do" from "it did nothing" is a test that passes on a
        // machine where the whole subsystem is missing.
        println!(
            "    disk journal   no block service on this machine, so no device to put a \
             filesystem on"
        );
        return true;
    }

    let Ok(owner) = domain::create("disk-journal", domain::ResourceEnvelope::new()) else {
        println!("\x1b[91m    disk journal   FAILED to create a domain to write from\x1b[0m");
        return false;
    };
    let Ok(object) = shared::create(owner, bhaskix_mm::FRAME_SIZE) else {
        println!("\x1b[91m    disk journal   FAILED to create a memory object\x1b[0m");
        domain::destroy(owner);
        return false;
    };
    // Read *and* write: the service fills it on a read and drains it on a
    // write, and the kernel checks a different right for each.
    // Slot 0 holds it with everything; slot 1 holds the **same object** with
    // `WRITE` and no `READ`. Two capabilities to one thing, so that the
    // refusal below is about the right and not about the lookup -- a caller
    // refused because it holds nothing has learned nothing about rights. The
    // same shape the shell already uses for `map`.
    let installed = shared::name(object).ok().and_then(|memory| {
        let write_only = cap::with_arena(|arena| arena.derive(memory, cap::Rights::WRITE, 0).ok())?;
        domain::with(owner, |d| {
            d.cspace.install_at(0, memory).is_ok() && d.cspace.install_at(1, write_only).is_ok()
        })
    });
    let Some((frames, count)) = shared::frames_of(object) else {
        domain::destroy(owner);
        return false;
    };
    if installed != Some(true) || count == 0 {
        println!("\x1b[91m    disk journal   FAILED to give the writer its memory\x1b[0m");
        domain::destroy(owner);
        return false;
    }

    DISK_HHDM.store(hhdm, Ordering::Release);
    DISK_FRAME.store(frames[0], Ordering::Release);
    DISK_JOURNAL.store(u64::MAX, Ordering::Release);

    let options = sched::SpawnOptions::new().in_domain(owner.as_u32());
    if sched::spawn_on_with(
        0,
        "disk-journal",
        journal_on_disk,
        u64::from(raw as u32),
        hhdm,
        options,
    )
    .is_err()
    {
        println!("\x1b[91m    disk journal   FAILED to spawn a writer\x1b[0m");
        domain::destroy(owner);
        return false;
    }

    // Waited for the answer rather than for a duration. Every block is eight
    // round trips to another domain and there are a few hundred of them, so
    // this is the slowest self-test on the machine and a fixed wait would be a
    // guess that is wrong in one direction or the other.
    let mut verdict = u64::MAX;
    for _ in 0..400 {
        verdict = DISK_JOURNAL.load(Ordering::Acquire);
        if verdict != u64::MAX {
            break;
        }
        wait_millis(50);
    }
    domain::destroy(owner);

    // Checked against the sentinel *first*. `u64::MAX` has the success bit
    // set, so a version of this that only tested the bit reported success on a
    // machine where the writer never finished -- and it did, with a replay
    // count of 16777215.
    if verdict == u64::MAX {
        println!(
            "    disk journal   FAILED: the writer did not finish; every block is eight round \
             trips to another domain and there was not time for them"
        );
        return false;
    }
    if verdict & 0x1_0000_0000 == 0 {
        println!(
            "    disk journal   FAILED at stage {verdict}: a filesystem on the device did not \
             survive being interrupted after its commit"
        );
        return false;
    }
    let replayed = (verdict >> 8) & 0xff_ffff;
    let commit_at = verdict & 0xff;
    println!(
        "    disk journal   a filesystem on the virtio disk, through the block service: a create \
         takes {commit_at} device writes to commit, the machine was stopped one write later, and \
         mounting replayed {replayed} blocks -- `recovered` is on the disk and so is `on-a-disk`"
    );
    true
}

fn block_service_self_test(hhdm: u64) -> bool {
    use core::sync::atomic::Ordering;

    /// What the Makefile puts in sector zero of the domain's disk.
    const EXPECTED: &[u8] = b"BHASKIX-DOMAIN-DISK-SECTOR-0";
    const BADGE: u64 = 0x00b2_0000;

    let raw = BLOCK_ENDPOINT.load(Ordering::Acquire);
    if raw == u64::MAX {
        // No second device, so no block service. Not a failure.
        return true;
    }
    let endpoint = ipc::EndpointId::from_u32(raw as u32);

    let Ok(owner) = domain::create("block-reader", domain::ResourceEnvelope::new()) else {
        println!("\x1b[91m    block service  FAILED to create a domain to ask from\x1b[0m");
        return false;
    };
    // The object outlives the asker, because the asker does not outlive its
    // question. Its thread exits once the sector is read, that ends the domain
    // since 2026-08-11, and ending destroys the memory the domain owns -- so
    // the contents check below would be reading frames already handed back to
    // the allocator. It read *plausible* bytes when it did, which is the worst
    // shape of failure: 512 of them, and the wrong ones.
    let Ok(keeper) = domain::create("block-keeper", domain::ResourceEnvelope::new()) else {
        println!("\x1b[91m    block service  FAILED to create the owning domain\x1b[0m");
        domain::destroy(owner);
        return false;
    };
    let Ok(object) = shared::create(keeper, bhaskix_mm::FRAME_SIZE) else {
        println!("\x1b[91m    block service  FAILED to create a memory object\x1b[0m");
        domain::destroy(owner);
        domain::destroy(keeper);
        return false;
    };
    let installed = shared::name(object)
        .ok()
        .and_then(|memory| domain::with(owner, |d| d.cspace.install_at(0, memory).is_ok()));
    if installed != Some(true) {
        println!("\x1b[91m    block service  FAILED to give the caller its memory\x1b[0m");
        domain::destroy(owner);
        domain::destroy(keeper);
        return false;
    }

    BLOCK_CALLER.store(owner.as_u32(), Ordering::Release);
    BLOCK_READ.store(u64::MAX, Ordering::Release);
    let options = sched::SpawnOptions::new().in_domain(owner.as_u32());
    if sched::spawn_on_with(
        0,
        "block-ask",
        block_asks,
        u64::from(raw as u32),
        hhdm,
        options,
    )
    .is_err()
    {
        println!("\x1b[91m    block service  FAILED to spawn a caller\x1b[0m");
        domain::destroy(owner);
        domain::destroy(keeper);
        return false;
    }
    let _ = endpoint;
    let _ = BADGE;

    // Wait for the answer rather than for a duration.
    let mut landed = u64::MAX;
    for _ in 0..80 {
        landed = BLOCK_READ.load(Ordering::Acquire);
        if landed != u64::MAX {
            break;
        }
        wait_millis(50);
    }

    let refused = BLOCK_REFUSED.load(Ordering::Acquire) == 0;
    let matches = match shared::frames_of(object) {
        Some((frames, count)) if count > 0 && landed == 512 => {
            // SAFETY: a frame this object owns, through the direct map.
            let bytes =
                unsafe { core::slice::from_raw_parts((hhdm + frames[0]) as *const u8, 512) };
            bytes.starts_with(EXPECTED)
        }
        _ => false,
    };

    shared::revoke(object);
    domain::destroy(owner);
    domain::destroy(keeper);

    let ok = matches && refused;
    if ok {
        println!(
            "    block service  {landed} bytes of sector 0 through the service, and they are \
             the domain disk's own; a sector past the end is refused"
        );
    } else {
        println!(
            "    block service  FAILED: {landed} bytes, contents match {matches}, \
             past the end refused {refused}"
        );
    }
    ok
}

/// The domain the block self-test asks from, and what came back.
/// What the journal-on-a-disk test found, or `u64::MAX` while it is running.
///
/// Packed rather than a struct because it crosses from a spawned thread to the
/// boot report and a struct would need a lock on a path that has no reason to
/// take one.
static DISK_JOURNAL: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(u64::MAX);

/// A block device reached by asking the block service for one sector at a time.
///
/// The `Store` RFC 0015 step 6 introduced, finally over something that is not
/// memory. Every read and every write here is a **round trip to another
/// domain**, which is the cost the trait exists to make payable rather than
/// invisible. One per 4 KiB block: the service carries eight sectors in a
/// request, which is what `args[1]` always meant and had never done.
struct DiskStore {
    endpoint: ipc::EndpointId,
    /// The slot, in *this* domain's CSpace, holding the memory the service
    /// fills and drains. The service cannot choose it and the kernel re-checks
    /// it against what this domain actually holds.
    slot: u64,
    /// The frame behind that memory, so the bytes can be moved without a
    /// second copy through a buffer this thread does not have room for.
    frame: u64,
    hhdm: u64,
    sectors: u64,
    /// Writes still permitted before this pretends to be a machine that
    /// stopped. `u32::MAX` for a device that does not stop.
    budget: u32,
    /// Writes that went, and which of them reached the commit block.
    writes: u32,
}

impl DiskStore {
    /// The bytes of the shared page, as the kernel sees them.
    ///
    /// `&mut self`, because handing out a `&mut [u8]` from a `&self` is a
    /// shape that is unsound whether or not this particular use of it is —
    /// two callers could hold the same page mutably and nothing would say so.
    fn page(&mut self) -> &mut [u8] {
        // SAFETY: one frame of a `Memory` object this thread's domain holds,
        // through the direct map. Nothing else touches it while this store
        // exists: the object was made for this test and installed in one slot
        // of one domain.
        unsafe { core::slice::from_raw_parts_mut((self.hhdm + self.frame) as *mut u8, 4096) }
    }
}

impl bhaskix_fs::Store for DiskStore {
    fn blocks(&self) -> u32 {
        u32::try_from(self.sectors / 8).unwrap_or(0)
    }

    fn read(&mut self, block: u32, into: &mut [u8]) -> Result<(), bhaskix_fs::FsError> {
        if u64::from(block) >= self.sectors / 8 {
            return Err(bhaskix_fs::FsError::OutOfRange);
        }
        let reply = ipc::call(
            self.endpoint,
            0x00b2_0000,
            bhaskix_abi::block::READ,
            [u64::from(block) * 8, 8, self.slot, 0],
        )
        .map_err(|_| bhaskix_fs::FsError::OutOfRange)?;
        if reply.args[0] != 4096 {
            return Err(bhaskix_fs::FsError::OutOfRange);
        }
        into.get_mut(..4096)
            .ok_or(bhaskix_fs::FsError::OutOfRange)?
            .copy_from_slice(self.page());
        Ok(())
    }

    fn write(&mut self, block: u32, from: &[u8]) -> Result<(), bhaskix_fs::FsError> {
        if u64::from(block) >= self.sectors / 8 {
            return Err(bhaskix_fs::FsError::OutOfRange);
        }
        if self.writes >= self.budget {
            // The machine stopped. Nothing is sent, which is what "it did not
            // happen" means -- and the sectors already sent stay sent, which is
            // what makes the recovery below have something to do.
            return Err(bhaskix_fs::FsError::Interrupted);
        }
        self.page()
            .copy_from_slice(from.get(..4096).ok_or(bhaskix_fs::FsError::OutOfRange)?);
        let reply = ipc::call(
            self.endpoint,
            0x00b2_0000,
            bhaskix_abi::block::WRITE,
            [u64::from(block) * 8, 8, self.slot, 0],
        )
        .map_err(|_| bhaskix_fs::FsError::OutOfRange)?;
        if reply.args[0] != 4096 {
            return Err(bhaskix_fs::FsError::OutOfRange);
        }
        self.writes += 1;
        Ok(())
    }
}

static BLOCK_CALLER: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(u32::MAX);
static BLOCK_READ: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(u64::MAX);
/// What a read past the end of the device answered.
static BLOCK_REFUSED: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(u64::MAX);

/// Asks the block service for sector zero, from inside a domain that holds the
/// memory it will land in.
/// Pages for the cache the disk journal runs through.
static mut DISK_FRAMES: [u8; 8 * bhaskix_fs::BLOCK] = [0; 8 * bhaskix_fs::BLOCK];

/// A filesystem on the **device**, interrupted after its commit and recovered.
///
/// Every write below is a message to a driver in another domain, which puts a
/// sector on a virtio disk. Until this existed the journal had only ever been
/// exercised against an array in memory: correct, exhaustive, and silent about
/// the one thing a journal is for. RFC 0015 step 1 called for `block::WRITE`
/// and only `READ` was built, so nothing since had needed the other half.
///
/// The exhaustive interruption harness stays on the host, where stopping at
/// every write of every operation costs milliseconds. Here there is one
/// interruption and it is the decisive one: the machine stops one device write
/// **after** the commit, which is the only place recovery has work to do.
extern "C" fn journal_on_disk(endpoint: u64) -> ! {
    use bhaskix_fs::{Cache, Kind, Store, Volume};
    use core::sync::atomic::Ordering;

    let endpoint = ipc::EndpointId::from_u32(endpoint as u32);
    let hhdm = DISK_HHDM.load(Ordering::Acquire);
    let frame = DISK_FRAME.load(Ordering::Acquire);

    let sectors = match ipc::call(endpoint, 0x00b2_0000, bhaskix_abi::block::CAPACITY, [0; 4]) {
        Ok(reply) => reply.args[0],
        Err(_) => 0,
    };

    // What a write refuses, before anything is written for real.
    //
    // A sector past the end, which must be refused *here* rather than asked of
    // the hardware: a device is entitled to do anything with a sector that
    // does not exist, and on a write that includes doing it to somebody
    // else's. And the same write named through slot 1 -- the same memory, held
    // without `READ` -- which the kernel must refuse to take bytes out of,
    // because taking them is reading it.
    let past = ipc::call(
        endpoint,
        0x00b2_0000,
        bhaskix_abi::block::WRITE,
        [sectors, 8, 0, 0],
    )
    .map_or(u64::MAX, |reply| reply.args[0]);
    let unreadable = ipc::call(
        endpoint,
        0x00b2_0000,
        bhaskix_abi::block::WRITE,
        [0, 8, 1, 0],
    )
    .map_or(u64::MAX, |reply| reply.args[0]);
    if past != bhaskix_abi::block::REFUSED || unreadable != 0 {
        DISK_JOURNAL.store(13, Ordering::Release);
        sched::exit()
    }
    let store = |budget: u32| DiskStore {
        endpoint,
        slot: 0,
        frame,
        hhdm,
        sectors,
        budget,
        writes: 0,
    };

    // SAFETY: this thread is the only one that reaches these pages, and it is
    // spawned once.
    let (image, frames) = unsafe {
        (
            &mut *core::ptr::addr_of_mut!(JOURNAL_IMAGE),
            &mut *core::ptr::addr_of_mut!(DISK_FRAMES),
        )
    };

    // Formatted in memory and then *put on the disk block by block*, which is
    // what `mkfs` does from a developer's machine. Formatting through the
    // store would work equally well and would prove less: what is wanted here
    // is a device holding an image this kernel did not make up as it read it.
    // Thirty-two, not sixteen. Sixteen left three data blocks after the
    // superblock, the bitmap, the inode table and the journal's nine, and the
    // tree below needs five. It failed as `Full`, which is the allocator
    // working; the number was simply wrong.
    let blocks = 32u32;
    if bhaskix_fs::format(image, 128).is_err() || u64::from(blocks) > sectors / 8 {
        DISK_JOURNAL.store(0, Ordering::Release);
        sched::exit()
    }
    {
        let mut device = store(u32::MAX);
        for block in 0..blocks {
            let at = (block as usize) * bhaskix_fs::BLOCK;
            if device
                .write(block, &image[at..at + bhaskix_fs::BLOCK])
                .is_err()
            {
                DISK_JOURNAL.store(1, Ordering::Release);
                sched::exit()
            }
        }
    }

    // A file, on the disk, through the journal. Nothing in memory is consulted
    // from here on: the cache is empty and every page it wants comes off the
    // device.
    let root = {
        let Ok(cache) = Cache::new(frames, store(u32::MAX)) else {
            DISK_JOURNAL.store(2, Ordering::Release);
            sched::exit()
        };
        let Ok((mut volume, _)) = Volume::mount(cache) else {
            DISK_JOURNAL.store(3, Ordering::Release);
            sched::exit()
        };
        let root = volume.superblock().root;
        let Ok(index) = volume.create(root, b"on-a-disk", Kind::File) else {
            DISK_JOURNAL.store(4, Ordering::Release);
            sched::exit()
        };
        // Contents, so that the filesystem service started afterwards has
        // something to find that only this filesystem holds. An empty file
        // would prove the name was there and nothing about the bytes.
        if volume
            .write(index, 0, b"written through a service\n")
            .is_err()
        {
            DISK_JOURNAL.store(14, Ordering::Release);
            sched::exit()
        }

        // And the tree the shell's own gates describe: `greeting` in the root,
        // `inner` inside `sub`, with the sizes those gates assert. RFC 0016
        // step 4 will have the *service* answer for this tree, and the claims
        // those gates make have to survive that move **unchanged** -- a test
        // rewritten to match a refactor has stopped guarding what it names.
        let made = (|| {
            let greeting = volume.create(root, b"greeting", Kind::File).ok()?;
            volume
                .write(greeting, 0, b"a file in a filesystem this kernel defined\n")
                .ok()?;
            let sub = volume.create(root, b"sub", Kind::Directory).ok()?;
            let inner = volume.create(sub, b"inner", Kind::File).ok()?;
            volume
                .write(inner, 0, b"only reachable through the subdirectory\n")
                .ok()
        })();
        if made.is_none() {
            DISK_JOURNAL.store(15, Ordering::Release);
            sched::exit()
        }
        root
    };

    // How many device writes a create takes, so the interruption lands one
    // *after* the commit rather than at a number somebody guessed.
    let commit_at = {
        let Ok(cache) = Cache::new(frames, store(u32::MAX)) else {
            DISK_JOURNAL.store(5, Ordering::Release);
            sched::exit()
        };
        let Ok((mut volume, _)) = Volume::mount(cache) else {
            DISK_JOURNAL.store(6, Ordering::Release);
            sched::exit()
        };
        let _ = volume.create(root, b"counted", Kind::File);
        let writes = volume.cache().store().writes;
        let _ = volume.remove(root, b"counted");
        // A transaction is symmetric: payload, commit, homes, cleared. The
        // commit is the middle write.
        writes / 2
    };

    // The same operation, on a device that stops one write after its commit.
    let interrupted = {
        let Ok(cache) = Cache::new(frames, store(commit_at + 1)) else {
            DISK_JOURNAL.store(7, Ordering::Release);
            sched::exit()
        };
        let Ok((mut volume, _)) = Volume::mount(cache) else {
            DISK_JOURNAL.store(8, Ordering::Release);
            sched::exit()
        };
        volume.create(root, b"recovered", Kind::File)
    };
    if interrupted != Err(bhaskix_fs::FsError::Interrupted) {
        DISK_JOURNAL.store(9, Ordering::Release);
        sched::exit()
    }

    // A fresh cache, so nothing that was only ever in memory can answer. What
    // this reads is what the disk holds.
    let (replayed, found, kept) = {
        let Ok(cache) = Cache::new(frames, store(u32::MAX)) else {
            DISK_JOURNAL.store(10, Ordering::Release);
            sched::exit()
        };
        let Ok((mut volume, replayed)) = Volume::mount(cache) else {
            DISK_JOURNAL.store(11, Ordering::Release);
            sched::exit()
        };
        let found = volume.lookup(root, b"recovered").is_ok();
        let kept = volume.lookup(root, b"on-a-disk").is_ok();
        (replayed, found, kept)
    };

    let ok = found && kept && replayed > 0;
    DISK_JOURNAL.store(
        if ok {
            0x1_0000_0000 | (u64::from(replayed) << 8) | u64::from(commit_at)
        } else {
            12
        },
        Ordering::Release,
    );
    sched::exit()
}

/// The filesystem service's endpoint, once it is answering.
static FS_ENDPOINT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(u64::MAX);
/// The badge that names `sub` to that service.
static FS_DIRECTORY: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// The badge that names a directory which is gone.
static FS_STALE: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Where the direct map is, for the thread above.
static DISK_HHDM: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// The frame behind the memory that thread shares with the block service.
static DISK_FRAME: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

extern "C" fn block_asks(endpoint: u64) -> ! {
    use core::sync::atomic::Ordering;

    const BADGE: u64 = 0x00b2_0000;

    let endpoint = ipc::EndpointId::from_u32(endpoint as u32);
    // Slot 0 of *this* domain's CSpace, which is where the memory was
    // installed. The service cannot choose it and the kernel re-checks it.
    let landed = match ipc::call(endpoint, BADGE, bhaskix_abi::block::READ, [0, 1, 0, 0]) {
        Ok(reply) => reply.args[0],
        Err(_) => 0,
    };

    // And a sector past the end of the device, which must be refused *here*
    // rather than asked of the hardware: a device is entitled to do anything
    // with a sector that does not exist, including answer.
    let past = match ipc::call(
        endpoint,
        BADGE,
        bhaskix_abi::block::READ,
        [1 << 40, 1, 0, 0],
    ) {
        Ok(reply) => reply.args[0],
        Err(_) => u64::MAX,
    };
    BLOCK_REFUSED.store(past, Ordering::Release);
    BLOCK_READ.store(landed, Ordering::Release);
    sched::exit()
}

/// Whether the driver has left its report yet.
///
/// The marker only, so that waiting for it costs nothing and cannot be
/// confused with reading it: a page of zeroes has no marker, and a driver that
/// never ran leaves the page as it found it.
fn block_domain_reported(hhdm: u64) -> bool {
    use core::sync::atomic::Ordering;

    let raw = BLOCK_RINGS.load(Ordering::Acquire);
    if raw == u64::MAX {
        return true;
    }
    let Some((frames, count)) = shared::frames_of(shared::MemoryId::from_u64(raw)) else {
        return true;
    };
    if count < 4 {
        return true;
    }
    // SAFETY: a frame this object owns, through the direct map.
    let marker = unsafe { core::ptr::read_volatile((hhdm + frames[3]) as *const u64) };
    marker == 0x424c_4b44_5250_5431
}

/// Reads what the driver in a domain wrote, and says so.
///
/// Through the memory the kernel granted it, because the driver holds no
/// console capability: a driver has no business printing, and giving it one to
/// make a test easier would have made the test prove less.
///
/// The marker is checked first. Without it a page of zeroes would read as a
/// report of all-zeroes, which is exactly the answer a driver that never ran
/// would appear to give.
fn report_block_domain(hhdm: u64) -> bool {
    use core::sync::atomic::Ordering;

    const MARKER: u64 = 0x424c_4b44_5250_5431;

    let raw = BLOCK_RINGS.load(Ordering::Acquire);
    if raw == u64::MAX {
        // Nothing was delegated: one device on the bus, which is not a
        // failure.
        return true;
    }
    let rings = shared::MemoryId::from_u64(raw);

    // The second page, through the direct map. The driver has it mapped as
    // writable memory in its own space; the kernel reaches the same frames the
    // way it reaches any object's.
    let Some((frames, count)) = shared::frames_of(rings) else {
        println!("\x1b[91m    block domain   FAILED: the rings are gone\x1b[0m");
        return false;
    };
    if count < 4 {
        println!(
            "\x1b[91m    block domain   FAILED: the rings are too small to hold a report\x1b[0m"
        );
        return false;
    }

    let mut words = [0u64; 13];
    // SAFETY: a frame this object owns, through the direct map, read as the
    // eight little-endian words the driver wrote there.
    // The last page. The first three are the descriptor table, the rings and
    // the request the *device* reads and writes -- a report living in any of
    // them would be a report the device could overwrite.
    // Half a page in, since the data area grew to four kilobytes: the report
    // moved out of its way rather than the transfer being kept small enough to
    // leave it where it was.
    let raw = unsafe { core::slice::from_raw_parts((hhdm + frames[3] + 0x800) as *const u8, 104) };
    for (index, word) in words.iter_mut().enumerate() {
        let mut buffer = [0u8; 8];
        buffer.copy_from_slice(&raw[index * 8..index * 8 + 8]);
        *word = u64::from_le_bytes(buffer);
    }
    if words[0] != MARKER {
        println!("\x1b[91m    block domain   FAILED: the driver left no report\x1b[0m");
        return false;
    }

    // What the unit saw, if anything. A device refused a page and a device
    // that never asked look identical from here, and this is the only thing
    // that tells them apart.
    if let Some(fault) = iommu::fault(hhdm) {
        let (bus, slot, function) = fault.device;
        println!(
            "    block domain   iommu FAULT {bus:02x}:{slot:02x}.{function} {} {:#x}, \
             reason {:#04x}",
            if fault.read { "read" } else { "write" },
            fault.address,
            fault.reason
        );
    }

    // What is asserted is what the driver *did*, and what only this device
    // could have told it.
    //
    // The status it found on arrival is reported and not asserted: the first
    // version expected zero, on the reasoning that nobody had driven this one,
    // and found 11 -- acknowledge, driver, features-ok. The firmware probes
    // disks before the kernel exists, so "untouched" was never true of a
    // device on a real bus. What it is evidence of is weaker than the capacity
    // anyway: this disk is one sector and the kernel's is 180, so a driver
    // handed the wrong device would say so in a number nothing else produces.
    let [
        _,
        found,
        drove_to,
        rings_at_device,
        queue_size,
        sectors,
        first_bytes,
        read_ok,
        used_index,
        request_status,
        by_interrupt,
        identified,
        hand_refusals,
    ] = words;

    // With a window, the driver is expected to have *read the disk*: status
    // 15 (acknowledge, driver, features-ok, driver-ok) and eight bytes off
    // sector zero. Without one it gets as far as the handshake and stops,
    // because nothing would contain a device it aimed at memory.
    let contained = iommu::present();
    // What `HAND` refused the driver before it was answering anybody. One
    // rule, checked on its own: the *other* refusal -- passing on a capability
    // without `GRANT` -- has to be asked from inside a request or it is
    // refused for having no caller instead, and the two would be
    // indistinguishable. The shell asks that one.
    // Exactly `WrongObject`, and not merely "something refused it". A version
    // of this asked only that the status was non-zero, and passed with the
    // rule deleted: the driver had declared nothing, so it was refused for
    // *that* instead. The driver now declares first, so this number is the
    // only one it can be.
    let not_answering = hand_refusals as u32;
    let ok = not_answering == syscall::Status::WrongObject as u32
        && if contained {
            drove_to == 15 && read_ok == 1 && by_interrupt == 1 && queue_size > 0 && sectors > 0
        } else {
            drove_to == 3 && queue_size > 0 && sectors > 0
        };
    if ok {
        let text = first_bytes.to_le_bytes();
        let text = core::str::from_utf8(&text).unwrap_or("????????");
        println!(
            "    block domain   ring 3 driver: found status {found}, drove it to {drove_to}, \
             rings at {rings_at_device:#x} for the device, queue of {queue_size}, \
             {sectors} sectors, sector 0 begins {text:?}, woken by the device, \
             and says it is {:04x}:{:04x} from its own configuration space; \
             handing a capability while answering nobody was refused it \
             (status {not_answering})",
            identified >> 16,
            identified & 0xffff
        );
    } else {
        println!(
            "    block domain   FAILED: found {found}, drove it to {drove_to}, \
             rings at {rings_at_device:#x}, queue size {queue_size}, sectors {sectors}, \
             read {read_ok}, by interrupt {by_interrupt}, used index {used_index}, \
             request status {request_status:#x}, hand refused {not_answering}"
        );
    }
    ok
}

/// Loads `bin/blkd` and becomes the block driver, in ring 3.
extern "C" fn block_domain_entry(hhdm_base: u64) -> ! {
    use bhaskix_boot::VirtAddr;
    use bhaskix_mm::{Protection, VirtRange};
    use vm::AddressSpace;

    let stop = |why: &str| -> ! {
        println!("\x1b[91m    block domain   FAILED: {why}\x1b[0m");
        sched::exit()
    };

    let Ok(file) = vfs::open(BLKD_PROGRAM) else {
        stop("bin/blkd is not in the filesystem")
    };
    let Ok(image) = elf::parse(file.bytes()) else {
        stop("bin/blkd is not an ELF this kernel will load")
    };
    let Ok(mut space) = AddressSpace::new(hhdm_base) else {
        stop("the address space would not be created")
    };
    let Some(stack) = VirtRange::from_pages(VirtAddr(BLKD_STACK), BLKD_STACK_PAGES) else {
        stop("the stack range is not a range")
    };
    if space.map_anonymous(stack, Protection::ReadWrite).is_err() {
        stop("the stack would not map")
    }
    let Ok(entry) = elf::load_into(&image, file.bytes(), &mut space, hhdm_base) else {
        stop("bin/blkd would not load")
    };

    // SAFETY: the higher half is copied from the running page table, so
    // everything currently executing stays addressable.
    unsafe { vm::install(space) };

    let rsp = BLKD_STACK + BLKD_STACK_PAGES * bhaskix_mm::FRAME_SIZE;
    // SAFETY: `entry` is inside a user-executable segment of the space just
    // installed, `rsp` is one past user-writable memory in the same space, and
    // `RSP0` was set before this thread was spawned.
    // SAFETY: `entry` is inside a user-executable segment of the space
    // just installed, and `rsp` is one past user-writable memory in it.
    unsafe { enter_user("block domain", entry, rsp, [0, 0]) }
}

/// Loads and enters `bin/fsd`.
extern "C" fn fs_domain_entry(hhdm_base: u64) -> ! {
    use bhaskix_boot::VirtAddr;
    use bhaskix_mm::{Protection, VirtRange};
    use vm::AddressSpace;

    let stop = |why: &str| -> ! {
        println!("\x1b[91m    fs domain      FAILED: {why}\x1b[0m");
        sched::exit()
    };

    let Ok(file) = vfs::open(FSD_PROGRAM) else {
        stop("bin/fsd is not in the filesystem")
    };
    let Ok(image) = elf::parse(file.bytes()) else {
        stop("bin/fsd is not an ELF this kernel will load")
    };
    let Ok(mut space) = AddressSpace::new(hhdm_base) else {
        stop("the address space would not be created")
    };
    let Some(stack) = VirtRange::from_pages(VirtAddr(FSD_STACK), FSD_STACK_PAGES) else {
        stop("the stack range is not a range")
    };
    if space.map_anonymous(stack, Protection::ReadWrite).is_err() {
        stop("the stack would not map")
    }
    let Ok(entry) = elf::load_into(&image, file.bytes(), &mut space, hhdm_base) else {
        stop("bin/fsd would not load")
    };

    // SAFETY: the higher half is copied from the running page table, so
    // everything currently executing stays addressable.
    unsafe { vm::install(space) };

    let rsp = FSD_STACK + FSD_STACK_PAGES * bhaskix_mm::FRAME_SIZE;
    // SAFETY: `entry` is inside a user-executable segment of the space just
    // installed, `rsp` is one past user-writable memory in the same space, and
    // `RSP0` was set before this thread was spawned.
    // SAFETY: `entry` is inside a user-executable segment of the space
    // just installed, and `rsp` is one past user-writable memory in it.
    unsafe { enter_user("fs domain", entry, rsp, [0, 0]) }
}

/// Starts the filesystem in a domain, and checks what it read off the disk.
///
/// RFC 0016 step 3. The program it loads contains **no filesystem code**: it
/// links `bhaskix-fs`, the same crate the kernel links, and supplies a `Store`
/// made of system calls. That the crate needed nothing else is the whole
/// return on RFC 0015 step 6 — a filesystem written against a slice could not
/// have been placed here at all.
///
/// What it is given is two capabilities: the block service's endpoint, and one
/// memory object it maps. It has no registers, no interrupt, no DMA window and
/// no way to name a disk. What it reads it reads by asking.
fn start_fs_domain(hhdm: u64) -> bool {
    use core::sync::atomic::Ordering;

    /// What `bin/fsd` writes when it has finished, after everything else.
    const MARKER: u64 = 0x4653_4452_5054_3031;
    /// What the kernel put in the file, and what the service must find.
    const EXPECTED: &[u8] = b"written through a service\n";

    let raw = BLOCK_ENDPOINT.load(Ordering::Acquire);
    if raw == u64::MAX {
        println!("    fs domain      no block service on this machine, so no disk to mount");
        return true;
    }
    let endpoint = ipc::EndpointId::from_u32(raw as u32);

    let Ok(realm) = domain::create("fs", domain::ResourceEnvelope::new()) else {
        println!("\x1b[91m    fs domain      FAILED: the domain would not be created\x1b[0m");
        return false;
    };

    // Two pages: one the block service fills and drains, and one the service
    // leaves its findings in.
    //
    // Its **page cache is eight separate one-page objects**, below, and that is
    // not tidiness. A cache in one object can only be lent whole, and lending
    // it whole hands a reader every other block in it -- other files' data, and
    // every piece of metadata the service has touched. A frame is the unit that
    // can be lent, so a frame has to be the unit that can be named.
    let Ok(memory) = shared::create(realm, 2 * bhaskix_mm::FRAME_SIZE) else {
        println!("\x1b[91m    fs domain      FAILED: its memory would not be created\x1b[0m");
        domain::destroy(realm);
        return false;
    };
    let Some((frames, count)) = shared::frames_of(memory) else {
        domain::destroy(realm);
        return false;
    };
    // Its own endpoint, at slot 2, installed **unbadged**. That is the whole of
    // its authority to name directories: only a capability with no badge may
    // set one, so this service can mint a handle for any directory on its disk
    // and nothing a client holds can mint one at all. RFC 0016 step 4.
    let Ok(serving) = ipc::create() else {
        println!("\x1b[91m    fs domain      FAILED: no endpoint for it to answer on\x1b[0m");
        domain::destroy(realm);
        return false;
    };
    let installed = shared::name(memory).ok().and_then(|named| {
        let (block, own) = cap::with_arena(|arena| {
            let root = arena
                .insert_root(
                    cap::ObjectRef::new(cap::ObjectKind::Endpoint, u64::from(endpoint.as_u32())),
                    cap::Rights::ALL,
                    0,
                )
                .ok()?;
            let block = arena.derive(root, cap::Rights::ALL, BADGE_FS_BLOCK).ok()?;
            let own = arena
                .insert_root(
                    cap::ObjectRef::new(cap::ObjectKind::Endpoint, u64::from(serving.as_u32())),
                    cap::Rights::ALL,
                    0,
                )
                .ok()?;
            Some((block, own))
        })?;
        domain::with(realm, |owner| {
            owner.cspace.install_at(0, block).is_ok()
                && owner.cspace.install_at(1, named).is_ok()
                && owner.cspace.install_at(2, own).is_ok()
        })
    });
    if installed != Some(true) || count < 2 {
        println!("\x1b[91m    fs domain      FAILED: its capabilities would not install\x1b[0m");
        domain::destroy(realm);
        return false;
    }

    // The page cache, one object per frame, at slots 3 and up. `shared::name`
    // gives them with every right, which is what lets the service both use
    // them as memory and hand weaker copies away: holding a thing and being
    // allowed to give it away are different permissions.
    for frame in 0..8usize {
        let Ok(page) = shared::create(realm, bhaskix_mm::FRAME_SIZE) else {
            println!("\x1b[91m    fs domain      FAILED: a cache page would not be created\x1b[0m");
            domain::destroy(realm);
            return false;
        };
        let landed = shared::name(page).ok().and_then(|named| {
            domain::with(realm, |owner| {
                owner.cspace.install_at(3 + frame, named).is_ok()
            })
        });
        if landed != Some(true) {
            println!("\x1b[91m    fs domain      FAILED: a cache page would not install\x1b[0m");
            domain::destroy(realm);
            return false;
        }
    }

    let options = sched::SpawnOptions::new()
        .pinned()
        .in_domain(realm.as_u32());
    if sched::spawn_on_with(3, "fsd", fs_domain_entry, hhdm, hhdm, options).is_err() {
        println!("\x1b[91m    fs domain      FAILED: it would not spawn\x1b[0m");
        domain::destroy(realm);
        return false;
    }

    // The report page is the object's last frame, read through the direct map.
    let mut words = [0u64; 9];
    for _ in 0..200 {
        // SAFETY: a frame this object owns, through the direct map, read as
        // the six little-endian words the service writes there.
        let raw = unsafe { core::slice::from_raw_parts((hhdm + frames[1]) as *const u8, 72) };
        for (index, word) in words.iter_mut().enumerate() {
            let mut buffer = [0u8; 8];
            buffer.copy_from_slice(&raw[index * 8..index * 8 + 8]);
            *word = u64::from_le_bytes(buffer);
        }
        // The marker, which the service writes last and after a fence. The
        // stage word is written as it goes and is *not* covered by that
        // fence -- it is what says how far a run that never got here reached.
        if words[0] == MARKER {
            break;
        }
        wait_millis(50);
    }

    // The domain is **not** destroyed. It was, and destroying it tore down a
    // ring 3 thread that had written its answer and had not yet reached its
    // `exit` -- after which the shell never started. A service that has
    // finished saying something is not a service that has finished, and this
    // one is going to be asked things in the next step anyway.
    let [
        _,
        blocks,
        entries,
        read,
        matched,
        sectors,
        stage,
        directory,
        stale,
    ] = words;
    // What the service says names `sub`. The kernel is the only thing that can
    // mint a capability, so the service supplies the badge and the kernel
    // stamps it. RFC 0016 step 4 is not finished; this is enough of it to
    // reproduce the defect that stopped it.
    FS_ENDPOINT.store(u64::from(serving.as_u32()), Ordering::Release);
    FS_DIRECTORY.store(directory, Ordering::Release);
    FS_STALE.store(stale, Ordering::Release);
    let _ = (directory, stale);
    let ok = matched == 1 && read == EXPECTED.len() as u64 && blocks > 0 && entries > 0;
    if ok {
        println!(
            "    fs domain      bin/fsd mounted the disk through the block service: \
             {sectors} sectors, {blocks} blocks, {entries} entries, and `on-a-disk` reads \
             {read} bytes that the kernel wrote through its own copy of the same crate"
        );
    } else {
        println!(
            "    fs domain      FAILED: {sectors} sectors, {blocks} blocks, {entries} entries, \
             {read} bytes read, contents match {matched}, reached stage {stage}"
        );
    }
    ok
}

/// Creates the domain the console service runs in, and starts it.
///
/// Two capabilities, and they are not the same kind of thing: the endpoint is
/// what callers reach it through, and the `Console` is the whole of what it
/// may do to the machine. A console service in the nucleus can do anything the
/// kernel can; this one can put a character and take a byte.
pub fn start_console_domain(cpu: u32, hhdm_base: u64) -> Result<(), &'static str> {
    let endpoint = service::console_endpoint().ok_or("there is no console endpoint")?;

    let realm = domain::create("console", domain::ResourceEnvelope::new())
        .map_err(|_| "the console domain would not be created")?;

    let installed = cap::with_arena(|arena| {
        let endpoint_cap = arena
            .insert_root(
                cap::ObjectRef::new(cap::ObjectKind::Endpoint, u64::from(endpoint.as_u32())),
                cap::Rights::ALL,
                0,
            )
            .ok()?;
        let console_cap = arena
            .insert_root(
                cap::ObjectRef::new(cap::ObjectKind::Console, CONSOLE_OBJECT),
                cap::Rights::ALL,
                0,
            )
            .ok()?;
        Some((endpoint_cap, console_cap))
    })
    .ok_or("the console domain's capabilities would not be created")?;

    if domain::with(realm, |owner| {
        owner.cspace.install_at(0, installed.0).is_ok()
            && owner.cspace.install_at(1, installed.1).is_ok()
    }) != Some(true)
    {
        return Err("the console domain's capabilities would not be installed");
    }

    let options = sched::SpawnOptions::new()
        .pinned()
        .in_domain(realm.as_u32());
    sched::spawn_on_with(
        cpu,
        "consoled",
        console_domain_entry,
        hhdm_base,
        hhdm_base,
        options,
    )
    .map_err(|_| "the console domain would not spawn")?;
    Ok(())
}

/// Loads `bin/consoled` and becomes the console service, in ring 3.
/// Starts the supervisor: a ring 3 program that restarts what it started.
///
/// RFC 0017's second unresolved question asked what restarts a service that
/// died, and answered that restart policy is **policy** — writable entirely in
/// userspace, and the RFC's own test of whether its six steps were the right
/// six. `bin/sup` is that test. Nothing in the kernel was added for it: every
/// call it makes existed already.
///
/// Five capabilities, and the interesting one is the third. The program it
/// starts arrives as **memory this function staged**, not as a filename — the
/// kernel has no business opening a file on a program's behalf, so a supervisor
/// that named one would be naming authority it does not hold. `START` takes a
/// capability for the same reason.
///
/// # Errors
///
/// A string naming what would not be built. Every one is survivable: the
/// machine boots to a shell without a supervisor.
fn start_supervisor(cpu: u32, hhdm_base: u64) -> Result<(), &'static str> {
    let console = service::console_endpoint().ok_or("the console service has no endpoint")?;

    // One child at a time, which is what makes the reap in the loop
    // load-bearing rather than tidy: without it the second start is refused for
    // the budget, and that is the negative test for this program.
    let realm = domain::create("sup", domain::ResourceEnvelope::new().max_child_domains(1))
        .map_err(|_| "no room for the supervisor's domain")?;

    // Slot 0: the console, badged as itself.
    let console_cap = cap::with_arena(|arena| {
        let root = arena
            .insert_root(
                cap::ObjectRef::new(cap::ObjectKind::Endpoint, u64::from(console.as_u32())),
                cap::Rights::ALL,
                0,
            )
            .ok()?;
        arena.derive(root, cap::Rights::ALL, BADGE_SUPERVISOR).ok()
    })
    .ok_or("the supervisor's console capability would not be created")?;

    // Slot 1: authority to create a domain. Necessary and not sufficient --
    // the envelope above is the other half.
    let control = cap::with_arena(|arena| {
        let root = arena
            .insert_root(
                cap::ObjectRef::new(cap::ObjectKind::DomainControl, 0),
                cap::Rights::ALL,
                0,
            )
            .ok()?;
        arena.derive(root, cap::Rights::ALL, 0).ok()
    })
    .ok_or("the supervisor's DomainControl would not be derive")?;

    // Slot 2: the program to start, staged into memory. The same shape the ring
    // 3 test uses to hand the probe its own image.
    let staged = vfs::open(USER_PROGRAM).ok().and_then(|file| {
        let bytes = file.bytes();
        let pages = bytes.len().div_ceil(bhaskix_mm::FRAME_SIZE as usize).max(1);
        let object = shared::create(realm, pages as u64 * bhaskix_mm::FRAME_SIZE).ok()?;
        let mut written = 0;
        shared::fill_from(object, 0, bytes.len(), &mut |page: &mut [u8]| {
            let take = page.len().min(bytes.len() - written);
            page[..take].copy_from_slice(&bytes[written..written + take]);
            written += take;
            take
        })?;
        SUP_IMAGE_BYTES.store(bytes.len() as u64, core::sync::atomic::Ordering::Release);
        shared::name(object).ok()
    });
    let staged = staged.ok_or("the supervisor's program image would not be staged")?;

    // Slot 3: a notification it owns, which is what `BIND` names. A supervisor
    // with none could not be told about anything.
    let notification = notify::create().map_err(|_| "no notification for the supervisor")?;
    let signal = cap::with_arena(|arena| {
        let root = arena
            .insert_root(
                cap::ObjectRef::new(
                    cap::ObjectKind::Notification,
                    u64::from(notification.index()) | (u64::from(notification.generation()) << 32),
                ),
                cap::Rights::ALL,
                0,
            )
            .ok()?;
        arena.derive(root, cap::Rights::ALL, 0).ok()
    })
    .ok_or("the supervisor's notification would not be created")?;

    // Slot 4 is left empty: it is where each child's `Domain` capability lands
    // and is given back from.
    if domain::with(realm, |owner| {
        owner.cspace.install_at(0, console_cap).is_ok()
            && owner.cspace.install_at(1, control).is_ok()
            && owner.cspace.install_at(2, staged).is_ok()
            && owner.cspace.install_at(3, signal).is_ok()
    }) != Some(true)
    {
        return Err("the supervisor's capabilities would not install");
    }

    let options = sched::SpawnOptions::new()
        .pinned()
        .in_domain(realm.as_u32());
    sched::spawn_on_with(cpu, "sup", supervisor_entry, hhdm_base, hhdm_base, options)
        .map_err(|_| "the supervisor's thread would not spawn")?;

    // Wait for it, rather than letting it run alongside everything else.
    //
    // It is a ring 3 program printing to the same console the boot is using,
    // and it creates and destroys domains while other self-tests are counting
    // them. Left concurrent it tore its own lines in half and turned two
    // unrelated checks red -- which is the coupling the comment beside the
    // shell's start describes, met again by a second program.
    //
    // Bounded, so a supervisor that wedges reports rather than hanging the
    // boot; and its domain ending is the signal, which is the rule adopted
    // earlier today.
    let finished = wait_until(|| !matches!(domain::state_of(realm), Ok(None)), 4_000);
    if !finished {
        println!("    supervisor     did not finish within four seconds");
    }
    Ok(())
}

/// Loads `bin/sup` and enters ring 3, the same way every other domain does.
extern "C" fn supervisor_entry(hhdm_base: u64) -> ! {
    use bhaskix_boot::VirtAddr;
    use bhaskix_mm::{Protection, VirtRange};
    use vm::AddressSpace;

    let stop = |why: &str| -> ! {
        println!("\x1b[91m    supervisor     FAILED: {why}\x1b[0m");
        sched::exit()
    };

    let Ok(file) = vfs::open(SUP_PROGRAM) else {
        stop("bin/sup is not in the filesystem")
    };
    let Ok(image) = elf::parse(file.bytes()) else {
        stop("bin/sup is not an ELF this kernel will load")
    };
    let Ok(mut space) = AddressSpace::new(hhdm_base) else {
        stop("the address space would not be created")
    };
    let Some(stack) = VirtRange::from_pages(VirtAddr(SUP_STACK), SUP_STACK_PAGES) else {
        stop("the stack range is not a range")
    };
    if space.map_anonymous(stack, Protection::ReadWrite).is_err() {
        stop("the stack would not map")
    }
    let Ok(entry) = elf::load_into(&image, file.bytes(), &mut space, hhdm_base) else {
        stop("bin/sup would not load")
    };

    // SAFETY: the higher half is copied from the running page table, so
    // everything currently executing stays addressable.
    unsafe { vm::install(space) };

    let rsp = SUP_STACK + SUP_STACK_PAGES * bhaskix_mm::FRAME_SIZE;
    // How many bytes the image is, passed in the entry word. `START` refuses a
    // length of zero and the program cannot measure memory it merely holds a
    // capability to, so this is the one fact that cannot reach it through a
    // CSpace.
    let bytes = SUP_IMAGE_BYTES.load(core::sync::atomic::Ordering::Acquire);
    // SAFETY: `entry` is inside a user-executable segment of the space just
    // installed -- `elf::parse` refuses an entry point that is not -- `rsp` is
    // one past user-writable memory in the same space, and `RSP0` was set
    // before this thread was spawned.
    unsafe { enter_user("sup", entry, rsp, [bytes, 0]) }
}

extern "C" fn console_domain_entry(hhdm_base: u64) -> ! {
    use bhaskix_boot::VirtAddr;
    use bhaskix_mm::{Protection, VirtRange};
    use vm::AddressSpace;

    let stop = |why: &str| -> ! {
        println!("\x1b[91m    console domain FAILED: {why}\x1b[0m");
        sched::exit()
    };

    let Ok(file) = vfs::open(CONSOLED_PROGRAM) else {
        stop("bin/consoled is not in the filesystem")
    };
    let Ok(image) = elf::parse(file.bytes()) else {
        stop("bin/consoled is not an ELF this kernel will load")
    };

    let Ok(mut space) = AddressSpace::new(hhdm_base) else {
        stop("the address space would not be created")
    };
    let Some(stack) = VirtRange::from_pages(VirtAddr(CONSOLED_STACK), CONSOLED_STACK_PAGES) else {
        stop("the stack range is not a range")
    };
    if space.map_anonymous(stack, Protection::ReadWrite).is_err() {
        stop("the stack would not map")
    }
    let Ok(entry) = elf::load_into(&image, file.bytes(), &mut space, hhdm_base) else {
        stop("bin/consoled would not load")
    };

    println!(
        "    console domain bin/consoled loaded, holding a console capability and nothing else"
    );

    // SAFETY: the higher half is copied from the running page table, so
    // everything currently executing stays addressable.
    unsafe { vm::install(space) };

    let rsp = CONSOLED_STACK + CONSOLED_STACK_PAGES * bhaskix_mm::FRAME_SIZE;
    // SAFETY: `entry` is inside a user-executable segment of the space just
    // installed, `rsp` is one past user-writable memory in the same space, and
    // `RSP0` was set before this thread was spawned.
    // SAFETY: `entry` is inside a user-executable segment of the space
    // just installed, and `rsp` is one past user-writable memory in it.
    unsafe { enter_user("console domain", entry, rsp, [0, 0]) }
}

/// Creates the domain the filesystem service runs in, and starts it.
///
/// The domain and its one capability are made *here* rather than in the thread
/// because a thread joins a domain when it is spawned: a program that could
/// join one afterwards could choose which.
pub fn start_vfs_domain(cpu: u32, hhdm_base: u64) -> Result<(), &'static str> {
    let endpoint = service::filesystem_endpoint().ok_or("there is no filesystem endpoint")?;

    let realm = domain::create("vfs", domain::ResourceEnvelope::new())
        .map_err(|_| "the filesystem domain would not be created")?;

    // One capability: the endpoint it answers on. Unbadged, because a badge is
    // what a *client* is stamped with, and this is the other end of the wire.
    let granted = cap::with_arena(|arena| {
        arena
            .insert_root(
                cap::ObjectRef::new(cap::ObjectKind::Endpoint, u64::from(endpoint.as_u32())),
                cap::Rights::ALL,
                0,
            )
            .ok()
    })
    .ok_or("the endpoint capability would not be created")?;
    if domain::with(realm, |owner| owner.cspace.install_at(0, granted).is_ok()) != Some(true) {
        return Err("the endpoint capability would not be installed");
    }

    let options = sched::SpawnOptions::new()
        .pinned()
        .in_domain(realm.as_u32());
    sched::spawn_on_with(cpu, "vfsd", vfs_domain_entry, hhdm_base, hhdm_base, options)
        .map_err(|_| "the filesystem domain would not spawn")?;
    Ok(())
}

/// Loads `bin/vfsd` and becomes the filesystem service, in ring 3.
///
/// The domain placement of RFC 0013. The kernel reads the program and the
/// image with its own filesystem code — it still has some, for its own shell —
/// maps both, and enters ring 3, after which every `fs::` method in the system
/// is answered by a program with no privilege at all.
///
/// Two things are given and nothing else: the endpoint capability its domain
/// was created with, and the image. A domain that could find its own storage
/// would not be a domain.
extern "C" fn vfs_domain_entry(hhdm_base: u64) -> ! {
    use bhaskix_boot::VirtAddr;
    use bhaskix_mm::{Protection, VirtRange};
    use vm::AddressSpace;

    let stop = |why: &str| -> ! {
        println!("\x1b[91m    vfs domain     FAILED: {why}\x1b[0m");
        sched::exit()
    };

    let Ok(file) = vfs::open(VFSD_PROGRAM) else {
        stop("bin/vfsd is not in the filesystem")
    };
    let Ok(image) = elf::parse(file.bytes()) else {
        stop("bin/vfsd is not an ELF this kernel will load")
    };
    let Some(root) = vfs::image() else {
        stop("there is no filesystem image to hand over")
    };

    let Ok(mut space) = AddressSpace::new(hhdm_base) else {
        stop("the address space would not be created")
    };
    let Some(stack) = VirtRange::from_pages(VirtAddr(VFSD_STACK), VFSD_STACK_PAGES) else {
        stop("the stack range is not a range")
    };
    if space.map_anonymous(stack, Protection::ReadWrite).is_err() {
        stop("the stack would not map")
    }

    // The image, read-only. Mapped before the copy and filled through the
    // direct map, exactly as the ELF loader places a read-only segment: the
    // protection says what *ring 3* may do, and the kernel filling it in first
    // is not ring 3.
    let pages = root.len().div_ceil(bhaskix_mm::FRAME_SIZE as usize) as u64;
    let Some(range) = VirtRange::from_pages(VirtAddr(VFSD_IMAGE), pages) else {
        stop("the image range is not a range")
    };
    if space.map_anonymous(range, Protection::ReadOnly).is_err() {
        stop("the image would not map")
    }
    let mut copied = 0usize;
    while copied < root.len() {
        let virtual_address = VFSD_IMAGE + copied as u64;
        let page = virtual_address & !(bhaskix_mm::FRAME_SIZE - 1);
        let within = (virtual_address - page) as usize;
        let chunk = (bhaskix_mm::FRAME_SIZE as usize - within).min(root.len() - copied);
        let Some(physical) = space.translate(VirtAddr(page)) else {
            stop("a page of the image did not stay mapped")
        };
        // SAFETY: `physical` names a frame this address space just mapped for
        // the image, reachable through the direct map, and `chunk` is bounded
        // by what remains in that page. The source is the mounted image, which
        // outlives every program.
        unsafe {
            core::ptr::copy_nonoverlapping(
                root.as_ptr().add(copied),
                (hhdm_base + (physical & !(bhaskix_mm::FRAME_SIZE - 1)) + within as u64) as *mut u8,
                chunk,
            );
        }
        copied += chunk;
    }

    let Ok(entry) = elf::load_into(&image, file.bytes(), &mut space, hhdm_base) else {
        stop("bin/vfsd would not load")
    };

    println!(
        "    vfs domain     bin/vfsd loaded, {} KiB of filesystem mapped read-only at {VFSD_IMAGE:#x}",
        root.len() / 1024
    );

    // SAFETY: the higher half is copied from the running page table, so
    // everything currently executing stays addressable.
    unsafe { vm::install(space) };

    let rsp = VFSD_STACK + VFSD_STACK_PAGES * bhaskix_mm::FRAME_SIZE;
    // SAFETY: `entry` is inside a user-executable segment of the space just
    // installed, `rsp` is one past user-writable memory in the same space, and
    // `RSP0` was set before this thread was spawned.
    // SAFETY: `entry` is inside a user-executable segment of the space
    // just installed, and `rsp` is one past user-writable memory in it.
    unsafe { enter_user("vfs domain", entry, rsp, [VFSD_IMAGE, root.len() as u64]) }
}

/// Where the user-mode shell's stack goes, and how much of it there is.
///
/// Four pages, against the probe's one. A shell has a line editor, a path
/// buffer and a listing buffer, all on the stack because it has no allocator —
/// and a program that cannot allocate keeps everything somewhere, which here
/// is here.
const SHELL_STACK: u64 = 0x0000_0000_1100_0000;
const SHELL_STACK_PAGES: u64 = 4;

/// Where the user-mode shell is in the filesystem.
const SHELL_PROGRAM: &[u8] = b"bin/shell";

/// The CPU the user-mode shell prefers.
///
/// Not the bootstrap CPU: that one runs the console service, which blocks
/// waiting for a byte, while the shell blocks waiting for the console's reply.
/// Both on one CPU works — the scheduler runs whichever is ready — but keeping
/// them apart makes the reply path a genuine cross-processor wake rather than
/// a local one, which is the case more likely to be wrong.
///
/// Clamped to what the machine has: a single-processor machine still gets a
/// shell, on the only CPU there is.
const SHELL_CPU: u32 = 2;

/// Slot base for the privilege stack the shell's CPU needs.
const SHELL_RSP0_SLOT: u64 = 3072;

/// The badges the shell's two capabilities carry.
const BADGE_CONSOLE: u64 = 0x0000_0000_00c0_0000;
const BADGE_FILESYSTEM: u64 = 0x0000_0000_00f5_0000;
/// The badge on the shell's capability to the block service.
const BADGE_SHELL_BLOCK: u64 = 0x0000_0000_00b1_0000;

/// The shell's domain, for reporting.
static SHELL_DOMAIN: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(u32::MAX);

/// Starts the console and filesystem services, then the shell that uses them.
///
/// Everything the shell can do is decided here, once, by what is installed in
/// its CSpace — two endpoints and nothing else. It cannot open a file the
/// filesystem service would not open for it, cannot print except through the
/// console service, and cannot name any other object in the system, because
/// there is no third slot.
fn user_shell(handoff: &Handoff) -> Result<(), &'static str> {
    let hhdm = handoff.hhdm_base.as_u64();

    // The console service is pinned to the CPU the serial line is routed to,
    // because it is the thread that blocks in `input::read`.
    service::start(0, hhdm)?;

    // The supervisor, before the shell. It answers RFC 0017's second question
    // and it runs to completion in a few milliseconds, so putting it here means
    // its output lands before the shell's prompt rather than interleaved with
    // what a person is typing -- which is the same reason the lines above the
    // shell's start are printed where they are.
    //
    // Not fatal: a machine with no supervisor still boots to a shell, and
    // saying so is better than refusing to start.
    // Not cpu 0. Ring 3 entry is pinned (M9-13), and pinning this to the
    // processor the boot thread is waiting on puts the two in contention --
    // which showed up as the block driver missing the three-second window its
    // own report is waited for in, on a machine where nothing was wrong.
    let cpu = bhaskix_arch::percpu::online_count().saturating_sub(1);
    if let Err(reason) = start_supervisor(cpu, hhdm) {
        println!("    supervisor     not started: {reason}");
    }

    let console = service::console_endpoint().ok_or("the console service has no endpoint")?;
    let filesystem = service::filesystem_endpoint().ok_or("the filesystem has no endpoint")?;

    // One child, which is the same limit the probe was given.
    //
    // The number is what makes a second `spawn` refused for the **budget**
    // rather than for the capability, and those are different refusals: one
    // says "you may not", the other says "not again". Without a limit, one
    // capability could exhaust a table of 32 for the whole machine, which is
    // `security.md` T10 through the door RFC 0017 step 4 opens.
    let realm = domain::create(
        "shell",
        domain::ResourceEnvelope::new().max_child_domains(1),
    )
    .map_err(|_| "no room for another domain")?;
    SHELL_DOMAIN.store(realm.as_u32(), core::sync::atomic::Ordering::Release);

    // A badged capability per service, derived from a root the kernel keeps.
    // Derived rather than installed directly for two reasons: the badge is
    // what the service uses to tell its callers apart, and revoking the root
    // takes the shell's authority with it -- so the shell holds its authority
    // on the same terms as anything else, rather than being trusted.
    //
    // Two slots, and there is no third. Everything this program can do is
    // decided here.
    for (index, endpoint, badge) in [
        (0usize, console, BADGE_CONSOLE),
        (1usize, filesystem, BADGE_FILESYSTEM),
    ] {
        let derived = cap::with_arena(|arena| {
            let root = arena
                .insert_root(
                    cap::ObjectRef::new(cap::ObjectKind::Endpoint, u64::from(endpoint.as_u32())),
                    cap::Rights::ALL,
                    0,
                )
                .ok()?;
            arena.derive(root, cap::Rights::ALL, badge).ok()
        })
        .ok_or("the capability arena is full")?;

        if domain::with(realm, |owner| {
            owner.cspace.install_at(index, derived).is_ok()
        }) != Some(true)
        {
            return Err("the capability would not install");
        }
    }

    // Memory the shell holds, twice: writable at slot 3 and read-only at slot
    // 4, naming the *same object*. Two capabilities to one thing is what makes
    // the refusal in `map` a test of rights rather than of lookup -- a program
    // refused because it holds nothing has learned nothing about rights.
    //
    // Slot 2 stays empty, because `caps` reports it as "no authority" and a
    // program holding something in every slot could not show what not holding
    // one looks like.
    let memory = shared::create(realm, 4 * bhaskix_mm::FRAME_SIZE)
        .map_err(|_| "the shell's memory object would not be created")?;
    let named = shared::name(memory).map_err(|_| "the shell's memory would not be named")?;
    let read_only = cap::with_arena(|arena| arena.derive(named, cap::Rights::READ, 0).ok())
        .ok_or("the read-only capability would not derive")?;
    if domain::with(realm, |owner| {
        owner.cspace.install_at(3, named).is_ok() && owner.cspace.install_at(4, read_only).is_ok()
    }) != Some(true)
    {
        return Err("the shell's memory capabilities would not install");
    }

    // A `DomainControl` at slot 14, which answers RFC 0017's first unresolved
    // question: the shell gets one.
    //
    // What that buys, both halves, because the RFC asked which was being
    // bought and the answer is both. It lets a person at the shell start a
    // program in a domain of its own, which is the first time anything but a
    // self-test uses RFC 0017 steps 4 to 6. It also hands the most exposed
    // program in the tree the ability to make more domains.
    //
    // The containment argument is that this is a capability like any other. It
    // is budgeted -- one child, set on the envelope above. It is derived from a
    // root the kernel keeps, so revoking that root takes the authority back. It
    // is refused if either the capability or the budget says no, and those are
    // separate refusals. A shell that could make domains without a limit would
    // be a shell that could exhaust the domain table; a shell that held this
    // ambiently rather than as a capability would be `root`.
    let control = cap::with_arena(|arena| {
        let root = arena
            .insert_root(
                cap::ObjectRef::new(cap::ObjectKind::DomainControl, 0),
                cap::Rights::ALL,
                0,
            )
            .ok()?;
        arena.derive(root, cap::Rights::ALL, 0).ok()
    })
    .ok_or("the shell's DomainControl would not derive")?;
    if domain::with(realm, |owner| owner.cspace.install_at(14, control).is_ok()) != Some(true) {
        return Err("the shell's DomainControl would not install");
    }

    // The block device's registers, read-only, at slot 5. A `Frame`
    // capability names one physical page and the kernel is the only thing that
    // can mint one -- a capability a domain could make would be permission to
    // map any physical page, which is permission to be the kernel.
    //
    // Read-only because this shell has no business driving the device. A
    // driver in a domain gets a writable one, and that is the entire
    // difference between the two: same object, same mechanism, different
    // rights. Installed only if there *is* a device, so a machine booted
    // without one still gets a shell.
    if let Some(registers) = virtio::registers(hhdm) {
        let window = cap::with_arena(|arena| {
            arena
                .insert_root(
                    cap::ObjectRef::new(cap::ObjectKind::Frame, registers),
                    cap::Rights::READ,
                    0,
                )
                .ok()
        })
        .ok_or("the device window capability would not be created")?;
        if domain::with(realm, |owner| owner.cspace.install_at(5, window).is_ok()) != Some(true) {
            return Err("the device window capability would not install");
        }
    }

    // A notification, at slot 6, and the same one write-only at slot 7.
    //
    // Signalled here, before the shell exists, so that waiting on it answers
    // immediately: a test that blocked until something happened to interrupt
    // would be a test of the machine's luck. The *source* of a signal is not
    // what this exercises -- an interrupt reaching a notification is already
    // gated, in the delegation self-test above. What was missing is the last
    // link: a program in ring 3 waiting on one and being woken.
    //
    // Slot 7 carries the write right and not the read right, which is the
    // wrong way round for waiting and is exactly the point: a capability that
    // names the notification and may not take from it.
    const SHELL_SIGNAL: u64 = 0xb10c;
    let notification = notify::create().map_err(|_| "no notification for the shell")?;
    let (readable, writable) = cap::with_arena(|arena| {
        let root = arena
            .insert_root(
                cap::ObjectRef::new(
                    cap::ObjectKind::Notification,
                    u64::from(notification.index()) | (u64::from(notification.generation()) << 32),
                ),
                cap::Rights::ALL,
                0,
            )
            .ok()?;
        let readable = arena.derive(root, cap::Rights::READ, 0).ok()?;
        let writable = arena.derive(root, cap::Rights::WRITE, 0).ok()?;
        Some((readable, writable))
    })
    .ok_or("the shell's notification capabilities would not be created")?;
    if domain::with(realm, |owner| {
        owner.cspace.install_at(6, readable).is_ok() && owner.cspace.install_at(7, writable).is_ok()
    }) != Some(true)
    {
        return Err("the shell's notification capabilities would not install");
    }
    notify::signal(notification, SHELL_SIGNAL)
        .map_err(|_| "the shell's notification would not signal")?;

    // Clamped to what the machine actually has, so a single-processor machine
    // gets a shell on the only CPU there is rather than an error.
    let cpu = SHELL_CPU.min(bhaskix_arch::percpu::online_count().saturating_sub(1));

    // The stack an interrupt from ring 3 lands on, for the shell's CPU.
    // SAFETY: a slot no thread, syscall stack or other privilege stack uses.
    let privileged = unsafe { stack::allocate(hhdm, SHELL_RSP0_SLOT + u64::from(cpu)) }
        .map_err(|_| "no privilege stack for the shell's cpu")?;
    // SAFETY: set before anything can enter ring 3 on that CPU.
    unsafe { bhaskix_arch::gdt::set_privilege_stack(cpu as usize, privileged.top) };

    // Before ring 3 gets near them, prove the services answer. A failure here
    // is a protocol bug reported as one; the same failure discovered through
    // the shell is a program that prints nothing for a reason nobody can see.
    if !service_self_test(filesystem) {
        println!("\x1b[91m    services       FAILED\x1b[0m");
    }

    // RFC 0009 step 6: the same file, by message and by shared memory.
    if !bulk_service_self_test(filesystem, hhdm) {
        println!("\x1b[91m    bulk path      FAILED\x1b[0m");
    }

    // RFC 0013 step 5: what the placement costs, said in numbers.
    if !measure_placements(console, filesystem) {
        println!("\x1b[91m    cost           FAILED\x1b[0m");
    }

    // RFC 0013 step 6: the second block device, driven from ring 3.
    if let Err(reason) = start_block_domain(cpu, hhdm, handoff.bsp_lapic_id, handoff.rsdp) {
        println!("\x1b[91m    block domain   FAILED: {reason}\x1b[0m");
    } else {
        // It has to have run before its report can be read. Waiting on a
        // notification would be better and is what a supervisor would do; RFC
        // 0013 says explicitly that it does not propose one, so this waits the
        // way the rest of the boot does.
        // Waited *for the report* rather than for a duration. A fixed wait is
        // a guess that is either too short on a loaded machine or too long on
        // every boot, and this one was both in turn. A supervisor would wait
        // on a notification; RFC 0013 says explicitly that it does not propose
        // one, so this looks for the thing it is waiting for.
        for _ in 0..60 {
            if block_domain_reported(hhdm) {
                break;
            }
            wait_millis(50);
        }
        if !report_block_domain(hhdm) {
            println!("\x1b[91m    block domain   FAILED\x1b[0m");
        }
        if !block_service_self_test(hhdm) {
            println!("\x1b[91m    block service  FAILED\x1b[0m");
        }
        if !disk_journal_self_test(hhdm) {
            println!("\x1b[91m    disk journal   FAILED\x1b[0m");
        }
        if !start_fs_domain(hhdm) {
            println!("\x1b[91m    fs domain      FAILED\x1b[0m");
        }
    }

    // The directories this program holds, at slots 8 and 10, and they are now
    // **badged endpoint capabilities to the filesystem service**. The badge
    // names the directory; the kernel stamps it on arrival so it cannot be
    // forged; and the kernel does not know what it means. There is no
    // `Directory` object kind any more and nothing here knows what an inode is
    // -- the service said which badges name `sub` and a directory that is
    // gone, and this mints capabilities carrying them.
    //
    // Slot 8 is `sub` and deliberately not the root: the shell can open
    // `inner`, and `greeting` -- same filesystem, one level up -- comes back
    // as "no such name", with no check to forget, because it holds nothing
    // that names the directory `greeting` is in.
    {
        let raw = FS_ENDPOINT.load(core::sync::atomic::Ordering::Acquire);
        let handles = [
            (
                8usize,
                FS_DIRECTORY.load(core::sync::atomic::Ordering::Acquire),
            ),
            (
                10usize,
                FS_STALE.load(core::sync::atomic::Ordering::Acquire),
            ),
        ];
        if raw != u64::MAX {
            for (slot, badge) in handles {
                let handle = cap::with_arena(|arena| {
                    let root = arena
                        .insert_root(
                            cap::ObjectRef::new(cap::ObjectKind::Endpoint, raw),
                            cap::Rights::ALL,
                            0,
                        )
                        .ok()?;
                    arena
                        .derive(root, cap::Rights::READ.union(cap::Rights::DERIVE), badge)
                        .ok()
                })
                .ok_or("a directory capability would not be created")?;
                if domain::with(realm, |owner| owner.cspace.install_at(slot, handle).is_ok())
                    != Some(true)
                {
                    return Err("a directory capability would not install");
                }
            }
        }
    }

    // The block service's endpoint, at slot 12, so this program can ask a
    // *service in another domain* for a capability. RFC 0016 step 2: what
    // comes back is not bytes but authority, and the shell then reads the
    // device itself rather than being told what it says.
    //
    // Installed only if there is a block domain, because a machine with one
    // disk delegates nothing.
    if let Some(endpoint) = block_service_endpoint() {
        let derived = cap::with_arena(|arena| {
            let root = arena
                .insert_root(
                    cap::ObjectRef::new(cap::ObjectKind::Endpoint, u64::from(endpoint.as_u32())),
                    cap::Rights::ALL,
                    0,
                )
                .ok()?;
            arena.derive(root, cap::Rights::ALL, BADGE_SHELL_BLOCK).ok()
        })
        .ok_or("the block endpoint capability would not be created")?;
        if domain::with(realm, |owner| owner.cspace.install_at(12, derived).is_ok()) != Some(true) {
            return Err("the block endpoint capability would not install");
        }
    }

    // Everything this machine has to say is said before the shell starts.
    //
    // It used to be the other way round, and the shell's first line came out
    // through the middle of the kernel's last ones: `a user-mode s` ... `boot
    // cost ...` ... `hell. 'help' lists what it can do.` Both were writing to
    // one console, and neither was wrong -- but a test looking for the banner
    // could not find it, and only under load, which is the worst way for a
    // test to be wrong. The console is shared and the interleaving is real, so
    // the fix is to stop overlapping rather than to make the test cleverer.
    //
    // **It was applied to two of the four lines.** The other two lived in the
    // caller, after this function returned, and went on tearing the banner for
    // another three milestones -- reported every time as a loaded host, because
    // that is what it looks like: the shell is alive and prompting, and the
    // harness is waiting for a string that arrived in two pieces. They are
    // here now.
    //
    // Said out loud because it was a bug for the whole of M5 and M6 and nothing
    // reported it: with a single user program at a time, keeping one installed
    // address space is indistinguishable from keeping the right one. Two
    // services in domains on one CPU is what told the difference, by running in
    // each other's page table.
    //
    // A high-water mark, not a sample. It was a sample until domains gave their
    // address-space slots back, and the two agreed only because the sample was
    // counting entries left behind by domains that had ended -- five on a boot
    // whose real concurrency was three. The gate below it asked for "at least
    // 3" and got it from corpses.
    println!(
        "    address spaces {} in use at once, each program in its own",
        vm::peak()
    );
    // Whether anything read after this point is complete. The transmitter drops
    // a byte rather than hang, which is right, and it did so silently until a
    // shell test failed on a string that had lost one character.
    //
    // It covers the kernel's own output and not the shell's, which is narrower
    // than it was and is the price of not overlapping. The shell's output is
    // checked by the shell test reading it back.
    let dropped = bhaskix_arch::serial::dropped();
    if dropped == 0 {
        println!("    console out    every byte reached the wire");
    } else {
        println!(
            "    console out    {dropped} bytes DROPPED; anything read from this log is \
             incomplete"
        );
    }
    if let Some(nanos) = time::now_nanos() {
        println!(
            "    boot cost      {}.{:03} ms to services up, console={} vfs={}",
            nanos / 1_000_000,
            nanos % 1_000_000 / 1_000,
            service::CONSOLE_PLACEMENT,
            service::VFS_PLACEMENT
        );
    }
    // Endpoint queues, after every domain the tests build and tear down.
    //
    // Placed here for the same reason the second lock-order check is placed
    // late: a gate that runs before the interesting work verifies the code
    // that ran before it. Two earlier positions for this one reported zero
    // because they ran before the services existed at all -- the endpoint
    // table had nothing live in it to look at, and "nothing wrong" and
    // "nothing there" print the same.
    // The check prints its own verdict, in detail. `FAILED` anywhere in the log
    // is what every harness here fails on, so there is nothing to accumulate.
    let _ = queue_entry_released_on_death(cpu, hhdm);

    let (queued_senders, queued_receivers, dead) = ipc::stranded_entries();
    println!(
        "    endpoint queues {queued_senders} senders and {queued_receivers} receivers queued, \
         {dead} naming a thread that has gone, {} cleared on the way",
        ipc::stranded_cleared()
    );

    BRINGUP_DONE.store(true, core::sync::atomic::Ordering::Release);
    println!("\x1b[92m  M6 in progress. Nothing left to do at this milestone.\x1b[0m");

    let options = sched::SpawnOptions::new()
        .pinned()
        .in_domain(realm.as_u32());
    sched::spawn_on_with(cpu, "usershell", user_shell_entry, hhdm, hhdm, options)
        .map_err(|_| "the shell would not spawn")?;

    Ok(())
}

/// Exercises the filesystem service's protocol without a user program.
///
/// Calls the endpoint directly, with a badge of this test's choosing, which is
/// something only in-kernel code can do — a caller in ring 3 gets whatever
/// badge its capability carries. That is the point: this checks the *service*,
/// and the shell checks the path a real program takes to it.
///
/// `console::READ` is deliberately not exercised. It blocks until somebody
/// types, and a boot test that waited for that would hang in CI and pass on a
/// developer's terminal.
/// What the bulk-path client found, since it cannot return a value.
static BULK_BYTES: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static BULK_TRIPS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// Cycles the bulk transfer took, and cycles the same bytes took by message.
///
/// Both measured in the same thread, moments apart, against the same service
/// and the same file — so the ratio is about the *path* and not about the
/// machine, which is the only part of a number taken on an emulator that
/// travels.
static BULK_CYCLES: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static MESSAGE_CYCLES: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// How many bytes a multi-page `READ_INTO` delivered, which is where the two
/// placements disagreed until 2026-08-11.
static BULK_SPANNED: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static BULK_REFUSED: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(u64::MAX);
static BULK_DONE: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
static BULK_ENDPOINT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Reads a file into shared memory from inside the domain that holds it.
extern "C" fn bulk_client(_argument: u64) -> ! {
    use bhaskix_abi::{Chunk, fs, outcome, outcome_of};
    use core::sync::atomic::Ordering;

    const BADGE: u64 = 0x00b1_0000;
    let filesystem = ipc::EndpointId::from_u32(BULK_ENDPOINT.load(Ordering::Acquire) as u32);
    let send = |method: u64, args: [u64; 4]| {
        ipc::call(filesystem, BADGE, method, args).map(|reply| reply.args)
    };

    let path = b"README";
    // Counted for the *data* path only. Opening a file costs the same either
    // way, and folding that into the figure would flatter the comparison --
    // the RFC's sixteen bytes a round trip is about moving bytes, not about
    // naming a file.
    // Both paths, five times each, least reported.
    //
    // The first version timed one of each and had the shared path nine times
    // *slower* than the message path -- because it ran first. The first
    // transfer into that memory object faults its pages in, allocates frames
    // and takes every cold line in the service; by the time the message path
    // ran, all of that had been paid. Timing the cold run of one thing against
    // the warm run of another is not a comparison, and it produced a number
    // that reversed the result.
    //
    // Five runs, minimum kept, and the file re-opened before each so both
    // paths start from the same place.
    const PASSES: u64 = 5;
    let mut shared_least = u64::MAX;
    let mut message_least = u64::MAX;
    let mut trips = 0;

    for pass in 0..PASSES {
        let _ = send(fs::PATH, Chunk::take(path).0.pack(0));
        let _ = send(fs::OPEN, [0; 4]);

        // Slot 0 holds the memory. One call, however many bytes fit.
        let start = bhaskix_arch::tsc::read();
        let moved = send(fs::READ_INTO, [0, 4096, 0, 0]);
        let elapsed = bhaskix_arch::tsc::read().saturating_sub(start);
        if let Ok(args) = moved
            && outcome_of(args[0]) == outcome::OK
        {
            shared_least = shared_least.min(elapsed);
            BULK_BYTES.store(args[0] & 0xffff_ffff, Ordering::Relaxed);
            if pass == 0 {
                trips = 1;
            }
        }

        // The same bytes the other way. Re-opened first, because the transfer
        // above consumed the file -- sixteen bytes a trip against an exhausted
        // file would have made the message path look free.
        let _ = send(fs::PATH, Chunk::take(path).0.pack(0));
        let _ = send(fs::OPEN, [0; 4]);
        let wanted = BULK_BYTES.load(Ordering::Relaxed);
        let start = bhaskix_arch::tsc::read();
        let mut by_message = 0u64;
        while by_message < wanted {
            match send(fs::READ, [0; 4]) {
                Ok(args) => {
                    let chunk = Chunk::unpack(&args);
                    if chunk.is_empty() {
                        break;
                    }
                    by_message += chunk.len() as u64;
                }
                Err(_) => break,
            }
        }
        let elapsed = bhaskix_arch::tsc::read().saturating_sub(start);
        if by_message >= wanted && wanted > 0 {
            message_least = message_least.min(elapsed);
        }
    }

    BULK_CYCLES.store(
        if shared_least == u64::MAX {
            0
        } else {
            shared_least
        },
        Ordering::Relaxed,
    );
    MESSAGE_CYCLES.store(
        if message_least == u64::MAX {
            0
        } else {
            message_least
        },
        Ordering::Relaxed,
    );
    BULK_TRIPS.store(trips, Ordering::Relaxed);

    // **More than one page**, which is the request no caller here made until
    // 2026-08-11. `bin/probe` is the largest file in the ramdisk, and asking
    // for four pages of it is what tells the two placements apart: the domain
    // one copies through a buffer of a single page, so before this it answered
    // 4096 and called that the file.
    let _ = send(fs::PATH, Chunk::take(b"bin/probe" as &[u8]).0.pack(0));
    let _ = send(fs::OPEN, [0; 4]);
    if let Ok(args) = send(fs::READ_INTO, [2, 4 * 4096, 0, 0])
        && outcome_of(args[0]) == outcome::OK
    {
        BULK_SPANNED.store(args[0] & 0xffff_ffff, Ordering::Relaxed);
    }

    // And the refusal: slot 1 names the same memory, read-only. A service
    // asked to *write* into something the caller may only read must say no,
    // however genuinely the caller holds it.
    if let Ok(args) = send(fs::READ_INTO, [1, 4096, 0, 0]) {
        BULK_REFUSED.store(outcome_of(args[0]), Ordering::Relaxed);
    }

    BULK_DONE.store(true, Ordering::Release);
    sched::exit();
}

/// RFC 0009 step 6: the filesystem service's bulk path.
///
/// The RFC's first sentence is that bulk data moves at sixteen bytes a round
/// trip, which is right for reading a filename and wrong for reading a file.
/// This measures both against each other on the same file: the chunk protocol
/// as it was, and one call that fills a shared region.
///
/// The comparison is the point. A shared-memory path that is not measured is a
/// claim; the number here is what makes it an argument.
fn bulk_service_self_test(filesystem: ipc::EndpointId, hhdm: u64) -> bool {
    use core::sync::atomic::Ordering;

    let Ok(owner) = domain::create("bulk-reader", domain::ResourceEnvelope::new()) else {
        println!("\x1b[91m    bulk path      FAILED to create a domain\x1b[0m");
        return false;
    };

    // **The objects are owned by a domain that is not going to end**, and the
    // reader holds capabilities to them. Since 2026-08-11 a domain ends when its
    // last thread exits, and `end` destroys the memory that domain owns -- so an
    // object owned by the reader would be gone before the checks below could
    // look at it, and this test would be asserting on freed frames.
    //
    // `keeper` runs no threads, so nothing ends it. It is the same shape the
    // shell's `spawn` uses: the thing that owns the memory is the thing that
    // outlives the program using it.
    let Ok(keeper) = domain::create("bulk-keeper", domain::ResourceEnvelope::new()) else {
        println!("\x1b[91m    bulk path      FAILED to create the owning domain\x1b[0m");
        domain::destroy(owner);
        return false;
    };
    let Ok(object) = shared::create(keeper, bhaskix_mm::FRAME_SIZE) else {
        println!("\x1b[91m    bulk path      FAILED to create a memory object\x1b[0m");
        domain::destroy(owner);
        domain::destroy(keeper);
        return false;
    };
    let Ok(memory_cap) = shared::name(object) else {
        println!("\x1b[91m    bulk path      FAILED to name the object\x1b[0m");
        domain::destroy(owner);
        domain::destroy(keeper);
        return false;
    };
    // Slot 1: the *same object*, read-only. The caller genuinely holds it and
    // it genuinely names memory — what it does not carry is the right to have
    // something written into it. That isolates the check being tested: an
    // empty slot is refused by the lookup, and a capability of another kind is
    // refused a second time by the generation check, so neither would tell us
    // whether the rights were consulted at all.
    let Some(decoy) = cap::with_arena(|arena| arena.derive(memory_cap, cap::Rights::READ, 0).ok())
    else {
        println!("\x1b[91m    bulk path      FAILED to derive a read-only capability\x1b[0m");
        domain::destroy(owner);
        domain::destroy(keeper);
        return false;
    };
    // **A second object, of four pages, added 2026-08-11.** Separate from the
    // one above rather than larger, so the measurement and the contents check
    // it feeds are undisturbed: this one exists only to be asked for more than
    // a placement can hold at once.
    //
    // A one-page object is a size both placements agree about by construction,
    // which is why this test passed for as long as it had only one.
    let Ok(big) = shared::create(keeper, 4 * bhaskix_mm::FRAME_SIZE) else {
        println!("\x1b[91m    bulk path      FAILED to create the multi-page object\x1b[0m");
        domain::destroy(owner);
        domain::destroy(keeper);
        return false;
    };
    let Ok(big_cap) = shared::name(big) else {
        println!("\x1b[91m    bulk path      FAILED to name the multi-page object\x1b[0m");
        domain::destroy(owner);
        domain::destroy(keeper);
        return false;
    };
    if domain::with(owner, |d| {
        d.cspace.install_at(0, memory_cap).is_ok()
            && d.cspace.install_at(1, decoy).is_ok()
            && d.cspace.install_at(2, big_cap).is_ok()
    }) != Some(true)
    {
        println!("\x1b[91m    bulk path      FAILED to install the capabilities\x1b[0m");
        domain::destroy(owner);
        domain::destroy(keeper);
        return false;
    }

    BULK_ENDPOINT.store(u64::from(filesystem.as_u32()), Ordering::Release);
    BULK_DONE.store(false, Ordering::Relaxed);
    BULK_BYTES.store(0, Ordering::Relaxed);
    BULK_REFUSED.store(u64::MAX, Ordering::Relaxed);

    let options = sched::SpawnOptions::new().in_domain(owner.as_u32());
    if sched::spawn_on_with(0, "bulk-reader", bulk_client, 0, hhdm, options).is_err() {
        println!("\x1b[91m    bulk path      FAILED to spawn a thread in the domain\x1b[0m");
        domain::destroy(owner);
        domain::destroy(keeper);
        return false;
    }
    wait_until(|| BULK_DONE.load(Ordering::Acquire), 4_000);

    let bytes = BULK_BYTES.load(Ordering::Relaxed);
    let trips = BULK_TRIPS.load(Ordering::Relaxed).max(1);
    let refused = BULK_REFUSED.load(Ordering::Relaxed);

    // What the service put there must be what the file holds -- read
    // independently, through the VFS, not through the service being tested.
    let matches = match (shared::frames_of(object), vfs::open(b"README")) {
        (Some((frames, count)), Ok(mut file)) if count > 0 && bytes > 0 => {
            let mut expected = [0u8; 256];
            let read = file.read(&mut expected);
            // SAFETY: a frame this object owns, through the direct map.
            let landed =
                unsafe { core::slice::from_raw_parts((hhdm + frames[0]) as *const u8, read) };
            read > 0 && landed == &expected[..read]
        }
        _ => false,
    };

    // And the same thing again, **past the first page**, which is the check
    // this test did not have. Reading `bin/probe` -- the largest file in the
    // ramdisk -- and comparing a window that starts after 4 KiB asserts two
    // things a single-page read cannot: that a placement delivers more than it
    // can hold at once, and that each piece lands where it belongs. A fill that
    // wrote every piece at offset zero would return the right *count* and the
    // wrong bytes, so the count alone would not have caught it either.
    let spans_pages = match (shared::frames_of(big), vfs::open(b"bin/probe")) {
        (Some((frames, count)), Ok(mut file)) if count >= 2 => {
            const PAST: usize = bhaskix_mm::FRAME_SIZE as usize + 64;
            let mut whole = [0u8; 256];
            let mut skipped = 0;
            // Walk the file to `PAST` in bites this stack can hold.
            while skipped < PAST {
                let want = (PAST - skipped).min(whole.len());
                let got = file.read(&mut whole[..want]);
                if got == 0 {
                    break;
                }
                skipped += got;
            }
            let read = file.read(&mut whole[..64]);
            // SAFETY: the second frame of an object this test owns, through the
            // direct map. `PAST` is 64 bytes into it, and 64 more is inside it.
            let landed =
                unsafe { core::slice::from_raw_parts((hhdm + frames[1] + 64) as *const u8, read) };
            skipped == PAST && read > 0 && landed == &whole[..read]
        }
        _ => false,
    };

    shared::revoke(object);
    shared::revoke(big);
    domain::destroy(owner);
    domain::destroy(keeper);

    // What the same file costs by message, at the RFC's own figure.
    let by_message = bytes.div_ceil(bhaskix_abi::CHUNK_BYTES as u64).max(1);
    // The one thing worth asserting about a timing: that shared memory is
    // still faster than fifteen round trips. Not a budget -- a factor of two,
    // against a measured eight to ten, so it fails when the bulk path has
    // stopped being one and not when the builder is busy. A tighter number
    // here would be a test of whatever machine CI runs on.
    let shared_cycles = BULK_CYCLES.load(Ordering::Relaxed);
    let message_cycles = MESSAGE_CYCLES.load(Ordering::Relaxed);
    let worth_it = shared_cycles > 0 && message_cycles >= shared_cycles.saturating_mul(2);

    // Both placements must deliver more than one page, and put it in the right
    // place. `spanned` is the count; `spans_pages` is the contents past the
    // first page -- and the count alone would not do, because a fill that wrote
    // every piece at offset zero returns the right number and the wrong bytes.
    let spanned = BULK_SPANNED.load(Ordering::Relaxed);
    let ok = bytes > 0
        && matches
        && spanned > bhaskix_mm::FRAME_SIZE
        && spans_pages
        && refused == bhaskix_abi::outcome::NOT_YOURS
        && worth_it;
    if ok {
        println!(
            "    bulk path      {bytes} bytes in {trips} round trip against {by_message} \
             by message; {spanned} bytes across pages, contents match, and a slot the \
             caller does not hold is refused"
        );
        let shared_cycles = shared_cycles.max(1);
        // Hundredths, because the interesting answers are between one and two
        // and an integer ratio would round every one of them to "1x".
        let ratio = message_cycles.saturating_mul(100) / shared_cycles;
        println!(
            "    bulk cost      {bytes} bytes: {shared_cycles} cycles shared, \
             {message_cycles} by message, {}.{:02}x, vfs={}",
            ratio / 100,
            ratio % 100,
            service::VFS_PLACEMENT
        );
    } else {
        println!(
            "    bulk path      FAILED: {bytes} bytes, contents match {matches}, \
             spanned {spanned} across pages {spans_pages}, \
             refusal {refused}, shared {shared_cycles} cycles against {message_cycles} \
             by message"
        );
        // What the service is doing, at the moment it stopped answering.
        //
        // The failure that made this necessary looks the same from outside
        // whatever caused it: the client blocks in `call` and the numbers stay
        // at their initial values. Whether the service *exited*, is still
        // waiting on its endpoint, or is queued behind something is three
        // different bugs, and the counts below tell them apart.
        match syscall::last_recv_refusal() {
            Some((thread, status)) => {
                println!("      the last refused receive was thread {thread}, status {status}")
            }
            None => println!("      no receive has been refused"),
        }
        println!(
            "      {} receives gave up on a gone endpoint",
            ipc::abandoned_recvs()
        );
        match ipc::queued(filesystem) {
            Some((senders, receivers)) => println!(
                "      the endpoint has {senders} senders and {receivers} receivers queued"
            ),
            None => println!("      the endpoint is gone"),
        }
        sched::for_each(|cpu, id, name, state, runs, _migrations, _class| {
            if name.contains("vfs") || name.contains("bulk") {
                println!("      cpu {cpu} thread {id} ({name}) {state:?}, {runs} runs");
            }
        });
    }
    ok
}

/// Measures what a service costs where it is, and says so.
///
/// RFC 0013 step 5. The RFC asked for three numbers per placement, and the
/// reason it asked is that "a domain is slower" is an argument and a cycle
/// count is not.
///
/// # What is asserted, and what is only reported
///
/// The **round trips** are asserted: one per operation, in either placement.
/// That is the number the RFC says decides whether a service can be moved, it
/// is structural rather than temporal, and it is the same on any machine.
///
/// The **cycles** are reported and not asserted. A threshold here would be a
/// test of whatever machine CI happens to run on, failing on a loaded builder
/// and passing on a fast one — which is a flaky test wearing a performance
/// budget's clothes. The numbers go in the boot log and into `TRACKER.md`,
/// where a change in them is something a person notices rather than something
/// a gate guesses at.
///
/// Nothing here prints to the console it is measuring: a zero-length write is
/// a whole round trip and no output, so the measurement does not pay for the
/// characters it would otherwise emit — and does not fill the log it is
/// written to.
fn measure_placements(console: ipc::EndpointId, filesystem: ipc::EndpointId) -> bool {
    use bhaskix_abi::{Chunk, console as console_method, fs};

    /// Enough that a single unlucky preemption does not dominate, few enough
    /// that a slow emulated machine is not held up by the measurement.
    const ROUNDS: u64 = 200;

    const BADGE: u64 = 0x00c1_0000;

    let Some(hertz) = bhaskix_arch::tsc::hertz() else {
        println!("    cost           no calibrated timer; nothing measured");
        return true;
    };

    // Timed one round trip at a time, and reported as the **minimum**.
    //
    // The first version timed the whole loop and divided, and produced a
    // filesystem in the nucleus that was four times *slower* than the same
    // filesystem in a domain -- across runs of the same build, by a factor
    // that moved. What it was measuring was preemption: the nucleus service
    // thread is not pinned, so a call may wait for another CPU to pick it up,
    // and one unlucky round trip in two hundred dominates a mean.
    //
    // The minimum is the least-disturbed sample: the run where nothing else
    // happened. It understates the cost a busy machine pays and it is the only
    // figure here that means the same thing twice, so the mean is printed
    // beside it rather than instead of it -- the gap between them is the
    // scheduling noise, which is worth seeing.
    let time = |call: &mut dyn FnMut() -> bool| -> (u64, u64, u64) {
        let (mut least, mut total, mut done) = (u64::MAX, 0u64, 0u64);
        for _ in 0..ROUNDS {
            let start = bhaskix_arch::tsc::read();
            let ok = call();
            let elapsed = bhaskix_arch::tsc::read().saturating_sub(start);
            if ok {
                done += 1;
                total = total.saturating_add(elapsed);
                least = least.min(elapsed);
            }
        }
        (least, total / done.max(1), done)
    };

    // An empty chunk: a real request, a real reply, and nothing printed.
    let (empty, _) = Chunk::take(&[]);
    let (console_least, console_mean, delivered) =
        time(&mut || ipc::call(console, BADGE, console_method::WRITE, empty.pack(0)).is_ok());

    // `fs::PATH` accumulates a path and answers. One round trip, no output.
    let (vfs_least, vfs_mean, answered) = time(&mut || {
        let (name, _) = Chunk::take(b"README");
        ipc::call(filesystem, BADGE, fs::PATH, name.pack(0)).is_ok()
    });

    // Nanoseconds, because cycles are only comparable against the same clock
    // and the clock is printed at boot anyway.
    let nanos = |cycles: u64| cycles.saturating_mul(1_000_000_000) / hertz.max(1);

    // Give the session back. `MAX_SESSIONS` is two, and a badge that has ever
    // sent `fs::PATH` holds one until it resets -- so measuring the filesystem
    // and walking away left the shell refused with `BUSY` and no filesystem at
    // all. It cost three shell checks to notice, and the service was behaving
    // exactly as documented: it has no way to know a caller has finished
    // unless the caller says so.
    // Verified, and retried, rather than sent and hoped for. A `RESET` whose
    // reply never came leaves the slot held, and the next caller -- the shell
    // -- is refused with `BUSY` and has no filesystem at all. That happened,
    // intermittently, and presented as `cat: could not reach the filesystem`
    // with nothing anywhere connecting the two.
    //
    // Three attempts because the failure is a lost round trip rather than a
    // refusal: the service always accepts a reset from a badge it knows.
    let mut released = false;
    for _ in 0..3 {
        if let Ok(reply) = ipc::call(filesystem, BADGE, fs::RESET, [0; 4])
            && bhaskix_abi::outcome_of(reply.args[0]) == bhaskix_abi::outcome::OK
        {
            released = true;
            break;
        }
    }
    if !released {
        println!(
            "\x1b[91m    cost           FAILED to release the session it measured with\x1b[0m"
        );
    }

    let ok = delivered == ROUNDS && answered == ROUNDS;
    if ok {
        println!(
            "    cost           console={} {console_least} cycles/round trip ({} ns), mean {console_mean}; \
             vfs={} {vfs_least} cycles ({} ns), mean {vfs_mean}; \
             1 round trip per operation either way, {ROUNDS} samples, least reported",
            service::CONSOLE_PLACEMENT,
            nanos(console_least),
            service::VFS_PLACEMENT,
            nanos(vfs_least),
        );
    } else {
        println!(
            "    cost           FAILED: {delivered}/{ROUNDS} console replies, \
             {answered}/{ROUNDS} filesystem replies"
        );
    }
    ok
}

fn service_self_test(filesystem: ipc::EndpointId) -> bool {
    use bhaskix_abi::{Chunk, fs, outcome, outcome_of};

    const TESTER: u64 = 0x00a1_0000;
    const SECOND: u64 = 0x00a2_0000;
    const THIRD: u64 = 0x00a3_0000;

    let send = |badge: u64, method: u64, args: [u64; 4]| {
        ipc::call(filesystem, badge, method, args).map(|reply| reply.args)
    };

    // A path in two chunks, because a path longer than sixteen bytes is the
    // ordinary case and the chunking is where an off-by-one would live.
    let path = b"etc/hostname";
    let (first, rest) = Chunk::take(&path[..8]);
    let (second, _) = Chunk::take(rest);
    let _ = send(TESTER, fs::PATH, first.pack(0));
    let _ = send(TESTER, fs::PATH, Chunk::take(&path[8..]).0.pack(0));
    let _ = second;

    let opened = send(TESTER, fs::OPEN, [0; 4]);
    let size = opened.map(|args| args[3]).unwrap_or(0);
    let opened_ok = opened.map(|args| outcome_of(args[0])) == Ok(outcome::OK);

    // Read it back through the chunk protocol.
    let mut contents = [0u8; 32];
    let mut length = 0;
    for _ in 0..8 {
        let Ok(args) = send(TESTER, fs::READ, [0; 4]) else {
            break;
        };
        let chunk = Chunk::unpack(&args);
        if chunk.is_empty() {
            break;
        }
        let room = contents.len() - length;
        let taken = chunk.len().min(room);
        contents[length..length + taken].copy_from_slice(&chunk.bytes()[..taken]);
        length += taken;
    }

    // A listing of the root, one entry per call.
    let _ = send(TESTER, fs::RESET, [0; 4]);
    let mut entries = 0;
    let mut directories = 0;
    for _ in 0..32 {
        let Ok(args) = send(TESTER, fs::LIST, [0; 4]) else {
            break;
        };
        let chunk = Chunk::unpack(&args);
        if chunk.is_empty() {
            break;
        }
        if !chunk.more() {
            entries += 1;
            let (_, directory) = bhaskix_abi::entry_of(args[3]);
            if directory {
                directories += 1;
            }
        }
    }

    // A path the filesystem refuses, through the service rather than directly.
    let _ = send(TESTER, fs::RESET, [0; 4]);
    let (traversal, _) = Chunk::take(b"../etc/hostname");
    let _ = send(TESTER, fs::PATH, traversal.pack(0));
    let refused = send(TESTER, fs::OPEN, [0; 4]).map(|args| outcome_of(args[0]));

    // A third caller, with two sessions already taken. Refused rather than
    // handed somebody else's open file. The second claims its session with a
    // `PATH`, because `RESET` *releases* one -- which is also why both are
    // released below, before anything real needs a session.
    let (probe, _) = Chunk::take(b"x");
    let _ = send(SECOND, fs::PATH, probe.pack(0));
    let busy = send(THIRD, fs::PATH, probe.pack(0)).map(|args| outcome_of(args[0]));

    // Hand both back. A test that left the service full would leave the shell
    // unable to open anything, which is precisely what the first version did.
    let _ = send(TESTER, fs::RESET, [0; 4]);
    let _ = send(SECOND, fs::RESET, [0; 4]);

    let checks = [
        ("a path sent in two chunks opened a file", opened_ok),
        ("the file's size came back", size == 8),
        (
            "its contents came back through the chunk protocol",
            &contents[..length] == b"bhaskix\n",
        ),
        ("a listing named what is in the root", entries >= 5),
        ("directories are distinguished", directories >= 2),
        (
            "a path with a parent component was refused",
            refused == Ok(outcome::BAD_PATH),
        ),
        (
            "a third caller was refused, not confused",
            busy == Ok(outcome::BUSY),
        ),
    ];

    let mut ok = true;
    for (name, passed) in checks {
        if !passed {
            println!(
                "\x1b[91m    services       FAILED: {name} ({length} bytes, {entries} entries)\x1b[0m"
            );
            ok = false;
        }
    }

    if ok {
        let (written, read, requests, refused_callers) = service::statistics();
        // The refusal is reported from what this test *observed*, not from the
        // service's counter. The counter lives wherever the service does, and
        // a service in its own domain has no way to add to a number the kernel
        // prints -- so a gate keyed on the counter would have been a gate that
        // only worked in one placement, which is the opposite of what these
        // two placements are for. `busy` is checked above either way.
        println!(
            "    services       {entries} entries listed, {length} bytes read by message; \
             a third caller was refused; console {written}/{read} b w/r; \
             {requests} requests and {refused_callers} refusals counted in the nucleus \
             (vfs={})",
            service::VFS_PLACEMENT
        );
    }
    ok
}

/// Loads `bin/shell` and becomes it.
///
/// The same shape as the ring 3 probe: this thread reads a file, maps what its
/// headers ask for, and enters user mode, which it never leaves except through
/// a system call. What is different is that this program is given capabilities
/// first, and everything it does afterwards goes through them.
extern "C" fn user_shell_entry(hhdm_base: u64) -> ! {
    use bhaskix_boot::VirtAddr;
    use bhaskix_mm::{Protection, VirtRange};
    use vm::AddressSpace;

    let stop = || -> ! { sched::exit() };

    let Ok(file) = vfs::open(SHELL_PROGRAM) else {
        println!("  the shell program is not in the filesystem");
        stop()
    };
    let Ok(image) = elf::parse(file.bytes()) else {
        println!("  the shell program is not an ELF this kernel will load");
        stop()
    };

    let Ok(mut space) = AddressSpace::new(hhdm_base) else {
        stop()
    };
    let Some(stack) = VirtRange::from_pages(VirtAddr(SHELL_STACK), SHELL_STACK_PAGES) else {
        stop()
    };
    if space.map_anonymous(stack, Protection::ReadWrite).is_err() {
        stop()
    }
    let Ok(entry) = elf::load_into(&image, file.bytes(), &mut space, hhdm_base) else {
        stop()
    };

    // SAFETY: the higher half is copied from the running page table, so
    // everything currently executing stays addressable.
    unsafe { vm::install(space) };

    let rsp = SHELL_STACK + SHELL_STACK_PAGES * bhaskix_mm::FRAME_SIZE;
    // SAFETY: `entry` is inside a user-executable segment of the space just
    // installed -- `elf::parse` refuses an entry point that is not -- `rsp` is
    // one past user-writable memory in the same space, and `RSP0` was set
    // before this thread was spawned.
    // SAFETY: `entry` is inside a user-executable segment of the space
    // just installed, and `rsp` is one past user-writable memory in it.
    unsafe { enter_user("shell", entry, rsp, [0, 0]) }
}

/// Largest filesystem image this will read off a disk.
///
/// Four megabytes. The image is read into the heap in one piece, so the bound
/// is what stops a device reporting an implausible capacity from turning into
/// an allocation the size of whatever it claimed. A real filesystem reads
/// blocks as it needs them and has no such number; this one is a whole image
/// held in memory, and says so.
const MAX_ROOT_IMAGE: u64 = 4 * 1024 * 1024;

/// Chooses where the root filesystem comes from, and mounts it.
///
/// The ramdisk by default. `root=disk` takes it from the block device instead,
/// which is the same bytes by a completely different route: enumerated on the
/// PCI bus, read by DMA, assembled in the heap. Everything above the VFS —
/// including the user-mode shell, which is a file — then comes from the disk
/// without knowing it.
///
/// Falls back to the ramdisk if the disk cannot be read, and says so. A
/// machine that booted with an empty filesystem because a drive was missing
/// would be a machine with no shell and no explanation.
fn mount_root(handoff: &Handoff) {
    let wants_disk = handoff
        .cmdline
        .split_ascii_whitespace()
        .any(|word| word == "root=disk");

    if wants_disk {
        match virtio::read_all(MAX_ROOT_IMAGE) {
            Ok(image) => {
                let bytes = alloc::vec::Vec::leak(image);
                println!(
                    "    root           {} KiB read from the block device",
                    bytes.len() / 1024
                );
                // SAFETY: called once, on the bootstrap CPU, before any thread
                // that could reach the VFS exists. The slice is leaked, so it
                // outlives everything that will borrow it.
                unsafe { vfs::mount(bytes) };
                return;
            }
            Err(error) => {
                println!(
                    "    root           the disk could not be read ({error:?}); using the ramdisk"
                );
            }
        }
    }

    // The ramdisk. Mounted on the bootstrap CPU while the only other CPUs are
    // idling in the scheduler and nothing has been spawned that could look at
    // a filesystem -- which is what the `unsafe` on `mount` asks for.
    if let Some(bytes) = handoff.initrd {
        // SAFETY: as above, with a slice that borrows the module the
        // bootloader loaded and never reclaims.
        unsafe { vfs::mount(bytes) };
    }
}

/// Checks RFC 0009 step 1: objects are made, charged, and given back whole.
///
/// The assertion that matters is the frame count across the whole thing. An
/// object holds frames the allocator no longer has, charged to a domain that
/// no longer wants them the moment either bookkeeping half is wrong — and the
/// frame-leak gate is the check this project trusts most, so this points it at
/// exactly the new case rather than hoping the existing one covers it.
fn shared_memory_self_test(hhdm: u64) -> bool {
    use bhaskix_mm::FRAME_SIZE;

    shared::set_hhdm(hhdm);

    let before = heap::available_frames();

    let Ok(realm) = domain::create("memtest", domain::ResourceEnvelope::new()) else {
        println!("\x1b[91m    memory objects FAILED: no domain to charge\x1b[0m");
        return false;
    };

    // A four-page object. Its frames must be real, distinct and page-aligned:
    // a device or a page table will use them directly, and two entries naming
    // one frame is a buffer that aliases itself.
    let object = shared::create(realm, 4 * FRAME_SIZE);
    let mut distinct = true;
    let mut aligned = true;
    if let Ok(id) = object {
        let mut seen = [0u64; 4];
        for page in 0..4 {
            let frame = shared::frame_at(id, page).unwrap_or(0);
            aligned &= frame != 0 && frame.is_multiple_of(FRAME_SIZE);
            distinct &= !seen[..page].contains(&frame);
            seen[page] = frame;
        }
        // One past the end names nothing, rather than the next object's first
        // page -- which is what an unchecked index would have returned.
        distinct &= shared::frame_at(id, 4).is_none();
    }

    let charged = domain::with(realm, |owner| owner.charged_frames()) == Some(4);
    let after_create = heap::available_frames();
    let took_frames = after_create + 4 == before;

    // Lengths: zero and one page past the bound are refusals, not clamps.
    let zero = shared::create(realm, 0) == Err(shared::MemoryError::BadLength);
    let huge = shared::create(realm, FRAME_SIZE * shared::MAX_FRAMES as u64 + 1)
        == Err(shared::MemoryError::BadLength);

    // A domain whose envelope will not cover it is refused, and nothing is
    // taken on the way out.
    let mut tiny = domain::ResourceEnvelope::new();
    tiny.memory_frames = 2;
    let pinched = domain::create("pinched", tiny).ok();
    let refused = pinched.is_some_and(|small| {
        let before_refusal = heap::available_frames();
        let outcome = shared::create(small, 4 * FRAME_SIZE);
        let unchanged = heap::available_frames() == before_refusal;
        outcome == Err(shared::MemoryError::QuotaExceeded) && unchanged
    });

    // The mapping half (step 2). Mapped into a fresh address space, checked
    // through the page tables, then the *space* is destroyed -- which must not
    // free frames that belong to the object. That invariant is the one RFC
    // 0009 singles out as the one that will be got wrong, so it is asserted
    // directly rather than inferred from a later leak check.
    let mut mapped_ok = false;
    let mut translated_ok = false;
    let mut execute_refused = false;
    let mut frames_kept = false;

    // The baseline is taken *before* the address space exists, so that after
    // it is destroyed the only correct answer is "exactly what it started
    // with". A threshold would not do: teardown also returns the page tables
    // it built, so "fewer than four extra frames" is a number that passes
    // whether or not the object's frames were wrongly freed. That version was
    // written first and failed for the right reason.
    let baseline = heap::available_frames();

    if let Ok(id) = object
        && let Ok(mut space) = vm::AddressSpace::new(hhdm)
    {
        const AT: u64 = 0x0000_0000_2000_0000;
        let at = bhaskix_boot::VirtAddr(AT);

        // Executable shared memory is refused outright: revocation unmaps
        // while the other side is running, and a receiver whose code vanishes
        // faults at an instruction that no longer exists.
        execute_refused =
            shared::map_into(id, &mut space, at, bhaskix_mm::Protection::ReadExecute).is_err();

        mapped_ok = shared::map_into(id, &mut space, at, bhaskix_mm::Protection::ReadWrite).is_ok();

        // The mapping points at the object's own frames, not at copies.
        translated_ok = (0..4).all(|page| {
            let virtual_address = bhaskix_boot::VirtAddr(AT + page * FRAME_SIZE);
            space
                .translate(virtual_address)
                .map(|physical| physical & !(FRAME_SIZE - 1))
                == shared::frame_at(id, page as usize)
        });

        space.destroy();
        // Exactly what it took, and nothing that was not its. If teardown
        // freed the object's four frames as well, this is four too many.
        frames_kept = heap::available_frames() == baseline;
    }

    // Step 3: revocation takes the pages out of every address space that
    // mapped them, before the object goes. The assertion is made through the
    // page tables, because page tables are what grant access -- a region map
    // that still lists the region is bookkeeping, and `vm::handle_fault`
    // refuses a fault on a shared region so a stale entry cannot become an
    // accidental grant.
    let mut revoked_ok = false;
    let mut ninth_refused = false;
    let mut mapped_before_revoke = false;

    if let Ok(realm2) = domain::create("revoketest", domain::ResourceEnvelope::new()) {
        if let Ok(id) = shared::create(realm2, 2 * FRAME_SIZE)
            && let Ok(mut space) = vm::AddressSpace::new(hhdm)
        {
            const AT: u64 = 0x0000_0000_3000_0000;
            let at = bhaskix_boot::VirtAddr(AT);
            let mapped = shared::map_into(id, &mut space, at, bhaskix_mm::Protection::ReadWrite);
            mapped_before_revoke =
                mapped.is_ok() && space.translate(at).is_some() && shared::mapping_count(id) == 1;

            // A ninth mapping is refused. Eight is the bound revocation can
            // walk without allocating, and a mapping revocation cannot find is
            // the one failure this design exists to prevent.
            let mut spaces = alloc::vec::Vec::new();
            for slot in 1..=8u64 {
                let Ok(mut extra) = vm::AddressSpace::new(hhdm) else {
                    break;
                };
                let outcome = shared::map_into(
                    id,
                    &mut extra,
                    bhaskix_boot::VirtAddr(AT + slot * 0x0010_0000),
                    bhaskix_mm::Protection::ReadOnly,
                );
                if slot == 8 {
                    ninth_refused = outcome == Err(shared::MemoryError::TooManyMappings);
                }
                spaces.push(extra);
            }

            let removed = shared::revoke(id);
            // The page is gone from the table it was mapped in. Not "the
            // region was removed" -- the region map is not what grants access.
            revoked_ok = removed >= 1 && space.translate(at).is_none() && !shared::live(id);

            space.destroy();
            for extra in spaces {
                extra.destroy();
            }
        }
        domain::destroy(realm2);
    }

    // Step 4: two domains, one object, and a capability crossing between them.
    // This is the step where the feature becomes usable, so the assertions are
    // about *sharing* rather than about mechanism: both address spaces must
    // resolve their own virtual address to the same physical frame, and the
    // recipient must hold rights no wider than it was given.
    let mut shared_by_two = false;
    let mut narrower_rights = false;
    let mut both_unmapped = false;

    if let (Ok(giver), Ok(taker)) = (
        domain::create("giver", domain::ResourceEnvelope::new()),
        domain::create("taker", domain::ResourceEnvelope::new()),
    ) {
        if let Ok(id) = shared::create(giver, 2 * FRAME_SIZE)
            && let Ok(root) = shared::name(id)
            && let Ok(mut mine) = vm::AddressSpace::new(hhdm)
            && let Ok(mut theirs) = vm::AddressSpace::new(hhdm)
        {
            const MINE: u64 = 0x0000_0000_4000_0000;
            const THEIRS: u64 = 0x0000_0000_5000_0000;

            // The giver hands over a *read-only* capability. Derivation is
            // monotone, so this is the ceiling on everything the taker can do
            // with it -- there is no path from here back to write access.
            let granted = cap::with_arena(|arena| {
                arena
                    .derive(root, cap::Rights::READ, 0x0000_0000_5ade_0000)
                    .ok()
            });
            narrower_rights = granted.is_some_and(|slot| {
                cap::with_arena(|arena| {
                    arena
                        .lookup(slot)
                        .is_some_and(|(_, rights)| rights == cap::Rights::READ)
                })
            }) && domain::with(taker, |owner| {
                granted.is_some_and(|slot| owner.cspace.install_at(0, slot).is_ok())
            }) == Some(true);

            let a = shared::map_into(
                id,
                &mut mine,
                bhaskix_boot::VirtAddr(MINE),
                bhaskix_mm::Protection::ReadWrite,
            );
            let b = shared::map_into(
                id,
                &mut theirs,
                bhaskix_boot::VirtAddr(THEIRS),
                bhaskix_mm::Protection::ReadOnly,
            );

            // The same frames, reached from two address spaces at two
            // different addresses. This is what "shared" means, and it is
            // checked through the page tables rather than inferred from the
            // calls having returned.
            shared_by_two = a.is_ok()
                && b.is_ok()
                && (0..2).all(|page| {
                    let one = mine
                        .translate(bhaskix_boot::VirtAddr(MINE + page * FRAME_SIZE))
                        .map(|physical| physical & !(FRAME_SIZE - 1));
                    let two = theirs
                        .translate(bhaskix_boot::VirtAddr(THEIRS + page * FRAME_SIZE))
                        .map(|physical| physical & !(FRAME_SIZE - 1));
                    one.is_some() && one == two
                });

            // Revoking the capability takes the memory from *both*, and the
            // derived capability with it. Mappings first, then the subtree.
            let (removed, capabilities) = shared::revoke_capability(root);
            both_unmapped = removed == 2
                && capabilities >= 2
                && mine.translate(bhaskix_boot::VirtAddr(MINE)).is_none()
                && theirs.translate(bhaskix_boot::VirtAddr(THEIRS)).is_none();

            mine.destroy();
            theirs.destroy();
        }
        domain::destroy(taker);
        domain::destroy(giver);
    }

    // Destroying the domain destroys its objects: a shared region does not
    // outlive the domain that made it.
    if let Some(small) = pinched {
        domain::destroy(small);
    }
    domain::destroy(realm);

    let after = heap::available_frames();
    let (live, created, destroyed) = shared::statistics();

    let checks = [
        ("an object was created", object.is_ok()),
        (
            "its frames are distinct and page-aligned",
            distinct && aligned,
        ),
        ("the frames left the allocator", took_frames),
        ("and were charged to the domain's envelope", charged),
        ("it maps into an address space", mapped_ok),
        ("an executable shared mapping is refused", execute_refused),
        ("the mapping names the object's own frames", translated_ok),
        (
            // The invariant RFC 0009 says will be got wrong.
            "destroying the address space did not free the object's frames",
            frames_kept,
        ),
        ("a mapped object reports its mapping", mapped_before_revoke),
        (
            "a ninth mapping is refused rather than untracked",
            ninth_refused,
        ),
        (
            // The property RFC 0009 exists for: after revoke returns, the
            // pages are gone from the page tables, not merely renamed.
            "revocation removed the pages from the page tables",
            revoked_ok,
        ),
        ("two address spaces reach the same frames", shared_by_two),
        (
            "the recipient's capability is narrower than the giver's",
            narrower_rights,
        ),
        (
            "revoking the capability unmapped both, and killed the derived one",
            both_unmapped,
        ),
        ("a length of zero is refused", zero),
        ("a length past the bound is refused", huge),
        (
            "an envelope that will not cover it refuses, taking nothing",
            refused,
        ),
        (
            "destroying the domain destroyed its objects",
            live == 0 && destroyed >= created,
        ),
        ("and every frame came back", after == before),
    ];

    let mut ok = true;
    for (name, passed) in checks {
        if !passed {
            println!(
                "\x1b[91m    memory objects FAILED: {name} (frames {before} -> {after}, {live} live)\x1b[0m"
            );
            ok = false;
        }
    }

    if ok {
        println!(
            "    memory objects {created} created, {destroyed} destroyed, none live; two domains \
             shared one object; {} mappings revoked out of their page tables; no frame lost \
             ({before})",
            shared::revocations()
        );
    }
    ok
}

/// Moves the block device off polling and onto an interrupt.
///
/// Runs after `console_input`, because claiming a source needs the vector
/// allocator and the I/O APIC that brings up. The assertion is a pair of
/// counters rather than a duration: **a request on MSI-X blocks once and spins
/// never**, and the reverse before this ran. A timing measurement could not
/// tell those apart on an emulator.
/// Checks that a domain's death releases the interrupt handlers it held.
///
/// RFC 0011 step 5. The assertion the RFC asks for is not "the release ran" —
/// that is a call returning — but that **the source can be claimed again**,
/// which is the only thing a later driver actually needs and the only thing
/// that fails if the vector or the claim leaked.
///
/// A legacy line rather than an MSI-X entry, because MSI-X programming writes
/// a real device's table and there is no spare device to write. `delegable`
/// says only message-signalled sources may be *given* to a domain; that rule
/// belongs to the syscall boundary in step 6. This records ownership inside
/// the kernel and proves teardown honours it.
fn irq_teardown_self_test(handoff: &Handoff) -> bool {
    /// A line with nothing behind it on this machine. Claiming it routes a
    /// chip input and masks it again on release, so a device that did appear
    /// there would be left exactly as it was found.
    const SPARE_GSI: u32 = 11;

    let source = irq::Source::Line { gsi: SPARE_GSI };
    let apic = handoff.bsp_lapic_id;
    let rsdp = handoff.rsdp;
    let hhdm = handoff.hhdm_base.as_u64();

    let (vectors_before, _) = vectors::usage();

    let Ok(owner) = domain::create("irq-teardown", domain::ResourceEnvelope::new()) else {
        println!("\x1b[91m    irq teardown   FAILED to create a domain\x1b[0m");
        return false;
    };

    // SAFETY: `trap` dispatches every unclaimed vector to `irq::on_interrupt`,
    // which is what the claim requires of its caller.
    let claimed = unsafe {
        irq::claim_for(
            source,
            owner.as_u32(),
            "irq teardown test",
            apic,
            rsdp,
            hhdm,
        )
    };
    let Ok(_handler) = claimed else {
        // Not a failure of the property under test: a machine whose chip has
        // no such input never had a handler to release. Say so rather than
        // reporting a teardown bug.
        println!("\x1b[93m    irq teardown   skipped, gsi {SPARE_GSI} could not be claimed\x1b[0m");
        domain::destroy(owner);
        return true;
    };

    // While it is alive, the source is exclusive -- otherwise "claimed again
    // afterwards" would prove nothing, because it was never unavailable.
    // SAFETY: as above.
    let second = unsafe { irq::claim(source, "irq teardown test", apic, rsdp, hhdm) };
    let exclusive = matches!(second, Err(irq::ClaimError::AlreadyClaimed));
    if let Ok(extra) = second {
        irq::release(extra);
    }
    let (vectors_held, _) = vectors::usage();

    domain::destroy(owner);

    let (vectors_after, _) = vectors::usage();

    // SAFETY: as above.
    let again = unsafe { irq::claim(source, "irq teardown test", apic, rsdp, hhdm) };
    let reclaimed = again.is_ok();
    if let Ok(id) = again {
        irq::release(id);
    }
    let (vectors_end, _) = vectors::usage();

    let checks = [
        (
            "the source was exclusive while the domain held it",
            exclusive,
        ),
        ("the claim took a vector", vectors_held > vectors_before),
        (
            "the domain's death freed it",
            vectors_after == vectors_before,
        ),
        ("and the source could be claimed again", reclaimed),
        ("with nothing left over", vectors_end == vectors_before),
    ];

    let mut ok = true;
    for (name, passed) in checks {
        if !passed {
            println!(
                "\x1b[91m    irq teardown   FAILED: {name} (vectors {vectors_before} -> {vectors_held} -> {vectors_after} -> {vectors_end})\x1b[0m"
            );
            ok = false;
        }
    }
    if ok {
        println!(
            "    irq teardown   a domain's handler released on its death; gsi {SPARE_GSI} claimed again, {vectors_before} vectors either side"
        );
    }
    ok
}

fn block_interrupt_self_test(handoff: &Handoff) -> bool {
    if !virtio::present() {
        return true;
    }

    let vector = match virtio::enable_interrupts(
        handoff.bsp_lapic_id,
        handoff.rsdp,
        handoff.hhdm_base.as_u64(),
    ) {
        Ok(vector) => vector,
        Err(error) => {
            // Survivable: the driver polls, which is what it did until now.
            println!("    virtio-blk irq not enabled ({error:?}); the driver polls");
            return true;
        }
    };

    let (_, spins_before) = virtio::waiting();
    let (delivered_before, _, _) = irq::statistics();

    // One read, with the whole path live.
    let mut sector = [0u8; 512];
    let read = virtio::read(8, &mut sector);

    let (waits, spins) = virtio::waiting();
    let interrupt_driven = virtio::interrupt_driven();
    let (delivered, strays, unbound) = irq::statistics();
    let expected = handoff.initrd.unwrap_or(&[]);
    let matches = expected.len() >= 8 * 512 + 512 && sector == expected[8 * 512..8 * 512 + 512];

    let checks = [
        ("the read completed", read.is_ok()),
        ("and returned the right sector", matches),
        // Deliberately *not* `waits > 0`. Whether the driver had to sleep
        // depends on whether the device finished before the first completion
        // check, which is a fact about the host: a read that completes that
        // fast is the driver working, not failing. That assertion cost a suite
        // run on a loaded machine, having passed 24 of 24 on an idle one.
        //
        // What is asserted instead cannot be satisfied by a polling driver:
        // the interrupt is bound (so completion has something to arrive on),
        // and `spins` below stays at zero (so nothing looked twice).
        (
            "the driver is interrupt-driven, not polling",
            interrupt_driven,
        ),
        (
            // The number RFC 0011 asks for. Not "fewer spins" -- none.
            "and did not spin once",
            spins == spins_before,
        ),
        (
            "the device delivered an interrupt",
            delivered > delivered_before,
        ),
        (
            "nothing arrived unclaimed or unbound",
            strays == 0 && unbound == 0,
        ),
    ];

    let mut ok = true;
    for (name, passed) in checks {
        if !passed {
            println!(
                "\x1b[91m    virtio-blk irq FAILED: {name} ({waits} waits, {} spins, {} deliveries)\x1b[0m",
                spins - spins_before,
                delivered - delivered_before
            );
            ok = false;
        }
    }

    if ok {
        println!(
            "    virtio-blk irq msi-x vector {vector:#04x}; {waits} waits, {} spins, \
             {} interrupts per request, {} woken by the clock rather than the device",
            spins - spins_before,
            delivered - delivered_before,
            virtio::unsignalled()
        );
    }
    ok
}

/// Brings up the block device and reads from it.
///
/// The disk is the initial ramdisk's own image, attached as a drive. That is
/// not a convenience: it means the test knows exactly what the first sectors
/// must contain, and can say so — a driver that read *something* and reported
/// success would pass a test that only checked for an error code.
///
/// A machine with no disk is not a failure. The kernel boots without one and
/// says there was none.
/// Brings the IOMMU up before any device is programmed.
///
/// RFC 0012 steps 1-4, in the only order that works. A window names the device
/// it translates for, so the device's requester id is needed before the window
/// exists — hence the probe. Translation is switched on before the driver is
/// brought up, because from `DRIVER_OK` the device may read a ring, and a ring
/// it cannot translate is a request that faults rather than completes.
///
/// `None` on any machine without a usable unit, which is every machine this
/// project was tested on until today, and the path that must stay unchanged.
/// What the delegated domain's thread found, since it cannot return a value.
static GRANT_ADDRESS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static GRANT_WITHOUT: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(u32::MAX);
static GRANT_DONE: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Runs the two `MAP` calls from inside the domain that holds the capabilities.
///
/// From inside, because that is the only way the check under test is the one
/// that runs: `resolve_window` looks up the caller's own CSpace, and a call
/// made from the kernel's thread would resolve against a different one.
extern "C" fn dma_client(_argument: u64) -> ! {
    use core::sync::atomic::Ordering;

    // Slot 1 is the window, slot 0 the memory it is allowed to map.
    let mut mapping = syscall::SyscallFrame {
        kind: syscall::Kind::Invoke as u64,
        capability: 1,
        method: syscall::method::MAP,
        arg0: 0,
        ..syscall::SyscallFrame::default()
    };
    let granted = syscall::dispatch(&mut mapping);
    if granted.status == syscall::Status::Ok {
        GRANT_ADDRESS.store(granted.value, Ordering::Relaxed);
    }

    // The same call naming the *memory* capability where a window belongs.
    // Authority to say what a device may reach has to be held; this is the
    // call that proves it is not ambient.
    let mut refused = syscall::SyscallFrame {
        kind: syscall::Kind::Invoke as u64,
        capability: 0,
        method: syscall::method::MAP,
        arg0: 0,
        ..syscall::SyscallFrame::default()
    };
    let without = syscall::dispatch(&mut refused);
    GRANT_WITHOUT.store(without.status as u32, Ordering::Relaxed);

    GRANT_DONE.store(true, Ordering::Release);
    sched::exit();
}

/// What the delegated driver's thread found.
static IRQ_BOUND: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(u32::MAX);
static IRQ_ACKED: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(u32::MAX);
static IRQ_WITHOUT: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(u32::MAX);
static IRQ_DONE: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Exercises `BIND`, `ACK` and a refusal, from inside the domain that holds
/// the capabilities.
extern "C" fn irq_client(_argument: u64) -> ! {
    use core::sync::atomic::Ordering;

    // Slot 0 the handler, slot 1 the notification it may signal.
    let mut bind = syscall::SyscallFrame {
        kind: syscall::Kind::Invoke as u64,
        capability: 0,
        method: syscall::method::BIND,
        arg0: 1,
        arg1: 1,
        ..syscall::SyscallFrame::default()
    };
    IRQ_BOUND.store(
        syscall::dispatch(&mut bind).status as u32,
        Ordering::Relaxed,
    );

    let mut ack = syscall::SyscallFrame {
        kind: syscall::Kind::Invoke as u64,
        capability: 0,
        method: syscall::method::ACK,
        ..syscall::SyscallFrame::default()
    };
    IRQ_ACKED.store(syscall::dispatch(&mut ack).status as u32, Ordering::Relaxed);

    // And the refusal: acknowledging through the *notification* capability,
    // which is not authority over an interrupt however much it is held.
    let mut without = syscall::SyscallFrame {
        kind: syscall::Kind::Invoke as u64,
        capability: 1,
        method: syscall::method::ACK,
        ..syscall::SyscallFrame::default()
    };
    IRQ_WITHOUT.store(
        syscall::dispatch(&mut without).status as u32,
        Ordering::Relaxed,
    );

    IRQ_DONE.store(true, Ordering::Release);
    sched::exit();
}

/// RFC 0011 step 6: an `IrqHandler` a domain holds.
///
/// The step the RFC would not take until there was an IOMMU, and there is one
/// now. What a holder gets is `BIND`, `ACK` and `RELEASE` — never the MSI-X
/// table, because an MSI is a memory write of an arbitrary vector to an
/// arbitrary CPU and a holder that could program one would hold an interrupt
/// injection primitive. The kernel keeps that.
///
/// Only a message-signalled source may be delegated at all, which this checks
/// by trying a legacy line and expecting a refusal: a line is shared, and a
/// holder that never acknowledges masks a line other devices need.
fn irq_delegation_self_test(handoff: &Handoff) -> bool {
    if !iommu::present() {
        // The RFC's own precondition, and `irq::name` refuses here too. A
        // machine with no translation is one where delegating a device is not
        // safe to do, so it is not done and the machine says so.
        println!(
            "\x1b[93m    irq grant      skipped, no IOMMU: a device cannot be delegated safely\x1b[0m"
        );
        return true;
    }
    let apic = handoff.bsp_lapic_id;
    let rsdp = handoff.rsdp;
    let hhdm = handoff.hhdm_base.as_u64();

    // A spare legacy line, which must be refused for delegation.
    let line = irq::Source::Line { gsi: 11 };
    // SAFETY: `trap` dispatches unclaimed vectors to `irq::on_interrupt`.
    let Ok(line_handler) = (unsafe { irq::claim(line, "irq delegation test", apic, rsdp, hhdm) })
    else {
        println!("\x1b[93m    irq grant      skipped, no spare line to claim\x1b[0m");
        return true;
    };
    let line_refused = matches!(irq::name(line_handler), Err(irq::ClaimError::NotDelegable));
    irq::release(line_handler);

    // The block device's own handler is message-signalled, so it is the one
    // that may be delegated. Claiming a second is not possible -- a source is
    // claimed once -- so this names the handler the driver already holds.
    let Some(handler) = virtio::handler() else {
        println!("\x1b[93m    irq grant      skipped, the block driver holds no handler\x1b[0m");
        return line_refused;
    };
    let (Ok(handler_cap), Ok(notification)) = (irq::name(handler), notify::create()) else {
        println!(
            "\x1b[91m    irq grant      FAILED to name the handler or make a notification\x1b[0m"
        );
        return false;
    };
    let Ok(notify_cap) = notify::name(notification) else {
        println!("\x1b[91m    irq grant      FAILED to name the notification\x1b[0m");
        return false;
    };

    let Ok(owner) = domain::create("irq-holder", domain::ResourceEnvelope::new()) else {
        println!("\x1b[91m    irq grant      FAILED to create a domain\x1b[0m");
        return false;
    };
    let placed = domain::with(owner, |domain| {
        domain.cspace.install_at(0, handler_cap).is_ok()
            && domain.cspace.install_at(1, notify_cap).is_ok()
    });
    if placed != Some(true) {
        println!("\x1b[91m    irq grant      FAILED to install the capabilities\x1b[0m");
        domain::destroy(owner);
        return false;
    }

    IRQ_DONE.store(false, core::sync::atomic::Ordering::Relaxed);
    let options = sched::SpawnOptions::new().in_domain(owner.as_u32());
    if sched::spawn_on_with(0, "irq-holder", irq_client, 0, hhdm, options).is_err() {
        println!("\x1b[91m    irq grant      FAILED to spawn a thread in the domain\x1b[0m");
        domain::destroy(owner);
        return false;
    }
    wait_until(
        || IRQ_DONE.load(core::sync::atomic::Ordering::Acquire),
        4_000,
    );

    let bound = IRQ_BOUND.load(core::sync::atomic::Ordering::Relaxed);
    let acked = IRQ_ACKED.load(core::sync::atomic::Ordering::Relaxed);
    let without = IRQ_WITHOUT.load(core::sync::atomic::Ordering::Relaxed);

    // Put the driver's own notification back: the domain pointed the block
    // device's interrupt at its own, and the driver is still using it.
    let _ = virtio::rebind_notification();
    domain::destroy(owner);
    notify::destroy(notification);

    let ok = bound == syscall::Status::Ok as u32
        && acked == syscall::Status::Ok as u32
        && without == syscall::Status::WrongObject as u32
        && line_refused;
    if ok {
        println!(
            "    irq grant      a domain bound and acknowledged an interrupt it was given; \
             a legacy line was refused delegation, and a notification is not an interrupt"
        );
    } else {
        println!(
            "    irq grant      FAILED: bind {bound}, ack {acked}, refusal {without}, \
             legacy line refused {line_refused}"
        );
    }
    ok
}

/// RFC 0012 step 7: a `DmaWindow` a domain holds, and what it cannot do without
/// one.
///
/// The step every earlier RFC was building toward, and the assertion is about
/// **refusal** rather than capability. That a domain holding both capabilities
/// can map is the easy half; that a domain holding the memory and *not* the
/// window cannot is the half that makes delegation mean anything. A device
/// writes with no page table and asks nobody, so the authority to say what one
/// may reach has to be held rather than ambient.
fn iommu_delegation_self_test(hhdm: u64) -> bool {
    let _ = hhdm;
    let Ok(owner) = domain::create("dma-holder", domain::ResourceEnvelope::new()) else {
        println!("\x1b[91m    iommu grant    FAILED to create a domain\x1b[0m");
        return false;
    };
    let Ok(object) = shared::create(owner, bhaskix_mm::FRAME_SIZE) else {
        println!("\x1b[91m    iommu grant    FAILED to create a memory object\x1b[0m");
        domain::destroy(owner);
        return false;
    };

    let Some(device) = virtio::probe() else {
        return false;
    };
    let (Ok(memory_cap), Ok(window_cap)) = (shared::name(object), iommu::name(device)) else {
        println!("\x1b[91m    iommu grant    FAILED to name the object or the window\x1b[0m");
        domain::destroy(owner);
        return false;
    };

    // Slot 0 holds the memory, slot 1 the window. A second domain gets only
    // the memory, which is the interesting one.
    let placed = domain::with(owner, |domain| {
        domain.cspace.install_at(0, memory_cap).is_ok()
            && domain.cspace.install_at(1, window_cap).is_ok()
    });
    if placed != Some(true) {
        println!("\x1b[91m    iommu grant    FAILED to install the capabilities\x1b[0m");
        domain::destroy(owner);
        return false;
    }

    // Run from inside the domain, because `resolve_window` resolves against
    // the caller's own CSpace -- a call made here would check the kernel's.
    GRANT_ADDRESS.store(0, core::sync::atomic::Ordering::Relaxed);
    GRANT_WITHOUT.store(u32::MAX, core::sync::atomic::Ordering::Relaxed);
    GRANT_DONE.store(false, core::sync::atomic::Ordering::Relaxed);

    let options = sched::SpawnOptions::new().in_domain(owner.as_u32());
    if sched::spawn_on_with(0, "dma-holder", dma_client, 0, hhdm, options).is_err() {
        println!("\x1b[91m    iommu grant    FAILED to spawn a thread in the domain\x1b[0m");
        domain::destroy(owner);
        return false;
    }
    wait_until(
        || GRANT_DONE.load(core::sync::atomic::Ordering::Acquire),
        4_000,
    );

    let address = GRANT_ADDRESS.load(core::sync::atomic::Ordering::Relaxed);
    let without = GRANT_WITHOUT.load(core::sync::atomic::Ordering::Relaxed);

    let mapped = address != 0;
    let denied = without == syscall::Status::WrongObject as u32;

    shared::revoke(object);
    domain::destroy(owner);

    match (mapped, denied) {
        (true, true) => {
            println!(
                "    iommu grant    a domain mapped its own memory for a device at {:#x}; \
                 the same call without a window capability was refused",
                address
            );
            true
        }
        (false, _) => {
            println!(
                "    iommu grant    FAILED: a domain holding both capabilities could not map \
                 (status {})",
                without
            );
            false
        }
        // The dangerous one: authority that is ambient rather than held.
        (_, false) => {
            println!(
                "    iommu grant    FAILED: A DOMAIN MAPPED FOR A DEVICE WITHOUT A WINDOW \
                 CAPABILITY (status {without})"
            );
            false
        }
    }
}

/// RFC 0012 step 5: a `Memory` object a device can reach, and a revoke that
/// takes it away from the device too.
///
/// The two RFCs meet here. RFC 0009's object is frames plus an owner plus a
/// revocation that must complete; RFC 0012 makes a device window one of the
/// places such an object can be mapped. What has to be true afterwards is not
/// "the tables were edited" but that the **device** can no longer reach it —
/// so that is what this asks the device.
///
/// Runs last, and only where translation is on. It deliberately ends with a
/// refused request outstanding.
/// Whether a device address that was freed and handed out again translates to
/// the memory it names *now*.
///
/// This is the proof `DevAddrSpace::allocate` was waiting on, and the reason
/// device-address reuse was disabled at M6-13: after a map, an unmap with a
/// global invalidation, and a map of the same address, a device was recorded
/// still reaching the old page. Reuse without this is a revocation with a
/// delay fuse — an address handed to something new while the hardware may
/// still translate it to something old.
///
/// # What makes it a test rather than a demonstration
///
/// Two objects, both alive throughout, and **the old one is checked**. A test
/// that only confirmed the new object received its sector would pass just as
/// happily with a stale translation, because a stale translation writes to the
/// old frame and says nothing. The assertion that catches the fault is that
/// the first object's page is *unchanged* after the device writes through an
/// address that used to be its.
///
/// Two different sectors, for the same reason: if both reads fetched the same
/// bytes, every frame would hold the right contents either way.
///
/// **If the address is not reused, this proves nothing and says so.** Reuse is
/// a policy `allocate` decides; a green line here on a bump-only allocator
/// would be the kind of check that is not looking at what it claims to.
fn iommu_reuse_self_test(found: &iommu::Report, handoff: &Handoff, hhdm: u64) -> bool {
    let image = handoff.initrd.unwrap_or(&[]);
    if image.len() < 1024 {
        println!("    iommu reuse    skipped: the image is too short to hold two sectors");
        return true;
    }
    let (first, second) = (&image[..512], &image[512..1024]);
    if first == second {
        println!(
            "    iommu reuse    skipped: sectors 0 and 1 are identical, so nothing to tell apart"
        );
        return true;
    }

    let Ok(owner) = domain::create("dma-reuse", domain::ResourceEnvelope::new()) else {
        println!("\x1b[91m    iommu reuse    FAILED to create a domain\x1b[0m");
        return false;
    };
    let (Ok(old), Ok(new)) = (
        shared::create(owner, bhaskix_mm::FRAME_SIZE),
        shared::create(owner, bhaskix_mm::FRAME_SIZE),
    ) else {
        println!("\x1b[91m    iommu reuse    FAILED to create two memory objects\x1b[0m");
        domain::destroy(owner);
        return false;
    };
    let Some(device) = virtio::probe() else {
        domain::destroy(owner);
        return true;
    };

    // Reads a frame of an object through the direct map.
    let page_of = |id| match crate::shared::frames_of(id) {
        Some((frames, count)) if count > 0 => {
            // SAFETY: a frame the object owns, and this reads it only.
            Some(unsafe { core::slice::from_raw_parts((hhdm + frames[0]) as *const u8, 512) })
        }
        _ => None,
    };

    let Some(address) = iommu::map_memory(
        device,
        old,
        bhaskix_arch::vtd::Rights::READ_WRITE,
        false,
        hhdm,
    ) else {
        println!("\x1b[91m    iommu reuse    FAILED to map the first object\x1b[0m");
        domain::destroy(owner);
        return false;
    };
    // SAFETY: the unit `iommu_bringup` mapped and programmed. Any fault before
    // this belongs to something else.
    let _ = unsafe { iommu::take_fault(found, hhdm) };
    let _ = virtio::read_into(0, address.as_u64());
    let old_took_sector_0 = page_of(old) == Some(first);

    // Unmapped, which clears the entries, returns the extent and invalidates.
    let unmapped = iommu::unmap_device(device, address.as_u64(), 1);

    let Some(again) = iommu::map_memory(
        device,
        new,
        bhaskix_arch::vtd::Rights::READ_WRITE,
        false,
        hhdm,
    ) else {
        println!("\x1b[91m    iommu reuse    FAILED to map the second object\x1b[0m");
        domain::destroy(owner);
        return false;
    };
    let reused = again == address;

    let _ = virtio::read_into(1, again.as_u64());
    let new_took_sector_1 = page_of(new) == Some(second);
    // The one that matters: nothing may have arrived through an address this
    // object no longer owns.
    let old_is_untouched = page_of(old) == Some(first);

    // SAFETY: as above.
    let faulted = unsafe { iommu::take_fault(found, hhdm) };
    let _ = iommu::unmap_device(device, again.as_u64(), 1);
    shared::revoke(old);
    shared::revoke(new);
    domain::destroy(owner);

    if !reused {
        println!(
            "    iommu reuse    nothing proven: {} was not handed out again, so no stale \
             translation could be exercised",
            address.as_u64()
        );
        return true;
    }

    let ok = old_took_sector_0 && unmapped && new_took_sector_1 && old_is_untouched;
    if ok {
        println!(
            "    iommu reuse    a device address was freed, handed out again, and translated to \
             the new object -- the old one's page is untouched"
        );
    } else {
        println!(
            "\x1b[91m    iommu reuse    FAILED: first read {old_took_sector_0}, unmapped \
             {unmapped}, second read {new_took_sector_1}, old page untouched {old_is_untouched}, \
             fault {faulted:?}\x1b[0m"
        );
    }
    ok
}

fn iommu_memory_self_test(found: &iommu::Report, handoff: &Handoff, hhdm: u64) -> bool {
    let Ok(owner) = domain::create("dma-object", domain::ResourceEnvelope::new()) else {
        println!("\x1b[91m    iommu memory   FAILED to create a domain\x1b[0m");
        return false;
    };
    let Ok(object) = shared::create(owner, bhaskix_mm::FRAME_SIZE) else {
        println!("\x1b[91m    iommu memory   FAILED to create a memory object\x1b[0m");
        domain::destroy(owner);
        return false;
    };

    let Some(device) = virtio::probe() else {
        domain::destroy(owner);
        return false;
    };
    let Some(address) = iommu::map_memory(
        device,
        object,
        bhaskix_arch::vtd::Rights::READ_WRITE,
        false,
        hhdm,
    ) else {
        println!(
            "\x1b[91m    iommu memory   FAILED to map the object into the device window\x1b[0m"
        );
        domain::destroy(owner);
        return false;
    };

    // Any fault recorded before this point belongs to something else, and
    // reading it here would attribute it to this test's own access -- which is
    // exactly what happened when the delegation test began running first.
    // SAFETY: the unit `iommu_bringup` mapped and programmed.
    let _ = unsafe { iommu::take_fault(found, hhdm) };

    // Reachable: the device is asked to write a sector into the object, and
    // the unit must not complain.
    let before = virtio::read_into(0, address.as_u64());
    // SAFETY: the unit `iommu_bringup` mapped and programmed.
    let faulted_while_mapped = unsafe { iommu::take_fault(found, hhdm) };

    // And the object holds what the device was asked to fetch.
    //
    // "No fault was recorded" is not evidence that a mapping is right, and
    // that is not a hypothetical: this test passed for a whole step while
    // every device mapping pointed 4096 times too high, because a translation
    // to an address that does not exist is dropped quietly rather than
    // refused. Comparing the bytes is what makes "reachable" mean reached.
    let expected = handoff.initrd.unwrap_or(&[]);
    let landed = match crate::shared::frames_of(object) {
        Some((frames, count)) if count > 0 && expected.len() >= 512 => {
            // SAFETY: a frame this object owns, read through the direct map.
            let written =
                unsafe { core::slice::from_raw_parts((hhdm + frames[0]) as *const u8, 512) };
            written == &expected[..512]
        }
        _ => false,
    };

    // Revoked. RFC 0009's walk now has a device window in it.
    let removed = shared::revoke(object);

    // And unreachable, which is the whole assertion: the same address, the
    // same device, and now a refusal.
    let _after = virtio::read_into(0, address.as_u64());
    // SAFETY: as above.
    let faulted_after = unsafe { iommu::take_fault(found, hhdm) };

    domain::destroy(owner);

    match (before, faulted_while_mapped, faulted_after) {
        _ if !landed => {
            println!(
                "    iommu memory   FAILED: the device wrote nothing the object can see -- \
                 mapped, unfaulted, and pointing somewhere else"
            );
            false
        }
        (Ok(()) | Err(_), None, Some(fault)) => {
            println!(
                "    iommu memory   an object was reachable at {:#x}{}, {removed} mappings \
                 revoked, and the device was then refused it ({:#x}, reason {:#04x})",
                address.as_u64(),
                if before.is_ok() {
                    ""
                } else {
                    " (the request did not complete)"
                },
                fault.address,
                fault.reason
            );
            true
        }
        (_, Some(fault), _) => {
            println!(
                "    iommu memory   FAILED: the device could not reach a mapped object \
                 ({:#x}, reason {:#04x})",
                fault.address, fault.reason
            );
            false
        }
        // The one that matters. Revocation edited the tables and the device
        // kept reaching the frames anyway.
        (_, _, None) => {
            println!(
                "\x1b[91m    iommu memory   FAILED: THE DEVICE STILL REACHED A REVOKED OBJECT at {:#x}\x1b[0m",
                address.as_u64()
            );
            false
        }
    }
}

fn iommu_bringup(handoff: &Handoff) -> Option<(iommu::Report, iommu::Window)> {
    let hhdm = handoff.hhdm_base.as_u64();
    // SAFETY: the handoff's addresses, and `mmio::map` is the mapper
    // `irq::init` walks these same tables with.
    let found = unsafe { iommu::discover(handoff.rsdp, hhdm) };
    iommu::report(found);

    // The way out, for a machine where the IOMMU is what is wrong.
    //
    // **After discovery and reporting, deliberately.** An escape hatch that
    // also silenced the `DMAR` would take away the one thing whoever is
    // holding the machine needs: what the firmware actually declared. This
    // builds nothing and enables nothing, and still prints the units, the
    // address width and the reserved regions.
    //
    // Nothing else has to know. Returning `None` here is the same state as a
    // machine with no unit at all -- `present()` is false, the block driver
    // takes the untranslated path every machine took before RFC 0012, and
    // `irq::name` and `iommu::name` refuse a domain-hosted driver for the
    // reason they always did. That configuration is not novel and not
    // untested: it is what `make test-boot` boots on every run.
    //
    // Why it exists at all: translation comes up before any service, so a
    // machine that wedges there cannot be booted far enough to say why. On
    // QEMU that is an inconvenience. On the first piece of real hardware this
    // kernel ever runs on -- M1-17, still owed -- it is the difference between
    // a debugging session and a brick, and real firmware declares reserved
    // regions that QEMU never has.
    if handoff
        .cmdline
        .split_ascii_whitespace()
        .any(|word| word == "iommu=off")
    {
        println!(
            "\x1b[93m    iommu          OFF by iommu=off: nothing is translating, every device \
             reaches all of memory (security.md T3 and T4 unmitigated)\x1b[0m"
        );
        // Load-bearing, and measured: with this `return` removed the machine
        // prints the line above and programs the unit anyway, and
        // `boot-test.sh iommu-off` fails on "printed its line and then
        // programmed the unit anyway" -- which is the shape of escape hatch
        // that is worse than none, because the log says you are safe.
        return None;
    }

    let found = found.filter(|report| report.units > 0)?;
    let device = virtio::probe()?;
    let (bus, slot, function) = device;

    let window = iommu::build_window(&found, device, 0, hhdm)?;
    if !iommu::verify_window(&window, 1, hhdm) {
        // Built and read back wrong is worse than not built: every value would
        // be right and the offsets wrong, which is a device translating
        // through some other device's tables.
        println!("\x1b[91m    iommu window   FAILED: the tables did not read back\x1b[0m");
        return None;
    }

    let kernel = iommu::kernel_extent(handoff);
    let (reserved, refused) = iommu::map_reserved(&window, &found, kernel, hhdm);

    // SAFETY: the window is built and verified, and its tables are never
    // freed. Nothing is doing DMA yet -- the device has not been programmed.
    if let Err(reason) = unsafe { iommu::enable(&found, &window, hhdm) } {
        println!("\x1b[91m    iommu enable   FAILED: {reason}\x1b[0m");
        return None;
    }

    // The transition RFC 0012 warns about. A device the firmware left running
    // -- and the firmware enumerated this disk to decide whether to boot from
    // it -- does a stray DMA the instant translation is on, with the physical
    // address it was configured with while nothing was translating. It is
    // expected, it is reported, and it is cleared here so that a fault seen
    // *after* the driver is up means something else entirely.
    //
    // SAFETY: the unit just programmed above.
    let transition = unsafe { iommu::take_fault(&found, hhdm) };

    // Interrupt remapping, and **off unless asked for**. RFC 0012 step 6 is
    // built -- the table, entries that validate which device may present a
    // handle, remappable lines and messages, and compatibility format blocked
    // -- and as of 2026-08-11 it works: with `iommu=remap-irq` the whole boot
    // test passes, the block driver is woken by its own device at one
    // interrupt per request, and every message that arrives is a handle this
    // kernel issued.
    //
    // **On by default since 2026-08-11**, which is a decision and not a
    // consequence of the fix: without it a device can raise any vector on any
    // CPU by writing a word, and RFC 0011 accepted that risk only because
    // there was no unit to close it. There is now.
    //
    // What the default costs, said plainly because it is not nothing: this
    // path was silently broken for its entire life until the day before it was
    // turned on, so it has few boots behind it; it has been seen working on
    // one emulator; and nothing has ever booted this kernel on physical
    // hardware, where an IOMMU is much less forgiving than a model of one.
    // `iommu=no-remap-irq` turns it off for a machine where it goes wrong, and
    // that escape hatch is the reason turning it on is reversible rather than
    // brave.
    //
    // A unit that cannot do it, or refuses, is **not** a boot failure: the
    // reason is printed and the machine runs with the risk RFC 0011 named,
    // exactly as it did before. Degrading loudly is the whole difference
    // between this and a machine that quietly polls.
    //
    // What it was, so that the shape of it is remembered rather than the
    // symptom: **enabling remapping turned translation off**. `GCMD` is
    // write-only, `vtd::Unit` shadows it, and `Unit::new` starts that shadow at
    // zero -- so a unit built fresh around an already-translating window wrote
    // a zero into the translation-enable bit with its first command. `GSTS`
    // went 0xc000_0000 to 0x4400_0000 across one line. Everything else was
    // downstream of that: with translation off the device gets a passthrough
    // address space, which has no interrupt-remapping region in it, so its
    // message went to the APIC in compatibility format and no request ever
    // reached the unit -- while the I/O APIC's line, which is not a device
    // DMA, kept working. `Unit::adopt` is the fix and the check below is the
    // guard.
    //
    // SAFETY: the unit is programmed, and nothing has been routed yet --
    // `console_input` and the block driver's MSI-X both come later.
    // `iommu=remap-irq` is still accepted and now means nothing, because a
    // command line that used to be the only way to get this is on machines and
    // in scripts that should not break for saying so.
    // Not `refused`: that name is taken, five lines up, by the count of
    // reserved regions this window would not map -- and shadowing it printed a
    // boolean into the boot line where a number belongs.
    let opted_out = handoff
        .cmdline
        .split_ascii_whitespace()
        .any(|word| word == "iommu=no-remap-irq");
    let remapped = if opted_out {
        None
    } else {
        // SAFETY: as above -- the unit is programmed and nothing is routed yet.
        Some(unsafe { iommu::enable_interrupt_remapping(hhdm) })
    };

    iommu::install(device, found, window);
    println!(
        "    iommu window   {bus:02x}:{slot:02x}.{function} {}-bit, {} levels, \
         {reserved} reserved pages mapped, {refused} refused",
        window.width.bits(),
        window.width.levels()
    );

    // The second block device, if there is one, gets a translation of its own
    // under the same unit: its own page table and its own domain id, reached
    // through its own context entry. Sharing the first device's page table
    // would have been one line and would have meant a driver in a domain could
    // reach whatever the kernel's device had mapped -- contained from the
    // kernel's memory and not from the kernel's device, which is not
    // containment.
    if let Some((second, _)) = virtio::find_nth(1) {
        let delegated = (second.bus, second.device, second.function);
        match iommu::attach_device(&window, delegated, 1, hhdm) {
            Some(second_window) => {
                if iommu::verify_window(&second_window, 2, hhdm) {
                    iommu::install(delegated, found, second_window);
                    // The unit is already translating, and it caches context
                    // entries: without this it goes on believing this device
                    // has none, and every request it makes is dropped with the
                    // entry sitting correct in memory.
                    // Hoisted out of the `if` so the unsafe block is the call
                    // and nothing else. The reporting that follows is ordinary
                    // safe code and has no business being counted as unsafe.
                    // SAFETY: the unit these windows are programmed into.
                    let invalidated = unsafe { iommu::invalidate_contexts() };
                    if !invalidated {
                        println!(
                            "\x1b[91m    iommu window   FAILED: the context cache did not invalidate\x1b[0m"
                        );
                    }
                    println!(
                        "    iommu window   {:02x}:{:02x}.{} translating too, its own page table \
                         and domain, {} in use",
                        delegated.0,
                        delegated.1,
                        delegated.2,
                        iommu::windows()
                    );
                } else {
                    println!(
                        "\x1b[91m    iommu window   FAILED: the second device's tables did not read back\x1b[0m"
                    );
                }
            }
            None => println!(
                "\x1b[91m    iommu window   FAILED: no page table for the second device\x1b[0m"
            ),
        }
    }
    match &remapped {
        Some(Ok(())) => println!(
            "    iommu irq      remapping interrupts; compatibility format blocked, \
             every message is a handle this kernel issued"
        ),
        // Not a boot failure, and not quiet either. The machine runs with the
        // risk RFC 0011 named, and the line says so in the same words the
        // opted-out case uses -- because the *state* is what matters to
        // whoever reads it, not how the machine arrived in it.
        Some(Err(reason)) => println!(
            "\x1b[91m    iommu irq      interrupts NOT remapped (RFC 0011's residual risk \
             stands): {reason}\x1b[0m"
        ),
        // Asked for, by `iommu=no-remap-irq`. Says what is still true rather
        // than what is built: a device may raise an MSI it was never
        // programmed to raise.
        None => println!(
            "    iommu irq      interrupts NOT remapped (RFC 0011's residual risk stands); \
             turned off by iommu=no-remap-irq"
        ),
    }
    if let Some(fault) = transition {
        println!(
            "    iommu          a device was mid-DMA when translation came on: {} {:#x} \
             refused, reason {:#04x} (expected, see RFC 0012)",
            if fault.read { "read" } else { "write" },
            fault.address,
            fault.reason
        );
    }
    Some((found, window))
}

fn block_self_test(handoff: &Handoff) -> bool {
    let hhdm = handoff.hhdm_base.as_u64();

    // Every frame the driver will hand the device, mapped as it is allocated
    // and given a `DevAddr` the device is told about instead of the physical
    // address the kernel knows it by. Without a unit the two are equal and
    // this is the path every machine has always taken.
    let capacity = if let Some(device) = virtio::probe().filter(|d| iommu::present_for(*d)) {
        // The kernel's own device, translating through its own window. Named
        // rather than implied: there is a second device now, with a window of
        // its own, and "the window" would have been whichever came first.
        let translate =
            |physical: u64| iommu::map_frame(device, physical, hhdm).map(|a| a.as_u64());
        virtio::init_mapped(hhdm, Some(&translate))
    } else {
        virtio::init(hhdm)
    };
    let capacity = match capacity {
        Ok(capacity) => capacity,
        Err(virtio::BlockError::NotFound) => {
            println!("    virtio-blk     no block device on the bus");
            return true;
        }
        Err(error) => {
            println!("\x1b[91m    virtio-blk     FAILED to bring up: {error:?}\x1b[0m");
            return false;
        }
    };

    // The disk is the ramdisk's own image, and the kernel already has that
    // image as a module. So every sector read here has a known answer, and the
    // test is not "did a read succeed" but "is this the same data by a
    // completely different route" -- bootloader module against PCI, DMA and a
    // virtqueue.
    let expected = handoff.initrd.unwrap_or(&[]);

    let mut first = [0u8; 512];
    let read_first = virtio::read(0, &mut first);
    let first_matches = expected.len() >= 512 && first == expected[..512];

    // From further in, and this is the check that matters: a driver that
    // ignored the sector number entirely would pass every test that only ever
    // read sector zero, and this kernel would then read one sector of a
    // filesystem over and over without noticing.
    const AT: usize = 4;
    let mut later = [0u8; 2048];
    let read_later = virtio::read(AT as u64, &mut later);
    let later_matches =
        expected.len() >= AT * 512 + 2048 && later == expected[AT * 512..AT * 512 + 2048];

    // Reading past the end must be refused rather than clamped: a filesystem
    // that asked for a sector beyond the device and got zeros would read a
    // hole where the error should have been.
    let past_end = virtio::read(capacity, &mut first[..512]);
    // And a length that is not a whole number of sectors.
    let ragged = virtio::read(0, &mut later[..100]);

    let (completed, timeouts) = virtio::statistics();
    let checks = [
        ("the first sector read", read_first.is_ok()),
        (
            "and is byte for byte what the bootloader loaded",
            first_matches,
        ),
        ("four sectors read from further in", read_later.is_ok()),
        (
            "and those are the right four, not sector zero again",
            later_matches,
        ),
        (
            "a read past the end is refused",
            past_end == Err(virtio::BlockError::OutOfRange),
        ),
        (
            "a read that is not a whole number of sectors is refused",
            ragged == Err(virtio::BlockError::TooLarge),
        ),
        ("the device says it is running", virtio::status() == 0x0f),
        (
            // Both bits are what makes DMA possible at all. Asserted as state
            // rather than as an action: firmware sets them too, so this cannot
            // tell whose write it was -- only that the requirement holds.
            "it may reach memory and act as a bus master",
            virtio::command() & 0b110 == 0b110,
        ),
        ("nothing timed out", timeouts == 0),
    ];

    let mut ok = true;
    for (name, passed) in checks {
        if !passed {
            println!(
                "\x1b[91m    virtio-blk     FAILED: {name} ({completed} completed, {timeouts} timed out)\x1b[0m"
            );
            ok = false;
        }
    }

    // `docs/memory.md` §5: a machine with no IOMMU runs in a degraded mode that
    // is *printed at boot*. That line used to be a constant, which meant it
    // said "NO IOMMU" on machines with three of them -- a warning printed

    if ok {
        let (bus, device, function) = virtio::location().unwrap_or((0, 0, 0));
        println!(
            "    virtio-blk     {bus:02x}:{device:02x}.{function} {capacity} sectors \
             ({} KiB), {completed} requests, status {:#04x}",
            capacity * virtio::SECTOR / 1024,
            virtio::status()
        );
    }
    ok
}

/// Brings up device interrupts and points the console's input at the UART.
///
/// Returns whether input works. Everything here is allowed to fail: a machine
/// with no ACPI tables, or with an I/O APIC this kernel cannot reach, still
/// boots and still prints — it simply cannot be typed at, and says so rather
/// than starting a shell that would wait for ever.
fn console_input(handoff: &Handoff) -> bool {
    let hhdm = handoff.hhdm_base.as_u64();

    // SAFETY: bootstrap CPU, once, after the heap exists, with the addresses
    // the bootloader reported.
    let report = match unsafe { irq::init(handoff.rsdp, hhdm) } {
        Ok(report) => report,
        Err(error) => {
            println!("    io apic        none: {error:?}; the console cannot read");
            return false;
        }
    };

    // The vectors the architecture and this kernel fix, registered before
    // anything can allocate one. A collision here is a boot failure rather
    // than a machine that behaves strangely -- which is what five constants in
    // four files could not give (RFC 0011).
    for (vector, owner) in [
        (bhaskix_arch::apic::TIMER_VECTOR, "apic timer"),
        (tlb::SHOOTDOWN_VECTOR, "tlb shootdown ipi"),
        (sched::RESCHEDULE_VECTOR, "reschedule ipi"),
        (bhaskix_arch::apic::ERROR_VECTOR, "apic error"),
        (bhaskix_arch::apic::SPURIOUS_VECTOR, "apic spurious"),
    ] {
        if let Err(error) = vectors::reserve(vector, owner) {
            println!(
                "\x1b[91m    vectors        FAILED: {owner} wants {vector:#04x}: {error:?}\x1b[0m"
            );
            return false;
        }
    }

    // The console claims its own line through `irq::claim`, which allocates a
    // vector rather than being told one. Nothing outside `vectors` chooses a
    // number any more.
    //
    // SAFETY: COM1 was initialised by `init_serial` at the top of boot. From
    // here the line is claimed, a notification is bound to it, and the UART
    // may raise its interrupt.
    let vector = match unsafe { input::install(COM1, handoff.bsp_lapic_id, handoff.rsdp, hhdm) } {
        Ok(vector) => vector,
        Err(reason) => {
            println!("\x1b[91m    console        FAILED to claim the serial line: {reason}\x1b[0m");
            return false;
        }
    };

    // Read the entry back. A write to a memory-mapped register that is never
    // read is a write that may have gone into a cache line, into the wrong
    // register, or nowhere -- and the symptom is a device that raises no
    // interrupts, which looks like a hardware problem for a long time.
    let gsi = irq::isa_to_gsi(handoff.rsdp, hhdm, input::SERIAL_IRQ);
    let entry = irq::redirection(gsi).unwrap_or(0);
    let vector_ok = entry & 0xff == u32::from(vector);
    let unmasked = entry & (1 << 16) == 0;
    if !vector_ok || !unmasked {
        println!(
            "\x1b[91m    io apic        FAILED: entry for gsi {gsi} reads back {entry:#x}\x1b[0m"
        );
        return false;
    }

    let (taken, total) = vectors::usage();
    println!(
        "    io apic        at {:#x}, {} inputs, {} overrides{}; irq {} -> gsi {gsi}, vector {vector:#04x}",
        report.address,
        report.inputs,
        report.overrides,
        if report.chips > 1 {
            " (first of several)"
        } else {
            ""
        },
        input::SERIAL_IRQ,
    );
    println!("    vectors        {taken} of {total} allocatable in use:");
    vectors::for_each(|vector, owner| println!("      {vector:#04x}  {owner}"));
    true
}

/// Checks that console input arrives by interrupt, and that commands run.
///
/// The input half uses the UART's loopback mode: the port is told to feed its
/// own output back to its input, so the kernel can produce an inbound byte on
/// demand. Without it this test would need someone to type, which means it
/// would pass on a developer's terminal and hang in CI — and a test that
/// cannot run in CI is a test that stops being run.
///
/// Nothing is printed while the port is looped back: output written then goes
/// into its own receive buffer instead of to the serial log.
fn shell_self_test() -> bool {
    use bhaskix_arch::SerialPort;

    const TYPED: &[u8] = b"ls /\r";

    let port = SerialPort::new(COM1);
    let (delivered_before, _, _) = irq::statistics();
    let (signals_before, _, _) = notify::statistics();

    // Drain anything already waiting, so what is counted below is what this
    // test produced.
    while input::try_read().is_some() {}

    // SAFETY: COM1 is initialised, and the port is put back below on every
    // path out of this function.
    unsafe { port.set_loopback(true) };
    for byte in TYPED {
        // SAFETY: as above.
        unsafe { port.write_byte(*byte) };
    }

    // Wait for the *interrupt*, not for the bytes. Since RFC 0011 the handler
    // does one thing -- mask the source and signal a notification -- so
    // nothing reaches the ring until a reader drains the UART. Waiting on the
    // ring here would be waiting for work this test has not done yet.
    let arrived = wait_until(|| irq::statistics().0 > delivered_before, 500);
    // SAFETY: as above -- and this must happen before anything is printed.
    unsafe { port.set_loopback(false) };

    // Now do what a reader does: drain the device, *then* acknowledge it. That
    // order is the rule an edge-triggered source makes load-bearing
    // (`docs/driver-model.md` §2).
    let drained = input::service();

    let mut received = [0u8; 8];
    let mut count = 0;
    while let Some(byte) = input::try_read() {
        if count < received.len() {
            received[count] = byte;
        }
        count += 1;
    }

    let (_, dropped, _) = input::statistics();
    let (delivered, strays, unbound) = irq::statistics();
    let (signals, _, _) = notify::statistics();
    let by_interrupt = delivered > delivered_before;
    let signalled = signals > signals_before;

    // The command half. Run through `shell::run`, which is the same function
    // the interactive loop calls -- so this tests the commands rather than a
    // parallel implementation of them.
    let outcomes = [
        (shell::run(b"help"), shell::Outcome::Ran),
        (shell::run(b"   "), shell::Outcome::Empty),
        (shell::run(b"echo hello"), shell::Outcome::Ran),
        (shell::run(b"ls /"), shell::Outcome::Ran),
        (shell::run(b"cat etc/hostname"), shell::Outcome::Ran),
        (shell::run(b"cat ../etc/hostname"), shell::Outcome::Failed),
        (shell::run(b"cat nothing"), shell::Outcome::Failed),
        (shell::run(b"elf bin/probe"), shell::Outcome::Ran),
        (shell::run(b"elf hello.txt"), shell::Outcome::Failed),
        (shell::run(b"mem"), shell::Outcome::Ran),
        (shell::run(b"ps"), shell::Outcome::Ran),
        (shell::run(b"uptime"), shell::Outcome::Ran),
        (shell::run(b"input"), shell::Outcome::Ran),
        (shell::run(b"disk"), shell::Outcome::Ran),
        (shell::run(b"nosuchcommand"), shell::Outcome::Unknown),
    ];
    let commands = outcomes.len();
    let wrong = outcomes
        .iter()
        .filter(|(actual, expected)| actual != expected)
        .count();

    let checks = [
        ("a byte typed at the console arrived", arrived),
        ("it arrived by interrupt rather than by luck", by_interrupt),
        (
            // The delivery path is RFC 0011's, end to end: the handler masked
            // the source and signalled a notification, and RFC 0010's object
            // counted it. A handler that quietly did the work itself would
            // pass every check but this one.
            "the interrupt signalled a notification",
            signalled,
        ),
        (
            "nothing arrived on a vector nobody claimed",
            strays == 0 && unbound == 0,
        ),
        (
            "draining after the wake found the bytes",
            drained == TYPED.len(),
        ),
        (
            "every byte arrived, in order",
            count == TYPED.len() && &received[..count.min(received.len())] == TYPED,
        ),
        ("nothing was dropped", dropped == 0),
        ("every command did what it should", wrong == 0),
    ];

    let mut ok = true;
    for (name, passed) in checks {
        if !passed {
            println!(
                "\x1b[91m    shell          FAILED: {name} ({count} of {} bytes, {} interrupts, {wrong} of {commands} commands wrong)\x1b[0m",
                TYPED.len(),
                delivered - delivered_before
            );
            ok = false;
        }
    }

    if ok {
        println!(
            "    shell          {commands} commands; {count} bytes read back through the interrupt path, \
             {} deliveries signalled a notification",
            delivered - delivered_before
        );
    }
    ok
}

/// Checks that paths resolve to files, and that bad paths do not.
///
/// The interesting half is the refusals. A path layer that resolves what it
/// should is easy to see working; one that also resolves `../..` looks
/// identical until something below it walks a tree.
///
/// Also parses the user program out of the filesystem — without loading it —
/// so that a broken image is reported here, as a filesystem and ELF result,
/// rather than as an unexplained ring 3 failure two tests later.
fn vfs_self_test(handoff: &Handoff) -> bool {
    let Some(_) = handoff.initrd else {
        println!("\x1b[91m    vfs            FAILED: nothing to mount\x1b[0m");
        return false;
    };

    let hostname = vfs::read_all(b"etc/hostname", &mut [0u8; 32]);
    let mut buffer = [0u8; 16];
    let read = vfs::open(b"/etc/hostname").map(|mut file| {
        let count = file.read(&mut buffer);
        (count, file.position(), file.len())
    });

    let program = vfs::open(b"bin/probe");
    let parsed = program.ok().map(|file| elf::parse(file.bytes()));

    let entries = vfs::count(b"");
    let bin = vfs::count(b"bin");

    let checks = [
        ("a file opens and reports its length", hostname == Ok(8)),
        (
            "a read fills the buffer and advances the cursor",
            read == Ok((8, 8, 8)),
        ),
        (
            "a leading slash is accepted and means the same thing",
            vfs::open(b"/hello.txt").is_ok(),
        ),
        (
            "a parent component is refused rather than resolved",
            vfs::open(b"../etc/hostname").err() == Some(vfs::VfsError::BadPath)
                && vfs::open(b"etc/../hello.txt").err() == Some(vfs::VfsError::BadPath),
        ),
        (
            "a name that is not there is not found",
            vfs::open(b"etc/nothing").err() == Some(vfs::VfsError::NotFound),
        ),
        (
            "a directory is not a file",
            vfs::open(b"etc").err() == Some(vfs::VfsError::NotAFile),
        ),
        (
            // Seven programs in /bin: the ring 3 probe, the user-mode shell,
            // both services as programs, the block driver (RFC 0013 steps 3, 4
            // and 6), the filesystem (RFC 0016 step 3), and the supervisor
            // (RFC 0017 question 2). Exact rather than "at least", so adding an
            // eighth without noticing this line is a failure rather than a
            // silently weaker test -- which it has now been, six times, once
            // per program added. It is the cheapest assertion in the
            // repository, and it caught the seventh the same day it was
            // written.
            "a listing shows what is directly under a directory",
            entries >= 3 && bin == 7,
        ),
        (
            "the user program is an ELF the loader accepts",
            matches!(&parsed, Some(Ok(image)) if image.segment_count() == 3),
        ),
    ];

    let mut ok = true;
    for (name, passed) in checks {
        if !passed {
            println!("\x1b[91m    vfs            FAILED: {name}\x1b[0m");
            ok = false;
        }
    }

    if ok {
        // The entry address is printed rather than asserted here. It is
        // asserted where it matters -- the ring 3 test checks that system
        // calls arrive from inside the segment this says the file asked for.
        let entry = match &parsed {
            Some(Ok(image)) => image.entry,
            _ => 0,
        };
        println!(
            "    vfs            {entries} entries in /, {bin} in /bin; bin/probe is ELF64, \
             entry {entry:#x}, 3 segments"
        );
    }
    ok
}

/// Checks that the fast system-call path is programmed as intended.
///
/// Reads the MSRs back rather than trusting the writes. Every one of them is a
/// value the CPU acts on without further checking, and three of them decide
/// what privilege level the machine returns to — a wrong `IA32_STAR` does not
/// fault, it returns to user mode with a stack descriptor that is really code.
///
/// The entry stub itself is not exercised here, because nothing runs in ring 3
/// until M5-04. That is stated in the report rather than implied by a passing
/// line.
fn syscall_self_test(hhdm_base: u64) -> bool {
    use bhaskix_arch::gdt;

    if !bhaskix_arch::syscall::enabled() {
        println!("\x1b[91m    syscall        FAILED: SYSCALL was never enabled\x1b[0m");
        return false;
    }

    // SAFETY: `init` ran on this CPU during early boot.
    let (efer, star, lstar, fmask) = unsafe { bhaskix_arch::syscall::programmed() };

    let stacks = smp::init_syscall_stacks(hhdm_base);
    let expected_star = (u64::from(gdt::KERNEL_DATA) << 48) | (u64::from(gdt::KERNEL_CODE) << 32);

    let checks = [
        ("EFER.SCE is set", efer & 1 == 1),
        (
            "IA32_STAR selects the kernel and user segments",
            star == expected_star,
        ),
        ("IA32_LSTAR points at the entry stub", lstar != 0),
        // The four that matter most: interrupts masked so the window between
        // `swapgs` and the stack switch cannot be interrupted, and AC cleared
        // so SMAP is not defeated for the whole call.
        ("IA32_FMASK clears IF", fmask & (1 << 9) != 0),
        ("IA32_FMASK clears DF", fmask & (1 << 10) != 0),
        ("IA32_FMASK clears AC", fmask & (1 << 18) != 0),
        ("IA32_FMASK clears TF", fmask & (1 << 8) != 0),
        (
            "every online cpu has a syscall stack",
            stacks == bhaskix_arch::percpu::online_count(),
        ),
    ];

    let mut ok = true;
    for (name, passed) in checks {
        if !passed {
            println!("\x1b[91m    syscall        FAILED: {name}\x1b[0m");
            ok = false;
        }
    }

    if ok {
        println!(
            "    syscall        entry armed on {stacks} cpus, star {star:#018x}, fmask {fmask:#x}"
        );
    }
    ok
}

/// Exercises capabilities against the real global arena.
///
/// The host tests cover the rules exhaustively against a local arena; this
/// checks the same properties through the lock, on the real one, which is the
/// only thing that can catch the arena being unreachable or the lock being
/// mis-ranked. It also proves the arena is left clean, so a later milestone
/// starting from a non-empty tree is a visible failure rather than a slow leak.
fn capability_self_test() -> bool {
    use cap::{ObjectKind, ObjectRef, Rights};

    let before = cap::live();

    let outcome = cap::with_arena(|arena| {
        let root = arena
            .insert_root(ObjectRef::new(ObjectKind::Frame, 0xbeef), Rights::ALL, 0)
            .ok()?;

        // A service is handed a narrowed, badged capability -- the shape every
        // grant in this system will take.
        // Narrowed, but still able to pass on and to be revoked: holding a
        // right is not the same as being allowed to delegate it, so those two
        // have to be granted explicitly.
        let service_rights = Rights::READ
            .union(Rights::WRITE)
            .union(Rights::DERIVE)
            .union(Rights::REVOKE);
        let granted = arena.derive(root, service_rights, 0xa11ce).ok()?;
        // Narrower rights, **the same badge**. This used to pass `0xb0b` and
        // assert the new badge survived, which documented badge forgery as a
        // feature: a holder could mint itself an identity and call a service
        // as somebody else. Now a badge can only be set by whoever had none,
        // and delegation means passing on less authority, not a different name.
        let further = arena.derive(granted, Rights::READ, 0xa11ce).ok()?;

        // And the badge rule itself, from the holder's side. Asked with rights
        // the parent *has*, so that only the badge can be what refuses it --
        // widening and re-badging in one call would be refused by whichever
        // check ran first, and the test could not say which.
        let forging_refused = arena
            .derive(granted, Rights::READ, 0xb0b)
            .is_err_and(|error| error == cap::CapError::BadgeNotMonotone);

        // Same badge, wider rights: refused by the rights rule and not the
        // badge one, which is the other half of keeping the two apart.
        let widening_refused = arena
            .derive(granted, Rights::ALL, 0xa11ce)
            .is_err_and(|error| error == cap::CapError::RightsNotMonotone);

        // Two domains, the same index, different authority.
        let mut alice = cap::CSpace::new();
        let mut bob = cap::CSpace::new();
        alice.install(granted).ok()?;
        bob.install(further).ok()?;
        let indices_are_not_authority = alice.get(0) != bob.get(0);

        let badge_survived = arena.badge_of(further) == Some(0xa11ce);

        // Revoking the middle capability must take the one below it and leave
        // the one above untouched -- checked before this call returns.
        let destroyed = arena.revoke(granted).ok()?;
        let transitive = destroyed == 2 && !arena.is_live(granted) && !arena.is_live(further);
        let parent_survived = arena.is_live(root);

        arena.revoke_unchecked(root);

        Some((
            widening_refused && forging_refused,
            indices_are_not_authority,
            badge_survived,
            transitive,
            parent_survived,
        ))
    });

    let after = cap::live();

    let Some((widening_refused, distinct, badge_survived, transitive, parent_survived)) = outcome
    else {
        println!(
            "\x1b[91m    capabilities   FAILED: the arena refused a capability it should have made\x1b[0m"
        );
        return false;
    };

    let checks = [
        (
            "derivation refused to widen rights, and refused to change a badge",
            widening_refused,
        ),
        ("an index means nothing outside its cspace", distinct),
        (
            "a granter's badge survived derivation unchanged",
            badge_survived,
        ),
        ("revocation was transitive and immediate", transitive),
        ("revocation spared the parent", parent_survived),
        ("no capabilities leaked", after == before),
    ];

    let mut ok = true;
    for (name, passed) in checks {
        if !passed {
            println!("\x1b[91m    capabilities   FAILED: {name}\x1b[0m");
            ok = false;
        }
    }

    if ok {
        println!(
            "    capabilities   derive is monotone in rights and in badges, revoke is transitive \
             and immediate; {after} live"
        );
    }
    ok
}

/// Reports the state of the per-CPU fault-path frame reserves.
///
/// Misses are the number worth watching: each one is a fault that had to be
/// refused because its CPU had run dry, which is the failure the reserve
/// exists to make rare. Reporting hits alone would look identical whether the
/// reserve was sized well or barely used.
fn frames_report() {
    let held = frames::held();
    let hits = frames::hits();
    let misses = frames::misses();
    let refilled = frames::refilled();

    println!(
        "    frame reserve  {held} frames held across {} cpus; {hits} faults served, {misses} missed, {refilled} refilled",
        bhaskix_arch::percpu::online_count()
    );
}

/// Reports what the tickless timer avoided, and that it is still arming.
///
/// Both numbers are needed. Skipped interrupts alone would be maximised by a
/// timer that never fires — which is also how every thread stops running — so
/// the count of interrupts actually armed is what distinguishes "idle CPUs
/// stopped ticking" from "the timer is broken".
fn tickless_report() {
    let idles = time::tickless_idles();
    let armed = time::armed();
    let ipis = sched::reschedule_ipis();
    let overflowed = time::overflowed();

    if overflowed > 0 {
        println!(
            "\x1b[93m    tickless       WARNING: {overflowed} timers refused, queue too small\x1b[0m"
        );
    }

    println!(
        "    tickless       {idles} idle interrupts avoided, {armed} armed on demand, {ipis} reschedule ipis"
    );
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
        println!(
            "\x1b[91m    lock order     FAILED: {real} real ordering violations before the probe\x1b[0m"
        );
        return false;
    }
    if detected != 1 {
        println!(
            "\x1b[91m    lock order     FAILED: deliberate inversion produced {detected} reports, expected 1\x1b[0m"
        );
        return false;
    }
    if checked == 0 {
        println!("\x1b[91m    lock order     FAILED: no acquisition was ever rank-checked\x1b[0m");
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
    // Colour via ANSI, which both console sinks now understand: the serial
    // line always did, and `framebuffer::FbConsole` learned the subset this
    // uses so the screen shows colour rather than the escape codes themselves.
    //
    // The name is drawn rather than printed because this is the first thing a
    // person sees, and on a machine that has just been handed control by the
    // firmware it is also the first evidence that the framebuffer, the font
    // blitter and the serial port all work.
    const SUN: &str = "\x1b[93m";
    const NAME: &str = "\x1b[96m";
    const TEXT: &str = "\x1b[97m";
    const DIM: &str = "\x1b[90m";
    const OFF: &str = "\x1b[0m";

    println!();
    println!("{SUN}      ____  _   _    _    ____  _  _____  __{OFF}");
    println!("{SUN}     | __ )| | | |  / \\  / ___|| |/ /_ _| \\ \\/ /{OFF}");
    println!("{SUN}     |  _ \\| |_| | / _ \\ \\___ \\| ' / | |   \\  /{OFF}");
    println!("{SUN}     | |_) |  _  |/ ___ \\ ___) | . \\ | |   /  \\{OFF}");
    println!("{SUN}     |____/|_| |_/_/   \\_\\____/|_|\\_\\___| /_/\\_\\{OFF}");
    println!();
    println!("{NAME}     भास्कर  —  the light-maker{OFF}");
    println!("{TEXT}     An open-source, AI-native, enterprise operating system,{OFF}");
    println!("{TEXT}     built from scratch, from India.{OFF}");
    println!();
    println!("{DIM}     Original author and developer   {OFF}{TEXT}Tarun Kumar Kushwaha{OFF}");
    println!("{DIM}     version {VERSION}  ·  x86_64  ·  Apache-2.0{OFF}");
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
        println!("\x1b[93m    timer          WARNING: hlt returned without a tick\x1b[0m");
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
        println!("\x1b[93m    WARNING: the memory map was truncated by the boot shim.\x1b[0m");
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
const PHASE_TICKLESS: u64 = 4;
const PHASE_DOMAIN: u64 = 5;
const PHASE_IPC: u64 = 6;

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

/// A spinner for the tickless phase, retiring one phase later than [`burner`].
///
/// A separate body rather than a reused one: the two generations must retire
/// at different times, and sharing a body meant the class-phase threads were
/// still spinning during the window that was supposed to measure idle CPUs —
/// which is precisely the thing being measured, so the test quietly compared
/// busy against busy.
extern "C" fn tickless_burner(_argument: u64) -> ! {
    use core::sync::atomic::Ordering;
    loop {
        if PHASE.load(Ordering::Acquire) > PHASE_TICKLESS {
            sched::exit();
        }
        core::hint::spin_loop();
    }
}

/// A spinner for the domain phase.
extern "C" fn domain_burner(id: u64) -> ! {
    use core::sync::atomic::Ordering;
    loop {
        if PHASE.load(Ordering::Acquire) > PHASE_DOMAIN {
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

/// Checks that a domain's CPU share is independent of its thread count.
///
/// `docs/scheduler.md` §3 claims a domain's share is "honoured regardless of
/// how many threads it spawns", and §10 asks for exactly this comparison: one
/// domain with a single thread against another with many, equal weight, and a
/// 1:1 split. Without it, spawning threads is a way to take CPU from other
/// domains — a privilege-escalation strategy that needs no bug.
fn domain_self_test(hhdm_base: u64, cpus: u32) -> bool {
    use core::sync::atomic::Ordering;
    use domain::ResourceEnvelope;
    use sched::SpawnOptions;

    if cpus < 2 {
        println!(
            "\x1b[93m    domains        skipped, needs a cpu that is not running the tests\x1b[0m"
        );
        return true;
    }

    const CPU: u32 = 2;
    let capabilities_before = cap::live();
    let mut ok = true;

    // --- creation, and the capability that names a domain -------------------
    let envelope = ResourceEnvelope::new().cpu_shares(1024).memory_frames(8);
    let (Ok(lonely), Ok(crowded)) = (
        domain::create("lonely", envelope),
        domain::create("crowded", envelope),
    ) else {
        println!("\x1b[91m    domains        FAILED to create domains\x1b[0m");
        return false;
    };

    // --- the envelope refuses, at allocation time ---------------------------
    let within = domain::charge_frames(lonely, 8).is_ok();
    let refused = matches!(
        domain::charge_frames(lonely, 1),
        Err(domain::DomainError::MemoryEnvelopeExceeded { .. })
    );
    domain::release_frames(lonely, 8);

    // --- share divided, not multiplied -------------------------------------
    // One thread in the first domain, three in the second, identical shares.
    // All pinned to one CPU so they genuinely compete.
    let mut ids = [u32::MAX; 4];
    let spawn = |domain_id: domain::DomainId, name, slot: usize| {
        let options = SpawnOptions::new().pinned().in_domain(domain_id.as_u32());
        sched::spawn_on_with(CPU, name, domain_burner, slot as u64, hhdm_base, options)
    };

    match spawn(lonely, "dom-a-0", 0) {
        Ok(id) => {
            ids[0] = id;
            let _ = domain::add_thread(lonely, id);
        }
        Err(error) => {
            println!(
                "\x1b[91m    domains        FAILED to spawn in the first domain: {error:?}\x1b[0m"
            );
            ok = false;
        }
    }
    for (slot, name) in [(1, "dom-b-0"), (2, "dom-b-1"), (3, "dom-b-2")] {
        match spawn(crowded, name, slot) {
            Ok(id) => {
                ids[slot] = id;
                let _ = domain::add_thread(crowded, id);
            }
            Err(error) => {
                println!(
                    "\x1b[91m    domains        FAILED to spawn in the second domain: {error:?}\x1b[0m"
                );
                ok = false;
            }
        }
    }

    // The mechanism, asserted directly. One domain's single thread should hold
    // the whole share; the other's three should hold a third each, so both
    // domains total the same. Checking the weights rather than inferring them
    // from CPU time is deterministic, and it says *which* thread was missed
    // when it fails.
    let weights: [u32; 4] = core::array::from_fn(|i| {
        if ids[i] == u32::MAX {
            0
        } else {
            sched::weight_of(ids[i]).unwrap_or(0)
        }
    });
    let lonely_weight = u64::from(weights[0]);
    let crowded_weight = u64::from(weights[1]) + u64::from(weights[2]) + u64::from(weights[3]);
    let shares_divided = lonely_weight > 0
        && crowded_weight > 0
        && crowded_weight.abs_diff(lonely_weight) * 20 <= lonely_weight;

    let baseline: [u64; 4] = core::array::from_fn(|i| {
        if ids[i] == u32::MAX {
            0
        } else {
            sched::cycles_of(ids[i]).unwrap_or(0)
        }
    });

    wait_millis(1500);

    let used: [u64; 4] = core::array::from_fn(|i| {
        if ids[i] == u32::MAX {
            0
        } else {
            sched::cycles_of(ids[i])
                .unwrap_or(0)
                .saturating_sub(baseline[i])
        }
    });

    let lonely_cycles = used[0];
    let crowded_cycles = used[1] + used[2] + used[3];
    let ratio_tenths = crowded_cycles
        .saturating_mul(10)
        .checked_div(lonely_cycles)
        .unwrap_or(0);

    // Wide, for the reason the class test's band is wide: this is an
    // interpreting emulator on a shared host, and the exact arithmetic is
    // proved by `domain::tests::a_domains_cpu_share_does_not_grow_with_its_
    // thread_count`. What this catches is the failure that band cannot hide --
    // three threads taking three times the CPU of one, which is what a
    // per-thread weight gives and is a 30x ratio away from the floor.
    let share_independent_of_thread_count = (4..=25).contains(&ratio_tenths);

    // --- destruction revokes what the domain granted ------------------------
    PHASE.store(PHASE_DOMAIN + 1, Ordering::Release);

    // Wait for the burners to *go*, not for a duration. Two hundred
    // milliseconds was enough on an idle machine and is not on a loaded one --
    // and the difference matters more since 2026-08-11, because what follows
    // now asks whether the domains ended themselves, which is a question about
    // whether their threads have finished rather than about how long we waited.
    // The bound stays, so a thread that never exits reports rather than hangs.
    let burners_gone = wait_until(
        || {
            sched::threads_in_domain(lonely.as_u32()) == 0
                && sched::threads_in_domain(crowded.as_u32()) == 0
        },
        4_000,
    );

    // **The rule itself, asserted rather than inferred.** These two were made by
    // boot code and nothing has destroyed them, so if they are over it is
    // because their last thread exited -- which is what changed on 2026-08-11
    // and did not apply to a kernel-made domain before it. Read here, ahead of
    // the `over` below, because destroying them would make the two cases
    // indistinguishable and a change that silently did nothing would look
    // exactly like one that worked.
    // Not `Ok(Some(Exited))`, which is what a *program-made* domain shows. A
    // corpse is kept only if somebody can ask about it -- `end` records the
    // reason when there is a parent still live to read it, and drops it
    // otherwise -- so a kernel-made domain ends and is forgotten in the same
    // breath. What is asserted is therefore "no longer live", which combined
    // with nothing here having destroyed them yet is exactly the claim: their
    // last thread ended them.
    // Waited for, not sampled. A thread stops counting towards its domain before
    // the ending it triggers has finished, so reading this the instant the
    // count reaches zero catches the teardown half-done -- which is what the
    // first version of this did, and it reported both that the domains were
    // still live and that capabilities had not come back.
    let ended_themselves = wait_until(
        || {
            !matches!(domain::state_of(lonely), Ok(None))
                && !matches!(domain::state_of(crowded), Ok(None))
        },
        4_000,
    );

    // `destroy` answers false for a domain that has already ended, and since
    // 2026-08-11 the last thread to exit ends it -- so by the time this runs
    // both of these are usually over already and there is nothing for this call
    // to do. What this section claims is that *destruction returns what the
    // domain granted*, and that holds however the domain ended, so the question
    // asked here is "is it over" rather than "did this call end it".
    let over = |id| domain::destroy(id) || !matches!(domain::state_of(id), Ok(None));
    let destroyed = over(lonely) && over(crowded);
    let capabilities_after = cap::live();

    let checks = [
        ("a charge within the envelope succeeded", within),
        ("a charge past the envelope was refused", refused),
        (
            "both domains ran at all",
            lonely_cycles > 0 && crowded_cycles > 0,
        ),
        ("every burner exited", burners_gone),
        (
            "a domain ends when its last thread exits, whoever made it",
            ended_themselves,
        ),
        (
            "both domains are over, and destruction returned their capabilities",
            destroyed,
        ),
        (
            "destruction returned every capability",
            capabilities_after == capabilities_before,
        ),
        ("no domains remain", domain::live() == 0),
    ];

    for (name, passed) in checks {
        if !passed {
            println!("\x1b[91m    domains        FAILED: {name}\x1b[0m");
            ok = false;
        }
    }

    // Reported with its numbers, always. A ratio assertion that fails without
    // saying what it measured sends the reader back to the emulator to find
    // out, which is the slowest possible way to learn one number.
    if !shares_divided {
        println!(
            "\x1b[91m    domains        FAILED: shares not divided -- weights {weights:?}, {lonely_weight} vs {crowded_weight} total\x1b[0m"
        );
        ok = false;
    }

    // Reported, not asserted: the same emulator noise that made the class
    // test's band wide applies here, and the property is already gated above
    // by the weights themselves.
    if !share_independent_of_thread_count {
        println!(
            "    domains        NOTE: measured {}.{}x cpu for 3 threads vs 1 at equal share ({crowded_cycles} vs {lonely_cycles} ticks)",
            ratio_tenths / 10,
            ratio_tenths % 10
        );
    }

    if ok {
        let (created, _) = domain::statistics();
        println!(
            "    domains        {created} created; envelope refuses past its cap; shares divided {lonely_weight} vs {crowded_weight}; measured {}.{}:1",
            ratio_tenths / 10,
            ratio_tenths % 10
        );
    }
    ok
}

/// Checks the scheduling classes: strict priority, weighted fairness,
/// real-time wakeup latency, and admission control.
fn class_self_test(hhdm_base: u64, cpus: u32) -> bool {
    use core::sync::atomic::Ordering;
    use sched::{Policy, RtPolicy, SpawnOptions};

    if cpus < 2 {
        println!(
            "\x1b[93m    sched classes  skipped, needs a cpu that is not running the tests\x1b[0m"
        );
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
            println!(
                "\x1b[91m    sched classes  FAILED to spawn the heavy thread: {error:?}\x1b[0m"
            );
            return false;
        }
    };
    let light_id = match sched::spawn_on_with(CPU, "fair-1x", burner, 1, hhdm_base, light) {
        Ok(id) => id,
        Err(error) => {
            println!(
                "\x1b[91m    sched classes  FAILED to spawn the light thread: {error:?}\x1b[0m"
            );
            return false;
        }
    };
    CLASS_IDS[0].store(u64::from(heavy_id), Ordering::Relaxed);
    CLASS_IDS[1].store(u64::from(light_id), Ordering::Relaxed);

    // Baseline *after* both exist. Spawning the second thread maps a stack and
    // shoots down a TLB entry across every CPU, and the first thread is
    // already running on the target CPU while that happens — so measuring from
    // before the second spawn charges the first for a head start it did not
    // earn, and the measured ratio came out consistently high.
    let heavy_start = sched::cycles_of(heavy_id).unwrap_or(0);
    let light_start = sched::cycles_of(light_id).unwrap_or(0);

    wait_millis(1500);

    let heavy_cycles = sched::cycles_of(heavy_id).unwrap_or(0) - heavy_start;
    let light_cycles = sched::cycles_of(light_id).unwrap_or(0) - light_start;

    // Reported as a ratio in tenths, so "30" reads as 3.0x.
    let ratio_tenths = heavy_cycles
        .saturating_mul(10)
        .checked_div(light_cycles)
        .unwrap_or(0);

    // A wide band, deliberately, and the reason matters more than the number.
    //
    // `docs/scheduler.md` §10 asks for 3:1 within 2%. That is a budget for a
    // quiet machine over a long run. This is a 1.5-second sample inside an
    // interpreting emulator on a shared build host, and repeated runs measured
    // 3.6, 3.6 and 1.9 with no code change between them — the spread is the
    // environment, not the policy.
    //
    // Tightening this band would make the gate a coin toss. The *exact* ratio
    // is proved where it can be: `sched::tests::three_to_one_weights_give_
    // three_to_one_service` runs the real pick-and-charge loop with time as an
    // exact input and requires 3.0x. What this gate is for is catching the
    // failures that band cannot hide — weights ignored entirely (1.0x) or
    // applied backwards (0.3x) — and it is negative-tested against both.
    //
    // The §10 figure stays unmet until it is measured on real hardware, and
    // TRACKER.md says so rather than quoting this looser band as the target.
    if !(15..=60).contains(&ratio_tenths) {
        println!(
            "\x1b[91m    sched classes  FAILED: weight 3:1 gave {}.{}x, outside 1.5-6.0x ({heavy_cycles} vs {light_cycles} ticks)\x1b[0m",
            ratio_tenths / 10,
            ratio_tenths % 10
        );
        ok = false;
    }

    // --- Strict class priority ----------------------------------------------
    // An RT thread on the same CPU must take essentially all of it. That the
    // fair threads starve is the intended behaviour, not a defect.
    // Measured in CPU time, not in loop iterations. A spin counter depends on
    // how fast each thread's loop happens to be and on cache behaviour, and
    // comparing two different threads' counters compares those as much as it
    // compares the scheduler. Cycles are the quantity the claim is about.
    let fair_before =
        sched::cycles_of(heavy_id).unwrap_or(0) + sched::cycles_of(light_id).unwrap_or(0);

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
            println!("\x1b[91m    sched classes  FAILED to spawn the rt thread: {error:?}\x1b[0m");
            return false;
        }
    };

    wait_millis(600);

    let fair_after =
        sched::cycles_of(heavy_id).unwrap_or(0) + sched::cycles_of(light_id).unwrap_or(0);
    let fair_cycles = fair_after.saturating_sub(fair_before);
    let rt_cycles = sched::cycles_of(rt_id).unwrap_or(0);

    if rt_cycles == 0 {
        println!("\x1b[91m    sched classes  FAILED: the real-time thread never ran\x1b[0m");
        ok = false;
    } else if fair_cycles.saturating_mul(2) > rt_cycles {
        // Not zero, and it should not be: the fair threads are outranked, not
        // forbidden, and the CPU still passes through the timer handler and
        // the idle path. What must not happen is them getting a share
        // comparable to the real-time thread's. Two-thirds is a wide margin
        // deliberately -- the property is "strictly preferred", and a tight
        // threshold here would measure the emulator.
        println!(
            "\x1b[91m    sched classes  FAILED: fair threads took {fair_cycles} ticks against the rt thread's {rt_cycles}\x1b[0m"
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
                "\x1b[91m    sched classes  FAILED: over-commit rejected for the wrong reason: {other:?}\x1b[0m"
            );
            ok = false;
            false
        }
        Ok(_) => {
            println!(
                "\x1b[91m    sched classes  FAILED: an over-committed rt thread was admitted\x1b[0m"
            );
            ok = false;
            false
        }
    };

    if ok {
        println!(
            "    sched classes  weight 3:1 measured {}.{}x; rt took {} ticks against fair's {fair_cycles}; over-commit {}",
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
        println!("\x1b[91m    rt latency     FAILED to spawn the probe: {error:?}\x1b[0m");
        return false;
    }

    // Let it reach the gate before the first measurement.
    wait_millis(50);

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
        println!(
            "\x1b[91m    rt latency     FAILED: only {rounds} of {ROUNDS} wakeups completed\x1b[0m"
        );
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
            println!("\x1b[91m    wait queues    FAILED to spawn {name}: {error:?}\x1b[0m");
            return false;
        }
    }

    // Generous, because the budget has to cover the slowest configuration
    // rather than the fastest. A cross-CPU wake waits for the target CPU's
    // next tick, and under UEFI the framebuffer console is slow enough that
    // the ring turns several times slower than it does under BIOS.
    wait_millis(2000);

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
    wait_millis(200);

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
            "\x1b[91m    wait queues    FAILED: a station stalled -- laps {laps:?}, {blocks} sleeps, {wakeups} wakeups, {races} races\x1b[0m"
        );
        ok = false;
    } else if fastest - slowest > 1 {
        println!(
            "\x1b[91m    wait queues    FAILED: ring uneven -- laps {laps:?}, so the token did not visit every station\x1b[0m"
        );
        ok = false;
    }

    if blocks == 0 {
        println!(
            "\x1b[91m    wait queues    FAILED: no thread ever blocked -- the ring spun instead\x1b[0m"
        );
        ok = false;
    }
    if wakeups == 0 {
        println!("\x1b[91m    wait queues    FAILED: no thread was ever woken\x1b[0m");
        ok = false;
    }
    if RING.overflowed() > 0 {
        println!(
            "\x1b[91m    wait queues    FAILED: {} sleepers overflowed the queue\x1b[0m",
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

/// Waits until `done` is true, or `limit_millis` elapses.
///
/// Returns whether the condition was met. Preferred over a fixed wait
/// wherever a test is waiting for *work to finish* rather than for time to
/// pass: a fixed window turns a loaded machine into a failed test, and this
/// project's tests run on a shared build host under an interpreting emulator
/// where cross-CPU work has varied by seventy times between runs.
///
/// The bound is still there, because a test that waits for ever reports
/// nothing at all.
fn wait_until(mut done: impl FnMut() -> bool, limit_millis: u64) -> bool {
    let started = bhaskix_arch::tsc::read();
    let limit = bhaskix_arch::tsc::from_micros(limit_millis.saturating_mul(1_000));
    let mut spins = 0u64;

    loop {
        if done() {
            return true;
        }
        if let Some(limit) = limit
            && bhaskix_arch::tsc::read().saturating_sub(started) > limit
        {
            return false;
        }
        spins += 1;
        if spins > 8_000_000_000 {
            return false;
        }
        core::hint::spin_loop();
    }
}

/// Waits for `millis` milliseconds of real time.
///
/// Wall clock, not ticks, and the change is forced rather than cosmetic. A
/// tickless CPU stops delivering timer interrupts precisely when it has
/// nothing to run — which is exactly the situation a test that waits for
/// "some ticks" is usually waiting through. Counting ticks measured elapsed
/// time only while the tick was periodic, and it stopped being periodic at
/// M4-10.
///
/// The spin bound is kept as well, because the two fail differently: the spin
/// count limits this thread, the clock limits everything else. A thread that
/// is not being scheduled spins zero times, so a spin bound alone never fires.
fn wait_millis(millis: u64) {
    let started = bhaskix_arch::tsc::read();
    let Some(limit) = bhaskix_arch::tsc::from_micros(millis.saturating_mul(1_000)) else {
        // No calibrated clock. Fall back to counting interrupts, which is what
        // this used to do and is better than not waiting at all.
        let deadline = trap::ticks() + millis / 10;
        let mut spins = 0u64;
        while trap::ticks() < deadline && spins < 2_000_000_000 {
            spins += 1;
            core::hint::spin_loop();
        }
        return;
    };

    let mut spins = 0u64;
    while bhaskix_arch::tsc::read().saturating_sub(started) < limit && spins < 4_000_000_000 {
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
        println!("\x1b[93m    migration      skipped, only one cpu online\x1b[0m");
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
            println!("\x1b[91m    migration      FAILED to spawn on cpu 0: {error:?}\x1b[0m");
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
            println!("\x1b[91m    migration      FAILED to place a thread: {error:?}\x1b[0m");
            return false;
        }
    };
    let placed_on = sched::cpu_of(placed);

    wait_millis(800);
    let steals = sched::steals() - steals_before;

    let mut ok = true;

    if steals == 0 {
        println!("\x1b[91m    migration      FAILED: no thread was stolen\x1b[0m");
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
            println!("\x1b[91m    migration      FAILED: migrant {id} never ran\x1b[0m");
            ok = false;
        } else if mask & !1 != 0 {
            moved += 1;
        }
    }

    if moved == 0 {
        println!(
            "\x1b[91m    migration      FAILED: every migrant stayed on cpu 0 ({steals} steals)\x1b[0m"
        );
        ok = false;
    }

    // The counter and the per-thread flags are written together under the
    // same lock, so they cannot legitimately disagree. If they do, one of the
    // two is being updated on a path the other is not.
    if moved > steals {
        println!(
            "\x1b[91m    migration      FAILED: {moved} threads moved but only {steals} steals counted\x1b[0m"
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
            println!("\x1b[91m    threads        FAILED to spawn on cpu {id}: {error:?}\x1b[0m");
            return false;
        }
    }

    let switches_before = sched::switches();
    sched::start();

    // Run for a fixed number of ticks. Every CPU contributes to the counter,
    // so this is shorter in wall-clock terms on a bigger machine -- which is
    // fine, since what is being measured is progress rather than duration.
    wait_millis(600);

    let switches = sched::switches() - switches_before;

    let mut ok = true;
    for id in 0..cpus as usize {
        let count = WORK[id].load(Ordering::Relaxed);
        let observed = OBSERVED_CPU[id].load(Ordering::Relaxed);

        if count == 0 {
            println!("\x1b[91m    threads        FAILED: worker {id} never ran\x1b[0m");
            ok = false;
        } else if observed != id as u64 {
            // The property that distinguishes per-CPU runqueues from a global
            // one: a thread created on CPU n must run on CPU n.
            println!(
                "\x1b[91m    threads        FAILED: worker {id} ran on cpu {observed}, expected {id}\x1b[0m"
            );
            ok = false;
        }
    }

    if switches == 0 {
        println!("\x1b[91m    threads        FAILED: no context switches occurred\x1b[0m");
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
    wait_millis(300);

    ok &= migration_self_test(hhdm_base, cpus);

    // Retire the migration workers before the wait-queue phase. They never
    // sleep, so leaving them spinning would let the ring make progress by
    // being preempted onto rather than by being woken -- which is the one
    // thing that phase is trying to distinguish.
    PHASE.store(PHASE_WAIT, Ordering::Release);
    wait_millis(300);

    ok &= wait_queue_self_test(hhdm_base);

    PHASE.store(PHASE_CLASS, Ordering::Release);
    wait_millis(200);

    ok &= class_self_test(hhdm_base, cpus);
    ok &= rt_latency_self_test(hhdm_base, cpus);

    PHASE.store(PHASE_DOMAIN, Ordering::Release);
    wait_millis(200);
    ok &= domain_self_test(hhdm_base, cpus);
    ok &= shared_memory_self_test(hhdm_base);

    // Retire the class threads: publish, then wake, then let them exit.
    PHASE.store(PHASE_CLASS + 1, Ordering::Release);
    RT_GATE.wake_all();
    wait_millis(300);

    sched::stop_all();

    sched::for_each(|cpu, id, name, state, runs, migrations, class| {
        let moved = if migrations > 0 { " (migrated)" } else { "" };
        println!(
            "      cpu {cpu}  thread {id}  {name:<9} {class:<4} {state:?}  {runs} runs{moved}"
        );
    });

    ok
}
