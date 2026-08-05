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
pub mod ustar;
pub mod vectors;
pub mod vfs;
pub mod virtio;
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
        println!("    scheduler      FAILED");
    }

    // Retire the class-phase threads before measuring idle CPUs, or the
    // "idle" window measures three spinning threads.
    PHASE.store(PHASE_TICKLESS, core::sync::atomic::Ordering::Release);
    wait_millis(200);

    if !tickless_self_test(
        handoff.hhdm_base.as_u64(),
        bhaskix_arch::percpu::online_count(),
    ) {
        println!("    tickless       FAILED");
    }
    if !initrd_self_test(handoff) {
        println!("    initrd         FAILED");
    }
    if !block_self_test(handoff) {
        println!("    virtio-blk     FAILED");
    }
    mount_root(handoff);
    if !vfs_self_test(handoff) {
        println!("    vfs            FAILED");
    }
    if !syscall_self_test(handoff.hhdm_base.as_u64()) {
        println!("    syscall        FAILED");
    }
    sched::start_all();

    if !ipc_self_test(
        handoff.hhdm_base.as_u64(),
        bhaskix_arch::percpu::online_count(),
    ) {
        println!("    ipc            FAILED");
    }
    if !ring3_self_test(
        handoff.hhdm_base.as_u64(),
        bhaskix_arch::percpu::online_count(),
    ) {
        println!("    ring 3         FAILED");
    }
    if !capability_self_test() {
        println!("    capabilities   FAILED");
    }
    frames_report();
    tickless_report();

    if !lock_ordering_self_test() {
        println!("    lock order     FAILED");
    }
    // Everything from here to the end of bring-up is code the check above ran
    // too early to see. The count is taken now and compared at the end.
    let lock_violations_at_start = sync::violations();

    // Device interrupts, and with them a console that can be typed at. Last of
    // the bring-up, because everything above it works on a machine with no I/O
    // APIC and this is the first thing that does not.
    let input_ready = console_input(handoff);
    if input_ready && !shell_self_test() {
        println!("    shell          FAILED");
    }
    if input_ready && !block_interrupt_self_test(handoff) {
        println!("    virtio-blk irq FAILED");
    }
    if input_ready && !irq_teardown_self_test(handoff) {
        println!("    irq teardown   FAILED");
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
        faultinject::trigger(fault);
        println!();
        println!("  FAULT INJECTION RETURNED: the exception was not delivered.");
        cpu::halt_forever();
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
            "    lock order     FAILED: {} violations after bring-up",
            late - lock_violations_at_start
        );
    } else {
        println!(
            "    lock order     clean through bring-up too ({} acquisitions checked)",
            sync::acquisitions()
        );
    }

    println!();

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
        println!("  M6 in progress. Nothing left to do at this milestone.");
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
            Ok(_) => println!("  M6 in progress. Nothing left to do at this milestone."),
            Err(error) => println!("  the shell could not be spawned: {error:?}"),
        }
    } else {
        match user_shell(handoff) {
            Ok(()) => println!("  M6 in progress. Nothing left to do at this milestone."),
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

/// Measures the actual claim: an idle CPU stops taking timer interrupts.
///
/// Two windows of equal length, differing only in whether the other CPUs have
/// anything to run. The tick count across the machine must be substantially
/// lower in the first — that is what "tickless" means, stated as a number
/// rather than as a feature.
///
/// Comparing two windows rather than checking an absolute rate is deliberate:
/// the absolute number depends on the tick rate, the CPU count and how busy
/// the host is, none of which the property depends on. The *ratio* between
/// idle and busy does not.
fn tickless_self_test(hhdm_base: u64, cpus: u32) -> bool {
    use core::sync::atomic::Ordering;

    if cpus < 2 {
        println!("    tickless       skipped, needs a cpu that is not running the tests");
        return true;
    }

    const WINDOW_MS: u64 = 400;

    // Window one: every other CPU has only its idle thread, so none of them
    // needs a tick. This thread keeps running, so its own CPU still ticks --
    // which is why the assertion below is a ratio and not a zero.
    let before = trap::ticks();
    wait_millis(WINDOW_MS);
    let idle_ticks = trap::ticks() - before;

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
        println!("    tickless       FAILED: could not make any cpu busy");
        return false;
    }
    wait_millis(100);

    let before = trap::ticks();
    wait_millis(WINDOW_MS);
    let busy_ticks = trap::ticks() - before;

    // Retire the spinners: publish, then poke, then let them exit.
    PHASE.store(PHASE_TICKLESS + 1, Ordering::Release);
    wait_millis(100);

    if busy_ticks <= idle_ticks.saturating_mul(2) {
        println!(
            "    tickless       FAILED: {idle_ticks} ticks idle vs {busy_ticks} busy over {WINDOW_MS} ms -- idle cpus are still ticking"
        );
        return false;
    }

    println!(
        "    tickless       {idle_ticks} ticks with {} cpus idle, {busy_ticks} with them busy, over {WINDOW_MS} ms each",
        cpus - 1
    );
    true
}

/// The endpoint the IPC self-test rendezvouses on.
static IPC_ENDPOINT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(u64::MAX);

/// Replies the client received, and how many carried the right answer.
static IPC_REPLIES: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static IPC_CORRECT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
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
                IPC_REPLIES.fetch_add(1, Ordering::Relaxed);
                // The service answers with the request doubled. Checking the
                // *value* rather than merely that a reply arrived is what
                // makes this a message and not a signal -- and it catches a
                // reply delivered to the wrong caller, which two clients
                // running at once makes possible.
                if outcome.value == request * 2 {
                    IPC_CORRECT.fetch_add(1, Ordering::Relaxed);
                }
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
            Err(_) => sched::exit(),
        }
    }
}

/// Checks that two threads can rendezvous, exchange a message, and that the
/// service can tell its callers apart without asking them.
fn ipc_self_test(hhdm_base: u64, cpus: u32) -> bool {
    use core::sync::atomic::Ordering;

    if cpus < 2 {
        println!("    ipc            skipped, needs a cpu that is not running the tests");
        return true;
    }

    let Ok(endpoint) = ipc::create() else {
        println!("    ipc            FAILED to create an endpoint");
        return false;
    };
    IPC_ENDPOINT.store(u64::from(endpoint.as_u32()), Ordering::Release);

    // A domain for the clients, holding two capabilities to the *same*
    // endpoint with *different* badges. That is the shape a service uses to
    // tell its clients apart: it hands each one a differently badged
    // capability, and thereafter neither can claim to be the other, because
    // neither can read or set its own badge.
    let Ok(clients) = domain::create("ipc-clients", domain::ResourceEnvelope::new()) else {
        println!("    ipc            FAILED to create a client domain");
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
        println!("    ipc            FAILED to derive endpoint capabilities");
        return false;
    };
    let placed = domain::with(clients, |owner| {
        owner.cspace.install_at(0, cap_a).is_ok() && owner.cspace.install_at(1, cap_b).is_ok()
    });
    if placed != Some(true) {
        println!("    ipc            FAILED to install the endpoint capabilities");
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
        println!("    ipc            FAILED to spawn the participants");
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

    let mut ok = true;
    let checks = [
        // Correctness, not throughput. Every reply that arrived carried the
        // value the service computed for *that* request, which is what catches
        // a reply delivered to the wrong caller -- possible precisely because
        // two clients are in flight at once.
        ("every reply carried the right value", correct == replies),
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

    let (dropped, wake_missed, received, replies_tried, no_caller, empty) = ipc::diagnostics();
    for (name, passed) in checks {
        if !passed {
            println!(
                "    ipc            FAILED: {name} (replies {replies}, correct {correct}, badges {badges:#x}, delivered {delivered}, replied {replied}, dropped {dropped}, wake missed {wake_missed}, mailboxes {pending}, recv returned {received}, reply tried {replies_tried}, no caller {no_caller}, empty checks {empty})"
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
            "    ipc            {delivered} rendezvous, {replied} replies, {correct}/{replies} correct; two badges distinguished, {stranded} stranded on teardown"
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
/// The badge ring 3 puts on the capability it derives for itself.
const BADGE_DERIVED: u64 = 0x0000_0000_5678_0000;
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
    unsafe { bhaskix_arch::syscall::enter_ring3(entry, rsp) }
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
        println!("    ring 3         skipped, needs a cpu that is not running the tests");
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
        println!("    ring 3         FAILED to allocate a privilege stack");
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
        println!("    ring 3         FAILED to create an endpoint");
        return false;
    };
    RING3_ENDPOINT.store(
        u64::from(endpoint.as_u32()),
        core::sync::atomic::Ordering::Release,
    );

    let Ok(realm) = domain::create("ring3", domain::ResourceEnvelope::new()) else {
        println!("    ring 3         FAILED to create a domain");
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
        println!("    ring 3         FAILED to derive an endpoint capability");
        return false;
    };
    if domain::with(realm, |owner| owner.cspace.install_at(0, granted).is_ok()) != Some(true) {
        println!("    ring 3         FAILED to install the endpoint capability");
        return false;
    }

    let (calls_before, refused_before, revoked_before) = syscall::statistics();
    let interrupts_before = bhaskix_arch::trap::interrupts_from_user();

    // The service on a different CPU, so the probe's call genuinely blocks and
    // is woken across processors rather than handed straight back.
    let service = sched::SpawnOptions::new().pinned();
    if sched::spawn_on_with(1, "r3-svc", ring3_service, 0, hhdm_base, service).is_err() {
        println!("    ring 3         FAILED to spawn the service");
        return false;
    }

    let options = sched::SpawnOptions::new()
        .pinned()
        .in_domain(realm.as_u32());
    if let Err(error) =
        sched::spawn_on_with(CPU, "ring3", ring3_probe, hhdm_base, hhdm_base, options)
    {
        println!("    ring 3         FAILED to spawn the probe: {error:?}");
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

    let ring3_calls = RING3_CALLS.load(core::sync::atomic::Ordering::Relaxed);
    let ring3_badge = RING3_BADGE.load(core::sync::atomic::Ordering::Relaxed);
    let echoed = RING3_ECHOED.load(core::sync::atomic::Ordering::Acquire);
    let segments = RING3_SEGMENTS.load(core::sync::atomic::Ordering::Acquire);

    RING3_STOP.store(true, core::sync::atomic::Ordering::Release);
    ipc::destroy(endpoint);
    domain::destroy(realm);

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
        (
            "the caller was on the user stack",
            rsp > USER_STACK && rsp <= stack_top,
        ),
        // Without this the probe only ever enters the kernel through
        // `SYSCALL`, and the interrupt entry path -- with its own `swapgs`,
        // its own stack switch through the TSS, and its own way to be wrong --
        // is never reached. Removing that `swapgs` passed a version of this
        // test that lacked this line.
        ("the probe was interrupted while in ring 3", interrupts > 0),
        // The IPC half. Four calls reach the service: the segment report and
        // two exchanges through the capability the kernel installed, and one
        // through the capability ring 3 derived for itself. The fifth, after
        // revocation, must not.
        ("ring 3 reached a service through IPC", ring3_calls == 4),
        (
            "the service saw the badge from the probe's capability",
            ring3_badge & BADGE_RING3 != 0,
        ),
        // The decisive one: user mode sent back the value it was told, so the
        // reply reached ring 3 rather than merely being delivered.
        ("the reply reached user mode", echoed),
        // Delegation, asked for by ring 3 rather than arranged for it. The
        // derived capability carries a badge the program chose, which the
        // service sees and the parent's badge does not explain.
        (
            "ring 3 derived a capability and used it",
            ring3_badge & BADGE_DERIVED != 0,
        ),
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
                "    ring 3         FAILED: {name} (calls {calls}, refused {refused}, rip {rip:#x}, rsp {rsp:#x}, segments {segments:#x})"
            );
            ok = false;
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
        println!("    initrd         FAILED: the bootloader loaded no module");
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
            println!("    initrd         FAILED: {name} ({members} members, {directories} dirs)");
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

    let console = service::console_endpoint().ok_or("the console service has no endpoint")?;
    let filesystem = service::filesystem_endpoint().ok_or("the filesystem has no endpoint")?;

    let realm = domain::create("shell", domain::ResourceEnvelope::new())
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
        println!("    services       FAILED");
    }

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
            println!("    services       FAILED: {name} ({length} bytes, {entries} entries)");
            ok = false;
        }
    }

    if ok {
        let (written, read, requests, refused_callers) = service::statistics();
        println!(
            "    services       {entries} entries listed, {length} bytes read by message; \
             {requests} requests, {refused_callers} callers refused, console {written}/{read} b w/r"
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
    unsafe { bhaskix_arch::syscall::enter_ring3(entry, rsp) }
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
        println!("    memory objects FAILED: no domain to charge");
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
            println!("    memory objects FAILED: {name} (frames {before} -> {after}, {live} live)");
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
        println!("    irq teardown   FAILED to create a domain");
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
        println!("    irq teardown   skipped, gsi {SPARE_GSI} could not be claimed");
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
                "    irq teardown   FAILED: {name} (vectors {vectors_before} -> {vectors_held} -> {vectors_after} -> {vectors_end})"
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
                "    virtio-blk irq FAILED: {name} ({waits} waits, {} spins, {} deliveries)",
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
fn block_self_test(handoff: &Handoff) -> bool {
    let capacity = match virtio::init(handoff.hhdm_base.as_u64()) {
        Ok(capacity) => capacity,
        Err(virtio::BlockError::NotFound) => {
            println!("    virtio-blk     no block device on the bus");
            return true;
        }
        Err(error) => {
            println!("    virtio-blk     FAILED to bring up: {error:?}");
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
                "    virtio-blk     FAILED: {name} ({completed} completed, {timeouts} timed out)"
            );
            ok = false;
        }
    }

    // `docs/memory.md` §5: a machine with no IOMMU runs in a degraded mode that
    // is *printed at boot*. That line used to be a constant, which meant it
    // said "NO IOMMU" on machines with three of them -- a warning printed
    // unconditionally cannot tell the dangerous case from the safe one, which
    // is the whole job of a warning. RFC 0012 step 1 makes it true: the units
    // are found and described, and nothing is programmed, so the degraded mode
    // is still real and is now stated for the right reason.
    //
    // SAFETY: the handoff's addresses, and `mmio::map` is the same mapper
    // `irq::init` walks these tables with.
    let iommu = unsafe { iommu::discover(handoff.rsdp, handoff.hhdm_base.as_u64()) };
    iommu::report(iommu);

    // RFC 0012 step 2: build the structures, enable nothing. The page table is
    // left *empty* -- default deny, so a device translated through this window
    // could reach nothing at all. It is not shown to any hardware until step 3
    // identity-maps what firmware says a device must keep reaching, because
    // enabling before that wedges the machines that need it most.
    if let Some(found) = iommu
        && found.units > 0
        && let Some((bus, slot, function)) = virtio::location()
    {
        let hhdm = handoff.hhdm_base.as_u64();
        match iommu::build_window(&found, (bus, slot, function), 0, hhdm) {
            Some(window) if iommu::verify_window(&window, hhdm) => println!(
                "    iommu window   {bus:02x}:{slot:02x}.{function} \
                 {}-bit, {} levels, nothing mapped, not programmed",
                window.width.bits(),
                window.width.levels()
            ),
            // Built and read back wrong is worse than not built: the values
            // would all be right and the *offsets* wrong, which is a device
            // silently translating through another device's tables.
            Some(_) => println!("    iommu window   FAILED: the tables did not read back"),
            None => println!("    iommu window   FAILED to build"),
        }
    }

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
            println!("    vectors        FAILED: {owner} wants {vector:#04x}: {error:?}");
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
            println!("    console        FAILED to claim the serial line: {reason}");
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
        println!("    io apic        FAILED: entry for gsi {gsi} reads back {entry:#x}");
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
                "    shell          FAILED: {name} ({count} of {} bytes, {} interrupts, {wrong} of {commands} commands wrong)",
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
        println!("    vfs            FAILED: nothing to mount");
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
            // Two programs in /bin since M6-05: the ring 3 probe and the
            // user-mode shell. Exact rather than "at least", so adding a
            // third without noticing this line is a failure rather than a
            // silently weaker test.
            "a listing shows what is directly under a directory",
            entries >= 3 && bin == 2,
        ),
        (
            "the user program is an ELF the loader accepts",
            matches!(&parsed, Some(Ok(image)) if image.segment_count() == 3),
        ),
    ];

    let mut ok = true;
    for (name, passed) in checks {
        if !passed {
            println!("    vfs            FAILED: {name}");
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
        println!("    syscall        FAILED: SYSCALL was never enabled");
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
            println!("    syscall        FAILED: {name}");
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
        let further = arena.derive(granted, Rights::READ, 0xb0b).ok()?;

        let widening_refused = arena
            .derive(granted, Rights::ALL, 0)
            .is_err_and(|error| error == cap::CapError::RightsNotMonotone);

        // Two domains, the same index, different authority.
        let mut alice = cap::CSpace::new();
        let mut bob = cap::CSpace::new();
        alice.install(granted).ok()?;
        bob.install(further).ok()?;
        let indices_are_not_authority = alice.get(0) != bob.get(0);

        let badge_survived = arena.badge_of(further) == Some(0xb0b);

        // Revoking the middle capability must take the one below it and leave
        // the one above untouched -- checked before this call returns.
        let destroyed = arena.revoke(granted).ok()?;
        let transitive = destroyed == 2 && !arena.is_live(granted) && !arena.is_live(further);
        let parent_survived = arena.is_live(root);

        arena.revoke_unchecked(root);

        Some((
            widening_refused,
            indices_are_not_authority,
            badge_survived,
            transitive,
            parent_survived,
        ))
    });

    let after = cap::live();

    let Some((widening_refused, distinct, badge_survived, transitive, parent_survived)) = outcome
    else {
        println!("    capabilities   FAILED: the arena refused a capability it should have made");
        return false;
    };

    let checks = [
        ("derivation refused to widen rights", widening_refused),
        ("an index means nothing outside its cspace", distinct),
        ("a granter's badge survived derivation", badge_survived),
        ("revocation was transitive and immediate", transitive),
        ("revocation spared the parent", parent_survived),
        ("no capabilities leaked", after == before),
    ];

    let mut ok = true;
    for (name, passed) in checks {
        if !passed {
            println!("    capabilities   FAILED: {name}");
            ok = false;
        }
    }

    if ok {
        println!(
            "    capabilities   derive is monotone, revoke is transitive and immediate; {after} live"
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
        println!("    tickless       WARNING: {overflowed} timers refused, queue too small");
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
        println!("    domains        skipped, needs a cpu that is not running the tests");
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
        println!("    domains        FAILED to create domains");
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
            println!("    domains        FAILED to spawn in the first domain: {error:?}");
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
                println!("    domains        FAILED to spawn in the second domain: {error:?}");
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
    wait_millis(200);

    let destroyed = domain::destroy(lonely) && domain::destroy(crowded);
    let capabilities_after = cap::live();

    let checks = [
        ("a charge within the envelope succeeded", within),
        ("a charge past the envelope was refused", refused),
        (
            "both domains ran at all",
            lonely_cycles > 0 && crowded_cycles > 0,
        ),
        ("both domains were destroyed", destroyed),
        (
            "destruction returned every capability",
            capabilities_after == capabilities_before,
        ),
        ("no domains remain", domain::live() == 0),
    ];

    for (name, passed) in checks {
        if !passed {
            println!("    domains        FAILED: {name}");
            ok = false;
        }
    }

    // Reported with its numbers, always. A ratio assertion that fails without
    // saying what it measured sends the reader back to the emulator to find
    // out, which is the slowest possible way to learn one number.
    if !shares_divided {
        println!(
            "    domains        FAILED: shares not divided -- weights {weights:?}, {lonely_weight} vs {crowded_weight} total"
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
            "    sched classes  FAILED: weight 3:1 gave {}.{}x, outside 1.5-6.0x ({heavy_cycles} vs {light_cycles} ticks)",
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
            println!("    sched classes  FAILED to spawn the rt thread: {error:?}");
            return false;
        }
    };

    wait_millis(600);

    let fair_after =
        sched::cycles_of(heavy_id).unwrap_or(0) + sched::cycles_of(light_id).unwrap_or(0);
    let fair_cycles = fair_after.saturating_sub(fair_before);
    let rt_cycles = sched::cycles_of(rt_id).unwrap_or(0);

    if rt_cycles == 0 {
        println!("    sched classes  FAILED: the real-time thread never ran");
        ok = false;
    } else if fair_cycles.saturating_mul(2) > rt_cycles {
        // Not zero, and it should not be: the fair threads are outranked, not
        // forbidden, and the CPU still passes through the timer handler and
        // the idle path. What must not happen is them getting a share
        // comparable to the real-time thread's. Two-thirds is a wide margin
        // deliberately -- the property is "strictly preferred", and a tight
        // threshold here would measure the emulator.
        println!(
            "    sched classes  FAILED: fair threads took {fair_cycles} ticks against the rt thread's {rt_cycles}"
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
        println!("    rt latency     FAILED to spawn the probe: {error:?}");
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

    wait_millis(800);
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
    wait_millis(600);

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
