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

pub mod ahci;
pub mod cap;
pub mod console;
pub mod domain;
pub mod elf;
pub mod fault;
pub mod faultinject;
pub mod font;
pub mod framebuffer;
pub mod frames;
pub mod heap;
pub mod input;
pub mod iommu;
pub mod ipc;
pub mod irq;
pub mod keyboard;
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
pub mod telemetry;
pub mod time;
pub mod tlb;
pub mod trap;
pub mod vectors;
pub mod virtio;
pub mod vm;
pub mod xhci;

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
    // **The instant this kernel began, before anything else.** The TSC is not
    // zeroed by a warm restart, so without this every "since boot" figure is
    // "since the machine was last powered on" -- which on an emulator is the
    // same thing and on a server is not. Free, and it has to be first or it is
    // measuring from somewhere else.
    time::mark_boot();
    // Serial first, before anything else can go wrong. It is the only sink
    // that works with no framebuffer, no memory manager, and a corrupt heap.
    let serial_present = console::init_serial(COM1);
    // And a second UART if this machine has one, written to as well. RFC 0042
    // step 6: the SR550 reports `serial present` for COM1 -- found, loopback
    // round-tripping -- while nothing reaches its serial-over-LAN, which is a
    // port that is real and that nobody carries.
    let serial_second = console::init_second_serial(bhaskix_arch::serial::COM2);

    let framebuffer_present = match handoff.framebuffer {
        Some(fb) => console::init_framebuffer(fb),
        None => false,
    };

    banner();

    // RFC 0025: this kernel speaks four-level paging, on purpose, and every
    // walk, canonical check and half-split in the tree says so at bit 47. A
    // boot entered with five-level paging live would corrupt addresses
    // silently — so the one register read that can tell runs here, before
    // any paging structure is touched, and refuses with a sentence instead.
    // SAFETY: reading CR4 at CPL 0.
    let cr4 = unsafe { bhaskix_arch::cpu::read_cr4() };
    if bhaskix_arch::cpu::five_level_paging_live(cr4) {
        println!(
            "  FATAL: this machine entered the kernel with five-level paging (CR4.LA57) live, \
             and this kernel's address arithmetic is four-level everywhere. Refusing to run is \
             deliberate -- RFC 0025 -- because running would corrupt addresses with no line of \
             output pointing anywhere."
        );
        loop {
            core::hint::spin_loop();
        }
    }

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

    report_boot_state(handoff, serial_present, serial_second, framebuffer_present);
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
            // SSE, on this CPU. See `cpu::enable_sse`: the ABI requires it,
            // nothing this kernel loaded had ever used it, and the first
            // real Linux binary died on `xorps` three instructions in.
            // SAFETY: init, before anything enters ring 3 here, and the
            // switch path keeps `OSFXSR`'s promise.
            unsafe { cpu::enable_sse() };
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

    // And the other half of the same mechanism: a supervisor writing into a
    // space it is not running in takes no fault, so it must commit the page
    // itself. Three bugs of one shape on 2026-08-20 are why this is a gate.
    if !vm::supervisor_write_self_test(handoff.hhdm_base.as_u64()) {
        println!("\x1b[91m    supervisor write  FAILED\x1b[0m");
    }

    // **The disclosure staged, on every boot.** `shared::create` allocated
    // frames without zeroing them until 2026-08-26, so an object handed to a
    // ring 3 service carried whatever its frames held before. This writes a
    // pattern, frees it, and asks what the next owner sees. It runs here
    // because it needs the heap and nothing else, and the sooner a hygiene
    // failure is said the less of the boot has to be read to find it.
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

    // **After `scheduling_self_test`, and that is not an aesthetic choice.**
    // `shared::set_hhdm` is called from exactly one place in this kernel --
    // inside `shared_memory_self_test`, which that test runs -- so before this
    // point `shared` has no direct map base and cannot touch a frame at all.
    // Placed earlier, this test printed nothing whatsoever: it returned false
    // from a guard, and the caller's own FAILED line was the only evidence.
    // A domain of its own, like every other self-test that needs one: `create`
    // charges the owner's envelope first, and at this point in the boot there
    // is no current domain to charge -- which is why the first version of this
    // printed nothing at all rather than failing.
    match domain::create("hygiene", domain::ResourceEnvelope::new()) {
        Ok(owner) => {
            if !shared::zeroed_self_test(owner) {
                println!("\x1b[91m    memory hygiene FAILED\x1b[0m");
            }
            domain::destroy(owner);
        }
        Err(_) => println!("\x1b[91m    memory hygiene FAILED: no domain to charge\x1b[0m"),
    }

    // Immediately, and before anything measures this machine. A stopped
    // scheduler is not a quiet one: `needs_preemption_tick` reads a stopped
    // queue as "not started yet" — early boot, keep ticking to prove the timer
    // works — so every frozen CPU arms a slice it has nothing to preempt to,
    // forever. The restart used to sit four tests further down, which put the
    // tickless measurement inside the frozen window and had it grading a state
    // the system is never in once it is running.
    sched::start_all();

    // RFC 0026 step 2. After `scheduling_self_test`, not before: that test's
    // domain and shared-memory checks assert an *absolutely* clean slate --
    // `domain::live() == 0`, every object revoked -- and the telemetry
    // keeper and its rings are permanent residents. First placed before it,
    // and both checks went red on the first boot; the assertions are the
    // tests' point, so the plane moved rather than the tests weakening.
    // Only the Sched class is on -- bring-up is the "something" that turns a
    // class on, and nothing else has a producer yet. A failure here is a red
    // line, not a halt: a machine without telemetry boots.
    match telemetry::init(handoff.hhdm_base.as_u64()) {
        Ok(()) => {
            telemetry::enable(bhaskix_telemetry::EventClass::Sched);
            // Step 5's producers: the syscall exits, the rendezvous events
            // and the signals all ride this class — the kernel crossings,
            // which is what makes hop attribution a query over the stream.
            telemetry::enable(bhaskix_telemetry::EventClass::Syscall);
        }
        Err(why) => println!("\x1b[91m    telemetry      FAILED: {why}\x1b[0m"),
    }

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

    // RFC 0043 step 2: what is actually on this bus, and how much of it this
    // kernel could contain if it were asked to.
    //
    // **Reported on every boot including every QEMU boot**, so that the answer
    // for a real machine is not a surprise the first time one is seen. On the
    // emulator every function is drivable; on a Lenovo SR550 most are not, and
    // that difference is the whole of RFC 0043's question.
    // SAFETY: configuration access works by here.
    let survey = unsafe { iommu::survey() };
    if survey.unknown == 0 {
        println!(
            "    dma devices    {} functions: {} drivable, {} bridges, and no endpoint this \
             kernel cannot describe",
            survey.functions, survey.drivable, survey.bridges
        );
    } else {
        println!(
            "\x1b[93m    dma devices    {} functions: {} drivable, {} bridges, and {} endpoint(s) \
             this kernel cannot describe (named above) -- a bus master with no driver has no \
             window, and translation cannot contain what it cannot describe (RFC 0043)\x1b[0m",
            survey.functions, survey.drivable, survey.bridges, survey.unknown
        );
    }

    // RFC 0041 step 2: xHCI controllers, and whether any of them may be
    // driven. **After the IOMMU windows exist**, which is the whole of this
    // call's safety contract: asking earlier would read "untranslated" for a
    // device about to be caged and refuse a controller that should have been
    // driven. Nothing is driven yet either way — this reports, and reporting a
    // controller nobody may touch is the point.
    // SAFETY: called once, here, with configuration access working and the
    // IOMMU settled.
    let xhci_found = unsafe { xhci::discover() };
    xhci::report(&xhci_found);

    // **Faults recorded before any driver here has touched anything.**
    //
    // The windows exist by now and translation is on, but nothing in this
    // kernel drives a device yet -- so a fault at this point belongs to
    // whoever was driving before this kernel did, which on a server is
    // firmware. It gets read and reported here so that it cannot be mistaken
    // for one caused by a driver below, and so that the drivers below start
    // from a clean set of records.
    //
    // Reading clears them, so the two reports are disjoint by construction:
    // anything printed at the end of the boot happened *after* this line.
    if let Some((found, _)) = iommu_state.as_ref() {
        // SAFETY: the unit `iommu_bringup` mapped and programmed.
        unsafe { iommu::report_faults_since(found, handoff.hhdm_base.as_u64(), "before drivers") };
    }

    // RFC 0046 step 2: SATA AHCI controllers, on exactly the same terms and in
    // the same place, because they are the same question about a different bus
    // master. Nothing is driven yet -- bring-up is step 3 -- so this reports
    // which controller exists and which of the two rules refuses it: the
    // programming interface, or the absence of a translation.
    //
    // SAFETY: as above -- once, here, with configuration access working and
    // the IOMMU windows already built.
    let ahci_found = unsafe { ahci::discover() };
    ahci::report(&ahci_found);
    // RFC 0041 step 3: and the one that may be driven, is.
    //
    // Only reached for a controller `discover` answered as drivable, which is
    // the type refusing rather than this line remembering to. `init` asks the
    // same question again on its own account -- two checks of one rule, because
    // the cost of the second is a comparison and the cost of neither is a bus
    // master reading all of memory.
    if xhci_found.drivable().is_some() {
        // SAFETY: called once, here, after the IOMMU windows exist.
        match unsafe { xhci::init(handoff.hhdm_base.as_u64()) } {
            Ok(started) => {
                println!(
                    "    xhci           running, {} slots, {} ports, {}-byte contexts, {} \
                     scratchpad{}, {} frames mapped into its window, usb {:x}.{:x}",
                    started.running.slots,
                    started.running.ports,
                    if started.running.context_size_64 {
                        64
                    } else {
                        32
                    },
                    started.running.scratchpads,
                    if started.running.scratchpads == 1 {
                        ""
                    } else {
                        "s"
                    },
                    started.frames,
                    started.running.version >> 8,
                    (started.running.version >> 4) & 0xf,
                );
                // RFC 0041 step 4. **Both rings, in one sentence**, and the
                // part that carries the claim is the address: a Command
                // Completion Event names the command TRB it is answering, so
                // "answered the no-op at X" says the controller read the ring
                // this driver wrote as well as wrote the ring it reads.
                //
                // Printed as a failure when the answer does not match, because
                // an event that arrived and named something else is a worse
                // state than no event at all -- it means the two sides disagree
                // about where the conversation is happening.
                let answered = &started.answered;
                if answered.matched {
                    println!(
                        "    xhci rings     answered the no-op at {:#x}: {} event{} \
                         ({} completion, {} port, {} transfer, {} unknown), {}, dequeue {}",
                        answered.asked_at,
                        answered.drained.events,
                        if answered.drained.events == 1 {
                            ""
                        } else {
                            "s"
                        },
                        answered.drained.command_completions,
                        answered.drained.port_changes,
                        answered.drained.transfers,
                        answered.drained.unrecognised,
                        match answered.drained.last_completion {
                            Some(code) if code.is_success() => "success",
                            Some(_) => "a failure code",
                            None => "no completion code",
                        },
                        if answered.dequeue_advanced {
                            "advanced"
                        } else {
                            "NOT advanced"
                        },
                    );
                } else {
                    // **What the controller says about itself, on the same
                    // line.** "Not answered" is a symptom with several causes
                    // and no way to tell them apart: a controller that
                    // stopped, one whose memory reads are being refused, and
                    // one that never picked the command ring up at all all
                    // produce exactly this silence. `HSE` is the one that
                    // matters most -- the controller sets it when a read or
                    // write of its own is answered with an error, which is
                    // what a refused DMA looks like from this side.
                    let state = answered.state;
                    println!(
                        "\x1b[91m    xhci rings     the no-op at {:#x} was not answered: \
                         {} event(s) arrived{}, last command {:#x}\x1b[0m",
                        answered.asked_at,
                        answered.drained.events,
                        if answered.arrived {
                            ""
                        } else {
                            " (nothing before the deadline)"
                        },
                        answered.drained.last_command,
                    );
                    println!(
                        "\x1b[91m    xhci rings     controller says: {}, {}, {}, command ring {}\x1b[0m",
                        if state.halted() { "HALTED" } else { "running" },
                        if state.host_system_error() {
                            "HOST SYSTEM ERROR (a read or write of its own was refused)"
                        } else {
                            "no host system error"
                        },
                        if state.host_controller_error() {
                            "HOST CONTROLLER ERROR"
                        } else {
                            "no internal error"
                        },
                        if state.command_ring_running() {
                            "running"
                        } else {
                            "NOT running (it never picked the ring up)"
                        },
                    );
                }
                // RFC 0041 step 5. **The claim is read back from the
                // controller's own memory**, not inferred from a success code:
                // Address Device answering `Success` says the command was
                // accepted, and the device context saying `Addressed` with a
                // nonzero address says the controller did what was asked.
                let attached = &started.attached;
                // **Printed before the outcome, because it belongs to both.**
                // A slot recycled and then addressed and a slot recycled and
                // still refused are different facts, and neither of the two
                // lines below has room to say so without changing text a gate
                // matches on. Silent at zero, so a machine that addressed its
                // device first time reads exactly as it always has.
                if attached.recoveries > 0 {
                    println!(
                        "    xhci recover   the slot was released and taken again {} time(s): \
                         xHCI 1.2 §4.6.5's recovery for a refused addressing, which this driver \
                         did not perform until 2026-08-25",
                        attached.recoveries,
                    );
                }
                if attached.addressed {
                    println!(
                        "    xhci device    port {} at speed {}{}, slot {}, addressed {} \
                         (slot state {}), {} frames",
                        attached.port,
                        attached.speed,
                        if attached.reset { " after a reset" } else { "" },
                        attached.slot,
                        attached.address,
                        xhci::describe_slot_state(attached.state),
                        attached.frames,
                    );
                    // RFC 0041 step 6. The packet size is printed as a pair
                    // because the interesting case is them differing: step 5
                    // had to guess before the device could be asked, and a
                    // full-speed device answering something else is normal.
                    let described = &attached.described;
                    if described.boot_keyboard {
                        println!(
                            "    xhci descrip   {:04x}:{:04x} said {} bytes of device and {} of \
                             configuration; ep0 packet {} (assumed {}); a boot keyboard on \
                             endpoint {} in, context index {}",
                            described.vendor,
                            described.product,
                            described.device_bytes,
                            described.configuration_bytes,
                            described.max_packet_size_0,
                            described.assumed_packet_size,
                            described.endpoint,
                            described.endpoint_index,
                        );
                        // The interval is printed as the descriptor's value
                        // beside the exponent programmed, because the
                        // conversion between them is speed-dependent and has
                        // not been checked against a specification here. Two
                        // numbers a reader can compare beat one they must
                        // trust.
                        if described.configured {
                            println!(
                                "    xhci endpoint  configured, running; packet {}, \
                                 bInterval {} programmed as exponent {} ({} us)",
                                described.endpoint_max_packet_size,
                                described.interval,
                                described.interval_exponent,
                                125u32 << described.interval_exponent,
                            );
                        } else {
                            println!(
                                "\x1b[93m    xhci endpoint  not configured: {} (endpoint state {})\x1b[0m",
                                described.stopped.unwrap_or("no reason recorded"),
                                described.endpoint_state,
                            );
                        }
                    } else {
                        println!(
                            "\x1b[93m    xhci descrip   not read: {}\x1b[0m",
                            described.stopped.unwrap_or("no reason recorded"),
                        );
                    }
                } else {
                    // Yellow and not red: a machine with nothing plugged in is
                    // a correct outcome, and the reason says which it was.
                    println!(
                        "\x1b[93m    xhci device    not addressed on port {} at speed {}{} after {} attempt(s): {} ({}, code {}); portsc {:#010x}\x1b[0m",
                        attached.port,
                        attached.speed,
                        if attached.reset { " after a reset" } else { "" },
                        attached.attempts,
                        attached.stopped.unwrap_or("no reason recorded"),
                        match attached.code {
                            // **The number, always.** This was a match over six
                            // named codes with `_ => "(an unnamed completion
                            // code)"` behind them, and the code an SR550
                            // actually answered Address Device with fell into
                            // that arm -- so the report named neither the
                            // meaning nor the value, and the only way to learn
                            // it was another boot of a live server. The crate
                            // now carries both.
                            Some(code) => code,
                            None => bhaskix_xhci::trb::CompletionCode::Invalid,
                        }
                        .describe(),
                        match attached.code {
                            Some(code) => code.raw(),
                            None => 0,
                        },
                        attached.portsc,
                    );
                }
            }
            Err(error) => {
                println!(
                    "\x1b[91m    xhci           FAILED to bring up: {}\x1b[0m",
                    error.describe()
                );
                // The numbers, where the refusal has them. `describe` is a
                // `&'static str` and cannot format; a reader who is told only
                // that a limit exists has to reboot the machine to learn what
                // it is, which on a server is a question per restart.
                if let xhci::InitError::TooManyScratchpads { wanted, limit } = error {
                    println!(
                        "\x1b[91m    xhci           it asked for {wanted} scratchpad buffers and this driver provides {limit}\x1b[0m"
                    );
                }
            }
        }
    }
    if let Some((found, _)) = iommu_state.as_ref() {
        // A fault here means a device reached for something nobody granted it,
        // during its own bring-up. RFC 0012 calls that the feature.
        //
        // **Every record, and a line when there are none.** This read one
        // record until 2026-08-24 -- the first of however many the unit holds
        // -- and printed nothing at all when it found none. Both halves were
        // wrong in the same way: a silent report is indistinguishable from a
        // report that did not run, and "no fault in slot zero" is not "no
        // fault". That ambiguity cost real time on an xHCI controller whose
        // DMA was going unanswered, where the absence of a fault line was the
        // single most useful fact available and could not be trusted.
        // The xHCI's frames, so a refused address can be classified instead of
        // merely printed. RFC 0049's boot produced a fault naming an address
        // that was explained by looking at a nearby number and getting it
        // wrong; this is the line that makes the comparison rather than
        // inviting one.
        if let Some((low, high)) = xhci::frame_extent() {
            println!(
                "    xhci frames    physical {low:#x}..={high:#x} -- an address refused inside                  this range is a device address confused with a physical one"
            );
        }
        // SAFETY: the unit `iommu_bringup` mapped and programmed.
        unsafe { iommu::report_faults_since(found, handoff.hhdm_base.as_u64(), "during bring-up") };
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
    if !gift_self_test(
        handoff.hhdm_base.as_u64(),
        bhaskix_arch::percpu::online_count(),
    ) {
        println!("\x1b[91m    gift           FAILED\x1b[0m");
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
    // The adapter, before the programs that call it.
    //
    // Not cpu 0, for `start_supervisor`'s reason: ring 3 entry is pinned, and
    // pinning this to the processor the boot thread runs on puts the two in
    // contention. Not the probes' cpu 3 either -- a hosted thread blocks on
    // this program's reply, and putting both on one processor makes every
    // foreign call a context switch rather than a message.
    let adapter_cpu = bhaskix_arch::percpu::online_count().saturating_sub(2);
    if let Err(reason) = start_linux_domain(adapter_cpu, handoff.hhdm_base.as_u64()) {
        println!("    linux domain   not started: {reason}");
    }
    if !personality_self_test(
        handoff.hhdm_base.as_u64(),
        bhaskix_arch::percpu::online_count(),
    ) {
        println!("\x1b[91m    personality    FAILED\x1b[0m");
    }
    if !auxv_self_test(
        handoff.hhdm_base.as_u64(),
        bhaskix_arch::percpu::online_count(),
    ) {
        println!("\x1b[91m    linux stack    FAILED\x1b[0m");
    }
    if !exec_self_test(
        handoff.hhdm_base.as_u64(),
        bhaskix_arch::percpu::online_count(),
    ) {
        println!("\x1b[91m    linux exec     FAILED\x1b[0m");
    }
    if !pipe_self_test(
        handoff.hhdm_base.as_u64(),
        bhaskix_arch::percpu::online_count(),
    ) {
        println!("\x1b[91m    linux pipe     FAILED\x1b[0m");
    }
    if !fork_self_test(
        handoff.hhdm_base.as_u64(),
        bhaskix_arch::percpu::online_count(),
    ) {
        println!("\x1b[91m    linux fork     FAILED\x1b[0m");
    }
    if !wait_self_test(
        handoff.hhdm_base.as_u64(),
        bhaskix_arch::percpu::online_count(),
    ) {
        println!("\x1b[91m    linux wait     FAILED\x1b[0m");
    }
    if !proc_self_test(
        handoff.hhdm_base.as_u64(),
        bhaskix_arch::percpu::online_count(),
    ) {
        println!("\x1b[91m    linux proc     FAILED\x1b[0m");
    }
    if !signal_self_test(
        handoff.hhdm_base.as_u64(),
        bhaskix_arch::percpu::online_count(),
    ) {
        println!("\x1b[91m    linux signal   FAILED\x1b[0m");
    }
    if !memory_self_test(
        handoff.hhdm_base.as_u64(),
        bhaskix_arch::percpu::online_count(),
    ) {
        println!("\x1b[91m    linux memory   FAILED\x1b[0m");
    }
    if !thread_self_test(
        handoff.hhdm_base.as_u64(),
        bhaskix_arch::percpu::online_count(),
    ) {
        println!("\x1b[91m    linux futex    FAILED\x1b[0m");
    }
    if !clone_self_test(
        handoff.hhdm_base.as_u64(),
        bhaskix_arch::percpu::online_count(),
    ) {
        println!("\x1b[91m    linux clone    FAILED\x1b[0m");
    }
    if !corpus_self_test(
        handoff.hhdm_base.as_u64(),
        bhaskix_arch::percpu::online_count(),
        false,
    ) {
        println!("\x1b[91m    go corpus      FAILED\x1b[0m");
    }
    // **RFC 0053: the input grant, proved by its refusal.**
    //
    // The half that can be asserted without anybody typing, and it is the half
    // that matters: a domain nobody granted input to is *refused*, and a domain
    // that was granted it gets an honest "nothing typed" from an empty console
    // rather than a refusal. Whether a shell can actually be typed at needs a
    // lane that types during the corpus, which is its own work -- this proves
    // the authority, not the keyboard.
    {
        let ungranted = domain::create("no-input", domain::ResourceEnvelope::new());
        let granted = domain::create("has-input", domain::ResourceEnvelope::new());
        if let (Ok(ungranted), Ok(granted)) = (ungranted, granted) {
            let refused = !domain::may_read_input(ungranted.as_u32());
            let allowed =
                domain::grant_input(granted).is_ok() && domain::may_read_input(granted.as_u32());
            // And it is one keyboard: a second live domain cannot take it.
            let exclusive = domain::grant_input(ungranted).is_err();
            domain::destroy(granted);
            // Released with the domain, or every later grant is refused for a
            // holder nobody can name.
            let freed = !domain::may_read_input(granted.as_u32());
            domain::destroy(ungranted);
            if refused && allowed && exclusive && freed {
                println!(
                    "    input grant   a domain with no grant may not read the console; one \
                     granted it may, no second domain can take it, and it is released with the \
                     domain"
                );
            } else {
                println!(
                    "\x1b[91m    input grant   FAILED: refused {refused}, allowed {allowed}, \
                     exclusive {exclusive}, freed {freed}\x1b[0m"
                );
            }
        }
    }

    // **The L1 corpus, and the first program here nobody in this project
    // wrote.** RFC 0005's instruction is to trace the binary rather than reason
    // about it, and the Go corpus has been doing that for one program built
    // from a source file in this tree. BusyBox is somebody else's binary,
    // unmodified: what it asks for is not a thing anybody here chose, and the
    // numbers it is refused are the L1 work queue.
    // **This pass is never the interactive one**, and that is a boot-order fact
    // rather than a preference: the console's serial line is not claimed until
    // bring-up is nearly over, so *here* there is no input path at all — no
    // interrupt, no port to drain, nothing a `read` could ever return. An
    // interactive BusyBox started at this point waits for a key that cannot
    // arrive.
    //
    // `busybox=sh` therefore arms [`BUSYBOX_INTERACTIVE`] much later, just
    // before the machine's own shell, and runs the corpus a second time. This
    // was found by measurement: the first version armed it here, the typing
    // lane failed exactly as it had before, and the boot report's own ordering
    // said why — `linux domain` at report line 161 and the serial claim at 181.
    if !corpus_self_test(
        handoff.hhdm_base.as_u64(),
        bhaskix_arch::percpu::online_count(),
        true,
    ) {
        println!("\x1b[91m    busybox        FAILED\x1b[0m");
    }
    personality_boundary_report();
    frames_report();
    tickless_report();
    // Late on purpose: by here the self-tests above have poured real
    // scheduler traffic through the rings, so the counters describe a
    // working boot rather than an idle one.
    telemetry::report();

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
    if !deadline_self_test() {
        println!("\x1b[91m    deadline       FAILED\x1b[0m");
    }
    if !measure_deadlines(handoff, "bring-up") {
        println!("\x1b[91m    timer delay    FAILED\x1b[0m");
    }
    if input_ready {
        // Which notification each signal hit, and what its waiter slot held.
        // `UNWAITED` counts signals that found nobody; with a console and a
        // block device both signalling it cannot say which, and that is the
        // question.
        // **The exit check, reported on every boot and not only on a fault.**
        // A thread that reached ring 3 with somebody else's space loaded is the
        // bug being hunted; waiting for it to fault is waiting for it to land
        // somewhere unmapped, which is luck. This says whether it happened at
        // all.
        let (wrong_space, unchecked) = sched::exit_check_counts();
        let (no_space, no_thread) = sched::switch_gaps();
        // **And the case the check could not see until 2026-08-20**: a thread
        // returning to ring 3 owning no address space at all. The comparison
        // above needs a root to compare against, so a root of zero was skipped
        // *silently* -- and `enter_space(0)` leaving somebody else's `CR3`
        // loaded is exactly how the fault this instrument hunts arrives. Zero
        // is the only correct answer, and the boot test fails on any other.
        let (rootless, rootless_site, rootless_thread) = sched::rootless_exits();
        if wrong_space == 0 && rootless == 0 {
            println!(
                "    address space  every exit to ring 3 held its own space ({unchecked} unchecked, \
                 runqueue busy; {no_space} switches loaded none, {no_thread} found no thread; \
                 none returned to ring 3 owning no space)"
            );
        } else if wrong_space == 0 {
            let where_ = match rootless_site {
                0 => "syscall",
                1 => "interrupt",
                2 => "first entry",
                _ => "serviced fault",
            };
            println!(
                "\x1b[91m    address space  {rootless} exits to ring 3 owned no space at all \
                 (first: t{rootless_thread} leaving {where_})\x1b[0m"
            );
        } else {
            println!(
                "\x1b[91m    address space  {wrong_space} exits to ring 3 held somebody else's \
                 space\x1b[0m"
            );
            sched::replay_exit_checks(|site, thread, loaded| {
                let where_ = match site {
                    0 => "syscall",
                    1 => "interrupt",
                    2 => "first entry",
                    _ => "serviced fault",
                };
                println!("      exit: t{thread} left {where_} with {loaded:#x} loaded");
            });
        }

        // **Where each byte came from, and not just how many.** A total
        // cannot answer the question somebody has when a keyboard seems dead:
        // did anything arrive from it at all? On the SR550 on 2026-08-27 that
        // could not be answered from a boot log — the report said `keyboard
        // i8042 present, irq 1 -> vector 0xfc` and never said whether a key had
        // followed — and the shell command that reads these counters needs a
        // working keyboard to run, which is the thing in doubt. That machine
        // cannot be typed at over serial either: the BMC redirects COM2, which
        // this kernel uses for output only.
        //
        // **Scancodes are reported beside bytes because they are different
        // facts.** A key release and a modifier are scancodes that emit no
        // byte, so `scancodes` moving while `keyboard` stays at zero says the
        // i8042 is delivering and the decoder is swallowing — a different
        // fault from silence, and indistinguishable in a sum.
        let (serial_in, serial_lost, keys_in, keys_lost) = input::per_source();
        let scancodes = keyboard::scancodes();
        println!(
            "    input by src   serial {serial_in} ({serial_lost} dropped); keyboard {keys_in} \
             from {scancodes} i8042 scancodes ({keys_lost} dropped){}",
            if scancodes == 0 {
                " -- nothing typed yet, which is expected: this prints before anyone can"
            } else {
                ""
            }
        );

        let (dirty, which) = futex_wakes_left_dirty();
        if dirty > 0 {
            println!(
                "\x1b[93m    futex wakes    {dirty} of {} notifications still hold bits nobody \
                 took (mask {which:#x}); the next sleeper in those slots takes them as its own \
                 wake\x1b[0m",
                FUTEX_WAKES
            );
        } else {
            println!(
                "    futex wakes    none of {FUTEX_WAKES} notifications was left holding bits \
                 nobody took"
            );
        }
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

    // **The interactive BusyBox, for the lane that types** — RFC 0053's gate.
    //
    // Here and not with the corpus above, because here the console can be read:
    // the line is claimed, its notification exists, and the adapter has been
    // handed the capability to park a hosted reader on it. The domain gets the
    // keyboard, `sh` runs until somebody types `exit`, and the grant goes back
    // with the domain — after which the machine starts its own shell, which is
    // the lane's last assertion and the one that says the keyboard was
    // *borrowed*.
    //
    // Off unless asked, and it has to be: an interactive shell blocks reading,
    // so every ordinary boot would stop here waiting for a key nobody is going
    // to press.
    if input_ready
        && handoff
            .cmdline
            .split_ascii_whitespace()
            .any(|word| word == "busybox=sh")
    {
        BUSYBOX_INTERACTIVE.store(true, core::sync::atomic::Ordering::Release);
        if !corpus_self_test(
            handoff.hhdm_base.as_u64(),
            bhaskix_arch::percpu::online_count(),
            true,
        ) {
            println!("\x1b[91m    busybox        FAILED\x1b[0m");
        }
        BUSYBOX_INTERACTIVE.store(false, core::sync::atomic::Ordering::Release);
        // **Printed here and not with the other personality counters**, which
        // run before the console's line is even claimed and so could only ever
        // report zero for this. A refused park loses a wake and answers
        // `EAGAIN` for a reason that is not the caller's -- at a shell that is
        // a line abandoned mid-word, which looks like a lost byte and is not.
        park_refusals_report();
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
                // A discriminant by hand, because `IpcError` stopped being
                // field-less when RFC 0022 gave refusals a status to carry.
                let code = match error {
                    ipc::IpcError::NoSuchEndpoint => 1,
                    ipc::IpcError::Congested => 2,
                    ipc::IpcError::Exhausted => 3,
                    ipc::IpcError::NoSuchCaller => 4,
                    ipc::IpcError::ServerGone => 5,
                    ipc::IpcError::Refused(_) => 6,
                    // Its own code rather than folded into 1: a service whose
                    // own domain was ended stopped for a different reason than
                    // one whose endpoint went, and this number is read to tell
                    // exactly that apart.
                    ipc::IpcError::CallerDying => 7,
                };
                RING3_RECV_ERROR.store(code, Ordering::Release);
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

    // The pick's own inputs, because a captured hang showed Ready threads
    // with zero runs starving behind a fair runner -- which earliest-
    // virtual-deadline makes impossible unless the deadlines are not what
    // the rule assumes, or preemption is vetoed. Both suspects print here.
    println!("  What the fair pick compares, and what can veto it:");
    sched::for_each_verdict(
        |cpu, id, name, state, deadline, vruntime, held_count, held_locks| {
            if !matches!(state, sched::State::Finished) {
                // The saved hold bookkeeping travels with the thread, and the
                // CPU's steady leaked count is some thread's context — for the
                // running thread it lives in the CPU counters, for the others
                // in these saved fields. A nonzero pair here names the thread
                // that leaked, which names the code path that leaked it.
                println!(
                    "    cpu {cpu}  thread {id}  {name}  {state:?}  deadline {deadline}  vruntime \
                 {vruntime}  saved holds {held_count} mask {held_locks:#x}"
                );
            }
        },
    );
    // Sampled over a second, because one read cannot tell a leak from live
    // traffic: a count *stuck* at the same nonzero for every sample is a
    // guard that will never drop -- the veto is permanent and the leak is
    // the stall -- while a fluctuating count is real work under load, and
    // the stall lives somewhere else. The first captured mask pair (Heap on
    // two CPUs at once, which one global lock cannot be) taught that single
    // reads across CPUs are instants, not a moment.
    for cpu in 0..bhaskix_arch::percpu::online_count() as usize {
        let mut steady = true;
        let first = crate::sync::holds_on(cpu);
        for _ in 0..10 {
            wait_millis(100);
            if crate::sync::holds_on(cpu) != first {
                steady = false;
                break;
            }
        }
        if first != 0 {
            println!(
                "    cpu {cpu} HOLDS {first} lock(s), rank mask {:#x}, {} over ten samples in a \
                 second -- {}",
                crate::sync::held_on(cpu),
                if steady { "STEADY" } else { "fluctuating" },
                if steady {
                    "a guard that will never drop; preemption is vetoed for ever and the leak \
                     is the stall"
                } else {
                    "live lock traffic under load; the stall lives somewhere else"
                },
            );
        }
    }
    // The ledger: a vetoing CPU's recent lock events, oldest first. An
    // acquire (>) with no later release (<) at the same site is the leak,
    // and the site is a file and line.
    for cpu in 0..bhaskix_arch::percpu::online_count() as usize {
        if crate::sync::holds_on(cpu) == 0 {
            continue;
        }
        println!("  cpu {cpu}'s open guards -- held right now, by acquisition site:");
        let now = bhaskix_arch::tsc::read();
        let hertz = bhaskix_arch::tsc::hertz().unwrap_or(0);
        crate::sync::for_each_open_guard(cpu, |at, rank, since| {
            let held_ms = if hertz == 0 {
                0
            } else {
                (u128::from(now.saturating_sub(since)) * 1_000 / u128::from(hertz)) as u64
            };
            println!(
                "    rank {:3}  held {held_ms} ms  {}:{}",
                rank,
                at.file(),
                at.line(),
            );
        });
        println!("  cpu {cpu}'s last lock events, oldest first (> acquire, < release):");
        crate::sync::for_each_lock_event(cpu, |at, rank, acquire, count_after| {
            println!(
                "    {} rank {:3}  count now {}  {}:{}",
                if acquire { ">" } else { "<" },
                rank,
                count_after,
                at.file(),
                at.line(),
            );
        });
    }

    let (shootdowns, timed_out) = crate::tlb::statistics();
    println!(
        "    tlb shootdowns {shootdowns} completed, {timed_out} timed out -- a large timeout \
         count is a CPU not answering IPIs, and each timeout burns tens of milliseconds with \
         the heap held"
    );

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

/// The phase the gift self-test is in. See `gift_self_test`.
static GIFT_PHASE: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
/// The gift endpoint, for the two test threads.
static GIFT_ENDPOINT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(u64::MAX);
/// What the client's calls returned, one nibble per phase (status + 1).
static GIFT_CLIENT_SAW: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// How many messages the service actually received, and how many of its
/// declared slots were filled when it looked.
static GIFT_SERVED: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static GIFT_LANDED: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
/// The lending verdict, one bit per property, for the failure report.
static GIFT_LENDING_BITS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
/// The `Memory` object the client lends in the revocation phase, as its
/// packed identity, or `u64::MAX` while there is none.
static GIFT_OBJECT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(u64::MAX);

/// The service half of `gift_self_test`. Declares when the phase says to,
/// receives, checks its own CSpace, replies.
extern "C" fn gift_service(_argument: u64) -> ! {
    use core::sync::atomic::Ordering;
    let endpoint = ipc::EndpointId::from_u32(GIFT_ENDPOINT.load(Ordering::Acquire) as u32);
    let me = sched::current_thread_id().unwrap_or(0);
    let my_domain = sched::current_domain();

    // One declaration before serving, consumed by phase 2's gift; **not**
    // renewed before phase 3, which is the no-declaration refusal; renewed at
    // slot 6 for phase 4, whose no-GRANT refusal must *restore* it, so that
    // phase 5's gift lands in it without another declaration. The restoration
    // is the property under test there — a declaration eaten by a refused
    // gift would leave every service one failed caller away from deafness.
    sched::set_receive_slot(me, Some((5, endpoint.as_u32())));

    loop {
        let Ok((message, caller)) = ipc::recv(endpoint) else {
            sched::exit()
        };
        GIFT_SERVED.fetch_add(1, Ordering::Relaxed);
        // Which declared slot this phase's gift should have landed in, if any.
        let slot = message.args[0] as usize;
        let landed = my_domain
            .and_then(|domain| domain::with(domain, |owner| owner.cspace.get(slot).is_some()))
            == Some(true);
        if landed {
            GIFT_LANDED.fetch_add(1, Ordering::Relaxed);
        }
        // A caller may ask for the *next* declaration in `args[1]` — how the
        // client scripts which slot each later gift may land in without the
        // service knowing the plot.
        if message.args[1] != 0 {
            sched::set_receive_slot(me, Some((message.args[1] as u32, endpoint.as_u32())));
        }
        let _ = ipc::reply(
            caller,
            ipc::Message {
                method: message.method,
                args: [u64::from(landed), 0, 0, 0],
                badge: 0,
            },
        );
        // The closing call, answered and then obeyed. An exit keyed to a
        // phase flag instead was a race: the flag could be read either side
        // of the closing call's arrival, and one side left it undelivered.
        // Obeying means *lingering*: this thread's exit would end its domain
        // and take the CSpace with it, and the harness still has to look at
        // that CSpace to see the lending end while the service holds its
        // side of it. Phase 92 is the harness saying it has looked.
        if message.method == 99 {
            while GIFT_PHASE.load(Ordering::Acquire) < 92 {
                core::hint::spin_loop();
            }
            sched::exit();
        }
    }
}

/// The client half: stages (or does not), calls, records what came back.
extern "C" fn gift_client(_argument: u64) -> ! {
    use core::sync::atomic::Ordering;
    let endpoint = ipc::EndpointId::from_u32(GIFT_ENDPOINT.load(Ordering::Acquire) as u32);
    let me = sched::current_thread_id().unwrap_or(0);

    let record = |phase: u32, status: u64| {
        GIFT_CLIENT_SAW.fetch_or((status + 1) << (phase * 8), Ordering::Release);
    };
    let stage = |from_slot: u32| {
        sched::stage_gift(
            me,
            sched::StagedGift {
                from_slot,
                rights: cap::Rights::READ.bits(),
                badge: 0,
                endpoint: endpoint.as_u32(),
            },
        );
    };

    // Phase 1: no gift staged. The plain rendezvous must be untouched by any
    // of this machinery — `complete_gift` returning "no gift" has no effect.
    let sanity = ipc::call(endpoint, 0, 1, [5, 0, 0, 0]);
    record(1, u64::from(sanity.is_err()));

    // Phase 2: a gift the client may give (slot 2 holds GRANT), into the
    // service's declared slot 5. The reply's args[0] says whether the service
    // found it there.
    stage(2);
    let gifted = ipc::call(endpoint, 0, 2, [5, 6, 0, 0]);
    let landed = matches!(&gifted, Ok(reply) if reply.args[0] == 1);
    record(2, u64::from(!landed));
    // And the staged gift must be consumed: a second call carries nothing.
    let consumed = sched::take_staged_gift(me, endpoint.as_u32()).is_none();
    record(3, u64::from(!consumed));

    // Phase 3: staged, but the service's declaration was consumed by phase 2
    // and method 2 re-declared at slot 6 — wait: it did. So the *true*
    // no-declaration case needs the declaration spent first. Spend it with a
    // no-GRANT refusal instead — phase 4 first, deliberately out of order:
    // slot 3 holds the same object *without* GRANT, so the derive refuses
    // with InsufficientRights, the call is never delivered, and the
    // declaration is restored.
    stage(3);
    let refused = ipc::call(endpoint, 0, 3, [6, 0, 0, 0]);
    let right_refusal = matches!(
        refused,
        Err(ipc::IpcError::Refused(raw))
            if raw == syscall::Status::InsufficientRights as u32
    );
    record(4, u64::from(!right_refusal));
    // The refused gift is retained (open question 3's draft answer): drop it
    // so it cannot ride a later call of this test.
    let _ = sched::take_staged_gift(me, endpoint.as_u32());

    // Phase 5: the declaration survived the refusal, so this gift lands at
    // slot 6 with no further declaration — the restoration property.
    stage(2);
    let restored = ipc::call(endpoint, 0, 3, [6, 0, 0, 0]);
    let landed = matches!(&restored, Ok(reply) if reply.args[0] == 1);
    record(5, u64::from(!landed));

    // Phase 6: that landing consumed the declaration, so the service now has
    // none — and a gift with nowhere to land refuses the *call*, rather than
    // delivering it bare. The security half of the design: a caller cannot
    // fill a service's slots uninvited, and cannot slip past by arriving
    // while the service is not expecting.
    stage(2);
    let undeclared = ipc::call(endpoint, 0, 3, [7, 0, 0, 0]);
    let right_refusal = matches!(
        undeclared,
        Err(ipc::IpcError::Refused(raw))
            if raw == syscall::Status::SlotUnavailable as u32
    );
    record(6, u64::from(!right_refusal));
    // The refusal restored the gift; drop it, or it rides the closing call —
    // which, with no declaration, would itself be refused and strand the
    // teardown.
    let _ = sched::take_staged_gift(me, endpoint.as_u32());

    // Phase 7: a real lending — a `Memory` object this domain *owns*, gifted
    // away, for the harness to end by killing this domain. The gift is the
    // same mechanism phase 2 proved; what phase 7 stages is the object whose
    // death step 3 is about.
    let lent = sched::current_domain().and_then(|domain| {
        let id = shared::create(domain, bhaskix_mm::FRAME_SIZE).ok()?;
        let root = shared::name(id).ok()?;
        domain::with(domain, |owner| owner.cspace.install_at(4, root).is_ok())
            .filter(|installed| *installed)
            .map(|_| id)
    });
    let mut lent_landed = false;
    if lent.is_some() {
        // Ask the service to declare slot 7, then gift into it.
        let _ = ipc::call(endpoint, 0, 1, [63, 7, 0, 0]);
        stage(4);
        let carried = ipc::call(endpoint, 0, 3, [7, 0, 0, 0]);
        lent_landed = matches!(&carried, Ok(reply) if reply.args[0] == 1);
    }
    record(7, u64::from(!lent_landed));
    GIFT_OBJECT.store(lent.map_or(u64::MAX, |id| id.as_u64()), Ordering::Release);

    // One last plain call, which the service answers and then exits on; only
    // after it returns is the harness told everything has happened.
    let _ = ipc::call(endpoint, 0, 99, [63, 0, 0, 0]);
    GIFT_PHASE.store(90, Ordering::Release);
    // And then this thread *waits to die*. Its exit is the event under test:
    // the last thread leaving ends the domain, and ending the domain is what
    // must end the lending — so the harness first observes the world with
    // the lending alive, then releases this thread, and its exit is the
    // program-dies-holding-a-connection story with nothing staged about it.
    while GIFT_PHASE.load(Ordering::Acquire) < 91 {
        core::hint::spin_loop();
    }
    sched::exit()
}

/// RFC 0022 step 2: a capability crosses in a call, refusals refuse whole,
/// and a refusal restores what it could not use.
fn gift_self_test(hhdm_base: u64, cpus: u32) -> bool {
    use core::sync::atomic::Ordering;

    if cpus < 3 {
        println!("\x1b[93m    gift           skipped, needs cpus for both parties\x1b[0m");
        return true;
    }

    let Ok(endpoint) = ipc::create() else {
        println!("\x1b[91m    gift           FAILED to create an endpoint\x1b[0m");
        return false;
    };
    GIFT_ENDPOINT.store(u64::from(endpoint.as_u32()), Ordering::Release);

    let (Ok(server_side), Ok(client_side)) = (
        domain::create("gift-svc", domain::ResourceEnvelope::new()),
        domain::create("gift-cli", domain::ResourceEnvelope::new()),
    ) else {
        println!("\x1b[91m    gift           FAILED to create the domains\x1b[0m");
        return false;
    };

    // The client's slot 2 holds a giftable object **with** GRANT; slot 3
    // holds the same object **without** it. A notification stands in for the
    // Memory object the real consumer gifts — what is under test is the
    // transfer, and any object kind rides it the same way.
    let Ok(parcel) = crate::notify::create() else {
        println!("\x1b[91m    gift           FAILED to create the parcel\x1b[0m");
        return false;
    };
    let installed = crate::notify::name(parcel).ok().and_then(|root| {
        cap::with_arena(|arena| {
            // Both parcels carry DERIVE, because the transfer *derives* the
            // recipient's copy and the arena checks that right itself. The
            // difference between them is GRANT alone, so the refusal the test
            // watches is the GRANT check and nothing adjacent to it.
            let giftable = cap::Rights::READ
                .union(cap::Rights::DERIVE)
                .union(cap::Rights::GRANT);
            let with_grant = arena.derive(root, giftable, 0).ok()?;
            let without = arena
                .derive(root, cap::Rights::READ.union(cap::Rights::DERIVE), 0)
                .ok()?;
            Some((with_grant, without))
        })
    });
    let Some((with_grant, without)) = installed else {
        println!("\x1b[91m    gift           FAILED to derive the parcels\x1b[0m");
        return false;
    };
    if domain::with(client_side, |owner| {
        owner.cspace.install_at(2, with_grant).is_ok()
            && owner.cspace.install_at(3, without).is_ok()
    }) != Some(true)
    {
        println!("\x1b[91m    gift           FAILED to install the parcels\x1b[0m");
        return false;
    }

    let svc = sched::SpawnOptions::new()
        .pinned()
        .in_domain(server_side.as_u32());
    let cli = sched::SpawnOptions::new()
        .pinned()
        .in_domain(client_side.as_u32());
    if sched::spawn_on_with(1, "gift-svc", gift_service, 0, hhdm_base, svc).is_err()
        || sched::spawn_on_with(2, "gift-cli", gift_client, 0, hhdm_base, cli).is_err()
    {
        println!("\x1b[91m    gift           FAILED to spawn the participants\x1b[0m");
        return false;
    }

    wait_until(|| GIFT_PHASE.load(Ordering::Acquire) >= 90, 8_000);
    wait_millis(100);

    // RFC 0022 step 3: the lender's death ends the lending. The harness
    // stands in for the recipient's address space — it maps the lent object
    // exactly as a ring-3 service would map a gifted ring — and then kills
    // the lending domain. Three things must be true afterwards, each a
    // different half-life the teardown could get wrong: the *mapping* is
    // removed by revocation (freed frames still mapped elsewhere would be
    // pages another domain reads after reuse); the *object* is gone; and the
    // *capability* the service was gifted resolves to nothing, its quota
    // charge released, because a name for a dead object is a slot the
    // service can never use and was still paying for.
    let mut lending_ended = false;
    let identity = GIFT_OBJECT.load(Ordering::Acquire);
    if identity != u64::MAX
        && let Ok(mut space) = vm::AddressSpace::new(hhdm_base)
    {
        let id = shared::MemoryId::from_u64(identity);
        let at = bhaskix_boot::VirtAddr(0x0000_0000_2100_0000);
        let mapped =
            shared::map_into(id, &mut space, at, bhaskix_mm::Protection::ReadWrite).is_ok();
        let held = domain::with(server_side, |owner| owner.cspace.get(7)).flatten();
        let resolves = |slot| cap::with_arena(|arena| arena.lookup(slot).is_some());
        let named_before = held.is_some_and(resolves);
        let unmapped_before = shared::revocations();

        // Release the client; its exit is the last thread leaving, which
        // ends the domain, which must end the lending.
        GIFT_PHASE.store(91, Ordering::Release);
        wait_until(|| !shared::live(id), 4_000);

        let unmapped = shared::revocations() == unmapped_before + 1;
        let object_gone = !shared::live(id);
        // The object's death and the sweep of its names happen in that order
        // under different locks, and `live` flips between them — so a single
        // read here can land in the gap. The claim is that the sweep
        // *happens*, not that no instruction separates it from the destroy;
        // the wait converges at once when it does and times out red when it
        // does not.
        wait_until(|| !held.is_some_and(resolves), 2_000);
        let named_after = held.is_some_and(resolves);
        GIFT_PHASE.store(92, Ordering::Release);
        space.destroy();
        GIFT_LENDING_BITS.store(
            u32::from(mapped)
                | u32::from(named_before) << 1
                | u32::from(unmapped) << 2
                | u32::from(object_gone) << 3
                | u32::from(!named_after) << 4,
            Ordering::Release,
        );
        lending_ended = mapped && named_before && unmapped && object_gone && !named_after;
    }

    let _ = ipc::destroy(endpoint);
    domain::destroy(server_side);
    domain::destroy(client_side);
    crate::notify::destroy(parcel);

    let saw = GIFT_CLIENT_SAW.load(Ordering::Acquire);
    let served = GIFT_SERVED.load(Ordering::Relaxed);
    let landed = GIFT_LANDED.load(Ordering::Relaxed);
    // Every recorded byte must be 1 — the phase ran and its check passed.
    // Phases: 1 sanity, 2 gifted, 3 consumed, 4 no-GRANT refusal,
    // 5 restoration, 6 no-declaration refusal, 7 a memory object lent.
    let ok = (1..=7u32).all(|phase| (saw >> (phase * 8)) & 0xff == 1)
        // The refused calls were never delivered: five delivered calls
        // (phases 1, 2, 5, 7's declare-then-gift pair) plus the closing one —
        // the refusals of phases 4 and 6 must not appear as served messages.
        && served == 6
        && landed == 3
        && lending_ended;
    if ok {
        println!(
            "    gift           a capability crossed in a call, landed only where declared, was \
             consumed by its ride; a giftless call was untouched; no declaration refused the \
             call rather than delivering it bare; no GRANT refused the call whole and restored \
             the declaration it could not use; and the lender's death unmapped, destroyed and \
             unnamed what it had lent"
        );
    } else {
        let bits = GIFT_LENDING_BITS.load(Ordering::Acquire);
        println!(
            "\x1b[91m    gift           FAILED: phases {saw:#x}, served {served}, landed \
             {landed}, lending ended {lending_ended} (bits {bits:#07b})\x1b[0m"
        );
    }
    ok
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

/// The kernel side of a Linux `clone`: a new thread of an existing domain,
/// entering ring 3 at the address its creator chose, on the stack its
/// creator supplied.
///
/// RFC 0005 step 6's missing half. Everything this needs already existed —
/// the domain, its address space, its capabilities — which is the point:
/// the personality creates a thread in a domain the caller already holds,
/// running code the caller already mapped. It conjures nothing.
///
/// The address space is **not** installed here: this thread belongs to a
/// domain whose space is already live, and the scheduler switches to it the
/// same way it does for every other thread of that domain.
pub extern "C" fn cloned_thread(domain: u64) -> ! {
    let id = domain::DomainId::from_u32(domain as u32);
    let Some((entry, stack, tls)) = domain::take_pending_clone(id) else {
        sched::exit()
    };
    // **The child's one argument.** Linux installs `tls` as a segment base
    // and the child finds its arguments on the stack its creator prepared;
    // this personality has no TLS install yet, so the value is delivered in
    // `rdi` instead -- a stated convention, not an accident, and the trigger
    // for changing it is the first hosted runtime that reads `fs:` before it
    // has made a system call. Documented in RFC 0005 step 6's record.
    let argument = tls;
    // **The space this thread runs in is its domain's, already live.** A
    // cloned thread builds nothing: its siblings are running in a page
    // table the domain recorded when its program started, and this thread
    // adopts it. Without this the thread is scheduled with no space of its
    // own, runs on the kernel's table, and faults on its first instruction
    // -- which is exactly what the first boot of this path did, reporting
    // `expects space 0x0` next to a user-mode fetch at the caller's entry.
    let Some(root) = domain::space_root_of(id) else {
        sched::exit()
    };
    if let Some(thread) = sched::current_thread_id() {
        sched::set_space_root(thread, root);
    }
    // SAFETY: the root a sibling of this thread is already running in, and
    // the higher half of every space in this system is the kernel's own --
    // the same promise `enter_space` makes on every switch into a thread
    // that has one. Loaded here rather than left to the next switch because
    // this thread enters ring 3 without going through one.
    unsafe { bhaskix_arch::paging::switch_address_space(root) };
    // The note, as every direct entry into ring 3 must: this thread speaks
    // Linux because its domain does, and the syscall entry reads it.
    telemetry::note_domain(domain as u32);
    // SAFETY: `entry` and `stack` are the *caller's own* addresses in the
    // caller's own space -- a hosted program pointing at memory it does not
    // hold gets a fault in ring 3, which ends the thread, exactly as a
    // native program's bad jump does. Nothing here dereferences either.
    unsafe { bhaskix_arch::syscall::enter_ring3(entry, stack, [argument, 0]) }
}

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
    // **Eight seconds, which is where it started, and it is back because the
    // bug it was hiding is fixed rather than because the number was wrong.**
    //
    // This was raised to 30,000 ms on 2026-08-21 while the arm was failing
    // about one run in four, on the reading that the release was merely late.
    // It was not late: `sched::exit` marked the exiting thread `Finished`
    // *before* releasing the caller, and a `Finished` thread is never scheduled
    // again, so a preemption in that window stranded the caller for ever. With
    // the order corrected the arm passes at the original bound.
    //
    // The **elapsed time is still reported**, because the median is 22 µs and a
    // bound eight seconds above it would hide a regression completely. A number
    // that changes is a better alarm than a gate that starts flaking.
    let waited_from = bhaskix_arch::tsc::read();
    let answered = wait_until(
        || STRANDED.load(core::sync::atomic::Ordering::Acquire) >= 2,
        8_000,
    );
    let release_micros =
        bhaskix_arch::tsc::to_nanos(bhaskix_arch::tsc::read().saturating_sub(waited_from))
            .map_or(0, |nanos| nanos / 1_000);
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
    if !answered || verdict != 2 {
        // What the caller is actually doing, at the moment the wait gave up.
        // `STRANDED` says how far it got -- 1 is "the call has not returned",
        // 2 is the right answer, 3 a wrong refusal, 4 a reply it should never
        // have received -- and the thread's own state says whether it is
        // blocked, runnable, or gone. A wait that only reports "not 2" cannot
        // tell a caller still asleep from one woken with the wrong answer.
        println!("      stranded verdict {verdict}, and the caller is:");
        let mut seen = false;
        sched::for_each(|cpu, id, name, state, _, _, _| {
            if name == "stranded" {
                seen = true;
                println!("      cpu {cpu} thread {id} ({name}) {state:?}");
            }
        });
        if !seen {
            println!("      no thread named 'stranded' is on any runqueue");
        }
        // Which rendezvous step failed, from the counters that already exist.
        // `reply_tried` against `reply_no_caller` says whether the server ever
        // tried to answer and was refused; `wake_missed` says whether somebody
        // was woken who was not asleep; `dropped` says whether a message was
        // handed over and lost.
        let (dropped, wake_missed, recv_returned, reply_tried, reply_no_caller, recv_empty) =
            ipc::diagnostics();
        println!(
            "      ipc: dropped {dropped}, wake missed {wake_missed}, recv returned              {recv_returned}, reply tried {reply_tried}, reply refused {reply_no_caller},              recv empty {recv_empty}"
        );
        // Every change to a reply obligation, oldest first, recorded without
        // printing so that watching does not close the window being watched.
        // A single `println!` inside `exit` made this arm pass eighteen times
        // running, which is why the trail exists at all.
        println!("      reply trail, oldest first:");
        for (kind, cpu, thread, caller) in sched::reply_trail() {
            if kind == 0 {
                continue;
            }
            let what = match kind {
                k if k == sched::reply_trail::SET => "set",
                k if k == sched::reply_trail::TAKEN_BY_REPLY => "taken by reply",
                k if k == sched::reply_trail::TAKEN_BY_EXIT => "taken by exit",
                k if k == sched::reply_trail::EXIT_FOUND_NONE => "exit found none",
                _ => "?",
            };
            let name = sched::describe(thread).map_or("?", |(name, _)| name);
            println!("        cpu {cpu} thread {thread} ({name}) {what} {caller:?}");
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
            "    user fault     a ring 3 fault ended its domain and nothing else, its siblings stopped and its caller was released after {release_micros} us; {live_after} domains live"
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
/// Where the foreigner's report page lands physically, told by the thread
/// that mapped it so the test can read the answers through the direct map.
static FOREIGNER_REPORT_PA: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Where a Tier 0 Go program's stack goes in its own space.
const GO_STACK_AT: u64 = 0x0000_7ffe_0000_0000;
/// How many pages of it. Go's runtime starts on this before it allocates
/// its own; eight is more than `runtime.rt0_go` touches before `mmap`.
const GO_STACK_PAGES: u64 = 8;
/// The corpus program, in the image.
const GO_PROGRAM: &[u8] = b"bin/go-hello";
/// The L1 corpus: a real static BusyBox, in the image.
///
/// **The first program here that nobody in this project wrote.** The Go corpus
/// was built from a source file in `corpus/`; this is somebody else's binary,
/// unmodified, so what it asks for is not a thing this project chose.
const BUSYBOX_PROGRAM: &[u8] = b"bin/busybox";

/// Which corpus program the next `ring3_corpus` thread should load.
///
/// A static rather than an argument because the entry point's signature is
/// `extern "C" fn(u64) -> !` and the `u64` is already the direct map base. Set
/// before the spawn and read once at the top; the two corpus tests run one
/// after the other, never at once.
static CORPUS_PROGRAM: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);

/// Whether the BusyBox corpus should be an **interactive** shell — RFC 0053.
///
/// Set from `busybox=sh` on the command line. Off by default, because an
/// interactive shell blocks reading and an ordinary boot has nobody to type at
/// it: the machine would stop in the middle of its own self-tests.
static BUSYBOX_INTERACTIVE: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// The thread that becomes RFC 0005 step 7's Tier 0 attempt: a **real static
/// Go binary**, loaded by this kernel's own fuzz-hardened ELF loader into a
/// Linux-tagged domain, entered on an initial process image built by
/// `bhaskix-personality` — argv, envp, and the auxiliary vector Go's
/// `runtime.sysargs` reads.
///
/// Whatever it does next is the specification: every system call it makes
/// that this personality does not answer is logged with its number, and that
/// histogram is the work queue RFC 0005 says to build from.
extern "C" fn ring3_go(hhdm_base: u64) -> ! {
    use bhaskix_boot::VirtAddr;
    use bhaskix_mm::{Protection, VirtRange};
    use bhaskix_personality::stack::{Builder, ProcessInfo};
    use vm::AddressSpace;

    let stop = || -> ! { sched::exit() };
    let busybox = CORPUS_PROGRAM.load(core::sync::atomic::Ordering::Acquire) == 1;
    let (program, label) = if busybox {
        (BUSYBOX_PROGRAM, "busybox")
    } else {
        (GO_PROGRAM, "go corpus")
    };
    let Ok(file) = vfs::open(program) else {
        println!("\x1b[93m    {label}      absent from the image\x1b[0m");
        stop()
    };
    let bytes = file.bytes();
    if bytes.is_empty() {
        println!(
            "\x1b[93m    {label}      skipped: the staged file is empty, which means this              machine had no Go toolchain when the image was built\x1b[0m"
        );
        stop()
    }
    let Ok(mut space) = AddressSpace::new(hhdm_base) else {
        stop()
    };
    // The program headers, before the load, because the auxiliary vector
    // must tell the runtime where they are *in its own space*.
    let Ok(parsed) = elf::parse(bytes) else {
        println!("\x1b[91m    {label}      FAILED: the loader refused the binary\x1b[0m");
        stop()
    };
    let entry = parsed.entry;
    // `AT_PHDR` is a **virtual address in the process's own space**, and the
    // loader does not track it -- so it is computed here from the file's own
    // header and the segment that carries it. Go's `runtime.sysargs` walks
    // the headers from this pointer.
    let word_at = |at: usize, width: usize| -> u64 {
        let mut value = [0u8; 8];
        let Some(slice) = bytes.get(at..at + width) else {
            return 0;
        };
        value[..width].copy_from_slice(slice);
        u64::from_le_bytes(value)
    };
    // ELF64 header: e_phoff at 32, e_phentsize at 54, e_phnum at 56.
    let phoff = word_at(32, 8) as usize;
    let phent = word_at(54, 2);
    let phnum = word_at(56, 2);
    let phdr = parsed
        .segments()
        .find(|segment| {
            phoff >= segment.file_offset && phoff < segment.file_offset + segment.file_size
        })
        .map(|segment| segment.address + (phoff - segment.file_offset) as u64)
        .unwrap_or(0);
    if elf::load_into(&parsed, bytes, &mut space, hhdm_base).is_err() {
        println!("\x1b[91m    {label}      FAILED: the segments would not map\x1b[0m");
        stop()
    }
    let Some(stack) = VirtRange::from_pages(VirtAddr(GO_STACK_AT), GO_STACK_PAGES) else {
        stop()
    };
    if space.map_anonymous(stack, Protection::ReadWrite).is_err() {
        stop()
    }
    let top = GO_STACK_AT + GO_STACK_PAGES * 4096;
    let image_at = top - 4096;
    let Some(image_pa) = space.translate(VirtAddr(image_at)) else {
        stop()
    };
    let random = [
        bhaskix_rand::u64().unwrap_or(0x5eed_0000_5eed_0000),
        bhaskix_rand::u64().unwrap_or(0x0dd0_5eed_0dd0_5eed),
    ];
    let mut entropy = [0u8; 16];
    entropy[..8].copy_from_slice(&random[0].to_le_bytes());
    entropy[8..].copy_from_slice(&random[1].to_le_bytes());
    // **The corpus's own name, and for BusyBox a name it answers to.** BusyBox
    // is a multi-call binary: it reads `argv[0]` and runs the applet with that
    // name, so a program handed `go-hello` looks the name up, does not find it,
    // and says so -- which is exactly what it did on the first boot it got this
    // far, and is BusyBox working rather than failing. `echo` is asked for here
    // because its output is unmistakable and it needs nothing from a
    // filesystem.
    //
    // **`sh -c` rather than an interactive `sh`, and the reason is a boundary
    // rather than a shortcoming.** An interactive shell reaches its prompt --
    // `/ #` -- and then cannot read a key: the adapter holds the console with
    // `Rights::WRITE` alone, on purpose, so that *"the adapter cannot take a
    // byte somebody typed at the shell"*. A hosted program reading stdin needs
    // an input authority of its own, which is a decision and not a syscall.
    // `-c` is what can be gated today: it runs, it prints, and it ends.
    let interactive = BUSYBOX_INTERACTIVE.load(core::sync::atomic::Ordering::Acquire);
    let args: &[&[u8]] = match (busybox, interactive) {
        // The lane that types. `sh` with no `-c` reads until end of input.
        (true, true) => &[b"sh"],
        (true, false) => &[b"sh", b"-c", b"echo hi from sh"],
        _ => &[b"go-hello"],
    };
    let env: [&[u8]; 0] = [];
    let builder = Builder::new(
        args,
        &env,
        ProcessInfo {
            entry,
            phdr,
            phent,
            phnum,
            page_size: 4096,
            hwcap: 0,
            random: entropy,
        },
    );
    // SAFETY: a frame this space owns, viewed through the direct map as the
    // page it is -- the same idiom the loader uses to fill a segment.
    let page = unsafe { core::slice::from_raw_parts_mut((hhdm_base + image_pa) as *mut u8, 4096) };
    if builder.build(page, image_at).is_err() {
        stop()
    }
    // SAFETY: the higher half is copied from the running table.
    unsafe { vm::install(space) };
    if let Some(domain) = sched::current_domain() {
        telemetry::note_domain(domain.as_u32());
    }
    // SAFETY: `entry` is inside a user-executable segment the loader
    // accepted and mapped; `image_at` is the `argc` word of the initial
    // image just built, which is where Linux puts a process's `rsp`.
    unsafe { bhaskix_arch::syscall::enter_ring3(entry, image_at, [0, 0]) }
}

/// Puts a Linux probe's domain down and *waits for its threads to be gone*
/// before returning.
///
/// Every probe below spins in ring 3 after it has reported, because a
/// program whose `exit_group` is refused has no way out of its own; the
/// test ends it. `domain::destroy` marks the threads dying and they stop
/// at their next safe point -- but it also releases the address-space slot
/// at once, so a test that returns immediately leaves a ring 3 thread
/// running on a space whose slot the *next* probe's `vm::install` is free
/// to claim. All six probes pin to the same CPU, so the next one starts
/// exactly where the last one has not finished dying.
///
/// That is the shape of the flake this closes: the signal probe reporting
/// `delivered 0` and the clone probe never concluding, in the same boot,
/// with everything green on the next run. The wait is bounded and asks
/// twice, because `sched::threads_in_domain` reports a runqueue it could
/// not lock as empty.
fn retire_probe(realm: domain::DomainId) {
    domain::destroy(realm);
    wait_for_probe_threads(realm);
}

/// Waits, bounded, for a domain to have no threads left on any runqueue.
///
/// Asks twice, because [`sched::threads_in_domain`] counts a runqueue it
/// could not lock as empty: one pass can answer zero for a thread that is
/// merely on a busy CPU, and two passes either side of a wait cannot.
fn wait_for_probe_threads(realm: domain::DomainId) {
    let mut clear = 0;
    for _ in 0..400 {
        if sched::threads_in_domain(realm.as_u32()) == 0 {
            clear += 1;
            if clear == 2 {
                break;
            }
        } else {
            clear = 0;
        }
        wait_millis(5);
    }
}

/// What the adapter's last `open` and `read` answered, out of its own page.
///
/// **Read where the asking happens, not in the boot report.** The first
/// version printed this with the boundary report, which runs with the other
/// Linux self-tests — long before the file probe, because the adapter's
/// directory capability does not exist until the filesystem service does. It
/// printed three zeros every time, which is what a record written after its
/// reader looks like.
fn adapter_file_record() -> (i64, i64, u64) {
    let page = ADAPTER_REPORT.load(core::sync::atomic::Ordering::Acquire);
    if page == u64::MAX {
        return (0, 0, 0);
    }
    // Where `personality::report` says, which since 2026-08-21 is the only
    // place either ring computes it. The arithmetic that used to be spelled
    // out here -- "256 + 1,024 + 24" -- put the scratch *before* the records
    // and sized it at 1,024, and both halves stopped being true when the
    // layout moved the scratch last and widened it. A comment that recomputes
    // a shared constant is a second derivation of exactly the kind that module
    // exists to prevent.
    const FIRST_WORD: usize = bhaskix_personality::report::FILE_AT / 8;
    let object = shared::MemoryId::from_u64(page);
    let mut record = [0u64; 3];
    let mut at = 0usize;
    let taken = shared::drain_into(object, (FIRST_WORD + 3) * 8, &mut |chunk: &[u8]| {
        for word in chunk.as_chunks::<8>().0 {
            if at >= FIRST_WORD + 3 {
                break;
            }
            if at >= FIRST_WORD {
                let mut eight = [0u8; 8];
                eight.copy_from_slice(word);
                record[at - FIRST_WORD] = u64::from_le_bytes(eight);
            }
            at += 1;
        }
        chunk.len()
    });
    if taken.is_none() {
        return (0, 0, 0);
    }
    (record[0] as i64, record[1] as i64, record[2])
}

/// What the personality boundary costs and how wide it is — RFC 0031's
/// interface **I1**, made visible on every boot rather than left in a file.
///
/// Two numbers, and each answers a question that would otherwise be settled
/// by opinion:
///
/// - **How many Linux numbers the nucleus interprets.** RFC 0031 says the
///   nucleus should carry a foreign call's number without understanding it.
///   It understands eighteen. Printing the count is what turns "we should
///   move this" into a figure that can only go down, and the boot gate is a
///   ratchet on it: it may shrink, and a change that grows it fails the
///   build rather than being noticed in review or not at all.
/// - **What a foreign call costs where it currently lives.** Relocating the
///   personality into a domain buys containment and costs one IPC round trip
///   per hosted system call. RFC 0031 requires the number *before* the move,
///   not after — a measurement taken afterwards can only justify what was
///   already done — so this is the in-nucleus placement's figure, taken with
///   the instrument the domain placement will be taken with.
///
/// Prints nothing when no foreign call has been made: a machine that ran no
/// hosted program has no boundary to report on, and a mean over zero samples
/// is a zero pretending to be a measurement.
fn personality_boundary_report() {
    let order = core::sync::atomic::Ordering::Relaxed;
    let answered = syscall::ADAPTER_ANSWERED.load(order);
    let (absent, refused, gave_up, caller_gone) = (
        syscall::ADAPTER_ABSENT.load(order),
        syscall::ADAPTER_REFUSED.load(order),
        syscall::ADAPTER_GAVE_UP.load(order),
        syscall::ADAPTER_CALLER_GONE.load(order),
    );
    let (priced, floor, mean, dropped, interpreted) = syscall::foreign_cost();
    // Nothing foreign happened at all: no hosted program ran on this machine,
    // so there is no boundary to report on.
    //
    // **Not "no sample was priced".** That was the condition until 2026-08-19,
    // and when the first call moved to the adapter every sample went past the
    // outlier cap and the entire report -- including the count of Linux
    // numbers still in the nucleus, which is the number the whole refactor is
    // measured by -- silently disappeared. A report that vanishes when its
    // instrument saturates is worse than one that says it has no samples.
    if answered + absent + priced + dropped == 0 {
        return;
    }
    // Every foreign call is accounted for, and the arithmetic is printed
    // rather than trusted: priced plus dropped plus answered must equal the
    // total. When it did not -- 7 priced out of 212 -- the cause was a
    // return path that was not being priced at all, and a report that only
    // showed the mean would have hidden it behind a plausible number.
    //
    // Three categories now, not four. "Blocks by construction" was a list of
    // Linux numbers in the nucleus deciding what to price, and it went with
    // the last of them at RFC 0032 step 10 -- the calls that block are still
    // excluded from the *adapter's* figure, but by where the round trip ends
    // rather than by the kernel knowing what `futex` means.
    let total = syscall::FOREIGN_CALLS.load(core::sync::atomic::Ordering::Relaxed);
    // Four categories now, not three: a call the adapter answered is priced by
    // `adapter_call` rather than by the nucleus instrument, so it has to be
    // counted here or the arithmetic would report the move itself as a leak.
    let counted = priced + dropped + answered;
    let _ = (refused, gave_up, caller_gone);
    let accounting = if counted == total {
        "all"
    } else {
        "SOME UNCOUNTED:"
    };
    // **A mean over an empty population is not a measurement**, and as of
    // RFC 0032 step 9 the population really is empty on an ordinary boot: the
    // two numbers still read in the nucleus are `futex`, which blocks by
    // construction and is excluded from pricing, and `write`, which a machine
    // may never make. Printing `floor 0 cycles ... mean 0` there would be a
    // confident zero standing for "nothing was priced" -- the same confusion
    // this instrument was built to stop, so it says which it is.
    if priced == 0 {
        println!(
            "    personality    boundary: {interpreted} linux numbers interpreted in the nucleus \
             (RFC 0031 wants 0); no in-nucleus call was priced -- none was made; {accounting} \
             {counted} of {total} accounted ({dropped} preempted, {answered} answered in \
             ring 3)"
        );
    } else {
        println!(
            "    personality    boundary: {interpreted} linux numbers interpreted in the nucleus \
             (RFC 0031 wants 0); floor {floor} cycles over {priced} non-blocking calls, mean \
             {mean}; {accounting} {counted} of {total} accounted ({dropped} preempted, \
             {answered} answered in ring 3)"
        );
    }
    // What the adapter did, from the kernel's own counters rather than from
    // the adapter's word for it -- which is the only kind of evidence
    // available for a program that holds no console, and the better kind.
    //
    // **The last figure is the instrument's own blind spot**, and it is here
    // because without it a refusal cannot be told from a misread teardown.
    // Separating those two depends on `sched::should_die`, which answers "no"
    // when this CPU's runqueue is contended — so a boot with a non-zero count
    // here is a boot in which the refusal above may be an accounting artefact
    // rather than a dead adapter. Printed on every boot, not only on the ones
    // that fail, because a number that appears only beside a failure cannot
    // establish what it looks like when nothing is wrong.
    println!(
        "    linux domain   the adapter in ring 3 answered {answered} foreign calls, and {absent} \
         found none to ask, {refused} were refused by its endpoint, {gave_up} gave up \
         retrying a full queue, and {caller_gone} were for a caller already being killed \
         (last refusal {}); {} times the kernel could not read the runqueue to tell whether a \
         caller was dying",
        syscall::ADAPTER_REFUSAL.load(order),
        crate::sched::DYING_UNKNOWN.load(order)
    );
    // **The cross-placement price, which is what RFC 0031 asked for before
    // the move rather than after.** Two figures, one instrument, one boot: a
    // call the nucleus answers, and the same shape of call answered by a
    // program in ring 3 through an IPC round trip. The difference is what the
    // containment costs, and it is a number a reviewer can argue with instead
    // of an estimate.
    // What the adapter saw, out of the page it writes into. Eight records of
    // four words: the address and length a hosted program asked for, the pages
    // and protection it resolved to, and whether it was a demand or a hint.
    //
    // **This is RFC 0005's own instruction, one layer out**: when moving
    // `mmap` changed what the Go corpus does, no amount of reading the diff
    // said why -- so the adapter traces what it is asked, and the kernel
    // prints it.
    let page = ADAPTER_REPORT.load(core::sync::atomic::Ordering::Acquire);
    if page != u64::MAX {
        let object = shared::MemoryId::from_u64(page);
        let mut records = [[0u64; 4]; 8];
        let mut at = 0usize;
        let taken = shared::drain_into(object, 8 * 32, &mut |chunk: &[u8]| {
            for word in chunk.as_chunks::<8>().0 {
                if at >= 32 {
                    break;
                }
                let mut eight = [0u8; 8];
                eight.copy_from_slice(word);
                records[at / 4][at % 4] = u64::from_le_bytes(eight);
                at += 1;
            }
            chunk.len()
        });
        if taken.is_some() {
            for (index, record) in records.iter().enumerate() {
                if record[1] == 0 {
                    continue;
                }
                println!(
                    "    linux mmap     #{index} addr {:#x} len {:#x} pages {} prot {} {}",
                    record[0],
                    record[1],
                    record[2],
                    record[3] & 0xff,
                    if record[3] & (1 << 8) != 0 {
                        "fixed"
                    } else if record[3] & (1 << 9) != 0 {
                        "hinted"
                    } else {
                        "anywhere"
                    }
                );
            }
        }
    }
    // **What an `execve` did, out of the adapter's own page** — RFC 0033 step
    // 5. Three numbers: the pid, the domain the program was in, and the domain
    // it is in now. The pid is the claim; the two domains are what make it a
    // claim worth checking, because a pid that survived a domain change is one
    // that was never derived from a domain.
    //
    // The other witness is the exec'd program itself, which asks `getpid` in
    // the new domain and prints the answer. The boot test compares the two,
    // and neither can produce the other's number.
    if page != u64::MAX {
        let object = shared::MemoryId::from_u64(page);
        let mut record = [0u64; 3];
        let mut at = 0usize;
        // Past the eight `mmap` records, which is where the adapter puts it.
        // **From the object's beginning, past the `mmap` records *and* the
        // adapter's scratch area.** `drain_into` is named for a sink rather
        // than for consumption: it reads from the start every time, so an
        // offset is walked rather than resumed.
        //
        // The scratch area matters and cost two boots: it began at 256, which
        // is where this record first sat, so every `copy_in` after the exec
        // overwrote it and the kernel printed the tail of a path as a pid. The
        // fix was `personality::report`, which is why no offset is computed
        // here any more -- the "1,280 = 256 + 1,024" this comment used to give
        // was itself out of date by the time anyone read it.
        const EXEC_RECORD_BYTE: usize = bhaskix_personality::report::EXEC_AT;
        const EXEC_RECORD_WORD: usize = EXEC_RECORD_BYTE / 8;
        let taken = shared::drain_into(object, EXEC_RECORD_BYTE + 24, &mut |chunk: &[u8]| {
            for word in chunk.as_chunks::<8>().0 {
                if at >= EXEC_RECORD_WORD + 3 {
                    break;
                }
                if at >= EXEC_RECORD_WORD {
                    let mut eight = [0u8; 8];
                    eight.copy_from_slice(word);
                    record[at - EXEC_RECORD_WORD] = u64::from_le_bytes(eight);
                }
                at += 1;
            }
            chunk.len()
        });
        if taken.is_some() && record[0] != 0 {
            println!(
                "    linux exec     pid {} kept across an exec: domain {} became domain {}",
                record[0], record[1], record[2]
            );
        }
    }

    report_supervised_copy();

    // What the fault path did. Printed whenever anything was handed over,
    // because a fault reaching the personality at all is the claim step 6
    // makes and the only evidence for it.
    let (handed, resumed, crowded) = fault::statistics();
    if handed > 0 {
        println!(
            "    linux fault    {handed} faults handed to the personality in ring 3, {resumed} \
             resumed, {crowded} found no free slot"
        );
        // **And where**, from the adapter's own record. The counts above are
        // the kernel's view of the exchange; these are the addresses the
        // program in ring 3 was told about, and they are the only evidence
        // that exists when a hosted program dies before it can print.
        //
        // **How many entries to believe is the kernel's own count, not a
        // non-zero test.** The first version of this filtered out entries
        // reading as two zero words, and that is wrong twice: a fault in slot
        // 0 at address 0 is a real record it would hide, and -- until
        // `shared::create` was fixed the same day -- an entry nobody had
        // written could hold the previous tenant's bytes and be printed as a
        // fault. It did: two junk entries appeared beside the true one, which
        // is how the unzeroed pages were found. `handed` is exact.
        let log = adapter_fault_log();
        let recorded = (handed as usize).min(log.len());
        if recorded > 0 {
            print!("    linux fault    the adapter logged {recorded}:");
            for (slot, at) in log.iter().take(recorded) {
                print!(" slot {slot} at {at:#x};");
            }
            println!();
        }
    }
    // What the reply that *blocks* did — RFC 0032 step 10. Printed because a
    // boot log is where this project's claims are checked, and "the futex
    // moved to ring 3" is otherwise invisible: a parked thread looks exactly
    // like a thread that was never asked to park.
    let parked = syscall::BLOCKED.load(core::sync::atomic::Ordering::Relaxed);
    if parked > 0 {
        println!(
            "    linux futex    {parked} hosted threads parked on a notification the adapter \
             named, and none in the nucleus"
        );
    }
    // **And every park that did not happen** — RFC 0054. A refused park loses a
    // wake and answers `EAGAIN` for a reason that is not the caller's, which at
    // a shell is a byte missing from a typed line. That is indistinguishable
    // from a driver bug until something counts it, so this counts it.
    let ungranted = syscall::PARK_UNGRANTED.load(core::sync::atomic::Ordering::Relaxed);
    let unnamed = syscall::PARK_UNNAMED.load(core::sync::atomic::Ordering::Relaxed);
    let refused = syscall::PARK_REFUSED.load(core::sync::atomic::Ordering::Relaxed);
    if ungranted + unnamed + refused > 0 {
        println!(
            "\x1b[93m    linux park     {} parks refused: {ungranted} for a domain with no \
             grant, {unnamed} naming an empty slot, {refused} by the notification itself\x1b[0m",
            ungranted + unnamed + refused
        );
    }
    // **What each hosted program was told its pid is** — RFC 0033 step 4, and
    // the claim is one a coincidence cannot satisfy: two programs that ran in
    // *the same domain slot* were given **different** pids. Under the scheme
    // this replaced — `pid = domain + 1` — they could not have been, because
    // the number was a function of the slot. So the line reports the pairs and
    // says how many of them shared a slot, and the boot test demands at least
    // one.
    let (pairs, count) = hosted_pids();
    if count > 0 {
        let mut distinct = true;
        let mut shared_slot = 0;
        for (index, (domain, pid)) in pairs.iter().take(count).enumerate() {
            for (other_domain, other_pid) in pairs.iter().take(index) {
                if other_pid == pid {
                    distinct = false;
                }
                if other_domain == domain {
                    shared_slot += 1;
                }
            }
        }
        print!("    linux pid      ");
        for (domain, pid) in pairs.iter().take(count) {
            print!("pid {pid} in domain {domain}; ");
        }
        println!(
            "{} pids across {count} hosted programs, {shared_slot} of which shared a domain slot",
            if distinct { "distinct" } else { "REUSED" }
        );
    }
    let (adapter_priced, adapter_floor, adapter_mean) = syscall::adapter_cost();
    if adapter_priced > 0 {
        if floor > 0 {
            println!(
                "    linux domain   the boundary priced in both placements: nucleus floor \
                 {floor} cycles, adapter floor {adapter_floor} over {adapter_priced} round \
                 trips (mean {adapter_mean}) -- what the containment costs"
            );
        } else {
            // **The other placement no longer exists to be measured**, which
            // is the point of RFC 0032 rather than a gap in the instrument.
            // Printing `nucleus floor 0` would read as a free nucleus, so the
            // half that has no sample this boot says so, and the comparison
            // is left to the figure recorded when there was one: 4,916
            // cycles, RFC 0032 step 3's table.
            println!(
                "    linux domain   the boundary priced in ring 3: adapter floor \
                 {adapter_floor} cycles over {adapter_priced} round trips (mean \
                 {adapter_mean}); no nucleus sample -- nothing is answered there to compare"
            );
        }
    }
}

/// RFC 0005 step 7: run a real static Go binary and say what it asked for.
///
/// The RFC is explicit that **the surface is defined by tracing the actual
/// binary**, not by reading a syscall table — so this test's deliverable is
/// the *histogram*: every system call the Go runtime made, in order, with
/// the ones this personality could not answer named. Whether the program
/// reaches `main` is the headline; what it asked for on the way is the work
/// queue.
/// Hands the adapter slot 24: the console's own notification — RFC 0054 step 3.
///
/// # Why this is a function of its own, called late
///
/// The adapter is started before the Linux self-tests, because they are its
/// first callers, and the console's serial line is claimed near the end of
/// bring-up. So there is no notification to name when its other slots are
/// filled, and a grant attempted there silently installs nothing: the park
/// falls through to `EAGAIN` and a hosted shell exits on an empty console. That
/// is not hypothetical — it is what the first version of this did, and the
/// typing lane failed identically to before with nothing in the report to say
/// why.
///
/// # What is conferred, and what is not
///
/// **`READ`, where the futex pool is `WRITE`.** There the adapter wakes
/// sleepers and must never become one; here it parks hosted threads on a
/// notification the *hardware* signals, and `WRITE` would let it invent a
/// keystroke — waking a reader that finds nothing and parks again. Waiting is
/// the whole authority: taking the byte is still `POLL_INPUT` on the domain,
/// which the nucleus refuses without the input grant, and `syscall::may_park_on`
/// refuses the park itself on the same terms.
///
/// # Errors
///
/// A string naming what would not be built. Survivable: without it a hosted
/// `read` answers `EAGAIN` exactly as it did before RFC 0054.
///
/// Returns the slot it went in, so the boot report can name it.
/// What the reply that *parks* refused, and why — RFC 0054.
fn park_refusals_report() {
    use core::sync::atomic::Ordering::Relaxed;
    let ungranted = syscall::PARK_UNGRANTED.load(Relaxed);
    let unnamed = syscall::PARK_UNNAMED.load(Relaxed);
    let refused = syscall::PARK_REFUSED.load(Relaxed);
    let parked = syscall::BLOCKED.load(Relaxed);
    if ungranted + unnamed + refused == 0 {
        println!("    input park     {parked} parked on the console, none refused");
        return;
    }
    println!(
        "\x1b[93m    input park     {parked} parked, {} refused: {ungranted} for a domain with \
         no grant, {unnamed} naming an empty slot, {refused} by the notification itself -- a \
         refusal loses a wake and answers EAGAIN\x1b[0m",
        ungranted + unnamed + refused
    );
}

fn grant_console_wake() -> Result<usize, &'static str> {
    /// The slot it goes in, and the assertion that nothing else may have it.
    ///
    /// **A comment would not have caught the bug this replaces.** The slot was
    /// 22, chosen by reading the fixed grants `start_linux_domain` makes and
    /// stopping there — which missed the root directory, granted from a
    /// different place entirely. It overwrote it, and a hosted `open` answered
    /// `-ENOENT` for a directory that no longer existed. The full suite found
    /// it; nothing else would have.
    const CONSOLE_WAKE_SLOT: usize = 24;
    const _: () = assert!(
        CONSOLE_WAKE_SLOT < syscall::ADAPTER_SLOT_FLOOR,
        "the console wake must sit below the floor hosted-domain handles are \
         allocated from, or the allocator will hand this slot out"
    );

    let adapter = syscall::ADAPTER_DOMAIN.load(core::sync::atomic::Ordering::Acquire);
    if adapter == u32::MAX {
        // No adapter on this boot. Nothing to grant to, and not a failure.
        return Ok(CONSOLE_WAKE_SLOT);
    }
    let Some(console_input) = input::notification() else {
        return Err("the console has no notification to name");
    };
    let named = crate::notify::name(console_input)
        .ok()
        .and_then(|root| cap::with_arena(|arena| arena.derive(root, cap::Rights::READ, 1).ok()))
        .ok_or("the console's notification would not be named")?;
    let realm = domain::DomainId::from_u32(adapter);
    if domain::with(realm, |owner| {
        owner.cspace.install_at(CONSOLE_WAKE_SLOT, named).is_ok()
    }) != Some(true)
    {
        return Err("it would not install in the adapter's slot 24");
    }
    Ok(CONSOLE_WAKE_SLOT)
}

fn corpus_self_test(hhdm_base: u64, cpus: u32, busybox: bool) -> bool {
    // Which program the loader thread should open. Set before the spawn and
    // read once at the top of it; the two corpus runs are sequential.
    CORPUS_PROGRAM.store(u8::from(busybox), core::sync::atomic::Ordering::Release);
    let label = if busybox { "busybox" } else { "go corpus" };
    use core::sync::atomic::Ordering;

    if cpus < 2 {
        println!("\x1b[93m    {label}      skipped, needs a second cpu\x1b[0m");
        return true;
    }
    const CPU: u32 = 3;

    let before = syscall::FOREIGN_CALLS.load(Ordering::Relaxed);
    let Ok(realm) = domain::create(
        if busybox { "busybox" } else { "go" },
        domain::ResourceEnvelope::new(),
    ) else {
        println!("\x1b[91m    {label}      FAILED: no domain\x1b[0m");
        return false;
    };
    if domain::with(realm, |owner| {
        owner.set_personality(domain::Personality::Linux)
    })
    .is_none()
    {
        println!("\x1b[91m    {label}      FAILED: the tag would not set\x1b[0m");
        return false;
    }
    // Record what *this* domain asks for, which is the L1 work queue: the
    // numbers a program somebody else wrote needs and this adapter refuses.
    syscall::trace_domain(realm.as_u32());
    // **The keyboard, for the lane that types** — RFC 0053. Granted to this
    // domain and to no other, and released when the domain ends, so the
    // Bhaskix shell that starts afterwards gets it back. Only the interactive
    // lane asks: a corpus running `sh -c` never reads, and granting it input it
    // will not use would take the keyboard from the shell for nothing.
    if busybox && BUSYBOX_INTERACTIVE.load(core::sync::atomic::Ordering::Acquire) {
        match domain::grant_input(realm) {
            Ok(()) => println!(
                "    busybox input  this domain was granted the console: it may read what is \
                 typed, and nothing else may while it holds it"
            ),
            Err(error) => {
                println!("\x1b[91m    busybox input  FAILED to grant the console: {error:?}\x1b[0m")
            }
        }
    }
    let options = sched::SpawnOptions::new()
        .pinned()
        .in_domain(realm.as_u32());
    if sched::spawn_on_with(
        CPU,
        if busybox { "busybox" } else { "go" },
        ring3_go,
        hhdm_base,
        hhdm_base,
        options,
    )
    .is_err()
    {
        println!("\x1b[91m    {label}      FAILED: the loader thread would not spawn\x1b[0m");
        return false;
    }

    // Time to get as far as it gets. This is not a wait for success: a
    // Tier 0 attempt that stops early is exactly the result worth printing,
    // and the histogram is the point either way.
    //
    // **Then it is put down, not destroyed under itself.** Destroying a
    // domain whose thread is still running tears the address space out from
    // under it, and the fault that follows lands in the middle of whatever
    // the next self-test is printing -- which is how this first showed up: a
    // console self-test reporting "16 of 5 bytes" while a page fault report
    // interleaved with its own output. `retire_probe` waits for the threads
    // to be gone, which is what the domain going away does not say.
    for _ in 0..400 {
        wait_millis(5);
        if domain::with(realm, |_| ()).is_none() {
            break;
        }
    }
    let made = syscall::FOREIGN_CALLS.load(Ordering::Relaxed) - before;
    retire_probe(realm);

    if made == 0 {
        println!(
            "\x1b[93m    {label}      the binary made no system calls: it is absent, empty, \
             or it faulted before its first one\x1b[0m"
        );
        return true;
    }

    // The histogram, in the order the runtime asked. Truncated to what the
    // table holds, and it says so rather than implying it saw everything.
    // **This program's calls, in the order it asked** — and until 2026-08-27
    // this read `syscall::FOREIGN_SEEN`, which is indexed by the *global* call
    // counter and so holds the first thirty-two foreign calls of the whole
    // boot. The corpus runs long after the eightieth, so the line printed the
    // machine's opening calls under a corpus's name. Two corpus runs printing
    // **identical** lists is what showed it.
    let made = syscall::stop_tracing().max(made);
    print!("    {label}      {made} calls, asked:");
    let mut shown = 0;
    for slot in syscall::TRACED_SEEN.iter() {
        let number = slot.load(Ordering::Relaxed);
        if number == u64::MAX {
            break;
        }
        print!(" {number}");
        shown += 1;
    }
    if made > shown {
        print!(" (and {} more)", made - shown);
    }
    println!();
    true
}

/// Where the clone probe's report page lands physically.
static CLONE_REPORT_PA: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Where the clone probe's code, stack and shared page live.
const CLONE_CODE_AT: u64 = 0x0000_0000_6000_0000;
const CLONE_STACK_AT: u64 = 0x0000_0000_6001_0000;
const CLONE_REPORT_AT: u64 = 0x0000_0000_6002_0000;

/// The clone probe: **two threads of one hosted program**, rendezvousing
/// through a futex. The parent clones a child with Go's own flag set, then
/// sleeps on a futex word; the child records its own tid, sets the word, and
/// wakes it. Nothing about this works unless `clone` creates a real thread
/// in the same address space *and* the futex wait/wake pair actually
/// blocks and releases — which is the half step 6 could not prove with one
/// thread, and the half Go's scheduler lives on.
const CLONE_CODE: [u8; 241] = [
    0x49, 0x89, 0xff, // mov r15, rdi          ; report page (shared, both threads)
    0x4c, 0x89, 0xfe, // mov rsi, r15
    0x48, 0x81, 0xc6, 0x00, 0x08, 0x00, 0x00, // add rsi, 0x800        ; child stack top
    0xbf, 0x00, 0x0f, 0x0d, 0x00, // mov edi, 0xd0f00      ; ...|SETTLS, which is
    //                                   what carries the child's one argument
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // (padding: the six bytes the first
    //                                     version wasted on an `add edi, 0`
    //                                     after getting the constant wrong --
    //                                     0xf0100 omitted FS, FILES and
    //                                     SIGHAND, and the decoder refused it
    //                                     exactly as it should have)
    0x31, 0xd2, // xor edx, edx          ; parent_tid
    0x4d, 0x31, 0xd2, // xor r10, r10          ; child_tid
    0x4d, 0x89, 0xf8, // mov r8, r15           ; tls = the shared page, which
    //                                   this personality hands the child in
    //                                   rdi (see cloned_thread)
    0x4c, 0x8d, 0x0d, 0x75, 0x00, 0x00, 0x00, // lea r9, [rip+child]   ; the entry
    //                                   (0x75, and it has moved three times:
    //                                   the parent's tail grew a wait for the
    //                                   test's word at step 9 and a futex
    //                                   park at step 10, and on 2026-08-26 the
    //                                   parent grew an eight-byte announcement
    //                                   below. Recomputed with the array
    //                                   disassembled rather than counted:
    //                                   `objdump` reads `lea r9,[rip+0x75]`
    //                                   and resolves it to 0x9c, which is
    //                                   where `child:` now begins)
    0xb8, 0x38, 0x00, 0x00, 0x00, // mov eax, 56           ; clone
    0x0f, 0x05, // syscall
    0x49, 0x89, 0x47, 0x08, // mov [r15+8], rax      ; the tid the parent got
    // **"I am about to wait", for the test to read.** One of the two witnesses
    // that let the kernel hold the child back until the parent is genuinely
    // asleep; see the gate in `child:` below. It is written here, *before*
    // `test rax, rax`, so that the `js` and its target move together and its
    // `rel8` needs no recomputing -- the displacement past the child does, and
    // did.
    0x49, 0xc7, 0x47, 0x30, 0x01, 0x00, 0x00, 0x00, // mov qword [r15+48], 1
    0x48, 0x85, 0xc0, // test rax, rax
    0x78, 0x24, // js parent_done        ; refused: stop here
    0x4c, 0x89, 0xff, // mov rdi, r15
    0x48, 0x83, 0xc7, 0x40, // add rdi, 64           ; &word
    0xbe, 0x80, 0x00, 0x00, 0x00, // mov esi, 128          ; WAIT|PRIVATE
    0x31, 0xd2, // xor edx, edx          ; expect 0
    0x4d, 0x31, 0xd2, // xor r10, r10
    0xb8, 0xca, 0x00, 0x00, 0x00, // mov eax, 202          ; futex
    0x0f, 0x05, // syscall
    0x49, 0x89, 0x47, 0x10, // mov [r15+16], rax     ; the wait's answer
    0x49, 0x8b, 0x47, 0x40, // mov rax, [r15+64]
    0x49, 0x89, 0x47, 0x18, // mov [r15+24], rax     ; the word the child set
    0x48, 0xb8, 0x45, 0x54, 0x55, 0x46, 0x58, 0x4b, 0x48, 0x42, // movabs rax, marker
    0x49, 0x89, 0x47, 0x38, // mov [r15+56], rax     ; marker last
    // **`exit_group`, on the kernel's word rather than at once** -- RFC 0032
    // step 9. The claim is that ending a *group* ends the other thread too,
    // and the only witness is the kernel counting the domain's threads. But
    // a domain that ends takes its report frame with it, and the frame is
    // what the numbers above are read out of. So the parent waits here for a
    // word the test writes once it has read them, and only then ends the
    // group -- the child is still spinning below when it does.
    0x49, 0x8b, 0x47, 0x60, // wait: mov rax, [r15+96]
    0x48, 0x85, 0xc0, //       test rax, rax
    0x74, 0xf7, //             jz wait
    // **And then the parent parks for ever**, on a word nobody will change.
    // It is the *child* that ends the group, and what this proves is the pair:
    // `exit_group` ends a thread that asked for nothing, and a thread parked
    // in a futex -- blocked in the kernel on a notification -- dies with its
    // domain rather than waiting for a wake that is never coming.
    // **The offsets are 112 and 120, and not 128 and 136, because a `disp8`
    // is signed**: `[r15+128]` assembles as `[r15-128]`, which stored the
    // announcement a hundred and twenty-eight bytes *below* the report page
    // and left this test reporting `parked false` with everything else right.
    0x49, 0xc7, 0x47, 0x70, 0x01, 0x00, 0x00, 0x00, // mov qword [r15+112], 1 ; "parking"
    0x4c, 0x89, 0xff, // mov rdi, r15
    0x48, 0x83, 0xc7, 0x78, // add rdi, 120          ; &word
    0xbe, 0x80, 0x00, 0x00, 0x00, // mov esi, 128          ; WAIT|PRIVATE
    0x31, 0xd2, // xor edx, edx          ; expect 0, and it stays 0
    0x4d, 0x31, 0xd2, // xor r10, r10
    0xb8, 0xca, 0x00, 0x00, 0x00, // mov eax, 202          ; futex
    0x0f, 0x05, // syscall
    0xeb, 0xfe, // jmp $                 ; only if the park ever returns
    0x49, 0x89, 0xff, // child: mov r15, rdi   ; the page, as handed over
    // **The child waits to be let go, and is let go by the only party that can
    // know.** Until 2026-08-26 this was `sched_yield` twice and a spin of four
    // million -- an attempt to lose a race on purpose, which worked until it
    // did not. When the child won anyway, the parent's `FUTEX_WAIT` saw a word
    // that had already changed and returned `EAGAIN`: correct behaviour, and a
    // run that never exercised the sleeping path this test exists to prove.
    //
    // Retrying was tried first and measured: three attempts, and on
    // 2026-08-26 the attempts were shown **not to be independent draws** --
    // the per-attempt loss rate was about 1 in 30 on this lane, which predicts
    // three-of-three at 1 in 27,000, and three-of-three was seen at 1 in 40.
    // Three orders of magnitude apart. When the machine is in a state where
    // the child wins, it wins again, so a fourth retry is a placebo.
    //
    // The old comment said the alternative was impossible: *"no amount of
    // user-mode delay can guarantee the parent is asleep, because the only
    // thing that knows is the kernel and the probe cannot ask it without a
    // syscall invented for the test."* Both halves are true and the conclusion
    // does not follow. **The kernel is running this test.** It does not need
    // to be asked, and it does not need a syscall: it watches for the parent's
    // announcement at `[r15+48]` together with its own count of hosted threads
    // parked by a `BLOCK_ON` reply, and only then writes the word below. The
    // same two witnesses the exit phase of this test has always used, applied
    // to the rendezvous that had been left to luck.
    0x49, 0x8b, 0x47, 0x48, // gate: mov rax, [r15+72]
    0x48, 0x85, 0xc0, //       test rax, rax
    0x74, 0xf7, //             jz gate
    0xb8, 0xba, 0x00, 0x00, 0x00, // mov eax, 186          ; gettid
    0x0f, 0x05, // syscall
    0x49, 0x89, 0x47, 0x20, // mov [r15+32], rax     ; the child's own tid
    0x49, 0xc7, 0x47, 0x40, 0x2a, 0x00, 0x00, 0x00, // mov qword [r15+64], 42
    0x4c, 0x89, 0xff, // mov rdi, r15
    0x48, 0x83, 0xc7, 0x40, // add rdi, 64
    0xbe, 0x81, 0x00, 0x00, 0x00, // mov esi, 129          ; WAKE|PRIVATE
    0xba, 0x01, 0x00, 0x00, 0x00, // mov edx, 1
    0xb8, 0xca, 0x00, 0x00, 0x00, // mov eax, 202
    0x0f, 0x05, // syscall
    0x49, 0x89, 0x47, 0x28, // mov [r15+40], rax     ; how many it woke
    // **The child says it has finished writing, and this is the actual bug the
    // "clone race" was.** The marker at `[r15+56]` is the *parent's* last
    // store, and the test read all five words the moment it appeared -- but
    // `[r15+40]` above is written by the **child**, on another CPU, with
    // nothing ordering the two. So a run where the parent was woken, wrote its
    // three words and set the marker before the child was scheduled again read
    // `woke` as **0** and called it a lost race. It was a lost race: the test
    // racing its own probe, not the child racing the parent.
    //
    // Every number in the failing run says so. `wait 0` means the parent's
    // `FUTEX_WAIT` *returned*, not `EAGAIN`, so it really did sleep; `word 42`
    // means the child really did set it; `0 futex notifications dirty` rules
    // out a latched bit waking the parent spuriously. The only word that
    // disagreed was the one written by the thread that had not run yet.
    0x49, 0xc7, 0x47, 0x50, 0x01, 0x00, 0x00, 0x00, // mov qword [r15+80], 1
    // The child waits for the test's word and then ends the group -- with the
    // parent parked in a futex it will never be woken from.
    0x49, 0x8b, 0x47, 0x68, // cwait: mov rax, [r15+104]
    0x48, 0x85, 0xc0, //        test rax, rax
    0x74, 0xf7, //              jz cwait
    0xb8, 0xe7, 0x00, 0x00, 0x00, // mov eax, 231          ; exit_group
    0x0f, 0x05, // syscall
    0xeb, 0xfe, // jmp $
];

/// The thread that becomes the clone probe's parent.
extern "C" fn ring3_clone(hhdm_base: u64) -> ! {
    use bhaskix_boot::VirtAddr;
    use bhaskix_mm::{Protection, VirtRange};
    use vm::AddressSpace;

    let stop = || -> ! { sched::exit() };
    let Ok(mut space) = AddressSpace::new(hhdm_base) else {
        stop()
    };
    for (at, pages, protection) in [
        (CLONE_CODE_AT, 1, Protection::ReadExecute),
        (CLONE_STACK_AT, 2, Protection::ReadWrite),
        (CLONE_REPORT_AT, 1, Protection::ReadWrite),
    ] {
        let Some(range) = VirtRange::from_pages(VirtAddr(at), pages) else {
            stop()
        };
        if space.map_anonymous(range, protection).is_err() {
            stop()
        }
    }
    let (Some(code_pa), Some(report_pa)) = (
        space.translate(VirtAddr(CLONE_CODE_AT)),
        space.translate(VirtAddr(CLONE_REPORT_AT)),
    ) else {
        stop()
    };
    // SAFETY: a freshly mapped frame this space owns, filled through the
    // direct map; the executable mapping is never writable.
    unsafe {
        core::ptr::copy_nonoverlapping(
            CLONE_CODE.as_ptr(),
            (hhdm_base + code_pa) as *mut u8,
            CLONE_CODE.len(),
        );
    }
    CLONE_REPORT_PA.store(report_pa, core::sync::atomic::Ordering::Release);
    // SAFETY: the higher half is copied from the running table.
    unsafe { vm::install(space) };
    // The domain note, as every direct entry sets it.
    if let Some(domain) = sched::current_domain() {
        telemetry::note_domain(domain.as_u32());
    }
    // SAFETY: the entry is in the user-executable page just written.
    unsafe {
        bhaskix_arch::syscall::enter_ring3(
            CLONE_CODE_AT,
            CLONE_STACK_AT + 2 * 4096,
            [CLONE_REPORT_AT, 0],
        )
    }
}

/// The witness that `clone` makes a thread and the futex pairs across it.
fn clone_self_test(hhdm_base: u64, cpus: u32) -> bool {
    use core::sync::atomic::Ordering;

    if cpus < 2 {
        println!("\x1b[93m    linux clone    skipped, needs a second cpu\x1b[0m");
        return true;
    }
    const CPU: u32 = 3;

    // As the signal test: a failure that made no foreign call at all was
    // judged the wrong dialect, and that is a different bug from a clone
    // that did not conclude.
    let foreign_before = syscall::FOREIGN_CALLS.load(Ordering::Relaxed);

    // **One run, because the race it used to retry around is gone.** The child
    // no longer guesses when the parent is asleep: it waits on a word the
    // kernel writes once it has seen the parent park, so the rendezvous cannot
    // be lost. See the gate in `CLONE_CODE`'s `child:`.
    //
    // Three attempts stood here until 2026-08-26, and they were measured
    // rather than removed on taste: the per-attempt loss rate on this lane was
    // about 1 in 30, which predicts three-of-three at 1 in 27,000, and
    // three-of-three was observed at 1 in 40. The attempts were **correlated**,
    // so a fourth would have lost too. The detector below is kept, now as a
    // failure rather than a retry: with the gate in place, a lost rendezvous
    // means the gate did not hold, and that is worth a red lane.
    clone_rendezvous_attempt(hhdm_base, CPU, foreign_before)
}

/// The clone-and-rendezvous run.
///
/// Returned `Option<bool>` until 2026-08-26, where `None` meant *the attempt
/// raced, run it again*. The race is gone — the kernel holds the child until
/// it has seen the parent park — so there is nothing to signal and nothing to
/// retry.
fn clone_rendezvous_attempt(hhdm_base: u64, cpu: u32, foreign_before: u64) -> bool {
    use core::sync::atomic::Ordering;

    // Each attempt builds its own space and republishes the report page, so
    // the previous attempt's address must not be read as this one's.
    CLONE_REPORT_PA.store(0, Ordering::Release);
    let Ok(realm) = domain::create("clone", domain::ResourceEnvelope::new()) else {
        println!("\x1b[91m    linux clone    FAILED: no domain\x1b[0m");
        return false;
    };
    if domain::with(realm, |owner| {
        owner.set_personality(domain::Personality::Linux)
    })
    .is_none()
    {
        println!("\x1b[91m    linux clone    FAILED: the tag would not set\x1b[0m");
        return false;
    }
    let options = sched::SpawnOptions::new()
        .pinned()
        .in_domain(realm.as_u32());
    // **Before the probe exists**, so that only parks this probe causes can
    // move it. The gate below opens on this counter rising *and* the parent's
    // own announcement, which is the pair that says "the parent is asleep in
    // the futex" rather than merely "somebody blocked".
    let parked_before_rendezvous = syscall::BLOCKED.load(Ordering::Relaxed);
    let Ok(parent_thread) =
        sched::spawn_on_with(cpu, "clone", ring3_clone, hhdm_base, hhdm_base, options)
    else {
        println!("\x1b[91m    linux clone    FAILED: the probe would not spawn\x1b[0m");
        return false;
    };

    const MARKER: u64 = u64::from_le_bytes(*b"ETUFXKHB");
    let mut answers = [0u64; 5];
    let mut marked = false;
    // **Whether the child was ever let go.** Distinguishes "the rendezvous
    // failed" from "the parent never parked, so the gate never opened", which
    // are different bugs and used to look identical from out here.
    let mut released = false;
    for _ in 0..600 {
        let report_pa = CLONE_REPORT_PA.load(Ordering::Acquire);
        if report_pa != 0 {
            // **The gate.** The child is spinning on `[report + 72]` and will
            // not touch the futex word until this is written. It opens on two
            // witnesses that cannot both be wrong: the parent's own
            // announcement at `[report + 48]`, written from ring 3 after
            // `clone` returned and before the wait, and the kernel's count of
            // hosted threads parked by a `BLOCK_ON` reply. Neither alone would
            // do -- the announcement says the parent *reached* the wait, not
            // that it is in it, and the counter says *somebody* parked.
            //
            // **And a third, because two were not enough.** The first version
            // opened on those two alone, mirroring the exit phase below, and
            // the placements lane caught it: `syscall::BLOCKED` is incremented
            // in `syscall.rs` *before* `notify::wait` parks the thread, so a
            // watcher acting on the counter can act in the window where the
            // parent has been counted and is still running. `sched::is_blocked`
            // answers the question the counter cannot -- has the park landed --
            // and it is only meaningful *after* the counter has moved, because
            // this thread is `Blocked` during every foreign call it makes.
            if !released {
                // SAFETY: a frame the probe's space owns, through the direct
                // map, while the domain is alive.
                let announced =
                    unsafe { core::ptr::read_volatile((hhdm_base + report_pa + 48) as *const u64) };
                if announced == 1
                    && syscall::BLOCKED.load(Ordering::Relaxed) > parked_before_rendezvous
                    && sched::is_blocked(parent_thread) == Some(true)
                {
                    // SAFETY: as above.
                    unsafe {
                        core::ptr::write_volatile((hhdm_base + report_pa + 72) as *mut u64, 1);
                    }
                    released = true;
                }
            }
            // SAFETY: a frame the probe's space owns, through the direct map.
            let (marker, words) = unsafe {
                (
                    core::ptr::read_volatile((hhdm_base + report_pa + 56) as *const u64),
                    [
                        core::ptr::read_volatile((hhdm_base + report_pa + 8) as *const u64),
                        core::ptr::read_volatile((hhdm_base + report_pa + 16) as *const u64),
                        core::ptr::read_volatile((hhdm_base + report_pa + 24) as *const u64),
                        core::ptr::read_volatile((hhdm_base + report_pa + 32) as *const u64),
                        core::ptr::read_volatile((hhdm_base + report_pa + 40) as *const u64),
                    ],
                )
            };
            // **Both writers, not just the parent.** The marker is the
            // parent's last store; `woke` is the child's. Reading on the
            // marker alone reads a word whose writer may not have run yet,
            // which is what produced `woke 0` on a run where everything else
            // was right. The child sets `[report + 80]` after storing it.
            // SAFETY: as above.
            let child_done =
                unsafe { core::ptr::read_volatile((hhdm_base + report_pa + 80) as *const u64) };
            if marker == MARKER && child_done != 0 {
                answers = words;
                marked = true;
                break;
            }
        }
        wait_millis(5);
    }

    // **The group's exit, watched from outside it.** The numbers are read;
    // the parent is told it may go; and what is counted is whether the
    // *child* -- which is spinning and has asked for nothing -- goes with
    // it. That is the whole difference between `exit` and `exit_group`, and
    // nothing inside the domain could report it: the reporter would be one
    // of the threads whose ending is the claim.
    let mut group_ended = false;
    let mut parked = false;
    if marked {
        let report_pa = CLONE_REPORT_PA.load(Ordering::Acquire);
        if report_pa != 0 {
            let parked_before = syscall::BLOCKED.load(Ordering::Relaxed);
            // SAFETY: the frame the probe's space owns, through the direct
            // map, and the domain is still alive: nothing has been retired.
            unsafe { core::ptr::write_volatile((hhdm_base + report_pa + 96) as *mut u64, 1) };
            // **Wait until the parent is really parked**, on two witnesses
            // that cannot both be wrong: its own word, written from ring 3
            // just before the call, and the kernel's count of threads parked
            // by a `BLOCK_ON` reply, which only `adapter_call` increments. A
            // sleep of some milliseconds instead would make the next step a
            // race dressed as a test.
            for _ in 0..400 {
                // SAFETY: as above.
                let announced = unsafe {
                    core::ptr::read_volatile((hhdm_base + report_pa + 112) as *const u64)
                };
                if announced == 1 && syscall::BLOCKED.load(Ordering::Relaxed) > parked_before {
                    parked = true;
                    break;
                }
                wait_millis(5);
            }
            // Now the *child* ends the group, with its parent asleep in a
            // futex nobody will ever wake.
            // SAFETY: as above.
            unsafe { core::ptr::write_volatile((hhdm_base + report_pa + 104) as *mut u64, 1) };
            // **`threads_counted_in` and not `threads_in_domain`**, and the
            // difference is the whole verdict. The scanning version treats a
            // runqueue it could not lock as empty -- and the failure this test
            // is looking for is a thread *spinning*, which keeps that very
            // lock busy. Armed with the fix removed, the scan was blinded by
            // the spin and reported the domain empty: a gate that passed
            // because the bug was bad enough to hide itself. The counter is an
            // atomic maintained at create and exit, so nothing a thread does
            // can make it lie.
            for _ in 0..400 {
                if sched::threads_counted_in(realm.as_u32()) == 0 {
                    group_ended = true;
                    break;
                }
                wait_millis(5);
            }
        }
    }
    retire_probe(realm);

    // The parent's view of the tid, its wait's answer, the word the child
    // set, the child's own tid, and how many the child's wake found.
    let [parent_saw, wait_answer, word, child_tid, woke] = answers;

    // **The detector is kept and its verdict inverted.** Everything went right
    // *except* that the parent never had to sleep, so the wake had nobody to
    // find. That used to mean "the child won the race, try again". With the
    // gate in place the child cannot win it, so this now means the gate did
    // not hold, and the right answer is a red lane rather than another roll.
    if marked && wait_answer == 0 && word == 42 && woke == 0 {
        println!(
            "\x1b[91m    linux clone    FAILED: wait {}, word {}, woke {}, parent saw {}, child \
             tid {}, child {}, parked before {} now {}\x1b[0m",
            wait_answer as i64,
            word,
            woke as i64,
            parent_saw as i64,
            child_tid as i64,
            if released {
                "released"
            } else {
                "never released"
            },
            parked_before_rendezvous,
            syscall::BLOCKED.load(Ordering::Relaxed)
        );
        // **The evidence, on the line, because this is rare and the last two
        // sightings were argued about rather than read.** A notification
        // holding bits nobody took would explain a wait that returned without
        // its waker: `notify::wait` swaps the pending word, so a bit latched
        // earlier is taken as this wait's own wake. That hypothesis was
        // measured on a passing boot and **found nothing** -- no futex
        // notification was left dirty -- so it is not the explanation unless
        // this line says otherwise on a failing one.
        let (dirty, which) = futex_wakes_left_dirty();
        let (signals, unwaited, stranded) = notify::statistics();
        println!(
            "\x1b[91m    linux clone    at the failure: {dirty} futex notifications dirty (mask \
             {which:#x}); {signals} signals, {unwaited} found no waiter, {stranded} stranded\x1b[0m"
        );
        return false;
    }

    // The gate never opened, and the run below would be describing a probe
    // that never got past its spin. Said separately because "the parent did
    // not park" and "the rendezvous failed" are different faults.
    if !released {
        println!(
            "\x1b[91m    linux clone    FAILED: the parent never parked, so the child was \
             never let go -- no announcement at report+48, or no BLOCK_ON park\x1b[0m"
        );
        return false;
    }

    let right = marked
        && parent_saw > 0
        && child_tid > 0
        && parent_saw == child_tid
        && wait_answer == 0
        && word == 42
        && woke == 1
        && parked
        && group_ended;
    if right {
        println!(
            "    linux clone    a Linux program cloned a thread (tid {parent_saw}, which the \
             child agrees is its own), then the two met through a futex: the parent slept, the \
             child set the word to 42 and woke {woke}, and the parent came back; the parent \
             then parked in a futex and the child's exit_group ended them both. The child was \
             held until the parent was seen parked, so nothing here was raced for"
        );
        true
    } else {
        let foreign = syscall::FOREIGN_CALLS.load(Ordering::Relaxed) - foreign_before;
        println!(
            "\x1b[91m    linux clone    FAILED: marked {}, parent saw {}, wait {}, word {}, \
             child tid {}, woke {}, parked {}, group ended {}, {foreign} foreign calls\x1b[0m",
            marked,
            parent_saw as i64,
            wait_answer as i64,
            word,
            child_tid as i64,
            woke as i64,
            parked,
            group_ended
        );
        false
    }
}

/// What each hosted program was told its pid is, packed `domain << 32 | pid`.
///
/// **The evidence for RFC 0033 step 4**, and it has to be collected here
/// because a pid is the *adapter's* answer to a *hosted program*: the kernel
/// never sees one except by reading it out of a probe's report page, which is
/// exactly what the self-tests already do. Eight slots because there are six
/// probes and room to be wrong about that.
static HOSTED_PIDS: [core::sync::atomic::AtomicU64; 8] =
    [const { core::sync::atomic::AtomicU64::new(u64::MAX) }; 8];
static HOSTED_PIDS_AT: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// Records that the program in `domain` was told its pid is `pid`.
fn note_hosted_pid(domain: u32, pid: u64) {
    use core::sync::atomic::Ordering;
    let at = HOSTED_PIDS_AT.fetch_add(1, Ordering::Relaxed);
    if let Some(slot) = HOSTED_PIDS.get(at) {
        slot.store(
            (u64::from(domain) << 32) | (pid & 0xffff_ffff),
            Ordering::Relaxed,
        );
    }
}

/// What the hosted programs were told, as `(domain, pid)` pairs.
fn hosted_pids() -> ([(u32, u64); 8], usize) {
    use core::sync::atomic::Ordering;
    let mut pairs = [(0u32, 0u64); 8];
    let mut count = 0;
    for slot in &HOSTED_PIDS {
        let packed = slot.load(Ordering::Relaxed);
        if packed != u64::MAX {
            pairs[count] = ((packed >> 32) as u32, packed & 0xffff_ffff);
            count += 1;
        }
    }
    (pairs, count)
}

/// Where the thread probe's report page lands physically.
static THREAD_REPORT_PA: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Where the thread probe's code, stack and report live.
const THREAD_CODE_AT: u64 = 0x0000_0000_5000_0000;
const THREAD_STACK_AT: u64 = 0x0000_0000_5001_0000;
const THREAD_REPORT_AT: u64 = 0x0000_0000_5002_0000;

/// The thread probe, hand-assembled: RFC 0005 step 6's witness. It asks its
/// own thread and process ids, yields, and then exercises the futex
/// contract's edges -- a `WAIT` whose word has already changed (which must
/// *not* sleep), a `WAKE` with nobody asleep, a shared futex (refused), and
/// a `clone` (refused, with the reason recorded in the RFC).
const THREAD_CODE: [u8; 251] = [
    0x49, 0x89, 0xff, // mov r15, rdi          ; report page
    0xb8, 0xba, 0x00, 0x00, 0x00, // mov eax, 186          ; gettid
    0x0f, 0x05, // syscall
    0x49, 0x89, 0x07, // mov [r15], rax
    0xb8, 0x27, 0x00, 0x00, 0x00, // mov eax, 39           ; getpid
    0x0f, 0x05, // syscall
    0x49, 0x89, 0x47, 0x08, // mov [r15+8], rax
    0xb8, 0x18, 0x00, 0x00, 0x00, // mov eax, 24           ; sched_yield
    0x0f, 0x05, // syscall
    0x49, 0x89, 0x47, 0x10, // mov [r15+16], rax
    0x49, 0xc7, 0x47, 0x40, 0x01, 0x00, 0x00, 0x00, // mov qword [r15+64], 1
    0x4c, 0x89, 0xff, // mov rdi, r15
    0x48, 0x83, 0xc7, 0x40, // add rdi, 64           ; &word
    0xbe, 0x80, 0x00, 0x00, 0x00, // mov esi, 128          ; WAIT|PRIVATE
    0x31, 0xd2, // xor edx, edx          ; expect 0, word is 1
    0x4d, 0x31, 0xd2, // xor r10, r10          ; no timeout
    0xb8, 0xca, 0x00, 0x00, 0x00, // mov eax, 202          ; futex
    0x0f, 0x05, // syscall
    0x49, 0x89, 0x47, 0x18, // mov [r15+24], rax     ; expect -EAGAIN
    0xbe, 0x81, 0x00, 0x00, 0x00, // mov esi, 129          ; WAKE|PRIVATE
    0xba, 0x01, 0x00, 0x00, 0x00, // mov edx, 1
    0xb8, 0xca, 0x00, 0x00, 0x00, // mov eax, 202
    0x0f, 0x05, // syscall
    0x49, 0x89, 0x47, 0x20, // mov [r15+32], rax     ; expect 0
    0xbe, 0x00, 0x00, 0x00, 0x00, // mov esi, 0            ; WAIT, not private
    0xb8, 0xca, 0x00, 0x00, 0x00, // mov eax, 202
    0x0f, 0x05, // syscall
    0x49, 0x89, 0x47, 0x28, // mov [r15+40], rax     ; expect -ENOSYS
    0xbf, 0x00, 0x01, 0x0f, 0x00, // mov edi, 0xf0100      ; Go's flag set (low)
    0x81, 0xcf, 0x00, 0x00, 0x00, 0x00, // or edi, 0             ; (kept simple)
    0xbe, 0x00, 0x80, 0x00, 0x00, // mov esi, 0x8000       ; a stack
    0xb8, 0x38, 0x00, 0x00, 0x00, // mov eax, 56           ; clone
    0x0f, 0x05, // syscall
    0x49, 0x89, 0x47, 0x30, // mov [r15+48], rax     ; expect -ENOSYS
    // The thread-local base, and then a read *through* it -- RFC 0032 step
    // 9. The witness word is written into the report page, the base is set
    // to point at it, and `fs:[0]` reads it back. Both halves matter: the
    // answer says `arch_prctl` was accepted, and the read says the base
    // survived the round trip through a program in ring 3 and the switch
    // back -- which is the only way to see a base that was written to the
    // wrong CPU's register.
    0x49, 0xc7, 0x47, 0x58, 0xfe, 0x5a, 0x00, 0x00, // mov qword [r15+88], 0x5afe
    0x4c, 0x89, 0xfe, // mov rsi, r15
    0x48, 0x83, 0xc6, 0x58, // add rsi, 88           ; &witness
    0xbf, 0x02, 0x10, 0x00, 0x00, // mov edi, 0x1002       ; ARCH_SET_FS
    0xb8, 0x9e, 0x00, 0x00, 0x00, // mov eax, 158          ; arch_prctl
    0x0f, 0x05, // syscall
    0x49, 0x89, 0x47, 0x48, // mov [r15+72], rax     ; expect 0
    0x64, 0x48, 0x8b, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00, // mov rax, fs:[0]
    0x49, 0x89, 0x47, 0x50, // mov [r15+80], rax     ; expect 0x5afe
    // A `write` that succeeds — RFC 0032 step 10. The bad-descriptor half is
    // the foreigner probe's; this is the other half, and it is the one that
    // needs a console: the sixteen bytes below go from this hosted program's
    // page, through `bin/linuxd`, out of a `Console` capability the adapter
    // holds with `Rights::WRITE` and nothing else. What proves it is the
    // string appearing in the log, which no counter could say.
    0x48, 0xb8, 0x68, 0x6f, 0x73, 0x74, 0x65, 0x64, 0x20, 0x77, // movabs rax, "hosted w"
    0x49, 0x89, 0x47, 0x68, // mov [r15+104], rax
    0x48, 0xb8, 0x72, 0x69, 0x74, 0x65, 0x20, 0x6f, 0x6b, 0x0a, // movabs rax, "rite ok\n"
    0x49, 0x89, 0x47, 0x70, // mov [r15+112], rax
    0xbf, 0x01, 0x00, 0x00, 0x00, // mov edi, 1            ; fd 1
    0x4c, 0x89, 0xfe, // mov rsi, r15
    0x48, 0x83, 0xc6, 0x68, // add rsi, 104          ; &"hosted write ok\n"
    0xba, 0x10, 0x00, 0x00, 0x00, // mov edx, 16
    0xb8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1            ; write
    0x0f, 0x05, // syscall
    0x49, 0x89, 0x47, 0x78, // mov [r15+120], rax    ; expect 16
    0x48, 0xb8, 0x45, 0x54, 0x55, 0x46, 0x58, 0x4b, 0x48, 0x42, // movabs rax, "BHKXFUTE"
    0x49, 0x89, 0x47, 0x38, // mov [r15+56], rax     ; the marker, written last
    0xeb, 0xfe, // jmp $
];

/// The thread that becomes RFC 0005 step 6's witness.
extern "C" fn ring3_thread(hhdm_base: u64) -> ! {
    use bhaskix_boot::VirtAddr;
    use bhaskix_mm::{Protection, VirtRange};
    use vm::AddressSpace;

    let stop = || -> ! { sched::exit() };
    let Ok(mut space) = AddressSpace::new(hhdm_base) else {
        stop()
    };
    for (at, pages, protection) in [
        (THREAD_CODE_AT, 1, Protection::ReadExecute),
        (THREAD_STACK_AT, 2, Protection::ReadWrite),
        (THREAD_REPORT_AT, 1, Protection::ReadWrite),
    ] {
        let Some(range) = VirtRange::from_pages(VirtAddr(at), pages) else {
            stop()
        };
        if space.map_anonymous(range, protection).is_err() {
            stop()
        }
    }
    let (Some(code_pa), Some(report_pa)) = (
        space.translate(VirtAddr(THREAD_CODE_AT)),
        space.translate(VirtAddr(THREAD_REPORT_AT)),
    ) else {
        stop()
    };
    // SAFETY: a freshly mapped frame this space owns, filled through the
    // direct map; the executable mapping is never writable.
    unsafe {
        core::ptr::copy_nonoverlapping(
            THREAD_CODE.as_ptr(),
            (hhdm_base + code_pa) as *mut u8,
            THREAD_CODE.len(),
        );
    }
    THREAD_REPORT_PA.store(report_pa, core::sync::atomic::Ordering::Release);
    // SAFETY: the higher half is copied from the running table.
    unsafe { vm::install(space) };
    // The domain note, for the same reason `enter_user` sets it: the syscall
    // entry reads it to decide which ABI this thread speaks, and a thread
    // entering ring 3 for the first time may not have been switched to on
    // this CPU. These probes enter directly rather than through `enter_user`
    // -- each builds its own space -- so each sets it. The memory probe found
    // this by being answered `BadSyscall`; the futex probe had been passing
    // on luck.
    if let Some(domain) = sched::current_domain() {
        telemetry::note_domain(domain.as_u32());
    }
    // SAFETY: the entry is in the user-executable page just written.
    unsafe {
        bhaskix_arch::syscall::enter_ring3(
            THREAD_CODE_AT,
            THREAD_STACK_AT + 2 * 4096,
            [THREAD_REPORT_AT, 0],
        )
    }
}

/// RFC 0005 step 6's witness: the futex contract's edges, and the identity
/// calls a runtime asks before it does anything else.
fn thread_self_test(hhdm_base: u64, cpus: u32) -> bool {
    use core::sync::atomic::Ordering;

    if cpus < 2 {
        println!("\x1b[93m    linux futex    skipped, needs a second cpu\x1b[0m");
        return true;
    }
    const CPU: u32 = 3;

    let Ok(realm) = domain::create("futex", domain::ResourceEnvelope::new()) else {
        println!("\x1b[91m    linux futex    FAILED: no domain\x1b[0m");
        return false;
    };
    if domain::with(realm, |owner| {
        owner.set_personality(domain::Personality::Linux)
    })
    .is_none()
    {
        println!("\x1b[91m    linux futex    FAILED: the tag would not set\x1b[0m");
        return false;
    }
    let options = sched::SpawnOptions::new()
        .pinned()
        .in_domain(realm.as_u32());
    if sched::spawn_on_with(CPU, "futex", ring3_thread, hhdm_base, hhdm_base, options).is_err() {
        println!("\x1b[91m    linux futex    FAILED: the probe would not spawn\x1b[0m");
        return false;
    }

    // The marker, written last by the probe, is what says the seven words
    // under it are its own. Without it this loop reads a frame that may
    // have been recycled from an earlier domain and finds a plausible-looking
    // set of numbers -- which is exactly what happened on the first run of
    // this test, and is why every report page in this project is marked.
    const MARKER: u64 = u64::from_le_bytes(*b"ETUFXKHB");
    let mut answers = [0u64; 10];
    let mut marked = false;
    for _ in 0..400 {
        let report_pa = THREAD_REPORT_PA.load(Ordering::Acquire);
        if report_pa != 0 {
            // SAFETY: a frame the probe's space owns, through the direct map.
            let (marker, words) = unsafe {
                (
                    core::ptr::read_volatile((hhdm_base + report_pa + 56) as *const u64),
                    [
                        core::ptr::read_volatile((hhdm_base + report_pa) as *const u64),
                        core::ptr::read_volatile((hhdm_base + report_pa + 8) as *const u64),
                        core::ptr::read_volatile((hhdm_base + report_pa + 16) as *const u64),
                        core::ptr::read_volatile((hhdm_base + report_pa + 24) as *const u64),
                        core::ptr::read_volatile((hhdm_base + report_pa + 32) as *const u64),
                        core::ptr::read_volatile((hhdm_base + report_pa + 40) as *const u64),
                        core::ptr::read_volatile((hhdm_base + report_pa + 48) as *const u64),
                        core::ptr::read_volatile((hhdm_base + report_pa + 72) as *const u64),
                        core::ptr::read_volatile((hhdm_base + report_pa + 80) as *const u64),
                        core::ptr::read_volatile((hhdm_base + report_pa + 120) as *const u64),
                    ],
                )
            };
            if marker == MARKER {
                answers = words;
                marked = true;
                break;
            }
        }
        wait_millis(5);
    }
    retire_probe(realm);

    let eagain = -11i64 as u64;
    let enosys = -38i64 as u64;
    // A tid and a pid that are never zero (a runtime treats zero as an
    // error), a yield that answered, the compare-and-sleep refusing to
    // sleep on a stale word, a wake with nobody asleep, and both refusals.
    //
    // The last two are RFC 0032 step 9's: `arch_prctl` accepted, and the
    // witness word read back **through** the base it set. The second is what
    // makes the first mean anything -- an answer of zero from a call that
    // wrote the register on the wrong CPU would look identical.
    const WITNESS: u64 = 0x5afe;
    note_hosted_pid(realm.as_u32(), answers[1]);
    let right = marked
        && answers[0] != 0
        && answers[1] != 0
        && answers[2] == 0
        && answers[3] == eagain
        && answers[4] == 0
        && answers[5] == enosys
        && answers[6] == enosys
        && answers[7] == 0
        && answers[8] == WITNESS
        // Sixteen bytes, out of a console capability held in ring 3. The
        // count is the answer; the string in the log above is the evidence.
        && answers[9] == 16;
    if right {
        println!(
            "    linux futex    a Linux program asked its tid ({}) and pid ({}), yielded, and \
             met the futex contract's edges: a WAIT on a word that had already changed refused \
             to sleep (EAGAIN), a WAKE with nobody asleep woke none, a shared futex and a clone \
             were refused; then it set its TLS base, read {:#x} back through it, and wrote {} \
             bytes to the console through the adapter",
            answers[0], answers[1], answers[8], answers[9]
        );
        true
    } else {
        println!(
            "\x1b[91m    linux futex    FAILED: tid {}, pid {}, yield {}, stale-wait {}, \
             empty-wake {}, shared {}, clone {}, arch_prctl {}, fs:[0] {:#x}, write {}\x1b[0m",
            answers[0],
            answers[1],
            answers[2] as i64,
            answers[3] as i64,
            answers[4] as i64,
            answers[5] as i64,
            answers[6] as i64,
            answers[7] as i64,
            answers[8],
            answers[9] as i64
        );
        false
    }
}

/// Where the memory probe's report page lands physically.
static MEMORY_REPORT_PA: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Where the memory probe's code, stack and report live.
const MEMORY_CODE_AT: u64 = 0x0000_0000_4000_0000;
const MEMORY_STACK_AT: u64 = 0x0000_0000_4001_0000;
const MEMORY_REPORT_AT: u64 = 0x0000_0000_4002_0000;

/// The memory probe, hand-assembled: RFC 0005 step 5's witness. It asks for
/// two anonymous pages, writes a pattern into the **second** one (so the
/// lazy commit has to reach past the first), reads it back, unmaps the
/// range, and gives `madvise` its advice. Each answer lands in the report.
const MEMORY_CODE: [u8; 116] = [
    0x49, 0x89, 0xff, // mov r15, rdi          ; report page
    0x31, 0xff, // xor edi, edi          ; addr = NULL
    0xbe, 0x00, 0x20, 0x00, 0x00, // mov esi, 8192         ; length
    0xba, 0x03, 0x00, 0x00, 0x00, // mov edx, 3            ; PROT_READ|WRITE
    0x41, 0xba, 0x22, 0x00, 0x00, 0x00, // mov r10d, 0x22        ; PRIVATE|ANONYMOUS
    0x49, 0xc7, 0xc0, 0xff, 0xff, 0xff, 0xff, // mov r8, -1            ; fd
    0x4d, 0x31, 0xc9, // xor r9, r9            ; offset
    0xb8, 0x09, 0x00, 0x00, 0x00, // mov eax, 9            ; mmap
    0x0f, 0x05, // syscall
    0x49, 0x89, 0x07, // mov [r15], rax        ; report the address
    0x48, 0x89, 0xc3, // mov rbx, rax          ; keep it
    0x48, 0x85, 0xc0, // test rax, rax
    0x78, 0x41, // js done               ; refused: leave proof zero
    0x48, 0xc7, 0x83, 0x00, 0x10, 0x00, 0x00, 0x2a, 0x00, 0x00,
    0x00, // mov qword [rbx+0x1000], 42
    0x48, 0x8b, 0x83, 0x00, 0x10, 0x00, 0x00, // mov rax, [rbx+0x1000]
    0x49, 0x89, 0x47, 0x08, // mov [r15+8], rax      ; report what read back
    0x48, 0x89, 0xdf, // mov rdi, rbx
    0xbe, 0x00, 0x20, 0x00, 0x00, // mov esi, 8192
    0xb8, 0x0b, 0x00, 0x00, 0x00, // mov eax, 11           ; munmap
    0x0f, 0x05, // syscall
    0x49, 0x89, 0x47, 0x10, // mov [r15+16], rax     ; report munmap's answer
    0x48, 0x89, 0xdf, // mov rdi, rbx
    0xbe, 0x00, 0x20, 0x00, 0x00, // mov esi, 8192
    0xba, 0x04, 0x00, 0x00, 0x00, // mov edx, 4
    0xb8, 0x1c, 0x00, 0x00, 0x00, // mov eax, 28           ; madvise
    0x0f, 0x05, // syscall
    0x49, 0x89, 0x47, 0x18, // mov [r15+24], rax     ; report it
    0xeb, 0xfe, // done: jmp $
];

/// The thread that becomes RFC 0005 step 5's witness.
extern "C" fn ring3_memory(hhdm_base: u64) -> ! {
    use bhaskix_boot::VirtAddr;
    use bhaskix_mm::{Protection, VirtRange};
    use vm::AddressSpace;

    let stop = || -> ! { sched::exit() };
    let Ok(mut space) = AddressSpace::new(hhdm_base) else {
        stop()
    };
    for (at, pages, protection) in [
        (MEMORY_CODE_AT, 1, Protection::ReadExecute),
        (MEMORY_STACK_AT, 2, Protection::ReadWrite),
        (MEMORY_REPORT_AT, 1, Protection::ReadWrite),
    ] {
        let Some(range) = VirtRange::from_pages(VirtAddr(at), pages) else {
            stop()
        };
        if space.map_anonymous(range, protection).is_err() {
            stop()
        }
    }
    let (Some(code_pa), Some(report_pa)) = (
        space.translate(VirtAddr(MEMORY_CODE_AT)),
        space.translate(VirtAddr(MEMORY_REPORT_AT)),
    ) else {
        stop()
    };
    // SAFETY: a freshly mapped frame this space owns, filled through the
    // direct map; the executable mapping is never writable.
    unsafe {
        core::ptr::copy_nonoverlapping(
            MEMORY_CODE.as_ptr(),
            (hhdm_base + code_pa) as *mut u8,
            MEMORY_CODE.len(),
        );
    }
    MEMORY_REPORT_PA.store(report_pa, core::sync::atomic::Ordering::Release);
    // SAFETY: the higher half is copied from the running table.
    unsafe { vm::install(space) };
    // The domain note, for the same reason `enter_user` sets it: the syscall
    // entry reads it to decide which ABI this thread speaks, and a thread
    // entering ring 3 for the first time may not have been switched to on
    // this CPU. These probes enter directly rather than through `enter_user`
    // -- each builds its own space -- so each sets it. The memory probe found
    // this by being answered `BadSyscall`; the futex probe had been passing
    // on luck.
    if let Some(domain) = sched::current_domain() {
        telemetry::note_domain(domain.as_u32());
    }
    // SAFETY: the entry is in the user-executable page just written, `rsp`
    // one past two user-writable stack pages.
    unsafe {
        bhaskix_arch::syscall::enter_ring3(
            MEMORY_CODE_AT,
            MEMORY_STACK_AT + 2 * 4096,
            [MEMORY_REPORT_AT, 0],
        )
    }
}

/// RFC 0005 step 5's witness: a Linux program maps memory, uses the page the
/// lazy commit had to reach for, unmaps it, and is given advice-taking
/// silence by `madvise`.
fn memory_self_test(hhdm_base: u64, cpus: u32) -> bool {
    use core::sync::atomic::Ordering;

    if cpus < 2 {
        println!("\x1b[93m    linux memory   skipped, needs a second cpu\x1b[0m");
        return true;
    }
    const CPU: u32 = 3;

    let Ok(realm) = domain::create("mmap", domain::ResourceEnvelope::new()) else {
        println!("\x1b[91m    linux memory   FAILED: no domain\x1b[0m");
        return false;
    };
    if domain::with(realm, |owner| {
        owner.set_personality(domain::Personality::Linux)
    })
    .is_none()
    {
        println!("\x1b[91m    linux memory   FAILED: the tag would not set\x1b[0m");
        return false;
    }
    let options = sched::SpawnOptions::new()
        .pinned()
        .in_domain(realm.as_u32());
    if sched::spawn_on_with(CPU, "mmap", ring3_memory, hhdm_base, hhdm_base, options).is_err() {
        println!("\x1b[91m    linux memory   FAILED: the probe would not spawn\x1b[0m");
        return false;
    }

    let mut answers = [0u64; 4];
    let mut report_pa = 0;
    for _ in 0..400 {
        report_pa = MEMORY_REPORT_PA.load(Ordering::Acquire);
        if report_pa != 0 {
            // SAFETY: a frame the probe's space owns, through the direct map.
            answers = unsafe {
                [
                    core::ptr::read_volatile((hhdm_base + report_pa) as *const u64),
                    core::ptr::read_volatile((hhdm_base + report_pa + 8) as *const u64),
                    core::ptr::read_volatile((hhdm_base + report_pa + 16) as *const u64),
                    core::ptr::read_volatile((hhdm_base + report_pa + 24) as *const u64),
                ]
            };
            if answers[1] == 42 {
                break;
            }
        }
        wait_millis(5);
    }
    retire_probe(realm);

    // A plausible address, the pattern read back out of the second page,
    // and both of the calls that answer zero having answered zero.
    let mapped_somewhere = answers[0] >= 0x0000_7000_0000_0000 && answers[0] % 4096 == 0;
    // `security.md` §1 gap 3: a hosted process's `mmap` region is drawn per
    // process rather than bumped from one shared counter at a fixed base. The
    // floor is what a machine with no `RDRAND` gets — `bin/linuxd` falls back
    // rather than refusing to run a program — so the line says which world this
    // is, exactly as the IOMMU lines do, instead of implying the stronger one.
    let drawn = answers[0] != 0x0000_7000_0000_0000;
    if report_pa != 0 && mapped_somewhere && answers[1] == 42 && answers[2] == 0 && answers[3] == 0
    {
        println!(
            "    linux memory   a Linux program mapped two anonymous pages at {:#x}, wrote and \
             read 42 in the second (so the lazy commit reached it), unmapped them, and had its \
             madvise taken as advice",
            answers[0]
        );
        if drawn {
            println!(
                "    linux aslr     the hosted mmap base was drawn, not fixed: {:#x}, {} bits \
                 page-granular above the floor",
                answers[0], 28
            );
        } else {
            println!(
                "\x1b[93m    linux aslr     the hosted mmap base is the floor -- this machine \
                 drew no entropy, so the layout is known\x1b[0m"
            );
        }
        true
    } else {
        println!(
            "\x1b[91m    linux memory   FAILED: mmap {:#x}, read back {}, munmap {}, madvise \
             {}\x1b[0m",
            answers[0], answers[1], answers[2] as i64, answers[3] as i64
        );
        false
    }
}

/// Where the signal probe's report page lands physically.
static SIGNAL_REPORT_PA: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// The signal probe, hand-assembled. RFC 0005 step 4's witness, and it does
/// exactly what Go's runtime does with a fault:
///
/// 1. installs a `SIGSEGV` handler with `rt_sigaction`, `SA_RESTORER`
///    pointing at its own two-instruction restorer;
/// 2. dereferences null on purpose;
/// 3. in the handler, reads `cr2` out of the `ucontext` it was handed,
///    stores it, then **edits the saved `rip`** to point past the faulting
///    instruction and returns through the restorer;
/// 4. having resumed where it said, records that it got there and spins.
///
/// If any link is wrong the probe never reaches step 4: a wrong `ucontext`
/// offset stores the wrong `cr2`, a wrong `rip` slot resumes into the fault
/// again, and a broken `rt_sigreturn` never resumes at all.
const SIGNAL_CODE: [u8; 103] = [
    0x49, 0x89, 0xff, // mov r15, rdi          ; the report page
    0x6a, 0x00, // push 0                ; sa_mask
    0x48, 0x8d, 0x05, 0x52, 0x00, 0x00, 0x00, // lea rax, [rip+restorer]
    0x50, // push rax              ; sa_restorer
    0xb8, 0x04, 0x00, 0x00, 0x04, // mov eax, SA_SIGINFO|SA_RESTORER
    0x50, // push rax              ; sa_flags
    0x48, 0x8d, 0x05, 0x27, 0x00, 0x00, 0x00, // lea rax, [rip+handler]
    0x50, // push rax              ; sa_handler
    0x48, 0x89, 0xe6, // mov rsi, rsp          ; act
    0xbf, 0x0b, 0x00, 0x00, 0x00, // mov edi, 11           ; SIGSEGV
    0x31, 0xd2, // xor edx, edx          ; oldact
    0x41, 0xba, 0x08, 0x00, 0x00, 0x00, // mov r10d, 8           ; sigsetsize
    0xb8, 0x0d, 0x00, 0x00, 0x00, // mov eax, 13           ; rt_sigaction
    0x0f, 0x05, // syscall
    0x31, 0xc0, // xor eax, eax
    0x48, 0x8b, 0x00, // mov rax, [rax]        ; #PF at null, 3 bytes
    0x49, 0xc7, 0x47, 0x08, 0x01, 0x00, 0x00, 0x00, // mov qword [r15+8], 1  ; resumed
    0xeb, 0xfe, // jmp $
    0x48, 0x8b, 0x82, 0xd0, 0x00, 0x00, 0x00, // mov rax, [rdx+0xd0]   ; ucontext cr2
    0x49, 0x89, 0x07, // mov [r15], rax        ; report it
    0x48, 0x8b, 0x82, 0xa8, 0x00, 0x00, 0x00, // mov rax, [rdx+0xa8]   ; saved rip
    0x48, 0x83, 0xc0, 0x03, // add rax, 3            ; past the faulting mov
    0x48, 0x89, 0x82, 0xa8, 0x00, 0x00, 0x00, // mov [rdx+0xa8], rax   ; edit it
    0xc3, // ret                   ; into the restorer
    0xb8, 0x0f, 0x00, 0x00, 0x00, // mov eax, 15           ; rt_sigreturn
    0x0f, 0x05, // syscall
    0xeb, 0xfe, // jmp $                 ; never reached
];

/// Where the signal probe's code, stack and report live in its own space.
const SIGNAL_CODE_AT: u64 = 0x0000_0000_3000_0000;
const SIGNAL_STACK_AT: u64 = 0x0000_0000_3001_0000;
const SIGNAL_REPORT_AT: u64 = 0x0000_0000_3002_0000;

/// The thread that becomes RFC 0005 step 4's witness.
extern "C" fn ring3_signal(hhdm_base: u64) -> ! {
    use bhaskix_boot::VirtAddr;
    use bhaskix_mm::{Protection, VirtRange};
    use vm::AddressSpace;

    let stop = || -> ! { sched::exit() };
    let Ok(mut space) = AddressSpace::new(hhdm_base) else {
        stop()
    };
    for (at, pages, protection) in [
        (SIGNAL_CODE_AT, 1, Protection::ReadExecute),
        (SIGNAL_STACK_AT, 4, Protection::ReadWrite),
        (SIGNAL_REPORT_AT, 1, Protection::ReadWrite),
    ] {
        let Some(range) = VirtRange::from_pages(VirtAddr(at), pages) else {
            stop()
        };
        if space.map_anonymous(range, protection).is_err() {
            stop()
        }
    }
    let (Some(code_pa), Some(report_pa)) = (
        space.translate(VirtAddr(SIGNAL_CODE_AT)),
        space.translate(VirtAddr(SIGNAL_REPORT_AT)),
    ) else {
        stop()
    };
    // SAFETY: a freshly mapped anonymous frame this space owns, filled
    // through the direct map -- the executable mapping is never writable.
    unsafe {
        core::ptr::copy_nonoverlapping(
            SIGNAL_CODE.as_ptr(),
            (hhdm_base + code_pa) as *mut u8,
            SIGNAL_CODE.len(),
        );
    }
    SIGNAL_REPORT_PA.store(report_pa, core::sync::atomic::Ordering::Release);
    // SAFETY: the higher half is copied from the running table.
    unsafe { vm::install(space) };
    // The domain note, for the same reason `enter_user` sets it: the syscall
    // entry reads it to decide which ABI this thread speaks, and a thread
    // entering ring 3 for the first time may not have been switched to on
    // this CPU. These probes enter directly rather than through `enter_user`
    // -- each builds its own space -- so each sets it. The memory probe found
    // this by being answered `BadSyscall`; the futex probe had been passing
    // on luck.
    if let Some(domain) = sched::current_domain() {
        telemetry::note_domain(domain.as_u32());
    }
    // SAFETY: the entry is inside the user-executable page just written;
    // `rsp` is one past four user-writable stack pages -- the signal frame
    // is built below it, so the room is deliberate; `RSP0` was set by the
    // ring 3 test.
    unsafe {
        bhaskix_arch::syscall::enter_ring3(
            SIGNAL_CODE_AT,
            SIGNAL_STACK_AT + 4 * 4096,
            [SIGNAL_REPORT_AT, 0],
        )
    }
}

/// RFC 0005 step 4's witness: a Linux program installs a `SIGSEGV` handler,
/// faults on purpose, reads the fault address out of the `ucontext` it was
/// handed, edits the saved `rip` to resume past the faulting instruction,
/// and returns through `rt_sigreturn` -- which is precisely how Go turns a
/// null dereference into a recovered panic.
fn signal_self_test(hhdm_base: u64, cpus: u32) -> bool {
    use core::sync::atomic::Ordering;

    if cpus < 2 {
        println!("\x1b[93m    linux signal   skipped, needs a second cpu\x1b[0m");
        return true;
    }
    const CPU: u32 = 3;

    // **Delivery is counted where delivery happens, which is no longer
    // here.** The kernel's own `DELIVERED` counter went with the dispositions
    // to `bin/linuxd` (RFC 0032 step 7); what the kernel still knows is how
    // many faults it *resumed* on the personality's say-so, which is the same
    // event seen from the side that performed it.
    let delivered_before = fault::RESUMED.load(Ordering::Relaxed);
    let returned_before = syscall::RESTORED.load(Ordering::Relaxed);
    // Counted so a failure can say *which* failure it is. A probe that made
    // no foreign call at all was dispatched natively -- its dialect was
    // judged wrong -- and one that made calls and still delivered no signal
    // failed somewhere in `signal`. The two have nothing in common but the
    // report line they used to share.
    let foreign_before = syscall::FOREIGN_CALLS.load(Ordering::Relaxed);
    let Ok(realm) = domain::create("sigsegv", domain::ResourceEnvelope::new()) else {
        println!("\x1b[91m    linux signal   FAILED: no domain\x1b[0m");
        return false;
    };
    if domain::with(realm, |owner| {
        owner.set_personality(domain::Personality::Linux)
    })
    .is_none()
    {
        println!("\x1b[91m    linux signal   FAILED: the tag would not set\x1b[0m");
        return false;
    }
    let options = sched::SpawnOptions::new()
        .pinned()
        .in_domain(realm.as_u32());
    if sched::spawn_on_with(CPU, "sigsegv", ring3_signal, hhdm_base, hhdm_base, options).is_err() {
        println!("\x1b[91m    linux signal   FAILED: the probe would not spawn\x1b[0m");
        return false;
    }

    // The probe reports the fault address, then -- only if it resumed where
    // the handler said -- a one. Bounded, paced.
    let mut answers = [0u64; 2];
    let mut report_pa = 0;
    for _ in 0..400 {
        report_pa = SIGNAL_REPORT_PA.load(Ordering::Acquire);
        if report_pa != 0 {
            // SAFETY: a frame the probe's space owns, through the direct map.
            answers = unsafe {
                [
                    core::ptr::read_volatile((hhdm_base + report_pa) as *const u64),
                    core::ptr::read_volatile((hhdm_base + report_pa + 8) as *const u64),
                ]
            };
            if answers[1] == 1 {
                break;
            }
        }
        wait_millis(5);
    }
    retire_probe(realm);

    let delivered = fault::RESUMED.load(Ordering::Relaxed) - delivered_before;
    let returned = syscall::RESTORED.load(Ordering::Relaxed) - returned_before;
    if report_pa != 0 && answers[0] == 0 && answers[1] == 1 && delivered == 1 && returned == 1 {
        println!(
            "    linux signal   a Linux program faulted on purpose, its SIGSEGV handler read \
             cr2 0x0 out of the ucontext, edited the saved rip, and rt_sigreturn resumed it \
             where it said: 1 delivered, 1 returned"
        );
        true
    } else {
        let foreign = syscall::FOREIGN_CALLS.load(Ordering::Relaxed) - foreign_before;
        println!(
            "\x1b[91m    linux signal   FAILED: cr2 {:#x}, resumed {}, delivered {delivered}, \
             returned {returned}, {foreign} foreign calls\x1b[0m",
            answers[0], answers[1]
        );
        false
    }
}

/// Where the auxv-reading probe's report page lands physically.
static AUXV_REPORT_PA: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// The auxv-reading probe, hand-assembled: walks the initial stack the way
/// a real `_start` does — over `argv`, over `envp`, then pair by pair
/// through the auxiliary vector — finds `AT_RANDOM` (25), copies the two
/// entropy words it points at into its report page beside `argc` and
/// `AT_ENTRY`, and spins. RFC 0005 step 3's witness: the image is right
/// only if a program that reads it the way Go does finds what was put there.
///
/// ```text
///   rsp -> argc, argv..., NULL, envp..., NULL, (type,value)..., AT_NULL
///   rdi =  the report page
/// ```
const AUXV_CODE: [u8; 81] = [
    0x48, 0x8b, 0x04, 0x24, //             mov rax, [rsp]        ; argc
    0x48, 0x89, 0x07, //                   mov [rdi], rax
    0x48, 0x8d, 0x74, 0x24, 0x08, //       lea rsi, [rsp+8]      ; &argv[0]
    0x48, 0x8d, 0x34, 0xc6, //             lea rsi, [rsi+rax*8]  ; past argv
    0x48, 0x83, 0xc6, 0x08, //             add rsi, 8            ; past NULL
    // skip envp: advance until the word is zero
    0x48, 0x8b, 0x06, //             1:    mov rax, [rsi]
    0x48, 0x83, 0xc6, 0x08, //             add rsi, 8
    0x48, 0x85, 0xc0, //                   test rax, rax
    0x75, 0xf4, //                         jnz 1b
    // walk auxv pairs looking for AT_RANDOM (25) and AT_ENTRY (9)
    0x48, 0x8b, 0x06, //             2:    mov rax, [rsi]        ; type
    0x48, 0x8b, 0x5e, 0x08, //             mov rbx, [rsi+8]      ; value
    0x48, 0x83, 0xc6, 0x10, //             add rsi, 16
    0x48, 0x83, 0xf8, 0x09, //             cmp rax, 9            ; AT_ENTRY
    0x75, 0x04, //                         jne 3f
    0x48, 0x89, 0x5f, 0x08, //             mov [rdi+8], rbx
    0x48, 0x83, 0xf8, 0x19, //       3:    cmp rax, 25           ; AT_RANDOM
    0x75, 0x0f, //                         jne 4f   (over 15 bytes)
    0x48, 0x8b, 0x0b, //                   mov rcx, [rbx]        ; entropy lo
    0x48, 0x89, 0x4f, 0x10, //             mov [rdi+16], rcx
    0x48, 0x8b, 0x4b, 0x08, //             mov rcx, [rbx+8]      ; entropy hi
    0x48, 0x89, 0x4f, 0x18, //             mov [rdi+24], rcx
    0x48, 0x85, 0xc0, //             4:    test rax, rax         ; AT_NULL?
    0x75, 0xd1, //                         jnz 2b   (47 bytes back)
    0xeb, 0xfe, //                         jmp $
];

/// The Linux-shaped probe, hand-assembled: `getpid`, `write` and
/// `exit_group`, each answer stored where `rdi` points -- then a spin,
/// because a program whose every exit is refused has no way out at all:
/// its own `exit_group` came back `-ENOSYS` two instructions ago. The
/// test that made the domain destroys it, which is also the supervisor
/// story a real Linux workload will live under until exit translates.
/// (The first version ended on `ud2` instead, and its perfectly
/// intentional fault dump tripped the shell test's blanket no-EXCEPTION
/// check -- an instrument should not have to be excused from other
/// instruments.)
const FOREIGNER_CODE: [u8; 105] = [
    0xb8, 0x27, 0x00, 0x00, 0x00, // mov eax, 39   (getpid)
    0x0f, 0x05, //                   syscall
    0x48, 0x89, 0x07, //             mov [rdi], rax
    0xb8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1    (write)
    0x0f, 0x05, //                   syscall
    0x48, 0x89, 0x47, 0x08, //       mov [rdi+8], rax
    // The smuggle. Each of the five numbers below is one of RFC 0008's
    // syscall kinds -- 0 Invoke, 2 Reply, 3 Recv, 4 Yield, 5 Exit -- and
    // also an ordinary Linux call number this personality does not answer.
    // A Linux program cannot name a capability, so the only way it could
    // reach the native interface is by a number this kernel read in the
    // wrong dialect. Each answer goes in the report; each must be -ENOSYS.
    0xb8, 0x00, 0x00, 0x00, 0x00, // mov eax, 0    (read / Invoke)
    0x0f, 0x05, //                   syscall
    0x48, 0x89, 0x47, 0x18, //       mov [rdi+24], rax
    0xb8, 0x02, 0x00, 0x00, 0x00, // mov eax, 2    (open / Reply)
    0x0f, 0x05, //                   syscall
    0x48, 0x89, 0x47, 0x20, //       mov [rdi+32], rax
    0xb8, 0x03, 0x00, 0x00, 0x00, // mov eax, 3    (close / Recv)
    0x0f, 0x05, //                   syscall
    0x48, 0x89, 0x47, 0x28, //       mov [rdi+40], rax
    0xb8, 0x04, 0x00, 0x00, 0x00, // mov eax, 4    (stat / Yield)
    0x0f, 0x05, //                   syscall
    0x48, 0x89, 0x47, 0x30, //       mov [rdi+48], rax
    0xb8, 0x05, 0x00, 0x00, 0x00, // mov eax, 5    (fstat / Exit)
    0x0f, 0x05, //                   syscall
    0x48, 0x89, 0x47, 0x38, //       mov [rdi+56], rax
    // Reached only if the line above did not end this thread, which is the
    // single strongest observation in this probe: read natively, 5 is Exit.
    0x48, 0xc7, 0x47, 0x40, 0x01, 0x00, 0x00, 0x00, // mov qword [rdi+64], 1
    // **The sentinel that makes the next slot mean something.** The claim is
    // that `exit` never returns, and the slot below is how it is read -- but
    // a fresh page is already zero, so a zero there proved nothing and an
    // `exit` that came back answering zero would have looked identical. It
    // did, when RFC 0032 step 9 moved the call to ring 3 and armed the gate.
    // Seeded, the slot holds this value if and only if the store after the
    // call never ran.
    0x48, 0xc7, 0x47, 0x10, 0x17, 0xe2, 0x00, 0x00, // mov qword [rdi+16], 0xe217
    0xb8, 0x3c, 0x00, 0x00, 0x00, // mov eax, 60   (exit)
    0x0f, 0x05, //                   syscall
    0x48, 0x89, 0x47, 0x10, //       mov [rdi+16], rax
    0xeb, 0xfe, //                   jmp $ -- spin; the test puts it down
];

/// Where the foreigner's code and report pages sit in its own space.
const FOREIGNER_CODE_AT: u64 = 0x0000_0000_1000_0000;
const FOREIGNER_REPORT_AT: u64 = 0x0000_0000_1001_0000;

/// Where the exec probe's code and path live in its own space.
const EXEC_PROBE_CODE_AT: u64 = 0x0000_0000_1200_0000;

/// The exec probe, hand-assembled: it asks its pid, calls `execve`, and — if
/// the call ever comes back, which is the failure this watches for — spins.
///
/// **RFC 0033 step 5's witness.** The pid it reads is the one the adapter gave
/// it; the program it execs into reads the pid again and prints a line. The
/// two numbers being equal across a *domain change* is the claim, and nothing
/// inside one domain can make it.
///
/// The path sits at offset 33 and `rdi` is loaded with its address from `rip`:
/// a supervisor-built program has no loader to relocate anything for it, which
/// is exactly the constraint a hosted `execve` lives under.
#[rustfmt::skip]
const EXEC_PROBE_CODE: [u8; 44] = [
    0xb8, 0x27, 0x00, 0x00, 0x00,        // mov eax, 39           ; getpid
    0x0f, 0x05,                          // syscall
    0x49, 0x89, 0xc7,                    // mov r15, rax          ; keep it
    0x48, 0x8d, 0x3d, 0x10, 0x00, 0x00,  // lea rdi, [rip+16]     ; the path,
    0x00,                                //                       ; at offset 33
    0x31, 0xf6,                          // xor esi, esi          ; argv
    0x31, 0xd2,                          // xor edx, edx          ; envp
    0xb8, 0x3b, 0x00, 0x00, 0x00,        // mov eax, 59           ; execve
    0x0f, 0x05,                          // syscall
    // Only reached if the exec was refused, which is a failure this test can
    // name rather than a silence it has to guess at.
    0x48, 0x89, 0xc6,                    // mov rsi, rax
    0xeb, 0xfe,                          // jmp $
    // Offset 33: the path, and nothing after it.
    b'/', b'b', b'i', b'n', b'/', b'e', b'x', b'e', b'c', b'e', b'd',
];

/// Where the `/proc` probe's code lands in its own space.
///
/// The address is in the blob: the probe loads its two path strings by
/// absolute address, because they sit past its own code and a
/// supervisor-built program has no loader to relocate anything for it.
const PROC_PROBE_CODE_AT: u64 = 0x0000_0000_1700_0000;

/// The `/proc` probe, assembled by the same script as the last three — RFC
/// 0033 step 10.
///
/// It maps a page, then opens, reads and prints `/proc/self/status` and
/// `/proc/self/maps`. **The second is the interesting one**: the line it
/// prints for the page it just mapped is the personality's own region list,
/// written back to the program that made it, in Linux's format — and if the
/// two disagreed about where that page is, the line would say so.
#[rustfmt::skip]
const PROC_PROBE_CODE: [u8; 256] = [
    0xbf, 0x00, 0x00, 0x00, 0x52, 0xbe, 0x00, 0x10,
    0x00, 0x00, 0xba, 0x03, 0x00, 0x00, 0x00, 0x41,
    0xba, 0x32, 0x00, 0x00, 0x00, 0x49, 0xc7, 0xc0,
    0xff, 0xff, 0xff, 0xff, 0x4d, 0x31, 0xc9, 0xb8,
    0x09, 0x00, 0x00, 0x00, 0x0f, 0x05, 0x48, 0x3d,
    0x00, 0x00, 0x00, 0x52, 0x0f, 0x85, 0x9a, 0x00,
    0x00, 0x00, 0x48, 0xc7, 0xc7, 0xd8, 0x00, 0x00,
    0x17, 0x31, 0xf6, 0x31, 0xd2, 0xb8, 0x02, 0x00,
    0x00, 0x00, 0x0f, 0x05, 0x48, 0x85, 0xc0, 0x0f,
    0x88, 0x7f, 0x00, 0x00, 0x00, 0x48, 0x89, 0xc7,
    0x48, 0xc7, 0xc6, 0x00, 0x00, 0x00, 0x52, 0xba,
    0x00, 0x02, 0x00, 0x00, 0x31, 0xc0, 0x0f, 0x05,
    0x48, 0x85, 0xc0, 0x0f, 0x8e, 0x63, 0x00, 0x00,
    0x00, 0x48, 0x89, 0xc2, 0x48, 0xc7, 0xc6, 0x00,
    0x00, 0x00, 0x52, 0xbf, 0x01, 0x00, 0x00, 0x00,
    0xb8, 0x01, 0x00, 0x00, 0x00, 0x0f, 0x05, 0x48,
    0xc7, 0xc7, 0xf0, 0x00, 0x00, 0x17, 0x31, 0xf6,
    0x31, 0xd2, 0xb8, 0x02, 0x00, 0x00, 0x00, 0x0f,
    0x05, 0x48, 0x85, 0xc0, 0x0f, 0x88, 0x32, 0x00,
    0x00, 0x00, 0x48, 0x89, 0xc7, 0x48, 0xc7, 0xc6,
    0x00, 0x00, 0x00, 0x52, 0xba, 0x00, 0x02, 0x00,
    0x00, 0x31, 0xc0, 0x0f, 0x05, 0x48, 0x85, 0xc0,
    0x0f, 0x8e, 0x16, 0x00, 0x00, 0x00, 0x48, 0x89,
    0xc2, 0x48, 0xc7, 0xc6, 0x00, 0x00, 0x00, 0x52,
    0xbf, 0x01, 0x00, 0x00, 0x00, 0xb8, 0x01, 0x00,
    0x00, 0x00, 0x0f, 0x05, 0x31, 0xff, 0xb8, 0xe7,
    0x00, 0x00, 0x00, 0x0f, 0x05, 0xeb, 0xfe, 0x00,
    0x2f, 0x70, 0x72, 0x6f, 0x63, 0x2f, 0x73, 0x65,
    0x6c, 0x66, 0x2f, 0x73, 0x74, 0x61, 0x74, 0x75,
    0x73, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x2f, 0x70, 0x72, 0x6f, 0x63, 0x2f, 0x73, 0x65,
    0x6c, 0x66, 0x2f, 0x6d, 0x61, 0x70, 0x73, 0x00,
];

/// The line `/proc/self/maps` must carry for the page the probe maps.
///
/// **Not printed by the kernel**, for the reason the fork probe's marker
/// records: a report line that quoted this would match the gate looking for
/// it, and the gate would pass on a boot where the file was never read.
#[expect(dead_code, reason = "the gate reads it from the log, not the kernel")]
const PROC_PROBE_MAPPING: &str = "0000000052000000-0000000052001000 rw-p";

/// Where the wait probe's code lands in its own space.
const WAIT_PROBE_CODE_AT: u64 = 0x0000_0000_1600_0000;

/// The wait probe, assembled by the same script as the last two — RFC 0033
/// step 9.
///
/// The parent forks; the child ends with `exit_group(7)`; the parent `wait4`s,
/// takes the status word Linux encodes, and prints `s=7`. **Seven is the
/// number**: it is in the child's register at the moment it ends, it travels
/// into the record, it comes back through `wait4` shifted eight bits left, and
/// the parent shifts it back. A `wait` that invented a status would print `s=0`
/// — which is what the record held until this step, and what the boot said
/// before it.
///
/// Like the fork probe, it maps a page and writes the routine into it, because
/// a forked child can only run in memory the personality knows about.
#[rustfmt::skip]
const WAIT_PROBE_CODE: [u8; 430] = [
    0xbf, 0x00, 0x00, 0x00, 0x51, 0xbe, 0x00, 0x10,
    0x00, 0x00, 0xba, 0x03, 0x00, 0x00, 0x00, 0x41,
    0xba, 0x32, 0x00, 0x00, 0x00, 0x49, 0xc7, 0xc0,
    0xff, 0xff, 0xff, 0xff, 0x4d, 0x31, 0xc9, 0xb8,
    0x09, 0x00, 0x00, 0x00, 0x0f, 0x05, 0x48, 0x3d,
    0x00, 0x00, 0x00, 0x51, 0x0f, 0x85, 0x71, 0x01,
    0x00, 0x00, 0x48, 0xc7, 0xc1, 0x00, 0x00, 0x00,
    0x51, 0x48, 0xb8, 0xb8, 0x39, 0x00, 0x00, 0x00,
    0x0f, 0x05, 0x48, 0x48, 0x89, 0x81, 0x00, 0x00,
    0x00, 0x00, 0x48, 0xb8, 0x85, 0xc0, 0x74, 0x5f,
    0x48, 0xc7, 0xc7, 0xff, 0x48, 0x89, 0x81, 0x08,
    0x00, 0x00, 0x00, 0x48, 0xb8, 0xff, 0xff, 0xff,
    0xbe, 0x00, 0x00, 0x01, 0x51, 0x48, 0x89, 0x81,
    0x10, 0x00, 0x00, 0x00, 0x48, 0xb8, 0x31, 0xd2,
    0x4d, 0x31, 0xd2, 0xb8, 0x3d, 0x00, 0x48, 0x89,
    0x81, 0x18, 0x00, 0x00, 0x00, 0x48, 0xb8, 0x00,
    0x00, 0x0f, 0x05, 0x48, 0x85, 0xc0, 0x7e, 0x48,
    0x89, 0x81, 0x20, 0x00, 0x00, 0x00, 0x48, 0xb8,
    0x37, 0x48, 0xc7, 0xc1, 0x00, 0x00, 0x01, 0x51,
    0x48, 0x89, 0x81, 0x28, 0x00, 0x00, 0x00, 0x48,
    0xb8, 0x8b, 0x01, 0xc1, 0xe8, 0x08, 0x25, 0xff,
    0x00, 0x48, 0x89, 0x81, 0x30, 0x00, 0x00, 0x00,
    0x48, 0xb8, 0x00, 0x00, 0x0c, 0x30, 0x88, 0x41,
    0x0a, 0xc6, 0x48, 0x89, 0x81, 0x38, 0x00, 0x00,
    0x00, 0x48, 0xb8, 0x41, 0x08, 0x73, 0xc6, 0x41,
    0x09, 0x3d, 0xc6, 0x48, 0x89, 0x81, 0x40, 0x00,
    0x00, 0x00, 0x48, 0xb8, 0x41, 0x0b, 0x0a, 0xbf,
    0x01, 0x00, 0x00, 0x00, 0x48, 0x89, 0x81, 0x48,
    0x00, 0x00, 0x00, 0x48, 0xb8, 0x48, 0x8d, 0x71,
    0x08, 0xba, 0x04, 0x00, 0x00, 0x48, 0x89, 0x81,
    0x50, 0x00, 0x00, 0x00, 0x48, 0xb8, 0x00, 0xb8,
    0x01, 0x00, 0x00, 0x00, 0x0f, 0x05, 0x48, 0x89,
    0x81, 0x58, 0x00, 0x00, 0x00, 0x48, 0xb8, 0x31,
    0xff, 0xb8, 0xe7, 0x00, 0x00, 0x00, 0x0f, 0x48,
    0x89, 0x81, 0x60, 0x00, 0x00, 0x00, 0x48, 0xb8,
    0x05, 0xeb, 0xfe, 0xbf, 0x07, 0x00, 0x00, 0x00,
    0x48, 0x89, 0x81, 0x68, 0x00, 0x00, 0x00, 0x48,
    0xb8, 0xb8, 0xe7, 0x00, 0x00, 0x00, 0x0f, 0x05,
    0xeb, 0x48, 0x89, 0x81, 0x70, 0x00, 0x00, 0x00,
    0x48, 0xb8, 0xfe, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x48, 0x89, 0x81, 0x78, 0x00, 0x00,
    0x00, 0xbf, 0x00, 0x00, 0x00, 0x51, 0xbe, 0x00,
    0x10, 0x00, 0x00, 0xba, 0x05, 0x00, 0x00, 0x00,
    0xb8, 0x0a, 0x00, 0x00, 0x00, 0x0f, 0x05, 0x48,
    0x85, 0xc0, 0x0f, 0x85, 0x3b, 0x00, 0x00, 0x00,
    0xbf, 0x00, 0x00, 0x01, 0x51, 0xbe, 0x00, 0x10,
    0x00, 0x00, 0xba, 0x03, 0x00, 0x00, 0x00, 0x41,
    0xba, 0x32, 0x00, 0x00, 0x00, 0x49, 0xc7, 0xc0,
    0xff, 0xff, 0xff, 0xff, 0x4d, 0x31, 0xc9, 0xb8,
    0x09, 0x00, 0x00, 0x00, 0x0f, 0x05, 0x48, 0x3d,
    0x00, 0x00, 0x01, 0x51, 0x0f, 0x85, 0x09, 0x00,
    0x00, 0x00, 0x48, 0xc7, 0xc0, 0x00, 0x00, 0x00,
    0x51, 0xff, 0xe0, 0x31, 0xff, 0xb8, 0xe7, 0x00,
    0x00, 0x00, 0x0f, 0x05, 0xeb, 0xfe,
];

/// What the child exits with, and the parent must print.
///
/// **Not named in the report line, and that is deliberate**: the gate looks for
/// these bytes in the log, and a kernel line quoting them would match it — the
/// fork probe's marker did exactly that one step ago, and two arms that should
/// have gone red stayed green.
#[expect(dead_code, reason = "the gate reads it from the log, not the kernel")]
const WAIT_PROBE_STATUS: &str = "s=7";

/// Where the fork probe's code lands in its own space.
const FORK_PROBE_CODE_AT: u64 = 0x0000_0000_1500_0000;

/// The fork probe, hand-assembled — RFC 0033 step 8.
///
/// **What it proves is that the *memory* was copied.** The parent `mmap`s a
/// page, writes eight bytes into it, forks, and yields; the child prints what
/// is at that address in **its own** address space.
///
/// The `mmap` is not decoration: a fork copies the regions the *personality*
/// knows about, and the personality knows about a region because it answered
/// the `mmap` that made it. This probe's code and stack were mapped by the
/// kernel before it ran, so they are invisible to the adapter and are not
/// copied — which is exactly right for a program the kernel starts by hand,
/// and would be wrong for one an `execve` built. Stated here because the first
/// version of this probe wrote its marker into a kernel-mapped page and the
/// record honestly said `0 bytes copied`. A fork that made a domain and
/// started a thread but copied nothing would print eight zeros; one that
/// shared the page rather than copying it would be a different bug with the
/// same output, which is why the child writes and the parent does not.
///
/// The child is entered through a trampoline `bin/linuxd` writes, so `rax` is
/// zero there and the parent sees the child's pid — the one branch this blob
/// takes.
///
/// **The probe forks from memory it mapped itself, and that is the whole
/// shape of what a fork can copy.** A fork copies the regions the
/// *personality* knows about, and the personality knows a region because it
/// answered the `mmap` that made it. This probe's own code and stack were
/// mapped by the kernel before it ran, so they are invisible to the adapter —
/// and a child whose `rip` pointed into them would jump into memory its space
/// does not have. So the probe maps a page, **writes the forking routine into
/// it eight bytes at a time**, makes it executable, maps a second page for the
/// data, and jumps in. Everything the child needs is then a region the adapter
/// recorded.
///
/// Two earlier versions of this probe failed exactly there: the first wrote
/// its marker into a kernel-mapped page and the record honestly said `0 bytes
/// copied`; the second copied the page but left the child jumping into code
/// its space did not contain, and the fault counter went up by one.
///
/// **Both addresses are constants**, because a child arrives with `rax`, its
/// stack pointer and its instruction pointer and *nothing else* — the parent's
/// other registers exist only in the CPU, and the entry stub saves the
/// caller-saved set alone.
///
/// Assembled by the same script as the pipe probe: the branch displacement
/// below is its output, not a count.
#[rustfmt::skip]
const FORK_PROBE_CODE: [u8; 447] = [
    0xbf, 0x00, 0x00, 0x00, 0x50, 0xbe, 0x00, 0x10,
    0x00, 0x00, 0xba, 0x03, 0x00, 0x00, 0x00, 0x41,
    0xba, 0x32, 0x00, 0x00, 0x00, 0x49, 0xc7, 0xc0,
    0xff, 0xff, 0xff, 0xff, 0x4d, 0x31, 0xc9, 0xb8,
    0x09, 0x00, 0x00, 0x00, 0x0f, 0x05, 0x48, 0x3d,
    0x00, 0x00, 0x00, 0x50, 0x0f, 0x85, 0x82, 0x01,
    0x00, 0x00, 0x48, 0xc7, 0xc1, 0x00, 0x00, 0x00,
    0x50, 0x48, 0xb8, 0x48, 0xb8, 0x63, 0x6f, 0x70,
    0x69, 0x65, 0x64, 0x48, 0x89, 0x81, 0x00, 0x00,
    0x00, 0x00, 0x48, 0xb8, 0x21, 0x0a, 0x48, 0xc7,
    0xc1, 0x00, 0x00, 0x01, 0x48, 0x89, 0x81, 0x08,
    0x00, 0x00, 0x00, 0x48, 0xb8, 0x50, 0x48, 0x89,
    0x01, 0xb8, 0x39, 0x00, 0x00, 0x48, 0x89, 0x81,
    0x10, 0x00, 0x00, 0x00, 0x48, 0xb8, 0x00, 0x0f,
    0x05, 0x48, 0x85, 0xc0, 0x74, 0x43, 0x48, 0x89,
    0x81, 0x18, 0x00, 0x00, 0x00, 0x48, 0xb8, 0xb8,
    0x18, 0x00, 0x00, 0x00, 0x0f, 0x05, 0xb8, 0x48,
    0x89, 0x81, 0x20, 0x00, 0x00, 0x00, 0x48, 0xb8,
    0x18, 0x00, 0x00, 0x00, 0x0f, 0x05, 0xb8, 0x18,
    0x48, 0x89, 0x81, 0x28, 0x00, 0x00, 0x00, 0x48,
    0xb8, 0x00, 0x00, 0x00, 0x0f, 0x05, 0xb8, 0x18,
    0x00, 0x48, 0x89, 0x81, 0x30, 0x00, 0x00, 0x00,
    0x48, 0xb8, 0x00, 0x00, 0x0f, 0x05, 0xb8, 0x18,
    0x00, 0x00, 0x48, 0x89, 0x81, 0x38, 0x00, 0x00,
    0x00, 0x48, 0xb8, 0x00, 0x0f, 0x05, 0xb8, 0x18,
    0x00, 0x00, 0x00, 0x48, 0x89, 0x81, 0x40, 0x00,
    0x00, 0x00, 0x48, 0xb8, 0x0f, 0x05, 0xb8, 0x18,
    0x00, 0x00, 0x00, 0x0f, 0x48, 0x89, 0x81, 0x48,
    0x00, 0x00, 0x00, 0x48, 0xb8, 0x05, 0xb8, 0x18,
    0x00, 0x00, 0x00, 0x0f, 0x05, 0x48, 0x89, 0x81,
    0x50, 0x00, 0x00, 0x00, 0x48, 0xb8, 0x31, 0xff,
    0xb8, 0xe7, 0x00, 0x00, 0x00, 0x0f, 0x48, 0x89,
    0x81, 0x58, 0x00, 0x00, 0x00, 0x48, 0xb8, 0x05,
    0xeb, 0xfe, 0xbf, 0x01, 0x00, 0x00, 0x00, 0x48,
    0x89, 0x81, 0x60, 0x00, 0x00, 0x00, 0x48, 0xb8,
    0xbe, 0x00, 0x00, 0x01, 0x50, 0xba, 0x08, 0x00,
    0x48, 0x89, 0x81, 0x68, 0x00, 0x00, 0x00, 0x48,
    0xb8, 0x00, 0x00, 0xb8, 0x01, 0x00, 0x00, 0x00,
    0x0f, 0x48, 0x89, 0x81, 0x70, 0x00, 0x00, 0x00,
    0x48, 0xb8, 0x05, 0x31, 0xff, 0xb8, 0x3c, 0x00,
    0x00, 0x00, 0x48, 0x89, 0x81, 0x78, 0x00, 0x00,
    0x00, 0x48, 0xb8, 0x0f, 0x05, 0xeb, 0xfe, 0x90,
    0x90, 0x90, 0x90, 0x48, 0x89, 0x81, 0x80, 0x00,
    0x00, 0x00, 0xbf, 0x00, 0x00, 0x00, 0x50, 0xbe,
    0x00, 0x10, 0x00, 0x00, 0xba, 0x05, 0x00, 0x00,
    0x00, 0xb8, 0x0a, 0x00, 0x00, 0x00, 0x0f, 0x05,
    0x48, 0x85, 0xc0, 0x0f, 0x85, 0x3b, 0x00, 0x00,
    0x00, 0xbf, 0x00, 0x00, 0x01, 0x50, 0xbe, 0x00,
    0x10, 0x00, 0x00, 0xba, 0x03, 0x00, 0x00, 0x00,
    0x41, 0xba, 0x32, 0x00, 0x00, 0x00, 0x49, 0xc7,
    0xc0, 0xff, 0xff, 0xff, 0xff, 0x4d, 0x31, 0xc9,
    0xb8, 0x09, 0x00, 0x00, 0x00, 0x0f, 0x05, 0x48,
    0x3d, 0x00, 0x00, 0x01, 0x50, 0x0f, 0x85, 0x09,
    0x00, 0x00, 0x00, 0x48, 0xc7, 0xc0, 0x00, 0x00,
    0x00, 0x50, 0xff, 0xe0, 0x31, 0xff, 0xb8, 0xe7,
    0x00, 0x00, 0x00, 0x0f, 0x05, 0xeb, 0xfe,
];

/// What the parent writes before forking, and the child must print.
///
/// **Deliberately not named in the report line.** The gate looks for these
/// bytes in the log, and a report line that contained them would match it —
/// so the boot would pass with the copy disabled, which is exactly what
/// happened when this was tried: two arms that should have gone red stayed
/// green because the kernel was quoting the marker at itself.
#[expect(dead_code, reason = "the gate reads it from the log, not the kernel")]
const FORK_PROBE_MARKER: &str = "copied!";

/// Where the pipe probe's code lands in its own space.
const PIPE_PROBE_CODE_AT: u64 = 0x0000_0000_1400_0000;

/// The pipe probe, hand-assembled — RFC 0033 step 7.
///
/// **It proves the blocking half, which is the half that is easy to get
/// wrong.** The parent makes a pipe, clones a thread, and reads — finding the
/// pipe empty, so it parks. The child yields twice so the parent is certainly
/// asleep, then writes; the parent wakes with the bytes and prints them. A
/// reader that was told "end of file" instead would print nothing, and a
/// reader that was never woken would hang and its domain would never end.
///
/// `rdi` is a writable page: the descriptor pair goes at its start, the child's
/// stack at `+0x800`, and the bytes read at `+64`.
///
/// **Every displacement in it was computed rather than counted.** Three earlier
/// probes in this file had a jump or a `lea` off by one because the padding and
/// the label were counted by hand; this one was laid out by a script that patches
/// its own branches, and the array below is that script's output.
#[rustfmt::skip]
const PIPE_PROBE_CODE: [u8; 179] = [
    0x49, 0x89, 0xfc, 0x31, 0xf6, 0xb8, 0x25, 0x01,
    0x00, 0x00, 0x0f, 0x05, 0x48, 0x85, 0xc0, 0x75,
    0x54, 0xbf, 0x00, 0x0f, 0x0d, 0x00, 0x4c, 0x89,
    0xe6, 0x48, 0x81, 0xc6, 0x00, 0x08, 0x00, 0x00,
    0x31, 0xd2, 0x4d, 0x31, 0xd2, 0x4d, 0x89, 0xe0,
    0x4c, 0x8d, 0x0d, 0x41, 0x00, 0x00, 0x00, 0xb8,
    0x38, 0x00, 0x00, 0x00, 0x0f, 0x05, 0x41, 0x8b,
    0x3c, 0x24, 0x4c, 0x89, 0xe6, 0x48, 0x83, 0xc6,
    0x40, 0xba, 0x20, 0x00, 0x00, 0x00, 0x31, 0xc0,
    0x0f, 0x05, 0x48, 0x85, 0xc0, 0x7e, 0x16, 0x48,
    0x89, 0xc2, 0x4c, 0x89, 0xe6, 0x48, 0x83, 0xc6,
    0x40, 0xbf, 0x01, 0x00, 0x00, 0x00, 0xb8, 0x01,
    0x00, 0x00, 0x00, 0x0f, 0x05, 0x31, 0xff, 0xb8,
    0xe7, 0x00, 0x00, 0x00, 0x0f, 0x05, 0xeb, 0xfe,
    0x49, 0x89, 0xfc, 0xb8, 0x18, 0x00, 0x00, 0x00,
    0x0f, 0x05, 0xb8, 0x18, 0x00, 0x00, 0x00, 0x0f,
    0x05, 0x41, 0x8b, 0x7c, 0x24, 0x04, 0x48, 0x8d,
    0x35, 0x17, 0x00, 0x00, 0x00, 0xba, 0x0f, 0x00,
    0x00, 0x00, 0xb8, 0x01, 0x00, 0x00, 0x00, 0x0f,
    0x05, 0x31, 0xff, 0xb8, 0x3c, 0x00, 0x00, 0x00,
    0x0f, 0x05, 0xeb, 0xfe, 0x74, 0x68, 0x72, 0x6f,
    0x75, 0x67, 0x68, 0x20, 0x61, 0x20, 0x70, 0x69,
    0x70, 0x65, 0x0a,
];

/// What the child writes, and what the parent must print. Fifteen bytes,
/// inside the blob at a fixed offset the assembler above computed.
const PIPE_PROBE_MESSAGE: &str = "through a pipe";

/// Where the file probe's code lands in its own space.
const FILE_PROBE_CODE_AT: u64 = 0x0000_0000_1300_0000;

/// The file probe, hand-assembled: it opens a real file, reads it and prints
/// what it read — RFC 0033 step 6.
///
/// **Every byte it prints came off a filesystem**, through a directory
/// capability `bin/linuxd` holds and a page the filesystem service lent it.
/// Nothing in this program knows what a file is; nothing in the kernel
/// answered any of its three calls.
///
/// It reads into the second half of its own page, which is the same page its
/// code is in — read-execute, so the read must go somewhere writable, and the
/// stack page is what that is. `rdi` carries the stack, `rsi` the path.
#[rustfmt::skip]
const FILE_PROBE_CODE: [u8; 71] = [
    0x49, 0x89, 0xfc,                    // mov r12, rdi          ; the buffer
    0x48, 0x89, 0xf7,                    // mov rdi, rsi          ; the name
    0x31, 0xf6,                          // xor esi, esi          ; O_RDONLY
    0x31, 0xd2,                          // xor edx, edx
    0xb8, 0x02, 0x00, 0x00, 0x00,        // mov eax, 2            ; open
    0x0f, 0x05,                          // syscall
    0x48, 0x85, 0xc0,                    // test rax, rax
    0x78, 0x26,                          // js done               ; refused
    0x48, 0x89, 0xc7,                    // mov rdi, rax          ; the descriptor
    0x4c, 0x89, 0xe6,                    // mov rsi, r12          ; where
    0xba, 0x28, 0x00, 0x00, 0x00,        // mov edx, 40           ; how much
    0x31, 0xc0,                          // xor eax, eax          ; read
    0x0f, 0x05,                          // syscall
    0x48, 0x85, 0xc0,                    // test rax, rax
    0x7e, 0x12,                          // jle done              ; nothing read
    0x48, 0x89, 0xc2,                    // mov rdx, rax          ; that many
    0x4c, 0x89, 0xe6,                    // mov rsi, r12
    0xbf, 0x01, 0x00, 0x00, 0x00,        // mov edi, 1            ; fd 1
    0xb8, 0x01, 0x00, 0x00, 0x00,        // mov eax, 1            ; write
    0x0f, 0x05,                          // syscall
    0x31, 0xff,                          // done: xor edi, edi
    0xb8, 0xe7, 0x00, 0x00, 0x00,        // mov eax, 231          ; exit_group
    0x0f, 0x05,                          // syscall
    0xeb, 0xfe,                          // jmp $
];

/// Where the socket probe's code lands in its own space.
const SOCKET_PROBE_CODE_AT: u64 = 0x0000_0000_1900_0000;

/// The socket probe, RFC 0005 step 9's witness: a hosted Linux program binds a
/// UDP socket and echoes a datagram to itself.
///
/// Assembled from [`tools/probes/linux-socketeer.s`](../../tools/probes/linux-socketeer.s)
/// by [`tools/probe-bytes.sh`](../../tools/probe-bytes.sh), which verifies its
/// transcription against the assembled binary.
///
/// **Over `[::1]` and not `127.0.0.1`, and that is a fact about this machine
/// rather than a preference.** `bin/ipd` reinjects a datagram addressed to
/// loopback so it never touches a device — and it does that for **v6 only**.
/// There is no v4 loopback in the service, so a hosted `sendto` to
/// `127.0.0.1` leaves and does not come back, and the receiving half of this
/// test could not exist. The v4 path is wired the same way and is *not*
/// demonstrated here; the trigger for demonstrating it is v4 loopback in
/// `bin/ipd`, which is that service's decision and not this step's.
///
/// Four calls, and the four bytes it prints went out through `bin/ipd` and
/// came back: no part of the adapter could have invented them.
#[rustfmt::skip]
const SOCKET_PROBE_CODE: [u8; 181] = [
    0x49, 0x89, 0xfc,                         // mov %rdi,%r12
    0x49, 0x89, 0xf6,                         // mov %rsi,%r14
    0xbf, 0x0a, 0x00, 0x00, 0x00,             // mov $0xa,%edi
    0xbe, 0x02, 0x00, 0x00, 0x00,             // mov $0x2,%esi
    0x31, 0xd2,                               // xor %edx,%edx
    0xb8, 0x29, 0x00, 0x00, 0x00,             // mov $0x29,%eax
    0x0f, 0x05,                               // syscall
    0x48, 0x85, 0xc0,                         // test %rax,%rax
    0x0f, 0x88, 0x88, 0x00, 0x00, 0x00,       // js aa <done>
    0x49, 0x89, 0xc5,                         // mov %rax,%r13
    0x4c, 0x89, 0xef,                         // mov %r13,%rdi
    0x4c, 0x89, 0xf6,                         // mov %r14,%rsi
    0xba, 0x1c, 0x00, 0x00, 0x00,             // mov $0x1c,%edx
    0xb8, 0x31, 0x00, 0x00, 0x00,             // mov $0x31,%eax
    0x0f, 0x05,                               // syscall
    0x48, 0x85, 0xc0,                         // test %rax,%rax
    0x78, 0x6e,                               // js aa <done>
    0x41, 0xc7, 0x04, 0x24, 0x64, 0x75, 0x70, 0x30, // movl $0x30707564,(%r12)
    0x4c, 0x89, 0xef,                         // mov %r13,%rdi
    0x4c, 0x89, 0xe6,                         // mov %r12,%rsi
    0xba, 0x04, 0x00, 0x00, 0x00,             // mov $0x4,%edx
    0x45, 0x31, 0xd2,                         // xor %r10d,%r10d
    0x4d, 0x89, 0xf0,                         // mov %r14,%r8
    0x41, 0xb9, 0x1c, 0x00, 0x00, 0x00,       // mov $0x1c,%r9d
    0xb8, 0x2c, 0x00, 0x00, 0x00,             // mov $0x2c,%eax
    0x0f, 0x05,                               // syscall
    0x48, 0x85, 0xc0,                         // test %rax,%rax
    0x78, 0x43,                               // js aa <done>
    0x41, 0xbf, 0x40, 0x00, 0x00, 0x00,       // mov $0x40,%r15d
    0x49, 0x8d, 0x74, 0x24, 0x40,             // lea 0x40(%r12),%rsi
    0x4c, 0x89, 0xef,                         // mov %r13,%rdi
    0xba, 0x04, 0x00, 0x00, 0x00,             // mov $0x4,%edx
    0x45, 0x31, 0xd2,                         // xor %r10d,%r10d
    0x45, 0x31, 0xc0,                         // xor %r8d,%r8d
    0x45, 0x31, 0xc9,                         // xor %r9d,%r9d
    0xb8, 0x2d, 0x00, 0x00, 0x00,             // mov $0x2d,%eax
    0x0f, 0x05,                               // syscall
    0x48, 0x85, 0xc0,                         // test %rax,%rax
    0x7f, 0x07,                               // jg 96 <arrived>
    0x41, 0xff, 0xcf,                         // dec %r15d
    0x75, 0xd9,                               // jne 6d <retry>
    0xeb, 0x14,                               // jmp aa <done>
    0x48, 0x89, 0xc2,                         // mov %rax,%rdx
    0x49, 0x8d, 0x74, 0x24, 0x40,             // lea 0x40(%r12),%rsi
    0xbf, 0x01, 0x00, 0x00, 0x00,             // mov $0x1,%edi
    0xb8, 0x01, 0x00, 0x00, 0x00,             // mov $0x1,%eax
    0x0f, 0x05,                               // syscall
    0x31, 0xff,                               // xor %edi,%edi
    0xb8, 0xe7, 0x00, 0x00, 0x00,             // mov $0xe7,%eax
    0x0f, 0x05,                               // syscall
    0xeb, 0xfe,                               // jmp b3 <done+0x9>
];

/// Where the socket the probe binds is placed: a `sockaddr_in6` for `[::1]`
/// on port 7777, past the code.
const SOCKET_PROBE_ADDRESS_AT: u64 = 256;
const _: () = assert!(
    SOCKET_PROBE_CODE.len() < SOCKET_PROBE_ADDRESS_AT as usize,
    "the socket probe's code has grown into the address beside it"
);

/// Where the directory probe's code lands in its own space.
const LIST_PROBE_CODE_AT: u64 = 0x0000_0000_1800_0000;

/// The directory probe, RFC 0005 step 8's witness: it lists the directory it
/// was given, then reads a file out of it by seeking to a length `fstat` told
/// it.
///
/// **Assembled by `as` and transcribed from `objdump`, not written by hand.**
/// The source is [`tools/probes/linux-lister.s`](../../tools/probes/linux-lister.s)
/// and the array below is what
/// [`tools/probe-bytes.sh`](../../tools/probe-bytes.sh) prints from it, so the
/// comments on the right are the disassembler's and a byte cannot drift from
/// its meaning. That script *verifies* rather than transcribes, and the
/// reason is written on it: the first version of it dropped `objdump`'s
/// continuation lines, shifted this probe by one byte, and produced a fault
/// in ring 3 that read exactly like a clobbered register.
///
/// It prints one five-letter name **four times** and then a line of the file,
/// and each printing is a different call's evidence:
///
/// 1. `open("/")` then `getdents64` — the directory this process was given,
///    which until this step could not be opened at all: every path had to
///    name something *inside* it. The name printed is off a filesystem image
///    and is one no part of the personality could invent.
/// 2. `lseek(dirfd, 0, SEEK_SET)` then `getdents64` again — the second
///    printing is the seek's, and only the seek's: a directory descriptor
///    left where the first listing finished answers the second call with
///    nothing, and the probe stops with one name on the console.
/// 3. `fstat(dirfd)`, printed only if `st_mode` says directory — so a mode
///    written to the wrong offset of the `struct stat`, or a kind taken from
///    the wrong field, stops the probe here rather than passing.
/// 4. `close(dirfd)` then `open("inner")` — the fourth printing is the close
///    guard's: the directory's handle is the adapter's own root capability
///    rather than a slot from its pool, and a `close` that gave it back would
///    take the filesystem away from every hosted process on the machine, so
///    this `open` would find nothing.
///
/// 5. `read` of that file, and printing what it read. **This is the second
///    file read on the machine**, and until
///    [RFC 0044](../../docs/rfc/0044-revocation-that-reaches-the-mapping.md)
///    it could not happen at all: the `linux file` probe reads one first, and
///    its lent page stayed mapped in the adapter because `method::REVOKE`
///    never unmapped anything — so this one's `ATTACH` was refused at an
///    address nothing appeared to be using. This step's own record says the
///    probe *deliberately did not read* for exactly that reason; it does now,
///    and that sentence is corrected there.
#[rustfmt::skip]
const LIST_PROBE_CODE: [u8; 416] = [
    0x49, 0x89, 0xfc,                         // mov %rdi,%r12
    0x49, 0x89, 0xf6,                         // mov %rsi,%r14
    0x48, 0x89, 0xf7,                         // mov %rsi,%rdi
    0x31, 0xf6,                               // xor %esi,%esi
    0x31, 0xd2,                               // xor %edx,%edx
    0xb8, 0x02, 0x00, 0x00, 0x00,             // mov $0x2,%eax
    0x0f, 0x05,                               // syscall
    0x48, 0x85, 0xc0,                         // test %rax,%rax
    0x0f, 0x88, 0x47, 0x01, 0x00, 0x00,       // js 164 <done>
    0x49, 0x89, 0xc5,                         // mov %rax,%r13
    0x4c, 0x89, 0xef,                         // mov %r13,%rdi
    0x4c, 0x89, 0xe6,                         // mov %r12,%rsi
    0xba, 0x00, 0x01, 0x00, 0x00,             // mov $0x100,%edx
    0xb8, 0xd9, 0x00, 0x00, 0x00,             // mov $0xd9,%eax
    0x0f, 0x05,                               // syscall
    0x48, 0x85, 0xc0,                         // test %rax,%rax
    0x0f, 0x8e, 0x29, 0x01, 0x00, 0x00,       // jle 164 <done>
    0xe8, 0x49, 0x01, 0x00, 0x00,             // callq 189 <say>
    0x4c, 0x89, 0xef,                         // mov %r13,%rdi
    0x31, 0xf6,                               // xor %esi,%esi
    0x31, 0xd2,                               // xor %edx,%edx
    0xb8, 0x08, 0x00, 0x00, 0x00,             // mov $0x8,%eax
    0x0f, 0x05,                               // syscall
    0x48, 0x85, 0xc0,                         // test %rax,%rax
    0x0f, 0x88, 0x0d, 0x01, 0x00, 0x00,       // js 164 <done>
    0x4c, 0x89, 0xef,                         // mov %r13,%rdi
    0x4c, 0x89, 0xe6,                         // mov %r12,%rsi
    0xba, 0x00, 0x01, 0x00, 0x00,             // mov $0x100,%edx
    0xb8, 0xd9, 0x00, 0x00, 0x00,             // mov $0xd9,%eax
    0x0f, 0x05,                               // syscall
    0x48, 0x85, 0xc0,                         // test %rax,%rax
    0x0f, 0x8e, 0xf2, 0x00, 0x00, 0x00,       // jle 164 <done>
    0xe8, 0x12, 0x01, 0x00, 0x00,             // callq 189 <say>
    0x49, 0x8d, 0xb4, 0x24, 0x00, 0x02, 0x00, 0x00, // lea 0x200(%r12),%rsi
    0x4c, 0x89, 0xef,                         // mov %r13,%rdi
    0xb8, 0x05, 0x00, 0x00, 0x00,             // mov $0x5,%eax
    0x0f, 0x05,                               // syscall
    0x48, 0x85, 0xc0,                         // test %rax,%rax
    0x0f, 0x88, 0xd2, 0x00, 0x00, 0x00,       // js 164 <done>
    0x41, 0x8b, 0x84, 0x24, 0x18, 0x02, 0x00, 0x00, // mov 0x218(%r12),%eax
    0x25, 0x00, 0xf0, 0x00, 0x00,             // and $0xf000,%eax
    0x3d, 0x00, 0x40, 0x00, 0x00,             // cmp $0x4000,%eax
    0x0f, 0x85, 0xba, 0x00, 0x00, 0x00,       // jne 164 <done>
    0xe8, 0xda, 0x00, 0x00, 0x00,             // callq 189 <say>
    0x4c, 0x89, 0xef,                         // mov %r13,%rdi
    0xb8, 0x03, 0x00, 0x00, 0x00,             // mov $0x3,%eax
    0x0f, 0x05,                               // syscall
    0x49, 0x8d, 0x7e, 0x02,                   // lea 0x2(%r14),%rdi
    0x31, 0xf6,                               // xor %esi,%esi
    0x31, 0xd2,                               // xor %edx,%edx
    0xb8, 0x02, 0x00, 0x00, 0x00,             // mov $0x2,%eax
    0x0f, 0x05,                               // syscall
    0x48, 0x85, 0xc0,                         // test %rax,%rax
    0x0f, 0x88, 0x93, 0x00, 0x00, 0x00,       // js 164 <done>
    0x49, 0x89, 0xc5,                         // mov %rax,%r13
    0xe8, 0xb0, 0x00, 0x00, 0x00,             // callq 189 <say>
    0x4c, 0x89, 0xef,                         // mov %r13,%rdi
    0x4c, 0x89, 0xe6,                         // mov %r12,%rsi
    0xba, 0x28, 0x00, 0x00, 0x00,             // mov $0x28,%edx
    0x31, 0xc0,                               // xor %eax,%eax
    0x0f, 0x05,                               // syscall
    0x48, 0x85, 0xc0,                         // test %rax,%rax
    0x7e, 0x77,                               // jle 164 <done>
    0x48, 0x89, 0xc2,                         // mov %rax,%rdx
    0x4c, 0x89, 0xe6,                         // mov %r12,%rsi
    0xbf, 0x01, 0x00, 0x00, 0x00,             // mov $0x1,%edi
    0xb8, 0x01, 0x00, 0x00, 0x00,             // mov $0x1,%eax
    0x0f, 0x05,                               // syscall
    0x49, 0x8d, 0xbc, 0x24, 0x00, 0x04, 0x00, 0x00, // lea 0x400(%r12),%rdi
    0xb8, 0x3f, 0x00, 0x00, 0x00,             // mov $0x3f,%eax
    0x0f, 0x05,                               // syscall
    0x48, 0x85, 0xc0,                         // test %rax,%rax
    0x78, 0x51,                               // js 164 <done>
    0x49, 0x8d, 0xb4, 0x24, 0x00, 0x04, 0x00, 0x00, // lea 0x400(%r12),%rsi
    0xba, 0x05, 0x00, 0x00, 0x00,             // mov $0x5,%edx
    0xbf, 0x01, 0x00, 0x00, 0x00,             // mov $0x1,%edi
    0xb8, 0x01, 0x00, 0x00, 0x00,             // mov $0x1,%eax
    0x0f, 0x05,                               // syscall
    0xbf, 0x01, 0x00, 0x00, 0x00,             // mov $0x1,%edi
    0xbe, 0x01, 0x54, 0x00, 0x00,             // mov $0x5401,%esi
    0x31, 0xd2,                               // xor %edx,%edx
    0xb8, 0x10, 0x00, 0x00, 0x00,             // mov $0x10,%eax
    0x0f, 0x05,                               // syscall
    0x48, 0x85, 0xc0,                         // test %rax,%rax
    0x78, 0x20,                               // js 164 <done>
    0xe8, 0x26, 0x00, 0x00, 0x00,             // callq 16f <machine>
    0x4c, 0x89, 0xef,                         // mov %r13,%rdi
    0xbe, 0x01, 0x54, 0x00, 0x00,             // mov $0x5401,%esi
    0x31, 0xd2,                               // xor %edx,%edx
    0xb8, 0x10, 0x00, 0x00, 0x00,             // mov $0x10,%eax
    0x0f, 0x05,                               // syscall
    0x48, 0x85, 0xc0,                         // test %rax,%rax
    0x79, 0x05,                               // jns 164 <done>
    0xe8, 0x0b, 0x00, 0x00, 0x00,             // callq 16f <machine>
    0x31, 0xff,                               // xor %edi,%edi
    0xb8, 0xe7, 0x00, 0x00, 0x00,             // mov $0xe7,%eax
    0x0f, 0x05,                               // syscall
    0xeb, 0xfe,                               // jmp 16d <done+0x9>
    0x49, 0x8d, 0xb4, 0x24, 0x04, 0x05, 0x00, 0x00, // lea 0x504(%r12),%rsi
    0xba, 0x06, 0x00, 0x00, 0x00,             // mov $0x6,%edx
    0xbf, 0x01, 0x00, 0x00, 0x00,             // mov $0x1,%edi
    0xb8, 0x01, 0x00, 0x00, 0x00,             // mov $0x1,%eax
    0x0f, 0x05,                               // syscall
    0xc3,                                     // retq
    0x49, 0x8d, 0x74, 0x24, 0x13,             // lea 0x13(%r12),%rsi
    0xba, 0x05, 0x00, 0x00, 0x00,             // mov $0x5,%edx
    0xbf, 0x01, 0x00, 0x00, 0x00,             // mov $0x1,%edi
    0xb8, 0x01, 0x00, 0x00, 0x00,             // mov $0x1,%eax
    0x0f, 0x05,                               // syscall
    0xc3,                                     // retq
];

/// Where the names this probe opens are put: `"/"` then `"inner"`, two
/// strings in one place, and the probe reaches the second at `+2`.
///
/// **Asserted to be past the code, because it once was not.** The probe grew
/// from 228 bytes to 277 when it gained a `read`, walked straight through the
/// names at 256, and the symptom was the *first* `getdents64` printing
/// nothing — a failure with no visible relationship to the change that caused
/// it. A constant that has to stay ahead of a length is a constant the
/// compiler should be checking.
const LIST_PROBE_NAMES_AT: u64 = 512;
const _: () = assert!(
    LIST_PROBE_CODE.len() < LIST_PROBE_NAMES_AT as usize,
    "the directory probe's code has grown into the names beside it"
);

/// The thread that becomes the socket probe — RFC 0005 step 9.
extern "C" fn ring3_socketeer(hhdm_base: u64) -> ! {
    use bhaskix_boot::VirtAddr;
    use bhaskix_mm::{Protection, VirtRange};
    use vm::AddressSpace;

    const BUFFER_AT: u64 = SOCKET_PROBE_CODE_AT + bhaskix_mm::FRAME_SIZE;

    let stop = || -> ! { sched::exit() };
    let Ok(mut space) = AddressSpace::new(hhdm_base) else {
        stop()
    };
    for (at, protection) in [
        (SOCKET_PROBE_CODE_AT, Protection::ReadExecute),
        (BUFFER_AT, Protection::ReadWrite),
    ] {
        let Some(range) = VirtRange::from_pages(VirtAddr(at), 1) else {
            stop()
        };
        if space.map_anonymous(range, protection).is_err() {
            stop()
        }
    }
    let Some(code_pa) = space.translate(VirtAddr(SOCKET_PROBE_CODE_AT)) else {
        stop()
    };
    // SAFETY: a freshly mapped frame this space owns, filled through the
    // direct map; the executable mapping is never writable. The address goes
    // at a fixed offset past the code, which a `const` assertion above holds
    // clear of it.
    unsafe {
        core::ptr::copy_nonoverlapping(
            SOCKET_PROBE_CODE.as_ptr(),
            (hhdm_base + code_pa) as *mut u8,
            SOCKET_PROBE_CODE.len(),
        );
        // A `sockaddr_in6` for `[::1]:7777`, laid out the way
        // `personality::socket::parse_endpoint` reads one: the family in the
        // first two bytes **little-endian**, the port in the next two
        // **big-endian**, then four bytes of flow label, then the address.
        // Two byte orders four bytes apart is exactly the trap that field
        // layout sets, and it is written here once rather than assembled by
        // hand in the probe.
        let mut address = [0u8; 28];
        address[0..2].copy_from_slice(&10u16.to_le_bytes()); // AF_INET6
        address[2..4].copy_from_slice(&7777u16.to_be_bytes());
        address[8..24].copy_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        core::ptr::copy_nonoverlapping(
            address.as_ptr(),
            (hhdm_base + code_pa + SOCKET_PROBE_ADDRESS_AT) as *mut u8,
            address.len(),
        );
    }
    // SAFETY: the higher half is copied from the running table.
    unsafe { vm::install(space) };
    // SAFETY: the entry is the first byte of the read-execute page; `rdi` is
    // the writable page it works in and `rsi` the address beside its code.
    unsafe {
        bhaskix_arch::syscall::enter_ring3(
            SOCKET_PROBE_CODE_AT,
            BUFFER_AT + 0x0f00,
            [BUFFER_AT, SOCKET_PROBE_CODE_AT + SOCKET_PROBE_ADDRESS_AT],
        )
    }
}

/// The thread that becomes the directory probe — RFC 0005 step 8.
extern "C" fn ring3_lister(hhdm_base: u64) -> ! {
    use bhaskix_boot::VirtAddr;
    use bhaskix_mm::{Protection, VirtRange};
    use vm::AddressSpace;

    const BUFFER_AT: u64 = LIST_PROBE_CODE_AT + bhaskix_mm::FRAME_SIZE;

    let stop = || -> ! { sched::exit() };
    let Ok(mut space) = AddressSpace::new(hhdm_base) else {
        stop()
    };
    for (at, protection) in [
        (LIST_PROBE_CODE_AT, Protection::ReadExecute),
        (BUFFER_AT, Protection::ReadWrite),
    ] {
        let Some(range) = VirtRange::from_pages(VirtAddr(at), 1) else {
            stop()
        };
        if space.map_anonymous(range, protection).is_err() {
            stop()
        }
    }
    let Some(code_pa) = space.translate(VirtAddr(LIST_PROBE_CODE_AT)) else {
        stop()
    };
    // SAFETY: a freshly mapped frame this space owns, filled through the direct
    // map; the executable mapping is never writable. The two names go at a
    // fixed offset inside the same page, past the code, as the file probe's
    // one does -- handed over rather than computed, for the reason written on
    // `FILE_PROBE_NAME_AT`.
    unsafe {
        core::ptr::copy_nonoverlapping(
            LIST_PROBE_CODE.as_ptr(),
            (hhdm_base + code_pa) as *mut u8,
            LIST_PROBE_CODE.len(),
        );
        let names = b"/\0inner\0";
        core::ptr::copy_nonoverlapping(
            names.as_ptr(),
            (hhdm_base + code_pa + LIST_PROBE_NAMES_AT) as *mut u8,
            names.len(),
        );
    }
    // SAFETY: the higher half is copied from the running table.
    unsafe { vm::install(space) };
    // SAFETY: the entry is the first byte of the read-execute page; `rdi` is
    // the writable page it works in and `rsi` the names beside its code.
    unsafe {
        bhaskix_arch::syscall::enter_ring3(
            LIST_PROBE_CODE_AT,
            BUFFER_AT + 0x0f00,
            [BUFFER_AT, LIST_PROBE_CODE_AT + LIST_PROBE_NAMES_AT],
        )
    }
}

/// Where the name this probe opens is put, and the address it is handed.
///
/// **Handed over rather than computed**, and the first version was not: it
/// found its own name with a `lea` from `rip`, which is three numbers that
/// have to agree — the displacement, the padding, and where the constant
/// actually landed. Two of them disagreed. The kernel puts the name in the
/// page and passes its address in `rsi`, which is the affordance
/// `enter_ring3` already has and the one every supervisor-built program will
/// use.
const FILE_PROBE_NAME_AT: u64 = 128;

/// The thread that becomes the `/proc` probe — RFC 0033 step 10.
extern "C" fn ring3_procer(hhdm_base: u64) -> ! {
    use bhaskix_boot::VirtAddr;
    use bhaskix_mm::{Protection, VirtRange};
    use vm::AddressSpace;

    const STACK_AT: u64 = PROC_PROBE_CODE_AT + bhaskix_mm::FRAME_SIZE;

    let stop = || -> ! { sched::exit() };
    let Ok(mut space) = AddressSpace::new(hhdm_base) else {
        stop()
    };
    for (at, protection) in [
        (PROC_PROBE_CODE_AT, Protection::ReadExecute),
        (STACK_AT, Protection::ReadWrite),
    ] {
        let Some(range) = VirtRange::from_pages(VirtAddr(at), 1) else {
            stop()
        };
        if space.map_anonymous(range, protection).is_err() {
            stop()
        }
    }
    let Some(code_pa) = space.translate(VirtAddr(PROC_PROBE_CODE_AT)) else {
        stop()
    };
    // SAFETY: a freshly mapped frame this space owns, filled through the direct
    // map; the executable mapping is never writable.
    unsafe {
        core::ptr::copy_nonoverlapping(
            PROC_PROBE_CODE.as_ptr(),
            (hhdm_base + code_pa) as *mut u8,
            PROC_PROBE_CODE.len(),
        );
    }
    // SAFETY: the higher half is copied from the running table.
    unsafe { vm::install(space) };
    // SAFETY: the entry is the first byte of the read-execute page, and the
    // stack is inside the writable one.
    unsafe { bhaskix_arch::syscall::enter_ring3(PROC_PROBE_CODE_AT, STACK_AT + 0x0f00, [0, 0]) }
}

/// The thread that becomes the wait probe — RFC 0033 step 9.
extern "C" fn ring3_waiter(hhdm_base: u64) -> ! {
    use bhaskix_boot::VirtAddr;
    use bhaskix_mm::{Protection, VirtRange};
    use vm::AddressSpace;

    const PAGE_AT: u64 = WAIT_PROBE_CODE_AT + bhaskix_mm::FRAME_SIZE;

    let stop = || -> ! { sched::exit() };
    let Ok(mut space) = AddressSpace::new(hhdm_base) else {
        stop()
    };
    for (at, protection) in [
        (WAIT_PROBE_CODE_AT, Protection::ReadExecute),
        (PAGE_AT, Protection::ReadWrite),
    ] {
        let Some(range) = VirtRange::from_pages(VirtAddr(at), 1) else {
            stop()
        };
        if space.map_anonymous(range, protection).is_err() {
            stop()
        }
    }
    let Some(code_pa) = space.translate(VirtAddr(WAIT_PROBE_CODE_AT)) else {
        stop()
    };
    // SAFETY: a freshly mapped frame this space owns, filled through the direct
    // map; the executable mapping is never writable.
    unsafe {
        core::ptr::copy_nonoverlapping(
            WAIT_PROBE_CODE.as_ptr(),
            (hhdm_base + code_pa) as *mut u8,
            WAIT_PROBE_CODE.len(),
        );
    }
    // SAFETY: the higher half is copied from the running table.
    unsafe { vm::install(space) };
    // SAFETY: the entry is the first byte of the read-execute page and the
    // stack is inside the writable one.
    unsafe {
        bhaskix_arch::syscall::enter_ring3(WAIT_PROBE_CODE_AT, PAGE_AT + 0x0f00, [PAGE_AT, 0])
    }
}

/// The thread that becomes the fork probe — RFC 0033 step 8.
extern "C" fn ring3_forker(hhdm_base: u64) -> ! {
    use bhaskix_boot::VirtAddr;
    use bhaskix_mm::{Protection, VirtRange};
    use vm::AddressSpace;

    const PAGE_AT: u64 = FORK_PROBE_CODE_AT + bhaskix_mm::FRAME_SIZE;

    let stop = || -> ! { sched::exit() };
    let Ok(mut space) = AddressSpace::new(hhdm_base) else {
        stop()
    };
    for (at, protection) in [
        (FORK_PROBE_CODE_AT, Protection::ReadExecute),
        (PAGE_AT, Protection::ReadWrite),
    ] {
        let Some(range) = VirtRange::from_pages(VirtAddr(at), 1) else {
            stop()
        };
        if space.map_anonymous(range, protection).is_err() {
            stop()
        }
    }
    let Some(code_pa) = space.translate(VirtAddr(FORK_PROBE_CODE_AT)) else {
        stop()
    };
    // SAFETY: a freshly mapped frame this space owns, filled through the direct
    // map; the executable mapping is never writable.
    unsafe {
        core::ptr::copy_nonoverlapping(
            FORK_PROBE_CODE.as_ptr(),
            (hhdm_base + code_pa) as *mut u8,
            FORK_PROBE_CODE.len(),
        );
    }
    // SAFETY: the higher half is copied from the running table.
    unsafe { vm::install(space) };
    // SAFETY: the entry is the first byte of the read-execute page and the
    // stack is inside the writable one; `rdi` is that page.
    unsafe {
        bhaskix_arch::syscall::enter_ring3(FORK_PROBE_CODE_AT, PAGE_AT + 0x0f00, [PAGE_AT, 0])
    }
}

/// The thread that becomes the pipe probe — RFC 0033 step 7.
extern "C" fn ring3_piper(hhdm_base: u64) -> ! {
    use bhaskix_boot::VirtAddr;
    use bhaskix_mm::{Protection, VirtRange};
    use vm::AddressSpace;

    const PAGE_AT: u64 = PIPE_PROBE_CODE_AT + bhaskix_mm::FRAME_SIZE;

    let stop = || -> ! { sched::exit() };
    let Ok(mut space) = AddressSpace::new(hhdm_base) else {
        stop()
    };
    for (at, pages, protection) in [
        (PIPE_PROBE_CODE_AT, 1, Protection::ReadExecute),
        // Two pages of scratch: the descriptor pair and the bytes read at the
        // start, the child's stack in the second half.
        (PAGE_AT, 2, Protection::ReadWrite),
    ] {
        let Some(range) = VirtRange::from_pages(VirtAddr(at), pages) else {
            stop()
        };
        if space.map_anonymous(range, protection).is_err() {
            stop()
        }
    }
    let Some(code_pa) = space.translate(VirtAddr(PIPE_PROBE_CODE_AT)) else {
        stop()
    };
    // SAFETY: a freshly mapped frame this space owns, filled through the direct
    // map; the executable mapping is never writable.
    unsafe {
        core::ptr::copy_nonoverlapping(
            PIPE_PROBE_CODE.as_ptr(),
            (hhdm_base + code_pa) as *mut u8,
            PIPE_PROBE_CODE.len(),
        );
    }
    // SAFETY: the higher half is copied from the running table.
    unsafe { vm::install(space) };
    // SAFETY: the entry is the first byte of the read-execute page, the stack
    // is inside the writable pair, and `rdi` is the page the probe works in.
    unsafe {
        bhaskix_arch::syscall::enter_ring3(PIPE_PROBE_CODE_AT, PAGE_AT + 0x0700, [PAGE_AT, 0])
    }
}

/// The thread that becomes the file probe — RFC 0033 step 6.
///
/// Two pages: one read-execute for the code and the name, one read-write for
/// what it reads. The name is copied in beside the code and its address is
/// handed over in `rsi`, so the program does no arithmetic about where its own
/// data is.
extern "C" fn ring3_filer(hhdm_base: u64) -> ! {
    use bhaskix_boot::VirtAddr;
    use bhaskix_mm::{Protection, VirtRange};
    use vm::AddressSpace;

    const BUFFER_AT: u64 = FILE_PROBE_CODE_AT + bhaskix_mm::FRAME_SIZE;

    let stop = || -> ! { sched::exit() };
    let Ok(mut space) = AddressSpace::new(hhdm_base) else {
        stop()
    };
    for (at, protection) in [
        (FILE_PROBE_CODE_AT, Protection::ReadExecute),
        (BUFFER_AT, Protection::ReadWrite),
    ] {
        let Some(range) = VirtRange::from_pages(VirtAddr(at), 1) else {
            stop()
        };
        if space.map_anonymous(range, protection).is_err() {
            stop()
        }
    }
    let Some(code_pa) = space.translate(VirtAddr(FILE_PROBE_CODE_AT)) else {
        stop()
    };
    // SAFETY: a freshly mapped frame this space owns, filled through the direct
    // map; the executable mapping is never writable. The name goes at a fixed
    // offset inside the same page, past the code.
    unsafe {
        core::ptr::copy_nonoverlapping(
            FILE_PROBE_CODE.as_ptr(),
            (hhdm_base + code_pa) as *mut u8,
            FILE_PROBE_CODE.len(),
        );
        let name = b"inner\0";
        core::ptr::copy_nonoverlapping(
            name.as_ptr(),
            (hhdm_base + code_pa + FILE_PROBE_NAME_AT) as *mut u8,
            name.len(),
        );
    }
    // SAFETY: the higher half is copied from the running table.
    unsafe { vm::install(space) };
    // SAFETY: the entry is the first byte of the read-execute page; `rdi` is
    // the writable page it reads into and `rsi` the name beside its code.
    unsafe {
        bhaskix_arch::syscall::enter_ring3(
            FILE_PROBE_CODE_AT,
            BUFFER_AT + 0x0f00,
            [BUFFER_AT, FILE_PROBE_CODE_AT + FILE_PROBE_NAME_AT],
        )
    }
}

/// The thread that becomes the exec probe — RFC 0033 step 5.
///
/// One page, read-execute, and no report page at all: what this probe has to
/// say it says by *execing*, and what the program it becomes has to say it
/// says to the console. A probe that reported through a page would have to
/// survive its own `execve` to write into it, which is the one thing an exec
/// guarantees it does not do.
extern "C" fn ring3_execer(hhdm_base: u64) -> ! {
    use bhaskix_boot::VirtAddr;
    use bhaskix_mm::{Protection, VirtRange};
    use vm::AddressSpace;

    let stop = || -> ! { sched::exit() };
    let Ok(mut space) = AddressSpace::new(hhdm_base) else {
        stop()
    };
    let Some(code) = VirtRange::from_pages(VirtAddr(EXEC_PROBE_CODE_AT), 1) else {
        stop()
    };
    if space.map_anonymous(code, Protection::ReadExecute).is_err() {
        stop()
    }
    let Some(code_pa) = space.translate(VirtAddr(EXEC_PROBE_CODE_AT)) else {
        stop()
    };
    // SAFETY: a freshly mapped frame this space owns, filled through the
    // direct map; the executable mapping is never writable.
    unsafe {
        core::ptr::copy_nonoverlapping(
            EXEC_PROBE_CODE.as_ptr(),
            (hhdm_base + code_pa) as *mut u8,
            EXEC_PROBE_CODE.len(),
        );
    }
    // SAFETY: the higher half is copied from the running table.
    unsafe { vm::install(space) };
    // SAFETY: the entry is the first byte of a page mapped read-execute above,
    // and the stack is one past the writable end of the same page -- this
    // program pushes nothing, and `execve` is its second instruction pair.
    unsafe {
        bhaskix_arch::syscall::enter_ring3(
            EXEC_PROBE_CODE_AT,
            EXEC_PROBE_CODE_AT + bhaskix_mm::FRAME_SIZE,
            [0, 0],
        )
    }
}

/// The thread that becomes the Linux-tagged probe: builds a two-page space,
/// copies the hand-assembled code in through the direct map (the mapping
/// itself is never writable), and enters ring 3 with `rdi` naming the
/// report page.
extern "C" fn ring3_foreigner(hhdm_base: u64) -> ! {
    use bhaskix_boot::VirtAddr;
    use bhaskix_mm::{Protection, VirtRange};
    use vm::AddressSpace;

    let stop = || -> ! { sched::exit() };
    let Ok(mut space) = AddressSpace::new(hhdm_base) else {
        stop()
    };
    let Some(code) = VirtRange::from_pages(VirtAddr(FOREIGNER_CODE_AT), 1) else {
        stop()
    };
    if space.map_anonymous(code, Protection::ReadExecute).is_err() {
        stop()
    }
    let Some(report) = VirtRange::from_pages(VirtAddr(FOREIGNER_REPORT_AT), 1) else {
        stop()
    };
    if space.map_anonymous(report, Protection::ReadWrite).is_err() {
        stop()
    }
    let (Some(code_pa), Some(report_pa)) = (
        space.translate(VirtAddr(FOREIGNER_CODE_AT)),
        space.translate(VirtAddr(FOREIGNER_REPORT_AT)),
    ) else {
        stop()
    };
    // SAFETY: freshly mapped anonymous frames this space owns, written
    // through the direct map exactly as the ELF loader fills code pages --
    // the executable mapping itself is never writable.
    unsafe {
        core::ptr::copy_nonoverlapping(
            FOREIGNER_CODE.as_ptr(),
            (hhdm_base + code_pa) as *mut u8,
            FOREIGNER_CODE.len(),
        );
    }
    FOREIGNER_REPORT_PA.store(report_pa, core::sync::atomic::Ordering::Release);
    // SAFETY: the higher half is copied from the running table.
    unsafe { vm::install(space) };
    // The domain note, for the same reason `enter_user` sets it: the syscall
    // entry reads it to decide which ABI this thread speaks, and a thread
    // entering ring 3 for the first time may not have been switched to on
    // this CPU. These probes enter directly rather than through `enter_user`
    // -- each builds its own space -- so each sets it. The memory probe found
    // this by being answered `BadSyscall`; the futex probe had been passing
    // on luck.
    if let Some(domain) = sched::current_domain() {
        telemetry::note_domain(domain.as_u32());
    }
    // SAFETY: the entry is inside the user-executable page just written and
    // mapped; `rsp` is one past the user-writable report page in the same
    // space; `RSP0` for this CPU was set by the ring 3 test that ran first.
    unsafe {
        bhaskix_arch::syscall::enter_ring3(
            FOREIGNER_CODE_AT,
            FOREIGNER_REPORT_AT + 4096,
            [FOREIGNER_REPORT_AT, 0],
        )
    }
}

/// Where the auxv probe's code, stack and report live in its own space.
const AUXV_CODE_AT: u64 = 0x0000_0000_2000_0000;
const AUXV_STACK_AT: u64 = 0x0000_0000_2001_0000;
const AUXV_REPORT_AT: u64 = 0x0000_0000_2002_0000;

/// The entropy the initial image carries, kept so the test can compare what
/// the probe read against what was written.
static AUXV_ENTROPY: [core::sync::atomic::AtomicU64; 2] = [
    core::sync::atomic::AtomicU64::new(0),
    core::sync::atomic::AtomicU64::new(0),
];

/// The thread that becomes RFC 0005 step 3's witness: builds a Linux
/// initial process image with `bhaskix_personality::stack` -- the same
/// builder the host tests check byte for byte -- and enters ring 3 on it.
extern "C" fn ring3_auxv(hhdm_base: u64) -> ! {
    use bhaskix_boot::VirtAddr;
    use bhaskix_mm::{Protection, VirtRange};
    use bhaskix_personality::stack::{Builder, ProcessInfo};
    use vm::AddressSpace;

    let stop = || -> ! { sched::exit() };
    let Ok(mut space) = AddressSpace::new(hhdm_base) else {
        stop()
    };
    for (at, protection) in [
        (AUXV_CODE_AT, Protection::ReadExecute),
        (AUXV_STACK_AT, Protection::ReadWrite),
        (AUXV_REPORT_AT, Protection::ReadWrite),
    ] {
        let Some(range) = VirtRange::from_pages(VirtAddr(at), 1) else {
            stop()
        };
        if space.map_anonymous(range, protection).is_err() {
            stop()
        }
    }
    let (Some(code_pa), Some(stack_pa), Some(report_pa)) = (
        space.translate(VirtAddr(AUXV_CODE_AT)),
        space.translate(VirtAddr(AUXV_STACK_AT)),
        space.translate(VirtAddr(AUXV_REPORT_AT)),
    ) else {
        stop()
    };

    // Entropy from the machine's own source, or a fixed pattern when it has
    // none -- RFC 0021's policy, stated: a machine that cannot be
    // unpredictable says so rather than pretending.
    let entropy = [
        bhaskix_rand::u64().unwrap_or(0x0123_4567_89ab_cdef),
        bhaskix_rand::u64().unwrap_or(0xfedc_ba98_7654_3210),
    ];
    AUXV_ENTROPY[0].store(entropy[0], core::sync::atomic::Ordering::Release);
    AUXV_ENTROPY[1].store(entropy[1], core::sync::atomic::Ordering::Release);
    let mut random = [0u8; 16];
    random[..8].copy_from_slice(&entropy[0].to_le_bytes());
    random[8..].copy_from_slice(&entropy[1].to_le_bytes());

    let args: [&[u8]; 2] = [b"penguin", b"--auxv"];
    let env: [&[u8]; 1] = [b"BHASKIX=1"];
    let builder = Builder::new(
        &args,
        &env,
        ProcessInfo {
            entry: AUXV_CODE_AT,
            phdr: AUXV_CODE_AT + 64,
            phent: 56,
            phnum: 1,
            page_size: bhaskix_mm::FRAME_SIZE,
            hwcap: 0,
            random,
        },
    );
    // SAFETY: a freshly mapped anonymous frame this space owns, viewed
    // through the direct map as the page it is -- the same idiom the ELF
    // loader uses to fill a segment.
    let stack_page =
        unsafe { core::slice::from_raw_parts_mut((hhdm_base + stack_pa) as *mut u8, 4096) };
    if builder.build(stack_page, AUXV_STACK_AT).is_err() {
        stop()
    }

    // SAFETY: as above, for the code page; the mapping itself is never
    // writable.
    unsafe {
        core::ptr::copy_nonoverlapping(
            AUXV_CODE.as_ptr(),
            (hhdm_base + code_pa) as *mut u8,
            AUXV_CODE.len(),
        );
    }
    AUXV_REPORT_PA.store(report_pa, core::sync::atomic::Ordering::Release);
    // SAFETY: the higher half is copied from the running table.
    unsafe { vm::install(space) };
    // The domain note, for the same reason `enter_user` sets it: the syscall
    // entry reads it to decide which ABI this thread speaks, and a thread
    // entering ring 3 for the first time may not have been switched to on
    // this CPU. These probes enter directly rather than through `enter_user`
    // -- each builds its own space -- so each sets it. The memory probe found
    // this by being answered `BadSyscall`; the futex probe had been passing
    // on luck.
    if let Some(domain) = sched::current_domain() {
        telemetry::note_domain(domain.as_u32());
    }
    // SAFETY: the entry is inside the user-executable page just written;
    // `rsp` points at the `argc` word of the image just built, which is
    // where Linux puts it; `RSP0` was set by the ring 3 test.
    unsafe { bhaskix_arch::syscall::enter_ring3(AUXV_CODE_AT, AUXV_STACK_AT, [AUXV_REPORT_AT, 0]) }
}

/// RFC 0005 step 3's witness: a Linux program walks the initial process
/// image this kernel built -- argv, envp, the auxiliary vector -- and finds
/// the entropy `AT_RANDOM` promised, which is the one auxv entry Go treats
/// as not optional.
fn auxv_self_test(hhdm_base: u64, cpus: u32) -> bool {
    use core::sync::atomic::Ordering;

    if cpus < 2 {
        println!("\x1b[93m    linux stack    skipped, needs a second cpu\x1b[0m");
        return true;
    }
    const CPU: u32 = 3;

    let Ok(realm) = domain::create("auxv", domain::ResourceEnvelope::new()) else {
        println!("\x1b[91m    linux stack    FAILED: no domain\x1b[0m");
        return false;
    };
    // Tagged Linux, because that is the domain a real hosted binary runs in
    // -- and because it proves the image is built for a domain whose every
    // system call is still refused: the stack is what a program reads
    // *before* it makes any.
    if domain::with(realm, |owner| {
        owner.set_personality(domain::Personality::Linux)
    })
    .is_none()
    {
        println!("\x1b[91m    linux stack    FAILED: the tag would not set\x1b[0m");
        return false;
    }
    let options = sched::SpawnOptions::new()
        .pinned()
        .in_domain(realm.as_u32());
    if sched::spawn_on_with(CPU, "auxv", ring3_auxv, hhdm_base, hhdm_base, options).is_err() {
        println!("\x1b[91m    linux stack    FAILED: the probe would not spawn\x1b[0m");
        return false;
    }

    // The probe walks the image and spins. Wait for its four words, bounded.
    let mut report_pa = 0;
    let mut answers = [0u64; 4];
    for _ in 0..400 {
        report_pa = AUXV_REPORT_PA.load(Ordering::Acquire);
        if report_pa != 0 {
            // SAFETY: a frame the probe's space owns, read through the
            // direct map; four loads of one page cannot fault.
            answers = unsafe {
                [
                    core::ptr::read_volatile((hhdm_base + report_pa) as *const u64),
                    core::ptr::read_volatile((hhdm_base + report_pa + 8) as *const u64),
                    core::ptr::read_volatile((hhdm_base + report_pa + 16) as *const u64),
                    core::ptr::read_volatile((hhdm_base + report_pa + 24) as *const u64),
                ]
            };
            if answers[2] != 0 || answers[3] != 0 {
                break;
            }
        }
        wait_millis(5);
    }
    retire_probe(realm);

    let entropy = [
        AUXV_ENTROPY[0].load(Ordering::Acquire),
        AUXV_ENTROPY[1].load(Ordering::Acquire),
    ];
    let right = report_pa != 0
        && answers[0] == 2
        && answers[1] == AUXV_CODE_AT
        && answers[2] == entropy[0]
        && answers[3] == entropy[1];
    if right {
        println!(
            "    linux stack    a Linux program walked the initial image this kernel built: \
             argc 2, AT_ENTRY {:#x}, and the sixteen AT_RANDOM bytes it found are the entropy \
             that was put there",
            AUXV_CODE_AT
        );
        true
    } else {
        println!(
            "\x1b[91m    linux stack    FAILED: argc {}, entry {:#x}, random {:#x} {:#x} \
             against entropy {:#x} {:#x}\x1b[0m",
            answers[0], answers[1], answers[2], answers[3], entropy[0], entropy[1]
        );
        false
    }
}

/// RFC 0033 step 10's witness: a hosted program reads `/proc` about itself.
///
/// **The claim is that what it reads is its own and nothing else's.** The
/// probe maps a page and then prints `/proc/self/status` and
/// `/proc/self/maps`; the gate looks for the line describing the page it just
/// mapped, which is the personality's region list written back to the program
/// that made it.
///
/// The *leak* half of this step is not a grep and cannot be: it is a host test
/// in `personality::proc` that enumerates the field names this personality may
/// publish and refuses any other. A boot gate can only look for what somebody
/// thought to forbid; the host test looks for anything not explicitly allowed.
fn proc_self_test(hhdm_base: u64, cpus: u32) -> bool {
    if cpus < 2 {
        println!("\x1b[93m    linux proc     skipped, needs a second cpu\x1b[0m");
        return true;
    }
    const CPU: u32 = 3;

    let Ok(realm) = domain::create("procer", domain::ResourceEnvelope::new()) else {
        println!("\x1b[91m    linux proc     FAILED: no domain\x1b[0m");
        return false;
    };
    if domain::with(realm, |owner| {
        owner.set_personality(domain::Personality::Linux)
    }) != Some(Ok(()))
    {
        println!("\x1b[91m    linux proc     FAILED: the tag was refused\x1b[0m");
        return false;
    }
    let options = sched::SpawnOptions::new()
        .pinned()
        .in_domain(realm.as_u32());
    if sched::spawn_on_with(CPU, "procer", ring3_procer, hhdm_base, hhdm_base, options).is_err() {
        println!("\x1b[91m    linux proc     FAILED: the probe would not spawn\x1b[0m");
        return false;
    }
    let mut ended = false;
    for _ in 0..400 {
        if sched::threads_counted_in(realm.as_u32()) == 0 {
            ended = true;
            break;
        }
        wait_millis(5);
    }
    retire_probe(realm);
    if ended {
        // **What this line may claim is what the kernel saw**: a program ran
        // and ended. Whether it *read* anything is on the console, in the text
        // the program printed, and the boot test reads it there — a report
        // that asserted the reading would have said so on a boot where both
        // opens were refused, which is what the first version did.
        println!(
            "    linux proc     a Linux program asked for /proc/self/status and /proc/self/maps; \
             what it read is above, generated by the personality"
        );
    } else {
        println!("\x1b[91m    linux proc     FAILED: the probe never ended\x1b[0m");
    }
    ended
}

/// RFC 0033 step 9's witness: a parent waits for its child and reads its status.
///
/// **The status is the claim.** The child ends with `exit_group(7)`; the parent
/// `wait4`s and prints `s=7`, having decoded Linux's status word itself. A
/// `wait` that invented a status would print `s=0`, which is exactly what the
/// record held before this step — so the number is what separates a `wait4`
/// that works from one that merely returns.
fn wait_self_test(hhdm_base: u64, cpus: u32) -> bool {
    if cpus < 2 {
        println!("\x1b[93m    linux wait     skipped, needs a second cpu\x1b[0m");
        return true;
    }
    const CPU: u32 = 3;

    let Ok(realm) = domain::create("waiter", domain::ResourceEnvelope::new()) else {
        println!("\x1b[91m    linux wait     FAILED: no domain\x1b[0m");
        return false;
    };
    if domain::with(realm, |owner| {
        owner.set_personality(domain::Personality::Linux)
    }) != Some(Ok(()))
    {
        println!("\x1b[91m    linux wait     FAILED: the tag was refused\x1b[0m");
        return false;
    }
    let options = sched::SpawnOptions::new()
        .pinned()
        .in_domain(realm.as_u32());
    if sched::spawn_on_with(CPU, "waiter", ring3_waiter, hhdm_base, hhdm_base, options).is_err() {
        println!("\x1b[91m    linux wait     FAILED: the probe would not spawn\x1b[0m");
        return false;
    }
    let mut ended = false;
    for _ in 0..400 {
        if sched::threads_counted_in(realm.as_u32()) == 0 {
            ended = true;
            break;
        }
        wait_millis(5);
    }
    retire_probe(realm);

    let (collected, status) = adapter_wait_record();
    let right = ended && collected > 0 && status != 0;
    if right {
        println!(
            "    linux wait     a Linux program forked, its child ended, and the parent collected \
             pid {collected} with status word {status:#x}"
        );
    } else {
        println!(
            "\x1b[91m    linux wait     FAILED: ended {ended}, wait4 answered {collected}, status \
             word {status:#x}\x1b[0m"
        );
    }
    right
}

/// RFC 0033 step 8's witness: a hosted program forks, and its memory comes too.
///
/// The parent writes eight bytes into a page of its own, forks, and yields; the
/// child prints what is at that address in **its own** address space. A fork
/// that made a domain and started a thread but copied nothing would print
/// zeros, and the gate demands the bytes.
///
/// The adapter's own record says what the copy *cost*: the child's pid and how
/// many bytes were moved. That number is the whole reason this step exists —
/// RFC 0033 writes copy-on-write as something to build only if a measurement
/// asks for it.
fn fork_self_test(hhdm_base: u64, cpus: u32) -> bool {
    if cpus < 2 {
        println!("\x1b[93m    linux fork     skipped, needs a second cpu\x1b[0m");
        return true;
    }
    const CPU: u32 = 3;

    let Ok(realm) = domain::create("forker", domain::ResourceEnvelope::new()) else {
        println!("\x1b[91m    linux fork     FAILED: no domain\x1b[0m");
        return false;
    };
    if domain::with(realm, |owner| {
        owner.set_personality(domain::Personality::Linux)
    }) != Some(Ok(()))
    {
        println!("\x1b[91m    linux fork     FAILED: the tag was refused\x1b[0m");
        return false;
    }
    let options = sched::SpawnOptions::new()
        .pinned()
        .in_domain(realm.as_u32());
    if sched::spawn_on_with(CPU, "forker", ring3_forker, hhdm_base, hhdm_base, options).is_err() {
        println!("\x1b[91m    linux fork     FAILED: the probe would not spawn\x1b[0m");
        return false;
    }
    let mut ended = false;
    for _ in 0..400 {
        if sched::threads_counted_in(realm.as_u32()) == 0 {
            ended = true;
            break;
        }
        wait_millis(5);
    }
    retire_probe(realm);

    let (pid, copied) = adapter_fork_record();
    let right = ended && pid > 0 && copied > 0;
    if right {
        println!(
            "    linux fork     a Linux program forked: the child is pid {pid}, {copied} bytes of \
             its parent's memory were copied into it a kilobyte at a time, and the child printed \
             what its parent had written there"
        );
    } else {
        println!(
            "\x1b[91m    linux fork     FAILED: ended {ended}, child pid {pid}, {copied} bytes \
             copied\x1b[0m"
        );
    }
    right
}

/// What the adapter's last `wait4` answered: the child collected, and the
/// status word. Negative firsts are refusals — see `bin/linuxd`'s `trace_wait`.
fn adapter_wait_record() -> (i64, u64) {
    let page = ADAPTER_REPORT.load(core::sync::atomic::Ordering::Acquire);
    if page == u64::MAX {
        return (0, 0);
    }
    const FIRST_WORD: usize = bhaskix_personality::report::WAIT_AT / 8;
    let object = shared::MemoryId::from_u64(page);
    let mut record = [0u64; 2];
    let mut at = 0usize;
    let taken = shared::drain_into(object, (FIRST_WORD + 2) * 8, &mut |chunk: &[u8]| {
        for word in chunk.as_chunks::<8>().0 {
            if at >= FIRST_WORD + 2 {
                break;
            }
            if at >= FIRST_WORD {
                let mut eight = [0u8; 8];
                eight.copy_from_slice(word);
                record[at - FIRST_WORD] = u64::from_le_bytes(eight);
            }
            at += 1;
        }
        chunk.len()
    });
    if taken.is_none() {
        return (0, 0);
    }
    (record[0] as i64, record[1])
}

/// What the adapter's last `fork` did: the child's pid and the bytes copied.
/// What a supervised copy costs, against the kernel's own.
///
/// [RFC 0036](../../docs/rfc/0036-a-relocatable-program-in-ring-3.md) step 2,
/// and the reason it is step 2: the RFC's question 1 — who chooses a hosted
/// program's load address — turns on whether `bin/linuxd` could load an image
/// itself through the supervisor interface it already holds, and that turns on
/// what a page costs that way against `copy_nonoverlapping` through the direct
/// map. **The RFC refused to choose a design before this number existed.**
///
/// Three numbers: what one kilobyte costs through `COPY_OUT` the **first** time
/// the path runs in a boot, what the **same** kilobyte costs immediately
/// afterwards, and what the kernel pays to move it with a single `memcpy`
/// through the direct map. The last is the floor — the copy with no crossing at
/// all.
///
/// **The first two used to be 96 bytes and 1,024 bytes, and the difference was
/// read as a per-byte cost. That was wrong**: the sizes were measured in a fixed
/// order to the same page, so the first one paid for the path's first execution
/// and the second did not. Swapping the order moved the cost with it —
/// 1,107,710 cycles for 96 bytes when 96 went first, 103,034 for 1,024
/// immediately after. What the pair actually shows is a translation cache
/// warming, which is a fact about TCG rather than about this interface.
/// Prices giving a lent page back — [RFC 0044](../../docs/rfc/0044-revocation-that-reaches-the-mapping.md)'s
/// missing number.
///
/// **That RFC shipped un-measured and said so, after first claiming the boot
/// report already priced this path.** It did not: `bulk cost` prices a shared
/// transfer against messages and `linux copyout` prices a page through
/// `COPY_OUT`, and neither is a lending coming back. This is the number, taken
/// by `bin/linuxd` where the cost is actually paid and read back here.
///
/// **What is in the span is more than the revocation**, and saying so is the
/// difference between a measurement and a misleading one: it is a whole `CALL`
/// to `bin/fsd`, which mounts, finds the frame, revokes the lending — the part
/// RFC 0044 changed — unpins, and replies. The revocation's own share is not
/// separable from out here, and pretending otherwise would be inventing a
/// number rather than reading one.
///
/// Cold and warm for the reason [`report_supervised_copy`] learned the hard
/// way. **And the warm one exists only because of what is being measured**:
/// before RFC 0044 a second hosted read was refused, so this path ran once per
/// machine and a steady-state figure for it could not be taken at all.
fn report_lending_cost() {
    let page = ADAPTER_REPORT.load(core::sync::atomic::Ordering::Acquire);
    if page == u64::MAX {
        return;
    }
    const FIRST_WORD: usize = bhaskix_personality::report::LEND_AT / 8;
    let object = shared::MemoryId::from_u64(page);
    let mut record = [0u64; 2];
    let mut at = 0usize;
    let taken = shared::drain_into(object, (FIRST_WORD + 2) * 8, &mut |chunk: &[u8]| {
        for word in chunk.as_chunks::<8>().0 {
            if at >= FIRST_WORD + 2 {
                break;
            }
            if at >= FIRST_WORD {
                let mut eight = [0u8; 8];
                eight.copy_from_slice(word);
                record[at - FIRST_WORD] = u64::from_le_bytes(eight);
            }
            at += 1;
        }
        chunk.len()
    });
    let (first, second) = (record[0], record[1]);
    if taken.is_none() || first == 0 {
        return;
    }
    if second == 0 {
        // One read happened and no second one. Said rather than skipped: a
        // machine where this line is missing is a machine where the thing
        // RFC 0044 fixed did not happen, and that is worth seeing.
        println!(
            "\x1b[93m    lending cost   {first} cycles, and no second lending to compare it \
             with -- only one hosted read on this boot\x1b[0m"
        );
        return;
    }
    // **Not "cold and warm", whatever the two slots are called.** The first
    // reading of this pair was 7,877,036 cycles and then 10,049,460 -- the
    // *second* larger -- so this path is not dominated by its first execution
    // the way `COPY_OUT` is, and calling the second figure "warm" would assert
    // a warming that the numbers deny. What dominates is `bin/fsd`'s own work
    // inside the call: mounting, and searching its cache for the frame.
    //
    // So both are printed as what they are, two samples, and the number that
    // answers RFC 0044's question is on the `lending` line instead -- the
    // unmapping alone, best of eight, where a repeat is possible.
    println!(
        "    lending cost   a lent page given back: {first} cycles, then {second}; \
         bin/fsd's mount and search dominate both, so neither is a revocation's price"
    );
}

fn report_supervised_copy() {
    let page = ADAPTER_REPORT.load(core::sync::atomic::Ordering::Acquire);
    if page == u64::MAX {
        return;
    }
    // Where `personality::report` says. The arithmetic once written here was
    // stale in the same way `adapter_file_record`'s was.
    const FIRST_WORD: usize = bhaskix_personality::report::COPY_AT / 8;
    let object = shared::MemoryId::from_u64(page);
    let mut record = [0u64; 2];
    let mut at = 0usize;
    let taken = shared::drain_into(object, (FIRST_WORD + 2) * 8, &mut |chunk: &[u8]| {
        for word in chunk.as_chunks::<8>().0 {
            if at >= FIRST_WORD + 2 {
                break;
            }
            if at >= FIRST_WORD {
                let mut eight = [0u8; 8];
                eight.copy_from_slice(word);
                record[at - FIRST_WORD] = u64::from_le_bytes(eight);
            }
            at += 1;
        }
        chunk.len()
    });
    let (narrow, wide) = (record[0], record[1]);
    if taken.is_none() || narrow == 0 {
        return;
    }

    // The floor: the same 1,024 bytes, moved by the kernel with no crossing.
    // Two static buffers rather than a frame allocation, because this runs on
    // the boot path and must not be able to fail.
    static mut FROM: [u8; 4096] = [0x5a; 4096];
    static mut INTO: [u8; 4096] = [0; 4096];
    let started = bhaskix_arch::tsc::read();
    // SAFETY: two distinct static buffers of the same length, neither aliased
    // by anything else on the boot path, copied whole.
    unsafe {
        core::ptr::copy_nonoverlapping(
            core::ptr::addr_of!(FROM).cast::<u8>(),
            core::ptr::addr_of_mut!(INTO).cast::<u8>(),
            4096,
        );
    }
    let direct = bhaskix_arch::tsc::read().saturating_sub(started);
    // How many crossings a page takes, which is what the scratch width decides.
    let crossings =
        bhaskix_personality::report::PAGE.div_ceil(bhaskix_personality::report::SCRATCH_BYTES);

    println!(
        "    linux copyout  a page through COPY_OUT costs {narrow} cycles the first time and \
         {wide} warm, in {crossings} crossings; the kernel moves a page through the direct map in \
         {direct}"
    );
}

/// The four fault records `bin/linuxd` writes, which nothing read until now.
///
/// **This slot was written on every fault handover and never printed.** The
/// layout module says so in as many words -- *"nothing noticed because the
/// kernel never reads the fault log"* -- as an aside about an old bug, and the
/// aside stayed true afterwards: the kernel reads six of the eight records in
/// this page and has never read this one. `bin/linuxd`'s own comment claimed
/// the opposite, *"in the report page the kernel reads"*, which was true of the
/// page and false of the record.
///
/// It matters because the adapter has no console. When a hosted program faults,
/// the slot and the address are the only thing that says *where* -- and a
/// hosted program that dies before its first `write` leaves nothing else at
/// all. That is the shape of the `execve` intermittent filed on 2026-08-21:
/// `console says ''`, with no evidence available to say whether the child
/// printed nothing or never reached the instruction.
///
/// Four entries because the adapter stores four and drops the rest; the *total*
/// is the kernel's own `fault::statistics`, which is why the two are printed
/// together. A zeroed entry is one never written.
fn adapter_fault_log() -> [(u64, u64); 4] {
    let mut log = [(0u64, 0u64); 4];
    let page = ADAPTER_REPORT.load(core::sync::atomic::Ordering::Acquire);
    if page == u64::MAX {
        return log;
    }
    const FIRST_WORD: usize = bhaskix_personality::report::FAULT_LOG_AT / 8;
    const WORDS: usize = 8;
    let object = shared::MemoryId::from_u64(page);
    let mut record = [0u64; WORDS];
    let mut at = 0usize;
    let taken = shared::drain_into(object, (FIRST_WORD + WORDS) * 8, &mut |chunk: &[u8]| {
        for word in chunk.as_chunks::<8>().0 {
            if at >= FIRST_WORD + WORDS {
                break;
            }
            if at >= FIRST_WORD {
                let mut eight = [0u8; 8];
                eight.copy_from_slice(word);
                record[at - FIRST_WORD] = u64::from_le_bytes(eight);
            }
            at += 1;
        }
        chunk.len()
    });
    if taken.is_none() {
        return log;
    }
    for (entry, pair) in log.iter_mut().zip(record.as_chunks::<2>().0) {
        *entry = (pair[0], pair[1]);
    }
    log
}

fn adapter_fork_record() -> (u64, u64) {
    let page = ADAPTER_REPORT.load(core::sync::atomic::Ordering::Acquire);
    if page == u64::MAX {
        return (0, 0);
    }
    // Where `personality::report` says. The arithmetic once written here was
    // stale in the same way `adapter_file_record`'s was.
    const FIRST_WORD: usize = bhaskix_personality::report::FORK_AT / 8;
    let object = shared::MemoryId::from_u64(page);
    let mut record = [0u64; 2];
    let mut at = 0usize;
    let taken = shared::drain_into(object, (FIRST_WORD + 2) * 8, &mut |chunk: &[u8]| {
        for word in chunk.as_chunks::<8>().0 {
            if at >= FIRST_WORD + 2 {
                break;
            }
            if at >= FIRST_WORD {
                let mut eight = [0u8; 8];
                eight.copy_from_slice(word);
                record[at - FIRST_WORD] = u64::from_le_bytes(eight);
            }
            at += 1;
        }
        chunk.len()
    });
    if taken.is_none() {
        return (0, 0);
    }
    (record[0], record[1])
}

/// RFC 0033 step 7's witness: two hosted threads meet through a pipe.
///
/// **The blocking half is the half worth testing.** The parent makes a pipe and
/// reads from it while it is empty, so it must *park*; the child yields twice
/// and then writes, which must wake it. A reader told "end of file" instead
/// would print nothing; a reader never woken would hang and its domain would
/// not end. Both failures are visible from here, and neither can be produced by
/// a pipe that works.
fn pipe_self_test(hhdm_base: u64, cpus: u32) -> bool {
    if cpus < 2 {
        println!("\x1b[93m    linux pipe     skipped, needs a second cpu\x1b[0m");
        return true;
    }
    // **The writer can win, and a run where it did proves nothing.** If the
    // child's write lands before the parent's read, the pipe is not empty when
    // the parent looks, so nobody parks -- which is correct behaviour and no
    // evidence about blocking at all. The clone probe learned this first, on
    // 2026-08-19, and the answer is the same: detect that case, say so, and run
    // it again rather than reporting it as success or as failure.
    for attempt in 1..=4 {
        match pipe_attempt(hhdm_base, attempt) {
            Some(verdict) => return verdict,
            None => continue,
        }
    }
    println!(
        "\x1b[91m    linux pipe     FAILED: the writer won the race four times; the reader never \
         had an empty pipe to park on\x1b[0m"
    );
    false
}

/// One attempt at the pipe rendezvous. `None` means the race went the wrong
/// way and nothing was proved.
fn pipe_attempt(hhdm_base: u64, attempt: u32) -> Option<bool> {
    use core::sync::atomic::Ordering;

    const CPU: u32 = 3;

    let Ok(realm) = domain::create("piper", domain::ResourceEnvelope::new()) else {
        println!("\x1b[91m    linux pipe     FAILED: no domain\x1b[0m");
        return Some(false);
    };
    if domain::with(realm, |owner| {
        owner.set_personality(domain::Personality::Linux)
    }) != Some(Ok(()))
    {
        println!("\x1b[91m    linux pipe     FAILED: the tag was refused\x1b[0m");
        return Some(false);
    }
    let parked_before = syscall::BLOCKED.load(Ordering::Relaxed);
    let options = sched::SpawnOptions::new()
        .pinned()
        .in_domain(realm.as_u32());
    if sched::spawn_on_with(CPU, "piper", ring3_piper, hhdm_base, hhdm_base, options).is_err() {
        println!("\x1b[91m    linux pipe     FAILED: the probe would not spawn\x1b[0m");
        return Some(false);
    }
    let mut ended = false;
    for _ in 0..400 {
        if sched::threads_counted_in(realm.as_u32()) == 0 {
            ended = true;
            break;
        }
        wait_millis(5);
    }
    retire_probe(realm);

    // **That somebody parked is the claim**, and the kernel counts it: a
    // `BLOCK_ON` reply is the only thing that increments this, and the only
    // call in this probe that can produce one is the read of an empty pipe.
    let parked = syscall::BLOCKED.load(Ordering::Relaxed) > parked_before;
    if ended && !parked {
        // The bytes crossed, and nobody had to wait for them. Correct, and not
        // the proof this test exists for.
        println!(
            "\x1b[93m    linux pipe     attempt {attempt}: the writer won the race, so the reader \
             never had an empty pipe to park on; trying again\x1b[0m"
        );
        return None;
    }
    if ended && parked {
        println!(
            "    linux pipe     two hosted threads met through a pipe: the reader parked on an \
             empty one, the writer woke it, and `{PIPE_PROBE_MESSAGE}` crossed (attempt {attempt})"
        );
    } else {
        println!(
            "\x1b[91m    linux pipe     FAILED: ended {ended}, a reader parked {parked}\x1b[0m"
        );
    }
    Some(ended && parked)
}

/// RFC 0033 step 6's witness: a hosted program reads a real file.
///
/// **Every byte it prints came off a filesystem.** The program opens a name it
/// was handed, reads it, and writes what it read to its standard output — and
/// each of those three calls is answered by `bin/linuxd`, out of a directory
/// capability the kernel granted it and a page the filesystem service lent.
/// The kernel's part is to start the program and watch its domain end.
///
/// The file's contents are the gate: the boot test looks for the line the
/// filesystem was built with, which no part of the personality could invent.
fn file_self_test(hhdm_base: u64, cpus: u32) -> bool {
    if cpus < 2 {
        println!("\x1b[93m    linux file     skipped, needs a second cpu\x1b[0m");
        return true;
    }
    const CPU: u32 = 3;

    // **A machine with no filesystem service has no directory to grant**, and a
    // hosted program asking for a file there is not a failure of anything this
    // step built. Said rather than assumed: the boot lane has no block service,
    // so this is the ordinary case on four of the five placements, and a test
    // that "passed" by finding nothing would be worth nothing.
    // **Two different absences, and the first version answered them the same
    // way.** A machine with no filesystem service has nothing to grant, and
    // skipping is honest. A machine that *has* one and did not grant it is a
    // bug in the grant — and the first version skipped there too, so moving
    // the capability to the wrong slot turned this gate green. Armed once,
    // caught once.
    let machine_has_files = FS_ENDPOINT.load(core::sync::atomic::Ordering::Acquire) != u64::MAX;
    let adapter = syscall::ADAPTER_DOMAIN.load(core::sync::atomic::Ordering::Relaxed);
    let holds_directory = adapter != u32::MAX
        && domain::with(domain::DomainId::from_u32(adapter), |owner| {
            owner.cspace.get(22).is_some()
        }) == Some(true);
    if !machine_has_files {
        println!(
            "    linux file     skipped: this machine has no filesystem service, so there is no \
             directory to give a hosted program"
        );
        return true;
    }
    if !holds_directory {
        println!(
            "\x1b[91m    linux file     FAILED: this machine has a filesystem and the adapter was \
             given no directory\x1b[0m"
        );
        return false;
    }

    let Ok(realm) = domain::create("filer", domain::ResourceEnvelope::new()) else {
        println!("\x1b[91m    linux file     FAILED: no domain\x1b[0m");
        return false;
    };
    if domain::with(realm, |owner| {
        owner.set_personality(domain::Personality::Linux)
    }) != Some(Ok(()))
    {
        println!("\x1b[91m    linux file     FAILED: the tag was refused\x1b[0m");
        return false;
    }
    let options = sched::SpawnOptions::new()
        .pinned()
        .in_domain(realm.as_u32());
    if sched::spawn_on_with(CPU, "filer", ring3_filer, hhdm_base, hhdm_base, options).is_err() {
        println!("\x1b[91m    linux file     FAILED: the probe would not spawn\x1b[0m");
        return false;
    }
    let mut ended = false;
    for _ in 0..400 {
        if sched::threads_counted_in(realm.as_u32()) == 0 {
            ended = true;
            break;
        }
        wait_millis(5);
    }
    retire_probe(realm);

    // **What the adapter says it did**, beside what the program printed. The
    // bytes on the console are the claim; these three numbers are what makes a
    // boot where they did not appear say *which* call refused, rather than
    // leaving the next reader to guess between three.
    let (opened, read, size) = adapter_file_record();
    let right = ended && opened >= 0 && read > 0;
    if right {
        println!(
            "    linux file     a Linux program opened a file through the adapter's directory, \
             read {read} of its {size} bytes at descriptor {opened}, and printed them"
        );
    } else {
        println!(
            "\x1b[91m    linux file     FAILED: ended {ended}, open answered {opened} (stage \
             {read}, detail {size})\x1b[0m"
        );
    }
    right
}

/// RFC 0044's witness: a lending taken back from the borrower **alone**.
///
/// **The existing sharing self-test revokes an object's *root* capability and
/// checks that both holders lost the memory. That is a different operation,
/// and it is the one that was already right.** What was wrong is the one every
/// file read performs: `bin/fsd` derives what it lends from the capability
/// naming its own cache frame and revokes *the lending*, and until 2026-08-23
/// that took the capability away and left the page mapped.
///
/// So three things have to be true at once here, and no two of them would be
/// true of a plausible wrong fix:
///
/// 1. The borrower's page is **gone** — `security.md` §2 rule 3 holding for
///    memory rather than only for capabilities.
/// 2. The lender's page is **still there**, and the object still alive. A
///    revocation that unmapped every domain in the tally would take the cache
///    page `bin/fsd` is serving from, on the path every file read goes down;
///    one that routed through `shared::revoke_capability` would free the frame
///    outright.
/// 3. The borrower can **map there again**, which is the half that has nothing
///    to do with page tables: `AddressSpace::unmap` removes the region record
///    and a revocation that only cleared the hardware entries would leave the
///    address permanently occupied. That is the exact symptom RFC 0005 step 8
///    met — an `ATTACH` refused `SlotUnavailable` at an address nothing
///    appears to be using, so a hosted program could read one file and not two.
///
/// The address spaces are **registered**, unlike the sharing self-test's,
/// because `shared::unmap_roots` reaches a holder through `vm::with_space` and
/// a space nobody installed is a space no revocation can find. A version of
/// this test that skipped that passed assertion 1 and silently lost 3.
fn lending_self_test(hhdm: u64) -> bool {
    use bhaskix_boot::VirtAddr;
    use bhaskix_mm::Protection;

    const LENDER_AT: u64 = 0x0000_0000_6000_0000;
    const BORROWER_AT: u64 = 0x0000_0000_6100_0000;

    let (Ok(lender), Ok(borrower)) = (
        domain::create("lender", domain::ResourceEnvelope::new()),
        domain::create("borrower", domain::ResourceEnvelope::new()),
    ) else {
        println!("\x1b[91m    lending        FAILED: no domains\x1b[0m");
        return false;
    };

    let outcome = (|| {
        let id = shared::create(lender, bhaskix_mm::FRAME_SIZE).ok()?;
        let (mine, theirs) = (
            vm::AddressSpace::new(hhdm).ok()?,
            vm::AddressSpace::new(hhdm).ok()?,
        );
        let mine_root = vm::register_for(lender, mine)?;
        let theirs_root = vm::register_for(borrower, theirs)?;

        // Both hold it, and both have it mapped -- which is the shape a
        // lending is in when it is taken back.
        for (root, at) in [(mine_root, LENDER_AT), (theirs_root, BORROWER_AT)] {
            vm::with_space(root, |space| {
                shared::map_into(id, space, VirtAddr(at), Protection::ReadOnly)
            })?
            .ok()?;
        }
        let mapped_first = vm::with_space(theirs_root, |space| {
            space.translate(VirtAddr(BORROWER_AT)).is_some()
        })? && vm::with_space(mine_root, |space| {
            space.translate(VirtAddr(LENDER_AT)).is_some()
        })?;

        // The loan comes back from the borrower and from nobody else.
        let removed = shared::unmap_roots(id, &[(borrower.as_u32(), Some(theirs_root))]);

        let borrower_lost_it = vm::with_space(theirs_root, |space| {
            space.translate(VirtAddr(BORROWER_AT)).is_none()
        })?;
        let lender_kept_it = vm::with_space(mine_root, |space| {
            space.translate(VirtAddr(LENDER_AT)).is_some()
        })?;
        let object_alive = shared::live(id);

        // And the address is free again, which is assertion 3.
        let can_map_again = vm::with_space(theirs_root, |space| {
            shared::map_into(id, space, VirtAddr(BORROWER_AT), Protection::ReadOnly)
        })?
        .is_ok();

        // **What RFC 0044 added, priced where it can be repeated.**
        //
        // The caller-visible number -- `lending cost`, taken by `bin/linuxd`
        // around a whole `dir::RELEASE` -- turned out to be useless for this
        // question: it is dominated by `bin/fsd` mounting and searching, and
        // its two samples came out 7.9M and 10.0M cycles, the *second* larger.
        // A spread like that at one sample each cannot attribute anything to a
        // page-table walk. So the added work is measured here instead, on its
        // own, the way `bulk cost` measures a transfer: several goes, and the
        // **minimum**, because the minimum is the one the scheduler and the
        // emulator have interfered with least.
        //
        // Re-mapped each time round, because unmapping is not idempotent --
        // the second call would find nothing to do and time an empty loop.
        let mut least = u64::MAX;
        for _ in 0..8 {
            if vm::with_space(theirs_root, |space| {
                shared::map_into(id, space, VirtAddr(BORROWER_AT), Protection::ReadOnly)
            })
            .is_none()
            {
                break;
            }
            let started = bhaskix_arch::tsc::read();
            let removed = shared::unmap_roots(id, &[(borrower.as_u32(), Some(theirs_root))]);
            let elapsed = bhaskix_arch::tsc::read().saturating_sub(started);
            if removed == 1 {
                least = least.min(elapsed);
            }
        }
        let unmap_cycles = if least == u64::MAX { 0 } else { least };

        Some((
            mapped_first,
            removed == 1,
            borrower_lost_it,
            lender_kept_it,
            object_alive,
            can_map_again,
            unmap_cycles,
        ))
    })();

    domain::destroy(borrower);
    domain::destroy(lender);

    let Some((mapped, one, lost, kept, alive, again, unmap_cycles)) = outcome else {
        println!("\x1b[91m    lending        FAILED: the arrangement could not be built\x1b[0m");
        return false;
    };

    let checks = [
        ("both holders had it mapped to begin with", mapped),
        ("exactly one mapping was taken back", one),
        ("the borrower's page is gone", lost),
        ("the lender's page is not", kept),
        ("and the object it lends from is still alive", alive),
        ("the borrower's address is free to map again", again),
    ];
    let mut ok = true;
    for (name, passed) in checks {
        if !passed {
            println!("\x1b[91m    lending        FAILED: {name}\x1b[0m");
            ok = false;
        }
    }
    if ok {
        println!(
            "    lending        a loan was taken back from the borrower alone: its page is gone \
             and its address is free again, the lender kept both, and the object outlived the \
             loan; the unmapping itself is {unmap_cycles} cycles, best of 8"
        );
    }
    ok
}

/// RFC 0005 step 9's witness: a hosted Linux program uses a socket.
///
/// **The four bytes it prints went out through `bin/ipd` and came back.** They
/// are not in the adapter, not in the kernel, and not in any file; the probe
/// writes them into a page, `sendto`s them to `[::1]`, and prints what
/// `recvfrom` gives back. A version of this that printed a constant would be
/// testing nothing, which is why the payload is written and read at opposite
/// ends of a round trip rather than compared in place.
fn socket_self_test(hhdm_base: u64, cpus: u32) -> bool {
    if cpus < 2 {
        println!("\x1b[93m    linux socket   skipped, needs a second cpu\x1b[0m");
        return true;
    }
    const CPU: u32 = 3;

    // The same two absences the file probe distinguishes. A machine with no
    // protocol service has nothing to send through, and skipping is honest; a
    // machine that has one and granted the adapter nothing is a bug in the
    // grant, and a skip there would turn it green.
    let adapter = syscall::ADAPTER_DOMAIN.load(core::sync::atomic::Ordering::Relaxed);
    // **Having a capability to the protocol service is not having a network,
    // and this test learned the difference the expensive way.** On a lane
    // whose network device gets no DMA window, RFC 0012's rule refuses the
    // device: `bin/netd` has nothing to drive and `bin/ipd` has nothing to
    // answer with. The capability still exists and still installs, so the
    // grant above says "holds a network now" -- and a hosted `bind` then
    // *blocks*, because a `CALL` to an endpoint nobody receives on queues for
    // ever. The adapter is single-threaded, so that one call wedges every
    // hosted program on the machine, and the probe never ends.
    //
    // `bin/udp6` already draws this line for itself -- "no unit contains the
    // device, so there is no network to ask" -- and this is the same line,
    // drawn from the flag the kernel already sets.
    let machine_has_network = network_endpoint_capability().is_some()
        && NET_CONTAINED.load(core::sync::atomic::Ordering::Acquire);
    let holds_network = adapter != u32::MAX
        && domain::with(domain::DomainId::from_u32(adapter), |owner| {
            owner.cspace.get(88).is_some() && owner.cspace.get(89).is_some()
        }) == Some(true);
    if !machine_has_network {
        println!(
            "    linux socket   skipped: no network this machine can drive, so there is nothing \
             for a hosted socket to ask"
        );
        return true;
    }
    if !holds_network {
        println!(
            "\x1b[91m    linux socket   FAILED: this machine has a network and the adapter was \
             given none\x1b[0m"
        );
        return false;
    }

    let Ok(realm) = domain::create("socketeer", domain::ResourceEnvelope::new()) else {
        println!("\x1b[91m    linux socket   FAILED: no domain\x1b[0m");
        return false;
    };
    if domain::with(realm, |owner| {
        owner.set_personality(domain::Personality::Linux)
    }) != Some(Ok(()))
    {
        println!("\x1b[91m    linux socket   FAILED: the tag was refused\x1b[0m");
        return false;
    }
    let options = sched::SpawnOptions::new()
        .pinned()
        .in_domain(realm.as_u32());
    if sched::spawn_on_with(
        CPU,
        "socketeer",
        ring3_socketeer,
        hhdm_base,
        hhdm_base,
        options,
    )
    .is_err()
    {
        println!("\x1b[91m    linux socket   FAILED: the probe would not spawn\x1b[0m");
        return false;
    }
    // **Twenty seconds, and the number is what the other lanes cost.** The
    // file probe waits two and the directory probe three, and this one was
    // given three by copying them -- which passed on the `iommu` lane and
    // failed on `uefi` and `shell`, because every `recvfrom` retry here is an
    // IPC round trip the adapter serves one at a time, and TCG makes each of
    // those tens of milliseconds. A probe that exhausts its retries on a lane
    // where no reply comes must still be allowed to *finish*, or the gate
    // reports a hang where there is only a slow refusal.
    let mut ended = false;
    for _ in 0..4000 {
        if sched::threads_counted_in(realm.as_u32()) == 0 {
            ended = true;
            break;
        }
        wait_millis(5);
    }
    retire_probe(realm);

    // **Ending is not passing, and the first version of this test thought it
    // was.** The probe gives up after a bounded retry and exits cleanly when
    // no datagram comes back, so "the domain ended" is true whether the round
    // trip happened or not -- and it reported success for a boot in which
    // `bind` was refused outright, because nothing here looked at the bytes.
    //
    // What decides it is the payload on the console, which the gate greps for
    // and this line points at. The kernel cannot see the probe's output from
    // here, so this says what happened rather than claiming a result.
    let (last, stage, detail) = adapter_file_record();
    if ended {
        println!(
            "    linux socket   a Linux program bound a UDP socket and sent a datagram to itself \
             through bin/ipd; what came back is on the console above, or nothing did (last \
             {last}, stage {stage}, detail {detail})"
        );
    } else {
        println!(
            "\x1b[91m    linux socket   FAILED: the probe never ended -- a bounded retry on \
             recvfrom should have given up rather than hanging\x1b[0m"
        );
    }
    ended
}

/// RFC 0005 step 8's witness: a hosted program lists a directory, stats a
/// file and seeks inside it.
///
/// **What makes this a test rather than a demonstration is that the console
/// output cannot be produced any other way.** The first five bytes are a name
/// read out of a filesystem image, and the last five are the tail of a file
/// found by an offset `fstat` supplied — so a `getdents64` that invented an
/// entry, an `fstat` reading `st_size` from the wrong offset, and an `lseek`
/// that quietly returned to the start each produce a *different line* rather
/// than a missing one.
fn list_self_test(hhdm_base: u64, cpus: u32) -> bool {
    if cpus < 2 {
        println!("\x1b[93m    linux dir      skipped, needs a second cpu\x1b[0m");
        return true;
    }
    const CPU: u32 = 3;

    // The same two absences the file probe distinguishes, and for the same
    // reason: a machine with no filesystem has nothing to list, and one that
    // has a filesystem and granted no directory is a bug that a skip would
    // turn green.
    let machine_has_files = FS_ENDPOINT.load(core::sync::atomic::Ordering::Acquire) != u64::MAX;
    let adapter = syscall::ADAPTER_DOMAIN.load(core::sync::atomic::Ordering::Relaxed);
    let holds_directory = adapter != u32::MAX
        && domain::with(domain::DomainId::from_u32(adapter), |owner| {
            owner.cspace.get(22).is_some()
        }) == Some(true);
    if !machine_has_files {
        println!(
            "    linux dir      skipped: this machine has no filesystem service, so there is no \
             directory to list"
        );
        return true;
    }
    if !holds_directory {
        println!(
            "\x1b[91m    linux dir      FAILED: this machine has a filesystem and the adapter was \
             given no directory\x1b[0m"
        );
        return false;
    }

    let Ok(realm) = domain::create("lister", domain::ResourceEnvelope::new()) else {
        println!("\x1b[91m    linux dir      FAILED: no domain\x1b[0m");
        return false;
    };
    if domain::with(realm, |owner| {
        owner.set_personality(domain::Personality::Linux)
    }) != Some(Ok(()))
    {
        println!("\x1b[91m    linux dir      FAILED: the tag was refused\x1b[0m");
        return false;
    }
    let options = sched::SpawnOptions::new()
        .pinned()
        .in_domain(realm.as_u32());
    if sched::spawn_on_with(CPU, "lister", ring3_lister, hhdm_base, hhdm_base, options).is_err() {
        println!("\x1b[91m    linux dir      FAILED: the probe would not spawn\x1b[0m");
        return false;
    }
    let mut ended = false;
    for _ in 0..400 {
        if sched::threads_counted_in(realm.as_u32()) == 0 {
            ended = true;
            break;
        }
        wait_millis(5);
    }
    retire_probe(realm);

    // The adapter's own record of the last file call, beside what the program
    // printed -- so a boot where the two lines above did not appear says which
    // call stopped rather than leaving the next reader to guess.
    let (last, stage, detail) = adapter_file_record();
    if ended {
        println!(
            "    linux dir      a Linux program listed the directory it was given, closed it, \
             then stat'ed and seeked inside a file it found there (last {last}, stage {stage}, \
             detail {detail})"
        );
    } else {
        println!(
            "\x1b[91m    linux dir      FAILED: the probe never ended (last {last}, stage \
             {stage}, detail {detail})\x1b[0m"
        );
    }
    ended
}

/// RFC 0033 step 5's witness: a hosted program `execve`s, and keeps its pid.
///
/// **What makes this a test rather than a demonstration is where the two
/// numbers come from.** The probe asks its pid in one domain; the program it
/// becomes runs in a *different* domain, created by `bin/linuxd` while the
/// first was still alive, and asks again. Only a pid that lives in the
/// adapter's record can be the same on both sides — one derived from the
/// domain could not be, which is exactly what step 4 changed.
///
/// The kernel's part is small on purpose: create a Linux-tagged domain, start
/// the probe, and wait for the domain to be gone. Everything between is the
/// adapter's, which is the claim.
fn exec_self_test(hhdm_base: u64, cpus: u32) -> bool {
    if cpus < 2 {
        println!("\x1b[93m    linux exec     skipped, needs a second cpu\x1b[0m");
        return true;
    }
    const CPU: u32 = 3;

    let Ok(realm) = domain::create("execer", domain::ResourceEnvelope::new()) else {
        println!("\x1b[91m    linux exec     FAILED: no domain\x1b[0m");
        return false;
    };
    if domain::with(realm, |owner| {
        owner.set_personality(domain::Personality::Linux)
    }) != Some(Ok(()))
    {
        println!("\x1b[91m    linux exec     FAILED: the tag was refused\x1b[0m");
        return false;
    }
    let options = sched::SpawnOptions::new()
        .pinned()
        .in_domain(realm.as_u32());
    if sched::spawn_on_with(CPU, "execer", ring3_execer, hhdm_base, hhdm_base, options).is_err() {
        println!("\x1b[91m    linux exec     FAILED: the probe would not spawn\x1b[0m");
        return false;
    }

    // The probe's own domain must *end*, because that is what an exec does to
    // it: the adapter replies `END_DOMAIN` after building the successor. A
    // probe still alive here either never reached its `execve` or was refused
    // one, and both are failures this can name.
    let mut ended = false;
    for _ in 0..400 {
        if sched::threads_counted_in(realm.as_u32()) == 0 {
            ended = true;
            break;
        }
        wait_millis(5);
    }
    retire_probe(realm);

    if ended {
        println!(
            "    linux exec     a Linux program execed: its own domain ended and the program it \
             became ran in another"
        );
    } else {
        println!("\x1b[91m    linux exec     FAILED: the execing domain is still alive\x1b[0m");
    }
    ended
}

/// RFC 0005 step 2's witness: a Linux-tagged domain's system calls are all
/// foreign, all answered `-ENOSYS`, all logged -- and the tag itself obeys
/// its rules: refused once a thread exists, cleared when the domain ends.
fn personality_self_test(hhdm_base: u64, cpus: u32) -> bool {
    use core::sync::atomic::Ordering;

    if cpus < 2 {
        println!("\x1b[93m    personality    skipped, needs a second cpu\x1b[0m");
        return true;
    }
    const CPU: u32 = 3;

    let calls_before = syscall::FOREIGN_CALLS.load(Ordering::Relaxed);
    let Ok(realm) = domain::create("penguin", domain::ResourceEnvelope::new()) else {
        println!("\x1b[91m    personality    FAILED: no domain\x1b[0m");
        return false;
    };
    if domain::with(realm, |owner| {
        owner.set_personality(domain::Personality::Linux)
    }) != Some(Ok(()))
    {
        println!("\x1b[91m    personality    FAILED: the tag was refused\x1b[0m");
        return false;
    }

    let options = sched::SpawnOptions::new()
        .pinned()
        .in_domain(realm.as_u32());
    if sched::spawn_on_with(
        CPU,
        "penguin",
        ring3_foreigner,
        hhdm_base,
        hhdm_base,
        options,
    )
    .is_err()
    {
        println!("\x1b[91m    personality    FAILED: the probe would not spawn\x1b[0m");
        return false;
    }

    // Wait for the probe to have *spoken* before poking the tag again.
    // The first version of this test raced itself: it tried the too-late
    // refusal immediately after spawn, won the race against the thread's
    // arrival (threads still zero), successfully re-tagged the domain
    // Native -- and then watched its own probe run native and call the
    // check a failure. Ordering by observed effect, not by issue order.
    //
    // Waiting for **all eight**, not the first three: the probe's own exit
    // is its last call, so a test that stopped waiting earlier would destroy
    // the domain in the middle of the smuggle sequence and read a report
    // half written. This said `+ 3` while the probe made three calls.
    // **The refusal is probed at the first call.** The rule is "too late once a
    // thread exists", and the first call is the earliest moment one provably
    // does -- something just made a syscall. Asking after the *eighth* asks at
    // the worst instant available, because the eighth call is the probe's own
    // `exit`.
    //
    // The difference is not subtle and was measured rather than argued: over
    // twelve boots, asking late found a live thread to refuse **once**; asking
    // early found one **eight times in ten**. Same question, same rule, ten
    // times the chance of actually putting it to the test.
    //
    // Asking early was once blamed for breaking this self-test and that blame
    // was withdrawn: re-applied and run ten times, zero failures. See
    // `TRACKER.md`, 2026-08-25.
    let mut arrived = false;
    for _ in 0..400 {
        if syscall::FOREIGN_CALLS.load(Ordering::Relaxed) > calls_before {
            arrived = true;
            break;
        }
        wait_millis(5);
    }
    if !arrived {
        println!("\x1b[91m    personality    FAILED: no foreign calls arrived\x1b[0m");
        return false;
    }
    //
    // **And it puts back what it changed.** A probe that alters the thing it is
    // observing is not a probe. When no thread exists at that instant the
    // re-tag *succeeds* -- correctly -- and the domain is then Native, so the
    // rest of the sequence runs in the wrong dialect and stops making foreign
    // calls at all. Measured before the restore was added: **1 boot in 10**
    // failed with `not all eight foreign calls arrived`, which is precisely the
    // failure an older comment here described and which was wrongly dismissed
    // as unrelated on 2026-08-25. It is related, and it is rare, and rare is
    // what made it look like something else.
    //
    // The restore runs inside the same `domain::with`, so it is under the same
    // table lock as the change it undoes.
    // **How many calls had landed when the question was asked**, because
    // without it an `Ok` is ambiguous and the two readings are very different.
    //
    // This loop polls every 5 ms and the probe's eight syscalls take
    // microseconds, so "the first call has arrived" can mean *all eight* have.
    // If the count is 1, a thread was demonstrably mid-sequence and an `Ok`
    // would mean a live thread went uncounted -- a hole in a guard that exists
    // to stop a program being re-tagged mid-flight. If the count is 8, the
    // probe had simply finished and gone, and `Ok` is the correct answer to a
    // question about an empty domain.
    //
    // One boot in twenty-seven answers `Ok` here. Which of those two it is
    // decides whether there is a defect, so the report carries the number
    // rather than leaving it to be argued.
    let calls_at_probe = syscall::FOREIGN_CALLS.load(Ordering::Relaxed) - calls_before;
    // **And whether the run-queue scan could see, because that is the suspect.**
    //
    // `sched::threads_in_domain` takes each queue with `try_lock` and its own
    // comment says a skipped queue counts as empty -- *"tolerable here, every
    // caller polls in a loop, so a blinded pass is corrected by the next"*, and
    // it names `exit` as deliberately not using it for that reason.
    // `set_personality` **does not poll**: it asks once and decides, and the
    // decision is a security rule. So a blinded scan there would read as "no
    // threads" and let a tag change win against a live one.
    //
    // That is a hypothesis with a mechanism, not a conclusion. The delta is
    // recorded so the next occurrence settles it instead of being argued about.
    let skips_before = sched::domain_scan_skips();
    let late = domain::with(realm, |owner| {
        let outcome = owner.set_personality(domain::Personality::Native);
        if outcome.is_ok() {
            let _ = owner.set_personality(domain::Personality::Linux);
        }
        outcome
    });

    // And *then* wait for all eight, which is what the destroy below needs: the
    // probe's own exit is its last call, so tearing the domain down earlier
    // would read a report half written.
    let mut spoke = false;
    for _ in 0..400 {
        if syscall::FOREIGN_CALLS.load(Ordering::Relaxed) >= calls_before + 8 {
            spoke = true;
            break;
        }
        wait_millis(5);
    }
    if !spoke {
        println!("\x1b[91m    personality    FAILED: not all eight foreign calls arrived\x1b[0m");
        return false;
    }

    // Too late now, and that refusal is part of the contract: a program
    // half-run under one ABI and finished under another is not a state.
    // `Err` is the live refusal; `None` means the domain already ended,
    // which is a different way of being too late and proves the same rule.
    //
    // **This is timing-dependent and it is known to be**: the eighth call is
    // the probe's own `exit`, so the question lands while the thread is being
    // torn down, and when the reap wins the domain has zero threads and the
    // re-tag is correctly allowed. Measured at **one boot in thirty** on an
    // idle machine, 2026-08-25.
    //
    // **Probing earlier is not the fix, and was tried the same day.** Waiting
    // for the *first* call instead makes it worse, not better: at that instant
    // the thread count can still read zero, the re-tag **succeeds**, the probe
    // then runs native and stops making foreign calls, and the self-test fails
    // outright rather than one time in thirty. The comment above records that
    // failure from an earlier attempt; it was reintroduced on 2026-08-25 by
    // somebody who read it as advice about the destroy.
    //
    // The lesson taken from that was that the fix has to make the thread's
    // existence unambiguous **at the moment of asking**, rather than pick a
    // different moment to ask at. That is what the code below does.
    // **And this is reported rather than asserted, because measured at this
    // point it cannot fail.**
    //
    // `set_personality` returns `Err(HasThreads)` when a thread exists and
    // `Ok` when none does, and by the time the eighth call has landed the
    // probe has usually exited -- so `Ok` here is the *correct* answer to a
    // question about a domain that no longer has a thread in it. Measured
    // 2026-08-25: over twelve boots the answer was "the domain had already
    // ended" **eleven times**, and the success line below was announcing "the
    // tag refused once a thread existed" on every one of them.
    //
    // **Its detection power was then measured directly and is zero.** With the
    // guard in `set_personality` deleted outright -- the rule simply gone --
    // six boots of six passed. A condition that cannot fail is not a check,
    // and leaving it in the pass condition was claiming an assurance that was
    // not there.
    //
    // **Two repairs were tried and neither works here.** Asking at the *first*
    // call instead: sound in principle, and ten boots of ten passed with the
    // refusal genuinely exercised -- but one of the ten still read
    // `(true, Ok)`, because `has_threads` consults the scheduler's queues and
    // those are not under this table lock, so the thread can be reaped between
    // the two calls inside one closure. Asking both questions "under one lock"
    // therefore does not close the race, it narrows it -- and turns a one in
    // thirty into about one in ten, with the failure now a *false* one, since
    // the kernel was right at both instants.
    //
    // What would close it **completely** is a probe that is guaranteed alive
    // while the question is asked -- one that does not spend its last call
    // exiting. Moving the moment raises the odds from about one in twelve to
    // about eight in ten; only changing the probe makes it certain, and that
    // is recorded in `TRACKER.md` rather than guessed at here.
    //
    // What actually happened, said plainly, so the rarity of the interesting
    // case is visible in every boot report instead of hidden behind a sentence
    // that assumed it.
    let late_note = match late {
        Some(Err(_)) => "a thread still existed and the tag change lost to it",
        Some(Ok(())) if calls_at_probe >= 8 => {
            "the probe had already made all eight calls and gone, so there was no tag to refuse"
        }
        Some(Ok(())) => {
            "A TAG CHANGE WON WHILE THE PROBE WAS MID-SEQUENCE -- a live thread went uncounted"
        }
        // (the blinded-scan count for this window is printed beside the note)
        None => "the domain had already ended, so no tag change was refused",
    };

    // The probe has said everything it can say; it is spinning, because a
    // program whose every exit is refused has no way out. Put it down --
    // which is the supervisor story a Linux workload lives under until
    // exit_group translates -- and watch the tag die with the domain.
    let report_pa = FOREIGNER_REPORT_PA.load(Ordering::Acquire);
    if report_pa == 0 {
        println!("\x1b[91m    personality    FAILED: the probe never mapped its report\x1b[0m");
        return false;
    }
    domain::destroy(realm);
    let mut ended = false;
    for _ in 0..400 {
        if domain::with(realm, |_| ()).is_none() {
            ended = true;
            break;
        }
        wait_millis(5);
    }
    if !ended {
        println!("\x1b[91m    personality    FAILED: the domain outlived its destruction\x1b[0m");
        return false;
    }
    // The domain being gone is not its thread being gone -- see
    // `retire_probe`. This probe's own `exit` should already have ended it,
    // and the wait costs nothing when it has.
    wait_for_probe_threads(realm);

    // The three answers, through the direct map. Linux's -ENOSYS is -38.
    // SAFETY: the report frame belonged to the probe's space; the space is
    // gone but the frame is read before anything reuses it, and three loads
    // of a page cannot fault through the direct map.
    let answers = unsafe {
        [
            core::ptr::read_volatile((hhdm_base + report_pa) as *const u64),
            core::ptr::read_volatile((hhdm_base + report_pa + 8) as *const u64),
            core::ptr::read_volatile((hhdm_base + report_pa + 16) as *const u64),
        ]
    };
    // And the smuggle's six words: five answers, then the survival mark.
    // SAFETY: as above -- the same frame, read before anything reuses it.
    let smuggled = unsafe {
        [
            core::ptr::read_volatile((hhdm_base + report_pa + 24) as *const u64),
            core::ptr::read_volatile((hhdm_base + report_pa + 32) as *const u64),
            core::ptr::read_volatile((hhdm_base + report_pa + 40) as *const u64),
            core::ptr::read_volatile((hhdm_base + report_pa + 48) as *const u64),
            core::ptr::read_volatile((hhdm_base + report_pa + 56) as *const u64),
        ]
    };
    // SAFETY: as above.
    let survived =
        unsafe { core::ptr::read_volatile((hhdm_base + report_pa + 64) as *const u64) } == 1;
    // What each of the probe's three calls now means, and the assertion has
    // been rewritten twice as the personality implemented them -- which is
    // the drift a self-test should catch in its own project rather than in
    // someone else's runtime. `getpid` answers a pid (never zero). `write`
    // is implemented, and the probe hands it the wrong descriptor, so it
    // gets `EBADF` -- a refusal from a real implementation rather than an
    // absence. And `exit` **never returns**, so the third slot stays zero:
    // the probe's own spin is unreachable, and a nonzero word there would
    // mean a call that should have ended a thread came back from it.
    let ebadf = -9i64 as u64;
    // **A pid is a small positive number, and "not zero" was not enough.**
    // When `getpid` moved out of the nucleus and the adapter was not yet
    // running, it answered `-ENOSYS` -- and `-38 != 0`, so this test reported
    // that "the pid answered" while the probe had been refused. An assertion
    // that accepts an errno as a process id is an assertion about nothing.
    let pid = answers[0] as i64;
    note_hosted_pid(realm.as_u32(), answers[0]);
    // The seed the probe wrote into the exit slot before calling `exit`. It
    // survives if and only if the call never came back; see `FOREIGNER_CODE`.
    const NEVER_RETURNED: u64 = 0xe217;
    let all_refused = pid > 0 && pid < 4096 && answers[1] == ebadf && answers[2] == NEVER_RETURNED;

    // **RFC 0031 §6's Test 1, in the arm this probe can already fund.** The
    // five numbers the probe smuggled are RFC 0008's own syscall kinds. If
    // the entry path ever read a Linux domain's `rax` as a `Kind`, a hosted
    // program would reach the capability interface by arithmetic alone --
    // which is why the dialects must not overlap, and why an assertion is
    // worth more here than a comment.
    //
    // **The assertion changed at RFC 0033 step 6, and the claim did not.** It
    // demanded `-ENOSYS` from all five, which was true only while this
    // personality answered none of them: 0, 2 and 3 are `read`, `open` and
    // `close`, and a file surface gives them Linux meanings. What has to
    // remain true is that each answer is a **Linux** one -- a small negative
    // errno, which no native status can be, since those are small positives --
    // and that the probe is **still alive**, because read natively, 5 is
    // `Exit` and this thread would have ended at it. Both are stronger than
    // "all -ENOSYS" would be now: an answer of `-9` from `read` is this
    // personality refusing a descriptor, and a native `Recv` would have
    // blocked rather than answered anything at all.
    let linux_shaped = |answer: &u64| {
        let value = *answer as i64;
        (-4096..0).contains(&value)
    };
    let no_smuggling = smuggled.iter().all(linux_shaped) && survived;

    let logged = syscall::FOREIGN_CALLS.load(Ordering::Relaxed) - calls_before;
    let numbers = [
        syscall::FOREIGN_SEEN[0].load(Ordering::Relaxed),
        syscall::FOREIGN_SEEN[1].load(Ordering::Relaxed),
        syscall::FOREIGN_SEEN[2].load(Ordering::Relaxed),
        syscall::FOREIGN_SEEN[3].load(Ordering::Relaxed),
        syscall::FOREIGN_SEEN[4].load(Ordering::Relaxed),
        syscall::FOREIGN_SEEN[5].load(Ordering::Relaxed),
        syscall::FOREIGN_SEEN[6].load(Ordering::Relaxed),
        syscall::FOREIGN_SEEN[7].load(Ordering::Relaxed),
    ];
    let sequence_right = numbers == [39, 1, 0, 2, 3, 4, 5, 60];

    // The tag must not survive the domain: the bitmask is keyed by slot and
    // a reused slot must never inherit a dialect.
    let bit_cleared = domain::LINUX_DOMAINS.load(Ordering::Relaxed)
        & (1u64 << (realm.as_u32() as usize % domain::MAX_DOMAINS))
        == 0;

    if all_refused && no_smuggling && logged == 8 && sequence_right && bit_cleared {
        println!(
            "    personality    a Linux-tagged domain asked getpid, write and exit: the pid \
             answered, the bad descriptor refused EBADF, and exit never came back; it then \
             asked for all five of this kernel's own syscall kinds by number and got a Linux \
             errno five times, surviving the one that is Exit natively; 8 foreign calls logged \
             in order, {late_note} (asked after {calls_at_probe} of 8 calls, \
             {} run-queue scans blinded), and the tag cleared when the domain ended",
            sched::domain_scan_skips().saturating_sub(skips_before)
        );
        true
    } else {
        println!(
            "\x1b[91m    personality    FAILED: answers {:#x} {:#x} {:#x}, smuggled \
             {smuggled:x?} survived {survived}, logged {logged}, numbers {numbers:?}, \
             late-refusal ({late_note}), bit-cleared {bit_cleared}\x1b[0m",
            answers[0], answers[1], answers[2]
        );
        false
    }
}

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
// 48 blocks since RFC 0030 step 4: the disk filesystem now holds installed
// packages, and two fifteen-kilobyte payloads plus their records did not
// fit in 32 -- the second install failed as `Full`, the allocator working,
// the number simply outgrown. The 512-sector disk holds 64.
static mut JOURNAL_IMAGE: [u8; 48 * bhaskix_fs::BLOCK] = [0; 48 * bhaskix_fs::BLOCK];

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

/// Where `bin/ahcid`'s stack goes. Its own address, because it has its own
/// address space; the number differs from `bin/blkd`'s only so that a fault
/// address in a report says which driver it came from without being looked up.
const AHCID_STACK: u64 = 0x0000_0000_1200_0000;
/// How many pages of it. Four, as every other driver here: this one keeps a
/// `Started` on the stack, which is thirty-two port records.
const AHCID_STACK_PAGES: u64 = 4;
/// The program.
const AHCID_PROGRAM: &[u8] = b"bin/ahcid";

/// Where the network driver's domain keeps its stack.
const NETD_STACK: u64 = 0x0000_0000_1200_0000;
const NETD_STACK_PAGES: u64 = 4;

/// Where the network driver's program is.
const NETD_PROGRAM: &[u8] = b"bin/netd";

/// Where the protocol service's domain keeps its stack.
const IPD_STACK: u64 = 0x0000_0000_1300_0000;
// Eight pages since RFC 0020 step 4. The TCP back-ring drain puts two
// frame-sized buffers on `serve`'s stack on top of the demonstration's, and
// four pages put the deepest path a few hundred bytes past the guard — found
// as a #PF at 0x12fffed8, the guard page doing exactly its job, presenting as
// a service that answered one caller and vanished.
const IPD_STACK_PAGES: u64 = 8;

/// Where the protocol service's program is.
const IPD_PROGRAM: &[u8] = b"bin/ipd";

/// Where the DHCP client's domain keeps its stack.
const DHCPD_STACK: u64 = 0x0000_0000_1400_0000;
const DHCPD_STACK_PAGES: u64 = 4;

/// Where the DHCP client's program is.
const DHCPD_PROGRAM: &[u8] = b"bin/dhcp";

/// The marker `bin/dhcp` writes before its report.
const DHCPD_MARKER: u64 = 0x3145_4e4f_5044_4844;

/// Where `bin/udp6`'s stack lives in its own address space.
const UDP6_STACK: u64 = 0x0000_0000_1900_0000;
const UDP6_STACK_PAGES: u64 = 4;

/// The v6 socket demonstration, from the filesystem.
const UDP6_PROGRAM: &[u8] = b"bin/udp6";

/// The marker `bin/udp6` writes before its report.
const UDP6_MARKER: u64 = 0x3136_5044_5544_5844;

/// The page `bin/udp6` leaves its findings in.
static UDP6_REPORT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(u64::MAX);

/// The page `bin/dhcp` leaves its findings in.
static DHCP_REPORT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(u64::MAX);

const TCPD_STACK: u64 = 0x0000_0000_1600_0000;
const TCPD_STACK_PAGES: u64 = 4;
const TCPD_PROGRAM: &[u8] = b"bin/tcpd";
const TCPD_MARKER: u64 = 0x3144_5043_5444_0a54;
static TCP_REPORT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(u64::MAX);

/// The TCP demonstration client, RFC 0022 step 4: the first program to open
/// a connection with rings its own domain owns.
const TCPC_STACK: u64 = 0x0000_0000_1700_0000;
const TCPC_STACK_PAGES: u64 = 4;
const TCPC_PROGRAM: &[u8] = b"bin/tcpc";
/// "TCPC_RPT", little-endian, as `bin/tcpc` writes it.
const TCPC_MARKER: u64 = 0x5450_525f_4350_4354;
/// Bytes in each stream ring the client owns. One frame is enough for a
/// sixteen-byte demonstration and small enough to see mistakes in.
const TCPC_RING_BYTES: u64 = 4 * bhaskix_mm::FRAME_SIZE;
/// The badge the client's capability to the TCP service carries.
const TCPC_BADGE: u64 = 0x7C_C1;
static TCPC_REPORT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(u64::MAX);
/// The TCP service's endpoint, for minting client capabilities to it.
static TCP_ENDPOINT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(u64::MAX);

/// The telemetry reader, RFC 0026 steps 3–4: the first program to hold the
/// rings read-only and the tails read-write, and prove the round trip.
const TRACED_STACK: u64 = 0x0000_0000_1800_0000;
const TRACED_STACK_PAGES: u64 = 4;
const TRACED_PROGRAM: &[u8] = b"bin/traced";
/// "TRACED01", little-endian, as `bin/traced` writes it.
const TRACED_MARKER: u64 = u64::from_le_bytes(*b"TRACED01");
/// Marked probes each CPU emits for the round trip.
const TRACED_PROBES_EACH: u64 = 8;
static TRACED_REPORT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(u64::MAX);
/// How many CPUs have finished their probe burst.
static TRACED_PROBES_DONE: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static TCP_CONFIG: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(u64::MAX);
static IP_INBOX: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

const IP_TCP_BADGE: u64 = 1 << 2;
const TCP_TIMER_BADGE: u64 = 1 << 0;
const TCP_FRAME_BADGE: u64 = 1 << 1;

/// Bytes in the ring between `bin/netd` and `bin/ipd`.
///
/// Sixteen pages, of which `abi::ring` uses the largest power of two that fits
/// after its header — 32 KiB of frames, which is sixteen at the Ethernet MTU.
/// Chosen rather than found: a ring is sized by the program that owns it.
const NET_RING_BYTES: u64 = 16 * 4096;

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
    // **The first entry to ring 3, which is where the fault was seen.** The
    // faulting `rip` in every capture is a program's own entry point, not
    // somewhere inside it — so the thread arrived in user mode with the wrong
    // space rather than losing it later. Checked here, immediately before the
    // jump, because after this there is no kernel left to ask.
    crate::sched::check_user_space(2);

    // The per-CPU domain note, set *here* — RFC 0005 step 6's correction.
    // The note is maintained on context switches, and a thread entering ring
    // 3 for the first time has not necessarily been through one on this CPU,
    // so it could carry whichever domain last ran here. That staleness is
    // harmless for telemetry (an event stamped with a neighbour's id is a
    // reporting nuisance) and *not* harmless for the syscall entry's
    // personality check, which reads it to decide which ABI this thread
    // speaks. Setting it at the one place a thread becomes a user thread
    // makes it true from the first instruction, and keeps that check a
    // relaxed load rather than a runqueue lock on every system call.
    if let Some(domain) = crate::sched::current_domain() {
        crate::telemetry::note_domain(domain.as_u32());
    }

    // SAFETY: as above.
    unsafe { bhaskix_arch::syscall::enter_ring3(entry, rsp, arguments) }
}

/// Where the filesystem service's stack goes in its own address space.
/// Deliberately not the address every other program uses, for the reason its
/// code is not: a fault report gives `rip` and `rsp`, and when every program
/// has both the same, neither says which one faulted.
const FSD_STACK: u64 = 0x0000_0000_1300_0000;
/// How many pages of it.
// Sixteen pages since RFC 0030 step 3, the shell's reason one domain over:
// the write path mounts a Volume -- which carries the whole Cache by value
// -- on this stack, and four pages put the floor eight kilobytes above
// where a create's frames actually reach.
const FSD_STACK_PAGES: u64 = 16;
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
    // Both halves of one fact, in one place. The absence used to be reported
    // three hundred lines below, in the `else` of a different question, and a
    // reader who found it there was told the wrong thing about the wrong
    // subsystem -- see the interrupt report at the end of this function.
    if contained {
        println!("    block domain   dma window granted; the device translates through its own");
    } else {
        println!(
            "    block domain   no dma window: nothing would contain the device, so the \
             driver gets registers and no way to make it read"
        );
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
        // This branch is about the *interrupt*, and for most of its life it
        // said "no dma window" instead -- a message about a different
        // subsystem, printed on the failure of this one. It appears in clean
        // BIOS boots, where both happen to be absent together, so it read as
        // routine; it sent two investigations at the DMA path and cost days.
        //
        // The gate in `boot-test.sh` grepped for that string to excuse a block
        // service that answered nothing, which is only a fair excuse when the
        // *window* is missing. So on a machine that had a window and lost its
        // interrupt, a genuinely broken service would have been let through.
        // Moving the window's absence to the window's own report is what makes
        // that excuse true again.
        println!(
            "    block domain   no interrupt delegated; the driver polls its used ring instead"
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

/// Hands the AHCI controller to a domain in ring 3.
///
/// RFC 0046 step 3b. The same delegation `start_block_domain` performs, for a
/// device that differs in one way that matters here: **this kernel has no
/// driver for it at all.** The virtio paths hand over a *second* device whose
/// first the kernel drives; there is one SATA controller and ring 3 gets it,
/// which is what RFC 0046 means by "a domain, like every other driver here".
///
/// What the domain is given: two `Frame`s covering the register file, memory to
/// leave its findings in, and -- where a unit exists -- the `DmaWindow` for its
/// own device. What it is not given is the bus: finding the controller means
/// reading configuration space, which is port I/O, and a domain holding that
/// would hold every device on the machine.
///
/// # Errors
///
/// A `&'static str` naming what would not be created. A machine with no AHCI
/// controller is **not** an error and returns `Ok`, the way a machine with one
/// virtio disk does.
pub fn start_ahci_domain(cpu: u32, hhdm_base: u64) -> Result<(), &'static str> {
    // SAFETY: bootstrap CPU during boot; configuration reads only.
    let Some((bus, device, function)) = (unsafe { ahci::probe() }) else {
        println!("    ahci domain    no AHCI controller on the bus; nothing delegated");
        return Ok(());
    };
    let address = bhaskix_arch::pci::Address::new(bus, device, function);

    // Memory space, so the register file answers. Bus mastering is **not**
    // enabled here: `enable_memory` clears it on purpose, and it is granted
    // below only once there is a window to bound what the controller can reach.
    // SAFETY: this device belongs to nobody -- this kernel has no AHCI driver,
    // and step 2 already cleared its bus-master bit.
    unsafe { bhaskix_arch::pci::enable_memory(address) };

    // The register file's address, read from BAR5 -- which is where AHCI puts
    // it and nowhere else. The low four bits are type bits and not address.
    let Some(configuration) = configuration_page(address) else {
        println!(
            "\x1b[93m    ahci domain    no ECAM, so no BAR to read; the controller is not \
             delegated\x1b[0m"
        );
        return Ok(());
    };
    // SAFETY: a dword of this function's configuration space, through the
    // mapping `configuration_page` describes, at the offset of BAR5.
    let abar = unsafe {
        core::ptr::read_volatile((hhdm_base + configuration + 0x24) as *const u32) & !0xf
    };
    if abar == 0 {
        println!(
            "\x1b[93m    ahci domain    the controller's BAR5 is unassigned; nothing to \
             map\x1b[0m"
        );
        return Ok(());
    }
    let abar = u64::from(abar);

    let realm = domain::create("ahci", domain::ResourceEnvelope::new())
        .map_err(|_| "the ahci domain would not be created")?;

    // Two pages, which is the whole of the register file AHCI defines: the
    // generic host control block is 0x100 and thirty-two ports of 0x80 follow,
    // so the last defined byte is at 0x10ff. Granted as two `Frame`s because a
    // `Frame` names one page -- and the driver is told which it got, by the
    // second attach succeeding or not.
    for (slot, page) in [abar, abar + bhaskix_mm::FRAME_SIZE].iter().enumerate() {
        let window = cap::with_arena(|arena| {
            arena
                .insert_root(
                    cap::ObjectRef::new(
                        cap::ObjectKind::Frame,
                        page & !(bhaskix_mm::FRAME_SIZE - 1),
                    ),
                    // No `GRANT`. A register window is the one thing this
                    // driver must not be able to hand on: it is the whole
                    // device, and `DERIVE` without `GRANT` lets it weaken a
                    // copy for itself and give nothing away.
                    cap::Rights::READ
                        .union(cap::Rights::WRITE)
                        .union(cap::Rights::DERIVE),
                    0,
                )
                .ok()
        })
        .ok_or("an ahci register window would not be created")?;
        if domain::with(realm, |owner| owner.cspace.install_at(slot, window).is_ok()) != Some(true)
        {
            return Err("an ahci register window would not install");
        }
    }

    // Owned by a domain that outlives the driver. `bin/ahcid` exits when it has
    // reported, and a domain's memory is freed when its last thread goes -- so
    // memory owned by the driver would be returned frames by the time the
    // kernel read the report out of them. `bin/blkd` learned this first.
    let keeper = domain::create("ahci-keeper", domain::ResourceEnvelope::new())
        .map_err(|_| "the ahci report's owner would not be created")?;
    let memory = shared::create(keeper, 4 * bhaskix_mm::FRAME_SIZE)
        .map_err(|_| "the ahci domain's memory would not be created")?;
    let named = shared::name(memory).map_err(|_| "the ahci memory would not be named")?;
    if domain::with(realm, |owner| owner.cspace.install_at(2, named).is_ok()) != Some(true) {
        return Err("the ahci memory capability would not install");
    }

    // The endpoint this driver answers block requests on, at slot 4.
    //
    // RFC 0046 step 6b, and the RFC's actual claim: `bin/fsd` calls
    // `block::READ` and cannot tell this service from `bin/blkd`. A filesystem
    // that had to know which driver was underneath would be a filesystem with a
    // driver inside it, and this is what makes that checkable rather than
    // asserted.
    let served_on = ipc::create().map_err(|_| "no endpoint for the ahci block service")?;
    let served = cap::with_arena(|arena| {
        arena
            .insert_root(
                cap::ObjectRef::new(cap::ObjectKind::Endpoint, u64::from(served_on.as_u32())),
                cap::Rights::ALL,
                0,
            )
            .ok()
    })
    .ok_or("the ahci endpoint capability would not be created")?;
    if domain::with(realm, |owner| owner.cspace.install_at(4, served).is_ok()) != Some(true) {
        return Err("the ahci endpoint capability would not install");
    }

    // The authority to say what this *device* may reach. Granted only where a
    // unit exists, for the reason the block path states: without one a device
    // address is a physical address, and a domain that could name one could
    // point its controller at the kernel.
    let delegated = (bus, device, function);
    let contained = if iommu::present_for(delegated) {
        let window =
            iommu::name(delegated).map_err(|_| "the ahci dma window would not be named")?;
        if domain::with(realm, |owner| owner.cspace.install_at(3, window).is_ok()) != Some(true) {
            return Err("the ahci dma window capability would not install");
        }
        true
    } else {
        false
    };

    println!(
        "    ahci domain    {bus:02x}:{device:02x}.{function} delegated: registers at \
         {abar:#x}, two pages"
    );
    if contained {
        println!(
            "    ahci domain    dma window granted; the controller translates through its own"
        );
    } else {
        println!(
            "\x1b[93m    ahci domain    no dma window: nothing would contain the controller, so \
             the driver gets registers and no way to make it read\x1b[0m"
        );
    }

    // **Bus mastering, and only behind a window.** Step 3b left this out and
    // said so: nothing was issued, so nothing needed to reach memory. Step 4
    // issues a command, and a controller that cannot master the bus cannot
    // fetch its own command list -- which on QEMU is not a clean refusal but a
    // port told to run with no way to run, and it took the machine down with no
    // console output at all. Three boots looked like a hung driver.
    //
    // Granted only when `contained`, which is stricter than the virtio paths:
    // they enable it unconditionally and rely on the window being granted
    // first. Here the device either translates or never masters the bus.
    if contained {
        // SAFETY: this controller is the ahci domain's, nothing else in this
        // kernel drives it, and a window is installed for it -- so a stray DMA
        // with whatever the firmware left reaches nothing it was not given and
        // arrives as a fault rather than as somebody else's memory.
        unsafe { bhaskix_arch::pci::enable(address) };
        println!(
            "    ahci domain    bus mastering enabled behind that window; nothing it fetches \
             can leave it"
        );
    }

    let options = sched::SpawnOptions::new()
        .pinned()
        .in_domain(realm.as_u32());
    sched::spawn_on_with(
        cpu,
        "ahcid",
        ahci_domain_entry,
        hhdm_base,
        hhdm_base,
        options,
    )
    .map_err(|_| "the ahci domain would not spawn")?;

    AHCI_MEMORY.store(memory.as_u64(), core::sync::atomic::Ordering::Release);
    // Recorded only where the driver can actually serve, which needs a window:
    // without one it cannot read a sector, so an endpoint nobody answers would
    // make the self-test wait for something that is never coming. The block
    // path learned this first and its comment says so.
    if contained {
        AHCI_ENDPOINT.store(
            u64::from(served_on.as_u32()),
            core::sync::atomic::Ordering::Release,
        );
    }
    Ok(())
}

/// Hands a virtio network device to a domain in ring 3.
///
/// RFC 0018 step 2. The same delegation `start_block_domain` performs, for a
/// device that differs in one way that matters: **a disk answers, a network
/// device initiates.** Everything below is the block path's shape; the receive
/// direction is what is new, and it is the driver's problem rather than this
/// function's.
///
/// Not a boot dependency. A machine with no network device boots, says so, and
/// carries on, exactly as it does with one disk.
///
/// # Errors
///
/// Every failure here leaves the machine bootable and is reported as a string,
/// because a network device is a convenience and a kernel that refuses to boot
/// without one is worse than a kernel with no network.
pub fn start_net_domain(
    cpu: u32,
    hhdm_base: u64,
    apic_id: u32,
    rsdp: Option<bhaskix_boot::PhysAddr>,
) -> Result<(), &'static str> {
    let Some((address, _)) = virtio::find_nth_of(virtio::Class::NET, 0) else {
        println!("    net domain     no device on the bus; nothing delegated");
        return Ok(());
    };
    let layout = virtio::layout(address).ok_or("the network device is not a modern virtio")?;

    // Memory space only. Bus mastering stays off until the driver has reset the
    // device and built its rings, for the reason the block path gives: a device
    // that could write to memory before its owner was ready would do so with
    // whatever the firmware left in its registers.
    // SAFETY: this device belongs to nobody -- the kernel has no network driver
    // of its own, which is the whole point of RFC 0018.
    unsafe { bhaskix_arch::pci::enable_memory(address) };

    let realm = domain::create("net", domain::ResourceEnvelope::new())
        .map_err(|_| "the net domain would not be created")?;

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

    // Rings: eight pages, and the arithmetic rather than a feel for it.
    //
    // Two queues, not the block driver's one, and each needs a descriptor
    // table, an available ring and a used ring. Then the buffers: a receive
    // queue must have somewhere to put a frame *before* the device has one to
    // deliver, so every receive descriptor owns a buffer big enough for a full
    // Ethernet frame plus the virtio header in front of it.
    //
    //   2 queues x (descriptors + available + used)        ~2 pages
    //   4 receive buffers x 2 KiB                            2 pages
    //   1 transmit buffer                                   <1 page
    //   slack, so the layout can move without re-sizing      3 pages
    //
    // Owned by a keeper domain rather than by the driver, for the reason
    // `blk-keeper` exists: a domain ends when its last thread exits and takes
    // the memory it owns with it, so rings owned by the driver would be freed
    // the moment it stopped and anything reading them afterwards would be
    // reading returned frames.
    let keeper = domain::create("net-keeper", domain::ResourceEnvelope::new())
        .map_err(|_| "the net rings' owner would not be created")?;
    NET_KEEPER.store(
        keeper.as_u32().saturating_add(1),
        core::sync::atomic::Ordering::Release,
    );
    let rings = shared::create(keeper, 8 * bhaskix_mm::FRAME_SIZE)
        .map_err(|_| "the net domain's rings would not be created")?;
    let named = shared::name(rings).map_err(|_| "the rings would not be named")?;
    if domain::with(realm, |owner| owner.cspace.install_at(3, named).is_ok()) != Some(true) {
        return Err("the rings capability would not install");
    }

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
        "    net domain     {:02x}:{:02x}.{} delegated: common {:#x}, notify {:#x} x{}, device {:#x}",
        address.bus,
        address.device,
        address.function,
        layout.common.0,
        layout.notify.0,
        layout.notify_multiplier,
        layout.device.0
    );
    NET_CONTAINED.store(contained, core::sync::atomic::Ordering::Release);
    if contained {
        println!("    net domain     dma window granted; the device translates through its own");
    } else {
        println!(
            "    net domain     no dma window: nothing would contain the device, so the \
             driver gets registers and no way to make it send or receive"
        );
    }

    // The device's interrupt. Same split as the block driver's: the domain gets
    // the authority to *wait* for a vector and to acknowledge it, and never the
    // authority to program one -- an MSI is a memory write of an arbitrary
    // vector to an arbitrary CPU.
    const NET_BADGE: u64 = 1 << 2;
    let signalled = match crate::notify::create() {
        Ok(notification) => {
            // Kept so `bin/ipd` can be given a doorbell onto it. **The kernel
            // used to poke this notification itself**, twice a second, because
            // RFC 0010's `SIGNAL` was specified in 2026 and not implemented
            // until 2026-08-13; no domain could wake another, so a frame in the
            // return ring waited for the poke. `wake_net_driver` is gone and
            // `bin/ipd` rings this notification directly -- see the doorbell
            // derived from it in `start_ip_domain`.
            NET_WAKE.store(
                u64::from(notification.index())
                    | (u64::from(notification.generation()) << 32)
                    | 1 << 63,
                core::sync::atomic::Ordering::Release,
            );
            // SAFETY: `trap` dispatches claimed vectors to `irq::on_interrupt`,
            // which acknowledges the local APIC. This device is the net
            // domain's and nothing else claims its entries.
            let claimed = unsafe {
                irq::claim_for(
                    irq::Source::MessageSignalled {
                        device: address,
                        entry: 0,
                    },
                    realm.as_u32(),
                    "netd",
                    apic_id,
                    rsdp,
                    hhdm_base,
                )
            };
            match claimed {
                Ok(handler) if irq::bind(handler, notification, NET_BADGE).is_ok() => {
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

    // Bus mastering last, and safe to grant before the driver has reset the
    // device only because the device translates -- the same argument the block
    // path makes, and the same one that fails without a unit.
    // SAFETY: this device is the net domain's; nothing else drives it.
    unsafe { bhaskix_arch::pci::enable(address) };

    if signalled {
        println!(
            "    net domain     interrupt delegated: the kernel programmed the vector, \
             the driver waits for it"
        );
    } else {
        println!("    net domain     no interrupt delegated; the driver polls its used rings");
    }

    // RFC 0018 step 3: the other half of the stack, and the ring between them.
    //
    // **Before the driver is spawned, and that ordering is load-bearing.** It
    // was after, and `netd` reached its own `ATTACH` of the ring before this
    // code had installed it — so the attach failed, the driver fell into its
    // idle loop, and nothing ever crossed. The symptom was a consumer reporting
    // zero frames, which points at the wrong end entirely. **A capability a
    // program needs at start has to be in its space before the program is.**
    //
    // Started even where the device has no window. `ipd` then finds an empty
    // ring and says so, which is a more useful state than a domain that was
    // never created, and it keeps the capability count the architecture
    // argument rests on visible on every boot.
    // **`bin/ipd` on a different processor from `bin/netd`, and that is worth
    // more than either of the two things blamed before it.**
    //
    // These two domains ping-pong every frame: the driver hands one across a
    // ring and the service hands one back. Pinned to the same CPU, every frame
    // is a context switch between them and the service's `YIELD` *is* the
    // handoff — which is why spinning instead of yielding made it worse, not
    // better, and why a doorbell changed nothing. The driver was never asleep;
    // it was runnable and waiting for the processor.
    //
    // Measured, three runs each, RFC 0018 step 7's burst: **103–234 µs a round
    // trip sharing a CPU, 34–149 µs apart.** The copies cost nanoseconds and
    // the wake cost nothing measurable; this is where the boundary's price was.
    //
    // Only when there are at least three processors. With two, `cpu` is 1 and
    // the only other is the boot processor, and moving a busy service onto the
    // thread bringing the machine up trades one contention for a worse one.
    let ip_cpu = if bhaskix_arch::percpu::online_count() >= 3 {
        cpu.saturating_sub(1)
    } else {
        cpu
    };
    if let Err(reason) = start_ip_domain(ip_cpu, hhdm_base, realm, keeper) {
        println!("\x1b[91m    net ring       FAILED: {reason}\x1b[0m");
    }

    let options = sched::SpawnOptions::new()
        .pinned()
        .in_domain(realm.as_u32());
    sched::spawn_on_with(cpu, "netd", net_domain_entry, hhdm_base, hhdm_base, options)
        .map_err(|_| "the net domain would not spawn")?;

    NET_RINGS.store(rings.as_u64(), core::sync::atomic::Ordering::Release);
    Ok(())
}

/// Creates the ring between `bin/netd` and `bin/ipd`, and starts `bin/ipd`.
///
/// # Errors
///
/// Any capability that would not be created or installed. Every one of them
/// leaves the machine bootable: a network stack is a convenience, and a kernel
/// that refuses to boot without one is worse than a kernel with no network.
fn start_ip_domain(
    cpu: u32,
    hhdm_base: u64,
    net: domain::DomainId,
    keeper: domain::DomainId,
) -> Result<(), &'static str> {
    let realm = domain::create("ip", domain::ResourceEnvelope::new())
        .map_err(|_| "the ip domain would not be created")?;

    // The ring is owned by `net-keeper` rather than by either side of it. Both
    // domains die independently and the ring must outlive whichever goes
    // first, which is why a keeper exists at all — and it is the *same* keeper
    // that holds the device's rings rather than a second one, because a domain
    // is a fixed global resource and a keeper that keeps two things is not
    // worse at keeping either. A separate `net-ring-keeper` cost a slot, and
    // the slot was the one the bulk-path self-test needed on a UEFI boot.
    let ring =
        shared::create(keeper, NET_RING_BYTES).map_err(|_| "the ring would not be created")?;

    // The same object, named twice. Both sides map it **read-write**, because
    // both advance an index — so the rights do not enforce the direction here;
    // the protocol does. Worth stating rather than implying: `netd` already
    // holds the device and its DMA window, so a compromised `netd` has worse
    // available to it than scribbling a ring. A future ring between two domains
    // that are *not* in that relationship needs two objects, not one.
    let for_producer = shared::name(ring).map_err(|_| "the ring would not be named")?;
    let for_consumer = shared::name(ring).map_err(|_| "the ring would not be named twice")?;
    if domain::with(realm, |owner| {
        owner.cspace.install_at(0, for_consumer).is_ok()
    }) != Some(true)
    {
        return Err("the ring would not install in the ip domain");
    }
    if domain::with(net, |owner| {
        owner.cspace.install_at(7, for_producer).is_ok()
    }) != Some(true)
    {
        return Err("the ring would not install in the net domain");
    }

    // The return ring, `ipd` to `netd`. A second object rather than a second
    // direction on the first, because `abi::ring` is single-producer and its
    // two indices are the whole of its discipline: two producers on one ring
    // would be two writers of one `head`.
    let back = shared::create(keeper, NET_RING_BYTES)
        .map_err(|_| "the return ring would not be created")?;
    let back_producer = shared::name(back).map_err(|_| "the return ring would not be named")?;
    let back_consumer =
        shared::name(back).map_err(|_| "the return ring would not be named twice")?;
    if domain::with(realm, |owner| {
        owner.cspace.install_at(2, back_producer).is_ok()
    }) != Some(true)
    {
        return Err("the return ring would not install in the ip domain");
    }
    if domain::with(net, |owner| {
        owner.cspace.install_at(8, back_consumer).is_ok()
    }) != Some(true)
    {
        return Err("the return ring would not install in the net domain");
    }

    // What this interface *is*, which `ipd` cannot find out for itself: it
    // holds no device to ask, and an ARP packet carries the sender's hardware
    // and protocol addresses, so it cannot build one without both.
    //
    // Read-only, because it is the kernel's statement rather than a shared
    // scratchpad. Filled *later* — the MAC is a number only the driver can read
    // out of the device, so this page is written once `netd` has reported it,
    // and `ipd` waits for the marker rather than reading a page of zeroes.
    let config = shared::create(keeper, bhaskix_mm::FRAME_SIZE)
        .map_err(|_| "the ip config page would not be created")?;
    // Named first, then derived — and **not** both inside `with_arena`, which
    // is what this was and what the lock-order detector refused: `shared::name`
    // takes the capability arena itself, so calling it from inside a
    // `with_arena` closure is the arena blocking on the arena. The report named
    // the file and line, which is the whole reason that check exists.
    let config_root = shared::name(config).map_err(|_| "the ip config would not be named")?;
    let config_named =
        cap::with_arena(|arena| arena.derive(config_root, cap::Rights::READ, 0).ok())
            .ok_or("the ip config capability would not derive")?;
    if domain::with(realm, |owner| {
        owner.cspace.install_at(3, config_named).is_ok()
    }) != Some(true)
    {
        return Err("the ip config would not install");
    }
    NET_CONFIG.store(config.as_u64(), core::sync::atomic::Ordering::Release);

    // One page for what `ipd` finds, read by the kernel the same way `netd`'s
    // report is. A driver has no business printing and neither has a service.
    let report = shared::create(keeper, bhaskix_mm::FRAME_SIZE)
        .map_err(|_| "the ip report page would not be created")?;
    let named = shared::name(report).map_err(|_| "the ip report would not be named")?;
    if domain::with(realm, |owner| owner.cspace.install_at(1, named).is_ok()) != Some(true) {
        return Err("the ip report would not install");
    }

    // The endpoint programs reach the network through, at slot 4 and
    // **unbadged** — this is the service's own, the one it receives on. Every
    // socket it hands out will be a *badged, weaker* capability to this same
    // endpoint, which is the shape RFC 0016 settled for directories and the
    // reason step 5 needs no new object kind.
    let net_endpoint = ipc::create().map_err(|_| "no endpoint for the protocol service")?;
    let serving = cap::with_arena(|arena| {
        arena
            .insert_root(
                cap::ObjectRef::new(cap::ObjectKind::Endpoint, u64::from(net_endpoint.as_u32())),
                cap::Rights::ALL,
                0,
            )
            .ok()
    })
    .ok_or("the network endpoint capability would not be created")?;
    if domain::with(realm, |owner| owner.cspace.install_at(4, serving).is_ok()) != Some(true) {
        return Err("the network endpoint capability would not install");
    }
    NET_ENDPOINT.store(
        u64::from(net_endpoint.as_u32()),
        core::sync::atomic::Ordering::Release,
    );

    // **`bin/ipd`'s inbox, and `bin/netd`'s doorbell onto it.**
    //
    // RFC 0010 question 1, answered 2026-08-13. Until this existed `ipd` had to
    // choose: block on its endpoint and be deaf to arriving frames, or poll the
    // ring and burn a processor. It polled — about thirty-seven looks per
    // frame. Now it binds this notification, and its blocking receive wakes for
    // whichever comes first, with the badge saying which.
    //
    // Read for the service, write for the driver. Neither can do the other's
    // half: `ipd` cannot signal itself awake, and `netd` cannot consume the
    // wake it is supposed to be sending.
    let inbox = crate::notify::create().ok();
    if let Some(inbox) = inbox {
        IP_INBOX.store(
            u64::from(inbox.index()) | (u64::from(inbox.generation()) << 32) | 1 << 63,
            core::sync::atomic::Ordering::Release,
        );
        let for_service = crate::notify::name(inbox).ok().and_then(|root| {
            cap::with_arena(|arena| arena.derive(root, cap::Rights::READ, 0).ok())
        });
        let for_driver = crate::notify::name(inbox).ok().and_then(|root| {
            cap::with_arena(|arena| arena.derive(root, cap::Rights::WRITE, NET_INBOX_BADGE).ok())
        });
        match (for_service, for_driver) {
            (Some(service), Some(driver))
                if domain::with(realm, |owner| owner.cspace.install_at(6, service).is_ok())
                    == Some(true)
                    && domain::with(net, |owner| owner.cspace.install_at(9, driver).is_ok())
                        == Some(true) => {}
            _ => {
                crate::notify::destroy(inbox);
                return Err("the inbox notification would not install");
            }
        }
    }

    // **The doorbell. RFC 0010 step 6, and the reason step 2 was built.**
    //
    // `bin/netd` sleeps on one notification. Its device's interrupt already
    // sets bit 2 of that notification's word; this gives `bin/ipd` a capability
    // to the *same* notification carrying a different bit, so the driver wakes
    // for either and the word says which.
    //
    // That is RFC 0010's badge-as-bitmask used for exactly what it was designed
    // for -- "64 distinguishable senders, one wait" -- and it is why `netd`
    // needs no second slot, no second wait and no change at all.
    //
    // **Write only.** A doorbell rings; it does not listen. `WAIT` needs the
    // read right and this capability does not carry it, so a bug in `ipd`
    // cannot consume the wake the driver is asleep for.
    let doorbell = {
        use core::sync::atomic::Ordering;
        let raw = NET_WAKE.load(Ordering::Acquire);
        if raw & (1 << 63) == 0 {
            None
        } else {
            let id = crate::notify::NotificationId::from_parts(
                raw as u32,
                (raw >> 32) as u32 & 0x7fff_ffff,
            );
            crate::notify::name(id).ok().and_then(|root| {
                cap::with_arena(|arena| {
                    arena
                        .derive(root, cap::Rights::WRITE, NET_DOORBELL_BADGE)
                        .ok()
                })
            })
        }
    };
    // Absent on a machine with no interrupt to delegate, which is every BIOS
    // boot. `ipd` finds an empty slot and does not ring, exactly as it finds an
    // empty ring and does not send.
    if let Some(doorbell) = doorbell
        && domain::with(realm, |owner| owner.cspace.install_at(5, doorbell).is_ok()) != Some(true)
    {
        return Err("the doorbell capability would not install");
    }

    // **Before `ipd` is spawned — capability before program, and this order
    // was abandoned once and reinstated with a correction worth recording.**
    // `start_tcp_domain` installs `ipd`'s ring slots, and installing them
    // after the spawn lost a race to `ipd`'s first attaches on every boot.
    // Moving the call here was tried on 2026-08-14 and rolled back, because
    // boots started stranding callers and losing wakes — which looked like
    // this order's fault and was not: the strandings were the notified-
    // receive blocked-mark bug (`sched::clear_blocked_mark` carries that
    // story), taking its coin toss under the changed timing. With that bug
    // fixed, the rolled-back order came back for a second reason too: running
    // this function *concurrently with a just-started `ipd`* — the rolled-
    // forward arrangement — intermittently deadlocked the boot thread against
    // `ipd`'s startup system calls, one boot in a handful, hanging bring-up
    // before `netd` existed. Setup first, program second, ends both races.
    // `ipd` still retries its attaches, which now merely tolerates a slower
    // install rather than papering over a lost one.
    let tcp_cpu = if bhaskix_arch::percpu::online_count() >= 4 {
        cpu.saturating_sub(2)
    } else {
        cpu
    };
    if let Err(reason) = start_tcp_domain(tcp_cpu, hhdm_base, realm, keeper) {
        println!("\x1b[91m    tcp domain     FAILED: {reason}\x1b[0m");
    } else if let Err(reason) = start_tcp_client_domain(tcp_cpu, hhdm_base, keeper) {
        println!("\x1b[91m    tcp client     FAILED: {reason}\x1b[0m");
    }

    let options = sched::SpawnOptions::new()
        .pinned()
        .in_domain(realm.as_u32());
    sched::spawn_on_with(cpu, "ipd", ip_domain_entry, hhdm_base, hhdm_base, options)
        .map_err(|_| "the ip domain would not spawn")?;

    NET_RING_REPORT.store(report.as_u64(), core::sync::atomic::Ordering::Release);

    println!(
        "    net ring       {} KiB between netd and ipd; bin/ipd started, holding two \
         capabilities and no device",
        NET_RING_BYTES / 1024
    );
    Ok(())
}

/// Creates the rings between `bin/ipd` and `bin/tcpd`, and starts `bin/tcpd`.
///
/// [RFC 0020](../../docs/rfc/0020-tcp.md) step 4: a third network domain,
/// because TCP is the largest remote-driven *stateful* parser this system will
/// contain and a bug in it must not take down the domain holding the machine's
/// address and every UDP socket. The shape is `start_ip_domain`'s exactly —
/// two rings owned by the keeper, a config page, a report page, an endpoint,
/// and an inbox rung by a doorbell — because that shape has now carried two
/// services and is the thing RFC 0013 promised would be repeatable.
///
/// # Errors
///
/// Any capability that would not be created or installed. Every one leaves the
/// machine bootable, for the reason `start_ip_domain` gives.
fn start_tcp_domain(
    cpu: u32,
    hhdm_base: u64,
    ip: domain::DomainId,
    keeper: domain::DomainId,
) -> Result<(), &'static str> {
    let realm = domain::create("tcp", domain::ResourceEnvelope::new())
        .map_err(|_| "the tcp domain would not be created")?;

    // The forward ring: `ipd` produces TCP payloads into it, `tcpd` consumes.
    let forward = shared::create(keeper, NET_RING_BYTES)
        .map_err(|_| "the tcp forward ring would not be created")?;
    let for_producer =
        shared::name(forward).map_err(|_| "the tcp forward ring would not be named")?;
    let for_consumer =
        shared::name(forward).map_err(|_| "the tcp forward ring would not be named twice")?;
    if domain::with(realm, |owner| {
        owner.cspace.install_at(0, for_consumer).is_ok()
    }) != Some(true)
    {
        return Err("the tcp forward ring would not install in the tcp domain");
    }
    if domain::with(ip, |owner| owner.cspace.install_at(7, for_producer).is_ok()) != Some(true) {
        return Err("the tcp forward ring would not install in the ip domain");
    }

    // The back ring: `tcpd` produces segments, `ipd` wraps and transmits them.
    let back = shared::create(keeper, NET_RING_BYTES)
        .map_err(|_| "the tcp back ring would not be created")?;
    let back_producer = shared::name(back).map_err(|_| "the tcp back ring would not be named")?;
    let back_consumer =
        shared::name(back).map_err(|_| "the tcp back ring would not be named twice")?;
    if domain::with(realm, |owner| {
        owner.cspace.install_at(2, back_producer).is_ok()
    }) != Some(true)
    {
        return Err("the tcp back ring would not install in the tcp domain");
    }
    if domain::with(ip, |owner| {
        owner.cspace.install_at(8, back_consumer).is_ok()
    }) != Some(true)
    {
        return Err("the tcp back ring would not install in the ip domain");
    }

    // One page for what `tcpd` finds, read by the kernel like every report.
    let report = shared::create(keeper, bhaskix_mm::FRAME_SIZE)
        .map_err(|_| "the tcp report page would not be created")?;
    let named = shared::name(report).map_err(|_| "the tcp report would not be named")?;
    if domain::with(realm, |owner| owner.cspace.install_at(1, named).is_ok()) != Some(true) {
        return Err("the tcp report would not install");
    }

    // What interface this machine is. Read-only, filled by
    // `publish_net_config` once the driver has read the address — the same
    // page format `ipd` waits on, written by the same code.
    let config = shared::create(keeper, bhaskix_mm::FRAME_SIZE)
        .map_err(|_| "the tcp config page would not be created")?;
    let config_root = shared::name(config).map_err(|_| "the tcp config would not be named")?;
    let config_named =
        cap::with_arena(|arena| arena.derive(config_root, cap::Rights::READ, 0).ok())
            .ok_or("the tcp config capability would not derive")?;
    if domain::with(realm, |owner| {
        owner.cspace.install_at(3, config_named).is_ok()
    }) != Some(true)
    {
        return Err("the tcp config would not install");
    }
    TCP_CONFIG.store(config.as_u64(), core::sync::atomic::Ordering::Release);

    // The endpoint programs will reach TCP through, unbadged and the
    // service's own. Step 5 hands out badged, weaker capabilities to it.
    let endpoint = ipc::create().map_err(|_| "no endpoint for the tcp service")?;
    let serving = cap::with_arena(|arena| {
        arena
            .insert_root(
                cap::ObjectRef::new(cap::ObjectKind::Endpoint, u64::from(endpoint.as_u32())),
                cap::Rights::ALL,
                0,
            )
            .ok()
    })
    .ok_or("the tcp endpoint capability would not be created")?;
    if domain::with(realm, |owner| owner.cspace.install_at(4, serving).is_ok()) != Some(true) {
        return Err("the tcp endpoint capability would not install");
    }
    TCP_ENDPOINT.store(
        u64::from(endpoint.as_u32()),
        core::sync::atomic::Ordering::Release,
    );

    // `tcpd`'s inbox: a deadline it arms fires through the same word `ipd`'s
    // doorbell rings, so one blocking receive wakes for a caller, a frame or a
    // timer — the loop RFC 0010 spent two questions arguing towards, in its
    // third service.
    let inbox = crate::notify::create().map_err(|_| "the tcp inbox would not be created")?;
    let for_service = crate::notify::name(inbox).ok().and_then(|root| {
        cap::with_arena(|arena| {
            arena
                .derive(
                    root,
                    cap::Rights::READ.union(cap::Rights::WRITE),
                    TCP_TIMER_BADGE,
                )
                .ok()
        })
    });
    let for_ip = crate::notify::name(inbox).ok().and_then(|root| {
        cap::with_arena(|arena| arena.derive(root, cap::Rights::WRITE, TCP_FRAME_BADGE).ok())
    });
    match (for_service, for_ip) {
        (Some(service), Some(bell))
            if domain::with(realm, |owner| owner.cspace.install_at(6, service).is_ok())
                == Some(true)
                && domain::with(ip, |owner| owner.cspace.install_at(9, bell).is_ok())
                    == Some(true) => {}
        _ => {
            crate::notify::destroy(inbox);
            return Err("the tcp inbox would not install");
        }
    }

    // `tcpd`'s doorbell onto `ipd`'s inbox: a third bit in a word two senders
    // already share, which is the badge-as-bitmask working at the scale it was
    // designed for. Write-only, so a bug in `tcpd` cannot eat a wake.
    let doorbell = {
        use core::sync::atomic::Ordering;
        let raw = IP_INBOX.load(Ordering::Acquire);
        if raw & (1 << 63) == 0 {
            None
        } else {
            let id = crate::notify::NotificationId::from_parts(
                raw as u32,
                (raw >> 32) as u32 & 0x7fff_ffff,
            );
            crate::notify::name(id).ok().and_then(|root| {
                cap::with_arena(|arena| arena.derive(root, cap::Rights::WRITE, IP_TCP_BADGE).ok())
            })
        }
    };
    if let Some(doorbell) = doorbell
        && domain::with(realm, |owner| owner.cspace.install_at(5, doorbell).is_ok()) != Some(true)
    {
        return Err("the tcp doorbell would not install");
    }

    let options = sched::SpawnOptions::new()
        .pinned()
        .in_domain(realm.as_u32());
    sched::spawn_on_with(cpu, "tcpd", tcp_domain_entry, hhdm_base, hhdm_base, options)
        .map_err(|_| "the tcp domain would not spawn")?;

    TCP_REPORT.store(report.as_u64(), core::sync::atomic::Ordering::Release);

    println!(
        "    tcp domain     bin/tcpd started: two rings to ipd, an endpoint, a timer, and no \
         device"
    );
    Ok(())
}

/// Loads `bin/tcpd` into a fresh address space and enters it.
///
/// The same steps `ip_domain_entry` takes, for the same reasons, with one
/// addition borrowed from the DHCP client: the cycle counter's rate goes in as
/// the entry argument, because the TCP service arms deadlines and a deadline
/// is a duration times a rate — the one fact about the clock that cannot
/// arrive through a CSpace.
extern "C" fn tcp_domain_entry(hhdm_base: u64) -> ! {
    use bhaskix_boot::VirtAddr;
    use bhaskix_mm::{Protection, VirtRange};
    use vm::AddressSpace;

    let stop = |why: &str| -> ! {
        println!("\x1b[91m    tcp domain     FAILED: {why}\x1b[0m");
        sched::exit()
    };

    let Ok(file) = vfs::open(TCPD_PROGRAM) else {
        stop("bin/tcpd is not in the filesystem")
    };
    let Ok(image) = elf::parse(file.bytes()) else {
        stop("bin/tcpd is not an ELF this kernel will load")
    };
    let Ok(mut space) = AddressSpace::new(hhdm_base) else {
        stop("the address space would not be created")
    };
    let Some(stack) = VirtRange::from_pages(VirtAddr(TCPD_STACK), TCPD_STACK_PAGES) else {
        stop("the stack range is not a range")
    };
    if space.map_anonymous(stack, Protection::ReadWrite).is_err() {
        stop("the stack would not map")
    }
    let Ok(entry) = elf::load_into(&image, file.bytes(), &mut space, hhdm_base) else {
        stop("bin/tcpd would not load")
    };

    // SAFETY: the higher half is copied from the running page table, so
    // everything currently executing stays addressable.
    unsafe { vm::install(space) };

    let rsp = TCPD_STACK + TCPD_STACK_PAGES * bhaskix_mm::FRAME_SIZE;
    let hertz = bhaskix_arch::tsc::hertz().unwrap_or(0);
    // SAFETY: `entry` is inside a user-executable segment of the space just
    // installed, `rsp` is one past user-writable memory in the same space, and
    // `RSP0` was set before this thread was spawned.
    unsafe { enter_user("tcp domain", entry, rsp, [hertz, 0]) }
}

/// The page `bin/linuxd` leaves its trace in.
static ADAPTER_REPORT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(u64::MAX);

/// Where `bin/linuxd`'s stack lives, and what it is called.
const LINUXD_STACK: u64 = 0x0000_0000_1D00_0000;
const LINUXD_STACK_PAGES: u64 = 8;
const LINUXD_PROGRAM: &[u8] = b"bin/linuxd";

/// Starts `bin/linuxd`, the Linux personality in a domain of its own.
///
/// [RFC 0032](../../docs/rfc/0032-a-supervisor-interface.md) step 3, and the
/// first time [RFC 0005](../../docs/rfc/0005-linux-abi-compatibility.md)'s
/// "Where it lives" has been true of anything: a foreign system call the
/// nucleus does not answer is delivered here instead of being refused.
///
/// The shape is `start_tcp_domain`'s, because that shape has now carried three
/// services and is the thing RFC 0013 promised would be repeatable: a console
/// to report through, an endpoint of its own, and nothing else. **It holds no
/// filesystem and no device**, which is what makes the containment claim
/// checkable rather than asserted — a bug in the largest untrusted-input
/// parser this project will ever have reaches a console and an endpoint.
///
/// Started *before* the Linux self-tests, because they are its first callers.
///
/// # Errors
///
/// A string naming what would not be built. Every one is survivable: a machine
/// with no adapter answers every unhandled foreign call `-ENOSYS`, which is
/// exactly what it did before this existed.
/// The adapter's first futex-wake slot, and how many there are.
///
/// Sixteen because that is how many hosted threads may be asleep in a futex at
/// once, and because the kernel's whole notification table is thirty-two
/// ([`notify::MAX_NOTIFICATIONS`]) — half of it is as much as one personality
/// may take. A seventeenth sleeper is refused with `EAGAIN`, which is a Linux
/// answer a correct caller already retries.
const FUTEX_WAKE_SLOT: usize = 4;
const FUTEX_WAKES: usize = 16;

/// The futex wake notifications, by identity, for the end-of-boot check below.
static FUTEX_WAKE_IDS: [core::sync::atomic::AtomicU64; FUTEX_WAKES] =
    [const { core::sync::atomic::AtomicU64::new(u64::MAX) }; FUTEX_WAKES];

/// How many futex wake notifications still hold bits nobody took, and which.
///
/// **Non-destructive**, deliberately: `notify::poll` takes the word, and a
/// check that consumed the evidence would clear the very thing it is reporting
/// and change the next boot's behaviour while measuring it.
fn futex_wakes_left_dirty() -> (usize, u64) {
    let mut dirty = 0;
    let mut which = 0u64;
    for (index, id) in FUTEX_WAKE_IDS.iter().enumerate() {
        let raw = id.load(core::sync::atomic::Ordering::Acquire);
        if raw == u64::MAX {
            continue;
        }
        let notification =
            crate::notify::NotificationId::from_parts(raw as u32, (raw >> 32) as u32);
        if crate::notify::peek(notification) != 0 {
            dirty += 1;
            which |= 1 << index;
        }
    }
    (dirty, which)
}

fn start_linux_domain(cpu: u32, hhdm_base: u64) -> Result<(), &'static str> {
    // **An envelope that allows children**, which is what `execve` needs — RFC
    // 0033 step 5. A hosted process that execs becomes a *new* domain, and the
    // adapter is what creates it, so the authority to create domains is the
    // adapter's and the *number* of them is this envelope's. Sixteen, and the
    // number is a limit rather than a guess: an exec'd domain is not reaped
    // until `wait4` exists to reap it (RFC 0033 step 9), so this is also how
    // many execs a boot may serve before the seventeenth is refused. A refusal
    // a hosted program can see beats a machine that quietly stops working.
    let realm = domain::create(
        "linux",
        domain::ResourceEnvelope::new().max_child_domains(16),
    )
    .map_err(|_| "the linux domain would not be created")?;

    // Slot 0, and the only slot: the endpoint foreign calls arrive on. The
    // adapter's own, and unbadged -- what distinguishes its callers is the
    // badge the *kernel* stamps on delivery, which names the hosted domain and
    // which no caller can supply.
    //
    // **Not even a console**, and not for tidiness: this is started before the
    // console service exists, because its first callers are the Linux
    // self-tests and those run long before `user_shell`. Rather than reorder
    // the boot to give an adapter somewhere to print, it holds nothing and the
    // boundary report says what it did from the kernel's own counters. The
    // containment claim is the better for it: a bug in the largest
    // untrusted-input parser this project will ever have reaches one endpoint.
    let endpoint = ipc::create().map_err(|_| "no endpoint for the linux adapter")?;
    let serving = cap::with_arena(|arena| {
        arena
            .insert_root(
                cap::ObjectRef::new(cap::ObjectKind::Endpoint, u64::from(endpoint.as_u32())),
                cap::Rights::ALL,
                0,
            )
            .ok()
    })
    .ok_or("the adapter's endpoint capability would not be created")?;

    // Slot 1: one page to report through. **Not a console** — the adapter is
    // started before the console service exists, and every other service on
    // this machine that must say something before there is a console says it
    // the same way: it writes into a page the kernel reads. `bin/tcpd` has
    // done this since RFC 0020.
    let report = shared::create(realm, bhaskix_mm::FRAME_SIZE)
        .map_err(|_| "the adapter's report page would not be created")?;
    let named = shared::name(report).map_err(|_| "the adapter's report would not be named")?;

    if domain::with(realm, |owner| {
        owner.cspace.install_at(0, serving).is_ok() && owner.cspace.install_at(1, named).is_ok()
    }) != Some(true)
    {
        return Err("the adapter's capabilities would not install");
    }
    ADAPTER_REPORT.store(report.as_u64(), core::sync::atomic::Ordering::Release);

    // Slot 2: the page a hosted program's fault is handed over in. One slot
    // per fault in flight -- see `fault.rs` for why a single buffer would give
    // one faulting CPU another's registers.
    let faults = shared::create(realm, fault::SLOTS as u64 * fault::SLOT_BYTES)
        .map_err(|_| "the adapter's fault page would not be created")?;
    let fault_named =
        shared::name(faults).map_err(|_| "the adapter's fault page would not be named")?;
    if domain::with(realm, |owner| {
        owner.cspace.install_at(2, fault_named).is_ok()
    }) != Some(true)
    {
        return Err("the adapter's fault page would not install");
    }

    // Slot 3: the console, **write-only** -- RFC 0032 step 10. A hosted
    // program's `write` has to reach a console somehow, and until now the
    // nucleus did the printing on its behalf, which is the last thing it did
    // for a Linux number. This capability is the whole of what the adapter may
    // do to the machine's console: put a character. It cannot take a byte
    // somebody typed, because `Rights::WRITE` does not include `READ` and the
    // console path checks -- a check that was unreachable while the console
    // service was the only holder.
    //
    // Granted here, at boot, and not through the console *service*: this
    // domain starts before that service exists, and the object it names is the
    // machine's console, which exists from the first `println!`.
    let console = cap::with_arena(|arena| {
        arena
            .insert_root(
                cap::ObjectRef::new(cap::ObjectKind::Console, CONSOLE_OBJECT),
                cap::Rights::WRITE,
                0,
            )
            .ok()
    })
    .ok_or("the adapter's console capability would not be created")?;
    if domain::with(realm, |owner| owner.cspace.install_at(3, console).is_ok()) != Some(true) {
        return Err("the adapter's console would not install");
    }

    // Slots 4 onwards: the notification pool — RFC 0032 step 10's other half.
    //
    // **A hosted `futex(WAIT)` has to park a thread, and only the kernel can
    // park one.** The adapter says so with a `BLOCK_ON` reply naming one of
    // these; the kernel blocks the calling thread on it and answers zero when
    // it is signalled. One notification per parked waiter, which is what makes
    // an exact wake count expressible in ring 3 -- `futex(WAKE, n)` signals
    // *n* of them -- and what `notify::wait`'s one-waiter-at-a-time rule wants
    // anyway.
    //
    // **`WRITE` and not `READ`**: the adapter may wake a sleeper and may not
    // become one. A single-threaded server that could block on a notification
    // could stop answering, and nothing about a futex needs it to.
    //
    // Granted at boot because a domain cannot create a notification -- there
    // is no method for it, deliberately -- so the pool is a fixed grant and
    // its size is a fixed limit: this many hosted threads may sleep in a futex
    // at once, and the adapter refuses the next with EAGAIN rather than
    // silently losing it.
    for (index, recorded) in FUTEX_WAKE_IDS.iter().enumerate() {
        let wake = crate::notify::create().map_err(|_| "a futex wake would not be created")?;
        // **Kept so the boot can ask whether any of them was left dirty.** A
        // notification latches the bits a signal sets and holds them until a
        // waiter takes them -- RFC 0010, and `notify`'s own test asserts it. If
        // a sleeper were signalled and then never parked, the bit would stay,
        // and the *next* hosted thread in that slot would take it as its own
        // wake.
        //
        // That was a hypothesis about the `linux clone` intermittent on
        // 2026-08-27, and measuring it before building on it is the only reason
        // it is known to be **wrong**: no futex notification has ever been found
        // dirty, on a passing boot or on a failing one. The cause was elsewhere
        // -- the test read the child's word before the child had written it.
        // The check stays because it costs nothing and rules out a whole class
        // in one glance.
        recorded.store(
            u64::from(wake.generation()) << 32 | u64::from(wake.index()),
            core::sync::atomic::Ordering::Release,
        );
        let handed = crate::notify::name(wake)
            .ok()
            .and_then(|root| {
                cap::with_arena(|arena| arena.derive(root, cap::Rights::WRITE, 1).ok())
            })
            .ok_or("a futex wake would not be named")?;
        if domain::with(realm, |owner| {
            owner
                .cspace
                .install_at(FUTEX_WAKE_SLOT + index, handed)
                .is_ok()
        }) != Some(true)
        {
            return Err("a futex wake would not install");
        }
    }

    // Slot 20: the authority to create a domain — RFC 0033 step 5, and the
    // largest grant this program has been given.
    //
    // **`execve` is why.** A hosted process that execs cannot reuse its own
    // domain: `START` refuses a domain that has threads, and the thread asking
    // is one. So the exec builds a new domain and ends the old one, and the
    // thing that builds it is the adapter — which means the adapter holds
    // `DomainControl`. Necessary and not sufficient: the envelope above says
    // how many, and every capability the child gets is one the adapter passes.
    //
    // This is the grant `security.md` §1's T11 note said was coming. It is
    // real now, and that note says so rather than predicting it.
    let control = cap::with_arena(|arena| {
        arena
            .insert_root(
                cap::ObjectRef::new(cap::ObjectKind::DomainControl, 0),
                cap::Rights::ALL,
                0,
            )
            .ok()
    })
    .ok_or("the adapter's DomainControl would not be created")?;
    if domain::with(realm, |owner| owner.cspace.install_at(20, control).is_ok()) != Some(true) {
        return Err("the adapter's DomainControl would not install");
    }

    // **Slot 22 is granted later**, by `grant_console_wake`, and not here: the
    // console's notification does not exist yet. This program is started before
    // the Linux self-tests, and the serial line is claimed near the end of
    // bring-up.

    let options = sched::SpawnOptions::new()
        .pinned()
        .in_domain(realm.as_u32());
    sched::spawn_on_with(
        cpu,
        "linuxd",
        linux_domain_entry,
        hhdm_base,
        hhdm_base,
        options,
    )
    .map_err(|_| "the adapter's thread would not spawn")?;

    // Published only once the program is on its way, so a foreign call cannot
    // find an endpoint whose server does not exist yet and block on it.
    //
    // It is still possible to arrive before the adapter's first `Recv` -- the
    // caller queues, which is what an endpoint is for -- but not to arrive
    // before there is anybody who will ever receive.
    syscall::ADAPTER_DOMAIN.store(realm.as_u32(), core::sync::atomic::Ordering::Release);
    fault::PAGE.store(faults.as_u64(), core::sync::atomic::Ordering::Release);
    syscall::ADAPTER_ENDPOINT.store(
        u64::from(endpoint.as_u32()),
        core::sync::atomic::Ordering::Release,
    );
    Ok(())
}

/// Loads `bin/linuxd` and enters ring 3, the same way every other domain does.
extern "C" fn linux_domain_entry(hhdm_base: u64) -> ! {
    use bhaskix_boot::VirtAddr;
    use bhaskix_mm::{Protection, VirtRange};
    use vm::AddressSpace;

    let stop = |why: &str| -> ! {
        println!("\x1b[91m    linux domain   {why}\x1b[0m");
        sched::exit()
    };
    let Ok(file) = vfs::open(LINUXD_PROGRAM) else {
        stop("bin/linuxd is not in the filesystem")
    };
    let Ok(image) = elf::parse(file.bytes()) else {
        stop("bin/linuxd is not an ELF this kernel will load")
    };
    let Ok(mut space) = AddressSpace::new(hhdm_base) else {
        stop("the address space would not be created")
    };
    let Some(stack) = VirtRange::from_pages(VirtAddr(LINUXD_STACK), LINUXD_STACK_PAGES) else {
        stop("the stack range is not a range")
    };
    if space.map_anonymous(stack, Protection::ReadWrite).is_err() {
        stop("the stack would not map")
    }
    let Ok(entry) = elf::load_into(&image, file.bytes(), &mut space, hhdm_base) else {
        stop("bin/linuxd would not load")
    };

    // SAFETY: the higher half is copied from the running page table, so
    // everything currently executing stays addressable.
    unsafe { vm::install(space) };

    let rsp = LINUXD_STACK + LINUXD_STACK_PAGES * bhaskix_mm::FRAME_SIZE;
    let hertz = bhaskix_arch::tsc::hertz().unwrap_or(0);
    // SAFETY: `entry` is inside a user-executable segment of the space just
    // installed, `rsp` is one past user-writable memory in the same space, and
    // `RSP0` was set before this thread was spawned.
    unsafe { enter_user("linux domain", entry, rsp, [hertz, 0]) }
}

/// The page `bin/ipd` leaves its findings in.
static NET_RING_REPORT: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(u64::MAX);

/// The page telling `bin/ipd` what this interface is.
static NET_CONFIG: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(u64::MAX);

/// Starts `bin/dhcp`, which asks the network for an address.
///
/// # Errors
///
/// Any capability that would not be created or installed. None is fatal: a
/// machine that cannot ask for an address still boots with the one the kernel
/// hardcoded.
fn start_dhcp_client(
    cpu: u32,
    hhdm_base: u64,
    keeper: domain::DomainId,
    endpoint: ipc::EndpointId,
) -> Result<(), &'static str> {
    let realm = domain::create("dhcp", domain::ResourceEnvelope::new())
        .map_err(|_| "the dhcp domain would not be created")?;

    let network = cap::with_arena(|arena| {
        arena
            .insert_root(
                cap::ObjectRef::new(cap::ObjectKind::Endpoint, u64::from(endpoint.as_u32())),
                cap::Rights::ALL,
                0,
            )
            .ok()
    })
    .ok_or("the client's network capability would not be created")?;
    if domain::with(realm, |owner| owner.cspace.install_at(0, network).is_ok()) != Some(true) {
        return Err("the client's network capability would not install");
    }

    // Slot 1 is left **empty on purpose**: it is where the socket lands, and
    // the client declares it with `EXPECT` before asking. A slot the kernel
    // pre-filled would be a slot `HAND` could not use.
    let memory = shared::create(keeper, bhaskix_mm::FRAME_SIZE)
        .map_err(|_| "the client's memory would not be created")?;
    let named = shared::name(memory).map_err(|_| "the client's memory would not be named")?;
    // **A notification the client can arm a deadline on.** RFC 0019 step 3: it
    // waits for an offer by sleeping until a deadline rather than by counting
    // loop iterations, so its patience is a duration in its source instead of a
    // number somebody tuned by experiment.
    //
    // Read and write: it waits on this and arms it, and both are itself. The
    // badge is what the wake carries, so a client that later waits on more than
    // one source can tell them apart.
    const DHCP_TIMER_BADGE: u64 = 1 << 0;
    let timer = crate::notify::create()
        .ok()
        .and_then(|id| crate::notify::name(id).ok())
        .and_then(|root| {
            cap::with_arena(|arena| {
                arena
                    .derive(
                        root,
                        cap::Rights::READ.union(cap::Rights::WRITE),
                        DHCP_TIMER_BADGE,
                    )
                    .ok()
            })
        });
    // Absent is a state, not a fault: the client then behaves as it did before.
    if let Some(timer) = timer
        && domain::with(realm, |owner| owner.cspace.install_at(4, timer).is_ok()) != Some(true)
    {
        return Err("the dhcp client's timer would not install");
    }

    if domain::with(realm, |owner| owner.cspace.install_at(2, named).is_ok()) != Some(true) {
        return Err("the client's memory would not install");
    }

    let report = shared::create(keeper, bhaskix_mm::FRAME_SIZE)
        .map_err(|_| "the client's report page would not be created")?;
    let named = shared::name(report).map_err(|_| "the client's report would not be named")?;
    if domain::with(realm, |owner| owner.cspace.install_at(3, named).is_ok()) != Some(true) {
        return Err("the client's report would not install");
    }

    let options = sched::SpawnOptions::new()
        .pinned()
        .in_domain(realm.as_u32());
    sched::spawn_on_with(
        cpu,
        "dhcp",
        dhcp_client_entry,
        hhdm_base,
        hhdm_base,
        options,
    )
    .map_err(|_| "the dhcp client would not spawn")?;

    DHCP_REPORT.store(report.as_u64(), core::sync::atomic::Ordering::Release);
    Ok(())
}

/// Starts `bin/udp6`, the v6 socket demonstration — RFC 0029 step 4.
///
/// `bin/dhcp`'s inventory exactly, granted the same way: the service
/// endpoint at 0, an empty slot at 1 for the socket, a page at 2, a report
/// page at 3, a timer at 4.
///
/// # Errors
///
/// Any capability that would not be created or installed. None is fatal: a
/// machine that cannot ask a v6 question still boots.
fn start_udp6_client(
    cpu: u32,
    hhdm_base: u64,
    keeper: domain::DomainId,
    endpoint: ipc::EndpointId,
) -> Result<(), &'static str> {
    let realm = domain::create("udp6", domain::ResourceEnvelope::new())
        .map_err(|_| "the udp6 domain would not be created")?;

    let network = cap::with_arena(|arena| {
        arena
            .insert_root(
                cap::ObjectRef::new(cap::ObjectKind::Endpoint, u64::from(endpoint.as_u32())),
                cap::Rights::ALL,
                0,
            )
            .ok()
    })
    .ok_or("the udp6 client's network capability would not be created")?;
    if domain::with(realm, |owner| owner.cspace.install_at(0, network).is_ok()) != Some(true) {
        return Err("the udp6 client's network capability would not install");
    }

    let memory = shared::create(keeper, bhaskix_mm::FRAME_SIZE)
        .map_err(|_| "the udp6 client's memory would not be created")?;
    let named = shared::name(memory).map_err(|_| "the udp6 client's memory would not be named")?;
    const UDP6_TIMER_BADGE: u64 = 1 << 0;
    let timer = crate::notify::create()
        .ok()
        .and_then(|id| crate::notify::name(id).ok())
        .and_then(|root| {
            cap::with_arena(|arena| {
                arena
                    .derive(
                        root,
                        cap::Rights::READ.union(cap::Rights::WRITE),
                        UDP6_TIMER_BADGE,
                    )
                    .ok()
            })
        });
    if let Some(timer) = timer
        && domain::with(realm, |owner| owner.cspace.install_at(4, timer).is_ok()) != Some(true)
    {
        return Err("the udp6 client's timer would not install");
    }

    if domain::with(realm, |owner| owner.cspace.install_at(2, named).is_ok()) != Some(true) {
        return Err("the udp6 client's memory would not install");
    }

    let report = shared::create(keeper, bhaskix_mm::FRAME_SIZE)
        .map_err(|_| "the udp6 client's report page would not be created")?;
    let named = shared::name(report).map_err(|_| "the udp6 client's report would not be named")?;
    if domain::with(realm, |owner| owner.cspace.install_at(3, named).is_ok()) != Some(true) {
        return Err("the udp6 client's report would not install");
    }

    let options = sched::SpawnOptions::new()
        .pinned()
        .in_domain(realm.as_u32());
    sched::spawn_on_with(
        cpu,
        "udp6",
        udp6_client_entry,
        hhdm_base,
        hhdm_base,
        options,
    )
    .map_err(|_| "the udp6 client would not spawn")?;

    UDP6_REPORT.store(report.as_u64(), core::sync::atomic::Ordering::Release);
    Ok(())
}

/// The endpoint `bin/ipd` serves the network on, once there is one.
static NET_ENDPOINT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(u64::MAX);

/// The keeper that owns the network's memory, plus one so zero means "none".
static NET_KEEPER: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// The endpoint the protocol service answers on, if it is serving.
fn net_service_endpoint() -> Option<ipc::EndpointId> {
    let raw = NET_ENDPOINT.load(core::sync::atomic::Ordering::Acquire);
    (raw != u64::MAX).then(|| ipc::EndpointId::from_u32(raw as u32))
}

/// The domain that keeps the network's memory alive.
///
/// One keeper for all of it, because a domain is a fixed global resource and a
/// keeper that keeps several things is no worse at keeping any of them.
fn net_keeper() -> domain::DomainId {
    domain::DomainId::from_u32(
        NET_KEEPER
            .load(core::sync::atomic::Ordering::Acquire)
            .saturating_sub(1),
    )
}

/// A capability to the protocol service's endpoint, for a program to hold.
///
/// **This is the whole of what "having networking" means for a program.** There
/// is no port table to ask and no interface list to enumerate: a program either
/// holds this or it has no way to name the network at all — which is not a
/// refused call, it is nothing to call.
fn network_endpoint_capability() -> Option<cap::SlotRef> {
    use core::sync::atomic::Ordering;

    let raw = NET_ENDPOINT.load(Ordering::Acquire);
    if raw == u64::MAX {
        return None;
    }
    cap::with_arena(|arena| {
        arena
            .insert_root(
                cap::ObjectRef::new(cap::ObjectKind::Endpoint, raw),
                cap::Rights::ALL,
                0,
            )
            .ok()
    })
}

/// The notification `bin/netd` sleeps on, with the top bit set when it is real.
static NET_WAKE: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// `bin/netd`'s bit in `bin/ipd`'s inbox. See `start_ip_domain`.
const NET_INBOX_BADGE: u64 = 1 << 1;

/// `bin/ipd`'s bit in that notification's word.
///
/// Distinct from the device's `1 << 2` so the driver can tell a frame arriving
/// from the wire from a frame `bin/ipd` has built for it. Neither sender chose
/// its own bit; the kernel stamped both at derivation, which is what makes the
/// distinction worth anything.
const NET_DOORBELL_BADGE: u64 = 1 << 3;

/// The marker `bin/ipd` waits for before believing its configuration.
const NET_CONFIG_MARKER: u64 = 0x3146_4e43_5049_5f4e;

/// This interface's IPv4 address.
///
/// Static, and RFC 0018 says why: *what owns the interface's address* is one of
/// its open questions, DHCP is a client holding a socket, and sockets do not
/// exist yet. `10.0.2.15` is what QEMU's built-in network hands a guest, so a
/// static choice and the emulator agree without either negotiating.
const NET_ADDRESS: [u8; 4] = [10, 0, 2, 15];

/// Tells `bin/ipd` its hardware and protocol addresses.
///
/// Called once `netd` has reported the MAC, because the MAC is a number only a
/// driver holding the device can read. Until then the page is zeroes with no
/// marker, and `ipd` waits rather than believing them.
fn publish_net_config(hhdm: u64, mac: u64) -> bool {
    use core::sync::atomic::Ordering;

    let raw = NET_CONFIG.load(Ordering::Acquire);
    if raw == u64::MAX {
        return false;
    }
    let Some((frames, count)) = shared::frames_of(shared::MemoryId::from_u64(raw)) else {
        return false;
    };
    if count == 0 {
        return false;
    }
    let address = u32::from_be_bytes(NET_ADDRESS);
    let words = [NET_CONFIG_MARKER, mac, u64::from(address)];
    // SAFETY: a frame this object owns, through the direct map. The marker goes
    // last, so a reader that catches this half-written sees no marker rather
    // than half a configuration.
    unsafe {
        for (index, word) in words.iter().enumerate().skip(1) {
            core::ptr::write_volatile((hhdm + frames[0] + index as u64 * 8) as *mut u64, *word);
        }
        core::sync::atomic::fence(Ordering::SeqCst);
        core::ptr::write_volatile((hhdm + frames[0]) as *mut u64, words[0]);
    }

    let raw = TCP_CONFIG.load(Ordering::Acquire);
    if raw != u64::MAX
        && let Some((frames, count)) = shared::frames_of(shared::MemoryId::from_u64(raw))
        && count > 0
    {
        // SAFETY: as above, on the tcp domain's page.
        unsafe {
            for (index, word) in words.iter().enumerate().skip(1) {
                core::ptr::write_volatile((hhdm + frames[0] + index as u64 * 8) as *mut u64, *word);
            }
            core::sync::atomic::fence(Ordering::SeqCst);
            core::ptr::write_volatile((hhdm + frames[0]) as *mut u64, words[0]);
        }
    }
    true
}

/// The rings the net domain was given, so its report can be read back.
static NET_RINGS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(u64::MAX);

/// Whether a unit contains the network device, so its driver could be given a
/// DMA window.
///
/// Recorded because the answer decides what the driver's report *means*. With
/// no window there is no device address for the rings, so the driver cannot
/// transmit and cannot receive — and reporting that as a failure would make
/// every BIOS boot red for a refusal working exactly as designed. The block
/// path learned this the other way round, when a message about a missing window
/// was printed from the interrupt's failure and made a gate excuse the wrong
/// thing.
static NET_CONTAINED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// The endpoint the block service answers on, once it exists.
static BLOCK_ENDPOINT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(u64::MAX);

/// The block service's endpoint, if there is a block service.
fn block_service_endpoint() -> Option<ipc::EndpointId> {
    let raw = BLOCK_ENDPOINT.load(core::sync::atomic::Ordering::Acquire);
    (raw != u64::MAX).then(|| ipc::EndpointId::from_u32(raw as u32))
}

/// The rings the block domain was given, so its report can be read back.
static BLOCK_RINGS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(u64::MAX);

/// The endpoint `bin/ahcid` answers `block::READ` on, or 0 if it cannot serve.
static AHCI_ENDPOINT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// The memory `bin/ahcid` leaves its report in, or `u64::MAX` if it never ran.
static AHCI_MEMORY: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(u64::MAX);

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
    // Thirty-two, not sixteen, and forty-eight since RFC 0030 step 4 --
    // each time it failed as `Full`, which is the allocator working; the
    // number was simply outgrown, first by the journal tree, then by two
    // installed packages.
    let blocks = 48u32;
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
/// The writable handle to `/pkg`, as the filesystem service reported it —
/// RFC 0030 step 3. Zero until the service says otherwise, and zero means
/// the shell gets no writable directory rather than a wrong one.
static FS_PKG: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

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

/// Asks the AHCI block service for sector zero, and for one past the end.
extern "C" fn ahci_asks(endpoint: u64) -> ! {
    use core::sync::atomic::Ordering;

    const BADGE: u64 = 0x00a4_0000;

    let endpoint = ipc::EndpointId::from_u32(endpoint as u32);
    // Slot 0 of *this* domain's CSpace, where the memory was installed. The
    // service cannot choose it and the kernel re-checks it.
    let landed = match ipc::call(endpoint, BADGE, bhaskix_abi::block::READ, [0, 1, 0, 0]) {
        Ok(reply) => reply.args[0],
        Err(_) => 0,
    };

    // And a sector past the end, refused *here* rather than asked of the
    // hardware -- which for this driver means refused by `ahci::plan_read`, the
    // same function that bounds every other transfer it makes.
    let past = match ipc::call(
        endpoint,
        BADGE,
        bhaskix_abi::block::READ,
        [1 << 40, 1, 0, 0],
    ) {
        Ok(reply) => reply.args[0],
        Err(_) => u64::MAX,
    };
    AHCI_REFUSED.store(past, Ordering::Release);
    AHCI_READ.store(landed, Ordering::Release);
    sched::exit()
}

/// What the AHCI service answered, or `u64::MAX` while the question is open.
static AHCI_READ: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(u64::MAX);
/// What it answered for a sector past the end.
static AHCI_REFUSED: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(u64::MAX);

/// Asks `bin/ahcid` for a sector, the same way anything asks `bin/blkd`.
///
/// **This is RFC 0046's claim, executed.** The RFC says a filesystem that had to
/// know which driver was underneath would be a filesystem with a driver inside
/// it. So this test is `block_service_self_test` with one endpoint changed and
/// one expected string changed, and nothing else -- if the two had to differ by
/// more than that, the interface would be in the wrong place.
/// How many ports the driver found a device communicating on, or `None` if it
/// has not left a report yet.
///
/// Reads the same words `report_ahci_domain` prints from -- `word(8)` for the
/// implemented-port count and the packed per-port word for `DET` -- so the two
/// cannot disagree about whether this machine has a disk.
fn ahci_disks(hhdm: u64) -> Option<usize> {
    use core::sync::atomic::Ordering;

    let raw = AHCI_MEMORY.load(Ordering::Acquire);
    if raw == 0 {
        return None;
    }
    let (frames, count) = shared::frames_of(shared::MemoryId::from_u64(raw))?;
    if count <= AHCID_REPORT_PAGE {
        return None;
    }
    let base = hhdm + frames[AHCID_REPORT_PAGE];
    // SAFETY: a frame this object owns, through the direct map; the driver
    // writes it and this only reads.
    let word = |index: usize| unsafe { core::ptr::read_volatile((base as *const u64).add(index)) };
    if word(0) != AHCID_MARKER {
        return None;
    }
    let ports = word(8) as usize;
    let mut disks = 0usize;
    for index in 0..ports.min(bhaskix_ahci::MAX_PORTS) {
        if (word(16 + index) >> 8) & 0xff == 3 {
            disks += 1;
        }
    }
    Some(disks)
}

fn ahci_service_self_test(hhdm: u64) -> bool {
    use core::sync::atomic::Ordering;

    /// What the Makefile puts in sector zero of the AHCI disk. **Not** the
    /// domain disk's string: a service answering from the wrong device fails
    /// here rather than passing plausibly.
    const EXPECTED: &[u8] = b"BHASKIX-SATA-DISK-SECTOR-0";

    let raw = AHCI_ENDPOINT.load(Ordering::Acquire);
    if raw == 0 {
        // No controller, or no window -- both reported where they happen. Not
        // a failure here.
        return true;
    }

    // **The controller can be up with nothing attached, and that is not a
    // failure.** On an SR550 the driver brings up four implemented ports, none
    // of which has a device: it says so -- *"no port has a disk, so nothing was
    // asked"* -- and this test then asked anyway, waited four seconds, and
    // reported `FAILED: 18446744073709551615 bytes`, which is `u64::MAX`
    // wearing a number's clothes.
    //
    // A gate that fails because the machine has no disk is a gate that says
    // "broken" about a true fact, and on the only physical machine this project
    // has it said it on every boot. The skip is keyed to the driver's own
    // count rather than to a timeout, so a disk that *is* present and does not
    // answer still fails here, which is the case worth keeping.
    if ahci_disks(hhdm) == Some(0) {
        println!(
            "    ahci service   not asked: the controller is up and no port has a disk, so there \
             is no sector to read"
        );
        return true;
    }

    let Ok(owner) = domain::create("ahci-reader", domain::ResourceEnvelope::new()) else {
        println!("\x1b[91m    ahci service   FAILED to create a domain to ask from\x1b[0m");
        return false;
    };
    // The object outlives the asker, because the asker does not outlive its
    // question -- the block path's own comment, and the failure it records was
    // 512 plausible bytes read out of frames already handed back.
    let Ok(keeper) = domain::create("ahci-keeper", domain::ResourceEnvelope::new()) else {
        println!("\x1b[91m    ahci service   FAILED to create the owning domain\x1b[0m");
        domain::destroy(owner);
        return false;
    };
    let Ok(object) = shared::create(keeper, bhaskix_mm::FRAME_SIZE) else {
        println!("\x1b[91m    ahci service   FAILED to create a memory object\x1b[0m");
        domain::destroy(owner);
        domain::destroy(keeper);
        return false;
    };
    let installed = shared::name(object)
        .ok()
        .and_then(|memory| domain::with(owner, |d| d.cspace.install_at(0, memory).is_ok()));
    if installed != Some(true) {
        println!("\x1b[91m    ahci service   FAILED to give the caller its memory\x1b[0m");
        domain::destroy(owner);
        domain::destroy(keeper);
        return false;
    }

    AHCI_READ.store(u64::MAX, Ordering::Release);
    AHCI_REFUSED.store(u64::MAX, Ordering::Release);
    let options = sched::SpawnOptions::new().in_domain(owner.as_u32());
    if sched::spawn_on_with(0, "ahci-ask", ahci_asks, raw, hhdm, options).is_err() {
        println!("\x1b[91m    ahci service   FAILED to spawn a caller\x1b[0m");
        domain::destroy(owner);
        domain::destroy(keeper);
        return false;
    }

    // Waited for the answer rather than for a duration.
    let mut landed = u64::MAX;
    for _ in 0..80 {
        landed = AHCI_READ.load(Ordering::Acquire);
        if landed != u64::MAX {
            break;
        }
        wait_millis(50);
    }

    let refused = AHCI_REFUSED.load(Ordering::Acquire) == 0;
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
            "    ahci service   {landed} bytes of sector 0 through the block interface, and \
             they are the SATA disk's own; a sector past the end is refused"
        );
    } else {
        println!(
            "\x1b[91m    ahci service   FAILED: {landed} bytes, contents match {matches}, \
             past the end refused {refused}\x1b[0m"
        );
    }
    ok
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

/// The marker `bin/ahcid` writes before its report. `AHCIRPT1` in ASCII.
const AHCID_MARKER: u64 = 0x4148_4349_5250_5431;

/// Which of its four pages the AHCI driver leaves its report in.
///
/// The last, for the reason `bin/netd`'s is in its last: every earlier page
/// becomes a structure the controller reads at the next step, and a report a
/// bus master can overwrite is not a report.
const AHCID_REPORT_PAGE: usize = 3;

/// Whether `bin/ahcid` has written its report yet.
///
/// The marker only, so waiting for it costs nothing and cannot be confused with
/// reading it: a page of zeroes has no marker, and a driver that never ran
/// leaves the page as it found it.
fn ahci_domain_reported(hhdm: u64) -> bool {
    use core::sync::atomic::Ordering;

    let raw = AHCI_MEMORY.load(Ordering::Acquire);
    if raw == u64::MAX {
        return true;
    }
    let Some((frames, count)) = shared::frames_of(shared::MemoryId::from_u64(raw)) else {
        return true;
    };
    if count <= AHCID_REPORT_PAGE {
        return true;
    }
    // SAFETY: a frame this object owns, through the direct map.
    let marker =
        unsafe { core::ptr::read_volatile((hhdm + frames[AHCID_REPORT_PAGE]) as *const u64) };
    marker == AHCID_MARKER
}

/// Prints what `bin/ahcid` found, and returns whether it found anything.
///
/// **This is where RFC 0046's recalled register offsets meet a machine.** The
/// raw `CAP`, `PI` and `VS` are printed rather than only what was concluded
/// from them, because the numbers are what a reader checks: a wrong `PI` offset
/// shows as an implausible port bitmap, and a wrong `CAP` offset as a slot
/// count outside 1..=32.
fn report_ahci_domain(hhdm: u64) -> bool {
    use core::sync::atomic::Ordering;

    let raw = AHCI_MEMORY.load(Ordering::Acquire);
    if raw == u64::MAX {
        // No controller was delegated. Already said, once, where it was found.
        return true;
    }
    let Some((frames, count)) = shared::frames_of(shared::MemoryId::from_u64(raw)) else {
        println!("\x1b[91m    ahci domain    the report memory is gone\x1b[0m");
        return false;
    };
    if count <= AHCID_REPORT_PAGE {
        println!("\x1b[91m    ahci domain    the report memory is too small\x1b[0m");
        return false;
    }
    let base = hhdm + frames[AHCID_REPORT_PAGE];
    // SAFETY: frames this object owns, through the direct map. The driver
    // writes the marker last with a release fence, so a marker that is there
    // means everything under it is too.
    let word = |index: usize| unsafe { core::ptr::read_volatile((base as *const u64).add(index)) };

    if word(0) != AHCID_MARKER {
        // **Which stage it stopped at, because "no report" is a dead end.** The
        // driver writes this as it goes rather than at the end, so a hang and a
        // fault and a program that never started are three different answers
        // instead of one. Step 4 spent two boots not knowing which it had.
        let where_it_stopped = match word(12) {
            // One answer and not three, because recording a stage means
            // writing to this memory: nothing before the attach can be
            // recorded. The first attempt put a stage above the attach and
            // faulted on it immediately.
            0 => "it never ran, could not map its registers, or could not reach its own memory",
            1 => "it mapped everything and the window would not answer",
            2 => "it was in the bring-up",
            3 => "it finished the bring-up and stopped before starting a port",
            4 => "it started a port and stopped before building a command",
            5 => "it built a command and stopped before issuing it",
            6 => "it issued a command and never came back",
            7 => "the command came back and it stopped before reporting",
            _ => "somewhere this kernel has no name for",
        };
        println!("\x1b[91m    ahci domain    the driver left no report: {where_it_stopped}\x1b[0m");
        return false;
    }

    let translated = word(9) == 1;
    if word(1) != 1 {
        let why = match (word(2), word(3)) {
            (1, 0) => "GHC.HR did not clear: the controller never finished its reset",
            (1, 1) => "BOHC.BOS did not clear: the firmware never let go",
            (1, 2) => "PxCMD.CR did not clear: a port's command engine would not stop",
            (1, 3) => "PxCMD.FR did not clear: a port's fis receive would not stop",
            (1, _) => "a register did not settle",
            (2, _) => "the controller implements no ports at all",
            (3, _) => "a structure was offered at an address the controller cannot be given",
            (4, _) => "a structure above 4 GiB on a controller that cannot address one",
            _ => "the driver refused a port it was not given",
        };
        println!("\x1b[91m    ahci domain    NOT up: {why}\x1b[0m");
        return false;
    }

    let implemented = word(2) as u32;
    let version = word(4) as u32;
    println!(
        "    ahci           up: {} port{} implemented ({:#010x}), {} slot{} each, version \
         {}.{}{}, {}-bit addressing, ncq {}{}",
        implemented.count_ones(),
        if implemented.count_ones() == 1 {
            ""
        } else {
            "s"
        },
        implemented,
        word(3),
        if word(3) == 1 { "" } else { "s" },
        version >> 16,
        (version >> 8) & 0xff,
        if version & 0xff == 0 {
            ""
        } else {
            " (revision set)"
        },
        if word(5) == 1 { 64 } else { 32 },
        if word(6) == 1 { "yes" } else { "no" },
        if word(7) == 1 {
            ", taken from the firmware"
        } else {
            ""
        }
    );

    // One line per port, and the three `DET` values are not flattened into two:
    // an empty port and a port whose link will not come up are different things
    // to whoever is standing at the machine.
    println!(
        "    ahci dma       the driver's memory is at {:#x} as the controller sees it",
        word(10)
    );
    let ports = word(8) as usize;
    let mut disks = 0usize;
    for index in 0..ports.min(bhaskix_ahci::MAX_PORTS) {
        let packed = word(16 + index);
        let port = packed & 0xff;
        let det = (packed >> 8) & 0xff;
        let ipm = (packed >> 16) & 0xff;
        let signature = (packed >> 32) as u32;
        let what = match det {
            0 => "nothing attached",
            1 => "a device attached whose link will not come up",
            3 => "a device attached and communicating",
            _ => "an unrecognised detection state",
        };
        if det == 3 {
            disks += 1;
        }
        // **The signature is not meaningful yet, and the report says so rather
        // than printing a number that looks like an answer.** `PxSIG` holds
        // what the device sent in its first D2H FIS, and no port has been
        // started -- step 4 -- so every one of them reads all-ones. Which is
        // also exactly what a read past the end of the mapping answers, so a
        // bare number here would be two different facts printed identically.
        let latched = if signature == u32::MAX {
            "signature not latched (no port is started until step 4)"
        } else {
            "signature"
        };
        if signature == u32::MAX {
            println!("    ahci port {port:<2}   det {det} ipm {ipm}, {latched} -- {what}");
        } else {
            println!(
                "    ahci port {port:<2}   det {det} ipm {ipm}, {latched} {signature:#010x} -- \
                 {what}"
            );
        }
    }
    if !translated {
        println!(
            "\x1b[93m    ahci domain    brought up with no dma window; nothing may be issued \
             to it, which is RFC 0012's rule and not a shortcoming\x1b[0m"
        );
        return true;
    }

    // RFC 0046 step 4: what the disk said about itself, which is the first
    // thing this system has ever heard from a SATA device.
    // What the started port's device turned out to be. Printed whether or not
    // a command followed, because "there is a device and it is not a disk" is a
    // different fact from "nothing answered" and both look like silence.
    if word(13) != u64::MAX {
        let sig = word(11) as u32;
        let what = match bhaskix_ahci::device_kind(sig) {
            bhaskix_ahci::DeviceKind::Disk => "a SATA disk",
            bhaskix_ahci::DeviceKind::Packet => {
                "an ATAPI device -- a CD or DVD, which answers IDENTIFY PACKET DEVICE and \
                 aborts IDENTIFY DEVICE by specification"
            }
            bhaskix_ahci::DeviceKind::PortMultiplier => "a port multiplier",
            bhaskix_ahci::DeviceKind::Enclosure => "an enclosure management bridge",
            bhaskix_ahci::DeviceKind::Unknown(_) => "a device this driver has no name for",
        };
        println!(
            "    ahci port {}    started; signature {sig:#010x} -- {what}",
            word(13)
        );
    }

    match word(48) {
        0 if disks == 0 => println!(
            "    ahci           no port has a disk, so nothing was asked; the controller is up \
             and idle"
        ),
        0 if word(13) != u64::MAX
            && bhaskix_ahci::device_kind(word(11) as u32) != bhaskix_ahci::DeviceKind::Disk =>
        {
            println!(
                "    ahci identify  not asked: the device on that port is not a disk, so \
                 IDENTIFY DEVICE does not apply to it"
            );
        }
        0 => println!(
            "\x1b[91m    ahci identify  FAILED: {disks} port(s) hold a device and none was \
             asked\x1b[0m"
        ),
        1 => {
            // **The sector count is a number the device chose**, and it is
            // printed beside the size it was multiplied by rather than only as
            // a capacity -- so a disk answering something absurd is visible as
            // the two numbers it answered rather than as one product.
            let sectors = word(49);
            let bytes = word(50);
            // RFC 0046 step 5: what sector zero actually holds.
            //
            // **The bytes, printed as bytes.** A gate that checked only "a read
            // returned" would pass a driver that returned zeroes, or the other
            // disk's sector -- which is why the image builder writes a distinct
            // string into this disk and not the domain disk, and why this line
            // prints what came back rather than how many bytes did.
            let read_state = word(52);
            if read_state == 1 {
                let mut text = [0u8; 32];
                for word_index in 0..4 {
                    let bytes = word(56 + word_index).to_le_bytes();
                    text[word_index * 8..word_index * 8 + 8].copy_from_slice(&bytes);
                }
                // Printable characters only. A sector of arbitrary bytes is not
                // a string, and a console that took a stray escape from a disk
                // would be a console a disk can drive.
                let mut shown = [b'.'; 32];
                for (at, byte) in text.iter().enumerate() {
                    shown[at] = if byte.is_ascii_graphic() || *byte == b' ' {
                        *byte
                    } else {
                        b'.'
                    };
                }
                println!(
                    "    ahci read      sector 0 begins \"{}\"",
                    core::str::from_utf8(&shown).unwrap_or("??")
                );
            }

            // KiB rather than MiB. The first disk this ever ran against is
            // 256 KiB, which printed as "0 MiB" -- a true number that reads as
            // a failure, and the last thing a first result should do.
            println!(
                "    ahci identify  the disk answered: {sectors} sectors of {bytes} bytes \
                 ({} KiB), {}-bit addressing",
                sectors.saturating_mul(bytes) / 1024,
                if word(51) == 1 { 48 } else { 28 }
            );
            // RFC 0046 step 6: a write, proved by reading it back.
            //
            // **Not sector zero**, whose bytes the read gate checks -- the last
            // sector, and the pattern is derived from the sector number, so a
            // driver that wrote sector N and read sector M cannot agree with
            // itself and pass.
            match word(54) {
                0 => {}
                1 => println!(
                    "    ahci write     sector {} written and read back byte-for-byte",
                    word(55)
                ),
                2 => println!(
                    "\x1b[91m    ahci write     FAILED: sector {} read back different from what \
                     was written\x1b[0m",
                    word(55)
                ),
                _ => println!(
                    "\x1b[91m    ahci write     FAILED: the write or its read-back was \
                     refused\x1b[0m"
                ),
            }

            match read_state {
                1 => {}
                0 => println!(
                    "\x1b[91m    ahci read      FAILED: sector 0 was never asked for\x1b[0m"
                ),
                3 => println!(
                    "\x1b[93m    ahci read      not asked: the disk's own answer would not \
                     permit a read of its first sector\x1b[0m"
                ),
                _ => {
                    let why = word(53);
                    if why & 0x100 != 0 {
                        println!(
                            "\x1b[91m    ahci read      FAILED: the device refused it, error \
                             {:#04x}\x1b[0m",
                            why & 0xff
                        );
                    } else if why & 0x200 != 0 {
                        println!(
                            "\x1b[91m    ahci read      FAILED: a host bus error, {:#x} -- on a \
                             translated controller this is what an unmapped address looks \
                             like\x1b[0m",
                            why & 0xff
                        );
                    } else if why == 1 {
                        println!(
                            "\x1b[91m    ahci read      FAILED: the read never completed\x1b[0m"
                        );
                    } else {
                        println!(
                            "\x1b[91m    ahci read      FAILED: the driver refused a slot it was \
                             not given\x1b[0m"
                        );
                    }
                }
            }
        }
        _ => {
            let why = match (word(49), word(50)) {
                (1, _) => "the command never completed",
                (2, 0) => "the controller finished the slot while the device was still busy",
                (2, error) => {
                    // ATA's error register says *what*, and throwing that away
                    // would discard the only diagnosis the disk offered.
                    println!(
                        "\x1b[91m    ahci identify  FAILED: the device refused it, error \
                         {error:#04x}\x1b[0m"
                    );
                    return false;
                }
                (3, bits) => {
                    // A bus error on a *translated* device is what a missing
                    // mapping looks like. Named apart from a refusal so nobody
                    // is sent to the disk for a window's problem.
                    println!(
                        "\x1b[91m    ahci identify  FAILED: a host bus error, {bits:#010x} -- on \
                         a translated controller this is what an unmapped address looks \
                         like\x1b[0m"
                    );
                    return false;
                }
                _ => "the driver refused a slot or a port it was not given",
            };
            println!("\x1b[91m    ahci identify  FAILED: {why}\x1b[0m");
            return false;
        }
    }
    true
}

/// The marker `bin/netd` writes before its report.
const NETD_MARKER: u64 = 0x3154_5052_4454_454e;

/// Where in the rings the network driver leaves its report.
///
/// The last of the eight pages. Every earlier one is a ring or a buffer the
/// *device* reads and writes, and a report living in any of them would be a
/// report the device could overwrite -- which is the same reason the block
/// driver's report sits in its last page.
const NETD_REPORT_PAGE: usize = 7;

/// The MAC `bin/netd` reported, if it has reported one.
///
/// Read separately from [`report_net_domain`] because the *configuration* has
/// to reach `ipd` as soon as the driver knows it, and the report is printed
/// much later — after a wait long enough for a network to answer.
fn net_domain_mac(hhdm: u64) -> Option<u64> {
    use core::sync::atomic::Ordering;

    let raw = NET_RINGS.load(Ordering::Acquire);
    if raw == u64::MAX {
        return None;
    }
    let (frames, count) = shared::frames_of(shared::MemoryId::from_u64(raw))?;
    if count <= NETD_REPORT_PAGE {
        return None;
    }
    // SAFETY: a frame this object owns, through the direct map: the marker and
    // then the MAC, the first two words the driver writes there.
    let (marker, mac) = unsafe {
        (
            core::ptr::read_volatile((hhdm + frames[NETD_REPORT_PAGE]) as *const u64),
            core::ptr::read_volatile((hhdm + frames[NETD_REPORT_PAGE] + 8) as *const u64),
        )
    };
    // A zero address is not an address. The driver writes its report with the
    // marker set and the MAC still zero when it had no window to read the
    // device through, so believing the marker alone publishes an interface that
    // does not exist -- and says so on the console every boot without an IOMMU.
    (marker == NETD_MARKER && mac != 0).then_some(mac)
}

/// Whether `bin/netd` has written its report yet.
fn net_domain_reported(hhdm: u64) -> bool {
    use core::sync::atomic::Ordering;

    let raw = NET_RINGS.load(Ordering::Acquire);
    if raw == u64::MAX {
        return true;
    }
    let Some((frames, count)) = shared::frames_of(shared::MemoryId::from_u64(raw)) else {
        return true;
    };
    if count <= NETD_REPORT_PAGE {
        return true;
    }
    // SAFETY: a frame this object owns, through the direct map.
    let marker =
        unsafe { core::ptr::read_volatile((hhdm + frames[NETD_REPORT_PAGE]) as *const u64) };
    marker == NETD_MARKER
}

/// RFC 0018 step 7: times the echo burst and prices the domain boundary.
///
/// `bin/ipd` has no clock. It counts phases and replies into its report page,
/// and this watches the phase number move — so the elapsed time of a phase is
/// measured by the kernel while the work is done entirely in ring 3.
///
/// # What the numbers mean, and what they do not
///
/// The serialised phases have one request in flight at a time, so their elapsed
/// time *is* round trips end to end. The pipelined phases do not wait, and are
/// bounded in **both** builds by this driver allowing one transmit outstanding
/// at a time — that is a property of `bin/netd`, not of the boundary.
///
/// These are means over a phase, not minima. `report_service_cost` explains why
/// a mean is the weaker statistic here: one preempted round trip in sixty-four
/// moves it. A per-packet minimum would need a clock in ring 3, which no
/// program has.
fn time_the_burst(hhdm: u64) {
    use core::sync::atomic::Ordering;

    // `bin/ipd` runs the burst and reports it. RFC 0018 step 7's folded build
    // read these same four numbers off the *driver's* page instead, because it
    // had no `bin/ipd`; that build is measured and gone, and what it found is
    // in TRACKER. The indirection it needed is gone with it.
    let (raw, marker, base, page) = (
        NET_RING_REPORT.load(Ordering::Acquire),
        IPD_MARKER,
        14usize,
        0,
    );
    if raw == u64::MAX {
        return;
    }
    let Some((pages, count)) = shared::frames_of(shared::MemoryId::from_u64(raw)) else {
        return;
    };
    if count <= page {
        return;
    }
    let Some(hertz) = bhaskix_arch::tsc::hertz() else {
        println!("    burst          no calibrated timer; nothing measured");
        return;
    };

    let word = |index: usize| -> u64 {
        // SAFETY: a frame this object owns, through the direct map, read as the
        // little-endian words the service wrote there.
        let bytes = unsafe { core::slice::from_raw_parts((hhdm + pages[page]) as *const u8, 176) };
        let mut buffer = [0u8; 8];
        buffer.copy_from_slice(&bytes[index * 8..index * 8 + 8]);
        u64::from_le_bytes(buffer)
    };

    if word(0) != marker {
        return;
    }

    const NAMES: [&str; 4] = [
        "serialised   16 B",
        "serialised 1400 B",
        "pipelined    16 B",
        "pipelined  1400 B",
    ];

    let mut done = 0usize;
    // **The clock starts when the burst does, not when this function does.**
    //
    // It started here once, and the first phase came back at 0.65 microseconds
    // a round trip — a number that is not physically possible through an
    // emulated NIC and was believed for exactly as long as it took to read it.
    // What had happened is that the phase finished before anything looked, so
    // its elapsed time was measured from the wrong end. The burst does not
    // begin until `bin/ipd`'s first demonstration ping is answered, which takes
    // an ARP exchange and a round trip of its own.
    //
    // So this waits for the first request of phase zero to go out, and stamps
    // then.
    //
    // # Two bounds, not one, and why that distinction cost a boot
    //
    // **Waiting for the burst to *begin* is a different question from waiting
    // for four phases to *finish*, and giving them one shared budget made this
    // instrument able to stop the machine it was measuring.**
    //
    // On a lane with no DMA window — `native`, and every lane where the IOMMU
    // contains nothing for the NIC — `bin/netd` maps no window, reports zeroes
    // and exits, exactly as designed. `bin/ipd` then blocks on frames that will
    // never arrive. Whether this function noticed was a race: it returns at once
    // if `bin/ipd` has not yet written its marker, and enters the wait if it
    // has. On 2026-08-23 the marker won that race on the `native` lane, nothing
    // was ever sent, and the loop below spent its whole 40-second budget one
    // millisecond at a time — inside a bring-up allowed 45 seconds in total. The
    // boot was stopped by its own measurement, and the four other lanes in the
    // same suite passed only because the race went the other way.
    //
    // A burst that has sent nothing after a few seconds is not slow, it is
    // absent: the trigger is an ARP exchange and one round trip, which is
    // milliseconds under emulation. So the start gets seconds and says so when
    // it expires; the phases keep the rest.
    const START_MS: usize = 5_000;
    const RUN_MS: usize = 35_000;
    let mut stamp = bhaskix_arch::tsc::read();
    let mut started = false;
    for _ in 0..START_MS {
        if word(base + 3) >= 1 || word(base) >= 1 {
            started = true;
            stamp = bhaskix_arch::tsc::read();
            break;
        }
        wait_millis(1);
    }
    if !started {
        println!(
            "\x1b[93m    burst          never started: nothing sent in {} s, so there is no \
             device behind it and nothing to time\x1b[0m",
            START_MS / 1000
        );
        return;
    }
    // Bounded: a burst that never finishes must not hold the boot. Whatever
    // completed is reported and the rest is said to be missing rather than
    // quietly left out.
    for _ in 0..RUN_MS {
        let phase = word(base) as usize;
        while done < phase.min(4) {
            let now = bhaskix_arch::tsc::read();
            let elapsed = now.saturating_sub(stamp);
            stamp = now;
            let replies = word(base + 2);
            let micros = elapsed.saturating_mul(1_000_000) / hertz.max(1);
            let each = micros.checked_div(replies).unwrap_or(0);
            let rate = replies
                .saturating_mul(1_000_000)
                .checked_div(micros)
                .unwrap_or(0);
            println!(
                "    burst          {}: {replies} replies in {}.{:03} ms, {each} us each, {rate}/s",
                NAMES[done],
                micros / 1000,
                micros % 1000
            );
            done += 1;
        }
        if done >= 4 {
            break;
        }
        // **One millisecond, not five.** A phase lasts tens of milliseconds, so
        // a five-millisecond sampling interval put a large fraction of the
        // answer into the quantisation: phases came back in an order that made
        // no sense, with 1400-byte packets faster than 16-byte ones. The burst
        // is longer for the same reason. This is still a coarse instrument and
        // the spread across runs is reported rather than hidden.
        wait_millis(1);
    }
    if done < 4 {
        println!(
            "\x1b[93m    burst          only {done} of 4 phases finished; the last had sent {} \
             and heard {} back\x1b[0m",
            word(base + 3),
            word(base + 1)
        );
    }
}

/// Reads the driver's counters **again, after the DHCP exchange**.
///
/// [`report_net_domain`] runs before `bin/dhcp` is even started, so every
/// number it prints predates the exchange. Reading those numbers and concluding
/// anything about a frame that had not been sent yet is measuring the reader's
/// timing rather than the thing measured — the same mistake this file already
/// records twice, made a third time and caught by the counter not moving.
///
/// This prints what the driver saw by the end, which is the only version of
/// those numbers that can say whether the offer was ever delivered.
fn report_net_after_exchange(hhdm: u64) {
    use core::sync::atomic::Ordering;

    let raw = NET_RINGS.load(Ordering::Acquire);
    if raw == u64::MAX {
        return;
    }
    let Some((frames, count)) = shared::frames_of(shared::MemoryId::from_u64(raw)) else {
        return;
    };
    if count <= NETD_REPORT_PAGE {
        return;
    }
    let mut words = [0u64; 16];
    // SAFETY: a frame this object owns, through the direct map, read as the
    // sixteen little-endian words the driver wrote there.
    let raw =
        unsafe { core::slice::from_raw_parts((hhdm + frames[NETD_REPORT_PAGE]) as *const u8, 128) };
    for (index, word) in words.iter_mut().enumerate() {
        let mut buffer = [0u8; 8];
        buffer.copy_from_slice(&raw[index * 8..index * 8 + 8]);
        *word = u64::from_le_bytes(buffer);
    }
    if words[0] != NETD_MARKER {
        return;
    }
    println!(
        "    net after      {} completions seen, {} handed across, {} sent back; widest frame \
         the device wrote {} bytes, {} buffers left with it",
        words[8], words[9], words[10], words[13], words[14]
    );

    let raw = NET_RING_REPORT.load(Ordering::Acquire);
    if raw == u64::MAX {
        return;
    }
    let Some((pages, count)) = shared::frames_of(shared::MemoryId::from_u64(raw)) else {
        return;
    };
    if count == 0 {
        return;
    }
    let mut ipd = [0u64; 21];
    // SAFETY: a frame this object owns, through the direct map, read as the ten
    // little-endian words the service wrote there.
    let bytes = unsafe { core::slice::from_raw_parts((hhdm + pages[0]) as *const u8, 168) };
    for (index, word) in ipd.iter_mut().enumerate() {
        let mut buffer = [0u8; 8];
        buffer.copy_from_slice(&bytes[index * 8..index * 8 + 8]);
        *word = u64::from_le_bytes(buffer);
    }
    if ipd[0] != IPD_MARKER {
        return;
    }
    println!(
        "    ipd state      {:#x} (send/configured/tcp-rings)",
        ipd[7]
    );
    println!(
        "    ipd after      {} frames taken, {} refused, {} datagrams delivered to a socket; \
         last refusal reason {}, on a frame of {} bytes with ethertype {:#06x}; ring head {} tail {}; \
         {} empty looks at the ring, longest run {}; woken by a frame {} times",
        ipd[1],
        ipd[4],
        ipd[9],
        ipd[10] & 0xffff,
        ipd[10] >> 32,
        (ipd[10] >> 16) & 0xffff,
        ipd[11],
        ipd[12],
        ipd[18],
        ipd[19],
        ipd[20]
    );

    // The demonstration runs on its own clock — a handshake, an echo and a
    // close against the emulator's peer — and reading its page at whatever
    // instant the boot happens to reach this line reported whichever moment
    // that was: `pending, 1 out` on a boot that would have echoed fine a
    // second later. Waited for, bounded, exactly as the driver's report is:
    // the loop ends the moment the outcome is terminal, so a working boot
    // pays a second or two and only a broken one pays the bound — five
    // seconds, sized so that a boot already stretched by suite load does not
    // cross the harness's own timeout on the days the wake loss stalls the
    // demonstration.
    for _ in 0..50u32 {
        let raw = TCP_REPORT.load(core::sync::atomic::Ordering::Acquire);
        if raw == u64::MAX {
            break;
        }
        let Some((pages, count)) = shared::frames_of(shared::MemoryId::from_u64(raw)) else {
            break;
        };
        if count == 0 {
            break;
        }
        // SAFETY: a frame this object owns, through the direct map.
        let (marker, outcome) = unsafe {
            (
                core::ptr::read_volatile((hhdm + pages[0]) as *const u64),
                core::ptr::read_volatile((hhdm + pages[0] + 16) as *const u64),
            )
        };
        // Terminal for this wait: anything but "pending". Established counts,
        // because the stream that used to complete inside this service now
        // completes in the caller — whose own bounded wait follows this one.
        if marker == TCPD_MARKER && outcome != 0 {
            break;
        }
        wait_millis(100);
    }
    report_tcp_domain(hhdm);

    // The demonstration client's exchange. Fifteen seconds rather than the
    // five every other wait gets, because step 6's bulk measurement is real
    // traffic on real time — thirty-two KiB echoed at one window in flight —
    // and a wait that gives up mid-measurement reports an instrument as a
    // failure.
    for _ in 0..150u32 {
        let raw = TCPC_REPORT.load(core::sync::atomic::Ordering::Acquire);
        if raw == u64::MAX {
            break;
        }
        let Some((pages, count)) = shared::frames_of(shared::MemoryId::from_u64(raw)) else {
            break;
        };
        if count == 0 {
            break;
        }
        // SAFETY: a frame this object owns, through the direct map.
        let (marker, outcome) = unsafe {
            (
                core::ptr::read_volatile((hhdm + pages[0]) as *const u64),
                core::ptr::read_volatile((hhdm + pages[0] + 16) as *const u64),
            )
        };
        // Six — outbound echoed — is on the way to nine, and nine is on
        // the way to twelve since RFC 0029 step 5 taught the same program
        // to echo itself through the v6 loopback. Neither is an end on a
        // networked machine.
        if marker == TCPC_MARKER && outcome >= 3 && outcome != 6 && outcome != 9 {
            break;
        }
        wait_millis(100);
    }
    report_tcp_client(hhdm);

    // RFC 0018 step 7: what the boundary cost, counted rather than argued.
    //
    // The RFC claims the split costs "two copies and two domain crossings per
    // packet that a monolithic stack does not pay". Every copy counted here is
    // a ring copy, and every ring copy exists only because the driver and the
    // protocol code are in different domains — so this total divided by the
    // packets that crossed *is* the claim, checked.
    let packets = words[9].saturating_add(words[10]);
    let copies = words[15].saturating_add(ipd[13]);
    if let Some(whole) = copies.checked_div(packets)
        && let Some(hundredths) = copies.saturating_mul(100).checked_div(packets)
    {
        println!(
            "    boundary       {copies} ring copies over {packets} packets = {whole}.{:02} per \
             packet ({} by the driver, {} by the service)",
            hundredths % 100,
            words[15],
            ipd[13]
        );
    }
}

/// What `bin/tcpd` reported, in one line the boot test can hold.
///
/// The state word is bits — attached, keyed, configured, serving — and the
/// outcome is the demonstration connection's end. "keyed" is RFC 0021's
/// deliverable consumed: the service drew a 128-bit secret from the hardware,
/// and on a machine that could not supply one the outcome reads 4 and nothing
/// was attempted, which is the refusal working.
/// Creates the TCP demonstration client's domain: two stream rings **it
/// owns**, a badged capability to the TCP service, a report page — and
/// nothing wired to the service by the kernel at all.
///
/// RFC 0022 step 4. The absence is the design: every earlier ring in this
/// file is installed into both ends by boot code, and this pair is installed
/// into one. The other end receives them the way every future program's
/// service will — handed across `CONNECT`, moved by the kernel at a
/// rendezvous, landing where the service declared. Ownership matters as much
/// as transport: the rings belong to the client's domain, so RFC 0022
/// step 3 makes the service's copies die with the client.
fn start_tcp_client_domain(
    cpu: u32,
    hhdm_base: u64,
    keeper: domain::DomainId,
) -> Result<(), &'static str> {
    use core::sync::atomic::Ordering;

    let raw = TCP_ENDPOINT.load(Ordering::Acquire);
    if raw == u64::MAX {
        return Err("no tcp endpoint to hand the client");
    }

    let realm = domain::create("tcpc", domain::ResourceEnvelope::new())
        .map_err(|_| "the tcp client domain would not be created")?;

    // The client's capability to the service: badged, so the service can key
    // the handover by who is calling, and carrying no GRANT — holding a
    // service is not permission to pass it on.
    let root = cap::with_arena(|arena| {
        arena
            .insert_root(
                cap::ObjectRef::new(cap::ObjectKind::Endpoint, raw),
                cap::Rights::ALL,
                0,
            )
            .ok()
    })
    .ok_or("the tcp client endpoint capability would not be created")?;
    let client_cap = cap::with_arena(|arena| {
        arena
            .derive(
                root,
                cap::Rights::READ.union(cap::Rights::WRITE),
                TCPC_BADGE,
            )
            .ok()
    })
    .ok_or("the tcp client endpoint capability would not derive")?;
    if domain::with(realm, |owner| {
        owner.cspace.install_at(0, client_cap).is_ok()
    }) != Some(true)
    {
        return Err("the tcp client endpoint capability would not install");
    }

    // The report page, owned by the keeper like every report: it must
    // outlive the client to be read after it exits.
    let report = shared::create(keeper, bhaskix_mm::FRAME_SIZE)
        .map_err(|_| "the tcp client report page would not be created")?;
    let named = shared::name(report).map_err(|_| "the tcp client report would not be named")?;
    if domain::with(realm, |owner| owner.cspace.install_at(1, named).is_ok()) != Some(true) {
        return Err("the tcp client report would not install");
    }

    // The rings, owned by the *client's* domain. `Rights::ALL` from `name`
    // is what a creator holds over its own object — including the GRANT and
    // DERIVE the gift needs.
    for (slot, label) in [
        (2usize, "send"),
        (3usize, "receive"),
        (5usize, "listener send"),
        (6usize, "listener receive"),
    ] {
        let ring = shared::create(realm, TCPC_RING_BYTES)
            .map_err(|_| "a tcp client ring would not be created")?;
        let ring_cap = shared::name(ring).map_err(|_| "a tcp client ring would not be named")?;
        let _ = label;
        if domain::with(realm, |owner| {
            owner.cspace.install_at(slot, ring_cap).is_ok()
        }) != Some(true)
        {
            return Err("a tcp client ring would not install");
        }
    }

    // The wakes, RFC 0023: one notification per handover, owned by the
    // client's domain like its rings — minted here because no program can
    // create one yet, gifted by the client because a connection costs the
    // objects of whoever opened it.
    // Badged, and the badge is load-bearing: a signal ORs the signaller's
    // badge into the word, and a zero badge ORs nothing — a wake rung with
    // one is a wake nobody feels. The client's copy carries the badge, so
    // its gifted derivations must carry the same one (badges are one-way),
    // and the deadline it arms expires through the same nonzero word.
    for (slot, badge) in [(9usize, 1u64), (10usize, 2u64)] {
        let wake = crate::notify::create().map_err(|_| "a tcp client wake would not be created")?;
        let root = crate::notify::name(wake).map_err(|_| "a tcp client wake would not be named")?;
        let wake_cap = cap::with_arena(|arena| arena.derive(root, cap::Rights::ALL, badge).ok())
            .ok_or("a tcp client wake would not derive")?;
        if domain::with(realm, |owner| {
            owner.cspace.install_at(slot, wake_cap).is_ok()
        }) != Some(true)
        {
            return Err("a tcp client wake would not install");
        }
    }

    let options = sched::SpawnOptions::new()
        .pinned()
        .in_domain(realm.as_u32());
    sched::spawn_on_with(
        cpu,
        "tcpc",
        tcpc_domain_entry,
        hhdm_base,
        hhdm_base,
        options,
    )
    .map_err(|_| "the tcp client would not spawn")?;

    TCPC_REPORT.store(report.as_u64(), Ordering::Release);
    // **The uptime, because `boot cost` is printed after this act and cannot
    // date it.**
    //
    // The host-side inbound connection lands on one of slirp's SYN-retransmit
    // rungs, and the tracker's measurement puts the shipped configuration about
    // a tenth of a second inside one. Whether a boot misses the rung is
    // therefore a question about *when this line happens*, and until 2026-08-25
    // nothing in the report could answer it: the only uptime figure is `boot
    // cost`, printed after the act and so containing it. A sweep of 14 boots
    // found the one failing run reaching `boot cost` 3.9 s later than any
    // passing run and could not say whether that was the cause or the wait it
    // caused -- the failing run did *less* work (63 segments against 155) in
    // more time, which is what an effect looks like.
    match crate::time::now_nanos() {
        Some(nanos) => println!(
            "    tcp client     bin/tcpc started at {}.{:03} ms: four rings and two wakes its domain owns, \
             a badged capability to the service, and nothing wired between them by the kernel",
            nanos / 1_000_000,
            nanos % 1_000_000 / 1_000,
        ),
        None => println!(
            "    tcp client     bin/tcpc started (no clock yet): four rings and two wakes its domain owns, \
             a badged capability to the service, and nothing wired between them by the kernel"
        ),
    }
    Ok(())
}

/// Loads `bin/tcpc` into a fresh address space and enters it.
///
/// The same steps `tcp_domain_entry` takes; no entry argument, because this
/// program arms no deadlines and owns no clock.
extern "C" fn tcpc_domain_entry(hhdm_base: u64) -> ! {
    use bhaskix_boot::VirtAddr;
    use bhaskix_mm::{Protection, VirtRange};
    use vm::AddressSpace;

    let stop = |why: &str| -> ! {
        println!("\x1b[91m    tcp client     FAILED: {why}\x1b[0m");
        sched::exit()
    };

    let Ok(file) = vfs::open(TCPC_PROGRAM) else {
        stop("bin/tcpc is not in the filesystem")
    };
    let Ok(image) = elf::parse(file.bytes()) else {
        stop("bin/tcpc is not an ELF this kernel will load")
    };
    let Ok(mut space) = AddressSpace::new(hhdm_base) else {
        stop("the address space would not be created")
    };
    let Some(stack) = VirtRange::from_pages(VirtAddr(TCPC_STACK), TCPC_STACK_PAGES) else {
        stop("the stack range is not a range")
    };
    if space.map_anonymous(stack, Protection::ReadWrite).is_err() {
        stop("the stack would not map")
    }
    let Ok(entry) = elf::load_into(&image, file.bytes(), &mut space, hhdm_base) else {
        stop("bin/tcpc would not load")
    };

    // SAFETY: the higher half is copied from the running page table, so
    // everything currently executing stays addressable.
    unsafe { vm::install(space) };

    let rsp = TCPC_STACK + TCPC_STACK_PAGES * bhaskix_mm::FRAME_SIZE;
    let hertz = bhaskix_arch::tsc::hertz().unwrap_or(0);
    // SAFETY: `entry` is inside a user-executable segment of the space just
    // installed, `rsp` is one past user-writable memory in the same space, and
    // `RSP0` was set before this thread was spawned.
    unsafe { enter_user("tcp client", entry, rsp, [hertz, 0]) }
}

/// One CPU's half of RFC 0026's round-trip self-test: empty the local ring,
/// emit the marked probes, say so, leave.
extern "C" fn traced_probe_entry(count: u64) -> ! {
    telemetry::probe_here(count);
    TRACED_PROBES_DONE.fetch_add(1, core::sync::atomic::Ordering::Release);
    sched::exit()
}

/// RFC 0026 steps 3 and 4: the grant, and the reader it is granted to.
///
/// Creates the `traced` domain; installs its report page, the tails object
/// **read-write**, and every CPU's ring **read-only** — derivation is what
/// narrows them, so a writable mapping of a ring is refused by rights, not
/// by convention. Then every CPU emits [`TRACED_PROBES_EACH`] marked probes
/// into its own freshly emptied ring, and `bin/traced` is spawned to read
/// the marked set back through pages it mapped itself.
fn start_traced(hhdm_base: u64) -> Result<(), &'static str> {
    if telemetry::tails_identity().is_none() {
        return Err("the telemetry plane never initialised");
    }
    let realm = domain::create("traced", domain::ResourceEnvelope::new())
        .map_err(|_| "the traced domain would not be created")?;

    // The report page belongs to a keeper, not to `traced`: the reader does
    // its one pass and exits, its domain ends with its last thread, and a
    // realm-owned page would be reclaimed in that teardown — the kernel
    // read "report page gone" on the first boot that tried it. The keeper
    // runs nothing, so nothing ends it.
    let keeper = domain::create("traced-keeper", domain::ResourceEnvelope::new())
        .map_err(|_| "the traced keeper would not be created")?;
    let report = shared::create(keeper, bhaskix_mm::FRAME_SIZE)
        .map_err(|_| "the traced report page would not be created")?;
    let named = shared::name(report).map_err(|_| "the traced report would not be named")?;
    if domain::with(realm, |owner| owner.cspace.install_at(1, named).is_ok()) != Some(true) {
        return Err("the traced report would not install");
    }

    let tails = telemetry::tails_identity().ok_or("the tails object is gone")?;
    let tails_root = shared::name(shared::MemoryId::from_u64(tails))
        .map_err(|_| "the tails object would not be named")?;
    let tails_cap = cap::with_arena(|arena| {
        arena
            .derive(tails_root, cap::Rights::READ.union(cap::Rights::WRITE), 0)
            .ok()
    })
    .ok_or("the tails capability would not derive")?;
    if domain::with(realm, |owner| owner.cspace.install_at(7, tails_cap).is_ok()) != Some(true) {
        return Err("the tails capability would not install");
    }

    // The reader's wake, RFC 0026's deferred "blocking readers" question
    // answered the way every service answers it: a notification it arms
    // deadlines on, so the drain loop sleeps between passes instead of
    // spinning a CPU for the life of the boot. Badge 1, nonzero because a
    // zero badge ORs nothing and a deadline expiring through it would be a
    // wake nobody feels.
    let wake = crate::notify::create().map_err(|_| "the traced wake would not be created")?;
    let wake_root = crate::notify::name(wake).map_err(|_| "the traced wake would not be named")?;
    let wake_cap = cap::with_arena(|arena| arena.derive(wake_root, cap::Rights::ALL, 1).ok())
        .ok_or("the traced wake would not derive")?;
    if domain::with(realm, |owner| owner.cspace.install_at(2, wake_cap).is_ok()) != Some(true) {
        return Err("the traced wake would not install");
    }

    let online = bhaskix_arch::percpu::online_count();
    for cpu in 0..online {
        let identity = telemetry::ring_identity(cpu as usize).ok_or("a ring object is missing")?;
        let root = shared::name(shared::MemoryId::from_u64(identity))
            .map_err(|_| "a ring object would not be named")?;
        let ring_cap = cap::with_arena(|arena| arena.derive(root, cap::Rights::READ, 0).ok())
            .ok_or("a ring capability would not derive")?;
        if domain::with(realm, |owner| {
            owner.cspace.install_at(8 + cpu as usize, ring_cap).is_ok()
        }) != Some(true)
        {
            return Err("a ring capability would not install");
        }
    }

    // The marked set, one CPU at a time on the CPU itself, because only the
    // owning CPU may write its ring. The wait is bounded: a probe thread
    // that never runs is a scheduler defect this test exists to catch, not
    // to hang on.
    TRACED_PROBES_DONE.store(0, core::sync::atomic::Ordering::Release);
    for cpu in 0..online {
        sched::spawn_on_with(
            cpu,
            "telemetry-probe",
            traced_probe_entry,
            TRACED_PROBES_EACH,
            hhdm_base,
            sched::SpawnOptions::new().pinned(),
        )
        .map_err(|_| "a probe thread would not spawn")?;
    }
    let mut waited = 0u32;
    while TRACED_PROBES_DONE.load(core::sync::atomic::Ordering::Acquire) < online {
        wait_millis(10);
        waited += 1;
        if waited > 500 {
            return Err("the probe threads never finished");
        }
    }

    let options = sched::SpawnOptions::new()
        .pinned()
        .in_domain(realm.as_u32());
    sched::spawn_on_with(
        0,
        "traced",
        traced_domain_entry,
        hhdm_base,
        hhdm_base,
        options,
    )
    .map_err(|_| "the traced reader would not spawn")?;
    TRACED_REPORT.store(report.as_u64(), core::sync::atomic::Ordering::Release);
    Ok(())
}

/// Loads `bin/traced` into a fresh address space and enters it, telling it
/// how many rings it was granted.
extern "C" fn traced_domain_entry(hhdm_base: u64) -> ! {
    use bhaskix_boot::VirtAddr;
    use bhaskix_mm::{Protection, VirtRange};
    use vm::AddressSpace;

    let stop = |why: &str| -> ! {
        println!("\x1b[91m    traced         FAILED: {why}\x1b[0m");
        sched::exit()
    };

    let Ok(file) = vfs::open(TRACED_PROGRAM) else {
        stop("bin/traced is not in the filesystem")
    };
    let Ok(image) = elf::parse(file.bytes()) else {
        stop("bin/traced is not an ELF this kernel will load")
    };
    let Ok(mut space) = AddressSpace::new(hhdm_base) else {
        stop("the address space would not be created")
    };
    let Some(stack) = VirtRange::from_pages(VirtAddr(TRACED_STACK), TRACED_STACK_PAGES) else {
        stop("the stack range is not a range")
    };
    if space.map_anonymous(stack, Protection::ReadWrite).is_err() {
        stop("the stack would not map")
    }
    let Ok(entry) = elf::load_into(&image, file.bytes(), &mut space, hhdm_base) else {
        stop("bin/traced would not load")
    };
    // SAFETY: the higher half is copied from the running page table, so
    // everything currently executing stays addressable.
    unsafe { vm::install(space) };
    let rsp = TRACED_STACK + TRACED_STACK_PAGES * bhaskix_mm::FRAME_SIZE;
    let cpus = u64::from(bhaskix_arch::percpu::online_count());
    let hertz = bhaskix_arch::tsc::hertz().unwrap_or(0);
    // SAFETY: `entry` is inside a user-executable segment of the space just
    // installed, `rsp` is one past user-writable memory in the same space,
    // and `RSP0` was set before this thread was spawned.
    unsafe { enter_user("traced", entry, rsp, [cpus, hertz]) }
}

/// Prints what `bin/traced` read back, and gates the round trip.
fn report_traced(hhdm: u64) {
    let raw = TRACED_REPORT.load(core::sync::atomic::Ordering::Acquire);
    if raw == u64::MAX {
        return;
    }
    let expected = TRACED_PROBES_EACH * u64::from(bhaskix_arch::percpu::online_count());
    let mut words = [0u64; 10];
    let mut settled = false;
    for _ in 0..100u32 {
        let Some((pages, count)) = shared::frames_of(shared::MemoryId::from_u64(raw)) else {
            println!("\x1b[91m    traced         report page gone\x1b[0m");
            return;
        };
        if count == 0 {
            println!("\x1b[91m    traced         report page empty\x1b[0m");
            return;
        }
        for (index, word) in words.iter_mut().enumerate() {
            // SAFETY: a frame this object owns, through the direct map.
            *word = unsafe {
                core::ptr::read_volatile((hhdm + pages[0] + index as u64 * 8) as *const u64)
            };
        }
        if words[0] == TRACED_MARKER && words[1] != 0 {
            settled = true;
            break;
        }
        wait_millis(100);
    }
    let (probes, decoded, refused, bad_rings, wrong_cpu) =
        (words[2], words[3], words[4], words[5], words[6]);
    let (sched, syscalls, passes) = (words[7], words[8], words[9]);
    if settled
        && words[1] == 1
        && probes == expected
        && bad_rings == 0
        && wrong_cpu == 0
        && refused == 0
    {
        println!(
            "    traced         all {expected} probe events read back through granted rings; \
             {decoded} events decoded, {refused} refused; {sched} sched + {syscalls} syscall \
             events, {passes} passes"
        );
    } else {
        println!(
            "\x1b[91m    traced         FAILED: outcome {} — {probes} of {expected} probes, \
             {decoded} decoded, {refused} refused, {bad_rings} bad rings, {wrong_cpu} wrong-cpu\
\x1b[0m",
            words[1]
        );
    }
}

/// Prints what `bin/tcpc` reported: how far the ring handover went.
fn report_tcp_client(hhdm: u64) {
    let raw = TCPC_REPORT.load(core::sync::atomic::Ordering::Acquire);
    if raw == u64::MAX {
        return;
    }
    let Some((pages, count)) = shared::frames_of(shared::MemoryId::from_u64(raw)) else {
        println!("\x1b[91m    tcp client     report page gone\x1b[0m");
        return;
    };
    if count == 0 {
        println!("\x1b[91m    tcp client     report page empty\x1b[0m");
        return;
    }
    // SAFETY: a frame this object owns, through the direct map.
    let (marker, step, outcome, detail) = unsafe {
        (
            core::ptr::read_volatile((hhdm + pages[0]) as *const u64),
            core::ptr::read_volatile((hhdm + pages[0] + 8) as *const u64),
            core::ptr::read_volatile((hhdm + pages[0] + 16) as *const u64),
            core::ptr::read_volatile((hhdm + pages[0] + 24) as *const u64),
        )
    };
    if marker != TCPC_MARKER {
        println!("\x1b[91m    tcp client     no report: the client never wrote its page\x1b[0m");
        return;
    }
    let said = match outcome {
        0 => "still mid-exchange, which after the wait above means stuck",
        1 => "rings accepted, connection capability still owed",
        2 => "connected, stream still in flight",
        3 => "a handover leg was refused",
        4 => "gave up: the service kept answering LATER",
        5 => "the reply said yes but the declared slot stayed empty",
        6 => "outbound echoed, but the inbound half never finished",
        7 => "bytes came back through the ring, and they were not the bytes sent",
        8 => {
            "holds a working connection capability on a machine with no network; the service \
             said unreachable when asked to stream, which is this machine's truthful ending"
        }
        9 => {
            "echoed outbound through rings it owns, then listened, accepted a connection the \
             host initiated, served the echo back from its own pages, and saw the peer close -- \
             both directions of RFC 0020, both through RFC 0022's rings"
        }
        10 => {
            "echoed outbound, listened, and nobody called -- which is a state, not a failure: \
             only the boot test runs a host-side caller"
        }
        11 => {
            "holds a working connection capability on a machine that cannot be unpredictable; \
             the service said so when asked to stream, which is this machine's truthful ending"
        }
        12 => {
            "did everything outcome 9 says, then opened a v6 connection to [::1], accepted it \
             with its own listener, and echoed itself eight samples and 32 KiB through the \
             loopback -- the whole TCP machine, both roles, second family, one program \
             (RFC 0029 steps 5 and 6)"
        }
        _ => "an outcome this kernel does not know",
    };
    // RFC 0020 step 6: the numbers, converted here because the client only
    // subtracts cycle counts and the kernel is what knows the rate. Printed
    // before the verdict so a failed run still shows what it measured.
    let hertz = bhaskix_arch::tsc::hertz().unwrap_or(0);
    let micros = |ticks: u64| -> u64 {
        if hertz == 0 {
            return 0;
        }
        (u128::from(ticks) * 1_000_000 / u128::from(hertz)) as u64
    };
    // SAFETY: the same frame as above, words four to nine.
    let (handshake, rtt_min, rtt_med, rtt_max, bulk_ticks, bulk_bytes) = unsafe {
        (
            core::ptr::read_volatile((hhdm + pages[0] + 32) as *const u64),
            core::ptr::read_volatile((hhdm + pages[0] + 40) as *const u64),
            core::ptr::read_volatile((hhdm + pages[0] + 48) as *const u64),
            core::ptr::read_volatile((hhdm + pages[0] + 56) as *const u64),
            core::ptr::read_volatile((hhdm + pages[0] + 64) as *const u64),
            core::ptr::read_volatile((hhdm + pages[0] + 72) as *const u64),
        )
    };
    if handshake != 0 && hertz != 0 {
        let bulk_micros = micros(bulk_ticks).max(1);
        // KiB/s of payload each way: the bytes went out and came back.
        let through = bulk_bytes.saturating_mul(1_000_000) / bulk_micros / 1024;
        println!(
            "    tcp measure    handshake {} us; 16-byte echo round trip min/median/max \
             {}/{}/{} us over 8; {} KiB echoed in {} ms, {} KiB/s each way",
            micros(handshake),
            micros(rtt_min),
            micros(rtt_med),
            micros(rtt_max),
            bulk_bytes / 1024,
            bulk_micros / 1000,
            through,
        );
    }
    // RFC 0029 step 6: the second family's numbers, from words ten to
    // thirteen. Both ends live in one program here, so the bulk figure is
    // per-crossing cost driven turn by turn, not a pipeline rate -- and
    // with the peer at [::1] there is no emulator in any of these numbers:
    // they are the stack's own price, paid twice per round trip.
    // SAFETY: the same frame as above, words ten to thirteen.
    let (handshake6, rtt6_median, bulk6_ticks, bulk6_bytes) = unsafe {
        (
            core::ptr::read_volatile((hhdm + pages[0] + 80) as *const u64),
            core::ptr::read_volatile((hhdm + pages[0] + 88) as *const u64),
            core::ptr::read_volatile((hhdm + pages[0] + 96) as *const u64),
            core::ptr::read_volatile((hhdm + pages[0] + 104) as *const u64),
        )
    };
    if handshake6 != 0 && hertz != 0 {
        let bulk6_micros = micros(bulk6_ticks).max(1);
        let through6 = bulk6_bytes.saturating_mul(1_000_000) / bulk6_micros / 1024;
        println!(
            "    tcp measure6   loopback handshake {} us; 16-byte echo round trip median \
             {} us over 8; {} KiB echoed in {} ms, {} KiB/s each way -- no emulator in the \
             loop, the stack's own cost both directions",
            micros(handshake6),
            micros(rtt6_median),
            bulk6_bytes / 1024,
            bulk6_micros / 1000,
            through6,
        );
    }
    if outcome == 9 || outcome == 8 || outcome == 10 || outcome == 11 || outcome == 12 {
        println!("    tcp client     {said}");
    } else {
        println!(
            "\x1b[91m    tcp client     FAILED at step {step}: {said} (detail {detail:#x})\
\x1b[0m"
        );
    }
}

fn report_tcp_domain(hhdm: u64) {
    use core::sync::atomic::Ordering;

    let raw = TCP_REPORT.load(Ordering::Acquire);
    if raw == u64::MAX {
        return;
    }
    let Some((pages, count)) = shared::frames_of(shared::MemoryId::from_u64(raw)) else {
        return;
    };
    if count == 0 {
        return;
    }
    let mut words = [0u64; 8];
    // SAFETY: a frame this object owns, through the direct map, read as the
    // **eight** little-endian words the service wrote there.
    //
    // The count and the array have to move together, and they did not: adding
    // the cookie word to the array while this still said `56` made the loop
    // index `bytes[56..64]` of a 56-byte slice, and the boot died before
    // printing anything at all. Written as `words.len() * 8` so the next word
    // cannot repeat it.
    let bytes =
        unsafe { core::slice::from_raw_parts((hhdm + pages[0]) as *const u8, words.len() * 8) };
    for (index, word) in words.iter_mut().enumerate() {
        let mut buffer = [0u8; 8];
        buffer.copy_from_slice(&bytes[index * 8..index * 8 + 8]);
        *word = u64::from_le_bytes(buffer);
    }
    if words[0] != TCPD_MARKER {
        println!("    tcpd           left no report");
        return;
    }
    let outcome = match words[2] {
        0 => "still pending",
        1 => "refused by the network",
        2 => "unanswered until the bounded retransmissions ran out",
        3 => "a caller's connection is open; the stream is the caller's story",
        4 => {
            "refused by this service: the machine cannot be unpredictable; serving ring \
             handovers only"
        }
        5 => "no network; serving ring handovers only",
        6 => "retired outcome 6 from before the stream moved to the caller",
        7 => "closed in order, and TIME_WAIT expired",
        8 => "retired outcome 8 from before the stream moved to the caller",
        _ => "an outcome this kernel does not know",
    };
    println!(
        "    tcpd           state {:#x} (attached/keyed/configured/serving), outcome {}: {}; \
         {} segments in, {} out, {} refused, machine ended in state {}",
        words[1], words[2], outcome, words[3], words[4], words[5], words[6]
    );
    // **RFC 0048 step 3, and the number that says the design is the one
    // running.** A connection built from a verified cookie is one for which no
    // state was held while the peer was unproven — so a `SYN` from an address
    // that need not exist can no longer take the accepted slot and hold it.
    // Zero here on a boot that accepted a connection would mean something
    // older served it.
    println!(
        "    tcpd cookies   {} connection(s) built from a verified SYN cookie; no state is held \
         for a peer that has proved nothing",
        words[7]
    );
}

/// RFC 0019 step 2: a deadline fires, and not before it is due.
///
/// **Both halves are asserted.** That a wake arrives is half a timer; the other
/// half is that it did not arrive early, and an early wake is the failure that
/// looks like success — the waiter runs, finds what it was waiting for has not
/// happened, and either sleeps again or acts on nothing.
///
/// Measured against the same clock the deadline is expressed in, so the two
/// cannot disagree about units.
fn deadline_self_test() -> bool {
    const BADGE: u64 = 1 << 5;

    let Some(hertz) = bhaskix_arch::tsc::hertz() else {
        println!("    deadline       no calibrated timer; nothing measured");
        return true;
    };
    let Ok(notification) = notify::create() else {
        println!("\x1b[91m    deadline       FAILED: no notification to arm\x1b[0m");
        return false;
    };

    // Twenty milliseconds: long enough that the tick granularity is not the
    // whole measurement, short enough that a boot does not wait on it.
    let wait = hertz / 50;
    let armed_at = bhaskix_arch::tsc::read();
    if notify::arm(notification, armed_at + wait, BADGE).is_err() {
        notify::destroy(notification);
        println!("\x1b[91m    deadline       FAILED: the table would not take it\x1b[0m");
        return false;
    }
    // The same second half of arming the `ARM` system call does. Arming the
    // table alone records a deadline nothing has been asked to deliver.
    time::arm_no_later_than(armed_at + wait);

    // Polled rather than waited on, because this is the boot thread and it has
    // other things to start. What is being tested is the kernel's expiry, not
    // this thread's blocking.
    let mut fired_at = None;
    for _ in 0..400 {
        if notify::poll(notification) & BADGE != 0 {
            fired_at = Some(bhaskix_arch::tsc::read());
            break;
        }
        wait_millis(1);
    }
    notify::disarm(notification);
    notify::destroy(notification);

    let Some(fired_at) = fired_at else {
        println!("\x1b[91m    deadline       FAILED: it never fired\x1b[0m");
        return false;
    };
    let took = fired_at.saturating_sub(armed_at);
    if took < wait {
        println!(
            "\x1b[91m    deadline       FAILED: fired early, {took} ticks against {wait}\x1b[0m"
        );
        return false;
    }
    // **And not absurdly late, which until 2026-08-14 it always was.**
    //
    // Half of a timer is that it does not fire early, and that is checked
    // above. The other half is that the deadline has any bearing on when it
    // does fire, and nothing checked that — so for two days a 20 ms deadline
    // woke after 150 to 193 ms and every gate in this project was content.
    //
    // Twenty-five milliseconds of lateness is the bound, chosen to sit an order
    // of magnitude below what the unfixed path produced and two above what the
    // fixed one does: 0.331 ms on the boot that first passed it. A bound tight
    // enough to be interesting on a loaded host would fail for being on a
    // loaded host, and a gate whose answer depends on the machine is not a
    // gate.
    let late = took.saturating_sub(wait);
    let late_micros = late.saturating_mul(1_000_000) / hertz.max(1);
    let micros = took.saturating_mul(1_000_000) / hertz.max(1);
    if late_micros > 25_000 {
        println!(
            "\x1b[91m    deadline       FAILED: armed for 20 ms and woke after {}.{:03} ms — late \
             by {}.{:03} ms, so the deadline is not reaching the hardware\x1b[0m",
            micros / 1000,
            micros % 1000,
            late_micros / 1000,
            late_micros % 1000
        );
        return false;
    }
    println!(
        "    deadline       armed for 20 ms, woke after {}.{:03} ms, never early and late by \
         {}.{:03} ms",
        micros / 1000,
        micros % 1000,
        late_micros / 1000,
        late_micros % 1000
    );
    true
}

/// RFC 0019 step 4: how late a deadline is, across four orders of magnitude.
///
/// Step 2 measured one duration once and got 157 ms for a 20 ms deadline. One
/// number cannot say whether that is a cost proportional to the wait, a fixed
/// overhead, or a quantisation — and those three want three different fixes.
/// So this arms the same notification at 0.1, 1, 5, 20 and 100 ms, sixteen
/// times each, and reports the lateness as a **distribution**.
///
/// A mean would hide the answer. `report_service_cost` says why at length for
/// the scheduler; here the specific reason is that if lateness is quantised by
/// something the deadline does not control, the spread runs from nearly zero
/// to nearly a whole period and the mean lands in the middle, looking like a
/// tidy fixed cost that no fix would remove.
///
/// **The tick interval is reported beside it, and that is the hypothesis under
/// test.** Expiry runs where the timer interrupt already runs, and arming does
/// not re-program the hardware, so the prediction is that lateness is the wait
/// for a tick that was going to happen anyway — bounded by the tick interval,
/// independent of the deadline. Printing the interval next to the lateness is
/// what lets that be read off rather than argued.
///
/// Two intervals, because expiry is not this CPU's job alone: the table is
/// global and `on_tick` scans it on **every** processor, so a deadline is
/// serviced by whichever tick lands first anywhere. The machine's interval is
/// therefore the one that predicts the lateness, and this CPU's is what a
/// reader would otherwise assume it was.
///
/// **Run twice, and the difference is the point.** Once during bring-up, where
/// little is running and a tickless machine can be silent for most of a
/// second; once with the services up, which is the machine a caller actually
/// meets. A timer measured only on an idle machine is measured in the one
/// configuration nothing uses.
///
/// **Polled by spinning, not by `wait_millis`**, which sleeps a millisecond at
/// a time — larger than the shortest deadline here. A measurement quantised by
/// its own polling loop would be reporting the loop.
///
/// **Gated on `timers=measure`.** Sixteen samples at five durations costs
/// seconds when each one waits out a tick, and a boot gate that slow would be
/// paid on every run by everyone to answer a question that is asked once.
fn measure_deadlines(handoff: &Handoff, when: &str) -> bool {
    const BADGE: u64 = 1 << 6;
    /// Four orders of magnitude on purpose: if the lateness is the same at all
    /// of them, it is not a property of the duration.
    const DURATIONS_US: [u64; 5] = [100, 1_000, 5_000, 20_000, 100_000];
    const SAMPLES: usize = 16;
    /// How far past its deadline a sample is waited for before it is called
    /// lost. Generous, because the point is to measure lateness and a bound
    /// that cut the tail off would flatter the number this exists to report.
    const PATIENCE_US: u64 = 3_000_000;

    if !handoff
        .cmdline
        .split_ascii_whitespace()
        .any(|word| word == "timers=measure")
    {
        return true;
    }

    let Some(hertz) = bhaskix_arch::tsc::hertz() else {
        println!("    timer delay    no calibrated timer; nothing measured");
        return true;
    };
    let Some(patience) = bhaskix_arch::tsc::from_micros(PATIENCE_US) else {
        println!("    timer delay    no calibrated timer; nothing measured");
        return true;
    };
    let Ok(notification) = notify::create() else {
        println!("\x1b[91m    timer delay    FAILED: no notification to arm\x1b[0m");
        return false;
    };

    let micros = |ticks: u64| ticks.saturating_mul(1_000_000) / hertz.max(1);
    let cpu = bhaskix_arch::percpu::cpu_id();
    let ticks_before = trap::ticks_on(cpu);
    let machine_ticks_before = trap::ticks();
    // Re-arms, which are **not** the same as ticks and are the thing that
    // turned out to matter. `rearm` folds `notify::earliest_deadline` into
    // whatever it programs, and it runs on every reschedule IPI as well as on
    // every tick -- so a deadline armed just before an unrelated re-arm is
    // programmed into the hardware after all, without the `ARM` path having
    // asked for it. Counting them is what tells that story from the alternative
    // one, where lateness is simply the wait for the next tick.
    let arms_before = time::armed();
    let started = bhaskix_arch::tsc::read();
    let mut early = 0u64;
    let mut lost = 0u64;

    for duration_us in DURATIONS_US {
        let Some(wait) = bhaskix_arch::tsc::from_micros(duration_us) else {
            continue;
        };
        let mut late = [0u64; SAMPLES];
        let mut taken = 0usize;
        // Ticks that landed anywhere on the machine between arming a deadline
        // and seeing it fire, summed over the samples.
        //
        // This is the question the aggregate counters could not answer. Expiry
        // runs only in `on_tick`, so every sample must contain at least one.
        // **One per sample means the tick was the deadline's own** -- something
        // programmed the hardware for it. Many per sample means it waited for
        // ticks that were happening for other reasons, which is what the RFC
        // recorded as the diagnosis.
        let mut ticks_waited = 0u64;

        for sample in 0..SAMPLES {
            // **Wait before arming, and this gap is the measurement working at
            // all.** Without it every sample is armed microseconds after the
            // previous one expired -- which is inside the expiring tick's own
            // handler, before it reaches `rearm`. That re-arm then picks up the
            // deadline armed moments ago and programs the hardware for it
            // exactly, and the next sample fires on time.
            //
            // The first version of this had no gap and reported a median
            // lateness of 0.1 ms with a 100 ms tick interval, which is
            // impossible for a deadline waiting on background ticks: 14 samples
            // in 16 cannot each land a 0.2 ms window by chance. What it had
            // measured was a self-clocking chain between its own poll loop and
            // the handler, not what a caller gets. Nothing that blocks in `Recv`
            // arms its next deadline a microsecond after the last one fired.
            //
            // The gap grows with the sample so the arrivals are spread across
            // whatever phase the machine's own timers are in rather than
            // locking to one point in it.
            if let Some(gap) = bhaskix_arch::tsc::from_micros(1_000 + sample as u64 * 917) {
                let until = bhaskix_arch::tsc::read().saturating_add(gap);
                while bhaskix_arch::tsc::read() < until {
                    core::hint::spin_loop();
                }
            }

            let ticks_at_arm = trap::ticks();
            let due = bhaskix_arch::tsc::read().saturating_add(wait);
            if notify::arm(notification, due, BADGE).is_err() {
                break;
            }
            // Exactly what the `ARM` system call does after the table takes it,
            // and it must stay exactly that: a measurement that armed
            // differently from the callers would be measuring something no
            // caller can ask for.
            time::arm_no_later_than(due);

            let mut fired_at = None;
            loop {
                if notify::poll(notification) & BADGE != 0 {
                    // Read *after* seeing it fire, so the error is a poll's
                    // worth of overestimate rather than an underestimate. A
                    // timer measured as earlier than it was is the direction
                    // that would hide the failure this whole RFC guards.
                    fired_at = Some(bhaskix_arch::tsc::read());
                    break;
                }
                if bhaskix_arch::tsc::read() > due.saturating_add(patience) {
                    break;
                }
                core::hint::spin_loop();
            }

            let Some(fired_at) = fired_at else {
                notify::disarm(notification);
                lost += 1;
                continue;
            };
            if fired_at < due {
                // Never expected, and counted rather than clamped: a negative
                // lateness saturated to zero would read as a very good result.
                early += 1;
                continue;
            }
            late[taken] = fired_at - due;
            ticks_waited += trap::ticks().saturating_sub(ticks_at_arm);
            taken += 1;
        }

        if taken == 0 {
            println!(
                "\x1b[93m    timer delay    {when}, {}.{:03} ms deadline: no samples\x1b[0m",
                duration_us / 1000,
                duration_us % 1000
            );
            continue;
        }

        // Insertion sort. Sixteen values in a fixed array, no allocator, and
        // the median is the statistic this is for.
        let samples = &mut late[..taken];
        for i in 1..samples.len() {
            let mut j = i;
            while j > 0 && samples[j - 1] > samples[j] {
                samples.swap(j - 1, j);
                j -= 1;
            }
        }
        let (low, mid, high) = (
            micros(samples[0]),
            micros(samples[taken / 2]),
            micros(samples[taken - 1]),
        );
        println!(
            "    timer delay    {when}, {}.{:03} ms deadline: late by {}.{:03} / {}.{:03} / \
             {}.{:03} ms (min/median/max), {taken} samples, {}.{:02} ticks a sample",
            duration_us / 1000,
            duration_us % 1000,
            low / 1000,
            low % 1000,
            mid / 1000,
            mid % 1000,
            high / 1000,
            high % 1000,
            ticks_waited * 100 / taken as u64 / 100,
            ticks_waited * 100 / taken as u64 % 100,
        );
    }

    notify::disarm(notification);
    notify::destroy(notification);

    // The tick interval this CPU actually ran at, over the whole measurement.
    // The comparison to make is against the medians above.
    let elapsed = micros(bhaskix_arch::tsc::read().saturating_sub(started));
    let mine = trap::ticks_on(cpu).saturating_sub(ticks_before);
    let machine = trap::ticks().saturating_sub(machine_ticks_before);
    // Zero re-arms is the interesting answer rather than a missing one, so it
    // is said in words. A rate printed as `one every 0.000 ms` would read as
    // continuous re-arming, which is the opposite of what it means.
    let arms = time::armed().saturating_sub(arms_before);
    println!(
        "    timer delay    {when}, over {}.{:03} ms: cpu {cpu} ticked {mine} times, the machine \
         {machine} times (one every {}.{:03} ms), and the timer was armed for a computed deadline \
         {arms} times",
        elapsed / 1000,
        elapsed % 1000,
        elapsed.checked_div(machine).unwrap_or(0) / 1000,
        elapsed.checked_div(machine).unwrap_or(0) % 1000,
    );
    if lost > 0 {
        println!(
            "\x1b[93m    timer delay    {when}, {lost} deadlines never fired within {} ms of \
             being due\x1b[0m",
            PATIENCE_US / 1000
        );
    }
    if early > 0 {
        println!("\x1b[91m    timer delay    FAILED: {early} fired early, {when}\x1b[0m");
        return false;
    }
    true
}

/// Reads what the network driver wrote, and says so.
///
/// Two separate findings, reported on two separate lines **on purpose**. A
/// driver that transmits into a void and never checks would pass a single gate
/// covering both; it cannot pass two.
fn report_net_domain(hhdm: u64) -> bool {
    use core::sync::atomic::Ordering;

    let raw = NET_RINGS.load(Ordering::Acquire);
    if raw == u64::MAX {
        // No device on the bus, which is not a failure.
        return true;
    }
    let Some((frames, count)) = shared::frames_of(shared::MemoryId::from_u64(raw)) else {
        println!("\x1b[91m    net domain     FAILED: the rings are gone\x1b[0m");
        return false;
    };
    if count <= NETD_REPORT_PAGE {
        println!("\x1b[91m    net domain     FAILED: the rings are too small for a report\x1b[0m");
        return false;
    }

    let mut words = [0u64; 13];
    // SAFETY: a frame this object owns, through the direct map, read as the
    // thirteen little-endian words the driver wrote there.
    let raw =
        unsafe { core::slice::from_raw_parts((hhdm + frames[NETD_REPORT_PAGE]) as *const u8, 104) };
    for (index, word) in words.iter_mut().enumerate() {
        let mut buffer = [0u8; 8];
        buffer.copy_from_slice(&raw[index * 8..index * 8 + 8]);
        *word = u64::from_le_bytes(buffer);
    }
    if words[0] != NETD_MARKER {
        println!("\x1b[91m    net domain     FAILED: the driver left no report\x1b[0m");
        return false;
    }

    let mac = words[1];
    let octets = |value: u64| {
        [
            (value >> 40) as u8,
            (value >> 32) as u8,
            (value >> 24) as u8,
            (value >> 16) as u8,
            (value >> 8) as u8,
            value as u8,
        ]
    };
    // With no unit to contain the device there is no device address for the
    // rings, so the driver was never able to drive it. That is the refusal
    // working rather than a fault, and it is the state every BIOS boot is in.
    if !NET_CONTAINED.load(Ordering::Acquire) {
        println!(
            "    net domain     driver reached the handshake and stopped; without a window \
             there is no address to give the device"
        );
        return true;
    }

    let [a, b, c, d, e, f] = octets(mac);
    println!(
        "    net domain     up: mac {a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{f:02x}, \
         rx queue {}, tx queue {}",
        words[6], words[7]
    );

    let transmitted = words[2];
    if transmitted == 0 {
        println!("\x1b[91m    net domain     FAILED: nothing was transmitted\x1b[0m");
        return false;
    }
    println!("    net frame      transmitted {transmitted} bytes onto the wire");

    // The receive half, gated separately. A length of zero means nothing came
    // back, which on a network that answers is a failure and not an absence.
    let length = words[3];
    if length == 0 {
        println!(
            "\x1b[91m    net domain     FAILED: nothing was received (the receive ring has \
             seen {} completions)\x1b[0m",
            words[8]
        );
        return false;
    }
    let [p, q, r, s, t, u] = octets(words[4]);
    println!(
        "    net frame      received {length} bytes from {p:02x}:{q:02x}:{r:02x}:{s:02x}:{t:02x}:{u:02x}, \
         virtio header {} bytes; {} of {} seen handed to the ring, {} sent back for ipd (took {} bytes starting {:#014x})",
        words[5], words[9], words[8], words[10], words[12], words[11]
    );
    true
}

/// The marker `bin/ipd` writes before its report.
const IPD_MARKER: u64 = 0x3154_5052_4450_4931;

/// Reads what `bin/ipd` found, and says so.
///
/// Returns whether anything crossed. **More than one frame is required**, and
/// that is not fussiness: `netd`'s step-2 self-test handled exactly one frame,
/// so a gate satisfied by one could not tell a working receive loop from the
/// old behaviour with a ring bolted to the side of it. A receive queue that is
/// drained and never refilled works precisely once.
fn report_net_ring(hhdm: u64) -> bool {
    use core::sync::atomic::Ordering;

    let raw = NET_RING_REPORT.load(Ordering::Acquire);
    if raw == u64::MAX {
        return true;
    }
    let Some((frames_of, count)) = shared::frames_of(shared::MemoryId::from_u64(raw)) else {
        println!("\x1b[91m    net ring       FAILED: the report page is gone\x1b[0m");
        return false;
    };
    if count == 0 {
        println!("\x1b[91m    net ring       FAILED: the report page is empty\x1b[0m");
        return false;
    }

    let mut words = [0u64; 23];
    // SAFETY: a frame this object owns, through the direct map, read as the
    // twenty-three little-endian words the service writes — nine consumed
    // here since RFC 0018, plus RFC 0029's two v6 words at 21 and 22. Not
    // 11 and 12: those carry the ring's own head and tail for the "ipd
    // after" line, which the first v6 draft discovered by overwriting them.
    let raw = unsafe { core::slice::from_raw_parts((hhdm + frames_of[0]) as *const u8, 184) };
    for (index, word) in words.iter_mut().enumerate() {
        let mut buffer = [0u8; 8];
        buffer.copy_from_slice(&raw[index * 8..index * 8 + 8]);
        *word = u64::from_le_bytes(buffer);
    }
    // No window means the driver could never make the device receive, so there
    // is nothing to hand across and nothing to count. Checked **before** the
    // count rather than only when the report is missing: `ipd` writes a report
    // the moment it starts, precisely so that "never ran" and "ran and saw
    // nothing" are distinguishable, which means the absent-marker branch no
    // longer catches this case. It did, until `ipd` started reporting early.
    if !NET_CONTAINED.load(Ordering::Acquire) {
        println!("    net ring       nothing crossed; without a dma window there are no frames");
        return true;
    }
    if words[0] != IPD_MARKER {
        println!("\x1b[91m    net ring       FAILED: the service left no report\x1b[0m");
        return false;
    }

    let (frames, bytes, source, refused) = (words[1], words[2], words[3], words[4]);
    let octets = [
        (source >> 40) as u8,
        (source >> 32) as u8,
        (source >> 24) as u8,
        (source >> 16) as u8,
        (source >> 8) as u8,
        source as u8,
    ];
    let [a, b, c, d, e, f] = octets;
    println!(
        "    net ring       {frames} frames crossed to ipd, {bytes} bytes, first from \
         {a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{f:02x}, {refused} refused"
    );
    // The return path, reported from both ends. `ipd` says how many frames it
    // built; `netd` says how many it took out of the ring and put on the wire.
    // Two numbers because "nothing came out" has an end at each side of a ring
    // and one number cannot say which -- the ambiguity that cost step 3 an
    // hour of looking at the wrong program.
    println!(
        "    net reply      ipd built {} frames, {} arp mappings learned (can send {}, configured {})",
        words[5],
        words[6],
        words[7] & 1,
        (words[7] >> 1) & 1
    );
    // The echo, reported separately because it is the only line here that says
    // the whole stack worked rather than that each piece did: an address
    // learned from a parsed reply, a header and two checksums written by
    // `bhaskix-net`, a driver that forwarded bytes it cannot read, and a
    // payload that came back exactly as it went out.
    if words[8] > 0 {
        println!(
            "    net echo       {} icmp echo replies, payload returned unchanged",
            words[8]
        );
    } else {
        // **This said the host could not answer an echo request, and that was
        // wrong.** The claim was that QEMU's user-mode network needs
        // permission from the host to open an ICMP socket and drops the
        // request silently without it. It does not: `filter-dump` on this
        // machine shows `10.0.2.2 > 10.0.2.15: ICMP echo reply` arriving
        // 32 microseconds after the request, and `bin/netd` hands that frame
        // across to `bin/ipd`.
        //
        // What actually happened is that every frame this system transmitted
        // for `bin/ipd` was truncated to 42 bytes by the wrong virtio
        // descriptor — see `take_from_ipd`'s caller. The echo request left
        // declaring 25 bytes of ICMP and carrying none, so nothing answered
        // *that*, and the environment was blamed for what this code did. The
        // earlier capture showing the request "leaving well-formed" read the
        // headers and not the length, which is how it survived being checked.
        //
        // The round trip now works and this branch no longer runs: see the
        // `net echo` line above, which counts replies whose payload came back
        // unchanged. Reaching here again would mean a real regression rather
        // than a host that cannot answer.
        println!(
            "    net echo       echo request sent and nothing answered it, which used to be \
             blamed on the host and never was the host"
        );
    }
    // RFC 0029 step 3: the second family, reported the same way. The
    // prefix word is the high half of what SLAAC obtained; zero means no
    // router advertisement ever arrived, which on a network without v6 is
    // a state and not a fault.
    let (v6_prefix, v6_state) = (words[21], words[22]);
    if v6_prefix != 0 {
        let seg = |shift: u32| (v6_prefix >> shift) & 0xffff;
        println!(
            "    net ipv6       slaac {:x}:{:x}:{:x}:{:x}::/64{}{}; {} v6 echo replies",
            seg(48),
            seg(32),
            seg(16),
            seg(0),
            if v6_state & 0b10 != 0 {
                ", router advertised"
            } else {
                ""
            },
            if v6_state & 0b100 != 0 {
                ", host resolved by ndp"
            } else {
                ""
            },
            v6_state >> 8
        );
    } else {
        println!("    net ipv6       no router advertisement; link-local only");
    }

    if words[5] == 0 {
        println!("\x1b[91m    net reply      FAILED: the service built nothing to send\x1b[0m");
        return false;
    }

    if frames < 2 {
        println!(
            "\x1b[91m    net ring       FAILED: {frames} frames crossed, which one buffer \
             would explain\x1b[0m"
        );
        return false;
    }
    true
}

/// Reads what `bin/dhcp` found, and says so.
///
/// Returns whether an address was offered. Not a failure when none was: a
/// machine with no network still boots, and this program's whole point is that
/// it needs nothing to try.
/// Reads what `bin/udp6` found, and says so.
///
/// Returns whether the question was answered where a network existed. Not a
/// failure when there is no network: the machine still boots.
fn report_udp6_client(hhdm: u64) -> bool {
    use core::sync::atomic::Ordering;

    let raw = UDP6_REPORT.load(Ordering::Acquire);
    if raw == u64::MAX {
        return true;
    }
    if !NET_CONTAINED.load(Ordering::Acquire) {
        println!("    udp6 client    no unit contains the device, so there is no network to ask");
        return true;
    }
    let Some((frames, count)) = shared::frames_of(shared::MemoryId::from_u64(raw)) else {
        return true;
    };
    if count == 0 {
        return true;
    }

    let mut words = [0u64; 4];
    // SAFETY: a frame this object owns, through the direct map, read as the
    // four little-endian words the client wrote there.
    let raw = unsafe { core::slice::from_raw_parts((hhdm + frames[0]) as *const u8, 32) };
    for (index, word) in words.iter_mut().enumerate() {
        let mut buffer = [0u8; 8];
        buffer.copy_from_slice(&raw[index * 8..index * 8 + 8]);
        *word = u64::from_le_bytes(buffer);
    }
    if words[0] != UDP6_MARKER {
        println!("    udp6 client    left no report");
        return false;
    }

    match words[3] {
        0 => {
            println!(
                "    udp6 client    a v6 datagram crossed to the service and back: two sockets, \
                 [::1]:{} to [::1]:{}, payload returned unchanged",
                words[2], words[1]
            );
            true
        }
        1 => {
            println!("    udp6 client    no network service to ask");
            true
        }
        2 => {
            println!(
                "\x1b[91m    udp6 client    the datagram went out and nothing was delivered\x1b[0m"
            );
            false
        }
        3 => {
            println!(
                "\x1b[91m    udp6 client    something was delivered and it was not ours \
                 (port {}, address tail {:#x})\x1b[0m",
                words[1], words[2]
            );
            false
        }
        4 => {
            println!(
                "\x1b[91m    udp6 client    refused a slot to be answered in, status {}\x1b[0m",
                words[1]
            );
            false
        }
        5 => {
            println!(
                "\x1b[91m    udp6 client    no socket: kernel {} service {}\x1b[0m",
                words[1], words[2]
            );
            false
        }
        6 => {
            println!(
                "\x1b[91m    udp6 client    would not send: kernel {} service {}\x1b[0m",
                words[1], words[2]
            );
            false
        }
        other => {
            println!("\x1b[91m    udp6 client    unknown outcome {other}\x1b[0m");
            false
        }
    }
}

fn report_dhcp_client(hhdm: u64) -> bool {
    use core::sync::atomic::Ordering;

    let raw = DHCP_REPORT.load(Ordering::Acquire);
    if raw == u64::MAX {
        return true;
    }
    // **No unit, no network, and therefore no offer** — which is a state and
    // not a fault, exactly as it is for the driver twenty lines up. Without a
    // window there is no address to give the device, so `bin/netd` stops at the
    // handshake and nothing this client sends can reach a wire. Every BIOS boot
    // is in this position by construction.
    //
    // This gate read "nobody answered" as a failure on those machines, which
    // meant the whole boot test failed for the one reason it should not: the
    // machine being what it says it is.
    if !NET_CONTAINED.load(Ordering::Acquire) {
        println!("    dhcp client    no unit contains the device, so there is no network to ask");
        return true;
    }
    let Some((frames, count)) = shared::frames_of(shared::MemoryId::from_u64(raw)) else {
        return true;
    };
    if count == 0 {
        return true;
    }

    let mut words = [0u64; 4];
    // SAFETY: a frame this object owns, through the direct map, read as the
    // four little-endian words the client wrote there.
    let raw = unsafe { core::slice::from_raw_parts((hhdm + frames[0]) as *const u8, 32) };
    for (index, word) in words.iter_mut().enumerate() {
        let mut buffer = [0u8; 8];
        buffer.copy_from_slice(&raw[index * 8..index * 8 + 8]);
        *word = u64::from_le_bytes(buffer);
    }
    if words[0] != DHCPD_MARKER {
        println!("    dhcp client    left no report");
        return false;
    }

    let octets = |value: u64| {
        [
            (value >> 24) as u8,
            (value >> 16) as u8,
            (value >> 8) as u8,
            value as u8,
        ]
    };
    match words[3] {
        0 => {
            let [a, b, c, d] = octets(words[1]);
            let [e, f, g, h] = octets(words[2]);
            println!(
                "    dhcp client    offered {a}.{b}.{c}.{d} by {e}.{f}.{g}.{h}, holding a socket \
                 and a page and nothing else"
            );
            true
        }
        1 => {
            println!("    dhcp client    no network to ask");
            true
        }
        // The three ways the client stops before it has asked anything, each
        // carrying the number that stopped it. Printed rather than folded into
        // one message: the folded version named the symptom three times over.
        4 => {
            println!(
                "    dhcp client    refused a slot to be answered in, status {}",
                words[1]
            );
            false
        }
        // **A machine with no network is a state, not a failure**, and this
        // returned `false` for it. Every BIOS boot has no unit, so the driver
        // has no address to give the device and `bin/ipd` answers `NO_NETWORK`
        // to anyone asking for a socket -- which is the refusal working exactly
        // as the driver's own "reached the handshake and stopped" does. The
        // diagnostics that split this outcome into three made the honest answer
        // look like a fault.
        //
        // Any *other* reason for the same two calls failing is still a failure:
        // a service that is there and refusing for a reason nobody chose is
        // precisely what a gate should catch.
        5 if words[2] == bhaskix_abi::socket::NO_NETWORK => {
            println!("    dhcp client    no network on this machine, so no address to ask for");
            true
        }
        5 => {
            println!(
                "    dhcp client    bound no socket, status {} and the service said {}",
                words[1], words[2]
            );
            false
        }
        6 if words[2] == bhaskix_abi::socket::NO_NETWORK => {
            println!("    dhcp client    a socket, but no network under it");
            true
        }
        6 => {
            println!(
                "    dhcp client    sent nothing, status {} and the service said {}",
                words[1], words[2]
            );
            false
        }
        3 => {
            println!("    dhcp client    something answered and it was not an offer");
            false
        }
        _ => {
            println!("    dhcp client    nobody answered");
            false
        }
    }
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
    // What `HAND` did for the driver while it was answering nobody. This was
    // "refused with exactly WrongObject" until RFC 0022 step 1: such a hand
    // now *stages* the capability for the thread's next call, so the checked
    // property is the new mechanism's actual promise — the hand is accepted
    // (high byte 0), and the slot the driver had declared stayed empty (low
    // byte NoSuchCapability), because a staged gift moves only at a
    // rendezvous the stager initiates. A capability appearing in the declared
    // slot without a call would be the old bug wearing the new rule.
    let not_answering = hand_refusals as u32;
    // The pair is hand-status * 256 + probe-status; the expected hand status
    // is OK, whose contribution to the high byte is zero by value rather than
    // by an arithmetic identity written out.
    let expected_pair = syscall::Status::NoSuchCapability as u32;
    let ok = not_answering == expected_pair
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
             a hand while answering nobody staged and installed nothing \
             (pair {not_answering:#x})",
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

/// Loads `bin/ahcid` and becomes the AHCI driver, in ring 3.
extern "C" fn ahci_domain_entry(hhdm_base: u64) -> ! {
    use bhaskix_boot::VirtAddr;
    use bhaskix_mm::{Protection, VirtRange};
    use vm::AddressSpace;

    let stop = |why: &str| -> ! {
        println!("\x1b[91m    ahci domain    FAILED: {why}\x1b[0m");
        sched::exit()
    };

    let Ok(file) = vfs::open(AHCID_PROGRAM) else {
        stop("bin/ahcid is not in the filesystem")
    };
    let Ok(image) = elf::parse(file.bytes()) else {
        stop("bin/ahcid is not an ELF this kernel will load")
    };
    let Ok(mut space) = AddressSpace::new(hhdm_base) else {
        stop("the address space would not be created")
    };
    let Some(stack) = VirtRange::from_pages(VirtAddr(AHCID_STACK), AHCID_STACK_PAGES) else {
        stop("the stack range is not a range")
    };
    if space.map_anonymous(stack, Protection::ReadWrite).is_err() {
        stop("the stack would not map")
    }
    let Ok(entry) = elf::load_into(&image, file.bytes(), &mut space, hhdm_base) else {
        stop("bin/ahcid would not load")
    };

    // SAFETY: the higher half is copied from the running page table, so
    // everything currently executing stays addressable.
    unsafe { vm::install(space) };

    // The cycle counter's rate, because a program in ring 3 cannot calibrate
    // one and every deadline in the bring-up needs it.
    //
    // **This comment said the wrong thing until 2026-08-24.** It claimed that a
    // zero rate left `now_nanos` answering a clock that never advances "so the
    // first wait refuses rather than the driver hanging". The opposite: a clock
    // that never advances makes `now - started >= budget` unreachable, so every
    // bounded wait becomes unbounded. Step 4's first boot hung on exactly that.
    // The driver now falls back to the raw cycle count, which always moves.
    let hertz = bhaskix_arch::tsc::hertz().unwrap_or(0);
    let rsp = AHCID_STACK + AHCID_STACK_PAGES * bhaskix_mm::FRAME_SIZE;
    // SAFETY: `entry` is inside a user-executable segment of the space just
    // installed, and `rsp` is one past user-writable memory in it.
    unsafe { enter_user("ahci domain", entry, rsp, [hertz, 0]) }
}

/// Loads and enters `bin/netd`.
extern "C" fn net_domain_entry(hhdm_base: u64) -> ! {
    use bhaskix_boot::VirtAddr;
    use bhaskix_mm::{Protection, VirtRange};
    use vm::AddressSpace;

    let stop = |why: &str| -> ! {
        println!("\x1b[91m    net domain     FAILED: {why}\x1b[0m");
        sched::exit()
    };

    let Ok(file) = vfs::open(NETD_PROGRAM) else {
        stop("bin/netd is not in the filesystem")
    };
    let Ok(image) = elf::parse(file.bytes()) else {
        stop("bin/netd is not an ELF this kernel will load")
    };
    let Ok(mut space) = AddressSpace::new(hhdm_base) else {
        stop("the address space would not be created")
    };
    let Some(stack) = VirtRange::from_pages(VirtAddr(NETD_STACK), NETD_STACK_PAGES) else {
        stop("the stack range is not a range")
    };
    if space.map_anonymous(stack, Protection::ReadWrite).is_err() {
        stop("the stack would not map")
    }
    let Ok(entry) = elf::load_into(&image, file.bytes(), &mut space, hhdm_base) else {
        stop("bin/netd would not load")
    };

    // SAFETY: the higher half is copied from the running page table, so
    // everything currently executing stays addressable.
    unsafe { vm::install(space) };

    let rsp = NETD_STACK + NETD_STACK_PAGES * bhaskix_mm::FRAME_SIZE;
    // SAFETY: `entry` is inside a user-executable segment of the space just
    // installed, `rsp` is one past user-writable memory in the same space, and
    // `RSP0` was set before this thread was spawned.
    unsafe { enter_user("net domain", entry, rsp, [0, 0]) }
}

/// Loads and enters `bin/ipd`.
extern "C" fn ip_domain_entry(hhdm_base: u64) -> ! {
    use bhaskix_boot::VirtAddr;
    use bhaskix_mm::{Protection, VirtRange};
    use vm::AddressSpace;

    let stop = |why: &str| -> ! {
        println!("\x1b[91m    net ring       FAILED: {why}\x1b[0m");
        sched::exit()
    };

    let Ok(file) = vfs::open(IPD_PROGRAM) else {
        stop("bin/ipd is not in the filesystem")
    };
    let Ok(image) = elf::parse(file.bytes()) else {
        stop("bin/ipd is not an ELF this kernel will load")
    };
    let Ok(mut space) = AddressSpace::new(hhdm_base) else {
        stop("the address space would not be created")
    };
    let Some(stack) = VirtRange::from_pages(VirtAddr(IPD_STACK), IPD_STACK_PAGES) else {
        stop("the stack range is not a range")
    };
    if space.map_anonymous(stack, Protection::ReadWrite).is_err() {
        stop("the stack would not map")
    }
    let Ok(entry) = elf::load_into(&image, file.bytes(), &mut space, hhdm_base) else {
        stop("bin/ipd would not load")
    };

    // SAFETY: the higher half is copied from the running page table, so
    // everything currently executing stays addressable.
    unsafe { vm::install(space) };

    let rsp = IPD_STACK + IPD_STACK_PAGES * bhaskix_mm::FRAME_SIZE;
    // SAFETY: `entry` is inside a user-executable segment of the space just
    // installed, `rsp` is one past user-writable memory in the same space, and
    // `RSP0` was set before this thread was spawned.
    unsafe { enter_user("net ring", entry, rsp, [0, 0]) }
}

/// Loads and enters `bin/dhcp`.
extern "C" fn dhcp_client_entry(hhdm_base: u64) -> ! {
    use bhaskix_boot::VirtAddr;
    use bhaskix_mm::{Protection, VirtRange};
    use vm::AddressSpace;

    let stop = |why: &str| -> ! {
        println!("\x1b[91m    dhcp client    FAILED: {why}\x1b[0m");
        sched::exit()
    };

    let Ok(file) = vfs::open(DHCPD_PROGRAM) else {
        stop("bin/dhcp is not in the filesystem")
    };
    let Ok(image) = elf::parse(file.bytes()) else {
        stop("bin/dhcp is not an ELF this kernel will load")
    };
    let Ok(mut space) = AddressSpace::new(hhdm_base) else {
        stop("the address space would not be created")
    };
    let Some(stack) = VirtRange::from_pages(VirtAddr(DHCPD_STACK), DHCPD_STACK_PAGES) else {
        stop("the stack range is not a range")
    };
    if space.map_anonymous(stack, Protection::ReadWrite).is_err() {
        stop("the stack would not map")
    }
    let Ok(entry) = elf::load_into(&image, file.bytes(), &mut space, hhdm_base) else {
        stop("bin/dhcp would not load")
    };

    // SAFETY: the higher half is copied from the running page table, so
    // everything currently executing stays addressable.
    unsafe { vm::install(space) };

    let rsp = DHCPD_STACK + DHCPD_STACK_PAGES * bhaskix_mm::FRAME_SIZE;
    // SAFETY: `entry` is inside a user-executable segment of the space just
    // installed, `rsp` is one past user-writable memory in the same space, and
    // `RSP0` was set before this thread was spawned.
    // **The clock's rate, handed over at entry.** `rdtsc` is unprivileged on this
    // machine so the program can read the counter, but nothing tells it how fast
    // the counter runs, and a deadline is a duration times a rate. RFC 0019
    // says reading time is ambient; knowing the units is not, and this is the
    // one thing that cannot arrive through a CSpace.
    let hertz = bhaskix_arch::tsc::hertz().unwrap_or(0);
    // SAFETY: as above.
    unsafe { enter_user("dhcp client", entry, rsp, [hertz, 0]) }
}

/// Loads and enters `bin/udp6`.
extern "C" fn udp6_client_entry(hhdm_base: u64) -> ! {
    use bhaskix_boot::VirtAddr;
    use bhaskix_mm::{Protection, VirtRange};
    use vm::AddressSpace;

    let stop = |why: &str| -> ! {
        println!("\x1b[91m    udp6 client    FAILED: {why}\x1b[0m");
        sched::exit()
    };

    let Ok(file) = vfs::open(UDP6_PROGRAM) else {
        stop("bin/udp6 is not in the filesystem")
    };
    let Ok(image) = elf::parse(file.bytes()) else {
        stop("bin/udp6 is not an ELF this kernel will load")
    };
    let Ok(mut space) = AddressSpace::new(hhdm_base) else {
        stop("the address space would not be created")
    };
    let Some(stack) = VirtRange::from_pages(VirtAddr(UDP6_STACK), UDP6_STACK_PAGES) else {
        stop("the stack range is not a range")
    };
    if space.map_anonymous(stack, Protection::ReadWrite).is_err() {
        stop("the stack would not map")
    }
    let Ok(entry) = elf::load_into(&image, file.bytes(), &mut space, hhdm_base) else {
        stop("bin/udp6 would not load")
    };

    // SAFETY: the higher half is copied from the running page table, so
    // everything currently executing stays addressable.
    unsafe { vm::install(space) };

    let rsp = UDP6_STACK + UDP6_STACK_PAGES * bhaskix_mm::FRAME_SIZE;
    // The clock's rate, handed over at entry, for bin/dhcp's stated reason:
    // reading time is ambient; knowing the units is not.
    let hertz = bhaskix_arch::tsc::hertz().unwrap_or(0);
    // SAFETY: `entry` is inside a user-executable segment of the space just
    // installed, `rsp` is one past user-writable memory in the same space,
    // and `RSP0` was set before this thread was spawned.
    unsafe { enter_user("udp6 client", entry, rsp, [hertz, 0]) }
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
    let mut words = [0u64; 10];
    for _ in 0..200 {
        // SAFETY: a frame this object owns, through the direct map, read as
        // the ten little-endian words the service writes there.
        let raw = unsafe { core::slice::from_raw_parts((hhdm + frames[1]) as *const u8, 80) };
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
        pkg,
    ] = words;
    // What the service says names `sub`. The kernel is the only thing that can
    // mint a capability, so the service supplies the badge and the kernel
    // stamps it. RFC 0016 step 4 is not finished; this is enough of it to
    // reproduce the defect that stopped it.
    FS_ENDPOINT.store(u64::from(serving.as_u32()), Ordering::Release);
    FS_DIRECTORY.store(directory, Ordering::Release);
    FS_STALE.store(stale, Ordering::Release);
    FS_PKG.store(pkg, Ordering::Release);
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

    // Slot 5: one page of scratch, which is what RFC 0032's copies move
    // through. A supervisor reading a child's memory must name **an object it
    // already owns** for the bytes to land in — it never names an address in
    // its own space, so the kernel is never asked to validate two addresses in
    // two address spaces. This page is that object.
    let scratch = shared::create(realm, bhaskix_mm::FRAME_SIZE)
        .map_err(|_| "the supervisor's scratch page would not be created")?;
    let scratch_cap = shared::name(scratch).map_err(|_| "the scratch page would not be named")?;

    // Slot 4 is left empty: it is where each child's `Domain` capability lands
    // and is given back from.
    if domain::with(realm, |owner| {
        owner.cspace.install_at(0, console_cap).is_ok()
            && owner.cspace.install_at(1, control).is_ok()
            && owner.cspace.install_at(2, staged).is_ok()
            && owner.cspace.install_at(3, signal).is_ok()
            && owner.cspace.install_at(5, scratch_cap).is_ok()
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
// Sixteen pages since RFC 0030 step 3: `pkg install` verifies a package
// with the same parser the host tools use, and a parsed manifest is a
// fixed-capacity value of about eight kilobytes that lives on the stack --
// the four-page stack blew through its floor at the first real install,
// faulting at 0x10fff668 with rsp eighteen kilobytes under the base.
const SHELL_STACK_PAGES: u64 = 16;

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

    // RFC 0046 step 3b: the SATA controller, driven from ring 3. Not gated on
    // the block path either, and for a stronger reason than the network's: this
    // is the machine's *other* storage, and a machine whose virtio disk is
    // missing is exactly the machine where knowing what is on the SATA ports
    // matters most.
    if let Err(reason) = start_ahci_domain(cpu, hhdm) {
        println!("\x1b[91m    ahci domain    FAILED: {reason}\x1b[0m");
    } else {
        // Waited for the report rather than for a duration, as every other
        // driver domain here is: a fixed wait is a guess that is too short on a
        // loaded machine and too long on every other boot. The bring-up's own
        // deadlines bound how long the driver can take, so this bounds only how
        // long the kernel will believe it is still coming.
        for _ in 0..60 {
            if ahci_domain_reported(hhdm) {
                break;
            }
            wait_millis(50);
        }
        if !report_ahci_domain(hhdm) {
            println!("\x1b[91m    ahci domain    FAILED\x1b[0m");
        }
        if !ahci_service_self_test(hhdm) {
            println!("\x1b[91m    ahci service   FAILED\x1b[0m");
        }
    }

    // RFC 0018 step 2: the network device, driven from ring 3. Not gated on the
    // block path above -- a machine with no disk to delegate should still get a
    // network, and coupling them would make one failure look like two.
    if let Err(reason) = start_net_domain(cpu, hhdm, handoff.bsp_lapic_id, handoff.rsdp) {
        println!("\x1b[91m    net domain     FAILED: {reason}\x1b[0m");
    } else {
        // Waited for the report rather than for a duration, for the reason the
        // block path records: a fixed wait is a guess that is too short on a
        // loaded machine and too long on every other boot.
        // Longer than the block domain's three seconds, and for a reason: this
        // driver waits on a *remote* party. Its transmit completes at once and
        // its receive does not, so the window has to cover a reply that a
        // network chooses the timing of rather than a disk that answers.
        for _ in 0..160 {
            if net_domain_reported(hhdm) {
                break;
            }
            wait_millis(50);
        }
        // The configuration, as soon as the driver knows it rather than when its
        // report is printed. `ipd` cannot build an ARP packet without the
        // hardware address, and it holds no device to ask for one.
        match net_domain_mac(hhdm) {
            Some(mac) if publish_net_config(hhdm, mac) => {
                println!(
                    "    net config     interface told to ipd: mac {mac:#014x}, address 10.0.2.15"
                );
            }
            Some(_) => println!(
                "\x1b[91m    net config     FAILED: the configuration page would not take it\x1b[0m"
            ),
            // A driver with no DMA window never gets as far as reading the
            // device's address, so there is nothing to pass on and nothing
            // wrong — that is every boot without an IOMMU. Only a driver that
            // *could* have read one and did not is a failure.
            None if !NET_CONTAINED.load(core::sync::atomic::Ordering::Acquire) => println!(
                "    net config     no address to pass on; the driver has no window to read one \
                 through"
            ),
            None => println!(
                "\x1b[91m    net config     FAILED: the driver reported no address to pass on\x1b[0m"
            ),
        }

        // Both reports are read after the same wait, and that is a correction:
        // reading the driver's report the moment its marker appeared caught it
        // before its receive loop had run, so it always said nothing had been
        // handed across. A report read at the wrong moment is a measurement of
        // the reader's timing rather than of the thing measured.
        //
        // `ipd` polls, so it needs wall-clock time rather than a barrier, and
        // the frames it counts arrive from a network that chooses when.
        //
        // **The burst is timed first, and the position is the measurement.**
        // It ran after this wait once, and reported the first phase at 0.65
        // microseconds a round trip — impossible through an emulated NIC, and
        // exactly what a phase that finished before anyone looked reads as.
        // The burst starts as soon as `bin/ipd`'s demonstration ping comes
        // back, which happens inside this wait; a timer that starts afterwards
        // is measuring its own lateness. This function does the driver poking
        // the loop below does, so nothing is lost by going first.
        time_the_burst(hhdm);
        for _ in 0..80 {
            wait_millis(50);
        }
        if !report_net_domain(hhdm) {
            println!("\x1b[91m    net domain     FAILED\x1b[0m");
        }
        // RFC 0018 step 6: a program that asks the network for an address,
        // holding **four capabilities and nothing else**.
        //
        // **Started here, and the position is load-bearing.** It was started
        // from inside `start_ip_domain`, which runs before `start_net_domain`
        // has spawned the driver — so the client came up before there was
        // anything to drive, and the boot never finished. `netd` was simply
        // absent from the thread dump.
        //
        // That is the third ordering bug in this subsystem in one day, all the
        // same shape: step 3's ring installed after its consumer had started,
        // step 5's capability installed before the service existed, and this.
        // Each time the symptom appeared somewhere other than the cause.
        // **And the fourth ordering bug, same shape, fixed by readiness
        // rather than by reordering.** A `Call` to a service that has not yet
        // reached its blocking receive queues the caller — correctly, that is
        // the rendezvous — but a boot cannot bound how long `ipd`'s
        // demonstration keeps it from receiving, so the client's first bind
        // stranded on the boots where the demonstration ran short. The
        // service now reports the moment it is serving (state bit 3), and
        // the client is held back until it does: not a sleep, a condition.
        // Bounded, because a service that never serves must not hang the
        // boot; the client then strands exactly as before, and the report
        // says which happened. Bounded at five seconds for the same
        // suite-timeout arithmetic as the demonstration wait below.
        if NET_CONTAINED.load(core::sync::atomic::Ordering::Acquire) {
            for _ in 0..50u32 {
                let raw = NET_RING_REPORT.load(core::sync::atomic::Ordering::Acquire);
                if raw == u64::MAX {
                    break;
                }
                let Some((pages, count)) = shared::frames_of(shared::MemoryId::from_u64(raw))
                else {
                    break;
                };
                if count == 0 {
                    break;
                }
                // SAFETY: a frame this object owns, through the direct map.
                let (marker, state) = unsafe {
                    (
                        core::ptr::read_volatile((hhdm + pages[0]) as *const u64),
                        core::ptr::read_volatile((hhdm + pages[0] + 56) as *const u64),
                    )
                };
                if marker == IPD_MARKER && state & (1 << 3) != 0 {
                    break;
                }
                wait_millis(100);
            }
        }
        if let Some(endpoint) = net_service_endpoint()
            && let Err(reason) = start_dhcp_client(cpu, hhdm, net_keeper(), endpoint)
        {
            println!("\x1b[91m    dhcp client    FAILED: {reason}\x1b[0m");
        }
        // RFC 0029 step 4's live proof, beside the v4 client it mirrors.
        if let Some(endpoint) = net_service_endpoint()
            && let Err(reason) = start_udp6_client(cpu, hhdm, net_keeper(), endpoint)
        {
            println!("\x1b[91m    udp6 client    FAILED: {reason}\x1b[0m");
        }

        if !report_net_ring(hhdm) {
            println!("\x1b[91m    net ring       FAILED\x1b[0m");
        }
        // **Time for the client to actually run**, which it was not given. It
        // was started ten lines above and read here, microseconds later, still
        // blocked in its first call — so the page held the "no network" it
        // writes before it asks anything, and the boot reported a refusal that
        // had not happened. The same mistake as reading the driver's report the
        // moment its marker appeared, noted forty lines up and repeated anyway.
        //
        // A `DISCOVER` goes out, a server answers, and the client asks for the
        // reply in a loop; the driver is asleep on its interrupt between those,
        // so it is woken here for the same reason as above.
        //
        // **Every pass rather than every tenth**, and that is the difference
        // between an offer arriving and not. The driver handed the offer across
        // half a second after it reached the wire, because half a second is how
        // often this poke used to happen — and by then `bin/dhcp` had asked
        // twenty thousand times and stopped. `bin/ipd` drains the ring only
        // when a client asks, so a frame that crosses after the last ask sits
        // there: the counters said twelve handed across and eleven taken, which
        // is the gap stated exactly.
        for _ in 0..80 {
            wait_millis(50);
        }
        // The client needs the service to be serving, which happens after its
        // own demonstration finishes, so this is read last of all.
        if !report_dhcp_client(hhdm) {
            println!("\x1b[91m    dhcp client    FAILED\x1b[0m");
        }
        if !report_udp6_client(hhdm) {
            println!("\x1b[91m    udp6 client    FAILED\x1b[0m");
        }
        report_net_after_exchange(hhdm);
    }

    // RFC 0026 steps 3 and 4, on every boot networked or not: the grant,
    // the marked probes, and the reader — the round trip that makes the
    // telemetry plane's counters somebody's rather than nobody's.
    match start_traced(hhdm) {
        Ok(()) => report_traced(hhdm),
        Err(why) => println!("\x1b[91m    traced         FAILED: {why}\x1b[0m"),
    }

    // The network, at slot 16, and only if there is one. **A program either
    // holds this or cannot name the network at all** — RFC 0018 step 5's whole
    // claim, and the thing `bin/probe` demonstrates by not having it.
    //
    // **Installed here rather than with the shell's other capabilities**, and
    // that is the whole of a bug: the rest are installed two hundred lines
    // above, before `start_net_domain` has run, so the endpoint did not exist
    // yet and the slot stayed empty. The shell then reported that it held no
    // network — which is the *negative* half of step 5 working perfectly and
    // the positive half never being tested at all.
    //
    // The same shape as step 3's ring, which was installed after its consumer
    // had already started. A capability a program needs has to exist before the
    // program's space is finished with, and "before it is spawned" is the line
    // that matters: the shell is spawned below.
    // **Not fatal, and that is the correction.** This returned `Err` when the
    // capability would not install, which fails the *whole* of `user_shell` —
    // so the machine fell back to the kernel shell and thirty-eight assertions
    // in unrelated subsystems went red because networking could not be wired.
    //
    // A shell that cannot be given a network is still a shell. It reports what
    // it has and carries on, which is what every other optional capability here
    // already does: the block registers at slot 5 are installed "only if there
    // *is* a device, so a machine booted without one still gets a shell".
    //
    // The same lesson as the bulk path's timing assertion, arriving from
    // another direction: a check that turns a small local failure into a broad
    // unrelated one is worse than the failure it reports.
    // **And the same for the Linux adapter** — RFC 0005 step 9, Tier 2's
    // prerequisite. Until now `bin/linuxd` held a console, a read-only
    // directory and its own endpoint; a hosted program calling `socket()` had
    // nothing behind it, and the arithmetic for one has been sitting in
    // `personality::socket` since 2026-08-19 with nothing to wire it to.
    //
    // **This widens what a compromise of the adapter reaches, and that is
    // recorded rather than absorbed.** `security.md` §1 T11's note enumerates
    // what the adapter holds; the network now belongs on that list.
    // [RFC 0031](../../docs/rfc/0031-linux-compatibility-as-an-adapter.md)'s
    // interface **I5** says an adapter should host *one workload's* process
    // group rather than being a system service every Linux process shares —
    // and one system-wide `bin/linuxd` already contradicts that. Adding the
    // network makes the drift larger, deliberately and with the project lead's
    // decision behind it: the alternative is per-hosted-process authority from
    // a manifest, which is an RFC and a supervisor change before any socket
    // works at all.
    //
    // **Slot 88, and not 16 like the shell's, and not 2 either.** This
    // adapter's CSpace is far fuller than the shell's: 0 and 1 are its
    // endpoint and report, 2 is the page faults are handed over in, 3 is the
    // console, **4 through 19 are its sixteen futex wakes**, 20 to 23 are the
    // supervisor control, the child handle, the root directory and the lent
    // page, hosted domains are allocated upward from 24 and open files
    // downward from 127. What is left is 88 to 95.
    //
    // Two attempts were refused before this one -- 16, taken by a futex wake,
    // and 2, taken by the fault page -- and both were refused by `install_at`
    // rather than silently overwriting something a hosted thread depends on.
    // That is the check earning its place: the failure was a boot line naming
    // the problem, not a lost wakeup found weeks later.
    let adapter = syscall::ADAPTER_DOMAIN.load(core::sync::atomic::Ordering::Relaxed);
    if adapter != u32::MAX {
        match network_endpoint_capability() {
            Some(network)
                if domain::with(domain::DomainId::from_u32(adapter), |owner| {
                    owner.cspace.install_at(88, network).is_ok()
                }) == Some(true) =>
            {
                println!(
                    "    linux domain   holds a network now: a hosted program's socket reaches \
                     bin/ipd, and the adapter's authority grew to match (RFC 0031 I5)"
                )
            }
            Some(_) => println!(
                "\x1b[93m    linux domain   the network capability would not install; hosted \
                 programs have no sockets\x1b[0m"
            ),
            None => println!(
                "    linux domain   no protocol service on this machine, so hosted programs get \
                 no sockets"
            ),
        }

        // **And a page for the datagrams themselves, at slot 89.** `SEND_TO`
        // reads its payload with `DRAIN` from *offset zero* of a memory object
        // the caller names, so the adapter needs one of its own: the report
        // page it already holds begins with the `mmap` trace records, and
        // using it would have a hosted `sendto` overwrite them.
        let owner = domain::DomainId::from_u32(adapter);
        match shared::create(owner, bhaskix_mm::FRAME_SIZE)
            .ok()
            .and_then(|page| shared::name(page).ok())
        {
            Some(named)
                if domain::with(owner, |domain| domain.cspace.install_at(89, named).is_ok())
                    == Some(true) => {}
            _ => println!(
                "\x1b[93m    linux domain   no page for datagrams; hosted sockets will not \
                 carry bytes\x1b[0m"
            ),
        }
    }

    match network_endpoint_capability() {
        Some(network)
            if domain::with(realm, |owner| owner.cspace.install_at(16, network).is_ok())
                == Some(true) =>
        {
            println!("    shell network  the shell holds a capability to the protocol service")
        }
        Some(_) => println!(
            "\x1b[93m    shell network  the capability would not install; this shell has no \
             network\x1b[0m"
        ),
        None => println!(
            "    shell network  none: there is no protocol service for the shell to be given"
        ),
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

            // **And one for the Linux adapter** — RFC 0033 step 6, at slot 22
            // of a domain that has been running since before the filesystem
            // existed. Installed into a live CSpace, which is the same thing
            // the kernel does when it hands the adapter a hosted domain's
            // handle: a capability may arrive at any time; what may not is a
            // program *asking* for one.
            //
            // The same directory the shell holds, `sub`, and deliberately not
            // the root: a hosted Linux process's `/` is a directory capability
            // the adapter was given, so it can open `inner` and cannot name
            // `greeting` one level up. That is `chroot` by construction rather
            // than by check, and it is the shape RFC 0031's interface I3
            // asks for.
            //
            // `READ` and `DERIVE`, no `WRITE`: this filesystem is readable to a
            // hosted program and not writable by one, which the personality
            // reports as `EROFS` rather than pretending.
            let adapter = syscall::ADAPTER_DOMAIN.load(core::sync::atomic::Ordering::Relaxed);
            if adapter != u32::MAX {
                let handle = cap::with_arena(|arena| {
                    let root = arena
                        .insert_root(
                            cap::ObjectRef::new(cap::ObjectKind::Endpoint, raw),
                            cap::Rights::ALL,
                            0,
                        )
                        .ok()?;
                    arena
                        .derive(
                            root,
                            cap::Rights::READ.union(cap::Rights::DERIVE),
                            FS_DIRECTORY.load(core::sync::atomic::Ordering::Acquire),
                        )
                        .ok()
                });
                match handle {
                    Some(handle) => {
                        if domain::with(domain::DomainId::from_u32(adapter), |owner| {
                            owner.cspace.install_at(22, handle).is_ok()
                        }) == Some(true)
                        {
                            // Said out loud, because a grant that silently did
                            // not happen is indistinguishable from a hosted
                            // program that cannot find a file -- which is
                            // exactly the boot this line was added after.
                            println!(
                                "    linux domain   holds a directory now: hosted programs can \
                                 open what is inside it and name nothing above it"
                            );
                        } else {
                            println!(
                                "\x1b[93m    linux domain   the directory would not install; \
                                 hosted programs will find no files\x1b[0m"
                            );
                        }
                    }
                    None => println!(
                        "\x1b[93m    linux domain   no directory capability could be made\x1b[0m"
                    ),
                }
            }

            // RFC 0030 step 3: the shell's one *writable* directory, at slot
            // 20 -- `/pkg`, whose handle the filesystem service reported and
            // whose writable bit this mint is the only source of. Narrow on
            // purpose: the shell can change what is under /pkg and nothing
            // above it, because it holds nothing that names anything above
            // it. Absent (zero) means the service could not make the
            // directory, and the shell simply holds no writable handle --
            // `pkg install` then refuses with the slot empty, which is the
            // honest state rather than a forged one.
            let pkg = FS_PKG.load(core::sync::atomic::Ordering::Acquire);
            if pkg != 0 {
                let handle = cap::with_arena(|arena| {
                    let root = arena
                        .insert_root(
                            cap::ObjectRef::new(cap::ObjectKind::Endpoint, raw),
                            cap::Rights::ALL,
                            0,
                        )
                        .ok()?;
                    arena
                        .derive(root, cap::Rights::READ.union(cap::Rights::DERIVE), pkg)
                        .ok()
                })
                .ok_or("the pkg directory capability would not be created")?;
                if domain::with(realm, |owner| owner.cspace.install_at(20, handle).is_ok())
                    != Some(true)
                {
                    return Err("the pkg directory capability would not install");
                }
            }
        }
    }

    // RFC 0030 step 3: sixteen pages the shell stages a package archive in
    // -- read out of the initrd through the vfs, verified in place with the
    // same parser the host tools use, and drained from by the filesystem
    // service one page at a time. At slot 21, mapped where the shell says.
    {
        let staging = shared::create(realm, 16 * bhaskix_mm::FRAME_SIZE)
            .map_err(|_| "the shell's package staging memory would not be created")?;
        let named = shared::name(staging).map_err(|_| "the staging memory would not be named")?;
        if domain::with(realm, |owner| owner.cspace.install_at(21, named).is_ok()) != Some(true) {
            return Err("the staging memory would not install");
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
        "    address spaces {} of {} in use at once, each program in its own ({} free)",
        vm::peak(),
        vm::MAX_SPACES,
        vm::MAX_SPACES.saturating_sub(vm::peak())
    );
    // Occupied rather than live, and the distinction is the whole point: a
    // domain that has ended keeps its slot until somebody reaps it, so this is
    // the number that decides whether `create` succeeds. Until this line the
    // table was sized by raising it whenever something failed — twice in one
    // day, and the second failure landed in a self-test with nothing to do
    // with the change that caused it.
    println!(
        "    domains        {} of {} slots occupied at once (a slot is held until reaped)",
        domain::peak_occupied(),
        domain::MAX_DOMAINS
    );
    println!(
        "    memory objects {} of {} live at once",
        shared::peak_live(),
        shared::MAX_OBJECTS
    );
    // **The bill for the four fixed tables, printed rather than estimated** —
    // RFC 0033 step 3. Each was raised because L1 walks into it: five
    // concurrent hosted processes was the machine's ceiling, and a hosted
    // process is a domain with an address space, a CSpace full of descriptors
    // and a capability in the arena for each one. What it cost is arithmetic,
    // and arithmetic belongs in the log rather than in a paragraph nobody can
    // check.
    //
    // Sizes, not counts: `size_of` is the honest measure of a static table,
    // and it moves when a field is added to what the table holds -- which is
    // the change most likely to make one of these expensive without anybody
    // noticing.
    println!(
        "    fixed tables   spaces {} x {}B, domains {} x {}B, cspace {} slots, arena {} x {}B \
         -- {} KiB of static kernel memory",
        vm::MAX_SPACES,
        core::mem::size_of::<Option<vm::AddressSpace>>(),
        domain::MAX_DOMAINS,
        domain::size_of_domain(),
        cap::CSPACE_SLOTS,
        cap::MAX_CAPABILITIES,
        cap::size_of_node(),
        (vm::MAX_SPACES * core::mem::size_of::<Option<vm::AddressSpace>>()
            + domain::MAX_DOMAINS * domain::size_of_domain()
            + cap::MAX_CAPABILITIES * cap::size_of_node())
            / 1024
    );
    // What the boot report itself cost, and whether all of it survived. RFC
    // 0042: this record is what makes a machine whose report scrolls off a
    // framebuffer diagnosable at all, and a record that quietly stopped would
    // take the diagnosis with it.
    {
        let (kept, refused) = console::recorded();
        if refused == 0 {
            println!(
                "    boot record    {kept} bytes kept of {} KiB, all of it -- readable back",
                console::RECORDED_BYTES / 1024
            );
        } else {
            println!(
                "\x1b[93m    boot record    {kept} bytes kept of {} KiB and {refused} REFUSED: \
                 the record is truncated and the earliest lines are the ones it kept\x1b[0m",
                console::RECORDED_BYTES / 1024
            );
        }
    }
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
    // What arming a deadline did to the hardware, reported on every boot rather
    // than only under `timers=measure`.
    //
    // Both halves are needed and the second is the one that would go wrong
    // quietly. Moves alone cannot distinguish "deadlines are being honoured"
    // from "every arming re-programs the timer whether or not it needs to",
    // which would be a program's way of taking a processor's timer away from
    // the scheduler. A healthy machine does some of each.
    let (hastened, already) = time::hastened();
    println!(
        "    deadline arms  {hastened} brought this cpu's next interrupt forward, {already} were \
         already soon enough"
    );

    let (leaks, first_leak) = sched::hold_leaks();
    if leaks > 0 {
        println!(
            "\x1b[91m    hold leaks     {} syscalls returned to ring 3 with a nonzero hold \
             count; the first was kind {} method {}\x1b[0m",
            leaks,
            first_leak >> 32,
            first_leak & 0xffff_ffff,
        );
    }

    // The worst any lock rank was ever held, with the line that held it —
    // the permanent form of the question every stall capture asked. Ranks
    // that never crossed a tenth of a millisecond are left off the line:
    // contention answers should name suspects, not list the innocent.
    {
        let names = [
            "address-space",
            "space-previous",
            "dma-window",
            "heap",
            "tlb-sender",
            "timers",
            "domains",
            "capabilities",
            "endpoints",
            "wait-queue",
            "runqueue",
            "notifications",
            "shared-memory",
            "irq-handlers",
            "vectors",
            "block",
            "console",
        ];
        let hold_hertz = bhaskix_arch::tsc::hertz().unwrap_or(0);
        if hold_hertz != 0 {
            let mut printed = false;
            for (rank, name) in names.iter().enumerate() {
                let (cycles, at) = crate::sync::longest_hold(rank);
                let micros = (u128::from(cycles) * 1_000_000 / u128::from(hold_hertz)) as u64;
                if micros >= 100 {
                    if !printed {
                        println!("    longest holds  ranks held past a tenth of a millisecond:");
                        printed = true;
                    }
                    if let Some(at) = at {
                        println!(
                            "                   {name} {micros} us, by {}:{}",
                            at.file(),
                            at.line(),
                        );
                    }
                }
            }
            if !printed {
                println!(
                    "    longest holds  no lock rank was ever held past a tenth of a millisecond"
                );
            }
        }
    }

    // The scheduler's share of a wake's latency, measured because RFC 0023
    // priced a wake-driven wait above a poll and the schedule's own gap is
    // the first suspect to convict or clear. Stamped by the waker, read at
    // dispatch; the mean says what the path usually costs, and the worst
    // says what it can cost.
    let (wakes, wake_cycles, wake_worst) = sched::wake_to_run();
    let wake_hertz = bhaskix_arch::tsc::hertz().unwrap_or(0);
    if wakes > 0 && wake_hertz != 0 {
        let micros = |ticks: u64| (u128::from(ticks) * 1_000_000 / u128::from(wake_hertz)) as u64;
        // **The worst is printed with the thread it happened to, on the same
        // line, and that is not decoration.** Every boot of 2026-08-21 reported
        // a worst case of about 8.027 seconds — healthy boots and failing ones
        // alike, varying by under two milliseconds between them — and a worst
        // case that is the same constant on every run is measuring something
        // other than what it claims. It was read for a day as evidence of a
        // scheduling stall.
        //
        // It is thread 3, `boot`: this thread, waiting through bring-up while
        // the self-tests run on the same CPU. A real delay, and an entirely
        // expected one, and it swamps the statistic — the bucket comment beside
        // `WAKE_TO_RUN_BUCKETS` already said the distribution "has bring-up in
        // it" and gave the median as the number to trust.
        //
        // So the name travels with the number. A reader who sees `(boot)` knows
        // immediately that the tail is the boot thread and not a service; a
        // reader who one day sees a different name has found something.
        let (worst_ticks, worst_thread) = sched::wake_to_run_worst();
        let worst_name = sched::describe(worst_thread).map_or("?", |(name, _)| name);
        println!(
            "    wake to run    {} wakes; p50 {} us, p99 {} us, mean {} us; worst {} us was \
             thread {worst_thread} ({worst_name}), from marked ready to dispatched",
            wakes,
            micros(sched::wake_to_run_percentile(50)),
            micros(sched::wake_to_run_percentile(99)),
            micros(wake_cycles / wakes),
            micros(worst_ticks.max(wake_worst)),
        );
    }

    // RFC 0019 step 4, the second half: the same measurement on a machine with
    // its services running. The first ran during bring-up, where a tickless
    // CPU can be silent for most of a second; this one is the machine every
    // caller of a deadline actually meets.
    if !measure_deadlines(handoff, "services up") {
        println!("\x1b[91m    timer delay    FAILED\x1b[0m");
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

    // **The file probe, here and not with the other Linux self-tests**, and the
    // reason is the order of the boot: the adapter's directory capability is
    // granted a few lines above this, because the filesystem service does not
    // exist when the adapter starts. A hosted program that opens a file has to
    // run after that, so it runs here — before the shell, which is what every
    // other check placed late does, so that nothing is still printing when the
    // shell begins.
    // RFC 0044, before the file probes: it is the mechanism they now depend on,
    // and a failure here explains a failure there rather than the other way
    // round.
    if !lending_self_test(hhdm) {
        println!("\x1b[91m    lending        FAILED\x1b[0m");
    }
    if !file_self_test(hhdm, bhaskix_arch::percpu::online_count()) {
        println!("\x1b[91m    linux file     FAILED\x1b[0m");
    }
    // And RFC 0005 step 8's, immediately after, for the same reason: it needs
    // the same directory and the same second CPU.
    //
    // **The order is load-bearing and stays this way.** This probe's `read` is
    // the *second* on the machine, and the second one is what found the slot
    // leak in `DELETE`: `bin/fsd` revokes the page it lent, and until
    // 2026-08-23 the borrower could never clear the slot it landed in. Run
    // this probe first and both still pass -- and the bug comes back unseen.
    if !list_self_test(hhdm, bhaskix_arch::percpu::online_count()) {
        println!("\x1b[91m    linux dir      FAILED\x1b[0m");
    }
    // **After both probes, and that is the whole reason it is here** rather
    // than with the other personality reports in `kernel_main`: those run
    // before this bring-up thread has started a hosted program, so the record
    // they would read is empty. The first version of this line was up there
    // and printed nothing, which the gate caught immediately.
    report_lending_cost();

    // RFC 0005 step 9, after the file probes because it needs the same second
    // CPU and because a failure here should not be read as a filesystem
    // problem.
    if !socket_self_test(hhdm, bhaskix_arch::percpu::online_count()) {
        println!("\x1b[91m    linux socket   FAILED\x1b[0m");
    }

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
    // **The ratio is reported and no longer asserted**, and the sentence that
    // used to be here is why it had to change. It said a factor of two "fails
    // when the bulk path has stopped being one and not when the builder is
    // busy", and that turned out to be exactly backwards: measured against
    // eight to ten on an idle machine, it fell to 1.74 with three fuzz
    // campaigns holding three of eight cores, and the gate went red three times
    // in one day in a subsystem unrelated to whatever was being changed.
    //
    // Worse than the noise, it misdirected. A red bulk path sent one
    // investigation into the domain table and produced a wrong diagnosis that
    // reached the remote before it was caught. A gate whose answer depends on
    // how busy the machine is cannot distinguish a regression from a neighbour,
    // and this project has a name for that: it is a check that is not looking
    // at the thing it claims to check.
    //
    // What survives is the measurement. The numbers are printed on every boot,
    // where a person or a soak can watch them move; a ratio that collapses is
    // then a question somebody asks, rather than a build that fails for a
    // reason nobody trusts. Asserting a *timing* needs an idle machine, and a
    // boot test does not get one.
    let shared_cycles = BULK_CYCLES.load(Ordering::Relaxed);
    let message_cycles = MESSAGE_CYCLES.load(Ordering::Relaxed);
    // Still asserted, because it is not a timing: a zero means the measurement
    // never happened, which is a broken test rather than a slow machine.
    let measured = shared_cycles > 0 && message_cycles > 0;

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
        && measured;
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
        // **Not a failure, and it used to be one.** This test grants a domain a
        // window for a device the kernel drives, and the only device it knows
        // how to ask for is virtio. A machine without one -- every real server
        // so far -- reported `iommu grant FAILED` on every boot, which says
        // "broken" about a true fact.
        //
        // It also **leaked the domain**: this arm returned before
        // `domain::destroy(owner)`, so a machine with no virtio device lost one
        // per boot. Two bugs on one line, both invisible to an emulator that
        // always has the device.
        println!(
            "    iommu grant    not asked: no virtio device on this machine to grant a window for"
        );
        domain::destroy(owner);
        return true;
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
        // A self-test maps on nobody's behalf; the owner domain names it.
        owner.as_u32(),
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
        // A self-test maps on nobody's behalf; the owner domain names it.
        owner.as_u32(),
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
        // As the grant test above: no virtio device is a fact about the
        // machine, not a fault in it. This arm at least cleaned up.
        println!(
            "    iommu memory   not asked: no virtio device on this machine to map memory for"
        );
        domain::destroy(owner);
        return true;
    };
    let Some(address) = iommu::map_memory(
        device,
        object,
        bhaskix_arch::vtd::Rights::READ_WRITE,
        false,
        hhdm,
        // A self-test maps on nobody's behalf; the owner domain names it.
        owner.as_u32(),
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

    // **The first device is whatever this kernel can drive, not whatever is
    // virtio.**
    //
    // This read `virtio::probe()?` until 2026-08-24, and that `?` is why the
    // SR550 has four working remapping units with none of them programmed:
    // bring-up returned before touching a register, because a real server has
    // no virtio device. `security.md` recorded it as *"`iommu_bringup`
    // sequences itself after `virtio::probe()` and no real server has a virtio
    // block device"* -- a sentence that describes a defect and reads like an
    // explanation.
    //
    // The first device is special only because reserved regions and the tables
    // are built alongside it; *which* device it is has never mattered. So:
    // virtio where there is one, so every existing lane keeps the machine it
    // had, and otherwise the AHCI controller -- which on that server is a real
    // bus master this kernel drives (RFC 0046). A machine with neither still
    // returns, because there is nothing to build tables around.
    //
    // SAFETY: configuration access works by here, and `ahci::probe` only reads
    // configuration space on functions the bus walk found present.
    let first = virtio::probe().or_else(|| unsafe { ahci::probe() });
    let Some(device) = first else {
        // **Said, not returned silently.** Bring-up returning with no line at
        // all is what made an SR550 boot on 2026-08-24 unreadable: the report
        // showed the units found and then nothing, and the only way to learn
        // where it stopped was another reboot of a live server. There is no
        // first device to build tables around, and that sentence is cheap.
        println!(
            "\x1b[93m    iommu          no device this kernel can drive to build tables around \
             (no virtio, no AHCI controller); the units stay unprogrammed\x1b[0m"
        );
        return None;
    };
    let first_device = device;
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

    // **Reset the delegated disk before translation exists at all.** The
    // firmware drove it looking for a boot sector and left its rings live at
    // physical addresses. The paragraph below already knows what that means at
    // the transition — one stray DMA, expected and cleared — but a live ring
    // is not one-shot: the device model can look at it again whenever it is
    // next poked, and the second look arrives mid-boot as an unowned fault at
    // an address whose appearance depends on image layout and nothing visible.
    // Found as `00:03.0 read 0xffd9000` the day RFC 0020's third domain
    // shifted the image; reason 0x06 with translation up, 0x02 when the reset
    // came after enable and the flush beat the context entry. Reset first,
    // and the firmware's configuration is gone before there is anything to
    // fault against. `bin/blkd` still does its own full reset when it claims
    // the device, exactly as before.
    if let Some((second, _)) = virtio::find_nth(1)
        && !virtio::quiesce_delegated(second, hhdm)
    {
        println!(
            "\x1b[93m    iommu          the delegated disk would not quiesce; the firmware's \
             rings may still be live behind the translation\x1b[0m"
        );
    }

    // **And the AHCI controller, for the same reason and with better cause.**
    // RFC 0046 step 2 gives it a window below, and of every endpoint on this
    // bus it is the one the firmware is most likely to have driven: it looks
    // for a boot sector on a SATA disk, and it does not tidy up afterwards.
    // The controller keeps the firmware's command list, at physical addresses
    // chosen when nothing was translating.
    //
    // Clearing bus mastering is the whole of it -- no BAR, no driver, no
    // register layout -- and it reaches the device even if this kernel turns
    // out never to drive it. Step 3's bring-up sets the bit again as its first
    // act, so this costs the ordering and nothing else.
    //
    // The probe is hoisted out of the `if let` rather than written inside its
    // condition. That began as an appeasement -- `tools/check-unsafe-budget.py`
    // was a line scanner that read `if let Some(x) = unsafe { f() } {` as one
    // brace deep and charged the whole body to the budget, 46 lines here for
    // three configuration reads and one write. **That was a defect in the
    // instrument and was fixed on 2026-08-24**, so the shape is no longer
    // required; it stays because a named binding reads better than a condition
    // with a bus walk inside it, which is a reason that does not depend on a
    // tool.
    //
    // SAFETY: configuration access works, and nothing in this kernel drives
    // this controller -- there is no driver for it to interrupt.
    let ahci_controller = unsafe { ahci::probe() };
    if let Some((bus, device, function)) = ahci_controller {
        // SAFETY: as above. One configuration write, clearing one bit.
        unsafe {
            bhaskix_arch::pci::quiesce(bhaskix_arch::pci::Address::new(bus, device, function));
        }
    }

    // **And the kernel's own disk, which until 2026-08-24 was the one endpoint
    // on this bus nobody quiesced.**
    //
    // `virtio::quiesce` was written for exactly this and **had no caller since
    // the day it was written** -- invisible to the compiler because a `pub fn`
    // in a library crate is never dead code as far as the lint is concerned.
    // TRACKER recorded it as harmless on the grounds that `init_mapped` resets
    // this device anyway. It does, and that is not sufficient: `init_mapped`
    // runs *after* `iommu::enable` below, and its own comment says why that
    // matters -- it withholds bus mastering until the device has been reset,
    // precisely so the device cannot touch memory "with the ring firmware
    // configured, which with translation on is a fault nobody owns". What it
    // cannot do is clear bus mastering the *firmware* left set, which survives
    // from power-on, through `enable`, to that reset.
    //
    // On the emulator the firmware boots from the CD and has no reason to
    // master a virtio disk, which is why this has never faulted. A machine
    // that boots from one is a different machine, and this is the ordering the
    // other two devices above already get.
    virtio::quiesce();

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

    if !iommu::install(device, found, window) {
        println!(
            "\x1b[91m    iommu window   FAILED: the first device's window would not install\x1b[0m"
        );
    }
    println!(
        "    iommu window   {bus:02x}:{slot:02x}.{function} {}-bit, {} levels, \
         {reserved} reserved pages mapped, {refused} refused",
        window.width.bits(),
        window.width.levels()
    );

    // **The device count these `verify_window` calls check against is computed,
    // not written down.** It is how many context entries this table should now
    // hold: everything already installed, plus the one being attached. They
    // were literals -- 2, 3, 4 -- which are correct only on a machine that has
    // every device before them. RFC 0041 step 7's `usb` profile has no network
    // device, so the controller is the third and not the fourth, and the
    // literal turned a correct window into "the tables did not read back".
    //
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
                if iommu::verify_window(&second_window, iommu::windows() + 1, hhdm)
                    && iommu::install(delegated, found, second_window)
                {
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

    // The network device, on the same terms and for the same reason. Its own
    // page table and its own domain id — the third — because a device that
    // *initiates* is the last one that should share a translation with
    // anything: an unsolicited frame arrives at a moment nobody chose, and a
    // shared page table would let it land wherever the sharer had mapped.
    if let Some((net, _)) = virtio::find_nth_of(virtio::Class::NET, 0) {
        let delegated = (net.bus, net.device, net.function);
        match iommu::attach_device(&window, delegated, 2, hhdm) {
            Some(net_window) => {
                if iommu::verify_window(&net_window, iommu::windows() + 1, hhdm)
                    && iommu::install(delegated, found, net_window)
                {
                    // SAFETY: the unit these windows are programmed into. The
                    // unit caches context entries, so without this it goes on
                    // believing this device has none and drops every request it
                    // makes with the entry sitting correct in memory.
                    let invalidated = unsafe { iommu::invalidate_contexts() };
                    if !invalidated {
                        println!(
                            "\x1b[91m    iommu window   FAILED: the context cache did not invalidate\x1b[0m"
                        );
                    }
                    println!(
                        "    iommu window   {:02x}:{:02x}.{} translating too, the network \
                         device's own page table and domain, {} in use",
                        delegated.0,
                        delegated.1,
                        delegated.2,
                        iommu::windows()
                    );
                } else {
                    println!(
                        "\x1b[91m    iommu window   FAILED: the network device's tables did not read back\x1b[0m"
                    );
                }
            }
            None => println!(
                "\x1b[91m    iommu window   FAILED: no page table for the network device\x1b[0m"
            ),
        }
    }

    // The **first** xHCI controller, on the same terms and for the fourth
    // domain id. RFC 0041 step 3: a controller is a bus master with unmediated
    // access to all of memory, so it gets a translation or it is not driven.
    //
    // Deliberately the first and only the first. A machine with two of them
    // leaves the second with no window, which is what keeps `xhci::report`'s
    // refusal a thing that can be watched happening rather than a claim -- and
    // `tests/qemu/devices.sh` puts a second one there for exactly that.
    //
    // SAFETY: configuration access works by here, and this reads config space
    // only.
    if let Some(controller) = unsafe { xhci::probe() } {
        match iommu::attach_device(&window, controller, 3, hhdm) {
            Some(controller_window) => {
                if iommu::verify_window(&controller_window, iommu::windows() + 1, hhdm)
                    && iommu::install(controller, found, controller_window)
                {
                    // SAFETY: the unit these windows are programmed into. The
                    // unit caches context entries, so without this it goes on
                    // believing this device has none and drops every request it
                    // makes with the entry sitting correct in memory.
                    let invalidated = unsafe { iommu::invalidate_contexts() };
                    if !invalidated {
                        println!(
                            "\x1b[91m    iommu window   FAILED: the context cache did not invalidate\x1b[0m"
                        );
                    }
                    println!(
                        "    iommu window   {:02x}:{:02x}.{} translating too, the xhci \
                         controller's own page table and domain, {} in use",
                        controller.0,
                        controller.1,
                        controller.2,
                        iommu::windows()
                    );
                } else {
                    println!(
                        "\x1b[91m    iommu window   FAILED: the xhci controller's tables did not read back\x1b[0m"
                    );
                }
            }
            None => println!(
                "\x1b[91m    iommu window   FAILED: no page table for the xhci controller\x1b[0m"
            ),
        }
    }

    // The **first** AHCI controller, on the same terms and for the fifth domain
    // id. RFC 0046 step 2: a SATA controller is a bus master, and RFC 0012's
    // rule is that a bus master is contained or it does not run -- which a
    // storage driver is the last place to make an exception to.
    //
    // `ahci::probe` answers only a controller presenting AHCI's registers, so a
    // vendor-specific SATA controller gets no window here and is refused by
    // name in `ahci::report` instead. Building a window for a controller this
    // kernel could never drive would contain it, which is not nothing -- but it
    // is RFC 0043's open question and not this step's to answer.
    //
    // This is also motivation 3 of RFC 0046 arriving: on the `iommu` lane
    // `00:1f.2` has been one of three endpoints with no driver, therefore no
    // window, therefore no containment. It becomes two.
    //
    // Answered above, before translation was enabled, and reused rather than
    // asked again: the bus has not changed and a second walk would only be a
    // second chance to disagree with the first.
    // Skipped when this controller *is* the first device, which happens on a
    // machine with no virtio: it already holds a window, domain 0, and the
    // reserved regions mapped into that page table. Attaching it again would
    // write its context entry a second time with a different domain and a
    // different page table, orphaning the one the reserved regions went into
    // -- and on the SR550 those regions are the BMC's, so that is a keyboard
    // that stops working.
    if let Some(controller) = ahci_controller.filter(|c| *c != first_device) {
        match iommu::attach_device(&window, controller, 4, hhdm) {
            Some(controller_window) => {
                if iommu::verify_window(&controller_window, iommu::windows() + 1, hhdm)
                    && iommu::install(controller, found, controller_window)
                {
                    // SAFETY: the unit these windows are programmed into. The
                    // unit caches context entries, so without this it goes on
                    // believing this device has none.
                    let invalidated = unsafe { iommu::invalidate_contexts() };
                    if !invalidated {
                        println!(
                            "\x1b[91m    iommu window   FAILED: the context cache did not invalidate\x1b[0m"
                        );
                    }
                    println!(
                        "    iommu window   {:02x}:{:02x}.{} translating too, the ahci \
                         controller's own page table and domain, {} in use",
                        controller.0,
                        controller.1,
                        controller.2,
                        iommu::windows()
                    );
                } else {
                    println!(
                        "\x1b[91m    iommu window   FAILED: the ahci controller's tables did not read back\x1b[0m"
                    );
                }
            }
            None => println!(
                "\x1b[91m    iommu window   FAILED: no page table for the ahci controller\x1b[0m"
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

    // The line exists now, so the adapter can be given the means to *wait* on
    // it -- RFC 0054 step 3, and it could not have been given it any earlier.
    // **Said out loud either way.** A grant that silently did not happen is
    // indistinguishable from a hosted program that cannot read its input --
    // which is exactly the boot this line was added after: the slot collided
    // with the root directory, the install failed, and the only symptom was a
    // shell that exited without reading.
    match grant_console_wake() {
        Ok(slot) => println!(
            "    console wake   the adapter holds it at slot {slot}, read-only: it may park a \
             hosted reader on the console and cannot signal it"
        ),
        Err(reason) => println!("\x1b[91m    console wake   FAILED: {reason}\x1b[0m"),
    }

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

    // The keyboard, if this machine has one. RFC 0037.
    //
    // Absence is a state, not a failure: every machine this has ever booted on
    // is reachable over serial, and the laptops this exists for are the ones
    // where it is the only way in. Reported either way, because "no keyboard"
    // is the single most useful line in the log for whoever is standing at
    // that laptop.
    if let Some(notification) = input::notification() {
        // SAFETY: called once, here, with the interrupt controller up and the
        // console's notification already created.
        match unsafe { keyboard::install(handoff.bsp_lapic_id, handoff.rsdp, hhdm, notification) } {
            Ok(keyboard_vector) => println!(
                "    keyboard       i8042 present, irq {} -> vector {keyboard_vector:#04x}",
                keyboard::KEYBOARD_IRQ
            ),
            Err(reason) => println!(
                "\x1b[93m    keyboard       none ({reason}); this machine can only be typed at over serial\x1b[0m"
            ),
        }

        // The USB keyboard, if step 6 configured one. RFC 0041 step 7.
        //
        // SAFETY: called once, here, with the interrupt controller up and the
        // console's notification already created.
        match unsafe {
            xhci::install_interrupt(handoff.bsp_lapic_id, handoff.rsdp, hhdm, notification)
        } {
            Ok(usb_vector) => {
                println!(
                    "    usb keyboard   reading reports, msi-x entry 0 -> vector {usb_vector:#04x}"
                );
                // **RFC 0041's unresolved question 2, answered out loud.**
                // "A machine with both should probably say so at boot rather
                // than silently preferring one." Both exist here, and which one
                // a keystroke reaches is decided by the *emulator or the
                // firmware*, not by this kernel -- on QEMU a key goes to the USB
                // keyboard and the i8042 never sees it. Both are serviced, so
                // either works; what a person needs to know is that a key
                // arriving at one is not evidence the other is alive.
                if keyboard::present() {
                    println!(
                        "\x1b[93m    input sources  two keyboards on this machine (i8042 and USB) \
                         plus serial; all three are read, and which one a keystroke reaches is not \
                         this kernel's choice -- a key arriving proves one of them works, not \
                         both\x1b[0m"
                    );
                }
            }
            // Not a failure worth colouring: a machine with no USB keyboard is
            // the ordinary case, and step 6 already said why there is none.
            Err(reason) => println!("    usb keyboard   none ({reason})"),
        }
    }
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

    // **Drain the devices as well as the rings, and *then* take the
    // baselines.**
    //
    // This used to drain `input::try_read()` alone — the rings — and leave the
    // hardware behind them holding whatever it held. `input::service()` below
    // pulls from **three** sources at once (the UART, the i8042 keyboard and a
    // USB one), so anything already sitting in any of them arrives counted as
    // this test's own bytes.
    //
    // **This did not fix the SR550's `14 of 5 bytes`, and the comment says so
    // rather than implying otherwise.** The reasoning above is sound as far as
    // it goes — `service()` really does pull from three sources, and draining
    // only the rings really did leave the devices behind them full — but a boot
    // on 2026-08-26 with this in place reported the identical `14 of 5 bytes,
    // 1 interrupts, 0 of 15 commands wrong`. So whatever those nine extra bytes
    // are, they were **not already waiting** when the test began.
    //
    // The surviving explanation is that they arrive *during* the window. This
    // function puts `COM1` into loopback and then waits up to 500 units for an
    // interrupt, and the console is shared: anything another CPU prints in that
    // window goes out of `COM1` and comes straight back in. The `set_loopback`
    // call below already carries the warning — *"this must happen before
    // anything is printed"* — and on sixteen processors there is far more
    // running concurrently than on the four QEMU gives.
    //
    // Kept anyway, because draining the devices first is correct on its own
    // terms and removes one real source of noise. It is simply not the source
    // that mattered here.
    //
    // The baselines move after the drain rather than before it, so counters
    // disturbed by draining cannot be charged to the test.
    for _ in 0..8 {
        input::service();
        if input::try_read().is_none() && !input::pending() {
            break;
        }
        while input::try_read().is_some() {}
    }

    let (delivered_before, _, _) = irq::statistics();
    let (signals_before, _, _) = notify::statistics();

    // **The console is held for the whole window, and that is the fix for the
    // SR550's `14 of 5 bytes`.**
    //
    // This function's own comment has always said *"nothing is printed while
    // the port is looped back"*, and until 2026-08-27 nothing enforced it. The
    // console's serial sink is this very port: anything another CPU printed
    // here went out of `COM1` and came straight back in, and was counted as a
    // byte this test had typed. On QEMU's four processors nothing happened to
    // print in the window; on sixteen, something did, every boot.
    //
    // Holding rather than suppressing: other CPUs wait and then print, so no
    // line is lost. Nothing inside the window may print -- see
    // `console::with_output_held` -- and nothing here does: writing a byte is
    // port I/O, and `wait_until` spins on an atomic.
    let arrived = console::with_output_held(|| {
        // SAFETY: COM1 is initialised, and the port is put back below on every
        // path out of this closure.
        unsafe { port.set_loopback(true) };
        for byte in TYPED {
            // SAFETY: as above.
            unsafe { port.write_byte(*byte) };
        }

        // Wait for the *interrupt*, not for the bytes. Since RFC 0011 the
        // handler does one thing -- mask the source and signal a notification
        // -- so nothing reaches the ring until a reader drains the UART.
        // Waiting on the ring here would be waiting for work this test has not
        // done yet.
        let arrived = wait_until(|| irq::statistics().0 > delivered_before, 500);
        // SAFETY: as above. It must happen before anything is printed, and now
        // it provably does: nothing else can print until this closure returns.
        unsafe { port.set_loopback(false) };
        arrived
    });

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
        (shell::run(b"readelf bin/probe"), shell::Outcome::Ran),
        (shell::run(b"readelf hello.txt"), shell::Outcome::Failed),
        (shell::run(b"free"), shell::Outcome::Ran),
        (shell::run(b"ps"), shell::Outcome::Ran),
        (shell::run(b"uptime"), shell::Outcome::Ran),
        (shell::run(b"input"), shell::Outcome::Ran),
        (shell::run(b"lsblk"), shell::Outcome::Ran),
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
            // Thirteen programs in /bin: the ring 3 probe, the user-mode
            // shell, both services as programs, the block driver (RFC 0013
            // steps 3, 4 and 6), the filesystem (RFC 0016 step 3), the
            // supervisor (RFC 0017 question 2), the network driver and the
            // protocol service (RFC 0018 steps 2 and 3), the DHCP client
            // (step 6), the TCP service (RFC 0020 step 4), the TCP
            // demonstration client (RFC 0022 step 4), and the telemetry
            // reader (RFC 0026 steps 3-4). Exact rather
            // than "at least", so adding a fourteenth without noticing this
            // line is a failure rather than a silently weaker test -- which
            // it has now been for every program added, most recently
            // `bin/go-hello` -- RFC 0005 step 7's Tier 0 corpus program,
            // and the first entry here that is not ours at all: a real
            // static Go binary, built by whatever toolchain the machine
            // has. Sixteen now -- `bin/linuxd` joined 2026-08-19 -- and this
            // line caught each of them as designed, exactly as it caught
            // `bin/traced`, `bin/tcpc` and `bin/tcpd` before them.
            // **Seventeen** as of 2026-08-24 -- `bin/ahcid`, RFC 0046 step 3b's
            // AHCI driver -- and it caught that one too, on the first boot.
            // **Eighteen** as of 2026-08-27: `bin/busybox`, the L1 corpus, and
            // the first entry here that nobody in this project wrote *or*
            // built -- the Go corpus is compiled from a source file in
            // `corpus/`, and this is somebody else's shipped binary. It caught
            // that one on the first boot too, which is eighteen for eighteen.
            "a listing shows what is directly under a directory",
            entries >= 3 && bin == 18,
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
    // The people the author wanted named where a person actually looks, which
    // is the screen in front of them rather than a file in the repository.
    // `CREDITS.md` says the same thing at length; this says it at boot.
    println!(
        "{DIM}     With thanks to                  {OFF}{TEXT}Professor Pawan Kumar Mall{OFF}"
    );
    println!(
        "{DIM}                                     {OFF}{TEXT}Prince Komal Boonlia · Mayur Agnihotri{OFF}"
    );
    println!(
        "{DIM}                                     {OFF}{TEXT}Devesh Singh · Neha Mourya{OFF}"
    );
    println!("{DIM}                                     {OFF}{TEXT}the StraightArc Team{OFF}");
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
        "                   umip {}  la57 {}  invariant-tsc {}  rdrand {}",
        mark(f.umip),
        mark(f.la57),
        mark(f.invariant_tsc),
        mark(f.rdrand)
    );
    // Capability beside choice (RFC 0025): the line above says what the CPU
    // can do; this one says what this kernel does, so a log reader never
    // infers the second from the first's silence.
    println!("    paging         4-level, on purpose; la57 stays a capability, not a mode");
    // **RFC 0021.** Said in words as well as in the table, because this one is
    // not a degraded guarantee — it is the difference between the machine being
    // able to be unpredictable at all and not. An operator reading `rdrand  NO`
    // in a row of yeses would have to know what depends on it; this says.
    if !f.rdrand {
        println!(
            "\x1b[93m    unpredictable  NO: this machine has no source of randomness, so anything \
             needing one refuses rather than guessing\x1b[0m"
        );
        return;
    }

    // **RFC 0021, and the half the host tests cannot reach.** They drive the
    // retry logic through a stub, which proves the decisions and nothing about
    // the instruction: whether `rdrand` and its `setc` assemble, execute, and
    // report a usable answer in *this* build, on *this* machine, in ring 0.
    //
    // Two draws, because one proves only that something was returned. Equal
    // draws are the exact signature of the failure this crate is built around —
    // a carry flag ignored on a part that leaves the register alone — so they
    // are a failure here rather than an improbability worth shrugging at.
    match (bhaskix_rand::u64(), bhaskix_rand::u64()) {
        (Some(first), Some(second)) if first != second => {
            println!("    unpredictable  two draws differ, and the machine reports rdrand");
        }
        (Some(_), Some(_)) => println!(
            "\x1b[91m    unpredictable  FAILED: two draws were identical, which is what a carry \
             flag nobody tested looks like\x1b[0m"
        ),
        _ => println!(
            "\x1b[91m    unpredictable  FAILED: rdrand is reported present and would not \
             answer\x1b[0m"
        ),
    }
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

fn report_boot_state(
    handoff: &Handoff,
    serial: bhaskix_arch::Presence,
    serial_second: bhaskix_arch::Presence,
    framebuffer: bool,
) {
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
    // Both ports, named, because the question this answers is *which one the
    // machine's service processor is listening to* -- and one line saying
    // "present" about a port nobody carries is what left that open for two
    // days.
    println!(
        "    serial (com2)   {}",
        match serial_second {
            bhaskix_arch::Presence::Working => "present -- output goes here too",
            bhaskix_arch::Presence::Unverified =>
                "present, loopback unverified -- output goes here too",
            bhaskix_arch::Presence::Absent => "absent (this machine has one UART)",
        }
    );
    println!(
        "    serial          {}",
        match serial {
            bhaskix_arch::Presence::Working => "present",
            // Named, not hidden. On a machine whose UART is shared with a
            // service processor this is the normal answer, and an operator
            // reading a log over that very port should be told why the
            // self-test did not agree that it works.
            bhaskix_arch::Presence::Unverified =>
                "present, loopback unverified (shared with a service processor?)",
            bhaskix_arch::Presence::Absent => "ABSENT",
        }
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
    } else if handoff
        .cmdline
        .split_ascii_whitespace()
        .any(|word| word == "kaslr=show")
    {
        // Asked for, at the console, by somebody who already controls the
        // machine enough to pass it a command line.
        println!("    kaslr           slid {slide:#x} bytes from {LINK_BASE:#018x} (kaslr=show)");
    } else {
        // **The slide is not printed, and RFC 0042 is why.** The boot report is
        // about to become readable from ring 3, and the slide is the one thing
        // in it that is a secret: `LINK_BASE + slide` is where the kernel is,
        // which is the whole of what KASLR hides. Everything else the report
        // prints is public -- `hhdm base` is a compile-time constant stated in
        // `architecture.md`, and the ACPI and SMBIOS pointers are firmware
        // physical addresses any program that can read ACPI can find.
        //
        // What the report is *for* is answering whether KASLR happened and
        // whether the two halves agree about it, and that is a yes or no.
        // `kaslr=show` prints the number for whoever is debugging a fault.
        println!("    kaslr           applied and confirmed (kaslr=show prints the slide)");
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

/// Which wakeup (1-based, as counted by [`RT_ROUNDS`]) set [`RT_WORST`].
///
/// The worst sits at 442–447 µs·1000 on every boot of 2026-08-16 — clustered
/// too tightly to be load — and a worst with no round number cannot say
/// whether the same round is slow every boot. That question is this static.
static RT_WORST_ROUND: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// TSC at the probe's first instruction, stored once.
///
/// The first read-out said the whole 444 ms lives in wakeup 1 — which cannot
/// distinguish "the wake was slow" from "the probe had never run". Against
/// the spawn stamp the waker keeps, this answers it.
static RT_FIRST_RAN: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// The CPU the probe first found itself on, against the one it was pinned to.
static RT_FIRST_CPU: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(u64::MAX);

/// A real-time thread that sleeps, and measures how long waking it took.
///
/// The number this produces is the one `docs/scheduler.md` §4 puts a budget
/// on. Measured rather than asserted, because a latency nobody measures is a
/// latency nobody meets.
extern "C" fn rt_probe(_argument: u64) -> ! {
    use core::sync::atomic::Ordering;
    let _ = RT_FIRST_RAN.compare_exchange(
        0,
        bhaskix_arch::tsc::read(),
        Ordering::Relaxed,
        Ordering::Relaxed,
    );
    RT_FIRST_CPU.store(u64::from(bhaskix_arch::percpu::cpu_id()), Ordering::Relaxed);
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
        let round = RT_ROUNDS.fetch_add(1, Ordering::Relaxed) + 1;
        if delay > RT_WORST.fetch_max(delay, Ordering::Relaxed) {
            RT_WORST_ROUND.store(round, Ordering::Relaxed);
        }

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

    // The capture, armed 2026-08-16: this check failed 3 times in 500 JOBS=1
    // boots and once in a suite run, always beside a green `burners_gone` --
    // and a bare FAILED cannot say which of three stories is true: a late end
    // (a scheduling delay and nothing more), a lost last-exit check (the
    // try_lock skip in `threads_in_domain_except` telling the genuinely last
    // thread it is not), or a burner that never really exited. One captured
    // boot with this block prints the discriminant.
    if !ended_themselves {
        let live = |id| matches!(domain::state_of(id), Ok(None));
        println!(
            "    domains        CAPTURE lonely {} with {} threads counted; crowded {} with {} \
             threads counted",
            if live(lonely) { "LIVE" } else { "over" },
            sched::threads_in_domain(lonely.as_u32()),
            if live(crowded) { "LIVE" } else { "over" },
            sched::threads_in_domain(crowded.as_u32()),
        );
        let late = wait_until(|| !live(lonely) && !live(crowded), 8_000);
        println!(
            "    domains        CAPTURE verdict: {}; {} domain scans were blinded by a busy \
             runqueue this boot",
            if late {
                "ended late -- a delay, not a loss"
            } else {
                "still live 8 s on -- the last exit's check was lost for good"
            },
            sched::domain_scan_skips(),
        );
    }

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
    } else {
        // The capture for the run-123 family, armed 2026-08-17: one boot in
        // ~1000 measures 0 vs 0 ticks here -- CPU 1 ran nothing it was handed
        // for over two seconds, resched IPIs and all. Both of `preempt`'s
        // declines are silent, so a failure without these numbers cannot say
        // whether the CPU was vetoed (a stale hold count repeating), locked
        // out of its own queue, or never asked at all.
        for cpu in 0..(cpus.min(bhaskix_arch::percpu::MAX_CPUS as u32)) {
            let (holds, busy) = sched::preempt_declines(cpu as usize);
            let ticks = trap::ticks_on(cpu);
            println!(
                "    sched classes  CAPTURE cpu {cpu}: {holds} preemptions vetoed by a held \
                 lock, {busy} declined on a busy queue, {ticks} timer ticks since boot"
            );
        }
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

    // Before the spawn, because the spawn is what depends on it: a same-CPU
    // spawn whose `resched` declines falls back to the reschedule IPI, and it
    // can only do that if the decline is reported at all.
    if sched::preempt_reports_its_decline() {
        println!(
            "    spawn retry    a declined preemption reports itself, so a same-cpu spawn can fall back to the ipi"
        );
    } else {
        println!(
            "\x1b[91m    spawn retry    FAILED: preempt declined while a lock was held and did not say so -- a same-cpu spawn that declines would be dropped, and its thread would wait for the one-second backstop\x1b[0m"
        );
        return false;
    }

    let spawned_at = bhaskix_arch::tsc::read();
    if let Err(error) = sched::spawn_on_with(cpu, "rt-probe", rt_probe, 0, hhdm_base, options) {
        println!("\x1b[91m    rt latency     FAILED to spawn the probe: {error:?}\x1b[0m");
        return false;
    }

    // Let it reach the gate before the first measurement.
    wait_millis(50);

    const ROUNDS: u64 = 50;
    // Which rounds the waker gave up on -- the spin bound expiring with the
    // probe still owing its consumption. The 2026-08-16 soaks measured a
    // worst clustered at 442-447 ms on every boot; a give-up is the only way
    // this loop can leave a stamp un-restamped long enough to age that much,
    // so counting them (and naming the first) is half the diagnosis.
    let mut gave_up = 0u64;
    let mut first_give_up = 0u64;
    let ticks_before = trap::ticks_on(cpu);
    let loop_start = bhaskix_arch::tsc::read();
    for round in 1..=ROUNDS {
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
        if RT_RELEASED.load(Ordering::Acquire) {
            gave_up += 1;
            if first_give_up == 0 {
                first_give_up = round;
            }
        }
    }
    let loop_ticks = bhaskix_arch::tsc::read().saturating_sub(loop_start);
    let timer_ticks_in_loop = trap::ticks_on(cpu).saturating_sub(ticks_before);

    let rounds = RT_ROUNDS.load(Ordering::Relaxed);
    let worst = RT_WORST.load(Ordering::Relaxed);
    let worst_round = RT_WORST_ROUND.load(Ordering::Relaxed);
    let worst_ns = bhaskix_arch::tsc::to_nanos(worst);

    if rounds < ROUNDS / 2 {
        println!(
            "\x1b[91m    rt latency     FAILED: only {rounds} of {ROUNDS} wakeups completed\x1b[0m"
        );
        return false;
    }

    let first_ran = RT_FIRST_RAN.load(Ordering::Relaxed);
    let spawn_to_first_run_us =
        bhaskix_arch::tsc::to_nanos(first_ran.saturating_sub(spawned_at)).unwrap_or(0) / 1_000;
    match worst_ns {
        Some(nanos) => println!(
            "    rt latency     {rounds} wakeups, worst {}.{:03} us at wakeup {worst_round}; \
             {gave_up} give-ups (first at round {first_give_up}), loop {} ms, \
             spawn to first run {spawn_to_first_run_us} us, pinned to cpu {cpu}, first ran on \
             cpu {}, waker now on cpu {}, {timer_ticks_in_loop} timer ticks on cpu {cpu} \
             during the loop, {} spawn resched declines \
             (target 50 us, docs/scheduler.md §4)",
            nanos / 1000,
            nanos % 1000,
            bhaskix_arch::tsc::to_nanos(loop_ticks).unwrap_or(0) / 1_000_000,
            RT_FIRST_CPU.load(Ordering::Relaxed),
            bhaskix_arch::percpu::cpu_id(),
            sched::spawn_resched_declines(),
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
    // Kept so this test can wait for its own workers rather than sleeping over
    // them -- see the retirement below.
    let mut spawned = [0u32; NAMES.len()];
    for (id, name) in NAMES.iter().enumerate() {
        // Placed by load, so the ring spans CPUs and the wakeups are genuinely
        // cross-processor. A ring confined to one CPU would never exercise the
        // window this test exists for.
        match sched::spawn(name, ring_station, id as u64, hhdm_base) {
            Ok(thread) => spawned[id] = thread,
            Err(error) => {
                println!("\x1b[91m    wait queues    FAILED to spawn {name}: {error:?}\x1b[0m");
                return false;
            }
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

    // Retire the ring: publish the phase, then wake, in that order -- and then
    // **wait for them**, rather than sleeping 200 ms and hoping.
    //
    // These threads *block*, so the wake is what lets them re-read the phase at
    // all; the ordering comment above is about that and is load-bearing. What
    // was missing is the other half: nothing checked they had actually gone.
    // The class phase that follows measures CPU shares, and a ring station
    // still runnable is a competitor it never accounted for.
    PHASE.store(PHASE_WAIT + 1, Ordering::Release);
    RING.wake_all();
    let ring_retired = wait_until(|| sched::threads_present_exact(&spawned) == 0, 4_000);

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

    if !ring_retired {
        println!(
            "\x1b[91m    wait queues    FAILED: {} ring stations did not retire, so the class \
             phase would measure a machine they are still competing on\x1b[0m",
            sched::threads_present_exact(&spawned)
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
    // **Kept, because this test has to be able to wait for them.** The ids
    // were discarded until 2026-08-26, which is why the only way to retire
    // these threads was to advance the phase and sleep.
    let mut spawned = [0u32; NAMES.len() + 1];
    for (id, name) in NAMES.iter().enumerate() {
        match sched::spawn_on(0, name, migrant, id as u64, hhdm_base) {
            Ok(thread) => spawned[id] = thread,
            Err(error) => {
                println!("\x1b[91m    migration      FAILED to spawn on cpu 0: {error:?}\x1b[0m");
                return false;
            }
        }
    }

    // With CPU 0 now holding four runnable threads and every other CPU one,
    // load-aware placement has exactly one correct answer: not CPU 0. Checked
    // before anything runs, so this measures the placement decision rather
    // than whatever balancing happens afterwards.
    let placed = match sched::spawn("placed", migrant, PLACED_SLOT, hhdm_base) {
        Ok(id) => {
            spawned[NAMES.len()] = id;
            id
        }
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

    // **Retire the workers here, and *wait* for them to be gone.**
    //
    // This test used to leave four spinning threads behind for its caller to
    // dispose of by advancing the phase and sleeping 300 ms. A fixed sleep is
    // a guess about how long a teardown takes, and the guess was load-bearing:
    // an intermittent kernel page fault -- near-null `cr2`, two threads at
    // once, the exception frame overwritten under the handler -- landed
    // **immediately after this line** on two different lanes, both naming
    // threads 12 and 13, which are these.
    //
    // Four threads that spin until a phase advances and then all call
    // `sched::exit()` at once, across four CPUs, **at least one of them having
    // been stolen from another CPU's run queue**, is the narrowest description
    // of the window. Waiting for them does not fix a teardown that races; it
    // stops the rest of the boot from being the other party to the race, and
    // it turns a fixed sleep into an observation.
    //
    // `threads_present_exact` blocks for each queue rather than skipping one
    // it cannot take, because the whole point is deciding *"they are gone"*
    // once, and a scan that answers early would reinstate the very race this
    // removes. A thread is present until reaped, so zero means teardown
    // finished.
    PHASE.store(PHASE_WAIT, Ordering::Release);
    let retired = wait_until(|| sched::threads_present_exact(&spawned) == 0, 4_000);
    let still_here = sched::threads_present_exact(&spawned);
    // **There was a settle here, and its removal is the point.**
    //
    // Waiting for the threads is the correctness half. A second half was added
    // beside it -- sleep on afterwards for as long as the old fixed sleep did
    // -- because replacing four sleeps with four waits appeared to make the TCP
    // inbound test far flakier, from about one boot in thirty to three in
    // twelve. It was a misattribution. The control, this tree with none of
    // these changes, failed **ten times in twelve** on the same host boot: the
    // machine underneath had rebooted mid-investigation and is a KVM guest
    // reporting five figures of steal time. The rate had moved for reasons
    // nothing here touched.
    //
    // So the settle was removed, because a compensation for a regression that
    // was never caused is just a sleep with a story attached. **The lesson is
    // kept where the mistake was made**: a rate measured before and after a
    // change says nothing unless both were measured on the same boot of the
    // host, and this instrument exists precisely so the boot stops depending
    // on how fast the machine happens to be.

    if ok {
        println!(
            "    migration      {steals} threads stolen; {moved} of 3 ran off their creating cpu; placement chose cpu {}",
            placed_on.unwrap_or(u32::MAX)
        );
        println!(
            "    migration      {} of its {} workers retired before the next phase{}",
            spawned.len() - still_here,
            spawned.len(),
            if retired {
                ""
            } else {
                " -- SOME ARE STILL RUNNING, and the next phase measures a machine they are on"
            }
        );
    }

    ok && retired
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

    // Kept for the same reason the migration test keeps its own: a generation
    // of workers that nothing can wait for can only be retired by sleeping.
    let mut spawned = [0u32; WORK.len()];
    let mut spawned_count = 0usize;
    for id in 0..cpus {
        match sched::spawn_on(id, NAMES[id as usize], worker, u64::from(id), hhdm_base) {
            Ok(thread) => {
                spawned[spawned_count] = thread;
                spawned_count += 1;
            }
            Err(error) => {
                println!(
                    "\x1b[91m    threads        FAILED to spawn on cpu {id}: {error:?}\x1b[0m"
                );
                return false;
            }
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

    // Retire the pinning workers before measuring migration, and **wait for
    // them** rather than sleeping over them. They are pinned only by
    // circumstance -- one per CPU, so no CPU is ever idle enough to steal --
    // and leaving them running would mean the migration phase found a
    // perfectly balanced machine and correctly did nothing.
    //
    // That is not a small failure mode: it would make the *next* test measure
    // the opposite of what it means to, and pass. A fixed 300 ms was the only
    // thing standing between here and there.
    PHASE.store(PHASE_MIGRATION, Ordering::Release);
    let pinning_retired = wait_until(
        || sched::threads_present_exact(&spawned[..spawned_count]) == 0,
        4_000,
    );
    if !pinning_retired {
        println!(
            "\x1b[91m    threads        FAILED: {} pinning workers still running, so the \
             migration phase would measure a machine they are on\x1b[0m",
            sched::threads_present_exact(&spawned[..spawned_count])
        );
        ok = false;
    }

    ok &= migration_self_test(hhdm_base, cpus);

    // The migration workers are retired **by the test that spawned them**, and
    // it waits for them rather than sleeping over them -- see the note there.
    // They never sleep, so leaving them spinning would let the ring make
    // progress by being preempted onto rather than by being woken, which is the
    // one thing the next phase is trying to distinguish.
    //
    // The store is kept as a belt: it is idempotent, and it means this sequence
    // still reads as "phase advances here" for anyone following it downwards.
    PHASE.store(PHASE_WAIT, Ordering::Release);

    ok &= wait_queue_self_test(hhdm_base);

    // The ring is retired **by the test that spawned it**, which waits for its
    // stations rather than sleeping over them -- see the note there. The store
    // is kept as a belt: it is idempotent, and this sequence still reads as
    // "phase advances here" to anyone following it downwards.
    PHASE.store(PHASE_CLASS, Ordering::Release);

    ok &= class_self_test(hhdm_base, cpus);
    ok &= rt_latency_self_test(hhdm_base, cpus);

    // Retire the class **burners** and wait for them. They spin and poll the
    // phase, so they go promptly; the domain phase that follows measures
    // envelopes and CPU share, and a burner still running is a competitor it
    // never accounted for.
    //
    // **Only the burners.** The `rt-probe` spawned beside them is *blocked* on
    // `RT_GATE`, and its retirement is deliberately split: the wake that lets
    // it re-read the phase comes two tests later, after `shared_memory`. That
    // split is in the code on purpose -- a blocked thread competes for nothing
    // -- so it is left alone rather than tidied into a shape that would need
    // the wake moved. `CLASS_IDS` is the array those tests already publish
    // into, and `u64::MAX` is its "never filled" sentinel.
    PHASE.store(PHASE_DOMAIN, Ordering::Release);
    let mut burners = [0u32; 2];
    let mut burner_count = 0usize;
    for slot in CLASS_IDS.iter().take(2) {
        let id = slot.load(Ordering::Relaxed);
        if id != u64::MAX {
            burners[burner_count] = id as u32;
            burner_count += 1;
        }
    }
    let burners_retired = wait_until(
        || sched::threads_present_exact(&burners[..burner_count]) == 0,
        4_000,
    );
    if !burners_retired {
        println!(
            "\x1b[91m    sched classes  FAILED: {} class burners still running, so the domain \
             phase would measure a machine they are on\x1b[0m",
            sched::threads_present_exact(&burners[..burner_count])
        );
        ok = false;
    }

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
