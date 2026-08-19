// SPDX-License-Identifier: Apache-2.0
//! Secondary CPU bring-up.
//!
//! Two ways up, one arrival. A loader that already took each secondary
//! processor through real mode and parked it hands the kernel a
//! [`bhaskix_boot::Handoff::start_secondaries`] and the kernel merely
//! releases them. A loader that offers nothing — `bhaskixboot`, on purpose
//! — gets the road this module used to call "worth owning eventually" and
//! now owns: the processors found in the MADT, a real-mode trampoline
//! copied to a page reserved below one megabyte at boot, and an
//! INIT-SIPI-SIPI sequence sent from the kernel itself, one processor at a
//! time. Either way every CPU lands in [`secondary_main`] and nothing
//! below this module knows which road it took.
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

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use bhaskix_arch::{acpi, apic, cpu, gdt, idt, mp, percpu};

use crate::println;

/// Physical address of the page reserved for the SMP trampoline.
///
/// Chosen inside the conventional-memory range every PC has below the
/// legacy hole, page-aligned because STARTUP can only point at a page, and
/// clear of the real-mode IVT and BIOS data area at the bottom. Carved out
/// of the allocator by `memory::init` before any frame reaches a free list.
pub const TRAMPOLINE_FRAME: u64 = 0x8000;

/// Whether the boot memory map had a usable page at [`TRAMPOLINE_FRAME`].
static TRAMPOLINE_RESERVED: AtomicBool = AtomicBool::new(false);

/// Processors the MADT declared, when native bring-up did the counting.
/// Zero when a loader did it instead, and `report` falls back to the
/// handoff's own count.
static MADT_REPORTED: AtomicU32 = AtomicU32::new(0);

/// Records that `memory::init` reserved the trampoline page.
pub fn note_trampoline_reserved() {
    TRAMPOLINE_RESERVED.store(true, Ordering::Release);
}

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

        // SSE, for this CPU too: the register file is per CPU, so the
        // enable is as well, and a thread migrated here would meet `#UD`
        // on its first floating-point instruction otherwise.
        //
        // **After the descriptor tables, not before them.** Placed at the
        // top of this function it wrote control registers on a CPU with no
        // IDT loaded, where any fault is a triple fault and the processor
        // simply never arrives -- which is what the native lane reported
        // as "the cpus line is missing or short of 4 online of 4".
        bhaskix_arch::cpu::enable_sse();

        // Only now: the GDT load above cleared GS.base, so pointing GS at the
        // per-CPU area has to happen after it rather than before.
        percpu::activate(cpu_id);

        // Fast system-call entry. MSRs only -- the kernel stack this CPU will
        // switch to is set later, once there is a heap to allocate one from.
        if let Some(area) = percpu::area_address() {
            bhaskix_arch::syscall::init(area);
        }

        apic::enable_this_cpu();

        // This CPU's runqueue, with the code currently executing as its first
        // thread -- otherwise the first preemption would have nowhere to save
        // the context it is running on.
        // The idle class, so this thread runs only when the CPU has nothing
        // else at all -- including nothing stolen from a busier processor.
        crate::sched::init_cpu("idle", crate::sched::Policy::Idle);

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

/// How long a released secondary is given to report in.
///
/// Two seconds because bring-up takes microseconds; a secondary that has
/// not arrived by then is not late, it is absent.
const WAIT_NANOS: u64 = 2_000_000_000;

/// Spins until the online count reaches `expected`, bounded by a
/// **deadline** rather than by a spin count.
///
/// A CPU that never arrives must not hang the boot, and reporting "3 of 7
/// came online" is far more useful than a machine that stops with no
/// explanation.
///
/// The count the deadline replaced was two billion iterations, which is not
/// a duration: it was measured at 6.4 seconds of *guest* time on a machine
/// where the same boot took 491 seconds of wall-clock, because an emulated
/// TSC does not track the host clock. A bound nobody can convert into
/// seconds cannot be reasoned about, and on a slow or emulated machine it
/// turns a diagnosable "one CPU is missing" into what looks like a hang.
fn wait_until_online(expected: u32, wait_nanos: u64) {
    wait_for(|| percpu::online_count() >= expected, wait_nanos);
}

/// Spins until `done`, bounded by the same deadline discipline.
///
/// Returns whether `done` was reached before the deadline.
fn wait_for(mut done: impl FnMut() -> bool, wait_nanos: u64) -> bool {
    let deadline = crate::time::now_nanos().map(|now| now.saturating_add(wait_nanos));
    let mut spins = 0u64;
    while !done() {
        // No clock yet is possible in principle, so the old bound stays as
        // the fallback rather than becoming an unbounded wait.
        let expired = match deadline {
            Some(deadline) => crate::time::now_nanos().is_some_and(|now| now >= deadline),
            None => {
                spins += 1;
                spins >= 2_000_000_000
            }
        };
        if expired {
            return false;
        }
        core::hint::spin_loop();
    }
    true
}

/// Spins for `nanos` nanoseconds — the INIT-SIPI protocol's delays.
///
/// Falls back to a counted spin when there is no clock; the count is a
/// guess that errs long, which for a bring-up delay is the safe direction.
fn delay_nanos(nanos: u64) {
    match crate::time::now_nanos() {
        Some(start) => {
            while crate::time::now_nanos().is_some_and(|now| now < start.saturating_add(nanos)) {
                core::hint::spin_loop();
            }
        }
        None => {
            for _ in 0..nanos.saturating_mul(4) {
                core::hint::spin_loop();
            }
        }
    }
}

/// Brings up every secondary CPU the loader reported.
///
/// Returns the number that came online, not counting the bootstrap CPU.
pub fn start_secondaries(handoff: &bhaskix_boot::Handoff) -> u32 {
    let Some(start) = handoff.start_secondaries else {
        // No loader help. The kernel's own road: discovery from the MADT,
        // the trampoline, INIT-SIPI from this CPU.
        return native_start(handoff);
    };

    // Snapshotted *before* the call, and that is the whole of a stall.
    //
    // `percpu::install` increments the online count as its first act, so a
    // secondary counts the instant it starts running. Reading the count after
    // `start` returns therefore counts every CPU that got there first *twice*
    // -- once in the count and once in `requested` -- and waits for a total
    // that can never arrive. On four CPUs it waited for seven.
    //
    // It cost one boot in 330: the window is the few instructions between
    // `start` returning and the count being read, and it only matters when a
    // secondary wins that race. Putting a `println!` in that gap made it
    // happen on every boot, which is how it was found -- and with this line
    // moved above the call, that same print boots cleanly five times out of
    // five.
    let before = percpu::online_count();
    let released = start(secondary_main);
    let requested = released.len() as u32;
    if requested == 0 {
        return 0;
    }

    let expected = before + requested;
    wait_until_online(expected, WAIT_NANOS);

    // Said out loud, and in the warning colour, because `report` prints
    // "N online of M reported" and a reader has to know M to see that N is
    // short. On real hardware a secondary that never checks in is a fault in
    // firmware, in the APIC, or in this kernel's own entry path -- and it is
    // the difference between a machine that is slow and a machine that is
    // missing a processor.
    let online = percpu::online_count();
    if online < expected {
        println!(
            "\x1b[93m    smp            {} of {requested} secondaries never reported in after {} ms\x1b[0m",
            expected - online,
            WAIT_NANOS / 1_000_000
        );
        // And *which*. A count says a processor is missing; only an identifier
        // can be taken to a firmware vendor, and on a machine that is not an
        // emulator that is the whole of the diagnosis. The loader returns the
        // identities it released precisely so this line can exist.
        for lapic_id in released {
            if !percpu::is_online_lapic(*lapic_id) {
                println!(
                    "\x1b[93m    smp              lapic {lapic_id} was released and never reported in\x1b[0m"
                );
            }
        }
    }

    online.saturating_sub(1)
}

/// Writes `bytes` into the trampoline page at `offset`, through the direct
/// map.
fn patch(hhdm: u64, offset: usize, bytes: &[u8]) {
    for (index, byte) in bytes.iter().enumerate() {
        // SAFETY: inside the page `memory::init` reserved for exactly this,
        // written before any processor is released at it.
        unsafe {
            core::ptr::write_volatile(
                (hhdm + TRAMPOLINE_FRAME + offset as u64 + index as u64) as *mut u8,
                *byte,
            );
        }
    }
}

/// Builds the world a secondary boots under: a copy of the live root plus
/// one addition — the trampoline page mapped at its own physical address,
/// present and executable and nothing else, because the far jump into long
/// mode lands there with paging already on and W^X holds even for a page
/// that lives one millisecond.
///
/// A copy rather than an edit of the live root, so the bootstrap CPU's
/// tables are never touched and there is no window where the kernel itself
/// could silently dereference low memory. The copy goes stale the moment
/// the kernel maps something new at top level — which is sound for the
/// same reason the loader-parked path is: a secondary switches onto real
/// tables at its first context switch, and every high-half entry it needs
/// existed long before SMP start.
fn bringup_root(hhdm: u64) -> Option<u64> {
    let take = || {
        crate::heap::with(|heap| heap.pmm_mut().allocate(0, bhaskix_mm::Zone::Normal).ok())
            .flatten()
            .map(|pfn| u64::from(pfn) * bhaskix_mm::FRAME_SIZE)
    };
    let (Some(pml4), Some(pdpt), Some(pd), Some(pt)) = (take(), take(), take(), take()) else {
        println!("    smp            no frames for the bring-up tables; secondaries stay off");
        return None;
    };
    for frame in [pml4, pdpt, pd, pt] {
        // The trampoline loads CR3 as 32 bits, because the instruction runs
        // in protected mode. Refused rather than truncated.
        if frame >= 1_u64 << 32 {
            println!("    smp            a bring-up table sits above 4 GiB; secondaries stay off");
            return None;
        }
        // SAFETY: freshly allocated, unaliased, covered by the direct map.
        // The allocator does not zero, and a page table must start empty.
        unsafe { core::ptr::write_bytes((hhdm + frame) as *mut u8, 0, 4096) };
    }

    // SAFETY: the live PML4 is a frame the direct map covers; the copy goes
    // to a frame nothing else references.
    unsafe {
        let live = bhaskix_arch::paging::active_page_table();
        core::ptr::copy_nonoverlapping((hhdm + live) as *const u64, (hhdm + pml4) as *mut u64, 512);
    }

    /// Present.
    const P: u64 = 1;
    /// Writable — intermediate entries only; the leaf stays read-execute.
    const W: u64 = 2;
    let entry = |table: u64, index: u64, value: u64| {
        // SAFETY: a table frame allocated and zeroed above.
        unsafe { core::ptr::write_volatile((hhdm + table + index * 8) as *mut u64, value) };
    };
    entry(pml4, 0, pdpt | P | W);
    entry(pdpt, 0, pd | P | W);
    entry(pd, 0, pt | P | W);
    entry(pt, TRAMPOLINE_FRAME >> 12, TRAMPOLINE_FRAME | P);
    Some(pml4)
}

/// Where a natively-released secondary lands, one claimed stack later.
///
/// The identity comes from the architecture, not from a patchable slot: a
/// processor that runs late — routine under emulation — may claim a stack
/// offered while a sibling was being started, and an identity read from
/// shared memory would then be the sibling's. `CPUID` cannot be stale.
/// Leaf 0xB's `EDX` is the full x2APIC identifier where the processor has
/// the leaf; the initial-APIC-ID byte of leaf 1 serves the rest.
extern "C" fn native_ap_entry(_zero: u32) -> ! {
    let lapic_id = if core::arch::x86_64::__cpuid(0).eax >= 0xb {
        core::arch::x86_64::__cpuid(0xb).edx
    } else {
        core::arch::x86_64::__cpuid(1).ebx >> 24
    };
    secondary_main(lapic_id)
}

/// The kernel's own bring-up, for a loader that offered none: processors
/// from the MADT, the trampoline copied and patched, INIT-SIPI-SIPI per
/// processor, sequentially. Each processor's stack goes through the
/// trampoline's atomic mailbox — offered by one store, won by one
/// `cmpxchg` — so no stack is ever shared, no matter how late a processor
/// arrives.
///
/// Returns the number that came online, not counting the bootstrap CPU.
fn native_start(handoff: &bhaskix_boot::Handoff) -> u32 {
    let hhdm = handoff.hhdm_base.as_u64();

    // Discovery. The processors are in the MADT or they are nowhere.
    let Some(rsdp) = handoff.rsdp else {
        println!("    smp            no loader help and no acpi; one CPU is the machine");
        return 0;
    };
    // SAFETY: `rsdp` and `hhdm` come from the handoff; the walk maps every
    // byte it reads through the closure before reading it.
    let madt = unsafe {
        acpi::madt(rsdp.as_u64(), hhdm, &mut |physical, length| {
            crate::mmio::map(physical, length as u64, hhdm).is_some()
        })
    };
    let Some(madt) = madt else {
        println!("    smp            no loader help and no madt; one CPU is the machine");
        return 0;
    };
    let processors = madt.processors();
    MADT_REPORTED.store(processors.len() as u32, Ordering::Release);
    if processors.len() <= 1 {
        println!("    smp            the madt names one processor; nothing to start");
        return 0;
    }
    if !TRAMPOLINE_RESERVED.load(Ordering::Acquire) {
        println!(
            "    smp            no usable page at the trampoline address; secondaries stay off"
        );
        return 0;
    }

    // The trampoline, copied whole, then its static slots: both far-jump
    // targets, the GDT descriptor's base, and the root every secondary
    // loads. The per-processor slots are patched in the loop.
    let image = mp::image();
    let bounds = mp::layout();
    // SAFETY: the reserved page, through the direct map, before any
    // processor was released at it.
    unsafe {
        core::ptr::copy_nonoverlapping(
            image.as_ptr(),
            (hhdm + TRAMPOLINE_FRAME) as *mut u8,
            image.len(),
        );
    }
    let Some(root) = bringup_root(hhdm) else {
        return 0;
    };
    let target = |offset: usize| ((TRAMPOLINE_FRAME as u32) + offset as u32).to_le_bytes();
    patch(hhdm, bounds.pm_target, &target(bounds.prot32));
    patch(hhdm, bounds.lm_target, &target(bounds.long64));
    patch(hhdm, bounds.gdtdesc + 2, &target(bounds.gdt));
    patch(hhdm, bounds.cr3, &root.to_le_bytes());
    patch(
        hhdm,
        bounds.entry,
        &(native_ap_entry as *const () as u64).to_le_bytes(),
    );

    // The stack mailbox, as the atomic it is. Everything above was patched
    // byte by byte before any processor existed to read it; this slot is
    // the one that is written *while* processors run, so its writes must
    // be single and indivisible.
    // SAFETY: the slot is 8-aligned inside the reserved page (the layout's
    // host tests hold it there), reachable through the direct map, and
    // shared only through this atomic from here on.
    let mailbox = unsafe {
        core::sync::atomic::AtomicU64::from_ptr(
            (hhdm + TRAMPOLINE_FRAME + bounds.stack as u64) as *mut u64,
        )
    };

    println!(
        "    smp            no loader help; INIT-SIPI from the kernel: {} processors in the madt",
        processors.len()
    );

    // The SIPI vector is the trampoline's page number — the architecture's
    // whole addressing for where a processor starts.
    let vector = (TRAMPOLINE_FRAME >> 12) as u8;
    /// Stack slots far above every range the thread, syscall and RSP0
    /// stacks use.
    const SLOT_BASE: u64 = 4096;
    let mut started = 0u64;
    for &lapic in processors {
        if lapic == handoff.bsp_lapic_id {
            continue;
        }
        // SAFETY: each offer gets a distinct slot, mapped here on the
        // bootstrap CPU before any processor can claim it.
        let Ok(stack) = (unsafe { crate::stack::allocate(hhdm, SLOT_BASE + started) }) else {
            println!("\x1b[93m    smp            no stack for lapic {lapic}; it stays off\x1b[0m");
            continue;
        };
        started += 1;

        let before = percpu::online_count();
        mailbox.store(stack.top, Ordering::Release);
        // INIT takes the processor to wait-for-SIPI; the settle delay is
        // the protocol's, ten milliseconds; STARTUP releases it into the
        // trampoline. The second STARTUP is sent only if the offer went
        // unclaimed — the protocol's retry, not a doubled release.
        // SAFETY: the APIC is initialised on this CPU, and `lapic` is a
        // secondary, never the sender.
        unsafe {
            apic::send_init(lapic);
        }
        delay_nanos(10_000_000);
        // SAFETY: as above, and the trampoline page was copied and patched.
        unsafe {
            apic::send_startup(lapic, vector);
        }
        wait_for(|| mailbox.load(Ordering::Acquire) == 0, WAIT_NANOS / 2);
        if mailbox.load(Ordering::Acquire) != 0 {
            // SAFETY: as above.
            unsafe {
                apic::send_startup(lapic, vector);
            }
            wait_for(|| mailbox.load(Ordering::Acquire) == 0, WAIT_NANOS);
        }
        // Retract an unclaimed offer — atomically, because a processor may
        // win the race against this very retraction, and then the claim
        // must stand. A retracted stack is leaked on purpose: an address a
        // lost processor might still wake up on is never reusable.
        if mailbox
            .compare_exchange(stack.top, 0, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            println!(
                "\x1b[93m    smp              lapic {lapic} never claimed its stack; it stays off\x1b[0m"
            );
            continue;
        }
        // Claimed: some processor is on its way through the kernel's own
        // bring-up. Under emulation that walk can take seconds, so the
        // arrival deadline is generous where the claim deadline was not.
        wait_until_online(before + 1, 4 * WAIT_NANOS);
        if !percpu::is_online_lapic(lapic) {
            println!(
                "\x1b[93m    smp              lapic {lapic} claimed a stack and never reported in\x1b[0m"
            );
        }
    }

    percpu::online_count().saturating_sub(1)
}

/// Prints what came online.
pub fn report(handoff: &bhaskix_boot::Handoff) {
    // When native bring-up did the counting, the MADT's claim supersedes
    // the loader's: a loader that cannot start secondaries honestly reports
    // the one CPU it entered on, and printing that "1" against four online
    // processors would make a working machine read as an error.
    let madt = MADT_REPORTED.load(Ordering::Acquire);
    let reported = if madt == 0 { handoff.cpu_count } else { madt };
    println!(
        "    cpus           {} online of {} reported (bsp lapic {})",
        percpu::online_count(),
        reported,
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

/// Gives every online CPU a guarded stack for the syscall entry path.
///
/// `SYSCALL` does not switch stacks, so the entry stub takes one from per-CPU
/// data. It must be a stack no thread is using: the stub switches to it before
/// anything has established what the interrupted thread was doing, so sharing
/// one with a running thread would overwrite that thread's frame.
///
/// Guarded, like every other kernel stack — an overflow here happens with a
/// user-controlled argument count and is exactly the kind of thing that should
/// fault cleanly rather than corrupt whatever is below.
///
/// Returns how many CPUs were given one.
pub fn init_syscall_stacks(hhdm_base: u64) -> u32 {
    /// Slot base for syscall stacks, far above the range thread ids use.
    const SLOT_BASE: u64 = 1024;

    let mut ready = 0;
    for cpu in 0..percpu::online_count() {
        // SAFETY: each CPU gets a distinct slot, so no two stacks overlap, and
        // the mapping is done here on the bootstrap CPU before any of them can
        // take a system call.
        let Ok(stack) = (unsafe { crate::stack::allocate(hhdm_base, SLOT_BASE + u64::from(cpu)) })
        else {
            continue;
        };
        // SAFETY: `cpu` is online, and `stack.top` is one past a freshly
        // mapped, guarded stack that nothing else uses.
        unsafe { percpu::set_kernel_stack(cpu, stack.top) };
        ready += 1;
    }
    ready
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
