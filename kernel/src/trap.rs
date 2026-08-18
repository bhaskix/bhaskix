// SPDX-License-Identifier: Apache-2.0
//! Exception reporting.
//!
//! M2's exit criterion is that every exception produces a clear diagnostic
//! instead of a triple fault. This module is that diagnostic.
//!
//! The design goal is narrow and worth stating: **make the next person's
//! debugging session short**. A kernel fault report is read by someone who has
//! no debugger, no logs, and no way to reproduce on demand. Everything they
//! will need has to be on screen the first time, because there may not be a
//! second time.
//!
//! So the report includes the decoded meaning of the error code, not just its
//! hex value; the faulting address for page faults; whether the fault came
//! from user or kernel mode; and an explicit note when the fault looks like a
//! stack overflow. Each of those is a question someone would otherwise have to
//! answer by hand, from a photograph of a screen.

use core::sync::atomic::{AtomicU64, Ordering};

use bhaskix_arch::idt::{exception_name, has_error_code};
use bhaskix_arch::percpu::{self, MAX_CPUS};
use bhaskix_arch::trap::TrapFrame;
use bhaskix_arch::{apic, cpu, msr, paging, pic};
use bhaskix_boot::{PhysAddr, VirtAddr};
use bhaskix_mm::BumpAllocator;

use crate::println;

/// Timer ticks since interrupts were enabled.
static TICKS: AtomicU64 = AtomicU64::new(0);

/// Timer interrupts per second.
///
/// 100 Hz is deliberately unambitious. It is frequent enough to prove
/// delivery works and to drive a coarse clock, and slow enough that a bug in
/// the handler is visible as a stall rather than as a livelock the machine
/// cannot be interrupted out of. The tickless design in
/// `docs/scheduler.md` §7 replaces this entirely in M4.
pub const TIMER_HZ: u32 = 100;

/// Registers this module as the architecture's trap handler.
pub fn init() {
    bhaskix_arch::trap::set_handler(handle);
}

/// Timer ticks taken by each CPU.
///
/// The machine-wide count above cannot answer the question "tickless" is
/// actually about, which is per-CPU: whether *this* processor stopped taking
/// interrupts when it had nothing to run. A single counter can only be turned
/// into a ratio against a baseline, and the baseline -- the CPU doing the
/// measuring, which is busy by definition -- is exactly the term that moves
/// when the host is loaded.
static TICKS_PER_CPU: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];

/// Timer ticks observed so far.
#[must_use]
pub fn ticks() -> u64 {
    TICKS.load(Ordering::Relaxed)
}

/// Timer ticks taken by one CPU.
///
/// Zero for a CPU that does not exist, which is the same answer as a CPU that
/// has never ticked -- a caller that could tell them apart would be asking a
/// question about topology, not about ticking.
#[must_use]
pub fn ticks_on(cpu: u32) -> u64 {
    usize::try_from(cpu)
        .ok()
        .and_then(|cpu| TICKS_PER_CPU.get(cpu))
        .map_or(0, |count| count.load(Ordering::Relaxed))
}

/// Why interrupt bring-up failed.
#[derive(Clone, Copy, Debug)]
pub enum InterruptError {
    /// The CPU reports no Local APIC.
    NoLocalApic,
    /// The APIC timer frequency could not be measured.
    CalibrationFailed,
    /// The CPU has only xAPIC, and its register page could not be mapped.
    MapFailed(paging::MapError),
}

/// Masks the legacy PIC, brings up the Local APIC, and enables interrupts.
///
/// Returns the measured APIC timer frequency in hertz.
///
/// # Errors
///
/// Returns [`InterruptError`] if the CPU has no Local APIC or its timer could
/// not be calibrated. In either case interrupts are left disabled, which is
/// survivable — the kernel simply has no clock yet.
///
/// # Safety
///
/// Must be called once, on the bootstrap CPU, after the IDT is loaded and
/// while interrupts are still disabled. `hhdm_base` must be the higher-half
/// direct map base from the boot handoff.
pub unsafe fn enable(
    hhdm_base: VirtAddr,
    frames: &mut BumpAllocator,
) -> Result<u32, InterruptError> {
    // SAFETY: single-threaded boot with interrupts disabled, per the contract.
    unsafe {
        // The PIC first, and remapped rather than merely masked: a masked PIC
        // can still deliver spurious interrupts, and unremapped those land on
        // exception vectors (see `arch::pic`).
        pic::remap_and_mask();

        if !msr::has_local_apic() {
            return Err(InterruptError::NoLocalApic);
        }

        // x2APIC needs no mapping at all. xAPIC does, and the bootloader's
        // direct map does not cover it -- it maps RAM, and the APIC is not
        // RAM. So on those machines, map the one page it needs.
        //
        // This is the only mapping the kernel creates before M3, and it is
        // created here rather than in `arch` because only the kernel knows
        // where physical memory is mapped.
        let mapped = if apic::has_x2apic() {
            None
        } else {
            let physical = apic::physical_base();
            let virtual_address = PhysAddr(physical).to_hhdm(hhdm_base).as_u64();

            paging::map_device_page(virtual_address, physical, hhdm_base.as_u64(), &mut || {
                frames.allocate_frame().ok().map(|f| f.as_u64())
            })
            .map_err(InterruptError::MapFailed)?;

            Some(virtual_address as *mut u8)
        };

        let frequency = apic::init(mapped).map_err(|error| match error {
            apic::ApicError::NotSupported => InterruptError::NoLocalApic,
            apic::ApicError::NeedsMmuForXapic => InterruptError::NoLocalApic,
            apic::ApicError::CalibrationFailed => InterruptError::CalibrationFailed,
        })?;

        apic::start_timer(TIMER_HZ);
        cpu::enable_interrupts();

        Ok(frequency)
    }
}

/// Handles a trap.
///
/// A page fault the region map can service is serviced. Everything else is
/// reported in full, and then **who dies depends on who faulted**: a fault in
/// ring 3 ends that domain and the machine keeps running, a fault in the kernel
/// halts.
///
/// That asymmetry is the whole point of a domain, and it took until
/// [RFC 0017](../../docs/rfc/0017-process-management.md) step 1 to exist. Until
/// then this function halted for both, on the reasoning — written here, and
/// true when it was written — that there was "no memory manager to service a
/// page fault, no scheduler to kill a process, and no user mode to fault". All
/// three arrived in M3, M4 and M5, and the comment outlived the condition it
/// described: a null pointer in the shell stopped the console and the
/// filesystem, which had done nothing wrong.
fn handle(frame: &mut TrapFrame) {
    // Snapshotted at dispatch, compared at report. The run-312 crash dump of
    // 2026-08-17 printed "UNEXPECTED INTERRUPT on vector 65" from a path only
    // reachable when the vector read below 32 -- so between this line and the
    // report, either the frame mutated or the read went to different memory.
    // A local copy makes that contradiction printable instead of inferable.
    let dispatched = frame.vector;

    // Vectors below 32 are architectural exceptions; everything above is an
    // interrupt. The split matters because exceptions are faults in the
    // kernel's own execution and interrupts are not, so only one of them is
    // fatal.
    if frame.vector >= 32 {
        handle_interrupt(frame);
        // On the way back to ring 3, and only then: an interrupt that
        // preempted a thread may return to a *different* one, which is exactly
        // the moment a space could go unloaded. See `sched::check_user_space`.
        if frame.from_user_mode() {
            crate::sched::check_user_space(1);
        }
        return;
    }

    // Page faults are the one exception that is routinely *not* a bug. The
    // region map decides: if it says the address is valid, the fault is
    // serviced and the faulting instruction retries. Everything else falls
    // through to the report below.
    if frame.vector == 14 {
        // Bit 1 of the architectural error code distinguishes a write from a
        // read. Taken from the CPU rather than from any kernel bookkeeping,
        // because bookkeeping is what may be wrong when a fault is handled.
        let write = frame.error_code & (1 << 1) != 0;
        let address = read_cr2();

        match crate::vm::handle_fault(address, write) {
            crate::vm::FaultOutcome::Handled => {
                // **The fourth way back to ring 3, and the one the other three
                // did not cover.** A demand-paging fault taken in user mode is
                // serviced here and the instruction retried — a return to user
                // mode that is neither a system call nor an interrupt. If a
                // thread can arrive in the wrong space at all, this path had to
                // be ruled in or out like the others.
                if frame.from_user_mode() {
                    crate::sched::check_user_space(3);
                }
                return;
            }
            crate::vm::FaultOutcome::NotOurs => {
                // The region map could not service it. Before treating the
                // fault as a bug, check whether the faulting instruction is
                // one that is *allowed* to fault: the copy routines in
                // `uaccess` register themselves in the exception table so a
                // bad user pointer becomes an error return rather than a
                // panic.
                //
                // Checked after the region map, not before, so that a
                // legitimate demand-paging fault inside a copy is serviced
                // rather than reported as a bad pointer.
                if !frame.from_user_mode()
                    && let Some(recovery) = bhaskix_arch::uaccess::fixup_for(frame.rip)
                {
                    frame.rip = recovery;
                    return;
                }
            }
            crate::vm::FaultOutcome::Refused(reason) => {
                println!();
                println!("  the region map refused this access: {reason}");
            }
            crate::vm::FaultOutcome::Unserviceable(reason) => {
                println!();
                println!("  the fault was legal but could not be serviced: {reason}");
            }
            crate::vm::FaultOutcome::Retry => {
                // Another CPU briefly holds the address-space table.
                // Returning re-executes the faulting instruction, which
                // re-faults until the holder releases -- a spin at
                // fault-granularity, bounded by the holder's own critical
                // section.
                return;
            }
        }
    }

    report_exception(frame, dispatched);

    // A fault in ring 3 is the program's bug, not the machine's.
    if frame.from_user_mode() {
        end_faulting_domain();
    }

    println!("  Halting. A fault in the kernel is the kernel's own bug: there is");
    println!("  no other domain to blame, and no state left worth trusting.");
    println!("==================================================================");
    cpu::halt_forever()
}

/// Ends the domain whose thread just faulted in ring 3. Never returns.
///
/// **Why it is safe to take kernel locks here, in a handler.** The faulting
/// thread was executing *user* code — that is what `from_user_mode` means — and
/// there is no path by which ring 3 holds a kernel lock. So the domain table
/// and the capability arena cannot be held by the thread this interrupted, and
/// taking them cannot deadlock against it. Every part of that sentence is
/// load-bearing, which is why this is reached only from the user-mode branch
/// and not shared with the kernel one.
fn end_faulting_domain() -> ! {
    let thread = crate::sched::current_thread_id();

    // Everything is printed *before* the domain is destroyed, and the order is
    // not cosmetic. Destroying it is what any waiter is watching for, so a
    // report finished afterwards races the next thing that prints and arrives
    // shredded through it -- which is what the first version of this did, and
    // a fault report interleaved with three other gates is not a report.
    match crate::sched::current_domain() {
        Some(id) => {
            // Copied out rather than borrowed: a runtime-created domain's
            // name lives in the table, and this prints after the lock is gone.
            let name = crate::domain::name_of(id);
            let others = crate::domain::with(id, |domain| domain.threads()).unwrap_or(0);

            match name {
                Some(name) => {
                    println!("  Domain {name:?} is gone. Its capabilities are revoked, its memory")
                }
                None => println!("  The domain is gone. Its capabilities are revoked, its memory"),
            }
            println!("  released, and this machine is still running.");

            // Honest about what this step does not do. RFC 0017 step 2 is
            // thread ownership; until it lands, a sibling thread of the dead
            // domain keeps running with no capabilities at all -- contained,
            // but not stopped. Saying so beats a report implying the domain is
            // entirely gone when part of it is still scheduled.
            if others > 1 {
                println!(
                    "  {} other thread(s) of it are still scheduled: RFC 0017 step 2.",
                    others - 1
                );
            }
            match thread {
                Some(id) => println!("  Thread {id} stopped."),
                None => println!("  The faulting thread could not be identified."),
            }
            println!("==================================================================");

            // `Faulted`, not `Killed`. A supervisor deciding whether to
            // start this program again wants to know the difference between a
            // program that was stopped on purpose and one with a bug in it.
            crate::domain::end(id, crate::domain::Ending::Faulted);
        }
        None => {
            // A ring 3 thread outside any domain should not exist -- entering
            // user mode goes through `enter_user`, which requires one. Report
            // it rather than destroying something arbitrary, and still stop
            // the thread: whatever it is, it has faulted.
            println!("  This thread is in ring 3 and belongs to no domain, which should");
            println!("  not be possible. Stopping the thread; nothing else is touched.");
            match thread {
                Some(id) => println!("  Thread {id} stopped."),
                None => println!("  The faulting thread could not be identified."),
            }
            println!("==================================================================");
        }
    }

    // The interrupt gate cleared IF on entry. `exit` halts this CPU if it has
    // nothing else to run, and a halt with interrupts disabled is the machine
    // stopping after all -- which is the behaviour this function exists to
    // remove. Nothing is held here: the report is printed and every lock taken
    // above has been released.
    //
    // SAFETY: at CPL 0 in a handler that holds no lock, on a thread that is
    // about to stop. Re-entering this handler is impossible -- the faulting
    // instruction is never retried, because this never returns.
    unsafe { cpu::enable_interrupts() };
    crate::sched::exit()
}

/// Services a delivered interrupt and returns, so `iretq` resumes the
/// interrupted code.
fn handle_interrupt(frame: &mut TrapFrame) {
    match frame.vector as u8 {
        apic::TIMER_VECTOR => {
            TICKS.fetch_add(1, Ordering::Relaxed);
            if let Some(count) = usize::try_from(percpu::cpu_id())
                .ok()
                .and_then(|cpu| TICKS_PER_CPU.get(cpu))
            {
                count.fetch_add(1, Ordering::Relaxed);
            }
            // SAFETY: the APIC is initialised -- interrupts cannot be enabled
            // before `enable` succeeds -- and this acknowledges exactly the
            // interrupt currently in service.
            unsafe { apic::end_of_interrupt() };

            // Expire timers and choose when to fire next, before scheduling.
            // The order matters: a thread whose sleep has just elapsed must be
            // runnable before the arming decision asks whether this CPU has
            // anything to run, or the CPU decides it is idle and stops the
            // very timer that would have corrected it.
            //
            // SAFETY: this is the timer interrupt handler, after
            // acknowledgement, and the APIC is initialised.
            unsafe { crate::time::on_tick() };

            // Preemption, after the acknowledgement. The order matters: the
            // switch does not return until this thread is scheduled again, and
            // an unacknowledged interrupt would block every later one in the
            // meantime -- including the timer that would eventually schedule
            // it back.
            //
            // Switching from inside the handler works because the outgoing
            // stack still holds this interrupt's frame. When the thread is
            // resumed the switch returns here, the handler unwinds normally,
            // and `iretq` returns to wherever that thread was interrupted.
            crate::sched::preempt();

            // The second safe point. Only for a thread interrupted in *user*
            // mode: at that point it holds no kernel lock, because ring 3
            // cannot take one. A thread interrupted inside the kernel may hold
            // anything, and is left alone until it reaches a point where it
            // does not -- its syscall returning, or its next decision to
            // block.
            if frame.from_user_mode() && crate::sched::should_die() {
                crate::sched::exit()
            }
        }

        // Another CPU made something runnable here. There is nothing to do
        // beyond acknowledging and letting the scheduler look: the sender has
        // already marked the thread ready under this CPU's queue lock, and the
        // whole purpose of the interrupt is to make this CPU *look*, which an
        // idle CPU with its timer stopped would otherwise not do.
        crate::sched::RESCHEDULE_VECTOR => {
            // SAFETY: the APIC is initialised -- interrupts cannot be enabled
            // before `enable` succeeds.
            unsafe { apic::end_of_interrupt() };

            // This CPU may have been idle and tickless, armed only for the
            // one-second backstop. It has work now, so it needs a tick to
            // preempt with -- re-armed before scheduling, because `preempt`
            // may not return until much later.
            //
            // SAFETY: timer interrupt context, after acknowledgement, on a CPU
            // whose APIC is initialised.
            unsafe { crate::time::rearm_this_cpu() };

            crate::sched::preempt();
        }

        // TLB shootdown from another CPU. Acknowledged like any delivered
        // interrupt; the invalidation itself takes no locks, because this CPU
        // may have been interrupted anywhere.
        crate::tlb::SHOOTDOWN_VECTOR => {
            crate::tlb::handle_ipi();
            // SAFETY: the APIC is initialised -- interrupts cannot be enabled
            // before it is -- and this acknowledges the interrupt in service.
            unsafe { apic::end_of_interrupt() };
        }

        // A device interrupt on a vector something claimed (RFC 0011). The
        // vector is not a constant here and cannot be: it was allocated at
        // claim time, which is the whole point of having an allocator. The
        // handler masks the source and signals a notification -- nothing
        // else, ever, in interrupt context.
        vector if crate::irq::is_claimed(vector) => {
            crate::irq::on_interrupt(vector);
            // SAFETY: the APIC is initialised -- interrupts cannot be enabled
            // before it is -- and this acknowledges the interrupt in service.
            unsafe { apic::end_of_interrupt() };
        }

        // Spurious interrupts get no acknowledgement. The APIC never placed
        // them in service, so an EOI here would clear a *different*
        // interrupt's in-service bit -- losing a real interrupt in a way that
        // is close to impossible to trace back to this line.
        apic::SPURIOUS_VECTOR => {}
        vector if pic::is_spurious(u64::from(vector)) => {}

        _ => {
            // Unexpected, but not fatal: report once and keep running. Halting
            // the machine over a stray interrupt would be a worse failure than
            // the stray interrupt.
            println!();
            println!(
                "  unexpected interrupt on vector {:#04x} -- ignoring",
                frame.vector
            );
            // SAFETY: as above; a delivered interrupt above the spurious
            // vectors was placed in service and must be acknowledged.
            unsafe { apic::end_of_interrupt() };
        }
    }
}

/// The name of the frame field at `offset` bytes from the frame's base, or
/// where the qword sits relative to it. The layout is `TrapFrame`'s, stated
/// here as a match so the dump can never drift from the struct silently —
/// a mismatch prints a wrong *label* beside a right *address*, which the
/// next reader catches against the struct in one glance.
const fn frame_field(offset: i64) -> &'static str {
    match offset {
        i64::MIN..=-1 => "below the frame",
        0 => "r15",
        8 => "r14",
        16 => "r13",
        24 => "r12",
        32 => "r11",
        40 => "r10",
        48 => "r9",
        56 => "r8",
        64 => "rbp",
        72 => "rdi",
        80 => "rsi",
        88 => "rdx",
        96 => "rcx",
        104 => "rbx",
        112 => "rax",
        120 => "vector",
        128 => "error code",
        136 => "rip  (iret)",
        144 => "cs   (iret)",
        152 => "rflags (iret)",
        160 => "rsp  (iret)",
        168 => "ss   (iret)",
        _ => "above the frame",
    }
}

/// What address family a qword belongs to — the classification the run-312
/// and run-85 analyses did by hand, printed so the next specimen arrives
/// pre-sorted.
const fn shape_of(value: u64) -> &'static str {
    if value == 0 {
        return "";
    }
    if value >= 0xffff_ffff_8000_0000 {
        return "  [kernel image half]";
    }
    if value >= 0xffff_a000_0000_0000 && value < 0xffff_c000_0000_0000 {
        return "  [kernel stacks]";
    }
    if value >= 0xffff_8000_0000_0000 {
        return "  [direct map]";
    }
    if value < 0x0000_8000_0000_0000 {
        return "";
    }
    "  [NON-CANONICAL]"
}

/// The raw qwords around the frame, one line each, annotated — the
/// instrument run-85 asked for. Its finding was made by hand: the error
/// code equalled the low sixteen bits of the live `rbx`, and the `ss` slot
/// held a kernel pointer, which reads as register-shaped data written over
/// an in-flight frame. This prints the clobber's *pattern*: every qword in
/// the window, its expected role, its address family, and — the
/// fingerprint — whether it echoes one of the frame's own registers.
fn dump_frame_window(frame: &TrapFrame) {
    let base = core::ptr::from_ref(frame) as u64;
    let size = core::mem::size_of::<TrapFrame>() as u64;
    // Only the pages the frame itself occupies are known-mapped — the CPU
    // and the stub wrote the frame there. One qword beyond them is a gamble
    // on a guard page, and a nested fault inside the fatal report loses the
    // report, so the window clamps to those pages rather than discovering
    // the edge the hard way.
    let lo_mapped = base & !0xFFF;
    let hi_mapped = ((base + size - 1) & !0xFFF) + 0x1000;
    let lo = core::cmp::max(lo_mapped, base.saturating_sub(4 * 8));
    let hi = core::cmp::min(hi_mapped, base + size + 16 * 8);

    println!();
    println!("  raw stack window around the frame, low to high:");
    let named = [
        (frame.rax, "rax"),
        (frame.rbx, "rbx"),
        (frame.rcx, "rcx"),
        (frame.rdx, "rdx"),
        (frame.rsi, "rsi"),
        (frame.rdi, "rdi"),
        (frame.rbp, "rbp"),
        (frame.r8, "r8"),
        (frame.r9, "r9"),
        (frame.r10, "r10"),
        (frame.r11, "r11"),
        (frame.r12, "r12"),
        (frame.r13, "r13"),
        (frame.r14, "r14"),
        (frame.r15, "r15"),
    ];
    let mut at = lo;
    while at < hi {
        // SAFETY: `at` stays within pages the frame occupies, which are
        // mapped -- the frame was written there by the CPU and the stub --
        // and the read is an aligned qword with no side effects.
        let value = unsafe { core::ptr::read_volatile(at as *const u64) };
        let offset = at as i64 - base as i64;
        let mut echo = "";
        let mut partial = "";
        if offset >= 120 {
            // Only the slots past the pushed registers are interesting to
            // fingerprint: a register slot equalling its register is the
            // frame working. Small values are excluded from the full-match
            // — a selector equalling a register that happens to hold 0x10
            // is coincidence, not contamination.
            for (register, name) in named {
                if value == register && value > 0xFFFF {
                    echo = name;
                    break;
                }
            }
            // The vector and error slots expect small values, and run-85's
            // decisive clue was a *fragment*: an error code equalling the
            // low sixteen bits of a live pointer register. Flagged only for
            // pointer-shaped registers, so a genuinely small error code
            // cannot echo a genuinely small register by accident.
            if echo.is_empty() && (offset == 120 || offset == 128) && value != 0 {
                for (register, name) in named {
                    if register > u64::from(u32::MAX) && register & 0xFFFF == value & 0xFFFF {
                        partial = name;
                        break;
                    }
                }
            }
        }
        if !echo.is_empty() {
            println!(
                "    {:#018x}  {:#018x}  {}{}  = live {}",
                at,
                value,
                frame_field(offset),
                shape_of(value),
                echo
            );
        } else if !partial.is_empty() {
            println!(
                "    {:#018x}  {:#018x}  {}{}  low bits echo live {}",
                at,
                value,
                frame_field(offset),
                shape_of(value),
                partial
            );
        } else {
            println!(
                "    {:#018x}  {:#018x}  {}{}",
                at,
                value,
                frame_field(offset),
                shape_of(value)
            );
        }
        at += 8;
    }
}

/// Reports an exception in full, and returns.
///
/// Returns rather than halting because the verdict is no longer the same for
/// every fault: the caller decides whether this ends a domain or the machine.
/// Everything above that line is identical for both, and deliberately so — the
/// report is the most valuable thing this kernel produces when something goes
/// wrong, and it should not get thinner because the fault turned out to be
/// survivable.
fn report_exception(frame: &mut TrapFrame, dispatched: u64) {
    // From here on the machine is being reported dead, and every print
    // must reach the wire even if another CPU wedged holding the console
    // lock -- run-80's report stopped at its fifth line for exactly that.
    crate::console::enter_fatal();
    println!();
    println!("==================================================================");
    match exception_name(frame.vector) {
        Some(name) => println!("  EXCEPTION: {name}"),
        None => println!("  UNEXPECTED INTERRUPT on vector {}", frame.vector),
    }
    println!("==================================================================");

    // The densest line first, and first on purpose: the run-312 specimen was
    // cut off by the harness cap five lines into the report, and everything
    // this line carries was in the part that never printed. CR2 is read
    // unconditionally -- stale for a non-#PF, but a stale value beside the
    // vector costs one word and the alternative cost a specimen.
    {
        let cpu = bhaskix_arch::percpu::cpu_id();
        let thread = crate::sched::current_thread_id();
        let cr2 = read_cr2();
        // SAFETY: reading CR3 at CPL 0 has no side effects.
        let cr3 = unsafe { bhaskix_arch::paging::active_page_table() };
        println!(
            "  cpu {cpu} thread {:?}; frame at {:p}; error {:#x} cr2 {:#x} cr3 {:#x}",
            thread, frame as *const TrapFrame, frame.error_code, cr2, cr3,
        );
    }
    if dispatched != frame.vector {
        println!(
            "  THE FRAME CHANGED UNDER THE HANDLER: dispatched as vector {dispatched}, the \
             frame now says {} -- the report below describes memory that was not what the \
             dispatch read",
            frame.vector,
        );
    }

    println!(
        "  vector {:#04x}   from {} mode",
        frame.vector,
        if frame.from_user_mode() {
            "USER"
        } else {
            "kernel"
        }
    );

    if has_error_code(frame.vector) {
        println!("  error code {:#018x}", frame.error_code);
        decode_error_code(frame);
    }

    // Whose program this is, and whether it is running in its own memory.
    //
    // A fault from ring 3 says `rip` and `rsp`, and both are useless when every
    // program in the tree is linked and stacked at the same addresses -- which
    // they are, and which sent one investigation into the wrong program twice.
    // The thread's name and the two page-table roots say it directly: if `CR3`
    // is not the space this thread is supposed to be in, that is the fault, and
    // whatever the address looks like is a consequence.
    if frame.from_user_mode()
        && let Some(me) = crate::sched::current_thread_id()
        && let Some((name, expected)) = crate::sched::describe(me)
    {
        // SAFETY: reading CR3 at CPL 0 has no side effects.
        let loaded = unsafe { bhaskix_arch::paging::active_page_table() };
        println!();
        println!("  thread {me} ({name}) expects space {expected:#x}, cr3 holds {loaded:#x}");
        if expected != 0 && expected != loaded {
            println!("    IT IS RUNNING IN SOMEBODY ELSE'S ADDRESS SPACE");

            // What the last few switches decided, oldest first. `enter_space`
            // returns without touching `CR3` when the root is zero, so a switch
            // that resumed a user thread with no space is how the wrong one
            // stays loaded — and a zero here beside this thread's identifier is
            // that, caught.
            let (without_space, without_thread) = crate::sched::switch_gaps();
            println!(
                "      {without_space} switches resumed with no space to load, \
                 {without_thread} with no thread at all"
            );
            let (wrong, unchecked) = crate::sched::exit_check_counts();
            println!(
                "      exits to ring 3 with the wrong space: {wrong} ({unchecked} not checked, \
                 runqueue busy)"
            );
            crate::sched::replay_exit_checks(|site, thread, loaded| {
                let where_ = match site {
                    0 => "syscall",
                    1 => "interrupt",
                    2 => "first entry",
                    _ => "serviced fault",
                };
                println!("      exit: t{thread} left {where_} with {loaded:#x} loaded");
            });
            crate::sched::replay_switches(|thread, space| {
                if space == 0 {
                    println!("      switch: t{thread} resumed with no space");
                } else {
                    println!("      switch: t{thread} -> {space:#x}");
                }
            });
        }
    }

    println!();
    println!("  rip {:#018x}   cs  {:#06x}", frame.rip, frame.cs);
    println!("  rsp {:#018x}   ss  {:#06x}", frame.rsp, frame.ss);
    println!(
        "  rflags {:#018x}  [{}]",
        frame.rflags,
        decode_rflags(frame.rflags)
    );

    println!();
    println!("  rax {:#018x}  rbx {:#018x}", frame.rax, frame.rbx);
    println!("  rcx {:#018x}  rdx {:#018x}", frame.rcx, frame.rdx);
    println!("  rsi {:#018x}  rdi {:#018x}", frame.rsi, frame.rdi);
    println!("  rbp {:#018x}  r8  {:#018x}", frame.rbp, frame.r8);
    println!("  r9  {:#018x}  r10 {:#018x}", frame.r9, frame.r10);
    println!("  r11 {:#018x}  r12 {:#018x}", frame.r11, frame.r12);
    println!("  r13 {:#018x}  r14 {:#018x}", frame.r13, frame.r14);
    println!("  r15 {:#018x}", frame.r15);

    println!();
    println!("  cr0 {:#018x}  cr2 {:#018x}", read_cr0(), read_cr2());
    println!("  cr3 {:#018x}  cr4 {:#018x}", read_cr3(), read_cr4());

    dump_frame_window(frame);

    if frame.vector == 8 {
        println!();
        println!("  A double fault means a second fault occurred while delivering");
        println!("  the first. The most common cause is kernel stack overflow: the");
        println!("  stack ran into its guard page, and the CPU could not push a");
        println!("  fault frame to report it.");
        println!("  This handler runs on its own IST stack, which is why you are");
        println!("  reading this instead of watching the machine reboot.");
    }

    println!("------------------------------------------------------------------");
}

/// Decodes the architecture-defined error code into words.
///
/// The hex value alone requires a manual reference lookup at exactly the
/// moment someone is least equipped to do one.
fn decode_error_code(frame: &TrapFrame) {
    let code = frame.error_code;

    if frame.vector == 14 {
        // Page fault. The bits describe what the access was, not what was
        // wrong -- which is the part people consistently misread, so it is
        // spelled out.
        let address = read_cr2();
        println!("  faulting address {address:#018x}   (cr2)");
        println!(
            "    {} while {} in {} mode{}{}",
            if code & 1 == 0 {
                "page not present"
            } else {
                "protection violation"
            },
            if code & (1 << 1) == 0 {
                "reading"
            } else {
                "writing"
            },
            if code & (1 << 2) == 0 {
                "kernel"
            } else {
                "user"
            },
            if code & (1 << 3) != 0 {
                ", reserved bit set in a page table entry"
            } else {
                ""
            },
            if code & (1 << 4) != 0 {
                ", on an instruction fetch"
            } else {
                ""
            },
        );

        if address < 0x1000 {
            println!("    address is in the first page: this is a null pointer dereference");
        }
        return;
    }

    // Selector-style error codes: #TS, #NP, #SS, #GP.
    if matches!(frame.vector, 10..=13) {
        if code == 0 {
            println!("    not segment-related (error code is zero)");
            return;
        }
        let table = match (code >> 1) & 0b11 {
            0 => "GDT",
            1 => "IDT",
            2 => "LDT",
            _ => "IDT",
        };
        println!(
            "    {} selector index {:#x} in the {}{}",
            if code & 1 != 0 {
                "external event referencing"
            } else {
                "referencing"
            },
            (code >> 3) & 0x1fff,
            table,
            if code & 1 != 0 {
                " (raised by an external interrupt)"
            } else {
                ""
            },
        );
    }
}

/// Renders the interesting RFLAGS bits.
fn decode_rflags(rflags: u64) -> &'static str {
    // Only the two that change how a fault should be read: whether interrupts
    // were enabled, and the direction flag, which breaks the SysV ABI if set.
    match (rflags & (1 << 9) != 0, rflags & (1 << 10) != 0) {
        (true, true) => "IF DF",
        (true, false) => "IF",
        (false, true) => "DF",
        (false, false) => "-",
    }
}

macro_rules! read_control_register {
    ($name:ident, $register:literal) => {
        /// Reads the named control register.
        fn $name() -> u64 {
            let value: u64;
            // SAFETY: reading a control register at CPL 0 has no side effects
            // and cannot fault. Kernel code always runs at CPL 0.
            unsafe {
                core::arch::asm!(
                    concat!("mov {}, ", $register),
                    out(reg) value,
                    options(nomem, nostack, preserves_flags)
                );
            }
            value
        }
    };
}

read_control_register!(read_cr0, "cr0");
read_control_register!(read_cr2, "cr2");
read_control_register!(read_cr3, "cr3");
read_control_register!(read_cr4, "cr4");
