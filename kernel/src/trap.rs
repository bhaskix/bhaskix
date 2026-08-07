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
    // Vectors below 32 are architectural exceptions; everything above is an
    // interrupt. The split matters because exceptions are faults in the
    // kernel's own execution and interrupts are not, so only one of them is
    // fatal.
    if frame.vector >= 32 {
        handle_interrupt(frame);
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
            crate::vm::FaultOutcome::Handled => return,
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
        }
    }

    report_exception(frame);

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
            let name = crate::domain::with(id, |domain| domain.name()).unwrap_or("?");
            let others = crate::domain::with(id, |domain| domain.threads()).unwrap_or(0);

            println!("  Domain {name:?} is gone. Its capabilities are revoked, its memory");
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

            crate::domain::destroy(id);
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

/// Reports an exception in full, and returns.
///
/// Returns rather than halting because the verdict is no longer the same for
/// every fault: the caller decides whether this ends a domain or the machine.
/// Everything above that line is identical for both, and deliberately so — the
/// report is the most valuable thing this kernel produces when something goes
/// wrong, and it should not get thinner because the fault turned out to be
/// survivable.
fn report_exception(frame: &mut TrapFrame) {
    println!();
    println!("==================================================================");
    match exception_name(frame.vector) {
        Some(name) => println!("  EXCEPTION: {name}"),
        None => println!("  UNEXPECTED INTERRUPT on vector {}", frame.vector),
    }
    println!("==================================================================");

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
