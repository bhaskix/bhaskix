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

use bhaskix_arch::cpu;
use bhaskix_arch::idt::{exception_name, has_error_code};
use bhaskix_arch::trap::TrapFrame;

use crate::println;

/// Registers this module as the architecture's trap handler.
pub fn init() {
    bhaskix_arch::trap::set_handler(handle);
}

/// Handles a trap.
///
/// Currently every trap is fatal: there is no memory manager to service a page
/// fault, no scheduler to kill a process, and no user mode to fault. Halting
/// with a full report is the correct behaviour at M2, and this function is
/// where recoverable cases get added in M3 and M5.
fn handle(frame: &mut TrapFrame) {
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
    println!("  Halting. Every exception is fatal at M2 -- there is no memory");
    println!("  manager to service a fault and no scheduler to kill a task.");
    println!("==================================================================");

    cpu::halt_forever()
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
