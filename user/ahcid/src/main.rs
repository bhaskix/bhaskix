// SPDX-License-Identifier: Apache-2.0
//! The AHCI driver, in a domain of its own.
//!
//! [RFC 0046](../../../docs/rfc/0046-a-driver-for-hardware-that-exists.md)
//! step 3b. Every storage device this system could drive was virtio -- a device
//! that exists because an emulator invents it. This one drives a SATA
//! controller that is on the emulator's `q35` and on the Lenovo SR550 alike.
//!
//! # What it holds, and what it cannot reach
//!
//! - two `Frame`s covering the controller's register file, which the kernel
//!   found by reading a BAR this program cannot read;
//! - a `Memory` object it leaves its findings in;
//! - a `DmaWindow` for its own device, where there is a unit to make one.
//!
//! It does not hold the bus. Finding the controller means reading PCI
//! configuration space, which is port I/O, and a domain holding that would hold
//! every device on the machine.
//!
//! # Why there is so little here
//!
//! `user/*` crates are separate workspaces, so `cargo test --workspace` never
//! reaches them and **nothing written in this file has a host test**. So
//! nothing that can be got wrong is written here: the register arithmetic, the
//! bring-up order, the deadlines and the refusals all live in `bhaskix-ahci`,
//! which the suite does reach and which is `forbid(unsafe_code)`. What is left
//! is the pair of accesses that crate deliberately cannot perform.
#![no_std]
#![no_main]

use bhaskix_abi::{method, status, syscall};
use bhaskix_ahci::{self as ahci, Registers};

/// Slot: the first page of the controller's register file.
const ABAR_LOW: u64 = 0;
/// Slot: the second, which is where ports 24 to 31 live.
const ABAR_HIGH: u64 = 1;
/// Slot: memory for the report, and later for the command list.
const MEMORY: u64 = 2;
/// Slot: the authority to say what this device may reach.
///
/// Unused at this step and held anyway, because holding it is what the next
/// step needs and because its *absence* is what the report has to say: a
/// controller nothing would contain is a controller this driver will not point
/// at memory.
const WINDOW: u64 = 3;

/// Where the register file goes in this program's address space.
const ABAR_AT: u64 = 0x2000_0000;
/// Where its own memory goes.
const MEMORY_AT: u64 = 0x2010_0000;
/// Where in it the report sits: the **last** of the four pages.
///
/// Every earlier one becomes a command list, a received-FIS area or a data
/// buffer at the next step -- structures the *controller* reads and writes -- and
/// a report living in any of them would be a report a bus master could
/// overwrite. `bin/blkd` and `bin/netd` put theirs in their last page for the
/// same reason, and moving it later would be moving it after something depends
/// on where it is.
const REPORT_AT: u64 = MEMORY_AT + 0x3000;

/// How long any single register may take to settle, in nanoseconds.
///
/// The specification's own figure for a reset is a second, and a controller
/// that has not answered in five is not going to. A deadline and never a spin
/// count: a count is a wait whose length depends on how fast the machine is.
const SETTLE_NS: u64 = 5_000_000_000;

/// A word the kernel looks for, so a zeroed page is not mistaken for a report
/// nobody wrote. `AHCIRPT1` in ASCII.
const MARKER: u64 = 0x4148_4349_5250_5431;

/// Issues one system call, and returns `(status, value)`.
fn call(kind: u64, capability: u64, method: u64, args: [u64; 4]) -> (u64, u64) {
    let status: u64;
    let mut value = args[0];
    // SAFETY: the system call convention from RFC 0008. Nothing is
    // dereferenced on this side, and every argument register is declared as an
    // output because the kernel writes the whole frame back on the way out.
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") kind => status,
            inlateout("rdi") capability => _,
            inlateout("rsi") method => _,
            inlateout("rdx") value,
            inlateout("r10") args[1] => _,
            inlateout("r8") args[2] => _,
            inlateout("r9") args[3] => _,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    (status, value)
}

/// Maps a capability at an address, and says whether it worked.
fn attach(slot: u64, at: u64, writable: u64) -> bool {
    call(syscall::INVOKE, slot, method::ATTACH, [at, writable, 0, 0]).0 == status::OK
}

/// Ends this program. Never returns.
fn exit() -> ! {
    call(syscall::EXIT, 0, 0, [0; 4]);
    #[allow(clippy::empty_loop)]
    loop {}
}

/// The cycle counter.
fn rdtsc() -> u64 {
    let low: u32;
    let high: u32;
    // SAFETY: `rdtsc` reads a counter and touches no memory.
    unsafe {
        core::arch::asm!("rdtsc", out("eax") low, out("edx") high, options(nomem, nostack));
    }
    (u64::from(high) << 32) | u64::from(low)
}

/// Monotonic nanoseconds.
///
/// 128-bit intermediate for the reason `bin/tcpd` gives: `tsc * 1_000_000_000`
/// overflows a `u64` eighteen seconds after reset on a gigahertz counter, and a
/// clock that wraps during boot fires every armed deadline at once.
fn now_nanos(hertz: u64) -> u64 {
    if hertz == 0 {
        return 0;
    }
    (u128::from(rdtsc()) * 1_000_000_000 / u128::from(hertz)) as u64
}

/// The controller's register file, as a mapping this program was given.
///
/// **The whole of this driver's unsafe surface.** Everything that decides
/// *which* offset, and in what order, is in `bhaskix-ahci` under
/// `forbid(unsafe_code)`; this is the two operations that crate cannot perform.
struct Abar {
    base: u64,
    /// How many bytes were mapped. An offset past this is a bug in the caller
    /// and would otherwise be a wild access into whatever follows the mapping.
    length: u64,
}

impl Registers for Abar {
    fn read(&self, offset: usize) -> u32 {
        let offset = offset as u64;
        if offset + 4 > self.length {
            // Not a panic. A driver that faults takes its domain down and says
            // nothing; a driver that answers a nonsense register with all-ones
            // reads the way a controller that is not there does, and the
            // sequence above already refuses that.
            return u32::MAX;
        }
        // SAFETY: inside the mapping this program attached, checked above, and
        // four-byte aligned because every AHCI register offset is.
        unsafe { core::ptr::read_volatile((self.base + offset) as *const u32) }
    }

    fn write(&mut self, offset: usize, value: u32) {
        let offset = offset as u64;
        if offset + 4 > self.length {
            return;
        }
        // SAFETY: as `read`, and this is a register of a controller no other
        // domain holds.
        unsafe { core::ptr::write_volatile((self.base + offset) as *mut u32, value) };
    }
}

/// Leaves the findings where the kernel reads them.
///
/// The marker last, with a fence before it, so a kernel that sees the marker
/// sees everything under it.
fn report(up: Result<ahci::Started, ahci::NotUp>, translated: bool) {
    // One word, one `unsafe`, so the report below is ordinary code.
    //
    // `bin/blkd` writes its report inside a single block spanning forty lines,
    // which is forty lines of budget for one fact. Here the fact is stated once
    // and the rest of this function is safe -- which matters more for this
    // driver than for that one, because the whole claim of this program is that
    // its unsafe surface is small enough to read.
    fn put(index: usize, value: u64) {
        // SAFETY: inside the four pages this program holds and mapped
        // writable. `index` is a small constant at every call site and the
        // report lives in the last page, so nothing here can reach a structure
        // the controller is given.
        unsafe { core::ptr::write_volatile((REPORT_AT as *mut u64).add(index), value) };
    }

    {
        match up {
            Ok(started) => {
                put(1, 1);
                put(2, u64::from(started.implemented));
                put(3, u64::from(started.slots));
                put(4, u64::from(started.version));
                put(5, u64::from(started.sixty_four_bit));
                put(6, u64::from(started.queuing));
                put(7, u64::from(started.took_from_firmware));
                put(8, started.port_count as u64);
                put(9, u64::from(translated));
                // One word per port: index, DET, IPM and signature packed so
                // the kernel prints what the controller said rather than what
                // this program concluded.
                for (slot, port) in started.ports().enumerate() {
                    let packed = u64::from(port.index)
                        | (u64::from(port.det) << 8)
                        | (u64::from(port.ipm) << 16)
                        | (u64::from(port.signature) << 32);
                    put(16 + slot, packed);
                }
            }
            Err(why) => {
                put(1, 0);
                // Which register did not settle, as an index the kernel turns
                // back into a name. A number rather than a pointer, because a
                // pointer into this program's rodata means nothing over there.
                let (kind, detail) = match why {
                    ahci::NotUp::NotSettled("GHC.HR") => (1, 0),
                    ahci::NotUp::NotSettled("BOHC.BOS") => (1, 1),
                    ahci::NotUp::NotSettled("PxCMD.CR") => (1, 2),
                    ahci::NotUp::NotSettled("PxCMD.FR") => (1, 3),
                    ahci::NotUp::NotSettled(_) => (1, 4),
                    ahci::NotUp::NoPortsImplemented => (2, 0),
                    ahci::NotUp::Misaligned(_) => (3, 0),
                    ahci::NotUp::Above4Gib => (4, 0),
                    ahci::NotUp::NoSuchPort => (5, 0),
                };
                put(2, kind);
                put(3, detail);
                put(9, u64::from(translated));
            }
        }
        core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
        put(0, MARKER);
    }
}

/// The driver.
///
/// `hertz` is the cycle counter's rate, handed over at entry because a program
/// in ring 3 has no way to calibrate one and a deadline needs it.
#[unsafe(no_mangle)]
extern "C" fn ahcid_main(hertz: u64) -> ! {
    // Two pages, which covers the whole of the standard register file: the
    // generic host control block is 0x100 and thirty-two ports of 0x80 follow
    // it, so the last byte AHCI defines is at 0x10ff.
    let low = attach(ABAR_LOW, ABAR_AT, 1);
    let high = attach(ABAR_HIGH, ABAR_AT + 0x1000, 1);
    let memory = attach(MEMORY, MEMORY_AT, 1);
    if !low || !memory {
        // Nothing can be said and nowhere to say it.
        exit();
    }

    // The window is not used at this step -- nothing is issued, so nothing does
    // DMA -- but whether it exists is the difference between a controller this
    // driver could later drive and one it must refuse. `MAP` is the only
    // question that can be asked of it from here.
    let translated = call(syscall::INVOKE, WINDOW, method::MAP, [MEMORY, 0, 0, 0]).0 == status::OK;

    let mut registers = Abar {
        base: ABAR_AT,
        length: if high { 0x2000 } else { 0x1000 },
    };
    let mut clock = || now_nanos(hertz);
    let up = ahci::bring_up(&mut registers, &mut clock, SETTLE_NS);
    report(up, translated);
    exit()
}

/// Stops where the kernel can see it.
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    // SAFETY: `ud2` raises an invalid-opcode fault, which is the point.
    unsafe { core::arch::asm!("ud2", options(noreturn)) }
}

// The entry point. `rbp` is zeroed so a walker stops here, and the stack is
// aligned because the ABI promises a callee that it is.
core::arch::global_asm!(
    r#"
.section .text._start,"ax",@progbits
.globl _start
_start:
    xor rbp, rbp
    and rsp, -16
    call ahcid_main
    ud2
"#
);
