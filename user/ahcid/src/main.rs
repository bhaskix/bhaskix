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

/// How many bytes of sector zero are carried back for the report.
///
/// Thirty-two: enough to hold the string the image builder writes there, which
/// is what the gate greps for, and short enough that the report stays one line.
const FIRST_BYTES: usize = 32;

/// Whether sector zero was read: 0 not attempted, 1 read, 2 refused by the
/// device or the bus, 3 refused by this driver before it was issued.
static READ_STATE: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// Why, when it was 2.
static READ_WHY: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// The first [`FIRST_BYTES`] of it, packed little-endian.
static FIRST: [core::sync::atomic::AtomicU64; FIRST_BYTES / 8] = [
    core::sync::atomic::AtomicU64::new(0),
    core::sync::atomic::AtomicU64::new(0),
    core::sync::atomic::AtomicU64::new(0),
    core::sync::atomic::AtomicU64::new(0),
];

/// What the started port's device said it is, and which port it was.
static SIGNATURE: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static PORT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(u64::MAX);

/// Where the window said this program's memory is, as the controller sees it.
///
/// Reported because it is the number every structure below is built from, and
/// because a driver in a domain cannot be asked what it thinks afterwards.
static DEVICE_BASE: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Where the register file goes in this program's address space.
const ABAR_AT: u64 = 0x2000_0000;
/// Where its own memory goes.
const MEMORY_AT: u64 = 0x2010_0000;
/// Where the command list sits: the start of page zero.
///
/// 1 KiB and 1 KiB aligned, which a page boundary gives for nothing. The
/// received-FIS area follows it at 0x400 -- 256-aligned, as it must be -- and
/// the two do not overlap because the list is exactly 1 KiB.
const LIST_AT: u64 = 0;
/// The received-FIS area, which the controller writes and this program reads.
const FIS_AT: u64 = 0x400;
/// The command table: page one, so its 128-byte alignment is free.
const TABLE_AT: u64 = 0x1000;
/// Where `IDENTIFY`'s 512 bytes land: page two, alone, because it is the one
/// buffer a *device* writes and nothing else may share a page with it.
const BUFFER_AT: u64 = 0x2000;

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

/// Where the driver leaves how far it got, **written as it goes**.
///
/// The marker at word zero says "there is a finished report here"; this says
/// "this is where I am". Without it a driver that hangs or faults is
/// indistinguishable from one that never started, and step 4's first boot spent
/// two boots being exactly that. A zeroed page reads stage 0, which is
/// "never ran" and is the truth.
const STAGE_AT: usize = 12;

/// Mapped its registers and its memory.
///
/// **The first stage there can be, and that is not a choice.** Recording a
/// stage means writing to this memory, so nothing before the attach can be
/// recorded -- which is why "never ran", "could not map its registers" and
/// "could not reach its own memory" are one answer rather than three. The first
/// attempt put a stage above this one and faulted on it immediately, which is
/// the mistake this paragraph exists to stop somebody repeating.
const STAGE_ATTACHED: u64 = 1;
/// Asked the window for a device address.
const STAGE_MAPPED: u64 = 2;
/// Finished the bring-up, one way or the other.
const STAGE_BROUGHT_UP: u64 = 3;
/// Started a port.
const STAGE_PORT_STARTED: u64 = 4;
/// Built the command.
const STAGE_BUILT: u64 = 5;
/// Issued it, and is waiting.
const STAGE_ISSUED: u64 = 6;
/// The command came back.
const STAGE_ANSWERED: u64 = 7;
/// The disk's answer parsed, and a read of sector zero was planned.
const STAGE_PLANNED: u64 = 8;
/// That read came back.
const STAGE_READ: u64 = 9;

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

/// Monotonic nanoseconds, and **it must always advance**.
///
/// 128-bit intermediate for the reason `bin/tcpd` gives: `tsc * 1_000_000_000`
/// overflows a `u64` eighteen seconds after reset on a gigahertz counter, and a
/// clock that wraps during boot fires every armed deadline at once.
///
/// # Why a zero rate is not answered with zero
///
/// `bin/tcpd` answers zero, and can: it falls back to a yield. A driver cannot.
/// Every wait in `bhaskix-ahci` is `now - started >= budget`, so a clock stuck
/// at zero makes every deadline unreachable and turns each bounded wait into a
/// **hang** -- which is exactly what happened on the first boot of step 4, and
/// which the comment in this program's own trampoline claimed would not.
///
/// So an uncalibrated counter falls back to the raw cycle count read as though
/// one cycle were one nanosecond. The scale is wrong and the direction of the
/// error is the safe one: on any real machine a cycle is well under a
/// nanosecond, so the deadline fires *early*. An early refusal is a report; a
/// clock that never moves is a machine that never finishes booting.
fn now_nanos(hertz: u64) -> u64 {
    let ticks = rdtsc();
    if hertz == 0 {
        return ticks;
    }
    (u128::from(ticks) * 1_000_000_000 / u128::from(hertz)) as u64
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

/// Records how far this program has got, for a kernel that finds no report.
fn stage(which: u64) {
    // SAFETY: inside the four pages this program holds and mapped writable, in
    // the last of them, at a fixed index well inside the page.
    unsafe { core::ptr::write_volatile((REPORT_AT as *mut u64).add(STAGE_AT), which) };
}

/// Leaves the findings where the kernel reads them.
///
/// The marker last, with a fence before it, so a kernel that sees the marker
/// sees everything under it.
fn report(
    up: Result<ahci::Started, ahci::NotUp>,
    translated: bool,
    identity: Option<Result<ahci::Identity, ahci::Failed>>,
) {
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
                put(10, DEVICE_BASE.load(core::sync::atomic::Ordering::Relaxed));
                put(
                    11,
                    u64::from(SIGNATURE.load(core::sync::atomic::Ordering::Relaxed)),
                );
                put(13, PORT.load(core::sync::atomic::Ordering::Relaxed));
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
        // What the disk said about itself, or why it did not. Words 48 up, so
        // the per-port block below 48 can grow to all thirty-two without
        // moving this.
        match identity {
            None => put(48, 0),
            Some(Ok(disk)) => {
                put(48, 1);
                put(49, disk.sectors);
                put(50, disk.sector_bytes as u64);
                put(51, u64::from(disk.lba48));
                put(52, READ_STATE.load(core::sync::atomic::Ordering::Relaxed));
                put(53, READ_WHY.load(core::sync::atomic::Ordering::Relaxed));
                for (word, cell) in FIRST.iter().enumerate() {
                    put(56 + word, cell.load(core::sync::atomic::Ordering::Relaxed));
                }
            }
            Some(Err(why)) => {
                put(48, 2);
                let (kind, detail) = match why {
                    ahci::Failed::TimedOut => (1u64, 0u64),
                    ahci::Failed::Device(error) => (2, u64::from(error)),
                    ahci::Failed::Bus(bits) => (3, u64::from(bits)),
                    ahci::Failed::NoSuchSlot => (4, 0),
                };
                put(49, kind);
                put(50, detail);
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
    stage(STAGE_ATTACHED);

    // The window is not used at this step -- nothing is issued, so nothing does
    // DMA -- but whether it exists is the difference between a controller this
    // driver could later drive and one it must refuse. `MAP` is the only
    // question that can be asked of it from here.
    let (mapped, device_base) = call(syscall::INVOKE, WINDOW, method::MAP, [MEMORY, 0, 0, 0]);
    let translated = mapped == status::OK;
    DEVICE_BASE.store(device_base, core::sync::atomic::Ordering::Relaxed);
    stage(STAGE_MAPPED);

    let mut registers = Abar {
        base: ABAR_AT,
        length: if high { 0x2000 } else { 0x1000 },
    };
    // **The clock yields, and that is not decoration.** RFC 0046 chose polling
    // before interrupts on purpose, and a polling loop in ring 3 that never
    // yields does not merely waste a CPU: pinned to the same one the boot
    // thread is on, it starves it, and the kernel's own three-second wait for
    // this driver's report never gets to run. Step 4 spent three boots looking
    // like a hung *driver* when what was hung was everything else on that CPU.
    //
    // Every deadline check in `bhaskix-ahci` calls this, so putting the yield
    // here puts one in every wait the crate has, without the crate -- which is
    // `no_std` and holds no capability -- needing to know a system call exists.
    let mut clock = || {
        call(syscall::YIELD, 0, 0, [0; 4]);
        now_nanos(hertz)
    };
    let up = ahci::bring_up(&mut registers, &mut clock, SETTLE_NS);
    stage(STAGE_BROUGHT_UP);

    // **Report the bring-up before issuing anything.** Said once so it is not
    // rediscovered: a driver that reports only at the end tells you nothing
    // when the thing it does in between is what fails, and the kernel's reader
    // then has a zeroed page and no way to say why. Step 4 spent three boots
    // in exactly that position. This report is overwritten below with the
    // identity when there is one; the stage word carries how far it got either
    // way.
    report(up, translated, None);

    // RFC 0046 step 4: the first command, on the first port that has a disk.
    //
    // Only with a window. Every structure below is an address the *controller*
    // reads, and without a translation this program cannot name one -- which is
    // the refusal RFC 0012 asks for and not a shortcoming. A driver that
    // guessed would be aiming a bus master with numbers that mean nothing.
    let identity = match (&up, translated) {
        (Ok(started), true) => identify(&mut registers, started, &mut clock, device_base),
        _ => None,
    };

    report(up, translated, identity);
    exit()
}

/// Asks the first port with a disk on it what that disk is.
///
/// Returns `None` when there is no such port, which is not a failure: five of
/// six ports being empty is what a machine looks like.
fn identify(
    registers: &mut Abar,
    started: &ahci::Started,
    clock: &mut impl FnMut() -> u64,
    device_base: u64,
) -> Option<Result<ahci::Identity, ahci::Failed>> {
    let port = started.ports().find(|port| port.has_device())?.index as usize;

    // The structures, at addresses the controller sees. `device_base` is what
    // `MAP` answered for this program's memory; the offsets are the same ones
    // it mapped for itself, so the two views agree by construction rather than
    // by a second calculation that could disagree.
    if ahci::start_port(
        registers,
        started,
        port,
        device_base + LIST_AT,
        device_base + FIS_AT,
    )
    .is_err()
    {
        return Some(Err(ahci::Failed::NoSuchSlot));
    }
    stage(STAGE_PORT_STARTED);

    // **What kind of device this is, before asking it anything.** `PxSIG` is
    // only meaningful now that the port is started and the device has sent its
    // first D2H FIS. `IDENTIFY DEVICE` is *aborted* by an ATAPI device -- the
    // specification says so -- and QEMU's `q35` puts the boot CD on this very
    // controller, so issuing it blind means reading the specification out of an
    // error code.
    let sig = ahci::read_signature(registers, port);
    SIGNATURE.store(sig, core::sync::atomic::Ordering::Relaxed);
    PORT.store(port as u64, core::sync::atomic::Ordering::Relaxed);
    if ahci::device_kind(sig) != ahci::DeviceKind::Disk {
        // Not a failure. A machine whose only SATA device is its boot CD is a
        // normal machine, and saying "there is no disk here" beats issuing a
        // command that cannot apply and reporting its refusal.
        return None;
    }

    // Slot zero. One command outstanding at a time, which is all a driver with
    // no queue needs and all RFC 0046 asks for before NCQ is measured.
    // SAFETY: two disjoint windows inside the four pages this program holds and
    // mapped writable -- the list at page zero and the table at page one, whose
    // sizes are the crate's own constants and both under a page. Nothing else
    // in this program aliases either.
    let list = unsafe {
        core::slice::from_raw_parts_mut((MEMORY_AT + LIST_AT) as *mut u8, ahci::COMMAND_LIST_BYTES)
    };
    // SAFETY: as above, page one.
    let table = unsafe {
        core::slice::from_raw_parts_mut(
            (MEMORY_AT + TABLE_AT) as *mut u8,
            ahci::PRDT_AT + ahci::PRD_BYTES,
        )
    };
    if ahci::build_command(
        list,
        table,
        0,
        ahci::Ata::identify(),
        ahci::Where {
            table: device_base + TABLE_AT,
            buffer: device_base + BUFFER_AT,
            bytes: ahci::IDENTIFY_BYTES,
        },
    )
    .is_err()
    {
        return Some(Err(ahci::Failed::NoSuchSlot));
    }
    stage(STAGE_BUILT);

    stage(STAGE_ISSUED);
    if let Err(why) = ahci::run(registers, port, 0, clock, SETTLE_NS) {
        return Some(Err(why));
    }
    stage(STAGE_ANSWERED);

    // 512 bytes a *device* wrote. `read_identity` is the crate's untrusted-input
    // parser and the one with a fuzz target, for exactly this reason.
    // SAFETY: page two, which this program holds, and which the controller has
    // just finished writing -- `run` returned `Ok`, which is the only thing
    // that says the device is no longer busy with it.
    let answered = unsafe {
        core::slice::from_raw_parts((MEMORY_AT + BUFFER_AT) as *const u8, ahci::IDENTIFY_BYTES)
    };
    let identity = match ahci::read_identity(answered) {
        Ok(identity) => identity,
        Err(_) => return Some(Err(ahci::Failed::Device(0))),
    };

    // RFC 0046 step 5: `READ DMA EXT`, sector zero.
    //
    // **Planned rather than asked for.** `plan_read` is where the disk's own
    // numbers are bounded before they size a transfer, which is RFC 0046's
    // security section in one call: the thing about to fill this buffer is a bus
    // master, and a byte count it is handed is a count it will honour.
    let planned = match ahci::plan_read(&identity, 0, 1, ahci::IDENTIFY_BYTES) {
        Ok(planned) => planned,
        // A disk whose own answer will not permit a read of its first sector.
        // Reported as a refusal rather than attempted anyway.
        Err(_) => {
            READ_STATE.store(3, core::sync::atomic::Ordering::Relaxed);
            return Some(Ok(identity));
        }
    };
    stage(STAGE_PLANNED);

    // The buffer is reused, and wiped first. Left as it was, a read that moved
    // no bytes would be indistinguishable from one that worked -- the IDENTIFY
    // response is still sitting there, and its first bytes are not zero.
    // SAFETY: page two, which this program holds and mapped writable, and which
    // no command is outstanding against.
    unsafe {
        core::ptr::write_bytes((MEMORY_AT + BUFFER_AT) as *mut u8, 0, ahci::IDENTIFY_BYTES);
    }

    if ahci::build_command(
        list,
        table,
        0,
        planned.ata,
        ahci::Where {
            table: device_base + TABLE_AT,
            buffer: device_base + BUFFER_AT,
            bytes: planned.bytes,
        },
    )
    .is_err()
    {
        READ_STATE.store(3, core::sync::atomic::Ordering::Relaxed);
        return Some(Ok(identity));
    }

    match ahci::run(registers, port, 0, clock, SETTLE_NS) {
        Ok(()) => {
            stage(STAGE_READ);
            // SAFETY: as above, and `run` returned `Ok` -- the only thing that
            // says the device is no longer writing into it.
            let sector = unsafe {
                core::slice::from_raw_parts((MEMORY_AT + BUFFER_AT) as *const u8, FIRST_BYTES)
            };
            for (word, chunk) in sector.chunks(8).enumerate() {
                let mut packed = [0u8; 8];
                packed[..chunk.len()].copy_from_slice(chunk);
                FIRST[word].store(
                    u64::from_le_bytes(packed),
                    core::sync::atomic::Ordering::Relaxed,
                );
            }
            READ_STATE.store(1, core::sync::atomic::Ordering::Relaxed);
        }
        Err(why) => {
            READ_STATE.store(2, core::sync::atomic::Ordering::Relaxed);
            READ_WHY.store(
                match why {
                    ahci::Failed::TimedOut => 1,
                    ahci::Failed::Device(error) => 0x100 | u64::from(error),
                    ahci::Failed::Bus(bits) => 0x200 | u64::from(bits),
                    ahci::Failed::NoSuchSlot => 3,
                },
                core::sync::atomic::Ordering::Relaxed,
            );
        }
    }

    Some(Ok(identity))
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
