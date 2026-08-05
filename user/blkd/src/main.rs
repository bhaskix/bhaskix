// SPDX-License-Identifier: Apache-2.0
//! The block driver, in a domain of its own.
//!
//! It drives the *second* virtio block device. The kernel drives the first and
//! never touches this one: two drivers on one device would race resets and
//! interleave rings, so a driver in a domain gets a device rather than a share
//! of somebody else's.
//!
//! # What it holds, and what it cannot reach
//!
//! Four capabilities and nothing else:
//!
//! - three `Frame`s, one per structure the virtio 1.0 transport defines —
//!   common configuration, queue notification, device configuration;
//! - a `Memory` object for its rings, which it maps for itself.
//!
//! It does not hold the bus. Finding those structures means reading PCI
//! configuration space, which is port I/O, and a domain holding that would
//! hold every device on the machine — so the kernel enumerates and this
//! drives. That split is where the hardware puts the line, not where it was
//! convenient to draw one.
//!
//! A wild pointer in here faults in ring 3 and takes the driver down. The same
//! mistake in a kernel driver takes the machine.
#![no_std]
#![no_main]

use bhaskix_abi::{method, status, syscall};

/// Slot: the common configuration structure.
const COMMON: u64 = 0;
/// Slot: the queue notification area.
const NOTIFY: u64 = 1;
/// Slot: device-specific configuration — for a block device, its capacity.
const DEVICE: u64 = 2;
/// Slot: memory for the rings.
const RINGS: u64 = 3;

/// Where each mapping goes in this program's address space.
const COMMON_AT: u64 = 0x2000_0000;
const NOTIFY_AT: u64 = 0x2001_0000;
const DEVICE_AT: u64 = 0x2002_0000;
const RINGS_AT: u64 = 0x2010_0000;

/// Offsets into the common configuration structure, from the specification.
mod common {
    pub const DEVICE_FEATURE_SELECT: u64 = 0x00;
    pub const DEVICE_FEATURE: u64 = 0x04;
    pub const DEVICE_STATUS: u64 = 0x14;
    pub const NUM_QUEUES: u64 = 0x12;
    pub const QUEUE_SELECT: u64 = 0x16;
    pub const QUEUE_SIZE: u64 = 0x18;
}

/// Status bits, written in the order the specification fixes.
mod device_status {
    pub const ACKNOWLEDGE: u8 = 1;
    pub const DRIVER: u8 = 2;
}

/// There is nothing to unwind and nowhere to print to.
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // SAFETY: an undefined instruction, deliberately. A driver that panicked
    // has a device in an unknown state, and stopping where the kernel can see
    // it beats continuing to program one.
    unsafe { core::arch::asm!("ud2", options(noreturn)) }
}

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

/// Reads one byte of a mapped register.
///
/// # Safety
///
/// `at` must be inside a device window this program mapped.
unsafe fn read8(at: u64) -> u8 {
    // SAFETY: delegated to the caller.
    unsafe { core::ptr::read_volatile(at as *const u8) }
}

/// Reads two bytes of a mapped register.
///
/// # Safety
///
/// As [`read8`], and `at` must be two-byte aligned.
unsafe fn read16(at: u64) -> u16 {
    // SAFETY: delegated to the caller.
    unsafe { core::ptr::read_volatile(at as *const u16) }
}

/// Reads four bytes of a mapped register.
///
/// # Safety
///
/// As [`read8`], and `at` must be four-byte aligned.
unsafe fn read32(at: u64) -> u32 {
    // SAFETY: delegated to the caller.
    unsafe { core::ptr::read_volatile(at as *const u32) }
}

/// Writes one byte of a mapped register.
///
/// # Safety
///
/// As [`read8`]. The value is one the specification defines for that register.
unsafe fn write8(at: u64, value: u8) {
    // SAFETY: delegated to the caller.
    unsafe { core::ptr::write_volatile(at as *mut u8, value) }
}

/// Writes two bytes of a mapped register.
///
/// # Safety
///
/// As [`write8`], and `at` must be two-byte aligned.
unsafe fn write16(at: u64, value: u16) {
    // SAFETY: delegated to the caller.
    unsafe { core::ptr::write_volatile(at as *mut u16, value) }
}

/// Writes four bytes of a mapped register.
///
/// # Safety
///
/// As [`write8`], and `at` must be four-byte aligned.
unsafe fn write32(at: u64, value: u32) {
    // SAFETY: delegated to the caller.
    unsafe { core::ptr::write_volatile(at as *mut u32, value) }
}

/// Where the program actually starts.
#[unsafe(no_mangle)]
extern "C" fn blkd_main() -> ! {
    // Everything this driver can reach, mapped by asking for it. A failure
    // here is a capability that was not granted, and there is nothing sensible
    // to do about that from in here.
    if !attach(COMMON, COMMON_AT, 1)
        || !attach(NOTIFY, NOTIFY_AT, 1)
        || !attach(DEVICE, DEVICE_AT, 0)
        || !attach(RINGS, RINGS_AT, 1)
    {
        exit()
    }

    // The device as the kernel left it: untouched. Nobody has driven this one,
    // so its status is zero and reading zero is the evidence — the kernel's own
    // device reads 15, and a driver that had been handed the wrong one would
    // see that instead.
    //
    // SAFETY: `COMMON_AT` is a device window this program mapped, and these
    // offsets are inside it. Reading a status register does not change it.
    let untouched = unsafe { read8(COMMON_AT + common::DEVICE_STATUS) };
    // SAFETY: as above -- the same window, a register two bytes wide at an
    // offset inside it, and reading it does not change it.
    let queues = unsafe { read16(COMMON_AT + common::NUM_QUEUES) };

    // The bring-up handshake, as far as the specification's first two steps:
    // acknowledge that the device is there, then that a driver is present.
    // Feature negotiation and the queue are the next step's work.
    //
    // SAFETY: as above; these writes are the values the specification defines
    // for that register, in the order it fixes.
    unsafe {
        write8(COMMON_AT + common::DEVICE_STATUS, 0);
        write8(
            COMMON_AT + common::DEVICE_STATUS,
            device_status::ACKNOWLEDGE,
        );
        write8(
            COMMON_AT + common::DEVICE_STATUS,
            device_status::ACKNOWLEDGE | device_status::DRIVER,
        );
    }
    // SAFETY: as above.
    let acknowledged = unsafe { read8(COMMON_AT + common::DEVICE_STATUS) };

    // What the device offers, and how big its queue is. Both are read from the
    // hardware, and neither is anything this program could have invented.
    //
    // SAFETY: as above.
    let (features, queue_size) = unsafe {
        write32(COMMON_AT + common::DEVICE_FEATURE_SELECT, 0);
        let features = read32(COMMON_AT + common::DEVICE_FEATURE);
        write16(COMMON_AT + common::QUEUE_SELECT, 0);
        (features, read16(COMMON_AT + common::QUEUE_SIZE))
    };

    // The capacity, in 512-byte sectors, from the device configuration
    // structure. This is the disk the kernel never opened.
    //
    // SAFETY: `DEVICE_AT` is the device configuration window this program
    // mapped read-only, and a block device's capacity is its first field.
    let sectors = unsafe { read32(DEVICE_AT) };

    // The rings are this program's own memory, and writing to them proves the
    // mapping is writable before a device is ever pointed at it.
    //
    // SAFETY: `RINGS_AT` is four pages of memory this program holds and mapped
    // writable, and nothing else in this program uses it.
    let rings_work = unsafe {
        core::ptr::write_volatile(RINGS_AT as *mut u64, 0x0123_4567_89ab_cdef);
        core::ptr::read_volatile(RINGS_AT as *const u64) == 0x0123_4567_89ab_cdef
    };

    report(
        untouched,
        acknowledged,
        queues,
        queue_size,
        features,
        sectors,
        rings_work,
    );
    exit()
}

/// Says what was found, through the one thing this domain does not hold.
///
/// It has no console capability: a driver has no business printing, and giving
/// it one to make a test easier would have made the test prove less. So the
/// numbers go where the kernel can read them — into the rings, at a fixed
/// offset, which the kernel checks and reports.
#[allow(clippy::too_many_arguments)]
fn report(
    untouched: u8,
    acknowledged: u8,
    queues: u16,
    queue_size: u16,
    features: u32,
    sectors: u32,
    rings_work: bool,
) {
    // A word the kernel looks for, so a zeroed page is not mistaken for a
    // report nobody wrote.
    const MARKER: u64 = 0x424c_4b44_5250_5431;

    // SAFETY: the second page of the rings, which this program holds and
    // mapped writable. The kernel reads the same offsets.
    unsafe {
        let at = (RINGS_AT + 0x1000) as *mut u64;
        core::ptr::write_volatile(at.add(1), u64::from(untouched));
        core::ptr::write_volatile(at.add(2), u64::from(acknowledged));
        core::ptr::write_volatile(at.add(3), u64::from(queues));
        core::ptr::write_volatile(at.add(4), u64::from(queue_size));
        core::ptr::write_volatile(at.add(5), u64::from(features));
        core::ptr::write_volatile(at.add(6), u64::from(sectors));
        core::ptr::write_volatile(at.add(7), u64::from(rings_work));
        // The marker last, and with a fence before it, so a kernel that sees
        // the marker sees everything under it.
        core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
        core::ptr::write_volatile(at, MARKER);
    }
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
    call blkd_main
    ud2
"#
);
