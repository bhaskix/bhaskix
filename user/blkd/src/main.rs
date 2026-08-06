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

use bhaskix_abi::{block, method, rights, status, syscall};
use bhaskix_device::Volatile;
use bhaskix_device::virtqueue::{self, Virtqueue};

/// Slot: the common configuration structure.
const COMMON: u64 = 0;
/// Slot: the queue notification area.
const NOTIFY: u64 = 1;
/// Slot: device-specific configuration — for a block device, its capacity.
const DEVICE: u64 = 2;
/// Slot: memory for the rings.
const RINGS: u64 = 3;
/// Slot: the authority to say what this device may reach.
const WINDOW: u64 = 4;
/// Slot: this device's interrupt — the authority to wait for it and to say
/// the driver is ready for the next one, and nothing about programming it.
const HANDLER: u64 = 5;
/// Slot: the notification the handler signals.
const SIGNAL: u64 = 6;
/// Slot: the endpoint this driver answers block requests on.
///
/// Also what it hands back to the kernel to fill a caller's memory: holding it
/// is what says this program is the block service rather than a program
/// pretending to be.
const BLOCK_ENDPOINT: u64 = 8;
/// Slot: kept empty, and declared as a destination that must never be filled.
///
/// It exists so that the rule being watched is the *only* thing in the way. A
/// probe that had declared nothing would be refused for that, and the refusal
/// it is meant to demonstrate would never be reached.
const SPARE: u64 = 14;
/// Slot: this device's configuration space, read-only.
///
/// Four kilobytes of ordinary memory, which is what PCIe made it and what the
/// port pair never could be. Read-only, and the BARs are the reason: a BAR
/// decides *where in physical address space the device answers*, and an IOMMU
/// governs what a device reads rather than where it responds.
const CONFIG: u64 = 7;

/// Where each mapping goes in this program's address space.
const COMMON_AT: u64 = 0x2000_0000;
const NOTIFY_AT: u64 = 0x2001_0000;
const DEVICE_AT: u64 = 0x2002_0000;
const RINGS_AT: u64 = 0x2010_0000;

/// How many entries the queue has, as this driver uses it.
///
/// A power of two, which is what makes the index wrap correct, and small
/// because this driver has one request outstanding at a time.
const QUEUE_ENTRIES: u16 = 4;

/// Where this program maps its own configuration space.
const CONFIG_AT: u64 = 0x2003_0000;

/// Where each structure sits inside the four pages of rings.
///
/// Laid out by hand because the device reads it: the descriptor table must be
/// sixteen-byte aligned, the used ring four-byte aligned, and the whole lot
/// has to be at offsets this program can turn into device addresses by adding
/// them to one base. A page each keeps every alignment true by construction.
mod ring {
    /// Descriptor table: sixteen bytes per entry.
    pub const DESCRIPTORS: u64 = 0x0000;
    /// Available ring, where the driver publishes what it wants done.
    pub const AVAILABLE: u64 = 0x0800;
    /// Used ring, where the device publishes what it has done.
    pub const USED: u64 = 0x1000;
    /// The sixteen-byte request header the device reads.
    pub const HEADER: u64 = 0x2000;
    /// One byte, which the device writes when it is finished.
    pub const STATUS: u64 = 0x2010;
    /// Where the sector lands.
    pub const DATA: u64 = 0x2800;
    /// Where this program leaves its findings for the kernel.
    pub const REPORT: u64 = 0x3000;
}

/// Offsets into the common configuration structure, from the specification.
mod common {
    pub const DEVICE_STATUS: u64 = 0x14;
    pub const NUM_QUEUES: u64 = 0x12;
    pub const DRIVER_FEATURE_SELECT: u64 = 0x08;
    pub const DRIVER_FEATURE: u64 = 0x0c;
    pub const CONFIG_MSIX_VECTOR: u64 = 0x10;
    pub const QUEUE_SELECT: u64 = 0x16;
    pub const QUEUE_SIZE: u64 = 0x18;
    pub const QUEUE_MSIX_VECTOR: u64 = 0x1a;
    pub const QUEUE_ENABLE: u64 = 0x1c;
    pub const QUEUE_NOTIFY_OFF: u64 = 0x1e;
    pub const QUEUE_DESC: u64 = 0x20;
    pub const QUEUE_DRIVER: u64 = 0x28;
    pub const QUEUE_DEVICE: u64 = 0x30;
}

/// Status bits, written in the order the specification fixes.
mod device_status {
    pub const ACKNOWLEDGE: u8 = 1;
    pub const DRIVER: u8 = 2;
    pub const DRIVER_OK: u8 = 4;
    pub const FEATURES_OK: u8 = 8;
}

/// There is nothing to unwind and nowhere to print to.
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // SAFETY: an undefined instruction, deliberately. A driver that panicked
    // has a device in an unknown state, and stopping where the kernel can see
    // it beats continuing to program one.
    unsafe { core::arch::asm!("ud2", options(noreturn)) }
}

/// Blocks until a request arrives, and returns `(status, badge, method, args)`.
///
/// The caller is not returned, because the kernel remembers it: a service that
/// could name its own reply target could answer a question nobody asked it.
fn receive() -> (u64, u64, u64, [u64; 4]) {
    let status: u64;
    let mut badge = BLOCK_ENDPOINT;
    let mut method = 0u64;
    let (mut a0, mut a1, mut a2, mut a3) = (0u64, 0u64, 0u64, 0u64);
    // SAFETY: the system call convention from RFC 0008. Every argument
    // register is an output because the kernel writes the whole frame back.
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") syscall::RECV => status,
            inlateout("rdi") badge,
            inlateout("rsi") method,
            inlateout("rdx") a0,
            inlateout("r10") a1,
            inlateout("r8") a2,
            inlateout("r9") a3,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    (status, badge, method, [a0, a1, a2, a3])
}

/// Answers the caller this thread received from, and nobody else.
fn reply(method: u64, value: u64) {
    let _ = call(syscall::REPLY, 0, method, [value, 0, 0, 0]);
}

/// Issues one system call and returns both the status and the value.
fn call_two(kind: u64, capability: u64, method: u64, args: [u64; 4]) -> (u64, u64) {
    let status: u64;
    let mut value = args[0];
    // SAFETY: as `call`.
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

/// Writes a 64-bit register, as two 32-bit stores.
///
/// Two stores and not one, because the specification defines these registers
/// as a low and a high half and a device model is entitled to notice the
/// difference. QEMU does: a single eight-byte store to `queue_desc` left the
/// device with a queue it never looked at — no fault, no completion, and
/// nothing anywhere saying why. The kernel's own driver had this comment
/// already, which is where the answer was.
///
/// # Safety
///
/// As [`write8`], and `at` must be four-byte aligned.
unsafe fn write64(at: u64, value: u64) {
    // SAFETY: delegated to the caller. The low half first, which is the order
    // the specification fixes.
    unsafe {
        core::ptr::write_volatile(at as *mut u32, value as u32);
        core::ptr::write_volatile((at + 4) as *mut u32, (value >> 32) as u32);
    }
}

/// Whether the queue took an MSI-X vector, decided during bring-up and read
/// after it.
///
/// A static because the answer belongs to the device and the question is asked
/// in two places; this program is single-threaded, so `Relaxed` is the whole
/// of what it needs.
static VECTORED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Whether the completion came from the notification rather than from looking.
///
/// Reported, because "it read the disk" is true of both paths and the whole
/// point of the interrupt is that the driver was not looking.
static BY_INTERRUPT: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

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

    // What this device *is*, from its own configuration space, without asking
    // the kernel. Vendor and device identify it; reading them grants nothing,
    // which is why they are the part a domain may have.
    let (vendor, identity, writable_refused) = if attach(CONFIG, CONFIG_AT, 0) {
        // SAFETY: the kernel mapped one page of configuration space read-only
        // at this address. The vendor and device ids are its first four bytes.
        let (vendor, identity) = unsafe { (read16(CONFIG_AT), read16(CONFIG_AT + 2)) };
        // And the same page asked for writably, which must be refused: a
        // writable configuration page is a writable BAR.
        let refused = !attach(CONFIG, CONFIG_AT + 0x1000, 1);
        (u64::from(vendor), u64::from(identity), refused)
    } else {
        (0, 0, false)
    };

    // The device as this driver found it. Reported and not asserted: the
    // firmware probes disks before a kernel exists, so a device on a real bus
    // is never untouched.
    //
    // SAFETY: `COMMON_AT` is a device window this program mapped, and these
    // offsets are inside it. Reading a status register does not change it.
    let found = unsafe { read8(COMMON_AT + common::DEVICE_STATUS) };
    // SAFETY: as above -- a register two bytes wide at an offset inside the
    // same window.
    let _queues = unsafe { read16(COMMON_AT + common::NUM_QUEUES) };

    // Where the device will look for the rings. Not a physical address: this
    // program cannot name one, and the number the device is given is whatever
    // the unit translates back to the frames the kernel gave it. Without a
    // window there is no such number and no read to be had — which is the
    // point, because a device with no translation in front of it would be
    // aimed with physical addresses by a program that must not know any.
    let (mapped, rings_at_device) = call(syscall::INVOKE, WINDOW, method::MAP, [RINGS, 0, 0, 0]);
    let translated = mapped == status::OK;

    let mut queue = if translated {
        bring_up(rings_at_device)
    } else {
        None
    };

    // Without a window there is no device address to give the queue, so the
    // device is brought as far as the handshake and no further. That is the
    // refusal, not a shortcoming: a domain that could aim a device with
    // physical addresses could aim it at the kernel.
    if queue.is_none() {
        // SAFETY: the common configuration window this program mapped; the
        // handshake as far as it goes without a queue to enable.
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
    }

    // One read of sector zero, which is what the kernel checks this driver by.
    let read = match queue.as_mut() {
        Some(queue) => {
            if read_sector(queue, rings_at_device, 0) {
                finished()
            } else {
                None
            }
        }
        None => None,
    };

    // SAFETY: as above.
    let status_now = unsafe { read8(COMMON_AT + common::DEVICE_STATUS) };
    // SAFETY: `DEVICE_AT` is the device configuration window this program
    // mapped read-only, and a block device's capacity is its first field.
    let sectors = unsafe { read32(DEVICE_AT) };
    // SAFETY: as above.
    let queue_size = unsafe {
        write16(COMMON_AT + common::QUEUE_SELECT, 0);
        read16(COMMON_AT + common::QUEUE_SIZE)
    };

    let (used_index, request_status) = aftermath();
    let by_interrupt = u64::from(BY_INTERRUPT.load(core::sync::atomic::Ordering::Relaxed));
    let identified = if writable_refused {
        (vendor << 16) | identity
    } else {
        0
    };
    // Handing a capability while answering nobody. A server with no caller has
    // nobody to hand anything to, and a server that could pick its recipient
    // would hold the one authority this mechanism exists not to give it.
    //
    // A receive slot is declared *first*, and that is what makes this a test.
    // Without it the refusal is "you did not say where" -- and a version of
    // this without the declaration passed with the reply-obligation check
    // deleted, because the missing declaration refused it instead. Declared,
    // the only thing standing between this program and handing itself a
    // capability is the rule being watched.
    let _ = call_two(
        syscall::INVOKE,
        BLOCK_ENDPOINT,
        method::EXPECT,
        [SPARE, 0, 0, 0],
    );
    let (not_answering, _) = call_two(
        syscall::INVOKE,
        BLOCK_ENDPOINT,
        method::HAND,
        [CONFIG, rights::READ, 0, 0],
    );

    report(
        found,
        status_now,
        rings_at_device,
        queue_size,
        sectors,
        read,
        used_index,
        request_status,
        by_interrupt,
        identified,
        not_answering,
    );

    // And now it is a *service*. RFC 0015 step 1: a driver nothing could ask
    // for a block was a driver with no interface, which was right for RFC 0014
    // and is the first thing in the way of a filesystem.
    match queue {
        Some(mut queue) => serve(&mut queue, rings_at_device, u64::from(sectors)),
        // Nothing to serve. Exiting says so, where a loop answering every
        // request with a refusal would look like a service that is working.
        None => exit(),
    }
}

/// Answers block requests, for ever.
///
/// The bulk path is RFC 0009's and the same one the filesystem uses: the caller
/// names memory it already holds, and this asks the kernel to fill it. No
/// sector data crosses in message registers, because a block that travelled
/// sixteen bytes at a time would be slower than the disk.
fn serve(queue: &mut Virtqueue<Volatile>, rings_at_device: u64, sectors: u64) -> ! {
    loop {
        let (status, badge, method, args) = receive();
        if status != status::OK {
            exit()
        }
        let _ = badge;

        let answer = match method {
            block::CAPACITY => sectors,
            // The configuration page, lent rather than copied. This service
            // holds a read-only capability to it and hands the caller a copy
            // no stronger than its own; the caller maps it and reads the
            // device itself, which is a thing this service never does on its
            // behalf.
            //
            // Where it lands is not this service's to choose. `HAND` puts it
            // in the slot the *caller* declared, and there is no argument here
            // that could say otherwise.
            block::LEND_CONFIG => {
                let (status, slot) = call_two(
                    syscall::INVOKE,
                    BLOCK_ENDPOINT,
                    method::HAND,
                    [CONFIG, rights::READ, 0, 0],
                );
                if status == status::OK { slot + 1 } else { 0 }
            }
            // The same call, for a capability this service holds and may not
            // pass on: every register window it was given lacks `GRANT`.
            // Answered from inside a request on purpose. Asked at start-up it
            // would be refused for having no caller, and the two refusals
            // would be indistinguishable -- which is what the first version of
            // this did, and both came back status 4.
            block::LEND_FORBIDDEN => {
                let (status, _) = call_two(
                    syscall::INVOKE,
                    BLOCK_ENDPOINT,
                    method::HAND,
                    [COMMON, rights::READ, 0, 0],
                );
                status
            }
            block::READ => {
                let sector = args[0];
                let slot = args[2];
                if sector >= sectors {
                    // Past the end of the device. Refused here rather than
                    // asked of the hardware, because a device is entitled to
                    // do anything with a sector that does not exist.
                    0
                } else if read_sector(queue, rings_at_device, sector) {
                    // Into the caller's memory, named by a slot in the
                    // caller's own CSpace -- which the kernel re-checks, and
                    // which this service could not have chosen.
                    let (filled, landed) = call_two(
                        syscall::INVOKE,
                        BLOCK_ENDPOINT,
                        method::FILL,
                        [slot, RINGS_AT + ring::DATA, 512, 0],
                    );
                    if filled == status::OK { landed } else { 0 }
                } else {
                    0
                }
            }
            _ => 0,
        };

        reply(method, answer);
    }
}

/// Brings the device up and readies its queue./// Brings the device up and reads sector zero.
///
/// The bring-up order is the specification's and the order *is* the protocol: a
/// status bit written early is a promise this driver has not yet kept. The
/// features are the two a virtio 1.0 device behind an IOMMU requires — version
/// 1, and that the driver uses the platform's addresses rather than physical
/// ones. The second is not a formality: without it the device bypasses
/// translation entirely and the window this program was given would contain
/// nothing.
///
/// Returns the queue, ready to carry requests, or `None` if the device never
/// came up.
fn bring_up(rings_at_device: u64) -> Option<Virtqueue<Volatile>> {
    // Device addresses are the ring base plus the same offsets this program
    // uses, because the window maps the object's pages in order.
    let device_address = |offset: u64| rings_at_device + offset;

    // SAFETY: `COMMON_AT` is the common configuration window this program
    // mapped writable, and every offset below is inside it. The values and
    // their order are the specification's.
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

        // Feature bits 32 and 33: VERSION_1 and ACCESS_PLATFORM.
        write32(COMMON_AT + common::DRIVER_FEATURE_SELECT, 1);
        write32(COMMON_AT + common::DRIVER_FEATURE, 0b11);
        write32(COMMON_AT + common::DRIVER_FEATURE_SELECT, 0);
        write32(COMMON_AT + common::DRIVER_FEATURE, 0);

        write8(
            COMMON_AT + common::DEVICE_STATUS,
            device_status::ACKNOWLEDGE | device_status::DRIVER | device_status::FEATURES_OK,
        );
        // Read back: a device that will not accept the feature set clears this
        // bit, and going on from there configures a queue nobody will service.
        if read8(COMMON_AT + common::DEVICE_STATUS) & device_status::FEATURES_OK == 0 {
            return None;
        }

        write16(COMMON_AT + common::QUEUE_SELECT, 0);

        // Which MSI-X entry this queue uses. *Which* is the driver's to say,
        // in a register it holds; what that entry contains -- a vector, and a
        // CPU to send it to -- is the kernel's, and this program has no way to
        // write it. The device reports 0xffff if it could not take the vector,
        // and a driver that did not read it back would wait for an interrupt
        // that was never going to arrive.
        write16(COMMON_AT + common::QUEUE_MSIX_VECTOR, 0);
        write16(COMMON_AT + common::CONFIG_MSIX_VECTOR, 0);
        let vectored = read16(COMMON_AT + common::QUEUE_MSIX_VECTOR) == 0;

        write64(
            COMMON_AT + common::QUEUE_DESC,
            device_address(ring::DESCRIPTORS),
        );
        write64(
            COMMON_AT + common::QUEUE_DRIVER,
            device_address(ring::AVAILABLE),
        );
        write64(COMMON_AT + common::QUEUE_DEVICE, device_address(ring::USED));
        write16(COMMON_AT + common::QUEUE_ENABLE, 1);
        VECTORED.store(vectored, core::sync::atomic::Ordering::Relaxed);

        write8(
            COMMON_AT + common::DEVICE_STATUS,
            device_status::ACKNOWLEDGE
                | device_status::DRIVER
                | device_status::FEATURES_OK
                | device_status::DRIVER_OK,
        );
    }

    // The queue, from the crate the kernel's driver uses too. What was a
    // hand-written copy of the split-virtqueue layout is now the same code:
    // the second driver stopped being a second implementation. Each ring is
    // given twice, because the address this program writes through and the
    // address the *device* is told are not the same one — that difference is
    // the IOMMU, from a driver's side.
    //
    // SAFETY: the three rings are inside the four pages this program holds and
    // mapped writable, at offsets that do not overlap, and the size is a power
    // of two.
    let queue = unsafe {
        Virtqueue::<Volatile>::new(
            virtqueue::Ring {
                at: (RINGS_AT + ring::DESCRIPTORS) as usize,
                device: device_address(ring::DESCRIPTORS),
            },
            virtqueue::Ring {
                at: (RINGS_AT + ring::AVAILABLE) as usize,
                device: device_address(ring::AVAILABLE),
            },
            virtqueue::Ring {
                at: (RINGS_AT + ring::USED) as usize,
                device: device_address(ring::USED),
            },
            QUEUE_ENTRIES,
        )
    };
    Some(queue)
}

/// Reads one sector into this driver's own buffer.
///
/// The whole request cycle: a header the device reads, a buffer it writes the
/// sector into, and a byte it writes when it is done. Three descriptors,
/// chained, because the device is told what each part is for by its flags and
/// not by its position.
///
/// `false` if the device reported a failure or never answered.
fn read_sector(queue: &mut Virtqueue<Volatile>, rings_at_device: u64, sector: u64) -> bool {
    let device_address = |offset: u64| rings_at_device + offset;

    // SAFETY: `RINGS_AT` is four pages of memory this program holds and mapped
    // writable, and every offset below is inside it.
    unsafe {
        // Header: type 0 (read), reserved 0, then the sector.
        let header = (RINGS_AT + ring::HEADER) as *mut u32;
        core::ptr::write_volatile(header, 0);
        core::ptr::write_volatile(header.add(1), 0);
        core::ptr::write_volatile((RINGS_AT + ring::HEADER + 8) as *mut u64, sector);
        // A value the device never writes, so "the device answered" and "the
        // device said ok" cannot be confused.
        core::ptr::write_volatile((RINGS_AT + ring::STATUS) as *mut u8, 0xff);
    }

    queue.describe(0, device_address(ring::HEADER), 16, virtqueue::NEXT, 1);
    queue.describe(
        1,
        device_address(ring::DATA),
        512,
        virtqueue::NEXT | virtqueue::WRITE,
        2,
    );
    queue.describe(2, device_address(ring::STATUS), 1, virtqueue::WRITE, 0);
    queue.publish(0);

    // Kick. The offset is the device's, in units it chose.
    //
    // SAFETY: the notify window this program mapped, at the offset the device
    // published for this queue.
    unsafe {
        let offset = u64::from(read16(COMMON_AT + common::QUEUE_NOTIFY_OFF));
        write16(NOTIFY_AT + offset * 4, 0);
    }

    // Wait for the interrupt, if the queue took a vector. This is the whole of
    // a driver's interrupt duty and the whole of what this program was given:
    // block until the notification says the device is finished, then say the
    // driver is ready for the next one.
    if VECTORED.load(core::sync::atomic::Ordering::Relaxed) {
        let (status, _badge) = call(syscall::INVOKE, SIGNAL, method::WAIT, [0; 4]);
        let _ = call(syscall::INVOKE, HANDLER, method::ACK, [0; 4]);
        if status != status::OK {
            return false;
        }
        BY_INTERRUPT.store(true, core::sync::atomic::Ordering::Relaxed);
        let _ = queue.completed();
        return finished().is_some();
    }

    // No vector: look instead, through the same queue. A bounded spin is
    // honest about being a spin, where a wait with no bound would hang a
    // machine on a device that never answers.
    for _ in 0..2_000_000u64 {
        if queue.completed().is_some() {
            return finished().is_some();
        }
        core::hint::spin_loop();
    }
    false
}

/// Reads what the device left, once it has said it is finished.
///
/// `None` if the device reported a failure.
fn finished() -> Option<u64> {
    // SAFETY: the status byte and the sector, in memory this program holds and
    // mapped writable. The device has finished with them, which is what the
    // used ring or the notification just said.
    unsafe {
        if core::ptr::read_volatile((RINGS_AT + ring::STATUS) as *const u8) != 0 {
            return None;
        }
        Some(core::ptr::read_volatile(
            (RINGS_AT + ring::DATA) as *const u64,
        ))
    }
}

/// What the device left in the used ring and the status byte.
///
/// Read whether or not the request completed, because "the device wrote
/// nothing" and "the device wrote a failure" are different answers and the
/// difference is the whole diagnosis.
fn aftermath() -> (u64, u64) {
    // SAFETY: the used ring and the status byte, in memory this program holds.
    unsafe {
        (
            u64::from(core::ptr::read_volatile(
                (RINGS_AT + ring::USED + 2) as *const u16,
            )),
            u64::from(core::ptr::read_volatile(
                (RINGS_AT + ring::STATUS) as *const u8,
            )),
        )
    }
}

/// Says what was found, through the one thing this domain does not hold.
///
/// It has no console capability: a driver has no business printing, and giving
/// it one to make a test easier would have made the test prove less. So the
/// numbers go where the kernel can read them — into the rings, at a fixed
/// offset, which the kernel checks and reports.
#[allow(clippy::too_many_arguments)]
fn report(
    found: u8,
    status_now: u8,
    rings_at_device: u64,
    queue_size: u16,
    sectors: u32,
    read: Option<u64>,
    used_index: u64,
    request_status: u64,
    by_interrupt: u64,
    identified: u64,
    hand_refusals: u64,
) {
    // A word the kernel looks for, so a zeroed page is not mistaken for a
    // report nobody wrote.
    const MARKER: u64 = 0x424c_4b44_5250_5431;

    // SAFETY: the last page of the rings, which this program holds and mapped
    // writable, and which nothing the device was told about overlaps. The
    // kernel reads the same offsets.
    unsafe {
        let at = (RINGS_AT + ring::REPORT) as *mut u64;
        core::ptr::write_volatile(at.add(1), u64::from(found));
        core::ptr::write_volatile(at.add(2), u64::from(status_now));
        core::ptr::write_volatile(at.add(3), rings_at_device);
        core::ptr::write_volatile(at.add(4), u64::from(queue_size));
        core::ptr::write_volatile(at.add(5), u64::from(sectors));
        core::ptr::write_volatile(at.add(6), read.unwrap_or(0));
        core::ptr::write_volatile(at.add(7), u64::from(read.is_some()));
        core::ptr::write_volatile(at.add(8), used_index);
        core::ptr::write_volatile(at.add(9), request_status);
        core::ptr::write_volatile(at.add(10), by_interrupt);
        core::ptr::write_volatile(at.add(11), identified);
        core::ptr::write_volatile(at.add(12), hand_refusals);
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
