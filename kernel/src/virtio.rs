// SPDX-License-Identifier: Apache-2.0
//! A `virtio-blk` driver: the first real device Bhaskix drives.
//!
//! Everything before this was the machine itself — timers, interrupt
//! controllers, a UART that has been on PCs since 1981. This is a device that
//! is *found*: enumerated on a bus, identified by what it says it is,
//! configured through registers whose addresses come out of its own
//! configuration space, and driven through rings in memory it reads by DMA.
//!
//! # Modern virtio, not legacy
//!
//! The 1.0 transport, discovered through vendor-specific PCI capabilities.
//! Legacy virtio is simpler — a handful of I/O ports at a fixed layout — and
//! it is also a device model that new hardware does not implement and that
//! QEMU disables by default on a PCI Express bus. Writing the driver everyone
//! will need anyway is worth the extra hundred lines.
//!
//! # DMA is the device reading the kernel's memory
//!
//! Every address in a virtqueue is *physical*, and the device dereferences it
//! without asking anyone. There is no IOMMU here yet, so a wrong address in a
//! descriptor is a device writing wherever the number pointed — which is the
//! one operation in this kernel that no page table can contain.
//!
//! Two consequences are honoured throughout. Buffers come from the frame
//! allocator, so their physical addresses are known rather than derived from a
//! pointer this code happened to have. And the sizes handed to the device are
//! the sizes of those allocations, never a length that arrived from somewhere
//! else.
//!
//! # One request at a time
//!
//! The driver submits a request and waits for it. A ring exists to hold many
//! in flight, and nothing here needs that yet: the filesystem above it reads
//! whole images at boot. What the single-request shape buys is that the ring
//! bookkeeping has one writer and one reader with nothing between them, which
//! is the version worth writing first.

use core::sync::atomic::Ordering;

use bhaskix_arch::pci;
use bhaskix_device::virtqueue;
use bhaskix_mm::{FRAME_SIZE, Zone};

use crate::heap;

/// The vendor every virtio device reports.
const VIRTIO_VENDOR: u16 = 0x1af4;
/// A modern virtio block device.
const DEVICE_BLOCK_MODERN: u16 = 0x1042;
/// A transitional one, which says what it is in its subsystem id instead.
const DEVICE_TRANSITIONAL: u16 = 0x1001;
/// The subsystem id a transitional device uses to say "block".
const SUBSYSTEM_BLOCK: u16 = 0x0002;

/// What kind of device to look for on the bus.
///
/// # Why the numbers are a table rather than four constants
///
/// A virtio device announces itself twice and differently depending on its age:
/// a modern one puts its identity in the PCI device id, a transitional one
/// reports a legacy id and says what it is in the subsystem id. Getting that
/// wrong means a driver that works on exactly one of QEMU's two default
/// configurations, which the block path found out and documented at
/// [`find_nth`].
///
/// Stating both ids per class, in one place, is what stops the second device
/// class re-deriving the same pair by hand -- and the pair *is* derivable, which
/// is why these constants are written down with their derivation rather than
/// recalled:
///
/// - `/usr/include/linux/virtio_ids.h` gives `VIRTIO_ID_NET = 1` and
///   `VIRTIO_ID_BLOCK = 2`.
/// - The modern PCI device id is `0x1040 + id`, which the block constant above
///   already embodies: `0x1042` for id 2. So net is `0x1041`.
/// - The transitional id is `0x1000 + id - 1` on the same evidence — block is
///   `0x1001` — and the subsystem id is the virtio id itself, which
///   `SUBSYSTEM_BLOCK = 2` likewise already embodies. So net is `0x1000`,
///   subsystem 1.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Class {
    /// The PCI device id a modern device of this class reports.
    modern: u16,
    /// The PCI device id a transitional one reports.
    transitional: u16,
    /// The subsystem id a transitional one says what it is with.
    subsystem: u16,
}

impl Class {
    /// A virtio block device.
    pub const BLOCK: Self = Self {
        modern: DEVICE_BLOCK_MODERN,
        transitional: DEVICE_TRANSITIONAL,
        subsystem: SUBSYSTEM_BLOCK,
    };

    /// A virtio network device.
    pub const NET: Self = Self {
        modern: 0x1041,
        transitional: 0x1000,
        subsystem: 0x0001,
    };

    /// Whether `identity` names a device of this class.
    fn matches(self, identity: pci::Identity) -> bool {
        identity.vendor == VIRTIO_VENDOR
            && (identity.device == self.modern
                || (identity.device == self.transitional && identity.subsystem == self.subsystem))
    }
}

/// The PCI capability id virtio uses for its own structures.
const CAP_VENDOR_SPECIFIC: u8 = 0x09;

/// Kinds of virtio capability, from the `cfg_type` byte.
const CFG_COMMON: u8 = 1;
const CFG_NOTIFY: u8 = 2;
const CFG_DEVICE: u8 = 4;

/// Status bits, written to the common configuration in this order.
const STATUS_ACKNOWLEDGE: u8 = 1;
const STATUS_DRIVER: u8 = 2;
const STATUS_DRIVER_OK: u8 = 4;
const STATUS_FEATURES_OK: u8 = 8;
const STATUS_FAILED: u8 = 128;

/// The feature that says "this driver speaks version 1", which a modern
/// device refuses to work without.
const FEATURE_VERSION_1: u32 = 1 << 0; // bit 32, selected by feature word 1

/// `VIRTIO_F_ACCESS_PLATFORM`: the device's addresses go through whatever the
/// platform puts in the way, which on x86 means the IOMMU.
///
/// Bit 33, so bit 1 of feature word 1. Without it a virtio device is entitled
/// to bypass translation entirely — and on QEMU it does, which made an early
/// version of RFC 0012's step 3 gate pass with the driver's memory deliberately
/// unmapped. Translation was genuinely on; the device simply was not subject to
/// it, so "the read still works" proved nothing at all.
///
/// Accepted only when the device offers it. A driver that sets a feature bit
/// it was not offered is telling the device it speaks a protocol that device
/// may not implement.
const FEATURE_ACCESS_PLATFORM: u32 = 1 << 1;

/// Request types.
const BLK_IN: u32 = 0;

/// Bytes in a sector, as virtio-blk defines it regardless of the underlying
/// device's own block size.
pub const SECTOR: u64 = 512;

/// Descriptors in the queue.
///
/// Eight, because the driver has one request outstanding and a request is
/// three descriptors. A larger ring would be capacity for concurrency that
/// does not exist, and every entry is memory the device may write to.
const QUEUE_SIZE: u16 = 8;

/// How long to wait for a request before giving up, in microseconds.
///
/// A device that has stopped answering must not stop the kernel. Under an
/// emulator a read completes in tens of microseconds; the bound is far above
/// that and far below anything a person would call a hang.
const REQUEST_TIMEOUT_MICROS: u64 = 2_000_000;

/// Why the device could not be brought up, or a request could not be made.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BlockError {
    /// No virtio block device on the bus.
    NotFound,
    /// The device did not describe itself the way a modern virtio device must.
    NotModern,
    /// A register window could not be mapped.
    MapFailed,
    /// The frame allocator had nothing.
    OutOfMemory,
    /// The device refused the features this driver offers.
    FeaturesRefused,
    /// The device did not answer in time.
    TimedOut,
    /// The device answered, and said the request failed.
    Failed,
    /// The request asked for more than the driver's buffer holds.
    TooLarge,
    /// The request runs past the end of the device.
    OutOfRange,
    /// Nothing has been brought up.
    NotPresent,
}

/// The header of a block request, as the device reads it.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct RequestHeader {
    kind: u32,
    reserved: u32,
    sector: u64,
}

/// Where everything the driver needs lives, once found.
struct Device {
    address: pci::Address,
    /// The common configuration structure, mapped. Kept after bring-up so the
    /// device's own view of its state can be read back rather than assumed:
    /// a driver that believes it configured a device is a driver that cannot
    /// tell "not started" from "started and then reset".
    ///
    /// A register block rather than an address: constructing it was the one
    /// promise that these are registers, and every access after it is safe.
    common: CommonCfg,
    /// Where this queue is notified.
    notify: u64,

    /// Each frame as `(physical, virtual, device-visible)`.
    ///
    /// The third is the address the *device* is given, and it is not the
    /// first. With an IOMMU in front of it they differ: the driver writes a
    /// `DevAddr` into every descriptor and register the device reads, and the
    /// unit translates it back. Without one they are equal, which is the whole
    /// of the no-IOMMU path — RFC 0012 step 4 does not fork the driver, it
    /// changes what one number means.
    descriptors: (u64, u64, u64),
    available: (u64, u64, u64),
    used: (u64, u64, u64),
    /// The queue itself, from the crate the domain's driver uses too.
    ///
    /// The layout and the ordering live there now: two drivers implemented
    /// this protocol separately and the second one paid for it.
    queue: bhaskix_device::virtqueue::Virtqueue,
    /// The buffer requests read into.
    buffer: (u64, u64, u64),
    /// The request header and status byte.
    request: (u64, u64, u64),

    /// What the driver has published to the available ring so far.

    /// What it has seen in the used ring so far.

    /// Sectors the device says it has.
    capacity: u64,

    /// The notification an interrupt signals, once MSI-X is programmed.
    ///
    /// `None` means the driver polls, which is what a device with no MSI-X or
    /// a machine with no I/O APIC gets — correct, and a CPU burnt per request.
    notification: Option<crate::notify::NotificationId>,
    handler: Option<crate::irq::HandlerId>,
}

/// The one device, once found.
///
/// A `static` rather than a handle threaded through callers, for the same
/// reason the console is: there is one, and there is no mechanism yet through
/// which a second could be given to anybody. The lock is what makes "one
/// request at a time" true rather than hoped for.
static DEVICE: crate::sync::SpinLock<Option<Device>> =
    crate::sync::SpinLock::new(crate::sync::Rank::Block, None);

/// Requests completed, and requests that timed out.
static COMPLETED: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static TIMEOUTS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// Times a request blocked on an interrupt, and times it spun for want of one.
///
/// The pair is the measurement RFC 0011 asks for: a driver on MSI-X blocks
/// once per request and spins never, and a driver without it does the reverse.
/// A single number could not tell those apart.
static WAITS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static SPINS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// Whether the device agreed that its addresses go through the platform's
/// translation. See [`FEATURE_ACCESS_PLATFORM`].
static TRANSLATED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
/// Blocks that ended with an empty notification word.
///
/// `wait_once` returns what was pending when it woke. Zero means something
/// other than the device's signal ended the wait -- which, since the only
/// other thing armed is the deadline, means the completion interrupt did not
/// arrive. Counted because "the driver waited and the device answered" and
/// "the driver waited and the clock answered" are the same duration and
/// entirely different facts.
static UNSIGNALLED: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// # Safety
///
/// As [`read32`].
unsafe fn write16(address: u64, value: u16) {
    // SAFETY: the caller's obligation.
    unsafe { core::ptr::write_volatile(address as *mut u16, value) }
}

/// # Safety
///
/// As [`read32`].
unsafe fn read8(address: u64) -> u8 {
    // SAFETY: the caller's obligation.
    unsafe { core::ptr::read_volatile(address as *const u8) }
}

bhaskix_device::register_block! {
    /// The virtio 1.0 common configuration structure.
    ///
    /// Offsets declared once, widths declared with them, and the layout
    /// checked at compile time — RFC 0014 step 2. They were a module of
    /// constants and a set of hand-rolled accessors, which is the arrangement
    /// that let `queue_desc` be written as one eight-byte store in the driver
    /// next door.
    struct CommonCfg(0x38) {
        0x00 => device_feature_select: u32,
        0x04 => device_feature: u32,
        0x08 => driver_feature_select: u32,
        0x0c => driver_feature: u32,
        0x10 => config_msix_vector: u16,
        0x12 => num_queues: u16,
        0x14 => device_status: u8,
        0x15 => config_generation: u8,
        0x16 => queue_select: u16,
        0x18 => queue_size: u16,
        0x1a => queue_msix_vector: u16,
        0x1c => queue_enable: u16,
        0x1e => queue_notify_off: u16,
        0x20 => queue_desc: u64,
        0x28 => queue_driver: u64,
        0x30 => queue_device: u64,
    }
}

/// Where `device_status` is inside the common configuration structure.
///
/// Named because one place needs to go the other way — from a register back to
/// the block's base — and recomputing that from a literal would be the same
/// offset written twice.
const COMMON_STATUS_OFFSET: u16 = 0x14;

bhaskix_device::register_block! {
    /// What a *block* device puts in its device-specific configuration.
    ///
    /// The capacity is a 64-bit register, which means two 32-bit reads — and
    /// that is now the only thing it can mean.
    struct BlockCfg(0x08) {
        0x00 => capacity: u64,
    }
}

/// Negotiates features with a device that has been told a driver is present.
///
/// Split out so it can be run against a device model on the host, which is
/// where its refusals get tested — RFC 0014 step 3. A device refuses a feature
/// set by clearing a bit the driver just wrote, and a driver that does not read
/// it back carries on speaking a protocol the device is not speaking.
///
/// # Errors
///
/// [`BlockError::NotModern`] if the device does not offer virtio 1.0, and
/// [`BlockError::FeaturesRefused`] if it will not accept what is offered.
fn negotiate<B: bhaskix_device::Bus>(common: &CommonCfg<B>) -> Result<(), BlockError> {
    // Feature word 1 holds VIRTIO_F_VERSION_1. Offering nothing else is
    // deliberate: every optional feature is a behaviour this driver would
    // then have to implement, and a device is entitled to assume the driver
    // meant it.
    common.device_feature_select.write(1);
    let offered = common.device_feature.read();
    if offered & FEATURE_VERSION_1 == 0 {
        common.device_status.write(STATUS_FAILED);
        return Err(BlockError::NotModern);
    }
    common.driver_feature_select.write(0);
    common.driver_feature.write(0);
    common.driver_feature_select.write(1);
    // Take `ACCESS_PLATFORM` whenever it is offered. It is what subjects this
    // device's DMA to the IOMMU rather than letting it address memory
    // directly, and a driver that declined it would be asking to be outside
    // the protection this kernel is building.
    let accepted = FEATURE_VERSION_1 | (offered & FEATURE_ACCESS_PLATFORM);
    common.driver_feature.write(accepted);
    TRANSLATED.store(offered & FEATURE_ACCESS_PLATFORM != 0, Ordering::Relaxed);

    common
        .device_status
        .write(STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK);
    // Read the status back. The device clears this bit to refuse the feature
    // set, and a driver that did not check would carry on regardless.
    if common.device_status.read() & STATUS_FEATURES_OK == 0 {
        common.device_status.write(STATUS_FAILED);
        return Err(BlockError::FeaturesRefused);
    }
    Ok(())
}

/// Tells a device which MSI-X entry its queue and configuration changes use,
/// and says whether it took it.
///
/// The read-back is the whole function. A device that cannot give out a vector
/// reports `0xffff`, and a driver that assumed it worked waits for an
/// interrupt that is never going to arrive — which looks exactly like a device
/// that is simply slow.
fn take_vector<B: bhaskix_device::Bus>(common: &CommonCfg<B>) -> bool {
    common.queue_select.write(0);
    common.queue_msix_vector.write(0);
    common.config_msix_vector.write(0);
    common.queue_msix_vector.read() == 0
}

/// Allocates one frame and returns `(physical, virtual)`.
///
/// A whole frame for each ring part, which wastes most of three pages. The
/// alternative is packing them together, and the packing has to respect three
/// different alignments and stay inside one frame — arithmetic that is wrong
/// silently, in a structure the device writes to by DMA. Twelve kilobytes is
/// a fair price for not having to be right about that.
fn frame(hhdm: u64) -> Option<(u64, u64)> {
    let pfn = heap::with(|heap| heap.pmm_mut().allocate(0, Zone::Normal).ok())??;
    let physical = u64::from(pfn) * FRAME_SIZE;
    // SAFETY: a frame that was just allocated, so nothing else refers to it,
    // reachable through the direct map. Zeroed because the device reads it and
    // a stale descriptor is an address it will happily use.
    unsafe {
        core::ptr::write_bytes((hhdm + physical) as *mut u8, 0, FRAME_SIZE as usize);
    }
    Some((physical, hhdm + physical))
}

/// Finds the block device, if there is one.
fn find() -> Option<(pci::Address, pci::Identity)> {
    find_nth(0)
}

/// Where a modern virtio device's three structures are, in physical memory.
///
/// The half of a driver that must stay in the kernel when the rest of it moves
/// into a domain: finding these means reading PCI configuration space, which
/// is port I/O, which a domain cannot be given without giving it every device
/// on the bus. So the kernel enumerates and the domain drives — the split is
/// not a convenience, it is where the hardware puts the line.
#[derive(Clone, Copy, Debug)]
pub struct Layout {
    /// Common configuration structure.
    pub common: (u64, u64),
    /// Queue notification area, and how far apart consecutive queues are.
    pub notify: (u64, u64),
    /// The multiplier between one queue's notify address and the next.
    pub notify_multiplier: u32,
    /// Device-specific configuration.
    pub device: (u64, u64),
}

/// Reads a device's capability list and says where its structures are.
///
/// Does not touch the device: this is configuration space, and a device that
/// is about to be handed to somebody else must arrive in the state its owner
/// expects rather than in one this function left behind.
#[must_use]
pub fn layout(address: pci::Address) -> Option<Layout> {
    let mut common_at = None;
    let mut notify_at = None;
    let mut notify_multiplier = 0u32;
    let mut device_at = None;

    // SAFETY: configuration reads on the bootstrap CPU during boot.
    unsafe {
        pci::for_each_capability(address, |capability| {
            if capability.id != CAP_VENDOR_SPECIFIC {
                return true;
            }
            let kind = pci::read8(address, capability.offset + 3);
            let bar_index = pci::read8(address, capability.offset + 4);
            let offset = pci::read32(address, capability.offset + 8);
            let length = pci::read32(address, capability.offset + 12);

            let pci::Bar::Memory { address: base, .. } = pci::bar(address, bar_index) else {
                return true;
            };

            let where_it_is = (base + u64::from(offset), u64::from(length));
            match kind {
                CFG_COMMON => common_at = Some(where_it_is),
                CFG_NOTIFY => {
                    notify_at = Some(where_it_is);
                    notify_multiplier = pci::read32(address, capability.offset + 16);
                }
                CFG_DEVICE => device_at = Some(where_it_is),
                _ => {}
            }
            true
        });
    }

    Some(Layout {
        common: common_at?,
        notify: notify_at?,
        notify_multiplier,
        device: device_at?,
    })
}

/// Finds the `skip`-th virtio block device on the bus, in bus order.
///
/// The kernel drives the first and hands the second to a domain. Two drivers
/// on one device would be a disaster -- resets racing, rings interleaved --
/// so the driver in a domain gets a device of its own rather than a share of
/// this one. Bus order is stable within a machine configuration, which is what
/// makes "the second one" a thing a boot can say and a test can rely on.
#[must_use]
pub fn find_nth(skip: usize) -> Option<(pci::Address, pci::Identity)> {
    find_nth_of(Class::BLOCK, skip)
}

/// Finds the `skip`-th virtio device of `class` on the bus, in bus order.
///
/// The general form of [`find_nth`], which is now a wrapper on it. Written when
/// the network device arrived and needed the same walk with two different
/// numbers: the alternative was a second copy of the transitional-versus-modern
/// rule, and that rule is the one the block path already got wrong once.
#[must_use]
pub fn find_nth_of(class: Class, skip: usize) -> Option<(pci::Address, pci::Identity)> {
    let mut found = None;
    let mut seen = 0usize;
    // SAFETY: bootstrap CPU during boot; nothing else is driving a
    // configuration cycle.
    unsafe {
        pci::for_each(|address, identity| {
            if class.matches(identity) {
                if seen == skip {
                    found = Some((address, identity));
                    return false;
                }
                seen += 1;
            }
            true
        });
    }
    found
}

/// Brings the device up: finds it, maps it, negotiates, builds its queue.
///
/// # Errors
///
/// [`BlockError`] naming what was missing. Every one is survivable — the
/// kernel boots without a disk, and says so.
pub fn init(hhdm: u64) -> Result<u64, BlockError> {
    init_mapped(hhdm, None)
}

/// Reads one sector into `device_address`, which is deliberately not checked.
///
/// The negative test RFC 0012 asks for, and nothing else may call it: it hands
/// the device an address the driver did not map, so that the unit's refusal
/// can be observed instead of assumed. Expect it to fail — a success means the
/// device reached memory nobody gave it.
///
/// # Errors
///
/// [`BlockError::TimedOut`] is the expected outcome, because a refused access
/// never completes.
pub fn read_into(sector: u64, device_address: u64) -> Result<(), BlockError> {
    let _request = Request::acquire()?;
    let (notification, handler) = {
        let mut guard = DEVICE.lock();
        let device = guard.as_mut().ok_or(BlockError::NotPresent)?;
        device.submit_to(sector, SECTOR as u32, device_address)?;
        (device.notification, device.handler)
    };
    await_completion(notification, handler)
}

/// Stops the block device doing DMA, before anything else is decided.
///
/// Called before translation is enabled. See `pci::quiesce`: the device the
/// firmware enumerated is still a bus master, still pointed at physical
/// addresses, and the moment a unit starts translating those become faults
/// attributed to a driver that has not run yet.
///
/// Bringing the device up afterwards re-enables bus mastering, so this costs
/// nothing but the ordering it enforces.
pub fn quiesce() {
    if let Some((address, _)) = find() {
        // SAFETY: this device is the kernel's -- it is about to be brought up
        // by `init_mapped`, and nothing else in this kernel drives it.
        unsafe { bhaskix_arch::pci::quiesce(address) };
    }
}

/// Finds the block device without touching it.
///
/// Needed because a `DmaWindow` names the device it translates for, so the
/// window must exist before the device is programmed — and the device's
/// requester id is what the window is built from. Scanning twice is cheaper
/// than threading the whole bring-up through the IOMMU.
#[must_use]
pub fn probe() -> Option<(u8, u8, u8)> {
    let (address, _) = find()?;
    Some((address.bus, address.device, address.function))
}

/// Brings the device up, mapping every frame it will hand the device.
///
/// `map` turns a physical frame into the address the device should be given.
/// `None` means there is no IOMMU and the two are the same number — the path
/// every machine without VT-d takes, and the one that must keep working.
///
/// The mapping happens *here*, before the device is told about any of it,
/// because there is no moment afterwards when it would be safe: from
/// `DRIVER_OK` the device may read the rings, and a ring it cannot translate
/// is a request that faults instead of completing.
///
/// # Errors
///
/// [`BlockError`] naming what was refused, including a frame that could not be
/// mapped — which is a refusal to bring the device up rather than a device
/// brought up with an address it cannot reach.
pub fn init_mapped(hhdm: u64, map: Option<&dyn Fn(u64) -> Option<u64>>) -> Result<u64, BlockError> {
    let (address, _) = find().ok_or(BlockError::NotFound)?;

    // Memory access and bus mastering before anything else: a device that is
    // not a bus master cannot write to the used ring, so every request would
    // time out and the device would look broken rather than disabled.
    //
    // Firmware has usually done this already, which is why removing this call
    // changes nothing on the machines Bhaskix is tested on. It is kept because
    // "usually" is a property of the firmware rather than of the requirement,
    // and `command()` below lets a test assert the state rather than the call.
    // Memory space now, bus mastering *after* the device has been reset. The
    // BARs must be readable to find the capabilities; letting the device touch
    // memory before it has been reset means it does so with the ring firmware
    // configured, which with translation on is a fault nobody owns.
    // SAFETY: this device is the kernel's from here on.
    unsafe { pci::enable_memory(address) };

    // Walk the capability list for the three structures a modern device must
    // expose. A device missing any of them is not one this driver understands,
    // which is a refusal rather than a guess at fixed offsets.
    let mut common_at = None;
    let mut notify_at = None;
    let mut notify_multiplier = 0u32;
    let mut device_at = None;

    // SAFETY: configuration reads on the bootstrap CPU during boot.
    unsafe {
        pci::for_each_capability(address, |capability| {
            if capability.id != CAP_VENDOR_SPECIFIC {
                return true;
            }
            let kind = pci::read8(address, capability.offset + 3);
            let bar_index = pci::read8(address, capability.offset + 4);
            let offset = pci::read32(address, capability.offset + 8);
            let length = pci::read32(address, capability.offset + 12);

            let pci::Bar::Memory { address: base, .. } = pci::bar(address, bar_index) else {
                // A structure in I/O space is a legacy device's, and this
                // driver maps memory. Skipped rather than misread.
                return true;
            };

            let where_it_is = (base + u64::from(offset), u64::from(length));
            match kind {
                CFG_COMMON => common_at = Some(where_it_is),
                CFG_NOTIFY => {
                    notify_at = Some(where_it_is);
                    // The notify capability has one extra field: how far apart
                    // consecutive queues' notification addresses are.
                    notify_multiplier = pci::read32(address, capability.offset + 16);
                }
                CFG_DEVICE => device_at = Some(where_it_is),
                _ => {}
            }
            true
        });
    }

    let (common_base, common_length) = common_at.ok_or(BlockError::NotModern)?;
    let (notify_base, notify_length) = notify_at.ok_or(BlockError::NotModern)?;
    let (device_base, device_length) = device_at.ok_or(BlockError::NotModern)?;

    let common_at =
        crate::mmio::map(common_base, common_length, hhdm).ok_or(BlockError::MapFailed)?;
    // SAFETY: `mmio::map` returned a mapping of this device's common
    // configuration structure, which lives for the machine's life. This is the
    // one promise; every register access below is safe because of it.
    let common = unsafe { CommonCfg::<bhaskix_device::Volatile>::new(common_at as usize) };
    let notify = crate::mmio::map(notify_base, notify_length, hhdm).ok_or(BlockError::MapFailed)?;
    let device_config_at =
        crate::mmio::map(device_base, device_length, hhdm).ok_or(BlockError::MapFailed)?;
    // SAFETY: as above, for the device-specific structure.
    let device_config =
        unsafe { BlockCfg::<bhaskix_device::Volatile>::new(device_config_at as usize) };

    // The bring-up sequence the specification fixes. Its order is the whole
    // protocol: a status bit written early enough is a promise the driver has
    // not yet kept.
    // SAFETY: `common` is the mapped common configuration structure of the
    // device this function owns.
    let capacity = unsafe {
        common.device_status.write(0); // reset
        // Reset first, then let it reach memory: from here its only
        // configuration is this driver's.
        pci::enable(address);
        common.device_status.write(STATUS_ACKNOWLEDGE);
        common
            .device_status
            .write(STATUS_ACKNOWLEDGE | STATUS_DRIVER);

        // Feature word 1 holds VIRTIO_F_VERSION_1. Offering nothing else is
        // deliberate: every optional feature is a behaviour this driver would
        // then have to implement, and a device is entitled to assume the
        // driver meant it.
        negotiate(&common)?;

        // Capacity, in 512-byte sectors, from the device-specific structure.
        device_config.capacity.read()
    };

    // Each frame, then the address the device will see for it.
    let translate = |frame: (u64, u64)| -> Result<(u64, u64, u64), BlockError> {
        let device = match map {
            Some(map) => map(frame.0).ok_or(BlockError::OutOfMemory)?,
            None => frame.0,
        };
        Ok((frame.0, frame.1, device))
    };

    let descriptors = translate(frame(hhdm).ok_or(BlockError::OutOfMemory)?)?;
    let available = translate(frame(hhdm).ok_or(BlockError::OutOfMemory)?)?;
    let used = translate(frame(hhdm).ok_or(BlockError::OutOfMemory)?)?;
    let buffer = translate(frame(hhdm).ok_or(BlockError::OutOfMemory)?)?;
    let request = translate(frame(hhdm).ok_or(BlockError::OutOfMemory)?)?;

    // No `unsafe` here any more, and that is RFC 0014 step 2's whole result:
    // the promise that these addresses are registers was made once, where the
    // block was constructed, so the accesses are ordinary code. Every address
    // written below is still one of the frames just allocated, which is the
    // only reason the device may write to them -- but that is an argument
    // about the *values*, and it always was.
    let notify_address = {
        common.queue_select.write(0);

        // The device says how deep the queue may be; the driver may ask for
        // less. Asking for less is what keeps the ring inside one frame.
        let offered = common.queue_size.read();
        let size = offered.min(QUEUE_SIZE);
        common.queue_size.write(size);

        // The device-visible addresses, not the physical ones. The rings are
        // themselves read by DMA, so they are translated exactly like the
        // buffers are -- a driver that mapped its buffers and then handed over
        // a physical ring address would fault on the first request.
        common.queue_desc.write(descriptors.2);
        common.queue_driver.write(available.2);
        common.queue_device.write(used.2);

        let queue_notify_off = common.queue_notify_off.read();
        common.queue_enable.write(1);

        common
            .device_status
            .write(STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK);

        notify + u64::from(queue_notify_off) * u64::from(notify_multiplier)
    };

    *DEVICE.lock() = Some(Device {
        address,
        common,
        notify: notify_address,
        descriptors,
        available,
        used,
        buffer,
        request,
        // SAFETY: three frames this function allocated and zeroed, each
        // mapped through the direct map for the machine's life, and the size
        // is a power of two.
        queue: unsafe {
            bhaskix_device::virtqueue::Virtqueue::new(
                bhaskix_device::virtqueue::Ring {
                    at: descriptors.1 as usize,
                    device: descriptors.2,
                },
                bhaskix_device::virtqueue::Ring {
                    at: available.1 as usize,
                    device: available.2,
                },
                bhaskix_device::virtqueue::Ring {
                    at: used.1 as usize,
                    device: used.2,
                },
                QUEUE_SIZE,
            )
        },
        capacity,
        notification: None,
        handler: None,
    });

    Ok(capacity)
}

/// Whether a device was found and brought up.
#[must_use]
pub fn present() -> bool {
    DEVICE.lock().is_some()
}

/// The physical page the device's common configuration registers live in.
///
/// For handing a *domain* the registers, as a `Frame` capability. The kernel
/// keeps its own mapping; this is the address, not the mapping, because a
/// capability names a thing and each holder maps it into its own space.
///
/// Page-aligned and one page: the common configuration is far smaller than a
/// page, and a holder gets what the hardware can be divided into rather than
/// what it asked for. Whatever else shares that page shares it — which is a
/// property of the device's layout and worth knowing about before a driver is
/// given one.
#[must_use]
pub fn registers(hhdm: u64) -> Option<u64> {
    let device = DEVICE.lock();
    // The block knows where it is, which is the address `mmio::map` returned
    // for it -- so the physical page is that minus the direct map base.
    let common = device.as_ref()?.common.device_status.address() as u64;
    let base = common - u64::from(COMMON_STATUS_OFFSET);
    base.checked_sub(hhdm)
        .map(|physical| physical & !(FRAME_SIZE - 1))
}

/// How many 512-byte sectors the device has.
#[must_use]
pub fn capacity() -> u64 {
    DEVICE.lock().as_ref().map_or(0, |device| device.capacity)
}

/// Requests completed and requests abandoned.
#[must_use]
pub fn statistics() -> (u64, u64) {
    (
        COMPLETED.load(Ordering::Relaxed),
        TIMEOUTS.load(Ordering::Relaxed),
    )
}

/// Blocks on an interrupt, and spin iterations for want of one.
#[must_use]
pub fn waiting() -> (u64, u64) {
    (WAITS.load(Ordering::Relaxed), SPINS.load(Ordering::Relaxed))
}

/// Blocks that woke with nothing signalled -- the clock, not the device.
#[must_use]
pub fn unsignalled() -> u64 {
    UNSIGNALLED.load(Ordering::Relaxed)
}

/// The physical frames this driver hands the device by DMA.
///
/// The rings, the buffer and the request header — everything whose address
/// appears in a descriptor. RFC 0012 step 3 identity-maps exactly these into
/// the device's window before enabling translation: the driver still puts
/// physical addresses in its descriptors, so the window must translate them to
/// themselves or the first read after enabling faults.
///
/// Naming them here rather than mapping "the driver's memory" is the point.
/// The set is five frames, it is written down, and a device that reaches
/// anything else is refused — which is the property the whole RFC is for.
#[must_use]
pub fn dma_frames() -> Option<[u64; 5]> {
    let guard = DEVICE.lock();
    let device = guard.as_ref()?;
    Some([
        device.descriptors.0,
        device.available.0,
        device.used.0,
        device.buffer.0,
        device.request.0,
    ])
}

/// The interrupt handler this driver claimed, if it has one.
#[must_use]
pub fn handler() -> Option<crate::irq::HandlerId> {
    DEVICE.lock().as_ref()?.handler
}

/// Points this device's interrupt back at the driver's own notification.
///
/// Needed because `BIND` is exactly the authority to redirect an interrupt,
/// and a self-test that hands that authority to a domain has the domain use
/// it. Putting it back is the test cleaning up after itself rather than the
/// driver losing its interrupt for the rest of the boot.
pub fn rebind_notification() -> bool {
    let (handler, notification) = {
        let guard = DEVICE.lock();
        let Some(device) = guard.as_ref() else {
            return false;
        };
        match (device.handler, device.notification) {
            (Some(handler), Some(notification)) => (handler, notification),
            _ => return false,
        }
    };
    crate::irq::bind(handler, notification, 1).is_ok()
}

/// Whether this device's DMA is subject to the platform's translation.
///
/// False means the device may address memory directly however the IOMMU is
/// programmed, so any claim that translation protects *this* device is false.
#[must_use]
pub fn translated() -> bool {
    TRANSLATED.load(Ordering::Relaxed)
}

/// Whether the device delivers interrupts rather than being polled.
#[must_use]
pub fn interrupt_driven() -> bool {
    DEVICE
        .lock()
        .as_ref()
        .is_some_and(|device| device.notification.is_some())
}

/// Claims the device's first MSI-X entry and binds a notification to it.
///
/// Called after bring-up, because it needs the vector allocator and the I/O
/// APIC — and because a device that is not yet configured has nothing to
/// interrupt about. Failure is survivable: the driver polls, and says so.
///
/// # Errors
///
/// [`BlockError`] if the source could not be claimed or bound.
/// The status byte the device reports, read back from its registers.
///
/// `0x0f` is a device that has acknowledged, accepted the feature set, and
/// been told the driver is ready — anything else means bring-up did not finish
/// or the device reset itself afterwards.
#[must_use]
pub fn status() -> u8 {
    DEVICE
        .lock()
        .as_ref()
        .map_or(0, |device| device.common.device_status.read())
}

/// The device's PCI command register.
///
/// What a caller wants from it is whether memory access and bus mastering are
/// on: without both, the device cannot reach the rings and every request times
/// out. Read back from the device rather than remembered, because what matters
/// is the state of the hardware and not what this driver believes it wrote.
#[must_use]
pub fn command() -> u16 {
    DEVICE.lock().as_ref().map_or(0, |device| {
        // SAFETY: a configuration read of the device this driver owns, which
        // has no side effects.
        unsafe { pci::read16(device.address, 0x04) }
    })
}

/// Where the device is on the bus, for reporting.
#[must_use]
pub fn location() -> Option<(u8, u8, u8)> {
    DEVICE.lock().as_ref().map(|device| {
        (
            device.address.bus,
            device.address.device,
            device.address.function,
        )
    })
}

/// Claims the device's first MSI-X entry and binds a notification to it.
///
/// Called after bring-up, because it needs the vector allocator and the I/O
/// APIC — and because a device that is not yet configured has nothing to
/// interrupt about. Failure is survivable: the driver polls, and says so.
///
/// # Errors
///
/// [`BlockError`] if the source could not be claimed or bound.
pub fn enable_interrupts(
    apic_id: u32,
    rsdp: Option<bhaskix_boot::PhysAddr>,
    hhdm: u64,
) -> Result<u8, BlockError> {
    /// The badge the device signals with.
    const BADGE: u64 = 1 << 0;

    // Where the device is, and nothing else, under the lock. Everything that
    // follows takes locks ranking *below* this driver's -- the notification
    // arena, the interrupt handlers, the vector allocator, the heap for the
    // MSI-X mapping -- and holding this one across them is the inversion the
    // lock-order checker reported six times over. It is the same mistake
    // `read` made, in the same module, on the same lock.
    let address = {
        let guard = DEVICE.lock();
        guard.as_ref().ok_or(BlockError::NotPresent)?.address
    };

    let notification = crate::notify::create().map_err(|_| BlockError::OutOfMemory)?;
    // SAFETY: `trap` dispatches claimed vectors to `irq::on_interrupt`, which
    // acknowledges the local APIC.
    let handler = unsafe {
        crate::irq::claim(
            crate::irq::Source::MessageSignalled {
                device: address,
                entry: 0,
            },
            "virtio-blk",
            apic_id,
            rsdp,
            hhdm,
        )
    }
    .map_err(|_| BlockError::NotModern)?;

    if crate::irq::bind(handler, notification, BADGE).is_err() {
        crate::irq::release(handler);
        crate::notify::destroy(notification);
        return Err(BlockError::NotModern);
    }
    let vector = crate::irq::vector_of(handler).unwrap_or(0);

    // Now the device's own registers, with nothing else acquired while the
    // lock is held.
    let accepted = {
        let mut guard = DEVICE.lock();
        let device = guard.as_mut().ok_or(BlockError::NotPresent)?;

        // Tell the device which MSI-X entry its queue and its configuration
        // changes use. Read back: the device reports `0xffff` if it could not
        // take the vector, and a driver that did not check would wait for an
        // interrupt that was never going to arrive.
        let accepted = take_vector(&device.common);
        if accepted {
            device.notification = Some(notification);
            device.handler = Some(handler);
        }
        accepted
    };

    if !accepted {
        // Outside the lock, for the reason above.
        crate::irq::release(handler);
        crate::notify::destroy(notification);
        return Err(BlockError::NotModern);
    }
    Ok(vector)
}

/// Reads `buffer.len()` bytes starting at `sector`.
///
/// The length must be a whole number of sectors and must fit in the driver's
/// one page of bounce buffer. Both are refusals rather than clamps: a short
/// read that reported success would be a filesystem reading a hole.
///
/// # Errors
///
/// [`BlockError`] naming what went wrong.
pub fn read(sector: u64, buffer: &mut [u8]) -> Result<(), BlockError> {
    if buffer.is_empty() {
        return Ok(());
    }
    if buffer.len() as u64 > FRAME_SIZE || !(buffer.len() as u64).is_multiple_of(SECTOR) {
        return Err(BlockError::TooLarge);
    }

    // One request at a time, enforced by a flag rather than by holding the
    // device lock across the wait.
    //
    // Holding it was the first version, and it was wrong in a way the
    // lock-order checker named: waiting means blocking, blocking takes a
    // runqueue lock and an interrupt-handler lock, and both rank *below* this
    // driver's. A spinlock held across a block is also what M4-08 exists to
    // refuse -- `block_self` will not switch away from a thread holding one,
    // so the "sleep" was a spin with a lock held, the worst of both.
    let _request = Request::acquire()?;

    let (notification, handler) = {
        let mut guard = DEVICE.lock();
        let device = guard.as_mut().ok_or(BlockError::NotPresent)?;

        let sectors = buffer.len() as u64 / SECTOR;
        if sector
            .checked_add(sectors)
            .is_none_or(|end| end > device.capacity)
        {
            return Err(BlockError::OutOfRange);
        }

        device.submit(sector, buffer.len() as u32)?;
        (device.notification, device.handler)
    };

    // Outside every lock. This is the part that may take milliseconds.
    let outcome = await_completion(notification, handler);

    let mut guard = DEVICE.lock();
    let device = guard.as_mut().ok_or(BlockError::NotPresent)?;
    outcome?;

    // SAFETY: `buffer` names the frame the device just wrote into, through the
    // direct map, and the length was bounded to that frame above.
    unsafe {
        core::ptr::copy_nonoverlapping(
            device.buffer.1 as *const u8,
            buffer.as_mut_ptr(),
            buffer.len(),
        );
    }
    Ok(())
}

/// Serialises requests without a spinlock, so the waiting happens with no lock
/// held at all.
///
/// A spinlock cannot be held across a block; this can, because the scheduler
/// does not know about it — a contending thread yields rather than spinning,
/// so the CPU goes to whoever is doing useful work.
struct Request;

static IN_FLIGHT: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

impl Request {
    fn acquire() -> Result<Self, BlockError> {
        let deadline = crate::time::now()
            + crate::time::micros(REQUEST_TIMEOUT_MICROS).unwrap_or(u64::MAX / 2);
        loop {
            if IN_FLIGHT
                .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                return Ok(Self);
            }
            if crate::time::now() >= deadline {
                return Err(BlockError::TimedOut);
            }
            crate::sched::yield_now();
        }
    }
}

impl Drop for Request {
    fn drop(&mut self) {
        IN_FLIGHT.store(false, Ordering::Release);
    }
}

/// Waits for the outstanding request, holding nothing.
///
/// Blocks on the notification when one is bound and spins when one is not. The
/// bound is kept either way: a device that has stopped answering must not stop
/// the kernel, so the interrupt-driven path arms its own deadline and blocks
/// *once* per pass, which is what `notify::wait_once` exists for.
fn await_completion(
    notification: Option<crate::notify::NotificationId>,
    handler: Option<crate::irq::HandlerId>,
) -> Result<(), BlockError> {
    let deadline =
        crate::time::now() + crate::time::micros(REQUEST_TIMEOUT_MICROS).unwrap_or(u64::MAX / 2);

    loop {
        // The completion check needs the device, so it takes the lock -- and
        // gives it straight back, without blocking while it is held.
        let finished = {
            let mut guard = DEVICE.lock();
            let device = guard.as_mut().ok_or(BlockError::NotPresent)?;
            device.completed()
        };

        if let Some(status) = finished {
            // Acknowledge *after* reading the completion and outside the
            // device lock: an edge raised while the source is masked is lost,
            // so the device must be read empty first, and `acknowledge` takes
            // a lock ranking below this driver's.
            if let Some(handler) = handler {
                let _ = crate::irq::acknowledge(handler);
            }
            COMPLETED.fetch_add(1, Ordering::Relaxed);
            return if status == 0 {
                Ok(())
            } else {
                Err(BlockError::Failed)
            };
        }

        if crate::time::now() >= deadline {
            TIMEOUTS.fetch_add(1, Ordering::Relaxed);
            if let Some(handler) = handler {
                let _ = crate::irq::acknowledge(handler);
            }
            return Err(BlockError::TimedOut);
        }

        match notification {
            Some(id) => {
                // Arm the deadline *before* blocking, or it is not a deadline.
                //
                // `wait_once` sleeps until the notification is signalled and
                // no longer. Without a timer the check at the top of this loop
                // is unreachable, so a completion interrupt that never arrives
                // does not fail this request -- it stops the machine. On a
                // single-processor boot, where the waiting thread is the only
                // runnable one, that is a dead machine with no output, and it
                // is what the fault-injection harness had been reporting about
                // one boot in four.
                //
                // RFC 0011: a device that stops answering must not stop the
                // kernel.
                if crate::time::wake_at(deadline) {
                    WAITS.fetch_add(1, Ordering::Relaxed);
                    let woken = crate::notify::wait_once(id);
                    crate::time::cancel_wake();
                    match woken {
                        Ok(0) => {
                            UNSIGNALLED.fetch_add(1, Ordering::Relaxed);
                        }
                        Ok(_) => {}
                        Err(_) => return Err(BlockError::TimedOut),
                    }
                } else {
                    // No timer left to wake us, so blocking here would be
                    // sleeping without a deadline. Spin instead: slower, and
                    // it still ends.
                    SPINS.fetch_add(1, Ordering::Relaxed);
                    core::hint::spin_loop();
                }
            }
            None => {
                SPINS.fetch_add(1, Ordering::Relaxed);
                core::hint::spin_loop();
            }
        }
    }
}

impl Device {
    /// Puts one read on the ring and rings the bell. Does not wait.
    fn submit(&mut self, sector: u64, length: u32) -> Result<(), BlockError> {
        let buffer = self.buffer.2;
        self.submit_to(sector, length, buffer)
    }

    /// Submits a read whose data lands at `buffer`, whatever that address is.
    ///
    /// Only the self-test that proves refusal passes anything but this
    /// device's own buffer. It exists so that "an address outside the window
    /// is refused" can be *demonstrated* rather than argued: RFC 0012's whole
    /// claim is that the hardware stops a device reaching what it was not
    /// given, and the only convincing evidence is to try.
    fn submit_to(&mut self, sector: u64, length: u32, buffer: u64) -> Result<(), BlockError> {
        let header = RequestHeader {
            kind: BLK_IN,
            reserved: 0,
            sector,
        };

        // SAFETY: every write below is to one of the frames this driver
        // allocated, through the direct map, at an offset inside it. The
        // descriptor addresses are the *physical* addresses of those frames,
        // because the device walks them itself with no page table.
        unsafe {
            core::ptr::write_volatile(self.request.1 as *mut RequestHeader, header);
            // The status byte, in the same frame, past the header. Set to a
            // value the device never writes, so "the device answered" and "the
            // device said ok" cannot be confused.
            core::ptr::write_volatile((self.request.1 + 16) as *mut u8, 0xff);
        }

        // The queue's own layout and ordering, from the crate the domain's
        // driver uses too. The descriptors carry the addresses the *device*
        // was given -- `.2` of each tuple -- which with an IOMMU in front of
        // it are not the physical ones.
        self.queue
            .describe(0, self.request.2, 16, virtqueue::NEXT, 1);
        self.queue
            .describe(1, buffer, length, virtqueue::NEXT | virtqueue::WRITE, 2);
        self.queue
            .describe(2, self.request.2 + 16, 1, virtqueue::WRITE, 0);
        self.queue.publish(0);

        // SAFETY: the notification address this driver computed at bring-up
        // from the offset the device published.
        unsafe {
            // Ring the bell.
            write16(self.notify, 0);
        }
        Ok(())
    }

    /// Whether the outstanding request has finished, and its status byte.
    ///
    /// Takes no lock and never blocks: the caller holds the device lock for
    /// exactly this call and waits outside it.
    fn completed(&mut self) -> Option<u8> {
        self.queue.completed()?;

        // SAFETY: the status byte the device was told to write, in the
        // driver's own frame.
        Some(unsafe { read8(self.request.1 + 16) })
    }
}

/// Reads the whole device into a buffer allocated for it.
///
/// For loading a filesystem image at boot: the image is small, it is read
/// once, and everything above wants a slice. Bounded by `limit` bytes, because
/// a device reporting an implausible capacity would otherwise be an allocation
/// the size of whatever it claimed.
///
/// # Errors
///
/// [`BlockError`] as [`read`].
pub fn read_all(limit: u64) -> Result<alloc::vec::Vec<u8>, BlockError> {
    let sectors = capacity().min(limit / SECTOR);
    if sectors == 0 {
        return Err(BlockError::NotPresent);
    }

    let mut image = alloc::vec::Vec::new();
    // Reserved up front so a failure to allocate happens before any I/O rather
    // than half way through it.
    image
        .try_reserve_exact((sectors * SECTOR) as usize)
        .map_err(|_| BlockError::OutOfMemory)?;

    // A page at a time, which is what the driver's bounce buffer holds.
    let per_read = (FRAME_SIZE / SECTOR).min(sectors);
    let mut chunk = alloc::vec![0u8; (per_read * SECTOR) as usize];

    let mut sector = 0;
    while sector < sectors {
        let count = per_read.min(sectors - sector);
        let bytes = (count * SECTOR) as usize;
        read(sector, &mut chunk[..bytes])?;
        image.extend_from_slice(&chunk[..bytes]);
        sector += count;
    }
    Ok(image)
}

#[cfg(test)]
mod tests {
    use bhaskix_device::testing::{self, Model};

    use super::{CommonCfg, FEATURE_ACCESS_PLATFORM, FEATURE_VERSION_1, negotiate, take_vector};

    /// The driver's own bring-up, run against a device model on the host.
    ///
    /// RFC 0014 step 3. This is the code the kernel runs — not a copy of it —
    /// reached through a `Bus` that is a model instead of a machine. Until the
    /// register accessors made that possible, the only way to find out what
    /// this function did about a device that said no was to find a device that
    /// said no.
    fn block() -> CommonCfg<Model> {
        // SAFETY: `Model` answers from a register file rather than from
        // memory, so "this address is a register" is true by construction.
        unsafe { CommonCfg::<Model>::new(0) }
    }

    /// Offers a feature word at `device_feature`, as a device would.
    fn offer_features(bits: u32) {
        testing::offer(0x04, &bits.to_le_bytes());
    }

    #[test]
    fn a_device_that_does_not_offer_virtio_1_is_refused() {
        let _alone = testing::exclusive();
        // Everything zero: a device offering nothing.
        assert!(negotiate(&block()).is_err());

        // And it was told, rather than merely abandoned. A driver that walks
        // away without writing FAILED leaves a device believing a driver is
        // still coming.
        let told = (0..testing::accesses())
            .map(testing::access)
            .any(|(write, _, at, value)| write && at == 0x14 && value & 0x80 != 0);
        assert!(told, "the device is told the driver failed");
    }

    #[test]
    fn a_device_that_refuses_the_feature_set_is_believed() {
        let _alone = testing::exclusive();
        offer_features(FEATURE_VERSION_1);
        testing::refuse_features();

        assert!(
            negotiate(&block()).is_err(),
            "a device clears FEATURES_OK to say no, and the read-back is the \
             only way the driver hears it"
        );
    }

    #[test]
    fn access_platform_is_taken_whenever_it_is_offered() {
        let _alone = testing::exclusive();
        offer_features(FEATURE_VERSION_1 | FEATURE_ACCESS_PLATFORM);
        assert!(negotiate(&block()).is_ok());

        // What was written back to `driver_feature` for word 1. Taking
        // ACCESS_PLATFORM is what subjects the device to the IOMMU, so a
        // driver that quietly dropped it would be asking to be outside the
        // protection the kernel is building -- and everything else would still
        // work, which is why this is asserted rather than assumed.
        let accepted = (0..testing::accesses())
            .map(testing::access)
            .filter(|(write, _, at, _)| *write && *at == 0x0c)
            .map(|(_, _, _, value)| value)
            .next_back();
        assert_eq!(
            accepted,
            Some(u64::from(FEATURE_VERSION_1 | FEATURE_ACCESS_PLATFORM)),
            "both bits accepted"
        );
    }

    #[test]
    fn a_device_that_gives_a_vector_is_believed() {
        let _alone = testing::exclusive();
        assert!(take_vector(&block()));
    }

    #[test]
    fn a_device_that_will_not_give_a_vector_says_so_and_is_heard() {
        // Two tests, not one with two guards. The first version took
        // `exclusive` twice in a single test: the guards are shadowed rather
        // than dropped, so the second call spun on a lock the first still
        // held, and the test hung instead of failing. The model is one
        // device, and one test uses it once.
        let _alone = testing::exclusive();
        testing::refuse_vector();
        assert!(
            !take_vector(&block()),
            "0xffff is no vector; a driver that did not read it back would \
             wait for an interrupt that is never going to arrive"
        );
    }
}
