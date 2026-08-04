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

use core::sync::atomic::{Ordering, fence};

use bhaskix_arch::pci;
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

/// Descriptor flags.
const DESC_NEXT: u16 = 1;
const DESC_WRITE: u16 = 2;

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

/// One entry of the descriptor table, as the device reads it.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Descriptor {
    address: u64,
    length: u32,
    flags: u16,
    next: u16,
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
    common: u64,
    /// Where this queue is notified.
    notify: u64,

    /// Physical and virtual addresses of the one ring's three parts.
    descriptors: (u64, u64),
    available: (u64, u64),
    used: (u64, u64),
    /// The buffer requests read into.
    buffer: (u64, u64),
    /// The request header and status byte.
    request: (u64, u64),

    /// What the driver has published to the available ring so far.
    available_index: u16,
    /// What it has seen in the used ring so far.
    used_index: u16,

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

/// Reads a `u32` from a mapped register.
///
/// # Safety
///
/// `address` must be inside a mapped device window.
unsafe fn read32(address: u64) -> u32 {
    // SAFETY: the caller guarantees a mapped register; volatile because the
    // value is the device's and may change without this code writing it.
    unsafe { core::ptr::read_volatile(address as *const u32) }
}

/// # Safety
///
/// As [`read32`].
unsafe fn write32(address: u64, value: u32) {
    // SAFETY: the caller's obligation.
    unsafe { core::ptr::write_volatile(address as *mut u32, value) }
}

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
unsafe fn read16(address: u64) -> u16 {
    // SAFETY: the caller's obligation.
    unsafe { core::ptr::read_volatile(address as *const u16) }
}

/// # Safety
///
/// As [`read32`].
unsafe fn write64(address: u64, value: u64) {
    // SAFETY: the caller's obligation. Written as two 32-bit stores because
    // the specification defines these registers that way, and a device model
    // is entitled to notice the difference.
    unsafe {
        write32(address, value as u32);
        write32(address + 4, (value >> 32) as u32);
    }
}

/// # Safety
///
/// As [`read32`].
unsafe fn write8(address: u64, value: u8) {
    // SAFETY: the caller's obligation.
    unsafe { core::ptr::write_volatile(address as *mut u8, value) }
}

/// # Safety
///
/// As [`read32`].
unsafe fn read8(address: u64) -> u8 {
    // SAFETY: the caller's obligation.
    unsafe { core::ptr::read_volatile(address as *const u8) }
}

/// Offsets within the common configuration structure.
mod common {
    pub const DEVICE_FEATURE_SELECT: u64 = 0x00;
    pub const DEVICE_FEATURE: u64 = 0x04;
    pub const DRIVER_FEATURE_SELECT: u64 = 0x08;
    pub const DRIVER_FEATURE: u64 = 0x0c;
    pub const CONFIG_MSIX_VECTOR: u64 = 0x10;
    pub const DEVICE_STATUS: u64 = 0x14;
    pub const QUEUE_SELECT: u64 = 0x16;
    pub const QUEUE_SIZE: u64 = 0x18;
    pub const QUEUE_MSIX_VECTOR: u64 = 0x1a;
    pub const QUEUE_ENABLE: u64 = 0x1c;
    pub const QUEUE_NOTIFY_OFF: u64 = 0x1e;
    pub const QUEUE_DESC: u64 = 0x20;
    pub const QUEUE_DRIVER: u64 = 0x28;
    pub const QUEUE_DEVICE: u64 = 0x30;
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
    let mut found = None;
    // SAFETY: bootstrap CPU during boot; nothing else is driving a
    // configuration cycle.
    unsafe {
        pci::for_each(|address, identity| {
            if identity.vendor != VIRTIO_VENDOR {
                return true;
            }
            // A modern device says what it is in its device id. A transitional
            // one reports the legacy id and says what it is in the subsystem
            // id instead -- so both have to be understood, or the driver works
            // on exactly one of QEMU's two default configurations.
            let block = identity.device == DEVICE_BLOCK_MODERN
                || (identity.device == DEVICE_TRANSITIONAL
                    && identity.subsystem == SUBSYSTEM_BLOCK);
            if block {
                found = Some((address, identity));
                return false;
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
    let (address, _) = find().ok_or(BlockError::NotFound)?;

    // Memory access and bus mastering before anything else: a device that is
    // not a bus master cannot write to the used ring, so every request would
    // time out and the device would look broken rather than disabled.
    //
    // Firmware has usually done this already, which is why removing this call
    // changes nothing on the machines Bhaskix is tested on. It is kept because
    // "usually" is a property of the firmware rather than of the requirement,
    // and `command()` below lets a test assert the state rather than the call.
    // SAFETY: this device is the kernel's from here on.
    unsafe { pci::enable(address) };

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

    let common = crate::mmio::map(common_base, common_length, hhdm).ok_or(BlockError::MapFailed)?;
    let notify = crate::mmio::map(notify_base, notify_length, hhdm).ok_or(BlockError::MapFailed)?;
    let device_config =
        crate::mmio::map(device_base, device_length, hhdm).ok_or(BlockError::MapFailed)?;

    // The bring-up sequence the specification fixes. Its order is the whole
    // protocol: a status bit written early enough is a promise the driver has
    // not yet kept.
    // SAFETY: `common` is the mapped common configuration structure of the
    // device this function owns.
    let capacity = unsafe {
        write8(common + common::DEVICE_STATUS, 0); // reset
        write8(common + common::DEVICE_STATUS, STATUS_ACKNOWLEDGE);
        write8(
            common + common::DEVICE_STATUS,
            STATUS_ACKNOWLEDGE | STATUS_DRIVER,
        );

        // Feature word 1 holds VIRTIO_F_VERSION_1. Offering nothing else is
        // deliberate: every optional feature is a behaviour this driver would
        // then have to implement, and a device is entitled to assume the
        // driver meant it.
        write32(common + common::DEVICE_FEATURE_SELECT, 1);
        let offered = read32(common + common::DEVICE_FEATURE);
        if offered & FEATURE_VERSION_1 == 0 {
            write8(common + common::DEVICE_STATUS, STATUS_FAILED);
            return Err(BlockError::NotModern);
        }
        write32(common + common::DRIVER_FEATURE_SELECT, 0);
        write32(common + common::DRIVER_FEATURE, 0);
        write32(common + common::DRIVER_FEATURE_SELECT, 1);
        write32(common + common::DRIVER_FEATURE, FEATURE_VERSION_1);

        write8(
            common + common::DEVICE_STATUS,
            STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK,
        );
        // Read the status back. The device clears this bit to refuse the
        // feature set, and a driver that did not check would carry on talking
        // a protocol the device is not speaking.
        if read8(common + common::DEVICE_STATUS) & STATUS_FEATURES_OK == 0 {
            write8(common + common::DEVICE_STATUS, STATUS_FAILED);
            return Err(BlockError::FeaturesRefused);
        }

        // Capacity, in 512-byte sectors, from the device-specific structure.
        u64::from(read32(device_config)) | (u64::from(read32(device_config + 4)) << 32)
    };

    let descriptors = frame(hhdm).ok_or(BlockError::OutOfMemory)?;
    let available = frame(hhdm).ok_or(BlockError::OutOfMemory)?;
    let used = frame(hhdm).ok_or(BlockError::OutOfMemory)?;
    let buffer = frame(hhdm).ok_or(BlockError::OutOfMemory)?;
    let request = frame(hhdm).ok_or(BlockError::OutOfMemory)?;

    // SAFETY: as above, and every address written is one of the frames just
    // allocated -- which is the only reason the device may write to them.
    let notify_address = unsafe {
        write16(common + common::QUEUE_SELECT, 0);

        // The device says how deep the queue may be; the driver may ask for
        // less. Asking for less is what keeps the ring inside one frame.
        let offered = read16(common + common::QUEUE_SIZE);
        let size = offered.min(QUEUE_SIZE);
        write16(common + common::QUEUE_SIZE, size);

        write64(common + common::QUEUE_DESC, descriptors.0);
        write64(common + common::QUEUE_DRIVER, available.0);
        write64(common + common::QUEUE_DEVICE, used.0);

        let queue_notify_off = read16(common + common::QUEUE_NOTIFY_OFF);
        write16(common + common::QUEUE_ENABLE, 1);

        write8(
            common + common::DEVICE_STATUS,
            STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK,
        );

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
        available_index: 0,
        used_index: 0,
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
pub fn enable_interrupts(
    apic_id: u32,
    rsdp: Option<bhaskix_boot::PhysAddr>,
    hhdm: u64,
) -> Result<u8, BlockError> {
    /// The badge the device signals with.
    const BADGE: u64 = 1 << 0;

    let mut guard = DEVICE.lock();
    let device = guard.as_mut().ok_or(BlockError::NotPresent)?;

    let notification = crate::notify::create().map_err(|_| BlockError::OutOfMemory)?;
    // SAFETY: `trap` dispatches claimed vectors to `irq::on_interrupt`, which
    // acknowledges the local APIC.
    let handler = unsafe {
        crate::irq::claim(
            crate::irq::Source::MessageSignalled {
                device: device.address,
                entry: 0,
            },
            "virtio-blk",
            apic_id,
            rsdp,
            hhdm,
        )
    }
    .map_err(|_| BlockError::NotModern)?;

    crate::irq::bind(handler, notification, BADGE).map_err(|_| BlockError::NotModern)?;

    // Tell the device which MSI-X entry its queue and its configuration
    // changes use. Read back: the device reports `0xffff` if it could not take
    // the vector, and a driver that did not check would then wait for an
    // interrupt that was never going to arrive.
    // SAFETY: the mapped common configuration of the device this driver owns.
    let accepted = unsafe {
        write16(device.common + common::QUEUE_SELECT, 0);
        write16(device.common + common::QUEUE_MSIX_VECTOR, 0);
        write16(device.common + common::CONFIG_MSIX_VECTOR, 0);
        read16(device.common + common::QUEUE_MSIX_VECTOR) == 0
    };
    if !accepted {
        crate::irq::release(handler);
        crate::notify::destroy(notification);
        return Err(BlockError::NotModern);
    }

    device.notification = Some(notification);
    device.handler = Some(handler);
    Ok(crate::irq::vector_of(handler).unwrap_or(0))
}

/// The status byte the device reports, read back from its registers.
///
/// `0x0f` is a device that has acknowledged, accepted the feature set, and
/// been told the driver is ready — anything else means bring-up did not finish
/// or the device reset itself afterwards.
#[must_use]
pub fn status() -> u8 {
    DEVICE.lock().as_ref().map_or(0, |device| {
        // SAFETY: the mapped common configuration of the device this driver
        // brought up; reading the status register has no side effects.
        unsafe { read8(device.common + common::DEVICE_STATUS) }
    })
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

impl Device {
    /// Puts one read on the ring, rings the bell, and waits for the answer.
    fn submit(&mut self, sector: u64, length: u32) -> Result<(), BlockError> {
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

            let table = self.descriptors.1 as *mut Descriptor;
            core::ptr::write_volatile(
                table,
                Descriptor {
                    address: self.request.0,
                    length: 16,
                    flags: DESC_NEXT,
                    next: 1,
                },
            );
            core::ptr::write_volatile(
                table.add(1),
                Descriptor {
                    address: self.buffer.0,
                    length,
                    flags: DESC_NEXT | DESC_WRITE,
                    next: 2,
                },
            );
            core::ptr::write_volatile(
                table.add(2),
                Descriptor {
                    address: self.request.0 + 16,
                    length: 1,
                    flags: DESC_WRITE,
                    next: 0,
                },
            );

            // The available ring: flags, index, then the ring itself.
            let ring = (self.available.1 + 4) as *mut u16;
            core::ptr::write_volatile(
                ring.add((self.available_index % QUEUE_SIZE) as usize),
                0, // the head of the chain just built
            );

            // Everything above must be visible to the device before the index
            // that publishes it. The device is not a thread and does not take
            // this lock; the fence is what orders the writes as far as it is
            // concerned.
            fence(Ordering::SeqCst);
            self.available_index = self.available_index.wrapping_add(1);
            core::ptr::write_volatile((self.available.1 + 2) as *mut u16, self.available_index);
            fence(Ordering::SeqCst);

            // Ring the bell.
            write16(self.notify, 0);
        }

        self.wait()
    }

    /// Waits for the used ring to advance, bounded.
    ///
    /// Blocks on a notification when one is bound, and spins when one is not.
    /// The bound is kept either way: a device that has stopped answering must
    /// not stop the kernel, so the interrupt-driven path arms a timer and
    /// blocks *once*, which is what `notify::wait_once` exists for.
    fn wait(&mut self) -> Result<(), BlockError> {
        let deadline = crate::time::now()
            + crate::time::micros(REQUEST_TIMEOUT_MICROS).unwrap_or(u64::MAX / 2);

        loop {
            // SAFETY: the used ring's index, in a frame this driver allocated
            // and the device writes to. Volatile because it changes without
            // this code writing it, which is the entire question being asked.
            let published = unsafe { core::ptr::read_volatile((self.used.1 + 2) as *const u16) };
            if published != self.used_index {
                fence(Ordering::SeqCst);
                self.used_index = published;
                COMPLETED.fetch_add(1, Ordering::Relaxed);

                // SAFETY: the status byte the device was told to write, in the
                // driver's own frame.
                let status = unsafe { read8(self.request.1 + 16) };

                // Acknowledge *after* reading the completion, never before.
                // Between delivery and this the source is masked, and an edge
                // raised while masked is lost -- so the device must be read
                // empty first (`docs/driver-model.md` §2).
                if let Some(handler) = self.handler {
                    let _ = crate::irq::acknowledge(handler);
                }

                return if status == 0 {
                    Ok(())
                } else {
                    Err(BlockError::Failed)
                };
            }

            if crate::time::now() >= deadline {
                TIMEOUTS.fetch_add(1, Ordering::Relaxed);
                if let Some(handler) = self.handler {
                    let _ = crate::irq::acknowledge(handler);
                }
                return Err(BlockError::TimedOut);
            }

            match self.notification {
                Some(id) => {
                    WAITS.fetch_add(1, Ordering::Relaxed);
                    // One block. Whether it was the device or the deadline
                    // that ended it is decided by the loop, not here.
                    if crate::notify::wait_once(id).is_err() {
                        return Err(BlockError::TimedOut);
                    }
                }
                None => {
                    SPINS.fetch_add(1, Ordering::Relaxed);
                    core::hint::spin_loop();
                }
            }
        }
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
