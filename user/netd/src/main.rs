// SPDX-License-Identifier: Apache-2.0
//! The network driver, in a domain of its own.
//!
//! [RFC 0018](../../../docs/rfc/0018-networking.md) step 2. It drives the
//! machine's virtio network device. The kernel has no network driver at all —
//! unlike the block path, where the kernel drives the first device and hands
//! over the second — so this is the only thing on the machine that touches it.
//!
//! # It moves frames and interprets none of them
//!
//! This is the property the two-domain split exists to create, and it is worth
//! stating as a rule because it is the kind that erodes one convenience at a
//! time: **a frame's bytes are opaque to the domain that has DMA.** This
//! program does not know what an IP header is, does not filter, and does not
//! link `bhaskix-net` — the parsers live in `ipd`, which has no device.
//!
//! The self-test below transmits a fixed byte template and reports what came
//! back by length and by its first octets. That is not parsing; the template is
//! a test vector, and reporting where a known six bytes appear is measurement.
//!
//! # What it holds
//!
//! Three `Frame`s for the virtio structures, a `Memory` object for its rings,
//! the authority to say what its device may reach, and an interrupt it may wait
//! on and acknowledge but never program. Seven capabilities, and no way to name
//! the bus: enumeration is port I/O and a domain holding that would hold every
//! device on the machine.
//!
//! # The one thing a block driver never has to think about
//!
//! A disk answers; a network device **initiates**. Receive buffers must be
//! posted before `DRIVER_OK`, because the answer to the frame this program is
//! about to send can arrive before the next instruction runs. A receive queue
//! with nothing posted does not fail — it drops, silently, which is why the
//! kernel gates transmit and receive as two separate findings.
#![no_std]
#![no_main]

use bhaskix_abi::{method, ring as chan, status, syscall};
use bhaskix_device::Volatile;
use bhaskix_device::virtqueue::{self, Virtqueue};

/// Slot: the common configuration structure.
const COMMON: u64 = 0;
/// Slot: the queue notification area.
const NOTIFY: u64 = 1;
/// Slot: device-specific configuration — for a network device, its MAC.
const DEVICE: u64 = 2;
/// Slot: memory for the rings and the buffers.
const RINGS: u64 = 3;
/// Slot: the authority to say what this device may reach.
const WINDOW: u64 = 4;
/// Slot: this device's interrupt.
const HANDLER: u64 = 5;
/// Slot: the notification the handler signals.
const SIGNAL: u64 = 6;
/// Slot: the ring frames are handed to `bin/ipd` through.
const RING: u64 = 7;
/// Slot: the ring `bin/ipd` hands frames back through.
const BACK: u64 = 8;
/// Slot: the doorbell that wakes `bin/ipd`.
///
/// **RFC 0010 question 1.** The service used to poll this ring — about
/// thirty-seven looks per frame — because it could not wait on its endpoint and
/// the ring at once. It binds this notification now, so a frame handed across
/// wakes it directly. Write only: a driver rings, it does not listen.
const INBOX: u64 = 9;

/// Slots the **second** port arrives in, when the machine has one.
///
/// RFC 0074 step 4: a bond needs two members driven, and the kernel delegates
/// the second at slots 10 upward so that "which slot is this?" has an answer
/// that does not depend on how many ports were found. A machine with one NIC
/// leaves them empty and the attach below simply fails, which is how this
/// program discovers there is no second port -- asked of the capability space
/// rather than told in a word somewhere.
///
/// There is no second signal: both ports' vectors raise the notification at
/// [`SIGNAL`] with different badges, so this program parks once and looks at
/// both devices when it wakes.
const COMMON_1: u64 = 10;
const NOTIFY_1: u64 = 11;
const DEVICE_1: u64 = 12;
const RINGS_1: u64 = 13;
const WINDOW_1: u64 = 14;
const HANDLER_1: u64 = 15;

/// Slots the **X722** arrives in, when the machine has one.
///
/// RFC 0075 step 2. A machine with no such NIC leaves them empty and the attach
/// below fails, which is how this program discovers there is none -- asked of
/// the capability space rather than told in a word somewhere, the same way the
/// second virtio port is found.
///
/// Its register pages start at [`X722_PAGES`] and run for one slot per entry in
/// `i40e::REGISTER_PAGES`. **Thirty-four of them, not one**, because a virtio
/// device's registers are a page and this device's are four megabytes: the
/// whole BAR cannot be a capability and should not be, so the crate names the
/// pages that hold a register it uses and the kernel grants exactly those. See
/// `i40e::REGISTER_PAGES`.
const X722_WINDOW: u64 = 16;
/// Slot: the page holding its admin rings and the buffers behind them.
const X722_MEMORY: u64 = 17;
/// Slot: the first of its register pages.
const X722_PAGES: u64 = 20;
/// Slot: the private-memory pages the HMC fetches queue contexts from.
///
/// **After the register pages, and computed rather than written down.** They
/// were 54, 55 and 56 -- inside the range the pages occupy once the interrupt
/// registers joined the list, so the kernel's install refused and the service
/// got a device it could not give memory to. A number chosen by hand beside a
/// range that grows is a number that will one day be inside it.
const X722_HMC: u64 = X722_PAGES + bhaskix_i40e::REGISTER_PAGES.len() as u64;
/// Slot: the receive rings and the buffers behind them.
const X722_RINGS: u64 = X722_HMC + 1;
/// Slot: the transmit ring and the one packet buffer it posts from.
const X722_TX: u64 = X722_HMC + 2;

/// Where the X722's registers are mapped: page `P` of its BAR at `X722_AT + P`.
///
/// Sparse — only the pages granted are mapped — and at their own offsets, so
/// every register offset in `bhaskix-i40e` works against this base unchanged.
/// A register in a page nobody granted faults instead of being reachable, which
/// is the whole point of naming pages.
const X722_AT: u64 = 0x3000_0000;
/// And where its admin page goes, clear of the register window's four megabytes.
const X722_MEMORY_AT: u64 = 0x3400_0000;
/// The private memory the HMC reads: a page-descriptor page and the pages it
/// names.
const X722_HMC_AT: u64 = 0x3410_0000;
/// The receive rings, and the packet buffers behind them.
const X722_RINGS_AT: u64 = 0x3420_0000;
/// The transmit ring and its packet buffer.
const X722_TX_AT: u64 = 0x3430_0000;

/// How many receive queues this driver takes on the X722.
///
/// **One, where the kernel took four.** Four answered a question the kernel was
/// asking -- *which* queue a frame is steered to -- and that question has an
/// answer now. One queue carries traffic; a bond over the card's four ports is
/// RFC 0074's work and needs four *ports*, not four queues on one.
const X722_QUEUES: u32 = 1;
/// Descriptors in each receive ring: a whole multiple of 32 outside PXE mode.
const X722_DESCRIPTORS: u16 = 32;
/// Descriptors handed to the device at a time, a multiple of eight.
const X722_POSTED: u32 = 8;
/// Bytes in each receive packet buffer, in 128-byte units and at least 1 KB.
const X722_BUFFER: u16 = 2048;

/// Where this program maps what it holds.
const COMMON_AT: u64 = 0x2000_0000;
const NOTIFY_AT: u64 = 0x2001_0000;
const DEVICE_AT: u64 = 0x2002_0000;
const RINGS_AT: u64 = 0x2010_0000;
/// And where the second port's windows go, a megabyte clear of the first's so
/// that a mistaken base reads as an unmapped address rather than as the other
/// port's registers.
const COMMON_1_AT: u64 = 0x2100_0000;
const NOTIFY_1_AT: u64 = 0x2101_0000;
const DEVICE_1_AT: u64 = 0x2102_0000;
const RINGS_1_AT: u64 = 0x2110_0000;
/// Where the ring to `bin/ipd` is mapped. Not the device's rings: those are
/// memory a *device* reads, this is memory another *domain* reads, and the two
/// are deliberately different objects with different owners.
const RING_AT: u64 = 0x2020_0000;
/// Where the return ring from `bin/ipd` is mapped.
const BACK_AT: u64 = 0x2030_0000;

/// The X722's registers, as this program reaches them.
///
/// **The one `unsafe` a driver genuinely needs**, in the place RFC 0075 says it
/// belongs: `bhaskix-i40e` forbids `unsafe` entirely and asks its holder for
/// reads and writes, and this is that holder. The kernel had the identical
/// three functions while it drove the device itself.
struct X722Registers;

impl bhaskix_i40e::Registers for X722Registers {
    fn read(&self, offset: u64) -> u32 {
        // SAFETY: the register pages this program attached at their own offsets
        // from `X722_AT`. An offset in a page nobody granted is not mapped and
        // faults, which is the containment working rather than a hazard.
        unsafe { read32(X722_AT + offset) }
    }

    fn write(&mut self, offset: u64, value: u32) {
        // SAFETY: as `read`.
        unsafe { write32(X722_AT + offset, value) };
    }

    fn read64(&self, offset: u64) -> u64 {
        // SAFETY: as `read`; every offset read this way is a documented 64-bit
        // register pair, 8-byte aligned by its own stride.
        unsafe { read64(X722_AT + offset) }
    }
}

/// Memory this program shares with the X722.
///
/// **Not a slice, and RFC 0075 records the boot that settled it**: a `&mut [u8]`
/// promises the compiler nothing else writes those bytes, and a device writing
/// them is precisely something else. Every access here is volatile.
struct X722Memory {
    /// Where this program mapped it.
    at: u64,
    /// How long it is, so an access past the end is refused rather than made.
    bytes: usize,
}

impl bhaskix_i40e::Dma for X722Memory {
    fn read(&self, at: usize, into: &mut [u8]) {
        for (index, slot) in into.iter_mut().enumerate() {
            *slot = if at + index < self.bytes {
                // SAFETY: a region this program mapped writable, bounded above.
                unsafe { read8(self.at + (at + index) as u64) }
            } else {
                0
            };
        }
    }

    fn write(&mut self, at: usize, from: &[u8]) {
        for (index, byte) in from.iter().enumerate() {
            if at + index < self.bytes {
                // SAFETY: as `read`.
                unsafe { write8(self.at + (at + index) as u64, *byte) };
            }
        }
    }

    fn zero(&mut self, at: usize, bytes: usize) {
        for index in at..at + bytes {
            if index < self.bytes {
                // SAFETY: as `read`.
                unsafe { write8(self.at + index as u64, 0) };
            }
        }
    }
}

/// Bytes in the ring to `bin/ipd`, matching what the kernel granted.
const RING_BYTES: usize = 16 * 4096;

/// Where one port's four windows are, and where its device looks for its rings.
///
/// **This program drove one device and named its windows in constants**, which
/// is what a driver with one device does. A bond has two, and every function
/// that touched a register had the first port's address welded into it -- so
/// this is the parameter those constants became. Nothing else changed about
/// them: `PORT_0` below holds exactly the values that used to be spelled
/// inline.
#[derive(Clone, Copy)]
struct Windows {
    /// The common configuration structure.
    common: u64,
    /// The queue notification area.
    notify: u64,
    /// The device-specific configuration: the MAC, and the link status.
    device: u64,
    /// The rings, as *this program* sees them.
    rings: u64,
    /// The rings, as the *device* sees them -- what the DMA window returned.
    at_device: u64,
    /// The capability slot whose interrupt this port raises, to acknowledge.
    handler: u64,
}

/// Entries per queue. Four, like the block driver's: this program sends one
/// frame and posts a handful of receive buffers, and a ring larger than the
/// work is a ring whose wrap-around is never tested.
const QUEUE_ENTRIES: u16 = 4;

/// **Which virtqueue is which, and how that was decided.**
///
/// The virtio specification fixes these indices. This machine has no copy of
/// the specification, and a queue index taken from memory is exactly the kind
/// of fact that works on one device model and not the next — so rather than
/// assert it, the pair below was **established by experiment**: transmit on one
/// queue, and see whether anything reaches the network and whether an answer
/// comes back on the other.
///
/// **Settled 2026-08-12.** With these values a frame reached the network and an
/// answer came back from QEMU's gateway. With them **swapped**, both gates went
/// red — `nothing was transmitted` and `nothing was received` — so this is a
/// measurement and not a recollection. `TRACKER.md` records the run.
mod queue {
    /// The queue the device writes received frames into.
    pub const RECEIVE: u16 = 0;
    /// The queue this driver puts frames on to be sent.
    pub const TRANSMIT: u16 = 1;
}

/// Offsets into the rings object. Eight pages, and every ring on its own page
/// so that alignment is true by construction rather than by arithmetic.
mod ring {
    /// Receive queue: descriptors, available, used.
    pub const RX_DESCRIPTORS: u64 = 0x0000;
    pub const RX_AVAILABLE: u64 = 0x0800;
    pub const RX_USED: u64 = 0x1000;
    /// Transmit queue: the same three.
    pub const TX_DESCRIPTORS: u64 = 0x1800;
    pub const TX_AVAILABLE: u64 = 0x2000;
    pub const TX_USED: u64 = 0x2800;
    /// Receive buffers, one per descriptor.
    pub const RX_BUFFERS: u64 = 0x3000;
    /// Bytes each receive buffer holds: a full frame, the virtio header in
    /// front of it, and room to spare. Two kilobytes rather than 1514 so the
    /// arithmetic below is shifts rather than multiplication by an odd number.
    pub const RX_BUFFER: u64 = 0x800;
    /// The frame this program sends.
    pub const TX_BUFFER: u64 = 0x5000;
    // A second transmit buffer at 0x5800 was here and is **deliberately gone**.
    //
    // Frames copied into it were correct -- the driver read back the right
    // forty-two bytes beginning with the broadcast address -- and the device
    // never transmitted them. Moving the same bytes to the buffer above, with
    // no other change, put them on the wire. Isolated by bisection: the
    // descriptor index was not the cause, the buffer address was.
    //
    // **Why is now understood, and it was never the address.** This driver did
    // not write `QUEUE_SIZE`, so the device wrapped the rings at its own
    // default of 256 while this side wrapped them at four; past the fourth
    // request the two were reading different slots. Bisection blamed the
    // address because moving the bytes changed which request went wrong, not
    // whether one did. The constant stays removed: one transmit buffer is all
    // this loop can use anyway.
    // One buffer means one transmit outstanding at a time, which this loop
    // already enforces and which the specification requires anyway.
    /// Where this program leaves its findings for the kernel.
    pub const REPORT: u64 = 0x7000;
}

/// Offsets into the common configuration structure, from the specification.
///
/// The same offsets `user/blkd` uses — this is the transport's layout and not
/// the device class's — plus the two feature-*read* registers, which the block
/// driver never needed because it negotiates without asking.
mod common {
    pub const DEVICE_FEATURE_SELECT: u64 = 0x00;
    pub const DEVICE_FEATURE: u64 = 0x04;
    pub const DRIVER_FEATURE_SELECT: u64 = 0x08;
    pub const DRIVER_FEATURE: u64 = 0x0c;
    pub const CONFIG_MSIX_VECTOR: u64 = 0x10;
    pub const NUM_QUEUES: u64 = 0x12;
    pub const DEVICE_STATUS: u64 = 0x14;
    pub const QUEUE_SELECT: u64 = 0x16;
    /// How many entries the queue has — **and this was missing entirely**.
    ///
    /// The register sits in the two bytes between `QUEUE_SELECT` and
    /// `QUEUE_MSIX_VECTOR`, which is how the gap in this list was noticed. A
    /// driver that never writes it leaves the device on its own default, and
    /// QEMU's default is 256 while this driver builds rings of four.
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

/// The feature bits this driver asks for, and nothing else.
///
/// Bit numbers from `/usr/include/linux/virtio_net.h` and the transport's own
/// range: `VIRTIO_NET_F_MAC` is 5, `VERSION_1` is 32 and `ACCESS_PLATFORM` is
/// 33.
///
/// **Nothing is negotiated that is not needed.** Checksum offload and merged
/// receive buffers each change either the header in front of a frame or the
/// rules for filling one, and a first driver that accepts them inherits their
/// failure modes on top of its own. `MAC` is asked for because a device that
/// will not tell this program its address leaves it unable to say what it is.
mod feature {
    /// Low word: the device-class bits.
    pub const MAC: u32 = 1 << 5;
    /// Low word: the device says whether its link is up.
    ///
    /// Bit 16, and the config field it unlocks is a `u16` six bytes into the
    /// device configuration -- after the MAC and before everything else. Both
    /// facts are from `/usr/include/linux/virtio_net.h` on the machine this was
    /// written on (`VIRTIO_NET_F_STATUS 16`, `VIRTIO_NET_S_LINK_UP 1`, and
    /// `struct virtio_net_config`), not from memory.
    ///
    /// **Negotiated only when offered.** A device told it agreed to a feature
    /// it never offered is within its rights to clear `FEATURES_OK` and refuse
    /// the whole handshake -- which would cost a working network to learn a
    /// link state.
    pub const STATUS: u32 = 1 << 16;
    /// High word: bits 32 and 33 of the transport.
    pub const VERSION_1_AND_ACCESS_PLATFORM: u32 = 0b11;
}

/// The virtio header that precedes every frame, in both directions.
///
/// **Twelve, and it was ten until the wire said otherwise.**
///
/// `/usr/include/linux/virtio_net.h:126-135` defines `struct virtio_net_hdr` as
/// two bytes and four 16-bit fields — ten — and says the twelve-byte
/// `virtio_net_hdr_mrg_rxbuf` is "the version to use when the MRG_RXBUF feature
/// has been negotiated", which this driver does not negotiate. Reading that as
/// ten is the obvious inference and it is wrong: a **modern** device uses the
/// twelve-byte layout regardless, and the UAPI comment describes the legacy
/// rule.
///
/// Settled by measurement rather than by argument. With ten here, QEMU's own
/// `filter-dump` showed the frame leaving as forty bytes beginning two bytes
/// into the Ethernet header:
///
/// ```text
/// dst=ff:ff:ff:ff:52:54  src=00:12:34:56:08:06  ethertype=0x0001
/// ```
///
/// — the broadcast address short by two, the source address holding the last
/// four of it, and the EtherType holding what should have been the ARP
/// hardware type. The device had consumed twelve bytes and sent the rest. See
/// `TRACKER.md` for the run.
const VIRTIO_NET_HEADER: u64 = 12;

/// The marker the kernel looks for before believing the report.
const MARKER: u64 = 0x3154_5052_4454_454e;

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
/// `at` must be inside a window this program mapped.
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
/// Two stores and not one, for the reason `user/blkd` records: the
/// specification defines these as a low and a high half and a device model is
/// entitled to notice. QEMU does — a single eight-byte store left the block
/// driver with a queue the device never looked at, no fault and no completion.
///
/// # Safety
///
/// As [`write8`], and `at` must be four-byte aligned.
unsafe fn write64(at: u64, value: u64) {
    // SAFETY: delegated to the caller. The low half first.
    unsafe {
        core::ptr::write_volatile(at as *mut u32, value as u32);
        core::ptr::write_volatile((at + 4) as *mut u32, (value >> 32) as u32);
    }
}

/// Reads eight bytes as one access.
///
/// **The counterpart of [`write64`] and the opposite decision**, for a
/// different device and a documented reason: the X722's statistics say *"the
/// low and high registers are part of a 64-bit register and are read using
/// 64-bit read accesses only"*, and two 32-bit reads would also tear across a
/// counter incrementing between them. `write64` splits its store because
/// virtio's specification defines those registers as two halves; this joins its
/// load because this one's specification says the opposite. Neither is a
/// preference.
///
/// # Safety
///
/// As [`read8`], and `at` must be eight-byte aligned.
unsafe fn read64(at: u64) -> u64 {
    // SAFETY: delegated to the caller.
    unsafe { core::ptr::read_volatile(at as *const u64) }
}

/// Rings this driver's doorbell for `index`.
///
/// The value written is the queue index, which is what tells a device with two
/// queues which one has work — the block driver writes zero because zero is the
/// only queue it has, and copying that here would notify the receive queue
/// every time a frame was sent.
///
/// # Safety
///
/// The notify window must be mapped and `index` must be an enabled queue.
unsafe fn kick(w: Windows, index: u16) {
    // SAFETY: the common window is mapped; selecting a queue and reading its
    // notify offset changes nothing.
    unsafe {
        write16(w.common + common::QUEUE_SELECT, index);
        let offset = u64::from(read16(w.common + common::QUEUE_NOTIFY_OFF));
        // Times four: the notification multiplier this transport reports, the
        // same constant `user/blkd` uses and for the same device model.
        write16(w.notify + offset * 4, index);
    }
}

/// The largest frame the **device** has said it wrote, virtio header included.
///
/// `received` above is the *first* frame's length and is written once, which
/// read like a running figure and is not one. A high-water mark is what says
/// whether a large frame ever arrived at all.
static WIDEST: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Bulk copies of a packet's bytes this program has made.
///
/// **Counted rather than reasoned about**, which is RFC 0018's own wording. The
/// RFC claims the two-domain split costs "two copies and two domain crossings
/// per packet that a monolithic stack does not pay", and a claim of that shape
/// is a hypothesis until something counts. One increment per packet-sized copy:
/// the four-byte length prefix in front of each frame is not a packet and is
/// not counted.
///
/// Both sites here are the *ring*, which is exactly the cost the boundary adds:
/// a frame received into this program's buffer must be copied to reach `ipd`,
/// and a frame `ipd` built must be copied to reach the device.
static COPIES: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Adds one to [`COPIES`].
fn copied() {
    COPIES.store(
        COPIES.load(core::sync::atomic::Ordering::Relaxed) + 1,
        core::sync::atomic::Ordering::Relaxed,
    );
}

/// Receive buffers the device is holding, the last time one completed.
static OUTSTANDING: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Whether the queues took MSI-X vectors.
static VECTORED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Configures one queue and returns it.
///
/// # Safety
///
/// The common window must be mapped, and the three offsets must name distinct
/// page-aligned regions inside the rings this program holds.
unsafe fn configure(
    w: Windows,
    index: u16,
    descriptors: u64,
    available: u64,
    used: u64,
) -> Virtqueue<Volatile> {
    // SAFETY: the caller guarantees the window and the offsets.
    let vectored = unsafe {
        write16(w.common + common::QUEUE_SELECT, index);
        // **The size, which this driver never told the device.** Both sides
        // index the same three rings, and they were indexing them differently:
        // the driver wrapping at four and the device at its own default of
        // 256. Entries zero to three agree, which is why anything worked at
        // all — and why what failed failed so strangely. Past the fourth
        // request the device read available-ring slots the driver had never
        // written, and wrote used-ring entries the driver never looked at.
        //
        // Three recorded mysteries are this one register. A frame sent on
        // descriptor two went out with descriptor zero's length. A transmit
        // buffer at 0x5800 was filled correctly and never transmitted. And no
        // received frame larger than sixty-four bytes was ever delivered while
        // three of four buffers sat free. None of them were about descriptors
        // or addresses or buffers; the two sides simply disagreed about how
        // long the rings were.
        write16(w.common + common::QUEUE_SIZE, QUEUE_ENTRIES);
        // Which MSI-X entry this queue uses is this driver's to say, in a
        // register it holds. What that entry *contains* is the kernel's, and
        // this program has no way to write it. Both queues share entry zero,
        // which is one interrupt for two directions -- correct, because the
        // driver looks at both used rings when it wakes.
        write16(w.common + common::QUEUE_MSIX_VECTOR, 0);
        let taken = read16(w.common + common::QUEUE_MSIX_VECTOR) == 0;
        write64(w.common + common::QUEUE_DESC, w.at_device + descriptors);
        write64(w.common + common::QUEUE_DRIVER, w.at_device + available);
        write64(w.common + common::QUEUE_DEVICE, w.at_device + used);
        write16(w.common + common::QUEUE_ENABLE, 1);
        taken
    };
    if !vectored {
        VECTORED.store(false, core::sync::atomic::Ordering::Relaxed);
    }

    // SAFETY: the three rings are inside the eight pages this program holds and
    // mapped writable, at offsets that do not overlap, and the size is a power
    // of two.
    unsafe {
        Virtqueue::<Volatile>::new(
            virtqueue::Ring {
                at: (w.rings + descriptors) as usize,
                device: w.at_device + descriptors,
            },
            virtqueue::Ring {
                at: (w.rings + available) as usize,
                device: w.at_device + available,
            },
            virtqueue::Ring {
                at: (w.rings + used) as usize,
                device: w.at_device + used,
            },
            QUEUE_ENTRIES,
        )
    }
}

/// Brings the device up and returns its two queues, and whether it offered a
/// link state.
///
/// `None` if the device refused the feature set, which is the one failure worth
/// distinguishing: going on from there configures queues nobody will service.
fn bring_up(w: Windows) -> Option<(Virtqueue<Volatile>, Virtqueue<Volatile>, bool)> {
    VECTORED.store(true, core::sync::atomic::Ordering::Relaxed);

    // SAFETY: `w.common` is the common configuration window this program
    // mapped writable, and every offset below is inside it. The values and
    // their order are the specification's.
    let mac_offered = unsafe {
        write8(w.common + common::DEVICE_STATUS, 0);
        write8(w.common + common::DEVICE_STATUS, device_status::ACKNOWLEDGE);
        write8(
            w.common + common::DEVICE_STATUS,
            device_status::ACKNOWLEDGE | device_status::DRIVER,
        );

        // Asked rather than assumed, unlike the block driver which writes what
        // it wants without looking. A device that is not offering `MAC` and is
        // told it was negotiated is within its rights to clear `FEATURES_OK`,
        // and the whole handshake then fails for a field this driver only
        // wanted in order to print it.
        write32(w.common + common::DEVICE_FEATURE_SELECT, 0);
        let low = read32(w.common + common::DEVICE_FEATURE);
        let mac = low & feature::MAC;
        // Asked for the same way and for a better reason than the MAC: a bond
        // that cannot tell a live member from a dead one is not a bond. See
        // `feature::STATUS`.
        let status = low & feature::STATUS;

        write32(w.common + common::DRIVER_FEATURE_SELECT, 1);
        write32(
            w.common + common::DRIVER_FEATURE,
            feature::VERSION_1_AND_ACCESS_PLATFORM,
        );
        write32(w.common + common::DRIVER_FEATURE_SELECT, 0);
        write32(w.common + common::DRIVER_FEATURE, mac | status);

        write8(
            w.common + common::DEVICE_STATUS,
            device_status::ACKNOWLEDGE | device_status::DRIVER | device_status::FEATURES_OK,
        );
        // Read back: a device that will not accept the feature set clears this
        // bit, and a driver that did not look would build queues for a device
        // that had already given up on it.
        if read8(w.common + common::DEVICE_STATUS) & device_status::FEATURES_OK == 0 {
            return None;
        }

        // Config-change interrupts go to the same entry as the queues. A
        // network device signals link state this way, and an entry left
        // unassigned means the device has nowhere to send one.
        write16(w.common + common::CONFIG_MSIX_VECTOR, 0);

        // Two queues at least, or there is no transmit queue to put a frame on.
        // Checked rather than assumed because it is one read, and because a
        // device offering one queue would otherwise be configured as though it
        // had two and fail somewhere less obvious.
        if read16(w.common + common::NUM_QUEUES) < 2 {
            return None;
        }
        (mac != 0, status != 0)
    };
    let (mac_offered, status_offered) = mac_offered;
    let _ = mac_offered;

    // SAFETY: the window is mapped and the offsets are distinct pages of the
    // rings object this program holds.
    let receive = unsafe {
        configure(
            w,
            queue::RECEIVE,
            ring::RX_DESCRIPTORS,
            ring::RX_AVAILABLE,
            ring::RX_USED,
        )
    };
    // SAFETY: as above, with the transmit queue's own three pages.
    let transmit = unsafe {
        configure(
            w,
            queue::TRANSMIT,
            ring::TX_DESCRIPTORS,
            ring::TX_AVAILABLE,
            ring::TX_USED,
        )
    };

    Some((receive, transmit, status_offered))
}

/// Gives the device every receive buffer this program owns.
///
/// **Before `DRIVER_OK`, and that ordering is the whole of this function's
/// reason to exist.** A network device delivers unbidden: the answer to the
/// frame sent below can arrive before the next instruction runs, and a receive
/// queue with nothing posted drops it without saying so.
fn post_receive_buffers(receive: &mut Virtqueue<Volatile>, w: Windows) {
    for index in 0..QUEUE_ENTRIES {
        let offset = ring::RX_BUFFERS + u64::from(index) * ring::RX_BUFFER;
        receive.describe(
            index,
            w.at_device + offset,
            ring::RX_BUFFER as u32,
            // The device writes this one. Without the flag it would read a
            // buffer this program never filled and send it.
            virtqueue::WRITE,
            0,
        );
        receive.publish(index);
    }
}

/// Fills the transmit buffer with a frame, and returns how many bytes.
///
/// A fixed template: a broadcast ARP request for the address QEMU's built-in
/// network puts its gateway at. **This program does not know what ARP is** —
/// the bytes are a test vector chosen because the network answers them, which
/// is what makes a receive path testable without a protocol stack in the domain
/// that holds DMA.
///
/// # Safety
///
/// The port's rings must be mapped writable at `w.rings`.
unsafe fn fill_transmit(w: Windows, mac: [u8; 6]) -> u64 {
    const FRAME: u64 = 42;
    let at = w.rings + ring::TX_BUFFER;

    // SAFETY: the caller guarantees the mapping; `VIRTIO_NET_HEADER + FRAME` is
    // far inside one page.
    unsafe {
        for offset in 0..VIRTIO_NET_HEADER + FRAME {
            core::ptr::write_volatile((at + offset) as *mut u8, 0);
        }
        let frame = at + VIRTIO_NET_HEADER;
        let put = |offset: u64, byte: u8| {
            core::ptr::write_volatile((frame + offset) as *mut u8, byte);
        };
        // Destination: everybody.
        for octet in 0..6 {
            put(octet, 0xff);
        }
        // Source: this device.
        for (index, octet) in mac.iter().enumerate() {
            put(6 + index as u64, *octet);
        }
        // EtherType 0x0806, then the fixed twenty-eight bytes: Ethernet over
        // IPv4, a request, this station asking for 10.0.2.2.
        let tail: [u8; 30] = [
            0x08, 0x06, // ethertype
            0x00, 0x01, // hardware type: Ethernet
            0x08, 0x00, // protocol type: IPv4
            0x06, 0x04, // address lengths
            0x00, 0x01, // operation: request
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], // sender hardware
            10, 0, 2, 15, // sender protocol
            0, 0, 0, 0, 0, 0, // target hardware: unknown, which is the question
            10, 0, 2, 2, // target protocol
        ];
        for (index, byte) in tail.iter().enumerate() {
            put(12 + index as u64, *byte);
        }
    }
    VIRTIO_NET_HEADER + FRAME
}

/// Whether the device says its link is up.
///
/// RFC 0074 step 4: a bond selects a member that can carry traffic, and the
/// only thing that knows whether a member can is the device. The `u16` six
/// bytes into the device configuration, bit 0 -- `virtio_net_config.status` and
/// `VIRTIO_NET_S_LINK_UP` in `/usr/include/linux/virtio_net.h`, read off the
/// machine rather than remembered.
///
/// **`true` when the feature was not negotiated**, which is the honest answer
/// rather than the convenient one: a device that never offered a link state has
/// not said its link is down, and a bond that treated silence as failure would
/// refuse to use a working port. `status_offered` is what the caller passes.
fn link_up(w: Windows, status_offered: bool) -> bool {
    if !status_offered {
        return true;
    }
    // SAFETY: the device configuration window this program mapped read-only,
    // two bytes at an offset inside it.
    unsafe { read16(w.device + 6) & 1 != 0 }
}

/// Waits for something to complete on `queue`, returning its used-ring length.
///
/// Bounded, and honest about being a spin where there is no vector. A wait with
/// no bound would hang the machine on a device that never answers, which is a
/// worse failure than reporting that nothing came.
fn await_completion(w: Windows, queue: &mut Virtqueue<Volatile>) -> Option<(u16, u32)> {
    // Looked at before waited on, and that order is deliberate. `WAIT` has no
    // timeout — RFC 0008 leaves that open and `kernel/src/ipc.rs` says so — so
    // a driver that waits first blocks for ever on any device that completes
    // without raising, and a self-test that blocks reports nothing at all
    // rather than reporting a failure. The block driver waits first and gets
    // away with it because a disk answers every request; a network device is
    // under no such obligation, and one interrupt here serves both queues, so
    // a wake means "look at both" rather than "this one is ready".
    for _ in 0..8_000_000u64 {
        if let Some(done) = queue.completed_with_length() {
            return Some(done);
        }
        core::hint::spin_loop();
    }

    // Nothing yet. Only now is blocking worth the risk, and only where there is
    // a vector to be woken by.
    if VECTORED.load(core::sync::atomic::Ordering::Relaxed) {
        let (status, _) = call(syscall::INVOKE, SIGNAL, method::WAIT, [0; 4]);
        let _ = call(syscall::INVOKE, w.handler, method::ACK, [0; 4]);
        if status == self::status::OK {
            return queue.completed_with_length();
        }
    }
    None
}

/// Copies `source` into the region at the offsets `runs` names.
///
/// # Safety
///
/// `runs` must be offsets `abi::ring` computed for the region mapped at
/// [`RING_AT`], and `source` readable for their combined length.
unsafe fn write_runs_from(source: *const u8, runs: (chan::Run, chan::Run)) {
    let (first, second) = runs;
    // SAFETY: the caller's obligation. The two runs are the halves a wrap
    // divides one transfer into and do not overlap.
    unsafe {
        core::ptr::copy_nonoverlapping(
            source,
            (RING_AT + first.offset as u64) as *mut u8,
            first.length,
        );
        if !second.is_empty() {
            core::ptr::copy_nonoverlapping(
                source.add(first.length),
                (RING_AT + second.offset as u64) as *mut u8,
                second.length,
            );
        }
    }
}

/// Hands one frame to `bin/ipd`: a four-byte length, then the bytes.
///
/// Returns whether it fitted. A frame that does not fit is **dropped and
/// counted**, which is what a datagram path is permitted to do — blocking the
/// driver would stop every flow rather than one, and the driver is the only
/// thing that can keep the device's receive queue refilled.
///
/// # Safety
///
/// The ring must be mapped writable at [`RING_AT`] and the frame readable at
/// `frame_at` for `length` bytes.
unsafe fn hand_to_ipd(frame_at: u64, length: usize) -> bool {
    let Some(layout) = chan::Layout::for_region(RING_BYTES) else {
        return false;
    };
    // SAFETY: the ring's header, in the region this program mapped. Read
    // volatile because the other domain writes the tail without taking a lock.
    let (head, tail) = unsafe {
        (
            core::ptr::read_volatile((RING_AT + chan::HEAD_OFFSET as u64) as *const u64),
            core::ptr::read_volatile((RING_AT + chan::TAIL_OFFSET as u64) as *const u64),
        )
    };

    // **Where the frame goes, from `abi::ring`.** This function used to do the
    // arithmetic itself, twice -- once for the prefix and once for the payload
    // -- and so did the three others like it. Between them they produced a
    // frame truncated to 42 bytes and a tail advanced past bytes nobody had
    // read. The arithmetic is one tested function now; what is left here is the
    // copying, which is the part that genuinely needs a pointer.
    let Some(cursor) = chan::Cursor::new(layout, head, tail) else {
        return false;
    };
    let Some(framed) = chan::frame_to_write(layout, cursor, length) else {
        return false;
    };
    let prefix = (length as u32).to_le_bytes();
    // SAFETY: every offset is one `abi::ring` computed inside the region this
    // program mapped writable, `frame_at` is a receive buffer readable for
    // `length`, and the runs of a transfer do not overlap -- they are the two
    // halves a wrap divides it into.
    unsafe {
        write_runs_from(prefix.as_ptr(), framed.prefix);
        write_runs_from(frame_at as *const u8, framed.payload);
    }
    // Inbound, copy one of two: this program's receive buffer into the ring.
    copied();

    // The bytes, then a fence, then the index that makes them visible. The
    // reader is another domain on another CPU and takes no lock, so this fence
    // is the whole of what orders the two -- the same reason `Virtqueue::publish`
    // has one.
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    // SAFETY: the ring's header, which only this program writes.
    unsafe {
        core::ptr::write_volatile(
            (RING_AT + chan::HEAD_OFFSET as u64) as *mut u64,
            framed.next,
        );
    }
    // **Then wake the service.** Index first, wake second, for the reason the
    // bytes go before the index: a reader woken before the index was published
    // would look, find nothing, and sleep again holding a frame that had
    // already been written.
    //
    // Unchecked. On a machine with no service this slot is empty and the call
    // is refused, which is a state rather than a fault.
    call(syscall::INVOKE, INBOX, method::SIGNAL, [0; 4]);
    true
}

/// Copies out of the return ring at the offsets `runs` names, into `into`.
///
/// # Safety
///
/// `runs` must be offsets `abi::ring` computed for the region mapped at
/// [`BACK_AT`], and `into` writable for their combined length.
unsafe fn read_runs_into(into: *mut u8, runs: (chan::Run, chan::Run)) {
    let (first, second) = runs;
    // SAFETY: the caller's obligation; the runs are a wrap's two halves and do
    // not overlap.
    unsafe {
        core::ptr::copy_nonoverlapping(
            (BACK_AT + first.offset as u64) as *const u8,
            into,
            first.length,
        );
        if !second.is_empty() {
            core::ptr::copy_nonoverlapping(
                (BACK_AT + second.offset as u64) as *const u8,
                into.add(first.length),
                second.length,
            );
        }
    }
}

/// Takes one frame out of the return ring, if `bin/ipd` has put one there.
///
/// Returns its length. The frame is copied straight into the transmit buffer
/// **after** the virtio header, so nothing is copied twice.
///
/// # Safety
///
/// The return ring must be mapped at [`BACK_AT`] and the rings at [`RINGS_AT`].
unsafe fn take_from_ipd_into(buffer: u64, header: u64) -> Option<usize> {
    let layout = chan::Layout::for_region(RING_BYTES)?;
    // SAFETY: the ring's header, in the region this program mapped. Volatile
    // because the producer is another domain and takes no lock.
    let (head, tail) = unsafe {
        (
            core::ptr::read_volatile((BACK_AT + chan::HEAD_OFFSET as u64) as *const u64),
            core::ptr::read_volatile((BACK_AT + chan::TAIL_OFFSET as u64) as *const u64),
        )
    };
    let cursor = chan::Cursor::new(layout, head, tail)?;
    if cursor.readable() < 4 {
        return None;
    }

    let mut prefix = [0u8; chan::PREFIX];
    let runs = chan::length_to_read(layout, cursor)?;
    // SAFETY: the ring is mapped and `prefix` is `PREFIX` writable bytes.
    unsafe { read_runs_into(prefix.as_mut_ptr(), runs) };
    let length = u32::from_le_bytes(prefix) as usize;
    // A length the *other side* wrote. Bounded before it is used, and refused
    // rather than clamped: a frame that does not fit a buffer is not a shorter
    // frame, it is a producer this program has stopped believing.
    if length == 0 || length > (ring::RX_BUFFER as usize - header as usize) {
        return None;
    }
    // **Where the frame is, from `abi::ring`.** The refusal below used to be
    // written here by hand: a length published without its bytes is a producer
    // mid-write, not an error, and a consumer that read anyway would take half a
    // frame and whatever was behind it. It is `frame_to_read`'s rule now, and
    // it is tested.
    let framed = chan::frame_to_read(layout, cursor, length)?;

    // SAFETY: the ring is mapped, and the destination is inside a transmit
    // buffer this program mapped writable, bounded by the check above.
    unsafe {
        // The virtio header this device expects in front of every frame. The
        // X722 wants none, which is why `header` is a parameter rather than a
        // constant: the two devices differ in exactly this and in nothing else
        // about taking a frame from `bin/ipd`.
        for offset in 0..header {
            core::ptr::write_volatile((buffer + offset) as *mut u8, 0);
        }
        read_runs_into((buffer + header) as *mut u8, framed.payload);
        // Outbound, copy two of two: the ring into the transmit buffer.
        copied();
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        core::ptr::write_volatile(
            (BACK_AT + chan::TAIL_OFFSET as u64) as *mut u64,
            framed.next,
        );
    }
    Some(length)
}

/// Takes a frame `bin/ipd` built into a virtio port's transmit buffer.
///
/// # Safety
///
/// As [`take_from_ipd_into`], for the buffer inside `w`'s rings.
unsafe fn take_from_ipd(w: Windows) -> Option<usize> {
    // SAFETY: the caller's, and the buffer is inside the rings object this
    // program mapped writable.
    unsafe { take_from_ipd_into(w.rings + ring::TX_BUFFER, VIRTIO_NET_HEADER) }
}

/// Looks once, without spinning and without blocking.
///
/// The steady-state loop uses this rather than [`await_completion`], and the
/// difference is not a micro-optimisation: this program is **pinned**, so a
/// long spin here is a CPU nothing else on the machine can have. Eight probes
/// through a spin of eight million each was enough to trip the bring-up
/// watchdog at forty-five seconds -- under emulation, a spin is not cheap.
///
/// The yield in the caller is what makes this a loop rather than a monopoly.
fn poll_completion(queue: &mut Virtqueue<Volatile>) -> Option<(u16, u32)> {
    queue.completed_with_length()
}

/// One driven NIC, and everything this program knows about it.
///
/// **A bond needs two of these** — RFC 0074 step 4 — and until it did, every
/// field here was a local in `netd_main` or an address welded into a function.
/// That is the whole of what changed: nothing about how a port is driven, only
/// that there can be more than one.
struct Port {
    /// Its windows, and where its device looks for its rings.
    at: Windows,
    receive: Virtqueue<Volatile>,
    transmit: Virtqueue<Volatile>,
    /// How many bytes the device puts in front of a received frame.
    header: u64,
    /// A descriptor handed to the device is the device's until it comes back.
    outstanding: bool,
    /// Whether the device offered a link state at all. See [`link_up`].
    reports_link: bool,
    /// What its link was, the last time it was looked at.
    up: bool,
}

/// The entry point.
#[unsafe(no_mangle)]
extern "C" fn netd_main() -> ! {
    // **The rings first, and alone, because they are where this program says
    // anything at all.** The report lives in their last page: a service that
    // could not attach them has no way to be heard, and one that exits before
    // attaching them is a service the kernel reports as having left no report.
    //
    // That is exactly what the SR550 showed on 2026-09-07 -- `bin/netd` started
    // and vanished, because the three attaches above these were the *virtio*
    // device's and that machine has no virtio device at all. A NIC is not
    // required to run; being able to report is.
    if !attach(RINGS, RINGS_AT, 1) {
        exit()
    }

    // **A virtio device, if there is one.** RFC 0075 step 3: this program is a
    // driver with ports rather than a driver with a device, and on a machine
    // whose only NIC is an X722 there is nothing here to attach.
    let has_virtio = attach(COMMON, COMMON_AT, 1)
        && attach(NOTIFY, NOTIFY_AT, 1)
        && attach(DEVICE, DEVICE_AT, 0);
    if !has_virtio {
        // Nothing of the virtio path can run. Take whatever else was delegated
        // -- which is the whole reason this program is started on a machine
        // with no virtio device -- and then carry its frames.
        let (x722, queues) = take_x722();
        let (state, firmware) = x722.words();
        no_virtio_report(state, firmware, x722.address());
        match queues {
            Some(queues) => carry_x722(queues, x722),
            None => loop {
                call(syscall::YIELD, 0, 0, [0; 4]);
            },
        }
    }

    // Where the device will look for the rings. Not a physical address: this
    // program cannot name one, and without a window there is no such number and
    // nothing to be driven -- which is the refusal working, because a domain
    // that could aim a device with physical addresses could aim it at the
    // kernel.
    let (mapped, rings_at_device) = call(syscall::INVOKE, WINDOW, method::MAP, [RINGS, 0, 0, 0]);
    if mapped != status::OK {
        report(0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        exit()
    }

    let first = Windows {
        common: COMMON_AT,
        notify: NOTIFY_AT,
        device: DEVICE_AT,
        rings: RINGS_AT,
        at_device: rings_at_device,
        handler: HANDLER,
    };

    let Some((mut receive, mut transmit, reports_link)) = bring_up(first) else {
        report(0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        exit()
    };

    // This device's address, from its own configuration space.
    // SAFETY: `DEVICE_AT` is the device configuration window this program
    // mapped read-only, and a network device's MAC is its first six bytes.
    let mac = unsafe {
        let mut octets = [0u8; 6];
        for (index, octet) in octets.iter_mut().enumerate() {
            *octet = read8(DEVICE_AT + index as u64);
        }
        octets
    };

    // Receive buffers first, then `DRIVER_OK`. See `post_receive_buffers`.
    post_receive_buffers(&mut receive, first);

    // SAFETY: the common window is mapped and the queues are enabled.
    unsafe {
        write8(
            COMMON_AT + common::DEVICE_STATUS,
            device_status::ACKNOWLEDGE
                | device_status::DRIVER
                | device_status::FEATURES_OK
                | device_status::DRIVER_OK,
        );
        kick(first, queue::RECEIVE);
    }

    // SAFETY: the rings are mapped writable.
    let length = unsafe { fill_transmit(first, mac) };
    transmit.describe(0, rings_at_device + ring::TX_BUFFER, length as u32, 0, 0);
    transmit.publish(0);
    // SAFETY: the notify window is mapped and the queue is enabled.
    unsafe { kick(first, queue::TRANSMIT) };

    let sent = if await_completion(first, &mut transmit).is_some() {
        length
    } else {
        0
    };

    // What came back, if anything.
    let (received, source, header, first_index) = match await_completion(first, &mut receive) {
        Some((index, written)) => {
            let buffer = RINGS_AT + ring::RX_BUFFERS + u64::from(index) * ring::RX_BUFFER;
            // The header size, measured rather than assumed. The frame is an
            // answer to this station's own broadcast, so its destination is
            // this device's MAC -- and the offset those six bytes appear at is
            // the size of whatever the device put in front of them.
            let mut header = 0u64;
            for candidate in [VIRTIO_NET_HEADER, 10] {
                // SAFETY: inside a receive buffer this program mapped writable
                // and the device has finished with.
                let matches = unsafe {
                    (0..6).all(|octet| read8(buffer + candidate + octet) == mac[octet as usize])
                };
                if matches {
                    header = candidate;
                    break;
                }
            }

            // SAFETY: as above -- the source address follows the destination.
            let source = unsafe {
                let mut value = 0u64;
                for octet in 0..6 {
                    value = (value << 8) | u64::from(read8(buffer + header + 6 + octet));
                }
                value
            };
            // The device's own count of what it wrote, less the header it put
            // in front: the frame's length, which nothing else here knows.
            (
                u64::from(written).saturating_sub(header),
                source,
                header,
                index,
            )
        }
        None => (0, 0, 0, 0),
    };
    // The measurement's premise is that the first received frame answers
    // this station's own broadcast, so its destination is this MAC. A
    // segment speaking IPv6 breaks that premise twice over: a router
    // advertisement is multicast and can arrive first (the probe matches
    // nothing), and on a wire where v4 is dead the answer never comes at
    // all (the await times out and the match never runs). Either way zero
    // was never an answer — it was the premise failing silently, and every
    // frame crossed to ipd with twelve bytes of virtio header still in
    // front, parsing as an all-zero Ethernet header. The documented modern
    // layout is the fallback; the probe stays for the ten-byte legacy
    // device it was written to catch.
    let header = if header == 0 {
        VIRTIO_NET_HEADER
    } else {
        header
    };

    let mut own = 0u64;
    for octet in mac {
        own = (own << 8) | u64::from(octet);
    }
    report(
        own,
        sent,
        received,
        source,
        header,
        u64::from(receive.seen()),
        0,
        0,
        0,
        0,
    );

    // **The bond's members.** RFC 0074 step 4.
    //
    // The first port is the one everything above measured, and it is member
    // zero. The second is delegated at slots 10 upward when the machine has a
    // NIC to spare; a machine with one leaves them empty, the attach fails, and
    // this program drives one port exactly as it always did. Asked of the
    // capability space rather than told in a word somewhere: a slot either
    // holds a device or it does not.
    let mut ports: [Option<Port>; 2] = [
        Some(Port {
            at: first,
            receive,
            transmit,
            header,
            outstanding: false,
            reports_link,
            up: link_up(first, reports_link),
        }),
        None,
    ];

    if attach(COMMON_1, COMMON_1_AT, 1)
        && attach(NOTIFY_1, NOTIFY_1_AT, 1)
        && attach(DEVICE_1, DEVICE_1_AT, 0)
        && attach(RINGS_1, RINGS_1_AT, 1)
    {
        let (mapped, at_device) = call(syscall::INVOKE, WINDOW_1, method::MAP, [RINGS_1, 0, 0, 0]);
        let second = Windows {
            common: COMMON_1_AT,
            notify: NOTIFY_1_AT,
            device: DEVICE_1_AT,
            rings: RINGS_1_AT,
            at_device,
            handler: HANDLER_1,
        };
        if mapped == status::OK
            && let Some((mut receive, transmit, reports_link)) = bring_up(second)
        {
            // **This member's own address is read by nobody**, and that is
            // the bond saying what it is: every frame leaves under the first
            // member's address whichever member carries it, so a second address
            // would be a fact with no consumer. See `bond_mac`.
            post_receive_buffers(&mut receive, second);
            // SAFETY: the second common window is mapped and its queues are
            // enabled.
            unsafe {
                write8(
                    COMMON_1_AT + common::DEVICE_STATUS,
                    device_status::ACKNOWLEDGE
                        | device_status::DRIVER
                        | device_status::FEATURES_OK
                        | device_status::DRIVER_OK,
                );
                kick(second, queue::RECEIVE);
            }
            ports[1] = Some(Port {
                at: second,
                receive,
                transmit,
                // The header size is the transport's, not the device's, and the
                // first port measured it against a frame addressed to itself.
                // This port has had no frame yet, so it takes that answer
                // rather than guessing from nothing.
                header,
                outstanding: false,
                reports_link,
                up: link_up(second, reports_link),
            });
        }
    }

    // **Which member carries traffic.** Active-backup, which is RFC 0074's
    // first mode because it needs no protocol and no cooperation from the
    // switch.
    //
    // Sticky: a member that comes back does *not* take the link back, because
    // that is churn and reordering bought for nothing. The selection changes
    // only when the member carrying traffic stops being able to.
    // **The X722, if the kernel delegated one** -- RFC 0075 step 2. Taken once,
    // here, because a device is brought up once and because the answer on every
    // machine that has none is the same answer every time: there is none.
    let (x722, x722_queues) = take_x722();
    // Wired into the loop at the next step; held now so the bring-up above is
    // not doing work nothing keeps.
    let _ = &x722_queues;

    let mut active = 0usize;
    let mut failovers = 0u64;
    // **The bond's address, which is the first member's**, and everything the
    // bond sends carries it whichever member carries the frame. That is what
    // makes this one interface rather than two: `bin/ipd` is told this address
    // once and never has to be told again, so a failover costs no ARP, no DHCP
    // and no reconfiguration above the driver.
    //
    // It is also the thing a failover can quietly break. Linux's bonding calls
    // the alternative `fail_over_mac` and offers it for hardware that cannot
    // send from an address that is not its own; this sends from the bond's, and
    // whether the answer comes back is what the failover gate measures.
    let bond_mac = mac;
    // Frames a member that is not carrying traffic delivered, and which were
    // therefore dropped. Counted rather than ignored: on a bond both members
    // are on the wire and both receive, and a frame taken from the backup would
    // be a duplicate of one the active member already handed across.
    let mut off_member = 0u64;

    // Everything after this is step 3: frames go to `bin/ipd` rather than into
    // a report. Without a ring there is nowhere to put them, and this program
    // idles rather than exiting -- a domain that ended would take the rings the
    // kernel reads its report from with it.
    let mut handed = 0u64;
    let mut sent_for_ipd = 0u64;
    let mut took = 0u64;
    let mut took_length = 0u64;
    let back_mapped = attach(BACK, BACK_AT, 1);
    if !attach(RING, RING_AT, 1) {
        loop {
            call(syscall::YIELD, 0, 0, [0; 4]);
        }
    }

    // The frame the self-test already received goes across first, so the ring
    // carries the same bytes the report above describes and the two can be
    // compared rather than merely both being non-zero.
    if received != 0 {
        let buffer = RINGS_AT + ring_buffer_of(first_index) + header;
        // SAFETY: a receive buffer this program mapped and the device has
        // finished with, and the ring it just mapped writable.
        if unsafe { hand_to_ipd(buffer, received as usize) } {
            handed += 1;
        }
        // Back to the device. **A receive queue that is drained and not
        // refilled works exactly once**, which is the failure a self-test
        // needing one frame could never have found.
        if let Some(port) = ports[0].as_mut() {
            port.receive.describe(
                first_index,
                rings_at_device + ring_buffer_of(first_index),
                ring::RX_BUFFER as u32,
                virtqueue::WRITE,
                0,
            );
            port.receive.publish(first_index);
            // SAFETY: the notify window is mapped and the queue is enabled.
            unsafe { kick(port.at, queue::RECEIVE) };
        }
    }

    // From here on: whatever arrives, handed across and the buffer given back.
    //
    // The probe is sent again a few times, because on this network nothing
    // speaks unless spoken to and a receive loop with no traffic proves
    // nothing. Bounded rather than endless: a driver that filled a segment with
    // its own broadcasts would be a worse citizen than one that says little.
    report(
        own,
        sent,
        received,
        source,
        header,
        u64::from(receive_seen(&ports)),
        handed,
        sent_for_ipd,
        took,
        took_length,
    );
    bond_report(&ports, active, failovers, off_member, x722);
    let mut probes = 0u32;
    let mut idle = 0u32;
    loop {
        // **What each member's link is doing**, asked every pass because it is
        // two reads of a register the device owns and because a bond that
        // noticed a failure late would drop everything sent in between.
        for port in ports.iter_mut().flatten() {
            port.up = link_up(port.at, port.reports_link);
        }
        // The member carrying traffic has stopped being able to: select
        // another, if there is one that can. If there is not, the bond keeps
        // the member it has -- a down member and a bond with no members are the
        // same amount of traffic, and staying put means the link coming back
        // needs no second decision.
        if !ports[active].as_ref().is_some_and(|port| port.up) {
            for (index, port) in ports.iter().enumerate() {
                if index != active && port.as_ref().is_some_and(|port| port.up) {
                    active = index;
                    failovers += 1;
                    // **Announce on the member that has taken over.** A switch
                    // learns which port an address is on from the frames it
                    // sees, and after a failover everything it learned is
                    // wrong: it goes on sending this station's traffic to a
                    // port that has gone away, until something arrives from the
                    // new one. Linux's bonding sends gratuitous ARP here for
                    // this reason; this driver has one frame it knows how to
                    // send, so it sends that.
                    //
                    // It is also what makes "traffic continues" measurable
                    // rather than hoped for: the answer comes back on the new
                    // member and crosses to `bin/ipd`, so the report can say a
                    // frame arrived *after* the failover rather than that
                    // nothing has gone wrong yet.
                    probes = 0;
                    break;
                }
            }
        }

        // **One transmit outstanding at a time.** A descriptor handed to the
        // device is the device's until it appears in the used ring, and this
        // loop was republishing descriptor zero every pass without waiting --
        // rewriting a descriptor the device had not finished with. The probes
        // survived it because every probe is the same bytes; the first frame
        // that differed, `ipd`'s, was published into a queue already being
        // mishandled and never reached the wire.
        for port in ports.iter_mut().flatten() {
            if poll_completion(&mut port.transmit).is_some() {
                port.outstanding = false;
            }
        }

        // Everything that goes out, goes out of the member carrying traffic.
        if let Some(port) = ports[active].as_mut() {
            // One probe per pass, and only when the last one is done.
            if probes < 8 && !port.outstanding {
                // SAFETY: this member's rings are mapped writable.
                let length = unsafe { fill_transmit(port.at, bond_mac) };
                port.transmit
                    .describe(0, port.at.at_device + ring::TX_BUFFER, length as u32, 0, 0);
                port.transmit.publish(0);
                // SAFETY: the notify window is mapped and the queue is enabled.
                unsafe { kick(port.at, queue::TRANSMIT) };
                probes += 1;
                port.outstanding = true;
            }

            // Anything `bin/ipd` has built goes out. One per pass, and the
            // completion collected on a later pass -- this program is pinned,
            // and step 3 established that a spin here trips the bring-up
            // watchdog.
            if back_mapped && !port.outstanding {
                // SAFETY: both rings are mapped and the transmit buffer is
                // inside the rings object this program holds.
                //
                // **Descriptor zero, and it was descriptor two.** Every frame
                // this program sent for `bin/ipd` reached the wire truncated to
                // exactly 42 bytes -- the probe's length, 54, less the virtio
                // header -- however long the frame actually was. The headers
                // were correct because they are the first 42 bytes of a correct
                // frame, so the damage was invisible from this side: the ring
                // said 59 bytes taken and `filter-dump` said 42 on the wire,
                // which is what finally named it. A server cannot answer a
                // datagram whose IP header promises 272 bytes and whose frame
                // carries 28.
                //
                // **Why descriptor two behaved that way is now known**, and it
                // was not descriptor two: this driver never wrote `QUEUE_SIZE`,
                // so the device wrapped the rings at 256 while this side
                // wrapped them at four. Past the fourth request the device was
                // reading available entries nobody had written. Descriptor two
                // would work today. Descriptor zero is kept because it is
                // simpler and `outstanding` already allows one transmit at a
                // time, so there is never a second one to name.
                if let Some(from_ipd) = unsafe { take_from_ipd(port.at) } {
                    idle = 0;
                    // SAFETY: the transmit buffer this program mapped, just
                    // filled.
                    took = unsafe {
                        let mut value = 0u64;
                        for octet in 0..6u64 {
                            value = (value << 8)
                                | u64::from(read8(
                                    port.at.rings + ring::TX_BUFFER + VIRTIO_NET_HEADER + octet,
                                ));
                        }
                        value
                    };
                    took_length = from_ipd as u64;
                    port.transmit.describe(
                        0,
                        port.at.at_device + ring::TX_BUFFER,
                        (VIRTIO_NET_HEADER + from_ipd as u64) as u32,
                        0,
                        0,
                    );
                    port.transmit.publish(0);
                    // SAFETY: the notify window is mapped and the queue is
                    // enabled.
                    unsafe { kick(port.at, queue::TRANSMIT) };
                    sent_for_ipd += 1;
                    port.outstanding = true;
                }
            }
        }

        idle = idle.saturating_add(1);
        // Every member's receive queue, because both are on the wire whether
        // or not either is carrying traffic. A frame from a member that is not
        // the active one is given back to the device and *not* handed across:
        // it is a duplicate of one the active member has already delivered, and
        // a bond that delivered both would be a bond that reordered.
        for index in 0..ports.len() {
            let Some(port) = ports[index].as_mut() else {
                continue;
            };
            let Some((slot, written)) = poll_completion(&mut port.receive) else {
                continue;
            };
            idle = 0;
            if u64::from(written) > WIDEST.load(core::sync::atomic::Ordering::Relaxed) {
                WIDEST.store(u64::from(written), core::sync::atomic::Ordering::Relaxed);
            }
            OUTSTANDING.store(
                u64::from(port.receive.posted().wrapping_sub(port.receive.seen())),
                core::sync::atomic::Ordering::Relaxed,
            );
            let buffer = port.at.rings + ring_buffer_of(slot) + port.header;
            let length = u64::from(written).saturating_sub(port.header) as usize;
            if index == active {
                // SAFETY: as above.
                if length > 0 && unsafe { hand_to_ipd(buffer, length) } {
                    handed += 1;
                }
            } else if length > 0 {
                off_member += 1;
            }
            port.receive.describe(
                slot,
                port.at.at_device + ring_buffer_of(slot),
                ring::RX_BUFFER as u32,
                virtqueue::WRITE,
                0,
            );
            port.receive.publish(slot);
            // SAFETY: the notify window is mapped and the queue is enabled.
            unsafe { kick(port.at, queue::RECEIVE) };
            report(
                own,
                sent,
                received,
                source,
                header,
                u64::from(receive_seen(&ports)),
                handed,
                sent_for_ipd,
                took,
                took_length,
            );
        }
        bond_report(&ports, active, failovers, off_member, x722);
        // **Quiesce rather than spin.** This loop polled for ever, and a pinned
        // program that never stops polling is a processor the rest of the
        // machine cannot have -- which showed up as the shell test timing out
        // with the shell answering every command correctly.
        //
        // A driver has something to sleep on, unlike `bin/ipd`: its own
        // interrupt. After a run of passes with nothing to do it blocks on the
        // notification the kernel binds to the device's vector, and the device
        // wakes it when there is a frame. That is what the interrupt was
        // delegated for, and until now this program only used it as a fallback.
        //
        // **Both members raise the same notification**, with different badges,
        // so one park covers the bond and the wake is followed by a look at
        // every port.
        //
        // **Parking is safe for a link, and that was worth checking rather than
        // assuming.** A device with no link has no frames to signal, so the
        // first version of this stayed awake on a two-port machine to read the
        // link registers -- a pinned domain spinning for the life of every boot
        // that has two NICs, which is the cost this park exists to avoid. It is
        // not necessary: a network device signals a *configuration change* on
        // the same MSI-X entry as its queues (see `CONFIG_MSIX_VECTOR` in
        // `bring_up`), and a link going down is one. The wake arrives, the loop
        // reads both links, and the bond selects.
        if idle > 200 && VECTORED.load(core::sync::atomic::Ordering::Relaxed) {
            let _ = call(syscall::INVOKE, SIGNAL, method::WAIT, [0; 4]);
            for port in ports.iter().flatten() {
                let _ = call(syscall::INVOKE, port.at.handler, method::ACK, [0; 4]);
            }
            idle = 0;
        } else {
            call(syscall::YIELD, 0, 0, [0; 4]);
        }
    }
}

/// What the first port's receive queue has seen, for the report.
///
/// The report's `rx_seen` word predates the bond and names one queue. It stays
/// the first port's, so the number means what it has always meant; the bond's
/// own counts are in [`bond_report`].
fn receive_seen(ports: &[Option<Port>; 2]) -> u16 {
    ports[0].as_ref().map_or(0, |port| port.receive.seen())
}

/// Words in the report this program writes.
///
/// Seventeen are the driver's own, five the bond's and two the X722's, and the
/// kernel reads exactly this many. Named because three places write it and a
/// length spelled three times is wrong in at least one of them -- which this
/// file has recorded happening twice.
const REPORT_WORDS: usize = 24;

/// Everything the X722 needs to carry a frame, once it is up.
///
/// **RFC 0075 step 4**: the queue programming the kernel used to do, in the
/// service that holds the device. What each call means is in `bhaskix-i40e`,
/// beside the datasheet section it came from; what is here is the memory and
/// the order.
#[allow(
    dead_code,
    reason = "held by the bring-up and read when the port joins the loop, which               is the next half of RFC 0075 step 4: frames to and from bin/ipd"
)]
struct X722Queues {
    /// The receive ring, as this program writes it and as the device reads it.
    ring: X722Memory,
    /// Where the device fetches it.
    ring_device: u64,
    /// The packet buffers, as this program reads them.
    buffers: X722Memory,
    /// Where the device writes them.
    buffers_device: u64,
    /// The transmit ring and its packet buffer.
    transmit: X722Memory,
    /// Where the device reads them.
    transmit_device: u64,
    /// The absolute index of the receive queue taken.
    queue: u32,
    /// The transmit queue, which is the same index in the other direction.
    transmit_queue: u32,
    /// Descriptors handed over, which is also the tail.
    posted: u32,
}

/// Brings the X722's queues up: private memory, contexts, buffers, filters and
/// the write-back path.
///
/// The order is the kernel's, which is the datasheet's: out of PXE mode, the
/// LAN private memory programmed, a segment descriptor written and read back, a
/// page descriptor for the page each context falls in, the contexts themselves,
/// the buffers posted, the VSI told which queues are its own, the completions
/// routed to an interrupt that reports and does not raise, and only then the
/// queues enabled.
///
/// Returns `None` at the first step that will not complete, because every step
/// after it would be programming a device that is not going to answer.
fn bring_up_x722(
    device: &mut bhaskix_i40e::Device<X722Registers>,
    admin: &mut X722Memory,
    admin_device: u64,
    vsi: u16,
    vsi_number: u16,
    stage: &mut u8,
) -> Option<X722Queues> {
    use bhaskix_i40e as i40e;
    const SPINS: u32 = 2_000_000;

    // The queues this PF owns, and where the VSI's start.
    let (first, queues) = device.queue_allocation()?;
    *stage = 5;
    let (base, _scattered) = device.vsi_queue_base(vsi_number)?;
    let queue = u32::from(first) + u32::from(base);
    *stage = 6;

    // **Out of PXE mode first** -- 38.30.2.1's "operating system driver only
    // step", and the queue-length rule depends on it.
    let _ = device.clear_pxe_mode(admin, SPINS);

    // The private memory the HMC fetches contexts from, sized to the queues
    // this function owns rather than to the one it takes.
    let memory = device.program_lan_private_memory(u32::from(queues));
    let receive_base = i40e::receive_base_after(0, u32::from(queues), memory.tx_object_size);
    let at = i40e::context_location(receive_base, memory.rx_object_size, queue);
    let end = i40e::object_area_end(receive_base, u32::from(queues), memory.rx_object_size);
    let backing = i40e::backing_pages_to(end);

    // The HMC object: a page-descriptor page, then the pages it names.
    let hmc_device = map_window(X722_WINDOW, X722_HMC)?;
    *stage = 7;
    let mut hmc = X722Memory {
        at: X722_HMC_AT,
        bytes: (1 + backing as usize) * 4096,
    };
    let pd_page_device = hmc_device;
    let backing_device = hmc_device + 4096;

    let read_back = device.write_segment_descriptor(at.segment, pd_page_device, backing);
    if read_back != i40e::segment_descriptor(pd_page_device, backing) {
        return None;
    }
    *stage = 8;
    // The page the context falls in, named to the device.
    i40e::write_page_descriptor(
        &mut hmc,
        at.page,
        backing_device + u64::from(at.page) * 4096,
    );

    // The rings and the buffers behind them.
    let rings_device = map_window(X722_WINDOW, X722_RINGS)?;
    *stage = 9;
    let ring_bytes = X722_DESCRIPTORS as usize * i40e::RECEIVE_DESCRIPTOR_BYTES as usize;
    let buffers_at = 4096;
    let mut ring = X722Memory {
        at: X722_RINGS_AT,
        bytes: ring_bytes,
    };
    let buffers = X722Memory {
        at: X722_RINGS_AT + buffers_at,
        bytes: X722_POSTED as usize * X722_BUFFER as usize,
    };
    let buffers_device = rings_device + buffers_at;

    // The context, into the backing page at the offset the layout gives.
    let context = i40e::ReceiveContext {
        ring: rings_device,
        descriptors: X722_DESCRIPTORS,
        buffer_bytes: X722_BUFFER,
        max_frame: X722_BUFFER,
    };
    let mut backing_page = X722Memory {
        at: X722_HMC_AT + 4096 + u64::from(at.page) * 4096,
        bytes: 4096,
    };
    i40e::write_receive_context(&mut backing_page, at.offset as usize, &context);

    let mut posted = [0u64; X722_POSTED as usize];
    for (slot, buffer) in posted.iter_mut().enumerate() {
        *buffer = buffers_device + (slot as u64) * u64::from(X722_BUFFER);
    }
    i40e::post_receive_descriptors(&mut ring, &posted);

    // **What the VSI forwards.** Its own MAC filter takes only frames sent to
    // this port; what a switch sends unprompted is multicast and broadcast.
    // One mode per command: bundling them was refused, and the refusal cost
    // the modes that had worked.
    for mode in [
        i40e::PromiscuousMode::Unicast,
        i40e::PromiscuousMode::Multicast,
        i40e::PromiscuousMode::Broadcast,
        i40e::PromiscuousMode::AnyVlan,
    ] {
        let _ = device.set_promiscuous(admin, vsi, mode, true, SPINS);
    }
    let _ = device.stop_lldp_agent(admin, false, SPINS);

    // The VSI is told which queues are its own, and the completions are routed
    // to an interrupt that reports and never raises -- without which the frames
    // arrive and nothing is ever posted back to say so.
    let mut vsi_buffer = X722Memory {
        at: X722_MEMORY_AT + i40e::VSI_BUFFER_OFFSET,
        bytes: i40e::VSI_BUFFER_BYTES as usize,
    };
    let _ = device.map_receive_queues(
        admin,
        vsi,
        admin_device + i40e::VSI_BUFFER_OFFSET,
        &mut vsi_buffer,
        0,
        X722_QUEUES as u16,
    );
    device.report_completions(queue, X722_QUEUES);

    *stage = 10;
    if !device.enable_receive_queue(queue, X722_POSTED, SPINS) {
        return None;
    }
    *stage = 11;
    device.arm_receive_queue(queue, X722_POSTED);

    // And the transmit side: its context in the same page, then the queue.
    let transmit_device = map_window(X722_WINDOW, X722_TX)?;
    *stage = 12;
    let transmit_at = i40e::context_location(0, memory.tx_object_size, queue);
    i40e::write_page_descriptor(
        &mut hmc,
        transmit_at.page,
        backing_device + u64::from(transmit_at.page) * 4096,
    );
    let mut transmit_backing = X722Memory {
        at: X722_HMC_AT + 4096 + u64::from(transmit_at.page) * 4096,
        bytes: 4096,
    };
    i40e::write_transmit_context(
        &mut transmit_backing,
        transmit_at.offset as usize,
        &i40e::TransmitContext {
            ring: transmit_device,
            descriptors: i40e::TRANSMIT_DESCRIPTORS,
            ready_list: 0,
        },
    );
    device.clear_transmit_queue_disable(queue);
    device.own_transmit_queue(queue, memory.function);
    let _ = device.enable_transmit_queue(queue, SPINS);
    device.attach_transmit_ring(i40e::TRANSMIT_DESCRIPTORS);

    Some(X722Queues {
        ring,
        ring_device: rings_device,
        buffers,
        buffers_device,
        transmit: X722Memory {
            at: X722_TX_AT,
            bytes: 4096,
        },
        transmit_device,
        queue,
        transmit_queue: queue,
        posted: X722_POSTED,
    })
}

/// Asks the DMA window where the device reaches the object in `slot`.
fn map_window(window: u64, slot: u64) -> Option<u64> {
    let (status_out, at) = call(syscall::INVOKE, window, method::MAP, [slot, 0, 0, 0]);
    (status_out == status::OK).then_some(at)
}

/// Carries frames between the X722 and `bin/ipd`, for ever.
///
/// **RFC 0075 step 4's other half.** The queues are up; this is what makes them
/// a network: what the device writes goes into the ring `bin/ipd` reads, and
/// what `bin/ipd` builds goes onto the wire.
///
/// The shape is the virtio loop's, with the two differences the devices have.
/// A received frame is found by walking the descriptors for a write-back rather
/// than by a used ring, and it carries no header in front of it -- so the frame
/// starts at the buffer rather than twelve bytes into it. A transmitted frame
/// is posted with the driver's own cursor, which is the one that must not be
/// recomputed by a caller.
fn carry_x722(mut queues: X722Queues, found: X722) -> ! {
    use bhaskix_i40e as i40e;
    const SPINS: u32 = 2_000_000;

    let mut device = i40e::Device::new(X722Registers);
    device.attach_transmit_ring(i40e::TRANSMIT_DESCRIPTORS);

    let back_mapped = attach(BACK, BACK_AT, 1);
    if !attach(RING, RING_AT, 1) {
        loop {
            call(syscall::YIELD, 0, 0, [0; 4]);
        }
    }

    let (state, firmware) = found.words();
    let mut handed = 0u64;
    let mut sent = 0u64;
    let mut seen = 0u64;
    // Which descriptor the device will fill next, as this program follows it.
    let mut next = 0u32;
    let mut idle = 0u32;

    loop {
        // **What arrived.** The descriptors are walked in order rather than
        // scanned, because the device fills them in order and a scan would take
        // a later frame before an earlier one -- which is a reordering, not a
        // shortcut.
        if let Some(completion) = i40e::completed_descriptor(&queues.ring, next) {
            idle = 0;
            seen += 1;
            let length = completion.length as usize;
            let buffer = queues.buffers.at + u64::from(next) * u64::from(X722_BUFFER);
            // SAFETY: a buffer this program mapped and the device has finished
            // with -- the descriptor's write-back is what says so -- and the
            // ring to `bin/ipd`, mapped writable above.
            if length > 0 && unsafe { hand_to_ipd(buffer, length) } {
                handed += 1;
            }
            // Back to the device, and the tail after it: a descriptor taken and
            // not given back is a ring that works once, which this file has
            // recorded discovering twice.
            i40e::post_receive_descriptor(
                &mut queues.ring,
                next,
                queues.buffers_device + u64::from(next) * u64::from(X722_BUFFER),
            );
            next = (next + 1) % queues.posted;
            device.arm_receive_queue(queues.queue, next);
            no_virtio_report_with(state, firmware, found.address(), handed, sent, seen);
        }

        // **What `bin/ipd` built.** One per pass, and its completion waited for
        // -- this program is pinned and the transmit ring is eight deep, so a
        // frame posted and forgotten is a descriptor nobody reclaims.
        if back_mapped {
            // SAFETY: the return ring is mapped, and the packet buffer is the
            // page this program mapped for the transmit ring's use. No header:
            // an X722 takes the frame as it stands.
            if let Some(length) = unsafe { take_from_ipd_into(queues.transmit.at + 2048, 0) } {
                idle = 0;
                if let Some(slot) = device.post_frame(
                    &mut queues.transmit,
                    queues.transmit_device + 2048,
                    length as u16,
                    false,
                ) {
                    device.transmit_doorbell(queues.transmit_queue, device.transmit_tail());
                    for _ in 0..SPINS {
                        if device.frame_completed(&queues.transmit, slot) {
                            break;
                        }
                        core::hint::spin_loop();
                    }
                    sent += 1;
                    no_virtio_report_with(state, firmware, found.address(), handed, sent, seen);
                }
            }
        }

        // **Yield rather than spin.** This program is pinned, and there is no
        // interrupt delegated for this device -- the completions are reported
        // through the write-back path and not through a vector -- so there is
        // nothing to park on and the processor has to be handed back by hand.
        idle = idle.saturating_add(1);
        if idle > 64 {
            idle = 0;
        }
        call(syscall::YIELD, 0, 0, [0; 4]);
    }
}

/// Publishes what this program found on a machine with no virtio device.
///
/// The report `report` writes describes a virtio driver's rings and counters,
/// none of which exist here. This writes the marker, the X722's two words, and
/// zeroes for the rest -- so the kernel reads a report rather than concluding
/// the service left none, and the X722 line is what says what was found.
fn no_virtio_report(state: u64, firmware: u64, address: u64) {
    no_virtio_report_with(state, firmware, address, 0, 0, 0)
}

/// The same, with what the frames have done so far.
fn no_virtio_report_with(
    state: u64,
    firmware: u64,
    address: u64,
    handed: u64,
    sent: u64,
    seen: u64,
) {
    let mut words = [0u64; REPORT_WORDS];
    words[0] = MARKER;
    // **Word 1 is the station address**, which is where the kernel reads it to
    // tell `bin/ipd` what interface it is on. On a machine with a virtio device
    // that is the virtio port's; here it is the X722's, and without it the
    // service above holds an unspecified address for the life of the boot.
    words[1] = address;
    words[8] = seen;
    words[9] = handed;
    words[10] = sent;
    words[22] = state;
    words[23] = firmware;
    let at = RINGS_AT + ring::REPORT;
    // SAFETY: the last page of the rings this program mapped writable, which no
    // ring and no buffer reaches. The marker is written last, so a kernel that
    // reads a partial report sees no marker rather than half the fields.
    unsafe {
        for (index, word) in words.iter().enumerate().skip(1) {
            core::ptr::write_volatile((at + index as u64 * 8) as *mut u64, *word);
        }
        core::ptr::write_volatile(at as *mut u64, words[0]);
    }
}

/// What the X722 answered, or that there is none to ask.
///
/// RFC 0075 step 2. This is deliberately the same first three questions RFC
/// 0072 step 3 asked when the kernel drove the device -- can it be reset, will
/// it take an admin queue, and what does it say it is -- because the whole
/// claim of the move is that the answers do not change when the asker does.
#[derive(Clone, Copy, Default)]
struct X722 {
    /// Whether the register pages and the memory were there to be taken.
    delegated: bool,
    /// Whether the device completed a PF reset.
    reset: bool,
    /// Whether both admin queues read back as enabled.
    queues: bool,
    /// The firmware version it reported, major and minor.
    firmware: (u16, u16),
    /// Its link, as `Get Link Status` answered.
    link_up: bool,
    /// And the speed byte behind that, kept raw for the report.
    link_speed: u8,
    /// How many switch elements it reported, which is what says a VSI exists
    /// for frames to be steered to.
    switch_elements: u16,
    /// The VSI number firmware assigned, which is what indexes its registers.
    vsi: u16,
    /// Whether its **LAN** queues came up -- the ones that carry frames, as
    /// against the admin queues that carry commands.
    carrying: bool,
    /// Its station address, once there is a queue to use it with.
    mac: [u8; 6],
    /// **How far the bring-up got.**
    ///
    /// A driver that stops has stopped *somewhere*, and on a machine that takes
    /// seven minutes to boot the difference between "it did not come up" and
    /// "it stopped at the segment descriptor" is a day. `bin/ahcid` keeps the
    /// same kind of number for the same reason.
    stage: u8,
}

impl X722 {
    /// Its station address as one word, the way the report carries a MAC.
    fn address(self) -> u64 {
        let mut value = 0u64;
        for octet in self.mac {
            value = (value << 8) | u64::from(octet);
        }
        value
    }

    /// Packs what the kernel prints into two words of the report.
    fn words(self) -> (u64, u64) {
        let flags = u64::from(self.delegated)
            | u64::from(self.reset) << 1
            | u64::from(self.queues) << 2
            | u64::from(self.link_up) << 3
            | u64::from(self.carrying) << 4
            | u64::from(self.stage) << 40;
        (
            flags | u64::from(self.link_speed) << 8 | u64::from(self.switch_elements) << 16,
            u64::from(self.firmware.0) | u64::from(self.firmware.1) << 16,
        )
    }
}

/// Takes the X722 the kernel delegated, if it delegated one.
///
/// **The absence path is the one every lane runs**, and it is the gate for this
/// step: a machine with no such NIC leaves the slots empty, the first attach
/// fails, and this answers `delegated: false` without touching a register. Every
/// QEMU lane checks that, because none of them has an X722 and none ever will.
fn take_x722() -> (X722, Option<X722Queues>) {
    let mut found = X722::default();
    let mut carrying = None;

    // The register pages first, because they are what makes the rest reachable
    // and because their absence is the cheapest thing to discover. Each is
    // mapped at its own offset from `X722_AT`, so every register offset in the
    // crate works against that base unchanged.
    for (index, page) in bhaskix_i40e::REGISTER_PAGES.iter().enumerate() {
        if !attach(X722_PAGES + index as u64, X722_AT + page, 1) {
            return (found, None);
        }
    }
    if !attach(X722_MEMORY, X722_MEMORY_AT, 1) {
        return (found, None);
    }
    // Where the device will look for its rings. Without a window there is no
    // such number, and a device that cannot be aimed cannot be driven -- the
    // refusal working, exactly as it does for the virtio ports above.
    let (mapped, admin_device) = call(
        syscall::INVOKE,
        X722_WINDOW,
        method::MAP,
        [X722_MEMORY, 0, 0, 0],
    );
    if mapped != status::OK {
        return (found, None);
    }
    found.delegated = true;

    /// Long enough for firmware to answer, bounded so a device that never does
    /// cannot hang a boot. The kernel used the same number for the same reason.
    const SPINS: u32 = 2_000_000;

    let mut device = bhaskix_i40e::Device::new(X722Registers);
    let mut admin = X722Memory {
        at: X722_MEMORY_AT,
        bytes: 4096,
    };
    found.reset = device.reset(SPINS);

    // The two rings, at the offsets the crate lays out, as the *device* reaches
    // them -- and the buffers behind them in the same page.
    device.enable_admin_queues(admin_device, admin_device + bhaskix_i40e::RING_BYTES);
    found.queues = device.admin_queues_enabled();

    if let Ok(version) = device.get_version(&mut admin, SPINS) {
        found.firmware = version;
    }
    if let Ok(link) = device.link_status(&mut admin, SPINS) {
        found.link_up = link.up();
        found.link_speed = link.speed;
    }
    // The switch, into the buffer that follows both rings in the same page.
    let mut buffer = X722Memory {
        at: X722_MEMORY_AT + bhaskix_i40e::SWITCH_BUFFER_OFFSET,
        bytes: bhaskix_i40e::SWITCH_BUFFER_BYTES as usize,
    };
    found.stage = 1;
    let mut seid = 0;
    if let Ok(switch) = device.switch_configuration(
        &mut admin,
        admin_device + bhaskix_i40e::SWITCH_BUFFER_OFFSET,
        &mut buffer,
        SPINS,
    ) {
        found.switch_elements = switch.count as u16;
        // The first VSI in the switch is the one this port's frames land in.
        for element in switch.elements() {
            if element.kind_name() == "VSI" {
                seid = element.seid;
                break;
            }
        }
    }
    if seid == 0 {
        return (found, None);
    }
    found.stage = 2;

    // **The number to index registers by is asked of firmware**, not taken from
    // the switch element: the two disagreed on the SR550, 19 against 12, and
    // `VSILAN_QBASE` is indexed by the number.
    let mut vsi_buffer = X722Memory {
        at: X722_MEMORY_AT + bhaskix_i40e::VSI_BUFFER_OFFSET,
        bytes: bhaskix_i40e::VSI_BUFFER_BYTES as usize,
    };
    let Ok(parameters) = device.vsi_parameters(
        &mut admin,
        seid,
        admin_device + bhaskix_i40e::VSI_BUFFER_OFFSET,
        &mut vsi_buffer,
        SPINS,
    ) else {
        return (found, None);
    };
    found.vsi = parameters.number;
    found.stage = 3;

    // The memory the queues need, and then the queues.
    if !attach(X722_HMC, X722_HMC_AT, 1)
        || !attach(X722_RINGS, X722_RINGS_AT, 1)
        || !attach(X722_TX, X722_TX_AT, 1)
    {
        return (found, None);
    }
    found.stage = 4;
    if let Some(queues) = bring_up_x722(
        &mut device,
        &mut admin,
        admin_device,
        seid,
        parameters.number,
        &mut found.stage,
    ) {
        found.carrying = true;
        found.mac = device.mac_address(device.port_number()).unwrap_or([0; 6]);
        carrying = Some(queues);
    }
    (found, carrying)
}

/// Leaves the bond's own state where the kernel reads the rest of the report.
///
/// Words 17 to 22, appended rather than folded into [`report`]'s arguments:
/// that function already takes ten and clippy's limit is not the only reason to
/// stop -- a caller passing four more positional numbers is a caller that will
/// pass them in the wrong order.
fn bond_report(
    ports: &[Option<Port>; 2],
    active: usize,
    failovers: u64,
    off_member: u64,
    x722: X722,
) {
    let at = RINGS_AT + ring::REPORT;
    let members = ports.iter().flatten().count() as u64;
    // One bit per member, so "the bond is up on one leg" and "both are up" are
    // different numbers rather than the same count.
    let mut links = 0u64;
    for (index, port) in ports.iter().enumerate() {
        if port.as_ref().is_some_and(|port| port.up) {
            links |= 1 << index;
        }
    }
    let (x722, firmware) = x722.words();
    let words = [
        members,
        active as u64,
        links,
        failovers,
        off_member,
        x722,
        firmware,
    ];
    // SAFETY: the report page this program mapped writable, at the five words
    // that follow the seventeen `report` writes. The marker is not touched:
    // this is an addition to a report that is already published, and a reader
    // that stops at seventeen words is unaffected.
    unsafe {
        for (index, word) in words.iter().enumerate() {
            core::ptr::write_volatile((at + (17 + index as u64) * 8) as *mut u64, *word);
        }
    }
}

/// Where receive buffer `index` starts, within the rings object.
const fn ring_buffer_of(index: u16) -> u64 {
    ring::RX_BUFFERS + (index as u64) * ring::RX_BUFFER
}

/// Leaves the findings where the kernel granted memory for them.
///
/// Through memory rather than a console, because this driver holds no console
/// capability: a driver has no business printing, and giving it one to make a
/// test easier would have made the test prove less.
#[allow(clippy::too_many_arguments)]
fn report(
    mac: u64,
    sent: u64,
    received: u64,
    source: u64,
    header: u64,
    rx_seen: u64,
    handed: u64,
    sent_for_ipd: u64,
    took: u64,
    took_length: u64,
) {
    let at = RINGS_AT + ring::REPORT;
    let words = [
        MARKER,
        mac,
        sent,
        received,
        source,
        header,
        u64::from(queue::RECEIVE),
        u64::from(queue::TRANSMIT),
        // What the receive ring itself says the device has done. Reported
        // because "nothing was received" has two very different causes -- the
        // device wrote nothing, or it wrote and this driver misread the ring --
        // and a count distinguishes them where a boolean cannot.
        rx_seen,
        // How many frames this program put into the ring to `ipd`. Reported
        // because "nothing crossed" has two causes -- a producer that never
        // handed anything over, and a consumer that never read it -- and they
        // are indistinguishable from the far end.
        handed,
        // Frames taken out of the return ring and put on the wire. Counted
        // separately from `handed` because "nothing came out" has an end at
        // each side of a ring, and one number cannot say which.
        sent_for_ipd,
        took,
        took_length,
        WIDEST.load(core::sync::atomic::Ordering::Relaxed),
        OUTSTANDING.load(core::sync::atomic::Ordering::Relaxed),
        COPIES.load(core::sync::atomic::Ordering::Relaxed),
    ];
    // SAFETY: the last page of the rings this program mapped writable, which no
    // ring and no buffer reaches. The marker is written *last*, so a kernel
    // that reads a partial report sees no marker rather than half the fields.
    unsafe {
        for (index, word) in words.iter().enumerate().skip(1) {
            core::ptr::write_volatile((at + index as u64 * 8) as *mut u64, *word);
        }
        core::ptr::write_volatile(at as *mut u64, words[0]);
    }
}

core::arch::global_asm!(
    r#"
.section .text._start,"ax",@progbits
.globl _start
_start:
    xor rbp, rbp
    and rsp, -16
    call netd_main
    ud2
"#
);
