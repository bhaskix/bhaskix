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
/// Its register pages start at this port's `grant::PAGES` and run for one slot
/// per entry in `i40e::REGISTER_PAGES`. **Thirty-seven of them, not one**,
/// because a virtio
/// device's registers are a page and this device's are four megabytes: the
/// whole BAR cannot be a capability and should not be, so the crate names the
/// pages that hold a register it uses and the kernel grants exactly those. See
/// `i40e::REGISTER_PAGES`.
const X722_FIRST_SLOT: u64 = 16;

/// How many X722 ports this program will drive.
///
/// **Four, which is every port the card has** -- RFC 0076. A port costs
/// `grant::SPAN` slots, which is 42, against `CSPACE_SLOTS` of 256 with the
/// first sixteen spoken for: four take 184 and six would not fit. The kernel
/// holds the matching constant and `bhaskix_i40e::grant`'s own test is what
/// says the number is right.
///
/// **It was two while that table was 128**, which was a fact about the table
/// and not about the card -- and the SR550's switch bundles all four ports in
/// one channel-group, so a bond of two was the wrong shape for that wire.
const X722_MEMBERS: usize = 4;

/// And the report's block of member addresses is the same width, because a
/// fifth port would have an address with nowhere to publish it. Asserted rather
/// than commented: two constants that must agree and do not have to is how this
/// file's bond spent two changes with a two-element array and four members.
const _: () = assert!(X722_MEMBERS == ring::MEMBER_ADDRESS_COUNT);

/// Slot `offset` of port `nth`'s grant.
///
/// **The layout is `bhaskix_i40e::grant`'s**, not this file's and not the
/// kernel's. Both used to spell it out, which is two copies of one arithmetic
/// that had to agree with no way to check that they did -- and slots 54, 55 and
/// 56 sitting inside a register range that had grown past them is what that
/// cost. RFC 0076 moved it into the crate both sides already link.
const fn x722_slot(nth: u64, offset: u64) -> u64 {
    bhaskix_i40e::grant::base(X722_FIRST_SLOT, nth) + offset
}

/// How far apart two ports' mappings are laid out.
///
/// A quarter of a gigabyte, against a register window of under four megabytes
/// and four memory objects behind it. Generous on purpose: these are addresses
/// in this program's own space, they cost nothing unmapped, and a stride that
/// is obviously clear of the thing it separates cannot be quietly outgrown.
const X722_STRIDE: u64 = 0x1000_0000;

/// Where port `nth`'s registers are mapped: page `P` of its BAR at `+ P`.
///
/// Sparse — only the pages granted are mapped — and at their own offsets, so
/// every register offset in `bhaskix-i40e` works against this base unchanged.
/// A register in a page nobody granted faults instead of being reachable, which
/// is the whole point of naming pages.
const fn x722_at(nth: u64) -> u64 {
    0x3000_0000 + nth * X722_STRIDE
}
/// And where its admin page goes, clear of the register window's four megabytes.
const fn x722_memory_at(nth: u64) -> u64 {
    x722_at(nth) + 0x0400_0000
}
/// The private memory the HMC reads: a page-descriptor page and the pages it
/// names.
const fn x722_hmc_at(nth: u64) -> u64 {
    x722_at(nth) + 0x0410_0000
}
/// The receive rings, and the packet buffers behind them.
const fn x722_rings_at(nth: u64) -> u64 {
    x722_at(nth) + 0x0420_0000
}
/// The transmit ring and its packet buffer.
const fn x722_tx_at(nth: u64) -> u64 {
    x722_at(nth) + 0x0430_0000
}

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
struct X722Registers {
    /// Where this port's register pages were mapped.
    ///
    /// **This was a unit struct with the address welded into all three
    /// methods**, which is what a program driving one device writes. RFC 0076
    /// needs two, and this field is the whole of what stood in the way:
    /// `X722Memory` already carried its own address, and `bring_up_x722`
    /// already took the device and its memory as parameters.
    at: u64,
}

impl bhaskix_i40e::Registers for X722Registers {
    fn read(&self, offset: u64) -> u32 {
        // SAFETY: the register pages this program attached at their own offsets
        // from `self.at`. An offset in a page nobody granted is not mapped and
        // faults, which is the containment working rather than a hazard.
        unsafe { read32(self.at + offset) }
    }

    fn write(&mut self, offset: u64, value: u32) {
        // SAFETY: as `read`.
        unsafe { write32(self.at + offset, value) };
    }

    fn read64(&self, offset: u64) -> u64 {
        // SAFETY: as `read`; every offset read this way is a documented 64-bit
        // register pair, 8-byte aligned by its own stride.
        unsafe { read64(self.at + offset) }
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

    /// Word in the report page the **kernel writes and this program reads**.
    ///
    /// **The one place the page runs the other way**, and it is worth naming
    /// rather than hiding: everything else here is `bin/netd` describing itself
    /// to the kernel. RFC 0076 step 3 needs the opposite -- a boot has to be
    /// able to ask for a failover, and on real hardware there is no hypervisor
    /// monitor to ask through. It is one word, well clear of the report's
    /// twenty-six, and non-zero means *take the active member's link down once
    /// traffic has proven it works*.
    pub const FAILOVER_REQUEST: u64 = REPORT + 40 * 8;

    /// The second such word: non-zero when the bond is **802.3ad**.
    ///
    /// A configuration fact, not a fact about any frame -- which is why this
    /// program may hold it. It decides whose received frames go up: in an
    /// aggregation every member carries, so every member's frames are handed
    /// across; in active-backup only the one carrying does, and a backup's
    /// frames would arrive twice.
    pub const BOND_IS_LACP: u64 = REPORT + 41 * 8;

    /// **Each member's own station address**, one word each, at word 32.
    ///
    /// Word 1 of the report is the *bond's* address, which is member zero's,
    /// and until 2026-09-10 it was the only address anything above this program
    /// could see. So every frame `bin/ipd` built left under one address
    /// whichever link carried it -- including the four LACPDUs of a four-link
    /// aggregation, and 802.1AX says an LACPDU's source is the individual
    /// address *of the port* it goes out of.
    ///
    /// The word here is a sentinel and the addresses follow it, one per member,
    /// zero where there is no member. The sentinel is what makes *not written
    /// yet* different from *no address*: the kernel waits for it before telling
    /// `bin/ipd` what the interface is, and without it a bring-up that reports
    /// after every port would be read one port in, with three addresses that
    /// had not been asked for yet published as zeros.
    pub const MEMBER_ADDRESSES: u64 = REPORT + 32 * 8;

    /// Written at [`MEMBER_ADDRESSES`], after the addresses behind it.
    pub const MEMBER_ADDRESSES_WRITTEN: u64 = 0x5352_4444_414d_454d;

    /// How many addresses follow the sentinel.
    ///
    /// The same four `X722_MEMBERS` is and `bin/ipd`'s `LACP_MACHINES` is: this
    /// is the width of the interface between them, so all three are one number
    /// or two of them are wrong.
    pub const MEMBER_ADDRESS_COUNT: usize = 4;
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
    // SAFETY: the caller's obligation, unchanged.
    unsafe { fill_announcement(w.rings + ring::TX_BUFFER, VIRTIO_NET_HEADER, mac) }
}

/// The same frame, at a raw address and with `header` bytes in front of it.
///
/// **Both bonds announce with this** -- RFC 0076 step 3. The X722 bond had no
/// frame of its own and forwarded only what `bin/ipd` built, so when it failed
/// over there was nothing to send and the report could say only that nothing
/// had crossed. That is not evidence about the switch; it is evidence that
/// nothing was tried, and RFC 0074's own note said what was needed: *"a switch
/// learns which port an address is on from the frames it sees, and after a
/// failover everything it learned is wrong"*.
///
/// `header` is the virtio header a virtio device expects in front of the frame,
/// and zero for an X722, which takes the frame as it stands.
///
/// # Safety
///
/// `at` must be a writable mapping of at least `header + 42` bytes.
unsafe fn fill_announcement(at: u64, header: u64, mac: [u8; 6]) -> u64 {
    const FRAME: u64 = 42;

    // SAFETY: the caller guarantees the mapping; `header + FRAME` is far inside
    // one page.
    unsafe {
        for offset in 0..header + FRAME {
            core::ptr::write_volatile((at + offset) as *mut u8, 0);
        }
        let frame = at + header;
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
    header + FRAME
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

/// Hands one frame to `bin/ipd`: a four-byte length and member, then the bytes.
///
/// `member` is the bond member the frame arrived on, or `None` where there is
/// no bond. `bin/ipd` runs one LACP machine per link and answers a partner on
/// the link it spoke from, so the index has to survive the crossing -- and an
/// index is all this program hands over, never a reading of the frame.
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
unsafe fn hand_to_ipd(frame_at: u64, length: usize, member: Option<u8>) -> bool {
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
    // The uplink flag is an instruction about *leaving*, so an arriving frame
    // never carries one.
    let prefix = chan::mark(length as u32, member, false).to_le_bytes();
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
unsafe fn take_from_ipd_into(buffer: u64, header: u64) -> Option<(usize, Option<u8>, bool)> {
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
    // **The member and the route, then the length.** `bin/ipd` names the member
    // a frame must leave by -- an LACPDU carries the port id of the link it goes
    // out of, so it can go out of that link and no other -- and says whether the
    // frame must reach the *wire* rather than this device's own switch. Both are
    // its to say: this program reads an index and a bit, never the frame, which
    // is the rule RFC 0018 set for the domain that holds DMA.
    let (length, for_member, uplink) = chan::marked(u32::from_le_bytes(prefix));
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
    Some((length, for_member, uplink))
}

/// Takes a frame `bin/ipd` built into a virtio port's transmit buffer.
///
/// # Safety
///
/// As [`take_from_ipd_into`], for the buffer inside `w`'s rings.
unsafe fn take_from_ipd(w: Windows) -> Option<usize> {
    // The member `bin/ipd` named is dropped here, deliberately: the virtio bond
    // sends out its active member only. It is a lane's bond with no switch to
    // aggregate it, so naming a link has nothing to act on -- the X722 bond is
    // where the mark is honoured.
    //
    // SAFETY: the caller's obligation, and the buffer is inside the rings
    // object this program mapped writable.
    unsafe { take_from_ipd_into(w.rings + ring::TX_BUFFER, VIRTIO_NET_HEADER) }
        .map(|(len, _, _)| len)
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
        //
        // **Both ports, RFC 0076 step 1.** A bond needs two members and this
        // program was given one, so on the only machine in the project with
        // real ports the bond RFC 0074 built had nothing to select between.
        // The second is taken exactly as the first is -- by asking the
        // capability space whether it is there -- so a machine with one port
        // gets `delegated: false` for the second and says so.
        let mut found = [X722::default(); X722_MEMBERS];
        // Sized from the constant rather than written out, so the array and
        // the count cannot disagree -- which they would have the moment
        // `X722_MEMBERS` moved off two.
        let mut members: [Option<X722Member>; X722_MEMBERS] = [const { None }; X722_MEMBERS];
        for nth in 0..X722_MEMBERS {
            let (taken, member) = take_x722(nth as u64);
            found[nth] = taken;
            // **Both members are kept now** -- RFC 0076 step 2. Step 1 drove
            // the first and measured the second; a bond has to be able to
            // choose, so each one's device, rings and admin queue survive the
            // bring-up that produced them.
            members[nth] = member;
            // **Publish after every port, not after all of them.** Bringing up
            // a second device is a second chance to die, and this program's
            // report is the only thing that says what happened -- so a port
            // that faults must not take the previous port's findings with it.
            //
            // It did. The second boot of RFC 0076 step 1 published nothing at
            // all and the machine reported *"the driver left no report"*, which
            // named neither the port that had come up perfectly nor the one
            // that had not. RFC 0075 step 3 learned the same lesson one level
            // out -- a NIC is not required to run, being able to report is --
            // and this is that rule applied between two ports rather than
            // between a device and none.
            let (state, firmware) = found[0].words();
            no_virtio_report_with(
                state,
                firmware,
                found[0].address(),
                0,
                0,
                0,
                found[X722_MEMBERS - 1].pair(),
            );
        }
        // **Every member's own address, now that every member is known.**
        //
        // Deliberately outside the loop above, which publishes after each port
        // so that a port that faults does not take the previous port's findings
        // with it. This block is the opposite case: it is read by the kernel to
        // decide what to tell `bin/ipd`, and a block published one port in
        // would say three of the four links have no address of their own.
        let mut addresses = [0u64; ring::MEMBER_ADDRESS_COUNT];
        for (slot, fact) in addresses.iter_mut().zip(found.iter()) {
            *slot = fact.address();
        }
        member_address_report(addresses);
        if members.iter().any(Option::is_some) {
            carry_x722(members, found);
        }
        loop {
            call(syscall::YIELD, 0, 0, [0; 4]);
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
        // No member came up, so no member has an address -- said rather than
        // left unwritten, because the kernel waits for this block and a driver
        // that never publishes it would hold the boot for the whole window.
        member_address_report([0; ring::MEMBER_ADDRESS_COUNT]);
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
            // **This member's own address is read below**, and until
            // 2026-09-10 it was read by nobody -- every frame left under the
            // first member's address whichever member carried it, so a second
            // address was a fact with no consumer. It has one now: RFC 0076
            // step 4 sources each link's LACPDU from the link's own address,
            // which is what 802.1AX says an LACPDU's source is. What has *not*
            // changed is where data leaves under: that is still the bond's
            // address, which is RFC 0074's rule and the reason a failover does
            // not change what the far end has learnt.
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

    // **Every member's own address, now that both ports have been tried.**
    //
    // This member's address used to be read by nobody, and the comment where it
    // is brought up said so: every frame left under the first member's address
    // whichever member carried it, so a second address was a fact with no
    // consumer. RFC 0076 step 4 gave it one -- `bin/ipd` sources each link's
    // LACPDU from the link's own address -- so it is read here, off the device
    // configuration window each port was brought up through.
    let mut addresses = [0u64; ring::MEMBER_ADDRESS_COUNT];
    for (slot, port) in addresses.iter_mut().zip(ports.iter()) {
        if let Some(port) = port {
            // SAFETY: the device configuration window this port was brought up
            // through, mapped read-only above.
            *slot = unsafe { station_address(port.at.device) };
        }
    }
    member_address_report(addresses);

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
    let (x722, x722_queues) = take_x722(0);
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
    // Frames a member that is not carrying traffic delivered. Counted rather
    // than ignored: in active-backup both members are on the wire and both
    // receive, and a frame taken from the backup would be a duplicate of one
    // the active member already handed across -- so those are dropped. In an
    // 802.3ad bond every member carries and they go up, still counted here.
    let mut off_member = 0u64;

    // Which of those two this is. Read once: the kernel writes the word before
    // this program starts, and it does not change while it runs.
    let lacp_bond = bond_is_lacp();

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
        if unsafe { hand_to_ipd(buffer, received as usize, None) } {
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
        // another, if there is one that can. **The rule lives in [`select`]**
        // -- RFC 0076 step 2 -- because the X722 bond makes the same decision
        // and two copies of it would drift.
        let up = [
            ports[0].as_ref().is_some_and(|port| port.up),
            ports[1].as_ref().is_some_and(|port| port.up),
        ];
        let chosen = select(active, &up);
        if chosen != active {
            active = chosen;
            failovers += 1;
            // **Announce on the member that has taken over.** A switch learns
            // which port an address is on from the frames it sees, and after a
            // failover everything it learned is wrong: it goes on sending this
            // station's traffic to a port that has gone away, until something
            // arrives from the new one. Linux's bonding sends gratuitous ARP
            // here for this reason; this driver has one frame it knows how to
            // send, so it sends that.
            //
            // It is also what makes "traffic continues" measurable rather than
            // hoped for: the answer comes back on the new member and crosses to
            // `bin/ipd`, so the report can say a frame arrived *after* the
            // failover rather than that nothing has gone wrong yet.
            probes = 0;
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
        // or not either is carrying traffic. What happens to a frame from a
        // member that is not the active one depends on the bond: in
        // active-backup it is given back to the device and not handed across,
        // because it duplicates one the active member already delivered and a
        // bond that delivered both would be a bond that reordered. In an
        // aggregation every member carries and there is no duplicate to drop.
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
            // **Whose frames go up.** In an 802.3ad bond every member carries,
            // so every member's frames are handed across; in active-backup only
            // the one carrying does, and a backup's would arrive twice. The
            // mode is `ring::BOND_IS_LACP`, a configuration fact the kernel
            // wrote -- this program still never reads a frame.
            if length > 0 && (index == active || lacp_bond) {
                // SAFETY: as above.
                if unsafe { hand_to_ipd(buffer, length, Some(index as u8)) } {
                    handed += 1;
                }
            }
            if index != active && length > 0 {
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
const REPORT_WORDS: usize = 28;

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

/// Which member of a bond should carry, given which one does now.
///
/// **The rule, and there is only one of it.** RFC 0076 step 2: the virtio bond
/// and the X722 bond make the same three decisions, and two loops with the same
/// logic written twice would drift. This is that logic, called by both.
///
/// * The member carrying traffic keeps it while its link is up.
/// * When it is not, the first other member that is up takes over.
/// * A member whose link comes back does **not** take it back. That is churn
///   and reordering for no gain -- RFC 0074's rule, unchanged.
/// * With nothing up, the bond stays where it is: a down member and no member
///   carry the same amount of traffic, and staying put means the link returning
///   needs no second decision.
///
/// **This has no host test and cannot have one**: `bin/netd` is its own
/// workspace, outside `cargo test --workspace`, which is what
/// `tools/check-deps.py` says about anything written here. What it has instead
/// is `make test-bond`, which boots two guests, drops the active member's link
/// and watches traffic move -- watched red when it was written. Sharing one
/// implementation is what makes that lane cover the X722 path too.
fn select(active: usize, up: &[bool]) -> usize {
    if up.get(active).copied().unwrap_or(false) {
        return active;
    }
    for (index, live) in up.iter().enumerate() {
        if index != active && *live {
            return index;
        }
    }
    active
}

/// How far a bring-up got, and the two numbers behind a refusal.
///
/// **One argument rather than two**, because `bring_up_x722` had eight and the
/// limit is seven -- and because these belong together anyway: they are the
/// whole of what a bring-up reports about itself when it does not finish.
struct Progress {
    /// **How far the bring-up got.**
    ///
    /// A driver that stops has stopped *somewhere*, and on a machine that takes
    /// seven minutes to boot the difference between "it did not come up" and
    /// "it stopped at the segment descriptor" is a day. `bin/ahcid` keeps the
    /// same kind of number for the same reason.
    stage: u8,
    /// The backing pages the layout wanted and the page its context fell in --
    /// the two `grant::HMC_PAGES` is checked against.
    layout: (u8, u8),
    /// Whether `allow_destination_override` succeeded.
    ///
    /// **Kept because it was discarded.** Without that flag a switch control tag
    /// is *"not permitted"*, so a failure here makes every uplink-tagged frame
    /// behave exactly like an untagged one -- silently, and with the driver
    /// still counting them sent.
    override_ok: bool,
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
    progress: &mut Progress,
    nth: u64,
) -> Option<X722Queues> {
    use bhaskix_i40e as i40e;
    use bhaskix_i40e::grant;
    const SPINS: u32 = 2_000_000;

    // The queues this PF owns, and where the VSI's start.
    //
    // **The index is the queue's number in the PF's own space, not the
    // device's**, and that distinction is invisible on the first function of a
    // card because its `FIRSTQ` is zero. RFC 0076 step 1's second boot is where
    // it stopped being invisible: `bin/netd` took a page fault at
    // `0x4411c000` bringing up `b1:00.1`, which is page 28 of a sixteen-page
    // object, because the context was located by an index that had `FIRSTQ`
    // added to it.
    //
    // C620 §38.30.3.4.2 says it three times for the three places it matters --
    // *"'n' is the queue index within the PF space"* for `QRX_TAIL[n]` and for
    // `QRX_ENA[n]`, and *"prepare the queue context in the FPM in the PF memory
    // space"*. Each function has a BAR of its own (`0x23ffd000000` and
    // `0x23ffc000000` on this machine), so a queue register named `Q=0...1535`
    // globally is still reached PF-relative through that window.
    //
    // `FIRSTQ` itself is not needed once the index is PF-relative -- it is the
    // thing that must *not* be added -- so it is read and discarded.
    let (_first, queue_count) = device.queue_allocation()?;
    progress.stage = 5;
    let (base, _scattered) = device.vsi_queue_base(vsi_number)?;
    let queue = u32::from(base);
    progress.stage = 6;

    // **Out of PXE mode first** -- 38.30.2.1's "operating system driver only
    // step", and the queue-length rule depends on it.
    let _ = device.clear_pxe_mode(admin, SPINS);

    // The private memory the HMC fetches contexts from, sized to the queues
    // this function owns rather than to the one it takes.
    let memory = device.program_lan_private_memory(u32::from(queue_count));
    let receive_base = i40e::receive_base_after(0, u32::from(queue_count), memory.tx_object_size);
    let at = i40e::context_location(receive_base, memory.rx_object_size, queue);
    let end = i40e::object_area_end(receive_base, u32::from(queue_count), memory.rx_object_size);
    let backing = i40e::backing_pages_to(end);

    // **The layout has to fit the memory that was granted, and if it does not
    // this refuses rather than writing past it.**
    //
    // The boot that made this necessary wrote to page 28 of a sixteen-page
    // object and took a page fault, which killed `bin/netd` before it could
    // report anything at all -- so the machine said "the driver left no report"
    // and named neither the port that worked nor the one that did not. The
    // index that produced 28 is fixed above; this is what makes the *class* of
    // that bug a refusal with a step number instead of a dead service.
    //
    // `X722Memory` bounds every access, but it cannot help here: the context
    // window's *base* is `at.page` pages in, so a page past the grant is
    // outside the mapping before the first offset is checked.
    //
    // **The two numbers are reported, not just the refusal.** A boot that says
    // "step 6" says a layout did not fit and nothing about why -- and the
    // difference between "this PF wants more backing pages than any PF gets"
    // and "this PF's context sits further into its private memory than the
    // grant reaches" is the difference between raising `HMC_PAGES` and finding
    // out why one function's queue base is not the other's.
    progress.layout = (backing.min(255) as u8, at.page.min(255) as u8);
    // The page-descriptor page, then the pages it names -- and the context has
    // to land inside them.
    let pages = u64::from(backing) + 1;
    if pages > grant::HMC_PAGES || u64::from(at.page) + 1 > grant::HMC_PAGES {
        return None;
    }

    // The HMC object: a page-descriptor page, then the pages it names.
    let hmc_device = map_window(x722_slot(nth, grant::WINDOW), x722_slot(nth, grant::HMC))?;
    progress.stage = 7;
    let mut hmc = X722Memory {
        at: x722_hmc_at(nth),
        bytes: (1 + backing as usize) * 4096,
    };
    let pd_page_device = hmc_device;
    let backing_device = hmc_device + 4096;

    let read_back = device.write_segment_descriptor(at.segment, pd_page_device, backing);
    if read_back != i40e::segment_descriptor(pd_page_device, backing) {
        return None;
    }
    progress.stage = 8;
    // The page the context falls in, named to the device.
    i40e::write_page_descriptor(
        &mut hmc,
        at.page,
        backing_device + u64::from(at.page) * 4096,
    );

    // The rings and the buffers behind them.
    let rings_device = map_window(x722_slot(nth, grant::WINDOW), x722_slot(nth, grant::RINGS))?;
    progress.stage = 9;
    let ring_bytes = X722_DESCRIPTORS as usize * i40e::RECEIVE_DESCRIPTOR_BYTES as usize;
    let buffers_at = 4096;
    let mut ring = X722Memory {
        at: x722_rings_at(nth),
        bytes: ring_bytes,
    };
    let buffers = X722Memory {
        at: x722_rings_at(nth) + buffers_at,
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
        at: x722_hmc_at(nth) + 4096 + u64::from(at.page) * 4096,
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
        at: x722_memory_at(nth) + i40e::VSI_BUFFER_OFFSET,
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

    // **And the VSI is allowed to fix a transmit packet's destination itself.**
    //
    // Without this flag a switch control tag in a transmit descriptor is *"not
    // permitted"*, and without that tag a frame is "routed according to hardware
    // filters" -- so this device's internal switch consumes one addressed to a
    // reserved group address instead of sending it out. Every LACPDU this system
    // built died there: `bin/ipd` counted 44 sent, `bin/netd` posted them and saw
    // them complete, and the switch at the far end reported DEFAULTED because
    // nothing had ever arrived.
    //
    // **The crate has had the command and the tag since 2026-09-06** -- the
    // reasoning is written out at `TX_SWTCH_UPLINK` -- and neither was ever
    // wired into this service. A mechanism nobody calls is not a mechanism.
    let override_ok = device
        .allow_destination_override(
            admin,
            // The switch element id, which is what this parameter is despite its
            // name -- `set_promiscuous` and `map_receive_queues` beside it take the
            // same value for the same field.
            vsi,
            admin_device + i40e::VSI_BUFFER_OFFSET,
            &mut vsi_buffer,
            SPINS,
        )
        .is_ok();
    progress.override_ok = override_ok;
    device.report_completions(queue, X722_QUEUES);

    progress.stage = 10;
    if !device.enable_receive_queue(queue, X722_POSTED, SPINS) {
        return None;
    }
    progress.stage = 11;
    device.arm_receive_queue(queue, X722_POSTED);

    // And the transmit side: its context in the same page, then the queue.
    let transmit_device = map_window(x722_slot(nth, grant::WINDOW), x722_slot(nth, grant::TX))?;
    progress.stage = 12;
    let transmit_at = i40e::context_location(0, memory.tx_object_size, queue);
    i40e::write_page_descriptor(
        &mut hmc,
        transmit_at.page,
        backing_device + u64::from(transmit_at.page) * 4096,
    );
    let mut transmit_backing = X722Memory {
        at: x722_hmc_at(nth) + 4096 + u64::from(transmit_at.page) * 4096,
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
            at: x722_tx_at(nth),
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

/// One X722 port the bond can select, and everything needed to drive it.
///
/// **`take_x722` built these one at a time and threw all but the queues
/// away** -- which was right while one port carried frames. RFC 0076 step 2
/// needs both, so each member keeps what its own bring-up produced: the
/// registers it is reached through, the admin ring a link poll goes down, and
/// where its receive walk had got to.
struct X722Member {
    device: bhaskix_i40e::Device<X722Registers>,
    queues: X722Queues,
    /// Its admin ring, for asking firmware about its link.
    ///
    /// **A member keeps its own.** `Get Link Status` is a command, not a
    /// register read, so a bond that polls two links needs two rings to poll
    /// down -- and they must be the rings each port's admin queues were
    /// enabled with, not a shared one.
    admin: X722Memory,
    /// Which receive descriptor this program will look at next. **Per member**,
    /// because two rings do not advance together.
    next: u32,
    /// What its link was, last time it was asked.
    up: bool,
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
fn carry_x722(mut members: [Option<X722Member>; X722_MEMBERS], facts: [X722; X722_MEMBERS]) -> ! {
    use bhaskix_i40e as i40e;
    const SPINS: u32 = 2_000_000;
    /// Announcements sent in one burst, on start and after each failover.
    const PROBES: u32 = 8;
    /// Passes to wait before putting a downed link back up.
    ///
    /// Long enough that the report's patience window sees the bond on the
    /// backup and traffic crossing there; short enough that the port is up
    /// again well before the boot ends.
    const RESTORE_AFTER: u32 = 20_000;
    /// Passes between link polls.
    ///
    /// **A link poll is an admin-queue round trip**, not a register read as it
    /// is for virtio -- `Get Link Status` posts a descriptor and waits for
    /// firmware. Doing that every pass would spend the loop on it, so it is
    /// counted out. Small enough that a failover is noticed in well under a
    /// second at this loop's rate, large enough that the cost disappears.
    const LINK_EVERY: u32 = 512;

    for member in members.iter_mut().flatten() {
        member
            .device
            .attach_transmit_ring(i40e::TRANSMIT_DESCRIPTORS);
    }

    let back_mapped = attach(BACK, BACK_AT, 1);
    if !attach(RING, RING_AT, 1) {
        loop {
            call(syscall::YIELD, 0, 0, [0; 4]);
        }
    }

    // **The bond's address is its first member's**, RFC 0074's rule, and the
    // kernel has already told `bin/ipd` that same address. So the *data* this
    // sends carries port 0's address whichever port carries it, which is what
    // makes a failover invisible to the far end.
    //
    // **Control frames are the exception, and were not.** An LACPDU is not
    // traffic on the bond -- it is a link talking about itself -- and 802.1AX
    // gives its source as the individual address of the port it leaves by.
    // Every one of them left under port 0's address until 2026-09-10, four
    // links claiming one address on four ports of one channel-group. The
    // members' own addresses go on the report at `ring::MEMBER_ADDRESSES` so
    // `bin/ipd` can put each link's own address on each link's PDU.
    let (state, firmware) = facts[0].words();
    let bond_address = facts[0].address();
    let address = facts[0].mac;
    let second = facts[X722_MEMBERS - 1].pair();

    let mut active = members.iter().position(Option::is_some).unwrap_or(0);
    let mut handed = 0u64;
    let mut sent = 0u64;
    let mut seen = 0u64;
    let mut failovers = 0u64;
    // **Frames handed across since the failover, counted by the side that knows
    // when it happened.**
    //
    // The kernel takes its baseline when *its* window opens, and the failover
    // can happen well before that -- during the wait for a first frame -- so
    // anything the new member carried in between landed in the baseline and was
    // invisible. A boot could then say "nothing has crossed since" about a
    // member that had been carrying for a minute. This is the same quantity,
    // measured from the instant that actually matters.
    let mut carried_since = 0u64;
    // Frames that arrived on a member that is not carrying traffic.
    let mut off_member = 0u64;
    // Whether they are handed up as well as counted -- see the virtio bond.
    let lacp_bond = bond_is_lacp();
    let mut idle = 0u32;
    let mut since_link = 0u32;
    // **Announcements this bond sends of its own** -- RFC 0076 step 3.
    //
    // Bounded, because a driver that filled a segment with its own broadcasts
    // would be a worse citizen than one that says little; reset on a failover,
    // because that is exactly when the switch's idea of where this address
    // lives has become wrong.
    let mut probes = 0u32;
    // **The failover test, once, and only when asked.** Nothing here takes a
    // link down unless the boot asked for it, because this is somebody's
    // cluster node and a port that goes dark for no reason is a fault report.
    let mut downed: Option<usize> = None;
    let mut since_down = 0u32;

    let publish = |handed: u64, sent: u64, seen: u64| {
        no_virtio_report_with(state, firmware, bond_address, handed, sent, seen, second);
    };

    loop {
        // **What each member's link is doing.** Counted out rather than asked
        // every pass, for the reason `LINK_EVERY` gives.
        since_link = since_link.saturating_add(1);
        if since_link >= LINK_EVERY {
            since_link = 0;
            for member in members.iter_mut().flatten() {
                if let Ok(link) = member.device.link_status(&mut member.admin, SPINS) {
                    member.up = link.up();
                }
            }
        }

        // Selection, by the same rule the virtio bond uses.
        //
        // **Every member, not the first two.** This was a two-element array
        // written out by index while a bond was two ports, and raising
        // `X722_MEMBERS` to four left it behind: members 2 and 3 were polled
        // above and then never consulted, so `select` could not choose them
        // and the report's link bitmap read zero for both. The first four-port
        // boot printed `link up on ports 0, 1 only` and it was read as a
        // finding about the hardware -- the BMC said all four were LinkUp at
        // 1 Gb/s at the same moment. The wrong number was this array's length.
        let mut up = [false; X722_MEMBERS];
        for (slot, member) in up.iter_mut().zip(members.iter()) {
            *slot = member.as_ref().is_some_and(|member| member.up);
        }
        let chosen = select(active, &up);
        if chosen != active {
            active = chosen;
            failovers += 1;
            // **Announce on the member that has taken over.** Until this
            // existed the X722 bond failed over into silence and the report
            // could say only that nothing had crossed -- which reads like a
            // switch refusing a moved address and was in fact a driver that
            // sent nothing. RFC 0074 named the need; this is it, on the side
            // that had been forwarding `bin/ipd`'s frames and nothing else.
            probes = 0;
        }

        // **Every member's ring is walked, and only the active one's frames
        // cross.** A member that is not carrying traffic still receives -- the
        // wire does not know which one this program has selected -- and
        // delivering those would duplicate what the active member already
        // handed across. They are dropped and counted, which is how the report
        // can say a backup was live without claiming its frames arrived twice.
        for (index, member) in members.iter_mut().enumerate() {
            let Some(member) = member else {
                continue;
            };
            let Some(completion) = i40e::completed_descriptor(&member.queues.ring, member.next)
            else {
                continue;
            };
            idle = 0;
            let length = completion.length as usize;
            let buffer = member.queues.buffers.at + u64::from(member.next) * u64::from(X722_BUFFER);
            if index == active {
                seen += 1;
                if downed.is_some() {
                    carried_since += 1;
                }
            } else {
                off_member += 1;
            }
            // **Whose frames go up** -- as the virtio bond above, and for the
            // same reason. An aggregation that dropped its backup's frames
            // would never hear that link's partner, and the machine speaking
            // for it could not aggregate.
            if length > 0 && (index == active || lacp_bond) {
                // SAFETY: a buffer this program mapped and the device has
                // finished with -- the descriptor's write-back is what says so
                // -- and the ring to `bin/ipd`, mapped writable above.
                if unsafe { hand_to_ipd(buffer, length, Some(index as u8)) } {
                    handed += 1;
                }
            }
            // Back to the device, and the tail after it: a descriptor taken and
            // not given back is a ring that works once, which this file has
            // recorded discovering twice. **Both members are refilled**, the
            // backup included -- a ring left empty is a member that cannot take
            // over.
            i40e::post_receive_descriptor(
                &mut member.queues.ring,
                member.next,
                member.queues.buffers_device + u64::from(member.next) * u64::from(X722_BUFFER),
            );
            member.next = (member.next + 1) % member.queues.posted;
            let (queue, next) = (member.queues.queue, member.next);
            member.device.arm_receive_queue(queue, next);
            publish(handed, sent, seen);
        }

        // **This bond's own frame, out of the member that carries.** One per
        // pass and only while the burst is unfinished, so that a wire nobody
        // else speaks on still shows whether this port can transmit -- and so
        // that a failover has something to be measured by.
        if probes < PROBES
            && let Some(member) = members[active].as_mut()
        {
            // SAFETY: the transmit buffer inside this member's rings object,
            // which this program mapped writable. No virtio header: an X722
            // takes the frame as it stands.
            let length = unsafe { fill_announcement(member.queues.transmit.at + 2048, 0, address) };
            let at = member.queues.transmit_device + 2048;
            if let Some(slot) =
                member
                    .device
                    .post_frame(&mut member.queues.transmit, at, length as u16, false)
            {
                let queue = member.queues.transmit_queue;
                let tail = member.device.transmit_tail();
                member.device.transmit_doorbell(queue, tail);
                for _ in 0..SPINS {
                    if member.device.frame_completed(&member.queues.transmit, slot) {
                        break;
                    }
                    core::hint::spin_loop();
                }
                probes += 1;
                sent += 1;
                publish(handed, sent, seen);
            }
        }

        // **What `bin/ipd` built** -- out of the member it named, or out of the
        // member that carries where it named none.
        //
        // 802.3ad runs a state machine per link, and each machine's PDU carries
        // the port id of the link it speaks for. So an LACPDU leaves by the
        // member whose machine built it and no other, and everything else
        // leaves by the one carrying traffic. Which member is `bin/ipd`'s mark,
        // not this program's reading of the frame -- see `chan::marked`.
        if back_mapped && let Some(carrier) = members[active].as_mut() {
            // SAFETY: the return ring is mapped, and the packet buffer is the
            // page this program mapped for this member's transmit ring. No
            // header: an X722 takes the frame as it stands.
            let taken = unsafe { take_from_ipd_into(carrier.queues.transmit.at + 2048, 0) };
            if let Some((length, for_member, uplink)) = taken {
                idle = 0;
                // The frame landed in the active member's buffer, because that
                // is the buffer `bin/ipd`'s ring writes into. A frame marked
                // for a different member is copied into that member's own --
                // a member owns its rings, and a descriptor may only name
                // memory its own device reaches through its own window.
                let source = carrier.queues.transmit.at + 2048;
                let leaves_by = match for_member {
                    Some(index) if members.get(index as usize).is_some_and(Option::is_some) => {
                        index as usize
                    }
                    // Named a member this program does not hold, or named none.
                    _ => active,
                };
                if leaves_by != active {
                    // SAFETY: two transmit buffers this program mapped, each a
                    // page it holds, and `length` is bounded by
                    // `take_from_ipd_into`.
                    unsafe {
                        let into = members[leaves_by]
                            .as_ref()
                            .expect("held")
                            .queues
                            .transmit
                            .at;
                        for offset in 0..length as u64 {
                            let byte = core::ptr::read_volatile((source + offset) as *const u8);
                            core::ptr::write_volatile((into + 2048 + offset) as *mut u8, byte);
                        }
                    }
                }
                if let Some(member) = members[leaves_by].as_mut() {
                    let at = member.queues.transmit_device + 2048;
                    // **The switch control tag, where `bin/ipd` asked for it.**
                    // Without it the descriptor is *"routed according to
                    // hardware filters"*, and this device's internal switch
                    // consumes a frame addressed to a reserved group address
                    // rather than sending it -- which is where every LACPDU this
                    // system built went until 2026-09-09: posted, completed, and
                    // never counted out of the MAC.
                    if let Some(slot) = member.device.post_frame(
                        &mut member.queues.transmit,
                        at,
                        length as u16,
                        uplink,
                    ) {
                        let queue = member.queues.transmit_queue;
                        let tail = member.device.transmit_tail();
                        member.device.transmit_doorbell(queue, tail);
                        for _ in 0..SPINS {
                            if member.device.frame_completed(&member.queues.transmit, slot) {
                                break;
                            }
                            core::hint::spin_loop();
                        }
                        sent += 1;
                    }
                }
                publish(handed, sent, seen);
            }
        }

        // **Take the active member's link down, if the boot asked and the bond
        // has shown it works.** `handed > 0` is the condition that matters: a
        // failover from a member that was never carrying anything proves
        // nothing, and the report could not tell the difference afterwards.
        if downed.is_none()
            && handed > 0
            && failover_requested()
            && let Some(member) = members[active].as_mut()
            && member
                .device
                .set_link(&mut member.admin, false, SPINS)
                .is_ok()
        {
            // Believed at once rather than waited for. The next link poll would
            // find it anyway; this makes the failover happen in the pass that
            // caused it, so a boot report that has to catch both halves has a
            // chance of catching them.
            member.up = false;
            downed = Some(active);
            since_down = 0;
        }

        // **And put it back.** RFC 0076's testing plan promises the machine is
        // returned as found, and a port left dark is the one way this change
        // could fail that promise. `Restart AN` touches no NVM, so a boot that
        // died between the two would still leave the port up at the next power
        // cycle -- but not leaving it to that is the point.
        if let Some(index) = downed {
            since_down = since_down.saturating_add(1);
            if since_down == RESTORE_AFTER
                && let Some(member) = members[index].as_mut()
            {
                let _ = member.device.set_link(&mut member.admin, true, SPINS);
            }
        }

        // What the bond is, for the kernel to print.
        // One bit per member, from the same array `select` reads -- so the
        // report cannot disagree with the choice.
        let links = up
            .iter()
            .enumerate()
            .fold(0u64, |bits, (index, live)| bits | u64::from(*live) << index);
        let count = members.iter().flatten().count() as u64;
        x722_bond_report(count, active as u64, links, failovers, off_member);
        carried_since_report(carried_since);

        // **What the device itself says it put out.** Every other number in this
        // report is a tally this program keeps; this one is the VSI's own
        // multicast transmit counter, and an LACPDU is multicast -- so it is the
        // only figure that distinguishes a frame that reached the wire from one
        // the device swallowed. Summed across members, because the question is
        // whether *any* left.
        let out = members
            .iter()
            .zip(facts.iter())
            .filter_map(|(member, fact)| {
                member
                    .as_ref()
                    .map(|m| m.device.vsi_transmitted(fact.vsi).multicast)
            })
            .sum();
        // **And the same frames one boundary further out.** `GLPRT_MPTCL` is
        // indexed by physical port, which each member's own device answers for
        // itself -- not by VSI, and not by the member's position in this array,
        // which are three different numbers that happen to agree on a
        // single-port card.
        let on_the_wire = members
            .iter()
            .flatten()
            .map(|m| m.device.port_transmitted(m.device.port_number()).multicast)
            .sum();
        x722_transmit_report(out, on_the_wire, facts.iter().any(|fact| fact.override_ok));

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
/// The same, with what the frames have done so far and what the second port is.
///
/// **`second` is that port's state word and its station address**, RFC 0076
/// step 1 -- a pair rather than two more arguments, because this function
/// already takes six positional numbers and a caller passing eight is a caller
/// that will pass two of them in the wrong order.
fn no_virtio_report_with(
    state: u64,
    firmware: u64,
    address: u64,
    handed: u64,
    sent: u64,
    seen: u64,
    second: (u64, u64),
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
    // **The second port, words 24 and 25.** Its own state word and its own
    // station address -- and the address is the half that matters, because two
    // ports reporting the same one would be one device counted twice, which is
    // exactly what step 1's gate exists to rule out.
    words[24] = second.0;
    words[25] = second.1;
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
    /// Whether this port's VSI was allowed to fix a transmit packet's
    /// destination -- see `Progress::override_ok`. Without it a switch
    /// control tag is not permitted, so an uplink-tagged frame behaves
    /// exactly like an untagged one and nothing says so.
    override_ok: bool,
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
    /// How many backing pages this port's HMC layout wants, and which page its
    /// receive context falls in -- the two numbers `grant::HMC_PAGES` is
    /// checked against, reported so a refusal says which one it was.
    layout: (u8, u8),
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
            | u64::from(self.stage) << 40
            | u64::from(self.layout.0) << 48
            | u64::from(self.layout.1) << 56;
        (
            flags | u64::from(self.link_speed) << 8 | u64::from(self.switch_elements) << 16,
            u64::from(self.firmware.0) | u64::from(self.firmware.1) << 16,
        )
    }

    /// What a *second* port contributes to the report: its state and its
    /// address.
    ///
    /// **Not its firmware**, which is the card's rather than the port's -- all
    /// four functions of an X722 are one device and answer the same version.
    /// The address is what differs, and what says two ports were driven rather
    /// than one driven twice.
    fn pair(self) -> (u64, u64) {
        (self.words().0, self.address())
    }
}

/// Takes the X722 the kernel delegated, if it delegated one.
///
/// **The absence path is the one every lane runs**, and it is the gate for this
/// step: a machine with no such NIC leaves the slots empty, the first attach
/// fails, and this answers `delegated: false` without touching a register. Every
/// QEMU lane checks that, because none of them has an X722 and none ever will.
fn take_x722(nth: u64) -> (X722, Option<X722Member>) {
    use bhaskix_i40e::grant;
    let mut found = X722::default();
    let mut carrying = None;

    // The register pages first, because they are what makes the rest reachable
    // and because their absence is the cheapest thing to discover. Each is
    // mapped at its own offset from `x722_at(nth)`, so every register offset in the
    // crate works against that base unchanged.
    for (index, page) in bhaskix_i40e::REGISTER_PAGES.iter().enumerate() {
        if !attach(
            x722_slot(nth, grant::PAGES) + index as u64,
            x722_at(nth) + page,
            1,
        ) {
            return (found, None);
        }
    }
    if !attach(x722_slot(nth, grant::MEMORY), x722_memory_at(nth), 1) {
        return (found, None);
    }
    // Where the device will look for its rings. Without a window there is no
    // such number, and a device that cannot be aimed cannot be driven -- the
    // refusal working, exactly as it does for the virtio ports above.
    let (mapped, admin_device) = call(
        syscall::INVOKE,
        x722_slot(nth, grant::WINDOW),
        method::MAP,
        [x722_slot(nth, grant::MEMORY), 0, 0, 0],
    );
    if mapped != status::OK {
        return (found, None);
    }
    found.delegated = true;

    /// Long enough for firmware to answer, bounded so a device that never does
    /// cannot hang a boot. The kernel used the same number for the same reason.
    const SPINS: u32 = 2_000_000;

    let mut device = bhaskix_i40e::Device::new(X722Registers { at: x722_at(nth) });
    let mut admin = X722Memory {
        at: x722_memory_at(nth),
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
        at: x722_memory_at(nth) + bhaskix_i40e::SWITCH_BUFFER_OFFSET,
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
        at: x722_memory_at(nth) + bhaskix_i40e::VSI_BUFFER_OFFSET,
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
    if !attach(x722_slot(nth, grant::HMC), x722_hmc_at(nth), 1)
        || !attach(x722_slot(nth, grant::RINGS), x722_rings_at(nth), 1)
        || !attach(x722_slot(nth, grant::TX), x722_tx_at(nth), 1)
    {
        return (found, None);
    }
    found.stage = 4;
    let mut progress = Progress {
        stage: found.stage,
        layout: (0, 0),
        override_ok: false,
    };
    let brought_up = bring_up_x722(
        &mut device,
        &mut admin,
        admin_device,
        seid,
        parameters.number,
        &mut progress,
        nth,
    );
    // **Whether it came up or not**, because the numbers a refusal leaves
    // behind are the whole reason they are collected.
    found.stage = progress.stage;
    found.layout = progress.layout;
    found.override_ok = progress.override_ok;
    if let Some(queues) = brought_up {
        found.carrying = true;
        // **Asked of firmware, not read out of `PRTPM_SAL`.** RFC 0076 step 1:
        // that register pair holds the *WoL* address, which equals the LAN one
        // on this card's first port and is marked invalid on its second -- so
        // the boot that finally brought port 1's queues up still reported
        // `000000000000` for it. 38.17.3's table names `Manage MAC Address
        // Read` as where a LAN address comes from.
        //
        // The port's own address is the fallback, because several functions of
        // one port share it and a shared address is better than none; the
        // register is the last resort, and no address at all is reported as
        // zeros rather than invented.
        let mut mac_buffer = X722Memory {
            at: x722_memory_at(nth) + bhaskix_i40e::MAC_BUFFER_OFFSET,
            bytes: bhaskix_i40e::MAC_BUFFER_BYTES as usize,
        };
        found.mac = device
            .mac_addresses(
                &mut admin,
                admin_device + bhaskix_i40e::MAC_BUFFER_OFFSET,
                &mut mac_buffer,
                SPINS,
            )
            .ok()
            .and_then(|found| found.lan.or(found.port))
            .or_else(|| device.mac_address(device.port_number()))
            .unwrap_or([0; 6]);
        // **The whole member, not just its queues.** RFC 0076 step 2: a bond
        // selects between two of these every pass, so what the bring-up
        // produced has to survive it -- the device it was reached through and
        // the admin ring a link poll goes down, as much as the queues.
        found.link_up = device
            .link_status(&mut admin, SPINS)
            .map_or(found.link_up, |link| link.up());
        carrying = Some(X722Member {
            device,
            queues,
            admin,
            next: 0,
            up: found.link_up,
        });
    }
    (found, carrying)
}

/// Publishes what the **device** says it transmitted -- words 27 and 28.
///
/// **The only numbers here that are not a driver's own tally.** Everything else
/// counts frames handed over: a descriptor posted, a write-back seen, a loop
/// iteration. `GLV_MPTCL` counts multicast packets the VSI put out, and an
/// LACPDU is multicast, so it can tell a frame the VSI let go of from one the
/// device swallowed. Without it "44 LACPDUs sent" and "the switch received
/// none" were both true and neither was informative.
///
/// **And one boundary was not enough.** The VSI is not the wire: a frame
/// crosses from the VSI to the device's internal switch, and from that switch
/// to the MAC. The SR550 reported 44 sent against 38 out of the VSI on
/// 2026-09-10, and 44 against 34 the boot before, and nothing here could say
/// whether those 38 reached the MAC -- so every statement about what the switch
/// received rested on a boundary one layer short of the wire. `GLPRT_MPTCL`
/// counts what the **port** put out, and the pair is the instrument.
///
/// Word 27: the VSI's multicast in the low half; bit 32 whether
/// `allow_destination_override` succeeded, because a switch control tag is
/// *"not permitted"* without it; **bit 33 that the port's count behind it was
/// measured at all**, since zero is what both a port that sent nothing and a
/// word nobody wrote look like, and this file has three times read the second
/// as the first. Word 28: the port's multicast.
fn x722_transmit_report(multicast: u64, port_multicast: u64, override_ok: bool) {
    let at = RINGS_AT + ring::REPORT + 27 * 8;
    // SAFETY: the report page this program mapped writable, past the failover
    // count and far short of the members' addresses at 32 and the kernel's own
    // words at 40 and 41. The port's count goes first and the word that says it
    // is there goes second, so a reader that catches this half-written finds
    // the bit clear rather than a number nobody wrote.
    unsafe {
        core::ptr::write_volatile((at + 8) as *mut u64, port_multicast);
        core::ptr::write_volatile(
            at as *mut u64,
            multicast | u64::from(override_ok) << 32 | 1 << 33,
        );
    }
}

/// Publishes each member's own station address -- [`ring::MEMBER_ADDRESSES`].
///
/// **Called once every member is known**, not after each one, and the sentinel
/// is written last. Those two together are what let the kernel read this block
/// and believe it: a member whose address has not been asked for yet is
/// indistinguishable from one that has none, and the whole point of the block
/// is to tell `bin/ipd` which link speaks under which address.
fn member_address_report(addresses: [u64; ring::MEMBER_ADDRESS_COUNT]) {
    let at = RINGS_AT + ring::MEMBER_ADDRESSES;
    // SAFETY: the report page this program mapped writable, past the report
    // itself and short of the kernel's own words at 40 and 41.
    unsafe {
        for (index, address) in addresses.iter().enumerate() {
            core::ptr::write_volatile((at + (index as u64 + 1) * 8) as *mut u64, *address);
        }
        core::ptr::write_volatile(at as *mut u64, ring::MEMBER_ADDRESSES_WRITTEN);
    }
}

/// A virtio network device's station address, as one word.
///
/// The same six bytes the bring-up reads for its own use, in the shape the
/// report carries an address in -- most significant octet first, so a MAC
/// prints as it is written.
///
/// # Safety
///
/// `device_at` must be a device-configuration window this program has mapped:
/// a network device's MAC is its first six bytes.
unsafe fn station_address(device_at: u64) -> u64 {
    let mut value = 0u64;
    for octet in 0..6 {
        // SAFETY: delegated to the caller.
        value = (value << 8) | u64::from(unsafe { read8(device_at + octet) });
    }
    value
}

/// Publishes how much the bond has carried since it failed over -- word 26.
fn carried_since_report(frames: u64) {
    let at = RINGS_AT + ring::REPORT + 26 * 8;
    // SAFETY: the report page this program mapped writable, one word past the
    // bond's five and far short of the failover request.
    unsafe { core::ptr::write_volatile(at as *mut u64, frames) };
}

/// Whether the boot asked for a failover -- [`ring::FAILOVER_REQUEST`].
fn failover_requested() -> bool {
    // SAFETY: the report page this program mapped writable, at a word outside
    // the report itself. The kernel writes it; this reads it.
    unsafe { core::ptr::read_volatile((RINGS_AT + ring::FAILOVER_REQUEST) as *const u64) != 0 }
}

/// Whether the bond is 802.3ad -- [`ring::BOND_IS_LACP`].
fn bond_is_lacp() -> bool {
    // SAFETY: as `failover_requested`, one word further on.
    unsafe { core::ptr::read_volatile((RINGS_AT + ring::BOND_IS_LACP) as *const u64) != 0 }
}

/// The bond's words, for a bond whose members are X722 ports.
///
/// **The same five slots [`bond_report`] writes**, so `report_bond` in the
/// kernel prints either bond without knowing which driver produced it. What
/// differs is only where the numbers come from: that one reads them off virtio
/// `Port`s, and this is handed them.
fn x722_bond_report(members: u64, active: u64, links: u64, failovers: u64, off_member: u64) {
    let at = RINGS_AT + ring::REPORT;
    let words = [members, active, links, failovers, off_member];
    // SAFETY: the report page this program mapped writable, at the five words
    // that follow the seventeen `report` writes -- the same ones `bond_report`
    // writes, and not the marker.
    unsafe {
        for (index, word) in words.iter().enumerate() {
            core::ptr::write_volatile((at + (17 + index as u64) * 8) as *mut u64, *word);
        }
    }
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
