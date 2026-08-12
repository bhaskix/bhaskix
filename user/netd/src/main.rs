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

/// Where this program maps what it holds.
const COMMON_AT: u64 = 0x2000_0000;
const NOTIFY_AT: u64 = 0x2001_0000;
const DEVICE_AT: u64 = 0x2002_0000;
const RINGS_AT: u64 = 0x2010_0000;
/// Where the ring to `bin/ipd` is mapped. Not the device's rings: those are
/// memory a *device* reads, this is memory another *domain* reads, and the two
/// are deliberately different objects with different owners.
const RING_AT: u64 = 0x2020_0000;
/// Where the return ring from `bin/ipd` is mapped.
const BACK_AT: u64 = 0x2030_0000;

/// Bytes in the ring to `bin/ipd`, matching what the kernel granted.
const RING_BYTES: usize = 16 * 4096;

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
unsafe fn kick(index: u16) {
    // SAFETY: the common window is mapped; selecting a queue and reading its
    // notify offset changes nothing.
    unsafe {
        write16(COMMON_AT + common::QUEUE_SELECT, index);
        let offset = u64::from(read16(COMMON_AT + common::QUEUE_NOTIFY_OFF));
        // Times four: the notification multiplier this transport reports, the
        // same constant `user/blkd` uses and for the same device model.
        write16(NOTIFY_AT + offset * 4, index);
    }
}

/// The largest frame the **device** has said it wrote, virtio header included.
///
/// `received` above is the *first* frame's length and is written once, which
/// read like a running figure and is not one. A high-water mark is what says
/// whether a large frame ever arrived at all.
static WIDEST: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

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
    index: u16,
    descriptors: u64,
    available: u64,
    used: u64,
    rings_at_device: u64,
) -> Virtqueue<Volatile> {
    // SAFETY: the caller guarantees the window and the offsets.
    let vectored = unsafe {
        write16(COMMON_AT + common::QUEUE_SELECT, index);
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
        write16(COMMON_AT + common::QUEUE_SIZE, QUEUE_ENTRIES);
        // Which MSI-X entry this queue uses is this driver's to say, in a
        // register it holds. What that entry *contains* is the kernel's, and
        // this program has no way to write it. Both queues share entry zero,
        // which is one interrupt for two directions -- correct, because the
        // driver looks at both used rings when it wakes.
        write16(COMMON_AT + common::QUEUE_MSIX_VECTOR, 0);
        let taken = read16(COMMON_AT + common::QUEUE_MSIX_VECTOR) == 0;
        write64(
            COMMON_AT + common::QUEUE_DESC,
            rings_at_device + descriptors,
        );
        write64(
            COMMON_AT + common::QUEUE_DRIVER,
            rings_at_device + available,
        );
        write64(COMMON_AT + common::QUEUE_DEVICE, rings_at_device + used);
        write16(COMMON_AT + common::QUEUE_ENABLE, 1);
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
                at: (RINGS_AT + descriptors) as usize,
                device: rings_at_device + descriptors,
            },
            virtqueue::Ring {
                at: (RINGS_AT + available) as usize,
                device: rings_at_device + available,
            },
            virtqueue::Ring {
                at: (RINGS_AT + used) as usize,
                device: rings_at_device + used,
            },
            QUEUE_ENTRIES,
        )
    }
}

/// Brings the device up and returns its two queues.
///
/// `None` if the device refused the feature set, which is the one failure worth
/// distinguishing: going on from there configures queues nobody will service.
fn bring_up(rings_at_device: u64) -> Option<(Virtqueue<Volatile>, Virtqueue<Volatile>)> {
    VECTORED.store(true, core::sync::atomic::Ordering::Relaxed);

    // SAFETY: `COMMON_AT` is the common configuration window this program
    // mapped writable, and every offset below is inside it. The values and
    // their order are the specification's.
    let mac_offered = unsafe {
        write8(COMMON_AT + common::DEVICE_STATUS, 0);
        write8(
            COMMON_AT + common::DEVICE_STATUS,
            device_status::ACKNOWLEDGE,
        );
        write8(
            COMMON_AT + common::DEVICE_STATUS,
            device_status::ACKNOWLEDGE | device_status::DRIVER,
        );

        // Asked rather than assumed, unlike the block driver which writes what
        // it wants without looking. A device that is not offering `MAC` and is
        // told it was negotiated is within its rights to clear `FEATURES_OK`,
        // and the whole handshake then fails for a field this driver only
        // wanted in order to print it.
        write32(COMMON_AT + common::DEVICE_FEATURE_SELECT, 0);
        let low = read32(COMMON_AT + common::DEVICE_FEATURE);
        let mac = low & feature::MAC;

        write32(COMMON_AT + common::DRIVER_FEATURE_SELECT, 1);
        write32(
            COMMON_AT + common::DRIVER_FEATURE,
            feature::VERSION_1_AND_ACCESS_PLATFORM,
        );
        write32(COMMON_AT + common::DRIVER_FEATURE_SELECT, 0);
        write32(COMMON_AT + common::DRIVER_FEATURE, mac);

        write8(
            COMMON_AT + common::DEVICE_STATUS,
            device_status::ACKNOWLEDGE | device_status::DRIVER | device_status::FEATURES_OK,
        );
        // Read back: a device that will not accept the feature set clears this
        // bit, and a driver that did not look would build queues for a device
        // that had already given up on it.
        if read8(COMMON_AT + common::DEVICE_STATUS) & device_status::FEATURES_OK == 0 {
            return None;
        }

        // Config-change interrupts go to the same entry as the queues. A
        // network device signals link state this way, and an entry left
        // unassigned means the device has nowhere to send one.
        write16(COMMON_AT + common::CONFIG_MSIX_VECTOR, 0);

        // Two queues at least, or there is no transmit queue to put a frame on.
        // Checked rather than assumed because it is one read, and because a
        // device offering one queue would otherwise be configured as though it
        // had two and fail somewhere less obvious.
        if read16(COMMON_AT + common::NUM_QUEUES) < 2 {
            return None;
        }
        mac != 0
    };
    let _ = mac_offered;

    // SAFETY: the window is mapped and the offsets are distinct pages of the
    // rings object this program holds.
    let receive = unsafe {
        configure(
            queue::RECEIVE,
            ring::RX_DESCRIPTORS,
            ring::RX_AVAILABLE,
            ring::RX_USED,
            rings_at_device,
        )
    };
    // SAFETY: as above, with the transmit queue's own three pages.
    let transmit = unsafe {
        configure(
            queue::TRANSMIT,
            ring::TX_DESCRIPTORS,
            ring::TX_AVAILABLE,
            ring::TX_USED,
            rings_at_device,
        )
    };

    Some((receive, transmit))
}

/// Gives the device every receive buffer this program owns.
///
/// **Before `DRIVER_OK`, and that ordering is the whole of this function's
/// reason to exist.** A network device delivers unbidden: the answer to the
/// frame sent below can arrive before the next instruction runs, and a receive
/// queue with nothing posted drops it without saying so.
fn post_receive_buffers(receive: &mut Virtqueue<Volatile>, rings_at_device: u64) {
    for index in 0..QUEUE_ENTRIES {
        let offset = ring::RX_BUFFERS + u64::from(index) * ring::RX_BUFFER;
        receive.describe(
            index,
            rings_at_device + offset,
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
/// The rings must be mapped writable at [`RINGS_AT`].
unsafe fn fill_transmit(mac: [u8; 6]) -> u64 {
    const FRAME: u64 = 42;
    let at = RINGS_AT + ring::TX_BUFFER;

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

/// Waits for something to complete on `queue`, returning its used-ring length.
///
/// Bounded, and honest about being a spin where there is no vector. A wait with
/// no bound would hang the machine on a device that never answers, which is a
/// worse failure than reporting that nothing came.
fn await_completion(queue: &mut Virtqueue<Volatile>) -> Option<(u16, u32)> {
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
        let _ = call(syscall::INVOKE, HANDLER, method::ACK, [0; 4]);
        if status == self::status::OK {
            return queue.completed_with_length();
        }
    }
    None
}

/// Copies `length` bytes from `source` into the ring at free-running `head`.
///
/// Returns the head the copy ended at, or `None` if the ring has no room.
///
/// The wrap is `abi::ring`'s arithmetic and not this program's. That module was
/// written for RFC 0009 step 5 and had **no caller until now** — which is worth
/// saying, because the alternative here was a second ring format written in a
/// hurry, and two ring formats disagree the first time either is edited.
///
/// # Safety
///
/// The ring must be mapped writable at [`RING_AT`], and `source` must be
/// readable for `length` bytes.
unsafe fn ring_copy_in(
    layout: chan::Layout,
    head: u64,
    tail: u64,
    source: *const u8,
    length: usize,
) -> Option<u64> {
    let cursor = chan::Cursor::new(layout, head, tail)?;
    if cursor.writable() < length {
        return None;
    }
    let (first, second) = chan::write_runs(layout, cursor, length);
    // SAFETY: both runs are offsets `abi::ring` computed inside the region this
    // program mapped, `source` is readable for `length` by the caller's
    // obligation, and the two runs do not overlap -- they are the two halves a
    // wrap divides one transfer into.
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
    Some(head + length as u64)
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

    let prefix = (length as u32).to_le_bytes();
    // SAFETY: the ring is mapped and `prefix` is four readable bytes.
    let Some(after_prefix) = (unsafe { ring_copy_in(layout, head, tail, prefix.as_ptr(), 4) })
    else {
        return false;
    };
    // SAFETY: as above; the frame is in a receive buffer this program mapped.
    let Some(after_frame) =
        (unsafe { ring_copy_in(layout, after_prefix, tail, frame_at as *const u8, length) })
    else {
        return false;
    };

    // The bytes, then a fence, then the index that makes them visible. The
    // reader is another domain on another CPU and takes no lock, so this fence
    // is the whole of what orders the two -- the same reason `Virtqueue::publish`
    // has one.
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    // SAFETY: the ring's header, which only this program writes.
    unsafe {
        core::ptr::write_volatile(
            (RING_AT + chan::HEAD_OFFSET as u64) as *mut u64,
            after_frame,
        );
    }
    true
}

/// Takes one frame out of the return ring, if `bin/ipd` has put one there.
///
/// Returns its length. The frame is copied straight into the transmit buffer
/// **after** the virtio header, so nothing is copied twice.
///
/// # Safety
///
/// The return ring must be mapped at [`BACK_AT`] and the rings at [`RINGS_AT`].
unsafe fn take_from_ipd() -> Option<usize> {
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

    let mut prefix = [0u8; 4];
    // SAFETY: the ring is mapped and `prefix` is four writable bytes.
    unsafe { ring_copy_out(layout, cursor, prefix.as_mut_ptr(), 4)? };
    let length = u32::from_le_bytes(prefix) as usize;
    // A length the *other side* wrote. Bounded before it is used, and refused
    // rather than clamped: a frame that does not fit a buffer is not a shorter
    // frame, it is a producer this program has stopped believing.
    if length == 0 || length > (ring::RX_BUFFER as usize - VIRTIO_NET_HEADER as usize) {
        return None;
    }
    let after = chan::Cursor::new(layout, head, tail + 4)?;
    if after.readable() < length {
        // The length is published and the bytes are not. Look again later
        // without moving the tail: this is not an error, it is a race the
        // producer will finish losing in a moment.
        return None;
    }

    let into = RINGS_AT + ring::TX_BUFFER + VIRTIO_NET_HEADER;
    // SAFETY: the ring is mapped, and the destination is inside a transmit
    // buffer this program mapped writable, bounded by the check above.
    unsafe {
        // The virtio header this device expects in front of every frame.
        for offset in 0..VIRTIO_NET_HEADER {
            core::ptr::write_volatile((RINGS_AT + ring::TX_BUFFER + offset) as *mut u8, 0);
        }
        ring_copy_out(layout, after, into as *mut u8, length)?;
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        core::ptr::write_volatile(
            (BACK_AT + chan::TAIL_OFFSET as u64) as *mut u64,
            tail + 4 + length as u64,
        );
    }
    Some(length)
}

/// Copies `length` bytes out of a ring at `cursor` into `into`.
///
/// # Safety
///
/// The ring must be mapped at [`BACK_AT`] and `into` writable for `length`.
unsafe fn ring_copy_out(
    layout: chan::Layout,
    cursor: chan::Cursor,
    into: *mut u8,
    length: usize,
) -> Option<()> {
    if cursor.readable() < length {
        return None;
    }
    let (first, second) = chan::read_runs(layout, cursor, length);
    if first.length + second.length != length {
        return None;
    }
    // SAFETY: both runs are offsets `abi::ring` computed inside the region this
    // program mapped, and `into` is writable for `length` by the caller's
    // obligation.
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
    Some(())
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

/// The entry point.
#[unsafe(no_mangle)]
extern "C" fn netd_main() -> ! {
    if !attach(COMMON, COMMON_AT, 1)
        || !attach(NOTIFY, NOTIFY_AT, 1)
        || !attach(DEVICE, DEVICE_AT, 0)
        || !attach(RINGS, RINGS_AT, 1)
    {
        exit()
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

    let Some((mut receive, mut transmit)) = bring_up(rings_at_device) else {
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
    post_receive_buffers(&mut receive, rings_at_device);

    // SAFETY: the common window is mapped and the queues are enabled.
    unsafe {
        write8(
            COMMON_AT + common::DEVICE_STATUS,
            device_status::ACKNOWLEDGE
                | device_status::DRIVER
                | device_status::FEATURES_OK
                | device_status::DRIVER_OK,
        );
        kick(queue::RECEIVE);
    }

    // SAFETY: the rings are mapped writable.
    let length = unsafe { fill_transmit(mac) };
    transmit.describe(0, rings_at_device + ring::TX_BUFFER, length as u32, 0, 0);
    transmit.publish(0);
    // SAFETY: the notify window is mapped and the queue is enabled.
    unsafe { kick(queue::TRANSMIT) };

    let sent = if await_completion(&mut transmit).is_some() {
        length
    } else {
        0
    };

    // What came back, if anything.
    let (received, source, header, first_index) = match await_completion(&mut receive) {
        Some((index, written)) => {
            let buffer = RINGS_AT + ring::RX_BUFFERS + u64::from(index) * ring::RX_BUFFER;
            // The header size, measured rather than assumed. The frame is an
            // answer to this station's own broadcast, so its destination is
            // this device's MAC -- and the offset those six bytes appear at is
            // the size of whatever the device put in front of them.
            let mut header = 0u64;
            for candidate in [VIRTIO_NET_HEADER, 12] {
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
        receive.describe(
            first_index,
            rings_at_device + ring_buffer_of(first_index),
            ring::RX_BUFFER as u32,
            virtqueue::WRITE,
            0,
        );
        receive.publish(first_index);
        // SAFETY: the notify window is mapped and the queue is enabled.
        unsafe { kick(queue::RECEIVE) };
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
        u64::from(receive.seen()),
        handed,
        sent_for_ipd,
        took,
        took_length,
    );
    let mut probes = 0u32;
    let mut outstanding = false;
    let mut idle = 0u32;
    loop {
        // **One transmit outstanding at a time.** A descriptor handed to the
        // device is the device's until it appears in the used ring, and this
        // loop was republishing descriptor zero every pass without waiting --
        // rewriting a descriptor the device had not finished with. The probes
        // survived it because every probe is the same bytes; the first frame
        // that differed, `ipd`'s, was published into a queue already being
        // mishandled and never reached the wire.
        if poll_completion(&mut transmit).is_some() {
            outstanding = false;
        }

        // One probe per pass, and only when the last one is done.
        if probes < 8 && !outstanding {
            transmit.describe(0, rings_at_device + ring::TX_BUFFER, length as u32, 0, 0);
            transmit.publish(0);
            // SAFETY: the notify window is mapped and the queue is enabled.
            unsafe { kick(queue::TRANSMIT) };
            probes += 1;
            outstanding = true;
        }

        // Anything `bin/ipd` has built goes out. One per pass, and the
        // completion collected on a later pass -- this program is pinned, and
        // step 3 established that a spin here trips the bring-up watchdog.
        if back_mapped && !outstanding {
            // SAFETY: both rings are mapped and the transmit buffer is inside
            // the rings object this program holds.
            // **Descriptor zero, and it was descriptor two.** Every frame this
            // program sent for `bin/ipd` reached the wire truncated to exactly
            // 42 bytes -- the probe's length, 54, less the virtio header --
            // however long the frame actually was. The headers were correct
            // because they are the first 42 bytes of a correct frame, so the
            // damage was invisible from this side: the ring said 59 bytes taken
            // and `filter-dump` said 42 on the wire, which is what finally
            // named it. A server cannot answer a datagram whose IP header
            // promises 272 bytes and whose frame carries 28.
            //
            // **Why descriptor two behaved that way is now known**, and it was
            // not descriptor two: this driver never wrote `QUEUE_SIZE`, so the
            // device wrapped the rings at 256 while this side wrapped them at
            // four. Past the fourth request the device was reading available
            // entries nobody had written. Descriptor two would work today.
            // Descriptor zero is kept because it is simpler and `outstanding`
            // already allows one transmit at a time, so there is never a second
            // one to name.
            if let Some(from_ipd) = unsafe { take_from_ipd() } {
                idle = 0;
                // SAFETY: the transmit buffer this program mapped, just filled.
                took = unsafe {
                    let mut value = 0u64;
                    for octet in 0..6u64 {
                        value = (value << 8)
                            | u64::from(read8(
                                RINGS_AT + ring::TX_BUFFER + VIRTIO_NET_HEADER + octet,
                            ));
                    }
                    value
                };
                took_length = from_ipd as u64;
                transmit.describe(
                    0,
                    rings_at_device + ring::TX_BUFFER,
                    (VIRTIO_NET_HEADER + from_ipd as u64) as u32,
                    0,
                    0,
                );
                transmit.publish(0);
                // SAFETY: the notify window is mapped and the queue is enabled.
                unsafe { kick(queue::TRANSMIT) };
                sent_for_ipd += 1;
                outstanding = true;
            }
        }

        idle = idle.saturating_add(1);
        if let Some((index, written)) = poll_completion(&mut receive) {
            idle = 0;
            if u64::from(written) > WIDEST.load(core::sync::atomic::Ordering::Relaxed) {
                WIDEST.store(u64::from(written), core::sync::atomic::Ordering::Relaxed);
            }
            OUTSTANDING.store(
                u64::from(receive.posted().wrapping_sub(receive.seen())),
                core::sync::atomic::Ordering::Relaxed,
            );
            let buffer = RINGS_AT + ring_buffer_of(index) + header;
            let length = u64::from(written).saturating_sub(header) as usize;
            // SAFETY: as above.
            if length > 0 && unsafe { hand_to_ipd(buffer, length) } {
                handed += 1;
            }
            report(
                own,
                sent,
                received,
                source,
                header,
                u64::from(receive.seen()),
                handed,
                sent_for_ipd,
                took,
                took_length,
            );
            receive.describe(
                index,
                rings_at_device + ring_buffer_of(index),
                ring::RX_BUFFER as u32,
                virtqueue::WRITE,
                0,
            );
            receive.publish(index);
            // SAFETY: the notify window is mapped and the queue is enabled.
            unsafe { kick(queue::RECEIVE) };
        }
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
        if idle > 200 && VECTORED.load(core::sync::atomic::Ordering::Relaxed) {
            let _ = call(syscall::INVOKE, SIGNAL, method::WAIT, [0; 4]);
            let _ = call(syscall::INVOKE, HANDLER, method::ACK, [0; 4]);
            idle = 0;
        } else {
            call(syscall::YIELD, 0, 0, [0; 4]);
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
