// SPDX-License-Identifier: Apache-2.0
//! Bringing up an Intel X722, far enough to ask it what it is.
//!
//! RFC 0072 step 3. This resets the function and gives it an admin queue,
//! which is the handshake every later question goes through: an i40e-class
//! device answers nothing until its admin queue exists.
//!
//! # Where these numbers come from
//!
//! The **Intel C620 Series Chipset Platform Controller Hub Datasheet**, a
//! public document, section 38.39.2. The X722 is that chipset's integrated
//! controller rather than a discrete adapter, which is why its registers are
//! there and not in the X710/XXV710/XL710 datasheet -- that one is public and
//! register-level too, and covers a different part. Nothing here is written
//! from memory of another driver, and nothing is derived from one: RFC 0071
//! records why that distinction matters, and RFC 0072 records that it did not
//! have to be argued because the specification is public.
//!
//! Every offset below carries the datasheet's own section number, so a reader
//! can check it rather than trust it.

/// PF Control -- 38.39.2.1.20, `PFGEN_CTRL (0x00092400; RW)`.
///
/// Bit 0 is `PFSWR`. Software sets it to ask for a PF reset; **hardware clears
/// it when the reset is done**, which the datasheet states as the last step of
/// the sequence: *"After all the previous steps are completed, hardware does
/// the following: clears the PFSWR bit in the PFGEN_CTRL register."* So the
/// completion test is the bit reading back as zero, and no other register has
/// to be consulted for it.
const PFGEN_CTRL: u64 = 0x0009_2400;
/// `PFGEN_CTRL.PFSWR`, bit 0 -- the same section.
const PFSWR: u32 = 1 << 0;

/// Admin queue registers -- 38.39.2.15, in the datasheet's own order.
///
/// The admin transmit queue is what the driver puts commands on; the admin
/// receive queue is what the firmware puts answers and events on. Both are
/// descriptor rings in host memory, so both take a base address split across
/// two registers and a length that carries an enable bit.
const PF_ATQBAL: u64 = 0x0008_0000;
/// 38.39.2.15.5.
const PF_ATQBAH: u64 = 0x0008_0100;
/// 38.39.2.15.9. Bits 9:0 are the ring length, maximum 1024; **bit 31 is
/// `ATQENABLE`**, and the datasheet is explicit about the order: *"Set by
/// driver to indicate that the queue is active. When setting the enable bit,
/// software should initialize all other fields."* So the base addresses are
/// written first and the length with its enable bit last.
const PF_ATQLEN: u64 = 0x0008_0200;
/// 38.39.2.15.12.
const PF_ATQH: u64 = 0x0008_0300;
/// 38.39.2.15.16.
const PF_ATQT: u64 = 0x0008_0400;
/// 38.39.2.15.3.
const PF_ARQBAL: u64 = 0x0008_0080;
/// 38.39.2.15.7.
const PF_ARQBAH: u64 = 0x0008_0180;
/// 38.39.2.15.11.
const PF_ARQLEN: u64 = 0x0008_0280;
/// 38.39.2.15.14.
const PF_ARQH: u64 = 0x0008_0380;
/// 38.39.2.15.18.
const PF_ARQT: u64 = 0x0008_0480;
/// `PF_ATQLEN.ATQENABLE` / `PF_ARQLEN.ARQENABLE`, bit 31.
const QUEUE_ENABLE: u32 = 1 << 31;

/// One admin queue descriptor, in bytes -- Table 38-339, *Admin Queue
/// Descriptor Structure (in LE 32 Order)*.
///
/// Eight 32-bit words: opcode and flags, return value and data length, cookie
/// high and low, `Param0` and `Param1`, and the data address split high and
/// low. Read off the table rather than inferred, because the text extraction of
/// that page renders a bit-field diagram as a column of loose digits and an
/// inferred size would have been a guess dressed as a citation.
pub const DESCRIPTOR_BYTES: u64 = 32;

/// How many descriptors each admin ring holds.
///
/// The datasheet allows up to 1024. Thirty-two is chosen because this step asks
/// the device a handful of questions and never queues more than one at a time,
/// and a ring is a page's worth of memory the domain has to lend either way.
pub const RING_DESCRIPTORS: u32 = 32;

/// Bytes one admin ring occupies.
pub const RING_BYTES: u64 = DESCRIPTOR_BYTES * RING_DESCRIPTORS as u64;

/// Where the receive ring sits in the page holding both.
///
/// Both rings fit one 4 KiB page -- 1 KiB each -- and sharing a page keeps this
/// to a single object to create, map and revoke. The transmit ring is at offset
/// zero and the receive ring follows it.
pub const RECEIVE_RING_OFFSET: u64 = RING_BYTES;

/// `Get Version`, the opcode -- Table 38-353, *Get Version Command*.
///
/// The datasheet is emphatic about its place: *"This must be the first command
/// that the software device driver issues before it can use the queue for other
/// purposes."* Its `Datalen` is 0 -- *"no external response buffer"* -- so the
/// answer comes back **in the descriptor**, which is why this needs no buffer
/// mapped for the reply.
const OPCODE_GET_VERSION: u16 = 0x0001;

/// `Flags.DD`, byte 0 bit 0 -- Table 38-340: *"Set by firmware to mark entry
/// done."* This is the completion test, and firmware is what sets it.
const FLAG_DD: u16 = 1 << 0;
/// `Flags.ERR`, byte 0 bit 2 -- *"Set by firmware to mark entry as an error
/// indication."*
const FLAG_ERR: u16 = 1 << 2;

/// Where `Get Version`'s answer sits in the completed descriptor -- Table
/// 38-353. Major at bytes 24-25 and minor at 26-27, which in a normal command
/// descriptor are the data address; a command with no external buffer reuses
/// them for its reply.
const VERSION_MAJOR_AT: usize = 24;

/// Global Receive Queue Enable -- 38.39.2.18.13, `QRX_ENA[Q]`
/// (`0x00120000 + 0x4*Q`, Q = 0..1535).
///
/// Four states rather than two, per Table 38-418, and the datasheet is explicit
/// about the handshake: *"If this bit is set, the software should poll the
/// QENA_STAT flag before using the queue... Once software changes the state of
/// the QENA_REQ flag it must poll the QENA_STAT before it is permitted to
/// revert the state of the QENA_REQ once again."* So enabling a queue is a
/// request and a wait, not a write.
const QRX_ENA: u64 = 0x0012_0000;
/// `QRX_ENA.QENA_REQ`, bit 0 -- what software asks for.
const QENA_REQ: u32 = 1 << 0;
/// `QRX_ENA.QENA_STAT`, bit 2 -- what the hardware reports. Read from the field
/// list rather than inferred from the reserved range, because a bit position
/// guessed from a gap is a guess.
const QENA_STAT: u32 = 1 << 2;

/// The highest queue index `QRX_ENA` covers -- 38.39.2.18.13 gives `Q = 0..1535`.
const MAX_RECEIVE_QUEUE: u64 = 1535;

/// How much of BAR0 this module needs mapped.
///
/// **Coupled to the offsets above, and that coupling has bitten twice on the
/// same machine.** First the window was one page and `PFGEN_CTRL` at `0x92400`
/// faulted; the window went to a megabyte with a comment saying that covered
/// every offset "with room". Then `QRX_ENA` at `0x120000` was added and the
/// comment was not revisited, so the boot faulted at exactly that address.
///
/// A comment cannot enforce this and did not. The assertion below can: it fails
/// the build if any register this module names falls outside the window, so the
/// next offset added has to either fit or move this number.
pub const REGISTER_WINDOW_BYTES: u64 = 0x20_0000;

const _: () = assert!(
    REGISTER_WINDOW_BYTES > QRX_ENA + 4 * MAX_RECEIVE_QUEUE,
    "the mapped register window must reach past the highest register this module uses"
);
const _: () = assert!(REGISTER_WINDOW_BYTES > PFGEN_CTRL);
const _: () = assert!(REGISTER_WINDOW_BYTES > PF_ARQT);

/// One mapped X722 function, far enough along to be asked questions.
pub struct Device {
    /// The register window, through the direct map.
    registers: u64,
}

impl Device {
    /// Takes a mapped register window.
    ///
    /// **The whole unsafety of this driver is here**, deliberately. `registers`
    /// must be a mapping of this function's BAR0, device-mapped, valid for the
    /// life of this value, and nothing else may be driving the device. Every
    /// method below relies on that and is therefore safe, which keeps the
    /// `unsafe` in this file down to the two volatile accesses that genuinely
    /// need it rather than a block around each driver step.
    ///
    /// # Safety
    ///
    /// As above.
    #[must_use]
    pub const unsafe fn new(registers: u64) -> Self {
        Self { registers }
    }

    /// Reads one register, which the offsets in this file are all within.
    fn read(&self, offset: u64) -> u32 {
        // SAFETY: `new`'s invariant -- a device mapping of this function's BAR0
        // -- and every offset here is a documented register within it.
        unsafe { core::ptr::read_volatile((self.registers + offset) as *const u32) }
    }

    /// Writes one register.
    fn write(&self, offset: u64, value: u32) {
        // SAFETY: as `read`.
        unsafe { core::ptr::write_volatile((self.registers + offset) as *mut u32, value) };
    }

    /// Asks for a PF reset and says whether the device finished one.
    ///
    /// Sets `PFGEN_CTRL.PFSWR` and waits for **hardware to clear it**, which is
    /// how the datasheet defines completion. `spins` bounds the wait: a device
    /// that never clears the bit is a device that is not there or not
    /// answering, and this must say so rather than hang a boot.
    ///
    pub fn reset(&self, spins: u32) -> bool {
        self.write(PFGEN_CTRL, PFSWR);
        for _ in 0..spins {
            if self.read(PFGEN_CTRL) & PFSWR == 0 {
                return true;
            }
            core::hint::spin_loop();
        }
        false
    }

    /// Points the admin queues at rings the caller owns.
    ///
    /// `transmit` and `receive` are the rings' addresses **as the device will
    /// issue them** -- which is not their physical address, because this device
    /// translates through its own IOMMU domain (RFC 0072 step 2). Handing a
    /// physical address here would name a page the device cannot reach, and the
    /// failure would be silence rather than a fault.
    ///
    /// The enable bit goes last, in both rings, because the datasheet says the
    /// other fields must be initialized before it is set.
    ///
    /// Both rings must stay mapped for the device's use while the queues are
    /// enabled, which is the caller's obligation and not checkable here.
    pub fn enable_admin_queues(&self, transmit: u64, receive: u64) {
        // Heads and tails first, so an enabled ring does not start from
        // whatever a previous owner left. A PF reset clears the enable bits,
        // but this does not assume the reset happened.
        self.write(PF_ATQH, 0);
        self.write(PF_ATQT, 0);
        self.write(PF_ARQH, 0);
        self.write(PF_ARQT, 0);

        self.write(PF_ATQBAL, transmit as u32);
        self.write(PF_ATQBAH, (transmit >> 32) as u32);
        self.write(PF_ARQBAL, receive as u32);
        self.write(PF_ARQBAH, (receive >> 32) as u32);

        self.write(PF_ATQLEN, RING_DESCRIPTORS | QUEUE_ENABLE);
        self.write(PF_ARQLEN, RING_DESCRIPTORS | QUEUE_ENABLE);
    }

    /// Whether both admin queues read back as enabled.
    ///
    /// **Read back rather than assumed.** A write to a register the device is
    /// not answering returns nothing and looks exactly like success, which is
    /// the failure mode every driver in this tree has hit at least once.
    ///
    /// # Safety
    ///
    /// As [`Device::reset`].
    #[must_use]
    pub fn admin_queues_enabled(&self) -> bool {
        // SAFETY: per the caller.
        let (transmit, receive) = (self.read(PF_ATQLEN), self.read(PF_ARQLEN));
        transmit & QUEUE_ENABLE != 0 && receive & QUEUE_ENABLE != 0
    }

    /// The admin queue lengths the device reports, for the boot report.
    ///
    #[must_use]
    pub fn admin_queue_lengths(&self) -> (u32, u32) {
        (self.read(PF_ATQLEN) & 0x3ff, self.read(PF_ARQLEN) & 0x3ff)
    }

    /// What a receive queue's enable handshake currently reads.
    ///
    /// Returns `(requested, active)` -- `QENA_REQ` and `QENA_STAT`. The four
    /// combinations are Table 38-418's states: neither is a queue that is off,
    /// both is one that is running, and the two mixed states are a request in
    /// flight in one direction or the other.
    ///
    /// **Read before anything is written**, for the reason the admin queues
    /// taught: firmware had left those sized, and assuming a clean slate would
    /// have enabled a ring at somebody else's size. A queue this platform is
    /// already using is worth knowing about before taking it.
    #[must_use]
    pub fn receive_queue_state(&self, queue: u32) -> (bool, bool) {
        let value = self.read(QRX_ENA + 4 * u64::from(queue));
        (value & QENA_REQ != 0, value & QENA_STAT != 0)
    }

    /// Posts `Get Version` and waits for firmware to answer it.
    ///
    /// `ring` is the transmit ring **as this kernel sees it** -- the direct-map
    /// address of the same page the device reaches at its own address. Both are
    /// needed and they are not the same number: the device was told where the
    /// ring is in its own translation, and the descriptor has to be written
    /// where the writer can reach it.
    ///
    /// Returns the firmware's major and minor version, or `None` if the
    /// descriptor never came back done or came back flagged as an error.
    ///
    /// # Safety
    ///
    /// `ring` must be the transmit ring's direct-map address, mapped for
    /// writing, at least [`RING_BYTES`] long, and the queues must be enabled.
    pub unsafe fn get_version(&self, ring: u64, spins: u32) -> Option<(u16, u16)> {
        // Descriptor zero, cleared first: firmware writes its answer over the
        // command, and a stale `DD` from a previous owner would read as an
        // answer that never came. Firmware left these rings configured, so this
        // is not a hypothetical.
        // SAFETY: per the caller -- a writable mapping of at least one
        // descriptor, and nothing else is writing this ring.
        unsafe {
            core::ptr::write_bytes(ring as *mut u8, 0, DESCRIPTOR_BYTES as usize);
            core::ptr::write_volatile((ring + 2) as *mut u16, OPCODE_GET_VERSION);
        }

        // The tail is what tells firmware a descriptor is there -- Table 38-341
        // calls `ATQT` the pointer "software device driver updates". One
        // descriptor posted, so the tail moves to one.
        self.write(PF_ATQT, 1);

        for _ in 0..spins {
            // SAFETY: per the caller.
            let flags = unsafe { core::ptr::read_volatile(ring as *const u16) };
            if flags & FLAG_DD != 0 {
                if flags & FLAG_ERR != 0 {
                    return None;
                }
                // SAFETY: per the caller; the descriptor is complete.
                let (major, minor) = unsafe {
                    (
                        core::ptr::read_volatile((ring + VERSION_MAJOR_AT as u64) as *const u16),
                        core::ptr::read_volatile(
                            (ring + VERSION_MAJOR_AT as u64 + 2) as *const u16,
                        ),
                    )
                };
                return Some((major, minor));
            }
            core::hint::spin_loop();
        }
        None
    }
}
