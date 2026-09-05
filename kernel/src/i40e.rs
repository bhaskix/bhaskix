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

/// How many descriptors each admin ring holds.
///
/// The datasheet allows up to 1024. Thirty-two is chosen because this step asks
/// the device a handful of questions and never queues more than one at a time,
/// and a ring is a page's worth of memory the domain has to lend either way.
pub const RING_DESCRIPTORS: u32 = 32;

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
}
