// SPDX-License-Identifier: Apache-2.0
#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! AHCI's byte layouts, and the 512 bytes a disk answers `IDENTIFY` with.
//!
//! [RFC 0046](../../docs/rfc/0046-a-driver-for-hardware-that-exists.md) step 1.
//! Everything here is either **a structure a DMA-capable device will read** or
//! **a structure a device wrote**, and both are testable without a controller:
//! the first is arithmetic over a byte array, the second is untrusted input.
//! So neither lives in the driver, and this crate depends on nothing.
//!
//! # Why the tests assert raw offsets
//!
//! A round trip through this crate's own writer and reader agrees with itself
//! about a field at the wrong offset. The device does not: it reads the bytes
//! at the offsets the specification names, and a command list entry whose
//! length lands two bytes late is a command the controller runs against
//! whatever was next in memory. So the tests below check *dwords*, the way
//! [RFC 0038](../../docs/rfc/0038-a-vendored-take.md)'s xHCI work learned to.
//!
//! # What this crate does not have
//!
//! No register access, no MMIO, no addresses of its own. A command table is
//! built *into a slice the caller owns*, and the physical address it must be
//! reached at is the caller's to know — this crate never learns one, which is
//! why it can be fuzzed and why it holds no authority.

/// A command list has thirty-two slots and the hardware fixes the number.
pub const COMMAND_SLOTS: usize = 32;

/// One command list entry, in bytes. Thirty-two, and the list is therefore
/// 1 KiB — which is also its required alignment.
pub const COMMAND_HEADER_BYTES: usize = 32;

/// The whole command list.
pub const COMMAND_LIST_BYTES: usize = COMMAND_HEADER_BYTES * COMMAND_SLOTS;

/// The received-FIS area, which the controller writes and the driver reads.
pub const RECEIVED_FIS_BYTES: usize = 256;

/// A Register Host-to-Device FIS: the command itself, twenty bytes.
pub const H2D_FIS_BYTES: usize = 20;

/// Where the scatter-gather list starts inside a command table. The FIS
/// occupies 64, then 16 of ATAPI command and 48 reserved.
pub const PRDT_AT: usize = 128;

/// One physical region descriptor.
pub const PRD_BYTES: usize = 16;

/// The largest a single region may be, and it is a **count of bytes minus
/// one** in the register — so the field's maximum of `0x3f_ffff` means this.
pub const PRD_MAX_BYTES: usize = 4 * 1024 * 1024;

/// What `IDENTIFY DEVICE` answers with.
pub const IDENTIFY_BYTES: usize = 512;

/// Errors this crate answers with.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Error {
    /// The buffer given is too small for the structure asked for.
    TooSmall,
    /// A region longer than one descriptor may describe.
    RegionTooLong,
    /// More regions than the caller's table has room for.
    TooManyRegions,
    /// A device's answer that does not describe a usable disk.
    NotADisk,
}

/// The ATA commands this driver issues, and no others.
pub mod command {
    /// Ask the device what it is. The answer is [`super::IDENTIFY_BYTES`].
    pub const IDENTIFY: u8 = 0xec;
    /// Read sectors by 48-bit LBA, by DMA.
    pub const READ_DMA_EXT: u8 = 0x25;
    /// Write them.
    pub const WRITE_DMA_EXT: u8 = 0x35;
}

/// FIS type bytes.
pub mod fis {
    /// Register, host to device — the only one this driver *writes*.
    pub const REGISTER_H2D: u8 = 0x27;
    /// Register, device to host.
    pub const REGISTER_D2H: u8 = 0x34;
}

/// Writes a Register Host-to-Device FIS carrying an ATA command.
///
/// **The LBA is split across two groups of three bytes and that is the whole
/// trap of this structure.** Bytes 4–6 are LBA 0–23 and bytes 8–10 are LBA
/// 24–47, with the device register in between; a driver that wrote six
/// consecutive bytes would put the top half of every address into the wrong
/// field and read a sector nowhere near the one it asked for. The test below
/// checks a value whose halves differ, because an LBA of zero passes either
/// way.
///
/// `count` is sectors, and zero means 65,536 in ATA — this refuses it rather
/// than sending a request whose size is the opposite of what it looks like.
///
/// # Errors
///
/// [`Error::TooSmall`] if `out` is shorter than [`H2D_FIS_BYTES`].
pub fn write_h2d(out: &mut [u8], ata: u8, lba: u64, count: u16) -> Result<(), Error> {
    if out.len() < H2D_FIS_BYTES {
        return Err(Error::TooSmall);
    }
    out[..H2D_FIS_BYTES].fill(0);
    out[0] = fis::REGISTER_H2D;
    // Bit 7 is "this is a command rather than a control update". Without it
    // the controller takes the FIS as a register write and issues nothing,
    // which looks exactly like a device that never answered.
    out[1] = 0x80;
    out[2] = ata;
    let lba = lba.to_le_bytes();
    out[4] = lba[0];
    out[5] = lba[1];
    out[6] = lba[2];
    // **LBA mode**, in the device register. Bit 6 selects LBA over the CHS
    // addressing this field meant in 1994; without it the low three bytes are
    // read as cylinder/head/sector.
    out[7] = 1 << 6;
    out[8] = lba[3];
    out[9] = lba[4];
    out[10] = lba[5];
    let count = count.to_le_bytes();
    out[12] = count[0];
    out[13] = count[1];
    Ok(())
}

/// Writes one command list entry.
///
/// `fis_words` is the command FIS's length **in dwords**, which is what the
/// low five bits of the first word hold — not bytes. A twenty-byte FIS is
/// five, and writing twenty there describes a FIS four times too long.
///
/// # Errors
///
/// [`Error::TooSmall`] if `out` cannot hold an entry.
pub fn write_command_header(
    out: &mut [u8],
    fis_bytes: usize,
    write: bool,
    regions: u16,
    table_at: u64,
) -> Result<(), Error> {
    if out.len() < COMMAND_HEADER_BYTES {
        return Err(Error::TooSmall);
    }
    out[..COMMAND_HEADER_BYTES].fill(0);
    let words = (fis_bytes / 4) as u32;
    // Bit 6 is the direction, and it means *write to the device*. A read with
    // it set makes the controller pull from memory the disk should be filling.
    let flags = (words & 0x1f) | (u32::from(write) << 6);
    out[0..4].copy_from_slice(&flags.to_le_bytes());
    out[2..4].copy_from_slice(&regions.to_le_bytes());
    // Bytes 8..16: the command table's address, low half then high. Written as
    // two 32-bit halves because that is how the structure is defined and how a
    // 32-bit controller reads it.
    let table = table_at.to_le_bytes();
    out[8..16].copy_from_slice(&table);
    Ok(())
}

/// Writes one physical region descriptor.
///
/// **The byte count is stored as one less than it is**, so a 512-byte region
/// holds 511. A driver that stores the true count transfers one byte too many
/// into memory it may not own — which is the direction that matters when the
/// thing doing the transfer is a bus master.
///
/// # Errors
///
/// [`Error::TooSmall`] for a short buffer, [`Error::RegionTooLong`] for a
/// region no descriptor can describe.
pub fn write_region(out: &mut [u8], at: u64, bytes: usize, interrupt: bool) -> Result<(), Error> {
    if out.len() < PRD_BYTES {
        return Err(Error::TooSmall);
    }
    if bytes == 0 || bytes > PRD_MAX_BYTES {
        return Err(Error::RegionTooLong);
    }
    out[..PRD_BYTES].fill(0);
    out[0..8].copy_from_slice(&at.to_le_bytes());
    let last = (bytes - 1) as u32;
    let word = (last & 0x003f_ffff) | (u32::from(interrupt) << 31);
    out[12..16].copy_from_slice(&word.to_le_bytes());
    Ok(())
}

/// What a disk said about itself.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Identity {
    /// How many logical sectors it has.
    pub sectors: u64,
    /// How many bytes each holds.
    pub sector_bytes: u32,
    /// Whether it answered as a device that supports 48-bit addressing.
    pub lba48: bool,
}

/// Reads what `IDENTIFY DEVICE` answered.
///
/// **Every field here is a number a device chose**, and one of them sizes
/// later requests, so this is the crate's untrusted-input parser and the one
/// with a fuzz target. Firmware is buggy and a disk on a shared bus is not a
/// trusted peer: a sector count of zero, a sector size of three, or a count
/// that would put the last byte past the end of the address space are all
/// things a real device has been known to answer, and none of them may reach
/// arithmetic that sizes a transfer.
///
/// # Errors
///
/// [`Error::TooSmall`] for a short buffer, [`Error::NotADisk`] for an answer
/// that does not describe one.
pub fn read_identity(words: &[u8]) -> Result<Identity, Error> {
    if words.len() < IDENTIFY_BYTES {
        return Err(Error::TooSmall);
    }
    let word =
        |index: usize| -> u16 { u16::from_le_bytes([words[index * 2], words[index * 2 + 1]]) };
    // Word 83 bit 10: the device supports the 48-bit commands. Without it the
    // 48-bit sector count in words 100..104 means nothing and must not be read.
    let lba48 = word(83) & (1 << 10) != 0;
    let sectors = if lba48 {
        u64::from(word(100))
            | (u64::from(word(101)) << 16)
            | (u64::from(word(102)) << 32)
            | (u64::from(word(103)) << 48)
    } else {
        u64::from(word(60)) | (u64::from(word(61)) << 16)
    };
    // Word 106 describes the sector size, and only when bit 14 is set and bit
    // 15 clear -- the pair is the field's "this word is meaningful" marker.
    // Bit 12 then says the logical sector is larger than 512, and words
    // 117..118 hold how many *16-bit words* it is.
    let sector_bytes = if word(106) & 0xc000 == 0x4000 && word(106) & (1 << 12) != 0 {
        let in_words = u32::from(word(117)) | (u32::from(word(118)) << 16);
        in_words.saturating_mul(2)
    } else {
        512
    };
    // The bounds, and they are the point of this function. A device that
    // answers nonsense is refused here rather than sizing a transfer later.
    if sectors == 0 || sector_bytes < 512 || !sector_bytes.is_power_of_two() {
        return Err(Error::NotADisk);
    }
    if sectors.checked_mul(u64::from(sector_bytes)).is_none() {
        return Err(Error::NotADisk);
    }
    Ok(Identity {
        sectors,
        sector_bytes,
        lba48,
    })
}

// ---------------------------------------------------------------------------
// RFC 0046 step 3a: the bring-up sequence.
//
// **The register offsets and bit positions below come from recall, not from a
// source on this machine.** There is no AHCI specification here and no
// `drivers/ata/ahci.h` -- the installed linux-headers packages ship Kconfig and
// a Makefile under `drivers/ata` and no sources. This project's standard is
// that a specification is **read, not recalled**, which is what RFC 0038 spent
// a whole document arranging for xHCI. So this says so plainly rather than
// letting the numbers below pass as sourced.
//
// What the tests below can prove and what they cannot: they prove **the
// sequence is right given these constants**. They cannot prove the constants,
// because a test and an implementation sharing a wrong number agree with each
// other. The constants get their first real check on the first boot that reads
// a controller and prints raw `CAP`, `PI` and `VS` -- a wrong `PI` offset shows
// as an implausible port bitmap, a wrong `GHC` offset as a reset that never
// settles, and a wrong `CAP` offset as a slot count outside 1..=32. The byte
// layouts of step 1 are in the same position and get theirs at step 5's
// sector-zero gate.
// ---------------------------------------------------------------------------

/// The controller's registers, as somebody else's problem.
///
/// **This is what keeps the crate `forbid(unsafe_code)` honestly rather than
/// technically.** An `Mmio` register block would work and would put an
/// `unsafe fn new` in this crate, which is the crate whose whole claim is that
/// it cannot reach a controller. Here the caller owns the mapping and the two
/// unsafe operations in the whole driver, and this crate holds no address.
///
/// It is also the better fit for this device. AHCI's ports are a **repeating
/// array** at [`port_at`], so a register block would need one `unsafe`
/// constructor per port; this needs one read and one write for all of them.
pub trait Registers {
    /// Reads the 32-bit register at `offset` from the ABAR base.
    fn read(&self, offset: usize) -> u32;
    /// Writes it.
    fn write(&mut self, offset: usize, value: u32);
}

/// The generic host control registers, at the start of the ABAR.
pub mod ghc {
    /// Host capabilities. Slot count, port count, and what the controller can do.
    pub const CAP: usize = 0x00;
    /// Global host control.
    pub const GHC: usize = 0x04;
    /// Interrupt status, one bit per port.
    pub const IS: usize = 0x08;
    /// Ports implemented, one bit per port. **Not a count** -- a bitmap, and a
    /// controller is entitled to implement port 5 and not ports 0 to 4.
    pub const PI: usize = 0x0c;
    /// Version.
    pub const VS: usize = 0x10;
    /// Extended capabilities.
    pub const CAP2: usize = 0x24;
    /// BIOS/OS handoff control and status.
    pub const BOHC: usize = 0x28;

    /// `GHC.AE` -- AHCI enable. **Cleared by a reset**, which is why it is set
    /// twice.
    pub const AE: u32 = 1 << 31;
    /// `GHC.HR` -- HBA reset. Written as one, cleared by the controller.
    pub const HR: u32 = 1 << 0;
}

/// `CAP` fields.
pub mod cap {
    /// Number of command slots, minus one, in bits 8..13.
    pub const NCS_SHIFT: u32 = 8;
    /// Its mask, before the shift.
    pub const NCS_MASK: u32 = 0x1f;
    /// Supports 64-bit addressing. Without it, no structure may sit above 4 GiB.
    pub const S64A: u32 = 1 << 31;
    /// Supports native command queuing.
    pub const SNCQ: u32 = 1 << 30;
}

/// `CAP2` fields.
pub mod cap2 {
    /// The controller implements the BIOS/OS handoff. **Without this bit there
    /// is no `BOHC` register**, and writing one would be writing at an offset
    /// the specification reserves.
    pub const BOH: u32 = 1 << 0;
}

/// `BOHC` fields.
pub mod bohc {
    /// BIOS owned semaphore. Set while the firmware still has the controller.
    pub const BOS: u32 = 1 << 0;
    /// OS owned semaphore. Written to ask for it.
    pub const OOS: u32 = 1 << 1;
    /// BIOS busy. The firmware is still cleaning up; not a refusal.
    pub const BB: u32 = 1 << 4;
}

/// A port's registers, at [`port_at`].
pub mod port {
    /// Command list base, low half.
    pub const CLB: usize = 0x00;
    /// Command list base, high half.
    pub const CLBU: usize = 0x04;
    /// Received-FIS base, low half.
    pub const FB: usize = 0x08;
    /// Received-FIS base, high half.
    pub const FBU: usize = 0x0c;
    /// Interrupt status.
    pub const IS: usize = 0x10;
    /// Interrupt enable.
    pub const IE: usize = 0x14;
    /// Command and status.
    pub const CMD: usize = 0x18;
    /// Task file data -- the device's status and error bytes.
    pub const TFD: usize = 0x20;
    /// Signature, which says what kind of device answered.
    pub const SIG: usize = 0x24;
    /// SATA status. The register that answers "is there a disk on this port".
    pub const SSTS: usize = 0x28;
    /// SATA control.
    pub const SCTL: usize = 0x2c;
    /// SATA error.
    pub const SERR: usize = 0x30;
    /// SATA active.
    pub const SACT: usize = 0x34;
    /// Command issue, one bit per slot.
    pub const CI: usize = 0x38;
}

/// `PxCMD` fields.
pub mod cmd {
    /// Start. The command engine runs while this is set.
    pub const ST: u32 = 1 << 0;
    /// FIS receive enable.
    pub const FRE: u32 = 1 << 4;
    /// FIS receive running. **Follows `FRE`, and not immediately.**
    pub const FR: u32 = 1 << 14;
    /// Command list running. Follows `ST`, and not immediately.
    pub const CR: u32 = 1 << 15;
}

/// `PxSSTS` fields.
pub mod ssts {
    /// Device detection, bits 0..4.
    pub const DET_MASK: u32 = 0x0f;
    /// Interface power management, bits 8..12.
    pub const IPM_SHIFT: u32 = 8;
    /// Its mask, before the shift.
    pub const IPM_MASK: u32 = 0x0f;

    /// Nothing is attached.
    pub const DET_NONE: u32 = 0;
    /// A device is attached and the link will not come up. **Not the same as
    /// [`DET_NONE`]**, and a driver that conflates them sends the next reader
    /// to the wrong place: one is an empty port and the other is a fault.
    pub const DET_PRESENT_NO_COMMS: u32 = 1;
    /// A device is attached and communicating. The only value that is a disk.
    pub const DET_PRESENT: u32 = 3;

    /// The interface is active.
    pub const IPM_ACTIVE: u32 = 1;
}

/// The most ports AHCI can have, and the width of the `PI` bitmap.
pub const MAX_PORTS: usize = 32;

/// Where a port's register lives.
///
/// **The stride is `0x80` and that is the trap.** With `0x40` every odd port's
/// registers land on top of an even port's, which is not a failure: it is a
/// driver that reads port 1's status out of port 0 and reports a disk on a port
/// that has none.
#[must_use]
pub const fn port_at(index: usize, register: usize) -> usize {
    0x100 + index * 0x80 + register
}

/// What one port answered.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct PortState {
    /// Which port this is.
    pub index: u8,
    /// `SSTS.DET`.
    pub det: u8,
    /// `SSTS.IPM`.
    pub ipm: u8,
    /// `PxSIG`, which says what kind of device answered.
    pub signature: u32,
}

impl PortState {
    /// Whether a device is attached *and* talking.
    #[must_use]
    pub fn has_device(&self) -> bool {
        u32::from(self.det) == ssts::DET_PRESENT
    }
}

/// What the controller said about itself once it was running.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Started {
    /// The `PI` bitmap, verbatim.
    pub implemented: u32,
    /// How many command slots each port has, bounded to 1..=32.
    pub slots: u8,
    /// `VS`, verbatim, so a boot can print what the controller claims to be.
    pub version: u32,
    /// Whether the controller can address memory above 4 GiB.
    pub sixty_four_bit: bool,
    /// Whether it supports native command queuing. Reported, never used here.
    pub queuing: bool,
    /// Whether the firmware owned it and handed it over.
    pub took_from_firmware: bool,
    /// Each implemented port, in order.
    pub ports: [PortState; MAX_PORTS],
    /// How many entries of `ports` are meaningful.
    pub port_count: usize,
}

impl Started {
    /// The ports this scan recorded.
    pub fn ports(&self) -> impl Iterator<Item = &PortState> {
        self.ports[..self.port_count].iter()
    }
}

/// Why a bring-up was refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NotUp {
    /// A register did not settle before the deadline. **Names which one**,
    /// because "the controller did not come up" sends a reader nowhere.
    NotSettled(&'static str),
    /// `PI` named no ports at all. A controller with nothing to drive.
    NoPortsImplemented,
    /// A structure was offered at an address the controller cannot be given.
    Misaligned(&'static str),
    /// A structure above 4 GiB on a controller that cannot address it.
    Above4Gib,
    /// A port index outside `PI`, or outside the register file.
    NoSuchPort,
}

/// Waits for `settled` to hold, bounded by a deadline off `clock`.
///
/// **A deadline, never a spin count.** A count is a wait whose length depends
/// on how fast the machine is, which means it is either too short on a slow one
/// or a hang on a broken one; `337b16f` replaced the last of those in this tree.
fn wait_until<R: Registers>(
    regs: &R,
    offset: usize,
    clock: &mut impl FnMut() -> u64,
    budget_ns: u64,
    name: &'static str,
    settled: impl Fn(u32) -> bool,
) -> Result<u32, NotUp> {
    let started = clock();
    loop {
        let value = regs.read(offset);
        if settled(value) {
            return Ok(value);
        }
        if clock().saturating_sub(started) >= budget_ns {
            return Err(NotUp::NotSettled(name));
        }
    }
}

/// Takes the controller from the firmware, if it has it.
///
/// Only when `CAP2.BOH` says there is a handoff to do: **a controller without
/// it has no `BOHC` register**, and writing one would be writing at a reserved
/// offset of a bus master.
///
/// `BB` -- BIOS busy -- is not a refusal. The firmware is entitled to take its
/// time cleaning up after it has given the semaphore back.
fn take_from_firmware<R: Registers>(
    regs: &mut R,
    clock: &mut impl FnMut() -> u64,
    budget_ns: u64,
) -> Result<bool, NotUp> {
    if regs.read(ghc::CAP2) & cap2::BOH == 0 {
        return Ok(false);
    }
    let owned = regs.read(ghc::BOHC);
    if owned & bohc::BOS == 0 {
        // Nothing to take. Ask anyway, so the register says who owns it.
        regs.write(ghc::BOHC, owned | bohc::OOS);
        return Ok(false);
    }
    regs.write(ghc::BOHC, owned | bohc::OOS);
    wait_until(regs, ghc::BOHC, clock, budget_ns, "BOHC.BOS", |v| {
        v & bohc::BOS == 0
    })?;
    Ok(true)
}

/// Stops a port's two engines, so its memory may be reprogrammed.
///
/// **Both, and the wait is on both.** `ST` drives the command engine and `FRE`
/// the FIS receive engine, and they stop independently: clearing `ST` and
/// waiting only for `CR` leaves the controller still writing received FISes
/// into the area about to be given a new address.
fn stop_port<R: Registers>(
    regs: &mut R,
    index: usize,
    clock: &mut impl FnMut() -> u64,
    budget_ns: u64,
) -> Result<(), NotUp> {
    let at = port_at(index, port::CMD);
    let running = regs.read(at);
    regs.write(at, running & !(cmd::ST | cmd::FRE));
    wait_until(regs, at, clock, budget_ns, "PxCMD.CR", |v| v & cmd::CR == 0)?;
    wait_until(regs, at, clock, budget_ns, "PxCMD.FR", |v| v & cmd::FR == 0)?;
    Ok(())
}

/// Brings the controller up as far as it goes without a command.
///
/// RFC 0046 step 3. Nothing is issued: this ends with every implemented port
/// stopped and its `SSTS` read, which is the register that answers *"is there a
/// disk on this port"* -- the question the bus survey could not.
///
/// # Errors
///
/// [`NotUp`], naming the register that did not settle where that is what
/// happened.
pub fn bring_up<R: Registers>(
    regs: &mut R,
    clock: &mut impl FnMut() -> u64,
    budget_ns: u64,
) -> Result<Started, NotUp> {
    let took_from_firmware = take_from_firmware(regs, clock, budget_ns)?;

    // Before the reset, because a controller in legacy mode is a controller
    // whose registers are not the ones being written.
    let enable = regs.read(ghc::GHC);
    regs.write(ghc::GHC, enable | ghc::AE);

    regs.write(ghc::GHC, regs.read(ghc::GHC) | ghc::HR);
    wait_until(regs, ghc::GHC, clock, budget_ns, "GHC.HR", |v| {
        v & ghc::HR == 0
    })?;

    // **Again, because the reset cleared it.** A driver that sets it once
    // programs an AHCI register file and then hands the controller back to
    // legacy mode, where those offsets mean something else.
    regs.write(ghc::GHC, regs.read(ghc::GHC) | ghc::AE);

    let capabilities = regs.read(ghc::CAP);
    let implemented = regs.read(ghc::PI);
    if implemented == 0 {
        return Err(NotUp::NoPortsImplemented);
    }

    // RFC 0038 rule 6: the controller's own number, bounded before it sizes
    // anything. **The mask is the bound**, and there is deliberately no clamp
    // after it: `NCS_MASK` is five bits, so the field is 0..=31 and the count
    // is 1..=32 for every value a controller can put there. A
    // `clamp(1, COMMAND_SLOTS)` was written here first and a mutation test
    // caught it as unreachable -- a guard that can never fire is worse than no
    // guard, because it reads as protection and moves the real bound out of
    // sight. The test below is exhaustive over all thirty-two values.
    let slots = (((capabilities >> cap::NCS_SHIFT) & cap::NCS_MASK) + 1) as u8;

    let mut started = Started {
        implemented,
        slots,
        version: regs.read(ghc::VS),
        sixty_four_bit: capabilities & cap::S64A != 0,
        queuing: capabilities & cap::SNCQ != 0,
        took_from_firmware,
        ports: [PortState::default(); MAX_PORTS],
        port_count: 0,
    };

    // **Only the ports `PI` names.** It is a bitmap and not a count: a
    // controller is entitled to implement port 5 and no port below it, and a
    // loop over 0..32 would read and *write* registers of ports that do not
    // exist.
    for index in 0..MAX_PORTS {
        if implemented & (1 << index) == 0 {
            continue;
        }
        stop_port(regs, index, clock, budget_ns)?;
        let status = regs.read(port_at(index, port::SSTS));
        started.ports[started.port_count] = PortState {
            index: index as u8,
            det: (status & ssts::DET_MASK) as u8,
            ipm: ((status >> ssts::IPM_SHIFT) & ssts::IPM_MASK) as u8,
            signature: regs.read(port_at(index, port::SIG)),
        };
        started.port_count += 1;
    }

    Ok(started)
}

/// Points a port at its command list and received-FIS area, and starts it.
///
/// **Both halves of each address are written, low first, and the high half even
/// when it is zero.** Firmware leaves values in these registers; a driver that
/// writes only the low half of a 32-bit address leaves the firmware's high bits
/// in place, and the controller then reads its command list from an address
/// nowhere near the one it was given -- by a bus master.
///
/// # Errors
///
/// [`NotUp::Misaligned`] for a command list not on a 1 KiB boundary or a
/// received-FIS area not on a 256-byte one; [`NotUp::Above4Gib`] for an address
/// a 32-bit controller cannot be given; [`NotUp::NoSuchPort`] for a port `PI`
/// did not name.
pub fn start_port<R: Registers>(
    regs: &mut R,
    started: &Started,
    index: usize,
    command_list: u64,
    received_fis: u64,
) -> Result<(), NotUp> {
    if index >= MAX_PORTS || started.implemented & (1 << index) == 0 {
        return Err(NotUp::NoSuchPort);
    }
    // The list is 1 KiB and must be 1 KiB aligned; the FIS area is 256 bytes
    // and must be 256 aligned. The controller ignores the low bits rather than
    // refusing, so an unaligned address is a structure silently read from
    // somewhere else.
    if !command_list.is_multiple_of(COMMAND_LIST_BYTES as u64) {
        return Err(NotUp::Misaligned("command list"));
    }
    if !received_fis.is_multiple_of(RECEIVED_FIS_BYTES as u64) {
        return Err(NotUp::Misaligned("received fis"));
    }
    if !started.sixty_four_bit
        && (command_list > u64::from(u32::MAX) || received_fis > u64::from(u32::MAX))
    {
        return Err(NotUp::Above4Gib);
    }

    regs.write(port_at(index, port::CLB), command_list as u32);
    regs.write(port_at(index, port::CLBU), (command_list >> 32) as u32);
    regs.write(port_at(index, port::FB), received_fis as u32);
    regs.write(port_at(index, port::FBU), (received_fis >> 32) as u32);

    // Errors first: `SERR` is write-one-to-clear, and a port started over a
    // stale error reports the firmware's problem as this driver's.
    let at = port_at(index, port::SERR);
    let stale = regs.read(at);
    regs.write(at, stale);

    // FIS receive before start. The controller may write a received FIS the
    // moment the command engine runs, and it must have somewhere to put it.
    let at = port_at(index, port::CMD);
    let current = regs.read(at);
    regs.write(at, current | cmd::FRE);
    regs.write(at, regs.read(at) | cmd::ST);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use core::array;
    use core::cell::Cell;

    /// A countdown that has not been armed: the bit never clears, which is
    /// what gives a deadline something to expire on.
    const NEVER: u32 = u32::MAX;

    /// A controller to test against, without one.
    ///
    /// **A model and not a register file**, for the reason `device::testing`'s
    /// own header gives: a register file answers with whatever was written,
    /// which is the one behaviour a real controller does not have. Real
    /// controllers take their time, and taking time is what a driver's waiting
    /// gets wrong. So `GHC.HR` and `BOHC.BOS` clear after a set number of
    /// reads, `PxCMD.CR` and `PxCMD.FR` follow their enables with a lag, and
    /// any of them can be set to [`NEVER`] -- which is what gives a refusal
    /// something to refuse.
    struct Controller {
        file: [u32; 0x400],
        /// Reads of `GHC` remaining before `HR` clears.
        hr_left: Cell<u32>,
        /// What `hr_left` is reloaded with when `HR` is written.
        hr_takes: u32,
        /// Reads of `BOHC` remaining before `BOS` clears.
        bos_left: Cell<u32>,
        /// Reads of a port's `CMD` remaining before `CR` follows `ST`.
        cr_left: [Cell<u32>; MAX_PORTS],
        /// And before `FR` follows `FRE`. **Separate, because the two engines
        /// stop independently** -- a single countdown would make a driver that
        /// waits only for `CR` look correct, which is the bug this models.
        fr_left: [Cell<u32>; MAX_PORTS],
        /// What each port's `SSTS` answers.
        status: [u32; MAX_PORTS],
        /// Every write, in order. Tests about *ordering* read this rather than
        /// the final state, because a final state cannot tell "low half then
        /// high half" from the other way round.
        writes: [(usize, u32); 256],
        written: usize,
    }

    impl Controller {
        fn new() -> Self {
            let mut file = [0u32; 0x400];
            // One port implemented, 32 slots, 64-bit capable. `NCS` holds one
            // less than the count.
            file[ghc::CAP / 4] = (31 << cap::NCS_SHIFT) | cap::S64A;
            file[ghc::PI / 4] = 0b1;
            file[ghc::VS / 4] = 0x0001_0300;
            let mut controller = Self {
                file,
                hr_left: Cell::new(0),
                hr_takes: 2,
                bos_left: Cell::new(2),
                cr_left: array::from_fn(|_| Cell::new(2)),
                fr_left: array::from_fn(|_| Cell::new(2)),
                status: [0; MAX_PORTS],
                writes: [(0, 0); 256],
                written: 0,
            };
            // A disk on port 0, attached and talking.
            controller.status[0] = ssts::DET_PRESENT | (ssts::IPM_ACTIVE << ssts::IPM_SHIFT);
            controller
        }

        /// The firmware owns it and there is a handoff to perform.
        fn with_firmware(mut self) -> Self {
            self.file[ghc::CAP2 / 4] = cap2::BOH;
            self.file[ghc::BOHC / 4] = bohc::BOS;
            self
        }

        fn with_ports(mut self, implemented: u32) -> Self {
            self.file[ghc::PI / 4] = implemented;
            self
        }

        fn with_status(mut self, index: usize, status: u32) -> Self {
            self.status[index] = status;
            self
        }

        /// A controller whose reset never completes.
        fn wedged(mut self) -> Self {
            self.hr_takes = NEVER;
            self
        }

        /// A controller whose firmware never lets go.
        fn firmware_never_lets_go(mut self) -> Self {
            self.bos_left = Cell::new(NEVER);
            self
        }

        /// A controller whose command engine never stops.
        fn command_engine_never_stops(mut self) -> Self {
            self.cr_left = array::from_fn(|_| Cell::new(NEVER));
            self
        }

        /// A controller whose *FIS receive* engine never stops, while the
        /// command engine does. The shape that makes a driver waiting only for
        /// `CR` look correct.
        fn fis_engine_never_stops(mut self) -> Self {
            self.fr_left = array::from_fn(|_| Cell::new(NEVER));
            self
        }

        fn writes(&self) -> &[(usize, u32)] {
            &self.writes[..self.written]
        }

        fn write_index(&self, offset: usize) -> Option<usize> {
            self.writes().iter().position(|(at, _)| *at == offset)
        }

        fn wrote(&self, offset: usize) -> bool {
            self.write_index(offset).is_some()
        }

        /// How many writes to `offset` had `bit` set.
        fn set_count(&self, offset: usize, bit: u32) -> usize {
            self.writes()
                .iter()
                .filter(|(at, value)| *at == offset && value & bit != 0)
                .count()
        }

        /// Counts down `left`, answering whether the thing it gates has
        /// happened yet. `NEVER` never counts down and never happens.
        fn elapsed(left: &Cell<u32>) -> bool {
            match left.get() {
                NEVER => false,
                0 => true,
                remaining => {
                    left.set(remaining - 1);
                    false
                }
            }
        }
    }

    impl Registers for Controller {
        fn read(&self, offset: usize) -> u32 {
            if offset == ghc::GHC {
                let value = self.file[offset / 4];
                if value & ghc::HR != 0 && Self::elapsed(&self.hr_left) {
                    return value & !ghc::HR;
                }
                return value;
            }
            if offset == ghc::BOHC {
                let value = self.file[offset / 4];
                if value & bohc::BOS != 0 && Self::elapsed(&self.bos_left) {
                    return value & !bohc::BOS;
                }
                return value;
            }
            for index in 0..MAX_PORTS {
                if offset == port_at(index, port::SSTS) {
                    return self.status[index];
                }
                if offset == port_at(index, port::CMD) {
                    let value = self.file[offset / 4];
                    let mut out = value & !(cmd::CR | cmd::FR);
                    // Each engine on its own countdown: one may still be
                    // running long after the other has stopped, which is the
                    // whole reason both are waited for.
                    if value & cmd::ST != 0 || !Self::elapsed(&self.cr_left[index]) {
                        out |= cmd::CR;
                    }
                    if value & cmd::FRE != 0 || !Self::elapsed(&self.fr_left[index]) {
                        out |= cmd::FR;
                    }
                    return out;
                }
            }
            self.file[offset / 4]
        }

        fn write(&mut self, offset: usize, value: u32) {
            assert!(self.written < self.writes.len(), "the model's log is full");
            self.writes[self.written] = (offset, value);
            self.written += 1;
            self.file[offset / 4] = value;
            if offset == ghc::GHC && value & ghc::HR != 0 {
                self.hr_left.set(self.hr_takes);
            }
        }
    }

    /// A monotonic clock that advances one unit per reading.
    fn ticking() -> impl FnMut() -> u64 {
        let mut now = 0u64;
        move || {
            now += 1;
            now
        }
    }

    /// Long enough that nothing healthy expires.
    const PATIENT: u64 = 1_000_000;

    #[test]
    fn an_h2d_fis_splits_the_lba_across_two_groups_of_three_bytes() {
        // **Halves that differ**, because an LBA of zero is written correctly
        // by a version that puts all six bytes in a row and by one that does
        // not. This is the field's whole trap.
        let mut out = [0xffu8; H2D_FIS_BYTES];
        write_h2d(&mut out, command::READ_DMA_EXT, 0x0000_5544_3322_1100, 8).expect("room");
        assert_eq!(out[0], fis::REGISTER_H2D);
        assert_eq!(
            out[1], 0x80,
            "not marked as a command, so nothing is issued"
        );
        assert_eq!(out[2], command::READ_DMA_EXT);
        assert_eq!([out[4], out[5], out[6]], [0x00, 0x11, 0x22], "lba 0..24");
        assert_eq!([out[8], out[9], out[10]], [0x33, 0x44, 0x55], "lba 24..48");
        assert_eq!(out[7] & (1 << 6), 1 << 6, "LBA mode, not CHS");
        assert_eq!([out[12], out[13]], [8, 0], "sector count");
    }

    #[test]
    fn a_command_header_states_its_fis_length_in_dwords_and_not_in_bytes() {
        let mut out = [0xffu8; COMMAND_HEADER_BYTES];
        write_command_header(&mut out, H2D_FIS_BYTES, false, 1, 0x1234_5678_9abc_d000)
            .expect("room");
        let flags = u32::from_le_bytes([out[0], out[1], 0, 0]);
        assert_eq!(flags & 0x1f, 5, "twenty bytes is five dwords");
        assert_eq!(flags & (1 << 6), 0, "a read must not be marked write");
        assert_eq!(u16::from_le_bytes([out[2], out[3]]), 1, "one region");
        assert_eq!(
            u64::from_le_bytes(out[8..16].try_into().unwrap()),
            0x1234_5678_9abc_d000,
            "the table address, both halves"
        );
    }

    #[test]
    fn a_write_command_is_marked_and_a_read_is_not() {
        // Bit 6 tells the controller which way the bytes go. Backwards on a
        // read, it pulls from the memory the disk should be filling.
        let mut read = [0u8; COMMAND_HEADER_BYTES];
        let mut write = [0u8; COMMAND_HEADER_BYTES];
        write_command_header(&mut read, H2D_FIS_BYTES, false, 1, 0).expect("room");
        write_command_header(&mut write, H2D_FIS_BYTES, true, 1, 0).expect("room");
        assert_eq!(read[0] & (1 << 6), 0);
        assert_eq!(write[0] & (1 << 6), 1 << 6);
    }

    #[test]
    fn a_region_stores_one_less_than_its_length() {
        // The field is a count *minus one*. Storing the true count transfers
        // one byte too many, and the thing doing the transfer is a bus master.
        let mut out = [0xffu8; PRD_BYTES];
        write_region(&mut out, 0xdead_0000, 512, false).expect("room");
        assert_eq!(
            u64::from_le_bytes(out[0..8].try_into().unwrap()),
            0xdead_0000
        );
        let word = u32::from_le_bytes(out[12..16].try_into().unwrap());
        assert_eq!(word & 0x003f_ffff, 511, "512 bytes is stored as 511");
        assert_eq!(word & (1 << 31), 0, "no interrupt asked for");
    }

    #[test]
    fn a_region_longer_than_a_descriptor_can_describe_is_refused() {
        let mut out = [0u8; PRD_BYTES];
        assert_eq!(
            write_region(&mut out, 0, PRD_MAX_BYTES + 1, false),
            Err(Error::RegionTooLong)
        );
        // And zero, which would otherwise be stored as 0xffffffff -- a region
        // of four megabytes described by a caller that wanted none.
        assert_eq!(
            write_region(&mut out, 0, 0, false),
            Err(Error::RegionTooLong)
        );
        assert!(write_region(&mut out, 0, PRD_MAX_BYTES, false).is_ok());
    }

    fn identify(setup: impl Fn(&mut [u8])) -> [u8; IDENTIFY_BYTES] {
        let mut words = [0u8; IDENTIFY_BYTES];
        setup(&mut words);
        words
    }

    fn put(words: &mut [u8], index: usize, value: u16) {
        words[index * 2..index * 2 + 2].copy_from_slice(&value.to_le_bytes());
    }

    #[test]
    fn a_48_bit_disk_reports_its_size_from_the_48_bit_words() {
        let words = identify(|w| {
            put(w, 83, 1 << 10);
            put(w, 100, 0x1000);
            put(w, 101, 0x0002);
            // And a *different* value in the 28-bit words, so a parser reading
            // the wrong pair is caught rather than agreeing by accident.
            put(w, 60, 0xffff);
            put(w, 61, 0x00ff);
        });
        let id = read_identity(&words).expect("a disk");
        assert!(id.lba48);
        assert_eq!(id.sectors, 0x0002_1000);
        assert_eq!(id.sector_bytes, 512);
    }

    #[test]
    fn a_disk_without_the_48_bit_bit_is_read_from_the_28_bit_words() {
        // Word 83 bit 10 is the "these words mean something" marker. Reading
        // the 48-bit count without it is reading whatever the device left in
        // words it never filled.
        let words = identify(|w| {
            put(w, 60, 0x8000);
            put(w, 61, 0x0001);
            put(w, 100, 0xdead);
        });
        let id = read_identity(&words).expect("a disk");
        assert!(!id.lba48);
        assert_eq!(id.sectors, 0x0001_8000);
    }

    #[test]
    fn a_large_logical_sector_is_read_only_when_the_word_says_it_is_meaningful() {
        // Word 106's top two bits are the marker: bit 14 set, bit 15 clear.
        // Bit 12 then says the sector is larger than 512.
        let with = identify(|w| {
            put(w, 83, 1 << 10);
            put(w, 100, 8);
            put(w, 106, 0x4000 | (1 << 12));
            put(w, 117, 2048); // words, so 4096 bytes
        });
        assert_eq!(read_identity(&with).expect("a disk").sector_bytes, 4096);

        // The same words with the marker absent must be ignored, not read.
        let without = identify(|w| {
            put(w, 83, 1 << 10);
            put(w, 100, 8);
            put(w, 106, 1 << 12);
            put(w, 117, 2048);
        });
        assert_eq!(read_identity(&without).expect("a disk").sector_bytes, 512);
    }

    #[test]
    fn a_device_that_answers_nonsense_is_refused_rather_than_sizing_a_transfer() {
        // Every one of these has been answered by real firmware at some point,
        // and each would otherwise reach arithmetic that sizes a DMA.
        let empty = identify(|_| {});
        assert_eq!(read_identity(&empty), Err(Error::NotADisk), "no sectors");

        let odd_sector = identify(|w| {
            put(w, 60, 16);
            put(w, 106, 0x4000 | (1 << 12));
            put(w, 117, 3); // six bytes: not a power of two
        });
        assert_eq!(read_identity(&odd_sector), Err(Error::NotADisk));

        let tiny_sector = identify(|w| {
            put(w, 60, 16);
            put(w, 106, 0x4000 | (1 << 12));
            put(w, 117, 128); // 256 bytes, below the floor
        });
        assert_eq!(read_identity(&tiny_sector), Err(Error::NotADisk));

        // A count and a size whose product does not fit. Nothing may multiply
        // these together afterwards without this check having run.
        let enormous = identify(|w| {
            put(w, 83, 1 << 10);
            for index in 100..104 {
                put(w, index, 0xffff);
            }
            put(w, 106, 0x4000 | (1 << 12));
            put(w, 117, 32768);
        });
        assert_eq!(read_identity(&enormous), Err(Error::NotADisk));
    }

    #[test]
    fn a_short_answer_is_refused_rather_than_read_past() {
        let short = [0u8; IDENTIFY_BYTES - 1];
        assert_eq!(read_identity(&short), Err(Error::TooSmall));
        let mut fis = [0u8; H2D_FIS_BYTES - 1];
        assert_eq!(write_h2d(&mut fis, 0, 0, 1), Err(Error::TooSmall));
    }
    #[test]
    fn a_reset_that_never_completes_is_refused_rather_than_waited_on_for_ever() {
        // The deadline, and the whole reason waits here take a clock rather
        // than a spin count: a count is a wait whose length depends on how fast
        // the machine is, so it is either too short on a slow one or a hang on
        // a broken one. The refusal names the register, because "the controller
        // did not come up" sends a reader nowhere.
        let mut controller = Controller::new().wedged();
        let mut clock = ticking();
        assert_eq!(
            bring_up(&mut controller, &mut clock, 32),
            Err(NotUp::NotSettled("GHC.HR"))
        );
    }

    #[test]
    fn ahci_mode_is_set_again_after_the_reset_because_the_reset_cleared_it() {
        // Set once, and the controller is programmed with AHCI's register file
        // and then handed back to legacy mode, where those offsets mean
        // something else entirely.
        let mut controller = Controller::new();
        let mut clock = ticking();
        bring_up(&mut controller, &mut clock, PATIENT).expect("comes up");
        // **The count alone is not the property, and asserting it was this
        // test's own bug for one mutation round.** The write that sets `HR`
        // carries `AE` too, because it is a read-modify-write of a register
        // that already had it -- so "AE was written twice" is true of a driver
        // that never re-asserts it. What matters is the *order*: an `AE` write
        // strictly after the last `HR` write.
        let last_reset = controller
            .writes()
            .iter()
            .rposition(|(at, v)| *at == ghc::GHC && v & ghc::HR != 0)
            .expect("the controller was reset at all");
        let enabled_after = controller
            .writes()
            .iter()
            .rposition(|(at, v)| *at == ghc::GHC && v & ghc::AE != 0 && v & ghc::HR == 0)
            .expect("AHCI mode was enabled at all");
        assert!(
            enabled_after > last_reset,
            "AHCI enable was never re-asserted after the reset that clears it"
        );
        // And it was on before the reset too: a controller still in legacy mode
        // is a controller whose GHC is not the one being reset.
        let enabled_first = controller
            .writes()
            .iter()
            .position(|(at, v)| *at == ghc::GHC && v & ghc::AE != 0)
            .expect("enabled at all");
        assert!(
            enabled_first < last_reset,
            "AHCI mode must be on before the reset"
        );
    }

    #[test]
    fn a_controller_with_no_handoff_is_never_written_at_the_handoff_register() {
        // `CAP2.BOH` is what says a `BOHC` register exists. Without it the
        // offset is reserved, and writing a reserved offset of a bus master is
        // the kind of thing that works on the emulator it was tried on.
        let mut controller = Controller::new();
        let mut clock = ticking();
        let started = bring_up(&mut controller, &mut clock, PATIENT).expect("comes up");
        assert!(!controller.wrote(ghc::BOHC));
        assert!(!started.took_from_firmware);
    }

    #[test]
    fn the_handoff_waits_for_the_firmware_to_drop_its_semaphore() {
        let mut controller = Controller::new().with_firmware();
        let mut clock = ticking();
        let started = bring_up(&mut controller, &mut clock, PATIENT).expect("comes up");
        assert!(started.took_from_firmware);
        // Asked for, and asked for *before* the reset -- a reset while the
        // firmware still owns the controller is two owners resetting one device.
        let asked = controller.write_index(ghc::BOHC).expect("asked");
        let reset = controller
            .writes()
            .iter()
            .position(|(at, v)| *at == ghc::GHC && v & ghc::HR != 0)
            .expect("reset");
        assert!(asked < reset);
    }

    #[test]
    fn firmware_that_never_lets_go_is_refused_by_name() {
        let mut controller = Controller::new().with_firmware().firmware_never_lets_go();
        let mut clock = ticking();
        assert_eq!(
            bring_up(&mut controller, &mut clock, 32),
            Err(NotUp::NotSettled("BOHC.BOS"))
        );
    }

    #[test]
    fn only_the_ports_the_bitmap_names_are_touched() {
        // `PI` is a bitmap, not a count. A controller is entitled to implement
        // port 5 and nothing below it, and a loop over 0..32 would read -- and
        // *write* -- registers of ports that do not exist.
        let mut controller = Controller::new()
            .with_ports(1 << 5)
            .with_status(5, ssts::DET_PRESENT);
        let mut clock = ticking();
        let started = bring_up(&mut controller, &mut clock, PATIENT).expect("comes up");
        assert_eq!(started.port_count, 1);
        assert_eq!(started.ports().next().map(|p| p.index), Some(5));
        for absent in [0usize, 1, 4, 6, 31] {
            assert!(
                !controller.wrote(port_at(absent, port::CMD)),
                "port {absent} is not implemented and was written anyway"
            );
        }
    }

    #[test]
    fn a_port_is_stopped_by_both_engines_and_waited_on_for_both() {
        // `ST` drives the command engine and `FRE` the FIS receive engine, and
        // they stop independently. Clearing `ST` and waiting only for `CR`
        // leaves the controller still writing received FISes into the area
        // about to be given a new address.
        let mut controller = Controller::new();
        let mut clock = ticking();
        bring_up(&mut controller, &mut clock, PATIENT).expect("comes up");
        let stop = controller
            .writes()
            .iter()
            .find(|(at, _)| *at == port_at(0, port::CMD))
            .expect("the port was stopped");
        assert_eq!(stop.1 & cmd::ST, 0, "the command engine was left running");
        assert_eq!(stop.1 & cmd::FRE, 0, "fis receive was left running");

        // And **both** waits are real, which needs two controllers rather than
        // one. A controller whose engines both hang is refused by the first
        // wait, so it cannot tell whether the second exists at all -- that was
        // this test's own bug for one mutation round, and removing the `FR`
        // wait left it green.
        let mut no_command_engine = Controller::new().command_engine_never_stops();
        let mut clock = ticking();
        assert_eq!(
            bring_up(&mut no_command_engine, &mut clock, 32),
            Err(NotUp::NotSettled("PxCMD.CR"))
        );

        // The command engine stops and the FIS receive engine does not. Only a
        // driver that waits for `FR` on its own account notices.
        let mut no_fis_engine = Controller::new().fis_engine_never_stops();
        let mut clock = ticking();
        assert_eq!(
            bring_up(&mut no_fis_engine, &mut clock, 32),
            Err(NotUp::NotSettled("PxCMD.FR"))
        );
    }

    #[test]
    fn a_ports_registers_are_eighty_hex_apart_and_not_forty() {
        // The trap. With a 0x40 stride every odd port's registers land on top
        // of an even port's, which is not a failure: it is a driver reporting a
        // disk on a port that has none.
        assert_eq!(port_at(0, port::CMD), 0x118);
        assert_eq!(port_at(1, port::CMD), 0x198);
        assert_eq!(port_at(1, port::CLB), 0x180);
        assert_eq!(port_at(31, port::CI), 0x100 + 31 * 0x80 + 0x38);
        // No two ports may share a register, which is the property the stride
        // exists for and the one a wrong stride breaks.
        assert_ne!(port_at(1, port::CLB), port_at(0, port::CLB));
        assert!(port_at(1, port::CLB) >= port_at(0, port::CI) + 4);
    }

    #[test]
    fn a_device_that_will_not_talk_is_not_a_disk() {
        // `DET` of 1 is a device attached whose link will not come up, and `3`
        // is one communicating. Treating any non-zero value as a disk turns a
        // fault into a device that later refuses every command for reasons
        // nobody logged.
        let mut controller = Controller::new()
            .with_ports(0b111)
            .with_status(0, ssts::DET_NONE)
            .with_status(1, ssts::DET_PRESENT_NO_COMMS)
            .with_status(2, ssts::DET_PRESENT);
        let mut clock = ticking();
        let started = bring_up(&mut controller, &mut clock, PATIENT).expect("comes up");
        let seen: [bool; 3] = [
            started.ports[0].has_device(),
            started.ports[1].has_device(),
            started.ports[2].has_device(),
        ];
        assert_eq!(seen, [false, false, true]);
        // And the difference is kept, not flattened: an empty port and a port
        // that will not talk are different things to whoever is standing at the
        // machine.
        assert_ne!(started.ports[0].det, started.ports[1].det);
    }

    #[test]
    fn both_halves_of_every_address_are_written_low_first() {
        // Firmware leaves values in these registers. A driver that writes only
        // the low half of a 32-bit address leaves the firmware's high bits in
        // place, and the controller reads its command list from an address
        // nowhere near the one it was given -- as a bus master.
        let mut controller = Controller::new();
        let mut clock = ticking();
        let started = bring_up(&mut controller, &mut clock, PATIENT).expect("comes up");
        controller.written = 0;
        start_port(&mut controller, &started, 0, 0x2000, 0x3000).expect("starts");

        for (low, high) in [(port::CLB, port::CLBU), (port::FB, port::FBU)] {
            let low_at = controller
                .write_index(port_at(0, low))
                .expect("the low half was written");
            let high_at = controller
                .write_index(port_at(0, high))
                .expect("the high half was written even though it is zero");
            assert!(low_at < high_at, "the high half must follow the low");
        }
        assert_eq!(controller.file[port_at(0, port::CLB) / 4], 0x2000);
        assert_eq!(controller.file[port_at(0, port::CLBU) / 4], 0);
    }

    #[test]
    fn a_misaligned_structure_is_refused_rather_than_silently_moved() {
        // The controller ignores the low bits rather than refusing, so an
        // unaligned address is a structure quietly read from somewhere else.
        let mut controller = Controller::new();
        let mut clock = ticking();
        let started = bring_up(&mut controller, &mut clock, PATIENT).expect("comes up");
        assert_eq!(
            start_port(&mut controller, &started, 0, 0x2200, 0x3000),
            Err(NotUp::Misaligned("command list"))
        );
        assert_eq!(
            start_port(&mut controller, &started, 0, 0x2000, 0x3010),
            Err(NotUp::Misaligned("received fis"))
        );
        // And a port the bitmap never named.
        assert_eq!(
            start_port(&mut controller, &started, 3, 0x2000, 0x3000),
            Err(NotUp::NoSuchPort)
        );
    }

    #[test]
    fn a_thirty_two_bit_controller_is_never_given_an_address_it_cannot_reach() {
        // `CAP.S64A` is the controller's own answer, and without it every
        // structure must live below 4 GiB. Handing one a 64-bit address writes
        // the high half into a register it does not implement and leaves it
        // reading the low half alone.
        let mut controller = Controller::new();
        controller.file[ghc::CAP / 4] &= !cap::S64A;
        let mut clock = ticking();
        let started = bring_up(&mut controller, &mut clock, PATIENT).expect("comes up");
        assert!(!started.sixty_four_bit);
        assert_eq!(
            start_port(&mut controller, &started, 0, 0x1_0000_0000, 0x3000),
            Err(NotUp::Above4Gib)
        );
        assert!(start_port(&mut controller, &started, 0, 0x2000, 0x3000).is_ok());
    }

    #[test]
    fn the_slot_count_is_the_controllers_number_and_is_bounded_before_it_is_used() {
        // RFC 0038 rule 6. `NCS` holds one less than the count, so the field's
        // maximum is 32 and there is no such thing as a port with no slots --
        // but the bound is here rather than assumed, because the number is the
        // controller's and a command list is sized from it.
        let mut controller = Controller::new();
        let mut clock = ticking();
        assert_eq!(
            bring_up(&mut controller, &mut clock, PATIENT)
                .expect("comes up")
                .slots,
            32
        );

        // Exhaustive over every value the field can hold, because the claim is
        // about the *mask* and a spot check of two values is not about the mask
        // at all. A wider mask -- the plausible wrong edit -- puts a controller's
        // reserved bits into a number that sizes a command list.
        for ncs in 0..=cap::NCS_MASK {
            let mut one = Controller::new();
            one.file[ghc::CAP / 4] = cap::S64A | (ncs << cap::NCS_SHIFT);
            let mut clock = ticking();
            let started = bring_up(&mut one, &mut clock, PATIENT).expect("comes up");
            assert_eq!(u32::from(started.slots), ncs + 1);
            assert!(started.slots >= 1, "no port has zero command slots");
            assert!(
                usize::from(started.slots) <= COMMAND_SLOTS,
                "ncs {ncs} gave {} slots, past the {COMMAND_SLOTS} a command list holds",
                started.slots
            );
        }
        // And the reserved bits above the field never reach it.
        let mut noisy = Controller::new();
        noisy.file[ghc::CAP / 4] = cap::S64A | (0xff << cap::NCS_SHIFT);
        let mut clock = ticking();
        let started = bring_up(&mut noisy, &mut clock, PATIENT).expect("comes up");
        assert_eq!(usize::from(started.slots), COMMAND_SLOTS);
    }

    #[test]
    fn a_controller_implementing_no_ports_is_refused_rather_than_reported_empty() {
        // Distinct from "every port is empty", which is a normal machine. `PI`
        // of zero is a controller with nothing to drive, and answering `Ok`
        // with an empty list would send the next step looking for a disk on a
        // controller that has no ports to put one on.
        let mut controller = Controller::new().with_ports(0);
        let mut clock = ticking();
        assert_eq!(
            bring_up(&mut controller, &mut clock, PATIENT),
            Err(NotUp::NoPortsImplemented)
        );
    }
}
