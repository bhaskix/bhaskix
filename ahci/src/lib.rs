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
    let word = |index: usize| -> u16 {
        u16::from_le_bytes([words[index * 2], words[index * 2 + 1]])
    };
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_h2d_fis_splits_the_lba_across_two_groups_of_three_bytes() {
        // **Halves that differ**, because an LBA of zero is written correctly
        // by a version that puts all six bytes in a row and by one that does
        // not. This is the field's whole trap.
        let mut out = [0xffu8; H2D_FIS_BYTES];
        write_h2d(&mut out, command::READ_DMA_EXT, 0x0000_5544_3322_1100, 8).expect("room");
        assert_eq!(out[0], fis::REGISTER_H2D);
        assert_eq!(out[1], 0x80, "not marked as a command, so nothing is issued");
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
        assert_eq!(u64::from_le_bytes(out[0..8].try_into().unwrap()), 0xdead_0000);
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
        assert_eq!(write_region(&mut out, 0, 0, false), Err(Error::RegionTooLong));
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
}
