// SPDX-License-Identifier: Apache-2.0
//! The slot disk, from the loader's side -- RFC 0100 step 1.
//!
//! Finds a whole disk whose GPT names a slot record and two slots, reads the
//! record, and asks `bhaskix-slotdisk` what to boot. Every decision is that
//! crate's host-tested arithmetic; this module is the firmware reads, and the
//! one write the loader makes: the record, when a trial spends a boot.

use bhaskix_slotdisk::{
    self as slotdisk, BLOCK, File, Header, Layout, Partition, Record, SetHeader,
};

use crate::efi::{self, Disk, SystemTable};
use crate::serial;

/// Pages of scratch this module reads small structures into: the GPT header
/// and its entry array (16 KiB for 128 entries), the record, a slot's header.
/// Page-aligned, because a disk's Block I/O may require it.
const SCRATCH_PAGES: usize = 5;

/// A slot disk, found.
pub struct SlotDisk {
    /// The disk.
    pub disk: Disk,
    /// Its three partitions.
    pub layout: Layout,
    /// The record, or why it was not believed.
    pub record: Result<Record, slotdisk::Refusal>,
    scratch: &'static mut [u8],
}

/// Looks for a slot disk among the firmware's whole disks. `None` is the
/// common case -- no such disk -- and the loader reads its set from the ESP
/// exactly as before.
pub fn find(table: *mut SystemTable) -> Option<SlotDisk> {
    let base = efi::allocate_pages(table, efi::LOADER_DATA, SCRATCH_PAGES).ok()?;
    // SAFETY: just allocated, sized as passed, owned by this loader until the
    // map is handed over.
    let scratch = unsafe { crate::pages_as_slice(base, SCRATCH_PAGES) };
    let mut found: Option<(Disk, Layout)> = None;
    efi::whole_disks(table, |disk| {
        if disk.read(1, &mut scratch[..BLOCK]).is_err() {
            return false;
        }
        let Ok(header) = Header::parse(&scratch[..BLOCK]) else {
            return false;
        };
        let bytes = header.entries_bytes();
        if bytes > scratch.len()
            || disk
                .read(
                    header.entries_at,
                    &mut scratch[..header.entries_blocks() as usize * BLOCK],
                )
                .is_err()
        {
            return false;
        }
        match Layout::find(&header, &scratch[..bytes]) {
            Ok(layout) if layout.b.last <= disk.last_block => {
                found = Some((disk, layout));
                true
            }
            _ => false,
        }
    });
    let (disk, layout) = found?;
    let record = disk
        .read(layout.record.first, &mut scratch[..BLOCK])
        .map_err(|_| slotdisk::Refusal::Short)
        .and_then(|()| Record::parse(&scratch[..BLOCK]));
    Some(SlotDisk {
        disk,
        layout,
        record,
        scratch,
    })
}

impl SlotDisk {
    /// Writes the record the plan asks for: the one block this loader writes.
    pub fn write_record(&mut self, record: &Record) -> Result<(), usize> {
        self.scratch[..BLOCK].copy_from_slice(&record.to_block());
        self.disk
            .write_and_flush(self.layout.record.first, &self.scratch[..BLOCK])
    }

    /// Reads `slot`'s header, the block the set's files are named in.
    pub fn header(&mut self, slot: Partition) -> Result<SetHeader, slotdisk::Refusal> {
        self.disk
            .read(slot.first, &mut self.scratch[..BLOCK])
            .map_err(|_| slotdisk::Refusal::Short)?;
        SetHeader::parse(&self.scratch[..BLOCK], slot.bytes())
    }

    /// Reads `file` of the set in `slot` into `buffer`, and returns its
    /// length. A file longer than the buffer is refused, as one on the ESP
    /// is. A page-aligned buffer -- the kernel's and the initrd's -- is read
    /// into directly; any other goes through the scratch pages, because a
    /// disk's Block I/O may require an alignment a stack array does not have.
    pub fn read(
        &mut self,
        slot: Partition,
        header: &SetHeader,
        file: File,
        buffer: &mut [u8],
    ) -> Result<usize, crate::Unread> {
        let (first, length) = header.locate(file);
        let length = usize::try_from(length).map_err(|_| crate::Unread::TooLarge)?;
        if length > buffer.len() {
            return Err(crate::Unread::TooLarge);
        }
        let whole = length.div_ceil(BLOCK) * BLOCK;
        let direct = (buffer.as_ptr() as usize).is_multiple_of(4096) && whole <= buffer.len();
        // A mebibyte at a time, a dot each, as the ESP path reads.
        let step = if direct { 1 << 20 } else { self.scratch.len() };
        let mut done = 0usize;
        while done < whole {
            let take = (whole - done).min(step);
            let lba = slot.first + first + (done / BLOCK) as u64;
            if direct {
                self.disk
                    .read(lba, &mut buffer[done..done + take])
                    .map_err(crate::Unread::Firmware)?;
            } else {
                self.disk
                    .read(lba, &mut self.scratch[..take])
                    .map_err(crate::Unread::Firmware)?;
                let keep = take.min(length - done);
                buffer[done..done + keep].copy_from_slice(&self.scratch[..keep]);
            }
            done += take;
            serial::write(".");
        }
        serial::write("\r\n");
        Ok(length)
    }
}
