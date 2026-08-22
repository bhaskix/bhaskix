// SPDX-License-Identifier: Apache-2.0
// Adapted from the `xhci` crate, Copyright (c) 2021 Hiroki Tokunaga.
// Upstream: https://github.com/rust-osdev/xhci, version 0.9.2, MIT OR Apache-2.0.
//! Runtime registers: the microframe counter, and the interrupters.
//!
//! These begin at `RTSOFF` bytes past the window base. An **interrupter** is
//! how the controller tells the driver something happened: it owns an event
//! ring, and the driver acknowledges what it has consumed by writing back a
//! dequeue pointer.

use crate::{bit32, bits32, bits64};

/// Byte offsets from the start of the runtime bank, which is the window base
/// plus `RTSOFF`.
pub mod offset {
    /// `MFINDEX` — the microframe counter.
    pub const MFINDEX: usize = 0x00;
    /// Where the interrupter register sets begin.
    pub const INTERRUPTERS: usize = 0x20;
    /// Bytes per interrupter register set.
    pub const INTERRUPTER_STRIDE: usize = 0x20;
}

/// Byte offsets **within one interrupter register set**.
pub mod interrupter {
    /// `IMAN` — interrupt pending and enable.
    pub const IMAN: usize = 0x00;
    /// `IMOD` — interrupt moderation.
    pub const IMOD: usize = 0x04;
    /// `ERSTSZ` — how many segments the event ring segment table has.
    pub const ERSTSZ: usize = 0x08;
    /// `ERSTBA` — where that table is. 64-bit, **64-byte aligned**.
    pub const ERSTBA: usize = 0x10;
    /// `ERDP` — how far the driver has consumed. 64-bit, **16-byte aligned**.
    pub const ERDP: usize = 0x18;
}

/// Interrupters the specification allows: 1024 (xHCI §5.3.3).
///
/// **The field is wider than the limit, and the gap is the interesting part.**
/// `HCSPARAMS1`'s interrupter count occupies bits 18:8 — eleven bits, which can
/// encode 2047 — while the specification's valid range stops at 1024. So a
/// controller *can* report a number the architecture does not permit, and a
/// driver that believed the field width rather than the limit would index
/// beyond any register set that exists.
///
/// That is not a hypothetical distinction for an emulated or hostile
/// controller, which is why this constant is the limit and not the field
/// width. It is still only a backstop: the number that actually bounds a
/// driver is the count the controller reported, and this catches the case
/// where that count is itself a lie.
///
/// The first version of this constant was `1 << 11`, and the test below caught
/// it.
pub const MAX_INTERRUPTERS: u16 = 1024;

/// Offset of interrupter `index`'s register set, relative to the runtime bank.
///
/// **Bounded, and the bound is the point.** The interrupter index reaches
/// straight into an offset calculation, so an unchecked one is an MMIO access
/// outside the controller's window — which on a mapped region is a read or
/// write of whatever is mapped next. Answers `None` past the architectural
/// ceiling; the caller is still responsible for checking against the count in
/// `HCSPARAMS1`, which is smaller on every real controller.
#[must_use]
pub const fn interrupter_at(index: u16) -> Option<usize> {
    if index >= MAX_INTERRUPTERS {
        return None;
    }
    Some(offset::INTERRUPTERS + offset::INTERRUPTER_STRIDE * index as usize)
}

/// `MFINDEX`: the microframe counter, bits 13:0.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MicroframeIndex(pub u32);

impl MicroframeIndex {
    /// The counter. Fourteen bits, wrapping.
    #[must_use]
    pub const fn microframe_index(self) -> u32 {
        bits32(self.0, 0, 13)
    }
}

/// `IMAN`: whether this interrupter has something pending, and whether it may
/// raise an interrupt.
///
/// **Bit 0 is write-one-to-clear.** See [`InterrupterManagement::acknowledging`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct InterrupterManagement(pub u32);

impl InterrupterManagement {
    /// Bit 0, write-one-to-clear. Something is pending.
    #[must_use]
    pub const fn interrupt_pending(self) -> bool {
        bit32(self.0, 0)
    }

    /// Bit 1. The interrupter may raise an interrupt.
    #[must_use]
    pub const fn interrupt_enable(self) -> bool {
        bit32(self.0, 1)
    }

    /// The one write-one-to-clear bit in this register.
    pub const WRITE_ONE_TO_CLEAR: u32 = 1;

    /// With interrupts enabled or disabled, **without acknowledging anything**.
    ///
    /// The whole reason this is not a bare bit-set: enabling an interrupter by
    /// reading `IMAN`, setting bit 1 and writing it back also writes bit 0 if
    /// it happened to be set, which acknowledges an event the driver has not
    /// looked at. The event is not redelivered. What that looks like is an
    /// interrupter that goes quiet under load, occasionally, on one machine.
    #[must_use]
    pub const fn with_interrupt_enable(self, enable: bool) -> Self {
        let without_pending = self.0 & !Self::WRITE_ONE_TO_CLEAR;
        Self(if enable {
            without_pending | (1 << 1)
        } else {
            without_pending & !(1 << 1)
        })
    }

    /// The value to write to acknowledge the pending flag and nothing else.
    #[must_use]
    pub const fn acknowledging(self) -> Self {
        Self((self.0 & !Self::WRITE_ONE_TO_CLEAR) | 1)
    }
}

/// `IMOD`: how often this interrupter is allowed to interrupt.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct InterrupterModeration(pub u32);

impl InterrupterModeration {
    /// Bits 15:0 — the interval, in 250 ns units.
    ///
    /// **Zero disables moderation**, which means an interrupt per event. That
    /// is the reset value on some controllers and is a livelock risk under a
    /// fast device, so a driver should set this rather than accept it.
    #[must_use]
    pub const fn interval(self) -> u16 {
        bits32(self.0, 0, 15) as u16
    }

    /// Bits 31:16 — the down-counter.
    #[must_use]
    pub const fn counter(self) -> u16 {
        bits32(self.0, 16, 31) as u16
    }

    /// With the interval set, in 250 ns units.
    #[must_use]
    pub const fn with_interval(self, interval: u16) -> Self {
        Self((self.0 & !0xffff) | interval as u32)
    }
}

/// `ERSTSZ`: how many segments the event ring segment table holds, bits 15:0.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct EventRingSegmentTableSize(pub u32);

impl EventRingSegmentTableSize {
    /// The segment count.
    #[must_use]
    pub const fn size(self) -> u16 {
        bits32(self.0, 0, 15) as u16
    }

    /// With the segment count set.
    ///
    /// **Must not exceed `HCSPARAMS2`'s maximum**, and must match the table the
    /// driver actually allocated: this number is how many entries the
    /// controller will read, and it reads them by DMA. A count larger than the
    /// allocation is the controller reading past it.
    #[must_use]
    pub const fn with_size(self, size: u16) -> Self {
        Self((self.0 & !0xffff) | size as u32)
    }
}

/// `ERSTBA`: where the event ring segment table is.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct EventRingSegmentTableBaseAddress(pub u64);

impl EventRingSegmentTableBaseAddress {
    /// The table's physical address.
    #[must_use]
    pub const fn pointer(self) -> u64 {
        self.0 & !0x3f
    }

    /// A value pointing at `address`.
    ///
    /// # Errors
    ///
    /// `None` unless `address` is **64-byte** aligned — note that this differs
    /// from [`EventRingDequeuePointer`], which is 16-byte aligned. Two pointers
    /// in the same register set with different alignments is exactly the detail
    /// a transcription gets wrong, so each is enforced separately rather than
    /// through a shared helper that would have to pick one.
    #[must_use]
    pub const fn with_pointer(address: u64) -> Option<Self> {
        if address & 0x3f != 0 {
            return None;
        }
        Some(Self(address))
    }
}

/// `ERDP`: how far the driver has consumed the event ring.
///
/// **Bit 3 is write-one-to-clear**, and bits 2:0 are the segment index rather
/// than address — so this register cannot be written by handing it an address.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct EventRingDequeuePointer(pub u64);

impl EventRingDequeuePointer {
    /// Bits 2:0 — which segment of the table the dequeue pointer is in.
    #[must_use]
    pub const fn segment_index(self) -> u8 {
        bits64(self.0, 0, 2) as u8
    }

    /// Bit 3, write-one-to-clear. The controller is still working on events.
    #[must_use]
    pub const fn event_handler_busy(self) -> bool {
        self.0 & (1 << 3) != 0
    }

    /// The dequeue address, with the flags masked out.
    #[must_use]
    pub const fn pointer(self) -> u64 {
        self.0 & !0b1111
    }

    /// The one write-one-to-clear bit in this register.
    pub const WRITE_ONE_TO_CLEAR: u64 = 1 << 3;

    /// A value advancing the dequeue pointer to `address` in `segment`.
    ///
    /// `clear_busy` writes the event-handler-busy bit, which acknowledges that
    /// the driver has finished with the events it read. **Passing `false`
    /// leaves it set**, which is the correct choice while more events remain —
    /// and passing `true` when events remain unread tells the controller it may
    /// overwrite them.
    ///
    /// # Errors
    ///
    /// `None` unless `address` is **16-byte** aligned — a different alignment
    /// from `ERSTBA` above — or `segment` does not fit in three bits. A
    /// misaligned address here does not fault: its low bits are read as the
    /// segment index and the busy flag, so the controller is silently told a
    /// different segment and a different intent.
    #[must_use]
    pub const fn advancing(address: u64, segment: u8, clear_busy: bool) -> Option<Self> {
        if address & 0b1111 != 0 || segment > 0b111 {
            return None;
        }
        let busy = if clear_busy {
            Self::WRITE_ONE_TO_CLEAR
        } else {
            0
        };
        Some(Self(address | segment as u64 | busy))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The transcription test: offsets written a second time, as literals.
    #[test]
    fn every_runtime_register_is_where_the_specification_puts_it() {
        assert_eq!(offset::MFINDEX, 0x00);
        assert_eq!(offset::INTERRUPTERS, 0x20);
        assert_eq!(offset::INTERRUPTER_STRIDE, 0x20);
        assert_eq!(interrupter::IMAN, 0x00);
        assert_eq!(interrupter::IMOD, 0x04);
        assert_eq!(interrupter::ERSTSZ, 0x08);
        assert_eq!(interrupter::ERSTBA, 0x10);
        assert_eq!(interrupter::ERDP, 0x18);
    }

    #[test]
    fn there_is_a_reserved_dword_before_erstba() {
        // ERSTSZ is at 0x08 and ERSTBA at 0x10, not 0x0c: the dword between
        // them is reserved. A table packed without it puts every register from
        // here on four bytes early.
        assert_eq!(interrupter::ERSTBA - interrupter::ERSTSZ, 8);
    }

    #[test]
    fn interrupters_start_after_mfindex_and_are_bounded() {
        assert_eq!(interrupter_at(0), Some(0x20));
        assert_eq!(interrupter_at(1), Some(0x40));
        assert_eq!(interrupter_at(1023), Some(0x20 + 0x20 * 1023));
        // 1024 is the specification's limit, so index 1024 is the first that
        // does not exist. Answering with an offset would be an MMIO access
        // outside the controller's window.
        assert_eq!(interrupter_at(1024), None);
        assert_eq!(interrupter_at(u16::MAX), None);
    }

    /// **The bound is the specification's, not the field's, and they differ.**
    ///
    /// Bits 18:8 can encode 2047; xHCI §5.3.3 permits 1024. A controller that
    /// reports something in between is out of specification, and a driver that
    /// sized its bound by the field would follow it there. This test exists
    /// because the constant was written as `1 << 11` first.
    #[test]
    fn the_bound_is_the_limit_and_not_the_width_of_the_field() {
        assert_eq!(MAX_INTERRUPTERS, 1024);
        assert!(
            interrupter_at(1500).is_none(),
            "encodable, but not permitted"
        );
        assert!(interrupter_at(2047).is_none(), "the field's maximum");
    }

    #[test]
    fn interrupter_zero_does_not_overlap_mfindex() {
        // The first interrupter is at 0x20, not 0x00. Getting this wrong makes
        // every IMAN write land on the microframe counter.
        assert!(interrupter_at(0).expect("exists") > offset::MFINDEX);
    }

    /// **The write-one-to-clear test for `IMAN`.**
    #[test]
    fn enabling_an_interrupter_does_not_acknowledge_a_pending_event() {
        // Pending set, as it would be with an event waiting.
        let read = InterrupterManagement(1);
        assert!(read.interrupt_pending());

        let write = read.with_interrupt_enable(true);
        assert!(write.interrupt_enable());
        // Bit 0 must not be in the written value, or the event is acknowledged
        // without having been read. Asserted as a literal rather than through
        // WRITE_ONE_TO_CLEAR, so that deleting the constant's bit cannot delete
        // the check with it.
        assert_eq!(write.0 & 1, 0, "the pending event would have been lost");
    }

    #[test]
    fn acknowledging_iman_sets_only_the_pending_bit() {
        let write = InterrupterManagement(0b10).acknowledging();
        assert_eq!(write.0 & 1, 1);
        // And leaves enable where it was.
        assert!(write.interrupt_enable());
    }

    #[test]
    fn the_two_pointers_have_different_alignments() {
        // ERSTBA is 64-byte aligned...
        assert!(EventRingSegmentTableBaseAddress::with_pointer(0x1_0000).is_some());
        assert!(EventRingSegmentTableBaseAddress::with_pointer(0x1_0010).is_none());
        // ...and ERDP is 16-byte, in the same register set. An address legal
        // for one is not necessarily legal for the other, and this is the test
        // that stops a shared helper being introduced.
        assert!(EventRingDequeuePointer::advancing(0x1_0010, 0, false).is_some());
        assert!(EventRingDequeuePointer::advancing(0x1_0008, 0, false).is_none());
    }

    #[test]
    fn the_dequeue_pointer_carries_its_segment_without_corrupting_the_address() {
        let p = EventRingDequeuePointer::advancing(0xdead_be00, 5, false).expect("aligned");
        assert_eq!(p.pointer(), 0xdead_be00);
        assert_eq!(p.segment_index(), 5);
        // Busy not written, so events still being read are not released.
        assert_eq!(p.0 & (1 << 3), 0);
    }

    #[test]
    fn clearing_event_handler_busy_is_explicit() {
        let p = EventRingDequeuePointer::advancing(0x2000, 0, true).expect("aligned");
        assert_eq!(p.0 & (1 << 3), 1 << 3);
        // And the address survives the flag.
        assert_eq!(p.pointer(), 0x2000);
    }

    #[test]
    fn a_segment_index_that_does_not_fit_is_refused() {
        // Three bits. An eighth segment would overflow into the busy bit and
        // release events the driver has not read.
        assert!(EventRingDequeuePointer::advancing(0x2000, 7, false).is_some());
        assert!(EventRingDequeuePointer::advancing(0x2000, 8, false).is_none());
    }

    #[test]
    fn moderation_interval_replaces_rather_than_accumulates() {
        let m = InterrupterModeration(0xffff_ffff).with_interval(4000);
        assert_eq!(m.interval(), 4000);
        // The counter half is untouched.
        assert_eq!(m.counter(), 0xffff);
    }

    #[test]
    fn the_segment_table_size_is_sixteen_bits() {
        let s = EventRingSegmentTableSize(0).with_size(u16::MAX);
        assert_eq!(s.size(), u16::MAX);
    }
}
