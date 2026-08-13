// SPDX-License-Identifier: Apache-2.0
//! A ring buffer laid out in shared memory.
//!
//! [RFC 0009](../../docs/rfc/0009-shared-memory.md) step 5: the channel that
//! makes a shared region useful. A `Memory` object gives two domains the same
//! frames; this says what to put in them so that both sides agree, and — more
//! importantly — so that the side doing the reading cannot be talked into
//! anything by the side doing the writing.
//!
//! # This module touches no memory, and that is the design
//!
//! `abi`'s `unsafe` budget is zero, and this module keeps it there. It
//! computes *where* bytes go and *whether* a pair of indices can be believed;
//! the loads and stores belong to whoever owns the mapping, because that side
//! is the one that can state the safety obligation. A ring type that
//! dereferenced a pointer would have to be handed one, and a pointer handed
//! across this boundary is the thing shared memory exists to avoid.
//!
//! # The double fetch, and why the API is shaped like this
//!
//! Both sides can write to the region. So **anything read out of it can change
//! between two reads of it** — the double-fetch bug, which is a recurring
//! source of kernel vulnerabilities elsewhere and is the price RFC 0009 paid
//! for zero-copy.
//!
//! The rule is *copy out, then validate the copy, then use the copy*. A value
//! validated in shared memory and then used from shared memory has been
//! validated once and used once, on two possibly different values.
//!
//! [`Cursor`] enforces that by shape rather than by documentation: it is
//! constructed from **numbers**, not from a reference to the region, so there
//! is nothing left to re-read. A caller physically cannot validate one value
//! and use another, because by the time it has a `Cursor` the region is out of
//! the picture.
//!
//! # Indices are free-running
//!
//! `head` and `tail` count bytes ever written and ever read, and wrap at
//! `u64`. They are masked into the buffer only when an offset is needed. The
//! alternative — indices already reduced modulo the capacity — makes
//! `head == tail` mean both "empty" and "full", and the usual fix is to waste
//! a byte or keep a third field that can disagree with the other two.

/// Bytes of header before the data.
///
/// Sixty-four so that the two indices sit in different cache lines: the
/// producer writes one and the consumer writes the other, and sharing a line
/// between them turns every message into a cache-line ping-pong. It is also
/// room to grow the header without moving the data.
pub const HEADER_BYTES: usize = 64;

/// Byte offset of the producer's index within the region.
pub const HEAD_OFFSET: usize = 0;
/// Byte offset of the consumer's index.
pub const TAIL_OFFSET: usize = 32;
/// Byte offset of the data.
pub const DATA_OFFSET: usize = HEADER_BYTES;

/// Where a ring's parts are, for a region of a given size.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Layout {
    capacity: usize,
}

impl Layout {
    /// Describes a ring in a region of `length` bytes.
    ///
    /// The capacity is the largest power of two that fits after the header.
    /// A power of two because masking an index is then one instruction and
    /// cannot be got wrong; the bytes it wastes are at most half of what is
    /// left, and a region is chosen by the program rather than found.
    ///
    /// Returns `None` if the region cannot hold a header and at least one
    /// byte — a ring with no room is not a small ring, it is a mistake.
    #[must_use]
    pub const fn for_region(length: usize) -> Option<Self> {
        if length <= HEADER_BYTES {
            return None;
        }
        let usable = length - HEADER_BYTES;
        // Largest power of two not exceeding `usable`.
        let capacity = 1usize << (usize::BITS - 1 - usable.leading_zeros());
        if capacity == 0 {
            return None;
        }
        Some(Self { capacity })
    }

    /// Bytes the ring can hold.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Where the data starts.
    #[must_use]
    pub const fn data_offset(&self) -> usize {
        DATA_OFFSET
    }

    /// The offset within the region of the byte at free-running index `at`.
    #[must_use]
    pub const fn offset_of(&self, at: u64) -> usize {
        DATA_OFFSET + (at as usize & (self.capacity - 1))
    }
}

/// A validated snapshot of a ring's two indices.
///
/// Constructed from values already copied out of shared memory. There is no
/// constructor that takes the region, and that is deliberate — see the module
/// header on double fetches.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Cursor {
    head: u64,
    tail: u64,
    capacity: usize,
}

impl Cursor {
    /// Validates a pair of indices read out of a region.
    ///
    /// Returns `None` when they cannot both be true — the consumer ahead of
    /// the producer, or more bytes outstanding than the ring can hold. Either
    /// means the other side is broken or hostile, and **the answer is to
    /// refuse rather than to clamp**: a clamped index is a number that looks
    /// usable and describes memory nobody wrote.
    ///
    /// What a caller does about a `None` is its own policy — stop talking to
    /// that peer, log it, restart the channel. This layer says only that the
    /// numbers are not believable.
    #[must_use]
    pub const fn new(layout: Layout, head: u64, tail: u64) -> Option<Self> {
        let used = head.wrapping_sub(tail);
        if used > layout.capacity as u64 {
            // Covers both impossible cases at once: a `tail` ahead of `head`
            // wraps to something enormous, and a genuine overrun exceeds the
            // capacity. One comparison, no signed arithmetic, no ordering
            // assumption about which index is larger.
            return None;
        }
        Some(Self {
            head,
            tail,
            capacity: layout.capacity,
        })
    }

    /// Bytes the consumer may read.
    #[must_use]
    pub const fn readable(&self) -> usize {
        self.head.wrapping_sub(self.tail) as usize
    }

    /// Bytes the producer may write.
    #[must_use]
    pub const fn writable(&self) -> usize {
        self.capacity - self.readable()
    }

    /// Whether there is nothing to read.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.readable() == 0
    }

    /// The producer's index.
    #[must_use]
    pub const fn head(&self) -> u64 {
        self.head
    }

    /// The consumer's index.
    #[must_use]
    pub const fn tail(&self) -> u64 {
        self.tail
    }
}

/// One contiguous run of bytes within the region.
///
/// A ring wraps, so a transfer of *n* bytes is one run or two. Returning them
/// rather than a length lets the caller copy with two `copy_from_slice` calls
/// and no arithmetic of its own — the arithmetic is here, where it is tested.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Run {
    /// Byte offset within the region.
    pub offset: usize,
    /// How many bytes.
    pub length: usize,
}

impl Run {
    /// Whether this run carries nothing.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.length == 0
    }
}

/// Where the next `count` readable bytes are, as at most two runs.
///
/// `count` is clamped to what is actually readable, so a caller asking for
/// more than exists gets what exists rather than a run describing bytes the
/// producer has not written.
#[must_use]
pub fn read_runs(layout: Layout, cursor: Cursor, count: usize) -> (Run, Run) {
    runs_from(layout, cursor.tail(), count.min(cursor.readable()))
}

/// Where the next `count` writable bytes are, as at most two runs.
///
/// Clamped to the free space, for the same reason: a run past it would
/// describe bytes the consumer has not finished reading.
#[must_use]
pub fn write_runs(layout: Layout, cursor: Cursor, count: usize) -> (Run, Run) {
    runs_from(layout, cursor.head(), count.min(cursor.writable()))
}

/// How many bytes carry a frame's length in front of it.
///
/// Every ring in this system that carries frames rather than a byte stream puts
/// the length first, and every one of them wrote that rule out again. See
/// [`frame_to_write`].
pub const PREFIX: usize = 4;

/// Where a frame of `length` bytes goes, and where the head lands after it.
///
/// **RFC 0010 step 6, the framing half.** `bin/netd` and `bin/ipd` each wrote
/// this arithmetic twice — once per ring, per direction — and between them it
/// produced a frame truncated to 42 bytes because a length and its payload
/// disagreed, a tail advanced past bytes nobody read, and a counter that
/// counted a copy which had not happened. It is one function now, and it is
/// safe code with tests, because `bhaskix-abi` carries an `unsafe` budget of
/// zero and this is the part that was getting things wrong anyway.
///
/// `None` when the ring cannot take the whole frame. **Refused rather than
/// truncated**: a frame that does not fit is not a shorter frame.
#[must_use]
pub fn frame_to_write(layout: Layout, cursor: Cursor, length: usize) -> Option<Framed> {
    let total = PREFIX.checked_add(length)?;
    if length == 0 || total > cursor.writable() {
        return None;
    }
    let prefix = write_runs(layout, cursor, PREFIX);
    let after_prefix = Cursor::new(layout, cursor.head() + PREFIX as u64, cursor.tail())?;
    let payload = write_runs(layout, after_prefix, length);
    Some(Framed {
        prefix,
        payload,
        next: cursor.head() + total as u64,
    })
}

/// Where the next frame's length bytes are, if the producer has published them.
///
/// `None` when fewer than [`PREFIX`] bytes are readable, which is not an error:
/// it is a ring with nothing in it yet.
#[must_use]
pub fn length_to_read(layout: Layout, cursor: Cursor) -> Option<(Run, Run)> {
    (cursor.readable() >= PREFIX).then(|| read_runs(layout, cursor, PREFIX))
}

/// Where a frame of `length` bytes is, and where the tail lands after it.
///
/// `None` when the producer has published a length but not yet all the bytes.
/// **That is a race the producer is in the middle of losing, not an error** —
/// the caller looks again without moving the tail. Reading the payload anyway
/// is how a consumer gets half a frame and a plausible-looking one.
#[must_use]
pub fn frame_to_read(layout: Layout, cursor: Cursor, length: usize) -> Option<Framed> {
    let total = PREFIX.checked_add(length)?;
    if length == 0 || total > cursor.readable() {
        return None;
    }
    let prefix = read_runs(layout, cursor, PREFIX);
    let after_prefix = Cursor::new(layout, cursor.head(), cursor.tail() + PREFIX as u64)?;
    let payload = read_runs(layout, after_prefix, length);
    Some(Framed {
        prefix,
        payload,
        next: cursor.tail() + total as u64,
    })
}

/// A framed transfer: where its two parts sit, and the index after it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Framed {
    /// The length prefix, as at most two runs.
    pub prefix: (Run, Run),
    /// The frame itself, as at most two runs.
    pub payload: (Run, Run),
    /// What the mover's own index becomes once every byte is in place.
    ///
    /// **Published last, and only then.** A ring whose index moves before its
    /// bytes hands the other side whatever happened to be in the region.
    pub next: u64,
}

fn runs_from(layout: Layout, from: u64, count: usize) -> (Run, Run) {
    // An empty run still names a legal offset. Returning `Run::default()`
    // gave one at offset zero -- inside the header, where the *other* side's
    // index lives -- and a caller that copied `length` bytes without checking
    // for empty first would have written there. Nothing does that today, and
    // "nothing does that today" is not a property of the type.
    let empty = Run {
        offset: DATA_OFFSET,
        length: 0,
    };
    if count == 0 {
        return (empty, empty);
    }
    let start = layout.offset_of(from);
    let to_end = DATA_OFFSET + layout.capacity() - start;
    let first = count.min(to_end);

    (
        Run {
            offset: start,
            length: first,
        },
        Run {
            offset: DATA_OFFSET,
            length: count - first,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn layout(bytes: usize) -> Layout {
        Layout::for_region(bytes).expect("a region big enough for a ring")
    }

    #[test]
    fn a_region_too_small_for_a_ring_is_refused() {
        for bytes in 0..=HEADER_BYTES {
            assert_eq!(Layout::for_region(bytes), None, "{bytes} bytes");
        }
        assert_eq!(layout(HEADER_BYTES + 1).capacity(), 1);
    }

    #[test]
    fn the_capacity_is_the_largest_power_of_two_that_fits() {
        // A power of two so that masking an index is one instruction that
        // cannot be got wrong. The waste is bounded and the region's size is
        // the program's choice.
        assert_eq!(layout(HEADER_BYTES + 4096).capacity(), 4096);
        assert_eq!(layout(HEADER_BYTES + 4095).capacity(), 2048);
        assert_eq!(layout(HEADER_BYTES + 6000).capacity(), 4096);
        assert_eq!(layout(8192).capacity(), 4096);
    }

    #[test]
    fn indices_that_cannot_both_be_true_are_refused_rather_than_clamped() {
        let layout = layout(HEADER_BYTES + 16);
        assert_eq!(layout.capacity(), 16);

        // The consumer cannot be ahead of the producer.
        assert_eq!(Cursor::new(layout, 4, 5), None);
        // Nor can more be outstanding than the ring holds.
        assert_eq!(Cursor::new(layout, 17, 0), None);
        assert_eq!(Cursor::new(layout, u64::MAX, 0), None);
        // Exactly full is legal; one more is not.
        assert!(Cursor::new(layout, 16, 0).is_some());

        // And the wrap is legal, not an error. `tail = u64::MAX`, `head = 0`
        // is the counter having wrapped with one byte outstanding -- which is
        // the whole point of free-running indices. This assertion was written
        // the other way round first, which was a misreading of the design
        // rather than a bug in it: the subtraction wraps too, and that is what
        // makes the arithmetic work at the seam.
        let wrapped = Cursor::new(layout, 0, u64::MAX).expect("a wrap is not an error");
        assert_eq!(wrapped.readable(), 1);
        assert_eq!(wrapped.writable(), 15);
    }

    #[test]
    fn free_running_indices_distinguish_empty_from_full() {
        let layout = layout(HEADER_BYTES + 8);

        let empty = Cursor::new(layout, 8, 8).expect("valid");
        assert!(empty.is_empty());
        assert_eq!(empty.readable(), 0);
        assert_eq!(empty.writable(), 8);

        // The same *offsets* -- both mask to zero -- and a different meaning.
        // Indices reduced modulo the capacity could not tell these apart.
        let full = Cursor::new(layout, 16, 8).expect("valid");
        assert!(!full.is_empty());
        assert_eq!(full.readable(), 8);
        assert_eq!(full.writable(), 0);
        assert_eq!(layout.offset_of(16), layout.offset_of(8));
    }

    #[test]
    fn a_transfer_that_wraps_comes_back_as_two_runs() {
        let layout = layout(HEADER_BYTES + 16);
        // Tail at 12, so four bytes to the end and the rest from the start.
        let cursor = Cursor::new(layout, 12 + 10, 12).expect("valid");
        let (first, second) = read_runs(layout, cursor, 10);

        assert_eq!(
            first,
            Run {
                offset: DATA_OFFSET + 12,
                length: 4
            }
        );
        assert_eq!(
            second,
            Run {
                offset: DATA_OFFSET,
                length: 6
            }
        );
        assert_eq!(first.length + second.length, 10);
    }

    #[test]
    fn a_transfer_that_does_not_wrap_has_an_empty_second_run() {
        let layout = layout(HEADER_BYTES + 16);
        let cursor = Cursor::new(layout, 4, 0).expect("valid");
        let (first, second) = read_runs(layout, cursor, 4);
        assert_eq!(
            first,
            Run {
                offset: DATA_OFFSET,
                length: 4
            }
        );
        assert!(second.is_empty());
    }

    #[test]
    fn asking_for_more_than_exists_yields_what_exists() {
        let layout = layout(HEADER_BYTES + 16);

        let cursor = Cursor::new(layout, 3, 0).expect("valid");
        let (first, second) = read_runs(layout, cursor, 100);
        assert_eq!(first.length + second.length, 3, "only three were written");

        let (first, second) = write_runs(layout, cursor, 100);
        assert_eq!(
            first.length + second.length,
            13,
            "thirteen free, not a hundred"
        );
    }

    #[test]
    fn every_run_stays_inside_the_region_for_every_position() {
        // The property that matters, over every index and length a ring of
        // this size can produce: a run never names a byte outside the data
        // area. An off-by-one here is a write into the header -- into the
        // *other* side's index -- which is the one bug in this module that
        // would be a security problem rather than a corruption.
        let layout = layout(HEADER_BYTES + 32);
        let limit = DATA_OFFSET + layout.capacity();

        for tail in 0..64u64 {
            for used in 0..=32u64 {
                let Some(cursor) = Cursor::new(layout, tail + used, tail) else {
                    continue;
                };
                for want in 0..=40usize {
                    for run in [
                        read_runs(layout, cursor, want).0,
                        read_runs(layout, cursor, want).1,
                        write_runs(layout, cursor, want).0,
                        write_runs(layout, cursor, want).1,
                    ] {
                        // Empty runs included: an offset is either legal or it
                        // is a place a careless caller writes zero bytes to
                        // today and some bytes to later.
                        assert!(run.offset >= DATA_OFFSET, "{run:?} is in the header");
                        assert!(
                            run.offset + run.length <= limit,
                            "{run:?} runs past the region"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn a_cursor_cannot_be_built_from_a_region() {
        // Not an assertion about behaviour -- an assertion about the API. The
        // only constructor takes numbers, so a caller that has a `Cursor` has
        // already copied out of shared memory and cannot re-read what it
        // validated. That is the double-fetch rule made structural rather than
        // written in a comment nobody reads twice.
        let layout = layout(HEADER_BYTES + 8);
        let snapshot = (4u64, 0u64);
        let cursor = Cursor::new(layout, snapshot.0, snapshot.1).expect("valid");
        assert_eq!(cursor.readable(), 4);
    }

    /// A frame and its prefix land where the runs say, and the head lands after.
    #[test]
    fn a_framed_write_places_the_prefix_then_the_payload() {
        let layout = Layout::for_region(HEADER_BYTES + 64).expect("valid");
        let cursor = Cursor::new(layout, 0, 0).expect("valid");
        let framed = frame_to_write(layout, cursor, 10).expect("fits");
        assert_eq!(framed.prefix.0.length, PREFIX);
        assert_eq!(framed.payload.0.length, 10);
        assert_eq!(framed.next, (PREFIX + 10) as u64);
    }

    /// **A frame that does not fit is refused, not shortened.** This is the rule
    /// a truncating writer breaks, and a truncated frame is one the far end
    /// parses happily and acts on.
    #[test]
    fn a_frame_larger_than_the_ring_is_refused() {
        let layout = Layout::for_region(HEADER_BYTES + 64).expect("valid");
        let cursor = Cursor::new(layout, 0, 0).expect("valid");
        assert_eq!(frame_to_write(layout, cursor, 61), None);
        assert!(frame_to_write(layout, cursor, 60).is_some());
    }

    /// A frame written across the wrap comes back as two runs that add up.
    #[test]
    fn a_frame_that_wraps_is_two_runs() {
        let layout = Layout::for_region(HEADER_BYTES + 64).expect("valid");
        // Chosen so the *payload* straddles the end rather than the prefix:
        // at 60 the four prefix bytes land exactly on the boundary and the
        // payload starts at zero, which is the case this test was written to
        // miss and did.
        let cursor = Cursor::new(layout, 58, 58).expect("valid");
        let framed = frame_to_write(layout, cursor, 10).expect("fits");
        assert_eq!(framed.payload.0.length + framed.payload.1.length, 10);
        assert!(
            !framed.payload.1.is_empty(),
            "expected a wrapped second run"
        );
    }

    /// **A length published without its bytes is not a frame yet.** The producer
    /// is mid-write; a consumer that read anyway would take half a frame and
    /// whatever was in the region behind it.
    #[test]
    fn a_length_without_its_payload_is_refused() {
        let layout = Layout::for_region(HEADER_BYTES + 64).expect("valid");
        // Four bytes readable: the prefix is there, the payload is not.
        let cursor = Cursor::new(layout, 4, 0).expect("valid");
        assert!(length_to_read(layout, cursor).is_some());
        assert_eq!(frame_to_read(layout, cursor, 10), None);
    }

    /// What the writer laid down is what the reader is told to pick up.
    #[test]
    fn a_write_and_a_read_agree_on_where_the_frame_is() {
        let layout = Layout::for_region(HEADER_BYTES + 64).expect("valid");
        let write = Cursor::new(layout, 0, 0).expect("valid");
        let written = frame_to_write(layout, write, 12).expect("fits");
        let read = Cursor::new(layout, written.next, 0).expect("valid");
        let got = frame_to_read(layout, read, 12).expect("published");
        assert_eq!(got.payload, written.payload);
        assert_eq!(got.next, written.next);
    }

    /// An empty frame is refused at both ends: it would advance an index by the
    /// prefix alone and leave the two sides describing different rings.
    #[test]
    fn an_empty_frame_is_refused() {
        let layout = Layout::for_region(HEADER_BYTES + 64).expect("valid");
        let cursor = Cursor::new(layout, 0, 0).expect("valid");
        assert_eq!(frame_to_write(layout, cursor, 0), None);
        let full = Cursor::new(layout, 8, 0).expect("valid");
        assert_eq!(frame_to_read(layout, full, 0), None);
    }
}
