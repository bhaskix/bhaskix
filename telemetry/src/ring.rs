// SPDX-License-Identifier: Apache-2.0
//! The per-CPU ring protocol, as arithmetic.
//!
//! One ring per CPU: a [`HEADER_BYTES`] header, then a power-of-two count of
//! [`EVENT_BYTES`](crate::EVENT_BYTES) slots. The producer is only the
//! owning CPU; the consumer is whoever holds the read capability. `head`
//! lives in the ring's header and only the kernel writes it; the consumer's
//! `tail` lives in a separate read-write region and is **untrusted** — every
//! use here clamps it first.
//!
//! The discipline is **drop-newest, never overwrite**: a slot below `head`
//! is never rewritten until the tail has freed it, so a reader can never
//! observe a torn record, and the price of pressure is a counted drop
//! rather than a corrupted stream. Head and tail are unwrapped 64-bit
//! sequence numbers — at a billion events a second the wrap is five
//! centuries out, and the arithmetic below still guards `head < tail`
//! because a hostile tail can claim anything it likes.
//!
//! Nothing in this module loads or stores shared memory. The kernel and the
//! reader do that, at the offsets and in the order these functions dictate;
//! the memory-ordering contract (publish `head` with a release store, read
//! it with an acquire load) is stated here and honoured there.

use crate::EVENT_BYTES;

/// Bytes before the first slot. Room for the header words plus a spare
/// cache line so `head` — rewritten on every emit — sits alone.
pub const HEADER_BYTES: usize = 128;

/// `b"BHXTEL01"`, little-endian: the marker the kernel writes last at
/// bring-up, so a reader that maps an unwritten or foreign page refuses it.
pub const MARKER: u64 = u64::from_le_bytes(*b"BHXTEL01");

/// Header offset of [`MARKER`].
pub const MARKER_OFFSET: usize = 0;
/// Header offset of the registry hash ([`crate::schema::registry_hash`]).
pub const HASH_OFFSET: usize = 8;
/// Header offset of the slot count, written once at bring-up.
pub const SLOTS_OFFSET: usize = 16;
/// Header offset of the drop counter: events refused because the ring was
/// full. Best-effort that says so.
pub const DROPPED_OFFSET: usize = 24;
/// Header offset of the audit-refused counter: events carrying the reserved
/// `Audit` class, dropped by policy until the audit RFC builds its
/// backpressure ring, and counted apart from pressure drops because they
/// are a different sentence.
pub const AUDIT_REFUSED_OFFSET: usize = 32;
/// Header offset of `head`, alone on its own cache line. The producer
/// publishes it with a release store after the slot's bytes are written;
/// the consumer reads it with an acquire load before reading any slot.
pub const HEAD_OFFSET: usize = 64;

/// Bytes each CPU's tail occupies in the tails region — a cache line each,
/// so two CPUs' reader-writer traffic never falsely shares.
pub const TAIL_STRIDE: usize = 64;

/// Where `cpu`'s tail word lives in the tails region.
#[must_use]
pub const fn tail_offset(cpu: usize) -> usize {
    cpu * TAIL_STRIDE
}

/// A ring region's shape: how many slots fit, and where things are.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layout {
    slots: u64,
}

impl Layout {
    /// The layout for a region of `length` bytes: the largest power-of-two
    /// slot count that fits after the header, or `None` if not even one
    /// slot does. Power of two so the slot index is a mask, not a divide,
    /// on the emit path.
    #[must_use]
    pub const fn for_region(length: usize) -> Option<Self> {
        if length < HEADER_BYTES + EVENT_BYTES {
            return None;
        }
        let fitting = (length - HEADER_BYTES) / EVENT_BYTES;
        // The largest power of two at or below `fitting`, which is at least
        // one here.
        let slots = 1u64 << (63 - (fitting as u64).leading_zeros());
        Some(Self { slots })
    }

    /// How many slots this ring holds.
    #[must_use]
    pub const fn slots(&self) -> u64 {
        self.slots
    }

    /// Bytes the ring actually uses; a region may be longer.
    #[must_use]
    pub const fn used_bytes(&self) -> usize {
        HEADER_BYTES + (self.slots as usize) * EVENT_BYTES
    }

    /// Where sequence number `sequence`'s slot begins.
    #[must_use]
    pub const fn slot_offset(&self, sequence: u64) -> usize {
        HEADER_BYTES + ((sequence & (self.slots - 1)) as usize) * EVENT_BYTES
    }
}

/// The tail the producer may believe: at most `head` (a tail claiming the
/// future reads as "everything consumed" and only cheats its claimant), at
/// least `head - slots` (a tail lagging further than the ring is a claim on
/// slots that no longer exist). A hostile tail can cause drops or
/// redeliveries in its own stream, and nothing else — that sentence is this
/// function.
#[must_use]
pub const fn clamp_tail(head: u64, claim: u64, slots: u64) -> u64 {
    if claim > head {
        return head;
    }
    if head - claim > slots {
        return head - slots;
    }
    claim
}

/// Whether the producer may write sequence `head`, given a **clamped**
/// tail: true exactly when the ring has a free slot. False is a drop, and
/// the drop counter is the other half of the answer.
#[must_use]
pub const fn admit(head: u64, clamped_tail: u64, slots: u64) -> bool {
    head - clamped_tail < slots
}

/// How many events the consumer may read: `[tail, tail + readable)`.
/// Defensive on both sides — a `head` behind `tail` reads as nothing
/// (the consumer's own state is stale or the ring was reinitialised), and
/// more than `slots` reads as `slots`, with [`resync`] naming where to
/// resume.
#[must_use]
pub const fn readable(head: u64, tail: u64, slots: u64) -> u64 {
    if head < tail {
        return 0;
    }
    let pending = head - tail;
    if pending > slots { slots } else { pending }
}

/// The tail a consumer that finds itself impossibly far behind resumes
/// from: the oldest sequence still guaranteed un-overwritten. With honest
/// parties this is never needed — drop-newest means `head` never laps the
/// tail — so needing it is itself a diagnostic.
#[must_use]
pub const fn resync(head: u64, slots: u64) -> u64 {
    head.saturating_sub(slots)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Values that break arithmetic, seeded per coding-style.md §8: a
    /// mutation harness tests the middle of the input space unless it is
    /// told where the edges are.
    const EDGES: [u64; 8] = [
        0,
        1,
        u64::MAX,
        u64::MAX - 1,
        1 << 63,
        (1 << 63) - 1,
        1 << 47,
        4096,
    ];

    #[test]
    fn a_region_must_fit_a_header_and_one_slot_or_it_is_no_ring() {
        assert_eq!(Layout::for_region(0), None);
        assert_eq!(Layout::for_region(HEADER_BYTES), None);
        assert_eq!(Layout::for_region(HEADER_BYTES + EVENT_BYTES - 1), None);
        let one = Layout::for_region(HEADER_BYTES + EVENT_BYTES);
        assert_eq!(one.map(|layout| layout.slots()), Some(1));
    }

    #[test]
    fn slot_counts_are_the_largest_fitting_power_of_two() {
        // 64 KiB: (65536 - 128) / 64 = 1022 fit, so 512 slots.
        let layout = Layout::for_region(64 * 1024).unwrap_or(Layout { slots: 0 });
        assert_eq!(layout.slots(), 512);
        // One page: (4096 - 128) / 64 = 62 fit, so 32.
        let page = Layout::for_region(4096).unwrap_or(Layout { slots: 0 });
        assert_eq!(page.slots(), 32);
        assert!(page.used_bytes() <= 4096);
    }

    #[test]
    fn slot_offsets_stay_inside_the_used_region_for_hostile_sequences() {
        let layout = Layout::for_region(4096).unwrap_or(Layout { slots: 0 });
        for sequence in EDGES {
            let at = layout.slot_offset(sequence);
            assert!(at >= HEADER_BYTES);
            assert!(at + EVENT_BYTES <= layout.used_bytes());
        }
    }

    #[test]
    fn the_clamp_believes_no_tail_outside_the_ring() {
        let slots = 32;
        for head in EDGES {
            for claim in EDGES {
                let tail = clamp_tail(head, claim, slots);
                assert!(tail <= head, "a tail from the future: {tail} > {head}");
                assert!(
                    head - tail <= slots,
                    "a tail claiming dead slots: {head} - {tail} > {slots}"
                );
            }
        }
    }

    #[test]
    fn an_honest_tail_is_believed_verbatim() {
        assert_eq!(clamp_tail(100, 100, 32), 100, "empty ring");
        assert_eq!(clamp_tail(100, 90, 32), 90, "mid-stream");
        assert_eq!(clamp_tail(100, 68, 32), 68, "exactly full");
    }

    #[test]
    fn admit_fills_to_capacity_drops_at_it_and_recovers_on_consumption() {
        let slots = 4;
        let tail = 10;
        // Four writes from empty, then full.
        assert!(admit(10, tail, slots));
        assert!(admit(11, tail, slots));
        assert!(admit(12, tail, slots));
        assert!(admit(13, tail, slots));
        assert!(!admit(14, tail, slots), "the fifth is a drop, not a wrap");
        // The reader frees one; exactly one write is admitted again.
        assert!(admit(14, tail + 1, slots));
        assert!(!admit(15, tail + 1, slots));
    }

    #[test]
    fn readable_never_exceeds_the_ring_and_never_goes_backwards() {
        let slots = 32;
        for head in EDGES {
            for tail in EDGES {
                let count = readable(head, tail, slots);
                assert!(count <= slots);
                if head >= tail {
                    assert!(count <= head - tail);
                }
                let resumed = resync(head, slots);
                assert!(readable(head, resumed, slots) <= slots);
            }
        }
    }

    /// The seeded mutation harness, coding-style.md §8's M6-01 pattern: a
    /// deterministic generator drives the protocol with mostly-edge values
    /// and requires every answer to stay in bounds. `BHASKIX_FUZZ_ITERATIONS`
    /// raises the count for a soak.
    #[test]
    fn the_protocol_survives_a_storm_of_hostile_values() {
        let iterations: u64 = std::env::var("BHASKIX_FUZZ_ITERATIONS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(10_000);
        let mut state = 0x2545_F491_4F6C_DD1Du64;
        let mut draw = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            // Half the draws come from the edge list, because uniform
            // sampling never lands within sixteen of u64::MAX on its own.
            if state & 1 == 0 {
                EDGES[(state >> 1) as usize % EDGES.len()]
            } else {
                state
            }
        };
        for _ in 0..iterations {
            let length = (draw() % (1 << 22)) as usize;
            let Some(layout) = Layout::for_region(length) else {
                assert!(length < HEADER_BYTES + EVENT_BYTES);
                continue;
            };
            let slots = layout.slots();
            assert!(slots.is_power_of_two());
            assert!(layout.used_bytes() <= length);

            let head = draw();
            let claim = draw();
            let tail = clamp_tail(head, claim, slots);
            assert!(tail <= head && head - tail <= slots);
            // An admitted write lands inside the region, on a slot the
            // clamped tail has freed.
            if admit(head, tail, slots) {
                let at = layout.slot_offset(head);
                assert!(at >= HEADER_BYTES && at + EVENT_BYTES <= layout.used_bytes());
            }
            assert!(readable(head, tail, slots) <= slots);
        }
    }
}
