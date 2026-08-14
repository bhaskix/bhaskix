// SPDX-License-Identifier: Apache-2.0
//! TCP — the sequence number and the segment, with no connection under them.
//!
//! [RFC 0020](../../docs/rfc/0020-tcp.md) steps 1 and 2: the initial sequence
//! number in [`isn`], the wire format in [`segment`], and here the two types
//! both of them and the state machine need. **The state machine is step 3 and
//! is not written yet**, so nothing in this module remembers anything between
//! calls — a segment is arithmetic over bytes, exactly as a datagram is.
//!
//! # Why the sequence number came first
//!
//! Not because it is the smallest piece. Because it is the piece that turned out
//! not to be buildable: an initial sequence number must be unpredictable, and
//! drafting that requirement is what discovered that **this system could not
//! produce an unpredictable number at all**, which became
//! [RFC 0021](../../docs/rfc/0021-unpredictability.md) and a crate of its own.
//! Building it first is what proves that prerequisite is actually met, rather
//! than met in a document.

pub mod isn;
pub mod segment;
pub mod state;

pub use segment::{Flags, Options, Segment};
pub use state::{Action, Actions, Emit, Ended, Event, State, Tcb, Timer, step};

use crate::addr::{Address, Port};

/// A TCP sequence number.
///
/// # It deliberately does not derive `PartialOrd`
///
/// Sequence numbers live on a circle. `0xffff_ffff` comes *before* `0`, and a
/// derived comparison says the opposite — so a derive here would put the wrong
/// answer behind the ordinary `<` operator, where nobody would look for it. Use
/// [`Sequence::precedes`] and [`Sequence::follows`], which implement the
/// wrapping comparison RFC 793 §3.3 describes.
///
/// This is not a hypothetical: it is the single failure RFC 0020's testing plan
/// names in advance — *"break the sequence-number comparison to use `<` instead
/// of a wrapping compare and the reordering tests must go red"*. The type is
/// arranged so that the mistake has to be typed out rather than defaulted into.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Sequence(pub u32);

impl Sequence {
    /// This number `n` bytes later, around the circle.
    #[must_use]
    pub const fn wrapping_add(self, n: u32) -> Self {
        Self(self.0.wrapping_add(n))
    }

    /// Whether this number comes before `other` in sequence space.
    ///
    /// The comparison is on the *signed* difference, which is what makes the
    /// wrap work: two numbers are ordered by the shorter way round the circle,
    /// so this is meaningful only for numbers within 2³¹ of each other — which
    /// is every pair TCP ever compares. A window caps at 2³⁰ even with the
    /// scaling RFC 0020 does not implement, and at 65,535 without it.
    ///
    /// **Exactly 2³¹ apart, `precedes` and `follows` are both true**, because
    /// the two ways round the circle are the same length and the signed
    /// difference is `i32::MIN` read from either end. That is a property of the
    /// circle and not of this implementation — no total order on a circle
    /// exists — and no pair TCP compares can reach it. It is written down, and
    /// tested, because the tempting assumption is the opposite one: that the
    /// degenerate case makes both *false*.
    #[must_use]
    pub const fn precedes(self, other: Self) -> bool {
        (self.0.wrapping_sub(other.0) as i32) < 0
    }

    /// Whether this number comes after `other` in sequence space.
    #[must_use]
    pub const fn follows(self, other: Self) -> bool {
        other.precedes(self)
    }
}

/// The four numbers that name a connection.
///
/// RFC 6528 calls this the connection-id and makes it the input to the sequence
/// number's keyed function; RFC 793 makes it the identity a segment is
/// demultiplexed onto. Same four fields, so there is one type.
///
/// The addresses are [`Address`] rather than `Ipv4Addr` for the reason the rest
/// of this crate gives: a second family should be an added arm, not a changed
/// signature.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct FourTuple {
    /// This machine's address.
    pub local: Address,
    /// The port here.
    pub local_port: Port,
    /// The peer's address.
    pub remote: Address,
    /// The port there.
    pub remote_port: Port,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_circle_wraps_and_a_naive_comparison_would_not() {
        // The three assertions that a derived `PartialOrd` would fail. Written
        // as the reason the derive is absent, so deleting the comment does not
        // delete the reason.
        let last = Sequence(u32::MAX);
        let first = Sequence(0);
        assert!(last.precedes(first), "0xffff_ffff comes before 0");
        assert!(first.follows(last));
        assert!(last.0 > first.0, "and a plain `>` says the opposite");
    }

    #[test]
    fn a_number_neither_precedes_nor_follows_itself() {
        let one = Sequence(12345);
        assert!(!one.precedes(one));
        assert!(!one.follows(one));
    }

    #[test]
    fn ordering_holds_across_the_wrap_for_a_windows_worth() {
        // A window's worth either side of the wrap, which is the span a real
        // connection compares over.
        let base = Sequence(u32::MAX - 32);
        for step in 1..=64u32 {
            let later = base.wrapping_add(step);
            assert!(base.precedes(later), "{base:?} before {later:?}");
            assert!(later.follows(base));
            assert!(!later.precedes(base));
        }
    }

    #[test]
    fn exactly_half_a_circle_apart_is_ambiguous_in_both_directions() {
        // Not a wish, a measurement: the signed difference is `i32::MIN` read
        // from either end, so each number precedes the other. Pinned here
        // because the doc comment on `precedes` originally claimed the
        // opposite — that both answers would be false — and the claim was
        // written before it was checked.
        let a = Sequence(0);
        let b = Sequence(1 << 31);
        assert!(a.precedes(b));
        assert!(b.precedes(a));
        assert_ne!(a, b);

        // One step either side of the degenerate distance, ordering is
        // unambiguous again — which is why no real sequence pair meets it.
        assert!(a.precedes(Sequence((1 << 31) - 1)));
        assert!(!Sequence((1 << 31) - 1).precedes(a));
        assert!(!a.precedes(Sequence((1 << 31) + 1)));
        assert!(Sequence((1 << 31) + 1).precedes(a));
    }

    #[test]
    fn adding_wraps_rather_than_overflowing() {
        // `overflow-checks` is on in every profile this workspace builds, so a
        // plain `+` here would be a remotely-triggerable panic once a
        // connection had sent four gigabytes.
        assert_eq!(Sequence(u32::MAX).wrapping_add(1), Sequence(0));
        assert_eq!(Sequence(u32::MAX).wrapping_add(2), Sequence(1));
    }
}
