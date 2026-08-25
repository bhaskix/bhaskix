// SPDX-License-Identifier: Apache-2.0
//! SYN cookies: a handshake that allocates nothing until the peer answers.
//!
//! [RFC 0048](../../../docs/rfc/0048-a-listener-that-cannot-be-wedged.md) step
//! 2. **This module is arithmetic and holds no state at all** — that is the
//! whole point of it, not a property it happens to have.
//!
//! # The problem it removes
//!
//! `bin/tcpd` births a connection when a `SYN` arrives. One packet, from an
//! address that need not exist, therefore takes a table slot and holds it until
//! the retransmission budget runs out. RFC 0048 step 1 cut that hold from 242
//! seconds to 14 by giving a half-open connection less patience than an
//! established one, and said plainly that this is a **reduction and not a
//! fix**: one `SYN` every fourteen seconds still owns the slot.
//!
//! A cookie removes the trade rather than repricing it. On a `SYN` nothing is
//! allocated; the initial sequence number *is* the state, carried on the wire.
//! The peer's `ACK` returns `cookie + 1`, and only a peer that received the
//! `SYN·ACK` can do that — so a connection is built from an `ACK` that proves
//! somebody is there, and a flood of `SYN`s costs this machine one hash each
//! and nothing else.
//!
//! # What has to fit, and what that costs
//!
//! Thirty-two bits have to carry three things:
//!
//! ```text
//!   31        24 23  21 20                                   0
//!  ┌────────────┬──────┬──────────────────────────────────────┐
//!  │  counter   │ mss  │        keyed hash (21 bits)          │
//!  └────────────┴──────┴──────────────────────────────────────┘
//! ```
//!
//! - the **counter**, so an old cookie can be refused rather than replayed for
//!   ever;
//! - the **MSS index**, because the peer's `SYN` announced a maximum segment
//!   size and there is nowhere else to keep it once the `SYN` is not stored;
//! - the **hash**, which is what an attacker cannot forge.
//!
//! Twenty-one bits of hash is the honest cost, and it is stated here rather
//! than buried: a blind attacker gets one guess in 2²¹ per `ACK`. That is the
//! standard construction's number and it is not a large one. It is acceptable
//! because forging requires *sending* an `ACK` for each attempt, from an
//! address that must receive the reply for the connection to be of any use,
//! and because the alternative — the state this replaces — costs the defender
//! rather than the attacker.
//!
//! **The MSS is not free either.** Three bits means the announced value is
//! rounded *down* to one of eight, so a peer's MSS is honoured approximately.
//! Rounding down is the safe direction: a segment smaller than the peer can
//! accept is delivered, one larger is not.
//!
//! # What this module is not allowed to do
//!
//! The same rule [`super::isn`] carries. It does not draw the key, does not
//! read a clock, and holds nothing between calls: every function takes the key
//! and the instant and returns a number. That is what lets the whole of it be
//! tested on the host with no processor involved, and it is why the cookie's
//! correctness can be established without a network.

use crate::siphash::{self, Key};
use crate::tcp::{FourTuple, Sequence};

/// How long one counter tick lasts, in nanoseconds.
///
/// Sixty-four seconds, which is the interval Linux's `tcp_syncookies` uses. It
/// is a compromise with only bad neighbours: shorter and a slow peer's `ACK`
/// arrives after its cookie has expired, longer and a captured cookie stays
/// replayable. The counter is eight bits, so the whole space is 256 ticks —
/// about four and a half hours — and wrapping is handled rather than avoided.
pub const TICK_NANOS: u64 = 64_000_000_000;

/// How many ticks old a cookie may be and still be accepted.
///
/// Two, so a cookie is good for between 64 and 128 seconds depending where in
/// a tick it was minted. The peer has to complete a handshake in that window,
/// which is far longer than any live path and far shorter than the counter's
/// wrap.
pub const MAX_AGE_TICKS: u8 = 2;

/// Bits of the cookie given to the keyed hash.
const HASH_BITS: u32 = 21;

/// The hash's mask — the low [`HASH_BITS`] bits.
const HASH_MASK: u32 = (1 << HASH_BITS) - 1;

/// Where the MSS index sits.
const MSS_SHIFT: u32 = HASH_BITS;

/// Where the counter sits.
const COUNTER_SHIFT: u32 = 24;

/// The maximum segment sizes a cookie can carry, smallest first.
///
/// Eight values because three bits is what is left over. They are the ones
/// that matter on real paths: the IPv6 minimum, the classic 576-byte and
/// 1280-byte floors, Ethernet with and without common tunnelling overheads,
/// and jumbo frames at the top.
///
/// **Sorted, and the code depends on it.** [`mss_index`] walks from the top
/// and takes the first value not larger than what the peer announced, which is
/// only a round-*down* if this table ascends.
pub const MSS_TABLE: [u16; 8] = [536, 1024, 1220, 1280, 1360, 1400, 1440, 1460];

/// The index of the largest table entry not larger than `announced`.
///
/// Rounds **down**, always. A peer that announces something smaller than every
/// entry gets index 0 and therefore 536, which is the smallest value any IPv4
/// path is required to carry; sending it segments that small is inefficient
/// and never wrong.
#[must_use]
pub fn mss_index(announced: u16) -> u8 {
    let mut index = 0u8;
    let mut i = 0;
    while i < MSS_TABLE.len() {
        if MSS_TABLE[i] <= announced {
            index = i as u8;
        }
        i += 1;
    }
    index
}

/// The segment size an index names.
#[must_use]
pub fn mss_of(index: u8) -> u16 {
    MSS_TABLE[(index & 0x7) as usize]
}

/// The keyed hash over everything the cookie commits to.
///
/// **The counter and the MSS index are inside the hash, not merely beside it.**
/// They sit in the clear in the top eleven bits of the cookie, so an attacker
/// can read and change them; covering them here is what makes changing them
/// produce a cookie that does not verify. Leaving them out would let a captured
/// cookie be aged backwards into validity, or its MSS raised to something the
/// peer never offered.
fn mac(key: &Key, connection: FourTuple, counter: u8, mss: u8) -> u32 {
    let mut input = [0u8; super::isn::ENCODED + 2];
    input[..super::isn::ENCODED].copy_from_slice(&super::isn::encode(connection));
    input[super::isn::ENCODED] = counter;
    input[super::isn::ENCODED + 1] = mss & 0x7;
    (siphash::hash(key, &input) as u32) & HASH_MASK
}

/// Which tick `now` falls in.
#[must_use]
pub const fn counter_at(now: u64) -> u8 {
    (now / TICK_NANOS) as u8
}

/// The cookie to answer a `SYN` with — the sequence number of the `SYN·ACK`.
///
/// `announced` is the maximum segment size the peer's `SYN` offered. Nothing is
/// stored: this number *is* the connection, until the peer proves it received
/// it.
#[must_use]
pub fn mint(key: &Key, connection: FourTuple, announced: u16, now: u64) -> Sequence {
    let counter = counter_at(now);
    let mss = mss_index(announced);
    Sequence(
        (u32::from(counter) << COUNTER_SHIFT)
            | (u32::from(mss) << MSS_SHIFT)
            | mac(key, connection, counter, mss),
    )
}

/// What a verified cookie told us about the connection it stands for.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Accepted {
    /// The maximum segment size the peer announced, rounded down to the table.
    pub mss: u16,
    /// The sequence number this end had claimed — the cookie itself.
    ///
    /// The connection is built as though a `SYN·ACK` carrying this had been
    /// sent, because one was.
    pub sequence: Sequence,
}

/// Whether `acknowledgement` is a real answer to a cookie this key minted.
///
/// `acknowledgement` is the `ACK` field of the peer's segment, which by the
/// handshake's own arithmetic is the cookie plus one.
///
/// `None` means build nothing. That covers every case: a forged number, a
/// cookie for a different four-tuple, one whose counter or MSS has been edited,
/// and one that is simply too old. **The caller cannot tell those apart, and
/// must not** — a service that reported *why* an `ACK` was refused would be an
/// oracle for grinding the hash.
#[must_use]
pub fn verify(
    key: &Key,
    connection: FourTuple,
    acknowledgement: Sequence,
    now: u64,
) -> Option<Accepted> {
    let cookie = acknowledgement.0.wrapping_sub(1);
    let counter = (cookie >> COUNTER_SHIFT) as u8;
    let mss = ((cookie >> MSS_SHIFT) & 0x7) as u8;

    // The age first, because it is the cheap check, and because a cookie from
    // outside the window is refused whatever its hash says. Wrapping
    // subtraction on eight bits is what makes the counter's four-and-a-half
    // hour wrap a non-event rather than a hole: a cookie minted at 255 and
    // presented at 1 is two ticks old, which is exactly right.
    if counter_at(now).wrapping_sub(counter) > MAX_AGE_TICKS {
        return None;
    }

    if cookie & HASH_MASK != mac(key, connection, counter, mss) {
        return None;
    }

    Some(Accepted {
        mss: mss_of(mss),
        sequence: Sequence(cookie),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addr::{Address, Ipv4Addr, Port};

    fn tuple() -> FourTuple {
        FourTuple {
            local: Address::V4(Ipv4Addr::new(10, 0, 0, 1)),
            local_port: Port(80),
            remote: Address::V4(Ipv4Addr::new(192, 0, 2, 9)),
            remote_port: Port(41234),
        }
    }

    fn other_tuple() -> FourTuple {
        FourTuple {
            remote_port: Port(41235),
            ..tuple()
        }
    }

    fn key() -> Key {
        Key::new(0x0706_0504_0302_0100, 0x0f0e_0d0c_0b0a_0908)
    }

    /// The `ACK` a peer sends back after receiving a `SYN·ACK` carrying `seq`.
    fn answer(seq: Sequence) -> Sequence {
        seq.wrapping_add(1)
    }

    #[test]
    fn a_cookie_this_key_minted_verifies() {
        let now = 900 * TICK_NANOS;
        let cookie = mint(&key(), tuple(), 1460, now);
        let accepted = verify(&key(), tuple(), answer(cookie), now).expect("our own cookie");
        assert_eq!(accepted.sequence, cookie);
        assert_eq!(accepted.mss, 1460);
    }

    #[test]
    fn a_forged_acknowledgement_is_refused() {
        // The whole security claim. An attacker who has never seen a
        // `SYN·ACK` sends an `ACK` with a number of its choosing; every one of
        // these must build nothing.
        let now = 900 * TICK_NANOS;
        for guess in [0u32, 1, 0xffff_ffff, 0x1234_5678, 0x8000_0000] {
            assert_eq!(
                verify(&key(), tuple(), Sequence(guess), now),
                None,
                "a made-up acknowledgement of {guess:#x} was accepted"
            );
        }
    }

    #[test]
    fn a_cookie_for_another_connection_is_refused() {
        // Replay across four-tuples. Without the tuple in the hash, one
        // connection's cookie would open any other.
        let now = 900 * TICK_NANOS;
        let cookie = mint(&key(), tuple(), 1460, now);
        assert_eq!(verify(&key(), other_tuple(), answer(cookie), now), None);
    }

    #[test]
    fn another_key_does_not_open_this_cookie() {
        let now = 900 * TICK_NANOS;
        let cookie = mint(&key(), tuple(), 1460, now);
        let theirs = Key::new(0x0706_0504_0302_0100, 0x0f0e_0d0c_0b0a_0909);
        assert_eq!(verify(&theirs, tuple(), answer(cookie), now), None);
    }

    #[test]
    fn an_expired_cookie_is_refused_and_a_fresh_one_is_not() {
        let minted = 900 * TICK_NANOS;
        let cookie = mint(&key(), tuple(), 1460, minted);

        // Inside the window, at every age the window allows.
        for age in 0..=u64::from(MAX_AGE_TICKS) {
            assert!(
                verify(&key(), tuple(), answer(cookie), minted + age * TICK_NANOS).is_some(),
                "a cookie {age} tick(s) old should still be good"
            );
        }

        // One tick past it.
        let stale = minted + (u64::from(MAX_AGE_TICKS) + 1) * TICK_NANOS;
        assert_eq!(verify(&key(), tuple(), answer(cookie), stale), None);
    }

    #[test]
    fn the_counter_wrapping_is_not_a_hole() {
        // Minted just before the eight-bit counter wraps, answered just after.
        // Naive subtraction would make this cookie appear 254 ticks old and
        // refuse a peer that did nothing wrong.
        let minted = 255 * TICK_NANOS;
        let cookie = mint(&key(), tuple(), 1460, minted);
        let after_wrap = 257 * TICK_NANOS; // counter 1, two ticks later
        assert_eq!(counter_at(minted), 255);
        assert_eq!(counter_at(after_wrap), 1);
        assert!(verify(&key(), tuple(), answer(cookie), after_wrap).is_some());
    }

    #[test]
    fn editing_the_counter_in_a_captured_cookie_does_not_age_it_backwards() {
        // The attack the counter being inside the hash exists to stop: take a
        // real cookie that has expired and rewrite its counter to now.
        let minted = 900 * TICK_NANOS;
        let cookie = mint(&key(), tuple(), 1460, minted);
        let much_later = minted + 50 * TICK_NANOS;

        let fresh_counter = counter_at(much_later);
        let edited = Sequence(
            (u32::from(fresh_counter) << COUNTER_SHIFT) | (cookie.0 & ((1 << COUNTER_SHIFT) - 1)),
        );
        assert_eq!(verify(&key(), tuple(), answer(edited), much_later), None);
    }

    #[test]
    fn editing_the_mss_in_a_captured_cookie_is_refused() {
        // A peer offering 536 must not have its cookie edited into 1460, which
        // would make this end send segments the path may not carry.
        let now = 900 * TICK_NANOS;
        let cookie = mint(&key(), tuple(), 536, now);
        assert_eq!(mss_index(536), 0);

        let edited = Sequence(cookie.0 | (7 << MSS_SHIFT));
        assert_eq!(verify(&key(), tuple(), answer(edited), now), None);
    }

    #[test]
    fn the_mss_rounds_down_and_never_up() {
        // Rounding up would tell this end it may send segments larger than the
        // peer said it can receive.
        for announced in [0u16, 1, 535, 536, 537, 1279, 1459, 1460, 1461, 9000] {
            let carried = mss_of(mss_index(announced));
            assert!(
                carried <= announced.max(MSS_TABLE[0]),
                "announced {announced} came back as {carried}"
            );
        }
        assert_eq!(mss_of(mss_index(1459)), 1440);
        assert_eq!(mss_of(mss_index(1460)), 1460);
        assert_eq!(mss_of(mss_index(9000)), 1460);
        assert_eq!(mss_of(mss_index(0)), 536, "below the table floors at 536");
    }

    #[test]
    fn the_table_ascends_because_the_index_walk_assumes_it() {
        for pair in MSS_TABLE.windows(2) {
            assert!(pair[0] < pair[1], "MSS_TABLE must ascend: {pair:?}");
        }
    }

    #[test]
    fn a_cookie_does_not_repeat_across_connections_or_ticks() {
        // Not a security property on its own -- the hash is -- but a collision
        // here would mean two peers sharing a sequence number, which is a
        // correctness problem regardless of attackers.
        let a = mint(&key(), tuple(), 1460, 900 * TICK_NANOS);
        let b = mint(&key(), other_tuple(), 1460, 900 * TICK_NANOS);
        let c = mint(&key(), tuple(), 1460, 901 * TICK_NANOS);
        assert_ne!(a, b);
        assert_ne!(a, c);
    }
}
