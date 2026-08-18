// SPDX-License-Identifier: Apache-2.0
//! The initial sequence number, by RFC 6528's construction.
//!
//! [RFC 0020](../../../docs/rfc/0020-tcp.md) step 1, and the reason RFC 0021
//! exists. **A TCP initial sequence number must be unpredictable**, or an
//! off-path attacker who never sees a packet from a connection can guess where
//! its window is and inject data into it. That is not hardening; it is the
//! difference between this stack being safe on a network and not.
//!
//! # The expression, and why each term is there
//!
//! RFC 6528 §3:
//!
//! ```text
//! ISN = M + F(localip, localport, remoteip, remoteport, secretkey)
//! ```
//!
//! - **`M`**, a counter incrementing every four microseconds, is what makes a
//!   *reincarnated* connection — the same four-tuple, opened again — start
//!   somewhere later than the one before it, so a segment from the dead
//!   connection cannot be mistaken for a live one. It is why the ISN is not
//!   simply a random number: a random number has no relationship to the
//!   connection it replaces.
//! - **`F`**, a keyed function of the four-tuple, is what stops the ISN of one
//!   connection revealing the ISN of another. Without it, `M` alone is a clock,
//!   and anyone who can open a connection to this machine can read it.
//! - **The secret** is what makes `F` uncomputable from outside, and it is drawn
//!   once, from hardware, at start-up. RFC 6528 §3 asks for at least 128 bits
//!   and says plainly that "the result of `F()` is no more secure than the
//!   secret key".
//!
//! Both terms are needed and they answer different attacks. Dropping `F` is the
//! 4.4BSD behaviour RFC 6528 was written to replace; dropping `M` gives up the
//! old-duplicate protection, which is what makes this a *sequence* number rather
//! than a nonce.
//!
//! # What this module is not allowed to do
//!
//! It does not draw the secret. `bhaskix-net` sits at the same dependency layer
//! as `bhaskix-rand` and cannot reach it — and that is the right shape rather
//! than an obstacle worked around, because it keeps every function here pure: a
//! host test supplies a key and a clock and gets an exact number back, with no
//! processor involved. The one caller with hardware, `bin/tcpd`, draws the key
//! at start-up and **does not start if it cannot**.

use crate::addr::{Address, Port};
use crate::siphash::{self, Key};
use crate::tcp::{FourTuple, Sequence};

/// Nanoseconds per tick of RFC 6528's `M`.
///
/// The RFC says "the 4 microsecond timer", which fixes this number rather than
/// leaving it to taste. It is expressed in nanoseconds because that is the unit
/// every `now` in this crate carries.
pub const TICK_NANOS: u64 = 4_000;

/// Bytes in the encoded four-tuple, now that both families exist.
///
/// A family byte and a sixteen-byte address slot per end, ports after each:
/// fixed-size again, because a v4 address in a padded slot with its family
/// byte in front cannot collide with any v6 arrangement, and a fixed size
/// keeps the hash input's length out of the attacker's hands. The second
/// family arrived exactly where the old comment promised it would — this
/// constant, this function — and nowhere else in the file.
const ENCODED: usize = 38;

/// The tag for an IPv4 address slot in the encoding.
const FAMILY_V4: u8 = 4;

/// The tag for an IPv6 address slot in the encoding.
const FAMILY_V6: u8 = 6;

/// The initial sequence number for `connection` at `now`.
///
/// `now` is monotonic nanoseconds, as everywhere else in this crate. `key` is
/// the per-boot secret; the same key, tuple and instant always give the same
/// number, which is what makes `M` mean anything.
///
/// # This function is total
///
/// There is no error path and no `Option`. Every refusal that belongs to
/// unpredictability happened when the key was drawn — [`Key::draw`] returns
/// `None` and the caller stops — so by the time there is a key to pass here,
/// the question has been answered. A fallible signature would invite a caller
/// to handle the failure twice and get it wrong once.
#[must_use]
pub fn initial_sequence(key: &Key, connection: FourTuple, now: u64) -> Sequence {
    let f = siphash::hash(key, &encode(connection));

    // Both terms are taken modulo 2³², written as a mask rather than an `as`
    // cast so that the truncation reads as arithmetic somebody chose. `M` is a
    // 32-bit timer by RFC 6528's definition, and it wraps every 2³² ticks —
    // 17,180 seconds, or four hours and forty-six minutes, at four microseconds
    // — which is the wrap the construction expects rather than a defect.
    let m = ((now / TICK_NANOS) & u64::from(u32::MAX)) as u32;
    Sequence(m.wrapping_add((f & u64::from(u32::MAX)) as u32))
}

/// The four-tuple as bytes, in a fixed order and with fixed widths.
///
/// The irrefutable `let Address::V4(..)` that used to live here did its job:
/// it stopped compiling the day the second family was added, and this
/// per-address encoding is what it forced. Each end is a family byte, a
/// sixteen-byte address slot (v4 in the first four bytes, the rest zero, the
/// family byte making the padding unambiguous), and the port — so no two
/// distinct tuples, same-family or cross-family, encode to the same bytes.
fn encode(connection: FourTuple) -> [u8; ENCODED] {
    // Ports in network order, which is the order they are seen in on the wire.
    let mut out = [0u8; ENCODED];
    encode_end(&mut out[0..19], connection.local, connection.local_port);
    encode_end(&mut out[19..38], connection.remote, connection.remote_port);
    out
}

/// One end of the tuple: family byte, padded address slot, port.
fn encode_end(out: &mut [u8], address: Address, port: Port) {
    match address {
        Address::V4(address) => {
            out[0] = FAMILY_V4;
            out[1..5].copy_from_slice(&address.octets());
        }
        Address::V6(address) => {
            out[0] = FAMILY_V6;
            out[1..17].copy_from_slice(&address.octets());
        }
    }
    out[17..19].copy_from_slice(&port.0.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addr::{Ipv4Addr, Port};

    const HERE: Address = Address::V4(Ipv4Addr::new(10, 0, 2, 15));
    const THERE: Address = Address::V4(Ipv4Addr::new(10, 0, 2, 2));

    /// An arbitrary but fixed secret. Fixed so every expectation below is an
    /// exact number rather than a property of whatever was drawn.
    const SECRET: Key = Key::new(0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210);

    fn tuple(local_port: u16, remote_port: u16) -> FourTuple {
        FourTuple {
            local: HERE,
            local_port: Port(local_port),
            remote: THERE,
            remote_port: Port(remote_port),
        }
    }

    #[test]
    fn the_same_connection_at_the_same_instant_is_the_same_number() {
        // Not a tautology: it is the property that makes `M` meaningful. If the
        // ISN were freshly random, a reincarnated connection would have no
        // relationship to the one it replaces and RFC 6528's whole argument
        // about old duplicates would not apply.
        let now = 1_234_567_890;
        assert_eq!(
            initial_sequence(&SECRET, tuple(49152, 80), now),
            initial_sequence(&SECRET, tuple(49152, 80), now)
        );
    }

    /// Four microseconds in nanoseconds, written out rather than taken from
    /// [`TICK_NANOS`].
    ///
    /// **This literal is the whole point of the two tests below.** They were
    /// first written against the constant, which made them self-consistent:
    /// substituting a millisecond for RFC 6528's four microseconds left every
    /// test in this file green, and it was caught by breaking the constant on
    /// purpose rather than by review. A test that reads its expectation from the
    /// code it is testing measures nothing, which is the same reason
    /// [`crate::checksum`] is tested against RFC 1071's worked example instead
    /// of a round trip.
    const FOUR_MICROSECONDS: u64 = 4_000;

    #[test]
    fn the_timer_ticks_at_the_rate_the_rfc_specifies() {
        assert_eq!(TICK_NANOS, FOUR_MICROSECONDS);
    }

    #[test]
    fn the_clock_term_advances_exactly_one_per_four_microseconds() {
        // An exact difference, not merely a different number. `F` is unchanged
        // across these calls, so the whole difference is `M`.
        let connection = tuple(49152, 80);
        let base = initial_sequence(&SECRET, connection, 0);
        for ticks in [1u32, 2, 1000, 250_000] {
            let later = initial_sequence(&SECRET, connection, u64::from(ticks) * FOUR_MICROSECONDS);
            assert_eq!(
                later.0.wrapping_sub(base.0),
                ticks,
                "at {ticks} ticks after zero"
            );
            assert!(base.precedes(later));
        }
    }

    #[test]
    fn within_one_tick_the_number_does_not_move() {
        // The other half of the same claim: the timer counts four microsecond
        // periods, so it must not advance for anything shorter.
        let connection = tuple(49152, 80);
        let base = initial_sequence(&SECRET, connection, 0);
        assert_eq!(
            initial_sequence(&SECRET, connection, FOUR_MICROSECONDS - 1),
            base
        );
        assert_ne!(
            initial_sequence(&SECRET, connection, FOUR_MICROSECONDS),
            base
        );
    }

    #[test]
    fn the_clock_wraps_rather_than_panicking() {
        // `overflow-checks` is on in every profile. A machine up long enough to
        // wrap the 32-bit timer must produce a sequence number, not a panic in
        // the service that holds every connection. Uptimes chosen either side of
        // the wrap, which is at 2³² ticks.
        let connection = tuple(49152, 80);
        let wrap = (u64::from(u32::MAX) + 1) * TICK_NANOS;
        assert_eq!(
            initial_sequence(&SECRET, connection, wrap),
            initial_sequence(&SECRET, connection, 0),
            "one full turn of the timer returns to the same offset"
        );
        // And far past it, at a `now` no clock will reach, to prove the
        // arithmetic is total rather than merely untested there.
        let _ = initial_sequence(&SECRET, connection, u64::MAX);
    }

    #[test]
    fn every_field_of_the_tuple_changes_the_number() {
        // The failure this guards against is an encoder that drops a field —
        // the remote port is the easiest to leave out and the most damaging,
        // because a scan of one port would then reveal the ISN for every other.
        let now = 42 * TICK_NANOS;
        let base = initial_sequence(&SECRET, tuple(49152, 80), now);
        assert_ne!(base, initial_sequence(&SECRET, tuple(49153, 80), now));
        assert_ne!(base, initial_sequence(&SECRET, tuple(49152, 81), now));

        let other_local = FourTuple {
            local: Address::V4(Ipv4Addr::new(10, 0, 2, 16)),
            ..tuple(49152, 80)
        };
        let other_remote = FourTuple {
            remote: Address::V4(Ipv4Addr::new(10, 0, 2, 3)),
            ..tuple(49152, 80)
        };
        assert_ne!(base, initial_sequence(&SECRET, other_local, now));
        assert_ne!(base, initial_sequence(&SECRET, other_remote, now));
    }

    #[test]
    fn the_ends_are_not_interchangeable() {
        // A tuple hashed into an order-insensitive encoding would make a
        // connection and its mirror image share a sequence number, which hands
        // an attacker who can open the reverse connection the number for the
        // forward one.
        let now = 7 * TICK_NANOS;
        let forward = tuple(49152, 80);
        let mirrored = FourTuple {
            local: forward.remote,
            local_port: forward.remote_port,
            remote: forward.local,
            remote_port: forward.local_port,
        };
        assert_ne!(
            initial_sequence(&SECRET, forward, now),
            initial_sequence(&SECRET, mirrored, now)
        );
    }

    #[test]
    fn an_address_and_a_port_are_not_the_same_bytes() {
        // 10.0.2.15:49152 against 10.0.2.15 with the port's bytes shifted into
        // the address. Fixed widths make this impossible; the test is here
        // because a variable-width encoding is the natural "simplification" of
        // `encode`, and this is what it would cost.
        let now = 0;
        let a = FourTuple {
            local: Address::V4(Ipv4Addr::new(10, 0, 2, 15)),
            local_port: Port(0xc000),
            remote: THERE,
            remote_port: Port(80),
        };
        let b = FourTuple {
            local: Address::V4(Ipv4Addr::new(10, 0, 2, 0xc0)),
            local_port: Port(0x0f00),
            remote: THERE,
            remote_port: Port(80),
        };
        assert_ne!(
            initial_sequence(&SECRET, a, now),
            initial_sequence(&SECRET, b, now)
        );
    }

    #[test]
    fn a_different_secret_gives_a_different_number() {
        // RFC 6528 §3: `F()` must not be computable from the outside. An
        // attacker who knows the algorithm, the tuple and the time still needs
        // the key, and this is the assertion that says so.
        let now = 99 * TICK_NANOS;
        let connection = tuple(49152, 80);
        let base = initial_sequence(&SECRET, connection, now);
        assert_ne!(base, initial_sequence(&Key::new(0, 0), connection, now));
        assert_ne!(
            base,
            initial_sequence(
                &Key::new(0x0123_4567_89ab_cdee, 0xfedc_ba98_7654_3210),
                connection,
                now
            ),
            "one bit of key is enough"
        );
    }

    #[test]
    fn adjacent_ports_do_not_give_adjacent_sequence_numbers() {
        // The property `F` exists for, and the one a counter fails outright: an
        // attacker who opens a connection and reads its ISN must learn nothing
        // about the next port's. Checked across sixty-four adjacent pairs rather
        // than one, so that passing is a statement about the function and not
        // about one lucky pair.
        //
        // The bound is generous on purpose — a keyed hash puts these numbers
        // anywhere in 2³², so a gap under a kilobyte in either direction is
        // roughly a one-in-two-million event per pair, while the counter this
        // rules out gives exactly one every time.
        let now = 5 * TICK_NANOS;
        for local_port in 49152..49216u16 {
            let first = initial_sequence(&SECRET, tuple(local_port, 80), now);
            let second = initial_sequence(&SECRET, tuple(local_port + 1, 80), now);
            let gap = second.0.wrapping_sub(first.0);
            assert!(
                (1024..=u32::MAX - 1024).contains(&gap),
                "ports {local_port} and {} gave sequence numbers {gap} apart",
                local_port + 1
            );
        }
    }
}
