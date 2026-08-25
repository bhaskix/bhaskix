// SPDX-License-Identifier: Apache-2.0
//! Coverage-guided fuzzing of the SYN cookie.
//!
//! [RFC 0048](../../docs/rfc/0048-a-listener-that-cannot-be-wedged.md) step 2
//! asks for this by name, and the reason is that a cookie is the one place in
//! this stack where **an attacker chooses the input to a security decision**.
//! Every other network parser here is handed bytes and asked what they mean; a
//! cookie is handed a number and asked whether *this machine minted it*. Get it
//! wrong in the permissive direction and a listener accepts connections nobody
//! opened.
//!
//! # What is asserted
//!
//! Two properties, and they pull in opposite directions on purpose.
//!
//! **Soundness — nothing this key minted is ever refused.** A cookie minted for
//! a tuple, at an instant, must verify at every instant inside its window, and
//! must report the segment size it was minted with. A cookie implementation
//! that refuses its own work is a listener that cannot be connected to, which
//! is the denial of service this whole RFC exists to remove, arrived at from
//! the other side.
//!
//! **Refusal — a number the fuzzer chose is not accepted.** Every arbitrary
//! acknowledgement is offered for verification. This cannot assert *never*: the
//! hash is twenty-one bits, so one draw in two million is a genuine forgery and
//! the target would be asserting against arithmetic it deliberately chose. What
//! it asserts instead is that any accepted number **verifies as its own
//! cookie** — the same acknowledgement offered again gives the same answer, and
//! the sequence it reports is the number minus one. A collision is allowed; an
//! *inconsistency* is a bug.
//!
//! And no panic, from any input, which for arithmetic over indices and shifts
//! is not a formality: the MSS index is three bits used to index a table of
//! eight, and an off-by-one there is a panic reachable from the network.
//!
//! Run with:
//!
//! ```text
//! cargo +nightly fuzz run tcp_cookie -- -max_total_time=3600
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;

use bhaskix_net::{
    addr::{Address, Ipv4Addr, Ipv6Addr, Port},
    siphash::Key,
    tcp::{
        FourTuple, Sequence,
        cookie::{self, MAX_AGE_TICKS, TICK_NANOS},
    },
};

/// A reader that never runs out, for the reason `tcp_state`'s does.
struct Script<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Script<'_> {
    fn byte(&mut self) -> u8 {
        let value = self.bytes.get(self.at).copied().unwrap_or(0);
        self.at = self.at.saturating_add(1);
        value
    }

    fn u16(&mut self) -> u16 {
        u16::from(self.byte()) << 8 | u16::from(self.byte())
    }

    fn u32(&mut self) -> u32 {
        u32::from(self.u16()) << 16 | u32::from(self.u16())
    }

    fn u64(&mut self) -> u64 {
        u64::from(self.u32()) << 32 | u64::from(self.u32())
    }

    /// An address of either family, because the encoding the cookie hashes has
    /// a slot per family and a v4/v6 confusion there is a real collision.
    fn address(&mut self) -> Address {
        if self.byte() & 1 == 0 {
            Address::V4(Ipv4Addr::new(
                self.byte(),
                self.byte(),
                self.byte(),
                self.byte(),
            ))
        } else {
            let mut octets = [0u8; 16];
            for slot in &mut octets {
                *slot = self.byte();
            }
            Address::V6(Ipv6Addr(octets))
        }
    }

    fn tuple(&mut self) -> FourTuple {
        FourTuple {
            local: self.address(),
            local_port: Port(self.u16()),
            remote: self.address(),
            remote_port: Port(self.u16()),
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let mut script = Script { bytes: data, at: 0 };

    let key = Key::new(script.u64(), script.u64());
    let connection = script.tuple();
    let announced = script.u16();
    // Kept well inside `u64` so that adding the window below cannot overflow;
    // the arithmetic under test wraps on the eight-bit counter, not here.
    let now = script.u64() % (1 << 48);

    // --- soundness ---------------------------------------------------------
    let minted = cookie::mint(&key, connection, announced, now);
    let expected = cookie::mss_of(cookie::mss_index(announced));

    for age in 0..=u64::from(MAX_AGE_TICKS) {
        let later = now + age * TICK_NANOS;
        let accepted = cookie::verify(&key, connection, minted.wrapping_add(1), later)
            .expect("a cookie this key minted, inside its own window, must verify");
        assert_eq!(accepted.sequence, minted, "the cookie came back changed");
        assert_eq!(accepted.mss, expected, "the segment size did not survive");
    }

    // --- refusal -----------------------------------------------------------
    // A number the fuzzer chose. Accepting one is allowed -- twenty-one bits of
    // hash means it happens -- but it must then behave like a cookie.
    let guess = Sequence(script.u32());
    if let Some(accepted) = cookie::verify(&key, connection, guess, now) {
        assert_eq!(
            accepted.sequence,
            Sequence(guess.0.wrapping_sub(1)),
            "an accepted acknowledgement reported a sequence that is not its own"
        );
        let again = cookie::verify(&key, connection, guess, now);
        assert_eq!(again, Some(accepted), "verification is not a function");
    }

    // A cookie offered for a different connection, which is the replay the
    // four-tuple is in the hash to stop. Refused unless the fuzzer found a
    // collision, and consistent either way.
    let elsewhere = script.tuple();
    if elsewhere != connection
        && let Some(accepted) = cookie::verify(&key, elsewhere, minted.wrapping_add(1), now)
    {
        assert_eq!(accepted.sequence, minted);
    }

    // And past the window, where only the age check should speak.
    let stale = now + (u64::from(MAX_AGE_TICKS) + 1) * TICK_NANOS;
    assert!(
        cookie::verify(&key, connection, minted.wrapping_add(1), stale).is_none()
            || cookie::counter_at(stale) == cookie::counter_at(now),
        "a cookie outside its window was accepted"
    );
});
