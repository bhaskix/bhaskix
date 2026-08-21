// SPDX-License-Identifier: Apache-2.0
//! Coverage-guided fuzzing of IPv6 and the four NDP messages.
//!
//! **The debt this pays.** [RFC 0029](../../docs/rfc/0029-ipv6.md) landed IPv6
//! on 2026-08-18 as a second address family rather than a second stack, with
//! zero-`unsafe` parsers — and committed only to the **seeded mutation
//! harness** in `net/src/fuzz.rs`, never to a libFuzzer target. `coding-style.md`
//! §8 names both mechanisms and is explicit that one does not replace the
//! other: *coverage guidance finds what blind mutation cannot, and blind
//! mutation runs on every commit without a nightly toolchain.* The v4 path has
//! had both since RFC 0018. The v6 path had one, and it was the weaker one, on
//! the newest parsers in the tree. The security reassessment of 2026-08-20
//! recorded that as gap 6.
//!
//! # The wall, and why this target does not pretend it is not there
//!
//! **Every ICMPv6 message carries a mandatory checksum over an IPv6
//! pseudo-header** — 16 bits covering forty bytes the message does not
//! contain. Unlike IPv4's optional UDP checksum, there is no zero-means-absent
//! escape: `icmpv6` refuses a message whose sum does not match, so a fuzzer
//! that cannot produce one never reaches a single field of a single NDP
//! message.
//!
//! The reachability audit of 2026-08-21 measured what that costs elsewhere and
//! the answer was surprising in both directions: a 16-bit checksum turned out
//! **not** to be a wall — `udp_parse`, `icmp_parse` and `ipv4_parse` all reach
//! their checksum-verified arms from an empty corpus, because a coverage-guided
//! fuzzer with byte-compare feedback finds a 16-bit sum in a few million
//! executions. A 32-bit checksum and a 48-bit address are walls. So this target
//! keeps an **as-given** arm, which is not decoration: it is the arm that
//! exercises the refusal itself, and the audit says it will get through.
//!
//! And it adds a **repaired** arm anyway, for the reason `ipv4_parse` already
//! gives: recomputing the sum is what an attacker does, so the fields behind it
//! are the ones worth attacking, and waiting several million executions for the
//! fuzzer to rediscover arithmetic is time not spent on the parser.
//!
//! # The arms
//!
//! - **A — as given.** The input read as an IPv6 datagram, and as each of the
//!   four ICMPv6 messages. Proves the refusals do not panic, and reaches the
//!   checksum test itself.
//! - **B — a well-formed datagram the fuzzer composed.** A real IPv6 header
//!   written around a fuzzer-chosen payload, so the header's own agreement
//!   between `payload_length` and the buffer is exercised from the *inside*:
//!   the interesting inputs are the ones that disagree by a little, not the
//!   ones that are nonsense.
//! - **C — an NDP message, repaired.** One of the four written properly, the
//!   fuzzer's bytes spliced over it, and **the checksum re-derived**, so the
//!   mutation lands on option parsing, the target address, the flags and the
//!   prefix rather than dying at the sum.
//! - **D — a sequence into one neighbour cache.** NDP exists to fill a table,
//!   and a table has decisions in it — replacement, expiry, the refusals for a
//!   group hardware address or an unspecified protocol address. One input
//!   drives several messages into one cache, which is the only way those are
//!   reachable.
//!
//! # What counts as a failure
//!
//! A panic, an abort, or a hang. **Not** a refusal: random bytes are not a
//! datagram, and `BadVersion` is the correct answer. `bhaskix-net` carries
//! `#![forbid(unsafe_code)]`, so an index out of bounds is a panic rather than
//! a silent read — which is what makes a panic worth fuzzing for.
//!
//! Run with:
//!
//! ```text
//! cargo +nightly fuzz run ipv6_ndp -- -max_total_time=3600
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;

use bhaskix_net::{
    addr::{Address, Ipv6Addr, MacAddr},
    checksum, icmpv6,
    ipv6::{self, Ipv6Header, NextHeader},
    neighbour::NeighbourCache,
};

/// The two ends every message here is addressed between.
///
/// Fixed rather than fuzzer-chosen, and that is deliberate: the addresses are
/// pseudo-header input, so varying them only varies the checksum the fuzzer
/// must match. The parsers do not branch on them.
const SOURCE: Ipv6Addr = Ipv6Addr::new([0xfe80, 0, 0, 0, 0, 0, 0, 1]);
const DESTINATION: Ipv6Addr = Ipv6Addr::new([0xfe80, 0, 0, 0, 0, 0, 0, 2]);
const MAC: MacAddr = MacAddr([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);

/// Re-derives an ICMPv6 checksum in place, which is the arithmetic an attacker
/// performs after changing a field.
///
/// The sum covers the pseudo-header and the message, with the checksum field
/// itself counted as zero — the same shape `icmpv6` verifies with.
fn seal(bytes: &mut [u8]) {
    if bytes.len() < icmpv6::HEADER {
        return;
    }
    let length = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    let pseudo = ipv6::pseudo_header(SOURCE, DESTINATION, NextHeader::ICMPV6, length);
    bytes[2..4].copy_from_slice(&[0, 0]);
    let sum = checksum(&[&pseudo, bytes]);
    bytes[2..4].copy_from_slice(&sum.to_be_bytes());
}

/// Every parsed shape, tried against the same bytes.
///
/// All four, always: a message is one type field away from being another, and
/// a parser that agreed with the wrong one would only show up here.
fn parse_all(bytes: &[u8], cache: &mut NeighbourCache<4>, now: u64) {
    if let Ok(echo) = icmpv6::Echo::parse(bytes, SOURCE, DESTINATION) {
        // The payload is a slice of the input; a longer one would mean the
        // parser invented bytes, which a `forbid(unsafe_code)` crate cannot do
        // by accident but can do by arithmetic.
        assert!(echo.payload.len() <= bytes.len());
    }

    if let Ok(advertisement) = icmpv6::NeighbourAdvertisement::parse(bytes, SOURCE, DESTINATION)
        && let Some(link) = advertisement.target_link
    {
        // What a caller does with one: learn it. The cache's own refusals --
        // a group hardware address, an unspecified target -- are only reachable
        // through a message that parsed.
        let learned = cache.learn(Address::V6(advertisement.target), link, now);
        if learned {
            assert_eq!(
                cache.lookup(Address::V6(advertisement.target), now),
                Some(link),
                "what the cache accepted must come back"
            );
        }
    }

    let _ = icmpv6::NeighbourSolicitation::parse(bytes, SOURCE, DESTINATION);
    let _ = icmpv6::RouterAdvertisement::parse(bytes, SOURCE, DESTINATION);
}

/// Writes one of the four NDP messages, chosen by `which`, and answers its
/// length.
fn write_ndp(out: &mut [u8], which: u8, seed: &[u8]) -> Option<usize> {
    let flag = seed.first().copied().unwrap_or(0);
    let target = Ipv6Addr::new([0xfe80, 0, 0, 0, 0, 0, 0, u16::from(flag)]);
    let link = if flag & 1 == 0 { Some(MAC) } else { None };

    match which % 4 {
        // `is_reply`, not a type byte: the writer takes the bool and chooses
        // the type itself, so both echo types are reachable from one flag.
        0 => icmpv6::write_echo(out, SOURCE, DESTINATION, flag & 16 == 0, 1, 1, seed).ok(),
        1 => icmpv6::write_neighbour_advertisement(
            out,
            SOURCE,
            DESTINATION,
            target,
            flag & 2 == 0,
            link,
        )
        .ok(),
        2 => icmpv6::write_neighbour_solicitation(out, SOURCE, DESTINATION, target, link).ok(),
        _ => icmpv6::write_router_advertisement(
            out,
            SOURCE,
            DESTINATION,
            u16::from_be_bytes([flag, flag]),
            link,
            (flag & 4 == 0).then_some(icmpv6::PrefixInformation {
                prefix_length: flag % 129,
                autonomous: flag & 8 == 0,
                valid_seconds: u32::from(flag) * 3600,
                prefix: Ipv6Addr::new([0xfec0, 0, 0, 0, 0, 0, 0, 0]),
            }),
        )
        .ok(),
    }
}

fuzz_target!(|data: &[u8]| {
    // A message this stack would ever see is far below this. The bound caps
    // what is *built*, not what is parsed: arm A reads the input whole.
    const MAX_BUILT: usize = 1024;

    let mut cache = NeighbourCache::<4>::new(60_000_000_000);

    arm_as_given(data, &mut cache);
    arm_composed(data);
    arm_repaired(data, &mut cache, MAX_BUILT);
    arm_sequence(data, MAX_BUILT);
});

/// Arm A — the input as it arrived.
fn arm_as_given(data: &[u8], cache: &mut NeighbourCache<4>) {
    if let Ok((header, payload)) = Ipv6Header::parse(data) {
        // The parser's contract, asserted rather than assumed: the payload is
        // **exactly the stated length**, not the rest of the buffer.
        //
        // The first version of this assertion said `data.len() - HEADER`, and
        // the fuzzer refuted it in seconds with a header claiming a zero-length
        // payload followed by twenty trailing bytes. That is a legal datagram —
        // IPv6 does not require one to fill its buffer, and `parse` returns
        // `&bytes[HEADER..HEADER + payload_length]` — so the assertion was
        // wrong and the parser was right. It is written here as the stronger
        // claim it should always have been: what came back is what the header
        // said, re-derived from the bytes rather than assumed from the length.
        let stated = usize::from(u16::from_be_bytes([data[4], data[5]]));
        assert_eq!(payload.len(), stated, "the payload is the stated length");
        assert!(ipv6::HEADER + payload.len() <= data.len());
        assert!(!header.next_header.is_extension());
    }
    parse_all(data, cache, 0);
}

/// Arm B — a real header the fuzzer supplied the payload for.
fn arm_composed(data: &[u8]) {
    let payload = data.get(..data.len().min(512)).unwrap_or(&[]);
    let mut bytes = vec![0u8; ipv6::HEADER + payload.len()];
    let next = NextHeader(payload.first().copied().unwrap_or(58));
    if ipv6::write_header(&mut bytes, SOURCE, DESTINATION, next, 64, payload.len()).is_err() {
        return;
    }
    bytes[ipv6::HEADER..].copy_from_slice(payload);

    // The stated length, moved off the truth by a little. A datagram that
    // disagrees with its buffer by one is the interesting input; one that
    // disagrees by a thousand is caught by the same branch.
    if let Some(nudge) = data.last() {
        let stated = (ipv6::HEADER + payload.len()) as i32 - 40 + i32::from(*nudge % 81) - 40;
        if let Ok(length) = u16::try_from(stated.max(0)) {
            bytes[4..6].copy_from_slice(&length.to_be_bytes());
        }
    }

    if let Ok((header, carried)) = Ipv6Header::parse(&bytes) {
        assert!(carried.len() <= bytes.len() - ipv6::HEADER);
        assert!(!header.next_header.is_extension());
    }
}

/// Arm C — an NDP message, mutated, and the checksum re-derived.
fn arm_repaired(data: &[u8], cache: &mut NeighbourCache<4>, max: usize) {
    let Some((&which, rest)) = data.split_first() else {
        return;
    };
    let mut built = vec![0u8; max];
    let Some(used) = write_ndp(&mut built, which, rest) else {
        return;
    };
    built.truncate(used);

    // The fuzzer's bytes over the message, from an offset it chooses, so the
    // type field, the flags, the target address and the option chain are each
    // reachable rather than only the tail.
    if let Some(offset) = rest
        .first()
        .map(|byte| usize::from(*byte) % built.len().max(1))
    {
        let room = built.len() - offset;
        let take = rest.len().min(room);
        built[offset..offset + take].copy_from_slice(&rest[..take]);
    }

    seal(&mut built);
    parse_all(&built, cache, 1);
}

/// Arm D — several messages into one cache, which is where the decisions are.
fn arm_sequence(data: &[u8], max: usize) {
    // Four slots and five messages: the table must reach capacity for
    // replacement to be reachable at all.
    const STEPS: usize = 8;

    let mut cache = NeighbourCache::<4>::new(1_000_000);
    for (step, chunk) in data.chunks(24).take(STEPS).enumerate() {
        let mut built = vec![0u8; max];
        let Some(used) = write_ndp(&mut built, step as u8, chunk) else {
            continue;
        };
        built.truncate(used);
        let take = chunk.len().min(built.len());
        built[..take].copy_from_slice(&chunk[..take]);
        seal(&mut built);

        // Time advances, so expiry is reachable and not only replacement.
        let now = step as u64 * 250_000;
        parse_all(&built, &mut cache, now);
        assert!(cache.live(now) <= 4, "the table's own bound");
    }
}

fn bad() -> u8 {
    1
}
