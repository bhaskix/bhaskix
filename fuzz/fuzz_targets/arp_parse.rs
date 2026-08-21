// SPDX-License-Identifier: Apache-2.0
//! Coverage-guided fuzzing of the ARP parser and the cache it fills.
//!
//! **The cache is fuzzed too, deliberately.** The parser is twenty-eight fixed
//! bytes and is the easy half; the cache is remotely-driven state, and state is
//! where the interesting failures are. A campaign that stopped at `parse` would
//! cover the half that was never going to be wrong.
//!
//! So every packet that parses is offered to a cache, and the cache's invariant
//! is checked afterwards: it must never hold more entries than it has slots,
//! and it must never return a hardware address that would redirect this
//! station's traffic to every station on the segment.
//!
//! # What ARP cannot be given
//!
//! Authentication. Any station may claim any address and nothing in the
//! protocol distinguishes a legitimate reply from a forged one, so this target
//! is not looking for poisoning — poisoning is not preventable here. It is
//! looking for a packet that makes the cache do something worse than believe a
//! lie: exceed its own bounds, or accept a mapping it documents as refused.
//!
//! Run with:
//!
//! ```text
//! cargo +nightly fuzz run arp_parse -- -max_total_time=3600
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;

use bhaskix_net::{
    addr::{Address, Ipv4Addr, MacAddr},
    arp::ArpPacket,
    neighbour::NeighbourCache,
};

fuzz_target!(|data: &[u8]| {
    const SLOTS: usize = 4;
    const LIFETIME: u64 = 60_000_000_000;

    // `NeighbourCache`, not `ArpCache`: RFC 0029 step 2 replaced ARP's table
    // with one table for both families, and the protocol address became
    // `Address` rather than `Ipv4Addr`. **This target did not compile from
    // 2026-08-18 until 2026-08-21**, so it ran no executions at all in that
    // window, and nothing said so — see the module comment.
    let mut cache = NeighbourCache::<SLOTS>::new(LIFETIME);

    // Chunked, so one input drives a sequence of packets into one cache rather
    // than a single packet into a fresh one. Eviction, replacement and expiry
    // are only reachable across several packets, and they are the parts with
    // decisions in them.
    for (step, chunk) in data.chunks(28).enumerate() {
        let Ok(packet) = ArpPacket::parse(chunk) else {
            continue;
        };
        let now = step as u64 * 1_000_000_000;
        let sender = Address::V4(packet.sender_protocol);
        let learned = cache.learn(sender, packet.sender_hardware, now);

        if learned {
            // What went in must come back, and must not be a group address --
            // believing one turns every unicast send into a broadcast, which is
            // a redirection primitive handed over for free.
            let found = cache.lookup(sender, now);
            assert_eq!(found, Some(packet.sender_hardware));
            assert!(!packet.sender_hardware.is_group());
            assert_ne!(packet.sender_protocol, Ipv4Addr::UNSPECIFIED);
        }

        // The bound the fixed table exists to provide.
        assert!(cache.live(now) <= SLOTS);
    }

    let _ = cache.forget(Address::V4(Ipv4Addr::new(10, 0, 0, 1)));
    let _ = cache.lookup(Address::V4(Ipv4Addr::BROADCAST), 0);
    let _ = cache.learn(Address::V4(Ipv4Addr::new(10, 0, 0, 2)), MacAddr::BROADCAST, 0);
});
