// SPDX-License-Identifier: Apache-2.0
//! One neighbour table, two fill mechanisms.
//!
//! [RFC 0029](../../docs/rfc/0029-ipv6.md) step 2. This began life as
//! `arp::ArpCache`, keyed on [`Ipv4Addr`](crate::addr::Ipv4Addr); the key is
//! now [`Address`], because the question the table answers — "which station
//! carries this network address" — is the same question in both families,
//! and one table with one eviction discipline beats two copies that drift.
//! ARP fills it for v4; neighbour solicitation and advertisement
//! ([`crate::icmpv6`]) fill it for v6. Nothing else about the discipline
//! changed, including its stated weaknesses.
//!
//! # Time is an argument, not a dependency
//!
//! Every method that ages an entry takes `now` in monotonic nanoseconds.
//! That keeps this crate free of a clock, which is what lets the whole
//! table be tested on the host — including expiry, which is otherwise the
//! hardest thing here to test and the easiest to get wrong.

use crate::addr::{Address, MacAddr};

/// One learned mapping.
#[derive(Clone, Copy, Debug)]
struct Entry {
    protocol: Address,
    hardware: MacAddr,
    /// Monotonic nanoseconds after which this is no longer believed.
    expires_at: u64,
}

/// A fixed-size neighbour table.
///
/// Generic over its capacity so that the service placing it chooses, rather
/// than this crate choosing for every future caller. There is no allocation
/// and no growth: the failure mode of a full table is stated on
/// [`NeighbourCache::learn`], not discovered under load.
#[derive(Debug)]
pub struct NeighbourCache<const N: usize> {
    entries: [Option<Entry>; N],
    /// How long a learned mapping is believed, in nanoseconds.
    lifetime: u64,
}

impl<const N: usize> NeighbourCache<N> {
    /// A table whose entries live for `lifetime` nanoseconds.
    #[must_use]
    pub const fn new(lifetime: u64) -> Self {
        Self {
            entries: [None; N],
            lifetime,
        }
    }

    /// The hardware address for `protocol`, if one is known and unexpired.
    #[must_use]
    pub fn lookup(&self, protocol: Address, now: u64) -> Option<MacAddr> {
        self.entries
            .iter()
            .flatten()
            .find(|entry| entry.protocol == protocol && entry.expires_at > now)
            .map(|entry| entry.hardware)
    }

    /// Records that `protocol` is at `hardware`.
    ///
    /// Returns whether anything was stored.
    ///
    /// # What is refused, and why each one
    ///
    /// - **A group or broadcast hardware address.** Believing one would make
    ///   this station send unicast traffic to every station on the segment,
    ///   which is a redirection primitive handed over for free.
    /// - **The family's unspecified address.** `0.0.0.0` is what an ARP
    ///   probe carries before it has an address; `::` is a duplicate-address
    ///   probe's source. Both name nobody, and caching either maps a real
    ///   address to the wrong station on the next lookup.
    /// - **A multicast or broadcast protocol address.** Neither family
    ///   resolves these through the table — v4 derives or broadcasts, v6
    ///   derives the `33:33` mapping — and an entry for one would shadow
    ///   the derived address a sender is supposed to compute.
    ///
    /// # Replacement, which is where the honest limit is
    ///
    /// An existing entry for the same address is updated in place —
    /// including by an unsolicited reply or advertisement, because neither
    /// ARP nor unauthenticated NDP can tell a legitimate update from a
    /// forged one, and pretending otherwise would be security theatre. A
    /// caller that needs more than this needs a protocol that
    /// authenticates.
    ///
    /// With no free or expired slot, the entry closest to expiry is
    /// replaced. **A flood can therefore churn the table**, which costs a
    /// round trip per evicted address and does not lose correctness. The
    /// alternative — refuse to learn once full — trades that for an
    /// attacker being able to freeze the table permanently, which is worse.
    /// Neither is safe; this one fails softer, and saying so is the point.
    pub fn learn(&mut self, protocol: Address, hardware: MacAddr, now: u64) -> bool {
        if hardware.is_group()
            || protocol.is_unspecified()
            || protocol.is_broadcast()
            || protocol.is_multicast()
        {
            return false;
        }
        let expires_at = now.saturating_add(self.lifetime);
        let entry = Entry {
            protocol,
            hardware,
            expires_at,
        };

        if let Some(slot) = self
            .entries
            .iter_mut()
            .flatten()
            .find(|slot| slot.protocol == protocol)
        {
            *slot = entry;
            return true;
        }
        if let Some(slot) = self
            .entries
            .iter_mut()
            .find(|slot| slot.is_none_or(|held| held.expires_at <= now))
        {
            *slot = Some(entry);
            return true;
        }
        // Full, and nothing has expired. Replace whatever goes first.
        if let Some(slot) = self
            .entries
            .iter_mut()
            .flatten()
            .min_by_key(|held| held.expires_at)
        {
            *slot = entry;
            return true;
        }
        // Only reachable with `N == 0`, which is a caller's choice and not
        // an error: a table with no room stores nothing and every send
        // resolves.
        false
    }

    /// Forgets `protocol`, returning whether anything was held.
    pub fn forget(&mut self, protocol: Address) -> bool {
        let mut found = false;
        for slot in &mut self.entries {
            if slot.is_some_and(|held| held.protocol == protocol) {
                *slot = None;
                found = true;
            }
        }
        found
    }

    /// How many entries are held and unexpired at `now`.
    #[must_use]
    pub fn live(&self, now: u64) -> usize {
        self.entries
            .iter()
            .flatten()
            .filter(|entry| entry.expires_at > now)
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addr::{Ipv4Addr, Ipv6Addr};

    const MINUTE: u64 = 60_000_000_000;
    const SENDER: MacAddr = MacAddr([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
    const TARGET: MacAddr = MacAddr([0x52, 0x54, 0x00, 0x65, 0x43, 0x21]);

    fn v4(d: u8) -> Address {
        Address::V4(Ipv4Addr::new(10, 0, 0, d))
    }

    fn v6(d: u16) -> Address {
        Address::V6(Ipv6Addr::new([0xfe80, 0, 0, 0, 0, 0, 0, d]))
    }

    #[test]
    fn a_learned_entry_is_found_and_then_expires() {
        let mut cache = NeighbourCache::<4>::new(MINUTE);
        for address in [v4(2), v6(2)] {
            assert!(cache.learn(address, TARGET, 0));
            assert_eq!(cache.lookup(address, 0), Some(TARGET));
            assert_eq!(cache.lookup(address, MINUTE - 1), Some(TARGET));
            // At the expiry instant it is gone: `expires_at > now` and not
            // `>=`, so the boundary is checked in the direction that fails
            // safe.
            assert_eq!(cache.lookup(address, MINUTE), None);
        }
        assert_eq!(cache.live(MINUTE), 0);
    }

    #[test]
    fn the_families_do_not_shadow_each_other() {
        // Two addresses that could collide under any byte-truncating key:
        // the v4 address's four bytes appear inside the v6 address's tail.
        let mut cache = NeighbourCache::<4>::new(MINUTE);
        let four = Address::V4(Ipv4Addr::new(0xfe, 0x80, 0, 2));
        let six = Address::V6(Ipv6Addr::new([0xfe80, 2, 0, 0, 0, 0, 0, 0]));
        assert!(cache.learn(four, SENDER, 0));
        assert!(cache.learn(six, TARGET, 0));
        assert_eq!(cache.lookup(four, 1), Some(SENDER));
        assert_eq!(cache.lookup(six, 1), Some(TARGET));
        assert_eq!(cache.live(1), 2);
    }

    #[test]
    fn a_hardware_address_that_would_redirect_traffic_is_refused() {
        let mut cache = NeighbourCache::<4>::new(MINUTE);
        for address in [v4(2), v6(2)] {
            assert!(!cache.learn(address, MacAddr::BROADCAST, 0));
            assert!(!cache.learn(address, MacAddr([0x01, 0, 0x5e, 0, 0, 1]), 0));
            assert_eq!(cache.lookup(address, 0), None);
        }
        // The v6 multicast MAC prefix is a group address too, and must be
        // refused by the same bit rather than by a v4-only list.
        assert!(!cache.learn(v6(2), MacAddr([0x33, 0x33, 0, 0, 0, 1]), 0));
    }

    #[test]
    fn protocol_addresses_that_name_nobody_are_refused_in_both_families() {
        let mut cache = NeighbourCache::<8>::new(MINUTE);
        assert!(!cache.learn(Address::V4(Ipv4Addr::UNSPECIFIED), TARGET, 0));
        assert!(!cache.learn(Address::V4(Ipv4Addr::BROADCAST), TARGET, 0));
        assert!(!cache.learn(Address::V4(Ipv4Addr::new(224, 0, 0, 1)), TARGET, 0));
        assert!(!cache.learn(Address::V6(Ipv6Addr::UNSPECIFIED), TARGET, 0));
        assert!(!cache.learn(Address::V6(Ipv6Addr::ALL_NODES), TARGET, 0));
        assert!(!cache.learn(
            Address::V6(Ipv6Addr::new([0xfe80, 0, 0, 0, 0, 0, 0, 1]).solicited_node()),
            TARGET,
            0
        ));
        assert_eq!(cache.live(0), 0);
    }

    #[test]
    fn a_full_table_replaces_the_entry_closest_to_expiry() {
        // The documented behaviour, tested because the alternative --
        // refusing to learn -- lets an attacker freeze the table, and the
        // two are one line apart. Mixed families on purpose: eviction must
        // not prefer either.
        let mut cache = NeighbourCache::<2>::new(MINUTE);
        assert!(cache.learn(v4(1), SENDER, 0));
        assert!(cache.learn(v6(2), TARGET, 10));
        assert!(cache.learn(v4(3), TARGET, 20));
        // The v4 entry from t=0 expires soonest, so it is the one that went.
        assert_eq!(cache.lookup(v4(1), 20), None);
        assert_eq!(cache.lookup(v6(2), 20), Some(TARGET));
        assert_eq!(cache.lookup(v4(3), 20), Some(TARGET));
        assert_eq!(cache.live(20), 2);
    }

    #[test]
    fn relearning_updates_in_place_rather_than_consuming_a_slot() {
        let mut cache = NeighbourCache::<2>::new(MINUTE);
        assert!(cache.learn(v6(1), SENDER, 0));
        assert!(cache.learn(v6(1), TARGET, 1));
        assert_eq!(cache.lookup(v6(1), 1), Some(TARGET));
        assert_eq!(cache.live(1), 1);
        // And the other slot is still free, which is what "in place" means.
        assert!(cache.learn(v6(2), SENDER, 1));
        assert_eq!(cache.live(1), 2);
    }

    #[test]
    fn a_table_with_no_room_stores_nothing_and_does_not_panic() {
        let mut cache = NeighbourCache::<0>::new(MINUTE);
        assert!(!cache.learn(v4(1), SENDER, 0));
        assert_eq!(cache.live(0), 0);
    }

    #[test]
    fn forgetting_removes_it() {
        let mut cache = NeighbourCache::<2>::new(MINUTE);
        cache.learn(v6(1), SENDER, 0);
        assert!(cache.forget(v6(1)));
        assert!(!cache.forget(v6(1)));
        assert_eq!(cache.lookup(v6(1), 0), None);
    }
}
