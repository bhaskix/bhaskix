// SPDX-License-Identifier: Apache-2.0
//! What a host takes off a wire: one verdict per family, decided here so that
//! the service that applies it cannot get the order or the addresses wrong
//! where no test reaches.
//!
//! **Pure, because nothing else can test it.** No emulator lane can put a frame
//! naming a loopback address on the wire — user-mode networking delivers only
//! frames its own stack built — so the refusal is proven here, on the host, or
//! nowhere. `bin/ipd` maps a verdict to its refusal code and does nothing else.
//!
//! Written 2026-10-16, when reading the v6 receive path for v4's loopback twin
//! found it checked no destination at all: a datagram for any host, `::1`
//! included, was delivered by port.

use crate::addr::{Ipv4Addr, Ipv6Addr};

/// What to do with a datagram that arrived from a wire.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Arrival {
    /// It is addressed to this host; take it.
    Accept,
    /// It names a loopback address, as source or destination, which no wire
    /// may carry. Dropped, and counted, because a correct peer never sends one.
    Loopback,
    /// It is addressed to some other host.
    NotForUs,
}

/// The v4 verdict. `me` is this host's address.
///
/// **Loopback first**: all of `127.0.0.0/8`, either way — RFC 1122
/// §3.2.1.3(g), "Addresses of this form MUST NOT appear outside a host". Then
/// v4's rule since RFC 0018, unchanged: this host's address or the limited
/// broadcast, and nothing else.
#[must_use]
pub fn arrival4(source: Ipv4Addr, destination: Ipv4Addr, me: Ipv4Addr) -> Arrival {
    if source.is_loopback() || destination.is_loopback() {
        Arrival::Loopback
    } else if destination == me || destination == Ipv4Addr::BROADCAST {
        Arrival::Accept
    } else {
        Arrival::NotForUs
    }
}

/// The v6 verdict. `link_local` and `global` are this host's addresses; a host
/// that has heard no router advertisement has no global one.
///
/// **Loopback first**: `::1`, either way — RFC 4291 §2.5.3, read 2026-10-16: a
/// packet "received on an interface with a destination address of loopback
/// must be dropped", and the loopback address "must not be used as the source
/// address in IPv6 packets that are sent outside of a single node". Then the
/// v4 rule's counterpart: this host's own addresses, or `ff02::1` — every node
/// on the link, which is what the limited broadcast is to v4.
#[must_use]
pub fn arrival6(
    source: Ipv6Addr,
    destination: Ipv6Addr,
    link_local: Ipv6Addr,
    global: Option<Ipv6Addr>,
) -> Arrival {
    if source.is_loopback() || destination.is_loopback() {
        Arrival::Loopback
    } else if destination == link_local
        || global == Some(destination)
        || destination == Ipv6Addr::ALL_NODES
    {
        Arrival::Accept
    } else {
        Arrival::NotForUs
    }
}

#[cfg(test)]
mod tests {
    use super::{Arrival, arrival4, arrival6};
    use crate::addr::{Ipv4Addr, Ipv6Addr};

    const ME: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 15);
    const PEER: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 2);

    #[test]
    fn v4_takes_what_is_addressed_to_it_and_the_broadcast() {
        assert_eq!(arrival4(PEER, ME, ME), Arrival::Accept);
        assert_eq!(arrival4(PEER, Ipv4Addr::BROADCAST, ME), Arrival::Accept);
    }

    #[test]
    fn v4_refuses_another_hosts_and_a_multicast_group() {
        assert_eq!(
            arrival4(PEER, Ipv4Addr::new(10, 0, 2, 16), ME),
            Arrival::NotForUs
        );
        assert_eq!(
            arrival4(PEER, Ipv4Addr::new(224, 0, 0, 1), ME),
            Arrival::NotForUs
        );
    }

    #[test]
    fn v4_refuses_the_whole_loopback_slash_eight_either_way() {
        // Destination and source, and not only `127.0.0.1`.
        assert_eq!(arrival4(PEER, Ipv4Addr::LOOPBACK, ME), Arrival::Loopback);
        assert_eq!(
            arrival4(PEER, Ipv4Addr::new(127, 9, 9, 9), ME),
            Arrival::Loopback
        );
        assert_eq!(
            arrival4(Ipv4Addr::new(127, 0, 0, 0), ME, ME),
            Arrival::Loopback
        );
        // **Loopback before "for us"**: a host configured, wrongly, with a
        // loopback address still takes no frame naming it.
        assert_eq!(
            arrival4(PEER, Ipv4Addr::LOOPBACK, Ipv4Addr::LOOPBACK),
            Arrival::Loopback
        );
    }

    fn v6(segments: [u16; 8]) -> Ipv6Addr {
        Ipv6Addr::new(segments)
    }

    #[test]
    fn v6_takes_its_own_addresses_and_all_nodes() {
        let link = v6([0xfe80, 0, 0, 0, 0x5054, 0xff, 0xfe12, 0x3456]);
        let global = v6([0xfec0, 0, 0, 0, 0x5054, 0xff, 0xfe12, 0x3456]);
        let peer = v6([0xfe80, 0, 0, 0, 0, 0, 0, 2]);
        assert_eq!(arrival6(peer, link, link, Some(global)), Arrival::Accept);
        assert_eq!(arrival6(peer, global, link, Some(global)), Arrival::Accept);
        assert_eq!(
            arrival6(peer, Ipv6Addr::ALL_NODES, link, None),
            Arrival::Accept
        );
    }

    #[test]
    fn v6_refuses_another_hosts_another_group_and_a_global_it_lacks() {
        let link = v6([0xfe80, 0, 0, 0, 0x5054, 0xff, 0xfe12, 0x3456]);
        let global = v6([0xfec0, 0, 0, 0, 0x5054, 0xff, 0xfe12, 0x3456]);
        let peer = v6([0xfe80, 0, 0, 0, 0, 0, 0, 2]);
        // Another host's link-local.
        assert_eq!(arrival6(peer, peer, link, Some(global)), Arrival::NotForUs);
        // All routers, which this host is not.
        assert_eq!(
            arrival6(peer, Ipv6Addr::ALL_ROUTERS, link, Some(global)),
            Arrival::NotForUs
        );
        // Its own global address, before a router advertisement gave it one.
        assert_eq!(arrival6(peer, global, link, None), Arrival::NotForUs);
    }

    #[test]
    fn v6_refuses_loopback_either_way() {
        let link = v6([0xfe80, 0, 0, 0, 0x5054, 0xff, 0xfe12, 0x3456]);
        let peer = v6([0xfe80, 0, 0, 0, 0, 0, 0, 2]);
        assert_eq!(
            arrival6(peer, Ipv6Addr::LOOPBACK, link, None),
            Arrival::Loopback
        );
        assert_eq!(
            arrival6(Ipv6Addr::LOOPBACK, link, link, None),
            Arrival::Loopback
        );
        // `::1` before "for us", as for v4.
        assert_eq!(
            arrival6(peer, Ipv6Addr::LOOPBACK, Ipv6Addr::LOOPBACK, None),
            Arrival::Loopback
        );
    }
}
