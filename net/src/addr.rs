// SPDX-License-Identifier: Apache-2.0
//! Addresses, as distinct types rather than as integers.
//!
//! `docs/coding-style.md` §5 makes this a rule rather than a preference, and
//! networking is where it earns most: a MAC address, an IPv4 address and a port
//! are all just numbers, they are all read out of the same packet, and swapping
//! two of them produces code that compiles and is wrong.
//!
//! # One family, and an enum anyway
//!
//! [`Address`] has a single variant today. RFC 0018 chose IPv4 first and
//! deferred IPv6, and this is the whole of what that decision costs now:
//! signatures take `Address`, the routing key is `Address`, and adding IPv6 is a
//! variant, a parser and a neighbour-discovery mechanism rather than a second
//! copy of everything above it. Retrofitting an address abstraction through a
//! socket API afterwards is the expensive version of the same decision, and it
//! is the version most stacks have had to do.

use core::fmt;

/// A 48-bit Ethernet address.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    /// The all-ones address every station on the segment accepts.
    pub const BROADCAST: Self = Self([0xff; 6]);

    /// The all-zero address, which names nobody.
    ///
    /// Carried in an ARP request's target hardware field, where it means "this
    /// is what I am asking for" rather than an address.
    pub const UNSPECIFIED: Self = Self([0x00; 6]);

    /// Whether this is the broadcast address.
    #[must_use]
    pub const fn is_broadcast(self) -> bool {
        matches!(self.0, [0xff, 0xff, 0xff, 0xff, 0xff, 0xff])
    }

    /// Whether the group bit is set — a multicast or broadcast destination.
    ///
    /// The low bit of the first octet, which is a fact about the wire format
    /// and not a convention this crate invents.
    #[must_use]
    pub const fn is_group(self) -> bool {
        self.0[0] & 0x01 != 0
    }

    /// The six bytes, in wire order.
    #[must_use]
    pub const fn octets(self) -> [u8; 6] {
        self.0
    }
}

impl fmt::Debug for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d, e, g] = self.0;
        write!(f, "{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{g:02x}")
    }
}

/// A 32-bit IPv4 address, held in host order.
///
/// Host order rather than wire order, deliberately: the wire order lives in the
/// parser, at exactly one place per direction, so that comparisons and prefix
/// arithmetic elsewhere cannot be quietly byte-swapped. A type that is
/// sometimes one and sometimes the other is the bug this newtype exists to
/// prevent.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ipv4Addr(pub u32);

impl Ipv4Addr {
    /// `0.0.0.0` — this host, or "no address yet".
    pub const UNSPECIFIED: Self = Self(0);

    /// `255.255.255.255` — the limited broadcast address.
    pub const BROADCAST: Self = Self(u32::MAX);

    /// Builds an address from its four octets, most significant first.
    #[must_use]
    pub const fn new(a: u8, b: u8, c: u8, d: u8) -> Self {
        Self(u32::from_be_bytes([a, b, c, d]))
    }

    /// The four octets, in wire order.
    #[must_use]
    pub const fn octets(self) -> [u8; 4] {
        self.0.to_be_bytes()
    }

    /// Whether this address is `224.0.0.0/4`.
    #[must_use]
    pub const fn is_multicast(self) -> bool {
        self.0 >> 28 == 0b1110
    }

    /// Whether this address is on `self`'s network given `prefix` bits.
    ///
    /// A prefix of zero puts everything on the same network and a prefix above
    /// 32 is meaningless; both are clamped rather than rejected, because this
    /// is arithmetic on a configured value and not a parser on a hostile one.
    #[must_use]
    pub const fn same_network(self, other: Self, prefix: u8) -> bool {
        if prefix == 0 {
            return true;
        }
        let bits = if prefix > 32 { 32 } else { prefix };
        // Built by shifting rather than by `!0 >> (32 - bits)`, so that a
        // prefix of 32 does not shift by zero in one step and 32 in another.
        let mask = u32::MAX << (32 - bits);
        self.0 & mask == other.0 & mask
    }
}

impl fmt::Debug for Ipv4Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d] = self.octets();
        write!(f, "{a}.{b}.{c}.{d}")
    }
}

/// A transport port.
///
/// A newtype because a port and a length and an identifier are all `u16` and
/// all appear within eight bytes of each other in a UDP datagram.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Port(pub u16);

impl Port {
    /// Port zero, which a caller passes to [`Port::is_unspecified`] territory —
    /// "assign me one" at bind time, and never a legitimate peer port.
    pub const UNSPECIFIED: Self = Self(0);

    /// Whether this is port zero.
    #[must_use]
    pub const fn is_unspecified(self) -> bool {
        self.0 == 0
    }
}

/// A network-layer address, of whichever family.
///
/// One variant today. See the module header for why it is an enum anyway.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum Address {
    /// An IPv4 address.
    V4(Ipv4Addr),
}

impl Address {
    /// The IPv4 address, if this is one.
    ///
    /// Returns an `Option` rather than being infallible, so that the call sites
    /// that will have to handle a second family are already written as though
    /// there is one.
    #[must_use]
    pub const fn v4(self) -> Option<Ipv4Addr> {
        match self {
            Self::V4(address) => Some(address),
        }
    }
}

impl From<Ipv4Addr> for Address {
    fn from(address: Ipv4Addr) -> Self {
        Self::V4(address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn octets_round_trip_in_wire_order() {
        let address = Ipv4Addr::new(192, 168, 1, 2);
        assert_eq!(address.octets(), [192, 168, 1, 2]);
        // The high octet must be the first one on the wire. If host order and
        // wire order were confused this passes for 1.2.3.4 and fails here.
        assert_eq!(address.0 >> 24, 192);
    }

    #[test]
    fn broadcast_and_group_are_not_the_same_question() {
        assert!(MacAddr::BROADCAST.is_broadcast());
        assert!(MacAddr::BROADCAST.is_group());
        // A multicast address is a group and is not broadcast. Treating the two
        // as one is how a stack starts accepting frames addressed elsewhere.
        let multicast = MacAddr([0x01, 0x00, 0x5e, 0x00, 0x00, 0x01]);
        assert!(multicast.is_group());
        assert!(!multicast.is_broadcast());
        assert!(!MacAddr::UNSPECIFIED.is_group());
    }

    #[test]
    fn prefix_matching_at_both_ends_of_the_range() {
        let a = Ipv4Addr::new(10, 0, 0, 1);
        let b = Ipv4Addr::new(10, 0, 1, 1);
        assert!(a.same_network(b, 16));
        assert!(!a.same_network(b, 24));
        // A /32 is only itself, and a /0 is everything. Both are the shifts
        // most likely to be off by one.
        assert!(a.same_network(a, 32));
        assert!(!a.same_network(b, 32));
        assert!(a.same_network(b, 0));
        // Above 32 is clamped, not wrapped: an unclamped `32 - prefix` would
        // underflow and panic in debug.
        assert!(a.same_network(a, 33));
        assert!(!a.same_network(b, 255));
    }

    #[test]
    fn multicast_covers_the_whole_class_and_no_more() {
        assert!(Ipv4Addr::new(224, 0, 0, 1).is_multicast());
        assert!(Ipv4Addr::new(239, 255, 255, 255).is_multicast());
        assert!(!Ipv4Addr::new(223, 255, 255, 255).is_multicast());
        assert!(!Ipv4Addr::new(240, 0, 0, 0).is_multicast());
    }
}
