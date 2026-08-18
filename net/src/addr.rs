// SPDX-License-Identifier: Apache-2.0
//! Addresses, as distinct types rather than as integers.
//!
//! `docs/coding-style.md` §5 makes this a rule rather than a preference, and
//! networking is where it earns most: a MAC address, an IPv4 address and a port
//! are all just numbers, they are all read out of the same packet, and swapping
//! two of them produces code that compiles and is wrong.
//!
//! # Two families, one enum — as designed
//!
//! [`Address`] was built with a single variant by RFC 0018, which chose IPv4
//! first and promised that IPv6 would be "a variant, a parser and a
//! neighbour-discovery mechanism rather than a second copy of everything
//! above it". RFC 0029 collected: signatures take `Address`, the routing key
//! is `Address`, and the `V6` variant arrived with the compiler producing
//! the list of every place that had quietly assumed one family.

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

/// A 128-bit IPv6 address, held in wire order.
///
/// Wire order rather than a host-order integer, deliberately — and
/// differently from [`Ipv4Addr`], whose host-order `u32` exists for prefix
/// arithmetic. Sixteen bytes have no natural host-integer form, every use
/// in this stack is a byte-for-byte comparison or a copy into a packet, and
/// a `u128` would put a byte-swap trap at every one of those sites.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ipv6Addr(pub [u8; 16]);

impl Ipv6Addr {
    /// `::` — no address, or "not yet".
    pub const UNSPECIFIED: Self = Self([0; 16]);

    /// `ff02::1` — every node on the link.
    pub const ALL_NODES: Self = Self([0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

    /// `ff02::2` — every router on the link.
    pub const ALL_ROUTERS: Self = Self([0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);

    /// An address from eight 16-bit segments, written the way the literature
    /// writes them.
    #[must_use]
    pub const fn new(segments: [u16; 8]) -> Self {
        let mut bytes = [0u8; 16];
        let mut index = 0;
        while index < 8 {
            let [high, low] = segments[index].to_be_bytes();
            bytes[index * 2] = high;
            bytes[index * 2 + 1] = low;
            index += 1;
        }
        Self(bytes)
    }

    /// The sixteen bytes, in wire order.
    #[must_use]
    pub const fn octets(self) -> [u8; 16] {
        self.0
    }

    /// The eight segments, in the order they are written.
    #[must_use]
    pub fn segments(self) -> [u16; 8] {
        let mut segments = [0u16; 8];
        for (index, segment) in segments.iter_mut().enumerate() {
            *segment = u16::from_be_bytes([self.0[index * 2], self.0[index * 2 + 1]]);
        }
        segments
    }

    /// Whether this is a multicast address — the `ff00::/8` block.
    #[must_use]
    pub const fn is_multicast(self) -> bool {
        self.0[0] == 0xff
    }

    /// Whether this is `::`.
    #[must_use]
    pub const fn is_unspecified(self) -> bool {
        matches!(self.0, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    }
}

impl fmt::Debug for Ipv6Addr {
    /// The compressed textual form: lowercase hex segments, leading zeros
    /// dropped, and the longest run of zero segments (of length at least
    /// two, leftmost on a tie) written `::` — RFC 5952's rules, because an
    /// address that prints differently from every other tool's rendering of
    /// it is an address nobody can grep for.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let segments = self.segments();

        // The longest zero run, leftmost on ties, only if two or more long.
        let mut best: Option<(usize, usize)> = None;
        let mut index = 0;
        while index < 8 {
            if segments[index] == 0 {
                let start = index;
                while index < 8 && segments[index] == 0 {
                    index += 1;
                }
                let length = index - start;
                if length >= 2 && best.is_none_or(|(_, held)| length > held) {
                    best = Some((start, length));
                }
            } else {
                index += 1;
            }
        }

        match best {
            Some((start, length)) => {
                for (index, segment) in segments.iter().enumerate().take(start) {
                    if index > 0 {
                        write!(f, ":")?;
                    }
                    write!(f, "{segment:x}")?;
                }
                write!(f, "::")?;
                for (index, segment) in segments.iter().enumerate().skip(start + length) {
                    if index > start + length {
                        write!(f, ":")?;
                    }
                    write!(f, "{segment:x}")?;
                }
                Ok(())
            }
            None => {
                for (index, segment) in segments.iter().enumerate() {
                    if index > 0 {
                        write!(f, ":")?;
                    }
                    write!(f, "{segment:x}")?;
                }
                Ok(())
            }
        }
    }
}

/// A network-layer address, of whichever family.
///
/// Built with one variant by RFC 0018, on the promise that the second would
/// be a variant and not a rewrite; RFC 0029 is the promise collected.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum Address {
    /// An IPv4 address.
    V4(Ipv4Addr),
    /// An IPv6 address.
    V6(Ipv6Addr),
}

impl Address {
    /// The IPv4 address, if this is one.
    #[must_use]
    pub const fn v4(self) -> Option<Ipv4Addr> {
        match self {
            Self::V4(address) => Some(address),
            Self::V6(_) => None,
        }
    }

    /// The IPv6 address, if this is one.
    #[must_use]
    pub const fn v6(self) -> Option<Ipv6Addr> {
        match self {
            Self::V4(_) => None,
            Self::V6(address) => Some(address),
        }
    }
}

impl From<Ipv4Addr> for Address {
    fn from(address: Ipv4Addr) -> Self {
        Self::V4(address)
    }
}

impl From<Ipv6Addr> for Address {
    fn from(address: Ipv6Addr) -> Self {
        Self::V6(address)
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
