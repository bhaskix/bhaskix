// SPDX-License-Identifier: Apache-2.0
//! ARP for IPv4 over Ethernet, and the cache it fills.
//!
//! Twenty-eight fixed bytes. The parser is the easy half; the cache is where
//! the design decisions are, because it is remotely-driven state.
//!
//! # ARP has no authentication and cannot be given any
//!
//! Any station on the segment can claim any address, and nothing in the
//! protocol distinguishes a legitimate reply from a fabricated one. This is a
//! property of ARP, not a gap in this implementation, and it is why the cache
//! below is written to bound its own damage rather than to prevent poisoning:
//! poisoning is not preventable at this layer.
//!
//! What *is* in scope here is refusing to let a remote party choose how much
//! memory it occupies, and refusing to learn from packets that give no reason
//! to be believed — see [`ArpCache::learn`].

use crate::{
    NetError,
    addr::{Ipv4Addr, MacAddr},
    be16, be32,
};

/// Bytes in an ARP packet for IPv4 over Ethernet.
pub const PACKET: usize = 28;

/// Hardware type 1: Ethernet.
const HARDWARE_ETHERNET: u16 = 1;
/// Protocol type 0x0800: IPv4.
const PROTOCOL_IPV4: u16 = 0x0800;

/// What an ARP packet is asking or answering.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ArpOp {
    /// "Who has this address?"
    Request,
    /// "I do."
    Reply,
}

/// A parsed ARP packet.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ArpPacket {
    /// Request or reply.
    pub operation: ArpOp,
    /// The hardware address of whoever sent this.
    pub sender_hardware: MacAddr,
    /// The protocol address of whoever sent this.
    pub sender_protocol: Ipv4Addr,
    /// The hardware address being asked about, or answering.
    pub target_hardware: MacAddr,
    /// The protocol address being asked about, or answered for.
    pub target_protocol: Ipv4Addr,
}

impl ArpPacket {
    /// Parses an ARP packet.
    ///
    /// Only IPv4 over Ethernet is accepted. The hardware and protocol length
    /// fields are **checked rather than trusted**: a packet claiming a
    /// six-byte protocol address is not an address family this parser handles,
    /// and treating the fields as advisory is how a parser ends up reading its
    /// own offsets out of the packet.
    ///
    /// # Errors
    ///
    /// - [`NetError::Truncated`] if fewer than [`PACKET`] bytes were supplied.
    /// - [`NetError::Unsupported`] for another hardware or protocol type, a
    ///   length field that does not match it, or an operation other than
    ///   request or reply.
    pub fn parse(bytes: &[u8]) -> Result<Self, NetError> {
        let packet = bytes.get(..PACKET).ok_or(NetError::Truncated {
            need: PACKET,
            have: bytes.len(),
        })?;

        let hardware = be16(packet, 0).unwrap_or(0);
        if hardware != HARDWARE_ETHERNET {
            return Err(NetError::Unsupported {
                field: "arp hardware type",
                value: u32::from(hardware),
            });
        }
        let protocol = be16(packet, 2).unwrap_or(0);
        if protocol != PROTOCOL_IPV4 {
            return Err(NetError::Unsupported {
                field: "arp protocol type",
                value: u32::from(protocol),
            });
        }
        // The lengths must agree with the types above. They are the fields a
        // parser is most tempted to use as offsets, and this one does not use
        // them at all -- it requires them to be the only values consistent with
        // Ethernet and IPv4, and reads at fixed offsets.
        if packet[4] != 6 {
            return Err(NetError::Unsupported {
                field: "arp hardware address length",
                value: u32::from(packet[4]),
            });
        }
        if packet[5] != 4 {
            return Err(NetError::Unsupported {
                field: "arp protocol address length",
                value: u32::from(packet[5]),
            });
        }

        let operation = match be16(packet, 6).unwrap_or(0) {
            1 => ArpOp::Request,
            2 => ArpOp::Reply,
            other => {
                return Err(NetError::Unsupported {
                    field: "arp operation",
                    value: u32::from(other),
                });
            }
        };

        let mut sender_hardware = [0u8; 6];
        let mut target_hardware = [0u8; 6];
        sender_hardware.copy_from_slice(&packet[8..14]);
        target_hardware.copy_from_slice(&packet[18..24]);

        Ok(Self {
            operation,
            sender_hardware: MacAddr(sender_hardware),
            sender_protocol: Ipv4Addr(be32(packet, 14).unwrap_or(0)),
            target_hardware: MacAddr(target_hardware),
            target_protocol: Ipv4Addr(be32(packet, 24).unwrap_or(0)),
        })
    }

    /// Writes this packet into `out`, returning the bytes written.
    ///
    /// # Errors
    ///
    /// [`NetError::Truncated`] if `out` cannot hold [`PACKET`] bytes.
    pub fn write(&self, out: &mut [u8]) -> Result<usize, NetError> {
        let available = out.len();
        let packet = out.get_mut(..PACKET).ok_or(NetError::Truncated {
            need: PACKET,
            have: available,
        })?;
        packet[0..2].copy_from_slice(&HARDWARE_ETHERNET.to_be_bytes());
        packet[2..4].copy_from_slice(&PROTOCOL_IPV4.to_be_bytes());
        packet[4] = 6;
        packet[5] = 4;
        let operation: u16 = match self.operation {
            ArpOp::Request => 1,
            ArpOp::Reply => 2,
        };
        packet[6..8].copy_from_slice(&operation.to_be_bytes());
        packet[8..14].copy_from_slice(&self.sender_hardware.octets());
        packet[14..18].copy_from_slice(&self.sender_protocol.octets());
        packet[18..24].copy_from_slice(&self.target_hardware.octets());
        packet[24..28].copy_from_slice(&self.target_protocol.octets());
        Ok(PACKET)
    }
}

/// One learned mapping.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Entry {
    protocol: Ipv4Addr,
    hardware: MacAddr,
    /// Monotonic nanoseconds after which this is no longer believed.
    expires_at: u64,
}

/// A fixed-size ARP cache.
///
/// Generic over its capacity so that the service placing it chooses, rather
/// than this crate choosing for every future caller. There is no allocation and
/// no growth: the entries a remote party can create are bounded by `N` before
/// the first packet arrives.
///
/// # Time is an argument, not a dependency
///
/// Every method that ages an entry takes `now` in monotonic nanoseconds. That
/// keeps this crate free of a clock, which is what lets the whole cache be
/// tested on the host — including expiry, which is otherwise the hardest thing
/// here to test and the easiest to get wrong.
#[derive(Debug)]
pub struct ArpCache<const N: usize> {
    entries: [Option<Entry>; N],
    /// How long a learned mapping is believed, in nanoseconds.
    lifetime: u64,
}

impl<const N: usize> ArpCache<N> {
    /// A cache whose entries live for `lifetime` nanoseconds.
    #[must_use]
    pub const fn new(lifetime: u64) -> Self {
        Self {
            entries: [None; N],
            lifetime,
        }
    }

    /// The hardware address for `protocol`, if one is known and unexpired.
    #[must_use]
    pub fn lookup(&self, protocol: Ipv4Addr, now: u64) -> Option<MacAddr> {
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
    /// - **The unspecified protocol address.** `0.0.0.0` is what an ARP probe
    ///   carries before it has an address; it names nobody and caching it maps
    ///   a real address to the wrong station on the next lookup.
    /// - **A multicast or broadcast protocol address.** These are not resolved
    ///   by ARP, and an entry for one would shadow the derived address a sender
    ///   is supposed to compute.
    ///
    /// # Replacement, which is where the honest limit is
    ///
    /// An existing entry for the same address is updated in place — including
    /// by an unsolicited reply, because ARP cannot tell a legitimate update
    /// from a forged one and pretending otherwise would be security theatre.
    /// A caller that needs more than this needs a protocol that authenticates.
    ///
    /// With no free or expired slot, the entry closest to expiry is replaced.
    /// **A flood can therefore churn the cache**, which costs a round trip per
    /// evicted address and does not lose correctness. The alternative — refuse
    /// to learn once full — trades that for an attacker being able to freeze
    /// the cache permanently, which is worse. Neither is safe; this one fails
    /// softer, and saying so is the point.
    pub fn learn(&mut self, protocol: Ipv4Addr, hardware: MacAddr, now: u64) -> bool {
        if hardware.is_group()
            || protocol == Ipv4Addr::UNSPECIFIED
            || protocol == Ipv4Addr::BROADCAST
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
        // Only reachable with `N == 0`, which is a caller's choice and not an
        // error: a cache with no room stores nothing and every send resolves.
        false
    }

    /// Forgets `protocol`, returning whether anything was held.
    pub fn forget(&mut self, protocol: Ipv4Addr) -> bool {
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

    const SENDER: MacAddr = MacAddr([0x52, 0x54, 0x00, 0x11, 0x22, 0x33]);
    const TARGET: MacAddr = MacAddr([0x52, 0x54, 0x00, 0x44, 0x55, 0x66]);
    const MINUTE: u64 = 60_000_000_000;

    fn request() -> ArpPacket {
        ArpPacket {
            operation: ArpOp::Request,
            sender_hardware: SENDER,
            sender_protocol: Ipv4Addr::new(10, 0, 0, 1),
            target_hardware: MacAddr::UNSPECIFIED,
            target_protocol: Ipv4Addr::new(10, 0, 0, 2),
        }
    }

    #[test]
    fn a_packet_written_parses_back_identically() {
        let mut out = [0u8; PACKET];
        assert_eq!(request().write(&mut out).unwrap(), PACKET);
        assert_eq!(ArpPacket::parse(&out).unwrap(), request());
    }

    #[test]
    fn one_byte_short_is_refused() {
        let mut out = [0u8; PACKET];
        request().write(&mut out).unwrap();
        assert_eq!(
            ArpPacket::parse(&out[..PACKET - 1]),
            Err(NetError::Truncated {
                need: PACKET,
                have: PACKET - 1
            })
        );
    }

    #[test]
    fn the_length_fields_are_checked_rather_than_used() {
        // A packet claiming a sixteen-byte protocol address must be refused,
        // not believed and used as an offset. This is the field that turns a
        // parser into an arbitrary read in implementations that trust it.
        let mut out = [0u8; PACKET];
        request().write(&mut out).unwrap();
        out[5] = 16;
        assert_eq!(
            ArpPacket::parse(&out),
            Err(NetError::Unsupported {
                field: "arp protocol address length",
                value: 16
            })
        );
        out[5] = 4;
        out[4] = 0;
        assert!(matches!(
            ArpPacket::parse(&out),
            Err(NetError::Unsupported { .. })
        ));
    }

    #[test]
    fn an_unknown_operation_is_refused_not_defaulted() {
        let mut out = [0u8; PACKET];
        request().write(&mut out).unwrap();
        out[6..8].copy_from_slice(&3u16.to_be_bytes());
        assert_eq!(
            ArpPacket::parse(&out),
            Err(NetError::Unsupported {
                field: "arp operation",
                value: 3
            })
        );
    }

    #[test]
    fn a_learned_entry_is_found_and_then_expires() {
        let mut cache = ArpCache::<4>::new(MINUTE);
        let address = Ipv4Addr::new(10, 0, 0, 2);
        assert!(cache.learn(address, TARGET, 0));
        assert_eq!(cache.lookup(address, 0), Some(TARGET));
        assert_eq!(cache.lookup(address, MINUTE - 1), Some(TARGET));
        // At the expiry instant it is gone: `expires_at > now` and not `>=`,
        // so the boundary is checked in the direction that fails safe.
        assert_eq!(cache.lookup(address, MINUTE), None);
        assert_eq!(cache.live(MINUTE), 0);
    }

    #[test]
    fn a_hardware_address_that_would_redirect_traffic_is_refused() {
        let mut cache = ArpCache::<4>::new(MINUTE);
        let address = Ipv4Addr::new(10, 0, 0, 2);
        assert!(!cache.learn(address, MacAddr::BROADCAST, 0));
        assert!(!cache.learn(address, MacAddr([0x01, 0, 0x5e, 0, 0, 1]), 0));
        assert_eq!(cache.lookup(address, 0), None);
    }

    #[test]
    fn protocol_addresses_that_name_nobody_are_refused() {
        let mut cache = ArpCache::<4>::new(MINUTE);
        assert!(!cache.learn(Ipv4Addr::UNSPECIFIED, TARGET, 0));
        assert!(!cache.learn(Ipv4Addr::BROADCAST, TARGET, 0));
        assert!(!cache.learn(Ipv4Addr::new(224, 0, 0, 1), TARGET, 0));
        assert_eq!(cache.live(0), 0);
    }

    #[test]
    fn a_full_cache_replaces_the_entry_closest_to_expiry() {
        // The documented behaviour, tested because the alternative -- refusing
        // to learn -- lets an attacker freeze the cache, and the two are one
        // line apart.
        let mut cache = ArpCache::<2>::new(MINUTE);
        let first = Ipv4Addr::new(10, 0, 0, 1);
        let second = Ipv4Addr::new(10, 0, 0, 2);
        let third = Ipv4Addr::new(10, 0, 0, 3);
        assert!(cache.learn(first, SENDER, 0));
        assert!(cache.learn(second, TARGET, 10));
        assert!(cache.learn(third, TARGET, 20));
        // `first` expires soonest, so it is the one that went.
        assert_eq!(cache.lookup(first, 20), None);
        assert_eq!(cache.lookup(second, 20), Some(TARGET));
        assert_eq!(cache.lookup(third, 20), Some(TARGET));
        assert_eq!(cache.live(20), 2);
    }

    #[test]
    fn relearning_updates_in_place_rather_than_consuming_a_slot() {
        let mut cache = ArpCache::<2>::new(MINUTE);
        let address = Ipv4Addr::new(10, 0, 0, 1);
        assert!(cache.learn(address, SENDER, 0));
        assert!(cache.learn(address, TARGET, 1));
        assert_eq!(cache.lookup(address, 1), Some(TARGET));
        assert_eq!(cache.live(1), 1);
        // And the other slot is still free, which is what "in place" means.
        assert!(cache.learn(Ipv4Addr::new(10, 0, 0, 2), SENDER, 1));
        assert_eq!(cache.live(1), 2);
    }

    #[test]
    fn a_cache_with_no_room_stores_nothing_and_does_not_panic() {
        let mut cache = ArpCache::<0>::new(MINUTE);
        assert!(!cache.learn(Ipv4Addr::new(10, 0, 0, 1), SENDER, 0));
        assert_eq!(cache.live(0), 0);
    }

    #[test]
    fn forgetting_removes_it() {
        let mut cache = ArpCache::<2>::new(MINUTE);
        let address = Ipv4Addr::new(10, 0, 0, 1);
        cache.learn(address, SENDER, 0);
        assert!(cache.forget(address));
        assert!(!cache.forget(address));
        assert_eq!(cache.lookup(address, 0), None);
    }
}
