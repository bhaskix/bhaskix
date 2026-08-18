// SPDX-License-Identifier: Apache-2.0
//! ICMPv6 — the echo half, and the checksum v4's ICMP does not have.
//!
//! [RFC 0029](../../docs/rfc/0029-ipv6.md) steps 1 and 2: the echo pair,
//! and the four neighbour-discovery messages that replaced ARP — ICMPv6 by
//! format, ARP by role. The error types stay out for [`crate::icmp`]'s
//! reasons, unchanged: they quote the packet that caused them, which is a
//! nested parser with nested bounds, and none of it is needed to answer a
//! ping or resolve a neighbour.
//!
//! # The checksum takes addresses, unlike v4's
//!
//! v4's ICMP checksum covers the message alone; v6's covers the message
//! *and* the pseudo-header, exactly like UDP and TCP. So everything in this
//! module takes the two addresses — a reader who expects the v4 shape will
//! reach for an address-free `parse` and find there isn't one, which is the
//! point of saying so here.

use crate::{
    NetError,
    addr::{Ipv6Addr, MacAddr},
    be16, checksum,
    ipv6::{NextHeader, pseudo_header},
};

/// Bytes in an echo header, before the payload. The same eight as v4's,
/// which is a coincidence of layout and not a shared definition.
pub const HEADER: usize = 8;

/// An echo request: "are you there". A different number from v4's 8.
pub const ECHO_REQUEST: u8 = 128;

/// An echo reply: "yes". A different number from v4's 0.
pub const ECHO_REPLY: u8 = 129;

/// A parsed ICMPv6 echo message, borrowing its payload.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Echo<'a> {
    /// Whether this is a request or a reply.
    pub is_reply: bool,
    /// Chosen by the sender, echoed back unchanged.
    pub identifier: u16,
    /// Chosen by the sender, echoed back unchanged.
    pub sequence: u16,
    /// The bytes after the header, which a reply must return exactly.
    pub payload: &'a [u8],
}

impl<'a> Echo<'a> {
    /// Parses an echo request or reply, verifying the checksum against the
    /// addresses the enclosing IPv6 header carried.
    ///
    /// # Errors
    ///
    /// - [`NetError::Truncated`] if fewer than [`HEADER`] bytes were
    ///   supplied.
    /// - [`NetError::BadChecksum`] if the checksum does not verify. There
    ///   is no optional-checksum arm: in v6 the sum is mandatory, and a
    ///   zero that does not verify is a bad checksum, not an abstention.
    /// - [`NetError::Unsupported`] for any type that is not an echo, and
    ///   for a non-zero code on one that is.
    pub fn parse(
        bytes: &'a [u8],
        source: Ipv6Addr,
        destination: Ipv6Addr,
    ) -> Result<Self, NetError> {
        let fixed = bytes.get(..HEADER).ok_or(NetError::Truncated {
            need: HEADER,
            have: bytes.len(),
        })?;

        let kind = fixed[0];
        let is_reply = match kind {
            ECHO_REQUEST => false,
            ECHO_REPLY => true,
            other => {
                return Err(NetError::Unsupported {
                    field: "icmpv6 type",
                    value: u32::from(other),
                });
            }
        };
        let code = fixed[1];
        if code != 0 {
            return Err(NetError::Unsupported {
                field: "icmpv6 code",
                value: u32::from(code),
            });
        }

        // The length is u32-wide in the pseudo-header; a slice length always
        // fits, because it was bounded by the IPv6 payload length upstream.
        // Computed over the message with the checksum field taken as zero —
        // the same spans trick as v4's, plus the pseudo-header in front —
        // so the error carries the number this side computed, not a
        // residual only the arithmetic understands.
        let length = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
        let pseudo = pseudo_header(source, destination, NextHeader::ICMPV6, length);
        let carried = be16(fixed, 2).unwrap_or(0);
        let computed = checksum(&[&pseudo, &bytes[..2], &[0, 0], &bytes[4..]]);
        if computed != carried {
            return Err(NetError::BadChecksum { computed, carried });
        }

        Ok(Self {
            is_reply,
            identifier: be16(fixed, 4).unwrap_or(0),
            sequence: be16(fixed, 6).unwrap_or(0),
            payload: &bytes[HEADER..],
        })
    }
}

/// Writes an echo message — header, checksum and payload — into `out`,
/// returning how many bytes it used.
///
/// # Errors
///
/// [`NetError::Truncated`] if `out` cannot hold the header and the payload.
pub fn write_echo(
    out: &mut [u8],
    source: Ipv6Addr,
    destination: Ipv6Addr,
    is_reply: bool,
    identifier: u16,
    sequence: u16,
    payload: &[u8],
) -> Result<usize, NetError> {
    let total = HEADER + payload.len();
    let message = {
        let have = out.len();
        out.get_mut(..total)
            .ok_or(NetError::Truncated { need: total, have })?
    };

    message[0] = if is_reply { ECHO_REPLY } else { ECHO_REQUEST };
    message[1] = 0;
    message[2] = 0;
    message[3] = 0;
    message[4..6].copy_from_slice(&identifier.to_be_bytes());
    message[6..8].copy_from_slice(&sequence.to_be_bytes());
    message[HEADER..].copy_from_slice(payload);

    let length = u32::try_from(total).unwrap_or(u32::MAX);
    let pseudo = pseudo_header(source, destination, NextHeader::ICMPV6, length);
    let sum = checksum(&[&pseudo, &*message]);
    message[2..4].copy_from_slice(&sum.to_be_bytes());
    Ok(total)
}

// --- Neighbour discovery: the four messages that replaced ARP -------------
//
// ICMPv6 by format, ARP by role. Each is a fixed part followed by options
// in eight-byte units; the option walk refuses a zero length (the classic
// infinite loop) and a length past the buffer, and skips unknown types by
// length — the MADT walker's rule, applied to the wire. The specification
// also requires these to arrive with hop limit 255 (proof the packet never
// crossed a router); the hop limit lives in the IP header this module never
// sees, so that check belongs to the caller and is stated here so it cannot
// be forgotten quietly.

/// A router solicitation: "who routes here". Type 133.
pub const ROUTER_SOLICITATION: u8 = 133;
/// A router advertisement: "I do, and here is the prefix". Type 134.
pub const ROUTER_ADVERTISEMENT: u8 = 134;
/// A neighbour solicitation: v6's "who has". Type 135.
pub const NEIGHBOUR_SOLICITATION: u8 = 135;
/// A neighbour advertisement: v6's "is at". Type 136.
pub const NEIGHBOUR_ADVERTISEMENT: u8 = 136;

/// Option type: the sender's link-layer address.
const OPTION_SOURCE_LINK: u8 = 1;
/// Option type: the target's link-layer address.
const OPTION_TARGET_LINK: u8 = 2;
/// Option type: prefix information, in a router advertisement.
const OPTION_PREFIX: u8 = 3;

/// Verifies an NDP message's envelope: length, type, zero code, checksum.
fn verified(
    bytes: &[u8],
    source: Ipv6Addr,
    destination: Ipv6Addr,
    expected: u8,
    fixed: usize,
) -> Result<(), NetError> {
    let header = bytes.get(..fixed).ok_or(NetError::Truncated {
        need: fixed,
        have: bytes.len(),
    })?;
    if header[0] != expected {
        return Err(NetError::Unsupported {
            field: "icmpv6 type",
            value: u32::from(header[0]),
        });
    }
    if header[1] != 0 {
        return Err(NetError::Unsupported {
            field: "icmpv6 code",
            value: u32::from(header[1]),
        });
    }
    let length = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    let pseudo = pseudo_header(source, destination, NextHeader::ICMPV6, length);
    let carried = be16(header, 2).unwrap_or(0);
    let computed = checksum(&[&pseudo, &bytes[..2], &[0, 0], &bytes[4..]]);
    if computed != carried {
        return Err(NetError::BadChecksum { computed, carried });
    }
    Ok(())
}

/// Walks the options after an NDP message's fixed part.
///
/// `take` receives each option's type and its bytes *after* the two-byte
/// header. A zero length is refused — trusting it is an infinite loop — and
/// so is a length past the buffer; unknown types are skipped by length,
/// which is what keeps this walk in step with options it has never heard
/// of.
fn options(bytes: &[u8], mut take: impl FnMut(u8, &[u8])) -> Result<(), NetError> {
    let mut at = 0;
    while at < bytes.len() {
        let header = bytes.get(at..at + 2).ok_or(NetError::Truncated {
            need: at + 2,
            have: bytes.len(),
        })?;
        let length = usize::from(header[1]) * 8;
        if length == 0 {
            return Err(NetError::Unsupported {
                field: "ndp option length",
                value: 0,
            });
        }
        let option = bytes
            .get(at..at + length)
            .ok_or(NetError::LengthBeyondBuffer {
                stated: at + length,
                have: bytes.len(),
            })?;
        take(header[0], &option[2..]);
        at += length;
    }
    Ok(())
}

/// Reads a link-layer address option's payload, if it is one.
fn link_option(payload: &[u8]) -> Option<MacAddr> {
    let mut mac = [0u8; 6];
    mac.copy_from_slice(payload.get(..6)?);
    Some(MacAddr(mac))
}

/// A prefix information option, as a router advertisement carries it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PrefixInformation {
    /// Bits of prefix. SLAAC needs 64 and the consumer decides; carried
    /// as stated rather than clamped.
    pub prefix_length: u8,
    /// Whether hosts may derive addresses from this prefix — the `A` bit,
    /// which is the one SLAAC runs on.
    pub autonomous: bool,
    /// Seconds the prefix is valid. `u32::MAX` means forever.
    pub valid_seconds: u32,
    /// The prefix itself, low bits unspecified by construction.
    pub prefix: Ipv6Addr,
}

/// A parsed router advertisement — the fields this stack consumes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RouterAdvertisement {
    /// Seconds the sender is willing to be a default router; zero means
    /// "route through me for nothing".
    pub router_lifetime_seconds: u16,
    /// The router's link-layer address, if it said one.
    pub source_link: Option<MacAddr>,
    /// The first prefix information option, if any. An advertisement may
    /// carry several; one network per interface is this stack's scope, so
    /// the first is used and the rest are skipped by length like any other
    /// option — the MADT's first-I/O-APIC rule.
    pub prefix: Option<PrefixInformation>,
}

impl RouterAdvertisement {
    /// Bytes in the fixed part.
    pub const FIXED: usize = 16;

    /// Parses a router advertisement.
    ///
    /// # Errors
    ///
    /// As [`Echo::parse`], plus the option walk's refusals: a zero option
    /// length and a length past the buffer.
    pub fn parse(bytes: &[u8], source: Ipv6Addr, destination: Ipv6Addr) -> Result<Self, NetError> {
        verified(
            bytes,
            source,
            destination,
            ROUTER_ADVERTISEMENT,
            Self::FIXED,
        )?;
        let mut parsed = Self {
            router_lifetime_seconds: be16(bytes, 6).unwrap_or(0),
            source_link: None,
            prefix: None,
        };
        options(&bytes[Self::FIXED..], |kind, payload| match kind {
            OPTION_SOURCE_LINK => {
                if parsed.source_link.is_none() {
                    parsed.source_link = link_option(payload);
                }
            }
            // 30 payload bytes: the option is four eight-byte units, and
            // anything shorter is skipped rather than misread — a prefix
            // read out of a wrong-sized option is a route to nowhere.
            OPTION_PREFIX if payload.len() >= 30 && parsed.prefix.is_none() => {
                let mut prefix = [0u8; 16];
                prefix.copy_from_slice(&payload[14..30]);
                parsed.prefix = Some(PrefixInformation {
                    prefix_length: payload[0],
                    autonomous: payload[1] & 0x40 != 0,
                    valid_seconds: u32::from_be_bytes([
                        payload[2], payload[3], payload[4], payload[5],
                    ]),
                    prefix: Ipv6Addr(prefix),
                });
            }
            _ => {}
        })?;
        Ok(parsed)
    }
}

/// A parsed neighbour solicitation: "who has `target`".
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct NeighbourSolicitation {
    /// The address being asked about.
    pub target: Ipv6Addr,
    /// The asker's link-layer address, if it said one — absent in a
    /// duplicate-address probe, whose source is `::`.
    pub source_link: Option<MacAddr>,
}

impl NeighbourSolicitation {
    /// Bytes in the fixed part.
    pub const FIXED: usize = 24;

    /// Parses a neighbour solicitation.
    ///
    /// # Errors
    ///
    /// As [`RouterAdvertisement::parse`].
    pub fn parse(bytes: &[u8], source: Ipv6Addr, destination: Ipv6Addr) -> Result<Self, NetError> {
        verified(
            bytes,
            source,
            destination,
            NEIGHBOUR_SOLICITATION,
            Self::FIXED,
        )?;
        let mut target = [0u8; 16];
        target.copy_from_slice(&bytes[8..24]);
        let mut source_link = None;
        options(&bytes[Self::FIXED..], |kind, payload| {
            if kind == OPTION_SOURCE_LINK && source_link.is_none() {
                source_link = link_option(payload);
            }
        })?;
        Ok(Self {
            target: Ipv6Addr(target),
            source_link,
        })
    }
}

/// A parsed neighbour advertisement: "`target` is at this address".
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct NeighbourAdvertisement {
    /// The address being answered for.
    pub target: Ipv6Addr,
    /// Whether this answers a solicitation, as opposed to being announced.
    pub solicited: bool,
    /// The target's link-layer address, if carried. The specification
    /// requires it on multicast advertisements and this stack requires a
    /// value before it learns anything — an advertisement without one
    /// updates nothing.
    pub target_link: Option<MacAddr>,
}

impl NeighbourAdvertisement {
    /// Bytes in the fixed part.
    pub const FIXED: usize = 24;

    /// Parses a neighbour advertisement.
    ///
    /// # Errors
    ///
    /// As [`RouterAdvertisement::parse`].
    pub fn parse(bytes: &[u8], source: Ipv6Addr, destination: Ipv6Addr) -> Result<Self, NetError> {
        verified(
            bytes,
            source,
            destination,
            NEIGHBOUR_ADVERTISEMENT,
            Self::FIXED,
        )?;
        let mut target = [0u8; 16];
        target.copy_from_slice(&bytes[8..24]);
        let mut target_link = None;
        options(&bytes[Self::FIXED..], |kind, payload| {
            if kind == OPTION_TARGET_LINK && target_link.is_none() {
                target_link = link_option(payload);
            }
        })?;
        Ok(Self {
            target: Ipv6Addr(target),
            solicited: bytes[4] & 0x40 != 0,
            target_link,
        })
    }
}

/// Writes the checksum into a finished message.
fn finish(message: &mut [u8], source: Ipv6Addr, destination: Ipv6Addr) {
    let length = u32::try_from(message.len()).unwrap_or(u32::MAX);
    let pseudo = pseudo_header(source, destination, NextHeader::ICMPV6, length);
    let sum = checksum(&[&pseudo, &*message]);
    message[2..4].copy_from_slice(&sum.to_be_bytes());
}

/// Writes a link-layer address option, eight bytes.
fn write_link_option(out: &mut [u8], kind: u8, mac: MacAddr) {
    out[0] = kind;
    out[1] = 1;
    out[2..8].copy_from_slice(&mac.octets());
}

/// Writes a router solicitation, returning how many bytes it used.
///
/// # Errors
///
/// [`NetError::Truncated`] if `out` cannot hold it.
pub fn write_router_solicitation(
    out: &mut [u8],
    source: Ipv6Addr,
    destination: Ipv6Addr,
    source_link: Option<MacAddr>,
) -> Result<usize, NetError> {
    let total = 8 + if source_link.is_some() { 8 } else { 0 };
    let message = {
        let have = out.len();
        out.get_mut(..total)
            .ok_or(NetError::Truncated { need: total, have })?
    };
    message.fill(0);
    message[0] = ROUTER_SOLICITATION;
    if let Some(mac) = source_link {
        write_link_option(&mut message[8..], OPTION_SOURCE_LINK, mac);
    }
    finish(message, source, destination);
    Ok(total)
}

/// Writes a router advertisement, returning how many bytes it used.
///
/// Exists for the tests and for whatever this system becomes when it is
/// the router; `bin/ipd` today only parses these.
///
/// # Errors
///
/// [`NetError::Truncated`] if `out` cannot hold it.
pub fn write_router_advertisement(
    out: &mut [u8],
    source: Ipv6Addr,
    destination: Ipv6Addr,
    router_lifetime_seconds: u16,
    source_link: Option<MacAddr>,
    prefix: Option<PrefixInformation>,
) -> Result<usize, NetError> {
    let total = RouterAdvertisement::FIXED
        + if source_link.is_some() { 8 } else { 0 }
        + if prefix.is_some() { 32 } else { 0 };
    let message = {
        let have = out.len();
        out.get_mut(..total)
            .ok_or(NetError::Truncated { need: total, have })?
    };
    message.fill(0);
    message[0] = ROUTER_ADVERTISEMENT;
    message[6..8].copy_from_slice(&router_lifetime_seconds.to_be_bytes());
    let mut at = RouterAdvertisement::FIXED;
    if let Some(mac) = source_link {
        write_link_option(&mut message[at..], OPTION_SOURCE_LINK, mac);
        at += 8;
    }
    if let Some(info) = prefix {
        let option = &mut message[at..at + 32];
        option[0] = OPTION_PREFIX;
        option[1] = 4;
        option[2] = info.prefix_length;
        option[3] = if info.autonomous { 0x40 } else { 0 };
        option[4..8].copy_from_slice(&info.valid_seconds.to_be_bytes());
        // Preferred lifetime: written equal to valid, because this writer's
        // consumers (the tests, a future router role) have no separate
        // preference to express and the parser does not carry it.
        option[8..12].copy_from_slice(&info.valid_seconds.to_be_bytes());
        option[16..32].copy_from_slice(&info.prefix.octets());
    }
    finish(message, source, destination);
    Ok(total)
}

/// Writes a neighbour solicitation for `target`.
///
/// # Errors
///
/// [`NetError::Truncated`] if `out` cannot hold it.
pub fn write_neighbour_solicitation(
    out: &mut [u8],
    source: Ipv6Addr,
    destination: Ipv6Addr,
    target: Ipv6Addr,
    source_link: Option<MacAddr>,
) -> Result<usize, NetError> {
    let total = NeighbourSolicitation::FIXED + if source_link.is_some() { 8 } else { 0 };
    let message = {
        let have = out.len();
        out.get_mut(..total)
            .ok_or(NetError::Truncated { need: total, have })?
    };
    message.fill(0);
    message[0] = NEIGHBOUR_SOLICITATION;
    message[8..24].copy_from_slice(&target.octets());
    if let Some(mac) = source_link {
        write_link_option(&mut message[24..], OPTION_SOURCE_LINK, mac);
    }
    finish(message, source, destination);
    Ok(total)
}

/// Writes a neighbour advertisement for `target`.
///
/// The override bit is set whenever a link address is carried: this stack
/// answers only for its own addresses, and an answer about your own address
/// that peers may not believe is not an answer.
///
/// # Errors
///
/// [`NetError::Truncated`] if `out` cannot hold it.
pub fn write_neighbour_advertisement(
    out: &mut [u8],
    source: Ipv6Addr,
    destination: Ipv6Addr,
    target: Ipv6Addr,
    solicited: bool,
    target_link: Option<MacAddr>,
) -> Result<usize, NetError> {
    let total = NeighbourAdvertisement::FIXED + if target_link.is_some() { 8 } else { 0 };
    let message = {
        let have = out.len();
        out.get_mut(..total)
            .ok_or(NetError::Truncated { need: total, have })?
    };
    message.fill(0);
    message[0] = NEIGHBOUR_ADVERTISEMENT;
    if solicited {
        message[4] |= 0x40;
    }
    if target_link.is_some() {
        message[4] |= 0x20;
    }
    message[8..24].copy_from_slice(&target.octets());
    if let Some(mac) = target_link {
        write_link_option(&mut message[24..], OPTION_TARGET_LINK, mac);
    }
    finish(message, source, destination);
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    const HERE: Ipv6Addr = Ipv6Addr::new([0xfe80, 0, 0, 0, 0, 0, 0, 1]);
    const THERE: Ipv6Addr = Ipv6Addr::new([0xfe80, 0, 0, 0, 0, 0, 0, 2]);

    #[test]
    fn an_echo_round_trips_with_its_addresses() {
        let mut out = [0u8; 64];
        let used = write_echo(&mut out, HERE, THERE, false, 0x1234, 7, b"payload").expect("fits");
        let echo = Echo::parse(&out[..used], HERE, THERE).expect("valid");
        assert!(!echo.is_reply);
        assert_eq!(echo.identifier, 0x1234);
        assert_eq!(echo.sequence, 7);
        assert_eq!(echo.payload, b"payload");
    }

    #[test]
    fn the_checksum_binds_the_addresses_not_just_the_bytes() {
        // The same bytes, verified against a *different* address, must
        // fail: that is the whole difference from v4's ICMP. Different, and
        // deliberately not merely swapped — one's-complement addition is
        // commutative, so a pseudo-header with source and destination
        // exchanged sums to the same value, and the first version of this
        // test asserted the arithmetic could see a swap it mathematically
        // cannot. The checksum binds the *set* of address words, not their
        // order; anything stronger is a job for authentication, not a sum.
        let mut out = [0u8; 64];
        let used = write_echo(&mut out, HERE, THERE, true, 1, 1, b"x").expect("fits");
        assert!(Echo::parse(&out[..used], HERE, THERE).is_ok());
        let elsewhere = Ipv6Addr::new([0xfe80, 0, 0, 0, 0, 0, 0, 3]);
        assert!(matches!(
            Echo::parse(&out[..used], HERE, elsewhere),
            Err(NetError::BadChecksum { .. })
        ));
    }

    #[test]
    fn a_flipped_bit_is_a_bad_checksum() {
        let mut out = [0u8; 64];
        let used = write_echo(&mut out, HERE, THERE, false, 1, 1, b"payload").expect("fits");
        out[HEADER + 2] ^= 0x40;
        assert!(matches!(
            Echo::parse(&out[..used], HERE, THERE),
            Err(NetError::BadChecksum { .. })
        ));
    }

    #[test]
    fn a_type_that_is_not_an_echo_is_unsupported_not_ignored() {
        // 135 is a neighbour solicitation — real traffic, and exactly what
        // must not be silently misread as an echo before step 2 parses it.
        let mut out = [0u8; 64];
        let used = write_echo(&mut out, HERE, THERE, false, 1, 1, b"").expect("fits");
        out[0] = 135;
        assert!(matches!(
            Echo::parse(&out[..used], HERE, THERE),
            Err(NetError::Unsupported { .. })
        ));
    }

    #[test]
    fn a_nonzero_code_on_an_echo_is_refused() {
        let mut out = [0u8; 64];
        let used = write_echo(&mut out, HERE, THERE, false, 1, 1, b"").expect("fits");
        out[1] = 3;
        assert!(matches!(
            Echo::parse(&out[..used], HERE, THERE),
            Err(NetError::Unsupported { .. })
        ));
    }

    #[test]
    fn a_short_buffer_is_truncated_not_read() {
        assert!(matches!(
            Echo::parse(&[128, 0, 0], HERE, THERE),
            Err(NetError::Truncated { .. })
        ));
    }

    const MAC: MacAddr = MacAddr([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);

    #[test]
    fn a_neighbour_solicitation_round_trips() {
        let mut out = [0u8; 64];
        let used =
            write_neighbour_solicitation(&mut out, HERE, THERE.solicited_node(), THERE, Some(MAC))
                .expect("fits");
        let parsed = NeighbourSolicitation::parse(&out[..used], HERE, THERE.solicited_node())
            .expect("valid");
        assert_eq!(parsed.target, THERE);
        assert_eq!(parsed.source_link, Some(MAC));
    }

    #[test]
    fn a_duplicate_address_probe_carries_no_link_option() {
        let mut out = [0u8; 64];
        let used = write_neighbour_solicitation(
            &mut out,
            Ipv6Addr::UNSPECIFIED,
            THERE.solicited_node(),
            THERE,
            None,
        )
        .expect("fits");
        let parsed = NeighbourSolicitation::parse(
            &out[..used],
            Ipv6Addr::UNSPECIFIED,
            THERE.solicited_node(),
        )
        .expect("valid");
        assert_eq!(parsed.source_link, None);
    }

    #[test]
    fn a_neighbour_advertisement_round_trips_with_its_flags() {
        let mut out = [0u8; 64];
        let used = write_neighbour_advertisement(&mut out, HERE, THERE, HERE, true, Some(MAC))
            .expect("fits");
        let parsed = NeighbourAdvertisement::parse(&out[..used], HERE, THERE).expect("valid");
        assert_eq!(parsed.target, HERE);
        assert!(parsed.solicited);
        assert_eq!(parsed.target_link, Some(MAC));
    }

    #[test]
    fn a_router_advertisement_yields_lifetime_link_and_prefix() {
        let prefix = PrefixInformation {
            prefix_length: 64,
            autonomous: true,
            valid_seconds: 86400,
            prefix: Ipv6Addr::new([0xfec0, 0, 0, 0, 0, 0, 0, 0]),
        };
        let mut out = [0u8; 96];
        let used = write_router_advertisement(
            &mut out,
            HERE,
            Ipv6Addr::ALL_NODES,
            1800,
            Some(MAC),
            Some(prefix),
        )
        .expect("fits");
        let parsed =
            RouterAdvertisement::parse(&out[..used], HERE, Ipv6Addr::ALL_NODES).expect("valid");
        assert_eq!(parsed.router_lifetime_seconds, 1800);
        assert_eq!(parsed.source_link, Some(MAC));
        assert_eq!(parsed.prefix, Some(prefix));
    }

    #[test]
    fn a_router_solicitation_round_trips_through_its_own_verifier() {
        // The solicitation has no parse struct -- this stack sends them and
        // slirp answers -- so the round trip is the envelope check.
        let mut out = [0u8; 64];
        let used = write_router_solicitation(&mut out, HERE, Ipv6Addr::ALL_ROUTERS, Some(MAC))
            .expect("fits");
        assert_eq!(out[0], ROUTER_SOLICITATION);
        assert!(
            verified(
                &out[..used],
                HERE,
                Ipv6Addr::ALL_ROUTERS,
                ROUTER_SOLICITATION,
                8
            )
            .is_ok()
        );
    }

    #[test]
    fn an_unknown_option_is_skipped_and_the_next_one_still_found() {
        // An MTU option (type 5) in front of the link option: the walk must
        // step over what it does not know by the length it declares.
        let mut out = [0u8; 64];
        let used = write_neighbour_advertisement(&mut out, HERE, THERE, HERE, false, Some(MAC))
            .expect("fits");
        let mut widened = [0u8; 64];
        widened[..NeighbourAdvertisement::FIXED]
            .copy_from_slice(&out[..NeighbourAdvertisement::FIXED]);
        widened[NeighbourAdvertisement::FIXED] = 5; // MTU
        widened[NeighbourAdvertisement::FIXED + 1] = 1;
        widened[NeighbourAdvertisement::FIXED + 8..used + 8]
            .copy_from_slice(&out[NeighbourAdvertisement::FIXED..used]);
        // Recompute the checksum over the widened message.
        widened[2..4].copy_from_slice(&[0, 0]);
        finish(&mut widened[..used + 8], HERE, THERE);
        let parsed =
            NeighbourAdvertisement::parse(&widened[..used + 8], HERE, THERE).expect("valid");
        assert_eq!(parsed.target_link, Some(MAC));
    }

    #[test]
    fn a_zero_option_length_is_refused_not_looped_on() {
        let mut out = [0u8; 64];
        let used = write_neighbour_advertisement(&mut out, HERE, THERE, HERE, false, Some(MAC))
            .expect("fits");
        out[NeighbourAdvertisement::FIXED + 1] = 0;
        out[2..4].copy_from_slice(&[0, 0]);
        finish(&mut out[..used], HERE, THERE);
        assert!(matches!(
            NeighbourAdvertisement::parse(&out[..used], HERE, THERE),
            Err(NetError::Unsupported {
                field: "ndp option length",
                ..
            })
        ));
    }

    #[test]
    fn an_option_length_past_the_buffer_is_refused_with_both_numbers() {
        let mut out = [0u8; 64];
        let used = write_neighbour_advertisement(&mut out, HERE, THERE, HERE, false, Some(MAC))
            .expect("fits");
        out[NeighbourAdvertisement::FIXED + 1] = 4; // claims 32 bytes; 8 exist
        out[2..4].copy_from_slice(&[0, 0]);
        finish(&mut out[..used], HERE, THERE);
        assert!(matches!(
            NeighbourAdvertisement::parse(&out[..used], HERE, THERE),
            Err(NetError::LengthBeyondBuffer { .. })
        ));
    }

    #[test]
    fn ndp_checksums_bind_the_addresses_too() {
        let mut out = [0u8; 64];
        let used = write_neighbour_advertisement(&mut out, HERE, THERE, HERE, true, Some(MAC))
            .expect("fits");
        let elsewhere = Ipv6Addr::new([0xfe80, 0, 0, 0, 0, 0, 0, 9]);
        assert!(matches!(
            NeighbourAdvertisement::parse(&out[..used], HERE, elsewhere),
            Err(NetError::BadChecksum { .. })
        ));
    }

    #[test]
    fn the_wrong_message_type_is_refused_by_every_parser() {
        let mut out = [0u8; 64];
        let used = write_neighbour_advertisement(&mut out, HERE, THERE, HERE, true, Some(MAC))
            .expect("fits");
        assert!(matches!(
            NeighbourSolicitation::parse(&out[..used], HERE, THERE),
            Err(NetError::Unsupported {
                field: "icmpv6 type",
                ..
            })
        ));
        assert!(matches!(
            RouterAdvertisement::parse(&out[..used], HERE, THERE),
            Err(NetError::Unsupported {
                field: "icmpv6 type",
                ..
            })
        ));
    }

    #[test]
    fn address_derivations_hold_both_ends_of_eui64() {
        // QEMU's locally-administered 52:54... must clear the bit; a
        // universally-administered address must set it. Both directions, so
        // the inversion cannot quietly become a set-always or clear-always.
        let local = Ipv6Addr::interface_id(MacAddr([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]));
        assert_eq!(local, [0x50, 0x54, 0x00, 0xff, 0xfe, 0x12, 0x34, 0x56]);
        let universal = Ipv6Addr::interface_id(MacAddr([0x00, 0x1b, 0x21, 0xaa, 0xbb, 0xcc]));
        assert_eq!(universal, [0x02, 0x1b, 0x21, 0xff, 0xfe, 0xaa, 0xbb, 0xcc]);

        let link_local = Ipv6Addr::link_local_from(MacAddr([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]));
        assert_eq!(
            link_local.segments(),
            [0xfe80, 0, 0, 0, 0x5054, 0x00ff, 0xfe12, 0x3456]
        );

        let solicited = link_local.solicited_node();
        assert_eq!(
            solicited.segments(),
            [0xff02, 0, 0, 0, 0, 1, 0xff12, 0x3456]
        );
        assert_eq!(
            solicited.multicast_mac(),
            MacAddr([0x33, 0x33, 0xff, 0x12, 0x34, 0x56])
        );

        let global = Ipv6Addr::from_prefix(Ipv6Addr::new([0xfec0, 0, 0, 0, 0, 0, 0, 0]), local);
        assert_eq!(
            global.segments(),
            [0xfec0, 0, 0, 0, 0x5054, 0x00ff, 0xfe12, 0x3456]
        );
    }
}
