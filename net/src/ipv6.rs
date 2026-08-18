// SPDX-License-Identifier: Apache-2.0
//! IPv6 — forty fixed bytes, and a refusal where the extension chain starts.
//!
//! [RFC 0029](../../docs/rfc/0029-ipv6.md) step 1. The fixed header, parse
//! and build, and the pseudo-header every transport checksum over v6 is
//! computed with. In v6 the transport checksum is not optional the way
//! UDP's is over v4 — the IP header lost its own checksum, so the transport
//! sum is the only integrity the datagram has.
//!
//! # Extension headers are refused, not skipped
//!
//! An extension chain is a walk over attacker-chosen lengths — the exact
//! shape of parser bug this crate exists to refuse — and nothing this stack
//! speaks (NDP, ICMPv6 echo, UDP, TCP) requires one. A packet whose next
//! header names an extension type is [`NetError::Unsupported`], counted and
//! dropped by the caller like every other hostile refusal. The day a
//! consumer genuinely needs one, building the walk is a decision recorded
//! in an RFC, not a discovery in a parser.

use crate::{NetError, addr::Ipv6Addr, be16};

/// Bytes in the fixed header. There is no variable part — that is the
/// extension chain, and the module header says what happens to it.
pub const HEADER: usize = 40;

/// A next-header value, which is an IPv4 protocol number when it is not an
/// extension type.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct NextHeader(pub u8);

impl NextHeader {
    /// TCP.
    pub const TCP: Self = Self(6);
    /// UDP.
    pub const UDP: Self = Self(17);
    /// ICMPv6 — a different number from v4's ICMP, which matters because
    /// the value feeds the pseudo-header.
    pub const ICMPV6: Self = Self(58);

    /// Whether this value names an extension header.
    ///
    /// The list is the specification's: hop-by-hop, routing, fragment,
    /// encapsulating security, authentication, destination options,
    /// mobility, and the three later additions (HIP, Shim6, and the two
    /// experimental values). "No next header" is included — a datagram
    /// whose payload is declared to be nothing is not one this stack has a
    /// consumer for.
    #[must_use]
    pub const fn is_extension(self) -> bool {
        matches!(
            self.0,
            0 | 43 | 44 | 50 | 51 | 59 | 60 | 135 | 139 | 140 | 253 | 254
        )
    }
}

/// A parsed fixed header.
///
/// The traffic class and flow label are checked for well-formedness by
/// position (they cannot be malformed — any bits are legal) and not
/// carried: nothing in this stack consumes them, and a field nobody reads
/// is a field somebody will misread.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Ipv6Header {
    /// Who sent it.
    pub source: Ipv6Addr,
    /// Who it is for.
    pub destination: Ipv6Addr,
    /// What the payload is.
    pub next_header: NextHeader,
    /// Hops remaining. Parsed for the builder's symmetry; this stack does
    /// not forward, so it never decrements one.
    pub hop_limit: u8,
}

impl Ipv6Header {
    /// Parses a fixed header and returns it with the payload that follows.
    ///
    /// The payload slice is exactly as long as the header claimed — bytes
    /// past it (an Ethernet frame's padding) are cut, and a claim past what
    /// was supplied is refused.
    ///
    /// # Errors
    ///
    /// - [`NetError::Truncated`] if fewer than [`HEADER`] bytes were
    ///   supplied.
    /// - [`NetError::BadVersion`] if the version field is not 6.
    /// - [`NetError::LengthBeyondBuffer`] if the payload length reaches
    ///   past the bytes supplied.
    /// - [`NetError::Unsupported`] if the next header is an extension type
    ///   — the module header's refusal, applied where the chain would
    ///   start.
    pub fn parse(bytes: &[u8]) -> Result<(Self, &[u8]), NetError> {
        let fixed = bytes.get(..HEADER).ok_or(NetError::Truncated {
            need: HEADER,
            have: bytes.len(),
        })?;

        let version = fixed[0] >> 4;
        if version != 6 {
            return Err(NetError::BadVersion(version));
        }

        let payload_length = usize::from(be16(fixed, 4).unwrap_or(0));
        let end = HEADER + payload_length;
        if end > bytes.len() {
            return Err(NetError::LengthBeyondBuffer {
                stated: end,
                have: bytes.len(),
            });
        }

        let next_header = NextHeader(fixed[6]);
        if next_header.is_extension() {
            return Err(NetError::Unsupported {
                field: "ipv6 next header (extension chain)",
                value: u32::from(next_header.0),
            });
        }

        let mut source = [0u8; 16];
        source.copy_from_slice(&fixed[8..24]);
        let mut destination = [0u8; 16];
        destination.copy_from_slice(&fixed[24..40]);

        Ok((
            Self {
                source: Ipv6Addr(source),
                destination: Ipv6Addr(destination),
                next_header,
                hop_limit: fixed[7],
            },
            &bytes[HEADER..end],
        ))
    }
}

/// Writes a fixed header into the first [`HEADER`] bytes of `out`.
///
/// The traffic class and flow label are written zero: this stack marks
/// nothing and labels no flows, and writing a field it would never read
/// honestly means writing the value that says so.
///
/// # Errors
///
/// - [`NetError::Truncated`] if `out` cannot hold the header.
/// - [`NetError::LengthBeyondBuffer`] if `payload_length` does not fit the
///   sixteen bits the wire gives it.
pub fn write_header(
    out: &mut [u8],
    source: Ipv6Addr,
    destination: Ipv6Addr,
    next_header: NextHeader,
    hop_limit: u8,
    payload_length: usize,
) -> Result<(), NetError> {
    let header = {
        let have = out.len();
        out.get_mut(..HEADER)
            .ok_or(NetError::Truncated { need: HEADER, have })?
    };
    let length = u16::try_from(payload_length).map_err(|_| NetError::LengthBeyondBuffer {
        stated: payload_length,
        have: usize::from(u16::MAX),
    })?;

    header[0] = 6 << 4;
    header[1] = 0;
    header[2] = 0;
    header[3] = 0;
    header[4..6].copy_from_slice(&length.to_be_bytes());
    header[6] = next_header.0;
    header[7] = hop_limit;
    header[8..24].copy_from_slice(&source.octets());
    header[24..40].copy_from_slice(&destination.octets());
    Ok(())
}

/// The pseudo-header a v6 transport checksum is computed over, as bytes
/// ready for [`crate::checksum`].
///
/// The layout is the specification's: both addresses, the transport length
/// as thirty-two bits, three zero bytes, and the next-header value — forty
/// bytes exactly, and *not* the same layout as v4's twelve, which is why it
/// is built in one place instead of at every call site.
#[must_use]
pub fn pseudo_header(
    source: Ipv6Addr,
    destination: Ipv6Addr,
    next_header: NextHeader,
    transport_length: u32,
) -> [u8; 40] {
    let mut pseudo = [0u8; 40];
    pseudo[0..16].copy_from_slice(&source.octets());
    pseudo[16..32].copy_from_slice(&destination.octets());
    pseudo[32..36].copy_from_slice(&transport_length.to_be_bytes());
    pseudo[39] = next_header.0;
    pseudo
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(next: u8, payload: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0u8; HEADER + payload.len()];
        let source = Ipv6Addr::new([0xfe80, 0, 0, 0, 0, 0, 0, 1]);
        let destination = Ipv6Addr::new([0xfe80, 0, 0, 0, 0, 0, 0, 2]);
        write_header(
            &mut bytes,
            source,
            destination,
            NextHeader(next),
            64,
            payload.len(),
        )
        .expect("fits");
        bytes[HEADER..].copy_from_slice(payload);
        bytes
    }

    #[test]
    fn a_well_formed_header_round_trips() {
        let built = packet(17, b"hello");
        let (header, payload) = Ipv6Header::parse(&built).expect("valid");
        assert_eq!(header.next_header, NextHeader::UDP);
        assert_eq!(header.hop_limit, 64);
        assert_eq!(header.source.segments()[0], 0xfe80);
        assert_eq!(payload, b"hello");
    }

    #[test]
    fn frame_padding_past_the_stated_length_is_cut() {
        let mut built = packet(17, b"hello");
        built.extend_from_slice(&[0u8; 10]); // an Ethernet minimum-size frame's padding
        let (_, payload) = Ipv6Header::parse(&built).expect("valid");
        assert_eq!(payload, b"hello");
    }

    #[test]
    fn a_length_past_the_buffer_is_refused_with_both_numbers() {
        let built = packet(17, b"hello");
        let clipped = &built[..HEADER + 2];
        match Ipv6Header::parse(clipped) {
            Err(NetError::LengthBeyondBuffer { stated, have }) => {
                assert_eq!(stated, HEADER + 5);
                assert_eq!(have, HEADER + 2);
            }
            other => panic!("wanted LengthBeyondBuffer, got {other:?}"),
        }
    }

    #[test]
    fn the_wrong_version_is_refused() {
        let mut built = packet(17, b"");
        built[0] = 4 << 4;
        assert!(matches!(
            Ipv6Header::parse(&built),
            Err(NetError::BadVersion(4))
        ));
    }

    #[test]
    fn a_short_buffer_is_truncated_not_read() {
        assert!(matches!(
            Ipv6Header::parse(&[0x60; 20]),
            Err(NetError::Truncated { need: HEADER, .. })
        ));
    }

    #[test]
    fn every_extension_type_is_refused_where_the_chain_would_start() {
        for extension in [0u8, 43, 44, 50, 51, 59, 60, 135, 139, 140, 253, 254] {
            let built = packet(extension, b"");
            match Ipv6Header::parse(&built) {
                Err(NetError::Unsupported { value, .. }) => {
                    assert_eq!(value, u32::from(extension));
                }
                other => panic!("extension {extension} not refused: {other:?}"),
            }
        }
    }

    #[test]
    fn the_pseudo_header_is_the_specifications_layout() {
        let source = Ipv6Addr::new([0xfe80, 0, 0, 0, 0, 0, 0, 1]);
        let destination = Ipv6Addr::ALL_NODES;
        let pseudo = pseudo_header(source, destination, NextHeader::ICMPV6, 0x1_0000);
        assert_eq!(&pseudo[0..16], &source.octets());
        assert_eq!(&pseudo[16..32], &destination.octets());
        // A transport length that needs the full thirty-two bits, because a
        // sixteen-bit write here would silently truncate jumbo-scale sums.
        assert_eq!(&pseudo[32..36], &0x0001_0000_u32.to_be_bytes());
        assert_eq!(&pseudo[36..39], &[0, 0, 0]);
        assert_eq!(pseudo[39], 58);
    }
}
