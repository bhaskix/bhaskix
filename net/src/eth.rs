// SPDX-License-Identifier: Apache-2.0
//! Ethernet II framing — fourteen bytes, and what follows them.
//!
//! The smallest parser in this crate and the one every packet passes through,
//! which makes it the one whose bounds checking matters most.
//!
//! # What is deliberately not parsed
//!
//! **802.1Q VLAN tags** are refused rather than skipped. A tagged frame carries
//! its real EtherType four bytes further on, so a parser that quietly stepped
//! over the tag would accept traffic from a VLAN this interface was never
//! configured for and hand it upward as though it had arrived untagged. That is
//! a segmentation boundary, and silently crossing one is worse than not
//! supporting it. When VLANs are supported it will be because something decides
//! *which* tags are acceptable.
//!
//! **802.3 length framing** — a value of 1500 or below in the same field — is
//! likewise refused. It means the two bytes are a length and an LLC header
//! follows, which is a different format, not a variant of this one.
//!
//! **The FCS** is not here: the device checks and strips it. A driver that
//! handed one up would make the last four bytes look like payload, which is why
//! `netd` is defined as passing frames the device accepted.

use crate::{NetError, addr::MacAddr, be16};

/// Bytes in an Ethernet II header.
pub const HEADER: usize = 14;

/// The largest payload standard Ethernet carries.
pub const MTU: usize = 1500;

/// What the two bytes after the addresses mean.
///
/// Values at or below [`EtherType::LENGTH_CEILING`] are lengths rather than
/// types, and are refused; see the module header.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct EtherType(pub u16);

impl EtherType {
    /// IPv4.
    pub const IPV4: Self = Self(0x0800);
    /// ARP.
    pub const ARP: Self = Self(0x0806);
    /// IPv6, recognised so that it can be counted rather than parsed.
    pub const IPV6: Self = Self(0x86dd);
    /// An 802.1Q VLAN tag.
    pub const VLAN: Self = Self(0x8100);

    /// The largest value that is a length rather than a type.
    pub const LENGTH_CEILING: u16 = 1500;
}

/// A parsed Ethernet II frame, borrowing its payload.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct EthFrame<'a> {
    /// Who the frame is addressed to.
    pub destination: MacAddr,
    /// Who sent it, according to the frame.
    pub source: MacAddr,
    /// What the payload is.
    pub ethertype: EtherType,
    /// The bytes after the header, exactly as they arrived.
    pub payload: &'a [u8],
}

impl<'a> EthFrame<'a> {
    /// Parses a frame.
    ///
    /// # Errors
    ///
    /// - [`NetError::Truncated`] if fewer than [`HEADER`] bytes were supplied.
    /// - [`NetError::Unsupported`] for a VLAN tag, an 802.3 length, or any
    ///   EtherType this crate does not carry upward. The value is in the error
    ///   so a caller can count what it is seeing rather than only that it saw
    ///   something.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, NetError> {
        let header = bytes.get(..HEADER).ok_or(NetError::Truncated {
            need: HEADER,
            have: bytes.len(),
        })?;

        // Infallible given the slice above, but taken through the same checked
        // reader as every other field so that a change to `HEADER` cannot leave
        // an unchecked index behind.
        let raw = be16(header, 12).ok_or(NetError::Truncated {
            need: HEADER,
            have: bytes.len(),
        })?;

        if raw <= EtherType::LENGTH_CEILING {
            return Err(NetError::Unsupported {
                field: "802.3 length framing, not EtherType",
                value: u32::from(raw),
            });
        }
        let ethertype = EtherType(raw);
        if ethertype == EtherType::VLAN {
            return Err(NetError::Unsupported {
                field: "802.1Q VLAN tag",
                value: u32::from(raw),
            });
        }

        let mut destination = [0u8; 6];
        let mut source = [0u8; 6];
        destination.copy_from_slice(&header[0..6]);
        source.copy_from_slice(&header[6..12]);

        Ok(Self {
            destination: MacAddr(destination),
            source: MacAddr(source),
            ethertype,
            // Not `&bytes[HEADER..]`: the slice above proves the length, and
            // `get` keeps the proof local to this line.
            payload: bytes.get(HEADER..).unwrap_or(&[]),
        })
    }

    /// Whether this frame is addressed to `mine`, to broadcast, or to a group.
    ///
    /// The receive filter, written here rather than in the caller so that every
    /// caller applies the same one. A frame addressed elsewhere reaching a
    /// station at all is normal on a hub, a mirror port, or a virtual switch —
    /// accepting it is the bug, not receiving it.
    #[must_use]
    pub fn addressed_to(&self, mine: MacAddr) -> bool {
        self.destination == mine || self.destination.is_group()
    }
}

/// Writes an Ethernet II header into `out`, returning the bytes written.
///
/// # Errors
///
/// [`NetError::Truncated`] if `out` cannot hold [`HEADER`] bytes.
pub fn write_header(
    out: &mut [u8],
    destination: MacAddr,
    source: MacAddr,
    ethertype: EtherType,
) -> Result<usize, NetError> {
    let available = out.len();
    let header = out.get_mut(..HEADER).ok_or(NetError::Truncated {
        need: HEADER,
        have: available,
    })?;
    header[0..6].copy_from_slice(&destination.octets());
    header[6..12].copy_from_slice(&source.octets());
    header[12..14].copy_from_slice(&ethertype.0.to_be_bytes());
    Ok(HEADER)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINE: MacAddr = MacAddr([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
    const PEER: MacAddr = MacAddr([0x52, 0x54, 0x00, 0xaa, 0xbb, 0xcc]);

    fn frame(ethertype: u16, payload: &[u8]) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        bytes[0..6].copy_from_slice(&MINE.octets());
        bytes[6..12].copy_from_slice(&PEER.octets());
        bytes[12..14].copy_from_slice(&ethertype.to_be_bytes());
        bytes[HEADER..HEADER + payload.len()].copy_from_slice(payload);
        bytes
    }

    #[test]
    fn a_frame_parses_into_its_three_fields_and_a_payload() {
        let bytes = frame(0x0800, &[0xde, 0xad]);
        let parsed = EthFrame::parse(&bytes).unwrap();
        assert_eq!(parsed.destination, MINE);
        assert_eq!(parsed.source, PEER);
        assert_eq!(parsed.ethertype, EtherType::IPV4);
        assert_eq!(&parsed.payload[..2], &[0xde, 0xad]);
    }

    #[test]
    fn exactly_a_header_is_a_frame_with_an_empty_payload() {
        // The boundary: one byte less must fail, exactly the header must not,
        // and the payload must be empty rather than the parser reaching past.
        let bytes = frame(0x0800, &[]);
        assert_eq!(
            EthFrame::parse(&bytes[..HEADER - 1]),
            Err(NetError::Truncated {
                need: HEADER,
                have: HEADER - 1
            })
        );
        let parsed = EthFrame::parse(&bytes[..HEADER]).unwrap();
        assert!(parsed.payload.is_empty());
    }

    #[test]
    fn a_vlan_tag_is_refused_and_not_stepped_over() {
        // The one that matters: skipping the tag would hand a frame from
        // another VLAN upward as though it had arrived on this one.
        let bytes = frame(0x8100, &[0x00, 0x64, 0x08, 0x00]);
        assert_eq!(
            EthFrame::parse(&bytes),
            Err(NetError::Unsupported {
                field: "802.1Q VLAN tag",
                value: 0x8100
            })
        );
    }

    #[test]
    fn the_boundary_between_a_length_and_a_type() {
        // 1500 is a length; 1501 is a type. Both directions, because an
        // off-by-one here accepts LLC frames as IPv4 or refuses valid ones.
        assert!(matches!(
            EthFrame::parse(&frame(1500, &[])),
            Err(NetError::Unsupported { .. })
        ));
        assert!(EthFrame::parse(&frame(1501, &[])).is_ok());
    }

    #[test]
    fn the_receive_filter_accepts_three_things_and_no_others() {
        assert!(
            EthFrame::parse(&frame(0x0800, &[]))
                .unwrap()
                .addressed_to(MINE)
        );

        let mut broadcast = frame(0x0800, &[]);
        broadcast[0..6].copy_from_slice(&MacAddr::BROADCAST.octets());
        assert!(EthFrame::parse(&broadcast).unwrap().addressed_to(MINE));

        let mut multicast = frame(0x0800, &[]);
        multicast[0..6].copy_from_slice(&[0x01, 0x00, 0x5e, 0, 0, 1]);
        assert!(EthFrame::parse(&multicast).unwrap().addressed_to(MINE));

        // Somebody else's unicast frame. This is the case that must be false,
        // and the reason the filter is not merely `!= UNSPECIFIED`.
        let mut elsewhere = frame(0x0800, &[]);
        elsewhere[0..6].copy_from_slice(&[0x52, 0x54, 0x00, 0x99, 0x99, 0x99]);
        assert!(!EthFrame::parse(&elsewhere).unwrap().addressed_to(MINE));
    }

    #[test]
    fn a_written_header_parses_back() {
        let mut out = [0u8; HEADER];
        assert_eq!(
            write_header(&mut out, PEER, MINE, EtherType::ARP).unwrap(),
            HEADER
        );
        let parsed = EthFrame::parse(&out).unwrap();
        assert_eq!(parsed.destination, PEER);
        assert_eq!(parsed.source, MINE);
        assert_eq!(parsed.ethertype, EtherType::ARP);

        let mut short = [0u8; HEADER - 1];
        assert!(write_header(&mut short, PEER, MINE, EtherType::ARP).is_err());
    }
}
