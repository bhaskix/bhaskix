// SPDX-License-Identifier: Apache-2.0
//! Ethernet II framing — fourteen bytes, and what follows them.
//!
//! The smallest parser in this crate and the one every packet passes through,
//! which makes it the one whose bounds checking matters most.
//!
//! # 802.1Q, and the refusal that preceded it
//!
//! This module used to refuse every tagged frame, and said why: a parser that
//! quietly stepped over a tag *"would accept traffic from a VLAN this interface
//! was never configured for"*, which is a segmentation boundary crossed in
//! silence. The condition it set for lifting the refusal was that something
//! decide **which** tags are acceptable.
//!
//! [RFC 0074](../../docs/rfc/0074-what-a-network-interface-is.md) is that
//! something: an interface knows its VLAN or knows it has none. So the refusal
//! is **kept and made conditional** rather than deleted.
//!
//! * [`EthFrame::parse`] behaves exactly as before — a tagged frame is refused.
//!   Every existing caller keeps the guarantee it was written against.
//! * [`EthFrame::parse_on`] takes what the interface is configured for, and
//!   accepts a tag **only** if it is that one. A frame for another VLAN, a
//!   tagged frame on an untagged interface, and an untagged frame on a VLAN
//!   interface are all refused.
//!
//! # What is still deliberately not parsed
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

    /// Parses a frame arriving on an interface configured for `vlan`.
    ///
    /// **This is the decision the old refusal was waiting for.** `vlan` is what
    /// the interface is configured with -- `Some(id)` for a VLAN interface,
    /// `None` for an untagged one -- and a frame is accepted only if it agrees:
    ///
    /// | frame | interface | outcome |
    /// |---|---|---|
    /// | untagged | untagged | accepted |
    /// | tagged `n` | VLAN `n` | accepted, payload after the tag |
    /// | tagged `n` | VLAN `m` | **refused** |
    /// | tagged | untagged | **refused** |
    /// | untagged | VLAN | **refused** |
    ///
    /// The last two are the segmentation boundary. A station on a trunk can
    /// send a tag for any VLAN, so a tag is never evidence of where a frame
    /// came from -- only agreement with what this interface was *given* is.
    ///
    /// # Errors
    ///
    /// As [`EthFrame::parse`], plus [`NetError::Unsupported`] naming the tag
    /// when it does not match, so a caller can count foreign VLANs it is
    /// seeing rather than only that it saw something.
    pub fn parse_on(bytes: &'a [u8], vlan: Option<u16>) -> Result<Self, NetError> {
        let header = bytes.get(..HEADER).ok_or(NetError::Truncated {
            need: HEADER,
            have: bytes.len(),
        })?;
        let raw = be16(header, 12).ok_or(NetError::Truncated {
            need: HEADER,
            have: bytes.len(),
        })?;

        let mut destination = [0u8; 6];
        let mut source = [0u8; 6];
        destination.copy_from_slice(&header[0..6]);
        source.copy_from_slice(&header[6..12]);

        if EtherType(raw) == EtherType::VLAN {
            let want = vlan.ok_or(NetError::Unsupported {
                field: "802.1Q tag on an interface with no VLAN",
                value: u32::from(raw),
            })?;
            // The tag's two control bytes, then the real EtherType behind it.
            let control = be16(bytes, HEADER).ok_or(NetError::Truncated {
                need: HEADER + Vlan::BYTES,
                have: bytes.len(),
            })?;
            let tag = Vlan::from_control(control);
            if tag.id != want & Vlan::MAX_ID {
                return Err(NetError::Unsupported {
                    field: "802.1Q tag for another VLAN",
                    value: u32::from(tag.id),
                });
            }
            let inner = be16(bytes, HEADER + 2).ok_or(NetError::Truncated {
                need: HEADER + Vlan::BYTES,
                have: bytes.len(),
            })?;
            if inner <= EtherType::LENGTH_CEILING {
                return Err(NetError::Unsupported {
                    field: "802.3 length framing behind a tag",
                    value: u32::from(inner),
                });
            }
            if EtherType(inner) == EtherType::VLAN {
                // A second tag is Q-in-Q, a different format, and stacking is
                // refused by RFC 0074 rather than half-supported here.
                return Err(NetError::Unsupported {
                    field: "stacked 802.1Q tags",
                    value: u32::from(inner),
                });
            }
            return Ok(Self {
                destination: MacAddr(destination),
                source: MacAddr(source),
                ethertype: EtherType(inner),
                payload: bytes.get(HEADER + Vlan::BYTES..).unwrap_or(&[]),
            });
        }

        // Untagged. A VLAN interface does not take it: its traffic arrives
        // tagged, and an untagged frame on a trunk belongs to the native VLAN,
        // which is somebody else's.
        if vlan.is_some() {
            return Err(NetError::Unsupported {
                field: "untagged frame on a VLAN interface",
                value: u32::from(raw),
            });
        }
        Self::parse(bytes)
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

/// An 802.1Q tag's control information.
///
/// Three bits of priority, one drop-eligible bit and twelve of VLAN id, in the
/// two bytes after the `0x8100` EtherType.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Vlan {
    /// Priority code point, 0 to 7.
    pub priority: u8,
    /// Drop eligible indicator.
    pub drop_eligible: bool,
    /// The VLAN identifier, 1 to 4094 in practice.
    pub id: u16,
}

impl Vlan {
    /// Bytes an 802.1Q tag adds to a header.
    pub const BYTES: usize = 4;
    /// The largest identifier the twelve-bit field holds.
    pub const MAX_ID: u16 = 0xfff;

    /// A tag carrying only an identifier, at priority zero.
    #[must_use]
    pub const fn id(id: u16) -> Self {
        Self {
            priority: 0,
            drop_eligible: false,
            id: id & Self::MAX_ID,
        }
    }

    /// Reads the two control bytes.
    #[must_use]
    pub const fn from_control(control: u16) -> Self {
        Self {
            priority: (control >> 13) as u8,
            drop_eligible: control & (1 << 12) != 0,
            id: control & Self::MAX_ID,
        }
    }

    /// The two control bytes.
    #[must_use]
    pub const fn control(&self) -> u16 {
        ((self.priority as u16 & 0b111) << 13)
            | if self.drop_eligible { 1 << 12 } else { 0 }
            | (self.id & Self::MAX_ID)
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

/// Writes a tagged Ethernet header into `out`, returning the bytes written.
///
/// Eighteen bytes: the addresses, `0x8100`, the tag's control bytes, then the
/// EtherType the payload really is.
///
/// # Errors
///
/// [`NetError::Truncated`] if `out` cannot hold them.
pub fn write_tagged_header(
    out: &mut [u8],
    destination: MacAddr,
    source: MacAddr,
    vlan: Vlan,
    ethertype: EtherType,
) -> Result<usize, NetError> {
    const TOTAL: usize = HEADER + Vlan::BYTES;
    let available = out.len();
    let header = out.get_mut(..TOTAL).ok_or(NetError::Truncated {
        need: TOTAL,
        have: available,
    })?;
    header[0..6].copy_from_slice(&destination.octets());
    header[6..12].copy_from_slice(&source.octets());
    header[12..14].copy_from_slice(&EtherType::VLAN.0.to_be_bytes());
    header[14..16].copy_from_slice(&vlan.control().to_be_bytes());
    header[16..18].copy_from_slice(&ethertype.0.to_be_bytes());
    Ok(TOTAL)
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

    /// The tag's three fields pack into two bytes the way 802.1Q says.
    #[test]
    fn a_tag_round_trips_through_its_control_bytes() {
        let tag = Vlan {
            priority: 5,
            drop_eligible: true,
            id: 17,
        };
        let control = tag.control();
        assert_eq!(control >> 13, 5, "priority in the top three bits");
        assert_ne!(control & (1 << 12), 0, "drop-eligible");
        assert_eq!(control & 0xfff, 17, "the identifier in the low twelve");
        assert_eq!(Vlan::from_control(control), tag);

        // An identifier wider than the field is masked, not wrapped into the
        // priority bits above it.
        assert_eq!(Vlan::id(0xffff).id, 0xfff);
        assert_eq!(Vlan::id(0xffff).priority, 0);
    }

    /// The table in `parse_on`'s documentation, as a test.
    #[test]
    fn a_tag_is_accepted_only_by_the_interface_it_belongs_to() {
        let mut tagged = [0u8; 32];
        write_tagged_header(&mut tagged, MINE, PEER, Vlan::id(17), EtherType::ARP).expect("writes");
        let untagged = frame(EtherType::ARP.0, &[0xaa; 8]);

        // Tagged 17 on VLAN 17: accepted, and the payload starts after the tag.
        let ours = EthFrame::parse_on(&tagged, Some(17)).expect("our own VLAN");
        assert_eq!(ours.ethertype, EtherType::ARP);
        assert_eq!(ours.destination, MINE);
        assert_eq!(ours.payload.len(), tagged.len() - HEADER - Vlan::BYTES);

        // Untagged on an untagged interface: accepted, exactly as before.
        assert!(EthFrame::parse_on(&untagged, None).is_ok());

        // The three refusals, which are the segmentation boundary.
        assert!(
            matches!(
                EthFrame::parse_on(&tagged, Some(18)),
                Err(NetError::Unsupported { .. })
            ),
            "a frame for another VLAN was accepted"
        );
        assert!(
            matches!(
                EthFrame::parse_on(&tagged, None),
                Err(NetError::Unsupported { .. })
            ),
            "a tagged frame was accepted on an untagged interface"
        );
        assert!(
            matches!(
                EthFrame::parse_on(&untagged, Some(17)),
                Err(NetError::Unsupported { .. })
            ),
            "an untagged frame was accepted on a VLAN interface"
        );
    }

    /// `parse` keeps the guarantee every existing caller was written against.
    #[test]
    fn the_plain_parser_still_refuses_every_tag() {
        let mut tagged = [0u8; 32];
        write_tagged_header(&mut tagged, MINE, PEER, Vlan::id(17), EtherType::IPV4)
            .expect("writes");
        assert!(matches!(
            EthFrame::parse(&tagged),
            Err(NetError::Unsupported { .. })
        ));
    }

    /// Stacked tags and a length behind a tag are refused rather than half-read.
    #[test]
    fn what_sits_behind_a_tag_is_checked_too() {
        let mut stacked = [0u8; 32];
        write_tagged_header(&mut stacked, MINE, PEER, Vlan::id(17), EtherType::VLAN)
            .expect("writes");
        assert!(
            matches!(
                EthFrame::parse_on(&stacked, Some(17)),
                Err(NetError::Unsupported { .. })
            ),
            "Q-in-Q was accepted"
        );

        let mut length = [0u8; 32];
        write_tagged_header(&mut length, MINE, PEER, Vlan::id(17), EtherType(600)).expect("writes");
        assert!(matches!(
            EthFrame::parse_on(&length, Some(17)),
            Err(NetError::Unsupported { .. })
        ));

        // A tag with nothing behind it is truncated, not a silent accept.
        let short = &stacked[..HEADER + 2];
        assert!(matches!(
            EthFrame::parse_on(short, Some(17)),
            Err(NetError::Truncated { .. })
        ));
    }
}
