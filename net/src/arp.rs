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
//! to be believed — see [`crate::neighbour::NeighbourCache::learn`],
//! where the cache this module used to own now lives, generalised over
//! both families.

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

#[cfg(test)]
mod tests {
    use super::*;

    const SENDER: MacAddr = MacAddr([0x52, 0x54, 0x00, 0x11, 0x22, 0x33]);

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
}
