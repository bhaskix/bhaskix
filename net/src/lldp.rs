// SPDX-License-Identifier: Apache-2.0
//! What a neighbour says about itself, as an inventory rather than a reading.
//!
//! **The switch has been describing itself on every boot and nothing read it.**
//! `bin/ipd` refuses these frames — `last refusal reason 2, on a frame of 171
//! bytes with ethertype 0x88cc` — and RFC 0076 spent a week asking what the
//! switch thinks of a port-channel that this host has no login to.
//!
//! # What is decoded, and what deliberately is not
//!
//! Only what the C620 datasheet grounds. Table 38-171 gives the TLV header as
//! **seven bits of type and nine bits of length**, followed by 0 to 511 octets;
//! Table 38-172 gives an organizationally specific TLV as that header plus a
//! three-octet OUI and a one-octet subtype. §38.29.4.2 names the mandatory
//! four: **0** end of LLDPDU with zero length, **1** chassis id (subtype 4 is a
//! MAC address), **2** port id (subtype 3 is a MAC address), **3** time to live.
//!
//! Everything else is left as an **inventory**: which types appeared, and which
//! OUI and subtype each organizationally specific TLV carried. In particular
//! there is a Link Aggregation TLV in IEEE 802.1AB that would answer RFC 0076's
//! question outright, and this parser does not pretend to know its number —
//! Table 38-173 lists only DCBx for that OUI, so the number is not grounded by
//! anything in this project. The inventory says what the switch *sends*; what to
//! decode next is then a decision made from evidence rather than from memory.

/// A TLV's type, as the seven bits Table 38-171 gives it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Inventory {
    /// One bit per TLV type 0 to 31, set where that type appeared.
    pub types: u32,
    /// How many TLVs were walked, whether or not their type is known.
    pub count: u16,
    /// Whether the walk ended cleanly: an end-of-LLDPDU TLV, or exactly
    /// consuming the frame. A frame that ran out mid-TLV sets this false, and
    /// nothing else in here should be believed when it is.
    pub whole: bool,
    /// The chassis id's subtype and its first six octets, from type 1.
    pub chassis: Option<(u8, [u8; 6])>,
    /// The port id's subtype and its first six octets, from type 2.
    pub port: Option<(u8, [u8; 6])>,
    /// Time to live, from type 3.
    pub ttl: Option<u16>,
    /// The first organizationally specific TLV's OUI and subtype, from type
    /// 127 -- the pair Table 38-172 puts at the front of its value.
    pub organisation: Option<([u8; 3], u8)>,
    /// How many organizationally specific TLVs there were.
    pub organisations: u16,
    /// The neighbour's management address, if it sent one.
    pub management: Option<ManagementAddress>,
    /// Its system name, truncated to what a report word carries.
    pub name: [u8; NAME_BYTES],
    /// How many of those bytes are real.
    pub name_length: u8,
}

/// Bytes of a neighbour's system name this keeps.
///
/// Eight, because that is a report word and a switch's hostname is identifying
/// well before it is complete.
pub const NAME_BYTES: usize = 8;

/// A neighbour's management address -- §38.29.4.2's TLV type eight.
///
/// The string is a length, an IANA address family, and the address itself:
/// family `1` is IPv4 and `2` is IPv6. What follows -- the interface numbering
/// subtype, the interface number and an object identifier -- says how to reach
/// the agent within the device and is not what is wanted here.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ManagementAddress {
    /// IANA address family: 1 IPv4, 2 IPv6.
    pub family: u8,
    /// The address octets, as many as `length` says.
    pub address: [u8; 16],
    /// How many octets the address has.
    pub length: u8,
}

impl ManagementAddress {
    /// The address as an IPv4 quad, when that is what it is.
    #[must_use]
    pub const fn ipv4(&self) -> Option<[u8; 4]> {
        if self.family == 1 && self.length == 4 {
            Some([
                self.address[0],
                self.address[1],
                self.address[2],
                self.address[3],
            ])
        } else {
            None
        }
    }

    /// Family, length and the first four octets, for a report word.
    #[must_use]
    pub const fn packed(&self) -> u64 {
        (self.family as u64)
            | (self.length as u64) << 8
            | (self.address[0] as u64) << 16
            | (self.address[1] as u64) << 24
            | (self.address[2] as u64) << 32
            | (self.address[3] as u64) << 40
    }
}

/// The type of an end-of-LLDPDU TLV -- §38.29.4.2, *"uses TLV type value
/// zero... sets the TLV information string length to zero"*.
pub const END: u8 = 0;
/// Chassis id -- *"TLV type value of one"*.
pub const CHASSIS_ID: u8 = 1;
/// Port id -- *"TLV type value of two"*.
pub const PORT_ID: u8 = 2;
/// Time to live -- *"TLV type value three"*.
pub const TIME_TO_LIVE: u8 = 3;
/// System name -- *"TLV type value of five"*, the neighbour's own name for
/// itself.
pub const SYSTEM_NAME: u8 = 5;
/// Management address -- *"TLV type value of eight"*.
///
/// **The switch has been announcing where to reach it since the first boot.**
/// This walker counted nine TLVs on every frame and decoded four; types four to
/// eight were passed over, and one of them is the neighbour's management
/// address. A machine that cannot read a switch's configuration and a switch
/// that says on every frame where its configuration lives is a gap worth
/// closing before guessing again.
pub const MANAGEMENT_ADDRESS: u8 = 8;
/// Organizationally specific -- *"TLV type value of 127"*.
pub const ORGANISATION: u8 = 127;

/// The EtherType an LLDPDU arrives under.
pub const ETHERTYPE: u16 = 0x88cc;

impl Inventory {
    /// Whether a type appeared, for types below 32.
    #[must_use]
    pub const fn saw(&self, tlv: u8) -> bool {
        tlv < 32 && self.types >> tlv & 1 != 0
    }
}

/// Walks an LLDPDU's TLVs. `body` is the frame's payload, after the Ethernet
/// header.
///
/// Never fails: a malformed frame yields whatever was walked before it went
/// wrong, with [`Inventory::whole`] clear. A neighbour's frame is hostile input
/// and a parser that refuses it wholesale tells the reader less than one that
/// says how far it got.
#[must_use]
pub fn inventory(body: &[u8]) -> Inventory {
    let mut seen = Inventory::default();
    let mut at = 0usize;
    loop {
        // Table 38-171: seven bits of type, nine of length, big-endian across
        // the two octets.
        let Some(header) = body.get(at..at + 2) else {
            // Exactly consumed is whole; short of a header is not.
            seen.whole = at == body.len();
            return seen;
        };
        let header = u16::from_be_bytes([header[0], header[1]]);
        let tlv = (header >> 9) as u8;
        let length = (header & 0x1ff) as usize;
        at += 2;
        let Some(value) = body.get(at..at + length) else {
            return seen;
        };
        at += length;
        seen.count = seen.count.saturating_add(1);
        if tlv < 32 {
            seen.types |= 1 << tlv;
        }
        match tlv {
            END => {
                seen.whole = true;
                return seen;
            }
            CHASSIS_ID => seen.chassis = identifier(value),
            PORT_ID => seen.port = identifier(value),
            TIME_TO_LIVE => {
                if let Some(pair) = value.get(..2) {
                    seen.ttl = Some(u16::from_be_bytes([pair[0], pair[1]]));
                }
            }
            SYSTEM_NAME => {
                let taken = value.len().min(NAME_BYTES);
                seen.name[..taken].copy_from_slice(&value[..taken]);
                seen.name_length = taken as u8;
            }
            MANAGEMENT_ADDRESS => {
                // Byte 0 is the string length, which counts the family octet
                // with the address -- so an address of `length - 1` follows the
                // family at byte 1. A length that does not fit the TLV is a
                // malformed frame and is left alone rather than clamped into
                // something that reads like an address.
                if let Some(&string) = value.first()
                    && string >= 2
                    && let Some(&family) = value.get(1)
                    && let Some(octets) = value.get(2..1 + string as usize)
                    && octets.len() <= 16
                {
                    let mut address = [0u8; 16];
                    address[..octets.len()].copy_from_slice(octets);
                    seen.management = Some(ManagementAddress {
                        family,
                        address,
                        length: octets.len() as u8,
                    });
                }
            }
            ORGANISATION => {
                seen.organisations = seen.organisations.saturating_add(1);
                // Table 38-172: three octets of OUI then one of subtype.
                if seen.organisation.is_none()
                    && let Some(head) = value.get(..4)
                {
                    seen.organisation = Some(([head[0], head[1], head[2]], head[3]));
                }
            }
            _ => {}
        }
    }
}

/// A chassis or port id: a subtype octet then the id. Only the first six octets
/// are kept, which is the whole of it when the subtype is a MAC address --
/// subtype 4 for a chassis and 3 for a port, per §38.29.4.2.
fn identifier(value: &[u8]) -> Option<(u8, [u8; 6])> {
    let (subtype, rest) = value.split_first()?;
    let mut id = [0u8; 6];
    for (slot, byte) in id.iter_mut().zip(rest.iter()) {
        *slot = *byte;
    }
    Some((*subtype, id))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds TLVs into a fixed buffer, the way Table 38-171 describes them:
    /// seven bits of type, nine of length, then the value.
    struct Pdu {
        bytes: [u8; 256],
        used: usize,
    }

    impl Pdu {
        fn new() -> Self {
            Self {
                bytes: [0; 256],
                used: 0,
            }
        }

        fn tlv(&mut self, kind: u8, value: &[u8]) -> &mut Self {
            let header = (u16::from(kind) << 9) | (value.len() as u16 & 0x1ff);
            self.bytes[self.used..self.used + 2].copy_from_slice(&header.to_be_bytes());
            self.used += 2;
            self.bytes[self.used..self.used + value.len()].copy_from_slice(value);
            self.used += value.len();
            self
        }

        fn raw(&mut self, bytes: &[u8]) -> &mut Self {
            self.bytes[self.used..self.used + bytes.len()].copy_from_slice(bytes);
            self.used += bytes.len();
            self
        }

        fn body(&self) -> &[u8] {
            &self.bytes[..self.used]
        }
    }

    /// A neighbour's LLDPDU is walked into an inventory of what it sent.
    ///
    /// **Seven bits of type and nine of length**, which is the part worth
    /// pinning: reading it as a byte and a byte -- the obvious mistake -- puts
    /// every type at half its value and every length off by the type's low bit,
    /// and the walk then wanders through the frame finding plausible rubbish.
    #[test]
    fn an_lldpdu_is_walked_into_an_inventory_of_what_the_neighbour_sent() {
        let mut pdu = Pdu::new();
        pdu.tlv(CHASSIS_ID, &[4, 0x08, 0xbd, 0x43, 0x76, 0x47, 0xe3])
            .tlv(PORT_ID, &[3, 0x08, 0xbd, 0x43, 0x76, 0x47, 0xf0])
            .tlv(TIME_TO_LIVE, &120u16.to_be_bytes())
            .tlv(ORGANISATION, &[0x00, 0x80, 0xc2, 0x09, 0xaa])
            .tlv(ORGANISATION, &[0x00, 0x12, 0x0f, 0x03, 0x01, 0, 0, 0, 5])
            .tlv(END, &[]);

        let seen = inventory(pdu.body());
        assert!(seen.whole, "the walk reached the end-of-LLDPDU TLV");
        assert_eq!(seen.count, 6);
        assert!(seen.saw(CHASSIS_ID) && seen.saw(PORT_ID) && seen.saw(TIME_TO_LIVE));
        assert!(!seen.saw(5), "the switch sent no system name here");
        assert_eq!(
            seen.chassis,
            Some((4, [0x08, 0xbd, 0x43, 0x76, 0x47, 0xe3]))
        );
        assert_eq!(seen.port, Some((3, [0x08, 0xbd, 0x43, 0x76, 0x47, 0xf0])));
        assert_eq!(seen.ttl, Some(120));
        assert_eq!(seen.organisations, 2, "both counted");
        assert_eq!(
            seen.organisation,
            Some(([0x00, 0x80, 0xc2], 0x09)),
            "and the first one's OUI and subtype are kept"
        );
        // Type 127 is past the bitmap, which holds 0..31 -- so the count is how
        // a reader knows they were there.
        assert!(!seen.saw(ORGANISATION));
    }

    /// The management address and system name decode at §38.29.4.2's TLVs.
    ///
    /// **This is where the switch says where to reach it.** The walker counted
    /// nine TLVs on every frame the SR550's switch sent and decoded four; types
    /// four to eight went past unread, and one of them is the address of the
    /// one machine whose configuration this work cannot otherwise see.
    ///
    /// The string length counts the family octet with the address, which is the
    /// detail that makes an off-by-one here read as a different address rather
    /// than as an error.
    #[test]
    fn a_neighbour_says_where_to_reach_it() {
        // Type 8: string length 5, family 1 (IPv4), 10.5.5.7, then the
        // interface numbering subtype, interface number and an empty OID --
        // all of which follow the address and none of which is wanted.
        let mut pdu = Pdu::new();
        pdu.tlv(CHASSIS_ID, &[4, 0x08, 0xbd, 0x43, 0x76, 0x47, 0xe3])
            .tlv(PORT_ID, &[3, 0x08, 0xbd, 0x43, 0x76, 0x47, 0xf0])
            .tlv(TIME_TO_LIVE, &[0, 120])
            .tlv(SYSTEM_NAME, b"switch-a-very-long-name")
            .tlv(MANAGEMENT_ADDRESS, &[5, 1, 10, 5, 5, 7, 2, 0, 0, 0, 9, 0])
            .tlv(END, &[]);
        let seen = inventory(pdu.body());

        let address = seen.management.expect("a management address was sent");
        assert_eq!(address.family, 1, "IANA family 1 is IPv4");
        assert_eq!(address.length, 4, "string length 5 is family plus four");
        assert_eq!(address.ipv4(), Some([10, 5, 5, 7]));
        assert_eq!(
            address.packed() & 0xff,
            1,
            "and it survives a report word, family first"
        );
        assert_eq!(address.packed() >> 16 & 0xff, 10);
        assert_eq!(address.packed() >> 40 & 0xff, 7);

        // The name is kept to what a word carries, and truncated rather than
        // dropped.
        assert_eq!(seen.name_length as usize, NAME_BYTES);
        assert_eq!(&seen.name[..], b"switch-a");

        // An IPv6 address is carried whole, and is not an IPv4 quad.
        let mut six_pdu = Pdu::new();
        six_pdu.tlv(TIME_TO_LIVE, &[0, 120]).tlv(
            MANAGEMENT_ADDRESS,
            &[
                17, 2, 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 0,
            ],
        );
        let six = inventory(six_pdu.body())
            .management
            .expect("an IPv6 address is still an address");
        assert_eq!(six.family, 2);
        assert_eq!(six.length, 16);
        assert_eq!(six.ipv4(), None, "and is not read as a quad");
        assert_eq!(six.address[0], 0xfe);
        assert_eq!(six.address[15], 1);

        // **A length that does not fit is left alone**, not clamped into
        // something that reads like an address.
        let mut short_pdu = Pdu::new();
        short_pdu
            .tlv(TIME_TO_LIVE, &[0, 120])
            .tlv(MANAGEMENT_ADDRESS, &[9, 1, 10, 5]);
        let short = inventory(short_pdu.body());
        assert_eq!(short.management, None, "a string longer than its TLV");
        assert!(
            short.saw(MANAGEMENT_ADDRESS),
            "though the type is still counted as having appeared"
        );

        // A neighbour that sends neither says so by absence.
        let mut bare_pdu = Pdu::new();
        bare_pdu.tlv(TIME_TO_LIVE, &[0, 120]);
        let bare = inventory(bare_pdu.body());
        assert_eq!(bare.management, None);
        assert_eq!(bare.name_length, 0);
    }

    /// A frame that stops mid-TLV says how far it got and marks itself partial.
    ///
    /// This is a neighbour's frame, which is hostile input: a parser that
    /// refuses it wholesale tells the reader less than one that says where it
    /// stopped, and a parser that reads past the end is the actual danger.
    #[test]
    fn a_truncated_lldpdu_is_partial_rather_than_refused_or_overrun() {
        let mut pdu = Pdu::new();
        pdu.tlv(CHASSIS_ID, &[4, 0x08, 0xbd, 0x43, 0x76, 0x47, 0xe3])
            // A header claiming forty octets with none behind it.
            .raw(&((u16::from(PORT_ID) << 9) | 40).to_be_bytes());

        let seen = inventory(pdu.body());
        assert!(!seen.whole, "it did not end cleanly");
        assert_eq!(
            seen.count, 1,
            "the chassis id was walked and the port id was not"
        );
        assert!(seen.chassis.is_some());
        assert_eq!(seen.port, None);

        // And an empty frame is partial rather than a panic.
        assert_eq!(inventory(&[]).count, 0);
        assert!(inventory(&[]).whole, "nothing to walk is exactly consumed");
        // A lone header byte with no second is not.
        assert!(!inventory(&[0x02]).whole);
    }
}
