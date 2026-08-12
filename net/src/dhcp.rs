// SPDX-License-Identifier: Apache-2.0
//! DHCP, enough of it to be given an address.
//!
//! [RFC 0018](../../docs/rfc/0018-networking.md) step 6, and the answer to its
//! own first unresolved question. That question asks *what owns the interface's
//! address*, and says DHCP "is a client holding a socket, which would be the
//! more capability-shaped answer". This is the parser that answer needs; the
//! client is a program holding a socket, and the kernel does not participate.
//!
//! # What is deliberately not here
//!
//! No lease timer, no state machine, no `REQUEST`, no `ACK`, no renewal, no
//! rebinding. A `DISCOVER` and the `OFFER` that answers it settle the question
//! "can a program holding a socket obtain an address", and everything else is a
//! protocol this system has no use for until something depends on keeping an
//! address rather than learning one.
//!
//! Stated rather than left to be discovered, so that adding a lease is a
//! decision somebody makes.
//!
//! # The magic cookie is from memory, and the wire checks it
//!
//! [`MAGIC`] identifies the options area. There is no copy of RFC 2131 on the
//! machine this was written on and no header that defines it, so the number
//! comes from recall — which this project treats as a claim rather than a fact.
//!
//! It is **checked by the exchange working**: a server that does not recognise
//! the cookie does not answer, so an offer arriving is the constant being
//! right, and no offer arriving is the first thing to suspect. The same
//! standard the virtio header size was held to, and for the same reason.

use crate::{NetError, addr::Ipv4Addr, addr::MacAddr, be32};

/// Bytes of fixed fields before the options area.
///
/// The BOOTP header this protocol is built on: an operation, hardware type and
/// length, hops, a transaction identifier, seconds and flags, four addresses,
/// sixteen bytes of client hardware address, and two long unused name fields.
pub const FIXED: usize = 236;

/// Bytes of the smallest message worth looking at: the fixed part and a cookie.
pub const MINIMUM: usize = FIXED + 4;

/// What says the options area is an options area. See the module header.
pub const MAGIC: u32 = 0x6382_5363;

/// A request from a client.
const BOOTREQUEST: u8 = 1;
/// A reply from a server.
const BOOTREPLY: u8 = 2;

/// Option code: what kind of DHCP message this is.
const OPTION_MESSAGE_TYPE: u8 = 53;
/// Option code: the end of the options.
const OPTION_END: u8 = 255;
/// Option code: padding, which carries no length byte.
const OPTION_PAD: u8 = 0;

/// Message type: "does anyone have an address for me".
pub const DISCOVER: u8 = 1;
/// Message type: "here is one".
pub const OFFER: u8 = 2;

/// What a server offered.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Offer {
    /// The address being offered.
    pub address: Ipv4Addr,
    /// The server that offered it.
    pub server: Ipv4Addr,
    /// The transaction this answers, which a client must check against its own.
    pub transaction: u32,
}

/// Parses a server's reply, if it is an offer.
///
/// # Errors
///
/// - [`NetError::Truncated`] if the message is shorter than [`MINIMUM`].
/// - [`NetError::Unsupported`] if it is not a reply, or not an offer, or the
///   options area is not marked by [`MAGIC`].
///
/// # What is checked, and why each
///
/// The operation must be a *reply*: a client that accepted a request would
/// accept its own broadcast back. The cookie must be present, or the bytes
/// after the fixed part are not options and walking them is walking whatever
/// happens to be there. And the message type must be an offer, because a
/// server has several things it can say and only one of them is an address.
pub fn parse_offer(bytes: &[u8]) -> Result<Offer, NetError> {
    let fixed = bytes.get(..MINIMUM).ok_or(NetError::Truncated {
        need: MINIMUM,
        have: bytes.len(),
    })?;

    if fixed[0] != BOOTREPLY {
        return Err(NetError::Unsupported {
            field: "dhcp operation",
            value: u32::from(fixed[0]),
        });
    }
    let cookie = be32(fixed, FIXED).unwrap_or(0);
    if cookie != MAGIC {
        return Err(NetError::Unsupported {
            field: "dhcp magic cookie",
            value: cookie,
        });
    }

    // The options, walked with every length checked before it is used. A option
    // whose length reaches past the message is where a walker runs off the end,
    // and it is the reason this returns rather than clamping.
    let mut at = MINIMUM;
    let mut kind = None;
    while at < bytes.len() {
        let code = bytes[at];
        if code == OPTION_END {
            break;
        }
        if code == OPTION_PAD {
            // Padding carries no length byte. Treating it as though it did
            // reads the *next* option's code as a length.
            at += 1;
            continue;
        }
        let Some(&length) = bytes.get(at + 1) else {
            break;
        };
        let value = at + 2;
        let end = value
            .checked_add(usize::from(length))
            .ok_or(NetError::LengthBeyondBuffer {
                stated: usize::from(length),
                have: bytes.len(),
            })?;
        if end > bytes.len() {
            return Err(NetError::LengthBeyondBuffer {
                stated: end,
                have: bytes.len(),
            });
        }
        if code == OPTION_MESSAGE_TYPE && length == 1 {
            kind = Some(bytes[value]);
        }
        at = end;
    }

    if kind != Some(OFFER) {
        return Err(NetError::Unsupported {
            field: "dhcp message type",
            value: u32::from(kind.unwrap_or(0)),
        });
    }

    Ok(Offer {
        // `yiaddr` -- "your address", the whole point of the exchange.
        address: Ipv4Addr(be32(fixed, 16).unwrap_or(0)),
        server: Ipv4Addr(be32(fixed, 20).unwrap_or(0)),
        transaction: be32(fixed, 4).unwrap_or(0),
    })
}

/// Writes a `DISCOVER` into `out`, returning how many bytes.
///
/// # Errors
///
/// [`NetError::Truncated`] if `out` cannot hold the message.
pub fn write_discover(
    out: &mut [u8],
    hardware: MacAddr,
    transaction: u32,
) -> Result<usize, NetError> {
    // Fixed part, cookie, one option and the end marker.
    const TOTAL: usize = MINIMUM + 4;
    let available = out.len();
    let message = out.get_mut(..TOTAL).ok_or(NetError::Truncated {
        need: TOTAL,
        have: available,
    })?;
    message.fill(0);

    message[0] = BOOTREQUEST;
    message[1] = 1; // Ethernet
    message[2] = 6; // six bytes of it
    message[4..8].copy_from_slice(&transaction.to_be_bytes());
    // Broadcast, because a client with no address cannot be answered by
    // unicast: the reply would be addressed to an address it does not have yet.
    message[10..12].copy_from_slice(&0x8000u16.to_be_bytes());
    message[28..34].copy_from_slice(&hardware.octets());
    message[FIXED..MINIMUM].copy_from_slice(&MAGIC.to_be_bytes());
    message[MINIMUM] = OPTION_MESSAGE_TYPE;
    message[MINIMUM + 1] = 1;
    message[MINIMUM + 2] = DISCOVER;
    message[MINIMUM + 3] = OPTION_END;
    Ok(TOTAL)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAC: MacAddr = MacAddr([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);

    /// A reply carrying `kind`, offering `address`.
    fn reply(kind: u8, address: Ipv4Addr) -> ([u8; 320], usize) {
        let mut out = [0u8; 320];
        out[0] = BOOTREPLY;
        out[4..8].copy_from_slice(&0xdead_beefu32.to_be_bytes());
        out[16..20].copy_from_slice(&address.octets());
        out[20..24].copy_from_slice(&Ipv4Addr::new(10, 0, 2, 2).octets());
        out[FIXED..MINIMUM].copy_from_slice(&MAGIC.to_be_bytes());
        out[MINIMUM] = OPTION_MESSAGE_TYPE;
        out[MINIMUM + 1] = 1;
        out[MINIMUM + 2] = kind;
        out[MINIMUM + 3] = OPTION_END;
        (out, MINIMUM + 4)
    }

    #[test]
    fn an_offer_yields_the_address_it_offers() {
        let (bytes, length) = reply(OFFER, Ipv4Addr::new(10, 0, 2, 15));
        let offer = parse_offer(&bytes[..length]).unwrap();
        assert_eq!(offer.address, Ipv4Addr::new(10, 0, 2, 15));
        assert_eq!(offer.server, Ipv4Addr::new(10, 0, 2, 2));
        assert_eq!(offer.transaction, 0xdead_beef);
    }

    #[test]
    fn a_request_is_not_a_reply() {
        // A client that accepted a request would accept its own broadcast back.
        let (mut bytes, length) = reply(OFFER, Ipv4Addr::new(10, 0, 2, 15));
        bytes[0] = BOOTREQUEST;
        assert!(matches!(
            parse_offer(&bytes[..length]),
            Err(NetError::Unsupported {
                field: "dhcp operation",
                ..
            })
        ));
    }

    #[test]
    fn a_reply_that_is_not_an_offer_is_refused() {
        let (bytes, length) = reply(5, Ipv4Addr::new(10, 0, 2, 15));
        assert!(matches!(
            parse_offer(&bytes[..length]),
            Err(NetError::Unsupported {
                field: "dhcp message type",
                ..
            })
        ));
    }

    #[test]
    fn a_missing_cookie_means_the_options_are_not_options() {
        let (mut bytes, length) = reply(OFFER, Ipv4Addr::new(10, 0, 2, 15));
        bytes[FIXED] ^= 0xff;
        assert!(matches!(
            parse_offer(&bytes[..length]),
            Err(NetError::Unsupported {
                field: "dhcp magic cookie",
                ..
            })
        ));
    }

    #[test]
    fn an_option_reaching_past_the_message_is_refused() {
        // The walker's own boundary, and the one that would run off the end.
        let (mut bytes, length) = reply(OFFER, Ipv4Addr::new(10, 0, 2, 15));
        bytes[MINIMUM] = 12; // some other option
        bytes[MINIMUM + 1] = 200; // longer than what remains
        assert!(matches!(
            parse_offer(&bytes[..length]),
            Err(NetError::LengthBeyondBuffer { .. })
        ));
    }

    #[test]
    fn padding_carries_no_length_byte() {
        // Treating a pad as though it had a length reads the *next* option's
        // code as one, which is how a walker loses its place.
        let mut out = [0u8; 320];
        out[0] = BOOTREPLY;
        out[16..20].copy_from_slice(&Ipv4Addr::new(10, 0, 2, 15).octets());
        out[FIXED..MINIMUM].copy_from_slice(&MAGIC.to_be_bytes());
        out[MINIMUM] = OPTION_PAD;
        out[MINIMUM + 1] = OPTION_PAD;
        out[MINIMUM + 2] = OPTION_MESSAGE_TYPE;
        out[MINIMUM + 3] = 1;
        out[MINIMUM + 4] = OFFER;
        out[MINIMUM + 5] = OPTION_END;
        let offer = parse_offer(&out[..MINIMUM + 6]).unwrap();
        assert_eq!(offer.address, Ipv4Addr::new(10, 0, 2, 15));
    }

    #[test]
    fn a_short_message_is_truncated_not_parsed() {
        let (bytes, _) = reply(OFFER, Ipv4Addr::new(10, 0, 2, 15));
        assert_eq!(
            parse_offer(&bytes[..MINIMUM - 1]),
            Err(NetError::Truncated {
                need: MINIMUM,
                have: MINIMUM - 1
            })
        );
    }

    #[test]
    fn a_discover_is_a_request_this_parser_refuses_to_read_as_a_reply() {
        let mut out = [0u8; 320];
        let length = write_discover(&mut out, MAC, 0x1234_5678).unwrap();
        assert_eq!(&out[28..34], &MAC.octets());
        assert_eq!(be32(&out, 4), Some(0x1234_5678));
        // Its own writer's output must not parse as an offer: it is a request,
        // and the operation check is what says so.
        assert!(parse_offer(&out[..length]).is_err());
    }

    #[test]
    fn writing_into_too_little_room_is_refused() {
        let mut small = [0u8; MINIMUM];
        assert!(write_discover(&mut small, MAC, 0).is_err());
    }
}
