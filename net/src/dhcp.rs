// SPDX-License-Identifier: Apache-2.0
//! DHCP, enough of it to be given an address.
//!
//! [RFC 0018](../../docs/rfc/0018-networking.md) step 6, and the answer to its
//! own first unresolved question. That question asks *what owns the interface's
//! address*, and says DHCP "is a client holding a socket, which would be the
//! more capability-shaped answer". This is the parser that answer needs; the
//! client is a program holding a socket, and the kernel does not participate.
//!
//! # What is here, and what is still not
//!
//! `DISCOVER`, `OFFER`, `REQUEST` and `ACK` -- the four messages that end with
//! an address a client may actually use. **The `REQUEST` and `ACK` halves were
//! added on 2026-09-07**, when the SR550's X722 began receiving and the machine
//! could be given a real address on a real network; until then an `OFFER` was
//! as far as anything could be proven and the rest would have been code nobody
//! could exercise.
//!
//! The distinction the two halves draw is not ceremony. **An offer is not an
//! address.** A server may offer to several clients at once and commits to none
//! of them until it acknowledges a request; a client that used the offered
//! address would be using one the server is free to give away.
//!
//! No lease timer, no renewal, no rebinding, no `DECLINE` and no `RELEASE`. A
//! lease has a duration and this records it without acting on it, which is a
//! gap worth naming rather than discovering: an address obtained here is held
//! until the machine stops, and on a network whose leases are shorter than an
//! uptime that will one day be wrong.
//!
//! # The option codes are from memory, and the wire checks them
//!
//! As with [`MAGIC`], and for the reason its paragraph gives. A server that
//! could not read the message type, the server identifier or the requested
//! address in a `REQUEST` would not acknowledge it -- so an `ACK` arriving is
//! these numbers being right, and a `NAK` or silence is the first thing to
//! suspect.
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
/// Message type: "I will take the one you offered".
pub const REQUEST: u8 = 3;
/// Message type: "it is yours".
pub const ACK: u8 = 5;
/// Message type: "no, it is not".
pub const NAK: u8 = 6;

/// Option code: the address a client is asking to be given.
const OPTION_REQUESTED_ADDRESS: u8 = 50;
/// Option code: how long the lease lasts, in seconds.
const OPTION_LEASE_SECONDS: u8 = 51;
/// Option code: which server is being answered.
///
/// **A `REQUEST` carries this and a `DISCOVER` does not**, and that is the
/// difference between the two: a discover asks everybody, a request names the
/// one server whose offer is being taken so the others can withdraw theirs.
const OPTION_SERVER: u8 = 54;
/// Option code: the subnet mask.
const OPTION_SUBNET: u8 = 1;
/// Option code: the default gateway.
const OPTION_ROUTER: u8 = 3;

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
    let lease = parse_reply(bytes, OFFER)?;
    Ok(Offer {
        address: lease.address,
        server: lease.server,
        transaction: lease.transaction,
    })
}

/// An address a server has committed to, and what it said about the network.
///
/// **What an [`Offer`] becomes once the server acknowledges the request for
/// it.** The distinction is the protocol's, not this crate's: until the `ACK`
/// the address is one the server may still give to somebody else.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Lease {
    /// The address, from `yiaddr`.
    pub address: Ipv4Addr,
    /// The server that committed to it.
    pub server: Ipv4Addr,
    /// The transaction it answers.
    pub transaction: u32,
    /// The subnet mask, or all zeroes if the server did not say.
    pub subnet: Ipv4Addr,
    /// The default gateway, or all zeroes if the server did not say.
    pub router: Ipv4Addr,
    /// How long the lease lasts, in seconds, or zero if the server did not say.
    ///
    /// **Recorded and not acted on.** See the module header: nothing here
    /// renews, so an address is held until the machine stops.
    pub seconds: u32,
}

impl Lease {
    /// Nothing learned yet: every address unspecified and no lease.
    ///
    /// By hand rather than derived, because `Ipv4Addr` has no `Default` -- and
    /// deliberately so, since "the default address" is not a thing an address
    /// type should have an opinion about.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            address: Ipv4Addr::UNSPECIFIED,
            server: Ipv4Addr::UNSPECIFIED,
            transaction: 0,
            subnet: Ipv4Addr::UNSPECIFIED,
            router: Ipv4Addr::UNSPECIFIED,
            seconds: 0,
        }
    }
}

/// Walks the options once, collecting what both replies carry.
///
/// Every length is checked before it is used, for the reason [`parse_offer`]
/// gives: an option whose length reaches past the message is where a walker
/// runs off the end.
fn walk(bytes: &[u8]) -> Result<(Option<u8>, Lease), NetError> {
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

    let mut found = Lease {
        // `yiaddr` -- "your address", the whole point of the exchange.
        address: Ipv4Addr(be32(fixed, 16).unwrap_or(0)),
        server: Ipv4Addr(be32(fixed, 20).unwrap_or(0)),
        transaction: be32(fixed, 4).unwrap_or(0),
        ..Lease::empty()
    };
    let mut kind = None;
    let mut at = MINIMUM;
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
        match (code, length) {
            (OPTION_MESSAGE_TYPE, 1) => kind = Some(bytes[value]),
            (OPTION_SUBNET, 4) => found.subnet = Ipv4Addr(be32(bytes, value).unwrap_or(0)),
            // A router option may list several; the first is the default.
            (OPTION_ROUTER, 4..) => found.router = Ipv4Addr(be32(bytes, value).unwrap_or(0)),
            (OPTION_LEASE_SECONDS, 4) => found.seconds = be32(bytes, value).unwrap_or(0),
            // **The server identifier wins over `siaddr`.** They are often the
            // same and need not be: a relayed reply carries the relay in the
            // fixed field and the server that actually decided in this option,
            // and a `REQUEST` addressed to the wrong one is a request no server
            // answers.
            (OPTION_SERVER, 4) => found.server = Ipv4Addr(be32(bytes, value).unwrap_or(0)),
            _ => {}
        }
        at = end;
    }
    Ok((kind, found))
}

/// Parses a reply of the message type `want`, returning everything in it.
///
/// The primitive [`parse_offer`] and [`parse_ack`] are written in terms of:
/// both walk the same options and differ only in which message type they will
/// take. A caller running the whole exchange wants one function and the type as
/// a value.
///
/// # Errors
///
/// - [`NetError::Truncated`] if the message is shorter than [`MINIMUM`].
/// - [`NetError::Unsupported`] if it is not a reply, or the options area is not
///   marked by [`MAGIC`], or the message type is not `want` -- and in that last
///   case the value carried is the type that *was* there, so a caller can tell
///   a `NAK` from a message it does not take.
/// - [`NetError::LengthBeyondBuffer`] if an option's length reaches past the
///   message.
pub fn parse_reply(bytes: &[u8], want: u8) -> Result<Lease, NetError> {
    let (kind, lease) = walk(bytes)?;
    if kind != Some(want) {
        return Err(NetError::Unsupported {
            field: "dhcp message type",
            value: u32::from(kind.unwrap_or(0)),
        });
    }
    Ok(lease)
}

/// Parses a server's acknowledgement, if it is one.
///
/// # Errors
///
/// As [`parse_offer`], and [`NetError::Unsupported`] on the message type when
/// the reply is a `NAK` -- which is a server refusing, and a different thing
/// from a message this parser does not take. The value carried is the message
/// type, so a caller can tell `NAK` from silence.
pub fn parse_ack(bytes: &[u8]) -> Result<Lease, NetError> {
    parse_reply(bytes, ACK)
}

/// Writes a `REQUEST` into `out`, returning how many bytes.
///
/// `offered` is the address from the [`Offer`] and `server` the server that
/// made it. Both are carried as options rather than in the fixed fields:
/// `ciaddr` is for a client that already holds the address, which one that has
/// only been offered it does not.
///
/// # Errors
///
/// [`NetError::Truncated`] if `out` cannot hold the message.
pub fn write_request(
    out: &mut [u8],
    hardware: MacAddr,
    transaction: u32,
    offered: Ipv4Addr,
    server: Ipv4Addr,
) -> Result<usize, NetError> {
    // Fixed part, cookie, the message type, the requested address, the server
    // identifier, and the end marker.
    const TOTAL: usize = MINIMUM + 3 + 6 + 6 + 1;
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
    // **Broadcast, still.** The client does not hold the address yet, so a
    // unicast reply would be addressed to somewhere it cannot receive.
    message[10..12].copy_from_slice(&0x8000u16.to_be_bytes());
    message[28..34].copy_from_slice(&hardware.octets());
    message[FIXED..MINIMUM].copy_from_slice(&MAGIC.to_be_bytes());

    let mut at = MINIMUM;
    message[at] = OPTION_MESSAGE_TYPE;
    message[at + 1] = 1;
    message[at + 2] = REQUEST;
    at += 3;
    message[at] = OPTION_REQUESTED_ADDRESS;
    message[at + 1] = 4;
    message[at + 2..at + 6].copy_from_slice(&offered.octets());
    at += 6;
    message[at] = OPTION_SERVER;
    message[at + 1] = 4;
    message[at + 2..at + 6].copy_from_slice(&server.octets());
    at += 6;
    message[at] = OPTION_END;
    Ok(TOTAL)
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

    /// A reply carrying `kind` plus the options a server sends with an `ACK`.
    fn acknowledged(kind: u8, address: Ipv4Addr) -> ([u8; 320], usize) {
        let mut out = [0u8; 320];
        out[0] = BOOTREPLY;
        out[4..8].copy_from_slice(&0xdead_beefu32.to_be_bytes());
        out[16..20].copy_from_slice(&address.octets());
        // `siaddr` says one thing and the server identifier option another, so
        // a test that reads the wrong one is a test that fails.
        out[20..24].copy_from_slice(&Ipv4Addr::new(10, 0, 2, 99).octets());
        out[FIXED..MINIMUM].copy_from_slice(&MAGIC.to_be_bytes());
        let mut at = MINIMUM;
        for option in [
            &[OPTION_MESSAGE_TYPE, 1, kind][..],
            &[OPTION_SUBNET, 4, 255, 255, 255, 0][..],
            &[OPTION_ROUTER, 4, 10, 0, 2, 2][..],
            &[OPTION_LEASE_SECONDS, 4, 0, 0, 0x0e, 0x10][..],
            &[OPTION_SERVER, 4, 10, 0, 2, 2][..],
        ] {
            out[at..at + option.len()].copy_from_slice(option);
            at += option.len();
        }
        out[at] = OPTION_END;
        (out, at + 1)
    }

    /// An acknowledgement is the address plus what the server said about the
    /// network it is on.
    #[test]
    fn an_ack_yields_the_lease_and_everything_beside_it() {
        let (bytes, length) = acknowledged(ACK, Ipv4Addr::new(10, 0, 2, 15));
        let lease = parse_ack(&bytes[..length]).unwrap();
        assert_eq!(lease.address, Ipv4Addr::new(10, 0, 2, 15));
        assert_eq!(lease.subnet, Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(lease.router, Ipv4Addr::new(10, 0, 2, 2));
        assert_eq!(lease.seconds, 3600);
        assert_eq!(
            lease.server,
            Ipv4Addr::new(10, 0, 2, 2),
            "the server identifier option, not siaddr -- a relayed reply carries \
             the relay in the fixed field and the server that decided here"
        );
    }

    /// **An offer is not an acknowledgement**, and taking one for the other is
    /// taking an address the server has not committed to.
    #[test]
    fn an_offer_is_not_an_acknowledgement() {
        let (bytes, length) = acknowledged(OFFER, Ipv4Addr::new(10, 0, 2, 15));
        assert!(matches!(
            parse_ack(&bytes[..length]),
            Err(NetError::Unsupported {
                field: "dhcp message type",
                value: 2,
            })
        ));
    }

    /// A refusal is reported as the refusal it is, so a caller can tell it from
    /// a message this parser does not take -- or from silence.
    #[test]
    fn a_nak_is_a_refusal_and_says_so() {
        let (bytes, length) = acknowledged(NAK, Ipv4Addr::new(0, 0, 0, 0));
        assert!(matches!(
            parse_ack(&bytes[..length]),
            Err(NetError::Unsupported {
                field: "dhcp message type",
                value: 6,
            })
        ));
    }

    /// The request names the address and the server, which is what makes it a
    /// request rather than a second discover.
    #[test]
    fn a_request_names_the_address_and_the_server_it_came_from() {
        let mut out = [0u8; 320];
        let length = write_request(
            &mut out,
            MAC,
            0x0b_1a_5c_01,
            Ipv4Addr::new(10, 0, 2, 15),
            Ipv4Addr::new(10, 0, 2, 2),
        )
        .unwrap();

        assert_eq!(out[0], BOOTREQUEST);
        assert_eq!(&out[4..8], &0x0b_1a_5c_01u32.to_be_bytes());
        assert_eq!(&out[28..34], &MAC.octets());
        assert_eq!(be32(&out, FIXED), Some(MAGIC));
        assert_eq!(
            &out[MINIMUM..MINIMUM + 3],
            &[OPTION_MESSAGE_TYPE, 1, REQUEST]
        );
        assert_eq!(
            &out[MINIMUM + 3..MINIMUM + 9],
            &[OPTION_REQUESTED_ADDRESS, 4, 10, 0, 2, 15]
        );
        assert_eq!(
            &out[MINIMUM + 9..MINIMUM + 15],
            &[OPTION_SERVER, 4, 10, 0, 2, 2]
        );
        assert_eq!(out[MINIMUM + 15], OPTION_END);
        assert_eq!(length, MINIMUM + 16);

        // And it does not fit where it does not fit.
        let mut narrow = [0u8; MINIMUM];
        assert!(matches!(
            write_request(
                &mut narrow,
                MAC,
                0,
                Ipv4Addr::UNSPECIFIED,
                Ipv4Addr::UNSPECIFIED
            ),
            Err(NetError::Truncated { .. })
        ));
    }

    /// A server that says nothing about the network leaves those fields
    /// unspecified rather than guessed.
    #[test]
    fn an_ack_without_options_still_carries_its_address() {
        let (bytes, length) = reply(ACK, Ipv4Addr::new(192, 168, 1, 50));
        let lease = parse_ack(&bytes[..length]).unwrap();
        assert_eq!(lease.address, Ipv4Addr::new(192, 168, 1, 50));
        assert_eq!(lease.subnet, Ipv4Addr::UNSPECIFIED, "not guessed");
        assert_eq!(lease.router, Ipv4Addr::UNSPECIFIED, "nor this");
        assert_eq!(lease.seconds, 0, "and a lease of no stated length");
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
