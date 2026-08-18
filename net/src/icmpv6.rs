// SPDX-License-Identifier: Apache-2.0
//! ICMPv6 — the echo half, and the checksum v4's ICMP does not have.
//!
//! [RFC 0029](../../docs/rfc/0029-ipv6.md) step 1. The reasons only echo is
//! here are [`crate::icmp`]'s reasons, unchanged: the error types quote the
//! packet that caused them, which is a nested parser with nested bounds,
//! and none of it is needed to answer a ping. Neighbour discovery — the
//! four messages that replaced ARP — is RFC 0029 step 2 and will live here
//! when it lands, because it is ICMPv6 by format even though it is ARP by
//! role.
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
    addr::Ipv6Addr,
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
}
