// SPDX-License-Identifier: Apache-2.0
//! ICMP, and only the echo half of it.
//!
//! [RFC 0018](../../docs/rfc/0018-networking.md) step 4b. Eight bytes of header
//! and a payload that is whatever the sender put there.
//!
//! # Why only echo
//!
//! ICMP carries error reporting as well — destination unreachable, time
//! exceeded, redirect — and every one of those *quotes the packet that caused
//! it*, which means parsing an IP header nested inside an ICMP body that was
//! itself nested in an IP header. That is a second parser with a second set of
//! bounds, and a redirect in particular changes routing on the say-so of
//! whoever sent it.
//!
//! None of that is needed to answer a ping, so none of it is here. What is here
//! refuses everything it does not recognise rather than ignoring it, so adding
//! a type later is a decision rather than a discovery.
//!
//! # The checksum covers the whole message and has no pseudo-header
//!
//! Unlike UDP. So an ICMP message can be verified on its own, which is why this
//! module takes no addresses — and a reader who expects the UDP shape will
//! reach for them and not find them, which is the point of saying so here.

use crate::{NetError, be16, checksum};

/// Bytes in an ICMP echo header, before the payload.
pub const HEADER: usize = 8;

/// An echo request: "are you there".
pub const ECHO_REQUEST: u8 = 8;

/// An echo reply: "yes".
pub const ECHO_REPLY: u8 = 0;

/// A parsed ICMP echo message, borrowing its payload.
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
    /// Parses an ICMP echo request or reply.
    ///
    /// # Errors
    ///
    /// - [`NetError::Truncated`] if fewer than [`HEADER`] bytes were supplied.
    /// - [`NetError::BadChecksum`] if the checksum does not verify.
    /// - [`NetError::Unsupported`] for any type that is not an echo, and for a
    ///   non-zero code — a code this module does not understand on a type it
    ///   does is still a message it has not understood.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, NetError> {
        let header = bytes.get(..HEADER).ok_or(NetError::Truncated {
            need: HEADER,
            have: bytes.len(),
        })?;

        let kind = header[0];
        if kind != ECHO_REQUEST && kind != ECHO_REPLY {
            return Err(NetError::Unsupported {
                field: "icmp type",
                value: u32::from(kind),
            });
        }
        if header[1] != 0 {
            return Err(NetError::Unsupported {
                field: "icmp code",
                value: u32::from(header[1]),
            });
        }

        let carried = be16(header, 2).unwrap_or(0);
        // Over the whole message with the checksum field taken as zero. Two
        // spans and the payload, so nothing is copied to blank two bytes.
        let computed = checksum(&[&bytes[..2], &[0, 0], &bytes[4..]]);
        if computed != carried {
            return Err(NetError::BadChecksum { computed, carried });
        }

        Ok(Self {
            is_reply: kind == ECHO_REPLY,
            identifier: be16(header, 4).unwrap_or(0),
            sequence: be16(header, 6).unwrap_or(0),
            payload: bytes.get(HEADER..).unwrap_or(&[]),
        })
    }
}

/// Writes an echo message into `out`, returning how many bytes.
///
/// # Errors
///
/// [`NetError::Truncated`] if `out` cannot hold the header and the payload.
pub fn write(
    out: &mut [u8],
    is_reply: bool,
    identifier: u16,
    sequence: u16,
    payload: &[u8],
) -> Result<usize, NetError> {
    let total = HEADER
        .checked_add(payload.len())
        .ok_or(NetError::Truncated {
            need: usize::MAX,
            have: out.len(),
        })?;
    let available = out.len();
    let message = out.get_mut(..total).ok_or(NetError::Truncated {
        need: total,
        have: available,
    })?;

    message[0] = if is_reply { ECHO_REPLY } else { ECHO_REQUEST };
    message[1] = 0;
    message[2..4].copy_from_slice(&[0, 0]);
    message[4..6].copy_from_slice(&identifier.to_be_bytes());
    message[6..8].copy_from_slice(&sequence.to_be_bytes());
    message[HEADER..total].copy_from_slice(payload);

    let sum = checksum(&[&message[..total]]);
    message[2..4].copy_from_slice(&sum.to_be_bytes());
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn built(is_reply: bool, payload: &[u8]) -> ([u8; 128], usize) {
        let mut out = [0u8; 128];
        let length = write(&mut out, is_reply, 0x1234, 7, payload).unwrap();
        (out, length)
    }

    #[test]
    fn a_written_echo_parses_back() {
        let (bytes, length) = built(false, &[1, 2, 3, 4]);
        let parsed = Echo::parse(&bytes[..length]).unwrap();
        assert!(!parsed.is_reply);
        assert_eq!(parsed.identifier, 0x1234);
        assert_eq!(parsed.sequence, 7);
        assert_eq!(parsed.payload, &[1, 2, 3, 4]);
    }

    #[test]
    fn a_reply_is_distinguishable_from_a_request() {
        let (request, r_len) = built(false, &[]);
        let (reply, p_len) = built(true, &[]);
        assert!(!Echo::parse(&request[..r_len]).unwrap().is_reply);
        assert!(Echo::parse(&reply[..p_len]).unwrap().is_reply);
        // And the two differ in the first byte, which is what the receiver
        // keys on. A writer that ignored `is_reply` would pass the round trip
        // above and fail this.
        assert_ne!(request[0], reply[0]);
    }

    #[test]
    fn an_odd_payload_checksums_correctly() {
        // The pad lands at the end of the message rather than mid-span, which
        // is the one case a two-span checksum can get wrong.
        for length in 0..9usize {
            let payload: [u8; 9] = [1, 2, 3, 4, 5, 6, 7, 8, 9];
            let (bytes, total) = built(false, &payload[..length]);
            let parsed = Echo::parse(&bytes[..total]).unwrap();
            assert_eq!(parsed.payload, &payload[..length]);
        }
    }

    #[test]
    fn a_corrupted_payload_fails_the_checksum() {
        let (mut bytes, length) = built(false, &[1, 2, 3, 4]);
        bytes[HEADER] ^= 0x01;
        assert!(matches!(
            Echo::parse(&bytes[..length]),
            Err(NetError::BadChecksum { .. })
        ));
    }

    #[test]
    fn a_type_this_module_does_not_answer_is_refused() {
        // Destination unreachable quotes the packet that caused it, which is an
        // IP header nested two layers down. Refused rather than ignored, so
        // adding it later is a decision.
        let (mut bytes, length) = built(false, &[1, 2, 3, 4]);
        bytes[0] = 3;
        assert_eq!(
            Echo::parse(&bytes[..length]),
            Err(NetError::Unsupported {
                field: "icmp type",
                value: 3
            })
        );
    }

    #[test]
    fn a_non_zero_code_on_a_type_we_know_is_still_refused() {
        let (mut bytes, length) = built(false, &[1, 2, 3, 4]);
        bytes[1] = 5;
        assert!(matches!(
            Echo::parse(&bytes[..length]),
            Err(NetError::Unsupported {
                field: "icmp code",
                ..
            })
        ));
    }

    #[test]
    fn seven_bytes_is_truncated_and_eight_is_an_empty_echo() {
        let (bytes, _) = built(false, &[]);
        assert_eq!(
            Echo::parse(&bytes[..HEADER - 1]),
            Err(NetError::Truncated {
                need: HEADER,
                have: HEADER - 1
            })
        );
        assert!(Echo::parse(&bytes[..HEADER]).unwrap().payload.is_empty());
    }

    #[test]
    fn writing_into_too_little_room_is_refused() {
        let mut out = [0u8; HEADER];
        assert!(write(&mut out, false, 1, 1, &[]).is_ok());
        assert!(write(&mut out, false, 1, 1, &[0]).is_err());
    }
}
