// SPDX-License-Identifier: Apache-2.0
//! UDP — eight bytes, and the pseudo-header that makes its checksum mean
//! something.
//!
//! # The checksum is optional, and that is the interesting part
//!
//! Over IPv4 a sender may decline to compute one and send zero instead. So a
//! parser has three cases, not two: verified, absent, and wrong — and
//! collapsing the first two loses the only signal a receiver has about whether
//! the bytes it is about to act on were checked at all.
//!
//! [`UdpDatagram::parse`] therefore reports which happened, in
//! [`UdpDatagram::checksummed`], rather than returning a bare success. A
//! service that requires checked datagrams can then require them, and one that
//! does not can say so deliberately.
//!
//! # Why the addresses are arguments
//!
//! The checksum covers a pseudo-header built from the *IP* source and
//! destination, so a UDP datagram cannot be verified alone. Passing them in
//! rather than parsing them here keeps this layer a function of its own bytes
//! and makes the coupling visible in the signature, which is where a reader
//! will look for it.

use crate::{NetError, addr::Ipv4Addr, addr::Port, be16, checksum, ipv4::Protocol};

/// Bytes in a UDP header.
pub const HEADER: usize = 8;

/// A parsed UDP datagram, borrowing its payload.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct UdpDatagram<'a> {
    /// The sending port.
    pub source: Port,
    /// The receiving port.
    pub destination: Port,
    /// The bytes after the header.
    pub payload: &'a [u8],
    /// Whether a checksum was carried and verified.
    ///
    /// `false` means the sender declined to compute one — which is legal over
    /// IPv4 — and **not** that one failed. A failure is
    /// [`NetError::BadChecksum`] and never reaches a caller as a datagram.
    pub checksummed: bool,
}

impl<'a> UdpDatagram<'a> {
    /// Parses a datagram, verifying its checksum against the IP addresses.
    ///
    /// # Errors
    ///
    /// - [`NetError::Truncated`] if fewer than [`HEADER`] bytes were supplied,
    ///   or if the length field is below eight — a datagram cannot be shorter
    ///   than its own header, and a length of zero is the value that turns an
    ///   unchecked subtraction into a very large number.
    /// - [`NetError::LengthBeyondBuffer`] if the length field reaches past the
    ///   bytes supplied.
    /// - [`NetError::BadChecksum`] if a checksum was carried and did not
    ///   verify.
    pub fn parse(
        bytes: &'a [u8],
        source_address: Ipv4Addr,
        destination_address: Ipv4Addr,
    ) -> Result<Self, NetError> {
        let header = bytes.get(..HEADER).ok_or(NetError::Truncated {
            need: HEADER,
            have: bytes.len(),
        })?;

        let stated = usize::from(be16(header, 4).unwrap_or(0));
        // Below its own header. Checked before it is used in any subtraction,
        // which is the whole reason this is a separate branch from the one
        // below rather than folded into it.
        if stated < HEADER {
            return Err(NetError::Truncated {
                need: HEADER,
                have: stated,
            });
        }
        if stated > bytes.len() {
            return Err(NetError::LengthBeyondBuffer {
                stated,
                have: bytes.len(),
            });
        }
        // Proved by the two checks above.
        let datagram = bytes.get(..stated).ok_or(NetError::LengthBeyondBuffer {
            stated,
            have: bytes.len(),
        })?;

        let carried = be16(header, 6).unwrap_or(0);
        let checksummed = carried != 0;
        if checksummed {
            // The pseudo-header, built on the stack: the two addresses, a zero,
            // the protocol, and the UDP length as the header states it.
            let mut pseudo = [0u8; 12];
            pseudo[0..4].copy_from_slice(&source_address.octets());
            pseudo[4..8].copy_from_slice(&destination_address.octets());
            pseudo[9] = Protocol::UDP.0;
            pseudo[10..12].copy_from_slice(&(stated as u16).to_be_bytes());

            // Summed with the checksum field taken as zero, in three spans, for
            // the same reason IPv4 does it: no allocation and no scratch copy
            // of a payload whose length a remote party chose.
            let computed = checksum(&[&pseudo, &datagram[..6], &[0, 0], &datagram[HEADER..]]);
            // A computed sum of zero is transmitted as 0xffff, because zero
            // means "no checksum". Both are accepted here; rejecting 0xffff
            // would drop legitimate datagrams roughly one time in 65536, which
            // is exactly the kind of defect that is never reproduced.
            let matches = computed == carried || (computed == 0 && carried == 0xffff);
            if !matches {
                return Err(NetError::BadChecksum { computed, carried });
            }
        }

        Ok(Self {
            source: Port(be16(header, 0).unwrap_or(0)),
            destination: Port(be16(header, 2).unwrap_or(0)),
            payload: datagram.get(HEADER..).unwrap_or(&[]),
            checksummed,
        })
    }
}

/// Writes a UDP datagram into `out`, returning the bytes written.
///
/// The checksum is always computed. A sender may legally omit it and this one
/// does not: omitting saves a pass over bytes that are already in cache, and
/// costs the receiver its only integrity check.
///
/// # Errors
///
/// [`NetError::Truncated`] if `out` cannot hold the header and payload, or
/// [`NetError::LengthBeyondBuffer`] if the two together exceed what a UDP
/// length field can state.
pub fn write(
    out: &mut [u8],
    source: Port,
    destination: Port,
    payload: &[u8],
    source_address: Ipv4Addr,
    destination_address: Ipv4Addr,
) -> Result<usize, NetError> {
    let total = HEADER
        .checked_add(payload.len())
        .ok_or(NetError::LengthBeyondBuffer {
            stated: payload.len(),
            have: usize::from(u16::MAX),
        })?;
    if total > usize::from(u16::MAX) {
        return Err(NetError::LengthBeyondBuffer {
            stated: total,
            have: usize::from(u16::MAX),
        });
    }
    let available = out.len();
    let datagram = out.get_mut(..total).ok_or(NetError::Truncated {
        need: total,
        have: available,
    })?;

    datagram[0..2].copy_from_slice(&source.0.to_be_bytes());
    datagram[2..4].copy_from_slice(&destination.0.to_be_bytes());
    datagram[4..6].copy_from_slice(&(total as u16).to_be_bytes());
    datagram[6..8].copy_from_slice(&[0, 0]);
    datagram[HEADER..].copy_from_slice(payload);

    let mut pseudo = [0u8; 12];
    pseudo[0..4].copy_from_slice(&source_address.octets());
    pseudo[4..8].copy_from_slice(&destination_address.octets());
    pseudo[9] = Protocol::UDP.0;
    pseudo[10..12].copy_from_slice(&(total as u16).to_be_bytes());

    let sum = checksum(&[&pseudo, datagram]);
    let sum = if sum == 0 { 0xffff } else { sum };
    datagram[6..8].copy_from_slice(&sum.to_be_bytes());
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    const HERE: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
    const THERE: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);

    fn built(payload: &[u8]) -> ([u8; 128], usize) {
        let mut out = [0u8; 128];
        let length = write(&mut out, Port(4242), Port(53), payload, HERE, THERE).unwrap();
        (out, length)
    }

    #[test]
    fn a_written_datagram_parses_back_with_its_checksum_verified() {
        let (bytes, length) = built(&[1, 2, 3, 4, 5]);
        let parsed = UdpDatagram::parse(&bytes[..length], HERE, THERE).unwrap();
        assert_eq!(parsed.source, Port(4242));
        assert_eq!(parsed.destination, Port(53));
        assert_eq!(parsed.payload, &[1, 2, 3, 4, 5]);
        assert!(parsed.checksummed);
    }

    #[test]
    fn an_odd_length_payload_checksums_correctly() {
        // The pseudo-header is twelve bytes and the header eight, so an odd
        // payload is the only way the pad lands in the middle of the span list.
        for length in 0..9usize {
            let payload: [u8; 9] = [1, 2, 3, 4, 5, 6, 7, 8, 9];
            let (bytes, total) = built(&payload[..length]);
            let parsed = UdpDatagram::parse(&bytes[..total], HERE, THERE).unwrap();
            assert_eq!(parsed.payload, &payload[..length]);
        }
    }

    #[test]
    fn the_checksum_covers_the_addresses_and_not_only_the_datagram() {
        // The point of the pseudo-header: the same bytes delivered to a
        // different address must fail. Without it a datagram could be replayed
        // at any host and still verify.
        let (bytes, length) = built(&[1, 2, 3, 4]);
        assert!(UdpDatagram::parse(&bytes[..length], HERE, THERE).is_ok());
        assert!(matches!(
            UdpDatagram::parse(&bytes[..length], HERE, Ipv4Addr::new(10, 0, 0, 3)),
            Err(NetError::BadChecksum { .. })
        ));
    }

    #[test]
    fn a_zero_checksum_means_unchecked_and_not_failed() {
        let (mut bytes, length) = built(&[1, 2, 3, 4]);
        bytes[6..8].copy_from_slice(&[0, 0]);
        let parsed = UdpDatagram::parse(&bytes[..length], HERE, THERE).unwrap();
        assert!(!parsed.checksummed);
        assert_eq!(parsed.payload, &[1, 2, 3, 4]);
    }

    #[test]
    fn a_corrupted_payload_fails_the_checksum() {
        let (mut bytes, length) = built(&[1, 2, 3, 4]);
        bytes[HEADER] ^= 0x01;
        assert!(matches!(
            UdpDatagram::parse(&bytes[..length], HERE, THERE),
            Err(NetError::BadChecksum { .. })
        ));
    }

    #[test]
    fn a_length_below_the_header_is_refused_before_it_is_subtracted() {
        // Zero is the value that makes `stated - HEADER` enormous. It must be
        // refused as a length, not reached as a subtraction.
        let (mut bytes, length) = built(&[1, 2, 3, 4]);
        for claim in [0u16, 1, 7] {
            bytes[4..6].copy_from_slice(&claim.to_be_bytes());
            assert_eq!(
                UdpDatagram::parse(&bytes[..length], HERE, THERE),
                Err(NetError::Truncated {
                    need: HEADER,
                    have: usize::from(claim)
                })
            );
        }
    }

    #[test]
    fn a_length_beyond_the_buffer_is_refused() {
        let (mut bytes, length) = built(&[1, 2, 3, 4]);
        bytes[4..6].copy_from_slice(&600u16.to_be_bytes());
        assert_eq!(
            UdpDatagram::parse(&bytes[..length], HERE, THERE),
            Err(NetError::LengthBeyondBuffer {
                stated: 600,
                have: length
            })
        );
    }

    #[test]
    fn trailing_bytes_beyond_the_stated_length_are_not_payload() {
        // A short UDP datagram inside a padded frame. The payload must be what
        // the length says, not what is left in the buffer.
        let (bytes, length) = built(&[1, 2, 3, 4]);
        let parsed = UdpDatagram::parse(&bytes, HERE, THERE).unwrap();
        assert_eq!(parsed.payload, &[1, 2, 3, 4]);
        assert_eq!(length, HEADER + 4);
    }

    #[test]
    fn seven_bytes_is_truncated_and_eight_is_an_empty_datagram() {
        let (bytes, _) = built(&[]);
        assert_eq!(
            UdpDatagram::parse(&bytes[..HEADER - 1], HERE, THERE),
            Err(NetError::Truncated {
                need: HEADER,
                have: HEADER - 1
            })
        );
        let parsed = UdpDatagram::parse(&bytes[..HEADER], HERE, THERE).unwrap();
        assert!(parsed.payload.is_empty());
    }
}
