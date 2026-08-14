// SPDX-License-Identifier: Apache-2.0
//! The TCP segment: twenty bytes, six flags, and an option list that is the
//! most dangerous thing in this crate.
//!
//! [RFC 0020](../../../docs/rfc/0020-tcp.md) step 2. Pure, host-tested, and
//! stateless — a segment is parsed from bytes and built into bytes, and nothing
//! here knows a connection exists. The state machine is step 3 and reads what
//! this produces.
//!
//! # How this differs from the parsers already in this crate
//!
//! **There is no length field**, and that is the interesting part. UDP carries
//! its own length, so the class of bug there is a length that lies about the
//! buffer. TCP takes its length from the IP header above it and its *header*
//! length from a four-bit field — so the segment's payload is "whatever is
//! left", and the only field that can lie is the data offset. One field, and
//! everything downstream of it is derived, which makes it the field to test to
//! destruction.
//!
//! **The option list is a loop over remotely-supplied lengths.** Every other
//! parser here reads a fixed layout; this one walks a list whose stride the
//! remote party chooses. An option that claims a length of zero is the classic
//! way to make such a loop never advance, and it is one byte to send. That guard
//! is [`NetError::BadOptionLength`] and it is the single most load-bearing check
//! in this file.
//!
//! # What is parsed and what is merely tolerated
//!
//! RFC 0020 implements the maximum segment size option and nothing else — no
//! window scaling, no SACK, no timestamps. That is a decision about what this
//! stack *negotiates*, not permission to mis-walk a list that contains them: an
//! unknown option is skipped by its own length, correctly, or the segment is
//! refused. A parser that stopped at the first option it did not recognise would
//! silently ignore an MSS sitting behind a timestamp, which is a real
//! arrangement on a real network.

use crate::addr::{Ipv4Addr, Port};
use crate::tcp::Sequence;
use crate::{NetError, be16, be32, checksum, ipv4::Protocol};

/// Bytes in a TCP header with no options.
pub const HEADER: usize = 20;

/// The largest header the data offset can describe: fifteen 32-bit words.
pub const MAX_HEADER: usize = 60;

/// End of the option list. One octet, no length.
const END_OF_LIST: u8 = 0;

/// No-operation, used to align what follows. One octet, no length.
const NO_OPERATION: u8 = 1;

/// Maximum segment size. Four octets: kind, length, and two of value.
const MAXIMUM_SEGMENT_SIZE: u8 = 2;

/// The six control bits, as a set.
///
/// A newtype rather than six booleans, because the combination is what matters:
/// `SYN|ACK` is a different segment from `SYN`, and RFC 793's state machine
/// branches on the set rather than on the members.
///
/// The two reserved bits above these six are **ignored, not refused** — see
/// [`Segment::parse`].
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct Flags(pub u8);

impl Flags {
    /// No more data from the sender.
    pub const FIN: Self = Self(0x01);
    /// Synchronise sequence numbers.
    pub const SYN: Self = Self(0x02);
    /// Reset the connection.
    pub const RST: Self = Self(0x04);
    /// Push function.
    pub const PSH: Self = Self(0x08);
    /// The acknowledgement field is significant.
    ///
    /// **Not set by hand.** [`write`] derives this bit from whether
    /// [`Segment::acknowledgement`] carries a number, so the flag and the field
    /// cannot disagree.
    pub const ACK: Self = Self(0x10);
    /// The urgent pointer is significant.
    ///
    /// Parsed so that a segment carrying it round-trips, and otherwise ignored:
    /// RFC 0020 does not implement urgent data.
    pub const URG: Self = Self(0x20);

    /// Every bit this crate names.
    const KNOWN: u8 = 0x3f;

    /// Whether every flag in `other` is set here.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Both sets together.
    #[must_use]
    pub const fn with(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// This set without the flags in `other`.
    #[must_use]
    pub const fn without(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }
}

impl core::fmt::Debug for Flags {
    /// Spells the set, because `Flags(18)` at 3 a.m. is a lookup and
    /// `SYN|ACK` is not.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut first = true;
        for (flag, name) in [
            (Self::URG, "URG"),
            (Self::ACK, "ACK"),
            (Self::PSH, "PSH"),
            (Self::RST, "RST"),
            (Self::SYN, "SYN"),
            (Self::FIN, "FIN"),
        ] {
            if self.contains(flag) {
                if !first {
                    f.write_str("|")?;
                }
                f.write_str(name)?;
                first = false;
            }
        }
        if self.0 & !Self::KNOWN != 0 {
            if !first {
                f.write_str("|")?;
            }
            write!(f, "reserved:{:#04x}", self.0 & !Self::KNOWN)?;
            first = false;
        }
        if first {
            f.write_str("-")?;
        }
        Ok(())
    }
}

/// The options this stack understands.
///
/// One field, and the absences are RFC 0020's stated scope rather than an
/// oversight. A future option is a field here and an arm in the walk; the walk
/// itself already handles options it does not know.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Options {
    /// The largest payload the sender will accept, if it said.
    ///
    /// Only ever carried on a segment with `SYN`, by RFC 793. This parser does
    /// not enforce that: it reports what was there and lets the state machine
    /// decide, because refusing here would turn a peculiar segment into a
    /// dropped connection at a layer that cannot tell which state it is in.
    pub mss: Option<u16>,
}

/// A parsed TCP segment, borrowing its payload.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Segment<'a> {
    /// The sending port.
    pub source: Port,
    /// The receiving port.
    pub destination: Port,
    /// The sequence number of the first payload byte — or of the `SYN` or `FIN`
    /// itself, both of which occupy one number.
    pub sequence: Sequence,
    /// What the sender has received, if it said.
    ///
    /// `None` when `ACK` is clear, which is the whole reason this is an
    /// `Option`: RFC 793 §3.1 makes the field "significant" only under that
    /// flag, and a state machine that read it unconditionally would believe a
    /// number the peer never meant to send. Only a `SYN` with no `ACK` and a
    /// `RST` legitimately arrive without one.
    pub acknowledgement: Option<Sequence>,
    /// The control bits, as carried.
    pub flags: Flags,
    /// How many more bytes the sender will accept.
    pub window: u16,
    /// The options that were understood.
    pub options: Options,
    /// The bytes after the header.
    pub payload: &'a [u8],
}

impl<'a> Segment<'a> {
    /// Parses a segment, verifying its checksum against the IP addresses.
    ///
    /// `bytes` is the whole segment — header and payload — which the IP layer
    /// above has already delimited. There is no length field to consult and
    /// none to disbelieve.
    ///
    /// # The reserved bits are ignored rather than refused
    ///
    /// RFC 793 §3.1 says the six reserved bits "must be zero", and a parser
    /// written to that sentence would refuse every segment from a peer using
    /// explicit congestion notification, which took two of them in RFC 3168.
    /// Refusing would be spec-literal and wrong against the network that exists.
    /// They are carried in [`Segment::flags`] so a round trip preserves them,
    /// and nothing here acts on them.
    ///
    /// # Errors
    ///
    /// - [`NetError::Truncated`] if fewer than [`HEADER`] bytes were supplied,
    ///   or if an option's length octet is not there to read.
    /// - [`NetError::BadHeaderLength`] if the data offset is below five words
    ///   or describes a header longer than the bytes supplied.
    /// - [`NetError::BadOptionLength`] if an option claims a length below two —
    ///   the value that makes an option walk never advance — or an MSS that is
    ///   not four bytes.
    /// - [`NetError::LengthBeyondBuffer`] if an option reaches past the header.
    /// - [`NetError::BadChecksum`] if the checksum does not verify. Unlike UDP
    ///   there is no way to decline one, so there are two outcomes here and not
    ///   three.
    pub fn parse(
        bytes: &'a [u8],
        source_address: Ipv4Addr,
        destination_address: Ipv4Addr,
    ) -> Result<Self, NetError> {
        let fixed = bytes.get(..HEADER).ok_or(NetError::Truncated {
            need: HEADER,
            have: bytes.len(),
        })?;

        // The data offset, in 32-bit words. Five is a header with no options;
        // fifteen is the most four bits can say, which is [`MAX_HEADER`].
        //
        // **Only the lower bound is a check written here.** The upper one is
        // `get` refusing to slice past the end, and that distinction is not
        // pedantry: it was found by deleting an explicit `header_length >
        // bytes.len()` and watching nothing go red, because the slice below had
        // been enforcing it all along. Two checks doing one job means one of
        // them is never observed working, and this project counts a gate it has
        // not seen fail as no gate. The lower bound *is* observed — delete it
        // and both a unit test and the mutation harness go red.
        let words = fixed[12] >> 4;
        let header_length = usize::from(words) * 4;
        if header_length < HEADER {
            return Err(NetError::BadHeaderLength {
                words,
                total: bytes.len(),
            });
        }
        let header = bytes
            .get(..header_length)
            .ok_or(NetError::BadHeaderLength {
                words,
                total: bytes.len(),
            })?;

        let carried = be16(fixed, 16).unwrap_or(0);
        // The pseudo-header: the two addresses, a zero, the protocol, and the
        // length of the whole segment, which TCP computes rather than carries.
        let mut pseudo = [0u8; 12];
        pseudo[0..4].copy_from_slice(&source_address.octets());
        pseudo[4..8].copy_from_slice(&destination_address.octets());
        pseudo[9] = Protocol::TCP.0;
        let length = u16::try_from(bytes.len()).map_err(|_| NetError::LengthBeyondBuffer {
            stated: bytes.len(),
            have: usize::from(u16::MAX),
        })?;
        pseudo[10..12].copy_from_slice(&length.to_be_bytes());

        // Summed with the checksum field taken as zero, in spans, so no copy of
        // a payload whose length a remote party chose is ever made.
        let computed = checksum(&[
            &pseudo,
            bytes.get(..16).unwrap_or(&[]),
            &[0, 0],
            bytes.get(18..).unwrap_or(&[]),
        ]);
        if computed != carried {
            return Err(NetError::BadChecksum { computed, carried });
        }

        let flags = Flags(fixed[13]);
        let acknowledgement = if flags.contains(Flags::ACK) {
            Some(Sequence(be32(fixed, 8).unwrap_or(0)))
        } else {
            None
        };

        Ok(Self {
            source: Port(be16(fixed, 0).unwrap_or(0)),
            destination: Port(be16(fixed, 2).unwrap_or(0)),
            sequence: Sequence(be32(fixed, 4).unwrap_or(0)),
            acknowledgement,
            flags,
            window: be16(fixed, 14).unwrap_or(0),
            options: parse_options(header)?,
            payload: bytes.get(header_length..).unwrap_or(&[]),
        })
    }

    /// The sequence space this segment occupies.
    ///
    /// Payload bytes, plus one for a `SYN` and one for a `FIN` — because both
    /// are acknowledged and therefore both consume a number. Getting this wrong
    /// makes every acknowledgement off by one at exactly the two moments a
    /// connection opens and closes, which is why it lives here beside the parser
    /// rather than being recomputed at each call site in step 3.
    #[must_use]
    pub fn sequence_length(&self) -> u32 {
        // A segment cannot exceed a 64 KiB datagram, so this cannot overflow;
        // saturating rather than wrapping regardless, because `overflow-checks`
        // turns a wrong assumption here into a panic in a network service.
        let payload = u32::try_from(self.payload.len()).unwrap_or(u32::MAX);
        let control =
            u32::from(self.flags.contains(Flags::SYN)) + u32::from(self.flags.contains(Flags::FIN));
        payload.saturating_add(control)
    }
}

/// Walks the option list in `header`, which is the fixed part plus the options.
///
/// # Why a malformed length refuses the segment rather than ending the walk
///
/// Both are defensible and one is testable. Stopping early means an MSS behind a
/// broken option is silently absent, and "silently absent" is indistinguishable
/// from "the peer did not send one" — so a bug here would present as a
/// mysteriously small segment size months later. Refusing produces a counted
/// error at the moment it happens.
fn parse_options(header: &[u8]) -> Result<Options, NetError> {
    let mut options = Options::default();
    let mut at = HEADER;

    while at < header.len() {
        let kind = *header.get(at).ok_or(NetError::Truncated {
            need: at + 1,
            have: header.len(),
        })?;
        match kind {
            END_OF_LIST => break,
            // One octet, and the only branch that may advance by one. Padding
            // after the end of the list is not checked for zeroes: RFC 793 asks
            // for it, nothing on a real network depends on it, and refusing
            // would drop segments that are otherwise perfectly ordinary.
            NO_OPERATION => at += 1,
            _ => {
                let length = *header.get(at + 1).ok_or(NetError::Truncated {
                    need: at + 2,
                    have: header.len(),
                })?;
                // **The guard the whole file exists around.** A length of zero
                // or one does not advance `at`, so a walk without this check
                // never terminates — one byte from a remote party, and the
                // service is gone. It is refused rather than clamped, because a
                // clamp invents a stride nobody sent.
                if length < 2 {
                    return Err(NetError::BadOptionLength { kind, length });
                }
                let end = at
                    .checked_add(usize::from(length))
                    .ok_or(NetError::BadOptionLength { kind, length })?;
                if end > header.len() {
                    return Err(NetError::LengthBeyondBuffer {
                        stated: end,
                        have: header.len(),
                    });
                }
                if kind == MAXIMUM_SEGMENT_SIZE {
                    if length != 4 {
                        return Err(NetError::BadOptionLength { kind, length });
                    }
                    options.mss = be16(header, at + 2);
                }
                at = end;
            }
        }
    }

    Ok(options)
}

/// Writes `segment` into `out`, returning the bytes written.
///
/// The checksum is always computed; TCP has no way to decline one.
///
/// # The `ACK` bit is not taken from `flags`
///
/// It is set if and only if [`Segment::acknowledgement`] carries a number, and
/// any `ACK` in `flags` is discarded. Two places to say the same thing is two
/// places for them to disagree, and the disagreement that matters — the bit set
/// with no number behind it — is the one an attacker would enjoy.
///
/// # Errors
///
/// [`NetError::Truncated`] if `out` cannot hold the header, options and
/// payload, or [`NetError::LengthBeyondBuffer`] if the segment would exceed
/// what the pseudo-header's length field can state.
pub fn write(
    out: &mut [u8],
    segment: &Segment<'_>,
    source_address: Ipv4Addr,
    destination_address: Ipv4Addr,
) -> Result<usize, NetError> {
    // Only one option is ever written, and it is four bytes, so the header is
    // always a multiple of four without padding. A second option changes that
    // and the padding becomes real work — stated here because the natural place
    // to discover it is a peer rejecting a header length that does not divide.
    let header_length = if segment.options.mss.is_some() {
        HEADER + 4
    } else {
        HEADER
    };
    let total =
        header_length
            .checked_add(segment.payload.len())
            .ok_or(NetError::LengthBeyondBuffer {
                stated: segment.payload.len(),
                have: usize::from(u16::MAX),
            })?;
    if total > usize::from(u16::MAX) {
        return Err(NetError::LengthBeyondBuffer {
            stated: total,
            have: usize::from(u16::MAX),
        });
    }
    let available = out.len();
    let bytes = out.get_mut(..total).ok_or(NetError::Truncated {
        need: total,
        have: available,
    })?;
    bytes.fill(0);

    bytes[0..2].copy_from_slice(&segment.source.0.to_be_bytes());
    bytes[2..4].copy_from_slice(&segment.destination.0.to_be_bytes());
    bytes[4..8].copy_from_slice(&segment.sequence.0.to_be_bytes());

    let flags = match segment.acknowledgement {
        Some(acknowledgement) => {
            bytes[8..12].copy_from_slice(&acknowledgement.0.to_be_bytes());
            segment.flags.with(Flags::ACK)
        }
        None => segment.flags.without(Flags::ACK),
    };

    // The data offset occupies the top four bits of byte 12; the bottom four
    // are reserved and stay zero.
    let words = u8::try_from(header_length / 4).unwrap_or(5);
    bytes[12] = words << 4;
    bytes[13] = flags.0;
    bytes[14..16].copy_from_slice(&segment.window.to_be_bytes());
    // Bytes 16..18 are the checksum, filled in below; 18..20 the urgent
    // pointer, which stays zero because RFC 0020 does not implement urgent data.

    if let Some(mss) = segment.options.mss {
        bytes[HEADER] = MAXIMUM_SEGMENT_SIZE;
        bytes[HEADER + 1] = 4;
        bytes[HEADER + 2..HEADER + 4].copy_from_slice(&mss.to_be_bytes());
    }
    bytes[header_length..].copy_from_slice(segment.payload);

    let mut pseudo = [0u8; 12];
    pseudo[0..4].copy_from_slice(&source_address.octets());
    pseudo[4..8].copy_from_slice(&destination_address.octets());
    pseudo[9] = Protocol::TCP.0;
    // Proved to fit by the bound above.
    let length = u16::try_from(total).unwrap_or(u16::MAX);
    pseudo[10..12].copy_from_slice(&length.to_be_bytes());

    let sum = checksum(&[&pseudo, bytes]);
    bytes[16..18].copy_from_slice(&sum.to_be_bytes());
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    const HERE: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 15);
    const THERE: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 2);

    fn segment<'a>(flags: Flags, payload: &'a [u8]) -> Segment<'a> {
        Segment {
            source: Port(49152),
            destination: Port(80),
            sequence: Sequence(0x1000_0000),
            acknowledgement: None,
            flags,
            window: 4096,
            options: Options::default(),
            payload,
        }
    }

    fn built(segment: &Segment<'_>) -> ([u8; 256], usize) {
        let mut out = [0u8; 256];
        let length = write(&mut out, segment, HERE, THERE).unwrap();
        (out, length)
    }

    #[test]
    fn a_written_segment_parses_back_unchanged() {
        let mut original = segment(Flags::PSH.with(Flags::ACK), &[1, 2, 3, 4, 5]);
        original.acknowledgement = Some(Sequence(0x2000_0000));
        original.options.mss = Some(1460);
        let (bytes, length) = built(&original);
        assert_eq!(
            Segment::parse(&bytes[..length], HERE, THERE).unwrap(),
            original
        );
    }

    #[test]
    fn a_bare_syn_has_no_acknowledgement_and_no_ack_bit() {
        let (bytes, length) = built(&segment(Flags::SYN, &[]));
        let parsed = Segment::parse(&bytes[..length], HERE, THERE).unwrap();
        assert_eq!(parsed.acknowledgement, None);
        assert!(!parsed.flags.contains(Flags::ACK));
        assert!(parsed.flags.contains(Flags::SYN));
        assert!(parsed.payload.is_empty());
        assert_eq!(length, HEADER);
    }

    #[test]
    fn the_ack_bit_comes_from_the_number_and_not_from_the_flags() {
        // Set by hand and not backed by a number: the bit must not survive, or
        // the peer is told to believe four bytes nobody supplied.
        let (bytes, length) = built(&segment(Flags::ACK, &[]));
        let parsed = Segment::parse(&bytes[..length], HERE, THERE).unwrap();
        assert!(!parsed.flags.contains(Flags::ACK));
        assert_eq!(parsed.acknowledgement, None);
        assert_eq!(&bytes[8..12], &[0, 0, 0, 0], "and no number was written");

        // And the converse: a number supplied without the flag set still gets
        // the bit, because the number is the thing that is true.
        let mut acknowledging = segment(Flags::default(), &[]);
        acknowledging.acknowledgement = Some(Sequence(7));
        let (bytes, length) = built(&acknowledging);
        let parsed = Segment::parse(&bytes[..length], HERE, THERE).unwrap();
        assert!(parsed.flags.contains(Flags::ACK));
        assert_eq!(parsed.acknowledgement, Some(Sequence(7)));
    }

    #[test]
    fn the_checksum_covers_the_addresses_and_not_only_the_segment() {
        // The pseudo-header's whole purpose: the same bytes delivered to a
        // different address must fail, or a segment can be replayed at any host.
        let (bytes, length) = built(&segment(Flags::ACK, &[1, 2, 3]));
        assert!(Segment::parse(&bytes[..length], HERE, THERE).is_ok());
        assert!(matches!(
            Segment::parse(&bytes[..length], HERE, Ipv4Addr::new(10, 0, 2, 3)),
            Err(NetError::BadChecksum { .. })
        ));
    }

    #[test]
    fn a_corrupted_payload_fails_the_checksum() {
        let (mut bytes, length) = built(&segment(Flags::PSH, &[1, 2, 3, 4]));
        bytes[HEADER] ^= 0x01;
        assert!(matches!(
            Segment::parse(&bytes[..length], HERE, THERE),
            Err(NetError::BadChecksum { .. })
        ));
    }

    #[test]
    fn an_odd_length_payload_checksums_correctly() {
        // The pseudo-header is twelve bytes and the header twenty, so an odd
        // payload is the only way the checksum's pad lands at the end of an
        // odd-length span.
        for length in 0..9usize {
            let payload: [u8; 9] = [1, 2, 3, 4, 5, 6, 7, 8, 9];
            let (bytes, total) = built(&segment(Flags::PSH, &payload[..length]));
            let parsed = Segment::parse(&bytes[..total], HERE, THERE).unwrap();
            assert_eq!(parsed.payload, &payload[..length]);
        }
    }

    #[test]
    fn nineteen_bytes_is_truncated_and_twenty_is_an_empty_segment() {
        let (bytes, _) = built(&segment(Flags::ACK, &[]));
        assert_eq!(
            Segment::parse(&bytes[..HEADER - 1], HERE, THERE),
            Err(NetError::Truncated {
                need: HEADER,
                have: HEADER - 1
            })
        );
        assert!(Segment::parse(&bytes[..HEADER], HERE, THERE).is_ok());
    }

    /// Rewrites the data offset and repairs the checksum, so that a test of the
    /// offset is not accidentally a test of the checksum.
    fn with_data_offset(bytes: &mut [u8], words: u8) {
        bytes[12] = (bytes[12] & 0x0f) | (words << 4);
        bytes[16..18].copy_from_slice(&[0, 0]);
        let mut pseudo = [0u8; 12];
        pseudo[0..4].copy_from_slice(&HERE.octets());
        pseudo[4..8].copy_from_slice(&THERE.octets());
        pseudo[9] = Protocol::TCP.0;
        pseudo[10..12].copy_from_slice(&(bytes.len() as u16).to_be_bytes());
        let sum = checksum(&[&pseudo, bytes]);
        bytes[16..18].copy_from_slice(&sum.to_be_bytes());
    }

    #[test]
    fn a_data_offset_below_five_is_refused() {
        // Four words is sixteen bytes: a header that does not contain its own
        // checksum. Anything that subtracted it from the segment length would
        // get a payload longer than the segment.
        let (mut bytes, length) = built(&segment(Flags::ACK, &[1, 2, 3, 4]));
        for words in 0..5u8 {
            with_data_offset(&mut bytes[..length], words);
            assert_eq!(
                Segment::parse(&bytes[..length], HERE, THERE),
                Err(NetError::BadHeaderLength {
                    words,
                    total: length
                })
            );
        }
    }

    #[test]
    fn a_data_offset_past_the_segment_is_refused() {
        // Fifteen words is sixty bytes, and the segment is twenty-four. This is
        // the field that decides where the payload starts, so believing it
        // would slice past the end.
        //
        // **No check in `parse` corresponds to this test**, and that is the
        // interesting part: the refusal comes from `get` returning `None`
        // rather than from a comparison anyone wrote. An explicit bound was
        // there until it was deleted on purpose and nothing went red — it had
        // been redundant since the day it was typed. The test stays, because
        // what it asserts is the behaviour, not the mechanism.
        let (mut bytes, length) = built(&segment(Flags::ACK, &[1, 2, 3, 4]));
        assert_eq!(length, 24, "twenty of header and four of payload");
        assert_eq!(MAX_HEADER, 15 * 4, "fifteen words is all four bits can say");
        for words in [7u8, 8, 15] {
            with_data_offset(&mut bytes[..length], words);
            assert_eq!(
                Segment::parse(&bytes[..length], HERE, THERE),
                Err(NetError::BadHeaderLength {
                    words,
                    total: length
                }),
                "a data offset of {words} words against a {length}-byte segment"
            );
        }

        // And the boundary itself, which is one word lower than it looks: six
        // words is twenty-four bytes, exactly the segment, so it is a
        // header-only segment whose option area happens to be the four bytes
        // that were the payload. Legal, and the walk refuses them on their own
        // merits rather than on the offset's. This assertion is here because
        // the loop above originally included six and was wrong to.
        with_data_offset(&mut bytes[..length], 6);
        assert_eq!(
            Segment::parse(&bytes[..length], HERE, THERE),
            Err(NetError::BadOptionLength { kind: 2, length: 3 }),
            "the offset was accepted and the bytes behind it walked as options"
        );
    }

    /// Builds a segment whose option area is exactly `options`, padded to a
    /// four-byte boundary, with a correct checksum.
    fn with_options(options: &[u8], payload: &[u8]) -> ([u8; 256], usize) {
        let area = options.len().div_ceil(4) * 4;
        let header_length = HEADER + area;
        let total = header_length + payload.len();
        let mut bytes = [0u8; 256];
        bytes[0..2].copy_from_slice(&49152u16.to_be_bytes());
        bytes[2..4].copy_from_slice(&80u16.to_be_bytes());
        bytes[12] = ((header_length / 4) as u8) << 4;
        bytes[13] = Flags::ACK.0;
        bytes[HEADER..HEADER + options.len()].copy_from_slice(options);
        bytes[header_length..total].copy_from_slice(payload);
        with_data_offset(&mut bytes[..total], (header_length / 4) as u8);
        (bytes, total)
    }

    #[test]
    fn an_option_length_of_zero_is_refused_rather_than_walked() {
        // The one-byte denial of service. Without the guard the walk never
        // advances past this option and the service stops answering — a failure
        // that costs the attacker two bytes and cannot be recovered from.
        for length in [0u8, 1] {
            let (bytes, total) = with_options(&[MAXIMUM_SEGMENT_SIZE, length, 0x05, 0xb4], &[]);
            assert_eq!(
                Segment::parse(&bytes[..total], HERE, THERE),
                Err(NetError::BadOptionLength {
                    kind: MAXIMUM_SEGMENT_SIZE,
                    length
                })
            );
        }
    }

    #[test]
    fn an_option_reaching_past_the_header_is_refused() {
        // An option that claims more bytes than the data offset allows for.
        // Believing it would read the payload as option data.
        let (bytes, total) = with_options(&[MAXIMUM_SEGMENT_SIZE, 4, 0x05, 0xb4], &[]);
        let mut bytes = bytes;
        bytes[HEADER + 1] = 8; // claims eight bytes in a four-byte area
        with_data_offset(&mut bytes[..total], 6);
        assert!(matches!(
            Segment::parse(&bytes[..total], HERE, THERE),
            Err(NetError::LengthBeyondBuffer { .. })
        ));
    }

    #[test]
    fn the_maximum_segment_size_is_read() {
        let (bytes, total) = with_options(&[MAXIMUM_SEGMENT_SIZE, 4, 0x05, 0xb4], &[9, 9]);
        let parsed = Segment::parse(&bytes[..total], HERE, THERE).unwrap();
        assert_eq!(parsed.options.mss, Some(1460));
        assert_eq!(parsed.payload, &[9, 9], "and the payload starts after it");
    }

    #[test]
    fn a_maximum_segment_size_of_the_wrong_length_is_refused() {
        // Length six with kind two: a peer that has invented its own option
        // shape, or a fuzzer. Reading two bytes from it and calling it an MSS
        // would silently adopt whatever the next option's kind and length are.
        let (bytes, total) = with_options(&[MAXIMUM_SEGMENT_SIZE, 6, 0x05, 0xb4, 0, 0], &[]);
        assert_eq!(
            Segment::parse(&bytes[..total], HERE, THERE),
            Err(NetError::BadOptionLength {
                kind: MAXIMUM_SEGMENT_SIZE,
                length: 6
            })
        );
    }

    #[test]
    fn an_unknown_option_is_skipped_by_its_own_length() {
        // The reason the walk exists at all. A timestamp option (kind 8, ten
        // bytes) that this stack does not implement sits before the MSS; a
        // parser that stopped at the first unknown kind would report no MSS,
        // and would be wrong on a great many real connections.
        let options = [
            8,
            10,
            1,
            2,
            3,
            4,
            5,
            6,
            7,
            8, // timestamps, not implemented
            MAXIMUM_SEGMENT_SIZE,
            4,
            0x05,
            0xb4,
        ];
        let (bytes, total) = with_options(&options, &[7]);
        let parsed = Segment::parse(&bytes[..total], HERE, THERE).unwrap();
        assert_eq!(parsed.options.mss, Some(1460));
        assert_eq!(parsed.payload, &[7]);
    }

    #[test]
    fn no_operation_pads_between_options() {
        // Two NOPs, an MSS, then end-of-list — the arrangement a real stack
        // sends to align an option on a word boundary.
        let options = [
            NO_OPERATION,
            NO_OPERATION,
            MAXIMUM_SEGMENT_SIZE,
            4,
            0x05,
            0xb4,
            END_OF_LIST,
        ];
        let (bytes, total) = with_options(&options, &[]);
        let parsed = Segment::parse(&bytes[..total], HERE, THERE).unwrap();
        assert_eq!(parsed.options.mss, Some(1460));
    }

    #[test]
    fn end_of_list_stops_the_walk_and_padding_is_not_parsed() {
        // Bytes after the end marker are padding by RFC 793, and here they are
        // an option that would be refused if it were read. Reaching it means
        // the marker was ignored.
        let options = [END_OF_LIST, MAXIMUM_SEGMENT_SIZE, 0, 0];
        let (bytes, total) = with_options(&options, &[]);
        let parsed = Segment::parse(&bytes[..total], HERE, THERE).unwrap();
        assert_eq!(parsed.options.mss, None);
    }

    #[test]
    fn an_option_kind_with_no_length_octet_is_truncated_not_indexed() {
        // A two-byte option area holding one byte of a kind that needs a
        // length. The length octet is off the end of the header, and reading it
        // is the index this parser must not perform.
        let (mut bytes, total) = with_options(&[NO_OPERATION, NO_OPERATION, 8, 0], &[]);
        // Shrink the header to five words, so the option area is empty, then
        // grow the claimed offset by one word with only three bytes present is
        // not expressible -- instead put the kind at the last header byte.
        bytes[HEADER] = NO_OPERATION;
        bytes[HEADER + 1] = NO_OPERATION;
        bytes[HEADER + 2] = NO_OPERATION;
        bytes[HEADER + 3] = 8; // a kind needing a length, at the very end
        with_data_offset(&mut bytes[..total], 6);
        assert_eq!(
            Segment::parse(&bytes[..total], HERE, THERE),
            Err(NetError::Truncated {
                need: HEADER + 5,
                have: HEADER + 4
            })
        );
    }

    #[test]
    fn a_syn_and_a_fin_each_occupy_a_sequence_number() {
        // The off-by-one that lands exactly when a connection opens and closes.
        assert_eq!(segment(Flags::default(), &[]).sequence_length(), 0);
        assert_eq!(segment(Flags::SYN, &[]).sequence_length(), 1);
        assert_eq!(segment(Flags::FIN, &[]).sequence_length(), 1);
        assert_eq!(
            segment(Flags::SYN.with(Flags::FIN), &[]).sequence_length(),
            2
        );
        assert_eq!(segment(Flags::PSH, &[1, 2, 3]).sequence_length(), 3);
        assert_eq!(
            segment(Flags::FIN.with(Flags::PSH), &[1, 2, 3]).sequence_length(),
            4
        );
    }

    #[test]
    fn flags_print_as_names_in_the_headers_own_bit_order() {
        // **`ACK|SYN`, not `SYN-ACK`.** The order is RFC 793 §3.1's, high bit
        // first, so the printed set maps straight onto byte 13 of a hex dump —
        // which is what somebody reading this at 3 a.m. has in front of them.
        // The conversational order would read better and compare worse, and
        // this test exists so the swap is a decision rather than a tidy-up.
        assert_eq!(format!("{:?}", Flags::SYN.with(Flags::ACK)), "ACK|SYN");
        assert_eq!(format!("{:?}", Flags(0x12)), "ACK|SYN", "and 0x12 is that");
        assert_eq!(format!("{:?}", Flags::default()), "-");
        assert_eq!(format!("{:?}", Flags(0xc0)), "reserved:0xc0");
        assert_eq!(format!("{:?}", Flags(0x82)), "SYN|reserved:0x80");
    }

    #[test]
    fn the_reserved_bits_are_carried_and_not_refused() {
        // A peer using explicit congestion notification sets two of the bits
        // RFC 793 calls reserved. Refusing would be spec-literal and would drop
        // every segment from a modern stack.
        let (mut bytes, length) = built(&segment(Flags::ACK, &[1, 2]));
        bytes[13] |= 0xc0;
        with_data_offset(&mut bytes[..length], 5);
        let parsed = Segment::parse(&bytes[..length], HERE, THERE).unwrap();
        assert_eq!(parsed.flags.0 & 0xc0, 0xc0);
    }

    #[test]
    fn a_segment_too_large_for_the_buffer_is_refused_before_it_is_written() {
        let mut out = [0u8; 24];
        let overflowing = segment(Flags::PSH, &[0; 32]);
        assert_eq!(
            write(&mut out, &overflowing, HERE, THERE),
            Err(NetError::Truncated {
                need: HEADER + 32,
                have: 24
            })
        );
    }
}
