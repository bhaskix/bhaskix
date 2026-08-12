// SPDX-License-Identifier: Apache-2.0
//! IPv4 headers, and the reassembly of the datagrams they fragment.
//!
//! # The header is the easy half
//!
//! Twenty fixed bytes and a variable options field, with three lengths that
//! must agree: the internet header length, the total length, and the number of
//! bytes actually supplied. Every parser bug of consequence in this layer comes
//! from believing one of the first two.
//!
//! So: `IHL` is checked against both the minimum and the total length; the
//! total length is checked against the buffer; and the payload is taken from a
//! range proved by those checks rather than computed and indexed.
//!
//! A frame longer than the total length is normal, not suspicious — Ethernet
//! pads short frames to sixty bytes — so trailing bytes are ignored rather than
//! rejected. A total length *longer* than the frame is rejected, because that
//! is the packet claiming bytes it did not bring.
//!
//! # Reassembly is where the danger is
//!
//! [`Reassembly`] holds bytes chosen by a remote party, keyed on fields chosen
//! by a remote party, for a duration chosen by a remote party's silence. It is
//! the classic resource-exhaustion primitive, and it has a second, older
//! problem: overlapping fragments, where two fragments claim the same offset
//! with different bytes and the reassembled datagram depends on which the stack
//! believed. That has been used to make one datagram appear differently to a
//! filter and to its destination.
//!
//! Both are answered structurally rather than by heuristics — a fixed table, a
//! deadline per entry, a refusal when full, and a first-writer-wins rule that
//! makes overlap unable to change any byte already held. See [`Reassembly`].

use crate::{NetError, addr::Ipv4Addr, be16, be32, checksum};

/// Bytes in an IPv4 header with no options.
pub const HEADER: usize = 20;

/// The largest total length an IPv4 header can state.
pub const MAX_DATAGRAM: usize = u16::MAX as usize;

/// The largest number of 8-byte blocks a datagram can be divided into.
const MAX_BLOCKS: usize = MAX_DATAGRAM / 8;

/// Words in the received-block bitmap: one bit per 8-byte block.
const BITMAP_WORDS: usize = MAX_BLOCKS.div_ceil(64);

/// What the protocol field names.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Protocol(pub u8);

impl Protocol {
    /// ICMP.
    pub const ICMP: Self = Self(1);
    /// TCP, recognised so it can be counted. RFC 0019 will parse it.
    pub const TCP: Self = Self(6);
    /// UDP.
    pub const UDP: Self = Self(17);
}

/// A parsed IPv4 header.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Ipv4Header {
    /// Where the datagram came from, according to the datagram.
    pub source: Ipv4Addr,
    /// Where it is going.
    pub destination: Ipv4Addr,
    /// What the payload is.
    pub protocol: Protocol,
    /// Hops remaining.
    pub ttl: u8,
    /// Identifies the datagram this fragment belongs to.
    pub identification: u16,
    /// Whether more fragments follow this one.
    pub more_fragments: bool,
    /// Whether the sender forbade fragmentation.
    pub dont_fragment: bool,
    /// Where this fragment sits in the datagram, **in bytes**.
    ///
    /// The wire carries 8-byte units; this is the multiplied value, because
    /// every use of it is a byte offset and doing the multiplication once, at
    /// the parse, is one place to check it rather than several.
    pub fragment_offset: usize,
    /// Bytes of header, including options.
    pub header_length: usize,
    /// Bytes of header plus payload, as the header states.
    pub total_length: usize,
}

impl Ipv4Header {
    /// Parses a header and returns it with the payload that follows.
    ///
    /// # Errors
    ///
    /// - [`NetError::Truncated`] if fewer than [`HEADER`] bytes were supplied.
    /// - [`NetError::BadVersion`] if the version field is not 4.
    /// - [`NetError::BadHeaderLength`] if `IHL` is below five, or describes a
    ///   header longer than the total length, or longer than what was supplied.
    /// - [`NetError::LengthBeyondBuffer`] if the total length reaches past the
    ///   bytes supplied.
    /// - [`NetError::BadChecksum`] if the header checksum does not verify.
    pub fn parse(bytes: &[u8]) -> Result<(Self, &[u8]), NetError> {
        let fixed = bytes.get(..HEADER).ok_or(NetError::Truncated {
            need: HEADER,
            have: bytes.len(),
        })?;

        let version = fixed[0] >> 4;
        if version != 4 {
            return Err(NetError::BadVersion(version));
        }

        let words = fixed[0] & 0x0f;
        let header_length = usize::from(words) * 4;
        let total_length = usize::from(be16(fixed, 2).unwrap_or(0));

        // All three lengths, checked against each other before any of them is
        // used to slice. `IHL` below five describes a header shorter than the
        // fixed part; above the total length it describes a header that does
        // not fit in its own datagram.
        if header_length < HEADER || header_length > total_length {
            return Err(NetError::BadHeaderLength {
                words,
                total: total_length,
            });
        }
        if total_length > bytes.len() {
            return Err(NetError::LengthBeyondBuffer {
                stated: total_length,
                have: bytes.len(),
            });
        }
        // Implied by the two checks above, and asserted anyway: this is the
        // slice everything below is taken from, and a reader should not have to
        // chain two inequalities to see that it is in bounds.
        let header = bytes
            .get(..header_length)
            .ok_or(NetError::BadHeaderLength {
                words,
                total: total_length,
            })?;

        let carried = be16(header, 10).unwrap_or(0);
        // The checksum is computed with its own field taken as zero, which is
        // done by summing the two spans either side of it rather than by
        // copying the header to blank it -- there is no allocation here and a
        // fixed scratch buffer would have to be as long as the longest header.
        let computed = checksum(&[&header[..10], &[0, 0], &header[12..]]);
        if computed != carried {
            return Err(NetError::BadChecksum { computed, carried });
        }

        let flags_and_offset = be16(header, 6).unwrap_or(0);
        // Bit 15 is reserved and bit 14 is `DF`; the offset is the low 13 bits,
        // in 8-byte units. Multiplied here, once, and bounded by construction:
        // 13 bits times 8 is at most 65528, which cannot overflow a `usize`.
        let fragment_offset = usize::from(flags_and_offset & 0x1fff) * 8;

        Ok((
            Self {
                source: Ipv4Addr(be32(header, 12).unwrap_or(0)),
                destination: Ipv4Addr(be32(header, 16).unwrap_or(0)),
                protocol: Protocol(header[9]),
                ttl: header[8],
                identification: be16(header, 4).unwrap_or(0),
                more_fragments: flags_and_offset & 0x2000 != 0,
                dont_fragment: flags_and_offset & 0x4000 != 0,
                fragment_offset,
                header_length,
                total_length,
            },
            // Both ends proved above: `header_length <= total_length <= len`.
            bytes.get(header_length..total_length).unwrap_or(&[]),
        ))
    }

    /// Whether this header describes part of a datagram rather than all of one.
    #[must_use]
    pub const fn is_fragment(&self) -> bool {
        self.more_fragments || self.fragment_offset != 0
    }
}

/// Writes an IPv4 header with no options, and returns how many bytes.
///
/// The total length written is `HEADER + payload_length`, so a caller fills the
/// payload itself and this never copies it — the same arrangement
/// [`crate::udp::write`] uses, and for the same reason: a writer that took the
/// payload would copy every byte twice on the way to a device.
///
/// # Errors
///
/// - [`NetError::Truncated`] if `out` cannot hold [`HEADER`] bytes.
/// - [`NetError::LengthBeyondBuffer`] if the header plus the payload would
///   exceed what a total-length field can state.
pub fn write_header(
    out: &mut [u8],
    source: Ipv4Addr,
    destination: Ipv4Addr,
    protocol: Protocol,
    payload_length: usize,
    identification: u16,
) -> Result<usize, NetError> {
    let total = HEADER
        .checked_add(payload_length)
        .ok_or(NetError::LengthBeyondBuffer {
            stated: payload_length,
            have: MAX_DATAGRAM,
        })?;
    if total > MAX_DATAGRAM {
        return Err(NetError::LengthBeyondBuffer {
            stated: total,
            have: MAX_DATAGRAM,
        });
    }
    let available = out.len();
    let header = out.get_mut(..HEADER).ok_or(NetError::Truncated {
        need: HEADER,
        have: available,
    })?;

    header[0] = 0x45; // version 4, five 32-bit words of header
    header[1] = 0;
    header[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    header[4..6].copy_from_slice(&identification.to_be_bytes());
    // `DF`: this datagram is not to be fragmented. Set rather than left clear
    // because nothing here reassembles what it sends, and a sender that permits
    // fragmentation of traffic it cannot reassemble the answer to is asking a
    // question it may not be able to hear.
    header[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
    header[8] = 64; // a hop count that crosses the internet and does not loop
    header[9] = protocol.0;
    header[10..12].copy_from_slice(&[0, 0]);
    header[12..16].copy_from_slice(&source.octets());
    header[16..20].copy_from_slice(&destination.octets());

    // Computed last, over the header with its own field zeroed — which it is,
    // because the two bytes were written as zero above and nothing has changed
    // them.
    let sum = checksum(&[&header[..HEADER]]);
    header[10..12].copy_from_slice(&sum.to_be_bytes());
    Ok(HEADER)
}

/// Identifies the datagram a fragment belongs to.
///
/// All four fields, as the specification requires. Keying on the identification
/// alone would let one sender's fragments be reassembled into another's
/// datagram, which is a way to inject bytes into a stream you cannot see.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Key {
    source: Ipv4Addr,
    destination: Ipv4Addr,
    identification: u16,
    protocol: Protocol,
}

/// One datagram being reassembled.
struct Pending<const MAX: usize> {
    key: Key,
    data: [u8; MAX],
    /// One bit per 8-byte block, set when that block has been written.
    received: [u64; BITMAP_WORDS],
    /// Known once the fragment with no `MF` bit arrives.
    total: Option<usize>,
    /// Monotonic nanoseconds after which this is abandoned.
    deadline: u64,
}

/// A fixed table of datagrams being reassembled.
///
/// Generic over how many datagrams may be in flight and how large each may be,
/// so the service placing it chooses its own exposure rather than inheriting a
/// number from this crate.
///
/// # Every limit here is deliberate
///
/// - **Fixed entries.** When the table is full a new datagram is *refused*,
///   not admitted by evicting one in progress. Eviction would let an attacker
///   destroy legitimate reassemblies at will by starting new ones; refusal
///   costs the attacker's own fragments nothing and the legitimate ones their
///   deadline at worst. This is the posture RFC 0018 chose and the opposite of
///   the ARP cache's, because the trade-offs genuinely differ: an evicted ARP
///   entry costs a round trip, an evicted reassembly costs a whole datagram.
/// - **A deadline per entry.** A datagram whose remaining fragments never
///   arrive must not occupy a slot for ever, and the sender of the first
///   fragment is exactly the party who would like it to.
/// - **First writer wins.** A fragment overlapping blocks already held is
///   accepted and its overlapping bytes are *discarded*, so no byte already in
///   the buffer can be changed by a later fragment. Overlapping fragments have
///   been used to make one datagram parse differently for a filter and for its
///   destination; that is impossible if the first bytes to arrive are the only
///   ones that count.
/// - **`MAX` bounds every offset.** A fragment whose offset plus length
///   exceeds the buffer is refused before anything is written.
pub struct Reassembly<const ENTRIES: usize, const MAX: usize> {
    entries: [Option<Pending<MAX>>; ENTRIES],
    /// How long an incomplete datagram is held, in nanoseconds.
    lifetime: u64,
}

impl<const ENTRIES: usize, const MAX: usize> Reassembly<ENTRIES, MAX> {
    /// A table holding incomplete datagrams for `lifetime` nanoseconds.
    #[must_use]
    pub fn new(lifetime: u64) -> Self {
        Self {
            entries: [const { None }; ENTRIES],
            lifetime,
        }
    }

    /// Offers a fragment.
    ///
    /// Returns the index of a now-complete datagram, whose bytes are then
    /// available from [`Reassembly::assembled`] until [`Reassembly::release`]
    /// is called, or `None` if more fragments are still needed.
    ///
    /// # Errors
    ///
    /// - [`NetError::LengthBeyondBuffer`] if this fragment would reach past
    ///   `MAX`, or past the total length an earlier last-fragment established.
    /// - [`NetError::Unsupported`] if a non-final fragment's length is not a
    ///   multiple of eight, which the specification requires and which is what
    ///   makes the block bitmap exact rather than approximate.
    /// - [`NetError::Exhausted`] if the table is full of unexpired entries.
    pub fn offer(
        &mut self,
        header: &Ipv4Header,
        payload: &[u8],
        now: u64,
    ) -> Result<Option<usize>, NetError> {
        let end = header.fragment_offset.checked_add(payload.len()).ok_or(
            NetError::LengthBeyondBuffer {
                stated: header.fragment_offset,
                have: MAX,
            },
        )?;
        if end > MAX {
            return Err(NetError::LengthBeyondBuffer {
                stated: end,
                have: MAX,
            });
        }
        // A fragment that is not the last must end on an 8-byte boundary. The
        // bitmap counts whole blocks, so a short middle fragment would either
        // mark a block it did not fill or leave a hole no later fragment can
        // address -- and the specification forbids it precisely because
        // reassembly is defined in these units.
        if header.more_fragments && !payload.len().is_multiple_of(8) {
            return Err(NetError::Unsupported {
                field: "non-final fragment not a multiple of 8 bytes",
                value: payload.len() as u32,
            });
        }

        let key = Key {
            source: header.source,
            destination: header.destination,
            identification: header.identification,
            protocol: header.protocol,
        };

        let index = match self.find_or_start(key, now)? {
            Some(index) => index,
            None => return Ok(None),
        };
        let Some(pending) = self.entries.get_mut(index).and_then(Option::as_mut) else {
            return Ok(None);
        };

        if !header.more_fragments {
            // The last fragment fixes the total length. A second, different
            // claim is a rewrite of the datagram's size after bytes have been
            // accepted against the first, and is refused.
            match pending.total {
                Some(known) if known != end => {
                    return Err(NetError::LengthBeyondBuffer {
                        stated: end,
                        have: known,
                    });
                }
                _ => pending.total = Some(end),
            }
        } else if pending.total.is_some_and(|known| end > known) {
            return Err(NetError::LengthBeyondBuffer {
                stated: end,
                have: pending.total.unwrap_or(MAX),
            });
        }

        // First writer wins, block by block. Copying whole blocks and skipping
        // held ones is what makes an overlapping fragment unable to change a
        // byte already accepted.
        for (block, chunk) in payload.chunks(8).enumerate() {
            let at = header.fragment_offset / 8 + block;
            if at >= MAX_BLOCKS || Self::held(&pending.received, at) {
                continue;
            }
            let start = at * 8;
            let stop = start + chunk.len();
            if let Some(destination) = pending.data.get_mut(start..stop) {
                destination.copy_from_slice(chunk);
                Self::hold(&mut pending.received, at);
            }
        }

        if Self::complete(pending) {
            Ok(Some(index))
        } else {
            Ok(None)
        }
    }

    /// The reassembled bytes at `index`, if that entry is complete.
    #[must_use]
    pub fn assembled(&self, index: usize) -> Option<&[u8]> {
        let pending = self.entries.get(index)?.as_ref()?;
        let total = pending.total?;
        if Self::complete(pending) {
            pending.data.get(..total)
        } else {
            None
        }
    }

    /// Frees the entry at `index`.
    pub fn release(&mut self, index: usize) {
        if let Some(slot) = self.entries.get_mut(index) {
            *slot = None;
        }
    }

    /// Drops every entry whose deadline has passed, returning how many.
    ///
    /// A caller should run this on a timer as well as relying on the sweep
    /// [`Reassembly::offer`] does, so that a table which stops receiving
    /// fragments entirely still empties.
    pub fn expire(&mut self, now: u64) -> usize {
        let mut dropped = 0;
        for slot in &mut self.entries {
            if slot.as_ref().is_some_and(|held| held.deadline <= now) {
                *slot = None;
                dropped += 1;
            }
        }
        dropped
    }

    /// How many entries are in use.
    #[must_use]
    pub fn in_flight(&self) -> usize {
        self.entries.iter().flatten().count()
    }

    /// Finds the entry for `key`, starting one if there is room.
    fn find_or_start(&mut self, key: Key, now: u64) -> Result<Option<usize>, NetError> {
        if let Some(index) = self
            .entries
            .iter()
            .position(|slot| slot.as_ref().is_some_and(|held| held.key == key))
        {
            return Ok(Some(index));
        }
        // Only sweep once a slot is actually wanted: an expired entry that
        // nobody needs the room for is harmless, and sweeping on every fragment
        // is work an attacker chooses the rate of.
        self.expire(now);

        let Some(index) = self.entries.iter().position(Option::is_none) else {
            return Err(NetError::Exhausted {
                table: "ipv4 reassembly",
            });
        };
        self.entries[index] = Some(Pending {
            key,
            data: [0u8; MAX],
            received: [0u64; BITMAP_WORDS],
            total: None,
            deadline: now.saturating_add(self.lifetime),
        });
        Ok(Some(index))
    }

    fn held(bitmap: &[u64; BITMAP_WORDS], block: usize) -> bool {
        bitmap
            .get(block / 64)
            .is_some_and(|word| word & (1u64 << (block % 64)) != 0)
    }

    fn hold(bitmap: &mut [u64; BITMAP_WORDS], block: usize) {
        if let Some(word) = bitmap.get_mut(block / 64) {
            *word |= 1u64 << (block % 64);
        }
    }

    /// Whether every block below the known total has arrived.
    fn complete(pending: &Pending<MAX>) -> bool {
        let Some(total) = pending.total else {
            return false;
        };
        (0..total.div_ceil(8)).all(|block| Self::held(&pending.received, block))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SOURCE: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
    const DESTINATION: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
    const SECOND: u64 = 1_000_000_000;

    /// Builds a header with a correct checksum, plus its payload.
    fn datagram(payload: &[u8], identification: u16, offset: usize, more: bool) -> [u8; 128] {
        let mut bytes = [0u8; 128];
        let total = HEADER + payload.len();
        bytes[0] = 0x45;
        bytes[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        bytes[4..6].copy_from_slice(&identification.to_be_bytes());
        let flags = if more { 0x2000u16 } else { 0 };
        bytes[6..8].copy_from_slice(&(flags | (offset / 8) as u16).to_be_bytes());
        bytes[8] = 64;
        bytes[9] = Protocol::UDP.0;
        bytes[12..16].copy_from_slice(&SOURCE.octets());
        bytes[16..20].copy_from_slice(&DESTINATION.octets());
        let sum = checksum(&[&bytes[..10], &[0, 0], &bytes[12..HEADER]]);
        bytes[10..12].copy_from_slice(&sum.to_be_bytes());
        bytes[HEADER..total].copy_from_slice(payload);
        bytes
    }

    fn parse(bytes: &[u8], length: usize) -> (Ipv4Header, &[u8]) {
        Ipv4Header::parse(&bytes[..length]).unwrap()
    }

    #[test]
    fn a_header_parses_and_its_payload_is_exactly_the_stated_length() {
        let bytes = datagram(&[1, 2, 3, 4], 7, 0, false);
        let (header, payload) = parse(&bytes, HEADER + 4);
        assert_eq!(header.source, SOURCE);
        assert_eq!(header.destination, DESTINATION);
        assert_eq!(header.protocol, Protocol::UDP);
        assert_eq!(header.ttl, 64);
        assert_eq!(header.identification, 7);
        assert_eq!(payload, &[1, 2, 3, 4]);
        assert!(!header.is_fragment());
    }

    #[test]
    fn ethernet_padding_after_the_datagram_is_ignored_not_returned() {
        // The whole 128-byte buffer is offered; only the stated four bytes come
        // back. A parser returning the padding hands 104 bytes of somebody
        // else's memory to UDP.
        let bytes = datagram(&[1, 2, 3, 4], 7, 0, false);
        let (_, payload) = Ipv4Header::parse(&bytes).unwrap();
        assert_eq!(payload, &[1, 2, 3, 4]);
    }

    #[test]
    fn a_total_length_longer_than_the_frame_is_refused() {
        let mut bytes = datagram(&[1, 2, 3, 4], 7, 0, false);
        bytes[2..4].copy_from_slice(&600u16.to_be_bytes());
        // The checksum must be repaired or the length check is never reached --
        // the mistake `docs/coding-style.md` §8 records for the DMAR fuzzer.
        let sum = checksum(&[&bytes[..10], &[0, 0], &bytes[12..HEADER]]);
        bytes[10..12].copy_from_slice(&sum.to_be_bytes());
        assert_eq!(
            Ipv4Header::parse(&bytes[..HEADER + 4]),
            Err(NetError::LengthBeyondBuffer {
                stated: 600,
                have: HEADER + 4
            })
        );
    }

    #[test]
    fn the_three_lengths_must_agree() {
        // IHL below the fixed header.
        let mut bytes = datagram(&[1, 2, 3, 4], 7, 0, false);
        bytes[0] = 0x44;
        let sum = checksum(&[&bytes[..10], &[0, 0], &bytes[12..HEADER]]);
        bytes[10..12].copy_from_slice(&sum.to_be_bytes());
        assert!(matches!(
            Ipv4Header::parse(&bytes[..HEADER + 4]),
            Err(NetError::BadHeaderLength { words: 4, .. })
        ));

        // IHL beyond the total length: a header that does not fit its datagram.
        let mut bytes = datagram(&[1, 2, 3, 4], 7, 0, false);
        bytes[0] = 0x4f;
        let sum = checksum(&[&bytes[..10], &[0, 0], &bytes[12..HEADER]]);
        bytes[10..12].copy_from_slice(&sum.to_be_bytes());
        assert!(matches!(
            Ipv4Header::parse(&bytes[..HEADER + 4]),
            Err(NetError::BadHeaderLength { words: 15, .. })
        ));
    }

    #[test]
    fn a_written_header_parses_back_and_its_checksum_verifies() {
        // The writer and the parser are the two halves most likely to disagree
        // about the checksum, because each computes it over a span it decides
        // for itself. A round trip is the cheapest way to keep them honest.
        let mut out = [0u8; 64];
        assert_eq!(
            write_header(&mut out, SOURCE, DESTINATION, Protocol::ICMP, 8, 0x1234).unwrap(),
            HEADER
        );
        out[HEADER..HEADER + 8].copy_from_slice(&[9u8; 8]);
        let (header, payload) = Ipv4Header::parse(&out[..HEADER + 8]).unwrap();
        assert_eq!(header.source, SOURCE);
        assert_eq!(header.destination, DESTINATION);
        assert_eq!(header.protocol, Protocol::ICMP);
        assert_eq!(header.total_length, HEADER + 8);
        assert_eq!(header.identification, 0x1234);
        assert!(header.dont_fragment);
        assert!(!header.is_fragment());
        assert_eq!(payload, &[9u8; 8]);

        // One bit of the header flipped must now fail, which is what says the
        // checksum written was the checksum and not a constant.
        out[8] ^= 0x01;
        assert!(matches!(
            Ipv4Header::parse(&out[..HEADER + 8]),
            Err(NetError::BadChecksum { .. })
        ));
    }

    #[test]
    fn a_header_that_will_not_fit_is_refused() {
        let mut small = [0u8; HEADER - 1];
        assert!(write_header(&mut small, SOURCE, DESTINATION, Protocol::ICMP, 0, 0).is_err());
        let mut out = [0u8; 64];
        assert!(
            write_header(
                &mut out,
                SOURCE,
                DESTINATION,
                Protocol::ICMP,
                MAX_DATAGRAM,
                0
            )
            .is_err()
        );
    }

    #[test]
    fn a_bad_version_and_a_bad_checksum_are_distinguishable() {
        let mut bytes = datagram(&[1, 2, 3, 4], 7, 0, false);
        bytes[0] = 0x65;
        assert_eq!(
            Ipv4Header::parse(&bytes[..HEADER + 4]),
            Err(NetError::BadVersion(6))
        );

        let mut bytes = datagram(&[1, 2, 3, 4], 7, 0, false);
        bytes[10] ^= 0xff;
        assert!(matches!(
            Ipv4Header::parse(&bytes[..HEADER + 4]),
            Err(NetError::BadChecksum { .. })
        ));
    }

    #[test]
    fn two_fragments_reassemble_in_order() {
        let mut table = Reassembly::<2, 512>::new(SECOND);
        let first = datagram(&[0xaa; 8], 1, 0, true);
        let second = datagram(&[0xbb; 4], 1, 8, false);

        let (header, payload) = parse(&first, HEADER + 8);
        assert_eq!(table.offer(&header, payload, 0).unwrap(), None);
        let (header, payload) = parse(&second, HEADER + 4);
        let index = table.offer(&header, payload, 0).unwrap().unwrap();

        let assembled = table.assembled(index).unwrap();
        assert_eq!(assembled.len(), 12);
        assert_eq!(&assembled[..8], &[0xaa; 8]);
        assert_eq!(&assembled[8..], &[0xbb; 4]);
        table.release(index);
        assert_eq!(table.in_flight(), 0);
    }

    #[test]
    fn fragments_arriving_out_of_order_reassemble_the_same() {
        // The last fragment first, so the total length is known before the
        // hole below it is filled -- the ordering that breaks a naive
        // "append as they arrive" implementation.
        let mut table = Reassembly::<2, 512>::new(SECOND);
        let first = datagram(&[0xaa; 8], 2, 0, true);
        let second = datagram(&[0xbb; 4], 2, 8, false);

        let (header, payload) = parse(&second, HEADER + 4);
        assert_eq!(table.offer(&header, payload, 0).unwrap(), None);
        let (header, payload) = parse(&first, HEADER + 8);
        let index = table.offer(&header, payload, 0).unwrap().unwrap();
        assert_eq!(&table.assembled(index).unwrap()[..8], &[0xaa; 8]);
    }

    #[test]
    fn an_overlapping_fragment_cannot_change_a_byte_already_held() {
        // The attack this rule exists for: the same offset claimed twice with
        // different bytes. First writer wins, so the second is discarded.
        let mut table = Reassembly::<2, 512>::new(SECOND);
        let honest = datagram(&[0xaa; 8], 3, 0, true);
        let forged = datagram(&[0xff; 8], 3, 0, true);
        let last = datagram(&[0xbb; 4], 3, 8, false);

        let (header, payload) = parse(&honest, HEADER + 8);
        table.offer(&header, payload, 0).unwrap();
        let (header, payload) = parse(&forged, HEADER + 8);
        table.offer(&header, payload, 0).unwrap();
        let (header, payload) = parse(&last, HEADER + 4);
        let index = table.offer(&header, payload, 0).unwrap().unwrap();

        assert_eq!(&table.assembled(index).unwrap()[..8], &[0xaa; 8]);
    }

    #[test]
    fn a_fragment_past_the_buffer_is_refused_before_anything_is_written() {
        let mut table = Reassembly::<2, 64>::new(SECOND);
        let far = datagram(&[0xaa; 8], 4, 64, true);
        let (header, payload) = parse(&far, HEADER + 8);
        assert_eq!(
            table.offer(&header, payload, 0),
            Err(NetError::LengthBeyondBuffer {
                stated: 72,
                have: 64
            })
        );
        assert_eq!(table.in_flight(), 0);
    }

    #[test]
    fn a_short_middle_fragment_is_refused() {
        let mut table = Reassembly::<2, 512>::new(SECOND);
        let ragged = datagram(&[0xaa; 5], 5, 0, true);
        let (header, payload) = parse(&ragged, HEADER + 5);
        assert!(matches!(
            table.offer(&header, payload, 0),
            Err(NetError::Unsupported { .. })
        ));
    }

    #[test]
    fn a_full_table_refuses_rather_than_evicting_a_datagram_in_progress() {
        // The documented posture, and the opposite of the ARP cache's. Evicting
        // here would let an attacker destroy legitimate reassemblies at will.
        let mut table = Reassembly::<1, 512>::new(SECOND);
        let mine = datagram(&[0xaa; 8], 6, 0, true);
        let (header, payload) = parse(&mine, HEADER + 8);
        table.offer(&header, payload, 0).unwrap();

        let theirs = datagram(&[0xcc; 8], 99, 0, true);
        let (header, payload) = parse(&theirs, HEADER + 8);
        assert_eq!(
            table.offer(&header, payload, 0),
            Err(NetError::Exhausted {
                table: "ipv4 reassembly"
            })
        );

        // And the entry that was there is untouched.
        let last = datagram(&[0xbb; 4], 6, 8, false);
        let (header, payload) = parse(&last, HEADER + 4);
        let index = table.offer(&header, payload, 0).unwrap().unwrap();
        assert_eq!(&table.assembled(index).unwrap()[..8], &[0xaa; 8]);
    }

    #[test]
    fn an_abandoned_datagram_frees_its_slot_when_its_deadline_passes() {
        let mut table = Reassembly::<1, 512>::new(SECOND);
        let abandoned = datagram(&[0xaa; 8], 7, 0, true);
        let (header, payload) = parse(&abandoned, HEADER + 8);
        table.offer(&header, payload, 0).unwrap();
        assert_eq!(table.in_flight(), 1);

        // Still held before the deadline; the table is genuinely full.
        let other = datagram(&[0xcc; 8], 98, 0, true);
        let (header, payload) = parse(&other, HEADER + 8);
        assert!(table.offer(&header, payload, SECOND - 1).is_err());

        // At the deadline the slot comes back and the new datagram is admitted.
        let (header, payload) = parse(&other, HEADER + 8);
        assert!(table.offer(&header, payload, SECOND).is_ok());
        assert_eq!(table.in_flight(), 1);
    }

    #[test]
    fn a_second_disagreeing_last_fragment_is_refused() {
        // Rewriting the datagram's length after bytes have been accepted
        // against the first claim.
        let mut table = Reassembly::<2, 512>::new(SECOND);
        let last = datagram(&[0xbb; 4], 8, 8, false);
        let (header, payload) = parse(&last, HEADER + 4);
        table.offer(&header, payload, 0).unwrap();

        let longer = datagram(&[0xbb; 8], 8, 8, false);
        let (header, payload) = parse(&longer, HEADER + 8);
        assert!(matches!(
            table.offer(&header, payload, 0),
            Err(NetError::LengthBeyondBuffer { .. })
        ));
    }

    #[test]
    fn fragments_of_different_datagrams_do_not_mix() {
        // Keyed on all four fields: a fragment from another source with the
        // same identification must not complete this datagram.
        let mut table = Reassembly::<2, 512>::new(SECOND);
        let mine = datagram(&[0xaa; 8], 9, 0, true);
        let (header, payload) = parse(&mine, HEADER + 8);
        table.offer(&header, payload, 0).unwrap();

        let mut theirs = datagram(&[0xbb; 4], 9, 8, false);
        theirs[12..16].copy_from_slice(&Ipv4Addr::new(10, 0, 0, 9).octets());
        let sum = checksum(&[&theirs[..10], &[0, 0], &theirs[12..HEADER]]);
        theirs[10..12].copy_from_slice(&sum.to_be_bytes());
        let (header, payload) = parse(&theirs, HEADER + 4);

        // It starts its own entry rather than completing the first.
        assert_eq!(table.offer(&header, payload, 0).unwrap(), None);
        assert_eq!(table.in_flight(), 2);
    }
}
