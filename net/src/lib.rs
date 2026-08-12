// SPDX-License-Identifier: Apache-2.0
//! Ethernet, ARP, IPv4 and UDP, as arithmetic over a byte slice.
//!
//! [RFC 0018](../../docs/rfc/0018-networking.md) step 1. This is the whole of
//! the protocol code, and deliberately none of the machinery around it: no
//! device, no domain, no IPC, no clock. A caller supplies bytes and, where
//! something ages, the current time; everything here is a pure function or a
//! fixed table.
//!
//! # This is the most exposed code in the system
//!
//! Every other untrusted input Bhaskix parses arrives from a *medium* — an ELF
//! image, a `ustar` archive, a `DMAR` table, a filesystem — controlled by
//! whoever can write the boot device. Serious, and bounded: it arrives once, at
//! rest, at a moment the system chooses.
//!
//! These bytes arrive continuously, from anyone who can reach the wire, at line
//! rate. A bug in `elf::parse` needs an attacker who can already write your
//! disk. A bug in the IPv4 header parser needs nobody. That is the reason this
//! crate exists separately from the driver that receives the frames, and the
//! reason its `unsafe` budget is zero and `forbid`den rather than merely
//! declared.
//!
//! # Nothing here indexes without checking
//!
//! No length read out of a packet is trusted, no offset is used before it is
//! compared against what was actually supplied, and no arithmetic on a
//! field-derived quantity is allowed to wrap silently. Where a length could
//! exceed a buffer the error carries both numbers, because
//! `docs/coding-style.md` §4 asks for errors that can be debugged at 3 a.m.
//!
//! # No allocation
//!
//! Everything works over `&[u8]`, and the two pieces of state — the ARP cache
//! and the fragment reassembly table — are fixed-size and generic over their
//! capacity. A fixed table's failure is a refusal; a growing one's failure is
//! somebody else's out-of-memory, and every byte that would grow it is chosen
//! by a remote party.
// `std` under `cfg(test)` only, so the seeded mutation harness in `fuzz` can
// read `BHASKIX_FUZZ_ITERATIONS` the way every other harness in this tree does.
// Nothing that ships sees it: the crate is `no_std` in every build that is not
// a host test, which is the same arrangement `boot/handoff` uses.
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]
// Tests are exempt from the `unwrap`/`expect`/`panic` bans, as
// `docs/coding-style.md` §3 and §4 specify: those bans exist to stop a fallible
// operation taking down a service, and a test that cannot panic cannot fail.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod addr;
pub mod arp;
pub mod eth;
pub mod icmp;
pub mod ipv4;
pub mod udp;

#[cfg(test)]
mod fuzz;

pub use addr::{Address, Ipv4Addr, MacAddr, Port};
pub use arp::{ArpCache, ArpOp, ArpPacket};
pub use eth::{EthFrame, EtherType};
pub use icmp::Echo;
pub use ipv4::{Ipv4Header, Protocol, Reassembly};
pub use udp::UdpDatagram;

/// Everything that can be wrong with a packet.
///
/// One enum for the crate, as `docs/coding-style.md` §4 requires, and every
/// variant carries what a reader would otherwise have to guess. A counter of
/// `BadChecksum` says a link is unreliable; a counter of `BadChecksum` that
/// records what was computed and what was carried says whether it is one bit or
/// a byte order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetError {
    /// Fewer bytes were supplied than the layer's fixed header needs.
    Truncated {
        /// Bytes the header requires.
        need: usize,
        /// Bytes actually supplied.
        have: usize,
    },
    /// A length read out of the packet reaches past the bytes supplied.
    ///
    /// Distinct from [`NetError::Truncated`], which is about a *fixed* header
    /// being short. This one is the packet claiming a size it did not bring,
    /// which is the shape of a great many parser bugs and is worth counting
    /// separately from a merely clipped frame.
    LengthBeyondBuffer {
        /// The length the packet stated.
        stated: usize,
        /// Bytes actually supplied.
        have: usize,
    },
    /// An internet header length shorter than the header it describes, or
    /// longer than the total length that contains it.
    BadHeaderLength {
        /// The `IHL` field, in 32-bit words, as carried.
        words: u8,
        /// The total length the same header stated, in bytes.
        total: usize,
    },
    /// The IP version field was not 4.
    BadVersion(u8),
    /// A header checksum did not verify.
    BadChecksum {
        /// What this implementation computed.
        computed: u16,
        /// What the packet carried.
        carried: u16,
    },
    /// A field that names a protocol carried a value this crate does not parse.
    ///
    /// Not a malformed packet: an unsupported one. A caller may reasonably
    /// count these and continue, where the others usually mean drop it.
    Unsupported {
        /// Which field — an EtherType, an ARP hardware type, an IP protocol.
        field: &'static str,
        /// The value carried.
        value: u32,
    },
    /// A fixed table had no room, and growing it is not an option this system
    /// takes with remotely-supplied data.
    Exhausted {
        /// Which table.
        table: &'static str,
    },
}

/// The one's-complement sum used by every checksum in this crate.
///
/// # Why it is written once
///
/// IPv4 and UDP use the same arithmetic over different spans, and two copies of
/// a checksum are two chances to fold the carry differently. The rule
/// `docs/coding-style.md` §3 states for `unsafe` — one reviewed abstraction
/// beats fifty individually-correct copies — applies to arithmetic somebody
/// else's bytes drive, for the same reason.
///
/// Odd-length spans are padded with a zero byte on the right, which is what the
/// specification requires and is easy to get wrong by padding on the left.
#[must_use]
pub fn checksum(spans: &[&[u8]]) -> u16 {
    let mut sum: u32 = 0;
    // Carried between spans, because a pseudo-header and a payload may each
    // have an odd length and the pair is summed as one stream. Summing them
    // independently and adding the results pads in the middle, which is a
    // different number.
    let mut pending: Option<u8> = None;

    for span in spans {
        let mut bytes = *span;
        if let Some(high) = pending.take() {
            if let Some((low, rest)) = bytes.split_first() {
                sum += u32::from(u16::from_be_bytes([high, *low]));
                bytes = rest;
            } else {
                pending = Some(high);
                continue;
            }
        }
        let mut chunks = bytes.chunks_exact(2);
        for pair in &mut chunks {
            sum += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
        }
        if let Some(&odd) = chunks.remainder().first() {
            pending = Some(odd);
        }
    }
    if let Some(high) = pending {
        sum += u32::from(u16::from_be_bytes([high, 0]));
    }

    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Reads a big-endian `u16` at `offset`, or `None` if it would run past `bytes`.
///
/// Every multi-byte field in every header here goes through this or its 32-bit
/// sibling. A parser that indexes directly is one refactor away from indexing
/// past the end, and this crate's whole subject is bytes chosen by someone who
/// would like it to.
#[must_use]
pub(crate) fn be16(bytes: &[u8], offset: usize) -> Option<u16> {
    let end = offset.checked_add(2)?;
    let slice = bytes.get(offset..end)?;
    Some(u16::from_be_bytes([slice[0], slice[1]]))
}

/// Reads a big-endian `u32` at `offset`, or `None` if it would run past `bytes`.
#[must_use]
pub(crate) fn be32(bytes: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    let slice = bytes.get(offset..end)?;
    Some(u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_of_a_known_header() {
        // RFC 1071's worked example: the sum of these bytes is 0xddf2, so the
        // one's complement is 0x220d. A fixed vector rather than a round trip,
        // because a round trip through the same code proves only that it is
        // self-consistent.
        let bytes = [0x00u8, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        assert_eq!(checksum(&[&bytes]), 0x220d);
    }

    #[test]
    fn checksum_pads_an_odd_span_on_the_right() {
        // 0x0100 is the odd byte 0x01 padded on the right. Padding on the left
        // would give 0x0001, a different sum, and is the classic way to get
        // this wrong.
        assert_eq!(checksum(&[&[0x01u8]]), !0x0100u16);
    }

    #[test]
    fn a_split_span_sums_as_one_stream() {
        // The property that makes the pseudo-header work: where the split falls
        // must not change the answer.
        let whole = [0x01u8, 0x02, 0x03, 0x04, 0x05];
        assert_eq!(checksum(&[&whole]), checksum(&[&whole[..1], &whole[1..]]));
        assert_eq!(checksum(&[&whole]), checksum(&[&whole[..2], &whole[2..]]));
        assert_eq!(checksum(&[&whole]), checksum(&[&whole[..3], &whole[3..]]));
    }

    #[test]
    fn reading_past_the_end_is_none_not_a_panic() {
        let bytes = [0u8; 4];
        // The last field that fits, and the first that does not. A reader that
        // checked `offset < len` rather than `offset + width <= len` passes the
        // first of each pair and fails the second.
        assert!(be16(&bytes, 2).is_some());
        assert!(be16(&bytes, 3).is_none());
        assert!(be32(&bytes, 0).is_some());
        assert!(be32(&bytes, 1).is_none());
        // The offsets that make `offset + width` wrap rather than exceed. These
        // are the ones a bare comparison misses entirely, because the sum is
        // small again by the time it is compared.
        assert!(be16(&bytes, usize::MAX).is_none());
        assert!(be32(&bytes, usize::MAX - 1).is_none());
    }
}
