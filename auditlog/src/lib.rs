// SPDX-License-Identifier: Apache-2.0
//! The audit log as it is kept, and the check that it was not quietly edited
//! -- RFC 0101 steps 2 and 3.
//!
//! `bin/auditd` drains the kernel's audit ring and appends each record here
//! as an [`Entry`]: the record, the link before it, and its own link, where a
//! link is the SHA-256 of the previous link and the record. A record changed,
//! removed, inserted or moved breaks the chain *at that record*, and
//! [`verify`] names it.
//!
//! What a chain cannot show, and this crate does not claim: that the whole
//! log was not replaced by another valid chain. Anchoring the head where an
//! attacker cannot rewrite it is the later RFC the lead deferred it to.
//!
//! Here rather than in `bhaskix-telemetry` so that the kernel, which links
//! that crate, stays free of a hash function (RFC 0101 design item 2).

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

use bhaskix_sha256::Sha256;
use bhaskix_telemetry::audit::{Kind, RECORD_BYTES, Record};

/// Bytes of one link.
pub const LINK_BYTES: usize = 32;

/// Bytes of one kept entry: the record, the link before it, its own link.
/// A power of two, so a 4,096-byte block holds exactly 32 and an entry never
/// straddles one.
pub const ENTRY_BYTES: usize = RECORD_BYTES + 2 * LINK_BYTES;

/// The link before a boot's first record.
pub const GENESIS: [u8; LINK_BYTES] = [0; LINK_BYTES];

/// Domain separation: a link is never the digest of some other structure
/// that happens to have the same bytes.
const LABEL: &[u8; 8] = b"BHXAUDIT";

/// The link after `record`, given the one before it.
#[must_use]
pub fn link(previous: &[u8; LINK_BYTES], record: &[u8; RECORD_BYTES]) -> [u8; LINK_BYTES] {
    let mut hasher = Sha256::new();
    hasher.update(LABEL);
    hasher.update(previous);
    hasher.update(record);
    hasher.finish()
}

/// One kept entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    /// The record, as the ring held it.
    pub record: [u8; RECORD_BYTES],
    /// The link before it: [`GENESIS`] for a boot's first.
    pub previous: [u8; LINK_BYTES],
    /// Its own link.
    pub link: [u8; LINK_BYTES],
}

impl Entry {
    /// The kept form.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; ENTRY_BYTES] {
        let mut bytes = [0u8; ENTRY_BYTES];
        bytes[..RECORD_BYTES].copy_from_slice(&self.record);
        bytes[RECORD_BYTES..RECORD_BYTES + LINK_BYTES].copy_from_slice(&self.previous);
        bytes[RECORD_BYTES + LINK_BYTES..].copy_from_slice(&self.link);
        bytes
    }

    /// Reads a kept entry back. Total: checking it is [`verify`]'s job.
    #[must_use]
    pub fn from_bytes(bytes: &[u8; ENTRY_BYTES]) -> Self {
        let mut entry = Self {
            record: [0; RECORD_BYTES],
            previous: [0; LINK_BYTES],
            link: [0; LINK_BYTES],
        };
        entry.record.copy_from_slice(&bytes[..RECORD_BYTES]);
        entry
            .previous
            .copy_from_slice(&bytes[RECORD_BYTES..RECORD_BYTES + LINK_BYTES]);
        entry
            .link
            .copy_from_slice(&bytes[RECORD_BYTES + LINK_BYTES..]);
        entry
    }
}

/// The writer's side: the head so far, and how many records it covers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Chain {
    head: [u8; LINK_BYTES],
    records: u64,
}

impl Default for Chain {
    fn default() -> Self {
        Self::new()
    }
}

impl Chain {
    /// A chain with nothing in it.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            head: GENESIS,
            records: 0,
        }
    }

    /// Appends one record, and returns the entry to keep.
    pub fn append(&mut self, record: &[u8; RECORD_BYTES]) -> Entry {
        let previous = self.head;
        self.head = link(&previous, record);
        self.records += 1;
        Entry {
            record: *record,
            previous,
            link: self.head,
        }
    }

    /// The link after the last record.
    #[must_use]
    pub const fn head(&self) -> [u8; LINK_BYTES] {
        self.head
    }

    /// Records appended.
    #[must_use]
    pub const fn records(&self) -> u64 {
        self.records
    }
}

/// Where and why a kept log stops being the one that was written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Break {
    /// Its length is not a whole number of entries: `bytes` is what is left.
    Torn {
        /// Bytes past the last whole entry.
        bytes: usize,
    },
    /// An entry's stored link before it is not the link the entries before
    /// it compute to: something before it, or this, was removed, inserted
    /// or moved.
    Previous {
        /// The entry's place in the file.
        index: u64,
    },
    /// An entry's record and its stored link disagree: the record, or its
    /// link, was changed.
    Link {
        /// The entry's place in the file.
        index: u64,
    },
    /// A record's sequence is not its place: the ring's order is not the
    /// file's.
    Sequence {
        /// The entry's place in the file.
        index: u64,
        /// The sequence it carries.
        found: u64,
    },
    /// The first record is not the attach record that names the boot.
    NoAttach,
}

/// What a whole, unbroken log says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Verified {
    /// Records in it.
    pub records: u64,
    /// The link after the last.
    pub head: [u8; LINK_BYTES],
    /// The boot it names, from its first record.
    pub boot: [u64; 2],
    /// Operations the kernel could not record, summed over its gap records.
    pub gaps: u64,
    /// Operations before the reader attached, from its first record.
    pub before: u64,
}

/// Checks a kept log, and names the first entry that breaks it.
///
/// # Errors
///
/// The first [`Break`], in file order.
pub fn verify(bytes: &[u8]) -> Result<Verified, Break> {
    let torn = bytes.len() % ENTRY_BYTES;
    let mut chain = Chain::new();
    let mut verified = Verified {
        records: 0,
        head: GENESIS,
        boot: [0; 2],
        gaps: 0,
        before: 0,
    };
    for (index, whole) in bytes.as_chunks::<ENTRY_BYTES>().0.iter().enumerate() {
        let index = index as u64;
        let entry = Entry::from_bytes(whole);
        if entry.previous != chain.head() {
            return Err(Break::Previous { index });
        }
        if link(&entry.previous, &entry.record) != entry.link {
            return Err(Break::Link { index });
        }
        let record = Record::from_bytes(&entry.record);
        if record.sequence != index {
            return Err(Break::Sequence {
                index,
                found: record.sequence,
            });
        }
        if index == 0 {
            if record.kind != Kind::Attach as u8 {
                return Err(Break::NoAttach);
            }
            verified.boot = [record.subject, record.source];
            verified.before = u64::from(record.count);
        } else if record.kind == Kind::Gap as u8 {
            verified.gaps += u64::from(record.count);
        }
        chain.append(&entry.record);
    }
    if torn != 0 {
        return Err(Break::Torn { bytes: torn });
    }
    verified.records = chain.records();
    verified.head = chain.head();
    Ok(verified)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn log(records: u64) -> Vec<u8> {
        let mut chain = Chain::new();
        let mut bytes = Vec::new();
        for sequence in 0..records {
            let record = Record {
                sequence,
                kind: if sequence == 0 {
                    Kind::Attach as u8
                } else if sequence == 3 {
                    Kind::Gap as u8
                } else {
                    Kind::Grant as u8
                },
                count: if sequence == 0 { 40 } else { 2 },
                subject: if sequence == 0 { 0xB007 } else { sequence },
                source: if sequence == 0 { 0x1D } else { 0 },
                ..Record::default()
            };
            bytes.extend_from_slice(&chain.append(&record.to_bytes()).to_bytes());
        }
        bytes
    }

    #[test]
    fn a_whole_log_verifies_and_says_what_it_holds() {
        let bytes = log(10);
        let verified = verify(&bytes).unwrap();
        assert_eq!(verified.records, 10);
        assert_eq!(verified.boot, [0xB007, 0x1D]);
        assert_eq!(verified.before, 40);
        assert_eq!(verified.gaps, 2, "the one gap record's count");
        // The head is the last entry's link, which the writer reported.
        let last = Entry::from_bytes(bytes[9 * ENTRY_BYTES..].try_into().unwrap());
        assert_eq!(verified.head, last.link);
    }

    #[test]
    fn an_empty_log_is_whole_and_holds_nothing() {
        assert_eq!(verify(&[]).unwrap().records, 0);
    }

    #[test]
    fn every_byte_of_every_entry_is_covered() {
        // One byte changed anywhere breaks the chain at that entry or at the
        // one after it -- never later, and never not at all.
        let bytes = log(6);
        for at in 0..bytes.len() {
            let mut changed = bytes.clone();
            changed[at] ^= 0x01;
            let index = (at / ENTRY_BYTES) as u64;
            match verify(&changed) {
                Ok(_) => panic!("byte {at} changed and the log still verified"),
                Err(Break::Previous { index: found } | Break::Link { index: found }) => {
                    assert!(found == index || found == index + 1, "byte {at}: {found}");
                }
                Err(Break::Sequence { index: found, .. }) => assert_eq!(found, index),
                Err(Break::NoAttach) => assert_eq!(index, 0),
                Err(other) => panic!("byte {at}: {other:?}"),
            }
        }
    }

    #[test]
    fn a_record_removed_moved_or_inserted_is_named_where_it_happened() {
        let bytes = log(6);
        let entry = |i: usize| bytes[i * ENTRY_BYTES..(i + 1) * ENTRY_BYTES].to_vec();

        let mut removed = bytes[..2 * ENTRY_BYTES].to_vec();
        removed.extend_from_slice(&bytes[3 * ENTRY_BYTES..]);
        assert_eq!(verify(&removed), Err(Break::Previous { index: 2 }));

        let mut swapped = bytes[..2 * ENTRY_BYTES].to_vec();
        swapped.extend(entry(3));
        swapped.extend(entry(2));
        swapped.extend_from_slice(&bytes[4 * ENTRY_BYTES..]);
        assert_eq!(verify(&swapped), Err(Break::Previous { index: 2 }));

        let mut inserted = bytes[..4 * ENTRY_BYTES].to_vec();
        inserted.extend(entry(1));
        inserted.extend_from_slice(&bytes[4 * ENTRY_BYTES..]);
        assert_eq!(verify(&inserted), Err(Break::Previous { index: 4 }));
    }

    #[test]
    fn a_torn_tail_and_a_missing_attach_are_named() {
        let bytes = log(3);
        assert_eq!(
            verify(&bytes[..bytes.len() - 5]),
            Err(Break::Torn {
                bytes: ENTRY_BYTES - 5
            })
        );
        // A chain that is whole but does not begin by naming its boot.
        let mut chain = Chain::new();
        let grant = Record {
            kind: Kind::Grant as u8,
            ..Record::default()
        };
        let headless = chain.append(&grant.to_bytes()).to_bytes();
        assert_eq!(verify(&headless), Err(Break::NoAttach));
    }

    #[test]
    fn a_link_is_the_digest_of_its_label_its_predecessor_and_its_record() {
        // Pinned to bytes, so a reader in another language can check one.
        let record = [0x5Au8; RECORD_BYTES];
        let mut input = Vec::new();
        input.extend_from_slice(b"BHXAUDIT");
        input.extend_from_slice(&GENESIS);
        input.extend_from_slice(&record);
        assert_eq!(link(&GENESIS, &record), bhaskix_sha256::digest(&input));
    }
}
