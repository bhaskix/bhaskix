// SPDX-License-Identifier: Apache-2.0
//! The schema registry: typed, versioned, hashed at build time.
//!
//! A schema names a payload format. The registry is a `const` table both the
//! kernel and every consumer compile against, and [`registry_hash`] is the
//! sentence that keeps them honest: the kernel writes the hash into every
//! ring's header, and a reader whose own registry hashes differently
//! **refuses to decode** instead of misreading structurally. Rewording a
//! payload is a version bump; a version bump changes the hash; a stale tool
//! says so instead of lying — which is the "typed, versioned, never text"
//! rule of [ai-native.md](../../docs/ai-native.md) §2 with its enforcement
//! attached.

use crate::PAYLOAD_BYTES;

/// One registered payload format.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Schema {
    /// The id events carry. Never reused, never renumbered.
    pub id: u32,
    /// Bumped on any change to the payload's meaning or layout.
    pub version: u16,
    /// Bytes of payload this schema reads. At most [`PAYLOAD_BYTES`],
    /// enforced by a compile-time check on the whole table.
    pub size: u8,
    /// For humans and reports. Not part of the wire format.
    pub name: &'static str,
}

/// The probe schema, RFC 0026 step 3's round-trip self-test: a marker word
/// the test chooses and a sequence number, so the reader can prove it saw
/// exactly the marked set — nothing missing, nothing invented.
pub const PROBE: Schema = Schema {
    id: 1,
    version: 1,
    size: 16,
    name: "probe",
};

/// The scheduler's dispatch event, RFC 0026 step 2's first producer: the
/// outgoing thread id, then the incoming, as two little-endian `u32`s. The
/// event's own header carries when, which CPU, and the incoming domain.
pub const DISPATCH: Schema = Schema {
    id: 2,
    version: 1,
    size: 8,
    name: "sched-dispatch",
};

/// Every schema this build knows. Extended in place as producers arrive
/// (RFC 0026 steps 2 and 5); ids are append-only.
pub static SCHEMAS: &[Schema] = &[PROBE, DISPATCH];

/// The table is checked at compile time: no payload wider than a slot's
/// payload field, no duplicate ids. A build that violates either does not
/// exist to be debugged.
const _: () = {
    let mut at = 0;
    while at < SCHEMAS.len() {
        assert!(SCHEMAS[at].size as usize <= PAYLOAD_BYTES);
        let mut other = at + 1;
        while other < SCHEMAS.len() {
            assert!(SCHEMAS[at].id != SCHEMAS[other].id);
            other += 1;
        }
        at += 1;
    }
};

/// The registry entry an id names, or `None` for a stranger.
#[must_use]
pub const fn find(id: u32) -> Option<&'static Schema> {
    let mut at = 0;
    while at < SCHEMAS.len() {
        if SCHEMAS[at].id == id {
            return Some(&SCHEMAS[at]);
        }
        at += 1;
    }
    None
}

/// FNV-1a over every entry — id, version, size, name — computed at build
/// time. Two builds agree on this exactly when they agree on how to read
/// every event.
#[must_use]
pub const fn registry_hash() -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    let mut at = 0;
    while at < SCHEMAS.len() {
        hash = fnv_bytes(hash, &SCHEMAS[at].id.to_le_bytes());
        hash = fnv_bytes(hash, &SCHEMAS[at].version.to_le_bytes());
        hash = fnv_bytes(hash, &[SCHEMAS[at].size]);
        hash = fnv_bytes(hash, SCHEMAS[at].name.as_bytes());
        at += 1;
    }
    hash
}

/// One FNV-1a pass over `bytes`, `const` so the hash exists before any code
/// runs.
const fn fnv_bytes(mut hash: u64, bytes: &[u8]) -> u64 {
    let mut at = 0;
    while at < bytes.len() {
        hash ^= bytes[at] as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01B3);
        at += 1;
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_answers_for_every_registered_id_and_refuses_strangers() {
        for entry in SCHEMAS {
            assert_eq!(find(entry.id), Some(entry));
        }
        assert_eq!(find(0), None);
        assert_eq!(find(u32::MAX), None);
    }

    #[test]
    fn the_hash_moves_when_any_field_of_any_entry_moves() {
        // The real registry is `const`, so the variations are hashed by the
        // same arithmetic over a scratch table — proving the hash covers
        // every field, which is what lets a reader trust it as "we agree on
        // how to read every event".
        const fn hash_of(entries: &[Schema]) -> u64 {
            let mut hash = 0xcbf2_9ce4_8422_2325u64;
            let mut at = 0;
            while at < entries.len() {
                hash = fnv_bytes(hash, &entries[at].id.to_le_bytes());
                hash = fnv_bytes(hash, &entries[at].version.to_le_bytes());
                hash = fnv_bytes(hash, &[entries[at].size]);
                hash = fnv_bytes(hash, entries[at].name.as_bytes());
                at += 1;
            }
            hash
        }
        let base = [PROBE, DISPATCH];
        assert_eq!(hash_of(&base), registry_hash(), "same table, same hash");

        // Each variation changes exactly one field of one entry, keeping the
        // table's shape — so a differing hash convicts the field, not the
        // length.
        let bumped_version = [
            Schema {
                version: 2,
                ..base[0]
            },
            DISPATCH,
        ];
        let widened = [
            Schema {
                size: 17,
                ..base[0]
            },
            DISPATCH,
        ];
        let renamed = [
            Schema {
                name: "probf",
                ..base[0]
            },
            DISPATCH,
        ];
        let renumbered = [Schema { id: 3, ..base[0] }, DISPATCH];
        assert_ne!(hash_of(&bumped_version), hash_of(&base));
        assert_ne!(hash_of(&widened), hash_of(&base));
        assert_ne!(hash_of(&renamed), hash_of(&base));
        assert_ne!(hash_of(&renumbered), hash_of(&base));
    }
}
