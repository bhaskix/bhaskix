// SPDX-License-Identifier: Apache-2.0
//! SipHash-2-4 — a keyed pseudorandom function, because RFC 6528 requires one.
//!
//! # Why this crate contains a hash at all
//!
//! [RFC 0021](../../docs/rfc/0021-unpredictability.md) said "no cryptographic
//! API", and meant it: `bhaskix-rand` is two `asm!` blocks and a retry loop, and
//! nothing else. That decision is unchanged. What arrived afterwards is a caller
//! with a requirement `RDRAND` alone cannot meet.
//!
//! A TCP initial sequence number is not a random number. RFC 6528's expression
//! is `ISN = M + F(localip, localport, remoteip, remoteport, secretkey)`, and
//! `F` has to be a *function* — the same four-tuple must give the same answer
//! at the same instant, or a reincarnated connection loses the protection
//! against old duplicates the whole construction exists to provide. A fresh draw
//! from the hardware is unpredictable and useless here, because it is not a
//! function of anything.
//!
//! So one keyed hash, in the crate that needs it, rather than a cryptographic
//! library nobody asked for.
//!
//! # Why SipHash-2-4 and not the MD5 the RFC names
//!
//! RFC 6528 §3 says MD5 "would be a good choice", and then says in the same
//! section that implementations "should consider the trade-offs involved in
//! using functions with stronger security properties, and employ them if it is
//! deemed appropriate". This is that consideration, and the trade-offs point one
//! way:
//!
//! - **The requirement is a PRF on a short input, not a message digest.** The
//!   RFC's own demand is that `F` "MUST NOT be computable from the outside";
//!   collision resistance over long messages, which is what a digest buys and
//!   what MD5 has lost, is not what is being asked for.
//! - **It is arithmetic, and this crate is arithmetic.** Four 64-bit words, a
//!   dozen operations a round, no tables, no allocation, no `unsafe` — which
//!   keeps `forbid(unsafe_code)` and the zero budget intact.
//! - **It has published test vectors.** All 64 of them are in this file's test
//!   module, taken from the reference implementation, so the tests compare
//!   against somebody else's arithmetic rather than this file's. A round trip
//!   through one implementation proves only that it is self-consistent, which is
//!   the same reason [`crate::checksum`] is tested against RFC 1071's worked
//!   example.
//! - **The key length is exactly what the RFC asks for.** SipHash takes 128
//!   bits; RFC 6528 says "key lengths of 128 bits should be adequate".
//!
//! Speed is not among the reasons, in either direction. This is computed once
//! per connection.
//!
//! # What this is not
//!
//! **Not a general-purpose hash for this project, and not a cryptographic
//! toolkit.** It is a PRF with one caller. It is not collision-resistant in the
//! sense a digest is, it must never be used to authenticate a message, and a key
//! that leaks makes every sequence number it ever produced predictable — which
//! is why [`Key`] does not print itself.

/// A 128-bit secret key.
///
/// # It does not print itself
///
/// [`Key`] implements `Debug` by hand, and the implementation writes no key
/// material. Every other type in this crate derives `Debug` because a packet
/// field in a log is a debugging aid; a secret in a log is the end of the
/// property this key exists to hold, since RFC 6528 §3 notes that "the result
/// of `F()` is no more secure than the secret key". The derive is left off on
/// purpose, and this comment is here so that adding it later is a decision
/// rather than a tidy-up.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Key {
    k0: u64,
    k1: u64,
}

impl Key {
    /// A key from two words.
    ///
    /// Public because the reference test vectors specify a key, and because a
    /// caller that has its own secret should not have to go through the
    /// hardware to use it. Whether the two words are unpredictable is the
    /// caller's claim, not this constructor's.
    #[must_use]
    pub const fn new(k0: u64, k1: u64) -> Self {
        Self { k0, k1 }
    }

    /// A key drawn from a source of unpredictability, or `None`.
    ///
    /// **Generic over the source, and deliberately not a dependency on
    /// `bhaskix-rand`.** `tools/check-deps.py` puts both crates on layer −2, so
    /// this one *cannot* reach that one — and the layering is right rather than
    /// merely binding: this crate must stay reachable from a host test and a
    /// fuzz target, neither of which has a processor whose `RDRAND` can be made
    /// to fail on demand. Passing the source in is what makes the refusal below
    /// testable at all.
    ///
    /// # The refusal is the point
    ///
    /// `None` from either draw gives `None` here, and no key. A machine that
    /// cannot be unpredictable therefore cannot produce a TCP sequence number,
    /// which is [RFC 0021](../../docs/rfc/0021-unpredictability.md)'s policy —
    /// *the caller refuses* — expressed in a type rather than in a comment. The
    /// second draw is not optional and must not be filled in from the first: a
    /// key whose halves are equal has half the length RFC 6528 asks for.
    ///
    /// The source's signature is `bhaskix_rand::u64`'s, so the one caller that
    /// has hardware passes the function itself and no adapter exists to get
    /// wrong.
    pub fn draw(mut source: impl FnMut() -> Option<u64>) -> Option<Self> {
        let k0 = source()?;
        let k1 = source()?;
        Some(Self::new(k0, k1))
    }
}

impl core::fmt::Debug for Key {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Key(<secret>)")
    }
}

/// Compression rounds — the 2 in SipHash-2-4.
const COMPRESSION_ROUNDS: usize = 2;

/// Finalization rounds — the 4 in SipHash-2-4.
const FINALIZATION_ROUNDS: usize = 4;

/// The initialisation constants: the ASCII of `somepseudorandomlygeneratedbytes`.
const INITIAL: [u64; 4] = [
    0x736f_6d65_7073_6575,
    0x646f_7261_6e64_6f6d,
    0x6c79_6765_6e65_7261,
    0x7465_6462_7974_6573,
];

/// SipHash-2-4 of `message` under `key`.
///
/// The message is read as little-endian 64-bit blocks, with the final block
/// carrying the low byte of the length in its top position — which is what makes
/// `[0x00]` and `[0x00, 0x00]` hash differently, and is the part of this
/// construction easiest to leave out and hardest to notice missing.
#[must_use]
pub fn hash(key: &Key, message: &[u8]) -> u64 {
    let mut state = [
        key.k0 ^ INITIAL[0],
        key.k1 ^ INITIAL[1],
        key.k0 ^ INITIAL[2],
        key.k1 ^ INITIAL[3],
    ];

    let mut blocks = message.chunks_exact(8);
    for block in blocks.by_ref() {
        absorb(&mut state, le64(block));
    }
    // The tail, zero-padded, with the length modulo 256 in the top byte. The
    // tail is at most seven bytes, so the two never overlap.
    let length = (message.len() % 256) as u64;
    absorb(&mut state, le64(blocks.remainder()) | (length << 56));

    state[2] ^= 0xff;
    for _ in 0..FINALIZATION_ROUNDS {
        round(&mut state);
    }
    state[0] ^ state[1] ^ state[2] ^ state[3]
}

/// Mixes one message word into the state.
fn absorb(state: &mut [u64; 4], word: u64) {
    state[3] ^= word;
    for _ in 0..COMPRESSION_ROUNDS {
        round(state);
    }
    state[0] ^= word;
}

/// One SipRound.
///
/// `wrapping_add` rather than `+` because the workspace keeps `overflow-checks`
/// on in release builds, and every addition here is *meant* to wrap — an ARX
/// construction with a panic in it is a remotely-triggerable halt.
fn round(state: &mut [u64; 4]) {
    let [mut v0, mut v1, mut v2, mut v3] = *state;

    v0 = v0.wrapping_add(v1);
    v1 = v1.rotate_left(13);
    v1 ^= v0;
    v0 = v0.rotate_left(32);

    v2 = v2.wrapping_add(v3);
    v3 = v3.rotate_left(16);
    v3 ^= v2;

    v0 = v0.wrapping_add(v3);
    v3 = v3.rotate_left(21);
    v3 ^= v0;

    v2 = v2.wrapping_add(v1);
    v1 = v1.rotate_left(17);
    v1 ^= v2;
    v2 = v2.rotate_left(32);

    *state = [v0, v1, v2, v3];
}

/// Reads up to eight bytes as a little-endian word, zero-padded.
///
/// One function for the full blocks and the tail, so the padding rule is
/// written once. Nothing here indexes past what was supplied: `take` is a
/// minimum, and both slices are taken to it.
fn le64(bytes: &[u8]) -> u64 {
    let mut word = [0u8; 8];
    let take = bytes.len().min(8);
    word[..take].copy_from_slice(&bytes[..take]);
    u64::from_le_bytes(word)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The reference implementation's 64 vectors for SipHash-2-4-64.
    ///
    /// From `vectors.h` in the reference distribution, converted from its
    /// little-endian byte arrays to the words this implementation returns. The
    /// key is bytes `00..0f` and vector `i` is the hash of the `i` bytes
    /// `00, 01, .. i-1`, which is the convention its own `test.c` uses — read
    /// from that file rather than remembered.
    const VECTORS: [u64; 64] = [
        0x726f_db47_dd0e_0e31,
        0x74f8_39c5_93dc_67fd,
        0x0d6c_8009_d9a9_4f5a,
        0x8567_6696_d7fb_7e2d,
        0xcf27_94e0_2771_87b7,
        0x1876_5564_cd99_a68d,
        0xcbc9_466e_58fe_e3ce,
        0xab02_00f5_8b01_d137,
        0x93f5_f579_9a93_2462,
        0x9e00_82df_0ba9_e4b0,
        0x7a5d_bbc5_94dd_b9f3,
        0xf4b3_2f46_226b_ada7,
        0x751e_8fbc_860e_e5fb,
        0x14ea_5627_c084_3d90,
        0xf723_ca90_8e7a_f2ee,
        0xa129_ca61_49be_45e5,
        0x3f2a_cc7f_57c2_9bdb,
        0x699a_e9f5_2cbe_4794,
        0x4bc1_b3f0_968d_d39c,
        0xbb6d_c91d_a779_61bd,
        0xbed6_5cf2_1aa2_ee98,
        0xd0f2_cbb0_2e3b_67c7,
        0x9353_6795_e3a3_3e88,
        0xa80c_038c_cd5c_cec8,
        0xb8ad_50c6_f649_af94,
        0xbce1_92de_8a85_b8ea,
        0x17d8_35b8_5bbb_15f3,
        0x2f2e_6163_076b_cfad,
        0xde4d_aaac_a71d_c9a5,
        0xa6a2_5066_8795_6571,
        0xad87_a353_5c49_ef28,
        0x32d8_92fa_d841_c342,
        0x7127_512f_72f2_7cce,
        0xa7f3_2346_f959_78e3,
        0x12e0_b01a_bb05_1238,
        0x15e0_34d4_0fa1_97ae,
        0x314d_ffbe_0815_a3b4,
        0x0279_90f0_2962_3981,
        0xcadc_d4e5_9ef4_0c4d,
        0x9abf_d876_6a33_735c,
        0x0e3e_a96b_5304_a7d0,
        0xad0c_42d6_fc58_5992,
        0x1873_06c8_9bc2_15a9,
        0xd4a6_0abc_f379_2b95,
        0xf935_451d_e4f2_1df2,
        0xa953_8f04_1975_5787,
        0xdb9a_cddf_f56c_a510,
        0xd06c_98cd_5c09_75eb,
        0xe612_a3cb_9ecb_a951,
        0xc766_e62c_fcad_af96,
        0xee64_435a_9752_fe72,
        0xa192_d576_b245_165a,
        0x0a87_87bf_8ecb_74b2,
        0x81b3_e73d_20b4_9b6f,
        0x7fa8_220b_a3b2_ecea,
        0x2457_31c1_3ca4_2499,
        0xb78d_bfaf_3a8d_83bd,
        0xea1a_d565_322a_1a0b,
        0x60e6_1c23_a379_5013,
        0x6606_d7e4_4628_2b93,
        0x6ca4_ecb1_5c5f_91e1,
        0x9f62_6da1_5c96_25f3,
        0xe51b_3860_8ef2_5f57,
        0x958a_324c_eb06_4572,
    ];

    /// The reference key: bytes `00..0f`, read little-endian in two halves.
    fn reference_key() -> Key {
        let mut bytes = [0u8; 16];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = index as u8;
        }
        let (low, high) = bytes.split_at(8);
        Key::new(
            u64::from_le_bytes(low.try_into().unwrap()),
            u64::from_le_bytes(high.try_into().unwrap()),
        )
    }

    #[test]
    fn every_reference_vector_matches() {
        // The one test that says this is SipHash-2-4 rather than something with
        // the same shape. Every constant, every rotation, the block order, the
        // length byte and the finalization are all pinned by these 64 numbers,
        // and none of them came from this file.
        let key = reference_key();
        let mut message = [0u8; 64];
        for (length, expected) in VECTORS.iter().enumerate() {
            for (index, byte) in message.iter_mut().enumerate().take(length) {
                *byte = index as u8;
            }
            assert_eq!(
                hash(&key, &message[..length]),
                *expected,
                "vector for a {length}-byte message"
            );
        }
    }

    #[test]
    fn the_length_is_part_of_the_hash() {
        // Zero bytes and one zero byte are different messages. Leaving the
        // length out of the final block is the classic omission, and it passes
        // every round-trip test anyone would write.
        let key = reference_key();
        assert_ne!(hash(&key, &[]), hash(&key, &[0]));
        assert_ne!(hash(&key, &[0]), hash(&key, &[0, 0]));
    }

    #[test]
    fn the_key_changes_the_answer() {
        // The property RFC 6528 §3 rests on: without the secret, the same
        // four-tuple gives a different number. One bit of key is enough.
        let message = [1u8, 2, 3, 4, 5];
        let base = hash(&Key::new(0, 0), &message);
        assert_ne!(base, hash(&Key::new(1, 0), &message));
        assert_ne!(base, hash(&Key::new(0, 1), &message));
    }

    #[test]
    fn a_key_needs_both_halves_drawn() {
        // A source that answers once and then refuses must produce no key. The
        // tempting bug is to reuse the first word, which halves a key length
        // the RFC states as a requirement.
        let mut answers = [Some(0x1111_1111_1111_1111u64), None].into_iter();
        assert_eq!(Key::draw(|| answers.next().flatten()), None);

        let mut answers = [None, Some(0x2222_2222_2222_2222u64)].into_iter();
        assert_eq!(Key::draw(|| answers.next().flatten()), None);
    }

    #[test]
    fn a_drawn_key_is_the_two_words_in_order() {
        let mut answers = [Some(1u64), Some(2u64)].into_iter();
        let key = Key::draw(|| answers.next().flatten()).unwrap();
        assert_eq!(key, Key::new(1, 2));
        assert_ne!(key, Key::new(1, 1), "the second draw is not the first");
        assert_ne!(key, Key::new(2, 1), "and the order is not reversed");
    }

    #[test]
    fn a_key_does_not_print_itself() {
        // `Debug` on a secret is how key material reaches a log. Written as a
        // test rather than a comment, because a derive added later would
        // silently undo it.
        let printed = format!(
            "{:?}",
            Key::new(0xdead_beef_dead_beef, 0xfeed_face_feed_face)
        );
        assert!(!printed.contains("dead"), "{printed}");
        assert!(!printed.contains("beef"), "{printed}");
        assert_eq!(printed, "Key(<secret>)");
    }
}
