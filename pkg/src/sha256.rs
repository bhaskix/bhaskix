// SPDX-License-Identifier: Apache-2.0
//! SHA-256, as arithmetic and nothing else.
//!
//! The package format's content identity: every `file` line in a manifest
//! carries the digest of the payload it names, verified before an install
//! writes its record. [RFC 0030](../../docs/rfc/0030-packages.md) is
//! explicit about what that buys — **corruption detection, not tamper
//! resistance**: inside an unsigned archive, whoever rewrites the payload
//! rewrites the hash beside it. The digest becomes load-bearing the day
//! Phase 3's secure-update chain signs the manifest, because a signature
//! over the hash lines is then a signature over everything they name.
//!
//! # Provenance, stated because it matters
//!
//! Written to FIPS 180-4 from reference material rather than derived here,
//! which is exactly the situation the published test vectors exist for: the
//! empty message, `"abc"`, the two-block message and the million-`a` message
//! are all asserted below, and a transcription error in any constant fails
//! them. The streaming and one-shot paths are additionally held equal across
//! every split point of a multi-block message, so the buffering logic cannot
//! drift from the block logic.
//!
//! # Why not a smaller checksum
//!
//! A CRC would detect the same accidental corruption for less arithmetic —
//! and would have to be ripped out the day signatures arrive, because a
//! signature over a CRC certifies nothing. Content identity is written once,
//! in the form the future consumer needs.

/// Bytes in a digest.
pub const DIGEST: usize = 32;

/// Bytes in one compression block.
const BLOCK: usize = 64;

/// The round constants: the fractional parts of the cube roots of the first
/// sixty-four primes, as FIPS 180-4 §4.2.2 lists them.
const K: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

/// The initial state: the fractional parts of the square roots of the first
/// eight primes, FIPS 180-4 §5.3.3.
const H0: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

/// A digest in progress. Feed it with [`Sha256::update`], close it with
/// [`Sha256::finish`]; [`digest`] is the one-shot form.
///
/// Streaming exists because the install path hashes a payload as it copies
/// it page by page — holding the whole file to hash it would make the
/// verify-before-record promise cost a second buffer.
pub struct Sha256 {
    state: [u32; 8],
    /// Bytes not yet forming a full block.
    buffer: [u8; BLOCK],
    /// How much of `buffer` is real.
    buffered: usize,
    /// Total message bytes seen, for the length trailer.
    length: u64,
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256 {
    /// An empty digest, ready for bytes.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: H0,
            buffer: [0; BLOCK],
            buffered: 0,
            length: 0,
        }
    }

    /// Absorbs `bytes`.
    pub fn update(&mut self, bytes: &[u8]) {
        self.length = self.length.wrapping_add(bytes.len() as u64);
        let mut rest = bytes;

        // Top up a partial block first. If the input is consumed entirely
        // into the buffer, stop here: falling through would overwrite
        // `buffered` with the empty remainder's length -- which is exactly
        // what the first run of this file did, and every digest hung in
        // `finish`'s pad loop with `buffered` pinned to zero.
        if self.buffered > 0 {
            let take = rest.len().min(BLOCK - self.buffered);
            self.buffer[self.buffered..self.buffered + take].copy_from_slice(&rest[..take]);
            self.buffered += take;
            rest = &rest[take..];
            if self.buffered == BLOCK {
                let block = self.buffer;
                self.compress(&block);
                self.buffered = 0;
            }
            if rest.is_empty() {
                return;
            }
        }

        // Whole blocks straight from the input.
        while rest.len() >= BLOCK {
            let (block, tail) = rest.split_at(BLOCK);
            let mut owned = [0u8; BLOCK];
            owned.copy_from_slice(block);
            self.compress(&owned);
            rest = tail;
        }

        // The remainder waits.
        self.buffer[..rest.len()].copy_from_slice(rest);
        self.buffered = rest.len();
    }

    /// Closes the message — the `0x80` byte, the zero pad, the bit length —
    /// and returns the digest.
    #[must_use]
    pub fn finish(mut self) -> [u8; DIGEST] {
        let bit_length = self.length.wrapping_mul(8);
        self.update(&[0x80]);
        while self.buffered != BLOCK - 8 {
            self.update(&[0]);
        }
        // Not through `update`: the trailer is not message bytes and must not
        // count toward the length it encodes.
        self.buffer[BLOCK - 8..].copy_from_slice(&bit_length.to_be_bytes());
        let block = self.buffer;
        self.compress(&block);

        let mut out = [0u8; DIGEST];
        for (chunk, word) in out.as_chunks_mut::<4>().0.iter_mut().zip(self.state) {
            *chunk = word.to_be_bytes();
        }
        out
    }

    /// One block through the compression function, FIPS 180-4 §6.2.2.
    fn compress(&mut self, block: &[u8; BLOCK]) {
        let mut w = [0u32; 64];
        for (index, chunk) in block.as_chunks::<4>().0.iter().enumerate() {
            w[index] = u32::from_be_bytes(*chunk);
        }
        for index in 16..64 {
            let s0 = w[index - 15].rotate_right(7)
                ^ w[index - 15].rotate_right(18)
                ^ (w[index - 15] >> 3);
            let s1 = w[index - 2].rotate_right(17)
                ^ w[index - 2].rotate_right(19)
                ^ (w[index - 2] >> 10);
            w[index] = w[index - 16]
                .wrapping_add(s0)
                .wrapping_add(w[index - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;
        for index in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[index])
                .wrapping_add(w[index]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        for (slot, value) in self.state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *slot = slot.wrapping_add(value);
        }
    }
}

/// The digest of `bytes`, in one call.
#[must_use]
pub fn digest(bytes: &[u8]) -> [u8; DIGEST] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Renders a digest as lowercase hex, for comparison with the vectors.
    fn hex(digest: [u8; DIGEST]) -> std::string::String {
        digest
            .iter()
            .map(|byte| std::format!("{byte:02x}"))
            .collect()
    }

    #[test]
    fn the_empty_message_matches_the_published_vector() {
        assert_eq!(
            hex(digest(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn abc_matches_the_published_vector() {
        assert_eq!(
            hex(digest(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn the_two_block_message_matches_the_published_vector() {
        assert_eq!(
            hex(digest(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn one_million_a_matches_the_published_vector() {
        let mut hasher = Sha256::new();
        let chunk = [b'a'; 1000];
        for _ in 0..1000 {
            hasher.update(&chunk);
        }
        assert_eq!(
            hex(hasher.finish()),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    #[test]
    fn streaming_equals_one_shot_at_every_split_point() {
        // The buffering logic cannot drift from the block logic if every way
        // of slicing a message across the block boundary gives one answer.
        // 150 bytes spans two boundaries and the length-trailer edge.
        let message: std::vec::Vec<u8> = (0u8..150).collect();
        let whole = digest(&message);
        for split in 0..=message.len() {
            let mut hasher = Sha256::new();
            hasher.update(&message[..split]);
            hasher.update(&message[split..]);
            assert_eq!(hasher.finish(), whole, "split at {split}");
        }
    }

    #[test]
    fn the_padding_edge_lengths_agree_between_paths() {
        // 55, 56, 63, 64 and 119 bytes are where the 0x80 byte and the length
        // trailer land in every distinct arrangement. No external vector for
        // these; what is asserted is that byte-at-a-time streaming agrees
        // with the one-shot path, which exercises the pad arithmetic twice
        // by different routes.
        for length in [55usize, 56, 63, 64, 119, 120] {
            let message: std::vec::Vec<u8> = (0..length).map(|i| i as u8).collect();
            let mut hasher = Sha256::new();
            for byte in &message {
                hasher.update(core::slice::from_ref(byte));
            }
            assert_eq!(hasher.finish(), digest(&message), "length {length}");
        }
    }
}
