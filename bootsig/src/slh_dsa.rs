// SPDX-License-Identifier: Apache-2.0
//! SLH-DSA-SHA2-128s **verification** (FIPS 205), and nothing else.
//!
//! One parameter set, the one [RFC 0091](../../docs/rfc/0091-a-boot-its-owner-signed.md)'s
//! lead chose on 2026-10-29. No signing: nothing secret enters this module,
//! so verification is public-data work and is not required to run in
//! constant time (RFC 0091, *Verification is public-data work*).
//!
//! # Where every line comes from
//!
//! FIPS 205 (August 2024), read 2026-10-29: each function below names the
//! algorithm it implements, and keeps its steps in the standard's order and
//! its variable names where Rust allows them. The parameters are Table 2's
//! row for SLH-DSA-SHA2-128s. The hash functions are §11.2.1's, over the
//! 22-byte compressed address of §11.2's Table 3. MGF1 is RFC 8017 §B.2.1's.
//!
//! Only what verification calls is here: `F`, `H`, `T_l` and `H_msg`. `PRF` and
//! `PRF_msg` (the HMAC) are signing's, and are absent on purpose.
//!
//! # What proves it
//!
//! NIST's ACVP vectors for this parameter set, both the external ("pure")
//! and the internal interface. Each group has two valid signatures and two of
//! each of the six labelled ways a signature can be wrong. A transcription
//! error anywhere on the verification path fails the valid ones.

use bhaskix_sha256::{DIGEST, Sha256};

/// Security parameter: bytes in a hash value (Table 2).
pub const N: usize = 16;
/// Total height of the hypertree (Table 2's `h`).
pub const HEIGHT: usize = 63;
/// Layers in the hypertree (Table 2's `d`).
pub const D: usize = 7;
/// Height of one XMSS tree (Table 2's `h′`).
pub const H_PRIME: usize = 9;
/// Height of one FORS tree (Table 2's `a`).
pub const A: usize = 12;
/// Trees in a FORS key (Table 2's `k`).
pub const K: usize = 14;
/// Bits per WOTS⁺ digit (Table 2's `lg_w`).
pub const LG_W: usize = 4;
/// Bytes of message digest (Table 2's `m`).
pub const M: usize = 30;

/// The WOTS⁺ base: `2^lg_w` (Equation 5.1).
const W: u32 = 1 << LG_W;
/// Message digits in a WOTS⁺ signature: Equation 5.2's
/// `⌊(8n + lg_w − 1) / lg_w⌋`, which is `⌈8n / lg_w⌉`.
pub const LEN1: usize = (8 * N).div_ceil(LG_W);
/// Checksum digits in a WOTS⁺ signature, as Algorithm 1 computes it for
/// these parameters; a test re-runs Algorithm 1 to hold this number to it.
pub const LEN2: usize = 3;
/// Chains in a WOTS⁺ key.
pub const LEN: usize = LEN1 + LEN2;

/// Bytes in a public key: `PK.seed ‖ PK.root`.
pub const PUBLIC_KEY_BYTES: usize = 2 * N;
/// Bytes in a signature, Algorithm 20 line 1: `(1 + k(1 + a) + h + d·len)·n`.
pub const SIGNATURE_BYTES: usize = (1 + K * (1 + A) + HEIGHT + D * LEN) * N;

/// Bytes of the FORS signature inside a signature.
const FORS_BYTES: usize = K * (1 + A) * N;
/// Bytes of one XMSS signature: a WOTS⁺ signature and an authentication path.
const XMSS_BYTES: usize = (H_PRIME + LEN) * N;
/// Algorithm 20 lines 9–11: how the digest is split.
const MD_BYTES: usize = (K * A).div_ceil(8);
const TREE_BYTES: usize = (HEIGHT - HEIGHT / D).div_ceil(8);
const LEAF_BYTES: usize = (HEIGHT / D).div_ceil(8);

// The split must be the whole digest, and MGF1 here produces one block.
const _: () = assert!(MD_BYTES + TREE_BYTES + LEAF_BYTES == M);
const _: () = assert!(M <= DIGEST);

/// Why a signature was not accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The signature is not [`SIGNATURE_BYTES`] long (Algorithm 20 line 1).
    WrongLength,
    /// The context string is longer than 255 bytes (Algorithm 24 line 1).
    ContextTooLong,
    /// The signature does not lead to the public key's root.
    Mismatch,
}

/// Address types (§4.2). Verification uses five of the seven.
const WOTS_HASH: u8 = 0;
const WOTS_PK: u8 = 1;
const TREE: u8 = 2;
const FORS_TREE: u8 = 3;
const FORS_ROOTS: u8 = 4;

/// A compressed address, `ADRSc` (§11.2, Figure 18): the layer in byte 0,
/// the tree in bytes 1–8, the type in byte 9, and three words after it.
/// The member functions are Table 3's.
#[derive(Clone, Copy)]
struct Adrs([u8; 22]);

impl Adrs {
    const fn new() -> Self {
        Self([0; 22])
    }

    fn set_layer_address(&mut self, layer: u8) {
        self.0[0] = layer;
    }

    fn set_tree_address(&mut self, tree: u64) {
        self.0[1..9].copy_from_slice(&tree.to_be_bytes());
    }

    fn set_type_and_clear(&mut self, kind: u8) {
        self.0[9] = kind;
        self.0[10..22].fill(0);
    }

    fn set_key_pair_address(&mut self, index: u32) {
        self.0[10..14].copy_from_slice(&index.to_be_bytes());
    }

    fn key_pair_address(&self) -> u32 {
        u32::from_be_bytes([self.0[10], self.0[11], self.0[12], self.0[13]])
    }

    /// `setChainAddress` and `setTreeHeight`: the same word (Table 3).
    fn set_word_2(&mut self, value: u32) {
        self.0[14..18].copy_from_slice(&value.to_be_bytes());
    }

    /// `setHashAddress` and `setTreeIndex`: the same word (Table 3).
    fn set_word_3(&mut self, value: u32) {
        self.0[18..22].copy_from_slice(&value.to_be_bytes());
    }

    fn tree_index(&self) -> u32 {
        u32::from_be_bytes([self.0[18], self.0[19], self.0[20], self.0[21]])
    }
}

/// `F`, `H` and `T_l` for one key (§11.2.1): every one is
/// `Trunc_n(SHA-256(PK.seed ‖ toByte(0, 64 − n) ‖ ADRSc ‖ input))`.
///
/// `PK.seed ‖ toByte(0, 48)` is exactly one SHA-256 block and the same for
/// every call, so it is compressed once per verification and the state
/// cloned for each call — one compression saved on each of several thousand.
struct Tweak {
    seeded: Sha256,
}

impl Tweak {
    fn new(pk_seed: &[u8]) -> Self {
        let mut seeded = Sha256::new();
        seeded.update(pk_seed);
        seeded.update(&[0; 64 - N]);
        Self { seeded }
    }

    fn hash(&self, adrs: &Adrs, parts: &[&[u8]]) -> [u8; N] {
        #[cfg(test)]
        cost::count(parts.iter().map(|part| part.len()).sum());
        let mut sha = self.seeded.clone();
        sha.update(&adrs.0);
        for part in parts {
            sha.update(part);
        }
        trunc(&sha.finish())
    }

    /// `F`: one value.
    fn f(&self, adrs: &Adrs, value: &[u8]) -> [u8; N] {
        self.hash(adrs, &[value])
    }

    /// `H`: two values, left then right.
    fn h(&self, adrs: &Adrs, left: &[u8], right: &[u8]) -> [u8; N] {
        self.hash(adrs, &[left, right])
    }

    /// `T_l`: `l` values, already concatenated.
    fn t(&self, adrs: &Adrs, values: &[u8]) -> [u8; N] {
        self.hash(adrs, &[values])
    }
}

fn trunc(digest: &[u8; DIGEST]) -> [u8; N] {
    let mut out = [0; N];
    out.copy_from_slice(&digest[..N]);
    out
}

/// `H_msg` (§11.2.1): `MGF1-SHA-256(R ‖ PK.seed ‖ SHA-256(R ‖ PK.seed ‖ PK.root ‖ M), m)`.
///
/// The message arrives as parts, so Algorithm 24's `M′` is hashed where it
/// lies and never assembled. MGF1 (RFC 8017 §B.2.1) concatenates
/// `Hash(seed ‖ I2OSP(counter, 4))` for counters from 0; `m` is 30, so the
/// first block is all of it.
fn h_msg(r: &[u8], pk_seed: &[u8], pk_root: &[u8], message: &[&[u8]]) -> [u8; M] {
    let mut inner = Sha256::new();
    inner.update(r);
    inner.update(pk_seed);
    inner.update(pk_root);
    for part in message {
        inner.update(part);
    }
    let inner = inner.finish();
    let mut mgf1 = Sha256::new();
    mgf1.update(r);
    mgf1.update(pk_seed);
    mgf1.update(&inner);
    mgf1.update(&0u32.to_be_bytes());
    let block = mgf1.finish();
    let mut digest = [0; M];
    digest.copy_from_slice(&block[..M]);
    digest
}

/// Algorithm 2, `toInt`, for up to eight bytes.
fn to_int(bytes: &[u8]) -> u64 {
    bytes
        .iter()
        .fold(0, |total, byte| (total << 8) | u64::from(*byte))
}

/// Algorithm 4, `base_2b`: the first `OUT` base-`2^b` digits of `x`.
///
/// `total` keeps only the bits not yet read out, where the standard lets it
/// grow and takes each digit modulo `2^b`; the digits are the same, and the
/// accumulator cannot overflow.
fn base_2b<const OUT: usize>(x: &[u8], b: u32) -> [u32; OUT] {
    let mut digits = [0; OUT];
    let mut input = 0;
    let mut bits = 0;
    let mut total: u32 = 0;
    for digit in &mut digits {
        while bits < b {
            total = (total << 8) | u32::from(x[input]);
            input += 1;
            bits += 8;
        }
        bits -= b;
        *digit = (total >> bits) & ((1 << b) - 1);
        total &= (1 << bits) - 1;
    }
    digits
}

/// Algorithm 5, `chain`: `F` iterated `steps` times from position `start`.
fn chain(tweak: &Tweak, x: &[u8], start: u32, steps: u32, adrs: &mut Adrs) -> [u8; N] {
    let mut tmp = [0; N];
    tmp.copy_from_slice(x);
    for j in start..start + steps {
        adrs.set_word_3(j);
        tmp = tweak.f(adrs, &tmp);
    }
    tmp
}

/// Algorithm 8, `wots_pkFromSig`: the WOTS⁺ public key a signature implies.
fn wots_pk_from_sig(tweak: &Tweak, sig: &[u8], message: &[u8; N], adrs: &mut Adrs) -> [u8; N] {
    let msg: [u32; LEN1] = base_2b(message, LG_W as u32);
    let mut csum: u32 = msg.iter().map(|digit| W - 1 - digit).sum();
    // Line 6: left-align the checksum in its bytes.
    csum <<= (8 - (LEN2 * LG_W) % 8) % 8;
    let csum_bytes = csum.to_be_bytes();
    let checksum: [u32; LEN2] = base_2b(&csum_bytes[4 - (LEN2 * LG_W).div_ceil(8)..], LG_W as u32);
    let mut tmp = [0; LEN * N];
    for i in 0..LEN {
        let digit = if i < LEN1 { msg[i] } else { checksum[i - LEN1] };
        adrs.set_word_2(i as u32);
        let end = chain(tweak, &sig[i * N..(i + 1) * N], digit, W - 1 - digit, adrs);
        tmp[i * N..(i + 1) * N].copy_from_slice(&end);
    }
    let mut wots_pk_adrs = *adrs;
    wots_pk_adrs.set_type_and_clear(WOTS_PK);
    wots_pk_adrs.set_key_pair_address(adrs.key_pair_address());
    tweak.t(&wots_pk_adrs, &tmp)
}

/// Climbs an authentication path from `node` at `index` to the root of a tree
/// of `height`: lines 8–18 of Algorithm 11, and lines 8–18 of Algorithm 17.
fn climb(
    tweak: &Tweak,
    mut node: [u8; N],
    index: u32,
    auth: &[u8],
    height: usize,
    adrs: &mut Adrs,
) -> [u8; N] {
    for k in 0..height {
        adrs.set_word_2(k as u32 + 1);
        let sibling = &auth[k * N..(k + 1) * N];
        if (index >> k) & 1 == 0 {
            adrs.set_word_3(adrs.tree_index() / 2);
            node = tweak.h(adrs, &node, sibling);
        } else {
            adrs.set_word_3((adrs.tree_index() - 1) / 2);
            node = tweak.h(adrs, sibling, &node);
        }
    }
    node
}

/// Algorithm 11, `xmss_pkFromSig`: the root of the XMSS tree a signature implies.
fn xmss_pk_from_sig(
    tweak: &Tweak,
    idx: u32,
    sig_xmss: &[u8],
    message: &[u8; N],
    adrs: &mut Adrs,
) -> [u8; N] {
    adrs.set_type_and_clear(WOTS_HASH);
    adrs.set_key_pair_address(idx);
    let (sig, auth) = sig_xmss.split_at(LEN * N);
    let node = wots_pk_from_sig(tweak, sig, message, adrs);
    adrs.set_type_and_clear(TREE);
    adrs.set_word_3(idx);
    climb(tweak, node, idx, auth, H_PRIME, adrs)
}

/// Algorithm 13, `ht_verify`: whether a hypertree signature over `message`
/// leads to `pk_root`.
fn ht_verify(
    tweak: &Tweak,
    message: &[u8; N],
    sig_ht: &[u8],
    idx_tree: u64,
    idx_leaf: u32,
    pk_root: &[u8],
) -> bool {
    let mut adrs = Adrs::new();
    adrs.set_tree_address(idx_tree);
    let mut node = xmss_pk_from_sig(tweak, idx_leaf, &sig_ht[..XMSS_BYTES], message, &mut adrs);
    let mut tree = idx_tree;
    for j in 1..D {
        let leaf = (tree & ((1 << H_PRIME) - 1)) as u32;
        tree >>= H_PRIME;
        adrs.set_layer_address(j as u8);
        adrs.set_tree_address(tree);
        let sig = &sig_ht[j * XMSS_BYTES..(j + 1) * XMSS_BYTES];
        node = xmss_pk_from_sig(tweak, leaf, sig, &node, &mut adrs);
    }
    node[..] == *pk_root
}

/// Algorithm 17, `fors_pkFromSig`: the FORS public key a signature implies.
fn fors_pk_from_sig(tweak: &Tweak, sig_fors: &[u8], md: &[u8], adrs: &mut Adrs) -> [u8; N] {
    let indices: [u32; K] = base_2b(md, A as u32);
    let mut roots = [0; K * N];
    for (i, index) in indices.iter().enumerate() {
        let tree = &sig_fors[i * (A + 1) * N..(i + 1) * (A + 1) * N];
        let (sk, auth) = tree.split_at(N);
        adrs.set_word_2(0);
        adrs.set_word_3((i as u32) * (1 << A) + index);
        let leaf = tweak.f(adrs, sk);
        let root = climb(tweak, leaf, *index, auth, A, adrs);
        roots[i * N..(i + 1) * N].copy_from_slice(&root);
    }
    let mut fors_pk_adrs = *adrs;
    fors_pk_adrs.set_type_and_clear(FORS_ROOTS);
    fors_pk_adrs.set_key_pair_address(adrs.key_pair_address());
    tweak.t(&fors_pk_adrs, &roots)
}

/// Algorithm 20, `slh_verify_internal`: verifies `signature` over the message
/// formed by concatenating `message`'s parts, under `public_key`.
///
/// This is the interface the standard says applications should not use
/// directly; it is public so the internal ACVP vectors can be checked against
/// it. Callers want [`verify`].
///
/// # Errors
///
/// [`Refusal::WrongLength`] for a signature of the wrong size, and
/// [`Refusal::Mismatch`] for one that does not lead to the key's root.
pub fn verify_internal(
    message: &[&[u8]],
    signature: &[u8],
    public_key: &[u8; PUBLIC_KEY_BYTES],
) -> Result<(), Refusal> {
    if signature.len() != SIGNATURE_BYTES {
        return Err(Refusal::WrongLength);
    }
    let (pk_seed, pk_root) = public_key.split_at(N);
    let tweak = Tweak::new(pk_seed);
    let (r, rest) = signature.split_at(N);
    let (sig_fors, sig_ht) = rest.split_at(FORS_BYTES);
    let digest = h_msg(r, pk_seed, pk_root, message);
    let (md, rest) = digest.split_at(MD_BYTES);
    let (tmp_idx_tree, tmp_idx_leaf) = rest.split_at(TREE_BYTES);
    let idx_tree = to_int(tmp_idx_tree) & ((1 << (HEIGHT - HEIGHT / D)) - 1);
    let idx_leaf = (to_int(tmp_idx_leaf) & ((1 << (HEIGHT / D)) - 1)) as u32;
    let mut adrs = Adrs::new();
    adrs.set_tree_address(idx_tree);
    adrs.set_type_and_clear(FORS_TREE);
    adrs.set_key_pair_address(idx_leaf);
    let pk_fors = fors_pk_from_sig(&tweak, sig_fors, md, &mut adrs);
    if ht_verify(&tweak, &pk_fors, sig_ht, idx_tree, idx_leaf, pk_root) {
        Ok(())
    } else {
        Err(Refusal::Mismatch)
    }
}

/// Algorithm 24, `slh_verify`: verifies a pure SLH-DSA signature over
/// `message` with `context`, under `public_key`.
///
/// The signed message is `M′ = toByte(0, 1) ‖ toByte(|ctx|, 1) ‖ ctx ‖ M`,
/// hashed in place.
///
/// # Errors
///
/// [`Refusal::ContextTooLong`] for a context over 255 bytes, and otherwise
/// as [`verify_internal`].
pub fn verify(
    message: &[u8],
    signature: &[u8],
    context: &[u8],
    public_key: &[u8; PUBLIC_KEY_BYTES],
) -> Result<(), Refusal> {
    let Ok(context_len) = u8::try_from(context.len()) else {
        return Err(Refusal::ContextTooLong);
    };
    let prefix = [0, context_len];
    verify_internal(&[&prefix[..], context, message], signature, public_key)
}

/// A count of the tweakable-hash calls one thread made, and the SHA-256
/// compressions they cost, so the cost test measures rather than estimates.
#[cfg(test)]
pub(crate) mod cost {
    use std::cell::Cell;

    std::thread_local! {
        static CALLS: Cell<u64> = const { Cell::new(0) };
        static COMPRESSIONS: Cell<u64> = const { Cell::new(0) };
    }

    /// One call of `F`, `H` or `T_l` with `input` bytes after the address:
    /// the seed block is already compressed, so the rest is
    /// `22 + input` bytes plus SHA-256's nine-byte minimum of padding.
    pub(crate) fn count(input: usize) {
        CALLS.with(|calls| calls.set(calls.get() + 1));
        let blocks = (22 + input + 9).div_ceil(64) as u64;
        COMPRESSIONS.with(|total| total.set(total.get() + blocks));
    }

    /// Calls and compressions since the last reset, and resets them.
    pub(crate) fn take() -> (u64, u64) {
        (
            CALLS.with(|calls| calls.replace(0)),
            COMPRESSIONS.with(|total| total.replace(0)),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One ACVP test case, from `third_party/acvp-slh-dsa/`.
    struct Case {
        tc_id: u32,
        group: u32,
        passed: bool,
        reason: &'static str,
        pk: [u8; PUBLIC_KEY_BYTES],
        context: std::vec::Vec<u8>,
        message: std::vec::Vec<u8>,
        signature: std::vec::Vec<u8>,
    }

    const VECTORS: &str = include_str!("../../third_party/acvp-slh-dsa/sha2-128s-sigver.tsv");
    /// ACVP's group numbers for this parameter set's two interfaces.
    const EXTERNAL_PURE: u32 = 19;
    const INTERNAL: u32 = 31;

    fn unhex(text: &str) -> std::vec::Vec<u8> {
        assert!(text.len().is_multiple_of(2), "odd hex length");
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    fn cases() -> std::vec::Vec<Case> {
        VECTORS
            .lines()
            .filter(|line| !line.starts_with('#') && !line.is_empty())
            .map(|line| {
                let fields: std::vec::Vec<&str> = line.split('\t').collect();
                assert_eq!(fields.len(), 8, "{line:.60}");
                Case {
                    tc_id: fields[0].parse().unwrap(),
                    group: fields[1].parse().unwrap(),
                    passed: fields[2] == "true",
                    reason: fields[3],
                    pk: unhex(fields[4]).try_into().unwrap(),
                    context: unhex(fields[5]),
                    message: unhex(fields[6]),
                    signature: unhex(fields[7]),
                }
            })
            .collect()
    }

    fn judge(case: &Case) -> Result<(), Refusal> {
        match case.group {
            EXTERNAL_PURE => verify(&case.message, &case.signature, &case.context, &case.pk),
            INTERNAL => verify_internal(&[&case.message], &case.signature, &case.pk),
            group => panic!("tcId {}: no interface for group {group}", case.tc_id),
        }
    }

    /// What each ACVP reason must be refused as.
    fn expected(case: &Case) -> Result<(), Refusal> {
        match case.reason {
            "valid signature and message - signature should verify successfully" => Ok(()),
            "invalid signature - too large" | "invalid signature - too small" => {
                Err(Refusal::WrongLength)
            }
            "modified message"
            | "modified signature - R"
            | "modified signature - SIGFORS"
            | "modified signature - SIGHT" => Err(Refusal::Mismatch),
            reason => panic!("tcId {}: unknown reason {reason:?}", case.tc_id),
        }
    }

    #[test]
    fn the_parameters_are_table_2s() {
        assert_eq!((LEN1, LEN2, LEN), (32, 3, 35));
        assert_eq!(SIGNATURE_BYTES, 7856, "Table 2's signature size");
        assert_eq!(PUBLIC_KEY_BYTES, 32, "Table 2's public key size");
        assert_eq!((MD_BYTES, TREE_BYTES, LEAF_BYTES), (21, 7, 2));
    }

    #[test]
    // Line 2 in the standard's own form, `⌊(8n + lg_w − 1) / lg_w⌋`, on purpose:
    // the constant uses `div_ceil`, and this is the independent derivation.
    #[allow(clippy::manual_div_ceil)]
    fn len2_is_what_algorithm_1_computes() {
        // Algorithm 1, gen_len2, line by line.
        let w = 1u64 << LG_W;
        let len1 = (8 * N as u64 + LG_W as u64 - 1) / LG_W as u64;
        let max_checksum = len1 * (w - 1);
        let mut len2 = 1;
        let mut capacity = w;
        while capacity <= max_checksum {
            len2 += 1;
            capacity *= w;
        }
        assert_eq!(len1, LEN1 as u64);
        assert_eq!(len2, LEN2);
    }

    #[test]
    fn base_2b_reads_digits_most_significant_first() {
        assert_eq!(base_2b::<4>(&[0x12, 0x34], 4), [1, 2, 3, 4]);
        // Twelve-bit digits straddle bytes, as FORS's do.
        assert_eq!(base_2b::<2>(&[0xab, 0xcd, 0xef], 12), [0xabc, 0xdef]);
    }

    #[test]
    fn the_vectors_are_the_two_groups_and_every_reason_twice() {
        let cases = cases();
        assert_eq!(cases.len(), 28);
        for group in [EXTERNAL_PURE, INTERNAL] {
            let mine: std::vec::Vec<&Case> = cases.iter().filter(|c| c.group == group).collect();
            assert_eq!(mine.len(), 14, "group {group}");
            assert_eq!(mine.iter().filter(|c| c.passed).count(), 2, "group {group}");
        }
    }

    #[test]
    fn every_acvp_vector_gets_its_verdict_and_its_reason() {
        for case in cases() {
            let verdict = judge(&case);
            assert_eq!(
                verdict.is_ok(),
                case.passed,
                "tcId {} ({})",
                case.tc_id,
                case.reason
            );
            assert_eq!(
                verdict,
                expected(&case),
                "tcId {} ({})",
                case.tc_id,
                case.reason
            );
        }
    }

    #[test]
    fn a_context_over_255_bytes_is_refused_before_anything_is_hashed() {
        let case = cases()
            .into_iter()
            .find(|c| c.passed && c.group == EXTERNAL_PURE)
            .unwrap();
        let long = [0; 256];
        assert_eq!(
            verify(&case.message, &case.signature, &long, &case.pk),
            Err(Refusal::ContextTooLong)
        );
    }

    #[test]
    fn the_message_as_parts_is_the_message_concatenated() {
        // `M′` is hashed in place: splitting it anywhere must not change it.
        let case = cases()
            .into_iter()
            .find(|c| c.passed && c.group == INTERNAL)
            .unwrap();
        let at = case.message.len() / 3;
        let (head, tail) = case.message.split_at(at);
        assert_eq!(
            verify_internal(&[head, &[], tail], &case.signature, &case.pk),
            Ok(())
        );
    }

    /// The cost of one verification, measured: `cargo test --release -p
    /// bhaskix-bootsig -- --ignored --nocapture verification_cost`.
    #[test]
    #[ignore = "a measurement, run on demand in release"]
    fn verification_cost() {
        let case = cases()
            .into_iter()
            .find(|c| c.passed && c.group == EXTERNAL_PURE)
            .unwrap();
        cost::take();
        verify(&case.message, &case.signature, &case.context, &case.pk).unwrap();
        let (calls, compressions) = cost::take();
        // The deterministic part of the call count: every `H` on an
        // authentication path (d·h′ + k·a), the eight `T_l`, and FORS's k
        // leaves. The WOTS⁺ chains add between 0 and d·len·(w − 1) `F`s,
        // depending on the digits.
        let fixed = (D * H_PRIME + K * A + D + 1 + K) as u64;
        let chains = calls - fixed;
        assert!(chains <= (D * LEN * (W as usize - 1)) as u64);
        let mut times = std::vec::Vec::new();
        for _ in 0..100 {
            let start = std::time::Instant::now();
            verify(&case.message, &case.signature, &case.context, &case.pk).unwrap();
            times.push(start.elapsed());
        }
        times.sort();
        std::println!(
            "verification: {calls} tweakable hashes ({fixed} fixed, {chains} chain steps), \
             {compressions} compressions for them plus 1 for the seed block and the \
             message's own; median {:?}, fastest {:?}, slowest {:?} over 100",
            times[50],
            times[0],
            times[99]
        );
    }
}
