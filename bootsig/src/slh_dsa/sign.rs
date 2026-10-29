// SPDX-License-Identifier: Apache-2.0
//! SLH-DSA-SHA2-128s **signing and key generation** (FIPS 205), behind the
//! `sign` feature: for `bootsign` on the custody machine, never for the loader.
//!
//! It reuses the verifier's address, tweakable hashes, digit and digest
//! arithmetic, so the two halves cannot disagree about them, and adds only
//! what signing needs: `PRF`, `PRF_msg` (HMAC-SHA-256), and the algorithms
//! that build trees from the secret seed — 6, 7, 9, 10, 12, 14, 15, 16, 18,
//! 19 and 22, each named in its doc comment.
//!
//! # Randomness is the caller's
//!
//! Nothing here reads a random source: key generation takes its three seeds
//! and signing takes `addrnd`. That keeps this `no_std` and testable against
//! NIST's vectors, which fix both. `bootsign` reads them from the operating
//! system and signs **hedged** — the project lead's choice of 2026-10-29, and
//! FIPS 205 §9.2's default "on platforms where side-channel attacks are a
//! concern". `addrnd = None` is the deterministic variant, which exists here
//! for NIST's deterministic vectors and nothing else.
//!
//! # Timing
//!
//! RFC 0040 proposes constant-time handling (T14) for code that holds key
//! material, and this does. The argument, since nothing here measures it:
//! every branch and every index depends only on public values — the tree
//! positions, and the digits of the message digest, which the signature
//! itself reveals. Secret values (`SK.seed`, `SK.prf`, and everything derived
//! from them before it is published) are only ever *hashed*, and SHA-256's
//! table lookups are indexed by round number, never by data. **What is not
//! done**: secret bytes are not zeroed after use, which would need `unsafe`
//! this crate's budget forbids; the signer is a short-lived process on an
//! offline machine (RFC 0091, question 4).

use super::{
    A, Adrs, D, FORS_BYTES, FORS_TREE, H_PRIME, K, LEN, M, N, PUBLIC_KEY_BYTES, Refusal,
    SIGNATURE_BYTES, TREE, Tweak, WOTS_HASH, WOTS_PK, XMSS_BYTES, base_2b, chain, fors_pk_from_sig,
    h_msg, split_digest, trunc, wots_digits, xmss_pk_from_sig,
};
use bhaskix_sha256::{DIGEST, Sha256};

/// Bytes in a secret key: `SK.seed ‖ SK.prf ‖ PK.seed ‖ PK.root` (§9.1).
pub const SECRET_KEY_BYTES: usize = 4 * N;

/// Address types only signing uses (§4.2).
const WOTS_PRF: u8 = 5;
const FORS_PRF: u8 = 6;

/// HMAC-SHA-256 (FIPS 198-1) over `first` and then each of `rest`,
/// concatenated in place.
fn hmac_sha256(key: &[u8], first: &[u8], rest: &[&[u8]]) -> [u8; DIGEST] {
    const BLOCK: usize = 64;
    let mut padded = [0u8; BLOCK];
    if key.len() > BLOCK {
        padded[..DIGEST].copy_from_slice(&bhaskix_sha256::digest(key));
    } else {
        padded[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha256::new();
    inner.update(&padded.map(|byte| byte ^ 0x36));
    inner.update(first);
    for part in rest {
        inner.update(part);
    }
    let inner = inner.finish();
    let mut outer = Sha256::new();
    outer.update(&padded.map(|byte| byte ^ 0x5c));
    outer.update(&inner);
    outer.finish()
}

/// `PRF` (§11.2.1): `Trunc_n(SHA-256(PK.seed ‖ toByte(0, 64 − n) ‖ ADRSc ‖ SK.seed))`,
/// which is the tweakable hash with the secret seed as its input.
fn prf(tweak: &Tweak, sk_seed: &[u8], adrs: &Adrs) -> [u8; N] {
    tweak.hash(adrs, &[sk_seed])
}

/// `PRF_msg` (§11.2.1): `Trunc_n(HMAC-SHA-256(SK.prf, opt_rand ‖ M))`.
fn prf_msg(sk_prf: &[u8], opt_rand: &[u8], message: &[&[u8]]) -> [u8; N] {
    trunc(&hmac_sha256(sk_prf, opt_rand, message))
}

/// Algorithm 6, `wots_pkGen`.
fn wots_pk_gen(tweak: &Tweak, sk_seed: &[u8], adrs: &mut Adrs) -> [u8; N] {
    let mut sk_adrs = *adrs;
    sk_adrs.set_type_and_clear(WOTS_PRF);
    sk_adrs.set_key_pair_address(adrs.key_pair_address());
    let mut tmp = [0; LEN * N];
    for i in 0..LEN {
        sk_adrs.set_word_2(i as u32);
        let sk = prf(tweak, sk_seed, &sk_adrs);
        adrs.set_word_2(i as u32);
        let end = chain(tweak, &sk, 0, super::W - 1, adrs);
        tmp[i * N..(i + 1) * N].copy_from_slice(&end);
    }
    let mut wots_pk_adrs = *adrs;
    wots_pk_adrs.set_type_and_clear(WOTS_PK);
    wots_pk_adrs.set_key_pair_address(adrs.key_pair_address());
    tweak.t(&wots_pk_adrs, &tmp)
}

/// Algorithm 7, `wots_sign`.
fn wots_sign(tweak: &Tweak, message: &[u8; N], sk_seed: &[u8], adrs: &mut Adrs) -> [u8; LEN * N] {
    let digits = wots_digits(message);
    let mut sk_adrs = *adrs;
    sk_adrs.set_type_and_clear(WOTS_PRF);
    sk_adrs.set_key_pair_address(adrs.key_pair_address());
    let mut sig = [0; LEN * N];
    for (i, &digit) in digits.iter().enumerate() {
        sk_adrs.set_word_2(i as u32);
        let sk = prf(tweak, sk_seed, &sk_adrs);
        adrs.set_word_2(i as u32);
        let value = chain(tweak, &sk, 0, digit, adrs);
        sig[i * N..(i + 1) * N].copy_from_slice(&value);
    }
    sig
}

/// Algorithm 9, `xmss_node`: the root of the subtree at height `z`, index `i`.
fn xmss_node(tweak: &Tweak, sk_seed: &[u8], i: u32, z: u32, mut adrs: Adrs) -> [u8; N] {
    if z == 0 {
        adrs.set_type_and_clear(WOTS_HASH);
        adrs.set_key_pair_address(i);
        wots_pk_gen(tweak, sk_seed, &mut adrs)
    } else {
        let left = xmss_node(tweak, sk_seed, 2 * i, z - 1, adrs);
        let right = xmss_node(tweak, sk_seed, 2 * i + 1, z - 1, adrs);
        adrs.set_type_and_clear(TREE);
        adrs.set_word_2(z);
        adrs.set_word_3(i);
        tweak.h(&adrs, &left, &right)
    }
}

/// Algorithm 10, `xmss_sign`: a WOTS⁺ signature and its authentication path.
fn xmss_sign(
    tweak: &Tweak,
    message: &[u8; N],
    sk_seed: &[u8],
    idx: u32,
    mut adrs: Adrs,
) -> [u8; XMSS_BYTES] {
    let mut sig_xmss = [0; XMSS_BYTES];
    for j in 0..H_PRIME as u32 {
        let k = (idx >> j) ^ 1;
        let node = xmss_node(tweak, sk_seed, k, j, adrs);
        let at = LEN * N + j as usize * N;
        sig_xmss[at..at + N].copy_from_slice(&node);
    }
    adrs.set_type_and_clear(WOTS_HASH);
    adrs.set_key_pair_address(idx);
    let sig = wots_sign(tweak, message, sk_seed, &mut adrs);
    sig_xmss[..LEN * N].copy_from_slice(&sig);
    sig_xmss
}

/// Algorithm 12, `ht_sign`: one XMSS signature per layer, each layer signing
/// the root of the one below.
fn ht_sign(
    tweak: &Tweak,
    message: &[u8; N],
    sk_seed: &[u8],
    idx_tree: u64,
    idx_leaf: u32,
    sig_ht: &mut [u8],
) {
    let mut adrs = Adrs::new();
    adrs.set_tree_address(idx_tree);
    let sig_tmp = xmss_sign(tweak, message, sk_seed, idx_leaf, adrs);
    sig_ht[..XMSS_BYTES].copy_from_slice(&sig_tmp);
    let mut scratch = adrs;
    let mut root = xmss_pk_from_sig(tweak, idx_leaf, &sig_tmp, message, &mut scratch);
    let mut tree = idx_tree;
    for j in 1..D {
        let leaf = (tree & ((1 << H_PRIME) - 1)) as u32;
        tree >>= H_PRIME;
        adrs.set_layer_address(j as u8);
        adrs.set_tree_address(tree);
        let sig_tmp = xmss_sign(tweak, &root, sk_seed, leaf, adrs);
        sig_ht[j * XMSS_BYTES..(j + 1) * XMSS_BYTES].copy_from_slice(&sig_tmp);
        if j < D - 1 {
            let mut scratch = adrs;
            root = xmss_pk_from_sig(tweak, leaf, &sig_tmp, &root, &mut scratch);
        }
    }
}

/// Algorithm 14, `fors_skGen`.
fn fors_sk_gen(tweak: &Tweak, sk_seed: &[u8], adrs: &Adrs, idx: u32) -> [u8; N] {
    let mut sk_adrs = *adrs;
    sk_adrs.set_type_and_clear(FORS_PRF);
    sk_adrs.set_key_pair_address(adrs.key_pair_address());
    sk_adrs.set_word_3(idx);
    prf(tweak, sk_seed, &sk_adrs)
}

/// Algorithm 15, `fors_node`: the root of the FORS subtree at height `z`,
/// index `i` (counted across all `k` trees).
fn fors_node(tweak: &Tweak, sk_seed: &[u8], i: u32, z: u32, mut adrs: Adrs) -> [u8; N] {
    if z == 0 {
        let sk = fors_sk_gen(tweak, sk_seed, &adrs, i);
        adrs.set_word_2(0);
        adrs.set_word_3(i);
        tweak.f(&adrs, &sk)
    } else {
        let left = fors_node(tweak, sk_seed, 2 * i, z - 1, adrs);
        let right = fors_node(tweak, sk_seed, 2 * i + 1, z - 1, adrs);
        adrs.set_word_2(z);
        adrs.set_word_3(i);
        tweak.h(&adrs, &left, &right)
    }
}

/// Algorithm 16, `fors_sign`.
fn fors_sign(tweak: &Tweak, md: &[u8], sk_seed: &[u8], adrs: &Adrs, sig_fors: &mut [u8]) {
    let indices: [u32; K] = base_2b(md, A as u32);
    for (i, &index) in indices.iter().enumerate() {
        let tree = i as u32;
        let base = i * (A + 1) * N;
        let sk = fors_sk_gen(tweak, sk_seed, adrs, (tree << A) + index);
        sig_fors[base..base + N].copy_from_slice(&sk);
        for j in 0..A as u32 {
            let s = (index >> j) ^ 1;
            let node = fors_node(tweak, sk_seed, (tree << (A as u32 - j)) + s, j, *adrs);
            let at = base + N + j as usize * N;
            sig_fors[at..at + N].copy_from_slice(&node);
        }
    }
}

/// Algorithm 18, `slh_keygen_internal`: the key pair three seeds determine.
///
/// Returns `(SK, PK)` in FIPS 205's encodings: `SK.seed ‖ SK.prf ‖ PK.seed ‖
/// PK.root` and `PK.seed ‖ PK.root`.
#[must_use]
pub fn keygen_internal(
    sk_seed: &[u8; N],
    sk_prf: &[u8; N],
    pk_seed: &[u8; N],
) -> ([u8; SECRET_KEY_BYTES], [u8; PUBLIC_KEY_BYTES]) {
    let tweak = Tweak::new(pk_seed);
    let mut adrs = Adrs::new();
    adrs.set_layer_address(D as u8 - 1);
    let pk_root = xmss_node(&tweak, sk_seed, 0, H_PRIME as u32, adrs);
    let mut sk = [0; SECRET_KEY_BYTES];
    sk[..N].copy_from_slice(sk_seed);
    sk[N..2 * N].copy_from_slice(sk_prf);
    sk[2 * N..3 * N].copy_from_slice(pk_seed);
    sk[3 * N..].copy_from_slice(&pk_root);
    let mut pk = [0; PUBLIC_KEY_BYTES];
    pk.copy_from_slice(&sk[2 * N..]);
    (sk, pk)
}

/// Algorithm 19, `slh_sign_internal`: signs the concatenation of `message`'s
/// parts under `sk`.
///
/// `addrnd` is the hedged variant's fresh randomness; `None` substitutes
/// `PK.seed`, the deterministic variant, which exists for NIST's vectors.
#[must_use]
pub fn sign_internal(
    message: &[&[u8]],
    sk: &[u8; SECRET_KEY_BYTES],
    addrnd: Option<&[u8; N]>,
) -> [u8; SIGNATURE_BYTES] {
    let (sk_seed, rest) = sk.split_at(N);
    let (sk_prf, pk) = rest.split_at(N);
    let (pk_seed, pk_root) = pk.split_at(N);
    let tweak = Tweak::new(pk_seed);
    let opt_rand: &[u8] = match addrnd {
        Some(addrnd) => addrnd,
        None => pk_seed,
    };
    let r = prf_msg(sk_prf, opt_rand, message);
    let mut sig = [0; SIGNATURE_BYTES];
    sig[..N].copy_from_slice(&r);
    let digest: [u8; M] = h_msg(&r, pk_seed, pk_root, message);
    let (md, idx_tree, idx_leaf) = split_digest(&digest);
    let mut adrs = Adrs::new();
    adrs.set_tree_address(idx_tree);
    adrs.set_type_and_clear(FORS_TREE);
    adrs.set_key_pair_address(idx_leaf);
    let (sig_fors, sig_ht) = sig[N..].split_at_mut(FORS_BYTES);
    fors_sign(&tweak, md, sk_seed, &adrs, sig_fors);
    let pk_fors = fors_pk_from_sig(&tweak, sig_fors, md, &mut adrs);
    ht_sign(&tweak, &pk_fors, sk_seed, idx_tree, idx_leaf, sig_ht);
    sig
}

/// Algorithm 22, `slh_sign`: a pure signature over `message` with `context`.
///
/// `M′ = toByte(0, 1) ‖ toByte(|ctx|, 1) ‖ ctx ‖ M`, signed in place.
///
/// # Errors
///
/// [`Refusal::ContextTooLong`] for a context over 255 bytes (line 1).
pub fn sign(
    message: &[u8],
    context: &[u8],
    sk: &[u8; SECRET_KEY_BYTES],
    addrnd: Option<&[u8; N]>,
) -> Result<[u8; SIGNATURE_BYTES], Refusal> {
    let Ok(context_len) = u8::try_from(context.len()) else {
        return Err(Refusal::ContextTooLong);
    };
    let prefix = [0, context_len];
    Ok(sign_internal(&[&prefix[..], context, message], sk, addrnd))
}

#[cfg(test)]
mod tests {
    use super::super::{verify, verify_internal};
    use super::*;

    fn unhex(text: &str) -> std::vec::Vec<u8> {
        (0..text.len() / 2)
            .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    fn rows(text: &'static str) -> impl Iterator<Item = std::vec::Vec<&'static str>> {
        text.lines()
            .filter(|line| !line.starts_with('#') && !line.is_empty())
            .map(|line| line.split('\t').collect())
    }

    // RFC 4231 §4.2–4.8, extracted from the RFC's text by script, not typed:
    // (key, data, HMAC-SHA-256). Test case 5's MAC is truncated to 128 bits,
    // as the RFC prints it.
    const RFC_4231: [(&str, &str, &str); 7] = [
        (
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            "4869205468657265",
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
        ),
        (
            "4a656665",
            "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
        ),
        (
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
        ),
        (
            "0102030405060708090a0b0c0d0e0f10111213141516171819",
            "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
            "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
        ),
        (
            "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
            "546573742057697468205472756e636174696f6e",
            "a3b6167473100ee06e0c796c2955552b",
        ),
        (
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374",
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
        ),
        (
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b657920616e642061206c6172676572207468616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565647320746f20626520686173686564206265666f7265206265696e6720757365642062792074686520484d414320616c676f726974686d2e",
            "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
        ),
    ];

    #[test]
    fn hmac_sha256_matches_rfc_4231() {
        for (i, (key, data, mac)) in RFC_4231.iter().enumerate() {
            let out = hmac_sha256(&unhex(key), &unhex(data), &[]);
            let want = unhex(mac);
            assert_eq!(&out[..want.len()], &want[..], "test case {}", i + 1);
        }
    }

    #[test]
    fn hmac_over_parts_is_hmac_over_the_concatenation() {
        let whole = hmac_sha256(b"key", b"abcdef", &[]);
        assert_eq!(hmac_sha256(b"key", b"ab", &[b"", b"cd", b"ef"]), whole);
    }

    const KEYGEN: &str = include_str!("../../../third_party/acvp-slh-dsa/sha2-128s-keygen.tsv");
    const SIGGEN: &str = include_str!("../../../third_party/acvp-slh-dsa/sha2-128s-siggen.tsv");

    #[test]
    fn every_acvp_keygen_vector_is_reproduced_exactly() {
        let mut count = 0;
        for row in rows(KEYGEN) {
            // tcId skSeed skPrf pkSeed sk pk
            let (sk, pk) = keygen_internal(
                &unhex(row[1]).try_into().unwrap(),
                &unhex(row[2]).try_into().unwrap(),
                &unhex(row[3]).try_into().unwrap(),
            );
            assert_eq!(sk.to_vec(), unhex(row[4]), "tcId {} sk", row[0]);
            assert_eq!(pk.to_vec(), unhex(row[5]), "tcId {} pk", row[0]);
            count += 1;
        }
        assert_eq!(count, 10);
    }

    /// Every sigGen vector in one ACVP group, signed and compared byte for
    /// byte, then verified. One test per group, so the four run in parallel.
    fn siggen_group(group: &str) {
        let mut count = 0;
        for row in rows(SIGGEN).filter(|row| row[1] == group) {
            // tcId group deterministic sk context message addrnd signature
            let sk: [u8; SECRET_KEY_BYTES] = unhex(row[3]).try_into().unwrap();
            let (context, message) = (unhex(row[4]), unhex(row[5]));
            let addrnd: Option<[u8; N]> =
                (row[2] == "false").then(|| unhex(row[6]).try_into().unwrap());
            let sig = match group {
                "19" | "55" => sign(&message, &context, &sk, addrnd.as_ref()).unwrap(),
                _ => sign_internal(&[&message], &sk, addrnd.as_ref()),
            };
            assert!(
                sig[..] == unhex(row[7])[..],
                "tcId {} differs from NIST's",
                row[0]
            );
            let pk: &[u8; PUBLIC_KEY_BYTES] = sk[2 * N..].try_into().unwrap();
            let verdict = match group {
                "19" | "55" => verify(&message, &sig, &context, pk),
                _ => verify_internal(&[&message], &sig, pk),
            };
            assert_eq!(verdict, Ok(()), "tcId {}", row[0]);
            count += 1;
        }
        assert_eq!(count, 7, "group {group}");
    }

    #[test]
    fn acvp_siggen_deterministic_external_pure() {
        siggen_group("19");
    }

    #[test]
    fn acvp_siggen_deterministic_internal() {
        siggen_group("31");
    }

    #[test]
    fn acvp_siggen_hedged_external_pure() {
        siggen_group("55");
    }

    #[test]
    fn acvp_siggen_hedged_internal() {
        siggen_group("67");
    }

    #[test]
    fn the_published_test_key_is_a_key_pair_keygen_would_make() {
        let secret: &[u8; SECRET_KEY_BYTES] =
            include_bytes!("../../../tests/keys/bootsig-TEST-KEY.secret");
        let public: &[u8] = include_bytes!("../../../tests/keys/bootsig-TEST-KEY.public");
        let (sk, pk) = keygen_internal(
            secret[..N].try_into().unwrap(),
            secret[N..2 * N].try_into().unwrap(),
            secret[2 * N..3 * N].try_into().unwrap(),
        );
        assert_eq!(&sk, secret);
        assert_eq!(&pk[..], public);
    }

    #[test]
    fn a_context_over_255_bytes_is_refused() {
        let (sk, _) = keygen_internal(&[1; N], &[2; N], &[3; N]);
        assert_eq!(
            sign(b"m", &[0; 256], &sk, None).err(),
            Some(Refusal::ContextTooLong)
        );
    }
}
