// SPDX-License-Identifier: Apache-2.0
//! `bhaskix\boot.sig`: one fixed statement naming a boot set, and the
//! signature over it ([RFC 0091](../../docs/rfc/0091-a-boot-its-owner-signed.md),
//! *Link 2*).
//!
//! The statement is 128 bytes at fixed offsets, little-endian, with no
//! length an attacker chooses and nothing to parse but offsets:
//!
//! | Offset | Bytes | Field |
//! |---|---|---|
//! | 0 | 16 | [`MAGIC`], so a signature over this is never one over anything else the project signs |
//! | 16 | 4 | algorithm: [`ALGORITHM`] is the only one accepted |
//! | 20 | 4 | security version: must be 0 until secure update gives it a meaning |
//! | 24 | 8 | key id: the first 8 bytes of SHA-256 over the public key |
//! | 32 | 32 | SHA-256 of `bhaskix\kernel` |
//! | 64 | 32 | SHA-256 of `bhaskix\initrd.tar` |
//! | 96 | 32 | SHA-256 of `bhaskix\boot.conf`, every byte |
//!
//! The file is the statement and then an SLH-DSA-SHA2-128s signature over
//! it, pure, with an empty context — [`BOOT_SIG_BYTES`] in all.
//!
//! [`check`] takes the digests of what the loader holds rather than the
//! buffers themselves, so this stays pure: hashing what was read is the
//! loader's job, and it measures before anything here runs.

use crate::slh_dsa::{self, PUBLIC_KEY_BYTES, SIGNATURE_BYTES};
use bhaskix_sha256::{DIGEST, digest};

/// Bytes in a statement.
pub const STATEMENT_BYTES: usize = 128;
/// Bytes in `boot.sig`: the statement and its signature (7,984).
pub const BOOT_SIG_BYTES: usize = STATEMENT_BYTES + SIGNATURE_BYTES;
/// The statement's first sixteen bytes.
pub const MAGIC: [u8; 16] = *b"bhaskix boot v1\0";
/// The one algorithm a statement may name: SLH-DSA-SHA2-128s.
pub const ALGORITHM: u32 = 1;

/// Which key signed: the first eight bytes of SHA-256 over its public key.
pub type KeyId = [u8; 8];

/// The key id of a public key.
#[must_use]
pub fn key_id(public_key: &[u8; PUBLIC_KEY_BYTES]) -> KeyId {
    let mut id = [0; 8];
    id.copy_from_slice(&digest(public_key)[..8]);
    id
}

/// The digests of the three files the loader read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Digests {
    /// `bhaskix\kernel`.
    pub kernel: [u8; DIGEST],
    /// `bhaskix\initrd.tar`.
    pub initrd: [u8; DIGEST],
    /// `bhaskix\boot.conf`; an absent file hashes as empty.
    pub boot_conf: [u8; DIGEST],
}

/// Why a boot set was not verified — one reason, the first that held, so a
/// report can say which check failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// `boot.sig` is not [`BOOT_SIG_BYTES`] long.
    WrongSize,
    /// The statement does not begin with [`MAGIC`].
    NotAStatement,
    /// The statement names an algorithm other than [`ALGORITHM`].
    UnknownAlgorithm(u32),
    /// The statement's security version is not 0.
    SecurityVersion(u32),
    /// The kernel read is not the one the statement names.
    KernelDiffers,
    /// The initrd read is not the one the statement names.
    InitrdDiffers,
    /// `boot.conf` as read is not the one the statement names.
    BootConfDiffers,
    /// No key the loader holds has the statement's key id.
    UnknownKey(KeyId),
    /// The signature does not verify under the key the statement names.
    BadSignature,
}

impl Refusal {
    /// The check that failed, in words a boot report can print.
    #[must_use]
    pub const fn describe(self) -> &'static str {
        match self {
            Self::WrongSize => "boot.sig is not the size of a statement and its signature",
            Self::NotAStatement => "boot.sig does not begin with a statement",
            Self::UnknownAlgorithm(_) => {
                "the statement names an algorithm this loader does not know"
            }
            Self::SecurityVersion(_) => "the statement's security version is not 0",
            Self::KernelDiffers => "the kernel is not the one boot.sig names",
            Self::InitrdDiffers => "the initrd is not the one boot.sig names",
            Self::BootConfDiffers => "boot.conf is not the one boot.sig names",
            Self::UnknownKey(_) => "boot.sig names a key this loader does not hold",
            Self::BadSignature => "the signature over the statement does not verify",
        }
    }
}

/// A `boot.sig` whose statement is well formed. Nothing about it is trusted
/// until [`check`] has verified the signature.
#[derive(Clone, Copy, Debug)]
pub struct BootSig<'a> {
    statement: &'a [u8],
    signature: &'a [u8],
}

impl<'a> BootSig<'a> {
    /// Reads `bytes` as a `boot.sig`: exactly [`BOOT_SIG_BYTES`], the magic,
    /// the one algorithm, and a security version of 0.
    ///
    /// # Errors
    ///
    /// The first of [`Refusal::WrongSize`], [`Refusal::NotAStatement`],
    /// [`Refusal::UnknownAlgorithm`] and [`Refusal::SecurityVersion`] that
    /// holds.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Refusal> {
        if bytes.len() != BOOT_SIG_BYTES {
            return Err(Refusal::WrongSize);
        }
        let (statement, signature) = bytes.split_at(STATEMENT_BYTES);
        if statement[..16] != MAGIC {
            return Err(Refusal::NotAStatement);
        }
        let sig = Self {
            statement,
            signature,
        };
        match sig.word(16) {
            ALGORITHM => {}
            other => return Err(Refusal::UnknownAlgorithm(other)),
        }
        match sig.word(20) {
            0 => {}
            other => return Err(Refusal::SecurityVersion(other)),
        }
        Ok(sig)
    }

    fn word(&self, at: usize) -> u32 {
        let mut bytes = [0; 4];
        bytes.copy_from_slice(&self.statement[at..at + 4]);
        u32::from_le_bytes(bytes)
    }

    fn digest_at(&self, at: usize) -> &[u8] {
        &self.statement[at..at + DIGEST]
    }

    /// The key id the statement names.
    #[must_use]
    pub fn key_id(&self) -> KeyId {
        let mut id = [0; 8];
        id.copy_from_slice(&self.statement[24..32]);
        id
    }
}

/// Verifies `boot_sig` for the boot set whose files hash to `held`, against
/// the keys the loader holds, in RFC 0091's order: the statement read, the
/// three digests compared, the key found, the signature verified.
///
/// Returns the id of the key that verified it.
///
/// # Errors
///
/// The first [`Refusal`] that holds, so the caller can say which check failed.
pub fn check(
    boot_sig: &[u8],
    keys: &[[u8; PUBLIC_KEY_BYTES]],
    held: &Digests,
) -> Result<KeyId, Refusal> {
    let sig = BootSig::parse(boot_sig)?;
    if *sig.digest_at(32) != held.kernel {
        return Err(Refusal::KernelDiffers);
    }
    if *sig.digest_at(64) != held.initrd {
        return Err(Refusal::InitrdDiffers);
    }
    if *sig.digest_at(96) != held.boot_conf {
        return Err(Refusal::BootConfDiffers);
    }
    let named = sig.key_id();
    let Some(key) = keys.iter().find(|key| key_id(key) == named) else {
        return Err(Refusal::UnknownKey(named));
    };
    slh_dsa::verify(sig.statement, sig.signature, &[], key)
        .map(|()| named)
        .map_err(|_| Refusal::BadSignature)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; PUBLIC_KEY_BYTES] = [7; PUBLIC_KEY_BYTES];

    fn held() -> Digests {
        Digests {
            kernel: [1; DIGEST],
            initrd: [2; DIGEST],
            boot_conf: digest(b""),
        }
    }

    /// A well-formed statement for `held()` under `KEY`, with a signature of
    /// zeroes: every check before the signature passes it.
    fn boot_sig() -> std::vec::Vec<u8> {
        let mut bytes = std::vec![0u8; BOOT_SIG_BYTES];
        bytes[..16].copy_from_slice(&MAGIC);
        bytes[16..20].copy_from_slice(&ALGORITHM.to_le_bytes());
        bytes[24..32].copy_from_slice(&key_id(&KEY));
        let held = held();
        bytes[32..64].copy_from_slice(&held.kernel);
        bytes[64..96].copy_from_slice(&held.initrd);
        bytes[96..128].copy_from_slice(&held.boot_conf);
        bytes
    }

    #[test]
    fn the_file_is_7984_bytes() {
        assert_eq!(BOOT_SIG_BYTES, 7984, "RFC 0091: 128 + 7,856");
    }

    #[test]
    fn a_file_of_any_other_size_is_refused() {
        let bytes = boot_sig();
        for len in [0, STATEMENT_BYTES, BOOT_SIG_BYTES - 1] {
            assert_eq!(
                BootSig::parse(&bytes[..len]).err(),
                Some(Refusal::WrongSize),
                "{len}"
            );
        }
        let mut longer = bytes.clone();
        longer.push(0);
        assert_eq!(BootSig::parse(&longer).err(), Some(Refusal::WrongSize));
    }

    #[test]
    fn a_statement_without_the_magic_is_refused() {
        let mut bytes = boot_sig();
        bytes[15] = b'x';
        assert_eq!(BootSig::parse(&bytes).err(), Some(Refusal::NotAStatement));
    }

    #[test]
    fn another_algorithm_is_refused_by_number() {
        let mut bytes = boot_sig();
        bytes[16..20].copy_from_slice(&2u32.to_le_bytes());
        assert_eq!(
            BootSig::parse(&bytes).err(),
            Some(Refusal::UnknownAlgorithm(2))
        );
    }

    #[test]
    fn a_security_version_other_than_0_is_refused() {
        let mut bytes = boot_sig();
        bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
        assert_eq!(
            BootSig::parse(&bytes).err(),
            Some(Refusal::SecurityVersion(1))
        );
    }

    #[test]
    fn each_digest_that_differs_is_named() {
        let bytes = boot_sig();
        let mut wrong = held();
        wrong.kernel[31] ^= 1;
        assert_eq!(check(&bytes, &[KEY], &wrong), Err(Refusal::KernelDiffers));
        let mut wrong = held();
        wrong.initrd[0] ^= 1;
        assert_eq!(check(&bytes, &[KEY], &wrong), Err(Refusal::InitrdDiffers));
        let mut wrong = held();
        wrong.boot_conf = digest(b"cmdline=\n");
        assert_eq!(check(&bytes, &[KEY], &wrong), Err(Refusal::BootConfDiffers));
    }

    #[test]
    fn a_key_the_loader_does_not_hold_is_named() {
        let other = [8; PUBLIC_KEY_BYTES];
        assert_eq!(
            check(&boot_sig(), &[other], &held()),
            Err(Refusal::UnknownKey(key_id(&KEY)))
        );
        assert_eq!(
            check(&boot_sig(), &[], &held()),
            Err(Refusal::UnknownKey(key_id(&KEY)))
        );
    }

    #[test]
    fn a_statement_that_passes_every_other_check_still_needs_its_signature() {
        // Every check before the signature holds; the signature is zeroes.
        assert_eq!(
            check(&boot_sig(), &[KEY], &held()),
            Err(Refusal::BadSignature)
        );
    }

    #[test]
    fn every_refusal_has_words_for_the_report() {
        let all = [
            Refusal::WrongSize,
            Refusal::NotAStatement,
            Refusal::UnknownAlgorithm(2),
            Refusal::SecurityVersion(1),
            Refusal::KernelDiffers,
            Refusal::InitrdDiffers,
            Refusal::BootConfDiffers,
            Refusal::UnknownKey([0; 8]),
            Refusal::BadSignature,
        ];
        for (i, refusal) in all.iter().enumerate() {
            assert!(!refusal.describe().is_empty());
            for other in &all[i + 1..] {
                assert_ne!(refusal.describe(), other.describe());
            }
        }
    }
}
