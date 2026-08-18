// SPDX-License-Identifier: Apache-2.0
//! The `.bpk` walk: manifest first, everything else proven or refused.
//!
//! A package is a ustar archive whose first member is `manifest`; the walk
//! parses that, then holds the archive to it — every `file` line must name a
//! member whose bytes match its digest and length, and every member must be
//! named by a `file` line or be a directory. [RFC 0030] is explicit that
//! nothing else rides along: a member the manifest does not claim is not
//! "extra data", it is bytes an installer would have copied without anyone
//! having reviewed them, and the whole package is refused for it.
//!
//! Verification happens **before** anything else looks at the archive, so an
//! installer that starts from a [`Verified`] can copy without re-deciding
//! anything — the decisions are all here, refusals all typed.
//!
//! [RFC 0030]: ../../docs/rfc/0030-packages.md

use crate::manifest::{self, Manifest, ManifestError};
use crate::sha256;
use bhaskix_ustar::{Archive, EntryKind};

/// The member name the manifest travels under.
pub const MANIFEST: &[u8] = b"manifest";

/// Why a package was refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PackageError {
    /// The archive's first member is not `manifest`.
    ManifestNotFirst,
    /// The manifest was refused; carries the grammar's reason.
    Manifest(ManifestError),
    /// A `file` line names a member the archive does not have. Carries the
    /// index of the line's entry in manifest order.
    Missing(usize),
    /// A member's length disagrees with its `file` line. Same index.
    WrongLength(usize),
    /// A member's bytes disagree with their digest. Same index.
    WrongDigest(usize),
    /// The archive carries a member no `file` line names.
    Unclaimed,
    /// A member's name is not a well-formed manifest path — `..`, an
    /// absolute name, a byte outside the alphabet.
    BadMemberName,
}

/// A package that survived verification: the manifest, and the archive it
/// was proven against.
pub struct Verified<'a> {
    manifest: Manifest<'a>,
    bytes: &'a [u8],
}

impl<'a> Verified<'a> {
    /// The manifest.
    #[must_use]
    pub const fn manifest(&self) -> &Manifest<'a> {
        &self.manifest
    }

    /// The verified bytes of the payload at `path`.
    ///
    /// `None` only for a path the manifest does not carry: everything the
    /// manifest names was proven present during verification.
    #[must_use]
    pub fn data(&self, path: &[u8]) -> Option<&'a [u8]> {
        self.manifest.file(path)?;
        Archive::new(self.bytes)
            .find(|entry| entry.is(path))
            .map(|entry| entry.data())
    }
}

/// Whether `name`, as stored in the archive, matches `path` from the
/// manifest — the parser's own `./`-insensitive rule.
fn named(name: &[u8], path: &[u8]) -> bool {
    let name = match name {
        [b'.', b'/', rest @ ..] => rest,
        name => name,
    };
    name == path
}

/// Verifies `bytes` as a package, whole or not at all.
///
/// # Errors
///
/// [`PackageError`], naming the first thing that disqualified it.
pub fn verify(bytes: &[u8]) -> Result<Verified<'_>, PackageError> {
    let mut entries = Archive::new(bytes);
    let first = entries.next().ok_or(PackageError::ManifestNotFirst)?;
    if !first.is(MANIFEST) || first.kind() != EntryKind::File {
        return Err(PackageError::ManifestNotFirst);
    }
    let manifest = manifest::parse(first.data()).map_err(PackageError::Manifest)?;

    // Every file line proven against the archive. Indexed refusals, because
    // "a digest was wrong" without which one is a riddle, not a report.
    for (index, file) in manifest.files().enumerate() {
        let Some(entry) = Archive::new(bytes).find(|entry| named(entry.name(), file.path)) else {
            return Err(PackageError::Missing(index));
        };
        if entry.kind() != EntryKind::File || entry.data().len() as u64 != file.length {
            return Err(PackageError::WrongLength(index));
        }
        if sha256::digest(entry.data()) != file.sha256 {
            return Err(PackageError::WrongDigest(index));
        }
    }

    // Every remaining member claimed, a directory, or the whole refused.
    for entry in entries {
        match entry.kind() {
            EntryKind::Directory => continue,
            EntryKind::File => {
                let name = match entry.name() {
                    [b'.', b'/', rest @ ..] => rest,
                    name => name,
                };
                // Held to the manifest's own path rule first: a name the
                // grammar could not have written cannot be claimed, and
                // refusing it as a *name* points at the actual problem --
                // `..` in a member name is an escape attempt, not a
                // forgotten file line.
                if !manifest::valid_path(name) {
                    return Err(PackageError::BadMemberName);
                }
                if manifest.file(name).is_none() {
                    return Err(PackageError::Unclaimed);
                }
            }
            EntryKind::Other => return Err(PackageError::Unclaimed),
        }
    }

    Ok(Verified { manifest, bytes })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bhaskix_ustar::test_support::archive_of;

    /// A hex rendering, for building manifests in tests.
    fn hex(digest: [u8; 32]) -> std::string::String {
        digest
            .iter()
            .map(|byte| std::format!("{byte:02x}"))
            .collect()
    }

    /// A well-formed one-program package: `bin/hello` plus a config file.
    fn good() -> std::vec::Vec<u8> {
        let binary = b"\x7fELF-stand-in";
        let config = b"greeting=namaste\n";
        let manifest_text = std::format!(
            "package hello\nversion 0.1.0\n\nprogram bin/hello\nentry hertz\ncap console\n\n\
             file bin/hello sha256={} length={}\nfile etc/hello.conf sha256={} length={}\n",
            hex(sha256::digest(binary)),
            binary.len(),
            hex(sha256::digest(config)),
            config.len(),
        );
        archive_of(&[
            (b"manifest".as_slice(), manifest_text.as_bytes(), b'0'),
            (b"bin/".as_slice(), b"".as_slice(), b'5'),
            (b"bin/hello".as_slice(), binary.as_slice(), b'0'),
            (b"etc/".as_slice(), b"".as_slice(), b'5'),
            (b"etc/hello.conf".as_slice(), config.as_slice(), b'0'),
        ])
    }

    #[test]
    fn a_well_formed_package_verifies_and_serves_its_payload() {
        let bytes = good();
        let verified = verify(&bytes).unwrap();
        assert_eq!(verified.manifest().name, b"hello");
        assert_eq!(verified.data(b"bin/hello").unwrap(), b"\x7fELF-stand-in");
        assert_eq!(
            verified.data(b"etc/hello.conf").unwrap(),
            b"greeting=namaste\n"
        );
        assert!(verified.data(b"etc/absent").is_none());
    }

    #[test]
    fn the_manifest_must_come_first() {
        let bytes = archive_of(&[
            (b"bin/hello".as_slice(), b"x".as_slice(), b'0'),
            (
                b"manifest".as_slice(),
                b"package hello\nversion 0.1.0\n".as_slice(),
                b'0',
            ),
        ]);
        assert_eq!(verify(&bytes).err(), Some(PackageError::ManifestNotFirst));
    }

    #[test]
    fn a_flipped_payload_byte_is_a_wrong_digest() {
        let mut bytes = good();
        // The binary's bytes sit after the manifest's blocks; flip one by
        // finding the stand-in's marker in the raw archive.
        let position = bytes
            .windows(13)
            .position(|window| window == b"\x7fELF-stand-in")
            .unwrap();
        bytes[position + 5] ^= 0x01;
        assert!(matches!(verify(&bytes), Err(PackageError::WrongDigest(0))));
    }

    #[test]
    fn a_missing_payload_is_named_by_index() {
        let manifest_text = std::format!(
            "package hello\nversion 0.1.0\n\nfile etc/gone sha256={} length=0\n",
            hex(sha256::digest(b"")),
        );
        let bytes = archive_of(&[(b"manifest".as_slice(), manifest_text.as_bytes(), b'0')]);
        assert!(matches!(verify(&bytes), Err(PackageError::Missing(0))));
    }

    #[test]
    fn a_length_that_disagrees_is_refused_before_hashing() {
        let manifest_text = std::format!(
            "package hello\nversion 0.1.0\n\nfile etc/x sha256={} length=99\n",
            hex(sha256::digest(b"abc")),
        );
        let bytes = archive_of(&[
            (b"manifest".as_slice(), manifest_text.as_bytes(), b'0'),
            (b"etc/x".as_slice(), b"abc".as_slice(), b'0'),
        ]);
        assert!(matches!(verify(&bytes), Err(PackageError::WrongLength(0))));
    }

    #[test]
    fn an_unclaimed_member_refuses_the_whole_package() {
        let manifest_text = "package hello\nversion 0.1.0\n";
        let bytes = archive_of(&[
            (b"manifest".as_slice(), manifest_text.as_bytes(), b'0'),
            (
                b"etc/dropping".as_slice(),
                b"nobody claimed me".as_slice(),
                b'0',
            ),
        ]);
        assert_eq!(verify(&bytes).err(), Some(PackageError::Unclaimed));
    }

    #[test]
    fn an_escaping_member_name_is_refused_as_a_name() {
        let manifest_text = "package hello\nversion 0.1.0\n";
        let bytes = archive_of(&[
            (b"manifest".as_slice(), manifest_text.as_bytes(), b'0'),
            (b"../escape".as_slice(), b"out".as_slice(), b'0'),
        ]);
        assert_eq!(verify(&bytes).err(), Some(PackageError::BadMemberName));
    }

    #[test]
    fn a_link_or_device_member_is_refused() {
        let manifest_text = "package hello\nversion 0.1.0\n";
        let bytes = archive_of(&[
            (b"manifest".as_slice(), manifest_text.as_bytes(), b'0'),
            (b"etc/link".as_slice(), b"".as_slice(), b'2'),
        ]);
        assert_eq!(verify(&bytes).err(), Some(PackageError::Unclaimed));
    }

    #[test]
    fn a_refused_manifest_refuses_the_package_with_its_reason() {
        let bytes = archive_of(&[(b"manifest".as_slice(), b"version 0.1.0\n".as_slice(), b'0')]);
        assert!(matches!(
            verify(&bytes),
            Err(PackageError::Manifest(ManifestError::PackageMisplaced(1)))
        ));
    }

    #[test]
    fn an_empty_archive_is_not_a_package() {
        assert!(matches!(verify(&[]), Err(PackageError::ManifestNotFirst)));
        assert!(matches!(
            verify(&[0u8; 1024]),
            Err(PackageError::ManifestNotFirst)
        ));
    }

    /// The seeded generator, a third time, for the same reason.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        }

        fn below(&mut self, bound: usize) -> usize {
            if bound == 0 {
                0
            } else {
                (self.next() % bound as u64) as usize
            }
        }
    }

    #[test]
    fn a_mutation_harness_never_makes_the_walk_panic() {
        let iterations: usize = std::env::var("BHASKIX_FUZZ_ITERATIONS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(10_000);

        let seed_package = good();
        for seed in 0..iterations as u64 {
            let mut rng = Rng(seed.wrapping_mul(0x2545_f491_4f6c_dd1d).wrapping_add(1));
            let mut bytes = seed_package.clone();
            let mutations = 1 + rng.below(8);
            for _ in 0..mutations {
                match rng.below(3) {
                    0 => {
                        let index = rng.below(bytes.len());
                        bytes[index] = rng.next() as u8;
                    }
                    1 => {
                        let length = rng.below(bytes.len().max(1));
                        bytes.truncate(length);
                    }
                    _ => {
                        let extra = rng.below(512);
                        for _ in 0..extra {
                            bytes.push(rng.next() as u8);
                        }
                    }
                }
                if bytes.is_empty() {
                    break;
                }
            }
            let first = verify(&bytes).is_ok();
            let second = verify(&bytes).is_ok();
            assert_eq!(first, second, "seed {seed} not stable");
        }
    }
}
