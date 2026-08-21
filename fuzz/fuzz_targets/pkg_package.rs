// SPDX-License-Identifier: Apache-2.0
//! Coverage-guided fuzzing of the whole `.bpk` walk.
//!
//! RFC 0030: `verify` is the single gate between "bytes an operator was
//! handed" and "a package an installer copies from" — the archive walk, the
//! manifest parse, the digest and length checks and the unclaimed-member
//! refusal, composed. Composition is why it gets its own target beside
//! `ustar_parse` and `pkg_manifest`: each layer can hold alone and the seam
//! between them still be wrong, and the seam is where a member's *name*
//! meets a manifest's *path*.
//!
//! # Why this target has nine arms
//!
//! The reachability audit of 2026-08-21 ran every target from an **empty
//! corpus**, which is what a fresh clone has, `fuzz/corpus/` being
//! gitignored. This target reached **0 of 5 probe points in 5,384,466
//! executions** — not one input ever got past the first line of `verify`.
//!
//! The cause is three integrity checks stacked on top of one another. A
//! `ustar` header needs the literal `ustar` at offset 257 *and* an octal
//! checksum at 148..156 covering the whole header; the first member must
//! then be named `manifest`; its text must contain the ASCII word `package`;
//! and every `file` line must carry sixty-four hex digits that are the
//! **actual SHA-256** of a member the archive **actually has**, at its
//! **actual length**. A fuzzer does not guess a SHA-256. Random bytes are
//! refused at the magic and the walk beneath is never entered.
//!
//! So this target does what `fs_image.rs` does: it **builds the valid
//! structure inside the target** and lets the fuzzer mutate within it,
//! re-deriving each integrity value the structure demands so the mutation
//! reaches the code being attacked. **Recomputing a digest is deliberate and
//! is not cheating.** A digest defends against corruption, not against
//! somebody who can write the archive: an attacker handing you a package
//! computes correct ones and then lies about something else. Arm A is the
//! accident; arms B onward are the threat model.
//!
//! **Arm A — raw bytes.** `verify` over whatever the fuzzer sent, with the
//! original assertions unchanged. This is the honest baseline, and on its
//! own it is the 5.4-million-execution nothing described above. It stays
//! because a corrupt download really does look like this, and because it is
//! the arm that proves the refusals themselves do not panic.
//!
//! **Arm B — a genuinely valid package.** Manifest first, one to four
//! payloads whose bytes come from the fuzzer, with `sha256=` and `length=`
//! derived from those bytes, plus a directory member. It **must verify**,
//! every payload must come back through `data()` byte for byte, and
//! `manifest_bytes()` must be the manifest exactly as it travelled — the
//! promise an installer relies on when it records what was reviewed. This
//! arm is also the seam test: a knob prefixes every member name with `./`,
//! the way `tar -C dir .` writes them, and acceptance must not change.
//!
//! Arms C to H each take arm B's package and break exactly one thing, so
//! each lands on a *named* refusal in `pkg/src/package.rs` and the assertion
//! can name it too. An arm that expected `WrongDigest` and got `Unclaimed`
//! would mean the walk refused for the wrong reason, which is how a check
//! that has quietly stopped running hides.
//!
//! - **C — a digest wrong by one nibble.** One hex digit of one `file` line
//!   is rotated to a different hex digit, so the manifest still parses and
//!   the length still agrees: the only thing left to catch it is the digest
//!   comparison. `WrongDigest(index)`.
//! - **D — a length that disagrees with the payload.** `WrongLength(index)`,
//!   and it must be refused *before* the hash is computed.
//! - **E — a member the manifest never mentions.** Three flavours, because
//!   the walk refuses them by different routes: an ordinary unclaimed file
//!   (`Unclaimed`), a name that escapes upward (`BadMemberName` — `..` in a
//!   member name is an escape attempt, not a forgotten line), and a link
//!   member, which is `EntryKind::Other` (`Unclaimed`).
//! - **F — a member mentioned but absent.** `Missing(index)`.
//! - **G — the manifest not first.** A payload before it, a `manifest` that
//!   is a directory, or a leading directory member — that last is what a
//!   plain `tar -C dir .` actually produces, so it is a real mistake and not
//!   only a hostile one. `ManifestNotFirst`.
//! - **H — a directory where a file was promised.** The member named by a
//!   `file` line is emitted with type flag `5`. Reported as
//!   `WrongLength(index)`, because a directory entry carries no payload and
//!   the kind check shares that variant — correct, and worth knowing before
//!   reading a refusal as "the bytes were the wrong size".
//!
//! **Arm I — a well-formed archive around the fuzzer's own manifest.** The
//! first member is `manifest` and its text is the raw input, with real
//! payload members after it. This is the only arm that lets the fuzzer steer
//! the *grammar* from inside a valid archive, so it is the one that reaches
//! `PackageError::Manifest` and the paths where a manifest parses but names
//! something the archive does not have. No expected error: almost everything
//! is refused, and an acceptance is checked like any other.
//!
//! # What counts as a failure
//!
//! A panic, an abort, or a hang. **Not** a refusal: almost every input is
//! refused, each with a typed reason. On the rare accepted input, every
//! payload the manifest names is fetched through `data()` and its length
//! re-checked against the file line — an acceptance whose promises then fail
//! is exactly the composed bug this target exists to catch. In the seeded
//! arms a *wrong* refusal is a failure too: those inputs are constructed, so
//! the expected reason is known before `verify` is called.
//!
//! No `unsafe`, nothing that reads a clock, and nothing random: every arm is
//! a pure function of the input, so a crash reproduces from its file.
//!
//! Run with:
//!
//! ```text
//! cargo +nightly fuzz run pkg_package -- -max_total_time=3600
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;

use bhaskix_pkg::package::{self, PackageError, Verified};
use bhaskix_pkg::sha256;
use bhaskix_ustar::test_support::archive_of;

/// The payload paths the seeded arms use, in manifest order.
///
/// Four, and the bound is deliberate: the grammar allows sixty-four `file`
/// lines, but the arms attack *one line by index*, and four is already
/// enough for an index to distinguish "the first" from "a later one" while
/// keeping every execution short. Raising it would buy repetition, not
/// coverage. `PATHS[0]` is what the optional `program` section names, so it
/// is always present — a `program` line without its `file` line is refused
/// by the grammar before this target's subject is reached.
const PATHS: [&str; 4] = [
    "bin/prog",
    "etc/prog.conf",
    "share/data.bin",
    "lib/thing.so",
];

/// How many bytes of the input steer the shape rather than fill a payload.
const CONTROL: usize = 4;

fuzz_target!(|data: &[u8]| {
    arm_a(data);

    let Some(seed) = Seed::of(data) else {
        return;
    };
    arm_b(&seed);
    arm_c(&seed);
    arm_d(&seed);
    arm_e(&seed);
    arm_f(&seed);
    arm_g(&seed);
    arm_h(&seed);
    arm_i(&seed, data);
});

/// Whatever the fuzzer sent, read as a package.
///
/// The original target, assertions intact.
fn arm_a(data: &[u8]) {
    if let Ok(verified) = package::verify(data) {
        for file in verified.manifest().files() {
            // Everything the manifest names was proven present, with this
            // length. Hold verify to its own promise.
            let payload = verified.data(file.path).expect("verified file present");
            assert_eq!(payload.len() as u64, file.length);
        }
    }
}

/// The shape of the package the seeded arms build, taken from the input.
struct Seed {
    /// One payload per `file` line, in manifest order. Between one and
    /// [`PATHS`]`.len()` of them.
    payloads: Vec<Vec<u8>>,
    /// Whether every member name carries the `./` prefix `tar -C dir .`
    /// writes. Acceptance must not depend on it.
    dotted: bool,
    /// Whether the manifest declares a `program` section for `PATHS[0]`.
    program: bool,
    /// Which `file` line the single-line arms attack. Always in range.
    target: usize,
    /// Which of the sixty-four hex digits arm C rotates.
    nibble: usize,
    /// How far arm D's stated length is from the truth. Never zero, or the
    /// arm would be arm B wearing a different name.
    skew: u64,
    /// Which flavour arms E and G use. Always 0, 1 or 2.
    flavour: usize,
}

impl Seed {
    /// Reads the shape out of the front of the input; the rest is payload.
    fn of(data: &[u8]) -> Option<Self> {
        if data.len() < CONTROL {
            return None;
        }
        let count = 1 + usize::from(data[0] & 0b11);
        let body = &data[CONTROL..];

        // Split the remainder into `count` payloads. The last takes the
        // remainder so no byte of the input is dropped; a body shorter than
        // `count` gives empty payloads, which is a legal package and worth
        // reaching (the digest of nothing is a real digest).
        let span = body.len() / count;
        let mut payloads = Vec::with_capacity(count);
        for index in 0..count {
            let start = index * span;
            let end = if index + 1 == count {
                body.len()
            } else {
                start + span
            };
            payloads.push(body[start..end].to_vec());
        }

        Some(Self {
            payloads,
            dotted: data[0] & 0b100 != 0,
            program: data[0] & 0b1000 != 0,
            target: usize::from(data[1]) % count,
            nibble: usize::from(data[2]) % 64,
            skew: 1 + u64::from(data[3]),
            flavour: usize::from(data[0] >> 4) % 3,
        })
    }

    /// How many `file` lines this package carries.
    fn count(&self) -> usize {
        self.payloads.len()
    }

    /// A member name, with the `./` prefix if this seed asked for one.
    fn name(&self, path: &str) -> Vec<u8> {
        let mut out = Vec::with_capacity(path.len() + 2);
        if self.dotted {
            out.extend_from_slice(b"./");
        }
        out.extend_from_slice(path.as_bytes());
        out
    }
}

/// Sixty-four lowercase hex digits, with one of them optionally rotated.
///
/// Rotating rather than replacing keeps the digit *inside* the hex
/// alphabet: a non-hex byte would be refused by the grammar as `BadFile`
/// and arm C would never reach the digest comparison it exists to attack.
fn hex(digest: [u8; sha256::DIGEST], flip: Option<usize>) -> String {
    const ALPHABET: [char; 16] = [
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
    ];
    let mut out = String::with_capacity(64);
    for (position, nibble) in digest
        .iter()
        .flat_map(|byte| [byte >> 4, byte & 0x0f])
        .enumerate()
    {
        let nibble = match flip {
            Some(at) if at == position => (nibble + 1) % 16,
            _ => nibble,
        };
        out.push(ALPHABET[usize::from(nibble)]);
    }
    out
}

/// Renders a manifest for `seed`, optionally lying about one line.
///
/// `flip` rotates one hex digit of one line's digest; `skew` adds to one
/// line's stated length. Everything else is derived from the payload bytes,
/// which is what makes the result verifiable at all.
fn manifest_text(seed: &Seed, flip: Option<(usize, usize)>, skew: Option<(usize, u64)>) -> String {
    let mut text = String::new();
    text.push_str("# built inside fuzz/fuzz_targets/pkg_package.rs\n");
    text.push_str("package hello\nversion 0.1.0\n\n");
    if seed.program {
        // `PATHS[0]` always has a `file` line below, so this section can
        // never be the grammar's `ProgramWithoutFile`.
        text.push_str("program bin/prog\nentry hertz\ncap console\ncap memory pages=2\n\n");
    }
    for (index, payload) in seed.payloads.iter().enumerate() {
        let nibble = match flip {
            Some((line, at)) if line == index => Some(at),
            _ => None,
        };
        let length = match skew {
            Some((line, by)) if line == index => payload.len() as u64 + by,
            _ => payload.len() as u64,
        };
        text.push_str("file ");
        text.push_str(PATHS[index]);
        text.push_str(" sha256=");
        text.push_str(&hex(sha256::digest(payload), nibble));
        text.push_str(" length=");
        text.push_str(&length.to_string());
        text.push('\n');
    }
    text
}

/// A member, owned, in the shape `archive_of` wants it.
type Member = (Vec<u8>, Vec<u8>, u8);

/// The members of a well-formed package: manifest, a directory, payloads.
///
/// The directory member is not decoration — it is the only thing that
/// reaches the `EntryKind::Directory` arm of the unclaimed-member loop, and
/// a real package built by `mkimage` carries one per directory level.
fn members(seed: &Seed, manifest: &str) -> Vec<Member> {
    let mut members = Vec::with_capacity(seed.count() + 2);
    members.push((seed.name("manifest"), manifest.as_bytes().to_vec(), b'0'));
    members.push((seed.name("bin/"), Vec::new(), b'5'));
    for (index, payload) in seed.payloads.iter().enumerate() {
        members.push((seed.name(PATHS[index]), payload.clone(), b'0'));
    }
    members
}

/// Well-formed `ustar` bytes for `members`, headers and checksums included.
///
/// Through `ustar`'s own builder on purpose: a second definition of "a
/// well-formed header" living in the fuzz target would be a second opinion
/// about the format, and the first one to drift would be this one.
fn assemble(members: &[Member]) -> Vec<u8> {
    let typed: Vec<(&[u8], &[u8], u8)> = members
        .iter()
        .map(|(name, data, kind)| (name.as_slice(), data.as_slice(), *kind))
        .collect();
    archive_of(&typed)
}

/// What a caller does with a package that verified.
///
/// Arm A's assertion, in a function so every arm holds `verify` to the same
/// promise: everything the manifest names is present, at the stated length.
fn check(verified: &Verified<'_>) {
    for file in verified.manifest().files() {
        let payload = verified.data(file.path).expect("verified file present");
        assert_eq!(payload.len() as u64, file.length);
    }
    for program in verified.manifest().programs() {
        // The grammar's cross-check, restated where it matters: a program
        // whose bytes were never proven is a program nobody reviewed.
        assert!(
            verified.manifest().file(program.path).is_some(),
            "accepted program without a file line",
        );
    }
}

/// A package built to the rules, which must verify.
fn arm_b(seed: &Seed) {
    let text = manifest_text(seed, None, None);
    let bytes = assemble(&members(seed, &text));

    let verified = package::verify(&bytes).expect("a package built to the rules verifies");
    check(&verified);

    // Byte for byte, not merely "a manifest that parses the same": an
    // installer records these bytes as what was reviewed.
    assert_eq!(verified.manifest_bytes(), text.as_bytes());

    for (index, payload) in seed.payloads.iter().enumerate() {
        let served = verified
            .data(PATHS[index].as_bytes())
            .expect("verified payload present");
        assert_eq!(
            served,
            payload.as_slice(),
            "payload {index} came back wrong"
        );
    }
}

/// One hex digit of one digest rotated: the digest check, alone.
fn arm_c(seed: &Seed) {
    let text = manifest_text(seed, Some((seed.target, seed.nibble)), None);
    let bytes = assemble(&members(seed, &text));
    assert_eq!(
        package::verify(&bytes).err(),
        Some(PackageError::WrongDigest(seed.target)),
        "a digest wrong by one nibble was not caught as one",
    );
}

/// A stated length the payload does not have.
fn arm_d(seed: &Seed) {
    let text = manifest_text(seed, None, Some((seed.target, seed.skew)));
    let bytes = assemble(&members(seed, &text));
    assert_eq!(
        package::verify(&bytes).err(),
        Some(PackageError::WrongLength(seed.target)),
    );
}

/// A member no `file` line claims.
fn arm_e(seed: &Seed) {
    let text = manifest_text(seed, None, None);
    let mut members = members(seed, &text);
    let payload = seed.payloads[seed.target].clone();

    // Three ways in, two refusals out. The escaping name is held to the
    // manifest's path rule and refused as a *name*, before anyone asks
    // whether a line claimed it.
    let expected = match seed.flavour {
        0 => {
            members.push((seed.name("etc/extra"), payload, b'0'));
            PackageError::Unclaimed
        }
        1 => {
            members.push((seed.name("../escape"), payload, b'0'));
            PackageError::BadMemberName
        }
        _ => {
            // Type flag `2` is a hard link: `EntryKind::Other`, which the
            // walk refuses outright rather than interpreting.
            members.push((seed.name("etc/link"), Vec::new(), b'2'));
            PackageError::Unclaimed
        }
    };

    let bytes = assemble(&members);
    assert_eq!(package::verify(&bytes).err(), Some(expected));
}

/// A `file` line whose member is not in the archive.
fn arm_f(seed: &Seed) {
    let text = manifest_text(seed, None, None);
    let mut members = members(seed, &text);
    // The manifest, the directory, then one member per payload — so the
    // line at `target` is at this offset.
    members.remove(2 + seed.target);

    let bytes = assemble(&members);
    assert_eq!(
        package::verify(&bytes).err(),
        Some(PackageError::Missing(seed.target)),
    );
}

/// Something other than the manifest at the front.
fn arm_g(seed: &Seed) {
    let text = manifest_text(seed, None, None);
    let mut members = members(seed, &text);

    match seed.flavour {
        0 => {
            // A payload first — the manifest is still in there, just not
            // where the format says to look.
            members.swap(0, 2);
        }
        1 => {
            // Named `manifest`, but a directory: the name check passes and
            // the kind check is what refuses it.
            members[0].1.clear();
            members[0].2 = b'5';
        }
        _ => {
            // What `tar -C dir .` actually writes: the directory itself,
            // first. An honest mistake, refused like a hostile one.
            members.swap(0, 1);
        }
    }

    let bytes = assemble(&members);
    assert_eq!(
        package::verify(&bytes).err(),
        Some(PackageError::ManifestNotFirst),
    );
}

/// A directory standing where a `file` line promised a file.
fn arm_h(seed: &Seed) {
    let text = manifest_text(seed, None, None);
    let mut members = members(seed, &text);
    let at = 2 + seed.target;
    members[at].1.clear();
    members[at].2 = b'5';

    let bytes = assemble(&members);
    // `WrongLength`, not a kind of its own: a directory carries no payload,
    // so the kind and the length are refused by the same check.
    assert_eq!(
        package::verify(&bytes).err(),
        Some(PackageError::WrongLength(seed.target)),
    );
}

/// A well-formed archive whose manifest is the fuzzer's own text.
///
/// The grammar arm: the `ustar` wall is climbed by construction, so every
/// byte the fuzzer writes lands in the manifest parser and in the seam
/// between a `file` line's path and a member's name. Nearly every input is
/// refused and no particular refusal is expected — but an acceptance is
/// held to the same promises as every other.
fn arm_i(seed: &Seed, data: &[u8]) {
    let mut members = members(seed, "");
    members[0].1 = data.to_vec();

    let bytes = assemble(&members);
    if let Ok(verified) = package::verify(&bytes) {
        check(&verified);
    }
}
