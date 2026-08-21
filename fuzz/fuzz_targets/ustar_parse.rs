// SPDX-License-Identifier: Apache-2.0
//! Coverage-guided fuzzing of the `ustar` archive parser.
//!
//! The initrd is the first untrusted input this system reads: the kernel finds
//! `bin/probe`, `etc/hostname` and every other early file by walking it, before
//! there is a filesystem, a service, or a domain to contain a mistake. A parser
//! this early has no one above it to catch anything.
//!
//! `TRACKER.md` has recorded the §8 deviation for this parser since M6 — the
//! requirement was met by a seeded mutation harness, and one million blind
//! archives is a real number that is not the same assurance as guidance. The
//! ELF loader closed its half on 2026-08-10; this is the other.
//!
//! # What is exercised
//!
//! Iteration, `members`, and `lookup` — deliberately all three. Iteration is
//! where a length field decides how far to jump; `lookup` compares names and
//! then hands back a slice. A parser can be safe walking an archive and still
//! be wrong about where a member's *data* ends, which is the bug that matters,
//! because `data()` is what the caller goes on to read.
//!
//! # Four arms, because one of them reaches almost nothing
//!
//! The reachability audit of 2026-08-21 instrumented this target with probe
//! points and ran it from an **empty corpus** — which is what a fresh clone
//! has, since `fuzz/corpus/` is gitignored. It reached **one of five**: "the
//! `ustar` magic is present in the first header block", and nothing below it.
//! It never yielded an entry, never saw a payload, never reached a second
//! member and never matched a lookup. With the 715-unit corpus that had
//! accumulated on one machine it reached all five in 34,227 runs — so the
//! assurance was real, and it lived in an untracked directory. That is not
//! assurance; that is a local file.
//!
//! The wall is the header itself. A block is only a header if it carries the
//! literal `ustar` at offset 257 **and** an octal checksum at 148..156 that
//! sums the whole 512 bytes with its own field read as spaces. Neither is
//! guessable, and the second one changes every time the fuzzer touches
//! anything. So the arms below build well-formed archives *inside* the target
//! and let the fuzzer mutate within them, re-deriving the checksum afterwards
//! so the mutation reaches the walker instead of dying at `checksum_matches`.
//! This is the `fs_image.rs` pattern, applied to the other integrity check.
//!
//! **Recomputing the checksum is deliberate and is not cheating.** The parser's
//! own comment says so first: the checksum "proves nothing about
//! trustworthiness — an attacker computes it as easily as `tar` does". It
//! catches a truncated or misaligned archive. Somebody who can write the boot
//! medium computes a valid one, and that is the threat being modelled. Arm A is
//! the accident; arms B to D are the attacker.
//!
//! **Arm A — raw bytes.** The original target, unchanged: whatever the fuzzer
//! sends, walked as an archive. It is the honest baseline, it is the arm that
//! proves the *refusal* does not panic, and on its own it is nearly useless —
//! from empty it reaches the magic check and stops. Corrupted boot media look
//! like this, so it stays.
//!
//! **Arm B — a well-formed archive the fuzzer composed.** One to three members
//! built through `ustar::test_support`, with names, payloads and type flags
//! taken from the input. This is the arm that reaches an entry, a payload, a
//! second member and a matching lookup at all, and it is the only arm that can
//! assert an *answer* rather than merely the absence of a crash: an archive
//! this target built has exactly one correct listing, and the arm checks it
//! member by member — name, kind, and the payload bytes. A parser that
//! mislaid a member's data by a block would be caught here and nowhere else.
//!
//! **Arm C — the size field, behind a valid checksum.** The field that decides
//! how far `next` jumps, handed to the fuzzer directly: a three-member archive
//! is built, the first header's size is re-rendered from a fuzzer-chosen value
//! as legal octal, and the header is resealed. The cursor then lands where the
//! input says — on the second header, one byte short of it, inside a payload,
//! or past the end. The first member's payload **begins with a well-formed
//! header block for a name the fuzzer chose**, which is the attack the parser's
//! own comment names: "a reader that hunts for the next plausible header can be
//! walked through a payload chosen to contain one". Here the payload contains
//! one, and the size field aims at it.
//!
//! **Arm D — fuzzer bytes spliced over the first header, resealed.** A window
//! whose offset and length the input picks, written over the header and the
//! checksum re-derived. Everything a header holds is reachable this way — the
//! name and its NUL, the octal fields with their spaces and their non-digits,
//! the type flag, the magic, the prefix — with the checksum no longer standing
//! in the way. Arm C aims one field; arm D aims at all of them.
//!
//! # Measured, not assumed
//!
//! The same five probe points, re-run against these arms — not under libFuzzer
//! but against 40,000 *uniformly random* inputs, which is the weakest input
//! source there is and therefore the honest floor. All five are reached: an
//! entry is yielded 204,255 times, a non-empty payload seen 77,347, a second
//! member reached 66,959, and a lookup matched 76,596 — of which 24,296 are
//! arm C's stowaway, found because a rewritten size field landed the cursor on
//! a header hidden inside a payload, and 12,501 are a later member found after
//! the first one's size was rewritten. That stowaway number is the one worth
//! having: it is the attack the parser's comment describes, reached on purpose
//! rather than waited for.
//!
//! The assertions were made to fail on purpose before being believed, which is
//! the only way to know an assertion is load-bearing. Expecting a directory to
//! carry its payload trips the data check; cutting one member off the end of a
//! well-formed archive trips the count check. Neither fires otherwise.
//!
//! Under libFuzzer itself, from an empty corpus: **610,801 runs in 241
//! seconds, no crash and no timeout**, and a corpus of 345 units grown from
//! nothing. That last number is the part that matters as much as the first —
//! the arms give the fuzzer inputs whose mutations are worth keeping, so a
//! fresh clone builds its own corpus instead of depending on someone else's
//! untracked directory.
//!
//! # What counts as a failure
//!
//! A panic, an abort, or a hang. **Not** a refusal, and not a nonsense answer:
//! random bytes are not an archive and finding nothing in them is correct. What
//! must never happen is a slice out of bounds, an offset that wraps, or an
//! iterator that never ends because a member claims a size that moves the
//! cursor backwards.
//!
//! Beyond that, three assertions, and each one is a real claim about the
//! parser rather than a check that the harness ran. **A well-formed archive
//! lists exactly what was put in it** (arm B). **A listing is never longer
//! than the archive has blocks**, on every arm, because `next` advances by at
//! least a block each time round. **The same bytes give the same answer
//! twice**, which is where a parser reading uninitialised state would show up.
//! If a seeded input trips one of these, that is a finding and not a thing to
//! silence.
//!
//! That last invariant of the walk is the parser's own and not this harness's
//! to enforce: `next` advances the cursor by at least a block every time round,
//! through `checked_add`, so it cannot presently run for ever. The bound in
//! `walk` caps what *this* target iterates. It is not a hang detector —
//! `members` and `lookup` walk the whole archive with no bound at all, and are
//! called precisely so that a parser which ever did loop would show up as a
//! libFuzzer timeout rather than as a target that quietly stopped at 4,096.
//!
//! Run with:
//!
//! ```text
//! cargo +nightly fuzz run ustar_parse -- -max_total_time=3600
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;

// The parser itself, not the filesystem service's re-export of it. Same crate
// and same types either way — `bhaskix_service_vfs::ustar` *is* this module —
// but the seeded arms need `test_support`, and the direct dependency is what
// carries the `test-support` feature that gates it.
use bhaskix_ustar::{Archive, BLOCK, EntryKind, test_support};

/// Offsets this target writes to, from the format definition.
///
/// Named here rather than re-derived at each use: the crate keeps its own copy
/// private, and a magic `124` three lines apart is how a harness ends up
/// attacking the uid field while claiming to attack the size.
const SIZE: (usize, usize) = (124, 12);
const CHECKSUM: (usize, usize) = (148, 8);

/// The largest member name the seeded arms will build.
///
/// The name field is 100 bytes and `test_support::header` copies the name in at
/// offset 0, so a longer one would overwrite the mode field — or, past 512,
/// panic inside the *builder*. A panic in the harness is not a finding, and a
/// finding that turns out to be the harness costs more than the input was
/// worth.
const MAX_NAME: usize = 100;

/// The largest payload the seeded arms will build.
///
/// Exactly two blocks: enough that a payload crosses a block boundary and can
/// hold a stowaway header with room after it, small enough that a three-member
/// archive stays in the low kilobytes and the fuzzer is mutating a large
/// fraction of it per pass.
const MAX_PAYLOAD: usize = 1024;

fuzz_target!(|data: &[u8]| {
    arm_raw(data);
    arm_built(data);
    arm_size(data);
    arm_splice(data);
});

/// Whatever the fuzzer sent, read as an archive.
///
/// The original target's work, unchanged: whatever arrives, walked, listed and
/// looked up. It reaches the magic check and, essentially never, anything past
/// it — which is the whole reason the other three exist. The two invariants
/// `walk` now asserts ride along with it, and they are claims about garbage as
/// much as about seeded input.
fn arm_raw(data: &[u8]) {
    walk(data);
}

/// An archive this target built, from names and payloads the fuzzer chose.
///
/// The arm that reaches an entry at all, and the only one that knows the right
/// answer: nothing has been corrupted, so the listing must be exactly the
/// members that went in.
fn arm_built(data: &[u8]) {
    let mut take = Take::new(data);
    let members = compose(&mut take);
    if members.is_empty() {
        return;
    }
    let refs = borrow(&members);
    let bytes = test_support::archive_of(&refs);

    // What the parser must say. A member whose stored name is empty — because
    // the fuzzer chose no name, or chose one starting with a NUL — is skipped
    // by `next` rather than yielded, and its payload is still stepped over, so
    // it drops out of the expectation but not out of the archive.
    let expected: Vec<(&[u8], &[u8], EntryKind)> = members
        .iter()
        .filter_map(|member| {
            let name = stored(member.name);
            if name.is_empty() {
                return None;
            }
            let kind = match member.kind {
                b'0' | b'\0' => EntryKind::File,
                b'5' => EntryKind::Directory,
                _ => EntryKind::Other,
            };
            let data: &[u8] = if kind == EntryKind::File {
                member.payload
            } else {
                // Anything that is not a file carries no payload, however many
                // bytes the header claimed — and the cursor still steps over
                // them, which is the half of this that is worth checking.
                &[]
            };
            Some((name, data, kind))
        })
        .collect();

    let listed: Vec<_> = Archive::new(&bytes).collect();
    assert_eq!(
        listed.len(),
        expected.len(),
        "a well-formed archive of {} members listed {}",
        expected.len(),
        listed.len()
    );
    for (index, (entry, (name, payload, kind))) in listed.iter().zip(expected.iter()).enumerate() {
        assert_eq!(
            entry.name(),
            *name,
            "member {index} listed under a wrong name"
        );
        assert_eq!(entry.kind(), *kind, "member {index} listed as a wrong kind");
        // The one that matters: a parser can walk an archive correctly and
        // still hand the caller a slice that starts or ends in the wrong place.
        assert_eq!(
            entry.data(),
            *payload,
            "member {index} handed back {} bytes of payload, not {}",
            entry.data().len(),
            payload.len()
        );
    }

    // A lookup that must match, which from an empty corpus never happened.
    // Only for a name `is()` can round-trip: it strips a leading `./` from the
    // stored name and a leading `/` from the path, so `./x` is found as `x` and
    // never as `./x`. Duplicate names are allowed here — `lookup` answers with
    // the first, which is still a match.
    if let Some((name, _, _)) = expected.first()
        && !name.starts_with(b"./")
        && !name.starts_with(b"/")
    {
        assert!(
            Archive::new(&bytes).lookup(name).is_some(),
            "a member of a well-formed archive was not found under its own name"
        );
    }

    walk(&bytes);
}

/// A valid archive whose first member's size field the fuzzer wrote.
///
/// The size decides how far `next` jumps, so this is the arm that decides where
/// the walk lands. The first payload opens with a well-formed header block, so
/// "somewhere in the middle of a payload" is a place a header can be found —
/// the misalignment the checksum is supposed to catch, aimed on purpose.
fn arm_size(data: &[u8]) {
    let mut take = Take::new(data);
    let selector = take.byte();
    // The stowaway's name, and a name for it if the input did not give one: an
    // empty-named header is skipped by `next` rather than yielded, so an
    // unnamed stowaway could never be observed arriving.
    let stowaway = match take.chunk(MAX_NAME) {
        [] => b"stowaway".as_slice(),
        chosen => chosen,
    };
    // Folded into the payload's range: a raw `u16` is past the end of anything
    // this arm builds nineteen times in twenty, and "past the end" is one case
    // rather than the only one.
    let stow_size = usize::from(u16::from_le_bytes([take.byte(), take.byte()])) % (MAX_PAYLOAD + 1);
    let members = compose(&mut take);
    if members.is_empty() {
        return;
    }

    // The first member's payload: a header for a member that does not exist,
    // followed by whatever the fuzzer put there. A size field that lands the
    // cursor on this block finds a member inside a payload.
    let mut first = Vec::with_capacity(BLOCK + members[0].payload.len());
    first.extend_from_slice(&test_support::header(stowaway, stow_size, b'0'));
    first.extend_from_slice(members[0].payload);

    let mut refs = borrow(&members);
    refs[0].1 = &first;
    let mut bytes = test_support::archive_of(&refs);
    if bytes.len() < BLOCK {
        return;
    }

    // What the honest header says, so the fuzzer can aim relative to it.
    let honest = first.len() as u64;
    let total = bytes.len() as u64;
    let word = take.word();
    let size = match selector % 4 {
        // Anywhere in the 33 bits the field can express — mostly past the end,
        // which is the refusal path and must not read out of bounds.
        0 => word,
        // A whole number of blocks, so the cursor lands on a block boundary
        // where a header could legitimately be.
        1 => (word % 32) * BLOCK as u64,
        // Near the truth: one byte either side of the correct jump is the
        // misaligned archive, where the next header is off by a byte.
        2 => honest.saturating_add(word % 33).saturating_sub(16),
        // Somewhere inside this archive, chosen by the input.
        _ => word % total.saturating_add(1),
    };
    write_octal(&mut bytes[SIZE.0..SIZE.0 + SIZE.1], size);
    seal(&mut bytes);

    walk(&bytes);
    // The names that only a successful jump can reach: the stowaway inside the
    // payload, and the members after the first.
    let archive = Archive::new(&bytes);
    let _ = archive.lookup(stowaway);
    for member in members.iter().skip(1) {
        let _ = archive.lookup(stored(member.name));
    }
}

/// A valid archive with fuzzer bytes spliced over the first header.
///
/// Arm C aims one field; this aims at all of them. The checksum is re-derived
/// after the splice, so a mutated name, type flag, octal field, magic or prefix
/// reaches the walker instead of ending the listing at `checksum_matches`.
fn arm_splice(data: &[u8]) {
    let mut take = Take::new(data);
    // Two bytes for the offset, because one reaches only the first 256 of the
    // header's 512 and the magic lives at 257.
    let at = usize::from(u16::from_le_bytes([take.byte(), take.byte()])) % BLOCK;
    let patch = take.chunk(BLOCK);
    let members = compose(&mut take);
    if members.is_empty() {
        return;
    }
    let refs = borrow(&members);
    let mut bytes = test_support::archive_of(&refs);
    if bytes.len() < BLOCK {
        return;
    }

    let end = at.saturating_add(patch.len()).min(BLOCK);
    bytes[at..end].copy_from_slice(&patch[..end - at]);
    seal(&mut bytes);

    walk(&bytes);
}

/// One member of an archive this target builds.
struct Member<'a> {
    name: &'a [u8],
    payload: &'a [u8],
    kind: u8,
}

/// Takes one to three members off the input.
///
/// Bounded at three because the fuzzer's leverage is in the *fields*, not in
/// the member count: a fourth member costs input bytes that would otherwise
/// steer a size, and every arm here is about where the cursor goes rather than
/// how long the listing is.
fn compose<'a>(take: &mut Take<'a>) -> Vec<Member<'a>> {
    // Three names to fall back on, one per slot. A member the input did not
    // name is stored with an empty name, and `next` skips an empty-named
    // member rather than yielding it — so an exhausted cursor would silently
    // reduce every archive to one member, and "reaches a second member" would
    // depend on the input being long enough rather than on the parser. An
    // empty name is still reachable on purpose: a name of one NUL byte stores
    // one, which is what a hostile archive would carry anyway.
    const FALLBACK: [&[u8]; 3] = [b"a", b"b/c", b"./d"];

    let count = 1 + usize::from(take.byte() % 3);
    let mut members = Vec::with_capacity(count);
    for slot in 0..count {
        let chosen = take.chunk(MAX_NAME);
        let name = if chosen.is_empty() {
            FALLBACK[slot % FALLBACK.len()]
        } else {
            chosen
        };
        let payload = take.chunk(MAX_PAYLOAD);
        // Weighted towards the flags the parser interprets — files most of
        // all, since a file is the only kind that carries data — with the raw
        // byte still reachable so `EntryKind::Other` and the undefined flags
        // are exercised.
        let raw = take.byte();
        let kind = match raw % 8 {
            0..=3 => b'0',
            4 => b'5',
            5 => 0,
            6 => b'2',
            _ => raw,
        };
        members.push(Member {
            name,
            payload,
            kind,
        });
    }
    members
}

/// The shape `test_support::archive_of` wants.
fn borrow<'a>(members: &'a [Member<'a>]) -> Vec<(&'a [u8], &'a [u8], u8)> {
    members
        .iter()
        .map(|member| (member.name, member.payload, member.kind))
        .collect()
}

/// The name as the header will store it: everything before the first NUL.
///
/// `text` reads a NUL-terminated field, so a name with a NUL in it is stored
/// whole and read back short. That is the parser's answer and this is how the
/// expectation is derived rather than assumed.
fn stored(name: &[u8]) -> &[u8] {
    match name.iter().position(|byte| *byte == 0) {
        Some(nul) => &name[..nul],
        None => name,
    }
}

/// Re-derives the header checksum over the first block, the way an attacker
/// would.
///
/// Not a second header builder — `ustar::test_support` is the one definition of
/// a well-formed header and this target uses it. This is the other half of the
/// threat model: the arithmetic anybody who can write the archive performs
/// after changing a field. The field itself is counted as spaces, by
/// definition, and the sum of 512 bytes cannot exceed six octal digits
/// (512 × 255 = 0o377100), so six digits, a NUL and a space is the whole
/// encoding.
fn seal(bytes: &mut [u8]) {
    let Some(header) = bytes.get_mut(..BLOCK) else {
        return;
    };
    let (start, length) = CHECKSUM;
    header[start..start + length].copy_from_slice(b"        ");
    let sum: u64 = header.iter().map(|byte| u64::from(*byte)).sum();

    let mut digits = [b'0'; 8];
    let mut value = sum;
    let mut index = 5;
    loop {
        digits[index] = b'0' + (value % 8) as u8;
        value /= 8;
        if index == 0 || value == 0 {
            break;
        }
        index -= 1;
    }
    digits[6] = 0;
    digits[7] = b' ';
    header[start..start + length].copy_from_slice(&digits);
}

/// Renders `value` into a twelve-byte octal field: eleven digits and a NUL.
///
/// Masked to what the field can hold rather than truncated silently, so the
/// size the parser reads is the value this target meant to write. Eleven octal
/// digits is 33 bits — about 8 GiB, far past the end of any archive the fuzzer
/// can build, which is exactly the refusal path worth reaching.
fn write_octal(field: &mut [u8], value: u64) {
    const MAX: u64 = 0o77_777_777_777;

    let mut digits = [b'0'; 12];
    let mut value = value & MAX;
    let mut index = 10;
    loop {
        digits[index] = b'0' + (value % 8) as u8;
        value /= 8;
        if index == 0 || value == 0 {
            break;
        }
        index -= 1;
    }
    digits[11] = 0;
    field.copy_from_slice(&digits);
}

/// What a caller does with an archive: walk it, count it, look something up.
///
/// Returns the member count so the arms can assert on it. Every arm ends here,
/// including the raw one, so that the bounded-listing and determinism claims
/// hold for garbage as well as for seeded input.
fn walk(bytes: &[u8]) -> usize {
    // Any real initrd is far below this; an input that exceeds it is one the
    // fuzzer built to be walked, not one a caller would read. It caps this
    // loop only — `members` and `lookup` below are unbounded on purpose.
    const MAX_MEMBERS: usize = 4096;

    let mut walked = 0usize;
    for entry in Archive::new(bytes) {
        // Touch what a caller touches: the name and the data slice. Walking
        // headers without reading a member proves only half of it.
        let _ = entry.name();
        let _ = entry.data();
        let _ = entry.kind();
        walked += 1;
        if walked >= MAX_MEMBERS {
            break;
        }
    }

    let archive = Archive::new(bytes);
    let members = archive.members();
    let _ = archive.lookup(b"etc/hostname");
    let _ = archive.lookup(b"");

    // A member costs at least one block, because `next` needs a whole header
    // to read one and advances by at least `BLOCK` afterwards. A listing longer
    // than the archive has blocks would mean the cursor went backwards.
    assert!(
        members <= bytes.len() / BLOCK + 1,
        "{members} members listed from {} bytes",
        bytes.len()
    );
    // The same bytes, the same answer. A parser whose result depended on
    // anything but its input would show up here.
    assert_eq!(
        Archive::new(bytes).members(),
        members,
        "two walks of one archive disagreed"
    );
    members
}

/// A cursor that takes fields off the front of the input.
///
/// Exhaustion yields zeros and empty slices rather than stopping the arm: a
/// short input should still build an archive and exercise the walk, and every
/// answer here is a function of the input alone — no clock, no randomness, so a
/// crashing input reproduces exactly.
struct Take<'a> {
    rest: &'a [u8],
}

impl<'a> Take<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { rest: bytes }
    }

    fn byte(&mut self) -> u8 {
        match self.rest.split_first() {
            Some((first, rest)) => {
                self.rest = rest;
                *first
            }
            None => 0,
        }
    }

    fn take(&mut self, length: usize) -> &'a [u8] {
        let length = length.min(self.rest.len());
        let (head, rest) = self.rest.split_at(length);
        self.rest = rest;
        head
    }

    /// A length-prefixed run of bytes, no longer than `max`.
    ///
    /// Folded into the range rather than clamped to it: clamping means every
    /// length byte above the cap asks for the cap, so a fuzzer nudging bytes
    /// spends most of its inputs on maximum-length names and empties the
    /// cursor before the later fields are reached. The fold spreads the
    /// lengths, and short names leave input over for the size field.
    fn chunk(&mut self, max: usize) -> &'a [u8] {
        let length = usize::from(u16::from_le_bytes([self.byte(), self.byte()])) % (max + 1);
        self.take(length)
    }

    fn word(&mut self) -> u64 {
        let taken = self.take(8);
        let mut buffer = [0u8; 8];
        buffer[..taken.len()].copy_from_slice(taken);
        u64::from_le_bytes(buffer)
    }
}
