// SPDX-License-Identifier: Apache-2.0
//! Coverage-guided fuzzing of the package manifest grammar.
//!
//! RFC 0030: the manifest is the reviewable half of a package — the file a
//! human reads to know what authority a program asks for. It is also the
//! first thing an installer parses out of an archive an operator was handed,
//! which makes it hostile input by definition, and `docs/coding-style.md` §8
//! applies before it merges.
//!
//! # The wall, and why arm A alone climbed none of it
//!
//! The reachability audit of 2026-08-21 instrumented this target with probe
//! points and ran it from an **empty corpus** — which is what a fresh clone
//! has, since `fuzz/corpus/` is gitignored. It reached **0 of 5 probes in
//! 1,523,042 executions**. Not one input got as far as a program section, a
//! capability line or a file line.
//!
//! The cause is the first line of the grammar. `parse` refuses everything
//! until it has seen the literal ASCII word `package`, and the second
//! directive must be a word from a closed table too. Seven specific bytes in
//! order is not a thing a mutator discovers by chance, so an empty-corpus
//! campaign spends its whole budget in `PackageMisplaced(1)`. The execution
//! count looks enormous and the assurance behind it is one `match` arm.
//!
//! The fix is the one `fs_image.rs` already demonstrates: **build the valid
//! structure inside the target and let the fuzzer choose what goes in it.**
//! Here the structure is text, so the keywords are literals this file writes
//! and every *value* — the name, the version, the paths, the entry word, the
//! cap lines, the `sha256=` hex and the `length=` digits — comes from the
//! fuzzer. The fuzzer stops trying to invent the word `package` and starts
//! exploring the value space, which is where the parser's arithmetic lives.
//!
//! # Five arms, because each one climbs a different part of the wall
//!
//! **Arm A — raw bytes.** `manifest::parse` over whatever the fuzzer sent,
//! with the accessor walk that was here before. This is the honest baseline
//! and it is also the arm the audit measured at zero: it stays because
//! garbage is what a truncated download actually looks like, and because it
//! is the arm that proves the refusal path itself does not panic.
//!
//! **Arm B — the grammar's shape, the fuzzer's values, rendered.** Keywords
//! literal; values mapped into the alphabets the grammar accepts — names and
//! paths through the `[a-z0-9-]` and `[a-z0-9-/._]` tables, versions as three
//! decimal runs, the digest as 64 lowercase hex digits over 32 fuzzer bytes,
//! the length as a fuzzer-chosen `u64`. This is the arm that reaches
//! *acceptance*, and therefore the only arm that reaches the accessors, the
//! cross-check and the capacity checks. Rendering into an alphabet is not
//! rendering into validity: `bin/../x`, `a//b`, a bare `..` and a 100-byte
//! path all fall out of the path table, so `valid_path`'s refusals are
//! reached by near-misses rather than by noise.
//!
//! **Arm C — the grammar's shape, raw values.** The same skeleton with the
//! fuzzer's bytes dropped in unrendered. Keywords still literal, so every
//! directive's argument parser is reached with arbitrary bytes: this is the
//! arm for `BadName`, `BadPath`, `BadFile`, `NotText` and `LineTooLong`, and
//! for the newline a value can smuggle into the middle of a line.
//!
//! **Arm D — keywords from a table.** Each line's *directive* is chosen from
//! a fixed table by a fuzzer byte and its argument from a second table or
//! from raw bytes. This is the malformed-but-plausible arm: a `program` with
//! no `file`, a `cap` before any `program`, a second `package`, `entry`
//! twice, a directive that is nearly a directive (`Package`, `provides`).
//! Arm B can only make a manifest that is shaped right; arm D makes ones
//! that are shaped wrong on purpose, cheaply, in every order.
//!
//! **Arm E — a valid manifest with exactly one deliberate defect.** The base
//! is built to be valid by construction, and a fuzzer byte selects one of
//! sixteen defects, each aimed at one named refusal: a duplicate `package`
//! line, a `program` whose `file` line is missing, a 63-character digest, an
//! uppercase hex digit, a 20-digit `length=` that overflows `u64`, a cap the
//! vocabulary does not contain, one past each of `MAX_PROGRAMS`, `MAX_CAPS`
//! and `MAX_FILES`, a repeated `program` path, a line one byte past
//! `MAX_LINE`, a NUL, `version` before `package`, `version` twice, and
//! `entry` outside a section. Defect 0 is *no defect* — and this arm asserts
//! both directions: with no defect the manifest **must** parse and its
//! accessors must return what was written into it, and with any of the
//! fifteen it **must** be refused.
//!
//! Arm E is the one that would notice a refusal quietly going away. A parser
//! that stops rejecting a 63-character digest still passes every "does not
//! panic" arm ever written, because accepting bad input is not a crash.
//!
//! # What counts as a failure
//!
//! A panic, an abort, or a hang. **Not** a refusal: random bytes are not a
//! manifest and refusing them with a line number is the correct answer. What
//! must never happen is an index past a fixed array's count, arithmetic that
//! wraps in the decimal or hex readers, or an accepted manifest whose
//! accessors then disagree with what was accepted.
//!
//! On success, everything a consumer reads is read: the name, the version,
//! every program's path and capability list, every file line's fields — so a
//! parse that "succeeds" into a state whose accessors panic shows up here
//! and not in an installer. Beyond that, [`exercise`] holds an accepted
//! manifest to the promises the grammar makes about it: the stated
//! capacities, the name and version alphabets, a `program` that always has
//! its `file` line, paths that are unique and cannot climb, `pages=` never
//! zero, and a service name that is never empty. Those are what a caller
//! goes on to trust, so an acceptance that breaks one of them is a finding
//! here rather than a grant of the wrong authority later.
//!
//! Every loop in this file is bounded, and each bound says what it is for at
//! the site. None of them is a hang detector: the parser walks the whole text
//! it is given with no bound at all, so a grammar that ever failed to advance
//! would show up as a libFuzzer timeout rather than as a target that quietly
//! stopped early.
//!
//! Run with:
//!
//! ```text
//! cargo +nightly fuzz run pkg_manifest -- -max_total_time=3600
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;

use bhaskix_pkg::manifest::{self, Cap, MAX_CAPS, MAX_FILES, MAX_LINE, MAX_NAME, MAX_PATH};

fuzz_target!(|data: &[u8]| {
    run(data);
});

/// Every arm, on the same input. Split out of the macro so the arms can be
/// driven from a host harness as well.
fn run(data: &[u8]) {
    arm_a(data);
    arm_b(data);
    arm_c(data);
    arm_d(data);
    arm_e(data);
}

// ---------------------------------------------------------------------------
// The input, read as a stream of decisions
// ---------------------------------------------------------------------------

/// A cursor over the fuzzer's bytes that never fails.
///
/// Past the end every read is zero and every slice is empty, so an arm's
/// shape degrades smoothly as the input shortens instead of vanishing at a
/// length check. That matters for a text format: the interesting inputs are
/// short, and an arm that needed 200 bytes before it emitted anything would
/// be unreachable for most of the corpus.
struct Bytes<'a> {
    data: &'a [u8],
    at: usize,
}

impl<'a> Bytes<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, at: 0 }
    }

    /// The next byte, or zero past the end.
    fn byte(&mut self) -> u8 {
        let byte = self.data.get(self.at).copied().unwrap_or(0);
        self.at = self.at.saturating_add(1);
        byte
    }

    /// The next eight bytes as a little-endian `u64`, zero-filled past the
    /// end. The source of every number a value needs.
    fn word(&mut self) -> u64 {
        let mut value = 0u64;
        for index in 0..8 {
            value |= u64::from(self.byte()) << (index * 8);
        }
        value
    }

    /// A run of up to `max` bytes, the length chosen by the fuzzer.
    ///
    /// The length byte is scaled across `0..=max` rather than used directly,
    /// so `max` may exceed 255 — arm C wants runs longer than `MAX_LINE` in
    /// order to reach `LineTooLong`.
    fn take(&mut self, max: usize) -> &'a [u8] {
        let want = usize::from(self.byte()) * (max + 1) / 256;
        let start = self.at.min(self.data.len());
        let end = start.saturating_add(want).min(self.data.len());
        self.at = end;
        &self.data[start..end]
    }
}

// ---------------------------------------------------------------------------
// Rendering values into the alphabets the grammar accepts
// ---------------------------------------------------------------------------

/// The name alphabet, exactly `manifest::name_byte`'s set.
const NAME: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789-";
/// The path alphabet: the name set plus the three separators. `/`, `.` and
/// `_` are in it on purpose — they are what makes `a//b`, `..` and a leading
/// slash reachable by rendering rather than by luck.
const PATH: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789-/._";
/// Lowercase hex, which is the only case `hex_digest` accepts.
const HEX: &[u8] = b"0123456789abcdef";

/// One byte of `src` per byte of output, folded into `alphabet`.
///
/// Never emits nothing: an empty run becomes a single `a`, because a caller
/// that wanted a *valid* name would otherwise get `BadName` for a reason
/// that has nothing to do with what the fuzzer chose. Arms that want the
/// empty case reach it through raw values in arm C or the tables in arm D.
fn push_alphabet(out: &mut Vec<u8>, src: &[u8], alphabet: &[u8]) {
    // Bounded by the caller's `take`, which is bounded by its own `max`.
    for byte in src {
        out.push(alphabet[usize::from(*byte) % alphabet.len()]);
    }
    if src.is_empty() {
        out.push(alphabet[0]);
    }
}

/// `value` in decimal, shortest form.
fn push_decimal(out: &mut Vec<u8>, mut value: u64) {
    // Twenty is every digit a `u64` can have, so the loop cannot run longer.
    let mut digits = [0u8; 20];
    let mut count = 0usize;
    loop {
        digits[count] = b'0' + u8::try_from(value % 10).unwrap_or(0);
        count += 1;
        value /= 10;
        if value == 0 || count == digits.len() {
            break;
        }
    }
    for index in (0..count).rev() {
        out.push(digits[index]);
    }
}

/// Exactly 64 lowercase hex digits over 32 bytes of `src`, zero-padded.
///
/// This is the wall inside the wall: `hex_digest` wants 64 bytes drawn from
/// a 16-symbol alphabet, so a mutator reaches a valid digest with probability
/// near zero, and no `file` line — and therefore no accepted manifest — is
/// reachable without one. The digest's *value* is still entirely the
/// fuzzer's, which is the part the parser decodes.
fn push_hex(out: &mut Vec<u8>, src: &[u8]) {
    for index in 0..32 {
        let byte = src.get(index).copied().unwrap_or(0);
        out.push(HEX[usize::from(byte >> 4)]);
        out.push(HEX[usize::from(byte & 0x0f)]);
    }
}

/// A `sha256=` field: honest three times in four, near-miss otherwise.
///
/// The near-misses are the ones a real broken manifest has — a digest that
/// lost a character, gained one, came from a tool that emitted uppercase, or
/// is simply absent — and each is a distinct path through `keyed` and
/// `hex_digest`. Weighted toward valid so acceptance stays reachable.
fn push_digest(out: &mut Vec<u8>, src: &[u8], variant: u8) {
    let start = out.len();
    push_hex(out, src);
    // Three in four are honest. The weighting is what keeps *acceptance*
    // reachable: a manifest is accepted only if every one of its file lines
    // is, so an even split across five variants would make a four-file
    // manifest parse about once in three hundred tries.
    if !variant.is_multiple_of(4) {
        return;
    }
    match (variant / 4) % 4 {
        // Sixty-three: the off-by-one that a length check must catch.
        0 => {
            out.pop();
        }
        // Sixty-five.
        1 => out.push(HEX[usize::from(src.first().copied().unwrap_or(0)) % 16]),
        // An uppercase digit, which is not this grammar's hex.
        2 => {
            if let Some(slot) = out.get_mut(start) {
                *slot = b'A';
            }
        }
        // Nothing at all: `sha256=` with an empty value.
        _ => out.truncate(start),
    }
}

/// A `length=` field, including the two ways a decimal reader gets it wrong.
fn push_length(out: &mut Vec<u8>, variant: u8, value: u64) {
    // Weighted like `push_digest`, and for the same reason.
    if !variant.is_multiple_of(4) {
        push_decimal(out, value);
        return;
    }
    match (variant / 4) % 4 {
        0 => out.push(b'0'),
        // Twenty digits beginning with nine: always above `u64::MAX`, so this
        // is the arm that reaches `checked_mul`'s `None` rather than the
        // length check in front of it.
        1 => {
            out.push(b'9');
            let mut rest = value;
            for _ in 0..19 {
                out.push(b'0' + u8::try_from(rest % 10).unwrap_or(0));
                rest /= 10;
            }
        }
        2 => {
            push_decimal(out, value);
            out.push(b'x');
        }
        _ => {}
    }
}

/// One capability line the vocabulary contains, with the fuzzer's service
/// name and page count inside it.
///
/// `pages` is made non-zero by the caller: `pages=0` is a refusal, and this
/// helper is used by the arm that must produce a manifest which parses.
fn push_valid_cap(out: &mut Vec<u8>, choice: u8, service: &[u8], pages: u64) {
    out.extend_from_slice(b"cap ");
    match choice % 13 {
        0 => out.extend_from_slice(b"console"),
        1 => out.extend_from_slice(b"notification"),
        2 => out.extend_from_slice(b"timer"),
        3 => out.extend_from_slice(b"device-registers"),
        4 => out.extend_from_slice(b"dma-window"),
        5 => out.extend_from_slice(b"interrupt"),
        6 => out.extend_from_slice(b"domain-control"),
        7 => out.extend_from_slice(b"directory"),
        8 => out.extend_from_slice(b"directory writable"),
        9 => out.extend_from_slice(b"memory"),
        10 => {
            out.extend_from_slice(b"memory pages=");
            push_decimal(out, pages);
        }
        11 => {
            out.extend_from_slice(b"endpoint ");
            push_alphabet(out, service, NAME);
        }
        _ => {
            out.extend_from_slice(b"serve ");
            push_alphabet(out, service, NAME);
        }
    }
    out.push(b'\n');
}

// ---------------------------------------------------------------------------
// What a consumer does with a manifest, and what it is entitled to assume
// ---------------------------------------------------------------------------

/// Parses `bytes` and, if it was accepted, reads everything a consumer reads
/// and holds the result to the grammar's stated promises.
///
/// Returns whether the manifest was accepted, which is what arm E asserts on.
fn exercise(bytes: &[u8]) -> bool {
    let Ok(parsed) = manifest::parse(bytes) else {
        return false;
    };

    let _ = parsed.name;
    let _ = parsed.version;

    // The name and version alphabets. A consumer prints these, uses them as
    // directory components and compares them; the grammar promises lowercase
    // ASCII within a stated length, and an acceptance that broke that promise
    // would be a hole in a place nobody re-checks.
    assert!(!parsed.name.is_empty() && parsed.name.len() <= MAX_NAME);
    assert!(
        parsed
            .name
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
    );
    assert!(parsed.version.split(|byte| *byte == b'.').count() == 3);
    assert!(
        parsed
            .version
            .iter()
            .all(|byte| byte.is_ascii_digit() || *byte == b'.')
    );

    for program in parsed.programs() {
        let _ = program.path;
        let _ = program.entry_declared;
        for cap in program.caps() {
            let _ = cap;
            match cap {
                // `pages=0` is a refusal, so an accepted manifest never
                // hands a granter a zero-sized memory request.
                Cap::Memory { pages: Some(pages) } => assert!(pages > 0),
                // A badge is minted for a *named* service.
                Cap::Endpoint(service) | Cap::Serve(service) => assert!(!service.is_empty()),
                _ => {}
            }
        }
        // The stated capacity, which is a refusal and not growth.
        assert!(program.caps().count() <= MAX_CAPS);

        // A path that was accepted cannot climb, cannot be absolute, and
        // fits ustar's name field — the property the archive walk relies on
        // when it matches a member's name against this.
        assert!(!program.path.is_empty() && program.path.len() <= MAX_PATH);
        assert!(program.path[0] != b'/');
        assert!(
            program
                .path
                .split(|byte| *byte == b'/')
                .all(|segment| !segment.is_empty() && segment != b"." && segment != b"..")
        );

        // The cross-check `parse` promises: an accepted program always
        // has its file line.
        assert!(parsed.file(program.path).is_some());
    }

    for file in parsed.files() {
        let _ = file.sha256;
        let _ = file.length;
        assert!(!file.path.is_empty() && file.path.len() <= MAX_PATH);
    }

    assert!(parsed.files().count() <= MAX_FILES);

    // No payload is named twice: an installer that copied a duplicate would
    // be copying one of two different files and could not say which.
    // Quadratic over at most `MAX_FILES` entries, so at most 64 x 64.
    for (index, file) in parsed.files().enumerate() {
        for (other_index, other) in parsed.files().enumerate() {
            if index != other_index {
                assert!(file.path != other.path);
            }
        }
    }

    true
}

// ---------------------------------------------------------------------------
// Arm A — raw bytes
// ---------------------------------------------------------------------------

/// Whatever the fuzzer sent, read as a manifest.
fn arm_a(data: &[u8]) {
    exercise(data);
}

// ---------------------------------------------------------------------------
// Arm B — the grammar's shape, the fuzzer's values, rendered
// ---------------------------------------------------------------------------

/// A manifest whose keywords are this file's and whose every value is the
/// fuzzer's, folded into the alphabets the grammar accepts.
fn arm_b(data: &[u8]) {
    // Ten sections: two past `MAX_PROGRAMS`, so the capacity refusal is
    // reachable, and bounded so the fuzzer cannot ask for a million.
    const MAX_SECTIONS: usize = 10;
    // Twenty caps: four past `MAX_CAPS`, same reason.
    const MAX_CAP_LINES: usize = 20;

    let mut input = Bytes::new(data);
    let mut text = Vec::with_capacity(1024);

    text.extend_from_slice(b"# a manifest whose values the fuzzer chose\n");

    text.extend_from_slice(b"package ");
    push_alphabet(&mut text, input.take(72), NAME);
    text.push(b'\n');

    text.extend_from_slice(b"version ");
    push_decimal(&mut text, input.word() % 1_000_000);
    text.push(b'.');
    push_decimal(&mut text, input.word() % 1_000_000);
    text.push(b'.');
    push_decimal(&mut text, input.word() % 1_000_000);
    text.push(b'\n');

    // The shape byte, and it exists to keep the *common* manifest small. A
    // rendered path is valid only if it has no empty segment, no `.` or `..`
    // segment and no leading `/`, and the path alphabet carries `/` and `.`
    // on purpose — so a long path is nearly always refused and a manifest of
    // ten long paths is refused every time. One input in eight gets the big
    // shape, which is what reaches `MAX_PROGRAMS` and `MAX_PATH`; the rest
    // stay small enough that acceptance is ordinary rather than lucky.
    let shape = input.byte();
    let sections = if shape.is_multiple_of(8) {
        usize::from(input.byte()) % MAX_SECTIONS + 1
    } else {
        usize::from(input.byte()) % 3 + 1
    };
    let path_bytes = if shape.is_multiple_of(4) { 110 } else { 24 };
    let mut paths: Vec<Vec<u8>> = Vec::with_capacity(sections);

    for _ in 0..sections {
        let mut path = Vec::with_capacity(64);
        push_alphabet(&mut path, input.take(path_bytes), PATH);

        text.extend_from_slice(b"\nprogram ");
        text.extend_from_slice(&path);
        text.push(b'\n');

        // The entry line, including both ways it is wrong: absent, and
        // declared twice.
        match input.byte() % 4 {
            0 | 1 => text.extend_from_slice(b"entry hertz\n"),
            2 => {}
            _ => text.extend_from_slice(b"entry hertz\nentry hertz\n"),
        }

        let caps = usize::from(input.byte()) % MAX_CAP_LINES;
        for _ in 0..caps {
            let choice = input.byte();
            let service = input.take(24);
            let pages = input.word() % 4096 + 1;
            if choice % 16 < 13 {
                push_valid_cap(&mut text, choice, service, pages);
            } else {
                // Off the vocabulary on purpose: a plausible word the table
                // does not contain, which is `BadCap`'s own path.
                text.extend_from_slice(b"cap ");
                push_alphabet(&mut text, service, NAME);
                text.push(b'\n');
            }
        }

        paths.push(path);
    }

    text.push(b'\n');
    for path in &paths {
        // Whether this program gets its bytes. Skipping is how
        // `ProgramWithoutFile` — the promise arm A asserts on — is reached.
        if input.byte().is_multiple_of(8) {
            continue;
        }
        text.extend_from_slice(b"file ");
        text.extend_from_slice(path);
        text.extend_from_slice(b" sha256=");
        let digest = input.take(32);
        let variant = input.byte();
        push_digest(&mut text, digest, variant);
        text.extend_from_slice(b" length=");
        let length_variant = input.byte();
        let length = input.word();
        push_length(&mut text, length_variant, length);
        text.push(b'\n');
    }

    // Data files: `file` lines no program claims, which the grammar allows
    // and which a package carrying configuration really has. Three at most.
    let data_files = usize::from(input.byte()) % 4;
    for _ in 0..data_files {
        text.extend_from_slice(b"file ");
        push_alphabet(&mut text, input.take(path_bytes), PATH);
        text.extend_from_slice(b" sha256=");
        let digest = input.take(32);
        let variant = input.byte();
        push_digest(&mut text, digest, variant);
        text.extend_from_slice(b" length=");
        let length_variant = input.byte();
        let length = input.word();
        push_length(&mut text, length_variant, length);
        text.push(b'\n');
    }

    exercise(&text);
}

// ---------------------------------------------------------------------------
// Arm C — the grammar's shape, raw values
// ---------------------------------------------------------------------------

/// The same skeleton with the fuzzer's bytes dropped in unrendered.
///
/// Every value here can carry a space, a newline, a NUL or a run longer than
/// `MAX_LINE`, so this is the arm that reaches the refusals arm B renders its
/// way around.
fn arm_c(data: &[u8]) {
    // Three sections is enough to reach a duplicate path and a second
    // section's `cap` handling; the capacity refusals are arm B's and E's.
    const MAX_SECTIONS: usize = 3;
    // A little past `MAX_LINE`, so `LineTooLong` is reachable from a single
    // value without letting one value dominate the whole input.
    const MAX_VALUE: usize = MAX_LINE + 48;

    let mut input = Bytes::new(data);
    let mut text = Vec::with_capacity(1024);

    text.extend_from_slice(b"package ");
    text.extend_from_slice(input.take(MAX_VALUE));
    text.push(b'\n');

    text.extend_from_slice(b"version ");
    text.extend_from_slice(input.take(40));
    text.push(b'\n');

    let sections = usize::from(input.byte()) % MAX_SECTIONS + 1;
    for _ in 0..sections {
        text.extend_from_slice(b"program ");
        let path = input.take(MAX_VALUE);
        text.extend_from_slice(path);
        text.push(b'\n');

        text.extend_from_slice(b"entry ");
        text.extend_from_slice(input.take(40));
        text.push(b'\n');

        // Four cap lines at most: enough for an ordering, bounded because
        // the fuzzer chooses the count.
        let caps = usize::from(input.byte()) % 4;
        for _ in 0..caps {
            text.extend_from_slice(b"cap ");
            text.extend_from_slice(input.take(120));
            text.push(b'\n');
        }

        text.extend_from_slice(b"file ");
        text.extend_from_slice(path);
        text.extend_from_slice(b" sha256=");
        text.extend_from_slice(input.take(80));
        text.extend_from_slice(b" length=");
        text.extend_from_slice(input.take(24));
        text.push(b'\n');
    }

    exercise(&text);
}

// ---------------------------------------------------------------------------
// Arm D — keywords from a table
// ---------------------------------------------------------------------------

/// A 64-hex digest, so arm D's table can carry a whole well-formed `file`
/// suffix: the SHA-256 of the empty string, which is what an empty payload
/// really has.
const EMPTY_DIGEST: &[u8] = b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// Directives, real and nearly-real. The near ones matter: `Package` and
/// `FILE` are what a case-insensitive habit produces, and the grammar's
/// answer must be a refusal with a line number rather than a shrug.
const DIRECTIVES: [&[u8]; 12] = [
    b"package",
    b"version",
    b"program",
    b"entry",
    b"cap",
    b"file",
    b"#",
    b"",
    b"provides",
    b"Package",
    b"depends",
    b"FILE",
];

/// Arguments that are plausible for *some* directive and therefore wrong for
/// most of them.
const ARGUMENTS: [&[u8]; 14] = [
    b"hello",
    b"0.1.0",
    b"bin/hello",
    b"hertz",
    b"console",
    b"memory pages=2",
    b"memory pages=0",
    b"endpoint net",
    b"serve fs",
    b"directory writable",
    b"..",
    b"/etc/shadow",
    b"",
    b"a b c",
];

/// Lines whose directive the fuzzer picked from a table.
///
/// Arm B can only build a manifest that is shaped right. This one builds
/// manifests that are shaped wrong in every order: `cap` before `program`,
/// `package` twice, `entry` on its own, a `program` whose `file` never comes.
fn arm_d(data: &[u8]) {
    // Twenty-four lines: past `MAX_PROGRAMS` so the capacity refusal is
    // reachable here too, and short enough that the fuzzer's bytes still
    // steer most of them rather than running out and repeating.
    const MAX_LINES: usize = 24;

    let mut input = Bytes::new(data);
    let mut text = Vec::with_capacity(1024);

    let lines = usize::from(input.byte()) % MAX_LINES + 1;
    for _ in 0..lines {
        let directive = DIRECTIVES[usize::from(input.byte()) % DIRECTIVES.len()];
        text.extend_from_slice(directive);
        if !directive.is_empty() {
            text.push(b' ');
        }
        match input.byte() % 4 {
            0 => text.extend_from_slice(ARGUMENTS[usize::from(input.byte()) % ARGUMENTS.len()]),
            1 => push_alphabet(&mut text, input.take(60), PATH),
            2 => {
                // A whole well-formed `file` suffix, so `file` lines in this
                // arm are not all refused at the digest.
                push_alphabet(&mut text, input.take(40), PATH);
                text.extend_from_slice(b" sha256=");
                text.extend_from_slice(EMPTY_DIGEST);
                text.extend_from_slice(b" length=");
                push_decimal(&mut text, input.word());
            }
            _ => text.extend_from_slice(input.take(200)),
        }
        text.push(b'\n');
    }

    exercise(&text);
}

// ---------------------------------------------------------------------------
// Arm E — a valid manifest with exactly one deliberate defect
// ---------------------------------------------------------------------------

/// How many defects arm E knows, defect 0 being "none".
const DEFECTS: usize = 16;

/// A manifest built to be valid, then broken in one named way.
///
/// This is the only arm that asserts on the *verdict* rather than on an
/// accepted manifest's contents, and it asserts in both directions: defect 0
/// must be accepted, and each of the other fifteen must be refused. A parser
/// that quietly stopped refusing one of them would pass every other arm in
/// this file, because accepting bad input is not a crash.
fn arm_e(data: &[u8]) {
    let mut input = Bytes::new(data);
    let defect = usize::from(input.byte()) % DEFECTS;

    // Every value below is rendered into an alphabet the grammar accepts and
    // bounded well inside the stated limits, so the base manifest parses.
    // The lengths: a name of at most 24 (`MAX_NAME` is 64), a path of at most
    // `bin/` plus 24 plus a section digit (`MAX_PATH` is 100), a version of
    // three runs of at most six digits, and a `length=` of at most twenty —
    // the longest line is the `file` line at roughly 130 bytes, half of
    // `MAX_LINE`.
    let mut name = Vec::with_capacity(24);
    push_alphabet(&mut name, input.take(24), NAME);
    let major = input.word() % 1_000_000;
    let minor = input.word() % 1_000_000;
    let patch = input.word() % 1_000_000;
    // One to three sections, so the section index stays a single digit and
    // the paths below cannot collide.
    let sections = usize::from(input.byte()) % 3 + 1;
    let caps = usize::from(input.byte()) % 4;
    let cap_choice = input.byte();
    let service = input.take(24);
    let pages = input.word() % 4096 + 1;
    let digest = input.take(32);
    let length = input.word();
    let unknown = input.take(24);

    // `bin/<digit><rendered>`: distinct across sections because the digit is,
    // and valid because every byte is from the path alphabet, no segment is
    // empty and neither segment is `.` or `..` (the name alphabet has no dot).
    let path_of = |section: usize, suffix: &[u8]| -> Vec<u8> {
        let mut path = Vec::with_capacity(32);
        path.extend_from_slice(b"bin/");
        push_decimal(&mut path, section as u64);
        push_alphabet(&mut path, suffix, NAME);
        path
    };

    let push_file = |out: &mut Vec<u8>, path: &[u8]| {
        out.extend_from_slice(b"file ");
        out.extend_from_slice(path);
        out.extend_from_slice(b" sha256=");
        let start = out.len();
        push_hex(out, digest);
        match defect {
            // Sixty-three hex digits, which is the wrong number.
            3 => {
                out.pop();
            }
            // An uppercase hex digit, which this grammar does not accept —
            // set rather than folded, so it is uppercase whatever the digest
            // was. (`to_ascii_uppercase` on a digit changes nothing, and a
            // digest of nothing but digits is reachable.)
            4 => out[start] = b'A',
            _ => {}
        }
        out.extend_from_slice(b" length=");
        if defect == 5 {
            // Twenty digits starting at nine: always past `u64::MAX`.
            out.push(b'9');
            let mut rest = length;
            for _ in 0..19 {
                out.push(b'0' + u8::try_from(rest % 10).unwrap_or(0));
                rest /= 10;
            }
        } else {
            push_decimal(out, length);
        }
        out.push(b'\n');
    };

    let mut text = Vec::with_capacity(1024);
    text.extend_from_slice(b"# a manifest this target built to be valid\n");

    // Defect 13: `version` before `package`, which is the one ordering rule
    // the grammar has.
    if defect == 13 {
        text.extend_from_slice(b"version 1.0.0\n");
    }

    text.extend_from_slice(b"package ");
    text.extend_from_slice(&name);
    text.push(b'\n');

    text.extend_from_slice(b"version ");
    push_decimal(&mut text, major);
    text.push(b'.');
    push_decimal(&mut text, minor);
    text.push(b'.');
    push_decimal(&mut text, patch);
    text.push(b'\n');

    // Defect 14: a second `version`.
    if defect == 14 {
        text.extend_from_slice(b"version 2.0.0\n");
    }
    // Defect 15: `entry` with no section open.
    if defect == 15 {
        text.extend_from_slice(b"entry hertz\n");
    }
    // Defect 12: a NUL, which is not text.
    if defect == 12 {
        text.push(0);
        text.push(b'\n');
    }
    // Defect 11: one byte past `MAX_LINE`. A comment, because the length
    // check runs before the `#` test and this must be about the length and
    // nothing else.
    if defect == 11 {
        text.push(b'#');
        text.extend(core::iter::repeat_n(b'a', MAX_LINE));
        text.push(b'\n');
    }

    // Defect 7: one section past `MAX_PROGRAMS`. Nine sections at most, so
    // the loop is still bounded by a constant.
    let sections = if defect == 7 { 9 } else { sections };

    let mut paths: Vec<Vec<u8>> = Vec::with_capacity(sections);
    for section in 0..sections {
        let path = path_of(section, unknown);

        text.extend_from_slice(b"\nprogram ");
        text.extend_from_slice(&path);
        text.push(b'\n');
        // Defect 10: the same `program` path twice.
        if defect == 10 {
            text.extend_from_slice(b"program ");
            text.extend_from_slice(&path);
            text.push(b'\n');
        }
        text.extend_from_slice(b"entry hertz\n");

        // Defect 8: one cap past `MAX_CAPS`, in the first section.
        let caps = if defect == 8 && section == 0 {
            MAX_CAPS + 1
        } else {
            caps
        };
        for _ in 0..caps {
            if defect == 8 {
                text.extend_from_slice(b"cap console\n");
            } else {
                push_valid_cap(&mut text, cap_choice, service, pages);
            }
        }

        // Defect 6: a capability the vocabulary does not contain. The `-x`
        // suffix is what makes it certain: no word in the table ends in it,
        // and the rest is name-alphabet bytes, so the line is well-formed
        // and still unknown.
        if defect == 6 {
            text.extend_from_slice(b"cap ");
            push_alphabet(&mut text, unknown, NAME);
            text.extend_from_slice(b"-x\n");
        }

        paths.push(path);
    }

    text.push(b'\n');
    for (section, path) in paths.iter().enumerate() {
        // Defect 2: the first program's bytes are never named.
        if defect == 2 && section == 0 {
            continue;
        }
        push_file(&mut text, path);
    }

    // Defect 9: one `file` line past `MAX_FILES`, with paths that are
    // distinct from each other and from the sections' (`d/` against `bin/`).
    if defect == 9 {
        for index in 0..=MAX_FILES {
            let mut path = Vec::with_capacity(16);
            path.extend_from_slice(b"d/");
            push_decimal(&mut path, index as u64);
            push_file(&mut text, &path);
        }
    }

    // Defect 1: a second `package` line.
    if defect == 1 {
        text.extend_from_slice(b"package again\n");
    }

    let accepted = exercise(&text);

    if defect == 0 {
        // The base is valid by construction, so a refusal here is either a
        // parser that stopped accepting something it documents, or this
        // target's model of the grammar drifting from the grammar. Both are
        // worth a crash.
        let parsed = manifest::parse(&text).expect("the base manifest is valid by construction");
        assert!(accepted);
        assert_eq!(parsed.name, &name[..]);
        assert_eq!(parsed.programs().count(), sections);
        assert_eq!(parsed.files().count(), sections);
        for (section, path) in paths.iter().enumerate() {
            let program = parsed.programs().nth(section).expect("section present");
            assert_eq!(program.path, &path[..]);
            assert!(program.entry_declared);
            assert_eq!(program.caps().count(), caps);
            let file = parsed.file(&path[..]).expect("the section's file line");
            assert_eq!(file.length, length);
        }
    } else {
        // Every other defect is decisive: each one breaks a rule the parser
        // states, so acceptance would mean the rule is gone.
        assert!(!accepted, "defect {defect} was accepted");
    }
}
