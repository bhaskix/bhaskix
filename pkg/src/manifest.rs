// SPDX-License-Identifier: Apache-2.0
//! The manifest: a package's authority, one line at a time.
//!
//! [RFC 0030](../../docs/rfc/0030-packages.md)'s grammar — line-oriented
//! `key value` text with sections, not a config language, so that a diff of
//! authority is a diff of lines and every tool that greps can read it. The
//! parser is zero-copy and allocation-free: every name it returns is a slice
//! of the input, every collection is a fixed array with a stated capacity,
//! and the capacities are refusals with numbers rather than growth.
//!
//! # Every byte here is hostile
//!
//! A manifest arrives inside an archive an operator was handed. Nothing in
//! it is trusted: not the lengths, not the hex, not the claim that a line is
//! short. A malformed manifest is refused with the line number that broke
//! it, whole — there is no "parse what we could", because a package half
//! understood is authority half reviewed.
//!
//! # The grammar
//!
//! ```text
//! # comment, blank lines ignored
//! package <name>              # exactly once, first directive
//! version <a.b.c>             # exactly once
//! program <path>              # opens a program section
//! entry hertz                 #   its entry convention (the only one)
//! cap console                 #   a capability request, one per line
//! cap notification
//! cap timer
//! cap memory pages=<n>        #   pages= omitted: the granter sizes it
//! cap endpoint <service>      #   the calling side of an endpoint
//! cap serve <service>         #   the answering side, a different power
//! cap device-registers
//! cap dma-window
//! cap interrupt
//! cap domain-control
//! cap directory              #   read; add 'writable' for the write side
//! cap directory writable
//! file <path> sha256=<64 hex> length=<n>
//! ```
//!
//! Names are lowercase ASCII, digits and `-`; paths add `/`, `.` and `_`,
//! refuse `..`, a leading `/` and empty segments, and fit ustar's 100-byte
//! name field because the payload travels in that format. Every `program`
//! path must be named by a `file` line; `file` lines without a program are
//! data, which is allowed — a package may carry configuration.

/// The most programs one package may declare.
pub const MAX_PROGRAMS: usize = 8;
/// The most capability requests one program may make. A program asking for
/// more than sixteen distinct authorities is not a package, it is a system.
pub const MAX_CAPS: usize = 16;
/// The most `file` lines one manifest may carry.
pub const MAX_FILES: usize = 64;
/// The longest line the grammar accepts, in bytes.
pub const MAX_LINE: usize = 256;
/// The longest name (`package`, `endpoint`) the grammar accepts.
pub const MAX_NAME: usize = 64;
/// The longest path, which is ustar's name field width.
pub const MAX_PATH: usize = 100;

/// One capability request, as the manifest states it.
///
/// The vocabulary is the ABI's object kinds, not an open set: a request the
/// grammar does not know is a parse error, because "unknown authority,
/// granted anyway" is the failure this file exists to make impossible.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Cap<'a> {
    /// Put a character, take a byte.
    Console,
    /// A badged endpoint to the named service — the *calling* side.
    Endpoint(&'a [u8]),
    /// The endpoint a service answers on — the *serving* side. Stated
    /// separately from [`Cap::Endpoint`] because answering and asking are
    /// different powers, and a manifest that conflated them would review
    /// as less than it grants.
    Serve(&'a [u8]),
    /// Memory, mappable. `pages` absent means the granter sizes the object
    /// — the supervisor's child-image is the case that forced the option:
    /// its memory is sized to the program it stages, and a fixed number
    /// here would be a lie every time the program changed.
    Memory {
        /// How many pages, if the manifest fixes it.
        pages: Option<u64>,
    },
    /// A notification to wait on and be signalled through.
    Notification,
    /// A notification with the deadline methods — RFC 0019's shape.
    Timer,
    /// A device's register windows — the driver authority.
    DeviceRegisters,
    /// The authority to bound what a device may reach (RFC 0012).
    DmaWindow,
    /// A device interrupt: wait for it, acknowledge it, nothing about
    /// programming it.
    Interrupt,
    /// The authority to create and start a child domain (RFC 0017).
    DomainControl,
    /// One directory of the filesystem, and what is inside it — no path
    /// upward. `writable` marks the handle that can change what it names;
    /// writability then inherits downward through opens, never upward.
    Directory {
        /// Whether the handle carries the write authority (RFC 0030 step 3:
        /// the badge's top bit, minted by the kernel, never by a caller).
        writable: bool,
    },
}

/// One program section: the binary, its entry convention, its requests.
#[derive(Clone, Copy)]
pub struct Program<'a> {
    /// The payload path of the binary.
    pub path: &'a [u8],
    /// The capability requests, in manifest order.
    caps: [Option<Cap<'a>>; MAX_CAPS],
    /// How many of `caps` are real.
    cap_count: usize,
    /// Whether the section carried its `entry hertz` line.
    pub entry_declared: bool,
}

impl<'a> Program<'a> {
    /// The requests, in manifest order.
    pub fn caps(&self) -> impl Iterator<Item = Cap<'a>> + '_ {
        self.caps.iter().take(self.cap_count).filter_map(|cap| *cap)
    }
}

/// One `file` line: a payload's path, digest and length.
#[derive(Clone, Copy)]
pub struct FileEntry<'a> {
    /// The payload path.
    pub path: &'a [u8],
    /// Its SHA-256, decoded from the hex.
    pub sha256: [u8; 32],
    /// Its length in bytes.
    pub length: u64,
}

/// A parsed manifest. Every slice borrows the input.
pub struct Manifest<'a> {
    /// The package's name.
    pub name: &'a [u8],
    /// The package's version, kept as written — ordering versions is
    /// refused work until upgrades exist (RFC 0030's table).
    pub version: &'a [u8],
    programs: [Option<Program<'a>>; MAX_PROGRAMS],
    program_count: usize,
    files: [Option<FileEntry<'a>>; MAX_FILES],
    file_count: usize,
}

impl<'a> Manifest<'a> {
    /// The program sections, in manifest order.
    pub fn programs(&self) -> impl Iterator<Item = &Program<'a>> {
        self.programs
            .iter()
            .take(self.program_count)
            .filter_map(|program| program.as_ref())
    }

    /// The `file` lines, in manifest order.
    pub fn files(&self) -> impl Iterator<Item = &FileEntry<'a>> {
        self.files
            .iter()
            .take(self.file_count)
            .filter_map(|file| file.as_ref())
    }

    /// The `file` line for `path`, if the manifest has one.
    #[must_use]
    pub fn file(&self, path: &[u8]) -> Option<&FileEntry<'a>> {
        self.files().find(|file| file.path == path)
    }
}

/// Why a manifest was refused. Every variant carries the 1-based line.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ManifestError {
    /// A line longer than [`MAX_LINE`].
    LineTooLong(usize),
    /// A directive the grammar does not know.
    UnknownDirective(usize),
    /// The first directive was not `package`, or `package` appeared twice.
    PackageMisplaced(usize),
    /// `version` missing, doubled, or malformed.
    BadVersion(usize),
    /// A name with a byte outside its alphabet, empty, or too long.
    BadName(usize),
    /// A path that is empty, too long, absolute, or contains `..` or an
    /// empty segment.
    BadPath(usize),
    /// An `entry` value other than `hertz`, or a second `entry` line.
    BadEntry(usize),
    /// A `cap` line outside a `program` section, or one the vocabulary
    /// does not contain, or a malformed parameter.
    BadCap(usize),
    /// A `file` line whose hex or length does not parse.
    BadFile(usize),
    /// Two `program` or two `file` lines naming one path.
    DuplicatePath(usize),
    /// More sections or lines than the stated capacities allow.
    TooMany(usize),
    /// The manifest ended without a `package` or `version` line.
    Incomplete,
    /// A `program` path with no `file` line to carry its bytes.
    ProgramWithoutFile,
    /// Not text: a NUL or other control byte where the grammar wants ASCII.
    NotText(usize),
}

/// Whether `byte` may appear in a name.
const fn name_byte(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
}

/// Whether `bytes` is a well-formed name.
fn valid_name(bytes: &[u8]) -> bool {
    !bytes.is_empty() && bytes.len() <= MAX_NAME && bytes.iter().all(|byte| name_byte(*byte))
}

/// Whether `bytes` is a well-formed relative path: named alphabet plus
/// `/ . _`, no leading `/`, no empty segment, no `.` or `..` segment.
/// `pub(crate)` because the package walk holds archive member names to the
/// same rule — one definition of "a path that cannot escape".
pub(crate) fn valid_path(bytes: &[u8]) -> bool {
    if bytes.is_empty() || bytes.len() > MAX_PATH {
        return false;
    }
    if !bytes
        .iter()
        .all(|byte| name_byte(*byte) || matches!(*byte, b'/' | b'.' | b'_'))
    {
        return false;
    }
    bytes
        .split(|byte| *byte == b'/')
        .all(|segment| !segment.is_empty() && segment != b"." && segment != b"..")
}

/// Splits `line` at its first run of spaces: `(word, rest)`, both trimmed.
fn word(line: &[u8]) -> (&[u8], &[u8]) {
    let line = trim(line);
    match line.iter().position(|byte| *byte == b' ') {
        Some(space) => (&line[..space], trim(&line[space..])),
        None => (line, &[]),
    }
}

/// `bytes` without leading and trailing spaces.
fn trim(bytes: &[u8]) -> &[u8] {
    let start = bytes.iter().position(|byte| *byte != b' ');
    let end = bytes.iter().rposition(|byte| *byte != b' ');
    match (start, end) {
        (Some(start), Some(end)) => &bytes[start..=end],
        _ => &[],
    }
}

/// Parses `key=value`, returning the value if the key matches.
fn keyed<'a>(bytes: &'a [u8], key: &[u8]) -> Option<&'a [u8]> {
    let equals = bytes.iter().position(|byte| *byte == b'=')?;
    if &bytes[..equals] == key {
        Some(&bytes[equals + 1..])
    } else {
        None
    }
}

/// Parses a decimal `u64`, refusing empty, non-digits and overflow.
fn decimal(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty() || bytes.len() > 20 {
        return None;
    }
    let mut value: u64 = 0;
    for byte in bytes {
        if !byte.is_ascii_digit() {
            return None;
        }
        value = value.checked_mul(10)?.checked_add(u64::from(byte - b'0'))?;
    }
    Some(value)
}

/// Parses exactly 64 lowercase hex digits into a digest.
fn hex_digest(bytes: &[u8]) -> Option<[u8; 32]> {
    if bytes.len() != 64 {
        return None;
    }
    let mut digest = [0u8; 32];
    for (slot, pair) in digest.iter_mut().zip(bytes.chunks_exact(2)) {
        let nibble = |byte: u8| match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            _ => None,
        };
        *slot = nibble(pair[0])? << 4 | nibble(pair[1])?;
    }
    Some(digest)
}

/// Whether `a.b.c`: three runs of digits joined by dots.
fn valid_version(bytes: &[u8]) -> bool {
    let mut parts = 0;
    for part in bytes.split(|byte| *byte == b'.') {
        if part.is_empty() || part.len() > 6 || !part.iter().all(u8::is_ascii_digit) {
            return false;
        }
        parts += 1;
    }
    parts == 3
}

/// Parses `bytes` as a manifest, whole or not at all.
///
/// # Errors
///
/// [`ManifestError`], carrying the 1-based line that was refused.
pub fn parse(bytes: &[u8]) -> Result<Manifest<'_>, ManifestError> {
    let mut manifest = Manifest {
        name: &[],
        version: &[],
        programs: [None; MAX_PROGRAMS],
        program_count: 0,
        files: [None; MAX_FILES],
        file_count: 0,
    };
    let mut saw_package = false;
    let mut saw_version = false;

    for (index, line) in bytes.split(|byte| *byte == b'\n').enumerate() {
        let number = index + 1;
        if line.len() > MAX_LINE {
            return Err(ManifestError::LineTooLong(number));
        }
        if line
            .iter()
            .any(|byte| *byte != b'\t' && (*byte < 0x20 || *byte == 0x7f))
        {
            return Err(ManifestError::NotText(number));
        }
        let line = trim(line);
        if line.is_empty() || line[0] == b'#' {
            continue;
        }
        let (directive, rest) = word(line);

        match directive {
            b"package" => {
                if saw_package {
                    return Err(ManifestError::PackageMisplaced(number));
                }
                if !valid_name(rest) {
                    return Err(ManifestError::BadName(number));
                }
                saw_package = true;
                manifest.name = rest;
            }
            _ if !saw_package => return Err(ManifestError::PackageMisplaced(number)),
            b"version" => {
                if saw_version || !valid_version(rest) {
                    return Err(ManifestError::BadVersion(number));
                }
                saw_version = true;
                manifest.version = rest;
            }
            b"program" => {
                if !valid_path(rest) {
                    return Err(ManifestError::BadPath(number));
                }
                if manifest.programs().any(|program| program.path == rest) {
                    return Err(ManifestError::DuplicatePath(number));
                }
                if manifest.program_count == MAX_PROGRAMS {
                    return Err(ManifestError::TooMany(number));
                }
                manifest.programs[manifest.program_count] = Some(Program {
                    path: rest,
                    caps: [None; MAX_CAPS],
                    cap_count: 0,
                    entry_declared: false,
                });
                manifest.program_count += 1;
            }
            b"entry" => {
                let Some(program) = manifest
                    .program_count
                    .checked_sub(1)
                    .and_then(|last| manifest.programs[last].as_mut())
                else {
                    return Err(ManifestError::BadEntry(number));
                };
                if program.entry_declared || rest != b"hertz" {
                    return Err(ManifestError::BadEntry(number));
                }
                program.entry_declared = true;
            }
            b"cap" => {
                let Some(program) = manifest
                    .program_count
                    .checked_sub(1)
                    .and_then(|last| manifest.programs[last].as_mut())
                else {
                    return Err(ManifestError::BadCap(number));
                };
                if program.cap_count == MAX_CAPS {
                    return Err(ManifestError::TooMany(number));
                }
                let (kind, argument) = word(rest);
                let cap = match (kind, argument) {
                    (b"console", b"") => Cap::Console,
                    (b"notification", b"") => Cap::Notification,
                    (b"timer", b"") => Cap::Timer,
                    (b"device-registers", b"") => Cap::DeviceRegisters,
                    (b"dma-window", b"") => Cap::DmaWindow,
                    (b"interrupt", b"") => Cap::Interrupt,
                    (b"domain-control", b"") => Cap::DomainControl,
                    (b"directory", b"") => Cap::Directory { writable: false },
                    (b"directory", b"writable") => Cap::Directory { writable: true },
                    (b"memory", b"") => Cap::Memory { pages: None },
                    (b"memory", argument) => {
                        let pages = keyed(argument, b"pages")
                            .and_then(decimal)
                            .filter(|pages| *pages > 0)
                            .ok_or(ManifestError::BadCap(number))?;
                        Cap::Memory { pages: Some(pages) }
                    }
                    (b"endpoint", service) if valid_name(service) => Cap::Endpoint(service),
                    (b"serve", service) if valid_name(service) => Cap::Serve(service),
                    _ => return Err(ManifestError::BadCap(number)),
                };
                program.caps[program.cap_count] = Some(cap);
                program.cap_count += 1;
            }
            b"file" => {
                let (path, rest) = word(rest);
                if !valid_path(path) {
                    return Err(ManifestError::BadPath(number));
                }
                if manifest.file(path).is_some() {
                    return Err(ManifestError::DuplicatePath(number));
                }
                if manifest.file_count == MAX_FILES {
                    return Err(ManifestError::TooMany(number));
                }
                let (first, second) = word(rest);
                let sha256 = keyed(first, b"sha256")
                    .and_then(hex_digest)
                    .ok_or(ManifestError::BadFile(number))?;
                let (second, tail) = word(second);
                let length = keyed(second, b"length")
                    .and_then(decimal)
                    .ok_or(ManifestError::BadFile(number))?;
                if !tail.is_empty() {
                    return Err(ManifestError::BadFile(number));
                }
                manifest.files[manifest.file_count] = Some(FileEntry {
                    path,
                    sha256,
                    length,
                });
                manifest.file_count += 1;
            }
            _ => return Err(ManifestError::UnknownDirective(number)),
        }
    }

    if !saw_package || !saw_version {
        return Err(ManifestError::Incomplete);
    }
    for program in manifest.programs() {
        if manifest.file(program.path).is_none() {
            return Err(ManifestError::ProgramWithoutFile);
        }
    }
    Ok(manifest)
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &[u8] = b"# a demonstration package\n\
        package hello\n\
        version 0.1.0\n\
        \n\
        program bin/hello\n\
        entry hertz\n\
        cap console\n\
        cap memory pages=2\n\
        cap endpoint net\n\
        \n\
        file bin/hello sha256=ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad length=3\n\
        file etc/hello.conf sha256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 length=0\n";

    #[test]
    fn a_well_formed_manifest_parses_whole() {
        let manifest = parse(GOOD).unwrap();
        assert_eq!(manifest.name, b"hello");
        assert_eq!(manifest.version, b"0.1.0");
        let program = manifest.programs().next().unwrap();
        assert_eq!(program.path, b"bin/hello");
        assert!(program.entry_declared);
        let caps: std::vec::Vec<_> = program.caps().collect();
        assert_eq!(
            caps,
            std::vec![
                Cap::Console,
                Cap::Memory { pages: Some(2) },
                Cap::Endpoint(b"net")
            ]
        );
        assert_eq!(manifest.files().count(), 2);
        assert_eq!(manifest.file(b"bin/hello").unwrap().length, 3);
    }

    /// A convenience: `GOOD` with one line's text replaced.
    fn with(from: &str, to: &str) -> std::vec::Vec<u8> {
        let text = core::str::from_utf8(GOOD).unwrap().replace(from, to);
        text.into_bytes()
    }

    #[test]
    fn the_first_directive_must_be_package() {
        assert_eq!(
            parse(b"version 0.1.0\npackage hello\n").err(),
            Some(ManifestError::PackageMisplaced(1))
        );
        assert!(matches!(
            parse(&with("package hello", "package hello\npackage again")),
            Err(ManifestError::PackageMisplaced(_))
        ));
    }

    #[test]
    fn names_and_versions_are_held_to_their_alphabets() {
        for bad in ["package Hello", "package ", "package a b"] {
            assert!(
                matches!(
                    parse(&with("package hello", bad)),
                    Err(ManifestError::BadName(_) | ManifestError::PackageMisplaced(_))
                ),
                "{bad}"
            );
        }
        for bad in [
            "version 1.0",
            "version a.b.c",
            "version 1.0.0.0",
            "version 1..0",
        ] {
            assert!(
                matches!(
                    parse(&with("version 0.1.0", bad)),
                    Err(ManifestError::BadVersion(_))
                ),
                "{bad}"
            );
        }
    }

    #[test]
    fn paths_that_escape_are_refused() {
        for bad in [
            "program /bin/hello",
            "program bin/../hello",
            "program bin//hello",
            "program ./hello",
            "program bin/..",
        ] {
            assert!(
                matches!(
                    parse(&with("program bin/hello", bad)),
                    Err(ManifestError::BadPath(_))
                ),
                "{bad}"
            );
        }
    }

    #[test]
    fn the_whole_vocabulary_parses_and_each_word_is_itself() {
        let manifest = parse(
            b"package all
version 0.1.0

program bin/all
entry hertz
              cap console
cap notification
cap timer
cap memory
              cap memory pages=16
cap endpoint net
cap serve fs
              cap device-registers
cap dma-window
cap interrupt
              cap domain-control
cap directory
              cap directory writable

              file bin/all sha256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 length=0
",
        )
        .unwrap();
        let caps: std::vec::Vec<_> = manifest.programs().next().unwrap().caps().collect();
        assert_eq!(
            caps,
            std::vec![
                Cap::Console,
                Cap::Notification,
                Cap::Timer,
                Cap::Memory { pages: None },
                Cap::Memory { pages: Some(16) },
                Cap::Endpoint(b"net"),
                Cap::Serve(b"fs"),
                Cap::DeviceRegisters,
                Cap::DmaWindow,
                Cap::Interrupt,
                Cap::DomainControl,
                Cap::Directory { writable: false },
                Cap::Directory { writable: true },
            ]
        );
    }

    #[test]
    fn the_cap_vocabulary_is_closed() {
        for bad in [
            "cap root",
            "cap memory pages=0",
            "cap memory pages=x",
            "cap endpoint",
            "cap endpoint Net",
            "cap serve",
            "cap console extra",
            "cap device-registers extra",
            "cap domain-control now",
        ] {
            assert!(
                matches!(
                    parse(&with("cap console", bad)),
                    Err(ManifestError::BadCap(_))
                ),
                "{bad}"
            );
        }
    }

    #[test]
    fn a_cap_or_entry_outside_a_program_is_refused() {
        assert!(matches!(
            parse(b"package hello\nversion 0.1.0\ncap console\n"),
            Err(ManifestError::BadCap(3))
        ));
        assert!(matches!(
            parse(b"package hello\nversion 0.1.0\nentry hertz\n"),
            Err(ManifestError::BadEntry(3))
        ));
    }

    #[test]
    fn file_lines_are_held_to_their_fields() {
        for bad in [
            // Wrong hex length.
            "file bin/hello sha256=ba7816bf length=3",
            // Uppercase hex.
            "file bin/hello sha256=BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD length=3",
            // Missing length.
            "file bin/hello sha256=ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            // Trailing junk.
            "file bin/hello sha256=ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad length=3 extra=1",
        ] {
            let manifest = with(
                "file bin/hello sha256=ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad length=3",
                bad,
            );
            assert!(
                matches!(parse(&manifest), Err(ManifestError::BadFile(_))),
                "{bad}"
            );
        }
    }

    #[test]
    fn a_program_needs_its_file_line() {
        let manifest = with(
            "file bin/hello sha256=ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad length=3",
            "# gone",
        );
        assert_eq!(
            parse(&manifest).err(),
            Some(ManifestError::ProgramWithoutFile)
        );
    }

    #[test]
    fn duplicates_are_refused_where_they_stand() {
        assert!(matches!(
            parse(&with(
                "program bin/hello",
                "program bin/hello\nprogram bin/hello"
            )),
            Err(ManifestError::DuplicatePath(_))
        ));
    }

    #[test]
    fn control_bytes_are_not_text() {
        assert!(matches!(
            parse(b"package hello\x00\nversion 0.1.0\n"),
            Err(ManifestError::NotText(1))
        ));
    }

    #[test]
    fn an_empty_manifest_is_incomplete_not_a_panic() {
        assert_eq!(parse(b"").err(), Some(ManifestError::Incomplete));
        assert_eq!(
            parse(b"package hello\n").err(),
            Some(ManifestError::Incomplete)
        );
    }

    /// The seeded generator the other parsers use, for the same reason.
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
    fn a_mutation_harness_never_makes_the_parser_panic() {
        // The §8 requirement's always-on half, the ustar harness's shape:
        // seeded, reproducible, asserting only that the parser returns and
        // is deterministic.
        let iterations: usize = std::env::var("BHASKIX_FUZZ_ITERATIONS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(20_000);

        for seed in 0..iterations as u64 {
            let mut rng = Rng(seed.wrapping_mul(0x2545_f491_4f6c_dd1d).wrapping_add(1));
            let mut bytes = GOOD.to_vec();
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
                        let extra = rng.below(64);
                        for _ in 0..extra {
                            bytes.push(rng.next() as u8);
                        }
                    }
                }
                if bytes.is_empty() {
                    break;
                }
            }
            let first = parse(&bytes).map(|manifest| manifest.files().count());
            let second = parse(&bytes).map(|manifest| manifest.files().count());
            assert_eq!(first.is_ok(), second.is_ok(), "seed {seed} not stable");
        }
    }
}
