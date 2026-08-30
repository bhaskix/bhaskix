// SPDX-License-Identifier: Apache-2.0
//! What a hosted `execve` carries: the two vectors of strings.
//!
//! [RFC 0059](../../docs/rfc/0059-an-execve-that-runs-a-program.md). Linux
//! passes `argv` and `envp` as NUL-terminated arrays of pointers into the
//! calling process's own memory, and every one of those pointers is a number
//! that process chose. Reading them is therefore a parser over untrusted
//! input, and it lives here — with no machine, no capability and no `unsafe`
//! — for the reason the rest of this crate exists: the arithmetic can be
//! wrong in ways that do not fail visibly, and a host test is the only place
//! it can be checked byte for byte.
//!
//! # What the caller supplies
//!
//! One closure, `fetch(address, buffer) -> bool`, which is however that
//! caller reaches the hosted process's memory. In `bin/linuxd` it is a
//! `COPY_IN` on the `Domain` capability, so nothing here dereferences a
//! pointer and nothing here can reach memory the adapter could not already
//! read. In a test it is a closure over a `Vec`, which is what makes the
//! refusals below testable at all.
//!
//! # The limits, and why each one is where it is
//!
//! * **Strings per vector** is [`crate::stack::MAX_STRINGS`], taken from that
//!   module rather than restated, because the image builder places exactly
//!   that many and two numbers that agree today would not stay agreed.
//! * **Total string bytes** is [`MAX_BYTES`], chosen so the worst case still
//!   fits [`IMAGE_BYTES`] — proved below by a compile-time assertion rather
//!   than by a comment claiming it.
//! * **Reads never cross a page boundary**, so a string at the end of a
//!   mapping is read to its NUL instead of failing because the *next* page is
//!   absent. Linux's own `strncpy_from_user` has the same shape and for the
//!   same reason.

/// The refusals this module makes, as Linux numbers.
pub mod errno {
    /// A pointer the process gave does not name memory it has.
    pub const EFAULT: i64 = -14;
    /// More strings, or more bytes of them, than one image holds.
    pub const E2BIG: i64 = -7;
}

/// Bytes of argument and environment strings one `execve` may carry,
/// **including one NUL terminator each**.
///
/// The terminators are counted because the image counts them: `stack::Builder`
/// writes `len + 1` bytes per string, so a budget that excluded them would be
/// a budget that did not measure the thing it exists to bound. It is also what
/// the reader needs — a string's NUL has to be *read* before its length is
/// known, so room for it is room that must be there.
///
/// **Not Linux's number.** Linux allows `MAX_ARG_STRLEN` of 128 KiB per string
/// and a quarter of the stack rlimit in total; this adapter builds its initial
/// image in one page, so its budget is what fits there. A program that wants
/// more is refused with `E2BIG`, which is the same errno Linux uses for the
/// same reason, so nothing has to learn a new answer.
pub const MAX_BYTES: usize = 2048;

/// The page the initial process image is built in.
pub const IMAGE_BYTES: usize = 4096;

/// The most strings in one vector, which is the image builder's own limit.
pub const MAX_STRINGS: usize = crate::stack::MAX_STRINGS;

/// The most strings in both vectors together.
const MAX_TOTAL: usize = 2 * MAX_STRINGS;

/// How much of one string is asked for at a time.
///
/// Bounded well below the adapter's scratch area, because `fetch` in
/// `bin/linuxd` stages through it and a request larger than that would be
/// refused for a reason that has nothing to do with the caller's memory.
const CHUNK: usize = 256;

/// The page size the chunking respects.
const PAGE: u64 = 4096;

// The worst case fits the page it is built in, checked by the compiler rather
// than asserted in prose.
//
// The vectors are `argc`, `argv` and its NULL, `envp` and its NULL, then seven
// auxv pairs and the terminating `AT_NULL` pair -- which is what
// `stack::Builder` lays out, and the arithmetic is repeated here because a
// `const` cannot call it. The strings block is every byte plus one NUL each,
// and `RANDOM_BYTES` follows it.
const _: () = {
    let words = 1 + (MAX_STRINGS + 1) + (MAX_STRINGS + 1) + (7 * 2 + 2);
    let vectors = (words * 8 + 15) & !15;
    assert!(
        vectors + MAX_BYTES + crate::stack::RANDOM_BYTES <= IMAGE_BYTES,
        "the worst-case initial image does not fit the page it is built in"
    );
    // And the offsets into the strings block stay inside the type that holds
    // them, which is what lets `push` cast without checking.
    assert!(MAX_BYTES <= u16::MAX as usize);
};

/// The `argv` and `envp` of one `execve`, copied out of the process that asked.
///
/// One buffer for both vectors, because they share one budget: what bounds
/// them is the image they are about to be laid out in, and that does not care
/// which vector a byte came from.
pub struct Arguments {
    /// Every string, back to back, each followed by its NUL — the strings
    /// block of the image, in the order it will be written.
    bytes: [u8; MAX_BYTES],
    /// How much of `bytes` is used, terminators included.
    used: usize,
    /// Where each string ends within `bytes`, not counting its NUL, in order:
    /// `argv`, then `envp`.
    ends: [u16; MAX_TOTAL],
    /// How many strings there are in total.
    count: usize,
    /// How many of them belong to `argv`.
    argc: usize,
}

impl Default for Arguments {
    fn default() -> Self {
        Self::new()
    }
}

impl Arguments {
    /// An empty pair of vectors.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            bytes: [0; MAX_BYTES],
            used: 0,
            ends: [0; MAX_TOTAL],
            count: 0,
            argc: 0,
        }
    }

    /// Reads both vectors out of a hosted process.
    ///
    /// A zero pointer is an empty vector, not a fault: `execve(path, NULL,
    /// NULL)` is a legal Linux call and the exec probe in this tree makes
    /// exactly that one.
    ///
    /// **Both in one call, deliberately.** Two entry points would let a caller
    /// read the environment before the arguments, and the split between them
    /// is a count rather than a marker — so the wrong order would silently
    /// hand a program its environment as `argv`.
    ///
    /// # Errors
    ///
    /// [`errno::EFAULT`] if any pointer does not name memory `fetch` can read,
    /// and [`errno::E2BIG`] if either vector has more than [`MAX_STRINGS`]
    /// entries or the strings together exceed [`MAX_BYTES`].
    pub fn read(
        &mut self,
        argv: u64,
        envp: u64,
        fetch: &mut dyn FnMut(u64, &mut [u8]) -> bool,
    ) -> Result<(), i64> {
        self.used = 0;
        self.count = 0;
        self.argc = 0;
        self.argc = self.read_vector(argv, fetch)?;
        self.read_vector(envp, fetch)?;
        Ok(())
    }

    /// How many argument strings there are.
    #[must_use]
    pub const fn argument_count(&self) -> usize {
        self.argc
    }

    /// How many environment strings there are.
    #[must_use]
    pub const fn environment_count(&self) -> usize {
        self.count - self.argc
    }

    /// Fills `out` with the argument strings, and says how many.
    ///
    /// # Errors
    ///
    /// [`errno::E2BIG`] if `out` is shorter than [`Arguments::argument_count`]
    /// — a refusal rather than a truncation, because a program silently handed
    /// half its arguments is worse off than one told no.
    pub fn arguments<'a>(&'a self, out: &mut [&'a [u8]]) -> Result<usize, i64> {
        self.fill(out, 0, self.argc)
    }

    /// Fills `out` with the environment strings, and says how many.
    ///
    /// # Errors
    ///
    /// As [`Arguments::arguments`].
    pub fn environment<'a>(&'a self, out: &mut [&'a [u8]]) -> Result<usize, i64> {
        self.fill(out, self.argc, self.count)
    }

    fn fill<'a>(&'a self, out: &mut [&'a [u8]], from: usize, to: usize) -> Result<usize, i64> {
        let wanted = to - from;
        if out.len() < wanted {
            return Err(errno::E2BIG);
        }
        for (slot, index) in out.iter_mut().zip(from..to) {
            *slot = self.string(index);
        }
        Ok(wanted)
    }

    /// The `index`th string. Bounds are this type's own invariant: `ends` is
    /// increasing and every entry is less than `used`. The `+ 1` steps over
    /// the previous string's terminator.
    fn string(&self, index: usize) -> &[u8] {
        let start = if index == 0 {
            0
        } else {
            self.ends[index - 1] as usize + 1
        };
        let end = self.ends[index] as usize;
        self.bytes.get(start..end).unwrap_or(&[])
    }

    /// Walks one NUL-terminated vector of pointers, collecting what it names.
    fn read_vector(
        &mut self,
        vector: u64,
        fetch: &mut dyn FnMut(u64, &mut [u8]) -> bool,
    ) -> Result<usize, i64> {
        if vector == 0 {
            return Ok(0);
        }
        let mut taken = 0usize;
        loop {
            let slot = vector.checked_add(taken as u64 * 8).ok_or(errno::EFAULT)?;
            let mut word = [0u8; 8];
            if !fetch(slot, &mut word) {
                return Err(errno::EFAULT);
            }
            let pointer = u64::from_le_bytes(word);
            // **The terminator is read before the count is checked**, and the
            // first version of this had it the other way round — so a vector
            // of exactly `MAX_STRINGS` strings, which is the most the image
            // builder places and therefore the most that is *legal*, was
            // refused with `E2BIG` at its own limit. Caught by the test that
            // asks for exactly the limit and one more, which is why that test
            // asks for both.
            if pointer == 0 {
                return Ok(taken);
            }
            if taken == MAX_STRINGS {
                return Err(errno::E2BIG);
            }
            self.push(pointer, fetch)?;
            taken += 1;
        }
    }

    /// Copies one string in and records where it ended.
    fn push(&mut self, at: u64, fetch: &mut dyn FnMut(u64, &mut [u8]) -> bool) -> Result<(), i64> {
        if self.count == MAX_TOTAL {
            return Err(errno::E2BIG);
        }
        let length = read_string(at, &mut self.bytes[self.used..], fetch)?;
        // `read_string` only returns once it has read a NUL into the buffer,
        // so the terminator is already there and `used` steps over it. The
        // casts are safe by the compile-time assertion above: `used` never
        // exceeds `MAX_BYTES`, which is well inside a `u16`.
        self.ends[self.count] = (self.used + length) as u16;
        self.used += length + 1;
        self.count += 1;
        Ok(())
    }
}

/// Copies a NUL-terminated string out of a hosted process into `out`.
///
/// Public because a path is one of these too: `execve` reads its program name
/// the same way it reads an argument, and the alternative — a fixed-size copy
/// of `MAX_NAME` bytes — refuses a perfectly good short path that happens to
/// sit near the end of a mapping.
///
/// Returns its length, not counting the NUL — which *is* written, because
/// finding it means reading it, and because the image needs it there anyway.
///
/// # Errors
///
/// [`errno::EFAULT`] if a chunk cannot be read, [`errno::E2BIG`] if no NUL
/// appears within `out`.
pub fn read_string(
    at: u64,
    out: &mut [u8],
    fetch: &mut dyn FnMut(u64, &mut [u8]) -> bool,
) -> Result<usize, i64> {
    let mut taken = 0usize;
    loop {
        if taken == out.len() {
            return Err(errno::E2BIG);
        }
        let address = at.checked_add(taken as u64).ok_or(errno::EFAULT)?;
        // **Never past the end of the page this byte is in.** A string may sit
        // anywhere, including the last four bytes of the last mapped page of a
        // process; a fixed-size read there would be refused for the page after
        // it, which the process does not have and does not need.
        let to_page_end = (PAGE - (address % PAGE)) as usize;
        let want = (out.len() - taken).min(CHUNK).min(to_page_end);
        let slice = &mut out[taken..taken + want];
        if !fetch(address, slice) {
            return Err(errno::EFAULT);
        }
        if let Some(nul) = slice.iter().position(|byte| *byte == 0) {
            return Ok(taken + nul);
        }
        taken += want;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A hosted process's memory: pages that exist, and everything else absent.
    struct Memory {
        pages: std::collections::BTreeMap<u64, [u8; PAGE as usize]>,
    }

    impl Memory {
        fn new() -> Self {
            Self {
                pages: std::collections::BTreeMap::new(),
            }
        }

        /// Puts `bytes` at `at`, mapping whatever pages that needs.
        fn put(&mut self, at: u64, bytes: &[u8]) {
            for (index, byte) in bytes.iter().enumerate() {
                let address = at + index as u64;
                let page = address & !(PAGE - 1);
                let entry = self.pages.entry(page).or_insert([0; PAGE as usize]);
                entry[(address % PAGE) as usize] = *byte;
            }
        }

        fn put_word(&mut self, at: u64, value: u64) {
            self.put(at, &value.to_le_bytes());
        }

        /// The `fetch` closure, refusing anything that touches an absent page —
        /// which is what a `COPY_IN` on an unmapped address does.
        fn fetch(&self) -> impl FnMut(u64, &mut [u8]) -> bool + '_ {
            move |at: u64, out: &mut [u8]| {
                for (index, byte) in out.iter_mut().enumerate() {
                    let address = at + index as u64;
                    let Some(page) = self.pages.get(&(address & !(PAGE - 1))) else {
                        return false;
                    };
                    *byte = page[(address % PAGE) as usize];
                }
                true
            }
        }
    }

    /// Lays out a vector of strings at `strings_at` and its pointer array at
    /// `vector_at`, the way a libc builds one before `execve`.
    fn lay_out(memory: &mut Memory, vector_at: u64, strings_at: u64, strings: &[&[u8]]) {
        let mut cursor = strings_at;
        for (index, string) in strings.iter().enumerate() {
            memory.put(cursor, string);
            memory.put(cursor + string.len() as u64, &[0]);
            memory.put_word(vector_at + index as u64 * 8, cursor);
            cursor += string.len() as u64 + 1;
        }
        memory.put_word(vector_at + strings.len() as u64 * 8, 0);
    }

    #[test]
    fn both_vectors_are_read_and_kept_apart() {
        let mut memory = Memory::new();
        lay_out(&mut memory, 0x1000, 0x2000, &[b"hosted", b"one", b"two"]);
        lay_out(
            &mut memory,
            0x3000,
            0x4000,
            &[b"GREETING=namaste", b"HOME=/"],
        );

        let mut arguments = Arguments::new();
        arguments
            .read(0x1000, 0x3000, &mut memory.fetch())
            .expect("both vectors are readable");

        assert_eq!(arguments.argument_count(), 3);
        assert_eq!(arguments.environment_count(), 2);

        let mut argv: [&[u8]; MAX_STRINGS] = [b""; MAX_STRINGS];
        let mut envp: [&[u8]; MAX_STRINGS] = [b""; MAX_STRINGS];
        let argc = arguments.arguments(&mut argv).unwrap();
        let envc = arguments.environment(&mut envp).unwrap();
        assert_eq!(&argv[..argc], &[b"hosted".as_slice(), b"one", b"two"]);
        assert_eq!(&envp[..envc], &[b"GREETING=namaste".as_slice(), b"HOME=/"]);
    }

    #[test]
    fn a_null_vector_is_empty_rather_than_a_fault() {
        let memory = Memory::new();
        let mut arguments = Arguments::new();
        arguments
            .read(0, 0, &mut memory.fetch())
            .expect("execve(path, NULL, NULL) is a legal call");
        assert_eq!(arguments.argument_count(), 0);
        assert_eq!(arguments.environment_count(), 0);
    }

    #[test]
    fn an_empty_vector_is_not_the_same_as_a_missing_one() {
        let mut memory = Memory::new();
        memory.put_word(0x1000, 0);
        let mut arguments = Arguments::new();
        arguments.read(0x1000, 0, &mut memory.fetch()).unwrap();
        assert_eq!(arguments.argument_count(), 0);
    }

    #[test]
    fn a_vector_that_is_never_terminated_is_refused() {
        let mut memory = Memory::new();
        // Every slot points at the same string and nothing is ever zero, so
        // the walk would run for ever if the count did not stop it.
        memory.put(0x2000, b"x\0");
        for index in 0..(MAX_STRINGS as u64 + 8) {
            memory.put_word(0x1000 + index * 8, 0x2000);
        }
        let mut arguments = Arguments::new();
        assert_eq!(
            arguments.read(0x1000, 0, &mut memory.fetch()),
            Err(errno::E2BIG)
        );
    }

    #[test]
    fn a_vector_running_off_its_mapping_is_a_fault_rather_than_a_hang() {
        let mut memory = Memory::new();
        memory.put(0x5000, b"x\0");
        // Two slots at the very end of a page, both non-zero, and then the
        // page after them does not exist — so the walk reads a slot in memory
        // the process does not have, which is exactly what an `execve` with a
        // vector that is never terminated looks like from here.
        let vector = 0x2000 + PAGE - 16;
        memory.put_word(vector, 0x5000);
        memory.put_word(vector + 8, 0x5000);

        let mut arguments = Arguments::new();
        assert_eq!(
            arguments.read(vector, 0, &mut memory.fetch()),
            Err(errno::EFAULT)
        );
    }

    #[test]
    fn a_pointer_to_nothing_is_a_fault() {
        let mut memory = Memory::new();
        memory.put_word(0x1000, 0x9000_0000);
        memory.put_word(0x1008, 0);
        let mut arguments = Arguments::new();
        assert_eq!(
            arguments.read(0x1000, 0, &mut memory.fetch()),
            Err(errno::EFAULT)
        );
    }

    #[test]
    fn strings_larger_than_the_budget_are_refused_rather_than_truncated() {
        let mut memory = Memory::new();
        let long = std::vec![b'a'; MAX_BYTES + 1];
        lay_out(&mut memory, 0x1000, 0x2000, &[&long]);
        let mut arguments = Arguments::new();
        assert_eq!(
            arguments.read(0x1000, 0, &mut memory.fetch()),
            Err(errno::E2BIG)
        );
    }

    #[test]
    fn the_two_vectors_share_one_budget() {
        // Each on its own fits; together they do not. This is the case a
        // per-vector budget would have let through, and the image it would
        // then have tried to build does not fit its page.
        let mut memory = Memory::new();
        let two_thirds = std::vec![b'a'; MAX_BYTES * 2 / 3];
        lay_out(&mut memory, 0x1000, 0x10000, &[&two_thirds]);
        lay_out(&mut memory, 0x3000, 0x20000, &[&two_thirds]);
        let mut arguments = Arguments::new();
        assert_eq!(
            arguments.read(0x1000, 0x3000, &mut memory.fetch()),
            Err(errno::E2BIG)
        );
    }

    /// A string whose NUL is the last byte of the last page a process has.
    ///
    /// This is the case the page-bounded chunking exists for: a fixed 256-byte
    /// read here would touch the page after it, which is absent, and the exec
    /// would be refused for a string that is perfectly well formed.
    #[test]
    fn a_string_at_the_very_end_of_a_mapping_is_read_to_its_nul() {
        let mut memory = Memory::new();
        let at = 0x2000 + PAGE - 4;
        memory.put(at, b"abc\0");
        memory.put_word(0x1000, at);
        memory.put_word(0x1008, 0);

        let mut arguments = Arguments::new();
        arguments
            .read(0x1000, 0, &mut memory.fetch())
            .expect("the string is entirely inside a mapped page");
        let mut argv: [&[u8]; MAX_STRINGS] = [b""; MAX_STRINGS];
        let argc = arguments.arguments(&mut argv).unwrap();
        assert_eq!(&argv[..argc], &[b"abc".as_slice()]);
    }

    /// And the same string with its NUL one byte into the *next* page, which
    /// the process does not have: that one really is a fault.
    #[test]
    fn a_string_running_past_its_last_page_is_a_fault() {
        let mut memory = Memory::new();
        let at = 0x2000 + PAGE - 3;
        memory.put(at, b"abc");
        memory.put_word(0x1000, at);
        memory.put_word(0x1008, 0);

        let mut arguments = Arguments::new();
        assert_eq!(
            arguments.read(0x1000, 0, &mut memory.fetch()),
            Err(errno::EFAULT)
        );
    }

    #[test]
    fn exactly_the_string_limit_is_accepted_and_one_more_is_not() {
        let strings: std::vec::Vec<&[u8]> = std::vec![b"x".as_slice(); MAX_STRINGS];
        let mut memory = Memory::new();
        lay_out(&mut memory, 0x1000, 0x2000, &strings);
        let mut arguments = Arguments::new();
        arguments.read(0x1000, 0, &mut memory.fetch()).unwrap();
        assert_eq!(arguments.argument_count(), MAX_STRINGS);

        let one_more: std::vec::Vec<&[u8]> = std::vec![b"x".as_slice(); MAX_STRINGS + 1];
        let mut memory = Memory::new();
        lay_out(&mut memory, 0x1000, 0x2000, &one_more);
        let mut arguments = Arguments::new();
        assert_eq!(
            arguments.read(0x1000, 0, &mut memory.fetch()),
            Err(errno::E2BIG)
        );
    }

    #[test]
    fn an_output_slice_too_short_is_refused_rather_than_truncating() {
        let mut memory = Memory::new();
        lay_out(&mut memory, 0x1000, 0x2000, &[b"a", b"b", b"c"]);
        let mut arguments = Arguments::new();
        arguments.read(0x1000, 0, &mut memory.fetch()).unwrap();
        let mut argv: [&[u8]; 2] = [b""; 2];
        assert_eq!(arguments.arguments(&mut argv), Err(errno::E2BIG));
    }

    /// Reading twice must not accumulate: the second `execve` of a process is
    /// a fresh pair of vectors, not the first one with more on the end.
    #[test]
    fn reading_again_replaces_rather_than_appends() {
        let mut memory = Memory::new();
        lay_out(&mut memory, 0x1000, 0x2000, &[b"first", b"second"]);
        lay_out(&mut memory, 0x5000, 0x6000, &[b"only"]);

        let mut arguments = Arguments::new();
        arguments.read(0x1000, 0, &mut memory.fetch()).unwrap();
        arguments.read(0x5000, 0, &mut memory.fetch()).unwrap();

        assert_eq!(arguments.argument_count(), 1);
        let mut argv: [&[u8]; MAX_STRINGS] = [b""; MAX_STRINGS];
        let argc = arguments.arguments(&mut argv).unwrap();
        assert_eq!(&argv[..argc], &[b"only".as_slice()]);
    }

    /// The strings this module collects go straight into an image the stack
    /// builder lays out, so the two are checked together rather than each
    /// against its own idea of the other.
    #[test]
    fn what_is_read_builds_an_image_that_fits_its_page() {
        use crate::stack::{Builder, ProcessInfo};

        let mut memory = Memory::new();
        lay_out(&mut memory, 0x1000, 0x2000, &[b"hosted", b"one"]);
        lay_out(&mut memory, 0x3000, 0x4000, &[b"GREETING=namaste"]);
        let mut arguments = Arguments::new();
        arguments.read(0x1000, 0x3000, &mut memory.fetch()).unwrap();

        let mut argv: [&[u8]; MAX_STRINGS] = [b""; MAX_STRINGS];
        let mut envp: [&[u8]; MAX_STRINGS] = [b""; MAX_STRINGS];
        let argc = arguments.arguments(&mut argv).unwrap();
        let envc = arguments.environment(&mut envp).unwrap();

        let builder = Builder::new(
            &argv[..argc],
            &envp[..envc],
            ProcessInfo {
                entry: 0x30_0000,
                phdr: 0x30_0040,
                phent: 56,
                phnum: 3,
                page_size: 4096,
                hwcap: 0,
                random: *b"0123456789abcdef",
            },
        );
        assert!(builder.size() <= IMAGE_BYTES);
        let mut image = std::vec![0u8; IMAGE_BYTES];
        builder.build(&mut image, 0x7fff_0000).unwrap();

        // argc, then argv[0] pointing at a string that reads back.
        let mut word = [0u8; 8];
        word.copy_from_slice(&image[..8]);
        assert_eq!(u64::from_le_bytes(word), 2);
        word.copy_from_slice(&image[8..16]);
        let at = (u64::from_le_bytes(word) - 0x7fff_0000) as usize;
        assert_eq!(&image[at..at + 7], b"hosted\0");
    }

    /// The worst case this module admits really does build, rather than only
    /// satisfying the compile-time arithmetic above.
    #[test]
    fn the_worst_case_this_admits_still_fits_the_image_page() {
        use crate::stack::{Builder, ProcessInfo};

        // `MAX_STRINGS` in each vector, filling the byte budget between them.
        // One byte of each string's share is its terminator, which is what
        // `MAX_BYTES` counts — the first version of this test spent the whole
        // budget on characters and was refused at its own stated limit.
        let each = MAX_BYTES / (2 * MAX_STRINGS) - 1;
        let string = std::vec![b'a'; each];
        let strings: std::vec::Vec<&[u8]> = std::vec![string.as_slice(); MAX_STRINGS];
        let mut memory = Memory::new();
        lay_out(&mut memory, 0x1000, 0x10000, &strings);
        lay_out(&mut memory, 0x3000, 0x20000, &strings);

        let mut arguments = Arguments::new();
        arguments.read(0x1000, 0x3000, &mut memory.fetch()).unwrap();

        let mut argv: [&[u8]; MAX_STRINGS] = [b""; MAX_STRINGS];
        let mut envp: [&[u8]; MAX_STRINGS] = [b""; MAX_STRINGS];
        let argc = arguments.arguments(&mut argv).unwrap();
        let envc = arguments.environment(&mut envp).unwrap();
        assert_eq!(argc, MAX_STRINGS);
        assert_eq!(envc, MAX_STRINGS);

        let builder = Builder::new(
            &argv[..argc],
            &envp[..envc],
            ProcessInfo {
                entry: 0x30_0000,
                phdr: 0x30_0040,
                phent: 56,
                phnum: 3,
                page_size: 4096,
                hwcap: 0,
                random: *b"0123456789abcdef",
            },
        );
        assert!(
            builder.size() <= IMAGE_BYTES,
            "the worst case needs {} bytes",
            builder.size()
        );
        let mut image = std::vec![0u8; IMAGE_BYTES];
        builder.build(&mut image, 0x7fff_0000).unwrap();
    }
}
