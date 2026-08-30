// SPDX-License-Identifier: Apache-2.0
//! The initial process stack a Linux program is entered with.
//!
//! Before any system call runs, a Linux process is started with a very
//! specific stack, and the Go runtime reads it directly — [RFC 0005](../../docs/rfc/0005-linux-abi-compatibility.md)
//! §"The initial process image". The kernel builds the real thing by calling
//! [`Builder::build`] with the addresses a real mapping will have; a host test
//! builds the same image over a plain buffer and checks it byte for byte,
//! which is the only way to get this right, because "off by one pointer-width
//! in the auxv" is a class of bug that does not fail visibly — it hands the
//! runtime the wrong `AT_RANDOM` and the program runs with predictable
//! startup entropy, or reads a `NULL` where a count belonged and diverges.
//!
//! # The layout, top of stack downward
//!
//! System V AMD64, exactly as `_start` expects to find it at `rsp`:
//!
//! ```text
//!   argc                     <- rsp points here at entry
//!   argv[0..argc]            pointers into the strings below
//!   NULL                     end of argv
//!   envp[0..envc]           pointers into the strings below
//!   NULL                     end of envp
//!   auxv: (type, value) pairs, AT_NULL-terminated
//!   (16-byte alignment padding)
//!   the strings argv and envp point at, and the 16 AT_RANDOM bytes
//! ```
//!
//! The strings live *above* the vectors that point at them (at higher
//! addresses), because the whole block is written into a region and the
//! pointers have to be absolute addresses in the process's own space — so the
//! builder is told the base address the region will map at and computes them.

/// Auxiliary-vector entry types, from Linux's `elf.h`. Only the ones Go's
/// `runtime.sysargs` actually reads are named; the rest are refused by
/// omission, which is honest — an auxv this does not build is one Go does not
/// need on the path this supports.
pub mod auxv {
    /// End of vector.
    pub const NULL: u64 = 0;
    /// Page size in bytes.
    pub const PAGESZ: u64 = 6;
    /// Address of the program headers in the process image.
    pub const PHDR: u64 = 3;
    /// Size of one program-header entry.
    pub const PHENT: u64 = 4;
    /// Number of program-header entries.
    pub const PHNUM: u64 = 5;
    /// The program's entry point.
    pub const ENTRY: u64 = 9;
    /// Hardware-capability bitmask.
    pub const HWCAP: u64 = 16;
    /// Pointer to sixteen random bytes — the runtime's startup entropy, and
    /// not optional: Go seeds its hash and its scheduler from it.
    pub const RANDOM: u64 = 25;
}

/// Bytes in the `AT_RANDOM` block.
pub const RANDOM_BYTES: usize = 16;

/// Everything the initial image needs that is not an argument string.
#[derive(Clone, Copy)]
pub struct ProcessInfo {
    /// The program's entry point, for `AT_ENTRY`.
    pub entry: u64,
    /// The address of the program headers in the process's own space.
    pub phdr: u64,
    /// The size of one program-header entry.
    pub phent: u64,
    /// How many program-header entries there are.
    pub phnum: u64,
    /// The page size to advertise.
    pub page_size: u64,
    /// The hardware-capability bitmask to advertise.
    pub hwcap: u64,
    /// Sixteen bytes of entropy for `AT_RANDOM`.
    pub random: [u8; RANDOM_BYTES],
}

/// Why an image could not be built.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StackError {
    /// The computed image is larger than the buffer it was given.
    TooLarge {
        /// Bytes the image needs.
        needed: usize,
        /// Bytes available.
        capacity: usize,
    },
    /// More argument or environment strings than [`MAX_STRINGS`].
    TooManyStrings {
        /// How many were given, whichever vector was the longer.
        count: usize,
        /// How many this builder places.
        limit: usize,
    },
}

/// Builds an initial-stack image into a caller's buffer.
///
/// `base` is the virtual address the *lowest* byte of the buffer will map at
/// in the process — every pointer written into the image is computed from it,
/// so the image is correct only when it is eventually placed at `base`.
pub struct Builder<'a> {
    args: &'a [&'a [u8]],
    env: &'a [&'a [u8]],
    info: ProcessInfo,
}

impl<'a> Builder<'a> {
    /// A builder for a process with these arguments, environment, and info.
    #[must_use]
    pub const fn new(args: &'a [&'a [u8]], env: &'a [&'a [u8]], info: ProcessInfo) -> Self {
        Self { args, env, info }
    }

    /// The seven `(type, value)` auxv pairs this builds, in order, before the
    /// terminating `AT_NULL`. `random_addr` is where the `AT_RANDOM` block
    /// will live.
    fn auxv_pairs(&self, random_addr: u64) -> [(u64, u64); 7] {
        [
            (auxv::PAGESZ, self.info.page_size),
            (auxv::PHDR, self.info.phdr),
            (auxv::PHENT, self.info.phent),
            (auxv::PHNUM, self.info.phnum),
            (auxv::ENTRY, self.info.entry),
            (auxv::HWCAP, self.info.hwcap),
            (auxv::RANDOM, random_addr),
        ]
    }

    /// Total bytes this image occupies, so a caller can size a region before
    /// building — and so `build` can refuse a short buffer with a number.
    #[must_use]
    pub fn size(&self) -> usize {
        // The word vectors: argc, argv + NULL, envp + NULL, auxv pairs + NULL.
        let words =
            1 + (self.args.len() + 1) + (self.env.len() + 1) + (self.auxv_pairs(0).len() * 2 + 2);
        let vector_bytes = words * 8;
        // The strings block, NUL-terminated, plus the random block, then the
        // whole image rounded so the strings start 16-aligned within it.
        let mut strings = 0;
        for arg in self.args {
            strings += arg.len() + 1;
        }
        for var in self.env {
            strings += var.len() + 1;
        }
        let aligned_vectors = (vector_bytes + 15) & !15;
        aligned_vectors + strings + RANDOM_BYTES
    }

    /// Writes the image into `buffer`, whose lowest byte maps at `base`.
    /// Returns the offset of `argc` — where the process's `rsp` must point.
    ///
    /// # Errors
    ///
    /// [`StackError::TooLarge`] if `buffer` cannot hold [`Builder::size`], and
    /// [`StackError::TooManyStrings`] if either vector is longer than
    /// [`MAX_STRINGS`].
    ///
    /// **The second refusal was claimed before it existed.** `MAX_STRINGS`'
    /// own comment has said since it was written that a process with more
    /// strings than this "is refused rather than silently truncated", and
    /// nothing refused it: the loops below index `[u64; MAX_STRINGS]` by
    /// `enumerate`, so a sixty-fifth string was an out-of-bounds index — a
    /// panic, which in a `no_std` program built with `panic = "abort"` is a
    /// `ud2`. It was unreachable while every caller passed a literal array of
    /// at most three. RFC 0059 makes `argv` come out of a hosted process's
    /// own memory, which is untrusted input, so the claim had to become true
    /// before the caller arrived rather than after.
    pub fn build(&self, buffer: &mut [u8], base: u64) -> Result<usize, StackError> {
        let count = self.args.len().max(self.env.len());
        if count > MAX_STRINGS {
            return Err(StackError::TooManyStrings {
                count,
                limit: MAX_STRINGS,
            });
        }
        let needed = self.size();
        if buffer.len() < needed {
            return Err(StackError::TooLarge {
                needed,
                capacity: buffer.len(),
            });
        }

        // The vectors sit at the bottom (rsp) and the strings above them, so
        // the strings' addresses are known before the pointers are written.
        let words =
            1 + (self.args.len() + 1) + (self.env.len() + 1) + (self.auxv_pairs(0).len() * 2 + 2);
        let vector_bytes = words * 8;
        let strings_start = (vector_bytes + 15) & !15;

        // Lay out the strings and remember where each landed.
        let mut cursor = strings_start;
        let mut arg_addrs = [0u64; MAX_STRINGS];
        for (index, arg) in self.args.iter().enumerate() {
            arg_addrs[index] = base + cursor as u64;
            buffer[cursor..cursor + arg.len()].copy_from_slice(arg);
            buffer[cursor + arg.len()] = 0;
            cursor += arg.len() + 1;
        }
        let mut env_addrs = [0u64; MAX_STRINGS];
        for (index, var) in self.env.iter().enumerate() {
            env_addrs[index] = base + cursor as u64;
            buffer[cursor..cursor + var.len()].copy_from_slice(var);
            buffer[cursor + var.len()] = 0;
            cursor += var.len() + 1;
        }
        let random_addr = base + cursor as u64;
        buffer[cursor..cursor + RANDOM_BYTES].copy_from_slice(&self.info.random);

        // Now the vectors, bottom up.
        let mut at = 0usize;
        let mut put = |value: u64, at: &mut usize| {
            buffer[*at..*at + 8].copy_from_slice(&value.to_le_bytes());
            *at += 8;
        };
        put(self.args.len() as u64, &mut at);
        for address in arg_addrs.iter().take(self.args.len()) {
            put(*address, &mut at);
        }
        put(0, &mut at);
        for address in env_addrs.iter().take(self.env.len()) {
            put(*address, &mut at);
        }
        put(0, &mut at);
        for (kind, value) in self.auxv_pairs(random_addr) {
            put(kind, &mut at);
            put(value, &mut at);
        }
        put(auxv::NULL, &mut at);
        put(0, &mut at);

        Ok(0)
    }
}

/// The most argument or environment strings this builder places. A process
/// with more than this many is refused rather than silently truncated; the
/// number is generous for the workloads RFC 0005 targets and is a fixed array
/// because this crate does not allocate.
///
/// **Public since RFC 0059**, because the refusal is now a caller's business:
/// `bin/linuxd` reads `argv` and `envp` out of a hosted process's own memory
/// and has to stop counting somewhere, and it should stop at the same number
/// this stops at rather than at a second one that happens to agree today.
pub const MAX_STRINGS: usize = 64;

#[cfg(test)]
mod tests {
    use super::*;

    fn info() -> ProcessInfo {
        ProcessInfo {
            entry: 0x40_1000,
            phdr: 0x40_0040,
            phent: 56,
            phnum: 5,
            page_size: 4096,
            hwcap: 0,
            random: *b"0123456789abcdef",
        }
    }

    /// Reads the `u64` at word `index` of an image.
    fn word(image: &[u8], index: usize) -> u64 {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&image[index * 8..index * 8 + 8]);
        u64::from_le_bytes(bytes)
    }

    #[test]
    fn argc_argv_envp_are_laid_out_and_null_terminated() {
        let args: [&[u8]; 2] = [b"prog", b"--flag"];
        let env: [&[u8]; 1] = [b"PATH=/bin"];
        let builder = Builder::new(&args, &env, info());
        let base = 0x7fff_0000_0000;
        let mut buffer = alloc_zeroed(builder.size());
        builder.build(&mut buffer, base).unwrap();

        assert_eq!(word(&buffer, 0), 2, "argc");
        // argv[0], argv[1], then a NULL.
        assert_eq!(word(&buffer, 3), 0, "argv NULL-terminated");
        // envp[0] then a NULL.
        assert_eq!(word(&buffer, 5), 0, "envp NULL-terminated");

        // The argv pointers land inside the image and read back the strings.
        let argv0 = (word(&buffer, 1) - base) as usize;
        assert_eq!(&buffer[argv0..argv0 + 5], b"prog\0");
        let argv1 = (word(&buffer, 2) - base) as usize;
        assert_eq!(&buffer[argv1..argv1 + 7], b"--flag\0");
        let path = (word(&buffer, 4) - base) as usize;
        assert_eq!(&buffer[path..path + 10], b"PATH=/bin\0");
    }

    #[test]
    fn the_auxv_carries_every_entry_go_reads_and_at_random_points_at_entropy() {
        let args: [&[u8]; 1] = [b"prog"];
        let env: [&[u8]; 0] = [];
        let builder = Builder::new(&args, &env, info());
        let base = 0x7fff_0000_0000;
        let mut buffer = alloc_zeroed(builder.size());
        builder.build(&mut buffer, base).unwrap();

        // argc(1) + argv[0] + NULL(1) + envp NULL(1) = word 4 starts auxv.
        let auxv_start = 1 + 1 + 1 + 1;
        let mut found = alloc_map();
        let mut index = auxv_start;
        loop {
            let kind = word(&buffer, index);
            let value = word(&buffer, index + 1);
            if kind == auxv::NULL {
                break;
            }
            found.push((kind, value));
            index += 2;
        }
        // Every entry Go reads is present, exactly once.
        for kind in [
            auxv::PAGESZ,
            auxv::PHDR,
            auxv::PHENT,
            auxv::PHNUM,
            auxv::ENTRY,
            auxv::HWCAP,
            auxv::RANDOM,
        ] {
            assert_eq!(
                found.iter().filter(|(k, _)| *k == kind).count(),
                1,
                "auxv entry {kind} present once"
            );
        }
        assert_eq!(pair(&found, auxv::PAGESZ), 4096);
        assert_eq!(pair(&found, auxv::ENTRY), 0x40_1000);

        // AT_RANDOM points at the sixteen entropy bytes, inside the image.
        let random_at = (pair(&found, auxv::RANDOM) - base) as usize;
        assert_eq!(&buffer[random_at..random_at + 16], b"0123456789abcdef");
    }

    #[test]
    fn a_short_buffer_is_refused_with_the_numbers() {
        let args: [&[u8]; 1] = [b"prog"];
        let env: [&[u8]; 0] = [];
        let builder = Builder::new(&args, &env, info());
        let mut buffer = alloc_zeroed(8);
        let error = builder.build(&mut buffer, 0x1000).unwrap_err();
        assert!(matches!(error, StackError::TooLarge { needed, capacity }
            if needed == builder.size() && capacity == 8));
    }

    #[test]
    fn the_image_is_deterministic() {
        let args: [&[u8]; 2] = [b"prog", b"x"];
        let env: [&[u8]; 1] = [b"K=V"];
        let builder = Builder::new(&args, &env, info());
        let mut a = alloc_zeroed(builder.size());
        let mut b = alloc_zeroed(builder.size());
        builder.build(&mut a, 0x2000).unwrap();
        builder.build(&mut b, 0x2000).unwrap();
        assert_eq!(a, b);
    }

    /// The regression test for the refusal `MAX_STRINGS` claimed and did not
    /// make.
    ///
    /// Before RFC 0059 this input did not return an error — it indexed
    /// `[u64; MAX_STRINGS]` at 64 and panicked, which in the ring 3 program
    /// that will now build these images is a `ud2`, taken by a hosted process
    /// choosing its own `argv`. The buffer is deliberately made large enough
    /// for the image, so that a `TooLarge` cannot pass this test by accident.
    #[test]
    fn more_strings_than_the_builder_places_are_refused_rather_than_panicking() {
        let many = [b"x".as_slice(); MAX_STRINGS + 1];
        let env: [&[u8]; 0] = [];
        let builder = Builder::new(&many, &env, info());
        let mut buffer = alloc_zeroed(builder.size());
        let error = builder.build(&mut buffer, 0x1000).unwrap_err();
        assert!(
            matches!(error, StackError::TooManyStrings { count, limit }
                if count == MAX_STRINGS + 1 && limit == MAX_STRINGS),
            "expected TooManyStrings, got {error:?}"
        );

        // The environment vector is counted too, and separately: a process
        // with two arguments and a thousand variables is the same overflow.
        let args: [&[u8]; 2] = [b"prog", b"x"];
        let vars = [b"K=V".as_slice(); MAX_STRINGS + 1];
        let builder = Builder::new(&args, &vars, info());
        let mut buffer = alloc_zeroed(builder.size());
        assert!(matches!(
            builder.build(&mut buffer, 0x1000).unwrap_err(),
            StackError::TooManyStrings { .. }
        ));

        // And exactly the limit still builds, so the refusal is at the right
        // place rather than one early.
        let full = [b"x".as_slice(); MAX_STRINGS];
        let builder = Builder::new(&full, &env, info());
        let mut buffer = alloc_zeroed(builder.size());
        builder.build(&mut buffer, 0x1000).unwrap();
        assert_eq!(word(&buffer, 0), MAX_STRINGS as u64, "argc");
    }

    // Small std helpers, test-only.
    fn alloc_zeroed(n: usize) -> std::vec::Vec<u8> {
        std::vec![0u8; n]
    }
    fn alloc_map() -> std::vec::Vec<(u64, u64)> {
        std::vec::Vec::new()
    }
    fn pair(found: &[(u64, u64)], kind: u64) -> u64 {
        found.iter().find(|(k, _)| *k == kind).unwrap().1
    }
}
