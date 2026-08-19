// SPDX-License-Identifier: Apache-2.0
//! The Linux memory calls, as arithmetic.
//!
//! [RFC 0005](../../docs/rfc/0005-linux-abi-compatibility.md) step 5:
//! `mmap`, `munmap`, `mprotect`, `madvise` over the region map this kernel
//! already has — which, as the RFC notes, *already makes `W^X`
//! unrepresentable*, because [`Protection`](crate::stack) has no variant for
//! writable-and-executable. That is not a check this layer performs; it is a
//! shape the type system enforces, and the translation below simply cannot
//! ask for what does not exist.
//!
//! What lives here is the decoding: which flags are honoured, which are
//! refused, what a length rounds to, and which `errno` each refusal is. All
//! of it is a pure function of the arguments, so all of it is host-tested.

/// `mmap` protection bits.
pub mod prot {
    /// Pages may not be accessed.
    pub const NONE: u64 = 0;
    /// Pages may be read.
    pub const READ: u64 = 1;
    /// Pages may be written.
    pub const WRITE: u64 = 2;
    /// Pages may be executed.
    pub const EXEC: u64 = 4;
}

/// `mmap` flags.
pub mod flags {
    /// Changes are private to this process.
    pub const PRIVATE: u64 = 0x02;
    /// Not backed by a file.
    pub const ANONYMOUS: u64 = 0x20;
    /// The address is a requirement, not a hint.
    pub const FIXED: u64 = 0x10;
    /// Reserve address space without committing memory — Go asks for this
    /// constantly, and honouring it as an ordinary lazy mapping is right:
    /// this kernel commits on fault either way.
    pub const NORESERVE: u64 = 0x4000;
    /// Grows downward — a stack. Refused; nothing hosted asks yet.
    pub const GROWSDOWN: u64 = 0x0100;
}

/// Linux `errno` values this translation returns, negated at the register.
pub mod errno {
    /// Invalid argument.
    pub const EINVAL: i64 = -22;
    /// Out of memory.
    pub const ENOMEM: i64 = -12;
    /// Function not implemented.
    pub const ENOSYS: i64 = -38;
    /// Permission denied.
    pub const EACCES: i64 = -13;
}

/// What the personality should do with an `mmap` request.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MapPlan {
    /// Map `pages` pages at this address with this protection. The address
    /// is either the caller's demand (`MAP_FIXED`) or one the personality
    /// picks; `fixed` says which, because "somewhere" and "exactly here" are
    /// different promises and only one of them can fail with `EEXIST` later.
    Map {
        /// Where, if the caller demanded a place.
        at: Option<u64>,
        /// How many pages.
        pages: u64,
        /// Readable.
        read: bool,
        /// Writable.
        write: bool,
        /// Executable.
        execute: bool,
    },
    /// Refuse with this `errno`.
    Refuse(i64),
}

/// Bytes in a page, as this translation rounds to.
pub const PAGE: u64 = 4096;

/// Rounds `bytes` up to whole pages, refusing an overflow rather than
/// wrapping — a length near `u64::MAX` is exactly the argument a hostile
/// caller supplies.
#[must_use]
pub fn pages_for(bytes: u64) -> Option<u64> {
    bytes.checked_add(PAGE - 1).map(|rounded| rounded / PAGE)
}

/// Decides what an `mmap(addr, length, prot, flags, fd, offset)` means.
#[must_use]
pub fn plan_mmap(addr: u64, length: u64, protection: u64, flags: u64, fd: i64) -> MapPlan {
    if length == 0 {
        return MapPlan::Refuse(errno::EINVAL);
    }
    let Some(pages) = pages_for(length) else {
        return MapPlan::Refuse(errno::ENOMEM);
    };
    // File mappings need a filesystem capability and a translation from a
    // Linux fd to it -- Tier 1's work, refused here rather than half-done.
    if flags & flags::ANONYMOUS == 0 || fd >= 0 {
        return MapPlan::Refuse(errno::ENOSYS);
    }
    if flags & flags::PRIVATE == 0 {
        // Shared anonymous memory between Linux processes is a concept this
        // system has no counterpart for yet: a domain shares by capability.
        return MapPlan::Refuse(errno::ENOSYS);
    }
    if flags & flags::GROWSDOWN != 0 {
        return MapPlan::Refuse(errno::ENOSYS);
    }
    let write = protection & prot::WRITE != 0;
    let execute = protection & prot::EXEC != 0;
    // W^X is unrepresentable in the region map's `Protection`, so a request
    // for both is refused *here*, with the errno Linux uses when a mapping's
    // permissions are not allowed -- rather than silently granted one of the
    // two, which is the failure mode that would matter.
    if write && execute {
        return MapPlan::Refuse(errno::EACCES);
    }
    let fixed = flags & flags::FIXED != 0;
    if fixed && (addr == 0 || !addr.is_multiple_of(PAGE)) {
        return MapPlan::Refuse(errno::EINVAL);
    }
    MapPlan::Map {
        at: fixed.then_some(addr),
        pages,
        read: protection & prot::READ != 0,
        write,
        execute,
    }
}

/// What an `munmap(addr, length)` means: pages to remove, or a refusal.
pub fn plan_munmap(addr: u64, length: u64) -> Result<(u64, u64), i64> {
    if length == 0 || !addr.is_multiple_of(PAGE) {
        return Err(errno::EINVAL);
    }
    let pages = pages_for(length).ok_or(errno::EINVAL)?;
    Ok((addr, pages))
}

/// `madvise` is advice, and this kernel takes none of it — every hint Go
/// gives (`MADV_DONTNEED`, `MADV_FREE`, `MADV_HUGEPAGE`) is about page
/// reclaim policy that does not exist here yet. Answered `0` rather than
/// refused, because advice a kernel declines to follow is not an error, and
/// `-ENOSYS` here makes Go's allocator take a slower path for no reason.
#[must_use]
pub const fn plan_madvise() -> i64 {
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    const ANON_PRIVATE: u64 = flags::ANONYMOUS | flags::PRIVATE;

    #[test]
    fn an_ordinary_anonymous_mapping_is_planned() {
        let plan = plan_mmap(0, 8192, prot::READ | prot::WRITE, ANON_PRIVATE, -1);
        assert_eq!(
            plan,
            MapPlan::Map {
                at: None,
                pages: 2,
                read: true,
                write: true,
                execute: false,
            }
        );
    }

    #[test]
    fn a_length_rounds_up_and_an_overflow_is_refused_not_wrapped() {
        assert_eq!(pages_for(1), Some(1));
        assert_eq!(pages_for(4096), Some(1));
        assert_eq!(pages_for(4097), Some(2));
        assert_eq!(pages_for(u64::MAX), None, "no wrap");
        assert_eq!(
            plan_mmap(0, u64::MAX, prot::READ, ANON_PRIVATE, -1),
            MapPlan::Refuse(errno::ENOMEM)
        );
    }

    #[test]
    fn write_and_execute_together_is_refused_because_it_is_unrepresentable() {
        // The region map has no writable-executable protection, so this is a
        // refusal rather than a downgrade -- the downgrade is the dangerous
        // answer, because the caller would never learn which half it lost.
        assert_eq!(
            plan_mmap(
                0,
                4096,
                prot::READ | prot::WRITE | prot::EXEC,
                ANON_PRIVATE,
                -1
            ),
            MapPlan::Refuse(errno::EACCES)
        );
        // Either one alone is fine.
        assert!(matches!(
            plan_mmap(0, 4096, prot::READ | prot::EXEC, ANON_PRIVATE, -1),
            MapPlan::Map {
                execute: true,
                write: false,
                ..
            }
        ));
    }

    #[test]
    fn file_and_shared_mappings_are_refused_rather_than_half_done() {
        // A file mapping needs an fd translation Tier 1 has not built.
        assert_eq!(
            plan_mmap(0, 4096, prot::READ, flags::PRIVATE, 3),
            MapPlan::Refuse(errno::ENOSYS)
        );
        assert_eq!(
            plan_mmap(0, 4096, prot::READ, flags::PRIVATE, -1),
            MapPlan::Refuse(errno::ENOSYS),
            "not anonymous"
        );
        // Shared anonymous memory has no counterpart: a domain shares by
        // capability, not by a flag.
        assert_eq!(
            plan_mmap(0, 4096, prot::READ, flags::ANONYMOUS, -1),
            MapPlan::Refuse(errno::ENOSYS)
        );
    }

    #[test]
    fn a_fixed_mapping_must_name_a_page_aligned_address() {
        assert_eq!(
            plan_mmap(0x1001, 4096, prot::READ, ANON_PRIVATE | flags::FIXED, -1),
            MapPlan::Refuse(errno::EINVAL)
        );
        assert_eq!(
            plan_mmap(0, 4096, prot::READ, ANON_PRIVATE | flags::FIXED, -1),
            MapPlan::Refuse(errno::EINVAL)
        );
        assert_eq!(
            plan_mmap(0x2000, 4096, prot::READ, ANON_PRIVATE | flags::FIXED, -1),
            MapPlan::Map {
                at: Some(0x2000),
                pages: 1,
                read: true,
                write: false,
                execute: false,
            }
        );
    }

    #[test]
    fn noreserve_is_honoured_as_an_ordinary_lazy_mapping() {
        // Go asks for this constantly. This kernel commits on fault either
        // way, so the flag changes nothing -- and *that* is the answer, not
        // a refusal.
        assert!(matches!(
            plan_mmap(0, 4096, prot::READ, ANON_PRIVATE | flags::NORESERVE, -1),
            MapPlan::Map { .. }
        ));
    }

    #[test]
    fn munmap_is_planned_or_refused_with_a_reason() {
        assert_eq!(plan_munmap(0x2000, 8192), Ok((0x2000, 2)));
        assert_eq!(plan_munmap(0x2001, 4096), Err(errno::EINVAL), "unaligned");
        assert_eq!(plan_munmap(0x2000, 0), Err(errno::EINVAL), "empty");
    }

    #[test]
    fn madvise_is_advice_and_declining_it_is_not_an_error() {
        assert_eq!(plan_madvise(), 0);
    }
}
