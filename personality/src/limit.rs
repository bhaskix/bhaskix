// SPDX-License-Identifier: Apache-2.0
//! `prlimit64` — [RFC 0086](../../docs/rfc/0086-the-motivating-workload.md)
//! step 5.
//!
//! **One resource is answered, and it is the one a limit here is true of.**
//! `RLIMIT_NOFILE` is [`crate::file::MAX_DESCRIPTORS`]: a process cannot hold
//! more descriptors than its table has rows, so that number is the limit, soft
//! and hard alike. Go's `syscall` package asks for it at start and raises the
//! soft limit to the hard one when they differ (go 1.27.1's
//! `syscall/rlimit.go`, read 2026-10-01); here they never differ, so it asks
//! nothing further.
//!
//! **A new limit is accepted only if it changes nothing.** Lowering it would be
//! a promise this adapter does not keep — nothing counts against a lower soft
//! limit — so it is refused `EPERM` rather than recorded and ignored. Every
//! other resource answers `ENOSYS`, which is what it answered before this step
//! and what Go tolerates: its `getrlimit` failure is ignored.

/// `RLIMIT_NOFILE`, from the build host's `bits/resource.h`.
pub const RLIMIT_NOFILE: u64 = 7;

/// Errnos, from the build host's `errno` headers.
pub mod errno {
    /// A limit this adapter will not set.
    pub const EPERM: i64 = -1;
    /// A resource it does not answer for.
    pub const ENOSYS: i64 = -38;
}

/// A `struct rlimit64`: the soft limit, then the hard.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Limit {
    /// `rlim_cur`.
    pub soft: u64,
    /// `rlim_max`.
    pub hard: u64,
}

impl Limit {
    /// The sixteen bytes a program reads.
    #[must_use]
    pub fn to_bytes(self) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[..8].copy_from_slice(&self.soft.to_le_bytes());
        out[8..].copy_from_slice(&self.hard.to_le_bytes());
        out
    }

    /// The sixteen bytes a program wrote.
    #[must_use]
    pub fn from_bytes(bytes: &[u8; 16]) -> Self {
        let mut soft = [0u8; 8];
        soft.copy_from_slice(&bytes[..8]);
        let mut hard = [0u8; 8];
        hard.copy_from_slice(&bytes[8..]);
        Self {
            soft: u64::from_le_bytes(soft),
            hard: u64::from_le_bytes(hard),
        }
    }
}

/// `prlimit64(pid, resource, new, old)` for the caller itself: the limit to
/// report as `old`, having checked `new` if one was given.
///
/// # Errors
///
/// `ENOSYS` for a resource not answered here; `EPERM` for a new limit that
/// would change the one answered.
pub fn plan(resource: u64, new: Option<Limit>) -> Result<Limit, i64> {
    if resource != RLIMIT_NOFILE {
        return Err(errno::ENOSYS);
    }
    let limit = Limit {
        soft: crate::file::MAX_DESCRIPTORS as u64,
        hard: crate::file::MAX_DESCRIPTORS as u64,
    };
    match new {
        Some(asked) if asked != limit => Err(errno::EPERM),
        _ => Ok(limit),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_descriptor_limit_is_the_table_both_ways() {
        let limit = plan(RLIMIT_NOFILE, None).expect("answered");
        assert_eq!(limit.soft, crate::file::MAX_DESCRIPTORS as u64);
        assert_eq!(limit.soft, limit.hard, "so Go asks nothing further");
        assert_eq!(Limit::from_bytes(&limit.to_bytes()), limit);
    }

    #[test]
    fn setting_it_to_itself_is_fine_and_changing_it_is_refused() {
        let limit = plan(RLIMIT_NOFILE, None).expect("answered");
        assert_eq!(plan(RLIMIT_NOFILE, Some(limit)), Ok(limit));
        let lower = Limit { soft: 8, ..limit };
        assert_eq!(plan(RLIMIT_NOFILE, Some(lower)), Err(errno::EPERM));
    }

    #[test]
    fn other_resources_are_not_answered() {
        assert_eq!(plan(3, None), Err(errno::ENOSYS)); // RLIMIT_STACK
    }
}
