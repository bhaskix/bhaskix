// SPDX-License-Identifier: Apache-2.0
//! Threads and futexes, as arithmetic.
//!
//! [RFC 0005](../../docs/rfc/0005-linux-abi-compatibility.md) step 6 and its
//! second and third "hard parts". Go creates its own OS threads with a very
//! specific `clone` flag set and parks its scheduler on `FUTEX_WAIT`; the RFC
//! is blunt about the failure mode of getting either subtly wrong — *"not an
//! error; a Go program that deadlocks under contention, occasionally, on a
//! machine with more cores than the one it was tested on."*
//!
//! What is decided here, and therefore host-tested: which `clone` flag set is
//! a thread of the current group (as against a request this personality
//! refuses), which futex operations are recognised, and how a thread id maps
//! onto a thread group. What the kernel does with those answers is the
//! kernel's.

/// `clone` flags, from Linux's `sched.h`.
pub mod clone {
    /// Share the address space.
    pub const VM: u64 = 0x0000_0100;
    /// Share the filesystem view.
    pub const FS: u64 = 0x0000_0200;
    /// Share the descriptor table.
    pub const FILES: u64 = 0x0000_0400;
    /// Share signal handlers.
    pub const SIGHAND: u64 = 0x0000_0800;
    /// Join the caller's thread group.
    pub const THREAD: u64 = 0x0001_0000;
    /// Share System V semaphore undo state.
    pub const SYSVSEM: u64 = 0x0004_0000;
    /// Set the new thread's TLS base from the argument.
    pub const SETTLS: u64 = 0x0008_0000;
    /// Write the new thread's id where the parent said.
    pub const PARENT_SETTID: u64 = 0x0010_0000;
    /// Clear the child's tid at this address on exit, and futex-wake it.
    pub const CHILD_CLEARTID: u64 = 0x0020_0000;
    /// A new process rather than a thread — refused: a Linux process maps
    /// onto a domain, and creating one is `START`'s business and its
    /// holder's authority, not a flag's.
    pub const NEWPID: u64 = 0x2000_0000;
}

/// The exact set Go's runtime passes to create an OS thread.
pub const GO_THREAD_FLAGS: u64 = clone::VM
    | clone::FS
    | clone::FILES
    | clone::SIGHAND
    | clone::THREAD
    | clone::SYSVSEM
    | clone::SETTLS;

/// What a `clone` request means to this personality.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ClonePlan {
    /// Create a thread in this thread group, sharing everything. `tls` is
    /// the base to install if the caller asked for one.
    Thread {
        /// The new thread's stack pointer.
        stack: u64,
        /// The TLS base, if `CLONE_SETTLS` was set.
        tls: Option<u64>,
        /// Where to write the new thread's id, if the parent asked.
        parent_tid: Option<u64>,
        /// Where the child's id is cleared and futex-woken on exit.
        child_tid: Option<u64>,
    },
    /// Refuse with this `errno`.
    Refuse(i64),
}

/// Decides what a `clone(flags, stack, parent_tid, child_tid, tls)` means.
///
/// The rule is deliberately narrow: **the flags must say "a thread of this
/// group, sharing everything"**, because that is the only shape this
/// personality can honour over a domain — and a partial share (a thread with
/// its own address space, say) is not something to approximate. Anything
/// else is `ENOSYS`, which is a refusal a runtime can see, rather than a
/// thread that shares less than it was promised.
#[must_use]
pub fn plan_clone(flags: u64, stack: u64, parent_tid: u64, child_tid: u64, tls: u64) -> ClonePlan {
    use crate::memory::errno;

    if flags & clone::NEWPID != 0 {
        return ClonePlan::Refuse(errno::ENOSYS);
    }
    // Every share Go asks for must be present. `CLONE_THREAD` without
    // `CLONE_VM` is a contradiction Linux itself rejects; the rest are what
    // make the new thread the same program.
    const REQUIRED: u64 =
        clone::VM | clone::FS | clone::FILES | clone::SIGHAND | clone::THREAD | clone::SYSVSEM;
    if flags & REQUIRED != REQUIRED {
        return ClonePlan::Refuse(errno::ENOSYS);
    }
    if stack == 0 {
        // A thread with no stack of its own would run on its creator's,
        // which is the deadlock nobody would find.
        return ClonePlan::Refuse(errno::EINVAL);
    }
    ClonePlan::Thread {
        stack,
        tls: (flags & clone::SETTLS != 0).then_some(tls),
        parent_tid: (flags & clone::PARENT_SETTID != 0).then_some(parent_tid),
        child_tid: (flags & clone::CHILD_CLEARTID != 0).then_some(child_tid),
    }
}

/// Futex operations, from Linux's `futex.h`.
pub mod futex {
    /// Sleep if the word still holds the expected value.
    pub const WAIT: u64 = 0;
    /// Wake up to `count` sleepers.
    pub const WAKE: u64 = 1;
    /// Private to this address space — Go always sets it, and it is the only
    /// kind this personality can honour: a shared futex would need a name
    /// for memory across domains, which is a capability, not an address.
    pub const PRIVATE: u64 = 128;
    /// Absolute rather than relative timeouts.
    pub const CLOCK_REALTIME: u64 = 256;
}

/// What a `futex` request means.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FutexPlan {
    /// Sleep on `address` while it holds `expected`.
    Wait {
        /// The word to watch.
        address: u64,
        /// The value that means "still worth sleeping".
        expected: u32,
    },
    /// Wake at most `count` sleepers on `address`.
    Wake {
        /// The word they slept on.
        address: u64,
        /// How many to wake.
        count: u32,
    },
    /// Refuse with this `errno`.
    Refuse(i64),
}

/// Decides what a `futex(uaddr, op, val, ...)` means.
#[must_use]
pub fn plan_futex(address: u64, operation: u64, value: u64) -> FutexPlan {
    use crate::memory::errno;

    // The flags come off first: `PRIVATE` is required (see its note), and a
    // realtime-clock timeout is honoured only in that it does not change
    // what the operation *is*.
    let bare = operation & !(futex::PRIVATE | futex::CLOCK_REALTIME);
    if operation & futex::PRIVATE == 0 {
        return FutexPlan::Refuse(errno::ENOSYS);
    }
    // A futex word is a `u32` and must be aligned: an unaligned one would
    // straddle nothing useful, and Linux refuses it too.
    if !address.is_multiple_of(4) || address == 0 {
        return FutexPlan::Refuse(errno::EINVAL);
    }
    match bare {
        futex::WAIT => FutexPlan::Wait {
            address,
            expected: value as u32,
        },
        futex::WAKE => FutexPlan::Wake {
            address,
            count: value as u32,
        },
        _ => FutexPlan::Refuse(errno::ENOSYS),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::errno;

    #[test]
    fn gos_own_flag_set_is_a_thread_of_this_group() {
        let plan = plan_clone(GO_THREAD_FLAGS, 0x7000, 0, 0, 0xf000);
        assert_eq!(
            plan,
            ClonePlan::Thread {
                stack: 0x7000,
                tls: Some(0xf000),
                parent_tid: None,
                child_tid: None,
            }
        );
    }

    #[test]
    fn the_tid_addresses_are_carried_only_when_asked_for() {
        let plan = plan_clone(
            GO_THREAD_FLAGS | clone::PARENT_SETTID | clone::CHILD_CLEARTID,
            0x7000,
            0x1000,
            0x2000,
            0xf000,
        );
        assert_eq!(
            plan,
            ClonePlan::Thread {
                stack: 0x7000,
                tls: Some(0xf000),
                parent_tid: Some(0x1000),
                child_tid: Some(0x2000),
            }
        );
        // And without the flags, the addresses are not carried -- which is
        // what stops a personality writing to a pointer nobody asked it to
        // write to. `GO_THREAD_FLAGS` carries SETTLS, so drop it here to
        // see all three absent.
        let bare = plan_clone(
            GO_THREAD_FLAGS & !clone::SETTLS,
            0x7000,
            0x1000,
            0x2000,
            0xf000,
        );
        assert_eq!(
            bare,
            ClonePlan::Thread {
                stack: 0x7000,
                tls: None,
                parent_tid: None,
                child_tid: None,
            }
        );
    }

    #[test]
    fn a_partial_share_is_refused_rather_than_approximated() {
        // A thread that does not share the address space is not a thread of
        // this program, and pretending otherwise is the bug that would not
        // show up until something wrote through a pointer.
        for missing in [
            clone::VM,
            clone::FS,
            clone::FILES,
            clone::SIGHAND,
            clone::THREAD,
        ] {
            assert_eq!(
                plan_clone(GO_THREAD_FLAGS & !missing, 0x7000, 0, 0, 0),
                ClonePlan::Refuse(errno::ENOSYS),
                "missing {missing:#x}"
            );
        }
    }

    #[test]
    fn a_new_process_is_refused_because_that_is_a_domain() {
        assert_eq!(
            plan_clone(GO_THREAD_FLAGS | clone::NEWPID, 0x7000, 0, 0, 0),
            ClonePlan::Refuse(errno::ENOSYS)
        );
    }

    #[test]
    fn a_thread_with_no_stack_is_refused() {
        assert_eq!(
            plan_clone(GO_THREAD_FLAGS, 0, 0, 0, 0),
            ClonePlan::Refuse(errno::EINVAL)
        );
    }

    #[test]
    fn the_two_futex_operations_go_uses_are_recognised_through_their_flags() {
        assert_eq!(
            plan_futex(0x4000, futex::WAIT | futex::PRIVATE, 7),
            FutexPlan::Wait {
                address: 0x4000,
                expected: 7
            }
        );
        assert_eq!(
            plan_futex(0x4000, futex::WAKE | futex::PRIVATE, 1),
            FutexPlan::Wake {
                address: 0x4000,
                count: 1
            }
        );
        // A realtime-clock timeout does not change what the operation is.
        assert_eq!(
            plan_futex(
                0x4000,
                futex::WAIT | futex::PRIVATE | futex::CLOCK_REALTIME,
                7
            ),
            FutexPlan::Wait {
                address: 0x4000,
                expected: 7
            }
        );
    }

    #[test]
    fn a_shared_futex_is_refused_because_sharing_here_is_a_capability() {
        assert_eq!(
            plan_futex(0x4000, futex::WAIT, 0),
            FutexPlan::Refuse(errno::ENOSYS)
        );
    }

    #[test]
    fn an_unaligned_or_null_futex_word_is_refused() {
        assert_eq!(
            plan_futex(0x4002, futex::WAIT | futex::PRIVATE, 0),
            FutexPlan::Refuse(errno::EINVAL)
        );
        assert_eq!(
            plan_futex(0, futex::WAIT | futex::PRIVATE, 0),
            FutexPlan::Refuse(errno::EINVAL)
        );
    }

    #[test]
    fn an_operation_this_does_not_know_is_refused_not_guessed() {
        for unknown in [2u64, 3, 5, 9, 13] {
            assert_eq!(
                plan_futex(0x4000, unknown | futex::PRIVATE, 0),
                FutexPlan::Refuse(errno::ENOSYS),
                "op {unknown}"
            );
        }
    }
}
