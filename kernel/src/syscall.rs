// SPDX-License-Identifier: Apache-2.0
//! System-call dispatch.
//!
//! Implements the kernel half of [RFC 0008]. The machine half — the `SYSCALL`
//! entry stub, the MSRs, the stack switch — is `bhaskix_arch::syscall`.
//!
//! [RFC 0008]: ../../../docs/rfc/0008-syscall-and-ipc-shape.md
//!
//! # There are six system calls, and adding a seventh is an RFC
//!
//! Not a table of hundreds. Every operation on an object is [`Kind::Invoke`]
//! with a capability naming the object, so the set of things a domain can *do*
//! grows with the objects it holds rather than with this enum.
//!
//! # Authority is the argument, so there is no permission check
//!
//! A conventional kernel's syscall handler looks up a resource by name and
//! then asks whether the caller is allowed it. Both halves are places to get
//! it wrong: the lookup can race the check, and the check can be forgotten.
//!
//! Here the caller passes an *index into its own CSpace*, and that index is
//! either a capability it was given or it is nothing. There is no name to
//! resolve, so nothing to race; and no separate authorisation step, so nothing
//! to omit. The failure mode of forgetting a check is not a vulnerability, it
//! is a compile error where the capability should have been.
//!
//! What remains, and what this module is mostly made of, is **type checking**:
//! a capability naming a thread must not be usable where an endpoint is
//! expected, and the kind travels in the capability precisely so that can be
//! rejected before anything is dereferenced.
//!
//! # Not yet
//!
//! - **Nothing is invokable.** [`Kind::Invoke`] resolves the capability, type
//!   checks it, and returns [`Status::NotImplemented`], because no object has
//!   methods yet. The resolution is the security-critical half and it is real.
//! - **No IPC.** `Call`, `Reply` and `Recv` need endpoints, which are M5-05.
//! - **No caller.** Nothing runs in ring 3 until M5-04, so the assembly entry
//!   path is unexercised. The dispatcher below is reached directly by tests.

use crate::cap::{Arena, CSpace, ObjectKind, SlotRef};
use crate::{cap, domain, sched};

pub use bhaskix_arch::syscall::SyscallFrame;

/// The six system calls.
///
/// Encoded rather than derived, so that an unrecognised value is a rejected
/// number and never an index into anything.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    /// Perform a method on the object a capability names.
    Invoke = 0,
    /// Invoke, then block for a reply.
    Call = 1,
    /// Answer a `Call`, consuming the reply capability.
    Reply = 2,
    /// Block until a message arrives on an endpoint.
    Recv = 3,
    /// Give up the rest of this thread's slice.
    Yield = 4,
    /// Terminate this thread.
    Exit = 5,
}

impl Kind {
    /// Decodes a raw value.
    ///
    /// Returns `None` rather than a default: a syscall number the kernel does
    /// not recognise is a caller error, and quietly treating it as something
    /// else is how a fuzzer finds a path nobody meant to expose.
    #[must_use]
    pub const fn from_raw(value: u64) -> Option<Self> {
        match value {
            0 => Some(Self::Invoke),
            1 => Some(Self::Call),
            2 => Some(Self::Reply),
            3 => Some(Self::Recv),
            4 => Some(Self::Yield),
            5 => Some(Self::Exit),
            _ => None,
        }
    }
}

/// What a system call returns in `rax`.
///
/// Zero is success, so a caller can branch on the sign or on zero without a
/// table. Everything else is a distinct, stable number — an error code that
/// changes meaning between builds is worse than one that is vague.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u64)]
pub enum Status {
    /// The call succeeded.
    Ok = 0,
    /// The syscall number is not one of the six.
    BadSyscall = 1,
    /// The capability index named nothing in this domain's CSpace.
    NoSuchCapability = 2,
    /// The capability was revoked, or its slot has been reused.
    Revoked = 3,
    /// The capability names the wrong kind of object for this operation.
    WrongObject = 4,
    /// The capability does not carry the rights this operation needs.
    InsufficientRights = 5,
    /// The operation is defined but not built yet.
    NotImplemented = 6,
    /// The calling thread belongs to no domain, so it has no CSpace.
    NoDomain = 7,
}

impl Status {
    /// The value returned in `rax`.
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self as u64
    }
}

/// What a dispatched system call produced.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Outcome {
    /// Returned in `rax`.
    pub status: Status,
    /// Returned in `rdx`.
    pub value: u64,
}

impl Outcome {
    /// A successful call returning `value`.
    #[must_use]
    pub const fn ok(value: u64) -> Self {
        Self {
            status: Status::Ok,
            value,
        }
    }

    /// A failed call.
    #[must_use]
    pub const fn err(status: Status) -> Self {
        Self { status, value: 0 }
    }
}

/// Resolves a capability index against a CSpace and the arena.
///
/// The two failure modes are kept distinct on purpose. "You never had one"
/// and "you had one and it was revoked" are different facts about the world,
/// and collapsing them makes a revocation bug indistinguishable from a caller
/// bug — which is exactly the confusion a security review cannot afford.
fn resolve(cspace: &CSpace, arena: &Arena, index: u64) -> Result<(SlotRef, ObjectKind), Status> {
    let index = usize::try_from(index).map_err(|_| Status::NoSuchCapability)?;
    let slot = cspace.get(index).ok_or(Status::NoSuchCapability)?;
    let (object, _) = arena.lookup(slot).ok_or(Status::Revoked)?;
    Ok((slot, object.kind))
}

/// Dispatches one system call against an explicit CSpace and arena.
///
/// Separated from [`dispatch`] so that every decision here can be tested on
/// the host against tables a test constructs, rather than only against
/// whatever the running system happens to hold.
pub fn dispatch_with(frame: &mut SyscallFrame, cspace: &CSpace, arena: &Arena) -> Outcome {
    let Some(kind) = Kind::from_raw(frame.kind) else {
        return Outcome::err(Status::BadSyscall);
    };

    match kind {
        // Neither takes a capability: they are the two things a thread does to
        // itself, and every thread may always do them. Routing them through a
        // capability would mean every thread holding one to itself, in every
        // CSpace, for no gain in expressiveness.
        Kind::Yield => {
            sched::yield_now();
            Outcome::ok(0)
        }
        Kind::Exit => sched::exit(),

        Kind::Invoke => match resolve(cspace, arena, frame.capability) {
            // The type check that replaces a permission check. A capability
            // naming a thread is not usable where an endpoint is expected,
            // and the kind travels *in* the capability so this can be decided
            // before anything is dereferenced.
            Ok((_, ObjectKind::Reply)) => Outcome::err(Status::WrongObject),
            Ok((_, _)) => Outcome::err(Status::NotImplemented),
            Err(status) => Outcome::err(status),
        },

        Kind::Call | Kind::Reply | Kind::Recv => {
            let expected = match kind {
                Kind::Reply => ObjectKind::Reply,
                _ => ObjectKind::Endpoint,
            };
            match resolve(cspace, arena, frame.capability) {
                Ok((_, actual)) if actual != expected => Outcome::err(Status::WrongObject),
                Ok(_) => Outcome::err(Status::NotImplemented),
                Err(status) => Outcome::err(status),
            }
        }
    }
}

/// Dispatches one system call for the calling thread.
///
/// Finds the caller's CSpace from the domain its thread belongs to. A thread
/// with no domain has no CSpace and therefore no authority at all, which is
/// the correct answer rather than an oversight — kernel threads created before
/// domains existed must not inherit the ability to name objects.
pub fn dispatch(frame: &mut SyscallFrame) -> Outcome {
    // `Yield` and `Exit` need no CSpace, and requiring one would make them
    // unavailable to exactly the threads most likely to want to exit.
    if matches!(
        Kind::from_raw(frame.kind),
        Some(Kind::Yield) | Some(Kind::Exit)
    ) {
        let empty = CSpace::new();
        return cap::with_arena(|arena| dispatch_with(frame, &empty, arena));
    }

    let Some(id) = sched::current_domain() else {
        return Outcome::err(Status::NoDomain);
    };

    // The domain table, then the arena: the order `sync::Rank` declares, and
    // the same order `domain::destroy` uses.
    let Some(outcome) = domain::with(id, |owner| {
        // The CSpace is moved out and back rather than borrowed across the
        // arena lock, because holding a borrow of the domain table while
        // taking the capability arena would nest the two locks in a way
        // nothing else does.
        let cspace = core::mem::take(&mut owner.cspace);
        let outcome = cap::with_arena(|arena| dispatch_with(frame, &cspace, arena));
        owner.cspace = cspace;
        outcome
    }) else {
        return Outcome::err(Status::NoDomain);
    };

    outcome
}

/// The entry point the assembly stub calls.
///
/// # Safety
///
/// `frame` must point at a [`SyscallFrame`] the stub built on the kernel
/// stack, which no other code can reach.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bhaskix_syscall_dispatch(frame: *mut SyscallFrame) {
    // SAFETY: the caller guarantees the pointer, and the frame lives on this
    // CPU's kernel stack for the duration of the call.
    let frame = unsafe { &mut *frame };
    let outcome = dispatch(frame);

    // The results go back through the same two registers the ABI names, which
    // the stub pops into `rax` and `rdx`.
    frame.kind = outcome.status.as_u64();
    frame.arg0 = outcome.value;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cap::{ObjectRef, Rights};

    fn frame(kind: u64, capability: u64) -> SyscallFrame {
        SyscallFrame {
            kind,
            capability,
            ..SyscallFrame::default()
        }
    }

    #[test]
    fn every_syscall_number_outside_the_six_is_refused() {
        // A number the kernel does not recognise must be a rejected value, not
        // an index into anything. Checked over a range wide enough to include
        // the obvious probes -- one past the end, and the sign boundaries.
        for raw in [6u64, 7, 63, 64, 255, 256, 1 << 31, 1 << 63, u64::MAX] {
            assert_eq!(Kind::from_raw(raw), None, "{raw} decoded to something");
            let mut f = frame(raw, 0);
            let arena = Arena::new();
            assert_eq!(
                dispatch_with(&mut f, &CSpace::new(), &arena).status,
                Status::BadSyscall
            );
        }
    }

    #[test]
    fn the_six_syscall_numbers_decode_to_themselves() {
        for (raw, expected) in [
            (0, Kind::Invoke),
            (1, Kind::Call),
            (2, Kind::Reply),
            (3, Kind::Recv),
            (4, Kind::Yield),
            (5, Kind::Exit),
        ] {
            assert_eq!(Kind::from_raw(raw), Some(expected));
        }
    }

    #[test]
    fn an_index_the_domain_was_never_given_names_nothing() {
        // The whole of rule 1, seen from the syscall side: guessing an index
        // gains nothing because an index is not authority.
        let arena = Arena::new();
        let empty = CSpace::new();
        for index in [0u64, 1, 63, 64, u64::MAX] {
            let mut f = frame(Kind::Invoke as u64, index);
            assert_eq!(
                dispatch_with(&mut f, &empty, &arena).status,
                Status::NoSuchCapability
            );
        }
    }

    #[test]
    fn a_revoked_capability_is_distinguishable_from_one_never_held() {
        // Collapsing these two makes a revocation bug look like a caller bug.
        let mut arena = Arena::new();
        let cap = arena
            .insert_root(ObjectRef::new(ObjectKind::Endpoint, 1), Rights::ALL, 0)
            .unwrap();
        let mut cspace = CSpace::new();
        cspace.install(cap).unwrap();

        let mut f = frame(Kind::Call as u64, 0);
        assert_eq!(
            dispatch_with(&mut f, &cspace, &arena).status,
            Status::NotImplemented,
            "a live endpoint reaches the unimplemented body"
        );

        arena.revoke(cap).unwrap();
        let mut f = frame(Kind::Call as u64, 0);
        assert_eq!(
            dispatch_with(&mut f, &cspace, &arena).status,
            Status::Revoked,
            "the slot is still occupied, but the capability is dead"
        );
    }

    #[test]
    fn a_capability_of_the_wrong_kind_is_refused_before_anything_is_used() {
        // The type check that stands in for a permission check. A thread
        // capability must not be usable as an endpoint however valid it is.
        let mut arena = Arena::new();
        let thread = arena
            .insert_root(ObjectRef::new(ObjectKind::Thread, 3), Rights::ALL, 0)
            .unwrap();
        let mut cspace = CSpace::new();
        cspace.install(thread).unwrap();

        for kind in [Kind::Call, Kind::Recv, Kind::Reply] {
            let mut f = frame(kind as u64, 0);
            assert_eq!(
                dispatch_with(&mut f, &cspace, &arena).status,
                Status::WrongObject,
                "{kind:?} accepted a thread capability"
            );
        }
    }

    #[test]
    fn reply_demands_a_reply_capability_and_nothing_else() {
        let mut arena = Arena::new();
        let endpoint = arena
            .insert_root(ObjectRef::new(ObjectKind::Endpoint, 1), Rights::ALL, 0)
            .unwrap();
        let reply = arena
            .insert_root(ObjectRef::new(ObjectKind::Reply, 2), Rights::ALL, 0)
            .unwrap();
        let mut cspace = CSpace::new();
        cspace.install(endpoint).unwrap();
        cspace.install(reply).unwrap();

        let mut f = frame(Kind::Reply as u64, 0);
        assert_eq!(
            dispatch_with(&mut f, &cspace, &arena).status,
            Status::WrongObject,
            "an endpoint is not a reply"
        );

        let mut f = frame(Kind::Reply as u64, 1);
        assert_eq!(
            dispatch_with(&mut f, &cspace, &arena).status,
            Status::NotImplemented
        );
    }

    #[test]
    fn a_reply_capability_cannot_be_invoked_directly() {
        // It is a one-shot right to answer a call, not an object with methods.
        let mut arena = Arena::new();
        let reply = arena
            .insert_root(ObjectRef::new(ObjectKind::Reply, 2), Rights::ALL, 0)
            .unwrap();
        let mut cspace = CSpace::new();
        cspace.install(reply).unwrap();

        let mut f = frame(Kind::Invoke as u64, 0);
        assert_eq!(
            dispatch_with(&mut f, &cspace, &arena).status,
            Status::WrongObject
        );
    }

    #[test]
    fn a_status_code_is_a_stable_number() {
        // Callers branch on these. Renumbering them between builds would be a
        // silent ABI break, so the values are asserted rather than assumed.
        assert_eq!(Status::Ok.as_u64(), 0);
        assert_eq!(Status::BadSyscall.as_u64(), 1);
        assert_eq!(Status::NoSuchCapability.as_u64(), 2);
        assert_eq!(Status::Revoked.as_u64(), 3);
        assert_eq!(Status::WrongObject.as_u64(), 4);
        assert_eq!(Status::InsufficientRights.as_u64(), 5);
        assert_eq!(Status::NotImplemented.as_u64(), 6);
        assert_eq!(Status::NoDomain.as_u64(), 7);
    }
}
