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

use core::sync::atomic::{AtomicU64, Ordering};

use crate::cap::{Arena, CSpace, ObjectKind, SlotRef};
use crate::{cap, domain, sched};

/// System calls dispatched.
static CALLS: AtomicU64 = AtomicU64::new(0);

/// Calls whose number was not one of the six.
static REFUSED: AtomicU64 = AtomicU64::new(0);

/// The user `RIP` of the most recent call, as `SYSCALL` left it in `rcx`.
static LAST_RIP: AtomicU64 = AtomicU64::new(0);

/// The user `RSP` of the most recent call.
static LAST_RSP: AtomicU64 = AtomicU64::new(0);

/// Calls refused because the capability they named had been revoked.
///
/// Counted separately from every other failure because it is the observable
/// consequence of revocation, and a test needs to see authority *stop*
/// working rather than merely never having worked.
static REVOKED_CALLS: AtomicU64 = AtomicU64::new(0);

/// `(calls, refused, revoked)` since boot.
#[must_use]
pub fn statistics() -> (u64, u64, u64) {
    (
        CALLS.load(Ordering::Relaxed),
        REFUSED.load(Ordering::Relaxed),
        REVOKED_CALLS.load(Ordering::Relaxed),
    )
}

/// The user `RIP` and `RSP` most recently seen entering the kernel.
///
/// Evidence rather than decoration: a system call that genuinely came from
/// ring 3 arrives with a return address inside the user program and a stack
/// pointer inside the user stack. A test can then assert that the kernel was
/// entered from user memory rather than from somewhere in itself, which is the
/// difference between "ring 3 works" and "a function was called".
#[must_use]
pub fn last_user_context() -> (u64, u64) {
    (
        LAST_RIP.load(Ordering::Relaxed),
        LAST_RSP.load(Ordering::Relaxed),
    )
}

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

// The six numbers are also written down in `bhaskix_abi`, which unprivileged
// programs compile against. Two definitions of a system call number is exactly
// the kind of duplication that drifts, so it does not get to: these assertions
// fail the build rather than a message.
const _: () = {
    assert!(Kind::Invoke as u64 == bhaskix_abi::syscall::INVOKE);
    assert!(Kind::Call as u64 == bhaskix_abi::syscall::CALL);
    assert!(Kind::Reply as u64 == bhaskix_abi::syscall::REPLY);
    assert!(Kind::Recv as u64 == bhaskix_abi::syscall::RECV);
    assert!(Kind::Yield as u64 == bhaskix_abi::syscall::YIELD);
    assert!(Kind::Exit as u64 == bhaskix_abi::syscall::EXIT);
    assert!(Status::Ok as u64 == bhaskix_abi::status::OK);
    assert!(Status::NoSuchCapability as u64 == bhaskix_abi::status::NO_SUCH_CAPABILITY);
    assert!(Status::Revoked as u64 == bhaskix_abi::status::REVOKED);
    assert!(Status::NoSuchMethod as u64 == bhaskix_abi::status::NO_SUCH_METHOD);
};

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

/// Methods every capability answers, whatever it names.
///
/// These are the delegation primitives, and they are `Invoke` methods rather
/// than syscall kinds on purpose. [RFC 0008] fixes the syscall set at six and
/// says adding a seventh should feel like an architectural change; granting
/// authority is not one. It is an operation *on a capability*, which is
/// exactly what `Invoke` is for — and routing it through a capability means a
/// domain can only delegate what it was itself given.
pub mod method {
    /// Create a weaker capability from this one, in the caller's own CSpace.
    ///
    /// `arg0` = rights mask, `arg1` = badge, `arg2` = destination slot.
    pub const DERIVE: u64 = 0;
    /// Revoke this capability and everything derived from it.
    pub const REVOKE: u64 = 1;
    /// Drop this capability from the caller's CSpace without revoking it.
    ///
    /// Distinct from revoking, and the difference matters: other domains may
    /// legitimately hold the same capability, and dropping your copy must not
    /// take theirs.
    pub const DELETE: u64 = 2;
    /// Give a derived capability to the domain this capability names.
    ///
    /// Only on a `Domain` capability. `arg0` = the caller's slot to derive
    /// from, `arg1` = rights, `arg2` = badge, `arg3` = slot in the recipient.
    pub const GRANT: u64 = 16;
    /// Map a `Memory` object into this `DmaWindow`, and return a `DevAddr`.
    ///
    /// Only on a `DmaWindow` capability. `arg0` = the caller's slot holding
    /// the `Memory` capability, `arg1` = rights for the device. RFC 0012.
    pub const MAP: u64 = 32;
    /// Remove a mapping made by [`MAP`], invalidating before returning.
    ///
    /// `arg0` = the `DevAddr`, `arg1` = pages.
    pub const UNMAP: u64 = 33;
    /// How many pages this window has mapped.
    pub const INFO: u64 = 34;
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
    /// The endpoint's queue is full in the direction this call needs.
    Congested = 8,
    /// The reply names a caller that is no longer waiting.
    NoSuchCaller = 9,
    /// The object does not answer that method.
    NoSuchMethod = 10,
    /// The destination slot is occupied or out of range.
    SlotUnavailable = 11,
    /// The domain's capability quota is full.
    QuotaExceeded = 12,
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
/// Returns an [`Outcome`] and performs no scheduling: `Yield` and `Exit` never
/// reach here, because they are decided before any lock is taken. See
/// [`dispatch`].
///
/// Separated from [`dispatch`] so that every decision here can be tested on
/// the host against tables a test constructs, rather than only against
/// whatever the running system happens to hold.
pub fn dispatch_with(frame: &mut SyscallFrame, cspace: &CSpace, arena: &Arena) -> Outcome {
    let Some(kind) = Kind::from_raw(frame.kind) else {
        return Outcome::err(Status::BadSyscall);
    };

    match kind {
        // Handled by `dispatch` before it takes anything. Reaching here would
        // mean a caller had bypassed that, so it is an error rather than a
        // second implementation that could drift from the first.
        Kind::Yield | Kind::Exit => Outcome::err(Status::BadSyscall),

        // `Invoke` is handled in `dispatch`, which has the mutable CSpace and
        // arena these methods rearrange. Reaching here means a caller went
        // round that, so it is an error rather than a second implementation.
        Kind::Invoke => match resolve(cspace, arena, frame.capability) {
            Ok((_, ObjectKind::Reply)) => Outcome::err(Status::WrongObject),
            // A `DmaWindow` method runs unlocked -- see `resolve_window`.
            Ok((_, ObjectKind::DmaWindow)) => Outcome::err(Status::NotImplemented),
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
                // Resolved and type-checked. The operation itself happens in
                // `dispatch`, after every lock is released, because it blocks
                // — see `Resolved`.
                Ok(_) => Outcome::err(Status::NotImplemented),
                Err(status) => Outcome::err(status),
            }
        }
    }
}

/// Performs an `Invoke` on the caller's own CSpace.
///
/// Runs with the domain table and the capability arena both held, which is
/// safe only because none of these methods block: they rearrange authority
/// and return. The moment one of them needs to wait, it must move out here
/// the way the IPC calls did.
fn invoke_capability(
    frame: &SyscallFrame,
    owner: u32,
    cspace: &mut CSpace,
    arena: &mut Arena,
) -> Outcome {
    let index = match usize::try_from(frame.capability) {
        Ok(index) => index,
        Err(_) => return Outcome::err(Status::NoSuchCapability),
    };
    let Some(slot) = cspace.get(index) else {
        return Outcome::err(Status::NoSuchCapability);
    };
    let Some((object, _)) = arena.lookup(slot) else {
        return Outcome::err(Status::Revoked);
    };

    match frame.method {
        method::DERIVE => {
            let rights = crate::cap::Rights::from_bits(frame.arg0 as u8);
            let destination = match usize::try_from(frame.arg2) {
                Ok(destination) => destination,
                Err(_) => return Outcome::err(Status::SlotUnavailable),
            };

            // Derive first, install second. If the slot is unavailable the
            // capability would otherwise exist with nothing referring to it —
            // charged to the domain and unreachable by it, which is a leak
            // that only a reboot clears.
            if cspace.get(destination).is_some() {
                return Outcome::err(Status::SlotUnavailable);
            }

            match arena.derive_owned(slot, rights, frame.arg1, owner) {
                Ok(derived) => match cspace.install_at(destination, derived) {
                    Ok(()) => Outcome::ok(frame.arg2),
                    Err(_) => {
                        arena.revoke_unchecked(derived);
                        Outcome::err(Status::SlotUnavailable)
                    }
                },
                Err(crate::cap::CapError::RightsNotMonotone) => {
                    Outcome::err(Status::InsufficientRights)
                }
                Err(crate::cap::CapError::DeriveNotPermitted) => {
                    Outcome::err(Status::InsufficientRights)
                }
                Err(_) => Outcome::err(Status::QuotaExceeded),
            }
        }

        method::REVOKE => {
            let mut tally = [0u32; crate::cap::MAX_OWNERS];
            match arena.revoke_tallied(slot, &mut tally) {
                Ok(destroyed) => {
                    // The revoked capability's own slot is now a dead
                    // reference. Clearing it is not required for safety --
                    // resolving it fails -- but leaving it occupies a slot the
                    // domain can never use again.
                    cspace.remove(index);
                    Outcome {
                        status: Status::Ok,
                        value: destroyed as u64,
                    }
                }
                Err(crate::cap::CapError::RevokeNotPermitted) => {
                    Outcome::err(Status::InsufficientRights)
                }
                Err(_) => Outcome::err(Status::NoSuchCapability),
            }
        }

        method::DELETE => {
            cspace.remove(index);
            Outcome::ok(0)
        }

        method::GRANT if object.kind == crate::cap::ObjectKind::Domain => {
            // Handled by the caller: it needs the *recipient's* CSpace, and
            // two domains' tables cannot be held at once.
            Outcome::err(Status::NotImplemented)
        }

        _ => Outcome::err(Status::NoSuchMethod),
    }
}

/// What a `DmaWindow` invocation resolved to, with every lock released.
///
/// The same shape as [`resolve_for_ipc`] and for the same reason: mapping a
/// page into a device's window may have to allocate a level of its page
/// tables, and allocating takes the heap — which ranks *outside* the
/// capability arena this method was resolved under. Doing the work here would
/// be an inversion on every map.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct ResolvedWindow {
    /// The `Memory` object to map, for `MAP`.
    memory: Option<crate::shared::MemoryId>,
    /// What the device may do, already narrowed by both capabilities' rights.
    rights: bhaskix_arch::vtd::Rights,
}

/// Resolves a `DmaWindow` method against the caller's own capabilities.
///
/// **Both** capabilities are checked: the window, and the memory being mapped
/// into it. Holding one without the other is not enough, and that is the whole
/// of the delegation story — a domain may hand a device only memory it already
/// holds, and only into a window it was given.
fn resolve_window(frame: &SyscallFrame) -> Result<ResolvedWindow, Status> {
    let Some(id) = sched::current_domain() else {
        return Err(Status::NoDomain);
    };

    let outcome = domain::with(id, |owner| {
        let cspace = core::mem::take(&mut owner.cspace);
        let result = cap::with_arena(|arena| {
            let index = usize::try_from(frame.capability).map_err(|_| Status::NoSuchCapability)?;
            let slot = cspace.get(index).ok_or(Status::NoSuchCapability)?;
            let (window, window_rights) = arena.lookup(slot).ok_or(Status::Revoked)?;
            if window.kind != ObjectKind::DmaWindow {
                return Err(Status::WrongObject);
            }

            if frame.method != crate::syscall::method::MAP {
                return Ok(ResolvedWindow {
                    memory: None,
                    rights: bhaskix_arch::vtd::Rights::READ,
                });
            }

            let memory_index = usize::try_from(frame.arg0).map_err(|_| Status::NoSuchCapability)?;
            let memory_slot = cspace.get(memory_index).ok_or(Status::NoSuchCapability)?;
            let (memory, memory_rights) = arena.lookup(memory_slot).ok_or(Status::Revoked)?;
            if memory.kind != ObjectKind::Memory {
                return Err(Status::WrongObject);
            }

            // A device may do what *both* capabilities allow and no more.
            // Narrowing to the weaker of the two is what stops a read-only
            // share becoming a writable one by being handed to a device.
            let write = window_rights.contains(crate::cap::Rights::WRITE)
                && memory_rights.contains(crate::cap::Rights::WRITE);
            if !window_rights.contains(crate::cap::Rights::READ)
                || !memory_rights.contains(crate::cap::Rights::READ)
            {
                return Err(Status::InsufficientRights);
            }

            Ok(ResolvedWindow {
                memory: Some(crate::shared::MemoryId::from_u64(memory.id)),
                rights: bhaskix_arch::vtd::Rights { read: true, write },
            })
        });
        owner.cspace = cspace;
        result
    });

    outcome.unwrap_or(Err(Status::NoDomain))
}

/// What a capability resolved to, for an operation that must run unlocked.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Resolved {
    object: crate::cap::ObjectRef,
    badge: u64,
}

/// Resolves the capability an IPC syscall names, and its badge.
///
/// Returns with every lock released. That is the point: `Call`, `Recv` and
/// `Reply` all block, and blocking while holding the capability arena is how
/// M5-04's `Exit` deadlocked the machine. The lesson generalises — resolve,
/// let go, then act.
fn resolve_for_ipc(index: u64, expected: ObjectKind) -> Result<Resolved, Status> {
    let Some(id) = sched::current_domain() else {
        return Err(Status::NoDomain);
    };

    let outcome = domain::with(id, |owner| {
        let cspace = core::mem::take(&mut owner.cspace);
        let result = cap::with_arena(|arena| {
            let index = usize::try_from(index).map_err(|_| Status::NoSuchCapability)?;
            let slot = cspace.get(index).ok_or(Status::NoSuchCapability)?;
            let (object, _) = arena.lookup(slot).ok_or(Status::Revoked)?;
            if object.kind != expected {
                return Err(Status::WrongObject);
            }
            let badge = arena.badge_of(slot).unwrap_or(0);
            Ok(Resolved { object, badge })
        });
        owner.cspace = cspace;
        result
    });

    outcome.unwrap_or(Err(Status::NoDomain))
}

/// Maps an IPC failure onto a status code.
const fn ipc_status(error: crate::ipc::IpcError) -> Status {
    match error {
        crate::ipc::IpcError::NoSuchEndpoint | crate::ipc::IpcError::Exhausted => {
            Status::NoSuchCapability
        }
        crate::ipc::IpcError::Congested => Status::Congested,
        crate::ipc::IpcError::NoSuchCaller => Status::NoSuchCaller,
    }
}

/// Dispatches one system call for the calling thread.
///
/// Finds the caller's CSpace from the domain its thread belongs to. A thread
/// with no domain has no CSpace and therefore no authority at all, which is
/// the correct answer rather than an oversight — kernel threads created before
/// domains existed must not inherit the ability to name objects.
pub fn dispatch(frame: &mut SyscallFrame) -> Outcome {
    let outcome = dispatch_inner(frame);
    if outcome.status == Status::Revoked {
        REVOKED_CALLS.fetch_add(1, Ordering::Relaxed);
    }
    outcome
}

fn dispatch_inner(frame: &mut SyscallFrame) -> Outcome {
    // Counted before anything can divert: `Exit` never returns, so a counter
    // incremented afterwards would miss exactly the call that ends the thread.
    CALLS.fetch_add(1, Ordering::Relaxed);
    let kind = Kind::from_raw(frame.kind);
    if kind.is_none() {
        REFUSED.fetch_add(1, Ordering::Relaxed);
    }
    LAST_RIP.store(frame.rip, Ordering::Relaxed);
    LAST_RSP.store(frame.user_rsp, Ordering::Relaxed);

    // `Yield` and `Exit` are handled here, before a single lock is taken, and
    // that ordering is not tidiness.
    //
    // `Exit` never returns. Dispatching it with a lock held leaves that lock
    // held for ever — and because M4-08 refuses to preempt a thread holding
    // one, the thread then spins in `exit` instead of leaving, so the lock is
    // never released by anything. The whole system stops at the next attempt
    // to take it.
    //
    // That is exactly what happened: `Exit` was dispatched inside the
    // capability arena's lock and the next `cap::live()` hung. The rank
    // machinery turned a corruption into a visible stall, which is what it is
    // for, but the fix is to take no lock at all on a path that may not
    // return.
    match kind {
        Some(Kind::Yield) => {
            sched::yield_now();
            return Outcome::ok(0);
        }
        Some(Kind::Exit) => sched::exit(),
        None => return Outcome::err(Status::BadSyscall),
        Some(_) => {}
    }

    // A `DmaWindow` method, which does not block but must not run locked: a
    // map may allocate a page-table level, and allocating takes the heap,
    // which ranks outside the capability arena the method was resolved under.
    if kind == Some(Kind::Invoke)
        && matches!(frame.method, method::MAP | method::UNMAP | method::INFO)
    {
        let resolved = match resolve_window(frame) {
            Ok(resolved) => resolved,
            Err(status) => return Outcome::err(status),
        };
        let hhdm = crate::shared::hhdm();
        return match frame.method {
            method::MAP => match resolved.memory {
                Some(memory) => {
                    match crate::iommu::map_memory(memory, resolved.rights, false, hhdm) {
                        Some(address) => Outcome::ok(address.as_u64()),
                        // No window, no room, or the object has gone. All
                        // refusals: a caller told an address for a mapping
                        // that did not happen would hand a device a number
                        // pointing at whatever is there.
                        None => Outcome::err(Status::NoSuchCapability),
                    }
                }
                None => Outcome::err(Status::WrongObject),
            },
            method::UNMAP => {
                if crate::iommu::unmap_device(frame.arg0, frame.arg1) {
                    Outcome::ok(0)
                } else {
                    Outcome::err(Status::NoSuchCapability)
                }
            }
            _ => Outcome::ok(crate::iommu::mapped_pages()),
        };
    }

    // The three that block. Each resolves its capability with the locks held,
    // releases them, and only then performs an operation that may not return
    // for a long time.
    match kind {
        Some(Kind::Call) => {
            let resolved = match resolve_for_ipc(frame.capability, ObjectKind::Endpoint) {
                Ok(resolved) => resolved,
                Err(status) => return Outcome::err(status),
            };
            let endpoint = crate::ipc::EndpointId::from_u32(resolved.object.id as u32);
            // The badge comes from the capability, never from the frame. A
            // caller that could set it could claim to be anyone.
            match crate::ipc::call(
                endpoint,
                resolved.badge,
                frame.method,
                [frame.arg0, frame.arg1, frame.arg2, frame.arg3],
            ) {
                Ok(reply) => {
                    // The whole message comes back, not just its first word.
                    // RFC 0008 says a message is four registers; returning one
                    // of them made every service that needed to answer with
                    // more than a number invent a way to say it in pieces.
                    // `arg0` is written again by the dispatcher from
                    // `Outcome::value`, which is why it is also set there.
                    frame.arg0 = reply.args[0];
                    frame.arg1 = reply.args[1];
                    frame.arg2 = reply.args[2];
                    frame.arg3 = reply.args[3];
                    return Outcome::ok(reply.args[0]);
                }
                Err(error) => return Outcome::err(ipc_status(error)),
            }
        }
        Some(Kind::Recv) => {
            let resolved = match resolve_for_ipc(frame.capability, ObjectKind::Endpoint) {
                Ok(resolved) => resolved,
                Err(status) => return Outcome::err(status),
            };
            let endpoint = crate::ipc::EndpointId::from_u32(resolved.object.id as u32);
            match crate::ipc::recv(endpoint) {
                Ok((message, caller)) => {
                    // The badge tells the receiver which route the caller
                    // used, and `arg1` names who to reply to.
                    frame.method = message.method;
                    frame.arg0 = message.args[0];
                    frame.arg1 = u64::from(caller);
                    frame.arg2 = message.badge;
                    return Outcome::ok(message.badge);
                }
                Err(error) => return Outcome::err(ipc_status(error)),
            }
        }
        Some(Kind::Reply) => {
            // `arg1` names the caller, as `Recv` returned it.
            let caller = frame.arg1 as u32;
            let answer = crate::ipc::Message {
                method: frame.method,
                args: [frame.arg0, 0, 0, 0],
                badge: 0,
            };
            return match crate::ipc::reply(caller, answer) {
                Ok(()) => Outcome::ok(0),
                Err(error) => Outcome::err(ipc_status(error)),
            };
        }
        _ => {}
    }

    let Some(id) = sched::current_domain() else {
        return Outcome::err(Status::NoDomain);
    };

    if kind == Some(Kind::Invoke) {
        return invoke(id, frame);
    }

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

/// Performs an `Invoke`, including the cross-domain grant.
fn invoke(id: domain::DomainId, frame: &mut SyscallFrame) -> Outcome {
    // A grant needs two domains' CSpaces and cannot hold both tables at once,
    // so it is resolved in stages rather than done in place.
    if frame.method == method::GRANT {
        return grant(id, frame);
    }

    let owner = id.as_u32();
    domain::with(id, |domain| {
        let mut cspace = core::mem::take(&mut domain.cspace);
        let before = cspace.occupied();
        let outcome = cap::with_arena(|arena| invoke_capability(frame, owner, &mut cspace, arena));
        let after = cspace.occupied();

        // Charge or release the quota by what the operation actually did,
        // rather than by what it was asked to do. A derive that failed on the
        // destination slot must not leave the domain charged for it.
        if after > before {
            if domain.charge_capability().is_err() {
                return Outcome::err(Status::QuotaExceeded);
            }
        } else {
            for _ in after..before {
                domain.release_capability();
            }
        }

        domain.cspace = cspace;
        outcome
    })
    .unwrap_or(Outcome::err(Status::NoDomain))
}

/// Gives a derived capability to another domain.
///
/// Requires two things the caller must already hold: a capability naming the
/// *recipient* domain, with `WRITE`, and the source capability it is
/// delegating, with `DERIVE`. Neither is a check bolted on — a domain that
/// holds no capability to another cannot name it, so there is no way to
/// express a grant to a stranger.
fn grant(id: domain::DomainId, frame: &mut SyscallFrame) -> Outcome {
    // Stage one: resolve both capabilities in the caller's own space, and
    // derive the copy that will be handed over. The derived capability is
    // charged to the *recipient*, because it is the recipient's to keep.
    let resolved = domain::with(id, |domain| {
        let cspace = core::mem::take(&mut domain.cspace);
        let result = cap::with_arena(|arena| {
            let target_index =
                usize::try_from(frame.capability).map_err(|_| Status::NoSuchCapability)?;
            let target_slot = cspace.get(target_index).ok_or(Status::NoSuchCapability)?;
            let (target, target_rights) = arena.lookup(target_slot).ok_or(Status::Revoked)?;
            if target.kind != crate::cap::ObjectKind::Domain {
                return Err(Status::WrongObject);
            }
            if !target_rights.contains(crate::cap::Rights::WRITE) {
                return Err(Status::InsufficientRights);
            }

            let source_index = usize::try_from(frame.arg0).map_err(|_| Status::NoSuchCapability)?;
            let source_slot = cspace.get(source_index).ok_or(Status::NoSuchCapability)?;
            let (_, source_rights) = arena.lookup(source_slot).ok_or(Status::Revoked)?;
            if !source_rights.contains(crate::cap::Rights::GRANT) {
                return Err(Status::InsufficientRights);
            }

            let recipient = u32::try_from(target.id).map_err(|_| Status::WrongObject)?;
            let rights = crate::cap::Rights::from_bits(frame.arg1 as u8);
            let derived = arena
                .derive_owned(source_slot, rights, frame.arg2, recipient)
                .map_err(|error| match error {
                    crate::cap::CapError::RightsNotMonotone
                    | crate::cap::CapError::DeriveNotPermitted => Status::InsufficientRights,
                    _ => Status::QuotaExceeded,
                })?;
            Ok((recipient, derived))
        });
        domain.cspace = cspace;
        result
    });

    let Some(Ok((recipient, derived))) = resolved else {
        return match resolved {
            Some(Err(status)) => Outcome::err(status),
            _ => Outcome::err(Status::NoDomain),
        };
    };

    // Stage two: install it in the recipient, and charge the recipient. If
    // either fails the derived capability is destroyed rather than left
    // orphaned in the arena.
    let destination = match usize::try_from(frame.arg3) {
        Ok(destination) => destination,
        Err(_) => {
            cap::with_arena(|arena| arena.revoke_unchecked(derived));
            return Outcome::err(Status::SlotUnavailable);
        }
    };

    let placed = domain::with(domain::DomainId::from_u32(recipient), |target| {
        if target.charge_capability().is_err() {
            return Err(Status::QuotaExceeded);
        }
        match target.cspace.install_at(destination, derived) {
            Ok(()) => Ok(()),
            Err(_) => {
                target.release_capability();
                Err(Status::SlotUnavailable)
            }
        }
    });

    match placed {
        Some(Ok(())) => Outcome::ok(frame.arg3),
        Some(Err(status)) => {
            cap::with_arena(|arena| arena.revoke_unchecked(derived));
            Outcome::err(status)
        }
        None => {
            cap::with_arena(|arena| arena.revoke_unchecked(derived));
            Outcome::err(Status::NoSuchCapability)
        }
    }
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
        assert_eq!(Status::Congested.as_u64(), 8);
        assert_eq!(Status::NoSuchCaller.as_u64(), 9);
        assert_eq!(Status::NoSuchMethod.as_u64(), 10);
        assert_eq!(Status::SlotUnavailable.as_u64(), 11);
        assert_eq!(Status::QuotaExceeded.as_u64(), 12);
    }

    /// The same deterministic generator the other harnesses use.
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

        /// A value drawn from the numbers that break arithmetic, or a random
        /// one. Uniform draws never land on a boundary; `elf`'s harness
        /// measured how badly, and this one is written knowing it.
        fn interesting(&mut self) -> u64 {
            const EDGES: [u64; 10] = [
                0,
                1,
                6,
                63,
                64,
                u64::MAX,
                u64::MAX - 1,
                1 << 63,
                0x7fff_ffff_ffff_ffff,
                0xffff_ffff,
            ];
            if self.below(2) == 0 {
                EDGES[self.below(EDGES.len())]
            } else {
                self.next()
            }
        }
    }

    /// The fuzz target [RFC 0008](../../docs/rfc/0008-syscall-and-ipc-shape.md)'s
    /// testing plan commits to: *"a fuzz target on syscall argument decoding,
    /// before user mode can be reached by anything untrusted"*.
    ///
    /// Every field of a system-call frame is chosen by ring 3. `dispatch_with`
    /// and `invoke_capability` are the two functions that read them, and both
    /// are pure by construction — they resolve, rearrange authority, and
    /// return, without blocking — which is what makes this testable on the
    /// host at all rather than only by booting.
    ///
    /// What is asserted is not "no panic". It is that **nothing a caller can
    /// write in a register produces authority**: every frame either fails, or
    /// succeeds against a capability that was already in the CSpace before the
    /// call. A fuzzer that only checked for panics would pass a kernel that
    /// handed out capabilities to anyone who asked in the right order.
    #[test]
    fn a_mutation_harness_never_lets_a_frame_invent_authority() {
        let iterations: usize = std::env::var("BHASKIX_FUZZ_ITERATIONS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(20_000);

        for seed in 0..iterations as u64 {
            let mut rng = Rng(seed.wrapping_mul(0x2545_f491_4f6c_dd1d).wrapping_add(13));

            // A domain holding exactly one capability, to an endpoint, with
            // *some* of the rights. Deliberately not `Rights::ALL`: a seed
            // capability that already held everything would make "no frame can
            // widen its rights" a statement with nothing to widen, and the
            // check below would pass against a kernel that ignored
            // monotonicity entirely. It did, when this was first written.
            const GRANTED: Rights = Rights::from_bits(
                Rights::READ.bits() | Rights::DERIVE.bits() | Rights::REVOKE.bits(),
            );

            let mut arena = Arena::new();
            let mut cspace = CSpace::new();
            let root = arena
                .insert_root(ObjectRef::new(ObjectKind::Endpoint, 7), GRANTED, 0)
                .expect("a fresh arena has room");
            cspace.install_at(0, root).expect("slot 0 is free");
            let before = arena.live();

            let mut f = SyscallFrame {
                kind: rng.interesting(),
                capability: rng.interesting(),
                method: rng.interesting(),
                arg0: rng.interesting(),
                arg1: rng.interesting(),
                arg2: rng.interesting(),
                arg3: rng.interesting(),
                ..SyscallFrame::default()
            };

            // Both readers of the frame, because they decode different fields:
            // `dispatch_with` reads the kind and the capability index, and
            // `invoke_capability` reads the method and all four arguments.
            let outcome = dispatch_with(&mut f, &cspace, &arena);
            assert!(
                outcome.status == Status::Ok || outcome.value == 0,
                "seed {seed}: a failed call returned a value"
            );

            let f = SyscallFrame {
                kind: Kind::Invoke as u64,
                capability: rng.interesting(),
                method: rng.interesting(),
                arg0: rng.interesting(),
                arg1: rng.interesting(),
                arg2: rng.interesting(),
                arg3: rng.interesting(),
                ..SyscallFrame::default()
            };
            let _ = invoke_capability(&f, 0, &mut cspace, &mut arena);

            // The invariant that matters. A frame may legitimately *derive* a
            // capability -- that is what `Invoke` is for -- but every one it
            // produces must descend from the one this domain already held, and
            // the arena must never lose track of how many exist.
            let after = arena.live();
            assert!(
                after >= before.saturating_sub(1),
                "seed {seed}: capabilities vanished without a revoke"
            );

            for index in 0..crate::cap::CSPACE_SLOTS {
                let Some(slot) = cspace.get(index) else {
                    continue;
                };
                let Some((object, rights)) = arena.lookup(slot) else {
                    continue;
                };
                assert_eq!(
                    object.kind,
                    ObjectKind::Endpoint,
                    "seed {seed}: slot {index} names an object kind nothing granted"
                );
                assert_eq!(
                    object.id, 7,
                    "seed {seed}: slot {index} names another object"
                );
                assert!(
                    GRANTED.contains(rights),
                    "seed {seed}: slot {index} holds rights nobody had to give -- \
                     {rights:?} is not within {GRANTED:?}"
                );
            }
        }
    }
}
