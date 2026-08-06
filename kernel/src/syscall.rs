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
    assert!(method::FILL == bhaskix_abi::method::FILL);
    assert!(method::ATTACH == bhaskix_abi::method::ATTACH);
    assert!(method::MAP == bhaskix_abi::method::MAP);
    assert!(method::ACK == bhaskix_abi::method::ACK);
    assert!(method::WAIT == bhaskix_abi::method::WAIT);
    assert!(method::PEEK == bhaskix_abi::method::PEEK);
    assert!(method::INFO == bhaskix_abi::method::INFO);
    assert!(method::DELETE == bhaskix_abi::method::DELETE);
    assert!(method::DERIVE == bhaskix_abi::method::DERIVE);
    assert!(method::HAND == bhaskix_abi::method::HAND);
    assert!(method::EXPECT == bhaskix_abi::method::EXPECT);
    assert!(method::DRAIN == bhaskix_abi::method::DRAIN);
    assert!(crate::cap::Rights::READ.bits() as u64 == bhaskix_abi::rights::READ);
    assert!(crate::cap::Rights::WRITE.bits() as u64 == bhaskix_abi::rights::WRITE);
    assert!(crate::cap::Rights::DERIVE.bits() as u64 == bhaskix_abi::rights::DERIVE);
    assert!(crate::cap::Rights::GRANT.bits() as u64 == bhaskix_abi::rights::GRANT);
    assert!(Status::InsufficientRights as u64 == bhaskix_abi::status::INSUFFICIENT_RIGHTS);
    assert!(Status::SlotUnavailable as u64 == bhaskix_abi::status::SLOT_UNAVAILABLE);
    assert!(method::PUT == bhaskix_abi::method::PUT);
    assert!(method::TAKE == bhaskix_abi::method::TAKE);
    assert!(method::POLL == bhaskix_abi::method::POLL);
    assert!(method::NOTHING == bhaskix_abi::method::NOTHING);
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
    /// Signal a notification when this `IrqHandler`'s source fires.
    ///
    /// `arg0` = the caller's slot holding the `Notification` capability,
    /// `arg1` = the badge to signal with. RFC 0011.
    pub const BIND: u64 = 35;
    /// Unmask this source, so the next interrupt may be delivered.
    ///
    /// The whole of a delegated driver's interrupt duty: the kernel masks on
    /// delivery, and nothing arrives again until the holder says it is ready.
    pub const ACK: u64 = 36;
    /// Give the source up: masked permanently, vector freed, claim released.
    pub const RELEASE: u64 = 37;
    /// Wait until this notification has been signalled, then take the word.
    ///
    /// Only on a `Notification` capability. Blocks, and returns everything
    /// that was pending — the badges of every signal since the last take,
    /// or-ed together, which is what makes a notification a *signal* and not a
    /// queue: two interrupts before the holder looks are one wake carrying
    /// both badges, and no interrupt is lost by the second overwriting the
    /// first.
    ///
    /// The last thing a driver in a domain needs. Its device raises an
    /// interrupt, the kernel masks the source and signals the notification,
    /// and the driver wakes here — with no way to reach the interrupt
    /// controller, which is the point of it being a capability rather than a
    /// vector.
    ///
    /// One waiter, per RFC 0010: a second is refused rather than queued.
    pub const WAIT: u64 = 43;
    /// Take whatever this notification has pending, without waiting.
    ///
    /// Only on a `Notification` capability. Zero if nothing has been
    /// signalled, which is a real answer and not an error — a driver polling
    /// between requests wants to know "nothing yet" without blocking.
    pub const PEEK: u64 = 44;
    /// Map the memory this capability names into the caller's address space.
    ///
    /// Only on a `Memory` capability. `arg0` = where, page-aligned; `arg1`
    /// non-zero asks for a writable mapping, which needs `Rights::WRITE`.
    ///
    /// A domain cannot allocate its own physical memory and must not be able
    /// to name any: it maps what it *holds*, at an address of its choosing in
    /// its own space, and the frames come from the object rather than from
    /// anything it said. Never executable — RFC 0009 refuses that outright,
    /// because revocation unmaps while the other side is running and a
    /// receiver whose code vanishes faults at an instruction that no longer
    /// exists.
    ///
    /// This is what a driver in a domain needs before anything else: its
    /// descriptor rings are memory it holds and the device reaches by
    /// `DevAddr`, and it cannot fill them in without being able to see them.
    pub const ATTACH: u64 = 42;
    /// Put one character on the console this capability names.
    ///
    /// Only on a `Console` capability. `arg0` = the character.
    pub const PUT: u64 = 39;
    /// Take a byte that was typed, waiting until there is one.
    ///
    /// Only on a `Console` capability. Blocks, which is why a holder that
    /// does this is not answering anything else while it waits.
    pub const TAKE: u64 = 40;
    /// Take a byte only if one is already waiting.
    ///
    /// Only on a `Console` capability. Returns the byte, or [`NOTHING`] if
    /// nobody has typed — the value is out of a byte's range, so "nothing"
    /// cannot be confused with a byte that was read.
    pub const POLL: u64 = 41;
    /// What [`POLL`] returns when nothing was waiting.
    pub const NOTHING: u64 = 0x100;
    /// Say where a capability handed back by a server may be put.
    ///
    /// Only on an `Endpoint` capability, and it sets *thread* state rather
    /// than anything about the endpoint: this thread will accept one
    /// capability, in the slot `arg0` names, on its next call. It is required
    /// before [`HAND`] can do anything, and it is consumed by the first
    /// capability that arrives.
    ///
    /// A capability is required to ask, because every operation in this system
    /// is an invocation on one (RFC 0008 A2) — not because the endpoint has
    /// anything to do with it.
    pub const EXPECT: u64 = 46;
    /// Read bytes *out of* memory the caller of this endpoint named.
    ///
    /// The mirror of [`FILL`], and the direction a write needs. Only on an
    /// `Endpoint` capability, and only from the thread answering a message
    /// taken from it. `arg0` = the *caller's* slot holding the `Memory`
    /// capability, `arg1` = where in this server's address space to put the
    /// bytes, `arg2` = how many at most. Returns how many were taken.
    ///
    /// The caller must hold that memory with `READ`, where `FILL` needs
    /// `WRITE`: the right asked for is the one the operation performs on the
    /// caller's object, and asking for a fixed one would let a capability that
    /// may only be written to be read out.
    pub const DRAIN: u64 = 48;
    /// Give the caller being answered a copy of a capability this server holds.
    ///
    /// Only on an `Endpoint` capability, and only from a thread that is
    /// answering a message taken from it. `arg0` = the server's own slot
    /// holding the capability to copy, `arg1` = rights for the copy, `arg2` =
    /// its badge. Where it lands is **not** in this call: it is the slot the
    /// caller declared with [`EXPECT`]. RFC 0016.
    pub const HAND: u64 = 47;
    /// Write bytes into memory the caller of this endpoint named.
    ///
    /// Only on an `Endpoint` capability, and only from the thread that is
    /// answering a message taken from it. `arg0` = the *caller's* slot holding
    /// the `Memory` capability, `arg1` = address of the bytes in this domain,
    /// `arg2` = how many. Returns how many landed.
    ///
    /// This is the bulk path a service gets when it runs in its own domain:
    /// the nucleus placement writes through the direct map, which a domain has
    /// no way to do and must not have. Which caller is not an argument — it is
    /// the one this thread is answering, and a service that could name it
    /// could write a file's contents into a third party's memory.
    pub const FILL: u64 = 38;
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
                // The same answer as the two above on purpose. A caller that
                // could tell "you may not derive" from "you may not change the
                // badge" would learn the shape of a rule it is not allowed to
                // use, one probe at a time.
                Err(crate::cap::CapError::BadgeNotMonotone) => {
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
    /// Which device's translation this capability is authority over.
    ///
    /// Carried because there is more than one window now: a capability names
    /// a device's view of memory, and mapping into "the window" would map into
    /// whichever one happened to be first.
    device: (u8, u8, u8),
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
                    device: crate::iommu::device_of(window.id),
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
                device: crate::iommu::device_of(window.id),
                memory: Some(crate::shared::MemoryId::from_u64(memory.id)),
                rights: bhaskix_arch::vtd::Rights { read: true, write },
            })
        });
        owner.cspace = cspace;
        result
    });

    outcome.unwrap_or(Err(Status::NoDomain))
}

/// What an `IrqHandler` invocation resolved to, with every lock released.
///
/// Same reason as [`resolve_window`]: binding and acknowledging reach the
/// handler table and the interrupt controller, which rank inside the
/// capability arena this was resolved under.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct ResolvedHandler {
    handler: crate::irq::HandlerId,
    notification: Option<crate::notify::NotificationId>,
}

/// Resolves an `IrqHandler` method against the caller's own capabilities.
///
/// `BIND` checks **both**: the handler, and the notification it is asked to
/// signal. A domain may only point an interrupt at something it already holds
/// — otherwise a holder could aim a device's interrupt at another domain's
/// notification, which is a wake nobody asked for delivered on somebody
/// else's behalf.
fn resolve_handler(frame: &SyscallFrame) -> Result<ResolvedHandler, Status> {
    let Some(id) = sched::current_domain() else {
        return Err(Status::NoDomain);
    };

    let outcome = domain::with(id, |owner| {
        let cspace = core::mem::take(&mut owner.cspace);
        let result = cap::with_arena(|arena| {
            let index = usize::try_from(frame.capability).map_err(|_| Status::NoSuchCapability)?;
            let slot = cspace.get(index).ok_or(Status::NoSuchCapability)?;
            let (object, rights) = arena.lookup(slot).ok_or(Status::Revoked)?;
            if object.kind != ObjectKind::IrqHandler {
                return Err(Status::WrongObject);
            }
            if !rights.contains(crate::cap::Rights::WRITE) {
                // Acknowledging and binding both change what the hardware
                // does next. A read-only handle to an interrupt is a thing to
                // observe, not to steer.
                return Err(Status::InsufficientRights);
            }
            let handler = crate::irq::handler_from_u64(object.id);

            if frame.method != method::BIND {
                return Ok(ResolvedHandler {
                    handler,
                    notification: None,
                });
            }

            let notify_index = usize::try_from(frame.arg0).map_err(|_| Status::NoSuchCapability)?;
            let notify_slot = cspace.get(notify_index).ok_or(Status::NoSuchCapability)?;
            let (notification, _) = arena.lookup(notify_slot).ok_or(Status::Revoked)?;
            if notification.kind != ObjectKind::Notification {
                return Err(Status::WrongObject);
            }
            Ok(ResolvedHandler {
                handler,
                notification: Some(crate::notify::NotificationId::from_parts(
                    notification.id as u32,
                    (notification.id >> 32) as u32,
                )),
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
    /// What this capability permits. Looked up alongside the object and kept,
    /// because `ATTACH` needs it: mapping something writable is a different
    /// authority from being able to name it.
    rights: crate::cap::Rights,
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
            let (object, rights) = arena.lookup(slot).ok_or(Status::Revoked)?;
            if object.kind != expected {
                return Err(Status::WrongObject);
            }
            let badge = arena.badge_of(slot).unwrap_or(0);
            Ok(Resolved {
                object,
                badge,
                rights,
            })
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

    // An `IrqHandler` method, unlocked for the same reason as the window's:
    // binding and acknowledging reach the handler table and the controller,
    // both of which rank inside the capability arena it was resolved under.
    if kind == Some(Kind::Invoke)
        && matches!(frame.method, method::BIND | method::ACK | method::RELEASE)
    {
        let resolved = match resolve_handler(frame) {
            Ok(resolved) => resolved,
            Err(status) => return Outcome::err(status),
        };
        return match frame.method {
            method::BIND => match resolved.notification {
                Some(notification) => {
                    match crate::irq::bind(resolved.handler, notification, frame.arg1) {
                        Ok(()) => Outcome::ok(0),
                        Err(_) => Outcome::err(Status::NoSuchCapability),
                    }
                }
                None => Outcome::err(Status::WrongObject),
            },
            method::ACK => match crate::irq::acknowledge(resolved.handler) {
                Ok(()) => Outcome::ok(0),
                Err(_) => Outcome::err(Status::NoSuchCapability),
            },
            _ => {
                if crate::irq::release(resolved.handler) {
                    Outcome::ok(0)
                } else {
                    Outcome::err(Status::NoSuchCapability)
                }
            }
        };
    }

    // A `DmaWindow` method, which does not block but must not run locked: a
    // map may allocate a page-table level, and allocating takes the heap,
    // which ranks outside the capability arena the method was resolved under.
    // Waiting on a notification, from a domain.
    //
    // In the blocking group below rather than here would be tidier, and wrong:
    // that group resolves for `Endpoint`. This resolves its own capability,
    // releases every lock, and only then blocks -- the same shape and the same
    // reason, which is that blocking while holding the capability arena is how
    // M5-04 deadlocked the machine.
    if kind == Some(Kind::Invoke) && matches!(frame.method, method::WAIT | method::PEEK) {
        let resolved = match resolve_for_ipc(frame.capability, ObjectKind::Notification) {
            Ok(resolved) => resolved,
            Err(status) => return Outcome::err(status),
        };
        if !resolved.rights.contains(crate::cap::Rights::READ) {
            return Outcome::err(Status::InsufficientRights);
        }

        // The identity is packed the same way `BIND` unpacks it: index in the
        // low half, generation in the high. One encoding, two readers, and
        // they have to agree or a holder waits on a notification that is not
        // the one it was given.
        let id = crate::notify::NotificationId::from_parts(
            resolved.object.id as u32,
            (resolved.object.id >> 32) as u32,
        );
        if frame.method == method::PEEK {
            return Outcome::ok(crate::notify::poll(id));
        }
        return match crate::notify::wait(id) {
            Ok(bits) => Outcome::ok(bits),
            // Congested: somebody is already waiting, and RFC 0010 refuses a
            // second rather than queueing. Gone: the notification was
            // destroyed, which for a holder is indistinguishable from never
            // having had it and is reported the same way.
            Err(crate::notify::NotifyError::Congested) => Outcome::err(Status::Congested),
            Err(_) => Outcome::err(Status::Revoked),
        };
    }

    // Mapping memory into the caller's own address space.
    if kind == Some(Kind::Invoke) && frame.method == method::ATTACH {
        // A `Memory` object, or one page of device registers. Two kinds, one
        // method, because from the caller's side it is one question -- "let me
        // see what I hold" -- and the difference is what it holds. Resolving
        // for `Memory` first and falling back keeps the error for a capability
        // that is neither: `WrongObject`, from the second attempt.
        let resolved = match resolve_for_ipc(frame.capability, ObjectKind::Memory) {
            Ok(resolved) => resolved,
            Err(Status::WrongObject) => {
                match resolve_for_ipc(frame.capability, ObjectKind::Frame) {
                    Ok(resolved) => resolved,
                    Err(status) => return Outcome::err(status),
                }
            }
            Err(status) => return Outcome::err(status),
        };

        let writable = frame.arg1 != 0;
        // Two separate questions. Naming the memory is one authority; being
        // allowed to write into it is another, and a caller that asked for a
        // writable mapping of read-only memory is refused rather than quietly
        // given a read-only one -- it would find out by faulting, later,
        // somewhere else.
        if !resolved.rights.contains(crate::cap::Rights::READ) {
            return Outcome::err(Status::InsufficientRights);
        }
        if writable && !resolved.rights.contains(crate::cap::Rights::WRITE) {
            return Outcome::err(Status::InsufficientRights);
        }

        let protection = if writable {
            bhaskix_mm::Protection::ReadWrite
        } else {
            bhaskix_mm::Protection::ReadOnly
        };
        let at = bhaskix_boot::VirtAddr(frame.arg0);

        // Device registers: one page, at the physical address the capability
        // names. The identity of a `Frame` *is* the address, which is why
        // minting one is the kernel's business and never a domain's -- a
        // capability a domain could make would be permission to map any
        // physical page, which is permission to be the kernel.
        if resolved.object.kind == ObjectKind::Frame {
            let physical = resolved.object.id;
            let Some(range) = bhaskix_mm::VirtRange::from_pages(at, 1) else {
                return Outcome::err(Status::SlotUnavailable);
            };
            let mapped =
                crate::vm::with_active(|space| space.map_device(range, physical, protection));
            return match mapped {
                Some(Ok(())) => Outcome::ok(frame.arg0),
                Some(Err(_)) => Outcome::err(Status::SlotUnavailable),
                None => Outcome::err(Status::WrongObject),
            };
        }

        let id = crate::shared::MemoryId::from_u64(resolved.object.id);

        // Into whichever space is loaded: the caller's, because the caller is
        // what is running. Asked of the hardware rather than of bookkeeping,
        // for the same reason the fault handler does.
        let mapped =
            crate::vm::with_active(|space| crate::shared::map_into(id, space, at, protection));
        return match mapped {
            Some(Ok(())) => Outcome::ok(frame.arg0),
            // The address was unusable: not page-aligned, overlapping
            // something already mapped, or asking for more pages than the
            // object has. All the same answer from out here on purpose -- a
            // domain that could tell them apart could map its way around its
            // own address space looking for what is already there.
            Some(Err(_)) => Outcome::err(Status::SlotUnavailable),
            // No user address space loaded. A kernel thread has no business
            // asking for this, and saying so beats mapping into whatever
            // happened to be in CR3.
            None => Outcome::err(Status::WrongObject),
        };
    }

    // The console, as a capability. Three methods and no more: put a
    // character, take a byte, look for a byte. A console service in its own
    // domain holds one of these and can do exactly that; the same service in
    // the nucleus can do anything, which is what the placement is for.
    if kind == Some(Kind::Invoke)
        && matches!(frame.method, method::PUT | method::TAKE | method::POLL)
    {
        let resolved = match resolve_for_ipc(frame.capability, ObjectKind::Console) {
            Ok(resolved) => resolved,
            Err(status) => return Outcome::err(status),
        };
        let _ = resolved;

        return match frame.method {
            method::PUT => {
                // One character, filtered by the *service* and not here. The
                // kernel's job is the device; deciding that an escape
                // sequence must not reach it is policy, and policy is what
                // was moved out.
                let character = char::from_u32(frame.arg0 as u32).unwrap_or('?');
                crate::print!("{character}");
                crate::service::counted(1, 0);
                Outcome::ok(0)
            }
            method::TAKE => {
                // Blocks. A holder waiting here is not answering anything
                // else, which is the same limit the service has always had
                // and which travelled with it.
                let byte = crate::input::read();
                crate::service::counted(0, 1);
                Outcome::ok(u64::from(byte))
            }
            _ => match crate::input::try_read() {
                Some(byte) => {
                    crate::service::counted(0, 1);
                    Outcome::ok(u64::from(byte))
                }
                // Out of a byte's range, so a caller cannot mistake "nothing"
                // for something somebody typed.
                None => Outcome::ok(method::NOTHING),
            },
        };
    }

    // Where this thread will accept a capability. Thread state, set through an
    // endpoint capability because every operation here is an invocation on
    // one -- not because the endpoint is what is being changed.
    if kind == Some(Kind::Invoke) && frame.method == method::EXPECT {
        // The endpoint is recorded with the slot. A declaration is an
        // invitation to *one* service, and without naming it the declaration
        // belonged to whichever call happened next -- which, for a program that
        // says where and then prints a line before asking, is the console.
        let invited = match resolve_for_ipc(frame.capability, ObjectKind::Endpoint) {
            Ok(resolved) => resolved.object.id as u32,
            Err(status) => return Outcome::err(status),
        };
        let Some(thread) = crate::sched::current_thread_id() else {
            return Outcome::err(Status::NoDomain);
        };
        let slot = match u32::try_from(frame.arg0) {
            Ok(slot) => slot,
            Err(_) => return Outcome::err(Status::SlotUnavailable),
        };
        return if crate::sched::set_receive_slot(thread, Some((slot, invited))) {
            Outcome::ok(frame.arg0)
        } else {
            Outcome::err(Status::NoDomain)
        };
    }

    // A capability, handed to the caller being answered. Held to the same
    // three checks `FILL` passes, in the same order and for the same reasons:
    // the endpoint capability proves this thread is a server, the reply
    // obligation says which caller, and the capability copied is one the
    // server already holds -- never a name it chose.
    //
    // The fourth is what `FILL` does not need. `FILL` writes into memory the
    // *caller* pointed at; this installs into the caller's CSpace, so where it
    // lands must also come from the caller. It does: the slot is the one the
    // caller declared with `EXPECT`, for this endpoint, and nothing in this
    // frame can change it.
    if kind == Some(Kind::Invoke) && frame.method == method::HAND {
        return hand(frame);
    }

    // The same path, the other way. A service that could read a caller's
    // memory without these three checks could read any domain's memory by
    // naming a slot, which is why this is not simply `FILL` with a flag.
    if kind == Some(Kind::Invoke) && frame.method == method::DRAIN {
        if let Err(status) = resolve_for_ipc(frame.capability, ObjectKind::Endpoint) {
            return Outcome::err(status);
        }
        let Some(caller) = crate::sched::current_thread_id().and_then(crate::sched::reply_target)
        else {
            return Outcome::err(Status::WrongObject);
        };
        let Some(object) =
            crate::shared::caller_object_for(caller, frame.arg0, crate::cap::Rights::READ)
        else {
            return Outcome::err(Status::NoSuchCapability);
        };

        let destination = frame.arg1;
        let limit = frame.arg2 as usize;
        let taken = crate::shared::drain_into(object, limit, &mut |bytes: &[u8]| {
            // Into the service's own address space, through the exception
            // table: a service that named an address it does not own gets a
            // short transfer, not a kernel fault.
            let len = bytes.len();
            // SAFETY: `bytes` is a kernel-visible view of frames the caller's
            // object owns, of `len` bytes, and `copy_to_user` is the
            // fault-protected write -- an unmapped or read-only destination is
            // a failure it reports rather than a fault it takes. `destination`
            // is not dereferenced anywhere else.
            let copied =
                unsafe { bhaskix_arch::uaccess::copy_to_user(destination, bytes.as_ptr(), len) };
            if copied.is_ok() { len } else { 0 }
        });
        return match taken {
            Some(taken) => Outcome::ok(taken as u64),
            None => Outcome::err(Status::NoSuchCapability),
        };
    }

    // The domain placement's bulk path. Held to the same three checks the
    // nucleus one passes, in the same order: the endpoint capability proves
    // this thread is a server, the reply obligation says which caller, and the
    // caller's own slot says which memory -- authority that the caller already
    // held and pointed at, never a name the service chose.
    if kind == Some(Kind::Invoke) && frame.method == method::FILL {
        let resolved = match resolve_for_ipc(frame.capability, ObjectKind::Endpoint) {
            Ok(resolved) => resolved,
            Err(status) => return Outcome::err(status),
        };
        let _ = resolved;

        let Some(caller) = crate::sched::current_thread_id().and_then(crate::sched::reply_target)
        else {
            // Not answering anybody. A thread that is not mid-request has no
            // caller, so there is no memory it is entitled to write into.
            return Outcome::err(Status::WrongObject);
        };
        let Some(object) = crate::shared::caller_object(caller, frame.arg0) else {
            return Outcome::err(Status::NoSuchCapability);
        };

        let source = frame.arg1;
        let limit = frame.arg2 as usize;
        let written = crate::shared::fill_from(object, limit, &mut |bytes: &mut [u8]| {
            // From the domain's own address space, through the exception
            // table: a service that passed an address it does not own gets a
            // short write, not a kernel fault.
            let taken = bytes.len();
            // SAFETY: `bytes` is a kernel buffer of `taken` bytes, and
            // `copy_from_user` is the fault-protected read -- an unmapped or
            // unreadable source is a failure it reports rather than a fault it
            // takes. `source` is not dereferenced anywhere else.
            let copied =
                unsafe { bhaskix_arch::uaccess::copy_from_user(bytes.as_mut_ptr(), source, taken) };
            if copied.is_ok() { taken } else { 0 }
        });
        return match written {
            Some(written) => Outcome::ok(written as u64),
            None => Outcome::err(Status::NoSuchCapability),
        };
    }

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
                    match crate::iommu::map_memory(
                        resolved.device,
                        memory,
                        resolved.rights,
                        false,
                        hhdm,
                    ) {
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
                if crate::iommu::unmap_device(resolved.device, frame.arg0, frame.arg1) {
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
            let outcome = crate::ipc::call(
                endpoint,
                resolved.badge,
                frame.method,
                [frame.arg0, frame.arg1, frame.arg2, frame.arg3],
            );

            match outcome {
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
                Ok((message, _caller)) => {
                    // All four registers, because a message is four registers
                    // (RFC 0008) and a server that received one of them could
                    // not speak the protocols this system already has. The
                    // filesystem packs a `Chunk` across all four; until this
                    // was symmetric, "the same service in either placement"
                    // was false at the boundary rather than in the service.
                    //
                    // The caller is not returned at all. It used to be, and a
                    // server then handed it back on `Reply` -- which meant a
                    // server could hand back a different one. The kernel
                    // remembers who this thread received from, so the badge
                    // gets the freed register and a service cannot address any
                    // caller but the one it is answering.
                    frame.method = message.method;
                    frame.arg0 = message.args[0];
                    frame.arg1 = message.args[1];
                    frame.arg2 = message.args[2];
                    frame.arg3 = message.args[3];
                    frame.capability = message.badge;
                    // `value` lands in the same register as `arg0`, so it has
                    // to agree with it rather than carry something else.
                    return Outcome::ok(message.args[0]);
                }
                Err(error) => return Outcome::err(ipc_status(error)),
            }
        }
        Some(Kind::Reply) => {
            // Nothing in the frame says who to answer. The kernel knows: it is
            // the caller this thread received from and has not yet answered,
            // and `ipc::reply` refuses anything else. A server that could name
            // its own reply target could plant a message in a thread it never
            // heard from and wake it holding an answer to a question it did
            // not ask.
            // Read, not taken: `ipc::reply` is the one that decides whether a
            // reply is allowed, and it must make that decision from the same
            // place every other caller of it does.
            let Some(caller) =
                crate::sched::current_thread_id().and_then(crate::sched::reply_target)
            else {
                return Outcome::err(Status::NoSuchCapability);
            };

            let answer = crate::ipc::Message {
                method: frame.method,
                args: [frame.arg0, frame.arg1, frame.arg2, frame.arg3],
                // Never from the frame. A server that could set a badge could
                // stamp its answer with an identity it was not given, and a
                // caller checking badges would believe it.
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
/// Gives the caller being answered a copy of a capability the server holds.
///
/// Two stages, like [`grant`], and for the same reason: the server's CSpace
/// and the caller's cannot both be held at once. Derive first from the
/// server's, then install into the caller's — and if the install fails, the
/// derived capability is destroyed rather than left in the arena charged to a
/// domain that cannot name it.
fn hand(frame: &SyscallFrame) -> Outcome {
    let Ok(resolved) = resolve_for_ipc(frame.capability, ObjectKind::Endpoint) else {
        return Outcome::err(Status::WrongObject);
    };
    let endpoint = resolved.object.id as u32;

    let Some(server) = crate::sched::current_thread_id() else {
        return Outcome::err(Status::NoDomain);
    };
    // Not answering anybody. A server that could hand a capability outside a
    // call would be a server that picks its recipient, and picking the
    // recipient is the whole authority this does not have.
    let Some(caller) = crate::sched::reply_target(server) else {
        return Outcome::err(Status::WrongObject);
    };
    let Some(recipient) = crate::sched::domain_of(caller) else {
        return Outcome::err(Status::NoDomain);
    };
    let Some(server_domain) = crate::sched::current_domain() else {
        return Outcome::err(Status::NoDomain);
    };

    // Where it goes, from the caller and from nowhere else. Taken rather than
    // read: a declaration admits one capability.
    // For *this* endpoint. A caller that invited some other service has not
    // invited this one, and a declaration is not a standing offer.
    let Some(destination) = crate::sched::take_receive_slot(caller, endpoint) else {
        return Outcome::err(Status::SlotUnavailable);
    };
    let destination = destination as usize;

    // Stage one: derive from the server's own CSpace, charged to the
    // recipient, because it is the recipient's to keep.
    let rights = crate::cap::Rights::from_bits(frame.arg1 as u8);
    let derived = domain::with(server_domain, |owner| {
        let cspace = core::mem::take(&mut owner.cspace);
        let result = cap::with_arena(|arena| {
            let index = usize::try_from(frame.arg0).map_err(|_| Status::NoSuchCapability)?;
            let slot = cspace.get(index).ok_or(Status::NoSuchCapability)?;
            let (_, held) = arena.lookup(slot).ok_or(Status::Revoked)?;
            // Holding a capability is not the same as being allowed to pass it
            // on, and this is passing it on to a domain the server does not
            // otherwise reach.
            if !held.contains(crate::cap::Rights::GRANT) {
                return Err(Status::InsufficientRights);
            }
            arena
                .derive_owned(slot, rights, frame.arg2, recipient.as_u32())
                .map_err(|error| match error {
                    crate::cap::CapError::RightsNotMonotone
                    | crate::cap::CapError::DeriveNotPermitted
                    | crate::cap::CapError::BadgeNotMonotone => Status::InsufficientRights,
                    _ => Status::QuotaExceeded,
                })
        });
        owner.cspace = cspace;
        result
    });
    let derived = match derived {
        Some(Ok(derived)) => derived,
        Some(Err(status)) => {
            // The declaration was taken and nothing arrived. Put it back, so a
            // caller is not left unable to receive because a server asked for
            // something it could not have.
            crate::sched::set_receive_slot(caller, Some((destination as u32, endpoint)));
            return Outcome::err(status);
        }
        None => return Outcome::err(Status::NoDomain),
    };

    // Stage two: install it in the caller, and charge the caller.
    let installed = domain::with(recipient, |owner| {
        if owner.charge_capability().is_err() {
            return Err(Status::QuotaExceeded);
        }
        match owner.cspace.install_at(destination, derived) {
            Ok(()) => Ok(()),
            Err(_) => {
                owner.release_capability();
                Err(Status::SlotUnavailable)
            }
        }
    });
    match installed {
        Some(Ok(())) => Outcome::ok(destination as u64),
        other => {
            cap::with_arena(|arena| arena.revoke_unchecked(derived));
            crate::sched::set_receive_slot(caller, Some((destination as u32, endpoint)));
            match other {
                Some(Err(status)) => Outcome::err(status),
                _ => Outcome::err(Status::NoDomain),
            }
        }
    }
}

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
                    | crate::cap::CapError::DeriveNotPermitted
                    | crate::cap::CapError::BadgeNotMonotone => Status::InsufficientRights,
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
