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
    assert!(method::SIGNAL == bhaskix_abi::method::SIGNAL);
    assert!(method::BIND_SELF == bhaskix_abi::method::BIND_SELF);
    assert!(method::ARM == bhaskix_abi::method::ARM);
    assert!(method::DISARM == bhaskix_abi::method::DISARM);
    assert!(method::INFO == bhaskix_abi::method::INFO);
    assert!(method::DELETE == bhaskix_abi::method::DELETE);
    assert!(method::DERIVE == bhaskix_abi::method::DERIVE);
    assert!(method::HAND == bhaskix_abi::method::HAND);
    assert!(method::EXPECT == bhaskix_abi::method::EXPECT);
    assert!(method::DRAIN == bhaskix_abi::method::DRAIN);
    assert!(method::PERSONALITY == bhaskix_abi::method::PERSONALITY);
    assert!(method::GRANT == bhaskix_abi::method::GRANT);
    assert!(method::BIND == bhaskix_abi::method::BIND);
    assert!(method::RELEASE == bhaskix_abi::method::RELEASE);
    assert!(method::SPAWN == bhaskix_abi::method::SPAWN);
    assert!(method::START == bhaskix_abi::method::START);
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
    assert!(Status::QuotaExceeded as u64 == bhaskix_abi::status::QUOTA_EXCEEDED);
    assert!(Status::Exhausted as u64 == bhaskix_abi::status::EXHAUSTED);
    assert!(Status::Notified as u64 == bhaskix_abi::status::NOTIFIED);
    assert!(method::SPAWN == bhaskix_abi::method::SPAWN);
    assert!(method::START == bhaskix_abi::method::START);
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
    /// from, `arg1` = the slot in the recipient, `arg2` = rights, `arg3` =
    /// badge.
    ///
    /// That order is what `grant` reads, and this comment said `arg1` was
    /// rights and `arg3` the recipient's slot until 2026-08-11 — wrong in a way
    /// nothing caught, because the only caller was hand-written assembly that
    /// had got it right from the implementation. The first caller to trust the
    /// comment granted a capability with the rights and the destination
    /// transposed.
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
    /// Signal a notification, with the bits taken from the capability's badge.
    pub const SIGNAL: u64 = 45;
    /// Bind a notification to the calling thread. RFC 0010 question 1.
    pub const BIND_SELF: u64 = 55;
    /// Arm a deadline on a notification. RFC 0019.
    pub const ARM: u64 = 56;
    /// Forget a notification's deadline. RFC 0019.
    pub const DISARM: u64 = 57;
    /// Set a `Domain`'s system-call dialect (RFC 0005 step 2).
    pub const PERSONALITY: u64 = 58;
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
    /// Create a domain, and install a capability to it in a slot the caller
    /// names.
    ///
    /// Only on a `DomainControl` capability. `arg0` = the destination slot in
    /// the caller's own CSpace, which must be empty; `arg1` and `arg2` = up to
    /// sixteen bytes of name. RFC 0017 step 4.
    pub const SPAWN: u64 = 49;
    /// Start a program in a domain this program holds.
    ///
    /// Only on a `Domain` capability carrying `WRITE`. `arg0` = the caller's
    /// slot holding a `Memory` object containing an ELF image, `arg1` = how
    /// many of its bytes are the image. RFC 0017 step 5.
    pub const START: u64 = 50;
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
    /// A resource the whole machine shares is used up.
    ///
    /// Distinct from [`Status::QuotaExceeded`] deliberately: "you may not have
    /// another" and "nobody may have another" call for different responses. A
    /// supervisor told the first should look at its own envelope; told the
    /// second it should look at the machine, and asking again later is the only
    /// thing that can help.
    Exhausted = 13,
    /// A blocking receive was woken by its bound notification rather than by a
    /// message. Not a failure. RFC 0010 question 1.
    Notified = 14,
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
    revoked: &mut [u32; crate::cap::MAX_OWNERS],
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
            // The tally goes back to the caller of this function, because
            // releasing it needs the *other* owners' table entries and this
            // runs with the invoker's held. It was collected and dropped
            // here from RFC 0014 until 2026-08-15: no owner but the invoker
            // ever got its quota back from a revocation, so a service
            // accepting a capability per client was spent to death by
            // clients that granted and revoked.
            match arena.revoke_tallied(slot, revoked) {
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
            // Handled outside this dispatch: it needs the *recipient's* CSpace
            // as well as the giver's, and two domains cannot be held at once.
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

/// The last refusal a `Recv` was given, and which thread got it.
///
/// Packed as `(thread << 8) | status | 1 << 32`, so zero means "no receive has
/// ever been refused" without a second flag.
///
/// **A service that is refused a receive exits**, because there is nothing left
/// for it to serve and a loop that spun there would look like a working service
/// using a whole CPU. That is right, and it means the refusal is the only
/// evidence of why the service is gone -- and until this existed there was
/// none. A filesystem service disappearing after ninety-eight requests left
/// eight callers queued behind it and no record at all of what it was told.
static RECV_REFUSED: AtomicU64 = AtomicU64::new(0);

fn note_recv_refusal(status: Status) {
    let id = crate::sched::current_thread_id().unwrap_or(0);
    RECV_REFUSED.store(
        (1 << 32) | (u64::from(id) << 8) | status as u64,
        Ordering::Relaxed,
    );

    // Said out loud, on the serial line, at the moment it happens -- but only
    // for a thread that belongs to a domain.
    //
    // Those are the services: `bin/consoled`, `bin/vfsd`, `bin/blkd`, `bin/fsd`.
    // A refused receive ends one of them, because `serve` has no other way out,
    // and the consequences are invisible from anywhere else. When the console
    // service is the one that goes, **nothing can report it** -- the shell's
    // next write blocks for ever and the machine simply stops saying anything.
    // The kernel's `println!` goes to the serial port directly rather than
    // through the console service, so this is the one voice left.
    //
    // Deliberately not printed for a thread with no domain: the IPC self-test
    // tears its endpoint down underneath its own service on every boot, which
    // is a refusal by design and would put a line in every log.
    if crate::sched::current_domain().is_some() {
        let name = crate::sched::describe(id).map_or("?", |(name, _)| name);
        crate::println!(
            "  A SERVICE WAS REFUSED A RECEIVE: thread {id} ({name}), status {}. It has \
             exited, and every later caller will block for ever.",
            status as u64
        );
    }
}

/// The last refused receive: `(thread, status)`, or `None` if there was none.
#[must_use]
pub fn last_recv_refusal() -> Option<(u32, u64)> {
    let packed = RECV_REFUSED.load(Ordering::Relaxed);
    (packed != 0).then_some((((packed >> 8) & 0xff_ffff) as u32, packed & 0xff))
}

/// Maps an IPC failure onto a status code.
const fn ipc_status(error: crate::ipc::IpcError) -> Status {
    match error {
        crate::ipc::IpcError::NoSuchEndpoint | crate::ipc::IpcError::Exhausted => {
            Status::NoSuchCapability
        }
        crate::ipc::IpcError::Congested => Status::Congested,
        crate::ipc::IpcError::NoSuchCaller => Status::NoSuchCaller,
        // The endpoint is fine; the program behind it is not. `Revoked` is the
        // status for authority that was good and has been taken away, which is
        // what a reply obligation becomes the moment its holder dies.
        crate::ipc::IpcError::ServerGone => Status::Revoked,
        // RFC 0022 step 2: the rendezvous refused a call whose staged gift
        // could not be completed, and the refusal's own status travels — "the
        // service never declared" and "your capability lacked GRANT" are
        // different mistakes, and only one of them is the caller's.
        crate::ipc::IpcError::Refused(_) => Status::SlotUnavailable,
    }
}

/// The `Status` a gift refusal was made with, from its stored raw value.
///
/// [`complete_gift`] runs on the server thread and the refusal travels to the
/// caller through a `u32` in its thread entry; this turns it back into the
/// variant it was, so the caller is told the actual mistake. Anything
/// unrecognised collapses to the commonest cause rather than inventing one.
fn refusal_status(raw: u32) -> Status {
    const RIGHTS: u32 = Status::InsufficientRights as u32;
    const QUOTA: u32 = Status::QuotaExceeded as u32;
    const NO_CAP: u32 = Status::NoSuchCapability as u32;
    const REVOKED: u32 = Status::Revoked as u32;
    const NO_DOMAIN: u32 = Status::NoDomain as u32;
    match raw {
        RIGHTS => Status::InsufficientRights,
        QUOTA => Status::QuotaExceeded,
        NO_CAP => Status::NoSuchCapability,
        REVOKED => Status::Revoked,
        NO_DOMAIN => Status::NoDomain,
        _ => Status::SlotUnavailable,
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
    // RFC 0026 step 5: one event per system call, at its exit, where the
    // status is known. `Exit` diverges inside `dispatch_inner` and never
    // appears here — the one call the stream cannot carry, said rather than
    // discovered. One load and a predicted branch when the class is off.
    let mut crossing = [0u8; 16];
    crossing[..4].copy_from_slice(&(frame.kind as u32).to_le_bytes());
    crossing[4..8].copy_from_slice(&(frame.method as u32).to_le_bytes());
    crossing[8..12].copy_from_slice(&(frame.capability as u32).to_le_bytes());
    crossing[12..].copy_from_slice(&(outcome.status as u32).to_le_bytes());
    let domain = crate::telemetry::domain_hint();
    crate::telemetry::emit(
        bhaskix_telemetry::EventClass::Syscall,
        bhaskix_telemetry::schema::SYSCALL.id,
        domain,
        &crossing,
    );
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

    // A `Domain` method, before the blocks below claim the numbers.
    //
    // `BIND`, `RELEASE` and `INFO` each mean something on more than one kind of
    // object, and the blocks that follow intercept them **by number**, resolve
    // the capability their own way, and `return` whatever that produced --
    // including its failure. So a `Domain` invoked with `INFO` was answered
    // `WrongObject` by the code for device windows, which had never heard of
    // domains, and RFC 0017 step 6 could not reach any of its three methods.
    //
    // Guarded by method rather than by kind, so the locks below are taken for
    // three methods and not for every invocation. Asking the kind on every
    // `Invoke` was the first fix and it was a bad one: it put the domain table
    // on the hot path of every system call, and the machine spent its time
    // queueing for it.
    if kind == Some(Kind::Invoke)
        && matches!(frame.method, method::BIND | method::INFO | method::RELEASE)
        && let Some(outcome) = domain_lifecycle(frame)
    {
        return outcome;
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

    // Signalling a notification, from a domain. **RFC 0010 step 2**, specified
    // when that RFC was accepted on 2026-08-04 and not built until now.
    //
    // Beside `WAIT` above rather than folded into it, because they are opposite
    // halves and want opposite rights: waiting reads the word, signalling
    // writes it.
    //
    // **The badge is the payload and the caller does not supply it.** No
    // argument here carries bits; `resolve_for_ipc` returns the badge the
    // kernel stamped on this capability at derivation, and that is what gets
    // or-ed into the pending word. It is the whole reason a receiver can trust
    // a badge to say *which* sender fired: the sender never chose it.
    //
    // Never blocks, so nothing is held across it and there is no ordering
    // hazard to avoid -- `notify::signal` publishes the bits before it looks
    // for a waiter, which is the rule that keeps a signal from being lost
    // against a waiter that is on its way to sleep.
    // Binding a notification to this thread. **RFC 0010 question 1.**
    //
    // No argument names a thread: the caller binds itself, which is the whole
    // authority question answered by construction rather than by a check.
    if kind == Some(Kind::Invoke) && frame.method == method::BIND_SELF {
        let resolved = match resolve_for_ipc(frame.capability, ObjectKind::Notification) {
            Ok(resolved) => resolved,
            Err(status) => return Outcome::err(status),
        };
        if !resolved.rights.contains(crate::cap::Rights::READ) {
            return Outcome::err(Status::InsufficientRights);
        }
        let Some(me) = crate::sched::current_thread_id() else {
            return Outcome::err(Status::NoDomain);
        };
        let id = crate::notify::NotificationId::from_parts(
            resolved.object.id as u32,
            (resolved.object.id >> 32) as u32,
        );
        return if crate::notify::bind_to(id, me) {
            Outcome::ok(0)
        } else {
            // Already bound to somebody else, or gone. Refused rather than
            // replacing: substituting a binding loses whoever held the first.
            Outcome::err(Status::Congested)
        };
    }

    // Arming and disarming a deadline. **RFC 0019.**
    //
    // Beside `SIGNAL` because it *is* a signal, just a later one: the same
    // right, the same badge, the same wake path. What the kernel adds is the
    // waiting, which is the part a program cannot do for itself -- it can
    // already read the clock, since `rdtsc` is unprivileged here.
    if kind == Some(Kind::Invoke) && (frame.method == method::ARM || frame.method == method::DISARM)
    {
        let resolved = match resolve_for_ipc(frame.capability, ObjectKind::Notification) {
            Ok(resolved) => resolved,
            Err(status) => return Outcome::err(status),
        };
        if !resolved.rights.contains(crate::cap::Rights::WRITE) {
            return Outcome::err(Status::InsufficientRights);
        }
        let id = crate::notify::NotificationId::from_parts(
            resolved.object.id as u32,
            (resolved.object.id >> 32) as u32,
        );
        if frame.method == method::DISARM {
            return Outcome::ok(u64::from(crate::notify::disarm(id)));
        }
        return match crate::notify::arm(id, frame.arg0, resolved.badge) {
            Ok(()) => {
                // Bring this processor's next timer interrupt forward, if the
                // deadline just armed is sooner than whatever it was going to
                // fire for. Without this the deadline is recorded and then
                // waited on by nothing: expiry runs in the timer interrupt, and
                // nothing had asked the timer to arrive. RFC 0019 step 4
                // measured what that costs — the wake instant did not depend on
                // the deadline at all.
                crate::time::arm_no_later_than(frame.arg0);
                Outcome::ok(0)
            }
            // Every slot is armed for somebody else. A refusal rather than
            // taking one from whoever holds it.
            Err(crate::notify::NotifyError::Exhausted) => Outcome::err(Status::Congested),
            Err(_) => Outcome::err(Status::Revoked),
        };
    }

    if kind == Some(Kind::Invoke) && frame.method == method::SIGNAL {
        let resolved = match resolve_for_ipc(frame.capability, ObjectKind::Notification) {
            Ok(resolved) => resolved,
            Err(status) => return Outcome::err(status),
        };
        if !resolved.rights.contains(crate::cap::Rights::WRITE) {
            return Outcome::err(Status::InsufficientRights);
        }
        let id = crate::notify::NotificationId::from_parts(
            resolved.object.id as u32,
            (resolved.object.id >> 32) as u32,
        );
        return match crate::notify::signal(id, resolved.badge) {
            Ok(()) => Outcome::ok(0),
            // A badge of zero is a capability that cannot say anything, which
            // is the granter's mistake and is refused at derivation too. Gone:
            // the notification was destroyed, reported as it is for a waiter.
            Err(crate::notify::NotifyError::EmptyBadge) => Outcome::err(Status::WrongObject),
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

    // Creating a domain, like handing over a capability, needs the caller's own
    // CSpace *and* the domain table, and cannot hold either while taking the
    // other. Handled here rather than in the per-object dispatch below for that
    // reason and no other.
    if kind == Some(Kind::Invoke) && frame.method == method::SPAWN {
        return spawn(frame);
    }

    // And starting one, for the same reason: it reads the caller's memory, and
    // then reaches the domain table and the scheduler.
    if kind == Some(Kind::Invoke) && frame.method == method::START {
        return start_program(frame);
    }

    // Choosing a domain's system-call dialect (RFC 0005 step 2). Before
    // START in a program's order and before the match blocks in this one,
    // for the same two-CSpace reason as its neighbours.
    if kind == Some(Kind::Invoke) && frame.method == method::PERSONALITY {
        return set_personality(frame);
    }

    // Giving a domain a capability, which is the middle of create-grant-start
    // and the only way authority reaches a child. Here for the same reason as
    // the two above: the giver's CSpace and the recipient's cannot be held at
    // once, so it is two stages and neither belongs in a match arm that
    // already holds one of them.
    if kind == Some(Kind::Invoke)
        && frame.method == method::GRANT
        && let Some(outcome) = grant_to_domain(frame)
    {
        return outcome;
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
        // Where in the caller's object to start. `arg3` was unused until
        // 2026-08-11, when it turned out a service in a domain could not fill
        // an object larger than its own stack buffer -- it had no way to say
        // "continue from here", so it wrote the first page and reported that as
        // the whole file. The nucleus placement, calling `fill_from` directly,
        // spanned every frame. Two placements, two answers, silently.
        let offset = frame.arg3 as usize;
        let written = crate::shared::fill_from(object, offset, limit, &mut |bytes: &mut [u8]| {
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
                Err(crate::ipc::IpcError::Refused(raw)) => {
                    return Outcome::err(refusal_status(raw));
                }
                Err(error) => return Outcome::err(ipc_status(error)),
            }
        }
        Some(Kind::Recv) => {
            let resolved = match resolve_for_ipc(frame.capability, ObjectKind::Endpoint) {
                Ok(resolved) => resolved,
                Err(status) => {
                    note_recv_refusal(status);
                    return Outcome::err(status);
                }
            };
            let endpoint = crate::ipc::EndpointId::from_u32(resolved.object.id as u32);
            match crate::ipc::recv_either(endpoint) {
                // The bound notification fired. The badge word goes back in the
                // value register and no message registers are touched: there is
                // no message, and writing zeroes into them would look like one.
                Ok(crate::ipc::Received::Notified(bits)) => {
                    return Outcome {
                        status: Status::Notified,
                        value: bits,
                    };
                }
                Ok(crate::ipc::Received::Message(message, _caller)) => {
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
                Err(error) => {
                    // Reported here as well as above. `Recv` is refused from
                    // two places -- resolving the capability, and the
                    // rendezvous itself -- and only the first said so, which
                    // made exactly half of every service death invisible to
                    // the diagnostic built to explain service deaths.
                    let status = ipc_status(error);
                    note_recv_refusal(status);
                    return Outcome::err(status);
                }
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

/// How many foreign (Linux-dialect) system calls have been refused.
pub static FOREIGN_CALLS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// The first eight foreign syscall numbers seen, for the boot report — the
/// self-test asserts the exact sequence its probe issued.
pub static FOREIGN_SEEN: [core::sync::atomic::AtomicU64; 32] =
    [const { core::sync::atomic::AtomicU64::new(u64::MAX) }; 32];

/// Linux's `-ENOSYS`, as the `u64` the register carries.
const LINUX_ENOSYS: u64 = -38i64 as u64;

/// Answers one foreign system call: `-ENOSYS`, logged.
///
/// RFC 0005 step 2, whole and deliberate: no translation exists yet, so
/// every call is refused — but *observed*. The telemetry event carries the
/// Linux syscall number and the caller's `rip`, and the histogram of these
/// events is the personality's work queue: what a real workload asks for is
/// the specification, and this refusal path is how it gets written down.
/// Never silently succeed — the RFC names that as the one forbidden answer.
/// Linux syscall numbers this personality answers rather than refuses.
mod linux {
    /// `rt_sigaction(sig, act, oldact, sigsetsize)`.
    pub const RT_SIGACTION: u64 = 13;
    /// `rt_sigreturn()` — never returns to its caller.
    pub const RT_SIGRETURN: u64 = 15;
    /// `sigaltstack(ss, old_ss)`.
    pub const SIGALTSTACK: u64 = 131;
    /// `mmap(addr, length, prot, flags, fd, offset)`.
    pub const MMAP: u64 = 9;
    /// `mprotect(addr, length, prot)`.
    pub const MPROTECT: u64 = 10;
    /// `munmap(addr, length)`.
    pub const MUNMAP: u64 = 11;
    /// `madvise(addr, length, advice)`.
    pub const MADVISE: u64 = 28;
    /// `clone(flags, stack, parent_tid, child_tid, tls)`.
    pub const CLONE: u64 = 56;
    /// `futex(uaddr, op, val, timeout, uaddr2, val3)`.
    pub const FUTEX: u64 = 202;
    /// `gettid()`.
    pub const GETTID: u64 = 186;
    /// `getpid()`.
    pub const GETPID: u64 = 39;
    /// `exit_group(status)` — every thread of the group.
    pub const EXIT_GROUP: u64 = 231;
    /// `exit(status)` — this thread only. Distinct numbers and distinct
    /// meanings: a hosted program with one thread cannot tell them apart,
    /// and one with many very much can.
    pub const EXIT: u64 = 60;
    /// `sched_yield()`.
    pub const SCHED_YIELD: u64 = 24;
    /// `write(fd, buf, count)`.
    pub const WRITE: u64 = 1;
    /// `arch_prctl(code, addr)` — `ARCH_SET_FS` is the one that matters.
    pub const ARCH_PRCTL: u64 = 158;
    /// `sched_getaffinity(pid, len, mask)`.
    pub const SCHED_GETAFFINITY: u64 = 204;
    /// `rt_sigprocmask(how, set, oldset, sigsetsize)`.
    pub const RT_SIGPROCMASK: u64 = 14;
}

/// The futex table: one wait queue per watched address, per domain.
///
/// RFC 0005 step 6's third hard part. Sixteen slots, because a Go runtime
/// parks its scheduler on a handful of words and a table that could grow
/// would be an allocation on the wait path. A word with no slot free is
/// refused with `EAGAIN` rather than silently not sleeping — a futex that
/// returns instead of blocking is the spin the RFC warns about, and it is
/// better to fail loudly than to burn a CPU quietly.
/// The queues themselves live *outside* the lock, and deliberately: each
/// carries its own, so the only shared mutable state is which address a slot
/// watches. Keeping them apart is what lets a sleeper hold a plain reference
/// to its queue while the key table is free for a waker — no raw pointer, no
/// lock held across a sleep.
static FUTEX_QUEUES: [crate::wait::WaitQueue; 16] = [const { crate::wait::WaitQueue::new() }; 16];

/// Which (domain, address) each queue watches.
static FUTEX_KEYS: crate::sync::SpinLock<[Option<(u32, u64)>; 16]> =
    crate::sync::SpinLock::new(crate::sync::Rank::Signals, [None; 16]);

/// How many futex sleeps and wakes have happened, for the boot report.
pub static FUTEX_SLEEPS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// See [`FUTEX_SLEEPS`].
pub static FUTEX_WAKES: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Reads the `u32` a futex watches out of the caller's memory.
fn futex_word(address: u64) -> Option<u32> {
    let mut bytes = [0u8; 4];
    // SAFETY: the fault-protected read; a bad address is reported, not taken.
    let read = unsafe { bhaskix_arch::uaccess::copy_from_user(bytes.as_mut_ptr(), address, 4) };
    read.ok()?;
    Some(u32::from_le_bytes(bytes))
}

/// Where the personality places a mapping when the caller says "anywhere".
///
/// A bump, downward from a fixed base well clear of anything an image or a
/// stack occupies. Not an allocator: a hosted program that unmaps and remaps
/// will drift upward in address space until it runs out, which is a stated
/// narrowing rather than a bug hiding — the trigger for a real region
/// allocator is the first program that churns mappings, and Go's heap grows
/// monotonically enough not to be it.
static MMAP_NEXT: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0x0000_7000_0000_0000);

/// Answers the Linux memory calls over the region map — RFC 0005 step 5.
///
/// The decoding is `bhaskix_personality::memory`'s and host-tested there;
/// what happens here is the mapping itself, in the *calling* domain's own
/// address space, which is the whole of rule 2: the personality maps memory
/// the caller already has a domain to hold, and can no more conjure a frame
/// than any other program can.
fn foreign_memory_call(frame: &mut SyscallFrame) -> Option<u64> {
    use bhaskix_personality::memory::{self, MapPlan};

    let (first, second, third) = (frame.capability, frame.method, frame.arg0);
    match frame.kind {
        linux::MMAP => {
            let plan = memory::plan_mmap(first, second, third, frame.arg1, frame.arg2 as i64);
            let MapPlan::Map {
                at,
                pages,
                read,
                write,
                execute,
            } = plan
            else {
                let MapPlan::Refuse(errno) = plan else {
                    return None;
                };
                return Some(errno as u64);
            };
            let protection = match (read, write, execute) {
                (_, true, _) => bhaskix_mm::Protection::ReadWrite,
                (_, _, true) => bhaskix_mm::Protection::ReadExecute,
                (true, _, _) => bhaskix_mm::Protection::ReadOnly,
                _ => bhaskix_mm::Protection::None,
            };
            let bytes = pages.checked_mul(memory::PAGE)?;
            let address = match at {
                Some(address) => address,
                None => MMAP_NEXT.fetch_add(bytes, Ordering::Relaxed),
            };
            let range = bhaskix_mm::VirtRange::from_pages(bhaskix_boot::VirtAddr(address), pages)?;
            // Lazily: a hosted program that asks for a gigabyte and touches
            // a page should pay for a page, which is what Go's allocator
            // assumes and what the fault handler already provides.
            let mapped =
                crate::vm::with_active(|space| space.map_anonymous_lazy(range, protection).is_ok());
            match mapped {
                Some(true) => Some(address),
                _ => Some(memory::errno::ENOMEM as u64),
            }
        }
        linux::MUNMAP => match memory::plan_munmap(first, second) {
            Ok((address, _pages)) => {
                let removed = crate::vm::with_active(|space| {
                    space.unmap(bhaskix_boot::VirtAddr(address)).is_ok()
                });
                // A range that was not mapped is not an error worth
                // distinguishing: Linux's `munmap` succeeds on unmapped
                // pages, and a program tidying up should not have to
                // remember what it still holds.
                let _ = removed;
                Some(0)
            }
            Err(errno) => Some(errno as u64),
        },
        linux::MPROTECT => {
            // Changing protection on a live region needs the region map to
            // split and re-enter ranges, which it does not offer yet.
            // Refused with `ENOSYS` rather than answered `0`: a program told
            // its pages are now read-only, and then able to write them, is
            // worse off than one told the call does not exist.
            Some(memory::errno::ENOSYS as u64)
        }
        linux::MADVISE => Some(memory::plan_madvise() as u64),
        _ => None,
    }
}

/// Answers the thread and futex calls — RFC 0005 step 6.
///
/// `clone` becomes a thread in the caller's own domain, entered at the
/// address the caller supplied on the stack it supplied: the personality
/// creates nothing the domain could not, which is rule 2 again. `futex`
/// parks on the kernel's own wait queues, which is the primitive the RFC
/// said this needs. `exit_group` ends the domain, which is what makes a
/// thread group's exit exact.
fn foreign_thread_call(frame: &mut SyscallFrame, domain: u32) -> Option<u64> {
    use bhaskix_personality::memory::errno;
    use bhaskix_personality::thread::{self, ClonePlan, FutexPlan};

    let (first, second, third) = (frame.capability, frame.method, frame.arg0);
    match frame.kind {
        linux::GETPID => Some(u64::from(domain) + 1),
        // The one call a hosted program needs before it can say anything.
        // Only the two standard streams, and only to this machine's console:
        // a hosted program writing to a descriptor it never opened is
        // asking for authority, and fd 1 and 2 are the two Linux hands
        // every process without being asked.
        linux::WRITE => {
            let (fd, buffer, count) = (first, second, third as usize);
            if fd != 1 && fd != 2 {
                // A real descriptor table is Tier 1's; until then, anything
                // else is honestly absent rather than silently swallowed.
                return Some(-9i64 as u64); // EBADF
            }
            let mut bytes = [0u8; 256];
            let take = count.min(bytes.len());
            if take == 0 {
                return Some(0);
            }
            // SAFETY: the fault-protected read; a bad pointer is reported.
            let read =
                unsafe { bhaskix_arch::uaccess::copy_from_user(bytes.as_mut_ptr(), buffer, take) };
            read.ok()?;
            // Through the console the kernel already prints with, because a
            // hosted program's output is output: the bytes are lossy-decoded
            // as UTF-8 so a binary write cannot corrupt the log's framing.
            let text = core::str::from_utf8(&bytes[..take]).unwrap_or("<non-utf8>");
            crate::print!("{text}");
            Some(take as u64)
        }
        // The thread-local base. Go sets it before it touches anything in
        // `fs:`, which is nearly everything the runtime does -- so without
        // this a hosted Go program faults on its own scheduler.
        linux::ARCH_PRCTL => {
            const ARCH_SET_FS: u64 = 0x1002;
            if first != ARCH_SET_FS {
                return Some(errno::ENOSYS as u64);
            }
            // Recorded on the thread and loaded now. Not written straight
            // to the MSR and left there: the register is per CPU and the
            // thread is not, so the value has to travel with the thread
            // across every switch or it is gone at the first one -- which
            // is what Go's `rt0` catches three instructions later.
            let thread = crate::sched::current_thread_id()?;
            if !crate::sched::set_fs_base(thread, second) {
                return Some(errno::ENOSYS as u64);
            }
            Some(0)
        }
        // Answered rather than refused, because Go reads the affinity mask
        // to size its scheduler and treats a refusal as one CPU. The mask
        // says how many this machine really has -- a truthful answer that
        // costs nothing.
        linux::SCHED_GETAFFINITY => {
            let (length, mask) = (second as usize, third);
            if mask == 0 || length < 8 {
                return Some(errno::EINVAL as u64);
            }
            let cpus = bhaskix_arch::percpu::online_count();
            let bits: u64 = if cpus >= 64 {
                u64::MAX
            } else {
                (1u64 << cpus) - 1
            };
            // SAFETY: the fault-protected write into the caller's own mask.
            let written = unsafe {
                bhaskix_arch::uaccess::copy_to_user(mask, bits.to_le_bytes().as_ptr(), 8)
            };
            written.ok()?;
            Some(8)
        }
        // Signal masking is recorded nowhere and honoured nowhere yet, and
        // answering zero is the *correct* lie for a system that delivers
        // only synchronous faults: nothing this personality can deliver is
        // maskable, so a mask that changes nothing is accurate. The trigger
        // for making it real is the first asynchronous signal.
        linux::RT_SIGPROCMASK => Some(0),
        // A thread id a hosted program can tell apart from its neighbours,
        // and stable for the life of the thread. Derived from the scheduler's
        // own id, offset so no thread is ever tid zero (Linux never issues
        // one, and a runtime that sees zero treats it as an error).
        linux::GETTID => crate::sched::current_thread_id().map(|id| u64::from(id) + 1),
        linux::SCHED_YIELD => {
            crate::sched::yield_now();
            Some(0)
        }
        linux::EXIT => {
            // This thread, not the group. The domain ends when its last
            // thread does, which is RFC 0017's own rule and needs no help
            // from here.
            crate::sched::exit()
        }
        linux::EXIT_GROUP => {
            // Every thread of the group, which is every thread of the
            // domain. `exit` never returns, so nothing after this runs.
            crate::domain::end(
                crate::domain::DomainId::from_u32(domain),
                crate::domain::Ending::Exited,
            );
            crate::sched::exit()
        }
        linux::CLONE => {
            let plan = thread::plan_clone(first, second, third, frame.arg1, frame.arg2);
            let ClonePlan::Thread {
                stack,
                tls,
                parent_tid,
                child_tid,
            } = plan
            else {
                let ClonePlan::Refuse(errno) = plan else {
                    return None;
                };
                return Some(errno as u64);
            };
            // Linux's `clone` returns in *both* threads: zero in the child,
            // the child's tid in the parent. The child never returns through
            // this path at all -- it starts at the entry the caller named,
            // with the caller's own stack -- so the zero is delivered by
            // construction rather than by writing a register: there is no
            // return for it to be written to.
            //
            // The entry is `rip`'s successor in the caller's code, which for
            // Go is the function it wants the thread to run: the runtime
            // puts it in the child's stack and jumps there. This
            // personality's contract is narrower and stated: the thread
            // starts at the address in `arg3` (Linux's fifth argument slot
            // is `tls`, and the sixth, `r9`, is where a caller with no
            // libc puts the entry). A hosted runtime that expects Linux's
            // "resume after the syscall" shape needs the register-file copy
            // this does not yet do -- written down, not pretended.
            let entry = frame.arg3;
            if entry == 0 {
                return Some(errno::ENOSYS as u64);
            }
            let _ = (parent_tid, child_tid);
            crate::domain::record_pending_clone(
                crate::domain::DomainId::from_u32(domain),
                entry,
                stack,
                tls.unwrap_or(0),
            )
            .ok()?;
            let cpu = crate::domain::next_start_cpu();
            let options = crate::sched::SpawnOptions::new().pinned().in_domain(domain);
            match crate::sched::spawn_on_with(
                cpu,
                "cloned",
                crate::cloned_thread,
                u64::from(domain),
                crate::shared::hhdm(),
                options,
            ) {
                Ok(id) => Some(u64::from(id) + 1),
                Err(_) => {
                    crate::domain::take_pending_clone(crate::domain::DomainId::from_u32(domain));
                    Some(-11i64 as u64)
                }
            }
        }
        linux::FUTEX => {
            match thread::plan_futex(first, second, third) {
                FutexPlan::Wait { address, expected } => {
                    // The compare-and-sleep, which is the whole contract: if
                    // the word has already changed, the sleeper must not
                    // sleep, or it sleeps through the wake that changed it.
                    let now = futex_word(address)?;
                    if now != expected {
                        // Linux's EAGAIN: "the value was not what you said".
                        return Some(-11i64 as u64);
                    }
                    let slot = {
                        let mut keys = FUTEX_KEYS.lock();
                        let existing = keys.iter().position(|key| *key == Some((domain, address)));
                        match existing.or_else(|| keys.iter().position(Option::is_none)) {
                            Some(index) => {
                                keys[index] = Some((domain, address));
                                index
                            }
                            None => return Some(-11i64 as u64),
                        }
                    };
                    FUTEX_SLEEPS.fetch_add(1, Ordering::Relaxed);
                    // The condition is re-read with the queue's own lock
                    // held, which is what closes the window between the
                    // compare above and the sleep: a waker that changes the
                    // word and wakes in between is seen here rather than
                    // slept through.
                    FUTEX_QUEUES[slot].wait_until(|| futex_word(address) != Some(expected));
                    Some(0)
                }
                FutexPlan::Wake { address, count } => {
                    let slot = {
                        let keys = FUTEX_KEYS.lock();
                        keys.iter().position(|key| *key == Some((domain, address)))
                    };
                    let woken = match slot {
                        Some(index) if count <= 1 => usize::from(FUTEX_QUEUES[index].wake_one()),
                        Some(index) => FUTEX_QUEUES[index].wake_all(),
                        None => 0,
                    };
                    FUTEX_WAKES.fetch_add(woken as u64, Ordering::Relaxed);
                    Some(woken as u64)
                }
                FutexPlan::Refuse(errno) => Some(errno as u64),
            }
        }
        _ => None,
    }
}

/// Reads a Linux `struct sigaction` out of a hosted process's memory.
///
/// Four words: handler, flags, restorer, mask — the x86-64 layout, and the
/// order matters because `sa_restorer` sits *between* the flags and the mask
/// on this architecture and nowhere else.
fn read_sigaction(at: u64) -> Option<bhaskix_personality::signal::Handler> {
    let mut bytes = [0u8; 32];
    // SAFETY: the fault-protected read; a bad pointer is reported, not taken.
    let read =
        unsafe { bhaskix_arch::uaccess::copy_from_user(bytes.as_mut_ptr(), at, bytes.len()) };
    read.ok()?;
    let word = |index: usize| -> u64 {
        let mut value = [0u8; 8];
        value.copy_from_slice(&bytes[index * 8..index * 8 + 8]);
        u64::from_le_bytes(value)
    };
    Some(bhaskix_personality::signal::Handler {
        entry: word(0),
        flags: word(1),
        restorer: word(2),
        mask: word(3),
    })
}

/// Answers the signal calls a hosted program must make before it can survive
/// a fault — RFC 0005 step 4. Everything else is still `-ENOSYS`, and that
/// is the RFC's tiering rather than an omission.
///
/// Returns `Some(value)` when the call was answered, `None` to refuse.
fn foreign_signal_call(frame: &mut SyscallFrame, domain: u32) -> Option<u64> {
    // **Linux's argument registers are not this ABI's argument fields, and
    // the names in `SyscallFrame` are RFC 0008's.** Linux passes
    // `rdi, rsi, rdx, r10, r8, r9`; this frame calls those `capability`,
    // `method`, `arg0`, `arg1`, `arg2`, `arg3`. Reading `arg0` as the first
    // argument is therefore reading `rdx` as `rdi` -- which is exactly what
    // the first version of this function did, and the symptom was a handler
    // that installed for signal-number-nothing and a fault that found none.
    let (first, second) = (frame.capability, frame.method);
    match frame.kind {
        linux::RT_SIGACTION => {
            // `first` = signal, `second` = the new action, `arg0` = where the
            // old one goes (ignored: nothing hosted reads it yet, and
            // pretending to write it would be worse than not).
            if second == 0 {
                // Querying, not installing. Answered as success with nothing
                // written, which is what a caller asking about an unset
                // handler would see anyway.
                return Some(0);
            }
            let handler = read_sigaction(second)?;
            crate::signal::install(domain, first, handler)?;
            Some(0)
        }
        linux::SIGALTSTACK => {
            // `first` = the new stack: base, flags, size.
            if first == 0 {
                return Some(0);
            }
            let mut bytes = [0u8; 24];
            // SAFETY: the fault-protected read.
            let read = unsafe {
                bhaskix_arch::uaccess::copy_from_user(bytes.as_mut_ptr(), first, bytes.len())
            };
            read.ok()?;
            let word = |index: usize| -> u64 {
                let mut value = [0u8; 8];
                value.copy_from_slice(&bytes[index * 8..index * 8 + 8]);
                u64::from_le_bytes(value)
            };
            let alt = bhaskix_personality::signal::AltStack {
                base: word(0),
                flags: word(1),
                size: word(2),
            };
            crate::signal::set_alt_stack(domain, alt).then_some(0)
        }
        _ => None,
    }
}

fn foreign_call(frame: &mut SyscallFrame) {
    let number = frame.kind;
    let count = FOREIGN_CALLS.fetch_add(1, Ordering::Relaxed);
    if let Some(slot) = FOREIGN_SEEN.get(count as usize) {
        slot.store(number, Ordering::Relaxed);
    }
    let mut event = [0u8; 16];
    event[..8].copy_from_slice(&number.to_le_bytes());
    event[8..].copy_from_slice(&frame.rip.to_le_bytes());
    crate::telemetry::emit(
        bhaskix_telemetry::EventClass::Syscall,
        bhaskix_telemetry::schema::FOREIGN.id,
        crate::telemetry::domain_hint(),
        &event,
    );
    // `rt_sigreturn` first and on its own, because it is the one call that
    // must *not* write a return value: it restores `rax` from the frame the
    // handler was given, and an answer written over that would be the
    // interrupted program's own register clobbered by its resumption.
    if number == linux::RT_SIGRETURN && crate::signal::sigreturn(frame) {
        return;
    }

    // The signal calls, which a hosted program must make before it can
    // survive a fault. Answered here rather than refused; everything else
    // still gets `-ENOSYS`, which is the RFC's tiering rather than an
    // omission. The telemetry event is emitted either way -- an *answered*
    // foreign call is as much part of the histogram as a refused one.
    if let Some(domain) = crate::sched::current_domain()
        && let Some(value) = foreign_signal_call(frame, domain.as_u32())
    {
        frame.kind = value;
        return;
    }

    // The memory calls, RFC 0005 step 5, over this domain's own space.
    if let Some(value) = foreign_memory_call(frame) {
        frame.kind = value;
        return;
    }

    // The thread and futex calls, RFC 0005 step 6.
    if let Some(domain) = crate::sched::current_domain()
        && let Some(value) = foreign_thread_call(frame, domain.as_u32())
    {
        frame.kind = value;
        return;
    }

    // `rax` alone. `arg0` (the caller's `rdx`) is left exactly as the stub
    // saved it, which is what preserves it.
    frame.kind = LINUX_ENOSYS;
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

    // Interrupts on, for the whole of dispatch. SYSCALL's mask cleared `IF`
    // so the entry stub could `swapgs` and switch stacks atomically, and for
    // want of this line the mask then covered *everything*: every system
    // call ran deaf, and a syscall that spun -- a heap wait under
    // contention -- deafened its whole CPU. No tick, no wake IPI, no TLB
    // shootdown ack. The seventh capture of the boot hang read the bill out
    // in milliseconds: every one of a teardown's per-page shootdowns burned
    // its full timeout waiting for an ack a masked CPU could never send,
    // stretching one heap hold to forty-two seconds; the seconds-long
    // wake-to-dispatch outliers were the same deafness. The frame is built
    // and this is the kernel's stack and `GS`, which is everything the mask
    // was protecting.
    //
    // SAFETY: the IDT has been installed since bring-up; every vector has a
    // handler.
    unsafe { bhaskix_arch::cpu::enable_interrupts() };

    // RFC 0005 step 2: a Linux-tagged domain's system calls are foreign.
    // One relaxed load and a predicted branch on the native path — the same
    // cost discipline as the telemetry class check. When the branch is
    // taken, nothing native runs: the number in `rax` is a Linux syscall
    // number, not a Kind, and interpreting it natively would hand a hosted
    // binary whatever capability method happens to share the value. The
    // epilogue below — the space check, the death door, the interrupt mask,
    // the hold canary — runs for both dialects: a foreign caller is still a
    // thread this kernel has to return safely.
    // Which dialect this thread speaks, from the per-CPU domain note: one
    // relaxed load, the telemetry class check's cost discipline.
    //
    // **The note is only trustworthy because `enter_user` sets it**, and
    // that line exists because of this one. Read alone it was stale — it
    // names whichever domain last ran on the CPU, and a thread entering
    // ring 3 for the first time need not have been switched to here — which
    // showed up as a Linux program's calls dispatched *natively* in the
    // placement rebuilds, every answer `BadSyscall`. Asking the scheduler
    // instead was correct and cost a runqueue lock on every system call in
    // the machine; the fix that survives is to make the cheap answer true.
    let hint = crate::telemetry::domain_hint();
    let foreign = hint < 32
        && crate::domain::LINUX_DOMAINS.load(core::sync::atomic::Ordering::Relaxed) & (1 << hint)
            != 0;
    if foreign {
        foreign_call(frame);
    }

    let outcome = if foreign { None } else { Some(dispatch(frame)) };

    // Every system call returns to ring 3, so this needs no condition. See
    // `sched::check_user_space`: the switch instrumentation proved some return
    // path resumes a thread without loading its space, and this is one of the
    // two places that can say which.
    crate::sched::check_user_space(0);

    // The results go back through the same two registers the ABI names, which
    // the stub pops into `rax` and `rdx`. A foreign call wrote its own `rax`
    // in `foreign_call` and deliberately left `arg0` untouched — the entry
    // stub stored the caller's `rdx` there, so leaving it is what *preserves*
    // `rdx`, which is Linux's contract: a syscall clobbers `rax`, `rcx` and
    // `r11` and nothing else.
    if let Some(outcome) = outcome {
        frame.kind = outcome.status.as_u64();
        frame.arg0 = outcome.value;
    }

    // The first of the two safe points where a thread told to stop actually
    // stops. Here, and not where it was told, because *here* it demonstrably
    // holds nothing: the dispatch above has returned, so every capability
    // arena, runqueue and endpoint lock it took has been released, and the
    // only thing left to do was to put two values in a frame.
    //
    // Killing a thread at the moment its domain died would instead catch it
    // mid-derivation or half-way through a rendezvous, and free the stack it
    // was standing on. See `sched::mark_domain_dying`.
    //
    // **This check is not independently gated, and the reason is worth stating
    // rather than leaving for someone to rediscover.** A ring 3 thread that
    // returns from a system call returns to user mode, where the *other* safe
    // point -- an interrupt returning to ring 3 -- catches it within a tick.
    // So deleting these four lines fails nothing today: measured, by deleting
    // them and watching the gate still pass. Deleting the interrupt one is
    // caught immediately, because a thread that makes no system call has no
    // other door.
    //
    // It is kept for two reasons that are not "it might help". Death becomes
    // prompt instead of tick-granular, which matters for a domain being torn
    // down under memory pressure. And it is the door a thread woken *out of a
    // blocking call* leaves by -- RFC 0017 step 3, where a caller whose
    // service died is woken with an error and must not go back to user mode at
    // all. That step is where this gets its own witness.
    if crate::sched::should_die() {
        crate::sched::exit()
    }

    // Interrupts off again for the exit stub, which mirrors the entry: it
    // restores the user stack pointer and `swapgs`, and an interrupt landing
    // between those two is the same exploit the entry mask exists for.
    //
    // SAFETY: masking before the unwind is exactly the state the stub's exit
    // sequence assumes.
    unsafe { bhaskix_arch::cpu::disable_interrupts() };

    // The hold-leak canary. A thread returning to ring 3 holds no kernel
    // lock -- every guard the dispatch took has dropped by here -- so a
    // nonzero hold count on this CPU is a leak, and a leaked count vetoes
    // preemption on this CPU for ever: the captured one-in-fifteen boot
    // hang, whose watchdog dump showed exactly such counts. The watchdog
    // fires forty-five seconds after the fact; this fires on the leaking
    // system call, and names it.
    if crate::sync::holds_any() {
        crate::sched::note_hold_leak(frame.kind, frame.method);
    }
}

/// Creates a domain and gives the caller a capability to it.
///
/// RFC 0017 step 4, and the first thing in this system that lets a program
/// bring an object into existence. Four checks, and each refuses on its own:
///
/// 1. The capability invoked is a `DomainControl`. Nothing else may ask.
/// 2. It carries `DERIVE` — the right to make something new from it. A holder
///    that may only *see* the authority cannot use it.
/// 3. The destination slot is empty. Installing over an occupied slot would let
///    a program lose a capability it was still using, and would make a failed
///    spawn indistinguishable from a successful one that overwrote something.
/// 4. The creator's envelope allows another child. This is the T10 check, and
///    it is the reason this step does not reopen the threat it opens the door
///    to: `MAX_DOMAINS` is 32 and shared by the whole machine.
///
/// What comes back holds **nothing**. Authority reaches it afterwards, one
/// `GRANT` at a time.
fn spawn(frame: &SyscallFrame) -> Outcome {
    let Some(me) = crate::sched::current_domain() else {
        return Outcome::err(Status::NoDomain);
    };

    // The control capability, checked before anything is created.
    let resolved = crate::domain::with(me, |owner| {
        let slot = owner.cspace.get(frame.capability as usize)?;
        crate::cap::with_arena(|arena| arena.lookup(slot))
    })
    .flatten();
    let Some((object, rights)) = resolved else {
        return Outcome::err(Status::NoSuchCapability);
    };
    if object.kind != ObjectKind::DomainControl {
        return Outcome::err(Status::WrongObject);
    }
    if !rights.contains(crate::cap::Rights::DERIVE) {
        return Outcome::err(Status::InsufficientRights);
    }

    // The destination, checked before anything is created for the same reason:
    // a spawn that succeeds and then cannot be delivered would leave a domain
    // nobody can name and nobody can destroy.
    let destination = frame.arg0 as usize;
    let free = crate::domain::with(me, |owner| owner.cspace.get(destination).is_none());
    if free != Some(true) {
        return Outcome::err(Status::SlotUnavailable);
    }

    // The name, out of two registers rather than out of user memory. Sixteen
    // bytes is enough to tell programs apart in a report, and taking it from
    // registers means this call has no user pointer to validate and no fault
    // path -- a name is a diagnostic aid, and it should not be able to fail.
    let mut name = [0u8; crate::domain::MAX_NAME];
    name[..8].copy_from_slice(&frame.arg1.to_le_bytes());
    name[8..].copy_from_slice(&frame.arg2.to_le_bytes());
    let used = name
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(name.len());
    let name = core::str::from_utf8(&name[..used]).unwrap_or("?");

    // The child's envelope is the creator's, minus the ability to create more.
    // A child that inherited a child budget would let one capability multiply
    // without limit through a chain of domains, which is the table exhausted by
    // a longer route.
    let envelope = crate::domain::with(me, |owner| owner.envelope)
        .unwrap_or_default()
        .max_child_domains(0);

    let child = match crate::domain::create_under(Some(me.as_u32()), name, envelope) {
        Ok(child) => child,
        Err(crate::domain::DomainError::ChildEnvelopeExceeded { .. }) => {
            return Outcome::err(Status::QuotaExceeded);
        }
        Err(_) => return Outcome::err(Status::Exhausted),
    };

    // Derived from the child's own root, so the creator holds a capability
    // *under* it rather than the root itself: destroying the child revokes the
    // root and this copy with it, which is what makes destruction total.
    // A handle to the domain, and **not** derived from the domain's own root.
    //
    // It was, until RFC 0017 step 6 showed why it must not be. The root is the
    // ancestor of everything the domain is *granted*, and ending a domain
    // revokes it so that no authority outlives the program that held it. A
    // handle derived from it goes the same way — so a creator that asked what
    // happened to its child was told the capability had been revoked, and the
    // slot the kernel had carefully kept for it could not be reached, let alone
    // reaped.
    //
    // The two are different things. Authority *inside* a domain dies with the
    // domain; a reference *to* a domain has to outlive it, or there is nobody
    // left to ask and nothing to reap with. So the handle is a root of its own,
    // and `reap` is what revokes it.
    let granted = crate::cap::with_arena(|arena| {
        arena
            .insert_root(
                crate::cap::ObjectRef::new(
                    crate::cap::ObjectKind::Domain,
                    u64::from(child.as_u32()),
                ),
                crate::cap::Rights::ALL,
                0,
            )
            .ok()
    });
    let Some(granted) = granted else {
        crate::domain::destroy(child);
        return Outcome::err(Status::Exhausted);
    };

    if crate::domain::with(me, |owner| {
        owner.cspace.install_at(destination, granted).is_ok()
    }) != Some(true)
    {
        crate::domain::destroy(child);
        return Outcome::err(Status::SlotUnavailable);
    }

    Outcome::ok(u64::from(child.as_u32()))
}

/// Watching a domain, asking after it, and reaping it: RFC 0017 step 6.
///
/// `None` when the capability is not a `Domain`, so the blocks that share these
/// method numbers still answer for the kinds they own.
fn domain_lifecycle(frame: &SyscallFrame) -> Option<Outcome> {
    let me = crate::sched::current_domain()?;
    let (object, _) = domain::with(me, |owner| {
        let slot = owner.cspace.get(frame.capability as usize)?;
        cap::with_arena(|arena| arena.lookup(slot))
    })
    .flatten()?;
    if object.kind != ObjectKind::Domain {
        return None;
    }
    let target = domain::DomainId::from_u32(object.id as u32);

    Some(match frame.method {
        method::BIND => {
            let notification = domain::with(me, |owner| {
                let slot = owner.cspace.get(frame.arg0 as usize)?;
                cap::with_arena(|arena| arena.lookup(slot))
            })
            .flatten();
            let Some((notification, _)) = notification else {
                return Some(Outcome::err(Status::NoSuchCapability));
            };
            if notification.kind != ObjectKind::Notification {
                return Some(Outcome::err(Status::WrongObject));
            }
            // A badge of zero cannot be signalled -- `notify::signal` refuses
            // it, because a notification carrying no bits is one a waiter
            // cannot tell from never having been signalled.
            if frame.arg1 == 0 {
                return Some(Outcome::err(Status::WrongObject));
            }
            let id = crate::notify::NotificationId::from_parts(
                notification.id as u32,
                (notification.id >> 32) as u32,
            );
            if domain::notify_on_end(target, id, frame.arg1) {
                Outcome::ok(0)
            } else {
                // Already ended. Refused rather than accepted-and-never-fired:
                // a watch registered for an event that has happened is a wait
                // that never ends. `INFO` has the answer.
                Outcome::err(Status::WrongObject)
            }
        }

        method::INFO => match domain::state_of(target) {
            Ok(None) => Outcome::ok(0),
            Ok(Some(reason)) => Outcome::ok(reason as u64),
            Err(()) => Outcome::err(Status::Revoked),
        },

        method::RELEASE => {
            if domain::reap(target) {
                // The capability goes with the slot. Leaving it would let a
                // holder ask about a domain that has been reaped and get an
                // answer about whatever took the slot next.
                let removed = domain::with(me, |owner| {
                    owner.cspace.remove(frame.capability as usize);
                });
                let _ = removed;
                Outcome::ok(0)
            } else {
                // Still running, or already reaped. Both mean "there is nothing
                // here to release", and a holder that could tell them apart
                // would learn something about a domain that no longer exists.
                Outcome::err(Status::WrongObject)
            }
        }

        _ => return None,
    })
}

/// Gives a domain a copy of a capability the caller holds.
///
/// `None` when the capability invoked is not a `Domain`, so the ordinary
/// dispatch can answer for every other kind — `GRANT` means something else on
/// those, and this must not swallow them.
///
/// The middle step of create-grant-start, and the only way authority reaches a
/// child. RFC 0017 claimed this "already exists"; it did not — the dispatch
/// answered `NotImplemented`, with a comment explaining why it could not be
/// done there and nothing doing it anywhere else. So a created domain could
/// not be given anything, and a started program could do nothing at all.
///
/// Four checks, the same ones `HAND` makes and for the same reasons:
///
/// 1. The target is a `Domain`, and the caller holds it with `WRITE`. Putting
///    a capability into a domain changes it.
/// 2. The capability being passed is one the caller holds with **`GRANT`**.
///    Holding a thing and being allowed to give it away are different
///    permissions, and this gives it to a domain the caller does not otherwise
///    reach.
/// 3. The rights asked for are no wider than the caller's, which
///    `derive_owned` enforces, along with the badge rule.
/// 4. The destination slot in the recipient is empty.
fn grant_to_domain(frame: &SyscallFrame) -> Option<Outcome> {
    let me = crate::sched::current_domain()?;

    let resolved = domain::with(me, |owner| {
        let slot = owner.cspace.get(frame.capability as usize)?;
        cap::with_arena(|arena| arena.lookup(slot))
    })
    .flatten();
    let (object, rights) = resolved?;
    if object.kind != ObjectKind::Domain {
        return None;
    }
    if !rights.contains(crate::cap::Rights::WRITE) {
        return Some(Outcome::err(Status::InsufficientRights));
    }
    let recipient = domain::DomainId::from_u32(object.id as u32);
    if recipient == me {
        // Granting to itself is `DERIVE`, which already exists and has its own
        // rules. Allowing it here would be a second door to the same room with
        // a different lock on it.
        return Some(Outcome::err(Status::WrongObject));
    }

    let destination = frame.arg1 as usize;
    let wanted = crate::cap::Rights::from_bits(frame.arg2 as u8);

    // Stage one: derive from the giver's own CSpace, charged to the recipient,
    // because it is the recipient's to keep.
    let derived = domain::with(me, |owner| {
        let cspace = core::mem::take(&mut owner.cspace);
        let result = cap::with_arena(|arena| {
            let index = usize::try_from(frame.arg0).map_err(|_| Status::NoSuchCapability)?;
            let slot = cspace.get(index).ok_or(Status::NoSuchCapability)?;
            let (_, held) = arena.lookup(slot).ok_or(Status::Revoked)?;
            if !held.contains(crate::cap::Rights::GRANT) {
                return Err(Status::InsufficientRights);
            }
            arena
                .derive_owned(slot, wanted, frame.arg3, recipient.as_u32())
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
        Some(Err(status)) => return Some(Outcome::err(status)),
        None => return Some(Outcome::err(Status::NoDomain)),
    };

    // Stage two: install it in the recipient, and charge the recipient.
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
    Some(match installed {
        Some(Ok(())) => Outcome::ok(destination as u64),
        other => {
            // Nothing half-given. A derivation that could not be delivered is
            // revoked rather than left in the arena charged to a domain that
            // cannot name it.
            cap::with_arena(|arena| arena.revoke_unchecked(derived));
            match other {
                Some(Err(status)) => Outcome::err(status),
                _ => Outcome::err(Status::NoDomain),
            }
        }
    })
}

/// Starts a program in a domain the caller holds.
///
/// RFC 0017 step 5, and the step after which a supervisor can be written
/// entirely in userspace. Three checks:
///
/// 1. The capability is a `Domain`, and carries `WRITE`. Starting a program in
///    a domain changes it, and a holder that may only *see* a domain — to wait
///    on it, or to ask what happened — must not be able to run code in it.
/// 2. The image is a `Memory` object the **caller** holds with `READ`. Not a
///    filename: the kernel has no business opening files for a program, and a
///    program naming one would be naming authority it does not hold.
/// 3. The domain has no threads yet. Starting a second program in a domain
///    that is already running one is a different operation with different
///    questions — whose address space, whose stack — and this is not it.
///
/// The loading happens on the *new* thread rather than here. It reads a page
/// at a time, allocates, parses something a program supplied, and builds an
/// address space; doing that inside a system call would make an untrusted
/// image's size the caller's syscall latency, and would put a parser on the
/// dispatch path.
/// Sets the dialect a domain's threads will speak — RFC 0005 step 2.
///
/// The same resolution and the same `WRITE` requirement as `START`, because
/// choosing an ABI is shaping the domain. Refused with `SlotUnavailable`
/// once a thread exists: too late, not wrong.
fn set_personality(frame: &SyscallFrame) -> Outcome {
    let Some(me) = crate::sched::current_domain() else {
        return Outcome::err(Status::NoDomain);
    };
    let resolved = crate::domain::with(me, |owner| {
        let slot = owner.cspace.get(frame.capability as usize)?;
        crate::cap::with_arena(|arena| arena.lookup(slot))
    })
    .flatten();
    let Some((object, rights)) = resolved else {
        return Outcome::err(Status::NoSuchCapability);
    };
    if object.kind != ObjectKind::Domain {
        return Outcome::err(Status::WrongObject);
    }
    if !rights.contains(crate::cap::Rights::WRITE) {
        return Outcome::err(Status::InsufficientRights);
    }
    let target = crate::domain::DomainId::from_u32(object.id as u32);
    let dialect = match frame.arg0 {
        0 => crate::domain::Personality::Native,
        1 => crate::domain::Personality::Linux,
        _ => return Outcome::err(Status::BadSyscall),
    };
    match crate::domain::with(target, |owner| owner.set_personality(dialect)) {
        Some(Ok(())) => Outcome::ok(0),
        Some(Err(_)) => Outcome::err(Status::SlotUnavailable),
        None => Outcome::err(Status::NoDomain),
    }
}

fn start_program(frame: &SyscallFrame) -> Outcome {
    let Some(me) = crate::sched::current_domain() else {
        return Outcome::err(Status::NoDomain);
    };

    // The domain to start, from the capability invoked.
    let resolved = crate::domain::with(me, |owner| {
        let slot = owner.cspace.get(frame.capability as usize)?;
        crate::cap::with_arena(|arena| arena.lookup(slot))
    })
    .flatten();
    let Some((object, rights)) = resolved else {
        return Outcome::err(Status::NoSuchCapability);
    };
    if object.kind != ObjectKind::Domain {
        return Outcome::err(Status::WrongObject);
    }
    if !rights.contains(crate::cap::Rights::WRITE) {
        return Outcome::err(Status::InsufficientRights);
    }
    let target = crate::domain::DomainId::from_u32(object.id as u32);

    // The image, from memory the caller holds. `caller_object_for` is the same
    // resolution `DRAIN` uses and asks for the same right, because this reads
    // the caller's memory in exactly the way a drain does.
    let Some(thread) = crate::sched::current_thread_id() else {
        return Outcome::err(Status::NoDomain);
    };
    let Some(image) =
        crate::shared::caller_object_for(thread, frame.arg0, crate::cap::Rights::READ)
    else {
        return Outcome::err(Status::NoSuchCapability);
    };

    // Asked of the scheduler, not of `Domain::threads` -- a counter only one
    // self-test ever increments, so it reads zero for every domain and this
    // check never fired. Found while building step 6, which needed the same
    // question answered properly.
    if crate::sched::threads_in_domain(target.as_u32()) != 0 {
        return Outcome::err(Status::SlotUnavailable);
    }

    let length = frame.arg1 as usize;
    if length == 0 {
        return Outcome::err(Status::WrongObject);
    }
    // One word handed to the program at entry, from the caller. The same
    // affordance `enter_ring3` documents: everything a domain has arrives
    // through its CSpace, and this is for the one thing that cannot.
    let argument = frame.arg2;
    if !crate::domain::record_pending_start(target, image, length, argument) {
        return Outcome::err(Status::Exhausted);
    }

    // Pinned, because every entry into ring 3 is (M9-13), and rotated across
    // the online processors so that starting several programs does not pile
    // them all onto one. A pinned thread cannot be moved later, so where it
    // lands is decided once and permanently -- which is an argument for
    // spreading them rather than for choosing well.
    let cpu = crate::domain::next_start_cpu();
    let options = crate::sched::SpawnOptions::new()
        .pinned()
        .in_domain(target.as_u32());
    match crate::sched::spawn_on_with(
        cpu,
        "started",
        crate::started_program,
        u64::from(target.as_u32()),
        crate::shared::hhdm(),
        options,
    ) {
        Ok(id) => Outcome::ok(u64::from(id)),
        Err(_) => {
            crate::domain::take_pending_start(target);
            Outcome::err(Status::Exhausted)
        }
    }
}

/// Performs an `Invoke`, including the cross-domain grant.
/// Gives the caller being answered a copy of a capability the server holds.
///
/// Two stages, like [`grant`], and for the same reason: the server's CSpace
/// and the caller's cannot both be held at once. Derive first from the
/// server's, then install into the caller's — and if the install fails, the
/// derived capability is destroyed rather than left in the arena charged to a
/// domain that cannot name it.
/// Completes a staged gift at the rendezvous, or refuses the call.
///
/// RFC 0022 step 2, run **on the server thread** inside its receive path —
/// the one place both parties are known — for either way the match happened:
/// a sender finding a waiting receiver, or a receiver picking up a queued
/// sender. `Ok(false)` is the common case: the caller staged nothing, and
/// nothing here has any effect. `Ok(true)` is a completed transfer. `Err` is
/// a refusal the caller must be told about, because its call was never
/// delivered and no reply is coming; the receive path does the telling.
///
/// The checks are `hand`'s, mirrored: the *giver* must hold the capability
/// and hold it with `GRANT`, the rights and badge must be monotone under the
/// derive rules, the recipient pays the quota, and where it lands is the one
/// slot the recipient declared. On any failure both declarations are put
/// back — the caller's staged gift (so a retry loop stages once, the draft
/// answer to the RFC's open question 3) and the server's declared slot (a
/// service asked for something this caller could not give is still owed its
/// next legitimate capability).
pub(crate) fn complete_gift(caller: u32, endpoint: u32, server: u32) -> Result<bool, u32> {
    let Some(gift) = crate::sched::take_staged_gift(caller, endpoint) else {
        return Ok(false);
    };

    let Some(destination) = crate::sched::take_receive_slot(server, endpoint) else {
        // The service never declared. The security half of the design: a
        // caller cannot fill a service's slots uninvited, so the call is
        // refused rather than delivered bare.
        crate::sched::restore_staged_gift(caller, gift);
        return Err(Status::SlotUnavailable as u32);
    };
    let restore = |gift| {
        crate::sched::restore_staged_gift(caller, gift);
        crate::sched::set_receive_slot(server, Some((destination, endpoint)));
    };

    let Some(giver) = crate::sched::domain_of(caller) else {
        restore(gift);
        return Err(Status::NoDomain as u32);
    };
    let Some(recipient) = crate::sched::domain_of(server) else {
        restore(gift);
        return Err(Status::NoDomain as u32);
    };

    // Stage one: derive from the giver's CSpace, charged to the recipient,
    // exactly as `hand` does it and with its checks in its order.
    let rights = crate::cap::Rights::from_bits(gift.rights);
    let derived = domain::with(giver, |owner| {
        let cspace = core::mem::take(&mut owner.cspace);
        let result = cap::with_arena(|arena| {
            let index = gift.from_slot as usize;
            let slot = cspace.get(index).ok_or(Status::NoSuchCapability)?;
            let (_, held) = arena.lookup(slot).ok_or(Status::Revoked)?;
            // Holding a capability is not permission to pass it on.
            if !held.contains(crate::cap::Rights::GRANT) {
                return Err(Status::InsufficientRights);
            }
            arena
                .derive_owned(slot, rights, gift.badge, recipient.as_u32())
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
            restore(gift);
            return Err(status as u32);
        }
        None => {
            restore(gift);
            return Err(Status::NoDomain as u32);
        }
    };

    // Stage two: install in the recipient, and charge the recipient.
    let installed = domain::with(recipient, |owner| {
        if owner.charge_capability().is_err() {
            return Err(Status::QuotaExceeded);
        }
        owner
            .cspace
            .install_at(destination as usize, derived)
            .map_err(|_| Status::SlotUnavailable)
    });
    match installed {
        Some(Ok(())) => Ok(true),
        Some(Err(status)) => {
            restore(gift);
            Err(status as u32)
        }
        None => {
            restore(gift);
            Err(Status::NoDomain as u32)
        }
    }
}

fn hand(frame: &SyscallFrame) -> Outcome {
    let Ok(resolved) = resolve_for_ipc(frame.capability, ObjectKind::Endpoint) else {
        return Outcome::err(Status::WrongObject);
    };
    let endpoint = resolved.object.id as u32;

    let Some(server) = crate::sched::current_thread_id() else {
        return Outcome::err(Status::NoDomain);
    };
    // Which direction this is comes from what the thread is doing, not from an
    // argument. A thread answering a caller is a server handing into its reply
    // — RFC 0016's path, below, unchanged. A thread answering nobody is a
    // **caller staging for its next call** — RFC 0022 step 1: the transfer
    // cannot run yet, because the service thread that will take the call is
    // not known until the rendezvous, so the kernel records intent — the slot,
    // the rights, the badge, the endpoint — one per thread, replaced by a
    // second staging, consumed by the next `Call` on that endpoint.
    //
    // Nothing validates the staged capability here beyond the arguments'
    // shape: the derive at the rendezvous is the authoritative check (holding,
    // `GRANT`, monotone rights and badge), and it must be — a capability
    // revoked between staging and calling has to fail *there*, so a check here
    // would be reassurance that expires. Until the rendezvous consumes gifts
    // (RFC 0022 step 2), a staged gift is inert.
    let caller = match crate::sched::reply_target(server) {
        Some(caller) => caller,
        None => {
            let Ok(slot) = u32::try_from(frame.arg0) else {
                return Outcome::err(Status::SlotUnavailable);
            };
            let gift = crate::sched::StagedGift {
                from_slot: slot,
                rights: frame.arg1 as u8,
                badge: frame.arg2,
                endpoint,
            };
            return if crate::sched::stage_gift(server, gift) {
                Outcome::ok(frame.arg0)
            } else {
                Outcome::err(Status::NoDomain)
            };
        }
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
    let mut revoked = [0u32; cap::MAX_OWNERS];
    let outcome = domain::with(id, |domain| {
        let mut cspace = core::mem::take(&mut domain.cspace);
        let before = cspace.occupied();
        let outcome = cap::with_arena(|arena| {
            invoke_capability(frame, owner, &mut cspace, arena, &mut revoked)
        });
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

        // A revocation's tally, for this domain: the slot removal above
        // already released the entries that left the CSpace, so only what
        // the tally counted *beyond* that is released here -- derived
        // children this domain was charged for that sat in nobody's slots,
        // or in slots that stay occupied by dead references.
        let index = owner as usize;
        if index < revoked.len() {
            let counted = revoked[index];
            let already = (before.saturating_sub(after)) as u32;
            for _ in 0..counted.saturating_sub(already) {
                domain.release_capability();
            }
            revoked[index] = 0;
        }

        domain.cspace = cspace;
        outcome
    })
    .unwrap_or(Outcome::err(Status::NoDomain));

    // The rest of a revocation's tally: every *other* owner whose derived
    // capabilities the subtree destruction reached, released after the
    // invoker's table entry is given up -- `domain::with` holds the one
    // domain table, so this cannot run inside it.
    for (charged, count) in revoked.iter().enumerate() {
        if *count > 0 && charged as u32 != owner {
            domain::with(domain::DomainId::from_u32(charged as u32), |other| {
                for _ in 0..*count {
                    other.release_capability();
                }
            });
        }
    }
    outcome
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
    fn a_revocation_returns_quota_to_every_owner_it_reached() {
        // The leak this guards against: `REVOKE` destroys nodes across many
        // domains' holdings, collects a per-owner tally -- and dropped it,
        // so no owner but the invoker (whose CSpace slot removal is counted
        // separately) ever got its capability quota back. A service accepting
        // a capability per client was spent to death by clients that granted
        // and revoked.
        use crate::domain::{self, ResourceEnvelope};

        let granter =
            domain::create("quota-granter", ResourceEnvelope::new().max_capabilities(4)).unwrap();
        // An envelope of exactly one, so "was the quota returned" is the
        // difference between a charge that succeeds and one that is refused.
        let holder =
            domain::create("quota-holder", ResourceEnvelope::new().max_capabilities(1)).unwrap();

        let root = crate::cap::with_arena(|arena| {
            arena.insert_root_owned(
                ObjectRef::new(crate::cap::ObjectKind::Notification, 7077),
                Rights::ALL,
                0,
                granter.as_u32(),
            )
        })
        .unwrap();
        assert_eq!(
            domain::with(granter, |d| {
                d.charge_capability().unwrap();
                d.cspace.install_at(0, root).is_ok()
            }),
            Some(true)
        );
        // A derivation charged to the holder, exactly as a grant charges the
        // recipient; the holder is now at its limit.
        let _child = crate::cap::with_arena(|arena| {
            arena.derive_owned(root, Rights::READ, 0, holder.as_u32())
        })
        .unwrap();
        assert_eq!(
            domain::with(holder, |d| d.charge_capability().is_ok()),
            Some(true),
            "the holder pays for its copy, as a grant would make it"
        );
        assert_eq!(
            domain::with(holder, |d| d.charge_capability().is_err()),
            Some(true),
            "the holder must start full for the release to be observable"
        );

        let mut f = frame(Kind::Invoke as u64, 0);
        f.method = method::REVOKE;
        let outcome = invoke(granter, &mut f);
        assert_eq!(outcome.status, Status::Ok, "the revoke itself must work");

        assert_eq!(
            domain::with(holder, |d| {
                let freed = d.charge_capability().is_ok();
                if freed {
                    d.release_capability();
                }
                freed
            }),
            Some(true),
            "the holder's quota was not released by the revocation that destroyed its capability"
        );

        domain::destroy(granter);
        domain::destroy(holder);
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
            let mut revoked = [0u32; crate::cap::MAX_OWNERS];
            let _ = invoke_capability(&f, 0, &mut cspace, &mut arena, &mut revoked);

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
