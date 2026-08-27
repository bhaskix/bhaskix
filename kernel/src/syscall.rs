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
    assert!(method::COPY_IN == bhaskix_abi::method::COPY_IN);
    assert!(method::COPY_OUT == bhaskix_abi::method::COPY_OUT);
    assert!(method::MAP_AT == bhaskix_abi::method::MAP_AT);
    assert!(method::UNMAP_AT == bhaskix_abi::method::UNMAP_AT);
    assert!(method::PROTECT_AT == bhaskix_abi::method::PROTECT_AT);
    assert!(method::SPAWN_THREAD == bhaskix_abi::method::SPAWN_THREAD);
    assert!(method::SET_TLS == bhaskix_abi::method::SET_TLS);
    assert!(method::MAKE_SPACE == bhaskix_abi::method::MAKE_SPACE);
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
    assert!(method::PUT_RUN == bhaskix_abi::method::PUT_RUN);
    assert!(method::INPUT_STATS == bhaskix_abi::method::INPUT_STATS);
    assert!(method::TAKE_INPUT == bhaskix_abi::method::TAKE_INPUT);
    assert!(method::POLL_INPUT == bhaskix_abi::method::POLL_INPUT);
    assert!(method::TAKE == bhaskix_abi::method::TAKE);
    assert!(method::POLL == bhaskix_abi::method::POLL);
    assert!(method::RECORD_SIZE == bhaskix_abi::method::RECORD_SIZE);
    assert!(method::RECORD == bhaskix_abi::method::RECORD);
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
    /// Read a held domain's memory into an object the caller owns. RFC 0032.
    pub const COPY_IN: u64 = 59;
    /// Write an object the caller owns into a held domain's memory. RFC 0032.
    pub const COPY_OUT: u64 = 60;
    /// Map anonymous pages in a held domain. RFC 0032.
    pub const MAP_AT: u64 = 61;
    /// Unmap a region in a held domain. RFC 0032.
    pub const UNMAP_AT: u64 = 62;
    /// Re-protect a whole region in a held domain. RFC 0032.
    pub const PROTECT_AT: u64 = 63;
    /// Start a thread in a held domain. RFC 0032.
    pub const SPAWN_THREAD: u64 = 64;
    /// Set a thread's thread-local base. RFC 0032.
    pub const SET_TLS: u64 = 65;
    /// Give a `Domain` an address space of its own — RFC 0033 step 5.
    pub const MAKE_SPACE: u64 = 66;
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
    /// Put a run of bytes with the console held once — RFC 0050.
    ///
    /// Only on a `Console` capability, and it needs the same `WRITE` right
    /// `PUT` does. `arg0` = the address in the caller's space, `arg1` = how
    /// many. This is *n* `PUT`s minus the gap between them, into which a kernel
    /// line could land and did.
    pub const PUT_RUN: u64 = 69;
    /// How much input has arrived, and from which source — RFC 0051.
    ///
    /// Only on a `Console` capability, and it needs `READ` — the right a holder
    /// must already have to take a typed byte. It counts without consuming.
    pub const INPUT_STATS: u64 = 70;
    /// Take a byte typed at the console, **for the domain this capability
    /// names** — RFC 0053. Blocks until there is one.
    ///
    /// On a `Domain` capability with `READ`, and refused unless that domain has
    /// been granted input. The adapter's *console* capability is still `WRITE`
    /// alone: this is the domain's authority, not the console's.
    pub const TAKE_INPUT: u64 = 71;
    /// The same without blocking: a byte if one is already waiting, or
    /// [`bhaskix_abi::method::NOTHING`]'s value.
    pub const POLL_INPUT: u64 = 72;
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
    /// How many bytes of what the kernel printed are kept. RFC 0042.
    pub const RECORD_SIZE: u64 = 67;
    /// Eight bytes of that record, starting at `arg0`. RFC 0042.
    pub const RECORD: u64 = 68;
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
    unmapping: &mut Option<Unmapping>,
) -> Outcome {
    let index = match usize::try_from(frame.capability) {
        Ok(index) => index,
        Err(_) => return Outcome::err(Status::NoSuchCapability),
    };
    let Some(slot) = cspace.get(index) else {
        // **`DELETE` is answered before the slot is resolved, because it is
        // the one method whose whole purpose is that the slot end up empty.**
        // The ABI says so -- "not an error on a slot that is already empty: a
        // program tidying up should not have to remember whether it has
        // anything to tidy" -- and until 2026-08-23 the kernel said
        // `NoSuchCapability` instead, which is the disagreement between a doc
        // and its code that this project treats as two bugs.
        if frame.method == method::DELETE {
            return Outcome::ok(0);
        }
        return Outcome::err(Status::NoSuchCapability);
    };
    let Some((object, _)) = arena.lookup(slot) else {
        // **And this half was a slot leak with no way out of it.** A
        // capability *the issuer revoked* leaves its holder a dead reference:
        // resolving it fails, so every method refuses -- including the one
        // that would clear it. The holder cannot empty the slot, cannot reuse
        // it, and nothing can ever be handed there again.
        //
        // It is not hypothetical. `bin/fsd` lends a page of its cache and
        // takes it back by revoking (`dir::RELEASE`), so *every* borrower's
        // slot dies this way; `bin/linuxd` borrows into one fixed slot, and
        // the second file read on the machine was refused with
        // `SlotUnavailable` -- by whichever hosted program happened to be
        // second. It went unseen because until RFC 0005 step 8 nothing had
        // ever read two files.
        //
        // `remove` does not revoke -- other domains may still hold the same
        // capability, and this one holds nothing but a name for something
        // already gone.
        if frame.method == method::DELETE {
            cspace.remove(index);
            return Outcome::ok(0);
        }
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
            // Read before the revocation, because after it the node is gone
            // and with it the only record of which object it named.
            let named = object;
            let before = *revoked;
            match arena.revoke_tallied(slot, revoked) {
                Ok(destroyed) => {
                    // The revoked capability's own slot is now a dead
                    // reference. Clearing it is not required for safety --
                    // resolving it fails -- but leaving it occupies a slot the
                    // domain can never use again.
                    cspace.remove(index);

                    // **And the memory goes with the capability** -- RFC 0044.
                    // Decided here, where the arena is held and the question
                    // is answerable, and performed by the caller, where the
                    // locks unmapping needs are not already inverted.
                    //
                    // Who lost a capability here; **whether they lost their
                    // last one is decided by the caller**, because that needs
                    // the other domains' CSpaces and this holds only the
                    // invoker's.
                    if named.kind == crate::cap::ObjectKind::Memory
                        && let Some(memory) = crate::shared::from_identity(named.id)
                    {
                        let mut tallied = [false; crate::cap::MAX_OWNERS];
                        for (domain, lost) in tallied.iter_mut().enumerate() {
                            *lost = revoked[domain].saturating_sub(before[domain]) > 0;
                        }
                        if tallied.iter().any(|lost| *lost) {
                            *unmapping = Some(Unmapping {
                                object: memory,
                                named,
                                tallied,
                            });
                        }
                    }
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

/// What a revocation still owes once the arena and domain locks are gone.
///
/// [RFC 0044](../../docs/rfc/0044-revocation-that-reaches-the-mapping.md)
/// design §3, and the same shape as [`ResolvedWindow`] for the same kind of
/// reason. Revoking a `Memory` capability has to take the memory out of the
/// holders' address spaces, and unmapping needs `Rank::TlbSender` (4),
/// `Rank::Heap` (3) and `Rank::AddressSpace` (0) — all **outer** to the
/// `Rank::Domains` (6) and `Rank::Capabilities` (7) held where the decision is
/// made. So the decision is made there and carried out here.
///
/// `tallied` is which domains lost *a* capability, which is **not** which
/// domains lost their last one: a lender that derived what it lent from its
/// own capability appears in the tally of every lending it revokes and still
/// holds the object. Narrowing the one to the other is `CSpace::names`, and it
/// happens in the caller because it needs the other domains' CSpaces — the
/// invoker's is the only one taken out here. Getting it wrong unmaps
/// `bin/fsd`'s cache page on every file read, which is not a thought
/// experiment: it faulted the filesystem on the first `pkg install`.
#[derive(Clone, Copy)]
struct Unmapping {
    /// The object whose mappings are owed a removal.
    object: crate::shared::MemoryId,
    /// The same object as the arena names it, for the CSpace check.
    named: crate::cap::ObjectRef,
    /// Which domains lost a capability naming it.
    tallied: [bool; crate::cap::MAX_OWNERS],
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
        crate::ipc::IpcError::NoSuchEndpoint
        | crate::ipc::IpcError::Exhausted
        // A caller being torn down sees exactly what it saw before this
        // variant existed. The distinction is the kernel's, not ring 3's.
        | crate::ipc::IpcError::CallerDying => Status::NoSuchCapability,
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

    // RFC 0032's supervisor interface, guarded by method number for the same
    // reason the block above is: these take the domain table and the space
    // table, and neither belongs on the hot path of every system call.
    if kind == Some(Kind::Invoke)
        && matches!(
            frame.method,
            method::COPY_IN
                | method::COPY_OUT
                | method::MAP_AT
                | method::UNMAP_AT
                | method::PROTECT_AT
                | method::SPAWN_THREAD
                | method::SET_TLS
                | method::MAKE_SPACE
                // RFC 0053. **This list is why the arm in `domain_supervise`
                // was unreachable on the first attempt**: the methods are
                // whitelisted here as well as handled there, and a method
                // handled in only one of the two places is answered by the
                // fall-through instead — which reads, from the caller, exactly
                // like a refusal it has no way to tell apart.
                | method::TAKE_INPUT
                | method::POLL_INPUT
        )
        && let Some(outcome) = domain_supervise(frame)
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
        && matches!(
            frame.method,
            method::PUT
                | method::PUT_RUN
                | method::INPUT_STATS
                | method::TAKE
                | method::POLL
                | method::RECORD_SIZE
                | method::RECORD
        )
    {
        let resolved = match resolve_for_ipc(frame.capability, ObjectKind::Console) {
            Ok(resolved) => resolved,
            Err(status) => return Outcome::err(status),
        };
        // **Putting and taking are separate authorities, and until RFC 0032
        // step 10 nothing needed them to be.** One holder existed — the
        // console service, holding `Rights::ALL` — so a rights check would
        // have been unreachable code. The Linux adapter is the second holder
        // and it is given `WRITE` alone: a hosted program's `write` reaches
        // the console, and the adapter cannot take a byte somebody typed at
        // the shell. Without this the narrowing would be a comment rather
        // than a mechanism.
        // Reading the record is a `READ`, like taking a byte. It is not a
        // *weaker* authority than taking one: the record is what the kernel
        // said, and the Linux adapter -- the one holder given `WRITE` alone --
        // still cannot ask for it.
        // `INPUT_STATS` falls through to `READ`, deliberately: it reads the
        // input side, which is what `TAKE` and `POLL` need the right for.
        let wanted = if frame.method == method::PUT || frame.method == method::PUT_RUN {
            crate::cap::Rights::WRITE
        } else {
            crate::cap::Rights::READ
        };
        if !resolved.rights.contains(wanted) {
            return Outcome::err(Status::InsufficientRights);
        }

        return match frame.method {
            method::PUT => {
                // One character, filtered by the *service* and not here. The
                // kernel's job is the device; deciding that an escape
                // sequence must not reach it is policy, and policy is what
                // was moved out.
                //
                // **"A character at a time is what a `Console` confers" was
                // half right, and the other half cost an intermittent.** The
                // *authority* is to put bytes to a console and nothing else,
                // and that is unchanged. Saying how many at once was never part
                // of it -- and because each `PUT` takes and releases the
                // console lock on its own, a caller putting a line one byte at
                // a time could have a kernel report land in the middle of it.
                // It did. `PUT_RUN` below is the same authority with the gap
                // removed; RFC 0050 has the specimen.
                let character = char::from_u32(frame.arg0 as u32).unwrap_or('?');
                crate::print!("{character}");
                crate::service::counted(1, 0);
                Outcome::ok(0)
            }
            // **A run of bytes, put with the console held once — RFC 0050.**
            //
            // The same authority as `PUT` and the same rendering; what it
            // removes is the gap between one byte and the next, into which a
            // kernel line could land and did. The bytes are read out of the
            // *caller's* address space, which is the one thing `PUT` never did:
            // the same page-by-page translation `copy_across` performs, with
            // `frame_for_read`, so a lazily-mapped page is refused rather than
            // committed by printing.
            method::PUT_RUN => {
                let (address, length) = (frame.arg0, frame.arg1);
                let Ok(length) = usize::try_from(length) else {
                    return Outcome::err(Status::WrongObject);
                };
                if length == 0 {
                    return Outcome::ok(0);
                }
                // The kernel's bound and not the caller's: the console lock is
                // held for the whole run, so how long that is may not be
                // something a domain chooses. A longer line is more calls, and
                // those calls can interleave with each other -- RFC 0050 says
                // so rather than leaving it to be found.
                if length > MAX_CONSOLE_RUN || address.checked_add(length as u64).is_none() {
                    return Outcome::err(Status::WrongObject);
                }
                let Some(root) =
                    crate::sched::current_domain().and_then(crate::domain::space_root_of)
                else {
                    return Outcome::err(Status::NoDomain);
                };
                let hhdm = crate::shared::hhdm();
                let mut buffer = [0u8; MAX_CONSOLE_RUN];
                let mut taken = 0usize;
                while taken < length {
                    let at = address + taken as u64;
                    let page = at & !(bhaskix_mm::FRAME_SIZE - 1);
                    let within = (at - page) as usize;
                    let room = (bhaskix_mm::FRAME_SIZE as usize - within).min(length - taken);
                    let Some(frame_pa) = crate::vm::frame_for_read(root, page) else {
                        return Outcome::err(Status::WrongObject);
                    };
                    // SAFETY: a frame this space maps, reached through the
                    // direct map, and `room` stays inside it by construction.
                    let source = unsafe {
                        core::slice::from_raw_parts(
                            (hhdm + frame_pa + within as u64) as *const u8,
                            room,
                        )
                    };
                    buffer[taken..taken + room].copy_from_slice(source);
                    taken += room;
                }
                crate::console::put_run(&buffer[..taken]);
                crate::service::counted(taken as u64, 0);
                Outcome::ok(taken as u64)
            }
            // **What arrived, and from where — RFC 0051.** Counts without
            // consuming, which is the whole difference from `TAKE`.
            //
            // Packed as `u32` pairs and **saturating**, which is stated on the
            // ABI constant too: these are boot-lifetime counters and four
            // billion bytes is not a session, but a counter that *wrapped*
            // would read as a working keyboard that had gone quiet — the one
            // answer this must never give.
            method::INPUT_STATS => {
                let (serial_in, serial_lost, keys_in, keys_lost) = crate::input::per_source();
                let (_, _, interrupts) = crate::input::statistics();
                let scancodes = crate::keyboard::scancodes();
                let pair = |high: u64, low: u64| {
                    (u64::from(u32::try_from(high).unwrap_or(u32::MAX)) << 32)
                        | u64::from(u32::try_from(low).unwrap_or(u32::MAX))
                };
                // **One word per call, selected by `arg0`**, because a system
                // call returns one: `Outcome` carries a status and a value, and
                // `RECORD` beside this already has its caller walk an offset
                // for the same reason. Out-of-range asks read zero rather than
                // failing -- a reader that adds a fourth pair later should get
                // "nothing here" and not a refusal it has to special-case.
                return Outcome::ok(match frame.arg0 {
                    0 => pair(serial_in, serial_lost),
                    1 => pair(keys_in, keys_lost),
                    2 => pair(scancodes, interrupts),
                    _ => 0,
                });
            }
            method::TAKE => {
                // Blocks. A holder waiting here is not answering anything
                // else, which is the same limit the service has always had
                // and which travelled with it.
                let byte = crate::input::read();
                crate::service::counted(0, 1);
                Outcome::ok(u64::from(byte))
            }
            // RFC 0042. The boot report is written before any service
            // exists, so the record is kernel memory and a console service in
            // its own domain has to ask for it.
            method::RECORD_SIZE => {
                let (kept, _refused) = crate::console::recorded();
                Outcome::ok(kept as u64)
            }
            method::RECORD => {
                let bytes = crate::console::recorded_at(frame.arg0 as usize);
                Outcome::ok(u64::from_le_bytes(bytes))
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
                    // **Who is asking, recorded with the mapping** — RFC 0044
                    // design §5. A revocation that takes this object away from
                    // some of its holders has to know whether the device
                    // mapping was one of theirs; without a name on it the only
                    // safe answer is to remove it on any revocation, which
                    // would take an unrelated driver's DMA down with a lending.
                    let Some(mapper) = crate::sched::current_domain() else {
                        return Outcome::err(Status::NoDomain);
                    };
                    match crate::iommu::map_memory(
                        resolved.device,
                        memory,
                        resolved.rights,
                        false,
                        hhdm,
                        mapper.as_u32(),
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
/// The domain whose foreign calls are being recorded, or `u32::MAX` for none.
///
/// **Because [`FOREIGN_SEEN`] never showed what the corpus asked.** That table
/// is indexed by the *global* call counter, so it holds the first thirty-two
/// foreign calls of the whole boot — and the corpus runs long after the
/// eightieth. The line that reads `N calls, first asked: …` has therefore been
/// printing the boot's opening calls under a corpus's name since it was
/// written, which two corpus runs printing **identical** lists is the proof of.
///
/// This records one domain's calls, in order, from the moment it is armed.
pub static TRACED_DOMAIN: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(u32::MAX);

/// The numbers that domain asked for, in order.
pub static TRACED_SEEN: [core::sync::atomic::AtomicU64; 64] =
    [const { core::sync::atomic::AtomicU64::new(u64::MAX) }; 64];

/// How many it has asked, which may exceed what [`TRACED_SEEN`] holds.
pub static TRACED_CALLS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Starts recording `domain`'s foreign calls, discarding any previous run.
pub fn trace_domain(domain: u32) {
    use core::sync::atomic::Ordering;
    TRACED_CALLS.store(0, Ordering::Relaxed);
    for slot in TRACED_SEEN.iter() {
        slot.store(u64::MAX, Ordering::Relaxed);
    }
    TRACED_DOMAIN.store(domain, Ordering::Release);
}

/// Stops recording, and answers how many calls were seen.
pub fn stop_tracing() -> u64 {
    use core::sync::atomic::Ordering;
    TRACED_DOMAIN.store(u32::MAX, Ordering::Release);
    TRACED_CALLS.load(Ordering::Relaxed)
}

/// The first foreign syscall numbers of the **boot**, for the boot report —
/// the self-test asserts the exact sequence its probe issued.
///
/// Indexed by the global call counter, so it holds the opening calls of the
/// machine and not of any one program. [`TRACED_SEEN`] is the per-domain
/// answer, and exists because this one was read as though it were.
pub static FOREIGN_SEEN: [core::sync::atomic::AtomicU64; 32] =
    [const { core::sync::atomic::AtomicU64::new(u64::MAX) }; 32];

/// Answers one foreign system call: `-ENOSYS`, logged.
///
/// RFC 0005 step 2, whole and deliberate: no translation exists yet, so
/// every call is refused — but *observed*. The telemetry event carries the
/// Linux syscall number and the caller's `rip`, and the histogram of these
/// events is the personality's work queue: what a real workload asks for is
/// the specification, and this refusal path is how it gets written down.
/// Never silently succeed — the RFC names that as the one forbidden answer.
/// The boundary type every foreign handler below takes — RFC 0031's
/// interface I1, and the reason none of them reads a kernel structure.
use bhaskix_personality::call::{Dialect, PersonalityCall};

/// Linux syscall numbers this personality answers rather than refuses.
///
/// **Empty, as of RFC 0032 step 10 — and it is kept rather than deleted so
/// that it can be seen to be empty.** Its size was the measure of a boundary
/// violation: RFC 0031's interface I1 says the nucleus carries a foreign
/// call's number without interpreting it, every constant here was a number
/// the nucleus *did* interpret, and [`ANSWERED`] published the count on every
/// boot. It read eighteen on 2026-08-19 and reads zero now.
///
/// A number added back changes this array's length, which the boot report
/// prints and a gate refuses to let rise. That is why the module stays: a
/// deleted ratchet cannot hold anything.
mod linux {
    /// Every number the nucleus interprets, once, so the boundary has a size.
    ///
    /// **Kept by hand, and the honest caveat is that nothing enforces it.** A
    /// `match` arm added without a line here would leave this number too
    /// small — so the boot report prints it as a count of *declared*
    /// interpretation, and the gate is a ratchet on that declaration. There is
    /// no longer any dispatch for it to be derived from, which is the point.
    pub const ANSWERED: [u64; 0] = [];
}

fn foreign_call(frame: &mut SyscallFrame) {
    // **The boundary, as a value.** RFC 0031's interface I1: the nucleus is
    // meant to carry a foreign call rather than understand it, and building
    // this frame here is what makes the rest of this file a *personality*
    // that happens to be linked into the kernel rather than kernel code that
    // happens to speak Linux. When it moves into a domain (RFC 0031 §5) this
    // is the message; nothing below it changes.
    //
    // The register order is Linux's -- `rdi, rsi, rdx, r10, r8, r9` -- and
    // the frame's field names are RFC 0008's for the same six registers. The
    // mapping is written once, here, instead of in each handler, which is
    // where it was written wrongly twice.
    let call = PersonalityCall::new(
        Dialect::Linux,
        frame.kind,
        [
            frame.capability,
            frame.method,
            frame.arg0,
            frame.arg1,
            frame.arg2,
            frame.arg3,
        ],
        crate::sched::current_thread_id().unwrap_or(u32::MAX),
        crate::telemetry::domain_hint(),
    );

    // **Priced before it moves, which is the order RFC 0031 asks for.**
    // Relocating the personality into a domain costs one IPC round trip per
    // hosted system call that this placement does not pay, and a decision
    // taken on a guess about that number is a decision that cannot be
    // reviewed. So the in-nucleus cost is measured *now*, while it is the
    // only placement there is, and the domain placement will be measured the
    // same way against the same instrument -- which is exactly what RFC 0013
    // built the two-placement discipline for.
    //
    // Two `rdtsc`s on a path a hosted program takes hundreds of times per
    // second, and no more: no serialising instruction, because the question
    // is the mean over thousands of calls rather than any single one, and a
    // fence here would price the fence.
    //
    // The exclusion is decided **here**, before dispatch, and not inside the
    // pricing function where it began. Two calls a boot went unaccounted for
    // otherwise, and the reason is worth keeping: `exit` and `exit_group`
    // never return, so a price taken on the way out is a price never taken.
    // Deciding on the way in also saves the `rdtsc` on every call that was
    // never going to be priced.
    // **The exclusion list went with the last number** — RFC 0032 step 10.
    // It was itself a `match` on Linux syscall numbers in the nucleus, and
    // one the ratchet never counted, because it decided *pricing* rather than
    // *answers*: a boundary violation hiding behind an instrument. What is
    // left here prices one thing, the `-ENOSYS` fall-through taken when there
    // is no adapter, and that path cannot block.
    let number = call.number;
    let started = bhaskix_arch::tsc::read();

    let count = FOREIGN_CALLS.fetch_add(1, Ordering::Relaxed);
    if let Some(slot) = FOREIGN_SEEN.get(count as usize) {
        slot.store(number, Ordering::Relaxed);
    }
    // And this caller's own, if somebody is watching it -- see `TRACED_DOMAIN`
    // for why the table above cannot answer that question.
    if call.domain == TRACED_DOMAIN.load(Ordering::Acquire) {
        let at = TRACED_CALLS.fetch_add(1, Ordering::Relaxed);
        if let Some(slot) = TRACED_SEEN.get(at as usize) {
            slot.store(number, Ordering::Relaxed);
        }
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
    // `rt_sigreturn` used to be answered here, first and on its own, because
    // it is the one call that must not write a return value. It is the
    // adapter's now, and the shape survived the move: its reply is a
    // *register image* rather than a number, which is the same statement
    // made through the boundary instead of inside it.

    // The memory calls used to be tried here. All four now live in
    // `bin/linuxd` (RFC 0032 steps 4 and 5), so there is nothing between the
    // signal calls and the thread calls -- which is what this refactor looks
    // like from inside the nucleus: arms disappearing, one at a time.

    // The thread and futex calls used to be tried here, and were the last to
    // go (RFC 0032 steps 9 and 10). **There is now no `if` at all between a
    // foreign call arriving and the adapter being asked** -- which is what
    // interface I1 asked for, written as the absence of code rather than as a
    // paragraph.

    // **And what the nucleus does not answer is asked of the adapter** —
    // RFC 0031's interface I1, and RFC 0032's delivery. Note what is *not*
    // here: any list of which numbers the adapter handles. The kernel tries
    // what it still has and hands over the rest, so a call moving out of the
    // nucleus is a deletion here and an addition there, with nothing in
    // between that has to be kept in step.
    //
    // The call is made by the hosted thread itself, which blocks until the
    // reply. This is not the kernel becoming an IPC client: it is a trap
    // becoming a call on an endpoint the domain was given, which is what a
    // foreign system call has always been in this design.
    if let Some(value) = adapter_call(frame, &call) {
        frame.kind = value;
        // **Not priced here**, and that is what keeps the comparison honest:
        // `adapter_call` prices its own round trips, and folding them into the
        // nucleus figure would average two different placements into one
        // number that describes neither. The nucleus floor was 4,916 cycles
        // before any call moved; it went to 17,520 the moment adapter calls
        // were priced into it, which is how this was noticed.
        let _ = started;
        return;
    }

    // `rax` alone. `arg0` (the caller's `rdx`) is left exactly as the stub
    // saved it, which is what preserves it.
    frame.kind = bhaskix_personality::call::ENOSYS.value;
    price_foreign_call(started);
}

/// The endpoint a foreign call is delivered to, or zero for none.
///
/// **Kernel-side, and deliberately not in the hosted domain's CSpace.**
/// RFC 0031's interface I3: a hosted process holds no capabilities and can
/// name none, so putting its adapter's endpoint where it could reach it would
/// hand it exactly one — and the one that talks to the program with authority
/// over it.
///
/// One adapter for the machine, for now. RFC 0031's interface I5 wants one per
/// hosted workload, and this becomes a per-domain field when there is a second
/// workload to tell apart. The trigger is written down rather than left as a
/// surprise.
///
/// **`u64::MAX` is "none", and zero is a perfectly good endpoint id.** Using
/// zero as the sentinel cost a boot: the adapter was started, its thread was
/// blocked in `Recv`, and every foreign call reported finding no adapter —
/// because `ipc::create` had handed out id zero, which this read as absence.
/// The convention here is `u64::MAX`, as `NET_RING_REPORT` and `NET_CONFIG`
/// already use, and it is the convention for exactly this reason.
pub static ADAPTER_ENDPOINT: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(u64::MAX);

/// How many foreign calls the adapter answered, and how many it could not be
/// asked because it was not there.
pub static ADAPTER_ANSWERED: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// How many times a foreign call found no adapter at all.
///
/// **Three different things used to share this counter**, and the report said
/// only "found no adapter to ask" for every one of them: an adapter that was
/// not there, an endpoint that refused the message, and a caller that gave up
/// retrying against a queue that stayed full. They want different repairs — a
/// boot-order bug, a dead adapter, a machine under load — and one number
/// could not tell them apart. It took a deliberate three-way concurrent
/// reproduction to find that out, which is the second time in a day an
/// instrument has hidden the thing it was measuring.
pub static ADAPTER_ABSENT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// How many deliveries the endpoint refused outright.
pub static ADAPTER_REFUSED: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// How many were given up on after [`ADAPTER_RETRIES`] congested attempts.
pub static ADAPTER_GAVE_UP: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// How many deliveries ended because the *caller* was being killed.
pub static ADAPTER_CALLER_GONE: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);
/// Cycles spent in adapter round trips, how many were priced, and the
/// cheapest — the domain placement's figures, against the nucleus placement's
/// in [`FOREIGN_FLOOR`].
pub static ADAPTER_CYCLES: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// How many adapter round trips contributed a sample.
pub static ADAPTER_PRICED: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// The cheapest adapter round trip this boot.
pub static ADAPTER_FLOOR: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(u64::MAX);
/// The last reason a delivery was refused, so an absent adapter can be told
/// from a refused one without a rebuild.
pub static ADAPTER_REFUSAL: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Asks the adapter, blocking this thread until it answers.
///
/// `None` when there is no adapter, or when the endpoint has gone — in which
/// case the caller falls back to `-ENOSYS`, because a hosted program told
/// nothing at all would spin on a call that never returns.
///
/// The Linux call number travels as the message's `method` and the first four
/// arguments as its words. **Five and six do not fit**, and that is why the
/// calls needing them — `mmap` above all — are still answered in the nucleus:
/// moving them needs a page shared with the adapter rather than a message, and
/// a page needs somewhere to put it *per thread*, which is RFC 0032 step 4's
/// work rather than a thing to improvise here.
fn adapter_call(frame: &mut SyscallFrame, call: &PersonalityCall) -> Option<u64> {
    // **The loop is for one reply shape**: `BLOCK_ON_RETRY`, which parks the
    // caller and then asks the same question again. A blocking `read` needs
    // exactly that -- it must come back with *bytes*, not with the zero a
    // `futex` is answered when it wakes -- and the alternative, teaching the
    // nucleus which calls resume with what, is Linux knowledge arriving by the
    // back door.
    //
    // Bounded, because an adapter parking for ever on a condition that never
    // changes would otherwise loop here for ever. Sixteen turns is more than a
    // wake-and-retry needs and is not a number a hosted program can choose;
    // past it the caller is told `EAGAIN`.
    let mut first = true;
    for _ in 0..16 {
        let answer = ask_adapter_counted(
            u64::from(call.domain),
            call.number,
            [call.first(), call.second(), call.third(), call.fourth()],
            first,
        )?;
        first = false;
        match answer.0 {
            // **The adapter needs more than a message can carry.** Some Linux
            // calls take five or six arguments and a message has four, so the
            // caller's whole register frame is staged in a slot and the question
            // asked again. The nucleus never learns *which* calls those are,
            // which is the point -- teaching it would be Linux knowledge arriving
            // by the back door -- and only the calls that need it pay for it.
            crate::fault::reply::NEED_FRAME => {
                let slot = crate::fault::stage_frame(frame)?;
                let again = ask_adapter_full(
                    u64::from(call.domain),
                    crate::fault::FRAME_METHOD,
                    [slot as u64, call.number, 0, 0],
                );
                let value = match again {
                    Some((crate::fault::reply::RESTORE, _)) => {
                        restore_from_slot(frame, slot);
                        crate::fault::give_back(slot);
                        RESTORED.fetch_add(1, Ordering::Relaxed);
                        return Some(frame.kind);
                    }
                    Some((_, value)) => Some(value),
                    None => None,
                };
                crate::fault::give_back(slot);
                return value;
            }
            // Resume from a register image rather than from a value, which is
            // what `rt_sigreturn` is: the answer is not a number, it is the
            // thread's own state as its handler left it.
            crate::fault::reply::RESTORE => {
                let slot = usize::try_from(answer.1).ok()?;
                restore_from_slot(frame, slot);
                crate::fault::give_back(slot);
                RESTORED.fetch_add(1, Ordering::Relaxed);
                return Some(frame.kind);
            }
            // Acts on the *caller* that only the kernel can perform, chosen by
            // the dialect that knows what the call meant. None of them is a Linux
            // concept: giving up a slice, ending a thread, ending a domain.
            crate::fault::reply::YIELD => {
                crate::sched::yield_now();
                return Some(answer.1);
            }
            // The reply that blocks. The adapter names one of the notifications it
            // was granted at boot; the kernel parks *this* thread on it and
            // answers zero when somebody signals it. One notification per parked
            // waiter, which is what makes an exact wake count possible in ring 3
            // and what `notify::wait`'s single-waiter rule wants anyway.
            crate::fault::reply::BLOCK_ON_RETRY => {
                // **Park, and then ask the same question again** -- RFC 0033 step
                // 7. The difference from `BLOCK_ON` is what the caller gets when it
                // wakes: a `futex` is answered zero, which is what Linux's futex
                // returns, but a `read` answered zero has been told *end of file*.
                // So this shape resumes the call rather than completing it, and the
                // adapter answers the second time with the bytes that woke it.
                let Some(notification) = adapter_notification(answer.1) else {
                    return Some(-11i64 as u64); // EAGAIN
                };
                BLOCKED.fetch_add(1, Ordering::Relaxed);
                if crate::notify::wait(notification).is_err() {
                    return Some(-11i64 as u64);
                }
                continue;
            }
            crate::fault::reply::BLOCK_ON => {
                let Some(notification) = adapter_notification(answer.1) else {
                    // The adapter named something that is not a notification it
                    // holds. That is the adapter being wrong, not the caller, and
                    // a hosted program is told the truth it can act on: nothing
                    // slept, try again.
                    return Some(-11i64 as u64); // EAGAIN
                };
                BLOCKED.fetch_add(1, Ordering::Relaxed);
                match crate::notify::wait(notification) {
                    Ok(_) => return Some(0),
                    // Congested means another thread is already parked on this
                    // notification -- the adapter handed the same one out twice,
                    // which is its bug and is reported as one it cannot hide.
                    Err(_) => return Some(-11i64 as u64),
                }
            }
            crate::fault::reply::END_THREAD => crate::sched::exit(),
            crate::fault::reply::END_DOMAIN => {
                crate::domain::end(
                    crate::domain::DomainId::from_u32(call.domain),
                    crate::domain::Ending::Exited,
                );
                crate::sched::exit()
            }
            _ => return Some(answer.1),
        }
    }
    // Sixteen parks for one call: whatever the adapter is waiting for is not
    // coming, and a hosted program told to try again can decide for itself.
    Some(-11i64 as u64)
}

/// Puts a staged register image back into the system-call frame.
///
/// **Only what the frame carries**, which is the caller-saved set the entry
/// stub saved: `rax`, `rdi`, `rsi`, `rdx`, `r8`-`r10`, and `rip`, `rflags`
/// and the user stack pointer. `rbx`, `rbp` and `r12`-`r15` were never saved
/// and cannot be restored here -- the same stated narrowing `rt_sigreturn`
/// has carried since RFC 0005 step 4, and structural rather than a shortcut:
/// widening it means widening the entry stub.
fn restore_from_slot(frame: &mut SyscallFrame, slot: usize) {
    let Some(image) = crate::fault::take_frame(slot) else {
        return;
    };
    frame.kind = image[0];
    frame.arg0 = image[3];
    frame.method = image[4];
    frame.capability = image[5];
    frame.arg2 = image[7];
    frame.arg3 = image[8];
    frame.arg1 = image[9];
    frame.rip = image[15];
    // The flags a hosted program may choose, and no others -- as the fault
    // path's own restore, and for the same reason.
    frame.rflags = (frame.rflags & !USER_FLAGS) | (image[16] & USER_FLAGS);
    frame.user_rsp = image[17];
}

/// The `rflags` bits a hosted program may choose when it is resumed.
const USER_FLAGS: u64 = 0x0000_0CD5;

/// How many callers the adapter resumed from a register image rather than
/// answering with a value — which is what `rt_sigreturn` is, counted where
/// the kernel performs it because that is the only side that can see it now.
pub static RESTORED: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Asks the adapter one question, blocking this thread until it answers.
///
/// Shared by the system-call path and the fault path — RFC 0032 step 6 — so
/// that a fault is delivered by the same door a call is, with the same badge
/// discipline and the same congestion retry. The fault's *method* is
/// [`crate::fault::FAULT_METHOD`], which no Linux number can collide with.
///
/// `None` when there is no adapter, or when the endpoint has gone.
pub fn ask_adapter(domain: u64, what: u64, args: [u64; 4]) -> Option<u64> {
    ask_adapter_full(domain, what, args).map(|(_, value)| value)
}

/// As [`ask_adapter`], but answering the reply's *method* as well as its
/// value -- which is how the adapter says the answer is not a number.
fn ask_adapter_full(domain: u64, what: u64, args: [u64; 4]) -> Option<(u64, u64)> {
    ask_adapter_counted(domain, what, args, true)
}

/// As [`ask_adapter_full`], saying whether this ask is a *new* foreign call.
///
/// **A retry is the second half of one call, not a second call.** A blocking
/// `read` parks and asks again (RFC 0033 step 7's `BLOCK_ON_RETRY`), and
/// counting both asks made the boundary report say `SOME UNCOUNTED` on the
/// first boot after it existed — the same arithmetic catching the same class of
/// mistake for the *third* time. The fault path and the frame retry are
/// excluded by method name; this one cannot be, because a retried `read` is the
/// same number as the `read`.
fn ask_adapter_counted(
    domain: u64,
    what: u64,
    args: [u64; 4],
    counted: bool,
) -> Option<(u64, u64)> {
    let endpoint = ADAPTER_ENDPOINT.load(Ordering::Relaxed);
    if endpoint == u64::MAX {
        ADAPTER_ABSENT.fetch_add(1, Ordering::Relaxed);
        return None;
    }
    let endpoint = crate::ipc::EndpointId::from_u32(endpoint as u32);
    // The adapter cannot touch a hosted process's memory without a capability
    // to its domain, and the kernel is what has one to give.
    ensure_adapter_holds(domain as u32);
    // **The badge names the caller, and now names it fully.** Its low half is
    // the hosted domain, as it always was; its high half is the calling
    // thread, plus one so that no thread is ever zero. The adapter needs both
    // and can forge neither -- the kernel stamps a badge from the capability
    // actually used, which is the entire reason it can be believed.
    let badge =
        domain | (u64::from(crate::sched::current_thread_id().map_or(0, |id| id + 1)) << 32);

    // Congestion is retried, and it is safe to retry precisely because it
    // cannot half-happen: the message was refused *before* being queued, so
    // the adapter never saw it. The endpoint's queue is sixteen deep, so an
    // eighteenth hosted thread arriving at once would otherwise be told its
    // system call failed for a reason that is nothing to do with the call.
    // `bin/shell` has done this since RFC 0015 and says why at more length.
    let started = bhaskix_arch::tsc::read();
    for _ in 0..ADAPTER_RETRIES {
        // The badge says which hosted domain is asking, and the kernel is
        // what stamps it. A caller cannot supply its own, which is the whole
        // reason the adapter can believe it.
        match crate::ipc::call(endpoint, badge, what, args) {
            Ok(message) => {
                // Counted only for a *system call*. A fault delivered through
                // this same door is counted by `fault::HANDED`, and folding
                // the two together broke the boundary report's own arithmetic
                // -- "37 of 36 accounted" -- which is the instrument catching
                // its keeper, exactly as it was built to.
                // Neither a fault nor a *retry* is a system call. The retry
                // is the second half of one already counted, and counting it
                // again broke the boundary report's arithmetic the first boot
                // after it existed -- the same instrument catching the same
                // class of mistake for the second time in two steps.
                if counted
                    && what != crate::fault::FAULT_METHOD
                    && what != crate::fault::FRAME_METHOD
                    && what != FORGET_METHOD
                {
                    ADAPTER_ANSWERED.fetch_add(1, Ordering::Relaxed);
                }
                // **Priced separately from the in-nucleus path, because the
                // comparison is the point.** A single figure over both
                // placements is an average of two different things and tells
                // a reviewer nothing about what the move costs; two figures
                // measured by the same instrument on the same boot is exactly
                // what RFC 0031's performance section asks for.
                if let Some(spent) = bhaskix_arch::tsc::read().checked_sub(started)
                    && spent <= 100_000_000
                {
                    ADAPTER_CYCLES.fetch_add(spent, Ordering::Relaxed);
                    ADAPTER_PRICED.fetch_add(1, Ordering::Relaxed);
                    ADAPTER_FLOOR.fetch_min(spent, Ordering::Relaxed);
                }
                return Some((message.method, message.args[0]));
            }
            Err(crate::ipc::IpcError::Congested) => {
                crate::sched::yield_now();
            }
            // The adapter has gone, or was never there. A hosted program is
            // told `-ENOSYS` rather than left blocked on an answer that is not
            // coming: the call it made is one this machine cannot perform, and
            // that is true whichever way the adapter is absent.
            // **A caller that is being killed is not an adapter failure**,
            // and telling them apart matters because one is a defect and the
            // other is teardown working. A thread whose domain has been ended
            // is woken out of its wait with `Abandoned`, which arrives here
            // as `NoSuchEndpoint` — the same value a genuinely missing
            // endpoint gives. The thread's own dying flag is what separates
            // them, and without this the suite reported "1 were refused by
            // its endpoint" for a boot in which nothing was wrong.
            // **Exact, and taken before the guess below.** The scheduler knew
            // this thread was dying at the moment it stopped waiting, and now
            // says so instead of leaving it to be inferred.
            Err(crate::ipc::IpcError::CallerDying) => {
                ADAPTER_CALLER_GONE.fetch_add(1, Ordering::Relaxed);
                return None;
            }
            // Kept as a second net rather than deleted: this covers the paths
            // that reach `NoSuchEndpoint` without passing through the wait —
            // a lookup that finds the endpoint already gone, say. It is the
            // arm that could answer wrongly under a contended runqueue, and
            // `sched::DYING_UNKNOWN` counts how often it could not tell.
            Err(crate::ipc::IpcError::NoSuchEndpoint) if crate::sched::should_die() => {
                ADAPTER_CALLER_GONE.fetch_add(1, Ordering::Relaxed);
                return None;
            }
            Err(why) => {
                ADAPTER_REFUSED.fetch_add(1, Ordering::Relaxed);
                ADAPTER_REFUSAL.store(
                    match why {
                        crate::ipc::IpcError::NoSuchEndpoint => 1,
                        crate::ipc::IpcError::ServerGone => 2,
                        crate::ipc::IpcError::Congested => 3,
                        _ => 4,
                    },
                    Ordering::Relaxed,
                );
                return None;
            }
        }
    }
    ADAPTER_GAVE_UP.fetch_add(1, Ordering::Relaxed);
    None
}

/// How many times a congested delivery is retried before the call is refused.
const ADAPTER_RETRIES: u32 = 1024;

/// The adapter's own domain, so capabilities can be installed in its CSpace.
pub static ADAPTER_DOMAIN: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(u32::MAX);

/// The lowest CSpace slot a hosted domain's `Domain` capability may be put in.
///
/// **Allocated from here rather than computed — RFC 0033 step 3.** It used to
/// be `32 + domain id`, which needed no table on either side and reserved one
/// slot per domain *whether or not that domain existed*: half a CSpace, held
/// against a machine that has two hosted programs. A descriptor is a
/// capability the adapter holds, so that reservation is exactly what L1 would
/// have run out of.
///
/// Now the kernel takes the lowest free slot at or above this floor and
/// **tells the adapter which** ([`HANDLE_METHOD`]). The floor is above the
/// fixed grants `start_linux_domain` makes — the endpoint, two pages, the
/// console and the futex pool — so an allocation can never collide with one.
const ADAPTER_SLOT_FLOOR: usize = 24;

/// The method that says "your `Domain` capability for this domain is in this
/// slot".
///
/// `u64::MAX - 3`, beside [`FORGET_METHOD`] and for the same reason: no Linux
/// number can collide with it, and a hosted program never chooses a method
/// anyway. Sent once per incarnation, before the first foreign call of that
/// domain is delivered — the message is an ordinary call made by the hosted
/// thread itself, so it completes before the call that provoked it.
pub const HANDLE_METHOD: u64 = u64::MAX - 3;

/// Which CSpace slot each domain's handle was put in, plus one — zero meaning
/// none has been allocated.
static ADAPTER_SLOT: [core::sync::atomic::AtomicU32; crate::domain::MAX_DOMAINS] =
    [const { core::sync::atomic::AtomicU32::new(0) }; crate::domain::MAX_DOMAINS];

/// Which incarnation of each domain the adapter has been given, plus one —
/// zero meaning none.
///
/// **Keyed by generation and not by "have we done this", because a domain
/// slot is reused.** Handing the adapter a capability for domain 3 and
/// leaving it there means the *next* domain 3 arrives with its predecessor's
/// handle already installed, and every operation on it is refused for a
/// reason that has nothing to do with what was asked. The kernel already
/// learned this once, on 2026-08-19, when a thread outliving its domain
/// decremented a counter the next occupant owned.
static ADAPTER_HELD: [core::sync::atomic::AtomicU64; crate::domain::MAX_DOMAINS] =
    [const { core::sync::atomic::AtomicU64::new(0) }; crate::domain::MAX_DOMAINS];

/// Makes sure the adapter holds a `Domain` capability for `domain`.
///
/// **This is the authority the adapter needs to do anything to a hosted
/// process's memory**, and it is granted by the kernel because the kernel is
/// what created the domain. RFC 0031's interface I5 wants the adapter to
/// create hosted domains itself, at which point it holds the capability by
/// construction and this function goes away; until something other than a
/// self-test makes a Linux domain, this is the honest stand-in and it is
/// written down as one.
///
/// Idempotent per incarnation: the generation is recorded, so this costs one
/// relaxed load per foreign call once a domain is known.
/// Resolves a capability index **in the adapter's CSpace** to a notification.
///
/// The one place kernel code reads another domain's CSpace for a hosted
/// program's benefit, and it is deliberately narrow: the index comes from the
/// adapter's own reply, the kind is checked, and what comes back is an object
/// id rather than a capability. A hosted process never sees any of it.
fn adapter_notification(index: u64) -> Option<crate::notify::NotificationId> {
    let adapter = ADAPTER_DOMAIN.load(Ordering::Relaxed);
    if adapter == u32::MAX {
        return None;
    }
    let index = usize::try_from(index).ok()?;
    let slot = crate::domain::with(crate::domain::DomainId::from_u32(adapter), |owner| {
        owner.cspace.get(index)
    })??;
    let (object, _) = cap::with_arena(|arena| arena.lookup(slot))?;
    if object.kind != cap::ObjectKind::Notification {
        return None;
    }
    // Packed as every other reader of a `Notification` capability unpacks it:
    // index in the low half, generation in the high.
    Some(crate::notify::NotificationId::from_parts(
        object.id as u32,
        (object.id >> 32) as u32,
    ))
}

/// Hosted threads parked on a notification by an adapter's `BLOCK_ON`.
pub static BLOCKED: AtomicU64 = AtomicU64::new(0);

fn ensure_adapter_holds(domain: u32) -> bool {
    ensure_adapter_holds_inner(domain).unwrap_or(false)
}

/// The forget message: this domain slot has been reused, so whatever the
/// adapter remembers about it belongs to somebody else.
///
/// **A domain id is reused and the adapter keeps state keyed by it.** Signal
/// dispositions moved out of the nucleus at RFC 0032 step 7, which means a
/// new domain 3 would inherit the old domain 3's handlers — and a program
/// that never installed one would survive a fault it should have died on.
/// This kernel learned the same lesson twice already: once when a thread
/// outliving its domain decremented its successor's counter, and once when
/// the adapter was handed a stale `Domain` capability.
pub const FORGET_METHOD: u64 = u64::MAX - 1;

fn ensure_adapter_holds_inner(domain: u32) -> Option<bool> {
    let adapter = ADAPTER_DOMAIN.load(Ordering::Relaxed);
    if adapter == u32::MAX {
        return Some(false);
    }
    let slot = ADAPTER_HELD.get(domain as usize)?;
    let id = crate::domain::DomainId::from_u32(domain);
    let generation = crate::domain::with(id, |owner| owner.generation())?;
    let wanted = u64::from(generation) + 1;
    let held = slot.load(Ordering::Relaxed);
    if held == wanted {
        return Some(true);
    }

    let handle = cap::with_arena(|arena| {
        arena
            .insert_root(
                cap::ObjectRef::new(cap::ObjectKind::Domain, u64::from(domain)),
                cap::Rights::ALL,
                0,
            )
            .ok()
    });
    let handle = handle?;
    let previous = ADAPTER_SLOT.get(domain as usize)?;
    let adapter_id = crate::domain::DomainId::from_u32(adapter);
    // The slot is allocated, and the *old* one is given back first: a
    // previous incarnation's handle is authority over a domain that no longer
    // exists, and leaving it installed would both leak a slot and leave the
    // adapter able to name a stale capability.
    let index = crate::domain::with(adapter_id, |owner| {
        if let Some(held) = previous.load(Ordering::Relaxed).checked_sub(1) {
            let _ = owner.cspace.remove(held as usize);
        }
        let index = owner.cspace.first_free_at_or_above(ADAPTER_SLOT_FLOOR)?;
        owner.cspace.install_at(index, handle).ok()?;
        Some(index)
    })??;
    previous.store(index as u32 + 1, Ordering::Relaxed);
    slot.store(wanted, Ordering::Relaxed);
    // **Only when a *previous* incarnation was remembered.** The first grant
    // for a fresh slot has nothing to forget, and telling the adapter to
    // forget something it never knew would cost a round trip on the first
    // foreign call of every hosted program.
    let endpoint = ADAPTER_ENDPOINT.load(Ordering::Relaxed);
    if endpoint != u64::MAX {
        let endpoint = crate::ipc::EndpointId::from_u32(endpoint as u32);
        if held != 0 {
            let _ = crate::ipc::call(endpoint, u64::from(domain), FORGET_METHOD, [0; 4]);
        }
        // **And where to find it**, which is no longer computable from the
        // domain id. Sent after the forget, so an adapter that clears its row
        // for a reused domain does not clear the slot it is about to be told.
        let _ = crate::ipc::call(
            endpoint,
            u64::from(domain),
            HANDLE_METHOD,
            [index as u64, 0, 0, 0],
        );
    }
    Some(true)
}

/// Records what one foreign call cost.
fn price_foreign_call(started: u64) {
    let ended = bhaskix_arch::tsc::read();
    let Some(spent) = ended.checked_sub(started) else {
        FOREIGN_COST_DROPPED.fetch_add(1, Ordering::Relaxed);
        return;
    };
    // **A million cycles, and the number moved once for a good reason.** It
    // was twenty thousand, calibrated against the in-nucleus placement where
    // an answered call is a few thousand — and when the first call moved to
    // the adapter, *every* sample went past it and the whole report vanished,
    // because a report that prints nothing when its instrument saturates is
    // what this was. An IPC round trip to ring 3 is worth hundreds of
    // thousands of cycles under emulation and that is the figure this
    // instrument exists to capture, not to discard. What the cap is for is
    // preemptions and migrations, which are milliseconds; a million cycles is
    // comfortably below one and comfortably above the thing being measured.
    if spent > 1_000_000 {
        FOREIGN_COST_DROPPED.fetch_add(1, Ordering::Relaxed);
        return;
    }
    FOREIGN_CYCLES.fetch_add(spent, Ordering::Relaxed);
    FOREIGN_PRICED.fetch_add(1, Ordering::Relaxed);
    // The floor, which is the figure worth comparing placements on: a mean
    // carries whatever else the machine was doing, and a minimum over
    // hundreds of samples is the cost with nothing in the way.
    FOREIGN_FLOOR.fetch_min(spent, Ordering::Relaxed);
}

/// Total cycles spent inside the foreign path, and how many calls that is.
///
/// RFC 0031's "priced first": the in-nucleus placement's number, taken now
/// so the domain placement has something to be compared against.
pub static FOREIGN_CYCLES: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// How many foreign calls contributed a usable sample.
pub static FOREIGN_PRICED: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// How many samples were thrown away as preemptions or migrations. Reported,
/// because a mean over an unstated fraction of the calls is not a mean.
pub static FOREIGN_COST_DROPPED: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);
/// The cheapest foreign call this boot — the boundary's cost with nothing in
/// the way, and the figure two placements can honestly be compared on.
pub static FOREIGN_FLOOR: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(u64::MAX);

/// What the foreign path has cost: calls priced, mean cycles, samples
/// dropped, and how many Linux numbers the nucleus declares it interprets.
#[must_use]
pub fn adapter_cost() -> (u64, u64, u64) {
    let priced = ADAPTER_PRICED.load(Ordering::Relaxed);
    let floor = ADAPTER_FLOOR.load(Ordering::Relaxed);
    (
        priced,
        if floor == u64::MAX { 0 } else { floor },
        ADAPTER_CYCLES
            .load(Ordering::Relaxed)
            .checked_div(priced)
            .unwrap_or(0),
    )
}

/// What an adapter round trip has cost: calls priced, floor, mean.
#[must_use]
pub fn foreign_cost() -> (u64, u64, u64, u64, usize) {
    let priced = FOREIGN_PRICED.load(Ordering::Relaxed);
    let cycles = FOREIGN_CYCLES.load(Ordering::Relaxed);
    let mean = cycles.checked_div(priced).unwrap_or(0);
    let floor = FOREIGN_FLOOR.load(Ordering::Relaxed);
    (
        priced,
        if floor == u64::MAX { 0 } else { floor },
        mean,
        FOREIGN_COST_DROPPED.load(Ordering::Relaxed),
        linux::ANSWERED.len(),
    )
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
    let foreign = (hint as usize) < crate::domain::MAX_DOMAINS
        && crate::domain::LINUX_DOMAINS.load(core::sync::atomic::Ordering::Relaxed)
            & (1u64 << hint)
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

/// The supervisor interface: what a program may do to a domain it holds.
///
/// [RFC 0032](../../docs/rfc/0032-a-supervisor-interface.md). `START` lets a
/// supervisor hand a child an image and let go; these five let it *keep hold*
/// — read and write the child's memory, and change its mappings. Nothing here
/// is a Linux concept: a debugger, a checkpointer and a container runtime want
/// the same five, which is why they are proved by `bin/sup` rather than by the
/// Linux personality that motivated them.
///
/// **The authority is the `Domain` capability carrying `WRITE`**, exactly as
/// `START` and `PERSONALITY` already require. A program that was not given one
/// can do none of this and has no way to obtain one by asking. Revoking it
/// ends the reach before the call returns, like every capability here.
///
/// **The reach is one-directional.** The held domain gains nothing: its CSpace
/// is untouched, which is what keeps RFC 0031's interface I3 true — a hosted
/// process holds no capabilities and can name none, whatever its supervisor
/// can do.
///
/// `None` when the capability is not a `Domain`, so the numbers stay available
/// to the kinds that own them.
fn domain_supervise(frame: &SyscallFrame) -> Option<Outcome> {
    let me = crate::sched::current_domain()?;
    let (object, rights) = domain::with(me, |owner| {
        let slot = owner.cspace.get(frame.capability as usize)?;
        cap::with_arena(|arena| arena.lookup(slot))
    })
    .flatten()?;
    if object.kind != ObjectKind::Domain {
        return None;
    }
    if !rights.contains(crate::cap::Rights::WRITE) {
        return Some(Outcome::err(Status::InsufficientRights));
    }
    let target = domain::DomainId::from_u32(object.id as u32);

    // Operating on yourself through this door is refused. Not because it is
    // dangerous -- a domain can already map its own memory -- but because the
    // two paths would then differ: `ATTACH` charges the caller and checks its
    // own space, and this does neither. One room, one lock.
    if target == me {
        return Some(Outcome::err(Status::WrongObject));
    }

    // **Before the root is demanded, because this is the call that makes one.**
    // RFC 0033 step 5: a supervisor assembling a process by hand needs the
    // domain to have an address space before it can map a page into it, and
    // every other way to get one is to be a thread inside the domain — which
    // there is not one of yet, and cannot be until its pages exist.
    // **Input, for a domain somebody granted it** — RFC 0053.
    //
    // The authority is named on the *domain* rather than on the console, which
    // is what lets the adapter's console capability stay `WRITE` alone: it can
    // put a byte on its own account and can take one only for a domain a
    // grant names. A compromised adapter therefore reads keystrokes for granted
    // domains and no others, and the check is here rather than in it.
    if frame.method == method::TAKE_INPUT || frame.method == method::POLL_INPUT {
        if !rights.contains(crate::cap::Rights::READ) {
            return Some(Outcome::err(Status::InsufficientRights));
        }
        if !domain::may_read_input(target.as_u32()) {
            // Not "no byte" but "not yours": a caller told the console was
            // merely empty would ask again for ever.
            return Some(Outcome::err(Status::InsufficientRights));
        }
        return Some(if frame.method == method::POLL_INPUT {
            match crate::input::try_read() {
                Some(byte) => Outcome::ok(u64::from(byte)),
                None => Outcome::ok(bhaskix_abi::method::NOTHING),
            }
        } else {
            Outcome::ok(u64::from(crate::input::read()))
        });
    }

    if frame.method == method::MAKE_SPACE {
        if domain::space_root_of(target).is_some() {
            // Already has one. Replacing it would unmap whatever is running in
            // it, which is a different operation and needs its own argument.
            return Some(Outcome::err(Status::SlotUnavailable));
        }
        if crate::sched::threads_counted_in(target.as_u32()) != 0 {
            return Some(Outcome::err(Status::SlotUnavailable));
        }
        let Ok(space) = crate::vm::AddressSpace::new(crate::shared::hhdm()) else {
            return Some(Outcome::err(Status::Exhausted));
        };
        return Some(match crate::vm::register_for(target, space) {
            // The root is not answered: it is a physical address, and a
            // program that could learn one would hold a fact about the machine
            // that no capability gave it. The caller names the *domain* for
            // everything it does next, which is what it held already.
            Some(_) => Outcome::ok(0),
            None => Outcome::err(Status::Exhausted),
        });
    }

    // The target's page-table root *is* the authority to touch its memory, and
    // it is fetched from the domain the capability named rather than supplied.
    // A domain that has not started, or has ended, has none -- which is the
    // honest refusal for "operate on a program that is not there".
    let Some(root) = domain::space_root_of(target) else {
        return Some(Outcome::err(Status::NoSuchCapability));
    };

    Some(match frame.method {
        method::COPY_IN | method::COPY_OUT => {
            let outward = frame.method == method::COPY_OUT;
            // The caller's own object, resolved out of the caller's own
            // CSpace with the rights the direction needs: reading the target
            // into it is a write to the object, and vice versa.
            let needs = if outward {
                crate::cap::Rights::READ
            } else {
                crate::cap::Rights::WRITE
            };
            let Some(thread) = crate::sched::current_thread_id() else {
                return Some(Outcome::err(Status::NoSuchCapability));
            };
            let Some(memory) = crate::shared::caller_object_for(thread, frame.arg0, needs) else {
                return Some(Outcome::err(Status::NoSuchCapability));
            };
            let (offset, address, length) = (frame.arg1, frame.arg2, frame.arg3);
            match copy_across(root, memory, offset, address, length, outward) {
                Some(moved) => Outcome::ok(moved),
                None => Outcome::err(Status::NoSuchCapability),
            }
        }
        method::MAP_AT => {
            let (address, pages, protection) = (frame.arg0, frame.arg1, frame.arg2);
            let Some(protection) = protection_from(protection) else {
                return Some(Outcome::err(Status::WrongObject));
            };
            // Bit 0 of the flags asks for a *lazy* mapping: the region is
            // recorded and no frame is taken until the domain touches a page.
            //
            // **This is what a hosted `mmap` needs and an eager mapping cannot
            // give it.** A Go runtime reserves address space by the gigabyte
            // and touches a little of it; charging frames for the reservation
            // would refuse a program on a machine with ample memory. A lazy
            // mapping is therefore not bounded by `MAX_SUPERVISED_PAGES` --
            // that bound exists because eager pages cost frames *now*, and
            // these cost none until they are touched.
            let lazy = frame.arg3 & 1 != 0;
            // Bit 1 says the caller *demands* this address and accepts that
            // whatever is there is discarded -- Linux's `MAP_FIXED`, whose
            // specification is exactly that: "if the memory region specified
            // overlaps pages of any existing mapping, then the overlapping
            // part will be discarded".
            //
            // **Opt-in, and the default stays a refusal.** RFC 0032 says a
            // `MAP_AT` over an existing region is refused rather than silently
            // replaced, because an adapter that thought it was making a new
            // mapping and actually replaced a live one is a bug that presents
            // as memory corruption a long way from its cause. A caller that
            // means to replace says so.
            //
            // Whole regions only, like `PROTECT_AT` and for its reason:
            // splitting a live range in three because a caller re-mapped its
            // middle is a different piece of work with its own failure modes.
            // That is enough for the pattern that motivated it -- a Go runtime
            // reserves an arena `PROT_NONE` and commits *the same range*
            // read-write -- and a partial overlap is refused where it can be
            // seen rather than approximated.
            let replace = frame.arg3 & 2 != 0;
            if pages == 0 || (!lazy && pages > MAX_SUPERVISED_PAGES) {
                return Some(Outcome::err(Status::WrongObject));
            }
            let Some(range) =
                bhaskix_mm::VirtRange::from_pages(bhaskix_boot::VirtAddr(address), pages)
            else {
                return Some(Outcome::err(Status::WrongObject));
            };
            // **Eagerly, and the reason is a limitation rather than a
            // preference.** A supervisor maps a page in order to *write* it,
            // and a copy needs a frame to write into: `translate` answers
            // nothing for a lazily-mapped page, so `COPY_OUT` straight after a
            // lazy `MAP_AT` is refused for a page that is legitimately mapped.
            // That is exactly what happened the first time this was built.
            //
            // Servicing it properly means committing a lazy page on demand
            // from outside the fault handler, and the commit is currently
            // welded to `vm::handle_fault` — the active space, and this CPU's
            // frame reserve, for reasons that are good ones there. Extracting
            // it is step 4's work, because that is when a hosted `mmap` needs
            // laziness for a reservation it will never touch all of. Until
            // then a supervisor pays for what it maps, and the bound below is
            // what stops that being unreasonable.
            let mapped = crate::vm::with_space(root, |space| {
                if replace {
                    // Only an exact match is discarded. `unmap` frees the
                    // frames of an eager region and has nothing to free for a
                    // lazy one, which is the common case here: a reservation
                    // nobody has touched yet.
                    let exact = space
                        .regions()
                        .find(bhaskix_boot::VirtAddr(address))
                        .is_some_and(|region| {
                            region.range.start.as_u64() == address && region.range.pages() == pages
                        });
                    if exact {
                        let _ = space.unmap(bhaskix_boot::VirtAddr(address));
                    }
                }
                if lazy {
                    space.map_anonymous_lazy(range, protection).is_ok()
                } else {
                    space.map_anonymous(range, protection).is_ok()
                }
            });
            if replace {
                crate::tlb::shootdown(address);
            }
            match mapped {
                Some(true) => Outcome::ok(address),
                _ => Outcome::err(Status::QuotaExceeded),
            }
        }
        method::SET_TLS => {
            // The thread is named by id, and must belong to the domain this
            // capability names -- a supervisor holds one domain's threads and
            // not another's, and `set_fs_base` would happily set any.
            let (thread, base) = (frame.arg0, frame.arg1);
            let Ok(thread) = u32::try_from(thread) else {
                return Some(Outcome::err(Status::WrongObject));
            };
            if crate::sched::domain_of(thread) != Some(target) {
                return Some(Outcome::err(Status::NoSuchCapability));
            }
            if crate::sched::set_fs_base(thread, base) {
                Outcome::ok(0)
            } else {
                Outcome::err(Status::NoSuchCapability)
            }
        }
        method::SPAWN_THREAD => {
            // The mechanism `clone` needs, and none of `clone`'s meaning: an
            // entry, a stack, and one word handed over in `rdi`. Which flags
            // made this legal, what a thread group is, and what the caller
            // gets back are the personality's, in ring 3.
            let (entry, stack, argument) = (frame.arg0, frame.arg1, frame.arg2);
            if entry == 0 || stack == 0 {
                return Some(Outcome::err(Status::WrongObject));
            }
            if crate::domain::record_pending_clone(target, entry, stack, argument).is_err() {
                return Some(Outcome::err(Status::QuotaExceeded));
            }
            let cpu = crate::domain::next_start_cpu();
            let options = crate::sched::SpawnOptions::new()
                .pinned()
                .in_domain(target.as_u32());
            match crate::sched::spawn_on_with(
                cpu,
                "cloned",
                crate::cloned_thread,
                u64::from(target.as_u32()),
                crate::shared::hhdm(),
                options,
            ) {
                Ok(id) => Outcome::ok(u64::from(id)),
                Err(_) => {
                    crate::domain::take_pending_clone(target);
                    Outcome::err(Status::Exhausted)
                }
            }
        }
        method::UNMAP_AT => {
            let unmapped = crate::vm::with_space(root, |space| {
                space.unmap(bhaskix_boot::VirtAddr(frame.arg0)).is_ok()
            });
            match unmapped {
                Some(true) => {
                    // The target may be running on another CPU right now, so
                    // the stale translation has to go the way `shared::revoke`
                    // sends it. An unmap whose shootdown is skipped is a page
                    // the other CPU can still write after it was taken away.
                    crate::tlb::shootdown(frame.arg0);
                    Outcome::ok(0)
                }
                _ => Outcome::err(Status::NoSuchCapability),
            }
        }
        method::PROTECT_AT => {
            let (address, pages, protection) = (frame.arg0, frame.arg1, frame.arg2);
            let Some(protection) = protection_from(protection) else {
                return Some(Outcome::err(Status::WrongObject));
            };
            let changed = crate::vm::with_space(root, |space| {
                space
                    .protect(bhaskix_boot::VirtAddr(address), pages, protection)
                    .is_ok()
            });
            match changed {
                Some(true) => {
                    crate::tlb::shootdown(address);
                    Outcome::ok(0)
                }
                _ => Outcome::err(Status::NoSuchCapability),
            }
        }
        _ => return None,
    })
}

/// Reads a protection word, refusing what the region map cannot represent.
///
/// The same encoding `ATTACH` takes. **Writable-and-executable is not a value
/// this can return**, because [`bhaskix_mm::Protection`] has no such variant —
/// so `W^X` is inherited by a supervisor for free rather than checked for.
fn protection_from(word: u64) -> Option<bhaskix_mm::Protection> {
    match word {
        0 => Some(bhaskix_mm::Protection::None),
        1 => Some(bhaskix_mm::Protection::ReadOnly),
        2 => Some(bhaskix_mm::Protection::ReadWrite),
        3 => Some(bhaskix_mm::Protection::ReadExecute),
        _ => None,
    }
}

/// Moves bytes between a `Memory` object and a domain's memory.
///
/// **Through the direct map, page by page, and never through a mapping.**
/// `uaccess::copy_to_user` resolves through `CR3` and so can only reach the
/// space that is loaded — which for a supervisor is its own, and the wrong
/// one. The idiom here is `elf::load_into`'s: ask the space to `translate` an
/// address to a frame, then write that frame through the direct map. It is
/// the same reason and the same shape: the target's mapping may be read-only,
/// or not yet faulted in, and neither should stop a supervisor that holds the
/// authority to write it.
///
/// Answers how many bytes moved, or `None` if the range is not wholly mapped —
/// **refused whole rather than partially moved**, because a supervisor told
/// "300 of 4,096" cannot tell a short object from a hole in the target, and
/// the two want different repairs.
fn copy_across(
    root: u64,
    memory: crate::shared::MemoryId,
    offset: u64,
    address: u64,
    length: u64,
    outward: bool,
) -> Option<u64> {
    let length = usize::try_from(length).ok()?;
    let offset = usize::try_from(offset).ok()?;
    if length == 0 {
        return Some(0);
    }
    // A bound the caller cannot raise: this is a system call, and a supervisor
    // asking to move a gigabyte would hold the domain table for as long as it
    // took. Larger transfers are more calls, which is also what makes them
    // interruptible.
    if length > MAX_SUPERVISED_COPY {
        return None;
    }
    address.checked_add(length as u64)?;

    let hhdm = crate::shared::hhdm();
    let mut moved = 0usize;
    while moved < length {
        let at = address + moved as u64;
        let page = at & !(bhaskix_mm::FRAME_SIZE - 1);
        let within = (at - page) as usize;
        let room = (bhaskix_mm::FRAME_SIZE as usize - within).min(length - moved);
        // Translated per page, because a region is not one frame and a lazily
        // mapped one has holes until it is touched.
        //
        // **Which accessor is the whole statement of intent.** A write commits
        // the page and a read does not, and saying which this copy is doing is
        // the only decision this loop makes about it — the rule itself lives in
        // `vm::frame_for_write`, where the next supervisor write will find it
        // without having to be told. This site used to carry the rule in a
        // comment; three bugs of one shape on 2026-08-20 are why it does not
        // any more.
        let frame = if outward {
            crate::vm::frame_for_write(root, page)?
        } else {
            crate::vm::frame_for_read(root, page)?
        };
        let physical = hhdm + (frame & !(bhaskix_mm::FRAME_SIZE - 1)) + within as u64;
        let carried = if outward {
            let mut taken = 0usize;
            crate::shared::drain_into(memory, offset + moved + room, |chunk| {
                // `drain_into` starts at the object's beginning, so the bytes
                // before `offset + moved` are walked past rather than copied.
                let skip = (offset + moved).saturating_sub(taken);
                let start = skip.min(chunk.len());
                let take = (chunk.len() - start).min(room);
                if take > 0 {
                    // SAFETY: `physical` is inside a frame the target's space
                    // translated for this page, viewed through the direct map,
                    // and `take` is bounded by what is left in this frame.
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            chunk[start..].as_ptr(),
                            physical as *mut u8,
                            take,
                        );
                    }
                }
                taken += chunk.len();
                chunk.len()
            })?;
            room
        } else {
            crate::shared::fill_from(memory, offset + moved, room, |slot| {
                let take = slot.len().min(room);
                // SAFETY: as above, in the other direction — the source is a
                // frame the target's space translated, and `take` is bounded
                // by both the object's slot and what is left in the frame.
                unsafe {
                    core::ptr::copy_nonoverlapping(physical as *const u8, slot.as_mut_ptr(), take);
                }
                take
            })?
        };
        if carried == 0 {
            break;
        }
        moved += carried;
    }
    u64::try_from(moved).ok()
}

/// The most one `COPY_IN`/`COPY_OUT` will move.
///
/// One page. Not a performance number — a *latency* one: this runs inside a
/// system call, and a supervisor that asked to move a gigabyte would make its
/// own call the machine's longest. Larger transfers are more calls, and more
/// calls are interruptible.
const MAX_SUPERVISED_COPY: usize = bhaskix_mm::FRAME_SIZE as usize;

/// The longest run `PUT_RUN` will put under one lock — RFC 0050.
///
/// `bin/linuxd`'s own `WRITE_BYTES`, so a hosted `write` of a line is a single
/// invocation. It is the kernel's number rather than the caller's because the
/// console lock is held for the whole run.
const MAX_CONSOLE_RUN: usize = 256;

/// The most pages one `MAP_AT` will map.
///
/// Sixty-four — a quarter of a megabyte — because the mapping is eager (see
/// `MAP_AT`) and a system call that allocated an unbounded number of frames
/// would be a system call that can exhaust the machine for whoever runs next.
/// A supervisor wanting more asks again, which also makes it interruptible.
const MAX_SUPERVISED_PAGES: u64 = 64;

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
    // RFC 0044: a revocation of mapped memory decides *inside* the locks and
    // acts outside them. Empty for every method but `REVOKE`, and for a
    // `REVOKE` whose object nobody mapped.
    let mut unmapping: Option<Unmapping> = None;
    let outcome = domain::with(id, |domain| {
        let mut cspace = core::mem::take(&mut domain.cspace);
        let before = cspace.occupied();
        let outcome = cap::with_arena(|arena| {
            invoke_capability(
                frame,
                owner,
                &mut cspace,
                arena,
                &mut revoked,
                &mut unmapping,
            )
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

    // **And the memory, last, with every lock this needed gone** -- RFC 0044.
    // `security.md` §2 rule 3 says a revocation is immediate and transitive;
    // it was true of capabilities and false of the pages they named, which is
    // how a borrower went on reading a frame its lender had taken back,
    // unpinned and refilled.
    //
    // The address-space roots are resolved here rather than inside `shared`,
    // because `space_root_of` takes `Rank::Domains` (6) and `shared::ARENA` is
    // `Rank::SharedMemory` (12): looking a domain up under the shared arena
    // would be an inversion of its own. Roots cross the boundary, not domains.
    if let Some(plan) = unmapping {
        let mut holders = [(0u32, None); cap::MAX_OWNERS];
        let mut count = 0;
        for (domain, lost) in plan.tallied.iter().enumerate() {
            if !*lost {
                continue;
            }
            let id = domain::DomainId::from_u32(domain as u32);
            // **Still holding a name for it? Then the mapping stays.** Asked
            // of the domain's CSpace and not of the arena's `owner` field: a
            // capability minted by `shared::name` is charged to the kernel and
            // *held* by the service, so "does this domain own a node naming
            // the object" is false for `bin/fsd` and its cache page. That
            // version of this check faulted the filesystem.
            let still_holds = domain::with(id, |holder| {
                cap::with_arena(|arena| holder.cspace.names(plan.named, arena))
            });
            if still_holds == Some(true) {
                continue;
            }
            holders[count] = (domain as u32, domain::space_root_of(id));
            count += 1;
        }
        if count > 0 {
            crate::shared::unmap_roots(plan.object, &holders[..count]);
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

    /// A slot whose capability the *issuer* revoked can still be emptied.
    ///
    /// **The bug this fixes had no workaround from ring 3.** A service that
    /// lends and takes back — `bin/fsd` lending a page of its cache and
    /// revoking it in `dir::RELEASE` — leaves its borrower a slot naming
    /// something gone. Every method refuses a dead reference, `DELETE`
    /// included, so the borrower could not clear it and nothing could ever be
    /// handed there again. `bin/linuxd` borrows into one fixed slot, so the
    /// *second* file read on the machine failed, whoever made it.
    ///
    /// Written as three assertions rather than one, because the interesting
    /// part is not that `DELETE` answers `Ok` — it is that the slot is empty
    /// afterwards and can take a capability again.
    #[test]
    fn a_slot_whose_capability_the_issuer_revoked_can_still_be_emptied() {
        let mut arena = Arena::new();
        let mut cspace = CSpace::new();
        let root = arena
            .insert_root(ObjectRef::new(ObjectKind::Endpoint, 7), Rights::ALL, 0)
            .expect("a fresh arena has room");
        cspace.install_at(5, root).expect("slot 5 is free");

        // The issuer takes it back. The holder is not consulted and does not
        // find out; its slot still names the dead capability.
        arena.revoke_unchecked(root);
        assert!(cspace.get(5).is_some(), "the slot still holds a name");
        assert!(
            arena.lookup(root).is_none(),
            "and the name no longer resolves"
        );

        let mut revoked = [0u32; crate::cap::MAX_OWNERS];
        let outcome = invoke_capability(
            &SyscallFrame {
                kind: Kind::Invoke as u64,
                capability: 5,
                method: method::DELETE,
                ..SyscallFrame::default()
            },
            0,
            &mut cspace,
            &mut arena,
            &mut revoked,
            &mut None,
        );
        assert_eq!(outcome.status, Status::Ok, "delete refused a dead slot");
        assert!(cspace.get(5).is_none(), "the slot was not emptied");

        // And it is usable again, which is the property the borrower needs:
        // the next lend has somewhere to land.
        let second = arena
            .insert_root(ObjectRef::new(ObjectKind::Endpoint, 8), Rights::ALL, 0)
            .expect("room");
        cspace
            .install_at(5, second)
            .expect("a slot emptied by DELETE takes a capability again");
    }

    /// `DELETE` on a slot that was never occupied is not an error.
    ///
    /// The ABI has said so since it was written — "a program tidying up
    /// should not have to remember whether it has anything to tidy" — and the
    /// kernel answered `NoSuchCapability` until 2026-08-23. A doc and its
    /// code disagreeing is two bugs, and this is the second.
    #[test]
    fn deleting_an_empty_slot_is_not_an_error() {
        let mut arena = Arena::new();
        let mut cspace = CSpace::new();
        let mut revoked = [0u32; crate::cap::MAX_OWNERS];
        let outcome = invoke_capability(
            &SyscallFrame {
                kind: Kind::Invoke as u64,
                capability: 9,
                method: method::DELETE,
                ..SyscallFrame::default()
            },
            0,
            &mut cspace,
            &mut arena,
            &mut revoked,
            &mut None,
        );
        assert_eq!(outcome.status, Status::Ok);
        assert!(cspace.get(9).is_none());
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
            let _ = invoke_capability(&f, 0, &mut cspace, &mut arena, &mut revoked, &mut None);

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
