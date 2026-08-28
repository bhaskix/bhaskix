// SPDX-License-Identifier: Apache-2.0
//! The interface between Bhaskix and the programs that run on it.
//!
//! Everything here is compiled into the kernel *and* into unprivileged
//! programs. That is the whole reason it exists: a protocol written down twice
//! is a protocol whose two halves disagree the first time either is edited,
//! and the disagreement shows up as a message that means something slightly
//! different on each side rather than as a build failure.
//!
//! # What may live here
//!
//! Constants, arithmetic on message registers, and pure state machines. No
//! pointers, no `unsafe`, no allocation — the `unsafe` budget for this crate
//! is zero and is meant to stay there. Code here is trusted by the kernel and
//! *supplied to* untrusted programs, so anything with an obligation attached
//! would owe it on both sides of the privilege boundary at once.
//!
//! # Why messages carry bytes in registers
//!
//! [RFC 0008](../../docs/rfc/0008-syscall-and-ipc-shape.md) fixes a message at
//! four machine words. A shell has to move more than that — a path, a line of
//! text, a directory listing — so [`Chunk`] packs sixteen bytes into two of
//! them and says whether more follows.
//!
//! Sixteen bytes per round trip is slow, and deliberately so for now: the
//! alternative is shared memory, which means a page granted across a domain
//! boundary and a whole capability type to describe it. That is a design
//! decision with an RFC's worth of consequences, and this milestone does not
//! need it. What it buys in the meantime is worth stating: **no pointer ever
//! crosses the boundary.** The kernel never dereferences a user address on
//! behalf of a caller, so the entire class of confused-deputy bugs that
//! `copy_from_user` exists to contain cannot occur here.

#![no_std]
// Tests are exempt from the `unwrap`/`expect`/`panic` bans, as
// docs/coding-style.md §4 specifies: those bans exist to stop a fallible
// operation taking down the nucleus, and a test that cannot panic cannot
// fail. Deliberately *not* exempting `undocumented_unsafe_blocks`, which the
// other crates do — there is no `unsafe` in this crate and its budget is zero,
// so an exemption here would be permission for something that must not appear.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod ring;

/// The six system calls. See `docs/rfc/0008-syscall-and-ipc-shape.md`.
///
/// The kernel keeps its own `Kind` enum whose discriminants are checked
/// against these at compile time. Two definitions with a static assertion
/// between them is not duplication — it is the assertion that makes the
/// duplication safe, and it fails the build rather than a message.
pub mod syscall {
    /// Perform a method on the object a capability names.
    pub const INVOKE: u64 = 0;
    /// Invoke, then block for a reply.
    pub const CALL: u64 = 1;
    /// Answer a `Call`, consuming the reply capability.
    ///
    /// All four argument registers are the reply. Nothing says *who* to
    /// answer: the kernel remembers the caller this thread received from and
    /// has not yet answered, and refuses a reply to anyone else. A server that
    /// could name its own reply target could plant a message in a thread it
    /// never heard from and wake it holding an answer to a question it did not
    /// ask. The badge is not settable either — a server that could stamp an
    /// identity on its answer would defeat every caller that checks one.
    pub const REPLY: u64 = 2;
    /// Block until a message arrives on an endpoint.
    ///
    /// Returns the method and all four argument registers as they were sent,
    /// and the badge in the capability register. Four arguments, and not one,
    /// because a message *is* four registers: a server that received fewer
    /// could not implement the protocols this system already has, which made
    /// "the same service in either placement" false at the boundary rather
    /// than in the service.
    ///
    /// The caller is not returned, because [`REPLY`] does not accept one.
    pub const RECV: u64 = 3;
    /// Give up the rest of this thread's slice.
    pub const YIELD: u64 = 4;
    /// Terminate this thread.
    pub const EXIT: u64 = 5;
}

/// Fixed limits both sides of the boundary have to agree on.
///
/// **A constant that exists twice is a constant that will disagree once.** The
/// kernel's domain table and a server's per-domain table are the same table
/// seen from two rings: if one holds 64 entries and the other 32 and the
/// second is indexed by `domain % 32`, two domains share a row — and the row
/// is signal handlers, or a capability slot. That is exactly the aliasing
/// found in `LINUX_DOMAINS` at RFC 0033 step 3, where the mask was a `u32`
/// and the table was about to hold 64.
///
/// So the number lives here, once, and the kernel asserts its own against it.
pub mod limits {
    /// Domains this machine can have at once — `domain::MAX_DOMAINS`.
    ///
    /// A server that keeps a table per hosted domain sizes it by this and
    /// indexes it by the domain id in a badge, which the kernel stamps and no
    /// caller can forge.
    pub const MAX_DOMAINS: usize = 64;

    /// How many capability slots one domain's CSpace holds.
    ///
    /// Declared here as well as in the kernel because [`crate::adapter`] lays
    /// out a CSpace and must know where it ends; the kernel asserts the two
    /// agree, as it does for every other number both sides name.
    pub const CSPACE_SLOTS: usize = 128;
}

/// **The Linux adapter's capability space, in one place** —
/// [RFC 0031](../../docs/rfc/0031-linux-compatibility-as-an-adapter.md) I3.
///
/// # Why this module exists
///
/// These numbers are a contract between the kernel, which installs the
/// capabilities, and `bin/linuxd`, which invokes them — and they lived as
/// literals on one side and constants on the other, agreeing only because
/// somebody kept them agreeing. **Three collisions happened in one day** on
/// 2026-08-28: a notification put where the root directory was (a hosted `open`
/// answered `-ENOENT`), one put where a hosted domain's handle is allocated,
/// and one put on the first slot of the socket pool (a hosted `bind` answered
/// `EADDRINUSE` on a port nobody held). Two of the three were found by booting
/// rather than by reading, because there was nothing to read: no file stated
/// the layout, and `install_at`'s refusal is reported where it happens rather
/// than where the mistake was made.
///
/// So the layout is stated once, and the assertions at the end make an overlap
/// a **build failure** instead of a boot report.
pub mod adapter {
    /// The endpoint foreign calls arrive on.
    pub const ENDPOINT: usize = 0;
    /// One page to report through.
    pub const REPORT: usize = 1;
    /// The page a hosted program's fault is handed over in.
    pub const FAULTS: usize = 2;
    /// The console, **write-only** — RFC 0032 step 10.
    pub const CONSOLE: usize = 3;

    /// The first futex wake notification.
    pub const WAKES: usize = 4;
    /// Sixteen of them: half the kernel's whole notification table.
    pub const WAKE_COUNT: usize = 16;

    /// The authority to create a domain — RFC 0033 step 5.
    pub const CONTROL: usize = 20;
    /// Where an `execve` holds the domain it is building, one at a time.
    pub const CHILD: usize = 21;
    /// The one directory a hosted process resolves every path through.
    pub const ROOT_DIR: usize = 22;
    /// Where a page lent by the filesystem service lands.
    pub const LENT: usize = 23;
    /// The console's own notification, **read-only** — RFC 0054.
    pub const INPUT_WAKE: usize = 24;

    /// The lowest slot a hosted domain's `Domain` capability may be put in.
    ///
    /// The kernel takes the lowest free slot at or above this — RFC 0033
    /// step 3 — so the region grows with the number of hosted domains alive at
    /// once and shrinks as they end.
    pub const HANDLE_FLOOR: usize = 25;

    /// The protocol service's endpoint.
    pub const NETWORK: usize = 88;
    /// A page of its own for datagram payloads.
    pub const PAYLOAD: usize = 89;
    /// The first socket slot.
    pub const SOCKETS: usize = 90;
    /// Five: what is left between the payload page and the datagram bell.
    pub const SOCKET_COUNT: usize = 5;
    /// The datagram bell, **read-only** — RFC 0058.
    pub const DATAGRAM_BELL: usize = 95;

    /// The highest slot an open file may take; they are allocated **downward**.
    pub const FILE_TOP: usize = 127;
    /// Thirty-two open files.
    pub const FILE_COUNT: usize = 32;
    /// The lowest slot a file may take, which is where that pool ends.
    pub const FILE_FLOOR: usize = FILE_TOP + 1 - FILE_COUNT;

    /// **How many hosted domains may hold a handle at once.**
    ///
    /// The handle region runs from [`HANDLE_FLOOR`] up to whatever sits above
    /// it, which is [`NETWORK`]. That is **sixty-three**, and
    /// [`crate::limits::MAX_DOMAINS`] is sixty-four — so a machine whose every
    /// domain slot held a hosted program would find the last handle refused by
    /// `install_at`.
    ///
    /// A stated capacity rather than a silent one. Raising it means moving the
    /// four grants above it, which is a change to a contract two programs share
    /// and belongs in an RFC rather than in a hurry.
    pub const HANDLE_CAPACITY: usize = NETWORK - HANDLE_FLOOR;

    /// Every fixed grant, for the checks below.
    const FIXED: [usize; 11] = [
        ENDPOINT, REPORT, FAULTS, CONSOLE, CONTROL, CHILD, ROOT_DIR, LENT, INPUT_WAKE, NETWORK,
        PAYLOAD,
    ];

    /// Whether `slot` is one a pool allocates from.
    const fn in_a_pool(slot: usize) -> bool {
        (slot >= WAKES && slot < WAKES + WAKE_COUNT)
            || (slot >= HANDLE_FLOOR && slot < NETWORK)
            || (slot >= SOCKETS && slot < SOCKETS + SOCKET_COUNT)
            || (slot >= FILE_FLOOR && slot <= FILE_TOP)
            || slot == DATAGRAM_BELL
    }

    // **No fixed grant may sit where a pool allocates**, and no two may share a
    // slot. This is the check that would have caught all three of
    // 2026-08-28's collisions before the machine was ever booted.
    const _: () = {
        let mut index = 0;
        while index < FIXED.len() {
            assert!(
                !in_a_pool(FIXED[index]),
                "an adapter grant sits where a pool allocates from"
            );
            let mut other = index + 1;
            while other < FIXED.len() {
                assert!(
                    FIXED[index] != FIXED[other],
                    "two adapter grants name the same slot"
                );
                other += 1;
            }
            index += 1;
        }
    };

    // And the pools may not run into each other or off the end.
    const _: () = {
        assert!(WAKES + WAKE_COUNT <= CONTROL);
        assert!(HANDLE_FLOOR > INPUT_WAKE);
        assert!(NETWORK > HANDLE_FLOOR);
        assert!(SOCKETS > PAYLOAD);
        assert!(SOCKETS + SOCKET_COUNT <= DATAGRAM_BELL);
        assert!(DATAGRAM_BELL < FILE_FLOOR);
        assert!(FILE_TOP < crate::limits::CSPACE_SLOTS);
    };
}

/// Methods invoked on a capability, for the programs that need to name one.
///
/// Only the ones an unprivileged program uses are here. The kernel keeps the
/// full set and a static assertion between the two definitions, which is what
/// makes having two of them safe.
pub mod method {
    /// Write bytes into memory the caller of this endpoint named.
    ///
    /// Only on an `Endpoint` capability, and only from the thread answering a
    /// message taken from it. `arg0` = the *caller's* slot holding the
    /// `Memory` capability, `arg1` = the address of the bytes in this domain,
    /// `arg2` = how many, `arg3` = where in the caller's object to put them.
    ///
    /// The offset is what lets a service copy something larger than its own
    /// buffer: it fills a piece, says where the piece goes, and comes back for
    /// the next. Without it a service in a domain could deliver only as much as
    /// it could hold at once, and reported that as the whole answer -- which it
    /// did until 2026-08-11, disagreeing with the nucleus placement about how
    /// much a bulk read reads.
    ///
    /// The bulk path a service gets when it runs in its own domain. Which
    /// caller is not an argument: it is the one being answered, and a service
    /// that could name it could write a file's contents into a third party's
    /// memory.
    pub const FILL: u64 = 38;

    /// Unmask this interrupt source, so the next one may be delivered.
    ///
    /// Only on an `IrqHandler` capability. The whole of a delegated driver's
    /// interrupt duty: the kernel masks the source on delivery, and nothing
    /// arrives again until the holder says it is ready. RFC 0011.
    pub const ACK: u64 = 36;

    /// Map a `Memory` object into this `DmaWindow`, and return a `DevAddr`.
    ///
    /// Only on a `DmaWindow` capability. `arg0` = the caller's slot holding
    /// the `Memory` capability, `arg1` = rights for the device. RFC 0012.
    ///
    /// The number that comes back is not a physical address and this program
    /// could not have named one: it is where the *device* looks, and what the
    /// unit translates back to the frames the object owns. A driver in a
    /// domain is aimed at its own memory by a number that means nothing
    /// anywhere else.
    pub const MAP: u64 = 32;

    /// Wait until this notification has been signalled, then take the word.
    ///
    /// Only on a `Notification` capability. Blocks, and returns the badges of
    /// every signal since the last take, or-ed together: two signals before
    /// the holder looks are one wake carrying both, and neither is lost.
    ///
    /// One waiter at a time. A second is refused rather than queued.
    pub const WAIT: u64 = 43;
    /// Take whatever this notification has pending, without waiting.
    ///
    /// Zero if nothing has been signalled, which is an answer and not an
    /// error.
    pub const PEEK: u64 = 44;
    /// Signal a `Notification`. Never blocks.
    ///
    /// **Takes no arguments, and that is the design.** The bits or-ed into the
    /// waiting word are the **badge on this capability**, which the kernel
    /// stamped when the capability was derived and which the holder can neither
    /// read nor choose. So a receiver waiting on one notification can tell its
    /// senders apart — up to 64 of them, one bit each — and the identification
    /// is trustworthy precisely because the sender did not pick its own bit.
    ///
    /// Needs the write right: signalling changes the word somebody else is
    /// waiting on. `WAIT` needs only read.
    ///
    /// Specified by [RFC 0010](../../docs/rfc/0010-notifications.md) when it was
    /// accepted on 2026-08-04, as step 2 of its implementation plan, and not
    /// built until 2026-08-13. What landed first was the other direction — an
    /// interrupt signalling a notification — because RFC 0011 step 3 needed it,
    /// and that half was mistaken for the whole object. Until this existed no
    /// domain could wake another, and the kernel poked a sleeping driver on
    /// their behalf.
    pub const SIGNAL: u64 = 45;
    /// Bind a `Notification` to the calling thread, so that a blocking `Recv`
    /// on an endpoint also wakes when this notification is signalled.
    ///
    /// **RFC 0010's unresolved question 1, answered 2026-08-13.** A service that
    /// must answer callers *while* something it did not ask for may arrive had
    /// no way to wait for both: there is no second thread to spare — the ABI can
    /// create a domain but not a thread — and no timed wait to poll safely
    /// around. `bin/ipd` looked at its ring about thirty-seven times per frame.
    ///
    /// The calling thread binds itself; no argument names a thread, because the
    /// only thread that may bind is the one asking. One binding per thread, and
    /// a second is **refused** rather than replacing the first, which would
    /// silently lose whoever was relying on it. Cleared when the thread stops.
    ///
    /// Needs the read right: being woken is a way of being told.
    ///
    /// 55 rather than 33: the kernel's own `UNMAP` holds 33, and 51–54 are the
    /// socket protocol's. Those are a service's methods rather than the
    /// kernel's and could not collide, but a reader checking a number should not
    /// have to know that.
    pub const BIND_SELF: u64 = 55;
    /// Ask the kernel to signal this `Notification` at `arg0`.
    ///
    /// **RFC 0019.** `arg0` is an absolute deadline on the same monotonic scale
    /// `rdtsc` reads — absolute rather than a duration, because a duration read
    /// before being descheduled becomes a lie, and this program can read that
    /// clock itself: `rdtsc` is unprivileged unless `CR4.TSD` is set and this
    /// kernel does not set it.
    ///
    /// The bits the wake carries are this capability's **badge**, recorded now
    /// and used when it fires, so a receiver can tell a timer from a frame in
    /// the one word it waits on.
    ///
    /// **A second `ARM` replaces the first.** That is the opposite of the
    /// second-waiter rule and deliberate: two waiters each want a wake and only
    /// one can have it, whereas re-arming is how a timer user says "not then,
    /// this instead". A program needing many timers keeps its own ordered list
    /// and arms the nearest.
    ///
    /// Needs the write right, as `SIGNAL` does, because arming causes a signal.
    /// Refused with `Congested` when every deadline slot is taken.
    pub const ARM: u64 = 56;
    /// Forget any deadline armed on this `Notification`. Never blocks.
    ///
    /// Returns whether one was armed, which is an answer rather than an error:
    /// a timer that has already fired and one that was never set look the same
    /// to the program that is cancelling it.
    pub const DISARM: u64 = 57;
    /// Set which system-call dialect a `Domain`'s threads will speak.
    ///
    /// RFC 0005 step 2. `arg0` = 0 for the native interface, 1 for the
    /// Linux x86_64 personality. Only before the domain's first thread:
    /// a program half-run under one ABI and finished under another is not
    /// a state anyone can reason about, and the refusal is
    /// `SLOT_UNAVAILABLE` — too late, not wrong. Needs `WRITE`, as `START`
    /// does: choosing a dialect is shaping the domain, not observing it.
    pub const PERSONALITY: u64 = 58;

    /// `COPY_IN(memory, offset, address, length)` on a `Domain` — read the
    /// target domain's memory into a `Memory` object the caller holds.
    ///
    /// [RFC 0032](../../docs/rfc/0032-a-supervisor-interface.md). The
    /// destination is an **object**, never an address: the caller names memory
    /// it already owns, so the kernel is never asked to validate two addresses
    /// in two address spaces, and a supervisor cannot ask for bytes to land
    /// anywhere it could not already write.
    pub const COPY_IN: u64 = 59;
    /// `COPY_OUT(memory, offset, address, length)` on a `Domain` — write a
    /// `Memory` object the caller holds into the target domain's memory.
    pub const COPY_OUT: u64 = 60;
    /// `MAP_AT(address, pages, protection, flags)` on a `Domain` — anonymous
    /// pages in the target domain. `protection` is the same encoding `ATTACH`
    /// uses, so writable-and-executable is not expressible.
    ///
    /// Bit 0 of `flags` asks for a **lazy** mapping: the region is recorded
    /// and no frame is taken until the domain touches a page. That is what a
    /// hosted `mmap` needs — a runtime reserving address space by the
    /// gigabyte and touching a little of it — and an eager mapping is bounded
    /// precisely because its pages cost frames at once.
    pub const MAP_AT: u64 = 61;
    /// `UNMAP_AT(address)` on a `Domain` — the region starting there.
    pub const UNMAP_AT: u64 = 62;
    /// `PROTECT_AT(address, pages, protection)` on a `Domain` — whole regions
    /// only, as `AddressSpace::protect` requires and for its reasons.
    pub const PROTECT_AT: u64 = 63;
    /// `SPAWN_THREAD(entry, stack, argument)` on a `Domain` — start a thread
    /// in the target domain, in the address space it already has.
    ///
    /// [RFC 0032](../../docs/rfc/0032-a-supervisor-interface.md). The
    /// mechanism `clone` needs and nothing of `clone`'s flags: a supervisor
    /// says where to start, on what stack, with what one word — and a
    /// personality decides what that means to the dialect it speaks. Answers
    /// the new thread's id.
    pub const SPAWN_THREAD: u64 = 64;
    /// `SET_TLS(thread, base)` on a `Domain` — a thread's thread-local base.
    ///
    /// [RFC 0032](../../docs/rfc/0032-a-supervisor-interface.md). Generic:
    /// every ABI has a thread-local base and this architecture keeps it in a
    /// register that is **per CPU**, so the value has to travel with the
    /// thread across every switch or it is gone at the first one. Which
    /// dialect asked, and under what name, is the personality's business.
    pub const SET_TLS: u64 = 65;
    /// `MAKE_SPACE()` on a `Domain` — give it an address space of its own.
    ///
    /// [RFC 0033](../../docs/rfc/0033-what-a-hosted-process-is.md) step 5, and
    /// generic in the way RFC 0032 requires of anything the nucleus grows:
    /// nothing about "this domain needs an address space" is a Linux concept.
    ///
    /// **Why it has to exist.** Every other way to get a space is to be a
    /// thread inside the domain and have the kernel build one — which a
    /// supervisor assembling a process by hand cannot be, because there is no
    /// thread until it starts one, and it cannot map the pages that thread
    /// will run in until the space exists. `execve` is the first caller: a
    /// hosted process cannot exec in place, so the adapter builds its
    /// successor and this is the successor's first breath.
    ///
    /// Refused on a domain that already has a space, and on one that has
    /// threads: both mean somebody is already running in memory this would
    /// replace.
    pub const MAKE_SPACE: u64 = 66;

    /// Map the memory this capability names into the caller's address space.
    ///
    /// Only on a `Memory` capability. `arg0` = where, page-aligned; `arg1`
    /// non-zero asks for a writable mapping, which needs the write right.
    /// Never executable.
    ///
    /// A domain maps what it *holds*, at an address of its choosing in its own
    /// space. The frames come from the object and not from anything the caller
    /// said, which is why naming an address here is safe.
    pub const ATTACH: u64 = 42;

    /// Put one character on the console this capability names.
    ///
    /// Only on a `Console` capability. `arg0` = the character.
    pub const PUT: u64 = 39;
    /// Put a run of bytes on the console, **without anything getting between
    /// them** — RFC 0050.
    ///
    /// Only on a `Console` capability, and it needs the same `WRITE` right
    /// `PUT` does: this is *n* `PUT`s, minus the opportunity for another CPU's
    /// line to land in the middle of a word. `arg0` = the address of the bytes
    /// in the **caller's** address space, `arg1` = how many. Returns how many
    /// were put.
    ///
    /// It exists because a hosted program's line was arriving in halves: one
    /// byte per invocation, and `console::_print` locks per call, so a kernel
    /// report could and did print between `e` and `xeced pid 3`.
    pub const PUT_RUN: u64 = 69;
    /// How much input has arrived, and from which source — RFC 0051.
    ///
    /// Only on a `Console` capability, and it needs `READ`: the right a holder
    /// must already have to *take* a typed byte. This counts without consuming.
    ///
    /// **One word per call**, chosen by `arg0`, because a system call returns
    /// one — `RECORD` beside this has its caller walk an offset for the same
    /// reason. Each word is a saturating pair of `u32`s, high half first:
    /// `0` is serial received and dropped, `1` the keyboard ring's received and
    /// dropped, `2` i8042 scancodes and input interrupts. Anything else reads
    /// zero rather than failing. Scancodes sit
    /// beside bytes because they are different facts — a key release emits no
    /// byte, so scancodes moving while the keyboard column does not says the
    /// i8042 is delivering and the decoder is swallowing.
    pub const INPUT_STATS: u64 = 70;
    /// Take a byte typed at the console **for the domain this capability
    /// names** — RFC 0053. Blocks until there is one.
    ///
    /// On a `Domain` capability with `READ`, and refused with
    /// `INSUFFICIENT_RIGHTS` unless that domain has been granted input. The
    /// adapter's console capability stays `WRITE` alone: this names the
    /// *domain's* authority, so a compromised adapter reads keystrokes for
    /// granted domains and no others.
    pub const TAKE_INPUT: u64 = 71;
    /// The same without blocking: a byte, or [`NOTHING`].
    pub const POLL_INPUT: u64 = 72;
    /// **Is a byte waiting?** Answers 1 or 0, and takes nothing —
    /// [RFC 0055](../../docs/rfc/0055-a-poll-that-tells-the-truth.md).
    ///
    /// The same `Rights::READ` on the same `Domain` capability as
    /// [`POLL_INPUT`], refused by the same grant, and it confers no authority
    /// those do not: a caller that may take a byte may certainly ask whether
    /// there is one.
    ///
    /// It exists because `poll` must not consume. A `poll` built on
    /// [`POLL_INPUT`] would lose a keystroke every time a program asked
    /// whether one was waiting, which is the opposite of what `poll` is for.
    pub const PEEK_INPUT: u64 = 73;
    /// Take a byte that was typed, waiting until there is one.
    ///
    /// Only on a `Console` capability, and it blocks: a holder waiting here is
    /// not answering anything else while it waits.
    pub const TAKE: u64 = 40;
    /// Take a byte only if one is already waiting.
    ///
    /// Returns the byte, or [`NOTHING`].
    pub const POLL: u64 = 41;
    /// What [`POLL`] returns when nobody has typed.
    ///
    /// Out of a byte's range on purpose, so "nothing" cannot be confused with
    /// a byte that was read.
    pub const NOTHING: u64 = 0x100;

    /// How many bytes of what the kernel printed are kept.
    ///
    /// Only on a `Console` capability, and it needs `READ`. RFC 0042.
    pub const RECORD_SIZE: u64 = 67;
    /// Eight bytes of that record, starting at `arg0`.
    ///
    /// Only on a `Console` capability, and it needs `READ`. Packed
    /// little-endian, zero-padded past the end — which is why the size is a
    /// separate question rather than something a caller infers from a zero
    /// byte, since a zero byte is a byte somebody could have printed.
    ///
    /// **These two are why RFC 0042's "the kernel gains no method" was wrong**,
    /// and the RFC says so now. The boot report is written by the kernel before
    /// any service exists, so the record is kernel memory; a console service in
    /// its own domain cannot read it without asking, and asking is a method.
    pub const RECORD: u64 = 68;

    /// How big the object this capability names is.
    ///
    /// Bytes on a `File`. A `DmaWindow` answers the same number with its own
    /// meaning, which is the one place in this ABI where a method number means
    /// two things — deliberately, because "how big" is the same question.
    pub const INFO: u64 = 34;
    /// Make a weaker capability from this one.
    ///
    /// `arg0` = rights for the copy, `arg1` = its badge, `arg2` = the slot to
    /// put it in. Rights may only narrow, and the badge may only be **set by a
    /// capability that has none**: a badge is a statement the granter made,
    /// and a holder that could change it could call a service as somebody
    /// else.
    pub const DERIVE: u64 = 0;
    /// Destroy this capability and everything derived from it.
    ///
    /// Revocation goes **down** the tree and not up: the capability named is
    /// destroyed along with every copy derived from it, and its own parent is
    /// untouched. That direction is what lets a server lend something and take
    /// it back — it derives a second capability of its own, hands copies from
    /// *that*, and revoking it reaches the copies without reaching the one the
    /// server is still using.
    ///
    /// Returns how many capabilities were destroyed. The slot is left empty.
    pub const REVOKE: u64 = 1;
    /// Drop this capability, leaving the slot empty.
    ///
    /// Not an error on a slot that is already empty: a program tidying up
    /// should not have to remember whether it has anything to tidy.
    pub const DELETE: u64 = 2;
    /// Say where a capability handed back by a server may be put.
    ///
    /// Only on an `Endpoint` capability. `arg0` = the slot. This thread will
    /// then accept **one** capability there, and a server cannot put one
    /// anywhere else — a program's CSpace is its own to arrange, and a service
    /// that could choose could fill a slot the program was keeping empty.
    ///
    /// One-shot: the declaration is consumed by the capability that arrives,
    /// and cleared when the call it was made for returns.
    ///
    /// **And the other direction, RFC 0022**: a *service* invoking this on its
    /// own endpoint declares where a capability arriving *in a call* may land.
    /// Same declaration, same one-shot rule, different holder — which end you
    /// hold is the role.
    pub const EXPECT: u64 = 46;
    /// Read bytes out of memory the caller of this endpoint named.
    ///
    /// The mirror of `FILL`, and what a write needs. `arg0` = the *caller's*
    /// slot holding the `Memory`, `arg1` = where in this program's address
    /// space to put them, `arg2` = how many at most. The caller must hold that
    /// memory with `READ`.
    pub const DRAIN: u64 = 48;
    /// Give the caller being answered a copy of a capability this server holds.
    ///
    /// Only on an `Endpoint` capability, and only while answering a message
    /// taken from it. `arg0` = the server's own slot, `arg1` = rights for the
    /// copy, `arg2` = its badge. Where it lands comes from the caller's
    /// [`EXPECT`] and not from here.
    ///
    /// **And the other direction, RFC 0022**: a thread that is *not*
    /// answering anybody stages instead — `arg0` = its slot, `arg1` = rights,
    /// `arg2` = badge — one gift per thread, replaced by a second staging,
    /// consumed by its next `Call` on this endpoint. The transfer happens at
    /// the rendezvous, atomically with the message: no [`EXPECT`] declared by
    /// the service's thread means the *call is refused* rather than delivered
    /// bare, and every refusal — no declaration, no `GRANT`, rights or badge
    /// not monotone — restores the staged gift, so a retry needs no second
    /// `HAND`.
    pub const HAND: u64 = 47;
    /// Give a derived capability to the domain this capability names.
    ///
    /// Only on a `Domain`. `arg0` = the caller's slot to derive from, `arg1` =
    /// the slot in the recipient, `arg2` = rights, `arg3` = badge — and that
    /// order is the implementation's, checked against the kernel by the
    /// assertions in `syscall.rs`. The kernel's own doc comment had `arg1` and
    /// `arg2` transposed until 2026-08-11, which nothing caught because the
    /// only caller was assembly written from the code.
    ///
    /// A badge may not be invented: it must be the one the capability already
    /// carries, because a service uses it to tell its callers apart.
    pub const GRANT: u64 = 16;
    /// Ask to be signalled when the domain this capability names ends.
    ///
    /// Only on a `Domain`. `arg0` = a slot **already holding** a notification
    /// this program owns, `arg1` = the badge the signal carries. It is not a
    /// slot to put a new notification in: the domain signals something the
    /// caller already has, so a caller with none cannot be told about anything.
    ///
    /// Must be asked **before** `START`. A binding made afterwards races a
    /// short-lived program, and the kernel refuses a watch for an event that
    /// has already happened rather than accepting a wait that never ends.
    pub const BIND: u64 = 35;
    /// Give back a domain that has ended, and the slot naming it.
    ///
    /// The capability goes with the slot: leaving it would let a holder ask
    /// about a domain that has been reaped and get an answer about whatever
    /// took the slot next.
    pub const RELEASE: u64 = 37;
    /// Create a domain, and put a capability to it in a slot this program names.
    ///
    /// Only on a `DomainControl` capability. `arg0` = the slot in this
    /// program's own CSpace for the new `Domain` capability, which must be
    /// empty; `arg1` and `arg2` = up to sixteen bytes of name, packed
    /// little-endian and truncated at the first zero.
    ///
    /// What comes back is **empty**: no threads, no capabilities, no address
    /// space. Everything it will ever hold is passed to it afterwards, one
    /// `GRANT` at a time, which is the whole reason this is three steps rather
    /// than one. Refused if the slot is occupied, if the creator's envelope
    /// allows no more children, or if the domain table is full.
    pub const SPAWN: u64 = 49;
    /// Start a program in a domain this program holds.
    ///
    /// Only on a `Domain` capability, and only one that carries `WRITE`.
    /// `arg0` = the caller's own slot holding a `Memory` object containing an
    /// ELF image; `arg1` = how many of its bytes are the image. Returns the
    /// identifier of the thread that was started.
    ///
    /// The image arrives as a **capability**, not a filename. The kernel has no
    /// business opening files on a program's behalf, and a program that could
    /// name one would be naming authority it does not hold — so it hands over
    /// memory it already has, and what it put there is its own affair.
    ///
    /// Where the program lands is decided by the image's own headers. Where its
    /// stack goes is decided by the kernel: an ELF says where its code and data
    /// belong and nothing about where it should be given room to push.
    pub const START: u64 = 50;
}

/// The bits a capability's rights are made of.
///
/// Mirrored from the kernel so that a program can ask for a *weaker* copy of
/// something it holds without linking the kernel. Asking for more than the
/// parent has is refused, so these are safe to name — the numbers are not the
/// authority, the capability is.
pub mod rights {
    /// Read the object's contents.
    pub const READ: u64 = 1 << 0;
    /// Modify the object.
    pub const WRITE: u64 = 1 << 1;
    /// Execute from it, where that means anything.
    pub const EXECUTE: u64 = 1 << 2;
    /// Pass a copy to another domain.
    pub const GRANT: u64 = 1 << 3;
    /// Revoke this capability and everything below it.
    pub const REVOKE: u64 = 1 << 4;
    /// Create a weaker capability from this one.
    pub const DERIVE: u64 = 1 << 5;
}

/// What a system call returned in `rax`.
pub mod status {
    /// The call succeeded.
    pub const OK: u64 = 0;
    /// The system call number is not one the kernel answers.
    pub const BAD_SYSCALL: u64 = 1;
    /// The capability index named nothing in this domain's CSpace.
    pub const NO_SUCH_CAPABILITY: u64 = 2;
    /// The capability was revoked, or its slot has been reused.
    pub const REVOKED: u64 = 3;
    /// The capability names the wrong kind of object for this operation.
    pub const WRONG_OBJECT: u64 = 4;
    /// The capability does not carry the rights this operation needs.
    ///
    /// Distinct from [`NO_SUCH_CAPABILITY`] on purpose: "you do not hold this"
    /// and "you hold it and may not do that with it" are different answers,
    /// and a program that could not tell them apart would not know whether to
    /// ask for the thing or for the right.
    pub const INSUFFICIENT_RIGHTS: u64 = 5;
    /// The operation is defined but not built yet.
    pub const NOT_IMPLEMENTED: u64 = 6;
    /// The calling thread belongs to no domain, so it has no CSpace.
    pub const NO_DOMAIN: u64 = 7;
    /// The endpoint's queue is full in the direction this call needs.
    ///
    /// **Transient, and the only status here that is.** Everything else says
    /// the authority is wrong or gone, and asking again will get the same
    /// answer. This one says the queue was full at that instant, so a caller
    /// that treats it like the others gives up on a request that would have
    /// worked. A *service* that treats it like the others exits.
    pub const CONGESTED: u64 = 8;
    /// The reply names a caller that is no longer waiting.
    pub const NO_SUCH_CALLER: u64 = 9;
    /// The address named is unusable: unaligned, occupied, or out of range.
    pub const SLOT_UNAVAILABLE: u64 = 11;
    /// The object does not answer that method.
    pub const NO_SUCH_METHOD: u64 = 10;
    /// This domain's quota for the thing asked for is full.
    pub const QUOTA_EXCEEDED: u64 = 12;
    /// A resource the whole machine shares is used up.
    ///
    /// Distinct from [`QUOTA_EXCEEDED`]: "you may not have another" and
    /// "nobody may have another" call for different responses. The first is
    /// about this program's envelope; the second is about the machine, and
    /// only asking again later can help.
    pub const EXHAUSTED: u64 = 13;
    /// `Recv` came back because the **bound notification** fired, not because a
    /// message arrived. The badge word is in the value register.
    ///
    /// Not an error, which is why it is worth its own number rather than being
    /// squeezed into `OK`: a service must be able to tell "somebody called me"
    /// from "something happened", and both are success. RFC 0010 question 1.
    pub const NOTIFIED: u64 = 14;
}

/// Methods the console service answers.
///
/// Raw bytes in both directions. The service does no line editing, because
/// line editing is a shell's job and a shell that could not do it would not be
/// one — it would be a program typing at a shell that lives in the kernel.
pub mod console {
    /// Write the chunk's bytes. Replies with how many were accepted.
    pub const WRITE: u64 = 1;
    /// Read whatever has been typed. Blocks until at least one byte has.
    pub const READ: u64 = 2;
    /// How many bytes of the boot report are kept. RFC 0042.
    pub const RECORD_SIZE: u64 = 3;
    /// A chunk of the boot report, starting at the offset in `args[0]`.
    ///
    /// Replies with a [`crate::Chunk`]. Short at the end, empty past it.
    pub const RECORD: u64 = 4;
    /// What has arrived on the input path, by source — RFC 0051.
    ///
    /// The service asks the nucleus and hands the three words back without
    /// interpreting them, as it does for [`RECORD`]. See
    /// [`crate::method::INPUT_STATS`] for the packing.
    ///
    /// It exists because a ring 3 shell could not answer *"is the keyboard
    /// working?"*: the counters are in the nucleus, the boot report prints
    /// before anyone can type, and on the machine that asked the question the
    /// serial line is output-only.
    pub const STATS: u64 = 5;
}

/// Methods the filesystem service answers.
///
/// Stateful per caller, keyed by the badge on the capability used. A path is
/// accumulated across as many [`Chunk`]s as it takes, and the operation that
/// follows consumes it — so a caller cannot open a path it did not finish
/// sending, and the service never has to guess where a name ends.
/// What a *directory* answers, in the filesystem service.
///
/// RFC 0016 step 4. A directory a program holds is a **badged endpoint
/// capability** to the filesystem service: the badge says which directory, the
/// kernel stamps it on arrival so it cannot be forged, and the service is the
/// only thing that knows what it means. There is no kernel object kind for a
/// directory any more, and nothing in the kernel knows what an inode is.
pub mod dir {
    /// Resolve one name inside the directory this capability names.
    ///
    /// The name is a [`Chunk`] in `arg0..3` — one component, no separators, no
    /// `.` or `..`. The caller must have said where a capability may land,
    /// with [`method::EXPECT`], before calling.
    ///
    /// Replies with `args[0]` an outcome below, `args[1]` the size in bytes,
    /// `args[2]` non-zero if what was opened is itself a directory, and
    /// `args[3]` its **inode number** — the filesystem's own name for it,
    /// which a caller answering a Linux `fstat` needs and cannot invent: a
    /// descriptor's identity cannot come from the capability slot holding it,
    /// because slots are reused and two files would report as one. On
    /// [`OK`] a capability to it has been handed to the caller.
    pub const OPEN_AT: u64 = 1;
    /// Lend the caller the page holding this file's first block.
    ///
    /// Only meaningful on a capability naming a *file*. The service pins the
    /// frame that block is in and hands over a **read-only capability to that
    /// one page** — not to its cache, which holds other files' data and every
    /// piece of metadata it has touched. The caller maps it and reads the
    /// bytes: nothing is copied, and no round trip carries them.
    ///
    /// A pinned frame is never chosen for eviction, so the page goes on
    /// meaning what it meant. Replies with `args[0]` an outcome and `args[1]`
    /// the file's size, and as [`OPEN_AT`] the caller must have said where
    /// with [`method::EXPECT`] first.
    pub const MAP: u64 = 2;
    /// Give back a page lent by [`MAP`].
    ///
    /// The caller says it is done with the page it was lent for this file. The
    /// service unpins the frame — so it can be reused — and **revokes what it
    /// handed over**, which unmaps the page from the caller wherever it put it.
    ///
    /// Both halves are needed and neither is a formality. Unpinning without
    /// revoking would leave the caller reading a frame the service is free to
    /// fill with somebody else's block, which is the disclosure [`MAP`] exists
    /// to avoid, arriving a moment later. Revoking without unpinning would give
    /// the frame back to nobody.
    ///
    /// So a caller that says it is done **is** done: the page is gone from its
    /// address space when this returns, and reading where it used to be is a
    /// fault. That is the point rather than a hazard — a caller keeping a
    /// mapping it has released is a caller reading a page the service has
    /// already reused.
    ///
    /// Replies with `args[0]` an outcome and `args[1]` how many of the
    /// service's frames are still lent, which is how a caller can see that its
    /// own release took effect rather than being told so.
    pub const RELEASE: u64 = 3;

    /// It resolved, and a capability was handed over.
    pub const OK: u64 = 0;
    /// Nothing of that name is in this directory.
    ///
    /// Deliberately not distinguished from a name that exists *elsewhere* on
    /// the same filesystem: a program that could tell those apart could map a
    /// filesystem it holds one directory of, one question at a time.
    pub const NO_SUCH_NAME: u64 = 1;
    /// That is not a name this system resolves: a separator, `.`, `..`, empty.
    ///
    /// Distinct from [`NO_SUCH_NAME`] because it describes the syntax the
    /// caller used, which the caller already knows — and because a refusal
    /// indistinguishable from "no such name" would be indistinguishable from
    /// no refusal at all: `..` is in no directory this format writes.
    pub const BAD_NAME: u64 = 2;
    /// The directory this capability named is gone.
    ///
    /// The badge carries an inode *and* a generation. A filesystem that reuses
    /// an inode bumps the generation, so a capability that outlived what it
    /// named resolves to nothing rather than to whatever took the slot.
    pub const GONE: u64 = 3;
    /// There was nowhere to put the answer: the caller declared no slot.
    pub const NOWHERE: u64 = 4;
    /// The handle does not carry the write authority the method needs.
    /// RFC 0030 step 3: writability rides the badge (see [`writable`]),
    /// minted by the kernel or inherited through [`CREATE_AT`], never
    /// invented by a caller.
    pub const READ_ONLY: u64 = 5;
    /// The name already exists, and the method needed it not to.
    pub const EXISTS: u64 = 6;
    /// The filesystem refused — out of space, out of inodes, or an inner
    /// error the service reports rather than interprets. `args[1]` carries
    /// a discriminant for the log, not for programs to branch on.
    pub const REFUSED: u64 = 7;
    /// A listing index past the last entry — the iteration's honest end.
    pub const END: u64 = 8;
    /// An entry's name does not fit one reply chunk. Sixteen bytes is the
    /// listing's stated ceiling; a package name longer than that installs
    /// fine and lists as this refusal — the trigger for multi-chunk
    /// listing is the first real name that hits it.
    pub const NAME_TOO_LONG: u64 = 9;

    /// Create a file named by the [`crate::Chunk`] in `arg0..3` inside this
    /// directory. Writable handles only. On [`OK`], a **writable** handle
    /// to the new file is handed to the caller's [`crate::method::EXPECT`]
    /// slot, and `args[1]` is zero (its size).
    ///
    /// RFC 0030 step 3: the first client-facing write the filesystem
    /// service has offered — the journal underneath is RFC 0016's,
    /// exercised until now only by its own demonstration.
    pub const CREATE_AT: u64 = 4;
    /// As [`CREATE_AT`], but the new thing is a directory, and the handle
    /// handed back is a writable directory handle.
    pub const MAKE_DIRECTORY_AT: u64 = 5;
    /// Write bytes into the file this **writable** handle names.
    ///
    /// `arg0` = the caller's own slot holding a `Memory` object, `arg1` =
    /// how many bytes, `arg2` = the file offset. The service drains the
    /// caller's memory — [`crate::method::DRAIN`], [`crate::method::FILL`]'s
    /// mirror — so the bytes cross without a register round trip each.
    /// Replies with the count written in `args[1]`.
    pub const WRITE_FROM: u64 = 6;
    /// Remove the name in the [`crate::Chunk`] from this **writable**
    /// directory. Removing a non-empty directory is refused by the
    /// filesystem and reported as [`REFUSED`].
    pub const REMOVE_AT: u64 = 7;
    /// List this directory: `arg0` = an entry index, and each call is its
    /// own question — no session, no cursor, nothing for a caller to leak.
    /// Replies with the entry's name as a chunk in `args[1..3]`, [`END`]
    /// past the last entry, and the name's length, the entry's kind and its
    /// inode packed into the fourth word.
    ///
    /// **Read that word with [`listing_length`], [`listing_is_directory`]
    /// and [`listing_inode`] rather than by hand.** It carried two fields
    /// and now carries three, and the obvious hand-written test for the
    /// second one — `word >> 8 != 0` — was correct while the inode was
    /// absent and reports every entry as a directory now that it is there.
    pub const LIST_AT: u64 = 8;
    /// Read bytes of the file this handle names into memory the caller
    /// named — [`WRITE_FROM`]'s mirror, and what running an installed
    /// program needs (RFC 0030 step 4): [`MAP`] lends only the first page,
    /// and a binary is bigger than a page.
    ///
    /// `arg0` = the caller's own slot holding a `Memory` object, `arg1` =
    /// how many bytes at most (one transfer page per call, the caller
    /// loops), `arg2` = the file offset — which is also the offset the
    /// bytes land at in the caller's object, so a linear read reassembles
    /// the file in place. Replies with the count in `args[1]`; zero is end
    /// of file. Any handle may read: reading is what every handle has.
    pub const READ_INTO: u64 = 9;

    /// Packs [`LIST_AT`]'s fourth reply word: the name's length in the low
    /// byte, whether the entry is a directory in bit 8, and the inode above
    /// bit 32.
    ///
    /// **Bit 8 and not "anything above the low byte".** The inode sits well
    /// clear of it so that the two can never be confused, and the reason is
    /// written here rather than left to a reader: the field grew, and every
    /// caller that had read the kind as "the rest of the word" would have
    /// started calling every file a directory.
    #[must_use]
    pub const fn listing(length: usize, is_directory: bool, inode: u32) -> u64 {
        ((length as u64) & 0xff) | ((is_directory as u64) << 8) | ((inode as u64) << 32)
    }

    /// The name's length out of [`listing`]'s word.
    #[must_use]
    pub const fn listing_length(word: u64) -> usize {
        (word & 0xff) as usize
    }

    /// Whether the entry is a directory, out of [`listing`]'s word.
    #[must_use]
    pub const fn listing_is_directory(word: u64) -> bool {
        word & (1 << 8) != 0
    }

    /// The entry's inode, out of [`listing`]'s word.
    #[must_use]
    pub const fn listing_inode(word: u64) -> u32 {
        (word >> 32) as u32
    }

    /// Packs an inode and a generation into the badge that names them.
    #[must_use]
    pub const fn handle(inode: u32, generation: u32) -> u64 {
        (inode as u64) | ((generation as u64) << 32)
    }

    /// The writable bit, which is the badge's top bit — the generation
    /// keeps thirty-one. Narrowed knowingly (RFC 0030 step 3): a
    /// generation counts directory reuses, thirty-one bits of them is
    /// beyond any machine lifetime this project will see, and the
    /// alternative was a second badge namespace for one boolean.
    pub const WRITABLE: u64 = 1 << 63;

    /// A writable handle: [`handle`], plus the authority to change what
    /// it names. Minted by the kernel at boot for the shell's root handle,
    /// and by the service when a writable handle creates a child — never
    /// from a caller's own arguments.
    pub const fn handle_writable(inode: u32, generation: u32) -> u64 {
        // The generation masked at packing, as `tcp::handle` masks its own:
        // packing a generation the unpacking would truncate silently is how
        // bit 63 gets stepped on.
        (inode as u64) | (((generation & 0x7fff_ffff) as u64) << 32) | WRITABLE
    }

    /// Whether this badge carries the write authority.
    #[must_use]
    pub const fn writable(badge: u64) -> bool {
        badge & WRITABLE != 0
    }

    /// The inode and generation a badge names.
    #[must_use]
    pub const fn parts(badge: u64) -> (u32, u32) {
        (badge as u32, ((badge & !WRITABLE) >> 32) as u32)
    }
}

/// Methods a socket answers, and the one that mints them.
///
/// [RFC 0018](../../docs/rfc/0018-networking.md) step 5. A socket is **a badged
/// capability to the protocol service's own endpoint**, not an object the
/// kernel knows about — the same shape a directory has since RFC 0016 deleted
/// `ObjectKind::Directory`, and for the same reason: the thing being named
/// lives in a userspace service, so the kernel has no business having a type
/// for it.
///
/// What the kernel does provide is the part a service cannot: the badge is
/// stamped on the way through and cannot be forged by the holder, so a program
/// cannot invent a socket it was never given.
///
/// # What holding one means
///
/// A program with a socket can send and receive on that flow. It cannot
/// enumerate ports, cannot bind another, cannot see another program's traffic,
/// and cannot reach the device. **A program without one has no way to name the
/// network at all** — there is no port table and no interface list to ask, so
/// the absence is not a refused call, it is nothing to call.
pub mod socket {
    /// Bind a local UDP port, and be handed a socket.
    ///
    /// Invoked on a capability to the protocol service's endpoint — the one a
    /// program is given at boot if it is to have networking at all.
    ///
    /// `arg0` is the port, or zero to be assigned one. The caller must have
    /// said where a capability may land with [`method::EXPECT`] first, exactly
    /// as [`dir::OPEN_AT`] requires, so the service cannot choose the slot.
    ///
    /// Replies with `args[0]` an outcome below and `args[1]` the port actually
    /// bound. On [`OK`] a socket capability has been handed to the caller.
    pub const BIND_UDP: u64 = 51;

    /// Send a datagram from this socket.
    ///
    /// Invoked on the socket capability itself. `arg0` is the destination
    /// address, `arg1` the destination port, and the payload is whatever the
    /// caller has put in the socket's ring.
    pub const SEND_TO: u64 = 52;

    /// Take the next datagram this socket has received.
    ///
    /// Replies with the source address in `args[1]` and its port in `args[2]`,
    /// or [`EMPTY`] when nothing has arrived — which is an answer rather than
    /// an error, because a caller polling between sends wants to hear it.
    pub const RECV_FROM: u64 = 53;

    /// Give up this socket.
    ///
    /// The binding ends and the capability stops working. A capability held
    /// after a close names a *generation* that no longer exists, which is what
    /// the badge's second half is for: the slot may be reused immediately and
    /// the old holder must not inherit the new socket.
    pub const CLOSE: u64 = 54;

    /// Bind a UDP socket in the second family — RFC 0029 step 4.
    ///
    /// `arg0` is the port, as [`BIND_UDP`]. The family is the method, not a
    /// flag: dispatch already switches on method numbers, and a flag would
    /// spend a bit of every word distinguishing what the number already
    /// says. The capability handed back is the same kind of socket; only
    /// what it can carry differs.
    pub const BIND_UDP6: u64 = 64;

    /// Send a datagram from a v6 socket.
    ///
    /// A v6 endpoint is wider than a v4 one and the message still has four
    /// words: `arg0`/`arg1` are the destination address's high and low
    /// halves in wire order, `arg2` packs `(length << 16) | port`, and
    /// `arg3` names the payload memory. The length cap this packing imposes
    /// — 65535 — is the UDP length field's own, so nothing sendable is
    /// lost to it.
    pub const SEND_TO6: u64 = 65;

    /// Take the next datagram from a v6 socket.
    ///
    /// The reply convention carries three service words, so the source
    /// port rides above the outcome: `value = outcome | (port << 16)`,
    /// `args[1]`/`args[2]` the source address's halves in wire order.
    /// [`EMPTY`] when nothing has arrived, as ever an answer and not an
    /// error.
    pub const RECV_FROM6: u64 = 66;

    /// **How many bytes are waiting on this socket, taking nothing** —
    /// [RFC 0056](../../docs/rfc/0056-asking-a-socket-without-emptying-it.md).
    ///
    /// Invoked on the socket capability, and needs exactly what [`RECV_FROM`]
    /// needs: a holder that may take a datagram may certainly ask whether there
    /// is one. Replies [`OK`] with the waiting datagram's length in `args[1]`,
    /// zero meaning nothing has arrived.
    ///
    /// It exists because `RECV_FROM` **consumes**. A readiness check built on
    /// that would take a datagram every time a program asked whether one was
    /// there, and the `recvfrom` that followed would find nothing — which is
    /// what `poll` is for, spelled backwards.
    ///
    /// **The service must look at the wire before answering**, exactly as
    /// `RECV_FROM` does: it is asleep in `receive` with no other wakeup, so a
    /// client asking is the only event it can act on. A peek that skipped that
    /// would report "nothing waiting" for a datagram already in the ring.
    pub const PEEK_FROM: u64 = 68;
    /// The same for a socket of the second family.
    ///
    /// Two numbers rather than one, matching [`SEND_TO`]/[`SEND_TO6`]: one
    /// service holds both families, and the number is what lets it refuse the
    /// v4 question asked about a v6 socket.
    pub const PEEK_FROM6: u64 = 69;

    /// It worked.
    pub const OK: u64 = 0;
    /// That port is already bound, or none is free.
    pub const NO_PORT: u64 = 1;
    /// This socket has been closed, and its slot may already be somebody
    /// else's. Distinct from a refusal: the capability was real once.
    pub const GONE: u64 = 2;
    /// Nothing has arrived.
    pub const EMPTY: u64 = 3;
    /// The caller never said where a capability may land.
    pub const NOWHERE: u64 = 4;
    /// The network is not reachable — no device, or no window to drive it
    /// through. Said rather than pretended, so a program can tell "nothing
    /// answered" from "there is nothing to answer".
    pub const NO_NETWORK: u64 = 5;
    /// The socket exists but speaks the other family: a v4 call on a v6
    /// socket or the reverse. Refused by name rather than mis-parsed,
    /// because the two shapes read the same four words differently.
    pub const WRONG_FAMILY: u64 = 6;
    /// **This service has no socket left to give.**
    ///
    /// Distinct from [`NO_PORT`], which it was folded into until 2026-08-28.
    /// One says *that port belongs to somebody*, the other says *this service
    /// is full*, and a caller can act on the first and only wait on the
    /// second — but a program told the first when the second was true goes
    /// looking for the holder of a port nobody holds.
    ///
    /// That was not hypothetical: it misdirected three separate investigations
    /// in one day, twice pointing at a port number that had nothing to do with
    /// the failure. See RFC 0056's status line, which recorded the conflation
    /// before this word existed to end it.
    pub const NO_SOCKET: u64 = 7;

    /// Packs a socket's identity into the badge a capability carries.
    #[must_use]
    pub const fn handle(index: u32, generation: u32) -> u64 {
        (index as u64) | ((generation as u64) << 32)
    }

    /// The socket index and generation a badge names.
    #[must_use]
    pub const fn parts(badge: u64) -> (u32, u32) {
        (badge as u32, (badge >> 32) as u32)
    }
}

/// Methods a TCP service answers.
///
/// [RFC 0020](../../docs/rfc/0020-tcp.md) step 4. A connection is the same
/// shape a socket is — **a badged capability to the service's own endpoint**,
/// minted with [`method::HAND`], landing where the caller said with
/// [`method::EXPECT`] — because RFC 0018 committed to a socket shape that could
/// carry TCP without reopening anything, and this is that commitment kept. No
/// new object kind, and no kernel change.
///
/// A *listener* is a differently-badged capability to the same endpoint, and
/// the badge carries which of the two it is: the operations do not overlap —
/// there is no `SEND` on a listener and no `ACCEPT` on a connection — so a
/// method applied to the wrong one is refused rather than reinterpreted.
///
/// [`socket::CLOSE`] is reused, unchanged in meaning: end the binding. The
/// numbers here start at 58 because [`method::DISARM`] is 57 and is the highest
/// allocated; there is no gap this time.
pub mod tcp {
    /// Open a connection.
    ///
    /// Invoked on a capability to the TCP service's endpoint. `arg0` is the
    /// destination address, `arg1` the destination port, and `arg2` the
    /// **leg**: RFC 0022 moves one capability per call, so `CONNECT` is
    /// three. Leg 0 carries the send ring as a staged gift ([`method::HAND`]
    /// then this call), leg 1 the receive ring, and leg 2 asks for the
    /// connection capability, which rides the reply into the slot the caller
    /// declared with [`method::EXPECT`]. Each leg replies with an outcome
    /// below; a leg missing its ring is told [`BARE`]. Leg 3 (optional,
    /// after every ring the caller intends) gifts a badged `Notification`
    /// the service signals whenever the connection has news — bytes
    /// delivered, send space freed, state changed — so the caller can block
    /// in `WAIT` instead of polling. The badge must be nonzero: a signal
    /// ORs the badge into the word, and zero rings nobody.
    pub const CONNECT: u64 = 58;

    /// Listen on a local port. The same three-leg handover as [`CONNECT`],
    /// because it is the same exchange: legs 0 and 1 gift the rings the
    /// accepted connection's stream will live in, and leg 2 (`arg0` = the
    /// port) replies with a *listener* capability — its badge carrying
    /// bit 63, which is what makes a listener a different capability rather
    /// than a differently-documented one.
    pub const LISTEN: u64 = 59;

    /// On a listener: poll for an established connection. `LATER` until a
    /// `SYN` has arrived and completed its handshake; then the reply carries
    /// the connection capability into the slot the caller declared with
    /// [`method::EXPECT`], exactly as `CONNECT` leg 2 does.
    pub const ACCEPT: u64 = 60;

    /// On a connection: "I have written `arg0` bytes into the send ring."
    /// No payload crosses in the message; the ring is where the bytes are —
    /// the `Memory` object the program gifted at `CONNECT` leg 0, whose byte
    /// `k` of the stream sits at `k` modulo the ring's size.
    pub const SEND: u64 = 61;

    /// On a connection: how far has the peer's stream reached? The reply's
    /// second word packs the machine's state (high 32 bits) over the
    /// cumulative bytes delivered into the gifted receive ring (low 32).
    /// `arg0` is the bytes this program has consumed since it last said so,
    /// and saying so matters: the receive window *is* the free space in the
    /// program's ring — it shrinks as bytes land and reopens only on this
    /// word, so a program that stops reporting stops the peer.
    pub const RECV: u64 = 62;

    /// Half-close: no more data this way. The other direction keeps working,
    /// which is what makes a request/response protocol expressible.
    pub const SHUTDOWN: u64 = 63;

    /// Open a connection in the second family — RFC 0029 step 5.
    ///
    /// The one call in the family that uses all four words exactly:
    /// `arg0`/`arg1` the destination address's halves in wire order,
    /// `arg2` the port, `arg3` the leg. The legs are [`CONNECT`]'s,
    /// unchanged — the handover never looked inside an address.
    pub const CONNECT6: u64 = 67;

    /// The first four bytes of a v6 record in the rings between the
    /// protocol service and the TCP service, where a v4 record carries the
    /// source address instead: `255.255.255.255` can never originate a
    /// TCP segment, which is what makes the marker unambiguous. A v6
    /// record follows it with the two sixteen-byte addresses, then the
    /// segment.
    pub const V6_RECORD: [u8; 4] = [0xff, 0xff, 0xff, 0xff];

    /// It worked.
    pub const OK: u64 = 0;
    /// The peer answered the connection request with a reset.
    pub const REFUSED: u64 = 1;
    /// The peer never answered, and the bounded retransmissions ran out.
    pub const UNREACHABLE: u64 = 2;
    /// The peer reset an established connection. Distinct from an orderly
    /// close, because a program that has read half a response needs to know
    /// the rest is not coming.
    pub const RESET: u64 = 3;
    /// This capability names a connection that no longer exists.
    pub const GONE: u64 = 4;
    /// The connection table is full. A fixed table refusing is this system's
    /// posture everywhere; a growing one's failure is somebody else's
    /// out-of-memory.
    pub const CONGESTED: u64 = 5;
    /// This machine cannot produce an unpredictable number, so this service
    /// refuses to mint sequence numbers at all.
    ///
    /// [RFC 0021](../../docs/rfc/0021-unpredictability.md)'s policy — *the
    /// caller refuses* — with this service as the caller. A guessable initial
    /// sequence number lets an off-path attacker inject into connections
    /// without seeing a packet, and shipping that unlabelled would be worse
    /// than shipping nothing.
    pub const NO_ENTROPY: u64 = 6;
    /// The service is running but not yet accepting connections.
    ///
    /// Step 4 starts the domain, the rings and the loop; minting connection
    /// capabilities to callers is the half that needs a program to call, and
    /// arrives with step 5. An honest "not yet" is distinguishable from a
    /// missing service, which is the difference between waiting and giving up.
    pub const LATER: u64 = 7;
    /// A `CONNECT` leg arrived without the ring it was supposed to carry,
    /// or out of order — the handover protocol misused, not the network.
    ///
    /// RFC 0022 step 4: `CONNECT` is three calls. Leg 0 (`args[2]` = 0)
    /// carries the send ring as a staged gift, leg 1 the receive ring, and
    /// leg 2 asks for the connection capability, which rides the reply into
    /// the slot the caller declared with [`method::EXPECT`]. One capability
    /// per call, as RFC 0022's alternatives table records; a caller that
    /// skips a leg is told so with this, and the reply's second word says
    /// which expectation was disappointed.
    pub const BARE: u64 = 8;

    /// Packs a connection's identity into the badge a capability carries.
    ///
    /// Bit 63 distinguishes a listener from a connection, which is what makes
    /// the two different capabilities rather than differently-documented ones.
    /// The generation therefore keeps 31 bits, and the mask here matches the
    /// one in [`parts`] — packing a generation the unpacking would truncate
    /// silently is how bit 63 gets stepped on.
    #[must_use]
    pub const fn handle(index: u32, generation: u32, listener: bool) -> u64 {
        (index as u64) | (((generation & 0x7fff_ffff) as u64) << 32) | ((listener as u64) << 63)
    }

    /// The index, generation, and whether this badge names a listener.
    #[must_use]
    pub const fn parts(badge: u64) -> (u32, u32, bool) {
        (
            badge as u32,
            ((badge >> 32) as u32) & 0x7fff_ffff,
            badge >> 63 != 0,
        )
    }
}

/// Methods a block service answers.
///
/// Sector data never crosses in message registers. The caller names memory it
/// already holds and the service fills it — RFC 0009's bulk path, and the same
/// shape the filesystem's `READ_INTO` uses, because a block that travelled
/// sixteen bytes at a time would be slower than the disk.
pub mod block {
    /// Read sectors into memory the caller names.
    ///
    /// `args[0]` = first sector, `args[1]` = how many, `args[2]` = the slot in
    /// the **caller's** CSpace holding the `Memory` to fill. Replies with the
    /// bytes that landed, and an outcome.
    pub const READ: u64 = 1;
    /// Write sectors from memory the caller names.
    ///
    /// `args[0]` = first sector, `args[1]` = how many, `args[2]` = the slot in
    /// the **caller's** CSpace holding the `Memory` to take them from. Replies
    /// with the bytes that went. The caller must hold that memory with
    /// `READ` — this is the direction that reads it.
    pub const WRITE: u64 = 5;
    /// What [`WRITE`] answers for a range the *service* refused itself.
    ///
    /// Distinct from zero, which means the write was attempted and did not
    /// land. The difference is not cosmetic: a sector past the end of the
    /// device must be refused **here** rather than asked of the hardware,
    /// because a device is entitled to do anything with a sector that does not
    /// exist — and on a write that includes doing it to somebody else's. A
    /// polite device refuses it too, so without a distinct answer the check
    /// and its absence look identical from outside, which is what a test of it
    /// found.
    pub const REFUSED: u64 = u64::MAX;
    /// How many 512-byte sectors the device has.
    pub const CAPACITY: u64 = 2;
    /// Lend the caller the device's configuration page, read-only.
    ///
    /// The driver holds a capability to it and hands over a **weaker copy**
    /// rather than reading the page and copying its bytes back: the caller
    /// maps it and reads the device itself. Where the copy lands is the slot
    /// the caller declared with [`method::EXPECT`], never one this service
    /// chose. RFC 0016.
    pub const LEND_CONFIG: u64 = 3;
    /// Try to lend a capability this service may **not** pass on.
    ///
    /// Replies with the status the kernel gave. It exists so that the refusal
    /// can be watched from a caller, *while the service is answering* — asked
    /// outside a request it would be refused for having no caller instead,
    /// which is a different rule and would prove nothing about this one.
    pub const LEND_FORBIDDEN: u64 = 4;
}

/// Methods the filesystem service answers.
pub mod fs {
    /// Append a chunk to this caller's path.
    pub const PATH: u64 = 1;
    /// Open the accumulated path. Replies with the size in `args[3]`.
    pub const OPEN: u64 = 2;
    /// Read the next bytes of the open file. A count of zero is end of file.
    pub const READ: u64 = 3;
    /// Begin listing the accumulated path, then return one entry per call.
    pub const LIST: u64 = 4;
    /// Read into a shared region instead of into registers.
    ///
    /// `arg0` = the caller's own capability slot holding a `Memory` object,
    /// `arg1` = how many bytes at most. Returns the number written.
    ///
    /// The register path stays for short transfers: RFC 0009 measured it at
    /// sixteen bytes a round trip, which is right for a path that reads a
    /// filename and wrong for one that reads a file.
    pub const READ_INTO: u64 = 6;

    // Two methods with one number is a service answering the wrong question,
    // and the compiler only noticed because one arm became unreachable. Said
    // here as an assertion so the next one fails the build instead.
    const _: () = {
        assert!(PATH != OPEN && PATH != READ && PATH != LIST && PATH != RESET && PATH != READ_INTO);
        assert!(OPEN != READ && OPEN != LIST && OPEN != RESET && OPEN != READ_INTO);
        assert!(READ != LIST && READ != RESET && READ != READ_INTO);
        assert!(LIST != RESET && LIST != READ_INTO);
        assert!(RESET != READ_INTO);
    };
    /// Forget this caller's path, open file, and listing.
    pub const RESET: u64 = 5;
}

/// Service-defined outcomes, returned in `args[0]`'s high half.
pub mod outcome {
    /// The operation succeeded.
    pub const OK: u64 = 0;
    /// No such file.
    pub const NOT_FOUND: u64 = 1;
    /// The path is one the filesystem will not resolve.
    pub const BAD_PATH: u64 = 2;
    /// The name is a directory, or the operation needs one and it is not.
    pub const WRONG_KIND: u64 = 3;
    /// Nothing is open, or nothing is being listed.
    pub const NOTHING_OPEN: u64 = 4;
    /// The service has no room for another caller.
    pub const BUSY: u64 = 5;
    /// The caller reached the service through a capability with no badge, so
    /// it cannot be told apart from any other such caller.
    pub const UNIDENTIFIED: u64 = 6;
    /// The caller named a capability it does not hold, or one of the wrong
    /// kind.
    ///
    /// Distinct from `BAD_PATH`: the request was well formed and the caller
    /// was not entitled to it, which is the answer a service must be able to
    /// give without saying anything about what it was asked for.
    pub const NOT_YOURS: u64 = 7;
}

/// Bytes one message carries.
///
/// Two of the four registers, because the other two say how many bytes there
/// are and carry whatever the method needs besides.
pub const CHUNK_BYTES: usize = 16;

/// Set in `args[0]` when the sender has more to send.
const MORE: u64 = 1 << 8;
/// Mask selecting the byte count from `args[0]`.
const COUNT: u64 = 0xff;
/// Where a service outcome sits in `args[0]`.
const OUTCOME_SHIFT: u64 = 16;

/// Up to [`CHUNK_BYTES`] bytes, and whether more follow.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Chunk {
    bytes: [u8; CHUNK_BYTES],
    length: usize,
    more: bool,
}

impl Default for Chunk {
    fn default() -> Self {
        Self::empty()
    }
}

impl Chunk {
    /// A chunk carrying nothing, and nothing to follow.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            bytes: [0; CHUNK_BYTES],
            length: 0,
            more: false,
        }
    }

    /// Takes the first [`CHUNK_BYTES`] of `bytes`, and returns the rest.
    ///
    /// Returning the remainder rather than an index is what makes the sending
    /// loop hard to write wrongly: a caller iterates until the remainder is
    /// empty, and cannot lose track of how far it has got.
    #[must_use]
    pub fn take(bytes: &[u8]) -> (Self, &[u8]) {
        let length = bytes.len().min(CHUNK_BYTES);
        let (head, tail) = bytes.split_at(length);
        let mut chunk = Self::empty();
        chunk.bytes[..length].copy_from_slice(head);
        chunk.length = length;
        chunk.more = !tail.is_empty();
        (chunk, tail)
    }

    /// The bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes[..self.length]
    }

    /// How many bytes it carries.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.length
    }

    /// Whether it carries none.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.length == 0
    }

    /// Whether the sender said more follows.
    #[must_use]
    pub const fn more(&self) -> bool {
        self.more
    }

    /// Sets the "more follows" flag.
    #[must_use]
    pub const fn with_more(mut self, more: bool) -> Self {
        self.more = more;
        self
    }

    /// Packs into message registers, with `extra` in `args[3]`.
    #[must_use]
    pub fn pack(&self, extra: u64) -> [u64; 4] {
        let mut low = 0u64;
        let mut high = 0u64;
        for (index, byte) in self.bytes[..self.length].iter().enumerate() {
            let shift = (index % 8) * 8;
            if index < 8 {
                low |= u64::from(*byte) << shift;
            } else {
                high |= u64::from(*byte) << shift;
            }
        }
        let count = self.length as u64 | if self.more { MORE } else { 0 };
        [count, low, high, extra]
    }

    /// Unpacks from message registers.
    ///
    /// A count larger than [`CHUNK_BYTES`] is clamped rather than trusted.
    /// This is the one function here that reads a value the *other* side of a
    /// privilege boundary chose, and a length is exactly the field that must
    /// not be believed: on the kernel's side it would otherwise index past a
    /// sixteen-byte array on behalf of a caller who asked it to.
    #[must_use]
    pub fn unpack(args: &[u64; 4]) -> Self {
        let length = ((args[0] & COUNT) as usize).min(CHUNK_BYTES);
        let mut chunk = Self::empty();
        for index in 0..length {
            let word = if index < 8 { args[1] } else { args[2] };
            let shift = (index % 8) * 8;
            chunk.bytes[index] = ((word >> shift) & 0xff) as u8;
        }
        chunk.length = length;
        chunk.more = args[0] & MORE != 0;
        chunk
    }
}

/// Puts a service outcome into `args[0]` alongside a count.
#[must_use]
pub const fn with_outcome(args0: u64, outcome: u64) -> u64 {
    args0 | (outcome << OUTCOME_SHIFT)
}

/// Reads a service outcome out of `args[0]`.
#[must_use]
pub const fn outcome_of(args0: u64) -> u64 {
    (args0 >> OUTCOME_SHIFT) & 0xff
}

/// Packs a directory entry's size and kind for `args[3]`.
#[must_use]
pub const fn entry_metadata(size: u64, directory: bool) -> u64 {
    (size << 1) | (directory as u64)
}

/// Unpacks [`entry_metadata`] into `(size, is_directory)`.
#[must_use]
pub const fn entry_of(metadata: u64) -> (u64, bool) {
    (metadata >> 1, metadata & 1 != 0)
}

/// Longest line either shell will accept.
///
/// A line that reaches this stops accepting rather than wrapping or
/// truncating silently: neither shell has scrollback, and a command whose end
/// the operator cannot see is worse than one that refuses to grow.
pub const MAX_LINE: usize = 128;

/// What a byte did to the line being edited.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Edit {
    /// Nothing. A control character with no meaning here, or a full line.
    Ignored,
    /// The byte was appended, and should be echoed.
    Inserted(u8),
    /// The last byte was removed.
    Erased,
    /// The line is finished.
    Complete,
    /// The operator abandoned the line.
    Cancelled,
}

/// A line being typed.
///
/// Shared between the kernel shell and the user-mode one, because they edit
/// lines identically and two implementations would disagree about backspace —
/// which is the sort of difference nobody notices until they have been typing
/// into the wrong one for a minute.
///
/// A pure state machine over bytes, so the interesting behaviour — backspace
/// at the start of a line, a line that grows too long, `\r\n` arriving as two
/// bytes — is testable on the host with no UART, no interrupt and no machine.
pub struct LineEditor {
    buffer: [u8; MAX_LINE],
    length: usize,
    /// Set after `\r`, so the `\n` that follows does not end a second, empty
    /// line. Terminals send both and mean one.
    swallow_newline: bool,
}

impl Default for LineEditor {
    fn default() -> Self {
        Self::new()
    }
}

impl LineEditor {
    /// An empty line.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            buffer: [0; MAX_LINE],
            length: 0,
            swallow_newline: false,
        }
    }

    /// The bytes typed so far.
    #[must_use]
    pub fn line(&self) -> &[u8] {
        &self.buffer[..self.length]
    }

    /// Discards the line.
    pub const fn clear(&mut self) {
        self.length = 0;
    }

    /// Feeds one byte in.
    pub fn accept(&mut self, byte: u8) -> Edit {
        let swallow = self.swallow_newline;
        self.swallow_newline = byte == b'\r';

        match byte {
            b'\n' if swallow => Edit::Ignored,
            b'\r' | b'\n' => Edit::Complete,
            // Backspace and delete. Terminals disagree about which they send,
            // and a shell that honoured only one is a shell where the
            // operator's mistakes are permanent.
            0x08 | 0x7f => {
                if self.length == 0 {
                    Edit::Ignored
                } else {
                    self.length -= 1;
                    Edit::Erased
                }
            }
            // Ctrl-C: abandon the line.
            0x03 => {
                self.length = 0;
                Edit::Cancelled
            }
            // Ctrl-U: erase it, silently.
            0x15 => {
                self.length = 0;
                Edit::Ignored
            }
            // Printable ASCII only. Anything else -- an escape sequence from an
            // arrow key, a stray high byte from a mismatched baud rate -- is
            // dropped rather than inserted, because a command line containing a
            // byte the operator cannot see is a command they did not mean to
            // type.
            0x20..=0x7e => {
                if self.length == MAX_LINE {
                    Edit::Ignored
                } else {
                    self.buffer[self.length] = byte;
                    self.length += 1;
                    Edit::Inserted(byte)
                }
            }
            _ => Edit::Ignored,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_listing_word_carries_three_fields_that_cannot_be_read_as_each_other() {
        let word = dir::listing(5, false, 0x1234_5678);
        assert_eq!(dir::listing_length(word), 5);
        assert_eq!(dir::listing_inode(word), 0x1234_5678);
        // **The regression this accessor exists for.** A plain `word >> 8`
        // was the directory test while the word held two fields; with an
        // inode above it, every entry in the tree would list as a directory
        // and `pkg remove` would try to recurse into files.
        assert!(
            !dir::listing_is_directory(word),
            "a file with a large inode is still a file"
        );
        assert!(dir::listing_is_directory(dir::listing(
            5,
            true,
            0x1234_5678
        )));
    }

    #[test]
    fn a_listing_word_at_the_edges_of_each_field_still_reads_back() {
        for (length, directory, inode) in [
            (0usize, false, 0u32),
            (255, true, u32::MAX),
            (16, true, 1),
            (1, false, u32::MAX),
        ] {
            let word = dir::listing(length, directory, inode);
            assert_eq!(dir::listing_length(word), length, "{word:#x}");
            assert_eq!(dir::listing_is_directory(word), directory, "{word:#x}");
            assert_eq!(dir::listing_inode(word), inode, "{word:#x}");
        }
    }

    #[test]
    fn an_over_long_name_cannot_reach_out_of_its_field_and_flip_the_kind() {
        // The length is a `usize` and the field is eight bits, so a caller
        // that passed a longer one would otherwise write straight through
        // the directory bit -- turning a file into a directory by the length
        // of its name. Masked at packing, and this is what says so.
        // A first version of this test used 255 and passed with the mask
        // removed, which made it a test of nothing.
        let word = dir::listing(0x1ff, false, 1);
        assert!(!dir::listing_is_directory(word), "{word:#x}");
        assert_eq!(dir::listing_inode(word), 1);
        // Bits 9..32 are unclaimed and must stay that way, so the next field
        // to arrive has somewhere to go that no caller is already reading.
        assert_eq!(dir::listing(255, true, u32::MAX) & 0x0000_0000_ffff_fe00, 0);
    }

    #[test]
    fn a_chunk_survives_a_round_trip_at_every_length() {
        let source: [u8; CHUNK_BYTES] = core::array::from_fn(|index| index as u8 + 1);
        for length in 0..=CHUNK_BYTES {
            let (chunk, rest) = Chunk::take(&source[..length]);
            assert!(rest.is_empty());
            let packed = chunk.pack(0);
            let back = Chunk::unpack(&packed);
            assert_eq!(back.bytes(), &source[..length], "length {length}");
            assert_eq!(back.len(), length);
            assert!(!back.more());
        }
    }

    #[test]
    fn taking_returns_the_remainder_so_a_sender_cannot_lose_its_place() {
        let source = b"abcdefghijklmnopqrstuvwxyz";
        let (first, rest) = Chunk::take(source);
        assert_eq!(first.bytes(), b"abcdefghijklmnop");
        assert!(first.more(), "there is more, and the flag says so");

        let (second, rest) = Chunk::take(rest);
        assert_eq!(second.bytes(), b"qrstuvwxyz");
        assert!(!second.more(), "and there is not, and the flag says that");
        assert!(rest.is_empty());
    }

    #[test]
    fn a_count_larger_than_the_chunk_is_clamped_rather_than_believed() {
        // The field the *other* side of a privilege boundary chooses. Trusting
        // it means indexing past a sixteen-byte array because a caller asked.
        let packed = [0xffu64, u64::MAX, u64::MAX, 0];
        let chunk = Chunk::unpack(&packed);
        assert_eq!(chunk.len(), CHUNK_BYTES);
        assert_eq!(chunk.bytes(), &[0xff; CHUNK_BYTES]);
    }

    #[test]
    fn an_outcome_and_a_count_share_a_register_without_colliding() {
        let args0 = with_outcome(CHUNK_BYTES as u64 | MORE, outcome::NOT_FOUND);
        assert_eq!(args0 & COUNT, CHUNK_BYTES as u64);
        assert_eq!(outcome_of(args0), outcome::NOT_FOUND);
        assert!(Chunk::unpack(&[args0, 0, 0, 0]).more());
    }

    #[test]
    fn entry_metadata_survives_a_round_trip() {
        for (size, directory) in [(0u64, false), (1, true), (4096, false), (1 << 40, true)] {
            assert_eq!(entry_of(entry_metadata(size, directory)), (size, directory));
        }
    }

    #[test]
    fn a_line_is_complete_at_a_carriage_return_or_a_newline() {
        let mut editor = LineEditor::new();
        for byte in b"ls /etc\r" {
            editor.accept(*byte);
        }
        assert_eq!(editor.line(), b"ls /etc");
    }

    #[test]
    fn a_carriage_return_and_newline_together_end_one_line_not_two() {
        let mut editor = LineEditor::new();
        assert_eq!(editor.accept(b'a'), Edit::Inserted(b'a'));
        assert_eq!(editor.accept(b'\r'), Edit::Complete);
        editor.clear();
        assert_eq!(editor.accept(b'\n'), Edit::Ignored);
        // And the swallow does not persist into the next line.
        assert_eq!(editor.accept(b'b'), Edit::Inserted(b'b'));
        assert_eq!(editor.accept(b'\n'), Edit::Complete);
        assert_eq!(editor.line(), b"b");
    }

    #[test]
    fn backspace_and_delete_both_erase_and_neither_underflows() {
        let mut editor = LineEditor::new();
        assert_eq!(editor.accept(0x08), Edit::Ignored, "nothing to erase");
        assert_eq!(editor.accept(0x7f), Edit::Ignored);

        for byte in b"lst" {
            editor.accept(*byte);
        }
        assert_eq!(editor.accept(0x08), Edit::Erased);
        assert_eq!(editor.line(), b"ls");
        assert_eq!(editor.accept(0x7f), Edit::Erased);
        assert_eq!(editor.line(), b"l");
    }

    #[test]
    fn a_line_that_grows_too_long_stops_accepting_rather_than_overflowing() {
        let mut editor = LineEditor::new();
        for _ in 0..MAX_LINE {
            assert_eq!(editor.accept(b'x'), Edit::Inserted(b'x'));
        }
        assert_eq!(editor.accept(b'x'), Edit::Ignored, "no room, and no panic");
        assert_eq!(editor.line().len(), MAX_LINE);
        assert_eq!(editor.accept(0x08), Edit::Erased, "still editable");
    }

    #[test]
    fn control_c_abandons_the_line_and_control_u_erases_it() {
        let mut editor = LineEditor::new();
        for byte in b"rm -rf" {
            editor.accept(*byte);
        }
        assert_eq!(editor.accept(0x03), Edit::Cancelled);
        assert_eq!(editor.line(), b"");

        for byte in b"cat x" {
            editor.accept(*byte);
        }
        assert_eq!(editor.accept(0x15), Edit::Ignored);
        assert_eq!(editor.line(), b"");
    }

    #[test]
    fn bytes_that_cannot_be_seen_are_not_inserted() {
        let mut editor = LineEditor::new();
        for byte in [0x00, 0x1b, 0x1f, 0x80, 0xff] {
            assert_eq!(editor.accept(byte), Edit::Ignored);
        }
        assert_eq!(editor.line(), b"");
    }
}
