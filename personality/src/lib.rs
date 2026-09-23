// SPDX-License-Identifier: Apache-2.0
//! The Linux personality, as arithmetic.
//!
//! [RFC 0005](../../docs/rfc/0005-linux-abi-compatibility.md): the Linux
//! `x86_64` ABI is a *personality* — a translation layer over the
//! capabilities a domain already holds — and never the native interface.
//! This crate is the half of it that needs no machine: what a process's
//! initial state is, and (as tiers land) what each system call's arguments
//! mean, as pure functions over byte buffers.
//!
//! Nothing here holds authority, allocates, or is `unsafe` — `forbid`, with
//! the budget written as zero. The kernel calls in; a host test checks the
//! bytes. That split is what makes the auxv builder testable at all, and the
//! RFC's testing plan names it as the preferred shape.

#![cfg_attr(not(test), no_std)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
#![forbid(unsafe_code)]

pub mod call;
pub mod event;
pub mod exec;
pub mod file;
pub mod memory;
pub mod pipe;
pub mod poll;
pub mod proc;
pub mod process;
pub mod signal;
pub mod socket;
pub mod stack;
pub mod thread;

/// The layout of the adapter's report page, defined once for both rings.
///
/// # Why this is here and not computed twice
///
/// `bin/linuxd` writes this page and the kernel reads it. Until 2026-08-21 each
/// side worked out the offsets for itself — the adapter as a chain of
/// `const … = PREVIOUS + 24`, the kernel as five separate expressions of the
/// form `(8 * 32 + 1024 + 24 + 24) / 8`. Two independent derivations of one
/// layout, in two rings, with nothing checking that they agreed.
///
/// They did not agree. `FAULT_LOG_OFFSET` was `8 * 32 + 64`, four sixteen-byte
/// entries at 320, and its comment said *"past the trace records and the
/// scratch word"* — which was true when the scratch **was** one word. The
/// scratch later became 1,024 bytes starting at 256, so the fault log came to
/// sit **inside it**, and nothing noticed because the kernel never reads the
/// fault log and this program is single-threaded, so no fault is ever handed
/// over between staging bytes and copying them out. A latent corruption held
/// off by an invariant that was never written down for this purpose.
///
/// So the layout lives here, in the crate both rings already depend on, and the
/// scratch is **last** so that widening it cannot walk into anything.
pub mod report {
    /// Eight `mmap` trace records, thirty-two bytes each.
    pub const TRACES_AT: usize = 0;
    /// Where the fault log begins: four sixteen-byte entries.
    pub const FAULT_LOG_AT: usize = TRACES_AT + TRACES_WORDS * 8;

    /// How many words [`TRACES_AT`] holds.
    pub const TRACES_WORDS: usize = 32;
    /// The exec record: pid, from, to.
    pub const EXEC_AT: usize = FAULT_LOG_AT + FAULT_LOG_WORDS * 8;

    /// How many words [`FAULT_LOG_AT`] holds — four entries of two.
    pub const FAULT_LOG_WORDS: usize = 8;
    /// The file record: outcome, stage, bytes.
    pub const FILE_AT: usize = EXEC_AT + EXEC_WORDS * 8;

    /// How many words [`EXEC_AT`] holds.
    pub const EXEC_WORDS: usize = 3;
    /// The fork record: child pid, bytes copied.
    pub const FORK_AT: usize = FILE_AT + FILE_WORDS * 8;

    /// How many words [`FILE_AT`] holds.
    pub const FILE_WORDS: usize = 3;
    /// The wait record: collected, status.
    pub const WAIT_AT: usize = FORK_AT + FORK_WORDS * 8;

    /// How many words [`FORK_AT`] holds.
    pub const FORK_WORDS: usize = 2;
    /// The supervised-copy measurement: cold cycles, warm cycles.
    pub const COPY_AT: usize = WAIT_AT + WAIT_WORDS * 8;

    /// How many words [`WAIT_AT`] holds.
    pub const WAIT_WORDS: usize = 2;
    /// Giving a lent page back: cold cycles, warm cycles.
    ///
    /// [RFC 0044](../../docs/rfc/0044-revocation-that-reaches-the-mapping.md)
    /// made `dir::RELEASE` do more — a revocation now takes the page out of
    /// the borrower's address space — and shipped without a number for it,
    /// because the boot report priced every other path and not this one. Two
    /// halves for the reason [`COPY_AT`]'s comment gives at length: a single
    /// figure here would be the first execution of the path rather than the
    /// cost of using it.
    pub const LEND_AT: usize = COPY_AT + COPY_WORDS * 8;

    /// How many words [`COPY_AT`] holds.
    pub const COPY_WORDS: usize = 2;

    /// The socket record: closes `bin/ipd` refused, and how many attempts the
    /// last successful close needed.
    ///
    /// **Added because the counter for the first of these already existed and
    /// nothing read it.** `bin/linuxd` has incremented a `CLOSES_REFUSED`
    /// since RFC 0058, behind a `closes_refused()` whose own doc comment says
    /// "for the boot report" — and that function had no caller, so the number
    /// the adapter kept specifically to make a lost port visible was never
    /// once printed. Every socket-reclaim failure to date has been silent
    /// about the one question that separates its two candidate causes.
    ///
    /// The second word is there because a retry that succeeds on its last
    /// attempt and one that succeeds on its first are the same "no failure" to
    /// every gate, and the difference is the whole margin.
    pub const SOCKET_AT: usize = LEND_AT + LEND_WORDS * 8;

    /// How many words [`LEND_AT`] holds, and how many slots
    /// `record_release` fills.
    pub const LEND_WORDS: usize = 2;

    /// The process record: records admitted, records found, the last domain a
    /// record was admitted for, and how many descriptors that record held.
    ///
    /// **Because `process_for` is not a lookup and the boot never said so.**
    /// It admits a fresh record when none matches `(domain, generation)`, so
    /// "no record for this domain" and "here is a record for this domain" are
    /// the same answer to every caller — and `release_sockets_of` walking a
    /// record admitted a moment earlier releases nothing and reports success.
    /// That path was written down as a suspect in the socket-reclaim hunt days
    /// before anything could see it happen.
    ///
    /// The fourth word is the one that turns a count into evidence: the
    /// reclaim gate's failing specimen showed a socket landing on descriptor
    /// **1**, and a table with the three standard descriptors installed hands
    /// out **3**. So the occupancy at the moment of admission says whether the
    /// record the taker used had stdio at all.
    /// Six words: four about `process_for`, and two about the adapter's file
    /// slots — how many are held now and the most ever held at once.
    ///
    /// The file-slot pair is here because an `O_CLOEXEC` descriptor crossing an
    /// `execve` has to give its capability back, and a leak there costs one of
    /// thirty-two slots for the rest of the boot. That defect was found by
    /// reading rather than by a failure, and was **unreachable by any test in
    /// this tree** — nothing set `O_CLOEXEC` and then exec'd. The exec probe
    /// does now, and these two words are what let a gate see whether the slot
    /// came back.
    pub const PROCESS_AT: usize = SOCKET_AT + SOCKET_WORDS * 8;

    /// How many words [`SOCKET_AT`] holds.
    pub const SOCKET_WORDS: usize = 2;

    /// How many words [`PROCESS_AT`] holds.
    ///
    /// **Eight since 2026-09-15**, the last two being the domain capabilities
    /// the adapter keeps so it can end a hosted process — RFC 0079 — as a
    /// count and a peak. The peak is not decoration: a count that ends at zero
    /// cannot distinguish "every one was released" from "none was ever kept",
    /// which is the same reason the file slots carry one. Named rather than
    /// written as a literal on both sides, because the writer and the reader
    /// disagreeing about the length is a silent wrong number rather than a
    /// build failure.
    pub const PROCESS_WORDS: usize = 8;

    /// The bind record: which domain asked, and what it was told.
    ///
    /// **The question the socket-reclaim hunt cannot currently answer.** Its
    /// gate reports `fd 1, bind 1` from the taker, and `answer_bind` returns
    /// `Answer::ok(0)` or `Answer::error(-errno)`, so a positive one is not an
    /// answer it can give. On the richest specimen so far the adapter's last
    /// file record said a bind had *succeeded*, descriptor 3, port 7781, while
    /// the gate said the taker's bind answered one. Either the record belongs
    /// to the previous program and
    /// the taker's bind never reached `answer_bind` at all, or the record is
    /// stale. Nothing distinguishes those, because the record does not say
    /// **whose** bind it was.
    ///
    /// Two words: the domain that asked, and its outcome packed as errno in the
    /// low sixteen bits, the port above them, and the service's refusal word
    /// above that. Written on both paths, so "no record for this domain" means
    /// the call did not arrive.
    /// **Derived from [`PROCESS_WORDS`], not written as 48.** It *was* 48 — six
    /// words — and on 2026-09-15 the process record grew to eight without this
    /// moving, so its last two words landed on top of this one. The adapter
    /// was overwriting the bind record on every process trace, and the kernel
    /// read this record's contents back as a domain-slot count.
    ///
    /// **QEMU could not show it and the SR550 did on the first boot.** The lane
    /// the change was developed on binds no socket, so the two words it
    /// clobbered were zero and the count read correctly; a machine with four
    /// network ports writes them, and the boot report read `adapter domains
    /// 12884901909 of 32 kept now`. That number is `0x3_0000_0015` — this
    /// record's own two halves, a domain of 21 and an outcome of 3.
    pub const BIND_AT: usize = PROCESS_AT + PROCESS_WORDS * 8;

    /// How many words [`BIND_AT`] holds: the domain that asked, and its
    /// outcome.
    pub const BIND_WORDS: usize = 2;

    /// The signal record — [RFC 0083](../../docs/rfc/0083-a-signal-a-process-can-catch.md):
    /// signals raised, signals delivered to a handler, and deliveries that
    /// could not be built.
    ///
    /// **Three words because two of them are only meaningful as a
    /// difference.** A raise that never becomes a delivery is the failure this
    /// record exists to make visible, and it is invisible in either count
    /// alone: a boot with one raise and one delivery and a boot with one raise
    /// and none both have "a raise". The third separates the two ways a
    /// delivery can not happen — a frame that could not be built, which is
    /// this adapter's fault, from a signal still pending, which is a process
    /// that has not made a call yet and is the limit this RFC names.
    pub const SIGNAL_AT: usize = BIND_AT + BIND_WORDS * 8;

    /// How many words [`SIGNAL_AT`] holds.
    ///
    /// **Five since 2026-09-21.** The first three could not tell a raise that
    /// was never delivered from one that was delivered late: a boot read
    /// `raised 4, delivered 3, unbuilt 0` and the difference had two possible
    /// causes with nothing between them. The fourth counts raises landing on a
    /// signal the target already had **blocked**, and the fifth counts
    /// `rt_sigreturn`s that could not read their own frame's `uc_sigmask` —
    /// which would latch a mask on for ever and is the one failure this
    /// design can have that nothing else would show.
    ///
    /// **Seven since 2026-09-21.** The sixth and seventh are how many domains
    /// still hold a signal that was raised and never taken, and the first such
    /// domain. `raised` minus `delivered` says one is owed; only this says
    /// *whether the target still has it*. A domain still holding it means the
    /// raise landed where it should and delivery never came; none holding it
    /// means the raise went somewhere the target never reads, and those are
    /// different bugs.
    /// **Nine since 2026-09-23.** The eighth and ninth are the `rip` a
    /// delivery built its frame from and the `rip` an `rt_sigreturn` restored.
    /// `TRACKER.md` §3 carries a defect where a handler demonstrably runs and
    /// returns and the program does not continue past the call the signal was
    /// delivered on — and eleven probe-level experiments could not say where
    /// it went instead, because only this program knows those two numbers.
    /// Three conclusions were published and withdrawn before it was accepted
    /// that no probe could settle it.
    /// **Eleven since 2026-09-23**, the same day as nine. The tenth is the
    /// handler **entry** a delivery jumped to and the eleventh is the domain
    /// it was for. Nine was not enough: the pair it added is *the last*
    /// delivery and `rt_sigreturn` in the boot, and on both a working and a
    /// failing run that turned out to be a different program's. A number that
    /// cannot say whose it is answers no question about anyone.
    /// **Thirteen since 2026-09-23.** The twelfth counts the times a pending
    /// signal met a reply shape that **neither delivery arm handles**, and the
    /// thirteenth packs the shape and the domain of the last such.
    ///
    /// `TRACKER.md` §3 has two specimens agreeing field for field that the
    /// `nanosleep`-parked child's delivery goes missing while the pipe-parked
    /// child's arrives. Those two take different arms by RFC 0083's own
    /// description — a completed call against a call about to park — so the
    /// finished-call arm is *inferred* to be the failing one. This is what
    /// turns that into a measurement, and it answers either way: a count above
    /// zero names the shape that slipped through, and a count of zero with a
    /// signal still owed says the domain never came back to be delivered to at
    /// all.
    ///
    /// **Thirteen and not fifteen**: the record would end at 648 against a
    /// scratch boundary of 640, and the compile-time assertion below would
    /// refuse it. Two words, chosen for what they answer rather than for what
    /// would be convenient to collect.
    /// **Fourteen since 2026-09-23, and fourteen is the last one that fits**:
    /// the record then ends at exactly [`SCRATCH_AT`], and a fifteenth would
    /// trip the assertion below. The word is spent on the blocked mask of the
    /// first domain still owed a delivery.
    ///
    /// `Dispositions::inherit` copies the parent's **blocked** set to a forked
    /// child, deliberately and as Linux does. A handler runs with its own
    /// signal blocked (step 7), so a child forked while its parent is inside
    /// that handler is born unable to receive the signal — `has_pending` masks
    /// it out, no frame is ever asked for, and it stays pending for ever.
    /// That fits every number `TRACKER.md` §3's specimens carry and it is
    /// timing-dependent, which is the shape of a 2.9% race. This word is what
    /// turns that from a fitting story into a reading.
    /// **Seventeen since 2026-09-23**, which moved [`SCRATCH_AT`] for the
    /// fourth time. Fourteen ended at exactly the old boundary and the record
    /// had no room left.
    ///
    /// The three new words account for **every path a pending signal can take
    /// out of a reply**, which is what `TRACKER.md` §3 is now short of. Seven
    /// sightings agree that the bit is set, is not blocked, and that the only
    /// reply carrying it was the target's own `exit_group`. Two hypotheses
    /// died — an inherited blocked set, measured twice; a raise ordered after
    /// its wake, read in `answer_kill` — and what is left is a child that
    /// returned from `nanosleep` without any reply of its reaching the check.
    ///
    /// | word | what it counts |
    /// |---|---|
    /// | `arm_finished` | a frame asked for on a **finished** call |
    /// | `arm_parked` | a frame asked for on a call **about to park** |
    /// | `took_nothing` | the stash taken and `take_pending` answering `None` |
    ///
    /// With `passed` those four partition it. `arm_finished` against
    /// `delivered` is the decisive comparison: equal, and the loss is after the
    /// frame was asked for; short by one, and it is before.
    pub const SIGNAL_WORDS: usize = 17;

    /// Where bulk staging begins.
    ///
    /// Rounded up from the end of the records, so the boundary is legible in a
    /// hex dump rather than merely correct.
    ///
    /// **640 since 2026-09-21; 576 before that, and 512 before that.** The
    /// records ended exactly at 512 while the process record held six words;
    /// widening it to eight took the sixteen bytes [`BIND_AT`] occupied,
    /// silently, because nothing asserted the two did not overlap. That is why
    /// the assertions below exist — and they earned it again on 2026-09-21,
    /// when the signal record grew from five words to seven and ended at 584
    /// against a boundary of 576. **It failed to build instead of overwriting
    /// the scratch**, which is the whole difference between this and the bug it
    /// was written for.
    ///
    /// Each move costs the scratch 64 bytes of the 3,584 it started with,
    /// which is a chunk size rather than a capacity.
    /// **704 since 2026-09-23**; 640 before that, 576 before that, 512 before
    /// that. The signal record reached exactly 640 and had nowhere to grow.
    pub const SCRATCH_AT: usize = 704;

    /// How much of the page bulk staging may use.
    ///
    /// **The rest of it.** 1,024 until 2026-08-21, which made a page-sized
    /// transfer four `COPY_OUT` crossings where `MAX_SUPERVISED_COPY` allows
    /// one — a 4× penalty in a constant, found by the measurement RFC 0036
    /// step 2 took for an unrelated reason. 3,584 makes it two. Reaching one
    /// would need a page of its own, which is an object in the manifest and an
    /// entry in `security.md` §1's T11 list, and is a decision rather than a
    /// constant.
    pub const SCRATCH_BYTES: usize = 4096 - SCRATCH_AT;

    /// The page these offsets are inside.
    pub const PAGE: usize = 4096;

    /// Every record ends before the scratch begins.
    /// **The process record must fit before the record after it.** Nothing
    /// asserted this, which is why widening `PROCESS_WORDS` silently moved two
    /// words on top of [`BIND_AT`] rather than failing to build. It is
    /// redundant now that `BIND_AT` is derived — and it is kept precisely
    /// because the next person to write a literal there will be caught by it.
    const _: () = assert!(PROCESS_AT + PROCESS_WORDS * 8 <= BIND_AT);
    const _: () = assert!(BIND_AT + BIND_WORDS * 8 <= SIGNAL_AT);
    const _: () = assert!(SIGNAL_AT + SIGNAL_WORDS * 8 <= SCRATCH_AT);

    /// **Every record ends before the next one begins.**
    ///
    /// Each offset is derived from the one before it *and that record's own
    /// length*, so a record that grows moves the rest rather than landing on
    /// them. This says it out loud as well, because a derivation is the kind of
    /// thing a later edit replaces with a literal — which is exactly what
    /// `BIND_AT` was, and what let the process record grow onto it unnoticed
    /// until a machine with four network ports read the collision back as a
    /// domain-slot count.
    const _: () = {
        assert!(TRACES_AT + TRACES_WORDS * 8 <= FAULT_LOG_AT);
        assert!(FAULT_LOG_AT + FAULT_LOG_WORDS * 8 <= EXEC_AT);
        assert!(EXEC_AT + EXEC_WORDS * 8 <= FILE_AT);
        assert!(FILE_AT + FILE_WORDS * 8 <= FORK_AT);
        assert!(FORK_AT + FORK_WORDS * 8 <= WAIT_AT);
        assert!(WAIT_AT + WAIT_WORDS * 8 <= COPY_AT);
        assert!(COPY_AT + COPY_WORDS * 8 <= LEND_AT);
        assert!(LEND_AT + LEND_WORDS * 8 <= SOCKET_AT);
        assert!(SOCKET_AT + SOCKET_WORDS * 8 <= PROCESS_AT);
    };

    /// **And the offsets did not move when they became derived.** The refactor
    /// is only worth having if it describes the layout that already exists;
    /// these are the numbers from before it.
    const _: () = {
        assert!(TRACES_AT == 0);
        assert!(FAULT_LOG_AT == 256);
        assert!(EXEC_AT == 320);
        assert!(FILE_AT == 344);
        assert!(FORK_AT == 368);
        assert!(WAIT_AT == 384);
        assert!(COPY_AT == 400);
        assert!(LEND_AT == 416);
        assert!(SOCKET_AT == 432);
        assert!(PROCESS_AT == 448);
        assert!(BIND_AT == 512);
    };
    /// And the scratch ends inside the page.
    const _: () = assert!(SCRATCH_AT + SCRATCH_BYTES == PAGE);
    /// The fault log is past the traces, which is what it used to claim and
    /// was not.
    const _: () = assert!(FAULT_LOG_AT >= TRACES_AT + 8 * 32);
}
