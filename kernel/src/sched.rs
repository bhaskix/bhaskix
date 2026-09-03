// SPDX-License-Identifier: Apache-2.0
//! Threads and per-CPU scheduling.
//!
//! Implements the runqueue structure of `docs/scheduler.md` §2: **one runqueue
//! per CPU**, each with its own lock, rather than a single global queue behind
//! one lock.
//!
//! # Why per-CPU, before there is any contention to relieve
//!
//! The usual argument is throughput — a global runqueue lock does not survive
//! past about four CPUs. That is true and is not the reason this landed now.
//!
//! The reason is that the previous single-queue scheduler was *unsound* on
//! more than one CPU: it took raw pointers into a shared thread table and
//! switched to them after dropping the lock, which is safe only if exactly one
//! processor is ever inside it. Making the queues per-CPU removes the sharing
//! rather than protecting it, which is a much easier thing to be confident
//! about. A CPU touches only its own threads' contexts, so there is nothing
//! for a second CPU to race against.
//!
//! # Work stealing, and how it keeps that property
//!
//! Stealing appears to give the sharing straight back: a thief reaches into
//! another CPU's queue. It does not, because what it moves is *ownership*. A
//! thread is removed from the victim's queue and inserted into the thief's
//! under the two locks, one at a time, and only in a state where no CPU is
//! touching its context. After the move it is owned by the thief exactly as if
//! it had been created there. At no point do two CPUs hold pointers to the
//! same context.
//!
//! Three rules make that true, and each rules out a specific way to corrupt a
//! thread ([`RunQueue::stealable`] and [`try_steal`]):
//!
//! 1. **Only `Ready` threads move.** A `Running` thread's context is not
//!    merely stale, it is the stack the victim is executing on.
//! 2. **Never from a CPU that is mid-switch.** A thread is marked `Ready`
//!    *before* the switch that saves its context, and the runqueue lock is
//!    released in between — it has to be, since the incoming thread will take
//!    it. So "`Ready`" alone admits a thread whose registers have not been
//!    written yet. [`RunQueue::switching`] closes that window.
//! 3. **The thread a CPU booted on never moves.** It is running on the stack
//!    the bootloader gave that CPU, and on secondaries it is the idle thread —
//!    take it away and the CPU has nothing to run when its queue drains.
//!
//! Only ever one lock is held at a time, and the victim's is taken with
//! `try_lock`, so two CPUs stealing from each other cannot deadlock: they both
//! fail and both give up.
//!
//! # What is still missing
//!
//! - **Balancing is pull-only and topology-blind.** A CPU steals when it would
//!   otherwise run only its idle thread; nothing pushes work, and nothing
//!   knows which CPUs share a cache. `docs/scheduler.md` §5 wants wakeup
//!   placement by LLC and NUMA distance, a periodic push pass, and migration
//!   cost accounting. None of that is here, so a steal is as likely to cross
//!   a socket as stay on one.
//! - **No priorities, no fair class.** Still round-robin.
//! - **No blocking.** A thread is runnable or finished; there is no sleep and
//!   no wakeup, so "no lost wakeups" remains not merely unproven but
//!   inexpressible.

use core::sync::atomic::{AtomicU64, Ordering};

use bhaskix_arch::context::{Context, bhaskix_context_switch};
use bhaskix_arch::cpu;
use bhaskix_arch::percpu::{self, MAX_CPUS};
use bhaskix_arch::tsc;

use crate::stack;
use crate::sync::{Rank, SpinLock};

/// Threads per CPU. Small on purpose: the switch path must not allocate, so
/// each queue is a fixed array rather than a heap-backed list.
pub const MAX_THREADS_PER_CPU: usize = 8;

/// What a thread is doing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// Waiting for a turn on its CPU.
    Ready,
    /// Currently executing.
    Running,
    /// Waiting for a condition. Not schedulable until something wakes it.
    Blocked,
    /// Finished; never scheduled again.
    Finished,
}

impl core::fmt::Display for State {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Ready => "ready",
            Self::Running => "running",
            Self::Blocked => "blocked",
            Self::Finished => "finished",
        })
    }
}

impl State {
    /// Whether the scheduler may choose this thread.
    ///
    /// `Blocked` and `Finished` are both unschedulable and are *not*
    /// interchangeable: a blocked thread still owns its stack and its slot and
    /// will run again, and it must keep counting against nothing at all —
    /// including the load figure, or an idle CPU would decline to steal from a
    /// CPU whose threads are all asleep.
    #[must_use]
    pub const fn is_schedulable(self) -> bool {
        matches!(self, Self::Ready | Self::Running)
    }
}

/// Weight of an ordinary Fair thread.
///
/// Ratios are what matter, not the absolute value; 1024 is used because it
/// leaves room to scale a thread down by three orders of magnitude before the
/// division below loses meaningful precision.
pub const BASE_WEIGHT: u64 = 1024;

/// Default slice a Fair thread asks for, in microseconds.
pub const DEFAULT_SLICE_US: u64 = 3_000;

/// How far ahead of a runqueue's virtual clock a thread may get, in units of
/// the default slice.
///
/// Proportional share on its own has no bound on this, and the consequence is
/// not theoretical. A thread that ran alone for a while is far ahead in
/// virtual time; if a group of threads then arrives that each run for
/// microseconds before blocking, they accrue virtual time so slowly that the
/// first thread waits for *all* of them to catch up — which took longer than
/// the test that found it was willing to wait, and read as a hung machine.
///
/// Clamping the lead trades a bounded amount of unfairness for a bound on how
/// long any runnable thread can be passed over. It is deliberately generous,
/// so that it never fires under ordinary contention — where threads track each
/// other within a slice or two — and only rescues the pathological case.
pub const MAX_VRUNTIME_LEAD_SLICES: u64 = 8;

/// Highest real-time priority.
pub const MAX_RT_PRIORITY: u8 = 99;

/// Share of a CPU real-time threads may claim, in percent.
///
/// The remainder is not slack. It is the guarantee that Fair-class threads —
/// including whatever an operator would use to log in and stop a runaway —
/// still run. `docs/scheduler.md` §4 sets this at 95%.
pub const RT_UTILISATION_CAP: u16 = 95;

/// How a real-time thread yields the CPU.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RtPolicy {
    /// Runs until it blocks or yields. Never preempted by an equal priority.
    Fifo,
    /// Also gives way to an equal priority at the end of its quantum.
    RoundRobin,
}

/// Which class a thread belongs to, and its parameters within that class.
///
/// Classes are in **strict priority order**: any runnable real-time thread
/// beats every fair thread, and any fair thread beats idle. That an RT thread
/// can starve a fair one is the intended behaviour rather than a flaw — the
/// mitigation is admission control on the RT side, not a softened rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Policy {
    /// Fixed priority, 0..=[`MAX_RT_PRIORITY`], higher wins.
    RealTime {
        /// Fixed priority; higher runs first.
        priority: u8,
        /// Whether an equal priority may displace it.
        policy: RtPolicy,
        /// Declared share of the CPU, in percent, for admission control.
        utilisation: u16,
    },
    /// Weighted proportional share.
    Fair {
        /// Share relative to [`BASE_WEIGHT`]. Twice the weight, twice the CPU.
        weight: u32,
    },
    /// Runs only when nothing else can. One per CPU.
    Idle,
}

impl Policy {
    /// An ordinary thread.
    #[must_use]
    pub const fn fair() -> Self {
        Self::Fair {
            weight: BASE_WEIGHT as u32,
        }
    }

    /// Short tag for the boot report.
    const fn tag(self) -> &'static str {
        match self {
            Self::RealTime { .. } => "rt",
            Self::Fair { .. } => "fair",
            Self::Idle => "idle",
        }
    }
}

/// A capability a caller has staged for its next call.
///
/// [RFC 0022](../../docs/rfc/0022-capability-in-a-call.md) step 1. A caller's
/// `HAND` cannot execute a transfer — the service thread that will take its
/// call is not known until the rendezvous — so it records intent here, one
/// gift per thread, and the rendezvous completes it or refuses the call.
///
/// **One-shot and replaceable**: a second staging before the call replaces the
/// first — the same replace-not-accumulate rule `ARM` follows, because
/// re-staging is how a caller says "this one instead" — and the rendezvous
/// consumes it. Addressed to one endpoint, so a gift staged for one service
/// cannot ride a call to another; a `Call` elsewhere leaves it in place.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct StagedGift {
    /// The slot in the staging thread's own CSpace holding the capability.
    pub from_slot: u32,
    /// The rights the derive at the rendezvous will request.
    pub rights: u8,
    /// The badge the derive will request, monotone or refused there.
    pub badge: u64,
    /// The endpoint this gift is for.
    pub endpoint: u32,
}

/// One kernel thread. Owned outright by the CPU whose queue holds it.
pub struct Thread {
    /// Globally unique identifier.
    pub id: u32,
    /// For diagnostics.
    pub name: &'static str,
    /// Saved registers, valid whenever the thread is not running.
    pub context: Context,
    /// Scheduling state.
    pub state: State,
    /// Times this thread has been switched to.
    pub runs: u64,
    /// Times this thread has been moved between CPUs.
    pub migrations: u64,
    /// Lock ranks this thread holds while it is not running.
    ///
    /// Held locks belong to the thread, not the processor. A thread preempted
    /// while holding the heap must take that fact with it, or the next thread
    /// to run on that CPU inherits an ordering constraint it had no part in.
    pub held_locks: u64,
    /// How many locks this thread holds while it is not running.
    ///
    /// Travels with the thread for the same reason [`Thread::held_locks`]
    /// does, and is separate from it because the two are given up at opposite
    /// ends of a release: the rank mask before the lock is let go, so the next
    /// acquisition of that rank is not misread as a second one, and this count
    /// after, so there is no instant where the lock is held and the CPU says
    /// it holds nothing. `sync::holds_any` is what `preempt` consults.
    pub held_count: u32,
    /// Whether this thread may never migrate.
    ///
    /// True for the thread each CPU registers for itself: it runs on the stack
    /// that CPU booted on, so "move it elsewhere" is not a meaningful request.
    pub pinned: bool,
    /// The page table this thread runs in, or zero for the kernel's.
    ///
    /// Kernel threads leave this zero and run in whatever is loaded, which is
    /// safe because every address space carries the same higher half. A user
    /// thread cannot: its code, stack and data are in the lower half, and
    /// resuming in the space that happened to run last would put it in another
    /// program's memory. That is not hypothetical — it is what two services in
    /// domains on one CPU did, and the only reason it had never happened is
    /// that there had never been two user programs on one CPU at once.
    pub space_root: u64,
    /// This thread's floating-point and SSE register file, saved when it
    /// leaves a CPU and restored when it arrives.
    ///
    /// **`CR4.OSFXSR` is the OS promising to do exactly this**, and the
    /// promise is what makes enabling SSE safe: the register file is per
    /// CPU and threads are not, so two threads sharing one would otherwise
    /// read each other's floating-point values — silently, and only
    /// sometimes, which is the worst shape a bug can have.
    ///
    /// Starts as the image `FXSAVE` produced of the machine's own initial
    /// state, not as zeroes: a zeroed area is not a valid state image, and
    /// `FXRSTOR` of one sets a control word no program asked for.
    pub fx: FxArea,
    /// The thread-local base this thread asked for with Linux's
    /// `arch_prctl(ARCH_SET_FS)`, or zero.
    ///
    /// **Per thread, because the register is per CPU.** Writing the MSR in
    /// the system call and leaving it there survives exactly until the next
    /// context switch — and Go's `rt0` stores through `fs:` and reads it
    /// back three instructions after asking, then executes `UD2` if the
    /// value did not survive. It did not, and that `UD2` is how this field
    /// came to exist.
    pub fs_base: u64,

    /// The caller this thread received from and has not yet answered.
    ///
    /// Set when a message is taken, cleared when it is answered. It exists so
    /// that a reply does not have to be *told* who to answer: a server that
    /// could name the thread to reply to could plant a message in the mailbox
    /// of a thread it never heard from, and wake it holding an answer to a
    /// question it did not ask. The caller is not a secret, so hiding it was
    /// never the point -- not accepting it is.
    pub reply_to: Option<u32>,
    /// Where a capability handed back may be put, and **which service** may.
    ///
    /// Declared by this thread before it calls, and consumed when one arrives.
    /// A server does not choose where its answer lands: a program's CSpace is
    /// its own to arrange, and a service that could pick a slot could fill one
    /// a caller was keeping empty on purpose — which the shell does, and which
    /// one of its own tests depends on.
    ///
    /// The endpoint is half of it, and the half that was missing. This was one
    /// slot number, cleared when *any* call returned — so a program that said
    /// where, printed a line, and then asked, lost its declaration to the
    /// console: printing is a call too. Naming the endpoint it was made for
    /// means an unrelated call cannot consume it, and a server still cannot
    /// receive an invitation addressed to somebody else.
    pub receive_slot: Option<(u32, u32)>,
    /// The capability this thread has staged for its next call, if any.
    ///
    /// The caller-direction mirror of [`Self::receive_slot`]: that says where
    /// this thread will *accept* one, this says which one it will *send*.
    /// Dies with the thread, exactly as the declaration does.
    pub staged_gift: Option<StagedGift>,
    /// When [`wake`] marked this thread ready, as a cycle count, or zero.
    ///
    /// The other half of a measurement: RFC 0023 priced a wake-driven wait
    /// at one to three milliseconds more than a poll, and this is what says
    /// whether the scheduler's wake-to-dispatch gap is the cost or an alibi.
    /// Stamped by the waker, read and cleared at dispatch, accumulated into
    /// the counters the boot report prints.
    pub woken_at: u64,

    /// A call this thread made was refused at the rendezvous, with this
    /// status.
    ///
    /// RFC 0022 step 2. Set by the *server's* receive path when a staged
    /// gift cannot be completed — no declaration, no `GRANT`, rights not
    /// monotone — because the caller is already blocked awaiting a reply
    /// that must now never come, and it has to be told with the status the
    /// refusal actually had. Checked in [`take_message_or_block`] beside
    /// [`Self::answer_lost`], which is the same shape of news.
    pub call_refused: Option<u32>,

    /// The domain this thread belongs to, or `u32::MAX` for none.
    ///
    /// Kernel threads created before domains exist have no domain, and must
    /// not be swept up by a re-weighting aimed at one.
    pub domain: u32,
    /// The answer this thread is waiting for is never coming.
    ///
    /// Set when the thread that owed it dies. A caller blocked in `Call` has no
    /// way to discover this for itself: the endpoint it called is still there,
    /// it is still a legitimate capability, and there may even be another
    /// server on it later — what has gone is the *obligation*, which lived in
    /// one thread. So it has to be told.
    ///
    /// Distinct from an endpoint being destroyed, which the caller can see, and
    /// distinct from [`Self::dying`], which is about this thread rather than
    /// the one it was waiting on.
    pub answer_lost: bool,

    /// This thread has been told to stop, and will at the next safe point.
    ///
    /// **A flag rather than a fifth [`State`]**, and the distinction is the
    /// design. A dying thread is still `Ready`, `Running` or `Blocked` — it has
    /// not stopped yet, and everything that reasons about runnability, load or
    /// eviction must keep seeing it as what it is until it does. A `State`
    /// variant would have to be handled by every one of those, and the ones
    /// that forgot would be the interesting bugs.
    ///
    /// It cannot be acted on wherever it is noticed. A thread may be holding a
    /// runqueue lock, be part-way through a capability derivation, or be the
    /// half-completed side of an IPC rendezvous — freeing its stack at any of
    /// those points corrupts a structure the rest of the kernel shares. So it
    /// is *read* at points where the thread demonstrably holds nothing:
    /// returning to user mode, and deciding to block. See
    /// [RFC 0017](../../docs/rfc/0017-process-management.md) step 2.
    pub dying: bool,
    /// A message delivered to this thread, and who sent it.
    ///
    /// One slot, because IPC is a rendezvous: a thread has at most one
    /// outstanding message at a time by construction, so a queue here would be
    /// a place for a second one to arrive that the protocol does not allow.
    pub mailbox: Option<(crate::ipc::Message, u32)>,
    /// One past this thread's kernel stack, for entry from user mode.
    ///
    /// Both the `SYSCALL` stub and the CPU's ring 3 → ring 0 transition need a
    /// kernel stack, and both must get *this thread's* — not the CPU's. A
    /// shared one is correct only while at most one thread per CPU can be in
    /// the kernel from user mode; the moment a system call blocks, a second
    /// thread enters on the same stack and overwrites the first's frame.
    pub kernel_stack_top: u64,
    /// Class and parameters.
    pub policy: Policy,
    /// Service received, scaled by weight. Only meaningful for Fair.
    ///
    /// A heavier thread accumulates this more slowly for the same real time,
    /// so choosing the smallest gives service in proportion to weight. That is
    /// the whole of proportional fairness.
    pub vruntime: u64,
    /// Virtual time by which this thread would like to have run.
    ///
    /// `vruntime + slice/weight`. Choosing the earliest is what separates this
    /// from picking the smallest `vruntime`: a thread that asks for a *short*
    /// slice earns an earlier deadline and so runs sooner and more often, for
    /// the same total share. That is how a latency-sensitive thread declares
    /// itself instead of being guessed at from its sleep pattern.
    pub deadline: u64,
    /// Requested slice, in TSC ticks.
    pub slice_ticks: u64,
    /// Real CPU ticks consumed.
    pub cycles: u64,
    /// TSC reading when this thread was last dispatched.
    pub last_start: u64,
}

impl Thread {
    /// Charges `delta` ticks of real service to this thread.
    fn charge(&mut self, delta: u64) {
        self.cycles = self.cycles.saturating_add(delta);
        if let Policy::Fair { weight } = self.policy {
            let weight = u64::from(weight.max(1));
            self.vruntime = self
                .vruntime
                .saturating_add(delta.saturating_mul(BASE_WEIGHT) / weight);
            self.deadline = self
                .vruntime
                .saturating_add(self.slice_ticks.saturating_mul(BASE_WEIGHT) / weight);
        }
    }
}

/// One CPU's runqueue.
struct RunQueue {
    threads: [Option<Thread>; MAX_THREADS_PER_CPU],
    /// Index of the thread currently on this CPU.
    current: usize,
    /// Whether this CPU may preempt yet.
    started: bool,
    /// This runqueue's virtual clock: the floor a waking or new thread is
    /// lifted to.
    ///
    /// **Monotonic, and that is the whole point.** The obvious implementation
    /// — take the smallest `vruntime` among threads that can currently run —
    /// moves *backwards* whenever a long-sleeping thread becomes runnable, and
    /// a thread that sleeps more than it runs therefore accumulates unbounded
    /// credit. Four such threads handing work to each other kept their virtual
    /// time near zero and starved a CPU-bound thread completely; the machine
    /// looked hung and was in fact scheduling exactly as written.
    ///
    /// A floor that never decreases bounds that credit at zero. Latency for
    /// threads that sleep does not come from virtual-time credit here — it
    /// comes from asking for a short slice, which earns an earlier deadline.
    /// That separation is the point of a virtual *deadline*.
    min_vruntime: u64,
    /// TSC value at which the running thread's slice expires.
    ///
    /// Absolute rather than a duration, because the timer is re-armed by every
    /// interrupt that reaches the scheduler and not only by the one that ends
    /// a slice. Arming for a *fresh* slice each time silently extends whoever
    /// happens to be running when an unrelated interrupt lands — a reschedule
    /// IPI, a shootdown — and the thread that runs most often benefits most.
    /// It measured as a 3:1 weight ratio delivering 3.7:1, while the policy
    /// itself is exactly 3:1 in simulation.
    slice_deadline: u64,
    /// Whether this CPU is between choosing a switch and completing it.
    ///
    /// Set under the lock before the lock is released for the switch, and
    /// cleared once the outgoing context has actually been written. While it
    /// is set, one thread in this queue is marked `Ready` but its saved
    /// registers are not yet valid, so nothing may be stolen from here.
    switching: bool,
}

impl RunQueue {
    const fn new() -> Self {
        Self {
            threads: [const { None }; MAX_THREADS_PER_CPU],
            current: 0,
            started: false,
            min_vruntime: 0,
            slice_deadline: 0,
            switching: false,
        }
    }

    /// Threads on this queue that could run: the load figure balancing uses.
    fn runnable(&self) -> usize {
        self.threads
            .iter()
            .flatten()
            .filter(|thread| thread.state.is_schedulable())
            .count()
    }

    /// Which thread, if any, a CPU with `thief_load` runnable threads may take
    /// from this queue.
    ///
    /// The whole steal policy, in one place and with no side effects, because
    /// every rule here is one that is invisible when broken. Removing the
    /// `pinned` test does not fail a boot; it strands a CPU minutes later,
    /// once its queue happens to drain. Removing the `switching` test corrupts
    /// a thread only when the timing lines up. Neither is something a boot
    /// test can be relied on to provoke, so they are unit-tested instead.
    fn steal_candidate(&self, thief_load: usize) -> Option<usize> {
        // Rule 2: a CPU partway through a switch has a thread already marked
        // `Ready` whose registers have not been written yet, and nothing here
        // distinguishes it from one that has been parked for a while.
        if self.switching {
            return None;
        }

        // Worth moving at all? See `STEAL_IMBALANCE`.
        if self.runnable() < thief_load + STEAL_IMBALANCE {
            return None;
        }

        self.threads.iter().position(|slot| {
            slot.as_ref().is_some_and(|thread| {
                // Rule 1: `Running` is the stack the victim is executing on.
                // `Finished` is not worth moving and would confuse the load
                // figure at the far end.
                thread.state == State::Ready
                    // Rule 3: the thread a CPU booted on runs on the stack
                    // that CPU was given, and on a secondary it is also the
                    // only thing left to run when the queue drains.
                    && !thread.pinned
                    // Rule 4: real-time threads do not migrate. Admission
                    // control is per-CPU, so moving one silently invalidates
                    // the budget at both ends -- the source keeps reserving
                    // capacity it no longer needs and the destination admits
                    // work it never counted. A latency guarantee that a
                    // background balancer can quietly overcommit is not one.
                    && !matches!(thread.policy, Policy::RealTime { .. })
            })
        })
    }

    /// First unused slot.
    fn free_slot(&self) -> Option<usize> {
        self.threads.iter().position(Option::is_none)
    }

    /// Drops finished threads, freeing their slots.
    ///
    /// Never the thread the CPU is currently on, even if it has finished: it
    /// is still executing on its own stack inside `exit`, and the switch away
    /// from it will read its context. Everything else that has finished is
    /// quiescent by definition — nothing will schedule it again — so its slot
    /// is reusable.
    ///
    /// Reaped lazily, when a slot is wanted, rather than eagerly on exit:
    /// exit runs with the CPU's queue in a state the exiting thread is still
    /// part of, and unpicking that at the moment of departure is how a
    /// use-after-free gets written.
    ///
    /// The *stack* is not reclaimed; that needs an allocator for stack slots
    /// and is recorded in TRACKER.md as outstanding.
    fn reap_finished(&mut self) {
        let current = self.current;
        for (slot, entry) in self.threads.iter_mut().enumerate() {
            if slot != current && entry.as_ref().is_some_and(|t| t.state == State::Finished) {
                *entry = None;
            }
        }
    }

    /// Slot indices in round-robin order, starting *after* `from`.
    ///
    /// Ending at `from` rather than starting there is what makes equal-ranked
    /// threads rotate: every comparison below is strict, so a peer visited
    /// earlier wins and the running thread is only kept when nothing ties it.
    fn slots_from(&self, from: usize) -> impl Iterator<Item = usize> + use<> {
        (1..=MAX_THREADS_PER_CPU).map(move |offset| (from + offset) % MAX_THREADS_PER_CPU)
    }

    fn schedulable(&self, slot: usize) -> Option<&Thread> {
        self.threads[slot]
            .as_ref()
            .filter(|thread| thread.state.is_schedulable())
    }

    /// The thread that should run next on this CPU.
    ///
    /// The whole scheduling policy, as a pure function of the queue, so that
    /// the class rules can be tested exhaustively on the host instead of being
    /// inferred from how a boot happened to interleave. Returning `from` means
    /// "no switch".
    ///
    /// Strict priority between classes, per `docs/scheduler.md` §2: a runnable
    /// real-time thread is chosen over every fair thread, and a fair thread
    /// over idle. There is no weighting *between* classes and there is not
    /// meant to be.
    fn pick_next(&self, from: usize) -> usize {
        // --- Real time: highest priority wins, ties rotate. -----------------
        let mut best: Option<(u8, usize)> = None;
        for slot in self.slots_from(from) {
            if let Some(thread) = self.schedulable(slot)
                && let Policy::RealTime { priority, .. } = thread.policy
                && best.is_none_or(|(best_priority, _)| priority > best_priority)
            {
                best = Some((priority, slot));
            }
        }

        if let Some((priority, slot)) = best {
            // FIFO means exactly this: an equal priority does not displace the
            // running thread. Only a strictly higher one does, and otherwise
            // it runs until it blocks or exits.
            if let Some(current) = self.schedulable(from)
                && let Policy::RealTime {
                    priority: mine,
                    policy: RtPolicy::Fifo,
                    ..
                } = current.policy
                && mine >= priority
            {
                return from;
            }
            return slot;
        }

        // --- Fair: earliest virtual deadline. -------------------------------
        //
        // Ties go to the next thread in rotation, and that is already the
        // right answer: `slots_from` starts one past `from`, so a fresh
        // thread tying the runner's deadline is found first and wins. The
        // captured boot hang's dump made this look broken — two fresh
        // threads starving at a deadline tie — and a test written to pin
        // the suspicion refuted it: the starvation was the hold-count veto
        // alone, which kept this function from running at all. Written down
        // here because the wrong claim briefly lived in TRACKER, and the
        // rotation deserves its alibi in the place someone would next
        // suspect it.
        let mut best: Option<(u64, usize)> = None;
        for slot in self.slots_from(from) {
            if let Some(thread) = self.schedulable(slot)
                && matches!(thread.policy, Policy::Fair { .. })
                && best.is_none_or(|(best_deadline, _)| thread.deadline < best_deadline)
            {
                best = Some((thread.deadline, slot));
            }
        }
        if let Some((_, slot)) = best {
            return slot;
        }

        // --- Idle. ----------------------------------------------------------
        for slot in self.slots_from(from) {
            if self.schedulable(slot).is_some() {
                return slot;
            }
        }
        from
    }

    /// Advances the virtual clock, never backwards, and bounds how far ahead
    /// of it any thread may be.
    fn advance_min_vruntime(&mut self) {
        let smallest = self.min_fair_vruntime();
        self.min_vruntime = self.min_vruntime.max(smallest);

        let Some(ceiling) = self
            .threads
            .iter()
            .flatten()
            .map(|thread| thread.slice_ticks)
            .max()
            .map(|slice| {
                self.min_vruntime
                    .saturating_add(slice.saturating_mul(MAX_VRUNTIME_LEAD_SLICES))
            })
        else {
            return;
        };

        for thread in self.threads.iter_mut().flatten() {
            if matches!(thread.policy, Policy::Fair { .. }) && thread.vruntime > ceiling {
                thread.vruntime = ceiling;
                thread.charge(0);
            }
        }
    }

    /// Smallest `vruntime` among fair threads that could run.
    ///
    /// Only an input to [`RunQueue::advance_min_vruntime`]; the floor itself is
    /// `min_vruntime`, which clamps this to never decrease.
    fn min_fair_vruntime(&self) -> u64 {
        self.threads
            .iter()
            .flatten()
            .filter(|thread| {
                thread.state.is_schedulable() && matches!(thread.policy, Policy::Fair { .. })
            })
            .map(|thread| thread.vruntime)
            .min()
            .unwrap_or(0)
    }

    /// Real-time utilisation already admitted on this CPU, in percent.
    fn rt_utilisation(&self) -> u16 {
        self.threads
            .iter()
            .flatten()
            .filter(|thread| thread.state != State::Finished)
            .map(|thread| match thread.policy {
                Policy::RealTime { utilisation, .. } => utilisation,
                _ => 0,
            })
            .sum()
    }
}

/// One queue per CPU, each independently locked.
static QUEUES: [SpinLock<RunQueue>; MAX_CPUS] =
    [const { SpinLock::new(Rank::SchedRunqueue, RunQueue::new()) }; MAX_CPUS];

/// Hands out globally unique thread identifiers and stack slots.
///
/// Stack slots must be unique across *all* CPUs, not just within one queue —
/// two CPUs allocating the same slot would give two threads the same stack,
/// which is the kind of corruption that presents as anything but its cause.
static NEXT_THREAD: AtomicU64 = AtomicU64::new(0);

/// Context switches performed, across every CPU.
static SWITCHES: AtomicU64 = AtomicU64::new(0);

/// Vector used to tell another CPU that its runqueue changed.
///
/// One above the shootdown vector, and for the same reason that one exists:
/// marking a thread `Ready` in another CPU's queue changes nothing that CPU
/// can observe until it next looks — and if it is idle, or has stopped its
/// timer, it may not look again for a very long time.
pub const RESCHEDULE_VECTOR: u8 = 0x41;

/// Reschedule interrupts sent to other CPUs.
static RESCHEDULE_IPIS: AtomicU64 = AtomicU64::new(0);

/// A kernel hold count found nonzero where it must be zero, with the system
/// call that left it that way. See the canary in `syscall.rs`; printed once
/// per boot in full and counted after, because the first leak is the story
/// and a leaking hot path would otherwise flood the console it needs.
static HOLD_LEAKS: AtomicU64 = AtomicU64::new(0);
static FIRST_LEAK: AtomicU64 = AtomicU64::new(0);

/// Records a hold leak at syscall exit. `kind` and `method` name the call.
pub fn note_hold_leak(kind: u64, method: u64) {
    let count = HOLD_LEAKS.fetch_add(1, Ordering::Relaxed);
    if count == 0 {
        FIRST_LEAK.store(kind << 32 | (method & 0xffff_ffff), Ordering::Relaxed);
        let cpu = percpu::cpu_id() as usize;
        crate::println!(
            "\x1b[91m  HOLD LEAK: returning to ring 3 with cpu {}'s hold count nonzero, rank \
             mask {:#x}, after syscall kind {} method {}. This count vetoes preemption on this \
             cpu until it returns to zero, which nothing will now do -- this is the boot hang, \
             caught at the door it leaked through.\x1b[0m",
            cpu,
            crate::sync::held_on(cpu),
            kind,
            method,
        );
    }
}

/// The hold-leak tally and the first leak's `(kind << 32) | method`.
#[must_use]
pub fn hold_leaks() -> (u64, u64) {
    (
        HOLD_LEAKS.load(Ordering::Relaxed),
        FIRST_LEAK.load(Ordering::Relaxed),
    )
}

/// Wake-to-dispatch, in cycles: how long woken threads sat ready before a
/// CPU ran them. The scheduler's own share of RFC 0023's measured latency.
static WAKE_TO_RUN_SUM: AtomicU64 = AtomicU64::new(0);
static WAKE_TO_RUN_COUNT: AtomicU64 = AtomicU64::new(0);
static WAKE_TO_RUN_MAX: AtomicU64 = AtomicU64::new(0);
/// Power-of-two buckets of the same delays, because a mean is the wrong
/// statistic for a distribution with bring-up in it: one four-second outlier
/// contributes hundreds of microseconds of mean across sixteen thousand
/// wakes, and the median it buries is the number the design decisions need.
/// Bucket `i` holds delays in `[2^i, 2^(i+1))` cycles.
static WAKE_TO_RUN_BUCKETS: [AtomicU64; 48] = [const { AtomicU64::new(0) }; 48];

/// The worst wake-to-dispatch, packed with the thread it happened to.
///
/// `waited << 16 | thread`, so `fetch_max` orders by the delay and carries the
/// thread along with it. Forty-eight bits of ticks is about a day at 3 GHz, and
/// sixteen of thread id is the whole table twice over.
///
/// **The packing exists because the number alone was useless.** Every boot on
/// 2026-08-21 reported a worst case of ~8.027 seconds — healthy boots and
/// failing ones alike, varying by less than two milliseconds between them — and
/// a worst case that is the same constant on every run is measuring something
/// other than what it claims. Nothing could say which thread it was, so nothing
/// could say whether it mattered. Now it can.
static WAKE_TO_RUN_WORST: AtomicU64 = AtomicU64::new(0);

/// The wake-to-dispatch tallies: `(count, total cycles, worst cycles)`.
#[must_use]
pub fn wake_to_run() -> (u64, u64, u64) {
    (
        WAKE_TO_RUN_COUNT.load(Ordering::Relaxed),
        WAKE_TO_RUN_SUM.load(Ordering::Relaxed),
        WAKE_TO_RUN_MAX.load(Ordering::Relaxed),
    )
}

/// The worst wake-to-dispatch and the thread it happened to: `(cycles, thread)`.
#[must_use]
pub fn wake_to_run_worst() -> (u64, u32) {
    let packed = WAKE_TO_RUN_WORST.load(Ordering::Relaxed);
    (packed >> 16, (packed & 0xffff) as u32)
}

/// The delay, in cycles, below which `percent` of wakes dispatched.
///
/// Answered from the histogram's bucket upper bounds, so the answer is at
/// most a factor of two above the truth — plenty for the question being
/// asked, which is "microseconds or milliseconds".
#[must_use]
pub fn wake_to_run_percentile(percent: u64) -> u64 {
    let total: u64 = WAKE_TO_RUN_BUCKETS
        .iter()
        .map(|bucket| bucket.load(Ordering::Relaxed))
        .sum();
    if total == 0 {
        return 0;
    }
    let want = (total * percent).div_ceil(100);
    let mut seen = 0;
    for (index, bucket) in WAKE_TO_RUN_BUCKETS.iter().enumerate() {
        seen += bucket.load(Ordering::Relaxed);
        if seen >= want {
            return 1u64 << (index + 1);
        }
    }
    WAKE_TO_RUN_MAX.load(Ordering::Relaxed)
}

/// Threads that actually went to sleep.
static BLOCKS: AtomicU64 = AtomicU64::new(0);

/// Threads moved from blocked back to ready.
static WAKEUPS: AtomicU64 = AtomicU64::new(0);

/// Sleeps abandoned because the wakeup arrived before the thread could sleep.
///
/// Not a safety counter. By the time this fires the waker has already marked
/// the thread `Ready`, and a `Ready` thread runs again regardless; what the
/// recheck saves is a pointless context switch, and a thread with nothing to
/// switch to from spinning in the block path forever.
static RACES: AtomicU64 = AtomicU64::new(0);

/// Threads moved from one CPU's queue to another's.
static STEALS: AtomicU64 = AtomicU64::new(0);

/// How much busier a CPU must be before its work is worth taking.
///
/// Two, not one. At one, a thief with a single thread would take from a CPU
/// with two, leaving both with two and one — and the victim, now the lighter
/// of the pair, would take it straight back. The thread would then spend its
/// life migrating instead of running. Requiring a gap of two means the move
/// leaves the pair no more unbalanced than it found them, so it converges.
const STEAL_IMBALANCE: usize = 2;

/// Why a thread could not be created.
#[derive(Clone, Copy, Debug)]
pub enum SpawnError {
    /// The target CPU does not exist.
    NoSuchCpu(u32),
    /// That CPU's queue is full.
    QueueFull(u32),
    /// A guarded stack could not be allocated.
    NoStack(crate::vm::VmError),
    /// Admitting this real-time thread would exceed the CPU's budget.
    RtOverCommitted {
        /// The CPU that refused it.
        cpu: u32,
        /// Utilisation already admitted there, in percent.
        admitted: u16,
        /// Utilisation this thread asked for, in percent.
        requested: u16,
    },
}

/// Registers the calling CPU's current execution as its first thread.
///
/// Every CPU needs this before it can be preempted: without an entry there is
/// nowhere to save the context of whatever is already running, and the first
/// switch would lose it.
pub fn init_cpu(name: &'static str, policy: Policy) {
    let cpu = percpu::cpu_id() as usize;
    if cpu >= MAX_CPUS {
        return;
    }
    let id = NEXT_THREAD.fetch_add(1, Ordering::Relaxed) as u32;

    // Idempotent, and every CPU runs this before any thread can be created on
    // it, which is the ordering the hook requires.
    bhaskix_arch::context::set_thread_entered(thread_entered);

    let mut queue = QUEUES[cpu].lock();
    queue.threads[0] = Some(Thread {
        id,
        name,
        context: Context::new(),
        state: State::Running,
        runs: 1,
        migrations: 0,
        held_locks: 0,
        held_count: 0,
        space_root: 0,
        fs_base: 0,
        fx: FxArea::initial(),
        reply_to: None,
        receive_slot: None,
        staged_gift: None,
        woken_at: 0,
        call_refused: None,
        domain: u32::MAX,
        dying: false,
        answer_lost: false,
        mailbox: None,
        // The thread a CPU registers for itself is already running on the
        // stack the bootloader gave it, and never enters from user mode.
        kernel_stack_top: 0,
        policy,
        vruntime: 0,
        deadline: 0,
        slice_ticks: default_slice_ticks(),
        cycles: 0,
        last_start: tsc::read(),
        // This thread *is* the CPU's boot context, executing on the stack the
        // bootloader handed it. Migrating it would move a stack out from under
        // the processor standing on it.
        pinned: true,
    });
    // Establish the deadline from the slice, exactly as `spawn_on_with` does.
    // Leaving it at zero gives this thread the earliest deadline that exists,
    // so it wins every comparison for ever and nothing spawned later runs at
    // all -- which is precisely what happened.
    if let Some(thread) = queue.threads[0].as_mut() {
        thread.charge(0);
    }
    queue.current = 0;
}

/// Creates a thread on `cpu` that will run `entry(argument)`.
///
/// # Errors
///
/// [`SpawnError`] if the CPU or a slot is unavailable, or no stack could be
/// allocated.
pub fn spawn_on(
    cpu: u32,
    name: &'static str,
    entry: extern "C" fn(u64) -> !,
    argument: u64,
    hhdm_base: u64,
) -> Result<u32, SpawnError> {
    spawn_on_with(cpu, name, entry, argument, hhdm_base, SpawnOptions::new())
}

/// How a thread should be scheduled, beyond where it starts.
#[derive(Clone, Copy, Debug)]
pub struct SpawnOptions {
    /// Class and parameters.
    pub policy: Policy,
    /// Requested slice, in microseconds. Shorter means chosen sooner and more
    /// often for the same total share.
    pub slice_us: u64,
    /// Whether the balancer may move this thread to another CPU.
    pub pinned: bool,
    /// The domain this thread belongs to, or `u32::MAX` for none.
    pub domain: u32,
}

impl Default for SpawnOptions {
    fn default() -> Self {
        Self::new()
    }
}

impl SpawnOptions {
    /// An ordinary fair thread, movable, with the default slice.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            policy: Policy::fair(),
            slice_us: DEFAULT_SLICE_US,
            pinned: false,
            domain: u32::MAX,
        }
    }

    /// Places the thread in a domain, so its weight follows that domain's
    /// share.
    #[must_use]
    pub const fn in_domain(mut self, domain: u32) -> Self {
        self.domain = domain;
        self
    }

    /// Sets the class.
    #[must_use]
    pub const fn policy(mut self, policy: Policy) -> Self {
        self.policy = policy;
        self
    }

    /// Sets the requested slice.
    #[must_use]
    pub const fn slice_us(mut self, slice_us: u64) -> Self {
        self.slice_us = slice_us;
        self
    }

    /// Keeps this thread on the CPU it was created on.
    #[must_use]
    pub const fn pinned(mut self) -> Self {
        self.pinned = true;
        self
    }
}

/// The requested slice in TSC ticks, or a fallback if the TSC is uncalibrated.
///
/// Without a rate the absolute value is meaningless, but deadlines are only
/// ever compared with each other -- so a consistent arbitrary unit still
/// orders threads correctly, and only the *reported* microseconds are wrong.
fn slice_ticks_for(slice_us: u64) -> u64 {
    tsc::from_micros(slice_us).unwrap_or(slice_us * 1000).max(1)
}

fn default_slice_ticks() -> u64 {
    slice_ticks_for(DEFAULT_SLICE_US)
}

/// Creates a thread on `cpu` with an explicit scheduling class.
///
/// # Errors
///
/// As [`spawn_on`], plus [`SpawnError::RtOverCommitted`] if admitting a
/// real-time thread would take the CPU past [`RT_UTILISATION_CAP`].
pub fn spawn_on_with(
    cpu: u32,
    name: &'static str,
    entry: extern "C" fn(u64) -> !,
    argument: u64,
    hhdm_base: u64,
    options: SpawnOptions,
) -> Result<u32, SpawnError> {
    let SpawnOptions {
        policy,
        slice_us,
        pinned,
        domain: _,
    } = options;
    if cpu as usize >= MAX_CPUS || cpu >= percpu::online_count() {
        return Err(SpawnError::NoSuchCpu(cpu));
    }

    // The slot is reserved under the lock, but the stack is allocated *outside*
    // it. Allocation needs the heap, and holding a runqueue lock across it
    // would order the two locks the opposite way round from every other path.
    let (slot, floor) = {
        let mut queue = QUEUES[cpu as usize].lock();

        // Admission control, before anything is allocated. `docs/scheduler.md`
        // §4: exceeding the cap must fail the request rather than hang the
        // machine, because the capacity being protected is what an operator
        // would need to *fix* an over-committed machine.
        if let Policy::RealTime { utilisation, .. } = policy {
            let admitted = queue.rt_utilisation();
            if admitted + utilisation > RT_UTILISATION_CAP {
                return Err(SpawnError::RtOverCommitted {
                    cpu,
                    admitted,
                    requested: utilisation,
                });
            }
        }

        queue.reap_finished();
        let Some(slot) = queue.free_slot() else {
            return Err(SpawnError::QueueFull(cpu));
        };
        (slot, queue.min_vruntime)
    };

    // Globally unique, so no two threads on any CPU can share a stack. The +1
    // steps past the slot the bootstrap kernel stack already occupies.
    let id = NEXT_THREAD.fetch_add(1, Ordering::Relaxed) as u32;

    // SAFETY: the stack slot is unique across all CPUs by construction, and
    // page-table modification is still serialised — only the bootstrap CPU
    // spawns threads.
    let guarded =
        unsafe { stack::allocate(hhdm_base, u64::from(id) + 1) }.map_err(SpawnError::NoStack)?;

    let mut context = Context::new();
    // SAFETY: `guarded.top` is one past a freshly mapped, page-aligned stack,
    // and `entry` is typed as diverging so it cannot return.
    unsafe { context.prepare(guarded.top, entry, argument) };

    // Counted *before* the thread becomes reachable below: once it sits on a
    // queue another CPU may run it to `exit` immediately, and a departure
    // recorded before its arrival would underflow the count and elect two
    // last threads on the domain's real last exit. Every path from here to
    // the insertion is infallible, so the count cannot leak on a failed
    // spawn. The arrival half of the arithmetic that answers "am I my
    // domain's last thread" in `exit`.
    if options.domain != u32::MAX {
        domain_thread_arrives(options.domain);
    }

    let mut queue = QUEUES[cpu as usize].lock();
    queue.threads[slot] = Some(Thread {
        id,
        name,
        context,
        state: State::Ready,
        runs: 0,
        migrations: 0,
        held_locks: 0,
        held_count: 0,
        space_root: 0,
        fs_base: 0,
        fx: FxArea::initial(),
        reply_to: None,
        receive_slot: None,
        staged_gift: None,
        woken_at: 0,
        call_refused: None,
        domain: options.domain,
        dying: false,
        answer_lost: false,
        mailbox: None,
        kernel_stack_top: guarded.top,
        pinned,
        policy,
        // Starting at the floor rather than at zero. A new thread with
        // `vruntime` of zero is owed every microsecond the CPU has ever run,
        // and would monopolise it until it caught up.
        vruntime: floor,
        deadline: 0,
        slice_ticks: slice_ticks_for(slice_us),
        cycles: 0,
        last_start: 0,
    });
    // Establishes the deadline from the vruntime and slice just set.
    if let Some(thread) = queue.threads[slot].as_mut() {
        thread.charge(0);
    }
    drop(queue);

    // Tell the target CPU, for the same reason `wake` does. Once a CPU can
    // stop its timer, *every* operation that makes a thread runnable on
    // another processor has to say so — otherwise the thread waits for the
    // idle backstop, which is a second. This one was missed at first and
    // presented as three worker threads that never ran.
    //
    // And the same rule, one CPU closer to home: a thread spawned onto the
    // *calling* CPU is also made runnable on a processor that may have
    // stopped its timer — this one, busy but alone, whose last tick decided
    // no slice deadline was needed. The wake path ends in `resched` and never
    // had this hole; spawn did, and it measured as a priority-90 probe
    // waiting 446 ms for its first dispatch behind a spinning fair thread —
    // every wakeup after the first taking 54 µs, because those went through
    // `wake`.
    //
    // **The two branches were not equivalent, and that was the rest of the
    // bug** (2026-08-21). `notify` sends an IPI, and the handler for it
    // re-arms this CPU's timer *before* calling `preempt` — so the tickless
    // hole is closed whether or not the preemption then happens. `resched` is
    // `preempt` alone, and `preempt` re-arms only along the path where it
    // actually switches. Its two silent declines — the holds veto, and losing
    // the `try_lock` on this CPU's own queue to something another processor
    // was doing in it — therefore left a runnable thread in the queue and the
    // timer still armed for whatever it was armed for before. On a CPU
    // running one spinning thread that is the one-second idle backstop, so
    // the spawnee waited a *uniform draw over a second* for its first
    // dispatch.
    //
    // That is the shape of the intermittent this closes: the gate allows
    // 50 ms, and the failures came in at 28 ms (passing, and unexplained at
    // the time) and 493,942 µs. Both are draws from the same second.
    // Confirmed rather than inferred by deleting the call below and booting:
    // **495,688 µs**, first try, where the fix measures in the low thousands.
    //
    // So the decline is no longer dropped. `preempt_reporting` distinguishes
    // "did not look" from "looked and stayed", and only the first falls back
    // to the IPI this CPU would have been sent had the spawn come from any
    // other processor. The fast path is unchanged: a switch that happens
    // directly costs no interrupt.
    if cpu != percpu::cpu_id() {
        notify(cpu);
    } else if preempt_reporting() {
        SPAWN_RESCHED_DECLINED.fetch_add(1, Ordering::Relaxed);
        notify(cpu);
    }

    Ok(id)
}

/// Creates a thread on whichever CPU is currently least loaded.
///
/// This is placement, not balancing: it is the one chance to get a thread onto
/// a quiet CPU without paying to move it later, and it is much cheaper than
/// the stealing that would otherwise have to correct it. `docs/scheduler.md`
/// §5 wants this to prefer a cache-warm CPU over a merely idle one; there is
/// no topology information yet, so every CPU looks equally distant.
///
/// # Errors
///
/// As [`spawn_on`].
pub fn spawn(
    name: &'static str,
    entry: extern "C" fn(u64) -> !,
    argument: u64,
    hhdm_base: u64,
) -> Result<u32, SpawnError> {
    let online = percpu::online_count() as usize;
    let mut best = 0;
    let mut best_load = usize::MAX;

    for (cpu, queue) in QUEUES.iter().enumerate().take(online) {
        // `try_lock`: a queue that is busy right now is not one we want to
        // pick anyway, so treating contention as "skip" costs nothing.
        if let Some(queue) = queue.try_lock() {
            let load = queue.runnable();
            if load < best_load {
                best_load = load;
                best = cpu;
            }
        }
    }

    spawn_on(best as u32, name, entry, argument, hhdm_base)
}

/// Puts a message in `thread`'s mailbox, from `from`.
///
/// Returns whether the thread exists and its mailbox was empty. A full mailbox
/// is refused rather than overwritten: the protocol permits one outstanding
/// message per thread, so a second arriving means something has gone wrong,
/// and silently replacing the first would lose a reply somebody is blocked
/// waiting for.
///
/// Written before the thread is woken, and that ordering is an *optimisation*
/// rather than a requirement — a distinction worth stating, because the
/// opposite claim is the intuitive one.
///
/// Waking first would let the receiver run and find an empty mailbox. It would
/// then recheck, find nothing, and block again, because every waiter here
/// loops rather than trusting a wake — the rule M4-09 arrived at. So the wrong
/// order costs a wasted switch and loses nothing. Reversing it deliberately
/// does not fail the IPC gate, and the comment says so instead of implying a
/// safety property the code does not depend on.
pub fn deliver(thread: u32, message: crate::ipc::Message, from: u32) -> bool {
    for queue in QUEUES.iter().take(percpu::online_count() as usize) {
        let mut queue = queue.lock();
        if let Some(target) = queue.threads.iter_mut().flatten().find(|t| t.id == thread) {
            if target.mailbox.is_some() {
                return false;
            }
            target.mailbox = Some((message, from));
            return true;
        }
    }
    false
}

/// A thread's `FXSAVE` area: 512 bytes, 16-byte aligned as the instruction
/// requires.
#[derive(Clone, Copy)]
#[repr(align(16))]
pub struct FxArea([u8; 512]);

impl FxArea {
    /// An area holding a valid initial state image, **built from constants
    /// rather than taken from the machine**.
    ///
    /// The first version executed `FXSAVE` here, on the reasoning that a
    /// real image beats an invented one. It was wrong twice over. Threads
    /// are constructed before SSE is enabled on the CPU that will run them
    /// — on the native-loader path an application processor builds its idle
    /// thread on the way up — so the instruction faulted and that processor
    /// simply never arrived, reported by the lane as "the cpus line is
    /// missing or short of 4 online of 4". And copying the *running* state
    /// would hand a new thread whatever the last one left in `xmm0`, which
    /// is a leak between threads however tidy it looks.
    ///
    /// So the image is written: `FCW` = `0x037f` (the x87 control word after
    /// `FNINIT`) and `MXCSR` = `0x1f80` (all SSE exceptions masked, round to
    /// nearest), everything else zero. That is what a process starts with on
    /// any system, and it depends on no instruction having been enabled yet.
    #[must_use]
    pub const fn initial() -> Self {
        let mut area = [0u8; 512];
        // `FCW` at 0, `MXCSR` at 24 — the layout `FXSAVE` writes and
        // `FXRSTOR` reads.
        area[0] = 0x7f;
        area[1] = 0x03;
        area[24] = 0x80;
        area[25] = 0x1f;
        Self(area)
    }
}

/// What each CPU's `IA32_FS_BASE` actually holds.
///
/// **The register, not a thread's record of it.** The switch path used to skip
/// its MSR write when the arriving thread's base matched *the departing
/// thread's `fs_base` field* — a fair proxy for the hardware only while nothing
/// else could write the register behind it. Something could: [`set_fs_base`]
/// wrote it from whichever CPU happened to be executing, so a cross-CPU set
/// left one CPU's record and its register disagreeing, and the next switch
/// there could skip a write it needed.
///
/// Tracking the register itself makes the comparison true by construction.
static FS_BASE_LOADED: [core::sync::atomic::AtomicU64; MAX_CPUS] =
    [const { core::sync::atomic::AtomicU64::new(0) }; MAX_CPUS];

/// Puts `base` in this CPU's `IA32_FS_BASE` and records that it is there.
///
/// # Safety
///
/// `IA32_FS_BASE` is a segment base for *user* accesses: every access through
/// it is a user-mode access under the caller's own page table, so a wrong value
/// faults the caller and reaches nothing of the kernel's.
unsafe fn load_fs_base(base: u64) {
    // SAFETY: the caller's obligation, restated above.
    unsafe { bhaskix_arch::msr::write(bhaskix_arch::msr::IA32_FS_BASE, base) };
    if let Some(slot) = FS_BASE_LOADED.get(percpu::cpu_id() as usize) {
        slot.store(base, core::sync::atomic::Ordering::Relaxed);
    }
}

/// What this CPU's `IA32_FS_BASE` holds, as last loaded.
fn fs_base_loaded() -> u64 {
    FS_BASE_LOADED
        .get(percpu::cpu_id() as usize)
        .map_or(0, |slot| slot.load(core::sync::atomic::Ordering::Relaxed))
}

/// Where a thread's newly-set `FS` base actually reaches the hardware.
///
/// **Pure, and on the host, for the reason `waited` is.** `set_fs_base` reads
/// the global run queues and a per-CPU identifier, so the live function cannot
/// run in a unit test -- and the distinction that matters is not the scan but
/// this three-way choice, which was previously observable only by booting a
/// machine and reading a counter. That is how the *first* version of it stayed
/// wrong: it wrote whichever CPU happened to be executing the call.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum BaseReach {
    /// The thread is running here, so the register can be written now.
    LoadedHere,
    /// The thread is running on another CPU, whose register this code must not
    /// write. The base follows at that CPU's next switch, and until then the
    /// thread runs in user mode with its old one -- the window counted by
    /// [`FS_BASE_SET_ELSEWHERE`].
    FollowsAtNextSwitch,
    /// The thread is not the current thread of any queue, so it cannot be in
    /// user mode, and its next switch-in loads the base before it runs.
    NotRunning,
}

/// The choice above, given what the scan found.
pub(crate) fn base_reach(
    running: Option<u32>,
    thread: u32,
    queue_cpu: usize,
    this_cpu: usize,
) -> BaseReach {
    if running != Some(thread) {
        return BaseReach::NotRunning;
    }
    if queue_cpu == this_cpu {
        BaseReach::LoadedHere
    } else {
        BaseReach::FollowsAtNextSwitch
    }
}

/// How often a thread's `FS` base was set while it ran on **another** CPU.
///
/// See the branch that increments it: the register cannot be written from here,
/// so the base does not reach the thread until that CPU's next switch, and the
/// thread runs in user mode with its old base until then.
pub static FS_BASE_SET_ELSEWHERE: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

/// Records a thread's `FS` base and loads it now, so the call that asked
/// for it sees it on return.
pub fn set_fs_base(thread: u32, base: u64) -> bool {
    for (index, queue) in QUEUES
        .iter()
        .take(percpu::online_count() as usize)
        .enumerate()
    {
        let mut queue = queue.lock();
        let running = queue.threads[queue.current].as_ref().map(|t| t.id);
        if let Some(target) = queue.threads.iter_mut().flatten().find(|t| t.id == thread) {
            target.fs_base = base;
            // **Loaded only when the thread is running on *this* CPU**, and
            // the emphasis is the fix.
            //
            // The register is one per CPU. The old test asked whether the
            // target was the *current* thread of the queue being scanned —
            // which is another CPU's queue as often as not — and then wrote the
            // register of whichever CPU was executing this call. So a
            // supervisor setting a hosted thread's TLS from its own CPU put the
            // value in **its** register and left the target's untouched: the
            // hosted thread returned to user mode and read `%fs:0x0` through a
            // base that was still zero.
            //
            // That is the fault localised on 2026-08-28 from a soak specimen —
            // a ring-3 null dereference at `rip 0x500000a6`, which
            // disassembles to `mov %fs:0x0,%rax` four instructions after
            // `arch_prctl(ARCH_SET_FS, …)`. It survived because the thread
            // usually *is* switched before it runs again, and the switch path
            // loads the base properly; twice in three hundred boots it was not.
            //
            // Every other thread still gets it at its next switch, which is
            // where the base travels.
            match base_reach(running, thread, index, percpu::cpu_id() as usize) {
                BaseReach::LoadedHere => {
                    // SAFETY: as `load_fs_base`.
                    unsafe { load_fs_base(base) };
                }
                BaseReach::FollowsAtNextSwitch => {
                    // **The case the fix above does not cover, counted rather than
                    // assumed away.** The target is running *right now*, on another
                    // CPU, whose `IA32_FS_BASE` this code must not write. Its
                    // record is updated, and the base reaches the register at that
                    // CPU's next switch -- so between here and there the thread
                    // runs in user mode with the old base, which for a thread that
                    // never had one is zero.
                    //
                    // That is the shape of the fault still open at `rip
                    // 0x500000a6`: `mov %fs:0x0,%rax` four instructions after
                    // `arch_prctl(ARCH_SET_FS, ...)`, once or twice in three
                    // hundred boots. The comment above already says it survived
                    // because the thread "usually *is* switched before it runs
                    // again" -- this counter is what turns that sentence into a
                    // number. Zero across a soak refutes the mechanism; non-zero
                    // makes it the first suspect and says how often the window
                    // opens.
                    //
                    // ~~Counting, not fixing~~ — **fixed by RFC 0062, with the IPI
                    // this sentence named.** `notify` already exists to make a
                    // CPU look at its queue; here it makes that CPU load the
                    // base its current thread has just been given, in the
                    // handler, *before* it schedules. The counter stays and
                    // changes meaning: it now says how often the IPI was
                    // needed, not how often the window was left open.
                    //
                    // The receiving half is the one that matters and is in
                    // `trap.rs`: `preempt` loads a base only when it actually
                    // switches, and a thread that is simply re-selected would
                    // return to user mode with the stale base and leave this
                    // exactly as broken as before.
                    FS_BASE_SET_ELSEWHERE.fetch_add(1, Ordering::Relaxed);
                    notify(index as u32);
                }
                BaseReach::NotRunning => {}
            }
            return true;
        }
    }
    false
}

/// Loads this CPU's current thread's recorded FS base into the register.
///
/// **The receiving half of RFC 0062.** `set_fs_base` cannot write another CPU's
/// `IA32_FS_BASE`, so it records the value and sends `RESCHEDULE_VECTOR`; this
/// runs there. It is not enough to let `preempt` do it: `preempt` loads a base
/// only when it *switches*, and the thread whose base was just set is usually
/// the one that gets re-selected — it would return to user mode with the stale
/// base and the window would be exactly as open as before.
///
/// `try_lock`, because this is reachable from an interrupt on a CPU that may
/// have been interrupted holding this very lock. A miss is not a failure: the
/// base still arrives at the next switch, which is what happened before this
/// existed.
pub(crate) fn refresh_fs_base_here() {
    let cpu = percpu::cpu_id() as usize;
    if cpu >= MAX_CPUS {
        return;
    }
    let Some(queue) = QUEUES[cpu].try_lock() else {
        // **Counted, because RFC 0062 named this as one of two readings and
        // could not tell them apart.** That RFC says a boot with `elsewhere`
        // above zero and `by_ipi` at zero "would mean the IPI is not arriving
        // or the handler is losing the race for the queue lock", and calls
        // either "a bug in this RFC rather than a mystery" -- but nothing
        // distinguished them, so the sentence could not be acted on. A miss
        // here is the second reading, and only this counter shows it.
        FS_BASE_IPI_CONTENDED.fetch_add(1, Ordering::Relaxed);
        return;
    };
    let current = queue.current;
    let Some(thread) = queue.threads[current].as_ref() else {
        return;
    };
    let base = thread.fs_base;
    drop(queue);
    if base != 0 && base != fs_base_loaded() {
        FS_BASES_LOADED_BY_IPI.fetch_add(1, Ordering::Relaxed);
        // SAFETY: as `load_fs_base` — a user-mode segment base for the thread
        // this CPU is about to return to.
        unsafe { load_fs_base(base) };
    } else {
        // **The handler ran and had nothing to do**, which is the *expected*
        // outcome most of the time and is not a failure: `RESCHEDULE_VECTOR`
        // is shared, so this runs for every reschedule IPI and not only for a
        // base. Counted so that `by_ipi == 0` can be read: with this above
        // zero the handler is arriving and finding another thread current, and
        // with both this and the contended count at zero the IPI itself never
        // reached the CPU -- which is the first reading RFC 0062 named.
        FS_BASE_IPI_NO_CHANGE.fetch_add(1, Ordering::Relaxed);
    }
}

/// Bases put in the register by RFC 0062's IPI rather than by a switch.
static FS_BASES_LOADED_BY_IPI: AtomicU64 = AtomicU64::new(0);

/// Times the IPI handler could not take this CPU's runqueue lock.
static FS_BASE_IPI_CONTENDED: AtomicU64 = AtomicU64::new(0);

/// Times the IPI handler ran with no base to load.
static FS_BASE_IPI_NO_CHANGE: AtomicU64 = AtomicU64::new(0);

/// What the IPI handler did when it did not load a base — RFC 0062 step 4.
///
/// `(contended, no_change)`. Together with [`fs_bases_loaded_by_ipi`] these
/// separate the two readings that RFC 0062 could only name: the handler losing
/// the queue lock, and the IPI never arriving at all.
#[must_use]
pub fn fs_base_ipi_misses() -> (u64, u64) {
    (
        FS_BASE_IPI_CONTENDED.load(Ordering::Relaxed),
        FS_BASE_IPI_NO_CHANGE.load(Ordering::Relaxed),
    )
}

/// How many bases the IPI loaded — RFC 0062.
#[must_use]
pub fn fs_bases_loaded_by_ipi() -> u64 {
    FS_BASES_LOADED_BY_IPI.load(Ordering::Relaxed)
}

/// Records the page table `thread` runs in.
///
/// Called by `vm::install`, which is the only thing that gives a thread one.
pub fn set_space_root(thread: u32, root: u64) {
    for queue in QUEUES.iter().take(percpu::online_count() as usize) {
        let mut queue = queue.lock();
        if let Some(target) = queue.threads.iter_mut().flatten().find(|t| t.id == thread) {
            target.space_root = root;
            return;
        }
    }
}

/// Loads `thread`'s page table if it has one and it is not already loaded.
///
/// Called on the way into a thread, with the runqueue lock released. Skipped
/// for kernel threads, which every address space maps identically.
fn enter_space(root: u64) {
    if root == 0 {
        return;
    }
    // SAFETY: reading CR3 has no side effects.
    let current = unsafe { bhaskix_arch::paging::active_page_table() };
    if current == root {
        return;
    }
    // SAFETY: `root` was recorded by `vm::install` for a space it built, and
    // every such space copies the kernel's higher half -- so the code running
    // here, its stack and the descriptor tables stay mapped across the load.
    unsafe {
        bhaskix_arch::paging::switch_address_space(root);
    }
}

/// Whether `cpu`'s runqueue lock can be taken right now.
///
/// For the bring-up watchdog, and it exists because [`for_each`] cannot answer
/// it. That walk uses `try_lock` and *skips* a CPU it cannot read -- correctly,
/// since it runs from a watchdog that must not block -- but the skip is silent,
/// so a CPU whose runqueue is held and a CPU that was merely busy for a
/// microsecond produce the same output: no lines. The first dump this mattered
/// on had no `cpu 0` rows at all, and the most important fact in it had to be
/// inferred from an absence.
///
/// Sampled repeatedly by the caller, so "held every time over two seconds" can
/// be told from "held once".
///
/// **This says the runqueue is unreadable, not which CPU wedged.** The holder
/// need not be `cpu` itself: [`spawn_on`] and the wake paths take a *remote*
/// runqueue lock and block on it, so a CPU stuck in either strands the queue it
/// reached for rather than its own. Reporting "cpu N is wedged" from a false
/// return would name the victim and let the culprit go unmentioned.
#[must_use]
pub fn runqueue_readable(cpu: usize) -> bool {
    if cpu >= MAX_CPUS {
        return false;
    }
    QUEUES[cpu].try_lock().is_some()
}

/// Online CPUs, clamped so it can index [`QUEUES`].
fn online_cpus() -> usize {
    (percpu::online_count() as usize).min(MAX_CPUS)
}

/// Times a thread was switched out carrying a non-empty rank mask.
///
/// The question both earlier instruments left open. A thread arrives at
/// `finish_switch` with `SchedRunqueue` already in its mask, and neither
/// blocking-while-holding nor preemption-while-holding-a-remote-queue accounts
/// for it. This catches the moment the bit is *written* to a thread, whatever
/// path produced it — and distinguishes a genuine hold from a mask that is
/// simply wrong, which the other two cannot.
static SAVED_HOLDING: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// The mask most recently saved into a switched-out thread, and who it was.
static LAST_SAVED_MASK: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static LAST_SAVED_THREAD: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(u32::MAX);

/// Records a thread being switched out holding ranks, and reports the first.
fn note_saved_holding(id: u32, name: &'static str, mask: u64, where_: &'static str) {
    let first = SAVED_HOLDING.fetch_add(1, Ordering::Relaxed) == 0;
    LAST_SAVED_MASK.store(mask, Ordering::Relaxed);
    LAST_SAVED_THREAD.store(id, Ordering::Relaxed);
    // Only the first, because this runs under the runqueue lock on the switch
    // path: a boot that did it often would spend bring-up printing.
    if first {
        crate::println!(
            "    SAVED HOLDING  thread {id} ({name}) switched out via {where_} holding mask {mask:#08b}"
        );
    }
}

/// Records a thread being switched out with a **counted hold and no rank**
/// — the poison signature the 2026-08-18 specimen implied but could not
/// show: a nonzero count saved into a thread whose mask is clean rides
/// with that thread and flags every later block it makes. Reported on
/// first occurrence with the open guards attached, counted always.
fn note_saved_count(id: u32, name: &'static str, count: u32, where_: &'static str) {
    let first = SAVED_COUNT_ONLY.fetch_add(1, Ordering::Relaxed) == 0;
    if first {
        crate::println!(
            "    SAVED COUNT    thread {id} ({name}) switched out via {where_} with {count} \
             counted holds and an empty mask -- the count-side tear, mid-poison"
        );
        crate::sync::dump_open_guards(bhaskix_arch::percpu::cpu_id() as usize);
    }
}

/// Switches that saved a nonzero count beside an empty mask.
static SAVED_COUNT_ONLY: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// How many switches saved a counted hold with no rank.
#[must_use]
pub fn saved_count_only() -> u64 {
    SAVED_COUNT_ONLY.load(Ordering::Relaxed)
}

/// `(count, last mask, last thread)` for switches made carrying held ranks.
#[must_use]
pub fn saved_holding() -> (u64, u64, Option<u32>) {
    let id = LAST_SAVED_THREAD.load(Ordering::Relaxed);
    (
        SAVED_HOLDING.load(Ordering::Relaxed),
        LAST_SAVED_MASK.load(Ordering::Relaxed),
        (id != u32::MAX).then_some(id),
    )
}

/// Times a thread blocked voluntarily while holding a lock.
///
/// **Any non-zero value is a defect**: the thread is switched out still
/// holding it, and if it is never chosen again nothing ever releases it.
static BLOCKED_HOLDING: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// How many threads blocked while holding a lock. Zero on a healthy boot.
#[must_use]
pub fn blocked_holding() -> u64 {
    BLOCKED_HOLDING.load(Ordering::Relaxed)
}

/// Times a thread was descheduled while holding another CPU's runqueue lock.
///
/// Instrumentation for the bring-up stall. **Any non-zero value is a defect**:
/// the CPU whose lock it was cannot schedule anything until the descheduled
/// thread runs again and releases it, and a thread part-way through `exit` may
/// never be chosen again at all.
static PREEMPTED_HOLDING_REMOTE: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);
/// The runqueue stranded by the most recent such switch.
static LAST_REMOTE_HELD: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(u32::MAX);
/// The CPU that was holding it.
static LAST_REMOTE_HOLDER: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(u32::MAX);

/// `(count, stranded runqueue, holder)` for switches made while holding a
/// remote runqueue lock. The last two are `None` until the first one happens.
#[must_use]
pub fn remote_hold_preemptions() -> (u64, Option<u32>, Option<u32>) {
    let none = |v: u32| (v != u32::MAX).then_some(v);
    (
        PREEMPTED_HOLDING_REMOTE.load(Ordering::Relaxed),
        none(LAST_REMOTE_HELD.load(Ordering::Relaxed)),
        none(LAST_REMOTE_HOLDER.load(Ordering::Relaxed)),
    )
}

/// The CPU holding `cpu`'s runqueue lock, or `None` if it is free.
///
/// The question [`runqueue_readable`] could not answer. That one reports a
/// runqueue held and says in the same breath that the CPU it names is where
/// the lock is rather than who took it — true, and unsatisfying, because
/// `spawn_on` and the wake paths block on a *remote* runqueue, so a CPU stuck
/// in either strands the queue it reached for and not its own.
///
/// Only worth reading once a lock has been seen stuck. On a live one the
/// holder may release before the answer arrives.
#[must_use]
pub fn runqueue_owner(cpu: usize) -> Option<u32> {
    if cpu >= MAX_CPUS {
        return None;
    }
    QUEUES[cpu].owner()
}

/// Whether `thread` still exists and could still be handed a message.
///
/// `Finished` counts as gone. A thread that has exited is still in its queue
/// slot until it is reaped, and an endpoint entry naming it is exactly as
/// stranded as one naming a thread that was never there.
#[must_use]
pub fn thread_is_live(thread: u32) -> bool {
    for queue in QUEUES.iter().take(percpu::online_count() as usize) {
        let queue = queue.lock();
        if let Some(found) = queue.threads.iter().flatten().find(|t| t.id == thread) {
            return found.state != State::Finished;
        }
    }
    false
}

/// What `thread` is called and which address space it should be running in.
///
/// For the fault report. A user-mode fault happens in ring 3, so the faulting
/// thread holds no kernel lock and taking the runqueue lock here cannot
/// deadlock — which is why this is only ever asked about a fault from user
/// mode.
#[must_use]
pub fn describe(thread: u32) -> Option<(&'static str, u64)> {
    for queue in QUEUES.iter().take(percpu::online_count() as usize) {
        let queue = queue.lock();
        if let Some(found) = queue.threads.iter().flatten().find(|t| t.id == thread) {
            return Some((found.name, found.space_root));
        }
    }
    None
}

/// Whether `thread` is parked rather than runnable.
///
/// `None` if there is no such thread.
///
/// **Written for the clone probe's gate, and the distinction it draws is the
/// whole reason it exists.** `syscall::BLOCKED` counts threads the adapter told
/// the kernel to park, and it is incremented *before* `notify::wait` actually
/// parks one — so a watcher waiting on that counter alone can act in the window
/// where the thread has been counted and is still running. This answers the
/// question the counter cannot: has the park landed?
#[must_use]
pub fn is_blocked(thread: u32) -> Option<bool> {
    for queue in QUEUES.iter().take(percpu::online_count() as usize) {
        let queue = queue.lock();
        if let Some(found) = queue.threads.iter().flatten().find(|t| t.id == thread) {
            return Some(found.state == State::Blocked);
        }
    }
    None
}

/// Whether `thread` may never be moved to another CPU.
///
/// `None` if there is no such thread.
#[must_use]
pub fn is_pinned(thread: u32) -> Option<bool> {
    for queue in QUEUES.iter().take(percpu::online_count() as usize) {
        let queue = queue.lock();
        if let Some(found) = queue.threads.iter().flatten().find(|t| t.id == thread) {
            return Some(found.pinned);
        }
    }
    None
}

/// A lock-free trail of every change to a reply obligation.
///
/// # Why a ring and not a `println!`
///
/// The teardown race of 2026-08-21 loses a reply obligation between a server
/// taking a call and exiting, and it is narrow: a **single** `crate::println!`
/// added inside `exit` made the failing arm pass eighteen times in a row where
/// it had been failing twice in ten. Serial output is thousands of cycles and a
/// lock; putting it inside the window closes the window. **Any instrument that
/// prints where the bug lives will report that there is no bug.**
///
/// So this records and says nothing. One relaxed store per event, into a fixed
/// array, read out only by the failure path long afterwards.
///
/// Packed per entry, most significant first:
///
/// ```text
///   8 bits  what happened -- 1 set, 2 taken by reply, 3 taken by exit, 4 exit found none
///   8 bits  the cpu it happened on
///  16 bits  the thread whose obligation it is
///  32 bits  the caller owed, or u32::MAX for none
/// ```
///
/// Zero is "nothing was recorded here", which no real entry can be: every kind
/// is non-zero.
static REPLY_TRAIL: [core::sync::atomic::AtomicU64; REPLY_TRAIL_LEN] =
    [const { core::sync::atomic::AtomicU64::new(0) }; REPLY_TRAIL_LEN];
static REPLY_TRAIL_AT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// How many transitions are kept.
///
/// Thirty-two: the arm under investigation produces a handful, and a ring that
/// wrapped during the window would lose the beginning of the story, which is
/// the half that says whether the obligation was ever set.
pub const REPLY_TRAIL_LEN: usize = 32;

/// What a trail entry records.
pub mod reply_trail {
    /// An obligation was recorded against a thread.
    pub const SET: u64 = 1;
    /// A reply took it.
    pub const TAKEN_BY_REPLY: u64 = 2;
    /// An exiting thread took it, and will abandon the caller.
    pub const TAKEN_BY_EXIT: u64 = 3;
    /// An exiting thread looked and found none.
    pub const EXIT_FOUND_NONE: u64 = 4;
}

/// Records one transition. Never prints, never locks, never allocates.
fn note_reply_trail(kind: u64, thread: u32, caller: Option<u32>) {
    use core::sync::atomic::Ordering;
    let cpu = percpu::cpu_id() as u64 & 0xff;
    let packed = (kind & 0xff) << 56
        | cpu << 48
        | (u64::from(thread) & 0xffff) << 32
        | u64::from(caller.unwrap_or(u32::MAX));
    let at = REPLY_TRAIL_AT.fetch_add(1, Ordering::Relaxed) as usize % REPLY_TRAIL_LEN;
    REPLY_TRAIL[at].store(packed, Ordering::Relaxed);
}

/// The trail, oldest first, as `(kind, cpu, thread, caller)` with `None` for a
/// caller of `u32::MAX`. Empty entries are skipped.
///
/// Read by the failure path only. Racy by construction — a torn read of a ring
/// being written is still worth more than nothing, and the alternative is a
/// lock in the window this exists to observe.
#[must_use]
pub fn reply_trail() -> [(u64, u64, u32, Option<u32>); REPLY_TRAIL_LEN] {
    use core::sync::atomic::Ordering;
    let mut out = [(0u64, 0u64, 0u32, None); REPLY_TRAIL_LEN];
    let next = REPLY_TRAIL_AT.load(Ordering::Relaxed) as usize;
    for (index, slot) in out.iter_mut().enumerate() {
        let at = (next + index) % REPLY_TRAIL_LEN;
        let packed = REPLY_TRAIL[at].load(Ordering::Relaxed);
        if packed == 0 {
            continue;
        }
        let caller = (packed & 0xffff_ffff) as u32;
        *slot = (
            packed >> 56,
            (packed >> 48) & 0xff,
            ((packed >> 32) & 0xffff) as u32,
            if caller == u32::MAX {
                None
            } else {
                Some(caller)
            },
        );
    }
    out
}

/// Records that `thread` owes `caller` an answer.
///
/// Called when a message is taken, so that [`take_reply_target`] can say who a
/// reply may go to without the replying thread being asked.
pub fn set_reply_target(thread: u32, caller: u32) {
    for queue in QUEUES.iter().take(percpu::online_count() as usize) {
        let mut queue = queue.lock();
        if let Some(target) = queue.threads.iter_mut().flatten().find(|t| t.id == thread) {
            target.reply_to = Some(caller);
            note_reply_trail(reply_trail::SET, thread, Some(caller));
            return;
        }
    }
}

/// Who `thread` owes an answer to, without taking the obligation.
///
/// For the work a service does *while* answering -- the filesystem writing a
/// file's bytes into the memory its caller named. The obligation is still
/// owed, so this reads rather than takes.
#[must_use]
pub fn reply_target(thread: u32) -> Option<u32> {
    for queue in QUEUES.iter().take(percpu::online_count() as usize) {
        let queue = queue.lock();
        if let Some(target) = queue.threads.iter().flatten().find(|t| t.id == thread) {
            return target.reply_to;
        }
    }
    None
}

/// Takes the caller `thread` owes an answer to, if it owes one.
///
/// Taking rather than reading: an answer is owed once. A server that replied
/// twice would otherwise be able to deliver a second message into a thread
/// that had moved on to asking something else, and the second answer would
/// look exactly like the first one's.
#[must_use]
pub fn take_reply_target(thread: u32) -> Option<u32> {
    for queue in QUEUES.iter().take(percpu::online_count() as usize) {
        let mut queue = queue.lock();
        if let Some(target) = queue.threads.iter_mut().flatten().find(|t| t.id == thread) {
            let taken = target.reply_to.take();
            note_reply_trail(reply_trail::TAKEN_BY_REPLY, thread, taken);
            return taken;
        }
    }
    None
}

/// Says where `thread` will accept a capability handed back to it.
///
/// Returns whether the thread was found.
pub fn set_receive_slot(thread: u32, slot: Option<(u32, u32)>) -> bool {
    for queue in QUEUES.iter().take(percpu::online_count() as usize) {
        let mut queue = queue.lock();
        if let Some(target) = queue.threads.iter_mut().flatten().find(|t| t.id == thread) {
            target.receive_slot = slot;
            return true;
        }
    }
    false
}

/// Takes where `thread` will accept a capability, if it said so for `endpoint`.
///
/// Taking, not reading: a declaration admits one capability. A server that
/// could hand two would be handing the second into a slot the caller no longer
/// expected to be free.
///
/// The endpoint must match. A declaration is an invitation to one service, and
/// a different one answering a different call must not be able to accept it.
pub fn take_receive_slot(thread: u32, endpoint: u32) -> Option<u32> {
    for queue in QUEUES.iter().take(percpu::online_count() as usize) {
        let mut queue = queue.lock();
        if let Some(target) = queue.threads.iter_mut().flatten().find(|t| t.id == thread) {
            return match target.receive_slot {
                Some((slot, invited)) if invited == endpoint => {
                    target.receive_slot = None;
                    Some(slot)
                }
                _ => None,
            };
        }
    }
    None
}

impl Thread {
    /// Takes this thread's staged gift, if it was staged for `endpoint`.
    ///
    /// The semantics [`take_staged_gift`] promises, kept on the type so a host
    /// test can hold them to it without a runqueue: one-shot — taking clears —
    /// and addressed, so a gift staged for one endpoint does not ride a call
    /// to another and is still there for the call it was meant for.
    pub fn take_gift_for(&mut self, endpoint: u32) -> Option<StagedGift> {
        match self.staged_gift {
            Some(gift) if gift.endpoint == endpoint => {
                self.staged_gift = None;
                Some(gift)
            }
            _ => None,
        }
    }
}

/// Stages a capability for `thread`'s next call, replacing any staged one.
///
/// Returns whether the thread was found. See [`StagedGift`] for the one-shot
/// and replace semantics; this function is deliberately just the storage.
pub fn stage_gift(thread: u32, gift: StagedGift) -> bool {
    for queue in QUEUES.iter().take(percpu::online_count() as usize) {
        let mut queue = queue.lock();
        if let Some(target) = queue.threads.iter_mut().flatten().find(|t| t.id == thread) {
            target.staged_gift = Some(gift);
            return true;
        }
    }
    false
}

/// Takes what `thread` staged, if it staged it for `endpoint`.
///
/// Taking, not reading: a gift rides one call. The endpoint must match — a
/// gift staged for one service must not ride a call to another, and a call
/// elsewhere leaves the gift in place for the call it was meant for.
pub fn take_staged_gift(thread: u32, endpoint: u32) -> Option<StagedGift> {
    for queue in QUEUES.iter().take(percpu::online_count() as usize) {
        let mut queue = queue.lock();
        if let Some(target) = queue.threads.iter_mut().flatten().find(|t| t.id == thread) {
            return target.take_gift_for(endpoint);
        }
    }
    None
}

/// Refuses a call `thread` is blocked in, with `status`, and wakes it.
///
/// RFC 0022 step 2's other half: the server's receive path decides the
/// refusal, and the caller — already blocked awaiting a reply — has to be
/// told. The flag is read under the same runqueue-lock hold that decides
/// whether to keep blocking, so the mark-first discipline covers it: a flag
/// set before the caller's check is found by it, and one set after finds a
/// blocked thread for the wake below.
pub fn refuse_call(thread: u32, status: u32) -> bool {
    let mut found = false;
    for queue in QUEUES.iter().take(percpu::online_count() as usize) {
        let mut queue = queue.lock();
        if let Some(target) = queue.threads.iter_mut().flatten().find(|t| t.id == thread) {
            target.call_refused = Some(status);
            found = true;
            break;
        }
    }
    if found {
        let _ = wake(thread);
    }
    found
}

/// Puts a taken gift back, for a refusal that retains it.
///
/// RFC 0022's draft answer to its open question 3: a refused call leaves the
/// gift staged, so a retry loop stages once. Recorded there as provisional.
pub fn restore_staged_gift(thread: u32, gift: StagedGift) -> bool {
    stage_gift(thread, gift)
}

/// How many threads are holding a message nobody has collected.
///
/// A handover writes the mailbox and then wakes; a woken thread rechecks and
/// takes it. So a mailbox that is still full once everything has stopped means
/// the message arrived and its owner never ran again — which distinguishes a
/// lost message from a lost wakeup, two failures that look identical from the
/// outside.
#[must_use]
pub fn pending_mailboxes() -> u32 {
    let mut pending = 0;
    for queue in QUEUES.iter().take(percpu::online_count() as usize) {
        let queue = queue.lock();
        for thread in queue.threads.iter().flatten() {
            if thread.mailbox.is_some() {
                pending += 1;
            }
        }
    }
    pending
}

/// Whether `thread` is holding a message it has not collected.
#[must_use]
pub fn has_message(thread: u32) -> bool {
    for queue in QUEUES.iter().take(percpu::online_count() as usize) {
        let queue = queue.lock();
        if let Some(target) = queue.threads.iter().flatten().find(|t| t.id == thread) {
            return target.mailbox.is_some();
        }
    }
    false
}

/// Takes the message waiting for `thread` and, if there was one, makes it
/// runnable again — both under one hold of its runqueue lock.
///
/// The two halves must not come apart, and this is why. A waiter marks itself
/// `Blocked` *before* checking its mailbox, so that a wake arriving in the gap
/// is not lost. That leaves a window where the thread is marked blocked and is
/// still running. If it takes the message and is preempted before clearing the
/// mark, it is switched out `Blocked` — and the wake that would have rescued it
/// has already been spent on delivering the message it is now holding. Nothing
/// will ever select it again: [`preempt`] only returns a thread to `Ready` if
/// it was `Running`, and no future sender will wake a receiver it has already
/// matched.
///
/// Holding the lock across both halves closes it, because `preempt` reaches
/// this runqueue with `try_lock` and gives up rather than switching a thread
/// out from under this.
///
/// Measured as an IPC rendezvous that stalled after exactly one delivery, on a
/// host fast enough to land a timer tick in a two-instruction window.
pub fn take_message_or_block(
    thread: u32,
    still_waiting: impl FnOnce() -> bool,
) -> Delivery<(crate::ipc::Message, u32)> {
    for queue in QUEUES.iter().take(percpu::online_count() as usize) {
        let mut queue = queue.lock();
        if let Some(target) = queue.threads.iter_mut().flatten().find(|t| t.id == thread) {
            // All three outcomes decided here, under the one lock. Marking
            // from a separate call would release it in between, and a tick
            // landing there strands a thread whose message had already arrived
            // and whose wake had already been spent finding it awake.
            if let Some(message) = target.mailbox.take() {
                target.state = State::Running;
                return Delivery::Message(message);
            }
            // The answer is not coming, because whoever owed it has gone. Ahead
            // of `still_waiting`, which asks about the *endpoint* and would say
            // yes: the endpoint is fine, and that is exactly why the caller
            // cannot work this out for itself.
            if core::mem::take(&mut target.answer_lost) {
                target.state = State::Running;
                return Delivery::Revoked;
            }
            // A refused call, RFC 0022 step 2: the server's receive path
            // could not complete this thread's staged gift, so the call was
            // never delivered and no reply is coming. Carried with the status
            // the refusal actually had, because "your gift lacked GRANT" and
            // "the service never declared" are different mistakes and only
            // one of them is the caller's.
            if let Some(status) = target.call_refused.take() {
                target.state = State::Running;
                return Delivery::Refused(status);
            }
            // A thread told to stop must not go back to sleep here.
            //
            // This is the third place that decides to block, and it was missed
            // when the other two learned the rule: it writes `State::Blocked`
            // directly rather than going through `mark_blocked`. A dying thread
            // waiting on an endpoint would be woken, find nothing, block again,
            // and never reach a safe point -- so RFC 0017 step 2 stopped every
            // thread except the ones that were asleep in IPC, which is most of
            // the interesting ones.
            //
            // The three-way choice itself lives in [`waited`], which is pure
            // and tested on the host. It used to live here, and the one
            // distinction it draws -- a dying caller against a vanished
            // endpoint -- was only observable by booting a machine and reading
            // a counter, which is how it stayed wrong.
            match waited(target.dying, still_waiting) {
                Waited::Dying => {
                    target.state = State::Running;
                    return Delivery::Dying;
                }
                Waited::Blocked => {
                    target.state = State::Blocked;
                    return Delivery::Blocked;
                }
                Waited::Abandoned => {
                    target.state = State::Running;
                    return Delivery::Abandoned;
                }
            }
        }
    }
    Delivery::Abandoned
}

/// What a waiting thread that found no message should be told.
///
/// Three outcomes, and the first two are the ones that get confused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Waited {
    /// **This thread** is being killed. It must not sleep again, and nothing
    /// has failed: its domain is ending, which is teardown working.
    Dying,
    /// Still waiting, and the thing waited on is still there.
    Blocked,
    /// What was waited on has gone.
    Abandoned,
}

/// The rule [`take_message_or_block`] applies when no message arrived.
///
/// **Pure, and separate, because the distinction it draws was wrong for weeks
/// and nothing on the host could see it.** `Dying` and `Abandoned` were one
/// answer until 2026-08-23. `syscall::ask_adapter_counted` needs them apart --
/// a domain ending under a hosted thread is not a dead adapter -- and with the
/// two collapsed it recovered the difference by asking `sched::should_die`,
/// which takes the runqueue lock again and answers "no" when it loses it. The
/// `native` boot gate failed on the resulting phantom refusal.
///
/// `still_waiting` stays lazy: a dying thread's answer does not depend on it,
/// and the closure is a lookup the caller should not pay for twice.
fn waited(dying: bool, still_waiting: impl FnOnce() -> bool) -> Waited {
    if dying {
        Waited::Dying
    } else if still_waiting() {
        Waited::Blocked
    } else {
        Waited::Abandoned
    }
}

/// What [`take_message_or_block`] concluded.
pub enum Delivery<T> {
    /// A message was waiting. The thread is running.
    Message(T),
    /// Nothing yet, and the thing being waited on is still there. The thread is
    /// marked blocked and should yield.
    Blocked,
    /// What was being waited on has gone. The thread is running and should give
    /// up rather than sleep for something that will never arrive.
    Abandoned,
    /// **This thread** has been told to stop, so it must not sleep again —
    /// which is a different fact from the endpoint having gone, and reaches a
    /// different conclusion. A caller seeing this is watching its own domain
    /// end underneath it: nothing is wrong, and nothing should be counted as a
    /// failure. See the branch that returns it.
    Dying,
    /// The thread that owed this answer has died. The thread is running and
    /// should report that, distinctly: "the endpoint you called does not exist"
    /// and "the program you called has gone" are different facts, and a caller
    /// that retried the first would be right to and the second would not.
    Revoked,
    /// The call was refused at the rendezvous — RFC 0022 step 2, a staged
    /// gift that could not be completed — with the status of the refusal.
    /// The thread is running and its message was never delivered.
    Refused(u32),
}

/// Clears a blocked mark this thread set on itself and then decided against.
///
/// The receive path marks itself blocked *before* checking its bound
/// notification — that order is what makes the check race-free — and when the
/// check finds bits, the thread returns to its caller instead of sleeping. The
/// mark has to be taken back first: a thread that returns still marked
/// `Blocked` keeps executing only until the next reschedule on its CPU, which
/// believes the mark, switches away, and never comes back — the wake that
/// would have corrected it was consumed by the very check that decided to
/// return. Whether it survived was decided by whichever of the wake and the
/// mark landed second, which is a coin toss taken on every notified receive.
///
/// Found as RFC 0020 step 5's one-in-three stall: a TCP service that armed a
/// deadline, was handed its wake, and vanished — and the same hole under
/// `bin/ipd`'s serve loop stranded the DHCP client's first call. Returns
/// whether a mark was actually cleared.
pub fn clear_blocked_mark(thread: u32) -> bool {
    for queue in QUEUES.iter().take(percpu::online_count() as usize) {
        let mut queue = queue.lock();
        if let Some(target) = queue.threads.iter_mut().flatten().find(|t| t.id == thread) {
            if target.state == State::Blocked {
                target.state = State::Running;
                return true;
            }
            return false;
        }
    }
    false
}

/// Takes the message waiting for `thread`, if there is one.
#[must_use]
pub fn take_message(thread: u32) -> Option<(crate::ipc::Message, u32)> {
    for queue in QUEUES.iter().take(percpu::online_count() as usize) {
        let mut queue = queue.lock();
        if let Some(target) = queue.threads.iter_mut().flatten().find(|t| t.id == thread) {
            return target.mailbox.take();
        }
    }
    None
}

/// The domain a given thread belongs to.
///
/// Distinct from [`current_domain`], which answers for the running thread. A
/// service is asked to act on a *caller's* behalf and has only that caller's
/// thread id, so resolving the caller's own capabilities needs this.
#[must_use]
pub fn domain_of(thread: u32) -> Option<crate::domain::DomainId> {
    for queue in QUEUES.iter().take(percpu::online_count() as usize) {
        let queue = queue.lock();
        if let Some(target) = queue.threads.iter().flatten().find(|t| t.id == thread) {
            if target.domain == u32::MAX {
                return None;
            }
            return Some(crate::domain::DomainId::from_u32(target.domain));
        }
    }
    None
}

/// The domain the calling thread belongs to.
///
/// `None` for a thread created before domains existed, which is the correct
/// answer rather than an oversight: such a thread has no CSpace and therefore
/// no authority to name anything.
///
/// # Why this blocks for the lock rather than trying for it
///
/// It used to be `try_lock()?`, and that one character of punctuation was a
/// service-killing bug. `None` here becomes [`Status::NoDomain`] in
/// `resolve_for_ipc`, and a service told its receive was refused **exits** --
/// deliberately, because there is nothing left for it to serve. So a runqueue
/// lock that happened to be held by another CPU for the duration of one
/// `Recv` did not delay that service. It ended it, permanently, along with
/// every caller that would ever queue behind it.
///
/// It presented as the console going silent mid-word, or the filesystem
/// answering ninety-eight requests and then nothing, once in fifteen to thirty
/// runs and more often on a loaded host -- with no fault, no panic, and every
/// self-test in the same boot green.
///
/// This is the conflation `wake_with` is careful about and names in its own
/// documentation: *contended* and *not there* are different answers, and a
/// caller that cannot tell them apart will do the wrong one of retry and give
/// up. `wake_with` learned it for wakes; this did not learn it for authority.
///
/// Blocking is safe, and by the argument already written down elsewhere:
/// `current_thread_id` two hundred lines below takes the same lock the same
/// way and is called beside this one on every path that reaches here, and
/// `trap::end_faulting_domain` sets out why a handler for a *user-mode* fault
/// may take kernel locks at all. This takes that one lock and releases it
/// before any other, so it cannot be the held half of a cycle.
#[must_use]
pub fn current_domain() -> Option<crate::domain::DomainId> {
    let cpu = percpu::cpu_id() as usize;
    if cpu >= MAX_CPUS {
        return None;
    }
    let queue = QUEUES[cpu].lock();
    let current = queue.current;
    let domain = queue.threads[current].as_ref()?.domain;
    if domain == u32::MAX {
        return None;
    }
    Some(crate::domain::DomainId::from_u32(domain))
}

/// The fair-class weight a thread currently carries.
///
/// Lets a test assert the *mechanism* rather than infer it from a CPU-time
/// measurement, which on an emulated, shared machine is a noisy way to learn
/// one number.
#[must_use]
pub fn weight_of(id: u32) -> Option<u32> {
    for queue in QUEUES.iter().take(percpu::online_count() as usize) {
        // Blocking. `try_lock` here reports "no such thread" for a thread that
        // exists on a busy CPU, and the caller cannot tell the two apart — a
        // query that answers `None` for "ask again later" is worse than one
        // that waits. This is the third place the same shortcut has produced
        // an intermittent wrong answer; see also `set_domain_weight` and
        // `start_all`.
        let queue = queue.lock();
        if let Some(thread) = queue.threads.iter().flatten().find(|t| t.id == id) {
            return match thread.policy {
                Policy::Fair { weight } => Some(weight),
                _ => None,
            };
        }
    }
    None
}

/// Real CPU ticks a thread has consumed, if it still exists.
///
/// Real, not virtual: proportional-share testing needs the time actually
/// spent, and `vruntime` is that number already divided by the weight the test
/// is trying to verify.
#[must_use]
pub fn cycles_of(id: u32) -> Option<u64> {
    for queue in QUEUES.iter().take(percpu::online_count() as usize) {
        // Blocking, for the reason in `weight_of`.
        let queue = queue.lock();
        if let Some(thread) = queue.threads.iter().flatten().find(|t| t.id == id) {
            return Some(thread.cycles);
        }
    }
    None
}

/// Moves one thread from a busier CPU's queue into `mine`, if that is worth
/// doing. Returns the slot it landed in.
///
/// The caller holds `mine`'s lock and no other. Victims are probed with
/// `try_lock`, so two CPUs that pick each other both fail rather than
/// deadlock; the cost of losing that race is one skipped steal.
fn try_steal(cpu: usize, mine: &mut RunQueue) -> Option<usize> {
    let online = percpu::online_count() as usize;
    if online < 2 {
        return None;
    }

    let my_load = mine.runnable();
    let free = mine.free_slot()?;

    // Start at the next CPU rather than at zero, so that CPUs going idle
    // together do not all descend on the same victim.
    for offset in 1..online {
        let victim = (cpu + offset) % online;

        let mut theirs = match QUEUES[victim].try_lock() {
            Some(queue) => queue,
            None => continue,
        };

        let Some(slot) = theirs.steal_candidate(my_load) else {
            continue;
        };
        let Some(mut thread) = theirs.threads[slot].take() else {
            continue;
        };
        drop(theirs);

        thread.migrations += 1;
        mine.threads[free] = Some(thread);
        STEALS.fetch_add(1, Ordering::Relaxed);
        return Some(free);
    }

    None
}

/// Records that the switch this CPU began has finished.
///
/// Called on the way out of every switch: from [`preempt`] for a thread that
/// has run before, and from the trampoline via `bhaskix_thread_entered` for
/// one that has not. Until it runs, no other CPU will steal from here — so
/// missing a path does not corrupt anything, it quietly stops balancing.
/// The last few switches, so the fault path can say what led to one.
///
/// Packed as `thread << 32 | root >> 12`: a thread identifier and the frame
/// number of the address space it resumed into. `u64::MAX` is "nothing yet".
static SWITCH_TRACE: [core::sync::atomic::AtomicU64; SWITCH_TRACE_LEN] =
    [const { core::sync::atomic::AtomicU64::new(u64::MAX) }; SWITCH_TRACE_LEN];
static SWITCH_AT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
const SWITCH_TRACE_LEN: usize = 16;

/// Switches that resumed a thread with **no address space to load**.
///
/// `enter_space(0)` returns without touching `CR3`, so a switch that computes a
/// root of zero leaves whatever the previous thread had loaded. For a kernel
/// thread that is correct and deliberate. For a user thread it is the fault
/// `trap.rs` prints as "IT IS RUNNING IN SOMEBODY ELSE'S ADDRESS SPACE", and
/// this counts how often the situation arises at all.
static SWITCHES_WITHOUT_SPACE: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

/// Switches where the runqueue had no thread at the index it was about to
/// resume — which is the way a root of zero arises without anybody choosing it.
static SWITCHES_WITHOUT_THREAD: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

/// Wrong address spaces caught on the way back to ring 3, and where.
///
/// Packed `site << 62 | thread << 32 | loaded >> 12`, with site 0 for the
/// system call exit and 1 for the trap exit.
static EXIT_TRACE: [core::sync::atomic::AtomicU64; 8] =
    [const { core::sync::atomic::AtomicU64::new(u64::MAX) }; 8];
static EXIT_AT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// How many exits to ring 3 found the wrong space loaded, and how many were
/// skipped because the runqueue was busy.
static EXIT_WRONG: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static EXIT_UNCHECKED: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Returns to ring 3 by a thread with **no address space recorded**.
///
/// **The blind spot this instrument had for a week, and the exact shape of the
/// fault it was built to hunt.** `check_user_space` compared a thread's
/// recorded root against `CR3` and returned *silently* when the root was zero
/// — so a thread about to run in ring 3 owning no space was the one case the
/// check could not see, while `finish_switch` calling `enter_space(0)` and
/// leaving somebody else's `CR3` loaded is precisely how the fault of
/// 2026-08-13 arrived. Counted since 2026-08-20, when a capture read
/// `wrong space: 0` beside a thread that was demonstrably in the wrong one.
///
/// A ring 3 thread that owns no address space is never correct: it either has
/// one or it has no business in user mode.
static EXIT_ROOTLESS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// The first rootless return, packed `site << 62 | thread`, or `u64::MAX`.
static EXIT_ROOTLESS_FIRST: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(u64::MAX);

/// Checks that the thread about to run in ring 3 owns the loaded address space.
///
/// **The last moment the kernel can tell.** The switch instrumentation showed a
/// thread resumed with a space recorded and a different one loaded, which means
/// some return path does not load it; this is the check that names which.
///
/// `site` says which way back to ring 3: 0 the system call return, 1 the
/// interrupt return, 2 the first entry — which is where every capture of this
/// fault has been, at a program's own entry point rather than inside it — and 3
/// a serviced page fault, where the instruction is retried.
///
/// Four sites, because "the wrong space is loaded" cannot be narrowed by
/// reasoning about which return path is likely; each one either accounts for it
/// or does not.
///
/// Takes the local runqueue with `try_lock` and gives up rather than waiting.
/// This runs on the trap exit, which may have interrupted a thread holding that
/// very lock — waiting there is how M6-04's one-CPU deadlock happened, and the
/// skipped checks are counted rather than hidden.
pub fn check_user_space(site: u64) {
    use core::sync::atomic::Ordering;

    let cpu = percpu::cpu_id() as usize;
    if cpu >= MAX_CPUS {
        return;
    }
    let Some(queue) = QUEUES[cpu].try_lock() else {
        EXIT_UNCHECKED.fetch_add(1, Ordering::Relaxed);
        return;
    };
    let Some((who, root)) = queue
        .threads
        .get(queue.current)
        .and_then(|thread| thread.as_ref())
        .map(|thread| (thread.id, thread.space_root))
    else {
        return;
    };
    drop(queue);

    if root == 0 {
        // **Not silence.** See `EXIT_ROOTLESS`: this is the one case the check
        // could not see, and it is the shape of the fault it exists for.
        EXIT_ROOTLESS.fetch_add(1, Ordering::Relaxed);
        let _ = EXIT_ROOTLESS_FIRST.compare_exchange(
            u64::MAX,
            (site << 62) | u64::from(who),
            Ordering::Relaxed,
            Ordering::Relaxed,
        );
        return;
    }
    // SAFETY: reading CR3 at CPL 0 has no side effects.
    let loaded = unsafe { bhaskix_arch::paging::active_page_table() };
    if loaded == root {
        return;
    }

    EXIT_WRONG.fetch_add(1, Ordering::Relaxed);
    let at = EXIT_AT.fetch_add(1, Ordering::Relaxed) as usize;
    EXIT_TRACE[at % 8].store(
        (site << 62) | (u64::from(who) << 32) | (loaded >> 12),
        Ordering::Relaxed,
    );
}

/// What the exit check found: wrong spaces, and checks skipped for a busy lock.
#[must_use]
pub fn exit_check_counts() -> (u64, u64) {
    use core::sync::atomic::Ordering;
    (
        EXIT_WRONG.load(Ordering::Relaxed),
        EXIT_UNCHECKED.load(Ordering::Relaxed),
    )
}

/// Returns to ring 3 by a thread owning no address space, and the first one:
/// `(count, site, thread)`.
///
/// Zero is the only correct answer. See [`EXIT_ROOTLESS`].
#[must_use]
pub fn rootless_exits() -> (u64, u64, u32) {
    use core::sync::atomic::Ordering;
    let first = EXIT_ROOTLESS_FIRST.load(Ordering::Relaxed);
    let (site, thread) = if first == u64::MAX {
        (0, 0)
    } else {
        (first >> 62, (first & 0xffff_ffff) as u32)
    };
    (EXIT_ROOTLESS.load(Ordering::Relaxed), site, thread)
}

/// Replays the exit ring, oldest first, as `(site, thread, loaded space)`.
pub fn replay_exit_checks(mut visit: impl FnMut(u64, u32, u64)) {
    use core::sync::atomic::Ordering;
    let at = EXIT_AT.load(Ordering::Relaxed) as usize;
    let first = at.saturating_sub(8);
    for index in first..at {
        let packed = EXIT_TRACE[index % 8].load(Ordering::Relaxed);
        if packed != u64::MAX {
            visit(
                packed >> 62,
                ((packed >> 32) & 0x3fff_ffff) as u32,
                (packed & 0xffff_ffff) << 12,
            );
        }
    }
}

/// Replays the switch ring, oldest first, as `(thread, space frame)`.
pub fn replay_switches(mut visit: impl FnMut(u32, u64)) {
    use core::sync::atomic::Ordering;
    let at = SWITCH_AT.load(Ordering::Relaxed) as usize;
    let first = at.saturating_sub(SWITCH_TRACE_LEN);
    for index in first..at {
        let packed = SWITCH_TRACE[index % SWITCH_TRACE_LEN].load(Ordering::Relaxed);
        if packed != u64::MAX {
            visit((packed >> 32) as u32, (packed & 0xffff_ffff) << 12);
        }
    }
}

/// How many switches resumed without a space, and without a thread.
#[must_use]
pub fn switch_gaps() -> (u64, u64) {
    use core::sync::atomic::Ordering;
    (
        SWITCHES_WITHOUT_SPACE.load(Ordering::Relaxed),
        SWITCHES_WITHOUT_THREAD.load(Ordering::Relaxed),
    )
}

fn finish_switch() {
    use core::sync::atomic::Ordering;

    let cpu = percpu::cpu_id() as usize;
    let mut root = 0;
    let mut who = 0;
    let mut found = false;
    if cpu < MAX_CPUS {
        let mut queue = QUEUES[cpu].lock();
        queue.switching = false;
        if let Some(thread) = queue
            .threads
            .get(queue.current)
            .and_then(|thread| thread.as_ref())
        {
            found = true;
            who = thread.id;
            root = thread.space_root;
        }
    }

    // **Recorded before the space is loaded**, so a fault afterwards can say
    // what the switch decided rather than what it should have decided.
    if !found {
        SWITCHES_WITHOUT_THREAD.fetch_add(1, Ordering::Relaxed);
    }
    if root == 0 {
        // Correct for a kernel thread, which has no space of its own. The
        // question this counter exists to answer is whether it ever happens to
        // a thread that *does*.
        SWITCHES_WITHOUT_SPACE.fetch_add(1, Ordering::Relaxed);
    }
    let at = SWITCH_AT.fetch_add(1, Ordering::Relaxed) as usize;
    SWITCH_TRACE[at % SWITCH_TRACE_LEN]
        .store((u64::from(who) << 32) | (root >> 12), Ordering::Relaxed);

    // Each thread loads its own address space as it resumes, rather than
    // something loading it on the way out. That way a thread stolen to another
    // CPU still arrives in its own space, and a CPU that has been running
    // kernel threads need not remember whose space it left loaded. The
    // runqueue lock above has gone out of scope by now: switching `CR3`
    // touches no kernel data, so there is no reason to hold one across it.
    enter_space(root);
}

/// Hook the thread trampoline calls before a brand-new thread starts.
///
/// A new thread never returns into [`bhaskix_context_switch`], so this is the
/// only place its arrival can be observed.
extern "C" fn thread_entered() {
    finish_switch();
}

/// Allows the calling CPU to start preempting.
pub fn start() {
    let cpu = percpu::cpu_id() as usize;
    if cpu < MAX_CPUS {
        QUEUES[cpu].lock().started = true;
    }
}

/// Stops preemption on the calling CPU.
pub fn stop() {
    let cpu = percpu::cpu_id() as usize;
    if cpu < MAX_CPUS {
        QUEUES[cpu].lock().started = false;
    }
}

/// Allows preemption on every online CPU.
///
/// The counterpart to [`stop_all`], for a later test that needs threads to run
/// again after the scheduler self-test froze the world to report on it.
/// Without it a thread spawned afterwards is created, is runnable, and is
/// never chosen — which looks exactly like a thread that failed to start.
pub fn start_all() {
    for queue in QUEUES.iter().take(percpu::online_count() as usize) {
        // Blocking, not `try_lock`. A CPU whose queue is contended is exactly
        // one with threads spinning on it -- in `exit`, or waiting for
        // something to become runnable -- so skipping on contention skips the
        // CPUs most likely to need starting. It measured as an IPC test where
        // no thread ran at all, intermittently, which is the second time this
        // exact shortcut has cost a milestone a day.
        //
        // Safe to block: the caller holds nothing, and every scheduler path
        // reachable from an interrupt uses `try_lock`.
        queue.lock().started = true;
    }
}

/// Stops preemption everywhere, so shutdown reporting is not interleaved.
pub fn stop_all() {
    for queue in &QUEUES {
        if let Some(mut queue) = queue.try_lock() {
            queue.started = false;
        }
    }
}

/// Switches to the next runnable thread on this CPU, if there is one.
///
/// Called from the timer interrupt and from [`yield_now`].
pub fn preempt() {
    let _ = preempt_reporting();
}

/// [`preempt`], answering `true` when it declined **without looking at the
/// queue** — the holds veto or a busy queue lock, and nothing else.
///
/// The distinction is the whole value of the return. "Looked and kept the
/// running thread" is a decision and needs no retry; "did not look" leaves a
/// runnable thread undispatched and a timer armed for whatever it was armed
/// for before, which on a tickless CPU is the one-second backstop. Only the
/// second is reported, so a caller acting on it cannot start an interrupt
/// storm out of threads that were simply not the best choice.
fn preempt_reporting() -> bool {
    let cpu = percpu::cpu_id() as usize;
    if cpu >= MAX_CPUS {
        return true;
    }

    // Never take the CPU away from a thread holding a spinlock.
    //
    // This is not an optimisation, it is what makes spinlocks work at all on
    // one processor. A thread preempted while holding a lock can only release
    // it by running again — and every other thread that wants that lock spins
    // holding no lock of its own, so the scheduler sees nothing wrong and may
    // keep choosing the spinner. On a single CPU that is a deadlock; on many
    // it is a stall until the timing happens to break.
    //
    // `docs/architecture.md` §6 prefers per-CPU data and short critical
    // sections precisely so that this window is small, but small is not zero.
    // The lock ranks added at M4-08 already track what this CPU holds, so the
    // check is a load and a comparison — the bookkeeping was already paid for.
    //
    // Skipping a preemption is harmless: this runs again on the next tick, and
    // critical sections here are bounded and never sleep.
    // **Both sets, and the second one cost a stall to find.** `held_mask`
    // covers blocking acquisitions only: `try_lock` stays out of the ranked set
    // because a non-blocking acquisition can never be an edge in a deadlock
    // cycle. That is sound, and it is about *ordering*. It was also being read
    // here as "holds nothing", which does not follow -- a `try_lock` holder
    // holds the lock, and descheduling one strands every CPU that wants it.
    //
    // `exit` used to reach `domain_of_raw` and `threads_in_domain_except`
    // with interrupts enabled, both `try_lock`ing every runqueue there is —
    // a tick landing in that scan could take the exiting thread off its CPU
    // still holding a *remote* runqueue. Both scans are gone (2026-08-17,
    // replaced by the per-domain thread count), but `ipc::cancel_all` still
    // walks locked tables from `exit`, so the concern stands.
    //
    // **This was expected to end the bring-up stall and did not**: 3 boots in
    // 500 with it against 4 in 500 without, and one of those arrived with the
    // very signature it should have made impossible. Kept because descheduling
    // a lock holder is wrong regardless, and left uncommented-out so nobody
    // rediscovers the unsoundness and assumes it was the fault all along.
    // The state run-409's SAVED HOLDING implies: the rank mask says a lock is
    // held while the count says nothing is — the only state in which this
    // veto waves a genuine holder through to be switched out. It is also the
    // shadow an underflow casts *before* the wedge: the count lost an
    // increment the mask still remembers. Caught here because this is the
    // decision the mismatch corrupts; printed once, because the condition
    // repeats on every tick until the drop that will underflow.
    // Sampled once, as `block_self` above: the mask this message prints must be
    // the mask the condition tested, or the report describes two moments.
    //
    // **Behind a cheap check, because this runs on every tick.** The coherent
    // sample costs a `cli`/`sti` pair when interrupts are on, and the common
    // case is a mask of zero — one relaxed load, exactly what this cost
    // before. The pair is only paid on the boots where there is something to
    // report, which is the whole point of a diagnostic.
    let (mask, held) = if crate::sync::held_mask() == 0 {
        (0, 0)
    } else {
        crate::sync::accounting()
    };
    if mask != 0 && held == 0 && COUNT_MISMATCHES.fetch_add(1, Ordering::Relaxed) == 0 {
        crate::println!(
            "    COUNT MISMATCH  cpu {cpu} rank mask {mask:#b} with a hold count of zero: a \
             counted increment has been lost, and the next release of this guard will \
             underflow"
        );
    }

    if crate::sync::holds_any() {
        // Counted, because a veto that repeats is invisible otherwise: every
        // decline looks identical to "nothing to do" from outside, and the
        // run-123 specimen (2026-08-17) is a CPU that ran nothing it was
        // handed for two seconds while its resched IPIs arrived and, by some
        // path, did nothing. If that path is this veto repeating on a stale
        // hold count, the counter says so; if the counter stays low, this
        // line is exonerated the same way.
        if let Some(count) = PREEMPT_VETO_HOLDS.get(cpu) {
            count.fetch_add(1, Ordering::Relaxed);
        }
        return true;
    }

    // **The counter-check on that veto, and the reason is three specimens.**
    //
    // The veto above asks `holds_any()` and declines to switch out a lock
    // holder. Everything below this line switches -- so if that predicate can
    // read *empty* while a lock is genuinely held, this is the instant the
    // damage is done: a thread holding the wait queue's lock is carried off the
    // CPU and nothing releases it.
    //
    // That is not idle worry. The accounting is already known to disagree with
    // itself in the *other* direction: `run-221` (2026-08-29) had a rank mask
    // remembering a rank with no open guard, and `run-244` had `holds_any()`
    // answering true while the mask and the count both read zero. One fault
    // that made it wrong here would explain `run-106`'s hang -- a waker
    // spinning on a lock whose holder is no longer running -- and the two ring
    // stations whose wake was consumed while they were off-CPU.
    //
    // **The guard ledger is the independent witness**, kept by the guards
    // themselves rather than by the mask and count this is checking. Eight
    // slots, so the scan is eight relaxed loads on a path that already takes a
    // runqueue lock.
    //
    // **Aged, and that is what stops it crying wolf.** `sync`'s own header
    // warns of a two-instruction window where a rank is claimed before the
    // count reflects it; a guard opened microseconds ago may legitimately not
    // be counted yet. A guard open for longer than `GUARD_AGE_SUSPICIOUS`
    // cycles is not that window.
    {
        let now = tsc::read();
        let mut oldest: Option<(&'static core::panic::Location<'static>, u8, u64)> = None;
        crate::sync::for_each_open_guard(cpu, |at, rank, since| {
            let age = now.saturating_sub(since);
            if age < GUARD_AGE_SUSPICIOUS {
                return;
            }
            if oldest.is_none_or(|(_, _, best)| age > best) {
                oldest = Some((at, rank, age));
            }
        });
        // Only the first witness is kept: the first is the one that happened
        // before anything else could have been disturbed by it.
        if let Some((at, rank, age)) = oldest
            && SWITCHED_WITH_OPEN_GUARD.fetch_add(1, Ordering::Relaxed) == 0
        {
            GUARD_WITNESS_SITE.store(at as *const _ as u64, Ordering::Relaxed);
            GUARD_WITNESS_RANK.store(u64::from(rank), Ordering::Relaxed);
            GUARD_WITNESS_AGE.store(age, Ordering::Relaxed);
        }
    }

    // From here to the end of the switch, this must not be re-entered.
    //
    // `preempt` is reached two ways: from the timer interrupt, where delivery
    // is already masked, and voluntarily through `yield_now` and `resched`,
    // where it is not. On the voluntary path a tick landing between choosing
    // the next thread and performing the switch re-enters this function on the
    // same thread, which then switches using *its* decision — and the outer
    // call resumes and switches again from stale state. The result was a
    // corrupted interrupt frame and a #GP on `iretq`, a long way from the
    // cause.
    //
    // Masking for the duration makes the decision and the switch one step. The
    // window is a few hundred instructions and takes no lock that sleeps.
    let interrupts_were_enabled = cpu::interrupts_enabled();
    if interrupts_were_enabled {
        // SAFETY: re-enabled below on every path out.
        unsafe { cpu::disable_interrupts() };
    }

    // The lock is taken, the decision made, and the lock *released* before the
    // switch. It has to be: the incoming thread will eventually return from
    // its own call to this function and take the same lock.
    //
    // `try_lock`, because this is reachable from an interrupt that may have
    // landed inside this CPU's own scheduler critical section. Skipping a
    // preemption is harmless; spinning for a lock the interrupted code holds
    // is a deadlock against itself.
    let switch = {
        let Some(mut queue) = QUEUES[cpu].try_lock_for_switch() else {
            // The other silent decline, counted for the same reason as the
            // holds veto above.
            if let Some(count) = PREEMPT_QUEUE_BUSY.get(cpu) {
                count.fetch_add(1, Ordering::Relaxed);
            }
            restore_interrupts(interrupts_were_enabled);
            return true;
        };
        if !queue.started {
            // Not a decline to retry: the scheduler has not started here, or
            // `stop_all` has frozen it for reporting. It will look when it
            // starts, and an IPI sent into a freeze would only be answered by
            // the same refusal.
            restore_interrupts(interrupts_were_enabled);
            return false;
        }

        let current = queue.current;

        // Account *before* deciding. The order matters more than it looks:
        // this function returns early when the running thread is still the
        // right choice, so charging afterwards means a thread that wins one
        // comparison is never charged again -- its deadline freezes at the
        // value that won, and it keeps winning for ever. That is not a
        // fairness bug, it is a livelock, and it is what happened.
        //
        // `last_start` is reset whether or not a switch follows, so the next
        // charge measures from here rather than double-counting this slice.
        let now = tsc::read();
        if let Some(thread) = queue.threads[current].as_mut() {
            let delta = now.saturating_sub(thread.last_start);
            thread.charge(delta);
            thread.last_start = now;
        }
        queue.advance_min_vruntime();

        // Renew the quantum only when it has run out. An interrupt arriving
        // mid-slice leaves it alone, so the running thread keeps the remainder
        // it was owed rather than being handed a fresh one.
        if now >= queue.slice_deadline
            && let Some(thread) = queue.threads[current].as_ref()
        {
            queue.slice_deadline = now.saturating_add(thread.slice_ticks);
        }

        let mut next = queue.pick_next(current);
        if next == current {
            // Nothing else here to run. This is the cheapest moment to
            // balance and the only one implemented: the CPU is about to have
            // no work, so anything it takes costs nothing to run.
            // `docs/scheduler.md` §5 calls this the idle pull.
            match try_steal(cpu, &mut queue) {
                Some(stolen) => next = stolen,
                None => {
                    restore_interrupts(interrupts_were_enabled);
                    return false;
                }
            }
        }

        if let Some(thread) = queue.threads[current].as_mut()
            && thread.state == State::Running
        {
            thread.state = State::Ready;
        }
        if let Some(thread) = queue.threads[next].as_mut() {
            thread.state = State::Running;
            thread.runs += 1;
            thread.last_start = now;
            if thread.woken_at != 0 {
                let waited = now.saturating_sub(thread.woken_at);
                thread.woken_at = 0;
                WAKE_TO_RUN_SUM.fetch_add(waited, Ordering::Relaxed);
                WAKE_TO_RUN_COUNT.fetch_add(1, Ordering::Relaxed);
                WAKE_TO_RUN_MAX.fetch_max(waited, Ordering::Relaxed);
                // The delay in the high bits so `fetch_max` orders by it, the
                // thread in the low bits so the winner says who it was.
                WAKE_TO_RUN_WORST.fetch_max(
                    (waited.min((1 << 48) - 1) << 16) | u64::from(thread.id & 0xffff),
                    Ordering::Relaxed,
                );
                let bucket = (63 - waited.max(1).leading_zeros() as usize).min(47);
                WAKE_TO_RUN_BUCKETS[bucket].fetch_add(1, Ordering::Relaxed);
            }
        }
        // **Both slots checked before anything is handed over.**
        //
        // Everything below this point moves a piece of this CPU from the
        // outgoing thread to the incoming one: the kernel stack, `current`,
        // the floating-point file, the `FS` base, and the held-lock
        // accounting. The two raw-pointer extractions at the end are fallible
        // in the type system -- the slots are re-borrowed -- and their `else`
        // arms used to `return false` from the middle of that sequence,
        // leaving this CPU running the *outgoing* thread with five pieces of
        // the *incoming* one installed.
        //
        // Restoring the accounting there is not enough, and that is measured
        // rather than argued: forcing the arm with only the accounting undone
        // faults the kernel outright. There is no partial undo, so the arms
        // must not be reachable -- which this check makes true by
        // construction, declining before the first handover instead of in the
        // middle of the last.
        if queue.threads[current].is_none() || queue.threads[next].is_none() {
            restore_interrupts(interrupts_were_enabled);
            return false;
        }
        // A new thread starts a new quantum.
        if let Some((slice, stack)) = queue.threads[next]
            .as_ref()
            .map(|thread| (thread.slice_ticks, thread.kernel_stack_top))
        {
            queue.slice_deadline = now.saturating_add(slice);
            install_kernel_stack(cpu, stack);
        }
        queue.current = next;

        // INSTRUMENTATION, and it counts rather than prevents.
        //
        // Testing whether an exiting thread can be switched out while holding
        // *another* CPU's runqueue lock. `held_mask` cannot answer it: a
        // `try_lock` deliberately never joins the held set, so the check above
        // that keeps lock holders on their CPU cannot see one. The two `exit`
        // scans that motivated this (`domain_of_raw`,
        // `threads_in_domain_except`) were replaced by the per-domain thread
        // count on 2026-08-17; the counter stays because the question is
        // about *any* remote try_lock, and `threads_in_domain` still scans.
        //
        // The owner field answers it directly: if any queue but this one
        // records this CPU, the thread about to be descheduled is holding it.
        //
        // Deliberately does not skip the switch. A fix that made a stall of
        // one boot in 125 stop reproducing would be indistinguishable from
        // luck; the count says whether the window is entered at all, and how
        // often, before anything is changed to close it.
        {
            let here = cpu as u32;
            for (other, queue) in QUEUES.iter().enumerate().take(online_cpus()) {
                if other != cpu && queue.owner() == Some(here) {
                    PREEMPTED_HOLDING_REMOTE.fetch_add(1, Ordering::Relaxed);
                    LAST_REMOTE_HELD.store(other as u32, Ordering::Relaxed);
                    LAST_REMOTE_HOLDER.store(here, Ordering::Relaxed);
                }
            }
        }

        // Held locks travel with the thread, not the CPU. Saved for the
        // outgoing thread and installed for the incoming one, both under this
        // lock so the swap cannot be observed half-done.
        let incoming_locks = queue.threads[next].as_ref().map_or(0, |t| t.held_locks);
        let incoming_count = queue.threads[next].as_ref().map_or(0, |t| t.held_count);
        // Kept, not just stored: the decline paths below hand these back.
        let outgoing_locks = crate::sync::held_mask();
        let outgoing_count = crate::sync::holds_count();
        if let Some(thread) = queue.threads[current].as_mut() {
            thread.held_locks = outgoing_locks;
            thread.held_count = outgoing_count;
            if thread.held_locks != 0 {
                note_saved_holding(thread.id, thread.name, thread.held_locks, "preempt");
            } else if thread.held_count != 0 {
                note_saved_count(thread.id, thread.name, thread.held_count, "preempt");
            }
        }
        // RFC 0026's dispatch event, emitted here — under the lock, before
        // `switching` opens the registers-unsaved window — so the plane's
        // cost lengthens a lock hold the contention map can see, not the
        // one window the save/restore disease lives in. Emit takes no lock,
        // so holding one over it is sound.
        // The note is about the thread being switched *to*, so it is taken
        // before the pair below and not inside it: a switch whose outgoing
        // slot is already empty -- the previous thread exited -- still
        // changes which domain runs here, and skipping the note there left
        // the next thread's system calls judged by its predecessor's
        // dialect. RFC 0005 step 6 found that the hard way.
        // The floating-point file travels with the thread: saved out of the
        // CPU for whoever is leaving, restored for whoever is arriving.
        // This is `CR4.OSFXSR`'s promise being kept.
        // What the *register* holds, not what the departing thread's record
        // says it should -- see `FS_BASE_LOADED`.
        let leaving_base = fs_base_loaded();
        if let Some(from_thread) = queue.threads[current].as_mut() {
            // SAFETY: 512 aligned bytes belonging to the thread being
            // switched away from, and this is its last instant on the CPU.
            unsafe { bhaskix_arch::cpu::fx_save(from_thread.fx.0.as_mut_ptr()) };
        }
        if let Some(to_thread) = queue.threads[next].as_ref() {
            // SAFETY: an image `FXSAVE` wrote — every area starts as one.
            unsafe { bhaskix_arch::cpu::fx_restore(to_thread.fx.0.as_ptr()) };
            crate::telemetry::note_domain(to_thread.domain);
            // The thread-local base travels with the thread, because the
            // register does not: it is one per CPU, and a hosted program
            // that set one expects to find it after any switch. **The
            // arriving thread's base is loaded even when it is zero** --
            // otherwise a thread that never set one keeps its predecessor's,
            // which is another domain's pointer sitting in this thread's
            // segment base. The comparison is against what the CPU already
            // holds, which is the leaving thread's, so the common case where
            // neither uses TLS still writes no MSR.
            if to_thread.fs_base != leaving_base {
                // SAFETY: as `load_fs_base` -- a user-mode segment base.
                unsafe { load_fs_base(to_thread.fs_base) };
            }
        }
        if let (Some(from_thread), Some(to_thread)) = (
            queue.threads[current].as_ref(),
            queue.threads[next].as_ref(),
        ) {
            let _ = to_thread;
            let mut handover = [0u8; 8];
            handover[..4].copy_from_slice(&from_thread.id.to_le_bytes());
            handover[4..].copy_from_slice(&to_thread.id.to_le_bytes());
            crate::telemetry::emit(
                bhaskix_telemetry::EventClass::Sched,
                bhaskix_telemetry::schema::DISPATCH.id,
                to_thread.domain,
                &handover,
            );
        }
        crate::sync::set_held_mask(incoming_locks);
        crate::sync::set_holds_count(incoming_count);

        // Everything from here until `finish_switch` is the window rule 2
        // exists for: `current` is marked `Ready`, the lock is about to be
        // released, and its registers have not been saved yet.
        queue.switching = true;

        // Raw pointers to the two contexts, taken one at a time so each borrow
        // ends before the next begins.
        //
        // These stay valid across the switch because the queue is a `static`
        // that never moves — and, unlike the previous global scheduler, they
        // point into *this CPU's own* queue. No other processor reads or writes
        // these threads, so there is nothing to race with rather than a race
        // that happens to be prevented.
        let Some(from) = queue.threads[current]
            .as_mut()
            .map(|thread| &raw mut thread.context)
        else {
            // **Unreachable by the guard above, and counted in case that is
            // wrong.** This is not an undo: four other pieces of this CPU have
            // already gone to the incoming thread and cannot be handed back
            // from here. Restoring the accounting and lowering `switching` is
            // what *can* be done, and forcing this arm with only that done
            // faults the kernel -- which is why the guard exists rather than
            // this. A non-zero `HALF_SWITCHES` means the guard is wrong.
            HALF_SWITCHES.fetch_add(1, Ordering::Relaxed);
            crate::sync::set_held_mask(outgoing_locks);
            crate::sync::set_holds_count(outgoing_count);
            queue.switching = false;
            restore_interrupts(interrupts_were_enabled);
            return false;
        };
        let Some(to) = queue.threads[next]
            .as_ref()
            .map(|thread| &raw const thread.context)
        else {
            HALF_SWITCHES.fetch_add(1, Ordering::Relaxed);
            crate::sync::set_held_mask(outgoing_locks);
            crate::sync::set_holds_count(outgoing_count);
            queue.switching = false;
            restore_interrupts(interrupts_were_enabled);
            return false;
        };
        Some((from, to))
    };

    if let Some((from, to)) = switch {
        SWITCHES.fetch_add(1, Ordering::Relaxed);
        // SAFETY: both pointers address `Context` fields inside a static
        // runqueue, which outlives every thread. Both were taken from *this*
        // CPU's queue under its lock, and `switching` stops any other CPU
        // moving either of them out from under this switch. `to` was prepared
        // by `spawn_on` or saved by a previous switch.
        unsafe { bhaskix_context_switch(from, to) };

        // Reached when this thread is scheduled again, which may be much later
        // and -- since stealing -- on a different CPU. `finish_switch` reads
        // the CPU afresh rather than trusting `cpu` above, which by now may
        // name the processor this thread used to be on.
        finish_switch();
    }

    // The flag is a local on *this thread's* stack, so it travels with the
    // thread rather than with the processor -- which is what makes it the
    // right place to keep a value that must survive a switch.
    restore_interrupts(interrupts_were_enabled);
    false
}

/// Points both kernel-entry paths at the incoming thread's stack.
///
/// Two places need it and neither can consult the other: `SYSCALL` reads
/// per-CPU data because it has no stack to compute on, and the CPU reads the
/// TSS on a privilege change without asking anyone. They must name the same
/// stack, and it must be the one belonging to the thread about to run.
///
/// A stack top of zero means a thread that never enters from user mode — the
/// one each CPU registered for itself. Installing it would leave both paths
/// pointing at address zero, so it is skipped.
fn install_kernel_stack(cpu: usize, top: u64) {
    if top == 0 {
        return;
    }
    // SAFETY: this CPU is about to run the thread that owns this stack, and
    // the value is one past a mapped, guarded kernel stack allocated for it.
    unsafe {
        percpu::set_kernel_stack(cpu as u32, top);
        bhaskix_arch::gdt::set_privilege_stack(cpu, top);
    }
}

/// Re-enables interrupts if they were enabled before a scheduler critical
/// section masked them.
fn restore_interrupts(were_enabled: bool) {
    if were_enabled {
        // SAFETY: restores the state the caller was already running with.
        unsafe { cpu::enable_interrupts() };
    }
}

/// Gives up the rest of this thread's slice.
pub fn yield_now() {
    preempt();
}

/// Hands the CPU to a higher-ranked thread if one has become runnable.
///
/// A voluntary preemption point, called after a wake. Without it a thread
/// woken on this very CPU still waits for the next timer interrupt before it
/// runs — which puts real-time wakeup latency at one tick, 10 ms at 100 Hz,
/// against the 50 µs `docs/scheduler.md` §4 asks for. The tick is not a
/// scheduling decision, it is a *backstop*; the moment a thread becomes
/// runnable is when the decision should be taken.
///
/// Safe to call unconditionally: [`preempt`] returns without switching when
/// the running thread is still the right choice, so a wake that changes
/// nothing costs a lock and a comparison.
///
/// Must not be called with a lock held — it may switch.
pub fn resched() {
    preempt();
}

/// Marks the running thread finished and never returns.
pub fn exit() -> ! {
    let cpu = percpu::cpu_id() as usize;

    // Whatever this thread still owed, taken as it stops.
    //
    // A thread that received a call and dies before answering leaves its caller
    // blocked on a reply that no longer has anyone to send it. The caller
    // cannot work this out: the endpoint is still there, the capability is
    // still good, and there may be another server on it later. The obligation
    // is what died, and it lived here.
    //
    // Taken **before** this thread is marked `Finished`, so there is no window
    // in which the thread is gone and the debt is still recorded.
    //
    // This sentence used to say "under the same lock that marks this thread
    // finished", and that stopped being true on 2026-08-21: the debt is now
    // taken under the queue lock, the caller is released after the lock is
    // dropped — `abandon_caller` takes another of the same rank — and only then
    // is this thread marked `Finished`. The invariant is unchanged and the
    // mechanism is not, which is exactly the kind of drift this file keeps
    // finding in itself.
    //
    // The reason for the order is the paragraph below, one step further on: a
    // `Finished` thread is never scheduled again, so anything still owed must
    // be discharged while this thread is still something the scheduler will
    // return to. Ending the domain happens before the marking too, and that
    // ordering is the whole of a bug that cost an evening — **the same shape,
    // found twice in this function, a fortnight apart.**
    //
    // `dispatch` handles `Exit` before it takes a single lock, and says why: a
    // thread holding one cannot be preempted (M4-08), so a thread that reaches
    // `exit` holding a lock spins here instead of leaving and nothing ever
    // releases it. Ending a domain takes several -- the memory objects, the
    // interrupt handlers, every runqueue, the domain table, the capability
    // arena -- and doing that *after* marking this thread `Finished` put a
    // thread that can never be scheduled again into the queue for all of them.
    // It hung the shell intermittently, in a different place each time.
    //
    // Done while this thread is still `Running`, it is an ordinary thread doing
    // ordinary work, and every one of those locks behaves as it does anywhere
    // else.
    //
    // "Am I the last?" is answered by arithmetic, not by a scan. The scan this
    // replaced (`threads_in_domain_except`) could lose the answer two ways,
    // and the 2026-08-17 soak captured it doing so: a thread preempted between
    // its "not last" answer and marking itself `Finished` looked alive to the
    // true last thread, so *both* concluded "not last" and the domain outlived
    // every thread it had; and a `try_lock`-skipped queue counted as empty,
    // which could elect the wrong thread outright. `fetch_sub` elects exactly
    // one, and its decision survives preemption because it is a value in hand.
    //
    // The domain is read under this CPU's queue lock, blocking -- the same
    // lesson `set_domain_weight` and `mark_domain_dying` state at their own
    // scan sites: skipping a contended queue here would skip the decrement,
    // and a skipped decrement is a domain that never ends. The lock is
    // released before the ending runs, because ending takes the domain table
    // (rank 6) and holding a runqueue (rank 10) across that is the inversion
    // the ranking exists to catch.
    let me = current_thread_id();
    let my_domain = if cpu < MAX_CPUS {
        let queue = QUEUES[cpu].lock();
        let current = queue.current;
        queue.threads[current]
            .as_ref()
            .map(|thread| thread.domain)
            .filter(|domain| *domain != u32::MAX)
    } else {
        None
    };
    if let Some(domain) = my_domain
        && domain_thread_departs(domain)
    {
        crate::domain::ended_by_last_thread(crate::domain::DomainId::from_u32(domain));
    }

    // Taken out of whatever it was waiting on, before the runqueue lock below.
    //
    // Ordering, not taste: `Endpoints` is rank 8 and `SchedRunqueue` is 10, so
    // the endpoint table has to be taken first or not while holding the queue.
    // This is the same reason the domain work above happens here rather than
    // further down.
    //
    // Without this a dying thread's queue entries stay for the life of the
    // machine, and there are sixteen per endpoint per direction. See
    // `ipc::cancel_all`.
    if let Some(thread) = me {
        crate::ipc::cancel_all(thread);
        // And any notification it had bound. A binding that outlives its thread
        // is a wake sent for ever to somebody who is not there, and a slot that
        // can never be bound again. RFC 0010 question 1.
        crate::notify::unbind_thread(thread);
    }

    // **The obligation is taken first and the thread is marked `Finished`
    // second, and the order is the whole of a bug fixed on 2026-08-21.**
    //
    // Both used to happen in one pass under the queue lock, `Finished` first.
    // `abandon_caller` cannot run there — it takes another runqueue lock, and
    // two of the same rank held at once have no order between them — so it runs
    // after the lock is dropped. That leaves a window in which this thread is
    // already `Finished` and has not yet released anybody, and **a `Finished`
    // thread is never scheduled again**: a preemption inside that window ends
    // the story there, with the obligation taken, the caller never woken, and
    // nothing anywhere recording that it happened.
    //
    // The symptom was `test-faults`' `user` arm failing about one run in four
    // with its caller blocked for ever. The breadcrumb trail showed the
    // obligation *taken by exit* while `A SERVER EXITED OWING A REPLY` never
    // printed — a take with no announcement, which is exactly this window.
    //
    // So: take the obligation, drop the lock, release the caller, and only then
    // say this thread is finished. Staying `Running` for those few instructions
    // costs nothing — the thread is inside `exit` and will never return to its
    // own code — and it means the release happens while this thread is still
    // something the scheduler will come back to.
    let owed = if cpu < MAX_CPUS {
        let mut queue = QUEUES[cpu].lock();
        let current = queue.current;
        queue.threads[current].as_mut().and_then(|thread| {
            let id = thread.id;
            let taken = thread.reply_to.take();
            note_reply_trail(
                if taken.is_some() {
                    reply_trail::TAKEN_BY_EXIT
                } else {
                    reply_trail::EXIT_FOUND_NONE
                },
                id,
                taken,
            );
            taken
        })
    } else {
        None
    };

    // Outside the lock: telling the caller takes its CPU's runqueue lock, and
    // two of the same rank held at once have no order between them.
    if let Some(caller) = owed {
        // Said out loud, because this is the moment a service failure becomes
        // somebody else's error and the two are hard to connect afterwards.
        //
        // The caller sees `Revoked` -- `ServerGone` maps onto it -- which reads
        // as "your capability was withdrawn" and is nothing of the kind: the
        // capability is fine and the thread behind it left mid-request. A shell
        // printing `could not reach the filesystem` once in seventy runs, with
        // every self-test in the same boot green, is that gap. Naming the
        // server here turns it into a question with an answer.
        let server = me.and_then(describe).map_or("?", |(name, _)| name);
        let client = describe(caller).map_or("?", |(name, _)| name);
        crate::println!(
            "  A SERVER EXITED OWING A REPLY: {server} left while {client} \
             (thread {caller}) was waiting. That call fails as Revoked."
        );
        abandon_caller(caller);
    }

    // Now that nobody is owed anything, this thread may stop being one the
    // scheduler will return to. See the comment above the take.
    if cpu < MAX_CPUS {
        let mut queue = QUEUES[cpu].lock();
        let current = queue.current;
        if let Some(thread) = queue.threads[current].as_mut() {
            thread.state = State::Finished;
        }
    }

    loop {
        preempt();

        // If `preempt` returned, this CPU had nothing else to run — so halt
        // rather than spin round to try again. Spinning here re-takes this
        // CPU's runqueue lock through `preempt` on every pass, on a thread
        // that has already finished, and the lock is not fair: a remote CPU
        // spawning work onto this queue competes with the loop for the cache
        // line and can be starved. It is the same hazard `block_self` had,
        // in the one other place a thread runs with nothing to do.
        //
        // SAFETY: interrupts are enabled here -- `exit` is only reachable from
        // thread context -- so the timer or an IPI will wake this. If they are
        // not, the thread is finished and the CPU has no work either way.
        if cpu::interrupts_enabled() {
            // SAFETY: interrupts are enabled, so the timer or an IPI wakes
            // this halt. A thread reaching `exit` with them disabled would be
            // a bug elsewhere; spinning covers that case without hanging.
            unsafe { cpu::halt() };
        } else {
            core::hint::spin_loop();
        }
    }
}

/// Total context switches across every CPU.
#[must_use]
pub fn switches() -> u64 {
    SWITCHES.load(Ordering::Relaxed)
}

/// Total threads moved between CPUs.
#[must_use]
pub fn steals() -> u64 {
    STEALS.load(Ordering::Relaxed)
}

/// Which CPU's queue holds thread `id`, if any still does.
///
/// Only meaningful as a snapshot: the answer can change the moment it is
/// returned, which is the whole point of migration.
#[must_use]
pub fn cpu_of(id: u32) -> Option<u32> {
    for (cpu, queue) in QUEUES
        .iter()
        .enumerate()
        .take(percpu::online_count() as usize)
    {
        let Some(queue) = queue.try_lock() else {
            continue;
        };
        if queue.threads.iter().flatten().any(|thread| thread.id == id) {
            return Some(cpu as u32);
        }
    }
    None
}

/// Runs `f` for each live thread: `(cpu, id, name, state, runs, migrations, class)`.
pub fn for_each(mut f: impl FnMut(u32, u32, &'static str, State, u64, u64, &'static str)) {
    for (cpu, queue) in QUEUES
        .iter()
        .enumerate()
        .take(percpu::online_count() as usize)
    {
        let Some(queue) = queue.try_lock() else {
            continue;
        };
        for thread in queue.threads.iter().flatten() {
            f(
                cpu as u32,
                thread.id,
                thread.name,
                thread.state,
                thread.runs,
                thread.migrations,
                thread.policy.tag(),
            );
        }
    }
}

/// The scheduling verdict's inputs, for the stall dump and nobody else.
///
/// Added after a captured one-in-fifteen bring-up hang whose snapshot could
/// not be explained: two `Ready` threads with zero runs sat thirty-five
/// seconds on a CPU whose fair runner kept being picked, which the earliest-
/// virtual-deadline rule should make impossible — a fresh thread's deadline
/// is zero and zero wins. Either something vetoes preemption on that CPU for
/// ever (a leaked hold count would), or the deadlines are not what the rule
/// assumes. This walk prints both, so the next occurrence answers instead of
/// taunting: per thread the deadline and vruntime the pick compares, and per
/// CPU the hold count that can veto the pick from ever running.
pub fn for_each_verdict(mut f: impl FnMut(u32, u32, &'static str, State, u64, u64, u32, u64)) {
    for (cpu, queue) in QUEUES
        .iter()
        .enumerate()
        .take(percpu::online_count() as usize)
    {
        let Some(queue) = queue.try_lock() else {
            continue;
        };
        for thread in queue.threads.iter().flatten() {
            f(
                cpu as u32,
                thread.id,
                thread.name,
                thread.state,
                thread.deadline,
                thread.vruntime,
                thread.held_count,
                thread.held_locks,
            );
        }
    }
}

/// Takes this CPU's runqueue lock and never gives it back.
///
/// **Fault injection only**, and it exists to make a deadlock deterministic
/// rather than one boot in three hundred. The fault report used to read the
/// current thread through a *blocking* runqueue lock, so a fault raised while
/// this CPU already held that lock spun for ever on a lock it was itself
/// holding and printed nothing after its banner. Reproducing that needed a
/// fault taken with the lock held, which is what this arranges.
///
/// The guard is deliberately leaked: the machine is about to fault and halt,
/// and a lock released on the way out would not reproduce anything.
pub fn wedge_own_runqueue() {
    let cpu = percpu::cpu_id() as usize;
    if cpu >= MAX_CPUS {
        return;
    }
    core::mem::forget(QUEUES[cpu].lock());
}

/// How old an open guard must be before it counts as evidence rather than as
/// the bookkeeping window `sync`'s header describes.
///
/// A few thousand cycles is far beyond "a rank claimed two instructions before
/// the count caught up" and far below anything a correct holder keeps a
/// runqueue or wait queue lock for.
const GUARD_AGE_SUSPICIOUS: u64 = 4_000;

/// Switches made while the guard ledger still showed an aged open guard.
///
/// Non-zero means `preempt`'s veto was asked and answered "holds nothing" while
/// something was held -- the direction that carries a lock holder off its CPU.
pub static SWITCHED_WITH_OPEN_GUARD: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

/// The first such guard: its `&'static Location` as an address, its rank, and
/// how old it was. Only the first, because the first is the one that happened
/// before anything else could have been disturbed by it.
pub static GUARD_WITNESS_SITE: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);
/// The rank of the guard in [`GUARD_WITNESS_SITE`].
pub static GUARD_WITNESS_RANK: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);
/// How many cycles that guard had been open.
pub static GUARD_WITNESS_AGE: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// What a report could learn about the running thread without waiting.
///
/// Three answers, because a report must distinguish them: the thread, no
/// thread, and *could not tell*. Collapsing the last into `None` would print
/// "no thread" for a CPU that has one, which is a lie in the one place lying is
/// least affordable.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Running {
    /// The identifier of the thread this CPU is running.
    Thread(u32),
    /// The queue was readable and holds no current thread.
    Nobody,
    /// The runqueue lock was held, so the question went unanswered.
    LockHeld,
}

/// [`current_thread_id`], for a path that must never block.
///
/// **`try_lock`, and the reason is a specimen.** `sync`'s rule is that anything
/// reachable from an interrupt uses `try_lock`; `preempt`, `wake_from_interrupt`
/// and `block_self` all obey it and the fault report did not. It called
/// `current_thread_id`, which takes this CPU's runqueue lock *blocking* -- so a
/// fault taken while that same CPU already held that lock spun for ever on a
/// spinlock it was itself holding, and the report stopped dead after its banner.
///
/// That is where `run-106` of 2026-08-29 stopped, and it reframes `run-80` and
/// `run-312`, both of which died within five lines of the banner and were read
/// as console trouble. The interrupt-return path is where the scheduler runs,
/// which is exactly where this fault has been localised since `isr_common+0x57`
/// resolved to `iretq` -- so the report was most likely to deadlock precisely
/// when it had something worth saying.
#[must_use]
pub fn running_now() -> Running {
    let cpu = percpu::cpu_id() as usize;
    if cpu >= MAX_CPUS {
        return Running::Nobody;
    }
    let Some(queue) = QUEUES[cpu].try_lock() else {
        return Running::LockHeld;
    };
    let current = queue.current;
    match queue.threads[current].as_ref() {
        Some(thread) => Running::Thread(thread.id),
        None => Running::Nobody,
    }
}

/// [`describe`], for a path that must never block.
///
/// Worse than the one above if left blocking: `describe` locks *every* queue,
/// so it can wedge on any CPU's held lock rather than only this one. A queue it
/// cannot read is skipped -- a report that names three of four queues is worth
/// more than one that names none.
#[must_use]
pub fn describe_now(thread: u32) -> Option<(&'static str, u64)> {
    for queue in QUEUES.iter().take(percpu::online_count() as usize) {
        let Some(queue) = queue.try_lock() else {
            continue;
        };
        if let Some(found) = queue.threads.iter().flatten().find(|t| t.id == thread) {
            return Some((found.name, found.space_root));
        }
    }
    None
}

/// The identifier of the thread running on this CPU.
///
/// `None` before this CPU has a runqueue.
///
/// **Blocking, so not for anything reachable from an interrupt** -- see
/// [`running_now`], which exists because this one deadlocked a fault report
/// against a lock the faulting CPU was already holding.
#[must_use]
pub fn current_thread_id() -> Option<u32> {
    let cpu = percpu::cpu_id() as usize;
    if cpu >= MAX_CPUS {
        return None;
    }
    let queue = QUEUES[cpu].lock();
    let current = queue.current;
    queue.threads[current].as_ref().map(|thread| thread.id)
}

/// Blocks the calling thread unless `ready` produces something first — the
/// decision and the mark under one hold of the runqueue lock.
///
/// This is the safe shape of "check a condition, and sleep if it has not
/// happened". Doing it as [`mark_blocked`], then a check, then either
/// [`cancel_block`] or [`block_self`], leaves the thread marked `Blocked`
/// while it is still running. A tick landing in that window switches it out
/// blocked, and if the event it was waiting for has already been consumed —
/// its wake spent, its bits taken — nothing will ever wake it again.
///
/// Holding the lock across the pair closes it: [`preempt`] reaches this
/// runqueue with `try_lock` and gives up rather than switching a thread out
/// mid-decision.
///
/// # `ready` must not take a lock
///
/// It runs with this CPU's runqueue lock held. Reading atomics is what it is
/// for. Taking another lock inside it either inverts an order or, for a second
/// runqueue lock, closes a cycle against a lock of its own rank.
pub fn block_unless<T>(me: u32, ready: impl FnOnce() -> Option<T>) -> Option<T> {
    let cpu = percpu::cpu_id() as usize;
    if cpu >= MAX_CPUS {
        return ready();
    }
    let mut queue = QUEUES[cpu].lock();
    let taken = ready();
    if taken.is_none() {
        let current = queue.current;
        if let Some(thread) = queue.threads[current].as_mut() {
            // **The same check [`mark_blocked`] was given, for the same
            // reason, in the second place that writes this state.**
            //
            // `mark_blocked` learned in 2026-08-31 that reading
            // `percpu::cpu_id()`, taking that queue's lock and marking
            // whatever is `current` are three separate instants, and that a
            // caller migrated in between marks **an uninvolved thread on the
            // old CPU** -- one that never enqueued, and so one that is
            // `Blocked` with no queue entry and nothing that will ever wake
            // it. That guard was added there and not here, and the comment
            // beside it asserted `Blocked` "comes only from here", which was
            // never true: this function and the IPC delivery path in
            // [`Queue::deliver`] both write it too.
            //
            // So the counter built to catch the mechanism was watching one of
            // three doors. Specimen twelve (2026-09-03) is the terminal state
            // with `0 blocks refused` -- consistent with the mechanism firing
            // here, where nothing was counting.
            //
            // Refusing is self-correcting, as it is there: [`wait`] loops and
            // re-evaluates, and [`wait_once`] takes the same path a spurious
            // return already takes. A missed sleep is a spin; a mis-marked
            // sleep is a lost thread.
            if thread.id != me {
                MISMARKED_BLOCKS.fetch_add(1, Ordering::Relaxed);
                MISMARKED_UNLESS.fetch_add(1, Ordering::Relaxed);
                note_mismark(me, thread.id);
                return taken;
            }
            if !thread.dying {
                thread.state = State::Blocked;
            }
        }
    }
    taken
}

/// Marks the running thread blocked, without yielding.
///
/// **A thread that has been told to stop is not marked**, here or in
/// [`block_unless`]. Sleeping is the one thing a dying thread must not do: its
/// safe points are returning to user mode and deciding to block, and a thread
/// asleep reaches neither. Leaving it runnable makes its call return with
/// whatever it had, and the return path is where the flag is read. See
/// [`mark_domain_dying`].
///
/// Split from [`block_self`] because the two happen either side of releasing a
/// wait queue's lock, and must. This half runs *under* that lock, together
/// with enqueueing the thread as a waiter — see `wait::Waiters::enqueue_and_block`,
/// which fuses them so they cannot drift apart. A waker only wakes threads
/// that are already `Blocked`, so an enqueued thread that is still `Ready` is
/// a lost wakeup waiting to happen.
pub fn mark_blocked(id: u32) {
    let cpu = percpu::cpu_id() as usize;
    if cpu >= MAX_CPUS {
        return;
    }
    let mut queue = QUEUES[cpu].lock();
    let current = queue.current;
    let Some(thread) = queue.threads[current].as_mut() else {
        return;
    };
    // **The caller says who it is, and this is checked rather than assumed.**
    //
    // The old signature took nobody's word for anything: it read
    // `percpu::cpu_id()`, then acquired a lock, then marked whatever thread
    // was `current` on that CPU. Those are three separate instants, and a
    // spinlock in this kernel does **not** hold interrupts off for its
    // duration -- `claim_uninterrupted` covers two bookkeeping stores and
    // nothing else. So a tick can land between reading the CPU and taking its
    // queue; `preempt` normally refuses to deschedule a lock holder, but §3
    // carries an open defect in exactly that accounting, and `preempt`'s own
    // comment names the state in which the veto "waves a genuine holder
    // through".
    //
    // Waved through, migrated, and resumed elsewhere, this function would lock
    // the *old* CPU's queue and mark **whatever thread is running there** as
    // blocked -- a thread that never enqueued, and so one that is `Blocked`
    // with no queue entry and nothing that will ever wake it.
    //
    // That is precisely specimen nine's terminal state, which reading the code
    // says is otherwise unreachable: `Blocked` comes only from here, and here
    // is only reached from `enqueue_and_block`, which always leaves an entry;
    // while having no entry means a wake landed, which always leaves `Ready`.
    // One of those "always" claims had to be false, and this is a way for the
    // first one to be.
    //
    // **CORRECTION, 2026-09-03: "`Blocked` comes only from here" was wrong
    // when it was written.** Three production paths write `State::Blocked` --
    // this one, [`block_unless`], and the IPC delivery path in
    // [`Queue::deliver`], whose own comment records being "the third place
    // that decides to block" and being missed when the other two learned the
    // dying-thread rule. The same enumeration was got wrong again here: the
    // guard below went on one door of three, so the counter that was supposed
    // to catch this mechanism could not see it fire in the other two.
    // `block_unless` now carries the identical check. `deliver` does not need
    // it: it marks `target`, a thread it was handed, not whatever is running
    // on a CPU it read earlier.
    //
    // Refusing is safe and self-correcting rather than merely cautious: the
    // caller's entry is already queued, so `block_self` finds it not blocked
    // and returns, `wait_until` loops, removes its own entry and re-evaluates.
    // A missed sleep is a spin; a mis-marked sleep is a lost thread.
    if thread.id != id {
        MISMARKED_BLOCKS.fetch_add(1, Ordering::Relaxed);
        note_mismark(id, thread.id);
        return;
    }
    if !thread.dying {
        thread.state = State::Blocked;
    }
}

/// Switches abandoned after this CPU's accounting had already been handed over.
///
/// **Zero is the only value seen, and the point is that it is now checked.**
/// Both switch paths install the *incoming* thread's held mask and count, set
/// `switching`, and only then take raw pointers to the two contexts. Those two
/// steps are fallible in the type system -- the slots are re-borrowed, so each
/// needs an `else` -- and their `else` arms used to return having done neither
/// the switch nor an undo. This CPU would then keep running the **outgoing**
/// thread while carrying the **incoming** thread's accounting, and the next
/// guard the outgoing thread dropped would decrement a count that never
/// counted it: the per-CPU hold count underflows to `u32::MAX`, and a CPU
/// whose count reads -1 vetoes every preemption for ever.
///
/// That is the exact disease §3's wake-delay row has been hunting since
/// 2026-08-17 and has never found a producer for. This is a producer. It is
/// **not** a demonstrated one -- both slots were `Some` a few lines earlier
/// under the same lock with interrupts off, so the arms look unreachable.
///
/// **And the accounting is only one of five.** By the time those arms are
/// reached this CPU has also handed over its kernel stack, `queue.current`,
/// the floating-point file and the `FS` base. Forcing the arm with the
/// accounting restored and nothing else faults the kernel, measured
/// 2026-09-03, so there is no undo to write: the arms have to be unreachable,
/// and a guard before the first handover now makes them so. This counter says
/// whether that guard is wrong, which is the only remaining question about
/// them.
static HALF_SWITCHES: AtomicU64 = AtomicU64::new(0);

/// Switches abandoned between handing the accounting over and switching.
#[must_use]
pub fn half_switches() -> u64 {
    HALF_SWITCHES.load(Ordering::Relaxed)
}

/// Times `mark_blocked` was asked to mark a thread that was not its caller.
///
/// **Zero is the only correct value**, and a non-zero one is a thread put to
/// sleep by somebody else's `wait_until` — `Blocked` with no queue entry, which
/// nothing will wake. Counted rather than asserted because the condition is
/// rare enough that a boot which never sees it must still say so.
static MISMARKED_BLOCKS: AtomicU64 = AtomicU64::new(0);

/// The share of [`mismarked_blocks`] that [`block_unless`] refused.
///
/// Kept apart from the total because the two doors fail for the same reason
/// but on different paths, and a specimen that names which one is a specimen
/// that can be chased. The total is what the boot report has always printed,
/// so it keeps counting both.
static MISMARKED_UNLESS: AtomicU64 = AtomicU64::new(0);

/// Who was refused, and who they would have put to sleep -- the first time.
///
/// **A count cannot answer the question this defect is now stuck on.** CI run
/// 548 (2026-09-03) is the first boot ever to report a non-zero mismark, `6`,
/// and it wedged the ring anyway. So the mechanism is real and firing, and the
/// refusal that was supposed to prevent the terminal state did not prevent
/// this one. The next thing worth knowing is whether the stuck station is ever
/// *either party*: the caller whose mark was refused, or the thread that would
/// have been marked in its place.
///
/// Packed as `caller << 32 | victim`, written once with a compare-exchange so
/// the first pair survives the thousands that a mis-addressed arming produces.
/// `u64::MAX` means no refusal has happened.
static FIRST_MISMARK: AtomicU64 = AtomicU64::new(u64::MAX);

/// Keeps the **first** refused pair and discards the rest.
///
/// First rather than last for the reason the lock-ordering instrument keeps
/// its first violation: the earliest one happened on a machine that was still
/// behaving, so it describes the fault rather than the wreckage after it.
fn note_mismark(caller: u32, victim: u32) {
    let packed = (u64::from(caller) << 32) | u64::from(victim);
    let _ = FIRST_MISMARK.compare_exchange(u64::MAX, packed, Ordering::Relaxed, Ordering::Relaxed);
}

/// The first refused `(caller, would-have-been-marked)` pair, if there was one.
#[must_use]
pub fn first_mismark() -> Option<(u32, u32)> {
    let packed = FIRST_MISMARK.load(Ordering::Relaxed);
    (packed != u64::MAX).then_some(((packed >> 32) as u32, packed as u32))
}

/// How many times a block was refused because the caller was not the thread
/// about to be marked.
#[must_use]
pub fn mismarked_blocks() -> u64 {
    MISMARKED_BLOCKS.load(Ordering::Relaxed)
}

/// How many of [`mismarked_blocks`] were refused by [`block_unless`].
#[must_use]
pub fn mismarked_unless() -> u64 {
    MISMARKED_UNLESS.load(Ordering::Relaxed)
}

/// Undoes a [`mark_blocked`] that turned out not to be needed.
///
/// The counterpart to marking first and checking second. A caller that marks
/// itself blocked, then finds the thing it was going to wait for has already
/// arrived, must not be left in a state nothing will wake it from.
pub fn cancel_block() {
    let cpu = percpu::cpu_id() as usize;
    if cpu >= MAX_CPUS {
        return;
    }
    let mut queue = QUEUES[cpu].lock();
    let current = queue.current;
    if let Some(thread) = queue.threads[current].as_mut()
        && thread.state == State::Blocked
    {
        thread.state = State::Running;
    }
}

/// Yields the CPU if the calling thread is still blocked.
///
/// Between [`mark_blocked`] and this call the wait queue's lock is released —
/// it has to be, because switching with a spinlock held is how a kernel stops
/// — so a waker may run in that gap and mark this thread `Ready`.
///
/// The recheck below is what lets such a thread *leave*. It is not what makes
/// the wakeup safe: the waker has already written `Ready`, and a `Ready`
/// thread is chosen by ordinary round-robin whether or not this switch
/// happens. But without the recheck a thread woken in the gap with nothing
/// else runnable on its CPU has no exit from the loop and spins here forever,
/// which is a hang rather than a slowdown.
#[track_caller]
pub fn block_self() {
    let cpu = percpu::cpu_id() as usize;
    if cpu >= MAX_CPUS {
        return;
    }

    // INSTRUMENTATION. Reports, and does not refuse.
    //
    // This is the last switch path a lock holder can still go through.
    // `preempt` turns such a thread away, and can: skipping a preemption costs
    // one tick. `block_self` cannot -- the caller has decided to stop, and a
    // block that declines to block becomes a spin.
    //
    // So a thread that arrives here holding a lock is switched out still
    // holding it, and if it is never chosen again nothing releases it. That is
    // the bring-up stall: measured from the other end, `finish_switch` blocks
    // on a runqueue while the mask restored for the incoming thread already
    // has that rank set, at one boot in thirty.
    //
    // Reporting rather than refusing, because the fix belongs at the call site
    // -- release before you block -- and refusing here would hide which call
    // site that is. `#[track_caller]` names it.
    // **Sampled once.** This used to ask four separate questions -- the mask
    // and `holds_any` for the guard, then the mask and the count again for the
    // message -- and this path runs with interrupts enabled, so an interrupt
    // taking and releasing a lock between them produced exactly the
    // "mask 0b000000, 0 held" contradiction filed against the accounting. A
    // report built from two reads cannot describe one moment; see
    // `sync::accounting`.
    let (mask, held) = crate::sync::accounting();
    if mask != 0 || held != 0 {
        BLOCKED_HOLDING.fetch_add(1, Ordering::Relaxed);
        let site = core::panic::Location::caller();
        crate::println!(
            "    BLOCK HOLDING  a thread blocked holding locks (mask {mask:#08b}, {held} held), \
             at {}:{}",
            site.file(),
            site.line()
        );
        // The 2026-08-18 specimen fired this line six times with mask zero
        // and count one and could name nothing further. The open guards are
        // what it was missing: either one is listed here -- a file to open
        // -- or none is, and a counted hold with no open guard convicts the
        // count itself.
        crate::sync::dump_open_guards(bhaskix_arch::percpu::cpu_id() as usize);
    }

    // Same reasoning as `preempt`: choosing and switching must be one step
    // with respect to the timer, or a tick landing in between re-enters the
    // scheduler on this thread and both calls switch from their own stale
    // view.
    let interrupts_were_enabled = cpu::interrupts_enabled();
    if interrupts_were_enabled {
        // SAFETY: restored on every path out.
        unsafe { cpu::disable_interrupts() };
    }

    loop {
        let switch = {
            // `try_lock`, exactly as `preempt` does, and for a second reason
            // beyond avoiding a deadlock against an interrupt: a blocking
            // acquisition would join this CPU's held-rank set, and the set is
            // captured a few lines below as the outgoing thread's. The thread
            // would then carry a lock it does not hold to wherever it next
            // runs, and be reported for an inversion on its own runqueue.
            let Some(mut queue) = QUEUES[cpu].try_lock_for_switch() else {
                core::hint::spin_loop();
                continue;
            };
            let current = queue.current;

            match queue.threads[current].as_ref().map(|thread| thread.state) {
                Some(State::Blocked) => {}
                // Woken in the window, or never really blocked. Either way
                // there is nothing to do.
                _ => {
                    RACES.fetch_add(1, Ordering::Relaxed);
                    restore_interrupts(interrupts_were_enabled);
                    return;
                }
            }

            // Same ordering rule as `preempt`: charge, then decide.
            let now = tsc::read();
            if let Some(thread) = queue.threads[current].as_mut() {
                let delta = now.saturating_sub(thread.last_start);
                thread.charge(delta);
                thread.last_start = now;
            }
            queue.advance_min_vruntime();

            let next = queue.pick_next(current);
            if next == current {
                // Nothing else this CPU can run. Falling through to spin is
                // correct rather than merely expedient: the thread is blocked
                // and will not be chosen, so the CPU has no work, and only an
                // interrupt or another CPU's waker can change that. Stealing
                // is not attempted -- a CPU with a blocked thread has no
                // capacity a thief would want.
                None
            } else {
                // As in `preempt`: both slots checked before the first
                // handover, because there is no partial undo of the five that
                // follow. See that guard's note.
                if queue.threads[current].is_none() || queue.threads[next].is_none() {
                    restore_interrupts(interrupts_were_enabled);
                    return;
                }
                if let Some(thread) = queue.threads[next].as_mut() {
                    thread.state = State::Running;
                    thread.runs += 1;
                    thread.last_start = now;
                }
                if let Some((slice, stack)) = queue.threads[next]
                    .as_ref()
                    .map(|thread| (thread.slice_ticks, thread.kernel_stack_top))
                {
                    queue.slice_deadline = now.saturating_add(slice);
                    install_kernel_stack(cpu, stack);
                }
                queue.current = next;

                // RFC 0026's dispatch event, under the lock for the same
                // reason as on preempt's path: the cost lands in a lock
                // hold, not in the registers-unsaved window.
                // As above: the note is about the incoming thread and is
                // taken whether or not the outgoing slot still holds one.
                // As above: the floating-point file travels with the thread.
                // As the other site: the register, not a record of it.
                let leaving_base = fs_base_loaded();
                if let Some(from_thread) = queue.threads[current].as_mut() {
                    // SAFETY: as the other switch site.
                    unsafe { bhaskix_arch::cpu::fx_save(from_thread.fx.0.as_mut_ptr()) };
                }
                if let Some(to_thread) = queue.threads[next].as_ref() {
                    // SAFETY: as the other switch site.
                    unsafe { bhaskix_arch::cpu::fx_restore(to_thread.fx.0.as_ptr()) };
                    crate::telemetry::note_domain(to_thread.domain);
                    // As the other site: the arriving thread's base, zero
                    // included, against what the CPU already holds.
                    if to_thread.fs_base != leaving_base {
                        // SAFETY: as above.
                        unsafe { load_fs_base(to_thread.fs_base) };
                    }
                }
                if let (Some(from_thread), Some(to_thread)) = (
                    queue.threads[current].as_ref(),
                    queue.threads[next].as_ref(),
                ) {
                    let _ = to_thread;
                    let mut handover = [0u8; 8];
                    handover[..4].copy_from_slice(&from_thread.id.to_le_bytes());
                    handover[4..].copy_from_slice(&to_thread.id.to_le_bytes());
                    crate::telemetry::emit(
                        bhaskix_telemetry::EventClass::Sched,
                        bhaskix_telemetry::schema::DISPATCH.id,
                        to_thread.domain,
                        &handover,
                    );
                }
                let incoming_locks = queue.threads[next].as_ref().map_or(0, |t| t.held_locks);
                let incoming_count = queue.threads[next].as_ref().map_or(0, |t| t.held_count);
                // Kept, not just stored: the decline paths below hand these back.
                let outgoing_locks = crate::sync::held_mask();
                let outgoing_count = crate::sync::holds_count();
                if let Some(thread) = queue.threads[current].as_mut() {
                    thread.held_locks = outgoing_locks;
                    thread.held_count = outgoing_count;
                    if thread.held_locks != 0 {
                        note_saved_holding(thread.id, thread.name, thread.held_locks, "block_self");
                    } else if thread.held_count != 0 {
                        note_saved_count(thread.id, thread.name, thread.held_count, "block_self");
                    }
                }
                crate::sync::set_held_mask(incoming_locks);
                crate::sync::set_holds_count(incoming_count);
                queue.switching = true;

                let Some(from) = queue.threads[current]
                    .as_mut()
                    .map(|thread| &raw mut thread.context)
                else {
                    // As in `preempt`: unreachable by the guard above, not an
                    // undo, and counted in case the guard is wrong.
                    HALF_SWITCHES.fetch_add(1, Ordering::Relaxed);
                    crate::sync::set_held_mask(outgoing_locks);
                    crate::sync::set_holds_count(outgoing_count);
                    queue.switching = false;
                    restore_interrupts(interrupts_were_enabled);
                    return;
                };
                let Some(to) = queue.threads[next]
                    .as_ref()
                    .map(|thread| &raw const thread.context)
                else {
                    HALF_SWITCHES.fetch_add(1, Ordering::Relaxed);
                    crate::sync::set_held_mask(outgoing_locks);
                    crate::sync::set_holds_count(outgoing_count);
                    queue.switching = false;
                    restore_interrupts(interrupts_were_enabled);
                    return;
                };
                Some((from, to))
            }
        };

        match switch {
            Some((from, to)) => {
                SWITCHES.fetch_add(1, Ordering::Relaxed);
                BLOCKS.fetch_add(1, Ordering::Relaxed);
                // SAFETY: as in `preempt` -- both contexts are in this CPU's
                // own static runqueue, taken under its lock, and `switching`
                // stops another CPU moving either out from under the switch.
                unsafe { bhaskix_context_switch(from, to) };
                finish_switch();
                restore_interrupts(interrupts_were_enabled);
                // Reached only when something made this thread runnable again:
                // `pick_next` never selects a blocked thread.
                return;
            }
            None => {
                // Nothing to run here. Interrupts must be *open* while
                // waiting, or the tick that would make something runnable can
                // never be delivered and this loop spins for ever -- but they
                // are opened by the halt itself, below, and not before it.
                //
                // Opening them here was a lost wakeup with a two-instruction
                // window: the interrupt that makes a thread runnable arrives
                // between the `sti` and the `hlt`, its handler runs, and the
                // `hlt` executes anyway. The CPU then sleeps with a `Ready`
                // thread on its runqueue, and nothing wakes it -- the tick is
                // stopped for being idle, and the device that would interrupt
                // has had its source masked until a driver that is now asleep
                // acknowledges it.
                //
                // Before sleeping on the belief that nothing is runnable,
                // deliver anything an interrupt handler could not.
                //
                // A handler that loses `try_lock` records the wake for the
                // tick to retry. On one CPU the lock it loses to is held by
                // *this* thread, on its way to sleep -- and the thread it was
                // trying to wake is this one. Halting here stops the tick that
                // was going to deliver it, so the machine sleeps holding a
                // wake it has already promised. Measured as a single-processor
                // boot that stopped dead the moment the block driver waited
                // for its completion interrupt.
                if drain_deferred_wakes() {
                    continue;
                }

                if interrupts_were_enabled {
                    // `sti; hlt` as one step -- see `enable_interrupts_and_halt`.
                    //
                    // Halt rather than spin, and the reason is not power.
                    //
                    // Spinning here means re-taking this CPU's runqueue lock
                    // on every pass, in a tight loop, on a CPU that has
                    // nothing to do. Another CPU trying to reach this queue --
                    // to deliver an IPC message, say -- competes with that
                    // loop for the cache line and can be starved indefinitely,
                    // because the lock is not fair. It measured as an IPC
                    // rendezvous that completed once and then stopped.
                    //
                    // SAFETY: interrupts were enabled on entry, so enabling
                    // them here restores the caller's state, and the `sti`
                    // shadow means the `hlt` cannot be reached with one
                    // already taken and acted on.
                    unsafe { cpu::enable_interrupts_and_halt() };
                    // SAFETY: re-masking for the next pass, as at entry.
                    unsafe { cpu::disable_interrupts() };
                } else {
                    core::hint::spin_loop();
                }
            }
        }
    }
}

/// Makes a blocked thread runnable again, wherever it is.
///
/// Returns whether it changed anything. Waking a thread that is not blocked is
/// not an error and is the common case under contention.
///
/// # Why this searches rather than being told where to look
///
/// The obvious design has the waiter record which CPU holds it, so a wake is
/// one lookup. It is wrong, and subtly: a thread is safe from migration only
/// while it is `Blocked`, and a thread that sleeps in a loop is `Ready` in
/// between. A cached CPU therefore goes stale exactly when a woken thread is
/// stolen before it sleeps again — and the next wake is delivered to a queue
/// that no longer holds it, which is a lost wakeup with a migration in its
/// history and nothing in the logs.
///
/// That happened. The ring self-test stalled with one station `Blocked` and
/// marked `(migrated)`, which is what the thread table is for. Searching by
/// identifier costs a few uncontended lock acquisitions and cannot go stale.
///
/// This is the one place a CPU touches a thread in *another* CPU's queue, and
/// it stays within the ownership rule M4-06 established: it changes a `state`
/// field under that queue's lock and never reads or writes a context. A woken
/// thread is scheduled by its own CPU, on its own stack, as it always was.
pub fn wake(id: u32) -> bool {
    wake_with(id, false) == WakeResult::Woken
}

/// What an attempt to wake a thread achieved.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum WakeResult {
    /// The thread was blocked and is now ready.
    Woken,
    /// No queue holds a blocked thread with that identifier.
    ///
    /// Distinct from [`WakeResult::Contended`], and the distinction is the
    /// whole reason this enum exists rather than a `bool`. A thread that is
    /// already awake needs nothing; a queue that was busy needs another
    /// attempt. Conflating them means either retrying for ever on threads that
    /// do not exist, or dropping wakes that were merely mistimed — the second
    /// of which was written first, and hung the wait-queue self-test.
    NotFound,
    /// A queue could not be inspected because its lock was held.
    Contended,
}

/// Wakes `id` from an interrupt handler, without ever waiting for a lock.
///
/// The distinction is not stylistic. A handler runs on a CPU that may have
/// interrupted a thread *holding that CPU's runqueue lock*, and a blocking
/// acquisition there waits for a thread that cannot run until the handler
/// returns — a one-CPU deadlock with no output and nothing to inspect. This
/// module's rule is stated in `preempt`: anything reachable from an interrupt
/// uses `try_lock`.
///
/// A contended queue means the wake did not happen, which for a sleeper is
/// indistinguishable from a lost one. So a contended attempt is **recorded**
/// rather than dropped, and retried from the next timer tick. The worst case
/// is a wake delayed by one tick — at most the idle backstop, one second —
/// rather than a thread that never wakes.
pub fn wake_from_interrupt(id: u32) -> bool {
    match wake_with(id, true) {
        WakeResult::Woken => true,
        WakeResult::Contended => {
            defer_wake(id);
            false
        }
        // Nothing to retry: no queue holds a blocked thread by that name.
        WakeResult::NotFound => false,
    }
}

/// Retries wakes an earlier handler could not deliver.
///
/// Called from the timer tick, still in interrupt context, so still
/// `try_lock`: an entry that cannot be delivered now stays for the next tick.
pub fn drain_deferred_wakes() -> bool {
    let mut delivered = false;
    for slot in &DEFERRED_WAKES {
        let id = slot.load(Ordering::Acquire);
        if id == NO_THREAD {
            continue;
        }
        // Cleared on anything but contention. A thread that has since woken
        // by another route, or exited, must not hold a slot for ever -- eight
        // stale entries is a table that can no longer defer anything.
        let outcome = wake_with(id, true);
        if outcome != WakeResult::Contended {
            delivered |= outcome == WakeResult::Woken;
            let _ = slot.compare_exchange(id, NO_THREAD, Ordering::AcqRel, Ordering::Relaxed);
        }
    }
    delivered
}

/// Records a wake that could not be delivered.
///
/// **A wake lost here is lost for ever, and that is not a slowdown.** A thread
/// blocked in `notify::wait` has already had its pending bits set by the
/// signaller — the bits go down before the wake goes out — so it would return
/// immediately if anything ever scheduled it again. Nothing will: it is
/// `Blocked`, and the only thing that was going to change that has just been
/// dropped on the floor.
///
/// For the console that is worse than a stuck thread. The serial source is
/// masked until the reader wakes and acknowledges it, so one lost wake means no
/// further interrupts, no further signals, and input is dead for the life of
/// the machine. It presents as a shell that echoes a command, answers it, and
/// then never reads another — with every other part of the system still running.
///
/// Two things made that reachable, and both are fixed here:
///
/// * **The table held eight entries.** At most `MAX_CPUS * MAX_THREADS_PER_CPU`
///   threads exist at once, so eight was not a bound on anything — it was a
///   guess, and a wake past it was dropped.
/// * **It did not check whether the thread was already in it.** A thread
///   deferred twice took two slots, so the eight were spent faster than there
///   were threads to spend them.
///
/// Sized to the live-thread bound and deduplicated, losing one is now
/// unreachable rather than unlikely: a thread occupies at most one slot and
/// there are as many slots as threads. The counter stays, and says so out loud
/// if it is ever wrong.
fn defer_wake(id: u32) {
    // Already waiting to be retried. A second entry would wake it twice, which
    // is harmless, and spend a slot, which is not.
    for slot in &DEFERRED_WAKES {
        if slot.load(Ordering::Acquire) == id {
            return;
        }
    }
    for slot in &DEFERRED_WAKES {
        if slot
            .compare_exchange(NO_THREAD, id, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            return;
        }
    }
    // Unreachable, unless the bound above is wrong. Said on the serial line
    // rather than only counted, because the counter was never read by anything
    // in three milestones and the failure it records is a machine that stops
    // answering with no other symptom.
    DEFERRED_LOST.fetch_add(1, Ordering::Relaxed);
    crate::println!(
        "  A WAKE WAS LOST: thread {id} is blocked and nothing will wake it. \
         The deferred table is full, which should not be possible."
    );
}

/// Whether any wake is waiting for a tick to retry it.
#[must_use]
pub fn deferred_wakes_pending() -> bool {
    DEFERRED_WAKES
        .iter()
        .any(|slot| slot.load(Ordering::Acquire) != NO_THREAD)
}

/// Wakes that were deferred and then dropped for want of a slot.
#[must_use]
pub fn deferred_wakes_lost() -> u64 {
    DEFERRED_LOST.load(Ordering::Relaxed)
}

/// Sentinel for an empty deferred-wake slot. Thread identifiers start at 1.
const NO_THREAD: u32 = 0;

/// Wakes an interrupt handler could not deliver immediately.
///
/// One slot per thread the machine can have. `defer_wake` records each thread
/// at most once, so the table cannot fill while there is a thread left to fill
/// it — which is the property that makes a lost wake unreachable rather than
/// rare. Two kilobytes of static for a failure mode whose symptom is a machine
/// that goes quiet.
static DEFERRED_WAKES: [core::sync::atomic::AtomicU32; MAX_CPUS * MAX_THREADS_PER_CPU] =
    [const { core::sync::atomic::AtomicU32::new(NO_THREAD) }; MAX_CPUS * MAX_THREADS_PER_CPU];
static DEFERRED_LOST: AtomicU64 = AtomicU64::new(0);

/// The last wake attempts made on this machine: which thread, and what came of
/// it.
///
/// **Because "by elimination it must have been delivered" is not an
/// observation.** `run-1007` has a station asleep with its entry gone, both
/// `UNSEEN_WAKES` and `LOST_WAKES` at zero, and its predicate evaluations level
/// with its peers -- so the wake landed, and a landed wake makes a thread
/// `Ready`. It is `Blocked`. One of those statements is wrong and no counter
/// currently in the tree can say which.
///
/// Packed as `id | outcome << 32`, one relaxed store per attempt on a path that
/// already takes a runqueue lock. Thirty-two slots, because what matters is the
/// handful of attempts around the moment a station stopped.
static WAKE_LOG: [core::sync::atomic::AtomicU64; 32] =
    [const { core::sync::atomic::AtomicU64::new(u64::MAX) }; 32];

/// Where the next [`WAKE_LOG`] entry goes.
static WAKE_LOG_NEXT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Records one wake attempt. `outcome`: 0 woken, 1 not found, 2 contended.
fn note_wake(id: u32, outcome: u64) {
    let slot = WAKE_LOG_NEXT.fetch_add(1, Ordering::Relaxed) as usize % WAKE_LOG.len();
    WAKE_LOG[slot].store(u64::from(id) | (outcome << 32), Ordering::Relaxed);
}

/// Walks the recorded wake attempts for one thread, oldest slot first, as
/// `(outcome, position)` where position is the slot index.
///
/// Reading by thread rather than dumping all thirty-two: the question is always
/// "what happened to *this* sleeper", and a report that prints every wake on the
/// machine is one nobody reads.
pub fn for_each_wake_attempt(thread: u32, mut f: impl FnMut(u64)) {
    for slot in &WAKE_LOG {
        let packed = slot.load(Ordering::Relaxed);
        if packed == u64::MAX {
            continue;
        }
        if u32::try_from(packed & 0xffff_ffff).unwrap_or(u32::MAX) == thread {
            f(packed >> 32);
        }
    }
}

fn wake_with(id: u32, from_interrupt: bool) -> WakeResult {
    let online = percpu::online_count() as usize;
    let here = percpu::cpu_id();
    let mut contended = false;

    for (cpu, queue) in QUEUES.iter().enumerate().take(online.min(MAX_CPUS)) {
        // One queue lock at a time. Two would be two locks of the same rank,
        // which have no order relative to each other and could close a cycle.
        let woken = {
            // Written as an `if`, not a `match` on `(from_interrupt,
            // queue.try_lock())`. The tuple form evaluates `try_lock` on
            // every path and keeps its guard alive for the whole match, so
            // the blocking arm waits for a lock the scrutinee is holding --
            // a self-deadlock on the first wake, which is exactly how this
            // was written the first time.
            let mut queue = if from_interrupt {
                match queue.try_lock() {
                    Some(queue) => queue,
                    // Contended, in interrupt context: reported to the caller,
                    // which records it for the next tick rather than waiting
                    // for a lock this CPU may itself be preventing from being
                    // released.
                    None => {
                        contended = true;
                        continue;
                    }
                }
            } else {
                queue.lock()
            };
            let floor = queue.min_vruntime;
            let mut woken = false;
            for thread in queue.threads.iter_mut().flatten() {
                if thread.id == id && thread.state == State::Blocked {
                    thread.state = State::Ready;
                    thread.woken_at = tsc::read();
                    if matches!(thread.policy, Policy::Fair { .. }) {
                        thread.vruntime = thread.vruntime.max(floor);
                        thread.charge(0);
                    }
                    WAKEUPS.fetch_add(1, Ordering::Relaxed);
                    woken = true;
                    break;
                }
            }
            woken
        };

        if woken {
            // Poke the other CPU. Sent after the lock is released -- an IPI is
            // not instantaneous, and holding a runqueue lock across it would
            // block the very CPU being woken from acting on the news.
            if cpu as u32 != here {
                notify(cpu as u32);
            }
            note_wake(id, 0);
            return WakeResult::Woken;
        }
    }

    if contended {
        note_wake(id, 2);
        WakeResult::Contended
    } else {
        note_wake(id, 1);
        WakeResult::NotFound
    }
}

/// Tells `cpu` that its runqueue changed.
///
/// The counterpart to the local `resched`. Marking a thread ready in another
/// CPU's queue is invisible to that CPU until it next runs the scheduler, and
/// an idle CPU with its timer stopped has no reason to. Without this, tickless
/// idle is not a power optimisation, it is a way to lose threads.
fn notify(cpu: u32) {
    let Some(lapic) = percpu::lapic_id_of(cpu) else {
        return;
    };
    RESCHEDULE_IPIS.fetch_add(1, Ordering::Relaxed);
    // SAFETY: the APIC is initialised long before any thread can block, and
    // every CPU has an IDT gate for all 256 vectors.
    unsafe {
        bhaskix_arch::apic::send_ipi(lapic, RESCHEDULE_VECTOR);
    }
}

/// Sleepers marked dying that could not be collected for waking. Always zero.
pub static WAKES_DROPPED: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Tells every thread of `domain` to stop, and wakes the ones that are asleep.
///
/// Returns how many were marked, including the caller if it belongs to that
/// domain — which it does when a program faults, since this runs on the way
/// out of the fault.
///
/// **Waking the blocked ones is not a courtesy, it is the whole mechanism.** A
/// thread asleep on an endpoint has no next safe point: it is not going to
/// return to user mode, and it is not going to decide to block again, so a
/// flag it never reads stops nothing. Waking it makes its call return, and the
/// return path is where the flag is read. This is also, in one step, the fix
/// for a caller whose service died — [RFC 0013](../../docs/rfc/0013-service-framework.md)
/// unresolved question 1 — because that caller is blocked on an endpoint the
/// dying domain served.
///
/// The wake is `wake`, not `wake_from_interrupt`: this is reached from a fault
/// handler, but from the *tail* of one, after the report is printed and with no
/// lock held. A dying thread that could not be woken because a queue was
/// contended would be a thread that never dies.
pub fn mark_domain_dying(domain: u32) -> usize {
    if domain == u32::MAX {
        // Not a domain. Marking every thread that belongs to no domain would
        // be every kernel thread on the machine.
        return 0;
    }

    // Blocking on each queue in turn, not `try_lock`. Skipping a contended
    // queue loses a thread, and a lost thread is a domain that reports itself
    // destroyed while part of it is still running -- the exact claim this step
    // exists to make true. Safe to block: every caller reaches here holding
    // nothing, including the fault path, where the thread that faulted was in
    // ring 3 and so held no kernel lock at all.
    //
    // One queue at a time. Two would be two locks of the same rank, which have
    // no order relative to each other and could close a cycle -- the rule
    // `wake_with` states a few hundred lines below.
    // **Every thread the machine can hold**, so this cannot truncate.
    //
    // It was `MAX_CPUS * 4` — two hundred and fifty-six — against a machine
    // that holds `MAX_CPUS * MAX_THREADS_PER_CPU`, five hundred and twelve. The
    // `get_mut` below silently dropped anything past the end, so a domain with
    // more than two hundred and fifty-six blocked threads would have marked
    // them all dying and woken only some. The rest would sleep for ever holding
    // whatever they were waiting on — and a notification takes one waiter, so
    // each one left behind refuses every later waiter on it.
    //
    // Sized from the same two constants the thread table is, so the two cannot
    // drift apart: two kilobytes of a sixty-four-kilobyte stack.
    let mut asleep = [0u32; MAX_CPUS * MAX_THREADS_PER_CPU];
    let mut waiting = 0;
    let mut marked = 0;

    let online = percpu::online_count() as usize;
    for queue in QUEUES.iter().take(online.min(MAX_CPUS)) {
        let mut queue = queue.lock();
        for thread in queue.threads.iter_mut().flatten() {
            if thread.domain != domain || thread.dying {
                continue;
            }
            thread.dying = true;
            marked += 1;
            if thread.state == State::Blocked {
                if let Some(slot) = asleep.get_mut(waiting) {
                    *slot = thread.id;
                    waiting += 1;
                } else {
                    // Unreachable while the array is sized as above, and
                    // counted rather than ignored because the thing it would
                    // mean — a sleeper marked dying and never woken — is
                    // invisible from anywhere else.
                    WAKES_DROPPED.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }

    // Outside every queue lock, for the reason above.
    for id in asleep.iter().take(waiting) {
        let _ = wake(*id);
    }
    marked
}

/// Domain-scans that could not see into every runqueue (see the counter's
/// bump site for why that is worth a number).
static DOMAIN_SCAN_SKIPS: AtomicU64 = AtomicU64::new(0);

/// How many times a domain thread-scan was blinded by a busy queue.
#[must_use]
pub fn domain_scan_skips() -> u64 {
    DOMAIN_SCAN_SKIPS.load(Ordering::Relaxed)
}

/// Times a CPU's rank mask read held while its hold count read zero — the
/// pre-underflow mismatch, counted so the first is printed and the rest are
/// a number.
static COUNT_MISMATCHES: AtomicU64 = AtomicU64::new(0);

/// Preemptions declined because this CPU's hold count read nonzero.
static PREEMPT_VETO_HOLDS: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];

/// Preemptions declined because this CPU's own queue lock was busy.
static PREEMPT_QUEUE_BUSY: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];

/// Spawns onto the calling CPU whose `resched` declined and fell back to an IPI.
///
/// Zero on a quiet machine and small under load. It is here so the fallback is
/// not itself silent: if this stays zero for ever the path is untested rather
/// than unnecessary, and if it climbs while spawn latencies climb with it the
/// IPI is being declined too and the fix is in the wrong place.
static SPAWN_RESCHED_DECLINED: AtomicU64 = AtomicU64::new(0);

/// How many same-CPU spawns had to fall back to an IPI. See the static.
#[must_use]
pub fn spawn_resched_declines() -> u64 {
    SPAWN_RESCHED_DECLINED.load(Ordering::Relaxed)
}

/// Checks that a declined preemption still *reports* itself.
///
/// The 20 ms boot bound on spawn-to-first-dispatch only fires when a decline
/// actually happens, and a decline is rare — so a change that stopped
/// `preempt_reporting` answering `true` could sit unnoticed for a long time
/// while the hole it guards quietly reopened. This asserts the reporting
/// directly and deterministically: hold a lock, ask for a preemption, and it
/// must say it declined.
///
/// Nothing else is taken. The holds veto is the first thing `preempt` checks,
/// before it looks at any runqueue, so this can never contend with the
/// scheduler or deschedule the caller.
#[must_use]
pub fn preempt_reports_its_decline() -> bool {
    static PROBE: SpinLock<()> = SpinLock::new(Rank::Console, ());
    let held = PROBE.lock();
    let declined = preempt_reporting();
    drop(held);
    declined
}

/// How often `preempt` declined on `cpu`: `(holds veto, queue busy)`.
///
/// Both declines are silent and look like "nothing to do" from outside; the
/// counters exist so a decline that *repeats* — the shape run-123's silent
/// CPU would leave — is a number in a capture instead of an inference.
#[must_use]
pub fn preempt_declines(cpu: usize) -> (u64, u64) {
    (
        PREEMPT_VETO_HOLDS
            .get(cpu)
            .map_or(0, |c| c.load(Ordering::Relaxed)),
        PREEMPT_QUEUE_BUSY
            .get(cpu)
            .map_or(0, |c| c.load(Ordering::Relaxed)),
    )
}

/// Live threads per domain, counted by arithmetic instead of by scanning.
///
/// The 2026-08-17 soak capture proved the scan answer to "am I my domain's
/// last thread" gets lost: `exit` asked it *before* marking `Finished`, so a
/// tick landing between the two let the true last thread see its predecessor
/// as still alive — both concluded "not last", and the domain outlived every
/// thread it had with nobody left to ask (eight captures, every one "still
/// live 8 s on", never "ended late"). A counter has no such window: joining
/// increments, leaving decrements, and `fetch_sub` returning 1 elects exactly
/// one thread — whose decision, once made, survives any preemption because it
/// is a value in hand rather than a scan to re-run.
static DOMAIN_LIVE_THREADS: [core::sync::atomic::AtomicU32; crate::domain::MAX_DOMAINS] =
    [const { core::sync::atomic::AtomicU32::new(0) }; crate::domain::MAX_DOMAINS];

/// Records a thread joining `domain`, at spawn.
fn domain_thread_arrives(domain: u32) {
    if let Some(count) = DOMAIN_LIVE_THREADS.get(domain as usize) {
        count.fetch_add(1, Ordering::AcqRel);
    }
}

/// Records a thread leaving `domain`, at exit: true exactly once — for the
/// thread whose departure left the domain empty.
fn domain_thread_departs(domain: u32) -> bool {
    DOMAIN_LIVE_THREADS
        .get(domain as usize)
        .is_some_and(|count| count.fetch_sub(1, Ordering::AcqRel) == 1)
}

/// How many threads the departure counter still attributes to a domain slot.
///
/// **This is what makes a slot unsafe to reuse.** `domain::end` marks a
/// domain's threads dying and returns; each stops at its own next safe
/// point, and until it has, it still holds this slot's number and will
/// decrement this counter when it goes. A slot handed out again in that
/// window gets a stranger's departure counted against it -- and a
/// departure that takes the count to zero *ends the innocent domain that
/// now holds the slot*, revoking its capabilities and clearing its
/// personality tag underneath a program that did nothing.
///
/// That is not a hypothesis. It was captured on 2026-08-19: the signal
/// self-test's Linux domain took the slot the previous probe's domain had
/// just released, the previous probe's thread exited a moment later, and
/// the fault handler then found the domain's Linux tag cleared and
/// delivered no signal -- `delivered 0`, with the handler demonstrably
/// installed. `domain::create_under` uses this to refuse such a slot.
#[must_use]
pub fn threads_counted_in(domain: u32) -> u32 {
    DOMAIN_LIVE_THREADS
        .get(domain as usize)
        .map_or(0, |count| count.load(Ordering::Relaxed))
}

/// How many threads still exist in `domain`, in any state but `Finished`.
///
/// `Finished` is excluded because a finished thread is one that *has* stopped;
/// its slot is freed by `reap_finished` on the next scheduling decision of the
/// CPU it was on, which may not have happened yet. Counting it would make
/// "stopped" depend on when the next timer tick lands somewhere else.
#[must_use]
pub fn threads_in_domain(domain: u32) -> usize {
    let online = percpu::online_count() as usize;
    let mut total = 0;
    for queue in QUEUES.iter().take(online.min(MAX_CPUS)) {
        let Some(queue) = queue.try_lock() else {
            // A skipped queue counts as empty. Tolerable here — every caller
            // polls in a loop, so a blinded pass is corrected by the next —
            // and counted, so the domain-test capture can report it. The
            // last-thread decision in `exit` deliberately does NOT use this
            // function for exactly this reason, and neither does
            // `Domain::set_personality` any more: see
            // [`threads_in_domain_exact`].
            DOMAIN_SCAN_SKIPS.fetch_add(1, Ordering::Relaxed);
            continue;
        };
        total += queue
            .threads
            .iter()
            .flatten()
            .filter(|thread| thread.domain == domain && thread.state != State::Finished)
            .count();
    }
    total
}

/// How many of `ids` are still held by some run queue.
///
/// **Blocks for each queue rather than skipping one it cannot take**, for the
/// reason [`threads_in_domain_exact`] gives at length: [`cpu_of`] answers with
/// `try_lock` and a queue it cannot take reads as *not holding the thread*, so
/// a caller waiting for a thread to disappear would be told it had, early and
/// wrongly. A caller that polls can live with that; a caller deciding *"they
/// are all gone, carry on"* cannot.
///
/// **`Finished` does not count as present**, and the first version of this got
/// that wrong: a thread that has called `sched::exit` keeps its slot until its
/// CPU makes another scheduling decision, and a CPU with nothing to run may
/// simply not make one. Waiting for the slot to be freed therefore waited for
/// something an idle machine need never do — measured, four workers of four
/// still "present" four seconds after they had all exited.
///
/// What a caller actually wants to know is whether these threads are still
/// *running*, because a spinner is what invalidates the next measurement. A
/// finished thread is not spinning. `threads_in_domain` filters the same way,
/// for the same reason.
///
/// # Lock order
///
/// Takes `Rank::SchedRunqueue` and nothing else, so it is sound from any caller
/// holding nothing or holding something outer. Not from one already holding a
/// run queue.
#[must_use]
pub fn threads_present_exact(ids: &[u32]) -> usize {
    let online = percpu::online_count() as usize;
    let mut present = 0;
    for queue in QUEUES.iter().take(online.min(MAX_CPUS)) {
        let queue = queue.lock();
        present += queue
            .threads
            .iter()
            .flatten()
            .filter(|thread| ids.contains(&thread.id) && thread.state != State::Finished)
            .count();
    }
    present
}

/// Like [`threads_in_domain`], but **blocks** for each queue rather than
/// skipping one it cannot take.
///
/// # Why both exist
///
/// `threads_in_domain` takes each run queue with `try_lock` and counts a
/// skipped queue as **empty**. Its own comment calls that tolerable *"because
/// every caller polls in a loop, so a blinded pass is corrected by the next"* —
/// and names `exit` as deliberately not using it for that reason.
///
/// A caller that asks **once** and decides is not the caller that comment
/// describes. `Domain::set_personality` is exactly such a caller: it refuses a
/// tag change while a thread exists, once, and a blinded scan there reads as
/// "no threads" and lets the change through. Measured on 2026-08-26 at about
/// **one attempt in twenty**, with the probe demonstrably mid-syscall — and
/// retryable, so a caller in a loop defeated the rule at will.
///
/// # Lock order
///
/// `Rank::Domains` is **6** and `Rank::SchedRunqueue` is **10**, so taking a
/// run queue while holding the domain table is the sanctioned direction and
/// blocking here is sound. It would not be sound from a caller already holding
/// a run queue — the rank detector reports that, and the boot gate that asserts
/// no lock-order violation anywhere in bring-up is what proves this change did
/// not introduce one.
#[must_use]
pub fn threads_in_domain_exact(domain: u32) -> usize {
    let online = percpu::online_count() as usize;
    let mut total = 0;
    for queue in QUEUES.iter().take(online.min(MAX_CPUS)) {
        let queue = queue.lock();
        total += queue
            .threads
            .iter()
            .flatten()
            .filter(|thread| thread.domain == domain && thread.state != State::Finished)
            .count();
    }
    total
}

/// Tells `caller` that the answer it is waiting for is never coming.
///
/// Returns whether a thread was found to tell. `false` is the ordinary case
/// where the caller has already given up or gone away, not an error.
///
/// The wake is what makes the flag mean anything: a caller blocked in `Call` is
/// asleep, and a flag set on a sleeping thread nobody wakes is a thread that
/// sleeps for ever holding a slightly more informative reason.
pub fn abandon_caller(caller: u32) -> bool {
    let online = percpu::online_count() as usize;
    let mut found = false;
    for queue in QUEUES.iter().take(online.min(MAX_CPUS)) {
        let mut queue = queue.lock();
        if let Some(target) = queue.threads.iter_mut().flatten().find(|t| t.id == caller) {
            target.answer_lost = true;
            found = true;
            break;
        }
    }
    if found {
        // Outside the loop, so the queue lock taken above is released first.
        let _ = wake(caller);
    }
    found
}

/// Whether any thread of `domain` currently owes a caller a reply.
///
/// Used to wait for a rendezvous to have *happened* rather than for a duration:
/// until the call has been taken there is no obligation to lose, and killing
/// the domain before then would test the endpoint disappearing instead.
#[must_use]
pub fn owes_reply_in_domain(domain: u32) -> bool {
    let online = percpu::online_count() as usize;
    for queue in QUEUES.iter().take(online.min(MAX_CPUS)) {
        let Some(queue) = queue.try_lock() else {
            continue;
        };
        if queue
            .threads
            .iter()
            .flatten()
            .any(|thread| thread.domain == domain && thread.reply_to.is_some())
        {
            return true;
        }
    }
    false
}

/// How many times [`should_die`] could not read the runqueue and answered
/// "no" without knowing.
///
/// Not a failure on its own — most callers of `should_die` lose nothing by a
/// missed tear-down and will ask again. It is here because one caller does
/// lose something, and because a blind spot that is never counted is
/// indistinguishable from one that does not exist.
pub static DYING_UNKNOWN: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Whether the running thread has been told to stop.
///
/// Read at the points where a thread provably holds no kernel lock: on the way
/// back to user mode, and when it is about to sleep. Answers `false` if this
/// CPU's runqueue is contended, which is the safe direction for those callers
/// — the thread stays alive until the next safe point.
///
/// **"There is always another safe point" is what this comment used to say,
/// and it is not true of every caller.** `syscall::ask_adapter_counted` asks
/// this once, to tell a domain ending underneath a hosted thread apart from an
/// adapter that has died; there is no later point at which it asks again,
/// because the call it is deciding about has already failed. For that caller a
/// contended lock is not "stay alive a little longer", it is a wrong answer
/// recorded as a refusal. [`DYING_UNKNOWN`] counts how often the lock is lost
/// so the width of that window is measured rather than assumed.
#[must_use]
pub fn should_die() -> bool {
    let cpu = percpu::cpu_id() as usize;
    if cpu >= MAX_CPUS {
        return false;
    }
    let Some(queue) = QUEUES[cpu].try_lock() else {
        // **This answers "no" when it means "I do not know", and the two are
        // not the same answer.**
        //
        // Every caller reads `false` as *the current thread is not being
        // killed*, and one of them — `syscall::ask_adapter_counted` — uses it
        // to tell a teardown apart from a dead adapter. A lost `try_lock` there
        // turns a domain ending normally into a counted refusal, which is
        // exactly the line the `native` lane failed on for 2026-08-23's suite:
        // `1 were refused by its endpoint, 0 were for a caller already being
        // killed`. Contention is load-dependent, which is why it is rare and
        // why it arrives in a full suite rather than in a lane run alone.
        //
        // Counted rather than fixed here, because the fix is not to block: two
        // of the five callers are on trap and notify paths where taking this
        // lock is what `try_lock` was chosen to avoid. What the count answers
        // is whether the window is real and how wide, before anything is
        // built on the guess that it is.
        DYING_UNKNOWN.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        return false;
    };
    let current = queue.current;
    queue.threads[current]
        .as_ref()
        .is_some_and(|thread| thread.dying)
}

/// Whether `cpu` still needs a periodic interrupt to preempt with.
///
/// A tick exists to take the CPU *away* from a thread, which means nothing
/// when there is nothing to give it to. This is the whole tickless rule, and
/// it is deliberately a property of the runqueue rather than of the timer.
///
/// Answers `true` before the scheduler has started on that CPU: early boot
/// counts ticks to prove the timer works at all, and a CPU that stopped
/// ticking before it had a runqueue would look identical to a broken timer.
///
/// **`started` does double duty, and the second job is a sharp edge.**
/// [`stop_all`] clears the same flag to freeze the world for reporting, and
/// this reads that as "early boot" — so a frozen CPU arms a slice it has
/// nothing to preempt to, once per slice, indefinitely. Nothing that runs
/// while the scheduler is stopped may measure ticks, and nothing should stay
/// stopped for long; [`start_all`] belongs immediately after the freeze that
/// needed it. The tickless gate spent several milestones grading a machine in
/// exactly this state and reporting the result as a near-miss on a ratio.
#[must_use]
pub fn needs_preemption_tick(cpu: usize) -> bool {
    if cpu >= MAX_CPUS {
        return true;
    }
    // A deferred wake is retried from the tick and from nowhere else, so a CPU
    // holding one must keep ticking or it has undertaken to deliver something
    // and then gone to sleep. That is not a slow wake, it is a lost one: the
    // thread it was for is blocked, so the runqueue looks idle, so the tick
    // stops, so the retry never runs.
    //
    // Reachable whenever an interrupt handler's `try_lock` loses to the thread
    // it interrupted, which on one CPU is exactly when a waiter is deciding to
    // sleep. Measured as a single-processor boot that stopped dead after the
    // console's notification was signalled.
    if deferred_wakes_pending() {
        return true;
    }
    let Some(queue) = QUEUES[cpu].try_lock() else {
        // Contended: assume a tick is needed. Being wrong costs one interrupt;
        // being wrong the other way costs a CPU that stops scheduling.
        return true;
    };
    if !queue.started {
        return true;
    }
    queue.runnable() > 1
}

/// Why [`needs_preemption_tick`] answered as it did, for diagnostics.
///
/// Separate from the decision rather than folded into it: the decision runs in
/// an interrupt handler on every arm, and it should not carry a string.
#[must_use]
pub fn preemption_tick_reason(cpu: usize) -> (&'static str, usize) {
    if cpu >= MAX_CPUS {
        return ("cpu out of range", 0);
    }
    if deferred_wakes_pending() {
        return ("a deferred wake is pending", 0);
    }
    let Some(queue) = QUEUES[cpu].try_lock() else {
        return ("its runqueue was contended", 0);
    };
    if !queue.started {
        return ("its scheduler has not started", 0);
    }
    let runnable = queue.runnable();
    if runnable > 1 {
        ("it has more than one schedulable thread", runnable)
    } else {
        ("nothing -- it should be tickless", runnable)
    }
}

/// When the running thread's slice next expires on `cpu`, in TSC units.
///
/// A deadline already in the past is replaced with a fresh slice rather than
/// returned as-is. The timer is armed from inside the interrupt handler,
/// *before* the scheduler has renewed the quantum — so at every slice
/// boundary the stored deadline is momentarily stale, and arming for the
/// remaining zero nanoseconds asks the hardware to interrupt immediately.
///
/// That is not a rounding error, it is an interrupt storm: the measured tick
/// rate went from 400 a second to over thirty thousand, which is a machine
/// spending all its time in the timer handler.
#[must_use]
pub fn next_slice_deadline(cpu: usize, now: u64) -> Option<u64> {
    if cpu >= MAX_CPUS {
        return None;
    }
    let queue = QUEUES[cpu].try_lock()?;
    if queue.slice_deadline > now {
        return Some(queue.slice_deadline);
    }
    let current = queue.current;
    queue.threads[current]
        .as_ref()
        .map(|thread| now.saturating_add(thread.slice_ticks))
}

/// Reschedule interrupts sent to other CPUs.
#[must_use]
pub fn reschedule_ipis() -> u64 {
    RESCHEDULE_IPIS.load(Ordering::Relaxed)
}

/// Threads that went to sleep.
#[must_use]
pub fn blocks() -> u64 {
    BLOCKS.load(Ordering::Relaxed)
}

/// Threads woken from a sleep.
#[must_use]
pub fn wakeups() -> u64 {
    WAKEUPS.load(Ordering::Relaxed)
}

/// Sleeps abandoned because the wakeup arrived in the window.
#[must_use]
pub fn races() -> u64 {
    RACES.load(Ordering::Relaxed)
}

/// Applies `weight` to every fair thread of `domain`.
///
/// Called when a domain gains or loses a thread, because the share is divided
/// among its threads: leaving the others at their old weight would let a
/// domain take more CPU simply by spawning, which is the hole
/// `docs/scheduler.md` §3's two-level runqueue exists to close.
///
/// `also` names a thread that should be re-weighted even if its domain field
/// has not been set yet, for the window during creation. Pass `u32::MAX` for
/// none.
pub fn set_domain_weight(domain: u32, weight: u32, also: u32) {
    if domain == u32::MAX {
        return;
    }
    for queue in QUEUES.iter().take(percpu::online_count() as usize) {
        // Blocking, not `try_lock`. Skipping a contended queue leaves some of
        // a domain's threads at their old, larger weight -- and since the
        // threads being re-weighted are precisely the ones running on that
        // queue, contention is *likely* rather than rare. Measured: a domain
        // with three threads took twice the CPU of one with a single thread
        // instead of the same, because the skip left the share multiplied.
        //
        // Safe to block: the caller has already released the domain table's
        // lock, and every scheduler path that runs from an interrupt uses
        // `try_lock`, so nothing here can be waiting on this thread.
        let mut queue = queue.lock();
        for thread in queue.threads.iter_mut().flatten() {
            if (thread.domain == domain || thread.id == also)
                && let Policy::Fair { .. } = thread.policy
            {
                thread.domain = domain;
                thread.policy = Policy::Fair { weight };
                // Recompute the deadline against the new weight, or the thread
                // keeps competing on the old one until it next runs.
                thread.charge(0);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn thread(slot: usize, state: State, policy: Policy) -> Thread {
        Thread {
            id: slot as u32,
            name: "t",
            context: Context::new(),
            state,
            runs: 0,
            migrations: 0,
            held_locks: 0,
            held_count: 0,
            space_root: 0,
            fs_base: 0,
            fx: FxArea::initial(),
            reply_to: None,
            receive_slot: None,
            staged_gift: None,
            woken_at: 0,
            call_refused: None,
            dying: false,
            answer_lost: false,
            domain: u32::MAX,
            mailbox: None,
            kernel_stack_top: 0,
            pinned: slot == 0,
            policy,
            vruntime: 0,
            deadline: 0,
            slice_ticks: 1,
            cycles: 0,
            last_start: 0,
        }
    }

    /// A queue holding `states`, all fair, with slot 0 as the pinned thread
    /// every CPU has.
    fn with(states: &[State]) -> RunQueue {
        let mut queue = RunQueue::new();
        for (slot, state) in states.iter().enumerate() {
            queue.threads[slot] = Some(thread(slot, *state, Policy::fair()));
        }
        queue
    }

    /// The rule `mark_blocked` and `block_unless` share, on the structure they
    /// share, without needing a CPU to run it on.
    ///
    /// Both functions read a global runqueue array and a per-CPU id, so the
    /// live versions cannot be called here. What *can* be tested is the
    /// predicate they turn on, which is the part that was added and the part
    /// that can be wrong.
    /// **A dying caller and a vanished endpoint are different answers**, and
    /// this is the test that did not exist while they were the same one.
    ///
    /// `syscall::ask_adapter_counted` counts the first as teardown and the
    /// second as a refused delivery, and a boot gate demands the refusal count
    /// be zero. With both collapsed into `Abandoned`, the adapter recovered the
    /// difference by asking `should_die` afterwards -- which loses this CPU's
    /// runqueue lock sometimes and then answers "no" without knowing. On
    /// 2026-08-23 that turned a domain ending normally into
    /// `1 were refused by its endpoint` and failed the `native` lane.
    ///
    /// **Both `dying` rows matter.** A thread being killed is told so whether
    /// or not the endpoint it waited on is still live: the answer is about the
    /// caller, not about what it was waiting for. Collapsing the first row into
    /// `Blocked` would put a dying thread back to sleep, which is the bug
    /// RFC 0017 step 2 fixed; collapsing the second into `Abandoned` is the one
    /// that cost the boot gate.
    #[test]
    fn a_dying_caller_is_told_so_and_is_never_confused_with_a_vanished_endpoint() {
        assert_eq!(
            waited(true, || true),
            Waited::Dying,
            "a dying thread must not be told to block, even with the endpoint still there"
        );
        assert_eq!(
            waited(true, || false),
            Waited::Dying,
            "a dying thread and a vanished endpoint are the two facts that were one"
        );
        assert_eq!(waited(false, || true), Waited::Blocked);
        assert_eq!(
            waited(false, || false),
            Waited::Abandoned,
            "nothing to wait for, and this caller is fine -- the endpoint is not"
        );
    }

    #[test]
    fn a_dying_thread_is_not_marked_blocked() {
        let mut queue = with(&[State::Running]);
        queue.threads[0].as_mut().unwrap().dying = true;

        // The body of `mark_blocked`, with its guard.
        if let Some(thread) = queue.threads[0].as_mut()
            && !thread.dying
        {
            thread.state = State::Blocked;
        }

        assert_eq!(
            queue.threads[0].as_ref().unwrap().state,
            State::Running,
            "a thread told to stop must not go to sleep: sleeping is the one \
             state with no next safe point, so a dying thread that blocks \
             never dies"
        );
    }

    /// The same guard, the other way round, or the test above would pass with
    /// the marking deleted entirely.
    #[test]
    fn a_living_thread_is_still_marked_blocked() {
        let mut queue = with(&[State::Running]);

        if let Some(thread) = queue.threads[0].as_mut()
            && !thread.dying
        {
            thread.state = State::Blocked;
        }

        assert_eq!(queue.threads[0].as_ref().unwrap().state, State::Blocked);
    }

    /// The `FS` base reaches the register now only when the thread is here.
    ///
    /// The middle arm is the one that matters: it is the window the fix of
    /// 2026-08-29 left open, and it existed for a day as a branch nothing could
    /// reach in a test. `set_fs_base` scans global queues, so this is where the
    /// choice can be checked at all.
    #[test]
    fn a_base_is_loaded_here_only_for_a_thread_running_here() {
        assert_eq!(
            base_reach(Some(7), 7, 2, 2),
            BaseReach::LoadedHere,
            "the target is the current thread of this cpu's queue, so the \
             register this code can write is the right one"
        );
    }

    /// The counted window: current, but current *somewhere else*.
    #[test]
    fn a_base_set_for_a_thread_running_elsewhere_follows_at_its_next_switch() {
        assert_eq!(
            base_reach(Some(7), 7, 3, 0),
            BaseReach::FollowsAtNextSwitch,
            "writing IA32_FS_BASE here would put the value in this cpu's \
             register and leave the running thread's untouched -- which is \
             the bug fixed on 2026-08-29, not the one to reintroduce"
        );
    }

    /// Not current anywhere is the safe case, and must not be counted as the
    /// window: the thread cannot be in user mode, so its next switch-in loads
    /// the base before it runs.
    #[test]
    fn a_base_for_a_thread_that_is_not_running_is_not_the_window() {
        assert_eq!(base_reach(Some(9), 7, 0, 0), BaseReach::NotRunning);
        assert_eq!(base_reach(None, 7, 0, 0), BaseReach::NotRunning);
        assert_eq!(
            base_reach(Some(9), 7, 3, 0),
            BaseReach::NotRunning,
            "a different thread running on another cpu is not this thread \
             running on another cpu, and counting it would inflate the very \
             number the window is being judged by"
        );
    }

    /// A dying thread is still schedulable, which is the point of the flag
    /// being a flag.
    ///
    /// It has not stopped yet. Everything that reasons about runnability, load
    /// and eviction must keep seeing it as what it is until it does — that is
    /// the argument for not making `Dying` a fifth [`State`], and this is the
    /// property that argument rests on.
    #[test]
    fn dying_does_not_change_what_the_scheduler_sees() {
        let mut queue = with(&[State::Running, State::Ready]);
        let before = queue.runnable();
        queue.threads[1].as_mut().unwrap().dying = true;

        assert_eq!(
            queue.runnable(),
            before,
            "marking a thread dying must not change the load figure: it is \
             still running until it reaches a safe point, and a CPU that \
             stopped counting it would decline to preempt for it"
        );
        assert!(queue.threads[1].as_ref().unwrap().state.is_schedulable());
    }

    /// The order the delivery decision asks its questions in.
    ///
    /// `take_message_or_block` reads a global array and a per-CPU id, so the
    /// live function cannot run here. What is testable is the order, which is
    /// where the meaning is: a reply that arrived before its sender died is
    /// still a reply, and must win over the news that the sender has gone.
    #[test]
    fn a_delivered_reply_beats_a_lost_answer() {
        let mut queue = with(&[State::Blocked]);
        let thread = queue.threads[0].as_mut().unwrap();
        thread.answer_lost = true;
        thread.mailbox = Some((crate::ipc::Message::default(), 9));

        // The decision, in the order the live one asks it.
        let outcome = if thread.mailbox.take().is_some() {
            "message"
        } else if core::mem::take(&mut thread.answer_lost) {
            "revoked"
        } else {
            "blocked"
        };

        assert_eq!(
            outcome, "message",
            "a server that replied and then died has still replied: asking \
             about the loss first would throw away an answer that arrived"
        );
    }

    /// And with no reply waiting, the loss is reported rather than slept on.
    #[test]
    fn a_lost_answer_is_reported_not_slept_on() {
        let mut queue = with(&[State::Blocked]);
        let thread = queue.threads[0].as_mut().unwrap();
        thread.answer_lost = true;

        let outcome = if thread.mailbox.take().is_some() {
            "message"
        } else if core::mem::take(&mut thread.answer_lost) {
            "revoked"
        } else {
            "blocked"
        };

        assert_eq!(outcome, "revoked");
        assert!(
            !thread.answer_lost,
            "the flag is taken, not read: a caller told once and left marked \
             would refuse its next call for a reason that had already been \
             delivered"
        );
    }

    /// A queue built from explicit classes, every thread `Ready`.
    fn classes(policies: &[Policy]) -> RunQueue {
        let mut queue = RunQueue::new();
        for (slot, policy) in policies.iter().enumerate() {
            queue.threads[slot] = Some(thread(slot, State::Ready, *policy));
        }
        queue
    }

    const fn rt(priority: u8, policy: RtPolicy) -> Policy {
        Policy::RealTime {
            priority,
            policy,
            utilisation: 10,
        }
    }

    #[test]
    fn finished_threads_do_not_count_towards_load() {
        let queue = with(&[State::Running, State::Ready, State::Finished]);
        assert_eq!(queue.runnable(), 2);
    }

    #[test]
    fn the_thread_a_cpu_booted_on_is_never_stolen() {
        // Slot 0 is pinned and Ready -- the only tempting candidate. Taking it
        // would move a CPU's own boot stack to another processor, and leave a
        // secondary with nothing to run once its queue drained.
        let mut queue = with(&[State::Ready, State::Running, State::Ready, State::Ready]);
        queue.current = 1;
        assert_eq!(queue.steal_candidate(1), Some(2));
    }

    #[test]
    fn a_running_thread_is_never_stolen() {
        // Its context is not stale -- it is the stack the victim is on.
        let queue = with(&[State::Ready, State::Running, State::Running]);
        assert_eq!(queue.steal_candidate(0), None);
    }

    #[test]
    fn a_finished_thread_is_never_stolen() {
        let queue = with(&[State::Ready, State::Finished, State::Finished]);
        assert_eq!(queue.steal_candidate(0), None);
    }

    #[test]
    fn nothing_is_stolen_from_a_cpu_midway_through_a_switch() {
        // The `Ready` thread in slot 1 has been marked but not yet saved.
        let mut queue = with(&[State::Running, State::Ready, State::Ready, State::Ready]);
        assert!(queue.steal_candidate(1).is_some());
        queue.switching = true;
        assert_eq!(queue.steal_candidate(1), None);
    }

    #[test]
    fn a_steal_never_makes_the_imbalance_worse() {
        // Victim 2, thief 1. Moving one leaves 1 and 2 -- the same gap, the
        // other way round -- so the thread would migrate forever.
        let queue = with(&[State::Running, State::Ready]);
        assert_eq!(queue.runnable(), 2);
        assert_eq!(queue.steal_candidate(1), None);

        // Victim 3, thief 1. Moving one leaves 2 and 2, which is stable.
        let queue = with(&[State::Running, State::Ready, State::Ready]);
        assert_eq!(queue.steal_candidate(1), Some(1));
    }

    #[test]
    fn an_idle_cpu_takes_from_a_queue_of_three() {
        let queue = with(&[State::Running, State::Ready, State::Ready]);
        assert_eq!(queue.steal_candidate(0), Some(1));
    }

    /// Runs the real pick-and-charge loop and reports the service split.
    ///
    /// The boot test measures this on hardware, where the answer is entangled
    /// with interrupt timing and emulator jitter. This runs the same algorithm
    /// with time as an exact input, so a deviation is the algorithm's and
    /// nothing else's.
    fn simulate(weights: &[u32], slice: u64, rounds: usize) -> Vec<u64> {
        let mut queue = RunQueue::new();
        for (slot, weight) in weights.iter().enumerate() {
            let mut thread = thread(slot, State::Ready, Policy::Fair { weight: *weight });
            thread.slice_ticks = slice;
            thread.charge(0);
            queue.threads[slot] = Some(thread);
        }
        queue.current = 0;

        for _ in 0..rounds {
            let next = queue.pick_next(queue.current);
            queue.current = next;
            if let Some(thread) = queue.threads[next].as_mut() {
                thread.charge(slice);
            }
            queue.advance_min_vruntime();
        }

        weights
            .iter()
            .enumerate()
            .map(|(slot, _)| queue.threads[slot].as_ref().map_or(0, |t| t.cycles))
            .collect()
    }

    #[test]
    fn equal_weights_share_the_cpu_equally() {
        let service = simulate(&[1024, 1024], 1_000, 1_000);
        assert_eq!(service[0], service[1]);
    }

    #[test]
    fn three_to_one_weights_give_three_to_one_service() {
        // The headline claim of the fair class. Ten thousand rounds, so a
        // startup transient cannot account for a deviation.
        let service = simulate(&[3 * 1024, 1024], 1_000, 10_000);
        let ratio_tenths = service[0] * 10 / service[1].max(1);
        assert!(
            (29..=31).contains(&ratio_tenths),
            "expected 3.0x, got {}.{}x ({} vs {})",
            ratio_tenths / 10,
            ratio_tenths % 10,
            service[0],
            service[1]
        );
    }

    #[test]
    fn reaping_frees_finished_slots_but_never_the_running_one() {
        // A finished thread that is still `current` is executing inside
        // `exit` on its own stack, and the switch away from it will read its
        // context. Reaping it would be a use-after-free.
        let mut queue = with(&[State::Finished, State::Finished, State::Ready]);
        queue.current = 0;
        queue.reap_finished();
        assert!(queue.threads[0].is_some(), "the running thread stays");
        assert!(
            queue.threads[1].is_none(),
            "a quiescent finished thread goes"
        );
        assert!(queue.threads[2].is_some(), "a ready thread stays");
    }

    #[test]
    fn free_slot_finds_the_first_gap() {
        let mut queue = with(&[State::Running, State::Ready, State::Ready]);
        assert_eq!(queue.free_slot(), Some(3));
        queue.threads[1] = None;
        assert_eq!(queue.free_slot(), Some(1));
    }

    #[test]
    fn any_runnable_real_time_thread_beats_every_fair_one() {
        // Strict priority between classes, `docs/scheduler.md` §2. Not a
        // weighting -- there is no number of fair threads that outvotes one
        // RT thread.
        let queue = classes(&[Policy::fair(), Policy::fair(), rt(1, RtPolicy::RoundRobin)]);
        assert_eq!(queue.pick_next(0), 2);
        assert_eq!(queue.pick_next(1), 2);
    }

    #[test]
    fn the_highest_real_time_priority_wins() {
        let queue = classes(&[
            rt(10, RtPolicy::RoundRobin),
            rt(50, RtPolicy::RoundRobin),
            rt(30, RtPolicy::RoundRobin),
        ]);
        assert_eq!(queue.pick_next(0), 1);
        assert_eq!(queue.pick_next(2), 1);
    }

    #[test]
    fn fifo_keeps_the_cpu_against_an_equal_priority() {
        // The defining property of FIFO: it runs until it blocks or yields,
        // and a peer of the same priority does not take it away.
        let queue = classes(&[rt(20, RtPolicy::Fifo), rt(20, RtPolicy::Fifo)]);
        assert_eq!(queue.pick_next(0), 0);
        assert_eq!(queue.pick_next(1), 1);
    }

    #[test]
    fn fifo_still_yields_to_a_strictly_higher_priority() {
        // Otherwise "fixed priority" would not be fixed, and the latency
        // guarantee for the higher thread would be unbounded.
        let queue = classes(&[rt(20, RtPolicy::Fifo), rt(21, RtPolicy::Fifo)]);
        assert_eq!(queue.pick_next(0), 1);
    }

    #[test]
    fn round_robin_gives_way_to_an_equal_priority() {
        // The one thing that separates RR from FIFO.
        let queue = classes(&[rt(20, RtPolicy::RoundRobin), rt(20, RtPolicy::RoundRobin)]);
        assert_eq!(queue.pick_next(0), 1);
        assert_eq!(queue.pick_next(1), 0);
    }

    #[test]
    fn a_deadline_tie_rotates_rather_than_entrenching() {
        // Written to pin a suspicion from the captured boot hang -- two
        // fresh threads starving at a deadline tie -- and it refuted the
        // suspicion instead: `slots_from` starts one past `from`, so a tie
        // goes to the next thread in rotation and a fresh spawn tying the
        // runner is found first. The starvation in that hang was the
        // hold-count veto keeping the pick from running at all. The test
        // stays, because the rotation is now the documented alibi in the
        // place someone would next suspect.
        let mut queue = classes(&[Policy::fair(), Policy::fair()]);
        queue.threads[0].as_mut().unwrap().deadline = 100;
        queue.threads[0].as_mut().unwrap().runs = 7;
        queue.threads[1].as_mut().unwrap().deadline = 100;
        queue.threads[1].as_mut().unwrap().runs = 0;
        assert_eq!(queue.pick_next(0), 1, "a tie leaves the incumbent");

        // And symmetrically: from the other side, the tie comes back.
        assert_eq!(queue.pick_next(1), 0, "rotation, not entrenchment");
    }

    #[test]
    fn fair_picks_the_earliest_virtual_deadline() {
        let mut queue = classes(&[Policy::fair(), Policy::fair(), Policy::fair()]);
        queue.threads[0].as_mut().unwrap().deadline = 300;
        queue.threads[1].as_mut().unwrap().deadline = 100;
        queue.threads[2].as_mut().unwrap().deadline = 200;
        assert_eq!(queue.pick_next(0), 1);

        // Still slot 1 while it holds the earliest deadline -- the running
        // thread is not displaced merely for having run. Rotation comes from
        // the deadline advancing as it consumes service, not from position,
        // which is the difference between this and round-robin.
        assert_eq!(queue.pick_next(1), 1);

        queue.threads[1].as_mut().unwrap().deadline = 400;
        assert_eq!(queue.pick_next(1), 2);
    }

    #[test]
    fn a_shorter_slice_earns_an_earlier_deadline_at_equal_weight() {
        // This is what a virtual deadline buys over picking the smallest
        // vruntime: two threads with the same share, but the one asking for a
        // short slice is chosen first and so runs sooner and more often. It is
        // how a latency-sensitive thread declares itself instead of being
        // guessed at from its sleep pattern.
        let mut queue = classes(&[Policy::fair(), Policy::fair()]);
        for slot in 0..2 {
            let thread = queue.threads[slot].as_mut().unwrap();
            thread.vruntime = 1_000;
            thread.slice_ticks = if slot == 0 { 10_000 } else { 100 };
            thread.charge(0);
        }
        assert!(
            queue.threads[1].as_ref().unwrap().deadline
                < queue.threads[0].as_ref().unwrap().deadline
        );
        assert_eq!(queue.pick_next(0), 1);
    }

    #[test]
    fn weight_scales_virtual_time_inversely() {
        // Twice the weight must accrue vruntime half as fast, because that is
        // the entire mechanism by which it receives twice the CPU.
        let mut light = thread(1, State::Ready, Policy::Fair { weight: 1024 });
        let mut heavy = thread(2, State::Ready, Policy::Fair { weight: 2048 });
        light.charge(1_000);
        heavy.charge(1_000);
        assert_eq!(light.vruntime, 1_000);
        assert_eq!(heavy.vruntime, 500);
        assert_eq!(light.cycles, heavy.cycles, "real time charged is the same");
    }

    #[test]
    fn idle_runs_only_when_nothing_else_can() {
        let mut queue = classes(&[Policy::Idle, Policy::fair()]);
        assert_eq!(queue.pick_next(0), 1);
        queue.threads[1].as_mut().unwrap().state = State::Blocked;
        assert_eq!(
            queue.pick_next(0),
            0,
            "idle is the last resort, not the first"
        );
    }

    #[test]
    fn a_blocked_thread_is_never_picked_whatever_its_class() {
        // Including the highest real-time priority: blocked outranks class.
        let mut queue = classes(&[Policy::fair(), rt(99, RtPolicy::Fifo)]);
        queue.threads[1].as_mut().unwrap().state = State::Blocked;
        assert_eq!(queue.pick_next(0), 0);
    }

    #[test]
    fn real_time_threads_are_never_stolen() {
        // Admission control is per-CPU, so migrating an RT thread invalidates
        // the budget at both ends.
        let mut queue = classes(&[Policy::Idle, rt(50, RtPolicy::Fifo), rt(60, RtPolicy::Fifo)]);
        assert_eq!(queue.steal_candidate(0), None);
        queue.threads[2] = Some(thread(2, State::Ready, Policy::fair()));
        assert_eq!(
            queue.steal_candidate(0),
            Some(2),
            "a fair thread still moves"
        );
    }

    #[test]
    fn admitted_utilisation_sums_only_live_real_time_threads() {
        let mut queue = classes(&[
            Policy::fair(),
            rt(10, RtPolicy::Fifo),
            rt(20, RtPolicy::Fifo),
        ]);
        assert_eq!(queue.rt_utilisation(), 20);
        queue.threads[2].as_mut().unwrap().state = State::Finished;
        assert_eq!(
            queue.rt_utilisation(),
            10,
            "a finished thread releases its budget"
        );
    }

    #[test]
    fn the_virtual_clock_never_runs_backwards() {
        // The bug this exists to prevent: a thread that sleeps far more than
        // it runs keeps a low `vruntime`, and a floor taken as the live
        // minimum would follow it down -- handing it unbounded credit and
        // starving anything CPU-bound. Four such threads did exactly that.
        let mut queue = classes(&[Policy::fair(), Policy::fair()]);
        queue.threads[0].as_mut().unwrap().vruntime = 900;
        queue.threads[1].as_mut().unwrap().vruntime = 900;
        queue.advance_min_vruntime();
        assert_eq!(queue.min_vruntime, 900);

        // A sleeper rejoins with a stale, much lower virtual time.
        queue.threads[1].as_mut().unwrap().vruntime = 5;
        queue.advance_min_vruntime();
        assert_eq!(queue.min_vruntime, 900, "the floor must not follow it down");
    }

    #[test]
    fn a_thread_cannot_run_unboundedly_far_ahead() {
        // Without this bound a thread that ran alone is so far ahead in
        // virtual time that a group of short-lived threads never lets it run
        // again -- which is starvation that looks exactly like a hang.
        let mut queue = classes(&[Policy::fair(), Policy::fair()]);
        queue.threads[0].as_mut().unwrap().slice_ticks = 100;
        queue.threads[1].as_mut().unwrap().slice_ticks = 100;
        queue.threads[0].as_mut().unwrap().vruntime = 1_000_000;
        queue.threads[1].as_mut().unwrap().vruntime = 0;

        queue.advance_min_vruntime();

        let ceiling = 100 * MAX_VRUNTIME_LEAD_SLICES;
        assert_eq!(queue.min_vruntime, 0);
        assert_eq!(
            queue.threads[0].as_ref().unwrap().vruntime,
            ceiling,
            "the runaway thread is pulled back to the ceiling"
        );
        assert_eq!(
            queue.threads[1].as_ref().unwrap().vruntime,
            0,
            "a thread inside the bound is untouched"
        );
    }

    #[test]
    fn the_vruntime_floor_ignores_threads_that_cannot_run() {
        // The floor exists to stop a waking thread monopolising the CPU. Taking
        // it from a blocked thread would set it to that thread's stale value
        // and defeat the purpose.
        let mut queue = classes(&[Policy::fair(), Policy::fair()]);
        queue.threads[0].as_mut().unwrap().vruntime = 500;
        queue.threads[1].as_mut().unwrap().vruntime = 10;
        queue.threads[1].as_mut().unwrap().state = State::Blocked;
        assert_eq!(queue.min_fair_vruntime(), 500);
    }

    /// RFC 0022 step 1: a staged gift is one-shot, addressed, and replaceable.
    #[test]
    fn a_staged_gift_rides_one_call_to_one_endpoint() {
        let mut held = thread(0, State::Running, Policy::Fair { weight: 1 });
        let gift = StagedGift {
            from_slot: 3,
            rights: 0b11,
            badge: 7,
            endpoint: 42,
        };
        held.staged_gift = Some(gift);

        // Addressed: a call to a different endpoint must not consume it, and
        // the gift is still there for the call it was staged for.
        assert_eq!(held.take_gift_for(41), None);
        assert_eq!(held.staged_gift, Some(gift), "a mismatch must not consume");

        // One-shot: the matching call takes it, and takes it once.
        assert_eq!(held.take_gift_for(42), Some(gift));
        assert_eq!(held.take_gift_for(42), None, "a gift rides one call");
    }

    /// A second staging replaces the first — the `ARM` rule, restated.
    #[test]
    fn staging_again_replaces_rather_than_accumulating() {
        let mut held = thread(0, State::Running, Policy::Fair { weight: 1 });
        let first = StagedGift {
            from_slot: 3,
            rights: 0b11,
            badge: 7,
            endpoint: 42,
        };
        let second = StagedGift {
            from_slot: 5,
            rights: 0b01,
            badge: 7,
            endpoint: 42,
        };
        held.staged_gift = Some(first);
        held.staged_gift = Some(second);
        assert_eq!(
            held.take_gift_for(42),
            Some(second),
            "re-staging is how a caller says: this one instead"
        );
        assert_eq!(
            held.take_gift_for(42),
            None,
            "and the first is gone, not queued"
        );
    }
}
