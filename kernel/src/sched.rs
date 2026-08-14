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
        reply_to: None,
        receive_slot: None,
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
        reply_to: None,
        receive_slot: None,
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
    if cpu != percpu::cpu_id() {
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

/// Records that `thread` owes `caller` an answer.
///
/// Called when a message is taken, so that [`take_reply_target`] can say who a
/// reply may go to without the replying thread being asked.
pub fn set_reply_target(thread: u32, caller: u32) {
    for queue in QUEUES.iter().take(percpu::online_count() as usize) {
        let mut queue = queue.lock();
        if let Some(target) = queue.threads.iter_mut().flatten().find(|t| t.id == thread) {
            target.reply_to = Some(caller);
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
            return target.reply_to.take();
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
            // A thread told to stop must not go back to sleep here.
            //
            // This is the third place that decides to block, and it was missed
            // when the other two learned the rule: it writes `State::Blocked`
            // directly rather than going through `mark_blocked`. A dying thread
            // waiting on an endpoint would be woken, find nothing, block again,
            // and never reach a safe point -- so RFC 0017 step 2 stopped every
            // thread except the ones that were asleep in IPC, which is most of
            // the interesting ones.
            if target.dying {
                target.state = State::Running;
                return Delivery::Abandoned;
            }
            if still_waiting() {
                target.state = State::Blocked;
                return Delivery::Blocked;
            }
            target.state = State::Running;
            return Delivery::Abandoned;
        }
    }
    Delivery::Abandoned
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
    /// The thread that owed this answer has died. The thread is running and
    /// should report that, distinctly: "the endpoint you called does not exist"
    /// and "the program you called has gone" are different facts, and a caller
    /// that retried the first would be right to and the second would not.
    Revoked,
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
    let cpu = percpu::cpu_id() as usize;
    if cpu >= MAX_CPUS {
        return;
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
    // `exit` reaches `domain_of_raw` and `threads_in_domain_except` with
    // interrupts enabled, and both `try_lock` every runqueue there is. A tick
    // landing in that scan could take the exiting thread off its CPU still
    // holding a *remote* runqueue, which nothing would then release.
    //
    // **This was expected to end the bring-up stall and did not**: 3 boots in
    // 500 with it against 4 in 500 without, and one of those arrived with the
    // very signature it should have made impossible. Kept because descheduling
    // a lock holder is wrong regardless, and left uncommented-out so nobody
    // rediscovers the unsoundness and assumes it was the fault all along.
    if crate::sync::holds_any() {
        return;
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
            restore_interrupts(interrupts_were_enabled);
            return;
        };
        if !queue.started {
            restore_interrupts(interrupts_were_enabled);
            return;
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
                    return;
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
        // that keeps lock holders on their CPU cannot see one, and
        // `domain_of_raw` and `threads_in_domain_except` -- both reached from
        // `exit`, with interrupts enabled -- `try_lock` every runqueue there
        // is, remote ones included.
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
        if let Some(thread) = queue.threads[current].as_mut() {
            thread.held_locks = crate::sync::held_mask();
            thread.held_count = crate::sync::holds_count();
            if thread.held_locks != 0 {
                note_saved_holding(thread.id, thread.name, thread.held_locks, "preempt");
            }
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
            restore_interrupts(interrupts_were_enabled);
            return;
        };
        let Some(to) = queue.threads[next]
            .as_ref()
            .map(|thread| &raw const thread.context)
        else {
            restore_interrupts(interrupts_were_enabled);
            return;
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
    // Taken under the same lock that marks this thread finished, so there is no
    // window in which the thread is gone and the debt is still recorded.
    // Ending the domain happens **before** this thread is marked `Finished`,
    // and that ordering is the whole of a bug that cost an evening.
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
    let me = current_thread_id();
    if let Some(thread) = me
        && let Some(domain) = domain_of_raw(thread)
        && threads_in_domain_except(domain, thread) == 0
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

    let owed = if cpu < MAX_CPUS {
        let mut queue = QUEUES[cpu].lock();
        let current = queue.current;
        queue.threads[current].as_mut().and_then(|thread| {
            thread.state = State::Finished;
            thread.reply_to.take()
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

/// The identifier of the thread running on this CPU.
///
/// `None` before this CPU has a runqueue.
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
pub fn block_unless<T>(ready: impl FnOnce() -> Option<T>) -> Option<T> {
    let cpu = percpu::cpu_id() as usize;
    if cpu >= MAX_CPUS {
        return ready();
    }
    let mut queue = QUEUES[cpu].lock();
    let taken = ready();
    if taken.is_none() {
        let current = queue.current;
        if let Some(thread) = queue.threads[current].as_mut()
            && !thread.dying
        {
            thread.state = State::Blocked;
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
pub fn mark_blocked() {
    let cpu = percpu::cpu_id() as usize;
    if cpu >= MAX_CPUS {
        return;
    }
    let mut queue = QUEUES[cpu].lock();
    let current = queue.current;
    if let Some(thread) = queue.threads[current].as_mut()
        && !thread.dying
    {
        thread.state = State::Blocked;
    }
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
    if crate::sync::held_mask() != 0 || crate::sync::holds_any() {
        BLOCKED_HOLDING.fetch_add(1, Ordering::Relaxed);
        let site = core::panic::Location::caller();
        crate::println!(
            "    BLOCK HOLDING  a thread blocked holding locks (mask {:#08b}, {} held), at {}:{}",
            crate::sync::held_mask(),
            crate::sync::holds_count(),
            site.file(),
            site.line()
        );
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

                let incoming_locks = queue.threads[next].as_ref().map_or(0, |t| t.held_locks);
                let incoming_count = queue.threads[next].as_ref().map_or(0, |t| t.held_count);
                if let Some(thread) = queue.threads[current].as_mut() {
                    thread.held_locks = crate::sync::held_mask();
                    thread.held_count = crate::sync::holds_count();
                    if thread.held_locks != 0 {
                        note_saved_holding(thread.id, thread.name, thread.held_locks, "block_self");
                    }
                }
                crate::sync::set_held_mask(incoming_locks);
                crate::sync::set_holds_count(incoming_count);
                queue.switching = true;

                let Some(from) = queue.threads[current]
                    .as_mut()
                    .map(|thread| &raw mut thread.context)
                else {
                    restore_interrupts(interrupts_were_enabled);
                    return;
                };
                let Some(to) = queue.threads[next]
                    .as_ref()
                    .map(|thread| &raw const thread.context)
                else {
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
            return WakeResult::Woken;
        }
    }

    if contended {
        WakeResult::Contended
    } else {
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
    let mut asleep = [0u32; MAX_CPUS * 4];
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
            if thread.state == State::Blocked
                && let Some(slot) = asleep.get_mut(waiting)
            {
                *slot = thread.id;
                waiting += 1;
            }
        }
    }

    // Outside every queue lock, for the reason above.
    for id in asleep.iter().take(waiting) {
        let _ = wake(*id);
    }
    marked
}

/// The domain a thread belongs to, read straight from the runqueues.
fn domain_of_raw(thread: u32) -> Option<u32> {
    let online = percpu::online_count() as usize;
    for queue in QUEUES.iter().take(online.min(MAX_CPUS)) {
        let Some(queue) = queue.try_lock() else {
            continue;
        };
        if let Some(target) = queue.threads.iter().flatten().find(|t| t.id == thread) {
            return (target.domain != u32::MAX).then_some(target.domain);
        }
    }
    None
}

/// How many threads of `domain` there are, not counting `except`.
///
/// The exclusion is what lets a thread ask "am I the last?" *before* marking
/// itself finished — which it must, because what it does with the answer takes
/// locks, and a finished thread may not queue for one.
#[must_use]
pub fn threads_in_domain_except(domain: u32, except: u32) -> usize {
    let online = percpu::online_count() as usize;
    let mut total = 0;
    for queue in QUEUES.iter().take(online.min(MAX_CPUS)) {
        let Some(queue) = queue.try_lock() else {
            continue;
        };
        total += queue
            .threads
            .iter()
            .flatten()
            .filter(|thread| {
                thread.domain == domain && thread.state != State::Finished && thread.id != except
            })
            .count();
    }
    total
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

/// Whether the running thread has been told to stop.
///
/// Read at the points where a thread provably holds no kernel lock: on the way
/// back to user mode, and when it is about to sleep. Answers `false` if this
/// CPU's runqueue is contended, which is the safe direction — the thread stays
/// alive until the next safe point, and there is always another one.
#[must_use]
pub fn should_die() -> bool {
    let cpu = percpu::cpu_id() as usize;
    if cpu >= MAX_CPUS {
        return false;
    }
    let Some(queue) = QUEUES[cpu].try_lock() else {
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
            reply_to: None,
            receive_slot: None,
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
}
