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
    /// Whether this thread may never migrate.
    ///
    /// True for the thread each CPU registers for itself: it runs on the stack
    /// that CPU booted on, so "move it elsewhere" is not a meaningful request.
    pub pinned: bool,
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
        }
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
    } = options;
    if cpu as usize >= MAX_CPUS || cpu >= percpu::online_count() {
        return Err(SpawnError::NoSuchCpu(cpu));
    }

    // The slot is reserved under the lock, but the stack is allocated *outside*
    // it. Allocation needs the heap, and holding a runqueue lock across it
    // would order the two locks the opposite way round from every other path.
    let (slot, floor) = {
        let queue = QUEUES[cpu as usize].lock();

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

        let Some(slot) = (0..MAX_THREADS_PER_CPU).find(|&i| queue.threads[i].is_none()) else {
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

/// Real CPU ticks a thread has consumed, if it still exists.
///
/// Real, not virtual: proportional-share testing needs the time actually
/// spent, and `vruntime` is that number already divided by the weight the test
/// is trying to verify.
#[must_use]
pub fn cycles_of(id: u32) -> Option<u64> {
    for queue in QUEUES.iter().take(percpu::online_count() as usize) {
        let Some(queue) = queue.try_lock() else {
            continue;
        };
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
fn finish_switch() {
    let cpu = percpu::cpu_id() as usize;
    if cpu < MAX_CPUS {
        QUEUES[cpu].lock().switching = false;
    }
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
    if crate::sync::held_mask() != 0 {
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
        let Some(mut queue) = QUEUES[cpu].try_lock() else {
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
        queue.current = next;

        // Held locks travel with the thread, not the CPU. Saved for the
        // outgoing thread and installed for the incoming one, both under this
        // lock so the swap cannot be observed half-done.
        let incoming_locks = queue.threads[next].as_ref().map_or(0, |t| t.held_locks);
        if let Some(thread) = queue.threads[current].as_mut() {
            thread.held_locks = crate::sync::held_mask();
        }
        crate::sync::set_held_mask(incoming_locks);

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
    if cpu < MAX_CPUS {
        let mut queue = QUEUES[cpu].lock();
        let current = queue.current;
        if let Some(thread) = queue.threads[current].as_mut() {
            thread.state = State::Finished;
        }
    }
    loop {
        preempt();
        core::hint::spin_loop();
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

/// Marks the running thread blocked, without yielding.
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
    if let Some(thread) = queue.threads[current].as_mut() {
        thread.state = State::Blocked;
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
pub fn block_self() {
    let cpu = percpu::cpu_id() as usize;
    if cpu >= MAX_CPUS {
        return;
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
            let Some(mut queue) = QUEUES[cpu].try_lock() else {
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
                queue.current = next;

                let incoming_locks = queue.threads[next].as_ref().map_or(0, |t| t.held_locks);
                if let Some(thread) = queue.threads[current].as_mut() {
                    thread.held_locks = crate::sync::held_mask();
                }
                crate::sync::set_held_mask(incoming_locks);
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
                // never be delivered and this loop spins for ever.
                restore_interrupts(interrupts_were_enabled);
                core::hint::spin_loop();
                if interrupts_were_enabled {
                    // SAFETY: re-masking for the next pass, as at entry.
                    unsafe { cpu::disable_interrupts() };
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
    let online = percpu::online_count() as usize;
    for queue in QUEUES.iter().take(online.min(MAX_CPUS)) {
        // One queue lock at a time. Two would be two locks of the same rank,
        // which have no order relative to each other and could close a cycle.
        let mut queue = queue.lock();
        let floor = queue.min_vruntime;
        for thread in queue.threads.iter_mut().flatten() {
            if thread.id == id && thread.state == State::Blocked {
                thread.state = State::Ready;
                // A thread that has slept has a `vruntime` frozen far behind
                // the ones that stayed awake, and would monopolise the CPU
                // until it caught up. Advance it to the floor -- it keeps its
                // deadline advantage, which is what makes a woken interactive
                // thread run *soon*, without also being owed a backlog.
                if matches!(thread.policy, Policy::Fair { .. }) {
                    thread.vruntime = thread.vruntime.max(floor);
                    thread.charge(0);
                }
                WAKEUPS.fetch_add(1, Ordering::Relaxed);
                return true;
            }
        }
    }
    false
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
