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
use bhaskix_arch::percpu::{self, MAX_CPUS};

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
    /// Finished; never scheduled again.
    Finished,
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
}

/// One CPU's runqueue.
struct RunQueue {
    threads: [Option<Thread>; MAX_THREADS_PER_CPU],
    /// Index of the thread currently on this CPU.
    current: usize,
    /// Whether this CPU may preempt yet.
    started: bool,
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
            switching: false,
        }
    }

    /// Threads on this queue that could run: the load figure balancing uses.
    fn runnable(&self) -> usize {
        self.threads
            .iter()
            .flatten()
            .filter(|thread| thread.state != State::Finished)
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
            })
        })
    }

    /// First unused slot.
    fn free_slot(&self) -> Option<usize> {
        self.threads.iter().position(Option::is_none)
    }

    /// Next runnable thread after `from`, round-robin within this CPU.
    fn next_runnable(&self, from: usize) -> usize {
        for offset in 1..=MAX_THREADS_PER_CPU {
            let candidate = (from + offset) % MAX_THREADS_PER_CPU;
            if let Some(thread) = &self.threads[candidate]
                && thread.state != State::Finished
            {
                return candidate;
            }
        }
        from
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
}

/// Registers the calling CPU's current execution as its first thread.
///
/// Every CPU needs this before it can be preempted: without an entry there is
/// nowhere to save the context of whatever is already running, and the first
/// switch would lose it.
pub fn init_cpu(name: &'static str) {
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
        // This thread *is* the CPU's boot context, executing on the stack the
        // bootloader handed it. Migrating it would move a stack out from under
        // the processor standing on it.
        pinned: true,
    });
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
    if cpu as usize >= MAX_CPUS || cpu >= percpu::online_count() {
        return Err(SpawnError::NoSuchCpu(cpu));
    }

    // The slot is reserved under the lock, but the stack is allocated *outside*
    // it. Allocation needs the heap, and holding a runqueue lock across it
    // would order the two locks the opposite way round from every other path.
    let slot = {
        let queue = QUEUES[cpu as usize].lock();
        let Some(slot) = (0..MAX_THREADS_PER_CPU).find(|&i| queue.threads[i].is_none()) else {
            return Err(SpawnError::QueueFull(cpu));
        };
        slot
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
        pinned: false,
    });
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
            return;
        };
        if !queue.started {
            return;
        }

        let current = queue.current;
        let mut next = queue.next_runnable(current);
        if next == current {
            // Nothing else here to run. This is the cheapest moment to
            // balance and the only one implemented: the CPU is about to have
            // no work, so anything it takes costs nothing to run.
            // `docs/scheduler.md` §5 calls this the idle pull.
            match try_steal(cpu, &mut queue) {
                Some(stolen) => next = stolen,
                None => return,
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
            return;
        };
        let Some(to) = queue.threads[next]
            .as_ref()
            .map(|thread| &raw const thread.context)
        else {
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
}

/// Gives up the rest of this thread's slice.
pub fn yield_now() {
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

/// Runs `f` for each live thread: `(cpu, id, name, state, runs, migrations)`.
pub fn for_each(mut f: impl FnMut(u32, u32, &'static str, State, u64, u64)) {
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
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A queue holding `states`, none pinned, with slot 0 as the pinned thread
    /// every CPU has.
    fn with(states: &[State]) -> RunQueue {
        let mut queue = RunQueue::new();
        for (slot, state) in states.iter().enumerate() {
            queue.threads[slot] = Some(Thread {
                id: slot as u32,
                name: "t",
                context: Context::new(),
                state: *state,
                runs: 0,
                migrations: 0,
                held_locks: 0,
                pinned: slot == 0,
            });
        }
        queue
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
}
