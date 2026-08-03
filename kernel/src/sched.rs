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
//! # What is still missing
//!
//! - **No migration and no work stealing.** A thread runs on the CPU it was
//!   created on, forever. An idle CPU stays idle while another has a queue.
//!   `docs/scheduler.md` §5 describes the balancing this needs; none of it is
//!   here, and the fairness this does provide is only within one CPU.
//! - **No priorities, no fair class.** Still round-robin.
//! - **No blocking.** A thread is runnable or finished; there is no sleep and
//!   no wakeup, so "no lost wakeups" remains not merely unproven but
//!   inexpressible.

use core::sync::atomic::{AtomicU64, Ordering};

use bhaskix_arch::context::{Context, bhaskix_context_switch};
use bhaskix_arch::percpu::{self, MAX_CPUS};

use crate::stack;
use crate::sync::SpinLock;

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
}

/// One CPU's runqueue.
struct RunQueue {
    threads: [Option<Thread>; MAX_THREADS_PER_CPU],
    /// Index of the thread currently on this CPU.
    current: usize,
    /// Whether this CPU may preempt yet.
    started: bool,
}

impl RunQueue {
    const fn new() -> Self {
        Self {
            threads: [const { None }; MAX_THREADS_PER_CPU],
            current: 0,
            started: false,
        }
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
    [const { SpinLock::new(RunQueue::new()) }; MAX_CPUS];

/// Hands out globally unique thread identifiers and stack slots.
///
/// Stack slots must be unique across *all* CPUs, not just within one queue —
/// two CPUs allocating the same slot would give two threads the same stack,
/// which is the kind of corruption that presents as anything but its cause.
static NEXT_THREAD: AtomicU64 = AtomicU64::new(0);

/// Context switches performed, across every CPU.
static SWITCHES: AtomicU64 = AtomicU64::new(0);

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

    let mut queue = QUEUES[cpu].lock();
    queue.threads[0] = Some(Thread {
        id,
        name,
        context: Context::new(),
        state: State::Running,
        runs: 1,
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
    });
    Ok(id)
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
        let next = queue.next_runnable(current);
        if next == current {
            return;
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
        // SAFETY: both pointers address `Context` fields inside this CPU's own
        // static runqueue, which outlives every thread; `to` was prepared by
        // `spawn_on` or saved by a previous switch on this same CPU.
        // Interrupts are disabled -- this is only reached from an interrupt
        // gate or with them masked.
        unsafe { bhaskix_context_switch(from, to) };
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

/// Runs `f` for each live thread: `(cpu, id, name, state, runs)`.
pub fn for_each(mut f: impl FnMut(u32, u32, &'static str, State, u64)) {
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
            );
        }
    }
}
