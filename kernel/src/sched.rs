// SPDX-License-Identifier: Apache-2.0
//! Threads and the scheduler.
//!
//! The first piece of `docs/scheduler.md`. What exists here is deliberately
//! the smallest thing that is genuinely a scheduler: real kernel threads, each
//! with its own guarded stack, preempted by the timer interrupt.
//!
//! # What this is not, yet
//!
//! `docs/scheduler.md` specifies per-CPU runqueues, a virtual-deadline fair
//! class, a fixed-priority RT class with admission control, and work stealing.
//! None of that is here. This is **round-robin over one runqueue**, and saying
//! so plainly is more useful than implying otherwise:
//!
//! - **No priorities and no fairness weighting.** Every thread gets the same
//!   slice. The two-level domain/thread structure that makes a container's
//!   share independent of its thread count is M5 work, since domains do not
//!   exist yet.
//! - **One CPU.** Per-CPU runqueues, load balancing, and work stealing all
//!   need a second CPU to be meaningful, and SMP bring-up is still ahead.
//! - **No sleeping or blocking.** A thread is runnable or it is finished.
//!   Wait queues arrive with IPC in M5.
//! - **Fixed thread capacity.** Threads live in a static array rather than a
//!   heap-allocated list, because the switch path must not allocate: a
//!   scheduler that can fail to schedule under memory pressure is not a
//!   scheduler.

use core::sync::atomic::{AtomicU64, Ordering};

use bhaskix_arch::context::{Context, bhaskix_context_switch};

use crate::stack;
use crate::sync::SpinLock;

/// Maximum threads. Small on purpose — see the module note on allocation.
pub const MAX_THREADS: usize = 16;

/// Stack slot index reserved for the boot thread, which already has one.
const BOOT_STACK_SLOT: u64 = 0;

/// What a thread is doing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// Waiting for a turn.
    Ready,
    /// Currently on the CPU.
    Running,
    /// Returned or was stopped; never scheduled again.
    Finished,
}

/// One kernel thread.
pub struct Thread {
    /// Identifier, and index into the thread table.
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

/// The scheduler's state.
struct Scheduler {
    threads: [Option<Thread>; MAX_THREADS],
    /// Index of the running thread.
    current: usize,
    /// Whether preemption is permitted yet.
    started: bool,
}

impl Scheduler {
    const fn new() -> Self {
        Self {
            threads: [const { None }; MAX_THREADS],
            current: 0,
            started: false,
        }
    }

    /// Next runnable thread after `from`, round-robin. Returns `from` if it is
    /// the only candidate.
    fn next_runnable(&self, from: usize) -> usize {
        for offset in 1..=MAX_THREADS {
            let candidate = (from + offset) % MAX_THREADS;
            if let Some(thread) = &self.threads[candidate]
                && thread.state != State::Finished
            {
                return candidate;
            }
        }
        from
    }
}

static SCHEDULER: SpinLock<Scheduler> = SpinLock::new(Scheduler::new());

/// Context switches performed, for reporting.
static SWITCHES: AtomicU64 = AtomicU64::new(0);

/// Why a thread could not be created.
#[derive(Clone, Copy, Debug)]
pub enum SpawnError {
    /// The thread table is full.
    TableFull,
    /// A guarded stack could not be allocated.
    NoStack(crate::vm::VmError),
}

/// Registers the currently executing code as the boot thread.
///
/// Without this the scheduler has nowhere to save the boot context on its
/// first switch, and the thread that brought the machine up would be lost the
/// moment anything else ran.
pub fn init_boot_thread(name: &'static str) {
    let mut scheduler = SCHEDULER.lock();
    scheduler.threads[0] = Some(Thread {
        id: 0,
        name,
        context: Context::new(),
        state: State::Running,
        runs: 1,
    });
    scheduler.current = 0;
}

/// Creates a thread that will run `entry(argument)`.
///
/// # Errors
///
/// [`SpawnError`] if the table is full or no stack could be allocated.
pub fn spawn(
    name: &'static str,
    entry: extern "C" fn(u64) -> !,
    argument: u64,
    hhdm_base: u64,
) -> Result<u32, SpawnError> {
    // The stack is allocated *before* the lock is taken. Allocation needs the
    // heap, and holding the scheduler lock across it would invert the lock
    // order against every other path -- the classic way to build a deadlock
    // that only appears under load.
    let slot = {
        let scheduler = SCHEDULER.lock();
        let Some(slot) = (0..MAX_THREADS).find(|&i| scheduler.threads[i].is_none()) else {
            return Err(SpawnError::TableFull);
        };
        slot
    };

    // SAFETY: single CPU during bring-up, and nothing else is modifying page
    // tables. Stack slot 0 belongs to the boot thread, so thread slots are
    // offset past it and no two threads can share a stack.
    let guarded = unsafe { stack::allocate(hhdm_base, BOOT_STACK_SLOT + 1 + slot as u64) }
        .map_err(SpawnError::NoStack)?;

    let mut context = Context::new();
    // SAFETY: `guarded.top` is one past a freshly mapped, page-aligned stack
    // with far more than eight quadwords of room, and `entry` is typed as
    // diverging so it cannot return.
    unsafe { context.prepare(guarded.top, entry, argument) };

    let mut scheduler = SCHEDULER.lock();
    scheduler.threads[slot] = Some(Thread {
        id: slot as u32,
        name,
        context,
        state: State::Ready,
        runs: 0,
    });
    Ok(slot as u32)
}

/// Allows the timer to start preempting.
///
/// Kept separate from [`init_boot_thread`] so that spawning can happen with
/// preemption still off — a half-built thread table being scheduled from is
/// not a situation worth handling.
pub fn start() {
    SCHEDULER.lock().started = true;
}

/// Stops preemption. Used before shutting down so the reporting that follows
/// is not interleaved with other threads' output.
pub fn stop() {
    SCHEDULER.lock().started = false;
}

/// Switches to the next runnable thread, if there is one.
///
/// Called from the timer interrupt and from [`yield_now`].
pub fn preempt() {
    // The lock is acquired, the decision made, and the lock *released* before
    // the switch. It has to be: the incoming thread will eventually return
    // from its own call to this function and try to take the same lock, and
    // holding it across the switch would deadlock the moment two threads exist.
    //
    // `try_lock`, not `lock`, because this is reachable from an interrupt that
    // may have landed inside a scheduler critical section. Skipping a
    // preemption is harmless; spinning for a lock the interrupted code holds
    // is not.
    let switch = {
        let Some(mut scheduler) = SCHEDULER.try_lock() else {
            return;
        };
        if !scheduler.started {
            return;
        }

        let current = scheduler.current;
        let next = scheduler.next_runnable(current);
        if next == current {
            return;
        }

        if let Some(thread) = scheduler.threads[current].as_mut()
            && thread.state == State::Running
        {
            thread.state = State::Ready;
        }
        if let Some(thread) = scheduler.threads[next].as_mut() {
            thread.state = State::Running;
            thread.runs += 1;
        }
        scheduler.current = next;

        // Raw pointers to the two contexts. Taken one at a time so each borrow
        // ends before the next begins, which is what lets both exist at once.
        //
        // They stay valid across the switch because the thread table is a
        // `static` that never moves or reallocates. That, and the assumption
        // that only one CPU is in here, are exactly what the SMP work will
        // have to revisit.
        let Some(from) = scheduler.threads[current]
            .as_mut()
            .map(|thread| &raw mut thread.context)
        else {
            return;
        };
        let Some(to) = scheduler.threads[next]
            .as_ref()
            .map(|thread| &raw const thread.context)
        else {
            return;
        };
        Some((from, to))
    };

    if let Some((from, to)) = switch {
        SWITCHES.fetch_add(1, Ordering::Relaxed);
        // SAFETY: both pointers address `Context` fields inside the static
        // thread table, which outlives every thread; `to` was either prepared
        // by `spawn` or saved by a previous switch. Interrupts are disabled --
        // this is only reached from an interrupt gate or with them masked.
        unsafe { bhaskix_context_switch(from, to) };
    }
}

/// Gives up the rest of this thread's slice.
pub fn yield_now() {
    preempt();
}

/// Marks the running thread finished and never returns.
pub fn exit() -> ! {
    {
        let mut scheduler = SCHEDULER.lock();
        let current = scheduler.current;
        if let Some(thread) = scheduler.threads[current].as_mut() {
            thread.state = State::Finished;
        }
    }
    loop {
        preempt();
        core::hint::spin_loop();
    }
}

/// Total context switches performed.
#[must_use]
pub fn switches() -> u64 {
    SWITCHES.load(Ordering::Relaxed)
}

/// Runs `f` for each live thread: `(id, name, state, runs)`.
pub fn for_each(mut f: impl FnMut(u32, &'static str, State, u64)) {
    let scheduler = SCHEDULER.lock();
    for slot in scheduler.threads.iter().flatten() {
        f(slot.id, slot.name, slot.state, slot.runs);
    }
}
