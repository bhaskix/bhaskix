// SPDX-License-Identifier: Apache-2.0
//! Monotonic time, per-CPU timers, and sleeping.
//!
//! Implements the timer half of `docs/scheduler.md` §7.
//!
//! # Why the tick is not a clock
//!
//! Until now the only notion of time in the kernel was a count of timer
//! interrupts. That works exactly as long as the timer interrupts on a fixed
//! schedule — and the whole point of this module is that it stops doing so. A
//! tickless CPU does not tick, so anything measuring duration in ticks
//! measures nothing at all once that CPU goes idle.
//!
//! Time therefore comes from the TSC, which advances whether or not anyone is
//! being interrupted. The tick count remains, and remains useful, but it now
//! means "timer interrupts delivered" rather than "time elapsed", and the two
//! are no longer the same number.
//!
//! # Why one-shot rather than periodic
//!
//! A periodic timer interrupts on a schedule chosen once at boot, which is
//! wrong in both directions: too often for a CPU with nothing to do, and at
//! the wrong moments for a timer that needs to fire between ticks. A one-shot
//! timer is re-armed after every interrupt for exactly as long as the next
//! thing that needs attention — and when nothing does, it is not armed at all.
//!
//! That is the entire mechanism. Ticklessness is not a separate feature layered
//! on top; it is what a one-shot timer does when asked for nothing.
//!
//! # What is deliberately not here
//!
//! - **No hierarchical timer wheel.** `docs/scheduler.md` §7 wants one for the
//!   many-short-timers case, which is a network stack's profile. There is no
//!   network stack, so a wheel would be a data structure with no workload to
//!   justify its shape. What exists is the few-precise-timers case: a small
//!   per-CPU array, scanned linearly. At [`MAX_TIMERS`] entries a scan beats a
//!   heap and allocates nothing, which the interrupt path requires.
//! - **No TSC-deadline mode.** The APIC one-shot counter is enough to be
//!   tickless. TSC-deadline removes a divide and a write from the arming path,
//!   which matters when arming is frequent and nothing measures it yet.
//! - **No cross-socket TSC synchronisation check.** Every reading here is
//!   compared only against another reading from the same CPU. That assumption
//!   must be revisited before any timestamp crosses a CPU boundary.
//! - **No `CLOCK_REALTIME`.** There is no RTC driver and no notion of wall
//!   time; this is monotonic-since-boot only.

use core::sync::atomic::{AtomicU64, Ordering};

use bhaskix_arch::percpu::{self, MAX_CPUS};
use bhaskix_arch::tsc;

use crate::sync::{Rank, SpinLock};

/// Timers one CPU can have outstanding.
///
/// Small on purpose: arming happens in the interrupt path, which must not
/// allocate. A queue that fills refuses rather than growing.
pub const MAX_TIMERS: usize = 16;

/// Longest a CPU is left un-armed when it has nothing else to wait for.
///
/// Strictly, a CPU with no runnable thread and no timer needs no interrupt at
/// all — an inter-processor interrupt will wake it when something changes.
/// This backstop exists because "strictly" is doing a lot of work in that
/// sentence: it assumes every path that makes a thread runnable remembers to
/// send that IPI, for ever, including paths not yet written. A CPU that wakes
/// once a second regardless costs almost nothing and converts "lost thread" —
/// the worst failure this design can have, and a silent one — into "that
/// thread ran a bit late".
pub const IDLE_BACKSTOP_MS: u64 = 1_000;

/// A pending timer: when it expires and which thread to wake.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Timer {
    /// TSC value at which this expires.
    deadline: u64,
    /// Thread to make runnable. Globally unique, so it cannot go stale the way
    /// a CPU index would.
    thread: u32,
}

struct Timers {
    entries: [Option<Timer>; MAX_TIMERS],
    /// Timers refused because the array was full.
    overflowed: u64,
}

impl Timers {
    const fn new() -> Self {
        Self {
            entries: [const { None }; MAX_TIMERS],
            overflowed: 0,
        }
    }

    fn insert(&mut self, timer: Timer) -> bool {
        match self.entries.iter().position(Option::is_none) {
            Some(slot) => {
                self.entries[slot] = Some(timer);
                true
            }
            None => {
                self.overflowed += 1;
                false
            }
        }
    }

    fn remove(&mut self, thread: u32) {
        for entry in &mut self.entries {
            if entry.is_some_and(|timer| timer.thread == thread) {
                *entry = None;
            }
        }
    }

    /// Soonest deadline outstanding, if any.
    fn earliest(&self) -> Option<u64> {
        self.entries
            .iter()
            .flatten()
            .map(|timer| timer.deadline)
            .min()
    }

    /// Removes and returns every timer due at or before `now`.
    ///
    /// Returns how many were written into `expired`.
    fn take_expired(&mut self, now: u64, expired: &mut [u32; MAX_TIMERS]) -> usize {
        let mut count = 0;
        for entry in &mut self.entries {
            if entry.is_some_and(|timer| timer.deadline <= now)
                && let Some(timer) = entry.take()
            {
                expired[count] = timer.thread;
                count += 1;
            }
        }
        count
    }
}

static TIMERS: [SpinLock<Timers>; MAX_CPUS] =
    [const { SpinLock::new(Rank::Timers, Timers::new()) }; MAX_CPUS];

/// Timer interrupts that were not armed because the CPU had nothing to wait
/// for. The measure of how much work ticklessness avoided.
static TICKLESS_IDLES: AtomicU64 = AtomicU64::new(0);

/// Times the timer was armed for a real deadline rather than a fixed period.
static ARMED: AtomicU64 = AtomicU64::new(0);

/// The absolute TSC deadline each CPU's timer is currently programmed for.
///
/// Zero means "not known" — either nothing has programmed it yet, or it was
/// armed through [`arm_default`], which runs when there is no calibrated clock
/// to express a deadline in.
///
/// Written only by the CPU it belongs to, and only with interrupts masked or
/// from the timer interrupt itself, so a read on that CPU cannot see a half of
/// it. It exists so [`arm_no_later_than`] can tell whether it has anything to
/// do: without it, every arming would re-program the timer, and a program
/// arming a deadline further away than the next tick would push that tick out.
static PROGRAMMED: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];

/// Times [`arm_no_later_than`] moved a CPU's timer earlier.
static HASTENED: AtomicU64 = AtomicU64::new(0);

/// Times it was asked and the timer was already going to fire in time.
static ALREADY_SOON_ENOUGH: AtomicU64 = AtomicU64::new(0);

/// Why each CPU last armed its timer, counted per reason.
///
/// `[slice, timer, backstop]`. A CPU that will not go tickless is arming for
/// *something*, and the difference between "a thread to preempt" and "a
/// registered timer" is the difference between a scheduler question and a
/// timer question. Without this the only observable is that the CPU still
/// ticks, which is a symptom shared by every possible cause.
static ARM_REASONS: [[AtomicU64; 3]; MAX_CPUS] =
    [const { [const { AtomicU64::new(0) }; 3] }; MAX_CPUS];

/// Why `cpu` has been arming its timer: `(slice, timer, backstop)`.
#[must_use]
pub fn arm_reasons(cpu: u32) -> (u64, u64, u64) {
    usize::try_from(cpu)
        .ok()
        .and_then(|cpu| ARM_REASONS.get(cpu))
        .map_or((0, 0, 0), |reasons| {
            (
                reasons[0].load(Ordering::Relaxed),
                reasons[1].load(Ordering::Relaxed),
                reasons[2].load(Ordering::Relaxed),
            )
        })
}

/// Monotonic time since boot, in TSC units.
#[must_use]
pub fn now() -> u64 {
    tsc::read()
}

/// Monotonic time since boot in nanoseconds, or `None` without a calibrated
/// TSC.
#[must_use]
pub fn now_nanos() -> Option<u64> {
    tsc::to_nanos(tsc::read())
}

/// Converts a duration in microseconds to TSC units.
#[must_use]
pub fn micros(micros: u64) -> Option<u64> {
    tsc::from_micros(micros)
}

/// How many timer interrupts were skipped because a CPU had nothing to wait
/// for.
#[must_use]
pub fn tickless_idles() -> u64 {
    TICKLESS_IDLES.load(Ordering::Relaxed)
}

/// How many times the timer was armed for a computed deadline.
#[must_use]
pub fn armed() -> u64 {
    ARMED.load(Ordering::Relaxed)
}

/// Timers refused because a CPU's array was full.
#[must_use]
pub fn overflowed() -> u64 {
    let mut total = 0;
    for timers in TIMERS.iter().take(percpu::online_count() as usize) {
        if let Some(timers) = timers.try_lock() {
            total += timers.overflowed;
        }
    }
    total
}

/// Registers a timer that will wake `thread` on this CPU at `deadline`.
///
/// Returns whether it was accepted.
fn arm_for(thread: u32, deadline: u64) -> bool {
    let cpu = percpu::cpu_id() as usize;
    if cpu >= MAX_CPUS {
        return false;
    }
    TIMERS[cpu].lock().insert(Timer { deadline, thread })
}

/// Wakes the calling thread at `deadline`, whatever else it is waiting for.
///
/// For a caller that is about to block on something *else* and must not sleep
/// past a deadline it has already decided on. [`crate::notify::wait_once`]
/// blocks until it is signalled and no longer; a driver that computes a
/// timeout and then blocks without arming this has computed a deadline it can
/// never reach, and an interrupt that does not arrive stops the machine rather
/// than the request.
///
/// The tickless path arms for the soonest outstanding timer, so this keeps an
/// otherwise idle CPU ticking until it fires.
///
/// Returns `false` if this CPU's timer queue is full, in which case the caller
/// **must not** block indefinitely — there is nothing left to wake it.
#[must_use]
pub fn wake_at(deadline: u64) -> bool {
    let Some(me) = crate::sched::current_thread_id() else {
        return false;
    };
    arm_for(me, deadline)
}

/// Cancels a timer armed by [`wake_at`].
pub fn cancel_wake() {
    if let Some(me) = crate::sched::current_thread_id() {
        cancel_for(me);
    }
}

/// Cancels any timer for `thread` on this CPU.
fn cancel_for(thread: u32) {
    let cpu = percpu::cpu_id() as usize;
    if cpu < MAX_CPUS {
        TIMERS[cpu].lock().remove(thread);
    }
}

/// Blocks the calling thread for at least `duration_us` microseconds.
///
/// "At least" is the honest guarantee and the only one available: the thread
/// becomes *runnable* at the deadline, and when it actually runs depends on
/// what else its CPU has to do. A caller needing a bound on the overshoot
/// wants the real-time class, not a shorter sleep.
pub fn sleep_micros(duration_us: u64) {
    let Some(ticks) = micros(duration_us) else {
        // No calibrated clock. Spinning is wrong but bounded; sleeping for an
        // unknown length of time would be worse.
        for _ in 0..duration_us.saturating_mul(100).min(100_000_000) {
            core::hint::spin_loop();
        }
        return;
    };

    let Some(thread) = crate::sched::current_thread_id() else {
        return;
    };
    let deadline = now().saturating_add(ticks);

    // The same shape as a wait queue, and the same race: the timer must be
    // registered *before* the thread is marked blocked, or the interrupt that
    // would wake it can arrive first, find nothing to wake, and leave the
    // thread asleep for ever.
    if !arm_for(thread, deadline) {
        // Queue full. Spinning is a worse sleep, not a wrong one.
        while now() < deadline {
            core::hint::spin_loop();
        }
        return;
    }

    while now() < deadline {
        crate::sched::mark_blocked();
        crate::sched::block_self();
    }
    cancel_for(thread);
}

/// Services expired timers on this CPU and re-arms for the next event.
///
/// Called from the timer interrupt, and the only place that decides whether a
/// CPU ticks at all.
///
/// # Safety
///
/// Must be called from the timer interrupt handler, after acknowledgement, on
/// a CPU whose APIC is initialised.
pub unsafe fn on_tick() {
    let cpu = percpu::cpu_id() as usize;
    if cpu >= MAX_CPUS {
        // No per-CPU data yet, so nothing can have registered a timer. Keep
        // the CPU ticking rather than silently stopping it this early.
        // SAFETY: the caller guarantees an initialised APIC.
        unsafe { arm_default() };
        return;
    }

    let now = now();

    // Expire first, so a thread whose deadline has passed is runnable before
    // the arming decision below asks whether anything is runnable.
    let mut expired = [0u32; MAX_TIMERS];
    let count = match TIMERS[cpu].try_lock() {
        Some(mut timers) => timers.take_expired(now, &mut expired),
        // Contended, which on this CPU means the interrupt landed inside
        // `sleep_micros`. Skipping is safe: the next interrupt expires them,
        // and the arming below still runs.
        None => 0,
    };
    for thread in expired.iter().take(count) {
        // `wake_from_interrupt`, not `wake`: this runs in a handler that may
        // have interrupted a thread holding this CPU's runqueue lock, and a
        // blocking acquisition there waits for a thread that cannot run until
        // this returns. Before M6-04 this called the blocking version, which
        // was a one-CPU deadlock waiting for a timer to expire in a window a
        // few instructions wide.
        crate::sched::wake_from_interrupt(*thread);
    }

    // Deadlines a program armed on a notification. **RFC 0019 step 2.**
    //
    // Here rather than anywhere else because this is where the kernel already
    // knows the time has moved, and because `notify::signal` is lock-free and
    // safe from a handler -- which is the property RFC 0010 built it for and
    // the reason this needs no new wake machinery.
    crate::notify::expire(now, |id, badge| {
        let _ = crate::notify::signal(id, badge);
    });

    // Anything an earlier handler could not deliver, including on this CPU.
    crate::sched::drain_deferred_wakes();

    // Top up this CPU's fault-path frame reserve. Here rather than in the
    // fault handler because this context can afford to fail: if the allocator
    // is busy the next tick tries again, whereas a fault that needs a frame
    // needs it now.
    crate::frames::refill();

    // SAFETY: the caller guarantees an initialised APIC.
    unsafe { rearm(cpu, now) };
}

/// Re-arms this CPU's timer for whatever it now has to do.
///
/// Called after an inter-processor interrupt has made something runnable here.
/// Without it a CPU that went tickless stays armed for the idle backstop — a
/// whole second — even though it now has a thread to preempt. The thread runs,
/// and is simply never interrupted.
///
/// That is not a small inefficiency. It measured as a user-mode program
/// completing without a single timer interrupt, which meant the
/// interrupt-from-ring-3 path was never exercised at all.
///
/// # Safety
///
/// Must be called from an interrupt handler, after acknowledgement, on a CPU
/// whose APIC is initialised.
pub unsafe fn rearm_this_cpu() {
    let cpu = percpu::cpu_id() as usize;
    if cpu >= MAX_CPUS {
        return;
    }
    // SAFETY: per the caller.
    unsafe { rearm(cpu, now()) };
}

/// Chooses the next deadline for this CPU and programs the timer for it.
///
/// # Safety
///
/// As [`on_tick`].
unsafe fn rearm(cpu: usize, now: u64) {
    let Some(hertz) = bhaskix_arch::apic::timer_hertz() else {
        // Uncalibrated: nothing can be computed, so fall back to the fixed
        // period rather than leaving the CPU un-armed. What it is now armed for
        // cannot be said on a scale a deadline uses, so it is recorded as not
        // known rather than left saying something stale.
        forget_programmed(cpu);
        // SAFETY: per the caller.
        unsafe { arm_default() };
        return;
    };

    // This CPU's thread timers, and the deadlines programs armed on
    // notifications. The second is a global table rather than a per-CPU one, so
    // every processor arms for it and whichever tick arrives first expires it —
    // `notify::expire` claims each entry, so it fires once. RFC 0019 step 2.
    let earliest = match (
        TIMERS[cpu].try_lock().and_then(|timers| timers.earliest()),
        crate::notify::earliest_deadline(),
    ) {
        (Some(thread), Some(armed)) => Some(thread.min(armed)),
        (Some(thread), None) => Some(thread),
        (None, armed) => armed,
    };

    // A CPU needs a periodic interrupt only to take the CPU *away* from a
    // thread, which is meaningless when there is no other thread to give it
    // to. This is `docs/scheduler.md` §7's rule, and it is a property of the
    // runqueue rather than of the timer.
    // The fixed period, in TSC units, as the answer when a tick is needed but
    // no thread has asked for a particular slice -- which is the case during
    // early boot, before any runqueue exists. Falling through to "nothing to
    // wait for" there would stop the timer before anything had proved it
    // works, and a stopped timer is indistinguishable from a broken one.
    // An *absolute* deadline, so an interrupt arriving mid-slice re-arms for
    // the remainder rather than for a fresh slice. See `slice_deadline`.
    let slice_end = if crate::sched::needs_preemption_tick(cpu) {
        let default = tsc::hertz()
            .map(|hz| now.saturating_add((hz / u64::from(crate::trap::TIMER_HZ.max(1))).max(1)));
        crate::sched::next_slice_deadline(cpu, now).or(default)
    } else {
        None
    };

    let deadline = match (slice_end, earliest) {
        (Some(slice_end), Some(timer)) => Some(slice_end.min(timer)),
        (Some(slice_end), None) => Some(slice_end),
        (None, Some(timer)) => Some(timer),
        (None, None) => None,
    };

    if let Some(reasons) = ARM_REASONS.get(cpu) {
        let which = match (slice_end, earliest) {
            (Some(_), _) => 0,
            (None, Some(_)) => 1,
            (None, None) => 2,
        };
        reasons[which].fetch_add(1, Ordering::Relaxed);
    }

    let Some(deadline) = deadline else {
        // Nothing to wait for. Arm the backstop rather than nothing at all --
        // see `IDLE_BACKSTOP_MS`.
        TICKLESS_IDLES.fetch_add(1, Ordering::Relaxed);
        let backstop = u64::from(hertz).saturating_mul(IDLE_BACKSTOP_MS).max(1_000) / 1_000;
        // Recorded on the same scale as every other deadline, so that a
        // program arming one *later* than the backstop is declined rather than
        // allowed to defer the safety net. Without a calibrated TSC there is no
        // such scale, and zero says so.
        if let Some(programmed) = PROGRAMMED.get(cpu) {
            programmed.store(
                tsc::from_micros(IDLE_BACKSTOP_MS.saturating_mul(1_000))
                    .map_or(0, |ticks| now.saturating_add(ticks)),
                Ordering::Relaxed,
            );
        }
        // SAFETY: per the caller.
        unsafe { bhaskix_arch::apic::arm_oneshot(backstop.min(u64::from(u32::MAX)) as u32) };
        return;
    };

    // SAFETY: per the caller.
    if !unsafe { program(cpu, now, deadline, hertz) } {
        forget_programmed(cpu);
        // SAFETY: per the caller.
        unsafe { arm_default() };
    }
}

/// Records that what this CPU's timer is armed for is not expressible as a
/// deadline, so [`arm_no_later_than`] does not compare against a stale one.
fn forget_programmed(cpu: usize) {
    if let Some(programmed) = PROGRAMMED.get(cpu) {
        programmed.store(0, Ordering::Relaxed);
    }
}

/// Programs this CPU's one-shot timer to fire at `deadline`, and records it.
///
/// Answers whether it could: `false` means there is no calibrated TSC to
/// express the interval in, and the caller wants [`arm_default`] instead.
///
/// Shared by the tick's own re-arming and by [`arm_no_later_than`], because
/// two copies of the conversion below would be two chances to round it the
/// wrong way.
///
/// # Safety
///
/// The APIC must be initialised, `cpu` must be the CPU this is running on, and
/// nothing may preempt onto another CPU between the two — the caller either
/// runs in an interrupt handler or has masked interrupts.
unsafe fn program(cpu: usize, now: u64, deadline: u64, hertz: u32) -> bool {
    // Convert a TSC deadline into APIC timer counts. The two run at different
    // rates, so this is a ratio rather than a subtraction.
    let remaining_tsc = deadline.saturating_sub(now);
    let Some(tsc_hertz) = tsc::hertz() else {
        return false;
    };
    // Rounded *up*. A timer must not fire before its deadline, and rounding
    // down means every slice is delivered a little short — which is not the
    // harmless rounding it looks like. A thread's virtual time advances by
    // `slice / weight`, so a heavy thread's increments are proportionally
    // smaller and a constant shortfall costs it a larger fraction of each
    // one. It needed a fourth slice to overtake where three should have done,
    // and a 3:1 weight ratio delivered 3.7:1 on hardware while the policy
    // itself measured exactly 3:1 in simulation.
    let scaled = remaining_tsc.saturating_mul(u64::from(hertz));
    let count = scaled
        .checked_add(tsc_hertz - 1)
        .and_then(|rounded| rounded.checked_div(tsc_hertz))
        .unwrap_or(u64::from(hertz))
        .clamp(1, u64::from(u32::MAX));

    ARMED.fetch_add(1, Ordering::Relaxed);
    if let Some(programmed) = PROGRAMMED.get(cpu) {
        programmed.store(deadline, Ordering::Relaxed);
    }
    // SAFETY: per the caller.
    unsafe { bhaskix_arch::apic::arm_oneshot(count as u32) };
    true
}

/// Brings this CPU's next timer interrupt forward to `deadline`, if it is not
/// already going to fire by then.
///
/// **This is what makes a deadline a deadline.** Everything else in this module
/// decides when to tick from what the *kernel* has to do — a slice to end, a
/// sleeping thread to wake — and re-decides it only when a tick happens. A
/// deadline armed between two ticks was therefore not considered until the next
/// one arrived for some other reason, which is why RFC 0019 step 4 measured a
/// deadline as late by `C − d`: the wake instant did not depend on the deadline
/// at all. The fix is this function, called where a deadline is armed.
///
/// **It only ever moves the interrupt earlier**, which is what makes it safe to
/// call from a system call. Programming the one-shot counter restarts it, so a
/// caller naming a *later* deadline would push out the tick that was already
/// due — a slice that never ends, or an idle CPU's backstop deferred by a
/// program that asked to be woken next week. [`PROGRAMMED`] is what lets that
/// case be recognised and declined.
///
/// Answers whether the timer was moved, which is how the boot report can say
/// this is doing anything at all.
pub fn arm_no_later_than(deadline: u64) -> bool {
    // Interrupts masked for the whole of it. This reads which CPU it is on and
    // then writes *that* CPU's timer; preempted in between, it would program
    // one CPU's APIC on another CPU's behalf, and the deadline would be armed
    // where nobody was waiting for it.
    let enabled = bhaskix_arch::cpu::interrupts_enabled();
    if enabled {
        // SAFETY: re-enabled below on every path out.
        unsafe { bhaskix_arch::cpu::disable_interrupts() };
    }

    let moved = 'moved: {
        let cpu = percpu::cpu_id() as usize;
        if cpu >= MAX_CPUS {
            break 'moved false;
        }
        let Some(hertz) = bhaskix_arch::apic::timer_hertz() else {
            break 'moved false;
        };

        // Already due to fire by then. Zero means nothing has recorded a
        // deadline for this CPU, which is not the same as "it will fire soon"
        // and so is not treated as it.
        let programmed = PROGRAMMED[cpu].load(Ordering::Relaxed);
        if programmed != 0 && deadline >= programmed {
            ALREADY_SOON_ENOUGH.fetch_add(1, Ordering::Relaxed);
            break 'moved false;
        }

        // SAFETY: interrupts are masked, so `cpu` is still this CPU; the APIC
        // is initialised because `timer_hertz` answered.
        let done = unsafe { program(cpu, now(), deadline, hertz) };
        if done {
            HASTENED.fetch_add(1, Ordering::Relaxed);
        }
        done
    };

    if enabled {
        // SAFETY: restoring the caller's state.
        unsafe { bhaskix_arch::cpu::enable_interrupts() };
    }
    moved
}

/// How often a deadline moved this machine's next timer interrupt earlier, and
/// how often it was already soon enough.
#[must_use]
pub fn hastened() -> (u64, u64) {
    (
        HASTENED.load(Ordering::Relaxed),
        ALREADY_SOON_ENOUGH.load(Ordering::Relaxed),
    )
}

/// Arms the timer for one period of the fixed tick rate.
///
/// # Safety
///
/// As [`on_tick`].
unsafe fn arm_default() {
    let Some(hertz) = bhaskix_arch::apic::timer_hertz() else {
        return;
    };
    let count = hertz / crate::trap::TIMER_HZ.max(1);
    // SAFETY: per the caller.
    unsafe { bhaskix_arch::apic::arm_oneshot(count.max(1)) };
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: Timer = Timer {
        deadline: 100,
        thread: 1,
    };
    const B: Timer = Timer {
        deadline: 50,
        thread: 2,
    };

    #[test]
    fn the_earliest_deadline_is_what_the_cpu_waits_for() {
        // Arming for anything later than the soonest timer means that timer
        // fires late, which is the one thing a timer must not do.
        let mut timers = Timers::new();
        assert_eq!(timers.earliest(), None);
        assert!(timers.insert(A));
        assert!(timers.insert(B));
        assert_eq!(timers.earliest(), Some(50));
    }

    #[test]
    fn expiry_takes_everything_due_and_leaves_the_rest() {
        let mut timers = Timers::new();
        timers.insert(A);
        timers.insert(B);
        let mut out = [0u32; MAX_TIMERS];

        assert_eq!(timers.take_expired(49, &mut out), 0, "nothing due yet");
        assert_eq!(
            timers.take_expired(50, &mut out),
            1,
            "due exactly now counts"
        );
        assert_eq!(out[0], 2);
        assert_eq!(timers.earliest(), Some(100));

        assert_eq!(timers.take_expired(1_000, &mut out), 1);
        assert_eq!(timers.earliest(), None);
    }

    #[test]
    fn a_cancelled_timer_does_not_fire() {
        // A thread woken by something other than its timer must not be woken
        // again later by the timer it no longer needs.
        let mut timers = Timers::new();
        timers.insert(A);
        timers.remove(1);
        let mut out = [0u32; MAX_TIMERS];
        assert_eq!(timers.take_expired(1_000, &mut out), 0);
    }

    #[test]
    fn a_full_queue_refuses_and_counts_rather_than_dropping() {
        let mut timers = Timers::new();
        for thread in 0..MAX_TIMERS as u32 {
            assert!(timers.insert(Timer {
                deadline: 10,
                thread
            }));
        }
        assert!(!timers.insert(A));
        assert_eq!(timers.overflowed, 1);
    }
}
