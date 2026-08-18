// SPDX-License-Identifier: Apache-2.0
//! The time-stamp counter.
//!
//! The scheduler needs to know how long a thread actually ran, and the timer
//! tick is far too coarse to tell it: at 100 Hz a thread that runs for 200 µs
//! and one that runs for 9 ms are both "one tick". Proportional fairness
//! measured in ticks is not proportional fairness, and a wakeup latency
//! measured in ticks cannot see the difference between 50 µs and 10 ms — which
//! is the entire range `docs/scheduler.md` §4 cares about.
//!
//! `RDTSC` reads a counter that increments at a fixed rate, is readable in a
//! handful of cycles, and needs no lock and no device access. That makes it the
//! only clock cheap enough to read on every context switch.
//!
//! # What is deliberately not done
//!
//! - **No serialising.** `RDTSC` may be reordered against surrounding
//!   instructions, so a measurement can be off by a few tens of cycles. For
//!   accounting a scheduling slice, that is noise several orders of magnitude
//!   below the signal; `RDTSCP` or an `LFENCE` would cost more than the error.
//!   Anything measuring a short instruction sequence must serialise for itself.
//! - **No cross-CPU comparison.** Counters on different processors are not
//!   guaranteed to agree, and on multi-socket machines they generally do not.
//!   Every reading here is compared only against another reading from the same
//!   CPU, which is what accounting a slice needs.
//! - **No invariant-TSC requirement.** Without it the counter varies with core
//!   frequency, so durations are approximate. `msr::features().invariant_tsc`
//!   reports whether this machine has it; the boot log prints it, and the
//!   scheduler uses the counter either way rather than having no clock at all.

use core::sync::atomic::{AtomicU64, Ordering};

/// Measured tick rate, in hertz. Zero until calibration succeeds.
static HERTZ: AtomicU64 = AtomicU64::new(0);

/// Reads the time-stamp counter.
#[must_use]
#[inline]
pub fn read() -> u64 {
    let low: u32;
    let high: u32;
    // SAFETY: `rdtsc` is readable at every privilege level unless CR4.TSD is
    // set, which this kernel never sets. It has no operands and no side
    // effects beyond writing EAX and EDX.
    unsafe {
        core::arch::asm!(
            "rdtsc",
            out("eax") low,
            out("edx") high,
            options(nomem, nostack, preserves_flags)
        );
    }
    (u64::from(high) << 32) | u64::from(low)
}

/// Records the measured tick rate.
///
/// Called once, by the APIC calibration, which already holds the PIT for long
/// enough to measure against.
pub fn set_hertz(hertz: u64) {
    HERTZ.store(hertz, Ordering::Release);
}

/// Measured tick rate, or `None` if calibration has not run or failed.
#[must_use]
pub fn hertz() -> Option<u64> {
    match HERTZ.load(Ordering::Acquire) {
        0 => None,
        hertz => Some(hertz),
    }
}

/// Converts a count of ticks to nanoseconds, or `None` without a rate.
///
/// Multiplies before dividing, so a short interval does not truncate to
/// zero — and the multiply is widened to 128 bits, because in 64 the
/// product overflows at eighteen giga-ticks: **a few seconds of uptime**
/// at any real rate. The saturating multiply this replaces froze the
/// clock there — every value after the cliff collapsed to one constant,
/// so every deadline computed from it was reachable never — and it was
/// found by a bring-up wait that genuinely never ended, not by this
/// comment's author reading carefully.
#[must_use]
pub fn to_nanos(ticks: u64) -> Option<u64> {
    let hertz = hertz()?;
    let nanos = (u128::from(ticks) * 1_000_000_000) / u128::from(hertz);
    // Beyond u64 nanoseconds is five centuries of uptime; saturation there
    // is a statement, not a bug.
    Some(u64::try_from(nanos).unwrap_or(u64::MAX))
}

/// Converts microseconds to ticks, or `None` without a rate.
///
/// Widened for the same reason as [`to_nanos`]: `micros × hertz` leaves
/// 64 bits while both factors are still ordinary.
#[must_use]
pub fn from_micros(micros: u64) -> Option<u64> {
    let hertz = hertz()?;
    let ticks = (u128::from(micros) * u128::from(hertz)) / 1_000_000;
    Some(u64::try_from(ticks).unwrap_or(u64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The clock must keep moving past eighteen giga-ticks — the exact
    /// cliff where the pre-widening arithmetic saturated. Beyond it every
    /// reading collapsed to one constant, so every deadline computed from
    /// the clock became unreachable; found by a bring-up wait that
    /// genuinely never ended, a few seconds into an emulated boot.
    #[test]
    fn the_clock_does_not_freeze_past_eighteen_giga_ticks() {
        set_hertz(2_400_000_000);
        let cliff = 19_030_889_816; // the reading the wedged boot printed
        let before = to_nanos(cliff).expect("calibrated");
        let after = to_nanos(cliff + 2_400_000_000).expect("calibrated");
        assert_eq!(before, 7_929_537_423);
        assert_eq!(
            after - before,
            1_000_000_000,
            "one second of ticks must be one second of nanoseconds, at any uptime"
        );
    }

    /// The other direction has the same cliff: microseconds times hertz
    /// leaves 64 bits while both factors are still ordinary.
    #[test]
    fn micros_conversion_survives_large_durations() {
        set_hertz(2_400_000_000);
        assert_eq!(from_micros(8_000_000_000), Some(19_200_000_000_000));
    }
}
