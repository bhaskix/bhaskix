// SPDX-License-Identifier: Apache-2.0
//! Cycles and milliseconds, without pretending to own a clock.
//!
//! Deadlines in this system are absolute cycle counts (RFC 0019): a program
//! is handed the counter's rate at entry, because that is the one thing
//! about the clock that cannot arrive through a CSpace. [`Pace`] carries
//! that rate and does the only two conversions anybody needs, saturating,
//! host-tested, honest about a machine whose rate is unknown.

/// The cycle counter, read directly. Unprivileged: `CR4.TSD` is clear on
/// this machine, which is why reading time needs no capability and being
/// *woken* does (RFC 0019).
#[must_use]
pub fn now() -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        let low: u32;
        let high: u32;
        // SAFETY: `rdtsc` reads a counter and touches no memory.
        unsafe {
            core::arch::asm!("rdtsc", out("eax") low, out("edx") high, options(nomem, nostack));
        }
        (u64::from(high) << 32) | u64::from(low)
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        0
    }
}

/// A cycle rate, and the arithmetic that turns durations into deadlines.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pace {
    hertz: u64,
}

impl Pace {
    /// A pace from the rate the kernel handed over at entry. Zero is a
    /// machine with no calibrated clock, and every conversion says so by
    /// answering zero cycles — callers fall back to yielding, exactly as
    /// the ported programs already did.
    #[must_use]
    pub const fn new(hertz: u64) -> Self {
        Self { hertz }
    }

    /// Whether this machine has a usable rate at all.
    #[must_use]
    pub const fn calibrated(&self) -> bool {
        self.hertz != 0
    }

    /// How many cycles `ms` milliseconds are, saturating — a huge duration
    /// on a fast clock clamps rather than wrapping into the past.
    #[must_use]
    pub const fn cycles(&self, ms: u64) -> u64 {
        self.hertz.saturating_mul(ms) / 1000
    }

    /// How many cycles `ns` nanoseconds are, exactly, saturating at `u64::MAX`.
    ///
    /// **Through a 128-bit intermediate, because `ns * hertz` does not fit in
    /// 64 bits for any sleep a program actually takes.** At 2 GHz it overflows
    /// past 9.2 seconds and at 1 GHz past 18.4. `bin/linuxd` did that multiply
    /// in `u64` with `checked_mul`, and on overflow answered `nanosleep` with an
    /// immediate `EINTR` -- so a hosted `nanosleep(1000 s)` never slept, and the
    /// killer probe's child, which the probe believed was parked, raced its own
    /// kill instead. That race is §3's undelivered-signal row (2026-09-28).
    /// `bin/tcpd`'s `now_nanos` already said the same thing in its own words:
    /// *128-bit intermediate on purpose*.
    #[must_use]
    pub const fn cycles_ns(&self, ns: u64) -> u64 {
        let cycles = (ns as u128) * (self.hertz as u128) / 1_000_000_000;
        if cycles > u64::MAX as u128 {
            u64::MAX
        } else {
            cycles as u64
        }
    }

    /// The absolute deadline `ms` milliseconds from now, saturating.
    #[must_use]
    pub fn after_ms(&self, ms: u64) -> u64 {
        now().saturating_add(self.cycles(ms))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_uncalibrated_pace_answers_zero_and_says_so() {
        let pace = Pace::new(0);
        assert!(!pace.calibrated());
        assert_eq!(pace.cycles(3_000), 0);
    }

    #[test]
    fn a_long_sleep_in_nanoseconds_converts_exactly_rather_than_overflowing() {
        // 1000 seconds at 3 GHz is 3e12 cycles. The product before dividing is
        // 3e21, past u64::MAX -- the multiply bin/linuxd did, and refused.
        let fast = Pace::new(3_000_000_000);
        assert_eq!(fast.cycles_ns(1_000_000_000_000), 3_000_000_000_000);
        // Ten seconds at 2 GHz: the product is 2e19, just past u64::MAX.
        assert_eq!(
            Pace::new(2_000_000_000).cycles_ns(10_000_000_000),
            20_000_000_000
        );
        // A duration no clock can reach saturates instead of wrapping.
        assert_eq!(Pace::new(u64::MAX).cycles_ns(u64::MAX), u64::MAX);
        // And no clock at all is still zero.
        assert_eq!(Pace::new(0).cycles_ns(1_000_000_000), 0);
    }

    #[test]
    fn conversions_saturate_instead_of_wrapping_into_the_past() {
        // The multiply clamps at u64::MAX, so the worst case divides down
        // instead of wrapping — a deadline in the past is the failure mode
        // this guards, and it cannot happen by overflow.
        let absurd = Pace::new(u64::MAX);
        assert_eq!(absurd.cycles(u64::MAX), u64::MAX / 1000);
        // An ordinary rate converts exactly: this machine's measured APIC
        // calibration, one second and one retry interval.
        let ordinary = Pace::new(62_579_000);
        assert_eq!(ordinary.cycles(1000), 62_579_000);
        assert_eq!(ordinary.cycles(20), 1_251_580);
    }
}
