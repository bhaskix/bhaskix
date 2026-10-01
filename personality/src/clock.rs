// SPDX-License-Identifier: Apache-2.0
//! `clock_gettime` — [RFC 0086](../../docs/rfc/0086-the-motivating-workload.md)
//! step 5.
//!
//! **Go cannot tell time without it, and does not notice when it cannot.** A
//! process here has no vDSO, so go 1.27.1's `runtime·nanotime1` falls back to
//! the syscall — and then reads the result buffer **whatever the syscall
//! answered** (`runtime/sys_linux_amd64.s`, read 2026-10-01). Refused, the
//! runtime's clock was whatever bytes were on its stack, and the server hung
//! in start-up before it ever listened.
//!
//! **Two clocks, one counter.** The monotonic clocks are the cycle counter
//! since it started, in nanoseconds. There is no RTC driver and no wall time on
//! this machine (`kernel/src/time.rs` says so), so `CLOCK_REALTIME` is **the
//! Unix epoch plus the time since boot** — the machine believes it is early
//! 1970, and says so here rather than inventing a date. The CPU-time clocks
//! are refused `EINVAL`: nothing here counts a process's or a thread's time.
//!
//! Clock numbers from the build host's `linux/time.h`, read 2026-10-01.

/// Which clock a caller named.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Clock {
    /// `CLOCK_MONOTONIC` and its raw, coarse and boot-time kin.
    Monotonic,
    /// `CLOCK_REALTIME` and its coarse kin: see the module note.
    Realtime,
}

/// `EINVAL`.
pub const EINVAL: i64 = -22;

/// The clock `id` names.
///
/// # Errors
///
/// `EINVAL` for a CPU-time clock or a number Linux does not define.
pub const fn plan(id: u64) -> Result<Clock, i64> {
    match id {
        // REALTIME, REALTIME_COARSE
        0 | 5 => Ok(Clock::Realtime),
        // MONOTONIC, MONOTONIC_RAW, MONOTONIC_COARSE, BOOTTIME
        1 | 4 | 6 | 7 => Ok(Clock::Monotonic),
        _ => Err(EINVAL),
    }
}

/// `cycles` of a counter running at `hertz`, in nanoseconds, exactly; zero on
/// a machine with no measured rate.
#[must_use]
pub const fn nanos(cycles: u64, hertz: u64) -> u64 {
    if hertz == 0 {
        return 0;
    }
    let whole = (cycles as u128) * 1_000_000_000 / (hertz as u128);
    if whole > u64::MAX as u128 {
        u64::MAX
    } else {
        whole as u64
    }
}

/// A `struct timespec` of `nanos`: seconds, then nanoseconds.
#[must_use]
pub fn timespec(nanos: u64) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&(nanos / 1_000_000_000).to_le_bytes());
    out[8..].copy_from_slice(&(nanos % 1_000_000_000).to_le_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_clocks_go_asks_for_are_answered_and_cpu_time_is_not() {
        assert_eq!(plan(1), Ok(Clock::Monotonic), "nanotime1");
        assert_eq!(plan(0), Ok(Clock::Realtime), "walltime");
        assert_eq!(plan(2), Err(EINVAL), "PROCESS_CPUTIME_ID");
        assert_eq!(plan(3), Err(EINVAL), "THREAD_CPUTIME_ID");
        assert_eq!(plan(99), Err(EINVAL));
    }

    #[test]
    fn cycles_become_nanoseconds_without_overflowing() {
        assert_eq!(nanos(3_000_000_000, 3_000_000_000), 1_000_000_000);
        assert_eq!(nanos(1_500, 3_000_000_000), 500);
        // A day at 3 GHz overflows `cycles * 1e9` in 64 bits; not in 128.
        let day = 86_400 * 3_000_000_000u64;
        assert_eq!(nanos(day, 3_000_000_000), 86_400_000_000_000);
        assert_eq!(nanos(5, 0), 0, "no rate, no time");
    }

    #[test]
    fn a_timespec_is_seconds_then_the_remainder() {
        let bytes = timespec(2_500_000_001);
        assert_eq!(u64::from_le_bytes(bytes[..8].try_into().unwrap()), 2);
        assert_eq!(
            u64::from_le_bytes(bytes[8..].try_into().unwrap()),
            500_000_001
        );
    }
}
