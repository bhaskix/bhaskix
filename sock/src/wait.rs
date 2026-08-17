// SPDX-License-Identifier: Apache-2.0
//! Sleeping until a deadline, on a notification the program holds.
//!
//! RFC 0019's shape, as the ported programs already spoke it: arm an
//! absolute cycle deadline on a notification, then block in `WAIT` until
//! the word goes non-zero. The fallback is stated rather than silent — a
//! machine that could not give the program a wake, or has no calibrated
//! clock, answers `false`, and the caller yields instead of spinning.

use crate::call::call;
use bhaskix_abi::{method, status, syscall};

/// Sleeps until the absolute cycle deadline passes, waking on the
/// notification in `timer_slot`. Returns whether it actually slept; a
/// `false` means the arm or the wait was refused, and asking again
/// immediately — after a yield — is all that is left.
#[must_use]
pub fn sleep_until(timer_slot: u64, deadline: u64) -> bool {
    if !call(
        syscall::INVOKE,
        timer_slot,
        method::ARM,
        [deadline, 0, 0, 0],
    )
    .kernel_ok()
    {
        return false;
    }
    call(syscall::INVOKE, timer_slot, method::WAIT, [0; 4]).status == status::OK
}

/// Sleeps for a stretch from now, or yields once when it cannot — the
/// retry-loop idiom every ported program repeated, with the fallback
/// built in instead of copied.
pub fn doze(timer_slot: u64, pace: &crate::time::Pace, ms: u64) {
    if !pace.calibrated()
        || !sleep_until(
            timer_slot,
            crate::time::now().saturating_add(pace.cycles(ms)),
        )
    {
        crate::call::yield_now();
    }
}
