// SPDX-License-Identifier: Apache-2.0
//! Unpredictable numbers from the hardware, or none at all.
//!
//! [RFC 0021](../../docs/rfc/0021-unpredictability.md). Until this crate
//! existed **this system could not produce an unpredictable number** — no
//! `RDRAND`, no `RDSEED`, no entropy pool, and no interface that returned one.
//! Nothing had noticed, because nothing had needed one: the first caller is a
//! TCP initial sequence number, which must be unguessable or an off-path
//! attacker injects into connections without ever seeing a packet.
//!
//! # There is no capability here, and that is a finding rather than an omission
//!
//! `RDRAND` is unprivileged, and so is the `CPUID` that detects it. A ring 3
//! program can therefore do all of this holding nothing at all, which means a
//! `Random` capability would guard something the kernel does not control — a
//! program refused one could simply execute the instruction. RFC 0019 reached
//! the same conclusion about `rdtsc` and said so in the same words.
//!
//! So the kernel gains no object and no system call. What it gains is a
//! feature bit, a line at boot, and a policy: **the caller refuses**. A machine
//! without `RDRAND` still has a filesystem, a shell and a supervisor, none of
//! which need to be unpredictable, so it boots and says what it cannot do.
//!
//! # The difficulty is the failure, not the instruction
//!
//! `RDRAND` can decline. Under contention it sets the carry flag to zero and
//! leaves the destination register holding *something* — on some parts, zero,
//! over and over. Reading the register without testing the flag is the classic
//! bug in every use of this instruction, and it fails silently in the worst
//! possible way: a stream of zeroes that looks like a number.
//!
//! Everything that decides anything therefore lives in safe functions that a
//! host test can drive, and the `unsafe` is reduced to "execute it and report
//! both halves". [`interpret`] is where the carry flag is believed or not, and
//! deleting its check turns tests red — which is the only reason to trust that
//! it is doing anything.
//!
//! # `RDSEED` is deliberately not used
//!
//! It is the better primitive — the entropy behind `RDRAND`'s generator rather
//! than its output — and the machine this project tests on does not have it.
//! QEMU's `-cpu max`, which every harness here boots, reports `rdrand` present
//! and `rdseed` absent. A design whose only implementation cannot be exercised
//! in CI is one RFC 0012 already argued against, and it was right.

#![cfg_attr(not(test), no_std)]
// Tests are exempt from the `unwrap`/`expect`/`panic` bans, as
// `docs/coding-style.md` §3 and §4 specify: those bans exist to stop a fallible
// operation taking down a service, and a test that cannot panic cannot fail.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

/// What one execution of `RDRAND` reported.
///
/// **Both halves, always together.** The value alone is meaningless — the
/// instruction leaves the register defined but arbitrary when it declines — and
/// a type that could carry the value without the flag would let a caller use
/// one without the other, which is exactly the mistake this crate exists to
/// make impossible.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Attempt {
    /// What the destination register held afterwards.
    pub value: u64,
    /// Whether the carry flag said that value is usable.
    pub usable: bool,
}

/// How many times to ask before giving up.
///
/// Ten is the figure Intel's own guidance gives for a reseed-contention retry
/// loop. The bound matters more than the number: an unbounded loop on a part
/// whose generator has failed is a hang, and a hang in a service that was asked
/// for one number is worse than a refusal.
pub const ATTEMPTS: usize = 10;

/// What a single attempt means.
///
/// **This is the carry-flag check**, and it is a separate function so that it
/// can be tested. A test that drove the real instruction could not tell a
/// working check from a missing one, because on a healthy processor the flag is
/// always set — the bug only appears on the machine you do not have.
///
/// A *usable* zero is a perfectly good random number and is returned as one.
/// Telling that apart from the zero a failed attempt leaves behind is the whole
/// job.
#[must_use]
pub fn interpret(attempt: Attempt) -> Option<u64> {
    if attempt.usable {
        Some(attempt.value)
    } else {
        None
    }
}

/// Asks `attempt` until it answers, up to [`ATTEMPTS`] times.
///
/// Generic over the attempt so the retry logic is testable without a processor
/// that can be made to fail on demand.
///
/// **`None` is a refusal and must never become a number.** A caller that cannot
/// proceed without unpredictability has to fail; returning a placeholder here
/// would push a silent weakness into every caller at once.
pub fn draw(mut attempt: impl FnMut() -> Attempt) -> Option<u64> {
    for _ in 0..ATTEMPTS {
        if let Some(value) = interpret(attempt()) {
            return Some(value);
        }
    }
    None
}

/// Whether this processor has `RDRAND`.
///
/// `CPUID` leaf 1, `ECX` bit 30. The bit position was confirmed against a
/// machine that reports the feature rather than quoted from a manual nobody
/// checked.
#[must_use]
pub fn available() -> bool {
    leaf1_ecx() & (1 << 30) != 0
}

/// An unpredictable 64-bit value, or `None` if this machine cannot produce one.
///
/// `None` for two different reasons that a caller cannot usefully tell apart —
/// the processor does not have the instruction, or it has it and would not
/// answer — because the action is the same either way: refuse.
#[must_use]
pub fn u64() -> Option<u64> {
    if !available() {
        return None;
    }
    draw(step)
}

/// Executes `RDRAND` once and reports both halves.
///
/// The two instructions are in one `asm!` block on purpose: `setc` must read
/// the flag `rdrand` just wrote, and anything the compiler were free to insert
/// between them could clobber it. For the same reason this block must **not**
/// claim `preserves_flags`.
fn step() -> Attempt {
    let value: u64;
    let usable: u8;
    // SAFETY: `rdrand` is unprivileged, cannot fault, and touches nothing but
    // the register it is given and the flags. `setc` reads that flag in the
    // same block. Both outputs are written before they are read.
    unsafe {
        core::arch::asm!(
            "rdrand {value}",
            "setc {usable}",
            value = out(reg) value,
            usable = out(reg_byte) usable,
            options(nomem, nostack),
        );
    }
    Attempt {
        value,
        usable: usable != 0,
    }
}

/// `CPUID` leaf 1, `ECX`.
///
/// A second `cpuid` in this tree, and the duplication is deliberate:
/// `bhaskix-arch-x86-64` has one, and depending on `arch` would make this crate
/// unreachable from the ring 3 programs that need it most. The manifest says so
/// at greater length.
fn leaf1_ecx() -> u32 {
    let ecx: u32;
    // SAFETY: `cpuid` is unprivileged, cannot fault, and has no memory
    // effects. `RBX` is callee-saved in the SysV ABI and cannot be named as an
    // operand, so it is preserved by hand around the instruction — the same
    // sequence `bhaskix_arch::msr::cpuid` uses, for the same reason.
    unsafe {
        core::arch::asm!(
            "mov {tmp:r}, rbx",
            "cpuid",
            "xchg {tmp:r}, rbx",
            tmp = out(reg) _,
            inout("eax") 1u32 => _,
            inout("ecx") 0u32 => ecx,
            out("edx") _,
            options(nostack, preserves_flags),
        );
    }
    ecx
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;

    #[test]
    fn a_refused_attempt_is_not_a_number() {
        // The whole crate, in one assertion. `RDRAND` leaves the register
        // defined but arbitrary when it declines, so a value that arrives with
        // the flag clear must not reach a caller however plausible it looks.
        assert_eq!(
            interpret(Attempt {
                value: 0x1234_5678_9abc_def0,
                usable: false
            }),
            None
        );
    }

    #[test]
    fn a_usable_zero_is_a_number() {
        // The case that makes the check worth having. Zero is a legal random
        // value; the failure this crate guards against is *also* zero. Only the
        // flag distinguishes them, which is why the flag is what is believed.
        assert_eq!(
            interpret(Attempt {
                value: 0,
                usable: true
            }),
            Some(0)
        );
    }

    #[test]
    fn a_processor_that_never_answers_is_refused_rather_than_waited_for() {
        let asked = Cell::new(0);
        let drawn = draw(|| {
            asked.set(asked.get() + 1);
            Attempt {
                value: 0xdead,
                usable: false,
            }
        });
        assert_eq!(drawn, None, "a refusal, not a placeholder");
        assert_eq!(
            asked.get(),
            ATTEMPTS,
            "bounded, and it used the whole bound"
        );
    }

    #[test]
    fn the_last_attempt_still_counts() {
        // Off by one here means a processor under contention is given up on one
        // ask early, which is invisible until the day it matters.
        let asked = Cell::new(0);
        let drawn = draw(|| {
            asked.set(asked.get() + 1);
            Attempt {
                value: 0x99,
                usable: asked.get() == ATTEMPTS,
            }
        });
        assert_eq!(drawn, Some(0x99));
        assert_eq!(asked.get(), ATTEMPTS);
    }

    #[test]
    fn a_working_processor_is_asked_once() {
        let asked = Cell::new(0);
        let drawn = draw(|| {
            asked.set(asked.get() + 1);
            Attempt {
                value: 0x42,
                usable: true,
            }
        });
        assert_eq!(drawn, Some(0x42));
        assert_eq!(asked.get(), 1, "no retry when the first answer is good");
    }

    #[test]
    fn the_instruction_agrees_with_the_feature_bit() {
        // Weak evidence, and stated as such. It proves the two `asm!` blocks
        // assemble, execute, and agree with each other; it proves nothing about
        // the quality of what comes out, which is a research exercise and would
        // be theatre in a unit test.
        //
        // On a host without the feature this asserts the refusal instead, which
        // is the more interesting half and the one no CI machine here can
        // reach.
        if available() {
            assert!(u64().is_some(), "the feature is reported and it answered");
        } else {
            assert_eq!(u64(), None, "no feature, no number");
        }
    }

    #[test]
    fn two_draws_differ() {
        // Catches a stub, a constant, and the missing carry-flag check on a
        // part that leaves zero behind. Nothing subtler than that, and skipped
        // where the instruction is absent rather than failing for the machine.
        if !available() {
            return;
        }
        let (first, second) = (u64(), u64());
        assert!(first.is_some() && second.is_some());
        assert_ne!(first, second, "two draws from a generator should differ");
    }
}
