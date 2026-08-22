// SPDX-License-Identifier: Apache-2.0
// Adapted from the `xhci` crate, Copyright (c) 2021 Hiroki Tokunaga.
// Upstream: https://github.com/rust-osdev/xhci, version 0.9.2, MIT OR Apache-2.0.
// Taken under Apache-2.0. See PROVENANCE.md.
//! xHCI register layouts: where each register is, and what its bits mean.
//!
//! [RFC 0038](../../docs/rfc/0038-vendoring-the-xhci-definitions.md). This is
//! **adapted third-party source**, not original work — see `PROVENANCE.md`
//! beside this file, which names the upstream, the version, the copyright
//! holder and everything that was changed.
//!
//! # This crate does no I/O, and that is a change from upstream
//!
//! Upstream reaches device memory through an abstraction of its own (the
//! `accessor` crate), so a register there is a thing you can read. Here a
//! register is an **offset and a decoder**: this crate says where the register
//! is and what the bits mean, and the caller — which is the kernel, the only
//! thing in this system allowed to touch device memory — does the volatile
//! read.
//!
//! That split is deliberate and it is the reason this crate holds no `unsafe`
//! at all. A driver reaching device memory through a second abstraction with
//! its own opinions about volatility and ordering is exactly the drift this
//! project keeps finding elsewhere; there is one such abstraction, it lives in
//! the kernel, and this crate does not compete with it.
//!
//! It also makes every line here host-testable, which for a body of
//! transcribed constants is the only assurance available.
//!
//! # The specification wins
//!
//! Upstream is why these numbers did not have to be derived from the
//! specification twice. It is not the authority on what they are. Where this
//! source and the xHCI specification disagree, the specification is right and
//! this file has a bug.

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod capability;
pub mod context;
pub mod doorbell;
pub mod operational;
pub mod runtime;

/// Extracts the bits `lo..=hi` of `value`, shifted down to bit zero.
///
/// Replaces upstream's `bit_field` dependency, which is 839 lines to say this.
/// Inclusive on both ends because that is how the specification writes a field
/// — "bits 8:0" — and a helper that made the reader translate would be a
/// helper that caused transcription errors rather than preventing them.
///
/// # Panics
///
/// Debug-only, on a range this type cannot hold. A release build cannot check
/// it and a wrong range is a programming error rather than a device condition.
#[must_use]
pub const fn bits32(value: u32, lo: u32, hi: u32) -> u32 {
    debug_assert!(lo <= hi && hi < 32);
    let width = hi - lo + 1;
    if width == 32 {
        value >> lo
    } else {
        (value >> lo) & ((1 << width) - 1)
    }
}

/// [`bits32`] for a 64-bit register.
///
/// # Panics
///
/// Debug-only, as [`bits32`].
#[must_use]
pub const fn bits64(value: u64, lo: u32, hi: u32) -> u64 {
    debug_assert!(lo <= hi && hi < 64);
    let width = hi - lo + 1;
    if width == 64 {
        value >> lo
    } else {
        (value >> lo) & ((1 << width) - 1)
    }
}

/// Whether bit `index` of `value` is set.
#[must_use]
pub const fn bit32(value: u32, index: u32) -> bool {
    value & (1 << index) != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_field_comes_out_shifted_down_to_zero() {
        // Bits 8..=18 of HCSPARAMS1 are the interrupter count. A value of 4
        // placed there must read back as 4, not as 4 << 8.
        assert_eq!(bits32(4 << 8, 8, 18), 4);
    }

    #[test]
    fn a_field_does_not_pick_up_its_neighbours() {
        // Every bit outside the range set, and none inside it.
        assert_eq!(bits32(!0 ^ (0b111 << 4), 4, 6), 0);
        // Every bit inside the range set, and none outside.
        assert_eq!(bits32(0b111 << 4, 4, 6), 0b111);
    }

    #[test]
    fn a_full_width_field_does_not_overflow_its_mask() {
        // `(1 << 32) - 1` overflows a u32 shift. The whole-register case is
        // handled separately for that reason, and this is the test that says
        // so -- without it the guard could be deleted and nothing would fail.
        assert_eq!(bits32(0xdead_beef, 0, 31), 0xdead_beef);
        assert_eq!(bits64(0xdead_beef_dead_beef, 0, 63), 0xdead_beef_dead_beef);
    }

    #[test]
    fn a_sixty_four_bit_field_crosses_the_word_boundary() {
        // DCBAAP's pointer is bits 6..=63: a field that spans both halves of
        // the register, which is where a 32-bit helper used by mistake would
        // silently truncate.
        assert_eq!(bits64(0xffff_ffff_ffff_ffc0, 6, 63), 0x03ff_ffff_ffff_ffff);
    }

    #[test]
    fn single_bits_read_as_themselves() {
        assert!(bit32(1 << 31, 31));
        assert!(!bit32(!(1 << 31), 31));
    }
}
