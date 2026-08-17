// SPDX-License-Identifier: Apache-2.0
//! A view of a ring the program owns and mapped itself.
//!
//! The stream lives in the program's pages (RFC 0022 step 4b): byte `k` of
//! the stream sits at `k` modulo the ring's size, and the fastest wait in
//! this system is reading one's own memory until the byte is there
//! (RFC 0020's attribution instrument measured the alternative at half the
//! round trip). This type is that lesson as a value: one `unsafe` at
//! construction, where the mapping claim lives, and every access after it
//! safe and bounded by the modulus.

use crate::time::Pace;
use crate::wait::news;

/// One mapped ring: a base address the program attached, and the ring's
/// size in bytes. Offsets wrap by the modulus, so no access can leave it.
#[derive(Clone, Copy, Debug)]
pub struct RingView {
    base: u64,
    bytes: u64,
}

impl RingView {
    /// A view of `bytes` bytes mapped at `base`.
    ///
    /// # Safety
    ///
    /// `base..base + bytes` must be this program's own mapping — attached
    /// before this call and never unmapped while the view lives. The one
    /// claim the crate cannot check is the one the constructor carries.
    #[must_use]
    pub const unsafe fn new(base: u64, bytes: u64) -> Self {
        assert!(bytes != 0, "a ring of nothing is not a ring");
        Self { base, bytes }
    }

    /// Reads the byte at stream offset `at`, wrapped by the ring.
    #[must_use]
    pub fn read(&self, at: u64) -> u8 {
        // SAFETY: the constructor's contract — the program's own mapping —
        // and the modulus keeps the offset inside it.
        unsafe { core::ptr::read_volatile((self.base + at % self.bytes) as *const u8) }
    }

    /// Writes the byte at stream offset `at`, wrapped by the ring.
    pub fn write(&self, at: u64, byte: u8) {
        // SAFETY: as in `read`; the mapping is the program's own and
        // writable by the same contract.
        unsafe { core::ptr::write_volatile((self.base + at % self.bytes) as *mut u8, byte) };
    }

    /// Blocks until `expected` appears at stream offset `at`, waking on the
    /// connection's notification with an armed deadline as the lost-wake
    /// backstop. Zero IPC calls until the byte is present — the ring itself
    /// says when the data is here, because TCP delivers in order into
    /// memory the program owns. Returns `false` if `tries` wakes pass
    /// without it.
    #[must_use]
    pub fn wait_for(&self, at: u64, expected: u8, wake_slot: u64, pace: &Pace, tries: u32) -> bool {
        for _ in 0..tries {
            if self.read(at) == expected {
                return true;
            }
            news(wake_slot, pace);
        }
        false
    }
}
