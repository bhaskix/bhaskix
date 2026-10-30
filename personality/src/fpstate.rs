// SPDX-License-Identifier: Apache-2.0
//! The floating-point image a switch saves and a signal frame carries --
//! [RFC 0094](../../docs/rfc/0094-a-programs-vector-registers-are-its-own.md),
//! as arithmetic.
//!
//! Two layouts, one prefix. `FXSAVE`'s 512 bytes -- the x87 registers, `MXCSR`
//! and `xmm0`-`xmm15` -- are the first 512 of `XSAVE`'s standard format, which
//! adds a 64-byte header and, from byte 576, the components `XCR0` enables.
//! Linux's signal frame carries the same image behind `sigcontext.fpstate`,
//! and marks an `XSAVE` one with two magic numbers so that a handler can tell
//! which it was given. Every offset here was compiled from this host's
//! `<asm/sigcontext.h>` on 2026-10-30, not recalled.
//!
//! **What `XRSTOR` and `FXRSTOR` refuse, as a function**, because the kernel
//! loads an image a hosted program wrote on its own stack, and an image the
//! instruction refuses would fault *in the switch path*, long after the call
//! that installed it. The rules are the instructions' own, read 2026-10-30 in
//! the instruction reference derived from Intel's SDM:
//!
//! * standard-form `XRSTOR` faults if `XSTATE_BV` sets a bit `XCR0` does not,
//!   or if bytes 8..24 of the header are not zero;
//! * both fault on an attempt to set a reserved bit of `MXCSR`, which `XRSTOR`
//!   loads whenever SSE or AVX is requested -- whatever `XSTATE_BV` says.

/// Bytes `FXSAVE` writes, and the legacy region of an `XSAVE` image.
pub const LEGACY: usize = 512;
/// The `XSAVE` header that follows the legacy region.
pub const HEADER: usize = 64;
/// The x87 control word, at the start of the legacy region.
pub const FCW: usize = 0;
/// `MXCSR`, in the legacy region.
pub const MXCSR: usize = 24;
/// Which `MXCSR` bits this processor lets software set, as `FXSAVE` reports.
pub const MXCSR_MASK: usize = 28;
/// `XSTATE_BV`: the components the image holds. A clear bit is a component
/// in its initial state, which `XRSTOR` initialises rather than reads.
pub const XSTATE_BV: usize = LEGACY;
/// Linux's `sw_reserved` bytes, in the legacy region: how a frame says an
/// `XSAVE` image follows.
pub const SW_RESERVED: usize = 464;
/// `FP_XSTATE_MAGIC1`.
pub const MAGIC1: u32 = 0x4650_5853;
/// `FP_XSTATE_MAGIC2`, written just after an `XSAVE` image in a frame.
pub const MAGIC2: u32 = 0x4650_5845;
/// The x87 control word after `FNINIT`.
pub const INITIAL_FCW: u16 = 0x037f;
/// Every SSE exception masked, rounding to nearest.
pub const INITIAL_MXCSR: u32 = 0x1f80;
/// The `MXCSR` mask assumed when a processor reports zero. **Recalled, not
/// read**: the SDM's text on `FXSAVE` gives it as every bit of the low half
/// but DAZ. Every processor this system has met reports its own, which the
/// kernel reads at boot; this is the safe direction if one does not.
pub const DEFAULT_MXCSR_MASK: u32 = 0xffbf;

/// Why an image was refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Refused {
    /// Shorter than the layout it claims.
    Short,
    /// `MXCSR` sets a bit the processor reserves.
    Mxcsr,
    /// `XSTATE_BV` names a component `XCR0` does not enable.
    Component,
    /// Header bytes 8..24 -- `XCOMP_BV` and the word after it -- not zero:
    /// a compacted image, or not an image at all.
    Header,
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    let mut word = [0u8; 4];
    word.copy_from_slice(&bytes[at..at + 4]);
    u32::from_le_bytes(word)
}

fn u64_at(bytes: &[u8], at: usize) -> u64 {
    let mut word = [0u8; 8];
    word.copy_from_slice(&bytes[at..at + 8]);
    u64::from_le_bytes(word)
}

/// Whether the processor would load `image` without faulting: by `XRSTOR`
/// with `xcr0` as its mask when `xcr0` is not zero, and by `FXRSTOR` when it
/// is. `mxcsr_mask` is what the processor reported, zero meaning it did not.
///
/// # Errors
///
/// The first rule the image breaks, as [`Refused`].
pub fn check(image: &[u8], xcr0: u64, mxcsr_mask: u32) -> Result<(), Refused> {
    let needed = if xcr0 == 0 { LEGACY } else { LEGACY + HEADER };
    if image.len() < needed {
        return Err(Refused::Short);
    }
    let mask = if mxcsr_mask == 0 {
        DEFAULT_MXCSR_MASK
    } else {
        mxcsr_mask
    };
    if u32_at(image, MXCSR) & !mask != 0 {
        return Err(Refused::Mxcsr);
    }
    if xcr0 != 0 {
        if u64_at(image, XSTATE_BV) & !xcr0 != 0 {
            return Err(Refused::Component);
        }
        if image[LEGACY + 8..LEGACY + 24].iter().any(|byte| *byte != 0) {
            return Err(Refused::Header);
        }
    }
    Ok(())
}

/// Writes the image a thread starts with into `into`: `FCW` and `MXCSR` at
/// their initial values and everything else zero, which for an `XSAVE` image
/// is a header saying every component is in its initial state.
pub fn initial(into: &mut [u8]) {
    into.fill(0);
    if into.len() >= LEGACY {
        into[FCW..FCW + 2].copy_from_slice(&INITIAL_FCW.to_le_bytes());
        into[MXCSR..MXCSR + 4].copy_from_slice(&INITIAL_MXCSR.to_le_bytes());
    }
}

/// Marks an `XSAVE` image of `size` bytes as Linux marks one in a signal
/// frame: `sw_reserved` says so, and `MAGIC2` follows the image -- so `frame`
/// must hold `size + 4` bytes.
///
/// # Errors
///
/// [`Refused::Short`] if it does not.
pub fn mark(frame: &mut [u8], xcr0: u64, size: u32) -> Result<(), Refused> {
    let end = size as usize;
    if end < LEGACY + HEADER || frame.len() < end + 4 {
        return Err(Refused::Short);
    }
    let sw = SW_RESERVED;
    frame[sw..sw + 4].copy_from_slice(&MAGIC1.to_le_bytes());
    frame[sw + 4..sw + 8].copy_from_slice(&(size + 4).to_le_bytes());
    frame[sw + 8..sw + 16].copy_from_slice(&xcr0.to_le_bytes());
    frame[sw + 16..sw + 20].copy_from_slice(&size.to_le_bytes());
    frame[end..end + 4].copy_from_slice(&MAGIC2.to_le_bytes());
    Ok(())
}

/// How many bytes of `XSAVE` image a frame's `fpstate` says it holds, or
/// `None` for a plain `FXSAVE` image -- the question `rt_sigreturn` asks.
/// Both magics must agree, and the size must fit what was read, as Linux
/// requires before it trusts the extended state.
#[must_use]
pub fn marked_size(frame: &[u8]) -> Option<usize> {
    if frame.len() < LEGACY || u32_at(frame, SW_RESERVED) != MAGIC1 {
        return None;
    }
    let size = u32_at(frame, SW_RESERVED + 16) as usize;
    let extended = u32_at(frame, SW_RESERVED + 4) as usize;
    if size < LEGACY + HEADER || extended != size + 4 || frame.len() < size + 4 {
        return None;
    }
    (u32_at(frame, size) == MAGIC2).then_some(size)
}

#[cfg(test)]
mod tests {
    use super::*;

    const XCR0: u64 = 0x3;

    fn image() -> [u8; 832] {
        let mut image = [0u8; 832];
        initial(&mut image);
        image
    }

    #[test]
    fn the_initial_image_is_one_both_instructions_accept() {
        let image = image();
        assert_eq!(check(&image, XCR0, 0xffff), Ok(()));
        assert_eq!(
            check(&image, 0, 0xffff),
            Ok(()),
            "and FXRSTOR, its first 512 bytes"
        );
        assert_eq!(u32_at(&image, MXCSR), 0x1f80);
        assert_eq!(&image[0..2], &[0x7f, 0x03]);
    }

    #[test]
    fn a_reserved_mxcsr_bit_is_refused() {
        let mut image = image();
        image[MXCSR + 2] = 1; // bit 16
        assert_eq!(check(&image, XCR0, 0xffff), Err(Refused::Mxcsr));
        // DAZ, bit 6: allowed where the processor says so, refused where it
        // reported no mask at all.
        let mut daz = self::image();
        daz[MXCSR] |= 0x40;
        assert_eq!(check(&daz, XCR0, 0xffff), Ok(()));
        assert_eq!(check(&daz, XCR0, 0), Err(Refused::Mxcsr));
    }

    #[test]
    fn a_component_xcr0_does_not_enable_is_refused() {
        let mut image = image();
        image[XSTATE_BV] = 0x7; // AVX, with XCR0 x87|SSE
        assert_eq!(check(&image, XCR0, 0xffff), Err(Refused::Component));
        assert_eq!(
            check(&image, 0x7, 0xffff),
            Ok(()),
            "and accepted once it is"
        );
    }

    #[test]
    fn a_compacted_or_dirty_header_is_refused() {
        for at in [LEGACY + 8, LEGACY + 15, LEGACY + 16, LEGACY + 23] {
            let mut image = image();
            image[at] = 0x80;
            assert_eq!(
                check(&image, XCR0, 0xffff),
                Err(Refused::Header),
                "byte {at}"
            );
        }
        // Bytes 24..64 are not checked by the instruction's standard form,
        // and so not here: refusing more than the hardware would turn a frame
        // Linux accepts into a fault this system invented.
        let mut image = image();
        image[LEGACY + 40] = 1;
        assert_eq!(check(&image, XCR0, 0xffff), Ok(()));
    }

    #[test]
    fn short_images_are_refused() {
        assert_eq!(check(&[0u8; 511], 0, 0xffff), Err(Refused::Short));
        assert_eq!(check(&[0u8; 575], XCR0, 0xffff), Err(Refused::Short));
    }

    #[test]
    fn a_marked_frame_says_its_size_and_an_unmarked_one_does_not() {
        let mut frame = [0u8; 836];
        initial(&mut frame[..832]);
        assert_eq!(marked_size(&frame), None, "an FXSAVE image");
        mark(&mut frame, 0x7, 832).expect("room for MAGIC2");
        assert_eq!(marked_size(&frame), Some(832));
        // Offsets as `<asm/sigcontext.h>` puts them, compiled 2026-10-30:
        // magic1 at sw_reserved + 0, extended_size + 4, xfeatures + 8,
        // xstate_size + 16.
        assert_eq!(u32_at(&frame, 464), MAGIC1);
        assert_eq!(u32_at(&frame, 468), 836);
        assert_eq!(u64_at(&frame, 472), 0x7);
        assert_eq!(u32_at(&frame, 480), 832);
        assert_eq!(u32_at(&frame, 832), MAGIC2);
        // A frame whose second magic is gone is not trusted with its size.
        frame[832] ^= 1;
        assert_eq!(marked_size(&frame), None);
    }
}
