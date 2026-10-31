// SPDX-License-Identifier: Apache-2.0
//! Coverage-guided fuzzing of the check a signal frame's floating-point image
//! passes before the kernel installs it -- RFC 0094 step 3.
//!
//! **The untrusted input is a hosted program's stack.** `rt_sigreturn` reads
//! the image a frame's `fpstate` names, which the handler may have rewritten
//! byte for byte, and the kernel loads it at the thread's next switch. An image
//! the processor refused would fault *in the switch path*, so
//! `bhaskix_personality::fpstate::check` stands between the two.
//!
//! # What counts as a failure
//!
//! A panic, and **an image the check accepts that breaks one of the
//! instruction's rules as restated here**, independently: long enough for its
//! layout; `MXCSR` within the processor's mask; for `XSAVE`, `XSTATE_BV` within
//! `XCR0` and header bytes 8..24 zero. A slip in the check's offsets or its
//! logic shows up as a disagreement between the two.
//!
//! **What this cannot see is a rule restated wrongly in both places.** That is
//! what loading every accepted image with the real `XRSTOR` catches, and it is
//! `tools/fpstate-hw` (`make check-fpstate-hw`, in `make test` and CI): a crate
//! of its own, because this one's `unsafe` budget is zero by rule -- a target
//! that can produce its own crashes makes a finding mean nothing until its
//! cause is known.
//!
//! The first byte chooses the layout: even for `FXSAVE` (`XCR0` of zero), odd
//! for `XSAVE` with x87 and SSE; the next four, the `MXCSR_MASK` a processor
//! might report, zero included.
#![no_main]

use bhaskix_personality::fpstate;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&choice, rest)) = data.split_first() else {
        return;
    };
    let Some((mask, image)) = rest.split_first_chunk::<4>() else {
        return;
    };
    let mask = u32::from_le_bytes(*mask);
    let xcr0: u64 = if choice & 1 == 0 { 0 } else { 0x3 };
    if fpstate::check(image, xcr0, mask).is_err() {
        return;
    }

    // Accepted: every rule, restated.
    let needed = if xcr0 == 0 {
        fpstate::LEGACY
    } else {
        fpstate::LEGACY + fpstate::HEADER
    };
    assert!(
        image.len() >= needed,
        "accepted an image shorter than its layout"
    );
    let mxcsr = u32::from_le_bytes(image[24..28].try_into().unwrap());
    let allowed = if mask == 0 {
        fpstate::DEFAULT_MXCSR_MASK
    } else {
        mask
    };
    assert_eq!(
        mxcsr & !allowed,
        0,
        "accepted an MXCSR with a reserved bit set"
    );
    if xcr0 != 0 {
        let bv = u64::from_le_bytes(image[512..520].try_into().unwrap());
        assert_eq!(bv & !xcr0, 0, "accepted a component XCR0 does not enable");
        assert!(
            image[520..536].iter().all(|byte| *byte == 0),
            "accepted a dirty header"
        );
    }
});
