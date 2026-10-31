// SPDX-License-Identifier: Apache-2.0
//! Every floating-point image `bhaskix_personality::fpstate::check` accepts
//! is one the processor loads -- RFC 0094 step 3, checked on the build host.
//!
//! `rt_sigreturn` installs an image a hosted program wrote on its own stack,
//! and the kernel loads it at the thread's next switch; one the processor
//! refused would fault *in the switch path*. The check stands between the two,
//! and its rules were read in the instruction reference -- so this asks the
//! instruction itself. Images are drawn near the boundary the rules describe:
//! the initial image, then random bytes in `MXCSR`, `XSTATE_BV` and the header.
//! Each accepted one is loaded by `FXRSTOR`, by `XRSTOR` for x87|SSE, and by
//! `XRSTOR` for x87|SSE|AVX where the host enables AVX. A refused load is a
//! `#GP`, which arrives as `SIGSEGV`: the process dies and the run fails.
//!
//!     cargo run --release -- [images]      (default 2,000,000)
//!
//! Armed on 2026-10-31: with the check's `MXCSR` rule removed, the run dies
//! on the processor's `#GP` within its first thousand images.

use bhaskix_personality::fpstate;

/// An area aligned for `XSAVE`, which needs 64.
#[repr(C, align(64))]
struct Area([u8; 1024]);

/// xorshift64*: enough to wander the bits the rules care about, and no crate.
struct Draw(u64);

impl Draw {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
}

/// `XCR0` as the host enabled it.
fn host_xcr0() -> u64 {
    let (low, high): (u32, u32);
    // SAFETY: XGETBV with ECX 0 is defined wherever the OS set CR4.OSXSAVE,
    // which every x86-64 Linux host this runs on has done.
    unsafe {
        core::arch::asm!("xgetbv", in("ecx") 0u32, out("eax") low, out("edx") high, options(nomem, nostack));
    }
    (u64::from(high) << 32) | u64::from(low)
}

/// Loads `image` with the instruction for `layout` (0 = FXRSTOR, else the
/// XRSTOR mask), between a save and a restore of this process's own state.
fn load(image: &Area, layout: u64) {
    let mut own = Area([0; 1024]);
    // SAFETY: both areas are 64-aligned and 1024 bytes, more than any layout
    // here uses. The process's own state is saved first and restored last in
    // the same block -- with XSAVE for every layout, so AVX state survives an
    // XRSTOR of 0x7 -- so no compiled code runs while the image is loaded.
    unsafe {
        if layout == 0 {
            core::arch::asm!(
                "xsave64 [{own}]",
                "fxrstor64 [{image}]",
                "xrstor64 [{own}]",
                own = in(reg) own.0.as_mut_ptr(),
                image = in(reg) image.0.as_ptr(),
                in("eax") 0x7u32,
                in("edx") 0u32,
                options(nostack),
            );
        } else {
            core::arch::asm!(
                "xsave64 [{own}]",
                "xrstor64 [{image}]",
                "xrstor64 [{own}]",
                own = in(reg) own.0.as_mut_ptr(),
                image = in(reg) image.0.as_ptr(),
                in("eax") layout as u32,
                in("edx") 0u32,
                options(nostack),
            );
        }
    }
}

/// This host's `MXCSR_MASK`, as `FXSAVE` reports it.
fn mxcsr_mask() -> u32 {
    let mut own = Area([0; 1024]);
    // SAFETY: 512 bytes of a 64-aligned area; FXSAVE only writes it.
    unsafe { core::arch::asm!("fxsave64 [{}]", in(reg) own.0.as_mut_ptr(), options(nostack)) };
    u32::from_le_bytes([own.0[28], own.0[29], own.0[30], own.0[31]])
}

fn main() {
    let images: u64 = std::env::args()
        .nth(1)
        .and_then(|n| n.parse().ok())
        .unwrap_or(2_000_000);
    let host = host_xcr0();
    let mut layouts = vec![0u64, 0x3];
    if host & 0x7 == 0x7 {
        layouts.push(0x7);
    }
    let mask = mxcsr_mask();
    let mut draw = Draw(0x9e37_79b9_7f4a_7c15);
    let mut accepted = [0u64; 3];
    let mut refused = 0u64;
    for _ in 0..images {
        let mut image = Area([0; 1024]);
        fpstate::initial(&mut image.0);
        let roll = draw.next();
        // MXCSR: usually valid, sometimes one bit flipped -- chosen from the top
        // of the draw, apart from the bits that decide whether to flip, so
        // that every bit, reserved ones included, is reached.
        let flip = (1u32 << ((roll >> 56) % 32)) * u32::from(roll & 0x30 == 0);
        let mxcsr = 0x1f80u32 ^ flip;
        image.0[24..28].copy_from_slice(&mxcsr.to_le_bytes());
        // XSTATE_BV: a few low bits, sometimes one beyond them.
        let bv = (roll >> 8) & 0x7 | ((roll >> 16) & 0x1) << ((roll >> 24) % 10);
        image.0[512..520].copy_from_slice(&bv.to_le_bytes());
        // The header after it: usually clean, sometimes one byte set.
        if roll >> 40 & 0x7 == 0 {
            image.0[520 + ((roll >> 44) % 44) as usize] = (roll >> 52) as u8 | 1;
        }
        // And some of the register bytes, which no rule constrains.
        for _ in 0..4 {
            let at = 32 + (draw.next() % 400) as usize;
            image.0[at] = draw.next() as u8;
        }
        for (slot, &layout) in layouts.iter().enumerate() {
            let bytes = if layout == 0 {
                512
            } else if layout == 0x3 {
                576
            } else {
                832
            };
            if fpstate::check(&image.0[..bytes], layout, mask).is_ok() {
                load(&image, layout);
                accepted[slot] += 1;
            } else {
                refused += 1;
            }
        }
    }
    println!(
        "ok    {images} images: {} accepted for FXRSTOR, {} for XRSTOR x87|SSE{}, {refused} refused -- every accepted one loaded by the processor (host XCR0 {host:#x}, MXCSR_MASK {mask:#x})",
        accepted[0],
        accepted[1],
        if layouts.len() == 3 {
            format!(", {} for XRSTOR x87|SSE|AVX", accepted[2])
        } else {
            String::new()
        },
    );
}
