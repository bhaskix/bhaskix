// SPDX-License-Identifier: Apache-2.0
//! The floating-point and vector state a switch saves -- RFC 0094.
//!
//! [RFC 0094](../../../docs/rfc/0094-a-programs-vector-registers-are-its-own.md):
//! a CPU that offers `XSAVE` saves and restores each thread's state with
//! `XSAVEOPT` (or `XSAVE`) and `XRSTOR`, the components named by `XCR0`; one
//! that does not keeps `FXSAVE` and `FXRSTOR`, exactly as before. Eager either
//! way: lazy switching lets one process read another's registers through
//! speculation (CVE-2018-3665), and `docs/scheduler.md` §6 records why.
//!
//! **What is enabled is chosen once, by the bootstrap CPU, and every CPU
//! applies the same choice** before it schedules anything: a thread migrated
//! to a CPU with a different `XCR0` would fault on its own state. The choice
//! is a pure function of what `CPUID` reported, host-tested below.

use core::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, Ordering};

use crate::msr::{cpuid, cpuid_count};

/// The components this kernel enables where they are offered: x87, SSE and
/// AVX -- RFC 0094 step 4 (2026-10-31), so a program built for x86-64-v3 runs.
///
/// AVX-512 (bits 5-7) waits on its trigger by the lead's decision of
/// 2026-10-30: the first program or distribution that assumes x86-64-v4. A
/// CPU that offers `XSAVE` without AVX -- QEMU 4.2.1's TCG `max` -- gets x87
/// and SSE through `XSAVE`, as step 2 gave every CPU.
pub const WANTED: u64 = 0x7;

/// Bytes a thread's area holds: the standard format with x87, SSE and AVX --
/// 512 of legacy region, 64 of header, 256 of AVX upper halves at 576, as
/// `CPUID` reports them on every machine read (2026-10-30). A plan needing
/// more is refused rather than trusted.
pub const CAPACITY: u32 = 832;

/// The legacy region and the header: what any `XSAVE` image occupies.
const BASE: u32 = 576;

/// How the state is saved.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Switch {
    /// No `XSAVE` on this CPU: `FXSAVE`/`FXRSTOR`, 512 bytes.
    Fxsave = 0,
    /// `XSAVE`/`XRSTOR`, where `XSAVEOPT` is absent.
    Xsave = 1,
    /// `XSAVEOPT`/`XRSTOR`.
    Xsaveopt = 2,
}

impl Switch {
    /// The instruction's name, as the boot report prints it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Fxsave => "fxsave",
            Self::Xsave => "xsave",
            Self::Xsaveopt => "xsaveopt",
        }
    }
}

/// What `CPUID` said, as the choice needs it.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Offered {
    /// `CPUID.1:ECX[26]`.
    pub xsave: bool,
    /// `CPUID.(0Dh,1):EAX[0]`.
    pub xsaveopt: bool,
    /// `CPUID.(0Dh,0):EDX:EAX`, the components `XCR0` may enable.
    pub components: u64,
    /// `CPUID.(0Dh,0):ECX`, bytes for all of them.
    pub all_bytes: u32,
    /// For each component `i` from 2 to 9, where its state ends in the
    /// standard format: `CPUID.(0Dh,i)` offset (`EBX`) plus size (`EAX`).
    pub ends: [u32; 8],
}

/// What this kernel will do with the state.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Plan {
    /// The instructions.
    pub switch: Switch,
    /// `XCR0`, or zero for `FXSAVE`.
    pub xcr0: u64,
    /// Bytes of each thread's area the instructions use.
    pub bytes: u32,
}

/// Decides the plan from what the CPU offered. Pure.
#[must_use]
pub fn choose(offered: &Offered) -> Plan {
    let fxsave = Plan {
        switch: Switch::Fxsave,
        xcr0: 0,
        bytes: 512,
    };
    // x87 and SSE are architectural on x86-64; a CPU that reports `XSAVE`
    // without them is reporting something this code does not understand.
    if !offered.xsave || offered.components & 0x3 != 0x3 {
        return fxsave;
    }
    let xcr0 = offered.components & WANTED;
    let bytes = (2..10)
        .filter(|bit| xcr0 & (1 << bit) != 0)
        .map(|bit| offered.ends[bit - 2])
        .fold(BASE, u32::max);
    if bytes > CAPACITY {
        return fxsave;
    }
    Plan {
        switch: if offered.xsaveopt {
            Switch::Xsaveopt
        } else {
            Switch::Xsave
        },
        xcr0,
        bytes,
    }
}

/// Reads [`Offered`] from this CPU.
#[must_use]
pub fn offered() -> Offered {
    let xsave = cpuid(1).ecx & (1 << 26) != 0;
    if !xsave || cpuid(0).eax < 0xd {
        return Offered::default();
    }
    let zero = cpuid_count(0xd, 0);
    let mut ends = [0u32; 8];
    for (slot, end) in ends.iter_mut().enumerate() {
        let leaf = cpuid_count(0xd, slot as u32 + 2);
        *end = leaf.ebx.saturating_add(leaf.eax);
    }
    Offered {
        xsave,
        xsaveopt: cpuid_count(0xd, 1).eax & 1 != 0,
        components: (u64::from(zero.edx) << 32) | u64::from(zero.eax),
        all_bytes: zero.ecx,
        ends,
    }
}

/// The plan every CPU applies, once the bootstrap CPU has chosen it.
static SWITCH: AtomicU8 = AtomicU8::new(Switch::Fxsave as u8);
static XCR0: AtomicU64 = AtomicU64::new(0);
static BYTES: AtomicU32 = AtomicU32::new(512);

/// Which `MXCSR` bits this processor lets software set, as `FXSAVE` reports
/// it at byte 28 -- read once by [`adopt`]. Zero means it did not say.
static MXCSR_MASK: AtomicU32 = AtomicU32::new(0);

/// The processor's `MXCSR_MASK`, for checking an image before it is loaded.
#[must_use]
pub fn mxcsr_mask() -> u32 {
    MXCSR_MASK.load(Ordering::Acquire)
}

/// Makes `plan` the one every CPU applies and every switch uses, and reads
/// this processor's `MXCSR_MASK`.
///
/// # Safety
///
/// On the bootstrap CPU, after [`crate::cpu::enable_sse`] -- `FXSAVE` needs
/// it -- and before any other CPU starts or anything is scheduled.
pub unsafe fn adopt(plan: Plan) {
    #[repr(align(16))]
    struct Legacy([u8; 512]);
    let mut legacy = Legacy([0; 512]);
    // SAFETY: 512 bytes, 16-byte aligned, and SSE is enabled per the contract.
    unsafe { crate::cpu::fx_save(legacy.0.as_mut_ptr()) };
    let mut mask = [0u8; 4];
    mask.copy_from_slice(&legacy.0[28..32]);
    MXCSR_MASK.store(u32::from_le_bytes(mask), Ordering::Release);

    XCR0.store(plan.xcr0, Ordering::Release);
    BYTES.store(plan.bytes, Ordering::Release);
    SWITCH.store(plan.switch as u8, Ordering::Release);
}

/// The plan in force.
#[must_use]
pub fn plan() -> Plan {
    Plan {
        switch: match SWITCH.load(Ordering::Acquire) {
            1 => Switch::Xsave,
            2 => Switch::Xsaveopt,
            _ => Switch::Fxsave,
        },
        xcr0: XCR0.load(Ordering::Acquire),
        bytes: BYTES.load(Ordering::Acquire),
    }
}

/// `CR4.OSXSAVE`.
const CR4_OSXSAVE: u64 = 1 << 18;

/// Whether `CR4.OSXSAVE` is set on this CPU.
#[must_use]
pub fn osxsave_live() -> bool {
    // SAFETY: reading CR4 at CPL 0.
    unsafe { crate::cpu::read_cr4() & CR4_OSXSAVE != 0 }
}

/// Applies the plan in force to this CPU and reads it back.
///
/// **`CR4.OSXSAVE` is set to the plan, not left as found**: for `FXSAVE` it
/// is cleared, so a firmware that set it cannot hand this CPU an AVX the
/// switch does not save. For `XSAVE`, `XCR0` is written and read back, and
/// the size `CPUID` now reports for it must be the plan's.
///
/// # Safety
///
/// During this CPU's initialisation, after [`crate::cpu::enable_sse`] and
/// before anything is scheduled here.
pub unsafe fn enable() -> bool {
    let plan = plan();
    // SAFETY: CR4 at CPL 0, during init, changing only OSXSAVE.
    unsafe {
        let cr4 = crate::cpu::read_cr4();
        let wanted = if plan.switch == Switch::Fxsave {
            cr4 & !CR4_OSXSAVE
        } else {
            cr4 | CR4_OSXSAVE
        };
        if wanted != cr4 {
            core::arch::asm!("mov cr4, {}", in(reg) wanted, options(nostack, preserves_flags));
        }
    }
    if plan.switch == Switch::Fxsave {
        return !osxsave_live();
    }
    // SAFETY: OSXSAVE is set; XCR0 holds x87 and SSE at least, which every
    // CPU offering XSAVE accepts, and the plan was chosen from this CPU's
    // own report of what it accepts.
    unsafe {
        core::arch::asm!(
            "xsetbv",
            in("ecx") 0u32,
            in("eax") plan.xcr0 as u32,
            in("edx") (plan.xcr0 >> 32) as u32,
            options(nostack, preserves_flags),
        );
    }
    xcr0() == plan.xcr0 && cpuid_count(0xd, 0).ebx == plan.bytes
}

/// `XCR0`, read with `XGETBV`. Zero where `OSXSAVE` is clear, which is when
/// the instruction would fault.
#[must_use]
pub fn xcr0() -> u64 {
    if !osxsave_live() {
        return 0;
    }
    let (low, high): (u32, u32);
    // SAFETY: OSXSAVE is set, so XGETBV with ECX 0 is defined.
    unsafe {
        core::arch::asm!(
            "xgetbv",
            in("ecx") 0u32,
            out("eax") low,
            out("edx") high,
            options(nomem, nostack, preserves_flags),
        );
    }
    (u64::from(high) << 32) | u64::from(low)
}

/// Saves this CPU's state into `area` by the plan in force.
///
/// # Safety
///
/// `area` must be [`CAPACITY`] bytes and 64-byte aligned, and this CPU must
/// have run [`enable`].
pub unsafe fn save(area: *mut u8) {
    let xcr0 = XCR0.load(Ordering::Relaxed);
    // SAFETY: delegated to this function's contract; the mask is the XCR0
    // every CPU applied.
    unsafe {
        match SWITCH.load(Ordering::Relaxed) {
            2 => core::arch::asm!(
                "xsaveopt64 [{}]",
                in(reg) area,
                in("eax") xcr0 as u32,
                in("edx") (xcr0 >> 32) as u32,
                options(nostack, preserves_flags),
            ),
            1 => core::arch::asm!(
                "xsave64 [{}]",
                in(reg) area,
                in("eax") xcr0 as u32,
                in("edx") (xcr0 >> 32) as u32,
                options(nostack, preserves_flags),
            ),
            _ => crate::cpu::fx_save(area),
        }
    }
}

/// Restores this CPU's state from `area` by the plan in force.
///
/// # Safety
///
/// As [`save`], and `area` must hold an image this plan's instruction
/// accepts: one [`save`] wrote, or one checked against the rules
/// `bhaskix_personality::fpstate::check` encodes.
pub unsafe fn restore(area: *const u8) {
    let xcr0 = XCR0.load(Ordering::Relaxed);
    // SAFETY: delegated to this function's contract.
    unsafe {
        if SWITCH.load(Ordering::Relaxed) == Switch::Fxsave as u8 {
            crate::cpu::fx_restore(area);
        } else {
            core::arch::asm!(
                "xrstor64 [{}]",
                in(reg) area,
                in("eax") xcr0 as u32,
                in("edx") (xcr0 >> 32) as u32,
                options(nostack, preserves_flags),
            );
        }
    }
}

/// The names of the components in `mask`, for the boot report.
pub fn names(mask: u64, mut put: impl FnMut(&'static str)) {
    const NAMES: [(u32, &str); 11] = [
        (0, "x87"),
        (1, "sse"),
        (2, "avx"),
        (3, "bndregs"),
        (4, "bndcsr"),
        (5, "opmask"),
        (6, "zmm_hi256"),
        (7, "hi16_zmm"),
        (9, "pkru"),
        (17, "xtilecfg"),
        (18, "xtiledata"),
    ];
    for (bit, name) in NAMES {
        if mask & (1 << bit) != 0 {
            put(name);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What CPUID leaf 0xD reported on this host's Xeon Silver 4314 under
    /// Linux, 2026-10-30: components 0x2e7; AVX at 576 for 256, opmask at
    /// 1088 for 64, ZMM_Hi256 at 1152 for 512, Hi16_ZMM at 1664 for 1024,
    /// PKRU at 2688 for 8.
    fn ice_lake() -> Offered {
        Offered {
            xsave: true,
            xsaveopt: true,
            components: 0x2e7,
            all_bytes: 2696,
            ends: [832, 0, 0, 1152, 1664, 2688, 0, 2696],
        }
    }

    #[test]
    fn a_cpu_without_xsave_keeps_fxsave() {
        let plan = choose(&Offered::default());
        assert_eq!(
            plan,
            Plan {
                switch: Switch::Fxsave,
                xcr0: 0,
                bytes: 512
            }
        );
    }

    #[test]
    fn a_cpu_with_avx_gets_x87_sse_and_avx_through_xsaveopt() {
        let plan = choose(&ice_lake());
        assert_eq!(
            plan,
            Plan {
                switch: Switch::Xsaveopt,
                xcr0: 0x7,
                bytes: 832
            }
        );
    }

    #[test]
    fn a_cpu_with_xsave_and_no_avx_keeps_x87_and_sse() {
        // QEMU 4.2.1's TCG `max`, as its `xstate` line read on 2026-10-30:
        // x87, SSE, MPX and PKRU, and no AVX.
        let offered = Offered {
            components: 0x21b,
            ends: [0; 8],
            ..ice_lake()
        };
        assert_eq!(
            choose(&offered),
            Plan {
                switch: Switch::Xsaveopt,
                xcr0: 0x3,
                bytes: 576
            }
        );
    }

    #[test]
    fn xsave_is_used_where_xsaveopt_is_absent() {
        let offered = Offered {
            xsaveopt: false,
            ..ice_lake()
        };
        assert_eq!(choose(&offered).switch, Switch::Xsave);
    }

    #[test]
    fn a_report_without_x87_and_sse_is_not_trusted() {
        let offered = Offered {
            components: 0x4,
            ..ice_lake()
        };
        assert_eq!(choose(&offered).switch, Switch::Fxsave);
    }

    #[test]
    fn what_is_enabled_is_never_more_than_wanted() {
        // AVX-512 offered, AVX-512 not taken: the lead's decision.
        assert_eq!(choose(&ice_lake()).xcr0 & !WANTED, 0);
    }

    #[test]
    fn the_names_follow_the_bits() {
        let mut seen = [""; 8];
        let mut at = 0;
        names(0x2e7, |name| {
            seen[at] = name;
            at += 1;
        });
        assert_eq!(
            &seen[..at],
            &[
                "x87",
                "sse",
                "avx",
                "opmask",
                "zmm_hi256",
                "hi16_zmm",
                "pkru"
            ]
        );
    }
}
