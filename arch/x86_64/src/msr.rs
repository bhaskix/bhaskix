// SPDX-License-Identifier: Apache-2.0
//! Model-specific registers.
//!
//! MSRs are the configuration surface for almost everything the CPU does that
//! is not expressible as an instruction: the APIC base, syscall entry points,
//! per-CPU bases, and the feature-enable bits in `EFER`.
//!
//! They are read and written 64 bits at a time through a pair of registers,
//! which is why every access here is a small assembly wrapper rather than
//! something the compiler can express.

/// `IA32_APIC_BASE` — Local APIC physical base address and enable bits.
pub const IA32_APIC_BASE: u32 = 0x1b;

/// `IA32_EFER` — extended feature enables, including NX.
pub const IA32_EFER: u32 = 0xc000_0080;
/// The `FS` segment base, which is where thread-local storage lives on
/// x86-64 — and what Linux's `arch_prctl(ARCH_SET_FS)` writes.
pub const IA32_FS_BASE: u32 = 0xc000_0100;

/// Reads a model-specific register.
///
/// # Safety
///
/// `register` must be an MSR this CPU implements. Reading an unimplemented MSR
/// raises a general protection fault, so the caller must have established the
/// register exists — through CPUID, or because it is architectural.
pub unsafe fn read(register: u32) -> u64 {
    let low: u32;
    let high: u32;
    // SAFETY: `rdmsr` reads the MSR named in ECX into EDX:EAX. It has no
    // memory effects. The caller guarantees the register exists on this CPU;
    // if it does not, this faults rather than misbehaving silently.
    unsafe {
        core::arch::asm!(
            "rdmsr",
            in("ecx") register,
            out("eax") low,
            out("edx") high,
            options(nomem, nostack, preserves_flags),
        );
    }
    ((high as u64) << 32) | (low as u64)
}

/// Writes a model-specific register.
///
/// # Safety
///
/// `register` must be an MSR this CPU implements, and `value` must be valid
/// for it. MSRs control fundamental CPU behaviour: a wrong value can disable
/// paging, relocate the APIC out from under the kernel, or fault immediately.
pub unsafe fn write(register: u32, value: u64) {
    let low = value as u32;
    let high = (value >> 32) as u32;
    // SAFETY: `wrmsr` writes EDX:EAX to the MSR named in ECX. The caller
    // guarantees both the register and the value are valid; the instruction
    // itself has no memory effects.
    unsafe {
        core::arch::asm!(
            "wrmsr",
            in("ecx") register,
            in("eax") low,
            in("edx") high,
            options(nomem, nostack, preserves_flags),
        );
    }
}

/// Result of a `cpuid` leaf.
#[derive(Clone, Copy, Debug)]
pub struct CpuidResult {
    /// EAX.
    pub eax: u32,
    /// EBX.
    pub ebx: u32,
    /// ECX.
    pub ecx: u32,
    /// EDX.
    pub edx: u32,
}

/// Executes `cpuid` for `leaf`.
///
/// Safe: `cpuid` cannot fault and has no side effects. An unsupported leaf
/// returns the highest supported leaf's data rather than failing, so callers
/// must check the maximum leaf first where that matters.
#[must_use]
pub fn cpuid(leaf: u32) -> CpuidResult {
    let (eax, ebx, ecx, edx);
    // SAFETY: `cpuid` is unprivileged, cannot fault, and has no memory
    // effects. RBX is callee-saved in the SysV ABI and cannot be named
    // directly as an operand, so it is preserved by hand around the
    // instruction.
    unsafe {
        core::arch::asm!(
            "mov {tmp:r}, rbx",
            "cpuid",
            "xchg {tmp:r}, rbx",
            tmp = out(reg) ebx,
            inout("eax") leaf => eax,
            inout("ecx") 0u32 => ecx,
            out("edx") edx,
            options(nostack, preserves_flags),
        );
    }
    CpuidResult { eax, ebx, ecx, edx }
}

/// Whether this CPU reports an integrated Local APIC.
#[must_use]
pub fn has_local_apic() -> bool {
    // CPUID leaf 1, EDX bit 9.
    cpuid(1).edx & (1 << 9) != 0
}

/// Hardware features the kernel's security guarantees depend on.
///
/// Reported at boot rather than assumed. `docs/security.md` §4 makes some of
/// these load-bearing — W^X is unenforceable without NX — so an operator needs
/// to see which ones are actually present on the machine in front of them,
/// not which ones the documentation hopes for.
#[derive(Clone, Copy, Debug)]
pub struct Features {
    /// Integrated Local APIC.
    pub apic: bool,
    /// x2APIC: MSR-addressed APIC, and >255 CPU addressing.
    pub x2apic: bool,
    /// No-execute page protection. W^X depends on it.
    pub nx: bool,
    /// Supervisor mode execution prevention.
    pub smep: bool,
    /// Supervisor mode access prevention.
    pub smap: bool,
    /// User-mode instruction prevention.
    pub umip: bool,
    /// 5-level paging.
    pub la57: bool,
    /// Invariant TSC: the timestamp counter does not vary with power state.
    pub invariant_tsc: bool,
    /// `RDRAND`: the machine can produce an unpredictable number.
    ///
    /// **RFC 0021**, and it is load-bearing in a way the others are not: this
    /// is the *only* source of unpredictability in the system. Without it a TCP
    /// sequence number is guessable, so `bin/tcpd` refuses to start rather than
    /// running with a weakness nobody can see. The machine still boots — a
    /// filesystem, a shell and a supervisor need no unpredictability at all.
    pub rdrand: bool,
}

/// Probes the features in [`Features`].
#[must_use]
pub fn features() -> Features {
    let leaf1 = cpuid(1);
    let leaf7 = cpuid(7);
    let extended = cpuid(0x8000_0001);
    let power = cpuid(0x8000_0007);

    Features {
        apic: leaf1.edx & (1 << 9) != 0,
        x2apic: leaf1.ecx & (1 << 21) != 0,
        nx: extended.edx & (1 << 20) != 0,
        smep: leaf7.ebx & (1 << 7) != 0,
        smap: leaf7.ebx & (1 << 20) != 0,
        umip: leaf7.ecx & (1 << 2) != 0,
        la57: leaf7.ecx & (1 << 16) != 0,
        invariant_tsc: power.edx & (1 << 8) != 0,
        // Asked of the crate that uses it rather than tested here, so the bit
        // position exists once. See this crate's manifest.
        rdrand: bhaskix_rand::available(),
    }
}
