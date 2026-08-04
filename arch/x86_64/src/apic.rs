// SPDX-License-Identifier: Apache-2.0
//! Local APIC and its timer.
//!
//! The Local APIC is the per-CPU interrupt controller. It replaces the legacy
//! PIC entirely ([`crate::pic`]), and it is what makes SMP possible at all —
//! inter-processor interrupts go through it, so M4's CPU bring-up depends on
//! this module existing.
//!
//! For M2 it provides two things: a per-CPU timer, and the end-of-interrupt
//! acknowledgement that every delivered interrupt needs.
//!
//! # Two ways to reach it
//!
//! The APIC has two register interfaces, and which one is available decides
//! how much else has to exist first:
//!
//! - **xAPIC** is memory-mapped, conventionally at physical `0xfee0_0000`.
//!   Reaching it needs that page mapped, and the bootloader's direct map does
//!   not cover it — it maps RAM, and the APIC is not RAM. So xAPIC needs the
//!   memory manager that arrives in M3.
//! - **x2APIC** is addressed through MSRs. No mapping, no memory manager, no
//!   dependency on anything M2 does not already have.
//!
//! So x2APIC is the preferred path, and not only for convenience: it is also
//! required to address more than 255 CPUs, which M4's SMP bring-up will need.
//! xAPIC remains implemented for hardware without x2APIC, and returns
//! [`ApicError::NeedsMmuForXapic`] until M3 can map the page.
//!
//! Registers are 32 bits wide in both modes. In xAPIC they must be accessed as
//! aligned 32-bit values; a 64-bit access does not do half of what you would
//! expect, it faults.

use core::sync::atomic::{AtomicPtr, AtomicU8, AtomicU32, Ordering};

use crate::msr;
use crate::port::Port;

// Register offsets from the APIC base.
const REG_ID: usize = 0x020;
const REG_VERSION: usize = 0x030;
const REG_EOI: usize = 0x0b0;
const REG_SPURIOUS: usize = 0x0f0;
const REG_LVT_TIMER: usize = 0x320;
const REG_LVT_LINT0: usize = 0x350;
const REG_LVT_LINT1: usize = 0x360;
const REG_LVT_ERROR: usize = 0x370;
const REG_TIMER_INITIAL: usize = 0x380;
const REG_TIMER_CURRENT: usize = 0x390;
const REG_TIMER_DIVIDE: usize = 0x3e0;
const REG_ICR_LOW: usize = 0x300;
const REG_ICR_HIGH: usize = 0x310;

/// Interrupt command: deliver to every CPU except the sender.
///
/// A shorthand, so no destination has to be computed. That matters for
/// correctness as much as convenience — building a destination mask means
/// knowing every APIC id, and a mask that is stale by one CPU produces a
/// shootdown that silently misses a processor.
const ICR_ALL_EXCLUDING_SELF: u32 = 0b11 << 18;
/// Fixed delivery to the destination in the ICR's high half, level assert.
const ICR_FIXED_ASSERT: u32 = 1 << 14;

/// Set while an IPI is still being delivered. xAPIC only; in x2APIC the write
/// is serialising and the bit does not exist.
const ICR_DELIVERY_PENDING: u32 = 1 << 12;

/// `IA32_APIC_BASE` bit 11: global enable. Clearing it is irreversible until
/// reset on most parts, which is why nothing here ever clears it.
const APIC_BASE_ENABLE: u64 = 1 << 11;
/// `IA32_APIC_BASE` bit 10: x2APIC mode. Enabling it is likewise one-way.
const APIC_BASE_X2APIC: u64 = 1 << 10;

/// Base MSR of the x2APIC register block.
///
/// An xAPIC register at byte offset `n` is MSR `X2APIC_MSR_BASE + (n >> 4)`,
/// because the memory-mapped registers are spaced 16 bytes apart.
const X2APIC_MSR_BASE: u32 = 0x800;
/// Mask selecting the physical base address from `IA32_APIC_BASE`.
const APIC_BASE_ADDRESS_MASK: u64 = 0xffff_ffff_f000;

/// Spurious-vector register bit 8: software enable.
const SPURIOUS_ENABLE: u32 = 1 << 8;

/// LVT bit 16: mask this interrupt source.
const LVT_MASKED: u32 = 1 << 16;
/// LVT timer mode bits 17-18: periodic.
const LVT_TIMER_PERIODIC: u32 = 1 << 17;

/// Divide configuration for divide-by-16.
///
/// The encoding is not contiguous — bit 2 is skipped — so this is the raw
/// value, not the number 16.
const TIMER_DIVIDE_16: u32 = 0b0011;

/// Vector the APIC timer is delivered on.
pub const TIMER_VECTOR: u8 = 0x20;
/// Vector reserved for spurious APIC interrupts.
///
/// Conventionally the highest vector. Some older parts ignore the low four
/// bits of this field, so a value with all four set avoids the question.
pub const SPURIOUS_VECTOR: u8 = 0xff;
/// Vector for the APIC's internal error reporting.
pub const ERROR_VECTOR: u8 = 0xfe;

/// Which register interface [`init`] selected.
mod mode {
    /// Not yet initialised.
    pub const UNINITIALISED: u8 = 0;
    /// MSR-addressed.
    pub const X2APIC: u8 = 1;
    /// Memory-mapped.
    pub const XAPIC: u8 = 2;
}

static MODE: AtomicU8 = AtomicU8::new(mode::UNINITIALISED);

/// Mapped base address of the Local APIC in xAPIC mode; null in x2APIC mode.
static BASE: AtomicPtr<u8> = AtomicPtr::new(core::ptr::null_mut());

/// Whether this CPU supports x2APIC. CPUID leaf 1, ECX bit 21.
#[must_use]
pub fn has_x2apic() -> bool {
    msr::cpuid(1).ecx & (1 << 21) != 0
}

/// Measured APIC timer frequency, in ticks per second, after division.
static TICKS_PER_SECOND: AtomicU32 = AtomicU32::new(0);

/// Reads an APIC register.
///
/// # Safety
///
/// [`init`] must have run, and `offset` must be a valid register offset.
unsafe fn read(offset: usize) -> u32 {
    // SAFETY: `init` established the mode and, in xAPIC mode, a base pointer
    // to the mapped APIC page. `offset` is one of the constants above, all
    // within 4 KiB. Registers are volatile and 32 bits wide in both modes.
    unsafe {
        if MODE.load(Ordering::Acquire) == mode::X2APIC {
            msr::read(X2APIC_MSR_BASE + (offset >> 4) as u32) as u32
        } else {
            BASE.load(Ordering::Acquire)
                .add(offset)
                .cast::<u32>()
                .read_volatile()
        }
    }
}

/// Writes an APIC register.
///
/// # Safety
///
/// [`init`] must have run, `offset` must be a valid register offset, and
/// `value` must be meaningful for it.
unsafe fn write(offset: usize, value: u32) {
    // SAFETY: as `read`. The write is volatile because it has a device-visible
    // effect the compiler must not reorder or elide.
    unsafe {
        if MODE.load(Ordering::Acquire) == mode::X2APIC {
            msr::write(X2APIC_MSR_BASE + (offset >> 4) as u32, u64::from(value));
        } else {
            BASE.load(Ordering::Acquire)
                .add(offset)
                .cast::<u32>()
                .write_volatile(value);
        }
    }
}

/// Why [`init`] failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApicError {
    /// CPUID reports no integrated Local APIC.
    NotSupported,
    /// The measured timer frequency was implausible, so calibration failed.
    CalibrationFailed,
    /// Only xAPIC is available, and its register page cannot be mapped until
    /// the memory manager exists in M3.
    NeedsMmuForXapic,
}

/// The physical base address the firmware assigned to the Local APIC.
///
/// Read before mapping, so the kernel knows what to map.
///
/// # Safety
///
/// The CPU must have a Local APIC; check [`msr::has_local_apic`] first.
#[must_use]
pub unsafe fn physical_base() -> u64 {
    // SAFETY: `IA32_APIC_BASE` is architectural on every CPU that reports an
    // APIC through CPUID, which the caller guarantees.
    unsafe { msr::read(msr::IA32_APIC_BASE) & APIC_BASE_ADDRESS_MASK }
}

/// Enables the Local APIC and calibrates its timer.
///
/// `mapped_base` must be the virtual address at which [`physical_base`] is
/// mapped. Interrupts must still be disabled: this leaves the timer armed but
/// masked, and the caller decides when to enable delivery.
///
/// # Errors
///
/// Returns [`ApicError::NotSupported`] if the CPU has no Local APIC, or
/// [`ApicError::CalibrationFailed`] if the timer frequency could not be
/// measured plausibly.
///
/// # Safety
///
/// Must be called once, on the bootstrap CPU, with interrupts disabled, and
/// `mapped_base` must address the APIC's 4 KiB register page.
pub unsafe fn init(mapped_base: Option<*mut u8>) -> Result<u32, ApicError> {
    if !msr::has_local_apic() {
        return Err(ApicError::NotSupported);
    }

    // SAFETY: single-threaded boot with interrupts disabled, and any supplied
    // `mapped_base` addresses the APIC page per the caller's obligation.
    unsafe {
        let base_msr = msr::read(msr::IA32_APIC_BASE);

        if has_x2apic() {
            // Set both enable bits in one write. The manual forbids the
            // intermediate state where x2APIC is set but the global enable is
            // not, so this cannot be split into two writes.
            msr::write(
                msr::IA32_APIC_BASE,
                base_msr | APIC_BASE_ENABLE | APIC_BASE_X2APIC,
            );
            MODE.store(mode::X2APIC, Ordering::Release);
        } else {
            let Some(base) = mapped_base else {
                return Err(ApicError::NeedsMmuForXapic);
            };
            BASE.store(base, Ordering::Release);
            MODE.store(mode::XAPIC, Ordering::Release);
            // Preserve the rest of the MSR, particularly the base address:
            // overwriting it would move the APIC out from under the mapping we
            // were just given.
            msr::write(msr::IA32_APIC_BASE, base_msr | APIC_BASE_ENABLE);
        }

        // Software-enable, and point spurious interrupts at a vector we own.
        write(REG_SPURIOUS, SPURIOUS_ENABLE | u32::from(SPURIOUS_VECTOR));

        // Mask everything we are not using yet. The LINT lines in particular:
        // on a machine where firmware wired the legacy timer or NMI through
        // them, leaving them unmasked delivers interrupts nobody handles.
        write(REG_LVT_TIMER, LVT_MASKED);
        write(REG_LVT_LINT0, LVT_MASKED);
        write(REG_LVT_LINT1, LVT_MASKED);
        write(REG_LVT_ERROR, u32::from(ERROR_VECTOR));

        let frequency = calibrate()?;
        TICKS_PER_SECOND.store(frequency, Ordering::Release);
        Ok(frequency)
    }
}

/// Measures the APIC timer frequency against the PIT.
///
/// The APIC timer counts at a rate nobody reports: it is derived from the bus
/// or core clock and varies by machine, and on many parts CPUID does not
/// disclose it. So it has to be measured against a clock whose frequency *is*
/// fixed — and the 8254 PIT, at exactly 1.193182 MHz since 1981, is that
/// clock.
///
/// PIT channel 2 is used rather than channel 0 because it is the only one
/// whose output can be polled directly, through port 0x61, without needing an
/// interrupt handler. Channel 2 was wired to the PC speaker; the speaker is
/// deliberately left disconnected here so the calibration is silent.
///
/// # Safety
///
/// Interrupts must be disabled and the APIC must be enabled.
unsafe fn calibrate() -> Result<u32, ApicError> {
    /// PIT input frequency, in hertz. Fixed by the original PC design.
    const PIT_FREQUENCY: u32 = 1_193_182;
    /// Calibrate over 50 ms. Long enough to swamp measurement noise, short
    /// enough not to be noticeable at boot.
    const CALIBRATION_MS: u32 = 50;
    const PIT_COUNT: u32 = PIT_FREQUENCY / (1000 / CALIBRATION_MS);

    let tsc_start: u64;
    let tsc_elapsed: u64;

    let pit_control: Port<u8> = Port::new(0x43);
    let pit_channel2: Port<u8> = Port::new(0x42);
    let speaker_gate: Port<u8> = Port::new(0x61);

    // SAFETY: these are the architectural PIT and NMI-status-register ports.
    // The caller guarantees interrupts are disabled, so nothing else can be
    // driving them concurrently.
    let elapsed = unsafe {
        // Enable channel 2's gate, but leave the speaker data line clear so
        // nothing is audible.
        let gate = speaker_gate.read();
        speaker_gate.write((gate & !0x02) | 0x01);

        // Channel 2, access low then high byte, mode 0 (interrupt on terminal
        // count) -- mode 0 drives the output line high when the count expires,
        // which is exactly the edge being polled.
        pit_control.write(0b1011_0000);
        pit_channel2.write((PIT_COUNT & 0xff) as u8);
        pit_channel2.write((PIT_COUNT >> 8) as u8);

        // Restart the count by toggling the gate low then high.
        let gate = speaker_gate.read() & !0x01;
        speaker_gate.write(gate);
        speaker_gate.write(gate | 0x01);

        // Start the APIC timer from its maximum and let it count down.
        write(REG_TIMER_DIVIDE, TIMER_DIVIDE_16);
        write(REG_TIMER_INITIAL, u32::MAX);

        // The same window measures the time-stamp counter. Opening a second
        // one would mean programming the PIT twice and adding 50 ms to every
        // boot for a number this window already contains.
        tsc_start = crate::tsc::read();

        // Poll the PIT output bit. Bounded, so a machine whose PIT never
        // asserts fails calibration instead of hanging the boot -- the same
        // rule the serial driver follows.
        let mut spins: u64 = 0;
        const SPIN_LIMIT: u64 = 1_000_000_000;
        while speaker_gate.read() & 0x20 == 0 {
            spins += 1;
            if spins >= SPIN_LIMIT {
                write(REG_LVT_TIMER, LVT_MASKED);
                return Err(ApicError::CalibrationFailed);
            }
            core::hint::spin_loop();
        }

        let remaining = read(REG_TIMER_CURRENT);
        tsc_elapsed = crate::tsc::read().saturating_sub(tsc_start);
        write(REG_LVT_TIMER, LVT_MASKED);

        u32::MAX - remaining
    };

    // Scale to a second. Published only if plausible: real parts run between
    // roughly 100 MHz and 10 GHz, and a scheduler accounting slices against a
    // wrong rate is worse than one that reports it has no clock.
    let tsc_hertz = (tsc_elapsed).saturating_mul(u64::from(1000 / CALIBRATION_MS));
    if (100_000_000..=10_000_000_000).contains(&tsc_hertz) {
        crate::tsc::set_hertz(tsc_hertz);
    }

    // Scale the measurement up to a full second, accounting for the divisor.
    let ticks_per_second = (elapsed as u64)
        .saturating_mul(1000 / u64::from(CALIBRATION_MS))
        .saturating_mul(16);

    // A plausibility check rather than blind trust. Real APIC timers run
    // between roughly 10 MHz and a few GHz; anything outside that means the
    // measurement is wrong, and an arbitrary tick rate is worse than an
    // honest failure.
    if !(1_000_000..=100_000_000_000).contains(&ticks_per_second) {
        return Err(ApicError::CalibrationFailed);
    }

    Ok((ticks_per_second / 16) as u32)
}

/// Arms the timer to fire once, after `count` timer ticks.
///
/// One-shot rather than periodic is what makes ticklessness possible at all: a
/// periodic timer interrupts on a schedule the kernel chose once at boot,
/// whereas a one-shot timer is re-armed after every interrupt for exactly as
/// long as the next thing that needs attention. A CPU with nothing to do
/// simply is not armed.
///
/// # Safety
///
/// [`init`] must have run and there must be an IDT gate for [`TIMER_VECTOR`].
pub unsafe fn arm_oneshot(count: u32) {
    // SAFETY: the APIC is initialised per the caller's obligation.
    unsafe {
        write(REG_TIMER_DIVIDE, TIMER_DIVIDE_16);
        // Mode bits clear: one-shot. Writing the initial count starts it.
        write(REG_LVT_TIMER, u32::from(TIMER_VECTOR));
        write(REG_TIMER_INITIAL, count.max(1));
    }
}

/// Stops the timer entirely. Nothing will fire until it is armed again.
///
/// # Safety
///
/// [`init`] must have run. The caller is responsible for arranging some other
/// way to be woken — on an otherwise idle CPU that means an inter-processor
/// interrupt, and without one the CPU sleeps until the machine is reset.
pub unsafe fn disarm_timer() {
    // SAFETY: the APIC is initialised per the caller's obligation.
    unsafe {
        write(REG_TIMER_INITIAL, 0);
        write(REG_LVT_TIMER, LVT_MASKED);
    }
}

/// Timer ticks per second, as measured at boot, or `None` before calibration.
#[must_use]
pub fn timer_hertz() -> Option<u32> {
    match TICKS_PER_SECOND.load(Ordering::Acquire) {
        0 => None,
        hertz => Some(hertz),
    }
}

/// Starts the timer at `hertz`, delivering on [`TIMER_VECTOR`].
///
/// # Safety
///
/// [`init`] must have succeeded, and the IDT must have a handler installed for
/// [`TIMER_VECTOR`] that issues an [`end_of_interrupt`].
pub unsafe fn start_timer(hertz: u32) {
    // SAFETY: the APIC is enabled and calibrated per the caller's obligation.
    unsafe {
        let count = TICKS_PER_SECOND.load(Ordering::Acquire) / hertz.max(1);
        write(REG_TIMER_DIVIDE, TIMER_DIVIDE_16);
        write(REG_LVT_TIMER, u32::from(TIMER_VECTOR) | LVT_TIMER_PERIODIC);
        write(REG_TIMER_INITIAL, count.max(1));
    }
}

/// Acknowledges the interrupt currently being serviced.
///
/// Every delivered interrupt needs exactly one of these, and **spurious
/// interrupts need none** — sending one for an interrupt the APIC never put
/// in service clears a different interrupt's in-service bit, which loses a
/// real interrupt and is close to impossible to debug afterwards.
///
/// # Safety
///
/// [`init`] must have run. Call once per delivered interrupt, from within its
/// handler.
pub unsafe fn end_of_interrupt() {
    // SAFETY: the EOI register accepts any value; writing zero is the
    // documented acknowledgement.
    unsafe { write(REG_EOI, 0) };
}

/// This CPU's APIC identifier.
///
/// # Safety
///
/// [`init`] must have run.
#[must_use]
pub unsafe fn id() -> u32 {
    // SAFETY: `init` has run per the caller's obligation.
    unsafe {
        let raw = read(REG_ID);
        // xAPIC keeps the 8-bit ID in the top byte; x2APIC uses the whole
        // 32-bit register. Reading one as the other silently yields a wrong
        // CPU identity, which would misroute every IPI in M4.
        if MODE.load(Ordering::Acquire) == mode::X2APIC {
            raw
        } else {
            raw >> 24
        }
    }
}

/// Whether the APIC is running in x2APIC mode.
#[must_use]
pub fn in_x2apic_mode() -> bool {
    MODE.load(Ordering::Acquire) == mode::X2APIC
}

/// The APIC's version register value.
///
/// # Safety
///
/// [`init`] must have run.
#[must_use]
pub unsafe fn version() -> u32 {
    // SAFETY: `init` has run per the caller's obligation.
    unsafe { read(REG_VERSION) & 0xff }
}

/// Enables the calling CPU's Local APIC.
///
/// Every CPU has its own APIC with its own register file, but they are reached
/// through the same MSRs or the same physical page — so the mode and base
/// established by [`init`] on the bootstrap CPU apply here unchanged, and only
/// the per-CPU enable bits need setting.
///
/// # Safety
///
/// [`init`] must have completed on the bootstrap CPU, and this must run once
/// per secondary CPU with interrupts disabled.
pub unsafe fn enable_this_cpu() {
    // SAFETY: `init` established the mode; the registers below belong to the
    // calling CPU's own APIC.
    unsafe {
        let base = msr::read(msr::IA32_APIC_BASE);
        if MODE.load(Ordering::Acquire) == mode::X2APIC {
            msr::write(
                msr::IA32_APIC_BASE,
                base | APIC_BASE_ENABLE | APIC_BASE_X2APIC,
            );
        } else {
            msr::write(msr::IA32_APIC_BASE, base | APIC_BASE_ENABLE);
        }

        write(REG_SPURIOUS, SPURIOUS_ENABLE | u32::from(SPURIOUS_VECTOR));
        write(REG_LVT_TIMER, LVT_MASKED);
        write(REG_LVT_LINT0, LVT_MASKED);
        write(REG_LVT_LINT1, LVT_MASKED);
        write(REG_LVT_ERROR, u32::from(ERROR_VECTOR));
    }
}

/// Writes the whole 64-bit x2APIC interrupt command register.
///
/// The generic register write is 32 bits, which is right for every other
/// register but cannot express a targeted send: in x2APIC the destination and
/// the command are one MSR, written together, and that write is what sends.
///
/// # Safety
///
/// The CPU must be in x2APIC mode.
unsafe fn write_icr64(value: u64) {
    // SAFETY: the caller guarantees x2APIC mode, where the ICR is a single
    // writable MSR at the base plus the register's index.
    unsafe { msr::write(X2APIC_MSR_BASE + (REG_ICR_LOW >> 4) as u32, value) };
}

/// Sends `vector` to the CPU with local APIC id `target`.
///
/// The x2APIC path takes a 32-bit destination; the xAPIC path only has eight
/// bits, so an id above 255 cannot be addressed and is refused rather than
/// silently truncated into somebody else's.
///
/// # Safety
///
/// As [`send_ipi_all_but_self`]: the APIC must be initialised and the target
/// must have an IDT gate for `vector`.
pub unsafe fn send_ipi(target: u32, vector: u8) -> bool {
    let command = ICR_FIXED_ASSERT | u32::from(vector);

    // SAFETY: the APIC is initialised per the caller's obligation.
    unsafe {
        if in_x2apic_mode() {
            write_icr64((u64::from(target) << 32) | u64::from(command));
        } else {
            if target > 0xff {
                return false;
            }
            // High half first: writing the low half is what sends, so the
            // other order sends with a stale destination.
            write(REG_ICR_HIGH, target << 24);
            write(REG_ICR_LOW, command);

            let mut spins = 0u32;
            while read(REG_ICR_LOW) & ICR_DELIVERY_PENDING != 0 && spins < 1_000_000 {
                spins += 1;
                core::hint::spin_loop();
            }
        }
    }
    true
}

/// Sends `vector` to every CPU except this one.
///
/// # Safety
///
/// [`init`] must have run, and every CPU that could receive this must have an
/// IDT gate for `vector` — an IPI delivered to a CPU with no handler is a
/// general protection fault on that CPU, reported nowhere useful.
pub unsafe fn send_ipi_all_but_self(vector: u8) {
    let command = ICR_ALL_EXCLUDING_SELF | u32::from(vector);

    // SAFETY: the APIC is initialised per the caller's obligation.
    unsafe {
        if in_x2apic_mode() {
            // One 64-bit MSR write, which is architecturally serialising, so
            // there is nothing to poll afterwards.
            write(REG_ICR_LOW, command);
        } else {
            // The high half must be written first: writing the low half is
            // what actually sends, so doing it in the other order sends with a
            // stale destination.
            write(REG_ICR_HIGH, 0);
            write(REG_ICR_LOW, command);

            // Bounded wait for delivery. A dead APIC must not hang the sender.
            let mut spins = 0u32;
            while read(REG_ICR_LOW) & ICR_DELIVERY_PENDING != 0 && spins < 1_000_000 {
                spins += 1;
                core::hint::spin_loop();
            }
        }
    }
}
