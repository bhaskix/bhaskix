// SPDX-License-Identifier: Apache-2.0
//! Per-CPU data.
//!
//! Every CPU needs somewhere to keep state that is *its own* — which CPU it
//! is, what it is running, its idle stack — reachable without a lock and
//! without knowing its own index first. That last part is the difficulty: a
//! table indexed by CPU id is useless until you know the id, and finding the
//! id by asking the APIC costs a memory-mapped read on the hot path.
//!
//! x86-64 solves it with a segment base. `GS` has a 64-bit base held in an
//! MSR, and `gs:`-prefixed accesses add it automatically, so `gs:[0]` reaches
//! a different structure on every CPU with no branch and no lookup.
//!
//! The structure begins with a pointer to itself. That looks redundant and is
//! not: `gs:[0]` can *read through* the base but there is no instruction to
//! read the base itself at CPL 0, so recovering an ordinary pointer to the
//! area means storing one where a `gs:` read can find it.
//!
//! # Not yet
//!
//! - **`swapgs`.** When user mode arrives in M5, `GS` will hold a user value
//!   on kernel entry and the kernel base will live in `IA32_KERNEL_GS_BASE`,
//!   swapped on every transition. Getting that wrong in either direction is a
//!   privilege-escalation bug, so it lands with the syscall path, not before.
//! - **`IA32_KERNEL_GS_BASE` as a scratch slot.** The kernel base is written
//!   directly to `IA32_GS_BASE` today. Once `swapgs` lands, the two MSRs
//!   change roles on every kernel entry and exit, and every path that reloads
//!   `GS` has to know which of them it is disturbing.

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use crate::cell::BootCell;
use crate::msr;

/// `IA32_GS_BASE` — the base address `gs:` accesses are relative to.
const IA32_GS_BASE: u32 = 0xc000_0101;

/// Most CPUs supported. Bhaskix is not addressing 256-CPU machines yet, and a
/// fixed table keeps this allocation-free — per-CPU state that cannot be
/// established because the heap is busy would be a poor foundation.
pub const MAX_CPUS: usize = 64;

/// One CPU's private state.
///
/// `#[repr(C)]` and the self-pointer first are load-bearing: the offset of
/// that field is baked into the assembly in [`current`].
#[repr(C, align(64))]
pub struct PerCpu {
    /// Address of this structure, readable as `gs:[0]`.
    self_pointer: u64,
    /// Dense index, 0 for the bootstrap CPU.
    pub cpu_id: u32,
    /// Local APIC identifier, which is *not* dense and may skip values.
    pub lapic_id: u32,
    /// Set once this CPU has finished bringing itself up.
    pub online: bool,
}

impl PerCpu {
    const fn new() -> Self {
        Self {
            self_pointer: 0,
            cpu_id: 0,
            lapic_id: 0,
            online: false,
        }
    }
}

static AREAS: BootCell<[PerCpu; MAX_CPUS]> = BootCell::new([const { PerCpu::new() }; MAX_CPUS]);

/// CPUs that have completed bring-up.
static ONLINE: AtomicU32 = AtomicU32::new(0);

/// Whether *any* CPU has installed an area yet.
///
/// Guards the `gs:` read in [`current`]. Before the first install the GS base
/// is zero, so reading `gs:[0]` dereferences address zero and page-faults —
/// and the caller is usually an interrupt handler, which makes it a fault
/// while handling a fault. This flag turns that into an ordinary `None`.
///
/// It is deliberately global rather than per-CPU, and that is only sound
/// because of the second check below. A CPU that has not yet run [`activate`]
/// has a zero base no matter what other CPUs have done, so this flag alone
/// would let it through once any *other* CPU had installed. What actually
/// makes the read safe is that a zero base makes `gs:[0]` read address zero,
/// which is unmapped in every address space — so the null test catches it. The
/// flag only avoids the fault during the window before the very first area
/// exists, when there is no `None` to return yet.
static ANY_INSTALLED: AtomicBool = AtomicBool::new(false);

/// Claims a slot and fills in this CPU's area, **without** activating it.
///
/// Splitting claim from activation is not tidiness. Loading *any* selector
/// into `GS` — including the null selector, which is exactly what reloading
/// the GDT does — resets `GS.base` to zero. So a CPU that sets its base and
/// then loads its descriptor tables silently loses it, and the next
/// `gs:`-relative read dereferences address zero.
///
/// The two steps therefore bracket the GDT load: claim, load the GDT,
/// [`activate`]. Anything else is a null dereference waiting for a reorder.
///
/// Returns the dense CPU id, or `None` if [`MAX_CPUS`] is exhausted.
///
/// # Safety
///
/// Must be called exactly once per CPU.
pub unsafe fn install(lapic_id: u32) -> Option<u32> {
    // A plain atomic increment hands out slots, so two CPUs racing here cannot
    // receive the same one. This is the first place in the kernel where that
    // matters -- every earlier allocation happened while one CPU ran.
    let cpu_id = ONLINE.fetch_add(1, Ordering::AcqRel);
    if cpu_id as usize >= MAX_CPUS {
        return None;
    }

    // SAFETY: `cpu_id` was claimed exclusively by the exchange above, so no
    // other CPU writes this element. The table is a `static` that never moves.
    unsafe {
        let areas = AREAS.get_mut();
        let area = &mut areas[cpu_id as usize];
        area.self_pointer = (&raw const *area) as u64;
        area.cpu_id = cpu_id;
        area.lapic_id = lapic_id;
        area.online = true;
    }

    Some(cpu_id)
}

/// Points `GS` at this CPU's area.
///
/// Must run **after** the last thing that loads a segment selector into `GS`,
/// which in practice means after the GDT is loaded. See [`install`].
///
/// # Safety
///
/// `cpu_id` must be the value [`install`] returned on this CPU, and nothing
/// may load a `GS` selector afterwards without calling this again.
pub unsafe fn activate(cpu_id: u32) {
    if cpu_id as usize >= MAX_CPUS {
        return;
    }
    // SAFETY: this CPU owns the element `install` claimed for it; the table is
    // a `static` that never moves.
    unsafe {
        let area = &AREAS.get()[cpu_id as usize];
        msr::write(IA32_GS_BASE, area.self_pointer);
    }
    ANY_INSTALLED.store(true, Ordering::Release);
}

/// This CPU's private area, or `None` before [`install`] has run on it.
#[must_use]
pub fn current() -> Option<&'static PerCpu> {
    if !ANY_INSTALLED.load(Ordering::Acquire) {
        return None;
    }

    let pointer: u64;
    // SAFETY: reads the first quadword of whatever `GS` points at. Every CPU
    // runs `activate` with interrupts disabled and before anything on it can
    // call in here, so a base is either established or still zero -- and zero
    // is the case the `ANY_INSTALLED` guard covers.
    unsafe {
        core::arch::asm!(
            "mov {}, gs:[0]",
            out(reg) pointer,
            options(nostack, preserves_flags, readonly)
        );
    }
    if pointer == 0 {
        return None;
    }
    // SAFETY: the value came from `self_pointer`, which `install` set to the
    // address of a `static` element that outlives the program.
    Some(unsafe { &*(pointer as *const PerCpu) })
}

/// This CPU's dense identifier, or 0 if per-CPU data is not up yet.
#[must_use]
pub fn cpu_id() -> u32 {
    current().map_or(0, |area| area.cpu_id)
}

/// How many CPUs have completed bring-up.
#[must_use]
pub fn online_count() -> u32 {
    ONLINE.load(Ordering::Acquire).min(MAX_CPUS as u32)
}

/// The local APIC identifier of `cpu_id`, if that CPU is online.
///
/// Needed to send a CPU an interrupt: the dense index is a kernel convenience
/// and means nothing to the hardware, which addresses processors by APIC id —
/// and the two are not interchangeable, because APIC ids are not dense and
/// routinely skip values.
#[must_use]
pub fn lapic_id_of(cpu_id: u32) -> Option<u32> {
    let count = online_count() as usize;
    // SAFETY: elements below `count` were fully written by `install` before
    // the counter that publishes them was incremented, and never change again.
    let areas = unsafe { AREAS.get() };
    areas
        .iter()
        .take(count)
        .find(|area| area.online && area.cpu_id == cpu_id)
        .map(|area| area.lapic_id)
}

/// Runs `f` for each online CPU: `(cpu_id, lapic_id)`.
pub fn for_each_online(mut f: impl FnMut(u32, u32)) {
    let count = online_count() as usize;
    // SAFETY: elements below `count` were fully written by `install` before
    // the counter that publishes them was incremented, and are never mutated
    // again.
    let areas = unsafe { AREAS.get() };
    for area in areas.iter().take(count) {
        if area.online {
            f(area.cpu_id, area.lapic_id);
        }
    }
}
