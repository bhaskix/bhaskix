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
//! - **Per-CPU GDT and TSS.** Both are still shared. That is safe only because
//!   secondary CPUs do not take interrupts yet; see `docs/scheduler.md`.

use core::sync::atomic::{AtomicU32, Ordering};

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

/// Claims the next free slot and installs it as this CPU's area.
///
/// Returns the dense CPU id, or `None` if [`MAX_CPUS`] is exhausted.
///
/// # Safety
///
/// Must be called exactly once per CPU, before anything reads `gs:`-relative
/// data on it.
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

        msr::write(IA32_GS_BASE, area.self_pointer);
    }

    Some(cpu_id)
}

/// This CPU's private area, or `None` before [`install`] has run on it.
#[must_use]
pub fn current() -> Option<&'static PerCpu> {
    let pointer: u64;
    // SAFETY: reads the first quadword of whatever `GS` points at. Before
    // `install` the base is zero, so this reads address 0 -- which is unmapped,
    // and would fault rather than return nonsense. That is why the base is set
    // as the last step of `install` and why nothing calls this before it.
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
