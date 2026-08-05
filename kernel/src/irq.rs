// SPDX-License-Identifier: Apache-2.0
//! Device interrupts: finding the I/O APIC and routing a line to a vector.
//!
//! The kernel could be interrupted by its own timer and by other CPUs since
//! M2. Nothing a *device* did could reach it, because the path a device
//! interrupt takes — pin, I/O APIC, vector, local APIC — was missing its
//! middle. This module is that middle, and M6-04's console input is its first
//! customer.
//!
//! # One chip, on the bootstrap CPU
//!
//! Everything here runs once, during boot, on the bootstrap CPU. The chip is
//! programmed through a non-atomic index/data pair (see
//! `bhaskix_arch::ioapic`), so concurrent programming would interleave; making
//! it single-threaded by construction is simpler and costs nothing, because
//! routing decisions are made at bring-up and not afterwards.
//!
//! The window address is kept in an atomic and the chip rebuilt around it per
//! call, rather than held in a lock. A lock would have to be ranked, and its
//! rank would be a claim about ordering against the scheduler that this
//! module — which programs hardware at boot and is never touched again — has
//! no reason to make.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use bhaskix_arch::acpi;
use bhaskix_arch::ioapic::IoApic;
use bhaskix_boot::PhysAddr;
use bhaskix_mm::FRAME_SIZE;

/// Makes `length` bytes at `physical` readable through the direct map.
///
/// ACPI tables are not always somewhere the bootloader mapped. The RSDP on a
/// BIOS machine sits in the legacy area below one megabyte, which the memory
/// map calls reserved — so the first version of this code faulted on it during
/// boot, at an address that looked entirely plausible.
fn ensure_mapped(physical: u64, length: usize, hhdm: u64) -> bool {
    crate::mmio::map(physical, length as u64, hhdm).is_some()
}

/// Virtual address of the chip's register window, or zero.
static WINDOW: AtomicU64 = AtomicU64::new(0);
/// The first global interrupt the chip is responsible for.
static GSI_BASE: AtomicU32 = AtomicU32::new(0);
/// Inputs the chip reported.
static INPUTS: AtomicU32 = AtomicU32::new(0);

/// Why interrupt routing could not be brought up.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum IrqError {
    /// The bootloader reported no ACPI tables.
    NoTables,
    /// The tables held no I/O APIC.
    NoIoApic,
    /// The register window could not be mapped.
    MapFailed,
    /// The heap was not available to allocate a page table from.
    NoHeap,
    /// The chip refused the redirection.
    NotRouted,
    /// Nothing has been brought up.
    NotPresent,
    /// The destination CPU's APIC id does not fit a physical destination.
    UnreachableCpu,
}

/// What bring-up found.
#[derive(Clone, Copy, Debug)]
pub struct Report {
    /// Physical address of the chip that was claimed.
    pub address: u32,
    /// How many inputs it has.
    pub inputs: u32,
    /// Interrupt source overrides the firmware declared.
    pub overrides: usize,
    /// I/O APICs the firmware declared, of which the first is used.
    pub chips: usize,
    /// Whether the firmware's table was longer than this kernel will read.
    pub truncated: bool,
}

/// Finds the I/O APIC and maps its registers.
///
/// # Errors
///
/// [`IrqError`] naming what was missing. Every one of them is survivable: the
/// kernel runs without device interrupts, it just cannot be typed at.
///
/// # Safety
///
/// Must be called once, on the bootstrap CPU, after the heap exists. `rsdp`
/// must be the address the bootloader reported and `hhdm` the direct map base.
pub unsafe fn init(rsdp: Option<PhysAddr>, hhdm: u64) -> Result<Report, IrqError> {
    let rsdp = rsdp.ok_or(IrqError::NoTables)?;

    // SAFETY: the caller guarantees these came from the handoff; the walk maps
    // every byte it reads through the closure before reading it.
    let madt = unsafe {
        acpi::madt(rsdp.as_u64(), hhdm, &mut |physical, length| {
            ensure_mapped(physical, length, hhdm)
        })
    }
    .ok_or(IrqError::NoTables)?;
    let entry = madt.io_apic().ok_or(IrqError::NoIoApic)?;

    let physical = u64::from(entry.address);

    // Mapped rather than assumed present: the window is a register page, and
    // the direct map covers memory.
    let window = crate::mmio::map(physical, FRAME_SIZE, hhdm).ok_or(IrqError::MapFailed)?;

    // SAFETY: `window` is the mapping just made of this chip's registers, and
    // this is the only code that touches it.
    let chip = unsafe { IoApic::new(window as *mut u8, entry.gsi_base) };

    INPUTS.store(chip.inputs(), Ordering::Relaxed);
    GSI_BASE.store(chip.gsi_base(), Ordering::Relaxed);
    // Published last: a non-zero window is what every other function here
    // takes as "the chip is ready", so it must not be visible before the
    // values describing it are.
    WINDOW.store(window, Ordering::Release);

    Ok(Report {
        address: entry.address,
        inputs: chip.inputs(),
        overrides: madt.overrides(),
        chips: madt.io_apics_seen,
        truncated: madt.truncated,
    })
}

/// Rebuilds the chip, if there is one.
fn chip() -> Option<IoApic> {
    let window = WINDOW.load(Ordering::Acquire);
    if window == 0 {
        return None;
    }
    // SAFETY: `window` was mapped by `init` and is never unmapped; the gsi
    // base was published before the window. Rebuilding is sound because the
    // type holds no state beyond these -- it reads the chip for anything else.
    Some(unsafe { IoApic::new(window as *mut u8, GSI_BASE.load(Ordering::Relaxed)) })
}

/// Routes a legacy ISA interrupt to `vector` on the CPU with `apic_id`.
///
/// The interrupt number is translated through the firmware's overrides first.
/// Skipping that step is the classic way to program an input nothing is wired
/// to and then debug a device that "raises no interrupts".
///
/// # Errors
///
/// [`IrqError`] if there is no chip, the CPU cannot be a physical destination,
/// or the chip refused the input.
///
/// # Safety
///
/// There must be an IDT gate for `vector` whose handler acknowledges the local
/// APIC. From the moment this returns, interrupts arrive.
pub unsafe fn route_isa(
    rsdp: Option<PhysAddr>,
    hhdm: u64,
    irq: u8,
    vector: u8,
    apic_id: u32,
) -> Result<u32, IrqError> {
    let mut chip = chip().ok_or(IrqError::NotPresent)?;
    let rsdp = rsdp.ok_or(IrqError::NoTables)?;
    // SAFETY: as `init`; the tables were mapped there and are not unmapped.
    let madt = unsafe {
        acpi::madt(rsdp.as_u64(), hhdm, &mut |physical, length| {
            ensure_mapped(physical, length, hhdm)
        })
    }
    .ok_or(IrqError::NoTables)?;
    let routing = madt.route(irq);

    let destination = u8::try_from(apic_id).map_err(|_| IrqError::UnreachableCpu)?;

    // SAFETY: the caller guarantees a handler for `vector`; the chip is the
    // one `init` mapped, and this runs on the bootstrap CPU only.
    unsafe {
        if let Some(handle) = crate::iommu::remap_interrupt(None, vector, destination) {
            chip.route_remapped(routing.gsi, handle, vector, routing.level)
        } else if crate::iommu::remapping() {
            // See `route_gsi`: no fallback once the old format is blocked.
            Err(bhaskix_arch::ioapic::IoApicError::NoSuchInput)
        } else {
            chip.route(
                routing.gsi,
                vector,
                destination,
                routing.active_low,
                routing.level,
            )
        }
    }
    .map_err(|_| IrqError::NotRouted)?;

    Ok(routing.gsi)
}

/// Routes an already-translated global interrupt to `vector`.
///
/// The counterpart to [`route_isa`], which translates an ISA number through
/// the firmware's overrides first. A caller that already has a GSI — because
/// it took one from a claim — must not translate it again: an override applied
/// twice programs an input nothing is wired to.
///
/// # Errors
///
/// [`IrqError`] if there is no chip, or it refused the input.
///
/// # Safety
///
/// As [`route_isa`].
pub unsafe fn route_gsi(
    _rsdp: Option<PhysAddr>,
    _hhdm: u64,
    gsi: u32,
    vector: u8,
    apic_id: u32,
) -> Result<(), IrqError> {
    let mut chip = chip().ok_or(IrqError::NotPresent)?;
    let destination = u8::try_from(apic_id).map_err(|_| IrqError::UnreachableCpu)?;
    // Remappable if the unit is remapping, and there is no choice about it:
    // with compatibility format blocked, an entry in the old format is a line
    // that stops being delivered. A line carries `None` for its source --
    // it is raised by a chip this kernel programs, not by a device choosing a
    // message, so there is no forgery to validate against.
    if let Some(handle) = crate::iommu::remap_interrupt(None, vector, destination) {
        // SAFETY: as below, and the handle names an entry just programmed.
        return unsafe { chip.route_remapped(gsi, handle, vector, false) }
            .map_err(|_| IrqError::NotRouted);
    }
    if crate::iommu::remapping() {
        // Remapping is on and no handle was issued. Falling back to the old
        // format would program a source that is never delivered, which looks
        // like a broken device rather than a full table.
        return Err(IrqError::NotRouted);
    }

    // SAFETY: the caller guarantees a handler for `vector`; the chip is the
    // one `init` mapped, and this runs on the bootstrap CPU only.
    unsafe { chip.route(gsi, vector, destination, false, false) }.map_err(|_| IrqError::NotRouted)
}

/// Reads back the redirection entry for `gsi`.
///
/// For the self-test: a write to a memory-mapped register that is never read
/// back is a write that may have gone anywhere.
#[must_use]
pub fn redirection(gsi: u32) -> Option<u32> {
    let chip = chip()?;
    // SAFETY: the chip `init` mapped; reading a redirection register has no
    // side effects.
    unsafe { chip.redirection(gsi) }
}

/// Whether a chip was found and mapped.
#[must_use]
pub fn present() -> bool {
    WINDOW.load(Ordering::Acquire) != 0
}

/// How many inputs the chip has.
#[must_use]
pub fn inputs() -> u32 {
    INPUTS.load(Ordering::Relaxed)
}

// ---------------------------------------------------------------------------
// RFC 0011: who may receive an interrupt
// ---------------------------------------------------------------------------

/// Interrupt sources the kernel will track at once.
pub const MAX_HANDLERS: usize = 16;

/// What an [`IrqHandler`] names.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Source {
    /// A legacy line, routed through the I/O APIC.
    Line {
        /// The global interrupt number.
        gsi: u32,
    },
    /// One entry of a PCI function's MSI-X table.
    MessageSignalled {
        /// Where the device is on the bus.
        device: bhaskix_arch::pci::Address,
        /// Which table entry.
        entry: u16,
    },
}

impl Source {
    /// Whether the kernel keeps this source for itself.
    ///
    /// Refused **by name**, not by vector, so the refusal survives the
    /// allocator moving anything. The timer and the two inter-processor
    /// interrupts are not lines at all — they are the local APIC's — so the
    /// list here is the legacy lines a domain must never be able to wedge.
    #[must_use]
    pub const fn reserved(&self) -> bool {
        match self {
            // The 8254 timer and the cascade line. Neither is used by this
            // kernel, and both are the kind of thing firmware leaves live.
            Self::Line { gsi } => *gsi == 0 || *gsi == 2,
            Self::MessageSignalled { .. } => false,
        }
    }

    /// Whether a *domain* may claim this, as opposed to in-nucleus code.
    ///
    /// Only message-signalled sources. A legacy line is shared between
    /// devices, and a holder that never acknowledges masks a line the others
    /// need — which the kernel cannot fix without a driver for each of them.
    #[must_use]
    pub const fn delegable(&self) -> bool {
        matches!(self, Self::MessageSignalled { .. })
    }
}

/// Names a claimed interrupt source.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct HandlerId {
    index: u32,
    generation: u32,
}

/// Why a claim, bind or acknowledge failed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ClaimError {
    /// Something already holds this source.
    AlreadyClaimed,
    /// The kernel keeps this source for itself.
    Reserved,
    /// No free handler slot.
    Exhausted,
    /// No vector could be allocated.
    NoVector,
    /// There is no I/O APIC, or it refused the routing.
    NotRouted,
    /// The handler has been released, or the name is stale.
    Gone,
    /// This source may not be delegated to a domain.
    ///
    /// Only message-signalled sources may. A legacy line is shared, so a
    /// holder that never acknowledges masks a line other devices need.
    NotDelegable,
}

/// One claimed source. Behind a lock; the interrupt path does not read this.
#[derive(Clone, Copy)]
struct Handler {
    source: Source,
    vector: u8,
    generation: u32,
    live: bool,
    /// Which domain must lose this when it dies, or [`NO_DOMAIN`].
    domain: u32,
}

/// A handler the nucleus holds for itself, which no domain's death releases.
///
/// Not a domain identifier that happens to be unused — the console's and the
/// block driver's handlers belong to the kernel, and a teardown that swept
/// them up because it matched a stale number would take the console away from
/// a running machine.
pub const NO_DOMAIN: u32 = u32::MAX;

/// What the interrupt path needs, per vector, without taking a lock.
///
/// The handler table above is behind a `SpinLock` and an interrupt handler
/// must not take one — so everything the delivery path reads lives here, in
/// atomics, written at claim time and read in the handler.
struct Delivery {
    /// Handler index plus one; zero means the vector is unclaimed.
    handler: AtomicU32,
    /// Notification index plus one; zero means nothing is bound.
    notification: AtomicU32,
    /// The bound notification's generation.
    generation: AtomicU32,
    /// The badge to signal with.
    badge: AtomicU64,
    /// The global interrupt to mask, or `u32::MAX` for a message-signalled
    /// source, which masks differently.
    gsi: AtomicU32,
}

impl Delivery {
    const fn new() -> Self {
        Self {
            handler: AtomicU32::new(0),
            notification: AtomicU32::new(0),
            generation: AtomicU32::new(0),
            badge: AtomicU64::new(0),
            gsi: AtomicU32::new(u32::MAX),
        }
    }
}

static DELIVERY: [Delivery; 256] = [const { Delivery::new() }; 256];

static HANDLERS: crate::sync::SpinLock<[Option<Handler>; MAX_HANDLERS]> =
    crate::sync::SpinLock::new(crate::sync::Rank::IrqHandlers, [None; MAX_HANDLERS]);

/// Interrupts delivered through a handler, and ones that found no claim.
static DELIVERED: AtomicU64 = AtomicU64::new(0);
static STRAYS: AtomicU64 = AtomicU64::new(0);
/// Deliveries that found a claim with nothing bound to it.
static UNBOUND: AtomicU64 = AtomicU64::new(0);

/// Claims `source`, allocating a vector and routing it to `apic_id`.
///
/// This is `IrqControl::CLAIM`. It is a plain function rather than a
/// capability method because nothing outside the kernel can reach it yet —
/// delegation is RFC 0011 step 6 and is blocked on an IOMMU. What it already
/// enforces is what makes delegation possible later: **a source may be claimed
/// once**, and reserved sources are refused by name.
///
/// # Errors
///
/// [`ClaimError`] naming what was refused.
///
/// # Safety
///
/// The caller must ensure the delivery path is ready to receive on the
/// allocated vector — which for this kernel means `trap` dispatches unclaimed
/// vectors to [`on_interrupt`], as it does.
pub unsafe fn claim(
    source: Source,
    owner: &'static str,
    apic_id: u32,
    rsdp: Option<PhysAddr>,
    hhdm: u64,
) -> Result<HandlerId, ClaimError> {
    // SAFETY: the caller's obligation, unchanged.
    unsafe { claim_for(source, NO_DOMAIN, owner, apic_id, rsdp, hhdm) }
}

/// Claims `source` on behalf of `domain`, which loses it when it dies.
///
/// The same claim as [`claim`], recording who it is for. Step 6 will set this
/// from the capability a domain invoked; step 5 is the half that can be built
/// and tested without one — a handler that outlives its owner leaves a line
/// masked and a vector spent for the life of the machine, and RFC 0011 says
/// destroying a domain is `RELEASE` for every handler it held.
///
/// `Source::delegable` — only message-signalled sources may be *given* to a
/// domain — is a rule about the syscall boundary that does not exist yet, and
/// is deliberately not enforced here. This records ownership; it does not hand
/// anything out.
///
/// # Errors
///
/// [`ClaimError`] naming what was refused.
///
/// # Safety
///
/// As [`claim`].
pub unsafe fn claim_for(
    source: Source,
    domain: u32,
    owner: &'static str,
    apic_id: u32,
    rsdp: Option<PhysAddr>,
    hhdm: u64,
) -> Result<HandlerId, ClaimError> {
    use core::sync::atomic::Ordering;

    if source.reserved() {
        return Err(ClaimError::Reserved);
    }

    // Reserve a slot under the lock, and do nothing else under it.
    //
    // Routing a source maps a register window, which takes the heap -- a lock
    // ranking *below* this one. Holding this across that is an inversion, and
    // it is the third time this pattern has appeared in this milestone: take
    // the thing you own, then go and do everything else while still holding
    // it. It reads naturally and it is wrong every time, because everything
    // else ranks lower.
    let (index, generation) = {
        let mut handlers = HANDLERS.lock();
        if handlers
            .iter()
            .flatten()
            .any(|handler| handler.live && handler.source == source)
        {
            return Err(ClaimError::AlreadyClaimed);
        }
        let index = handlers
            .iter()
            .position(|slot| slot.is_none_or(|handler| !handler.live))
            .ok_or(ClaimError::Exhausted)?;

        let generation = handlers[index].map_or(0, |handler| handler.generation.wrapping_add(1));
        // Claimed immediately, so a second caller cannot take the same source
        // or the same slot while this one is out of the lock doing the work.
        handlers[index] = Some(Handler {
            source,
            vector: 0,
            generation,
            live: true,
            domain,
        });
        (index, generation)
    };

    let undo = |index: usize| {
        let mut handlers = HANDLERS.lock();
        if let Some(Some(handler)) = handlers.get_mut(index) {
            handler.live = false;
        }
    };

    let Ok(vector) = crate::vectors::allocate(owner) else {
        undo(index);
        return Err(ClaimError::NoVector);
    };

    // Route it, holding nothing.
    let routed = match source {
        Source::Line { gsi } => {
            // SAFETY: the caller's obligation -- the vector's handler is
            // `on_interrupt`, which acknowledges the local APIC.
            let outcome = unsafe { route_gsi(rsdp, hhdm, gsi, vector, apic_id) };
            if outcome.is_ok() {
                DELIVERY[vector as usize].gsi.store(gsi, Ordering::Relaxed);
            }
            outcome.is_ok()
        }
        Source::MessageSignalled { device, entry } => {
            // SAFETY: this device is the kernel's, and the caller guarantees a
            // handler for `vector`.
            unsafe { program_msix(device, entry, vector, apic_id, hhdm) }.is_ok()
        }
    };

    if !routed {
        let _ = crate::vectors::release(vector);
        undo(index);
        return Err(ClaimError::NotRouted);
    }

    {
        let mut handlers = HANDLERS.lock();
        if let Some(Some(handler)) = handlers.get_mut(index) {
            handler.vector = vector;
        }
    }

    // Published last: a non-zero handler is what the delivery path takes as
    // "this vector is claimed", so it must not be visible before the values
    // describing it are.
    DELIVERY[vector as usize]
        .handler
        .store(index as u32 + 1, Ordering::Release);

    Ok(HandlerId {
        index: index as u32,
        generation,
    })
}

/// Binds a notification to a claimed source.
///
/// From here, an interrupt on that source signals `notification` with `badge`.
///
/// # Errors
///
/// [`ClaimError::Gone`] if the handler has been released.
pub fn bind(
    id: HandlerId,
    notification: crate::notify::NotificationId,
    badge: u64,
) -> Result<(), ClaimError> {
    use core::sync::atomic::Ordering;
    let handlers = HANDLERS.lock();
    let handler = resolve(&handlers, id).ok_or(ClaimError::Gone)?;
    let entry = &DELIVERY[handler.vector as usize];

    entry.badge.store(badge, Ordering::Relaxed);
    entry
        .generation
        .store(notification.generation(), Ordering::Relaxed);
    // Last, for the same reason as above.
    entry
        .notification
        .store(notification.index() + 1, Ordering::Release);
    Ok(())
}

/// Unmasks a source after its driver has finished with it.
///
/// This is `IrqHandler::ACK`. **Drain the device before calling it:** between
/// delivery and this the source is masked, and an edge raised while masked is
/// lost. See `docs/driver-model.md` §2.
///
/// # Errors
///
/// [`ClaimError::Gone`] if the handler has been released.
pub fn acknowledge(id: HandlerId) -> Result<(), ClaimError> {
    let handlers = HANDLERS.lock();
    let handler = resolve(&handlers, id).ok_or(ClaimError::Gone)?;
    let Source::Line { gsi } = handler.source else {
        return Ok(());
    };
    drop(handlers);

    let Some(mut chip) = chip() else {
        return Err(ClaimError::NotRouted);
    };
    // Interrupts off across the index/data pair: the same window an interrupt
    // handler uses to mask, and the chip has one of each.
    let enabled = bhaskix_arch::cpu::interrupts_enabled();
    if enabled {
        // SAFETY: restored below on every path.
        unsafe { bhaskix_arch::cpu::disable_interrupts() };
    }
    // SAFETY: the chip `init` mapped; this CPU is the only one touching the
    // index/data pair while interrupts are off here.
    let outcome = unsafe { chip.unmask(gsi) };
    if enabled {
        // SAFETY: they were enabled on entry.
        unsafe { bhaskix_arch::cpu::enable_interrupts() };
    }
    outcome.map_err(|_| ClaimError::NotRouted)
}

/// Names a claimed handler with a capability, so it can be granted.
///
/// RFC 0011 step 6, and the restriction is the RFC's: **only a
/// message-signalled source may be delegated.** A legacy line is shared
/// between devices, so a holder that never acknowledges masks a line the
/// others need — and the kernel cannot fix that without a driver for each of
/// them. A domain that wedges its own device is its own problem; one that
/// wedges somebody else's is the kernel's.
///
/// What the holder gets is `BIND`, `ACK` and `RELEASE`. It does not get the
/// MSI-X table, and there is no method that would let it program one.
///
/// # Errors
///
/// [`ClaimError::NotDelegable`] for a source that may not be delegated, or
/// [`ClaimError::Gone`] if the handler has been released.
pub fn name(id: HandlerId) -> Result<crate::cap::SlotRef, ClaimError> {
    let source = {
        let handlers = HANDLERS.lock();
        resolve(&handlers, id).ok_or(ClaimError::Gone)?.source
    };
    if !source.delegable() {
        return Err(ClaimError::NotDelegable);
    }

    // RFC 0011 would not take this step until there was an IOMMU, and that is
    // enforced here rather than remembered. A domain driving a device needs
    // the device's DMA constrained; without translation the driver it runs
    // can point that device at the kernel's memory, and an interrupt
    // capability would be the least of it.
    if !crate::iommu::present() {
        return Err(ClaimError::NotDelegable);
    }

    let identity = u64::from(id.index) | (u64::from(id.generation) << 32);
    crate::cap::with_arena(|arena| {
        arena.insert_root(
            crate::cap::ObjectRef::new(crate::cap::ObjectKind::IrqHandler, identity),
            crate::cap::Rights::ALL,
            0,
        )
    })
    .map_err(|_| ClaimError::Exhausted)
}

/// Rebuilds a handler identity from the packed form a capability carries.
#[must_use]
pub const fn handler_from_u64(identity: u64) -> HandlerId {
    HandlerId {
        index: identity as u32,
        generation: (identity >> 32) as u32,
    }
}

/// Releases every handler `domain` held, returning how many there were.
///
/// RFC 0011: destroying a domain is `RELEASE` for every handler it held. A
/// domain that dies mid-request must not leave a line masked and a vector
/// spent for the life of the machine — the source would be unclaimable, and
/// the device behind it silently dead, with nothing to point at.
///
/// Collected under the lock and released outside it, like `ipc::destroy`:
/// [`release`] takes the same lock, and masking a line reaches the chip while
/// freeing a vector reaches the allocator, both of which rank below it.
///
/// [`NO_DOMAIN`] matches nothing, so the kernel's own handlers are never swept
/// up by a domain's death.
pub fn release_owned_by(domain: u32) -> u32 {
    if domain == NO_DOMAIN {
        return 0;
    }

    let mut held = [HandlerId {
        index: 0,
        generation: 0,
    }; MAX_HANDLERS];
    let mut count = 0;
    {
        let handlers = HANDLERS.lock();
        for (index, handler) in handlers.iter().enumerate() {
            if let Some(handler) = handler
                && handler.live
                && handler.domain == domain
            {
                held[count] = HandlerId {
                    index: index as u32,
                    generation: handler.generation,
                };
                count += 1;
            }
        }
    }

    let mut released = 0;
    for id in held.iter().take(count) {
        if release(*id) {
            released += 1;
        }
    }
    released
}

/// Releases a claim: masks the source permanently and frees the vector.
pub fn release(id: HandlerId) -> bool {
    use core::sync::atomic::Ordering;
    let mut handlers = HANDLERS.lock();
    let Some(handler) = resolve(&handlers, id) else {
        return false;
    };
    let vector = handler.vector;

    // The delivery path stops seeing it before anything else changes.
    DELIVERY[vector as usize]
        .handler
        .store(0, Ordering::Release);
    DELIVERY[vector as usize]
        .notification
        .store(0, Ordering::Release);

    if let Source::Line { gsi } = handler.source
        && let Some(mut chip) = chip()
    {
        // SAFETY: the chip `init` mapped. Masked rather than left live: a
        // device still raising an interrupt nobody owns would be a stray on
        // every assertion, for ever.
        let _ = unsafe { chip.mask(gsi) };
    }
    let _ = crate::vectors::release(vector);

    if let Some(slot) = handlers.get_mut(id.index as usize)
        && let Some(entry) = slot.as_mut()
    {
        entry.live = false;
    }
    true
}

fn resolve(handlers: &[Option<Handler>; MAX_HANDLERS], id: HandlerId) -> Option<Handler> {
    let handler = (*handlers.get(id.index as usize)?)?;
    (handler.live && handler.generation == id.generation).then_some(handler)
}

/// Whether `vector` has been claimed.
#[must_use]
pub fn is_claimed(vector: u8) -> bool {
    DELIVERY[vector as usize]
        .handler
        .load(core::sync::atomic::Ordering::Acquire)
        != 0
}

/// Services an interrupt on a claimed vector.
///
/// **Mask, signal, and nothing else.** The mask is what stops a
/// level-triggered line re-asserting the instant this returns — and it is also
/// flow control, so a slow driver gets fewer interrupts rather than a storm.
/// The signal is lock-free by RFC 0010's design, which was chosen for exactly
/// this caller.
///
/// The local APIC is acknowledged by the dispatcher, after this returns.
pub fn on_interrupt(vector: u8) {
    use core::sync::atomic::Ordering;
    let entry = &DELIVERY[vector as usize];

    if entry.handler.load(Ordering::Acquire) == 0 {
        STRAYS.fetch_add(1, Ordering::Relaxed);
        return;
    }
    DELIVERED.fetch_add(1, Ordering::Relaxed);

    let gsi = entry.gsi.load(Ordering::Relaxed);
    if gsi != u32::MAX
        && let Some(mut chip) = chip()
    {
        // SAFETY: the chip `init` mapped, and this runs with interrupts
        // already disabled, so nothing else on this CPU is between the index
        // and the data write.
        let _ = unsafe { chip.mask(gsi) };
    }

    let notification = entry.notification.load(Ordering::Acquire);
    if notification == 0 {
        UNBOUND.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let id = crate::notify::NotificationId::from_parts(
        notification - 1,
        entry.generation.load(Ordering::Relaxed),
    );
    let _ = crate::notify::signal(id, entry.badge.load(Ordering::Relaxed));
}

/// Interrupts delivered, strays, and deliveries with nothing bound.
#[must_use]
pub fn statistics() -> (u64, u64, u64) {
    use core::sync::atomic::Ordering::Relaxed;
    (
        DELIVERED.load(Relaxed),
        STRAYS.load(Relaxed),
        UNBOUND.load(Relaxed),
    )
}

/// The vector a handler was given, for reporting.
#[must_use]
pub fn vector_of(id: HandlerId) -> Option<u8> {
    let handlers = HANDLERS.lock();
    resolve(&handlers, id).map(|handler| handler.vector)
}

/// Translates an ISA interrupt number to the global interrupt it arrives on.
///
/// Once, at claim time. Everything downstream works in the translated number,
/// because an override applied twice programs an input nothing is wired to.
#[must_use]
pub fn isa_to_gsi(rsdp: Option<PhysAddr>, hhdm: u64, irq: u8) -> u32 {
    let Some(rsdp) = rsdp else {
        return u32::from(irq);
    };
    // SAFETY: the tables were mapped by `init` and are not unmapped.
    let madt = unsafe {
        acpi::madt(rsdp.as_u64(), hhdm, &mut |physical, length| {
            ensure_mapped(physical, length, hhdm)
        })
    };
    madt.map_or(u32::from(irq), |madt| madt.route(irq).gsi)
}

/// Packs a handler name into one word, so a caller can keep it in an atomic.
///
/// The delivery path is lock-free and its clients are too; a two-field name
/// that cannot be stored atomically would push them all back to a lock.
#[must_use]
pub const fn handler_raw(id: HandlerId) -> u64 {
    ((id.index as u64) << 32) | id.generation as u64
}

/// Unpacks [`handler_raw`].
#[must_use]
pub const fn handler_from_raw(raw: u64) -> HandlerId {
    HandlerId {
        index: (raw >> 32) as u32,
        generation: raw as u32,
    }
}

/// The PCI capability identifier for MSI-X.
const CAP_MSIX: u8 = 0x11;

/// Programs one MSI-X table entry to deliver `vector` to `apic_id`.
///
/// **Kernel-side, and never delegated** (RFC 0011). An MSI is a memory write
/// the device performs: an address in the local APIC's window and a data word
/// that *is* the vector. A holder that could program it could point any
/// device's interrupt at any vector on any CPU, which is an
/// interrupt-injection primitive obtained by writing two words.
///
/// The consequence for whoever hands out MMIO capabilities is in
/// `docs/driver-model.md` §3: **a device's MSI-X table pages must never be
/// inside one.**
///
/// # Errors
///
/// [`ClaimError::NotRouted`] if the device has no MSI-X capability, too few
/// entries, or its table cannot be mapped.
///
/// # Safety
///
/// The device must be the kernel's, and `vector` must have a handler that
/// acknowledges the local APIC.
unsafe fn program_msix(
    device: bhaskix_arch::pci::Address,
    entry: u16,
    vector: u8,
    apic_id: u32,
    hhdm: u64,
) -> Result<(), ClaimError> {
    use bhaskix_arch::pci;

    let mut capability = None;
    // SAFETY: configuration reads on the bootstrap CPU during boot.
    unsafe {
        pci::for_each_capability(device, |found| {
            if found.id == CAP_MSIX {
                capability = Some(found.offset);
                return false;
            }
            true
        });
    }
    let offset = capability.ok_or(ClaimError::NotRouted)?;

    // SAFETY: the capability the walk just found, on a device the kernel owns.
    let (table_base, entries) = unsafe {
        let control = pci::read16(device, offset + 2);
        let entries = (control & 0x7ff) + 1;
        let table = pci::read32(device, offset + 4);
        let bir = (table & 0b111) as u8;
        let within = u64::from(table & !0b111);

        let pci::Bar::Memory { address, .. } = pci::bar(device, bir) else {
            return Err(ClaimError::NotRouted);
        };
        (address + within, entries)
    };

    if entry >= entries {
        return Err(ClaimError::NotRouted);
    }

    // One entry is four 32-bit words: address low, address high, data, and a
    // vector control word whose bit 0 is the per-entry mask.
    const ENTRY_BYTES: u64 = 16;
    let table = crate::mmio::map(table_base, ENTRY_BYTES * u64::from(entries), hhdm)
        .ok_or(ClaimError::NotRouted)?;
    let slot = table + ENTRY_BYTES * u64::from(entry);

    // SAFETY: `slot` is inside the mapped MSI-X table of this device, and the
    // layout is the four words the specification fixes.
    unsafe {
        // Masked while it is programmed, so a device that fires mid-write does
        // not deliver a half-written vector.
        core::ptr::write_volatile((slot + 12) as *mut u32, 1);
        // A remapped message names a *handle*, not a CPU and not a vector --
        // which is the whole mechanism. The handle is issued against this
        // device's requester id, so presenting it from anywhere else is
        // refused by the unit: RFC 0011's residual risk, retired.
        let remapped = crate::iommu::remap_interrupt(
            Some((device.bus, device.device, device.function)),
            vector,
            u8::try_from(apic_id).unwrap_or(0),
        );
        match remapped {
            Some(handle) => {
                core::ptr::write_volatile(
                    slot as *mut u32,
                    bhaskix_arch::vtd::remappable_message_address(handle),
                );
                core::ptr::write_volatile((slot + 4) as *mut u32, 0);
                core::ptr::write_volatile(
                    (slot + 8) as *mut u32,
                    bhaskix_arch::vtd::remappable_message_data(),
                );
            }
            None => {
                core::ptr::write_volatile(slot as *mut u32, 0xfee0_0000 | (apic_id << 12));
                core::ptr::write_volatile((slot + 4) as *mut u32, 0);
                core::ptr::write_volatile((slot + 8) as *mut u32, u32::from(vector));
            }
        }
        // Unmasked last.
        core::ptr::write_volatile((slot + 12) as *mut u32, 0);
    }

    // Enable MSI-X, and clear the function mask that would hold every entry.
    // SAFETY: the message control word of the capability just walked to.
    unsafe {
        let control = pci::read16(device, offset + 2);
        pci::write16(device, offset + 2, (control | (1 << 15)) & !(1 << 14));
    }
    Ok(())
}
