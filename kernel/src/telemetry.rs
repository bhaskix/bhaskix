// SPDX-License-Identifier: Apache-2.0
//! The telemetry plane's kernel half — RFC 0026 step 2.
//!
//! One drop-newest ring per CPU, in frames a keeper domain owns, written
//! through the direct map with a bounded, allocation-free, lock-free store
//! sequence. Every decision — admit or drop, clamp the reader's tail claim,
//! where a sequence lands — is `bhaskix_telemetry`'s host-tested arithmetic;
//! this module contributes only the stores, the interrupt discipline, and
//! the boot-time wiring.
//!
//! **The producer is only the owning CPU.** [`emit`] disables interrupts for
//! the duration of its stores because it must be atomic against *itself* on
//! the same CPU: a timer landing between the slot write and the head publish
//! whose handler also emits would claim the same slot. It takes no lock, so
//! it is exempt from ranking and legal from interrupt context
//! ([docs/coding-style.md](../../docs/coding-style.md) §7).
//!
//! **The reader's tail is hostile.** It lives in a page that will be mapped
//! read-write into `bin/traced` (step 3), so every use here clamps it first;
//! a lying tail causes drops or redeliveries in the liar's own stream and
//! nothing else.
//!
//! Until [`init`] runs, every emit returns at the mask check: the plane
//! starts with every class disabled, and bring-up turns `Sched` on when the
//! rings exist. Events before that moment are not queued anywhere — early
//! bring-up narrates through `println!`, which is for humans.

use bhaskix_arch::percpu::MAX_CPUS;
use bhaskix_arch::{cpu, percpu, tsc};
use bhaskix_telemetry::{EVENT_BYTES, Event, EventClass, PAYLOAD_BYTES, enabled, ring, schema};
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::shared;

/// Pages per CPU ring: a 128-byte header and 512 slots is 32,896 bytes —
/// nine pages, chosen against [`shared::MAX_FRAMES`]'s sixteen-page bound on
/// one object rather than the RFC's sketched 1024 slots, and revisited when
/// the boot report's drop row says otherwise.
pub const RING_PAGES: usize = 9;

/// Bytes one CPU's ring region spans.
const RING_BYTES: u64 = RING_PAGES as u64 * bhaskix_mm::FRAME_SIZE;

/// The per-class enable mask. All zero until bring-up turns something on;
/// one relaxed load and a predicted-not-taken branch is the whole cost of a
/// disabled class.
static MASK: AtomicU32 = AtomicU32::new(0);

/// Slots per ring, zero until [`init`] — the second guard on the emit path.
static SLOTS: AtomicU64 = AtomicU64::new(0);

/// The direct-map base, stashed by [`init`] so emit sites need no handoff.
static HHDM: AtomicU64 = AtomicU64::new(0);

/// Each CPU's ring frames, physical, in region order. Written once by
/// [`init`], read on every emit — the one indirection the frame-granular
/// allocator costs, since a 64-byte slot never straddles a page.
static RING_FRAMES: [[AtomicU64; RING_PAGES]; MAX_CPUS] =
    [const { [const { AtomicU64::new(0) }; RING_PAGES] }; MAX_CPUS];

/// The tails page, physical: one cache line per CPU, reader-writable once
/// granted (step 3), clamped on every read here.
static TAILS_FRAME: AtomicU64 = AtomicU64::new(0);

/// The ring objects' identities, for step 3's grant. `u64::MAX` = none.
static RING_IDS: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(u64::MAX) }; MAX_CPUS];

/// The tails object's identity, for step 3's grant.
static TAILS_ID: AtomicU64 = AtomicU64::new(u64::MAX);

/// One CPU's domain hint, alone on its cache line.
///
/// The padding is load-bearing: the first version packed sixteen CPUs'
/// hints into each line, so every context switch on every CPU stored into
/// lines the others were storing into too — cross-CPU traffic injected
/// into the switch path itself, which is the last place this machine can
/// afford a perturbation it did not order.
#[repr(align(64))]
struct DomainHint(AtomicU32);

/// Each CPU's current domain, kept by the switch path for producers that
/// must not ask the scheduler: `sched::current_domain()` takes the runqueue
/// lock, which `notify::signal` — legal from interrupt context — must never
/// block on, and which `ipc`'s trace point may already sit inside another
/// lock to reach. A *hint*, briefly stale around a switch, and said so.
static DOMAIN_HINT: [DomainHint; MAX_CPUS] =
    [const { DomainHint(AtomicU32::new(u32::MAX)) }; MAX_CPUS];

/// Records the domain now running on the calling CPU. Called by the switch
/// path with interrupts off, beside the dispatch event.
pub fn note_domain(domain: u32) {
    let cpu_index = percpu::cpu_id() as usize;
    if cpu_index < MAX_CPUS {
        DOMAIN_HINT[cpu_index].0.store(domain, Ordering::Relaxed);
    }
}

/// The domain most recently noted for this CPU — the lock-free answer
/// producers stamp into their events. `u32::MAX` is "none or unknown".
#[must_use]
pub fn domain_hint() -> u32 {
    let cpu_index = percpu::cpu_id() as usize;
    if cpu_index < MAX_CPUS {
        DOMAIN_HINT[cpu_index].0.load(Ordering::Relaxed)
    } else {
        u32::MAX
    }
}

/// Where `offset` within `cpu`'s ring region lives in the direct map.
///
/// Slots are 64 bytes and frames 4,096, so 64 divides 4,096 and no slot or
/// header word straddles a frame — which is what makes frame-granular
/// backing sound.
fn ring_address(cpu: usize, offset: usize) -> u64 {
    let frame = RING_FRAMES[cpu][offset >> 12].load(Ordering::Relaxed);
    HHDM.load(Ordering::Relaxed) + frame + (offset & 0xFFF) as u64
}

/// Reads a header word of `cpu`'s ring.
fn header_word(cpu: usize, offset: usize) -> u64 {
    // SAFETY: a frame the ring object owns, through the direct map, at an
    // offset inside the header; only this module writes ring headers.
    unsafe { core::ptr::read_volatile(ring_address(cpu, offset) as *const u64) }
}

/// Writes a header word of `cpu`'s ring.
fn set_header_word(cpu: usize, offset: usize, value: u64) {
    // SAFETY: as in `header_word`, and the write is a single aligned word.
    unsafe { core::ptr::write_volatile(ring_address(cpu, offset) as *mut u64, value) };
}

/// Emits one event on the calling CPU, or drops it and says so.
///
/// Callable from any context including interrupt handlers: no locks, no
/// allocation, a bounded store sequence under disabled interrupts. `payload`
/// is copied up to [`PAYLOAD_BYTES`]; the schema's declared size is the
/// consumer's contract, not enforced here, because the emit path budgets no
/// branch for a caller lying about its own schema.
pub fn emit(class: EventClass, schema_id: u32, domain: u32, payload: &[u8]) {
    // The Audit refusal comes before the mask so it is counted even while
    // the class is disabled — RFC 0026 reserves the class and refuses it,
    // and an uncounted refusal would be a silent one. `class` is a constant
    // at every call site, so this folds away everywhere else.
    let audit = matches!(class, EventClass::Audit);
    if !audit && !enabled(MASK.load(Ordering::Relaxed), class) {
        return;
    }
    let slots = SLOTS.load(Ordering::Relaxed);
    if slots == 0 {
        return;
    }

    let were_enabled = cpu::interrupts_enabled();
    if were_enabled {
        // SAFETY: interrupts back on before every return below; the window
        // is the bounded store sequence, entered from ring 0 only.
        unsafe { cpu::disable_interrupts() };
    }
    let cpu_index = percpu::cpu_id() as usize;

    if audit {
        let refused = header_word(cpu_index, ring::AUDIT_REFUSED_OFFSET);
        set_header_word(cpu_index, ring::AUDIT_REFUSED_OFFSET, refused + 1);
    } else {
        let head = header_word(cpu_index, ring::HEAD_OFFSET);
        let claim = {
            let at = HHDM.load(Ordering::Relaxed)
                + TAILS_FRAME.load(Ordering::Relaxed)
                + ring::tail_offset(cpu_index) as u64;
            // SAFETY: the tails frame, through the direct map, one aligned
            // word per CPU; the value is untrusted and clamped below.
            unsafe { core::ptr::read_volatile(at as *const u64) }
        };
        let tail = ring::clamp_tail(head, claim, slots);
        if ring::admit(head, tail, slots) {
            let mut event = Event {
                timestamp: tsc::read(),
                cpu: cpu_index as u32,
                domain,
                class: class as u32,
                schema: schema_id,
                payload: [0u8; PAYLOAD_BYTES],
            };
            let taken = payload.len().min(PAYLOAD_BYTES);
            event.payload[..taken].copy_from_slice(&payload[..taken]);
            let bytes = event.to_bytes();
            let layout = ring::Layout::for_region(RING_BYTES as usize);
            if let Some(layout) = layout {
                let slot = layout.slot_offset(head);
                for word in 0..EVENT_BYTES / 8 {
                    let mut value = [0u8; 8];
                    value.copy_from_slice(&bytes[word * 8..word * 8 + 8]);
                    // SAFETY: a slot inside the ring region, whole by the
                    // 64-divides-4096 argument on `ring_address`, and below
                    // `head` so no reader may look at it yet.
                    unsafe {
                        core::ptr::write_volatile(
                            ring_address(cpu_index, slot + word * 8) as *mut u64,
                            u64::from_le_bytes(value),
                        );
                    }
                }
                // The publish: slot bytes first, then head, so a reader that
                // acquires `head` never sees a half-written record.
                core::sync::atomic::fence(Ordering::Release);
                set_header_word(cpu_index, ring::HEAD_OFFSET, head + 1);
            }
        } else {
            let dropped = header_word(cpu_index, ring::DROPPED_OFFSET);
            set_header_word(cpu_index, ring::DROPPED_OFFSET, dropped + 1);
        }
    }

    if were_enabled {
        // SAFETY: restoring exactly the state observed on entry.
        unsafe { cpu::enable_interrupts() };
    }
}

/// Turns a class on. Bring-up policy lives at the call sites, not here.
pub fn enable(class: EventClass) {
    MASK.fetch_or(class.bit(), Ordering::Relaxed);
}

/// The identity of `cpu`'s ring object, for the grant (step 3).
pub fn ring_identity(cpu: usize) -> Option<u64> {
    if cpu >= MAX_CPUS {
        return None;
    }
    match RING_IDS[cpu].load(Ordering::Relaxed) {
        u64::MAX => None,
        identity => Some(identity),
    }
}

/// The identity of the tails object, for the grant (step 3).
pub fn tails_identity() -> Option<u64> {
    match TAILS_ID.load(Ordering::Relaxed) {
        u64::MAX => None,
        identity => Some(identity),
    }
}

/// The payload mark the round-trip probes carry: `b"TRACEPRB"`. Distinct
/// from the boot report's own instrument probes, so `bin/traced`'s count
/// means "the marked set" and nothing else.
pub const PROBE_MARK: u64 = u64::from_le_bytes(*b"TRACEPRB");

/// Empties the calling CPU's ring and emits `count` marked probes into it.
///
/// The self-test's per-CPU half: run on each CPU in turn (emit writes only
/// the caller's own ring), it guarantees the probes are admitted — the ring
/// was just emptied and holds 512 — so `bin/traced` reading back fewer than
/// `count` convicts the path, not the pressure. Writing the tail from here
/// is sound for the same reason the report instrument's write is: it
/// happens before the consumer is spawned, while the kernel is still the
/// only party.
pub fn probe_here(count: u64) {
    if SLOTS.load(Ordering::Relaxed) == 0 {
        return;
    }
    let cpu_index = percpu::cpu_id() as usize;
    let head = header_word(cpu_index, ring::HEAD_OFFSET);
    let at = HHDM.load(Ordering::Relaxed)
        + TAILS_FRAME.load(Ordering::Relaxed)
        + ring::tail_offset(cpu_index) as u64;
    // SAFETY: the tails frame, through the direct map; no consumer holds
    // the grant yet, so the kernel is the only writer.
    unsafe { core::ptr::write_volatile(at as *mut u64, head) };
    for sequence in 0..count {
        let mut payload = [0u8; 16];
        payload[..8].copy_from_slice(&PROBE_MARK.to_le_bytes());
        payload[8..].copy_from_slice(&sequence.to_le_bytes());
        emit(EventClass::Sched, schema::PROBE.id, u32::MAX, &payload);
    }
}

/// Creates the rings and the tails page, and arms the plane.
///
/// One ring per online CPU, each a `Memory` object a keeper domain owns —
/// the same shape every boot-created ring uses, and what step 3's grant
/// hands to `bin/traced`. The header's marker is written last, behind a
/// release fence, so a reader that maps a ring mid-initialisation refuses
/// it rather than trusting garbage.
pub fn init(hhdm: u64) -> Result<(), &'static str> {
    let keeper = crate::domain::create("telemetry-keeper", crate::domain::ResourceEnvelope::new())
        .map_err(|_| "the telemetry keeper domain would not be created")?;
    HHDM.store(hhdm, Ordering::Relaxed);

    let tails = shared::create(keeper, bhaskix_mm::FRAME_SIZE)
        .map_err(|_| "the tails page would not be created")?;
    let Some((tail_frames, tail_count)) = shared::frames_of(tails) else {
        return Err("the tails page has no frames");
    };
    if tail_count == 0 {
        return Err("the tails page is empty");
    }
    for word in 0..(bhaskix_mm::FRAME_SIZE as usize / 8) {
        // SAFETY: the tails frame, freshly allocated, through the direct
        // map; zeroed before anything reads it.
        unsafe {
            core::ptr::write_volatile((hhdm + tail_frames[0] + word as u64 * 8) as *mut u64, 0)
        };
    }
    TAILS_FRAME.store(tail_frames[0], Ordering::Relaxed);
    TAILS_ID.store(tails.as_u64(), Ordering::Relaxed);

    let Some(layout) = ring::Layout::for_region(RING_BYTES as usize) else {
        return Err("the ring region is too small for a ring");
    };

    let online = percpu::online_count() as usize;
    for cpu_index in 0..online.min(MAX_CPUS) {
        let object = shared::create(keeper, RING_BYTES)
            .map_err(|_| "a telemetry ring would not be created")?;
        let Some((frames, count)) = shared::frames_of(object) else {
            return Err("a telemetry ring has no frames");
        };
        if count < RING_PAGES {
            return Err("a telemetry ring is short of frames");
        }
        for (page, frame) in frames.iter().enumerate().take(RING_PAGES) {
            RING_FRAMES[cpu_index][page].store(*frame, Ordering::Relaxed);
        }
        set_header_word(cpu_index, ring::HASH_OFFSET, schema::registry_hash());
        set_header_word(cpu_index, ring::SLOTS_OFFSET, layout.slots());
        set_header_word(cpu_index, ring::DROPPED_OFFSET, 0);
        set_header_word(cpu_index, ring::AUDIT_REFUSED_OFFSET, 0);
        set_header_word(cpu_index, ring::HEAD_OFFSET, 0);
        core::sync::atomic::fence(Ordering::Release);
        set_header_word(cpu_index, ring::MARKER_OFFSET, ring::MARKER);
        RING_IDS[cpu_index].store(object.as_u64(), Ordering::Relaxed);
    }

    // Armed: the emit path's second guard opens last, after every ring is
    // whole, so a concurrent emit on a secondary CPU cannot write into a
    // half-built ring.
    core::sync::atomic::fence(Ordering::Release);
    SLOTS.store(layout.slots(), Ordering::Relaxed);
    Ok(())
}

/// What the boot report prints, and the emit-cost measurement.
///
/// Reads every ring's counters, then prices the emit path: this CPU's tail
/// is set to its head (the ring is empty and nothing has been granted yet —
/// step 3 revisits this instrument once a consumer owns the tail), and 256
/// probe events are emitted under the cycle counter, all admitted, so the
/// figure prices the write path rather than the cheaper drop path.
pub fn report() {
    if SLOTS.load(Ordering::Relaxed) == 0 {
        crate::println!("\x1b[91m    telemetry      not initialised\x1b[0m");
        return;
    }
    let online = (percpu::online_count() as usize).min(MAX_CPUS);
    let mut events = 0u64;
    let mut dropped = 0u64;
    let mut refused = 0u64;
    for cpu_index in 0..online {
        events += header_word(cpu_index, ring::HEAD_OFFSET);
        dropped += header_word(cpu_index, ring::DROPPED_OFFSET);
        refused += header_word(cpu_index, ring::AUDIT_REFUSED_OFFSET);
    }

    let cpu_index = percpu::cpu_id() as usize;
    let head = header_word(cpu_index, ring::HEAD_OFFSET);
    {
        let at = HHDM.load(Ordering::Relaxed)
            + TAILS_FRAME.load(Ordering::Relaxed)
            + ring::tail_offset(cpu_index) as u64;
        // SAFETY: the tails frame, through the direct map; sound to write
        // from the kernel while no consumer holds the grant, which is
        // step 2's world by construction.
        unsafe { core::ptr::write_volatile(at as *mut u64, head) };
    }
    const SAMPLES: u64 = 256;
    let mut payload = [0u8; 16];
    let before = tsc::read();
    for sample in 0..SAMPLES {
        payload[..8].copy_from_slice(&ring::MARKER.to_le_bytes());
        payload[8..].copy_from_slice(&sample.to_le_bytes());
        emit(EventClass::Sched, schema::PROBE.id, u32::MAX, &payload);
    }
    let cycles = (tsc::read().wrapping_sub(before)) / SAMPLES;

    // The other half of the A/B: the same loop through a class that is
    // actually off, measured only if one is — a disabled class whose cost
    // was measured while it was enabled would be the instrument lying about
    // the claim it exists to check, that a disabled class costs one load
    // and a predicted branch.
    let mask = MASK.load(Ordering::Relaxed);
    let off = [
        EventClass::Net,
        EventClass::Io,
        EventClass::Memory,
        EventClass::Fault,
    ]
    .into_iter()
    .find(|class| !enabled(mask, *class));
    let disabled_cycles = off.map(|class| {
        let before = tsc::read();
        for sample in 0..SAMPLES {
            payload[8..].copy_from_slice(&sample.to_le_bytes());
            emit(class, schema::PROBE.id, u32::MAX, &payload);
        }
        (tsc::read().wrapping_sub(before)) / SAMPLES
    });

    crate::println!(
        "    telemetry      {} events across {} cpus, {} dropped, {} audit-refused; \
         ~{} cycles/emit over {}, ~{} disabled; {} slots/cpu",
        events + SAMPLES,
        online,
        dropped,
        refused,
        cycles,
        SAMPLES,
        disabled_cycles.unwrap_or(0),
        SLOTS.load(Ordering::Relaxed),
    );
}
