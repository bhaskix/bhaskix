// SPDX-License-Identifier: Apache-2.0
//! Domains: the unit of isolation, accounting and scheduling.
//!
//! Implements `docs/architecture.md` §4 and the resource half of
//! `docs/security.md` §2. A domain is what a container is and what a virtual
//! machine is; the difference between them is the kind of address space, and
//! nothing above this layer knows which it is serving.
//!
//! # The envelope is enforced, not advisory
//!
//! `docs/security.md` threat T10 — one domain denying service to others by
//! exhausting a resource — is answered by the [`ResourceEnvelope`], and its
//! wording is deliberate: enforced **at allocation and scheduling time, not by
//! best effort**. A limit that is checked after the fact, or that is a hint to
//! a reclaim policy, does not answer T10; it describes it.
//!
//! So [`charge_frames`] refuses. It does not warn, it does not reclaim, and it
//! does not succeed and notify. The caller gets an error and must cope, which
//! is the only behaviour that makes the limit mean anything to the *other*
//! domains.
//!
//! # CPU share is divided, not multiplied
//!
//! `docs/scheduler.md` §3: "a domain's CPU share is honoured regardless of how
//! many threads it spawns". That is not what a per-thread weight gives you — a
//! domain with ten threads at weight *w* takes ten times the CPU of a domain
//! with one, which turns the envelope into a suggestion and makes spawning
//! threads a privilege-escalation strategy.
//!
//! The share is therefore *divided* among a domain's threads: each gets
//! `cpu_shares / thread_count`, recomputed whenever the count changes. The
//! domain's total weight is then constant, which is the property the envelope
//! claims.
//!
//! This is an approximation of §3's two-level runqueue, not a replacement for
//! it. It gets the aggregate right and the *distribution within* a domain
//! wrong: every thread in a domain is weighted equally, so a domain cannot
//! prioritise among its own threads. That needs the real two-level structure.
//!
//! # What is not here
//!
//! - **No address space.** A domain records one but does not own one yet;
//!   binding them needs the object table that M5-02 only begins.
//! - **No I/O weight enforcement**, because there is no I/O.
//! - **No telemetry channel.** `docs/ai-native.md` §2 specifies one per domain.
//! - **A thread stops at its next safe point, not immediately.** Destroying a
//!   domain marks its threads and wakes the sleeping ones; each stops when it
//!   next returns to user mode or decides to block, because stopping a thread
//!   where it stands can mean freeing the stack it is standing on. The window
//!   is bounded by one timer tick for a thread in ring 3. It is *not* bounded
//!   for a thread spinning inside the kernel, and [RFC 0017](../../docs/rfc/0017-process-management.md)
//!   takes the position that such a thread is a kernel bug rather than a case
//!   to be handled.
//! - **Kernel stacks are still not reclaimed.** That is older than this and
//!   larger: `sched::reap_finished` frees a thread's slot and leaves its stack,
//!   because there is no allocator for stack slots. Recorded in TRACKER.md.

use crate::cap::{self, CSpace, ObjectKind, ObjectRef, Rights, SlotRef};
use crate::sched;
use crate::sync::{Rank, SpinLock};

/// Domains that can exist at once.
///
/// Fixed, so that creating a domain cannot fail for want of heap on a path
/// that may run during memory pressure — which is exactly when a supervisor
/// most wants to start a replacement.
pub const MAX_DOMAINS: usize = 32;

/// The weight of a domain with an ordinary CPU share.
pub const DEFAULT_CPU_SHARES: u32 = 1024;

/// How urgently a domain's threads need the CPU when they become runnable.
///
/// Distinct from CPU *share*, which is how much they get: a domain can need
/// very little CPU and need it promptly, which is the profile of every control
/// loop in `docs/rfc/0004-ot-security-gateway.md`'s target.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LatencyClass {
    /// Runs when nothing else wants the CPU.
    Background,
    /// The default.
    Normal,
    /// Wants a short slice, soon. Maps to a shorter requested slice, which
    /// earns an earlier virtual deadline.
    Interactive,
    /// Real-time. Requires an explicit utilisation budget; see
    /// `docs/scheduler.md` §4.
    RealTime {
        /// Fixed priority, 0..=99.
        priority: u8,
        /// Declared share of a CPU, in percent, for admission control.
        utilisation: u16,
    },
}

/// What a domain is permitted to consume.
#[derive(Clone, Copy, Debug)]
pub struct ResourceEnvelope {
    /// Relative CPU share, against [`DEFAULT_CPU_SHARES`]. Divided among the
    /// domain's threads rather than given to each.
    pub cpu_shares: u32,
    /// Hard cap on frames charged to this domain. Allocation past it fails.
    pub memory_frames: u64,
    /// Relative I/O share. Recorded; nothing enforces it, because there is no
    /// I/O to enforce it against.
    pub io_weight: u32,
    /// How promptly its threads should run once runnable.
    pub latency_class: LatencyClass,
    /// Cap on live capabilities derived by this domain.
    ///
    /// The capability arena is a fixed global resource, so without this a
    /// domain that derives in a loop denies service to every other domain —
    /// T10 through a door nobody was watching.
    pub max_capabilities: u32,
}

impl Default for ResourceEnvelope {
    fn default() -> Self {
        Self::new()
    }
}

impl ResourceEnvelope {
    /// An ordinary envelope: a normal CPU share, a modest memory cap.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            cpu_shares: DEFAULT_CPU_SHARES,
            memory_frames: 4096,
            io_weight: 1024,
            latency_class: LatencyClass::Normal,
            max_capabilities: 64,
        }
    }

    /// Sets the CPU share.
    #[must_use]
    pub const fn cpu_shares(mut self, shares: u32) -> Self {
        self.cpu_shares = shares;
        self
    }

    /// Sets the memory cap, in frames.
    #[must_use]
    pub const fn memory_frames(mut self, frames: u64) -> Self {
        self.memory_frames = frames;
        self
    }

    /// Sets the latency class.
    #[must_use]
    pub const fn latency_class(mut self, class: LatencyClass) -> Self {
        self.latency_class = class;
        self
    }

    /// Sets the capability cap.
    #[must_use]
    pub const fn max_capabilities(mut self, capabilities: u32) -> Self {
        self.max_capabilities = capabilities;
        self
    }
}

/// Why a domain operation failed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DomainError {
    /// No free slot in the domain table.
    TooManyDomains,
    /// No such domain, or it has been destroyed.
    NoSuchDomain,
    /// The request would exceed the domain's memory envelope.
    MemoryEnvelopeExceeded {
        /// Frames already charged.
        charged: u64,
        /// Frames requested.
        requested: u64,
        /// The cap.
        limit: u64,
    },
    /// The request would exceed the domain's capability envelope.
    CapabilityEnvelopeExceeded {
        /// Capabilities already held.
        held: u32,
        /// The cap.
        limit: u32,
    },
    /// The capability arena had no room.
    CapabilityExhausted,
    /// The capability named something other than a domain.
    NotADomain,
}

/// A domain's identity. Dense, and reused after destruction.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DomainId(u32);

impl DomainId {
    /// The raw index.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self.0
    }

    /// Rebuilds an identity from a raw index.
    ///
    /// Does not check that the domain exists; every operation taking one
    /// resolves it against the table and fails if it does not.
    #[must_use]
    pub const fn from_u32(id: u32) -> Self {
        Self(id)
    }
}

/// The unit of isolation, accounting and scheduling.
pub struct Domain {
    id: u32,
    /// Distinguishes a reused slot from the domain that held it before.
    generation: u32,
    name: &'static str,
    /// What it may touch.
    pub cspace: CSpace,
    /// What it may consume.
    pub envelope: ResourceEnvelope,
    /// Frames currently charged against the envelope.
    charged_frames: u64,
    /// Capabilities currently charged against the envelope.
    held_capabilities: u32,
    /// Threads belonging to this domain.
    threads: u32,
    /// The capability naming this domain. Revoking it revokes everything the
    /// domain was ever granted, because everything was derived from it.
    root: Option<SlotRef>,
    live: bool,
}

impl Domain {
    const fn empty() -> Self {
        Self {
            id: 0,
            generation: 0,
            name: "",
            cspace: CSpace::new(),
            envelope: ResourceEnvelope::new(),
            charged_frames: 0,
            held_capabilities: 0,
            threads: 0,
            root: None,
            live: false,
        }
    }

    /// Frames charged against this domain's envelope.
    #[must_use]
    pub const fn charged_frames(&self) -> u64 {
        self.charged_frames
    }

    /// Capabilities charged against this domain's envelope.
    #[must_use]
    pub const fn held_capabilities(&self) -> u32 {
        self.held_capabilities
    }

    /// Threads belonging to this domain.
    #[must_use]
    pub const fn threads(&self) -> u32 {
        self.threads
    }

    /// This domain's identity.
    #[must_use]
    pub const fn id(&self) -> DomainId {
        DomainId(self.id)
    }

    /// Which incarnation of this table slot the domain is.
    ///
    /// Slots are reused, so a stale reference to a destroyed domain must be
    /// distinguishable from the one that replaced it — the same reasoning as
    /// the capability arena's generation, and the same failure if it is
    /// missing: a reference that silently addresses somebody else's resources.
    #[must_use]
    pub const fn generation(&self) -> u32 {
        self.generation
    }

    /// This domain's name, for diagnostics.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// The weight each of this domain's threads should carry.
    ///
    /// The share divided, not handed to each. See the module header: a domain
    /// with ten threads must not take ten times the CPU of a domain with one,
    /// or the envelope is a suggestion and spawning threads is a way around it.
    #[must_use]
    pub const fn thread_weight(&self) -> u32 {
        let threads = if self.threads == 0 { 1 } else { self.threads };
        let weight = self.envelope.cpu_shares / threads;
        // Never zero: a weight of zero would divide by zero in the scheduler's
        // virtual-time accounting. A domain sliced thinner than its thread
        // count gets the floor, which is the honest failure -- it asked for
        // less CPU than it has threads to spend it.
        if weight == 0 { 1 } else { weight }
    }

    /// Charges `frames` against the envelope, refusing rather than exceeding.
    ///
    /// # Errors
    ///
    /// [`DomainError::MemoryEnvelopeExceeded`] if the total would pass the cap.
    pub fn charge_frames(&mut self, frames: u64) -> Result<(), DomainError> {
        let total = self.charged_frames.saturating_add(frames);
        if total > self.envelope.memory_frames {
            return Err(DomainError::MemoryEnvelopeExceeded {
                charged: self.charged_frames,
                requested: frames,
                limit: self.envelope.memory_frames,
            });
        }
        self.charged_frames = total;
        Ok(())
    }

    /// Returns `frames` to the envelope. Saturating: releasing more than was
    /// charged is a bug, and reporting zero is better than wrapping to a
    /// number that reads as an enormous allocation.
    pub fn release_frames(&mut self, frames: u64) {
        self.charged_frames = self.charged_frames.saturating_sub(frames);
    }

    /// Charges one capability against the envelope.
    ///
    /// # Errors
    ///
    /// [`DomainError::CapabilityEnvelopeExceeded`] if the domain is at its cap.
    pub fn charge_capability(&mut self) -> Result<(), DomainError> {
        if self.held_capabilities >= self.envelope.max_capabilities {
            return Err(DomainError::CapabilityEnvelopeExceeded {
                held: self.held_capabilities,
                limit: self.envelope.max_capabilities,
            });
        }
        self.held_capabilities += 1;
        Ok(())
    }

    /// Returns one capability to the envelope.
    pub fn release_capability(&mut self) {
        self.held_capabilities = self.held_capabilities.saturating_sub(1);
    }
}

struct Table {
    domains: [Domain; MAX_DOMAINS],
    created: u64,
    destroyed: u64,
}

impl Table {
    const fn new() -> Self {
        Self {
            domains: [const { Domain::empty() }; MAX_DOMAINS],
            created: 0,
            destroyed: 0,
        }
    }
}

static TABLE: SpinLock<Table> = SpinLock::new(Rank::Domains, Table::new());

/// Creates a domain, and a root capability naming it.
///
/// The capability is the domain's authority over itself and the root of
/// everything it will ever be granted, which is what makes destruction total:
/// revoking it revokes the whole derived subtree, in every other domain's
/// CSpace, before [`destroy`] returns.
///
/// # Errors
///
/// [`DomainError::TooManyDomains`] or [`DomainError::CapabilityExhausted`].
pub fn create(name: &'static str, envelope: ResourceEnvelope) -> Result<DomainId, DomainError> {
    let mut table = TABLE.lock();
    let index = table
        .domains
        .iter()
        .position(|domain| !domain.live)
        .ok_or(DomainError::TooManyDomains)?;

    let generation = table.domains[index].generation;
    let id = index as u32;

    // The capability first: if the arena is full, nothing has been changed.
    let root = cap::with_arena(|arena| {
        arena.insert_root(
            ObjectRef::new(ObjectKind::Domain, u64::from(id)),
            Rights::ALL,
            u64::from(id),
        )
    })
    .map_err(|_| DomainError::CapabilityExhausted)?;

    table.domains[index] = Domain {
        id,
        generation,
        name,
        cspace: CSpace::new(),
        envelope,
        charged_frames: 0,
        held_capabilities: 0,
        threads: 0,
        root: Some(root),
        live: true,
    };
    table.created += 1;
    Ok(DomainId(id))
}

/// Destroys a domain, revoking everything derived from its root capability.
///
/// Returns whether it existed. The revocation completes before this returns —
/// `docs/security.md` §2 rule 3 — so a destroyed domain's grants are dead
/// everywhere, not scheduled for cleanup.
pub fn destroy(id: DomainId) -> bool {
    // Memory objects first, and outside the table lock. A shared region does
    // not outlive the domain that made it (RFC 0009): the frames are charged
    // to this envelope, and leaving them would be a leak the frame gate would
    // find and nobody could explain. Done before the domain is marked dead, so
    // the release finds an envelope to release into.
    let objects = crate::shared::destroy_owned_by(id);
    let _ = objects;

    // Interrupt handlers next, and for the same reason: a handler outlives its
    // owner as a masked line and a spent vector, which nothing later can claim
    // and nobody can explain. RFC 0011 step 5 -- destroying a domain is
    // `RELEASE` for every handler it held. Outside the table lock, because
    // releasing reaches the chip and the vector allocator.
    let handlers = crate::irq::release_owned_by(id.0);
    let _ = handlers;

    // Threads next, and before the table is touched. Until RFC 0017 step 2
    // this function zeroed a counter and left them running: `destroy` released
    // a domain's accounting and its authority, and the programs carried on
    // with no capabilities -- contained, and not stopped.
    //
    // Marking is all that happens here. A thread stops at its own next safe
    // point, because stopping one where it stands may mean freeing the stack
    // it is standing on. Outside the table lock, because waking a blocked
    // thread takes runqueue locks and holding both would order two locks in a
    // way nothing else does -- the same reason the memory objects and the
    // interrupt handlers are released above.
    let stopped = crate::sched::mark_domain_dying(id.0);
    let _ = stopped;

    let root = {
        let mut table = TABLE.lock();
        let Some(domain) = table.domains.get_mut(id.0 as usize) else {
            return false;
        };
        if !domain.live {
            return false;
        }
        let root = domain.root.take();
        domain.live = false;
        domain.generation = domain.generation.wrapping_add(1);
        domain.charged_frames = 0;
        domain.held_capabilities = 0;
        domain.threads = 0;
        domain.cspace = CSpace::new();
        table.destroyed += 1;
        root
    };

    // Outside the table lock: revocation takes the capability arena, and
    // holding both would order the two locks in a way nothing else does.
    if let Some(root) = root {
        cap::with_arena(|arena| arena.revoke_unchecked(root));
    }
    true
}

/// Runs `f` against a live domain.
pub fn with<R>(id: DomainId, f: impl FnOnce(&mut Domain) -> R) -> Option<R> {
    let mut table = TABLE.lock();
    let domain = table.domains.get_mut(id.0 as usize)?;
    if !domain.live {
        return None;
    }
    Some(f(domain))
}

/// The domain a capability names, if it names one at all.
///
/// Type-checked before anything dereferences the identity: a capability to a
/// *frame* with the same numeric id must not be usable as a domain, and the
/// kind is part of the capability rather than looked up from the id precisely
/// so that this check is possible.
#[must_use]
pub fn from_capability(slot: SlotRef) -> Option<DomainId> {
    let (object, _) = cap::with_arena(|arena| arena.lookup(slot))?;
    if object.kind != ObjectKind::Domain {
        return None;
    }
    let id = DomainId(u32::try_from(object.id).ok()?);
    with(id, |_| ()).map(|()| id)
}

/// Charges frames against a domain's envelope.
///
/// # Errors
///
/// [`DomainError::NoSuchDomain`] or [`DomainError::MemoryEnvelopeExceeded`].
pub fn charge_frames(id: DomainId, frames: u64) -> Result<(), DomainError> {
    with(id, |domain| domain.charge_frames(frames)).unwrap_or(Err(DomainError::NoSuchDomain))
}

/// Releases frames back to a domain's envelope.
pub fn release_frames(id: DomainId, frames: u64) {
    let _ = with(id, |domain| domain.release_frames(frames));
}

/// Records that a domain gained a thread, and re-divides its CPU share.
///
/// # Errors
///
/// [`DomainError::NoSuchDomain`].
pub fn add_thread(id: DomainId, thread: u32) -> Result<(), DomainError> {
    let weight = with(id, |domain| {
        domain.threads += 1;
        domain.thread_weight()
    })
    .ok_or(DomainError::NoSuchDomain)?;

    // Every thread in the domain, not just the new one: adding a thread makes
    // each existing one's share smaller, and leaving them at the old weight is
    // exactly the "spawn threads for more CPU" hole this exists to close.
    reweight(id, weight, thread);
    Ok(())
}

/// Records that a domain lost a thread, and re-divides its CPU share.
pub fn remove_thread(id: DomainId, thread: u32) {
    let weight = with(id, |domain| {
        domain.threads = domain.threads.saturating_sub(1);
        domain.thread_weight()
    });
    if let Some(weight) = weight {
        let _ = thread;
        reweight(id, weight, u32::MAX);
    }
}

/// Applies `weight` to every thread of `id`, including `also` if it is not yet
/// recorded as belonging to the domain.
fn reweight(id: DomainId, weight: u32, also: u32) {
    sched::set_domain_weight(id.as_u32(), weight, also);
}

/// Domains created and destroyed since boot.
#[must_use]
pub fn statistics() -> (u64, u64) {
    let table = TABLE.lock();
    (table.created, table.destroyed)
}

/// Live domains.
#[must_use]
pub fn live() -> usize {
    TABLE.lock().domains.iter().filter(|d| d.live).count()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn domain(envelope: ResourceEnvelope) -> Domain {
        let mut domain = Domain::empty();
        domain.envelope = envelope;
        domain.live = true;
        domain
    }

    #[test]
    fn the_memory_envelope_refuses_rather_than_exceeding() {
        // `docs/security.md` T10: enforced at allocation time, not by best
        // effort. Refusing is the only behaviour that means anything to the
        // *other* domains.
        let mut domain = domain(ResourceEnvelope::new().memory_frames(10));
        assert_eq!(domain.charge_frames(6), Ok(()));
        assert_eq!(domain.charge_frames(4), Ok(()));
        assert_eq!(domain.charged_frames(), 10);

        assert_eq!(
            domain.charge_frames(1),
            Err(DomainError::MemoryEnvelopeExceeded {
                charged: 10,
                requested: 1,
                limit: 10,
            })
        );
        assert_eq!(
            domain.charged_frames(),
            10,
            "a refused charge must not be partially applied"
        );
    }

    #[test]
    fn a_refused_charge_leaves_room_for_a_smaller_one() {
        // The failure must be about this request, not a latch that puts the
        // domain into a permanently-failing state.
        let mut domain = domain(ResourceEnvelope::new().memory_frames(10));
        domain.charge_frames(8).unwrap();
        assert!(domain.charge_frames(5).is_err());
        assert_eq!(domain.charge_frames(2), Ok(()));
    }

    #[test]
    fn a_huge_request_cannot_wrap_past_the_limit() {
        // Saturating arithmetic, so a request near `u64::MAX` is refused
        // rather than wrapping to a small total that fits.
        let mut domain = domain(ResourceEnvelope::new().memory_frames(10));
        domain.charge_frames(5).unwrap();
        assert!(domain.charge_frames(u64::MAX).is_err());
        assert_eq!(domain.charged_frames(), 5);
    }

    #[test]
    fn releasing_more_than_was_charged_reports_zero_rather_than_wrapping() {
        let mut domain = domain(ResourceEnvelope::new().memory_frames(10));
        domain.charge_frames(3).unwrap();
        domain.release_frames(100);
        assert_eq!(domain.charged_frames(), 0);
    }

    #[test]
    fn the_capability_envelope_bounds_a_domain_that_derives_in_a_loop() {
        // The arena is a fixed global resource, so this is threat T10 through
        // a door that is easy not to watch.
        let mut domain = domain(ResourceEnvelope::new().max_capabilities(3));
        for _ in 0..3 {
            assert_eq!(domain.charge_capability(), Ok(()));
        }
        assert_eq!(
            domain.charge_capability(),
            Err(DomainError::CapabilityEnvelopeExceeded { held: 3, limit: 3 })
        );
        domain.release_capability();
        assert_eq!(domain.charge_capability(), Ok(()));
    }

    #[test]
    fn a_domains_cpu_share_does_not_grow_with_its_thread_count() {
        // `docs/scheduler.md` §3's claim, as arithmetic: the share is divided
        // among threads, so the domain's total weight is constant. Without
        // this, spawning threads is a way to take CPU from other domains.
        let mut domain = domain(ResourceEnvelope::new().cpu_shares(1200));

        domain.threads = 1;
        assert_eq!(domain.thread_weight(), 1200);
        domain.threads = 2;
        assert_eq!(domain.thread_weight(), 600);
        domain.threads = 4;
        assert_eq!(domain.thread_weight(), 300);

        // The product is what matters and it is invariant.
        for threads in 1..=64u32 {
            domain.threads = threads;
            let total = u64::from(domain.thread_weight()) * u64::from(threads);
            assert!(
                total <= 1200,
                "{threads} threads took {total} of a 1200 share"
            );
        }
    }

    #[test]
    fn a_thread_weight_is_never_zero() {
        // A zero weight divides by zero in the scheduler's virtual-time
        // accounting. A domain sliced thinner than its thread count gets the
        // floor instead, which is the honest failure.
        let mut domain = domain(ResourceEnvelope::new().cpu_shares(4));
        domain.threads = 100;
        assert_eq!(domain.thread_weight(), 1);
    }

    #[test]
    fn a_domain_with_no_threads_does_not_divide_by_zero() {
        let domain = domain(ResourceEnvelope::new().cpu_shares(512));
        assert_eq!(domain.threads(), 0);
        assert_eq!(domain.thread_weight(), 512);
    }
}
