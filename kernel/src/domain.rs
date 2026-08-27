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
pub const MAX_DOMAINS: usize = 64;
// Thirty-two, and now for a measured reason rather than an assumed one.
//
// It was raised to 64 on 2026-08-12 on the belief that a `NO_DOMAIN` refusal
// had exhausted the table. **That was a misreading**: the refusal in question
// was `outcome::NOT_YOURS`, which is also 7 and which was the value the test
// *expected*. Nothing was ever short of a domain. The instrumentation below was
// added to settle it and reports a high-water mark of **seven to nine slots**
// on a full boot, so thirty-two carries roughly three times the margin the
// machine has ever used.
//
// What remains true, and is why the measurement is of *occupied* rather than
// live slots: `create` takes the first entry that is neither live nor **ended**,
// because a domain's exit reason has to survive until somebody reaps it, which
// is what RFC 0017 step 6 rests on. So the effective capacity is the size minus
// every domain that has finished and not been reaped. That is a real property
// and it is worth knowing; it simply was not what went wrong.

/// The most slots ever occupied at once, live or ended-and-unreaped.
static PEAK_OCCUPIED: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// The high-water mark of occupied slots.
///
/// Occupied rather than live: a domain that has ended keeps its slot until it
/// is reaped, so this is the number that actually decides whether `create`
/// succeeds. Reported at boot so the table is sized by measurement instead of
/// by raising it whenever something fails.
#[must_use]
pub fn peak_occupied() -> usize {
    PEAK_OCCUPIED.load(core::sync::atomic::Ordering::Relaxed)
}
// Raised from 32 on 2026-08-12, and the number is a measurement rather than a
// guess -- which is what RFC 0017's third open question asked for.
//
// **A slot is not freed when a domain ends.** `create` takes the first entry
// that is neither live nor *ended*, because a domain's exit reason has to
// survive until somebody asks for it: that is what reaping is, and RFC 0017
// step 6 rests on it. So the table's effective capacity is its size minus every
// domain that has finished and not been reaped, and the kernel's own self-tests
// end a dozen domains that nothing ever reaps.
//
// It went unnoticed while the boot created few enough domains to fit anyway.
// RFC 0018 step 3 added one -- `ip` -- and a UEFI boot then failed in the
// *bulk-path self-test*, which creates two domains of its own and got
// `NO_DOMAIN` for the second. The symptom named a subsystem with nothing to do
// with networking, which is what a shared fixed table does when it runs out.
//
// Sixty-four rather than a reaper for the kernel's own corpses: a reaper is a
// policy decision about who owns an unreaped domain's exit reason, and that
// belongs in an RFC rather than in a bug fix. The cost is a larger fixed
// table; the alternative is a limit that depends on how many self-tests ran
// earlier in the same boot.

/// How a domain ended.
///
/// Recorded rather than merely counted, because a supervisor's restart policy
/// is a different decision for each: a program that exited did what it was
/// asked, one that faulted has a bug, one that was killed was killed on
/// purpose, and one that hit its envelope needs a bigger envelope rather than
/// another go.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Ending {
    /// Its last thread called the exit system call.
    Exited = 1,
    /// A thread took an exception in ring 3.
    Faulted = 2,
    /// A holder of its `Domain` capability said so.
    Killed = 3,
    /// It asked for a resource its envelope refuses, where no error could be
    /// returned.
    Envelope = 4,
}

/// How many bytes of a domain's name are kept.
///
/// Enough to tell programs apart in a fault report, and short enough that the
/// table stays a fixed cost. Names longer than this are truncated; see
/// [`Domain::name`].
pub const MAX_NAME: usize = 16;

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
    /// Cap on domains this domain may have in existence at once.
    ///
    /// [`MAX_DOMAINS`] is a fixed global resource in exactly the way the
    /// capability arena is, and once a program can create domains it can
    /// exhaust the table for everyone else. That is the same **T10** the line
    /// above closes, through the door
    /// [RFC 0017](../../docs/rfc/0017-process-management.md) step 4 opens — so
    /// this is a requirement of that step and not a refinement of it.
    ///
    /// Charged to the **creator**, not the child, because the resource being
    /// protected is the shared table and the creator is who consumes it.
    /// Default zero: a domain may not create domains unless it was given the
    /// budget to, which makes the capability *and* the envelope both necessary
    /// and neither sufficient.
    pub max_child_domains: u32,
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
            max_child_domains: 0,
        }
    }

    /// Sets how many domains this one may have in existence at once.
    #[must_use]
    pub const fn max_child_domains(mut self, limit: u32) -> Self {
        self.max_child_domains = limit;
        self
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
    /// The domain already has a thread, and the operation needed it not to.
    HasThreads,
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
    /// The request would exceed the creator's child-domain envelope.
    ChildEnvelopeExceeded {
        /// Children already in existence.
        held: u32,
        /// The cap.
        limit: u32,
    },
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

/// Which system-call dialect a domain's threads speak.
///
/// RFC 0005 step 2. `Native` is RFC 0008's capability interface; `Linux` is
/// the personality: every syscall from such a domain is foreign, answered
/// `-ENOSYS` and logged until a translator exists. The tag is the whole of
/// what the nucleus knows about Linux -- rule 1 of the RFC, enforced by
/// there being nowhere here to put more.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Personality {
    /// RFC 0008: six syscall kinds, all authority a capability argument.
    Native,
    /// The Linux x86_64 ABI, translated -- or, until a translator exists,
    /// refused with `-ENOSYS` and telemetry.
    Linux,
}

/// Which domain slots are Linux-tagged, as a bitmask over the whole table.
///
/// The syscall entry reads this once per call with a relaxed load -- the
/// same cost discipline as the telemetry class check. Maintained by
/// [`Domain::set_personality`] and cleared when a domain ends, so a reused
/// slot never inherits a dialect.
///
/// **One bit per domain, and the assertion below is what keeps that true.**
/// It was a `u32` masked with `% 32` while the table held 32, which is the
/// same number by coincidence rather than by construction: raising
/// [`MAX_DOMAINS`] to 64 without widening this would have made domain 33
/// alias domain 1, so a *native* domain would have had its system calls read
/// in Linux's dialect and handed to the adapter. Found by raising the
/// constant at RFC 0033 step 3; the assertion is so that the next raise
/// fails to build instead.
pub static LINUX_DOMAINS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Which domain, if any, may read what somebody types — RFC 0053.
///
/// **One at a time, because a console has one keyboard.** This is not a mask
/// like [`LINUX_DOMAINS`] but a single domain id, and that is the design rather
/// than a simplification: two domains reading one keyboard is exactly the
/// muddle the adapter's `WRITE`-only console was narrowed to prevent, and
/// letting two hold the grant would reintroduce it one level up.
///
/// `u32::MAX` means nobody, which is every boot that does not ask.
static INPUT_GRANTED_TO: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(u32::MAX);

/// Gives `id` the authority to read console input, if nobody else holds it.
///
/// # Errors
///
/// [`DomainError::NoSuchDomain`] if there is no such domain, and
/// [`DomainError::HasThreads`] — reused for "somebody else has it" — if another
/// live domain already holds the grant. **Refused rather than transferred**: a
/// grant that silently moved would take the keyboard from a program that is
/// blocked reading it, and that program would wait for a key that now goes
/// somewhere else.
pub fn grant_input(id: DomainId) -> Result<(), DomainError> {
    if with(id, |_| ()).is_none() {
        return Err(DomainError::NoSuchDomain);
    }
    let holder = INPUT_GRANTED_TO.load(core::sync::atomic::Ordering::Acquire);
    if holder != u32::MAX && holder != id.as_u32() && live_id(holder) {
        return Err(DomainError::HasThreads);
    }
    INPUT_GRANTED_TO.store(id.as_u32(), core::sync::atomic::Ordering::Release);
    Ok(())
}

/// Whether `domain` may read what somebody types.
#[must_use]
pub fn may_read_input(domain: u32) -> bool {
    INPUT_GRANTED_TO.load(core::sync::atomic::Ordering::Acquire) == domain
}

/// Takes the grant back, if `domain` holds it.
///
/// Called when a domain ends, so the keyboard is not held by something that is
/// gone — which would refuse every later grant for a domain nobody can name.
pub fn release_input(domain: u32) {
    let _ = INPUT_GRANTED_TO.compare_exchange(
        domain,
        u32::MAX,
        core::sync::atomic::Ordering::AcqRel,
        core::sync::atomic::Ordering::Relaxed,
    );
}

/// Whether a domain with this raw id is live, for the grant's own check.
fn live_id(raw: u32) -> bool {
    with(DomainId::from_u32(raw), |_| ()).is_some()
}

// One bit per domain, or the mask aliases and a dialect is applied to the
// wrong program. See `LINUX_DOMAINS`.
const _: () = {
    assert!(MAX_DOMAINS <= u64::BITS as usize);
    // The arena attributes capabilities to owners by domain id, so its table
    // and this one are the same table wearing two names. They are declared
    // apart on purpose (see `cap::MAX_OWNERS`) and checked together here.
    assert!(MAX_DOMAINS == crate::cap::MAX_OWNERS);
    // And a *ring 3* server that keeps a table per hosted domain sizes it by
    // the ABI's copy of this number. A server holding 32 rows for a 64-domain
    // machine would give two domains one row of signal handlers.
    assert!(MAX_DOMAINS == bhaskix_abi::limits::MAX_DOMAINS);
};

/// What one entry of the domain table costs.
///
/// For the boot report's bill — RFC 0033 step 3 raised the table from 32 to
/// 64 and the CSpace inside each entry from 64 slots to 128, which is four
/// times the memory. A number printed on every boot is a number a reviewer
/// can object to; an estimate in a commit message is not.
#[must_use]
pub fn size_of_domain() -> usize {
    core::mem::size_of::<Domain>()
}

/// The unit of isolation, accounting and scheduling.
pub struct Domain {
    id: u32,
    /// Distinguishes a reused slot from the domain that held it before.
    generation: u32,
    /// The name, inline.
    ///
    /// A `&'static str` until RFC 0017 step 4, which is by itself a statement
    /// that every caller is compiled into the kernel — a domain created at
    /// runtime has nowhere to get one. Sixteen bytes, truncated rather than
    /// refused: a name is a diagnostic aid, and failing to start a program
    /// because its name is long would be a worse outcome than a short name in
    /// a report.
    name: [u8; MAX_NAME],
    /// How much of `name` is used.
    name_len: u8,
    /// The domain charged for this one's existence, or `u32::MAX` for none.
    ///
    /// Boot-created domains have none, which is correct rather than a gap:
    /// nothing charged for them and nothing will be refunded.
    parent: u32,
    /// Which incarnation of `parent`, so a reused slot is not mistaken for it.
    ///
    /// A slot index alone is not an identity here. Domains are destroyed and
    /// their slots reused, so a child recording "my parent is slot 5" would be
    /// claimed by whatever domain occupied slot 5 next — and destroying *that*
    /// would take an unrelated domain down with it, which is the worst
    /// available outcome for a mechanism whose whole job is to stop things
    /// deliberately.
    ///
    /// It cannot happen today, because a child is destroyed with its parent
    /// and a child may have no children of its own. Both of those are policy
    /// in `spawn`, and this is the mechanism; the mechanism should not be
    /// correct only for as long as the policy holds.
    parent_generation: u32,
    /// Domains this one has created that still exist.
    children: u32,
    /// How this domain ended, once it has.
    ///
    /// **A dead domain keeps its slot until it is reaped.** Otherwise "what
    /// happened to it" is a race against whoever asks: the slot would be free,
    /// something else would take it, and the answer would be about a different
    /// domain — or would be "no such domain", which is true and useless.
    ///
    /// Only domains with a **parent** are kept this way. Those are the ones a
    /// program created and can be asked about. A domain the kernel made at boot
    /// has nobody to ask and nobody to reap it, and keeping it would fill a
    /// table of 32 with the remains of self-tests.
    ended: Option<Ending>,
    /// A notification to signal when this domain ends, and with what badge.
    notify: Option<(crate::notify::NotificationId, u64)>,
    /// An image waiting for this domain's first thread to collect it.
    ///
    /// Set by `START` and taken by the thread it spawns. It lives here because
    /// a thread entry point takes one word and this needs three, and a domain
    /// is the identity both sides already agree on.
    pending_start: Option<(crate::shared::MemoryId, usize, u64)>,
    /// A Linux `clone`'s parameters, waiting for the thread it creates —
    /// RFC 0005 step 6's missing half. `(entry, stack, tls)`, all three the
    /// caller's own: the personality creates a thread in the domain the
    /// caller already has, running code the caller already mapped.
    pending_clone: Option<(u64, u64, u64)>,
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
    /// Which system-call dialect this domain's threads speak.
    personality: Personality,
    /// The capability naming this domain. Revoking it revokes everything the
    /// domain was ever granted, because everything was derived from it.
    root: Option<SlotRef>,
    /// The page table the domain's program runs in, or zero before one is
    /// installed.
    ///
    /// Recorded so that [`end`] can give the address-space slot back. `vm`
    /// holds installed spaces in a table of `MAX_SPACES`, keyed by root, and
    /// without this nothing ever knows which entry belonged to a domain that
    /// has gone -- so every domain that ended kept its slot for ever, and the
    /// ninth program to start silently ran with unserviceable faults.
    space_root: u64,
    live: bool,
}

impl Domain {
    const fn empty() -> Self {
        Self {
            id: 0,
            generation: 0,
            name: [0; MAX_NAME],
            name_len: 0,
            parent: u32::MAX,
            parent_generation: 0,
            children: 0,
            ended: None,
            notify: None,
            pending_start: None,
            pending_clone: None,
            cspace: CSpace::new(),
            envelope: ResourceEnvelope::new(),
            charged_frames: 0,
            held_capabilities: 0,
            threads: 0,
            personality: Personality::Native,
            root: None,
            space_root: 0,
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
    pub fn name(&self) -> &str {
        // Lossy rather than fallible. The bytes came from a caller that may
        // have sent anything, and a name that failed to render would take a
        // diagnostic away at the moment it is being read.
        core::str::from_utf8(&self.name[..self.name_len as usize]).unwrap_or("?")
    }

    /// The domain charged for this one's existence, if any.
    #[must_use]
    pub const fn parent(&self) -> Option<u32> {
        if self.parent == u32::MAX {
            None
        } else {
            Some(self.parent)
        }
    }

    /// How many domains this one has created that still exist.
    #[must_use]
    pub const fn children(&self) -> u32 {
        self.children
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
pub fn create(name: &str, envelope: ResourceEnvelope) -> Result<DomainId, DomainError> {
    create_under(None, name, envelope)
}

/// A domain's name, copied out of the table.
///
/// Exists because the name stopped being `&'static str` at RFC 0017 step 4: a
/// runtime-created domain's name lives in the table, so a borrow of it cannot
/// outlive the lock, and every caller that wants to *print* a name wants to do
/// so after releasing it.
#[derive(Clone, Copy)]
pub struct Name {
    bytes: [u8; MAX_NAME],
    len: u8,
}

impl Name {
    /// The name as a string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.bytes[..self.len as usize]).unwrap_or("?")
    }
}

impl core::fmt::Display for Name {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl core::fmt::Debug for Name {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Debug::fmt(self.as_str(), formatter)
    }
}

/// Which CPU the next started program is pinned to.
static NEXT_CPU: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Parks a `clone`'s parameters for the thread about to be spawned.
///
/// Refused if one is already waiting: two clones racing for one slot would
/// have a thread start on the other's stack, which is the corruption this
/// whole step exists to avoid.
///
/// # Errors
///
/// [`DomainError::NoSuchDomain`], or [`DomainError::HasThreads`] when a
/// clone is already pending — the nearest existing variant for "not now".
pub fn record_pending_clone(
    id: DomainId,
    entry: u64,
    stack: u64,
    tls: u64,
) -> Result<(), DomainError> {
    with(id, |domain| {
        if domain.pending_clone.is_some() {
            return Err(DomainError::HasThreads);
        }
        domain.pending_clone = Some((entry, stack, tls));
        Ok(())
    })
    .unwrap_or(Err(DomainError::NoSuchDomain))
}

/// Takes the parked `clone` parameters, if any.
pub fn take_pending_clone(id: DomainId) -> Option<(u64, u64, u64)> {
    with(id, |domain| domain.pending_clone.take()).flatten()
}

/// Records the image a domain is about to be started with.
///
/// Kept in the domain itself, under the table lock that already exists, rather
/// than in a table of its own. A second lock would need a rank, and a rank
/// beside `Rank::Domains` would be two locks with no order between them that
/// every future caller has to remember not to nest.
///
/// Returns `false` if one is already recorded, which means two starts raced:
/// the second is refused rather than overwriting the first, because the first
/// already has a thread on its way to collect it.
pub fn record_pending_start(
    id: DomainId,
    image: crate::shared::MemoryId,
    length: usize,
    argument: u64,
) -> bool {
    let mut table = TABLE.lock();
    let Some(domain) = table.domains.get_mut(id.0 as usize).filter(|d| d.live) else {
        return false;
    };
    if domain.pending_start.is_some() {
        return false;
    }
    domain.pending_start = Some((image, length, argument));
    true
}

/// Takes the image a domain was started with, if one is waiting.
pub fn take_pending_start(id: DomainId) -> Option<(crate::shared::MemoryId, usize, u64)> {
    let mut table = TABLE.lock();
    table.domains.get_mut(id.0 as usize)?.pending_start.take()
}

/// The CPU to pin the next started program to.
///
/// Rotated across the online processors. A pinned thread cannot be moved
/// afterwards, so this is an argument for spreading rather than for choosing
/// well: getting it wrong once is permanent, and the cheapest way to be wrong
/// rarely is not to concentrate.
#[must_use]
pub fn next_start_cpu() -> u32 {
    let online = bhaskix_arch::percpu::online_count().max(1);
    NEXT_CPU.fetch_add(1, core::sync::atomic::Ordering::Relaxed) % online
}

/// How a domain is, for a holder of a capability to it.
///
/// `Ok(None)` means it is still running. `Ok(Some(reason))` means it has ended
/// and has not been reaped. `Err(())` means there is no such domain — either it
/// never existed or it was reaped, and those are deliberately the same answer:
/// a caller that could tell them apart would be asking about a slot rather than
/// about a domain.
#[allow(clippy::result_unit_err)]
pub fn state_of(id: DomainId) -> Result<Option<Ending>, ()> {
    let table = TABLE.lock();
    let domain = table.domains.get(id.0 as usize).ok_or(())?;
    if domain.live {
        Ok(None)
    } else if let Some(reason) = domain.ended {
        Ok(Some(reason))
    } else {
        Err(())
    }
}

/// Ends `id` because its last thread finished — **whoever made it**.
///
/// Returns whether it ended anything.
///
/// # The exemption this used to carry, and why it is gone
///
/// Until 2026-08-11 a domain the *kernel* created was exempt: only a domain a
/// *program* had created ended when its threads ran out. RFC 0017 recorded that
/// as its fourth open question and as a limitation rather than a decision, and
/// the reason was not about domains at all. Several boot self-tests created a
/// memory object **owned by the domain they were about to run a thread in**,
/// and then checked its contents after that thread exited — and [`end`] calls
/// `shared::destroy_owned_by`, so the object died with the domain. Ending those
/// domains replaced a passing test with `NoDomain`.
///
/// The fix was in the tests and not here: the thing that verifies now owns what
/// it verifies, and hands the child a capability. That is the shape the rest of
/// the system already used — a program that starts another program owns the
/// image and grants it — so the exemption was the odd one out rather than the
/// tests being unusual.
///
/// One rule now: a domain with no threads left is over, and who created it does
/// not enter into it.
pub fn ended_by_last_thread(id: DomainId) -> bool {
    {
        let table = TABLE.lock();
        let Some(domain) = table.domains.get(id.0 as usize) else {
            return false;
        };
        if !domain.live {
            return false;
        }
    }
    end(id, Ending::Exited)
}

/// Releases a dead domain's slot.
///
/// Returns whether there was something to reap. Refuses a domain that is still
/// running: reaping is what *follows* an ending, and a call that could do both
/// would let a holder destroy a domain by asking about it.
pub fn reap(id: DomainId) -> bool {
    let mut table = TABLE.lock();
    let Some(domain) = table.domains.get_mut(id.0 as usize) else {
        return false;
    };
    if domain.live || domain.ended.is_none() {
        return false;
    }
    domain.ended = None;
    domain.notify = None;
    domain.parent = u32::MAX;
    domain.children = 0;
    true
}

/// Asks to be told when `id` ends.
///
/// Returns `false` for a domain that has already ended, and that is the useful
/// answer rather than a courtesy: a binding made after the fact would wait for
/// an event that has happened, which is the shape of every missed wakeup. A
/// caller told `false` should ask [`state_of`] instead, which has the answer.
pub fn notify_on_end(
    id: DomainId,
    notification: crate::notify::NotificationId,
    badge: u64,
) -> bool {
    let mut table = TABLE.lock();
    let Some(domain) = table.domains.get_mut(id.0 as usize).filter(|d| d.live) else {
        return false;
    };
    domain.notify = Some((notification, badge));
    true
}

/// The capability naming a domain, from which everything it is granted derives.
///
/// Exposed so a creator can be handed a capability *under* the root rather than
/// the root itself — which is what makes destroying the domain revoke the
/// creator's copy along with everything else it ever passed on.
#[must_use]
pub fn root_capability(id: DomainId) -> Option<SlotRef> {
    with(id, |domain| domain.root).flatten()
}

/// The page-table root a domain's program runs in, or `None` before one is
/// installed. RFC 0005 step 6's clone needs it: a new thread of a running
/// domain does not build a space, it *adopts* the one its siblings are in.
#[must_use]
pub fn space_root_of(id: DomainId) -> Option<u64> {
    with(id, |domain| domain.space_root).filter(|root| *root != 0)
}

/// Records the page table a domain's program runs in, so [`end`] can give the
/// address-space slot back.
///
/// Called by `vm::install`, which is the only thing that puts a space in the
/// table this reclaims from — the same place, and for the same reason, that it
/// calls `sched::set_space_root` for the thread.
///
/// A domain that starts a second program overwrites the first root. That is
/// correct rather than lossy: `install` reuses the slot already holding a root
/// it is replacing, so the entry this would have named is not a separate one.
pub fn record_space_root(id: DomainId, root: u64) {
    with(id, |domain| domain.space_root = root);
}

/// The first live domain created by `parent`, if any.
///
/// A test affordance rather than a general facility: nothing in the system
/// needs to enumerate children, because a creator holds capabilities to the
/// ones it made and that is how it names them. This exists so a gate can ask
/// what a program created without the program having to tell it.
#[must_use]
pub fn child_of(parent: DomainId) -> Option<DomainId> {
    let table = TABLE.lock();
    table
        .domains
        .iter()
        .find(|domain| domain.live && domain.parent == parent.0)
        .map(|domain| DomainId(domain.id))
}

/// A live domain's name, copied so it outlives the table lock.
#[must_use]
pub fn name_of(id: DomainId) -> Option<Name> {
    with(id, |domain| Name {
        bytes: domain.name,
        len: domain.name_len,
    })
}

/// Creates a domain charged to `parent`, if there is one.
///
/// The charge is the whole of this function's reason to exist. [`MAX_DOMAINS`]
/// is a fixed global resource, so a domain that can create domains can exhaust
/// the table for every other domain on the machine — `security.md` §1 **T10**,
/// reopened by the feature that lets a program start a program. Charging the
/// creator closes it, and it must be closed in the same change that opens it.
///
/// # Errors
///
/// As [`create`], plus [`DomainError::ChildEnvelopeExceeded`] when the parent
/// already has as many children as its envelope allows, and
/// [`DomainError::NoSuchDomain`] if the parent has gone.
pub fn create_under(
    parent: Option<u32>,
    name: &str,
    envelope: ResourceEnvelope,
) -> Result<DomainId, DomainError> {
    let mut table = TABLE.lock();

    // Charged before anything is allocated, so a refusal changes nothing. The
    // envelope refuses; it does not warn and it does not succeed and notify.
    if let Some(parent) = parent {
        let owner = table
            .domains
            .get_mut(parent as usize)
            .filter(|domain| domain.live)
            .ok_or(DomainError::NoSuchDomain)?;
        if owner.children >= owner.envelope.max_child_domains {
            return Err(DomainError::ChildEnvelopeExceeded {
                held: owner.children,
                limit: owner.envelope.max_child_domains,
            });
        }
    }

    // A free slot is one with no live domain, no corpse waiting to be reaped,
    // **and no thread of its previous incarnation still running**. The third
    // condition is the one that is easy to miss and expensive to have missed:
    // see `sched::threads_counted_in`. Refusing here costs a domain creation
    // that could have waited a tick; not refusing cost an innocent domain its
    // authority, intermittently, in a different self-test each time.
    // Keyed by the slot's *position*, not by `Domain::id`: a slot that has
    // never been used carries the `empty()` id of zero, so asking the domain
    // would ask about slot 0 thirty-two times over.
    let index = table
        .domains
        .iter()
        .enumerate()
        .position(|(slot, domain)| {
            !domain.live
                && domain.ended.is_none()
                && crate::sched::threads_counted_in(slot as u32) == 0
        })
        .ok_or(DomainError::TooManyDomains)?;

    // The high-water mark of *occupied* slots, which is not the same as live
    // domains: a slot is held until its domain is reaped. Recorded because the
    // difference between those two numbers is the whole reason this table runs
    // out, and until now nothing measured it -- the table was sized by raising
    // it whenever something failed.
    let occupied = table
        .domains
        .iter()
        .filter(|domain| domain.live || domain.ended.is_some())
        .count()
        + 1;
    PEAK_OCCUPIED.fetch_max(occupied, core::sync::atomic::Ordering::Relaxed);

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

    let mut stored = [0u8; MAX_NAME];
    let taken = name.len().min(MAX_NAME);
    stored[..taken].copy_from_slice(&name.as_bytes()[..taken]);

    table.domains[index] = Domain {
        id,
        generation,
        name: stored,
        name_len: taken as u8,
        parent: parent.unwrap_or(u32::MAX),
        parent_generation: parent
            .and_then(|parent| table.domains.get(parent as usize))
            .map_or(0, |owner| owner.generation),
        children: 0,
        ended: None,
        notify: None,
        pending_start: None,
        pending_clone: None,
        cspace: CSpace::new(),
        envelope,
        charged_frames: 0,
        held_capabilities: 0,
        threads: 0,
        personality: Personality::Native,
        root: Some(root),
        space_root: 0,
        live: true,
    };
    table.created += 1;

    // After the child exists, so a failure above leaves nothing charged. The
    // parent was checked under this same lock, which is why it cannot have gone
    // away in between.
    if let Some(parent) = parent
        && let Some(owner) = table.domains.get_mut(parent as usize)
    {
        owner.children = owner.children.saturating_add(1);
    }
    Ok(DomainId(id))
}

/// Destroys a domain, revoking everything derived from its root capability.
///
/// Returns whether it existed. The revocation completes before this returns —
/// `docs/security.md` §2 rule 3 — so a destroyed domain's grants are dead
/// everywhere, not scheduled for cleanup.
pub fn destroy(id: DomainId) -> bool {
    end(id, Ending::Killed)
}

/// Ends a domain, recording *why*.
///
/// The same teardown as [`destroy`] in every respect but one: a domain that was
/// created by a program keeps its slot afterwards, holding the reason, until
/// somebody reaps it. A domain the kernel made at boot is freed at once,
/// because nobody can ask about it and nothing would ever release the slot.
///
/// # Errors
///
/// Returns whether the domain existed.
pub fn end(id: DomainId, reason: Ending) -> bool {
    // Memory objects first, and outside the table lock. A shared region does
    // not outlive the domain that made it (RFC 0009): the frames are charged
    // to this envelope, and leaving them would be a leak the frame gate would
    // find and nobody could explain. Done before the domain is marked dead, so
    // the release finds an envelope to release into.
    let objects = crate::shared::destroy_owned_by(id);
    let _ = objects;

    // The keyboard, if this domain held it -- RFC 0053. A grant left behind by
    // a domain that is gone refuses every later one for a holder nobody can
    // name, which is a console that stops working for the rest of the boot.
    release_input(id.as_u32());

    // Interrupt handlers next, and for the same reason: a handler outlives its
    // owner as a masked line and a spent vector, which nothing later can claim
    // and nobody can explain. RFC 0011 step 5 -- destroying a domain is
    // `RELEASE` for every handler it held. Outside the table lock, because
    // releasing reaches the chip and the vector allocator.
    let handlers = crate::irq::release_owned_by(id.0);
    let _ = handlers;

    // The address-space slot next, and for the third time the same reason: an
    // installed space outlives its domain as an entry in a table of
    // `vm::MAX_SPACES`, which nothing later can claim and nobody can explain.
    // Until this existed, every domain that ended kept its slot, and the ninth
    // program to start got `no free slot` and ran with faults that could not be
    // serviced -- reported, six days running, as a fault in whatever *else*
    // started ninth.
    //
    // Outside the table lock, because `Rank::AddressSpace` is 0 and
    // `Rank::Domains` is 6: taking the space table while holding this one would
    // invert the order, which is exactly what the memory objects and the
    // handlers above are placed here to avoid.
    //
    // The frames are **not** freed. `AddressSpace::destroy` requires that no
    // CPU holds the root in `CR3`, and that does not hold here:
    // `sched::enter_space` skips the reload for kernel threads, so the CPU
    // whose last user thread just exited is still running on these page tables.
    // Dropping the bookkeeping is safe because they stay allocated. Reclaiming
    // them needs every CPU moved off the root first, which is its own change --
    // see TRACKER.
    if let Some(root) = with(id, |domain| core::mem::take(&mut domain.space_root))
        && root != 0
    {
        crate::vm::forget(root);
    }

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
        let parent = domain.parent;
        // Kept only if somebody can ask. See `Domain::ended`.
        // Kept only if somebody can ask, which means a parent that is still
        // alive. A domain whose creator has gone has nobody to tell and nobody
        // to reap it, and keeping it would fill a table of 32 with corpses no
        // living program can name.
        let watched = parent != u32::MAX
            && table
                .domains
                .get(parent as usize)
                .is_some_and(|owner| owner.live);
        let domain = &mut table.domains[id.0 as usize];
        domain.ended = watched.then_some(reason);
        // The dialect dies with the domain: a reused slot must never inherit
        // a Linux tag, because the syscall entry's bitmask is keyed by slot.
        domain.personality = Personality::Native;
        LINUX_DOMAINS.fetch_and(
            !(1u64 << (id.0 as usize % MAX_DOMAINS)),
            core::sync::atomic::Ordering::Relaxed,
        );
        let notify = domain.notify.take();
        let parent_generation = domain.parent_generation;
        // Captured before the increment below: the children still recorded
        // against this domain recorded *this* incarnation of it.
        let mine = domain.generation;
        domain.parent = u32::MAX;
        domain.live = false;
        domain.generation = domain.generation.wrapping_add(1);
        domain.charged_frames = 0;
        domain.held_capabilities = 0;
        domain.threads = 0;
        domain.cspace = CSpace::new();
        domain.pending_start = None;
        table.destroyed += 1;

        // The creator gets its budget back. Under the same lock that marked
        // this domain dead, so there is no instant where the child is gone and
        // the parent is still charged for it -- which is the direction that
        // leaks, and it leaks a limit rather than memory: the parent quietly
        // loses the ability to start something later, for no reason anyone
        // could find.
        if parent != u32::MAX
            && let Some(owner) = table.domains.get_mut(parent as usize)
            && owner.live
            && owner.generation == parent_generation
        {
            owner.children = owner.children.saturating_sub(1);
        }
        // Every domain this one created, collected while the table is held.
        //
        // **The capability tree does not do this on its own**, and RFC 0017
        // said it did. A child's root is inserted into the arena as a *root*,
        // not derived from its creator's, so revoking the creator reaches the
        // copy it was handed and stops there. Measured: a program created a
        // domain, its creator was destroyed, and the child was still live.
        //
        // Collected rather than destroyed here, because destroying takes this
        // same lock.
        let mut children = [0u32; MAX_DOMAINS];
        let mut count = 0;
        for domain in &table.domains {
            if domain.live
                && domain.parent == id.0
                && domain.parent_generation == mine
                && count < children.len()
            {
                children[count] = domain.id;
                count += 1;
            }
        }

        (root, children, count, notify)
    };
    let (root, children, count, notify) = root;

    // Outside the table lock, because signalling wakes a waiter and waking
    // takes runqueue locks.
    //
    // After the domain is marked dead and its reason recorded, so a supervisor
    // woken by this finds the answer already there. Signalled before the
    // children are ended, which means a supervisor watching a parent hears
    // about it before it hears about the parent's children -- which is the
    // order the events happened in.
    if let Some((notification, badge)) = notify {
        let _ = crate::notify::signal(notification, badge);
    }

    // Depth is bounded by the table: a domain cannot be its own ancestor, and
    // there are 32 slots. Today it is at most one level, because a child's
    // envelope allows it no children of its own -- but that is a policy in
    // `spawn` and this is the mechanism, and the mechanism should not depend
    // on the policy staying that way.
    for child in children.iter().take(count) {
        destroy(DomainId(*child));
    }

    // Outside the table lock: revocation takes the capability arena, and
    // holding both would order the two locks in a way nothing else does.
    if let Some(root) = root {
        cap::with_arena(|arena| arena.revoke_unchecked(root));
    }
    true
}

impl Domain {
    /// The dialect this domain's threads speak.
    #[must_use]
    pub const fn personality(&self) -> Personality {
        self.personality
    }

    /// Whether a thread exists in this domain.
    ///
    /// Both thread counts, because they answer at different moments: the
    /// table's own field counts RFC 0017 `START`ed programs, and the
    /// scheduler's atomic counts every spawned thread from the instant of its
    /// spawn -- including kernel-spawned test threads, which is exactly what
    /// the first version of [`Domain::set_personality`]'s guard missed. A tag
    /// change must lose to a thread that merely *exists*, not only to one that
    /// has registered.
    ///
    /// **Not public, and there is a story in that.** It was made public on
    /// 2026-08-25 so a self-test could ask the same question
    /// `set_personality` asks, under the same table lock, in the same instant
    /// -- and that does not work: this consults the **scheduler's** queues,
    /// which that lock does not cover, so the answer can change between two
    /// calls inside one closure. Measured: one boot in ten read "a thread
    /// exists" and then had the tag change accepted. Private again, because an
    /// accessor whose only purpose was an approach that failed is an invitation
    /// to try it again.
    #[must_use]
    fn has_threads(&self) -> bool {
        // **The exact scan, not the `try_lock` one.** `threads_in_domain`
        // counts a queue it could not take as empty, which is safe for a
        // caller that polls and wrong for one that decides. This decides.
        //
        // And it is the whole guard in practice: `self.threads` counts RFC
        // 0017 `START`ed programs, a counter `syscall.rs` records as reading
        // "zero for every domain" outside one self-test -- so the scan is not
        // a second opinion, it is the only one.
        self.threads > 0 || crate::sched::threads_in_domain_exact(self.id) > 0
    }

    /// Sets the dialect — refused once the domain has a thread, because a
    /// program half-run under one ABI and finished under another is not a
    /// state anyone can reason about. The bitmask the syscall entry reads
    /// is maintained here and only here.
    ///
    /// # Errors
    ///
    /// [`DomainError::HasThreads`] if a thread already exists — which is
    /// exactly [`Domain::has_threads`], so a caller can ask what this will
    /// answer before it answers.
    pub fn set_personality(&mut self, personality: Personality) -> Result<(), DomainError> {
        if self.has_threads() {
            return Err(DomainError::HasThreads);
        }
        self.personality = personality;
        let bit = 1u64 << (self.id as usize % MAX_DOMAINS);
        match personality {
            Personality::Linux => {
                LINUX_DOMAINS.fetch_or(bit, core::sync::atomic::Ordering::Relaxed);
            }
            Personality::Native => {
                LINUX_DOMAINS.fetch_and(!bit, core::sync::atomic::Ordering::Relaxed);
            }
        }
        Ok(())
    }
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

    /// Held by the tests that touch the **global** input grant, one at a time.
    ///
    /// RFC 0053's grant is a single domain id for the whole machine, because a
    /// console has one keyboard — so two tests exercising it in parallel take
    /// it from each other. Caught the way these always are: the pair passed
    /// alone and failed together. `notify` and the console service each learned
    /// this and each wrote it down; this is the third.
    static KEYBOARD: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn holds_the_keyboard() -> std::sync::MutexGuard<'static, ()> {
        KEYBOARD
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

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

    /// RFC 0053: the grant is one domain's at a time, and a dead holder does
    /// not keep it.
    #[test]
    fn input_is_granted_to_one_domain_and_released_with_it() {
        let _keyboard = holds_the_keyboard();
        let first = create("input-a", ResourceEnvelope::new()).expect("a domain");
        let second = create("input-b", ResourceEnvelope::new()).expect("another");

        assert!(grant_input(first).is_ok(), "nobody held it");
        assert!(may_read_input(first.as_u32()));
        assert!(
            !may_read_input(second.as_u32()),
            "and only the one that has it"
        );

        // **Refused rather than transferred.** A grant that silently moved would
        // take the keyboard from a program blocked reading it.
        assert!(
            grant_input(second).is_err(),
            "the first still holds it and is still alive"
        );

        // Ending the holder gives it back, or the console stops working for the
        // rest of the boot: every later grant would be refused for a holder
        // nobody can name.
        destroy(first);
        assert!(!may_read_input(first.as_u32()));
        assert!(grant_input(second).is_ok(), "the keyboard is free again");
        assert!(may_read_input(second.as_u32()));
        destroy(second);
    }

    /// Granting it twice to the same domain is not a refusal.
    #[test]
    fn a_domain_may_be_granted_input_it_already_has() {
        let _keyboard = holds_the_keyboard();
        let only = create("input-c", ResourceEnvelope::new()).expect("a domain");
        assert!(grant_input(only).is_ok());
        assert!(grant_input(only).is_ok(), "idempotent, not a second holder");
        destroy(only);
    }
}
