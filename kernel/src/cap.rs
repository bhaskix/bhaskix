// SPDX-License-Identifier: Apache-2.0
//! Capabilities: the authority mechanism.
//!
//! Implements [`architecture.md`] §3 and the four rules of [`security.md`] §2.
//! There is no user identity in the nucleus and no `root`. Authority is a
//! thing a domain *holds*, not a thing it *is*.
//!
//! [`architecture.md`]: ../../../docs/architecture.md
//! [`security.md`]: ../../../docs/security.md
//!
//! # The four rules, and where each one lives
//!
//! | Rule | Enforced by |
//! |---|---|
//! | Unforgeable | [`CSpace`] — a domain holds an index, meaningless outside its own space |
//! | Monotone derivation | [`Arena::derive`], one function, tested over every rights pair |
//! | Immediate transitive revocation | [`Arena::revoke`], completing before it returns |
//! | Granter-set badges | no API lets a holder read or write its own badge |
//!
//! # Why the derivation tree is global rather than per-domain
//!
//! Revocation has to be transitive across domains, because the whole point of
//! granting is that the capability ends up somewhere else. A per-domain tree
//! could not answer "what was derived from this?" once the answer lived in
//! another domain's space.
//!
//! So derivation lives in one arena, and a domain's [`CSpace`] holds
//! *references* into it. Revoking a node invalidates every slot in every
//! CSpace that refers to it or to anything below it, with no domain traversal
//! at all — the slots do not need to be found, because they were never the
//! authority. The node was.
//!
//! # Why slots carry a generation
//!
//! Arena entries are reused. Without a generation, a stale index would silently
//! address whatever now occupies that entry — a use-after-free that hands out
//! authority instead of crashing, which is the worst possible version of it.
//! A slot therefore records the generation it was created against, and a
//! mismatch reads as "revoked" rather than as a different object.
//!
//! # What is not here yet
//!
//! - **No objects.** [`ObjectRef`] names a kind and an identity; nothing yet
//!   maps an identity to a frame, a thread or an endpoint. That arrives with
//!   the objects themselves in M5-02 onwards.
//! - **No syscall interface.** [RFC 0008] proposes it; this is the layer
//!   beneath, deliberately built first because it does not depend on the
//!   answer.
//! - **No allocation.** Both the arena and every CSpace are fixed arrays, so
//!   nothing on the invocation path can fail for want of memory. The cost is a
//!   hard ceiling on live capabilities, recorded below.
//!
//! [RFC 0008]: ../../../docs/rfc/0008-syscall-and-ipc-shape.md

use crate::sync::{Rank, SpinLock};

/// Live capabilities across the whole system.
///
/// Fixed, so that deriving a capability cannot fail for want of memory on a
/// path that must not allocate. It is also a denial-of-service surface: a
/// domain that derives in a loop exhausts a global resource. Per-domain quotas
/// belong in `ResourceEnvelope` and are recorded as outstanding.
pub const MAX_CAPABILITIES: usize = 4096;

/// Capability slots one domain can hold.
pub const CSPACE_SLOTS: usize = 128;

/// Distinct owners the arena can attribute capabilities to.
///
/// Matches `domain::MAX_DOMAINS`, and is declared here rather than imported so
/// that the arena does not depend on the domain table — the dependency runs
/// the other way, and a cycle would make either one impossible to test alone.
pub const MAX_OWNERS: usize = 64;

/// The owner of a capability the kernel created for itself.
pub const OWNER_KERNEL: u32 = u32::MAX;

/// What a capability permits.
///
/// A bitmask rather than an enum: rights compose, and derivation is defined by
/// subset, which is one instruction on a mask and a case analysis on anything
/// else.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
pub struct Rights(u8);

impl Rights {
    /// No authority at all. A valid capability that permits nothing — useful
    /// as a proof of identity without power, which badges make meaningful.
    pub const NONE: Self = Self(0);
    /// Read the object's contents.
    pub const READ: Self = Self(1 << 0);
    /// Modify the object.
    pub const WRITE: Self = Self(1 << 1);
    /// Execute from it, where that means anything.
    pub const EXECUTE: Self = Self(1 << 2);
    /// Pass a copy to another domain.
    pub const GRANT: Self = Self(1 << 3);
    /// Revoke this capability and everything below it.
    pub const REVOKE: Self = Self(1 << 4);
    /// Create a weaker capability from this one.
    pub const DERIVE: Self = Self(1 << 5);

    /// Every right. Only a root capability should hold this.
    pub const ALL: Self = Self(0b0011_1111);

    /// Builds a rights mask from raw bits, discarding undefined ones.
    ///
    /// Discarding rather than rejecting: undefined bits carry no authority, so
    /// there is nothing to refuse, and rejecting would make a future right's
    /// introduction a compatibility break.
    #[must_use]
    pub const fn from_bits(bits: u8) -> Self {
        Self(bits & Self::ALL.0)
    }

    /// The raw mask.
    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// Whether every right in `other` is present here.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// The rights present in both.
    #[must_use]
    pub const fn intersection(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    /// The rights present in either.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Whether no rights are held.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

/// The kind of thing a capability names.
///
/// The kind is part of the capability rather than looked up from the identity,
/// so an invocation can be type-checked before anything dereferences it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ObjectKind {
    /// A physical frame.
    ///
    /// Kept for the one case that wants a single page — a device register
    /// window. Bulk memory is a [`ObjectKind::Memory`] object instead.
    Frame,
    /// A set of frames a capability names: [RFC 0009](../../docs/rfc/0009-shared-memory.md).
    ///
    /// There is deliberately no `Untyped`. seL4 makes all kernel memory come
    /// from untyped capabilities that userspace retypes; RFC 0009's acceptance
    /// took the simpler model, where an object is allocated from a domain's
    /// `ResourceEnvelope`. The cost is that accounting is a quota rather than
    /// an exact partition of physical memory, and it was accepted with the
    /// decision.
    Memory,
    /// An address space.
    AddressSpace,
    /// A thread.
    Thread,
    /// A domain.
    Domain,
    /// An IPC endpoint.
    Endpoint,
    /// A one-shot right to answer a `Call`.
    Reply,
    /// A signal with no payload.
    Notification,
    /// One claimed interrupt source: [RFC 0011](../../docs/rfc/0011-irq-handler.md).
    ///
    /// Holding one is the authority to *receive* an interrupt and to
    /// acknowledge it. Deliberately not the authority to **program** one: an
    /// MSI is a memory write of an arbitrary vector to an arbitrary CPU, so a
    /// holder that could program its own table entry would hold an interrupt
    /// injection primitive. The kernel keeps that and hands out this.
    IrqHandler,
    /// A device's DMA address space: [RFC 0012](../../docs/rfc/0012-iommu.md).
    ///
    /// Holding one is the authority to say what a *device* may reach. That is
    /// a strictly larger power than holding the memory itself — a device
    /// writes without a page table and without asking anyone — which is why it
    /// is a capability of its own rather than a right on a memory object.
    DmaWindow,
    /// The machine's console: [RFC 0013](../../docs/rfc/0013-service-framework.md).
    ///
    /// Holding one is the authority to put a character on the console and to
    /// take a byte that was typed. Deliberately not the authority to *drive*
    /// the hardware: the console service in its own domain holds this and can
    /// do those two things, where the same service in the nucleus could do
    /// anything at all. That difference is the entire reason for placing it
    /// somewhere else, and it is only real because this capability is narrow.
    ///
    /// A read is a *blocking* operation, which is unusual for an invocation
    /// and is why it is worth naming here: a holder that takes a byte nobody
    /// typed waits, and while it waits it is not answering anything else. The
    /// console service is single-threaded and always has been; that limit
    /// moved with it.
    Console,
    /// The authority to create domains: [RFC 0017](../../docs/rfc/0017-process-management.md).
    ///
    /// Holding one is the authority to bring a domain into existence — and
    /// nothing else. The domain that comes back is **empty**: no threads, no
    /// capabilities, no address space. Every power it will ever have is one its
    /// creator held and chose to pass, through the `GRANT` that already exists
    /// and already has rules.
    ///
    /// That is why there is no `fork` here. Duplicating a domain would give a
    /// child everything its parent had because of *what it is* rather than
    /// because anyone granted it, which is ambient authority arriving through
    /// the back door of a system built to refuse it.
    ///
    /// Holding this is **not sufficient**: the creator's envelope must also
    /// allow another child, and it allows none by default. The capability says
    /// who may ask; the envelope says how often. Either alone would be a way to
    /// exhaust a table with 32 entries in it.
    DomainControl,
}

/// What a capability names: a kind and an identity within that kind.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ObjectRef {
    /// What kind of object.
    pub kind: ObjectKind,
    /// Identity within that kind. Meaningful only to the subsystem owning it.
    pub id: u64,
}

impl ObjectRef {
    /// Names an object.
    #[must_use]
    pub const fn new(kind: ObjectKind, id: u64) -> Self {
        Self { kind, id }
    }
}

/// Index of a node in the derivation arena.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct NodeId(u16);

/// A reference held in a CSpace slot: which node, and which incarnation of it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SlotRef {
    node: NodeId,
    generation: u32,
}

/// What one capability costs in the arena, for the boot report's bill.
#[must_use]
pub fn size_of_node() -> usize {
    core::mem::size_of::<Option<CapNode>>()
}

/// One node of the derivation tree.
#[derive(Clone, Copy, Debug)]
struct CapNode {
    object: ObjectRef,
    rights: Rights,
    badge: u64,
    /// The capability this was derived from, if any.
    parent: Option<NodeId>,
    /// Incremented every time this entry is reused.
    generation: u32,
    /// Which domain is charged for this capability's existence.
    ///
    /// The arena is a fixed global resource, so "who created this" is the
    /// question a quota has to answer — and it cannot be answered from the
    /// CSpaces a capability happens to sit in, because revocation destroys
    /// nodes without touching any CSpace.
    owner: u32,
    live: bool,
}

/// Why a capability operation failed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CapError {
    /// The slot or node named nothing live.
    NotFound,
    /// The requested rights were not a subset of the parent's.
    RightsNotMonotone,
    /// The parent does not permit derivation.
    DeriveNotPermitted,
    /// The derivation would change the badge, and only a master may set one.
    ///
    /// Separate from [`CapError::DeriveNotPermitted`] so that the kernel can
    /// tell which rule refused. Both answer userspace with the same status:
    /// which rule stopped you is a thing a caller can learn nothing useful
    /// from and can probe with.
    BadgeNotMonotone,
    /// The capability does not permit revocation.
    RevokeNotPermitted,
    /// The capability does not permit being granted onwards.
    GrantNotPermitted,
    /// No free arena entry, or no free CSpace slot.
    Exhausted,
}

/// The global derivation tree.
///
/// Kept as a plain structure with no statics of its own so that every property
/// below can be tested on the host against a local instance, which is what
/// `security.md` §2's "tested exhaustively" requires to be practical.
pub struct Arena {
    nodes: [CapNode; MAX_CAPABILITIES],
    /// Nodes currently live, for reporting.
    live: usize,
    /// Where `kill` records owners during a tallied revocation.
    ///
    /// Threaded through the structure rather than passed down, because the
    /// sweep that finds descendants is several calls deep and giving every
    /// one of them an optional out-parameter would obscure what they do.
    tally: Option<[u32; MAX_OWNERS]>,
}

impl Default for Arena {
    fn default() -> Self {
        Self::new()
    }
}

impl Arena {
    /// An empty arena.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            nodes: [CapNode {
                object: ObjectRef::new(ObjectKind::Frame, 0),
                rights: Rights::NONE,
                badge: 0,
                parent: None,
                generation: 0,
                owner: OWNER_KERNEL,
                live: false,
            }; MAX_CAPABILITIES],
            live: 0,
            tally: None,
        }
    }

    fn free_index(&self) -> Option<usize> {
        self.nodes.iter().position(|node| !node.live)
    }

    /// Creates a capability with no parent.
    ///
    /// The only way authority enters the system. Every other capability is
    /// derived from one of these, which is what makes the tree a tree and
    /// revocation total.
    ///
    /// # Errors
    ///
    /// [`CapError::Exhausted`] if the arena is full.
    pub fn insert_root(
        &mut self,
        object: ObjectRef,
        rights: Rights,
        badge: u64,
    ) -> Result<SlotRef, CapError> {
        self.insert_root_owned(object, rights, badge, OWNER_KERNEL)
    }

    /// Creates a capability with no parent, charged to `owner`.
    ///
    /// # Errors
    ///
    /// [`CapError::Exhausted`] if the arena is full.
    pub fn insert_root_owned(
        &mut self,
        object: ObjectRef,
        rights: Rights,
        badge: u64,
        owner: u32,
    ) -> Result<SlotRef, CapError> {
        let index = self.free_index().ok_or(CapError::Exhausted)?;
        let generation = self.nodes[index].generation;
        self.nodes[index] = CapNode {
            object,
            rights,
            badge,
            parent: None,
            generation,
            owner,
            live: true,
        };
        self.live += 1;
        Ok(SlotRef {
            node: NodeId(index as u16),
            generation,
        })
    }

    /// Resolves a slot reference to a live node index.
    fn resolve(&self, slot: SlotRef) -> Option<usize> {
        let index = slot.node.0 as usize;
        let node = self.nodes.get(index)?;
        // Both conditions matter, and for different reasons. `live` rejects a
        // revoked capability; the generation rejects a *stale* one whose entry
        // has since been reused for something else, which would otherwise hand
        // out authority over an unrelated object.
        if node.live && node.generation == slot.generation {
            Some(index)
        } else {
            None
        }
    }

    /// Whether `slot` still names a live capability.
    #[must_use]
    pub fn is_live(&self, slot: SlotRef) -> bool {
        self.resolve(slot).is_some()
    }

    /// The capability a slot names, if it is still live.
    #[must_use]
    pub fn lookup(&self, slot: SlotRef) -> Option<(ObjectRef, Rights)> {
        let index = self.resolve(slot)?;
        Some((self.nodes[index].object, self.nodes[index].rights))
    }

    /// The badge a capability carries.
    ///
    /// Deliberately *not* reachable by the holder: this is for the nucleus to
    /// stamp on a message so a receiver can identify its caller. A holder that
    /// could read its own badge could forge one; a holder that could write it
    /// could impersonate anyone.
    #[must_use]
    pub fn badge_of(&self, slot: SlotRef) -> Option<u64> {
        let index = self.resolve(slot)?;
        Some(self.nodes[index].badge)
    }

    /// Creates a weaker capability from an existing one.
    ///
    /// **Rule 2 of `security.md` §2, and this is the one function that
    /// enforces it.** The requested rights must be a subset of the parent's:
    /// authority can be narrowed on the way down a derivation chain and never
    /// widened, at any depth.
    ///
    /// The badge is set by the granter here, which is the whole of rule 4.
    ///
    /// # Errors
    ///
    /// [`CapError::NotFound`] if the parent is dead, [`CapError::DeriveNotPermitted`]
    /// if it does not carry [`Rights::DERIVE`], [`CapError::RightsNotMonotone`]
    /// if the request would widen authority, [`CapError::Exhausted`] if the
    /// arena is full.
    pub fn derive(
        &mut self,
        parent: SlotRef,
        rights: Rights,
        badge: u64,
    ) -> Result<SlotRef, CapError> {
        self.derive_owned(parent, rights, badge, OWNER_KERNEL)
    }

    /// Derives a capability charged to `owner`.
    ///
    /// # Errors
    ///
    /// As [`Arena::derive`].
    pub fn derive_owned(
        &mut self,
        parent: SlotRef,
        rights: Rights,
        badge: u64,
        owner: u32,
    ) -> Result<SlotRef, CapError> {
        let index = self.resolve(parent).ok_or(CapError::NotFound)?;
        let parent_node = self.nodes[index];

        if !parent_node.rights.contains(Rights::DERIVE) {
            return Err(CapError::DeriveNotPermitted);
        }
        if !parent_node.rights.contains(rights) {
            return Err(CapError::RightsNotMonotone);
        }
        // A badge is a statement the *granter* made, and until this check
        // existed it was a statement the holder could make: the badge came
        // straight from the argument, and `INVOKE`'s `DERIVE` passes that
        // through from ring 3. So any program holding a badged capability with
        // `DERIVE` could mint itself another badge and call a service as
        // somebody else -- which is the whole of what a badge is for.
        //
        // The rule is one-way. A capability with badge zero is a **master**
        // and may be derived into any badge; a capability that already carries
        // one may only be derived with the same badge. Rights stay monotone
        // independently, so delegation still works -- a holder can pass on a
        // weaker capability, it just cannot pass on a different identity.
        //
        // Zero means unbadged, which is already how this kernel uses it: every
        // root it mints has badge zero and every client capability is a badged
        // derivation of one. Shedding a badge is refused along with changing
        // it, because a caller that could arrive anonymously at a service that
        // tells its callers apart by badge is a caller that has escaped being
        // told apart.
        if parent_node.badge != 0 && badge != parent_node.badge {
            return Err(CapError::BadgeNotMonotone);
        }

        // **No badge rule for notifications here, and RFC 0010 says there
        // should be one.** That RFC states: "a badge of zero is refused at
        // derivation for a notification capability."
        //
        // Implemented exactly as written, it stops the machine booting. The
        // supervisor's notification is `insert_root` then `derive(root, ALL,
        // 0)` -- a badge-zero derivation -- and so are others; every one of
        // them is a capability held in order to **wait**, and a waiter has no
        // use for a badge. The rule's own reason is about senders: "a signal
        // that sets no bits is a wake that says nothing". It does not reach a
        // capability that will never signal.
        //
        // So the check stays where it can tell the two apart: `notify::signal`
        // refuses a zero badge, which is the only moment the distinction is
        // real. RFC 0010's sentence is corrected in place rather than enforced
        // into a boot failure.

        let free = self.free_index().ok_or(CapError::Exhausted)?;
        let generation = self.nodes[free].generation;
        self.nodes[free] = CapNode {
            object: parent_node.object,
            rights,
            badge,
            parent: Some(parent.node),
            generation,
            owner,
            live: true,
        };
        self.live += 1;
        Ok(SlotRef {
            node: NodeId(free as u16),
            generation,
        })
    }

    /// Revokes a capability and everything derived from it, transitively.
    ///
    /// **Rule 3 of `security.md` §2.** Complete when it returns — there is no
    /// deferred work, no queue and nothing to flush. "Revoked eventually" is a
    /// vulnerability with a delay fuse.
    ///
    /// Returns how many capabilities were destroyed, including this one.
    ///
    /// # How completeness is achieved without child pointers
    ///
    /// Repeatedly sweep the arena killing any node whose parent is no longer
    /// live, until a sweep changes nothing. Each sweep kills at least the
    /// shallowest surviving descendant, so the number of sweeps is bounded by
    /// the depth of the tree, which is bounded by the arena size.
    ///
    /// The alternative — child links — makes revocation `O(subtree)` instead of
    /// `O(arena × depth)`, and makes *insertion* maintain a second invariant
    /// that must be correct or revocation silently misses a branch. Given that
    /// missing a branch is a privilege-escalation bug and this runs at human
    /// speed, the sweep is the right trade. Revisit if a workload revokes hot.
    pub fn revoke(&mut self, slot: SlotRef) -> Result<usize, CapError> {
        let index = self.resolve(slot).ok_or(CapError::NotFound)?;
        if !self.nodes[index].rights.contains(Rights::REVOKE) {
            return Err(CapError::RevokeNotPermitted);
        }
        Ok(self.destroy_subtree(index))
    }

    /// Revokes without checking rights.
    ///
    /// For the nucleus tearing down an object whose capabilities must all die
    /// regardless of what rights they carry — destroying a domain, say. Not
    /// reachable from a syscall.
    pub fn revoke_unchecked(&mut self, slot: SlotRef) -> usize {
        match self.resolve(slot) {
            Some(index) => self.destroy_subtree(index),
            None => 0,
        }
    }

    /// Revokes, and records how many capabilities each owner got back.
    ///
    /// The subtree can span domains — that is the point of granting — so
    /// releasing quota accurately means attributing every destroyed node to
    /// whoever was charged for it. Counting only the revoker's own would leak
    /// quota from every domain it had ever granted to.
    ///
    /// # Errors
    ///
    /// As [`Arena::revoke`].
    pub fn revoke_tallied(
        &mut self,
        slot: SlotRef,
        tally: &mut [u32; MAX_OWNERS],
    ) -> Result<usize, CapError> {
        let index = self.resolve(slot).ok_or(CapError::NotFound)?;
        if !self.nodes[index].rights.contains(Rights::REVOKE) {
            return Err(CapError::RevokeNotPermitted);
        }
        self.tally = Some(*tally);
        let destroyed = self.destroy_subtree(index);
        if let Some(collected) = self.tally.take() {
            *tally = collected;
        }
        Ok(destroyed)
    }

    /// Revokes every root naming one object, tallying per owner.
    ///
    /// For the death of the *object*: when the domain owning a `Memory`
    /// object dies, every capability naming that object — the owner's root,
    /// and every derivation it ever handed to anybody — must go, or each
    /// holder keeps a live arena node charged against its envelope for an
    /// object that no longer exists. Stale nodes confer nothing (the
    /// generation in the identity sees to that); what they cost is quota,
    /// and a service accepting a gift per connection would be spent to death
    /// by clients that connect and die.
    ///
    /// Only *roots* are matched, because derivation copies the `ObjectRef`:
    /// every node naming the object sits in a tree whose root names it too,
    /// so destroying those subtrees is destroying them all. This is not a
    /// revocation a holder performs — no rights are checked — it is the
    /// object's own death reaching its names, which is why it lives beside
    /// [`Arena::revoke_unchecked`] and not [`Arena::revoke_tallied`]'s
    /// permission gate.
    pub fn revoke_roots_naming(
        &mut self,
        object: ObjectRef,
        tally: &mut [u32; MAX_OWNERS],
    ) -> usize {
        self.tally = Some(*tally);
        let mut destroyed = 0;
        for index in 0..MAX_CAPABILITIES {
            let node = self.nodes[index];
            if node.live && node.parent.is_none() && node.object == object {
                destroyed += self.destroy_subtree(index);
            }
        }
        if let Some(collected) = self.tally.take() {
            *tally = collected;
        }
        destroyed
    }

    fn destroy_subtree(&mut self, root: usize) -> usize {
        let mut destroyed = 0;

        // The root first, so the sweep below has a dead parent to find.
        self.kill(root);
        destroyed += 1;

        loop {
            let mut killed_this_pass = 0;
            for index in 0..MAX_CAPABILITIES {
                if !self.nodes[index].live {
                    continue;
                }
                let Some(parent) = self.nodes[index].parent else {
                    continue;
                };
                if !self.nodes[parent.0 as usize].live {
                    self.kill(index);
                    killed_this_pass += 1;
                }
            }
            destroyed += killed_this_pass;
            if killed_this_pass == 0 {
                break;
            }
        }

        destroyed
    }

    fn kill(&mut self, index: usize) {
        if !self.nodes[index].live {
            return;
        }
        if let Some(tally) = self.tally.as_mut() {
            let owner = self.nodes[index].owner as usize;
            if owner < MAX_OWNERS {
                tally[owner] = tally[owner].saturating_add(1);
            }
        }
        self.nodes[index].live = false;
        // Bumped on death rather than on reuse, so a slot referring to this
        // node stops resolving the moment it dies, even before the entry is
        // handed to something else.
        self.nodes[index].generation = self.nodes[index].generation.wrapping_add(1);
        self.live -= 1;
    }

    /// Live capabilities.
    #[must_use]
    pub const fn live(&self) -> usize {
        self.live
    }

    /// The domain charged for a capability, if it is still live.
    #[must_use]
    pub fn owner_of(&self, slot: SlotRef) -> Option<u32> {
        let index = self.resolve(slot)?;
        Some(self.nodes[index].owner)
    }
}

/// A domain's capability space.
///
/// The indirection that makes capabilities unforgeable: a domain holds a small
/// integer, and that integer means nothing outside this table. Guessing gains
/// nothing because there is nothing to guess *at* — an index either names a
/// slot this domain was given or it names nothing.
pub struct CSpace {
    slots: [Option<SlotRef>; CSPACE_SLOTS],
}

impl Default for CSpace {
    fn default() -> Self {
        Self::new()
    }
}

impl CSpace {
    /// An empty capability space. A domain holding this can do nothing at all,
    /// which is the correct starting point.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            slots: [None; CSPACE_SLOTS],
        }
    }

    /// Stores a capability, returning the index the domain will use.
    ///
    /// # Errors
    ///
    /// [`CapError::Exhausted`] if the space is full.
    pub fn install(&mut self, slot: SlotRef) -> Result<usize, CapError> {
        let index = self
            .slots
            .iter()
            .position(Option::is_none)
            .ok_or(CapError::Exhausted)?;
        self.slots[index] = Some(slot);
        Ok(index)
    }

    /// Stores a capability at a chosen index.
    ///
    /// # Errors
    ///
    /// [`CapError::Exhausted`] if the index is out of range or occupied.
    pub fn install_at(&mut self, index: usize, slot: SlotRef) -> Result<(), CapError> {
        if index >= CSPACE_SLOTS || self.slots[index].is_some() {
            return Err(CapError::Exhausted);
        }
        self.slots[index] = Some(slot);
        Ok(())
    }

    /// The lowest empty slot at or above `floor`, if there is one.
    ///
    /// For a caller that does not care *where* a capability lands but must
    /// know afterwards — the kernel granting a hosted domain's handle to the
    /// Linux adapter, which then has to be told the number
    /// ([RFC 0033](../../docs/rfc/0033-what-a-hosted-process-is.md) step 3).
    /// The floor exists so an allocation cannot land on a fixed grant a boot
    /// path made by hand.
    #[must_use]
    pub fn first_free_at_or_above(&self, floor: usize) -> Option<usize> {
        self.slots
            .iter()
            .enumerate()
            .skip(floor)
            .find(|(_, slot)| slot.is_none())
            .map(|(index, _)| index)
    }

    /// The reference at `index`, if the domain holds one there.
    ///
    /// Returning a reference rather than the capability itself is the point:
    /// resolving it still requires the arena, so a CSpace on its own confers
    /// nothing.
    #[must_use]
    pub fn get(&self, index: usize) -> Option<SlotRef> {
        self.slots.get(index).copied().flatten()
    }

    /// Whether this CSpace still holds a live capability naming `object`.
    ///
    /// [RFC 0044](../../docs/rfc/0044-revocation-that-reaches-the-mapping.md)
    /// design §2. Asked after a revocation, to decide whether that domain's
    /// *mapping* of the object survives it: a holder that lost one name for an
    /// object and kept another has not lost the authority the mapping rests
    /// on.
    ///
    /// **Held, not owned, and the difference is what makes this a CSpace
    /// method rather than an `Arena` one.** A node's `owner` records which
    /// domain is *charged* for a capability, and its own comment says that
    /// cannot be read off the CSpaces it sits in. `shared::name` mints the
    /// cache frames' capabilities with `insert_root`, so they are charged to
    /// the kernel and held by `bin/fsd` — and a version of this that asked
    /// the arena "does this domain own a node naming it" answered *no* for
    /// the service that had the page mapped, unmapped its cache, and faulted
    /// the filesystem on the first `pkg install`.
    ///
    /// A slot holding a **dead** reference does not count: `lookup` fails on
    /// it, which is exactly the borrower's state after its loan is revoked.
    #[must_use]
    pub fn names(&self, object: ObjectRef, arena: &Arena) -> bool {
        self.slots
            .iter()
            .flatten()
            .filter_map(|slot| arena.lookup(*slot))
            .any(|(named, _)| named == object)
    }

    /// Removes whatever is at `index`. Does not revoke it — other domains may
    /// legitimately still hold the same capability.
    pub fn remove(&mut self, index: usize) -> Option<SlotRef> {
        self.slots.get_mut(index)?.take()
    }

    /// Slots currently occupied, including any whose capability has since been
    /// revoked.
    #[must_use]
    pub fn occupied(&self) -> usize {
        self.slots.iter().filter(|slot| slot.is_some()).count()
    }
}

/// The system's derivation tree.
static ARENA: SpinLock<Arena> = SpinLock::new(Rank::Capabilities, Arena::new());

/// Runs `f` against the global arena.
pub fn with_arena<R>(f: impl FnOnce(&mut Arena) -> R) -> R {
    f(&mut ARENA.lock())
}

/// Live capabilities in the global arena.
#[must_use]
pub fn live() -> usize {
    ARENA.lock().live()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shape `bin/fsd` is in on every `dir::RELEASE`, and the reason
    /// RFC 0044 asks the **CSpace** rather than the arena's `owner` field.
    #[test]
    fn a_lender_that_kept_its_own_name_for_an_object_still_holds_it_after_revoking_the_loan() {
        let mut arena = Arena::new();
        let object = ObjectRef::new(ObjectKind::Memory, 40);
        let (mut lender, mut borrower) = (CSpace::new(), CSpace::new());

        // **Charged to the kernel and held by the service**, which is what
        // `shared::name` does for every cache frame -- and the detail that
        // makes an owner-based check answer "no" for the domain that has the
        // page mapped. The first version of this fix asked the arena's `owner`
        // field and faulted the filesystem on the first `pkg install`.
        let own = arena
            .insert_root(object, Rights::ALL, 0)
            .expect("a fresh arena has room");
        lender.install_at(3, own).expect("slot 3 is free");

        let lending = arena
            .derive(
                own,
                Rights::READ
                    .union(Rights::GRANT)
                    .union(Rights::DERIVE)
                    .union(Rights::REVOKE),
                0,
            )
            .expect("room");
        lender.install_at(40, lending).expect("free");
        let borrowed = arena.derive(lending, Rights::READ, 0).expect("room");
        borrower.install_at(23, borrowed).expect("free");

        assert!(lender.names(object, &arena));
        assert!(borrower.names(object, &arena));

        // dir::RELEASE: the lending goes, and the borrower's copy with it.
        let mut tally = [0u32; MAX_OWNERS];
        arena
            .revoke_tallied(lending, &mut tally)
            .expect("the lending carries REVOKE");

        assert!(
            lender.names(object, &arena),
            "the lender kept its own capability and must keep its mapping"
        );
        assert!(
            !borrower.names(object, &arena),
            "the borrower's slot holds a dead reference and must lose its mapping"
        );
    }

    #[test]
    fn naming_is_per_object_and_per_cspace_rather_than_either_alone() {
        let mut arena = Arena::new();
        let one = ObjectRef::new(ObjectKind::Memory, 7);
        let two = ObjectRef::new(ObjectKind::Memory, 8);
        let (mut holder, empty) = (CSpace::new(), CSpace::new());
        let a = arena.insert_root(one, Rights::ALL, 0).expect("room");
        holder.install_at(5, a).expect("free");

        assert!(holder.names(one, &arena));
        assert!(!holder.names(two, &arena), "a different object");
        assert!(!empty.names(one, &arena), "a different holder");

        // And a slot whose capability has been revoked names nothing, which
        // is the borrower's state and the whole point of asking.
        arena.revoke_unchecked(a);
        assert!(!holder.names(one, &arena), "a dead reference is not a name");
    }

    const FRAME: ObjectRef = ObjectRef::new(ObjectKind::Frame, 7);

    fn root(arena: &mut Arena, rights: Rights) -> SlotRef {
        arena.insert_root(FRAME, rights, 0).expect("arena has room")
    }

    #[test]
    fn a_root_capability_carries_what_it_was_given() {
        let mut arena = Arena::new();
        let cap = root(&mut arena, Rights::READ.union(Rights::WRITE));
        assert_eq!(
            arena.lookup(cap),
            Some((FRAME, Rights::READ.union(Rights::WRITE)))
        );
        assert_eq!(arena.live(), 1);
    }

    #[test]
    fn derivation_is_monotone_for_every_pair_of_rights() {
        // Rule 2, exhaustively rather than by sample: all 64 parent masks
        // against all 64 requested masks. `security.md` §2 asks for exactly
        // this, and a sampled version would pass while missing the one
        // combination that matters.
        for parent_bits in 0..=Rights::ALL.bits() {
            for requested_bits in 0..=Rights::ALL.bits() {
                let parent_rights = Rights::from_bits(parent_bits).union(Rights::DERIVE);
                let requested = Rights::from_bits(requested_bits);

                let mut arena = Arena::new();
                let parent = root(&mut arena, parent_rights);
                let result = arena.derive(parent, requested, 0);

                if parent_rights.contains(requested) {
                    let child = result.expect("subset must be permitted");
                    let (_, granted) = arena.lookup(child).expect("child is live");
                    assert_eq!(granted, requested);
                    assert!(
                        parent_rights.contains(granted),
                        "a child must never hold a right its parent lacked"
                    );
                } else {
                    assert_eq!(
                        result,
                        Err(CapError::RightsNotMonotone),
                        "parent {parent_bits:#08b} must not grant {requested_bits:#08b}"
                    );
                }
            }
        }
    }

    #[test]
    fn derivation_requires_the_derive_right() {
        // Holding a right is not the same as being allowed to pass it on.
        let mut arena = Arena::new();
        let parent = root(&mut arena, Rights::READ.union(Rights::WRITE));
        assert_eq!(
            arena.derive(parent, Rights::READ, 0),
            Err(CapError::DeriveNotPermitted)
        );
    }

    #[test]
    fn an_objects_death_reaches_every_name_it_was_given() {
        // RFC 0022 step 3. Two roots naming the same object -- an owner may
        // name an object more than once -- one with a derivation handed to
        // somebody else, and an unrelated tree naming a different object.
        // The object's death destroys both roots and the handed-out child,
        // tallied to whoever was charged, and touches nothing else.
        let mut arena = Arena::new();
        let dying = ObjectRef::new(ObjectKind::Memory, 7);
        let first = arena.insert_root_owned(dying, Rights::ALL, 0, 1).unwrap();
        let second = arena.insert_root_owned(dying, Rights::ALL, 0, 1).unwrap();
        let lent = arena.derive_owned(first, Rights::READ, 9, 2).unwrap();
        let other = ObjectRef::new(ObjectKind::Memory, 8);
        let bystander = arena.insert_root_owned(other, Rights::ALL, 0, 3).unwrap();

        let mut tally = [0u32; MAX_OWNERS];
        let destroyed = arena.revoke_roots_naming(dying, &mut tally);

        assert_eq!(destroyed, 3, "both roots and the lending");
        assert!(arena.lookup(first).is_none(), "the first root is gone");
        assert!(arena.lookup(second).is_none(), "the second root is gone");
        assert!(arena.lookup(lent).is_none(), "the recipient holds nothing");
        assert!(
            arena.lookup(bystander).is_some(),
            "the other object is untouched"
        );
        assert_eq!(tally[1], 2, "the owner is tallied for its roots");
        assert_eq!(tally[2], 1, "the recipient is tallied for its copy");
        assert_eq!(tally[3], 0, "the bystander is not");
    }

    #[test]
    fn revocation_reaches_every_descendant() {
        // Rule 3. A chain four deep with a branch, revoked at the top.
        let mut arena = Arena::new();
        let a = root(&mut arena, Rights::ALL);
        let b = arena.derive(a, Rights::ALL, 0).unwrap();
        let c = arena.derive(b, Rights::ALL, 0).unwrap();
        let d = arena.derive(c, Rights::READ, 0).unwrap();
        let branch = arena.derive(b, Rights::READ, 0).unwrap();

        assert_eq!(arena.live(), 5);
        assert_eq!(arena.revoke(a), Ok(5));

        for (name, cap) in [("a", a), ("b", b), ("c", c), ("d", d), ("branch", branch)] {
            assert!(!arena.is_live(cap), "{name} survived a revoke of its root");
            assert_eq!(arena.lookup(cap), None);
        }
        assert_eq!(arena.live(), 0);
    }

    #[test]
    fn revocation_leaves_everything_outside_the_subtree_alone() {
        // The other half of rule 3, and the half a naive implementation gets
        // wrong: revoking must be total *within* the subtree and inert outside.
        let mut arena = Arena::new();
        let a = root(&mut arena, Rights::ALL);
        let child = arena.derive(a, Rights::ALL, 0).unwrap();
        let grandchild = arena.derive(child, Rights::READ, 0).unwrap();

        let unrelated = root(&mut arena, Rights::ALL);
        let unrelated_child = arena.derive(unrelated, Rights::READ, 0).unwrap();

        assert_eq!(arena.revoke(child), Ok(2));
        assert!(!arena.is_live(child));
        assert!(!arena.is_live(grandchild));
        assert!(arena.is_live(a), "the parent must survive");
        assert!(arena.is_live(unrelated));
        assert!(arena.is_live(unrelated_child));
    }

    #[test]
    fn revocation_requires_the_revoke_right() {
        let mut arena = Arena::new();
        let cap = root(&mut arena, Rights::READ);
        assert_eq!(arena.revoke(cap), Err(CapError::RevokeNotPermitted));
        assert!(arena.is_live(cap));
    }

    #[test]
    fn a_stale_reference_never_resolves_to_a_reused_entry() {
        // The use-after-free that hands out authority instead of crashing.
        let mut arena = Arena::new();
        let old = root(&mut arena, Rights::ALL);
        assert_eq!(arena.revoke(old), Ok(1));

        // The next allocation reuses the same entry.
        let new = arena
            .insert_root(ObjectRef::new(ObjectKind::Thread, 99), Rights::ALL, 0)
            .unwrap();
        assert_eq!(new.node, old.node, "the entry should be reused");

        assert!(!arena.is_live(old), "the stale reference must stay dead");
        assert_eq!(arena.lookup(old), None);
        assert!(arena.is_live(new));
    }

    #[test]
    fn a_badge_is_set_by_the_granter_and_travels_with_the_capability() {
        // Rule 4. A holder has no way to read or write this, which is what
        // lets a service trust it.
        let mut arena = Arena::new();
        let parent = root(&mut arena, Rights::ALL);
        let issued = arena.derive(parent, Rights::READ, 0xdecafbad).unwrap();
        assert_eq!(arena.badge_of(issued), Some(0xdecafbad));
        assert_eq!(arena.badge_of(parent), Some(0));
    }

    #[test]
    fn an_index_means_nothing_outside_its_own_cspace() {
        // Rule 1. Two domains, the same integer, different authority -- and
        // neither can reach the other's object by guessing.
        let mut arena = Arena::new();
        let frame = arena
            .insert_root(ObjectRef::new(ObjectKind::Frame, 1), Rights::ALL, 0)
            .unwrap();
        let thread = arena
            .insert_root(ObjectRef::new(ObjectKind::Thread, 2), Rights::ALL, 0)
            .unwrap();

        let mut alice = CSpace::new();
        let mut bob = CSpace::new();
        assert_eq!(alice.install(frame), Ok(0));
        assert_eq!(bob.install(thread), Ok(0));

        let alice_object = alice.get(0).and_then(|slot| arena.lookup(slot));
        let bob_object = bob.get(0).and_then(|slot| arena.lookup(slot));
        assert_ne!(alice_object, bob_object);
        assert_eq!(
            alice_object.map(|(object, _)| object.kind),
            Some(ObjectKind::Frame)
        );
        assert_eq!(
            bob_object.map(|(object, _)| object.kind),
            Some(ObjectKind::Thread)
        );
    }

    #[test]
    fn an_empty_cspace_confers_nothing() {
        let space = CSpace::new();
        for index in 0..CSPACE_SLOTS {
            assert_eq!(space.get(index), None);
        }
        assert_eq!(space.get(CSPACE_SLOTS), None, "out of range is not a panic");
    }

    #[test]
    fn removing_from_a_cspace_does_not_revoke() {
        // Two domains can hold the same capability; one dropping it must not
        // disturb the other.
        let mut arena = Arena::new();
        let cap = root(&mut arena, Rights::ALL);
        let mut alice = CSpace::new();
        let mut bob = CSpace::new();
        alice.install(cap).unwrap();
        bob.install(cap).unwrap();

        alice.remove(0);
        assert_eq!(alice.get(0), None);
        assert!(arena.is_live(cap), "the capability itself must survive");
        assert_eq!(bob.get(0), Some(cap));
    }

    #[test]
    fn the_arena_refuses_rather_than_overflowing() {
        let mut arena = Arena::new();
        for _ in 0..MAX_CAPABILITIES {
            arena.insert_root(FRAME, Rights::NONE, 0).unwrap();
        }
        assert_eq!(
            arena.insert_root(FRAME, Rights::NONE, 0),
            Err(CapError::Exhausted)
        );
    }

    #[test]
    fn undefined_rights_bits_carry_no_authority() {
        let rights = Rights::from_bits(0xff);
        assert_eq!(rights, Rights::ALL);
        assert!(Rights::ALL.contains(rights));
    }

    #[test]
    fn a_badge_can_be_set_by_a_master_and_by_nobody_else() {
        // The hole this closes, written as the derivation that found it. A
        // client is given a badged capability; what it can do for itself with
        // that capability is the whole question.
        let mut arena = Arena::new();
        let master = arena
            .insert_root(ObjectRef::new(ObjectKind::Endpoint, 7), Rights::ALL, 0)
            .expect("a root");

        // A master has no badge, so it may set one. This is how every client
        // capability in this kernel is made.
        let client = arena
            .derive(master, Rights::ALL, 0xaaaa)
            .expect("a badged capability for a client");
        assert_eq!(arena.badge_of(client), Some(0xaaaa));

        // And the master may hand out a *different* badge to somebody else,
        // which is what makes badges able to tell callers apart at all.
        let other = arena
            .derive(master, Rights::ALL, 0xcccc)
            .expect("a second client");
        assert_eq!(arena.badge_of(other), Some(0xcccc));

        // What the client cannot do: call itself something else. This is the
        // derivation that succeeded before the rule existed.
        assert_eq!(
            arena.derive(client, Rights::ALL, 0xbbbb),
            Err(CapError::BadgeNotMonotone),
            "a holder minted itself a badge"
        );

        // Nor shed it. A caller arriving with no badge at a service that tells
        // its callers apart by badge has escaped being told apart, which is
        // the same escape by a quieter route.
        assert_eq!(
            arena.derive(client, Rights::ALL, 0),
            Err(CapError::BadgeNotMonotone),
            "a holder shed its badge"
        );
    }

    #[test]
    fn delegation_still_works_with_the_badge_kept() {
        // The other half, and the one that makes the test above mean
        // something: a rule that refused *every* derivation from a badged
        // capability would pass the forgery test and break the system. A
        // holder must still be able to pass on less authority under the same
        // name.
        let mut arena = Arena::new();
        let master = arena
            .insert_root(ObjectRef::new(ObjectKind::Endpoint, 7), Rights::ALL, 0)
            .expect("a root");
        let client = arena.derive(master, Rights::ALL, 0xaaaa).expect("badged");

        // `DERIVE` as well as `READ`, because holding a right is not the same
        // as being allowed to pass it on -- this test asked for `READ` alone
        // first and was refused, which is the rule working.
        let passed_on = arena
            .derive(client, Rights::READ.union(Rights::DERIVE), 0xaaaa)
            .expect("a weaker capability under the same badge");
        assert_eq!(arena.badge_of(passed_on), Some(0xaaaa));

        // And one more level down, because a rule that allowed exactly one
        // generation of delegation would also pass everything above.
        let further = arena
            .derive(passed_on, Rights::READ, 0xaaaa)
            .expect("and weaker again");
        assert_eq!(arena.badge_of(further), Some(0xaaaa));

        // Rights stay monotone independently of any of this.
        assert_eq!(
            arena.derive(passed_on, Rights::WRITE, 0xaaaa),
            Err(CapError::RightsNotMonotone)
        );
    }

    #[test]
    fn an_unbadged_capability_is_not_a_master_by_accident() {
        // Badge zero means "no badge", so a derivation of a master that keeps
        // zero is itself a master. That is a real consequence and worth
        // pinning: it means the kernel can hand out an unbadged capability
        // that the recipient may badge, which is how a service would be given
        // the right to name its own objects -- and it means an unbadged
        // capability must never be handed to somebody who should not have
        // that.
        let mut arena = Arena::new();
        let master = arena
            .insert_root(ObjectRef::new(ObjectKind::Endpoint, 7), Rights::ALL, 0)
            .expect("a root");
        let still_master = arena.derive(master, Rights::ALL, 0).expect("unbadged");
        assert_eq!(arena.badge_of(still_master), Some(0));
        assert!(
            arena.derive(still_master, Rights::ALL, 0xdddd).is_ok(),
            "an unbadged derivation is still able to badge"
        );
    }
}
