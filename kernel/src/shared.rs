// SPDX-License-Identifier: Apache-2.0
//! `Memory` objects: frames a capability can name.
//!
//! [RFC 0009](../../../docs/rfc/0009-shared-memory.md), accepted, step 1. An
//! object is a set of frames with a length and an owner. A capability names
//! it; mapping it into an address space is step 2, and into a *device's*
//! address space is [RFC 0012](../../../docs/rfc/0012-iommu.md).
//!
//! # Why an object rather than a capability per frame
//!
//! `ObjectKind::Frame` exists and would have been the smaller change. It is
//! also sixteen CSpace slots to share sixty-four kilobytes, and sixteen
//! fallible `MAP` calls to place them — each of which can fail separately,
//! leaving a partially mapped buffer nobody named. One object with a length is
//! one allocation, one failure mode, and one thing to revoke.
//!
//! # There is no untyped memory, and that was a decision
//!
//! seL4 makes all kernel memory come from `Untyped` capabilities that
//! userspace retypes, which makes accounting an exact partition of physical
//! memory and the API considerably larger. RFC 0009's acceptance took the
//! simpler model: **an object is allocated from a domain's
//! `ResourceEnvelope`**, and `ObjectKind::Untyped` is deleted. The cost came
//! with the decision — accounting here is a quota, not a partition — and it is
//! recorded in `TRACKER.md` rather than discovered later.
//!
//! # What step 1 does not do
//!
//! No mapping, no sharing, no revocation walk. What it does is the part
//! everything else needs to be right about: **frames are charged to a
//! domain's envelope when the object is made and released when it goes**, and
//! the frame-leak gate is pointed at exactly that.

use crate::domain::DomainId;
use crate::sync::{Rank, SpinLock};
use bhaskix_mm::{FRAME_SIZE, Zone};

/// Memory objects that can exist at once.
pub const MAX_OBJECTS: usize = 16;

/// Address spaces one object may be mapped into at once.
///
/// RFC 0009 proposes eight, and the bound is not an apology: revocation must
/// **complete**, and a list it had to allocate to walk is a revocation that
/// can fail. A ninth `MAP` is refused, which is a caller finding out at map
/// time rather than a revocation finding out at the worst time.
pub const MAX_MAPPINGS: usize = 8;

/// Frames one object may hold — 64 KiB.
///
/// Fixed, because the object must not chase an allocation while it is being
/// torn down: destruction has to complete, and a destruction that could fail
/// to allocate is a destruction that can leave frames charged to a domain that
/// no longer wants them. A larger buffer is a second object.
pub const MAX_FRAMES: usize = 16;

/// Why an object could not be made or found.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MemoryError {
    /// No free object slot.
    Exhausted,
    /// The requested length is zero, or larger than [`MAX_FRAMES`] pages.
    BadLength,
    /// The domain's memory envelope will not cover it.
    QuotaExceeded,
    /// The physical allocator had nothing.
    OutOfMemory,
    /// The object has been destroyed, or the name is stale.
    Gone,
    /// The domain does not exist.
    NoSuchDomain,
    /// The object is already mapped in [`MAX_MAPPINGS`] address spaces.
    TooManyMappings,
}

/// Names a memory object, with the generation current when it was named.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MemoryId {
    index: u32,
    generation: u32,
}

impl MemoryId {
    /// Rebuilds an identity from the packed form a capability carries.
    ///
    /// The generation travels with the index, so a capability that outlived
    /// its object names nothing rather than naming whatever took the slot.
    #[must_use]
    pub const fn from_u64(identity: u64) -> Self {
        Self {
            index: identity as u32,
            generation: (identity >> 32) as u32,
        }
    }

    /// The slot this names, for reporting.
    #[must_use]
    pub const fn index(&self) -> u32 {
        self.index
    }

    /// The identity as one word, the inverse of [`MemoryId::from_u64`].
    ///
    /// For keeping one somewhere a capability cannot go — an atomic, so that
    /// boot code which handed an object to a domain can find it again to read
    /// what the domain wrote.
    #[must_use]
    pub const fn as_u64(&self) -> u64 {
        self.index as u64 | ((self.generation as u64) << 32)
    }
}

/// Where an object is mapped: a page table, and where in it.
///
/// The *page-table root*, not a reference to an `AddressSpace`. Revocation has
/// to work on the thing that actually grants access, and that is the page
/// table — a reference to the owning struct would be a pointer this arena
/// cannot keep valid, and the region map it contains is bookkeeping that
/// outliving the mapping does no harm (`vm::handle_fault` refuses a fault on a
/// shared region for exactly that reason).
#[derive(Clone, Copy, PartialEq, Eq)]
struct Mapping {
    root: u64,
    address: u64,
    pages: u64,
}

/// Where a device reaches an object.
#[derive(Clone, Copy)]
pub struct DeviceMapping {
    /// The address the *device* uses, which is not a physical one.
    pub address: u64,
    /// How many pages from there.
    pub pages: u64,
    /// Which device, packed as bus/slot/function.
    ///
    /// Recorded because a device address only means anything in one device's
    /// translation, and there is more than one now. Revocation has to unmap it
    /// from the window it was mapped into: unmapping the same number from
    /// somebody else's would leave the device that holds it still reaching the
    /// page, which is the exact failure revocation exists to prevent.
    pub device: u64,
}

/// One object.
#[derive(Clone, Copy)]
struct Object {
    /// Physical *addresses*, in order. Index *i* is the object's *i*-th page.
    ///
    /// Addresses, not frame numbers: `allocate_frame` multiplies by the frame
    /// size before storing them. This comment said "numbers" for a milestone,
    /// and a caller that believed it multiplied again and built device
    /// mappings pointing 4096 times too high.
    frames: [u64; MAX_FRAMES],
    /// How many of them are real.
    count: usize,
    /// Bytes. Always `count * FRAME_SIZE`; kept because every caller wants it
    /// and recomputing it at each use is where an off-by-one lives.
    length: u64,
    /// Whose envelope paid, and keeps paying for as long as this exists.
    owner: DomainId,
    /// Every address space this is mapped into. Walked by [`revoke`].
    mappings: [Option<Mapping>; MAX_MAPPINGS],
    /// Where a *device* reaches this object, if one was given it.
    ///
    /// RFC 0012 step 5. A device mapping is the case that makes the bound on
    /// `mappings` worth having: revoking must complete, and it now has an
    /// IOTLB to invalidate per entry as well as a page table to edit. One
    /// window exists today; when there are more this becomes an array with
    /// exactly the same reasoning behind its size.
    device: Option<DeviceMapping>,
    generation: u32,
    live: bool,
}

impl Object {
    const fn empty() -> Self {
        Self {
            frames: [0; MAX_FRAMES],
            count: 0,
            length: 0,
            owner: DomainId::from_u32(0),
            mappings: [None; MAX_MAPPINGS],
            device: None,
            generation: 0,
            live: false,
        }
    }
}

struct Arena {
    objects: [Object; MAX_OBJECTS],
}

impl Arena {
    const fn new() -> Self {
        Self {
            objects: [Object::empty(); MAX_OBJECTS],
        }
    }
}

/// The arena is a **leaf**: nothing is acquired while it is held. Frames are
/// allocated and freed, and envelopes charged and released, either side of it —
/// both of those take lower-ranked locks, and taking a lower rank while
/// holding a higher one is the inversion this project's checker exists to
/// catch. It caught this one.
static ARENA: SpinLock<Arena> = SpinLock::new(Rank::SharedMemory, Arena::new());

/// Objects created and destroyed, for the leak gate.
static CREATED: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static DESTROYED: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// Mappings removed by revocation.
static REVOKED: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// The direct-map base, so revocation can walk page tables without being
/// handed one. Written once during boot.
static HHDM: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Records the direct-map base for the revocation walk.
///
/// Called once during boot. Revocation cannot take an `hhdm` argument: it is
/// reached from a capability being revoked, and that path has no reason to
/// know about the direct map.
pub fn set_hhdm(hhdm: u64) {
    HHDM.store(hhdm, core::sync::atomic::Ordering::Relaxed);
}

/// Creates an object of `length` bytes, charged to `owner`.
///
/// The length is rounded **up** to whole pages, because a frame is the unit a
/// device and a page table both work in — and a caller told it received 100
/// bytes when it has a page would be a caller with 3 996 bytes of somebody
/// else's history in reach. The rounded length is what [`length_of`] reports.
///
/// # Errors
///
/// [`MemoryError`] naming what was refused. **Nothing is charged and no frame
/// is taken on any failing path**: a half-made object is one that has to be
/// found and cleaned up by whoever notices, which is nobody.
pub fn create(owner: DomainId, length: u64) -> Result<MemoryId, MemoryError> {
    let pages = length.div_ceil(FRAME_SIZE);
    if length == 0 || pages > MAX_FRAMES as u64 {
        return Err(MemoryError::BadLength);
    }

    // The envelope first, because it is the cheapest thing to refuse and the
    // only one whose refusal is a policy rather than a shortage.
    crate::domain::charge_frames(owner, pages).map_err(|_| MemoryError::QuotaExceeded)?;

    // Allocate every frame, or none, and do it **before taking the arena**.
    // The allocator is a lower-ranked lock than this arena, so holding one
    // while asking for the other is an inversion -- which the rank checker
    // reported on the first boot after this module was written, exactly as it
    // is meant to. Nothing here is held while anything else is acquired.
    let mut frames = [0u64; MAX_FRAMES];
    let mut taken = 0;
    while taken < pages as usize {
        let Some(frame) = allocate_frame() else {
            for frame in frames.iter().take(taken) {
                free_frame(*frame);
            }
            crate::domain::release_frames(owner, pages);
            return Err(MemoryError::OutOfMemory);
        };
        frames[taken] = frame;
        taken += 1;
    }

    let claimed = {
        let mut arena = ARENA.lock();
        match arena.objects.iter().position(|object| !object.live) {
            Some(index) => {
                let generation = arena.objects[index].generation;
                arena.objects[index] = Object {
                    frames,
                    count: taken,
                    length: pages * FRAME_SIZE,
                    owner,
                    mappings: [None; MAX_MAPPINGS],
                    device: None,
                    generation,
                    live: true,
                };
                Some(MemoryId {
                    index: index as u32,
                    generation,
                })
            }
            None => None,
        }
    };

    let Some(id) = claimed else {
        // No slot. Give everything back, outside the arena, for the same
        // reason it was taken outside it.
        for frame in frames.iter().take(taken) {
            free_frame(*frame);
        }
        crate::domain::release_frames(owner, pages);
        return Err(MemoryError::Exhausted);
    };

    CREATED.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    Ok(id)
}

/// Destroys an object, freeing its frames and releasing its charge.
///
/// Returns whether anything was destroyed. Idempotent: destroying a name that
/// is already gone is not an error, because a caller racing a teardown should
/// not have to distinguish "I destroyed it" from "it was already destroyed" to
/// know that it is gone.
pub fn destroy(id: MemoryId) -> bool {
    // Take the object out under the arena, and give its frames back outside
    // it. The allocator and the domain table are both lower-ranked than this
    // arena, so neither may be acquired while it is held.
    let removed = {
        let mut arena = ARENA.lock();
        let Some(object) = resolve(&arena, id) else {
            return false;
        };
        let index = id.index as usize;
        arena.objects[index].live = false;
        arena.objects[index].generation = object.generation.wrapping_add(1);
        arena.objects[index].count = 0;
        object
    };

    for frame in removed.frames.iter().take(removed.count) {
        free_frame(*frame);
    }
    crate::domain::release_frames(removed.owner, removed.count as u64);
    DESTROYED.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    true
}

/// Destroys every object a domain owns.
///
/// For domain teardown. A shared region does not outlive the domain that made
/// it — RFC 0009 says so, and says why it is worth stating out loud: a
/// receiver that wants memory to outlive its provider must own it itself.
pub fn destroy_owned_by(owner: DomainId) -> usize {
    let names: [Option<MemoryId>; MAX_OBJECTS] = {
        let arena = ARENA.lock();
        core::array::from_fn(|index| {
            let object = arena.objects[index];
            (object.live && object.owner == owner).then_some(MemoryId {
                index: index as u32,
                generation: object.generation,
            })
        })
    };

    names.iter().flatten().filter(|id| destroy(**id)).count()
}

fn resolve(arena: &Arena, id: MemoryId) -> Option<Object> {
    let object = *arena.objects.get(id.index as usize)?;
    (object.live && object.generation == id.generation).then_some(object)
}

/// The object's length in bytes, or `None` if it is gone.
#[must_use]
pub fn length_of(id: MemoryId) -> Option<u64> {
    resolve(&ARENA.lock(), id).map(|object| object.length)
}

/// The physical address of the object's `page`-th frame.
///
/// This is what step 2 maps and what RFC 0012 hands to a device. It is
/// deliberately not public beyond the kernel: a physical address is not
/// authority anyone outside should be able to name.
#[must_use]
pub(crate) fn frame_at(id: MemoryId, page: usize) -> Option<u64> {
    let object = resolve(&ARENA.lock(), id)?;
    (page < object.count).then(|| object.frames[page])
}

/// Maps `id` into `space` at `address`, with `protection`.
///
/// **Into the caller's own address space, and nobody else's.** There is no
/// method here that maps into another domain's, and the absence is the design:
/// sharing happens by handing over a *capability*, which `grant` already does.
/// A service that could map into a caller's address space would be a service
/// that could write to its callers.
///
/// # Errors
///
/// [`MemoryError::Gone`] if the object has been destroyed, or
/// [`MemoryError::BadLength`] if the address space refused — which for an
/// executable protection it always will, per RFC 0009.
pub fn map_into(
    id: MemoryId,
    space: &mut crate::vm::AddressSpace,
    address: bhaskix_boot::VirtAddr,
    protection: bhaskix_mm::Protection,
) -> Result<(), MemoryError> {
    // The frame list is copied out from under the arena, because mapping takes
    // the heap lock and this arena is a leaf.
    let (frames, count) = {
        let arena = ARENA.lock();
        let object = resolve(&arena, id).ok_or(MemoryError::Gone)?;

        // Refuse the ninth *before* anything is mapped. A mapping that
        // succeeded and then could not be recorded would be one revocation
        // could not find, which is the one failure this whole design exists to
        // prevent.
        if object.mappings.iter().all(Option::is_some) {
            return Err(MemoryError::TooManyMappings);
        }
        (object.frames, object.count)
    };

    let range =
        bhaskix_mm::VirtRange::from_pages(address, count as u64).ok_or(MemoryError::BadLength)?;

    space
        .map_shared(range, id.index, &frames[..count], protection)
        .map_err(|_| MemoryError::BadLength)?;

    // Recorded after the mapping exists, and the slot was reserved above, so
    // this cannot fail. If it somehow did, the mapping would be unreachable by
    // revocation -- so it undoes itself rather than leaving one.
    let mut arena = ARENA.lock();
    let Some(object) = arena.objects.get_mut(id.index as usize) else {
        return Err(MemoryError::Gone);
    };
    let Some(slot) = object.mappings.iter_mut().find(|slot| slot.is_none()) else {
        drop(arena);
        let _ = space.unmap(address);
        return Err(MemoryError::TooManyMappings);
    };
    *slot = Some(Mapping {
        root: space.root(),
        address: address.as_u64(),
        pages: count as u64,
    });
    Ok(())
}

/// Takes an object's pages out of every address space that mapped them, and
/// then destroys it.
///
/// This is what makes revocation mean something for memory. `security.md` §2
/// rule 3 says revocation is transitive and immediate; for a `Memory`
/// capability that has to include the mappings, because **a revoked capability
/// whose pages are still mapped is not revoked, it is renamed.**
///
/// The order is load-bearing: mappings first, then the object. The reverse
/// would leave a window in which the object is gone and its frames are still
/// reachable — and those frames are about to be handed to somebody else.
///
/// Returns how many mappings were removed.
pub fn revoke(id: MemoryId) -> usize {
    // Take the list out under the arena; do the page-table work outside it,
    // because unmapping walks tables through the direct map and shooting down
    // a TLB sends an interrupt to every other CPU.
    let (mappings, device, hhdm) = {
        let mut arena = ARENA.lock();
        let Some(object) = resolve(&arena, id) else {
            return 0;
        };
        let index = id.index as usize;
        let mappings = object.mappings;
        let device = object.device;
        arena.objects[index].mappings = [None; MAX_MAPPINGS];
        arena.objects[index].device = None;
        (
            mappings,
            device,
            HHDM.load(core::sync::atomic::Ordering::Relaxed),
        )
    };

    let mut removed = 0;
    for mapping in mappings.iter().flatten() {
        for page in 0..mapping.pages {
            let address = mapping.address + page * FRAME_SIZE;
            // SAFETY: `root` is a page table this object was mapped into, and
            // the frame it returns belongs to the object -- so it is
            // deliberately *not* freed here. `destroy` returns it, once,
            // however many address spaces had it mapped.
            let _ = unsafe { bhaskix_arch::paging::unmap_page(mapping.root, address, hhdm) };

            // Before returning, on every CPU that might have loaded this
            // address space. An entry that survives in one CPU's TLB is a
            // mapping that is gone from the tables and still works, which is
            // the exact shape of a revocation with a delay fuse.
            crate::tlb::shootdown(address);
        }
        removed += 1;
    }

    // And out of the device's window, which is the half RFC 0012 step 5 adds.
    // A revocation that removed a page from every address space and left a
    // device reaching it would be the same failure as leaving one CPU's TLB
    // entry behind -- gone from the tables, and still working.
    if let Some(device) = device {
        // Unmapped from the window it was mapped into, named by the device
        // recorded with it.
        removed += usize::from(crate::iommu::unmap_device(
            crate::iommu::device_of(device.device),
            device.address,
            device.pages,
        ));
    }

    REVOKED.fetch_add(removed as u64, core::sync::atomic::Ordering::Relaxed);
    destroy(id);
    removed
}

/// The direct map base this module was given at bring-up.
///
/// Kept because unmapping happens from paths that were not handed one — a
/// revocation reaches a device window, and the caller asking for the revoke
/// has no reason to know where physical memory is mapped.
#[must_use]
pub fn hhdm() -> u64 {
    HHDM.load(core::sync::atomic::Ordering::Relaxed)
}

/// Records that a device can reach this object at `address`.
///
/// Returns false if the object is gone, or already reachable by a device —
/// mapping one twice would leave the first address unrevoked, which is a page
/// a device keeps after the object naming it has been destroyed.
pub fn record_device_mapping(id: MemoryId, device: u64, address: u64, pages: u64) -> bool {
    let mut arena = ARENA.lock();
    if resolve(&arena, id).is_none() {
        return false;
    }
    let object = &mut arena.objects[id.index as usize];
    if object.device.is_some() {
        return false;
    }
    object.device = Some(DeviceMapping {
        address,
        pages,
        device,
    });
    true
}

/// The frames this object is made of, in order.
///
/// For whoever is about to map them somewhere this module does not know about
/// — a device window, today. Returns `None` for an object that has gone.
pub fn frames_of(id: MemoryId) -> Option<([u64; MAX_FRAMES], usize)> {
    let arena = ARENA.lock();
    let object = resolve(&arena, id)?;
    Some((object.frames, object.count))
}

/// Resolves a `Memory` capability a *caller* holds, by slot in its own CSpace.
///
/// For a service acting on somebody else's behalf. The caller names a slot it
/// holds rather than an object identity: an identity would be the caller
/// asserting what it may reach, and a service that believed it would write
/// into whatever was named. A slot is a caller pointing at authority it
/// already has, which is checkable.
///
/// `None` if the thread has no domain, the slot is empty or revoked, or it
/// names something that is not memory.
#[must_use]
pub fn caller_object(caller: u32, slot: u64) -> Option<MemoryId> {
    caller_object_for(caller, slot, crate::cap::Rights::WRITE)
}

/// The same, for an operation that needs some other right.
///
/// A `FILL` writes into the caller's memory and needs `WRITE`; a `DRAIN` reads
/// out of it and needs `READ`. Asking for the right the *operation* needs, and
/// not for a fixed one, is what stops a read-only capability being enough to
/// have something written through it — or, the way round that matters more
/// here, a write-only one being enough to have its contents taken.
pub fn caller_object_for(caller: u32, slot: u64, needs: crate::cap::Rights) -> Option<MemoryId> {
    let domain = crate::sched::domain_of(caller)?;
    let index = usize::try_from(slot).ok()?;

    crate::domain::with(domain, |owner| {
        let cspace = core::mem::take(&mut owner.cspace);
        let found = cspace.get(index).and_then(|slot| {
            crate::cap::with_arena(|arena| {
                let (object, rights) = arena.lookup(slot)?;
                // Whatever the operation needs of it: writing into a caller's
                // memory needs `WRITE`, taking bytes out of it needs `READ`.
                if object.kind != crate::cap::ObjectKind::Memory || !rights.contains(needs) {
                    return None;
                }
                Some(MemoryId::from_u64(object.id))
            })
        });
        owner.cspace = cspace;
        found
    })
    .flatten()
}

/// Reads an object's frames into `sink`, returning how many bytes were taken.
///
/// The mirror of [`fill_from`], and the direction a *write* needs: a caller
/// names memory it holds, and a service takes bytes out of it rather than
/// putting bytes in. RFC 0016 step 3, which is the half RFC 0015 step 1 owed.
///
/// `None` if the object has gone. Never reads past the object, for the same
/// reason the other direction never writes past it: the length is the
/// object's, and a caller that could name a length would be naming memory
/// beyond what it holds — which in *this* direction would be reading it.
pub fn drain_into(
    id: MemoryId,
    limit: usize,
    mut sink: impl FnMut(&[u8]) -> usize,
) -> Option<usize> {
    let (frames, count) = frames_of(id)?;
    let hhdm = hhdm();
    let capacity = (count * FRAME_SIZE as usize).min(limit);

    let mut read = 0;
    for frame in frames.iter().take(count) {
        if read >= capacity {
            break;
        }
        let room = (capacity - read).min(FRAME_SIZE as usize);
        // SAFETY: a frame this object owns, reached through the direct map,
        // and `room` is bounded by the frame size. Read only: this is the
        // direction that takes a caller's bytes rather than giving it any.
        let page = unsafe { core::slice::from_raw_parts((hhdm + frame) as *const u8, room) };
        let taken = sink(page);
        read += taken;
        if taken < room {
            // The sink has stopped accepting. The rest of the object is not
            // read, which matters more here than in the other direction: a
            // caller is entitled to know that what it did not ask to send was
            // not sent.
            break;
        }
    }
    Some(read)
}

/// Fills an object's frames from `source`, returning how many bytes landed.
///
/// The bulk path RFC 0009 step 6 asks for. `source` is handed one frame's
/// worth at a time and returns how much it produced; a short read ends the
/// transfer, which is what makes this work for a file that ends mid-page.
///
/// `None` if the object has gone. Never writes past the object: the length is
/// the object's, not the caller's claim about it, because a caller that could
/// name a length would be naming memory beyond what it holds.
pub fn fill_from(
    id: MemoryId,
    offset: usize,
    limit: usize,
    mut source: impl FnMut(&mut [u8]) -> usize,
) -> Option<usize> {
    let (frames, count) = frames_of(id)?;
    let hhdm = hhdm();
    let size = count * FRAME_SIZE as usize;
    if offset >= size {
        // Past the end is not a fault and not a lie: nothing was written, and
        // saying so lets a caller stop rather than retry for ever.
        return Some(0);
    }
    let capacity = (size - offset).min(limit);

    let mut written = 0;
    for (index, frame) in frames.iter().take(count).enumerate() {
        if written >= capacity {
            break;
        }
        // Where this frame sits in the object, and where the cursor is now.
        // Frames entirely before the offset are skipped, and the first one that
        // is not starts part-way in -- which is the whole of what an offset
        // means for an object that is not contiguous in physical memory.
        let start = index * FRAME_SIZE as usize;
        let cursor = offset + written;
        if cursor >= start + FRAME_SIZE as usize {
            continue;
        }
        let within = cursor.saturating_sub(start);
        let room = (FRAME_SIZE as usize - within).min(capacity - written);

        // SAFETY: a frame this object owns, reached through the direct map.
        // `within` is below the frame size and `room` is bounded by what is
        // left of the frame, so the slice stays inside it.
        let page = unsafe {
            core::slice::from_raw_parts_mut((hhdm + frame + within as u64) as *mut u8, room)
        };
        let produced = source(page);
        written += produced;
        if produced < room {
            // Short: the source has run out, and the rest of the object is
            // deliberately left as it was rather than zeroed. A caller reads
            // what it was told arrived.
            break;
        }
    }
    Some(written)
}

/// Names a `Memory` object with a capability, so it can be granted.
///
/// Returns a root capability with every right, from which the owner derives
/// what it hands out. Sharing happens by **handing over a capability**, which
/// is what makes it capability-shaped rather than an address someone was told:
/// the recipient maps it into its own address space, with rights no wider than
/// it was given, because derivation is monotone (`security.md` §2 rule 2).
///
/// # Errors
///
/// [`MemoryError::Gone`] if the object has been destroyed, or
/// [`MemoryError::Exhausted`] if the capability arena is full.
pub fn name(id: MemoryId) -> Result<crate::cap::SlotRef, MemoryError> {
    if !live(id) {
        return Err(MemoryError::Gone);
    }
    // The identity carries the generation, so a capability outliving its
    // object names nothing rather than naming whatever took the slot.
    let identity = u64::from(id.index) | (u64::from(id.generation) << 32);
    crate::cap::with_arena(|arena| {
        arena
            .insert_root(
                crate::cap::ObjectRef::new(crate::cap::ObjectKind::Memory, identity),
                crate::cap::Rights::ALL,
                0,
            )
            .map_err(|_| MemoryError::Exhausted)
    })
}

/// The object a `Memory` capability names, if it is still there.
#[must_use]
pub fn from_identity(identity: u64) -> Option<MemoryId> {
    let id = MemoryId {
        index: identity as u32,
        generation: (identity >> 32) as u32,
    };
    live(id).then_some(id)
}

/// Revokes a `Memory` capability: its mappings first, then its subtree.
///
/// **The order is the design.** Doing the capabilities first would leave a
/// window in which the capability is dead and the memory is still mapped —
/// which is precisely the delay fuse `security.md` §2 rule 3 exists to forbid.
/// So the pages come out of every address space that had them, and only then
/// does the derivation tree go.
///
/// Returns the mappings removed and the capabilities destroyed.
pub fn revoke_capability(slot: crate::cap::SlotRef) -> (usize, usize) {
    let object = crate::cap::with_arena(|arena| {
        arena.lookup(slot).and_then(|(object, _)| {
            (object.kind == crate::cap::ObjectKind::Memory).then_some(object.id)
        })
    });

    let mappings = object.and_then(from_identity).map_or(0, revoke);

    let capabilities = crate::cap::with_arena(|arena| arena.revoke_unchecked(slot));
    (mappings, capabilities)
}

/// How many address spaces have this object mapped.
#[must_use]
pub fn mapping_count(id: MemoryId) -> usize {
    let arena = ARENA.lock();
    resolve(&arena, id).map_or(0, |object| object.mappings.iter().flatten().count())
}

/// Whether the object is live./// Whether the object is live.
#[must_use]
pub fn live(id: MemoryId) -> bool {
    resolve(&ARENA.lock(), id).is_some()
}

/// How many objects are live, and objects created and destroyed since boot.
#[must_use]
pub fn statistics() -> (usize, u64, u64) {
    use core::sync::atomic::Ordering::Relaxed;
    let arena = ARENA.lock();
    (
        arena.objects.iter().filter(|object| object.live).count(),
        CREATED.load(Relaxed),
        DESTROYED.load(Relaxed),
    )
}

/// Mappings removed by revocation since boot.
#[must_use]
pub fn revocations() -> u64 {
    REVOKED.load(core::sync::atomic::Ordering::Relaxed)
}

fn allocate_frame() -> Option<u64> {
    crate::heap::with(|heap| {
        heap.pmm_mut()
            .allocate(0, Zone::Normal)
            .ok()
            .map(|pfn| u64::from(pfn) * FRAME_SIZE)
    })
    .flatten()
}

fn free_frame(frame: u64) {
    let _ = crate::heap::with(|heap| heap.pmm_mut().free((frame / FRAME_SIZE) as u32, 0));
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The arena is a global and the frame allocator is not available on the
    /// host, so what is tested here is the bookkeeping that does not touch
    /// either: the length arithmetic and the identity rules. The allocation
    /// and accounting halves are asserted in QEMU, against the frame-leak
    /// gate, which is the only place they mean anything.
    #[test]
    fn a_length_is_rounded_up_to_whole_pages_and_bounded() {
        for (bytes, pages) in [
            (1u64, 1u64),
            (FRAME_SIZE - 1, 1),
            (FRAME_SIZE, 1),
            (FRAME_SIZE + 1, 2),
            (FRAME_SIZE * MAX_FRAMES as u64, MAX_FRAMES as u64),
        ] {
            assert_eq!(bytes.div_ceil(FRAME_SIZE), pages, "{bytes} bytes");
        }

        // Zero is refused rather than rounded to nothing: an object with no
        // pages is a name for no memory, and every caller of it would be
        // asking for a mapping of length zero.
        assert_eq!(0u64.div_ceil(FRAME_SIZE), 0);

        // And one page past the bound is refused rather than truncated.
        let over = FRAME_SIZE * MAX_FRAMES as u64 + 1;
        assert!(over.div_ceil(FRAME_SIZE) > MAX_FRAMES as u64);
    }

    #[test]
    fn a_name_carries_a_generation_so_a_stale_one_addresses_nothing() {
        let mut arena = Arena::new();
        arena.objects[3] = Object {
            frames: [0; MAX_FRAMES],
            count: 1,
            length: FRAME_SIZE,
            owner: DomainId::from_u32(1),
            mappings: [None; MAX_MAPPINGS],
            device: None,
            generation: 7,
            live: true,
        };

        let good = MemoryId {
            index: 3,
            generation: 7,
        };
        let stale = MemoryId {
            index: 3,
            generation: 6,
        };
        assert!(resolve(&arena, good).is_some());
        assert!(
            resolve(&arena, stale).is_none(),
            "a name from before the slot was reused must not address what took it"
        );

        // A dead slot answers to nobody, whatever the generation.
        arena.objects[3].live = false;
        assert!(resolve(&arena, good).is_none());

        // And an index past the end is a refusal rather than a panic.
        assert!(
            resolve(
                &arena,
                MemoryId {
                    index: MAX_OBJECTS as u32,
                    generation: 0
                }
            )
            .is_none()
        );
    }
}
