// SPDX-License-Identifier: Apache-2.0
//! Directories as capabilities: [RFC 0015](../../docs/rfc/0015-filesystem.md) step 4.
//!
//! Every filesystem this kernel has had until now was reached by naming a
//! path, and a path starts somewhere. That somewhere is the root, every
//! program has it, and holding it is holding the filesystem — which is the
//! ambient authority this system has spent nine RFCs removing everywhere else.
//! A program that could open `/etc/shadow` because it could open `/` is not
//! restrained by permissions on the file; it is restrained by permissions
//! *checked* on the file, which is a different and much weaker thing.
//!
//! So there is no root here. A lookup begins at a `Directory` capability
//! somebody was given, resolves one component, and produces another
//! capability. There is no `..`, no separator, and no call that takes a path.
//! What a program can reach is the transitive closure of what it holds, and
//! that is decided by whoever handed it the capability rather than by a check
//! at the moment of use.
//!
//! Two consequences worth stating, because they are the point:
//!
//! - A name that exists on this filesystem but not in *this* directory is
//!   refused with the same status as a name that exists nowhere. A program
//!   that could tell those apart could map the filesystem it was not given, one
//!   question at a time.
//! - A capability names an inode **and** a generation. Reusing an inode bumps
//!   the generation, so a capability that outlived its directory resolves to
//!   nothing rather than to whatever took the slot. Nothing writes to this
//!   image yet, which is exactly why the check is built now: the step that
//!   introduces reuse should find the check already there and already tested,
//!   rather than being the step that has to invent it.
//!
//! The filesystem behind it is the read-only image [`crate::filesystem_self_test`]
//! mounts. That is deliberate for one step: a mistake in a namespace cannot
//! destroy anything on an image nobody can write. Moving the backing store
//! behind the block service — so that resolution is a message rather than a
//! function call — is step 6's problem, and it does not change any of the
//! above.

use bhaskix_abi::Chunk;
use bhaskix_fs::{Filesystem, Image, Kind};
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::cap::{self, ObjectKind, ObjectRef, Rights};
use crate::domain;
use crate::sched;
use crate::syscall::{Outcome, Status, SyscallFrame};

/// Where the mounted image is, and how long it is.
///
/// Two atomics rather than a lock: this is read on the syscall path, and the
/// paths around it are unlocked on purpose (a lock taken here would rank
/// inside the capability arena the caller was resolved under). Written once at
/// boot, from a slice that is part of the initrd and outlives everything.
static IMAGE_AT: AtomicUsize = AtomicUsize::new(0);
/// How many bytes [`IMAGE_AT`] points at. Zero when nothing is mounted.
static IMAGE_LENGTH: AtomicUsize = AtomicUsize::new(0);

/// Remembers `bytes` as the filesystem directory capabilities resolve in.
///
/// Idempotent, and takes the first image offered: a second mount would leave
/// capabilities already handed out pointing into an image nobody holds.
pub fn mount(bytes: &'static [u8]) -> bool {
    if IMAGE_LENGTH.load(Ordering::Acquire) != 0 {
        return false;
    }
    IMAGE_AT.store(bytes.as_ptr() as usize, Ordering::Relaxed);
    IMAGE_LENGTH.store(bytes.len(), Ordering::Release);
    true
}

/// The mounted image, or `None` on a machine booted without one.
fn image() -> Option<&'static [u8]> {
    let length = IMAGE_LENGTH.load(Ordering::Acquire);
    if length == 0 {
        return None;
    }
    let at = IMAGE_AT.load(Ordering::Relaxed);
    // SAFETY: `at` and `length` were written by `mount` from a `&'static
    // [u8]`, in that order, and `length` is released last -- so a non-zero
    // length means the pointer beside it is the one that came with it. The
    // slice is part of the initrd: it is mapped for the life of the machine
    // and nothing writes to it, which is what makes handing out a shared
    // reference to it sound.
    Some(unsafe { core::slice::from_raw_parts(at as *const u8, length) })
}

/// An inode and its generation, as a capability's identity.
///
/// Packed rather than kept in a side table because a capability *is* its
/// identity: a side table would have to be consulted to know whether two
/// capabilities named the same thing, and would have to be revoked in step
/// with them.
const fn pack(inode: u32, generation: u32) -> u64 {
    (inode as u64) | ((generation as u64) << 32)
}

/// The inode and generation an identity was packed from.
const fn unpack(id: u64) -> (u32, u32) {
    (id as u32, (id >> 32) as u32)
}

/// The identity a `Directory` capability for the image's root would have.
///
/// The only place in the system a root is named, and it is named *here* — by
/// the kernel, deciding what to hand out — rather than by a program asking for
/// one. Nothing currently holds a capability built from this: the shell is
/// given a directory one level down, and there is no way to climb. What it is
/// for is the boot report, and the negative test behind it: handing the shell
/// this instead is how the containment gates were watched failing, and they
/// fail by *succeeding* — the shell reads the file it is supposed to be unable
/// to reach.
pub fn root_identity() -> Option<u64> {
    let mut pages = Image::new(image()?);
    let mut mounted = Filesystem::mount(&mut pages).ok()?;
    let root = mounted.root().ok()?;
    Some(pack(mounted.superblock().root, root.generation))
}

/// The identity of `name` directly under the root, if it is a directory.
///
/// For the kernel's own handing-out of capabilities at boot. A program has no
/// equivalent: it resolves names in what it holds, and this is how what it
/// holds gets decided.
pub fn directory_under_root(name: &[u8]) -> Option<u64> {
    let mut pages = Image::new(image()?);
    let mut mounted = Filesystem::mount(&mut pages).ok()?;
    let root = mounted.root().ok()?;
    let (index, inode) = mounted.lookup(&root, name).ok()?;
    (inode.kind == Kind::Directory).then(|| pack(index, inode.generation))
}

/// The identity `directory_under_root` would give, one generation on.
///
/// For the boot-time test of the generation check, and for nothing else.
/// Nothing writes to this image, so there is no way for a capability here to
/// go stale by itself — which would leave the check that catches stale ones
/// untested until the step that makes them possible, and that is the step
/// least able to afford discovering it does not work. So one is manufactured:
/// a capability naming the same inode, one generation later, exactly as a
/// capability that outlived its directory would.
pub fn stale_directory_under_root(name: &[u8]) -> Option<u64> {
    let mut pages = Image::new(image()?);
    let mut mounted = Filesystem::mount(&mut pages).ok()?;
    let root = mounted.root().ok()?;
    let (index, inode) = mounted.lookup(&root, name).ok()?;
    (inode.kind == Kind::Directory).then(|| pack(index, inode.generation.wrapping_add(1)))
}

/// Whether a name is one component of a name and nothing else.
///
/// The separator is refused rather than split on, and `.` and `..` are refused
/// outright. Splitting would make this a path resolver, and `..` would make a
/// capability to a directory a capability to its parent — which is a
/// capability to everything, arrived at one level at a time.
///
/// The refusal is [`Status::BadName`] and not [`Status::NoSuchName`], and that
/// matters more than it looks. `..` is not an entry in any directory this
/// format writes, so a version of this function that returned `true` for it
/// would send it to the lookup, the lookup would not find it, and the answer
/// would be identical. The check would be gone and every test of it would
/// still pass. A distinct status is what makes deleting this a visible act.
fn is_one_component(name: &[u8]) -> bool {
    !name.is_empty() && name != b"." && name != b".." && !name.contains(&b'/') && !name.contains(&0)
}

/// Resolves `frame`'s name in the directory `frame`'s capability names.
///
/// `arg3` says where to put the result — the same shape `DERIVE` has, and for
/// the same reason: a program's CSpace is its own to arrange, and a kernel
/// that chose would fill whichever slot happened to be free, including one the
/// program was keeping empty deliberately. `Chunk::pack` carries it, which is
/// what its `extra` argument is for.
///
/// The reply is that slot, with [`bhaskix_abi::method::IS_DIRECTORY`] set if
/// what landed in it is another directory.
pub fn open_at(frame: &SyscallFrame) -> Outcome {
    let Some(bytes) = image() else {
        // No image on this machine. Not "the capability is bad" -- there is
        // nothing to resolve in, and saying so beats a refusal that reads like
        // a permission failure.
        return Outcome::err(Status::NotImplemented);
    };

    // The name, out of the caller's own registers. At most one chunk: a longer
    // name is refused rather than truncated, because a truncated name opens a
    // *different file* and would do it silently.
    let chunk = Chunk::unpack(&[frame.arg0, frame.arg1, frame.arg2, frame.arg3]);
    let name = chunk.bytes();
    if !is_one_component(name) || chunk.more() {
        return Outcome::err(Status::BadName);
    }

    let Some(id) = sched::current_domain() else {
        return Outcome::err(Status::NoDomain);
    };

    let Ok(destination) = usize::try_from(frame.arg3) else {
        return Outcome::err(Status::SlotUnavailable);
    };

    let outcome = domain::with(id, |owner| {
        let mut cspace = core::mem::take(&mut owner.cspace);
        let result = resolve_and_install(
            frame.capability,
            name,
            bytes,
            &mut cspace,
            id.as_u32(),
            destination,
        );
        // Charged only if a capability actually landed, and after it landed:
        // a domain over quota must not end up holding one it was not charged
        // for, and one charged for a capability that failed to install can
        // never spend that charge again.
        let outcome = match result {
            Ok(reply) => {
                if owner.charge_capability().is_ok() {
                    Outcome::ok(reply)
                } else {
                    if let Some(slot) = cspace.remove(destination) {
                        cap::with_arena(|arena| arena.revoke_unchecked(slot));
                    }
                    Outcome::err(Status::QuotaExceeded)
                }
            }
            Err(status) => Outcome::err(status),
        };
        owner.cspace = cspace;
        outcome
    });

    outcome.unwrap_or(Outcome::err(Status::NoDomain))
}

/// The half of [`open_at`] that holds the caller's CSpace.
fn resolve_and_install(
    capability: u64,
    name: &[u8],
    bytes: &'static [u8],
    cspace: &mut cap::CSpace,
    owner: u32,
    destination: usize,
) -> Result<u64, Status> {
    let index = usize::try_from(capability).map_err(|_| Status::NoSuchCapability)?;
    let slot = cspace.get(index).ok_or(Status::NoSuchCapability)?;

    // Checked before anything is resolved, and checked again by `install_at`.
    // Early because a lookup that succeeded and then had nowhere to go would
    // have to undo itself, and undoing a mint is the step that gets forgotten.
    if cspace.get(destination).is_some() {
        return Err(Status::SlotUnavailable);
    }

    let directory = cap::with_arena(|arena| {
        let (object, rights) = arena.lookup(slot).ok_or(Status::Revoked)?;
        if object.kind != ObjectKind::Directory {
            return Err(Status::WrongObject);
        }
        // Reading a name is reading. A directory capability without it is a
        // capability to hold a directory and not to look in one, which is a
        // distinction worth being able to make.
        if !rights.contains(Rights::READ) {
            return Err(Status::InsufficientRights);
        }
        Ok(object.id)
    })?;

    let mut pages = Image::new(bytes);
    let mut mounted = Filesystem::mount(&mut pages).map_err(|_| Status::NotImplemented)?;
    let (inode_index, generation) = unpack(directory);
    let inode = mounted
        .inode(inode_index)
        .map_err(|_| Status::NoSuchCapability)?;

    // The generation check, before the kind check and before the lookup. A
    // capability whose directory has been reused names an inode that is now
    // somebody else's, and every question asked of it -- including "is this a
    // directory" -- is a question about their data.
    if inode.generation != generation {
        return Err(Status::Revoked);
    }
    if inode.kind != Kind::Directory {
        return Err(Status::WrongObject);
    }

    let (found, target) = mounted
        .lookup(&inode, name)
        .map_err(|_| Status::NoSuchName)?;
    let kind = match target.kind {
        Kind::Directory => ObjectKind::Directory,
        Kind::File => ObjectKind::File,
        // An entry naming a free inode is a damaged image, not a missing
        // name. Refused either way, and refused as missing: a program cannot
        // do anything with the difference and telling it would say something
        // about an inode it does not hold.
        Kind::Free => return Err(Status::NoSuchName),
    };

    // The new capability carries the *caller's* rights and not more. A lookup
    // that produced a writable handle from a read-only directory would be a
    // rights amplification hidden inside a name resolution -- the quietest
    // possible place to put one.
    let rights = cap::with_arena(|arena| arena.lookup(slot).map(|(_, rights)| rights))
        .ok_or(Status::Revoked)?;

    let minted = cap::with_arena(|arena| {
        arena.insert_root_owned(
            ObjectRef::new(kind, pack(found, target.generation)),
            rights,
            0,
            owner,
        )
    })
    .map_err(|_| Status::QuotaExceeded)?;

    match cspace.install_at(destination, minted) {
        Ok(()) => {
            let tag = if kind == ObjectKind::Directory {
                bhaskix_abi::method::IS_DIRECTORY
            } else {
                0
            };
            Ok(destination as u64 | tag)
        }
        Err(_) => {
            // Nowhere to put it. Destroyed rather than left in the arena,
            // where it would be charged to a domain that cannot name it.
            cap::with_arena(|arena| arena.revoke_unchecked(minted));
            Err(Status::SlotUnavailable)
        }
    }
}

/// How many bytes the `File` at `capability` holds, if that is what it is.
///
/// `None` -- rather than an error -- when the capability is something else, so
/// that `INFO` on a `DmaWindow` still reaches the window's own answer. Two
/// objects answering the same method with different meanings is a thing worth
/// doing carefully and once.
pub fn size_of(capability: u64) -> Option<u64> {
    let bytes = image()?;
    let id = sched::current_domain()?;

    let identity = domain::with(id, |owner| {
        let cspace = core::mem::take(&mut owner.cspace);
        let index = usize::try_from(capability).ok();
        let found = index
            .and_then(|index| cspace.get(index))
            .and_then(|slot| cap::with_arena(|arena| arena.lookup(slot)))
            .and_then(|(object, _)| (object.kind == ObjectKind::File).then_some(object.id));
        owner.cspace = cspace;
        found
    })??;

    let mut pages = Image::new(bytes);
    let mut mounted = Filesystem::mount(&mut pages).ok()?;
    let (inode_index, generation) = unpack(identity);
    let inode = mounted.inode(inode_index).ok()?;
    // A stale file capability reports nothing rather than the size of whatever
    // took its inode, for the same reason a stale directory resolves nothing.
    (inode.generation == generation).then_some(inode.size)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_identity_survives_the_round_trip() {
        // The generation is the high half, so an inode of zero with a
        // generation is not zero -- a packing that lost it would make every
        // capability to inode 0 look alike whatever generation it named.
        for (inode, generation) in [(0, 0), (1, 1), (0, 7), (u32::MAX, u32::MAX), (5, 0)] {
            assert_eq!(unpack(pack(inode, generation)), (inode, generation));
        }
        assert_ne!(pack(0, 1), pack(0, 2));
    }

    #[test]
    fn a_name_is_one_component_or_nothing() {
        assert!(is_one_component(b"inner"));
        assert!(is_one_component(b"greeting"));

        // Nothing to resolve.
        assert!(!is_one_component(b""));
        // A path, refused rather than split: splitting is what makes a
        // resolver, and a resolver starts somewhere.
        assert!(!is_one_component(b"sub/inner"));
        assert!(!is_one_component(b"/"));
        assert!(!is_one_component(b"inner/"));
        // Upwards, which would make a capability to a directory a capability
        // to its parent and so to everything.
        assert!(!is_one_component(b".."));
        assert!(!is_one_component(b"."));
        // A zero, which would end the name early anywhere that treated it as
        // a C string -- so `inner\0greeting` could be made to mean either.
        assert!(!is_one_component(b"inner\0extra"));

        // And names that merely *look* like the refused ones are ordinary
        // names. A check that rejected these would be refusing files that
        // exist, which is a different bug and a quieter one.
        assert!(is_one_component(b"..."));
        assert!(is_one_component(b"..inner"));
        assert!(is_one_component(b"a.b"));
    }
}
