// SPDX-License-Identifier: Apache-2.0
//! The filesystem, in a domain of its own, reading a disk it cannot touch.
//!
//! RFC 0016 step 3. Every filesystem this kernel has had so far has run *in*
//! the kernel: `bhaskix-fs` is three and a half thousand lines that parse
//! inodes, directory entries, block pointers and a journal out of bytes that
//! came off a device, and all of it has been linked into ring 0. This program
//! is the same code somewhere else.
//!
//! **It contains no filesystem code.** That is the point, and it is only
//! possible because RFC 0015 step 6 had already done the hard part: the crate
//! was written against a [`Store`] — how many blocks, read one, write one —
//! because a filesystem on a disk cannot be handed its own bytes. Placing it
//! here needed a `Store` made of system calls and nothing else.
//!
//! # What it is given, and how
//!
//! Two capabilities and one mapping, and it can reach nothing else:
//!
//! - **The block service's endpoint**, at slot 0. It can ask for sectors. It
//!   cannot reach the device: it has no registers, no interrupt, no DMA
//!   window, and no idea which disk it is reading. A filesystem that could
//!   drive the hardware would be a filesystem that could aim it.
//! - **One memory object**, at slot 1, which it maps. The first page is the
//!   buffer the block service fills and drains — named by *slot*, so the
//!   service is pointed at authority this program already holds rather than at
//!   an address it made up. The rest is its page cache and one page to leave
//!   its findings in.
//!
//! # Directories, since RFC 0016 step 4
//!
//! It also *serves*. A directory a program holds is a **badged endpoint
//! capability to this program**: the badge carries an inode and a generation,
//! the kernel stamps it on arrival so it cannot be forged, and this is the only
//! thing that knows what it means. The kernel has no `Directory` object kind
//! and does not know what an inode is.
//!
//! The rules that used to live in `kernel/src/namespace.rs` live here now, and
//! they are the same rules: one component, no separators, no `.` or `..`; a
//! name outside the directory held answers exactly as a name that exists
//! nowhere; a handle whose generation no longer matches resolves to nothing.
//! What changed is that they are ordinary code in a domain that holds two
//! capabilities, rather than syscall-path code in ring 0.

#![no_std]
#![no_main]

use bhaskix_abi::{Chunk, block, dir, method, rights, status, syscall};
use bhaskix_fs::{Cache, Filesystem, FsError, Kind, Store};

/// The slot the block service's endpoint capability is in.
const BLOCK: u64 = 0;
/// The slot this program's memory object is in.
///
/// Named to the block service, which cannot choose it: the kernel re-checks it
/// against what this domain actually holds, so a service pointed at the wrong
/// slot reaches nothing rather than somebody else's memory.
const MEMORY: u64 = 1;

/// Where the two-page object is mapped: the bulk buffer and the report.
const MEMORY_AT: u64 = 0x2000_0000;
/// The page the block service fills and drains.
const BULK_AT: u64 = MEMORY_AT;
/// The page this program leaves its findings in.
const REPORT_AT: u64 = MEMORY_AT + 0x1000;

/// The first slot holding one page of page cache.
///
/// **One object per frame**, and that is the whole reason they are separate. A
/// cache in one object can only be lent whole, and lending it whole hands a
/// reader every other block in it — other files' data, and every piece of
/// metadata this service has touched. A frame is the unit that can be lent, so
/// a frame is the unit that has to be nameable. RFC 0016 step 5.
const CACHE_SLOT: u64 = 3;
/// How many pages of cache. Enough that a transaction does not thrash.
const CACHE_PAGES: usize = 8;
/// Where they are mapped, one after another, so the cache sees one run.
const CACHE_AT: u64 = 0x2001_0000;

/// The endpoint this program answers on, and derives directory handles from.
///
/// Held with no badge, which is what makes it a *master*: only a capability
/// with badge zero may set one, so this is the thing that can name directories
/// and nothing a client holds can. RFC 0016 step 1.
const ENDPOINT: u64 = 2;
/// A word the kernel looks for, so a zeroed page is not mistaken for a report.
const MARKER: u64 = 0x4653_4452_5054_3031;

/// What the kernel wrote into the filesystem on the disk, for this to find.
const EXPECTED: &[u8] = b"written through a service\n";

/// There is nothing to unwind and nowhere to print to.
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // SAFETY: an undefined instruction, deliberately. A service that panicked
    // has no correct answer to give, and stopping is visible to the kernel
    // where a wrong answer would not be.
    unsafe { core::arch::asm!("ud2", options(noreturn)) }
}

/// Issues one system call and returns both the status and the value.
fn call(kind: u64, capability: u64, method: u64, args: [u64; 4]) -> (u64, u64) {
    let status: u64;
    let value: u64;
    // SAFETY: the system call convention from RFC 0008. Nothing is
    // dereferenced here; the kernel writes the whole frame back, which is why
    // every argument register is declared as an in-out.
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") kind => status,
            inlateout("rdi") capability => _,
            // `inlateout`, not `in`. The kernel pops the whole frame back on
            // the way out -- `rsi` included -- so telling the compiler it is
            // preserved is telling it something the machine does not promise.
            // This system has been bitten by exactly that once already, for
            // the argument registers; `rsi` was the one that was missed.
            inlateout("rsi") method => _,
            inlateout("rdx") args[0] => value,
            inlateout("r10") args[1] => _,
            inlateout("r8") args[2] => _,
            inlateout("r9") args[3] => _,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    (status, value)
}

/// Ends this program. Never returns.
fn exit() -> ! {
    call(syscall::EXIT, 0, 0, [0; 4]);
    // The kernel does not return from `Exit`. If it ever did, stopping here is
    // better than running into whatever follows.
    #[allow(clippy::empty_loop)]
    loop {}
}

/// The block service, as somewhere blocks come from.
///
/// Every method here is a round trip to another domain. That is the cost RFC
/// 0015 step 6 made visible by giving the filesystem a trait instead of a
/// slice, and it is the reason the cache above it is not an optimisation.
struct BlockService {
    /// How many 512-byte sectors the device has, as the service reports them.
    sectors: u64,
}

impl BlockService {
    /// Asks the service how big the device is.
    fn new() -> Self {
        let (status, sectors) = call(syscall::CALL, BLOCK, block::CAPACITY, [0; 4]);
        Self {
            sectors: if status == status::OK { sectors } else { 0 },
        }
    }

    /// The bulk page, as bytes.
    ///
    /// `&mut self`, and the lifetime is tied to that borrow. Handing out a
    /// `&'static mut [u8]` from a `&self` — which is what this did first — is
    /// two mutable aliases to the same page whenever it is called twice, and
    /// the compiler is entitled to assume that cannot happen.
    fn bulk(&mut self) -> &mut [u8] {
        // SAFETY: one page of a memory object this program holds and mapped
        // writable at a fixed address. The borrow of `self` is what keeps this
        // the only reference to it.
        unsafe { core::slice::from_raw_parts_mut(BULK_AT as *mut u8, 4096) }
    }
}

impl Store for BlockService {
    fn blocks(&self) -> u32 {
        u32::try_from(self.sectors / 8).unwrap_or(0)
    }

    fn read(&mut self, block_index: u32, into: &mut [u8]) -> Result<(), FsError> {
        if u64::from(block_index) >= self.sectors / 8 {
            return Err(FsError::OutOfRange);
        }
        // Eight sectors in one request. The service carries a whole filesystem
        // block, which is why this is one round trip and not eight.
        let (status, moved) = call(
            syscall::CALL,
            BLOCK,
            block::READ,
            [u64::from(block_index) * 8, 8, MEMORY, 0],
        );
        if status != status::OK || moved != 4096 {
            return Err(FsError::OutOfRange);
        }
        into.get_mut(..4096)
            .ok_or(FsError::OutOfRange)?
            .copy_from_slice(self.bulk());
        Ok(())
    }

    fn write(&mut self, block_index: u32, from: &[u8]) -> Result<(), FsError> {
        if u64::from(block_index) >= self.sectors / 8 {
            return Err(FsError::OutOfRange);
        }
        let from = from.get(..4096).ok_or(FsError::OutOfRange)?;
        self.bulk().copy_from_slice(from);
        let (status, moved) = call(
            syscall::CALL,
            BLOCK,
            block::WRITE,
            [u64::from(block_index) * 8, 8, MEMORY, 0],
        );
        if status != status::OK || moved != 4096 {
            return Err(FsError::OutOfRange);
        }
        Ok(())
    }
}

/// Says how far this program has got, so a crash can be located.
///
/// It earned its place: the first version of this program died inside the
/// first block read, and the only thing visible from outside was a report page
/// of zeroes. With this the kernel says *which stage* was reached, and the
/// question changes from "what happened" to "what happens at stage four".
///
/// The marker goes down first and the stage is updated in place, which is the
/// opposite of [`report`] and is deliberate: `report` is a result and must not
/// be seen half-written, this is a breadcrumb and is only useful if it
/// survives the thing that stopped it.
fn mark(stage: u64) {
    // SAFETY: the last page of the memory this program holds and mapped
    // writable, and nothing else in this program uses it.
    unsafe {
        core::ptr::write_volatile((REPORT_AT as *mut u64).add(6), stage);
    }
}

/// Receives one request. Blocks.
fn receive() -> (u64, u64, u64, [u64; 4]) {
    let status: u64;
    let mut badge = ENDPOINT;
    let mut method = 0u64;
    let (mut a0, mut a1, mut a2, mut a3) = (0u64, 0u64, 0u64, 0u64);
    // SAFETY: the system call convention from RFC 0008. Every argument
    // register is an output because the kernel writes the whole frame back.
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") syscall::RECV => status,
            inlateout("rdi") badge,
            inlateout("rsi") method,
            inlateout("rdx") a0,
            inlateout("r10") a1,
            inlateout("r8") a2,
            inlateout("r9") a3,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    (status, badge, method, [a0, a1, a2, a3])
}

/// Answers the caller this program is holding a reply for.
fn answer(outcome: u64, size: u64, is_directory: u64) {
    let (status, _) = call(syscall::REPLY, 0, 0, [outcome, size, is_directory, 0]);
    let _ = status;
}

/// Whether a name is one component of a name and nothing else.
///
/// Moved from the kernel unchanged, and the reasoning with it: the separator is
/// refused rather than split on, because splitting is what makes a path
/// resolver and a path resolver starts somewhere. `..` is refused because a
/// capability to a directory that answered it would be a capability to its
/// parent, and so to everything, one level at a time.
///
/// The refusal is [`dir::BAD_NAME`] and not [`dir::NO_SUCH_NAME`], and that
/// matters more than it looks: `..` is not an entry in any directory this
/// format writes, so a version of this that let it through would fail to find
/// it and give the same answer. A distinct outcome is what makes deleting this
/// a visible act.
fn is_one_component(name: &[u8]) -> bool {
    !name.is_empty() && name != b"." && name != b".." && !name.contains(&b'/') && !name.contains(&0)
}

/// Leaves what this program found where the kernel can read it.
///
/// Including the **handles** for `sub` and for a directory that no longer
/// exists. The kernel is the only thing that can mint a capability, and after
/// this step it is no longer a thing that knows what an inode is — so the
/// service says which badges name what, and the kernel stamps them.
///
/// A page of the memory object it holds, which the kernel can reach through
/// the object's frames. The marker goes last and after a fence, so a kernel
/// that sees the marker sees everything under it.
fn report(
    blocks: u64,
    entries: u64,
    read: u64,
    matched: u64,
    sectors: u64,
    directory: u64,
    stale: u64,
) {
    // SAFETY: the last page of the memory this program holds and mapped
    // writable, and nothing else in this program uses it.
    unsafe {
        let at = REPORT_AT as *mut u64;
        core::ptr::write_volatile(at.add(1), blocks);
        core::ptr::write_volatile(at.add(2), entries);
        core::ptr::write_volatile(at.add(3), read);
        core::ptr::write_volatile(at.add(4), matched);
        core::ptr::write_volatile(at.add(5), sectors);
        core::ptr::write_volatile(at.add(7), directory);
        core::ptr::write_volatile(at.add(8), stale);
        core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
        core::ptr::write_volatile(at, MARKER);
    }
}

/// Mounts the disk and reads one file off it.
#[unsafe(no_mangle)]
extern "C" fn fsd_main() -> ! {
    // The memory, mapped where this program said. A domain cannot allocate and
    // must not be able to name physical memory: it maps what it *holds*, at an
    // address of its own choosing, and the frames come from the object.
    let (mapped, _) = call(
        syscall::INVOKE,
        MEMORY,
        method::ATTACH,
        [MEMORY_AT, 1, 0, 0],
    );
    if mapped != status::OK {
        exit()
    }
    // Each cache frame mapped where the one before it ends, so the cache sees
    // one run of pages and does not have to know they are eight objects. It
    // has to be eight for them to be lent one at a time.
    for frame in 0..CACHE_PAGES as u64 {
        let (mapped, _) = call(
            syscall::INVOKE,
            CACHE_SLOT + frame,
            method::ATTACH,
            [CACHE_AT + frame * 0x1000, 1, 0, 0],
        );
        if mapped != status::OK {
            mark(50 + frame);
            exit()
        }
    }

    mark(1);
    let store = BlockService::new();
    mark(2);
    let sectors = store.sectors;
    if sectors == 0 {
        report(0, 0, 0, 0, 0, 0, 0);
        exit()
    }

    // SAFETY: eight pages of the memory this program holds and mapped
    // writable, and nothing else in this program uses them.
    let frames =
        unsafe { core::slice::from_raw_parts_mut(CACHE_AT as *mut u8, CACHE_PAGES * 4096) };
    mark(3);
    let Ok(mut cache) = Cache::new(frames, store) else {
        report(0, 0, 0, 0, sectors, 0, 0);
        exit()
    };

    // From here on there is nothing left that this program wrote: every
    // structure below is read by `bhaskix-fs`, unchanged, out of pages that
    // came off a disk through another domain.
    mark(4);
    let Ok(mut mounted) = Filesystem::mount(&mut cache) else {
        report(0, 0, 0, 0, sectors, 0, 0);
        exit()
    };
    mark(6);
    let blocks = mounted.superblock().blocks;
    let Ok(root) = mounted.root() else {
        report(blocks, 0, 0, 0, sectors, 0, 0);
        exit()
    };

    mark(7);
    let mut entries = 0u64;
    mounted.list(&root, |_| entries += 1);

    let Ok((_, inode)) = mounted.lookup(&root, b"on-a-disk") else {
        report(blocks, entries, 0, 0, sectors, 0, 0);
        exit()
    };
    mark(8);
    let mut contents = [0u8; 64];
    let read = mounted.read(&inode, 0, &mut contents);
    let matched = u64::from(contents.get(..read) == Some(EXPECTED));

    // The handles the shell will be given: `sub`, and the same one a
    // generation on -- a capability to a directory that is gone. Nothing on
    // this disk goes stale by itself, so one is manufactured, for the reason
    // it was manufactured in the kernel: the check that catches a stale handle
    // should be working *before* the step that can produce one.
    let (directory, stale) = match mounted.lookup(&root, b"sub") {
        Ok((index, inode)) if inode.kind == Kind::Directory => (
            dir::handle(index, inode.generation),
            dir::handle(index, inode.generation.wrapping_add(1)),
        ),
        _ => (0, 0),
    };

    // Warm the pages a lookup in `sub` will want, before anything is being
    // answered. A miss during a request means calling the block service while
    // already owing a reply, which is the thing under test.
    if let Ok((index, inode)) = mounted.lookup(&root, b"sub") {
        let _ = index;
        let _ = mounted.lookup(&inode, b"inner");
        let _ = mounted.lookup(&inode, b"absent");
    }

    report(
        blocks,
        entries,
        read as u64,
        matched,
        sectors,
        directory,
        stale,
    );

    // Not `exit`. A service that has answered one question is not a service
    // that is finished, and giving up the capabilities it holds is what
    // unmounting a disk would be.
    serve(cache)
}

/// Lends the caller the page holding the first block of the file `badge` names.
///
/// The frame is **pinned** before it is lent, and a pinned frame is never
/// chosen for eviction. Without that the holder would go on reading a page the
/// cache had since given to another block — somebody else's data, arriving
/// silently, which is the failure this whole step is arranged around.
///
/// Read-only, and **one frame**. A capability to the cache would be a
/// capability to every block in it.
fn lend(cache: &mut Cache<'static, BlockService>, badge: u64) {
    let (inode_index, generation) = dir::parts(badge);
    let found = {
        let Ok(mut mounted) = Filesystem::mount(cache) else {
            answer(dir::GONE, 0, 0);
            return;
        };
        match mounted.inode(inode_index) {
            Ok(inode)
                if inode.generation == generation
                    && inode.kind == Kind::File
                    && inode.direct[0] != 0 =>
            {
                Some((inode.direct[0], inode.size))
            }
            _ => None,
        }
    };
    let Some((block, size)) = found else {
        answer(dir::GONE, 0, 0);
        return;
    };
    let Ok(frame) = cache.pin(block) else {
        // Every frame is lent already. A refusal, and the honest one: the
        // alternative is taking back a page somebody is reading.
        answer(dir::NOWHERE, 0, 0);
        return;
    };
    // Churn the cache before handing anything over. This is not housekeeping;
    // it is what makes the gates below mean anything, and the amount is not
    // arbitrary:
    //
    // * With no churn at all, deleting the pin is **invisible** -- nothing
    //   wants the frame, so it still holds this block and the caller still
    //   reads the right bytes. Measured, not assumed: with `pin` made a no-op
    //   and this loop empty, every gate passed.
    // * With exactly as many blocks as there are frames it is *still* almost
    //   invisible, because the frame holding this block was the most recently
    //   read and so the last one an LRU cache would choose.
    // * With twice as many, every frame the cache is *allowed* to reuse is
    //   reused and reused again, and a deleted pin shows up immediately: the
    //   caller is handed a page holding the **directory** block instead, and
    //   both gates fail on the bytes.
    //
    // That last line is the whole point of this step. The failure being
    // guarded against is not a crash, it is one program silently reading
    // another's data, and it is only visible if something is competing for
    // the frame. The exhaustive form of the question lives on the host, asked
    // after every eviction; this asks it once, on a real disk, under pressure.
    {
        use bhaskix_fs::Pages;
        for other in 1..=(CACHE_PAGES as u32) * 2 {
            let _ = cache.page(other);
        }
    }

    let (handed, _) = call(
        syscall::INVOKE,
        ENDPOINT,
        method::HAND,
        [CACHE_SLOT + frame as u64, rights::READ, 0, 0],
    );
    if handed == status::OK {
        answer(dir::OK, size, 0);
    } else {
        cache.unpin(frame);
        answer(dir::NOWHERE, handed, 0);
    }
}

/// Answers directory lookups, for ever.
///
/// The badge on each request says which directory is being asked, and the
/// **kernel** put it there: a badge may only be set by a capability that has
/// none, this program holds the only unbadged one, and so a client cannot name
/// a directory it was not given. That is the whole of the namespace.
fn serve(mut cache: Cache<'static, BlockService>) -> ! {
    loop {
        let (status, badge, method, args) = receive();
        if status != status::OK {
            exit()
        }
        if method == dir::MAP {
            lend(&mut cache, badge);
            continue;
        }
        if method != dir::OPEN_AT {
            answer(dir::NO_SUCH_NAME, 0, 0);
            continue;
        }

        let chunk = Chunk::unpack(&args);
        let name = chunk.bytes();
        if !is_one_component(name) || chunk.more() {
            answer(dir::BAD_NAME, 0, 0);
            continue;
        }

        let (inode_index, generation) = dir::parts(badge);
        let Ok(mut mounted) = Filesystem::mount(&mut cache) else {
            answer(dir::GONE, 0, 0);
            continue;
        };
        let Ok(directory) = mounted.inode(inode_index) else {
            answer(dir::GONE, 0, 0);
            continue;
        };
        // The generation first, before the kind and before the lookup. A
        // handle whose directory has been reused names an inode that is now
        // somebody else's, and every question asked of it -- including "is
        // this a directory" -- is a question about their data.
        if directory.generation != generation {
            answer(dir::GONE, 0, 0);
            continue;
        }
        let Ok((found, target)) = mounted.lookup(&directory, name) else {
            answer(dir::NO_SUCH_NAME, 0, 0);
            continue;
        };
        let is_directory = u64::from(target.kind == Kind::Directory);
        let size = target.size;

        // Touch the file's own data block, which is not cached: a call to the
        // block service made *while this program already owes its caller a
        // reply*. This is the reproduction the syscall stub's user-stack bug
        // was found with, and it stays because it is the cheapest thing in
        // this tree that exercises a service calling a service.
        if target.kind == Kind::File && target.direct[0] != 0 {
            use bhaskix_fs::Pages;
            let _ = cache.page(target.direct[0]);
        }

        // A capability naming what was found, derived from this program's own
        // endpoint and handed to the caller. Where it lands is the caller's to
        // say and this program cannot influence it: `HAND` puts it in the slot
        // the caller declared with `EXPECT`, and no argument here could name
        // another.
        let (handed, _) = call(
            syscall::INVOKE,
            ENDPOINT,
            method::HAND,
            [
                ENDPOINT,
                rights::READ | rights::DERIVE,
                dir::handle(found, target.generation),
                0,
            ],
        );
        if handed == status::OK {
            answer(dir::OK, size, is_directory);
        } else {
            // The commonest reason is that the caller never said where. That
            // is the caller's mistake and not a missing name, so it is a
            // different answer.
            // The status, not just "it did not work": the commonest reason is
            // that the caller never said where, and that is a different fault
            // from the service being refused.
            answer(dir::NOWHERE, handed, is_directory);
        }
    }
}

core::arch::global_asm!(
    r#"
.section .text._start,"ax",@progbits
.globl _start
_start:
    xor rbp, rbp
    and rsp, -16
    call fsd_main
    ud2
"#
);
