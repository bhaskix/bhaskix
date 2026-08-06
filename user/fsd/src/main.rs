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
//! What it does **not** have is a way to be asked anything. Serving comes with
//! RFC 0016 step 4, along with directory capabilities; the claim this program
//! is here to support is narrower and is worth making on its own: the
//! filesystem parses a real disk from a domain, and gets the same answer the
//! kernel gets.

#![no_std]
#![no_main]

use bhaskix_abi::{block, method, status, syscall};
use bhaskix_fs::{Cache, Filesystem, FsError, Store};

/// The slot the block service's endpoint capability is in.
const BLOCK: u64 = 0;
/// The slot this program's memory object is in.
///
/// Named to the block service, which cannot choose it: the kernel re-checks it
/// against what this domain actually holds, so a service pointed at the wrong
/// slot reaches nothing rather than somebody else's memory.
const MEMORY: u64 = 1;

/// Where that memory is mapped. Ten pages.
const MEMORY_AT: u64 = 0x2000_0000;
/// The page the block service fills and drains, at the start of it.
const BULK_AT: u64 = MEMORY_AT;
/// The eight pages after it, which are the page cache.
const CACHE_AT: u64 = MEMORY_AT + 0x1000;
/// How many pages of cache. Enough that a transaction does not thrash.
const CACHE_PAGES: usize = 8;
/// The last page, where this program leaves what it found.
const REPORT_AT: u64 = CACHE_AT + (CACHE_PAGES as u64) * 0x1000;

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
            in("rsi") method,
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

/// Leaves what this program found where the kernel can read it.
///
/// A page of the memory object it holds, which the kernel can reach through
/// the object's frames. The marker goes last and after a fence, so a kernel
/// that sees the marker sees everything under it.
fn report(blocks: u64, entries: u64, read: u64, matched: u64, sectors: u64) {
    // SAFETY: the last page of the memory this program holds and mapped
    // writable, and nothing else in this program uses it.
    unsafe {
        let at = REPORT_AT as *mut u64;
        core::ptr::write_volatile(at.add(1), blocks);
        core::ptr::write_volatile(at.add(2), entries);
        core::ptr::write_volatile(at.add(3), read);
        core::ptr::write_volatile(at.add(4), matched);
        core::ptr::write_volatile(at.add(5), sectors);
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

    mark(1);
    let store = BlockService::new();
    mark(2);
    let sectors = store.sectors;
    if sectors == 0 {
        report(0, 0, 0, 0, 0);
        exit()
    }

    // SAFETY: eight pages of the memory this program holds and mapped
    // writable, and nothing else in this program uses them.
    let frames =
        unsafe { core::slice::from_raw_parts_mut(CACHE_AT as *mut u8, CACHE_PAGES * 4096) };
    mark(3);
    let Ok(mut cache) = Cache::new(frames, store) else {
        report(0, 0, 0, 0, sectors);
        exit()
    };

    // From here on there is nothing left that this program wrote: every
    // structure below is read by `bhaskix-fs`, unchanged, out of pages that
    // came off a disk through another domain.
    mark(4);
    let Ok(mut mounted) = Filesystem::mount(&mut cache) else {
        report(0, 0, 0, 0, sectors);
        exit()
    };
    mark(6);
    let blocks = mounted.superblock().blocks;
    let Ok(root) = mounted.root() else {
        report(blocks, 0, 0, 0, sectors);
        exit()
    };

    mark(7);
    let mut entries = 0u64;
    mounted.list(&root, |_| entries += 1);

    let Ok((_, inode)) = mounted.lookup(&root, b"on-a-disk") else {
        report(blocks, entries, 0, 0, sectors);
        exit()
    };
    mark(8);
    let mut contents = [0u8; 64];
    let read = mounted.read(&inode, 0, &mut contents);
    let matched = u64::from(contents.get(..read) == Some(EXPECTED));

    report(blocks, entries, read as u64, matched, sectors);

    // Not `exit`. A service that has answered is not a service that is
    // finished, and in RFC 0016 step 4 this becomes a `recv` loop. Parking
    // here rather than leaving is also what a filesystem should do with the
    // capabilities it holds: giving them up means the disk is unmounted.
    loop {
        call(syscall::YIELD, 0, 0, [0; 4]);
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
