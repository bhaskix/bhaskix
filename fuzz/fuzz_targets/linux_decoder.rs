// SPDX-License-Identifier: Apache-2.0
//! Coverage-guided fuzzing of the Linux personality's system-call argument
//! decoder -- and of what the nucleus does with what it accepts.
//!
//! RFC 0005's testing plan made this target mandatory, and `coding-style.md`
//! §8 makes one mandatory for every parser of untrusted input; until
//! 2026-10-29 the personality had targets for its `dirent` encoder and its
//! `sockaddr` parser only. The decoder is the `plan_*` functions: six
//! registers a hosted program chose, turned into a typed plan or a refusal.
//!
//! # What it found before it existed
//!
//! Writing it, 2026-10-29: the decoder rightly passes `munmap(0xffff_ffff_
//! ffff_f000, 0x2000)` on -- page-aligned, two pages -- and the nucleus built
//! the range with `VirtRange::from_pages`, which added without checking. With
//! overflow checks on in release kernels, that panicked the nucleus on the CPU
//! running `bin/linuxd`, from one hosted call; `mmap(MAP_FIXED)`, `mprotect`
//! and `madvise` the same. So every range the decoder accepts is handed here to
//! that same constructor, which must answer rather than panic: **the decoder
//! and the nucleus's first use of its output, fuzzed together**, because each
//! was correct alone.
//!
//! # What counts as a failure
//!
//! A panic, an abort or a hang. **Not** a refusal: random registers are mostly
//! nonsense, and refusing them is right. Asserted beyond that, each where the
//! decoder promises it:
//!
//! 1. Every refusal is a Linux errno, `-4095..=-1` -- the range a C library
//!    reads as an error; anything else reads as success.
//! 2. An accepted mapping's page count covers its length, and no more than one
//!    page over.
//! 3. An accepted range, built by the nucleus's constructor, either is refused
//!    there or spans exactly the pages the decoder planned.
//! 4. An accepted `lseek` lands where the arithmetic says, inside an `i64`.
//! 5. An accepted `write` takes no more than was asked or than one chunk, and
//!    one that moves bytes ends inside an `i64`.
//!
//! The first byte picks the call; the next forty-eight are its six registers,
//! little-endian, short input read as zeros.
//!
//! ```text
//! cargo +nightly fuzz run linux_decoder -- -max_total_time=3600
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;

use bhaskix_boot::VirtAddr;
use bhaskix_mm::VirtRange;
use bhaskix_personality::file::Kind;
use bhaskix_personality::memory::{Madvise, MapPlan, PAGE};
use bhaskix_personality::thread::{ClonePlan, FutexPlan};
use bhaskix_personality::{clock, eventfd, file, limit, memory, socket, thread};

const KINDS: [Kind; 8] = [
    Kind::Console,
    Kind::File,
    Kind::Directory,
    Kind::Socket,
    Kind::Epoll,
    Kind::Pipe,
    Kind::Proc,
    Kind::EventFd,
];

fn errno(value: i64) {
    assert!(
        (-4095..=-1).contains(&value),
        "a refusal outside the errno range: {value}"
    );
}

fn refused<T>(result: Result<T, i64>) -> Option<T> {
    match result {
        Ok(value) => Some(value),
        Err(value) => {
            errno(value);
            None
        }
    }
}

/// Property 2: `pages` covers `length` and is at most one page over.
fn covers(length: u64, pages: u64) {
    assert!(pages >= 1);
    assert!(u128::from(pages) * u128::from(PAGE) >= u128::from(length));
    assert!(u128::from(pages - 1) * u128::from(PAGE) < u128::from(length));
}

/// Property 3: the nucleus's constructor answers, and agrees when it builds.
fn nucleus_range(start: u64, pages: u64) {
    if let Some(range) = VirtRange::from_pages(VirtAddr(start), pages) {
        assert_eq!(range.start, VirtAddr(start));
        assert_eq!(
            u128::from(range.len()),
            u128::from(pages) * u128::from(PAGE)
        );
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&which, rest)) = data.split_first() else {
        return;
    };
    let mut a = [0u64; 6];
    for (index, word) in a.iter_mut().enumerate() {
        let mut bytes = [0u8; 8];
        for (offset, byte) in bytes.iter_mut().enumerate() {
            *byte = rest.get(index * 8 + offset).copied().unwrap_or(0);
        }
        *word = u64::from_le_bytes(bytes);
    }

    match which % 16 {
        0 => match memory::plan_mmap(a[0], a[1], a[2], a[3], a[4] as i64) {
            MapPlan::Refuse(value) => errno(value),
            MapPlan::Map {
                at,
                hint,
                pages,
                write,
                execute,
                ..
            } => {
                covers(a[1], pages);
                assert!(
                    !(write && execute),
                    "a mapping both writable and executable"
                );
                for start in [at, hint].into_iter().flatten() {
                    assert_eq!(start % PAGE, 0);
                    nucleus_range(start, pages);
                }
            }
        },
        1 => {
            if let Some((start, pages)) = refused(memory::plan_munmap(a[0], a[1])) {
                covers(a[1], pages);
                nucleus_range(start, pages);
            }
        }
        2 => {
            if let Some((start, pages, _, write, execute)) =
                refused(memory::plan_mprotect(a[0], a[1], a[2]))
            {
                covers(a[1], pages);
                assert!(!(write && execute));
                nucleus_range(start, pages);
            }
        }
        3 => {
            if let Some(Madvise::Discard { at, pages }) =
                refused(memory::plan_madvise(a[0], a[1], a[2]))
            {
                covers(a[1], pages);
                nucleus_range(at, pages);
            }
        }
        4 => {
            let _ = refused(file::plan_openat(a[0]));
        }
        5 => {
            let _ = refused(file::plan_fcntl(a[0], a[1]));
        }
        6 => {
            let _ = refused(file::plan_ioctl(a[0], KINDS[(a[1] % 8) as usize]));
        }
        7 => {
            let (current, size, offset, from) = (a[0], a[1], a[2] as i64, a[3]);
            if let Some(landed) = refused(file::plan_lseek(current, size, offset, from)) {
                assert!(landed <= i64::MAX as u64);
                let base = match from {
                    0 => 0,
                    1 => i128::from(current),
                    _ => i128::from(size),
                };
                assert_eq!(i128::from(landed), base + i128::from(offset));
            }
        }
        8 => {
            let (offset, count) = (a[0], a[1]);
            if let Some(take) = refused(file::plan_write(offset, count)) {
                assert!(take <= count && take <= file::WRITE_CHUNK);
                assert_eq!(take == 0, count == 0);
                // Only for a write that moves bytes: a zero-length one is `Ok(0)`
                // without looking at the offset, by `plan_write`'s own rule, and
                // the offset is the descriptor's, which `plan_lseek` already keeps
                // inside an `i64`. The first campaign (2026-10-29) stopped on
                // exactly that -- this property stated too broadly, not a fault.
                if take > 0 {
                    assert!(u128::from(offset) + u128::from(take) <= i64::MAX as u128);
                }
            }
        }
        9 => {
            let _ = refused(clock::plan(a[0]));
        }
        10 => {
            let _ = refused(eventfd::plan(a[0]));
        }
        11 => {
            let new = (a[1] & 1 != 0).then_some(limit::Limit {
                soft: a[2],
                hard: a[3],
            });
            let _ = refused(limit::plan(a[0], new));
        }
        12 => {
            let _ = refused(socket::plan_socket(a[0], a[1], a[2]));
        }
        13 => {
            let _ = refused(socket::plan_setsockopt(a[0], a[1], a[2]));
        }
        14 => {
            if let ClonePlan::Refuse(value) = thread::plan_clone(a[0], a[1], a[2], a[3], a[4]) {
                errno(value);
            }
        }
        _ => {
            if let FutexPlan::Refuse(value) = thread::plan_futex(a[0], a[1], a[2]) {
                errno(value);
            }
        }
    }
});
