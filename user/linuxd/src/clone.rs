// SPDX-License-Identifier: Apache-2.0
//! A cloned thread that starts as Linux starts it — [RFC 0086](../../../docs/rfc/0086-the-motivating-workload.md)
//! step 5, the project lead's choice of 2026-10-01 over a kernel method.
//!
//! The nucleus starts a thread at an address on a stack (`SPAWN_THREAD`) and
//! gives it nothing else. Linux resumes a `clone` child just after its parent's
//! `syscall`, with the parent's registers, `rax` zero, the new stack and — for
//! `CLONE_SETTLS` — its own TLS base; go 1.27.1's runtime depends on every part
//! of that. So each clone gets a **trampoline**
//! (`bhaskix_personality::thread::clone_trampoline`) written into a page of the
//! process's own, and the thread is started on it. It is the `fork` trampoline's
//! idea (RFC 0084) carrying the whole register file instead of `rax` alone.
//!
//! **The whole file needed a kernel change underneath it.** The staged frame
//! read `rbx`, `rbp` and `r12`–`r15` as zero, because the `SYSCALL` stub saved
//! only caller-saved registers — and Go's child reads `R12` and `R13`. The stub
//! saves all six since the same day; see `SyscallFrame::r15`.
//!
//! # The page and its slots
//!
//! One read-execute page per process, sixteen slots of 256 bytes. A slot is
//! taken before the thread is started and given back at the thread's **second
//! call**. Sixteen threads that have not yet left their trampoline is the
//! bound, and a seventeenth `clone` is told `EAGAIN`, which Linux answers when
//! it cannot make a thread.
//!
//! ~~Given back at the thread's first call~~ — **wrong, and it corrupted Go,
//! found 2026-10-01.** The first call is the trampoline's own `arch_prctl`,
//! and when it returns the thread is *still running the trampoline*: the
//! register loads and the jump come after it, on the thread's own CPU, while
//! this program goes on answering others. A `clone` answered in that window
//! took the same slot and rewrote the code under the running thread, which
//! then left with some of another thread's registers — two threads sharing one
//! Go `m` or `g`. Three five-minute runs had died three different ways
//! ("stopm holding locks", a map pointer of 8, a signal with no `g`), and the
//! window fits all three; whether it was the whole cause is what the runs after
//! the fix are for, and RFC 0086 records what they showed. The second call is made from after the jump, so it is the first
//! moment the slot is certainly free: for Go it is `gettid`, at once.
//!
//! **Retired: the `r9` entry.** Until this step the child started at whatever
//! the caller put in `r9`, a contract of this project's own (RFC 0005 step 6,
//! moved here by RFC 0032 step 10). Go puts its `g` there. The kernel's clone
//! probe was the one caller written to the old contract and was rewritten to
//! Linux's the same day.

use bhaskix_abi::{method, status, syscall};
use bhaskix_personality::call::{Answer, PersonalityCall};
use bhaskix_personality::signal::Registers;
use bhaskix_personality::thread::{TRAMPOLINE_BYTES, clone_trampoline};

/// Processes with a trampoline page at once.
const PAGES: usize = 8;
/// Slots on a page.
const SLOTS: usize = 4096 / TRAMPOLINE_BYTES;
/// Where a process's trampoline page is looked for first, and how far it moves
/// when that page is taken — `fork`'s numbers, for `fork`'s reasons.
const FIRST_AT: u64 = 0x0000_0000_3100_0000;
const STRIDE: u64 = 0x20_0000;
const TRIES: u32 = 32;
const EAGAIN: i64 = -11;

#[derive(Clone, Copy)]
struct Page {
    domain: u32,
    at: u64,
    /// The Linux tid each slot waits for, or 0 for a free slot.
    owners: [u32; SLOTS],
    /// Whether that thread has made its first call — the trampoline's own.
    started: [bool; SLOTS],
}

static mut TABLE: [Option<Page>; PAGES] = [None; PAGES];

fn table() -> &'static mut [Option<Page>; PAGES] {
    // SAFETY: single-threaded by construction, as every table in this program:
    // it has one thread, which runs one call to completion before the next.
    unsafe { &mut *core::ptr::addr_of_mut!(TABLE) }
}

/// The registers a `syscall` frame image carries, in the order the frame is
/// staged (see the fault path in `main.rs`).
fn registers_of(image: &[u64]) -> Registers {
    Registers {
        rax: image[0],
        rbx: image[1],
        rcx: image[2],
        rdx: image[3],
        rsi: image[4],
        rdi: image[5],
        rbp: image[6],
        r8: image[7],
        r9: image[8],
        r10: image[9],
        r11: image[10],
        r12: image[11],
        r13: image[12],
        r14: image[13],
        r15: image[14],
        rip: image[15],
        eflags: image[16],
        rsp: image[17],
        cr2: 0,
    }
}

/// This process's trampoline page, mapping one if it has none.
fn page_of(request: &PersonalityCall) -> Option<usize> {
    let pages = table();
    if let Some(index) = pages
        .iter()
        .position(|page| page.is_some_and(|page| page.domain == request.domain))
    {
        return Some(index);
    }
    let index = pages.iter().position(Option::is_none)?;
    let handle = super::handle_of(request.domain);
    let mut at = super::process_for(request.domain)?.free_page(FIRST_AT)?;
    for _ in 0..TRIES {
        if super::map_at_eager(handle, at, 1, super::PROT_READ_EXECUTE) {
            pages[index] = Some(Page {
                domain: request.domain,
                at,
                owners: [0; SLOTS],
                started: [false; SLOTS],
            });
            return Some(index);
        }
        at = at.checked_add(STRIDE)?;
    }
    None
}

/// Starts a `clone` child as Linux would: see the module note. `image` is
/// the parent's staged frame; `stack` and `tls` are `plan_clone`'s.
pub(crate) fn spawn(
    request: &PersonalityCall,
    image: &[u64],
    stack: u64,
    tls: Option<u64>,
) -> Answer {
    let Some(index) = page_of(request) else {
        return Answer::error(EAGAIN);
    };
    let Some(Some(page)) = table().get(index).copied() else {
        return Answer::error(EAGAIN);
    };
    let Some(slot) = page.owners.iter().position(|owner| *owner == 0) else {
        return Answer::error(EAGAIN);
    };
    let parent = registers_of(image);
    // Linux: a stack of zero is the parent's own.
    let stack = if stack == 0 { parent.rsp } else { stack };
    let (code, length) = clone_trampoline(&parent, stack, tls);
    let entry = page.at + (slot * TRAMPOLINE_BYTES) as u64;
    if !super::copy_out(request.domain, entry, &code[..length]) {
        return Answer::error(EAGAIN);
    }
    let made = super::call(
        syscall::INVOKE,
        super::handle_of(request.domain),
        method::SPAWN_THREAD,
        [entry, stack, 0, 0],
    );
    if made.status != status::OK {
        return Answer::error(EAGAIN);
    }
    // The tid this program hands out is the nucleus's plus one; it is also
    // what the child's first call will arrive carrying.
    let tid = made.args[0] as u32 + 1;
    if let Some(Some(page)) = table().get_mut(index) {
        page.owners[slot] = tid;
        page.started[slot] = false;
    }
    Answer::ok(u64::from(tid))
}

/// A thread made a call. A clone child's first is its trampoline's own, and
/// marks it started; its second is made from past the trampoline's last
/// instruction, and frees the slot. See the module note for why the first is
/// not enough.
pub(crate) fn seen(domain: u32, thread: u32) {
    for page in table().iter_mut().flatten() {
        if page.domain != domain {
            continue;
        }
        for (owner, started) in page.owners.iter_mut().zip(page.started.iter_mut()) {
            if *owner != thread {
                continue;
            }
            if *started {
                *owner = 0;
                *started = false;
            } else {
                *started = true;
            }
        }
    }
}

/// A domain is gone: its page's record with it. The page went with the space.
pub(crate) fn forget_domain(domain: u32) {
    for slot in table().iter_mut() {
        if slot.is_some_and(|page| page.domain == domain) {
            *slot = None;
        }
    }
}
