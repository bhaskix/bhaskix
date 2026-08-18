// SPDX-License-Identifier: Apache-2.0
//! Synchronisation primitives, and the lock ordering they enforce.
//!
//! # Lock ranking
//!
//! `docs/architecture.md` §6 and `docs/coding-style.md` §7 require that lock
//! ordering be *declared rather than remembered*. Every [`SpinLock`] carries a
//! [`Rank`], and a blocking acquisition of a lock ranked at or below one this
//! execution context already holds is reported as an ordering violation.
//!
//! The point is not to catch deadlocks when they happen — a deadlocked kernel
//! prints nothing and there is nothing to catch. It is to catch the *ordering*
//! that would one day deadlock, on the run where the timing happened to be
//! benign. Nearly every acquisition order in this kernel is currently safe by
//! accident of which code paths overlap; ranking makes it safe on purpose.
//!
//! ## Why `try_lock` is exempt from *ranking*
//!
//! [`SpinLock::try_lock`] neither checks the order nor records the
//! acquisition, and that exemption is load-bearing rather than a convenience.
//!
//! A deadlock is a cycle in which *every* edge is a blocking wait. A
//! `try_lock` never waits, so it can never be such an edge, and an order that
//! contains one cannot close a cycle. This matters because interrupt handlers
//! acquire locks at points chosen by the hardware rather than by the code:
//! a timer interrupt can land while any lock at all is held, so *every* lock
//! taken in interrupt context is out of rank with respect to something. That
//! is precisely why [`crate::sched::preempt`] and the page-fault handler use
//! `try_lock` — and it is why ranking them would produce a flood of reports
//! about orders that cannot deadlock.
//!
//! ## And why it is *not* exempt from holding
//!
//! The paragraph above is about ordering, and for a long time its conclusion
//! was quietly read as a second one: that a `try_lock` holder is safe to
//! deschedule. It does not follow, and the difference cost a stall.
//!
//! `preempt` refuses to take the CPU from a thread holding a lock, because a
//! preempted holder can only release by running again. It decided that by
//! asking whether the ranked set was empty — and a `try_lock` is not in the
//! ranked set, so its holder looked like a thread holding nothing at all. It
//! was holding a lock. `sched::exit` reaches two functions that `try_lock`
//! *every* runqueue with interrupts enabled, so a tick landing in that scan
//! could carry the exiting thread off its CPU still holding a **remote**
//! runqueue, which nothing would then release.
//!
//! [`holds_any`] answers the question the rank set cannot: not *where in
//! the order* this CPU is, but *whether it is holding anything at all*. Taking
//! no rank and holding no lock are different claims, and only the first is
//! true of `try_lock`.
//!
//! ## Two questions, two pieces of state, and why they cannot be one
//!
//! [`held_mask`] and [`holds_any`] look redundant and are not. The mask says
//! *where in the declared order* this CPU sits; the count says *whether it is
//! holding anything*. They are given up at opposite ends of the release, and
//! neither order works for both:
//!
//! - The **rank bit must go before** the lock is released. Held one instant
//!   longer, the next acquisition of that rank looks like two at once and is
//!   reported as a violation against blameless code.
//! - The **count must go after**. Given up first, there is a window in which
//!   the lock is still held and the CPU reports nothing — and a tick landing
//!   there carries the holder away with the lock still set.
//!
//! For one milestone a single mask did both jobs and was cleared before the
//! release, which is correct for ranking and wrong for preemption. That was
//! the bring-up stall: a lock left held by a thread that would never run
//! again, recorded as held by nobody. Splitting the two, and moving only the
//! count, took 700 boots from an expected five stalls to none.
//!
//! Getting this backwards is not hypothetical: the first attempt moved *both*
//! to after the release and produced a false ordering report at one boot in
//! 700 — the wait-queue bit still set from a release that had not finished
//! being recorded.
//!
//! **Acquisition has the same rule and the opposite order**: the count goes up
//! *before* the rank bit. Set the mask first and there are two instructions in
//! which this CPU claims a rank while the count still reads empty, so a tick
//! carries the thread off holding a rank it has not yet acquired — and on
//! resume `finish_switch` reports an ordering violation against it. That was
//! the second false report, at one boot in thirty, and it was found by an
//! instrument rather than by rereading this file: `SAVED HOLDING` named
//! `ipc-cli-a` and `dom-a-0` being switched out carrying masks they did not
//! hold.
//!
//! The rule both halves obey: **claim before you might hold, give up after you
//! certainly do not.** Over-claiming costs a skipped preemption. Under-claiming
//! costs a CPU.
//!
//! ## Why a violation reports rather than panics
//!
//! `docs/coding-style.md` §7 says debug builds should panic. This reports and
//! continues instead, for the reason `lockdep` does the same: the report is
//! the entire value, and halting on the first one discards the coverage of the
//! rest of the boot. A rank violation is a latent risk, not present corruption
//! — turning it into a guaranteed crash trades a possible future deadlock for
//! a certain immediate one. The boot test asserts the count is zero, which is
//! the same guarantee with more information when it fails.

use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use bhaskix_arch::percpu::{self, MAX_CPUS};

/// No CPU holds the lock. Matches the `NO_DOMAIN` convention in `irq.rs`.
///
/// `u32::MAX` rather than `0`, because `0` is a CPU.
const NO_OWNER: u32 = u32::MAX;

/// Every lock in the kernel, ordered by the sequence in which they may be
/// acquired: a context holding one may only block on a lock declared *below*
/// it here.
///
/// The order is not aesthetic. It is what the code already does, recovered by
/// reading every nesting site, and two entries are placed where intuition
/// would not put them:
///
/// - **`Heap` above `TlbSender`**, because unmapping frees frames inside
///   `heap::with`, and a shootdown must happen before a frame is handed back —
///   so the TLB lock is genuinely taken under the heap's.
/// - **`SchedRunqueue` below `Heap`**, which looks backwards for something as
///   central as the scheduler. A thread can be preempted while holding the
///   heap, and the switch path then blocks on the incoming CPU's runqueue: the
///   runqueue lock is an inner lock. `sched::spawn_on` already allocates
///   *outside* the runqueue lock for exactly this reason, which is the same
///   constraint arrived at independently.
///
/// Discriminants are bit indices into the per-CPU held set, so they must stay
/// distinct and below 64.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[repr(u8)]
pub enum Rank {
    /// `vm::ACTIVE` — the address space this CPU has loaded.
    AddressSpace = 0,
    /// `vm::PREVIOUS_ROOT` — the page-table root to restore on deactivate.
    AddressSpacePrevious = 1,
    /// `iommu::WINDOW` — the device windows a unit translates through.
    ///
    /// **Outside the heap**, because mapping a page into a device's window may
    /// have to allocate a level of its page tables, and allocating takes the
    /// heap while this is held. It was ranked innermost at first, on the
    /// reasoning that revocation reaches it last — and the detector reported
    /// the inversion on the first boot that mapped anything.
    ///
    /// Nothing is held when this is taken: `shared::revoke` releases the arena
    /// before unmapping from a device, and the syscall path resolves its
    /// capabilities and lets go before it maps.
    DmaWindow = 2,
    /// `heap::HEAP` — the kernel allocator, and the physical allocator inside it.
    Heap = 3,
    /// `tlb::SENDER` — serialises shootdowns over the one shared address slot.
    TlbSender = 4,
    /// `time::TIMERS` — one CPU's pending timer deadlines.
    ///
    /// Outside the runqueues for the same reason the wait queues are: expiring
    /// a timer wakes a thread, which takes a runqueue lock while this is held.
    Timers = 5,
    /// `domain::TABLE` — the domain table.
    ///
    /// Outside the capability arena: destroying a domain revokes its root
    /// capability, so the table lock is taken first and the arena second.
    /// Nothing goes the other way.
    Domains = 6,
    /// `cap::ARENA` — the global capability derivation tree.
    ///
    /// Outside the wait queues: revoking a capability to an endpoint will need
    /// to wake whoever is blocked on it, and that takes a wait queue and then a
    /// runqueue. Nothing goes the other way — the IPC paths resolve
    /// capabilities before they block, never after.
    Capabilities = 7,
    /// `ipc::TABLE` — the endpoint table.
    ///
    /// Inside the capability arena, because a syscall resolves the endpoint
    /// capability before it touches the endpoint; outside the runqueues,
    /// because completing a rendezvous wakes the thread on the other side.
    Endpoints = 8,
    /// `wait::WaitQueue` — the waiter list of a blocking primitive.
    ///
    /// Outside the runqueues, because both halves of a sleep take them in that
    /// order: a sleeper holds this while marking itself blocked, and a waker
    /// holds it while marking a sleeper ready. Either one taking them the
    /// other way round is the deadlock this ordering exists to make visible.
    WaitQueue = 9,
    /// `sched::QUEUES` — one runqueue per CPU.
    SchedRunqueue = 10,
    /// `notify::ALLOCATION` — creation and destruction of notifications.
    ///
    /// Outside the runqueues, because destroying one wakes whoever was
    /// waiting. The *signal* path takes no lock at all, which is what lets an
    /// interrupt handler call it.
    Notifications = 11,
    /// `shared::ARENA` — memory objects (RFC 0009).
    ///
    /// Outside the heap, because creating one allocates frames while it is
    /// held; inside the domain table, because charging an envelope happens
    /// before the arena is taken. Nothing goes the other way.
    SharedMemory = 12,
    /// `irq::HANDLERS` — claimed interrupt sources.
    ///
    /// Outside `vectors::TABLE`, because claiming a source takes this and then
    /// allocates a vector. Nothing goes the other way. They were briefly the
    /// same rank, which the checker reported on the first boot: two locks of
    /// one rank have no declared order and can close a cycle just as easily as
    /// an inversion.
    IrqHandlers = 13,
    /// `vectors::TABLE` — who owns which interrupt vector.
    ///
    /// A leaf: taken at boot and when a driver claims a source, with nothing
    /// acquired while it is held. Inside the scheduler's queues because a
    /// claim never wakes anything.
    Vectors = 14,
    /// `virtio::DEVICE` — the one block device.
    ///
    /// Inside the scheduler's queues because nothing here wakes a thread: the
    /// driver waits for its device by spinning on a ring the device writes,
    /// not by blocking. Outside the console, because a driver reports what it
    /// found while holding itself.
    Block = 15,
    /// `console::CONSOLE` — the innermost lock. Anything may print.
    Console = 16,
}

impl Rank {
    /// This rank's bit in a held set.
    const fn bit(self) -> u64 {
        1u64 << (self as u8)
    }

    /// Every rank at or *inside* this one, as a mask.
    ///
    /// Holding any of these when blocking on `self` is a violation. Strictly
    /// inside is the inversion; equal means two locks of the same rank, which
    /// have no declared order relative to each other and so can close a cycle
    /// just as easily.
    const fn at_or_inside(self) -> u64 {
        // Bits `self..64`. Note the direction: a *lower* discriminant is
        // acquired earlier, so the ranks that must not already be held are the
        // ones numbered at or above this.
        u64::MAX << (self as u8)
    }

    /// For reports.
    const fn name(self) -> &'static str {
        match self {
            Self::AddressSpace => "vm::ACTIVE",
            Self::AddressSpacePrevious => "vm::PREVIOUS_ROOT",
            Self::Heap => "heap::HEAP",
            Self::TlbSender => "tlb::SENDER",
            Self::Timers => "time::TIMERS",
            Self::Domains => "domain::TABLE",
            Self::Capabilities => "cap::ARENA",
            Self::Endpoints => "ipc::TABLE",
            Self::WaitQueue => "wait::WaitQueue",
            Self::SchedRunqueue => "sched::QUEUES",
            Self::Notifications => "notify::ALLOCATION",
            Self::SharedMemory => "shared::ARENA",
            Self::IrqHandlers => "irq::HANDLERS",
            Self::Vectors => "vectors::TABLE",
            Self::Block => "virtio::DEVICE",
            Self::DmaWindow => "iommu::WINDOW",
            Self::Console => "console::CONSOLE",
        }
    }
}

/// Whether blocking on `rank` is legal while `held` is held.
///
/// Pure, so that the policy can be tested exhaustively on the host rather than
/// inferred from whether a particular boot happened to deadlock.
#[must_use]
pub const fn would_violate(held: u64, rank: Rank) -> bool {
    held & rank.at_or_inside() != 0
}

/// The set of ranks each CPU currently holds, one bit per [`Rank`].
///
/// A bitmask rather than a stack: it is a single atomic, it makes "is anything
/// at or below this held" one `and`, and it stays correct when guards are
/// dropped out of order, which a stack would not.
static HELD: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];

/// Ordering violations observed since boot.
static VIOLATIONS: AtomicU64 = AtomicU64::new(0);

/// Rank-checked acquisitions since boot.
///
/// Reported alongside the violation count because zero violations is equally
/// consistent with a correct kernel and with a checker that never ran. The
/// acquisition count distinguishes them.
static ACQUISITIONS: AtomicU64 = AtomicU64::new(0);

/// Whether to print each violation. Cleared while the self-test provokes one
/// deliberately, so the expected report does not read like a real failure.
static REPORT: AtomicBool = AtomicBool::new(true);

/// Which per-CPU cell this thread's holds live in.
///
/// On the machine: the CPU. Under the host test harness: a **leased slot per
/// test thread**, because `percpu::cpu_id()` answers 0 for every host thread
/// -- per-CPU data is never installed there -- so every parallel test shared
/// `HELD[0]` and `HOLDS[0]`, and tests of this module raced each other: one
/// thread's `set_held_mask(0)` erased another's live hold, about twice in
/// twenty-six full runs. A lease per thread is not a test convenience, it is
/// the semantics: on the machine a thread's holds live with the CPU it
/// occupies alone, and a test thread is the only occupant of its slot.
fn effective_cpu() -> usize {
    #[cfg(test)]
    {
        test_cpu::id()
    }
    #[cfg(not(test))]
    {
        let cpu = percpu::cpu_id() as usize;
        // Before per-CPU data exists, `cpu_id` answers 0 -- which is correct,
        // since everything that early runs on the bootstrap CPU.
        if cpu < MAX_CPUS { cpu } else { 0 }
    }
}

/// Per-test-thread slot leases. See [`effective_cpu`].
#[cfg(test)]
mod test_cpu {
    use super::MAX_CPUS;
    use core::sync::atomic::{AtomicU64, Ordering};

    /// One bit per leased slot. `MAX_CPUS` is 64, which is what makes a
    /// single word the whole allocator.
    static TAKEN: AtomicU64 = AtomicU64::new(0);

    struct Lease(usize);

    impl Drop for Lease {
        fn drop(&mut self) {
            TAKEN.fetch_and(!(1 << self.0), Ordering::Relaxed);
        }
    }

    fn take() -> Lease {
        loop {
            let current = TAKEN.load(Ordering::Relaxed);
            let free = (!current).trailing_zeros() as usize;
            assert!(free < MAX_CPUS, "more live test threads than per-cpu slots");
            if TAKEN
                .compare_exchange(
                    current,
                    current | 1 << free,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                )
                .is_ok()
            {
                return Lease(free);
            }
        }
    }

    std::thread_local! {
        static ID: Lease = take();
    }

    pub fn id() -> usize {
        ID.with(|lease| lease.0)
    }
}

fn slot() -> &'static AtomicU64 {
    &HELD[effective_cpu()]
}

/// The ranks this CPU currently holds.
#[must_use]
pub fn held_mask() -> u64 {
    slot().load(Ordering::Relaxed)
}

/// How many locks this CPU holds, of any kind, ranked or not.
///
/// **A second question, deliberately not answered by the rank mask.** The mask
/// says *where in the declared order* this CPU sits, and it must be exact for
/// the order check: a bit left set after its lock is released makes the next
/// acquisition of that rank look like two at once, which is a violation
/// reported against code that did nothing wrong. It was, and the soak found it
/// at one boot in 700.
///
/// This says only *whether anything at all is held*, which is what deciding to
/// deschedule a thread depends on. Being a count, it is exact under nesting;
/// being separate, it can be given up **after** the release while the rank bit
/// is given up before it, and neither has to compromise for the other.
static HOLDS: [AtomicU32; MAX_CPUS] = [const { AtomicU32::new(0) }; MAX_CPUS];

/// The last lock events per CPU, for the stall dump and nothing else.
///
/// Three captures of the boot hang showed steady phantom hold counts on the
/// running threads' CPUs, and reasoning from construction failed three times
/// to find the pair of acquires whose releases never land. So the ledger:
/// every counted acquisition and every release records the acquisition
/// site's `Location` into a per-CPU ring, and the stall dump prints the ring
/// for a vetoing CPU. An acquire whose release never appears is the leak,
/// named by file and line. Atomics only — recording must not take locks.
const LOCK_EVENTS: usize = 16;

struct LockEventRing {
    /// `&'static Location` as a pointer; null = empty slot.
    at: [core::sync::atomic::AtomicUsize; LOCK_EVENTS],
    /// Rank byte (255 = unranked try_lock), bit 8 = acquire, bit 9 = the
    /// count after the event (low bits 16..24), packed small on purpose.
    meta: [AtomicU32; LOCK_EVENTS],
    next: core::sync::atomic::AtomicUsize,
}

impl LockEventRing {
    const fn new() -> Self {
        Self {
            at: [const { core::sync::atomic::AtomicUsize::new(0) }; LOCK_EVENTS],
            meta: [const { AtomicU32::new(0) }; LOCK_EVENTS],
            next: core::sync::atomic::AtomicUsize::new(0),
        }
    }
}

static LOCK_EVENTS_PER_CPU: [LockEventRing; MAX_CPUS] = [const { LockEventRing::new() }; MAX_CPUS];

/// The guards currently open per CPU: acquisition site and rank, cleared on
/// release. The ring above shows *recent* traffic and rotated the culprits
/// out on the fourth capture; this table shows *what is held right now*, so
/// a steady phantom count reads out as the exact unreleased lines.
const OPEN_GUARDS: usize = 8;

struct OpenGuards {
    at: [core::sync::atomic::AtomicUsize; OPEN_GUARDS],
    rank: [AtomicU32; OPEN_GUARDS],
    /// Cycle count at acquisition, so the dump can print each hold's age —
    /// the difference between "a long teardown" and "a loop that will never
    /// end" is a number, and the sixth capture needed it.
    since: [AtomicU64; OPEN_GUARDS],
}

impl OpenGuards {
    const fn new() -> Self {
        Self {
            at: [const { core::sync::atomic::AtomicUsize::new(0) }; OPEN_GUARDS],
            rank: [const { AtomicU32::new(0) }; OPEN_GUARDS],
            since: [const { AtomicU64::new(0) }; OPEN_GUARDS],
        }
    }
}

static OPEN_GUARDS_PER_CPU: [OpenGuards; MAX_CPUS] = [const { OpenGuards::new() }; MAX_CPUS];

/// Claims an open-guard slot; returns its index, or `OPEN_GUARDS` when the
/// table is full (eight simultaneous holds on one CPU is already a story the
/// rank mask tells without this table's help).
fn open_guard(at: &'static core::panic::Location<'static>, rank: u8) -> usize {
    let cpu = percpu::cpu_id() as usize;
    let table = &OPEN_GUARDS_PER_CPU[if cpu < MAX_CPUS { cpu } else { 0 }];
    for slot in 0..OPEN_GUARDS {
        if table.at[slot]
            .compare_exchange(
                0,
                at as *const _ as usize,
                Ordering::Relaxed,
                Ordering::Relaxed,
            )
            .is_ok()
        {
            table.rank[slot].store(u32::from(rank), Ordering::Relaxed);
            table.since[slot].store(bhaskix_arch::tsc::read(), Ordering::Relaxed);
            return slot;
        }
    }
    OPEN_GUARDS
}

/// The longest any lock of each rank was ever held, in cycles, with the
/// acquisition site of the record holder.
///
/// The permanent form of the question every stall capture asked: not "is
/// something held right now" but "what is the worst this rank has ever
/// been held, and by which line". Printed in the boot report, so contention
/// answers come from a line in every log instead of an investigation.
static LONGEST_HOLD: [AtomicU64; 64] = [const { AtomicU64::new(0) }; 64];
static LONGEST_HOLD_AT: [core::sync::atomic::AtomicUsize; 64] =
    [const { core::sync::atomic::AtomicUsize::new(0) }; 64];

/// The longest recorded hold of `rank`: `(cycles, site)`, site `None` if
/// the rank was never held.
#[must_use]
pub fn longest_hold(rank: usize) -> (u64, Option<&'static core::panic::Location<'static>>) {
    if rank >= 64 {
        return (0, None);
    }
    let cycles = LONGEST_HOLD[rank].load(Ordering::Relaxed);
    let raw = LONGEST_HOLD_AT[rank].load(Ordering::Relaxed);
    let at = if raw == 0 {
        None
    } else {
        // SAFETY: only `&'static Location`s are ever stored.
        Some(unsafe { &*(raw as *const core::panic::Location<'static>) })
    };
    (cycles, at)
}

fn note_hold_duration(table: &OpenGuards, slot: usize) {
    let rank = table.rank[slot].load(Ordering::Relaxed) as usize;
    if rank >= 64 {
        // Unranked try_locks share bucket 63's neighbourhood nowhere; skip
        // them — their story is the count, not the order.
        return;
    }
    let since = table.since[slot].load(Ordering::Relaxed);
    let held = bhaskix_arch::tsc::read().saturating_sub(since);
    if held > LONGEST_HOLD[rank].fetch_max(held, Ordering::Relaxed) {
        LONGEST_HOLD_AT[rank].store(table.at[slot].load(Ordering::Relaxed), Ordering::Relaxed);
    }
}

/// Releases an open-guard slot claimed by [`open_guard`].
///
/// Tries the remembered slot on the current CPU first; a guard released on
/// a different CPU than it was taken on — a thread that blocked holding,
/// migrated, and resumed, which is exactly the case being hunted — falls
/// back to scanning every CPU's table for the matching site.
fn close_guard(slot: usize, at: &'static core::panic::Location<'static>) {
    let key = at as *const _ as usize;
    if slot < OPEN_GUARDS {
        let cpu = percpu::cpu_id() as usize;
        let table = &OPEN_GUARDS_PER_CPU[if cpu < MAX_CPUS { cpu } else { 0 }];
        if table.at[slot].load(Ordering::Relaxed) == key {
            note_hold_duration(table, slot);
        }
        if table.at[slot]
            .compare_exchange(key, 0, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            return;
        }
    }
    for table in &OPEN_GUARDS_PER_CPU {
        for slot in 0..OPEN_GUARDS {
            if table.at[slot].load(Ordering::Relaxed) == key {
                note_hold_duration(table, slot);
            }
            if table.at[slot]
                .compare_exchange(key, 0, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                return;
            }
        }
    }
}

/// Prints every guard currently open on `cpu`, one line each — the
/// acquisition site and the rank byte (255 = unranked `try_lock`). The
/// count says something is held; this says *what*, which is the difference
/// between "the count leaked" and a file to open. Called from the markers
/// that fire when a count and reality disagree, so the specimen carries
/// its suspects with it.
pub fn dump_open_guards(cpu: usize) {
    let mut any = false;
    for_each_open_guard(cpu, |at, rank, _since| {
        any = true;
        crate::println!(
            "      open guard   rank {} acquired at {}:{}",
            rank,
            at.file(),
            at.line()
        );
    });
    if !any {
        crate::println!(
            "      open guard   none -- the counted hold has no open guard, which is itself the answer"
        );
    }
}

/// Walks the guards currently open on `cpu`: `(site, rank byte)`.
pub fn for_each_open_guard(
    cpu: usize,
    mut f: impl FnMut(&'static core::panic::Location<'static>, u8, u64),
) {
    let table = &OPEN_GUARDS_PER_CPU[if cpu < MAX_CPUS { cpu } else { 0 }];
    for slot in 0..OPEN_GUARDS {
        let raw = table.at[slot].load(Ordering::Relaxed);
        if raw != 0 {
            // SAFETY: only `&'static Location`s are ever stored.
            let at = unsafe { &*(raw as *const core::panic::Location<'static>) };
            f(
                at,
                table.rank[slot].load(Ordering::Relaxed) as u8,
                table.since[slot].load(Ordering::Relaxed),
            );
        }
    }
}

fn record_lock_event(at: &'static core::panic::Location<'static>, rank: u8, acquire: bool) {
    let cpu = percpu::cpu_id() as usize;
    let ring = &LOCK_EVENTS_PER_CPU[if cpu < MAX_CPUS { cpu } else { 0 }];
    let slot = ring.next.fetch_add(1, Ordering::Relaxed) % LOCK_EVENTS;
    let count = holds_slot().load(Ordering::Relaxed).min(0xff);
    ring.at[slot].store(at as *const _ as usize, Ordering::Relaxed);
    ring.meta[slot].store(
        u32::from(rank) | (u32::from(acquire) << 8) | (count << 16),
        Ordering::Relaxed,
    );
}

/// Walks a CPU's recent lock events, oldest first: `(location, rank byte,
/// acquire?, hold count just after)`. For the stall dump.
pub fn for_each_lock_event(
    cpu: usize,
    mut f: impl FnMut(&'static core::panic::Location<'static>, u8, bool, u32),
) {
    let ring = &LOCK_EVENTS_PER_CPU[if cpu < MAX_CPUS { cpu } else { 0 }];
    let next = ring.next.load(Ordering::Relaxed);
    for offset in 0..LOCK_EVENTS {
        let slot = (next + offset) % LOCK_EVENTS;
        let raw = ring.at[slot].load(Ordering::Relaxed);
        if raw == 0 {
            continue;
        }
        let meta = ring.meta[slot].load(Ordering::Relaxed);
        // SAFETY: only `&'static Location`s are ever stored.
        let at = unsafe { &*(raw as *const core::panic::Location<'static>) };
        f(at, meta as u8, meta & (1 << 8) != 0, (meta >> 16) & 0xff);
    }
}

/// Runs the acquire's claim — the count and rank going up — with interrupts
/// off, as one step with respect to the tick.
///
/// **This closes the hole every 2026-08-18 specimen pointed at.** The veto
/// in `preempt` protects a claimed holder; it cannot protect a claim in
/// flight. Between reading which CPU this is and landing the increment —
/// and again between the count's increment and the rank's — the count is
/// still zero, so a tick there switches the thread out and steal may resume
/// it on another CPU. The increment then lands on the *old* CPU's counter,
/// poisoning whichever thread runs there next with a hold it never took
/// (`BLOCK HOLDING` with no open guard, `SAVED COUNT`), while the claimant
/// carries a rank with no count (`COUNT MISMATCH`) and its release
/// underflows (`COUNT UNDERFLOW`) — the four markers of one tear, and
/// run-161's mirror is the same race with the windows reversed. A few
/// interrupt-free stores make the claim land whole, on one CPU, after which
/// the veto's protection is continuous.
fn claim_uninterrupted(claim: impl FnOnce()) {
    // On the host there is no tick and no steal — the per-thread leases
    // that stand in for CPUs never migrate — and a `cli` in ring 3 would
    // end the test process, so the guard is the target's alone.
    #[cfg(test)]
    claim();
    #[cfg(not(test))]
    {
        let were_enabled = bhaskix_arch::cpu::interrupts_enabled();
        if were_enabled {
            // SAFETY: re-enabled below on the same path; the window is a
            // handful of stores.
            unsafe { bhaskix_arch::cpu::disable_interrupts() };
        }
        claim();
        if were_enabled {
            // SAFETY: restoring exactly the state observed on entry.
            unsafe { bhaskix_arch::cpu::enable_interrupts() };
        }
    }
}

fn holds_slot() -> &'static AtomicU32 {
    &HOLDS[effective_cpu()]
}

/// Whether this CPU holds any lock taken with [`SpinLock::try_lock`].
///
/// **Exists because the rank exemption was quietly doing a second job it does
/// not support.** `try_lock` stays out of the ranked set for a sound reason: a
/// non-blocking acquisition can never be an edge in a deadlock cycle, so
/// ranking it would report orders that cannot deadlock. `sched::preempt` then
/// used that same emptiness to decide a thread was safe to deschedule — and
/// those are different claims. A `try_lock` cannot *deadlock*, but its holder
/// still holds the lock, and descheduling one strands every CPU waiting on it.
///
/// Whether this CPU holds any lock at all — the question [`held_mask`] cannot
/// answer, and the one [`crate::sched::preempt`] needs.
///
/// Covers `try_lock` as well as `lock`: taking no rank and holding no lock are
/// different claims, and only the first is true of a `try_lock`.
///
/// Stays true until *after* the lock is released, so there is no instant in
/// which a CPU holds something and reports nothing. The reverse — reporting a
/// lock for a few instructions after dropping it — costs at most one skipped
/// preemption.
#[must_use]
pub fn holds_any() -> bool {
    holds_slot().load(Ordering::Relaxed) != 0
}

/// The hold count of a *named* CPU, for the stall dump.
///
/// A nonzero count on a CPU that is spinning through bounded waits is a
/// leaked hold: `preempt` refuses to deschedule a holder, so a count that
/// never returns to zero vetoes preemption on that CPU for ever, and every
/// fresh thread pinned there starves at zero runs — the exact silhouette of
/// a captured one-in-fifteen bring-up hang. Reading another CPU's count is
/// racy and fine: the dump wants "stuck at nonzero", not an instant.
#[must_use]
pub fn holds_on(cpu: usize) -> u32 {
    HOLDS[if cpu < MAX_CPUS { cpu } else { 0 }].load(Ordering::Relaxed)
}

/// The rank mask of a *named* CPU, for the same dump.
///
/// The count says a lock is leaking; the mask says which ranks are lit, and
/// a rank is a name in [`Rank`] — the difference between "something leaks"
/// and a file to open. An unranked `try_lock` hold lights no bit, so a
/// nonzero count beside a zero mask is itself an answer: the leak is in a
/// `try_lock` guard.
#[must_use]
pub fn held_on(cpu: usize) -> u64 {
    HELD[if cpu < MAX_CPUS { cpu } else { 0 }].load(Ordering::Relaxed)
}

/// How many locks this CPU holds, for the context switch to save.
///
/// The count belongs to the *thread*, exactly as the rank mask does — see
/// [`set_held_mask`]. Left on the CPU it would pass to whoever ran next: a
/// thread that took no lock would inherit a count it never earned, and a CPU
/// whose count never fell back to zero would stop preempting altogether.
///
/// This was learned the second way round. The count was added per-CPU with no
/// saving, on the assumption that a holder could never be switched out — which
/// is what the guard is *for*, but `block_self` switches without consulting
/// it. The leak moved enough scheduling around to expose a genuine two-runqueue
/// inversion that 800 previous boots had never produced.
#[must_use]
pub fn holds_count() -> u32 {
    holds_slot().load(Ordering::Relaxed)
}

/// Replaces the hold count for this CPU, for the incoming thread.
pub fn set_holds_count(count: u32) {
    holds_slot().store(count, Ordering::Relaxed);
}

/// Replaces the held set for this CPU.
///
/// For the context switch: held locks belong to the *thread*, not the
/// processor, so the scheduler saves the outgoing thread's set and installs
/// the incoming one. Without this, a thread preempted while holding the heap
/// would leave its ranks behind, and the next thread to run on that CPU would
/// be reported for an order it had nothing to do with.
pub fn set_held_mask(mask: u64) {
    slot().store(mask, Ordering::Relaxed);
}

/// Violations observed since boot. The boot test requires this to be zero.
#[must_use]
pub fn violations() -> u64 {
    VIOLATIONS.load(Ordering::Relaxed)
}

/// Rank-checked acquisitions since boot.
#[must_use]
pub fn acquisitions() -> u64 {
    ACQUISITIONS.load(Ordering::Relaxed)
}

/// Discards violations counted so far.
///
/// Exists for the self-test, which provokes one on purpose and must not leave
/// it behind for the boot gate to trip over.
pub fn reset_violations() {
    VIOLATIONS.store(0, Ordering::Relaxed);
}

/// Silences violation reports, for a test that provokes one on purpose.
pub fn set_reporting(on: bool) {
    REPORT.store(on, Ordering::Relaxed);
}

fn record(held: u64, rank: Rank, site: &core::panic::Location<'_>) {
    VIOLATIONS.fetch_add(1, Ordering::Relaxed);
    if !REPORT.load(Ordering::Relaxed) {
        return;
    }
    // Naming both ends matters: "out of order" without saying against what
    // sends the reader to read every lock site, which is the work the rank
    // list exists to avoid.
    //
    // And naming *where*, because the two ends are not enough when both are
    // the same rank. `blocking on SchedRunqueue while holding SchedRunqueue`
    // identifies a shape, not a line, and this kernel takes runqueue locks in
    // some thirty places. The caller's location turns a week of reading into
    // one `grep`.
    //
    // The thread is deliberately not named: asking which thread is running
    // takes a runqueue lock, and this runs *inside* an acquisition that is
    // already going wrong.
    crate::println!(
        "    LOCK ORDER     blocking on {} (rank {}) while holding mask {:#08b}, at {}:{}",
        rank.name(),
        rank as u8,
        held,
        site.file(),
        site.line()
    );
}

/// A spinlock protecting a value.
///
/// Naming what it protects in the type — `SpinLock<Console>` rather than a
/// `SpinLock<()>` next to a `Console` — is the convention in
/// `docs/coding-style.md` §7, because it makes the protected data
/// unreachable without acquiring.
///
/// The [`Rank`] is a constructor argument rather than something registered
/// elsewhere, so that a lock cannot be added without declaring where it sits.
pub struct SpinLock<T> {
    locked: AtomicBool,
    /// The CPU that took the lock, or [`NO_OWNER`] when it is free.
    ///
    /// Diagnostic only — nothing in the locking protocol reads it. It exists
    /// because a held lock could say *that* it was held and not *by whom*: the
    /// bring-up watchdog could report a runqueue stuck for two seconds and had
    /// to state in the same breath that the CPU it named was where the lock
    /// was, not who took it. `spawn_on` and the wake paths block on a remote
    /// runqueue, so those are different questions.
    owner: AtomicU32,
    rank: Rank,
    value: UnsafeCell<T>,
}

// SAFETY: `SpinLock` grants access to its interior only through `lock()`,
// which returns a guard after winning an atomic compare-exchange, and only one
// guard can exist at a time. That makes concurrent access to `T` mutually
// exclusive, so sharing the lock across threads is sound whenever `T` may be
// sent across threads.
unsafe impl<T: Send> Sync for SpinLock<T> {}
// SAFETY: sending the lock sends the contained value; no reference to the
// interior can outlive a guard, so there is nothing left behind on the old
// thread.
unsafe impl<T: Send> Send for SpinLock<T> {}

impl<T> SpinLock<T> {
    /// Creates a new unlocked `SpinLock` at `rank`.
    pub const fn new(rank: Rank, value: T) -> Self {
        Self {
            locked: AtomicBool::new(false),
            owner: AtomicU32::new(NO_OWNER),
            rank,
            value: UnsafeCell::new(value),
        }
    }

    /// The CPU currently holding this lock, or `None` if it is free.
    ///
    /// **A snapshot, and only worth reading when the answer cannot change.**
    /// On a live lock the holder may release before this returns, so a caller
    /// that acts on it is racing. It is meant for the case where a lock has
    /// been observed stuck — there the value is as stable as the fault is, and
    /// it names the CPU to go and look at.
    ///
    /// Reports the CPU that *acquired* the lock, which before per-CPU areas
    /// are installed is `0` for everyone, since [`percpu::cpu_id`] has no
    /// better answer that early. Every caller so far runs long after that.
    #[must_use]
    pub fn owner(&self) -> Option<u32> {
        match self.owner.load(Ordering::Relaxed) {
            NO_OWNER => None,
            cpu => Some(cpu),
        }
    }

    /// The raw pointer to the protected value, for exactly one caller: the
    /// console's fatal path, which steals a lock a wedged machine may never
    /// release. Aliasing through this is a data race accepted with eyes
    /// open, and nothing on a healthy path may touch it.
    pub(crate) fn data_ptr(&self) -> *mut T {
        self.value.get()
    }

    /// Acquires the lock if it is free, without spinning.
    ///
    /// Exists for the page-fault path and for every other acquisition made
    /// from interrupt context. A fault can interrupt code that already holds
    /// this lock, and a fault handler that then spins for it would hang the
    /// machine with no diagnostic. Returning `None` lets the handler say what
    /// happened instead — a clear report of an unserviceable fault beats a
    /// silent lock-up every time.
    ///
    /// Exempt from rank checking, and does not record the acquisition: see the
    /// module header.
    ///
    /// **It does count towards [`holds_any`]**, which is a different
    /// question from ranking and was for a long time answered by accident. The
    /// order it takes is nothing; the lock it holds is real.
    #[track_caller]
    pub fn try_lock(&self) -> Option<SpinLockGuard<'_, T>> {
        // Counted *before* the attempt, and given back if it fails. After a
        // winning exchange there is a window -- however short -- in which this
        // CPU holds the lock and has not yet said so, and `preempt` reads that
        // as a thread holding nothing. `lock` has always claimed its rank
        // before it starts spinning, for the same reason; this is that rule
        // applied to the count. Over-claiming costs a skipped preemption.
        claim_uninterrupted(|| {
            holds_slot().fetch_add(1, Ordering::Relaxed);
        });
        let won = self
            .locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok();
        if !won {
            holds_slot().fetch_sub(1, Ordering::Relaxed);
            return None;
        }
        self.owner.store(percpu::cpu_id(), Ordering::Relaxed);
        let at = core::panic::Location::caller();
        record_lock_event(at, 255, true);
        let open_slot = open_guard(at, 255);
        Some(SpinLockGuard {
            lock: self,
            ranked: false,
            counted: true,
            at,
            open_slot,
        })
    }

    /// [`SpinLock::try_lock`] for the scheduler's own runqueue, during a
    /// switch, which must **not** count towards [`holds_any`].
    ///
    /// Everywhere else the count means "locks the running thread holds", and
    /// the switch saves it into that thread. This one is held by the CPU
    /// *performing* the switch rather than by either thread involved, so
    /// counting it records a lock against whichever thread happens to be going
    /// out — a phantom hold it never releases. Threads then accumulate holds
    /// they do not have, `holds_any` never falls back to false, preemption
    /// stops, and the machine wedges before its first scheduler test. That is
    /// not a hypothetical; it is what the first attempt at this did.
    ///
    /// Safe to leave uncounted because the two callers hold it only with
    /// interrupts masked, and release it before the switch itself.
    #[track_caller]
    pub fn try_lock_for_switch(&self) -> Option<SpinLockGuard<'_, T>> {
        self.locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .ok()
            .map(|_| {
                self.owner.store(percpu::cpu_id(), Ordering::Relaxed);
                SpinLockGuard {
                    lock: self,
                    ranked: false,
                    counted: false,
                    at: core::panic::Location::caller(),
                    open_slot: OPEN_GUARDS,
                }
            })
    }

    /// Acquires the lock, spinning until it is free.
    ///
    /// Checks the declared order first. The check happens *before* the spin,
    /// not after: once this blocks on a lock it should not have, the report
    /// would never be printed.
    ///
    /// `#[track_caller]` so a violation can name the line that caused it. It
    /// costs a `Location` argument on a path that already does a
    /// compare-exchange, and buys the one fact the report was missing.
    #[track_caller]
    pub fn lock(&self) -> SpinLockGuard<'_, T> {
        let held = held_mask();
        ACQUISITIONS.fetch_add(1, Ordering::Relaxed);
        if would_violate(held, self.rank) {
            record(held, self.rank, core::panic::Location::caller());
        }
        // **The count goes up before the rank bit, and the order is not
        // arbitrary.** `preempt` asks the count, and the mask is what a switch
        // saves into the outgoing thread. Set the mask first and there are two
        // instructions in which this CPU claims a rank while the count still
        // says it holds nothing — so a tick landing there switches the thread
        // out carrying a rank it has not even acquired yet, and on resume
        // `finish_switch` takes a runqueue lock against that phantom bit and
        // reports an ordering violation against blameless code.
        //
        // Measured, not reasoned: `ipc-cli-a` and `dom-a-0` were caught being
        // switched out holding masks they did not hold, once in thirty boots,
        // matching the false reports one for one.
        //
        // Both go up before the spin, so there is no instant in which the lock
        // is held and either says otherwise. Claiming while merely waiting
        // costs a skipped preemption.
        claim_uninterrupted(|| {
            holds_slot().fetch_add(1, Ordering::Relaxed);
            slot().fetch_or(self.rank.bit(), Ordering::Relaxed);
        });

        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            // Spin on a relaxed load rather than hammering the bus with
            // read-modify-write cycles: the exchange only retries once the
            // lock actually looks free.
            while self.locked.load(Ordering::Relaxed) {
                core::hint::spin_loop();
            }
        }
        self.owner.store(percpu::cpu_id(), Ordering::Relaxed);
        let at = core::panic::Location::caller();
        record_lock_event(at, self.rank as u8, true);
        let open_slot = open_guard(at, self.rank as u8);
        SpinLockGuard {
            lock: self,
            ranked: true,
            counted: true,
            at,
            open_slot,
        }
    }
}

/// Grants access to the value protected by a [`SpinLock`], and releases it on
/// drop.
pub struct SpinLockGuard<'a, T> {
    lock: &'a SpinLock<T>,
    /// Whether acquisition was recorded in the held set, and so must be
    /// cleared. False for `try_lock`, which does not participate.
    ranked: bool,
    /// Whether acquisition was counted towards [`holds_any`], and so must be
    /// given back. False only for [`SpinLock::try_lock_for_switch`].
    counted: bool,
    /// Where the acquisition happened, so the release event pairs with it in
    /// the per-CPU ledger — the instrument three hang captures asked for.
    at: &'static core::panic::Location<'static>,
    /// This guard's slot in the open-guards table, for O(1) close.
    open_slot: usize,
}

impl<T> Deref for SpinLockGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        // SAFETY: this guard exists, so the compare-exchange in `lock()`
        // succeeded and no other guard exists. The shared reference cannot
        // outlive the guard, so no aliasing mutable reference can be created
        // while it lives.
        unsafe { &*self.lock.value.get() }
    }
}

impl<T> DerefMut for SpinLockGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: as above, and `&mut self` means no shared reference derived
        // from this guard is live either.
        unsafe { &mut *self.lock.value.get() }
    }
}

impl<T> Drop for SpinLockGuard<'_, T> {
    fn drop(&mut self) {
        // Four steps whose order is the whole of two bugs. Each says why it is
        // where it is, because every plausible rearrangement of them is wrong.

        // **The rank bit goes first, before the release.** It answers "where in
        // the declared order is this CPU", and it must be exact: held one
        // instant past the release, the next acquisition of the same rank
        // looks like two at once and is reported as a violation against code
        // that did nothing. Clearing it late did exactly that, once in 700
        // boots -- `blocking on wait::WaitQueue while holding` the wait queue
        // bit, which is the release that had not finished being recorded.
        if self.ranked {
            slot().fetch_and(!self.lock.rank.bit(), Ordering::Relaxed);
        }

        // **The owner goes before the release too.** After it the lock is free,
        // another CPU may take it and record itself, and this store would
        // erase a live owner -- the lock reading unheld while somebody holds
        // it, wrong in the one case the field exists for.
        self.lock.owner.store(NO_OWNER, Ordering::Relaxed);

        if self.counted {
            record_lock_event(
                self.at,
                if self.ranked {
                    self.lock.rank as u8
                } else {
                    255
                },
                false,
            );
            close_guard(self.open_slot, self.at);
        }

        // Release ordering pairs with the Acquire in `lock`, so everything
        // written under the lock is visible to the next holder.
        self.lock.locked.store(false, Ordering::Release);

        // **The hold count goes last, after the release, and that is the other
        // bug.** It answers "is this CPU holding anything", which is what
        // `sched::preempt` asks before descheduling a thread. Given up before
        // the release -- as the rank bit used to be, doing both jobs at once --
        // there is a window where the lock is still held and the CPU reports
        // nothing, and a tick landing in it carries the holder away with
        // `locked` still set and nothing recorded as holding it. That is a
        // runqueue no CPU can ever acquire again: the `readable 0 of 20,
        // records no owner` dump.
        //
        // Late is the safe direction. For these few instructions the CPU
        // claims a lock it has already dropped, and the cost is one skipped
        // preemption.
        //
        // And the decrement refuses to wrap. The 2026-08-17 hunt convicted a
        // count at `u32::MAX` — an underflow — as the wedge behind three
        // failure families: a CPU whose count reads −1 vetoes every
        // preemption for ever. A release that finds the count already at
        // zero is that underflow *happening*, and this is the only place it
        // can be caught with the victim's name attached: the count lost a
        // matching increment somewhere earlier, and the guard being dropped
        // — acquired at the site printed — is the one paying for it. The
        // compare-exchange loop costs the same as `fetch_sub` when nothing
        // is wrong; saturating instead of wrapping turns a machine-wide
        // wedge into one loud line and a boot that can finish its report.
        if self.counted {
            let slot = holds_slot();
            let mut count = slot.load(Ordering::Relaxed);
            loop {
                if count == 0 {
                    COUNT_UNDERFLOWS.fetch_add(1, Ordering::Relaxed);
                    crate::println!(
                        "    COUNT UNDERFLOW  a release found this CPU's hold count already \
                         zero; the guard acquired at {}:{} is paying for an increment lost \
                         earlier (cpu {})",
                        self.at.file(),
                        self.at.line(),
                        percpu::cpu_id(),
                    );
                    dump_open_guards(percpu::cpu_id() as usize);
                    break;
                }
                match slot.compare_exchange_weak(
                    count,
                    count - 1,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => break,
                    Err(seen) => count = seen,
                }
            }
        }
    }
}

/// Releases that found the hold count already at zero — each one an
/// underflow caught in the act instead of a CPU wedged for ever.
static COUNT_UNDERFLOWS: AtomicU64 = AtomicU64::new(0);

/// How many hold-count underflows have been caught at release.
#[must_use]
pub fn count_underflows() -> u64 {
    COUNT_UNDERFLOWS.load(Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guards_provide_access_to_the_value() {
        let lock = SpinLock::new(Rank::Console, 41);
        *lock.lock() += 1;
        assert_eq!(*lock.lock(), 42);
    }

    #[test]
    fn lock_is_released_on_drop() {
        let lock = SpinLock::new(Rank::Console, ());
        drop(lock.lock());
        // Would spin forever if the guard had not released it.
        drop(lock.lock());
    }

    #[test]
    fn a_lock_is_never_held_while_the_cpu_claims_nothing() {
        // The stall this cost: release used to clear the held bookkeeping
        // before letting go, so a tick in between descheduled a thread that
        // still held the lock -- `preempt` having been told it held nothing.
        //
        // Checked at every point a switch could land, by observing both facts
        // together rather than trusting the order of the lines.
        set_held_mask(0);
        let lock = SpinLock::new(Rank::Console, ());

        let guard = lock.try_lock().expect("free");
        assert!(
            lock.locked.load(Ordering::Relaxed) && holds_any(),
            "held, and said to be held"
        );
        drop(guard);
        assert!(
            !lock.locked.load(Ordering::Relaxed) && !holds_any(),
            "free, and said to be free"
        );

        // The ranked path carries the same obligation.
        let guard = lock.lock();
        assert!(
            lock.locked.load(Ordering::Relaxed) && held_mask() != 0,
            "held, and said to be held"
        );
        drop(guard);
        assert!(!lock.locked.load(Ordering::Relaxed) && held_mask() == 0);
    }

    #[test]
    fn releasing_and_retaking_one_rank_is_not_a_violation() {
        // The regression the first attempt at the release order caused. Two
        // wait queues taken one after the other are ordinary; only *both at
        // once* is a violation. Clearing the rank bit after the release made
        // the second look like the second of two, and the soak reported it
        // against blameless code at one boot in 700.
        set_held_mask(0);
        reset_violations();
        let first = SpinLock::new(Rank::WaitQueue, ());
        let second = SpinLock::new(Rank::WaitQueue, ());
        drop(first.lock());
        drop(second.lock());
        assert_eq!(violations(), 0, "sequential, not nested");
    }

    #[test]
    fn holding_a_rank_still_blocks_preemption_after_its_bit_is_cleared() {
        // The other half: the bit goes early and the count goes late, so
        // between them the lock is held, the order says nothing, and the
        // thread still must not be moved.
        set_held_mask(0);
        let lock = SpinLock::new(Rank::Console, ());
        let guard = lock.lock();
        assert!(holds_any(), "held");
        drop(guard);
        assert!(!holds_any(), "and given up only once truly released");
    }

    #[test]
    fn try_lock_keeps_its_holder_on_the_cpu() {
        // The fix for the bring-up stall, as a property: `try_lock` takes no
        // rank -- it cannot be an edge in a deadlock cycle -- but it *is*
        // holding a lock, and `sched::preempt` must not deschedule its holder.
        set_held_mask(0);
        let lock = SpinLock::new(Rank::Console, ());
        assert!(!holds_any(), "nothing held to begin with");
        let guard = lock.try_lock().expect("free");
        assert_eq!(held_mask(), 0, "still takes no rank");
        assert!(holds_any(), "but is held, so its holder must not move");
        drop(guard);
        assert!(!holds_any(), "released");
    }

    #[test]
    fn unranked_holds_nest() {
        set_held_mask(0);
        let a = SpinLock::new(Rank::Console, ());
        let b = SpinLock::new(Rank::Heap, ());
        let first = a.try_lock().expect("free");
        let second = b.try_lock().expect("free");
        drop(second);
        assert!(holds_any(), "one is still held after the inner release");
        drop(first);
        assert!(!holds_any());
    }

    #[test]
    fn a_failed_try_lock_leaves_no_hold_behind() {
        // A losing attempt must not count, or a CPU that probed a busy lock
        // would refuse preemption for ever.
        set_held_mask(0);
        let lock = SpinLock::new(Rank::Console, ());
        let held = lock.try_lock().expect("free");
        assert!(lock.try_lock().is_none(), "already held");
        drop(held);
        assert!(!holds_any(), "the failed attempt counted nothing");
    }

    #[test]
    fn a_lock_records_its_holder_and_forgets_on_release() {
        let lock = SpinLock::new(Rank::Console, ());
        assert_eq!(lock.owner(), None, "a free lock has no owner");
        let guard = lock.lock();
        assert!(lock.owner().is_some(), "a held lock names its holder");
        drop(guard);
        assert_eq!(lock.owner(), None, "release clears the owner");
    }

    #[test]
    fn try_lock_records_its_holder_too() {
        // `try_lock` is exempt from *ranking*, which is a statement about
        // deadlock cycles. It is not exempt from holding the lock, and a
        // stuck `try_lock` holder is as worth naming as any other.
        let lock = SpinLock::new(Rank::Console, ());
        let guard = lock.try_lock().expect("free");
        assert!(lock.owner().is_some());
        drop(guard);
        assert_eq!(lock.owner(), None);
    }

    #[test]
    fn a_failed_try_lock_does_not_disturb_the_recorded_owner() {
        let lock = SpinLock::new(Rank::Console, ());
        let held = lock.lock();
        let owner = lock.owner().expect("held");
        assert!(lock.try_lock().is_none(), "already held");
        assert_eq!(
            lock.owner(),
            Some(owner),
            "a losing attempt records nothing"
        );
        drop(held);
    }

    #[test]
    fn an_empty_context_may_take_anything() {
        assert!(!would_violate(0, Rank::AddressSpace));
        assert!(!would_violate(0, Rank::Console));
    }

    #[test]
    fn acquiring_downwards_is_a_violation() {
        // Holding the heap and blocking on the address space lock is the
        // inversion of the order vm::unmap_range establishes.
        let held = Rank::Heap.bit();
        assert!(would_violate(held, Rank::AddressSpace));
    }

    #[test]
    fn acquiring_upwards_is_allowed() {
        let held = Rank::AddressSpace.bit();
        assert!(!would_violate(held, Rank::Heap));
        assert!(!would_violate(held, Rank::Console));
    }

    #[test]
    fn two_locks_of_the_same_rank_are_a_violation() {
        // Two runqueues have no declared order relative to each other, so
        // blocking on one while holding another can close a cycle. Stealing
        // takes the second with `try_lock` precisely because of this.
        let held = Rank::SchedRunqueue.bit();
        assert!(would_violate(held, Rank::SchedRunqueue));
    }

    #[test]
    fn the_whole_declared_order_is_legal_end_to_end() {
        // The order the kernel actually uses, walked in one pass.
        let order = [
            Rank::AddressSpace,
            Rank::AddressSpacePrevious,
            Rank::Heap,
            Rank::TlbSender,
            Rank::Timers,
            Rank::Domains,
            Rank::Capabilities,
            Rank::Endpoints,
            Rank::WaitQueue,
            Rank::SchedRunqueue,
            Rank::Console,
        ];
        let mut held = 0;
        for rank in order {
            assert!(!would_violate(held, rank), "{rank:?} rejected in order");
            held |= rank.bit();
        }
        // ...and every reverse step is rejected.
        let mut held = 0;
        for rank in order.into_iter().rev() {
            if held != 0 {
                assert!(would_violate(held, rank), "{rank:?} accepted out of order");
            }
            held |= rank.bit();
        }
    }

    #[test]
    fn releasing_out_of_order_leaves_the_set_correct() {
        // Guards are usually dropped last-in-first-out, but nothing enforces
        // it. A bitmask stays right either way; a stack would not.
        let outer = SpinLock::new(Rank::Heap, ());
        let inner = SpinLock::new(Rank::Console, ());
        set_held_mask(0);

        let a = outer.lock();
        let b = inner.lock();
        assert_eq!(held_mask(), Rank::Heap.bit() | Rank::Console.bit());

        drop(a); // the *outer* one first
        assert_eq!(held_mask(), Rank::Console.bit());
        drop(b);
        assert_eq!(held_mask(), 0);
    }

    #[test]
    fn try_lock_does_not_join_the_held_set() {
        let lock = SpinLock::new(Rank::Heap, ());
        set_held_mask(0);
        let guard = lock.try_lock().expect("free");
        assert_eq!(held_mask(), 0, "try_lock must not record");
        drop(guard);
        assert_eq!(held_mask(), 0);
    }
}
