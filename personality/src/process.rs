// SPDX-License-Identifier: Apache-2.0
//! What a hosted process **is**, as arithmetic.
//!
//! [RFC 0033](../../docs/rfc/0033-what-a-hosted-process-is.md): a Linux
//! process is a *record*, bound one-to-one to a Bhaskix domain. Identity —
//! pid, parent, group, session, credentials, descriptors — lives here, in
//! ring 3, because identity is a Linux concept. Isolation lives in the
//! domain, because isolation is the product.
//!
//! **Nothing in this module is authority, and that is the whole design.** A
//! pid is a number a program prints and compares. A uid is arithmetic for a
//! permission check the *adapter* performs, with capabilities the adapter
//! holds. The only fields that confer anything are handles — `cwd`, `root`,
//! and a descriptor's `handle` — and a handle here is a number this crate
//! cannot turn into a capability, has never seen a capability behind, and
//! could not invoke if it had. The same charter every module in this crate
//! keeps: the kernel calls in, a host test checks the answer.
//!
//! ## What this module is for
//!
//! Three things Linux specifies exactly and a translator gets subtly wrong:
//!
//! - **Which pid a process gets, and how long it keeps it.** A pid is *not*
//!   a domain id. `execve` must build a new domain — `START` refuses a
//!   domain that has threads — so a pid tied to a domain would change across
//!   an exec, and `wait`, `$!` and job control would all break on software
//!   that has depended on the opposite since 1971.
//! - **What survives an `execve`.** The list is short, it is not obvious, and
//!   every item on it is something a shell notices: the pid, the parent, the
//!   process group, the session, the credentials, the working directory, and
//!   every descriptor *without* `FD_CLOEXEC`. Signal handlers do not survive;
//!   the disposition resets to default, because the code the handler pointed
//!   at is gone.
//! - **How an exit status is encoded.** `wait` does not return a status; it
//!   returns a *word* with the status in one byte, the signal in another, and
//!   a core-dump bit between them. Every shell decodes it by hand.
//!
//! ## What this module deliberately is not
//!
//! It does not create domains, load images, resolve paths, or know what a
//! capability is. Those are the adapter's, and they are the half that cannot
//! be tested on a host — which is why the split is here.

use crate::file::Table;

/// Linux `errno` values this module returns, negated at the register.
pub mod errno {
    /// No such process.
    pub const ESRCH: i64 = -3;
    /// No child processes.
    pub const ECHILD: i64 = -10;
    /// Try again — the resource this needs is a fixed table that is full.
    pub const EAGAIN: i64 = -11;
    /// Invalid argument.
    pub const EINVAL: i64 = -22;
    /// Operation not permitted.
    pub const EPERM: i64 = -1;
}

/// How many hosted processes one adapter tracks at once.
///
/// **Thirty-two, and the number is a consequence rather than a choice.** A
/// hosted process is a domain (RFC 0033), the kernel's domain table holds
/// `MAX_DOMAINS` of them, and that is thirty-two — shared with every service
/// on the machine, so the real ceiling is lower still and is the machine's,
/// not this table's. Sized to match rather than to guess, and a full table is
/// `EAGAIN`, which is what Linux answers a `fork` it cannot serve.
pub const MAX_PROCESSES: usize = 32;

/// The first pid this personality hands out.
///
/// **Not 1, and not zero.** Zero is `wait`'s "any process in my group" and a
/// `kill` target meaning the whole group; 1 is `init`, which this system does
/// not have and should not pretend to be — a program that finds itself pid 1
/// may reasonably start reaping orphans and reading `/proc/1/`. Starting
/// above both means neither number is ever a hosted process, and a program
/// that special-cases them finds nothing to special-case.
pub const FIRST_PID: u32 = 2;

/// How many mapped regions one hosted process may have.
///
/// **Sixteen, and it is `fork` that made this table necessary.** Until step 8
/// the adapter answered `mmap` and forgot: the kernel held the mapping and
/// nothing needed a list. A fork has to *copy* an address space, and the only
/// thing that knows what is in one is whoever answered every `mmap` for it.
/// Sixteen is what a hand-written program and a small runtime both fit inside;
/// a seventeenth is `ENOMEM`, which is what Linux answers a mapping it cannot
/// make.
pub const MAX_REGIONS: usize = 16;

/// One mapped range of a hosted process's memory.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Region {
    /// Where it starts.
    pub at: u64,
    /// How many pages.
    pub pages: u64,
    /// The protection, in the kernel's own encoding — this crate does not
    /// interpret it, it carries it.
    pub protection: u64,
}

/// A hosted process's identity, and what it is entitled to keep.
#[derive(Clone, Copy, Debug)]
pub struct Process {
    /// What the program calls itself. Invented here; never a domain id.
    pub pid: u32,
    /// Its parent's pid, or zero once the parent has gone.
    pub ppid: u32,
    /// Its process group, for job control and for `kill(-pgid)`.
    pub pgid: u32,
    /// Its session.
    pub sid: u32,
    /// The Bhaskix domain this process *is*.
    pub domain: u32,
    /// That domain's generation when it was bound.
    ///
    /// **A domain id is reused.** Without the generation, a record outliving
    /// its domain by one creation would name somebody else's program — the
    /// same mistake the kernel's `FORGET` message exists to prevent, and the
    /// same one that once let a thread outlive its domain and decrement its
    /// successor's counter.
    pub generation: u32,
    /// Linux's credentials: numbers, for Linux's own arithmetic.
    pub credentials: Credentials,
    /// Where this process's next `mmap` lands.
    ///
    /// **Per process, and drawn rather than shared** — `security.md` §1 gap 3.
    /// It used to be one global bump allocator for every hosted process at
    /// once, which meant two things: every layout was fixed, and each process's
    /// addresses were predictable from any other's. A base per record fixes
    /// both, and [`layout::base_from`] is the arithmetic.
    ///
    /// Zero means "not drawn yet" and the adapter fills it at admission; a
    /// record that reached `mmap` with zero would allocate from the bottom of
    /// the address space, so the adapter refuses rather than guessing.
    pub mmap_next: u64,
    /// The adapter's handle for the directory this process resolves relative
    /// paths against.
    pub cwd: u64,
    /// The adapter's handle for what this process may call `/`.
    ///
    /// A hosted process's root is a directory capability the adapter holds,
    /// which is what `chroot` already means here — there is no ambient root
    /// to fall back to, deliberately (RFC 0016 deleted it).
    pub root: u64,
    /// Its open descriptors.
    pub descriptors: Table,
    /// What is mapped in its address space, so that a `fork` can copy it.
    pub regions: [Option<Region>; MAX_REGIONS],
    /// What it is doing.
    pub state: State,
}

/// Linux's credentials.
///
/// **Numbers, and RFC 0031's second thesis restated as a struct.** A hosted
/// process that becomes uid 0 has changed a number in ring 3 and gained
/// nothing: the adapter still performs every operation with the capability it
/// holds, and holds no more than it did. Linux `root` is not Bhaskix
/// authority, and this is where that stops being a slogan.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Credentials {
    /// Real user id.
    pub uid: u32,
    /// Effective user id — what a permission check reads.
    pub euid: u32,
    /// Real group id.
    pub gid: u32,
    /// Effective group id.
    pub egid: u32,
}

/// What a process is doing, from the point of view of whoever waits for it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum State {
    /// Running, or blocked in a call. The distinction is the scheduler's.
    Live,
    /// Ended, and not yet waited for.
    ///
    /// **A zombie is not an oversight; it is the exit status waiting to be
    /// collected.** The domain is gone — the kernel reclaimed it — and what
    /// remains is this record, holding a number its parent is entitled to
    /// read exactly once.
    Zombie(Exit),
}

/// How a process ended, before Linux's encoding is applied to it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Exit {
    /// It called `exit_group`, with this status. Only the low byte survives
    /// into `wait`'s word, which is Linux's rule and not a narrowing here.
    Status(u8),
    /// A signal ended it.
    Signalled {
        /// Which signal.
        signal: u8,
        /// Whether a core would have been dumped, had this system dumped
        /// cores. It does not; the bit is carried because `wait` macros read
        /// it and a shell prints "(core dumped)" from it.
        core: bool,
    },
}

impl Exit {
    /// Linux's `wait` status word.
    ///
    /// **This encoding is not a formality.** Every shell decodes it by hand:
    /// `WIFEXITED` is `(w & 0x7f) == 0`, `WEXITSTATUS` is `(w >> 8) & 0xff`,
    /// `WIFSIGNALED` is the low seven bits being neither zero nor `0x7f`, and
    /// `WCOREDUMP` is bit seven. A translator that returned the status
    /// unshifted would have every `$?` in every script read zero.
    #[must_use]
    pub const fn to_wait_status(self) -> u32 {
        match self {
            Self::Status(status) => (status as u32) << 8,
            Self::Signalled { signal, core } => {
                (signal as u32 & 0x7f) | if core { 0x80 } else { 0 }
            }
        }
    }
}

impl Process {
    /// A new process, in a domain, with nothing open.
    #[must_use]
    pub const fn new(pid: u32, ppid: u32, domain: u32, generation: u32) -> Self {
        Self {
            pid,
            ppid,
            // Its own group and session until something says otherwise,
            // which is what a process started by nobody in particular is.
            pgid: pid,
            sid: pid,
            domain,
            generation,
            credentials: Credentials {
                uid: 0,
                euid: 0,
                gid: 0,
                egid: 0,
            },
            // Filled by the adapter at admission, from a drawn number. Zero
            // here rather than the floor, so a record that never got one is
            // visible as a refusal instead of quietly using a fixed address.
            mmap_next: 0,
            cwd: 0,
            root: 0,
            descriptors: Table::new(),
            regions: [None; MAX_REGIONS],
            state: State::Live,
        }
    }

    /// Records a mapping this process now has.
    ///
    /// # Errors
    ///
    /// `ENOMEM` when the table is full, which is what Linux answers a mapping
    /// it cannot make.
    pub fn mapped(&mut self, region: Region) -> Result<(), i64> {
        let free = self
            .regions
            .iter()
            .position(Option::is_none)
            .ok_or(crate::memory::errno::ENOMEM)?;
        self.regions[free] = Some(region);
        Ok(())
    }

    /// Forgets a mapping, by its start address.
    ///
    /// **Whole regions only**, which is the same narrowing `mprotect` already
    /// carries: a partial unmap would split a region, and a list that could
    /// split is a list that needs merging too. A hosted program that unmaps
    /// part of a mapping is answered as though it unmapped none of it, and the
    /// address it named is what this looks for.
    pub fn unmapped(&mut self, at: u64) -> bool {
        let found = self
            .regions
            .iter()
            .position(|region| region.is_some_and(|region| region.at == at));
        match found {
            Some(index) => {
                self.regions[index] = None;
                true
            }
            None => false,
        }
    }

    /// Records that a mapping's protection has changed.
    ///
    /// **Whole regions only**, as [`Self::unmapped`]. Answers whether a region
    /// started there — a `mprotect` of something this list does not know about
    /// is not an error to the hosted program, it is a mapping the personality
    /// did not make.
    ///
    /// Without this a `fork` maps the child's copy with the protection the
    /// region was *created* with: a program that mapped a page writable, wrote
    /// code into it and made it executable would have a child whose copy is
    /// writable and not executable, and the child would fault on its first
    /// instruction. That is not hypothetical — it is what the fork probe did,
    /// at `rip 0x5000001b`.
    pub fn protected(&mut self, at: u64, protection: u64) -> bool {
        for region in self.regions.iter_mut().flatten() {
            if region.at == at {
                region.protection = protection;
                return true;
            }
        }
        false
    }

    /// How many pages this process has mapped, over every region.
    #[must_use]
    pub fn mapped_pages(&self) -> u64 {
        self.regions
            .iter()
            .flatten()
            .map(|region| region.pages)
            .sum()
    }

    /// Rewrites this record for a successful `execve`.
    ///
    /// **What survives is the list, and the list is the point.** The pid, the
    /// parent, the group, the session, the credentials, the working
    /// directory, the root, and every descriptor without `FD_CLOEXEC`. What
    /// does not survive is everything that named the old image: its memory,
    /// its threads, its signal *handlers* (the code they pointed at is gone,
    /// so the disposition resets to default), and its alternate signal stack.
    ///
    /// The new domain is an argument because building it is the adapter's
    /// work — this crate has no way to make one and no business knowing how.
    /// The old domain's teardown is likewise the adapter's; by the time this
    /// returns, the record names the new one.
    ///
    /// Signal dispositions are *not* a field of this record yet: they live in
    /// `bin/linuxd`'s own table, keyed by domain, and moving them in here is
    /// a later step. This function is where their reset belongs when they
    /// arrive, and the comment is here so that it is not forgotten — a
    /// handler surviving an exec would call an address that is no longer
    /// code.
    /// `released` is handed every descriptor the exec closes, because each
    /// carried a handle the adapter holds a capability behind and this crate
    /// cannot release one.
    pub fn exec_into(
        &mut self,
        domain: u32,
        generation: u32,
        base: u64,
        released: impl FnMut(crate::file::Entry),
    ) -> usize {
        // **A new image gets a new layout**, which is where Linux randomises
        // too: `fork` copies and must not move anything, `execve` replaces and
        // is the moment a fresh draw costs nothing. Without this, a program
        // that learned its parent's layout — by crashing it, by reading
        // `/proc/self/maps`, by any of the ways a local attacker learns an
        // address — would keep that knowledge across the exec that was supposed
        // to be a new program.
        self.mmap_next = base;
        self.domain = domain;
        self.generation = generation;
        // **The old image's memory is not the new one's.** An exec replaces the
        // address space, so a region list carried across it would describe
        // mappings that no longer exist — and the first `fork` after an `exec`
        // would copy them.
        self.regions = [None; MAX_REGIONS];
        self.descriptors.close_on_exec(released)
    }

    /// The child of a `fork`: a copy, with a new identity and a new domain.
    ///
    /// **The descriptor table is copied and the handles are shared**, which
    /// is Linux's rule: a forked child's descriptor 1 refers to the *same*
    /// open file, including its offset, and two processes writing to an
    /// inherited descriptor interleave rather than overwrite. What that means
    /// for the adapter is that the child's rows name the same capability, and
    /// that a narrower right — when one is wanted — is a *derivation*, so
    /// revoking the parent's takes the child's with it.
    #[must_use]
    pub fn fork_into(&self, pid: u32, domain: u32, generation: u32) -> Self {
        Self {
            pid,
            ppid: self.pid,
            pgid: self.pgid,
            sid: self.sid,
            // **The child inherits the parent's layout, deliberately.** `fork`
            // copies an address space, so a child whose `mmap` base differed
            // from its parent's would be a copy that is not a copy: a pointer
            // the parent computed before forking would name nothing in the
            // child. Linux re-randomises at `execve`, not at `fork`, and so
            // does this — see `exec_into`.
            mmap_next: self.mmap_next,
            domain,
            generation,
            credentials: self.credentials,
            cwd: self.cwd,
            root: self.root,
            descriptors: self.descriptors,
            // **The child's map is the parent's**, which is what makes a fork
            // a copy rather than a fresh start: the same addresses, the same
            // protections, and — once the adapter has copied the bytes — the
            // same contents.
            regions: self.regions,
            state: State::Live,
        }
    }
}

/// Every hosted process this adapter knows about.
///
/// Fixed, because this crate does not allocate. The table is the adapter's;
/// this type is the arithmetic over it, so that the parts that are easy to
/// get wrong — pid allocation, reparenting, reaping — are host-tested rather
/// than discovered in QEMU.
///
/// **Deliberately not `Copy`, unlike everything else in this crate.** A
/// descriptor table is two kilobytes and a process carries one, so this is
/// tens of kilobytes; a `Copy` on it would let a stray `let mine = *table`
/// compile into a memcpy of the whole thing on a system whose kernel stack is
/// sixty-four kilobytes. The adapter holds exactly one and reaches it by
/// reference. The size is asserted below rather than described.
#[derive(Debug)]
pub struct Processes {
    slots: [Option<Process>; MAX_PROCESSES],
    /// The next pid to hand out. Monotonic within a boot.
    next: u32,
}

impl Default for Processes {
    fn default() -> Self {
        Self::new()
    }
}

impl Processes {
    /// An empty table.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            slots: [None; MAX_PROCESSES],
            next: FIRST_PID,
        }
    }

    /// Admits a process in `domain`, with `parent` as its parent pid.
    ///
    /// **Pids are never reused within a boot**, and that is a decision rather
    /// than an implementation detail: a reused pid is a `kill` delivered to
    /// whoever inherited the number, which is the oldest race in Unix. Linux
    /// reuses them because it wraps at `pid_max` after tens of thousands;
    /// this hands out a fresh one until the counter itself would wrap, and
    /// then refuses. A machine that has started four billion hosted processes
    /// can be rebooted.
    ///
    /// # Errors
    ///
    /// [`errno::EAGAIN`] when the table is full or the counter is exhausted —
    /// the answer Linux gives a `fork` it cannot serve, so a program that
    /// handles one handles this.
    pub fn admit(&mut self, parent: u32, domain: u32, generation: u32) -> Result<u32, i64> {
        let free = self
            .slots
            .iter()
            .position(Option::is_none)
            .ok_or(errno::EAGAIN)?;
        let pid = self.next;
        self.next = self.next.checked_add(1).ok_or(errno::EAGAIN)?;
        self.slots[free] = Some(Process::new(pid, parent, domain, generation));
        Ok(pid)
    }

    /// The process with this pid, if it is one this adapter serves.
    #[must_use]
    pub fn by_pid(&self, pid: u32) -> Option<&Process> {
        self.slots.iter().flatten().find(|p| p.pid == pid)
    }

    /// As [`Self::by_pid`], for changing it.
    pub fn by_pid_mut(&mut self, pid: u32) -> Option<&mut Process> {
        self.slots.iter_mut().flatten().find(|p| p.pid == pid)
    }

    /// The **live** process bound to this domain incarnation.
    ///
    /// Both halves are required, and the generation is the half that is easy
    /// to leave out: a domain id is reused, and a record found by id alone
    /// would answer for whoever holds the slot now. A zombie is also excluded
    /// — its domain is gone, so a domain id matching one is a coincidence,
    /// not an identity.
    #[must_use]
    pub fn by_domain(&self, domain: u32, generation: u32) -> Option<&Process> {
        self.slots
            .iter()
            .flatten()
            .find(|p| p.domain == domain && p.generation == generation && p.state == State::Live)
    }

    /// As [`Self::by_domain`], for changing it.
    pub fn by_domain_mut(&mut self, domain: u32, generation: u32) -> Option<&mut Process> {
        self.slots
            .iter_mut()
            .flatten()
            .find(|p| p.domain == domain && p.generation == generation && p.state == State::Live)
    }

    /// Records that a process has ended, and leaves it for its parent.
    ///
    /// The record becomes a zombie rather than disappearing, because the exit
    /// status belongs to the parent and nothing else knows it. Its children
    /// are reparented in the same step — see [`Self::reparent_children_of`]
    /// — because a child whose parent is a zombie has nobody to wait for it.
    ///
    /// # Errors
    ///
    /// [`errno::ESRCH`] if no live process has that pid.
    pub fn ended(&mut self, pid: u32, exit: Exit) -> Result<(), i64> {
        let process = self.by_pid_mut(pid).ok_or(errno::ESRCH)?;
        if process.state != State::Live {
            return Err(errno::ESRCH);
        }
        process.state = State::Zombie(exit);
        self.reparent_children_of(pid);
        Ok(())
    }

    /// Gives every child of `pid` to nobody, by setting its parent to zero.
    ///
    /// **Linux gives orphans to `init`; this system has no `init`, and
    /// inventing one to receive them would be a process that exists only to
    /// make a lie true.** A parent of zero means "nobody is waiting for
    /// this", and the adapter reaps such a process the moment it ends rather
    /// than keeping a status no one will read. Stated here because the
    /// alternative — a zombie nothing collects — is a leak with a Unix
    /// pedigree.
    pub fn reparent_children_of(&mut self, pid: u32) {
        for child in self.slots.iter_mut().flatten() {
            if child.ppid == pid {
                child.ppid = 0;
            }
        }
    }

    /// Collects a dead child's status, as `wait4` does.
    ///
    /// `pid` is the child asked for, or `WAIT_ANY` for "any of mine". Answers
    /// the child's pid and its status word, and **removes the record**: a
    /// status is collected exactly once, which is what makes a second `wait`
    /// return `ECHILD` rather than the same child twice.
    ///
    /// # Errors
    ///
    /// [`errno::ECHILD`] when the caller has no such child — including when
    /// it has no children at all, which is the same answer Linux gives.
    /// [`WouldBlock`](WaitOutcome::WouldBlock) is *not* an error: a caller
    /// with living children and nothing to collect must be told to wait, and
    /// telling it `ECHILD` would make every shell think its job had finished.
    pub fn collect(&mut self, parent: u32, pid: WaitFor) -> Result<WaitOutcome, i64> {
        let mut had_child = false;
        let mut found = None;
        for (index, slot) in self.slots.iter().enumerate() {
            let Some(child) = slot else { continue };
            if child.ppid != parent {
                continue;
            }
            let wanted = match pid {
                WaitFor::Any => true,
                WaitFor::Pid(pid) => child.pid == pid,
                WaitFor::Group(pgid) => child.pgid == pgid,
            };
            if !wanted {
                continue;
            }
            had_child = true;
            if let State::Zombie(exit) = child.state {
                found = Some((index, child.pid, exit));
                break;
            }
        }
        match found {
            Some((index, pid, exit)) => {
                self.slots[index] = None;
                Ok(WaitOutcome::Collected {
                    pid,
                    status: exit.to_wait_status(),
                })
            }
            None if had_child => Ok(WaitOutcome::WouldBlock),
            None => Err(errno::ECHILD),
        }
    }

    /// Drops a record whose status nobody will ever read.
    ///
    /// For a process whose parent is gone: there is no `init` to inherit it,
    /// so the adapter reaps it itself rather than holding a slot for a reader
    /// that does not exist.
    ///
    /// # Errors
    ///
    /// [`errno::EPERM`] if the process still has a parent — a status that
    /// belongs to somebody must not be thrown away.
    pub fn discard(&mut self, pid: u32) -> Result<(), i64> {
        let index = self
            .slots
            .iter()
            .position(|slot| slot.is_some_and(|p| p.pid == pid))
            .ok_or(errno::ESRCH)?;
        let process = self.slots[index].ok_or(errno::ESRCH)?;
        if process.ppid != 0 {
            return Err(errno::EPERM);
        }
        self.slots[index] = None;
        Ok(())
    }

    /// How many records are held, live and zombie together.
    #[must_use]
    pub fn count(&self) -> usize {
        self.slots.iter().flatten().count()
    }
}

/// Which child a `wait4` is asking for.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WaitFor {
    /// Any child of the caller — Linux's `-1`.
    Any,
    /// One named child.
    Pid(u32),
    /// Any child in a process group — Linux's negative pid.
    Group(u32),
}

impl WaitFor {
    /// Decodes `wait4`'s first argument, which packs three questions into one
    /// signed integer.
    ///
    /// **`0` is not "any", and the difference bites.** Linux reads `-1` as
    /// any child, a positive number as that child, `0` as any child in the
    /// caller's *own* group, and any other negative number as the group named
    /// by its absolute value. A translator that treated zero as "any" would
    /// answer a shell's group wait with the wrong child.
    #[must_use]
    pub const fn from_argument(argument: i64, caller_group: u32) -> Self {
        if argument == -1 {
            Self::Any
        } else if argument == 0 {
            Self::Group(caller_group)
        } else if argument < 0 {
            Self::Group(argument.unsigned_abs() as u32)
        } else {
            Self::Pid(argument as u32)
        }
    }
}

/// What a `wait4` found.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WaitOutcome {
    /// A child had ended; here is its pid and Linux's status word.
    Collected {
        /// Which child.
        pid: u32,
        /// The word `wait`'s macros decode.
        status: u32,
    },
    /// The caller has children, and none has ended. A blocking `wait` sleeps
    /// here; `WNOHANG` answers zero.
    WouldBlock,
}

/// The table's size, bounded rather than discovered.
///
/// A `Process` carries a whole descriptor table, so this type is measured in
/// tens of kilobytes and the adapter must hold it in `static` storage. The
/// bound is a build failure, so that a field added to `Process` — or a raised
/// `MAX_DESCRIPTORS` — is priced when it is written rather than when a kernel
/// stack overflows.
const _: () = {
    assert!(core::mem::size_of::<Processes>() <= 128 * 1024);
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file::{Entry, Kind};

    fn table_with(close_on_exec: bool) -> Table {
        let mut table = Table::new();
        table.install_standard(7);
        table
            .insert(
                Entry {
                    handle: 42,
                    inode: 7,
                    kind: Kind::File,
                    close_on_exec,
                    offset: 0,
                    size: 0,
                    readable: true,
                    writable: false,
                },
                0,
            )
            .expect("a fresh table has room");
        table
    }

    #[test]
    fn a_pid_is_never_a_domain_id_and_never_reused() {
        let mut table = Processes::new();
        let first = table.admit(0, 3, 1).expect("room");
        let second = table.admit(first, 4, 1).expect("room");
        assert_ne!(first, second);
        assert!(first >= FIRST_PID, "0 is wait's own, 1 is init's");
        // Ending and collecting the first must not let its number come back.
        table.ended(first, Exit::Status(0)).expect("it was live");
        // Its parent is nobody, so it is discarded rather than collected.
        table.discard(first).expect("nobody is waiting for it");
        let third = table.admit(second, 3, 2).expect("room");
        assert_ne!(
            third, first,
            "a reused pid is a kill delivered to a stranger"
        );
        assert_ne!(third, second);
    }

    #[test]
    fn a_record_is_found_by_domain_only_with_the_generation_that_bound_it() {
        let mut table = Processes::new();
        let pid = table.admit(0, 5, 1).expect("room");
        assert_eq!(table.by_domain(5, 1).map(|p| p.pid), Some(pid));
        assert_eq!(
            table.by_domain(5, 2).map(|p| p.pid),
            None,
            "a reused domain slot is not this process"
        );
    }

    #[test]
    fn exec_keeps_the_identity_and_closes_what_asked_to_be_closed() {
        let mut process = Process::new(9, 2, 3, 1);
        process.pgid = 4;
        process.sid = 5;
        process.cwd = 0xbeef;
        process.credentials.uid = 1000;
        process.descriptors = table_with(true);
        assert_eq!(process.descriptors.open_count(), 4);

        let closed = process.exec_into(11, 2, layout::base_from(99), |_| {});
        assert_eq!(closed, 1, "the exec must say what it closed");

        assert_eq!(
            process.pid, 9,
            "a pid survives an exec or every shell breaks"
        );
        assert_eq!(process.ppid, 2);
        assert_eq!(process.pgid, 4);
        assert_eq!(process.sid, 5);
        assert_eq!(process.cwd, 0xbeef);
        assert_eq!(process.credentials.uid, 1000);
        assert_eq!(process.domain, 11, "the domain is the thing that changed");
        assert_eq!(process.generation, 2);
        assert_eq!(
            process.descriptors.open_count(),
            3,
            "the CLOEXEC descriptor is gone and the three standard ones are not"
        );
    }

    #[test]
    fn a_descriptor_without_cloexec_crosses_an_exec() {
        let mut process = Process::new(9, 2, 3, 1);
        process.descriptors = table_with(false);
        let mut released = 0;
        process.exec_into(11, 2, layout::base_from(7), |_| released += 1);
        assert_eq!(released, 0);
        assert_eq!(process.descriptors.open_count(), 4);
        assert_eq!(process.descriptors.get(3).map(|e| e.handle), Some(42));
    }

    #[test]
    fn a_forked_child_inherits_the_map_it_will_be_given_copies_of() {
        let mut parent = Process::new(9, 2, 3, 1);
        parent
            .mapped(Region {
                at: 0x1000,
                pages: 2,
                protection: 2,
            })
            .expect("room");
        parent
            .mapped(Region {
                at: 0x8000,
                pages: 1,
                protection: 3,
            })
            .expect("room");
        assert_eq!(parent.mapped_pages(), 3);

        let child = parent.fork_into(10, 4, 1);
        assert_eq!(child.regions, parent.regions, "the same map, page for page");
        assert_eq!(child.mapped_pages(), 3);
    }

    #[test]
    fn an_exec_forgets_the_map_because_the_memory_is_gone() {
        let mut process = Process::new(9, 2, 3, 1);
        process
            .mapped(Region {
                at: 0x1000,
                pages: 4,
                protection: 2,
            })
            .expect("room");
        process.exec_into(11, 2, layout::base_from(1), |_| {});
        assert_eq!(
            process.mapped_pages(),
            0,
            "a fork after an exec would copy mappings that no longer exist"
        );
    }

    #[test]
    fn a_protection_change_follows_the_region_a_fork_will_copy() {
        let mut process = Process::new(9, 2, 3, 1);
        process
            .mapped(Region {
                at: 0x5000,
                pages: 1,
                protection: 2,
            })
            .expect("room");
        assert!(process.protected(0x5000, 3));
        assert_eq!(process.regions[0].expect("there").protection, 3);
        assert!(
            !process.protected(0x6000, 3),
            "a region this list does not know about is not one to change"
        );
    }

    #[test]
    fn unmapping_names_the_region_by_where_it_starts() {
        let mut process = Process::new(9, 2, 3, 1);
        for at in [0x1000, 0x2000] {
            process
                .mapped(Region {
                    at,
                    pages: 1,
                    protection: 2,
                })
                .expect("room");
        }
        assert!(process.unmapped(0x1000));
        assert!(!process.unmapped(0x1000), "twice is not a region");
        assert!(!process.unmapped(0x1800), "the middle of one is not one");
        assert_eq!(process.mapped_pages(), 1);
    }

    #[test]
    fn a_full_region_table_is_enomem_and_not_a_panic() {
        let mut process = Process::new(9, 2, 3, 1);
        for index in 0..MAX_REGIONS {
            process
                .mapped(Region {
                    at: 0x1000 * (index as u64 + 1),
                    pages: 1,
                    protection: 2,
                })
                .expect("room");
        }
        assert_eq!(
            process.mapped(Region {
                at: 0x9_0000,
                pages: 1,
                protection: 2
            }),
            Err(crate::memory::errno::ENOMEM)
        );
    }

    #[test]
    fn a_forked_child_shares_its_parents_open_files() {
        let mut parent = Process::new(9, 2, 3, 1);
        parent.descriptors = table_with(false);
        parent.cwd = 0x1234;
        let child = parent.fork_into(10, 4, 1);

        assert_eq!(child.ppid, 9);
        assert_eq!(child.pgid, parent.pgid, "a fork does not leave the group");
        assert_eq!(child.sid, parent.sid);
        assert_eq!(child.cwd, 0x1234);
        assert_eq!(
            child.descriptors.get(3).map(|e| e.handle),
            parent.descriptors.get(3).map(|e| e.handle),
            "an inherited descriptor names the same open file"
        );
    }

    #[test]
    fn an_exit_status_is_encoded_the_way_a_shell_decodes_it() {
        // WIFEXITED, WEXITSTATUS.
        let word = Exit::Status(3).to_wait_status();
        assert_eq!(word & 0x7f, 0, "the low bits say it was not a signal");
        assert_eq!((word >> 8) & 0xff, 3);
        // WIFSIGNALED, WTERMSIG, WCOREDUMP.
        let word = Exit::Signalled {
            signal: 11,
            core: true,
        }
        .to_wait_status();
        assert_eq!(word & 0x7f, 11);
        assert_ne!(word & 0x7f, 0);
        assert_eq!(word & 0x80, 0x80);
        assert_eq!((word >> 8) & 0xff, 0);
    }

    #[test]
    fn a_status_is_collected_exactly_once() {
        let mut table = Processes::new();
        let parent = table.admit(0, 1, 1).expect("room");
        let child = table.admit(parent, 2, 1).expect("room");
        assert_eq!(
            table.collect(parent, WaitFor::Any),
            Ok(WaitOutcome::WouldBlock),
            "a living child is not ECHILD"
        );
        table.ended(child, Exit::Status(7)).expect("it was live");
        assert_eq!(
            table.collect(parent, WaitFor::Any),
            Ok(WaitOutcome::Collected {
                pid: child,
                status: 7 << 8
            })
        );
        assert_eq!(
            table.collect(parent, WaitFor::Any),
            Err(errno::ECHILD),
            "the second wait must not find the same child again"
        );
    }

    #[test]
    fn waiting_for_a_child_that_is_not_ours_is_echild() {
        let mut table = Processes::new();
        let parent = table.admit(0, 1, 1).expect("room");
        let other = table.admit(0, 2, 1).expect("room");
        let theirs = table.admit(other, 3, 1).expect("room");
        table.ended(theirs, Exit::Status(0)).expect("it was live");
        assert_eq!(table.collect(parent, WaitFor::Any), Err(errno::ECHILD));
        assert_eq!(
            table.collect(parent, WaitFor::Pid(theirs)),
            Err(errno::ECHILD)
        );
    }

    #[test]
    fn waiting_for_a_group_answers_only_that_group() {
        let mut table = Processes::new();
        let parent = table.admit(0, 1, 1).expect("room");
        let first = table.admit(parent, 2, 1).expect("room");
        let second = table.admit(parent, 3, 1).expect("room");
        table.by_pid_mut(second).expect("it is there").pgid = 99;
        table.ended(first, Exit::Status(1)).expect("live");
        table.ended(second, Exit::Status(2)).expect("live");

        assert_eq!(
            table.collect(parent, WaitFor::Group(99)),
            Ok(WaitOutcome::Collected {
                pid: second,
                status: 2 << 8
            })
        );
    }

    #[test]
    fn waits_first_argument_packs_three_questions() {
        assert_eq!(WaitFor::from_argument(-1, 7), WaitFor::Any);
        assert_eq!(WaitFor::from_argument(0, 7), WaitFor::Group(7));
        assert_eq!(WaitFor::from_argument(-42, 7), WaitFor::Group(42));
        assert_eq!(WaitFor::from_argument(42, 7), WaitFor::Pid(42));
    }

    #[test]
    fn an_orphans_parent_becomes_nobody_and_it_can_be_discarded() {
        let mut table = Processes::new();
        let parent = table.admit(0, 1, 1).expect("room");
        let child = table.admit(parent, 2, 1).expect("room");
        table.ended(parent, Exit::Status(0)).expect("live");
        assert_eq!(table.by_pid(child).map(|p| p.ppid), Some(0));

        // The parent itself has no parent, so nothing will ever read its
        // status and the adapter may drop it.
        table.discard(parent).expect("nobody is waiting");
        assert_eq!(table.by_pid(parent).map(|p| p.pid), None);

        // The child still has a status somebody might have wanted -- but its
        // parent is gone, so it too may be dropped once it ends.
        table.ended(child, Exit::Status(0)).expect("live");
        table.discard(child).expect("its parent is gone");
        assert_eq!(table.count(), 0);
    }

    #[test]
    fn a_live_process_cannot_be_discarded_out_from_under_its_parent() {
        let mut table = Processes::new();
        let parent = table.admit(0, 1, 1).expect("room");
        let child = table.admit(parent, 2, 1).expect("room");
        table.ended(child, Exit::Status(0)).expect("live");
        assert_eq!(
            table.discard(child),
            Err(errno::EPERM),
            "its parent is entitled to that status"
        );
    }

    #[test]
    fn the_table_costs_what_the_bound_says_and_the_number_is_written_down() {
        // Not a limit test -- a *statement*. A reader deciding where this
        // lives needs the number, and a reviewer needs it to move visibly.
        let bytes = core::mem::size_of::<Processes>();
        assert!(
            bytes > 32 * 1024,
            "if this got small, a descriptor table stopped being carried: {bytes}"
        );
        assert!(
            bytes <= 128 * 1024,
            "{bytes} bytes is a static, not a stack"
        );
    }

    #[test]
    fn a_full_table_is_eagain_and_not_a_panic() {
        let mut table = Processes::new();
        for _ in 0..MAX_PROCESSES {
            table.admit(0, 1, 1).expect("room");
        }
        assert_eq!(table.admit(0, 1, 1), Err(errno::EAGAIN));
    }

    #[test]
    fn ending_a_process_twice_is_refused() {
        let mut table = Processes::new();
        let pid = table.admit(0, 1, 1).expect("room");
        table.ended(pid, Exit::Status(0)).expect("live");
        assert_eq!(table.ended(pid, Exit::Status(0)), Err(errno::ESRCH));
    }
}

/// Where a hosted process's `mmap` allocations begin.
///
/// [security.md](../../docs/security.md) §1 gap 3, and the half of it that is
/// this personality's to fix.
///
/// # Why a hosted process gets this and a Bhaskix program does not
///
/// Bhaskix's own services are Rust and their per-program bases are **fixed on
/// purpose**: they were all at one address until 2026-08-13, which made a
/// debugger useless because a fault `rip` meant eight different instructions.
/// That decision stands. The software arriving under L1–L4 is C, and a hosted
/// process at a wholly predictable layout turns any bug in BusyBox or `curl`
/// into a reliable exploit rather than a crash. The domain still contains it —
/// but containment is the claim this project sells, and cheap exploitation of
/// the contained thing weakens the sale.
///
/// # What this randomises, and what it cannot
///
/// **The `mmap` region only.** The image itself is where its ELF says: the
/// loader refuses `ET_DYN`, deliberately, to keep relocation processing out of
/// the program loader, so a static non-PIE binary has one possible base and no
/// amount of policy here changes that. Randomising the image needs `ET_DYN`
/// accepted in ring 3, which is a separate decision with its own fuzz
/// obligation and belongs in an RFC rather than in this function.
///
/// So this is **partial** ASLR, and saying which part is the point: the heap
/// and every shared mapping move; the text does not.
pub mod layout {
    /// The lowest address `mmap` may return.
    ///
    /// The same base the nucleus used before RFC 0032 moved the personality
    /// out, so a hosted program that reads `/proc/self/maps` sees the region it
    /// always saw, one window further along.
    pub const MMAP_FLOOR: u64 = 0x0000_7000_0000_0000;

    /// How many bits of the base are drawn.
    ///
    /// **Twenty-eight, page-granular**, which is what Linux gives `mmap` on
    /// `x86_64` and is a 1 TiB window — comfortably inside the 47-bit user half
    /// this kernel's four-level paging provides
    /// ([RFC 0025](../../docs/rfc/0025-four-level-paging-on-purpose.md)), and
    /// comfortably above the fixed addresses the adapter maps into a hosted
    /// domain for `execve` and `fork`.
    ///
    /// Stated as a number because "randomised" without a bit count is a claim
    /// nobody can check. Twenty-eight bits is not a defence against an attacker
    /// who can retry — nothing at this layer is — it is a defence against one
    /// who gets a single attempt at a fixed address.
    pub const BITS: u32 = 28;

    /// Page size, in bytes.
    const PAGE: u64 = 4096;

    /// The base a hosted process should use, given one drawn number.
    ///
    /// Page-aligned, inside the window, and a pure function of the draw — which
    /// is what lets the whole of this be tested on the host with no machine and
    /// no entropy source anywhere near it.
    #[must_use]
    pub const fn base_from(draw: u64) -> u64 {
        let slots = 1u64 << BITS;
        MMAP_FLOOR + (draw % slots) * PAGE
    }

    /// The highest base [`base_from`] can return.
    #[must_use]
    pub const fn ceiling() -> u64 {
        MMAP_FLOOR + ((1u64 << BITS) - 1) * PAGE
    }
}

#[cfg(test)]
mod aslr_tests {
    use super::{Process, layout};

    #[test]
    fn a_forked_child_keeps_its_parent_layout_and_an_exec_replaces_it() {
        let mut parent = Process::new(2, 1, 5, 1);
        parent.mmap_next = layout::base_from(0x1111);

        // `fork` copies an address space, so the child must land where the
        // parent's pointers already point. A child that moved would be a copy
        // that is not a copy.
        let child = parent.fork_into(3, 6, 1);
        assert_eq!(child.mmap_next, parent.mmap_next, "fork moved the layout");

        // `execve` replaces the image, and that is the moment to redraw --
        // otherwise an address learned from the old program survives into the
        // new one, which is the whole thing this defends against.
        let mut after = child;
        let fresh = layout::base_from(0x2222);
        after.exec_into(7, 2, fresh, |_| {});
        assert_eq!(after.mmap_next, fresh, "exec kept the old layout");
        assert_ne!(after.mmap_next, parent.mmap_next, "exec did not move it");
    }

    #[test]
    fn a_record_that_was_never_given_a_base_is_visibly_unset() {
        // Zero rather than the floor, so an adapter that forgot to draw one is
        // a refusal the next `mmap` can see instead of a silent fixed address.
        let fresh = Process::new(2, 1, 5, 1);
        assert_eq!(fresh.mmap_next, 0);
        assert!(layout::base_from(0) > 0, "the floor is never zero");
    }
}

#[cfg(test)]
mod layout_tests {
    use super::layout;

    #[test]
    fn every_base_is_page_aligned_and_inside_the_window() {
        for draw in [0, 1, 4095, 4096, u64::MAX, u64::MAX / 3, 0x5eed_face] {
            let base = layout::base_from(draw);
            assert_eq!(base % 4096, 0, "draw {draw:#x} gave an unaligned base");
            assert!(
                base >= layout::MMAP_FLOOR,
                "draw {draw:#x} fell below the floor"
            );
            assert!(
                base <= layout::ceiling(),
                "draw {draw:#x} rose above the ceiling"
            );
        }
    }

    #[test]
    fn the_window_is_the_stated_size() {
        // A bit count that does not match the window it produces is the kind
        // of claim this comment exists to stop.
        assert_eq!(
            layout::ceiling() - layout::MMAP_FLOOR,
            ((1u64 << 28) - 1) * 4096
        );
        assert_eq!(layout::BITS, 28);
    }

    #[test]
    fn different_draws_give_different_bases() {
        // Not a randomness test -- it cannot be one, since `base_from` is a
        // pure function. It is the mapping being injective enough to carry the
        // entropy it is given, which is the part that would break silently if
        // somebody "simplified" the arithmetic.
        let mut seen = alloc_free_set();
        for draw in 0..1000u64 {
            let base = layout::base_from(draw * 7 + 3);
            assert!(seen.insert(base), "two draws collided at {base:#x}");
        }
    }

    /// A tiny set, because this crate is `no_std` and its tests run on the host
    /// without pulling `std` collections into the shipping build.
    fn alloc_free_set() -> std::collections::BTreeSet<u64> {
        std::collections::BTreeSet::new()
    }
}
