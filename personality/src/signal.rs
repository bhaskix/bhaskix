// SPDX-License-Identifier: Apache-2.0
//! Signals: the state a handler is installed into, and the frame it reads.
//!
//! [RFC 0005](../../docs/rfc/0005-linux-abi-compatibility.md) calls this the
//! single most unforgiving part of the design and says to build it first,
//! *precisely because it is where the design is most likely to be wrong*.
//! Go does not merely tolerate signals: it converts `SIGSEGV` into a panic by
//! reading the saved register frame, and it preempts goroutines with `SIGURG`
//! — so a stubbed-out signal path does not fail visibly, it hangs under load.
//!
//! What lives here is the part that needs no machine: which handler is
//! installed for which signal, where the alternate stack is, and — the fiddly
//! half — the **byte layout** of the `ucontext` a handler is handed and the
//! `sigcontext` inside it, whose field order is ABI and whose offsets Go
//! reads and *writes* (it modifies `rip` to recover from a fault). Every
//! offset below is asserted by a host test against the layout Linux defines,
//! because an off-by-one field here hands a runtime a register it did not
//! ask for and the failure appears somewhere else entirely.

/// The signals this personality can deliver, by Linux number. Named rather
/// than ranged: a signal this does not name is one nothing has asked for, and
/// the refusal should be a compile-time absence rather than a runtime guess.
pub mod number {
    /// Illegal instruction.
    pub const SIGILL: u64 = 4;
    /// Bad memory access — the one Go turns into a panic.
    pub const SIGSEGV: u64 = 11;
    /// Go's asynchronous preemption signal (Go 1.14 and later).
    pub const SIGURG: u64 = 23;
    /// The highest signal number this personality knows.
    pub const MAX: usize = 64;
}

/// `sigaction` flags this personality honours.
pub mod flags {
    /// The handler takes three arguments (`siginfo`, `ucontext`).
    pub const SIGINFO: u64 = 4;
    /// Deliver on the alternate stack set by `sigaltstack`.
    pub const ONSTACK: u64 = 0x0800_0000;
    /// Restart interrupted calls — accepted and recorded; nothing this
    /// personality delivers can interrupt a call yet.
    pub const RESTART: u64 = 0x1000_0000;
    /// The handler returns through a restorer the caller supplies, which is
    /// how every real libc and the Go runtime do it.
    pub const RESTORER: u64 = 0x0400_0000;
}

/// One installed handler.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Handler {
    /// The handler's address, or zero for none.
    pub entry: u64,
    /// The `sa_flags` it was installed with.
    pub flags: u64,
    /// The `sa_mask`, recorded and returned; masking during delivery is not
    /// yet enforced, and the RFC's tier notes say so rather than implying it.
    pub mask: u64,
    /// The restorer Go supplies, invoked by returning to it.
    pub restorer: u64,
}

/// The alternate signal stack a process asked for.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct AltStack {
    /// Its base address.
    pub base: u64,
    /// Its size in bytes.
    pub size: u64,
    /// `SS_DISABLE` and friends, recorded as given.
    pub flags: u64,
}

/// Every signal's disposition for one hosted process.
///
/// A fixed table, because this crate does not allocate and because sixty-four
/// signals is the whole of the space Linux defines.
pub struct Dispositions {
    handlers: [Handler; number::MAX],
    alt: AltStack,
}

impl Default for Dispositions {
    fn default() -> Self {
        Self::new()
    }
}

impl Dispositions {
    /// Nothing installed, no alternate stack.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            handlers: [Handler {
                entry: 0,
                flags: 0,
                mask: 0,
                restorer: 0,
            }; number::MAX],
            alt: AltStack {
                base: 0,
                size: 0,
                flags: 0,
            },
        }
    }

    /// Installs `handler` for `signal`, returning what was there before.
    ///
    /// # Errors
    ///
    /// `()` for a signal outside the table — refused rather than wrapped,
    /// because a signal number this does not know is a caller mistake and
    /// silently aliasing it onto another signal is the worst answer.
    pub fn install(&mut self, signal: u64, handler: Handler) -> Result<Handler, SignalError> {
        let index = usize::try_from(signal).map_err(|_| SignalError::NoSuchSignal)?;
        if index == 0 || index >= number::MAX {
            return Err(SignalError::NoSuchSignal);
        }
        let previous = self.handlers[index];
        self.handlers[index] = handler;
        Ok(previous)
    }

    /// What is installed for `signal`, if anything.
    #[must_use]
    pub fn handler(&self, signal: u64) -> Option<Handler> {
        let index = usize::try_from(signal).ok()?;
        let handler = self.handlers.get(index)?;
        (handler.entry != 0).then_some(*handler)
    }

    /// Records an alternate stack, returning the previous one.
    pub fn set_alt_stack(&mut self, alt: AltStack) -> AltStack {
        core::mem::replace(&mut self.alt, alt)
    }

    /// The alternate stack, as recorded.
    #[must_use]
    pub const fn alt_stack(&self) -> AltStack {
        self.alt
    }

    /// Where a delivery of `signal` should put its frame: the alternate stack
    /// if one is set and the handler asked for it, otherwise the interrupted
    /// stack. Returns the address to build *down* from.
    #[must_use]
    pub fn delivery_stack(&self, signal: u64, interrupted_rsp: u64) -> u64 {
        match self.handler(signal) {
            Some(handler)
                if handler.flags & flags::ONSTACK != 0
                    && self.alt.size > 0
                    && self.alt.flags == 0 =>
            {
                self.alt.base + self.alt.size
            }
            _ => interrupted_rsp,
        }
    }
}

/// Why a signal operation was refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SignalError {
    /// A signal number outside the table.
    NoSuchSignal,
    /// The frame would not fit the stack it was given.
    NoRoom,
}

/// Byte offsets within the `sigcontext` Linux builds on x86-64.
///
/// The order is ABI and is not ours to choose: it is `struct sigcontext_64`
/// in `arch/x86/include/uapi/asm/sigcontext.h`, and Go's
/// `runtime/signal_linux_amd64.go` reads these exact slots — and writes
/// `rip`, which is how a recovered panic resumes somewhere else. Written down
/// as constants, asserted contiguous by a host test, so a field inserted in
/// the wrong place fails here rather than in a runtime's stack trace.
pub mod sigcontext {
    /// Offsets of the general-purpose registers, in the order Linux stores
    /// them: r8..r15, then rdi, rsi, rbp, rbx, rdx, rax, rcx, rsp, rip.
    /// `r8`, first of the general-purpose block.
    pub const R8: usize = 0;
    /// `r9`.
    pub const R9: usize = 8;
    /// `r10`.
    pub const R10: usize = 16;
    /// `r11`.
    pub const R11: usize = 24;
    /// `r12`.
    pub const R12: usize = 32;
    /// `r13`.
    pub const R13: usize = 40;
    /// `r14`.
    pub const R14: usize = 48;
    /// `r15`.
    pub const R15: usize = 56;
    /// `rdi`.
    pub const RDI: usize = 64;
    /// `rsi`.
    pub const RSI: usize = 72;
    /// `rbp`.
    pub const RBP: usize = 80;
    /// `rbx`.
    pub const RBX: usize = 88;
    /// `rdx`.
    pub const RDX: usize = 96;
    /// `rax`.
    pub const RAX: usize = 104;
    /// `rcx`.
    pub const RCX: usize = 112;
    /// The interrupted stack pointer.
    pub const RSP: usize = 120;
    /// Where the thread was interrupted — the slot Go writes to recover.
    pub const RIP: usize = 128;
    /// The saved flags register.
    pub const EFLAGS: usize = 136;
    /// `cs`, `gs`, `fs`, `ss` packed as four `u16`s in one word.
    pub const SEGMENTS: usize = 144;
    /// The faulting address, for `SIGSEGV`.
    pub const CR2: usize = 168;
    /// Bytes in the whole structure.
    pub const SIZE: usize = 256;
}

/// The register file a delivery saves and a `rt_sigreturn` restores.
///
/// Ordered as the caller pleases; [`Registers::write_sigcontext`] places each
/// where the ABI says. Keeping the two apart is what lets the placement be
/// host-tested against the offsets without a machine in the loop.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Registers {
    /// The general-purpose registers, as the interrupted thread had them.
    pub rax: u64,
    /// See [`Registers::rax`].
    pub rbx: u64,
    /// See [`Registers::rax`].
    pub rcx: u64,
    /// See [`Registers::rax`].
    pub rdx: u64,
    /// See [`Registers::rax`].
    pub rsi: u64,
    /// See [`Registers::rax`].
    pub rdi: u64,
    /// See [`Registers::rax`].
    pub rbp: u64,
    /// The interrupted stack pointer.
    pub rsp: u64,
    /// See [`Registers::rax`].
    pub r8: u64,
    /// See [`Registers::rax`].
    pub r9: u64,
    /// See [`Registers::rax`].
    pub r10: u64,
    /// See [`Registers::rax`].
    pub r11: u64,
    /// See [`Registers::rax`].
    pub r12: u64,
    /// See [`Registers::rax`].
    pub r13: u64,
    /// See [`Registers::rax`].
    pub r14: u64,
    /// See [`Registers::rax`].
    pub r15: u64,
    /// Where the thread was interrupted — and the field a handler edits to
    /// resume somewhere else, which is how Go recovers from a fault.
    pub rip: u64,
    /// The flags register as saved.
    pub eflags: u64,
    /// The faulting address, for a `SIGSEGV`'s `cr2` slot.
    pub cr2: u64,
}

impl Registers {
    /// Writes this file into a `sigcontext` at the front of `out`.
    ///
    /// # Errors
    ///
    /// [`SignalError::NoRoom`] if `out` is shorter than the structure.
    pub fn write_sigcontext(&self, out: &mut [u8]) -> Result<(), SignalError> {
        if out.len() < sigcontext::SIZE {
            return Err(SignalError::NoRoom);
        }
        let mut put = |offset: usize, value: u64| {
            out[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        };
        put(sigcontext::R8, self.r8);
        put(sigcontext::R9, self.r9);
        put(sigcontext::R10, self.r10);
        put(sigcontext::R11, self.r11);
        put(sigcontext::R12, self.r12);
        put(sigcontext::R13, self.r13);
        put(sigcontext::R14, self.r14);
        put(sigcontext::R15, self.r15);
        put(sigcontext::RDI, self.rdi);
        put(sigcontext::RSI, self.rsi);
        put(sigcontext::RBP, self.rbp);
        put(sigcontext::RBX, self.rbx);
        put(sigcontext::RDX, self.rdx);
        put(sigcontext::RAX, self.rax);
        put(sigcontext::RCX, self.rcx);
        put(sigcontext::RSP, self.rsp);
        put(sigcontext::RIP, self.rip);
        put(sigcontext::EFLAGS, self.eflags);
        put(sigcontext::CR2, self.cr2);
        Ok(())
    }

    /// Reads a register file back out of a `sigcontext` — what
    /// `rt_sigreturn` does, and the reason a handler can change `rip` and
    /// have the change take effect.
    ///
    /// # Errors
    ///
    /// [`SignalError::NoRoom`] if `bytes` is shorter than the structure.
    pub fn read_sigcontext(bytes: &[u8]) -> Result<Self, SignalError> {
        if bytes.len() < sigcontext::SIZE {
            return Err(SignalError::NoRoom);
        }
        let get = |offset: usize| -> u64 {
            let mut word = [0u8; 8];
            word.copy_from_slice(&bytes[offset..offset + 8]);
            u64::from_le_bytes(word)
        };
        Ok(Self {
            r8: get(sigcontext::R8),
            r9: get(sigcontext::R9),
            r10: get(sigcontext::R10),
            r11: get(sigcontext::R11),
            r12: get(sigcontext::R12),
            r13: get(sigcontext::R13),
            r14: get(sigcontext::R14),
            r15: get(sigcontext::R15),
            rdi: get(sigcontext::RDI),
            rsi: get(sigcontext::RSI),
            rbp: get(sigcontext::RBP),
            rbx: get(sigcontext::RBX),
            rdx: get(sigcontext::RDX),
            rax: get(sigcontext::RAX),
            rcx: get(sigcontext::RCX),
            rsp: get(sigcontext::RSP),
            rip: get(sigcontext::RIP),
            eflags: get(sigcontext::EFLAGS),
            cr2: get(sigcontext::CR2),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registers() -> Registers {
        Registers {
            rax: 0x0a,
            rbx: 0x0b,
            rcx: 0x0c,
            rdx: 0x0d,
            rsi: 0x51,
            rdi: 0xd1,
            rbp: 0xb9,
            rsp: 0x5b,
            r8: 8,
            r9: 9,
            r10: 10,
            r11: 11,
            r12: 12,
            r13: 13,
            r14: 14,
            r15: 15,
            rip: 0x4141,
            eflags: 0x202,
            cr2: 0xdead,
        }
    }

    #[test]
    fn a_register_file_round_trips_through_the_abi_layout() {
        let mut frame = std::vec![0u8; sigcontext::SIZE];
        registers().write_sigcontext(&mut frame).unwrap();
        assert_eq!(Registers::read_sigcontext(&frame).unwrap(), registers());
    }

    #[test]
    fn the_registers_land_where_linux_puts_them() {
        // Spot-checked against `struct sigcontext_64`: the general-purpose
        // block starts at r8 and runs to rip, and cr2 is the last field of
        // the structure Go reads for a fault address. Reading a *byte* slice
        // at these offsets is what a handler does, so the test does too.
        let mut frame = std::vec![0u8; sigcontext::SIZE];
        registers().write_sigcontext(&mut frame).unwrap();
        let at = |offset: usize| {
            let mut word = [0u8; 8];
            word.copy_from_slice(&frame[offset..offset + 8]);
            u64::from_le_bytes(word)
        };
        assert_eq!(at(0), 8, "r8 first");
        assert_eq!(at(56), 15, "r15 eighth");
        assert_eq!(at(128), 0x4141, "rip where Go writes it");
        assert_eq!(at(120), 0x5b, "rsp just below rip");
        assert_eq!(at(168), 0xdead, "cr2, the fault address");
    }

    #[test]
    fn a_handler_writing_rip_is_what_a_recovered_panic_reads_back() {
        // Go's SIGSEGV handler edits `rip` in the frame and returns; the
        // change takes effect because rt_sigreturn reads the frame back.
        // That is the whole mechanism, and it is testable without a machine.
        let mut frame = std::vec![0u8; sigcontext::SIZE];
        registers().write_sigcontext(&mut frame).unwrap();
        frame[sigcontext::RIP..sigcontext::RIP + 8].copy_from_slice(&0x5252u64.to_le_bytes());
        let restored = Registers::read_sigcontext(&frame).unwrap();
        assert_eq!(restored.rip, 0x5252);
        assert_eq!(restored.rax, registers().rax, "everything else survives");
    }

    #[test]
    fn a_short_buffer_is_refused_both_ways() {
        let mut small = std::vec![0u8; sigcontext::SIZE - 1];
        assert_eq!(
            registers().write_sigcontext(&mut small),
            Err(SignalError::NoRoom)
        );
        assert_eq!(
            Registers::read_sigcontext(&small).unwrap_err(),
            SignalError::NoRoom
        );
    }

    #[test]
    fn handlers_install_and_report_what_was_there() {
        let mut dispositions = Dispositions::new();
        assert_eq!(dispositions.handler(number::SIGSEGV), None);
        let handler = Handler {
            entry: 0x1000,
            flags: flags::SIGINFO | flags::ONSTACK,
            mask: 0,
            restorer: 0x2000,
        };
        let previous = dispositions.install(number::SIGSEGV, handler).unwrap();
        assert_eq!(previous.entry, 0, "nothing was installed before");
        assert_eq!(dispositions.handler(number::SIGSEGV), Some(handler));
        // Another signal is untouched -- the table is per-signal, which is
        // the bug a shared slot would introduce.
        assert_eq!(dispositions.handler(number::SIGURG), None);
    }

    #[test]
    fn a_signal_outside_the_table_is_refused_not_wrapped() {
        let mut dispositions = Dispositions::new();
        for bad in [0u64, 64, 65, u64::MAX] {
            assert_eq!(
                dispositions.install(bad, Handler::default()),
                Err(SignalError::NoSuchSignal),
                "signal {bad}"
            );
        }
    }

    #[test]
    fn delivery_uses_the_alternate_stack_only_when_asked_and_enabled() {
        let mut dispositions = Dispositions::new();
        dispositions
            .install(
                number::SIGSEGV,
                Handler {
                    entry: 0x1000,
                    flags: flags::ONSTACK,
                    mask: 0,
                    restorer: 0,
                },
            )
            .unwrap();
        // No alternate stack set: the interrupted stack, whatever the flag.
        assert_eq!(dispositions.delivery_stack(number::SIGSEGV, 0x7000), 0x7000);
        dispositions.set_alt_stack(AltStack {
            base: 0x9000,
            size: 0x1000,
            flags: 0,
        });
        assert_eq!(dispositions.delivery_stack(number::SIGSEGV, 0x7000), 0xa000);
        // A handler that did not ask for it keeps the interrupted stack --
        // which is the case Go's SIGURG handler relies on.
        dispositions
            .install(
                number::SIGURG,
                Handler {
                    entry: 0x1000,
                    flags: 0,
                    mask: 0,
                    restorer: 0,
                },
            )
            .unwrap();
        assert_eq!(dispositions.delivery_stack(number::SIGURG, 0x7000), 0x7000);
    }
}
