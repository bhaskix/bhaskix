// SPDX-License-Identifier: Apache-2.0
//! The personality boundary: one frame, carried and not interpreted.
//!
//! [RFC 0031](../../docs/rfc/0031-linux-compatibility-as-an-adapter.md)'s
//! interface **I1**. The nucleus's total knowledge of Linux is meant to be
//! *this domain speaks a foreign dialect; here is the register frame;
//! deliver it.* Today it is that plus twenty syscall numbers and their
//! implementations, which is the drift RFC 0031 §5 records and gives a
//! trigger for. This type is what makes correcting that drift a
//! **relocation** rather than a rewrite: once every handler takes a
//! [`PersonalityCall`] instead of reaching into a kernel structure, moving
//! them into a domain is a change of caller, not of code.
//!
//! ## The bug this type exists to make unrepresentable
//!
//! Linux passes system-call arguments in `rdi, rsi, rdx, r10, r8, r9`. The
//! kernel's own `SyscallFrame` calls those same registers `capability`,
//! `method`, `arg0`, `arg1`, `arg2`, `arg3`, because RFC 0008's ABI is about
//! capabilities and those are its names for them. **The two namings overlap
//! and disagree**: a handler that reads `arg0` as "the first argument" is
//! reading `rdx`, which is Linux's *third*.
//!
//! That has been written wrongly twice in this project — once installing a
//! signal handler for signal-number-nothing, once decoding an `mmap` whose
//! length was its protection — and each time the symptom appeared a long way
//! from the cause. Here the arguments are a plain array in Linux's own
//! order, named [`PersonalityCall::args`], and there is no second naming to
//! confuse it with.

/// Which dialect a domain's threads speak.
///
/// A `u16` rather than a bare enum discriminant in the wire form, because
/// this frame is meant to survive becoming a message: a field that is
/// exactly as wide as it prints is one fewer thing to get wrong when it
/// crosses a domain boundary.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u16)]
pub enum Dialect {
    /// RFC 0008's six capability-invocation kinds. Never delivered to a
    /// personality — a native call is not foreign and does not travel.
    Native = 0,
    /// Linux `x86_64`.
    Linux = 1,
}

impl Dialect {
    /// The wire value.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self as u16
    }

    /// Reads a wire value, refusing one nobody has defined rather than
    /// defaulting to a dialect.
    #[must_use]
    pub const fn from_u16(value: u16) -> Option<Self> {
        match value {
            0 => Some(Self::Native),
            1 => Some(Self::Linux),
            _ => None,
        }
    }
}

/// How many arguments a system call in any supported dialect carries.
///
/// Six, because that is what the `x86_64` Linux ABI passes in registers and
/// nothing here needs a seventh. A dialect wanting more would pass a pointer
/// to them, as Linux itself does for `select`.
pub const ARGUMENTS: usize = 6;

/// One foreign system call, as the nucleus should hand it over.
///
/// **The nucleus does not interpret `number`.** It carries it, logs it —
/// RFC 0026's `FOREIGN` event already does — and delivers it. Every `match`
/// on a Linux syscall number inside `kernel/` is a boundary violation, and
/// [`crate::call`]'s existence is what makes that statement checkable rather
/// than aspirational.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PersonalityCall {
    /// Which dialect. Carried rather than assumed, because a second
    /// personality is the whole reason this is not called `LinuxCall`.
    pub dialect: Dialect,
    /// The dialect's own call number, uninterpreted by whoever carries it.
    pub number: u64,
    /// The six arguments, **in the dialect's own register order** — for
    /// Linux, `rdi, rsi, rdx, r10, r8, r9`. See this module's own
    /// documentation for why that sentence is written down.
    pub args: [u64; ARGUMENTS],
    /// Which thread made the call. A personality needs it for `gettid` and
    /// to know whom to resume; it is an identifier, never authority.
    pub thread: u32,
    /// Which domain the thread belongs to. Likewise an identifier: what the
    /// domain may *do* is what its capabilities say, and this number cannot
    /// be turned into one.
    pub domain: u32,
}

impl PersonalityCall {
    /// Builds a call from the six registers, in Linux's order.
    #[must_use]
    pub const fn new(
        dialect: Dialect,
        number: u64,
        args: [u64; ARGUMENTS],
        thread: u32,
        domain: u32,
    ) -> Self {
        Self {
            dialect,
            number,
            args,
            thread,
            domain,
        }
    }

    /// The first argument — Linux's `rdi`.
    #[must_use]
    pub const fn first(&self) -> u64 {
        self.args[0]
    }

    /// The second — `rsi`.
    #[must_use]
    pub const fn second(&self) -> u64 {
        self.args[1]
    }

    /// The third — `rdx`.
    #[must_use]
    pub const fn third(&self) -> u64 {
        self.args[2]
    }

    /// The fourth — `r10`, and *not* `rcx`: `syscall` clobbers `rcx` with
    /// the return address, which is why Linux's fourth argument register
    /// differs from the ordinary C calling convention's. A translator that
    /// used the C order would read a return address as a `futex` timeout.
    #[must_use]
    pub const fn fourth(&self) -> u64 {
        self.args[3]
    }

    /// The fifth — `r8`.
    #[must_use]
    pub const fn fifth(&self) -> u64 {
        self.args[4]
    }

    /// The sixth — `r9`.
    #[must_use]
    pub const fn sixth(&self) -> u64 {
        self.args[5]
    }
}

/// What comes back: one value, in the dialect's return register.
///
/// **Never a capability, and that is interface I3 restated in a type.** A
/// hosted process holds no capabilities and has no way to name one, so a
/// personality has nothing to give it even if it wanted to. A reply that
/// could carry one would be the single hole through which a Linux program
/// could reach the capability interface.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Answer {
    /// The value for `rax` — a result, or a negative `errno`.
    pub value: u64,
}

impl Answer {
    /// A successful result.
    #[must_use]
    pub const fn ok(value: u64) -> Self {
        Self { value }
    }

    /// A refusal, from a negative Linux `errno`.
    #[must_use]
    pub const fn error(errno: i64) -> Self {
        Self {
            value: errno as u64,
        }
    }

    /// Whether this is a refusal, by Linux's own convention: the top 4,096
    /// values of the address space are errors, which is how a program tells
    /// `mmap` returning a very high address from `mmap` failing.
    #[must_use]
    pub const fn is_error(&self) -> bool {
        (self.value as i64) < 0 && (self.value as i64) >= -4095
    }
}

/// `-ENOSYS`, the answer for everything no tier has reached yet.
///
/// A refusal a runtime can see, which is the RFC's tiering rather than an
/// omission — and it is *logged*, so the set of calls a real workload needs
/// is discovered rather than guessed.
pub const ENOSYS: Answer = Answer::error(-38);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_arguments_are_in_linuxs_order_and_the_fourth_is_r10() {
        let call = PersonalityCall::new(Dialect::Linux, 202, [10, 20, 30, 40, 50, 60], 7, 3);
        assert_eq!(call.first(), 10, "rdi");
        assert_eq!(call.second(), 20, "rsi");
        assert_eq!(call.third(), 30, "rdx");
        // `syscall` clobbers `rcx`, so Linux's fourth argument is `r10`. A
        // translator using the C convention reads the return address here.
        assert_eq!(call.fourth(), 40, "r10, not rcx");
        assert_eq!(call.fifth(), 50, "r8");
        assert_eq!(call.sixth(), 60, "r9");
    }

    #[test]
    fn a_dialect_nobody_defined_is_refused_rather_than_defaulted() {
        assert_eq!(Dialect::from_u16(0), Some(Dialect::Native));
        assert_eq!(Dialect::from_u16(1), Some(Dialect::Linux));
        assert_eq!(Dialect::from_u16(2), None);
        assert_eq!(Dialect::from_u16(u16::MAX), None);
        assert_eq!(Dialect::Linux.as_u16(), 1);
    }

    #[test]
    fn an_answer_tells_a_refusal_from_a_high_address() {
        assert!(ENOSYS.is_error());
        assert_eq!(ENOSYS.value as i64, -38);
        // Linux's own rule: the top 4,096 values are errors and everything
        // else is a result. An `mmap` that legitimately returned an address
        // near the top of the address space must not read as a failure.
        assert!(Answer::error(-4095).is_error());
        assert!(!Answer::error(-4096).is_error());
        assert!(!Answer::ok(0).is_error());
        assert!(!Answer::ok(0x7fff_ffff_f000).is_error());
        assert!(!Answer::ok(u64::MAX - 4096).is_error());
    }
}
