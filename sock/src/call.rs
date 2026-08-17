// SPDX-License-Identifier: Apache-2.0
//! The one syscall stub.
//!
//! Every networked program used to carry its own copy of this `asm!` block,
//! each a slightly different shape — two returned words here, three there —
//! and each a separate `unsafe` review. This is the copy that replaces
//! them: RFC 0008's convention, all four reply words captured, one
//! `SAFETY` argument.

/// What a system call answered: the status register and the three reply
/// words the kernel may have written back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reply {
    /// The kernel's status, `bhaskix_abi::status::OK` on success.
    pub status: u64,
    /// The first reply word (`rdx`) — usually a service's own outcome.
    pub value: u64,
    /// The second reply word (`r10`).
    pub second: u64,
    /// The third reply word (`r8`).
    pub third: u64,
}

impl Reply {
    /// Whether the kernel said yes. Says nothing about the service's own
    /// outcome, which rides [`Reply::value`] — a distinction every refusal
    /// path in the ported programs turned out to need.
    #[must_use]
    pub const fn kernel_ok(&self) -> bool {
        self.status == bhaskix_abi::status::OK
    }
}

/// Issues one system call.
#[must_use]
pub fn call(kind: u64, capability: u64, method: u64, args: [u64; 4]) -> Reply {
    let status: u64;
    let mut value = args[0];
    let mut second = args[1];
    let mut third = args[2];
    // SAFETY: the system call convention from RFC 0008. Nothing is
    // dereferenced on this side, and every argument register is declared as
    // an output because the kernel writes the whole frame back on the way
    // out.
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") kind => status,
            inlateout("rdi") capability => _,
            inlateout("rsi") method => _,
            inlateout("rdx") value,
            inlateout("r10") second,
            inlateout("r8") third,
            inlateout("r9") args[3] => _,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    Reply {
        status,
        value,
        second,
        third,
    }
}

/// Gives up the processor until the scheduler comes back around.
pub fn yield_now() {
    let _ = call(bhaskix_abi::syscall::YIELD, 0, 0, [0; 4]);
}

/// Maps the capability in `slot` at `at`, writable if asked, and says
/// whether the kernel agreed — the touch-and-check idiom stays with the
/// caller, whose memory it is.
#[must_use]
pub fn attach(slot: u64, at: u64, writable: bool) -> bool {
    call(
        bhaskix_abi::syscall::INVOKE,
        slot,
        bhaskix_abi::method::ATTACH,
        [at, u64::from(writable), 0, 0],
    )
    .kernel_ok()
}
