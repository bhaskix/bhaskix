// SPDX-License-Identifier: Apache-2.0
//! The domain placement's run loop: the ring 3 counterpart of the kernel's.
//!
//! The kernel's `run::<S>()` calls `ipc::recv` and `ipc::reply` as functions.
//! This one issues the same two operations as system calls. That is the whole
//! difference between the placements, and it is why this crate is thirty lines
//! of loop rather than a framework: a service that needed more than this to be
//! moved would not have been movable.
//!
//! [RFC 0013](../../docs/rfc/0013-service-framework.md).
#![no_std]

use bhaskix_abi::{status, syscall};
use bhaskix_service::{Request, Service};

/// Issues one system call, and hands back what the kernel put in the frame.
///
/// `rax` kind, `rdi` capability, `rsi` method, `rdx`/`r10`/`r8`/`r9`
/// arguments — RFC 0008. `syscall` destroys `rcx` and `r11`, so nothing that
/// must survive lives there.
fn syscall(kind: u64, capability: u64, method: u64, args: [u64; 4]) -> (u64, u64, u64, [u64; 4]) {
    let status: u64;
    let mut capability = capability;
    let mut method = method;
    let [mut a0, mut a1, mut a2, mut a3] = args;
    // SAFETY: the system call convention is the one the kernel's entry stub
    // reads, and every register it may write is declared as an output here.
    // Nothing is dereferenced on either side: the whole exchange is registers.
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") kind => status,
            inlateout("rdi") capability,
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
    (status, capability, method, [a0, a1, a2, a3])
}

/// Ends this program. Never returns.
fn exit() -> ! {
    syscall(syscall::EXIT, 0, 0, [0; 4]);
    // The kernel does not return from `Exit`. Stopping here is better than
    // running into whatever follows if it ever did.
    #[allow(clippy::empty_loop)]
    loop {}
}

/// Runs a service in a domain, for ever.
///
/// `endpoint` is the slot in this domain's CSpace holding the capability to
/// the endpoint it answers on — a slot and not an identity, because a program
/// naming an identity would be asserting what it may reach rather than
/// pointing at authority it was given.
///
/// The loop is the kernel's loop with two calls swapped for two instructions.
/// It reads the same four registers, hands the service the same [`Request`],
/// and sends back the same four — which is only possible because the server
/// side of `Recv` and `Reply` carries a whole message. Until RFC 0013 step 3
/// it carried one register, and no service that packs a chunk could have run
/// out here at all: "the same service in either placement" was false at the
/// boundary before it was ever false in a service.
pub fn serve<S: Service>(endpoint: u64, context: S::Context) -> ! {
    let Ok(mut state) = S::start(context) else {
        exit()
    };

    loop {
        let (status, badge, method, args) = syscall(syscall::RECV, endpoint, 0, [0; 4]);

        // A domain cannot ask why: an endpoint that stops delivering has been
        // revoked or destroyed, and there is nothing left for this program to
        // serve. Exiting is the honest end -- a loop that spun here would look
        // like a working service using a whole CPU.
        if status != status::OK {
            exit()
        }

        let reply = S::handle(
            &mut state,
            &context,
            Request {
                method,
                args: &args,
                badge,
            },
        );

        // Nothing says who to answer. The kernel remembers who this thread
        // received from, which is why the badge fits in a register at all --
        // and why a service out here cannot answer anybody else.
        syscall(syscall::REPLY, 0, method, reply.args);
    }
}
