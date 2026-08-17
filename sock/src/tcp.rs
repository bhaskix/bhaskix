// SPDX-License-Identifier: Apache-2.0
//! TCP connections: the handover, the stream calls, the refusal shapes.
//!
//! RFC 0020's service spoken through RFC 0022's exchange: rings the program
//! owns cross as staged gifts, one per call, and the connection capability
//! rides a reply into a slot the program declared. This module holds the
//! leg discipline — the staging, the bounded retry while a service is still
//! starting, the refusal decoding — and the stream verbs. It deliberately
//! does *not* fix the leg order into one `connect()` shape: the service
//! declares where gifts may land in its own order, a program juggling a
//! connection and a listener interleaves the legs to match, and the
//! primitive is what makes that expressible. A plain client strings four
//! legs and an `EXPECT` together in five lines.

use crate::call::{Reply, call};
use bhaskix_abi::{method, rights, status, syscall, tcp};

/// Why a handover leg did not complete.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LegError {
    /// The service answered `LATER` or had not declared its gift slot for
    /// the whole retry budget. Patience ran out, not the exchange.
    Stuck,
    /// The staged gift itself was refused; the word is the kernel's status.
    HandRefused(u64),
    /// The call came back and said no, with every raw word kept, because
    /// report pages print exact numbers.
    Refused {
        /// The kernel's status.
        status: u64,
        /// The service's own word.
        value: u64,
        /// The reply's detail word.
        detail: u64,
    },
}

/// One handover leg on the service endpoint in `service_slot`: stage the
/// gift if there is one, then call `verb` with the leg number, retrying
/// while the service's own declaration races this call or it answers
/// `LATER`. Returns the reply's detail word on success.
///
/// Staging and calling are two invocations by design — `HAND` attaches one
/// capability to the *next* call on that endpoint, so the pair reads
/// exactly like the sentence it implements.
///
/// # Errors
///
/// [`LegError`], with every raw word kept.
pub fn leg(
    service_slot: u64,
    verb: u64,
    a0: u64,
    a1: u64,
    gift: Option<(u64, u64)>,
    leg_number: u64,
) -> Result<u64, LegError> {
    for _ in 0..50_000u32 {
        if let Some((slot, badge)) = gift {
            // The badge travels with the gift, and for the wakes it must:
            // their capabilities are badged, badges are one-way, and a
            // signal ORs the badge into the word — zero would OR nothing
            // and ring nobody.
            let staged = call(
                syscall::INVOKE,
                service_slot,
                method::HAND,
                [slot, rights::READ | rights::WRITE, badge, 0],
            );
            if !staged.kernel_ok() {
                return Err(LegError::HandRefused(staged.status));
            }
        }
        let reply = call(syscall::CALL, service_slot, verb, [a0, a1, leg_number, 0]);
        // The service has not declared yet (its `EXPECT` races this call),
        // or has not started serving. Both answer with a status a later try
        // can change, so yield and try again.
        if reply.status == status::SLOT_UNAVAILABLE || reply.value == tcp::LATER {
            crate::call::yield_now();
            continue;
        }
        if reply.kernel_ok() && reply.value == tcp::OK {
            return Ok(reply.second);
        }
        return Err(LegError::Refused {
            status: reply.status,
            value: reply.value,
            detail: reply.second,
        });
    }
    Err(LegError::Stuck)
}

/// Declares where a reply-carried capability may land: `EXPECT` on the
/// endpoint, one-shot, the slot chosen by the program and never by the
/// service.
///
/// # Errors
///
/// The kernel's status, verbatim.
pub fn expect(endpoint_slot: u64, landing_slot: u64) -> Result<(), u64> {
    let reply = call(
        syscall::INVOKE,
        endpoint_slot,
        method::EXPECT,
        [landing_slot, 0, 0, 0],
    );
    if reply.kernel_ok() {
        Ok(())
    } else {
        Err(reply.status)
    }
}

/// Whether a slot holds *something*, read by refusal shape: an empty slot
/// fails to resolve at all (`NO_SUCH_CAPABILITY`), while an occupied one
/// reaches method dispatch and is refused there — and that refusal is
/// itself the proof something is there to refuse it. Returns the verdict
/// and the raw reply for the caller's report.
#[must_use]
pub fn occupied(slot: u64) -> (bool, Reply) {
    let reply = call(syscall::INVOKE, slot, method::INFO, [0; 4]);
    (reply.status != status::NO_SUCH_CAPABILITY, reply)
}

/// What one stream poll said.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamPoll {
    /// The stream answered.
    Ready {
        /// The machine's state number.
        state: u64,
        /// Cumulative bytes delivered into the program's receive ring.
        delivered: u64,
    },
    /// No wire on this machine; the capability answered, the network is
    /// what there is not.
    Unreachable,
    /// No unpredictability on this machine, so the service refuses to mint
    /// sequence numbers — RFC 0021's policy, heard from the caller's side.
    NoEntropy,
    /// The service said something else; the raw word.
    ServiceSaid(u64),
    /// The kernel refused the call; the raw status.
    KernelSaid(u64),
}

/// One `RECV` poll on a connection. `consumed` names bytes the program has
/// finished with since it last said so — the service reopens the receive
/// window by exactly that much, which is window-follows-free-space running
/// from the caller's side, and forgetting it is the deadlock RFC 0020's
/// measurement found. Zero consumes nothing.
#[must_use]
pub fn recv(connection_slot: u64, consumed: u64) -> StreamPoll {
    let reply = call(
        syscall::CALL,
        connection_slot,
        tcp::RECV,
        [consumed, 0, 0, 0],
    );
    if !reply.kernel_ok() {
        return StreamPoll::KernelSaid(reply.status);
    }
    match reply.value {
        tcp::OK => StreamPoll::Ready {
            state: reply.second >> 32,
            delivered: reply.second & 0xffff_ffff,
        },
        tcp::UNREACHABLE => StreamPoll::Unreachable,
        tcp::NO_ENTROPY => StreamPoll::NoEntropy,
        word => StreamPoll::ServiceSaid(word),
    }
}

/// Tells the service `count` more bytes are in the send ring. No payload
/// crosses in the message; the ring is where the bytes are.
///
/// # Errors
///
/// The kernel's status, verbatim.
pub fn send(connection_slot: u64, count: u64) -> Result<(), u64> {
    let reply = call(syscall::CALL, connection_slot, tcp::SEND, [count, 0, 0, 0]);
    if reply.kernel_ok() {
        Ok(())
    } else {
        Err(reply.status)
    }
}

/// Half-close: no more data this way.
///
/// # Errors
///
/// The kernel's status, verbatim.
pub fn shutdown(connection_slot: u64) -> Result<(), u64> {
    let reply = call(syscall::CALL, connection_slot, tcp::SHUTDOWN, [0; 4]);
    if reply.kernel_ok() {
        Ok(())
    } else {
        Err(reply.status)
    }
}

/// What one `ACCEPT` poll said.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AcceptPoll {
    /// An established connection's capability has landed in the slot the
    /// program declared with [`expect`].
    Accepted,
    /// Nothing yet; ask again after a wake.
    Later,
    /// No wire on this machine.
    Unreachable,
    /// The service said something else; the raw word.
    ServiceSaid(u64),
    /// The kernel refused the call; the raw status.
    KernelSaid(u64),
}

/// One `ACCEPT` poll on a listener.
#[must_use]
pub fn accept(listener_slot: u64) -> AcceptPoll {
    let reply = call(syscall::CALL, listener_slot, tcp::ACCEPT, [0; 4]);
    if !reply.kernel_ok() {
        return AcceptPoll::KernelSaid(reply.status);
    }
    match reply.value {
        tcp::OK => AcceptPoll::Accepted,
        tcp::LATER => AcceptPoll::Later,
        tcp::UNREACHABLE => AcceptPoll::Unreachable,
        word => AcceptPoll::ServiceSaid(word),
    }
}
