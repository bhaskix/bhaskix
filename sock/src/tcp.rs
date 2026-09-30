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
    leg_words(service_slot, verb, a0, a1, gift, leg_number).map(|(second, _)| second)
}

/// [`leg`], answering both of the reply's free words — the second is the
/// detail `leg` returns, the third is what a leg that answers two things puts
/// beside it (a new listener's first ring pair, RFC 0086 step 3b).
///
/// # Errors
///
/// As [`leg`].
pub fn leg_words(
    service_slot: u64,
    verb: u64,
    a0: u64,
    a1: u64,
    gift: Option<(u64, u64)>,
    leg_number: u64,
) -> Result<(u64, u64), LegError> {
    for _ in 0..50_000u32 {
        if let Some((slot, badge)) = gift {
            // The badge travels with the gift, and for the wakes it must:
            // their capabilities are badged, badges are one-way, and a
            // signal ORs the badge into the word — zero would OR nothing
            // and ring nobody.
            // Staging, said outright (RFC 0086 step 3b): a program that also
            // serves -- `bin/linuxd` -- would otherwise have this read as a
            // hand into the reply it owes.
            let staged = call(
                syscall::INVOKE,
                service_slot,
                method::HAND,
                [
                    slot,
                    rights::READ | rights::WRITE,
                    badge,
                    method::HAND_STAGE,
                ],
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
            return Ok((reply.second, reply.third));
        }
        return Err(LegError::Refused {
            status: reply.status,
            value: reply.value,
            detail: reply.second,
        });
    }
    Err(LegError::Stuck)
}

/// One `CONNECT6` leg — RFC 0029 step 5.
///
/// [`leg`]'s discipline exactly (the stage-then-call retry, the same
/// refusal decoding), with the second family's packing: the destination's
/// halves in the first two words, the port in the third, the leg in the
/// fourth — the one call in the family that spends all four words.
///
/// # Errors
///
/// As [`leg`].
pub fn leg6(
    service_slot: u64,
    address: [u8; 16],
    port: u16,
    gift: Option<(u64, u64)>,
    leg_number: u64,
) -> Result<u64, LegError> {
    let mut high = [0u8; 8];
    let mut low = [0u8; 8];
    high.copy_from_slice(&address[..8]);
    low.copy_from_slice(&address[8..]);
    for _ in 0..50_000u32 {
        if let Some((slot, badge)) = gift {
            // Staging, said outright (RFC 0086 step 3b): a program that also
            // serves -- `bin/linuxd` -- would otherwise have this read as a
            // hand into the reply it owes.
            let staged = call(
                syscall::INVOKE,
                service_slot,
                method::HAND,
                [
                    slot,
                    rights::READ | rights::WRITE,
                    badge,
                    method::HAND_STAGE,
                ],
            );
            if !staged.kernel_ok() {
                return Err(LegError::HandRefused(staged.status));
            }
        }
        let reply = call(
            syscall::CALL,
            service_slot,
            tcp::CONNECT6,
            [
                u64::from_be_bytes(high),
                u64::from_be_bytes(low),
                u64::from(port),
                leg_number,
            ],
        );
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
    /// program declared with [`expect`]; its stream lives in ring pair
    /// `pair` — 0 for `LISTEN`'s own, else the number [`arm_pair`] returned.
    Accepted {
        /// The ring pair the connection took.
        pair: u32,
    },
    /// Nothing yet; ask again after a wake.
    Later,
    /// No wire on this machine.
    Unreachable,
    /// The service said something else; the raw word.
    ServiceSaid(u64),
    /// The kernel refused the call; the raw status.
    KernelSaid(u64),
}

/// Arms the listener in `listener_slot` with one more ring pair — RFC 0086
/// step 2. Returns the pair's number, which [`accept`] names again when it
/// hands out the connection that took it.
///
/// The rings are gifted, so they must be memory capabilities in
/// `send_ring_slot` and `recv_ring_slot` that this program no longer needs
/// for anything else: the service writes the peer's stream into the second
/// and reads this program's out of the first for as long as a connection
/// holds the pair, and the pair returns to the listener by itself when that
/// connection is gone.
///
/// # Errors
///
/// [`LegError`] from whichever of the four legs refused, with its words.
pub fn arm_pair(
    listener_slot: u64,
    send_ring_slot: u64,
    recv_ring_slot: u64,
) -> Result<u32, LegError> {
    leg(listener_slot, tcp::ARM_PAIR, 0, 0, None, tcp::OPEN_LEG)?;
    leg(
        listener_slot,
        tcp::ARM_PAIR,
        0,
        0,
        Some((send_ring_slot, 0)),
        0,
    )?;
    leg(
        listener_slot,
        tcp::ARM_PAIR,
        0,
        0,
        Some((recv_ring_slot, 0)),
        1,
    )?;
    leg(listener_slot, tcp::ARM_PAIR, 0, 0, None, 2).map(|pair| pair as u32)
}

/// Opens a **new listener** on `port` — RFC 0086 step 3a — and returns its
/// badge and the number of the ring pair `rings` became (step 3b), which
/// [`accept`] names again when a connection takes it. The listener
/// capability lands in `landing_slot`.
///
/// The way a second program listens: `bin/tcpc`'s `LISTEN` uses the service's
/// one fixed handover, and any other caller opens its own with an open leg
/// carrying no gift, then gifts the listener's first ring pair (legs 0 and
/// 1), optionally the wake its connections will ring (leg 3), and completes
/// (leg 2). The rings are the caller's memory and must not be used for
/// anything else while the listener lives; more pairs are [`arm_pair`]'s.
///
/// # Errors
///
/// [`LegError`] from whichever leg refused — `tcp::REFUSED` in its value if
/// the port is already held — or from declaring `landing_slot`, as
/// `HandRefused`.
pub fn listen_open(
    service_slot: u64,
    port: u16,
    rings: (u64, u64),
    wake: Option<(u64, u64)>,
    landing_slot: u64,
) -> Result<(u64, u32), LegError> {
    let port = u64::from(port);
    leg(service_slot, tcp::LISTEN, port, 0, None, tcp::OPEN_LEG)?;
    leg(service_slot, tcp::LISTEN, port, 0, Some((rings.0, 0)), 0)?;
    leg(service_slot, tcp::LISTEN, port, 0, Some((rings.1, 0)), 1)?;
    if let Some(wake) = wake {
        leg(service_slot, tcp::LISTEN, port, 0, Some(wake), 3)?;
    }
    expect(service_slot, landing_slot).map_err(LegError::HandRefused)?;
    leg_words(service_slot, tcp::LISTEN, port, 0, None, 2)
        .map(|(handle, pair)| (handle, pair as u32))
}

/// Who is at the other end of a connection — RFC 0086 step 3a.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Peer {
    /// An IPv4 peer: its address in host order, and its port.
    V4 {
        /// The address, as a host-order `u32`.
        address: u32,
        /// The port.
        port: u16,
    },
    /// `::1`, the only v6 peer the service can have (RFC 0029).
    Loopback6 {
        /// The port.
        port: u16,
    },
}

/// Asks the service who is at the other end of the connection in
/// `connection_slot`. `None` if the service would not say — a retired
/// connection, or a word this version does not understand.
#[must_use]
pub fn peer(connection_slot: u64) -> Option<Peer> {
    let reply = call(syscall::CALL, connection_slot, tcp::PEER, [0; 4]);
    if !reply.kernel_ok() || reply.value != tcp::OK {
        return None;
    }
    let port = (reply.second & 0xffff) as u16;
    match reply.second >> 16 {
        4 => Some(Peer::V4 {
            address: reply.third as u32,
            port,
        }),
        6 if reply.third == 1 => Some(Peer::Loopback6 { port }),
        _ => None,
    }
}

/// One `ACCEPT` poll on a listener.
#[must_use]
pub fn accept(listener_slot: u64) -> AcceptPoll {
    let reply = call(syscall::CALL, listener_slot, tcp::ACCEPT, [0; 4]);
    if !reply.kernel_ok() {
        return AcceptPoll::KernelSaid(reply.status);
    }
    match reply.value {
        tcp::OK => AcceptPoll::Accepted {
            pair: reply.third as u32,
        },
        tcp::LATER => AcceptPoll::Later,
        tcp::UNREACHABLE => AcceptPoll::Unreachable,
        word => AcceptPoll::ServiceSaid(word),
    }
}
