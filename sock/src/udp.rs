// SPDX-License-Identifier: Apache-2.0
//! UDP sockets: a capability in, datagrams out.
//!
//! RFC 0018 step 5's shape, spoken once. A socket is a badged capability
//! the protocol service mints; the payload for each call is a `Memory`
//! object the program lends for exactly that call. Every function takes
//! the slots as arguments, because they are the program's — this module
//! adds the exchange, the refusal decoding and nothing else.

use crate::call::{Reply, call};
use bhaskix_abi::{method, socket, status, syscall};

/// Why an operation failed, with the raw words kept: the ported programs
/// report exact numbers, and an error type that discarded them would force
/// the reporting back into hand-rolled calls.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The kernel refused the call itself; the word is the kernel status.
    Kernel(u64),
    /// The kernel delivered and the service said no; the word is the
    /// service's outcome (`socket::NO_PORT`, `socket::GONE`, …).
    Service(u64),
}

impl Refusal {
    /// The raw word, whichever side it came from — what a report page
    /// wants.
    #[must_use]
    pub const fn word(&self) -> u64 {
        match self {
            Self::Kernel(word) | Self::Service(word) => *word,
        }
    }

    fn from(reply: &Reply) -> Self {
        if reply.status != status::OK {
            Self::Kernel(reply.status)
        } else {
            Self::Service(reply.value)
        }
    }
}

/// Declares where the socket capability may land: `EXPECT` on the network
/// endpoint, one-shot, the slot chosen by the program and never by the
/// service. Separate from [`bind`] because a program retries the bind while
/// a service finishes starting, and re-declaring per attempt would burn the
/// declaration.
///
/// # Errors
///
/// The kernel's refusal, verbatim. No endpoint means no network, which is a
/// state rather than a failure: a machine with no device still boots.
pub fn expect_socket(network_slot: u64, socket_slot: u64) -> Result<(), Refusal> {
    let reply = call(
        syscall::INVOKE,
        network_slot,
        method::EXPECT,
        [socket_slot, 0, 0, 0],
    );
    if reply.kernel_ok() {
        Ok(())
    } else {
        Err(Refusal::Kernel(reply.status))
    }
}

/// One bound socket: the slot its capability landed in, and the local port
/// the service actually assigned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Socket {
    slot: u64,
    port: u16,
}

/// Binds a local UDP port — zero to be assigned one — on the network
/// endpoint in `network_slot`. On success the socket capability has landed
/// in the slot named by [`expect_socket`], which must have been called
/// first.
///
/// One attempt, decoded honestly: a service that is not answering yet is
/// not a service that refused, and the retry policy — how patient, how
/// often — belongs to the caller, who knows what it is waiting for.
///
/// # Errors
///
/// [`Refusal`] with the side and word that said no.
pub fn bind(network_slot: u64, socket_slot: u64, port: u16) -> Result<Socket, Refusal> {
    let reply = call(
        syscall::CALL,
        network_slot,
        socket::BIND_UDP,
        [u64::from(port), 0, 0, 0],
    );
    if reply.kernel_ok() && reply.value == socket::OK {
        Ok(Socket {
            slot: socket_slot,
            port: reply.second as u16,
        })
    } else {
        Err(Refusal::from(&reply))
    }
}

/// A datagram that arrived: who sent it, from which port.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct From {
    /// The source IPv4 address, as the wire word the services speak.
    pub address: u32,
    /// The source port.
    pub port: u16,
}

impl Socket {
    /// A socket whose capability is already in a slot this program holds.
    ///
    /// [`bind`] returns one because it is what just created the capability.
    /// A program that keeps sockets in a *table* — `bin/linuxd`, holding one
    /// per hosted descriptor — cannot keep the returned value beside each
    /// row, so it keeps the slot and rebuilds the handle when it needs to
    /// act. Nothing is created here and nothing is checked: this is a name
    /// for a capability the caller already has, and if the slot is empty the
    /// call made through it is refused by the kernel, which is where that
    /// check belongs.
    #[must_use]
    pub const fn from_slot(slot: u64, port: u16) -> Self {
        Self { slot, port }
    }


    /// The slot this socket's capability occupies.
    #[must_use]
    pub const fn slot(&self) -> u64 {
        self.slot
    }

    /// The local port the service bound.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// Sends `length` bytes of the `Memory` object in `payload_slot` to
    /// `address:port`. The payload is lent for exactly this call; the
    /// program's mapping of it is untouched.
    ///
    /// # Errors
    ///
    /// [`Refusal`] with the side and word that said no.
    pub fn send_to(
        &self,
        payload_slot: u64,
        address: u32,
        port: u16,
        length: usize,
    ) -> Result<(), Refusal> {
        let reply = call(
            syscall::CALL,
            self.slot,
            socket::SEND_TO,
            [
                u64::from(address),
                u64::from(port),
                payload_slot,
                length as u64,
            ],
        );
        if reply.kernel_ok() && reply.value == socket::OK {
            Ok(())
        } else {
            Err(Refusal::from(&reply))
        }
    }

    /// Takes the next datagram into the `Memory` object in `payload_slot`.
    /// `Ok(None)` is an empty mailbox — an answer, not an error, because a
    /// caller polling between sends wants to hear it.
    ///
    /// # Errors
    ///
    /// [`Refusal`] for anything other than delivery or emptiness.
    pub fn recv_from(&self, payload_slot: u64) -> Result<Option<From>, Refusal> {
        let reply = call(
            syscall::CALL,
            self.slot,
            socket::RECV_FROM,
            [payload_slot, 0, 0, 0],
        );
        if reply.kernel_ok() && reply.value == socket::OK {
            return Ok(Some(From {
                address: reply.second as u32,
                port: reply.third as u16,
            }));
        }
        if reply.kernel_ok() && reply.value == socket::EMPTY {
            return Ok(None);
        }
        Err(Refusal::from(&reply))
    }

    /// Gives up the socket: the binding ends and the capability stops
    /// working.
    ///
    /// # Errors
    ///
    /// [`Refusal`] if the service or kernel would not end it.
    pub fn close(self) -> Result<(), Refusal> {
        let reply = call(syscall::CALL, self.slot, socket::CLOSE, [0; 4]);
        if reply.kernel_ok() && reply.value == socket::OK {
            Ok(())
        } else {
            Err(Refusal::from(&reply))
        }
    }
}
