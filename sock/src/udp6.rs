// SPDX-License-Identifier: Apache-2.0
//! UDP sockets in the second family — RFC 0029 step 4.
//!
//! The same service, the same capabilities, the same lifecycle as
//! [`crate::udp`]; what differs is the width of an endpoint, and this
//! module is where the two-word split lives so that no program hand-rolls
//! it. A v6 address is two `u64`s in wire order; `SEND_TO6` packs
//! `(length << 16) | port` into its third word (the cap that packing
//! imposes is the UDP length field's own), and `RECV_FROM6`'s reply rides
//! the source port above the outcome, because the reply convention carries
//! three service words and a v6 source needs two of them.

use bhaskix_abi::{method, socket, status, syscall};

use crate::call::{Reply, call};
use crate::udp::Refusal;

/// The two-sided refusal split, as [`crate::udp`] makes it: the kernel's
/// word when the call itself failed, the service's when it answered no.
fn refused(reply: &Reply) -> Refusal {
    if reply.status == status::OK {
        Refusal::Service(reply.value)
    } else {
        Refusal::Kernel(reply.status)
    }
}

/// Declares where the socket capability may land, exactly as
/// [`crate::udp::expect_socket`] — the family changes nothing about slots.
///
/// # Errors
///
/// [`Refusal::Kernel`] with the status that said no.
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

/// A bound v6 socket: the capability's slot and the local port.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Socket6 {
    slot: u64,
    port: u16,
}

/// Binds a v6 UDP socket on `port` (zero: "assign me one").
///
/// # Errors
///
/// [`Refusal`] with the side and word that said no.
pub fn bind6(network_slot: u64, socket_slot: u64, port: u16) -> Result<Socket6, Refusal> {
    let reply = call(
        syscall::CALL,
        network_slot,
        socket::BIND_UDP6,
        [u64::from(port), 0, 0, 0],
    );
    if reply.kernel_ok() && reply.value == socket::OK {
        Ok(Socket6 {
            slot: socket_slot,
            port: reply.second as u16,
        })
    } else {
        Err(refused(&reply))
    }
}

/// A datagram that arrived: who sent it, from which port.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct From6 {
    /// The source address, sixteen bytes in wire order.
    pub address: [u8; 16],
    /// The source port.
    pub port: u16,
}

impl Socket6 {
    /// A socket whose capability is already in a slot this program holds.
    ///
    /// [`bind6`]'s counterpart for a program that keeps its sockets in a
    /// table rather than in a local — see [`crate::udp::Socket::from_slot`],
    /// which exists for the same caller and the same reason.
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
    /// `address:port`.
    ///
    /// # Errors
    ///
    /// [`Refusal`] with the side and word that said no.
    pub fn send_to(
        &self,
        payload_slot: u64,
        address: [u8; 16],
        port: u16,
        length: usize,
    ) -> Result<(), Refusal> {
        let mut high = [0u8; 8];
        let mut low = [0u8; 8];
        high.copy_from_slice(&address[..8]);
        low.copy_from_slice(&address[8..]);
        let reply = call(
            syscall::CALL,
            self.slot,
            socket::SEND_TO6,
            [
                u64::from_be_bytes(high),
                u64::from_be_bytes(low),
                ((length as u64) << 16) | u64::from(port),
                payload_slot,
            ],
        );
        if reply.kernel_ok() && reply.value == socket::OK {
            Ok(())
        } else {
            Err(refused(&reply))
        }
    }

    /// Takes the next datagram into the `Memory` object in `payload_slot`.
    /// `Ok(None)` is an empty mailbox — an answer, not an error.
    ///
    /// # Errors
    ///
    /// [`Refusal`] for anything other than delivery or emptiness.
    pub fn recv_from(&self, payload_slot: u64) -> Result<Option<From6>, Refusal> {
        let reply = call(
            syscall::CALL,
            self.slot,
            socket::RECV_FROM6,
            [payload_slot, 0, 0, 0],
        );
        let outcome = reply.value & 0xffff;
        if reply.kernel_ok() && outcome == socket::OK {
            let mut address = [0u8; 16];
            address[..8].copy_from_slice(&reply.second.to_be_bytes());
            address[8..].copy_from_slice(&reply.third.to_be_bytes());
            return Ok(Some(From6 {
                address,
                port: (reply.value >> 16) as u16,
            }));
        }
        if reply.kernel_ok() && outcome == socket::EMPTY {
            return Ok(None);
        }
        Err(refused(&reply))
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
            Err(refused(&reply))
        }
    }
}

/// The one place a refusal's word is read out of a v6 reply: the outcome
/// rides the low sixteen bits when a port shares the word, and every other
/// reply keeps the whole word — which is [`Refusal::from`]'s assumption,
/// still true because refusals never carry a port.
const _OUTCOMES_FIT_SIXTEEN_BITS: () = {
    assert!(socket::OK < 1 << 16);
    assert!(socket::EMPTY < 1 << 16);
    assert!(socket::WRONG_FAMILY < 1 << 16);
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_packing_round_trips() {
        // The exact arithmetic ipd unpacks with, asserted from this side so
        // the two cannot drift apart silently.
        let word = ((25_u64) << 16) | u64::from(53_u16);
        assert_eq!(word as u16, 53);
        assert_eq!((word >> 16) as usize, 25);

        let value = socket::OK | (u64::from(49152_u16) << 16);
        assert_eq!(value & 0xffff, socket::OK);
        assert_eq!((value >> 16) as u16, 49152);
    }

    #[test]
    fn an_address_splits_and_rejoins_in_wire_order() {
        let address: [u8; 16] = [0xfe, 0xc0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3];
        let mut high = [0u8; 8];
        let mut low = [0u8; 8];
        high.copy_from_slice(&address[..8]);
        low.copy_from_slice(&address[8..]);
        let (hi, lo) = (u64::from_be_bytes(high), u64::from_be_bytes(low));
        assert_eq!(hi, 0xfec0_0000_0000_0000);
        assert_eq!(lo, 3);
        let mut rejoined = [0u8; 16];
        rejoined[..8].copy_from_slice(&hi.to_be_bytes());
        rejoined[8..].copy_from_slice(&lo.to_be_bytes());
        assert_eq!(rejoined, address);
    }
}
