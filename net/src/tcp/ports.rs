// SPDX-License-Identifier: Apache-2.0
//! Which local port a connection this machine opens comes from.
//!
//! [RFC 0090](../../../docs/rfc/0090-a-hosted-program-that-dials-out.md) part 3,
//! step 2. `bin/tcpd` opens every outbound connection from one fixed port today,
//! which is one connection to a given peer at a time for the whole machine. A
//! connection a program opens through `OPEN_LEG` takes its port from here
//! instead.
//!
//! **A start drawn from entropy, then the first port that is free for this
//! peer.** The start is the caller's — this module holds no randomness, so a
//! machine without any is the caller's refusal (`NO_ENTROPY`), never a
//! predictable port chosen here. "Free" is a property of the **four-tuple**,
//! not of the port: two connections may share a local port as long as they go
//! to different peers, because the peer is half of what demultiplexes them.
//!
//! Pure arithmetic over a question the caller answers, so every property is a
//! host test.

use super::FourTuple;
use crate::addr::{Address, Port};

/// The first port of the dynamic range, from which this machine dials.
pub const DYNAMIC_FIRST: u16 = 49152;
/// The last.
pub const DYNAMIC_LAST: u16 = 65535;
/// How many ports the range holds.
const DYNAMIC_SPAN: u64 = DYNAMIC_LAST as u64 - DYNAMIC_FIRST as u64 + 1;

/// The four-tuple for a new connection from `local` to `remote:remote_port`,
/// or `None` when every port of the dynamic range already carries one.
///
/// The search starts at the port `start` names — any value, reduced into the
/// range, so the caller can pass a raw draw — and walks upward, wrapping from
/// [`DYNAMIC_LAST`] to [`DYNAMIC_FIRST`], until `taken` says a tuple is not
/// already a connection. `taken` is the caller's table; a port the caller holds
/// for something else (a listener, or the fixed outbound port the handover
/// uses without asking) is one it answers `true` for.
pub fn local_port(
    start: u64,
    local: Address,
    remote: Address,
    remote_port: Port,
    taken: impl Fn(&FourTuple) -> bool,
) -> Option<FourTuple> {
    (0..DYNAMIC_SPAN)
        .map(|step| {
            // Below `DYNAMIC_SPAN` after the reduction, so the sum fits a u16.
            let offset = (start % DYNAMIC_SPAN + step) % DYNAMIC_SPAN;
            FourTuple {
                local,
                local_port: Port(DYNAMIC_FIRST + offset as u16),
                remote,
                remote_port,
            }
        })
        .find(|tuple| !taken(tuple))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addr::Ipv4Addr;

    fn here() -> Address {
        Address::V4(Ipv4Addr::new(10, 0, 2, 15))
    }

    fn peer(last: u8) -> Address {
        Address::V4(Ipv4Addr::new(10, 0, 2, last))
    }

    #[test]
    fn the_start_is_reduced_into_the_range() {
        let free = |_: &FourTuple| false;
        let port =
            |start| local_port(start, here(), peer(100), Port(9), free).map(|t| t.local_port);
        assert_eq!(port(0), Some(Port(DYNAMIC_FIRST)));
        assert_eq!(port(DYNAMIC_SPAN), Some(Port(DYNAMIC_FIRST)));
        assert_eq!(port(DYNAMIC_SPAN - 1), Some(Port(DYNAMIC_LAST)));
        assert_eq!(
            port(u64::MAX),
            Some(Port(DYNAMIC_FIRST + (u64::MAX % DYNAMIC_SPAN) as u16))
        );
    }

    #[test]
    fn the_tuple_is_the_one_asked_for() {
        let tuple = local_port(7, here(), peer(100), Port(9), |_| false).unwrap();
        assert_eq!(tuple.local, here());
        assert_eq!(tuple.remote, peer(100));
        assert_eq!(tuple.remote_port, Port(9));
        assert_eq!(tuple.local_port, Port(DYNAMIC_FIRST + 7));
    }

    #[test]
    fn a_taken_port_moves_the_search_on() {
        let start = 100;
        let taken = |t: &FourTuple| t.local_port.0 < DYNAMIC_FIRST + 103;
        let tuple = local_port(start, here(), peer(100), Port(9), taken).unwrap();
        assert_eq!(tuple.local_port, Port(DYNAMIC_FIRST + 103));
    }

    /// The edge of the range: the last port taken wraps the search to the first,
    /// never past 65535 and never below 49152.
    #[test]
    fn the_search_wraps_at_the_top_of_the_range() {
        let start = DYNAMIC_SPAN - 1;
        let taken = |t: &FourTuple| t.local_port == Port(DYNAMIC_LAST);
        let tuple = local_port(start, here(), peer(100), Port(9), taken).unwrap();
        assert_eq!(tuple.local_port, Port(DYNAMIC_FIRST));
    }

    #[test]
    fn a_full_range_is_none_and_every_port_was_asked_once() {
        let asked = core::cell::Cell::new(0_u64);
        let all = |t: &FourTuple| {
            asked.set(asked.get() + 1);
            assert!((DYNAMIC_FIRST..=DYNAMIC_LAST).contains(&t.local_port.0));
            true
        };
        assert_eq!(local_port(12345, here(), peer(100), Port(9), all), None);
        assert_eq!(asked.get(), DYNAMIC_SPAN);
    }

    /// The four-tuple, not the port: every port is in use toward one peer, and a
    /// different peer — even on the same port there — still gets the start.
    #[test]
    fn a_tuple_that_differs_only_in_the_peer_is_free() {
        let toward_one = |t: &FourTuple| t.remote == peer(100) && t.remote_port == Port(9);
        let other_peer = local_port(5, here(), peer(101), Port(9), toward_one).unwrap();
        assert_eq!(other_peer.local_port, Port(DYNAMIC_FIRST + 5));
        let other_port = local_port(5, here(), peer(100), Port(10), toward_one).unwrap();
        assert_eq!(other_port.local_port, Port(DYNAMIC_FIRST + 5));
        assert_eq!(local_port(5, here(), peer(100), Port(9), toward_one), None);
    }
}
