// SPDX-License-Identifier: Apache-2.0
//! Sockets, as arithmetic.
//!
//! [RFC 0005](../../docs/rfc/0005-linux-abi-compatibility.md)'s Tier 2. What
//! is decided here — and therefore host-tested — is what a `socket()` call
//! asks for, what a `sockaddr` a process handed over actually contains, and
//! which of the two is refused. What happens next is the adapter's: a UDP
//! socket is a badged capability from `bin/ipd` and a TCP connection is
//! RFC 0022's three-leg handover, and neither is anything this crate can
//! reach or wants to.
//!
//! ## The parser is the point
//!
//! `parse_endpoint` reads bytes a hosted process supplied, at a length the
//! same process chose. That is the shape of every remote-code-execution bug
//! in every personality layer ever written, which is why it is here — pure,
//! `no_std`, zero `unsafe`, total over its input, and fuzzed
//! (`fuzz/fuzz_targets/sockaddr.rs`). It cannot panic, cannot read past the
//! slice it was given, and answers an `errno` for everything it does not
//! understand.
//!
//! ## Where the layouts come from
//!
//! `sockaddr_in` (16 bytes), `sockaddr_in6` (28) and the `AF_*`/`SOCK_*`
//! values were taken **from this machine's `<netinet/in.h>` and
//! `<sys/socket.h>`** by a program printing `offsetof` and `sizeof`, not
//! from memory. The family is host-endian and the port is **network-endian
//! in the same structure**, which is the single most-often-recalled-wrong
//! fact in this file and the reason it is stated here.

/// Address families.
pub mod family {
    /// Local sockets. Refused: a `AF_UNIX` socket is a rendezvous named by a
    /// path in a shared namespace, and this system's rendezvous is an
    /// endpoint capability. Offering it would mean a global namespace,
    /// which RFC 0016 deleted on purpose.
    pub const UNIX: u16 = 1;
    /// IPv4.
    pub const INET: u16 = 2;
    /// IPv6.
    pub const INET6: u16 = 10;
    /// Raw device-level access. Refused, and it is the clearest example of
    /// this personality's second rule: a packet socket reaches the network
    /// device itself, which is `bin/netd`'s authority and not something a
    /// hosted process can be handed by asking for it.
    pub const PACKET: u16 = 17;
}

/// Socket types, and the flags Linux packs into the same argument.
pub mod kind {
    /// A byte stream — TCP.
    pub const STREAM: u64 = 1;
    /// Datagrams — UDP.
    pub const DGRAM: u64 = 2;
    /// Raw IP. Refused, for [`family::PACKET`]'s reason one layer up.
    pub const RAW: u64 = 3;
    /// The low bits carrying the type, below the flags.
    pub const MASK: u64 = 0xf;
    /// Do not block.
    pub const NONBLOCK: u64 = 0o4000;
    /// Close on `execve`.
    pub const CLOEXEC: u64 = 0o2_000_000;
}

/// Protocol numbers, as `socket()`'s third argument.
pub mod protocol {
    /// Let the type decide, which is what almost every caller passes.
    pub const DEFAULT: u64 = 0;
    /// TCP.
    pub const TCP: u64 = 6;
    /// UDP.
    pub const UDP: u64 = 17;
}

/// Errors this module answers with, as Linux numbers.
pub mod errno {
    /// Not permitted.
    pub const EPERM: i64 = -1;
    /// Bad address — a `sockaddr` that is not one.
    pub const EFAULT: i64 = -14;
    /// Invalid argument.
    pub const EINVAL: i64 = -22;
    /// This socket type is not supported.
    pub const ESOCKTNOSUPPORT: i64 = -94;
    /// This protocol is not supported for this family.
    pub const EPROTONOSUPPORT: i64 = -93;
    /// This address family is not supported.
    pub const EAFNOSUPPORT: i64 = -97;
    /// Function not implemented.
    pub const ENOSYS: i64 = -38;
    /// Input/output error — the call did not reach the service, or the
    /// refusal is this program's own mistake rather than the caller's.
    pub const EIO: i64 = -5;
    /// Bad file descriptor: it named a socket that has been closed.
    pub const EBADF: i64 = -9;
    /// Too many open files **in the system** — the service is full.
    ///
    /// `ENFILE` and not `EMFILE`: the caller's own descriptors are fine, and a
    /// program told it had too many of its own would go closing them to no
    /// effect. Confirmed against this machine's `asm-generic/errno-base.h`.
    pub const ENFILE: i64 = -23;
    /// That address is already in use.
    pub const EADDRINUSE: i64 = -98;
    /// The network is down. Confirmed against `asm-generic/errno.h`.
    pub const ENETDOWN: i64 = -100;
    /// Nothing to take yet, on a descriptor that asked not to wait.
    pub const EAGAIN: i64 = -11;
    /// An option this personality does not know at a level it does. Read
    /// from the build host's `asm-generic/errno.h`, as every value here.
    pub const ENOPROTOOPT: i64 = -92;
    /// A stream call on a socket that is not connected.
    pub const ENOTCONN: i64 = -107;
    /// A call a listening socket does not answer, or the reverse.
    pub const EOPNOTSUPP: i64 = -95;
    /// Writing to a stream whose other end is gone.
    pub const EPIPE: i64 = -32;
}

/// The bytes of a `struct sockaddr_in`. Confirmed against this machine's
/// headers.
pub const SOCKADDR_IN_BYTES: usize = 16;
/// The bytes of a `struct sockaddr_in6`. Likewise.
pub const SOCKADDR_IN6_BYTES: usize = 28;

/// A remote or local address, in the only two families this system has.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Endpoint {
    /// An IPv4 address and port, both in host order once parsed.
    V4 {
        /// The four address bytes, in the order they appear on the wire.
        address: [u8; 4],
        /// The port, host order.
        port: u16,
    },
    /// An IPv6 address and port.
    V6 {
        /// The sixteen address bytes, wire order.
        address: [u8; 16],
        /// The port, host order.
        port: u16,
        /// The scope id, which a link-local address needs and nothing else
        /// uses. Carried rather than dropped: dropping it silently turns
        /// `fe80::1%2` into an address that reaches the wrong link.
        scope: u32,
    },
}

impl Endpoint {
    /// How many bytes this endpoint occupies as a `sockaddr`.
    #[must_use]
    pub const fn bytes(&self) -> usize {
        match self {
            Self::V4 { .. } => SOCKADDR_IN_BYTES,
            Self::V6 { .. } => SOCKADDR_IN6_BYTES,
        }
    }
}

/// Reads a `sockaddr` a process supplied.
///
/// `given` is the length the *caller* claimed, which is not the length of
/// the buffer and must never be trusted as one — the slice is the truth.
/// Both are checked: a caller that says 16 and provides 4 is refused, and so
/// is one that provides 128 and says 4.
///
/// # Errors
///
/// [`errno::EINVAL`] for a length that cannot hold the family it names,
/// [`errno::EAFNOSUPPORT`] for a family this system does not have, and
/// [`errno::EFAULT`] when the claimed length exceeds what was given.
pub fn parse_endpoint(bytes: &[u8], given: usize) -> Result<Endpoint, i64> {
    if given > bytes.len() {
        return Err(errno::EFAULT);
    }
    let bytes = &bytes[..given];
    // Two bytes is the least that can name a family; anything shorter is not
    // a `sockaddr` at all and must be refused before the family is read.
    let family = match bytes.first_chunk::<2>() {
        Some(pair) => u16::from_le_bytes(*pair),
        None => return Err(errno::EINVAL),
    };
    match family {
        family::INET => {
            if bytes.len() < SOCKADDR_IN_BYTES {
                return Err(errno::EINVAL);
            }
            let port = u16::from_be_bytes([bytes[2], bytes[3]]);
            let address = [bytes[4], bytes[5], bytes[6], bytes[7]];
            Ok(Endpoint::V4 { address, port })
        }
        family::INET6 => {
            if bytes.len() < SOCKADDR_IN6_BYTES {
                return Err(errno::EINVAL);
            }
            let port = u16::from_be_bytes([bytes[2], bytes[3]]);
            let mut address = [0u8; 16];
            address.copy_from_slice(&bytes[8..24]);
            let scope = u32::from_le_bytes([bytes[24], bytes[25], bytes[26], bytes[27]]);
            Ok(Endpoint::V6 {
                address,
                port,
                scope,
            })
        }
        _ => Err(errno::EAFNOSUPPORT),
    }
}

/// Writes an endpoint back as a `sockaddr`, for `recvfrom`, `getsockname`
/// and `accept`.
///
/// Answers how many bytes the *whole* address is — which is what those calls
/// must report even when the caller's buffer was shorter, because that is
/// how a caller learns it was truncated. Writes no more than the buffer
/// holds.
///
/// # Errors
///
/// [`errno::EINVAL`] if the buffer cannot hold even the family.
pub fn write_endpoint(out: &mut [u8], endpoint: &Endpoint) -> Result<usize, i64> {
    if out.len() < 2 {
        return Err(errno::EINVAL);
    }
    let mut whole = [0u8; SOCKADDR_IN6_BYTES];
    let bytes = endpoint.bytes();
    match endpoint {
        Endpoint::V4 { address, port } => {
            whole[0..2].copy_from_slice(&family::INET.to_le_bytes());
            whole[2..4].copy_from_slice(&port.to_be_bytes());
            whole[4..8].copy_from_slice(address);
        }
        Endpoint::V6 {
            address,
            port,
            scope,
        } => {
            whole[0..2].copy_from_slice(&family::INET6.to_le_bytes());
            whole[2..4].copy_from_slice(&port.to_be_bytes());
            whole[8..24].copy_from_slice(address);
            whole[24..28].copy_from_slice(&scope.to_le_bytes());
        }
    }
    let copied = out.len().min(bytes);
    out[..copied].copy_from_slice(&whole[..copied]);
    Ok(bytes)
}

/// What kind of socket a `socket()` call asked for.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SocketPlan {
    /// IPv6 rather than IPv4.
    pub v6: bool,
    /// A stream (TCP) rather than a datagram (UDP).
    pub stream: bool,
    /// Never block.
    pub non_blocking: bool,
    /// Close on `execve`.
    pub close_on_exec: bool,
}

/// Reads `socket(domain, type, protocol)`.
///
/// **Every refusal here is one of RFC 0031's invariants doing its job**, not
/// an omission: a raw or packet socket is a request for the network device's
/// own authority, which belongs to `bin/netd` and is not obtainable by
/// asking, and a Unix socket is a request for a global namespace this system
/// deleted. Each is answered with the `errno` Linux uses for "this kernel
/// does not offer that", so a program that handles the refusal handles this.
///
/// # Errors
///
/// [`errno::EAFNOSUPPORT`], [`errno::ESOCKTNOSUPPORT`],
/// [`errno::EPROTONOSUPPORT`], or [`errno::EPERM`] for a raw socket, which
/// is what an unprivileged Linux process gets and therefore what a program
/// is prepared for.
pub fn plan_socket(domain: u64, socket_type: u64, protocol: u64) -> Result<SocketPlan, i64> {
    let v6 = match u16::try_from(domain) {
        Ok(family::INET) => false,
        Ok(family::INET6) => true,
        _ => return Err(errno::EAFNOSUPPORT),
    };
    let stream = match socket_type & kind::MASK {
        kind::STREAM => true,
        kind::DGRAM => false,
        kind::RAW => return Err(errno::EPERM),
        _ => return Err(errno::ESOCKTNOSUPPORT),
    };
    let wanted = if stream { protocol::TCP } else { protocol::UDP };
    if protocol != protocol::DEFAULT && protocol != wanted {
        return Err(errno::EPROTONOSUPPORT);
    }
    // A flag bit outside the two Linux defines is refused rather than
    // ignored: unlike `open`, this argument's spare bits are the *type*
    // field's neighbours, and a caller that set one meant something.
    if socket_type & !(kind::MASK | kind::NONBLOCK | kind::CLOEXEC) != 0 {
        return Err(errno::EINVAL);
    }
    Ok(SocketPlan {
        v6,
        stream,
        non_blocking: socket_type & kind::NONBLOCK != 0,
        close_on_exec: socket_type & kind::CLOEXEC != 0,
    })
}

/// The socket service's outcome words, **mirrored** from `bhaskix_abi::socket`.
///
/// # Why mirrored rather than imported
///
/// `tools/check-deps.py` enforces `docs/architecture.md` §5: dependencies point
/// strictly downward, and `bhaskix-abi` sits on this crate's own layer. So this
/// crate cannot name it, and a table mapping the service's answers to Linux
/// errnos has to hold both vocabularies somehow.
///
/// The copy is kept honest at the one place that legitimately speaks both:
/// `bin/linuxd` asserts each of these equals its ABI original at compile time,
/// which is the same idiom the nucleus uses for every method number both sides
/// name. A drift is a build failure there, not a wrong errno here.
pub mod outcome {
    /// It worked.
    pub const OK: u64 = 0;
    /// That port is already bound.
    pub const NO_PORT: u64 = 1;
    /// The socket has been closed and its slot may be somebody else's.
    pub const GONE: u64 = 2;
    /// Nothing has arrived.
    pub const EMPTY: u64 = 3;
    /// The caller never said where a capability may land.
    pub const NOWHERE: u64 = 4;
    /// No device, or no window to drive one through.
    pub const NO_NETWORK: u64 = 5;
    /// A v4 call about a v6 socket, or the reverse.
    pub const WRONG_FAMILY: u64 = 6;
    /// The service has no socket left to give.
    pub const NO_SOCKET: u64 = 7;
}

/// What a hosted program should be told when the socket service refuses.
///
/// # Why this exists
///
/// Every failed `bind` answered `EADDRINUSE` — the only errno the adapter could
/// honestly guess at while the service had one word for several refusals. That
/// guess **misdirected three separate investigations in one day**, twice
/// pointing at a port number that had nothing to do with the failure: a
/// capability slot collision, a service whose socket table was full, and a
/// close whose answer had been thrown away. RFC 0056's status line recorded the
/// conflation; `socket::NO_SOCKET` ended it on the service's side, and this is
/// the other half.
///
/// A pure function over the outcome word, so the table is host-tested rather
/// than read.
#[must_use]
pub fn errno_for(answer: u64) -> i64 {
    use outcome as socket;

    match answer {
        // That port belongs to somebody. The one case the old guess was right
        // about, and a caller can act on it -- pick another port.
        socket::NO_PORT => errno::EADDRINUSE,
        // The *service* is full. A system-wide limit, which is what `ENFILE`
        // says and `EMFILE` does not: the caller's own descriptors are fine.
        socket::NO_SOCKET => errno::ENFILE,
        // The capability named a socket that has been closed. From the
        // program's side that is a descriptor that no longer names anything.
        socket::GONE => errno::EBADF,
        // There is no network to bind on. `ENETDOWN` is exactly this, and it
        // is what lets a program tell "nothing answered" from "there is
        // nothing to answer" -- the distinction the service draws by name.
        socket::NO_NETWORK => errno::ENETDOWN,
        // A v4 call about a v6 socket or the reverse.
        socket::WRONG_FAMILY => errno::EAFNOSUPPORT,
        // The adapter did not declare where a capability could land. That is
        // this program's bug and not the caller's, and `EIO` says so without
        // inventing a reason the caller could act on.
        socket::NOWHERE => errno::EIO,
        // Anything else, including a refusal from the kernel rather than the
        // service: the call did not arrive.
        _ => errno::EIO,
    }
}

/// Socket option levels and names — RFC 0086 step 3b. Read from the build
/// host's `asm-generic/socket.h`, `netinet/tcp.h`, `linux/in6.h` and
/// `linux/in.h` on 2026-09-30, not recalled.
pub mod option {
    /// `SOL_SOCKET`.
    pub const SOL_SOCKET: u64 = 1;
    /// `IPPROTO_TCP`, which is also the level for TCP's options.
    pub const IPPROTO_TCP: u64 = 6;
    /// `IPPROTO_IPV6`.
    pub const IPPROTO_IPV6: u64 = 41;
    /// `SO_REUSEADDR`.
    pub const SO_REUSEADDR: u64 = 2;
    /// `SO_ERROR`, read-only: the pending error, taken as it is read.
    pub const SO_ERROR: u64 = 4;
    /// `SO_BROADCAST`.
    pub const SO_BROADCAST: u64 = 6;
    /// `SO_KEEPALIVE`.
    pub const SO_KEEPALIVE: u64 = 9;
    /// `TCP_NODELAY`.
    pub const TCP_NODELAY: u64 = 1;
    /// `TCP_KEEPIDLE`.
    pub const TCP_KEEPIDLE: u64 = 4;
    /// `TCP_KEEPINTVL`.
    pub const TCP_KEEPINTVL: u64 = 5;
    /// `IPV6_V6ONLY`.
    pub const IPV6_V6ONLY: u64 = 26;
}

/// An option `setsockopt` accepts — the seven a Go `net/http` server was
/// traced setting (RFC 0086 step 1).
///
/// **Accepted is not honoured**, and the difference is stated here rather
/// than left for a reader to assume: `bin/tcpd` has no Nagle delay to turn
/// off, sends no keepalives, and binds nothing a second time, so
/// `TCP_NODELAY`, the keepalive options and `SO_REUSEADDR` change nothing it
/// does. They are accepted because refusing them would stop a correct
/// program for asking about behaviour this system already has or does not
/// offer. Only `IPV6_V6ONLY` is *kept*: it decides how an IPv4 peer is
/// written back to a v6 socket.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SockOpt {
    /// `SO_REUSEADDR`.
    ReuseAddr,
    /// `SO_KEEPALIVE`.
    KeepAlive,
    /// `SO_BROADCAST`.
    Broadcast,
    /// `TCP_NODELAY`.
    NoDelay,
    /// `TCP_KEEPIDLE`.
    KeepIdle,
    /// `TCP_KEEPINTVL`.
    KeepInterval,
    /// `IPV6_V6ONLY`, with whether it was set.
    V6Only,
}

/// What `setsockopt(level, name, _, length)` is asking for.
///
/// # Errors
///
/// [`errno::EINVAL`] for a value shorter than the `int` every one of these
/// takes; [`errno::ENOPROTOOPT`] for an option this personality does not
/// know — what Linux answers for a name it does not recognise.
pub fn plan_setsockopt(level: u64, name: u64, length: u64) -> Result<SockOpt, i64> {
    let known = match (level, name) {
        (option::SOL_SOCKET, option::SO_REUSEADDR) => SockOpt::ReuseAddr,
        (option::SOL_SOCKET, option::SO_KEEPALIVE) => SockOpt::KeepAlive,
        (option::SOL_SOCKET, option::SO_BROADCAST) => SockOpt::Broadcast,
        (option::IPPROTO_TCP, option::TCP_NODELAY) => SockOpt::NoDelay,
        (option::IPPROTO_TCP, option::TCP_KEEPIDLE) => SockOpt::KeepIdle,
        (option::IPPROTO_TCP, option::TCP_KEEPINTVL) => SockOpt::KeepInterval,
        (option::IPPROTO_IPV6, option::IPV6_V6ONLY) => SockOpt::V6Only,
        _ => return Err(errno::ENOPROTOOPT),
    };
    if length < 4 {
        return Err(errno::EINVAL);
    }
    Ok(known)
}

/// How a TCP peer is written back to a hosted program — RFC 0086 step 3b.
///
/// A v4 socket gets the v4 address. A **v6 socket that is not `V6ONLY` gets a
/// v4 peer as `::ffff:a.b.c.d`**, which is what Linux does and what a
/// dual-stack server — Go's `net/http` listens on `::` that way, as the step 1
/// trace showed — expects to parse. A `V6ONLY` socket cannot have a v4 peer at
/// all, so `None` says that is a mistake upstream rather than inventing one.
#[must_use]
pub fn peer_endpoint(v6_socket: bool, v6_only: bool, peer: [u8; 4], port: u16) -> Option<Endpoint> {
    if !v6_socket {
        return Some(Endpoint::V4 {
            address: peer,
            port,
        });
    }
    if v6_only {
        return None;
    }
    let mut address = [0u8; 16];
    address[10] = 0xff;
    address[11] = 0xff;
    address[12..].copy_from_slice(&peer);
    Some(Endpoint::V6 {
        address,
        port,
        scope: 0,
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_seven_traced_options_are_accepted_and_nothing_else_is() {
        use option::*;
        for (level, name) in [
            (SOL_SOCKET, SO_REUSEADDR),
            (SOL_SOCKET, SO_KEEPALIVE),
            (SOL_SOCKET, SO_BROADCAST),
            (IPPROTO_TCP, TCP_NODELAY),
            (IPPROTO_TCP, TCP_KEEPIDLE),
            (IPPROTO_TCP, TCP_KEEPINTVL),
            (IPPROTO_IPV6, IPV6_V6ONLY),
        ] {
            assert!(plan_setsockopt(level, name, 4).is_ok(), "{level}/{name}");
            assert_eq!(
                plan_setsockopt(level, name, 2),
                Err(errno::EINVAL),
                "short {level}/{name}"
            );
        }
        // A real option at the wrong level, and a name nobody set.
        assert_eq!(
            plan_setsockopt(SOL_SOCKET, TCP_KEEPIDLE, 4),
            Err(errno::ENOPROTOOPT)
        );
        assert_eq!(plan_setsockopt(IPPROTO_TCP, 99, 4), Err(errno::ENOPROTOOPT));
        assert_eq!(plan_setsockopt(0, SO_REUSEADDR, 4), Err(errno::ENOPROTOOPT));
    }

    #[test]
    fn a_v4_peer_is_v4_mapped_on_a_dual_stack_socket_and_refused_on_a_v6_only_one() {
        let peer = [10, 0, 2, 2];
        assert_eq!(
            peer_endpoint(false, false, peer, 4000),
            Some(Endpoint::V4 {
                address: peer,
                port: 4000
            })
        );
        let Some(Endpoint::V6 {
            address,
            port,
            scope,
        }) = peer_endpoint(true, false, peer, 4000)
        else {
            panic!("a dual-stack socket gets a v6 answer");
        };
        assert_eq!(
            address,
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 2, 2]
        );
        assert_eq!((port, scope), (4000, 0));
        assert_eq!(peer_endpoint(true, true, peer, 4000), None);
        // And it writes as a `sockaddr_in6` a program can read back.
        let mut out = [0u8; SOCKADDR_IN6_BYTES];
        let written =
            write_endpoint(&mut out, &peer_endpoint(true, false, peer, 4000).unwrap()).unwrap();
        assert_eq!(
            parse_endpoint(&out, written),
            peer_endpoint(true, false, peer, 4000).ok_or(0)
        );
    }

    #[test]
    fn a_taken_port_and_a_full_service_are_different_answers() {
        use outcome as socket;

        // The whole point: one is the caller's to act on, the other is not.
        assert_eq!(errno_for(socket::NO_PORT), errno::EADDRINUSE);
        assert_eq!(errno_for(socket::NO_SOCKET), errno::ENFILE);
        assert_ne!(errno_for(socket::NO_PORT), errno_for(socket::NO_SOCKET));
    }

    #[test]
    fn no_network_is_not_a_busy_port() {
        use outcome as socket;

        // A machine with no network answering EADDRINUSE would have a program
        // retrying other ports for ever.
        assert_eq!(errno_for(socket::NO_NETWORK), errno::ENETDOWN);
        assert_eq!(errno_for(socket::WRONG_FAMILY), errno::EAFNOSUPPORT);
        assert_eq!(errno_for(socket::GONE), errno::EBADF);
    }

    #[test]
    fn the_adapters_own_mistake_is_not_blamed_on_the_caller() {
        use outcome as socket;

        // `NOWHERE` means this program forgot to declare a landing slot.
        assert_eq!(errno_for(socket::NOWHERE), errno::EIO);
        // And anything unrecognised is EIO rather than a guess with a story.
        assert_eq!(errno_for(9_999), errno::EIO);
    }

    #[test]
    fn every_answer_is_a_refusal() {
        use outcome as socket;

        for answer in [
            socket::NO_PORT,
            socket::NO_SOCKET,
            socket::GONE,
            socket::NO_NETWORK,
            socket::WRONG_FAMILY,
            socket::NOWHERE,
            12345,
        ] {
            assert!(errno_for(answer) < 0, "{answer} mapped to a success");
        }
    }

    use super::*;

    #[test]
    fn a_v4_sockaddr_round_trips_with_the_port_in_network_order() {
        // 127.0.0.1:8080. The port bytes are 0x1f 0x90 on the wire, and a
        // parser that read them host-endian would answer 36895 — a number
        // that looks like a port and connects to the wrong service.
        let bytes = [
            2, 0, // AF_INET, host order
            0x1f, 0x90, // port 8080, network order
            127, 0, 0, 1, // address
            0, 0, 0, 0, 0, 0, 0, 0, // sin_zero
        ];
        let parsed = parse_endpoint(&bytes, SOCKADDR_IN_BYTES).expect("legal");
        assert_eq!(
            parsed,
            Endpoint::V4 {
                address: [127, 0, 0, 1],
                port: 8080
            }
        );
        let mut out = [0u8; SOCKADDR_IN_BYTES];
        assert_eq!(write_endpoint(&mut out, &parsed), Ok(SOCKADDR_IN_BYTES));
        assert_eq!(out, bytes);
    }

    #[test]
    fn a_v6_sockaddr_round_trips_and_keeps_its_scope() {
        let mut bytes = [0u8; SOCKADDR_IN6_BYTES];
        bytes[0..2].copy_from_slice(&family::INET6.to_le_bytes());
        bytes[2..4].copy_from_slice(&443u16.to_be_bytes());
        bytes[8] = 0xfe;
        bytes[9] = 0x80;
        bytes[23] = 1;
        bytes[24..28].copy_from_slice(&2u32.to_le_bytes());
        let parsed = parse_endpoint(&bytes, SOCKADDR_IN6_BYTES).expect("legal");
        let Endpoint::V6 { port, scope, .. } = parsed else {
            panic!("v6")
        };
        assert_eq!(port, 443);
        // Dropping this silently sends a link-local address down the wrong
        // link, and nothing reports an error anywhere.
        assert_eq!(scope, 2);
        let mut out = [0u8; SOCKADDR_IN6_BYTES];
        assert_eq!(write_endpoint(&mut out, &parsed), Ok(SOCKADDR_IN6_BYTES));
        assert_eq!(out, bytes);
    }

    #[test]
    fn a_short_or_lying_sockaddr_is_refused_and_not_read() {
        // Says sixteen, gives four.
        assert_eq!(parse_endpoint(&[2, 0, 0, 0], 16), Err(errno::EFAULT));
        // A v4 family in a buffer too short to hold a v4 address.
        assert_eq!(parse_endpoint(&[2, 0, 0, 0], 4), Err(errno::EINVAL));
        // A v6 family in a v4-sized buffer — the length that would be legal
        // for the other family, which is the interesting confusion.
        let mut short = [0u8; SOCKADDR_IN_BYTES];
        short[0..2].copy_from_slice(&family::INET6.to_le_bytes());
        assert_eq!(
            parse_endpoint(&short, SOCKADDR_IN_BYTES),
            Err(errno::EINVAL)
        );
        // Nothing, one byte, and a family nobody has.
        assert_eq!(parse_endpoint(&[], 0), Err(errno::EINVAL));
        assert_eq!(parse_endpoint(&[2], 1), Err(errno::EINVAL));
        assert_eq!(parse_endpoint(&[99, 0, 0, 0], 4), Err(errno::EAFNOSUPPORT));
    }

    #[test]
    fn the_families_this_system_refuses_are_refused_by_name() {
        let unix = [1u8, 0, 0, 0];
        assert_eq!(parse_endpoint(&unix, 4), Err(errno::EAFNOSUPPORT));
        assert_eq!(
            plan_socket(u64::from(family::UNIX), kind::STREAM, 0),
            Err(errno::EAFNOSUPPORT)
        );
        assert_eq!(
            plan_socket(u64::from(family::PACKET), kind::DGRAM, 0),
            Err(errno::EAFNOSUPPORT)
        );
        // A raw socket is the network device's own authority asked for by a
        // number. `EPERM` is what an unprivileged Linux process is told, so
        // a program that copes with that copes with this.
        assert_eq!(
            plan_socket(u64::from(family::INET), kind::RAW, 0),
            Err(errno::EPERM)
        );
    }

    #[test]
    fn socket_arguments_decode() {
        let plan = plan_socket(
            u64::from(family::INET),
            kind::STREAM | kind::NONBLOCK | kind::CLOEXEC,
            protocol::TCP,
        )
        .expect("legal");
        assert_eq!(
            plan,
            SocketPlan {
                v6: false,
                stream: true,
                non_blocking: true,
                close_on_exec: true
            }
        );
        let udp6 =
            plan_socket(u64::from(family::INET6), kind::DGRAM, protocol::DEFAULT).expect("legal");
        assert!(udp6.v6 && !udp6.stream && !udp6.non_blocking);

        // A stream asked to carry UDP, and a datagram asked to carry TCP.
        assert_eq!(
            plan_socket(u64::from(family::INET), kind::STREAM, protocol::UDP),
            Err(errno::EPROTONOSUPPORT)
        );
        assert_eq!(
            plan_socket(u64::from(family::INET), kind::DGRAM, protocol::TCP),
            Err(errno::EPROTONOSUPPORT)
        );
        assert_eq!(
            plan_socket(u64::from(family::INET), 9, 0),
            Err(errno::ESOCKTNOSUPPORT)
        );
        assert_eq!(
            plan_socket(u64::from(family::INET), kind::STREAM | 1 << 40, 0),
            Err(errno::EINVAL)
        );
    }

    #[test]
    fn a_short_output_buffer_is_truncated_and_says_the_whole_length() {
        let endpoint = Endpoint::V4 {
            address: [10, 0, 0, 7],
            port: 53,
        };
        let mut out = [0xffu8; 4];
        // The answer is the length of the whole address, not what fitted —
        // which is exactly how a caller learns it was truncated.
        assert_eq!(write_endpoint(&mut out, &endpoint), Ok(SOCKADDR_IN_BYTES));
        assert_eq!(out, [2, 0, 0, 53]);
        let mut nothing = [0u8; 1];
        assert_eq!(write_endpoint(&mut nothing, &endpoint), Err(errno::EINVAL));
    }

    #[test]
    fn the_parser_is_total_over_short_inputs() {
        // The property the fuzz target checks at length; this is the cheap
        // version that runs on every build. No input of any length may
        // panic, and none may answer success for a length it cannot hold.
        let bytes = [2u8, 0, 10, 20, 30, 40, 50, 60, 70, 80];
        for family in [0u8, 1, 2, 10, 17, 255] {
            for length in 0..=bytes.len() {
                let mut input = bytes;
                input[0] = family;
                match parse_endpoint(&input, length) {
                    Ok(endpoint) => assert!(endpoint.bytes() <= length),
                    Err(errno) => assert!(errno < 0),
                }
            }
        }
    }
}
