// SPDX-License-Identifier: Apache-2.0
//! Hosted TCP, the server side — [RFC 0086](../../../docs/rfc/0086-the-motivating-workload.md)
//! step 3b.
//!
//! A hosted program's stream socket is this adapter's: the listener and every
//! connection are capabilities to `bin/tcpd` the adapter holds (RFC 0033's
//! model — a descriptor is a capability the adapter holds for the process),
//! and the bytes move through **stream rings the adapter owns**, from a pool
//! the kernel granted it at start. The pool was the project lead's choice over
//! a kernel method for making memory (2026-09-30), and it bounds hosted TCP
//! machine-wide: seventeen ring pairs, a listener's first plus sixteen
//! connections.
//!
//! # What is interim, said here
//!
//! - **A blocking `accept` or `read` waits by retrying**, parked ten
//!   milliseconds at a time. `bin/tcpd` rings [`adapter::TCP_WAKE`] when there
//!   is news, but a notification has one waiter and several hosted threads may
//!   block; step 4's `epoll` is where readiness replaces the retry.
//!   **Since step 4 (2026-09-30)** a blocking wait parks on that
//!   wake when nobody else holds it -- see [`park_on_wake`] -- and falls back
//!   to the ten-millisecond retry only when somebody does. It matters beyond
//!   speed: a blocking `accept` that waited a second on the retry was
//!   answered `EAGAIN` -- **reproduced 2026-09-30** by holding the host back
//!   one second: `htcp fail 4 0b` on the retry, served on the wake. Which of
//!   the retry path's two `EAGAIN`s it was (the nucleus parks one call at
//!   most sixteen times; the adapter may find no timed-wait slot) is not
//!   established, and `TRACKER.md` says so.
//! - **A pair given to a listener stays with it.** `bin/tcpd` has no way to
//!   stop listening, so a hosted listener that closes keeps its pairs for the
//!   life of the boot.
//! - **The send side has no flow control the adapter can see.** `bin/tcpd`
//!   tells a client how far the peer's stream has reached, not how much of its
//!   own it has acknowledged, so a write is bounded to a page and trusts the
//!   peer to keep acknowledging. Request-and-response traffic does; a bulk
//!   writer racing sixteen kilobytes ahead of its acknowledgements would
//!   overwrite its own unsent bytes. Stated, not solved.

use bhaskix_abi::{adapter, method, status, syscall};
use bhaskix_personality::call::{Answer, PersonalityCall};
use bhaskix_personality::file::{Entry, Kind};
use bhaskix_personality::poll::Condition;
use bhaskix_personality::socket::{self, Endpoint, SockOpt, errno, write_endpoint};
use bhaskix_sock::ring::RingView;
use bhaskix_sock::tcp::{self, AcceptPoll, Peer, StreamPoll};
use core::sync::atomic::AtomicU64;
use core::sync::atomic::Ordering::Relaxed;

use super::{REPLY_BLOCK_ON_RETRY, REPLY_VALUE};

/// Where the adapter maps its ring pool: ring `i` at `RINGS_AT + i * RING_BYTES`.
const RINGS_AT: u64 = 0x0000_0000_2800_0000;
/// Bytes in each ring, as the kernel granted them.
const RING_BYTES: u64 = 4 * 4096;
/// Ring pairs in the pool.
const PAIRS: usize = adapter::TCP_RING_COUNT / 2;
/// Hosted stream sockets at once, in every state — fresh ones included, which
/// a Go program opens a few of just to probe what the machine supports.
const MAX_STREAMS: usize = 32;
/// The bit on a socket descriptor's `offset` that says it is a stream. The low
/// bit is the family (v6), as for datagram sockets; the datagram paths test
/// this first so a stream never reaches them.
pub(crate) const STREAM_TAG: u64 = 2;
/// How long a blocking call waits before it looks again.
const RETRY_NANOS: u64 = 10_000_000;
/// The most bytes one `read` or `write` moves.
const CHUNK: usize = 4096;

/// `tcpd`'s state numbers: a peer can still send while the connection is
/// established or this end is closing; anything else with nothing delivered
/// is the end of the stream.
fn peer_may_send(state: u64) -> bool {
    matches!(state, 4..=6)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Fresh,
    Bound {
        port: u16,
    },
    Listening {
        port: u16,
        listener: usize,
    },
    /// A `connect` under way — RFC 0090 step 4. Its connection is in the
    /// table from the moment `bin/tcpd` dialled, and becomes [`State::Connected`]
    /// once it opens; until then nothing reads or writes it.
    Connecting {
        connection: usize,
    },
    Connected {
        connection: usize,
    },
}

#[derive(Clone, Copy)]
struct Stream {
    domain: u32,
    state: State,
    v6: bool,
    v6_only: bool,
    nonblocking: bool,
}

#[derive(Clone, Copy)]
struct Connection {
    /// Which of the adapter's pairs its bytes live in.
    pool: usize,
    /// Bytes the program has read, and how many of them `tcpd` has been told
    /// of — the difference reopens the receive window on the next `RECV`.
    consumed: u64,
    told: u64,
    /// Bytes the program has written.
    sent: u64,
    peer: Peer,
    local_port: u16,
    /// Taken from `tcpd` and not yet given to the program: the listener it
    /// waits in. Step 4 accepts **eagerly**, because `tcpd` has no way to ask
    /// whether a connection waits without taking it, and `epoll` must be able
    /// to say a listener is readable without an `accept`.
    pending_on: Option<usize>,
    /// When it was taken, so `accept` hands out the oldest first.
    born: u64,
    /// A dial that ended before it opened — RFC 0090 step 4 — and its error
    /// until somebody takes it: `SO_ERROR`, `read`, `write` or `connect`,
    /// whichever asks first, as Linux's `sock_error` hands it to one caller.
    failed: bool,
    pending: i64,
    /// A dial that has opened and no `connect` has said so yet. The next one
    /// answers `0`, and every one after it `EISCONN` — Linux's socket stays
    /// connecting until a `connect` sees it open, while its data already flows.
    owed_zero: bool,
}

struct Tcp {
    ready: bool,
    /// Rings of the pool mapped so far, in order. Mapping resumes here, so a
    /// ring already mapped is never asked to map again.
    mapped: usize,
    streams: [Option<Stream>; MAX_STREAMS],
    listeners: [bool; adapter::TCP_LISTENER_COUNT],
    connections: [Option<Connection>; adapter::TCP_CONNECTION_COUNT],
    /// Pool pairs given to a listener so far; they are never given back.
    pool_used: usize,
    /// `tcpd`'s pair number → the adapter's pool pair, plus one (0: unknown).
    pool_of: [u8; 64],
    /// Connections each listener has been given, ever: the news an
    /// edge-triggered `epoll` interest in it counts.
    births: [u64; adapter::TCP_LISTENER_COUNT],
    /// Connections taken, ever, for [`Connection::born`].
    taken: u64,
}

static mut TCP: Tcp = Tcp {
    ready: false,
    mapped: 0,
    streams: [None; MAX_STREAMS],
    listeners: [false; adapter::TCP_LISTENER_COUNT],
    connections: [None; adapter::TCP_CONNECTION_COUNT],
    pool_used: 0,
    pool_of: [0; 64],
    births: [0; adapter::TCP_LISTENER_COUNT],
    taken: 0,
};

fn tcp() -> &'static mut Tcp {
    // SAFETY: single-threaded by construction, as every table in this program:
    // it has one thread, which runs one call to completion before the next.
    unsafe { &mut *core::ptr::addr_of_mut!(TCP) }
}

/// Ring `index` of the pool, as a view.
fn view(index: usize) -> RingView {
    // SAFETY: only reached once `init` has mapped all of the pool at these
    // addresses (`ready`), and they stay mapped for this program's life.
    unsafe { RingView::new(RINGS_AT + index as u64 * RING_BYTES, RING_BYTES) }
}

/// Maps the ring pool, if the kernel has granted one, and says whether all of
/// it is mapped. Without it every stream socket is refused as before this
/// step, which is what a machine with no TCP service should say.
///
/// **Asked again on every stream `socket()` until it is true, not once at
/// start** -- and the first version asked once, which is the bug this says:
/// this program starts early in the boot and the kernel grants the pool much
/// later, once `bin/tcpd` exists, so the one look at start found nothing and
/// every hosted stream was refused for the rest of the boot. Mapping resumes
/// at the first ring not yet mapped, so asking again never asks a mapped ring
/// to map twice.
pub(crate) fn init() -> bool {
    let table = tcp();
    while !table.ready && table.mapped < adapter::TCP_RING_COUNT {
        let index = table.mapped;
        let attached = super::call(
            syscall::INVOKE,
            (adapter::TCP_RINGS + index) as u64,
            method::ATTACH,
            [RINGS_AT + index as u64 * RING_BYTES, 1, 0, 0],
        );
        if attached.status != status::OK {
            return false;
        }
        table.mapped += 1;
    }
    table.ready = table.mapped == adapter::TCP_RING_COUNT;
    table.ready
}

/// Whether a descriptor row is a stream socket.
pub(crate) fn is_stream(entry: &Entry) -> bool {
    entry.kind == Kind::Socket && entry.offset & STREAM_TAG != 0
}

fn stream_of(request: &PersonalityCall, descriptor: u64) -> Result<(usize, Stream), i64> {
    let descriptor = i32::try_from(descriptor).map_err(|_| errno::EBADF)?;
    let process = super::process_for(request.domain).ok_or(errno::EAGAIN)?;
    let entry = process
        .descriptors
        .get(descriptor)
        .copied()
        .ok_or(errno::EBADF)?;
    if entry.kind != Kind::Socket {
        return Err(-88); // ENOTSOCK
    }
    if !is_stream(&entry) {
        return Err(errno::EOPNOTSUPP);
    }
    let index = entry.handle as usize;
    let stream = tcp()
        .streams
        .get(index)
        .copied()
        .flatten()
        .ok_or(errno::EBADF)?;
    Ok((index, stream))
}

fn install(request: &PersonalityCall, stream: Stream, close_on_exec: bool) -> Answer {
    let Some(index) = tcp().streams.iter().position(Option::is_none) else {
        return Answer::error(errno::ENFILE);
    };
    let Some(process) = super::process_for(request.domain) else {
        return Answer::error(errno::EAGAIN);
    };
    let entry = Entry {
        handle: index as u64,
        inode: 0,
        kind: Kind::Socket,
        close_on_exec,
        offset: STREAM_TAG | u64::from(stream.v6),
        size: 0,
        readable: true,
        writable: true,
    };
    match process.descriptors.insert(entry, 0) {
        Ok(descriptor) => {
            tcp().streams[index] = Some(stream);
            Answer::ok(descriptor as u64)
        }
        Err(code) => Answer::error(code),
    }
}

/// `socket(AF_INET or AF_INET6, SOCK_STREAM, …)`.
pub(crate) fn socket(request: &PersonalityCall, plan: &socket::SocketPlan) -> Answer {
    if !init() {
        return Answer::error(errno::EPROTONOSUPPORT);
    }
    install(
        request,
        Stream {
            domain: request.domain,
            state: State::Fresh,
            v6: plan.v6,
            v6_only: false,
            nonblocking: plan.non_blocking,
        },
        plan.close_on_exec,
    )
}

/// `bind` on a stream socket: records the port. Nothing is claimed from the
/// service until `listen`, which is where a port becomes a listener.
pub(crate) fn bind(request: &PersonalityCall, port: u16, v6: bool) -> Answer {
    let (index, stream) = match stream_of(request, request.first()) {
        Ok(found) => found,
        Err(code) => return Answer::error(code),
    };
    if stream.state != State::Fresh {
        return Answer::error(errno::EINVAL);
    }
    if v6 != stream.v6 {
        return Answer::error(errno::EAFNOSUPPORT);
    }
    tcp().streams[index] = Some(Stream {
        state: State::Bound { port },
        ..stream
    });
    Answer::ok(0)
}

/// `listen(fd, backlog)`: a listener of the adapter's own on `tcpd`, armed
/// with as many of the pool's pairs as the backlog asks and the pool has.
pub(crate) fn listen(request: &PersonalityCall) -> Answer {
    let (index, stream) = match stream_of(request, request.first()) {
        Ok(found) => found,
        Err(code) => return Answer::error(code),
    };
    let port = match stream.state {
        State::Bound { port } => port,
        State::Listening { .. } => return Answer::ok(0),
        _ => return Answer::error(errno::EINVAL),
    };
    let table = tcp();
    let Some(listener) = table.listeners.iter().position(|used| !used) else {
        return Answer::error(errno::ENFILE);
    };
    if table.pool_used >= PAIRS {
        return Answer::error(-105); // ENOBUFS
    }
    let first = table.pool_used;
    let opened = tcp::listen_open(
        adapter::TCP_SERVICE as u64,
        port,
        (
            (adapter::TCP_RINGS + 2 * first) as u64,
            (adapter::TCP_RINGS + 2 * first + 1) as u64,
        ),
        Some((adapter::TCP_WAKE as u64, adapter::TCP_WAKE_BADGE)),
        (adapter::TCP_LISTENERS + listener) as u64,
    );
    let (_, pair) = match opened {
        Ok(opened) => opened,
        // The port is held by somebody else's listener.
        Err(tcp::LegError::Refused { value, .. }) if value == bhaskix_abi::tcp::REFUSED => {
            return Answer::error(errno::EADDRINUSE);
        }
        Err(_) => return Answer::error(errno::EIO),
    };
    table.pool_used += 1;
    if let Some(slot) = table.pool_of.get_mut(pair as usize) {
        *slot = first as u8 + 1;
    }
    table.listeners[listener] = true;

    // More pairs, up to the backlog and the pool. A backlog of one is the
    // listener's first pair alone.
    let backlog = (request.second() as i32).max(1) as usize;
    for _ in 1..backlog {
        if table.pool_used >= PAIRS {
            break;
        }
        let next = table.pool_used;
        let Ok(pair) = tcp::arm_pair(
            (adapter::TCP_LISTENERS + listener) as u64,
            (adapter::TCP_RINGS + 2 * next) as u64,
            (adapter::TCP_RINGS + 2 * next + 1) as u64,
        ) else {
            break;
        };
        table.pool_used += 1;
        if let Some(slot) = table.pool_of.get_mut(pair as usize) {
            *slot = next as u8 + 1;
        }
    }
    table.streams[index] = Some(Stream {
        state: State::Listening { port, listener },
        ..stream
    });
    Answer::ok(0)
}

/// Who is parked on [`adapter::TCP_WAKE`]: `(domain + 1) << 32 | thread`, or
/// 0 for nobody.
///
/// **One owner, because the nucleus allows one waiter** (RFC 0010): a second
/// park on the same notification is refused, and a refused park is a hosted
/// call answered `EAGAIN`. So the wake is claimed by exactly one parked
/// thread, given back when that thread's call comes back, and everybody else
/// waits the old way. An atomic, so this adds nothing to the `unsafe` budget.
static WAKE_OWNER: AtomicU64 = AtomicU64::new(0);

const fn wake_key(domain: u32, thread: u32) -> u64 {
    ((domain as u64 + 1) << 32) | thread as u64
}

/// Claims [`adapter::TCP_WAKE`] for this thread's park, if nobody holds it.
///
/// **No wake can be lost between looking and parking.** `tcpd` signals the
/// notification whether or not anybody waits, and the nucleus keeps the bit;
/// news that arrives after this program looked and before the caller parks
/// leaves the bit set, and the park returns at once.
pub(crate) fn park_on_wake(domain: u32, thread: u32) -> bool {
    WAKE_OWNER
        .compare_exchange(0, wake_key(domain, thread), Relaxed, Relaxed)
        .is_ok()
}

/// Whether a thread is parked on the wake -- so a write that is news for it,
/// an eventfd's, should ring it.
pub(crate) fn wake_is_held() -> bool {
    WAKE_OWNER.load(Relaxed) != 0
}

/// A thread's call has come back: the wake is free again if it held it.
pub(crate) fn wake_returned(domain: u32, thread: u32) {
    let _ = WAKE_OWNER.compare_exchange(wake_key(domain, thread), 0, Relaxed, Relaxed);
}

/// A domain -- or one of its threads -- will never come back for the wake:
/// it ended, or its park became a signal delivery.
pub(crate) fn abandon_wake(domain: u32, thread: Option<u32>) {
    let held = WAKE_OWNER.load(Relaxed);
    let same_domain = held >> 32 == u64::from(domain) + 1;
    let same_thread = thread.is_none_or(|thread| held & 0xffff_ffff == u64::from(thread));
    if held != 0 && same_domain && same_thread {
        let _ = WAKE_OWNER.compare_exchange(held, 0, Relaxed, Relaxed);
    }
}

/// Parks a blocking stream call until there is news: on the wake when this
/// thread can have it, and otherwise ten milliseconds at a time. Answers
/// `EAGAIN` if no park can be had at all.
fn wait_and_retry(request: &PersonalityCall) -> (u64, Answer) {
    let _ = super::took_timed_wait(request.domain, request.thread);
    if park_on_wake(request.domain, request.thread) {
        return (REPLY_BLOCK_ON_RETRY, Answer::ok(adapter::TCP_WAKE as u64));
    }
    match super::park_until(request.domain, request.thread, RETRY_NANOS) {
        Some(slot) => (REPLY_BLOCK_ON_RETRY, Answer::ok(slot)),
        None => (REPLY_VALUE, Answer::error(errno::EAGAIN)),
    }
}

/// Takes one connection from `tcpd` for `listener`, into this program's table
/// and not yet into any process. Answers whether one was taken.
///
/// A full table takes nothing: the connection waits in `tcpd`, which is where
/// Linux's backlog would hold it too.
fn take_one(listener: usize, port: u16) -> Result<bool, i64> {
    let table = tcp();
    let Some(connection) = table.connections.iter().position(Option::is_none) else {
        return Ok(false);
    };
    let landing = (adapter::TCP_CONNECTIONS + connection) as u64;
    if tcp::expect(adapter::TCP_SERVICE as u64, landing).is_err() {
        return Err(errno::EIO);
    }
    let pair = match tcp::accept((adapter::TCP_LISTENERS + listener) as u64) {
        AcceptPoll::Accepted { pair } => pair,
        AcceptPoll::Later => return Ok(false),
        _ => return Err(errno::EIO),
    };
    let pool = match table.pool_of.get(pair as usize).copied() {
        Some(tagged) if tagged > 0 => usize::from(tagged - 1),
        // A pair this adapter never armed: not its connection to serve.
        _ => {
            let _ = tcp::shutdown(landing);
            let _ = super::call(syscall::INVOKE, landing, method::DELETE, [0; 4]);
            return Err(errno::EIO);
        }
    };
    let peer = tcp::peer(landing).unwrap_or(Peer::V4 {
        address: 0,
        port: 0,
    });
    table.taken += 1;
    table.connections[connection] = Some(Connection {
        pool,
        consumed: 0,
        told: 0,
        sent: 0,
        peer,
        local_port: port,
        pending_on: Some(listener),
        born: table.taken,
        failed: false,
        pending: 0,
        owed_zero: false,
    });
    table.births[listener] += 1;
    Ok(true)
}

/// The oldest connection waiting in `listener`.
fn oldest_pending(listener: usize) -> Option<usize> {
    tcp()
        .connections
        .iter()
        .enumerate()
        .filter_map(|(index, held)| {
            held.filter(|held| held.pending_on == Some(listener))
                .map(|held| (held.born, index))
        })
        .min()
        .map(|(_, index)| index)
}

/// Connections waiting in `listener`.
fn waiting(listener: usize) -> usize {
    tcp()
        .connections
        .iter()
        .flatten()
        .filter(|held| held.pending_on == Some(listener))
        .count()
}

/// Shuts a connection and gives its capability back.
fn drop_connection(connection: usize) {
    let slot = (adapter::TCP_CONNECTIONS + connection) as u64;
    let _ = tcp::shutdown(slot);
    let _ = super::call(syscall::INVOKE, slot, method::DELETE, [0; 4]);
    tcp().connections[connection] = None;
}

/// `accept4(fd, addr, addrlen, flags)` and `accept` (flags 0).
pub(crate) fn accept(request: &PersonalityCall, flags: u64) -> (u64, Answer) {
    wake_returned(request.domain, request.thread);
    let (_, stream) = match stream_of(request, request.first()) {
        Ok(found) => found,
        Err(code) => return (REPLY_VALUE, Answer::error(code)),
    };
    let State::Listening { port, listener } = stream.state else {
        return (REPLY_VALUE, Answer::error(errno::EINVAL));
    };
    let taken = match oldest_pending(listener) {
        Some(connection) => Ok(connection),
        None => match take_one(listener, port) {
            Ok(true) => oldest_pending(listener).ok_or(errno::EIO),
            Ok(false) if stream.nonblocking => Err(errno::EAGAIN),
            Ok(false) => return wait_and_retry(request),
            Err(code) => Err(code),
        },
    };
    let _ = super::took_timed_wait(request.domain, request.thread);
    let connection = match taken {
        Ok(connection) => connection,
        Err(code) => return (REPLY_VALUE, Answer::error(code)),
    };
    let table = tcp();
    let Some(mut held) = table.connections[connection] else {
        return (REPLY_VALUE, Answer::error(errno::EIO));
    };
    held.pending_on = None;
    table.connections[connection] = Some(held);
    let made = install(
        request,
        Stream {
            domain: request.domain,
            state: State::Connected { connection },
            v6: stream.v6,
            v6_only: stream.v6_only,
            nonblocking: flags & socket::kind::NONBLOCK != 0,
        },
        flags & socket::kind::CLOEXEC != 0,
    );
    if (made.value as i64) < 0 {
        drop_connection(connection);
        return (REPLY_VALUE, made);
    }
    // The peer's address, if the caller asked. A caller that passed no buffer
    // is not told, which is what a null pointer means.
    if request.second() != 0 && request.third() != 0 {
        let Some(endpoint) = endpoint_of(&stream, held.peer) else {
            return (REPLY_VALUE, made);
        };
        let _ = write_address(request.domain, request.second(), request.third(), &endpoint);
    }
    (REPLY_VALUE, made)
}

/// What a stream descriptor is doing, for `poll`, `select` and `epoll` — and
/// the count of news on it an edge-triggered interest compares, which only
/// grows.
///
/// A listener with nothing waiting asks `tcpd` for one, so a connection that
/// has arrived is seen without an `accept`. A connection asks `tcpd` how far
/// the peer's stream has reached, which takes nothing, and tells it what the
/// program has read since it last asked, as `read` does.
///
/// A socket neither listening nor connected reports nothing — Linux says
/// `EPOLLOUT | EPOLLHUP` for one, and nothing here connects out yet.
pub(crate) fn condition(entry: &Entry) -> (Condition, Option<u64>) {
    let _ = settle(entry.handle as usize);
    let Some(Some(stream)) = tcp().streams.get(entry.handle as usize).copied() else {
        return (Condition::Unknown, None);
    };
    match stream.state {
        // RFC 0090 step 4: quiet while the dial is out, and all of it once it
        // failed. Settled above, so an opened dial is `Connected` by now.
        State::Connecting { connection } => {
            let held = tcp().connections[connection];
            let failed = held.is_some_and(|c| c.failed);
            let error = held.is_some_and(|c| c.pending != 0);
            (
                Condition::Connecting {
                    ended: failed,
                    error,
                },
                failed.then_some(1 + u64::from(error)),
            )
        }
        State::Fresh | State::Bound { .. } => (Condition::Listener { waiting: 0 }, None),
        State::Listening { port, listener } => {
            if waiting(listener) == 0 {
                let _ = take_one(listener, port);
            }
            (
                Condition::Listener {
                    waiting: waiting(listener),
                },
                Some(tcp().births[listener]),
            )
        }
        State::Connected { connection } => {
            let Some(mut held) = tcp().connections[connection] else {
                return (Condition::Unknown, None);
            };
            let slot = (adapter::TCP_CONNECTIONS + connection) as u64;
            match tcp::recv(slot, held.consumed - held.told) {
                StreamPoll::Ready {
                    state, delivered, ..
                } => {
                    held.told = held.consumed;
                    tcp().connections[connection] = Some(held);
                    let closed = !peer_may_send(state);
                    (
                        Condition::Stream {
                            unread: delivered.saturating_sub(held.consumed),
                            peer_closed: closed,
                        },
                        // Plus one so that the first look is news: a quiet,
                        // writable connection is reported once, as Linux does
                        // on `EPOLL_CTL_ADD`.
                        Some(1 + delivered + u64::from(closed)),
                    )
                }
                // Gone, or the service would not say: readable, so the
                // program's `read` learns which.
                _ => (
                    Condition::Stream {
                        unread: 0,
                        peer_closed: true,
                    },
                    Some(u64::MAX),
                ),
            }
        }
    }
}

fn endpoint_of(stream: &Stream, peer: Peer) -> Option<Endpoint> {
    match peer {
        Peer::V4 { address, port } => {
            socket::peer_endpoint(stream.v6, stream.v6_only, address.to_be_bytes(), port)
        }
        Peer::Loopback6 { port } => {
            let mut address = [0u8; 16];
            address[15] = 1;
            Some(Endpoint::V6 {
                address,
                port,
                scope: 0,
            })
        }
    }
}

/// Writes `endpoint` where a `sockaddr` and its length live, truncating to
/// the caller's buffer and storing the full length, as Linux does.
fn write_address(domain: u32, address: u64, length_at: u64, endpoint: &Endpoint) -> bool {
    let mut length = [0u8; 4];
    if !super::copy_in(domain, length_at, &mut length) {
        return false;
    }
    let room = u32::from_le_bytes(length) as usize;
    let mut bytes = [0u8; socket::SOCKADDR_IN6_BYTES];
    let Ok(written) = write_endpoint(&mut bytes, endpoint) else {
        return false;
    };
    super::copy_out(domain, address, &bytes[..written.min(room)])
        && super::copy_out(domain, length_at, &(written as u32).to_le_bytes())
}

fn connection_of(stream: &Stream) -> Result<(usize, u64), i64> {
    match stream.state {
        State::Connected { connection } => {
            Ok((connection, (adapter::TCP_CONNECTIONS + connection) as u64))
        }
        _ => Err(errno::ENOTCONN),
    }
}

/// Where a dial stands now, and the stream moved on to match — RFC 0090 step
/// 4. One `RECV`, read by `socket::dial_progress`: once it has opened the
/// stream is connected, owing its `connect` a `0`; once it failed, its error
/// waits for whoever asks first. Answers the socket as `connect` sees it.
fn settle(index: usize) -> socket::Socket {
    use socket::{Dial, Socket};
    let Some(Some(mut stream)) = tcp().streams.get(index).copied() else {
        return Socket::Unconnected;
    };
    let connection = match stream.state {
        State::Fresh | State::Bound { .. } => return Socket::Unconnected,
        State::Listening { .. } => return Socket::Listening,
        State::Connected { connection } => {
            return if tcp().connections[connection].is_some_and(|c| c.owed_zero) {
                Socket::Connecting(Dial::Established)
            } else {
                Socket::Connected
            };
        }
        State::Connecting { connection } => connection,
    };
    let Some(mut held) = tcp().connections[connection] else {
        return Socket::Connecting(Dial::Failed(errno::ECONNABORTED));
    };
    if held.failed {
        return Socket::Connecting(Dial::Failed(held.pending));
    }
    let slot = (adapter::TCP_CONNECTIONS + connection) as u64;
    let progress = match tcp::recv(slot, 0) {
        StreamPoll::Ready { state, ended, .. } => {
            socket::dial_progress(state, ended.map_or(socket::ended::NONE, tcp::Ending::word))
        }
        _ => Dial::Failed(errno::ECONNABORTED),
    };
    match progress {
        Dial::Waiting => {}
        Dial::Established => {
            held.owed_zero = true;
            stream.state = State::Connected { connection };
            tcp().streams[index] = Some(stream);
        }
        Dial::Failed(code) => {
            held.failed = true;
            held.pending = code;
        }
    }
    tcp().connections[connection] = Some(held);
    Socket::Connecting(progress)
}

/// `connect(fd, address, length)` — RFC 0090 step 4, non-blocking.
///
/// **First, whether this program may dial at all.** The nucleus keeps the
/// grant, the project lead's decision of 2026-10-08, and a program without it
/// is told `EACCES` before anything about its socket is asked — as a Linux
/// security module refuses `connect` before the protocol is called. Then RFC
/// 0090 part 5's table, `socket::connect_step`.
pub(crate) fn connect(request: &PersonalityCall) -> Answer {
    use socket::ConnectStep;
    let (index, stream) = match stream_of(request, request.first()) {
        Ok(found) => found,
        Err(code) => return Answer::error(code),
    };
    let mut address = [0u8; 32];
    if !super::copy_in(request.domain, request.second(), &mut address) {
        return Answer::error(errno::EFAULT);
    }
    let asked = super::call(
        syscall::INVOKE,
        super::handle_of(request.domain),
        method::MAY_DIAL,
        [0; 4],
    );
    if asked.status != status::OK || asked.args[0] == 0 {
        return Answer::error(errno::EACCES);
    }
    let given = (request.third() as usize).min(address.len());
    let (destination, port) = match socket::parse_endpoint(&address, given) {
        Ok(Endpoint::V4 { address, port }) if !stream.v6 => (u32::from_be_bytes(address), port),
        // `CONNECT6` keeps the service's fixed handover until a step dials v6.
        Ok(_) => return Answer::error(errno::ENETUNREACH),
        Err(code) => return Answer::error(code),
    };
    let pending = match stream.state {
        State::Connecting { connection } => tcp().connections[connection].map_or(0, |c| c.pending),
        _ => 0,
    };
    match socket::connect_step(settle(index), stream.nonblocking, pending) {
        ConnectStep::Start => start_dial(index, destination, port),
        ConnectStep::Answer(code) => Answer::error(code),
        ConnectStep::Connected => {
            if let Some(Some(Stream {
                state: State::Connected { connection },
                ..
            })) = tcp().streams.get(index).copied()
                && let Some(mut held) = tcp().connections[connection]
            {
                held.owed_zero = false;
                tcp().connections[connection] = Some(held);
            }
            Answer::ok(0)
        }
        ConnectStep::Unconnected(code) => {
            if let Some(Some(mut now)) = tcp().streams.get(index).copied() {
                if let State::Connecting { connection } = now.state {
                    drop_connection(connection);
                }
                now.state = State::Fresh;
                tcp().streams[index] = Some(now);
            }
            Answer::error(code)
        }
        ConnectStep::NotYet => Answer::error(errno::ENOSYS),
    }
}

/// Dials: a pair from the pool, a slot for the connection, and the legs of
/// `sock::tcp::connect` — RFC 0090 step 3's `OPEN_LEG` dial. Answers
/// `EINPROGRESS`, which is what a non-blocking `connect` says when it has
/// started and not finished.
fn start_dial(index: usize, destination: u32, port: u16) -> Answer {
    let table = tcp();
    let Some(Some(mut stream)) = table.streams.get(index).copied() else {
        return Answer::error(errno::EBADF);
    };
    // A dial from a port the program chose is not offered: `bin/tcpd` draws
    // the local port, and a bound one would be a promise this cannot keep.
    if stream.state != State::Fresh {
        return Answer::error(errno::EOPNOTSUPP);
    }
    if table.pool_used >= PAIRS {
        return Answer::error(errno::EAGAIN);
    }
    let Some(slot) = table.connections.iter().position(Option::is_none) else {
        return Answer::error(errno::EAGAIN);
    };
    // Counted whatever the answer: the rings are gifted by the first legs, so
    // a dial refused at the last is a pair spent all the same. Pairs come back
    // at RFC 0090 step 5.
    let pair = table.pool_used;
    table.pool_used += 1;
    let opened = tcp::connect(
        adapter::TCP_SERVICE as u64,
        destination,
        port,
        (
            (adapter::TCP_RINGS + 2 * pair) as u64,
            (adapter::TCP_RINGS + 2 * pair + 1) as u64,
        ),
        Some((adapter::TCP_WAKE as u64, adapter::TCP_WAKE_BADGE)),
        (adapter::TCP_CONNECTIONS + slot) as u64,
    );
    match opened {
        Ok((_, local_port)) => {
            table.connections[slot] = Some(Connection {
                pool: pair,
                consumed: 0,
                told: 0,
                sent: 0,
                peer: Peer::V4 {
                    address: destination,
                    port,
                },
                local_port,
                pending_on: None,
                born: 0,
                failed: false,
                pending: 0,
                owed_zero: false,
            });
            stream.state = State::Connecting { connection: slot };
            table.streams[index] = Some(stream);
            Answer::error(errno::EINPROGRESS)
        }
        Err(tcp::LegError::Refused { value, detail, .. }) => {
            use bhaskix_abi::tcp::{CONGESTED, NO_ENTROPY};
            Answer::error(match (value, detail) {
                (CONGESTED, 2) => errno::EADDRNOTAVAIL,
                (CONGESTED | NO_ENTROPY, _) => errno::EAGAIN,
                _ => errno::EIO,
            })
        }
        Err(_) => Answer::error(errno::EIO),
    }
}

/// What a stream call finds on a socket whose `connect` has not opened — RFC
/// 0090 step 4, as Linux's `tcp_recvmsg_locked` and `sk_stream_wait_connect`
/// answer, read at `24a19b9`: the pending error first, to whichever call asks;
/// once it is taken, `0` for a read (both directions were shut) and `EPIPE`
/// for a write; and while the dial is out, `EAGAIN` without waiting, or a wait.
/// `None` when the socket is not connecting, so the caller goes on as before.
fn while_connecting(
    request: &PersonalityCall,
    index: usize,
    stream: &Stream,
    reading: bool,
) -> Option<(u64, Answer)> {
    let _ = settle(index);
    let state = tcp().streams.get(index).copied().flatten()?.state;
    let State::Connecting { connection } = state else {
        return None;
    };
    let Some(mut held) = tcp().connections[connection] else {
        return Some((REPLY_VALUE, Answer::error(errno::ENOTCONN)));
    };
    if held.failed {
        let _ = super::took_timed_wait(request.domain, request.thread);
        if held.pending != 0 {
            let taken = held.pending;
            held.pending = 0;
            tcp().connections[connection] = Some(held);
            return Some((REPLY_VALUE, Answer::error(taken)));
        }
        return Some((
            REPLY_VALUE,
            if reading {
                Answer::ok(0)
            } else {
                Answer::error(errno::EPIPE)
            },
        ));
    }
    if stream.nonblocking {
        let _ = super::took_timed_wait(request.domain, request.thread);
        return Some((REPLY_VALUE, Answer::error(errno::EAGAIN)));
    }
    Some(wait_and_retry(request))
}

/// `read` (and `recvfrom` with no address) on a stream.
pub(crate) fn read(
    request: &PersonalityCall,
    descriptor: u64,
    buffer: u64,
    count: u64,
) -> (u64, Answer) {
    wake_returned(request.domain, request.thread);
    let (at, stream) = match stream_of(request, descriptor) {
        Ok(found) => found,
        Err(code) => return (REPLY_VALUE, Answer::error(code)),
    };
    if let Some(answer) = while_connecting(request, at, &stream, true) {
        return answer;
    }
    // Settled: an opened dial is connected now, so look again.
    let stream = tcp().streams[at].unwrap_or(stream);
    let (index, slot) = match connection_of(&stream) {
        Ok(found) => found,
        Err(code) => return (REPLY_VALUE, Answer::error(code)),
    };
    let Some(mut connection) = tcp().connections[index] else {
        return (REPLY_VALUE, Answer::error(errno::ENOTCONN));
    };
    let (state, delivered) = match tcp::recv(slot, connection.consumed - connection.told) {
        StreamPoll::Ready {
            state, delivered, ..
        } => (state, delivered),
        StreamPoll::ServiceSaid(_) => (0, connection.consumed),
        _ => return (REPLY_VALUE, Answer::error(-104)), // ECONNRESET
    };
    connection.told = connection.consumed;
    let available = delivered.saturating_sub(connection.consumed);
    if available == 0 {
        tcp().connections[index] = Some(connection);
        if !peer_may_send(state) {
            let _ = super::took_timed_wait(request.domain, request.thread);
            return (REPLY_VALUE, Answer::ok(0)); // end of stream
        }
        if stream.nonblocking {
            let _ = super::took_timed_wait(request.domain, request.thread);
            return (REPLY_VALUE, Answer::error(errno::EAGAIN));
        }
        return wait_and_retry(request);
    }
    let _ = super::took_timed_wait(request.domain, request.thread);
    let take = available.min(count).min(CHUNK as u64) as usize;
    let mut bytes = [0u8; CHUNK];
    let ring = view(2 * connection.pool + 1);
    for (offset, byte) in bytes.iter_mut().take(take).enumerate() {
        *byte = ring.read(connection.consumed + offset as u64);
    }
    if !super::copy_out(request.domain, buffer, &bytes[..take]) {
        tcp().connections[index] = Some(connection);
        return (REPLY_VALUE, Answer::error(errno::EFAULT));
    }
    connection.consumed += take as u64;
    tcp().connections[index] = Some(connection);
    (REPLY_VALUE, Answer::ok(take as u64))
}

/// `write` (and `sendto` with no address) on a stream.
pub(crate) fn write(request: &PersonalityCall, descriptor: u64, buffer: u64, count: u64) -> Answer {
    let (at, stream) = match stream_of(request, descriptor) {
        Ok(found) => found,
        Err(code) => return Answer::error(code),
    };
    // A write that would wait is answered `EAGAIN` here, as a write that would
    // wait for ring space already is: this path has no way to park.
    let mut quick = stream;
    quick.nonblocking = true;
    if let Some((_, answer)) = while_connecting(request, at, &quick, false) {
        return answer;
    }
    let stream = tcp().streams[at].unwrap_or(stream);
    let (index, slot) = match connection_of(&stream) {
        Ok(found) => found,
        Err(code) => return Answer::error(code),
    };
    let Some(mut connection) = tcp().connections[index] else {
        return Answer::error(errno::ENOTCONN);
    };
    let take = (count as usize).min(CHUNK);
    let mut bytes = [0u8; CHUNK];
    if !super::copy_in(request.domain, buffer, &mut bytes[..take]) {
        return Answer::error(errno::EFAULT);
    }
    let ring = view(2 * connection.pool);
    for (offset, byte) in bytes.iter().take(take).enumerate() {
        ring.write(connection.sent + offset as u64, *byte);
    }
    if tcp::send(slot, take as u64).is_err() {
        return Answer::error(errno::EPIPE);
    }
    connection.sent += take as u64;
    tcp().connections[index] = Some(connection);
    Answer::ok(take as u64)
}

/// `shutdown(fd, how)`. Reading is never stopped here — the bytes are
/// already in the ring — so only a direction that includes writing is sent on.
pub(crate) fn shutdown(request: &PersonalityCall) -> Answer {
    let (_, stream) = match stream_of(request, request.first()) {
        Ok(found) => found,
        Err(code) => return Answer::error(code),
    };
    let (_, slot) = match connection_of(&stream) {
        Ok(found) => found,
        Err(code) => return Answer::error(code),
    };
    match request.second() {
        0 => Answer::ok(0),
        1 | 2 => match tcp::shutdown(slot) {
            Ok(()) => Answer::ok(0),
            Err(_) => Answer::error(errno::ENOTCONN),
        },
        _ => Answer::error(errno::EINVAL),
    }
}

/// `getsockname`: the wildcard address and the port this end is on — the
/// adapter is not told which of the machine's addresses a connection
/// arrived at, and the wildcard is what the program bound.
pub(crate) fn getsockname(request: &PersonalityCall) -> Answer {
    let (_, stream) = match stream_of(request, request.first()) {
        Ok(found) => found,
        Err(code) => return Answer::error(code),
    };
    let port = match stream.state {
        State::Fresh => 0,
        State::Bound { port } | State::Listening { port, .. } => port,
        State::Connecting { connection } | State::Connected { connection } => {
            tcp().connections[connection].map_or(0, |c| c.local_port)
        }
    };
    let endpoint = if stream.v6 {
        Endpoint::V6 {
            address: [0; 16],
            port,
            scope: 0,
        }
    } else {
        Endpoint::V4 {
            address: [0; 4],
            port,
        }
    };
    if write_address(request.domain, request.second(), request.third(), &endpoint) {
        Answer::ok(0)
    } else {
        Answer::error(errno::EFAULT)
    }
}

/// `getpeername`.
pub(crate) fn getpeername(request: &PersonalityCall) -> Answer {
    let (_, stream) = match stream_of(request, request.first()) {
        Ok(found) => found,
        Err(code) => return Answer::error(code),
    };
    let (index, _) = match connection_of(&stream) {
        Ok(found) => found,
        Err(code) => return Answer::error(code),
    };
    let Some(connection) = tcp().connections[index] else {
        return Answer::error(errno::ENOTCONN);
    };
    let Some(endpoint) = endpoint_of(&stream, connection.peer) else {
        return Answer::error(errno::EINVAL);
    };
    if write_address(request.domain, request.second(), request.third(), &endpoint) {
        Answer::ok(0)
    } else {
        Answer::error(errno::EFAULT)
    }
}

/// `setsockopt(fd, level, name, value, length)` — `level`, `name`, `value`
/// and `length` are arguments two to five, from the frame.
pub(crate) fn setsockopt(
    request: &PersonalityCall,
    level: u64,
    name: u64,
    value: u64,
    length: u64,
) -> Answer {
    let (index, stream) = match stream_of(request, request.first()) {
        Ok(found) => found,
        Err(code) => return Answer::error(code),
    };
    let option = match socket::plan_setsockopt(level, name, length) {
        Ok(option) => option,
        Err(code) => return Answer::error(code),
    };
    if option == SockOpt::V6Only {
        let mut word = [0u8; 4];
        if !super::copy_in(request.domain, value, &mut word) {
            return Answer::error(errno::EFAULT);
        }
        tcp().streams[index] = Some(Stream {
            v6_only: u32::from_le_bytes(word) != 0,
            ..stream
        });
    }
    Answer::ok(0)
}

/// `getsockopt(fd, level, name, value, length)`: `SO_ERROR` — ~~which is zero:
/// an accepted connection has no pending error the adapter could report~~ —
/// since RFC 0090 step 4, a failed dial's error, **once**, and zero after it
/// is taken or when there is none (`sk_getsockopt`'s `sock_error`, which
/// exchanges it for zero, read at `24a19b9`).
pub(crate) fn getsockopt(
    request: &PersonalityCall,
    level: u64,
    name: u64,
    value: u64,
    length_at: u64,
) -> Answer {
    let at = match stream_of(request, request.first()) {
        Ok((at, _)) => at,
        Err(code) => return Answer::error(code),
    };
    if (level, name) != (socket::option::SOL_SOCKET, socket::option::SO_ERROR) {
        return Answer::error(errno::ENOPROTOOPT);
    }
    let _ = settle(at);
    let mut error = 0u32;
    if let Some(Some(Stream {
        state: State::Connecting { connection },
        ..
    })) = tcp().streams.get(at).copied()
        && let Some(mut held) = tcp().connections[connection]
        && held.pending != 0
    {
        error = held.pending.unsigned_abs() as u32;
        held.pending = 0;
        tcp().connections[connection] = Some(held);
    }
    if super::copy_out(request.domain, value, &error.to_le_bytes())
        && super::copy_out(request.domain, length_at, &4u32.to_le_bytes())
    {
        Answer::ok(0)
    } else {
        Answer::error(errno::EFAULT)
    }
}

/// `fcntl(F_SETFL)` on a stream: `O_NONBLOCK` is kept, because a stream call
/// honours it.
pub(crate) fn set_nonblocking(entry: &Entry, flags: u64) {
    if let Some(Some(stream)) = tcp().streams.get_mut(entry.handle as usize) {
        stream.nonblocking = flags & socket::kind::NONBLOCK != 0;
    }
}

/// Whether a stream row is non-blocking, for `F_GETFL`.
pub(crate) fn nonblocking(entry: &Entry) -> bool {
    tcp()
        .streams
        .get(entry.handle as usize)
        .copied()
        .flatten()
        .is_some_and(|stream| stream.nonblocking)
}

/// A stream descriptor's last row closed: a connection is shut and its
/// capability dropped (its pair returns to the listener when `tcpd` retires
/// it); a listener keeps its pairs, which is this step's stated limit, and
/// sheds the connections it had taken and nobody accepted.
pub(crate) fn close(entry: &Entry) {
    let index = entry.handle as usize;
    let Some(Some(stream)) = tcp().streams.get(index).copied() else {
        return;
    };
    match stream.state {
        State::Connecting { connection } | State::Connected { connection } => {
            drop_connection(connection);
        }
        // Connections taken for a listener nobody will accept from again.
        State::Listening { listener, .. } => {
            while let Some(connection) = oldest_pending(listener) {
                drop_connection(connection);
            }
        }
        State::Fresh | State::Bound { .. } => {}
    }
    let _ = stream.domain;
    tcp().streams[index] = None;
}
