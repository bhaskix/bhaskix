// SPDX-License-Identifier: Apache-2.0
//! The protocol service, in a domain with no device.
//!
//! [RFC 0018](../../../docs/rfc/0018-networking.md) step 3. It takes frames
//! from `bin/netd` through a shared ring and, for now, counts them. ARP and
//! IPv4 are step 4; keeping them out is what makes this step a test of the
//! *ring* rather than of a ring and a parser at once.
//!
//! # What it does not hold, which is the whole argument
//!
//! No device. No DMA window. No interrupt. No configuration space. Two
//! capabilities: the ring it reads and a page it writes findings into.
//!
//! That asymmetry is why RFC 0018 splits the stack across two domains. Every
//! byte this program will eventually parse arrives from whoever can reach the
//! wire, continuously, at line rate — and a parser bug here cannot be turned
//! into a device pointed anywhere, because there is no device within reach.
//!
//! # The ring is `abi::ring`, and this is its first caller
//!
//! That module was written for RFC 0009 step 5 and had no user until now. Its
//! shape carries a rule worth restating: **copy out, validate the copy, use the
//! copy.** `Cursor` is built from numbers rather than from the region, so a
//! reader physically cannot validate one value and then use a different one
//! that the writer changed in between. The producer is another domain and can
//! write whatever it likes into the header; nothing here may be trusted twice.
#![no_std]
#![no_main]

use bhaskix_abi::{method, rights, ring, socket, status, syscall};
use bhaskix_net::{
    ArpCache, ArpOp, ArpPacket, EthFrame, EtherType, Ipv4Addr, Ipv4Header, MacAddr, Port, Protocol,
    UdpDatagram, arp, eth, icmp, ipv4, udp,
};

/// Slot: the ring `bin/netd` writes frames into.
const RING: u64 = 0;
/// Slot: the page this program leaves its findings in.
const REPORT: u64 = 1;
/// Slot: the ring this program hands frames back to `bin/netd` through.
const BACK: u64 = 2;
/// Slot: what this interface is, read-only, written by the kernel.
const CONFIG: u64 = 3;
/// Slot: the endpoint this service answers on.
///
/// Unbadged, because it is this program's own. Every socket handed out is a
/// *badged, weaker* capability to this same endpoint — which is why RFC 0018
/// step 5 needs no new kernel object kind, and why the kernel gained nothing
/// for this step.
const ENDPOINT: u64 = 4;

/// Where this program maps what it holds.
const RING_AT: u64 = 0x2100_0000;
const REPORT_AT: u64 = 0x2110_0000;
const BACK_AT: u64 = 0x2120_0000;
const CONFIG_AT: u64 = 0x2130_0000;

/// Bytes in the ring, matching what the kernel granted.
const RING_BYTES: usize = 16 * 4096;

/// The largest frame this program will take out of the ring.
///
/// A length is a number the *other side* wrote, so it is bounded here before
/// it is used for anything. Without this a producer could name a length that
/// reached past the ring, and the bound is what makes that a refusal rather
/// than a read of whatever follows.
const MAX_FRAME: usize = 2048;

/// The marker the kernel looks for before believing the report.
const MARKER: u64 = 0x3154_5052_4450_4931;

/// The marker the kernel writes before this program's configuration is true.
const CONFIG_MARKER: u64 = 0x3146_4e43_5049_5f4e;

/// The address this program asks about, to prove it can send.
///
/// **Deliberately not the one `bin/netd`'s probe asks for.** The driver asks
/// for `10.0.2.2`; this asks for `10.0.2.3`, so a request for `.3` on the wire
/// is a frame that can only have been built here, crossed the return ring, and
/// been transmitted by a program that cannot parse it. One byte of difference
/// is what makes the two distinguishable to a test.
const ASK_ABOUT: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 3);

/// The address this program pings, once it knows how to reach it.
///
/// QEMU's built-in network answers an echo request to its gateway, which makes
/// a *sent* ping the demonstrable half of ICMP here. Answering one is written
/// and untestable on this network: nothing has a reason to ping us.
const GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 2);

/// What this program puts in an echo request, and expects back unchanged.
const PING_PAYLOAD: [u8; 17] = *b"bhaskix-icmp-0001";

/// How long a learned mapping is believed, in **frames handled**.
///
/// This program has no clock — `bhaskix-net` takes time as an argument
/// precisely so it does not need one — so what is passed in is a monotonic
/// count of frames rather than nanoseconds. A lie of units and not of ordering:
/// entries still expire in the order they were learned, which is the property
/// the cache's own tests check.
///
/// It was a count of *loop passes* first, which runs at the speed of a spin, so
/// a thousand of them elapsed in milliseconds and the cache always read empty.
/// A clock has to tick at the rate of the thing it is timing.
const ARP_LIFETIME: u64 = 1_000;

/// There is nothing to unwind and nowhere to print to.
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // SAFETY: an undefined instruction, deliberately. Stopping where the kernel
    // can see it beats carrying on with a ring in an unknown state.
    unsafe { core::arch::asm!("ud2", options(noreturn)) }
}

/// Issues one system call, and returns `(status, value)`.
fn call(kind: u64, capability: u64, method: u64, args: [u64; 4]) -> (u64, u64) {
    let status: u64;
    let mut value = args[0];
    // SAFETY: the system call convention from RFC 0008. Nothing is
    // dereferenced on this side, and every argument register is declared as an
    // output because the kernel writes the whole frame back on the way out.
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") kind => status,
            inlateout("rdi") capability => _,
            inlateout("rsi") method => _,
            inlateout("rdx") value,
            inlateout("r10") args[1] => _,
            inlateout("r8") args[2] => _,
            inlateout("r9") args[3] => _,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    (status, value)
}

/// Blocks until a request arrives, and returns `(status, badge, method, args)`.
///
/// The caller is not returned, because the kernel remembers it: a service that
/// could name its own reply target could answer a question nobody asked it.
///
/// **This is a real sleep**, and it is what turns this program from a poll loop
/// into a service. Until step 5 it spun on the ring and stopped when quiet,
/// because it had nothing to wait on; an endpoint is something to wait on.
fn receive() -> (u64, u64, u64, [u64; 4]) {
    let status: u64;
    let mut badge = ENDPOINT;
    let mut method = 0u64;
    let (mut a0, mut a1, mut a2, mut a3) = (0u64, 0u64, 0u64, 0u64);
    // SAFETY: the system call convention from RFC 0008. Every argument register
    // is an output because the kernel writes the whole frame back.
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") syscall::RECV => status,
            inlateout("rdi") badge,
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
    (status, badge, method, [a0, a1, a2, a3])
}

/// Answers the caller this thread received from, and nobody else.
fn reply(outcome: u64, a1: u64, a2: u64) {
    let _ = call(syscall::REPLY, 0, 0, [outcome, a1, a2, 0]);
}

/// Maps a capability at an address, and says whether it worked.
fn attach(slot: u64, at: u64, writable: u64) -> bool {
    call(syscall::INVOKE, slot, method::ATTACH, [at, writable, 0, 0]).0 == status::OK
}

/// Ends this program. Never returns.
fn exit() -> ! {
    call(syscall::EXIT, 0, 0, [0; 4]);
    #[allow(clippy::empty_loop)]
    loop {}
}

/// Copies `length` bytes out of the ring at free-running `tail` into `into`.
///
/// # Safety
///
/// The ring must be mapped at [`RING_AT`] and `into` writable for `length`.
unsafe fn ring_copy_out(
    layout: ring::Layout,
    cursor: ring::Cursor,
    into: *mut u8,
    length: usize,
) -> bool {
    if cursor.readable() < length {
        return false;
    }
    let (first, second) = ring::read_runs(layout, cursor, length);
    if first.length + second.length != length {
        return false;
    }
    // SAFETY: both runs are offsets `abi::ring` computed inside the region this
    // program mapped, `into` is writable for `length` by the caller's
    // obligation, and the two runs are the halves one transfer wraps into.
    unsafe {
        core::ptr::copy_nonoverlapping(
            (RING_AT + first.offset as u64) as *const u8,
            into,
            first.length,
        );
        if !second.is_empty() {
            core::ptr::copy_nonoverlapping(
                (RING_AT + second.offset as u64) as *const u8,
                into.add(first.length),
                second.length,
            );
        }
    }
    true
}

/// Copies `length` bytes from `source` into the return ring.
///
/// # Safety
///
/// The return ring must be mapped writable at [`BACK_AT`], and `source`
/// readable for `length`.
unsafe fn back_copy_in(
    layout: ring::Layout,
    head: u64,
    tail: u64,
    source: *const u8,
    length: usize,
) -> Option<u64> {
    let cursor = ring::Cursor::new(layout, head, tail)?;
    if cursor.writable() < length {
        return None;
    }
    let (first, second) = ring::write_runs(layout, cursor, length);
    // SAFETY: both runs are offsets `abi::ring` computed inside the region this
    // program mapped, and `source` is readable for `length` by the caller.
    unsafe {
        core::ptr::copy_nonoverlapping(
            source,
            (BACK_AT + first.offset as u64) as *mut u8,
            first.length,
        );
        if !second.is_empty() {
            core::ptr::copy_nonoverlapping(
                source.add(first.length),
                (BACK_AT + second.offset as u64) as *mut u8,
                second.length,
            );
        }
    }
    Some(head + length as u64)
}

/// Hands one frame to `bin/netd` to put on the wire.
///
/// # Safety
///
/// The return ring must be mapped writable at [`BACK_AT`].
unsafe fn send(frame: &[u8]) -> bool {
    let Some(layout) = ring::Layout::for_region(RING_BYTES) else {
        return false;
    };
    // SAFETY: the ring's header, in the region this program mapped. Volatile
    // because the consumer is another domain and takes no lock.
    let (head, tail) = unsafe {
        (
            core::ptr::read_volatile((BACK_AT + ring::HEAD_OFFSET as u64) as *const u64),
            core::ptr::read_volatile((BACK_AT + ring::TAIL_OFFSET as u64) as *const u64),
        )
    };
    let prefix = (frame.len() as u32).to_le_bytes();
    // SAFETY: the ring is mapped and both sources are readable.
    let Some(after_prefix) = (unsafe { back_copy_in(layout, head, tail, prefix.as_ptr(), 4) })
    else {
        return false;
    };
    // SAFETY: as above -- the ring is mapped writable and `frame` is a slice
    // this program owns, readable for its own length.
    let Some(after_frame) =
        (unsafe { back_copy_in(layout, after_prefix, tail, frame.as_ptr(), frame.len()) })
    else {
        return false;
    };
    // The bytes, then a fence, then the index that publishes them. The reader
    // is another domain on another CPU and takes no lock.
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    // SAFETY: the ring's header, which only this program writes.
    unsafe {
        core::ptr::write_volatile(
            (BACK_AT + ring::HEAD_OFFSET as u64) as *mut u64,
            after_frame,
        );
    }
    true
}

/// Builds an Ethernet frame carrying `payload` as `ethertype`.
///
/// Returns how many bytes of `into` were used. Every byte of this comes from
/// `bhaskix-net`, which is the point: the framing is the same code the parser
/// on the other side of the wire is tested against.
fn frame(
    into: &mut [u8],
    destination: MacAddr,
    source: MacAddr,
    ethertype: EtherType,
    payload: &[u8],
) -> Option<usize> {
    eth::write_header(into, destination, source, ethertype).ok()?;
    let end = eth::HEADER + payload.len();
    into.get_mut(eth::HEADER..end)?.copy_from_slice(payload);
    Some(end)
}

/// What this program was able to do, as bits.
fn state(can_send: bool, mac: MacAddr) -> u64 {
    u64::from(can_send) | (u64::from(mac != MacAddr::UNSPECIFIED) << 1)
}

/// Builds and hands over one UDP datagram.
///
/// Every layer of it comes from `bhaskix-net`: the same code the parser on the
/// other side of the wire is tested against, and the reason this program can
/// send a correct packet without knowing how to drive anything.
fn send_datagram(
    me: (MacAddr, Ipv4Addr),
    gateway: MacAddr,
    from: u16,
    to: Ipv4Addr,
    to_port: u16,
    payload: &[u8],
) -> bool {
    let mut out = [0u8; MAX_FRAME];
    let body = match udp::write(
        &mut out[eth::HEADER + ipv4::HEADER..],
        Port(from),
        Port(to_port),
        payload,
        me.1,
        to,
    ) {
        Ok(body) => body,
        Err(_) => return false,
    };
    if ipv4::write_header(
        &mut out[eth::HEADER..],
        me.1,
        to,
        Protocol::UDP,
        body,
        0x2603,
    )
    .is_err()
    {
        return false;
    }
    // Broadcast at layer two when the destination is the broadcast address:
    // a client with no address is answering nobody in particular, and sending
    // that to the gateway's MAC would be asking one station a question meant
    // for all of them.
    let destination = if to == Ipv4Addr::BROADCAST {
        MacAddr::BROADCAST
    } else {
        gateway
    };
    if eth::write_header(&mut out, destination, me.0, EtherType::IPV4).is_err() {
        return false;
    }
    // SAFETY: the return ring is mapped writable by this program.
    unsafe { send(&out[..eth::HEADER + ipv4::HEADER + body]) }
}

/// Datagrams placed into a bound socket. See `drain_ring`.
static DELIVERED: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Frames taken from the ring **while serving**, which nothing used to count.
static TAKEN: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Where `drain_ring` has read up to, so the report can show it.
static SERVING_TAIL: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Why the last frame was not given to a socket.
///
/// `drain_ring` has seven ways to refuse a frame and reported none of them, so
/// a datagram that never reached a socket was indistinguishable from one that
/// never arrived. Each refusal is a different bug, and a count of zero
/// deliveries names none of them.
static WHY: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Refusal codes for [`WHY`], in the order `drain_ring` applies them.
mod why {
    pub const NOT_A_FRAME: u64 = 1;
    pub const NOT_IPV4: u64 = 2;
    pub const NOT_A_HEADER: u64 = 3;
    pub const NOT_UDP: u64 = 4;
    pub const NOT_FOR_US: u64 = 5;
    pub const NOT_A_DATAGRAM: u64 = 6;
    pub const NO_SOCKET: u64 = 7;
}

/// Records why a frame was refused, **with the bytes that caused it**.
///
/// The code alone said "not IPv4" of a frame that certainly was one, which is
/// a claim about the parser or a claim about the bytes and no way to tell
/// which. The length and ethertype the program actually read decide it.
fn refuse(code: u64, length: usize, ethertype: u16) {
    WHY.store(
        code | ((ethertype as u64) << 16) | ((length as u64) << 32),
        core::sync::atomic::Ordering::Relaxed,
    );
}

/// The last full report, so that [`refresh`] can rewrite the page.
///
/// # Why this exists
///
/// Every `report` call in this program is in `ipd_main`, so the page stopped
/// changing the moment `serve` was entered — and `serve` is where all the
/// interesting work happens. The kernel then read eleven frames and nothing
/// delivered, and that was true of a service which had since taken more frames
/// and delivered a datagram. **A counter that has stopped moving reads exactly
/// like a subsystem that has stopped working**, which cost three separate
/// wrong diagnoses in one day, twice on this very page.
static CACHE: [core::sync::atomic::AtomicU64; 8] = [
    core::sync::atomic::AtomicU64::new(0),
    core::sync::atomic::AtomicU64::new(0),
    core::sync::atomic::AtomicU64::new(0),
    core::sync::atomic::AtomicU64::new(0),
    core::sync::atomic::AtomicU64::new(0),
    core::sync::atomic::AtomicU64::new(0),
    core::sync::atomic::AtomicU64::new(0),
    core::sync::atomic::AtomicU64::new(0),
];

/// Rewrites the report with what serving has changed since.
fn refresh() {
    use core::sync::atomic::Ordering::Relaxed;
    let mut held = [0u64; 8];
    for (slot, value) in held.iter_mut().zip(CACHE.iter()) {
        *slot = value.load(Relaxed);
    }
    write_report([
        MARKER,
        held[0] + TAKEN.load(Relaxed),
        held[1],
        held[2],
        held[3],
        held[4],
        held[5],
        held[6],
        held[7],
        DELIVERED.load(Relaxed),
        WHY.load(Relaxed),
        // The ring's own two numbers. Counters are a story about the ring;
        // these are the ring. Where they disagree, the counters are wrong.
        // SAFETY: the ring's header, in the region this program mapped.
        unsafe { core::ptr::read_volatile((RING_AT + ring::HEAD_OFFSET as u64) as *const u64) },
        SERVING_TAIL.load(Relaxed),
    ]);
}

/// How many sockets this service will hand out.
///
/// Fixed, like every other table this system exposes to something it does not
/// control: a program that could make the service allocate without bound would
/// hold a denial of service dressed as a feature.
const SOCKETS: usize = 4;

/// One bound socket.
/// The largest datagram a socket will hold for its owner.
///
/// A DHCP offer is about three hundred bytes. Fixed and small, because this is
/// memory a *remote party* fills and there are [`SOCKETS`] of them.
const DATAGRAM: usize = 384;

#[derive(Clone, Copy)]
struct Socket {
    /// Zero when this slot is free.
    port: u16,
    /// Bumped every time the slot is reused, so a capability held across a
    /// close names a socket that no longer exists rather than the next one.
    generation: u32,
    /// **One** datagram, and the limit is stated rather than implied. A queue
    /// is a later question; what this step answers is whether a program holding
    /// a socket can be given what arrived for it.
    from: Ipv4Addr,
    from_port: u16,
    length: u16,
    held: [u8; DATAGRAM],
}

/// Takes whatever has arrived and gives each datagram to the socket it is for.
///
/// Called from inside a client's `RECV_FROM`, because that is the only event
/// this service can act on while asleep on its endpoint.
///
/// A datagram is matched to a socket by **destination port**. A broadcast
/// destination is accepted as well as this interface's own address: a client
/// with no address yet is answered by broadcast, which is the whole reason
/// DHCP works at all.
fn drain_ring(sockets: &mut [Socket; SOCKETS], me: (MacAddr, Ipv4Addr), tail: &mut u64) {
    let Some(layout) = ring::Layout::for_region(RING_BYTES) else {
        return;
    };
    let mut frame = [0u8; MAX_FRAME];

    // Bounded: a client asking for one datagram must not be made to walk an
    // arbitrarily long backlog before it is answered.
    for _ in 0..16 {
        // SAFETY: the ring's header, in the region this program mapped.
        let head =
            unsafe { core::ptr::read_volatile((RING_AT + ring::HEAD_OFFSET as u64) as *const u64) };
        SERVING_TAIL.store(*tail, core::sync::atomic::Ordering::Relaxed);
        let Some(cursor) = ring::Cursor::new(layout, head, *tail) else {
            return;
        };
        if cursor.readable() < 4 {
            return;
        }
        let mut prefix = [0u8; 4];
        // SAFETY: the ring is mapped and `prefix` is four writable bytes.
        if !unsafe { ring_copy_out(layout, cursor, prefix.as_mut_ptr(), 4) } {
            return;
        }
        let length = u32::from_le_bytes(prefix) as usize;
        if length == 0 || length > MAX_FRAME {
            // A length this program has stopped believing. Skip the prefix and
            // carry on rather than wedging on it for ever.
            *tail = tail.wrapping_add(4);
            continue;
        }
        let Some(after) = ring::Cursor::new(layout, head, *tail + 4) else {
            return;
        };
        // SAFETY: as above; `frame` is `MAX_FRAME` writable bytes and `length`
        // is bounded by it.
        if !unsafe { ring_copy_out(layout, after, frame.as_mut_ptr(), length) } {
            return;
        }
        *tail = tail.wrapping_add(4 + length as u64);
        publish(*tail);
        TAKEN.store(
            TAKEN.load(core::sync::atomic::Ordering::Relaxed) + 1,
            core::sync::atomic::Ordering::Relaxed,
        );

        // Every refusal below is `bhaskix-net`'s. This program decides only
        // which socket a datagram belongs to.
        let seen = if length >= 14 {
            u16::from_be_bytes([frame[12], frame[13]])
        } else {
            0
        };
        let Ok(parsed) = EthFrame::parse(&frame[..length]) else {
            refuse(why::NOT_A_FRAME, length, seen);
            continue;
        };
        if parsed.ethertype != EtherType::IPV4 {
            refuse(why::NOT_IPV4, length, seen);
            continue;
        }
        let Ok((header, payload)) = Ipv4Header::parse(parsed.payload) else {
            refuse(why::NOT_A_HEADER, length, seen);
            continue;
        };
        if header.protocol != Protocol::UDP || header.is_fragment() {
            refuse(why::NOT_UDP, length, seen);
            continue;
        }
        if header.destination != me.1 && header.destination != Ipv4Addr::BROADCAST {
            refuse(why::NOT_FOR_US, length, seen);
            continue;
        }
        let Ok(datagram) = UdpDatagram::parse(payload, header.source, header.destination) else {
            refuse(why::NOT_A_DATAGRAM, length, seen);
            continue;
        };
        let Some(socket) = sockets
            .iter_mut()
            .find(|held| held.port != 0 && held.port == datagram.destination.0)
        else {
            refuse(why::NO_SOCKET, length, seen);
            continue;
        };
        // One datagram, and a second overwrites the first rather than being
        // dropped: the newest answer is the one a client asking now wants, and
        // a queue is a later question.
        let take = datagram.payload.len().min(DATAGRAM);
        socket.held[..take].copy_from_slice(&datagram.payload[..take]);
        socket.length = take as u16;
        socket.from = header.source;
        socket.from_port = datagram.source.0;
        // **Counted, because nothing counted it.** Every number this program
        // reported described frames crossing the ring; not one said whether a
        // datagram ever reached a socket. So "the client heard nothing" and
        // "the service delivered nothing" were the same observation, and the
        // search went looking at the device three times over.
        DELIVERED.store(
            DELIVERED.load(core::sync::atomic::Ordering::Relaxed) + 1,
            core::sync::atomic::Ordering::Relaxed,
        );
    }
}

/// Serves the network to whoever holds a capability to this endpoint.
///
/// **Blocks in `receive`**, which is the whole reason this is a service rather
/// than the poll loop it was through step 4. A frame arriving while nothing is
/// asking sits in the ring; it is drained when a client next calls, which is
/// what a receive queue is for.
///
/// Returns never.
fn serve(
    sockets: &mut [Socket; SOCKETS],
    me: (MacAddr, Ipv4Addr),
    gateway: MacAddr,
    can_send: bool,
    mut tail: u64,
) -> ! {
    loop {
        let (status_in, badge, method, args) = receive();
        // What serving has changed, put where the kernel can read it. See
        // `CACHE`: without this the page froze at the moment serving began.
        refresh();
        if status_in != status::OK {
            continue;
        }

        // Unbadged means the caller invoked the service's own endpoint, which
        // is the only capability that can mint a socket. A badge means the
        // caller holds a socket and is using it.
        if badge == 0 {
            if method != socket::BIND_UDP {
                reply(socket::GONE, 0, 0);
                continue;
            }
            if !can_send {
                // No device, or no window to drive it through. Said rather
                // than pretended: a program can tell "nothing answered" from
                // "there is nothing to answer".
                reply(socket::NO_NETWORK, 0, 0);
                continue;
            }
            let wanted = args[0] as u16;
            let taken = sockets
                .iter()
                .position(|held| held.port == 0)
                .filter(|_| wanted == 0 || sockets.iter().all(|held| held.port != wanted));
            let Some(index) = taken else {
                reply(socket::NO_PORT, 0, 0);
                continue;
            };
            // Zero means "assign me one", and the assignment is this service's
            // to make. Ports start above the well-known range.
            let port = if wanted == 0 {
                49152 + index as u16
            } else {
                wanted
            };
            sockets[index].port = port;
            let generation = sockets[index].generation;

            // The capability, derived from this program's own endpoint and
            // handed over. **Where it lands is the caller's to say**: `HAND`
            // puts it in the slot the caller declared with `EXPECT`, and no
            // argument here could name another — which is what stops a service
            // filling a slot a program was keeping empty.
            let (handed, _) = call(
                syscall::INVOKE,
                ENDPOINT,
                method::HAND,
                [
                    ENDPOINT,
                    rights::READ | rights::DERIVE,
                    socket::handle(index as u32, generation),
                    0,
                ],
            );
            if handed == status::OK {
                reply(socket::OK, u64::from(port), 0);
            } else {
                // The commonest reason is that the caller never said where.
                // That is the caller's mistake rather than a missing socket, so
                // it gets its own answer and the slot is given back.
                sockets[index].port = 0;
                reply(socket::NOWHERE, 0, 0);
            }
            continue;
        }

        // A badged capability: a socket. The badge was stamped by the kernel on
        // the way through and cannot be forged by the holder, which is the one
        // thing making the rest of this safe.
        let (index, generation) = socket::parts(badge);
        let held = sockets.get(index as usize).copied();
        let Some(held) = held.filter(|held| held.port != 0 && held.generation == generation) else {
            // Either never a socket, or one that has been closed and whose slot
            // may already be somebody else's. The generation is what tells
            // those apart from the socket that is there now.
            reply(socket::GONE, 0, 0);
            continue;
        };

        match method {
            socket::CLOSE => {
                sockets[index as usize].port = 0;
                // Bumped on release rather than on reuse, so the next holder of
                // this slot cannot be mistaken for the one that just left.
                sockets[index as usize].generation = generation.wrapping_add(1);
                reply(socket::OK, 0, 0);
            }
            socket::SEND_TO => {
                // The payload comes out of memory the **caller** named, with
                // `DRAIN` -- the mirror of `FILL`, built by RFC 0016 step 3 for
                // exactly this and used by the block service since. Which
                // caller is not an argument: it is the one being answered, so a
                // service cannot read a third party's memory.
                let mut payload = [0u8; DATAGRAM];
                let wanted = (args[3] as usize).min(DATAGRAM);
                let (drained, took) = call(
                    syscall::INVOKE,
                    ENDPOINT,
                    method::DRAIN,
                    [args[2], payload.as_mut_ptr() as u64, wanted as u64, 0],
                );
                if drained != status::OK {
                    // No memory named, or not held with `READ`. Sending
                    // something else in its place would answer a different
                    // question than the one asked.
                    reply(socket::GONE, 0, 0);
                    continue;
                }
                let sent = send_datagram(
                    me,
                    gateway,
                    held.port,
                    Ipv4Addr(args[0] as u32),
                    args[1] as u16,
                    &payload[..(took as usize).min(wanted)],
                );
                reply(if sent { socket::OK } else { socket::NO_NETWORK }, 0, 0);
            }
            socket::RECV_FROM => {
                // **Asking is what makes this service look at the wire.** It is
                // asleep in `receive` and has no other wakeup, so a client
                // asking for a datagram is the only event it can act on. Not a
                // workaround: the alternative is a poll loop, and this system
                // has already paid for one of those today.
                drain_ring(sockets, me, &mut tail);

                let waiting = sockets[index as usize];
                if waiting.length == 0 {
                    reply(socket::EMPTY, 0, 0);
                    continue;
                }
                let (filled, _) = call(
                    syscall::INVOKE,
                    ENDPOINT,
                    method::FILL,
                    [
                        args[0],
                        waiting.held.as_ptr() as u64,
                        u64::from(waiting.length),
                        0,
                    ],
                );
                if filled != status::OK {
                    reply(socket::GONE, 0, 0);
                    continue;
                }
                sockets[index as usize].length = 0;
                let mut source = 0u64;
                for octet in waiting.from.octets() {
                    source = (source << 8) | u64::from(octet);
                }
                reply(socket::OK, source, u64::from(waiting.from_port));
            }
            _ => reply(socket::GONE, 0, 0),
        }
    }
}

/// The entry point.
#[unsafe(no_mangle)]
extern "C" fn ipd_main() -> ! {
    if !attach(RING, RING_AT, 1) || !attach(REPORT, REPORT_AT, 1) {
        exit()
    }
    let can_send = attach(BACK, BACK_AT, 1) && attach(CONFIG, CONFIG_AT, 0);
    // Whether this program has an endpoint to answer on at all. Without one it
    // is still the frame mover it was at step 4, and says so by stopping.
    let serving =
        call(syscall::INVOKE, ENDPOINT, method::INFO, [0; 4]).0 != status::NO_SUCH_CAPABILITY;
    let Some(layout) = ring::Layout::for_region(RING_BYTES) else {
        exit()
    };

    let mut frames = 0u64;
    let mut bytes = 0u64;
    let mut first_source = 0u64;
    let mut refused = 0u64;
    let mut built = 0u64;
    let mut buffer = [0u8; MAX_FRAME];
    let mut outgoing = [0u8; MAX_FRAME];
    let mut cache = ArpCache::<8>::new(ARP_LIFETIME);
    // Stands in for a clock. See `ARP_LIFETIME`.
    let mut ticks = 0u64;
    let mut me = (MacAddr::UNSPECIFIED, Ipv4Addr::UNSPECIFIED);
    let mut asked = false;
    let mut pinged = false;
    let mut quiet = 0u32;
    let mut sockets = [Socket {
        port: 0,
        generation: 1,
        from: Ipv4Addr::UNSPECIFIED,
        from_port: 0,
        length: 0,
        held: [0u8; DATAGRAM],
    }; SOCKETS];
    let mut pongs = 0u64;
    // Only this program advances the tail, so it is kept here and written out
    // rather than read back. A consumer that re-read its own index would be
    // trusting the producer with it.
    let mut tail = 0u64;

    // A report before anything has arrived, so that "this program never ran"
    // and "this program ran and saw nothing" are different findings. Without
    // it the kernel reads an absent marker for both, and the two have entirely
    // different causes.
    report(0, 0, 0, 0, 0, 0, u64::from(can_send), 0);

    // No wakeup, and this is a gap rather than a choice. RFC 0018 step 3 asked
    // for a notification here; RFC 0010's notifications can only be signalled
    // by the *kernel* -- a program holding one may `WAIT` and `PEEK` and there
    // is no method that signals -- so a domain cannot wake another domain
    // today. Polling with a yield between looks is what is available, and the
    // missing half is recorded in TRACKER rather than invented here.
    loop {
        // Reported every pass, not only when a frame arrives. It was the
        // latter, and the consequence was a report frozen at the moment the
        // last frame crossed — which was *before* the kernel had published this
        // program's configuration, so the page said "unconfigured" long after
        // it had been configured. A report written only when something happens
        // cannot say what happened last.
        report(
            frames,
            bytes,
            first_source,
            refused,
            built,
            cache.live(ticks) as u64,
            state(can_send, me.0),
            pongs,
        );

        // What this interface is, once the kernel has been able to say. It
        // cannot say until `bin/netd` has read the address out of the device,
        // so this waits for a marker rather than believing a page of zeroes.
        if can_send && me.0 == MacAddr::UNSPECIFIED {
            // SAFETY: the configuration page, mapped read-only by this program.
            let (marker, mac, address) = unsafe {
                (
                    core::ptr::read_volatile(CONFIG_AT as *const u64),
                    core::ptr::read_volatile((CONFIG_AT + 8) as *const u64),
                    core::ptr::read_volatile((CONFIG_AT + 16) as *const u64),
                )
            };
            if marker == CONFIG_MARKER {
                let mut octets = [0u8; 6];
                for (index, octet) in octets.iter_mut().enumerate() {
                    *octet = (mac >> (40 - index * 8)) as u8;
                }
                me = (MacAddr(octets), Ipv4Addr(address as u32));
            }
        }

        // One request of this program's own, so that something on the wire can
        // only have come from here. Built entirely by `bhaskix-net`.
        if can_send && !asked && me.0 != MacAddr::UNSPECIFIED {
            let request = ArpPacket {
                operation: ArpOp::Request,
                sender_hardware: me.0,
                sender_protocol: me.1,
                target_hardware: MacAddr::UNSPECIFIED,
                target_protocol: ASK_ABOUT,
            };
            let mut packet = [0u8; arp::PACKET];
            if request.write(&mut packet).is_ok()
                && let Some(length) = frame(
                    &mut outgoing,
                    MacAddr::BROADCAST,
                    me.0,
                    EtherType::ARP,
                    &packet,
                )
                // SAFETY: the return ring is mapped writable.
                && unsafe { send(&outgoing[..length]) }
            {
                built += 1;
                asked = true;
            }
        }

        // One echo request, once the cache can say where the gateway is. This
        // is the whole stack in one frame: an address learned from a reply this
        // program parsed, a header and a checksum written by `bhaskix-net`, and
        // a driver that will put it on the wire without understanding any of
        // it.
        if can_send
            && !pinged
            && me.0 != MacAddr::UNSPECIFIED
            && let Some(gateway) = cache.lookup(GATEWAY, ticks)
        {
            let mut message = [0u8; icmp::HEADER + PING_PAYLOAD.len()];
            if let Ok(body) = icmp::write(&mut message, false, 0xbe57, 1, &PING_PAYLOAD)
                && ipv4::write_header(
                    &mut outgoing[eth::HEADER..],
                    me.1,
                    GATEWAY,
                    Protocol::ICMP,
                    body,
                    0x2601,
                )
                .is_ok()
            {
                let at = eth::HEADER + ipv4::HEADER;
                outgoing[at..at + body].copy_from_slice(&message[..body]);
                let total = at + body;
                if eth::write_header(&mut outgoing, gateway, me.0, EtherType::IPV4).is_ok()
                    // SAFETY: the return ring is mapped writable.
                    && unsafe { send(&outgoing[..total]) }
                {
                    built += 1;
                    pinged = true;
                }
            }
        }

        // SAFETY: the ring's header, in the region this program mapped. Read
        // volatile because the producer is another domain and takes no lock.
        let head =
            unsafe { core::ptr::read_volatile((RING_AT + ring::HEAD_OFFSET as u64) as *const u64) };

        // Copied out, then validated, then used. `Cursor::new` refuses a pair
        // that cannot be true -- a head behind the tail, or a gap wider than
        // the ring -- which is the one thing standing between a hostile
        // producer and this program reading its own memory as a frame.
        let Some(cursor) = ring::Cursor::new(layout, head, tail) else {
            refused += 1;
            call(syscall::YIELD, 0, 0, [0; 4]);
            continue;
        };
        if cursor.is_empty() {
            // **This program has nothing to sleep on.** RFC 0010's
            // notifications can only be signalled by the kernel, so no domain
            // can wake another, and a poll loop is all that is available.
            //
            // A poll loop that never ends is a processor the rest of the
            // machine cannot have — which is exactly what it cost: the shell
            // test timed out with the shell answering every command correctly,
            // because two pinned domains were spinning for the life of the
            // boot.
            //
            // So it stops. This is a demonstration rather than a service: once
            // there has been nothing to do for a long run of passes, it writes
            // a last report and exits. The report page belongs to the keeper
            // domain, so it outlives this program and the kernel still reads
            // it. **A persistent `ipd` needs the wakeup RFC 0010 does not
            // have**, and that is the honest reason this exits rather than
            // idles.
            quiet = quiet.saturating_add(1);
            // Not before the work is done. Twenty thousand idle passes elapse
            // in a fraction of a second, and the kernel cannot publish this
            // program's configuration until the driver has read the device's
            // address -- so an exit on idleness alone quits before there is
            // anything to be idle about.
            //
            // The second bound is the backstop for a machine where the
            // configuration never comes at all, which is every boot without a
            // DMA window: there is nothing to wait for and no reason to spin.
            let done = asked && pinged;
            if (done && quiet > 20_000) || quiet > 2_000_000 {
                // **Serve rather than stop.** Through step 4 this program
                // exited here, because it had nothing to wait on and a poll
                // loop that never ends is a processor nobody else can have.
                // An endpoint is something to wait on: `receive` blocks, and a
                // service asleep in it costs nothing at all.
                //
                // The demonstration above is done by this point, so what
                // follows is the program's real job. A frame arriving while it
                // is asleep waits in the ring, which is what a receive queue is.
                if serving {
                    report(
                        frames,
                        bytes,
                        first_source,
                        refused,
                        built,
                        cache.live(ticks) as u64,
                        state(can_send, me.0),
                        pongs,
                    );
                    let gateway = cache.lookup(GATEWAY, ticks).unwrap_or(MacAddr::BROADCAST);
                    serve(&mut sockets, me, gateway, can_send, tail);
                }
                report(
                    frames,
                    bytes,
                    first_source,
                    refused,
                    built,
                    cache.live(ticks) as u64,
                    state(can_send, me.0),
                    pongs,
                );
                exit()
            }
            call(syscall::YIELD, 0, 0, [0; 4]);
            continue;
        }
        quiet = 0;

        // The four-byte length first.
        let mut prefix = [0u8; 4];
        // SAFETY: the ring is mapped and `prefix` is four writable bytes.
        if !unsafe { ring_copy_out(layout, cursor, prefix.as_mut_ptr(), 4) } {
            call(syscall::YIELD, 0, 0, [0; 4]);
            continue;
        }
        let length = u32::from_le_bytes(prefix) as usize;
        // A number the other side chose. Bounded before it is used, and a
        // refusal rather than a clamp: a frame that does not fit is not a
        // shorter frame, it is a producer this program has stopped believing.
        if length == 0 || length > MAX_FRAME {
            refused += 1;
            tail = tail.wrapping_add(4);
            publish(tail);
            continue;
        }

        let Some(after_prefix) = ring::Cursor::new(layout, head, tail + 4) else {
            refused += 1;
            call(syscall::YIELD, 0, 0, [0; 4]);
            continue;
        };
        // SAFETY: the ring is mapped and `buffer` is `MAX_FRAME` writable
        // bytes, which `length` is bounded by above.
        if !unsafe { ring_copy_out(layout, after_prefix, buffer.as_mut_ptr(), length) } {
            // The producer has published a length but not yet the bytes. Not
            // an error and not a refusal: look again without moving the tail.
            call(syscall::YIELD, 0, 0, [0; 4]);
            continue;
        }

        // The clock advances per *frame handled*, not per pass round the loop.
        // Per pass it ran at the speed of a spin, so a cache lifetime of a
        // thousand expired in milliseconds and the cache always read empty.
        // Time measured in frames is a fiction, but it is a fiction that orders
        // events the way the thing being measured does.
        ticks += 1;
        frames += 1;
        bytes += length as u64;
        if first_source == 0 && length >= 12 {
            // The source address, six bytes in. Reported rather than parsed:
            // this program has no idea what an Ethernet header means, and the
            // number exists so the kernel can check that the *same* frame
            // crossed two domain boundaries rather than that a counter moved.
            let mut value = 0u64;
            for octet in &buffer[6..12] {
                value = (value << 8) | u64::from(*octet);
            }
            first_source = value;
        }

        // An IPv4 datagram addressed to us. The echo reply this program asked
        // for arrives here, and so would anything else anyone chose to send:
        // every refusal below is `bhaskix-net`'s rather than this program's.
        if let Ok(parsed) = EthFrame::parse(&buffer[..length])
            && parsed.ethertype == EtherType::IPV4
            && let Ok((header, payload)) = Ipv4Header::parse(parsed.payload)
            && header.destination == me.1
            && header.protocol == Protocol::ICMP
            && !header.is_fragment()
            && let Ok(echo) = icmp::Echo::parse(payload)
        {
            if echo.is_reply {
                // The payload must come back unchanged, which is the only
                // thing that distinguishes an answer to *our* question from
                // any other echo reply on the segment.
                if echo.payload == PING_PAYLOAD {
                    pongs += 1;
                }
            } else if can_send {
                // Somebody pinged us. Written, and not exercised on this
                // network: QEMU's gateway answers echo requests and never
                // sends them.
                let mut message = [0u8; MAX_FRAME];
                if let Ok(body) = icmp::write(
                    &mut message,
                    true,
                    echo.identifier,
                    echo.sequence,
                    echo.payload,
                ) && ipv4::write_header(
                    &mut outgoing[eth::HEADER..],
                    me.1,
                    header.source,
                    Protocol::ICMP,
                    body,
                    0x2602,
                )
                .is_ok()
                {
                    let at = eth::HEADER + ipv4::HEADER;
                    outgoing[at..at + body].copy_from_slice(&message[..body]);
                    if eth::write_header(&mut outgoing, parsed.source, me.0, EtherType::IPV4).is_ok()
                        // SAFETY: the return ring is mapped writable.
                        && unsafe { send(&outgoing[..at + body]) }
                    {
                        built += 1;
                    }
                }
            }
        }

        // **This is the first parsing this system does of bytes from a wire.**
        // Every one of them was chosen by whoever can reach the segment, and
        // every refusal below is `bhaskix-net`'s rather than this program's.
        if let Ok(parsed) = EthFrame::parse(&buffer[..length])
            && parsed.ethertype == EtherType::ARP
            && let Ok(packet) = ArpPacket::parse(parsed.payload)
        {
            match packet.operation {
                // Somebody answered. The cache learns it, refusing on its own
                // terms what should not be believed -- a group hardware
                // address, an unspecified protocol address.
                ArpOp::Reply => {
                    cache.learn(packet.sender_protocol, packet.sender_hardware, ticks);
                }
                // Somebody asked, and if they asked for us we answer. Written
                // and host-tested; on this network nothing has a reason to ask
                // us yet, so it is not exercised live until something does.
                ArpOp::Request if can_send && packet.target_protocol == me.1 => {
                    let reply = ArpPacket {
                        operation: ArpOp::Reply,
                        sender_hardware: me.0,
                        sender_protocol: me.1,
                        target_hardware: packet.sender_hardware,
                        target_protocol: packet.sender_protocol,
                    };
                    let mut packet_out = [0u8; arp::PACKET];
                    if reply.write(&mut packet_out).is_ok()
                        && let Some(out) = frame(
                            &mut outgoing,
                            packet.sender_hardware,
                            me.0,
                            EtherType::ARP,
                            &packet_out,
                        )
                        // SAFETY: the return ring is mapped writable.
                        && unsafe { send(&outgoing[..out]) }
                    {
                        built += 1;
                    }
                }
                ArpOp::Request => {}
            }
        }

        tail = tail.wrapping_add(4 + length as u64);
        publish(tail);
        report(
            frames,
            bytes,
            first_source,
            refused,
            built,
            cache.live(ticks) as u64,
            state(can_send, me.0),
            pongs,
        );
    }
}

/// Tells the producer how far this program has read.
fn publish(tail: u64) {
    // The bytes are finished with before the index that frees them is written,
    // which is the mirror of the producer's fence: a producer that saw the new
    // tail first could overwrite a frame still being read.
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    // SAFETY: the ring's header, which only this program writes.
    unsafe {
        core::ptr::write_volatile((RING_AT + ring::TAIL_OFFSET as u64) as *mut u64, tail);
    }
}

/// Leaves the findings where the kernel granted memory for them.
#[allow(clippy::too_many_arguments)]
fn report(
    frames: u64,
    bytes: u64,
    first_source: u64,
    refused: u64,
    built: u64,
    learned: u64,
    state: u64,
    pongs: u64,
) {
    let words = [
        MARKER,
        frames,
        bytes,
        first_source,
        refused,
        // Frames this program *built* and handed back, and how many mappings
        // its cache holds. The first says the return path works from this end;
        // the second is the `ArpCache` running outside a host test for the
        // first time since it was written.
        built,
        learned,
        // What this program was able to do, as bits: it could send at all, and
        // it had been told what this interface is. "Built nothing" has three
        // causes -- no return ring, no configuration, or a ring that would not
        // take the bytes -- and a count cannot say which.
        state,
        // Echo replies whose payload came back exactly as sent. The only
        // number here that says the whole stack worked end to end rather than
        // that each piece did.
        pongs,
        DELIVERED.load(core::sync::atomic::Ordering::Relaxed),
        WHY.load(core::sync::atomic::Ordering::Relaxed),
        0,
        0,
    ];
    for (slot, value) in CACHE.iter().zip([
        frames,
        bytes,
        first_source,
        refused,
        built,
        learned,
        state,
        pongs,
    ]) {
        slot.store(value, core::sync::atomic::Ordering::Relaxed);
    }
    write_report(words);
}

/// Puts ten words on the report page.
fn write_report(words: [u64; 13]) {
    // SAFETY: the page this program mapped writable, which nothing else
    // reaches. The marker is written last, so a kernel reading a partial report
    // sees no marker rather than half the fields.
    unsafe {
        for (index, word) in words.iter().enumerate().skip(1) {
            core::ptr::write_volatile((REPORT_AT + index as u64 * 8) as *mut u64, *word);
        }
        core::ptr::write_volatile(REPORT_AT as *mut u64, words[0]);
    }
}

core::arch::global_asm!(
    r#"
.section .text._start,"ax",@progbits
.globl _start
_start:
    xor rbp, rbp
    and rsp, -16
    call ipd_main
    ud2
"#
);
