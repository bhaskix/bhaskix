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
    Address, ArpOp, ArpPacket, EthFrame, EtherType, Ipv4Addr, Ipv4Header, Ipv6Addr, Ipv6Header,
    MacAddr, NeighbourCache, NextHeader, Port, Protocol, UdpDatagram, arp, eth, icmp, icmpv6, ipv4,
    ipv6, udp,
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
/// Slot: the doorbell that wakes `bin/netd`.
///
/// **RFC 0010 step 6.** A frame published into the return ring is invisible to
/// a driver asleep on its interrupt, and until 2026-08-13 nothing in this
/// system could wake another domain: the kernel poked `bin/netd` twice a second
/// on this program's behalf. RFC 0018 step 7 measured what that cost — 122 to
/// 234 microseconds a round trip against 10 to 16 with the two domains folded
/// into one, which is four orders of magnitude more than the copies the
/// networking RFC blamed.
///
/// Write only, and the badge is the kernel's. This capability cannot be waited
/// on, so a bug here cannot eat the wake the driver is asleep for, and its bit
/// was not chosen here, so the driver can trust the word to say who rang.
const DOORBELL: u64 = 5;
/// Slot: the notification `bin/netd` rings when a frame has arrived.
///
/// **RFC 0010 question 1, answered 2026-08-13.** This program has to answer
/// socket calls on its endpoint *and* notice frames it did not ask for. Until
/// now it could not wait for both — there is no second thread to spare and no
/// timed wait — so it polled, about thirty-seven looks at the ring per frame.
///
/// Bound to this thread, so `receive` wakes for a caller or a frame, whichever
/// comes first, and says which.
const INBOX: u64 = 6;
/// Slot: the ring this program forwards TCP segments into.
///
/// **RFC 0020 step 4.** `bin/tcpd` is on the other end. What crosses is not a
/// frame: it is eight bytes of addresses — source, destination — and then the
/// TCP segment, because the pseudo-header needs the addresses and `tcpd`
/// deliberately parses no IP. This program stays the only parser of the IPv4
/// header, exactly as the RFC's diagram draws it.
const TCP_FWD: u64 = 7;
/// Slot: the ring `bin/tcpd` hands segments back through.
const TCP_BACK: u64 = 8;
/// Slot: the doorbell that wakes `bin/tcpd`.
const TCP_BELL: u64 = 9;

/// Where this program maps what it holds.
const RING_AT: u64 = 0x2100_0000;
const REPORT_AT: u64 = 0x2110_0000;
const BACK_AT: u64 = 0x2120_0000;
const CONFIG_AT: u64 = 0x2130_0000;
const TCP_FWD_AT: u64 = 0x2140_0000;
const TCP_BACK_AT: u64 = 0x2150_0000;

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

/// The v6 face of the same host: slirp answers at `fec0::2` on its default
/// prefix, the way `10.0.2.2` answers on the v4 side.
const HOST6: Ipv6Addr = Ipv6Addr::new([0xfec0, 0, 0, 0, 0, 0, 0, 2]);

/// The v6 demonstration ping's identifier. Distinct from the v4 ping's and
/// from [`BURST_ID`], because the identifier is how replies are told apart.
const PING6_ID: u16 = 0xbe59;

/// RFC 0018 step 7: the burst that prices the two-domain split.
///
/// Every packet in this burst crosses the boundary twice — once from `bin/netd`
/// into this program, once back — and each crossing is a copy. The RFC claims
/// that costs "two copies and two domain crossings per packet"; this is the
/// traffic that makes the claim checkable, and `COPIES` is what checks it.
///
/// ICMP echo because it is the only flow QEMU's gateway answers. The identifier
/// is this program's own and differs from the single demonstration ping above,
/// so the gate that asserts *that* ping came back unchanged still means what it
/// meant before.
const BURST: u32 = 256;
/// Payload sizes: the smallest worth sending, and near a full frame.
const BURST_SMALL: usize = 16;
const BURST_LARGE: usize = 1400;
/// Whose replies these are.
const BURST_ID: u16 = 0xbe58;
/// Requests a pipelined phase keeps in flight at once.
///
/// **Not unbounded, and the bound is the point.** "Pipelined" first meant "send
/// all 256 without waiting", which for 1400-byte packets is 369 KiB pushed at a
/// 64 KiB ring: the ring overran, frames were dropped at both ends, the phase
/// never collected its replies and `bin/ipd` went quiet and left for `serve`
/// with the measurement half done. A sender that overruns its own ring is
/// measuring drops, not throughput.
///
/// Sixteen frames is 23 KiB at the largest payload — comfortably inside a ring
/// — and is still sixteen times the serialised phase's one.
const BURST_WINDOW: u32 = 16;
/// Passes to wait for a phase's replies before giving up on it. Bounded because
/// a burst that never finishes would keep this program out of `serve`, and the
/// shell, the DHCP client and every socket wait behind that.
///
/// **The pipelined 1400-byte phase needs this and does not reach 256 replies.**
/// Two hundred and fifty-six frames of 1442 bytes is 369 KiB, and each ring is
/// 64 KiB, so a sender that does not wait overruns the ring and frames are
/// dropped at both ends. That is a real property of this boundary — the rings
/// are a fixed size and a fixed size refuses — and the phase reports how many
/// replies it actually got rather than pretending to a round number.
const BURST_PATIENCE: u32 = 20_000;

/// How many burst phases have finished. The kernel stamps the clock when this
/// moves, which is how a program with no clock gets timed.
static BURST_PHASE: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// Replies counted in the phase now running.
static BURST_PONGS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// Requests sent in the phase now running.
static BURST_SENT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// Times `receive` came back because a frame arrived rather than a caller.
///
/// The number that says RFC 0010 question 1's answer is **used** rather than
/// merely wired. Zero here would mean the binding never fired and any speed-up
/// came from somewhere else.
static NOTIFIED_WAKES: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Passes round the demonstration loop that found the ring empty.
///
/// **Measured before anything is changed.** RFC 0010 step 2 gave `bin/ipd` a
/// doorbell to `bin/netd` and the round-trip latency did not move, which leaves
/// the other direction as the standing hypothesis: `netd` cannot tell this
/// program a frame has arrived, so this program polls, and every look that
/// finds nothing is a `YIELD` and a scheduling round trip.
///
/// If that is where the time goes, these counters are large. If this program
/// takes a frame within a look or two of it being published, the polling is not
/// the cost and the hypothesis is wrong. A change made before this is measured
/// would be a guess with a diff attached.
static EMPTY_POLLS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// The longest run of empty looks between two frames.
static LONGEST_WAIT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Replies the phase that just finished actually got.
///
/// Kept separately because the running counters reset when a phase ends, and
/// the kernel reads the page after the edge rather than on it. Without this a
/// phase that answered 61 of 64 would be indistinguishable from one that
/// answered all of them.
static BURST_RESULT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

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
    // Where the frame goes, from `abi::ring` rather than from arithmetic
    // written here. See `frame_to_write`.
    let Some(cursor) = ring::Cursor::new(layout, head, tail) else {
        return false;
    };
    let Some(framed) = ring::frame_to_write(layout, cursor, frame.len()) else {
        return false;
    };
    let prefix = (frame.len() as u32).to_le_bytes();
    // SAFETY: every offset is `abi::ring`'s, inside the region this program
    // mapped writable, and `frame` is a slice it owns.
    unsafe {
        write_runs(BACK_AT, prefix.as_ptr(), framed.prefix);
        write_runs(BACK_AT, frame.as_ptr(), framed.payload);
    }
    // Outbound, copy one of two: this program's frame into the return ring.
    copied();
    // The bytes, then a fence, then the index that publishes them. The reader
    // is another domain on another CPU and takes no lock.
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    // SAFETY: the ring's header, which only this program writes.
    unsafe {
        core::ptr::write_volatile(
            (BACK_AT + ring::HEAD_OFFSET as u64) as *mut u64,
            framed.next,
        );
    }
    // **Then ring the doorbell.** Index first, wake second: a driver woken
    // before the index was published would look, find nothing, and go back to
    // sleep holding a frame that had already been written. The same ordering
    // the bytes and the index have, for the same reason, one level up.
    //
    // Unchecked, deliberately. On a machine with no interrupt to delegate there
    // is no notification and this slot is empty, which is a refusal rather than
    // a fault — and a driver that cannot be woken is one that is not asleep.
    call(syscall::INVOKE, DOORBELL, method::SIGNAL, [0; 4]);
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

/// Builds an Ethernet + IPv6 frame around an ICMPv6 message.
///
/// Returns how many bytes of `into` were used. `hop` is 255 for neighbour
/// discovery — the specification's proof-of-no-router — and an ordinary 64
/// for echo.
#[allow(clippy::too_many_arguments)]
fn frame6(
    into: &mut [u8],
    destination_mac: MacAddr,
    source_mac: MacAddr,
    source: Ipv6Addr,
    destination: Ipv6Addr,
    hop: u8,
    message: &[u8],
) -> Option<usize> {
    eth::write_header(into, destination_mac, source_mac, EtherType::IPV6).ok()?;
    ipv6::write_header(
        &mut into[eth::HEADER..],
        source,
        destination,
        NextHeader::ICMPV6,
        hop,
        message.len(),
    )
    .ok()?;
    let at = eth::HEADER + ipv6::HEADER;
    let end = at + message.len();
    into.get_mut(at..end)?.copy_from_slice(message);
    Some(end)
}

/// What this program was able to do, as bits.
///
/// Bit 2 is whether the TCP rings attached, which cannot be a one-shot answer:
/// the kernel installs them after this program starts, so the bit may be clear
/// on an early report and set on a later one — and a final report with it
/// still clear is the finding that matters.
fn state(can_send: bool, mac: MacAddr, can_tcp: bool) -> u64 {
    u64::from(can_send)
        | (u64::from(mac != MacAddr::UNSPECIFIED) << 1)
        | (u64::from(can_tcp) << 2)
        | (u64::from(SERVING_NOW.load(core::sync::atomic::Ordering::Relaxed)) << 3)
}

/// Copies `source` into a ring mapped at `base`, at the offsets `runs` names.
///
/// It hardcoded the return ring until RFC 0020 step 4 gave this program a
/// second ring it produces into, and one reviewed copy routine beats two that
/// agree by inspection.
///
/// # Safety
///
/// `runs` must be offsets `abi::ring` computed for the region mapped writable
/// at `base`, and `source` readable for their combined length.
unsafe fn write_runs(base: u64, source: *const u8, runs: (ring::Run, ring::Run)) {
    let (first, second) = runs;
    // SAFETY: the caller's obligation; a wrap's two halves do not overlap.
    unsafe {
        core::ptr::copy_nonoverlapping(
            source,
            (base + first.offset as u64) as *mut u8,
            first.length,
        );
        if !second.is_empty() {
            core::ptr::copy_nonoverlapping(
                source.add(first.length),
                (base + second.offset as u64) as *mut u8,
                second.length,
            );
        }
    }
}

/// Copies out of a ring mapped at `base` at the offsets `runs` names.
///
/// # Safety
///
/// `runs` must be offsets `abi::ring` computed for the region mapped at
/// `base`, and `into` writable for their combined length.
unsafe fn read_runs(base: u64, into: *mut u8, runs: (ring::Run, ring::Run)) {
    let (first, second) = runs;
    // SAFETY: as above.
    unsafe {
        core::ptr::copy_nonoverlapping(
            (base + first.offset as u64) as *const u8,
            into,
            first.length,
        );
        if !second.is_empty() {
            core::ptr::copy_nonoverlapping(
                (base + second.offset as u64) as *const u8,
                into.add(first.length),
                second.length,
            );
        }
    }
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

/// Bulk copies of a packet's bytes this program has made.
///
/// **Counted rather than reasoned about**, which is RFC 0018's own wording. See
/// the same counter in `bin/netd`: together they are what prices the boundary,
/// because every one of these copies exists only because the driver and the
/// protocol code are in different domains. The four-byte length prefix in front
/// of each frame is not a packet and is not counted.
static COPIES: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Adds one to [`COPIES`].
fn copied() {
    COPIES.store(
        COPIES.load(core::sync::atomic::Ordering::Relaxed) + 1,
        core::sync::atomic::Ordering::Relaxed,
    );
}

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
/// RFC 0029 step 3's two report words, held here so `refresh` can keep
/// writing them after `serve` takes over the page.
static V6_PREFIX: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static V6_STATE: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

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
        held[6] | (u64::from(SERVING_NOW.load(Relaxed)) << 3),
        held[7],
        DELIVERED.load(Relaxed),
        WHY.load(Relaxed),
        // The ring's own two numbers. Counters are a story about the ring;
        // these are the ring. Where they disagree, the counters are wrong.
        // SAFETY: the ring's header, in the region this program mapped.
        unsafe { core::ptr::read_volatile((RING_AT + ring::HEAD_OFFSET as u64) as *const u64) },
        SERVING_TAIL.load(Relaxed),
        COPIES.load(Relaxed),
        BURST_PHASE.load(Relaxed),
        BURST_PONGS.load(Relaxed),
        BURST_RESULT.load(Relaxed),
        BURST_SENT.load(Relaxed),
        EMPTY_POLLS.load(Relaxed),
        LONGEST_WAIT.load(Relaxed),
        NOTIFIED_WAKES.load(Relaxed),
        V6_PREFIX.load(Relaxed),
        V6_STATE.load(Relaxed),
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

/// TCP segments handed on to `bin/tcpd`.
static TCP_FORWARDED: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// TCP segments taken back from `bin/tcpd` and transmitted.
static TCP_RETURNED: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Hands one TCP segment to `bin/tcpd`: eight bytes of addresses, then the
/// segment itself.
///
/// This program stays the only parser of the IPv4 header — what crosses is the
/// payload and the two addresses the pseudo-header needs, which is RFC 0020's
/// diagram exactly: "IPv4 payloads where protocol = 6".
///
/// # Safety
///
/// The forward ring must be mapped writable at [`TCP_FWD_AT`].
unsafe fn forward_tcp(source: Ipv4Addr, destination: Ipv4Addr, segment: &[u8]) -> bool {
    let Some(layout) = ring::Layout::for_region(RING_BYTES) else {
        return false;
    };
    // SAFETY: the ring's header, in the region this program mapped. Volatile
    // because the consumer is another domain and takes no lock.
    let (head, tail) = unsafe {
        (
            core::ptr::read_volatile((TCP_FWD_AT + ring::HEAD_OFFSET as u64) as *const u64),
            core::ptr::read_volatile((TCP_FWD_AT + ring::TAIL_OFFSET as u64) as *const u64),
        )
    };
    let Some(cursor) = ring::Cursor::new(layout, head, tail) else {
        return false;
    };
    let total = 8 + segment.len();
    let Some(framed) = ring::frame_to_write(layout, cursor, total) else {
        return false;
    };
    // Assembled contiguously, then written through `abi::ring`'s offsets. The
    // eight address bytes and the segment could be written as separate runs to
    // save this copy, but a wrap can fall inside the address prefix and the
    // arithmetic for that case is exactly the kind this program refuses to
    // write by hand. One bounded memcpy is the price of one copy routine.
    let mut entry = [0u8; 8 + MAX_FRAME];
    entry[0..4].copy_from_slice(&source.octets());
    entry[4..8].copy_from_slice(&destination.octets());
    let Some(slot) = entry.get_mut(8..total) else {
        return false;
    };
    slot.copy_from_slice(segment);
    let prefix = (total as u32).to_le_bytes();
    // SAFETY: offsets are `abi::ring`'s, inside the region mapped writable, and
    // `entry` is a buffer this program owns, `total` bounded by its size.
    unsafe {
        write_runs(TCP_FWD_AT, prefix.as_ptr(), framed.prefix);
        write_runs(TCP_FWD_AT, entry.as_ptr(), framed.payload);
    }
    copied();
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    // SAFETY: the ring's header, which only this program writes.
    unsafe {
        core::ptr::write_volatile(
            (TCP_FWD_AT + ring::HEAD_OFFSET as u64) as *mut u64,
            framed.next,
        );
    }
    // Index first, wake second, as every doorbell in this system orders it.
    call(syscall::INVOKE, TCP_BELL, method::SIGNAL, [0; 4]);
    TCP_FORWARDED.store(
        TCP_FORWARDED.load(core::sync::atomic::Ordering::Relaxed) + 1,
        core::sync::atomic::Ordering::Relaxed,
    );
    true
}

/// Takes segments `bin/tcpd` has handed back and puts them on the wire.
///
/// Each entry is eight bytes of addresses and a segment; this program wraps it
/// in the IPv4 and Ethernet headers `tcpd` deliberately cannot build, using
/// the gateway's hardware address for every destination — one interface, one
/// route, which is all this network has.
fn drain_tcp_back(me: (MacAddr, Ipv4Addr), gateway: MacAddr, tail: &mut u64) {
    let Some(layout) = ring::Layout::for_region(RING_BYTES) else {
        return;
    };
    let mut entry = [0u8; 8 + MAX_FRAME];
    let mut outgoing = [0u8; MAX_FRAME];
    for _ in 0..16 {
        // SAFETY: the ring's header, in the region this program mapped.
        let head = unsafe {
            core::ptr::read_volatile((TCP_BACK_AT + ring::HEAD_OFFSET as u64) as *const u64)
        };
        let Some(cursor) = ring::Cursor::new(layout, head, *tail) else {
            return;
        };
        let mut prefix = [0u8; ring::PREFIX];
        let Some(runs) = ring::length_to_read(layout, cursor) else {
            return;
        };
        // SAFETY: the ring is mapped and `prefix` is `PREFIX` writable bytes.
        unsafe { read_runs(TCP_BACK_AT, prefix.as_mut_ptr(), runs) };
        let length = u32::from_le_bytes(prefix) as usize;
        if !(8..=8 + MAX_FRAME).contains(&length) {
            *tail = tail.wrapping_add(ring::PREFIX as u64);
            publish_tcp_tail(*tail);
            continue;
        }
        let Some(framed) = ring::frame_to_read(layout, cursor, length) else {
            return;
        };
        // SAFETY: as above; `entry` is large enough and `length` bounded.
        unsafe { read_runs(TCP_BACK_AT, entry.as_mut_ptr(), framed.payload) };
        copied();
        *tail = framed.next;
        publish_tcp_tail(*tail);

        let destination = Ipv4Addr(u32::from_be_bytes([entry[4], entry[5], entry[6], entry[7]]));
        let segment = &entry[8..length];
        let body_length = segment.len();
        if ipv4::write_header(
            &mut outgoing[eth::HEADER..],
            me.1,
            destination,
            Protocol::TCP,
            body_length,
            0x2604,
        )
        .is_err()
        {
            continue;
        }
        let at = eth::HEADER + ipv4::HEADER;
        let Some(slot) = outgoing.get_mut(at..at + body_length) else {
            continue;
        };
        slot.copy_from_slice(segment);
        if eth::write_header(&mut outgoing, gateway, me.0, EtherType::IPV4).is_ok()
            // SAFETY: the return ring is mapped writable.
            && unsafe { send(&outgoing[..at + body_length]) }
        {
            TCP_RETURNED.store(
                TCP_RETURNED.load(core::sync::atomic::Ordering::Relaxed) + 1,
                core::sync::atomic::Ordering::Relaxed,
            );
        }
    }
}

/// Tells `bin/tcpd` how far this program has read its back ring.
fn publish_tcp_tail(tail: u64) {
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    // SAFETY: the ring's header, which only this program writes.
    unsafe {
        core::ptr::write_volatile((TCP_BACK_AT + ring::TAIL_OFFSET as u64) as *mut u64, tail);
    }
}

/// Takes whatever has arrived and gives each datagram to the socket it is for.
///
/// Called from a client's `RECV_FROM` **and** from the wake a frame rings.
///
/// This said "called from inside a client's `RECV_FROM`, because that is the
/// only event this service can act on while asleep on its endpoint" until
/// 2026-08-14. That stopped being true on 2026-08-13, when RFC 0010's question
/// 1 was answered and `serve` gained the `NOTIFIED` arm that drains without
/// anybody asking — see `serve`, which is the other caller. A comment
/// describing the constraint a change removed is worse than no comment: it
/// tells the next reader the service still cannot do the thing it now does.
///
/// A datagram is matched to a socket by **destination port**. A broadcast
/// destination is accepted as well as this interface's own address: a client
/// with no address yet is answered by broadcast, which is the whole reason
/// DHCP works at all.
fn drain_ring(
    sockets: &mut [Socket; SOCKETS],
    me: (MacAddr, Ipv4Addr),
    tail: &mut u64,
    can_tcp: bool,
) {
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
        let mut prefix = [0u8; ring::PREFIX];
        let Some(runs) = ring::length_to_read(layout, cursor) else {
            return;
        };
        // SAFETY: the ring is mapped and `prefix` is `PREFIX` writable bytes.
        unsafe { read_runs(RING_AT, prefix.as_mut_ptr(), runs) };
        let length = u32::from_le_bytes(prefix) as usize;
        if length == 0 || length > MAX_FRAME {
            // A length this program has stopped believing. Skip the prefix and
            // carry on rather than wedging on it for ever.
            *tail = tail.wrapping_add(ring::PREFIX as u64);
            continue;
        }
        // `None` is the producer mid-write, not an error. See `frame_to_read`.
        let Some(framed) = ring::frame_to_read(layout, cursor, length) else {
            return;
        };
        // SAFETY: as above; `frame` is `MAX_FRAME` writable bytes and `length`
        // is bounded by it.
        unsafe { read_runs(RING_AT, frame.as_mut_ptr(), framed.payload) };
        // Inbound, copy two of two: the ring into this program's buffer.
        copied();
        *tail = framed.next;
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
        // RFC 0020 step 4: a TCP segment for this interface goes to the
        // domain that understands it. Forwarded before the UDP refusal, so
        // "not UDP" keeps meaning what it says — a protocol nobody here
        // serves — rather than covering the one that is served next door.
        if can_tcp
            && header.protocol == Protocol::TCP
            && !header.is_fragment()
            && header.destination == me.1
        {
            // SAFETY: the forward ring is mapped writable when `can_tcp`.
            unsafe { forward_tcp(header.source, header.destination, payload) };
            continue;
        }
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
    mut can_tcp: bool,
    mut tail: u64,
    mut tcp_tail: u64,
) -> ! {
    loop {
        // The rings may land after serving has begun — a boot whose
        // demonstration ends early reaches here first — and a serve loop
        // that froze the answer it was constructed with refused `SYN·ACK`s
        // as `NOT_UDP` for the life of the boot, on the boots that lost
        // that race and only those.
        if can_send && !can_tcp {
            can_tcp = try_attach_tcp();
        }
        let (status_in, badge, method, args) = receive();
        // What serving has changed, put where the kernel can read it. See
        // `CACHE`: without this the page froze at the moment serving began.
        refresh();
        // **Woken by a frame rather than by a caller.** RFC 0010 question 1:
        // this is the wake that used to be impossible, and the reason this loop
        // no longer has to be asked before it looks at the wire. Drain, then go
        // back to waiting; there is nobody to reply to.
        //
        // The wake does not say which ring, and it does not need to: `tcpd`'s
        // doorbell and `netd`'s land in the same word, and looking at a ring
        // that is empty costs one volatile read.
        if status_in == status::NOTIFIED {
            NOTIFIED_WAKES.store(
                NOTIFIED_WAKES.load(core::sync::atomic::Ordering::Relaxed) + 1,
                core::sync::atomic::Ordering::Relaxed,
            );
            drain_ring(sockets, me, &mut tail, can_tcp);
            if can_tcp {
                drain_tcp_back(me, gateway, &mut tcp_tail);
            }
            continue;
        }
        if status_in != status::OK {
            continue;
        }
        if can_tcp {
            drain_tcp_back(me, gateway, &mut tcp_tail);
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
                drain_ring(sockets, me, &mut tail, can_tcp);

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

/// Whether each TCP ring has attached. Statics because both the
/// demonstration loop and `serve` retry them — the kernel installs the rings
/// after this program starts, so any single moment's answer can be "not yet".
static FWD_ATTACHED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
static BACK_ATTACHED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
/// Set the moment `serve` is entered, and reported: the kernel holds the DHCP
/// client back until this is true, because a caller that calls before its
/// service is receiving strands in the send queue — the fourth ordering bug
/// of this shape, and the first whose fix is to say when readiness happens
/// rather than to reorder who starts first.
static SERVING_NOW: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Retries whichever TCP ring is not attached yet. Idempotent, one ring at a
/// time, because a successful attach is not repeatable: retrying the pair as
/// one expression wedged `can_tcp` false forever on any boot where the two
/// slots were installed a pass apart.
fn try_attach_tcp() -> bool {
    use core::sync::atomic::Ordering::Relaxed;
    if !FWD_ATTACHED.load(Relaxed) && attach(TCP_FWD, TCP_FWD_AT, 1) {
        FWD_ATTACHED.store(true, Relaxed);
    }
    if !BACK_ATTACHED.load(Relaxed) && attach(TCP_BACK, TCP_BACK_AT, 1) {
        BACK_ATTACHED.store(true, Relaxed);
    }
    FWD_ATTACHED.load(Relaxed) && BACK_ATTACHED.load(Relaxed)
}

/// The entry point.
#[unsafe(no_mangle)]
extern "C" fn ipd_main() -> ! {
    if !attach(RING, RING_AT, 1) || !attach(REPORT, REPORT_AT, 1) {
        exit()
    }
    let can_send = attach(BACK, BACK_AT, 1) && attach(CONFIG, CONFIG_AT, 0);
    // RFC 0020 step 4: the rings to and from `bin/tcpd`. **Retried in the
    // demonstration loop rather than attached once here**, because the kernel
    // installs them *after* this program has started — the TCP domain is set
    // up on the other side of this program's own spawn — so a one-shot attach
    // at entry loses the race on every boot, silently, and the loss presents
    // as a service that took segments into a ring nobody ever drained. A slot
    // that is empty now and full in a moment is what retrying is for. Absent
    // on a machine with no TCP domain, which is a state rather than a fault —
    // TCP frames are then refused as `NOT_UDP` exactly as before the domain
    // existed.
    let mut can_tcp = false;
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
    let mut cache = NeighbourCache::<8>::new(ARP_LIFETIME);
    // Stands in for a clock. See `ARP_LIFETIME`.
    let mut ticks = 0u64;
    let mut me = (MacAddr::UNSPECIFIED, Ipv4Addr::UNSPECIFIED);
    let mut asked = false;
    let mut pinged = false;
    let mut quiet = 0u32;
    let mut run = 0u64;
    let mut sockets = [Socket {
        port: 0,
        generation: 1,
        from: Ipv4Addr::UNSPECIFIED,
        from_port: 0,
        length: 0,
        held: [0u8; DATAGRAM],
    }; SOCKETS];
    let mut pongs = 0u64;
    // RFC 0029 step 3: the v6 identity and its demonstrations. The
    // link-local address is derived the moment the MAC is known; the global
    // address and the default router arrive by SLAAC; the neighbour
    // solicitation and the ping mirror the ARP request and the v4 ping.
    let mut link_local = Ipv6Addr::UNSPECIFIED;
    let mut prefix6 = Ipv6Addr::UNSPECIFIED;
    let mut global6: Option<Ipv6Addr> = None;
    let mut router6: Option<Ipv6Addr> = None;
    let mut rs_sent = false;
    let mut rs_pass = 0u64;
    let mut ns6_sent = false;
    let mut ns6_pass = 0u64;
    let mut pinged6 = false;
    let mut ping6_pass = 0u64;
    let mut pongs6 = 0u64;
    // Sticky: the v6 host was resolved at least once. The cache entry
    // itself expires on a busy wire — ticks race past the lifetime — and
    // the report's question is "did NDP work", not "is the entry warm".
    let mut resolved6 = false;
    // The retry clock for the three sends above. Loop passes rather than
    // `ticks`: ticks advance one per *received* frame, and on the quiet
    // wire this family boots on, a lost reply would freeze exactly the
    // clock that should be retrying it.
    let mut passes = 0u64;
    // RFC 0018 step 7's burst state. See `BURST`.
    let mut phase = 0u32;
    let mut burst_sent = 0u32;
    let mut burst_pongs = 0u32;
    let mut burst_waited = 0u32;
    let mut burst_gateway: Option<MacAddr> = None;
    // Only this program advances the tail, so it is kept here and written out
    // rather than read back. A consumer that re-read its own index would be
    // trusting the producer with it.
    let mut tail = 0u64;
    // Where this program has read `tcpd`'s back ring up to. Same discipline.
    let mut tcp_tail = 0u64;

    // A report before anything has arrived, so that "this program never ran"
    // and "this program ran and saw nothing" are different findings. Without
    // it the kernel reads an absent marker for both, and the two have entirely
    // different causes.
    report(
        0,
        0,
        0,
        0,
        0,
        0,
        state(can_send, MacAddr::UNSPECIFIED, can_tcp),
        0,
        0,
        0,
    );

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
            state(can_send, me.0, can_tcp),
            pongs,
            prefix_word(prefix6),
            v6_word(global6.is_some(), router6.is_some(), resolved6, pongs6),
        );

        passes += 1;

        // The TCP rings, once the kernel has installed them. See the note at
        // `can_tcp`'s declaration: they land after this program starts.
        //
        // **Each ring retried separately, because a successful attach is not
        // repeatable.** The first version retried the pair as one expression;
        // on a boot where the forward ring's slot was installed a pass before
        // the back ring's, the forward attach succeeded, the pair failed, and
        // every later pass re-attached an already-mapped ring — which is
        // refused — so the pair stayed false for the life of the boot with
        // both rings sitting installed. One boot in a handful lost that race,
        // which is the worst kind of failure to have.
        if can_send && !can_tcp {
            can_tcp = try_attach_tcp();
        }

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
            && let Some(gateway) = cache.lookup(Address::V4(GATEWAY), ticks)
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

        // RFC 0029 step 3: the same demonstrations, second family. A router
        // solicitation instead of a DHCP exchange, a neighbour solicitation
        // instead of an ARP request, and the same ping — each built entirely
        // by `bhaskix-net` and each sent once.
        if me.0 != MacAddr::UNSPECIFIED && link_local.is_unspecified() {
            link_local = Ipv6Addr::link_local_from(me.0);
        }
        if router6.is_none() && rs_sent && passes >= rs_pass + 200_000 {
            rs_sent = false;
        }
        if can_send && !rs_sent && !link_local.is_unspecified() {
            let mut message = [0u8; 16];
            if let Ok(body) = icmpv6::write_router_solicitation(
                &mut message,
                link_local,
                Ipv6Addr::ALL_ROUTERS,
                Some(me.0),
            ) && let Some(total) = frame6(
                &mut outgoing,
                Ipv6Addr::ALL_ROUTERS.multicast_mac(),
                me.0,
                link_local,
                Ipv6Addr::ALL_ROUTERS,
                255,
                &message[..body],
            )
                // SAFETY: the return ring is mapped writable.
                && unsafe { send(&outgoing[..total]) }
            {
                built += 1;
                rs_sent = true;
                rs_pass = passes;
            }
        }
        if ns6_sent
            && passes >= ns6_pass + 200_000
            && cache.lookup(Address::V6(HOST6), ticks).is_none()
        {
            ns6_sent = false;
        }
        if can_send
            && !ns6_sent
            && let Some(from) = global6
        {
            let mut message = [0u8; 32];
            if let Ok(body) = icmpv6::write_neighbour_solicitation(
                &mut message,
                from,
                HOST6.solicited_node(),
                HOST6,
                Some(me.0),
            ) && let Some(total) = frame6(
                &mut outgoing,
                HOST6.solicited_node().multicast_mac(),
                me.0,
                from,
                HOST6.solicited_node(),
                255,
                &message[..body],
            )
                // SAFETY: the return ring is mapped writable.
                && unsafe { send(&outgoing[..total]) }
            {
                built += 1;
                ns6_sent = true;
                ns6_pass = passes;
            }
        }
        if pinged6 && pongs6 == 0 && passes >= ping6_pass + 200_000 {
            pinged6 = false;
        }
        if can_send
            && !pinged6
            && let Some(from) = global6
            && let Some(host) = cache.lookup(Address::V6(HOST6), ticks)
        {
            let mut message = [0u8; icmpv6::HEADER + PING_PAYLOAD.len()];
            if let Ok(body) =
                icmpv6::write_echo(&mut message, from, HOST6, false, PING6_ID, 1, &PING_PAYLOAD)
                && let Some(total) =
                    frame6(&mut outgoing, host, me.0, from, HOST6, 64, &message[..body])
                // SAFETY: the return ring is mapped writable.
                && unsafe { send(&outgoing[..total]) }
            {
                built += 1;
                pinged6 = true;
                ping6_pass = passes;
            }
        }

        // RFC 0018 step 7: the burst, once the single ping above has come back.
        //
        // Four phases: serialised at each payload size, then pipelined at each.
        // Serialised gives round-trip latency, because one request is in flight
        // at a time and the elapsed time *is* the round trip. Pipelined gives a
        // rate — bounded, in both the split and folded builds, by this driver
        // allowing one transmit outstanding at a time, which is a property of
        // the driver and not of the boundary being priced.
        //
        // The kernel cannot see inside this loop, so the phase counter is the
        // signal: it stamps its clock when the number moves.
        // The gateway's hardware address is taken once and held for the whole
        // burst. **The cache expires in frames handled, and the burst handles
        // more frames than the lifetime**: every run stopped at exactly 245 of
        // 256 in the last phase, which is the tick where `ARP_LIFETIME` ran out
        // and `lookup` began returning nothing. Re-asking mid-burst would put
        // an ARP exchange inside the interval being timed, so the address is
        // held instead — a measurement keeps everything constant except the
        // thing it is measuring.
        if burst_gateway.is_none()
            && let Some(found) = cache.lookup(Address::V4(GATEWAY), ticks)
        {
            burst_gateway = Some(found);
        }
        if can_send
            && pongs >= 1
            && phase < 4
            && me.0 != MacAddr::UNSPECIFIED
            && let Some(gateway) = burst_gateway
        {
            let size = if phase.is_multiple_of(2) {
                BURST_SMALL
            } else {
                BURST_LARGE
            };
            let serialised = phase < 2;
            // Serialised waits for the previous reply; pipelined does not.
            let in_flight = burst_sent.saturating_sub(burst_pongs);
            let room = if serialised {
                in_flight == 0
            } else {
                in_flight < BURST_WINDOW
            };
            if burst_sent < BURST && room {
                let mut message = [0u8; icmp::HEADER + BURST_LARGE];
                let mut payload = [0u8; BURST_LARGE];
                // A pattern rather than zeroes, so a reply that came back
                // hollow is not mistaken for one that came back whole.
                for (index, byte) in payload[..size].iter_mut().enumerate() {
                    *byte = (index as u8) ^ 0x5a;
                }
                if let Ok(body) = icmp::write(
                    &mut message[..icmp::HEADER + size],
                    false,
                    BURST_ID,
                    (burst_sent + 1) as u16,
                    &payload[..size],
                ) && ipv4::write_header(
                    &mut outgoing[eth::HEADER..],
                    me.1,
                    GATEWAY,
                    Protocol::ICMP,
                    body,
                    0x2602,
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
                        burst_sent += 1;
                        BURST_SENT
                            .store(u64::from(burst_sent), core::sync::atomic::Ordering::Relaxed);
                    }
                }
            }

            burst_waited += 1;
            // A phase ends when every reply is in, or when waiting for them has
            // gone on long enough that something is not coming. Both end it:
            // a burst that hangs would keep this program out of `serve`.
            if burst_pongs >= BURST || burst_waited > BURST_PATIENCE {
                // What this phase achieved, before the counters go back to zero.
                BURST_RESULT.store(
                    u64::from(burst_pongs),
                    core::sync::atomic::Ordering::Relaxed,
                );
                phase += 1;
                burst_sent = 0;
                burst_pongs = 0;
                burst_waited = 0;
                BURST_SENT.store(0, core::sync::atomic::Ordering::Relaxed);
                BURST_PONGS.store(0, core::sync::atomic::Ordering::Relaxed);
                // Written last, because it is the edge the kernel is watching.
                BURST_PHASE.store(u64::from(phase), core::sync::atomic::Ordering::Relaxed);
            }
        }

        // Segments `bin/tcpd` has queued while this loop was measuring. One
        // volatile read when the ring is empty, and a `SYN` that would
        // otherwise wait for `serve` when it is not.
        //
        // The gateway's address is used if the cache still holds it and the
        // broadcast address if not — **not** gated on the lookup, which is
        // what it was: the cache expires by frames handled, the burst handles
        // more frames than the lifetime, so whether a segment drained here
        // depended on whether it arrived before or after an expiry nobody
        // was thinking about. The demonstration connected on the boots where
        // it won that race and sat unsent on the boots where it lost, which
        // is the exact shape of flakiness this project keeps paying for.
        // Slirp routes on the IP header and accepts a broadcast frame — the
        // DHCP exchange depends on that already.
        if can_tcp && me.0 != MacAddr::UNSPECIFIED {
            let mac = cache
                .lookup(Address::V4(GATEWAY), ticks)
                .unwrap_or(MacAddr::BROADCAST);
            drain_tcp_back(me, mac, &mut tcp_tail);
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
            // **Not while a burst phase is unfinished.** This left for `serve`
            // with the last phase at 245 replies of 256: the ring went quiet
            // between packets, the counter tripped, and the measurement was
            // abandoned rather than finished. `BURST_PATIENCE` already bounds a
            // phase that will never complete, so waiting here cannot hang.
            //
            // Gated on the same conditions the burst itself needs. Without
            // them the burst never starts, `phase` stays at zero for ever, and
            // waiting for it would strand this program short of `serve` — on
            // every machine with no network, which is every BIOS boot.
            if can_send && pongs >= 1 && phase < 4 {
                // Still measuring. Fall through to another pass.
            } else if (done && quiet > 20_000) || quiet > 2_000_000 {
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
                        state(can_send, me.0, can_tcp),
                        pongs,
                        prefix_word(prefix6),
                        v6_word(global6.is_some(), router6.is_some(), resolved6, pongs6),
                    );
                    let gateway = cache
                        .lookup(Address::V4(GATEWAY), ticks)
                        .unwrap_or(MacAddr::BROADCAST);
                    // Bound before serving, not before the demonstration: the
                    // loop above polls deliberately and would be woken for
                    // nothing. Refused on a machine with no inbox, which is a
                    // state — `serve` then behaves exactly as it did before.
                    call(syscall::INVOKE, INBOX, method::BIND_SELF, [0; 4]);
                    // Published *before* the blocking receive, so the kernel
                    // reads "serving" only when a caller can no longer strand.
                    SERVING_NOW.store(true, core::sync::atomic::Ordering::Relaxed);
                    report(
                        frames,
                        bytes,
                        first_source,
                        refused,
                        built,
                        cache.live(ticks) as u64,
                        state(can_send, me.0, can_tcp),
                        pongs,
                        prefix_word(prefix6),
                        v6_word(global6.is_some(), router6.is_some(), resolved6, pongs6),
                    );
                    serve(&mut sockets, me, gateway, can_send, can_tcp, tail, tcp_tail);
                }
                report(
                    frames,
                    bytes,
                    first_source,
                    refused,
                    built,
                    cache.live(ticks) as u64,
                    state(can_send, me.0, can_tcp),
                    pongs,
                    prefix_word(prefix6),
                    v6_word(global6.is_some(), router6.is_some(), resolved6, pongs6),
                );
                exit()
            }
            // One look that found nothing. See `EMPTY_POLLS`.
            EMPTY_POLLS.store(
                EMPTY_POLLS.load(core::sync::atomic::Ordering::Relaxed) + 1,
                core::sync::atomic::Ordering::Relaxed,
            );
            run += 1;
            call(syscall::YIELD, 0, 0, [0; 4]);
            continue;
        }
        // A frame arrived: close the run of empty looks that preceded it.
        if run > LONGEST_WAIT.load(core::sync::atomic::Ordering::Relaxed) {
            LONGEST_WAIT.store(run, core::sync::atomic::Ordering::Relaxed);
        }
        run = 0;
        quiet = 0;

        // The four-byte length first.
        let mut prefix = [0u8; ring::PREFIX];
        let Some(runs) = ring::length_to_read(layout, cursor) else {
            call(syscall::YIELD, 0, 0, [0; 4]);
            continue;
        };
        // SAFETY: the ring is mapped and `prefix` is `PREFIX` writable bytes.
        unsafe { read_runs(RING_AT, prefix.as_mut_ptr(), runs) };
        let length = u32::from_le_bytes(prefix) as usize;
        // A number the other side chose. Bounded before it is used, and a
        // refusal rather than a clamp: a frame that does not fit is not a
        // shorter frame, it is a producer this program has stopped believing.
        if length == 0 || length > MAX_FRAME {
            refused += 1;
            tail = tail.wrapping_add(ring::PREFIX as u64);
            publish(tail);
            continue;
        }

        // The producer has published a length but not yet the bytes. Not an
        // error and not a refusal: look again without moving the tail.
        let Some(framed) = ring::frame_to_read(layout, cursor, length) else {
            call(syscall::YIELD, 0, 0, [0; 4]);
            continue;
        };
        // SAFETY: the ring is mapped and `buffer` is `MAX_FRAME` writable
        // bytes, which `length` is bounded by above.
        unsafe { read_runs(RING_AT, buffer.as_mut_ptr(), framed.payload) };
        // Inbound, copy two of two, on the demonstration loop's path rather than
        // the service's. **After** the copy, not before: this path retries when
        // the producer has published a length and not yet the bytes, and a
        // counter incremented before the retry would price crossings that never
        // happened.
        copied();

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

        // A TCP segment arriving while the demonstration is still running.
        // Forwarded here as well as in `drain_ring`, because `bin/tcpd` opens
        // its own connection as soon as it is configured — which is while this
        // loop is still measuring — and an answer eaten here would cost it a
        // retransmission timeout for nothing.
        if can_tcp
            && let Ok(parsed) = EthFrame::parse(&buffer[..length])
            && parsed.ethertype == EtherType::IPV4
            && let Ok((header, payload)) = Ipv4Header::parse(parsed.payload)
            && header.protocol == Protocol::TCP
            && !header.is_fragment()
            && header.destination == me.1
        {
            // SAFETY: the forward ring is mapped writable when `can_tcp`.
            unsafe { forward_tcp(header.source, header.destination, payload) };
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
                } else if echo.identifier == BURST_ID {
                    // A burst reply. Counted by identifier and length rather
                    // than by comparing every byte: the comparison is what the
                    // demonstration ping above is for, and doing it per packet
                    // would put this program's own memcmp inside the number it
                    // is trying to measure.
                    if echo.payload.len() == BURST_SMALL || echo.payload.len() == BURST_LARGE {
                        burst_pongs += 1;
                        BURST_PONGS.store(
                            u64::from(burst_pongs),
                            core::sync::atomic::Ordering::Relaxed,
                        );
                    }
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

        // RFC 0029 step 3: the second family's arrivals. Neighbour discovery
        // is accepted only at hop limit 255 — the check `icmpv6`'s header
        // assigned to the caller, because a discovery message that crossed a
        // router is a forgery by construction, and the hop limit lives in
        // the IP header only this program sees.
        if let Ok(parsed) = EthFrame::parse(&buffer[..length])
            && parsed.ethertype == EtherType::IPV6
            && let Ok((header6, body6)) = Ipv6Header::parse(parsed.payload)
            && header6.next_header == NextHeader::ICMPV6
            && !body6.is_empty()
        {
            let (from6, to6) = (header6.source, header6.destination);
            match body6[0] {
                icmpv6::ROUTER_ADVERTISEMENT if header6.hop_limit == 255 => {
                    if let Ok(ra) = icmpv6::RouterAdvertisement::parse(body6, from6, to6) {
                        if let Some(link) = ra.source_link {
                            cache.learn(Address::V6(from6), link, ticks);
                        }
                        if ra.router_lifetime_seconds > 0 && router6.is_none() {
                            router6 = Some(from6);
                        }
                        // SLAAC's one step: the advertised /64 plus this
                        // interface's identifier. Held once obtained — a
                        // later advertisement does not move an address
                        // sockets may already be bound to.
                        if global6.is_none()
                            && let Some(info) = ra.prefix
                            && info.autonomous
                            && info.prefix_length == 64
                            && me.0 != MacAddr::UNSPECIFIED
                        {
                            prefix6 = info.prefix;
                            global6 = Some(Ipv6Addr::from_prefix(
                                info.prefix,
                                Ipv6Addr::interface_id(me.0),
                            ));
                        }
                    }
                }
                icmpv6::NEIGHBOUR_ADVERTISEMENT if header6.hop_limit == 255 => {
                    if let Ok(na) = icmpv6::NeighbourAdvertisement::parse(body6, from6, to6)
                        && let Some(link) = na.target_link
                        && cache.learn(Address::V6(na.target), link, ticks)
                        && na.target == HOST6
                    {
                        resolved6 = true;
                    }
                }
                icmpv6::NEIGHBOUR_SOLICITATION if header6.hop_limit == 255 && can_send => {
                    if let Ok(ns) = icmpv6::NeighbourSolicitation::parse(body6, from6, to6)
                        && (ns.target == link_local || Some(ns.target) == global6)
                        && !from6.is_unspecified()
                    {
                        // Answered from the address that was asked about, to
                        // the asker, at their link address — the option if
                        // they carried one, the frame's source if not.
                        let to_mac = ns.source_link.unwrap_or(parsed.source);
                        let mut message = [0u8; 40];
                        if let Ok(body) = icmpv6::write_neighbour_advertisement(
                            &mut message,
                            ns.target,
                            from6,
                            ns.target,
                            true,
                            Some(me.0),
                        ) && let Some(total) = frame6(
                            &mut outgoing,
                            to_mac,
                            me.0,
                            ns.target,
                            from6,
                            255,
                            &message[..body],
                        )
                            // SAFETY: the return ring is mapped writable.
                            && unsafe { send(&outgoing[..total]) }
                        {
                            built += 1;
                        }
                    }
                }
                icmpv6::ECHO_REQUEST if can_send => {
                    if let Ok(echo) = icmpv6::Echo::parse(body6, from6, to6)
                        && !echo.is_reply
                        && (to6 == link_local || Some(to6) == global6)
                    {
                        let mut message = [0u8; MAX_FRAME];
                        if let Ok(body) = icmpv6::write_echo(
                            &mut message,
                            to6,
                            from6,
                            true,
                            echo.identifier,
                            echo.sequence,
                            echo.payload,
                        ) && let Some(total) = frame6(
                            &mut outgoing,
                            parsed.source,
                            me.0,
                            to6,
                            from6,
                            64,
                            &message[..body],
                        )
                            // SAFETY: the return ring is mapped writable.
                            && unsafe { send(&outgoing[..total]) }
                        {
                            built += 1;
                        }
                    }
                }
                icmpv6::ECHO_REPLY => {
                    // The v6 pong. Matched by identifier and payload, the
                    // same discipline as the v4 one: only an exact return
                    // proves the whole path.
                    if let Ok(echo) = icmpv6::Echo::parse(body6, from6, to6)
                        && echo.is_reply
                        && echo.identifier == PING6_ID
                        && echo.payload == PING_PAYLOAD
                    {
                        pongs6 += 1;
                    }
                }
                _ => {}
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
                    cache.learn(
                        Address::V4(packet.sender_protocol),
                        packet.sender_hardware,
                        ticks,
                    );
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

        tail = framed.next;
        publish(tail);
        report(
            frames,
            bytes,
            first_source,
            refused,
            built,
            cache.live(ticks) as u64,
            state(can_send, me.0, can_tcp),
            pongs,
            prefix_word(prefix6),
            v6_word(global6.is_some(), router6.is_some(), resolved6, pongs6),
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
/// The high half of the SLAAC prefix, as one report word. Zero until a
/// router advertisement carried one, which is what makes zero mean "none".
fn prefix_word(prefix: Ipv6Addr) -> u64 {
    let o = prefix.octets();
    u64::from_be_bytes([o[0], o[1], o[2], o[3], o[4], o[5], o[6], o[7]])
}

/// What v6 obtained, as bits, with the echo count above them.
fn v6_word(global: bool, router: bool, resolved: bool, pongs6: u64) -> u64 {
    u64::from(global) | (u64::from(router) << 1) | (u64::from(resolved) << 2) | (pongs6 << 8)
}

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
    v6_prefix: u64,
    v6_state: u64,
) {
    let words = [
        MARKER,
        frames,
        bytes,
        first_source,
        refused,
        // Frames this program *built* and handed back, and how many mappings
        // its cache holds. The first says the return path works from this end;
        // the second is the neighbour cache running outside a host test for the
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
        // Words 11 and 12 belong to the ring's own head and tail -- zero
        // here, filled by `refresh` once serving starts, printed by the
        // kernel's "ipd after" line. RFC 0029's first draft took the zeros
        // for spares and its v6 words were silently overwritten on the
        // first refresh; the v6 words live at 21 and 22 instead, and this
        // comment is the map that was missing.
        0,
        0,
        COPIES.load(core::sync::atomic::Ordering::Relaxed),
        BURST_PHASE.load(core::sync::atomic::Ordering::Relaxed),
        BURST_PONGS.load(core::sync::atomic::Ordering::Relaxed),
        BURST_RESULT.load(core::sync::atomic::Ordering::Relaxed),
        BURST_SENT.load(core::sync::atomic::Ordering::Relaxed),
        EMPTY_POLLS.load(core::sync::atomic::Ordering::Relaxed),
        LONGEST_WAIT.load(core::sync::atomic::Ordering::Relaxed),
        NOTIFIED_WAKES.load(core::sync::atomic::Ordering::Relaxed),
        // RFC 0029 step 3: the high half of the SLAAC prefix, and a word
        // packing what v6 obtained with the v6 echo count above it. Stored
        // into statics as well, so `refresh` keeps reporting them after
        // serving starts.
        v6_prefix,
        v6_state,
    ];
    V6_PREFIX.store(v6_prefix, core::sync::atomic::Ordering::Relaxed);
    V6_STATE.store(v6_state, core::sync::atomic::Ordering::Relaxed);
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
fn write_report(words: [u64; 23]) {
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
