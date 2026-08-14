// SPDX-License-Identifier: Apache-2.0
//! The TCP service, in a domain with no device.
//!
//! [RFC 0020](../../../docs/rfc/0020-tcp.md) step 4, and the first program to
//! run the state machine on a machine rather than under a test harness. What it
//! holds: a ring `bin/ipd` forwards TCP segments into, a ring it hands segments
//! back through, one page saying what interface it is on, one page it reports
//! through, an endpoint, and a notification it can be woken by — for a frame,
//! or for a deadline it armed. **No device, no DMA window, no interrupt, no
//! address of its own.**
//!
//! # Why a third domain
//!
//! TCP is the largest parser of remote input this system will contain, and the
//! one with *state* a remote party can drive: a datagram parser forgets each
//! packet; a TCP endpoint remembers sequence numbers, windows and timers for as
//! long as the peer keeps it alive. A bug here must not take down the domain
//! holding the machine's address and every UDP socket — including the one
//! holding the DHCP lease — which is the same argument that split `netd` from
//! `ipd`, made stronger.
//!
//! # The refusal this program owes RFC 0021
//!
//! A TCP initial sequence number must be unpredictable, or an off-path attacker
//! injects into connections without seeing a packet. This program draws its
//! 128-bit secret from `bhaskix-rand` **before doing anything else**, and on a
//! machine that cannot be unpredictable it reports why and serves nothing.
//! That is RFC 0021's policy — *the caller refuses* — with this program as the
//! caller it was written about.
//!
//! # What step 4 does and does not demonstrate
//!
//! The serve loop runs: callers, frames and timers, one blocking `receive`,
//! told apart by what it returns. The demonstration is a connection this
//! program opens itself — a `SYN` built from a drawn sequence number, carried
//! by `ipd` and `netd` onto the wire, and whatever the network answers driven
//! back into the same state machine the host tests drive. Minting connection
//! capabilities to *other* programs is step 5, and a caller today is told
//! [`tcp::LATER`] rather than left to guess.
#![no_std]
#![no_main]

use bhaskix_abi::{method, ring, status, syscall, tcp};
use bhaskix_net::siphash::Key;
use bhaskix_net::tcp::{
    FourTuple, isn,
    segment::{self, Segment},
    state::{self, Action, Event, Tcb, Timer},
};
use bhaskix_net::{Address, Ipv4Addr, Port};

/// Slot: the ring `bin/ipd` forwards TCP segments into.
const FWD: u64 = 0;
/// Slot: the page this program leaves its findings in.
const REPORT: u64 = 1;
/// Slot: the ring this program hands segments back to `bin/ipd` through.
const BACK: u64 = 2;
/// Slot: what interface this machine is, read-only, written by the kernel.
const CONFIG: u64 = 3;
/// Slot: the endpoint this service answers on.
const ENDPOINT: u64 = 4;
/// Slot: the doorbell that wakes `bin/ipd` when a segment is in the back ring.
const DOORBELL: u64 = 5;
/// Slot: this program's own notification — `ipd` rings it for a frame, and a
/// deadline armed on it fires through the same word. One wait, told apart by
/// bits, which is RFC 0010's badge-as-bitmask doing what it was designed for.
const INBOX: u64 = 6;

/// Where this program maps what it holds.
const FWD_AT: u64 = 0x2300_0000;
const REPORT_AT: u64 = 0x2310_0000;
const BACK_AT: u64 = 0x2320_0000;
const CONFIG_AT: u64 = 0x2330_0000;

/// Bytes in each ring, matching what the kernel granted.
const RING_BYTES: usize = 16 * 4096;

/// The largest entry this program will take out of the ring: the eight-byte
/// address prefix and a segment no larger than an Ethernet payload.
const MAX_ENTRY: usize = 8 + 1500;

/// The marker the kernel looks for before believing the report.
const MARKER: u64 = 0x3144_5043_5444_0a54;

/// The marker the kernel writes before this program's configuration is true.
///
/// The same value `bin/ipd` waits for, because it is the same page format
/// written by the same kernel code.
const CONFIG_MARKER: u64 = 0x3146_4e43_5049_5f4e;

/// The address this program's demonstration connects to.
///
/// RFC 0020 step 5: the harness's `guestfwd` peer, a host-side `cat` behind
/// `10.0.2.100:9` that echoes the stream until EOF. Deterministic on every
/// boot, which is what a live network never is — a hardcoded address is
/// acceptable in a demonstration for the same reason `bin/ipd` pings a
/// hardcoded gateway, and a configured route stays the honest general answer
/// nothing here can read yet.
const PEER: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 100);

/// The port the echo peer answers on. Nine is `discard` by tradition; here it
/// is whatever the harness forwarded, and the number matters only in that both
/// ends agree.
const DEMO_PORT: u16 = 9;

/// What the demonstration sends, and must receive back unchanged.
///
/// Sixteen bytes, so it fits one segment and the whole exchange is
/// SYN, SYN·ACK, ACK, data, echo, FIN, FIN — every arrow of the diagram every
/// TCP text draws, produced by a state machine that was host-tested against a
/// simulated peer and is now talking to a real one.
const DEMO_PAYLOAD: &[u8] = b"bhaskix-tcp-0001";

/// The local port the demonstration uses. Above the well-known range, and
/// fixed so the report is deterministic.
const DEMO_LOCAL: u16 = 49999;

/// The receive window the demonstration advertises: what a page holds.
const DEMO_WINDOW: u16 = 4096;

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

/// Blocks until a caller calls or the inbox is rung, and says which.
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

/// Reads the cycle counter. Unprivileged: `CR4.TSD` is clear on this machine.
fn rdtsc() -> u64 {
    let low: u32;
    let high: u32;
    // SAFETY: reads a counter and touches no memory. RFC 0019 records that this
    // is readable at every privilege level here.
    unsafe {
        core::arch::asm!("rdtsc", out("eax") low, out("edx") high, options(nomem, nostack));
    }
    (u64::from(high) << 32) | u64::from(low)
}

/// The clock the state machine runs on: monotonic nanoseconds.
///
/// 128-bit intermediate on purpose. `tsc * 1_000_000_000` overflows a `u64`
/// eighteen seconds after reset on a gigahertz counter, and a clock that wraps
/// during boot is a clock that fires every armed deadline at once.
fn now_nanos(hertz: u64) -> u64 {
    if hertz == 0 {
        return 0;
    }
    (u128::from(rdtsc()) * 1_000_000_000 / u128::from(hertz)) as u64
}

/// A moment in nanoseconds, as the cycle count `ARM` wants.
///
/// Zero on a machine with no calibrated counter, for the same reason
/// [`now_nanos`] is: arming at zero is refused by the kernel and the caller
/// falls back to a yield, where a division by a rate of zero would be a panic
/// in the service holding every connection.
fn nanos_to_tsc(nanos: u64, hertz: u64) -> u64 {
    if hertz == 0 {
        return 0;
    }
    (u128::from(nanos) * u128::from(hertz) / 1_000_000_000) as u64
}

/// Copies `source` into a ring mapped at `base`, at the offsets `runs` names.
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

/// Copies out of a ring mapped at `base` into `into`.
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

/// Hands one entry to `bin/ipd`: eight bytes of addresses, then the segment.
///
/// # Safety
///
/// The back ring must be mapped writable at [`BACK_AT`].
unsafe fn send_entry(source: Ipv4Addr, destination: Ipv4Addr, segment: &[u8]) -> bool {
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
    let Some(cursor) = ring::Cursor::new(layout, head, tail) else {
        return false;
    };
    let total = 8 + segment.len();
    let Some(framed) = ring::frame_to_write(layout, cursor, total) else {
        return false;
    };
    let mut entry = [0u8; MAX_ENTRY];
    let Some(slot) = entry.get_mut(..total) else {
        return false;
    };
    slot[0..4].copy_from_slice(&source.octets());
    slot[4..8].copy_from_slice(&destination.octets());
    slot[8..].copy_from_slice(segment);
    let prefix = (total as u32).to_le_bytes();
    // SAFETY: every offset is `abi::ring`'s, inside the region this program
    // mapped writable, and `entry` is a buffer it owns.
    unsafe {
        write_runs(BACK_AT, prefix.as_ptr(), framed.prefix);
        write_runs(BACK_AT, slot.as_ptr(), framed.payload);
    }
    // The bytes, then a fence, then the index that publishes them.
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    // SAFETY: the ring's header, which only this program writes.
    unsafe {
        core::ptr::write_volatile(
            (BACK_AT + ring::HEAD_OFFSET as u64) as *mut u64,
            framed.next,
        );
    }
    // Index first, wake second, exactly as `ipd` orders its own doorbell.
    call(syscall::INVOKE, DOORBELL, method::SIGNAL, [0; 4]);
    true
}

/// What the demonstration connection has reached. Outcomes for the report.
mod outcome {
    /// Still going, or never started.
    pub const PENDING: u64 = 0;
    /// A `RST` came back: a remote stack heard the `SYN` and refused it.
    /// **The whole path worked** — that is what this value proves.
    pub const REFUSED: u64 = 1;
    /// Retransmissions ran out. The `SYN`s went to the ring; whether anything
    /// beyond `ipd` heard them, this machine cannot say.
    pub const UNREACHABLE: u64 = 2;
    /// The connection opened and the payload has been sent; the echo is not
    /// back yet. The steady state only if the peer swallows data it accepted.
    pub const ESTABLISHED: u64 = 3;
    /// The machine cannot be unpredictable, so nothing was attempted.
    pub const NO_ENTROPY: u64 = 4;
    /// There is no network to demonstrate against.
    pub const NO_NETWORK: u64 = 5;
    /// The payload came back byte-for-byte and the close is under way.
    /// With the connection in `TIME_WAIT`, this is RFC 0020 step 5's gate:
    /// connect, echo, orderly close, all through three domains and a wire.
    pub const ECHOED: u64 = 6;
    /// `TIME_WAIT` was entered **and left**: the full lifetime of a
    /// connection, first byte to freed control block, on real time.
    pub const ORDERLY: u64 = 7;
    /// Something came back that was not the payload sent. Distinct from
    /// silence, because a peer that corrupts is a different finding from a
    /// peer that is absent.
    pub const MANGLED: u64 = 8;
}

/// Where the demonstration has got to. Drives the one-shot events — write
/// once, shut down once — that the state machine must not be handed twice.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Demo {
    /// Waiting for the handshake to complete.
    Opening,
    /// The payload is written into the machine; watching for the echo.
    Sent,
    /// The echo matched and `Shutdown` has been driven.
    Closing,
    /// Nothing more to do.
    Done,
}

/// One armed deadline per timer, as absolute nanoseconds.
///
/// RFC 0019 gives one deadline per notification and says a service needing
/// several keeps its own ordered list and arms the nearest. This is that list,
/// sized by [`Timer`]'s four variants — and it is the workload `M4-10b`'s
/// timer wheel has been waiting for since M4, in its smallest real form.
struct Deadlines {
    at: [Option<u64>; 4],
}

impl Deadlines {
    const fn new() -> Self {
        Self { at: [None; 4] }
    }

    fn slot(timer: Timer) -> usize {
        match timer {
            Timer::Retransmit => 0,
            Timer::DelayedAck => 1,
            Timer::Probe => 2,
            Timer::TimeWait => 3,
        }
    }

    fn arm(&mut self, timer: Timer, at: u64) {
        self.at[Self::slot(timer)] = Some(at);
    }

    fn cancel(&mut self, timer: Timer) {
        self.at[Self::slot(timer)] = None;
    }

    /// The nearest armed deadline, if any.
    fn nearest(&self) -> Option<u64> {
        self.at.iter().flatten().copied().min()
    }

    /// Takes one due deadline, earliest first.
    fn due(&mut self, now: u64) -> Option<Timer> {
        let timers = [
            Timer::Retransmit,
            Timer::DelayedAck,
            Timer::Probe,
            Timer::TimeWait,
        ];
        let index = self
            .at
            .iter()
            .enumerate()
            .filter_map(|(index, at)| at.map(|at| (index, at)))
            .filter(|(_, at)| *at <= now)
            .min_by_key(|(_, at)| *at)
            .map(|(index, _)| index)?;
        self.at[index] = None;
        Some(timers[index])
    }
}

/// Everything the serve loop carries.
struct Service {
    key: Key,
    hertz: u64,
    me: Ipv4Addr,
    tcb: Tcb,
    deadlines: Deadlines,
    /// Where this program has read the forward ring up to.
    tail: u64,
    /// The demonstration's outcome, for the report.
    outcome: u64,
    /// Segments taken from the forward ring.
    taken: u64,
    /// Segments handed to the back ring.
    sent: u64,
    /// Entries refused before they reached the machine.
    refused: u64,
    /// Which one-shot demonstration events have been driven.
    demo: Demo,
    /// What the peer has echoed back, in order. Step 5 stands in for the
    /// program's receive ring; the machine only ever reported *counts*, and
    /// these are the bytes those counts were about.
    echo: [u8; DEMO_PAYLOAD.len()],
    /// How many of those bytes have arrived.
    echoed: usize,
}

/// Performs what one `step` asked for.
fn perform(service: &mut Service, actions: &state::Actions) {
    for action in actions.iter() {
        match action {
            Action::Emit(emit) => {
                // An `Emit` names a *range of the stream*, not bytes — the
                // design that keeps the machine pure — and this is where the
                // range becomes bytes. The demonstration's send stream is
                // [`DEMO_PAYLOAD`], standing in for the program ring a real
                // client supplies; byte `k` of the stream carries sequence
                // `iss + 1 + k`, the `+ 1` being the `SYN`'s own number.
                let offset = emit
                    .sequence
                    .0
                    .wrapping_sub(service.tcb.iss.0.wrapping_add(1))
                    as usize;
                let payload = DEMO_PAYLOAD
                    .get(offset..)
                    .and_then(|from| from.get(..usize::from(emit.length)))
                    .unwrap_or(&[]);
                let built = emit.segment(service.tcb.connection, payload);
                let mut bytes = [0u8; segment::MAX_HEADER + DEMO_PAYLOAD.len()];
                let Some(destination) = service.tcb.connection.remote.v4() else {
                    continue;
                };
                if let Ok(written) = segment::write(&mut bytes, &built, service.me, destination) {
                    // SAFETY: the back ring is mapped writable at BACK_AT.
                    if unsafe { send_entry(service.me, destination, &bytes[..written]) } {
                        service.sent += 1;
                    }
                }
            }
            Action::Arm { timer, at } => service.deadlines.arm(timer, at),
            Action::Cancel(timer) => service.deadlines.cancel(timer),
            // The demonstration has no program behind it to wake; the counters
            // stand in. Step 5 signals the holder's notification here.
            Action::Delivered(_) | Action::Acknowledged(_) => {}
            Action::Closed(ended) => {
                service.outcome = match ended {
                    state::Ended::Refused => outcome::REFUSED,
                    state::Ended::Unreachable => outcome::UNREACHABLE,
                    // The good ending, reached only through `TIME_WAIT`'s
                    // 2×MSL — a real minute of real time, so most boots end
                    // while the state is still `TIME_WAIT` and the outcome
                    // still `ECHOED`. Both are gated.
                    state::Ended::Orderly => outcome::ORDERLY,
                    state::Ended::Aborted => service.outcome,
                    state::Ended::Reset => outcome::REFUSED,
                };
            }
        }
    }
}

/// Drives one event into the machine and performs what it asks.
fn drive(service: &mut Service, event: Event<'_>) {
    let now = now_nanos(service.hertz);
    let (tcb, actions) = state::step(service.tcb, event, now);
    service.tcb = tcb;
    perform(service, &actions);
}

/// Arms the inbox for the nearest deadline, or disarms it.
fn arm_nearest(service: &Service) {
    match service.deadlines.nearest() {
        Some(at) => {
            let tsc = nanos_to_tsc(at, service.hertz);
            call(syscall::INVOKE, INBOX, method::ARM, [tsc, 0, 0, 0]);
        }
        None => {
            call(syscall::INVOKE, INBOX, method::DISARM, [0; 4]);
        }
    }
}

/// Fires every deadline that has passed.
fn fire_due(service: &mut Service) {
    loop {
        let now = now_nanos(service.hertz);
        let Some(timer) = service.deadlines.due(now) else {
            break;
        };
        drive(service, Event::Expired(timer));
    }
}

/// Takes everything from the forward ring and drives it into the machine.
fn drain_forward(service: &mut Service) {
    let Some(layout) = ring::Layout::for_region(RING_BYTES) else {
        return;
    };
    let mut entry = [0u8; MAX_ENTRY];
    // Bounded, as every ring drain here is.
    for _ in 0..16 {
        // SAFETY: the ring's header, in the region this program mapped.
        let head =
            unsafe { core::ptr::read_volatile((FWD_AT + ring::HEAD_OFFSET as u64) as *const u64) };
        let Some(cursor) = ring::Cursor::new(layout, head, service.tail) else {
            return;
        };
        let mut prefix = [0u8; ring::PREFIX];
        let Some(runs) = ring::length_to_read(layout, cursor) else {
            return;
        };
        // SAFETY: the ring is mapped and `prefix` is `PREFIX` writable bytes.
        unsafe { read_runs(FWD_AT, prefix.as_mut_ptr(), runs) };
        let length = u32::from_le_bytes(prefix) as usize;
        if !(8..=MAX_ENTRY).contains(&length) {
            // A length this program has stopped believing. Skip the prefix and
            // carry on rather than wedging on it for ever.
            service.refused += 1;
            service.tail = service.tail.wrapping_add(ring::PREFIX as u64);
            publish_tail(service.tail);
            continue;
        }
        // `None` is the producer mid-write, not an error.
        let Some(framed) = ring::frame_to_read(layout, cursor, length) else {
            return;
        };
        // SAFETY: as above; `entry` is `MAX_ENTRY` writable bytes and `length`
        // is bounded by it.
        unsafe { read_runs(FWD_AT, entry.as_mut_ptr(), framed.payload) };
        service.tail = framed.next;
        publish_tail(service.tail);
        service.taken += 1;

        let source = Ipv4Addr(u32::from_be_bytes([entry[0], entry[1], entry[2], entry[3]]));
        let destination = Ipv4Addr(u32::from_be_bytes([entry[4], entry[5], entry[6], entry[7]]));
        // Every refusal in `parse` is `bhaskix-net`'s, fuzzed as ordinary code,
        // which is the whole reason the segment parser lives there.
        let Ok(parsed) = Segment::parse(&entry[8..length], source, destination) else {
            service.refused += 1;
            continue;
        };
        // One connection today: the demonstration's. A segment for any other
        // four-tuple has nobody to belong to. Step 5 looks the tuple up in a
        // table here instead.
        let expected = service.tcb.connection;
        let matches = Address::V4(source) == expected.remote
            && Address::V4(destination) == expected.local
            && parsed.source == expected.remote_port
            && parsed.destination == expected.local_port;
        if !matches {
            service.refused += 1;
            continue;
        }
        // What the machine takes, it reports as a count; the bytes behind the
        // count are captured here — `rcv_nxt` before and after telling how
        // many, with the peer's `FIN`, which occupies a number and is not a
        // byte, subtracted back out. Byte `k` of the peer's stream is sequence
        // `irs + 1 + k`, mirroring the send side.
        let before = service.tcb.rcv_nxt;
        let fin_before = service.tcb.fin_received;
        let synchronised = service.tcb.state.can_receive();
        drive(service, Event::Arrived(parsed));
        // Only a synchronised connection's advance is data. A `SYN·ACK` moves
        // `rcv_nxt` from its initial zero to `irs + 1` — a wrap-sized jump that
        // read as four billion delivered bytes, whose wrapped offset then
        // summed back to exactly the buffer's length and reported a zeroed
        // buffer as a complete, corrupt echo. Outcome 8 with three segments
        // in was this arithmetic, not the peer.
        if !synchronised {
            continue;
        }
        let advanced = service.tcb.rcv_nxt.0.wrapping_sub(before.0) as usize;
        let fin_took = usize::from(service.tcb.fin_received && !fin_before);
        let delivered = advanced.saturating_sub(fin_took);
        if delivered > 0 {
            let at = before.0.wrapping_sub(service.tcb.irs.0.wrapping_add(1)) as usize;
            for (index, byte) in parsed.payload.iter().take(delivered).enumerate() {
                if let Some(slot) = service.echo.get_mut(at + index) {
                    *slot = *byte;
                }
            }
            service.echoed = service.echoed.max((at + delivered).min(service.echo.len()));
        }
    }
}

/// Tells the producer how far this program has read.
fn publish_tail(tail: u64) {
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    // SAFETY: the ring's header, which only this program writes.
    unsafe {
        core::ptr::write_volatile((FWD_AT + ring::TAIL_OFFSET as u64) as *mut u64, tail);
    }
}

/// Leaves the findings where the kernel granted memory for them.
fn report(state_bits: u64, outcome: u64, taken: u64, sent: u64, refused: u64, tcb_state: u64) {
    let words = [MARKER, state_bits, outcome, taken, sent, refused, tcb_state];
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

/// Bits in the report's state word.
mod state_bits {
    /// The rings and pages attached.
    pub const ATTACHED: u64 = 1 << 0;
    /// The 128-bit secret was drawn from the hardware.
    pub const KEYED: u64 = 1 << 1;
    /// The kernel published what interface this is.
    pub const CONFIGURED: u64 = 1 << 2;
    /// The serve loop was entered.
    pub const SERVING: u64 = 1 << 3;
}

/// The eleven states, as a number the report can carry.
fn state_number(tcb: &Tcb) -> u64 {
    match tcb.state {
        state::State::Closed => 0,
        state::State::Listen => 1,
        state::State::SynSent => 2,
        state::State::SynReceived => 3,
        state::State::Established => 4,
        state::State::FinWait1 => 5,
        state::State::FinWait2 => 6,
        state::State::CloseWait => 7,
        state::State::Closing => 8,
        state::State::LastAck => 9,
        state::State::TimeWait => 10,
    }
}

/// The entry point. `hertz` is the cycle counter's rate, handed over at entry
/// for the reason `bin/dhcp` gives: reading time is ambient, knowing the units
/// is not, and the rate cannot arrive through a CSpace.
#[unsafe(no_mangle)]
extern "C" fn tcpd_main(hertz: u64) -> ! {
    if !attach(FWD, FWD_AT, 1) || !attach(REPORT, REPORT_AT, 1) {
        exit()
    }
    let mut bits = state_bits::ATTACHED;
    let networked = attach(BACK, BACK_AT, 1) && attach(CONFIG, CONFIG_AT, 0);
    report(bits, outcome::PENDING, 0, 0, 0, 0);

    // **The refusal, before anything else.** A 128-bit secret from the
    // hardware, or nothing: `Key::draw` returns `None` if either half is
    // refused, and no path below turns `None` into a number. On a machine
    // without `RDRAND` this program reports why it will not serve and stops —
    // which is RFC 0021's policy running, not a fallback quietly seeding from
    // something guessable.
    let Some(key) = Key::draw(bhaskix_rand::u64) else {
        report(bits, outcome::NO_ENTROPY, 0, 0, 0, 0);
        exit()
    };
    bits |= state_bits::KEYED;
    report(bits, outcome::PENDING, 0, 0, 0, 0);

    if !networked {
        // No rings to a protocol service means no network, which is a state
        // rather than a failure: the machine boots, and this page says what
        // this program could not do.
        report(bits, outcome::NO_NETWORK, 0, 0, 0, 0);
        exit()
    }

    // What this interface is, written by the kernel once the driver has read
    // the address out of the device. Waited for by marker, bounded by a
    // deadline rather than a spin: this program can sleep now.
    let mut me = Ipv4Addr::UNSPECIFIED;
    for _ in 0..200u32 {
        // SAFETY: the configuration page, mapped read-only by this program.
        let (marker, address) = unsafe {
            (
                core::ptr::read_volatile(CONFIG_AT as *const u64),
                core::ptr::read_volatile((CONFIG_AT + 16) as *const u64),
            )
        };
        if marker == CONFIG_MARKER {
            me = Ipv4Addr(address as u32);
            break;
        }
        // Fifty milliseconds between looks, through the same deadline the
        // machine's own timers use. If arming fails there is no timer on this
        // machine and a yield is what is left.
        let wake = nanos_to_tsc(now_nanos(hertz).saturating_add(50_000_000), hertz);
        if call(syscall::INVOKE, INBOX, method::ARM, [wake, 0, 0, 0]).0 != status::OK
            || call(syscall::INVOKE, INBOX, method::WAIT, [0; 4]).0 != status::OK
        {
            call(syscall::YIELD, 0, 0, [0; 4]);
        }
    }
    if me == Ipv4Addr::UNSPECIFIED {
        report(bits, outcome::NO_NETWORK, 0, 0, 0, 0);
        exit()
    }
    bits |= state_bits::CONFIGURED;

    // The demonstration connection: this machine to the harness's echo peer.
    // The initial sequence number is RFC 6528's construction over the key
    // drawn above — the first sequence number this system has ever minted
    // that an off-path attacker cannot predict.
    let connection = FourTuple {
        local: Address::V4(me),
        local_port: Port(DEMO_LOCAL),
        remote: Address::V4(PEER),
        remote_port: Port(DEMO_PORT),
    };
    let mut service = Service {
        key,
        hertz,
        me,
        tcb: Tcb::new(connection),
        deadlines: Deadlines::new(),
        tail: 0,
        outcome: outcome::PENDING,
        taken: 0,
        sent: 0,
        refused: 0,
        demo: Demo::Opening,
        echo: [0u8; DEMO_PAYLOAD.len()],
        echoed: 0,
    };
    let iss = isn::initial_sequence(&service.key, connection, now_nanos(hertz));
    drive(
        &mut service,
        Event::Connect {
            iss,
            window: DEMO_WINDOW,
        },
    );
    arm_nearest(&service);

    // Bind the inbox to this thread, so `receive` wakes for a caller, a frame
    // or a deadline — whichever comes first — and says which.
    call(syscall::INVOKE, INBOX, method::BIND_SELF, [0; 4]);
    bits |= state_bits::SERVING;

    loop {
        // The demonstration's one-shot events, driven by what the machine has
        // reached rather than by a schedule.
        if service.tcb.state == state::State::Established && service.demo == Demo::Opening {
            service.outcome = outcome::ESTABLISHED;
            service.demo = Demo::Sent;
            drive(&mut service, Event::Wrote(DEMO_PAYLOAD.len() as u32));
            arm_nearest(&service);
        }
        if service.demo == Demo::Sent && service.echoed >= DEMO_PAYLOAD.len() {
            if &service.echo[..] == DEMO_PAYLOAD {
                // The whole point of the boot: sixteen bytes out through
                // three domains, sixteen back, unchanged. Close in order.
                service.outcome = outcome::ECHOED;
                service.demo = Demo::Closing;
                drive(&mut service, Event::Shutdown);
                arm_nearest(&service);
            } else {
                service.outcome = outcome::MANGLED;
                service.demo = Demo::Done;
            }
        }
        report(
            bits,
            service.outcome,
            service.taken,
            service.sent,
            service.refused,
            state_number(&service.tcb),
        );

        let (status_in, _badge, method_in, _args) = receive();
        if status_in == status::NOTIFIED {
            // A frame, a deadline, or both — the word does not say which
            // deadline, so both halves are checked. Cheap: one is a ring header
            // read and the other four comparisons.
            fire_due(&mut service);
            drain_forward(&mut service);
            arm_nearest(&service);
            continue;
        }
        if status_in != status::OK {
            continue;
        }
        // A caller. Connections for other programs are step 5; an honest
        // "not yet" is distinguishable from a missing service.
        let _ = method_in;
        reply(tcp::LATER, 0, 0);
    }
}

core::arch::global_asm!(
    r#"
.section .text._start,"ax",@progbits
.globl _start
_start:
    xor rbp, rbp
    and rsp, -16
    call tcpd_main
    ud2
"#
);
