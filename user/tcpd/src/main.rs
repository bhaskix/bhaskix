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

use bhaskix_abi::{method, rights, ring, status, syscall, tcp};
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

/// Where a caller's gifted send ring lands (RFC 0022): declared with
/// `EXPECT` before every receive while unfilled, consumed by the gift that
/// arrives with `CONNECT` leg 0.
const GIFT_SEND: u64 = 8;
/// The receive ring's slot, filled by leg 1.
const GIFT_RECV: u64 = 9;
/// The listener's ring slots, filled by `LISTEN` legs 0 and 1.
const GIFT_L_SEND: u64 = 10;
const GIFT_L_RECV: u64 = 11;
/// The wakes, RFC 0023: one notification per handover, gifted at leg 3,
/// signalled whenever the connection has news.
const GIFT_NOTIFY: u64 = 12;
const GIFT_L_NOTIFY: u64 = 13;

/// Where this program maps what it holds.
const FWD_AT: u64 = 0x2300_0000;
const REPORT_AT: u64 = 0x2310_0000;
const BACK_AT: u64 = 0x2320_0000;
const CONFIG_AT: u64 = 0x2330_0000;
/// Where a caller's gifted rings map. The stream rides them in step 4b; in
/// step 4a mapping them is the proof the handover happened.
const SENDR_AT: u64 = 0x2340_0000;
const RECVR_AT: u64 = 0x2350_0000;
/// And where the listener's pair maps, taken over by the connection a `SYN`
/// births.
const L_SENDR_AT: u64 = 0x2360_0000;
const L_RECVR_AT: u64 = 0x2370_0000;

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

/// Bytes in a caller's gifted stream ring. The stream's byte `k` lives at
/// offset `k % STREAM_RING_BYTES`; with a window no wider than the ring,
/// unacknowledged bytes are never overwritten by the wrap.
const STREAM_RING_BYTES: usize = 4 * 4096;

/// The largest payload one `Emit` is honoured for. The machine bounds emits
/// by the peer's window, not by this program's buffers; an emit wider than
/// this is refused and counted rather than truncated, because a truncated
/// stream is corruption with extra steps. The demonstration sends sixteen
/// bytes; this bound is for the machine's future, not its present.
const MAX_EMIT: usize = 1024;

/// The local port a connection uses. One connection, one port; a port
/// allocator arrives with the connection table. Above the well-known range,
/// and fixed so the report is deterministic.
const LOCAL_PORT: u16 = 49999;

/// The receive window a connection advertises: what a page holds. Narrower
/// than the client's ring on purpose — the ring bounds what can be stored,
/// the window what the peer may send, and the window must never exceed the
/// ring or the wrap overwrites bytes the client has not read.
const WINDOW: u16 = 4096;

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
    /// A caller's connection opened. The stream is the caller's story now —
    /// RFC 0022 step 4b moved the bytes into rings the caller owns — so for
    /// this service the steady state is exactly this.
    pub const ESTABLISHED: u64 = 3;
    /// The machine cannot be unpredictable, so nothing was attempted.
    pub const NO_ENTROPY: u64 = 4;
    /// There is no network to demonstrate against.
    pub const NO_NETWORK: u64 = 5;
    // 6 was ECHOED, retired by RFC 0022 step 4b: whether the payload came
    // back is the *caller's* finding now, asserted against rings it owns.
    // The number is left unassigned so old logs still read unambiguously.
    /// `TIME_WAIT` was entered **and left**: the full lifetime of a
    /// connection, first byte to freed control block, on real time.
    pub const ORDERLY: u64 = 7;
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

/// Live connections at once. Two: one a caller opens outbound, one a
/// listener accepts. A table refusing at its size is this project's posture;
/// a third caller is told `CONGESTED` rather than growing anything.
const MAX_CONNECTIONS: usize = 2;

/// The outbound connection's slot in the table, and the accepted one's.
const OUTBOUND: usize = 0;
const ACCEPTED: usize = 1;

/// One live connection: the machine, its timers, and the rings its stream
/// lives in — RFC 0022's gifts, mapped where the handover put them.
struct Connection {
    tcb: Tcb,
    deadlines: Deadlines,
    /// Where the caller's send ring is mapped in this program.
    sendr_at: u64,
    /// And its receive ring.
    recvr_at: u64,
    /// Bytes of the peer's stream written into the receive ring, cumulative.
    delivered: u64,
    /// The badge its connection capability carries.
    handle: u64,
    /// The CSpace slot of the caller's gifted wake, if it sent one (RFC
    /// 0023), and whether the last step produced news worth ringing it for.
    notify_slot: Option<u64>,
    wake_owed: bool,
}

/// A port with a caller waiting behind it: RFC 0020's `LISTEN`, existing
/// only once its rings crossed. The rings' addresses live here because the
/// connection a `SYN` births takes them; a listener with spent rings can
/// birth nothing more until the table's next step adds re-arming.
struct Listener {
    port: u16,
    /// The badge on the listener capability, bit 63 set.
    handle: u64,
    sendr_at: u64,
    recvr_at: u64,
    /// The gifted wake the accepted connection inherits (RFC 0023).
    notify_slot: Option<u64>,
}

/// Everything the serve loop carries.
struct Service {
    key: Key,
    hertz: u64,
    me: Ipv4Addr,
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
    connections: [Option<Connection>; MAX_CONNECTIONS],
    listener: Option<Listener>,
}

/// Performs what one `step` asked for, against one connection's rings.
///
/// `index` says which table slot the connection came out of, because one
/// duty is not the connection's own: the report's outcome word narrates the
/// outbound demonstration, and only slot `OUTBOUND` writes it.
fn perform(
    service: &mut Service,
    connection: &mut Connection,
    index: usize,
    actions: &state::Actions,
) {
    for action in actions.iter() {
        match action {
            Action::Emit(emit) => {
                // An `Emit` names a *range of the stream*, not bytes — the
                // design that keeps the machine pure — and this is where the
                // range becomes bytes. RFC 0022 step 4b: the send stream
                // lives in the ring the caller gifted, mapped at `SENDR_AT`;
                // byte `k` of the stream carries sequence `iss + 1 + k`, the
                // `+ 1` being the `SYN`'s own number, and sits at offset
                // `k % STREAM_RING_BYTES`. Retransmission is the same read:
                // the tail of the ring advances on `ACK`, not transmission,
                // so the bytes are still there.
                let length = usize::from(emit.length);
                if length > MAX_EMIT {
                    // Refused and counted rather than truncated: a truncated
                    // stream is corruption with extra steps. A zero-length
                    // emit — pure `ACK`, `SYN`, `FIN` — carries no stream
                    // bytes and rides regardless.
                    service.refused += 1;
                    continue;
                }
                let offset = emit
                    .sequence
                    .0
                    .wrapping_sub(connection.tcb.iss.0.wrapping_add(1))
                    as usize;
                let mut payload = [0u8; MAX_EMIT];
                for (at_index, slot) in payload.iter_mut().enumerate().take(length) {
                    let at = (offset + at_index) % STREAM_RING_BYTES;
                    // SAFETY: the caller's send ring, mapped readable at the
                    // address the handover recorded before this connection
                    // existed; `at` stays within it by the modulus.
                    *slot = unsafe {
                        core::ptr::read_volatile((connection.sendr_at + at as u64) as *const u8)
                    };
                }
                let built = emit.segment(connection.tcb.connection, &payload[..length]);
                let mut bytes = [0u8; segment::MAX_HEADER + MAX_EMIT];
                let Some(destination) = connection.tcb.connection.remote.v4() else {
                    continue;
                };
                if let Ok(written) = segment::write(&mut bytes, &built, service.me, destination) {
                    // SAFETY: the back ring is mapped writable at BACK_AT.
                    if unsafe { send_entry(service.me, destination, &bytes[..written]) } {
                        service.sent += 1;
                        if length > 0 {
                            stamp_once(7);
                        }
                    }
                }
            }
            Action::Arm { timer, at } => connection.deadlines.arm(timer, at),
            Action::Cancel(timer) => connection.deadlines.cancel(timer),
            // RFC 0023: news. The wake itself is rung once per step, after
            // every action is performed, because two deliveries in one step
            // are one piece of news and the notification coalesces anyway.
            Action::Delivered(_) | Action::Acknowledged(_) => {
                connection.wake_owed = true;
            }
            Action::Closed(ended) => {
                if index == OUTBOUND {
                    service.outcome = match ended {
                        state::Ended::Refused => outcome::REFUSED,
                        state::Ended::Unreachable => outcome::UNREACHABLE,
                        // The good ending, reached only through `TIME_WAIT`'s
                        // 2×MSL — a real minute of real time, so most boots
                        // end while the state is still `TIME_WAIT`.
                        state::Ended::Orderly => outcome::ORDERLY,
                        state::Ended::Aborted => service.outcome,
                        state::Ended::Reset => outcome::REFUSED,
                    };
                }
            }
        }
    }
}

/// Drives one event into the table's `index`-th machine.
///
/// Take-out, step, put-back: the connection leaves the table for the length
/// of the step so `perform` can hold it and the service's counters at once.
fn drive_at(service: &mut Service, index: usize, event: Event<'_>) {
    let Some(mut connection) = service.connections[index].take() else {
        return;
    };
    let before = connection.tcb.state;
    let now = now_nanos(service.hertz);
    let (tcb, actions) = state::step(connection.tcb, event, now);
    connection.tcb = tcb;
    perform(service, &mut connection, index, &actions);
    // RFC 0023: ring the caller's wake if this step left it news — bytes
    // delivered, send space freed, or the machine in a new state. One
    // signal per step: the notification coalesces, and a holder that was
    // not waiting finds the word set when it next looks.
    if connection.tcb.state != before {
        connection.wake_owed = true;
    }
    if connection.wake_owed
        && let Some(slot) = connection.notify_slot
    {
        let _ = call(syscall::INVOKE, slot, method::SIGNAL, [0; 4]);
        connection.wake_owed = false;
    }
    service.connections[index] = Some(connection);
}

/// Arms the inbox for the nearest deadline of any connection, or disarms it.
fn arm_nearest(service: &Service) {
    let nearest = service
        .connections
        .iter()
        .flatten()
        .filter_map(|connection| connection.deadlines.nearest())
        .min();
    match nearest {
        Some(at) => {
            let tsc = nanos_to_tsc(at, service.hertz);
            call(syscall::INVOKE, INBOX, method::ARM, [tsc, 0, 0, 0]);
        }
        None => {
            call(syscall::INVOKE, INBOX, method::DISARM, [0; 4]);
        }
    }
}

/// Fires every deadline that has passed, in every connection.
fn fire_due(service: &mut Service) {
    for index in 0..MAX_CONNECTIONS {
        loop {
            let now = now_nanos(service.hertz);
            let Some(timer) = service.connections[index]
                .as_mut()
                .and_then(|connection| connection.deadlines.due(now))
            else {
                break;
            };
            drive_at(service, index, Event::Expired(timer));
        }
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
        // The table lookup RFC 0020 promised where one connection used to
        // be assumed: a segment belongs to the connection whose four-tuple
        // it names, or — if it is a `SYN` to a port somebody is listening
        // on — it births the accepted connection, or it has nobody.
        let mut index = None;
        for (candidate, connection) in service.connections.iter().enumerate() {
            if let Some(connection) = connection {
                let expected = connection.tcb.connection;
                if Address::V4(source) == expected.remote
                    && Address::V4(destination) == expected.local
                    && parsed.source == expected.remote_port
                    && parsed.destination == expected.local_port
                {
                    index = Some(candidate);
                    break;
                }
            }
        }
        let index = match index {
            Some(index) => index,
            None => {
                let born = accept_syn(service, &parsed, source, destination);
                let Some(index) = born else {
                    service.refused += 1;
                    continue;
                };
                index
            }
        };
        // What the machine takes, it reports as a count; the bytes behind the
        // count are captured here — `rcv_nxt` before and after telling how
        // many, with the peer's `FIN`, which occupies a number and is not a
        // byte, subtracted back out. Byte `k` of the peer's stream is sequence
        // `irs + 1 + k`, mirroring the send side.
        let Some(connection) = service.connections[index].as_ref() else {
            continue;
        };
        let before = connection.tcb.rcv_nxt;
        let fin_before = connection.tcb.fin_received;
        let synchronised = connection.tcb.state.can_receive();
        drive_at(service, index, Event::Arrived(parsed));
        let Some(connection) = service.connections[index].as_ref() else {
            continue;
        };
        // Only a synchronised connection's advance is data. A `SYN·ACK` moves
        // `rcv_nxt` from its initial zero to `irs + 1` — a wrap-sized jump that
        // read as four billion delivered bytes, whose wrapped offset then
        // summed back to exactly the buffer's length and reported a zeroed
        // buffer as a complete, corrupt echo. Outcome 8 with three segments
        // in was this arithmetic, not the peer.
        if !synchronised {
            continue;
        }
        let advanced = connection.tcb.rcv_nxt.0.wrapping_sub(before.0) as usize;
        let fin_took = usize::from(connection.tcb.fin_received && !fin_before);
        let delivered = advanced.saturating_sub(fin_took);
        if delivered > 0 {
            // Byte `k` of the peer's stream is sequence `irs + 1 + k`,
            // mirroring the send side, and lands at `k % STREAM_RING_BYTES`
            // of the ring the caller gifted for exactly this. The window
            // advertised is narrower than the ring, so the wrap cannot
            // overwrite bytes the caller has not read.
            let at = before.0.wrapping_sub(connection.tcb.irs.0.wrapping_add(1)) as usize;
            let recvr_at = connection.recvr_at;
            for (byte_index, byte) in parsed.payload.iter().take(delivered).enumerate() {
                let slot = (at + byte_index) % STREAM_RING_BYTES;
                // SAFETY: the caller's receive ring, mapped writable at the
                // address the handover recorded; the modulus keeps the
                // offset within it.
                unsafe {
                    core::ptr::write_volatile((recvr_at + slot as u64) as *mut u8, *byte);
                }
            }
            if let Some(connection) = service.connections[index].as_mut() {
                connection.delivered += delivered as u64;
            }
            stamp_once(8);
        }
    }
}

/// Births the accepted connection, if this segment is the `SYN` a listener
/// has been waiting for. Returns its table slot.
///
/// RFC 0020's passive open, driven exactly as the state machine's host tests
/// drive it: a fresh machine, `Event::Listen`, then the `SYN` — two steps,
/// so the initial sequence number can be minted for the *full* four-tuple,
/// which RFC 6528 requires and which does not exist until the `SYN` says who
/// is calling.
fn accept_syn(
    service: &mut Service,
    parsed: &Segment<'_>,
    source: Ipv4Addr,
    destination: Ipv4Addr,
) -> Option<usize> {
    use bhaskix_net::tcp::segment::Flags;

    let listener = service.listener.as_ref()?;
    if !parsed.flags.contains(Flags::SYN)
        || parsed.acknowledgement.is_some()
        || parsed.destination != Port(listener.port)
        || Address::V4(destination) != Address::V4(service.me)
    {
        return None;
    }
    if service.connections[ACCEPTED].is_some() {
        // The one accepted slot is taken. `CONGESTED` is the table's word
        // for this, and the refusal is silent at this layer -- the peer
        // retries its `SYN`, and if the slot has freed by then, it lands.
        return None;
    }
    let connection = FourTuple {
        local: Address::V4(service.me),
        local_port: Port(listener.port),
        remote: Address::V4(source),
        remote_port: parsed.source,
    };
    let iss = isn::initial_sequence(&service.key, connection, now_nanos(service.hertz));
    service.connections[ACCEPTED] = Some(Connection {
        tcb: Tcb::new(connection),
        deadlines: Deadlines::new(),
        sendr_at: listener.sendr_at,
        recvr_at: listener.recvr_at,
        delivered: 0,
        handle: tcp::handle(ACCEPTED as u32, 1, false),
        notify_slot: listener.notify_slot,
        wake_owed: false,
    });
    drive_at(
        service,
        ACCEPTED,
        Event::Listen {
            iss,
            window: WINDOW,
        },
    );
    Some(ACCEPTED)
}

/// Tells the producer how far this program has read.
fn publish_tail(tail: u64) {
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    // SAFETY: the ring's header, which only this program writes.
    unsafe {
        core::ptr::write_volatile((FWD_AT + ring::TAIL_OFFSET as u64) as *mut u64, tail);
    }
}

/// One ring handover, RFC 0022 step 4: two gifts and then a capability
/// back. `CONNECT` runs one toward the outbound connection; `LISTEN` runs
/// another toward the listener. A multi-caller service keys these by the
/// badge on the call; the fields are what that table's rows will be.
struct Handover {
    /// Which CSpace slots the gifts land in, declared in this order.
    slots: (u64, u64),
    /// Where the rings map once landed.
    at: (u64, u64),
    /// Where a gifted wake lands (RFC 0023 leg 3), if the caller sends one.
    notify_slot: u64,
    /// Whether leg 2 mints a listener capability (badge bit 63) rather than
    /// a connection's.
    listener: bool,
    send_mapped: bool,
    recv_mapped: bool,
    /// Whether leg 3's notification arrived.
    notified: bool,
    /// The badge the capability was minted under, once handed.
    handle: u64,
}

impl Handover {
    const fn new(slots: (u64, u64), at: (u64, u64), notify_slot: u64, listener: bool) -> Self {
        Self {
            slots,
            at,
            notify_slot,
            listener,
            send_mapped: false,
            recv_mapped: false,
            notified: false,
            handle: 0,
        }
    }
}

/// Declares where the next gifted ring may land, if one is still owed.
///
/// Before *every* receive, because the declaration is one-shot: the gift
/// that lands consumes it, and a service that forgets to renew is deaf to
/// the next caller. Declaring the same slot twice replaces, which makes
/// this safe to call unconditionally.
fn declare_gift_slot(connect: &Handover, listen: &Handover) {
    // Rings before wakes, both handovers' rings before either's wake, and
    // the order is load-bearing: one declaration exists per thread, so a
    // slot declared for a gift the caller never sends blocks every gift
    // behind it. A polling caller never sends leg 3 — with a wake slot
    // declared mid-list, its `LISTEN` rings would refuse for ever. This is
    // RFC 0022 open question 4's collision wearing new clothes, and its
    // second recorded witness.
    let owed = [
        (!connect.send_mapped).then_some(connect.slots.0),
        (!connect.recv_mapped).then_some(connect.slots.1),
        (!listen.send_mapped).then_some(listen.slots.0),
        (!listen.recv_mapped).then_some(listen.slots.1),
        (!connect.notified).then_some(connect.notify_slot),
        (!listen.notified).then_some(listen.notify_slot),
    ];
    let Some(slot) = owed.into_iter().flatten().next() else {
        // Nothing owed: leave no declaration, so an uninvited gift refuses
        // its call rather than landing somewhere this service will not look.
        return;
    };
    let _ = call(syscall::INVOKE, ENDPOINT, method::EXPECT, [slot, 0, 0, 0]);
}

/// Answers one `CONNECT` leg. Returns what to reply: `(outcome, detail)`.
///
/// Legs 0 and 1 each carry one ring, because RFC 0022 moves one capability
/// per call — its alternatives table records why. Leg 2 is the other
/// direction: the connection capability rides the reply, RFC 0016 unchanged.
fn connect_leg(handover: &mut Handover, leg: u64) -> (u64, u64) {
    match leg {
        0 | 1 => {
            let (slot, at) = if leg == 0 {
                (handover.slots.0, handover.at.0)
            } else {
                (handover.slots.1, handover.at.1)
            };
            let mapped = if leg == 0 {
                &mut handover.send_mapped
            } else {
                &mut handover.recv_mapped
            };
            if *mapped {
                // A retried leg is answered, not punished: the ring is here.
                return (tcp::OK, 0);
            }
            // The map is the probe. The kernel refuses a gifted call when no
            // slot is declared, so a leg that arrives *delivered* but with
            // this slot empty is a caller that called without staging —
            // `ATTACH` then fails with `NO_SUCH_CAPABILITY`, told apart from
            // a ring that arrived and would not map.
            match call(syscall::INVOKE, slot, method::ATTACH, [at, 1, 0, 0]).0 {
                s if s == status::OK => {
                    *mapped = true;
                    (tcp::OK, 0)
                }
                s if s == status::NO_SUCH_CAPABILITY => (tcp::BARE, leg),
                other => (tcp::BARE, 0x100 | other << 4 | leg),
            }
        }
        3 => {
            // RFC 0023: the wake. Probed by refusal shape, as every gift
            // is — `PEEK` answers on a notification and on nothing else, so
            // an empty slot and a wrong-kind gift are both told apart from
            // the wake this leg promises.
            if handover.notified {
                return (tcp::OK, 0);
            }
            match call(syscall::INVOKE, handover.notify_slot, method::PEEK, [0; 4]).0 {
                s if s == status::OK => {
                    handover.notified = true;
                    (tcp::OK, 0)
                }
                s if s == status::NO_SUCH_CAPABILITY => (tcp::BARE, 3),
                other => (tcp::BARE, 0x30 | other),
            }
        }
        2 => {
            if !(handover.send_mapped && handover.recv_mapped) {
                return (tcp::BARE, 2);
            }
            if handover.handle == 0 {
                handover.handle = tcp::handle(0, 1, handover.listener);
            }
            // The reply direction: derived from this service's own endpoint
            // capability, badged with the connection's identity, landing
            // where the caller's `EXPECT` said. Where it lands is not this
            // service's to choose.
            let handed = call(
                syscall::INVOKE,
                ENDPOINT,
                method::HAND,
                [ENDPOINT, rights::READ | rights::WRITE, handover.handle, 0],
            );
            if handed.0 != status::OK {
                return (tcp::BARE, 0x20 | handed.0);
            }
            (tcp::OK, handover.handle)
        }
        _ => (tcp::BARE, 3),
    }
}

/// Answers one `CONNECT` leg on a machine that has a network.
///
/// Legs 0 and 1 are [`connect_leg`] unchanged. Leg 2 is where step 4b
/// diverges from 4a: with both rings mapped, asking for the connection
/// capability now also *opens the connection* — the tuple comes from the
/// leg's own arguments, the initial sequence number from RFC 6528's
/// construction over the secret drawn at start, and the `SYN` goes to the
/// wire before the reply goes to the caller. The caller polls the returned
/// capability for establishment; this thread must not block on a handshake
/// while other work arrives.
fn connect_leg_serving(
    handover: &mut Handover,
    service: &mut Service,
    args: [u64; 4],
) -> (u64, u64) {
    if args[2] != 2 {
        let answer = connect_leg(handover, args[2]);
        // A wake that lands after leg 2 still reaches the live connection:
        // the handover is where gifts arrive, the table is where they act.
        if args[2] == 3
            && handover.notified
            && let Some(connection) = service.connections[OUTBOUND].as_mut()
        {
            connection.notify_slot = Some(handover.notify_slot);
        }
        return answer;
    }
    if !(handover.send_mapped && handover.recv_mapped) {
        return (tcp::BARE, 2);
    }
    if service.connections[OUTBOUND].is_none() {
        let connection = FourTuple {
            local: Address::V4(service.me),
            local_port: Port(LOCAL_PORT),
            remote: Address::V4(Ipv4Addr(args[0] as u32)),
            remote_port: Port(args[1] as u16),
        };
        let iss = isn::initial_sequence(&service.key, connection, now_nanos(service.hertz));
        service.connections[OUTBOUND] = Some(Connection {
            tcb: Tcb::new(connection),
            deadlines: Deadlines::new(),
            sendr_at: handover.at.0,
            recvr_at: handover.at.1,
            delivered: 0,
            handle: tcp::handle(OUTBOUND as u32, 1, false),
            notify_slot: handover.notified.then_some(handover.notify_slot),
            wake_owed: false,
        });
        drive_at(
            service,
            OUTBOUND,
            Event::Connect {
                iss,
                window: WINDOW,
            },
        );
        arm_nearest(service);
    }
    if handover.handle == 0 {
        handover.handle = tcp::handle(OUTBOUND as u32, 1, false);
    }
    let handed = call(
        syscall::INVOKE,
        ENDPOINT,
        method::HAND,
        [ENDPOINT, rights::READ | rights::WRITE, handover.handle, 0],
    );
    if handed.0 != status::OK {
        return (tcp::BARE, 0x20 | handed.0);
    }
    (tcp::OK, handover.handle)
}

/// Answers one `LISTEN` leg on a machine that has a network.
///
/// The same three-leg shape as `CONNECT`, because it is the same handover:
/// two rings across, a capability back. Leg 2 (`args[0]` = the port)
/// registers the listener — from then on a `SYN` to that port births the
/// accepted connection out of these rings — and hands back a capability
/// whose badge carries bit 63, which is what makes a listener a different
/// capability rather than a differently-documented one.
fn listen_leg_serving(
    handover: &mut Handover,
    service: &mut Service,
    args: [u64; 4],
) -> (u64, u64) {
    if args[2] != 2 {
        let answer = connect_leg(handover, args[2]);
        if args[2] == 3
            && handover.notified
            && let Some(listener) = service.listener.as_mut()
        {
            listener.notify_slot = Some(handover.notify_slot);
        }
        return answer;
    }
    if !(handover.send_mapped && handover.recv_mapped) {
        return (tcp::BARE, 2);
    }
    if service.listener.is_none() {
        service.listener = Some(Listener {
            port: args[0] as u16,
            handle: tcp::handle(0, 1, true),
            sendr_at: handover.at.0,
            recvr_at: handover.at.1,
            notify_slot: handover.notified.then_some(handover.notify_slot),
        });
    }
    if handover.handle == 0 {
        handover.handle = tcp::handle(0, 1, true);
    }
    let handed = call(
        syscall::INVOKE,
        ENDPOINT,
        method::HAND,
        [ENDPOINT, rights::READ | rights::WRITE, handover.handle, 0],
    );
    if handed.0 != status::OK {
        return (tcp::BARE, 0x20 | handed.0);
    }
    (tcp::OK, handover.handle)
}

/// Serves ring handovers and nothing else, on a machine with no network.
///
/// The exchange RFC 0022 step 4 exists for needs no wire: rings cross, the
/// connection capability comes back, and what that connection cannot do
/// without a network is its own report to make when asked. Exiting instead —
/// which this program did — left the endpoint dead and every caller queued
/// against it for ever.
fn serve_handover_only() -> ! {
    let mut connect_handover = Handover::new(
        (GIFT_SEND, GIFT_RECV),
        (SENDR_AT, RECVR_AT),
        GIFT_NOTIFY,
        false,
    );
    let mut listen_handover = Handover::new(
        (GIFT_L_SEND, GIFT_L_RECV),
        (L_SENDR_AT, L_RECVR_AT),
        GIFT_L_NOTIFY,
        true,
    );
    loop {
        declare_gift_slot(&connect_handover, &listen_handover);
        let (status_in, badge, method_in, args) = receive();
        if status_in != status::OK {
            continue;
        }
        let minted =
            badge != 0 && (badge == connect_handover.handle || badge == listen_handover.handle);
        if minted {
            // A stream method on a capability this machine minted but cannot
            // serve: without a wire the peer is unreachable, and saying so
            // is what lets the caller end with the truth rather than a
            // timeout.
            reply(tcp::UNREACHABLE, 0, 0);
        } else if method_in == tcp::CONNECT {
            let (outcome_word, detail) = connect_leg(&mut connect_handover, args[2]);
            reply(outcome_word, detail, 0);
        } else if method_in == tcp::LISTEN {
            let (outcome_word, detail) = connect_leg(&mut listen_handover, args[2]);
            reply(outcome_word, detail, 0);
        } else {
            reply(tcp::LATER, 0, 0);
        }
    }
}

/// Stamps the cycle counter into report word `index`, first time only.
///
/// The pipeline attribution instrument: the first payload emit and the first
/// payload delivery each leave one timestamp, and the kernel lines them up
/// with the client's and the protocol service's after boot. First-only,
/// because a "last" would be overwritten by whatever traffic came after the
/// exchange being attributed.
fn stamp_once(index: u64) {
    // SAFETY: this program's own report page, mapped writable at start; the
    // words above 6 belong to this instrument alone.
    unsafe {
        let at = (REPORT_AT + index * 8) as *mut u64;
        if core::ptr::read_volatile(at) == 0 {
            core::ptr::write_volatile(at, rdtsc());
        }
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
        // this program could not do. What it *can* still do is accept rings
        // and mint connections — the handover needs no wire, and exiting
        // here would leave the endpoint dead with every caller queued
        // against it for ever.
        report(bits, outcome::NO_NETWORK, 0, 0, 0, 0);
        serve_handover_only()
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
        serve_handover_only()
    }
    bits |= state_bits::CONFIGURED;

    // No connection yet, and that is RFC 0022 step 4b: connections are
    // *opened by callers* — outbound when `CONNECT` legs gift the rings,
    // inbound when a `SYN` reaches a port a `LISTEN` armed. The table
    // starts empty.
    let mut service = Service {
        key,
        hertz,
        me,
        tail: 0,
        outcome: outcome::PENDING,
        taken: 0,
        sent: 0,
        refused: 0,
        connections: [None, None],
        listener: None,
    };

    // Bind the inbox to this thread, so `receive` wakes for a caller, a frame
    // or a deadline — whichever comes first — and says which.
    call(syscall::INVOKE, INBOX, method::BIND_SELF, [0; 4]);
    bits |= state_bits::SERVING;

    let mut connect_handover = Handover::new(
        (GIFT_SEND, GIFT_RECV),
        (SENDR_AT, RECVR_AT),
        GIFT_NOTIFY,
        false,
    );
    let mut listen_handover = Handover::new(
        (GIFT_L_SEND, GIFT_L_RECV),
        (L_SENDR_AT, L_RECVR_AT),
        GIFT_L_NOTIFY,
        true,
    );

    loop {
        if service.outcome == outcome::PENDING
            && service.connections[OUTBOUND]
                .as_ref()
                .is_some_and(|connection| connection.tcb.state == state::State::Established)
        {
            service.outcome = outcome::ESTABLISHED;
        }
        report(
            bits,
            service.outcome,
            service.taken,
            service.sent,
            service.refused,
            service.connections[OUTBOUND]
                .as_ref()
                .map_or(0, |connection| state_number(&connection.tcb)),
        );

        declare_gift_slot(&connect_handover, &listen_handover);
        let (status_in, badge, method_in, args) = receive();
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
        // A caller, told apart by badge: the service capability carries the
        // caller's badge and answers `CONNECT` and `LISTEN`; a connection
        // capability carries the handle this service minted and answers the
        // stream; a listener capability carries bit 63 and answers `ACCEPT`.
        let connection_index = service.connections.iter().position(|connection| {
            connection
                .as_ref()
                .is_some_and(|connection| connection.handle != 0 && connection.handle == badge)
        });
        if let Some(index) = connection_index {
            match method_in {
                tcp::SEND => {
                    // "I have written `args[0]` more bytes into the send
                    // ring." No payload in the message — the ring is where
                    // the bytes are, and the `Emit`s this drives read them
                    // from it.
                    drive_at(&mut service, index, Event::Wrote(args[0] as u32));
                    arm_nearest(&service);
                    reply(tcp::OK, 0, 0);
                }
                tcp::RECV => {
                    // "I have consumed `args[0]` bytes; how far has the
                    // peer's stream reached?" The consumption is RFC 0020's
                    // flow-control design running: the machine's receive
                    // window *is* the free space in the caller's ring — it
                    // shrinks as bytes are delivered and reopens only when
                    // the caller says it has read them. Until this drove
                    // `Event::Read`, a bulk echo deadlocked at one window:
                    // the peer stopped sending into a window that never
                    // reopened, so the echo stalled, so the caller's own
                    // sends stalled behind the peer's full buffers.
                    if args[0] > 0 {
                        drive_at(&mut service, index, Event::Read(args[0] as u32));
                        arm_nearest(&service);
                    }
                    let packed = service.connections[index].as_ref().map_or(0, |connection| {
                        state_number(&connection.tcb) << 32 | connection.delivered
                    });
                    reply(tcp::OK, packed, 0);
                }
                tcp::SHUTDOWN => {
                    drive_at(&mut service, index, Event::Shutdown);
                    arm_nearest(&service);
                    reply(tcp::OK, 0, 0);
                }
                _ => reply(tcp::LATER, 0, 0),
            }
        } else if service
            .listener
            .as_ref()
            .is_some_and(|listener| listener.handle == badge)
        {
            if method_in == tcp::ACCEPT {
                // Poll-shaped for the same reason `CONNECT` is: one reply
                // obligation per thread. The accepted connection's
                // capability rides the reply that says yes, into the slot
                // the caller declared.
                let established = service.connections[ACCEPTED]
                    .as_ref()
                    .is_some_and(|connection| connection.tcb.state == state::State::Established);
                if established {
                    let handle = tcp::handle(ACCEPTED as u32, 1, false);
                    let handed = call(
                        syscall::INVOKE,
                        ENDPOINT,
                        method::HAND,
                        [ENDPOINT, rights::READ | rights::WRITE, handle, 0],
                    );
                    if handed.0 == status::OK {
                        reply(tcp::OK, handle, 0);
                    } else {
                        reply(tcp::BARE, 0x20 | handed.0, 0);
                    }
                } else {
                    reply(tcp::LATER, 0, 0);
                }
            } else {
                reply(tcp::LATER, 0, 0);
            }
        } else if method_in == tcp::CONNECT {
            let (outcome_word, detail) =
                connect_leg_serving(&mut connect_handover, &mut service, args);
            reply(outcome_word, detail, 0);
        } else if method_in == tcp::LISTEN {
            let (outcome_word, detail) =
                listen_leg_serving(&mut listen_handover, &mut service, args);
            reply(outcome_word, detail, 0);
        } else {
            reply(tcp::LATER, 0, 0);
        }
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
