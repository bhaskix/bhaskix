// SPDX-License-Identifier: Apache-2.0
//
//! The TCP demonstration client — the first program to open a connection the
//! way every program will.
//!
//! RFC 0020 says a connection's stream lives in the *program's* pages: two
//! `Memory` objects, supplied at `CONNECT`, mapped by the service. RFC 0022
//! is the mechanism that makes the sentence sayable — a capability crosses in
//! a call — and this program is the sentence said. It holds two rings its own
//! domain owns, hands one across each of two `CONNECT` calls, and receives
//! the connection capability in the reply of a third, landing in the slot it
//! declared with `EXPECT`. Both directions of RFC 0016's mechanism in one
//! exchange, from ring 3, with nothing wired by the kernel but the
//! capabilities this program starts with.
//!
//! Step 4a carries the *capabilities*; the bytes still ride the service's
//! demonstration connection. Step 4b moves the stream onto these rings and
//! retires that demonstration. The split is why this program asserts that the
//! rings were accepted and the connection capability landed — not yet that
//! data flowed through them.
//!
//! What lands in the report page is read by the kernel after boot and gated
//! in `tests/qemu/boot-test.sh`, like every service report.

#![no_std]
#![no_main]

use bhaskix_abi::{method, rights, status, syscall, tcp};

/// The capability to the TCP service's endpoint, badged as this client.
const SERVICE: u64 = 0;
/// The report page, written for the kernel to read.
const REPORT: u64 = 1;
/// The send ring: a `Memory` object this domain owns, gifted at leg 0.
const SEND_RING: u64 = 2;
/// The receive ring: gifted at leg 1.
const RECV_RING: u64 = 3;
/// Where the connection capability may land, declared with `EXPECT`.
const CONNECTION: u64 = 4;
/// The listener's rings: two more `Memory` objects this domain owns, gifted
/// across `LISTEN` the way the first pair crossed `CONNECT`.
const L_SEND_RING: u64 = 5;
const L_RECV_RING: u64 = 6;
/// Where the listener capability lands, and where the accepted connection's
/// does.
const LISTENER: u64 = 7;
const INBOUND: u64 = 8;
/// The wakes (RFC 0023): one notification per handover, this domain's own,
/// gifted so the service can ring them and waited on so this program stops
/// spinning.
const WAKE: u64 = 9;
const L_WAKE: u64 = 10;

/// Where the report page maps in this program's space.
const REPORT_AT: u64 = 0x2300_0000;
/// Where this program maps its own rings. It owns them; mapping is not a
/// grant, and the same pages are mapped by the service once gifted — that
/// double mapping *is* the shared stream.
const SENDR_AT: u64 = 0x2400_0000;
const RECVR_AT: u64 = 0x2410_0000;
const L_SENDR_AT: u64 = 0x2420_0000;
const L_RECVR_AT: u64 = 0x2430_0000;

/// The port this program listens on, and the harness forwards to. Seven is
/// `echo` by tradition, and this program is exactly that for one caller.
const LISTEN_PORT: u64 = 7;
/// How many bytes the host-side driver sends, and must get back.
const INBOUND_LEN: usize = 16;

/// What the demonstration sends, and must receive back unchanged. Sixteen
/// bytes, one segment: SYN, SYN·ACK, ACK, data, echo, FIN, FIN — every arrow
/// of the diagram every TCP text draws, and now the data rides rings this
/// program owns.
const PAYLOAD: &[u8] = b"bhaskix-tcp-0001";

/// The machine-state numbers the service packs into `RECV` replies.
const STATE_ESTABLISHED: u64 = 4;

/// First eight bytes of the report: "TCPC_RPT" says the mapping worked.
const MARKER: u64 = 0x5450_525f_4350_4354;

/// The echo peer the demonstration talks to, and its port. The same peer the
/// service's own demonstration uses, because `tests/qemu/devices.sh` wires
/// exactly one and the point of a deterministic peer is that everything
/// tests against it.
const PEER: u32 = u32::from_be_bytes([10, 0, 2, 100]);
const PEER_PORT: u64 = 9;

/// How this run ended, in the report's outcome word.
mod outcome {
    /// Started; nothing has happened yet.
    pub const STARTING: u64 = 0;
    /// Both rings were handed across `CONNECT` and accepted.
    pub const RINGS_ACCEPTED: u64 = 1;
    /// The connection capability landed where `EXPECT` said. Terminal
    /// success for step 4a.
    pub const CONNECTED: u64 = 2;
    /// A handover leg was refused with a status that will not change.
    pub const REFUSED: u64 = 3;
    /// The service kept answering `LATER` until patience ran out.
    pub const STUCK: u64 = 4;
    /// The reply said the rings arrived, but the declared slot is empty —
    /// the reply-carried half of the exchange failed.
    pub const UNLANDED: u64 = 5;
    /// The payload went out through the send ring and came back through the
    /// receive ring byte-for-byte. Terminal success: RFC 0020's echo, in
    /// RFC 0022's rings, asserted by the program that owns them.
    pub const ECHOED: u64 = 6;
    /// Bytes came back, and they were not the bytes sent.
    pub const MANGLED: u64 = 7;
    /// The connection capability works but the machine has no network: the
    /// service answered `UNREACHABLE` when asked to stream. Terminal, and
    /// the truthful ending on a machine with no wire.
    pub const DARK: u64 = 8;
    /// The whole of RFC 0020 step 5: outbound echoed through owned rings,
    /// then a listener armed, a host-initiated connection accepted, its
    /// bytes read out of this program's ring and sent back — and the peer's
    /// close arrived, which only happens after the reply reached it.
    pub const SERVED: u64 = 9;
    /// Listened, and nobody called. A state rather than a failure: only the
    /// boot test's harness runs a host-side driver, and every other boot of
    /// this machine — the shell test's, a hand-started one — has a listener
    /// with an honest nothing to accept.
    pub const NOBODY: u64 = 10;
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // SAFETY: an undefined instruction, deliberately. Stopping where the
    // kernel can see it beats reporting a success that did not happen.
    unsafe { core::arch::asm!("ud2", options(noreturn)) }
}

/// Issues one system call, and returns `(status, value, second)` — the
/// status, the reply's first word, and its second, which the handover
/// protocol uses for detail.
fn call(kind: u64, capability: u64, method: u64, args: [u64; 4]) -> (u64, u64, u64) {
    let status: u64;
    let mut value = args[0];
    let mut second = args[1];
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
            inlateout("r10") second,
            inlateout("r8") args[2] => _,
            inlateout("r9") args[3] => _,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    (status, value, second)
}

/// Ends this program. Never returns.
fn exit() -> ! {
    call(syscall::EXIT, 0, 0, [0; 4]);
    #[allow(clippy::empty_loop)]
    loop {}
}

/// Writes one word of the report page.
fn report_word(index: usize, value: u64) {
    // SAFETY: the report page is this program's slot 1, mapped read-write at
    // `REPORT_AT` before anything is reported; the index stays within it.
    unsafe {
        core::ptr::write_volatile((REPORT_AT + (index as u64) * 8) as *mut u64, value);
    }
}

/// Publishes progress: which step, and how it ended so far.
fn report(step: u64, outcome: u64, detail: u64) {
    report_word(1, step);
    report_word(2, outcome);
    report_word(3, detail);
}

/// One `CONNECT` leg, with a staged gift if `gift_slot` names one.
///
/// Staging and calling are two invocations by design — RFC 0022's `HAND`
/// attaches one capability to the *next* call on that endpoint, so the pair
/// reads exactly like the sentence it implements. Retried while the service
/// answers `SLOT_UNAVAILABLE`, because the service declares where a gift may
/// land just before it listens, and this program may call first.
fn leg(
    verb: u64,
    a0: u64,
    a1: u64,
    gift_slot: Option<(u64, u64)>,
    leg_number: u64,
) -> (u64, u64, u64) {
    for _ in 0..50_000 {
        if let Some((slot, badge)) = gift_slot {
            // The badge travels with the gift, and for the wakes it must:
            // their capabilities are badged, badges are one-way, and a
            // signal ORs the badge into the word — zero would OR nothing
            // and ring nobody.
            let (staged, _, _) = call(
                syscall::INVOKE,
                SERVICE,
                method::HAND,
                [slot, rights::READ | rights::WRITE, badge, 0],
            );
            if staged != status::OK {
                return (0xFFFF, staged, 0);
            }
        }
        let (called, value, second) = call(syscall::CALL, SERVICE, verb, [a0, a1, leg_number, 0]);
        // The service has not declared yet (its `EXPECT` races this call), or
        // has not started serving. Both answer with a status that a later
        // try can change, so yield and try again.
        if called == status::SLOT_UNAVAILABLE || value == tcp::LATER {
            let _ = call(syscall::YIELD, 0, 0, [0; 4]);
            continue;
        }
        return (called, value, second);
    }
    (STUCK_STATUS, 0, 0)
}

/// The status `leg` invents for "patience ran out" — outside the kernel's
/// status space, so it cannot be mistaken for an answer.
const STUCK_STATUS: u64 = 0xFFFE;

/// Reads the cycle counter. Unprivileged: `CR4.TSD` is clear on this
/// machine, and the kernel converts ticks to time — this program only ever
/// subtracts them.
fn rdtsc() -> u64 {
    let low: u32;
    let high: u32;
    // SAFETY: reads a counter and touches no memory. RFC 0019 records that
    // this is readable at every privilege level here.
    unsafe {
        core::arch::asm!("rdtsc", out("eax") low, out("edx") high, options(nomem, nostack));
    }
    (u64::from(high) << 32) | u64::from(low)
}

/// Blocks until the service rings `wake_slot`, or a tenth of a second
/// passes — RFC 0023's whole point on the first arm, and the second is what
/// keeps a lost wake a slowdown rather than a hang: the deadline rides the
/// same notification (RFC 0019), so `WAIT` returns either way and the
/// caller re-reads the only truth, which is `RECV`'s reply. On a machine
/// with no calibrated counter there is no deadline to arm, and a yield is
/// what is left.
fn wait_for_news(wake_slot: u64, hertz: u64) {
    if hertz == 0 {
        let _ = call(syscall::YIELD, 0, 0, [0; 4]);
        return;
    }
    let deadline = rdtsc().wrapping_add(hertz / 10);
    let _ = call(syscall::INVOKE, wake_slot, method::ARM, [deadline, 0, 0, 0]);
    let _ = call(syscall::INVOKE, wake_slot, method::WAIT, [0; 4]);
}

/// One `RECV` poll on the outbound connection: `(state, delivered)`.
///
/// `consumed` names bytes this program has finished with since it last said
/// so — the service reopens the receive window by exactly that much, which
/// is RFC 0020's window-follows-free-space running from the caller's side.
/// Refusals and darkness end the run here, reported under `step`, because
/// every caller would have written the same four lines.
fn stream_state_consuming(step: u64, consumed: u64) -> (u64, u64) {
    let (called, word, packed) = call(syscall::CALL, CONNECTION, tcp::RECV, [consumed, 0, 0, 0]);
    if called != status::OK {
        report(step, outcome::REFUSED, called << 16);
        exit();
    }
    if word == tcp::UNREACHABLE {
        // No wire on this machine. The capability answered — that was step
        // 4a's claim — and the truthful end of the stream's story here is
        // that there is nobody to stream to.
        report(step, outcome::DARK, 0);
        exit();
    }
    if word != tcp::OK {
        report(step, outcome::REFUSED, word << 16);
        exit();
    }
    (packed >> 32, packed & 0xffff_ffff)
}

/// A poll that consumes nothing.
fn stream_state(step: u64) -> (u64, u64) {
    stream_state_consuming(step, 0)
}

/// Tells the service `count` more bytes are in the send ring, or ends the
/// run under `step`.
fn stream_send(count: u64, step: u64) {
    let (sent, _, _) = call(syscall::CALL, CONNECTION, tcp::SEND, [count, 0, 0, 0]);
    if sent != status::OK {
        report(step, outcome::REFUSED, sent << 8);
        exit();
    }
}

#[unsafe(no_mangle)]
extern "C" fn tcpc_main(hertz: u64) -> ! {
    // The report page first, so every later failure has somewhere to be seen.
    if call(
        syscall::INVOKE,
        REPORT,
        method::ATTACH,
        [REPORT_AT, 1, 0, 0],
    )
    .0 != status::OK
    {
        exit();
    }
    report_word(0, MARKER);
    report(0, outcome::STARTING, 0);

    // The rings are this program's own; map them and put the payload in the
    // send ring *before* gifting — the bytes are in place before the service
    // ever sees the pages, which is the ownership story told in the right
    // order.
    let attached = [
        (SEND_RING, SENDR_AT),
        (RECV_RING, RECVR_AT),
        (L_SEND_RING, L_SENDR_AT),
        (L_RECV_RING, L_RECVR_AT),
    ]
    .into_iter()
    .all(|(slot, at)| call(syscall::INVOKE, slot, method::ATTACH, [at, 1, 0, 0]).0 == status::OK);
    if !attached {
        report(0, outcome::REFUSED, 0xA);
        exit();
    }
    for (index, byte) in PAYLOAD.iter().enumerate() {
        // SAFETY: this program's own send ring, just mapped read-write.
        unsafe {
            core::ptr::write_volatile((SENDR_AT + index as u64) as *mut u8, *byte);
        }
    }
    // Touch every ring once, now, so a mapping that did not take faults here
    // -- two lines from the attach that claimed it did -- rather than deep in
    // the inbound serve with the interesting state a page fault destroys.
    for base in [RECVR_AT, L_SENDR_AT, L_RECVR_AT] {
        // SAFETY: this program's own rings, just mapped read-write.
        unsafe {
            let probe = core::ptr::read_volatile(base as *const u8);
            core::ptr::write_volatile(base as *mut u8, probe);
        }
    }

    // Leg 0: the send ring crosses. Leg 1: the receive ring. Each is one
    // `HAND` and one `CONNECT`, and each ring is a `Memory` object this
    // domain owns — which is what makes RFC 0022 step 3 mean something here:
    // if this program dies mid-connection, the service's copies die with it.
    let (status_0, value_0, detail_0) = leg(
        tcp::CONNECT,
        u64::from(PEER),
        PEER_PORT,
        Some((SEND_RING, 0)),
        0,
    );
    if status_0 == STUCK_STATUS {
        report(1, outcome::STUCK, 0);
        exit();
    }
    if status_0 != status::OK || value_0 != tcp::OK {
        report(
            1,
            outcome::REFUSED,
            status_0 << 32 | value_0 << 16 | detail_0,
        );
        exit();
    }

    let (status_1, value_1, detail_1) = leg(
        tcp::CONNECT,
        u64::from(PEER),
        PEER_PORT,
        Some((RECV_RING, 0)),
        1,
    );
    if status_1 == STUCK_STATUS {
        report(2, outcome::STUCK, 0);
        exit();
    }
    if status_1 != status::OK || value_1 != tcp::OK {
        report(
            2,
            outcome::REFUSED,
            status_1 << 32 | value_1 << 16 | detail_1,
        );
        exit();
    }
    report(2, outcome::RINGS_ACCEPTED, 0);

    // Leg 2: the connection capability comes back. Declared before the call,
    // one-shot and addressed to this endpoint, so a hostile service could not
    // fill a slot this program was keeping empty — and this service, asked
    // properly, can fill exactly the one it was offered.
    let (declared, _, _) = call(
        syscall::INVOKE,
        SERVICE,
        method::EXPECT,
        [CONNECTION, 0, 0, 0],
    );
    if declared != status::OK {
        report(3, outcome::REFUSED, declared << 8);
        exit();
    }
    // The listener's rings cross now too, and then both wakes — the order
    // is the service's declaration order (rings before wakes, RFC 0022 open
    // question 4's one-declaration constraint), and the wakes land before
    // the connection opens so no news is ever produced unrung.
    let (l0, v0, _) = leg(tcp::LISTEN, LISTEN_PORT, 0, Some((L_SEND_RING, 0)), 0);
    let (l1, v1, _) = leg(tcp::LISTEN, LISTEN_PORT, 0, Some((L_RECV_RING, 0)), 1);
    if l0 != status::OK || v0 != tcp::OK || l1 != status::OK || v1 != tcp::OK {
        report(2, outcome::REFUSED, l0 << 48 | v0 << 32 | l1 << 16 | v1);
        exit();
    }
    let (c3, cv3, _) = leg(tcp::CONNECT, u64::from(PEER), PEER_PORT, Some((WAKE, 1)), 3);
    let (l3, lv3, _) = leg(tcp::LISTEN, LISTEN_PORT, 0, Some((L_WAKE, 2)), 3);
    if c3 != status::OK || cv3 != tcp::OK || l3 != status::OK || lv3 != tcp::OK {
        report(2, outcome::REFUSED, c3 << 48 | cv3 << 32 | l3 << 16 | lv3);
        exit();
    }

    // The handshake clock starts here: leg 2 is what makes the SYN leave.
    let handshake_started = rdtsc();
    let (status_2, value_2, detail_2) = leg(tcp::CONNECT, u64::from(PEER), PEER_PORT, None, 2);
    if status_2 == STUCK_STATUS {
        report(3, outcome::STUCK, 0);
        exit();
    }
    if status_2 != status::OK || value_2 != tcp::OK {
        report(
            3,
            outcome::REFUSED,
            status_2 << 32 | value_2 << 16 | detail_2,
        );
        exit();
    }

    // The reply said yes; the slot says whether the capability truly landed.
    // Both halves are asserted because either alone can lie: a reply without
    // a landing is the exchange half-done, and a landing without a reply was
    // never offered. The probe reads by *refusal shape*: an empty slot fails
    // to resolve at all (`NO_SUCH_CAPABILITY`), while an occupied one reaches
    // method dispatch — `INFO` is not a method on an endpoint, and that
    // refusal is itself the proof something is there to refuse it.
    let (landed, kind, _) = call(syscall::INVOKE, CONNECTION, method::INFO, [0; 4]);
    if landed == status::NO_SUCH_CAPABILITY {
        report(4, outcome::UNLANDED, landed);
        exit();
    }
    report(4, outcome::CONNECTED, kind ^ value_2);

    // RFC 0022 step 4b's stream, run as RFC 0020 step 6's instrument. The
    // same exchange as before — establish, echo, close — but timed, repeated
    // and widened, because the numbers are what tell the next RFC whether it
    // is congestion control or reassembly. Raw cycle counts go in the report;
    // the kernel owns the conversion to time.
    let mut state;
    let mut bounded = 0u32;
    loop {
        let (s, _) = stream_state(5);
        state = s;
        if state == STATE_ESTABLISHED {
            break;
        }
        bounded += 1;
        if bounded > 300 {
            report(5, outcome::STUCK, state);
            exit();
        }
        wait_for_news(WAKE, hertz);
    }
    report_word(4, rdtsc().wrapping_sub(handshake_started));

    // Eight echoed round trips of sixteen bytes, each written at its own
    // stream offset, each timed from "the service was told" to "the echo is
    // in this program's ring". Eight, because a distribution needs more than
    // one and the boot has better things to do than a thousand.
    let mut samples = [0u64; 8];
    let mut sent_bytes = 0u64;
    // What has come back, and how much of it this program has told the
    // service it is done with. Everything seen is consumed at once: the
    // checks below read only the freshest window of the ring.
    let mut delivered_seen = 0u64;
    let mut consumed_told = 0u64;
    for (index, sample) in samples.iter_mut().enumerate() {
        for (offset, byte) in PAYLOAD.iter().enumerate() {
            let at = (index * PAYLOAD.len() + offset) % (4 * 4096);
            // SAFETY: this program's own send ring, bounded by the modulus.
            unsafe {
                core::ptr::write_volatile((SENDR_AT + at as u64) as *mut u8, *byte);
            }
        }
        let begun = rdtsc();
        if index == 0 {
            // The pipeline attribution's first stamp (RFC 0020 step 6's
            // follow-on instrument): the services each stamp their first
            // payload hop once, and the kernel lines the stamps up after
            // boot. First-echo-only, because later traffic — the bulk, the
            // inbound serve — would overwrite a "last" into meaninglessness.
            report_word(10, begun);
        }
        stream_send(PAYLOAD.len() as u64, 6);
        sent_bytes += PAYLOAD.len() as u64;
        let mut waited = 0u32;
        loop {
            let (_, delivered) = stream_state_consuming(6, delivered_seen - consumed_told);
            consumed_told = delivered_seen;
            delivered_seen = delivered_seen.max(delivered);
            if delivered >= sent_bytes {
                break;
            }
            waited += 1;
            if waited > 300 {
                report(6, outcome::STUCK, delivered);
                exit();
            }
            wait_for_news(WAKE, hertz);
        }
        *sample = rdtsc().wrapping_sub(begun);
        if index == 0 {
            report_word(11, rdtsc());
        }
    }
    samples.sort_unstable();
    report_word(5, samples[0]);
    report_word(6, samples[samples.len() / 2]);
    report_word(7, samples[samples.len() - 1]);

    // The first sample's echo, byte for byte, from pages this program owns.
    // This is the sentence the whole RFC chain exists for: the peer's bytes
    // are *here*, in memory no kernel wired and no service allocated.
    let echoed = (0..PAYLOAD.len()).all(|index| {
        // SAFETY: this program's own receive ring, mapped before anything
        // was gifted; the index is bounded.
        let byte = unsafe { core::ptr::read_volatile((RECVR_AT + index as u64) as *const u8) };
        byte == PAYLOAD[index]
    });
    if !echoed {
        report(6, outcome::MANGLED, 0);
        exit();
    }

    // Bulk: thirty-two KiB out and thirty-two echoed back, through a
    // sixteen-KiB ring — the wrap is the point — paced no more than four
    // KiB (one window) ahead of the echo so the un-acknowledged bytes
    // retransmission would need are never overwritten. Each chunk is stamped with its own
    // number, spot-checked after the wrap.
    const CHUNK: u64 = 1024;
    const CHUNKS: u64 = 32;
    let ring = (4 * 4096) as u64;
    let bulk_started = rdtsc();
    for chunk in 0..CHUNKS {
        let mut waited = 0u32;
        loop {
            let (_, delivered) = stream_state_consuming(7, delivered_seen - consumed_told);
            consumed_told = delivered_seen;
            delivered_seen = delivered_seen.max(delivered);
            if delivered + 4 * CHUNK >= sent_bytes {
                break;
            }
            waited += 1;
            if waited > 600 {
                report(7, outcome::STUCK, delivered);
                exit();
            }
            wait_for_news(WAKE, hertz);
        }
        for offset in 0..CHUNK {
            let at = (sent_bytes + offset) % ring;
            // SAFETY: this program's own send ring, bounded by the modulus.
            unsafe {
                core::ptr::write_volatile((SENDR_AT + at) as *mut u8, chunk as u8);
            }
        }
        stream_send(CHUNK, 7);
        sent_bytes += CHUNK;
    }
    let mut waited = 0u32;
    loop {
        let (_, delivered) = stream_state_consuming(7, delivered_seen - consumed_told);
        consumed_told = delivered_seen;
        delivered_seen = delivered_seen.max(delivered);
        if delivered >= sent_bytes {
            break;
        }
        waited += 1;
        if waited > 600 {
            report(7, outcome::STUCK, delivered);
            exit();
        }
        wait_for_news(WAKE, hertz);
    }
    report_word(8, rdtsc().wrapping_sub(bulk_started));
    report_word(9, CHUNKS * CHUNK);
    // The last chunk's first byte, read back across the wrap.
    let last_at = (sent_bytes - CHUNK) % ring;
    // SAFETY: this program's own receive ring, bounded by the modulus.
    let last = unsafe { core::ptr::read_volatile((RECVR_AT + last_at) as *const u8) };
    if last != (CHUNKS - 1) as u8 {
        report(7, outcome::MANGLED, u64::from(last));
        exit();
    }

    // Close in order, and see it acknowledged.
    let (closed, _, _) = call(syscall::CALL, CONNECTION, tcp::SHUTDOWN, [0; 4]);
    if closed != status::OK {
        report(8, outcome::REFUSED, closed << 8);
        exit();
    }
    let mut waited = 0u32;
    loop {
        let (s, _) = stream_state(8);
        state = s;
        if state != STATE_ESTABLISHED {
            break;
        }
        waited += 1;
        if waited > 300 {
            report(8, outcome::STUCK, state);
            exit();
        }
        wait_for_news(WAKE, hertz);
    }

    report(8, outcome::ECHOED, state);

    // RFC 0020 step 5's inbound half. The rings and the wake crossed before
    // the outbound stream began; what remains is asking for the listener
    // capability and then waiting — no longer polling — for the connection
    // the harness's host-side driver initiates.
    let (declared, _, _) = call(
        syscall::INVOKE,
        SERVICE,
        method::EXPECT,
        [LISTENER, 0, 0, 0],
    );
    if declared != status::OK {
        report(9, outcome::REFUSED, declared << 8);
        exit();
    }
    let (l2, v2, _) = leg(tcp::LISTEN, LISTEN_PORT, 0, None, 2);
    if l2 != status::OK || v2 != tcp::OK {
        report(9, outcome::REFUSED, l2 << 16 | v2);
        exit();
    }

    // Accept: poll the listener until the host's connection is established.
    let (declared, _, _) = call(syscall::INVOKE, SERVICE, method::EXPECT, [INBOUND, 0, 0, 0]);
    if declared != status::OK {
        report(10, outcome::REFUSED, declared << 8);
        exit();
    }
    let mut accepted = false;
    for _ in 0..100u32 {
        let (called, word, _) = call(syscall::CALL, LISTENER, tcp::ACCEPT, [0; 4]);
        if called != status::OK {
            report(10, outcome::REFUSED, called << 16);
            exit();
        }
        if word == tcp::OK {
            accepted = true;
            break;
        }
        if word == tcp::UNREACHABLE {
            report(10, outcome::DARK, 0);
            exit();
        }
        if word != tcp::LATER {
            report(10, outcome::REFUSED, word << 16);
            exit();
        }
        wait_for_news(L_WAKE, hertz);
    }
    if !accepted {
        report(10, outcome::NOBODY, 0);
        exit();
    }

    // Serve the echo: wait for the driver's bytes, copy them from the ring
    // the peer's stream lands in to the ring this program sends from, both
    // its own pages, and tell the service. Then wait for the peer's close,
    // which only arrives after the reply reached it — the causal proof.
    let mut served = false;
    for _ in 0..300u32 {
        let (called, word, packed) = call(syscall::CALL, INBOUND, tcp::RECV, [0, 0, 0, 0]);
        if called != status::OK || word != tcp::OK {
            report(11, outcome::REFUSED, called << 16 | word);
            exit();
        }
        let available = packed & 0xffff_ffff;
        if available >= INBOUND_LEN as u64 {
            served = true;
            break;
        }
        wait_for_news(L_WAKE, hertz);
    }
    if !served {
        report(11, outcome::STUCK, 0);
        exit();
    }
    for index in 0..INBOUND_LEN {
        // SAFETY: both rings are this program's own, mapped read-write at
        // fixed addresses before anything was gifted; the index is bounded.
        unsafe {
            let byte = core::ptr::read_volatile((L_RECVR_AT + index as u64) as *const u8);
            core::ptr::write_volatile((L_SENDR_AT + index as u64) as *mut u8, byte);
        }
    }
    let (sent, _, _) = call(
        syscall::CALL,
        INBOUND,
        tcp::SEND,
        [INBOUND_LEN as u64, 0, 0, 0],
    );
    if sent != status::OK {
        report(12, outcome::REFUSED, sent << 8);
        exit();
    }
    let mut closed = false;
    for _ in 0..300u32 {
        let (called, word, packed) = call(syscall::CALL, INBOUND, tcp::RECV, [0, 0, 0, 0]);
        if called != status::OK || word != tcp::OK {
            report(12, outcome::REFUSED, called << 16 | word);
            exit();
        }
        if packed >> 32 != STATE_ESTABLISHED {
            closed = true;
            break;
        }
        wait_for_news(L_WAKE, hertz);
    }
    if !closed {
        report(12, outcome::STUCK, 0);
        exit();
    }
    let (_, _, _) = call(syscall::CALL, INBOUND, tcp::SHUTDOWN, [0; 4]);
    report(13, outcome::SERVED, 0);
    exit()
}

core::arch::global_asm!(
    r#"
.section .text._start,"ax",@progbits
.globl _start
_start:
    xor rbp, rbp
    and rsp, -16
    call tcpc_main
    ud2
"#
);
