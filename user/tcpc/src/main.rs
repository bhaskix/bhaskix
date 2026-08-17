// SPDX-License-Identifier: Apache-2.0
//! The TCP demonstration client: rings it owns, handed across `CONNECT`.
//!
//! RFC 0022 step 4's caller, RFC 0020 step 6's instrument, and RFC 0020
//! step 5's server for one connection. It opens a connection the way every
//! program will: two rings its own domain owns cross as staged gifts, a
//! wake crosses after them, and the connection capability rides a reply
//! into a slot this program declared. Then it echoes — sixteen bytes eight
//! times, timed; thirty-two KiB through the ring's wrap, paced by its own
//! memory — listens, accepts a connection the harness's host driver
//! initiates, and serves the echo back from pages it owns before the data
//! flowed through them.
//!
//! What lands in the report page is read by the kernel after boot and gated
//! in `tests/qemu/boot-test.sh`, like every service report.
//!
//! # The second program ported onto `bhaskix-sock`
//!
//! RFC 0027 step 4. The exchange — the staged legs and their bounded
//! retries, the `EXPECT` declarations, the refusal decoding, the stream
//! verbs, the memory-wait — is the crate's now; what remains here is what
//! is genuinely this program's: the demonstration's order, the instrument's
//! clocks, and the report it leaves. The leg *interleaving* stays local on
//! purpose: the service declares where gifts may land in its own order, and
//! the crate's primitive is what makes that expressible (RFC 0027 open
//! question 2, answered by this port).

#![no_std]
#![no_main]

use bhaskix_abi::{syscall, tcp as abi_tcp};
use bhaskix_sock::call::{attach, call};
use bhaskix_sock::ring::RingView;
use bhaskix_sock::tcp::{self, AcceptPoll, LegError, StreamPoll};
use bhaskix_sock::time::{Pace, now};
use bhaskix_sock::wait::news;

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

/// Bytes in each stream ring this program owns.
const RING_BYTES: u64 = 4 * 4096;

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
    /// The connection capability works but the machine cannot be
    /// unpredictable: the service answered `NO_ENTROPY` when asked to
    /// stream. Terminal, and the truthful ending on a machine whose
    /// sequence numbers would be guessable — [`DARK`]'s sibling, told
    /// apart because the network may exist here and "unreachable" would
    /// be a lie.
    pub const NO_ENTROPY: u64 = 11;
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // SAFETY: an undefined instruction, deliberately. Stopping where the
    // kernel can see it beats reporting a success that did not happen.
    unsafe { core::arch::asm!("ud2", options(noreturn)) }
}

/// Ends this program. Never returns.
fn exit() -> ! {
    let _ = call(syscall::EXIT, 0, 0, [0; 4]);
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

/// One handover leg, or the end of the run under `step` — the crate keeps
/// every raw word a refusal carried, and this packs them the way this
/// program's report has always packed them.
fn leg_or_die(
    verb: u64,
    a0: u64,
    a1: u64,
    gift: Option<(u64, u64)>,
    leg_number: u64,
    step: u64,
) -> u64 {
    match tcp::leg(SERVICE, verb, a0, a1, gift, leg_number) {
        Ok(detail) => detail,
        Err(LegError::Stuck) => {
            report(step, outcome::STUCK, 0);
            exit()
        }
        Err(LegError::HandRefused(status)) => {
            report(step, outcome::REFUSED, 0xFFFF << 32 | status << 16);
            exit()
        }
        Err(LegError::Refused {
            status,
            value,
            detail,
        }) => {
            report(step, outcome::REFUSED, status << 32 | value << 16 | detail);
            exit()
        }
    }
}

/// One `RECV` poll on the outbound connection: `(state, delivered)`.
///
/// `consumed` names bytes this program has finished with since it last said
/// so — the service reopens the receive window by exactly that much.
/// Refusals and darkness end the run here, reported under `step`, because
/// every caller would have written the same four lines.
fn stream_state_consuming(step: u64, consumed: u64) -> (u64, u64) {
    match tcp::recv(CONNECTION, consumed) {
        StreamPoll::Ready { state, delivered } => (state, delivered),
        StreamPoll::Unreachable => {
            // No wire on this machine. The capability answered — that was
            // step 4a's claim — and the truthful end of the stream's story
            // here is that there is nobody to stream to.
            report(step, outcome::DARK, 0);
            exit()
        }
        StreamPoll::NoEntropy => {
            // No unpredictability on this machine, so the service refuses
            // to mint sequence numbers — RFC 0021's policy, heard from the
            // caller's side.
            report(step, outcome::NO_ENTROPY, 0);
            exit()
        }
        StreamPoll::ServiceSaid(word) => {
            report(step, outcome::REFUSED, word << 16);
            exit()
        }
        StreamPoll::KernelSaid(status) => {
            report(step, outcome::REFUSED, status << 16);
            exit()
        }
    }
}

/// A poll that consumes nothing.
fn stream_state(step: u64) -> (u64, u64) {
    stream_state_consuming(step, 0)
}

/// Tells the service `count` more bytes are in the send ring, or ends the
/// run under `step`.
fn stream_send(count: u64, step: u64) {
    if let Err(status) = tcp::send(CONNECTION, count) {
        report(step, outcome::REFUSED, status << 8);
        exit();
    }
}

#[unsafe(no_mangle)]
extern "C" fn tcpc_main(hertz: u64) -> ! {
    let pace = Pace::new(hertz);
    // The report page first, so every later failure has somewhere to be seen.
    if !attach(REPORT, REPORT_AT, true) {
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
    .all(|(slot, at)| attach(slot, at, true));
    if !attached {
        report(0, outcome::REFUSED, 0xA);
        exit();
    }
    // SAFETY: each ring was attached just above at its fixed address, and
    // stays mapped for the life of this program — the one claim the views
    // carry, made where the mapping was made.
    let (send_view, recv_view, l_send_view, l_recv_view) = unsafe {
        (
            RingView::new(SENDR_AT, RING_BYTES),
            RingView::new(RECVR_AT, RING_BYTES),
            RingView::new(L_SENDR_AT, RING_BYTES),
            RingView::new(L_RECVR_AT, RING_BYTES),
        )
    };
    for (index, byte) in PAYLOAD.iter().enumerate() {
        send_view.write(index as u64, *byte);
    }
    // Touch every ring once, now, so a mapping that did not take faults here
    // -- two lines from the attach that claimed it did -- rather than deep in
    // the inbound serve with the interesting state a page fault destroys.
    for view in [recv_view, l_send_view, l_recv_view] {
        let probe = view.read(0);
        view.write(0, probe);
    }

    // Leg 0: the send ring crosses. Leg 1: the receive ring. Each is one
    // `HAND` and one `CONNECT`, and each ring is a `Memory` object this
    // domain owns — which is what makes RFC 0022 step 3 mean something here:
    // if this program dies mid-connection, the service's copies die with it.
    let _ = leg_or_die(
        abi_tcp::CONNECT,
        u64::from(PEER),
        PEER_PORT,
        Some((SEND_RING, 0)),
        0,
        1,
    );
    let _ = leg_or_die(
        abi_tcp::CONNECT,
        u64::from(PEER),
        PEER_PORT,
        Some((RECV_RING, 0)),
        1,
        2,
    );
    report(2, outcome::RINGS_ACCEPTED, 0);

    // Leg 2's landing: the connection capability comes back. Declared before
    // the call, one-shot and addressed to this endpoint, so a hostile service
    // could not fill a slot this program was keeping empty — and this
    // service, asked properly, can fill exactly the one it was offered.
    if let Err(status) = tcp::expect(SERVICE, CONNECTION) {
        report(3, outcome::REFUSED, status << 8);
        exit();
    }
    // The listener's rings cross now too, and then both wakes — the order
    // is the service's declaration order (rings before wakes, RFC 0022 open
    // question 4's one-declaration constraint), and the wakes land before
    // the connection opens so no news is ever produced unrung.
    let _ = leg_or_die(
        abi_tcp::LISTEN,
        LISTEN_PORT,
        0,
        Some((L_SEND_RING, 0)),
        0,
        2,
    );
    let _ = leg_or_die(
        abi_tcp::LISTEN,
        LISTEN_PORT,
        0,
        Some((L_RECV_RING, 0)),
        1,
        2,
    );
    let _ = leg_or_die(
        abi_tcp::CONNECT,
        u64::from(PEER),
        PEER_PORT,
        Some((WAKE, 1)),
        3,
        2,
    );
    let _ = leg_or_die(abi_tcp::LISTEN, LISTEN_PORT, 0, Some((L_WAKE, 2)), 3, 2);

    // The handshake clock starts here: leg 2 is what makes the SYN leave.
    let handshake_started = now();
    let _ = leg_or_die(abi_tcp::CONNECT, u64::from(PEER), PEER_PORT, None, 2, 3);
    // `leg_or_die` returns only when the service said yes, so the reply
    // word the old detail XORed against is the constant it always was.
    let value_2 = abi_tcp::OK;

    // The reply said yes; the slot says whether the capability truly landed.
    // Both halves are asserted because either alone can lie: a reply without
    // a landing is the exchange half-done, and a landing without a reply was
    // never offered. The probe reads by *refusal shape* — the crate's
    // `occupied` is that idiom, kept.
    let (landed, probe) = tcp::occupied(CONNECTION);
    if !landed {
        report(4, outcome::UNLANDED, probe.status);
        exit();
    }
    report(4, outcome::CONNECTED, probe.value ^ value_2);

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
        news(WAKE, &pace);
    }
    report_word(4, now().wrapping_sub(handshake_started));

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
            send_view.write((index * PAYLOAD.len() + offset) as u64, *byte);
        }
        let begun = now();
        stream_send(PAYLOAD.len() as u64, 6);
        sent_bytes += PAYLOAD.len() as u64;
        // Seen when the echo's last byte is in this program's own ring —
        // no calls on the wait path. The consuming RECV afterwards reports
        // the read bytes so the window reopens, off the clock.
        let expected = PAYLOAD[PAYLOAD.len() - 1];
        if !recv_view.wait_for(sent_bytes - 1, expected, WAKE, &pace, 600) {
            report(6, outcome::STUCK, 0);
            exit();
        }
        *sample = now().wrapping_sub(begun);
        let (_, delivered) = stream_state_consuming(6, sent_bytes - consumed_told);
        consumed_told = sent_bytes;
        delivered_seen = delivered_seen.max(delivered);
    }
    samples.sort_unstable();
    report_word(5, samples[0]);
    report_word(6, samples[samples.len() / 2]);
    report_word(7, samples[samples.len() - 1]);

    // The first sample's echo, byte for byte, from pages this program owns.
    // This is the sentence the whole RFC chain exists for: the peer's bytes
    // are *here*, in memory no kernel wired and no service allocated.
    let echoed = (0..PAYLOAD.len()).all(|index| recv_view.read(index as u64) == PAYLOAD[index]);
    if !echoed {
        report(6, outcome::MANGLED, 0);
        exit();
    }

    // Bulk: thirty-two KiB out and thirty-two echoed back, through a
    // sixteen-KiB ring — the wrap is the point — paced one full ring ahead
    // of the echo, which is one full window now that the service advertises
    // the whole ring. The pacing constraint *is* the ring: chunk `c` lands
    // where chunk `c - 16` lived, and an echoed chunk is an acknowledged
    // chunk — its echo rode a segment whose `ACK` the service processed
    // before delivering the bytes this program polls for — so the bytes
    // retransmission would need are never overwritten. Each chunk is stamped
    // with its own number, spot-checked after the wrap.
    const CHUNK: u64 = 1024;
    const CHUNKS: u64 = 32;
    // Chunks the ring holds, which is how far ahead of the echo to run.
    let depth = RING_BYTES / CHUNK;
    let bulk_started = now();
    let bulk_base = sent_bytes;
    for chunk in 0..CHUNKS {
        // Pace by the ring itself: before chunk `c` goes out, the chunk
        // whose ring bytes it overwrites must have echoed back — its stamp
        // visible in this program's own receive ring — keeping a full ring
        // in flight with no calls on the wait path. A stale byte cannot
        // fake the stamp: stamps run 1..=32, the ring starts zeroed, the
        // round-trip payload's bytes are all ASCII forty-five and up, and
        // the previous lap's stamp at the same offset differs by sixteen.
        // The consuming RECV that follows is the window reopening, once
        // per chunk instead of once per poll.
        if chunk >= depth {
            let awaited = chunk - depth;
            let at = bulk_base + (awaited + 1) * CHUNK - 1;
            if !recv_view.wait_for(at, (awaited as u8).wrapping_add(1), WAKE, &pace, 600) {
                report(7, outcome::STUCK, awaited);
                exit();
            }
            let arrived = bulk_base + (awaited + 1) * CHUNK;
            let (_, delivered) = stream_state_consuming(7, arrived - consumed_told);
            consumed_told = arrived;
            delivered_seen = delivered_seen.max(delivered);
        }
        for offset in 0..CHUNK {
            // The stamp is `chunk + 1`, never zero, so an arrived chunk is
            // distinguishable from the zero-initialised ring it lands in --
            // which is what lets the wait read its own memory instead of
            // asking the service.
            send_view.write(sent_bytes + offset, (chunk as u8).wrapping_add(1));
        }
        stream_send(CHUNK, 7);
        sent_bytes += CHUNK;
    }
    {
        if !recv_view.wait_for(
            sent_bytes - 1,
            (CHUNKS as u8 - 1).wrapping_add(1),
            WAKE,
            &pace,
            600,
        ) {
            report(7, outcome::STUCK, CHUNKS);
            exit();
        }
        let _ = stream_state_consuming(7, sent_bytes - consumed_told);
    }
    report_word(8, now().wrapping_sub(bulk_started));
    report_word(9, CHUNKS * CHUNK);
    // The last chunk's first byte, read back across the wrap.
    let last = recv_view.read(sent_bytes - CHUNK);
    if last != (CHUNKS - 1) as u8 + 1 {
        report(7, outcome::MANGLED, u64::from(last));
        exit();
    }

    // Close in order, and see it acknowledged.
    if let Err(status) = tcp::shutdown(CONNECTION) {
        report(8, outcome::REFUSED, status << 8);
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
        news(WAKE, &pace);
    }

    report(8, outcome::ECHOED, state);

    // RFC 0020 step 5's inbound half. The rings and the wake crossed before
    // the outbound stream began; what remains is asking for the listener
    // capability and then waiting — no longer polling — for the connection
    // the harness's host-side driver initiates.
    if let Err(status) = tcp::expect(SERVICE, LISTENER) {
        report(9, outcome::REFUSED, status << 8);
        exit();
    }
    let _ = leg_or_die(abi_tcp::LISTEN, LISTEN_PORT, 0, None, 2, 9);

    // Accept: poll the listener until the host's connection is established.
    if let Err(status) = tcp::expect(SERVICE, INBOUND) {
        report(10, outcome::REFUSED, status << 8);
        exit();
    }
    let mut accepted = false;
    for _ in 0..100u32 {
        match tcp::accept(LISTENER) {
            AcceptPoll::Accepted => {
                accepted = true;
                break;
            }
            AcceptPoll::Later => news(L_WAKE, &pace),
            AcceptPoll::Unreachable => {
                report(10, outcome::DARK, 0);
                exit();
            }
            AcceptPoll::ServiceSaid(word) => {
                report(10, outcome::REFUSED, word << 16);
                exit();
            }
            AcceptPoll::KernelSaid(status) => {
                report(10, outcome::REFUSED, status << 16);
                exit();
            }
        }
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
        match tcp::recv(INBOUND, 0) {
            StreamPoll::Ready { delivered, .. } => {
                if delivered >= INBOUND_LEN as u64 {
                    served = true;
                    break;
                }
                news(L_WAKE, &pace);
            }
            StreamPoll::KernelSaid(status) => {
                report(11, outcome::REFUSED, status << 16);
                exit();
            }
            StreamPoll::Unreachable | StreamPoll::NoEntropy => {
                report(11, outcome::REFUSED, 0);
                exit();
            }
            StreamPoll::ServiceSaid(word) => {
                report(11, outcome::REFUSED, word);
                exit();
            }
        }
    }
    if !served {
        report(11, outcome::STUCK, 0);
        exit();
    }
    for index in 0..INBOUND_LEN as u64 {
        l_send_view.write(index, l_recv_view.read(index));
    }
    if let Err(status) = tcp::send(INBOUND, INBOUND_LEN as u64) {
        report(12, outcome::REFUSED, status << 8);
        exit();
    }
    let mut closed = false;
    for _ in 0..300u32 {
        match tcp::recv(INBOUND, 0) {
            StreamPoll::Ready { state, .. } => {
                if state != STATE_ESTABLISHED {
                    closed = true;
                    break;
                }
                news(L_WAKE, &pace);
            }
            StreamPoll::KernelSaid(status) => {
                report(12, outcome::REFUSED, status << 16);
                exit();
            }
            StreamPoll::Unreachable | StreamPoll::NoEntropy => {
                report(12, outcome::REFUSED, 0);
                exit();
            }
            StreamPoll::ServiceSaid(word) => {
                report(12, outcome::REFUSED, word);
                exit();
            }
        }
    }
    if !closed {
        report(12, outcome::STUCK, 0);
        exit();
    }
    let _ = tcp::shutdown(INBOUND);
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
