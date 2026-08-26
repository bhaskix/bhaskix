// SPDX-License-Identifier: Apache-2.0
//! The connection, as a pure function.
//!
//! [RFC 0020](../../../docs/rfc/0020-tcp.md) step 3, and the decision the whole
//! document rests on:
//!
//! ```text
//! step(tcb, event, now) -> (tcb, actions)
//! ```
//!
//! No I/O. No clock — the time is an argument. No allocation. No knowledge that
//! domains, rings or capabilities exist. An [`Event`] is a segment that arrived,
//! a call the program made, or a timer that expired; an [`Action`] is a segment
//! to send, a timer to arm, bytes to hand the program, or the news that the
//! connection is over.
//!
//! # Why this shape, and what it buys
//!
//! Everything hard about TCP is a *sequence* of events with time between them:
//! a segment lost, a pair reordered, a `RST` arriving in the one state that must
//! ignore it, a `FIN` crossing a `FIN`, a peer that advertises zero and never
//! opens. A live network will not reproduce any of that on demand.
//!
//! Here they are all ordinary host tests: build a control block, drive events
//! into it, advance a `u64`. `docs/coding-style.md` calls a subsystem testable
//! only in QEMU a design smell, and TCP is where that rule either pays for
//! itself or is worthless.
//!
//! # The stream is not here
//!
//! Not one byte of application data lives in this module. The program supplies
//! the pages ([RFC 0020](../../../docs/rfc/0020-tcp.md) §"a connection's stream
//! lives in the program's pages"), and this machine only ever names *ranges of
//! the stream*: [`Emit`] says "send `length` bytes starting at this sequence
//! number", and `bin/tcpd` reads them out of the program's ring when it builds
//! the segment.
//!
//! That is what makes the second-largest claim here true as well — **the receive
//! window is the free space in the program's own ring**, so flow control needs
//! no separate accounting and a connection costs the memory of whoever opened
//! it.
//!
//! # What is deliberately absent
//!
//! No congestion control, no window scaling, no SACK, no timestamps, no path
//! MTU discovery, no keepalive, no urgent data, and **no reassembly queue** — a
//! segment arriving ahead of what is expected is dropped rather than held.
//! Each of those is named in RFC 0020 with what it costs. The one that shows up
//! first is the missing queue: a single loss costs a retransmission timeout
//! rather than a duplicate acknowledgement.

use crate::tcp::segment::{Flags, Options, Segment};
use crate::tcp::{FourTuple, Sequence};

/// The eleven states of RFC 793 §3.2.
///
/// `Closed` is "no connection at all", and is both where a control block starts
/// and where every path ends.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum State {
    /// No connection.
    Closed,
    /// Waiting for a connection request from anyone.
    Listen,
    /// A connection request has been sent; waiting for a matching one back.
    SynSent,
    /// A connection request has been both received and sent; waiting for it to
    /// be acknowledged.
    SynReceived,
    /// Open. Data may pass in both directions.
    Established,
    /// This end has closed; waiting for the peer's acknowledgement or its own
    /// close.
    FinWait1,
    /// This end's close is acknowledged; waiting for the peer's.
    FinWait2,
    /// The peer has closed; this end may still send.
    CloseWait,
    /// Both ends closed at once; waiting for this end's close to be
    /// acknowledged.
    Closing,
    /// The peer closed first and this end followed; waiting for the last
    /// acknowledgement.
    LastAck,
    /// Waiting long enough that any duplicate of this connection has left the
    /// network.
    TimeWait,
}

impl State {
    /// Whether data may still be sent from this end.
    #[must_use]
    pub const fn can_send(self) -> bool {
        matches!(self, Self::Established | Self::CloseWait)
    }

    /// Whether a segment from the peer can still carry data to this end.
    #[must_use]
    pub const fn can_receive(self) -> bool {
        matches!(self, Self::Established | Self::FinWait1 | Self::FinWait2)
    }
}

/// The four timers a connection can have outstanding.
///
/// [RFC 0019](../../../docs/rfc/0019-time-and-timers.md) gives one deadline per
/// notification and says a service needing several keeps its own ordered list
/// and arms the nearest. That list belongs to `bin/tcpd`; this module only ever
/// says which timer wants which instant.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Timer {
    /// Nothing has been acknowledged for long enough: send it again.
    Retransmit,
    /// An acknowledgement is owed and was held back in case data followed.
    DelayedAck,
    /// The peer advertised a zero window; poke it so a lost window update
    /// cannot deadlock the connection.
    Probe,
    /// `TIME_WAIT` has run long enough that a duplicate cannot still arrive.
    TimeWait,
}

/// Why a connection ended.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Ended {
    /// Both ends closed in order and `TIME_WAIT` expired. The good ending.
    Orderly,
    /// The peer sent `RST`. Distinct from [`Ended::Orderly`] because a program
    /// that has read half a response needs to know the rest is not coming.
    Reset,
    /// The peer answered a connection request with `RST`.
    Refused,
    /// Retransmitted [`MAX_RETRANSMITS`] times with no acknowledgement.
    Unreachable,
    /// This end gave up on purpose — the program asked to abort, or its address
    /// space went away.
    Aborted,
}

/// Bytes of a segment's payload, at most.
///
/// Derived from the interface MTU (`net/src/eth.rs`) less an IPv4 header and a
/// TCP header, and never revised: RFC 0020 does not implement path MTU
/// discovery, and says what that costs — on a path with a smaller MTU this
/// stalls rather than degrades.
pub const DEFAULT_MSS: u16 = 1460;

/// The retransmission timeout before any round trip has been measured.
///
/// One second, which is RFC 6298's initial value and is chosen for a network
/// nobody has measured yet rather than for this one.
pub const INITIAL_RTO_US: u64 = 1_000_000;

/// The smallest retransmission timeout this implementation will use.
///
/// **This is RFC 0020's open question 2 and it is not answered here.** The
/// traditional floor is 200 ms and exists for clocks this system does not have:
/// RFC 0019's deadline was measured on 2026-08-14 as late by a median of
/// 0.065–0.226 ms, so a floor in the low milliseconds is expressible. Ten
/// milliseconds is a placeholder that makes the machine testable, chosen
/// deliberately *without* a caller, and step 6's measurement is what should
/// replace it. Recorded here rather than in a commit message so that the next
/// reader knows it is provisional.
pub const MIN_RTO_US: u64 = 10_000;

/// The largest retransmission timeout backoff will reach.
pub const MAX_RTO_US: u64 = 60_000_000;

/// How long an acknowledgement may be held back waiting for data to carry it.
///
/// RFC 1122 §4.2.3.2 caps this at 500 ms and asks for an acknowledgement at
/// least every second full-sized segment; both are implemented, and 200 ms is
/// the customary value inside that cap.
pub const DELAYED_ACK_US: u64 = 200_000;

/// Maximum segment lifetime.
///
/// RFC 793 says two minutes. Thirty seconds is what contemporary stacks use and
/// what this one uses, because `TIME_WAIT` holds a table slot and RFC 793's
/// figure was chosen for a slower network. The consequence is stated rather
/// than hidden: a duplicate delayed by more than a minute could in principle be
/// mistaken for a live segment, which the initial sequence number's clock
/// component (`super::isn`) is the second defence against.
pub const MSL_US: u64 = 30_000_000;

/// How many times a segment is retransmitted before the connection is
/// abandoned.
///
/// Eight, with exponential backoff from [`INITIAL_RTO_US`], is well past RFC
/// 1122's hundred-second floor for `R2`.
pub const MAX_RETRANSMITS: u8 = 8;

/// How many times a `SYN·ACK` is retransmitted before a connection **nobody
/// has proved they wanted** is abandoned. Named after Linux's
/// `tcp_synack_retries`, which is the same knob.
///
/// # Why this is smaller than [`MAX_RETRANSMITS`]
///
/// A connection in [`State::SynReceived`] was created by one packet from an
/// address that need not exist, and the peer has not yet said anything only a
/// real peer could say. Until the handshake completes, patience is spent on
/// somebody who may not be there — and it is spent out of a table this service
/// refuses at the size of, so the patience is *somebody else's connection*.
///
/// Under RFC 0047 that cost was measured rather than argued about: one such
/// connection held `bin/tcpd`'s single accepted slot for **242 seconds**, and
/// every later `SYN` was refused silently for all of it.
///
/// # This is a deliberate deviation from RFC 1122, read and quoted
///
/// RFC 1122 §4.2.3.5, on connection failures:
///
/// > *"However, the values of R1 and R2 may be different for SYN and data
/// > segments. In particular, R2 for a SYN segment MUST be set large enough to
/// > provide retransmission of the segment for at least 3 minutes. The
/// > application can close the connection (i.e., give up on the open attempt)
/// > sooner, of course."*
///
/// Three retransmissions is **fourteen seconds**, and 180 is the floor. The
/// specification was read on 2026-08-24 rather than recalled, and this constant
/// does not meet it. The deviation is taken knowingly, for one reason: the
/// compliant value is what let **one packet from an address that need not
/// exist** take a listener out for 242 seconds, and keep taking it out for as
/// long as the sender cared to continue. Availability was chosen over the
/// letter, and the choice is written here rather than left for somebody to
/// discover in a packet trace.
///
/// Two things bound it. The spec's own escape hatch is an *application*
/// giving up sooner, which is a shape this system could adopt — the listening
/// program choosing its own patience — and has not. And **SYN cookies remove
/// the trade rather than repricing it**: with no state allocated for a peer
/// that has proved nothing, there is no half-open connection for `R2` to
/// govern and this constant stops mattering. That is [RFC 0048]'s steps 2 to 4,
/// specified and not built.
pub const MAX_SYNACK_RETRANSMITS: u8 = 3;

/// The whole point is that these differ, and that it is *this* one that is
/// smaller. Checked at compile time rather than in a test, because a test can
/// only fail after somebody has built the thing.
const _: () = assert!(MAX_SYNACK_RETRANSMITS < MAX_RETRANSMITS);

/// The largest number of actions a single [`step`] can produce.
///
/// # This number was wrong, and the fuzz target is what said so
///
/// It was eight, with a comment reasoning that "a segment that acknowledges
/// data, delivers data, and carries a `FIN` is the worst case, and it does not
/// reach eight". The state-machine fuzz target overflowed it within a hundred
/// seconds of first being run. The reasoning had counted the segments and
/// forgotten the timers: one arriving segment can acknowledge data, complete a
/// close, deliver data, acknowledge *that*, and leave this end with data of its
/// own to send, touching three timers on the way.
///
/// **The fix is [`Actions::push`], not this number**, and which one did the
/// work was measured rather than assumed. `push` now *replaces* an instruction
/// for a timer that already has one in the same step, so a step can never hold
/// more than one instruction per timer — four at most, each meaningful rather
/// than the last of a pile. With that in place, a target left at **eight**
/// survived 9.8 million executions without overflowing.
///
/// Sixteen is therefore **headroom and not a measured requirement**, and it is
/// deliberate: the previous number was a counted worst case that was wrong, and
/// a repeat costs a service its actions where a spare eight slots cost a few
/// bytes of stack. Recorded this way so the next reader does not mistake it for
/// a figure somebody derived.
pub const MAX_ACTIONS: usize = 16;

/// What a caller did, what arrived, or what expired.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Event<'a> {
    /// The program asked to connect. Carries the initial sequence number —
    /// computed by the caller from [`super::isn`], because this function has no
    /// clock and no secret — and the size of the program's receive ring.
    Connect {
        /// This end's initial sequence number.
        iss: Sequence,
        /// Bytes free in the program's receive ring, which is the window.
        window: u16,
    },
    /// The program asked to listen. Same arguments, and a connection is not
    /// created until a `SYN` arrives.
    Listen {
        /// This end's initial sequence number, used when the `SYN` arrives.
        iss: Sequence,
        /// Bytes free in the program's receive ring.
        window: u16,
    },
    /// The program wrote bytes into its send ring.
    Wrote(u32),
    /// The program consumed bytes from its receive ring, which reopens the
    /// window by that much.
    Read(u32),
    /// The program will send no more. Half-close: the other direction keeps
    /// working, which is what makes a request/response protocol expressible.
    Shutdown,
    /// The program gave up. Sends `RST` and destroys the connection.
    Abort,
    /// A segment arrived from the peer.
    Arrived(Segment<'a>),
    /// A timer expired.
    Expired(Timer),
}

/// A segment to send, named as a range of the stream rather than as bytes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Emit {
    /// The control bits, less `ACK` — which [`crate::tcp::segment::write`]
    /// derives from [`Emit::acknowledgement`].
    pub flags: Flags,
    /// The sequence number of the first byte, or of the `SYN`/`FIN` itself.
    pub sequence: Sequence,
    /// What this end has received, if anything is being acknowledged.
    pub acknowledgement: Option<Sequence>,
    /// The window this end is advertising.
    pub window: u16,
    /// How many bytes of the program's send ring to put in this segment,
    /// starting at [`Emit::sequence`].
    pub length: u16,
    /// The maximum segment size option, on a `SYN` only.
    pub mss: Option<u16>,
}

impl Emit {
    /// The segment this describes, given where the payload was read from.
    ///
    /// The one place the two halves of this crate meet: the state machine names
    /// a range, the caller fetches those bytes, and this builds the thing that
    /// goes on the wire. Written here so no caller has to remember which fields
    /// come from which.
    #[must_use]
    pub fn segment<'a>(&self, connection: FourTuple, payload: &'a [u8]) -> Segment<'a> {
        Segment {
            source: connection.local_port,
            destination: connection.remote_port,
            sequence: self.sequence,
            acknowledgement: self.acknowledgement,
            flags: self.flags,
            window: self.window,
            options: Options { mss: self.mss },
            payload,
        }
    }
}

/// One thing the caller must do.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Action {
    /// Put this segment on the wire.
    Emit(Emit),
    /// Arm `timer` to expire at this absolute time, replacing any deadline it
    /// already had.
    Arm {
        /// Which timer.
        timer: Timer,
        /// When, in the same monotonic nanoseconds every `now` here uses.
        at: u64,
    },
    /// Cancel `timer` if it is armed.
    Cancel(Timer),
    /// This many bytes were appended to the program's receive ring, in order.
    /// The program should be woken.
    Delivered(u32),
    /// This many bytes at the tail of the program's send ring are acknowledged
    /// and the space is free. The program should be woken.
    Acknowledged(u32),
    /// The connection is over. Every blocked caller should be told, and the
    /// control block may be reused.
    Closed(Ended),
}

/// A bounded list of [`Action`]s.
///
/// Fixed size, because everything in this crate that a remote party can drive
/// is fixed size. A growing list would be memory a peer decides how to spend.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Actions {
    items: [Option<Action>; MAX_ACTIONS],
    count: usize,
    overflowed: bool,
}

impl Actions {
    /// An empty list.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            items: [None; MAX_ACTIONS],
            count: 0,
            overflowed: true_if_never(),
        }
    }

    /// Adds an action, or records that it could not be added.
    ///
    /// **An instruction for a timer replaces one already in this list.** Arming
    /// a timer twice in one step is not two instructions, it is one decision
    /// taken twice — only the last would survive at the caller anyway — so
    /// folding them here keeps the list a description of what must happen
    /// rather than a log of how the machine got there. The replacement keeps
    /// the earlier position, which is safe because the order that matters is
    /// segments against each other, and a timer is not a segment.
    fn push(&mut self, action: Action) {
        if let Some(timer) = timer_of(action)
            && let Some(slot) = self
                .items
                .iter_mut()
                .take(self.count)
                .find(|slot| slot.and_then(timer_of) == Some(timer))
        {
            *slot = Some(action);
            return;
        }
        match self.items.get_mut(self.count) {
            Some(slot) => {
                *slot = Some(action);
                self.count += 1;
            }
            // Not a panic — this runs in a service holding every connection —
            // and not silent either. `MAX_ACTIONS` is sized for the worst case
            // this machine can produce, so reaching here is a bug in `step`,
            // and both fuzz targets assert it never does. One of them has
            // already caught it once; see `MAX_ACTIONS`.
            None => self.overflowed = true,
        }
    }

    /// How many actions are in the list.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Whether the list is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Whether an action was dropped for want of room. Always a bug.
    #[must_use]
    pub const fn overflowed(&self) -> bool {
        self.overflowed
    }

    /// The actions, in the order they must be performed.
    pub fn iter(&self) -> impl Iterator<Item = Action> + '_ {
        self.items.iter().take(self.count).filter_map(|slot| *slot)
    }
}

/// `false`, written so [`Actions::new`] can be `const` and still read as
/// "nothing has overflowed yet".
const fn true_if_never() -> bool {
    false
}

/// Which timer an action instructs, if it instructs one at all.
const fn timer_of(action: Action) -> Option<Timer> {
    match action {
        Action::Arm { timer, .. } | Action::Cancel(timer) => Some(timer),
        _ => None,
    }
}

/// Everything a connection remembers.
///
/// The variable names are RFC 793 §3.2's, deliberately: `snd_una`, `rcv_nxt`
/// and the rest are what every description of TCP ever written calls them, and
/// inventing clearer ones would make this code harder to check against the
/// specification, not easier.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Tcb {
    /// Which of the eleven states this connection is in.
    pub state: State,
    /// The four numbers that name it.
    pub connection: FourTuple,

    /// Oldest sequence number sent and not yet acknowledged.
    pub snd_una: Sequence,
    /// Next sequence number to send.
    pub snd_nxt: Sequence,
    /// One past the last byte the program has made available to send.
    pub snd_avail: Sequence,
    /// The window the peer last advertised.
    pub snd_wnd: u16,
    /// This end's initial sequence number.
    pub iss: Sequence,
    /// The sequence number this end's `FIN` occupies, once it has been sent.
    pub fin_seq: Option<Sequence>,
    /// Whether the program has asked to close and the `FIN` is not yet sent.
    pub fin_queued: bool,

    /// Next sequence number expected from the peer.
    pub rcv_nxt: Sequence,
    /// Free space in the program's receive ring, which *is* the window.
    pub rcv_wnd: u16,
    /// The size of that ring, which the window can never exceed.
    pub rcv_capacity: u16,
    /// The peer's initial sequence number.
    pub irs: Sequence,
    /// Whether the peer's `FIN` has been received and acknowledged.
    pub fin_received: bool,

    /// The largest payload this end will send.
    pub mss: u16,

    /// Smoothed round-trip time, microseconds. `None` until one is measured.
    pub srtt_us: Option<u64>,
    /// Round-trip time variation, microseconds.
    pub rttvar_us: u64,
    /// The current retransmission timeout, microseconds.
    pub rto_us: u64,
    /// The sequence number and send time of the segment being timed, if any.
    ///
    /// **Karn's algorithm lives in this field.** It is cleared on
    /// retransmission, so an acknowledgement that could belong to either the
    /// original or the retransmission never updates the estimate — because
    /// nobody can tell which one it acknowledges, and guessing wrong drives the
    /// estimate to a value that guarantees more retransmissions.
    pub timing: Option<(Sequence, u64)>,
    /// Consecutive retransmissions with nothing acknowledged.
    pub retransmits: u8,

    /// Segments received since the last acknowledgement was sent.
    pub since_ack: u8,
}

impl Tcb {
    /// A closed control block for `connection`.
    #[must_use]
    pub const fn new(connection: FourTuple) -> Self {
        Self {
            state: State::Closed,
            connection,
            snd_una: Sequence(0),
            snd_nxt: Sequence(0),
            snd_avail: Sequence(0),
            snd_wnd: 0,
            iss: Sequence(0),
            fin_seq: None,
            fin_queued: false,
            rcv_nxt: Sequence(0),
            rcv_wnd: 0,
            rcv_capacity: 0,
            irs: Sequence(0),
            fin_received: false,
            mss: DEFAULT_MSS,
            srtt_us: None,
            rttvar_us: 0,
            rto_us: INITIAL_RTO_US,
            timing: None,
            retransmits: 0,
            since_ack: 0,
        }
    }

    /// An **established** control block, rebuilt from a verified SYN cookie.
    ///
    /// RFC 0048 step 3. With cookies there is no `SynReceived` state to
    /// advance out of: the handshake's middle is a number the peer carried
    /// back, and the first this stack knows of the connection is the `ACK`
    /// that proves it. So this constructs what the three-way handshake would
    /// have produced, from what the `ACK` and the cookie together establish.
    ///
    /// - `cookie` is the sequence this stack chose and the peer echoed, so
    ///   `snd_una` and `snd_nxt` are one past it — the `SYN` occupied it.
    /// - `irs` is the peer's initial sequence, one below the number its `ACK`
    ///   is at, and `rcv_nxt` is that number.
    /// - `mss` comes out of the cookie rather than the segment, because the
    ///   `ACK` does not carry the option and the cookie is where the `SYN`'s
    ///   announcement was stored. It is the *rounded* value, which is the
    ///   documented cost of three bits.
    ///
    /// **`snd_avail` is `snd_nxt`, not zero.** A control block whose available
    /// sequence sits behind what has been sent claims the whole sequence space
    /// as unsent — the failure `unsent` below documents at length, reached
    /// here by a different road.
    #[must_use]
    pub fn from_cookie(
        connection: FourTuple,
        cookie: Sequence,
        irs: Sequence,
        peer_window: u16,
        capacity: u16,
        mss: u16,
    ) -> Self {
        let iss = cookie;
        let next = iss.wrapping_add(1);
        Self {
            state: State::Established,
            connection,
            snd_una: next,
            snd_nxt: next,
            snd_avail: next,
            snd_wnd: peer_window,
            iss,
            fin_seq: None,
            fin_queued: false,
            rcv_nxt: irs.wrapping_add(1),
            rcv_wnd: capacity,
            rcv_capacity: capacity,
            irs,
            fin_received: false,
            mss,
            srtt_us: None,
            rttvar_us: 0,
            rto_us: INITIAL_RTO_US,
            timing: None,
            retransmits: 0,
            since_ack: 0,
        }
    }

    /// Bytes the program has supplied that have not been sent yet.
    ///
    /// **Zero rather than a wrap** when `snd_avail` is behind `snd_nxt`. On a
    /// circle a subtraction always produces an answer, and the wrong answer
    /// here is four billion — which is what a control block with `snd_avail`
    /// one below `snd_nxt` produced, and what turned the first run of these
    /// tests into a segment claiming the whole sequence space. The ordering
    /// test costs a comparison and makes the failure unreachable rather than
    /// merely fixed.
    #[must_use]
    pub fn unsent(&self) -> u32 {
        if self.snd_avail.follows(self.snd_nxt) {
            self.snd_avail.0.wrapping_sub(self.snd_nxt.0)
        } else {
            0
        }
    }

    /// Bytes sent and not yet acknowledged.
    #[must_use]
    pub fn in_flight(&self) -> u32 {
        if self.snd_nxt.follows(self.snd_una) {
            self.snd_nxt.0.wrapping_sub(self.snd_una.0)
        } else {
            0
        }
    }

    /// Whether anything is outstanding that a retransmission timer should
    /// cover.
    fn awaiting_ack(&self) -> bool {
        self.snd_una != self.snd_nxt
    }
}

/// Drives one event into a control block.
///
/// Returns the new control block and what the caller must do, in order. **The
/// caller must perform the actions in the order given**: a `Closed` after an
/// `Emit` means the segment goes out first, which is how a `RST` reaches the
/// peer at all.
///
/// `now` is monotonic nanoseconds, as everywhere else in this crate.
#[must_use]
pub fn step(mut tcb: Tcb, event: Event<'_>, now: u64) -> (Tcb, Actions) {
    let mut actions = Actions::new();
    match event {
        Event::Connect { iss, window } => open(&mut tcb, &mut actions, iss, window, false, now),
        Event::Listen { iss, window } => open(&mut tcb, &mut actions, iss, window, true, now),
        Event::Wrote(bytes) => {
            tcb.snd_avail = tcb.snd_avail.wrapping_add(bytes);
            send_what_we_can(&mut tcb, &mut actions, now);
        }
        Event::Read(bytes) => reopen_window(&mut tcb, &mut actions, bytes),
        Event::Shutdown => shutdown(&mut tcb, &mut actions, now),
        Event::Abort => abort(&mut tcb, &mut actions),
        Event::Arrived(segment) => arrived(&mut tcb, &mut actions, &segment, now),
        Event::Expired(timer) => expired(&mut tcb, &mut actions, timer, now),
    }
    (tcb, actions)
}

/// `CONNECT` and `LISTEN`, which differ only in whether a `SYN` goes out.
fn open(tcb: &mut Tcb, actions: &mut Actions, iss: Sequence, window: u16, passive: bool, now: u64) {
    if tcb.state != State::Closed {
        return;
    }
    tcb.iss = iss;
    tcb.snd_una = iss;
    tcb.snd_nxt = iss;
    tcb.snd_avail = iss;
    tcb.rcv_wnd = window;
    tcb.rcv_capacity = window;

    if passive {
        tcb.state = State::Listen;
        return;
    }
    tcb.state = State::SynSent;
    // The `SYN` occupies one sequence number, which is why `snd_nxt` moves by
    // one for a segment carrying no data.
    actions.push(Action::Emit(Emit {
        flags: Flags::SYN,
        sequence: tcb.snd_nxt,
        acknowledgement: None,
        window: tcb.rcv_wnd,
        length: 0,
        mss: Some(tcb.mss),
    }));
    tcb.snd_nxt = tcb.snd_nxt.wrapping_add(1);
    // Data starts after the `SYN`, which occupies a sequence number of its own.
    // Leaving this at `iss` puts `snd_avail` one *behind* `snd_nxt`.
    tcb.snd_avail = tcb.snd_nxt;
    start_timing(tcb, now);
    arm_retransmit(tcb, actions, now);
}

/// The program consumed bytes, so the window opens by that much.
fn reopen_window(tcb: &mut Tcb, actions: &mut Actions, bytes: u32) {
    let opened = u32::from(tcb.rcv_wnd).saturating_add(bytes);
    let capped = u32::from(tcb.rcv_capacity).min(opened);
    let was = tcb.rcv_wnd;
    // The invariant the fuzz target checks: the advertised window is the free
    // space in the program's ring and can never exceed the ring.
    tcb.rcv_wnd = u16::try_from(capped).unwrap_or(tcb.rcv_capacity);

    // A window that has just gone from nothing to something must be advertised
    // immediately. Waiting for the delayed-acknowledgement timer would leave a
    // peer that is blocked on a zero window stalled for no reason, and the peer
    // has no way to ask.
    if was == 0 && tcb.rcv_wnd > 0 && tcb.state.can_receive() {
        acknowledge_now(tcb, actions);
    }
}

/// The program will send no more.
fn shutdown(tcb: &mut Tcb, actions: &mut Actions, now: u64) {
    match tcb.state {
        State::Established | State::CloseWait | State::SynReceived => {
            tcb.fin_queued = true;
            send_what_we_can(tcb, actions, now);
        }
        // Nothing was ever established, so there is nothing to close down
        // politely.
        State::Listen | State::SynSent => {
            tcb.state = State::Closed;
            actions.push(Action::Closed(Ended::Aborted));
        }
        _ => {}
    }
}

/// The program gave up, or its address space went away.
fn abort(tcb: &mut Tcb, actions: &mut Actions) {
    if matches!(tcb.state, State::Closed | State::Listen) {
        tcb.state = State::Closed;
        actions.push(Action::Closed(Ended::Aborted));
        return;
    }
    actions.push(Action::Emit(Emit {
        flags: Flags::RST,
        sequence: tcb.snd_nxt,
        acknowledgement: None,
        window: 0,
        length: 0,
        mss: None,
    }));
    tcb.state = State::Closed;
    actions.push(Action::Closed(Ended::Aborted));
}

/// A timer expired.
fn expired(tcb: &mut Tcb, actions: &mut Actions, timer: Timer, now: u64) {
    match timer {
        Timer::Retransmit => retransmit(tcb, actions, now),
        Timer::DelayedAck => {
            if tcb.state != State::Closed {
                acknowledge_now(tcb, actions);
            }
        }
        Timer::Probe => probe(tcb, actions, now),
        Timer::TimeWait => {
            if tcb.state == State::TimeWait {
                tcb.state = State::Closed;
                actions.push(Action::Closed(Ended::Orderly));
            }
        }
    }
}

/// Nothing was acknowledged in time.
fn retransmit(tcb: &mut Tcb, actions: &mut Actions, now: u64) {
    if tcb.state == State::Closed || !tcb.awaiting_ack() {
        return;
    }
    // A half-open connection is given less patience than an established one,
    // and the reason is whose it is: until the handshake completes, the slot
    // is held on the word of one packet. See [`MAX_SYNACK_RETRANSMITS`].
    let limit = if tcb.state == State::SynReceived {
        MAX_SYNACK_RETRANSMITS
    } else {
        MAX_RETRANSMITS
    };
    if tcb.retransmits >= limit {
        tcb.state = State::Closed;
        actions.push(Action::Closed(Ended::Unreachable));
        return;
    }
    tcb.retransmits += 1;
    // Exponential backoff, and **Karn's algorithm**: the measurement in flight
    // is abandoned, because an acknowledgement arriving now could be for either
    // transmission and there is no way to tell which.
    tcb.rto_us = tcb.rto_us.saturating_mul(2).min(MAX_RTO_US);
    tcb.timing = None;

    // Go back to the first unacknowledged byte and send from there. There is no
    // record of what was in which segment — that is what a reassembly queue and
    // a retransmission queue are for, and RFC 0020 has neither.
    tcb.snd_nxt = tcb.snd_una;
    resend(tcb, actions);
    arm_retransmit(tcb, actions, now);
}

/// Sends the first unacknowledged thing again, whatever it was.
fn resend(tcb: &mut Tcb, actions: &mut Actions) {
    match tcb.state {
        State::SynSent => {
            actions.push(Action::Emit(Emit {
                flags: Flags::SYN,
                sequence: tcb.snd_una,
                acknowledgement: None,
                window: tcb.rcv_wnd,
                length: 0,
                mss: Some(tcb.mss),
            }));
            tcb.snd_nxt = tcb.snd_una.wrapping_add(1);
        }
        State::SynReceived => {
            actions.push(Action::Emit(Emit {
                flags: Flags::SYN,
                sequence: tcb.snd_una,
                acknowledgement: Some(tcb.rcv_nxt),
                window: tcb.rcv_wnd,
                length: 0,
                mss: Some(tcb.mss),
            }));
            tcb.snd_nxt = tcb.snd_una.wrapping_add(1);
        }
        _ => {
            // Data first, from the oldest unacknowledged byte. `send_segment`
            // works out how much, so there is one place that decides what a
            // segment contains.
            send_segment(tcb, actions, true);

            // Then this end's `FIN`, if everything before it has just been put
            // back on the wire. `send_segment` will not do this itself, because
            // `fin_seq` is already set — a `FIN` is assigned its sequence number
            // once and keeps it, or the peer sees two different closes.
            //
            // With more than one segment of data outstanding this does nothing
            // until the data ahead of the `FIN` is acknowledged, which is the
            // ordinary go-back-N behaviour and not a special case.
            if let Some(fin) = tcb.fin_seq
                && !tcb.snd_una.follows(fin)
                && tcb.snd_nxt == fin
            {
                actions.push(Action::Emit(Emit {
                    flags: Flags::FIN,
                    sequence: fin,
                    acknowledgement: Some(tcb.rcv_nxt),
                    window: tcb.rcv_wnd,
                    length: 0,
                    mss: None,
                }));
                tcb.snd_nxt = fin.wrapping_add(1);
            }
        }
    }
}

/// The peer's window is closed and something is waiting for it to open.
fn probe(tcb: &mut Tcb, actions: &mut Actions, now: u64) {
    if !tcb.state.can_send() || tcb.snd_wnd != 0 || tcb.unsent() == 0 {
        return;
    }
    // One byte past the window, deliberately. A probe that respected the window
    // would send nothing, and the peer would never be prompted for the window
    // update whose loss is the deadlock this exists to break.
    actions.push(Action::Emit(Emit {
        flags: Flags::PSH,
        sequence: tcb.snd_nxt,
        acknowledgement: Some(tcb.rcv_nxt),
        window: tcb.rcv_wnd,
        length: 1,
        mss: None,
    }));
    tcb.snd_nxt = tcb.snd_nxt.wrapping_add(1);
    arm_probe(tcb, actions, now);
    arm_retransmit(tcb, actions, now);
}

/// Sends as much as the window, the data available and the segment size allow.
fn send_what_we_can(tcb: &mut Tcb, actions: &mut Actions, now: u64) {
    if !tcb.state.can_send() && tcb.state != State::SynReceived {
        return;
    }
    let mut sent_any = false;
    // Bounded by the action list rather than by the data, so one call cannot
    // fill the list and lose the timer arming that has to follow it.
    for _ in 0..2 {
        if !send_segment(tcb, actions, false) {
            break;
        }
        sent_any = true;
    }

    if tcb.snd_wnd == 0 && tcb.unsent() > 0 {
        arm_probe(tcb, actions, now);
    }
    if sent_any {
        if tcb.timing.is_none() {
            start_timing(tcb, now);
        }
        arm_retransmit(tcb, actions, now);
    }
}

/// Builds one segment of data, a `FIN`, or both. Returns whether it sent
/// anything.
fn send_segment(tcb: &mut Tcb, actions: &mut Actions, retransmission: bool) -> bool {
    // How far the peer's window reaches beyond what it has acknowledged.
    let window_end = tcb.snd_una.wrapping_add(u32::from(tcb.snd_wnd));
    let allowed = if window_end.follows(tcb.snd_nxt) {
        window_end.0.wrapping_sub(tcb.snd_nxt.0)
    } else {
        0
    };
    let available = tcb.unsent();
    let length = available.min(allowed).min(u32::from(tcb.mss));
    let length = u16::try_from(length).unwrap_or(u16::MAX);

    // The `FIN` rides along only when everything before it is in this segment,
    // because it must be the last sequence number this end ever sends.
    let fin_now = tcb.fin_queued
        && tcb.fin_seq.is_none()
        && u32::from(length) == available
        && (retransmission || allowed >= available);

    if length == 0 && !fin_now {
        return false;
    }

    let mut flags = Flags::default();
    if length > 0 {
        flags = flags.with(Flags::PSH);
    }
    let sequence = tcb.snd_nxt;
    if fin_now {
        flags = flags.with(Flags::FIN);
    }
    actions.push(Action::Emit(Emit {
        flags,
        sequence,
        acknowledgement: Some(tcb.rcv_nxt),
        window: tcb.rcv_wnd,
        length,
        mss: None,
    }));
    tcb.since_ack = 0;

    tcb.snd_nxt = tcb.snd_nxt.wrapping_add(u32::from(length));
    if fin_now {
        tcb.fin_seq = Some(tcb.snd_nxt);
        tcb.snd_nxt = tcb.snd_nxt.wrapping_add(1);
        advance_close_state(tcb);
    }
    true
}

/// Moves the state on once this end's `FIN` has been sent.
fn advance_close_state(tcb: &mut Tcb) {
    tcb.state = match tcb.state {
        State::Established | State::SynReceived => State::FinWait1,
        State::CloseWait => State::LastAck,
        other => other,
    };
}

/// Sends an acknowledgement immediately and cancels any owed one.
fn acknowledge_now(tcb: &mut Tcb, actions: &mut Actions) {
    actions.push(Action::Emit(Emit {
        flags: Flags::default(),
        sequence: tcb.snd_nxt,
        acknowledgement: Some(tcb.rcv_nxt),
        window: tcb.rcv_wnd,
        length: 0,
        mss: None,
    }));
    tcb.since_ack = 0;
    actions.push(Action::Cancel(Timer::DelayedAck));
}

/// Starts a round-trip measurement of whatever was just sent.
///
/// The sequence recorded is the **last byte** of that segment, not the next one
/// to send, so that [`finish_timing`]'s "does this acknowledgement cover it"
/// test is `ack > last`. Recording `snd_nxt` instead makes the test `ack >
/// snd_nxt`, which the acknowledgement for that very segment does not satisfy —
/// and the measurement then never completes, leaving the retransmission timeout
/// at its initial value for the life of the connection.
fn start_timing(tcb: &mut Tcb, now: u64) {
    tcb.timing = Some((tcb.snd_nxt.wrapping_add(u32::MAX), now));
}

/// Arms the retransmission timer, or cancels it if nothing is outstanding.
fn arm_retransmit(tcb: &Tcb, actions: &mut Actions, now: u64) {
    if tcb.awaiting_ack() {
        actions.push(Action::Arm {
            timer: Timer::Retransmit,
            at: now.saturating_add(tcb.rto_us.saturating_mul(1_000)),
        });
    } else {
        actions.push(Action::Cancel(Timer::Retransmit));
    }
}

/// Arms the zero-window probe.
fn arm_probe(tcb: &Tcb, actions: &mut Actions, now: u64) {
    actions.push(Action::Arm {
        timer: Timer::Probe,
        at: now.saturating_add(tcb.rto_us.saturating_mul(1_000)),
    });
}

/// Folds a round-trip sample into the estimate, by Jacobson and Karels.
fn measure(tcb: &mut Tcb, sample_us: u64) {
    match tcb.srtt_us {
        None => {
            // RFC 6298: the first measurement seeds both directly rather than
            // being smoothed against a value that does not exist yet.
            tcb.srtt_us = Some(sample_us);
            tcb.rttvar_us = sample_us / 2;
        }
        Some(srtt) => {
            let difference = srtt.abs_diff(sample_us);
            tcb.rttvar_us = (tcb.rttvar_us * 3 + difference) / 4;
            tcb.srtt_us = Some((srtt * 7 + sample_us) / 8);
        }
    }
    let srtt = tcb.srtt_us.unwrap_or(sample_us);
    tcb.rto_us = srtt
        .saturating_add(tcb.rttvar_us.saturating_mul(4))
        .clamp(MIN_RTO_US, MAX_RTO_US);
}

/// A segment arrived.
fn arrived(tcb: &mut Tcb, actions: &mut Actions, segment: &Segment<'_>, now: u64) {
    match tcb.state {
        State::Closed => closed_arrival(actions, segment),
        State::Listen => listen_arrival(tcb, actions, segment, now),
        State::SynSent => syn_sent_arrival(tcb, actions, segment, now),
        _ => synchronised_arrival(tcb, actions, segment, now),
    }
}

/// The `SYN·ACK` for an incoming `SYN`, built **without a control block**.
///
/// RFC 0048 step 3: with SYN cookies there is no connection yet when this reply
/// goes out — that is the whole point. The initial sequence number *is* the
/// cookie, and the peer proves it received this segment by echoing
/// `cookie + 1` in its `ACK`. Nothing is allocated until then, so a `SYN` from
/// a peer that never answers costs this stack one reply and no state at all.
///
/// The shape mirrors [`reset_for`], and for the same reason: the arithmetic
/// belongs in this crate, which is fuzzed and `forbid`s `unsafe`, while
/// `bin/tcpd` owns only the tuple swap and the ring.
///
/// `None` for anything that is not a bare connection request — a segment
/// carrying `RST`, or one that already acknowledges something, is not a `SYN`
/// this can answer.
///
/// The `ACK` flag is not set here. `segment::write` derives it from whether an
/// acknowledgement is present, and setting it as well would be two sources for
/// one bit — the note `reset_for` makes, meant the same way.
#[must_use]
pub fn synack_for(segment: &Segment<'_>, cookie: Sequence, window: u16, mss: u16) -> Option<Emit> {
    if !segment.flags.contains(Flags::SYN)
        || segment.flags.contains(Flags::RST)
        || segment.acknowledgement.is_some()
    {
        return None;
    }
    Some(Emit {
        flags: Flags::SYN,
        sequence: cookie,
        // The peer's `SYN` occupies one number, so this acknowledges it and
        // nothing else. `sequence_length` is deliberately *not* used: a bare
        // `SYN` carries no payload, and a `SYN` that carried one would be
        // acknowledged for data this stack has not accepted.
        acknowledgement: Some(segment.sequence.wrapping_add(1)),
        window,
        length: 0,
        mss: Some(mss),
    })
}

/// The `RST` that answers a segment naming no connection here, or `None` when
/// there is nothing to say.
///
/// RFC 793 §3.4: a segment arriving for a connection that does not exist is
/// answered with a reset, so the peer stops rather than retransmitting into a
/// hole for the whole of its own connect timeout. A segment that already
/// carries `RST` is answered with silence, or two stacks with nothing in
/// common reset each other for ever.
///
/// Public, and pure, because this refusal is owed in two places that share no
/// control block: [`closed_arrival`] below, where a machine in
/// [`State::Closed`] has one, and `bin/tcpd`'s dispatcher, where a `SYN` for a
/// port no listener holds has none and never will have one. One
/// implementation is what stops those two drifting -- and the second caller is
/// why this is a function rather than four lines inlined where they were.
#[must_use]
pub fn reset_for(segment: &Segment<'_>) -> Option<Emit> {
    if segment.flags.contains(Flags::RST) {
        return None;
    }
    // RFC 793 §3.4's two shapes, and they differ in more than a field. A
    // segment that acknowledged something is answered *at the number it
    // acknowledged* and acknowledges nothing back. One that acknowledged
    // nothing -- a bare `SYN` -- is answered at zero and acknowledges
    // everything the segment occupied, the `SYN`'s own number included, which
    // is exactly what `sequence_length` counts and why it is used here rather
    // than the payload length.
    //
    // The `ACK` flag itself is not set here: `segment::write` derives it from
    // whether an acknowledgement is present, so setting it as well would be
    // two sources for one bit.
    let (sequence, acknowledgement) = match segment.acknowledgement {
        Some(ack) => (ack, None),
        None => (
            Sequence(0),
            Some(segment.sequence.wrapping_add(segment.sequence_length())),
        ),
    };
    Some(Emit {
        flags: Flags::RST,
        sequence,
        acknowledgement,
        window: 0,
        length: 0,
        mss: None,
    })
}

/// Nothing here to receive it. RFC 793 §3.4, through [`reset_for`].
fn closed_arrival(actions: &mut Actions, segment: &Segment<'_>) {
    if let Some(emit) = reset_for(segment) {
        actions.push(Action::Emit(emit));
    }
}

/// Waiting for anyone. Only a `SYN` is interesting.
fn listen_arrival(tcb: &mut Tcb, actions: &mut Actions, segment: &Segment<'_>, now: u64) {
    if segment.flags.contains(Flags::RST) {
        return;
    }
    // An `ACK` in `LISTEN` names a connection that does not exist here.
    if segment.acknowledgement.is_some() {
        closed_arrival(actions, segment);
        return;
    }
    if !segment.flags.contains(Flags::SYN) {
        return;
    }

    tcb.irs = segment.sequence;
    tcb.rcv_nxt = segment.sequence.wrapping_add(1);
    tcb.snd_wnd = segment.window;
    tcb.mss = segment
        .options
        .mss
        .map_or(tcb.mss, |mss| mss.min(DEFAULT_MSS));
    tcb.state = State::SynReceived;

    actions.push(Action::Emit(Emit {
        flags: Flags::SYN,
        sequence: tcb.iss,
        acknowledgement: Some(tcb.rcv_nxt),
        window: tcb.rcv_wnd,
        length: 0,
        mss: Some(tcb.mss),
    }));
    tcb.snd_nxt = tcb.iss.wrapping_add(1);
    tcb.snd_avail = tcb.snd_nxt;
    start_timing(tcb, now);
    arm_retransmit(tcb, actions, now);
}

/// A connection request has gone out. RFC 793 §3.9's `SYN-SENT` arm.
fn syn_sent_arrival(tcb: &mut Tcb, actions: &mut Actions, segment: &Segment<'_>, now: u64) {
    // An acknowledgement that does not name this end's `SYN` is talking about
    // some other connection.
    if let Some(ack) = segment.acknowledgement
        && (!ack.follows(tcb.iss) || ack.follows(tcb.snd_nxt))
    {
        if !segment.flags.contains(Flags::RST) {
            actions.push(Action::Emit(Emit {
                flags: Flags::RST,
                sequence: ack,
                acknowledgement: None,
                window: 0,
                length: 0,
                mss: None,
            }));
        }
        return;
    }

    if segment.flags.contains(Flags::RST) {
        // Only believable behind an acknowledgement here, which the check above
        // has already validated. Without that, anyone who can guess the port
        // pair refuses connections for free.
        if segment.acknowledgement.is_some() {
            tcb.state = State::Closed;
            actions.push(Action::Closed(Ended::Refused));
        }
        return;
    }

    if !segment.flags.contains(Flags::SYN) {
        return;
    }

    tcb.irs = segment.sequence;
    tcb.rcv_nxt = segment.sequence.wrapping_add(1);
    tcb.snd_wnd = segment.window;
    tcb.mss = segment
        .options
        .mss
        .map_or(tcb.mss, |mss| mss.min(DEFAULT_MSS));
    if let Some(ack) = segment.acknowledgement {
        tcb.snd_una = ack;
    }

    if tcb.snd_una.follows(tcb.iss) {
        // The `SYN` was acknowledged: the connection is open.
        tcb.state = State::Established;
        finish_timing(tcb, tcb.snd_una, now);
        acknowledge_now(tcb, actions);
        arm_retransmit(tcb, actions, now);
        send_what_we_can(tcb, actions, now);
    } else {
        // **Simultaneous open**: both ends sent a `SYN` and neither has seen
        // the other's acknowledged. Answer with `SYN, ACK` and wait.
        tcb.state = State::SynReceived;
        tcb.snd_nxt = tcb.iss;
        actions.push(Action::Emit(Emit {
            flags: Flags::SYN,
            sequence: tcb.iss,
            acknowledgement: Some(tcb.rcv_nxt),
            window: tcb.rcv_wnd,
            length: 0,
            mss: Some(tcb.mss),
        }));
        tcb.snd_nxt = tcb.iss.wrapping_add(1);
        arm_retransmit(tcb, actions, now);
    }
}

/// Whether a segment falls inside the receive window.
///
/// RFC 793 §3.3's four cases, which differ by whether the segment occupies any
/// sequence space and whether the window is open. Written out rather than
/// collapsed, because the zero-length and zero-window cases are the ones every
/// simplification gets wrong.
fn acceptable(tcb: &Tcb, segment: &Segment<'_>) -> bool {
    let length = segment.sequence_length();
    let window_end = tcb.rcv_nxt.wrapping_add(u32::from(tcb.rcv_wnd));
    let in_window =
        |sequence: Sequence| !sequence.precedes(tcb.rcv_nxt) && sequence.precedes(window_end);
    match (length, tcb.rcv_wnd) {
        (0, 0) => segment.sequence == tcb.rcv_nxt,
        (0, _) => in_window(segment.sequence),
        (_, 0) => false,
        (_, _) => {
            in_window(segment.sequence)
                || in_window(segment.sequence.wrapping_add(length.saturating_sub(1)))
        }
    }
}

/// Every state from `SYN-RECEIVED` onwards, which share RFC 793 §3.9's order of
/// checks: sequence, `RST`, `SYN`, `ACK`, data, `FIN`.
fn synchronised_arrival(tcb: &mut Tcb, actions: &mut Actions, segment: &Segment<'_>, now: u64) {
    let is_acceptable = acceptable(tcb, segment);

    if !is_acceptable {
        if segment.flags.contains(Flags::RST) {
            // An unacceptable `RST` is the off-path attacker's segment, and
            // dropping it silently is the whole defence.
            return;
        }
        // **An old duplicate is acknowledged; a future segment is not.**
        //
        // RFC 0020 says an out-of-order segment is "discarded and not
        // acknowledged, so the peer retransmits" — which is right for a segment
        // *ahead* of what is expected, and wrong for one *behind* it. A segment
        // behind means the peer never saw the acknowledgement for data already
        // taken; staying quiet leaves it retransmitting until it abandons a
        // connection that is working. So the two cases are separated here, and
        // the sentence in the RFC covers only the first.
        if segment.sequence.precedes(tcb.rcv_nxt) {
            acknowledge_now(tcb, actions);
        }
        return;
    }

    if segment.flags.contains(Flags::RST) {
        let ended = if tcb.state == State::SynReceived {
            Ended::Refused
        } else {
            Ended::Reset
        };
        tcb.state = State::Closed;
        actions.push(Action::Closed(ended));
        return;
    }

    // A `SYN` inside the window on a synchronised connection is an error, and
    // RFC 793 says to reset. It cannot be a legitimate retransmission, because
    // a retransmitted `SYN` carries a sequence number one *below* `rcv_nxt` and
    // was handled as an old duplicate above.
    if segment.flags.contains(Flags::SYN) && segment.sequence != tcb.irs {
        abort(tcb, actions);
        return;
    }

    let Some(ack) = segment.acknowledgement else {
        // Everything past `SYN-RECEIVED` must acknowledge something.
        return;
    };

    if !process_ack(tcb, actions, segment, ack, now) {
        return;
    }

    // Data, then the `FIN` behind it, and only when they are the next thing
    // expected — there is no reassembly queue, by design.
    let delivered = deliver(tcb, actions, segment);
    // **The `FIN` is only reached if every byte in front of it was taken.**
    // A payload larger than the window is accepted in part, and the `FIN` then
    // sits beyond what was accepted — believing it would close the connection
    // with data still outstanding, and the peer would retransmit into a stream
    // this end had already ended.
    let whole_payload = usize::from(delivered) == segment.payload.len();
    let fin = segment.flags.contains(Flags::FIN)
        && whole_payload
        && segment.sequence.wrapping_add(u32::from(delivered)) == tcb.rcv_nxt;

    if fin && !tcb.fin_received {
        tcb.fin_received = true;
        tcb.rcv_nxt = tcb.rcv_nxt.wrapping_add(1);
        peer_closed(tcb, actions, now);
    } else if delivered > 0 {
        acknowledge_or_delay(tcb, actions, now);
    }

    send_what_we_can(tcb, actions, now);
}

/// Handles the acknowledgement field. Returns whether processing continues.
fn process_ack(
    tcb: &mut Tcb,
    actions: &mut Actions,
    segment: &Segment<'_>,
    ack: Sequence,
    now: u64,
) -> bool {
    if ack.follows(tcb.snd_nxt) {
        // Acknowledging something never sent. RFC 793 says acknowledge and drop
        // rather than reset, because a reset here is remotely triggerable.
        acknowledge_now(tcb, actions);
        return false;
    }

    if tcb.state == State::SynReceived {
        if ack.follows(tcb.iss) {
            tcb.state = State::Established;
            tcb.snd_una = ack;
            finish_timing(tcb, ack, now);
            // The `SYN` is no longer outstanding, so the timer covering it must
            // go. Without this the handshake completes with a retransmission
            // armed for a segment nobody is waiting for, and it fires into an
            // established connection.
            arm_retransmit(tcb, actions, now);
        } else {
            return false;
        }
    }

    if ack.follows(tcb.snd_una) {
        let freed = ack.0.wrapping_sub(tcb.snd_una.0);
        // The `FIN` occupies a sequence number and is not a byte of the
        // program's ring, so it must not be reported as space freed.
        let fin_included = tcb
            .fin_seq
            .is_some_and(|fin| !fin.precedes(tcb.snd_una) && fin.precedes(ack));
        let bytes = freed.saturating_sub(u32::from(fin_included));

        tcb.snd_una = ack;
        tcb.retransmits = 0;
        if bytes > 0 {
            actions.push(Action::Acknowledged(bytes));
        }
        finish_timing(tcb, ack, now);
        arm_retransmit(tcb, actions, now);
        advance_after_ack(tcb, actions, now);
    }

    // The peer's window, and the update that reopens a closed one.
    let was_closed = tcb.snd_wnd == 0;
    tcb.snd_wnd = segment.window;
    if was_closed && tcb.snd_wnd > 0 {
        actions.push(Action::Cancel(Timer::Probe));
    }
    true
}

/// Moves the state on when the peer's acknowledgement covers this end's `FIN`.
fn advance_after_ack(tcb: &mut Tcb, actions: &mut Actions, now: u64) {
    let fin_acked = tcb.fin_seq.is_some_and(|fin| tcb.snd_una.follows(fin));
    if !fin_acked {
        return;
    }
    match tcb.state {
        State::FinWait1 => tcb.state = State::FinWait2,
        State::Closing => enter_time_wait(tcb, actions, now),
        State::LastAck => {
            tcb.state = State::Closed;
            actions.push(Action::Closed(Ended::Orderly));
        }
        _ => {}
    }
}

/// Takes the payload if it is exactly what was expected. Returns how much.
fn deliver(tcb: &mut Tcb, actions: &mut Actions, segment: &Segment<'_>) -> u16 {
    if !tcb.state.can_receive() || segment.payload.is_empty() {
        return 0;
    }
    // The one place "no reassembly queue" is implemented: anything that does
    // not start exactly where the stream left off is not taken. A segment that
    // partially overlaps is not trimmed either — the peer will send it again.
    if segment.sequence != tcb.rcv_nxt {
        return 0;
    }
    let length = u16::try_from(segment.payload.len()).unwrap_or(u16::MAX);
    let taken = length.min(tcb.rcv_wnd);
    if taken == 0 {
        return 0;
    }
    tcb.rcv_nxt = tcb.rcv_nxt.wrapping_add(u32::from(taken));
    tcb.rcv_wnd -= taken;
    actions.push(Action::Delivered(u32::from(taken)));
    taken
}

/// Acknowledges now or arms the delay, by RFC 1122 §4.2.3.2.
fn acknowledge_or_delay(tcb: &mut Tcb, actions: &mut Actions, now: u64) {
    tcb.since_ack = tcb.since_ack.saturating_add(1);
    // Every second segment gets an immediate acknowledgement; so does a window
    // that has just closed, because a peer waiting on a window update cannot
    // afford the delay.
    if tcb.since_ack >= 2 || tcb.rcv_wnd == 0 {
        acknowledge_now(tcb, actions);
    } else {
        actions.push(Action::Arm {
            timer: Timer::DelayedAck,
            at: now.saturating_add(DELAYED_ACK_US.saturating_mul(1_000)),
        });
    }
}

/// The peer's `FIN` arrived and was accepted.
fn peer_closed(tcb: &mut Tcb, actions: &mut Actions, now: u64) {
    acknowledge_now(tcb, actions);
    match tcb.state {
        State::Established | State::SynReceived => tcb.state = State::CloseWait,
        // **A `FIN` crossing a `FIN`.** This end closed first and the peer
        // closed before seeing it, so neither close is acknowledged yet.
        State::FinWait1 => tcb.state = State::Closing,
        State::FinWait2 => enter_time_wait(tcb, actions, now),
        _ => {}
    }
}

/// Enters `TIME_WAIT` and arms the 2×MSL deadline.
fn enter_time_wait(tcb: &mut Tcb, actions: &mut Actions, now: u64) {
    tcb.state = State::TimeWait;
    actions.push(Action::Cancel(Timer::Retransmit));
    actions.push(Action::Arm {
        timer: Timer::TimeWait,
        at: now.saturating_add(MSL_US.saturating_mul(2_000)),
    });
}

/// Completes a round-trip measurement if this acknowledgement covers it.
fn finish_timing(tcb: &mut Tcb, ack: Sequence, now: u64) {
    let Some((sequence, sent_at)) = tcb.timing else {
        return;
    };
    if !ack.follows(sequence) {
        return;
    }
    tcb.timing = None;
    // Nanoseconds in, microseconds out — the estimate's unit, and the one the
    // constants above are written in.
    let sample_us = now.saturating_sub(sent_at) / 1_000;
    measure(tcb, sample_us);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addr::{Address, Ipv4Addr, Port};

    const HERE: Address = Address::V4(Ipv4Addr::new(10, 0, 2, 15));
    const THERE: Address = Address::V4(Ipv4Addr::new(10, 0, 2, 2));

    /// This end's initial sequence number in every test below.
    const ISS: Sequence = Sequence(1000);
    /// The peer's.
    const IRS: Sequence = Sequence(5000);
    /// The program's receive ring.
    const RING: u16 = 4096;
    /// What the peer advertises unless a test says otherwise.
    const PEER_WINDOW: u16 = 8192;

    fn connection() -> FourTuple {
        FourTuple {
            local: HERE,
            local_port: Port(49152),
            remote: THERE,
            remote_port: Port(80),
        }
    }

    /// A segment from the peer.
    fn from_peer<'a>(
        sequence: u32,
        acknowledgement: Option<u32>,
        flags: Flags,
        window: u16,
        payload: &'a [u8],
    ) -> Segment<'a> {
        Segment {
            source: Port(80),
            destination: Port(49152),
            sequence: Sequence(sequence),
            acknowledgement: acknowledgement.map(Sequence),
            flags,
            window,
            options: Options::default(),
            payload,
        }
    }

    /// A connection, a virtual clock, and the timer table `bin/tcpd` will keep.
    ///
    /// **This is the simulated peer RFC 0020 asked for**, and it is thirty lines
    /// because the state machine takes its time as an argument. Nothing here
    /// sleeps, nothing is flaky, and a two-minute `TIME_WAIT` costs one
    /// addition.
    struct Link {
        tcb: Tcb,
        now: u64,
        timers: [Option<u64>; 4],
        sent: Vec<Emit>,
        delivered: Vec<u32>,
        acknowledged: Vec<u32>,
        ended: Option<Ended>,
    }

    fn slot(timer: Timer) -> usize {
        match timer {
            Timer::Retransmit => 0,
            Timer::DelayedAck => 1,
            Timer::Probe => 2,
            Timer::TimeWait => 3,
        }
    }

    impl Link {
        fn new() -> Self {
            Self {
                tcb: Tcb::new(connection()),
                now: 0,
                timers: [None; 4],
                sent: Vec::new(),
                delivered: Vec::new(),
                acknowledged: Vec::new(),
                ended: None,
            }
        }

        /// Drives one event and returns what went on the wire because of it.
        fn drive(&mut self, event: Event<'_>) -> Vec<Emit> {
            self.sent.clear();
            let (tcb, actions) = step(self.tcb, event, self.now);
            self.tcb = tcb;
            assert!(!actions.overflowed(), "the action list overflowed");
            for action in actions.iter() {
                match action {
                    Action::Emit(emit) => self.sent.push(emit),
                    Action::Arm { timer, at } => self.timers[slot(timer)] = Some(at),
                    Action::Cancel(timer) => self.timers[slot(timer)] = None,
                    Action::Delivered(bytes) => self.delivered.push(bytes),
                    Action::Acknowledged(bytes) => self.acknowledged.push(bytes),
                    Action::Closed(ended) => self.ended = Some(ended),
                }
            }
            self.sent.clone()
        }

        fn armed(&self, timer: Timer) -> Option<u64> {
            self.timers[slot(timer)]
        }

        /// Moves the clock to the earliest armed deadline and fires it.
        fn fire_earliest(&mut self) -> Timer {
            let (index, at) = self
                .timers
                .iter()
                .enumerate()
                .filter_map(|(index, at)| at.map(|at| (index, at)))
                .min_by_key(|(_, at)| *at)
                .expect("a timer to fire");
            let timer = [
                Timer::Retransmit,
                Timer::DelayedAck,
                Timer::Probe,
                Timer::TimeWait,
            ][index];
            self.now = at;
            self.timers[index] = None;
            self.drive(Event::Expired(timer));
            timer
        }

        /// An established connection, opened actively, with a measured
        /// round trip of exactly 100 ms.
        fn established() -> Self {
            let mut link = Self::new();
            link.drive(Event::Connect {
                iss: ISS,
                window: RING,
            });
            link.now = 100_000_000;
            link.drive(Event::Arrived(from_peer(
                IRS.0,
                Some(ISS.0 + 1),
                Flags::SYN,
                PEER_WINDOW,
                &[],
            )));
            assert_eq!(link.tcb.state, State::Established);
            link
        }
    }

    // ---- the handshake ------------------------------------------------

    #[test]
    fn an_active_open_sends_a_syn_and_waits() {
        let mut link = Link::new();
        let sent = link.drive(Event::Connect {
            iss: ISS,
            window: RING,
        });
        assert_eq!(link.tcb.state, State::SynSent);
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].flags, Flags::SYN);
        assert_eq!(sent[0].sequence, ISS);
        assert_eq!(sent[0].acknowledgement, None, "nothing to acknowledge yet");
        assert_eq!(sent[0].window, RING);
        assert_eq!(sent[0].mss, Some(DEFAULT_MSS));
        // The SYN occupies one number, which is why a segment with no data
        // still moves `snd_nxt`.
        assert_eq!(link.tcb.snd_nxt, ISS.wrapping_add(1));
        assert!(link.armed(Timer::Retransmit).is_some());
    }

    #[test]
    fn a_syn_ack_establishes_the_connection_and_is_acknowledged() {
        let mut link = Link::new();
        link.drive(Event::Connect {
            iss: ISS,
            window: RING,
        });
        let sent = link.drive(Event::Arrived(from_peer(
            IRS.0,
            Some(ISS.0 + 1),
            Flags::SYN,
            PEER_WINDOW,
            &[],
        )));
        assert_eq!(link.tcb.state, State::Established);
        assert_eq!(
            link.tcb.rcv_nxt,
            IRS.wrapping_add(1),
            "the peer's SYN counts"
        );
        assert_eq!(link.tcb.snd_una, ISS.wrapping_add(1));
        assert_eq!(link.tcb.snd_wnd, PEER_WINDOW);
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].flags, Flags::default(), "a bare acknowledgement");
        assert_eq!(sent[0].acknowledgement, Some(IRS.wrapping_add(1)));
        assert_eq!(
            link.armed(Timer::Retransmit),
            None,
            "nothing is outstanding, so nothing is timed"
        );
    }

    #[test]
    fn a_passive_open_answers_a_syn_and_completes_on_the_ack() {
        let mut link = Link::new();
        link.drive(Event::Listen {
            iss: ISS,
            window: RING,
        });
        assert_eq!(link.tcb.state, State::Listen);

        let sent = link.drive(Event::Arrived(from_peer(
            IRS.0,
            None,
            Flags::SYN,
            PEER_WINDOW,
            &[],
        )));
        assert_eq!(link.tcb.state, State::SynReceived);
        assert_eq!(sent.len(), 1);
        assert!(sent[0].flags.contains(Flags::SYN));
        assert_eq!(sent[0].acknowledgement, Some(IRS.wrapping_add(1)));

        let sent = link.drive(Event::Arrived(from_peer(
            IRS.0 + 1,
            Some(ISS.0 + 1),
            Flags::default(),
            PEER_WINDOW,
            &[],
        )));
        assert_eq!(link.tcb.state, State::Established);
        assert!(sent.is_empty(), "a bare ACK is not answered with an ACK");
        assert_eq!(link.armed(Timer::Retransmit), None);
    }

    #[test]
    fn a_simultaneous_open_reaches_established_from_both_sides() {
        // Both ends sent a SYN and neither has seen the other's acknowledged.
        // The state that catches it is SYN-RECEIVED reached from SYN-SENT,
        // which no ordinary connection ever visits.
        let mut link = Link::new();
        link.drive(Event::Connect {
            iss: ISS,
            window: RING,
        });
        let sent = link.drive(Event::Arrived(from_peer(
            IRS.0,
            None,
            Flags::SYN,
            PEER_WINDOW,
            &[],
        )));
        assert_eq!(link.tcb.state, State::SynReceived);
        assert_eq!(sent.len(), 1);
        assert!(sent[0].flags.contains(Flags::SYN));
        assert_eq!(sent[0].acknowledgement, Some(IRS.wrapping_add(1)));
        assert_eq!(sent[0].sequence, ISS, "the same SYN, not a new one");

        link.drive(Event::Arrived(from_peer(
            IRS.0 + 1,
            Some(ISS.0 + 1),
            Flags::default(),
            PEER_WINDOW,
            &[],
        )));
        assert_eq!(link.tcb.state, State::Established);
    }

    #[test]
    fn an_acknowledgement_of_a_syn_never_sent_is_reset_and_ignored() {
        // The off-path segment. Believing it would let anyone who can guess a
        // port pair complete a handshake this end never agreed to.
        let mut link = Link::new();
        link.drive(Event::Connect {
            iss: ISS,
            window: RING,
        });
        let sent = link.drive(Event::Arrived(from_peer(
            IRS.0,
            Some(ISS.0 + 99),
            Flags::SYN,
            PEER_WINDOW,
            &[],
        )));
        assert_eq!(link.tcb.state, State::SynSent, "still waiting");
        assert_eq!(sent.len(), 1);
        assert!(sent[0].flags.contains(Flags::RST));
        assert_eq!(sent[0].sequence, Sequence(ISS.0 + 99));
    }

    #[test]
    fn a_reset_refuses_a_connection_only_when_it_acknowledges_the_syn() {
        // An unacknowledged RST in SYN-SENT is a segment anyone can forge.
        let mut link = Link::new();
        link.drive(Event::Connect {
            iss: ISS,
            window: RING,
        });
        link.drive(Event::Arrived(from_peer(IRS.0, None, Flags::RST, 0, &[])));
        assert_eq!(link.tcb.state, State::SynSent, "not believed");
        assert_eq!(link.ended, None);

        link.drive(Event::Arrived(from_peer(
            IRS.0,
            Some(ISS.0 + 1),
            Flags::RST,
            0,
            &[],
        )));
        assert_eq!(link.tcb.state, State::Closed);
        assert_eq!(link.ended, Some(Ended::Refused), "refused, not reset");
    }

    // ---- data ---------------------------------------------------------

    #[test]
    fn written_bytes_are_sent_and_acknowledged_bytes_are_reported() {
        let mut link = Link::established();
        let sent = link.drive(Event::Wrote(100));
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].sequence, ISS.wrapping_add(1));
        assert_eq!(sent[0].length, 100);
        assert!(sent[0].flags.contains(Flags::PSH));
        assert_eq!(sent[0].acknowledgement, Some(IRS.wrapping_add(1)));
        assert!(link.armed(Timer::Retransmit).is_some());

        link.drive(Event::Arrived(from_peer(
            IRS.0 + 1,
            Some(ISS.0 + 101),
            Flags::default(),
            PEER_WINDOW,
            &[],
        )));
        assert_eq!(link.acknowledged, vec![100], "the ring's space is freed");
        assert_eq!(link.armed(Timer::Retransmit), None, "nothing outstanding");
    }

    #[test]
    fn a_segment_is_never_larger_than_the_maximum_segment_size() {
        let mut link = Link::established();
        let sent = link.drive(Event::Wrote(10_000));
        assert!(!sent.is_empty());
        for emit in &sent {
            assert!(emit.length <= DEFAULT_MSS, "{} bytes", emit.length);
        }
    }

    #[test]
    fn a_peer_advertising_a_giant_mss_does_not_widen_the_segments() {
        // `bin/tcpd` copies every emit through buffers sized to
        // `DEFAULT_MSS` and refuses anything wider, so this cap is what
        // makes every emit honourable: a peer may name any MSS it likes,
        // and the machine takes the smaller of that and its own bound.
        let mut link = Link::new();
        link.drive(Event::Connect {
            iss: ISS,
            window: RING,
        });
        let mut syn_ack = from_peer(IRS.0, Some(ISS.0 + 1), Flags::SYN, u16::MAX, &[]);
        syn_ack.options.mss = Some(9000);
        link.drive(Event::Arrived(syn_ack));
        assert_eq!(link.tcb.state, State::Established);
        assert_eq!(link.tcb.mss, DEFAULT_MSS, "the advertisement is capped");
        let sent = link.drive(Event::Wrote(10_000));
        assert!(!sent.is_empty());
        for emit in &sent {
            assert!(emit.length <= DEFAULT_MSS, "{} bytes", emit.length);
        }
    }

    #[test]
    fn nothing_is_sent_past_the_window_the_peer_advertised() {
        let mut link = Link::new();
        link.drive(Event::Connect {
            iss: ISS,
            window: RING,
        });
        link.drive(Event::Arrived(from_peer(
            IRS.0,
            Some(ISS.0 + 1),
            Flags::SYN,
            50,
            &[],
        )));
        let sent = link.drive(Event::Wrote(500));
        let total: u32 = sent.iter().map(|emit| u32::from(emit.length)).sum();
        assert_eq!(total, 50, "the window, and not a byte more");
    }

    #[test]
    fn arriving_data_is_delivered_in_order_and_closes_the_window_by_that_much() {
        let mut link = Link::established();
        link.drive(Event::Arrived(from_peer(
            IRS.0 + 1,
            Some(ISS.0 + 1),
            Flags::PSH,
            PEER_WINDOW,
            &[1, 2, 3, 4],
        )));
        assert_eq!(link.delivered, vec![4]);
        assert_eq!(link.tcb.rcv_nxt, Sequence(IRS.0 + 5));
        assert_eq!(link.tcb.rcv_wnd, RING - 4, "the ring has four fewer bytes");
    }

    #[test]
    fn a_segment_ahead_of_the_stream_is_dropped_without_an_acknowledgement() {
        // RFC 0020's "no reassembly queue", and the cost it names: the peer
        // waits out a retransmission timeout rather than seeing a duplicate
        // acknowledgement.
        let mut link = Link::established();
        let sent = link.drive(Event::Arrived(from_peer(
            IRS.0 + 100,
            Some(ISS.0 + 1),
            Flags::PSH,
            PEER_WINDOW,
            &[9, 9, 9],
        )));
        assert!(sent.is_empty(), "silence, so the peer retransmits");
        assert!(link.delivered.is_empty());
        assert_eq!(
            link.tcb.rcv_nxt,
            IRS.wrapping_add(1),
            "the stream did not move"
        );
    }

    #[test]
    fn a_segment_behind_the_stream_is_acknowledged_rather_than_ignored() {
        // **The case RFC 0020's sentence does not cover.** A duplicate means
        // the peer never saw the acknowledgement for data already taken.
        // Staying quiet leaves it retransmitting until it abandons a connection
        // that is working perfectly.
        let mut link = Link::established();
        link.drive(Event::Arrived(from_peer(
            IRS.0 + 1,
            Some(ISS.0 + 1),
            Flags::PSH,
            PEER_WINDOW,
            &[1, 2, 3, 4],
        )));
        let sent = link.drive(Event::Arrived(from_peer(
            IRS.0 + 1,
            Some(ISS.0 + 1),
            Flags::PSH,
            PEER_WINDOW,
            &[1, 2, 3, 4],
        )));
        assert_eq!(sent.len(), 1, "the acknowledgement is sent again");
        assert_eq!(sent[0].acknowledgement, Some(Sequence(IRS.0 + 5)));
        assert_eq!(
            link.delivered,
            vec![4],
            "and the bytes are not delivered twice"
        );
    }

    #[test]
    fn reading_reopens_the_window_and_never_past_the_ring() {
        let mut link = Link::established();
        link.drive(Event::Arrived(from_peer(
            IRS.0 + 1,
            Some(ISS.0 + 1),
            Flags::PSH,
            PEER_WINDOW,
            &[0; 100],
        )));
        assert_eq!(link.tcb.rcv_wnd, RING - 100);
        link.drive(Event::Read(100));
        assert_eq!(link.tcb.rcv_wnd, RING);
        // The invariant: the window is the ring's free space, so no sequence of
        // reads can advertise more room than the program has.
        link.drive(Event::Read(10_000));
        assert_eq!(link.tcb.rcv_wnd, RING, "capped at the ring");
        assert!(link.tcb.rcv_wnd <= link.tcb.rcv_capacity);
    }

    #[test]
    fn a_window_reopening_from_zero_is_advertised_at_once() {
        // A peer blocked on a zero window has no way to ask. Waiting for the
        // delayed acknowledgement would stall it for no reason.
        let mut link = Link::established();
        link.drive(Event::Arrived(from_peer(
            IRS.0 + 1,
            Some(ISS.0 + 1),
            Flags::PSH,
            PEER_WINDOW,
            &[0; RING as usize],
        )));
        assert_eq!(link.tcb.rcv_wnd, 0, "the ring is full");
        let sent = link.drive(Event::Read(1000));
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].window, 1000);
    }

    #[test]
    fn an_acknowledgement_is_delayed_once_and_then_sent_with_the_second_segment() {
        let mut link = Link::established();
        let sent = link.drive(Event::Arrived(from_peer(
            IRS.0 + 1,
            Some(ISS.0 + 1),
            Flags::PSH,
            PEER_WINDOW,
            &[1, 2],
        )));
        assert!(sent.is_empty(), "held back in case data follows");
        assert_eq!(
            link.armed(Timer::DelayedAck),
            Some(DELAYED_ACK_US * 1_000 + link.now)
        );

        let sent = link.drive(Event::Arrived(from_peer(
            IRS.0 + 3,
            Some(ISS.0 + 1),
            Flags::PSH,
            PEER_WINDOW,
            &[3, 4],
        )));
        assert_eq!(sent.len(), 1, "RFC 1122: at least every second segment");
        assert_eq!(sent[0].acknowledgement, Some(Sequence(IRS.0 + 5)));
        assert_eq!(link.armed(Timer::DelayedAck), None);
    }

    #[test]
    fn a_delayed_acknowledgement_is_sent_when_its_timer_expires() {
        let mut link = Link::established();
        link.drive(Event::Arrived(from_peer(
            IRS.0 + 1,
            Some(ISS.0 + 1),
            Flags::PSH,
            PEER_WINDOW,
            &[1, 2],
        )));
        assert_eq!(link.fire_earliest(), Timer::DelayedAck);
        assert_eq!(link.sent.len(), 1);
        assert_eq!(link.sent[0].acknowledgement, Some(Sequence(IRS.0 + 3)));
    }

    // ---- retransmission -----------------------------------------------

    #[test]
    fn a_measured_round_trip_sets_the_timeout() {
        // The handshake took exactly 100 ms of virtual time, so this is an
        // exact number rather than a range: RFC 6298's first measurement seeds
        // both terms, and the timeout is srtt + 4 * rttvar.
        let link = Link::established();
        assert_eq!(link.tcb.srtt_us, Some(100_000));
        assert_eq!(link.tcb.rttvar_us, 50_000);
        assert_eq!(link.tcb.rto_us, 100_000 + 4 * 50_000);
    }

    #[test]
    fn a_lost_segment_is_sent_again_and_the_timeout_backs_off() {
        let mut link = Link::established();
        link.drive(Event::Wrote(100));
        let before = link.tcb.rto_us;

        assert_eq!(link.fire_earliest(), Timer::Retransmit);
        assert_eq!(link.sent.len(), 1, "the same bytes again");
        assert_eq!(link.sent[0].sequence, ISS.wrapping_add(1));
        assert_eq!(link.sent[0].length, 100);
        assert_eq!(link.tcb.rto_us, before * 2, "exponential backoff");
        assert_eq!(link.tcb.retransmits, 1);
        assert!(link.armed(Timer::Retransmit).is_some(), "and timed again");
    }

    #[test]
    fn a_peer_that_never_answers_is_abandoned_after_a_bounded_number_of_tries() {
        let mut link = Link::established();
        link.drive(Event::Wrote(100));
        for _ in 0..MAX_RETRANSMITS {
            assert_eq!(link.fire_earliest(), Timer::Retransmit);
        }
        assert_eq!(link.tcb.retransmits, MAX_RETRANSMITS);
        assert_eq!(link.tcb.state, State::Established, "not yet");

        assert_eq!(link.fire_earliest(), Timer::Retransmit);
        assert_eq!(link.tcb.state, State::Closed);
        assert_eq!(link.ended, Some(Ended::Unreachable));
    }

    #[test]
    fn karns_algorithm_refuses_to_measure_a_retransmitted_segment() {
        // The acknowledgement below could belong to either transmission, and
        // there is no way to tell. Believing it belongs to the second makes the
        // estimate far too small, which causes more retransmissions, which
        // makes it smaller still.
        let mut link = Link::established();
        let srtt_before = link.tcb.srtt_us;
        link.drive(Event::Wrote(100));
        assert_eq!(link.fire_earliest(), Timer::Retransmit);
        let rto_after_backoff = link.tcb.rto_us;
        assert!(link.tcb.timing.is_none(), "the measurement was abandoned");

        link.now += 1_000_000;
        link.drive(Event::Arrived(from_peer(
            IRS.0 + 1,
            Some(ISS.0 + 101),
            Flags::default(),
            PEER_WINDOW,
            &[],
        )));
        assert_eq!(link.tcb.srtt_us, srtt_before, "the estimate did not move");
        assert_eq!(link.tcb.rto_us, rto_after_backoff);
        assert_eq!(
            link.acknowledged,
            vec![100],
            "but the bytes are still freed"
        );
    }

    // ---- flow control -------------------------------------------------

    #[test]
    fn a_zero_window_stops_the_sender_and_arms_a_probe() {
        let mut link = Link::established();
        link.drive(Event::Arrived(from_peer(
            IRS.0 + 1,
            Some(ISS.0 + 1),
            Flags::default(),
            0,
            &[],
        )));
        let sent = link.drive(Event::Wrote(100));
        assert!(sent.is_empty(), "the peer has no room");
        assert!(link.armed(Timer::Probe).is_some());

        assert_eq!(link.fire_earliest(), Timer::Probe);
        assert_eq!(link.sent.len(), 1);
        assert_eq!(link.sent[0].length, 1, "one byte, past the closed window");
    }

    #[test]
    fn a_window_update_cancels_the_probe_and_the_data_flows() {
        let mut link = Link::established();
        link.drive(Event::Arrived(from_peer(
            IRS.0 + 1,
            Some(ISS.0 + 1),
            Flags::default(),
            0,
            &[],
        )));
        link.drive(Event::Wrote(100));
        assert!(link.armed(Timer::Probe).is_some());

        let sent = link.drive(Event::Arrived(from_peer(
            IRS.0 + 1,
            Some(ISS.0 + 1),
            Flags::default(),
            PEER_WINDOW,
            &[],
        )));
        assert_eq!(link.armed(Timer::Probe), None);
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].length, 100, "and the waiting bytes go out");
    }

    // ---- closing ------------------------------------------------------

    #[test]
    fn an_orderly_close_from_this_end_walks_fin_wait_1_2_and_time_wait() {
        let mut link = Link::established();
        let sent = link.drive(Event::Shutdown);
        assert_eq!(link.tcb.state, State::FinWait1);
        assert_eq!(sent.len(), 1);
        assert!(sent[0].flags.contains(Flags::FIN));
        let fin = sent[0].sequence;

        link.drive(Event::Arrived(from_peer(
            IRS.0 + 1,
            Some(fin.0 + 1),
            Flags::default(),
            PEER_WINDOW,
            &[],
        )));
        assert_eq!(link.tcb.state, State::FinWait2);
        assert!(
            link.acknowledged.is_empty(),
            "a FIN is not a byte of the ring"
        );

        let sent = link.drive(Event::Arrived(from_peer(
            IRS.0 + 1,
            Some(fin.0 + 1),
            Flags::FIN,
            PEER_WINDOW,
            &[],
        )));
        assert_eq!(link.tcb.state, State::TimeWait);
        assert_eq!(sent.len(), 1, "the peer's FIN is acknowledged");
        assert_eq!(sent[0].acknowledgement, Some(Sequence(IRS.0 + 2)));
        assert_eq!(
            link.armed(Timer::TimeWait),
            Some(link.now + 2 * MSL_US * 1_000)
        );

        assert_eq!(link.fire_earliest(), Timer::TimeWait);
        assert_eq!(link.tcb.state, State::Closed);
        assert_eq!(link.ended, Some(Ended::Orderly));
    }

    #[test]
    fn a_fin_crossing_a_fin_goes_through_closing() {
        // Simultaneous close: this end closed and the peer closed before seeing
        // it, so neither close is acknowledged yet. CLOSING is the state that
        // exists only for this.
        let mut link = Link::established();
        let sent = link.drive(Event::Shutdown);
        let fin = sent[0].sequence;
        assert_eq!(link.tcb.state, State::FinWait1);

        link.drive(Event::Arrived(from_peer(
            IRS.0 + 1,
            Some(fin.0),
            Flags::FIN,
            PEER_WINDOW,
            &[],
        )));
        assert_eq!(link.tcb.state, State::Closing, "not FIN-WAIT-2");

        link.drive(Event::Arrived(from_peer(
            IRS.0 + 2,
            Some(fin.0 + 1),
            Flags::default(),
            PEER_WINDOW,
            &[],
        )));
        assert_eq!(link.tcb.state, State::TimeWait);
    }

    #[test]
    fn a_peer_closing_first_leaves_this_end_able_to_send() {
        // The half-close that makes a request/response protocol expressible:
        // the peer has said it will send no more, and this end may still reply.
        let mut link = Link::established();
        let sent = link.drive(Event::Arrived(from_peer(
            IRS.0 + 1,
            Some(ISS.0 + 1),
            Flags::FIN,
            PEER_WINDOW,
            &[],
        )));
        assert_eq!(link.tcb.state, State::CloseWait);
        assert_eq!(sent.len(), 1, "acknowledged at once");
        assert_eq!(sent[0].acknowledgement, Some(Sequence(IRS.0 + 2)));

        let sent = link.drive(Event::Wrote(10));
        assert_eq!(sent.len(), 1, "and this end can still send");
        assert_eq!(sent[0].length, 10);

        let sent = link.drive(Event::Shutdown);
        assert_eq!(link.tcb.state, State::LastAck);
        let fin = sent[0].sequence;

        link.drive(Event::Arrived(from_peer(
            IRS.0 + 2,
            Some(fin.0 + 1),
            Flags::default(),
            PEER_WINDOW,
            &[],
        )));
        assert_eq!(link.tcb.state, State::Closed);
        assert_eq!(link.ended, Some(Ended::Orderly));
    }

    #[test]
    fn a_fin_is_sent_again_after_the_data_in_front_of_it() {
        let mut link = Link::established();
        link.drive(Event::Wrote(50));
        link.drive(Event::Shutdown);
        assert_eq!(link.tcb.state, State::FinWait1);

        assert_eq!(link.fire_earliest(), Timer::Retransmit);
        let flags: Vec<Flags> = link.sent.iter().map(|emit| emit.flags).collect();
        assert!(
            flags.iter().any(|flag| flag.contains(Flags::FIN)),
            "the close must be retransmitted too, or the peer waits for ever: {flags:?}"
        );
    }

    // ---- resets -------------------------------------------------------

    #[test]
    fn a_reset_inside_the_window_ends_the_connection() {
        let mut link = Link::established();
        link.drive(Event::Arrived(from_peer(
            IRS.0 + 1,
            Some(ISS.0 + 1),
            Flags::RST,
            0,
            &[],
        )));
        assert_eq!(link.tcb.state, State::Closed);
        assert_eq!(
            link.ended,
            Some(Ended::Reset),
            "distinct from an orderly end"
        );
    }

    #[test]
    fn a_reset_outside_the_window_is_ignored() {
        // Without this check an off-path attacker who can guess the port pair
        // resets connections for free — they never have to see a packet.
        let mut link = Link::established();
        link.drive(Event::Arrived(from_peer(
            IRS.0 + 1 + u32::from(RING) + 1,
            Some(ISS.0 + 1),
            Flags::RST,
            0,
            &[],
        )));
        assert_eq!(link.tcb.state, State::Established, "not believed");
        assert_eq!(link.ended, None);
    }

    #[test]
    fn a_reset_is_believed_in_every_synchronised_state() {
        // Eleven states, and the ones a reset can legitimately reach.
        for build in [
            (|| {
                let mut link = Link::established();
                link.drive(Event::Shutdown);
                link
            }) as fn() -> Link,
            || {
                let mut link = Link::established();
                link.drive(Event::Arrived(from_peer(
                    IRS.0 + 1,
                    Some(ISS.0 + 1),
                    Flags::FIN,
                    PEER_WINDOW,
                    &[],
                )));
                link
            },
            Link::established,
        ] {
            let mut link = build();
            let before = link.tcb.state;
            link.drive(Event::Arrived(from_peer(
                link.tcb.rcv_nxt.0,
                Some(link.tcb.snd_nxt.0),
                Flags::RST,
                0,
                &[],
            )));
            assert_eq!(link.tcb.state, State::Closed, "from {before:?}");
            assert!(link.ended.is_some());
        }
    }

    #[test]
    fn a_segment_for_a_closed_connection_is_reset() {
        let mut link = Link::new();
        let sent = link.drive(Event::Arrived(from_peer(
            IRS.0,
            Some(ISS.0),
            Flags::PSH,
            PEER_WINDOW,
            &[1, 2, 3],
        )));
        assert_eq!(sent.len(), 1);
        assert!(sent[0].flags.contains(Flags::RST));
        assert_eq!(
            sent[0].sequence, ISS,
            "a reset takes the sequence acknowledged"
        );
    }

    #[test]
    fn a_reset_is_never_answered_with_a_reset() {
        // Two closed ends answering each other's resets is a packet storm that
        // only stops when a link does.
        let mut link = Link::new();
        let sent = link.drive(Event::Arrived(from_peer(
            IRS.0,
            Some(ISS.0),
            Flags::RST,
            0,
            &[],
        )));
        assert!(sent.is_empty());
    }

    #[test]
    fn an_abort_sends_a_reset_and_the_connection_is_gone() {
        let mut link = Link::established();
        let sent = link.drive(Event::Abort);
        assert_eq!(sent.len(), 1);
        assert!(sent[0].flags.contains(Flags::RST));
        assert_eq!(link.tcb.state, State::Closed);
        assert_eq!(link.ended, Some(Ended::Aborted));
    }

    #[test]
    fn an_acknowledgement_of_something_never_sent_is_answered_and_dropped() {
        // RFC 793 asks for an acknowledgement rather than a reset here,
        // because a reset would be remotely triggerable by a forged number.
        let mut link = Link::established();
        let sent = link.drive(Event::Arrived(from_peer(
            IRS.0 + 1,
            Some(ISS.0 + 9999),
            Flags::PSH,
            PEER_WINDOW,
            &[1, 2, 3],
        )));
        assert_eq!(link.tcb.state, State::Established);
        assert_eq!(sent.len(), 1);
        assert!(!sent[0].flags.contains(Flags::RST));
        assert!(link.delivered.is_empty(), "and nothing was taken from it");
    }

    // ---- the joins to the other two steps ------------------------------

    #[test]
    fn what_the_machine_emits_is_a_segment_that_parses_back() {
        // The seam between step 2 and step 3: a range named here becomes bytes
        // on the wire and comes back as the same fields.
        use crate::addr::Ipv4Addr;
        let mut link = Link::established();
        let sent = link.drive(Event::Wrote(4));
        let payload = [7u8, 8, 9, 10];
        let segment = sent[0].segment(connection(), &payload);

        let (here, there) = (
            Address::V4(Ipv4Addr::new(10, 0, 2, 15)),
            Address::V4(Ipv4Addr::new(10, 0, 2, 2)),
        );
        let mut bytes = [0u8; 128];
        let written = crate::tcp::segment::write(&mut bytes, &segment, here, there).unwrap();
        let parsed = Segment::parse(&bytes[..written], here, there).unwrap();
        assert_eq!(parsed.sequence, sent[0].sequence);
        assert_eq!(parsed.acknowledgement, sent[0].acknowledgement);
        assert_eq!(parsed.window, sent[0].window);
        assert_eq!(parsed.payload, &payload);
    }

    #[test]
    fn the_action_list_never_overflows_on_the_busiest_step() {
        // The worst case this machine can produce in one step: a segment that
        // acknowledges data, delivers data, carries a FIN, and leaves this end
        // with data of its own to send.
        let mut link = Link::established();
        link.drive(Event::Wrote(200));
        link.drive(Event::Wrote(200));
        let (_, actions) = step(
            link.tcb,
            Event::Arrived(from_peer(
                IRS.0 + 1,
                Some(ISS.0 + 101),
                Flags::PSH.with(Flags::FIN),
                PEER_WINDOW,
                &[1, 2, 3, 4],
            )),
            link.now,
        );
        assert!(!actions.overflowed());
        assert!(actions.len() <= MAX_ACTIONS);
    }

    #[test]
    fn one_step_never_gives_two_instructions_for_the_same_timer() {
        // **This is the fix for the overflow the fuzz target found**, so it is
        // the property that must be watched rather than the size of the list.
        // A step that acknowledges data, closes, delivers data and enters
        // TIME-WAIT touches the retransmission timer three times over; what the
        // caller needs is the last answer, once.
        let mut link = Link::established();
        link.drive(Event::Wrote(100));
        link.drive(Event::Shutdown);
        let fin = link.tcb.fin_seq.unwrap();

        let (_, actions) = step(
            link.tcb,
            Event::Arrived(from_peer(
                IRS.0 + 1,
                Some(fin.0 + 1),
                Flags::PSH.with(Flags::FIN),
                PEER_WINDOW,
                &[1, 2, 3, 4],
            )),
            link.now,
        );
        assert!(!actions.overflowed());

        let mut seen: Vec<Timer> = Vec::new();
        for action in actions.iter() {
            if let Action::Arm { timer, .. } | Action::Cancel(timer) = action {
                assert!(
                    !seen.contains(&timer),
                    "{timer:?} was instructed twice in one step: {:?}",
                    actions.iter().collect::<Vec<_>>()
                );
                seen.push(timer);
            }
        }
        assert!(
            seen.len() >= 2,
            "this step should touch at least two timers, or it is not the busy one"
        );
    }

    #[test]
    fn the_send_sequence_never_runs_backwards() {
        // `snd_una <= snd_nxt <= snd_avail + 1` is the invariant the fuzz target
        // checks; this is it stated once against an ordinary exchange.
        let mut link = Link::established();
        link.drive(Event::Wrote(500));
        link.drive(Event::Arrived(from_peer(
            IRS.0 + 1,
            Some(ISS.0 + 201),
            Flags::default(),
            PEER_WINDOW,
            &[],
        )));
        link.drive(Event::Shutdown);
        assert!(!link.tcb.snd_una.follows(link.tcb.snd_nxt));
        assert!(link.tcb.in_flight() <= 501);
    }

    // ------------------------------------------------------------------
    // RFC 0048 step 1: a connection nobody has proved they wanted is given
    // less patience than one somebody completed.
    //
    // Both tests are here rather than one, and the second is the important
    // one: shortening the wrong connections would be a worse bug than the one
    // being fixed, and a test that only checked the half-open case would pass
    // a change that shortened everything.
    // ------------------------------------------------------------------

    /// Drives `Expired(Retransmit)` at whatever instant the machine asks for
    /// next, and answers how long it took to reach `Closed` and after how many
    /// retransmissions. The clock is the machine's own, so this measures the
    /// backoff rather than assuming it.
    fn hold_until_closed(mut tcb: Tcb) -> (u64, u32) {
        let mut now = 0u64;
        let mut fired = 0;
        while tcb.state != State::Closed && fired < 64 {
            let (next_tcb, actions) = step(tcb, Event::Expired(Timer::Retransmit), now);
            tcb = next_tcb;
            let mut next = None;
            for action in actions.iter() {
                if let Action::Arm {
                    timer: Timer::Retransmit,
                    at,
                } = action
                {
                    next = Some(at);
                }
            }
            match next {
                Some(at) => now = at,
                None => break,
            }
            fired += 1;
        }
        (now / 1_000_000_000, fired)
    }

    #[test]
    fn a_half_open_connection_is_abandoned_in_seconds_not_minutes() {
        // The measured cost of the defect RFC 0048 exists for: before the
        // split limit, one `SYN` from a peer that then vanished held
        // `bin/tcpd`'s single accepted slot for **242 seconds**, and every
        // later `SYN` was refused silently for all of it.
        //
        // The number is asserted, not just the state. "It closes eventually"
        // was already true at 242 seconds.
        let mut link = Link::new();
        link.drive(Event::Listen {
            iss: ISS,
            window: RING,
        });
        link.drive(Event::Arrived(from_peer(
            IRS.0,
            None,
            Flags::SYN,
            PEER_WINDOW,
            &[],
        )));
        assert_eq!(link.tcb.state, State::SynReceived, "the peer knocked");

        let (seconds, retransmits) = hold_until_closed(link.tcb);
        assert_eq!(
            retransmits,
            u32::from(MAX_SYNACK_RETRANSMITS),
            "a half-open connection gets the SYN·ACK budget"
        );
        assert_eq!(seconds, 14, "fourteen seconds, measured -- and it was 242");
    }

    #[test]
    fn an_established_connection_keeps_the_patience_it_always_had() {
        // The half of this that must not break. A connection somebody
        // completed has proved the peer exists, so it keeps `MAX_RETRANSMITS`
        // — and shortening *this* would drop live connections on a lossy path,
        // which is a worse defect than the one being fixed.
        let mut link = Link::established();
        link.drive(Event::Wrote(100));
        assert!(
            link.tcb.awaiting_ack(),
            "something is outstanding to resend"
        );

        let (_, retransmits) = hold_until_closed(link.tcb);
        assert_eq!(
            retransmits,
            u32::from(MAX_RETRANSMITS),
            "eight, unchanged, and more than the SYN·ACK budget"
        );
    }

    // ------------------------------------------------------------------
    // RFC 0047: refusing a connection to a port nobody holds.
    //
    // These test `reset_for` directly rather than through a `Tcb`, because
    // its second caller -- `bin/tcpd`'s dispatcher, for a `SYN` naming a port
    // no listener holds -- has no control block to drive. A test that could
    // only reach this through `State::Closed` would not cover the caller the
    // function was made public for.
    // ------------------------------------------------------------------

    #[test]
    fn a_syn_for_a_port_nobody_holds_is_acknowledged_at_the_syns_own_number() {
        // RFC 793 §3.4's ack-less shape: <SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST>.
        // The `+1` is the `SYN` occupying a sequence number. Off by that one
        // and the peer discards the reset as outside its window, which reads
        // as this fix not working rather than as an arithmetic slip.
        let emit = reset_for(&from_peer(IRS.0, None, Flags::SYN, PEER_WINDOW, &[]))
            .expect("a SYN naming nothing here is refused");
        assert!(emit.flags.contains(Flags::RST));
        assert_eq!(emit.sequence, Sequence(0));
        assert_eq!(emit.acknowledgement, Some(IRS.wrapping_add(1)));
        assert_eq!(emit.length, 0, "a reset carries no stream bytes");
        assert_eq!(emit.mss, None, "and no options");
    }

    #[test]
    fn the_acknowledgement_counts_every_number_the_segment_occupied() {
        // `sequence_length`, not `payload.len()`: a segment carrying both data
        // and a control bit occupies one number more than its bytes. Asserted
        // separately from the bare `SYN` above because a reset that used the
        // payload length alone passes that test and fails this one.
        let emit = reset_for(&from_peer(
            IRS.0,
            None,
            Flags::SYN.with(Flags::FIN),
            PEER_WINDOW,
            &[1, 2, 3, 4, 5],
        ))
        .expect("refused");
        assert_eq!(
            emit.acknowledgement,
            Some(IRS.wrapping_add(7)),
            "five bytes, a SYN and a FIN"
        );
    }

    #[test]
    fn a_segment_that_acknowledged_something_is_reset_at_that_number() {
        // The other shape: <SEQ=SEG.ACK><CTL=RST>, acknowledging nothing back.
        // A reset that acknowledged here would be claiming to have received a
        // stream from a connection this end does not have.
        let emit = reset_for(&from_peer(
            IRS.0,
            Some(ISS.0 + 41),
            Flags::default(),
            PEER_WINDOW,
            &[],
        ))
        .expect("refused");
        assert!(emit.flags.contains(Flags::RST));
        assert_eq!(emit.sequence, Sequence(ISS.0 + 41));
        assert_eq!(emit.acknowledgement, None);
    }

    /// RFC 0048 step 3: the reply that costs no state.
    #[test]
    fn a_synack_acknowledges_the_syn_and_carries_the_cookie() {
        let syn = from_peer(IRS.0, None, Flags::SYN, 0, &[]);
        let emit = synack_for(&syn, Sequence(0xdead_beef), 4096, 1460).expect("a SYN is answered");
        assert!(emit.flags.contains(Flags::SYN), "it is a SYN");
        assert_eq!(
            emit.sequence,
            Sequence(0xdead_beef),
            "the cookie is the ISN"
        );
        assert_eq!(
            emit.acknowledgement,
            Some(IRS.wrapping_add(1)),
            "the peer's SYN occupies one number and this acknowledges exactly it"
        );
        assert_eq!(emit.window, 4096);
        assert_eq!(
            emit.mss,
            Some(1460),
            "the option the peer needs to hear back"
        );
        assert_eq!(emit.length, 0, "a SYN-ACK carries no payload");
        // The ACK flag is derived by `segment::write` from the acknowledgement
        // being present. Setting it here as well would be two sources for one
        // bit, and this asserts the choice rather than leaving it to be
        // rediscovered.
        assert!(
            !emit.flags.contains(Flags::ACK),
            "the flag is derived, not set"
        );

        // **A `SYN` carrying data is acknowledged for the `SYN` only.**
        //
        // This case exists because without it the assertion above cannot fail:
        // `sequence_length()` of a bare `SYN` is 1, so acknowledging the
        // segment's whole length and acknowledging just its `SYN` are the same
        // number, and a mutation swapping one for the other stayed green.
        // A `SYN` with a payload is the input that tells them apart — and the
        // answer matters, since this stack has accepted no data at this point.
        let with_data = from_peer(IRS.0, None, Flags::SYN, 0, b"early");
        let emit = synack_for(&with_data, Sequence(7), 4096, 1460).expect("still a SYN");
        assert_eq!(
            emit.acknowledgement,
            Some(IRS.wrapping_add(1)),
            "the SYN alone, not the five bytes riding with it"
        );
    }

    /// The three shapes that are **not** a connection request.
    ///
    /// Each is a separate guard, and a fix that dropped one would still pass a
    /// test that only tried another — the argument
    /// `reset_for_answers_a_reset_with_silence_on_both_its_branches` makes,
    /// applied to three branches instead of two.
    #[test]
    fn a_synack_is_offered_only_for_a_bare_syn() {
        assert!(
            synack_for(&from_peer(IRS.0, None, Flags::ACK, 0, &[]), ISS, 4096, 1460).is_none(),
            "no SYN flag"
        );
        assert!(
            synack_for(
                &from_peer(IRS.0, None, Flags::SYN.with(Flags::RST), 0, &[]),
                ISS,
                4096,
                1460
            )
            .is_none(),
            "a SYN carrying RST"
        );
        assert!(
            synack_for(
                &from_peer(IRS.0, Some(ISS.0), Flags::SYN.with(Flags::ACK), 0, &[]),
                ISS,
                4096,
                1460
            )
            .is_none(),
            "a SYN that already acknowledges something is not a fresh request"
        );
    }

    /// RFC 0048 step 3: what a verified cookie rebuilds.
    #[test]
    fn a_cookie_rebuilds_an_established_control_block() {
        let tcb = Tcb::from_cookie(connection(), Sequence(1000), Sequence(500), 8192, 4096, 536);
        assert_eq!(
            tcb.state,
            State::Established,
            "there is no SynReceived to sit in"
        );
        assert_eq!(tcb.iss, Sequence(1000), "the cookie is this end's ISS");
        assert_eq!(
            (tcb.snd_una, tcb.snd_nxt),
            (Sequence(1001), Sequence(1001)),
            "the SYN occupied the cookie's own number, so sending resumes one past it"
        );
        assert_eq!(tcb.irs, Sequence(500));
        assert_eq!(tcb.rcv_nxt, Sequence(501), "one past the peer's SYN");
        assert_eq!(tcb.snd_wnd, 8192, "the peer's window");
        assert_eq!((tcb.rcv_wnd, tcb.rcv_capacity), (4096, 4096));
        assert_eq!(tcb.mss, 536, "the rounded value the cookie carried");
    }

    /// **`snd_avail` must not sit behind `snd_nxt`.**
    ///
    /// Its own field documents what that costs: `unsent` on a control block
    /// whose available sequence is behind what has been sent claims the whole
    /// sequence space. Asserted here rather than trusted, because this
    /// constructor sets the two fields on adjacent lines and a zero would look
    /// entirely reasonable there.
    #[test]
    fn a_rebuilt_control_block_has_nothing_unsent() {
        let tcb = Tcb::from_cookie(connection(), Sequence(1000), Sequence(500), 8192, 4096, 536);
        // **The field, not just `unsent()`.** Asserting only the helper cannot
        // fail: `unsent` answers zero both when nothing is pending *and* when
        // `snd_avail` sits behind `snd_nxt`, which is the very mistake this
        // guards against — a zeroed `snd_avail` passed it unchanged.
        assert_eq!(
            tcb.snd_avail, tcb.snd_nxt,
            "available and next are the same point; behind is the failure `unsent` documents"
        );
        assert_eq!(tcb.unsent(), 0, "and so nothing is waiting to be sent");
    }

    #[test]
    fn reset_for_answers_a_reset_with_silence_on_both_its_branches() {
        // `a_reset_is_never_answered_with_a_reset` above asserts this through a
        // `Link` and reaches only the acknowledging branch. Both are tested
        // here because the guard sits before the branch: a fix that moved it
        // after would still pass that test and let a bare `RST` be answered.
        assert!(
            reset_for(&from_peer(IRS.0, None, Flags::RST, 0, &[])).is_none(),
            "a bare RST"
        );
        assert!(
            reset_for(&from_peer(
                IRS.0,
                Some(ISS.0),
                Flags::RST.with(Flags::ACK),
                0,
                &[]
            ))
            .is_none(),
            "and one that acknowledges, which takes the other branch"
        );
    }
}
