// SPDX-License-Identifier: Apache-2.0
//! Synchronous IPC: endpoints, `Call`, `Recv` and `Reply`.
//!
//! Implements [RFC 0008]'s answer to **A3**. IPC is a *rendezvous*: a sender
//! and a receiver meet, the message is copied directly from one to the other,
//! and both continue. There is no buffer in the nucleus.
//!
//! [RFC 0008]: ../../../docs/rfc/0008-syscall-and-ipc-shape.md
//!
//! # Why there is no queue of messages
//!
//! Buffering a message the receiver has not asked for raises a question with
//! no good answer at this layer: **whose memory is it?** Charge it to the
//! sender and a slow receiver blocks the sender anyway — the synchronous
//! behaviour with a buffer's complexity added. Charge it to the receiver and a
//! hostile sender exhausts a victim's envelope by talking to it. Charge it to
//! the nucleus and there is an unbounded kernel allocation driven by untrusted
//! callers.
//!
//! Rendezvous makes the question disappear. What *is* queued here is
//! *threads*, and a thread is already accounted for: it belongs to a domain,
//! it has a stack, and it was going to exist anyway.
//!
//! # The reply capability is one-shot, and that is the whole protection
//!
//! `Call` creates a capability naming the caller and hands it to whoever
//! receives the message. Answering consumes it. A service therefore cannot
//! accumulate the ability to answer callers later, cannot answer twice, and
//! cannot answer someone who never called — none of which is enforced by
//! checking, because there is nothing to check against: the capability either
//! exists or it does not.
//!
//! # Badges answer "who is calling?" without trusting the caller
//!
//! The badge travels on the *endpoint capability the sender used*, and it was
//! written by whoever granted that capability. A sender cannot read it, cannot
//! change it, and cannot present someone else's. So a service that hands out
//! differently-badged capabilities to different clients can tell them apart —
//! which is what makes access control implementable in userspace rather than
//! in the nucleus.
//!
//! # What is not here
//!
//! - **No timeout on `Recv`.** A service bug hangs its callers. RFC 0008
//!   records this as unresolved; it needs a policy decision, not code.
//! - **No slice donation.** A `Call` should arguably charge the service's work
//!   to the caller's budget. It complicates the fair class's accounting and is
//!   deliberately not first.
//! - **No message longer than four registers.** Anything larger travels as a
//!   capability to shared memory, which the sender must already hold.
//! - **No cross-CPU wake ordering guarantee.** Waking is prompt on the waker's
//!   own CPU and takes an IPI otherwise; either way the woken thread runs when
//!   its CPU next schedules.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::sched;
use crate::sync::{Rank, SpinLock};

/// Rendezvous matched, message never handed over.
///
/// A match takes the partner out of the endpoint's queue and counts a delivery
/// while holding the table lock, but the handover happens after that lock is
/// released. If the handover fails there is no longer a queue entry to put
/// back, so the message is gone and both threads wait for each other. Counted
/// rather than ignored: `delivered` would otherwise report a rendezvous that
/// did not happen.
static DROPPED: AtomicU64 = AtomicU64::new(0);

/// Handovers whose wake found the partner not blocked.
///
/// Not an error on its own — the partner may not have marked itself blocked
/// yet, and will find the message when it checks. Counted to tell that case
/// apart from a genuinely lost wakeup.
static WAKE_MISSED: AtomicU64 = AtomicU64::new(0);

/// Calls to [`recv`] that returned a message to their caller.
static RECV_RETURNED: AtomicU64 = AtomicU64::new(0);

/// Times a queued receiver checked its mailbox and found it empty.
///
/// One such check per `recv` is expected — the receiver marks itself blocked
/// and looks before sleeping. Many more mean it is being woken and finding
/// nothing, which is a different failure from never being woken at all.
static RECV_EMPTY: AtomicU64 = AtomicU64::new(0);

/// Calls to [`reply`] that were attempted, whatever came of them.
static REPLY_TRIED: AtomicU64 = AtomicU64::new(0);

/// Receives that gave up because what they were waiting on had gone.
///
/// Counted apart from the other refusals because it is the one a *service*
/// cannot survive: `serve` exits when a receive is refused, so one of these
/// ends a service permanently and every later caller queues behind nothing.
static ABANDONED_RECVS: AtomicU64 = AtomicU64::new(0);

/// How many receives gave up on an endpoint that had gone.
#[must_use]
pub fn abandoned_recvs() -> u64 {
    ABANDONED_RECVS.load(Ordering::Relaxed)
}

/// Replies whose caller was no longer waiting to receive one.
static REPLY_NO_CALLER: AtomicU64 = AtomicU64::new(0);

/// A ring of the last few rendezvous events, for when the counters agree on
/// something impossible.
///
/// Counters say how often; they cannot say in what order, or between whom. A
/// stalled rendezvous is a question about ordering between three threads, so
/// the ring records `(what, who, with-whom)` and the self-test prints it when
/// it fails.
static TRACE: [AtomicU64; TRACE_LEN] = [const { AtomicU64::new(0) }; TRACE_LEN];
static TRACE_AT: AtomicU64 = AtomicU64::new(0);

const TRACE_LEN: usize = 48;

/// What a [`TRACE`] entry records.
#[derive(Clone, Copy)]
#[repr(u64)]
enum Event {
    SendMatched = 1,
    SendQueued = 2,
    RecvMatched = 3,
    RecvQueued = 4,
    RecvTook = 5,
    Replied = 6,
    ReplyRefused = 7,
}

fn trace(event: Event, who: u32, with: u32) {
    let what = event as u64;
    let slot = TRACE_AT.fetch_add(1, Ordering::Relaxed) as usize % TRACE_LEN;
    let packed = what << 56 | u64::from(who) << 28 | u64::from(with);
    TRACE[slot].store(packed, Ordering::Relaxed);
    // RFC 0026 step 5: the same record, onto the plane. Every rendezvous
    // event already funnels through here, which is what makes this the one
    // emission point rather than seven. Emit takes no lock, so calling it
    // with an endpoint held is sound.
    let mut pairing = [0u8; 12];
    pairing[..4].copy_from_slice(&(what as u32).to_le_bytes());
    pairing[4..8].copy_from_slice(&who.to_le_bytes());
    pairing[8..].copy_from_slice(&with.to_le_bytes());
    let domain = crate::telemetry::domain_hint();
    crate::telemetry::emit(
        bhaskix_telemetry::EventClass::Syscall,
        bhaskix_telemetry::schema::RENDEZVOUS.id,
        domain,
        &pairing,
    );
}

/// Replays the trace ring, oldest first, as `(event name, who, with)`.
pub fn replay(mut visit: impl FnMut(&'static str, u32, u32)) {
    let at = TRACE_AT.load(Ordering::Relaxed) as usize;
    let first = at.saturating_sub(TRACE_LEN);
    for index in first..at {
        let packed = TRACE[index % TRACE_LEN].load(Ordering::Relaxed);
        let name = match packed >> 56 {
            1 => "send matched",
            2 => "send queued",
            3 => "recv matched",
            4 => "recv queued",
            5 => "recv took",
            6 => "replied",
            7 => "reply refused",
            _ => continue,
        };
        visit(
            name,
            ((packed >> 28) & 0xfff_ffff) as u32,
            (packed & 0xfff_ffff) as u32,
        );
    }
}

/// Endpoints that can exist at once.
pub const MAX_ENDPOINTS: usize = 32;

/// Mirrors each endpoint's `live` flag outside the table lock.
///
/// A blocked receiver has to notice that its endpoint died *while holding its
/// runqueue lock* -- that is the only way the decision and the blocked mark can
/// be one step. [`live`] cannot serve: it takes the table lock, and a table
/// lock nested under a runqueue lock is an inversion against every path that
/// takes them the other way round.
///
/// Written false before [`destroy`] clears the queues and before it wakes
/// anyone, so a receiver either reads false here or is woken afterwards.
static LIVE: [AtomicBool; MAX_ENDPOINTS] = [const { AtomicBool::new(false) }; MAX_ENDPOINTS];

/// Whether an endpoint still exists.
///
/// The only way to ask. A table-lock version existed and was deleted rather
/// than kept beside this one: it cannot be called from where the question
/// actually matters -- under a runqueue lock -- and a second, more obvious
/// spelling of "is it alive" is a trap for whoever reaches for it there.
fn live(id: EndpointId) -> bool {
    LIVE.get(id.0 as usize)
        .is_some_and(|live| live.load(Ordering::Acquire))
}

/// Threads that can be queued on one endpoint in each direction.
///
/// Fixed, because the IPC path must not allocate. A queue that fills refuses
/// the call rather than growing, which is a denial of service against one
/// endpoint instead of against the whole machine.
pub const MAX_QUEUED: usize = 16;

/// A message: everything an invocation carries in registers.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Message {
    /// Which operation, chosen by the sender within the object's interface.
    pub method: u64,
    /// Four scalars. Anything larger is a capability to shared memory.
    pub args: [u64; 4],
    /// Who is calling, written by whoever granted the endpoint capability.
    ///
    /// Set by the nucleus from the capability actually used, never from
    /// anything the sender supplied — that is the entire point.
    pub badge: u64,
}

/// A thread waiting to send, and what it is sending.
#[derive(Clone, Copy, Debug)]
struct PendingSend {
    thread: u32,
    message: Message,
}

/// Why an IPC operation failed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum IpcError {
    /// No such endpoint, or it has been destroyed.
    NoSuchEndpoint,
    /// The endpoint's queue in that direction is full.
    Congested,
    /// No endpoint slots left.
    Exhausted,
    /// The reply capability names a caller that is no longer waiting.
    NoSuchCaller,
    /// The thread that owed this caller a reply has died.
    ///
    /// Not the same as the endpoint being gone: the capability is still valid,
    /// and the endpoint may be served again by something else. What was lost is
    /// the obligation, which lived in one thread.
    ServerGone,
    /// The rendezvous refused this call: a staged gift could not be
    /// completed, and the message was never delivered. RFC 0022 step 2.
    /// Carries the refusal's own status, raw, because "the service never
    /// declared" and "your capability lacked `GRANT`" are different mistakes
    /// and only one of them is the caller's.
    Refused(u32),
}

/// A rendezvous point.
struct Endpoint {
    generation: u32,
    /// Senders with a message, waiting for someone to take it.
    senders: [Option<PendingSend>; MAX_QUEUED],
    /// Receivers waiting for a message.
    receivers: [Option<u32>; MAX_QUEUED],
    live: bool,
}

impl Endpoint {
    const fn empty() -> Self {
        Self {
            generation: 0,
            senders: [None; MAX_QUEUED],
            receivers: [None; MAX_QUEUED],
            live: false,
        }
    }

    /// Removes and returns the sender that has waited longest.
    ///
    /// First-in-first-out in both directions. Waking the most recent arrival
    /// is cheaper to implement and starves the oldest caller under sustained
    /// load, which is the worst time to discover it.
    fn take_sender(&mut self) -> Option<PendingSend> {
        let slot = self.senders.iter().position(Option::is_some)?;
        self.senders[slot].take()
    }

    fn take_receiver(&mut self) -> Option<u32> {
        let slot = self.receivers.iter().position(Option::is_some)?;
        self.receivers[slot].take()
    }

    fn queue_sender(&mut self, pending: PendingSend) -> Result<(), IpcError> {
        let slot = self
            .senders
            .iter()
            .position(Option::is_none)
            .ok_or(IpcError::Congested)?;
        self.senders[slot] = Some(pending);
        Ok(())
    }

    fn queue_receiver(&mut self, thread: u32) -> Result<(), IpcError> {
        let slot = self
            .receivers
            .iter()
            .position(Option::is_none)
            .ok_or(IpcError::Congested)?;
        self.receivers[slot] = Some(thread);
        Ok(())
    }

    /// Removes a thread from both queues, and says how many entries went.
    ///
    /// For a thread that stopped waiting some other way — it was killed, or
    /// its domain was destroyed. A stale entry would have a later rendezvous
    /// deliver a message to a thread that is not there.
    ///
    /// That sentence was written when this was, and for three milestones
    /// nothing called it for either reason: the only caller was `recv`
    /// cancelling *itself*. See [`cancel_all`].
    fn remove(&mut self, thread: u32) -> usize {
        let mut cleared = 0;
        for entry in &mut self.senders {
            if entry.is_some_and(|pending| pending.thread == thread) {
                *entry = None;
                cleared += 1;
            }
        }
        for entry in &mut self.receivers {
            if *entry == Some(thread) {
                *entry = None;
                cleared += 1;
            }
        }
        cleared
    }

    fn queued(&self) -> (usize, usize) {
        (
            self.senders.iter().filter(|s| s.is_some()).count(),
            self.receivers.iter().filter(|r| r.is_some()).count(),
        )
    }
}

struct Table {
    endpoints: [Endpoint; MAX_ENDPOINTS],
    /// Rendezvous completed: a message handed from a sender to a receiver.
    delivered: u64,
    /// Replies delivered.
    replied: u64,
}

impl Table {
    const fn new() -> Self {
        Self {
            endpoints: [const { Endpoint::empty() }; MAX_ENDPOINTS],
            delivered: 0,
            replied: 0,
        }
    }
}

static TABLE: SpinLock<Table> = SpinLock::new(Rank::Endpoints, Table::new());

/// An endpoint's identity.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct EndpointId(u32);

impl EndpointId {
    /// The raw index.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self.0
    }

    /// Rebuilds an identity from a raw index.
    #[must_use]
    pub const fn from_u32(id: u32) -> Self {
        Self(id)
    }
}

/// What a rendezvous produced, for the caller to act on after the lock is
/// released.
///
/// Returned rather than performed, because acting means waking a thread and
/// possibly blocking this one — and neither may happen while the endpoint
/// table is held. Separating the decision from its effects is also what makes
/// the decision testable.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Rendezvous {
    /// A partner was waiting; wake it.
    Matched { partner: u32, message: Message },
    /// Nobody was waiting; this thread is queued and must block.
    Queued,
}

/// Creates an endpoint.
///
/// # Errors
///
/// [`IpcError::Exhausted`] if the table is full.
pub fn create() -> Result<EndpointId, IpcError> {
    let mut table = TABLE.lock();
    let index = table
        .endpoints
        .iter()
        .position(|endpoint| !endpoint.live)
        .ok_or(IpcError::Exhausted)?;
    let generation = table.endpoints[index].generation;
    table.endpoints[index] = Endpoint {
        generation,
        senders: [None; MAX_QUEUED],
        receivers: [None; MAX_QUEUED],
        live: true,
    };
    LIVE[index].store(true, Ordering::Release);
    Ok(EndpointId(index as u32))
}

/// Destroys an endpoint, returning how many threads were still queued on it.
///
/// Those threads are woken rather than left blocked: a destroyed endpoint that
/// silently kept its waiters asleep would be indistinguishable from a service
/// that is merely slow, for ever.
pub fn destroy(id: EndpointId) -> usize {
    let waiters = {
        let mut table = TABLE.lock();
        let Some(endpoint) = table.endpoints.get_mut(id.0 as usize) else {
            return 0;
        };
        if !endpoint.live {
            return 0;
        }

        let mut waiters = [0u32; MAX_QUEUED * 2];
        let mut count = 0;
        for pending in endpoint.senders.iter_mut().flatten() {
            waiters[count] = pending.thread;
            count += 1;
        }
        for thread in endpoint.receivers.iter_mut().flatten() {
            waiters[count] = *thread;
            count += 1;
        }

        endpoint.live = false;
        // Before the queues are cleared and before anyone is woken: a receiver
        // that looks after this point gives up on its own.
        LIVE[id.0 as usize].store(false, Ordering::Release);
        endpoint.generation = endpoint.generation.wrapping_add(1);
        endpoint.senders = [None; MAX_QUEUED];
        endpoint.receivers = [None; MAX_QUEUED];
        (waiters, count)
    };

    // Outside the table lock: waking takes a runqueue lock, and the two must
    // not nest in both directions.
    let (threads, count) = waiters;
    for thread in threads.iter().take(count) {
        sched::wake(*thread);
    }
    count
}

/// Sends a message on `id` and blocks until a reply arrives.
///
/// `badge` identifies the caller and must come from the capability the sender
/// presented — never from the sender itself.
///
/// # Errors
///
/// [`IpcError::NoSuchEndpoint`] or [`IpcError::Congested`].
pub fn call(id: EndpointId, badge: u64, method: u64, args: [u64; 4]) -> Result<Message, IpcError> {
    // The badge is a separate parameter, not a field of a message the caller
    // hands over, and that is deliberate. A `Message` argument would let any
    // caller supply its own badge — which is precisely what a badge exists to
    // prevent. Only the dispatcher can produce one, by reading it from the
    // capability actually used, so the structure of this signature is what
    // makes forgery impossible rather than a check somewhere.
    let message = Message {
        method,
        args,
        badge,
    };

    let Some(me) = sched::current_thread_id() else {
        return Err(IpcError::NoSuchEndpoint);
    };

    let outcome = rendezvous_send(
        id,
        PendingSend {
            thread: me,
            message,
        },
    )?;

    match outcome {
        Rendezvous::Matched { partner, message } => {
            // A receiver was already waiting. Hand it the message and wake it,
            // then block for the reply -- the mailbox is written before the
            // wake, or the receiver could run and find nothing.
            if !sched::deliver(partner, message, me) {
                DROPPED.fetch_add(1, Ordering::Relaxed);
            }
            if !sched::wake(partner) {
                WAKE_MISSED.fetch_add(1, Ordering::Relaxed);
            }
        }
        Rendezvous::Queued => {}
    }

    // Mark first, check second, and that order is the whole correctness of
    // this loop.
    //
    // Checking first leaves a window: the reply can be delivered and the wake
    // sent between the check and the mark, and a wake finds a thread that is
    // not blocked yet, so it does nothing. The thread then blocks with its
    // answer already sitting in its mailbox, for ever. That is the M4-09 lost
    // wakeup in a place with no wait queue to fuse the two steps, and it
    // measured as an IPC test that completed three rounds in eight seconds
    // with both clients stuck mid-call.
    //
    // Marking first closes it from both sides. A reply delivered *before* the
    // mark is found by the check below; one delivered *after* it sets this
    // thread ready, and `block_self` returns without sleeping.
    loop {
        // Reply, keep waiting, or give up -- decided and marked under one hold
        // of the runqueue lock, so a tick cannot land between the decision and
        // the mark and leave this thread blocked with nothing left to wake it.
        match sched::take_message_or_block(me, || live(id)) {
            sched::Delivery::Message((reply, _)) => return Ok(reply),
            // The server took this call and then died. Distinct from the
            // endpoint going away, which is what `Abandoned` means here: the
            // endpoint is still perfectly good and may have another server on
            // it tomorrow. What has gone is the obligation, and it lived in one
            // thread. RFC 0013's unresolved question 1.
            sched::Delivery::Revoked => return Err(IpcError::ServerGone),
            sched::Delivery::Abandoned => return Err(IpcError::NoSuchEndpoint),
            // The server's receive path could not complete this thread's
            // staged gift; the message was never delivered. RFC 0022 step 2.
            sched::Delivery::Refused(status) => return Err(IpcError::Refused(status)),
            sched::Delivery::Blocked => sched::block_self(),
        }
    }
}

/// Blocks until a message arrives on `id`.
///
/// Returns the message and the thread to reply to.
///
/// # Errors
///
/// [`IpcError::NoSuchEndpoint`] or [`IpcError::Congested`].
/// What a blocking receive came back with.
///
/// RFC 0010 question 1: a thread that has bound a notification is woken by
/// whichever arrives first, so a receive has two ways to succeed.
pub enum Received {
    /// A message, and who sent it.
    Message(Message, u32),
    /// The bound notification's badge word, taken whole.
    Notified(u64),
}

/// Blocks until a message arrives on `id`.
///
/// The plain shape, for callers that have bound no notification. See
/// [`recv_either`] for the one that can also be woken by a signal.
///
/// # Errors
///
/// [`IpcError::NoSuchEndpoint`] if the endpoint dies or the thread is stopped.
pub fn recv(id: EndpointId) -> Result<(Message, u32), IpcError> {
    match recv_either(id)? {
        Received::Message(message, from) => Ok((message, from)),
        // Only a thread that bound a notification can be told about one, and a
        // caller asking for this shape did not.
        Received::Notified(_) => Err(IpcError::NoSuchEndpoint),
    }
}

/// Blocks until a message arrives **or the bound notification fires**.
///
/// RFC 0010 question 1, answered 2026-08-13. A service that must answer callers
/// while something it did not ask for may arrive had, until this existed, to
/// poll: `bin/ipd` looked at its ring about 37 times per frame.
///
/// # Errors
///
/// [`IpcError::NoSuchEndpoint`] if the endpoint dies or the thread is stopped.
pub fn recv_either(id: EndpointId) -> Result<Received, IpcError> {
    let Some(me) = sched::current_thread_id() else {
        return Err(IpcError::NoSuchEndpoint);
    };

    // Anything already pending, before committing to a rendezvous. A signal that
    // arrived while this thread was busy is work in hand, and queueing as a
    // receiver first would sleep on top of it.
    let waiting = crate::notify::take_bound(me);
    if waiting != 0 {
        return Ok(Received::Notified(waiting));
    }

    // The outer loop exists for one reason: a refused gift. RFC 0022 step 2
    // completes a caller's staged gift here, **on the server thread**, at
    // whichever of the two match points the rendezvous took — and when the
    // gift cannot be completed, the caller is refused and this thread must go
    // back to *being a receiver*, which its match consumed. Continuing the
    // outer loop re-runs `rendezvous_recv`, which re-queues it; anything less
    // leaves a server absent from the receive queue with every later caller
    // stranded, which is the strander this file already documents twice.
    loop {
        match rendezvous_recv(id, me)? {
            // A sender was already waiting; its message is in hand.
            Rendezvous::Matched { partner, message } => {
                match crate::syscall::complete_gift(partner, id.as_u32(), me) {
                    Ok(_) => {}
                    Err(status) => {
                        sched::refuse_call(partner, status);
                        continue;
                    }
                }
                RECV_RETURNED.fetch_add(1, Ordering::Relaxed);
                sched::set_reply_target(me, partner);
                return Ok(Received::Message(message, partner));
            }

            // Queued as a receiver. A sender that arrives writes the message
            // into this thread's mailbox *before* waking it, so a wake with an
            // empty mailbox is spurious rather than an empty answer — which is
            // why this rechecks rather than trusting the wake.
            // Mark first, check second — see `call` for why the other order
            // loses messages.
            Rendezvous::Queued => loop {
                match sched::take_message_or_block(me, || live(id)) {
                    sched::Delivery::Message((message, from)) => {
                        // The sender matched this thread while it was blocked
                        // and delivered into its mailbox; its gift completes
                        // now, before the server sees the message — a service
                        // must never observe a message whose capability half
                        // was dropped. On refusal the caller is told and this
                        // thread rejoins the receive queue via the outer loop:
                        // its queue entry was consumed by the very match that
                        // delivered this mailbox.
                        match crate::syscall::complete_gift(from, id.as_u32(), me) {
                            Ok(_) => {}
                            Err(status) => {
                                sched::refuse_call(from, status);
                                break;
                            }
                        }
                        RECV_RETURNED.fetch_add(1, Ordering::Relaxed);
                        trace(Event::RecvTook, me, from);
                        sched::set_reply_target(me, from);
                        return Ok(Received::Message(message, from));
                    }
                    // Either the endpoint was destroyed under us, or this
                    // thread has been told to stop. Both leave the same duty:
                    // take the queue entry out, or a later rendezvous delivers
                    // to a thread that has gone.
                    sched::Delivery::Abandoned | sched::Delivery::Revoked => {
                        cancel(id, me);
                        ABANDONED_RECVS.fetch_add(1, Ordering::Relaxed);
                        return Err(IpcError::NoSuchEndpoint);
                    }
                    // Refusals are flagged on callers by servers; a thread
                    // blocked in *receive* is never flagged. Defensive rather
                    // than reachable, and treated as the abandonment it would
                    // have to be if it ever were.
                    sched::Delivery::Refused(_) => {
                        cancel(id, me);
                        ABANDONED_RECVS.fetch_add(1, Ordering::Relaxed);
                        return Err(IpcError::NoSuchEndpoint);
                    }
                    sched::Delivery::Blocked => {
                        // **Message first, notification second.** `take_message_
                        // or_block` has just marked this thread blocked and
                        // found no message; only now is the bound notification
                        // read. A thread that looked at the notification first,
                        // and cancelled on finding bits, could throw away a
                        // message a sender had already written into its mailbox
                        // -- stranding that sender for ever.
                        //
                        // The mark-blocked-then-check order is what makes the
                        // read safe against a signal arriving right here: the
                        // signaller wakes this thread, so `block_self` returns
                        // at once and the loop looks again.
                        let bits = crate::notify::take_bound(me);
                        if bits != 0 {
                            // **The blocked mark must come off before this
                            // returns.** `take_message_or_block` marked this
                            // thread blocked — that is what makes reading the
                            // notification race-free — and a thread that
                            // returns still carrying the mark runs only until
                            // the next reschedule believes it, switches away,
                            // and never comes back: the wake that would have
                            // corrected the mark is the one this line just
                            // consumed. Whether the thread survived used to
                            // depend on whether the signaller's wake landed
                            // before or after the mark — a coin toss taken on
                            // every notified receive, and RFC 0020 step 5's
                            // one-in-three stall.
                            sched::clear_blocked_mark(me);
                            // Out of the receive queue, or a later rendezvous
                            // delivers to a thread that has stopped waiting.
                            cancel(id, me);
                            return Ok(Received::Notified(bits));
                        }
                        RECV_EMPTY.fetch_add(1, Ordering::Relaxed);
                        sched::block_self();
                    }
                }
            },
        }
    }
}

/// Answers a caller.
///
/// # Errors
///
/// [`IpcError::NoSuchCaller`] if the caller is no longer waiting.
pub fn reply(caller: u32, message: Message) -> Result<(), IpcError> {
    let Some(me) = sched::current_thread_id() else {
        return Err(IpcError::NoSuchCaller);
    };
    REPLY_TRIED.fetch_add(1, Ordering::Relaxed);

    // A reply may go to the thread this one received from, and to no other.
    //
    // `deliver` writes a message into whichever thread it is given and wakes
    // it, so without this a server could answer a question nobody asked it:
    // pick any thread id, plant a message in its mailbox, and wake it holding
    // what looks like the reply it was waiting for. That was reachable from
    // ring 3, because `Reply` is a system call and the caller was a number in
    // a register. It is now taken from what this thread actually received.
    //
    // Taken and not read, so an answer is owed exactly once.
    match sched::take_reply_target(me) {
        Some(owed) if owed == caller => {}
        Some(owed) => {
            // Put it back: this thread still owes an answer, to somebody else.
            sched::set_reply_target(me, owed);
            REPLY_NO_CALLER.fetch_add(1, Ordering::Relaxed);
            trace(Event::ReplyRefused, me, caller);
            return Err(IpcError::NoSuchCaller);
        }
        None => {
            REPLY_NO_CALLER.fetch_add(1, Ordering::Relaxed);
            trace(Event::ReplyRefused, me, caller);
            return Err(IpcError::NoSuchCaller);
        }
    }

    if !sched::deliver(caller, message, me) {
        // **Put the obligation back.** `take_reply_target` above has already
        // removed it, and returning here without restoring it drops an answer
        // that is still owed: the caller stays blocked, and the server no
        // longer owes anything, so neither `exit`'s `abandon_caller` nor the
        // domain's teardown will ever release it. That is a thread asleep for
        // the life of the machine, and nothing reports it.
        //
        // The branch six lines above — a reply aimed at the wrong caller —
        // already does this, with the comment *"Put it back: this thread still
        // owes an answer, to somebody else."* This path wanted the same
        // sentence and did not have it.
        //
        // Correct for both ways `deliver` fails. If the caller's mailbox is
        // occupied, the answer is still owed and the server may retry. If the
        // caller has gone, the obligation now names a thread that no longer
        // exists, and `abandon_caller` answers `false` for it harmlessly.
        //
        // Found on 2026-08-21 by `test-faults`' `user` arm, which failed about
        // one run in four with the caller never released — and was called a
        // 120-second hang for a week, because the harness deleted the log that
        // said otherwise.
        sched::set_reply_target(me, caller);
        REPLY_NO_CALLER.fetch_add(1, Ordering::Relaxed);
        trace(Event::ReplyRefused, me, caller);
        return Err(IpcError::NoSuchCaller);
    }
    trace(Event::Replied, me, caller);
    TABLE.lock().replied += 1;
    sched::wake(caller);
    Ok(())
}

/// `(dropped, wake_missed, recv_returned, reply_tried, reply_no_caller, recv_empty)`.
///
/// Enough to tell apart the ways a rendezvous can stall: a message that was
/// never handed over, a wakeup that found nobody, a receiver that never came
/// back from `recv`, and a reply with no one left to take it.
#[must_use]
pub fn diagnostics() -> (u64, u64, u64, u64, u64, u64) {
    (
        DROPPED.load(Ordering::Relaxed),
        WAKE_MISSED.load(Ordering::Relaxed),
        RECV_RETURNED.load(Ordering::Relaxed),
        REPLY_TRIED.load(Ordering::Relaxed),
        REPLY_NO_CALLER.load(Ordering::Relaxed),
        RECV_EMPTY.load(Ordering::Relaxed),
    )
}

/// `(delivered, replied)` since boot.
#[must_use]
pub fn statistics() -> (u64, u64) {
    let table = TABLE.lock();
    (table.delivered, table.replied)
}

/// Threads queued on an endpoint, as `(senders, receivers)`.
#[must_use]
pub fn queued(id: EndpointId) -> Option<(usize, usize)> {
    let table = TABLE.lock();
    let endpoint = table.endpoints.get(id.0 as usize)?;
    endpoint.live.then(|| endpoint.queued())
}

/// Removes a thread from an endpoint's queues.
pub fn cancel(id: EndpointId, thread: u32) {
    let mut table = TABLE.lock();
    if let Some(endpoint) = table.endpoints.get_mut(id.0 as usize)
        && endpoint.live
    {
        endpoint.remove(thread);
    }
}

/// Removes `thread` from **every** endpoint's queues, and says how many entries
/// went. Called when a thread dies.
///
/// # Why this exists, and why its absence was not obvious
///
/// [`cancel`] needs to be told which endpoint. A thread blocked in `call` knows
/// -- it is the one it is calling -- and cancels itself on the way out. A thread
/// that *dies* knows nothing, because it does not run again: it is killed by
/// another domain, or it faults, or its domain is destroyed under it. There was
/// no way to ask "take this thread out of wherever it is waiting", so nothing
/// did, and `Endpoint::remove` sat there documented for exactly this case with
/// no caller for it.
///
/// The entries do not decay. Each endpoint has [`MAX_QUEUED`] slots in each
/// direction, so a machine that creates and destroys domains -- which is what a
/// supervisor does, and what this kernel's own self-tests do on every boot --
/// loses slots permanently, a few at a time. When the last one goes, every
/// later caller is answered [`IpcError::Congested`], for ever, and a service
/// whose *receive* is refused exits. That is not back-pressure, which is what
/// `Congested` is supposed to mean. It is a countdown.
///
/// Swept across all endpoints rather than recorded per thread: a thread waits
/// on at most one, so the sweep finds nothing almost every time, and the
/// alternative is a second piece of state that has to be kept true on every
/// path that queues, dequeues, matches or dies.
pub fn cancel_all(thread: u32) -> usize {
    let mut table = TABLE.lock();
    let mut cleared = 0;
    for endpoint in &mut table.endpoints {
        if endpoint.live {
            cleared += endpoint.remove(thread);
        }
    }
    if cleared > 0 {
        STRANDED_CLEARED.fetch_add(cleared as u64, Ordering::Relaxed);
    }
    cleared
}

/// Queue entries removed by [`cancel_all`] since boot.
#[must_use]
pub fn stranded_cleared() -> u64 {
    STRANDED_CLEARED.load(Ordering::Relaxed)
}

static STRANDED_CLEARED: AtomicU64 = AtomicU64::new(0);

/// Queue entries naming a thread that no longer exists.
///
/// The gate on [`cancel_all`], and it fails without it: the kernel's own
/// self-tests create domains, call services from them and destroy them, so a
/// boot that leaves entries behind leaves them where this can see them.
///
/// Takes the endpoint table first and a runqueue second, which is the declared
/// order (`Endpoints` is 8, `SchedRunqueue` is 10) and so is allowed to block
/// for both.
#[must_use]
pub fn stranded_entries() -> (usize, usize, usize) {
    let table = TABLE.lock();
    let (mut senders, mut receivers, mut dead) = (0, 0, 0);
    for endpoint in &table.endpoints {
        if !endpoint.live {
            continue;
        }
        for pending in endpoint.senders.iter().flatten() {
            senders += 1;
            if !sched::thread_is_live(pending.thread) {
                dead += 1;
            }
        }
        for receiver in endpoint.receivers.iter().flatten() {
            receivers += 1;
            if !sched::thread_is_live(*receiver) {
                dead += 1;
            }
        }
    }
    (senders, receivers, dead)
}

fn rendezvous_send(id: EndpointId, pending: PendingSend) -> Result<Rendezvous, IpcError> {
    let mut table = TABLE.lock();
    let Some(endpoint) = table.endpoints.get_mut(id.0 as usize) else {
        return Err(IpcError::NoSuchEndpoint);
    };
    if !endpoint.live {
        return Err(IpcError::NoSuchEndpoint);
    }

    if let Some(receiver) = endpoint.take_receiver() {
        table.delivered += 1;
        trace(Event::SendMatched, pending.thread, receiver);
        return Ok(Rendezvous::Matched {
            partner: receiver,
            message: pending.message,
        });
    }

    let me = pending.thread;
    endpoint.queue_sender(pending)?;
    trace(Event::SendQueued, me, 0);
    Ok(Rendezvous::Queued)
}

fn rendezvous_recv(id: EndpointId, me: u32) -> Result<Rendezvous, IpcError> {
    let mut table = TABLE.lock();
    let Some(endpoint) = table.endpoints.get_mut(id.0 as usize) else {
        return Err(IpcError::NoSuchEndpoint);
    };
    if !endpoint.live {
        return Err(IpcError::NoSuchEndpoint);
    }

    if let Some(sender) = endpoint.take_sender() {
        table.delivered += 1;
        trace(Event::RecvMatched, me, sender.thread);
        return Ok(Rendezvous::Matched {
            partner: sender.thread,
            message: sender.message,
        });
    }

    endpoint.queue_receiver(me)?;
    trace(Event::RecvQueued, me, 0);
    Ok(Rendezvous::Queued)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(method: u64, badge: u64) -> Message {
        Message {
            method,
            args: [0; 4],
            badge,
        }
    }

    fn sending(thread: u32, method: u64) -> PendingSend {
        PendingSend {
            thread,
            message: message(method, 0),
        }
    }

    #[test]
    fn a_receiver_takes_the_sender_that_waited_longest() {
        // First-in-first-out. Taking the newest arrival is cheaper and starves
        // the oldest caller under sustained load, which is the worst time to
        // find out.
        let mut endpoint = Endpoint::empty();
        endpoint.live = true;
        endpoint.queue_sender(sending(1, 100)).unwrap();
        endpoint.queue_sender(sending(2, 200)).unwrap();

        let first = endpoint.take_sender().expect("a sender is queued");
        assert_eq!(first.thread, 1);
        assert_eq!(first.message.method, 100);
        assert_eq!(endpoint.take_sender().map(|s| s.thread), Some(2));
        assert_eq!(endpoint.take_sender().map(|s| s.thread), None);
    }

    #[test]
    fn receivers_are_taken_in_arrival_order_too() {
        let mut endpoint = Endpoint::empty();
        endpoint.live = true;
        endpoint.queue_receiver(7).unwrap();
        endpoint.queue_receiver(8).unwrap();
        assert_eq!(endpoint.take_receiver(), Some(7));
        assert_eq!(endpoint.take_receiver(), Some(8));
        assert_eq!(endpoint.take_receiver(), None);
    }

    #[test]
    fn a_full_queue_refuses_rather_than_dropping_a_caller() {
        // Congestion must be an error the sender sees. Silently dropping would
        // leave it blocked for a reply to a message nobody has.
        let mut endpoint = Endpoint::empty();
        endpoint.live = true;
        for thread in 0..MAX_QUEUED as u32 {
            assert_eq!(endpoint.queue_sender(sending(thread, 0)), Ok(()));
        }
        assert_eq!(
            endpoint.queue_sender(sending(99, 0)),
            Err(IpcError::Congested)
        );
    }

    #[test]
    fn cancelling_removes_a_thread_from_both_directions() {
        // A thread that stopped waiting some other way -- killed, or its
        // domain destroyed -- must leave no entry behind, or a later
        // rendezvous delivers a message to a thread that is not there.
        let mut endpoint = Endpoint::empty();
        endpoint.live = true;
        endpoint.queue_sender(sending(5, 0)).unwrap();
        endpoint.queue_receiver(5).unwrap();
        endpoint.queue_receiver(6).unwrap();

        endpoint.remove(5);
        assert_eq!(endpoint.queued(), (0, 1));
        assert_eq!(endpoint.take_receiver(), Some(6));
    }

    #[test]
    fn the_two_queues_are_never_both_occupied() {
        // The rendezvous invariant: a sender and a receiver waiting at once
        // would be two threads blocked on each other. Whichever arrives second
        // must match rather than queue.
        let mut endpoint = Endpoint::empty();
        endpoint.live = true;

        endpoint.queue_receiver(1).unwrap();
        // A sender arriving now finds the receiver and does not queue.
        assert_eq!(endpoint.take_receiver(), Some(1));
        assert_eq!(endpoint.queued(), (0, 0));

        endpoint.queue_sender(sending(2, 0)).unwrap();
        assert!(endpoint.take_sender().is_some());
        assert_eq!(endpoint.queued(), (0, 0));
    }

    #[test]
    fn a_badge_travels_with_the_message_and_not_with_the_sender() {
        // The badge is written by whoever granted the endpoint capability, so
        // it is a property of the *route* rather than of the thread. Two
        // threads using differently-badged capabilities are distinguishable;
        // one thread using two of them is too.
        let mut endpoint = Endpoint::empty();
        endpoint.live = true;
        endpoint
            .queue_sender(PendingSend {
                thread: 1,
                message: message(0, 0xa11ce),
            })
            .unwrap();
        endpoint
            .queue_sender(PendingSend {
                thread: 1,
                message: message(0, 0xb0b),
            })
            .unwrap();

        assert_eq!(endpoint.take_sender().unwrap().message.badge, 0xa11ce);
        assert_eq!(endpoint.take_sender().unwrap().message.badge, 0xb0b);
    }
}
