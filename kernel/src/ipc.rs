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

use crate::sched;
use crate::sync::{Rank, SpinLock};

/// Endpoints that can exist at once.
pub const MAX_ENDPOINTS: usize = 32;

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

    /// Removes a thread from both queues.
    ///
    /// For a thread that stopped waiting some other way — it was killed, or
    /// its domain was destroyed. A stale entry would have a later rendezvous
    /// deliver a message to a thread that is not there.
    fn remove(&mut self, thread: u32) {
        for entry in &mut self.senders {
            if entry.is_some_and(|pending| pending.thread == thread) {
                *entry = None;
            }
        }
        for entry in &mut self.receivers {
            if *entry == Some(thread) {
                *entry = None;
            }
        }
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
            sched::deliver(partner, message, me);
            sched::wake(partner);
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
        sched::mark_blocked();
        if let Some((reply, _)) = sched::take_message(me) {
            sched::cancel_block();
            return Ok(reply);
        }
        if !live(id) {
            sched::cancel_block();
            return Err(IpcError::NoSuchEndpoint);
        }
        sched::block_self();
    }
}

/// Blocks until a message arrives on `id`.
///
/// Returns the message and the thread to reply to.
///
/// # Errors
///
/// [`IpcError::NoSuchEndpoint`] or [`IpcError::Congested`].
pub fn recv(id: EndpointId) -> Result<(Message, u32), IpcError> {
    let Some(me) = sched::current_thread_id() else {
        return Err(IpcError::NoSuchEndpoint);
    };

    match rendezvous_recv(id, me)? {
        // A sender was already waiting; its message is in hand.
        Rendezvous::Matched { partner, message } => Ok((message, partner)),

        // Queued as a receiver. A sender that arrives writes the message into
        // this thread's mailbox *before* waking it, so a wake with an empty
        // mailbox is spurious rather than an empty answer — which is why this
        // rechecks rather than trusting the wake.
        // Mark first, check second — see `call` for why the other order loses
        // messages.
        Rendezvous::Queued => loop {
            sched::mark_blocked();
            if let Some((message, from)) = sched::take_message(me) {
                sched::cancel_block();
                return Ok((message, from));
            }
            if !live(id) {
                // The endpoint was destroyed under us. Leaving the queue entry
                // behind would have a later rendezvous deliver to a thread
                // that has gone.
                sched::cancel_block();
                cancel(id, me);
                return Err(IpcError::NoSuchEndpoint);
            }
            sched::block_self();
        },
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
    if !sched::deliver(caller, message, me) {
        return Err(IpcError::NoSuchCaller);
    }
    TABLE.lock().replied += 1;
    sched::wake(caller);
    Ok(())
}

/// Whether an endpoint still exists.
#[must_use]
pub fn live(id: EndpointId) -> bool {
    TABLE
        .lock()
        .endpoints
        .get(id.0 as usize)
        .is_some_and(|endpoint| endpoint.live)
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
        return Ok(Rendezvous::Matched {
            partner: receiver,
            message: pending.message,
        });
    }

    endpoint.queue_sender(pending)?;
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
        return Ok(Rendezvous::Matched {
            partner: sender.thread,
            message: sender.message,
        });
    }

    endpoint.queue_receiver(me)?;
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
