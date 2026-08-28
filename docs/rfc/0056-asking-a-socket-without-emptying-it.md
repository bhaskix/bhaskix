# RFC 0056: asking a socket whether anything arrived, without emptying it

| | |
|---|---|
| **Status** | ✅ **ACCEPTED 2026-08-28** — proposed, built and accepted the same day. Gated on the lane that has a network. A hosted Linux program polls a UDP socket (quiet), sends to itself, polls again (`POLLIN`), and then **receives all four bytes** — which is what says asking took nothing. Watched red by making the peek consume: `received -11, payload 0x0`, exactly the failure this exists to prevent. **What this does not claim.** *(1)* A socket becoming readable still does not wake a parked poller — unresolved question 1 below. *(2)* TCP is refused at `socket()`, so there is nothing to report for one. *(3)* It found an older defect it deliberately does not fix: a hosted process that ends without closing leaks its socket in `bin/ipd`, whose whole supply is four |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | net |
| **Milestone** | Phase 2 — Core Operating System (L1) |
| **Depends on** | [RFC 0055](0055-a-poll-that-tells-the-truth.md) (the readiness table), [RFC 0018](0018-a-network-stack.md) and [RFC 0029](0029-ipv6.md) (the UDP services) |

---

## Summary

A socket capability gains a method that answers **whether a datagram is
waiting** and takes nothing. `poll` and `select` use it, and stop answering
`0` for every socket. This closes RFC 0055's unresolved question 1.

## Motivation

**`poll` currently lies about sockets by staying silent.** RFC 0055 answers
`Condition::Unanswered` for one — no readable, no writable, no error — and says
plainly why: a socket's readiness lives in the network service, and inventing an
answer would be inventing a fact. The consequence is a set containing only
sockets and an infinite timeout answering *now* rather than waiting, so a
program that polls a socket is told nothing has arrived, for ever.

**The obvious shortcut is the one this exists to avoid.** `RECV_FROM`
**consumes** the datagram. A readiness check built on it would take a datagram
every time a program asked whether one was there, and the program that then
called `recvfrom` would find nothing. This is precisely the mistake RFC 0055
refused for the console, where `POLL_INPUT` consumes and `PEEK_INPUT` was added
beside it. The same reasoning arrives at the same answer one layer out.

## Design

### The method

| | |
|---|---|
| `socket::PEEK_FROM` | How many bytes are waiting on this v4 socket, and take nothing |
| `socket::PEEK_FROM6` | The same for a v6 socket |

Invoked on the **socket capability**, replying `OK` with the waiting datagram's
length in `args[1]` — zero meaning nothing has arrived. It needs whatever
`RECV_FROM` needs and confers nothing further: a holder that may take a
datagram may certainly ask whether there is one.

**Two numbers and not one**, matching `SEND_TO`/`SEND_TO6` and
`RECV_FROM`/`RECV_FROM6`. That looked redundant — a socket capability belongs to
one service, which already knows the family — until `bin/ipd` was read: it
serves **both** families and matches `socket::SEND_TO if held.v6` to refuse the
v4 question asked about a v6 socket. The number carries the family so that
refusal is possible, so it is a check rather than a duplication.

### It must look at the wire first

`RECV_FROM` calls `drain_ring` before it answers, and says why: *"asking is what
makes this service look at the wire. It is asleep in `receive` and has no other
wakeup, so a client asking for a datagram is the only event it can act on."*

**The peek must do the same**, and this is not a detail. A peek that skipped the
drain would report "nothing waiting" for a datagram sitting in the ring, and a
program polling a socket would be told for ever that nothing had arrived while
its datagrams piled up unlooked-at. That is the identical fault RFC 0054 found
one layer down, where servicing the console was also what unmasked its
interrupt — and it is why this RFC states the requirement rather than leaving it
to be inferred from the neighbouring arm.

### What `poll` then says

`Condition::Socket { datagram_waiting }` replaces `Condition::Unanswered` for a
socket, and the table gains one row:

| Descriptor | Readable | Writable |
|---|---|---|
| Socket | a datagram is waiting | always |

**Always writable is the truth here rather than a convenience.** A hosted socket
is UDP — `answer_socket` refuses `SOCK_STREAM` with `EPROTONOSUPPORT` — and
`sendto` does not block: it hands the payload to the service and answers. There
is no buffer to fill and no state in which a write would wait.

`Condition::Unanswered` stays, with one holder left: `epoll`, which has no
readiness of its own until something implements it.

## Alternatives considered

**Have the adapter hold the datagram it peeked.** No service change, and the
adapter buffers one datagram per socket. Rejected for the reason the same
proposal was rejected for the console: a datagram held for a program that then
exits is a packet that arrived and went nowhere, and "was one taken?" becomes
state two call paths must agree about.

**Report every socket readable and let `recvfrom` say.** One line, and it makes
`poll` useless in the way that matters: a caller loops, reads, gets nothing,
and asks again.

**Answer readiness from the adapter's own bookkeeping.** It has none — the
datagram is in the service, and the adapter's descriptor row remembers only
which slot holds the capability.

## Impact on existing design documents

- **RFC 0055** unresolved question 1 is answered.
- `docs/security.md` is unchanged: a new method on a capability a program
  already holds, conferring strictly less than the method beside it.

## Security implications

**No new authority.** The peek needs the socket capability, which is the same
thing `RECV_FROM` needs, and it answers a number the holder could have learned
by taking the datagram. Nothing that could not already read a socket learns
anything about it.

**One fewer reason to consume.** A program that only wants to know whether a
datagram arrived no longer has to take it to find out.

## Performance implications

One service call per socket named in a `poll`, which is the same cost as the
`recvfrom` that follows it. A `poll` naming no socket pays nothing.

## Testing plan

1. **Host tests** on the readiness table's new row, watched red.
2. **A hosted Linux program** that binds a UDP socket, polls it before sending
   (expecting *not* readable), sends to itself, polls with a timeout (expecting
   readable), and then **receives the payload**. The last step is what proves
   the peek did not consume: if it had, the datagram would be gone and the
   payload assertion would fail.
3. That probe runs on the lane that has a network, and says so rather than
   passing quietly on the lanes that do not — the distinction `socket_self_test`
   already draws between *no network* and *a network the adapter was not
   granted*.
4. **Watched red** by making the peek consume, and by removing the drain.

## What was found while building it

**A hosted process that ends leaks its socket, and nothing notices.** The probe
was written to bind, poll, send and receive, and then simply end — its domain
killed like every other probe's. The *next* test on that boot, the socket probe
that has passed since RFC 0005 step 9, was then refused its own `bind` and the
adapter reported `EADDRINUSE` on a port nobody else held.

The cause is written down in `bin/linuxd` already, in the comment on
`release_socket_slot`: *"`bin/ipd` holds four sockets in a table of its own, and
nothing tells it a client has stopped caring."* Ending a domain releases the
descriptor table and the capability; it does not tell the service. Four sockets
is the whole supply, and the error every failed bind is flattened to is
`EADDRINUSE`, which named a port that was not the problem.

**This RFC closes its own probe's socket and does not fix that.** The leak is
older than this change, reachable by any hosted program that exits without
closing, and fixing it means a domain's death reaching the network service —
which is `release_owned_by`'s shape for interrupt handlers and memory objects,
applied to a service that currently has no way to hear it. It is recorded in
TRACKER as an open defect rather than folded in here, because it is not this
RFC's subject and a change that size deserves its own gate.

## Unresolved questions

1. **A socket that becomes readable does not wake a parked poller.** A `poll`
   naming only sockets with an infinite timeout still cannot park, because the
   thing that would wake it is a datagram arriving in another program's ring and
   there is no notification for that. A positive timeout works, by the same
   re-examine-on-expiry route everything else uses. Closing this needs the
   service to signal a notification the caller can be parked on, which is RFC
   0054's mechanism pointed at a different source.
2. **TCP.** Hosted stream sockets are refused at `socket()`, so there is nothing
   to report readiness for yet.

## Implementation plan

1. `socket::PEEK_FROM` and `PEEK_FROM6` in the ABI.
2. Both arms in `bin/ipd`, draining first, refusing the wrong family.
3. `Socket::pending` in `bhaskix-sock`, both families.
4. `Condition::Socket` in `bhaskix-personality`, with host tests.
5. `bin/linuxd` asks it in `condition_of`.
6. The hosted probe and its boot gate.
