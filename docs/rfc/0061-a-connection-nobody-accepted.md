# RFC 0061: a connection nobody accepted

| | |
|---|---|
| **Status** | 🔨 **Draft 2026-08-31 — steps 1, 4 and 5 built and gated; step 2 withdrawn on evidence and step 3 not built, with the reason for each below.** The denial of service is closed. The listener serves one connection at a time and **that is now a decision rather than a limit**: cookies queue peers statelessly for 64-128 s, measured at 11 connections through one slot in a single boot |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | net |
| **Milestone** | Phase 2 — networking |
| **Depends on** | [RFC 0020](0020-tcp.md), [RFC 0047](0047-refusing-a-connection-to-a-port-nobody-holds.md), [RFC 0048](0048-a-listener-that-cannot-be-wedged.md) |

---

## Summary

A peer that completes a handshake to a listening port and then closes —
**before the application has accepted it** — permanently disables that port.
Two packets, from an unauthenticated peer, at no cost, for the rest of the
boot. Every later connection is answered and then silently dropped.

This is the root cause of the TCP inbound gate's intermittent failure, filed
2026-08-24, called environmental 2026-08-26, and mis-attributed twice since.
It is also a remote denial of service, and that is the more serious half.

## The defect

`bin/tcpd` holds **one** accepted connection: `MAX_CONNECTIONS = 2`, with
`OUTBOUND = 0` and `ACCEPTED = 1`. The slot is released here, and only here:

```rust
if matches!(held.tcb.state, State::Closed | State::TimeWait) {
    service.connections[ACCEPTED] = None;
}
```

and handed to the application only here:

```rust
let established = ...is_some_and(|c| c.tcb.state == State::Established);
if established { hand } else { reply(tcp::LATER, 0, 0) }
```

Now take a peer that connects, is built into the slot by `accept_cookie`, and
closes before the application calls `ACCEPT`. Its `FIN` moves it to
**`CLOSE-WAIT`**, which is neither `Closed` nor `TimeWait`, so the slot is not
released; and it is not `Established`, so `ACCEPT` answers `LATER`. Forever,
both. Nothing can move it out of `CLOSE-WAIT`, because leaving that state
requires a `CLOSE` from the local user and **this connection has no local
user** — no application ever received it.

The port stays superficially healthy, which is what made this hard to see: it
still answers every `SYN` with a cookie, because RFC 0048 made that path
stateless. It simply can never build a connection again.

### Why the standard convicts it

**RFC 9293 §3.3.2** defines the state this connection is parked in:

> CLOSE-WAIT - represents waiting for a connection termination request from
> the local user.

and **§3.6, case 2** says who must act:

> If an unsolicited FIN arrives from the network, the receiving TCP endpoint
> can ACK it and tell the user that the connection is closing. The user will
> respond with a CLOSE […]

So `CLOSE-WAIT` is defined by an obligation on the local user. A stack that
puts a connection there while no local user exists has created an obligation
nobody can discharge. That is the bug in one sentence, and it is the
standard's own sentence.

**Stated rather than implied, because it would be easy to claim otherwise:**
RFC 9293 does *not* specify an accept queue. The backlog is Berkeley sockets
and POSIX `listen()`, not IETF. This RFC takes the *state machine* from RFC
9293 and the *queue* from POSIX, and says which is which instead of citing one
for the other.

## The evidence, measured

A packet capture of a failing boot (`filter-dump` on `net0`, `ringsoak=6500`,
`bin/tcpc` starting at 20.27 s), times relative to capture start:

```
t+20.90  first SYN reaches the guest        (slirp holds them until it exists)
t+22.19  guest SYN-ACKs, ACKs 16 bytes      <- this one takes the slot
t+22.19 .. t+32.08   eight further connections, each SYN-ACKed
         data bytes sent by the guest:  ZERO
```

The first connection is acknowledged at the data level; **not one of the eight
after it is**, because their cookie-`ACK`s reach a `accept_cookie` that
returns `None` on a busy slot, so no control block is ever built. One
connection (`48536`) retransmits its sixteen bytes three times into silence.
`bin/tcpc` polls `ACCEPT` a hundred times, is told `LATER` a hundred times, and
reports `NOBODY`.

The host driver's own trace, clock-aligned to the capture, confirms the peers
whose connections were established had by then already timed out and closed —
which is precisely the condition that wedges the slot.

## Security

`docs/security.md` gains a threat this tree has not named. The cost to an
attacker is one `SYN`, one `ACK`, one `FIN`; it needs no authority, no
credential, and no address that must exist beyond completing a handshake. The
result is that a listening port serves nobody until reboot.

RFC 0048 is titled *a listener that cannot be wedged*. It removed a
242-second half-open wedge and left a permanent post-handshake one standing
beside it, so the title is true of the attack it studied and false of the
listener. That is worth saying plainly rather than quietly widening its scope:
the paper it wrote was right, and its conclusion was too broad. Its note — *"the slot is held by a peer
that completed a handshake and is being served, not by one that sent a packet
and vanished"* — names two cases and the defect is the third: a peer that
completed a handshake, was **never delivered to an application**, and vanished.

## Steps

**Step 1 — the service is the local user for a connection nobody accepted.**
`Connection` gains a flag recording whether `ACCEPT` ever handed it out. When a
peer's `FIN` arrives for a connection that flag says nobody owns, `bin/tcpd`
issues the `CLOSE` itself — the local user's obligation under §3.6 — sends its
`FIN`, and lets the connection reach `Closed`/`TimeWait` by the existing path,
which frees the slot with no new release rule. This closes the denial of
service on its own.

**Step 2 — a backlog, POSIX-shaped, inside the existing ABI. WITHDRAWN
2026-08-31, before it was built, and the reason is a measurement.**

The queue this step proposed to add **already exists, statelessly, and is
better.** RFC 0048 made a `SYN` allocate nothing: the connection is built when
the peer's `ACK` brings a cookie home, and `cookie::TICK` gives that cookie
**64 to 128 seconds** of validity. A peer whose `ACK` arrives while the single
accepted slot is busy is not refused and not dropped — TCP retransmits its
`ACK`, and any retransmission inside that window builds the connection the
moment the slot frees. The queue is the peer's retransmit timer, and the state
it costs this machine is zero.

**Measured rather than reasoned**, on boots of the `iommu` lane with the step-4
prober running: **11 connections built through the one accepted slot in a single
boot**, 9 of them reclaimed, and the real caller still served; 6 and 3 on two
others. Sequential reuse of one slot is not a theory here, it is what the
counter prints on every networked boot.

So a backlog of control blocks would buy **latency and nothing else** — a
queued peer served at once instead of after one retransmit timeout — and it
would pay for that by holding state for peers the application has not accepted.
That is precisely the state RFC 0048 removed, re-added one layer up: attacker
-controllable, bounded only by the table's depth, and the direct ancestor of the
defect this RFC exists to fix.

**The trade, stated so it can be overruled rather than assumed.** If a hosted
server ever needs several connections *concurrently* — not sequentially — this
becomes necessary, because retransmission serialises them by construction.
Nothing in this tree needs that today: `bin/tcpc` accepts one, and the sockets
API exposes one listener. When something does, the right shape is the one
described above and the reason to build it will be concurrency, not queueing.

**Step 3 — host tests, which this defect could have been caught by. NOT BUILT,
and the reason is a finding in itself.** The state machine in `net/src/tcp/state.rs`
is host-testable and it is **not where the defect lives**: the machine moved to
`CLOSE-WAIT` correctly and every transition it made was right. The defect is in
the *ownership* rule around it — `drive_at` and the release condition in
`user/tcpd/src/main.rs`, a `no_std` binary with no test harness. So there is no
host test to write until that rule is extracted from the binary, and writing one
against `state.rs` would test the half that was already correct and pass either
way. That extraction is worth doing and is not done here; the boot gate in step 4
is what stands in for it, and a boot gate is a weaker instrument than a host test
by exactly the margin this project usually refuses to accept.

**Step 4 — a boot gate that reproduces the wedge.**
The harness opens a connection, closes it immediately without waiting, *then*
runs the existing inbound echo. Before step 1 the echo cannot be served; after
it, it is. Armed red on purpose before it is believed.

**Step 5 — the record.** `docs/security.md` threat and price, `TRACKER.md` §3
row closed with the capture as evidence, RFC 0047's and RFC 0048's notes
amended where they claim this case is handled, `make progress`.

## What this does not do

- It does not make the guest's TCP a general-purpose stack. Two connections
  become one outbound plus a small backlog; it is not a server.
- It does not change what a peer can do to a port it can reach *before* the
  fix ships, which is why step 1 is first and separable.
- The harness's own untimed read — a driver whose retry loop could not retry —
  is a real defect and is **not** this one. It is fixed separately in
  `tests/qemu/boot-test.sh`, and that fix does not close this.
