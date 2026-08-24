# RFC 0047: refusing a connection to a port nobody holds

| | |
|---|---|
| **Status** | 🔨 **Draft 2026-08-24, all four steps implemented and gated, awaiting the project lead's acceptance.** Opened the day the intermittent filed against the TCP inbound gate was measured rather than argued about — and the measurement found a defect the gate was not looking for, plus a second one this RFC deliberately does **not** fix |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | net |
| **Milestone** | Phase 2 — Core Operating System |
| **Depends on** | [RFC 0020](0020-tcp.md) (the TCP service), [RFC 0022](0022-capability-in-a-call.md) (the rings the listener's connection inherits) |

---

## Summary

`bin/tcpd` cannot refuse a connection. A `SYN` naming no connection and no
listener is dropped silently, so a peer hears nothing and retransmits into a
hole for its whole connect timeout — minutes, on an ordinary host stack. This
RFC gives the service the one answer RFC 793 §3.4 requires: a `RST`, for a `SYN`
addressed to a port no listener holds. Nothing else changes; every other
unmatched segment keeps the silence it has always had.

## Motivation

### What was found, and how

`TRACKER.md` carried an open defect filed 2026-08-24: *the TCP inbound gate
fails intermittently, and nobody knows since when.* Its own row said
**provenance remains unestablished** and named the next step. It was measured.

**First finding: the service has no way to refuse.** `send_entry` — the only
path from this program to the wire — has exactly one caller, inside
`Action::Emit`, which needs a control block. A `SYN` that matches no connection
reaches `accept_syn`, which returns `None` at its first line when no listener
exists, and the dispatcher counts it and continues. There is no code path by
which `bin/tcpd` can put a `RST` on the wire for a segment it has no connection
for. The refusal is not merely unsent; it is unreachable.

This project's own state machine says what should happen. `closed_arrival`'s doc
comment reads *"RFC 793 §3.4: answer with `RST` so the peer stops rather than
retransmitting into a hole"* — and it runs only for a control block already in
`State::Closed`, which a port nobody listens on does not have.

**Second finding: the gate that caught it was riding a coincidence.** The boot
test's host-side driver was written to reattempt once a second. Instrumented, it
never reattempted at all: in **20 boots out of 20** it opened one connection at
t≈1.5 s and blocked in a single read for 18.2 s. It retries only when `connect`
fails, and QEMU's `hostfwd` accepts on the host side whatever the guest does.

Delivery to the guest was therefore scheduled entirely by slirp's SYN-retransmit
ladder. A delayed-start sweep measured it as a fixed offset from when the *host*
connection opens, not from when the guest is ready:

| driver opens | served at | delta |
|---|---|---|
| 1.54 s | 19.64 s | 18.10 s |
| 5.52 s | 23.72 s | 18.20 s |
| 10.51 s | 28.77 s | 18.26 s |
| 14.52 s | 20.81 s | 6.29 s |

Rungs at roughly T+6.3 s and T+18.2 s. The guest becomes reachable at ≈19.6 s
— measured directly, by hammering a port nothing holds through a whole boot and
watching the first answer arrive at 19.62 s — and the shipped configuration
lands on the 19.64 s rung. **The margin is about a tenth of a second.** A boot a
fraction late misses it, the next rung is roughly twenty-four seconds later, the
guest's accept window is ten seconds, and the gate fails.

### Why this is a defect and not a test artefact

The harness is where it was found; it is not who it happens to. A peer
connecting to a shut port on a Bhaskix machine **hangs until its own connect
timeout**. On the SR550 — the first real machine this project has — anything
that probes a closed port waits minutes for an answer that never comes. Every
other stack on that network answers in microseconds.

That is also a availability property, not only a politeness one: a client that
cannot distinguish *shut* from *lost* cannot fail over.

## Design

One function, in the crate that is fuzzed and forbids `unsafe`, and one caller
in the binary that owns the ring.

**`bhaskix-net`** gains `tcp::state::reset_for(&Segment) -> Option<Emit>`: pure,
`#[must_use]`, and the sole implementation of RFC 793 §3.4's arithmetic.
`closed_arrival` becomes a two-line caller of it, so the existing state-machine
tests keep covering the path and the two cannot drift. `unsafe_budget` stays 0.

Its two shapes, and they differ in more than a field:

- A segment that acknowledged something is answered `<SEQ=SEG.ACK><CTL=RST>`,
  acknowledging nothing back — acknowledging here would claim to have received a
  stream from a connection this end does not have.
- One that acknowledged nothing — a bare `SYN` — is answered
  `<SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>`, where `SEG.LEN` counts the `SYN`'s
  own sequence number. Off by that one and the peer discards the reset as
  outside its window, which reads as the fix not working rather than as an
  arithmetic slip.
- A segment already carrying `RST` is answered with silence, or two stacks with
  nothing in common reset each other for ever.

The `ACK` flag is not set in the `Emit`: `segment::write` derives it from
whether an acknowledgement is present, and two sources for one bit is how they
disagree later.

**`bin/tcpd`** stops answering "no" and starts answering "no, because":
`accept_syn` returns `Result<usize, Unmatched>` over three reasons —
`NoListener`, `SlotBusy`, `NotOurs`. Only `NoListener` is refused on the wire.
The reply's four-tuple is the arriving segment's, swapped, and it goes out
through the same `send_entry` every other segment uses. **One line of `unsafe`**,
hoisted into its own `let` because `tools/check-unsafe-budget.py` is a line
scanner and would otherwise bill the function's tail; `unsafe_budget` 105 → 106.

### Failure behaviour

A reset needs no memory, no control block and no slot: it is built on the stack,
written to the back ring, and forgotten. If the ring is full the reset is
dropped and the peer is no worse off than before this RFC. Hostile input reaches
only `reset_for`, which is total over any parsed segment and is covered by the
segment parser's existing fuzz target.

## Alternatives considered

| Alternative | Why rejected | Would reconsider if |
|---|---|---|
| **Full RFC 793 §3.4 — reset every segment naming no connection** | Correct against the specification, and out of proportion to what is known. The shipped close sequences have never seen a reset answering a stray or late segment during teardown, and this change is being made to *remove* a timing surprise, not to add one. The narrow rule fixes the whole of the found defect | A peer is seen retransmitting into a hole for anything other than a `SYN` — a stray `ACK` after a slot is reclaimed is the likely first witness |
| **Fix the harness instead: give the driver's read a timeout** | It was built and measured, and it does not fix this. It makes the driver reattempt (attempts at 11.5, 17.5, 23.5 s, from one connection for the whole boot), which is an improvement to a test — but the guest still hangs every real peer, and the extra attempts increase the pressure on the single accepted slot that the second finding below is about. A harness change cannot fix a protocol defect, and shipping one instead would have closed the row while leaving the machine wrong | Never as a substitute. As an addition, once the accepted slot can no longer be wedged |
| **Reset when the single accepted slot is busy, too** | A reset there says *shut* when the truth is *busy for a moment*, and the existing comment at that check already chose the peer's retry as the better answer. It is also the exact case the second finding shows is currently wedged — resetting would turn a wedged listener into a listener that actively refuses everyone, which is worse | The slot becomes a queue, at which point a full queue is a real and durable refusal |
| **Leave it: this is only the boot test being flaky** | The boot test is where it was seen. The property is that a Bhaskix machine never tells a peer its port is shut | — |

## Impact on existing design documents

- [RFC 0020](0020-tcp.md) — its table of arriving events lists what happens when
  a `RST` *arrives* and never says what this end sends when nothing is
  listening. Recorded there, in place, as this project records corrections.
- [docs/security.md](../security.md) — the disclosure below.

## Security implications

**It introduces no authority and changes nothing about what is reachable
without a capability.** `bin/tcpd` already held the ring; this uses it for one
more segment shape.

**It does disclose one bit, deliberately: open versus shut.** A peer that
probes a port now learns from the answer whether anything is listening, where
before it learned the same thing from the *silence* — more slowly, and with the
same certainty. Port scanning is not made possible by this; it is made faster,
for the scanner and for every legitimate client equally. Every stack this
machine will ever talk to behaves this way, and a machine that behaves
otherwise is one whose clients cannot fail over.

**No new parser.** `reset_for` consumes an already-parsed `Segment` and is
total; the untrusted-input boundary is `Segment::parse`, which has had a fuzz
target since RFC 0020 step 3.

## Performance implications

One extra segment written per refused `SYN`, replacing a dropped one. Nothing on
any established connection's path changes, and nothing measurable is claimed.
What it removes is a *latency* on the peer's side that was not being counted:
minutes to learn a port is shut, against microseconds.

## Testing plan

**Host.** `reset_for` is pure and is tested directly rather than through a
control block, because its second caller has none: four tests over the two
shapes, the `sequence_length` count, and the reset-answers-silence rule. Each
was watched red — the `sequence_length` swapped for the payload length, the
`RST` guard deleted, and the acknowledged number ignored — and each mutation
took down exactly the test that names it, the third also taking down the
pre-existing closed-connection test, which is what proves the refactor is
load-bearing rather than cosmetic.

**QEMU.** One boot gate, on every networked placement: a host connection to a
guest port nothing holds must be **refused, and refused promptly**. The machine
gains a second `hostfwd` for that port alone; `bin/ipd` forwards TCP by address
and not by port, so the `SYN` reaches `bin/tcpd`. The probe waits for the
inbound driver's verdict first, deliberately — that file is proof the guest is
networked *and* serving, so a refusal after it is the machine refusing rather
than the machine being absent. Its verdict is three-valued for the same reason:
refused, never-refused, and never-asked. Watched red by deleting the emit: the
closed-port gate failed, alone.

**Real hardware.** Nothing here is hardware-specific and nothing needs the
SR550. It is, though, the first thing on this list that a person can check by
hand on that machine with a stock client, which is worth more than it sounds.

## Unresolved questions

1. **The single accepted slot can be wedged, and this RFC does not fix it.**
   Found while measuring the above, and it is the more serious of the two.
   `bin/tcpd` has one accepted slot. A `SYN` from a peer that then vanishes
   births a connection in `SynReceived` which occupies that slot until
   `MAX_RETRANSMITS` — eight, with backoff, far beyond any accept window — and
   every later `SYN` is refused **silently** as `SlotBusy`. The listener is
   then deaf while looking healthy.

   Measured, not supposed: with the refusal reasons temporarily separated, a
   failing boot read *one* `SlotBusy` and *zero* `NoListener`, and a passing
   boot read two `SlotBusy`. So the condition occurs on ordinary boots and is
   survived by luck.

   **This is a remote denial of service against any listener this system ever
   offers** — one packet from an address that need not exist, and nothing is
   listening any more. It is filed in `TRACKER.md`'s open defects with its
   reproduction. It is not fixed here because the fix is a design decision, not
   a bug fix: a bounded queue of half-open connections, a `SynReceived`
   deadline, or both, each with its own arithmetic to get wrong. It is the
   project lead's call, and it should be its own RFC.

2. **Does the reset need a rate limit?** Every stack that answers this way
   eventually grows one, because a reset is a reply an unauthenticated peer can
   ask for. Deferred with a trigger: when this service faces anything that is
   not the boot harness.

## Implementation plan

1. **`reset_for` in `bhaskix-net`**, with `closed_arrival` rewritten onto it,
   and four host tests each watched red. ✅
2. **`accept_syn` says why**, returning `Unmatched` over three reasons, with the
   two silent ones keeping their existing comments and gaining the reason they
   are silent. ✅
3. **`refuse` in `bin/tcpd`** — the tuple swap and the ring, one line of
   `unsafe`, and the budget raised with its reason written down. ✅
4. **The gate**: a second `hostfwd` to a port nothing holds, a three-armed
   probe, and the whole thing watched red with the emit deleted. ✅
