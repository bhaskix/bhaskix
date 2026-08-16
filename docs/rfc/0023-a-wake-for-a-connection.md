# RFC 0023: A wake for a connection

| | |
|---|---|
| **Status** | ✅ **Accepted 2026-08-16**, all three steps implemented 2026-08-15 — and accepted *with* the verdict the draft did not predict, not despite it: the wake made the round-trip median slower (1.4–3.1 ms against polling's 0.5–2.2 ms), and the win is the one the round-trip metric never priced — client scheduler activity fell from 87,584 runs to 296. The mechanism is accepted for that burn and for turning the 1–3 ms wake-to-run latency into a named scheduler number; the round trip's next win lives in the wake path, not in TCP. Questions 1 and 2 stay open. |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | `bin/tcpd`, `bin/tcpc`, ABI |
| **Milestone** | Phase 2 — the first thing [RFC 0020](0020-tcp.md) step 6's numbers ask for |
| **Depends on** | [RFC 0010](0010-notifications.md) (the object this hands over), [RFC 0020](0020-tcp.md) (the connections that want waking), [RFC 0022](0022-capability-in-a-call.md) (how the capability crosses) |

---

## Summary

**A connection may carry a notification, and the service rings it.** A program gifts one
`Notification` capability alongside its rings at `CONNECT` or `LISTEN`; the TCP service signals it
whenever the connection has news — bytes delivered, bytes acknowledged, state changed. The program
blocks in `WAIT` instead of spinning in `RECV` polls. Nothing else changes: every method keeps its
meaning, a program that gifts no notification polls exactly as today, and the mechanism that moves
the capability is RFC 0022 unchanged — a fourth leg on an exchange that already has three.

## Motivation

**This is what RFC 0020 step 6 measured, not what anyone guessed.** The measured round trip floor
is 4–10× UDP's, and the named cause is the client's poll loop: every wait for establishment, for an
echo, for a close acknowledgement is a `RECV`-and-`YIELD` spin, which burns a scheduling quantum
per look and adds a reschedule of latency per event. The service already *has* the event in hand —
`Action::Delivered` and `Action::Acknowledged` come out of every `step`, and `bin/tcpd` currently
discards them with a comment that says a notification belongs there. The state machine has been
producing the wake this RFC delivers since the day it was written.

**And the shape already exists three times.** `bin/ipd` wakes `bin/tcpd` through a notification;
the kernel wakes `bin/dhcp` the same way; RFC 0019 arms deadlines through the same object. A
program waiting on a connection is the same problem, currently solved worse.

**What happens if we do nothing**: every TCP client pays a poll loop, and the measured floor
stands.

## Design

### One more gift, same exchange

`CONNECT` and `LISTEN` gain **leg 3**: `HAND` a `Notification` capability carrying `READ` and
`WRITE` — `WRITE` to ring it, `READ` because the service probes the landed gift with `PEEK`, the
refusal-shape test every gift gets — and a **nonzero** badge of the caller's choosing, then call
with `args[2] = 3`. The service maps nothing — it holds the capability and invokes `SIGNAL` on it.
Leg 3 is optional and comes **after every ring the caller intends to gift** (the service declares
gift slots in a fixed order, rings first — see the implementation notes); a handover with no leg 3
is today's polling connection, refused nothing.

One notification per handover, replace-not-accumulate, exactly as the rings behave. The badge is
the caller's own affair: a program juggling several connections gives each a different badge and
tells its wakes apart by the word `WAIT` returns, which is RFC 0010's design used as designed.

### When the service rings

After driving any event into a connection's machine, the service signals that connection's
notification if the step produced any of:

- `Action::Delivered` — bytes are in the receive ring;
- `Action::Acknowledged` — send-ring space came free;
- a state change — established, peer's half-close, reset, gone.

Coalescing is the notification object's own semantics (RFC 0010: signals before the holder looks
are one wake), so the service signals unconditionally on news and never tracks whether the holder
is awake. A wake with nothing new behind it costs the holder one spurious `RECV`, which is the
price RFC 0010 chose for every user of the object.

### What the caller does

Replace the yield in every poll loop with `WAIT` on the notification, then `RECV` as before. The
`RECV` reply remains the whole truth — the notification carries *that* something happened, never
*what* — so a program that ignores wakes entirely still works, and a program that gets a spurious
wake reads an unchanged answer and waits again.

### `ACCEPT` wakes too

The listener's handover takes its own leg 3. A `SYN` completing its handshake signals the
listener's notification; the program `WAIT`s, then polls `ACCEPT` once. The accepted connection's
stream events ring the same notification — the listener handover's rings and its notification move
to the accepted connection together, which is the transfer the rings already make.

## Alternatives considered

| Alternative | Why not |
|---|---|
| Blocking `RECV`/`ACCEPT` in the service | One reply obligation per thread (RFC 0016): a service holding a caller blocked in `RECV` cannot answer anyone else. A thread per connection reopens the memory-per-connection design RFC 0020 rejected. |
| The service creates the notification and hands it back | Works, but backwards: RFC 0009/0020's posture is that a connection costs the memory — and now the objects — of whoever opened it. The caller creating and gifting also exercises RFC 0022 in the direction that has a gate. |
| Edge information in the wake (which event, how many bytes) | RFC 0010 chose badge-bits-or-nothing, and the `RECV` reply already carries the counts. Two sources of truth about one stream is how they disagree. |

## Impact on existing design documents

- [RFC 0020](0020-tcp.md) §"Where the impurity goes": `bin/tcpd` stops discarding
  `Delivered`/`Acknowledged`. Its step 6 verdict is this RFC's motivation and is cited rather than
  restated.
- [RFC 0010](0010-notifications.md): consumed unchanged; this is its fourth user.
- [RFC 0022](0022-capability-in-a-call.md): consumed unchanged; leg 3 is one more staged gift.

## Security implications

The service holds a `READ`+`WRITE` derivation of one notification: it can wake the holder and
peek that one word, and nothing else — not signal any other object, not name any other. A malicious service can over-ring (a spurious-wake denial
of the holder's own time, bounded by the holder's willingness to `WAIT` again) and under-ring
(indistinguishable from a quiet connection, which polling `RECV` still detects — a suspicious
program keeps a coarse deadline armed, RFC 0019's job). The caller's badge crosses under RFC
0022's monotonicity rules, so a service cannot ring as somebody else.

## Performance implications

The point of the document. Expected: the poll loop's yield-spin disappears from the round-trip
path; the wake costs one `SIGNAL` (a word OR and at most one scheduler wake) per event batch.
Measured before/after by the instrument RFC 0020 step 6 already installed — the same six-boot
distribution, recorded in TRACKER next to the numbers that motivated this.

## Unresolved questions

1. **Should `SEND` stop replying?** With wakes, the reply to `SEND` is pure round trip cost; a
   one-way `Invoke` would halve the calls on the hot path. RFC 0008 makes `Call` the shape of
   service interaction; deciding to break that for one method deserves its own measurement first.
2. **Does the accepted connection want its own notification**, separate from the listener's? One
   object per handover is this draft's answer; a server juggling many accepted connections may
   want per-connection badges the single gift cannot express. The connection table is capacity
   two today; revisit when it grows.

## Implementation plan

Each step leaves the tree green.

1. **Leg 3 in `bin/tcpd`**: accept the gift on both handovers, hold the capability, signal on
   `Delivered`, `Acknowledged` and state change. No caller uses it yet; the negative gate is that
   a connection without leg 3 behaves exactly as before.
2. **`bin/tcpc` waits**: gift a notification per handover, replace every yield-spin with `WAIT`,
   and re-measure. The step 6 distribution rerun is the gate: the median round trip must move,
   and TRACKER records the before and after.
3. **The listener wake**: `ACCEPT` via `WAIT`, the host-driver gate unchanged — it must pass
   against a client that never spins.

---

**Implementation notes, 2026-08-15 — all three steps landed, and the measurement said something
the draft did not predict.**

The wake works: every gate green in both boot modes, the client's scheduler activity down from
**87,584 runs to 296** — a three-hundred-fold reduction in burn, which is the real win and the one
the round-trip metric never priced. But the round trip itself **got slower**: the wake-driven
median is 1.4–3.1 ms against polling's 0.5–2.2 ms, same min, same max, same bulk. The reason is
the topology this measures on: `bin/tcpc` and `bin/tcpd` are pinned to the same CPU, where a
yield is a near-free handoff between the only two runnable threads, while a wake pays the full
block-signal-reschedule path. Polling was only cheap because nothing else wanted the processor —
on a machine with real load the 87,584 runs are the cost that matters — but the 1–3 ms
wake-to-run latency is now a **named scheduler number**, and it, not TCP, is the next thing worth
measuring (M4-10b's timer wheel and the wake path are where it lives).

Two mechanism findings, both kept:

- **A zero badge rings nobody.** A signal ORs the signaller's badge into the word, so a wake
  gifted unbadged — and a deadline armed on an unbadged capability — sets nothing and wakes
  no one. The first wake-driven boot hung in exactly this way, on both wake sources at once,
  which was this change's watched red: the client's capabilities now carry badges, the gift
  carries the same badge because badges are one-way, and the ABI doc states the rule.
- **Rings before wakes, in the declaration order.** One `EXPECT` declaration exists per thread
  (RFC 0022 open question 4), so the service declares gift slots in a fixed order and an optional
  gift must come last — a polling caller that never sends leg 3 would otherwise block every gift
  declared behind it, for ever. Open question 4 gains its second recorded witness.

Open question 1 (`SEND` without a reply) stays open, now with a sharper prior: the reply is not
the bottleneck, the wake path is.
