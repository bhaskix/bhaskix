# RFC 0058: what a service learns without being called

| | |
|---|---|
| **Status** | ✅ **ACCEPTED 2026-08-28**, and **completed 2026-08-28 after acceptance**. *The status line accepted said "both parts built" and that was wrong*: Part B created, granted and rang the bell, and nothing ever waited on it — `bin/linuxd`'s constant for it was **never used**, which the compiler said in as many words and which shipped because the adapter was the one crate `make clippy` did not cover. The park is wired now and the wake is **proved**: a hosted program parks on the bell with no timeout, a second sends it four bytes, and the first wakes and reads them — the sender started only once the nucleus has counted a park *on the bell*, so the order is observed rather than slept for. Watched red both ways: no park (*"the poller never parked"*) and no ring (*"sent 4"*, parked, never woken). Part B is gated: the bell is granted to both sides and the boot asserts `bin/ipd` **rang** it when a datagram arrived, read by peeking the notification rather than taking it, and watched red by removing the signal. **What this does not claim.** *(1)* **Part A has no lane of its own** — proving it needs a hosted domain killed while holding a socket and another taking the same slot afterwards, which no probe here arranges; it is reasoned from the code and the correction it rests on is stated above. *(2)* ~~The parked wake is unproven~~ — **proved 2026-08-28**, see above. *(3)* The leak is **bounded, not closed** — the message arrives on slot reuse. *(4)* One bell for every socket, so a poller wakes for datagrams that were not its own |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | net |
| **Milestone** | Phase 2 — Core Operating System (L1) |
| **Depends on** | [RFC 0056](0056-asking-a-socket-without-emptying-it.md) (a socket's readiness), [RFC 0057](0057-a-park-that-names-two-wake-sources.md) (parking on a notification) |

---

## Summary

Two things a hosted program's socket needs that no call it makes can provide: a
socket **given back** when its domain is killed rather than exited, and a
**datagram that wakes** whoever is parked waiting for one. Both are the same
shape — a fact that happens outside the adapter's own call paths and has to
reach it anyway.

## A correction, first

RFC 0056's status line and TRACKER both say *"a hosted process that ends without
closing leaks its socket in `bin/ipd`"*. **That is wrong, and narrower than it
sounds.** A hosted process that *exits* — `exit_group`, a fatal fault, or
`tgkill` at itself — reaches `note_exit`, which already releases its sockets and
whose comment already describes this exact failure. What leaks is a process that
is **killed from outside**: `domain::end` tells the adapter nothing, and the one
message that eventually arrives, `FORGET_METHOD`, is sent when the domain *slot
is reused* and its handler does not release sockets.

The claim was written from one observation — a probe leaking a socket — without
reading the path that already handled the other case. It is corrected here, in
RFC 0056's own status line, and in TRACKER.

## Part A: a killed domain's socket comes back

**The handler that already exists gains the release the exit path already
does.** `FORGET_METHOD` clears the domain's signal dispositions, its sleepers
and its process record, because each would otherwise belong to whoever gets that
slot next. A socket capability is the same kind of thing and was missed.

**This bounds the leak; it does not remove it.** The message arrives when the
slot is *reused*, so a socket held by a domain killed and never replaced stays
held. That is a real improvement over "for ever" and it is not "fixed", and the
difference is stated rather than rounded.

**Why not tell the adapter at death.** `domain::end` would have to make a
blocking `ipc::call` from a path that includes the dying thread itself, the
fault handler, and boot self-tests — and, when the adapter is what is dying, a
call to itself. The kernel already sends `FORGET_METHOD` by `ipc::call`, but
from the syscall path, where the caller is a live thread that can afford to
block. Moving that into `domain::end` is a deadlock waiting for the first
supervisor that kills a program from a fault handler, and it is not worth it for
a pool of four.

## Part B: a datagram wakes a parked poller

RFC 0056 gave `poll` a truthful answer for a socket and left the waiting: a set
naming only sockets cannot park, because nothing signals when a datagram lands.

**`bin/ipd` already rings a doorbell — for TCP.** A notification is created at
boot, `WRITE` is derived for the service and it signals it when a segment
arrives. The same pattern serves datagrams: one notification, `WRITE` to
`bin/ipd` and **`READ` to `bin/linuxd`**, signalled when a datagram is delivered
to a UDP socket, and the adapter parks a socket-polling thread on it.

**`READ` for the adapter, exactly as RFC 0054 gave it the console's.** It may
wait for a datagram and may not claim one arrived, which is the same narrowing
for the same reason: a program that can signal the bell can wake a poller that
finds nothing, repeatedly.

## Alternatives considered

**A notification per socket, gifted at bind.** More precise — a poller would
wake only for its own socket — and it needs a capability to cross from client to
service, which `EXPECT`/`HAND` can express but nothing here does yet. One bell
for all datagrams costs a re-examination of the caller's set on every arrival,
which is what `poll` does anyway.

**Have `bin/ipd` learn about domains.** It has no notion of one, and giving it
one to solve a four-entry table is the wrong direction: the adapter owns the
descriptors and the capabilities, and it is the thing that already cleans up on
exit.

## Impact on existing design documents

- **RFC 0056**'s status line is corrected as above, and its unresolved question
  1 is answered by Part B.
- `docs/security.md` gains nothing: the adapter's new capability is `READ` on a
  notification, which confers waiting and not reading.

## Security implications

**Waiting, not claiming.** The adapter cannot signal the datagram bell, so it
cannot manufacture the appearance of network traffic for a hosted program.

**A shared bell is a side channel of one bit.** Any domain the adapter parks on
it learns that *some* datagram arrived, not whose. The adapter serves every
hosted program already and holds all their descriptors; this tells it nothing it
could not learn by polling the sockets it holds.

## Testing plan

1. **Part A**: a hosted domain binds a socket and is **killed**; a second hosted
   domain then takes the same slot and must be able to bind. Watched red by
   removing the release from the `FORGET` handler.
2. **Part B, what is provable here**: the bell is granted to both, and the boot
   report counts the datagram signals `bin/ipd` sends, which must be non-zero on
   a lane that moves a datagram. Watched red by removing the signal.
3. **Part B, what is not**: no lane proves a *parked* poller was woken by a
   datagram. Doing so needs a datagram to arrive while a poller is blocked,
   which needs two hosted programs — the sender delivering loopback traffic
   synchronously means a probe that sends to itself never parks at all. This is
   stated in the status line rather than left for a reader to discover.

## What was found while building it

**Two mistakes of mine, and one of them for the third time.**

**A slot collision, again.** The bell went into the adapter's slot 90, which is
the *first* of its six socket slots — so `expect_socket` could not declare a slot
a notification already held, and a hosted `bind` answered `EADDRINUSE`. That is
the third collision in this CSpace in one day (22, then 24, now 90) and the
second found by a boot rather than by reading the map. There was no gap left:
0–24 are fixed grants, 25 upward is a handle per hosted domain, 88 and 89 are
the network and its page, 90 up is the socket pool and 96 up is the file pool
counting down. The pool gave up its last slot, which costs nothing — `bin/ipd`
serves four sockets in total, so five was already one more than it can fill.

**A double release, introduced by giving the release a second caller.**
`note_exit` released a socket without clearing the descriptor's handle, which
was harmless while it was the only caller. With `FORGET` calling it too, a
record that survived the first was walked again by the second — and the slot is
reused between them, so the second release closes a socket belonging to whoever
holds it *now*. The handle is cleared on release.

**Part B was half built, and the compiler said so.** The bell was created,
granted and rung, and `bin/linuxd` never waited on it: the constant naming its
slot was dead, and `cargo` reported *"constant `DATAGRAM_BELL` is never used"*
on every build. It shipped because **the adapter was the one crate `make clippy`
did not cover** — `security.md` calls it the largest concentration of authority
in the system, and it was the one place a warning could not fail the suite.
`user/linuxd`, `user/udp6`, `user/fsd` and `user/hello` are in `make fmt` and
`make clippy` now; the adapter had a formatting drift and two other lints
waiting there as well.

**And a gate that only worked while it was useless.** The bell's own check read
the notification's *latched bit*, which is set by a signal and cleared by
whoever waits. That was proof the service had rung it — for exactly as long as
nothing waited on it. The moment a poller actually parked there, waking took the
bit and the check reported a bell that had just done its job as one that had
never rung. It counts rings now: a count survives its own success.

**And a check placed where it could only tell the truth about the wrong
moment.** The bell's report ran before the probe that sends a datagram, so it
reported a bell that had had nothing to announce yet. It is after it now.

**`bind`'s error names the wrong thing, and now says so in the trace.** Every
failure answers `EADDRINUSE` because that is the only errno this can honestly
guess at — RFC 0056 recorded that. The *trace* need not guess, and carries the
service's or the kernel's own word now: the difference between "that port is
taken" and "there are no sockets left" is what a boot spent looking like the
first while being the second.

## Unresolved questions

1. ~~**The parked wake is unproven.**~~ **Closed 2026-08-28**, with the second
   hosted program this question named. What it needed beyond the two programs
   was an *order*: a probe that sends to itself never parks, because loopback
   delivery is synchronous inside `bin/ipd`, so the sender is not started until
   the nucleus has counted a park on the bell. The count is the precondition,
   observed rather than slept for.

   It also needed two more sockets. `bin/ipd` served **four**, and this
   machine's own boot already spends three — the DHCP client for the life of
   the boot and the v6 round trip's two — so the pair's second bind was refused,
   as `EADDRINUSE` on a port nobody held. Six now, at a cost of 768 bytes.
2. **The leak is bounded rather than closed**, as above.
3. **One bell for every socket.** A poller wakes for a datagram that was not
   theirs and re-examines; correct, and more work than a per-socket
   notification would be.

## Implementation plan

1. The `FORGET` handler releases the domain's sockets, as `note_exit` does.
2. A datagram bell: created at boot, `WRITE` to `bin/ipd`, `READ` to
   `bin/linuxd`.
3. `bin/ipd` signals it where it delivers a datagram to a socket.
4. `bin/linuxd` parks on it when a wait names a socket and nothing is ready.
5. The gates and the mutations.
