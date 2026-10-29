# RFC 0093: A ring pair stays with its connection until the holder lets go

| | |
|---|---|
| **Status** | ✅ **ACCEPTED 2026-10-29 by the project lead.** Drafted 2026-10-20. **The lead chose the fix before this was written**: hold the pair until the holder lets go, over asking the service before every write, or leaving the defect filed. **Every step built and gated 2026-10-20**: the rule host-tested and watched red against the old one; the `iommu` lane's loopback probe gates it (208 passed, none failed); each of three arms is red, two of them earlier than predicted, for reasons the implementation plan records. |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | net / userspace |
| **Milestone** | L1 ([roadmap.md](../roadmap.md)) — a hosted server whose bytes reach only the peer they were written for |
| **Depends on** | [RFC 0086](0086-the-motivating-workload.md) (ring pairs a listener arms, step 2), [RFC 0090](0090-a-hosted-program-that-dials-out.md) (step 5: a dial retired only once released), [RFC 0092](0092-a-listener-that-can-be-closed.md) (a listener that drains) |

---

## Summary

`bin/tcpd` retires a finished accepted connection only once the program holding it has said, with
`RELEASE`, that it is done. Its ring pair goes back to its listener then, and not before. Until
this, a finished connection was retired whoever held it, and its pair could serve the next peer
while the old holder could still write into it.

## Motivation

Found 2026-10-20 while writing RFC 0092 step 4, from the code. It has never been seen.

- **A hosted `write` writes first and learns second.** `bin/linuxd`'s `write` copies a program's
  bytes into the connection's send ring, then calls `SEND`. Only `SEND` answers `GONE` for a
  connection the service has retired.
- **The service retired early.** `bin/tcpd` retired a finished accepted connection (`CLOSED`, or
  `TIME_WAIT`, which holds the tuple and not the slot) at the next connection's birth
  (`retire_finished`). It then armed the connection's pair again for its listener.
- **So the bytes could land in someone else's stream.** A program still holding the old
  descriptor writes; the bytes land in the ring of whichever connection took that pair next. They
  overwrite bytes that connection's holder had written and the service had not yet sent, or had sent
  and not had acknowledged.
- **The likely path is ordinary.** A client resets while a server is still writing its answer, on
  a port busy enough that a new peer takes the pair in between. The Go server the preview ships is
  such a server.

`read` was never exposed: it asks the service first, and a retired connection reads as the end of
its stream.

## Design

**One rule, in `bhaskix-net` where a host test can drive it**: `state::retirable(state, claimed,
released)` — finished, and nobody holds it. Nobody holds a connection never handed to a program
(`claimed` false), or one whose holder has released it. RFC 0061's rule, `reclaim_unclaimed`, sits
beside it for the same reason: a pure function of three values belongs where it can be tested.

**`bin/tcpd` asks it everywhere a finished connection leaves**:

- at a birth (`retire_finished`);
- when a closing listener counts its children (RFC 0092's `finish_closing`);
- after each step of a connection (`drive_at`);
- at `RELEASE` itself, when the connection had already finished.

An accepted connection goes through `retire`, which arms its pair for its listener again. A dial
goes through `retire_dial`, as it has since RFC 0090 step 5. The paths for a connection nobody was
handed — RFC 0061's reclaim, and dropping one that closed — do not change.

**Every holder releases what it was handed, at close**:

- **`bin/linuxd`**: a hosted descriptor's last close shuts the connection, releases it, and
  deletes its capability. The pair goes back to the listener, not to the adapter, so nothing waits
  for `GONE` the way a dial's does. A connection the adapter took and never handed out is released
  too.
- **`bin/tcpc`**: its inbound echo, its IPv6 twin, the four-client act's four connections and its
  ghosts, and its second listener's connection.

The two halves land together. Either alone breaks something:

- tcpd's rule without tcpc's releases leaves port 7 with no pair after the four-client act, and
  RFC 0061's prober finds none;
- the releases without the rule fix nothing.

**Why the race closes rather than narrows.** A holder releases at close, and after its close no
`write` can reach that descriptor. A pair therefore cannot be armed for a new peer while any
descriptor names it.

RFC 0092 step 4's mask of pairs "a hosted row still names" was there to keep a stopped listener's
pairs back from exactly that. It is dead by construction now and goes. A row exists only until its
release, and tcpd answers that a listener has stopped only once every connection it accepted has
been released and retired.

## Alternatives considered

| Alternative | Why not | Would be right if |
|---|---|---|
| Ask the service before every write | One more call per `write`, and it narrows the race rather than closing it: the service can retire the connection between the answer and the copy | the service could not hold a pair, for some reason of its own |
| Leave it filed for the preview | A defect that corrupts another client's bytes on the path the preview ships | it could not happen on that path |
| Give a retired connection's pair back to the adapter, which arms the listener again | Two services share the bookkeeping for one pair, and the adapter learns of each retirement only by asking | the adapter needed to choose which pair a listener arms |

## Impact on existing design documents

- `abi/src/lib.rs`, `tcp::RELEASE`: it applies to an accepted connection too.
- `sock::tcp::release`: it said "a dialled connection".
- `bin/tcpd`'s `retire_finished`: it called retiring a finished connection at a birth "the same
  early release the single accepted slot always had". It still is, but only for one nobody holds.
- RFC 0092 §4: a connection that "lives on" pins its listener's slot. Since this RFC, so does
  one whose holder has not released it.
- `bin/linuxd`'s module doc: the write bullet is struck.

## Security implications

**A peer's bytes reach only the program they were sent to**, and a program's writes reach only its
own peer. Before this, a program could put bytes into another connection's send ring without
meaning to, and so onto another client's wire — in the adapter's case, between two hosted
programs.

**What a holder can now cost.** A holder that never releases keeps the connection's slot and pair
for as long as it holds them, which a dial's holder could already do. A hosted program cannot leak
them past its own end: a domain's teardown closes every descriptor, and that close releases. A
native program that dies without releasing does leak them — `bin/tcpc`, the only native one,
releases on every path that succeeds.

## Performance implications

One `RELEASE` per accepted connection, at its close. Finished connections stay in tcpd's table
until their release, where they left at the next birth before. For a program that closes promptly
the difference is the time between its peer's close and its own.

## Testing plan

- **Host:** `retirable`. A connection its holder has not released is never retirable in any of the
  eleven states. Released and finished is retirable; never handed out and finished is retirable;
  nothing unfinished is. The tests are watched red against the old rule, finished alone.
- **QEMU, gated on the `iommu` lane**, in the loopback probe:
  - a one-pair listener's connection finishes while the probe still holds its descriptor;
  - a second peer must then find no pair: nothing to accept for 300 ms;
  - once the descriptor is closed, a third peer is accepted within two seconds.
- **Arms, each booted:**
  - the old rule (the second peer is born on the held pair);
  - linuxd that does not release (the third peer is never accepted);
  - tcpc that does not release (RFC 0061's prober finds port 7 with no pair).

## Unresolved questions

None. The one question, which fix, was the lead's, and was decided before this was written.

## Implementation plan

0. **Drafted with the lead's decision.**
1. **The rule**, in `bhaskix-net`, host-tested, red against the old rule.
2. **tcpd asks it; every holder releases** — one change, because either half alone breaks
   something.
3. **The gate green and the arms red**, and the records: TRACKER, the release note's defect, the
   documents above.

**Steps 0 to 3 done 2026-10-20.**

- **Step 1.** `retirable`'s four host tests were written against the old rule first. The one that
  names the defect, `a_connection_its_holder_has_not_released_is_never_retired`, failed; with the
  rule, `bhaskix-net`'s 267 tests pass.
- **Step 2** is one change, as planned.
- **Step 3.** Green on the `iommu` lane: 208 passed and none failed — the 207 before, and this
  gate. The machine's own line reads: `a finished connection held open keeps its ring pair: a
  second peer found none until the holder closed it, then a third was accepted on it (RFC 0093)`.
  The RFC 0061 prober was still served (`tcpd reclaim 2 connection(s) ...`), and the four-client
  act still held its four.

**The arms, each booted on that lane:**

| Arm | What it read |
|---|---|
| The old rule, finished alone | `a second peer born on its pair` — **the defect's mechanism, seen on a boot for the first time**: a pair still named by an open descriptor was given to the next peer |
| linuxd does not release | red **earlier than predicted**: RFC 0092's re-listen read `listen -23`. A listener whose connections linuxd accepted now drains only once they are released, so none of its three listener slots came back. This is the coupling between RFC 0092 and this RFC, shown |
| tcpc does not release | red **earlier than predicted**: `tcp client FAILED at step 16: still mid-exchange`, and the four-client act was never attempted. The inference, which the boot's `guest answered 6 SYN(s)` fits: tcpc's IPv6 twin on port 7 needs the pair its inbound echo held, and that pair never came back. RFC 0061's own gate stayed green, because it counts a slot an application holds as in use, not wedged |

