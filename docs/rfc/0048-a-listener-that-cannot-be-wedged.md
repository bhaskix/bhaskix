# RFC 0048: a listener that cannot be wedged

| | |
|---|---|
| **Status** | ✅ **ACCEPTED 2026-08-24 — step 1 only, and accepted *as a deliberate deviation from a MUST*.** One `SYN` from a peer that vanishes held `bin/tcpd`'s single accepted slot for **242 seconds**, refusing every later connection **silently**; `MAX_SYNACK_RETRANSMITS` takes that to **14 seconds**, measured both times by driving the state machine. **The question this document said should block its acceptance was answered, and answered against it.** RFC 1122 §4.2.3.5: *"R2 for a SYN segment MUST be set large enough to provide retransmission of the segment for at least 3 minutes."* Fourteen seconds is not 180, and the old compliant value is exactly what made the listener wedgeable. **The project lead accepted with the deviation recorded rather than hidden**: availability over the letter, taken knowingly. Steps 2–4 — SYN cookies — are specified and **not built**, and they are what removes the trade rather than repricing it: with no state allocated for a peer that has proved nothing, there is no half-open connection for `R2` to govern |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | net |
| **Milestone** | Phase 2 — Core Operating System |
| **Depends on** | [RFC 0020](0020-tcp.md) (the TCP service), [RFC 0021](0021-unpredictability.md) (the entropy the key needs), [RFC 0047](0047-refusing-a-connection-to-a-port-nobody-holds.md) (found it) |

---

## Summary

One `SYN` from an address that need not exist takes any Bhaskix listener out of
service for **242 seconds**, and every connection offered during that window is
refused **silently**. It costs the attacker one packet, no handshake, no
capability and no authority. This RFC shortens the window to **14 seconds**
now — measured, not estimated — and specifies the change that stops the
attacker creating state at all: **SYN cookies**, for which the keyed hash
already exists in this tree.

## Motivation

### The defect

`bin/tcpd` has **one** accepted slot. A `SYN` for the listener's port births a
connection in `State::SynReceived` and sends `SYN·ACK`. If the peer never
completes the handshake — because it never intended to, or because it has
vanished — that connection holds the slot until the retransmission budget runs
out. `accept_syn` then refuses every later `SYN` as `SlotBusy`, and that
refusal is **silent by design** (the peer is expected to retry). The listener is
deaf, and looks healthy from the inside: its program is still blocked in
`ACCEPT`, its service is still serving, and nothing is counted anywhere a person
looks.

**How long, exactly.** Driven through the state machine on the host, firing each
retransmission at the instant the machine itself asks for it:

| | |
|---|---|
| Half-open hold, before this RFC | **242 seconds** |
| Retransmissions in that time | 8, backing off from 1 s and capped at 60 s |

242 seconds was *measured*. It is worth saying that an earlier arithmetic
estimate in this same investigation said 183, which is why the number in this
document comes from a test and not from adding up constants.

### Why it is worse than it looks

- **It needs nothing.** No capability, no handshake, no reachable address. A
  single unsolicited packet.
- **It renews.** One packet every four minutes holds the slot indefinitely.
- **It is silent at both ends.** The attacker's victim sees no error, and the
  legitimate client sees no refusal — only a connection that never completes,
  which since [RFC 0047](0047-refusing-a-connection-to-a-port-nobody-holds.md)
  is the one shape this stack was specifically taught not to produce.
- **It already happens by accident.** With the refusal reasons temporarily
  separated for one boot, a *passing* boot of the ordinary suite read **two**
  slot-busy refusals and a failing one read one. Ordinary boots survive this by
  luck, not by design.

This is `docs/security.md`'s T-class availability property, and it applies to
every listener this system will ever offer — including `httpd`, which
[RFC 0039](0039-pingala-a-native-web-server.md) intends to be reachable.

## Design

### Step 1 — a connection nobody has proved they wanted gets less patience

`MAX_RETRANSMITS` is eight for every connection. It is split:

```rust
pub const MAX_SYNACK_RETRANSMITS: u8 = 3;
```

and `retransmit` chooses by state — `SynReceived` gets the `SYN·ACK` budget,
everything else keeps the eight it had. Named after Linux's
`tcp_synack_retries`, which is the same knob, per the project's standing rule
that a name a Linux user would guess is the right name.

The argument is about **whose** patience is being spent. An established
connection has proved the peer exists; waiting for it costs that connection.
A half-open connection was created by one packet, and waiting for it costs
*somebody else's connection*, out of a table this service refuses at the size
of.

**Measured effect: 242 s → 14 s.** No new timer, no new memory, no new
arithmetic — the give-up path is the one that was already tested.

**Nothing in `bin/tcpd` changes.** Its slot reclamation is already lazy: a
`SYN` arriving when the held connection is `Closed` or `TimeWait` frees the slot
and births in the same call, so the shorter budget is all that was needed.

### The limit of step 1, stated rather than discovered

**Fourteen seconds is a reduction, not a fix.** An attacker sending one `SYN`
every fourteen seconds still owns the slot essentially all of the time. Step 1
buys back the accidental case and the casual one; it does not buy back the
deliberate one. That is why this RFC does not stop here.

### A specification question this document could not settle, and then did

*Written as an open risk, and resolved on the day of acceptance.*
`MAX_RETRANSMITS`'s own comment invokes *"RFC 1122's hundred-second floor for
`R2`"*. RFC 1122 sets a **separate** floor for `R2` on a `SYN`, and the value of
it was not known when this section was drafted, there being no copy of the
document on this machine. It was recorded as an open risk rather than asserted
from recall — and then the document was fetched and read:

> *"However, the values of R1 and R2 may be different for SYN and data
> segments. In particular, **R2 for a SYN segment MUST be set large enough to
> provide retransmission of the segment for at least 3 minutes.** The
> application can close the connection (i.e., give up on the open attempt)
> sooner, of course."*
> — RFC 1122 §4.2.3.5

**180 seconds is the floor. Step 1 gives 14.** The original open-risk note
follows, struck through, because what it feared turned out to be the case:

> ~~**Step 1 may put this stack below a floor RFC 1122 sets for `SYN`
> retries.** What is not known is the exact number the specification names.~~
> **It was read on 2026-08-24: the floor is 180 seconds and step 1 gives 14.
> This is below it — a violation of a MUST, not an uncertainty.**

~~**Whoever accepts this RFC should read RFC 1122 §4.2.3.5 first.**~~ It was
read first, and it said the thing that would have been least convenient to
assume. Of the two honest resolutions this section named — raise the constant,
or record a deliberate deviation — **the second was taken**, because raising it
restores the denial of service this RFC exists to remove. The deviation is
recorded in the status line, in the constant's own doc comment with the
sentence quoted beside it, and in [security.md](../security.md).

### Steps 2–4 — SYN cookies, which make step 1 stop mattering

The real fix is to **create no state until the peer proves it received the
`SYN·ACK`**. On a `SYN`, instead of allocating a slot, the initial sequence
number *is* a cookie: a keyed hash over the four-tuple and a coarse timestamp.
The peer's `ACK` carries `cookie + 1` back, and only then — when the reply
proves the peer received something only it could have received — is a
connection built.

**The machinery already exists.** `isn::initial_sequence(&key, connection, now)`
already computes a keyed SipHash over exactly the four-tuple, against a key
drawn from `RDRAND` at start-up and refused if entropy is absent
([RFC 0021](0021-unpredictability.md)). What is missing is the verify direction
and the timestamp encoding, not the primitive.

What this costs, honestly: the cookie has to encode enough to rebuild the
connection (the peer's window scale and MSS have nowhere else to live), which is
the standard difficulty and the reason cookies are usually a *fallback* engaged
under pressure rather than the always-on path.

- **Step 2**: the cookie's encode/verify as pure, host-tested arithmetic in
  `bhaskix-net` — including a forged `ACK` being refused, and a cookie
  from an expired window being refused.
- **Step 3**: `bin/tcpd` builds a connection from a verified cookie, and the
  slot is taken at that moment rather than at the `SYN`.
- **Step 4**: the gate — the wedge attempted and survived.

## Alternatives considered

| Alternative | Why rejected | Would reconsider if |
|---|---|---|
| **A bounded backlog of half-open slots** | It reprices the attack rather than closing it: a backlog of *n* costs the attacker *n* packets instead of one, and *n* is bounded by a table this service refuses at the size of. It is also the option that adds the most memory and the most new arithmetic, for a property cookies give for none | It turns out cookies cannot carry what a connection needs to be rebuilt, which is the known difficulty with them |
| **A separate `Timer::HalfOpen` deadline** | Genuinely considered and rejected as bigger for the same result: a fifth `Timer` variant, a fifth slot in `bin/tcpd`'s `Deadlines` array, and arm/cancel logic in two crates — where a state-dependent limit reuses the give-up path that is already tested. An absolute deadline is clearer about *what* it bounds; it is not worth two crates of new state to say it | The bound needs to be independent of the RTO estimate — for instance if a future RTO floor makes three retransmissions too brief on a real path |
| **Free the slot eagerly on `Action::Closed`** | Not an alternative — it changes nothing. The slot is reclaimed by the next `SYN` anyway, and the window being complained about is the time before `Closed`, not after | — |
| **Do nothing; RFC 0047 already improved matters** | 0047 made this *worse* to leave alone, not better: now that a shut port is refused promptly, a wedged listener is the one remaining way this stack makes a peer hang, and it is the reachable one | — |
| **SYN cookies only, skipping step 1** | Rejected for sequencing, not merit. Step 1 is a constant and a branch, measured at 17× and shipped today; cookies are an ISN-scheme change that wants its own review. Shipping the cheap 17× while the real fix is reviewed is not a substitute for it, and this document says so in its own step list | — |

## Impact on existing design documents

- [docs/security.md](../security.md) — this is a denial of service reachable
  without authority, which its threat model owes a row.
- [RFC 0020](0020-tcp.md) — its table of situations has a *"Connection table
  full"* row reasoning that a fixed table refusing is this project's posture.
  That reasoning assumed the table fills with connections **somebody asked
  for**. It does not survive one packet from nobody, and the row should say so.
- [RFC 0039](0039-pingala-a-native-web-server.md) — a web server is the first
  listener here meant to face strangers; its risk section inherits this.

## Security implications

**This RFC exists to close an availability hole, and step 1 only narrows it.**
Between step 1 and step 3 the honest statement is: *a listener can be denied by
a peer willing to send one packet every fourteen seconds.*

Step 3 changes what an unauthenticated peer can cause to be allocated — from a
table slot to nothing at all — which is the same instinct as the rest of this
system: **no state for anyone who has not proved anything**. It also makes the
listener's ISN a function of a secret, which it already is.

No new parser. No new authority. The cookie key is the key
[RFC 0021](0021-unpredictability.md) already requires and already refuses to
run without.

## Performance implications

Step 1: none. A constant and a branch on the give-up path, which runs once per
abandoned connection.

Step 3: a SipHash per `SYN` where today there is a table write — measurable, and
to be measured against the existing ISN hash, which is the same cost and is
already paid on the same path.

## Testing plan

**Host, and this is where the property lives.** The give-up budget is pure
arithmetic over the state machine and is tested directly:

- A half-open connection reaches `Closed` after exactly `MAX_SYNACK_RETRANSMITS`
  retransmissions, **and in 14 seconds** — the number asserted, not just the
  state, because *"it closes eventually"* was already true at 242 seconds.
- **An established connection keeps all eight.** This is the more important of
  the two: shortening the wrong connections would drop live streams on a lossy
  path, which is a worse defect than the one being fixed.

Watched red three ways, each taking down exactly the test that names it:
removing the split (the half-open test fails, back to 242 s), shortening
*everything* (the established test fails — **and so does the pre-existing
`a_peer_that_never_answers_is_abandoned_after_a_bounded_number_of_tries`**,
which is the guard against the worse bug working), and changing the constant
(the fourteen-second assertion fails).

**QEMU: no gate for step 1, and the reason is stated rather than skipped.**
A half-open connection cannot be produced through `hostfwd` on demand, because
slirp is a full TCP stack and completes the guest-side handshake itself — the
one that occurred during the RFC 0047 investigation was an accident of slirp
abandoning a socket mid-handshake, not something a test can ask for. A gate
that cannot be armed is a gate that proves nothing. **Step 4 is where the gate
belongs**, because a service that allocates nothing on a `SYN` can be shown
surviving a flood the harness *can* produce.

## Unresolved questions

1. ~~**What floor does RFC 1122 set for `R2` on a `SYN`?**~~ **ANSWERED
   2026-08-24, by reading it, and answered against this RFC.** §4.2.3.5:
   *"However, the values of R1 and R2 may be different for SYN and data
   segments. In particular, R2 for a SYN segment MUST be set large enough to
   provide retransmission of the segment for at least 3 minutes. The
   application can close the connection (i.e., give up on the open attempt)
   sooner, of course."* The floor is **180 seconds**; step 1 gives **14**. So it
   is a **violation**, not a trade — accepted deliberately, because the
   compliant value is the one that let a single packet deny service.

   Two things bound it, and both are follow-ups rather than excuses. The
   specification's own escape hatch is the *application* giving up sooner,
   which this system could adopt — the listening program choosing its own
   patience, defaulting to compliant — and has not; that is the smallest way
   back to conformance and it wants an interface on `LISTEN`. And steps 2–4
   dissolve the question: cookies allocate nothing, so there is no half-open
   connection whose `R2` could be short.
2. **Do cookies become the always-on path, or a fallback under pressure?**
   Always-on is simpler to reason about and loses the options a `SYN` carried;
   a fallback keeps the fast path and adds a mode. Deferred to step 2, where
   the encoding will say which is affordable.
3. **Should `bin/tcpd`'s silent `SlotBusy` refusal stay silent once cookies
   land?** [RFC 0047](0047-refusing-a-connection-to-a-port-nobody-holds.md)
   kept it silent because *busy* is not *shut*. With cookies there is no busy
   slot to speak of, and the answer may become moot — which is the good kind of
   unresolved question.

## Implementation plan

1. **The split budget**, `MAX_SYNACK_RETRANSMITS`, with both host tests and all
   three mutations watched red. ✅ **Done 2026-08-24.**
2. The cookie's arithmetic in `bhaskix-net`: encode, verify, expire. Pure,
   `forbid(unsafe_code)`, fuzzed. ✅ **Done 2026-08-25** — `net/src/tcp/cookie.rs`.
   Twelve host tests, **six mutations each watched red**, and a `tcp_cookie`
   fuzz target that was itself watched red by breaking `verify` in the
   permissive direction. The layout is the standard one: an 8-bit counter, a
   3-bit MSS index and a 21-bit keyed hash, with the counter and the index
   **inside** the hash rather than merely beside it — otherwise a captured
   cookie can be aged backwards into validity or have its segment size raised
   to something the peer never offered, and both attacks have a test.

   **Two costs are written into the module rather than left to be discovered.**
   Twenty-one bits of hash gives a blind attacker one guess in 2²¹ per `ACK`;
   that is the construction's number and it is not large. And three bits of MSS
   means the peer's announced size is rounded **down** to one of eight, so the
   value is honoured approximately — down, always, because a segment smaller
   than the peer can accept is delivered and one larger is not.
3. `bin/tcpd` builds the connection from a verified `ACK` rather than from a
   `SYN`.
4. The gate: the wedge attempted, and survived.
