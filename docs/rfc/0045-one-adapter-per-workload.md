# RFC 0045: One adapter per workload, and the three failures that argued for it

| | |
|---|---|
| **Status** | ⬜ **Draft 2026-08-23. No code.** It collects evidence and frames a decision that is the project lead's, and it deliberately proposes nothing that could be merged before that decision is taken |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | `kernel/syscall` (the adapter routing), `bin/linuxd`, `bin/sup` |
| **Milestone** | Phase 2's Linux personality; it adds no feature |
| **Depends on** | [RFC 0031](0031-linux-compatibility-as-an-adapter.md) (**I5**, which this is about), [RFC 0005](0005-linux-abi-compatibility.md) (the tiers whose work produced the evidence), [RFC 0030](0030-packages.md) (manifest-declared authority, which is the shape a per-workload grant would take), [RFC 0033](0033-what-a-hosted-process-is.md) (what the adapter holds today) |

---

## Summary

[RFC 0031](0031-linux-compatibility-as-an-adapter.md)'s interface **I5** says
the Linux adapter is *not* a system service every hosted process shares: one
adapter domain hosts one workload's process group. The implementation is a
single `bin/linuxd`, and has been since RFC 0032 moved it out of the nucleus.
**Three independent failures on 2026-08-23 traced to that difference** — one
of authority, one of blast radius, one of availability. This RFC writes them
down together, states what closing the gap would cost, and leaves the choice
open, because it is a decision about the system's shape rather than a bug.

## Motivation

I5 is not new and its reasoning is not disputed. What is new is that the
divergence stopped being theoretical three times in one day, in three different
ways, none of which was being looked for.

### 1. Authority: one grant, every hosted program

Tier 2 needed the adapter to hold a capability to `bin/ipd`. There is one
adapter, so that grant is to *every hosted program at once*: nothing in the
system can now give one Linux workload a network and another none, because
there is one translator between them and it either holds the capability or it
does not.

`security.md` §1 **T11** already enumerates what a compromise of the adapter
reaches, and the network joined that list the same day. The entry is honest
and it is also the shape of the problem: the list exists because there is one
adapter to make a list about.

### 2. Blast radius: a leak in one program took another program's network

The socket probe exited without closing its socket. `bin/ipd` holds four; that
was the fourth; and the **shell** — which is not a hosted Linux program at all
— could no longer bind. A resource leak inside one hosted program surfaced as
an unrelated native program losing a capability it had held since boot.

The leak is fixed. What the incident shows is not the leak: it is that the
blast radius of a hosted program's mistake reached outside the hosted world,
through a service table shared by way of one adapter.

### 3. Availability: one hosted call stops every hosted program

On a machine whose network device gets no DMA window, `bin/ipd` has nothing to
answer with — but the capability to it still exists and still installs. A
hosted `bind` then blocks for ever, because a `CALL` to an endpoint nobody
receives on queues rather than failing. **`bin/linuxd` is one thread**, so that
single call stops it answering every hosted process on the machine.

This one is not fixed, and it is not a bug in the IPC design: blocking is what
a `CALL` does. It is a consequence of one thread serving every hosted program.
The self-test now avoids the situation by skipping; a real workload would not
have that option.

> **Three arguments arriving in one day, none of them sought, is the strongest
> kind of evidence this project collects** — and it is worth more than the
> original argument for I5, because that one was reasoning and these are
> incidents.

## Design

Nothing here is proposed for implementation before the decision below. What
follows is what each option would actually mean in this tree, so the decision
is taken against costs rather than against adjectives.

### What makes the adapter singular today

Two globals, and the routing that reads them:

```
ADAPTER_ENDPOINT: AtomicU64   // where a Linux syscall is sent
ADAPTER_DOMAIN:   AtomicU32   // which domain is the adapter
```

Every domain tagged `Personality::Linux` routes to that one endpoint. The tag
says *which dialect* a domain speaks; it does not say *which adapter* serves
it. That is the whole of the singularity: not a design commitment, but a pair
of atomics that were enough while there was one.

### Option A — one adapter domain per workload

The tag gains an adapter, or the domain record does: a hosted domain names the
endpoint that serves it, and `start_linux_domain` becomes something a
supervisor does per workload rather than something bring-up does once.

- **What it fixes:** all three. Authority is per workload because the grant is
  to that workload's adapter; a leak is confined to one adapter's slots; a
  blocked adapter stops one workload.
- **What it costs:** the supervisor grows a real job (`bin/sup` creates the
  adapter, grants it what the workload's manifest declares, starts the
  program), the boot report's single `linux domain` line becomes a set, and
  every one of RFC 0033's per-process records becomes per-adapter — which it
  arguably always should have been. The probes in `kernel/src/lib.rs` each
  currently assume the one adapter and would each need one.
- **What it does not fix:** nothing about the *nucleus*. This is entirely a
  ring 3 and routing change.

### Option B — one shared adapter that holds nothing

RFC 0031's own alternatives table carves this out explicitly: *"A stateless
shared service that holds no authority of its own — that is not this
alternative."* Today's `bin/linuxd` is shared **and** holds a console, a
read-only directory and a network endpoint, so it is the rejected thing rather
than the carve-out. Option B is to make the carve-out true: the adapter holds
nothing, and each hosted domain holds its own capabilities, which it passes on
the call.

- **What it fixes:** authority and blast radius. A compromise of the adapter
  reaches what the caller of the moment handed it.
- **What it does not fix:** availability. One thread still serves everybody,
  and one blocking call still stops it.
- **What it costs:** every hosted process must *hold* capabilities, which
  [RFC 0031](0031-linux-compatibility-as-an-adapter.md)'s **I3** currently
  forbids — "a hosted process holds none and cannot name one" is a stated
  invariant and a security property, not an implementation detail. Option B
  therefore trades one invariant for another and cannot be taken quietly.

### Option C — keep one adapter, and amend I5 to say so

Defensible, and the honest version of the status quo. The cost is that the
three incidents above become the accepted behaviour of the system, and I5 —
which is currently a rule the implementation breaks — becomes a rule the
implementation follows because the rule was changed to match it.

**If this is the choice, the amendment should quote all three incidents**, so
that a reader in a year sees what was known when the decision was taken.

## Alternatives considered

| Alternative | Why not proposed | Would reconsider if |
|---|---|---|
| Make `bin/linuxd` multi-threaded | Answers only the availability argument, and answers it by adding concurrency to the most authority-concentrated program in the system. The other two arguments are untouched | The decision lands on Option C and availability still has to be addressed |
| A watchdog that kills a wedged adapter | Turns a hang into a restart, and every hosted process dies with it. Treats the symptom of one thread serving everybody | Never as a substitute for the decision; possibly as belt-and-braces after it |
| Bound every `CALL` the adapter makes | A `CALL` with a deadline is a different IPC primitive, and adding one to serve this case would change the shape of every service interaction in the system | The IPC design gains deadlines for reasons of its own |
| Do nothing and record the incidents | This RFC *is* that, minus the decision. Recording without deciding is what let the divergence run for three days after RFC 0032 created it | — |

## Impact on existing design documents

- **[RFC 0031](0031-linux-compatibility-as-an-adapter.md) I5** either becomes
  true (A, B) or is amended with the evidence (C). It cannot stay as it is.
- **`security.md` §1 T11**'s note enumerates what one adapter holds. Under A it
  becomes per workload; under C it grows a sentence saying the union is
  deliberate.
- **[RFC 0033](0033-what-a-hosted-process-is.md)** describes a process as a
  record in *the* adapter. Under A, "the" becomes "its".
- **[RFC 0005](0005-linux-abi-compatibility.md)**'s step 9 record carries the
  availability incident and would point here.

## Security implications

This RFC changes nothing by itself. What it decides changes:

- **Option A** narrows every column: authority, blast radius, availability.
- **Option B** narrows authority and blast radius and **weakens I3**, which is
  currently the invariant that a hosted process holds no capability. That is a
  real trade and not a refinement.
- **Option C** narrows nothing and makes the current exposure explicit.

## Performance implications

Option A costs one domain and one thread per workload rather than per machine —
`RFC 0033`'s own numbers say a domain is cheap, and the boot report already
prices address spaces and domain slots. Nothing here is on a syscall path.
**No measurement is offered and none is claimed**; if A is chosen, the number
to take is what a second adapter costs at boot, beside the first.

## Testing plan

Whatever is chosen, the three incidents are the tests, and two of them already
have gates:

1. **Authority** — a hosted program in workload X cannot reach a capability
   granted to workload Y. Under A this is a new gate and it is the point of
   the change; under C it is a gate that cannot be written.
2. **Blast radius** — the socket-leak incident, as a test: a hosted program
   exits holding a socket, and something outside its workload still binds.
   Reproducible today by removing the reclamation added on 2026-08-23.
3. **Availability** — a hosted `bind` against a service that cannot answer,
   with a second hosted program expected to keep running. Under A it does;
   today it does not, and the socket self-test skips rather than demonstrate
   it.

## Unresolved questions

1. **Which option.** The project lead's, and the reason this RFC exists.
2. **If A: who creates the adapter?** `bin/sup` is the supervisor and RFC 0032
   gave it the interface, but nothing has yet started a *service* domain from
   ring 3 — only hosted ones. That may be a step of its own.
3. **If A: what does a workload's manifest look like?** RFC 0030 declares a
   package's authority and is the obvious shape; whether a Linux workload is a
   package is not obvious at all.

## Implementation plan

**Deliberately none.** This RFC is evidence and a decision. A plan written
before the choice would be a plan for one option, which is how a decision gets
taken by whoever writes the plan rather than by whoever should.
