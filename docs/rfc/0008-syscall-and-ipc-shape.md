# RFC 0008: The shape of the system-call and IPC interface

| | |
|---|---|
| **Status** | ✅ **Accepted 2026-08-04.** Resolves open decisions **A2**, **A3** and **A4**. |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | kernel; new subsystems `cap`, `ipc`, `syscall` |
| **Milestone** | M5 — decision required before M5-03 |
| **Depends on** | [architecture.md](../architecture.md) §3–4, [security.md](../security.md) §2, [RFC 0005](0005-linux-abi-compatibility.md) |

---

> **Accepted 2026-08-04 by the project lead**, per
> [GOVERNANCE.md](../../GOVERNANCE.md) — architecture direction and open
> decisions A1–A5 are the lead's call, after an RFC with a public rationale.
>
> What acceptance covers: the six syscall kinds and their register convention,
> capability invocation as the only route to authority, synchronous rendezvous
> as the IPC primitive, and a capability-shaped native ABI. Thirteen milestones
> were built against this document before it was accepted; that was recorded in
> `TRACKER.md` at the time as building on a recommendation rather than a
> decision, and the note now comes off.
>
> The **unresolved questions below remain open.** Two have since been answered
> by implementation rather than by argument, and `TRACKER.md` records which —
> this document is not edited to claim it foresaw them.
>
> The argument above and below this note is unchanged and, per the document
> ownership table in `TRACKER.md`, is now immutable. A change of mind is a new
> RFC that supersedes this one.

---

## Summary

Three decisions have been recorded as open since M1 and all three block M5.
They are answered together because they are one decision seen from three
angles.

| | Question | Answer |
|---|---|---|
| **A2** | Numbered syscall table, or capability invocation? | **Capability invocation.** A fixed, tiny set of syscall *kinds*; all authority arrives as a capability argument. |
| **A3** | Synchronous rendezvous, or async buffered channels? | **Synchronous rendezvous is the primitive.** Async is built above it from shared memory plus a notification capability. |
| **A4** | Native ABI: own shape, or POSIX-shaped? | **Own, capability-shaped.** POSIX and Linux are personalities, per RFC 0005. |

The common thread: **the nucleus provides mechanism that cannot be named
without authority, and refuses to hold state on anyone's behalf.**

---

## A2 — Capability invocation, not a syscall table

### The proposal

Six syscall kinds. Nothing else, ever, without an RFC.

| Kind | Meaning |
|---|---|
| `Invoke` | Perform a method on the object a capability names. |
| `Call` | `Invoke`, then block for a reply. Creates a one-shot reply capability. |
| `Reply` | Answer a `Call`, consuming the reply capability. |
| `Recv` | Block until a message arrives on an endpoint. |
| `Yield` | Give up the rest of this thread's slice. |
| `Exit` | Terminate this thread. |

Register convention on `x86_64`, chosen to fit `SYSCALL` without shuffling:

```
  rax  syscall kind                    rax  result status
  rdi  capability index (in CSpace)    rdx  reply badge / returned value
  rsi  method selector
  rdx  argument 0                      rcx  clobbered by SYSCALL (return rip)
  r10  argument 1                      r11  clobbered by SYSCALL (rflags)
  r8   argument 2
  r9   argument 3
```

`rcx` and `r11` are unavailable because `SYSCALL` overwrites them with the
return address and flags. That is why Linux uses `r10` where the C ABI would
use `rcx`, and this follows the same convention rather than inventing a
different one for no gain.

### Why not a numbered table

A numbered syscall table is a list of operations a domain may perform *because
of what it is*. That is ambient authority, and it is precisely the thing
[security.md](../security.md) §2 says the nucleus does not have. `open("/etc/shadow")`
is dangerous because the caller names a resource it was never given; the
authority was latent in being root.

With capability invocation the question "may this domain do this?" has no
separate answer — a domain that holds no capability for an object cannot
express an operation on it. There is no check to forget, because there is no
check: the argument is the authority.

### Why so few kinds

`Yield` and `Exit` do not obviously need to be syscalls at all — both could be
invocations on a capability to the calling thread. They are separate because
they are the two operations a thread performs on *itself*, which every thread
can always do, and routing them through a capability would mean every thread
holds a capability to itself in every CSpace, for no gain in expressiveness and
a real cost in bookkeeping.

Everything else is `Invoke`, `Call`, `Reply`, `Recv`. Adding a seventh kind
should feel like an architectural change, because it is one.

### The cost, stated

- **Every operation costs a CSpace lookup.** An index bounds-check and a rights
  test on the hot path, where a syscall table costs one bounds-check. This is
  the price of the model and it is not large; it is also exactly where the
  measurement should go once there is something to measure.
- **A method selector is a small numbered table in disguise**, per object kind.
  The difference that matters is that it is only reachable *through* a
  capability, so the selector is a choice among operations already authorised
  rather than a choice of authority.
- **Debuggability is worse.** `strace` on Linux shows names; here it shows an
  index into a space the tracer cannot see. The telemetry plane
  ([ai-native.md](../ai-native.md) §2) has to resolve capabilities to object
  kinds or introspection is unusable — worth designing in rather than
  discovering.

---

## A3 — Synchronous rendezvous is the primitive

### The proposal

IPC is a **rendezvous**: a sender and a receiver meet, the message is copied
directly from one to the other, and both continue. There is no buffer in the
nucleus, and therefore no queue, no queue limit, and no question of whose
memory the queue is.

- `Call` sends and blocks, creating a **one-shot reply capability** the
  receiver gets as part of the message. It cannot be copied or stored past its
  use, so a service cannot accumulate the ability to answer callers later.
- `Recv` blocks on an endpoint until a sender arrives.
- Messages are small and register-carried. Anything larger travels as a
  capability to shared memory, which the sender must already hold.

### Why not async buffered channels

Buffering means storing a message the receiver has not yet asked for, and that
raises a question with no good nucleus-level answer: **whose memory is it?**

- Charge it to the sender, and a slow receiver blocks the sender anyway — the
  synchronous behaviour, with a buffer's complexity added.
- Charge it to the receiver, and a hostile sender exhausts a victim's
  `ResourceEnvelope` by talking to it.
- Charge it to the nucleus, and there is now an unbounded kernel allocation
  driven by untrusted callers, which is the shape of every denial-of-service
  bug in this category.

Synchronous rendezvous makes the question disappear. It also makes the
scheduler's job honest: the sender's time is charged to the sender, the
receiver's to the receiver, and a `Call` can donate the remainder of the
sender's slice to the receiver so that a service request costs the *caller's*
budget rather than the service's. That is not possible with a queue, because by
the time the message is processed the sender is gone.

### But throughput

The real objection to synchronous IPC is that a request per message is the
wrong shape for high-rate I/O. The answer is not to buffer in the nucleus; it
is that high-rate I/O should not use messages at all:

> **Shared memory carries the data; IPC carries the notification.**

A ring buffer in memory both parties hold a capability to, plus a
`Notification` capability to signal when it is non-empty, gives batching,
zero-copy and no kernel involvement per item. This is the shape `io_uring`
converged on after Linux spent two decades on syscall-per-operation, and it
needs the nucleus to provide exactly one thing: a way to wake someone.

So async *is* supported. It is built one layer up, out of two primitives the
nucleus already has to provide for other reasons, and the nucleus never holds
a message.

### What this costs

- **Two context switches per request/response**, unless the reply path is
  optimised into a direct hand-off. That optimisation is well understood and
  should be measured, not assumed — the sender is blocked and the receiver is
  the obvious next thread, which is a scheduler hint rather than a special case.
- **A slow receiver blocks its senders.** That is a real property and it is the
  honest one: the alternative hides the backpressure in a queue until the queue
  is the problem.
- **`Recv` needs a timeout eventually**, or a service bug becomes a caller
  hang. Not in the first version, and recorded below as unresolved.

---

## A4 — The native ABI is capability-shaped

Already argued in [RFC 0005](0005-linux-abi-compatibility.md), which observes
that own-ABI-versus-POSIX is a false choice: the native interface is
capability-shaped, and Linux compatibility is a *personality* that translates
into it while holding no authority its domain lacks.

This RFC settles the remaining half — what the native shape actually is — and
the answer is A2's six kinds. There is no separate "native ABI" document to
write; the ABI is the syscall interface above.

Consequence worth stating: **there will be no native `libc`.** The roadmap's
Phase 2 "libc — enough for real userspace software" is a *Linux-personality*
concern. Native software links a small capability runtime instead, and that
runtime is the right place for anything that looks like a standard library.

---

## Design consequences for M5

| Piece | Shape it must have |
|---|---|
| **CSpace** | A per-domain array of capability slots. An index means nothing outside its own CSpace, which is what makes guessing useless. |
| **Derivation** | `derive(cap, rights)` requires `rights ⊆ cap.rights`, in one function, exhaustively tested. |
| **Revocation** | Transitive and complete *before the syscall returns*. This is the hardest requirement in M5 and it constrains the data structure: a derivation tree, not a flat table. |
| **Badges** | Written by the granter, unreadable and unwritable by the holder. |
| **Endpoints** | A kernel object with a wait queue of senders and one of receivers. M4-09's wait queues are the mechanism. |
| **Reply capabilities** | One-shot, non-copyable, created by `Call` and consumed by `Reply`. |

---

## Alternatives considered

| Alternative | Why rejected | Would reconsider if |
|---|---|---|
| **Numbered syscall table** (Linux shape) | Ambient authority: the operation is available because of what the caller *is*. Discards the project's central security claim on the first syscall. | Never for the native interface. It is exactly what RFC 0005's personality provides for foreign binaries. |
| **Async buffered channels as primitive** | The nucleus must own the buffer, and every answer to "whose memory" is either a denial-of-service or the synchronous behaviour with extra steps. | If measurement shows the shared-memory-plus-notification path cannot reach the throughput a real workload needs. Measure before rebuilding. |
| **Both, as peers** | Two IPC mechanisms means two sets of semantics, two failure modes, and services that pick differently. The composition of the two is where the bugs would be. | Never as peers. Async as a *library* over the primitive is the proposal. |
| **seL4's exact API** | Closest prior art and worth learning from, but it carries choices this project has not made — its own CNode addressing scheme, and a fastpath tuned for a formal proof effort that is not happening here. | Deliberately staying close in *shape* while not copying the interface. Divergence should be justified case by case. |
| **Capabilities as unforgeable 128-bit tokens** rather than CSpace indices | Removes the per-domain table, and makes revocation require finding every copy — which is the one property that must be immediate. | Never; revocation decides this. |

---

## Impact on existing design documents

| Document | What changes |
|---|---|
| [roadmap.md](../roadmap.md) | M5's "syscall dispatch" is now specified. Phase 2's "libc" should be re-labelled as belonging to the Linux personality, not to native userspace. |
| [architecture.md](../architecture.md) §3 | Gains the concrete syscall interface; the `Capability` structure there is unchanged. |
| [security.md](../security.md) §2 | Its four rules become testable statements about named functions rather than aspirations. |
| `TRACKER.md` | **A2**, **A3** and **A4** move from Open to Draft-answered, pending acceptance. |

---

## Testing plan

- **Host, and most of it.** Derivation monotonicity is a pure function over
  rights sets and should be tested exhaustively over *every* pair of rights
  masks, not sampled. Revocation is a tree operation over a fixed-size arena,
  equally host-testable.
- **The revocation gate is the important one**, because "immediate and
  transitive" is the property most likely to be quietly wrong: build a
  derivation tree several levels deep with branches, revoke an interior node,
  and assert that every descendant is invalid and every non-descendant is
  untouched — with the check running *before* the operation returns.
- **QEMU**: a domain in ring 3 performing a `Call` into a service and receiving
  a reply, and a second domain proving it cannot name the first's objects.
  Negative-tested by handing it a valid index from the other CSpace, which must
  fail rather than succeed against the wrong object.
- **Fuzz target** on syscall argument decoding, before user mode can be
  reached by anything untrusted.

---

## Unresolved questions

1. **Does `Recv` need a timeout in M5, or later?** Without one, a service bug
   hangs its callers. With one, every caller has a policy decision to make.
   Leaning towards later, with the hang being visible in telemetry.
2. **How large is a register-carried message?** Four arguments is enough for a
   selector and a handful of scalars; more means a shared buffer. The boundary
   should be set by what services actually need, and there are no services yet.
3. **Does `Call` donate the remainder of the sender's slice?** It makes service
   time charge to the caller, which is right, and it complicates the fair
   class's accounting. Worth doing, not necessarily first.
4. **How does the telemetry plane name a capability?** An index is meaningless
   outside its CSpace, so tracing needs the nucleus to resolve it to an object
   kind and identity. Designing this after the fact tends to mean not doing it.
5. **How many capability slots per CSpace, and is it fixed?** Fixed avoids
   allocation on the invocation path. It also caps how many objects a domain
   can hold, which a service might legitimately exceed.
