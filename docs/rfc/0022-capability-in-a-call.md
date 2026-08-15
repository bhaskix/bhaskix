# RFC 0022: A capability in a call

| | |
|---|---|
| **Status** | Draft. **Steps 1–3 and 4a implemented 2026-08-15** — a staged capability crosses at the rendezvous, refusals refuse whole and restore, a lender's death unmaps and unnames, and `bin/tcpc` hands two rings across `CONNECT` and receives the connection capability back, kernel-wired nothing. Step 4b (the stream rides the gifted rings) remains. |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | kernel, ABI |
| **Milestone** | Phase 2 — required before [RFC 0020](0020-tcp.md)'s connection capabilities |
| **Depends on** | [RFC 0008](0008-syscall-and-ipc-shape.md) (the call this rides on), [RFC 0009](0009-shared-memory.md) (the `Memory` objects that want carrying), [RFC 0016](0016-capability-in-a-reply.md) (the other half of this mechanism, whose every rule this mirrors or explains why not) |

---

## Summary

**A call may carry a capability.** A program invokes `HAND` on the endpoint capability it is about
to call, staging one capability it holds; the service invokes `EXPECT` on its own endpoint,
declaring the one slot an incoming capability may land in; and the kernel completes the transfer at
the rendezvous, atomically with the message — both declared, or the call is refused before it is
delivered. It is [RFC 0016](0016-capability-in-a-reply.md) run in the other direction, built from
the same parts, and its purpose is the same: authority moves along the channel that already exists,
addressed by the party that owns the destination, never by the party sending.

## Motivation

**Two accepted designs have now been blocked by the same missing mechanism, and the second cannot
be worked around.** RFC 0016 §"A service cannot give a caller a capability" records the state of
the world: a capability reaches a domain from the kernel at boot, or by `GRANT` — which requires
holding the recipient's `Domain` capability, and "handing the server the client is not a
solution." RFC 0016 built the reply direction and solved file handles with it. The call direction
was left unbuilt, and RFC 0020 has now hit it squarely: its `CONNECT` says the program supplies
"the two ring capabilities" — the `Memory` objects its stream lives in — and there is no way to
say that. `bin/tcpd`'s endpoint answers `LATER` today for exactly this reason.

**The workaround this forecloses is one RFC 0020 already rejected.** Without call-carried
capabilities, a TCP service must buffer streams in its own memory — the alternative RFC 0020's
table refuses because it makes the service's memory a resource a remote party spends, and because
the receive window stops being the program's own free space. That rejection was made on the
assumption the program *could* supply pages. It cannot; this RFC is the difference.

**And the shape recurs.** A program handing a service the memory a long-lived operation works on
is not TCP-specific: it is what any subscription, any watch, any streaming interface needs. The
reply direction has already been consumed by two services since RFC 0016; the call direction will
be too.

**What happens if we do nothing**: RFC 0020's connection capabilities stay unbuildable as
designed, and either ship as the rejected buffered alternative or not at all.

## Design

### One rule, stated twice

RFC 0016's mechanism is: *the sender attaches a capability it holds to a message it is already
sending; the receiver declares, one-shot and per endpoint, the single slot where it may land; the
kernel moves it with the message or not at all.* Nothing in that sentence names a direction, and
this RFC's whole proposal is to stop the implementation naming one:

- **`EXPECT`**, invoked on an endpoint capability, declares where the next capability arriving *on
  that endpoint* may land — for a caller expecting one in a reply (RFC 0016, unchanged), or for a
  service expecting one in a call (new). The declaration is one-shot, addressed to one endpoint,
  and stored per thread; the kernel already keeps it that way (`sched::set_receive_slot` is a
  per-thread `(slot, endpoint)` pair with no notion of role), so the service side is the same
  primitive invoked by a different holder.
- **`HAND`**, invoked on an endpoint capability, attaches one capability the invoker holds to the
  next message it sends on that endpoint — for a service answering a caller (RFC 0016, unchanged),
  or for a caller about to `Call` (new). Which case applies is decided by what the thread is
  doing, not by an argument: a thread holding a reply obligation is a server handing into its
  answer; a thread holding none is a caller staging for its next call.

### The caller's side: stage, then call

A server's `HAND` executes immediately — the caller is blocked in `Call`, its declaration is
readable, and the reply obligation names it. A caller's `HAND` has nobody to give to yet: the
service thread that will take its call may not even be in `Recv`. So the caller's `HAND` **stages**:
the kernel records, per thread, one pending gift — the source slot, the rights requested, and the
endpoint it is for — and the transfer happens at the rendezvous, inside the same kernel path that
moves the message.

Staging is one-shot and single-entry, like the declaration it mirrors. A second `HAND` before the
call replaces the first — the same replace-not-accumulate rule `ARM` follows, because re-staging is
how a caller says "this one instead". A staged gift is consumed by the next `Call` on that
endpoint, refused for any other endpoint, and dropped if the thread exits.

### The transfer is atomic with the message, and refusal precedes delivery

At rendezvous, with a staged gift present:

1. The kernel reads the *service* thread's declaration. No declaration for this endpoint — the
   service did not ask — and the call is **refused whole**: status `NOWHERE` to the caller, the
   message never delivered, the staged gift retained. A service must never observe a message whose
   capability half was dropped, and a caller must never have a capability installed into a service
   that was not expecting one — the second being the security half: **a caller cannot fill a
   service's slots uninvited.**
2. The gift is derived from the caller's capability — the same checks `HAND` makes today, in the
   same order: the caller must hold it, must hold it with **`GRANT`** (holding is not permission to
   pass on), and the rights and badge requested must be monotone under the derive rules. The child
   is charged to the service's domain and owned by it.
3. It is installed at the declared slot, the declaration is consumed, and the message is delivered.
   A failure in 2 or 3 refuses the call and restores the declaration, exactly as the reply
   direction restores it — a service asked for something the caller could not give is still owed
   its next legitimate capability.

### What the service holds afterwards, and when it ends

The installed capability is a **derived child of the caller's**. Everything RFC 0016 bought for
lending falls out unchanged, in the direction RFC 0020's failure table needs:

- **Revocation is transitive and immediate.** A program that dies holding a connection has its
  capabilities revoked with its domain; the service's copies of the rings die with them, and its
  next access is refused. RFC 0020's row — "`tcpd` sees the revocation, sends a `RST`, and frees
  the control block" — is this property, not new machinery.
- **The badge stays one-way.** The service receives the badge the derive produced under the
  monotonicity rules; it cannot be a name the caller invented, and services must key per-caller
  state by the badge on the *call* — kernel-stamped — never by anything about the gift.

### The confused deputy, named

A capability arriving in a call is an instruction to a service to act on somebody else's authority,
and the classic failure is the service acting on its own instead. The kernel's part of the answer
is above: the gift lands only where the service declared, carries only what the caller could grant,
and identifies nobody (the call's badge does that). The service's part is a rule this RFC states
for its consumers to follow: **a handed capability is per-caller state, stored and used only against
the badge it arrived with.** `bin/tcpd` mapping caller A's ring while answering caller B would be
this bug; its connection table is keyed by badge for exactly this reason.

### Concurrency and failure behaviour

- The staging record is per-thread, written by its own thread's syscall and read at its own
  rendezvous — no new lock, no interrupt-context access.
- The transfer runs inside the existing rendezvous path, under the locks it already holds, in the
  order: resolve declaration → derive → install → deliver. The derive and install stages reuse
  `hand()`'s two-stage discipline (the giver's CSpace and the recipient's are never held at once).
- Out of arena, out of the recipient's capability quota, rights not monotone: the call is refused
  with the specific status, the declaration restored, the gift retained. Nothing partial exists.
- A caller that stages and never calls holds one pending record until it exits; thread teardown
  drops it. A staged gift does not pin the underlying capability — if it is revoked before the
  call, the derive fails and the call is refused, which is the ordinary meaning of revocation.

### Where `unsafe` is needed

Nowhere new. The transfer is capability-table and CSpace arithmetic on paths that exist; the only
`unsafe` in the neighbourhood remains the user-memory copies of `FILL`/`DRAIN`, untouched.

## Alternatives considered

| Alternative | Why rejected | Would reconsider if |
|---|---|---|
| **Buffered streams in the service** (for RFC 0020 specifically) | Already rejected by RFC 0020's own table: service memory becomes a resource a remote party spends, and the receive window stops being the program's free space. Rejecting it there assumed pages could be supplied; building this is what makes that assumption true. | Never as the general answer; per RFC 0020, possibly as a fallback for programs too small to hold a window. |
| **`GRANT` with a service-held `Domain` capability** | RFC 0016 already rejected it in the other direction and the argument is symmetric: a service holding `Domain` over every client could install anything into them, kill them, or reach their address spaces. Authority to receive a page must not be authority over the whole program. | Never. |
| **A capability in the message registers** | The message is four words of *data* by RFC 0008, and a register value that the kernel sometimes interprets as authority is exactly the confused encoding capabilities exist to kill. The transfer must be out-of-band of the payload, kernel-mediated, and declared by the receiver. | Never. |
| **Transfer executes at `HAND` time, into the waiting receiver** | Requires the caller's `HAND` to find "the thread serving this endpoint", which may be nobody yet, several candidates, or a thread mid-teardown — and a transfer completed before the call means a refused call leaves the capability already installed. Staging and completing at rendezvous makes the transfer atomic with the one event that defines both parties. | Never; the rendezvous is the only moment both ends are known. |
| **Multi-capability calls** | One per message, as RFC 0016 chose for replies: a count turns a fixed-size transfer into a loop over somebody else's numbers on the kernel's most trafficked path. RFC 0020 needs two rings; two `HAND`+`Call` round trips at `CONNECT` cost microseconds, once per connection. | A measured caller for whom N round trips is a real cost, and even then a bounded N. |
| **A new method pair instead of overloading `EXPECT`/`HAND`** | Two names for one rule invites the two to drift, and the roles are already unambiguous from what the thread holds (a reply obligation or not) and which end of the endpoint it holds (badged or its own). | If the role inference ever admits a genuinely ambiguous state — a thread that is both mid-reply and staging a call on the same endpoint is the case to watch, and it is refused rather than guessed at (see unresolved question 2). |

## Impact on existing design documents

- **[RFC 0016](0016-capability-in-a-reply.md)** — its §"A service cannot give a caller a
  capability" describes the world this changes; a note points here. Its rules are otherwise
  untouched, which is the point.
- **[RFC 0020](0020-tcp.md)** — step 4's owed connection capabilities and `CONNECT`'s "the two
  ring capabilities" become expressible; its implementation plan consumes this.
- **[RFC 0008](0008-syscall-and-ipc-shape.md)** — no new syscall kind; `EXPECT` and `HAND` gain a
  second role each, decided by the invoker's state.
- **`docs/security.md` §1** — gains the confused-deputy paragraph: a handed capability is
  per-caller state, keyed by the call's badge.

## Security implications

**New authority movable: exactly what `GRANT`-bearing holders could already lose, one object at a
time, to services that asked.** A caller cannot install into a service uninvited (no declaration,
no delivery); a service cannot take more than the caller staged, nor from a caller that staged
nothing; neither party chooses the other's slot. The badge rules of RFC 0016 step 1 apply
unchanged, so nothing here lets any party manufacture an identity.

**The service's exposure is the new thing worth stating**: accepting capabilities in calls means a
service's CSpace now contains objects whose lifetime a *client* controls. Revocation mid-operation
is therefore an ordinary event a consuming service must handle on every access — which RFC 0020's
failure table already commits `bin/tcpd` to, and which the testing plan below makes a gate rather
than a comment.

## Performance implications

Two extra syscalls per capability-carrying call (`EXPECT` by the service once per accepted
capability, `HAND` by the caller), and one derive-plus-install inside the rendezvous. All on the
connection-setup path, never per segment or per datagram. Measured, not predicted, in step 4.

## Testing plan

- **Host**: the staging record's one-shot and replace semantics; the refusal matrix — no
  declaration, wrong endpoint, no `GRANT`, rights not monotone, quota exhausted — each restoring
  what it should; and the atomicity claim as a property: after any refusal, the service's CSpace
  and the caller's staging are exactly as before the call.
- **Watched failing**: remove the `GRANT` check and the no-grant test must go red; remove the
  declaration restore on a failed derive and the restore test must.
- **QEMU**: a program stages a `Memory` capability, calls a service that declared, and the service
  maps and writes it — asserted end to end by the caller reading what the service wrote. Then the
  revocation gate: the caller's domain is killed mid-lending and the service's next access is
  refused, watched from the service's report.
- **The consumer gate**: RFC 0020 step 4's `CONNECT` handing two rings, which is the reason this
  document exists and the only test that proves the design fits its purpose.

## Unresolved questions

1. **Does `Call`-with-gift want a distinct status for "the service exists but never expects"?**
   `NOWHERE` says what happened mechanically; a caller cannot tell "wrong service" from "service
   not ready yet". RFC 0018's `LATER` suggests services answer this at the protocol level, which
   may be enough.
2. **A thread that is mid-reply *and* stages a gift on the same endpoint** — a service calling its
   own endpoint is degenerate, but a service calling *another* service while answering is not, and
   the role inference must not misread it. The draft rule: the reply obligation decides `HAND`'s
   meaning only for the endpoint the obligation belongs to; staging on any other endpoint is a
   caller's `HAND`. To be settled by the implementation against the checks `hand()` already makes.
3. **Should a staged gift survive a failed call and apply to the retry?** Retained-on-refusal (the
   draft's answer) means a retry loop stages once; dropped-on-refusal means no stale gift can ride
   a later, unrelated call. Both are defensible; the implementation should pick after writing the
   retry loops RFC 0020's client actually needs.

   *Step 2 status:* retained. Every refusal path restores the gift before flagging the caller, so
   a retry after fixing the cause — or after the service declares — needs no second `HAND`. The
   self-test drops its refused gift explicitly, which is what any caller that decides *not* to
   retry must do. Revisit if step 4's client shows the stale-gift hazard is real rather than
   theoretical.
4. **One declaration per thread is one declaration per thread.** The `EXPECT` slot is per-thread
   state, and a gift consumes the *service thread's* declaration — the same declaration that
   thread would use as a caller expecting a capability in a reply from its own upstream. A service
   that both accepts gifts and calls upstream with `EXPECT` on the same thread is therefore
   juggling one cell for two conversations. Today's services do neither or one; if step 4's
   `tcpd` (which accepts ring gifts *and* may someday expect capabilities from `ipd`) trips over
   this, the declaration wants to be per-(thread, endpoint) like the staging record already is.

## Implementation plan

Each step leaves the tree green.

1. **The staging record and the caller-side `HAND`**: per-thread pending gift, the role inference,
   host tests for one-shot and replace. Nothing consumes it yet.

   **Done 2026-08-15.** `sched::StagedGift`, one per thread beside the declaration it mirrors;
   `hand()` infers the role from the reply obligation — answering somebody is RFC 0016's path
   unchanged, answering nobody stages. The semantics live as a method on `Thread` so the host
   holds them without a runqueue: taking clears, a mismatched endpoint leaves the gift in place,
   re-staging replaces. Both watched failing — removing the clear reddens two tests, removing the
   address check reddens the one about it. Staging validates nothing beyond argument shape, on
   purpose: the rendezvous derive is the authoritative check and must be, so a check here would be
   reassurance that expires. Open question 2's refinement (the mid-reply thread calling a *third*
   endpoint) is **not** implemented — the conservative rule ships first: any reply obligation makes
   `HAND` a server's, so that case gets today's refusal rather than a wrong success — and the
   question stays open with this note as its status.
2. **The transfer at rendezvous**: declaration lookup, derive with `hand()`'s checks, install,
   refusal matrix with restoration — the atomicity property tested on the host, the end-to-end
   hand-map-write gate in QEMU.

   **Done 2026-08-15.** The transfer runs on the **service thread**, inside `recv_either`'s two
   match points — the only places a rendezvous completes — so the caller's `Call` path needed no
   change at all. Refusal is a flag on the caller's thread entry (`refuse_call`), read where the
   caller checks for its answer; the refused status crosses as a raw `u32` and is mapped back to
   the variant it was. A refused rendezvous consumed the server's queue entry, so the server loops
   back to `rendezvous_recv` and re-queues — the alternative strands every later caller. The
   refusal matrix is a six-phase kernel self-test with a domained service and client (sanity,
   landed-where-declared, consumed-by-its-ride, refused-whole-without-GRANT, declaration restored
   by the refusal, refused-undeclared rather than delivered bare), gated in the boot test and watched failing twice: transfer stubbed out reddens
   the landing phases, the GRANT check deleted reddens the refusal phase — and showed the missing
   refusal also eats the next phase's declaration, which is the deafness the restoration rule
   exists to prevent. One finding recorded as open question 4: the declaration cell is per-thread,
   and a gift spends the same cell a service's own upstream `EXPECT` would use.
3. **The revocation gate**: a lending ended by domain death, observed from the service.

   **Done 2026-08-15.** Domain teardown now *revokes* its `Memory` objects rather than destroying
   them — `shared::destroy_owned_by` goes through `revoke`, so the pages come out of every address
   space and device window before the frames are freed. Destroying alone was the exact failure
   `revoke`'s own comment names: frames gone from the allocator's books and still writable from
   another domain — latent until this RFC, because nothing mapped an object owned by a domain that
   could die first. Then the object's death reaches its names: a new arena sweep
   (`revoke_roots_naming`) destroys every root naming the dead object and each derivation those
   roots ever handed out, tallied per owner so the *recipient's* quota charge is released — a
   service accepting a gift per connection would otherwise be spent to death by clients that
   connect and die. The QEMU gate is the self-test's lending phase: the client creates and gifts a
   `Memory` object it owns, the harness maps it as a recipient would, the client thread's exit
   ends its domain — the program-dies-holding-a-connection story, nothing staged — and afterwards
   the mapping is removed *by revocation*, the object is gone, and the service's copy resolves to
   nothing. Watched failing both ways: teardown-destroys-without-revoking reddens the unmap and
   the unnaming; revoke-without-sweep reddens the unnaming alone.
4. **RFC 0020 step 4's consumer**: `CONNECT` carries two rings, `bin/tcpd` maps them, and the
   connection capability comes back in the reply — both directions of RFC 0016's mechanism in one
   exchange, which is the sentence this RFC exists to make true.

   **Step 4a done 2026-08-15** — the exchange itself, end to end from ring 3. A new program,
   `bin/tcpc`, holds two `Memory` rings its own domain owns and a badged capability to the TCP
   service; the kernel wires *nothing* between the two programs. `CONNECT` is three legs
   (`args[2]`), one capability per call as the alternatives table records: leg 0 hands the send
   ring, leg 1 the receive ring — `bin/tcpd` declares with `EXPECT` before every receive and maps
   what lands — and leg 2's reply carries the connection capability back into the slot the client
   declared. The service now serves the handover even on a machine with no network (the old
   no-network path exited, leaving the endpoint dead and every future caller queued against it
   for ever), which makes the boot gate unconditional. Watched failing in both directions:
   service-replies-yes-but-hands-nothing reddens the client's landing probe;
   client-calls-without-staging reddens leg 0 with the service's `BARE` refusal. Two probe
   lessons worth keeping: `INFO` is not implemented for `Memory` or `Endpoint` capabilities, so
   occupancy is probed by *refusal shape* — an empty slot fails to resolve
   (`NO_SUCH_CAPABILITY`), an occupied one reaches method dispatch and is refused differently.

   **Step 4b remains**: the stream rides the gifted rings — `SEND`/`RECV` against the mapped
   pages, the demonstration moves out of the service into `bin/tcpc`, and the service's internal
   kernel-wired connection retires.
