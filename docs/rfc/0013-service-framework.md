# RFC 0013: The service framework, and what "place anywhere" has to cost

| | |
|---|---|
| **Status** | ✅ **Accepted 2026-08-05**, including the `architecture.md` correction it asks for. Resolves **SF1**. Two of its four open questions are decided by acceptance; the other two stay open and are named below. |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | kernel (`service`, `cap`, `ipc`), tools (build, CI), userspace |
| **Milestone** | Phase 2 in [roadmap.md](../roadmap.md) |
| **Depends on** | [RFC 0008](0008-syscall-and-ipc-shape.md) (the message shape), [RFC 0009](0009-shared-memory.md) (the bulk path, without which both placements are identical by accident), [RFC 0010](0010-notifications.md), [RFC 0011](0011-irq-handler.md) and [RFC 0012](0012-iommu.md) (what a service outside the nucleus is given), [architecture.md](../architecture.md) §2 |

---

## Summary

`architecture.md` §2 says Bhaskix is "a capability-based nucleus with **relocatable services**", and
that a service is a crate implementing a `Service` trait whose placement — in the nucleus or in a
domain — is a build-time choice. **None of that exists.** There is no trait, no placement
selection, and no service that has ever run outside the nucleus.

This RFC proposes the trait, the two placements, the build selection, and — the part that decides
whether any of it survives — **the CI job that builds both placements for every service, and the
QEMU run that boots with every service forced into a domain.**

It also argues that the honest caveat already written into `architecture.md` should become a
*measured* claim: the document says "write once, place anywhere" is a claim many have made and few
delivered. This RFC's position is that the claim is worth making only if a failure to deliver it is
**visible on every pull request**, and that the mechanism for that is cheap now and will not be
cheap later.

---

## Motivation

**1. The three services that exist are not services.** `service.rs` holds a console and a
filesystem that run as in-nucleus threads, reached over IPC endpoints. They are close to the shape
this RFC wants, which is encouraging, and they are reached by direct construction and share the
kernel's address space, which is the shape it does not want. Nothing stops a fourth from taking a
direct call into `vfs::open`, and once one does, the userspace placement is gone.

**2. Until RFC 0009 step 6, both placements were identical by accident.** Every message carried
four registers. There was nothing to map, so "the same code runs in either placement" was true and
meaningless. That changed at M6-18: the filesystem's read path now fills a shared region, and a
region has to be *mapped into somebody*. In the nucleus that is the direct map; in a domain it is a
`Memory` capability the service was granted. **The two placements now genuinely differ, which is
what makes a both-placements test worth running.**

**3. Everything needed to run a service in a domain now exists**, and did not a milestone ago: a
domain with a CSpace (M5), IPC with badges (RFC 0008), shared memory that can be granted and
revoked (RFC 0009), a notification to wake on (RFC 0010), an interrupt a domain may hold (RFC 0011
step 6), and a DMA window a domain may map into (RFC 0012 step 7). This RFC is the thing those five
were building toward, and it is the first one that will *use* all of them at once.

**4. The failure mode is silent and slow.** An in-nucleus service that acquires a direct call does
not break anything. It breaks the *other placement*, which nobody is building, and the breakage is
discovered a year later when someone tries. That is precisely the shape of failure this project has
spent M6 learning to catch early — nine checks that were not looking at the thing they claimed to
check — and the answer is the same one: make the property fail loudly and continuously, or do not
claim it.

---

## Design

### The trait

```rust
/// A service: state, a message handler, and nothing else.
pub trait Service {
    /// Everything the service knows. No statics, no globals.
    type State: Send;

    /// What it is called in the placement table and in the boot log.
    const NAME: &'static str;

    /// Built once, from the capabilities the placement hands over.
    fn start(context: Context) -> Result<Self::State, StartError>;

    /// One message in, one reply out. Never blocks; never panics on input.
    fn handle(state: &mut Self::State, request: Request<'_>) -> Reply;
}
```

`Context` is the whole of what a service may reach, and it is deliberately a value rather than an
ambient: whatever is not in it, the service does not have. In the nucleus placement the context is
constructed by the kernel; in the domain placement it is the domain's CSpace, and the two must
carry the *same* names for the same things or the code above them cannot be identical.

### The four rules, and what actually enforces each

`architecture.md` lists four rules. Rules stated in prose are rules that erode, so this RFC pairs
each with the thing that fails when it is broken:

| Rule | Enforced by |
|---|---|
| No global mutable state | The trait: state is `Self::State`, threaded through `handle`. A `static mut` in a service crate fails the existing `unsafe` budget gate at zero |
| No direct hardware access | The domain placement has no MMIO mapping and no direct map. It faults. The nucleus placement is where this rots, so the lint denies `bhaskix_arch::*` in service crates |
| No blocking calls | `handle` returns a `Reply`; there is nowhere to await. A service that needs to wait returns "pending" and is re-entered on a notification |
| No panics on input | `handle` returns `Reply`, and a malformed request is a reply. The panic path in a domain placement kills only that domain, which is the point — but a service that relies on that is one the nucleus placement cannot host |

The asymmetry in the last two rows is the real content of this RFC. **A service is constrained by
the intersection of both placements, not the union**, and the constraint that binds is almost
always the nucleus one: it is the placement with the fewest walls.

### Placement, and what differs

```
[services]
console  = "nucleus"
vfs      = "nucleus"
block    = "domain"
```

| | Nucleus placement | Domain placement |
|---|---|---|
| Dispatch | Direct call from the IPC receive loop | `ipc::recv` in the domain's own thread |
| Bulk buffer | A `Memory` object, reached through the direct map | The same object, mapped into the domain and named by a capability |
| Device access | The kernel's `MmioCapability` | A `DmaWindow` (RFC 0012 step 7) and an `IrqHandler` (RFC 0011 step 6) |
| A panic | Takes the machine | Takes the domain, and the supervisor sees an endpoint whose holder has gone |
| Cost | A call and a reply | Two context switches and a round trip, measured at M6-05 and M6-18 |

**The bulk path is where the two placements stop being the same code by accident.** In the nucleus,
`fill_from` writes through the direct map. In a domain, the service holds a `Memory` capability and
must map it — the same object, a different address, and *the service must not care which*. That is
the first genuine test of the abstraction, and it is why this RFC could not have been written before
M6-18.

### What the supervisor is, and is not

A service in a domain needs someone to create the domain, grant it capabilities, and notice when it
dies. This RFC does **not** propose a general supervisor, an init system, or a restart policy. It
proposes the minimum: a boot-time table, capabilities granted from it, and a counter of services
that stopped answering. Restart policy is a separate argument with its own failure modes, and
putting it here would make this RFC about that.

---

## Alternatives considered

| Alternative | Why not |
|---|---|
| **Only in-nucleus services** | Honest, and it abandons `architecture.md` §2 and every isolation claim that rests on it. If we choose this, the document must say so — which the document itself already commits to |
| **Only domain services** | Costs two context switches on the console's write path and the filesystem's read path, on a kernel whose scheduler is young. Also unbootable: something must run before there are domains |
| **A dynamic placement switch at runtime** | Doubles the surface and answers a question nobody asked. The placement is a property of the build and of what the machine is for |
| **`async` with a real executor** | `architecture.md` says services are async state machines. This RFC proposes the state machine without the executor: `handle` returns, and pending work is resumed on a notification. An executor in the nucleus is a scheduler nobody reviewed |
| **Defer until there are more services** | The cost of the both-placements job grows with every service written under the assumption that only one placement is built. Three services is the cheapest this will ever be |

---

## Impact on existing design documents

- **`architecture.md` §2** — the caveat becomes a mechanism. The paragraph promising CI builds of
  both placements is what this RFC delivers; the wording should change from a promise to a
  reference to the job.
- **`roadmap.md` Phase 2** — the service framework item gains this RFC number, and its dependency on
  RFC 0009 (already noted there) is now satisfied rather than pending.
- **`coding-style.md`** — a new section for service crates: the denied imports, and why the lint
  exists rather than a review convention.
- **`security.md`** — a domain-placed service is the first non-shell code to run outside the
  nucleus. The threat model does not change; what changes is that T3 and T4 become reachable claims
  about a real driver rather than about the shell.

---

## Security implications

**A domain placement is not a security boundary by itself.** It is one only if the service is
granted less than the nucleus has, and the thing that decides that is the capability table in the
boot-time placement file — not the trait. A service moved to a domain and handed every capability
it asks for has bought two context switches and no isolation. **The placement file is therefore a
security-relevant document and should be reviewed as one.**

**What a domain-placed service holds** is exactly: its endpoint, the `Memory` objects it was
granted, a `DmaWindow` if it drives a device, an `IrqHandler` if that device interrupts, and a
notification. It holds no address space but its own, no capability to create domains, and no way to
name another service's memory.

**The panic asymmetry is a real gain and a real trap.** A service that panics in a domain takes the
domain; the same code in the nucleus takes the machine. That is an argument for the domain
placement and *not* an argument for tolerating panics, because the constraint is the intersection:
the nucleus placement must survive every input the domain placement survives.

---

## Performance implications

**Slower**: every message to a domain-placed service costs two context switches and a round trip
instead of a call. M6-05 measured the round trip; M6-18 measured what the bulk path costs by
message (fifteen round trips for a 228-byte file) versus shared memory (one).

**Faster**: nothing. This is a structural mechanism, and it costs what it costs.

**What will be measured**, per service and per placement:

| Measurement | Why |
|---|---|
| Round trips per operation, both placements | The number that decides whether a service *can* be moved |
| Bytes per second through the bulk path, both placements | Whether shared memory closed the gap RFC 0009 opened it for |
| Boot time with all services in the nucleus, and all in domains | The cost of the isolation, stated once rather than argued about |

---

## Testing plan

**On the host:**

- The trait's contract: a service that returns an error for malformed input, and a test that feeds
  it every shape of malformed request the message layer can produce.
- The placement table parser, including a service named twice and a placement that is not a
  placement. *Both are fixtures under `tests/fixtures/placement/`, run by `make gates`, and the
  gate asserts that **both** faults in the malformed table are reported: the first version stopped
  at the first one it found and hid the other.*

**In QEMU — and this is the part that makes the design true rather than aspirational:**

- **Every service, both placements, every build.** The CI job builds each service crate twice. A
  service that only compiles in the nucleus fails the build, which is the whole mechanism.
- **A boot with every service forced to `domain`.** The existing shell tests then exercise a
  filesystem service running outside the kernel, over IPC, with its bulk path in granted memory.
- **The negative test**: a service crate that takes a direct call into the kernel must fail to
  build in the domain placement. Written first, as a fixture that is expected to fail, because a
  build gate nobody has seen fail is a build gate nobody should trust.
- A domain-placed service that panics: the domain dies, the machine does not, and the endpoint's
  holder is reported as gone.

---

## Unresolved questions

**Decided by acceptance:**

- **The nucleus placement dispatches through IPC**, not by direct call (question 2). Direct is
  faster and is also the door through which "no direct calls" erodes, and a measurement can reopen
  it later — a design that started with the fast path would never get the slow one back.
- **The placement table is a build-time input** (question 3), with a command-line override
  permitted **for tests only**, because the QEMU run that forces every service into a domain is the
  mechanism this RFC exists for and it must not require a second image. The override is a testing
  affordance and not a runtime feature: a machine whose placements can be changed at boot has a
  security-relevant table outside the build.

**Still open, and deliberately not answered here:**

1. **What happens to a caller whose service died?** Today an endpoint whose holder has gone leaves
   the caller blocked for ever — `service.rs` records this as a known limitation and the fix needs
   a mechanism that does not exist: an endpoint that reports when the capability reaching it is
   revoked. This RFC surfaces the problem and does not solve it.
2. **How much does the domain placement cost the console?** Every printed line would cross a
   boundary. It may be that the console is permanently in-nucleus and the honest thing is to say so in the
   table rather than pretend it is relocatable.

---

## Implementation plan

1. **The trait and the nucleus placement.** `Service`, `Context`, `Request`, `Reply`, with the
   existing console and filesystem services rewritten against it. No behaviour change, and every
   existing gate still passes — that is the success criterion.
2. **The placement table and the build.** Parsed at build time, one crate per service, and the CI
   job that builds both placements for each. The negative fixture lands here.

   *Done, 2026-08-05, with one deviation recorded here rather than quietly.* "One crate per
   service" is one crate per *relocatable* service: the console moved out, the filesystem did not,
   and `services.toml` carries `relocatable = false` for it. The filesystem's bulk path reads a
   caller's pages through the direct map, so deciding what a context hands over for bulk transfer
   is a design question — and it is step 3's question, not something to answer in passing here.
   The check enforces the rule against the resolved dependency graph and by building each
   relocatable service with no kernel in the build at all, which is the domain placement's compile.
3. **The domain placement for one service.** The filesystem, because its bulk path is the one that
   differs and M6-18 gives it a measurement to beat.

   *Done, 2026-08-05.* `bin/vfsd` is the filesystem service in ring 3, holding one endpoint
   capability and a read-only mapping of the image, answering every `fs::` method in the system.
   The service crate is byte for byte the one the kernel compiles for the nucleus placement; what
   differs is the context (`Bulk::fill` is a system call, `method::FILL`) and the run loop
   (`serve::<S>` instead of `run::<S>`). `make test-placements` boots both, every build.

   Three things this found, none of which were visible from the design:

   - `Recv` delivered one of a message's four registers, so no service that packs a `Chunk` could
     ever have run in a domain. Fixed by not accepting a caller from the server, which also closed
     a hole: a server could reply to a thread it had never heard from.
   - The two placements disagreed about a refusal. The nucleus checks the caller's capability
     before reading; the domain version read first and returned early on an empty read, so a caller
     with no right to that memory got "fine, nothing" instead of "not yours". Caught by the
     negative half of the bulk test and by nothing else.
   - A counter is not a witness. The boot report keyed a gate on the service's refusal counter,
     which a service in its own domain has no way to add to — so the gate would have passed in one
     placement and failed in the other while the service behaved identically in both. It now
     reports what the test observed.
4. **The boot with everything in a domain**, and the shell tests running against it.

   *Done, 2026-08-05.* `bin/consoled` joins `bin/vfsd`: the console service holds a `Console`
   capability — put a character, take a byte — and nothing else. In that build the nucleus runs no
   service at all. All four placement combinations boot and pass, every build.

   It also found the thing that made "everything in a domain" impossible: the kernel had kept a
   single installed address space since M5, and the scheduler never touched `CR3`. With one user
   program at a time that is indistinguishable from keeping the right one. Two services in domains
   on one CPU ran in each other's page table — and every boot gate passed while they did, because
   nothing in the boot self-tests runs two user programs at once.
5. **The measurement**, per service and per placement, against the table above.

   *Done, 2026-08-05.* Round trips: one per operation in either placement, asserted. Cycles: a
   domain costs ~5,000 a round trip, about +48%, and the same +48% for both services. Bulk path:
   shared memory beats fifteen round trips by 10.3× in the nucleus and 7.3× in a domain. Boot time:
   unchanged, ~7.6 s either way.

   The measurement paid for itself twice over. It found that the nucleus filesystem thread was
   unpinned and therefore **six times** slower per round trip than the same code pinned — a cost
   nothing else in the suite could have noticed. And it got the answer backwards twice before it was
   right: a mean over 200 samples that one preemption dominated, and a cold path timed against a
   warm one. Both reversals were in the direction of flattering the design.
6. **A second service in a domain** — the block driver, which is where RFC 0011 step 6 and RFC 0012
   step 7 stop being self-tests and become a driver.

   *Started, 2026-08-05.* A driver in a domain needs three things it did not have: its rings mapped
   into its own address space, its device registers mapped, and its interrupts delivered as a
   notification it can wait on. The first is built — `method::ATTACH` maps a `Memory` capability
   into the caller's own space, at an address of its choosing, from frames the object supplies —
   and is exercised from ring 3 with two capabilities to one object, so the refusal tests the right
   rather than the lookup.

   The second is built too: `ATTACH` takes a `Frame` capability, one physical page mapped uncached
   into the caller's space, and the shell reads the block device's status register from ring 3
   through one. Only the kernel can mint a `Frame`, because a `Frame` *is* a physical address and a
   capability a domain could make would be permission to be the kernel.

   The third — interrupts delivered to a domain as a notification it can wait on — is not started,
   and neither is the driver.

Steps 1–2 are the mechanism. Steps 3–5 are the proof. Step 6 is the first driver outside the
kernel, and the reason the previous four RFCs exist.
