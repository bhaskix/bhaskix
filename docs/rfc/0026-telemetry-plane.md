# RFC 0026: The telemetry plane

| | |
|---|---|
| **Status** | Draft — all six steps implemented 2026-08-17, awaiting acceptance review. Step 5 landed differently than sketched, and the plan below was edited to match before acceptance rather than after: the crossings ride the `Syscall` class as three general schemas (syscall exit, rendezvous event, signal) rather than a bespoke `Net` re-expression, `bin/traced` became the live deadline-woken consumer, and the pipeline stamps were retired with one measurement knowingly lost — deliver-to-seen, an in-program memory poll no kernel crossing can see; TRACKER's changelog has the full account |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | kernel, tools, ABI |
| **Milestone** | Phase 2 — the roadmap's "telemetry plane" bullet, [ai-native.md](../ai-native.md) §2 made real |
| **Depends on** | [RFC 0009](0009-shared-memory.md) (the `Memory` objects the rings are read through), [RFC 0008](0008-syscall-and-ipc-shape.md) (whose question 4 — how telemetry names a capability — this partially answers) |

---

## Summary

**A fixed-size, typed event record; one lock-free ring per CPU; a capability to read them.** The
kernel emits 64-byte events — timestamped, classed, schema-versioned, never text — into per-CPU
rings with a bounded, allocation-free store sequence. A ring 3 tracing tool, `bin/traced`, maps
the rings read-only through capabilities it is granted like any other authority, decodes events
structurally against a build-time schema registry, and reports. Under pressure telemetry drops
events and counts the drops where the reader can see them. This is
[ai-native.md](../ai-native.md) §2 built as designed — the developer tracing tool first, the
model's input only in the sense that the pipe will still be there in Phase 4 — and it is the
foundation [security.md](../security.md) §8's audit framework and the roadmap's Phase 3
consumers are declared against.

## Motivation

**Every instrument this project has built in the last two weeks is a hand-rolled special case of
this plane.** The TCP pipeline attribution is six one-shot cycle stamps in four report pages,
first-echo-only because a second echo would overwrite them. The contention map, the lock ledger,
the preempt-decline counters, the watchdog dump — each is its own ad-hoc format, its own page,
its own kernel printer, parsed back out of boot logs with `grep`. Each was worth building, and
each was more expensive than it should have been, because there is no general way for the kernel
to say *what happened, when, on which CPU* to a consumer that is not a human reading serial
output.

The cost of not having it is now measured rather than argued: the serve-loop hunt that the TCP
window refutation opened (TRACKER §7, 2026-08-17) needs per-hop timing over *streams* of events,
and the existing stamp instrument can attribute exactly one echo per boot. Building that hunt's
instrument as one more special case would be the fourth such; building the plane instead is the
same work with a future.

**What happens if we do nothing:** every future subsystem pays the special-case tax, the audit
framework (Phase 3) and the AI plane (Phase 4) have nothing to consume, and `architecture.md`'s
domain sketch keeps a `telemetry: TelemetryChannel` field that has never existed.

## Design

### The event

The record is [ai-native.md](../ai-native.md) §2's, unchanged:

```rust
#[repr(C)]
pub struct Event {
    timestamp: u64,        // TSC, raw; the kernel knows the rate, readers ask it
    cpu:       u32,        // which CPU emitted
    domain:    u32,        // DomainId of the domain running when emitted
    class:     u32,        // Sched | Memory | Io | Net | Syscall | Cap | Fault | Audit
    schema:    u32,        // registered at build time, versioned
    payload:   [u8; 40],   // fixed-size, typed by schema
}
```

Sixty-four bytes, const-asserted, no implicit padding. Two deliberate narrownesses:

- **`domain` is the id without the generation.** `DomainId` is a `u32` and the generation is a
  second `u32`; carrying both would cost the header eight bytes it does not have. A tracing
  consumer correlates over windows of seconds, where slot reuse is rare and visible (a
  domain-created event intervenes); a schema that genuinely needs the generation puts it in its
  own payload. Audit-grade identity is the audit RFC's problem, stated in §8's terms there.
- **`timestamp` is the raw TSC.** Converting to nanoseconds at emit time puts a multiply and a
  divide in every producer; the reader does it once per batch, with the rate the kernel already
  reports.

### The schema registry

A schema is a `#[repr(C)]` payload struct of at most 40 bytes, registered in a `const` table in
the shared `telemetry` crate — id, version, size — that both the kernel and every consumer
compile against. The registry is hashed at build time (a `const` FNV over the entries) and the
hash is written into every ring's header: a reader whose registry hash differs **refuses to
decode** rather than misreading structurally. Re-wording a schema is a version bump; a version
bump changes the hash; a stale tool says so instead of lying. This is the "typed, versioned,
never text" rule with its enforcement attached.

### The rings

One ring per CPU, fixed at bring-up, in frames the kernel allocates once. Each ring is a header
page plus a power-of-two count of 64-byte slots. The producer is **only the owning CPU**; there
is no cross-CPU write path, so there is no cross-CPU contention, which is the entire point of
per-CPU rings.

The producer sequence, with interrupts disabled for its duration:

1. Load the class-enable mask; a disabled class is one load, one test, one predicted-not-taken
   branch, and out.
2. Read the reader's tail (untrusted — see below), clamp it into `[head − capacity, head]`.
3. If `head − tail == capacity`: increment the ring's drop counter and out. **Drop-newest,
   never overwrite**: a slot below `head` is never rewritten until the reader frees it, so a
   reader can never observe a torn record.
4. Write the 64-byte record into `slots[head % capacity]`.
5. Publish `head + 1` with a release store.

Interrupts are disabled because emit must be atomic against *itself* on the same CPU: a timer
landing between steps 4 and 5 whose handler also emits would claim the same slot. Disabling
interrupts around roughly six stores is the bounded, allocation-free sequence the design doc
promises, and it is exempt from lock ranking because it takes no lock
([coding-style.md](../coding-style.md) §7). It is legal from interrupt context for the same
reason.

**The drop counter is per ring, in the ring's header, visible to the reader** — best-effort that
says so, not best-effort that hopes.

### Enable bits

A single global atomic word, one bit per class, all classes off until something turns them on.
**Per-domain enable bits are deferred**, which is a stated narrowing of
[ai-native.md](../ai-native.md) §2 rather than a quiet one: per-domain filtering costs a second
load and mask on every emit, and no consumer exists yet that filters by domain — the tracing
tool wants everything, and the consumer that genuinely needs per-domain scoping (multi-tenant
audit) arrives in Phase 3. The emit path's check is shaped so the second mask drops in without
touching call sites, and the design doc is edited on acceptance to say "per-class now,
per-domain with its first consumer". What would change this: any Phase 2 consumer that drowns
in another domain's events.

### The `Audit` class is reserved, not served

`security.md` §8 requires audit events to apply backpressure rather than drop, in a ring debug
telemetry cannot evict. A best-effort audit event is worse than none — it is false assurance
with a checksum. This RFC therefore **refuses to carry audit events**: the class exists in the
enum so the numbering is settled, and emitting it drops the event and counts it separately. The
backpressure ring, the hash chain, and the naming question are one RFC, later, on this plane's
foundation — exactly as `security.md` declares audit "a consumer of the typed telemetry plane".

### The read side

Two `Memory` objects, created at bring-up, granted as capabilities like every other authority:

- **The rings** — headers and slots, every CPU's, in one object — mapped **read-only**. A reader
  cannot forge events, cannot move `head`, cannot touch another consumer's state.
- **The tails** — one word per CPU in a single page — mapped **read-write**. The tail is the
  reader's claim of how far it has consumed, and the kernel treats it as untrusted: clamped at
  every use, a lying tail can only cause drops or redeliveries in the liar's own stream, never a
  kernel fault or a torn record.

The reader's loop is: acquire-load `head`, read slots `[tail, head)`, release-store the new
tail. No syscall on the hot path; the reader that wants to block instead of poll gifts a
notification, the same shape every service already speaks — but that is a consumer convenience
and is deliberately not in this RFC's first steps.

`bin/traced` is the Phase 2 consumer: it drains all rings, merges by timestamp, decodes against
the registry, and reports — counts per class and schema, drop totals, and whatever the current
hunt needs printed. It is a developer tool and holds exactly two capabilities: the rings and the
tails.

### How telemetry names a capability — RFC 0008's question 4, partially

An event that refers to a capability records **(domain, slot index, object kind)** in its
payload: a *name* in the holder's own coordinate system, conferring nothing, meaningless outside
the trace, stable exactly as long as the slot is. That is sufficient for tracing (the consumer
correlates grant and use within a window) and insufficient for audit (which needs identity that
survives revocation and reuse) — so question 4 is answered here for the tracing consumer and
explicitly left open for the audit RFC.

## Alternatives considered

| Alternative | Why rejected | Would reconsider if |
|---|---|---|
| **Text logging in the kernel, parsed by consumers** | Formatting cost in hot paths, regex parsing downstream, silent breakage on rewording — [ai-native.md](../ai-native.md) §2 rejected this before any code existed, and the two weeks of grepping boot logs since are the demonstration | Never for the plane; `println!` stays for boot narration, which is for humans |
| **One global ring under a lock** | Every emit contends with every CPU; the hot paths this exists to observe are exactly the paths that cannot afford a shared cache line, let alone a lock | Never |
| **Per-domain rings (`architecture.md`'s `TelemetryChannel` sketch)** | The producer is a *CPU*, often in interrupt context, and the interesting events (scheduler, faults) happen while switching *between* domains; per-domain rings make emit cross-CPU, unbounded in count, and ambiguous mid-switch. The salvageable half is per-domain *filtering*, which is the deferred enable-bits work. The sketch is corrected on acceptance | A consumer that needs per-domain *isolation* of the stream itself, not filtering — e.g. handing a tenant its own trace; that is a view over this plane, not a different plane |
| **Overwrite-oldest (flight-recorder) rings, like `perf`** | The reader can observe a slot being rewritten under it, so every read needs a seqcount retry loop and torn-record handling; drop-newest makes torn reads structurally impossible and matches the design doc's "drops events and says so" | The next hang hunt wants "the last N events before the wedge" — a flight-recorder *mode* is one header bit and a reader that tolerates tearing, and the watchdog would be its consumer. Recorded as the likely second mode, not built now |
| **Events as IPC messages to a collector service** | An emit that can block, allocate, or wake is a denial-of-service vector aimed at the kernel by whoever can provoke events — the design doc's exact words for why telemetry must not stall the kernel | Never for emit; consumers above the rings are free to re-ship events however they like |
| **Reuse `abi::ring` (the byte rings services speak)** | Built for two-party rendezvous: variable-length entries behind an 8-byte prefix walk, one producer one consumer by contract, no class mask, no drop accounting. Fixed 64-byte slots index arithmetically, decode without a walk, and never tear under drop-newest | If the record ever grows variable-length payloads — and the 40-byte fixed payload is a deliberate wall against exactly that |
| **eBPF-style programmable probes** | Dynamic code in the nucleus is what [RFC 0007](0007-livepatch.md) narrowed away from even for *patching*; the bounded version of "programs observe the kernel" is the policy-hook contract of [ai-native.md](../ai-native.md) §3, which is Phase 4's problem | A concrete Phase 4 need the static schema set cannot express, argued then |

## Impact on existing design documents

- **[architecture.md](../architecture.md)** — the domain sketch's `telemetry: TelemetryChannel,
  // see ai-native.md` field, and the "not yet: telemetry channel" gap note. Both become wrong:
  the rings belong to CPUs, not domains, and what a domain will eventually carry is enable bits.
  The sketch and the gap list are edited in the implementing change.
- **[ai-native.md](../ai-native.md)** §2 — "per-class, per-domain enable bits" becomes
  "per-class now, per-domain with its first consumer", with this RFC cited. The rest of §2 is
  implemented as written, and the section gains pointers to the real crate and tool.
- **[security.md](../security.md)** §8 — unchanged in substance; gains a sentence that the
  plane exists, the `Audit` class is reserved, and backpressure is still owed to a future RFC.

## Security implications

- **New authority**: two capabilities — read the rings, write the tails. Holding them is
  cross-domain observability: event streams reveal scheduling, faults, and IPC activity of every
  domain. That is what a tracing tool is; the containment is that it is a *capability*, granted
  at boot to `bin/traced` and to nothing else, revocable like any `Memory` object. Per-domain
  filtering, when it arrives, is the multi-tenant refinement.
- **Reachable without a capability**: nothing. A domain with no grant observes no events and
  cannot tell whether telemetry is enabled.
- **Untrusted input**: the tail words, written by ring 3, read by the kernel — clamped into
  range at every use, and the clamp is host-tested with hostile values (zero, `u64::MAX`, ahead
  of head, a lap behind). The consumer side treats ring bytes defensively — unknown class,
  unknown schema, size mismatch are counted and skipped, never indexed blindly — and the decoder
  gets a seeded mutation harness per [coding-style.md](../coding-style.md) §8's M6-01 pattern
  (its input is kernel-produced, but the harness is cheap and torn-input robustness is worth
  pinning).
- **Scope moves**: none. The audit framework stays future work and this RFC says so rather than
  half-shipping it.

## Performance implications

What gets slower: every enabled emit site pays the ring write (~six stores, interrupts off);
every disabled site pays one load and a predicted branch. What gets faster: nothing directly —
this is an instrument.

Measured, not hoped:

1. **Cycles per emit**, printed in the boot report over a calibrated loop — the number the
   `< 1 %` target of [ai-native.md](../ai-native.md) §2 is checked against, per workload
   arithmetic rather than vibes.
2. **The existing gates stay green with default classes enabled** — RT latency p99.9 < 50 µs
   and the IPC self-tests, which are the hot paths that would show a regression first.
3. **Drop rate under the suite's own load**, visible in the boot report, which is what sizes
   the rings (start: 1024 slots, 64 KiB per CPU) against evidence instead of guesswork.

## Testing plan

- **Host**: the ring protocol is pure logic over a byte region — producer and consumer as
  functions of (header, slots, candidate event), tested for: fill and drain, wrap, drop-newest
  at capacity, the tail clamp against hostile values, head monotonicity, and the registry hash
  refusing a mismatched tool. The mutation harness drives the consumer with corrupted regions.
  This is most of the work, and it runs in CI in milliseconds.
- **QEMU**: a boot self-test emits marked events on every CPU, and `bin/traced` must read back
  exactly the marked set through its capabilities and report — the round trip proven through
  real mappings. The boot gate demands the report line and a zero *unexplained*-drop count.
  Negative arm: with the grant withheld, `traced` must fail closed, observing nothing.
- **Real hardware**: nothing hardware-specific beyond the TSC, which every existing gate
  already depends on. M1-17 applies to this as to everything.
- **Fuzz target**: the consumer's decoder, via the seeded mutation harness (see Security);
  promotion to a libFuzzer target in `fuzz/` if it ever parses input from a less trusted
  producer.

## Unresolved questions

1. **Per-domain enable bits** — deferred; decided at latest by the audit RFC, earlier if a
   Phase 2 consumer needs them (see Design).
2. **A flight-recorder mode** for the watchdog and hang hunts — one header bit and a
   tearing-tolerant reader; wanted by the next hunt, not by this RFC.
3. **Does `bin/traced` ship in every initrd or only test builds?** Leaning every build — a
   tracing tool that is absent on the machine that is misbehaving is the wrong default — but the
   image-size question belongs to the package-management bullet.
4. **Blocking readers** — a notification gifted alongside the tails, the shape every service
   speaks. Trivial to add, deliberately not in the first steps.

## Implementation plan

1. **The `telemetry` crate**: the 64-byte `Event` (const-asserted layout), `EventClass`, the
   schema registry with its build-time hash, and the ring producer/consumer protocol as pure
   host-tested logic. Zero `unsafe`. The mutation harness for the consumer.
2. **The kernel emit path**: per-CPU rings allocated at bring-up, the global class mask,
   `telemetry::emit` with the interrupts-off bounded sequence, drop counters. First producer:
   the scheduler's dispatch event, because every boot exercises it. Boot report line: events,
   drops, cycles per emit.
3. **The grant**: the two `Memory` objects, mapped into a test consumer in the boot self-test;
   the marked-events round trip, watched red by withholding the grant.
4. **`bin/traced` v0**: drains, merges, decodes, reports through the console service; the boot
   gate line.
5. **Producers that earn their keep**: one event per syscall at its exit, one per rendezvous
   event through `ipc`'s existing trace funnel, one per notification signal — the kernel
   crossings, all riding the `Syscall` class as general schemas rather than the `Net`-class
   TCP re-expression first sketched here, because the crossings are what every hop of every
   pipeline rides and a TCP-shaped schema would have rebuilt the special case one layer up.
   `bin/traced` becomes the live consumer the stream needs — validating once, draining every
   pass, sleeping on an armed deadline between passes. Then the pipeline stamps die, with one
   loss stated rather than hidden: deliver-to-seen was an in-program memory poll, and no
   kernel crossing can see it; its bound survives as the wake-to-next-syscall gap.
6. **The overhead measurement**: the A/B emit-cost line in the boot report, the drop-rate row,
   and the CI assertion that the existing latency gates hold with default classes on.

Steps 1 and 2 are worth doing alone; step 5 is where the plane starts paying rent.
