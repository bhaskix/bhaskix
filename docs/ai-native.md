# Bhaskix — AI-Native Design

*Status: draft for review. Prerequisite reading: [architecture.md](architecture.md),
[scheduler.md](scheduler.md) §8.*

---

## 0. The problem with "AI-native operating system"

Most projects that claim this ship a chatbot that runs shell commands. That is an application, not an
operating system property, and it would work equally well on any OS.

For "AI-native" to mean anything architecturally, the kernel has to provide something a bolt-on
cannot: **structured, high-frequency, semantically-typed observability of its own decisions**, and
**safe, bounded places to change those decisions**. That is what this document specifies. The
assistant is the least interesting part.

Three rules govern everything here:

> **1. The model advises; the kernel decides.**
> **2. Every AI path must degrade to a working default.**
> **3. Inference never runs in the nucleus.**

If a proposed feature violates any of these, it does not go in.

---

## 1. Why a kernel can do this better than a userspace agent

A userspace monitoring agent on a conventional OS sees: sampled counters, text logs, `/proc`
snapshots, and after-the-fact metrics. It is guessing at causality from lagging indicators.

The kernel sees the actual decisions, at the moment they are made, with full context:

- *why* this thread was placed on this CPU rather than that one
- *which* page was evicted and what the alternatives were
- *what* the I/O queue depth was when latency spiked, per device, per domain
- *which* capability was invoked before a domain started misbehaving

That is causal data, not correlational. It is the difference between "CPU was at 90% and latency rose"
and "thread T was migrated across a NUMA boundary at t=... because domain D's envelope was exceeded,
and its next 400 memory accesses were remote". A model given the second kind of data can be useful.
A model given the first kind produces plausible-sounding nonsense.

**This is the actual thesis of AI-native Bhaskix.** Everything else follows from building the
telemetry plane properly.

---

## 2. The telemetry plane

The foundation. Built in Phase 1–2, long before any model exists, because it is independently
valuable for debugging, profiling, and audit.

> **Built, 2026-08-17** — [RFC 0026](rfc/0026-telemetry-plane.md), accepted. The arithmetic
> lives in the `telemetry` crate, the stores in `kernel/src/telemetry.rs`, and the first
> consumer is `bin/traced`, which holds the rings read-only and the tails read-write and
> drains for the life of the boot. Two boot gates hold it: the report line, and a marked
> round trip that fails closed when the grant is withheld. Where this section and the built
> thing differ, the divergence is stated inline below rather than left to be discovered.

### Design

```rust
#[repr(C)]
pub struct Event {
    timestamp: u64,        // TSC, monotonic
    cpu:       CpuId,
    domain:    DomainId,
    class:     EventClass,  // Sched | Memory | Io | Net | Syscall | Cap | Fault | Audit
    schema:    SchemaId,    // versioned, registered at build time
    payload:   [u8; 40],    // fixed-size, typed by schema
}
```

- **Per-CPU lock-free ring buffers.** A producing CPU never contends with another. Writing an event
  is a bounded, allocation-free, lock-free sequence of stores.
- **Typed, versioned schemas — never text.** Text logging in a hot kernel path costs formatting time,
  produces data that must be re-parsed with regexes, and breaks silently when a message is reworded.
  Consumers get a schema registry and decode structurally.
- **Best-effort by default, with a visible drop counter.** Under pressure, telemetry drops events and
  says so. Telemetry that can stall the kernel is a denial-of-service vector.
- **`Audit`-class events are the exception:** they apply backpressure rather than drop, and live in a
  separate ring so a debug-telemetry flood cannot evict a security record
  ([security.md](security.md) §8).
- **Per-class enable bits now, per-domain with their first consumer.** Disabled classes compile to
  a predicted-not-taken branch on an atomic — measured, not hoped: the boot report prices both
  sides of the emit on every boot. Per-domain filtering was deferred by RFC 0026, stated rather
  than slipped: it costs a second load and mask on every emit, and no consumer exists yet that
  filters by domain — the multi-tenant consumer that needs it arrives with the audit work, and
  the emit path's check is shaped so the second mask drops in without touching call sites.

### Consumers

The same pipeline feeds all of these, which is why it is worth building well:

```
per-CPU rings ──┬──► bhaskixd-ai        (Phase 4: models)
                ├──► bhaskixd-audit     (Phase 3: tamper-evident log, attestation)
                ├──► bin/traced         (Phase 2: the developer tracing tool — exists)
                └──► metrics export  (Phase 3: Prometheus/OTLP-shaped, in userspace)
```

Building the telemetry plane in Phase 2 is not "starting the AI work early". It is building the
debugging tool the kernel developers will need anyway, in a form that happens to also be a model's
input.

---

## 3. Policy hooks

The second half of the mechanism: bounded places where a decision can be influenced.

### The contract, in general

For every pluggable policy:

1. The kernel computes the set of **legal** actions using its own logic.
2. The policy may **rank or select within that set**. It cannot add to it.
3. Any numeric value returned is **clamped to kernel-computed bounds**.
4. The policy runs under a **hard time budget**; exceeding it disables the policy permanently until
   an operator re-enables it, and logs the event.
5. There is always a **complete default heuristic**. The system is fully functional with every
   policy hook empty.

A compromised, hallucinating, or simply bad model can therefore make Bhaskix *slower*. It cannot make
it incorrect, unfair beyond a domain's envelope, or insecure. This containment property is what makes
it defensible to ship AI in an operating system at all.

### The hooks

| Hook | Kernel decides | Policy may influence | Bounded by |
|---|---|---|---|
| **Scheduling** ([scheduler.md](scheduler.md) §8) | Which CPUs are legal for a thread | Ranking among them; slice length; runtime prediction | Affinity, isolation, envelope; slice clamped to `[min,max]` |
| **Page reclaim** ([memory.md](memory.md) §6) | Which pages are eligible for eviction | Ordering of eligible candidates | Pinned, locked, and in-use pages are never eligible |
| **I/O scheduling** | Deadline and fairness constraints per domain | Ordering within the deadline window | No request exceeds its deadline; no domain starves |
| **Readahead / prefetch** | Maximum prefetch window | Predicted access pattern, window size within max | Memory envelope; prefetch is discardable by definition |
| **Frequency / power** | Legal P-states and thermal limits | Selection among legal states | Firmware and thermal limits are hard |
| **OOM candidate ranking** | Which domains are eligible to kill | Ordering among eligible | init, `bhaskixd-ai` itself, and lock-critical domains are never eligible |

Note the last row. **The AI daemon can never nominate itself, and can never be nominated, for
termination.** Both directions matter: self-preservation would be a conflict of interest, and
killing it during memory pressure would remove the component being asked to help.

---

## 4. Where inference runs

```
┌─────────────── nucleus ───────────────┐
│  feature extraction  (fixed-cost, no  │
│  allocation, no floating point in     │
│  the hot path)                        │
│  policy application  (clamped)        │
└──────────────┬────────────────────────┘
               │ telemetry out / advice in
               │ (shared-memory ring, no syscall in the fast path)
┌──────────────▼────────────────────────┐
│  bhaskixd-ai — an ordinary domain        │
│  · no special capabilities beyond     │
│    telemetry-read + policy-advise     │
│  · subject to a ResourceEnvelope      │
│  · killable; system continues         │
│  · runs the model (CPU, or NPU/GPU    │
│    via an ordinary device capability) │
└───────────────────────────────────────┘
```

Non-negotiable: **no model weights, no inference, no floating-point-heavy work, and no unbounded
memory in the nucleus.** The nucleus does feature extraction (counters, ratios, histogram buckets —
integer arithmetic, fixed cost) and applies clamped advice. That is all.

`bhaskixd-ai` is an ordinary domain. It has an envelope. It can be killed. If it is killed, every policy
reverts to its default heuristic and the system keeps running at its Phase-3 performance. This is
testable, and it is a CI test: **boot, run the benchmark suite, kill `bhaskixd-ai`, assert the suite
still passes.**

---

## 5. Models: what is actually realistic

Honesty about what fits where.

| Use | Model class | Where | Latency budget |
|---|---|---|---|
| Scheduling hints, reclaim ranking, prefetch prediction | Small statistical / gradient-boosted models, or online linear models. Kilobytes to low megabytes. | `bhaskixd-ai`, CPU, always resident | µs–ms |
| Anomaly detection over telemetry | Streaming statistical methods, small sequence models | `bhaskixd-ai`, CPU | ms–s |
| Diagnostics, root-cause narration, config generation, the operator assistant | An LLM, local (quantised, NPU/GPU) or remote by explicit operator configuration | A separate domain, off the critical path entirely | seconds |

An LLM is **never** in a scheduling or memory-reclaim path. Anyone who proposes it has confused two
very different latency regimes. The fast-path policies are small models or nothing.

**All AI features must work fully offline.** The edge, embedded, and air-gapped enterprise
deployments are not optional targets, and an OS feature that requires a network call to a third party
is not an OS feature. If a remote model is configured, it is opt-in, explicit, logged, and
disableable — and disabling it must not degrade anything but the assistant.

---

## 6. Phase 4 features, restated concretely

The vision's Phase 4 list, translated from goal to mechanism:

| Vision item | What it actually is |
|---|---|
| Local AI assistant | An LLM in a userspace domain with capability-scoped access to system introspection and (separately granted) configuration. Every action it takes is an audited capability invocation — so "the AI changed something" is always attributable and always revocable. |
| AI-powered diagnostics | Correlation over the telemetry plane: given an incident, find the causally-preceding events across subsystems and explain them. Only possible because telemetry is typed and causal. |
| Intelligent scheduling | The `SchedPolicy` hook, backed by a runtime-prediction model. |
| Predictive resource optimization | Envelope pre-sizing from historical per-domain telemetry; prefetch and reclaim hooks. |
| Automated incident detection | Streaming anomaly detection on telemetry, feeding the audit and alerting paths. |
| Autonomous system management | Closed-loop actions (restart a service domain, resize an envelope, drain a node) executed **only** within pre-declared, operator-authored bounds, with every action logged and reversible. Autonomy is a bounded authority grant, not an ambition. |

---

## 7. Things we will not do

Written down so they do not creep in.

- **No AI in the nucleus.** Not "small models are fine". None.
- **No mandatory telemetry upload.** Telemetry is local by default. Export is opt-in, configured,
  and visible.
- **No unexplainable actions.** Every autonomous action records the events that triggered it and the
  policy that authorised it. "The model decided" is not an audit record.
- **No AI on the security decision path.** A model may *detect* and *alert*. It may not *authorise*.
  Capabilities are the authorisation mechanism; a probabilistic system does not get a vote.
- **No feature that cannot be turned off.** Every AI subsystem has an off switch, and the system is
  supported with all of them off.

---

## 8. Open questions

- Telemetry schema evolution: how do we version schemas so that a tool built against v1 keeps working
  at v5? (Lean: additive-only within a `SchemaId`, new ID for breaking changes.)
- Model provenance: models are executable policy. Should they be signed and measured into the boot
  chain like the kernel is? (Lean: yes, for anything that influences a policy hook.)
- Does the kernel need a stable "feature vector" ABI, or does `bhaskixd-ai` compute features from raw
  telemetry? (Lean: raw telemetry out, features in userspace — keeps the nucleus dumber.)
- On-device training/adaptation: valuable for per-machine tuning, but a persistent, mutable,
  model-shaped attack surface. Deferred, not decided.
