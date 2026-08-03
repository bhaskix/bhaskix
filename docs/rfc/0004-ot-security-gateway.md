# RFC 0004: Operational technology as the first target deployment

| | |
|---|---|
| **Status** | **Draft — for discussion** |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | project-wide; affects roadmap ordering |
| **Milestone** | Decision now; delivery in Phase 3 |
| **Depends on** | [RFC 0003](0003-storage-architecture.md) (storage), M5 capabilities, Phase 3 virtualization |

---

## Summary

Bhaskix's first real deployment target should be **operational technology** —
industrial control systems, SCADA, substation automation, process control —
and the product shape should be a **security gateway and hypervisor that runs
the customer's existing OT software unmodified underneath it.**

Not a replacement OT operating system. A trustworthy layer *below* the one
they already have and cannot change.

---

## Motivation

### The observation

OT environments run software that is, by any ordinary standard, indefensible:
Windows XP and Server 2003 HMIs, unpatched Windows 7, decade-old VxWorks and
QNX builds, Linux kernels from three LTS generations ago. This is not
negligence. It is structural:

| Why it cannot be patched | Consequence |
|---|---|
| The vendor certified *that exact build*. Patching voids the certification, and often the safety case with it. | A known-vulnerable system is the *compliant* configuration. |
| Equipment lifecycles are 20–30 years. The controller outlives the OS vendor's support by decades. | There is no patch to apply, at any price. |
| Availability requirements are 99.99%+ with maintenance windows measured in hours per year. | Reboot-to-patch is not available. |
| Safety-instrumented systems require re-validation after any change. | Change is expensive enough to avoid indefinitely. |

And the air gap that historically justified all of this has largely
evaporated — remote maintenance links, USB-based updates, and IT/OT
convergence for production analytics have each punched holes through it.

The results are documented and severe: Stuxnet (2010), the Ukrainian grid
attacks (2015 and 2016), Industroyer, and — most alarming — TRITON/TRISIS
(2017), which targeted a *safety instrumented system*, the layer whose entire
job is to prevent explosions and loss of life.

### Why this matters for a project from India

India has designated critical-infrastructure sectors under NCIIPC, and the
power sector has explicit cyber-security guidelines. Attention rose sharply
after the October 2020 Mumbai grid outage and the subsequent public discussion
of foreign-origin malware in power infrastructure. Railways, refineries, water
treatment, metro rail, and port automation are all in scope.

This is the intersection [vision.md](../vision.md) describes — governments
deploying secure infrastructure without depending on proprietary foreign
operating systems — with an actual, funded, urgent problem. It is a far more
credible entry point than the general-purpose server or desktop market, where
Bhaskix would be competing with Linux on Linux's terms.

---

## The design: run their stack, don't replace it

**The wedge is not "replace your OT operating system."** That sale is
impossible and should not be attempted: vendor certification, frozen safety
cases, and 20-year support contracts all forbid it, and no plant manager will
risk an unplanned outage on a new kernel.

The wedge is:

```
    ┌──────────────────────────────────────────────────────────┐
    │  legacy HMI / SCADA / engineering workstation            │
    │  Windows XP or 7, VxWorks, vendor Linux -- BIT IDENTICAL │
    │  vendor certification intact, safety case unchanged      │
    └───────────────────────┬──────────────────────────────────┘
                            │  VM domain
    ┌───────────────────────┴──────────────────────────────────┐
    │  BHASKIX                                                  │
    │                                                           │
    │  · every device and network access is a CAPABILITY        │
    │  · IEC 62443 zones/conduits enforced structurally         │
    │  · measured boot: the stack is provably untampered        │
    │  · tamper-evident audit of every action                   │
    │  · anomaly detection on kernel telemetry                  │
    │  · RT domains for native, deterministic control tasks     │
    └───────────────────────────────────────────────────────────┘
```

The legacy system keeps running exactly as certified. Bhaskix becomes the part
that can be trusted, updated, and attested — because it is the part nobody has
frozen.

### What the existing design already provides

This is not a pivot. Every mechanism this needs is already in the design
documents, which is the main argument that the fit is real rather than
retrofitted:

| OT requirement | Already specified in |
|---|---|
| Run unmodified legacy OS with full isolation | Domains unify containers and VMs — [architecture.md](../architecture.md) §4 |
| Least privilege that cannot be misconfigured | Capabilities; no ambient authority, no `root` — [security.md](../security.md) §2 |
| Deterministic control loops | RT scheduling class with priority inheritance, admission control, and a measured latency bound — [scheduler.md](../scheduler.md) §4 |
| Prove the system has not been tampered with | Measured boot into TPM PCRs, remote attestation — [security.md](../security.md) §3 |
| Forensics after an incident | Tamper-evident hash-chained audit log — [security.md](../security.md) §8 |
| Detect abnormal behaviour | Typed causal telemetry plane — [ai-native.md](../ai-native.md) §2 |
| Operate fully offline | Mandated: all AI features work air-gapped — [ai-native.md](../ai-native.md) §5 |
| Small footprint on industrial hardware | Edge and embedded editions — [vision.md](../vision.md) Phase 5 |

### Two things that fit unusually well

**Capabilities are what IEC 62443 zones and conduits want to be.** The standard
asks for segmentation into zones with controlled conduits between them. In
practice that is implemented as firewall rules and VLANs — configuration, which
can be wrong, drift, or be edited by an attacker who gets in. As a capability,
an HMI domain holds the authority to speak Modbus to exactly PLC #7 and to
nothing else. It cannot exceed that by misconfiguration, because there is no
configuration to get wrong.

**OT traffic is the ideal case for anomaly detection.** General IT traffic is
irregular enough that behavioural detection drowns in false positives. OT
traffic is the opposite: the same Modbus polls, to the same registers, at the
same intervals, for years. A deviation is genuinely anomalous. Combined with
the rule in [ai-native.md](../ai-native.md) §7 that a model may *detect and
alert* but never *authorise*, this is a safe and unusually effective
application — a model must never be permitted to actuate a valve, and the
architecture already forbids it.

---

## Consequences for the roadmap

This is the concrete output of the RFC, and the reason it is an RFC rather
than a note.

| Change | From | To |
|---|---|---|
| **Hardware virtualization (VMX/EPT)** | Phase 3, alongside containers | **Earliest Phase 3 item.** It is the product, not a feature. |
| **RT class + latency measurement** | M4 | M4, but the p99.9 latency gate becomes a **release gate**, not a nice-to-have |
| **Attestation and audit** | Phase 3 | Phase 3, but scoped to what IEC 62443 evaluators actually ask for |
| **Certification target** | Unspecified | **IEC 62443-4-1 and -4-2** first (product and process security), *not* Common Criteria |
| **Desktop edition** | Phase 5 | Phase 5, and explicitly deprioritised further |
| **Fieldbus/serial drivers** | Not planned | Added to the Phase 2–3 driver list: serial, legacy PCI, and common fieldbus cards |
| **Protocol awareness** | Not planned | Modbus, DNP3, IEC 61850, OPC-UA — in **userspace**, as capability-mediated conduits, never in the nucleus |

---

## Alternatives considered

| Alternative | Why rejected | Would reconsider if |
|---|---|---|
| **General-purpose server OS** | Competes with Linux on Linux's terms — mature drivers, vast ecosystem, decades of tuning. No differentiating claim, and adoption would depend on mandates. This is the BOSS Linux failure mode described in [RFC 0003](0003-storage-architecture.md). | Never as a *first* target; it can follow. |
| **Replace the OT operating system outright** | The obvious reading of "secure OT". Rejected as unsellable: vendor certification, frozen safety cases, and multi-decade support contracts each independently block it. A plant will not risk an outage on a new kernel. | A greenfield deployment with a vendor partner willing to certify on Bhaskix. |
| **Desktop or edge-consumer first** | Largest driver surface, least differentiating, and no buyer who values verifiable isolation enough to pay for it. | — |
| **Defence/space (DRDO, ISRO) first** | Arguably an even better fit for verifiable isolation, and there is real appetite for indigenous stacks. Rejected as *first* target because procurement cycles are long, requirements are classified and therefore hard to design against publicly, and the project could not develop in the open — which [vision.md](../vision.md) makes non-negotiable. | It becomes a natural second market once OT deployments exist as evidence. |
| **Pure security appliance (no hypervisor)** | Simpler: a monitoring box beside the OT network. Rejected because it cannot enforce anything — it observes traffic it has no authority over, which is what existing OT IDS products already do, and they have not solved this. | — |

---

## The honest difficulties

Recorded plainly, because a positioning document that lists only advantages is
marketing rather than engineering.

- **Safety certification is brutal.** IEC 61508 SIL 2/3 takes years, costs
  millions, and requires a frozen codebase — the opposite of an active
  project. seL4 is the only kernel with genuinely strong credentials here, and
  it took a decade of formal verification to get them. **Bhaskix should not
  claim safety certification, and should target the security standards
  (62443) rather than the functional-safety ones (61508) until there is a
  funded path.**
- **OT buyers are the most conservative in computing**, correctly. "New
  kernel" is close to a disqualifier. The only credible entry is alongside an
  existing system, in a monitoring or isolation role, where failure degrades
  rather than stops the plant.
- **Real-time guarantees must be measured, not asserted.** A latency claim
  without a reproducible benchmark on the customer's hardware is worthless in
  this market.
- **Determinism under virtualization is genuinely hard** — lock-holder
  preemption, cache and memory-bandwidth interference between domains. Gang
  scheduling is already noted as deferred in [scheduler.md](../scheduler.md)
  §9; this RFC makes it mandatory rather than optional.
- **Industrial hardware is strange**: fieldbus cards, serial multiplexers,
  legacy PCI, vendor-specific watchdogs. The driver effort is unglamorous and
  large.
- **Support commitments** in OT run 10–20 years. A young project cannot
  credibly offer that alone; it needs an institutional backer, which is a
  governance and funding question rather than a technical one.

### What would falsify this bet

Worth stating so the decision can be revisited on evidence rather than
sentiment:

- If OT operators consistently reject a hypervisor layer on latency or
  certification grounds, the isolation thesis fails and the project should
  fall back to the monitoring-appliance role.
- If measured RT latency under virtualization cannot beat a bounded target on
  real industrial hardware, the "run control tasks natively" half of the
  proposition is dead and only the isolation half survives.
- If IEC 62443 evaluation proves to require a frozen codebase in practice, the
  certification path needs rethinking before any of it is promised.

---

## Security implications

This is a security proposition end to end. The relevant note is a caution
rather than a benefit: **positioning Bhaskix as protecting critical
infrastructure raises the consequences of every defect in it.** A bug in a
desktop OS is an inconvenience; a bug in a layer beneath a substation
controller is not.

Concretely, this RFC should be read as making the following non-negotiable
rather than aspirational: the fuzzing requirement in
[coding-style.md](../coding-style.md) §8, external security audit before any
deployment claim, and the honest threat-model boundaries in
[security.md](../security.md) §1 — particularly the **out-of-scope** list,
which must be presented to any OT customer rather than quietly omitted.

## Testing plan

- **Latency**: cyclictest-equivalent inside a VM domain under adversarial load
  from a neighbouring domain. Published numbers, on named hardware.
- **Isolation**: a compromised domain attempting to reach a device it holds no
  capability for; assert the attempt faults and is attributed in the audit log.
- **Availability**: sustained multi-week soak with fault injection; OT cares
  about uptime more than throughput and the test suite should reflect that.
- **Legacy guest fidelity**: an actual Windows XP or vendor HMI image booting
  and running unmodified is the acceptance test for the central claim.

## Unresolved questions

- **Which sector first?** Power/substation (IEC 61850) has the clearest Indian
  regulatory driver; discrete manufacturing has lower safety consequences and
  is therefore an easier first customer. These pull in opposite directions.
- **Do we need a hardware partner?** OT is sold as an appliance, not as
  software. That is a business-model question with technical consequences for
  the driver roadmap.
- **How much protocol awareness belongs in the product**, versus leaving
  conduits opaque and enforcing only endpoint-to-endpoint capabilities? Deep
  packet inspection of Modbus is useful and is also a large new parser attack
  surface aimed at untrusted input.
- **Certification sequencing** relative to Phase 3 completion.
