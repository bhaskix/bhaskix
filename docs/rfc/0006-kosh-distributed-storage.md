# RFC 0006: Kosh — unified storage, from one node to many

| | |
|---|---|
| **Status** | **Draft — for discussion** |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | fs, net; new subsystem `kosh` |
| **Milestone** | Decision now; single-node in Phase 2, replication in Phase 3, geo in Phase 3+ |
| **Depends on** | [RFC 0003](0003-storage-architecture.md) (storage architecture), M6 (VFS, block driver), Phase 2 networking |

---

## Summary

**Kosh** is the name of Bhaskix's storage system: the concrete implementation
of [RFC 0003](0003-storage-architecture.md)'s three layers, extended with
replication and distribution.

From *कोष* (*kośa*) — treasury, repository, store. Coined into the project's
namespace the same way `Bhaskix` was, and for the same reason: a name the
project owns rather than a dictionary word anyone can claim.

The scope requested is a single system that is simultaneously:

- **Elastic from one node** — usable on a single machine, growing to two,
  three, and beyond without a migration or a different product.
- **Replicated at RF=1…n**, chosen per volume rather than per cluster.
- **Multi-protocol** — block, file, object, and key-value over one substrate.
- **Geo-replicated across heterogeneous sites**, with unequal hardware and
  unequal links.
- **Unified across workloads** — VM images, HPC scratch, and ordinary
  application data on the same pool.

This RFC scopes that honestly. It does not describe the finished system; it
decides what gets built, in what order, what is refused outright, and — the
part that matters most — **which claims cannot be made truthfully** and must
therefore never appear in the documentation or on a slide.

---

## Motivation

### Why this is a commitment, not an extension

RFC 0003 §"Sequencing" has a row that this RFC exists to change:

| Phase | Deliverable |
|---|---|
| **Not committed** | Ceph-scale or Lustre-scale distributed filesystem. *A decade and a team.* |

That estimate was not pessimism and it is not withdrawn. Ceph is roughly twenty
years old and has had hundreds of contributors; vSAN, GPFS and Lustre are of
similar scale. Committing to Kosh means accepting that the distributed tier is
a decade-scale programme, and the value of this document is in making the
first two years of it useful on their own.

**The single-node work is not a stepping stone to be thrown away.** Every layer
below is useful, shippable, and certifiable on one machine. If the distributed
tier is never funded, what remains is still a Merkle-checksummed,
copy-on-write, capability-scoped store with atomic update and attestable
integrity — which is what RFC 0003 argued a government evaluator actually
needs.

### Why unified is the defensible claim

The three-protocol split is where most storage products accumulate their
complexity: a block product, a file product and an object product, each with
its own replication, its own repair, and its own bugs. RFC 0003's bet is that
redundancy belongs *below* the protocol, so that a VM disk, a POSIX file and
an S3 object inherit it from one implementation.

Kosh is that bet at cluster scale. It is also the one place where "we wrote our
own kernel" pays for itself twice: the storage stack is not fighting a VFS that
assumes POSIX, and it is not fighting a page cache that assumes a block device.

---

## The claims that cannot be made truthfully

This section is first, not last, because everything else is easier to design
once these are settled. Each is a place where storage products routinely
mislead, and where Bhaskix's credibility would not survive being caught.

### 1. RF=1 is not durable, and must be labelled so

A single replica is a *placement*, not a redundancy policy. A volume at RF=1
loses data when its device fails. Kosh must refuse to describe RF=1 as
protected, must warn at creation, and must report it as `Unprotected` in every
status output rather than as "healthy".

### 2. RF=2 on exactly two nodes cannot survive a partition safely

This is the most common lie in the category. With two voters and no third
party, a network partition leaves each side unable to distinguish "the peer is
dead" from "the peer is unreachable". Continuing on both sides is split-brain
and silent divergence; halting on both sides is a total outage.

There is no clever resolution. The only honest answers are:

- **A witness** — a third vote that stores no data and can run on anything,
  including a low-power box or another site. This is the recommended default,
  and Kosh should make a two-node cluster *ask* for one.
- **A declared primary** — one side keeps serving, the other stops. Safe, and
  asymmetric in a way the operator must choose deliberately.

Kosh must implement one of these explicitly and never silently pick.

### 3. Geo-replication is asynchronous, and therefore lossy on failover

Synchronous replication means every write pays a round trip. Mumbai to Chennai
is roughly 1,000 km, which is about 10 ms of round trip *at the speed of light
in fibre*, before any equipment. No amount of engineering removes it.

So cross-site replication is asynchronous, and asynchronous replication has a
non-zero **RPO**: on a site failure, recent writes that had not yet shipped are
lost. Kosh must *measure and report* its current RPO — "replication lag: 4.2 s"
— rather than describing itself as "geo-replicated" and leaving the reader to
assume zero. A product that cannot state its RPO does not know it.

### 4. Replication is not backup, and must never be sold as it

Replication copies every write faithfully, including the destructive ones. A
`rm -rf`, a ransomware encryption pass, or a corrupting application bug is
replicated to all `n` copies at wire speed — RF=3 across three sites means
three copies of the damage. Every storage product knows this and a great many
market around it.

Kosh's answer is that the two mechanisms are architecturally distinct and both
must exist:

- **Replication** protects against *hardware and site loss*. It is
  synchronous, current, and copies everything.
- **Snapshots** protect against *logical loss* — the mistake, the bug, the
  attacker. They are points in time, and because Layer 0 is copy-on-write they
  cost nothing to take and nothing to keep beyond the divergence.

A snapshot that can be deleted by whoever compromised the system is not
protection. Kosh must support **immutable snapshots with a retention floor**,
where the retention capability is separate from the write capability — which
the capability model makes expressible in a way a POSIX permission bit is not.
This is a genuine advantage of the architecture and one of the few places the
capability story pays off visibly to a buyer.

### 5. "Universal" is a description of the interface, not of performance

One substrate serving VM images, HPC scratch and application data does not mean
it is *optimal* for all three. HPC wants huge sequential streams and no
metadata in the path; VM disks want small random writes and instant clones;
application data wants POSIX semantics that cost the most of the three. The
personalities let each avoid paying for the others' semantics — they do not
make one implementation the fastest at all three, and Kosh should not imply it.

---

## Design

### The layering, and what Kosh adds

RFC 0003's Layers 0–2 are taken as given. Kosh adds the distribution tier
between placement and the protocols:

```
   Layer 2   personalities        block │ POSIX │ object │ key-value
             ─────────────────────────────────────────────────────
   Layer 1½  distribution         cluster map · replication · repair · geo   ← this RFC
             ─────────────────────────────────────────────────────
   Layer 1   placement            extent groups, redundancy policy
   Layer 0   extent store         log-structured, CoW, Merkle-checksummed
```

Placing distribution *below* the personalities is the same architectural bet
RFC 0003 made for redundancy, extended: a VM disk replicated across three sites
and a POSIX file replicated across three sites use one implementation of
replication, not two.

### One code path at every size

**The single hardest constraint, and the one that must hold from the first
line of code: `n = 1` is not a special case.**

A system with a "single-node mode" and a "cluster mode" has two products, two
sets of bugs, and a migration between them that users discover is the risky
part. Kosh runs the same replication, the same cluster map and the same repair
logic on one node as on a hundred; at `n = 1` the map has one entry, every
placement resolves locally, and consensus is degenerate.

This costs something real up front — a single-node write goes through
machinery it does not need — and it is worth it. The alternative is discovered
late, and the discovery is a rewrite.

### Cluster membership and the map

Kosh needs exactly one piece of strongly consistent state: **the cluster map** —
which nodes exist, which devices they hold, what failure domain each is in, and
which volumes have which policy. Everything else is derived.

- **Consensus: Raft**, over the map only. The map is small, changes rarely
  (node added, device failed, policy edited) and is read constantly, so it is
  exactly the shape consensus is good at. Data never goes through it.
- **At `n = 1`** the log has one voter and commits locally. Degenerate, not
  special-cased.
- **At `n = 2`** there is no majority; see the witness discussion above.
- **From `n = 3`** ordinary majority quorum.

### Placement: deterministic, not looked up

Given the cluster map and an object identifier, **any node computes where the
replicas live** — no metadata server, no lookup, no round trip before a read.
This follows Ceph's CRUSH, and for the reason CRUSH exists: a metadata service
in the data path is the thing that stops distributed filesystems scaling, and
RFC 0003's key-value personality already claims "no metadata server in the
path". Kosh must not contradict its own architecture one layer down.

Placement must be:

- **Failure-domain aware** — a tree of device → host → rack → site, with the
  rule expressed as "replicas must span *k* domains at level *L*". This is what
  makes "3 copies" mean something rather than three copies on one shelf.
- **Weighted**, for heterogeneity. Nodes differ in capacity and in media class,
  and a placement function that assumes uniformity strands capacity on the
  large nodes and overloads the small ones.
- **Stable under change** — adding a node must move roughly `1/n` of the data,
  not reshuffle everything. This is the property naive hashing lacks and the
  reason consistent hashing exists.

### Data locality

Distance costs latency, and on a shared network it also costs everyone else
bandwidth. Locality is therefore not a tuning knob added later; it is a
placement input.

**Reads prefer the nearest copy.** With RF=n there are n places to read from,
and they are not equivalent: same device, same host, same rack, same site,
remote site. A read served from local NVMe and a read served across a WAN
differ by four orders of magnitude. Kosh ranks replicas by the same
failure-domain tree used for placement, and reads the nearest healthy one.

**Writes cannot be local.** A synchronous write at RF=n is only durable once
every in-quorum replica has it, so write latency is the slowest replica's
regardless of where the writer sits. Locality helps reads, and helps writes
only by making one of the replicas local so the *others* are the tail. Any
claim that locality speeds up replicated writes is a claim about a weaker
durability guarantee.

**The interesting case is moving the compute, not the data.** Bhaskix
schedules VMs and containers as domains under one scheduler, and Kosh knows
which nodes hold which extents. That makes "start this VM where its disk
already is" a placement decision the system can make itself, rather than an
operator convention. It is the hyperconverged argument, and it is more
defensible here than in a stack assembled from separate products, because both
halves are the same project's — `docs/scheduler.md` §5's placement hooks and
Kosh's cluster map are the two inputs to one decision.

That is also the honest limit of the claim: the mechanism is a *hint*. A domain
pinned to the node holding its data is a domain that cannot be moved for load,
and the two goals conflict directly. Kosh should express locality as a weight
the scheduler may trade off, never as a constraint it must satisfy — a
constraint turns a busy node into a queue and calls it optimisation.

**A local read cache** for remote data is the remaining lever, and it is
deferred: it introduces a second copy with its own coherence problem, and
coherent caching across nodes is a distributed-systems project in itself.

### Consistency

| Scope | Model | Consequence |
|---|---|---|
| Within a site, RF≥2 | **Synchronous, primary-copy.** A write acknowledges after it is durable on every in-quorum replica. | Reads are consistent; a node failure loses nothing. Write latency is the slowest replica's. |
| Across sites | **Asynchronous**, per-volume, with reported lag. | Non-zero RPO, stated in seconds. Failover is an operator decision, not automatic. |

Automatic cross-site failover is deliberately **not** offered. A system that
cannot distinguish "the other site is down" from "the link is down" will
eventually promote both, and cross-site split-brain is unrecoverable in a way
that within-site split-brain is not.

### Disaster recovery, as distinct from high availability

These are routinely conflated and they are different mechanisms with different
guarantees. Kosh should use the words precisely and force the operator to as
well:

| | High availability | Disaster recovery |
|---|---|---|
| Protects against | Device, host or rack loss | Site loss |
| Scope | Within a site | Between sites |
| Replication | Synchronous | Asynchronous |
| RPO (data lost) | **Zero** | Non-zero, measured, reported |
| RTO (time to serve) | Seconds, automatic | Minutes, **operator-initiated** |
| Failure mode if wrong | Outage | Split-brain, unrecoverable |

**Both numbers must be measured, not asserted.** RPO is the current replication
lag, which Kosh already has to compute to report it. RTO is only knowable by
performing a failover, which means:

**A disaster-recovery plan that has never been executed is not a plan.** The
single most common finding in a real incident is that the failover procedure
was documented and never run, and that it fails on something trivial. Kosh
should therefore support a **rehearsal**: promote the secondary site against a
snapshot, run the workload, verify, and discard — without touching the primary
and without interrupting replication. If rehearsal is not a first-class
operation, it will not happen.

**Failback is harder than failover and gets forgotten.** After a site failure,
the secondary has accepted writes the primary never saw, and the primary — when
it returns — holds writes that were never shipped. The two have diverged, and
there is no correct automatic merge. Kosh must:

- Detect divergence explicitly, from the extent generations Layer 0 already
  maintains, rather than assuming the returning site is stale.
- Require the operator to choose which side survives, and record the choice.
- Resynchronise by *difference*, using the Merkle tree, rather than by copying
  the volume — a full re-copy after every failover makes failback so expensive
  that sites stop failing back, which quietly halves the investment.

**Layered against the standard rule.** Replication gives copies; snapshots give
history; neither gives an off-platform copy. A software defect in Kosh itself
is correlated across every node running Kosh, so an export path to
foreign media is a requirement rather than an admission — and it is exactly
what an evaluator will ask for.

### Repair, and the operation everything else depends on

Changing redundancy is the operation that makes RF=1→2→n and elastic growth
real, and it is where distributed storage systems are actually hard:

- **Re-replication must be online**, throttled, and resumable. A repair that
  saturates the network converts one failed disk into a site-wide outage — the
  well-documented failure mode of naive rebuild.
- **Scrub** must read and verify Merkle checksums continuously, not on demand,
  because the point of checksums is detecting corruption *before* the other
  copy also fails.
- **Repair must be provably complete.** "Rebuilding: 94%" is only useful if the
  remaining 6% is bounded; a system that cannot say when it will be protected
  again cannot be operated.

### Personalities, mapped to the requested workloads

| Requested | Personality | Notes |
|---|---|---|
| Create VMs | **Block** | An object exposed as a block device. Copy-on-write clone means VM provisioning is a map update, not a copy. |
| High-performance workloads | **Key-value** | No metadata in the path; the HPC access pattern RFC 0003 §"POSIX is the bottleneck" describes. |
| Applications | **POSIX** | Full semantics, paid for only by callers who ask. |
| Network distributed | **Object** | S3-shaped, immutable-write. |

---

## What is refused, and what is merely deferred

Refusing loudly is most of the value of a scoping document.

| Item | Status | Why |
|---|---|---|
| **Erasure coding** | Deferred, Phase 4+ | Replication first. EC changes the repair path, the read path and the failure analysis at once; layering it on top of an unproven replication tier means debugging both together and trusting neither. |
| **Deduplication** | Deferred, no date | Interacts badly with encryption and with the integrity story, and the wins are workload-specific. |
| **Synchronous cross-site replication** | **Refused** | Physics. See "claims that cannot be made". |
| **Automatic cross-site failover** | **Refused** | Cannot be made safe without an arbiter no customer will deploy. Operator-initiated only. |
| **Ceph or S3 wire compatibility** | **Refused as a goal** | Compatibility with a protocol means inheriting its semantics, which is how RFC 0003's whole argument gets given away. An S3-*shaped* personality is not the same as bug-for-bug compatibility. |
| **POSIX as the primary interface** | **Refused** | RFC 0003 §"POSIX is the bottleneck". |
| **Coherent cross-node read cache** | Deferred | A second copy with its own coherence problem; a distributed-systems project inside a distributed-systems project. |
| **Locality as a hard placement constraint** | **Refused** | It conflicts directly with load balancing, and a constraint turns a busy node into a queue. Locality is a weight the scheduler may trade off. |
| **Automatic failback after a site returns** | **Refused** | Both sides will have diverged. There is no correct automatic merge; the operator chooses and the choice is recorded. |
| **Kernel-mode client for other operating systems** | Deferred | Serving Linux clients means an NFS or SMB personality, which is a protocol project of its own. |

---

## Sequencing

Nothing distributed can begin before Bhaskix has a network stack, which is
Phase 2. **Kosh's first years are single-node, and that is not a delay — it is
the part that is independently useful.**

| Stage | Deliverable | Prerequisite | Size |
|---|---|---|---|
| **K0** | Extent store on one device: log-structured, CoW, Merkle-checksummed. Block and POSIX personalities. | M6 | Substantial |
| **K1** | Multi-device on one node: pools, mirroring across devices, scrub and repair. **RF=1 and RF=2 within a machine.** | K0 | Substantial |
| **K2** | Cluster map over Raft; node join and leave; deterministic placement. **Still no data replication across nodes** — this stage is membership only, and shipping it alone is what makes the next one debuggable. | K1, networking | Large |
| **K3** | Synchronous replication across nodes, RF=1…n; online RF change; throttled re-replication; witness for two-node. | K2 | Large |
| **K4** | Failure-domain trees, weighted heterogeneous placement, rebalancing on topology change. | K3 | Large |
| **K4½** | Locality-ranked reads; locality as a scheduler placement weight; immutable snapshots with a retention floor. | K4 | Substantial |
| **K5** | Asynchronous geo-replication with measured RPO; operator-initiated failover; **rehearsal and difference-based failback**. | K4½ | Large |
| **K6** | Erasure coding; object and key-value personalities at scale. | K5 | Very large |

**K2 shipping without replication is deliberate.** The temptation is to build
membership and replication together, because neither is useful alone. The
result is a first cluster test in which a placement bug and a replication bug
are indistinguishable. Cluster membership that demonstrably survives node
churn, with no data at risk, is worth a release on its own.

---

## Security implications

Per [security.md](../security.md) §1.

- **Capability scoping survives distribution, and must.** An object is reachable
  by presenting a capability, and that does not become "reachable by any node in
  the cluster". Inter-node authority needs its own answer: a node holding a
  replica must be able to serve it *without* thereby holding authority over
  every object. This is unresolved and is the most important open question here.
- **The cluster network is a new trust boundary.** Replication traffic must be
  authenticated and encrypted; a node that can inject writes into the
  replication path can corrupt every volume. Mutual authentication with
  per-node identity, and a node's admission to the map as the only grant.
- **New parsers on untrusted input**: the replication wire protocol and the
  on-disk metadata format. Both are mandatory fuzz targets before their stage
  merges, per [coding-style.md](../coding-style.md) §8.
- **Integrity gets stronger, not weaker.** Merkle root hashes already prove an
  object's contents; with replication, a mismatched replica is *detectable and
  repairable* rather than a coin flip between two copies. This is a real
  advantage over systems that replicate without checksumming, and it is worth
  stating because it is true.

---

## Performance implications

Every number here is a hypothesis until measured, and should be written that
way in any material that leaves the project.

- **Single node, RF=1**: the target is to be within 20% of the raw device for
  sequential writes. Log-structured layout should help; Merkle checksumming
  costs CPU.
- **RF=n within a site**: write latency becomes the slowest replica's, not the
  average. The metric that matters is the **99.9th percentile**, because tail
  latency is what a VM guest experiences as a stall.
- **Repair throughput versus client impact**: the number to publish is not
  "rebuild speed" but *client latency during rebuild*. A fast rebuild that
  halts the workload has solved nothing.
- **Geo**: the number is replication lag, reported continuously.

---

## Testing plan

- **Host, and most of it.** Placement is a pure function of (map, identifier) —
  it needs no cluster, and its properties are testable exhaustively: replicas
  span the required domains; adding a node moves about `1/n`; weights are
  respected. The extent tree, the Merkle logic and the wire codecs are likewise
  pure.
- **Deterministic fault injection, not a soak test.** A cluster test that runs
  for a week and passes proves very little. Kosh needs a harness that drives
  *scripted* failures — kill a node mid-write, partition during a map change,
  fail a device during repair — reproducibly, from a seed.
- **Split-brain must be a test, not a hope.** The two-node partition case is
  the one this RFC is most emphatic about, so it gets an explicit gate: both
  sides partitioned, and the assertion is that at most one accepts writes.
- **Data integrity is the top-level gate**, in the shape `memory.md` §7's
  frame-leak test already established for memory: write a known corpus, inject
  corruption directly into a replica, and assert the read returns correct data
  *and* reports the repair. Negative-tested by disabling the checksum compare.
- **Failover and failback are gates, not procedures.** The rehearsal path is
  tested on every release: promote a secondary from a snapshot, run a
  workload against it, verify, discard, and assert replication was never
  interrupted. Failback is tested by *deliberately diverging* both sites and
  asserting that Kosh detects it and refuses to merge silently.
- **Locality is asserted on placement, not on latency.** Reading a benchmark
  number proves nothing repeatable in a VM; the testable property is that the
  replica chosen for a read is the nearest healthy one given a synthetic
  topology, which is a pure function and belongs on the host.
- **The snapshot-versus-replication distinction gets a gate**, because it is
  the one users get wrong: delete a file, assert every replica reflects the
  delete (replication is working) *and* that the snapshot still returns it
  (history is intact). A system that passes only the first is a system that
  will lose someone's data to a typo.
- **Fuzz targets**: the replication protocol and the on-disk metadata parser.

---

## Alternatives considered

| Alternative | Why rejected | Would reconsider if |
|---|---|---|
| **Port or fork Ceph** | It is C++ on Linux, assumes a POSIX VFS and Linux threading, and is larger than Bhaskix will be for years. Porting it makes Bhaskix a host for someone else's storage, which is the BOSS Linux mistake RFC 0003 §"The cautionary precedent" warns about. | Never as the storage layer. A Ceph *client* personality is a separate, reasonable question. |
| **Metadata service in the data path** (GFS/HDFS shape) | Simpler to build and the known scaling ceiling of the category. Contradicts RFC 0003's own key-value claim. | The deterministic placement function turns out to make rebalancing unmanageable — a real risk, and the reason K4 is scoped separately. |
| **Build the distributed tier first** | There would be nothing to distribute. The extent store is the substrate; a cluster of unproven stores is an unproven cluster. | Never. |
| **Single-node only, and refuse the rest** | Honest, and it forfeits the workloads — VM farms, HPC, geo-resilient infrastructure — that make an indigenous platform interesting to a government at all. | If the distributed tier is not funded. K0 and K1 are shaped so that this remains a clean stopping point rather than a half-built cluster. |
| **Erasure coding from the start** | Better storage efficiency and a much harder repair path. Doing it before replication is proven means two unproven mechanisms in one failure analysis. | After K3 is stable, as K6. |
| **`n = 1` as a special case** | Faster to build and the source of the migration cliff between "single" and "cluster" products. | Never; see "One code path at every size". |

---

## Impact on existing design documents

| Document | What changes |
|---|---|
| [rfc/0003](0003-storage-architecture.md) | Its sequencing table lists Ceph-scale distribution as "not committed". If this RFC is accepted that row is superseded, and the table should point here. Layers 0–2 are unchanged and remain the authority for them. |
| [roadmap.md](../roadmap.md) | Phase 3 "Storage — volume management, snapshots, encryption at rest" is K0–K1. Phases 3+ and 4 need the K2–K6 stages added. |
| [security.md](../security.md) §1 | The threat model gains the cluster network as a boundary, and a hostile or compromised peer node as an adversary. Neither is currently in scope. |
| [architecture.md](../architecture.md) §2 | Kosh is the largest service domain the project will have; it is the real test of the relocatable-service claim. |

---

## Unresolved questions

1. **How does a capability survive a hop?** A node holding a replica must serve
   it without thereby gaining authority over everything. This is the deepest
   open question in the RFC and it is a capability-system question, not a
   storage one. *Blocks K3.*
2. **Witness or declared primary as the two-node default?** A witness is safer
   and requires a third box; a declared primary requires none and is
   asymmetric. Probably witness, defaulted, with the other available.
   *Blocks K3.*
3. **Which deterministic placement function?** CRUSH is proven and has known
   rebalancing pathologies. Consistent hashing with virtual nodes is simpler
   with different trade-offs. Decide with a simulation on the host, not by
   argument. *Blocks K2.*
4. **Is the on-disk format stable from K0, or explicitly unstable until K3?**
   Committing early costs flexibility; committing late means real users cannot
   upgrade. Declaring it unstable with a stated end date is probably right.
5. **Does Kosh run in the nucleus or a domain?** [architecture.md](../architecture.md)
   §2 says services are relocatable. This is where that gets tested for real,
   and the answer may differ between K0 and K3.
6. **How is locality expressed to the scheduler?** `docs/scheduler.md` §5 charges
   migration against measured cost; a data-locality weight is a second input to
   the same decision, and the two need a common currency. Nothing in either
   document defines one yet.
7. **What is the retention floor's unit of authority?** An immutable snapshot is
   only immutable if the capability that can shorten its retention is separate
   from the one that writes the data — and possibly separate from the one that
   administers the cluster. This is the same question as (1), from the other
   end.
8. **What is the smallest useful witness?** If it can run on an ARM SBC, a
   two-node deployment becomes practical for exactly the edge and OT sites
   [RFC 0004](0004-ot-security-gateway.md) targets.

---

## Implementation plan

Not a schedule — a decomposition. Nothing before M6.

1. **Name and skeleton.** `kosh` crate, the object and extent types from RFC
   0003 §Layer 0 as pure data structures, host-tested. No I/O.
2. **Extent store on one device**, over the M6 block driver. Log-structured
   commit; crash consistency by finding the last valid commit. Gate: a corpus
   survives a power-cut simulation at every write boundary.
3. **Merkle checksumming and scrub.** Gate: injected corruption is detected,
   negative-tested by disabling the compare.
4. **Block personality**, then POSIX. Gate: a VM image, cloned, provisions in
   constant time.
5. **Multi-device pools and mirroring** (K1). Gate: pull a device mid-write,
   data intact, repair completes and says so.
6. **Placement function**, host-only, with a simulator (K2). Gate: the
   properties in the testing plan, over thousands of random topologies.
7. **Cluster map over Raft**, membership only, no data (K2). Gate: scripted
   node churn under partition, map stays consistent.
8. **Replication and online RF change** (K3), with the split-brain gate.
9. **Failure domains and heterogeneous weighting** (K4).
10. **Asynchronous geo-replication with reported RPO** (K5).
