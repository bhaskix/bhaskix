# RFC 0003: Storage architecture

| | |
|---|---|
| **Status** | **Draft — for discussion** |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | `fs/`, `drivers/` |
| **Milestone** | Design now; implementation begins M6 and continues through Phase 3 |
| **Depends on** | [RFC 0001](0001-license-apache-2.0.md) (license), M5 capabilities |

---

## Summary

Bhaskix does not build "a filesystem". It builds a **capability-scoped,
integrity-checked object store**, and exposes POSIX as *one personality among
several* on top of it.

```
personalities   POSIX VFS  │  object (S3-shaped)  │  key-value  │  block (VM disks)
                ───────────┴──────────────────────┴─────────────┴──────────────────
placement       replication, erasure coding, and location as properties
                of an extent group -- not a separate clustering product
                ────────────────────────────────────────────────────────
extent store    log-structured, copy-on-write, Merkle-checksummed
                every object reachable only through a capability
                ────────────────────────────────────────────────────────
devices         NVMe, virtio-blk (driver-model.md)
```

The decision this RFC actually asks for is narrow and cheap **today**: make the
storage primitive an object/extent store rather than a block device with a
POSIX filesystem welded to it. That costs nothing now, when `fs/` is empty. It
is a rewrite once a POSIX VFS exists.

---

## Motivation

### The question this answers

*"Why would anyone use a filesystem written from scratch, when ZFS, XFS, Ceph,
and Lustre exist and are decades ahead?"*

They would not — if we compete on the same axis. ZFS took a funded Sun team
years and is still being finished twenty years on. Ceph took fifteen years and
hundreds of engineers. Lustre is older than most of its users' careers.
Out-engineering them from scratch is not a plan.

But there is an axis where none of them can compete, because it is closed to
them by the platform they are built on.

### POSIX is the bottleneck, and Linux makes it mandatory

Every serious distributed storage system on Linux spends enormous effort
fighting the POSIX/VFS shape that Linux imposes:

- **Lustre** bypasses large parts of the VFS and maintains out-of-tree kernel
  patches to do it.
- **Ceph** built RADOS — an object store — and then had to bolt CephFS on top
  to give POSIX back to clients that demand it.
- **DAOS** gave up on the block/POSIX model entirely and went to a key-value
  model over NVMe and persistent memory, precisely because POSIX metadata
  semantics — atomic rename, coherent `stat`, byte-range locks across nodes —
  are what stops scaling past a few thousand nodes.

The pattern is consistent: the people who most need scale discover that POSIX
is the wrong primitive, and then pay to work around a kernel that assumes it.

A kernel written from scratch does not have to make that assumption. **This is
one of the few places where "we built our own kernel" converts into a concrete
technical advantage rather than a slogan**, which is exactly the standard
[vision.md](../vision.md) sets for the project's claims.

### Why this matters for the mission specifically

[vision.md](../vision.md) commits Bhaskix to serving "developers, enterprises,
and governments" with "secure and intelligent computing infrastructure". For
that audience, storage is not optional and it is not primarily about
throughput. It is about **provable integrity**:

- Can you prove the system image has not been tampered with?
- Can you prove an audit log has not been truncated?
- Can you detect silent data corruption rather than serving it?
- Can you update atomically and roll back a bad update?

A Merkle-checksummed, copy-on-write object store answers all four *by
construction*. A conventional block filesystem answers none of them and has to
have each bolted on. For a system that intends to be certifiable — see
[security.md](../security.md) §3 and §7 — the integrity property is not a
feature, it is the foundation of the argument.

### The cautionary precedent

BOSS Linux (C-DAC, government-backed, from 2007) is the honest comparison for
any India-origin operating system, and its lesson is uncomfortable: **being
indigenous and being mandated were not sufficient for adoption.** It was a
Debian derivative, so it owned none of its own technical claims — every
security or integrity property it had, it inherited.

Bhaskix is differently positioned only if it owns the properties it claims.
Building a conventional filesystem would repeat BOSS's mistake at the storage
layer: shipping something that is Indian by authorship but identical in
capability to what already exists, and therefore chosen only when mandated.

---

## Design

### Layer 0 — the extent store

The primitive. Everything else is built on it.

```rust
/// A stored object. Not a file: no name, no path, no directory.
pub struct ObjectId(u128);

pub struct Extent {
    device: DeviceId,
    offset: u64,
    length: u32,
    checksum: Checksum,   // of the extent contents
}

pub struct Object {
    id: ObjectId,
    generation: u64,      // bumped on every write; makes snapshots trivial
    extents: ExtentTree,  // B-tree keyed by logical offset
    root_hash: Checksum,  // Merkle root over the extent tree
}
```

Properties, and why each one is here:

| Property | Why |
|---|---|
| **Log-structured** | Writes are sequential, which is what both flash and shingled drives want. Also makes crash consistency a matter of finding the last valid commit rather than replaying a journal. |
| **Copy-on-write** | Snapshots and clones become free. A VM image clone is a new object sharing every extent. This is the whole virtualization story in one property. |
| **Merkle-checksummed** | Silent corruption is *detected*, not served. And an object's root hash is a proof of its contents — which is what makes attestation of a system image possible at all. |
| **Capability-scoped** | An object is reachable only by presenting a capability for it ([security.md](../security.md) §2). There is no path lookup to race against, so the entire TOCTOU class of filesystem bug is not expressible. |
| **No names** | Naming is a personality concern. Directories are a POSIX idea, not a storage idea. |

### Layer 1 — placement

Replication and erasure coding are **properties of an extent group**, not a
separate product layered on top.

```rust
pub struct ExtentGroup {
    policy: Redundancy,        // Mirror(n) | ErasureCoded { data, parity }
    placement: PlacementRule,  // which failure domains the copies must span
    members: Vec<ExtentRef>,
}
```

Putting this *below* the personalities rather than above them is the whole
architectural bet: it means POSIX files, VM disks, and objects all inherit
redundancy from the same code, instead of each growing its own.

### Layer 2 — personalities

| Personality | Serves | Notes |
|---|---|---|
| **POSIX VFS** | Ordinary software, ported applications | Full semantics, and the cost of them, paid only by callers who ask |
| **Object** | Cloud-native, backups, AI datasets | S3-shaped; immutable-write, no rename, no partial update |
| **Key-value** | HPC, databases, the telemetry plane | No metadata server in the path |
| **Block** | VM disks | An object exposed as a block device; CoW clone = instant VM provisioning |

The point of the table: **HPC and cloud workloads stop paying for POSIX
semantics they never wanted**, which is the single largest source of the
scaling problems in the systems listed earlier.

---

## Sequencing — and the honest scoping

The temptation is to describe the finished system. The useful thing is to say
what gets built when, and to be explicit that the far end is a decade away.

| Phase | Deliverable | Roughly |
|---|---|---|
| **M6** | Read-only initrd filesystem; ELF loading. Enough to reach a shell. | Small |
| **Phase 2** | The extent store on one device: log-structured, CoW, checksummed. POSIX personality over it. `virtio-fs`/9p so Bhaskix can use a *host* filesystem meanwhile. | Substantial |
| **Phase 3** | Encryption at rest sealed to TPM; A/B atomic update with rollback protection; tamper-evident audit log. **This is the certifiable set.** | Substantial |
| **Phase 3+** | Multi-device pools, mirroring, scrub and repair. Single-digit node replication. | Large |
| **Phase 4+** | Erasure coding, real placement policies, many-node clustering. | Very large |
| **Not committed** | Ceph-scale or Lustre-scale distributed filesystem. | A decade and a team |

**`virtio-fs` in Phase 2 is the item that unblocks everything else.** It lets
Bhaskix run real software against a host filesystem long before its own storage
stack is mature. Without it, the project cannot demonstrate anything useful
until the storage stack is finished, which is backwards.

### What a government or enterprise evaluator actually needs

Worth stating plainly, because it is a much shorter list than "a distributed
filesystem", and it is reachable:

1. Integrity that can be *verified*, not asserted — Merkle root hashes.
2. Encryption at rest, with keys sealed to a measured boot state.
3. Atomic update with rollback protection against signed-but-outdated images.
4. A tamper-evident audit log.
5. A documented threat model, and an external audit against it.

That is Phase 3 of this RFC plus [security.md](../security.md) §3 and §7 — not
a Ceph competitor. The distributed story can follow once the trustworthy local
story exists; it cannot precede it.

---

## Alternatives considered

| Alternative | Why rejected | Would reconsider if |
|---|---|---|
| **A conventional block filesystem (ext-like or FFS-like)** | Fastest to a working `open`/`read`/`write`, and the well-trodden path. Rejected because it forecloses everything above: snapshots, integrity proofs, VM cloning, and distribution all become retrofits, and the retrofit is a rewrite. It would also make the storage layer indistinguishable from what already exists, which is the BOSS Linux failure mode. | The project's goal narrowed to a teaching kernel. |
| **Port or reimplement ZFS semantics** | ZFS is the closest existing design to layer 0, and the ideas here owe it a great deal. Rejected as a *port*: the CDDL is incompatible with Apache-2.0 (RFC 0001), and reimplementing it wholesale is a decade of work for a system whose design we would not fully choose. We take the ideas — CoW, Merkle integrity, pooled storage — and not the code. | Never for the code; the ideas are already adopted. |
| **Build on an existing distributed store (Ceph/RADOS) from day one** | Would give clustering immediately. Rejected: it means depending on a Linux-based userspace stack, which contradicts the sovereignty argument in the Motivation and adds an enormous external dependency surface ([security.md](../security.md) §1). | We wanted clustering more than we wanted independence. |
| **POSIX VFS first, other personalities later** | The conventional order. Rejected because in practice the first personality defines the primitive: once the VFS exists, everything below it grows POSIX assumptions, and the object personality ends up emulated on top of files. That is precisely the inversion Ceph had to live with. | — |
| **Object store only; no POSIX at all** | Cleanest, and tempting. Rejected as unusable: no existing software would run, so the project could never demonstrate anything a user recognises. POSIX is a compatibility obligation even where it is not a technical preference. | — |

---

## Impact on existing design documents

| Document | Change |
|---|---|
| [architecture.md](../architecture.md) §5 | `fs/` described as "VFS and filesystems"; becomes "storage: extent store, placement, and personalities" |
| [roadmap.md](../roadmap.md) | M6 narrows to read-only initrd + ELF; the storage stack moves to Phase 2-3 with the sequencing above |
| [driver-model.md](../driver-model.md) §7 | `virtio-fs` added to the Phase 2 driver priority list, ahead of NVMe |
| [security.md](../security.md) §7 | Secure update gains a concrete mechanism: object generations plus root-hash verification |

If this RFC is accepted, those edits are part of the implementation, not a
follow-up.

## Security implications

Substantially positive, and central to the design rather than a side effect:

- **Capability-scoped objects remove path-based TOCTOU entirely.** There is no
  name to resolve, so there is no window between resolving it and using it.
- **Merkle integrity makes tampering detectable**, including tampering by a
  compromised device or a malicious storage backend — which
  [security.md](../security.md) §1 lists as in-scope (T3, T4) and which
  checksum-free filesystems cannot address.
- **New parser surface**: on-disk metadata is untrusted input, including on a
  disk an attacker supplied. Every metadata parser requires a fuzz target
  *before merge*, per [coding-style.md](../coding-style.md) §8. This is the
  single largest new risk the RFC introduces and should be treated as such.
- **Encryption at rest** interacts with the sealed-key model in
  [security.md](../security.md) §3; the object store must not leak plaintext
  metadata (extent sizes and access patterns) that defeats it. Unresolved
  below.

## Performance implications

- Log-structured writes suit flash and are sequential by construction.
- Copy-on-write costs read-modify-write on partial overwrites, and needs
  garbage collection — historically where log-structured designs disappoint.
  **Nothing here should be claimed as fast until measured**; the CoW and GC
  behaviour under a write-heavy VM workload is the benchmark that matters, and
  it does not exist yet.
- Checksum verification costs CPU on every read. Hardware CRC and a fast hash
  make this small, but it is not zero and should be measured, not assumed.

## Testing plan

| Layer | How |
|---|---|
| Extent tree, allocator, Merkle computation | Host unit tests and property tests — all pure logic, no device needed |
| On-disk format | `cargo-fuzz` on every metadata parser, before merge |
| Crash consistency | Deterministic write-fault injection: cut writes at every possible point, assert the store always mounts to a consistent prior state |
| Corruption detection | Deliberately flip bits in extents and metadata; assert detection, and repair where redundancy exists |
| Integrity proof | Assert the root hash changes on any modification and matches across a snapshot round-trip |
| Personalities | The same workload through POSIX and object personalities must agree on contents |

The crash-consistency harness is the highest-value item and should be built
*before* the on-disk format is finalised. A storage system that has not been
crash-tested exhaustively is a storage system that loses data, and finding that
out after there are users is the worst possible outcome for the project's
credibility.

## Unresolved questions

- **Object identifier size and allocation.** 128-bit random, or structured with
  a node identifier for the distributed case?
- **Metadata encryption.** Extent sizes and access patterns leak information
  even when contents are encrypted. How much do we care, and at what cost?
- **Garbage collection policy.** The classic weakness of log-structured
  designs. Is this a candidate for the AI policy hooks in
  [ai-native.md](../ai-native.md) §3, where an eligible-set-plus-ranking model
  fits well?
- **POSIX fidelity.** Which corners do we implement, and which do we refuse?
  `O_DIRECT`, mandatory locking, and full `rename` atomicity are each a real
  cost. Refusing some is legitimate; refusing them *silently* is not.
- **Does the extent store live in the nucleus or in a domain?**
  ([architecture.md](../architecture.md) §2.) It is performance-critical and
  large — the two criteria point in opposite directions.
