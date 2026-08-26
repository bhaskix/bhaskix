# Bhaskix — Prior art and neighbouring systems

*Status: living document. Prerequisite reading: [architecture.md](architecture.md), [security.md](security.md).*

A system that refuses things has to be able to say what it refuses **relative to what other people
are building**, and to say it in a form that survives the week it was thought about. This document
records those comparisons as they are made, dated, with sources.

---

## 0. How entries here are written

These rules exist because a comparison is the easiest place in a project's documents to flatter
itself.

1. **Cite the source and the date it was read.** A neighbouring system moves; an entry that does not
   say when it was looked at is an entry nobody can check.
2. **Separate what the source says from what we infer.** Quotes are quotes. An inference from a
   quote is labelled as one, and an inference drawn from a *summary* rather than from the code says
   so, because that is a weaker thing.
3. **State where Bhaskix is behind.** Every system here is further along than this one in some
   direction, and usually in the direction that matters to a user. An entry that finds only
   favourable differences has been written badly.
4. **Say what would change our mind.** A comparison that no evidence could overturn is an opinion
   with citations.

---

## 1. Multikernel — Linux `7.0-mk2`

**Read 2026-08-26**, from Phoronix's report of the release
(`phoronix.com/news/Linux-7.0-mk2-Multikernel`). **The tree itself has not been read**, so
everything below that is not a quotation is an inference from a news summary and is marked.

### What it is

A host Linux kernel partitions the machine and boots further, independent Linux kernels into the
partitions. In the developer's words (Cong Wang, of Multikernel Technologies), quoted by the report:

> A host kernel owns a pool of CPUs, memory and PCI devices, carves that pool into instances, and
> boots a spawn kernel into each instance through `kexec_file_load()`.

> Every spawn kernel runs natively on its own CPUs, its own physical memory and its own devices.
> Nothing is emulated and nothing is trapped.

> Instances do not share a kernel, so a lock, a panic or an exploit in one kernel cannot reach
> another.

Device-tree overlays move resources between instances without a reboot. The report describes
performance advantages over KVM virtualisation.

**State, and it matters for any comparison:** this is *"the first public release of the multikernel
Linux tree"* — a **separate tree**, not a mainline feature, and the report states that mainline
integration remains uncertain. It should not be described as "in Linux 7.0".

### The axis

**Multikernel isolates by replication. Bhaskix isolates by reduction.**

Multikernel's isolation comes from instances not sharing a kernel: partition the hardware, run a
whole Linux in each partition. Bhaskix's comes from there being very little kernel to share — a
capability nucleus, no ambient authority, drivers in ring 3 behind IOMMU windows
([architecture.md](architecture.md) §4, [driver-model.md](driver-model.md)).

The consequence is the interesting part. **Replication does not shrink the trusted computing base;
it multiplies it.** Each instance is still a monolithic kernel in which a compromised driver owns
that instance, and there are now several of them. What replication buys is blast radius at coarse
granularity — real, and worth having. What it does not touch is everything *inside* an instance,
which is the region Bhaskix's design is about.

### The question we would ask them

The claim that *"an exploit in one kernel cannot reach another"* is doing more work than the two
claims beside it, and **this is an inference, from a summary, and not a finding**: if nothing traps,
each spawn kernel runs in ring 0 on real cores with control of its own page tables, and ring 0 can
map any physical page it likes. An IOMMU constrains that instance's *devices*, not its *CPU*.
Without something like SEV-SNP or TDX — neither mentioned in the report — peer-to-peer exploit
isolation would rest on each spawn kernel choosing not to look, which is a convention rather than a
mechanism.

The *panic* and *lock* halves of the claim need no such qualification. A panic genuinely cannot
propagate, and that is a strong property that Bhaskix should not be smug about: a nucleus panic
takes the machine.

**That question is exactly where the two designs part.** Bhaskix's isolation is enforced by a
nucleus that stays in control of every domain; multikernel's is arranged by partitioning trust among
ring 0 peers.

### Where Bhaskix is behind, and it is not close

Multikernel runs real workloads on real hardware today, with the whole Linux driver and application
ecosystem behind it. Bhaskix has no libc and no self-hosting, has booted on **one** physical machine
on which **no disk has been found**, and its Phase 0 review criterion — two reviewers who did not
write the documents — is unmet. Architectural cleanliness is not deployability, and a comparison
that leaves this out is the kind of entry rule 3 exists to prevent.

### What we take from it

**It is validation of the problem, not a threat to the approach.** People with funding are attacking
"isolation without the hypervisor tax", which is the bet [vision.md](vision.md) makes. And by adding
a *third* primitive to the Linux world — container, virtual machine, and now spawn kernel — it makes
this project's "domains unify containers and VMs" thesis more interesting rather than less: the
alternative to unifying them is evidently to keep adding them.

**One concrete technical observation, recorded because it bears on a Phase 3 assumption.**
[security.md](security.md) T5 lists VMX/SVM and EPT/NPT as planned and nonexistent, and treats a
hypervisor as the way to run a guest kernel. Multikernel demonstrates a second way — `kexec` a
kernel onto dedicated cores and do not trap it at all — which needs no virtualisation extensions and
would be far cheaper to build.

**We should not take it.** Running a foreign kernel natively means giving it ring 0 on real
hardware, which is the precise property this system exists to refuse; it would import the open
question above into a design whose entire claim is that isolation is a mechanism rather than an
arrangement. Recorded here so that the option is known to have been considered and declined, rather
than rediscovered later as though it were new.

### What would change our mind

- **The tree, read.** If the spawn kernels are constrained by hardware — memory encryption with
  ownership tracking, or nested paging under the host kernel — then the exploit-isolation claim
  stands as written, the inference above is wrong, and it should be corrected here.
- **Mainline acceptance.** A separate tree and a merged subsystem are different things to compare
  against.
- **A measurement of what the partitioning costs.** The interesting number is not throughput against
  KVM; it is how much of a machine is stranded by static partitioning when instances are idle, which
  is the cost a scheduler-based design like this one does not pay.
