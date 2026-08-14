# RFC 0021: A source of unpredictability, and the discovery that there is none

| | |
|---|---|
| **Status** | ✅ **Accepted 2026-08-14**, with its single step implemented. `bhaskix-rand` exists, `Features::rdrand` is probed and printed, and a boot draws two values and asserts they differ. **Both machines were run, not just the convenient one**: `-cpu max` reports `rdrand yes` and demonstrates it; `-cpu qemu64` reports `rdrand  NO`, prints the warning, and **still boots**, which is the policy this document argued for working rather than being asserted. Open questions 1, 2 and 3 stay open. |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | `arch`, kernel, a new `bhaskix-rand` crate |
| **Milestone** | Phase 2 — required before [RFC 0020](0020-tcp.md) step 1 |
| **Depends on** | Nothing. It is a prerequisite, not a consequence. |

---

## Summary

**This system cannot produce an unpredictable number, and until RFC 0020 was drafted nothing had
noticed.** There is no `RDRAND`, no `RDSEED`, no entropy pool and no interface that returns one;
the only `Rng` in the tree is a seeded mutation harness in `kernel/src/elf.rs` used by a test.

The proposal is deliberately small, because **`RDRAND` is an unprivileged instruction** and so is the
`CPUID` that detects it. A program in ring 3 can therefore obtain unpredictability without holding
anything, exactly as RFC 0019 found it could already read a clock. There is no capability to design
and no system call to add.

What is left is real but narrow: a **shared implementation** that gets the failure mode right, a
**boot-time feature probe** so a machine without it is known rather than assumed, and a **policy** —
what a machine with no source of unpredictability is allowed to do.

## Motivation

**RFC 0020 cannot start without it.** A TCP initial sequence number must be unpredictable, or an
off-path attacker who never sees a packet from a connection can inject data into it. That is not a
hardening nicety; it is the difference between a stack being safe on a network and not being safe on
one.

**And TCP is not the only caller, which is what makes this an RFC rather than a step.** Three others
already exist or are already wrong:

- **Ephemeral ports are a counter.** `user/ipd/src/main.rs:801` assigns `49152 + index`, so the
  first socket on any boot gets 49152. Port randomisation is half of what makes off-path injection
  hard; the other half is the sequence number. Both are currently absent, and they are absent for
  the same reason.
- **`docs/security.md`'s mitigation table already claims a randomisation this system does not
  perform.** Its row reads *"KASLR | Randomise kernel image and heap base | Always on"*. The kernel
  image is slid — by **Limine**, not by us: `kernel/src/lib.rs:10599` computes the slide it was
  given rather than choosing one. The heap base is not randomised at all. It lives in the direct
  map, and this machine's boot reports `hhdm base 0xffff800000000000`, which is the protocol's fixed
  address on every boot. **Half of that row is false**, and it is false precisely because there is
  no source to randomise from.
- **Anything later that wants a canary, an ASLR offset or a hash seed** meets the same wall.

**What happens if we do nothing**: TCP ships with guessable sequence numbers, or does not ship.

## Design

### Reading unpredictability is unprivileged, and that decides most of this

`RDRAND` requires no privilege. Neither does the `CPUID` that reports it, and this kernel does not
enable `CPUID` faulting. **A ring 3 program can therefore detect and use it with no help from the
kernel and no capability at all.**

This is the same finding RFC 0019 recorded about `rdtsc` and it has the same consequence: designing
a `Random` capability would be ceremony around an instruction any program can already execute, and
would read as authority the system does not actually control. It is stated here so that a later
reader does not mistake its absence for an oversight.

**So the kernel gains no object, no method, and no system call.** What it gains is a feature bit and
an opinion.

### `bhaskix-rand`: one implementation, because the failure mode is the whole difficulty

A new crate, `no_std`, usable by the kernel and by ring 3 services alike — the pattern `bhaskix-net`
already establishes for code both sides need.

```rust
pub fn available() -> bool;          // CPUID leaf 1, ECX bit 30
pub fn u64() -> Option<u64>;         // None if unavailable, or if the hardware would not answer
```

**`RDRAND` can fail, and ignoring that is the classic bug.** It sets the carry flag to say whether
the value it produced is usable; under contention it can decline. Code that reads the register
without testing `CF` gets whatever was there — on some parts, zero, repeatedly. So:

- The carry flag is tested, always.
- A bounded retry — ten attempts, the figure Intel's own guidance uses — and then **`None`**.
- **`None` is never turned into a number.** A caller that cannot proceed without unpredictability
  must fail, and the type makes that unavoidable rather than merely advised.

Two lines of `unsafe`, one instruction, and a budget of its own so that a third line is a
conversation.

**`RDSEED` is not used, and the reason is measured rather than assumed.** It is the more direct
source — the entropy behind `RDRAND`'s generator — but QEMU's `-cpu max`, which is the machine every
harness in this project boots, reports `rdrand: true` and **`rdseed: false`**. Checked on this
machine's QEMU 4.2.1 through `query-cpu-model-expansion`, not recalled. A design whose only
implementation could not be tested in CI is a design this project has already argued against once,
in RFC 0012, and it was right then.

### The probe, and what a machine without it may do

`bhaskix_arch::msr::Features` already exists and already carries exactly this kind of fact — `nx`,
`smep`, `smap`, `umip`, `la57`, `invariant_tsc` — probed at boot and printed, because
`docs/security.md` §4 makes some of them load-bearing and an operator needs to see which are
actually present. `rdrand` joins it, and the boot line says so.

The policy, in the vocabulary `security.md`'s table already uses:

| | |
|---|---|
| **Not** refuse to boot | A machine with no `RDRAND` is a working machine. It has a filesystem, a shell and a supervisor, none of which need to be unpredictable. Refusing to boot would be this project's strongest sanction applied to a machine that is merely limited. |
| **Warn loudly, and record it** | The same treatment SMAP's absence gets: printed at boot, and part of what the machine reports about itself. |
| **Refuse the things that need it** | `bin/tcpd` does not start. `bin/ipd` keeps its counter and **says** the ports are predictable rather than implying otherwise. The refusal is at the caller, where the requirement is, rather than in a kernel that cannot know who needs what. |

**Refusing at the caller is the load-bearing part.** A system-wide "no randomness, no boot" hides
the question; a system-wide fallback answers it wrongly for everyone. Each caller knows whether it
can proceed, and TCP is the one that cannot.

### What is deliberately not built

- **No entropy pool.** Collecting, mixing and reseeding from interrupt timing and device jitter is a
  subsystem, not a function, and it is only worth building when there is a machine that needs it —
  which today means a machine without `RDRAND`, which this project has never booted on.
- **No cryptographic API.** No hashing, no DRBG, no key material. `RDRAND` is a hardware CSPRNG and
  the callers here want unpredictable integers, not a cryptographic library.
- **No system call.** See above; there is nothing to mediate.

## Alternatives considered

| Alternative | Why rejected | Would reconsider if |
|---|---|---|
| **A `Random` capability or a syscall** | Ceremony around an unprivileged instruction. The capability would guard nothing, because a program that was refused it could execute `RDRAND` anyway. | If `CPUID` faulting were enabled and the kernel actually controlled access — which would be a separate decision with its own costs, exactly as RFC 0019 said about `CR4.TSD`. |
| **Seed from the TSC** | It is the tempting fallback and it is the dangerous one. Uptime is estimable by anyone who can talk to the machine, so the ISN becomes a narrow guess rather than a wide one — and it *looks* solved, which is worse than being visibly absent, because the next reader stops looking. | Never as a silent fallback. Only as an explicitly labelled insecure mode, and the refusal is cheaper than the label. |
| **A software entropy pool now** | Real work, for a machine this project has never had. Building it before there is a machine that needs it means testing it against nothing. | The first physical machine (M1-17) turns out to lack `RDRAND`, or a target appears where it must not be trusted. |
| **Mix `RDRAND` with a second source** | Correct in principle — Linux does not trust `RDRAND` alone, because a backdoored hardware generator is undetectable from the outside. Rejected only because **there is no second source to mix with**, and inventing one is the pool above. Recorded as an open question rather than dismissed. | A pool exists, or a second hardware source does. |
| **Use `RDSEED` in preference** | It is the better primitive and the harness's own machine does not have it. | The CI machine gains it, at which point it is a preference inside this crate and not a design change. |
| **Put it in `bhaskix-abi`** | `abi`'s `unsafe_budget` is zero by deliberate policy, and this needs inline assembly. | Never; the budget is the point. |

## Impact on existing design documents

- **[security.md](../security.md) §4** — the hardware-feature table gains an `RDRAND` row with the
  policy above. **And its KASLR row is corrected**: it claims the kernel randomises "kernel image and
  heap base"; the image is slid by the bootloader and the heap base is not randomised at all
  (`hhdm base 0xffff800000000000`, every boot). Correcting a claim the code does not implement is
  part of this change, not a follow-up.
- **[architecture.md](../architecture.md)** — gains a crate, at the layer `check-deps.py` assigns.
- **[rfc/0020-tcp.md](0020-tcp.md)** — its open question 1 is answered by this document existing;
  its step 1 depends on this landing first.
- **`tools/check-deps.py`** — `bhaskix-rand` needs its layer entry.

## Security implications

**New authority: none.** Nothing here can be held, granted or revoked, because the instruction it
wraps is available to everyone already.

**What changes is what the system can honestly claim.** Today `security.md` asserts a randomisation
that does not happen. After this, the machine reports whether it can be unpredictable at all, and
the components that depend on it refuse rather than pretend.

**A trust assumption, stated plainly**: this depends on a hardware generator that cannot be audited
from outside. That is a real weakness, it is the reason mature systems mix `RDRAND` with other
sources, and this system has nothing to mix with. It is recorded as an open question rather than
hidden behind a wrapper that looks like a pool.

**No new parser**, and no new reachable surface.

## Performance implications

`RDRAND` costs on the order of a few hundred cycles and is called once per connection and once per
port assignment, not per packet. Nothing here is on a hot path. The one thing worth measuring is the
**failure rate under contention** — how often the bounded retry gives up on four processors — because
a caller that must refuse when it fails needs to know how often that is.

## Testing plan

- **Host**: the retry-and-give-up logic, with the instruction behind a trait so a stub can fail
  every attempt, fail nine times and succeed on the tenth, and report unavailable. That is where the
  actual difficulty is, and none of it needs a CPU that has the feature.
- **Watched failing**: delete the carry-flag test and the "fails nine times" case must go red. A
  test that cannot distinguish a returned zero from a produced zero is not testing anything.
- **QEMU**: the boot reports `rdrand` present, and two values drawn in one boot differ. The second
  half is weak evidence on its own and is stated as such — it catches a stub that returns a
  constant, which is exactly the failure the carry flag causes, and nothing subtler.
- **Not tested here**: the quality of the hardware's output. Statistical testing of a CSPRNG is a
  research exercise and would be theatre in a boot gate.
- **No fuzz target**: there is no untrusted input. The value comes from the CPU.

## Unresolved questions

1. **Is depending on an unauditable hardware generator acceptable for this project's stated threat
   model?** `security.md` §1 does not currently contemplate a hostile CPU. The answer is probably
   "yes, and note it", but it should be decided rather than assumed by whoever accepts this.
2. **Does the kernel randomise anything once it can?** The heap base is the obvious first candidate,
   since the security document already claims it. That is a separate change with its own risk to the
   direct map, and it is not part of this RFC.
3. **What does a machine without `RDRAND` do about ephemeral ports?** Refusing TCP is clear. Whether
   `ipd` should keep handing out a predictable sequence, or refuse to bind at all, is a judgement
   about how much worse a predictable port is than no network — and nobody has that machine yet.

## Implementation plan

One step, which is the point of a short RFC.

1. **`bhaskix-rand`**, its host tests including the watched failures, `Features::rdrand` and the
   boot line, the `security.md` rows — the new one and the KASLR correction — and `check-deps.py`'s
   layer entry. RFC 0020 step 1 then consumes it.

   **Done 2026-08-14.** Seven host tests; deleting the carry-flag check in `interpret` turns exactly
   three of them red — the refused attempt, the processor that never answers, and the off-by-one on
   the last attempt — and leaves the other four green, which is the right answer rather than a
   coincidence: they do not exercise the failure path. A boot draws twice and asserts the values
   differ, with a positive gate in `boot-test.sh` as well as the `FAILED` marker, because the marker
   catches a self-test that ran and failed and only a positive gate catches one that stopped running.
   Breaking the draw to return the same value twice fails both. `unsafe_budget = 21`, set to exactly
   what the two `asm!` blocks cost, with no headroom.
