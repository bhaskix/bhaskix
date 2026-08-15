# RFC 0025: Four-level paging, on purpose

| | |
|---|---|
| **Status** | Draft |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | arch, boot |
| **Milestone** | Phase 2 — closes **A5**, the last open architecture question |
| **Depends on** | [docs/architecture.md](../architecture.md) §8 (where A5 is asked) |

---

## Summary

**Bhaskix runs four-level paging, and now says so instead of assuming so.** A5 asked whether this
kernel should support LA57 — five-level paging, 57-bit virtual addresses. The answer is: not
until a workload needs an address space wider than 128 TiB per half, and that day has a written
trigger rather than an open wait. What ships now is the part that cannot wait: the kernel's
address arithmetic assumes bit-47 canonicality and a 512-entry PML4 split at index 256 in every
walk, so a boot entered with `CR4.LA57` already set would corrupt addresses *silently*. Bring-up
now checks `CR4` on the bootstrap processor and halts with a named refusal if five-level paging
is live — one register read that converts silent corruption into a sentence.

## Motivation

**The assumption is everywhere and stated nowhere.** `paging.rs` indexes the top level at
`virtual_address >> 39`; the kernel half begins at `KERNEL_PML4_START = 256`; every canonical
check, sign extension and half-split in the tree is a bit-47 statement. None of it is wrong —
it is the right design for every machine this project can currently run on — but nothing
*verifies* it against the machine. The bootstrap path never reads `CR4.LA57`, and the boot shim
makes no paging-mode request of the bootloader, so the four-level world rests on a bootloader
default this project has never written down.

**The hardware already advertises the other world.** The CPU feature word this kernel reads and
prints includes `la57`; QEMU's `-cpu max` sets it. A capable CPU is not a five-level boot — the
mode is what `CR4` says — but a capable CPU under a bootloader whose default changes is exactly
how this goes wrong two years from now, on the first machine that matters.

**What happens if we do nothing**: nothing, until a bootloader update or a physical machine
(M1-17 is blocked on one) enters the kernel in five-level mode, at which point the failure is
address corruption with no line of output pointing anywhere.

## Design

### The refusal

Early bring-up, bootstrap processor, before paging structures are touched: read `CR4`; if bit 12
(`LA57`) is set, print one sentence naming the situation and halt. The check is a load and a
test. The sentence says what mode the machine is in, what mode this kernel speaks, and that the
refusal is deliberate — the same posture as RFC 0021's entropy refusal: a machine this kernel
cannot serve honestly is told so, loudly, instead of being served wrongly.

### The statement

The boot feature line already prints `la57` as a CPU capability. It keeps doing so, and the
report gains the *mode*: four-level, stated, so a log reader sees capability and choice side by
side rather than inferring the second from silence.

### The trigger, written down

Five-level paging gets built when one of these becomes true, and not before:

1. a workload needs more than 128 TiB of virtual address space in one half — today's largest
   consumer maps rings measured in kilobytes;
2. physical memory beyond what the four-level direct map can carry arrives on a machine this
   project targets;
3. the IOMMU work needs guest-address widths only five-level tables express — `vtd.rs` already
   models 57-bit address widths for *device* tables, which is independent of CPU paging and
   stays so.

When triggered, the work is mechanical but wide: the walk gains a level, the half-split moves,
canonicality moves to bit 56, and every constant this RFC lists in its survey becomes a
parameter. That is a real RFC's worth of change, to be written against the trigger's actual
numbers.

### Explicitly not done now

Requesting a paging mode from the bootloader. The vendored Limine protocol has a paging-mode
feature; adopting it means pinning a protocol revision and testing both answers. The `CR4` check
makes the kernel safe under *any* bootloader default — the request would make the preference
explicit to one bootloader, and belongs with the `bhaskixboot.efi` work where the boot contract
is already being rewritten.

## Alternatives considered

| Alternative | Why not |
|---|---|
| Implement LA57 now | Every walk, split and canonical check changes, for an address space nothing here can fill a millionth of. A data structure without a customer, at kernel-wide blast radius. |
| Trust the bootloader default forever | It has held so far, silently. A silent dependency on another project's default is exactly the class of assumption this project writes down or refuses. |
| Support both modes at runtime | Doubles the test matrix for every paging path, on QEMU-only hardware, to serve zero machines. |

## Impact on existing design documents

- [docs/architecture.md](../architecture.md) §8: **A5 is closed** — four-level on purpose, with
  this RFC as the record and the trigger.
- `TRACKER.md`: the open-questions table loses its last architecture row.

## Security implications

The refusal removes a silent-corruption path: address arithmetic running under a wider mode than
it was written for is the kind of wrongness that lands in page-table walks and capability
boundaries before it lands in any visible symptom. One register read at boot closes it.

## Performance implications

None. The check runs once; four-level paging is what already runs.

## Testing plan

- **Host**: the mode-check decision as a pure function of a `CR4` value — set bit 12, expect
  refusal; clear it, expect passage — watched failing by inverting the test.
- **QEMU**: every existing boot passes with the check in place (`-cpu max` advertises `la57`;
  the mode stays four-level, so the check must not fire on capability alone). A forced five-level
  boot is not constructible under the current bootloader without the paging-mode request this
  RFC defers, and the gate says so rather than pretending coverage.

## Unresolved questions

None. This RFC exists to close a question.

## Implementation plan

One step, and it lands with this document: the `CR4` check at bring-up, the mode line in the
boot report, the host test for the decision, and A5 marked closed in the tracker pending
acceptance.
