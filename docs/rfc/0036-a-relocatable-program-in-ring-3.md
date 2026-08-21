# RFC 0036: A relocatable program in ring 3 — the other half of a hosted layout

| | |
|---|---|
| **Status** | ⬜ **Draft 2026-08-21** — the half of [security.md](../security.md) §1 gap 3 that the hosted-layout work deliberately did not do, opened the same day that work landed so the split is a decision rather than an omission. **Nothing here is built** |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | elf, kernel (the program loader), userspace (`bin/linuxd`'s policy) |
| **Milestone** | Phase 3, beside the hosted-layout row it completes — and **after** L1 has real C programs to protect, because until then it is a mechanism with no adversary |
| **Depends on** | [RFC 0033](0033-what-a-hosted-process-is.md) (what a hosted process is), [RFC 0021](0021-unpredictability.md) (the draw), [RFC 0028](0028-bhaskixboot.md) (the kernel's own slide, which is the working precedent), [RFC 0025](0025-four-level-paging-on-purpose.md) (the 47-bit half the slide lives in) |

---

## Summary

**Accept `ET_DYN` for ring 3 programs, so that a hosted process's *text* can move as its `mmap`
region already does.** The loader refuses it today, deliberately, and this RFC is the case for
reversing that refusal along with the price of doing so.

On 2026-08-21 a hosted process's `mmap` base became a per-process draw: 28 bits, page-granular,
inherited across `fork` and redrawn at `execve`. That is **half** of gap 3, and the documents say
which half:

```text
moves:          the heap, and every shared mapping
does not move:  the text, the entry point, and every gadget in them
```

The half that does not move is the half an attacker uses. A return-oriented chain is built out of
bytes in the *image*, and an image at a fixed address supplies them whatever the heap does.

## Motivation

### The problem this solves

**Randomising the heap and not the text is the configuration that looks like ASLR and is not one.**
An attacker with a memory-safety bug in a hosted C program wants a known address to jump to. The
`mmap` draw denies them a known *heap*, which frustrates a heap-spray. It does nothing to the far
commoner primitive: overwrite a return address with the address of a gadget in the program's own
text, which sits exactly where its ELF header said it would.

The software this matters for is arriving. `security.md` §1 gap 3 says it plainly: Bhaskix's own
services are Rust and largely memory-safe, and **the code coming under L1–L4 is C**. BusyBox,
`curl`, OpenSSH. The domain contains a compromise of any of them — that is the architecture's whole
claim — but *"contained"* is a weaker sentence when the contained thing is trivially exploitable,
and the difference between "an attacker needs a bug" and "an attacker needs a bug and an information
leak" is the difference this RFC buys.

### Why the refusal exists, and it is a good refusal

`elf/src/lib.rs` states it exactly:

> Ring 3 programs: static executables only. Refusing `ET_DYN` is what keeps relocation processing out
> of the *program* loader entirely.

That is not timidity. Relocation processing is a **write-back pass over an image, driven by a table
inside that image**, and the image is untrusted input. The crate that parses ELF carries
`#![forbid(unsafe_code)]` and `unsafe_budget = 0`; the loader that would apply the relocations lives
in the kernel. Reversing the refusal moves attacker-influenced arithmetic into ring 0.

**So this RFC is not "the refusal was wrong". It is "the refusal has a price, the price is now
visible, and here is what it would cost to stop paying it."**

### What happens if we do nothing

L1 lands, BusyBox runs, and every hosted program has its text at a constant address on every boot of
every machine. The heap draw stays in the release notes as "address-space layout randomisation"
without the qualifier, or the qualifier stays and a reader has to decide how much it takes back.

## Design

### The mechanism already exists, twice

This is the argument that makes the RFC worth writing at all: **Bhaskix already relocates an
`ET_DYN` image, on every boot, and has since RFC 0028.** The kernel is one. `bhaskixboot` draws a
slide, `elf::for_each_relative_relocation` walks the image's `RELA` table, and every entry must be
`R_X86_64_RELATIVE` or the whole image is refused. The kernel confirms the slide it was given.

So the parts are:

| Part | State |
|---|---|
| Parsing `ET_DYN` | **Exists**, gated to the kernel half by `AddressHalf` |
| Walking `RELA`, refusing anything but `R_X86_64_RELATIVE` | **Exists**, `for_each_relative_relocation` |
| Drawing a slide | **Exists**, `bhaskix-rand`, and `bin/linuxd` already draws for `mmap` |
| Applying relocations into a *not yet running* address space | **Exists in the loader**, for the kernel; not for a user image |
| Deciding a user image's base | **Does not exist.** Nothing in ring 3 chooses where a program loads |

### The change, in the order it would be built

1. **`AddressHalf::User` accepts `TYPE_DYN`.** One arm of one `match`, and the smallest part.
2. **`elf::load_into` takes a slide** and adds each segment's virtual address to it, then walks the
   relocations and applies them into the frames it just filled — *through the direct map, before the
   mapping is made executable*, which is the same discipline the loader already follows so that
   user-executable memory is never simultaneously user-writable.
3. **Somebody chooses the slide.** See the unresolved questions: this is the decision, not the code.
4. **The fuzz obligation is discharged first** — see below, because it is not a formality here.

### Where the slide comes from, and why it is the hard part

Every address a hosted process sees is `bin/linuxd`'s policy: the `mmap` base is drawn there, and
RFC 0031's frame says compatibility policy belongs above the kernel, never inside it. But **loading
is the kernel's**: `elf::load_into` is called from `kernel/src/lib.rs`, and nothing in ring 3 has
ever chosen where a program's text goes.

Three shapes, argued in *Alternatives*: the kernel draws; the adapter passes a slide to `START`; or
the adapter loads the image itself through the supervisor interface it already holds. The last is
the most faithful to the architecture and the most work, and it is the one this RFC leans toward
without deciding.

### What stays refused

- **Anything but `R_X86_64_RELATIVE`.** A full dynamic linker is a different project, and RFC 0031
  is explicit that a Linux dynamic loader belongs in the adapter's world rather than in Bhaskix's.
  A static-PIE binary needs only `RELATIVE`, which is why this is tractable at all.
- **A dynamic *interpreter*.** `PT_INTERP` stays refused; L2 is where that conversation happens.
- **Bhaskix's own programs, by default.** Their fixed per-program bases are a deliberate decision
  from 2026-08-13 — eight programs at one address made a debugger useless, because a fault `rip`
  meant eight different instructions — and two boot gates assert those addresses. **A slid native
  program would undo a debuggability decision to buy hardening for code that is already Rust.** If
  it is ever wanted it is a separate switch with its own argument.

## Alternatives considered

| Alternative | Why rejected | Would reconsider if |
|---|---|---|
| **Do nothing; ship the heap draw and say so** | It is the honest status quo and it is what stands today. Rejected only as a *destination*: the qualifier gets harder to write once BusyBox is running and somebody asks what "ASLR" meant | L1 arrives and measurement shows text-gadget attacks are not the primitive that matters — which would be a surprising result and should be shown, not assumed |
| **The kernel draws the slide itself** | Smallest change, and it puts a policy decision — *how much entropy a hosted program gets* — inside the nucleus, where RFC 0031 says compatibility policy must not live. It also gives native programs a slide by default, undoing the 2026-08-13 decision as a side effect | The measurement in question 2 shows a ring 3 round trip per `execve` is too expensive, and the number is written down first |
| **The adapter passes a slide to `START`** | Keeps the draw in ring 3 and the loading in ring 0, which is a clean seam — but it adds a Linux-shaped argument to a *native* method, which is exactly what RFC 0032's ratchet drove out of the nucleus | It turns out the adapter cannot load an image itself without a new kernel mechanism — in which case this is the cheaper of two evils and the argument should be made explicitly |
| **The adapter loads the image itself**, through `COPY_OUT`/`MAP_AT`/`PROTECT_AT` | The most faithful: the kernel gains nothing, the adapter already holds every method needed, and `execve` becomes a ring 3 operation end to end. The cost is real — an image copied through the supervisor interface a page at a time, and the ELF parse moving into a program that currently has none | Nothing. This is the leaning, and the work is to price it |
| **Full dynamic linking** (`PT_INTERP`, `ld.so`, PLT/GOT) | An entirely different scale, belongs to L2, and RFC 0031 puts it in the adapter's world. Static-PIE needs none of it | L2 starts, at which point this RFC is a prerequisite rather than a competitor |
| **Slide native Bhaskix programs too** | Undoes a deliberate debuggability decision, breaks two boot gates that assert literal entry addresses, and buys hardening for Rust code that is already the least likely place to need it | A native program is ever exposed to hostile input in a way its Rust does not already contain — and the case would be made about *that program* |

## Impact on existing design documents

- **[security.md](../security.md) §1 gap 3** — the row says "the hosted half done, the image half
  needs its own RFC". This is that RFC; the row would point at it.
- **[architecture.md](../architecture.md) §7** — the portability boundary discussion is untouched,
  but the loader's contract changes and §7's neighbours describe it.
- **[RFC 0033](0033-what-a-hosted-process-is.md)** — `execve` is where a slide is drawn, so its step
  5 gains a sentence. If the adapter takes over loading, RFC 0033's "what a hosted process is" grows
  a paragraph about who builds its image.
- **`elf/Cargo.toml`** — the crate's `unsafe_budget = 0` and `#![forbid(unsafe_code)]` must survive
  this change. If they cannot, that is a finding worth more than the feature.

## Security implications

Reference [security.md](../security.md) §1.

**This RFC's whole purpose is T1 and T11 hardening** — making a memory-safety bug in a hosted C
program expensive to exploit rather than reliable. It is not a mitigation for a bug; it is a tax on
using one.

**And it moves attacker-influenced arithmetic into the kernel, which is T9.** A relocation table is
data inside an untrusted file that tells the loader *where to write*. Every entry is an offset the
loader adds a slide to and stores through. The existing walk refuses non-`RELATIVE` entries and
bounds the table against the file and its segments — but it has only ever been driven by **one
image, built by this project's own toolchain, on the boot path.**

**The measured state of that code, from the reachability audit of 2026-08-21, is the sharpest thing
this RFC has to say.** `fuzz/fuzz_targets/elf_parse.rs` has five probe points. Four reach. The fifth
— *"a relative relocation was applied"* — **was never reached in a campaign from an empty corpus.**
The walk returns `Ok` with nothing to do; no relocation has ever actually been applied under a
fuzzer.

So the fuzz obligation here is not a formality to satisfy at merge time. **It is a prerequisite, and
it is bigger than adding a target**: it means constructing images whose `RELA` tables are valid
enough to be walked and hostile in their contents, which is the same seeding problem
`fuzz_targets/fs_image.rs` and the package targets solved on 2026-08-21 by building the structure
inside the target. The technique exists now. It should be applied here **before** step 1, not after
step 4.

## Performance implications

| What | Claim to test |
|---|---|
| `execve` cost | A relocation pass is a linear walk of a table plus a store per entry. For a static-PIE BusyBox that is thousands of entries, not millions — but it is per `exec`, and `exec` is on the shell's hot path |
| Loading through the supervisor interface (if the adapter loads) | A page at a time through `COPY_OUT` against a direct `copy_nonoverlapping` in the kernel. **This is the number that decides the alternative**, and it should be measured on a real image before the shape is chosen |
| The draw | One `RDRAND` per `execve`, which the `mmap` base already pays |

## Testing plan

**Host.** The slide arithmetic — segment addresses, the relocation offsets, and the refusal of
anything outside the image — is pure and belongs in `elf`'s own tests, which is where the existing
walk is tested. A slid image's entry point must equal its unslid entry plus the slide, and every
segment must land inside the space it was mapped into.

**Fuzz, and first.** `elf_parse` gains a seeded arm that builds an `ET_DYN` image with a real `RELA`
table and lets the fuzzer mutate inside it — offsets, addends, tags, table sizes — with the fifth
probe point (*a relocation applied*) reached and kept reached. **The target should be measured
before and after, as the three seeded targets were on 2026-08-21**, because "we added a target" is
not the same claim as "the code is reached".

**QEMU.** A hosted program loads at a different address on two boots, and runs. Negative-armed by
fixing the slide to zero and asserting the address stops moving — the same shape as the hosted-layout
gate, which accepts a no-entropy machine and refuses silence.

**Real hardware.** Nothing specific, and that is worth stating: this is arithmetic and page tables,
not a device.

## What step 2 measured

Printed on every boot that runs a hosted `execve`, and gated so it cannot quietly stop being taken.
Five samples, medians:

| | cycles |
|---|---|
| A supervised copy of **96 bytes** (one `COPY_OUT` round trip) | ~158,000 |
| A supervised copy of **1,024 bytes** | ~1,165,000 |
| The kernel moving the same **1,024 bytes** through the direct map | ~112 |

So the crossing costs on the order of **10⁴× the copy it performs**, and the marginal cost is around
**1,100 cycles per byte** against roughly a tenth of a cycle per byte for `copy_nonoverlapping`. A
one-megabyte image at that rate is over a billion cycles.

**The obvious explanation was tested and is wrong.** `copy_out_through` stages bytes into the scratch
area **one volatile write at a time**, which looked like the whole story. Replacing that loop with a
single bulk copy and re-measuring changed nothing: 96 bytes went ~158,000 → ~164,000 and 1,024 went
~1,165,000 → ~1,005,000, both inside the spread of the samples. **The cost is on the kernel side of
`COPY_OUT`, not in how the adapter feeds it.**

**Which is why this measurement does not decide question 1, and saying so is the honest outcome.**
A per-byte cost of a thousand cycles inside a supervised copy is not a property anybody designed on
purpose, and a design chosen against an unexplained number inherits the misunderstanding. Two things
must happen before question 1 is answered:

1. **Understand the per-byte term.** `copy_across` copies in bulk once it has a frame, so ~1,100
   cycles per byte has no obvious source in the code. `shared::drain_into` re-walks its object from
   the beginning on every call — documented, and named for its sink rather than for consumption —
   which is the first place to look.
2. **Repeat it somewhere that is not TCG.** Every figure above is emulated, and this project has
   never booted on physical hardware (M1-17). The telemetry plane's own numbers carry the same
   caveat and say so.

**What the measurement does establish**: the interface is not *near* free, so the "adapter loads the
image" design cannot be adopted on the assumption that it is cheap — which is exactly the assumption
step 2 existed to test.

## Unresolved questions

1. **Who chooses the slide?** The three shapes are in *Alternatives*. The leaning is the adapter,
   loading through the supervisor interface it already holds — but it is the largest of the three
   and the decision should follow the measurement in *Performance*, not precede it.
2. ~~**What does loading through the supervisor interface cost?**~~ **Measured 2026-08-21 —
   ~10⁴× the copy itself, ~1,100 cycles per byte — and the number raised a new question instead of
   settling one.** Why the per-byte term is that large is not understood; the staging loop was
   ruled out by experiment. Question 1 waits on that, not on more measuring.
3. **How many bits?** The `mmap` base takes 28, matching Linux. A text slide has less room — the
   image must stay inside the user half and clear of the fixed addresses the adapter maps for
   `execve` and `fork` — and the number should be stated rather than inherited.
4. **Does `/proc/self/maps` change?** It reports regions from the process record today. A slid image
   means the text's line moves, which is correct — but the `Region` list is what `write_maps` walks,
   and a slid image's segments must be in it.
5. **Does anything native ever want this?** Refused by default above. The question is left open
   because "never" is a longer commitment than the evidence supports.

## Implementation plan

Not a schedule, and **the first step is not the feature**.

1. ~~**Seed `elf_parse` for relocations**, and measure the fifth probe point reached.~~ **Done
   2026-08-21, the day this RFC was drafted.** Three arms, the builder hoisted into
   `elf::test_support` rather than rewritten, and the probe measured reached — *never* before,
   reached in 2,499,337 runs after, both from an empty corpus. 24,472,731 executions clean. `elf`
   keeps `forbid(unsafe_code)` and a zero budget. **The prerequisite is discharged; the rest of
   this plan is not started.**
2. ~~Measure what loading an image through `COPY_OUT`/`MAP_AT` costs against the kernel's direct
   copy.~~ **Done 2026-08-21 — and it does not answer question 1, which is itself the finding.**
   See §"What step 2 measured" below.
3. Host tests for the slide arithmetic in `elf`, with the crate's `forbid(unsafe_code)` and zero
   budget intact.
4. `AddressHalf::User` accepts `TYPE_DYN`; the loader takes and applies a slide.
5. Whoever question 1 named draws it; a hosted program loads slid, and a boot gate asserts the
   address moves between boots, negative-armed by pinning the slide to zero.
6. `security.md` §1 gap 3's row closes, and says which parts move.
