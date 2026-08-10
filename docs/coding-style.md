# Bhaskix — Coding Style and Engineering Rules

*Status: adopted for Phase 1. Read this before your first pull request.*

The purpose of this document is to make code review about *design* rather than about formatting,
naming, and remembering the rules. Everything mechanical here is enforced by CI so that no human has
to be the linter.

---

## 1. Language and toolchain

- **Rust**, `#![no_std]`, edition 2024. Pinned in `rust-toolchain.toml` — do not override locally.
- Target `x86_64-unknown-none` (soft-float, no red zone, kernel code model).
- **Stable Rust wherever possible.** Every nightly feature must be listed in
  `docs/nightly-features.md` with (a) why it is needed, (b) what we would do without it, and (c) what
  we are tracking for its stabilisation. An undocumented nightly feature is a build failure.
- **Assembly only where Rust cannot go:** the boot entry, context switch, interrupt stubs, and a
  handful of instruction wrappers. If you are writing assembly for performance, bring a benchmark.
- Dependencies: **minimal, vendored, and hash-pinned.** Every new dependency requires justification in
  the PR description. A kernel's dependency graph is its supply-chain attack surface
  ([security.md](security.md) §1).

---

## 2. Formatting and lints

```
cargo fmt --check          # rustfmt defaults, 100-column max
cargo clippy -- -D warnings
```

Both are CI gates. There is no style debate: rustfmt's output is correct by definition.

Crate-root attributes, required:

```rust
#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
```

Crates that must contain no `unsafe` at all — `sched`, `fs`, `net`, and all service logic — add:

```rust
#![forbid(unsafe_code)]
```

---

## 3. `unsafe`

The most important section in this document.

**Every `unsafe` block carries a `// SAFETY:` comment.** Not the function — the block. The comment
states the invariants that make the operation sound and why they hold at this call site.

```rust
// SAFETY: `frame` came from Pmm::alloc, which returns frames that are
// exclusively owned by the caller and mapped in the HHDM. The write stays
// within PAGE_SIZE bytes of the frame base, and no other reference to this
// frame exists (refcount == 1, asserted above).
unsafe { core::ptr::write_bytes(hhdm_ptr, 0, PAGE_SIZE) }
```

Rejected in review:

- `// SAFETY: this is fine`
- `// SAFETY: see above`
- A comment that restates the code (`// SAFETY: writes zeroes to the frame`)

**Test code is excluded** from both the budget and the `// SAFETY:`
requirement. The budget tracks the auditable surface of the kernel *as
deployed*, and test code does not ship — counting it would distort the number
the budget exists to produce. The checker blanks `#[cfg(test)]` modules before
counting.

**`unsafe` is confined by crate.** It is permitted in `arch`, `mm`, the allocator internals, and each
driver's `hal` submodule. It is forbidden everywhere else, at the crate root, by the compiler.

**Every crate has an `unsafe` budget** declared in `Cargo.toml`:

```toml
[package.metadata.bhaskix]
unsafe_budget = 120     # lines of code inside unsafe blocks
```

CI counts and fails if exceeded. Raising the budget requires the PR description to explain why the
new `unsafe` could not be avoided. The point is not to make `unsafe` impossible — a kernel needs it —
but to make its growth **visible**, because the failure mode is gradual and invisible.

**Prefer a safe abstraction over a repeated `unsafe` block.** One reviewed, tested `Mmio<T>` is worth
more than fifty individually-correct volatile writes.

---

## 4. Error handling

- **`Result` everywhere.** No sentinel values, no out-parameters, no negative error codes.
- **`unwrap()` and `expect()` are denied** by lint outside `#[cfg(test)]` and one-time init paths
  where failure genuinely means the machine cannot boot. In those paths, use `expect()` with a
  message that tells the operator what is wrong, not what the assertion was.
- **`panic!` in the nucleus is a denial of service.** Treat every panic as a bug of the same
  severity as the one that would have caused it.
- One error enum per crate, convertible upward:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MmError {
    OutOfMemory { requested: usize, zone: ZoneId },
    NotMapped(VirtAddr),
    AlreadyMapped(VirtAddr),
    Misaligned { addr: VirtAddr, required: usize },
    /* ... */
}
```

Errors carry the context needed to debug them. `OutOfMemory` alone tells you nothing at 3 a.m.

- **Fallible allocation.** In nucleus paths, use `try_new` / `try_reserve` forms. A kernel that
  aborts on allocation failure has an OOM policy of "die", which is not an enterprise OS.

---

## 5. Naming

| Kind | Convention | Example |
|---|---|---|
| Crates, modules, files | `snake_case` | `mm`, `page_table.rs` |
| Types, traits, enum variants | `UpperCamelCase` | `AddressSpace`, `SchedPolicy` |
| Functions, variables | `snake_case` | `alloc_frames`, `hhdm_base` |
| Constants, statics | `SCREAMING_SNAKE_CASE` | `PAGE_SIZE`, `MAX_ORDER` |
| Assembly symbols | `bhaskix_` prefix | `bhaskix_context_switch` |
| Type aliases for units | Distinct newtypes, never `u64` | `PhysAddr`, `VirtAddr`, `DevAddr`, `Pfn` |

The last row is a rule, not a preference. `PhysAddr`, `VirtAddr`, and `DevAddr` are all 64-bit
integers and confusing them is a class of bug that costs days. Make the compiler do the checking.

Use the domain's real vocabulary. A page table entry is a `PageTableEntry`, not a `Pte64Struct`.
Avoid Hungarian notation, avoid abbreviations that are not universal in the field (`pfn`, `tlb`,
`mmio` are fine; `addrsp` is not).

---

## 6. Documentation

- **Every public item has a doc comment.** `#![deny(missing_docs)]` enforces it.
- Module-level docs (`//!`) explain *why the module exists and how it fits*, not what its functions
  are named.
- Document **invariants and panics**, not mechanics:

```rust
/// Maps `pages` frames at `va` with `prot`.
///
/// # Invariants
/// - `va` must be page-aligned and within this address space's user range.
/// - The range must not overlap an existing region; check with [`Self::find_free`].
///
/// # Errors
/// Returns [`MmError::AlreadyMapped`] if any page in the range is present.
///
/// # Safety-relevant
/// `prot` cannot express W+X; see `docs/memory.md` §3.
```

- **Design docs precede implementation.** A substantial subsystem gets an RFC in `docs/rfc/` before
  the PR. Code that arrives without a design discussion will be asked to have one first — this is
  the discipline the project was founded on.
- Comments explain **why**. The code already says what. A comment that will be wrong after the next
  refactor is worse than no comment.

---

## 7. Concurrency rules

Restated from [architecture.md](architecture.md) §6 because they are style rules too.

- **Declare lock ranks.** Every lock has a static rank, passed to `SpinLock::new` so that a lock
  cannot be added without declaring where it sits. The rank list lives in `kernel/src/sync.rs`.
  A blocking acquisition of a lock ranked at or inside one already held is **reported and counted**;
  the boot test requires the count to be zero.
- **`try_lock` is exempt from ranking**, and this is load-bearing rather than convenient. A deadlock
  is a cycle in which every edge is a blocking wait, so a non-blocking acquisition can never be one.
  It matters because interrupt handlers acquire locks at points the hardware chooses: a timer can
  land while any lock is held, so every lock taken in interrupt context is out of rank with respect
  to *something*. Acquire from interrupt context with `try_lock`, or not at all.
- **`try_lock` is *not* exempt from holding, and the two were confused for a milestone.** Taking no
  rank and holding no lock are different claims; only the first is true of `try_lock`. `preempt`
  refuses to deschedule a lock holder — a preempted holder can only release by running again — and
  it asked the *ranked* set, so a `try_lock` holder looked like a thread holding nothing. `exit`
  reaches two functions that `try_lock` every runqueue with interrupts enabled, so a tick in that
  scan could carry the exiting thread away still holding a **remote** runqueue. A `try_lock` holder
  now counts towards `sync::holds_unranked` and cannot be preempted, while still taking no position
  in the order.
  > **This closes an unsoundness; it did not fix the bring-up stall.** The stall was the reason to
  > look, and the guard was expected to end it. It did not: 3 boots in 500 stalled with it in place
  > against 4 in 500 without, which is the same rate. Kept because descheduling a lock holder is
  > wrong whether or not it is *this* bug, and recorded here so the next reader does not assume the
  > rule was verified by the stall going away. It was not.

> **Deviation, M4-08.** This rule previously said debug builds *panic* on an out-of-rank
> acquisition. The implementation reports and continues, for the reason `lockdep` does: the report
> is the entire value, and halting on the first one discards the coverage of the rest of the boot.
> A rank violation is a latent risk rather than present corruption — panicking trades a possible
> future deadlock for a certain immediate one. The guarantee is unchanged, because the boot test
> fails on a non-zero count; only the failure mode is more informative. Reverting to a panic is a
> one-line change if the original rule is preferred.
- **Never sleep in interrupt context.** Enforced by the `SleepGuard` marker type.
- **Prefer, in order:** per-CPU data → read-mostly (RCU-style) → lock. Reach for a lock last.
- **Hold locks for the shortest possible span.** Never `await` while holding a spinlock — the type
  system prevents it; do not work around it.
- **Name what a lock protects, in the type.** `SpinLock<FreeLists>` is better than a `SpinLock<()>`
  next to the data it notionally guards.

---

## 8. Testing

Restated per-subsystem in each design doc. The rules:

- **Anything that can be tested on the host, is.** Allocators, page-table logic, schedulers, parsers,
  and driver state machines are all pure logic and need no hardware. A subsystem designed so that it
  can only be tested in QEMU is a design smell.
- **Every parser that touches untrusted input gets a fuzz target before merge.** Untrusted input
  includes: ELF files, filesystem metadata, network packets, IPC messages, and *device DMA
  responses*.

> **Deviation, M6-01.** Coverage-guided fuzzing (`cargo-fuzz`, libFuzzer) needs a nightly toolchain
> for sanitizer support, and [nightly-features.md](nightly-features.md) is empty and worth keeping
> that way. What runs instead is a **seeded mutation harness** in the parser's own test module: a
> deterministic generator produces malformed inputs and requires the parser to terminate without
> panicking, on stable, in CI, on every build. `BHASKIX_FUZZ_ITERATIONS` raises the count for a
> soak.
>
> It is weaker, and the weakness is specific: it explores blindly and will not find a path that
> needs several particular bytes to line up, which is exactly what coverage guidance is for. The
> `ustar` reader has been through a million mutated archives on that harness; that is a real number
> and it is not the same assurance as a fuzzer. When the project accepts a nightly toolchain, or an
> external fuzzing harness, this becomes the second line of defence rather than the only one.
>
> **Measured at M6-03, and worse than expected.** A wrapping bounds check was reintroduced in the
> ELF parser on purpose and survived *half a million* uniform mutations. For that check to wrap, an
> offset must land within sixteen of `u64::MAX` — about one draw in 2^60, so the harness was never
> going to find it, at any iteration count. The fix is to stop sampling uniformly: half of the
> 64-bit field mutations now come from a fixed list of values that break arithmetic (`u64::MAX` and
> its neighbours, the sign bit, the kernel-half boundary and its neighbour, zero). The same bug is
> then caught at seed 424, in under a second.
>
> The general rule this buys: **a mutation harness tests the middle of the input space unless it is
> told where the edges are.** Any new harness in this project seeds the edges explicitly, and a
> harness is not considered working until a deliberately reintroduced bug of the kind it is meant to
> catch actually fails it.
>
> **Closed 2026-08-10.** All three parsers this deviation was written about — `elf::parse`, the
> `ustar` reader, and `DMAR` — now have libFuzzer targets in [`fuzz/`](../fuzz), so the seeded
> harness is the second line of defence the paragraph above anticipated rather than the only one. It
> stays, and not out of sentiment: it runs on stable, in CI, on every build, in twenty milliseconds,
> and a libFuzzer campaign does none of those things.
>
> The nightly toolchain that made this possible is a *toolchain*, not a language feature.
> [nightly-features.md](nightly-features.md) is still empty and still correct: there is no
> `#![feature(...)]` anywhere in the tree, `fuzz/` is its own workspace, host-only, and nothing that
> boots is linked against it. Anyone can still build Bhaskix with the stable toolchain their
> distribution ships; they cannot fuzz it.
>
> **What guidance was worth, measured.** Over `elf::parse`, coverage guidance found 2,054 inputs
> reaching code earlier inputs had not, while twelve billion blind mutations found nothing the
> harness had not already seen. Over `DMAR` it was worth more than that, and for a reason worth
> keeping: an ACPI table carries a checksum over every one of its bytes, so every mutation of a
> valid table lands an invalid one and the fuzzer never gets past the header. The target repairs the
> checksum before the second of its two parses. **A parser guarded by a whole-input checksum is
> unreachable to a fuzzer that does not repair it**, and a target that does not say so reports a
> clean campaign over the doorway.
- **Every bug fix adds a regression test.** No exceptions. If the bug was not testable, say what you
  changed to make it testable.
- QEMU integration tests run on every PR. The frame-leak test
  ([memory.md](memory.md) §7) and the RT-latency test ([scheduler.md](scheduler.md) §10) are gates.

---

## 9. Commits and pull requests

```
mm: fix buddy coalescing across zone boundary

Frames at the top of the DMA32 zone were coalescing with frames at the
bottom of Normal, producing blocks that spanned zones. Allocation from
DMA32 could then return memory above 4 GiB.

Add a zone-boundary check in buddy_of(). Adds a regression test that
allocates the boundary frame and asserts the returned PA is < 4 GiB.

Fixes: #142
Signed-off-by: Name <email>
```

- **Subject:** `subsystem: imperative summary`, ≤ 72 characters, no trailing period.
  Subsystems: `boot`, `arch`, `kernel`, `mm`, `sched`, `fs`, `net`, `drivers`, `libc`, `userspace`,
  `tools`, `tests`, `docs`, `ci`.
- **Body:** what was wrong, why this fixes it, what the trade-off was. Not what the diff shows.
- **DCO sign-off required** (`git commit -s`). See [../CONTRIBUTING.md](../CONTRIBUTING.md).
- **One logical change per commit.** Rebase, do not merge, before submitting.
- **PRs describe the design decision**, and where an alternative was rejected, say why. A rejected
  alternative recorded is worth more than the chosen one explained.

---

## 10. Review standards

A reviewer is expected to check, in this order:

1. **Is the design right?** Formatting and naming are CI's job. Spend review budget on design.
2. **Is every `unsafe` block's `// SAFETY:` comment actually true?** This is the highest-value thing
   a reviewer does in this project.
3. **What happens when this fails?** Out of memory, hostile input, concurrent access, hardware absent.
4. **Is it tested at the lowest layer it could be?** A QEMU test where a host unit test would do is
   a missed opportunity.
5. **Does it hold the invariants in the design docs?** If it does not, either the code is wrong or
   the doc is out of date — and fixing the doc is part of the PR.

Reviews are on the code, never on the author. Disagreements escalate to the design document: if two
reasonable people disagree, the doc was ambiguous, and the outcome of the argument belongs in it.
