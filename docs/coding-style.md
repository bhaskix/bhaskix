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

- **Declare lock ranks.** Every lock has a static rank; debug builds panic on out-of-rank
  acquisition. Add your lock to the rank list in the same PR that adds the lock.
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
