# Nightly Features In Use

*Policy: [coding-style.md](coding-style.md) §1.*

Bhaskix builds on **stable Rust**. The toolchain is pinned in
[`rust-toolchain.toml`](../rust-toolchain.toml).

Every nightly feature the project adopts must be listed here with:

1. **why** it is needed,
2. **what we would do without it**, and
3. **what we are tracking** for its stabilisation.

An undocumented nightly feature is a build failure. This is not
bureaucracy — a kernel pinned to nightly for a feature nobody can justify is a
kernel that cannot be built five years from now, and that is a real way for a
systems project to die.

---

## Currently in use

**None.**

As of M1, Bhaskix compiles on stable Rust 1.98.0 with no `#![feature(...)]`
attributes anywhere in the tree. Everything the kernel needs is stable:

| Capability | How, on stable |
|---|---|
| Freestanding build | The `x86_64-unknown-none` target is tier 2 and ships precompiled `core` and `alloc` |
| Inline assembly | `core::arch::asm!` — stable since 1.59 |
| Naked functions | Not needed yet. When M4 needs them for the context switch, `#[unsafe(naked)]` is stable since 1.88 |
| No red zone, soft float | Set by the target spec, not by a feature flag |
| Panic on abort | `panic = "abort"` in the workspace profiles |
| Custom link script | `cargo:rustc-link-arg-bins` from `boot/shim/build.rs` |

This is worth stating plainly because it is not the historical norm. Rust
kernel development required nightly for years, and much of the reference
material still assumes it. That is no longer true, and starting on stable is a
decision worth defending: it means anyone can build Bhaskix with a toolchain
their distribution ships.

## Anticipated pressure points

Recorded in advance so that reaching for nightly is a decision rather than a
reflex. None of these is currently a blocker.

| Milestone | What might tempt us | Stable alternative |
|---|---|---|
| M3 | `allocator_api` for fallible allocation | Hand-written `try_*` methods on our own collections. More code, no toolchain risk. |
| M3 | `const` trait methods for page-table arithmetic | Plain functions and associated constants. |
| M4 | `thread_local` / per-CPU statics | Explicit per-CPU areas indexed by CPU id, which we need for SMP anyway. |
| Phase 2 | `async` in traits with full object safety | Available on stable since 1.75 for static dispatch; boxed futures where dynamic dispatch is required. |

## If you need to add one

1. Open an RFC (`docs/rfc/`) explaining the three points at the top of this
   document.
2. Add a row to *Currently in use* with the tracking issue.
3. Expect to be asked whether the stable alternative was actually tried.
