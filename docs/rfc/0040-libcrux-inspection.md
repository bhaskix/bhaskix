# RFC 0040 step 1 — the libcrux inspection

| | |
|---|---|
| **Status** | ✅ **Done 2026-08-22.** Verdict: **qualified GO — on an adapted vendored subset, and *not* on the dependency as published.** The distinction is the whole finding, and it is the same one [RFC 0038](0038-vendoring-the-xhci-definitions.md) reached about the `xhci` crate by the same method |
| **Inspected** | `cryspen/libcrux`, commit `47d5b4a6cf82122185ca18f60f880740a962b0fc`, committed 2026-08-20. Shallow clone taken 2026-08-22 |
| **Method** | Source read, plus **two builds against `x86_64-unknown-none`** — the target this project's ring-3 programs already build for. Nothing was added to the Bhaskix tree; the clone and both builds live in a scratch directory |
| **Owner** | [RFC 0040](0040-where-cryptography-comes-from.md) step 1. This document is its output: the `PROVENANCE.md`-shaped record and the go/no-go it asked for |
| **Corrections it forces** | **Three, to RFC 0040 itself**, listed in §6. Two of them make that RFC's central recommendation *weaker* than it was written, and are recorded here rather than quietly fixed |
| **What this inspection did *not* do** | ~~`libcrux-iot` was not inspected.~~ **Closed 2026-08-22 — see §5.** It is **refused on two independent grounds**, the first of which is dispositive on its own. Two line counts in §(b) remain unmeasured, and say so |

---

## Verdict

**Qualified GO — and as of 2026-08-22 the gate is run and passed. See §8.**

- ❌ **Taking libcrux as a dependency, or vendoring its crates as they are packaged, does not work.** Every primitive needed fails to link into a freestanding binary: *no global memory allocator found but one is required*.
- ✅ **Taking an adapted subset does work, and the obstacle disappears when it is taken.** The allocator requirement is an artifact of **how the crates are packaged**, not of the algorithms. The X25519 and ChaCha20-Poly1305 code itself allocates nothing.
- ⚠️ **The verification is real but is weaker than RFC 0040 claimed**, and that claim was the entire argument for preferring this option. §3 and §6 say exactly how much weaker.

The recommendation therefore stands, with its reasoning repaired rather than its conclusion reversed — but a reader who accepted RFC 0040 on the strength of the phrase *"machine-checked proof of secret independence"* should read §3 before continuing to accept it.

---

## (a) Does it compile `no_std` without a global allocator?

**No as published. Yes for the subset, on the evidence below.**

Upstream ships `no-std-build.sh`, which builds `libcrux-chacha20poly1305`, `libcrux-curve25519`, `libcrux-ed25519`, `libcrux-hkdf`, `libcrux-hmac`, `libcrux-p256`, `libcrux-poly1305`, `libcrux-sha2`, `libcrux-secrets` and `libcrux-traits` as `no_std`. **Every primitive RFC 0040 §1's table needs is on that list**, which is why this looked settled before it was tested.

**Build 1 — the false green.** `cargo build --target x86_64-unknown-none --release` over `libcrux-curve25519`, `libcrux-chacha20poly1305`, `libcrux-ed25519`, `libcrux-sha2` and `libcrux-poly1305` **succeeded**, in 19.68s, with no allocator anywhere.

That result is worthless and it is recorded because it is worthless. Library crates compile to `rlib`; **nothing links**, and *no global memory allocator found* is a **link-time** error. A `cargo build` of a library against a bare-metal target does not test the thing the criterion asks about. This is `coding-style.md` §8's rule arriving from the other direction: a test that cannot fail has not passed.

**Build 2 — the test that could fail.** A freestanding `#![no_std] #![no_main]` binary, no `#[global_allocator]`, `panic = "abort"`, calling `secret_to_public`, `ecdh`, `encrypt`, and `sha256`, built for the same target:

```
error: no global memory allocator found but one is required;
       link to std or add `#[global_allocator]` to a static item
       that implements the GlobalAlloc trait
```

Isolated one crate at a time, with a real call in each so the code is reachable:

| Crate | Freestanding link |
|---|---|
| `libcrux-curve25519` (X25519) | ❌ allocator required |
| `libcrux-chacha20poly1305` | ❌ allocator required |
| `libcrux-sha2` | ❌ allocator required |
| `libcrux-ed25519` | ❌ allocator required |
| `libcrux-poly1305` | ❌ allocator required |

**Five for five. The obstacle RFC 0040 flagged is real and it is worse than that RFC guessed** — it is not "some crates", it is all of them.

### Why — and this is the finding that changes the verdict

Every one of those crates depends on `libcrux-hacl-rs`. Its `src/lib.rs` declares, with no `cfg` guard:

```rust
pub mod bignum;        // line 9 — unconditional
```

`bignum/` is arbitrary-precision integer arithmetic — `bignum64.rs`, `bignum256.rs`, `bignum4096.rs` and friends — and those modules use `Vec` and `Box`. They exist for **RSA and P-256**. **X25519 never calls them. ChaCha20-Poly1305 never calls them.**

The algorithm modules themselves are clean. Measured, as a count of `Vec<` / `Box<` / `alloc::` references:

| Module | Allocation references |
|---|---|
| `hacl-rs/src/curve25519_51.rs` | **0** |
| `hacl-rs/src/bignum25519_51.rs` | **0** |
| `hacl-rs/src/fstar.rs`, `lowstar.rs`, `util.rs` | **0** |
| `crates/algorithms/curve25519/src/*` | **0** |
| `crates/algorithms/chacha20poly1305/src/*` | **0** |

So the allocator is dragged in by a sibling module in a shared utility crate that the needed code never touches. `bignum25519_51.rs` — despite the name — is the **field arithmetic modulo 2²⁵⁵−19** in 51-bit limbs, not the general bignum, and it allocates nothing.

**Removing that is exactly what vendoring is.** RFC 0038's `PROVENANCE.md` records the same operation on the same grounds: *"Adapted rather than copied: all five upstream dependencies were removed and their work written out."* Here the removal is one unconditional `pub mod` line and the directory behind it.

**What this does not prove.** That the adapted subset links clean has **not** been demonstrated — doing so means performing the adaptation, which is code, and this step was scoped to inspection. It is a strong inference from five measured zeroes, not a result. **It must be the first thing the taking step proves, with the same freestanding-link test, before anything else is built on it.**

---

## (b) What would be taken, and how large is it

Measured, not estimated. Where a number was not measured, it says so.

| Piece | Lines | Note |
|---|---|---|
| `hacl-rs/src/curve25519_51.rs` | 342 | The X25519 scalar multiplication |
| `hacl-rs/src/bignum25519_51.rs` | 726 | Field arithmetic mod 2²⁵⁵−19, 51-bit limbs |
| `crates/algorithms/curve25519/src/{lib,ecdh_api,impl_hacl}.rs` | 169 | The safe wrapper: 91 + 60 + 18 |
| **X25519 subtotal** | **1,237** | |
| `crates/algorithms/chacha20poly1305/src/*.rs` | 748 | `lib` 176, `impl_hacl` 154, `impl_aead_trait` 245, `xchacha20_poly1305` 173 — **the last two are probably droppable**: this design needs neither the generic AEAD trait nor XChaCha |
| `chacha20poly1305/src/hacl/` (the backend `aead_chacha20poly1305`) | **not measured** | A subdirectory; the 748 above counts `src/*.rs` only. **An open number** |
| `hacl-rs` `fstar/`, `lowstar/`, `util/` support | **not measured** | The `.rs` files at those names are 5, 2 and 2 lines — re-export shims over directories that were not counted |
| `libcrux-secrets` + `libcrux-traits` | 4,492 combined | Most of `traits` is unrelated (ML-KEM, ML-DSA, digests). The needed slice is small and was **not** isolated |

**Order of magnitude: the take is low thousands of lines, comparable to RFC 0038's 5,759.** The precise figure needs the subset actually cut, and the two unmeasured rows are named so the number is not quoted as final.

---

## (c) What the proofs cover — and what they do not

**This is the criterion that matters most, because it is the entire argument for this option, and it is where RFC 0040 overstated.**

### What is actually there

**1. HACL\* provenance — real, and inherited rather than re-proved here.** `hacl-rs/src/lib.rs` records the upstream it was generated from:

```
hacl-star commit: efbf82f29190e2aecdac8899e4f42c8cb9defc98
```

The code is *generated from* F\*-verified HACL\* sources. The verification lives upstream, in F\*, over the F\* source — not in this repository, and not over these Rust bytes.

**2. Rust-side proof artifacts exist — for other algorithms.** `proofs/` directories are present under `crates/algorithms/aes`, `kmac`, `sha3`, and under `libcrux-ml-kem` and `libcrux-ml-dsa`. **There is no `proofs/` directory under `curve25519` or `chacha20poly1305`** — the two primitives this design most needs. What exists for ChaCha is `formal_verification/hacl-star/spec-equivalence/Hacspec_chacha20.fst`, a spec-equivalence artifact, which is a different and narrower thing.

**3. Secret independence is a type discipline plus a dynamic check — not a static proof.** `libcrux-secrets`' own documentation is explicit. Secret values take distinct types (`U8` rather than `u8`); enabling the `check-secret-independence` feature makes the **Rust typechecker** reject branching on secret comparisons, indexing by secret values, and non-constant-time operations like division and modulus. Optionally, with `--cfg valgrind_ct_test`, classify/declassify operations emit Valgrind client requests so memcheck flags secret-dependent behaviour dynamically.

And the escape hatch, in upstream's own words:

> *every use of `.declassify()` is at the responsibility of the programmer and represents a potential side-channel leak*

### What that is worth, stated without inflation

It is **substantially stronger than discipline** — a typechecker is mechanical, it runs on every build, and it does not get tired. It is **substantially weaker than a proof** — it is a discipline the compiler enforces *given correct annotation*, with a human-audited escape hatch, over code whose functional verification happened upstream in another language.

**RFC 0040 §2 argued that only "machine-checked secret independence" delivers T14, and put this option above hand-writing on that basis. What is actually on offer is a checked type discipline plus an optional dynamic test.** That is still the best of the three mechanisms §2 listed, and it is not the thing that section named. §6 records the correction.

---

## (d) Does the subset need instructions that trigger `asm_budget`?

**No.** Searched across `crates/algorithms/curve25519/src`, `crates/algorithms/chacha20poly1305/src` and `hacl-rs/src/curve25519_51.rs` for `core::arch`, `asm!`, `target_feature` and `is_x86_feature_detected`: **no matches.**

The portable path is portable. `architecture.md` §7's instruction-containment gate is **not** triggered by this take, and `asm_budget = 0` holds — which confirms RFC 0040 §1's claim that the ChaCha20-Poly1305 route costs zero instruction budget.

A separate `libcrux-intrinsics` crate exists upstream and is on the `no_std` list; **it is not needed by this subset** and must not be taken. If AES-NI is ever wanted, that is the crate to inspect and it is a different decision with a different budget line.

---

## (e) Pinning a pre-release upstream

Versions at the inspected commit, all below `0.1` as RFC 0040 anticipated:

| Crate | Version |
|---|---|
| `libcrux-chacha20poly1305` | 0.0.9 |
| `libcrux-ed25519` | 0.0.9 |
| `libcrux-curve25519` | 0.0.8 |
| `libcrux-sha2` | 0.0.8 |
| `libcrux-traits` | 0.0.8 |
| `libcrux-secrets` | 0.0.6 |
| `libcrux-poly1305` | 0.0.6 |
| `libcrux-hacl-rs` | 0.0.5 |

**And the pre-release problem dissolves in the vendoring model, which is the second reason to prefer it.** A version requirement below `0.1` is a live dependency that can move under a caret nobody reviewed. Vendored source does not move: `third_party/README.md` already states the rule — *"Vendored source is frozen: reviewed once in full, at a known version, changing only when somebody changes it here."*

So "frozen at a known version" is answerable even when the version is `0.0.8`: the anchor is the **git commit**, `47d5b4a6cf82122185ca18f60f880740a962b0fc`, plus the upstream `hacl-star` commit the generated code names. Both go in `PROVENANCE.md`, exactly as RFC 0038 recorded `xhci` 0.9.2.

### Licensing

Both `LICENSE` (Apache License 2.0) and `LICENSE-MIT` (MIT, *Copyright (c) 2024 Cryspen*) are present at the repository root, while the workspace manifest declares `license = "Apache-2.0"`.

**Reported as the discrepancy it is rather than resolved into a tidier sentence.** The declared SPDX license is Apache-2.0, which is what RFC 0038's criterion needs — Bhaskix's own license, so no second license enters the tree — and on that reading the criterion **passes**. The presence of a second license file suggests a dual grant that the manifest does not state. **This must be confirmed with upstream in writing before anything is taken**, and it is cheap to do.

> **A correction to something said in conversation while this inspection was running.** On first seeing the two files this was reported as *"dual-licensed, not Apache-only"*. That was a conclusion drawn from a directory listing, before the manifest was read. What is verified is the paragraph above: two license files present, one license declared. The looser claim is corrected here because it is the kind that travels.

---

## 5. `libcrux-iot` — refused, on two independent grounds

Inspected at commit `6a728a365388e891f3548d65d692136481062d72`, committed 2026-07-14.

### Ground 1 — it is AGPL-3.0, and that is dispositive

There is **one** licence file in the repository and it is the **GNU Affero General Public License,
Version 3**. `libcrux-iot/Cargo.toml` declares it in the metadata as well:

```toml
license = "AGPL-3.0-only"
```

The three member crates inherit it through `license.workspace = true`. There is no second licence
file and no dual grant anywhere in the tree.

**This fails RFC 0038's criterion at the first hurdle**, and fails it in the strongest possible way.
That RFC took the `xhci` crate specifically because it was `MIT OR Apache-2.0` and could therefore be
taken *purely under Apache-2.0*, "so there is no license mixing anywhere in the tree and no second
license text to reconcile". AGPL-3.0 offers no such option: it is one-way compatible in the direction
this project does not want. Apache-2.0 code may be combined **into** an AGPL work; AGPL code cannot
be redistributed under Apache-2.0. Vendoring it would put the combined work under AGPL-3.0 and
contradict [RFC 0001](0001-license-apache-2.0.md), which is **accepted** and chose Apache-2.0
deliberately for "maximal enterprise and government adoption".

**And the network clause makes it worse for this use than for any other.** AGPL-3.0 §13 requires that
users who interact with a modified version *over a network* be offered its Corresponding Source. The
consumer here is a **web server**. That is precisely the interaction the clause names, so the
obligation would attach to every deployment of Pingala and to every operator who ran one — an
obligation this project has no standing to impose on its users and has never told them to expect.

> **Stated as an engineering reading, not as legal advice.** The licence identity and the manifest
> declaration are facts checked in the tree at the commit above. The compatibility conclusion is the
> standard understanding of AGPL-3.0 and Apache-2.0 and should be confirmed by someone qualified
> before it is relied on for anything other than *not* taking this dependency — which is what it is
> being relied on for here.

### Ground 2 — it does not contain any primitive this design needs

Independent of the licence, and it would be refused on this alone. The workspace has **three**
members:

```toml
members = ["ml-dsa", "ml-kem", "sha3"]
```

ML-DSA and ML-KEM are the post-quantum signature and key-encapsulation schemes; SHA-3 is what they
hash with. Searched across the whole repository for the primitives RFC 0040 §1's table asks for:

| Primitive | Paths matching |
|---|---|
| `curve25519` / `x25519` | **0** |
| `chacha` | **0** |
| `poly1305` | **0** |
| `ed25519` | **0** |
| `hkdf` / `hmac` | **0** |

It is also aimed at a different machine: the surrounding crates target Cortex-M boards
(`libcrux-nucleo-l4r5zi`, `thumbv7em-none-eabihf`), which is what "IoT friendly" means here.

### The correction this forces on §7 of this document

> **`[corrected]` 2026-08-22.** §7 item 6 speculated that `libcrux-iot` "may already be the subset
> §(a) argues for — in which case the adaptation is smaller than §(b) estimates and someone else
> maintains it". **That was wrong**, and it was a guess written from a repository name and a
> one-line description rather than from the tree. It contains none of the needed primitives and
> could not be taken if it did. The item is closed as **refused**, not as done.

**What it changes about the recommendation: nothing.** §(a)'s finding stands on its own — the
adaptation of the main repository is the route, and there is no maintained subset to inherit.

---

## 6. Corrections this inspection forces on RFC 0040

Per this project's rule, recorded where the wrong claim lives rather than deleted.

| # | RFC 0040 said | What is true |
|---|---|---|
| **1** | *"`libcrux` is **Apache-2.0**"* | The **manifest** declares Apache-2.0; a `LICENSE-MIT` file is also present and the two have not been reconciled. The criterion still passes; the statement was more confident than the evidence |
| **2** | *"its `no_std` support is documented as requiring a global allocator"* — presented as a documented caveat about the library | **Measured, and it is not a caveat, it is a fact about all five needed crates**, traced to one unconditional `pub mod bignum` in a shared utility crate. RFC 0040 treated this as an open risk; it is a confirmed defect of the packaging, **and it is removable by the vendoring the RFC recommends** |
| **3** | *"a machine-checked proof of ... secret independence"*, and §2's argument that only mechanism 3 delivers **T14** | **Overstated, and it was the load-bearing sentence.** What exists is a *checked type discipline* (`libcrux-secrets` + `check-secret-independence`) with a programmer-responsible `declassify()` escape hatch, optionally cross-checked at runtime under Valgrind, over code generated from F\*-verified HACL\* sources. There are **no Rust-side proof artifacts for curve25519 or chacha20poly1305** in this repository, though there are for `aes`, `kmac`, `sha3`, ML-KEM and ML-DSA |

**Correction 3 does not reverse the recommendation, and it does narrow it.** The honest form of RFC 0040 §2's argument is now:

> A compiler-enforced secret-independence discipline, applied by people who work on this full time and cross-checkable under Valgrind, is better evidence for **T14** than the care of a volunteer project with no side-channel expertise claimed anywhere in its documents. It is not a proof, and **T14's status must not be written as though it were.**

That is a weaker sentence than the one in RFC 0040, and it still argues for the same option.

---

## 7. What must be answered before anything is taken

1. **Prove the subset links.** Cut it, then run the same freestanding-link test from §(a). **This is the gate; everything else waits behind it.** A finding of "still requires an allocator" returns the whole decision to option A.
2. **Confirm the license grant with upstream, in writing.** §(e).
3. **Measure the two unmeasured rows** in §(b) — the ChaCha backend directory and the needed slice of `secrets`/`traits` — so the take has a real line count before review, not after.
4. **Decide whether `check-secret-independence` is on in the shipped build.** Upstream says the type swap has no performance impact and the *feature* is the checker. Bhaskix should build with it enabled in CI at minimum, and this needs a decision recorded, not assumed.
5. **Decide what happens to `declassify()`.** Every call site is an unproven human assertion. The vendoring rule — *reviewed as our own* — means each one is read and justified like an `unsafe` block, and `coding-style.md` §3's model applies almost unchanged. **A `declassify_budget`, counted per crate the way `unsafe` already is, is the obvious mechanism and is proposed here for the taking step.**
6. ~~**Inspect `libcrux-iot`.**~~ ✅ **Done 2026-08-22 — §5. Refused**, on two independent grounds:
   it is **AGPL-3.0-only**, which cannot enter an Apache-2.0 tree and whose §13 network clause would
   attach to every deployment of a *web server* specifically; and it contains **none** of the needed
   primitives, being ML-KEM / ML-DSA / SHA-3 for Cortex-M. The speculation that it might already be
   the needed subset was wrong and is corrected in §5.
7. **RFC 0040's questions 2 and 4 are unaffected** and stay open: whether ring 3 gains an allocator (this inspection argues it need not, which is the useful answer), and Ed25519 versus ECDSA P-256 — noting that **P-256 is exactly the algorithm that needs `bignum/`**, so choosing it re-imports the allocator problem this inspection just removed. That is a new and material input to question 4.

---

## 8. The cut, and the gate — done 2026-08-22

§(a) inferred that the subset would link once `bignum` was removed, and said in terms that this was
"a strong inference from five measured zeroes, not a result", and that proving it was **the taking
step's gate**. **The cut has now been performed and the gate run. It passes.**

The work was done in a scratch directory. **Nothing has been added to this tree**, because the
licence confirmation (§7 item 2) is still outstanding and that is a precondition, not a formality.

### What the cut removed

| Removed | Why it could go | Size |
|---|---|---|
| `hacl-rs/src/bignum/` and `bignum.rs` | Arbitrary-precision integers for **RSA and P-256**. Neither is taken; X25519 and ChaCha20-Poly1305 never call them. **This is the allocator** | **9,144 lines** |
| The `alloc` re-exports in `hacl-rs`'s `prelude` | `Box`, `Vec`, `vec!` — glob-imported by the ChaCha backend and **never used by it**, measured | 4 lines, and the `extern crate alloc` behind them |
| `libcrux-macros`' `ml_dsa_parameter_sets` and `trace_span` | The subset uses **exactly one** macro, `unroll_for!`, at 13 call sites, and it uses only the built-in `proc_macro`. The two removed macros are what pulled **`syn` and `quote`** | 141 → 52 lines, **2 external build dependencies → 0** |
| Poly1305's streaming API — `state_t`, `malloc`, `reset`, `update`, `digest` | The only allocating code in `mac_poly1305.rs`. The AEAD calls the one-shot `mac`, never the stream | 617 → 430 lines |
| `libcrux-traits`' `digest` and `kem` modules | Unused, and `kem` pulls **`rand`** | 2 modules |
| curve25519's `Kem` impl for X25519 | TLS 1.3 uses raw ECDH — `secret_to_public` and `ecdh` — not X25519-as-a-KEM | ~40 lines |
| ChaCha's XChaCha20-Poly1305, `impl_aead_trait`, and the typed owned/ref aliases | Not used by a TLS record layer; the typed API is where `Box` entered | 2 files + a block |
| `hax-lib`, and the six `#[hax_lib::exclude]` markers in `secrets` | Extraction markers for the hax tool, **no-ops at build time**. Turned into comments in place, so the information is not lost | the **last external dependency** |

**`syn` deserves its own line.** RFC 0038 refused the `xhci` crate partly because `syn` 1.0.109 is
44,682 lines. The subset reached here pulls `syn` at first, through one proc-macro crate, for **two
macros it never calls**. Removing them is a ten-line edit. Had that not been true, this take would
have inherited the exact objection RFC 0038 rejected a crate over.

### The result

| | |
|---|---|
| **Size** | **6,807 lines across 48 files**, in 7 crates |
| **External dependencies** | **Zero.** Every dependency is a path within the subset — the same position `Cargo.lock`'s 20-of-20 `bhaskix-*` already holds |
| **Instruction budget** | `asm_budget = 0` — confirmed again on the cut, no `core::arch`, no `asm!`, no `target_feature` |
| **Removed in total** | ~9,900 lines, the bulk of it `bignum` |

### The gate

A freestanding `#![no_std] #![no_main]` binary, **no `#[global_allocator]`**, `panic = "abort"`,
calling `secret_to_public`, `ecdh` and ChaCha20-Poly1305 `encrypt` so that every path is reachable,
built for `x86_64-unknown-none`:

```
    Finished `release` profile [optimized] target(s) in 1.26s
```

**73,288 bytes of ELF, and `nm` reports zero allocator symbols** — no `__rust_alloc`, no
`__rg_alloc`, no `malloc`. The same test against the unmodified upstream crates failed five for
five in §(a). **The obstacle was packaging, exactly as §(a) argued, and the adaptation removes it.**

### Correctness — because a subset that links and computes wrong is worse than one that does not link

Cutting code out of a cryptographic library is precisely the operation whose failure is silent, so
linking was not treated as success.

**A differential test against pristine upstream.** One harness, built twice — once against the cut,
once against the unmodified `libcrux` crates — computing an X25519 public key, an ECDH shared secret
in both directions, and a ChaCha20-Poly1305 encryption and round trip.

**All six values byte-identical.** The shared secrets agree in both directions and the AEAD round
trip returns the plaintext, in both builds, with the same ciphertext.

**And the harness was proven able to fail**, per `coding-style.md` §8's rule that a test that cannot
fail has not passed. One byte of the X25519 basepoint constant in the cut was changed from `9` to
`10`; the differential went red on all three X25519 values immediately. Restoring the byte returned
it to identical. The negative arm was watched failing, not assumed.

> **What this does and does not establish.** It establishes that **the cut is faithful** — the
> adaptation changed no behaviour. It does **not** establish that upstream is correct: no RFC 7748
> or RFC 8439 known-answer vectors were run here, and no Wycheproof vectors. Those remain
> [RFC 0040](0040-where-cryptography-comes-from.md)'s step 4 obligation, and they test a different
> claim than this test does.

### What §7 now looks like

Item 1 — *prove the subset links* — is **discharged**. Item 3 — *measure the unmeasured rows* — is
discharged by the 6,807-line figure. **Items 2, 4 and 5 stand**, and item 2, the licence
confirmation, is now the only thing between this and a `third_party/libcrux/` directory.

---

## Appendix — `PROVENANCE.md`, drafted for the taking step

Not placed in `third_party/` because nothing has been taken. Written now so the taking step has no discretion about what gets recorded.

```text
# Provenance

This crate is **adapted from third-party source**. It is not original work and
must not be presented as any.

| | |
|---|---|
| Upstream            | libcrux (Cryspen)
| Source              | https://github.com/cryspen/libcrux
| Commit taken        | 47d5b4a6cf82122185ca18f60f880740a962b0fc (2026-08-20)
| Crate versions      | curve25519 0.0.8, chacha20poly1305 0.0.9, hacl-rs 0.0.5,
|                     | secrets 0.0.6, traits 0.0.8
| Generated from      | hacl-star efbf82f29190e2aecdac8899e4f42c8cb9defc98
| Upstream copyright  | Copyright (c) 2024 Cryspen
| Upstream license    | Apache-2.0 declared in the manifest; a LICENSE-MIT file
|                     | is also present -- see the inspection, criterion (e)
| Taken under         | Apache-2.0 (the license Bhaskix already uses)
| Decision            | RFC 0040, and its step 1 inspection

## What was taken

X25519 and ChaCha20-Poly1305: the field arithmetic, the scalar multiplication,
the AEAD, and the minimum support modules they need.

## What was changed, and why

`libcrux-hacl-rs` declares `pub mod bignum` unconditionally, and those modules
use `Vec` and `Box` for RSA and P-256 -- neither of which is taken. That one
line is why every upstream crate fails to link into a freestanding binary with
no allocator. It is removed here, with the directory behind it, which is what
makes this subset usable in ring 3 at all.

Also dropped: the generic AEAD trait impl and XChaCha20-Poly1305, neither of
which this system uses.

## What was NOT taken, deliberately

`libcrux-intrinsics` (no AES-NI path is wanted; see RFC 0040 section 1),
`bignum/` (see above), and every algorithm outside the two named.
```
