# RFC 0040: Where cryptography comes from

| | |
|---|---|
| **Status** | ⬜ **Draft 2026-08-22.** A **decision RFC**: it proposes almost no code and instead answers the question [RFC 0039](0039-pingala-a-native-web-server.md) refused to answer alone. It does **not** adopt an option — it recommends one and specifies the **inspection that decides**, which is the shape [RFC 0038](0038-vendoring-the-xhci-definitions.md) used when "vendor the crate" turned out on inspection not to be possible. **Step 1 is done, and its gate is run and passed — [the inspection](0040-libcrux-inspection.md), 2026-08-22.** The subset was cut and a freestanding binary with **no allocator** links against it, with outputs byte-identical to pristine upstream and the differential harness watched going red. The take is **6,807 lines, zero external dependencies, `asm_budget` 0**. The inspection returned a qualified GO on an adapted vendored subset and a flat NO on the crates as packaged: every needed primitive fails to link into a freestanding binary for want of an allocator, traced to one unconditional `pub mod bignum` the taken code never calls. **It also forced three corrections on this document**, two of which weaken its central argument; they are marked `[corrected]` below and enumerated in that document's §6. **`libcrux-iot` was inspected 2026-08-22 and is refused** — AGPL-3.0-only, and it holds none of the needed primitives. Two findings are independent of which option wins: §2 identifies a **hole in the threat model** that cryptography cannot be built over, and §1 finds that a TLS **server** needs roughly half the primitives a TLS *stack* does |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | A new `no_std` crate (`bhaskix-crypto`) and/or `third_party/`; `docs/security.md` §1; `tools/check-deps.py` |
| **Milestone** | Phase 2 (the decision) → Phase 3 (the code). It gates [RFC 0039](0039-pingala-a-native-web-server.md) step 5, and it is the **longest-lead item** in that RFC, which is why it is opened now rather than when step 5 arrives |
| **Depends on** | [RFC 0039](0039-pingala-a-native-web-server.md) §5 **W1** (the finding that started this), [RFC 0038](0038-vendoring-the-xhci-definitions.md) (the vendoring precedent, and the boundary this RFC must argue with), [RFC 0021](0021-unpredictability.md) (`RDRAND`, and "the caller refuses"), [RFC 0030](0030-packages.md) (which refused signatures for the reason §5 restates), [security.md](../security.md) §1 (**T9**, and the out-of-scope row §2 disputes), [coding-style.md](../coding-style.md) §3 and §8 |

---

## Summary

**There is no cryptography in this repository.** A grep for `aes`, `chacha20`, `poly1305`, `x25519`,
`ed25519`, `curve25519`, `p256`, `hmac`, `hkdf`, `sha384` and `sha512` across every `.rs` in the tree
returns **zero hits**. The only primitives are `pkg/src/sha256.rs` — a digest over public data — and
`rand/`, which is `RDRAND` and a policy.

Cryptography must therefore be *obtained*, and there are exactly three ways to obtain it: write it,
vendor it, or depend on it. **The third is refused** — it spends **P5**, the twenty-of-twenty
`bhaskix-*` lockfile, and `ring` and `aws-lc-rs` additionally carry C and assembly that this tree has
no mechanism to build. The choice is between the first two, and this RFC recommends **vendoring
formally verified source** under RFC 0038's existing pattern, with hand-written code for whatever the
inspection says cannot be taken.

**The argument for that recommendation is narrow and it is the whole RFC.** It is not that vendored
code is less work. It is that a machine-checked proof of *secret independence* is a property this
project cannot produce by discipline, in the one domain where the absence of that property is
**remote key recovery** rather than a bug.

Two findings arrive independently of the decision:

1. **§1** — a TLS **server** does not validate certificates, so no X.509 parser, no trust store, no
   revocation, and **no wall clock** are needed. That retires RFC 0039's **W3** for the server case
   and removes the largest untrusted-input parser from the design before it is written.
2. **§2** — `security.md` §1 places side channels **out of scope**, and cryptography is the one
   place that stance cannot hold. A variable-time implementation is not a microarchitectural exotic;
   it is a remote attack with a stopwatch. **The threat model needs a new in-scope row before any of
   this is written**, or the result is theatre.

## Motivation

### The problem this solves

[RFC 0039](0039-pingala-a-native-web-server.md) proposed a web server and its §5 audit found the
title's own adjectives unfunded. **W1** was the flattest of them: a production web server is TLS 1.3
or it is nothing, and this tree cannot perform a single cryptographic operation beyond hashing a
package.

That RFC deliberately did not decide this, for a reason worth repeating: the decision **collides with
P5**, which RFC 0034 calls "a supply-chain position almost nothing else in this class holds" and
which `tools/check-deps.py` enforces with an `ALLOWED_EXTERNAL` set holding exactly one name —
`libfuzzer-sys`, reached only by `fuzz/`, which is its own workspace and never ships.

### Who has this problem

The project lead, who owns architecture direction per `GOVERNANCE.md` §2. And **Phase 3's secure-boot
chain**, which needs signature verification and a key story and is `security.md` §1's top-ranked gap
— so this RFC's answer is reused there, or contradicted there. §5 says which.

### What happens if we do nothing

RFC 0039 stops at step 4. More quietly: the next person who needs a signature writes one, because
the alternative is to stop, and this document exists so that the answer is on a page rather than in
whoever's judgement arrives first.

---

## 1. What is actually needed — and the cut that halves it

**A TLS server presents a certificate. It does not validate one.**

That sentence is worth more than any implementation choice below it, because the certificate
validator is where the mass is: X.509 and DER parsing, name constraints, path building, trust
anchors, revocation, and a clock. **A server needs none of it.** It sends its certificate chain as
opaque bytes it was configured with and never parses, and it proves possession of the matching
private key by signing the handshake transcript.

Three consequences, all of them subtractions:

- **No X.509 parser.** The largest untrusted-input parser this design might have had does not exist,
  because the certificate is not untrusted input to the server — it is configuration.
- **No wall clock.** RFC 0039's **W3** said certificate validity is an interval on a calendar and
  nothing in this system can name a date. A server checks no validity interval. Combined with the
  refusal of session tickets below — whose age computation is the other thing that wants time —
  **the server needs no time-of-day source at all**, and W3 is retired for this use.
- **No trust store, no revocation, no path building**, and therefore no governance question about
  what the trust roots are.

### The primitive set, and where each one stands

| Primitive | Why a server needs it | Status here |
|---|---|---|
| SHA-256 | Handshake transcript hash; HKDF's underlying hash | ✅ **exists** — `pkg/src/sha256.rs`, written to FIPS 180-4 and asserted against the four published vectors |
| HMAC-SHA256 | HKDF's construction | ⬜ ~40 lines over the above; the easiest thing in this table |
| HKDF + HKDF-Expand-Label | The TLS 1.3 key schedule (RFC 5869, RFC 8446 §7.1) | ⬜ pure arithmetic over HMAC; host-testable against published vectors |
| X25519 | ECDHE key agreement (RFC 7748) | ⬜ **the hard one.** Field arithmetic modulo 2²⁵⁵−19, constant-time throughout, with low-order-point and non-canonical-encoding handling |
| An AEAD | Record protection | ⬜ see below — the one place where the *choice* carries a real security argument |
| One signature algorithm | `CertificateVerify` over the transcript, proving key possession | ⬜ see *Unresolved questions* 4 |
| A CSPRNG | The ephemeral key, and nonces | 🔨 `RDRAND` exists ([RFC 0021](0021-unpredictability.md)); a DRBG over it does not, and **drawing every byte straight from `RDRAND` is a design decision, not a default** |

### The AEAD choice is a security argument, not a preference

**ChaCha20-Poly1305 is constant-time by construction.** It is add–rotate–xor: no lookup tables, no
data-dependent branches, no secret-dependent memory addresses. It is constant-time on any machine,
in portable Rust, with **zero** entries in this project's `asm_budget`.

**AES is not**, in software. The fast portable implementation is table-driven, and table-driven AES
leaks the key through the cache — that is not a theoretical result, it is the oldest practical
side-channel attack on a real cipher. Doing AES safely on x86-64 means **AES-NI**, and doing GCM
safely means **PCLMULQDQ**, both of which are architecture-specific instructions and therefore land
squarely on `architecture.md` §7's instruction-containment gate, which requires a declared
`asm_budget` and a reason.

That produces a rule this RFC asks to be adopted whichever option wins:

> **Never ship a table-driven software AES fallback.** On a machine without AES-NI and PCLMULQDQ,
> the server offers ChaCha20-Poly1305 and refuses AES-GCM — a refusal reported in the boot log, in
> exactly the words RFC 0012 uses for a machine with no IOMMU and RFC 0021 uses for a machine with
> no `RDRAND`. A degraded mode that leaks the key is not a degraded mode.

**And the conformance cost of that, stated plainly.** RFC 8446 §9.1 makes `TLS_AES_128_GCM_SHA256`
**mandatory to implement** — confirmed against two independent sources — and lists
`TLS_CHACHA20_POLY1305_SHA256` as `SHOULD`. **A ChaCha-only server is therefore not RFC 8446
conformant**, even though every current mainstream client negotiates ChaCha20-Poly1305 happily. This
RFC proposes shipping the non-conformant subset first and saying so in those words, with AES-GCM
behind AES-NI as the second step rather than the first.

> **A citation this document deliberately does not make.** RFC 8446 §9.1's exact `MUST`/`SHOULD`
> split for *supported groups* (secp256r1 versus X25519) and for *signature schemes* was **not
> verified to the letter** while drafting — one source paraphrased it rather than quoting it, and
> this project does not assert a specification from recall. The mandatory cipher suite above is
> confirmed; the group and signature requirements must be **read from RFC 8446 §9.1 directly**
> before the implementation commits to a set. It is called out here rather than smoothed over
> because *Unresolved questions* 4 turns on it.

---

## 2. The threat-model hole, which must be closed first

`security.md` §1 lists, under **Out of scope — stated honestly**:

> | Microarchitectural side channels (Spectre-class, MDS, port contention) | Requires per-CPU-generation mitigation work we cannot sustain yet | Phase 3: core scheduling, IBRS/STIBP, cache partitioning. Documented gap until then. |

**That row is correct, and it does not cover this.** Two different things are being named by one
phrase, and cryptography is the place the conflation becomes dangerous:

| | Microarchitectural side channels | Secret-dependent timing in crypto code |
|---|---|---|
| **Who attacks** | An attacker with **code execution on the same machine**, often the same core | **Anyone on the network**, with a stopwatch |
| **What it costs them** | Per-CPU-generation research | A loop and statistics |
| **The mitigation** | Core scheduling, IBRS/STIBP, cache partitioning — per-CPU-generation work this project cannot sustain | Writing the code so it has no secret-dependent branch or memory address — a property of *our* source |
| **Precedent** | Spectre, MDS | Lucky13, Bleichenbacher, cache-timing AES — all remote, all practical, all against real deployments |

The second row is **in scope by every criterion this document uses elsewhere**: the attacker is the
one the whole system is built to defend against, the mitigation is ours to write, and the failure is
total — a leaked long-term key is not degradation, it is impersonation of the server for the life of
the certificate.

**Proposal: `security.md` §1 gains an in-scope row before any cryptographic code merges.**

> **T14** — An attacker recovering key material by measuring the time our cryptographic operations
> take. *Mitigation*: no secret-dependent branch, no secret-dependent memory address, and no
> secret-dependent loop bound in any code handling key material; the property held by construction
> and evidenced by §"Testing plan"'s mechanism rather than asserted. *Status*: ⬜ planned — there is
> no such code yet, and this row exists so that the first line of it arrives under a rule.

The microarchitectural row stays exactly where it is and keeps its wording. This is a **new row, not
an amendment** — the two threats genuinely differ and merging them is what let the gap exist.

### And this is the argument for the recommendation

Rust does not guarantee constant time. `if secret == 0` compiles to a branch, `table[secret]` to a
secret-dependent address, and LLVM is permitted to introduce branches into code that had none. The
honest mechanisms available are:

1. **Discipline and review** — what most projects do. This project has no side-channel expertise
   claimed anywhere in its documents, and `security.md` T9's own posture is that discipline is built
   and exposure is structural.
2. **Statistical timing tests** (`dudect`-style) — a **detector**, not a proof. It finds gross
   leaks, it does not certify their absence, and it is noisy under a scheduler.
3. **Machine-checked secret independence** — a proof, produced once, by a tool, over the source
   being shipped.

**Only the third gives what T14 asks for.** That is the entire case for §3's recommendation, and it
is why the recommendation is about *provenance* rather than about effort.

> **`[corrected]` 2026-08-22, and this is the correction that matters most.** The inspection found
> that libcrux offers mechanism **3′**, not mechanism 3: a *compiler-enforced secret-independence
> type discipline* (`libcrux-secrets` with `check-secret-independence`), with a
> programmer-responsible `.declassify()` escape hatch, optionally cross-checked at runtime under
> Valgrind — over code generated from F\*-verified HACL\* sources upstream. **There are no
> Rust-side proof artifacts for curve25519 or chacha20poly1305 in that repository.** So the
> sentence above is wrong as written: nothing on offer *proves* secret independence over the
> shipped Rust. The repaired argument, which still favours the same option: a compiler-enforced
> discipline maintained by people who do this full time is better evidence for T14 than the care of
> a project claiming no side-channel expertise — and **T14's status must never be written as though
> a proof existed.** See [the inspection](0040-libcrux-inspection.md) §(c).

---

## 3. The three ways to obtain it

Status vocabulary as elsewhere. **The obstacle column is the point of the table.**

| | Option | What it buys | What it costs, and the obstacle found | Verdict |
|---|---|---|---|---|
| **A** | **Hand-write `bhaskix-crypto`** | **P5 preserved absolutely.** Sovereign, reviewable, in this project's own idiom, `unsafe` budget zero, no license question, no upstream | Roughly three to five thousand lines of the least forgiving code in the tree, where a defect is silent — X25519 has no test that fails when it leaks. **T14 would be held by discipline alone**, which §2 argues is the one mechanism that does not deliver it. The project's own precedent cuts against: RFC 0038 refused to re-derive xHCI layouts from the specification because doing so "invites a class of error that the existing work has already been through" — and that argument is *stronger* here, not weaker | 🔨 **The fallback, and the destination for whatever B cannot supply.** HMAC, HKDF and HKDF-Expand-Label should be written here regardless: they are thin, fully specified, and have published vectors |
| **B** | **Vendor formally verified source** into `third_party/`, under RFC 0038's pattern | **Machine-checked memory safety, functional correctness, *and* secret independence** — the T14 property, produced by a tool rather than by care. `libcrux` (Cryspen) declares **Apache-2.0** in its manifest, which is RFC 0038's exact criterion: Bhaskix's own license, so no second license enters the tree — `[corrected]` a `LICENSE-MIT` file is *also* present and the two are unreconciled; the criterion still passes, and the claim was more confident than the evidence. Its primitives are compiled from **HACL\***'s F\* proofs, and it carries the sub-crates this design needs — `libcrux-curve25519` (X25519) and `libcrux-chacha20poly1305` | **Two obstacles found, and neither is fatal on its face.** (1) **`no_std` support is documented as requiring a global allocator, and ring-3 programs here have none** — verified: no `#[global_allocator]`, no `extern crate alloc` anywhere under `user/`, while the kernel has a heap. `[corrected]` **this is not a caveat but measured fact for all five needed crates** — and it is *removable*, because it comes from one unconditional `pub mod bignum` serving RSA and P-256, which this take does not include. (2) It is **pre-release**: all crates versioned below `0.1`, with maintainers asking to be contacted before production use. `libcrux-iot`, an IoT-targeted variant, is the obvious thing for the inspection to look at first | ✅ **Recommended, subject to the inspection in step 1.** The verification is the whole reason, and `third_party/README.md`'s rule applies unchanged: it is reviewed as our own, budgeted as our own, and **"tested here rather than trusted because it was tested elsewhere"** |
| **C** | **Depend on crates.io** — RustCrypto, `ring`, `aws-lc-rs` | Least work by a wide margin, and well-exercised code | **Spends P5**, the strongest verified claim this project has, and turns a frozen reviewable body of code into a live version requirement — the exact distinction `third_party/README.md` was written to draw. `ring` and `aws-lc-rs` additionally carry C and assembly, which this tree has no mechanism to build and which would put a C toolchain on the path to a booting image | ❌ **Refused.** Recorded so it stays refused rather than being rediscovered as obvious |

**A note on what "vendored" means here, because it is the hinge.** Option B is *not* a dependency,
and taking it does **not** change `ALLOWED_EXTERNAL` or spend P5 in the way C does. RFC 0038 already
established the distinction and `NOTICE` already carries the corrected sentence: this project
vendors third-party source into `third_party/` and lists every component. Option B adds a second
entry to that list. P5's honest statement afterwards is "zero external *dependencies*, two vendored
components, both listed" — which is what `NOTICE` already says and what `security.md`'s supply-chain
row was already amended to say on 2026-08-22.

### The boundary this extends, stated rather than assumed

RFC 0038 was careful about what it took: **layouts, not logic.** Its own words — "the bulk of an xHCI
driver is not logic, it is layout" — and it explicitly refused `crab-usb` because that would have
been "the driver as well as the definitions, and the driver half is the part that cannot transfer."

**Cryptography is entirely logic.** So option B is a genuine extension of the precedent and must be
argued rather than assumed to follow. The argument is that RFC 0038's *reason* transfers even though
its category does not: it took existing work because re-deriving it "invites a class of error that
the existing work has already been through", and it refused the driver half because that half
"assumes ambient kernel authority" — a portability problem, not a trust problem. Verified crypto has
no such coupling: X25519 is a function from bytes to bytes. It assumes nothing about this system.

**And one thing does not transfer and should not be smoothed over.** RFC 0038's vendored layouts are
checkable by a reviewer against a public specification, line by line. Vendored field arithmetic is
not checkable that way by anyone, which is precisely why the *proof* is doing the work here and why
option B without the verification would be strictly worse than option A.

---

## 4. What is refused, and when that changes

| Refused | Why | Trigger to build |
|---|---|---|
| **TLS 1.2 and below**, permanently | It is where the CVEs live: CBC padding oracles, RC4, compression, renegotiation, downgrade. A server that offers it inherits all of them | **Nothing.** Not deferred — refused |
| **RSA, in any padding** | PKCS#1 v1.5 is Bleichenbacher's home address and has been re-broken roughly once a decade; PSS is safer and still large-integer arithmetic in constant time. Neither is worth it for a first server | A public CA chain the operator cannot replace, and only with the constant-time question answered first |
| Session tickets, resumption, 0-RTT | 0-RTT is replayable **by design** and the anti-replay window is a distributed-systems problem; tickets need a key rotation story and an age computation that wants a clock. Refusing them also removes the last reason to need time-of-day | An operator with a measured handshake-cost problem — not before |
| Client certificates / mutual TLS | It reintroduces the certificate *validator* that §1 deleted, which is the mass of a TLS implementation | A deployment that needs it, at which point §1's subtraction is spent deliberately |
| Compression | CRIME | Nothing |
| Renegotiation | Removed in TLS 1.3; naming it here stops it being reinvented as a feature | Nothing |
| **A table-driven software AES fallback** | §1. A degraded mode that leaks the key is not a degraded mode | Nothing. AES arrives with AES-NI or it does not arrive |
| Any primitive not in §1's table | "One more curve" is how a crypto library becomes unauditable | A named interop failure against a client that matters |
| **Cryptography anywhere in the nucleus** | The nucleus interprets no Linux syscall number and it will hold no cipher. This is a ring-3 library used by ring-3 programs | Nothing in Phase 2 or 3. Secure boot (§5) needs *verification* in the loader, which is a different binary and a different decision |

## 5. Key custody — the question this shares with secure boot

A server's private key must live somewhere, and the wrong answer is a file in the document root.

The shape this architecture makes available, and which RFC 0039 step 6 already names: **the key lives
in a domain that never returns it.** `bin/tlsd` holds the private key capability and offers one
operation — *sign this transcript hash* — and the request parser, in a different domain, is
structurally incapable of naming the key. Revoking the key capability reaches it immediately and
transitively, which is a property this system already gates (**T2**). No mainstream stack offers
that, and it costs this project nothing extra because the mechanism predates the requirement.

**But how the key gets there is an open governance question, and it is not a new one.**
[RFC 0030](0030-packages.md) refused package signatures with a sentence this RFC must not
contradict: *a signature without key storage, distribution, or revocation is theatre that trains
reviewers to see green checkmarks.* `roadmap.md`'s Phase 3 secure-boot row names key custody as "an
open governance question", and `security.md` §10 carries it.

So there are now **two** consumers of one unanswered question, and this RFC's position is that this
is the cheaper one to answer first: a TLS server key is **per-deployment, operator-generated,
rotatable, and blast-radius-bounded by one domain**, where a secure-boot signing key is
project-wide, permanent, and catastrophic to lose. Answering the small one first is how the big one
gets answered with experience instead of with a decision.

---

## Alternatives considered

| Alternative | Why rejected | Would reconsider if |
|---|---|---|
| **Do nothing until RFC 0039 step 5 arrives** | It is the longest-lead item in that RFC and the only one whose answer is a *decision* rather than work. Deciding it late means steps 1–4 are built without knowing whether ring 3 gains an allocator — which changes how every program in the tree is written | Never; this is why the RFC is opened now |
| **Write a smaller thing than TLS** — a bespoke protocol over the existing rings | Removes interop, which is the entire point of a web server, and replaces a specification thousands of people have attacked with one nobody has | Nothing. A bespoke protocol is the classic way to get this wrong |
| **Terminate TLS off-box**, on a proxy in front | Legitimate and common, and worth naming as what an operator can do *today*. Rejected as the project's answer because it concedes the demonstration: "a compromise does not spread" is not a claim you can make about a machine whose transport security lives on somebody else's Linux box | It becomes the documented deployment advice for the preview, which it arguably already is |
| **Take the verification argument to its conclusion and verify our own code** | F\*/hax over this project's own source is a research programme, not a step. RFC 0038's scale argument applies: this is a volunteer project with one author | The project acquires that expertise, which would be a considerable thing and is not on any roadmap |
| **Vendor RustCrypto instead of libcrux** | Pure Rust, `no_std`, widely used, and **not formally verified** — `subtle` and hand-audited constant-time discipline are exactly mechanism 1 from §2. Vendoring unverified code is strictly worse than option A: same trust problem, plus a second codebase's idiom | The libcrux inspection fails on the allocator and RustCrypto's relevant crates prove allocation-free — then it is a real contest between B-without-proof and A |
| **Adopt option A now and treat B as an optimisation** | Tempting, because A can start today. Rejected because the migration would be *from* hand-written crypto *to* verified crypto, and the hand-written code would be load-bearing in a shipped preview by then. The order matters more than the start date | The inspection in step 1 rules B out |

## Impact on existing design documents

- **[security.md](../security.md) §1** — gains **T14** (§2). This is the load-bearing change and it
  lands **before** any cryptographic code, not with it. The existing microarchitectural out-of-scope
  row is unchanged.
- **[security.md](../security.md) §10** — the key-custody open question gains a second consumer
  (§5), and the note that the TLS key is the smaller of the two.
- **[RFC 0039](0039-pingala-a-native-web-server.md)** — **W3 is retired for the server case** by §1
  (no validation, no tickets, therefore no clock). Its step 5 gains this RFC as its owner and its
  *Unresolved questions* 2 is answered here to the extent that a recommendation answers it.
  RFC 0039 is a draft, so this is legal.
- **`NOTICE` and `third_party/README.md`** — one more component listed, under the pattern already
  written, **if and only if** option B survives the inspection.
- **[roadmap.md](../roadmap.md)** — Phase 3's secure-boot row gains a pointer to §5. No reordering
  is proposed: that row is still first, and this does not displace it.
- **`tools/check-deps.py`** — learns the new crate and its layer so the dependency direction stays
  enforced rather than excepted, exactly as RFC 0038 required for `bhaskix-xhci`. **`ALLOWED_EXTERNAL`
  does not change** — that is the whole difference between options B and C.

## Security implications

- **New authority?** Yes, and it is the most sensitive in the system: a **key capability**. §5 is its
  design. It is held by one domain, it is never returned, and revocation reaches it transitively.
- **New parser for untrusted input?** **Yes, and it is large** — the TLS record layer and the
  handshake. Note what §1 removed: this is a *protocol* parser, not a *certificate* parser, which is
  the smaller and better-specified half. `coding-style.md` §8 binds: a fuzz target lands **before**
  it merges, seeded per the rule that harness learned the hard way.
- **Scope movement.** One row **into** scope: **T14** (§2), which is the point of that section. None
  out.
- **`unsafe` budget.** `bhaskix-crypto`'s budget is **zero** and should be declared exact
  (`unsafe_budget_exact = true`), the mechanism already used for `bin/linuxd` — cryptographic code
  has no business dereferencing anything, and a budget that can drift silently in this crate is the
  wrong default. Vendored source is budgeted the same way, per `third_party/README.md`.
- **`asm_budget`.** Zero for the ChaCha20-Poly1305 path — that is one of its advantages. Non-zero
  only if AES-NI arrives, and then declared with a reason, per `architecture.md` §7.
- **The failure this most needs to avoid** is the one this project has already named in another
  context: a mitigation that *looks* present. A cipher suite list in a boot report proves nothing
  about whether the multiplication under it was constant-time.

## Performance implications

**Not the bottleneck, and saying so early prevents a false trade.** RFC 0039 **W7** established that
performance is not a tracked property here, and the transport measured 1–2.6 MiB/s with a serve loop
convicted twice as the limiter. A handshake costs one X25519 scalar multiplication and one
signature; the record layer costs ChaCha20-Poly1305 per record. On this transport, **none of that
will be visible**, and any claim that a constant-time choice cost throughput would be unmeasured.

What will be measured, in the same style as every other boundary in this tree: the scalar
multiplication and the per-record cost, in cycles, floored before they are believed. The **only**
performance argument this RFC accepts as legitimate is the AES-NI one, and it is deferred to its
own step for exactly that reason.

## Testing plan

**Host — where all of it belongs.** Cryptographic primitives are pure functions over byte slices;
there is no excuse for any of this to need QEMU.

- **Known-answer tests against published vectors**, which is what they exist for and the precedent
  `pkg/src/sha256.rs` already set with FIPS 180-4: RFC 8439 (ChaCha20-Poly1305), RFC 7748 (X25519),
  RFC 5869 (HKDF), and — the valuable one — **RFC 8448, *Example Handshake Traces for TLS 1.3***,
  which publishes complete handshakes with every intermediate value, so the key schedule can be
  verified step by step rather than only at its output.
- **Wycheproof vectors**, which exist specifically for the edge cases known-answer tests miss:
  low-order points, non-canonical encodings, signature malleability, all-zero shared secrets. A
  primitive that passes RFC vectors and fails Wycheproof is the normal outcome, and that is the
  point of running them.
- **The T14 mechanism**, and its honest limit. A `dudect`-style statistical test over secret inputs
  is a **detector, not a proof**: it finds gross leaks and cannot certify absence, and it is noisy.
  It is worth running and it must not be reported as evidence that T14 is met. **If option B wins,
  the proof is the evidence and this test is the smoke alarm; if option A wins, this test is all
  there is, and T14's status says so in those words.**
- **A deliberately reintroduced defect must fail the suite before the suite is believed** — the
  ELF-parser lesson in `coding-style.md` §8. For crypto the reintroduction is specific: flip one
  constant in the field arithmetic and the RFC 7748 vectors must go red; make one branch
  secret-dependent and the timing test must notice.

**Fuzz** — `fuzz/fuzz_targets/tls_record.rs` and `tls_handshake.rs`, before merge, seeded with
well-formed structure mutated within it rather than hoped for from empty, per the 2026-08-21 lesson.

**QEMU** — nothing at this layer. The gates belong to RFC 0039's steps 5 and 6.

**Real hardware** — nothing new, and **M1-17** remains the ceiling over every number.

## Unresolved questions

1. **Does the libcrux inspection succeed?** Step 1 answers it, and the criteria are written there so
   the answer is a finding rather than a judgement. **Project lead decides on the finding.**
2. **Does ring 3 gain a global allocator?** The obstacle found in §3, and it is much bigger than
   cryptography — every ring-3 program in this tree is deliberately heapless, and Phase 5's Embedded
   edition lists "no dynamic allocation in critical paths" as a property. **A heap in ring 3 is an
   architecture decision that must not be taken as a side effect of a crypto import.** If option B
   needs it, that is an argument against option B, not for a heap.
3. **Where does the private key come from, and in what format?** §5. Recommend the narrowest thing
   that works — a raw scalar the operator generates — rather than PKCS#8, which is a parser.
4. **Ed25519 or ECDSA P-256?** The genuine trade. **Ed25519** is far safer to implement — complete
   formulas, deterministic nonces, no catastrophic failure mode from a repeated `k` — but public CAs
   do not widely issue Ed25519 certificates. **ECDSA P-256** is what the ecosystem actually uses and
   is in RFC 8446's mandatory signature set. Recommend **Ed25519 first** with operator-generated
   certificates, and P-256 when a public CA chain is required — **and this question cannot be closed
   until RFC 8446 §9.1 is read to the letter** (§1's note).
5. **Does `security.md` §1 gain T14?** §2 recommends yes, before any code. This is the one item here
   that should be settled independently of which option wins, because it is true either way.

## Implementation plan

Step 1 is an inspection and produces a document, not code. **Nothing else starts until it lands** —
which is the same discipline RFC 0038 used, and the reason that RFC exists in the form it does.

1. **The inspection.** Read `libcrux` and `libcrux-iot` and answer, in writing, against this tree:
   (a) do the needed primitives compile `no_std` **without a global allocator**; (b) exactly which
   files would be taken, and how many lines; (c) what the F\* / hax proofs actually cover — memory
   safety, functional correctness, secret independence — and **what they do not**; (d) does anything
   in the taken subset require an instruction that triggers `asm_budget`; (e) how a pre-release
   upstream is pinned and what "frozen at a known version" means when the version is below `0.1`.
   Output: a `PROVENANCE.md`-shaped document and a go/no-go. **A finding of "no" here is a success
   of this step, not a failure of it.**

   > ✅ **Done 2026-08-22 — [the inspection](0040-libcrux-inspection.md).** Qualified GO: **no** on
   > the crates as packaged, **go** on an adapted subset. (a) all five primitives fail the
   > freestanding link, traced to `pub mod bignum`; (b) the X25519 take measures 1,237 lines, with
   > two rows left unmeasured and named; (c) the verification is weaker than this RFC claimed — see
   > the correction in §2; (d) **no** intrinsics, so `asm_budget` stays 0; (e) the anchor is a git
   > commit, which is what makes a sub-`0.1` version pinnable at all.
   >
   > ✅ **The gate is discharged, 2026-08-22 (inspection §8).** The subset was cut — `bignum`
   > (9,144 lines), the prelude's `alloc` re-exports, Poly1305's streaming API, the KEM impl,
   > `syn`/`quote`, and `hax-lib` — and a freestanding `#![no_std]` binary with **no
   > `#[global_allocator]`** links: 73,288 bytes, **zero allocator symbols**. **6,807 lines, 48
   > files, zero external dependencies.** A differential test against pristine upstream returned
   > **all six values byte-identical**, and the harness was proven able to fail by perturbing one
   > byte of the X25519 basepoint. **Known-answer and Wycheproof vectors were not run** — that is
   > still step 4.
   >
   > **`libcrux-iot` inspected 2026-08-22 and REFUSED**, on two independent grounds: it is
   > **AGPL-3.0-only** — which cannot enter an Apache-2.0 tree, contradicts
   > [RFC 0001](0001-license-apache-2.0.md), and whose §13 network clause would attach to every
   > deployment of a **web server** specifically — and it contains **none** of the needed
   > primitives, being ML-KEM / ML-DSA / SHA-3 for Cortex-M. Step 1 is now complete in both halves.
2. **`security.md` §1 gains T14** (§2). Independent of step 1's outcome, and first if step 1 is slow.
3. **`bhaskix-crypto`, the parts written regardless** — HMAC-SHA256, HKDF, HKDF-Expand-Label over the
   existing SHA-256, plus the CSPRNG question from §1's table. Thin, fully specified, published
   vectors, `unsafe_budget = 0` declared exact. This is real progress that does not depend on the
   decision.
4. **The primitives**, by whichever route step 1 chose: X25519, ChaCha20-Poly1305, one signature
   algorithm. **Step 1 chose: the adapted vendored subset, and its link gate is already passed** —
   what remains here is the licence confirmation, the vectors, and the timing detector. Known-answer *and* Wycheproof vectors, plus the timing detector, before anything
   consumes them.
5. **The TLS 1.3 server handshake and record layer** — RFC 8446, server-only, with §4's refusal list
   as its scope boundary and RFC 8448's traces as its step-by-step test. Fuzz targets before merge.
6. **`bin/tlsd`** — the key in a domain that never returns it (§5). This is RFC 0039's step 6, and
   it is where the architecture stops being an argument and starts being the reason to use this.
