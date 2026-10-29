# RFC 0091: A boot its owner signed

| | |
|---|---|
| **Status** | ⬜ **Draft 2026-10-12 — ~~nothing built~~ steps 1 and 2 built 2026-10-29** (`bhaskix-sha256` and `bhaskix-bootsig`, then the signer and `bootsign`; step 0's QEMU halves measured the same day). The project lead chose the scope (firmware → loader → kernel; package and update signing stay with the secure-update RFC) and asked for a draft that lays the decisions out. ~~**The signature algorithm, the enforcement policy and every key-custody question below are the lead's to decide** before step 1 starts.~~ **The lead decided questions 1–8 on 2026-10-29, each as recommended**: SLH-DSA-SHA2-128s for link 2; refuse only with Secure Boot on, handing back to the boot manager; the lead alone holds the release keys, on an offline machine, under an offline CA with a signing leaf; `dbx` for revocation, rollback left to T7; owner keys outside the tree; the verdict in PCR 8. Question 9, the SR550, stays for step 7, on the lead's word at the time. Step 0 may start. |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | boot (`bhaskixboot.efi`, `bhaskix_boot::Handoff`), a new `bootsig` crate and a `sha256` leaf crate, kernel (boot report), tools (a signer), tests, governance (key custody) |
| **Milestone** | Phase 3 — *Secure boot chain*, the roadmap's first row; [security.md](../security.md) §1 **T6** and gap 1 |
| **Depends on** | [RFC 0089](0089-a-boot-the-tpm-records.md) (measured boot — this RFC's predecessor, which handed signing on to it), [RFC 0028](0028-bhaskixboot.md) (the loader that would verify), [RFC 0030](0030-packages.md) (the tree's SHA-256, and its refusal of signatures without custody, which this RFC must answer rather than repeat), [RFC 0040](0040-where-cryptography-comes-from.md) (a Draft — and why this RFC does not have to wait for it) |

---

## Summary

Today anyone who can write the EFI system partition owns ring 0 from the next boot, and since RFC 0089
the TPM *records* that they did — but nothing stops them. This RFC proposes the two links that do.
**First**, UEFI Secure Boot: the firmware checks an Authenticode signature on `bhaskixboot.efi`
against a certificate **the machine's owner enrolled** — not a vendor's. **Second**, the loader checks
one small signed statement, `bhaskix\boot.sig`, naming the SHA-256 of the kernel, the initrd and the
whole of `boot.conf`, against a public key compiled into the loader — so the first link's signature
covers the key the second link trusts. With Secure Boot on, a boot set that fails is refused; with it
off, the loader boots anyway and says, on the screen, in the boot report and in a PCR, that nothing
was enforced. The signature for the second link is **SLH-DSA-SHA2-128s** (FIPS 205, the lead's choice of 2026-10-29),
whose verification needs only the SHA-256 the tree already has. **Nothing is built by this draft**:
the algorithm, the policy and who holds which key are laid out below, ~~for the lead to decide~~ and
were decided by the lead on 2026-10-29, each as recommended (*Unresolved questions*).

## Motivation

[security.md](../security.md) §1 ranks *the kernel image has no authenticity check* first — "the only
gap on this list that hands an attacker ring 0 outright" — and T6 still reads **"Whoever can write the
ESP owns ring 0."** RFC 0089 made that *observable*: the loader measures the kernel and initrd into
PCR 9 and the command line into PCR 8, and the boot report says whether the log and the TPM agree. It
said, on purpose, that it stopped there: "Refusing to boot a kernel that is not ours is signing, which
needs the key-custody decision this RFC deliberately does not take", and its alternatives table hands
the work on — "Key custody is decided — then signing is the next RFC".

The roadmap names key custody the one prerequisite that "is not a task", and
[RFC 0030](0030-packages.md) refused package signatures over it: "A signature without key storage,
distribution, or revocation is theatre that trains reviewers to see green checkmarks". **This RFC does
not get around that sentence; it puts storage, distribution and revocation on the table as decisions**
— *Unresolved questions* 3–7 — and builds nothing that would need them answered first. Everything up
to step 5 of the plan runs on a **published test key**, which proves the mechanism and protects
nothing, and says so in red when it is the key that verified a boot.

Doing nothing leaves gap 1 open with the best instrument for watching it fail. Doing this closes it
for a machine whose owner turns Secure Boot on — and the SR550, today, has it off.

## Design

### The chain, and who holds what

```
UEFI firmware, Secure Boot on
   │  link 1: Authenticode over the PE image, checked against db ──► PCR 7 (firmware's)
   ▼
bhaskixboot.efi  ── holds the boot-set public key(s), compiled in, covered by link 1
   │  measures kernel, initrd, cmdline (RFC 0089) ───────────────► PCR 9, PCR 8
   │  link 2: verifies boot.sig over kernel + initrd + boot.conf
   │  measures the verdict and the key that gave it ─────────────► PCR 8
   ▼
Bhaskix kernel ── reads the verdict from the handoff, prints it
   │  (no link 3: every service is in the initrd, and the initrd's digest is in the statement)
   ▼
services
```

**Two keys, two owners' decisions.** The *firmware-facing* key signs loaders; its certificate sits in
the machine's `db`. The *boot-set* key signs statements; its public half is compiled into the loader.
They are separate on purpose: the firmware dictates the first key's algorithm (below), and the second
is the project's choice.

**The owner is the root.** A machine's owner enrols the certificate of whoever they trust to sign
loaders — the project's, for its release builds, or their own, for a loader they built with their own
boot-set key. The project never asks to be the only root.

### Link 1: the firmware checks the loader

Read from the UEFI 2.10 specification (see *Sources*), not recalled:

- **What may change `db`**: `db`, `dbx`, `dbt` and `dbr` "can always be read but can only be written
  if: The platform is in user mode and the provided variable data is signed with the private half of a
  previously enrolled key exchange key (KEKpriv \*), or the platform private key (PKpriv); or if The
  platform is in setup mode" (§32.6.3). They live under `EFI_IMAGE_SECURITY_DATABASE_GUID`, not the
  global-variable GUID (§32.8.1).
- **How an image is checked**: the PE image hash is Authenticode's ("Creating the PE Image Hash",
  §32.2.3); the signature is `WIN_CERT_TYPE_PKCS_SIGNED_DATA` "formatted as described in the
  Authenticode specification" (§32.2.4.1); and `db` "must either contain an entry with a hash value of
  the image … or it must contain an entry with a certificate against which an entry in the image's
  certificate table can be verified" (§32.6.3.3).
- **Which key the firmware must accept**: the spec's one requirement is §2.6.5's — "The platform key
  (PK) format shall be at least RSA-2048", and PKCS7 verification "shall support SHA-256 … Digest
  Encryption shall support sha256WithRSAEncryption". RSA-3072/4096, RSA-PSS and ECDSA P-256/P-384
  appear only as optional `CryptoIndications` bits (§32.5). **So the firmware-facing key is RSA-2048
  with SHA-256** — the only combination every Secure Boot firmware is required to verify. §32.5 itself
  warns that SHA-256/RSASSA-2048 "should only be used for compatibility consideration"; for a key whose
  whole purpose is compatibility with whatever firmware the owner has, that is the case it names.
- **What a refusal looks like**: "if the image's signature is not found in the authorized database, or
  is found in the forbidden database, the image will not be started" (§32.4.2); `LoadImage` returns
  `EFI_SECURITY_VIOLATION` (§7.4.1); and "In the case of OS Loaders, the next boot option will be
  selected" (§32.6.1).
- **Revoking one loader**: `dbx` defeats verification for "Any entry with SignatureListType of
  EFI_CERT_SHA256_GUID with any SignatureData containing the SHA-256 hash of the binary", and for a
  listed certificate anywhere in the signing chain (§32.6.3.3, items A and C).

**This link needs no code in the tree.** The firmware verifies; the project produces a signed PE with
`sbsign` (sbsigntool, a distribution host tool, 0.9.2 on the build host — the name a Linux user would
guess) and publishes a certificate. Owning a PKCS#7 writer would be owning an ASN.1 encoder in the
release path for no gain.

### Link 2: the loader checks the boot set

**The statement** is 128 bytes, fixed layout, little-endian — no ASN.1, no length fields an attacker
chooses, nothing to parse but offsets:

| Offset | Bytes | Field |
|---|---|---|
| 0 | 16 | magic `"bhaskix boot v1\0"` — domain separation: a signature over this can never be a signature over anything else the project signs |
| 16 | 4 | algorithm — `1` is SLH-DSA-SHA2-128s; the only value step 1 accepts |
| 20 | 4 | security version — **must be 0** until secure update (T7) gives it a meaning; carried now so a format change is not needed then |
| 24 | 8 | key id — the first 8 bytes of SHA-256 over the public key |
| 32 | 32 | SHA-256 of `bhaskix\kernel`, as read |
| 64 | 32 | SHA-256 of `bhaskix\initrd.tar`, as read |
| 96 | 32 | SHA-256 of `bhaskix\boot.conf`, **every byte** — an absent file hashes as empty, which is what the loader already treats it as |

`bhaskix\boot.sig` is the statement followed by the signature: 128 + 7,856 = **7,984 bytes** for
SLH-DSA-SHA2-128s (FIPS 205 Table 2). The signature is FIPS 205's *pure* `slh_sign` over the statement
with an empty context, so the signed message is `0x00 ‖ 0x00 ‖ statement` (Algorithm 24's
`M′ ← toByte(0, 1) ‖ toByte(|ctx|, 1) ‖ ctx ‖ M`).

**All of `boot.conf`, not only the command line.** RFC 0089 measures only the `cmdline=` value, and an
empty one not at all; the option lines — `early-event-log` today — are neither measured nor covered by
anything. A signature over the command line alone would leave a line the loader acts on unsigned. So
the statement covers the file, and a changed option is a changed boot set.

**Order** (`boot/bhaskixboot/src/main.rs` as read 2026-10-12): the kernel, initrd and `boot.conf` are
read before the volume is closed; `boot.sig` is read with them. Then:

1. **measure** — RFC 0089's rule, unchanged: measure before anything interprets;
2. **verify** — hash the three buffers the loader holds, compare with the statement, check the key id
   against the compiled-in list, verify the signature;
3. **decide** — the policy below;
4. parse the ELF — only after a decision to boot.

The loader hashes what it holds rather than reading the digests back out of the event log: the log is
firmware-written input, and a check that trusted it would move the root of link 2 into the firmware's
log-keeping.

### What the loader does with the answer

The loader reads the firmware's `SecureBoot` variable (`EFI_GLOBAL_VARIABLE`
`{0x8BE4DF61,0x93CA,0x11d2,{0xAA,0x0D,0x00,0xE0,0x98,0x03,0x2B,0x8C}}`, attributes BS and RT, UEFI
§3.3) through `GetVariable` (§8.2.1), which runtime services offer "before and after any call to
ExitBootServices()". `SecureBoot` is 1 when "platform firmware performs driver and boot application
signature verification … during the current boot", and it "must be 0 if the platform is in Setup Mode
or Audit Mode during its initialization" (§3.3) — so it alone answers whether link 1 held, and `SetupMode` adds nothing the
loader acts on. An absent variable (firmware older than Secure Boot) is read as 0.

**The policy** — *Unresolved question* 2, decided by the lead 2026-10-29 as recommended:

| `SecureBoot` | `boot.sig` | Loader | Boot report |
|---|---|---|---|
| 1 | verifies, known key | boots | green: `boot signature  verified: key <id>, Secure Boot on` |
| 1 | missing, unknown key, wrong digest, bad signature | **refuses**: says why on the **screen and serial**, then returns `EFI_SECURITY_VIOLATION` to the boot manager, which tries the next boot option — what the firmware itself does with an image it refuses (§32.6.1) | — |
| 0 | verifies, known key | boots | red: `boot signature  verified: key <id>, but NOT ENFORCED: Secure Boot is off` |
| 0 | anything else | boots | red: `boot signature  NOT VERIFIED (<which check failed>), NOT ENFORCED: Secure Boot is off` |
| — | (Limine path) | — | red: `boot signature  NOT CHECKED: the Limine path verifies nothing` |

**Why boot at all with Secure Boot off.** With link 1 down, the loader is itself unprotected: whoever
can write `boot.sig` can write `BOOTX64.EFI`, and a refusal there stops nobody the RFC is about while
stopping every developer whose machine has Secure Boot off — which today is every machine this project
boots on, the SR550 included. ~~Refusing anyway is the alternative the lead may prefer; the table is a
recommendation.~~ Refusing anyway was the alternative; the lead chose the table (2026-10-29).

**The refusal is seen.** Today `refuse()` (main.rs) writes to serial only and parks; a screen with
nothing on it is not an answer a person can act on. This one prints a plain sentence on ConOut and
serial — `bhaskixboot: refusing to boot: the kernel is not the one boot.sig names (Secure Boot is on)`
— and *returns*, so a machine with another boot option still boots something its owner signed.

**Unmistakable either way** — security.md §10 asks how an unsigned boot "is made unmistakable to the
user and to a remote verifier":

- **To the user**: the report lines above, red whenever nothing was enforced, and the **test key named
  as such** — `verified: TEST KEY 0x…` — whenever it is the test key that verified.
- **To a remote verifier**: the loader measures one event — the verdict, the key id and the
  `SecureBoot` value it read — into **PCR 8**, so a quote distinguishes *enforced by key K* from *not
  enforced*. The firmware already measures `SecureBoot`, `PK`, `KEK`, `db` and `dbx` into PCR 7 (TCG
  PC Client Platform Firmware Profile 1.06 §3.3.4.8), so link 1's state is in the quote whatever the
  loader says. Why PCR 8 and not 7 is *Unresolved question* 8.
- **To the kernel**: the verdict reaches it in the handoff — a new `signature` record, so
  **`HANDOFF_VERSION` 4** — and the boot report prints it from there, as RFC 0089's measurement line
  does.

### The signature for link 2

The firmware fixes link 1's algorithm. Link 2's is the project's, and the choice is mostly about what
the loader must contain and what custody must look like — *Unresolved question* 1.

| | SLH-DSA-SHA2-128s (FIPS 205) — **chosen 2026-10-29** | Ed25519 (RFC 8032) | LMS (RFC 8554, SP 800-208) | The firmware's PKCS#7 (RSA-2048) |
|---|---|---|---|---|
| What verification needs | **SHA-256 and MGF1-SHA-256 only** (§11.2.1; that verification calls neither PRF nor the HMAC is read from Algorithm 20's calls, not a sentence of the standard) | SHA-512 — not in the tree — and arithmetic mod 2²⁵⁵−19 with a square root for point decoding (§5.1.1, §5.1.7) | SHA-256 only | Nothing in the tree: the loader asks the firmware |
| Source | written here, `forbid(unsafe)`, against NIST's vectors | waits on [RFC 0040](0040-where-cryptography-comes-from.md), a Draft; the libcrux Ed25519 needs an allocator as published, and nobody has measured one that does not | written here | firmware's |
| State | **stateless** ("This standard specifies the stateless hash-based digital signature algorithm", Abstract) | stateless | **stateful**: "If a secret key state is used twice, no cryptographic security guarantees remain" (RFC 8554 §1.1) | stateless |
| Custody it implies | a file on an offline machine — no hardware token was found that holds one (Yubico's 5.7/5.8 documentation names no SLH-DSA or LMS; other vendors not checked) | a hardware token: YubiKey PIV from firmware 5.7, OpenPGP from 5.2.3 (Yubico's documentation) | SP 800-208 §1: key and signature generation "be performed in hardware cryptographic modules that do not allow secret keying material to be exported" | an RSA key — any token |
| Post-quantum | yes | no | yes | no |
| Sizes | public key 32 B, signature 7,856 B (Table 2) | 32 B, 64 B | per parameter set (RFC 8554 Tables 1–2) | certificate-sized |
| Against it | big signatures; signing is the slow direction; **the NSA's CNSA 2.0 FAQ says SLH-DSA "is not part of CNSA and is not approved for any use in NSS"** — a rule for US national security systems, which this project is not, stated so nobody finds it later | the loader would carry the project's first curve arithmetic, before RFC 0040 has decided where any comes from | state on an offline file is the failure SP 800-208 exists to prevent; done properly it is an HSM | only on firmware that offers `EFI_PKCS7_VERIFY_PROTOCOL` — §2.6.2 requires it of Secure Boot platforms — and the Secure Boot-off developer boots are exactly where it may be missing; not testable on the host; chapter 37 **not read** for this draft |

**Why SLH-DSA-SHA2-128s.** It is the only option whose verifier needs nothing the tree lacks: the
loader adds `sha256` (already tested and trusted for public data by RFC 0030 and RFC 0089) and a few
hundred lines of tree-walking, written against NIST's published vectors. It decouples the boot chain
from RFC 0040, which says itself that secure boot's verifier is "a different binary and a different
decision" (0040 §4, *What is refused*). And it is stateless, so custody is "keep a file secret", not "never lose count".
**What it costs is a second signature scheme in the project**, against the "One signature algorithm" row of
RFC 0040's primitive set for TLS: this RFC argues that the loader is a separate binary, that the scheme
adds no primitive beyond SHA-256, and that TLS's choice is still RFC 0040's to make. The lead may
weigh that the other way.

**Verification is public-data work.** Algorithm 20's inputs are the message, the signature and
`PK = (PK.seed, PK.root)` — nothing secret enters the loader, so the constant-time property RFC 0040
proposes as T14 for "any code handling key material" does not bind the verifier. It binds the signer,
which runs on the custody machine (step 2).

### Where the code lives

- **`sha256/`** — a leaf crate holding `pkg/src/sha256.rs` as it is, re-exported by `bhaskix-pkg` so
  `bin/tpmd` and `pkg`'s callers do not change. The loader may already depend on `pkg` under the layer
  rule (`tools/check-deps.py`: 5 > −2), but that would bring the package manifest code and `ustar`
  into the first code that runs; the loader's dependencies today are leaves (`handoff`, `elf`, `rand`,
  `tcglog`), and this keeps them so.
- **`bootsig/`** — `no_std`, `forbid(unsafe_code)`, no allocation: the statement, and SLH-DSA
  verification for **one** parameter set. Pure, host-tested, fuzzed.
- **The loader** — read `boot.sig` (8 KiB of pages), a `RuntimeServices` table where
  `efi.rs` now has an opaque `usize`, one `GetVariable` call (new `unsafe`, budgeted in
  `Cargo.toml`), the verify-and-decide step, the ConOut refusal, the PCR 8 event, handoff version 4.
- **The kernel** — validates the version-4 handoff and prints the line. No new `unsafe`.
- **`tools/bootsign`** — a host binary, named after `sbsign`: `keygen`, `sign`, `show`. It builds the
  statement from the three files and signs it. SLH-DSA signing needs HMAC-SHA-256 for `PRF_msg`
  (§11.2.1) and randomness, or FIPS 205's deterministic variant (§9.2). OpenSSL signs SLH-DSA from 3.5
  (its NEWS: "Support for PQC algorithms (ML-KEM, ML-DSA and SLH-DSA)", 8 Apr 2025); the build host has
  1.1.1f, so step 2 cross-checks `bootsign` against OpenSSL 3.5+ in a container rather than trusting
  either alone.

### What this does not do

- **Rollback.** An older signed boot set still verifies. Refusing it needs a counter the attacker cannot
  rewind — security.md §7's "monotonic version counter in TPM NVRAM" — which is T7's, with the security
  version field above waiting for it.
- **Packages and updates.** RFC 0030's manifests are signed by the secure-update RFC, which the roadmap
  orders second, "because it needs the same key infrastructure the row above builds".
- **The Limine path.** It boots the BIOS lanes and verifies nothing; the report says so (above).
  Whether Limine could is not checked here, as RFC 0089 did not check whether it could measure.
- **Attestation.** The PCR 8 event is what a verifier would consume; the format (security.md §10: DICE
  or RATS/EAT) stays open.
- **Firmware and SMM.** A compromised firmware verifies whatever it likes. T6 does not ask for more;
  DRTM is RFC 0089's rejected alternative and stays one.

## Alternatives considered

| Alternative | Why rejected | Would reconsider if |
|---|---|---|
| **Microsoft's third-party UEFI CA, through shim** | It works on most machines with no enrolment, and it puts a foreign vendor's review and key at the root of a system whose positioning is independence; shim also brings its own policy (MOK) into the chain. Owner enrolment is a firmware step, said so in the testing plan, not hidden | A target cannot enrol owner keys at all (some locked laptops), and the lead decides that target matters more than the root |
| **Loader → kernel only, no Secure Boot** | The lead's scope decision: without link 1, an ESP writer replaces the loader and its check together | — |
| **Make the kernel a PE image and let the firmware verify it** (no link 2) | One algorithm and no verifier in the tree — but RSA-2048 for everything, a PE wrapper around the ELF kernel, a second image the firmware loads with its own placement, and RFC 0089's measurements rebuilt around it | The firmware path is wanted for a UKI-style single image for reasons other than signing |
| **Ask the firmware's `EFI_PKCS7_VERIFY_PROTOCOL` to verify the boot set** | Kept as a column above, not rejected outright: no crypto in the tree and `db` as the single root. Against it: not testable on the host, absent on exactly the Secure Boot-off machines that need the report, RSA only, and its chapter unread | Step 0 finds the protocol on OVMF *and* the SR550, and the lead prefers one root to a host-testable verifier |
| **Verify in the kernel** | A kernel verifying itself checks what the attacker wrote, with code the attacker wrote — RFC 0089's same row, for the same reason | Never, for the kernel image |
| **Sign only the command line, as RFC 0089 measures only it** | `boot.conf`'s other lines change what the loader does and would stay unsigned | — |
| **One key for both links** | The firmware dictates RSA-2048 for link 1; using it for link 2 means a `bignum` in the loader — the allocator problem RFC 0040's inspection traced — and ties the boot set's lifetime to a certificate's | The PKCS#7 column wins question 1 |
| **Ed25519 now** | Needs SHA-512 and field arithmetic the tree does not have, from a source RFC 0040 has not chosen | RFC 0040 settles an allocator-free Ed25519 and the lead chooses token custody (question 4) |
| **LMS / HSS** | Stateful; SP 800-208 confines generation and signing to hardware modules that store "the incremented leaf index value in nonvolatile storage before exporting a signature value" (§8.1) | Custody is an HSM that implements LMS that way — the NSA's CNSA 2.0 prefers LMS for firmware signing, which matters to anyone selling to US national security systems |

## Impact on existing design documents

- [security.md](../security.md) — T6's mitigation column gains this RFC; gap 1's text points here; §3's
  diagram gains link 2 and the PCR 8 verdict event, and its "(signed, once key custody is decided)"
  stays true until question 3 is answered; §10's developer-mode question is answered by question 2.
- [roadmap.md](../roadmap.md) — the *Secure boot chain* row: TPM driver and handoff bump done
  (RFC 0089), signing drafted here, custody still open.
- [GOVERNANCE.md](../../GOVERNANCE.md) §5 — it promises custody "will be documented before any signed
  release exists". The answers to questions 3–7 are that document; GOVERNANCE.md should state them or
  point at the RFC that does.
- [architecture.md](../architecture.md) — the `Handoff` listing gains `signature`; the version reads 4.
- [RFC 0007](0007-livepatch.md) — its question 5, "Who signs?", gains a candidate answer: the boot-set
  key's custody, or a separate patch key under the same rules.
- [RFC 0028](0028-bhaskixboot.md) — its "Secure Boot signing — deliberately out of scope" points here.

## Security implications

- **What it gives**: with Secure Boot on and the owner's certificate enrolled, a replaced loader is
  refused by the firmware and a replaced kernel, initrd or `boot.conf` by the loader — T6's prevention
  half, for the native path. With it off, it gives what RFC 0089 gave, plus a verdict nobody can
  mistake for enforcement.
- **What it does not give**: rollback protection (T7); protection from firmware or SMM; protection from
  someone who can put the platform into setup mode — in which case `SecureBoot` reads 0, the report
  says *not enforced*, and PCR 7 records the change, so it is detectable and not prevented.
- **New untrusted input**: `boot.sig`, read off the ESP. The statement is offsets into 128 bytes; the
  signature is hashed, never parsed for lengths. Both are fuzzed with the verifier.
- **No secrets in the loader**: verification takes the public key and public data only (FIPS 205,
  Algorithm 20). The signer handles the secret, on the custody machine.
- **The test key is a published secret**, on purpose — the snakeoil precedent: Ubuntu's OVMF ships
  `OVMF_VARS_4M.snakeoil.fd`, "for testing purposes only", with its private key beside it. A loader
  that trusts the test key accepts anything anyone signs. So the release recipe **refuses to build a
  loader embedding the test key id** (a gate, armed), and the report names the test key in red whenever
  it verified a boot.
- **A key lost**: the boot-set key → `dbx` the loaders that embed it (item A, by hash) and ship a loader
  with a new key; the firmware-facing key → `dbx` its certificate (item C). Both need every owner to
  update `dbx`, signed by their KEK or PK — which is why question 5's hierarchy matters.

## Performance implications

- **The loader hashes the kernel and initrd itself** — about 16 MB (RFC 0089's measured sizes), on top
  of the firmware's hashing for the PCRs. Measured in step 3 with the loader's own timing, on QEMU and
  on the SR550, not estimated here.
- **Verification**: by count from FIPS 205 Table 2 — FORS `k·(1+a)` = 182 hash calls, plus, for each of
  `d` = 7 layers, at most `len·(w−1)` = 35·15 = 525 chain steps and `h′` = 9 tree hashes — **at most
  about 3,900 SHA-256 calls** for one signature, half that on average for the chains. Counted, not
  measured: step 1 measures it on the host and step 3 in the loader.
- **Size**: `boot.sig` is 7,984 bytes; the loader grows by `sha256` and `bootsig`, reported in step 3.
- Nothing after `ExitBootServices`.

## Testing plan

- **Step 0, before any code, three measurements**:
  - **Does this host's OVMF honour the snakeoil certificate's expiry?** The certificate beside
    `OVMF_VARS.snakeoil.fd` on the build host (`/usr/share/ovmf/PkKek-1-snakeoil.pem`, RSA 2048,
    sha256WithRSAEncryption) **expired 2019-12-01** — read with `openssl x509` on 2026-10-12. If a
    loader signed with it is refused, the Secure Boot lane uses Ubuntu 24.04's OVMF, whose README says
    its snakeoil key is enrolled "in PK, KEK & DB", in a container, as `tools/swtpm.sh` does for swtpm.
  - Whether OVMF and the SR550 offer `EFI_PKCS7_VERIFY_PROTOCOL` (question 1's fourth column).
  - What `GetVariable("SecureBoot")` reads on the plain native lanes (expected 0) and on the SR550.
- **Step 0, measured 2026-10-29 — the QEMU halves done, the SR550's waiting on a boot there.**
  Every arm was run, from scratch files; no code was written or merged.

  | | This host: QEMU 4.2.1, OVMF `0~20191122.bd85bf54-2ubuntu3.6` | CI's runner: QEMU 10.2.1, OVMF `2025.11-3ubuntu7.3` (Ubuntu 26.04, in a container) |
  |---|---|---|
  | The loader `sbsign`ed with the package's snakeoil key, on the Secure Boot build and the snakeoil variable store | **boots** (its banner prints), although the certificate expired 2019-12-01: **this OVMF does not honour certificate expiry**, so the lane needs no other firmware | boots; this certificate is a newer one, valid to 2053-05-17, so expiry does not arise |
  | The same loader unsigned — the control | refused: `failed to load Boot0001 …: Security Violation`, and the firmware's own shell refused the same way | refused: `Access Denied -- rejected probably by Secure Boot` |
  | `EFI_PKCS7_VERIFY_PROTOCOL` (`dh -p Pkcs7Verify` in a UEFI shell; `dh -p SimpleFileSystem` listing a handle is the control) | **absent** from the plain build and from the Secure Boot build | **absent** from both |
  | `SecureBoot`, read with the shell's `dmpstore` | **0** on the plain 4 MiB pair the native lanes use (`SetupMode` 1); 0 on the Secure Boot build with an un-enrolled store | **absent** on the plain pair — the "read as 0" case of *What the loader does with the answer*, so CI's native lanes are what exercise it; 0 on the Secure Boot build with an un-enrolled store |

  - **The Secure Boot lane here needs `-global ICH9-LPC.disable_s3=1`.** Without it the Secure
    Boot build wrote nothing to serial or to the debug port in 60 s; with it, it reached its boot
    manager at once. QEMU 10.2.1 needed no such flag.
  - **The snakeoil key is encrypted.** The 20.04 package's `README.Debian` gives the password,
    `snakeoil`; it opens the 26.04 key as well. CI's firmware has no shell of its own, so the probe
    there booted Ubuntu's `efi-shell-x64` (the same edk2 release) from the ESP.
  - **Not measured**: `SecureBoot` *with* the snakeoil store enrolled. The shell is refused there,
    so the value was not read; enforcement was observed instead, in the refusals above. Every value
    in the table was read by the shell's `dmpstore`, not by the loader — that reading is step 3's,
    through `GetVariable`. And the SR550's two halves — the PKCS#7 protocol and `SecureBoot` — need
    a boot there, on the lead's word.
- **Host**: `bootsig` against NIST's ACVP vectors (`SLH-DSA-sigVer-FIPS205`, the SHA2-128s groups —
  each with valid signatures and the labelled negatives "modified message", "modified signature - R",
  "- SIGFORS", "- SIGHT", "too large", "too small"), every negative armed red once; the statement's
  every refusal; `sha256` keeps `pkg`'s tests; a fuzz target over parse-and-verify.
- **QEMU, Secure Boot off** (the native lanes): a test-signed set → *verified, NOT ENFORCED*; one byte
  flipped in the kernel, the initrd or `boot.conf` → *NOT VERIFIED* naming which digest; `boot.sig`
  missing; an unknown key id; the test key named in red.
- **QEMU, Secure Boot on** (a new lane on `OVMF_CODE.secboot.fd`): an `sbsign`ed loader and a signed
  set boot *verified, Secure Boot on*; a flipped kernel byte is **refused**, on the screen and serial,
  and the loader returns; an **unsigned loader never prints its banner** — the firmware refused it.
- **CI**: both kinds of lane, beside the native TPM lanes.
- **Hardware**: step 7, on the lead's word.

## Unresolved questions

**Every one of these is the lead's.** Each carries a recommendation; none is decided by this draft.
**Questions 1–8 were decided by the lead on 2026-10-29, each as recommended; question 9 stays open
until step 7.**

1. **The algorithm for link 2.** **Decided 2026-10-29 by the lead, as recommended**. Recommended: **SLH-DSA-SHA2-128s**. The alternatives are the other
   three columns. Decide together with question 4: the algorithm decides what custody can be.
2. **The policy.** **Decided 2026-10-29 by the lead, as recommended**. Recommended: the table above — refuse only with Secure Boot on, and return to the
   boot manager rather than park. The alternative is refusing whenever a key is compiled in; it
   protects nothing extra while link 1 is down and stops every Secure Boot-off machine.
3. **Who holds the release keys.** **Decided 2026-10-29 by the lead, as recommended**. Recommended: the lead alone for now, written down in GOVERNANCE.md
   §5 — the project has one author and the governance model says so — with a second holder of a
   sealed backup named when there is a second maintainer, and k-of-n considered then.
4. **Where they live.** **Decided 2026-10-29 by the lead, as recommended**. Recommended, for SLH-DSA: an **offline machine** that has never been networked,
   disk-encrypted, the key backed up on two offline media kept in two places. For Ed25519 it would be a
   hardware token. **Never a cloud KMS** — the key that decides what boots on an owner's machine should
   not sit in a third country's data centre.
5. **The hierarchy.** **Decided 2026-10-29 by the lead, as recommended**. Recommended: for the firmware-facing key, an **offline CA certificate in `db`**
   and a signing leaf beneath it, so a leaf is rotated without every owner re-enrolling (`db` verifies
   against "a certificate against which an entry in the image's certificate table can be verified");
   for the boot-set key, keys compiled into each loader release and rotated with it — no second
   hierarchy.
6. **Revocation and rollback.** **Decided 2026-10-29 by the lead, as recommended**. Recommended: `dbx` for both kinds of loss, as above, and the security
   version left at 0 until T7's RFC gives it a counter.
7. **Owner and developer keys.** **Decided 2026-10-29 by the lead, as recommended**. Recommended: `bootsign keygen` writes an owner's keys **outside the
   tree** (`$BHASKIX_KEYS`, default `~/.bhaskix-keys`), so no `git add` can reach them and
   `make clean` cannot destroy a key a machine has enrolled; CI and the lanes use the test key, in
   `tests/keys/`, labelled as a test key in its file name and its report line.
8. **Which PCR carries the verdict.** **Decided 2026-10-29 by the lead, as recommended**. Recommended: **8**. The TCG profile says "PCR[0-7] are
   exclusively for the use of platform firmware. Operating system and OS present software should never
   use those PCRs" (§3.3.1); shim extends PCR 7 anyway (its `README.tpm`), and this RFC does not copy
   it. RFC 0089 read PCRs 10–15 as taken in the UAPI registry; 9 is "files read" by grub's convention
   and 8 its "commands and command line", which a verdict is closer to.
9. **The SR550.** Enrolling a certificate and turning Secure Boot on are firmware changes on a live
   oVirt node, whose own OS must still boot afterwards. Recommended: **append** the project certificate
   to `db`, keep every existing entry, boot once with Secure Boot on, and turn it off again — each step
   on the lead's go-ahead at the time.

## Implementation plan

Nothing starts until questions 1 and 2 are answered — ~~and~~ they were, on 2026-10-29. Steps 1–5 need
no custody decision; step 6 does, and questions 3–7 were decided the same day.

0. **The three measurements** in the testing plan (**the QEMU halves done 2026-10-29**, recorded there; the SR550's
   wait for a boot on it) — the snakeoil certificate's expiry, the PKCS#7
   protocol, `SecureBoot` as read. No code merged; the answers recorded here.
1. **`sha256` and `bootsig`**: the leaf crate re-exported by `pkg`; the statement; SLH-DSA-SHA2-128s
   verification against the ACVP vectors, armed; a fuzz target; the verification cost measured.
   **Done 2026-10-29**, recorded below *Implementation plan*.
2. **`tools/bootsign`** and the test key: `keygen`, `sign`, `show`; cross-checked against OpenSSL 3.5+
   in a container, both directions; owner keys outside the tree. **Done 2026-10-29**, signed hedged
   (the lead's choice), recorded below *Step 1, as built*.
3. **The loader**: `boot.sig`, `GetVariable`, verify after measuring, the policy, the refusal on ConOut
   and serial, the return to the boot manager, the PCR 8 event, handoff version 4; the kernel's report
   line; the hashing cost measured.
4. **The native-lane gates**, Secure Boot off.
5. **The Secure Boot lane**, QEMU and CI, with the release recipe's test-key refusal gated.
6. **Release keys and the first signed loader** — ~~**blocked on questions 3–7**~~ (decided 2026-10-29), and GOVERNANCE.md §5
   updated in the same change.
7. **The SR550** — question 9, on the lead's word at the time.

### Step 1, as built (2026-10-29)

- **`bhaskix-sha256`** is `pkg/src/sha256.rs` moved unchanged, its six published-vector tests with
  it, and re-exported by `bhaskix-pkg`, so no caller changed. `Sha256` became `Clone`, so the
  constant first block of every tweakable hash, `PK.seed ‖ 0^48`, is compressed once per
  verification.
- **`bhaskix-bootsig`** (layer −2, `no_std`, no allocation, `unsafe` budget 0, depending on
  `bhaskix-sha256` alone) holds `slh_dsa` and `statement`.
  - `slh_dsa` implements FIPS 205 Algorithms 2–5, 8, 11, 13, 17, 20 and 24, each named in its
    doc comment, over §11.2.1's hashes and Table 3's 22-byte address. The message is taken in
    parts, so `M′` is never assembled.
  - `statement` is the 128-byte layout. `check` names the first check a boot set fails, in this
    RFC's order: the parse, the three digests, the key, then the signature.
- **The vectors**: NIST ACVP-Server's SHA2-128s sigVer groups 19 (external, pure) and 31
  (internal), 28 tests, in `third_party/acvp-slh-dsa/`. The NIST notice is kept intact there, and
  the selection is recorded. Every one gets its verdict and its reason.
- **Armed red, each once and reverted**:
  - a verifier accepting any right-length signature turns all 16 modified-message,
    modified-R, -SIGFORS and -SIGHT negatives red;
  - with the length check removed, a too-large signature is **accepted**;
  - six one-line transcription faults each turn the valid vectors red: `H_msg` ignoring the
    message, the WOTS⁺ checksum unshifted, the siblings swapped, the FORS index offset dropped,
    the layer unset, and MGF1's counter wrong;
  - each of `check`'s nine refusals, disabled, turns its own test red.
- **The cost, measured**: one verification is 2,098 tweakable hashes for the vector measured.
  253 are fixed by the parameters (d·h′ + k·a `H`s, the eight `T_l`, k FORS leaves). The other
  1,845 are WOTS⁺ chain steps, which depend on the message, between 0 and d·len·(w − 1) = 3,675.
  That is 2,164 compressions for them, plus one for the seed block and the message's own hashing.
  The median is **845 µs** over 100 (809 µs to 1.01 ms), in release on a Xeon Silver 4314 at
  2.4 GHz, under a load of about 4 from other users. The loader's figure is step 3's to measure,
  where it runs.
- **Fuzzed**: `fuzz_targets/bootsig.rs`, three arms. Ten minutes from an empty corpus gave
  314,709 executions and no crash, hang or artifact.
  - Read back from the corpus, arm B got past the parse in 101 inputs and **verified a signature
    in 33**, refusing every one, as nothing it builds was signed.
  - Arm C verified the unchanged NIST vector in 5, refused a bent one in 64, and pushed the
    context past 255 in 1.
  - Arm A never got past the size check: libFuzzer's input limit stayed under 2,820 bytes against
    a 7,984-byte file. Arm B is what reaches the parse's checks.
- **Not testable until step 2**: `check` *accepting* a boot set, which needs a signer. Its
  signature path is proven by the vectors through `slh_dsa::verify`. ~~Not testable~~ — step 2's
  integration tests are the first to see it accept.

### Step 2, as built (2026-10-29)

- **Signing**, in `bhaskix-bootsig` behind a `sign` feature the loader never enables. It reuses
  the verifier's address, tweakable hashes, digit and digest arithmetic, so the two halves cannot
  disagree about them. It adds `PRF`, `PRF_msg` over HMAC-SHA-256, and Algorithms 6, 7, 9, 10,
  12, 14–16, 18, 19 and 22. It stays `no_std` and allocation-free, and the caller supplies the
  randomness.
- **Hedged**, as the lead chose: `bootsign` draws `addrnd` from `/dev/urandom` for every
  signature, so two signatures over one statement differ and both verify, which a test shows.
  `addrnd = None`, the deterministic variant, exists only for NIST's deterministic vectors.
- **Proven byte-exact** against:
  - RFC 4231's seven HMAC-SHA-256 cases, extracted from the RFC's text by script;
  - all 10 NIST ACVP SHA2-128s keyGen vectors;
  - all 28 sigGen vectors for the two interfaces, deterministic and hedged, each then verified.

  The tests turn on `sign` through a self dev-dependency, so `cargo test --workspace`, and with it
  CI, checks the signer. The two crates are optimised in the dev profile, which takes the signing
  tests from minutes to about 8 s; overflow checks stay on.
- **Armed red, each reverted**:
  - the WOTS⁺ PRF address type wrong: keyGen and every sigGen group go red;
  - `addrnd` ignored: **only the two hedged groups** go red;
  - HMAC's inner pad wrong: RFC 4231 and sigGen go red;
  - XMSS's sibling index, FORS's secret index, or keygen's layer wrong: their vectors go red.
- **`bootsign`** (`make bootsign`; `make gates` checks it still builds):
  - `keygen` writes to `$BHASKIX_KEYS`, by default `~/.bhaskix-keys/`: the directory `0700`, the
    secret `0600`. It refuses a destination inside a git work tree and never overwrites a key.
  - `keygen --test` made the published test key, `tests/keys/bootsig-TEST-KEY`, key id
    `a6c913d8a0e2476e`, which `statement::TEST_KEY_ID` names and a test holds to the file.
  - `sign` hashes the ESP's three files and signs hedged. It runs the loader's own `check` before
    writing, so it never writes a `boot.sig` that would not verify.
  - `show` names each digest as matching or `DIFFERS` and gives `check`'s verdict.

  Eight integration tests drive the binary. Armed: with the self-check bypassed, a damaged key
  writes a bad `boot.sig`, and with the in-tree refusal disabled, `keygen` writes into a work
  tree. Signing a 13 MB kernel and a 3.4 MB initrd took 0.90 s wall time and 18 MB of memory on
  the build host, at a load of 2.3; `show` took 0.10 s.
- **Cross-checked with OpenSSL 3.5.5** (`tools/bootsign-crosscheck.sh`, in an Ubuntu 26.04
  container), all four results ok:
  - OpenSSL verified a `bootsign` signature, and refused it over a statement with a byte changed;
  - `bootsign` verified OpenSSL's signature, and refused it with a byte changed.

  The keys crossed as OpenSSL's own encodings, read from what it wrote: a 20-byte PKCS#8 prefix
  and an 18-byte SPKI prefix in front of FIPS 205's raw bytes. Armed: with the OID byte wrong,
  the first result goes FAIL.
- **Limits, stated**:
  - the signer's constant-time property is argued, not measured;
  - secret bytes are not zeroed in memory, which would need `unsafe` this crate's budget forbids.

## Sources

Read for this draft on 2026-10-12. uefi.org and trustedcomputinggroup.org refused this build host
(HTTP 403), so their pages were read from Common Crawl's captures of the official URLs; the NSA's
documents from the Internet Archive's copies.

- UEFI Specification 2.10 (§2.6.2, §2.6.5, §3.3, §7.4.1, §8.2.1, §32) — `https://uefi.org/specs/UEFI/2.10/`.
  Chapter 37 (PKCS7 Verify Protocol) and 2.11 **not read**.
- TCG PC Client Platform Firmware Profile, Version 1.06 Revision 52 (§3.3.1, §3.3.4, §3.3.4.8) — read
  to page 91 of the published PDF.
- FIPS 205, *Stateless Hash-Based Digital Signature Standard*, NIST, 13 August 2024 (Table 2, §9.2,
  §11.2, Algorithms 20 and 24). NIST ACVP vectors: `usnistgov/ACVP-Server`,
  `gen-val/json-files/SLH-DSA-sigVer-FIPS205`.
- RFC 8554 (Leighton-Micali Hash-Based Signatures) §1.1, §2, §4.2; NIST SP 800-208 §1, §8.1.
- RFC 8032 (EdDSA) §5.1.
- NSA, CNSA 2.0 advisory (September 2022) and FAQ v2.1 (December 2024).
- OpenSSL `NEWS.md` (3.5.0, 3.6.0); Yubico's YubiKey 5 technical manual (firmware 5.7, 5.8, OpenPGP).
- shim's `README.tpm` and `tpm.c` (rhboot/shim); GNU GRUB manual §19.6 (Measured Boot).
- Ubuntu's and Debian's `ovmf.README.Debian` (the snakeoil variable store).
