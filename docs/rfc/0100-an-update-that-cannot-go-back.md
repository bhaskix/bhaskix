# RFC 0100: An update that cannot go back

| | |
|---|---|
| **Status** | ⬜ **Draft 2026-10-31 — nothing built.** ~~Questions for the lead~~ Questions 1-4 decided by the lead the same day, each as proposed; question 5 open (§*Unresolved questions*). Drafted at the lead's request, as Phase 3's second row. |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | boot (`boot/bhaskixboot`), userspace (an update service), tpm, tools |
| **Milestone** | Phase 3, *secure update* ([roadmap.md](../roadmap.md)): threat T7 |
| **Depends on** | [RFC 0091](0091-a-boot-its-owner-signed.md) (the signed boot set and its keys), [RFC 0089](0089-a-boot-the-tpm-records.md) (the TPM, read-only today), [RFC 0030](0030-packages.md) (the package signatures it deferred to here), [RFC 0095](0095-a-disk-that-keeps-what-was-written.md) (a disk that keeps what was written) |

---

## Summary

[`security.md` §7](../security.md) specifies secure update, written in advance:
- an **immutable root**;
- **A/B slots**, with a boot that fails falling back on its own;
- a **monotonic counter that refuses a genuinely signed old image**;
- **no partially updated state**.

None of it exists. This RFC proposes how each is met on what is built: RFC 0091's signed boot set,
the native loader, the TPM, and the block drivers in ring 3. It also proposes how RFC 0030's
package signatures are discharged. **Nothing is built until the lead answers its questions.**

## Motivation

**T7 is "planned, not built"** (`security.md` §1): "no signing, no A/B slots, no rollback counter.
There is no update mechanism at all yet."

Since RFC 0091 the signing half exists. `boot.sig` covers the kernel, the initrd and `boot.conf`,
under an SLH-DSA boot-set key the release carries, and the loader refuses a changed set under
Secure Boot. Three things are still missing:
- **Rollback.** A genuinely signed *old* set still verifies (`guide/secure-boot.md`). `boot.sig`
  already carries a **security version at offset 20, which "must be 0 until secure update gives it
  a meaning"** (`bootsig/src/statement.rs`); this RFC gives it one.
- **An update path.** The loader reads one fixed set from the ESP it was loaded from
  (`efi.rs:467-482`, `main.rs:42-46`). Nothing writes a second one, and nothing here writes FAT.
- **A fallback.** A set that verifies and then fails to boot leaves the machine down.

## Design

1. **Two slots, and where they live.** Each slot holds a complete signed boot set: kernel,
   initrd, `boot.conf`, `boot.sig`. *Proposed*: **raw partitions the loader reads through UEFI's
   Block I/O protocol** and the running system writes through its own block service, with a
   fixed header naming each file's offset and length.
   - It needs no FAT writer.
   - The ESP holds only the loader, which is updated separately (question 1).
2. **The slot record.** A small block naming the active slot, the slot being tried, and a try
   count.
   - Written only after the new slot is fully written and its `boot.sig` verified, so there is no
     partial state.
   - The loader decrements the try count before it boots a slot on trial.
   - The running system marks the slot good once it has booted.
   - A slot whose count reaches zero falls back to the other.
3. **The counter.** A monotonic counter the boot-set's security version is checked against. A set
   whose version is below it is refused as rollback.
   - *Proposed*: **a TPM NV counter**, read by the loader, and advanced to a slot's version only
     after that slot has been marked good, so a broken update cannot strand the machine above the
     version it can still boot.
   - This needs new TPM commands. RFC 0089 kept the TPM read-only on purpose, so **who may
     advance it** is a question.
4. **The immutable root.** The root today is the initrd: read-only, loaded whole into memory, and
   verified whole by `boot.sig` before the kernel runs.
   - *Proposed*: **that counts as §7's immutable root now**.
   - Block-level verification at runtime (a dm-verity equivalent) waits for a root read from disk
     a block at a time.
5. **The update service.**
   - A ring-3 program holding the block capability to the inactive slot and nothing else.
   - It writes a set it has verified against the release's boot-set key, then writes the slot
     record.
   - How a set reaches it (network, disk, a package) is a question; the first version takes it
     from the kept disk (RFC 0095).
6. **Package signatures.** RFC 0030 deferred them here, and its manifests' hash lines were built
   to be a signature's payload. Packages inside the initrd are already covered by `boot.sig`.
   Separately installed ones need a key: the boot-set key, or one of their own.

## Alternatives considered

| Alternative | Why rejected | Would reconsider if |
|---|---|---|
| Slots as directories on the ESP | Needs a FAT writer in ring 3, for a filesystem the system otherwise never writes. | The firmware's own file protocol is used to apply a staged set, which moves the update into the loader. |
| The counter in a UEFI variable | Its tamper resistance is the firmware's, and the counter's whole job is to resist the machine's owner being tricked by an old signed image. | A machine without a TPM. |
| The counter in the slot record | An attacker who can write the disk rewinds it. | Never. |

## Security implications

- **New authority, three pieces:**
  - writing a boot slot;
  - writing the slot record;
  - advancing the TPM counter.

  Each must be held by one program and nothing else. The third is the most sensitive: advanced
  wrongly, the machine refuses its own good images.
- **T7 moves from planned towards mitigated.** T6's "signed, immutable system image" is helped by
  design item 4's statement of what is immutable today.
- **RFC 0089's read-only TPM rule** is reopened by design item 3, deliberately, for one counter.

## Testing plan

To be written once the questions are answered. At least:
- a slot that fails its boot falls back after N tries;
- a genuinely signed old set is refused once the counter has passed it;
- an update interrupted at every write leaves the old slot booting;
- each armed.

## Unresolved questions

**Decided by the lead on 2026-10-31, each as proposed:**
- **1:** raw partitions read through UEFI Block I/O;
- **2:** a TPM NV counter, advanced by the loader only after a slot is marked good;
- **3:** the verified in-memory initrd is the immutable root for now;
- **4:** separately installed packages get **a package key of their own**, not the boot-set key.

**Question 5 is open.**

1. **Where the slots live:** raw partitions read through UEFI Block I/O (*proposed*), or
   directories on the ESP with a FAT writer, or a staged set the loader applies.
2. **The counter and who may advance it:** a TPM NV counter advanced by the loader after a slot
   is marked good (*proposed*), or a UEFI variable.
3. **The immutable root:** the verified in-memory initrd counts now, and block-level verification
   waits (*proposed*); or block-level verification now.
4. **Package signatures:** under the boot-set key, or a package key of their own.
5. **How an update arrives:** from the kept disk first (*proposed*), then the network.

## Implementation plan

Written once the questions are answered.
