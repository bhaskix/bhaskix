# RFC 0001: License — Apache-2.0

| | |
|---|---|
| **Status** | **Accepted** — 2026-08-02 |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | project-wide |
| **Milestone** | Phase 0 |
| **Resolves** | Open decision **A1** ([docs/architecture.md](../architecture.md) §8) |

---

## Summary

Bhaskix is licensed under the **Apache License, Version 2.0**.

Every source file carries `// SPDX-License-Identifier: Apache-2.0`. Contributions are made under the
Developer Certificate of Origin; there is no CLA and no copyright assignment.

## Motivation

A1 was the one open decision that blocked accepting external contributions. Relicensing a project
that already has outside contributors requires tracking down and obtaining agreement from every one
of them — sometimes impossible. Relicensing a project with none is free. The decision therefore had
to be made before the first external PR, and it is now made.

## Decision

**Apache-2.0**, for four reasons:

1. **Explicit patent grant.** Section 3 grants a patent license from every contributor, and
   terminates it for anyone who initiates patent litigation over the work. MIT and BSD grant
   copyright permission only, leaving patent exposure ambiguous. For an operating system that
   enterprises and governments are being asked to deploy — and that touches virtualization and
   cryptography, both patent-dense areas — this is the single most important difference.

2. **Enterprise and government adoption.** [docs/vision.md](../vision.md) states the mission as
   enabling "developers, enterprises, and governments to deploy secure and intelligent computing
   infrastructure". Apache-2.0 is on essentially every corporate and public-sector approved-license
   list. A copyleft license would require legal review at each of those organisations before a
   single engineer could evaluate Bhaskix, and that friction is paid before any technical merit is
   assessed.

3. **Ecosystem consistency.** The Rust ecosystem is overwhelmingly Apache-2.0 OR MIT. Being
   Apache-2.0 means Bhaskix can consume that ecosystem, and that ecosystem can consume Bhaskix
   components, without a compatibility analysis each time.

4. **Trademark and attribution are handled separately.** Section 6 explicitly withholds trademark
   rights, and the `NOTICE` file carries attribution into derivative works. This gives us the
   naming protection described in [GOVERNANCE.md](../../GOVERNANCE.md) §5 without using the license
   to restrict use.

## Alternatives considered

| Alternative | Why rejected | Would reconsider if |
|---|---|---|
| **MIT** | Shortest and most permissive, but grants no patent rights. For a project in virtualization and security, silence on patents is a liability an adopter's legal team will notice. Apache-2.0 is permissive *and* explicit. | Never — Apache-2.0 strictly dominates for this project's purposes. |
| **Apache-2.0 OR MIT (dual, Rust convention)** | Genuinely tempting: it is the Rust norm and maximises downstream flexibility. Rejected because dual licensing lets a downstream take the work under MIT alone and thereby **discard the patent grant** — which defeats reason 1. The convention exists largely for GPLv2 compatibility, which is not a goal for a project that shares no code with GPLv2 works. | We needed GPLv2 compatibility for a specific integration. |
| **GPLv2** | Linux's license. Strong copyleft would guarantee that improvements return to the community, which aligns with the "fully open source" principle. Rejected for two reasons: it is incompatible with Apache-2.0, cutting us off from the Rust crate ecosystem; and it materially slows enterprise and government adoption, which the mission statement makes a primary goal, not a secondary one. | The project's goal shifted from adoption to guaranteed reciprocity. |
| **GPLv3** | Adds patent and anti-tivoisation provisions. The anti-tivoisation clause conflicts directly with the verified-boot and sealed-key model in [docs/security.md](../security.md) §3 — a locked-down attestable appliance is a *feature* of the hypervisor, edge, and embedded editions. | The project abandoned verified boot as a differentiator. |
| **MPL-2.0** | File-level copyleft; a reasonable middle ground that keeps modifications to Bhaskix files open while permitting proprietary additions. Rejected as the weaker option on both axes: less adoption-friendly than Apache-2.0, less protective than GPL, and the file-level boundary is awkward for a kernel where the unit of modification is rarely a whole file. | Reciprocity became a requirement but GPL was too restrictive. |

**On the honest tension:** copyleft would better guarantee that a company shipping Bhaskix returns its
improvements. Apache-2.0 does not compel that. We accept this cost deliberately, and rely on
governance and community norms rather than license enforcement to keep development in public. If a
large vendor were to build a closed derivative and contribute nothing back, this decision would be
the reason — and we would still consider it the right trade, because a project nobody may adopt has
no improvements to lose.

## Impact on existing design documents

| Document | Change |
|---|---|
| [docs/architecture.md](../architecture.md) §8 | A1 moves from open to resolved |
| [README.md](../../README.md) | License row: "Undecided" → Apache-2.0 |
| [Cargo.toml](../../Cargo.toml) | `license = "Apache-2.0"` |
| [TRACKER.md](../../TRACKER.md) §2 | A1 marked Accepted |

## Security implications

None directly. Indirectly positive: the patent grant reduces legal risk for security researchers and
for downstream adopters of security-relevant components.

The rejection of GPLv3 on anti-tivoisation grounds is a security-architecture decision as much as a
licensing one — see [docs/security.md](../security.md) §3.

## Performance implications

None.

## Testing plan

A CI check asserts that every source file carries an `SPDX-License-Identifier: Apache-2.0` header,
and that `LICENSE` matches the canonical Apache-2.0 text byte for byte.

## Unresolved questions

- **Trademark policy** for the "Bhaskix" name is separate from the license and is still to be written
  ([GOVERNANCE.md](../../GOVERNANCE.md) §5). Required before the first release.
- **Third-party components** fetched at build time (Limine, BSD 2-Clause) are recorded in `NOTICE`.
  A policy for accepting future third-party code — and a license-compatibility check in CI — is
  still needed.

## Implementation

1. ✅ Add `LICENSE` (canonical Apache-2.0 text) and `NOTICE`.
2. ✅ Set `license = "Apache-2.0"` in the workspace manifest.
3. ✅ Update `README.md` and `TRACKER.md`.
4. ⬜ Add SPDX headers to every source file as it is written (M1 onward).
5. ⬜ Add the SPDX-header and LICENSE-integrity CI check (task M1-14).
