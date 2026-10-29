# Provenance

These are **NIST's test vectors, not this project's work**, and must not be
presented as any. They are test data: read by `bhaskix-bootsig`'s host tests
and linked into nothing.

| | |
|---|---|
| **Upstream** | NIST ACVP-Server |
| **Source** | https://github.com/usnistgov/ACVP-Server, `gen-val/json-files/SLH-DSA-sigVer-FIPS205/internalProjection.json` |
| **Version taken** | the file as of upstream commit `112690e8484d` (2025-06-12), the last to change it when it was read |
| **Source file sha256** | `a013fc2104f4ed4799d96d51141f65b965969b2cf10646626a021b6d456ce792` |
| **Upstream terms** | the NIST notice in the upstream README, kept intact in [`LICENSE-NIST.md`](LICENSE-NIST.md) |
| **Taken on** | 2026-10-29 |
| **Decision** | [RFC 0091](../../docs/rfc/0091-a-boot-its-owner-signed.md) step 1, *Testing plan*: "`bootsig` against NIST's ACVP vectors" |

**Acknowledgment**, as the notice asks: these vectors are the work of the
National Institute of Standards and Technology, and this directory's only
source is NIST's ACVP-Server.

## What was changed, and when

**2026-10-29: selected, trimmed and re-encoded; no value altered.**
`tools/acvp-extract.py` produced `sha2-128s-sigver.tsv` from the file above. It
refuses any file whose sha256 differs, so the change is reproducible exactly.

- **Selected**: only the SLH-DSA-SHA2-128s groups for the two interfaces
  `bhaskix-bootsig` offers: group 19 (external, pure — FIPS 205 Algorithm 24)
  and group 31 (internal — Algorithm 20), 14 tests each. The pre-hash group and
  every other parameter set were left out.
- **Trimmed**: each test keeps `tcId`, its group, `testPassed`, `reason`, `pk`,
  `context`, `message` and `signature`. The secret key and the signing
  randomness were dropped, because nothing here signs.
- **Re-encoded**: from JSON to one tab-separated line per test, with the byte
  fields in hex exactly as upstream wrote them.
