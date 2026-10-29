# boot/keys — the project's public signing halves

**Empty of keys until the project lead runs the key ceremony** ([RFC 0091](../../docs/rfc/0091-a-boot-its-owner-signed.md)
step 6, [docs/release-keys.md](../../docs/release-keys.md)). Nothing in a release is signed by the
project until then; the 29 Nov preview's loader trusts no key, by the lead's decision of 2026-10-29.

What the ceremony's `export` puts here, and nothing else:

| File | What it is | Who uses it |
|---|---|---|
| `db-ca.pem`, `db-ca.der` | the offline CA's certificate — RSA-2048, SHA-256 | an owner enrols it in `db`; `make release-finish` verifies the loader against it |
| `leaf.pem` | the current signing leaf's certificate | a reader checking a signature by hand |
| `bootsig-release-<id>.public` | the boot-set key's public half, 32 bytes | `RELEASE_BOOT_KEYS` compiles it into a release's loader; `make release-finish` checks `boot.sig` with it |

**No secret ever comes here.** The private halves stay on the lead's offline machine and its two
encrypted backups ([GOVERNANCE.md](../../GOVERNANCE.md) §5), and `make gates` refuses a tracked
private key, a `*.secret` file, or a file ending in one of these public keys — which is what an
SLH-DSA secret is.

The published **test** key is elsewhere, in [`tests/keys/`](../../tests/keys/), and protects nothing
on purpose.
