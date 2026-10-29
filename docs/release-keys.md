# Release keys — the ceremony

**Who runs it:** the project lead, alone ([GOVERNANCE.md](../GOVERNANCE.md) §5).
**What it makes:** the keys of [RFC 0091](rfc/0091-a-boot-its-owner-signed.md) step 6 — the
project's signature on its loader and on each release's boot set.
**Status:** prepared 2026-10-29 and rehearsed end to end with throwaway keys by
`make test-release-keys`; **not yet run for real**. The 29 Nov preview ships unsigned, by the lead's
decision; the first signed release is the one after it.

Every command below is `tools/release-keys.sh`, which refuses to run with a network interface up,
inside a git work tree, or over an existing key. It does what a person should not be trusted to
remember; this page is what it cannot do — the machine, the media, and where they are kept.

## What it makes

| Key | Algorithm | Its public half goes | Signs |
|---|---|---|---|
| the **CA** | RSA-2048, SHA-256, thirty years | into each owner's `db`, once | the signing leaf, and nothing else |
| the **signing leaf** | RSA-2048, code signing, five years | inside each signed loader | the loader (`sbsign`) — what the firmware checks |
| the **boot-set key** | SLH-DSA-SHA2-128s | compiled into each release's loader | `boot.sig` — what the loader checks |

RSA-2048 with SHA-256 is the one combination every Secure Boot firmware must verify (UEFI 2.10
§2.6.5); the CA exists so a leaf can be replaced without any owner enrolling anything again.

## What you need

- **The offline machine.** A computer that has never been on a network and never will be, with
  Ubuntu 26.04 LTS installed from an ISO whose checksum you verified on another machine, and the
  installer's **full-disk encryption** chosen. Install it with no network; afterwards turn every
  radio off (`nmcli radio all off`) and check that `ip link` shows nothing up but `lo`. If its Wi-Fi
  card can be removed, remove it.
- **Two backup media**, USB sticks you will keep — in two different places.
- **One transfer medium**, which carries the kit in, and public halves and signed releases out.
- **A backup passphrase**, long, kept apart from both backup media. Without it the backups are
  noise; with it and either medium, the keys are anyone's.

## 1. Build the kit — on the build host

```sh
make ceremony-kit          # writes build/ceremony-kit/
```

It holds `bootsign`, `release-keys.sh`, this page, Ubuntu 26.04's `sbsigntool` package pinned by its
SHA-256, `SOURCE` (the commit), and `SHA256SUMS` over all of it. A kit built from uncommitted changes
says so in `SOURCE`; do not use one for a real ceremony. **Write down the sums it prints**, on paper:
step 2 compares them on the other side of the air gap. Copy `build/ceremony-kit/` to the transfer
medium.

## 2. Install the kit — on the offline machine

```sh
cp -r /media/$USER/<transfer>/ceremony-kit ~/ceremony
cd ~/ceremony
sha256sum -c SHA256SUMS                # and compare each line with the paper copy
sudo dpkg -i sbsigntool_*.deb
openssl version                        # 3.5 or later, as 26.04 ships it
```

## 3. Make the keys

```sh
~/ceremony/release-keys.sh init
```

The keys are made in `~/.bhaskix-release-keys` (mode `0700`; `BHASKIX_RELEASE_KEYS` names another).
It prints the CA's SHA-256 fingerprint and the boot-set key's id — **write both down**; they are how
anyone checks later that a published certificate or key is this one.

## 4. Back up, twice

```sh
~/ceremony/release-keys.sh backup /media/$USER/<backup-1>
~/ceremony/release-keys.sh backup /media/$USER/<backup-2>
```

Each writes `bhaskix-release-keys-<time>.tar.enc` (AES-256, the passphrase stretched by PBKDF2 over
600,000 rounds) and a `.sha256` beside it, then **decrypts what it wrote and compares it with the
keys** before it says `ok`. The passphrase is typed — never set in the environment; the script
refuses that for a real backup. Put the two media in two places.

To bring keys back onto a machine — after a disk failure, or to check a backup —
`release-keys.sh restore <archive>` writes them into an empty key directory.

## 5. Export the public halves

```sh
~/ceremony/release-keys.sh export /media/$USER/<transfer>/public
```

It copies `db-ca.pem`, `db-ca.der`, `leaf.pem` and `bootsig-release-<id>.public`, with
`SHA256SUMS`, and refuses if anything secret followed. On the build host:

```sh
cp /media/$USER/<transfer>/public/* boot/keys/
(cd boot/keys && sha256sum -c SHA256SUMS) && rm boot/keys/SHA256SUMS
make gates                             # refuses a tracked secret
git add boot/keys && git commit -s     # by the lead
```

## 6. Sign a release

On the build host, with the release key compiled into the loader:

```sh
make release-dist TAG=vX.Y.Z RELEASE_BOOT_KEYS=boot/keys/bootsig-release-<id>.public
```

Besides the usual `dist/`, that writes **`dist/to-sign/`**: the unsigned loader, the kernel and
initrd read out of the ISO, `boot.conf`, and their sums. Carry it across, and on the offline machine:

```sh
~/ceremony/release-keys.sh sign /media/$USER/<transfer>/to-sign /media/$USER/<transfer>/signed
```

It checks the bundle's sums, refuses a loader that holds the published test key or does not hold
this boot-set key, `sbsign`s the loader with the leaf, writes `boot.sig` over the boot set, and
verifies both before it stops. Back on the build host:

```sh
make release-finish SIGNED=/media/$USER/<transfer>/signed
```

That verifies the loader against `boot/keys/db-ca.pem`, checks that **the signed loader is the one
built here plus a signature and nothing else**, verifies `boot.sig` with the release key, and
assembles `dist/` with the signed loader, the boot set under `bhaskix/`, and
`bhaskix-secure-boot-ca.der` for owners to enrol.

## 7. Rotate

- **The leaf**, when it nears five years or on any doubt: `release-keys.sh rotate-leaf`. Owners
  enrolled the CA, so nothing changes for them. Back up both media again and export again.
- **The boot-set key**: `release-keys.sh rotate-bootset`. Loaders already shipped keep trusting the
  old key — it is compiled in — so the next release's loader carries the new one. Back up and export
  again.

## 8. Revoke

Revocation is `dbx`, on each owner's machine (RFC 0091 question 6); the project publishes what to
put there. An owner writes `dbx` with their own KEK or PK, through their firmware's setup screen,
efitools' `efi-updatevar`, or — for a virtual machine — `virt-fw-vars`.

| Lost or compromised | What owners add to `dbx` | Then |
|---|---|---|
| a loader (a bug, not a key) | its Authenticode SHA-256 — `pesign -h -i bhaskixboot.efi` on any machine | ship a fixed loader |
| the **signing leaf** | `leaf.pem`, the certificate (UEFI 2.10 §32.6.3.3, item C) | `rotate-leaf`, re-sign the current release |
| the **boot-set key** | the hash of every loader that embeds it (item A) | `rotate-bootset`, ship a loader with the new key |
| the **CA** | the CA certificate, and remove it from `db` | a new `init`; every owner enrols the new CA |

`make test-release-keys` boots a loader with its leaf in `dbx`, and one with its own hash there, and
both are refused.

## What is never done

- No key, backup or passphrase ever goes on a networked machine, into a git work tree, or into a
  cloud key service.
- The offline machine is never connected, even "just once", to update it. Its packages are the ones
  the kit carries.
- The published test key (`tests/keys/`) never signs anything a release ships; `release-keys.sh sign`
  and `tools/release-dist.sh` both refuse a loader that holds it.
