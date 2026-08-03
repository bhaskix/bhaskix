# Security Policy

## Project status: pre-alpha

**Bhaskix has never been audited, has no releases, and must not be deployed
anywhere that matters.** It boots, manages memory, and handles exceptions. It
has no user mode, no isolation between processes (there are no processes), no
verified boot, and no update mechanism.

This document exists because [docs/security.md](docs/security.md) §9 promises a
private reporting channel, and a promise made publicly should be actionable.
It is not a claim that the system is ready to defend anything.

## Supported versions

None yet. There have been no releases.

Until there are, security fixes land on `main` and nowhere else. When releases
begin, this table will say which are supported and for how long.

| Version | Supported |
|---|---|
| `main` | Fixes land here |
| Releases | None exist |

## Reporting a vulnerability

**Do not open a public issue for a security bug.**

Report privately to **tarunsoft1@gmail.com** with `[SECURITY]` in the subject.

Please include, as far as you can:

- What the issue is, and which file or subsystem it is in.
- How to reproduce it — a QEMU command line and a commit hash are ideal.
- What an attacker gains. This matters more than severity labels.
- Whether you intend to disclose publicly, and on what timeline.

There is currently **no PGP key**. If you need encrypted communication, say so
in a first message containing no details and one will be published.

## What we commit to

Carrying over the commitments in [docs/security.md](docs/security.md) §9, with
the honest caveat that this is a single-maintainer project and response depends
on one person being available:

- **Acknowledgement within 72 hours.** If you do not hear back, assume the mail
  was lost rather than ignored, and send it again.
- **A coordinated disclosure window of 90 days by default**, negotiable in
  either direction for severe or complex issues.
- **Public credit** in the advisory, unless you prefer otherwise.
- **A published post-mortem** for every issue rated high or critical, including
  what in the design or process allowed it. "Security by design" means treating
  a vulnerability as a design question, not only as a patch.

## What is in scope

The threat model is written down in [docs/security.md](docs/security.md) §1,
including what it explicitly does **not** cover. Reports are most useful when
they land inside it. In particular:

- Memory-safety defects, especially inside `unsafe` blocks whose `// SAFETY:`
  justification turns out to be wrong. That justification being false is
  exactly the bug class this project's process is built to catch, and finding
  one is genuinely valuable.
- Anything that lets code reach memory or a device it holds no capability for.
- Defects in the boot handoff validation, or in any parser reachable from
  untrusted input.
- Flaws in the isolation the design *claims* — if `docs/` says something is
  guaranteed and it is not, that is a real finding even if no attacker exists
  yet.

## What is not a vulnerability *yet*

Bhaskix documents its unfinished work in the open, so please check before
reporting. These are known and tracked, not oversights:

- **No user mode, no processes, no privilege separation.** Everything runs in
  ring 0. This is M5.
- **No KASLR, no demand paging, no copy-on-write.** Tracked in
  [TRACKER.md](TRACKER.md) under M3.
- **No verified boot, no secure update, no attestation.** Phase 3.
- **No SMP, so no locking under contention.** M4.
- **Known gaps in the threat model** — side channels, firmware, and supply
  chain are listed as out of scope in
  [docs/security.md](docs/security.md) §1 with reasons.

[TRACKER.md](TRACKER.md) records what is proven and what merely compiles. If
something there says "not proven", showing that it is in fact broken is
welcome — that is a documentation-versus-reality finding, which is worth having.

## Third-party components

Bhaskix vendors no third-party source and has **zero external Rust
dependencies**, enforced in CI by `tools/check-deps.py`. The bootloader
(Limine, BSD 2-Clause) is fetched at build time and is a boot dependency only;
see [NOTICE](NOTICE). Vulnerabilities in it should go to that project, though
we would like to know.

## Signing keys

There are none yet, because there are no releases. When there are, key custody
will be documented before the first signed artifact exists — and no release
signing key will ever live in this repository
([GOVERNANCE.md](GOVERNANCE.md) §5).
