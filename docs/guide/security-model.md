<!-- SPDX-License-Identifier: Apache-2.0 -->

# The security model

**Verified** 2026-10-30 against `aa2dcc5`, by booting `make demo` and typing every command shown;
the rest checked against `docs/security.md` at that commit.

Bhaskix's security rests on one rule: **a program can do exactly what the
capabilities it holds allow, and nothing else.** There is no superuser to become,
no file it can reach by guessing a path, and no device it can drive without
having been given it. This page says what that protects, how, and — as plainly —
what it does not protect yet. The full threat model is
[security.md](../security.md).

## No root, no ambient authority

On most systems a program inherits authority it was never handed: the user's
files, the network, every path it can name. Bhaskix has none of that. A program
starts with the capabilities its creator gave it, and the shell can show you
what that is — `caps` lists every slot it holds:

```
bhaskix$ caps
  0  console   reachable
  1  files     reachable
  2  (nothing) no authority
  8  directory reachable, and answers no method it was not given
  1  badge     can be passed on, and cannot be changed by its holder
  10 stale dir the directory it named is gone
```

Anything else is refused at the boundary where it is asked for, with a reason —
here, memory the shell does not hold, asked to be writable:

```
bhaskix$ map
  3  memory rw  mapped and holds what was written
  4  memory ro  refused a writable mapping
  5  device ro  status 15
  5  device rw  refused a writable mapping
```

Authority can be taken back: **revoking a capability revokes every copy derived
from it**, wherever it was passed, at once. That is checked on every boot.

## What keeps programs apart

- **Address spaces.** Each domain has its own; one cannot read another's
  memory. Code is never writable and data never executable (W^X), by
  construction rather than by convention.
- **The kernel guards itself.** SMEP and SMAP stop the kernel running or
  touching user memory by accident, its address is randomised at boot (KASLR),
  and it is written in Rust, with every `unsafe` block justified and counted
  against a budget per crate.
- **Devices are confined.** Each device can reach only the memory its driver
  was given, through the machine's IOMMU; a device with no driver can reach
  nothing. A machine without an IOMMU is reported as such, in yellow, at boot.
- **Linux programs are guests.** A hosted Linux program's `root` is not
  Bhaskix authority; what it can reach is what the Linux adapter was granted for
  it, and the adapter answers its system calls instead of the kernel.

## What the boot proves about itself

- **Measured boot.** Bhaskix's own loader records the kernel, the initrd and the
  command line in the machine's TPM, and `bin/tpmd`, a program outside the
  kernel, replays the event log against the TPM's own registers.
- **Signed boot.** The loader checks a signature over the same files and, with
  UEFI Secure Boot on, refuses a set that fails. The project's own keys do not
  exist yet; [Sign your own boot](secure-boot.md) shows how to use yours.

## What it does not protect yet

From [security.md](../security.md), in its words where they are short:

| | Not yet |
|---|---|
| **Virtual machines** | Domains are meant to isolate guests too, but there is no hardware virtualisation yet, so there are no guests to isolate |
| **Updates** | There is no update mechanism, so nothing signs, stages or rolls one back |
| **Audit** | There is no tamper-evident audit log or remote attestation yet; the telemetry plane that would feed them is built |
| **Old signed boots** | An older signed boot set still verifies; refusing it needs a rollback counter not yet built |
| **The Linux adapter** | `bin/linuxd` holds the authority for every hosted program, so a compromise of it reaches all of their files — the concentration point the design accepts, and states |
| **Randomness** | One entropy source, the CPU's `RDRAND`, with no pool behind it |
| **Firmware** | A compromised firmware verifies whatever it likes; nothing here defends against it |

Bugs are found too, and fixed in the open: on 2026-10-29 a Linux program could
panic the kernel with one `munmap`, and until 2026-10-30 a boot wrote one sector
to any SATA disk it found. Both are fixed, and each has a test that fails if it
comes back; the [tracker](../../TRACKER.md) records them.

## Report a security problem

**Privately**, as [SECURITY.md](../../SECURITY.md) describes — not in a public
issue.
