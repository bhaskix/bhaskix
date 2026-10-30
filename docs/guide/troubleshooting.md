<!-- SPDX-License-Identifier: Apache-2.0 -->

# Troubleshooting

**Verified** 2026-10-30 against `6150ade`, under QEMU 4.2.1 on Ubuntu 20.04 — the firmware names on
Ubuntu 26.04 too — by reproducing each symptom.

The problems people meet first, what each looks like, and what to do. Every
symptom below was reproduced on purpose, and the fix shown was the one that
cleared it.

## Nothing appears when it boots

Bhaskix speaks on the **serial console**. If QEMU has no serial console in your
terminal, the machine boots and you see nothing at all:

```
$ timeout 40 qemu-system-x86_64 -M q35 -cpu max -smp 4 -m 512M -display none -cdrom bhaskix.iso
qemu-system-x86_64: terminating on signal 15 from pid 646085 (timeout)
```

Forty seconds of a machine booting, and the only line is QEMU's own when
`timeout` ended it. Give it one: `-serial mon:stdio`, as these pages do. Plain
`-serial stdio` shows the output too, but then `Ctrl-A x` cannot reach QEMU (next
section).

## `Ctrl-A x` does nothing

`Ctrl-A x` is QEMU's monitor key. It works only when the console is
`-serial mon:stdio`; with `-serial stdio`, the keys go to Bhaskix instead. From
another terminal, `pkill qemu-system-x86` ends it either way — the process's
name is cut to fifteen characters, which is why it stops at `x86` — or close the
terminal.

## QEMU cannot find the UEFI firmware

The firmware files are named differently from one distribution, and one release,
to the next:

```
$ ls /usr/share/OVMF/        # Ubuntu 20.04
OVMF_CODE_4M.fd OVMF_CODE_4M.ms.fd OVMF_CODE_4M.secboot.fd OVMF_CODE.fd OVMF_CODE.ms.fd OVMF_CODE.secboot.fd OVMF_VARS_4M.fd OVMF_VARS_4M.ms.fd OVMF_VARS.fd OVMF_VARS.ms.fd OVMF_VARS.snakeoil.fd
$ ls /usr/share/OVMF/        # Ubuntu 26.04
OVMF_CODE_4M.fd OVMF_CODE_4M.ms.fd OVMF_CODE_4M.secboot.fd OVMF_CODE_4M.snakeoil.fd OVMF_VARS_4M.fd OVMF_VARS_4M.ms.fd OVMF_VARS_4M.snakeoil.fd
```

**Ubuntu 26.04 has no `OVMF_CODE.fd` at all**, only the `_4M` pair — so a command
naming `OVMF_CODE.fd` fails there. Use whichever pair your system has:
`OVMF_CODE.fd` with `OVMF_VARS.fd`, or `OVMF_CODE_4M.fd` with `OVMF_VARS_4M.fd`.
On Debian and Ubuntu they come from the `ovmf` package.

## How long a boot takes

A boot to the prompt takes **about twenty to thirty seconds** in QEMU, and most
of it is the boot report — the machine checking itself. It is not raw
computation: on the machine these pages were checked on, **KVM made it slower,
not faster** (`-enable-kvm -cpu host` against plain emulation, the same ISO,
the same day):

```
emulated    boot cost      22530.475 ms to services up, console=domain vfs=domain
KVM         boot cost      32647.153 ms to services up, console=domain vfs=domain
```

So a boot that takes about half a minute is working as it should; one that
stops altogether is worth [reporting](#report-a-problem).

## A command answers `not a command`

Typed at the prompt, a command the shell does not have — `ps`, say — answers:

```
ps: not a command. Try 'help'.
```

The shell is Bhaskix's own, not `bash`, and it has its own commands; `help` lists
them, and [The shell and packages](shell-and-packages.md) explains each. Linux
programs run beside it, through the adapter: [Linux programs](linux-programs.md).

## QEMU says a port is busy

The fuller machine in [Get started](get-started.md) forwards host ports to the
guest. If another program — or a QEMU you did not end — already holds one, QEMU
refuses to start:

```
qemu-system-x86_64: Could not set up host forwarding rule 'tcp:127.0.0.1:18080-:8080'
```

End the other QEMU (`pkill qemu-system-x86`), or change the host port in the
command.

## Red lines in the boot report

Every line of the boot report is a check the machine just ran. A **red** line is
one that failed, and it says what it saw; a **yellow** one is a check this
machine could not make, and it says why — for example, one that needs a second
CPU on a machine started with one. Yellow is not a fault.

A red line on a release or on `main` is a bug worth reporting, whatever else
works.

## Report a problem

Open an issue on [GitHub](https://github.com/bhaskix/bhaskix/issues) with:

1. **what you booted** — the release and its `SHA256SUMS`, or the commit you
   built (`git rev-parse HEAD`);
2. **how** — the whole QEMU command, or the machine and how it was booted;
3. **the red lines**, copied whole, and the boot report around them (`dmesg` at
   the prompt shows it again, a page at a time).

A **security** problem is reported privately instead, as
[SECURITY.md](../../SECURITY.md) describes.
