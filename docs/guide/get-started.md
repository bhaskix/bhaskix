<!-- SPDX-License-Identifier: Apache-2.0 -->

# Get started

**Verified** 2026-10-19 against `9a87171`, under QEMU 4.2.1, by booting copies
of that commit's ISO and loader exactly as below and typing every command shown.

This guide boots Bhaskix in QEMU, tries its shell, and leaves. Expect about ten
minutes, most of it the first boot.

Bhaskix is a **developer preview**. It is not a product, and nothing here
should go near a machine you rely on — which QEMU guarantees, because
everything below happens inside an emulator. What it does not do yet is in the
[release note](../release-notes.md#what-it-does-not-do), stated as plainly as
what it does.

## What you need

- An x86-64 Linux machine.
- **QEMU** (`qemu-system-x86_64`). These steps were run with 4.2.1, and the
  project's CI uses 8.2.2.
- **OVMF**, the UEFI firmware QEMU boots with, for the two UEFI boots below.
- **xorriso**, for the boot through Bhaskix's own loader, to take two files off
  the ISO.

On Debian or Ubuntu:

```sh
sudo apt install qemu-system-x86 ovmf xorriso
```

## Download and check

From the [`v0.1.0-preview` release](https://github.com/bhaskix/bhaskix/releases)
on GitHub, download three files into one directory: `bhaskix.iso`,
`bhaskixboot.efi` and `SHA256SUMS`. Then:

```
$ sha256sum -c SHA256SUMS
bhaskix.iso: OK
bhaskixboot.efi: OK
```

**`OK` means the download is intact. It does not mean the files are genuine.**
They are not signed, and anyone able to replace a file could replace its sum
too. The release note says [why](../release-notes.md#what-it-does-not-do).

> **Before 29 November 2026** the release is not published yet. Build the same
> two files from source instead — `tools/setup-dev.sh`, then
> `make iso boot/bhaskixboot/target/x86_64-unknown-uefi/release/bhaskixboot.efi`
> — and find them at `build/bhaskix.iso` and
> `boot/bhaskixboot/target/x86_64-unknown-uefi/release/bhaskixboot.efi`.

## Boot it

Three ways. Each one ends at the same shell, and you only need one; the first
is the simplest.

### Under BIOS

```sh
qemu-system-x86_64 -M q35 -cpu max -smp 4 -m 512M -display none -serial mon:stdio \
    -cdrom bhaskix.iso
```

What the options do:
- `-serial mon:stdio` puts the machine's serial console in your terminal —
  that is where Bhaskix speaks and where you type — and lets `Ctrl-A` then `x`
  leave QEMU. **With plain `-serial stdio`, `Ctrl-A x` does nothing.**
- `-display none` opens no window; everything happens in the terminal.
- `-smp 4` gives the machine four CPUs. **With one CPU the boot still reaches
  the shell, but 34 of its self-tests report `skipped`**,
  because they need a CPU of their own.

### Under UEFI

OVMF keeps its settings in a file it writes to, so give it a copy:

```sh
cp /usr/share/OVMF/OVMF_VARS.fd vars.fd
qemu-system-x86_64 -M q35 -cpu max -smp 4 -m 512M -display none -serial mon:stdio \
    -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE.fd \
    -drive if=pflash,format=raw,file=vars.fd \
    -cdrom bhaskix.iso
```

The paths are Ubuntu 20.04's. A newer distribution may name the pair
`OVMF_CODE_4M.fd` and `OVMF_VARS_4M.fd`; use the two that match, since the
firmware refuses a code file and a settings file of different sizes. If QEMU
cannot open them, `ls /usr/share/OVMF` shows what yours are called.

### Through Bhaskix's own loader

The ISO boots through Limine, a bootloader the project did not write.
`bhaskixboot.efi` is Bhaskix's own: it loads the kernel, chooses where it lives
in memory, and starts it. It reads the kernel and its initial files from an EFI
system partition — here, a directory QEMU presents as one:

```sh
mkdir -p esp/EFI/BOOT esp/bhaskix
cp bhaskixboot.efi esp/EFI/BOOT/BOOTX64.EFI
xorriso -osirrox on -indev bhaskix.iso \
    -extract /boot/bhaskix esp/bhaskix/kernel \
    -extract /boot/initrd.tar esp/bhaskix/initrd.tar
cp /usr/share/OVMF/OVMF_VARS.fd vars.fd
qemu-system-x86_64 -M q35 -cpu max -smp 4 -m 512M -display none -serial mon:stdio \
    -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE.fd \
    -drive if=pflash,format=raw,file=vars.fd \
    -drive format=raw,file=fat:rw:esp
```

This is also the way to give the kernel options. The ISO's command line is
fixed, but the loader reads one from `esp/bhaskix/boot.conf`, a line of the form
`cmdline=<options>`. The other guides use it.

## What you will see

A banner, then the **boot report**: the machine testing itself, one line per
check, before it hands you anything. Every line is a claim it has just tested.
Through Bhaskix's own loader, a few `bhaskixboot:` lines come first, as it reads
the kernel and the initrd. Under BIOS it begins:

```

      ____  _   _    _    ____  _  _____  __
     | __ )| | | |  / \  / ___|| |/ /_ _| \ \/ /
     |  _ \| |_| | / _ \ \___ \| ' / | |   \  /
     | |_) |  _  |/ ___ \ ___) | . \ | |   /  \
     |____/|_| |_/_/   \_\____/|_|\_\___| /_/\_\

     भास्कर  —  the light-maker
     ज्ञानम् • गणितम् • सिद्धिः
     An open-source, AI-native, enterprise operating system,
     built from scratch, from India.

     Original author and developer   Tarun Kumar Kushwaha
     With thanks to                  Professor Pawan Kumar Mall
                                     Prince Komal Boonlia · Mayur Agnihotri
                                     Devesh Singh · Neha Mourya
                                     the StraightArc Team
     version 0.0.0  ·  x86_64  ·  Apache-2.0

  cpu
    gdt + tss      loaded (double fault and NMI on dedicated stacks)
    idt            loaded (256 vectors)
    features       apic yes  x2apic  NO  nx yes  smep yes  smap yes
                   umip  NO  la57 yes  invariant-tsc  NO  rdrand yes  pat yes  mtrr yes
    paging         4-level, on purpose; la57 stays a capability, not a mode
    unpredictable  two draws differ, and the machine reports rdrand
    local apic     enabled, timer calibrated to 62.615 MHz
    interrupts     ENABLED, timer at 100 Hz
…
```

and runs for about 400 lines. A line that reads `FAILED` is a
defect; please [report it](https://github.com/bhaskix/bhaskix/issues). None did
in these runs.

**Fourteen lines say `skipped`, each with its reason**, and on this machine
that is correct rather than a fault. The QEMU command above gives Bhaskix no
disk, and no network card it may use: Bhaskix lets a device reach memory only
through an IOMMU that contains it, and this command gives it none. So the
filesystem and network self-tests say what they would have needed and stop.
BusyBox says it is not in this image; the release leaves it out (see
[*Linux programs*](linux-programs.md)). The other guides add a disk and a network.

It ends at the shell:

```
…
  Bring-up complete. Nothing left to do at this milestone.

  a user-mode shell. 'help' lists what it can do.
bhaskix$
```

Under QEMU 4.2.1 on this project's machine, with four CPUs, the prompt
arrived **23 seconds** after QEMU started under BIOS, **33** under UEFI and
**29** through Bhaskix's own loader — while the machine was busy with other work.
Emulation is slow, and your time will differ.

## Your first commands

This shell runs in ring 3, outside the kernel, and **can do nothing it does not
hold a capability for**. There is no `root` and no `sudo`; there is what this
program was given.

`help` lists what it can do:

```
bhaskix$ help
  commands
    help              this list
    echo <words>      print the arguments
    ls [path]         list a directory
    cat <path>        print a file
    open <name>       resolve one name in the directory held -- no paths,
                      no '..'; also maps the page the service lends
    held              print what the page lent by 'open' begins with
    release           give back the page 'open' was lent, and prove it
                      cannot be mapped again
    ask               ask the block service for a capability, and be
                      refused it until a slot is declared for it
    caps              what this program is allowed to do
    input             what arrived on the console, and from where
    irq               wait for a signal, and report the badge it carried
    net <host>        speak to a host through the network service
    map               map memory this program holds, and be refused what it does not
    spawn <path>      start a program in a domain of its own
    pkg install <f>   install a package onto the writable filesystem
    pkg list          what is installed
    pkg run <n>       start an installed program, grants from its manifest
    pkg remove <n>    remove an installed package
    dmesg             print what the kernel printed while booting, a
                      page at a time (q quits) --
                      the bytes themselves, in order, not a log with
                      priorities or timestamps
    exit              end this shell

  this shell runs in ring 3 and can do nothing it does not hold a
  capability for. 'caps' lists them. one of them creates domains,
  and the envelope allows exactly one -- so a second 'spawn' is
  refused for the budget rather than for the authority.
```

`ls /` lists the boot image's files, which the shell reaches read-only through
its `files` capability:

```
bhaskix$ ls /
       228  README
         0  bin/
         0  etc/
    131072  fs.img
     20480  greedy.bpk
     20480  hello.bpk
        31  hello.txt
        79  motd
         0  packages/
```

`cat` prints one of them:

```
bhaskix$ cat etc/hostname
bhaskix
```

`caps` is the shell's authority, slot by slot. A program cannot read the list
of what it holds — there is no call for that, on purpose — so `caps` asks each
slot a question no service answers, and reports what the kernel says:

```
bhaskix$ caps
  0  console   reachable
  1  files     reachable
  2  (nothing) no authority
  8  directory no authority
  1  badge     can be passed on, and cannot be changed by its holder
  10 stale dir status 2
```

Line by line:
- **0 and 1** are what this shell holds on this machine: the console, and the
  boot image's files.
- **2** is empty on purpose. Its refusal comes from the kernel before any
  service is reached, which is what *no authority* looks like.
- **8 and 10** belong to the filesystem service, which needs a disk this machine
  does not have, so they are empty too. Slot 10's `status 2` is the same "no such
  capability" answer, printed as a number.
- The **badge** line is two attempts: passing the `files` capability on, which
  works, and changing the badge the kernel stamped on it, which the kernel
  refuses.

`pkg list` shows what is installed — or, here, why it cannot. Packages live on
a disk, this machine has none, and so the shell holds nothing in that slot and
says so:

```
bhaskix$ pkg list
  pkg list: no authority -- nothing in that slot
```

`dmesg` shows the boot report again, a page at a time; `q` stops it.

## Leave

Press `Ctrl-A`, then `x`. QEMU ends at once.

Nothing persists from the ISO boots: the machine had no disk, and its memory
went with it. Two files remain in your directory — `vars.fd`, OVMF's settings,
and `esp/`, the loader's partition — and you can delete both.

## A fuller machine: a disk and a network

The machine above has no disk and no network card Bhaskix may use. [*The shell
and packages*](shell-and-packages.md) and [*Linux programs*](linux-programs.md) need both, and this is the machine they use.

**It needs an IOMMU.** Bhaskix lets a device reach memory only through an IOMMU
that contains it, and refuses a disk or a network card it cannot contain — which
is why the machine above has neither. QEMU provides one with
`-device intel-iommu`.

**Its disks are made the way the project's own tests make theirs.** Each begins
with a marker that the boot's self-tests read back, and a disk without its
marker is reported as a `FAILED` check: this preview's self-tests were written
against these disks, and say so rather than guess. Two small files:

```sh
printf 'BHASKIX-DOMAIN-DISK-SECTOR-0' > domain.img && truncate -s 4M domain.img
printf 'BHASKIX-SATA-DISK-SECTOR-0' > sata.img && truncate -s 256K sata.img
```

`domain.img` holds the writable filesystem — packages are installed onto it,
and Linux programs write their files there. **Remake both files before every
boot.** Bhaskix formats `domain.img` each time it starts, so nothing written to
it survives a reboot, and the format writes over the marker — so the next boot,
on the same file, reports `block service FAILED`. `sata.img` sits on the SATA
controller, ahead of the loader's partition.

This machine boots through Bhaskix's own loader, from the `esp/` directory of
[*Through Bhaskix's own loader*](#through-bhaskixs-own-loader), and reads the
boot image a second time as a disk of its own:

```sh
cp esp/bhaskix/initrd.tar initrd.tar
cp /usr/share/OVMF/OVMF_VARS.fd vars.fd
qemu-system-x86_64 -M q35,kernel-irqchip=split -cpu max -smp 4 -m 512M \
    -display none -serial mon:stdio -no-reboot \
    -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE.fd \
    -drive if=pflash,format=raw,file=vars.fd \
    -device intel-iommu,intremap=on \
    -drive file=initrd.tar,format=raw,if=none,id=boot,readonly=on \
    -device virtio-blk-pci,drive=boot,disable-legacy=on,iommu_platform=on \
    -drive file=domain.img,format=raw,if=none,id=data \
    -device virtio-blk-pci,drive=data,disable-legacy=on,iommu_platform=on \
    -netdev user,id=net,restrict=on,guestfwd=tcp:10.0.2.100:9-cmd:cat,hostfwd=tcp:127.0.0.1:18080-:8080 \
    -device virtio-net-pci,netdev=net,disable-legacy=on,iommu_platform=on \
    -drive file=sata.img,format=raw,if=none,id=sata -device ide-hd,drive=sata,bus=ide.0 \
    -drive if=ide,index=2,format=raw,file=fat:rw:esp
```

What the new lines do:
- `kernel-irqchip=split` and `intel-iommu` give the machine its IOMMU.
- Two `virtio-blk` disks: the boot image, read-only, and `domain.img`. Each
  has `iommu_platform=on`, so the IOMMU stands between it and memory.
- One `virtio-net` card on QEMU's user network. `restrict=on` keeps the machine
  from reaching anything beyond your computer, apart from two openings:
  - `hostfwd` forwards your `127.0.0.1:18080` to the machine's port 8080, where
    *Linux programs* runs a web server. If 18080 is taken on your machine, QEMU
    refuses to start and says so; change the first number to a free port;
  - `guestfwd` hands a connection to `10.0.2.100:9` to `cat` on your machine,
    which sends every byte back. That is how that guide's server shows it can
    dial out.
- `sata.img` on the SATA controller's first port, and the loader's partition on
  its third.

It reaches `bhaskix$` with nothing `FAILED`, after about 36 seconds
here. Five lines say `skipped`: BusyBox, which this release leaves out, and tests that only the project's own test harness can complete, because they wait for a client it connects.

## If something goes wrong

- **QEMU cannot find `OVMF_CODE.fd`.** See *Under UEFI* above: your
  distribution names the files differently.
- **Nothing appears.** Check the command has `-serial mon:stdio`, not
  `-serial stdio`. Without a serial console in your terminal, Bhaskix has
  nowhere to speak.
- **`Ctrl-A x` does nothing.** The same cause: it needs `mon:stdio`.
- **A command answers `not a command`.** This shell does not have it; `help`
  lists what it has. It is not a Linux shell, so a command you know from Linux,
  such as `ps`, may not be here. Linux programs run beside it, through an
  adapter; [*Linux programs*](linux-programs.md) shows how.

Report anything else on [GitHub](https://github.com/bhaskix/bhaskix/issues).
Report a security problem privately, as
[SECURITY.md](../../SECURITY.md) describes.

## Next

- [*The shell and packages*](shell-and-packages.md): every command, what
  holding a capability means, and installing a package.
- [*Linux programs*](linux-programs.md): what runs, how to start it, and what
  is refused and why.
- The [release note](../release-notes.md): what this preview does, what it does
  not, and the defects it is known to have.
- The [roadmap](../roadmap.md): where it is going.
