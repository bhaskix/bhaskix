<!-- SPDX-License-Identifier: Apache-2.0 -->

# Run it on a real machine

**Verified** 2026-10-30 against `aa2dcc5`: the USB boots under QEMU 4.2.1 on Ubuntu 20.04, and the
SR550 boot on that machine the same day, by running every command shown.

**There is no installer.** Nothing in Bhaskix writes it to a disk or changes how
a machine boots: it starts from a USB stick, a server's virtual CD, or an EFI
partition you prepare, runs from memory, and when you switch the machine off it
is gone. This page says how to start it on real hardware, what has been tried,
and what has not.

## Before you start: what it writes

**Since 2026-10-30, a boot writes to no disk but the project's own**: the SATA
test disk the project's tests use, recognised by a marker in its first sector,
and a disk that already carries Bhaskix's own filesystem, recognised by its
superblock. Any other disk is read — its first sector, to identify it — and never
written. A lane boots a machine with a foreign SATA disk on every run of the
suite and checks that its last sector is unchanged.

**Builds from before 2026-10-30 are not safe on a machine whose disks you care
about**: their SATA driver wrote a test pattern into the last sector of any disk
it found, which on a GPT disk is the backup partition table. Use a build from
that date or later.

Even so, this is a developer preview. **Use a machine whose disks hold nothing
you need**, or remove them.

## What you need

- An **x86-64** machine with **UEFI or BIOS** firmware. Bhaskix has run on
  between 256 MiB and 192 GiB of memory, and on up to sixteen CPU threads.
- **A way to read what it says.** Bhaskix writes its boot report to the screen
  and to both serial ports. A server's serial-over-LAN or its remote console is
  the easiest; a monitor works on a desktop.
- A **USB stick** you can erase, or a server with a BMC that can mount an ISO
  as a virtual CD.

## From a USB stick

Write the ISO to the stick. **This erases the stick**; check the device name
twice — `lsblk` lists them, and the stick is the one whose size you recognise:

```sh
sudo dd if=bhaskix.iso of=/dev/sdX bs=4M conv=fsync status=progress
```

Then boot from the stick through your firmware's boot menu (often F12, F11 or
Esc at power-on). The same image boots under BIOS and under UEFI, through
Limine; the UEFI boot below added OVMF's two `-drive if=pflash` lines to the
same command.

**This has not been tried on a physical stick.** It was verified by attaching
the written image to QEMU as a USB disk, under both firmwares, and booting it to
the shell:

```
$ dd if=bhaskix.iso of=stick.img bs=4M conv=fsync status=none
$ qemu-system-x86_64 -M q35 -m 512M -smp 4 -display none -serial file:usb.txt -no-reboot \
    -device qemu-xhci,id=xhci -drive if=none,id=stick,format=raw,file=stick.img \
    -device usb-storage,bus=xhci.0,drive=stick
$ grep -a -e 'boot cost' -e 'Bring-up' -e '^bhaskix' usb.txt
    boot cost      22544.599 ms to services up, console=domain vfs=domain
  Bring-up complete. Nothing left to do at this milestone.
bhaskix$
```

## Through Bhaskix's own loader

`bhaskixboot.efi`, Bhaskix's own UEFI loader, boots from an EFI system
partition holding it and the boot set — the same files [Get started](get-started.md)
puts in a directory for QEMU. For a real machine, `tools/native-iso.sh` in the
source tree builds them into an image a server's BMC can mount as a virtual CD:

```sh
make iso bootsign boot/bhaskixboot/target/x86_64-unknown-uefi/release/bhaskixboot.efi
tools/native-iso.sh build/bhaskix-native.iso
```

It is how the project boots its one physical test machine, a Lenovo
ThinkSystem SR550. On 2026-10-31, mounted through its BMC and booted once with
Secure Boot off, its initrd carrying the x86-64-v3 BusyBox, it said over
serial-over-LAN:

```
bhaskixboot 0.0.0: the machine entered through our own door
bhaskixboot 0.0.0: the machine entered through our own door
bhaskixboot: console adopted; diagnostics go to both
bhaskixboot: opening the boot volume
bhaskixboot: allocating the kernel buffer
bhaskixboot: the command line is empty; not measured
bhaskixboot: SecureBoot reads 0 -- nothing verified this loader
bhaskixboot: boot set hashed and checked: 16878408 bytes in 294217958 ticks, ~140 ms at 2095410 ticks/ms
bhaskixboot: boot signature verified: key a6c913d8a0e2476e TEST KEY, NOT ENFORCED: Secure Boot is off
bhaskixboot: memory map 45 descriptors, 200493232 KiB usable, 359192 KiB reclaimable; truncated: no
bhaskixboot: boot services exited; the machine is ours
…
    xstate         offered x87 sse avx bndregs bndcsr opmask zmm_hi256 hi16_zmm pkru (0x2ff, 2696 bytes for all); enabled x87 sse avx (0x7), 832 bytes, saved by xsaveopt; CR4.OSXSAVE at entry 0
…
    boot cost      79939.113 ms to services up, console=domain vfs=domain
  Bring-up complete. Nothing left to do at this milestone.
  a user-mode shell. 'help' lists what it can do.
bhaskix$
```

The image's boot set is signed with the project's **published test key**, so the
check passes and says, in red, that anyone could have signed it. To have a boot
only you can change, sign it yourself: [Sign your own boot](secure-boot.md).

## What hardware is known

| Machine | What works | What does not |
|---|---|---|
| Lenovo ThinkSystem SR550, one Xeon Silver 4110, 192 GiB | Boots to its shell through Limine (since 2026-08-22) and through its own loader (since 2026-10-11); its IOMMU confines every device; its TPM 2.0 records the boot; AVX is enabled and each program's vector registers, the upper halves of `ymm` included, are kept across switches and signals, and an x86-64-v3 BusyBox runs (read 2026-10-31); the keyboard through the BMC's remote console | Its disks sit behind a RAID 530-8i adapter Bhaskix does not drive; nothing is attached to its onboard SATA; its X722 network answers a ping but gets no address and opens no TCP connection; the USB keyboard port does not complete enumeration |
| QEMU (`q35`, from 4.2.1 to 10.2.1) | Everything the project's tests check | — |

No other physical machine has been tried. If you boot one, the boot report says
what it found; [reporting it](troubleshooting.md#report-a-problem) helps.

## Give the machine back

Switch it off, remove the stick or unmount the virtual CD, and boot as before.
Bhaskix changed no boot entry, wrote no partition, and kept nothing.
