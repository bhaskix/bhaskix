<!-- SPDX-License-Identifier: Apache-2.0 -->

# Sign your own boot

**Verified** 2026-10-29 against `579ab9b`, by running every command shown: part 1
under QEMU 4.2.1 on Ubuntu 20.04, part 2 on Ubuntu 26.04 — QEMU 10.2.1,
virt-firmware 25.12, sbsigntool 0.9.4 — in a container. Part 4 on 2026-11-01, by
`make test-boot-slots`, which runs its commands and boots each case under QEMU 4.2.1.
Part 5 on 2026-11-03, by `make test-boot-rollback`, the same way, with an emulated
TPM (swtpm 0.7.3); the same day, part 1's `sign` and `show` gained the security
version they print, read from a run of each.

Bhaskix's own loader, `bhaskixboot.efi`, checks a signature over the kernel, the
initrd and `boot.conf` before it starts them, and says what it found in the boot
report ([RFC 0091](../rfc/0091-a-boot-its-owner-signed.md)). With **Secure Boot**
on, the firmware checks the loader first, and the loader refuses a boot set that
fails its check. Together they mean that someone who can write to the disk cannot
change what boots.

**The project's own keys do not exist yet.** The developer preview's loader
trusts no key, and the first release signed by the project is the one after the
preview. Until then, the way to have a boot only you can change is to sign it
yourself, which is what this guide does. Expect half an hour, most of it builds.

## What you need

- A checkout of Bhaskix that builds (`make iso` works).
- **QEMU** and **OVMF**, as in [Get started](get-started.md).
- For part 2: **sbsigntool**, and to try it in QEMU, **virt-firmware**, which
  writes certificates into OVMF's variable store — Ubuntu 24.04 and 26.04
  package it as `python3-virt-firmware`; 20.04 does not.

Keep everything below **outside your checkout**. A key inside one is a `git add`
away from being published, and `bootsign` refuses to write one there.

## 1. Sign your boot set

Make a key. `bootsign` is the project's signer; it writes the key to
`~/.bhaskix-keys/`:

```sh
make bootsign
target/x86_64-unknown-linux-gnu/release/bootsign keygen
```

```
ok    key 50d55e1a47e6367e
      secret  /root/.bhaskix-keys/boot-50d55e1a47e6367e.secret
      public  /root/.bhaskix-keys/boot-50d55e1a47e6367e.public
```

Your id will differ: a key is made fresh each time.

Build a loader that trusts that key and no other. `BHASKIX_BOOT_KEYS` names the
public half it compiles in:

```sh
KEY=~/.bhaskix-keys/boot-50d55e1a47e6367e     # the id keygen printed
(cd boot/bhaskixboot && BHASKIX_BOOT_KEYS=$KEY.public \
    CARGO_TARGET_DIR=$HOME/bhaskix-my-loader cargo build --release --target x86_64-unknown-uefi)
```

Put it on an EFI system partition with the kernel and initrd your checkout built,
then sign the three files the loader checks:

```sh
make iso
ESP=~/bhaskix-esp
mkdir -p $ESP/EFI/BOOT $ESP/bhaskix
cp ~/bhaskix-my-loader/x86_64-unknown-uefi/release/bhaskixboot.efi $ESP/EFI/BOOT/BOOTX64.EFI
cp target/x86_64-unknown-none/release/bhaskix $ESP/bhaskix/kernel
cp build/initrd.tar $ESP/bhaskix/initrd.tar
printf 'cmdline=\n' > $ESP/bhaskix/boot.conf
target/x86_64-unknown-linux-gnu/release/bootsign sign --key $KEY.secret $ESP
target/x86_64-unknown-linux-gnu/release/bootsign show $ESP --public $KEY.public
```

```
ok    signed /root/bhaskix-esp/bhaskix/boot.sig with key 50d55e1a47e6367e, security version 0
      verified before writing, with the loader's own check
      boot.sig   key 50d55e1a47e6367e
      version    0
      kernel     ee039c6b29e3b9215a55d173c77bd200509693af9a98697980b8c56ae39aec71 matches
      initrd.tar 7e5b0cedd75a2091e17820ca2f11160caf6be3b8d4b0431c68213fb8714e5a95 matches
      boot.conf  39ace9f01dd14d7ca44d7f89dce168638b2358520e914c738eab42759fc027d6 matches
ok    verified: key 50d55e1a47e6367e
```

`show` is what the loader will decide, asked in advance. Boot it as
[Get started](get-started.md) boots the loader, with Secure Boot off:

```sh
cp /usr/share/OVMF/OVMF_VARS.fd vars.fd
qemu-system-x86_64 -M q35 -cpu max -smp 4 -m 512M -display none -serial mon:stdio \
    -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE.fd \
    -drive if=pflash,format=raw,file=vars.fd \
    -drive format=raw,file=fat:rw:$ESP
```

The loader says what it decided before it starts the kernel, and the boot report
says it again, in red:

```
bhaskixboot: SecureBoot reads 0 -- nothing verified this loader
bhaskixboot: boot signature verified: key 50d55e1a47e6367e, NOT ENFORCED: Secure Boot is off
…
    boot signature  verified: key 50d55e1a47e6367e, but NOT ENFORCED: Secure Boot is off
```

**Verified, and in red**, because nothing enforces it: with Secure Boot off,
anyone who can write the disk can replace the loader too, and a replaced loader
checks nothing. Change one byte of the kernel and boot again, and the loader
still boots it, saying why it should not have — the developer's state, stated
plainly:

```
    boot signature  NOT VERIFIED (the kernel is not the one boot.sig names), NOT ENFORCED: Secure Boot is off
```

## 2. Enforce it with Secure Boot

The firmware checks the loader against the certificates in its `db` variable,
and only RSA-2048 with SHA-256 is certain to be accepted by every Secure Boot
firmware. Make a key and certificate for that, and sign your loader with it:

```sh
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 3650 -subj "/CN=My Bhaskix boot" \
    -keyout ~/.bhaskix-keys/db.key -out ~/.bhaskix-keys/db.pem
sbsign --key ~/.bhaskix-keys/db.key --cert ~/.bhaskix-keys/db.pem \
    --output $ESP/EFI/BOOT/BOOTX64.EFI $ESP/EFI/BOOT/BOOTX64.EFI
```

**On a real machine**, enrol `db.pem` in `db` through the firmware's setup
screen, keeping every entry already there so the machine's own operating system
still boots, then turn Secure Boot on. Whether your firmware can append a
certificate from a USB stick, and whether it appends or replaces, is the
vendor's; check before you save. **This part has not been run on physical
hardware**: the project's own test of a physical machine is RFC 0091's step 7,
still to come.

**In QEMU**, write a variable store with your certificate enrolled and Secure
Boot on, and boot with OVMF's Secure Boot build:

```sh
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 3650 -subj "/CN=My platform" \
    -keyout pk.key -out pk.pem
G=$(cat /proc/sys/kernel/random/uuid)
virt-fw-vars --input /usr/share/OVMF/OVMF_VARS_4M.fd --output sb-vars.fd \
    --set-pk $G pk.pem --add-kek $G pk.pem --add-db $G ~/.bhaskix-keys/db.pem --no-microsoft --sb
qemu-system-x86_64 -M q35,smm=on -global driver=cfi.pflash01,property=secure,value=on \
    -cpu max -smp 4 -m 512M -display none -serial mon:stdio \
    -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.secboot.fd \
    -drive if=pflash,format=raw,file=sb-vars.fd \
    -drive format=raw,file=fat:rw:$ESP
```

```
bhaskixboot: SecureBoot reads 1 -- the firmware verified this loader
bhaskixboot: boot signature verified: key 50d55e1a47e6367e, Secure Boot on
…
    boot signature  verified: key 50d55e1a47e6367e, Secure Boot on
```

**Green.** Now change a byte of the kernel and boot again: the loader refuses,
says why on the screen, and hands the machine back to the firmware:

```
bhaskixboot: refusing to boot: the kernel is not the one boot.sig names (Secure Boot is on)
bhaskixboot: returning to the boot manager in 5 seconds
```

Replace the loader with one you did not sign, and the firmware refuses it before
it says a word:

```
BdsDxe: failed to load Boot0002 "UEFI QEMU HARDDISK QM00001 " from PciRoot(0x0)/Pci(0x1F,0x2)/Sata(0x0,0xFFFF,0x0): Access Denied -- rejected probably by Secure Boot
```

## 3. The project's certificate — with the first signed release

When the project signs a release, it will publish its CA certificate,
`bhaskix-secure-boot-ca.der`, and that certificate's SHA-256 fingerprint. Enrol
it in `db` as in part 2, after checking the fingerprint against the one in the
release note, and the project's signed loader and boot set will boot with
Secure Boot on. **Not yet**: the developer preview is unsigned, by decision, and
this part is written now so it is not a surprise later. How the project keeps
its keys is [GOVERNANCE.md](../../GOVERNANCE.md) §5.

## 4. Two slots, and falling back

Since 2026-11-01 the loader can boot from a **slot disk**: a second disk holding
two complete boot sets, A and B, and a one-block record saying which is active
and which, if any, is on trial. A set that does not verify is passed over for
the other slot, in the same boot. It is step 1 of
[RFC 0100](../rfc/0100-an-update-that-cannot-go-back.md): nothing in the running
system writes a slot yet, so a script stands in.

Sign two sets as in part 1, each in its own directory's `bhaskix/`, then build
the disk and put B on trial for two boots:

```sh
python3 tools/slot-disk.py make slots.img --a set-a/bhaskix --b set-b/bhaskix
python3 tools/slot-disk.py record slots.img --active a --trial b --tries 2
```

Boot as in part 1 with one more drive, `-drive if=ide,index=3,format=raw,file=slots.img`.
The loader says what it found and what it chose, and **spends a trial's boot
before taking it**, so a set that hangs cannot be tried for ever:

```
bhaskixboot: slot record: A active, B on trial with 2 boot(s) left, 1 write(s)
bhaskixboot: booting slot B on trial; 1 boot(s) left after this one
bhaskixboot: slot record written
bhaskixboot: boot signature verified: key a6c913d8a0e2476e TEST KEY, NOT ENFORCED: Secure Boot is off
```

After two such boots the trial is over and A boots again. A slot whose set does
not verify is refused and the other booted:

```
bhaskixboot: boot signature NOT VERIFIED (the kernel is not the one boot.sig names), NOT ENFORCED: Secure Boot is off -- not booted: the other slot is tried
bhaskixboot: slot B's set did not verify; falling back to slot A
```

`python3 tools/slot-disk.py show slots.img` reads the record back. The record
is the only block the loader ever writes; a damaged record is not believed, A
is tried, then B, and nothing is written.

## 5. A counter that refuses an older set

Since 2026-11-03 a set carries a **security version**, and a machine with a TPM
and a slot disk keeps a **rollback counter** in the TPM: once a set at version
`v` has been booted as the active slot, every set below `v` is refused, however
genuinely signed. It is step 2 of RFC 0100.

Give a set its version when you sign it, from 0 (the default, no version) to 64:

```sh
bootsign sign --key ~/.bhaskix-keys/boot-<id>.secret --security-version 2 set-b
```

Raise it only for a set that fixes something an older set must never be booted
again to undo: the counter only rises, and nothing short of deleting it from the
TPM lowers it.

The first boot that finds a slot disk on a machine with a TPM creates the
counter; a loader that finds no slot disk never writes to the TPM. The counter
moves only for the **active** slot's set, when it is verified and newer than the
counter -- a trial does not move it -- and the loader then locks it until the
next restart and proves the lock:

```
bhaskixboot: the TPM's owner has NO PASSWORD: anything that can command this TPM can delete the counter
bhaskixboot: rollback counter: at 1; a set below that version is refused
bhaskixboot: security version 2; the rollback counter is at 1
bhaskixboot: rollback counter: advanced to 2, the version of the set marked good
bhaskixboot: rollback counter: locked until the next restart, and a write was refused (TPM_RC_NV_LOCKED)
```

An older set is refused as a set that did not verify is, and the other slot is
tried in the same boot:

```
bhaskixboot: boot signature NOT VERIFIED (the set is signed, and older than the rollback counter allows), NOT ENFORCED: Secure Boot is off -- not booted: the other slot is tried
bhaskixboot: security version 1 is below the rollback counter's 2: an older set, signed and refused
bhaskixboot: slot A's set did not verify; falling back to slot B
```

The set on the ESP is held to the counter too, so removing the slot disk is no
way around it. With Secure Boot off, a refused set still boots and says so, as
an unsigned one does; with it on, it is refused. A machine with a slot disk and
no TPM boots and says, in capitals, `NO ROLLBACK COUNTER: no TPM -- an older
signed set would boot`.

## What this does not protect against

- ~~**An older boot set you signed.** It still verifies, from the ESP or from a
  slot; refusing old ones needs a rollback counter the project has not built
  (RFC 0100 step 2).~~ **Since 2026-11-03, on a machine with a TPM and a slot
  disk, it does** (part 5). Without a TPM, or before the first boot with a slot
  disk, an older signed set still verifies.
- **Someone who can command your TPM, if its owner has no password.** They can
  delete the counter, and its history with it. The loader says which kind of TPM
  it is on; set an owner password to close this. And before the loader locks the
  counter, another loader booted on the machine could set its bits and make it
  refuse your sets -- Secure Boot is what keeps other loaders out.
- **The firmware itself**, or anyone who can put it in setup mode. Then
  `SecureBoot` reads 0, the report says *not enforced*, and the TPM's PCR 7
  records the change: noticed, not prevented.
- **Your keys.** Whoever has `boot-….secret` and `db.key` can sign a boot your
  machine accepts. Keep them off the machine they protect.
