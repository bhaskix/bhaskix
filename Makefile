# SPDX-License-Identifier: Apache-2.0
#
# Bhaskix build system.
#
#   make            build the kernel and a bootable ISO
#   make run        boot it in QEMU (BIOS)
#   make run-uefi   boot it in QEMU (UEFI, via OVMF)
#   make test       everything CI runs: host tests, boot tests, and all gates
#
# Requires the toolchain installed by tools/setup-dev.sh.

SHELL := /bin/bash
.DEFAULT_GOAL := all

CARGO        ?= cargo
QEMU         ?= qemu-system-x86_64
PROFILE      ?= release
TARGET       := x86_64-unknown-none
HOST_TARGET  := x86_64-unknown-linux-gnu

KERNEL       := target/$(TARGET)/$(PROFILE)/bhaskix
ISO          := build/bhaskix.iso
ISO_ROOT     := build/iso_root
INITRD       := build/initrd.tar
# A second disk, for the block driver that runs in a domain. Its own device and
# its own image: two drivers on one device would be a disaster, and a domain
# driver reading the *kernel's* disk would not show that it had read anything
# the kernel did not hand it.
DOMAIN_DISK  := build/domain-disk.img
# An image in the new on-disk format, carried *inside* the archive -- which is
# what makes RFC 0015 step 3's "beside the archive" literal. The machine mounts
# both and reads a file from each.
FS_IMAGE     := build/fs.img
MKFS         := target/$(HOST_TARGET)/release/mkfs
# The image assembler (RFC 0030 step 2): the initrd as a function of the
# package set. Built like mkfs -- a host binary behind a feature.
MKIMAGE      := target/$(HOST_TARGET)/release/mkimage
PACKAGES     := $(wildcard packages/*.manifest.in)
INITRD_DIR   := initrd
INITRD_ROOT  := build/initrd_root
LIMINE_DIR   := boot/limine/limine

# The ring 3 probe: a real program, built separately from the kernel and put
# into the initrd for the kernel to find, parse and load. It is not a workspace
# member — it needs its own code-generation settings, which a member cannot
# have (see user/probe/Cargo.toml).
PROBE_DIR    := user/probe
PROBE        := $(PROBE_DIR)/target/$(TARGET)/release/probe
SHELL_DIR    := user/shell
VFSD_DIR     := user/vfsd
CONSOLED_DIR := user/consoled
BLKD_DIR     := user/blkd
NETD_DIR     := user/netd
IPD_DIR      := user/ipd
DHCPD_DIR    := user/dhcp
UDP6_DIR     := user/udp6
TCPD_DIR     := user/tcpd
LINUXD_DIR   := user/linuxd
TCPC_DIR     := user/tcpc
TRACED_DIR   := user/traced
FSD_DIR      := user/fsd
SUP_DIR      := user/sup
# RFC 0030 step 3's demonstration payload: built like every user program,
# shipped as a .bpk rather than a line in the image.
HELLO_DIR    := user/hello
HELLO        := $(HELLO_DIR)/target/$(TARGET)/release/hello
HELLO_BPK    := build/hello.bpk
# RFC 0005 step 7: the Tier 0 corpus. A real static Go binary, built with
# the toolchain on this machine, carried into the image and loaded by the
# kernel's own ELF loader into a Linux-tagged domain. Built only if `go` is
# present -- a contributor without it still builds everything else, and the
# boot test says the corpus is absent rather than failing.
GO           := $(shell command -v go 2>/dev/null)
GO_HELLO     := build/go-hello
GREEDY_BPK   := build/greedy.bpk
USER_SHELL   := $(SHELL_DIR)/target/$(TARGET)/release/shell
USER_SUP     := $(SUP_DIR)/target/$(TARGET)/release/sup
USER_VFSD    := $(VFSD_DIR)/target/$(TARGET)/release/vfsd
USER_CONSOLED := $(CONSOLED_DIR)/target/$(TARGET)/release/consoled
USER_BLKD    := $(BLKD_DIR)/target/$(TARGET)/release/blkd
USER_NETD    := $(NETD_DIR)/target/$(TARGET)/release/netd
USER_IPD     := $(IPD_DIR)/target/$(TARGET)/release/ipd
USER_DHCPD   := $(DHCPD_DIR)/target/$(TARGET)/release/dhcp
USER_UDP6    := $(UDP6_DIR)/target/$(TARGET)/release/udp6
USER_TCPD    := $(TCPD_DIR)/target/$(TARGET)/release/tcpd
USER_LINUXD  := $(LINUXD_DIR)/target/$(TARGET)/release/linuxd
USER_TCPC    := $(TCPC_DIR)/target/$(TARGET)/release/tcpc
USER_TRACED  := $(TRACED_DIR)/target/$(TARGET)/release/traced
BOOTEFI_DIR  := boot/bhaskixboot
BOOTEFI      := $(BOOTEFI_DIR)/target/x86_64-unknown-uefi/release/bhaskixboot.efi
USER_FSD     := $(FSD_DIR)/target/$(TARGET)/release/fsd
# `RUSTFLAGS` in the environment *replaces* the workspace's `.cargo/config.toml`
# flags rather than adding to them, which is exactly what is wanted here: the
# kernel's PIC/kernel-code-model settings are wrong for a user program linked
# at a fixed low address.
PROBE_FLAGS  := -C relocation-model=static -C code-model=small \
                -C link-arg=-T$(CURDIR)/$(PROBE_DIR)/link.ld
SHELL_FLAGS  := -C relocation-model=static -C code-model=small \
                -C link-arg=-T$(CURDIR)/$(SHELL_DIR)/link.ld
VFSD_FLAGS   := -C relocation-model=static -C code-model=small \
                -C link-arg=-T$(CURDIR)/$(VFSD_DIR)/link.ld
# The supervisor, which RFC 0017 question 2 asked for: same shape as the rest,
# its own linker script because it says where it goes.
SUP_FLAGS    := -C relocation-model=static -C code-model=small \
                -C link-arg=-T$(CURDIR)/$(SUP_DIR)/link.ld
CONSOLED_FLAGS := -C relocation-model=static -C code-model=small \
                -C link-arg=-T$(CURDIR)/$(CONSOLED_DIR)/link.ld
BLKD_FLAGS   := -C relocation-model=static -C code-model=small \
                -C link-arg=-T$(CURDIR)/$(BLKD_DIR)/link.ld
NETD_FLAGS   := -C relocation-model=static -C code-model=small \
                -C link-arg=-T$(CURDIR)/$(NETD_DIR)/link.ld
IPD_FLAGS    := -C relocation-model=static -C code-model=small \
                -C link-arg=-T$(CURDIR)/$(IPD_DIR)/link.ld
DHCPD_FLAGS  := -C relocation-model=static -C code-model=small \
                -C link-arg=-T$(CURDIR)/$(DHCPD_DIR)/link.ld
UDP6_FLAGS   := -C relocation-model=static -C code-model=small \
                -C link-arg=-T$(CURDIR)/$(UDP6_DIR)/link.ld
TCPD_FLAGS   := -C relocation-model=static -C code-model=small \
                -C link-arg=-T$(CURDIR)/$(TCPD_DIR)/link.ld
LINUXD_FLAGS := -C relocation-model=static -C code-model=small \
                -C link-arg=-T$(CURDIR)/$(LINUXD_DIR)/link.ld
TCPC_FLAGS   := -C relocation-model=static -C code-model=small \
                -C link-arg=-T$(CURDIR)/$(TCPC_DIR)/link.ld
TRACED_FLAGS := -C relocation-model=static -C code-model=small \
                -C link-arg=-T$(CURDIR)/$(TRACED_DIR)/link.ld
FSD_FLAGS    := -C relocation-model=static -C code-model=small \
                -C link-arg=-T$(CURDIR)/$(FSD_DIR)/link.ld

# 256 MiB is comfortably more than the kernel needs and small enough that the
# memory-map output stays readable.
QEMU_MEM     ?= 256M

# QEMU's default `qemu64` model predates x2APIC (2008) and SMEP, so it does not
# represent any machine Bhaskix targets. `max` exposes everything the host and
# TCG can offer, which is what a modern kernel should be developed against.
# Override to qemu64 to exercise the degraded no-x2APIC path.
QEMU_CPU     ?= max

# Kernel command line baked into the image. Used by the fault-injection tests
# to select which exception to trigger; empty for a normal boot.
CMDLINE      ?=

# The kernel command line is baked into the ISO, so the ISO has to depend on
# it. It did not, and the consequence was quiet: `make iso CMDLINE=...` with an
# unchanged kernel left the *previous* image in place, so every fault-injection
# case after the first booted the case before it. Different subsets failed on
# different runs, which reads as flakiness rather than as a stale artefact.
#
# The stamp is rewritten only when the value actually changes, so this forces a
# rebuild exactly when it should and never otherwise.
CMDLINE_STAMP := build/.cmdline
# The initial ramdisk, attached as a disk as well as loaded as a module. The
# same bytes in both places is deliberate: a test that reads the disk knows
# exactly what must come back, because the kernel already parsed it from
# somewhere else.
#
# `readonly=on` is not decoration. The kernel only reads this image, and QEMU's
# default is an *exclusive write lock* on the file — so two runs that overlap
# by a second, which is every `make test` on a loaded machine, fight over it
# and the loser starts with no disk. Read-only takes a shared lock instead.
QEMU_DISK    := -drive file=$(INITRD),format=raw,if=none,id=disk0,readonly=on \
                -device virtio-blk-pci,drive=disk0

QEMU_COMMON  := -M q35 -cpu $(QEMU_CPU) -m $(QEMU_MEM) -no-reboot -no-shutdown $(QEMU_DISK)

# OVMF ships as a CODE/VARS pair that must be size-matched -- a 4 MB CODE with
# a 2 MB VARS is rejected by the firmware, not by QEMU. Selected as a pair for
# the same reason tests/qemu/boot-test.sh does: searching independently finds a
# CODE on distributions that ship only the 4 MB layout, finds no VARS, and
# hands QEMU a nonexistent file.
OVMF_DIR     := $(dir $(firstword $(wildcard /usr/share/OVMF/OVMF_CODE_4M.fd \
                                             /usr/share/OVMF/OVMF_CODE.fd \
                                             /usr/share/edk2/ovmf/OVMF_CODE.fd)))
OVMF_SUFFIX  := $(if $(wildcard /usr/share/OVMF/OVMF_CODE_4M.fd),_4M,)
OVMF_CODE    := $(firstword $(wildcard $(OVMF_DIR)OVMF_CODE$(OVMF_SUFFIX).fd))
OVMF_VARS    := $(firstword $(wildcard $(OVMF_DIR)OVMF_VARS$(OVMF_SUFFIX).fd))

.PHONY: FORCE all kernel iso run run-uefi test test-host test-boot test-boot-uefi test-boot-iommu test-keyboard \
        test-boot-iommu-off test-boot-qemu64 test-boot-native test-boot-native-full \
        test-placements mkfs test-shell test-faults fmt clippy gates clean distclean help

all: iso

# --- build ---------------------------------------------------------------

kernel:
	$(CARGO) build --profile $(PROFILE) --target $(TARGET)

iso: $(ISO)

# Eight sectors, with something in the first that only this disk has. The
# domain driver reads sector 0 and reports what it found, and the kernel asks
# the block *service* for the same sector and compares -- so a driver that
# returned zeroes, or the other disk's bytes, is visible rather than plausible.
# Eight rather than one because a device with a single sector has no sector a
# test can be wrong about.
$(MKFS): $(wildcard fs/src/*.rs) $(wildcard fs/src/bin/*.rs) fs/Cargo.toml
	$(CARGO) build --release --target $(HOST_TARGET) -p bhaskix-fs --features tool
	@echo "built $@"

$(MKIMAGE): $(wildcard pkg/src/*.rs) $(wildcard pkg/src/bin/*.rs) pkg/Cargo.toml
	$(CARGO) build --release --target $(HOST_TARGET) -p bhaskix-pkg --features tool
	@echo "built $@"

# The image, with one file whose contents nothing else on the machine has. A
# format that reads back its own zeroes would look identical to one that works.
$(FS_IMAGE): $(MKFS) $(INITRD_DIR)/etc/hostname
	@mkdir -p $(dir $@)
	@printf 'a file in a filesystem this kernel defined\n' > build/fs-greeting.txt
	@printf 'only reachable through the subdirectory\n' > build/fs-inner.txt
	@./$(MKFS) $@ 32 greeting=build/fs-greeting.txt hostname=$(INITRD_DIR)/etc/hostname \
	    sub/inner=build/fs-inner.txt

# 256 KiB, where it used to be one page. Large enough to hold a filesystem in
# this kernel's own format, which is what RFC 0016 step 3 needs: until now the
# journal has only ever been exercised against an array in memory, and a disk
# with room for one block could not change that.
#
# Regenerated by the test scripts before every run, because the disk is now
# *written to*. A fixture a test mutates is a fixture whose next run starts
# somewhere nobody chose.
$(DOMAIN_DISK):
	@mkdir -p $(dir $@)
	@printf 'BHASKIX-DOMAIN-DISK-SECTOR-0' > $@
	@dd if=/dev/zero bs=1 count=262116 >> $@ 2>/dev/null
	@echo "built $@"

# Depends on the phony `kernel` target directly, so the image is rebuilt every
# time rather than when make believes the ELF changed. Regenerating costs under
# a second; testing a stale image costs an afternoon of chasing a bug that was
# already fixed. In kernel work that trade is not close.
$(CMDLINE_STAMP): FORCE
	@mkdir -p $(dir $@)
	@printf '%s\n' '$(CMDLINE)' | cmp -s - $@ || printf '%s\n' '$(CMDLINE)' > $@

FORCE:

# The initial ramdisk. `ustar` explicitly rather than whatever the local tar
# defaults to: GNU tar emits its own extensions for long names and large
# files, and the kernel's parser implements the documented format rather than
# one vendor's superset. Sorted, so the archive is byte-identical for the same
# inputs and a rebuild does not change the image for no reason.
# RFC 0030 step 2: the image is a function of the package set. The cp list
# that lived here through fourteen programs retired on 2026-08-18; each
# program's payload path and its authority now live in packages/*.manifest.in,
# and mkimage stages, hashes, verifies with the machine's own parsers, and
# drives the same tar flags this rule always trusted. Assembled twice and
# byte-compared every build: determinism is a gate, not a hope.
$(INITRD): $(MKIMAGE) $(shell find $(INITRD_DIR) packages -type f 2>/dev/null | sort) $(PROBE) $(USER_SHELL) $(USER_VFSD) $(USER_CONSOLED) $(USER_BLKD) $(USER_NETD) $(USER_IPD) $(USER_DHCPD) $(USER_UDP6) $(USER_TCPD) $(USER_LINUXD) $(USER_TCPC) $(USER_TRACED) $(USER_FSD) $(USER_SUP) $(FS_IMAGE) $(HELLO_BPK) $(GREEDY_BPK) $(GO_HELLO)
	@mkdir -p $(dir $@)
	./$(MKIMAGE) $@ $(INITRD_ROOT) --root . --static $(INITRD_DIR) \
	    --file fs.img=$(FS_IMAGE) \
	    --file hello.bpk=$(HELLO_BPK) \
	    --file greedy.bpk=$(GREEDY_BPK) \
	    --file bin/go-hello=$(GO_HELLO) \
	    \
	    $(foreach manifest,$(PACKAGES),--package $(manifest))
	./$(MKIMAGE) $@.again $(INITRD_ROOT).again --root . --static $(INITRD_DIR) \
	    --file fs.img=$(FS_IMAGE) \
	    --file hello.bpk=$(HELLO_BPK) \
	    --file greedy.bpk=$(GREEDY_BPK) \
	    --file bin/go-hello=$(GO_HELLO) \
	    $(foreach manifest,$(PACKAGES),--package $(manifest))
	cmp $@ $@.again
	@rm -rf $@.again $(INITRD_ROOT).again
	@echo "built $@ ($$(stat -c%s $@) bytes, byte-identical twice)"

# Built through a staging directory rather than into `initrd/`, so that a
# compiled artefact never lands in a source tree that is under version control.
$(PROBE): $(PROBE_DIR)/src/main.rs $(PROBE_DIR)/link.ld $(PROBE_DIR)/Cargo.toml
	cd $(PROBE_DIR) && RUSTFLAGS="$(PROBE_FLAGS)" \
	    $(CARGO) build --release --target $(TARGET)
	@echo "built $@"

# The user-mode shell. Depends on the ABI crate as well as its own source: the
# ABI is compiled into both sides of the boundary, so a change there changes
# the program as surely as a change here.
$(USER_SHELL): $(SHELL_DIR)/src/main.rs $(SHELL_DIR)/link.ld $(SHELL_DIR)/Cargo.toml \
               $(wildcard abi/src/*.rs)
	cd $(SHELL_DIR) && RUSTFLAGS="$(SHELL_FLAGS)" \
	    $(CARGO) build --release --target $(TARGET)
	@echo "built $@"

$(USER_SUP): $(SUP_DIR)/src/main.rs $(SUP_DIR)/link.ld $(SUP_DIR)/Cargo.toml \
             $(wildcard abi/src/*.rs)
	cd $(SUP_DIR) && RUSTFLAGS="$(SUP_FLAGS)" \
	    $(CARGO) build --release --target $(TARGET)
	@echo "built $@"

HELLO_FLAGS := -C relocation-model=static -C code-model=small \
                -C link-arg=-T$(CURDIR)/$(HELLO_DIR)/link.ld
$(HELLO): $(HELLO_DIR)/src/main.rs $(HELLO_DIR)/link.ld $(HELLO_DIR)/Cargo.toml \
             $(wildcard abi/src/*.rs)
	cd $(HELLO_DIR) && RUSTFLAGS="$(HELLO_FLAGS)" \
	    $(CARGO) build --release --target $(TARGET)
	@echo "built $@"

# The Go corpus program. `-ldflags -s -w` strips it: the loader does not
# read symbols and the image does not need 400 KiB of them.
$(GO_HELLO): corpus/hello.go
	@mkdir -p $(dir $@)
	@if [ -n "$(GO)" ]; then \
	    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -ldflags '-s -w' \
	        -o $@ corpus/hello.go && echo "built $@ ($$(stat -c%s $@) bytes)"; \
	else \
	    : > $@; \
	    echo "no go toolchain: $@ left empty, the corpus gate will say so"; \
	fi

# The demonstration package, emitted and verified by the same tool and the
# same parsers the installer uses.
$(HELLO_BPK): $(MKIMAGE) $(HELLO) packages/demo/hello.manifest.in
	./$(MKIMAGE) --bpk $@ build/bpk_stage --root . \
	    --package packages/demo/hello.manifest.in

# The over-asker, RFC 0030 step 4: the same binary under a manifest that
# asks for more than the shell holds, so the refusal can be gated.
$(GREEDY_BPK): $(MKIMAGE) $(HELLO) packages/demo/greedy.manifest.in
	./$(MKIMAGE) --bpk $@ build/bpk_stage_greedy --root . \
	    --package packages/demo/greedy.manifest.in

# The filesystem service as a program, for the domain placement. Rebuilt when
# the service crate changes too: the same crate is compiled into the kernel for
# the nucleus placement, and the two must be the same code or the claim this
# program exists to make is not being made.
$(USER_VFSD): $(VFSD_DIR)/src/main.rs $(VFSD_DIR)/link.ld $(VFSD_DIR)/Cargo.toml \
              $(wildcard abi/src/*.rs) $(wildcard services/vfs/src/*.rs) \
              $(wildcard service/src/*.rs) $(wildcard service-domain/src/*.rs)
	cd $(VFSD_DIR) && RUSTFLAGS="$(VFSD_FLAGS)" \
	    $(CARGO) build --release --target $(TARGET)
	@echo "built $@"

# The console service as a program, for the domain placement.
$(USER_CONSOLED): $(CONSOLED_DIR)/src/main.rs $(CONSOLED_DIR)/link.ld $(CONSOLED_DIR)/Cargo.toml \
              $(wildcard abi/src/*.rs) $(wildcard services/console/src/*.rs) \
              $(wildcard service/src/*.rs) $(wildcard service-domain/src/*.rs)
	cd $(CONSOLED_DIR) && RUSTFLAGS="$(CONSOLED_FLAGS)" \
	    $(CARGO) build --release --target $(TARGET)
	@echo "built $@"

# The block driver as a program. It shares no code with the kernel's driver --
# only the specification -- so its dependencies are the ABI and nothing else.
$(USER_BLKD): $(BLKD_DIR)/src/main.rs $(BLKD_DIR)/link.ld $(BLKD_DIR)/Cargo.toml \
              $(wildcard abi/src/*.rs)
	cd $(BLKD_DIR) && RUSTFLAGS="$(BLKD_FLAGS)" \
	    $(CARGO) build --release --target $(TARGET)
	@echo "built $@"

# The network driver as a program. RFC 0018 step 2. Like the block driver it
# shares no code with anything in the kernel -- and unlike it, there is no
# kernel driver for this device class at all. It does not depend on
# `bhaskix-net`: the parsers live in the domain that has no device.
$(USER_NETD): $(NETD_DIR)/src/main.rs $(NETD_DIR)/link.ld $(NETD_DIR)/Cargo.toml \
              $(wildcard abi/src/*.rs) $(wildcard device/src/*.rs)
	cd $(NETD_DIR) && RUSTFLAGS="$(NETD_FLAGS)" \
	    $(CARGO) build --release --target $(TARGET)
	@echo "built $@"

# The protocol service. RFC 0018 step 3. It depends on the ABI alone -- there
# is no device to drive and, at this step, no protocol to parse.
$(USER_IPD): $(IPD_DIR)/src/main.rs $(IPD_DIR)/link.ld $(IPD_DIR)/Cargo.toml \
             $(wildcard abi/src/*.rs) $(wildcard net/src/*.rs)
	cd $(IPD_DIR) && RUSTFLAGS="$(IPD_FLAGS)" \
	    $(CARGO) build --release --target $(TARGET)
	@echo "built $@"

# The DHCP client. RFC 0018 step 6, and a program rather than a shell command
# because it needs a socket and a page and should hold a socket and a page.
$(USER_DHCPD): $(DHCPD_DIR)/src/main.rs $(DHCPD_DIR)/link.ld $(DHCPD_DIR)/Cargo.toml \
               $(wildcard abi/src/*.rs) $(wildcard net/src/*.rs) $(wildcard sock/src/*.rs)
	cd $(DHCPD_DIR) && RUSTFLAGS="$(DHCPD_FLAGS)" \
	    $(CARGO) build --release --target $(TARGET)
	@echo "built $@"

# RFC 0029 step 4's live proof: one v6 datagram to loopback and back,
# through the socket capabilities and nothing else.
$(USER_UDP6): $(UDP6_DIR)/src/main.rs $(UDP6_DIR)/link.ld $(UDP6_DIR)/Cargo.toml \
               $(wildcard abi/src/*.rs) $(wildcard sock/src/*.rs)
	cd $(UDP6_DIR) && RUSTFLAGS="$(UDP6_FLAGS)" \
	    $(CARGO) build --release --target $(TARGET)
	@echo "built $@"

# The TCP service. RFC 0020 step 4: a third network domain, holding two rings
# to ipd, an endpoint, a timer, and no device. It depends on `bhaskix-rand`
# as well as the protocol code, because the initial sequence number's secret
# is drawn at start -- and on a machine that cannot supply one it refuses to
# serve, which is RFC 0021's policy with this program as the caller.
$(USER_TCPD): $(TCPD_DIR)/src/main.rs $(TCPD_DIR)/link.ld $(TCPD_DIR)/Cargo.toml \
              $(wildcard abi/src/*.rs) $(wildcard net/src/*.rs) $(wildcard net/src/tcp/*.rs) \
              $(wildcard rand/src/*.rs)
	cd $(TCPD_DIR) && RUSTFLAGS="$(TCPD_FLAGS)" \
	    $(CARGO) build --release --target $(TARGET)
	@echo "built $@"

# The Linux personality, in a domain of its own -- RFC 0032 step 3. It depends
# on `personality/` as well as the ABI, because the half of the translation
# that needs no machine was kept in that crate while the rest of it was in the
# kernel, and this is what that separation was for: the move changes where the
# code runs and not what it says.
$(USER_LINUXD): $(LINUXD_DIR)/src/main.rs $(LINUXD_DIR)/link.ld $(LINUXD_DIR)/Cargo.toml \
              $(wildcard abi/src/*.rs) $(wildcard personality/src/*.rs)
	cd $(LINUXD_DIR) && RUSTFLAGS="$(LINUXD_FLAGS)" \
	    $(CARGO) build --release --target $(TARGET)
	@echo "built $@"

# The TCP demonstration client -- the first program to open a connection the
# way every program will: rings it owns, handed across CONNECT (RFC 0022
# step 4). Only the ABI: what it demonstrates is the exchange, and an
# exchange that needed protocol code on the client side would be the wrong
# exchange.
$(USER_TCPC): $(TCPC_DIR)/src/main.rs $(TCPC_DIR)/link.ld $(TCPC_DIR)/Cargo.toml \
              $(wildcard abi/src/*.rs) $(wildcard sock/src/*.rs)
	cd $(TCPC_DIR) && RUSTFLAGS="$(TCPC_FLAGS)" \
	    $(CARGO) build --release --target $(TARGET)
	@echo "built $@"


# The telemetry reader -- RFC 0026 steps 3 and 4. The ABI for the calls, and
# the telemetry crate for everything about the bytes: the same registry the
# kernel hashed into the ring headers, so a mismatched build refuses to
# decode instead of misreading structurally.
$(USER_TRACED): $(TRACED_DIR)/src/main.rs $(TRACED_DIR)/link.ld $(TRACED_DIR)/Cargo.toml \
              $(wildcard abi/src/*.rs) $(wildcard telemetry/src/*.rs)
	cd $(TRACED_DIR) && RUSTFLAGS="$(TRACED_FLAGS)" \
	    $(CARGO) build --release --target $(TARGET)
	@echo "built $@"


# The native UEFI loader -- RFC 0028 step 1. Its own target and its own
# linker convention (PE, efi_main), so its own cargo invocation; no RUSTFLAGS
# because the uefi target's defaults are the convention.
$(BOOTEFI): $(BOOTEFI_DIR)/src/main.rs $(BOOTEFI_DIR)/Cargo.toml
	cd $(BOOTEFI_DIR) && $(CARGO) build --release --target x86_64-unknown-uefi
	@echo "built $@"

# The filesystem as a program. It depends on `fs/` as well as the ABI, because
# unlike the block driver this *is* the same code the kernel runs -- so a
# change to the format rebuilds both, and the two can never be reading
# different filesystems.
$(USER_FSD): $(FSD_DIR)/src/main.rs $(FSD_DIR)/link.ld $(FSD_DIR)/Cargo.toml \
             $(wildcard abi/src/*.rs) $(wildcard fs/src/*.rs)
	cd $(FSD_DIR) && RUSTFLAGS="$(FSD_FLAGS)" \
	    $(CARGO) build --release --target $(TARGET)
	@echo "built $@"

$(ISO): kernel boot/limine.conf $(CMDLINE_STAMP) $(INITRD) $(DOMAIN_DISK) | $(LIMINE_DIR)
	@rm -rf $(ISO_ROOT)
	@mkdir -p $(ISO_ROOT)/boot/limine $(ISO_ROOT)/EFI/BOOT
	cp $(KERNEL) $(ISO_ROOT)/boot/bhaskix
	cp $(INITRD) $(ISO_ROOT)/boot/initrd.tar
	sed 's|^    cmdline:.*|    cmdline: $(CMDLINE)|' boot/limine.conf \
	    > $(ISO_ROOT)/boot/limine/limine.conf
	cp $(LIMINE_DIR)/limine-bios.sys \
	   $(LIMINE_DIR)/limine-bios-cd.bin \
	   $(LIMINE_DIR)/limine-uefi-cd.bin $(ISO_ROOT)/boot/limine/
	cp $(LIMINE_DIR)/BOOTX64.EFI $(LIMINE_DIR)/BOOTIA32.EFI $(ISO_ROOT)/EFI/BOOT/
	xorriso -as mkisofs -quiet \
	    -b boot/limine/limine-bios-cd.bin \
	    -no-emul-boot -boot-load-size 4 -boot-info-table \
	    --efi-boot boot/limine/limine-uefi-cd.bin \
	    -efi-boot-part --efi-boot-image --protective-msdos-label \
	    $(ISO_ROOT) -o $@
	$(LIMINE_DIR)/limine bios-install $@ 2>/dev/null
	@echo "built $@"

$(LIMINE_DIR):
	@echo "Limine is missing. Run tools/setup-dev.sh" >&2; exit 1

# --- run -----------------------------------------------------------------

run: $(ISO)
	$(QEMU) $(QEMU_COMMON) -cdrom $(ISO) -boot d -serial stdio

run-uefi: $(ISO)
	@test -n "$(OVMF_CODE)" -a -n "$(OVMF_VARS)" || \
	    { echo "no complete OVMF CODE/VARS pair; install the 'ovmf' package" >&2; exit 1; }
	@echo "firmware: $(notdir $(OVMF_CODE)) + $(notdir $(OVMF_VARS))"
	@mkdir -p build
	@cp $(OVMF_VARS) build/OVMF_VARS.fd
	$(QEMU) $(QEMU_COMMON) \
	    -drive if=pflash,unit=0,format=raw,readonly=on,file=$(OVMF_CODE) \
	    -drive if=pflash,unit=1,format=raw,file=build/OVMF_VARS.fd \
	    -cdrom $(ISO) -boot d -serial stdio

# --- test ----------------------------------------------------------------

# Everything CI runs. Ordered cheapest-first so a trivial mistake fails in
# seconds rather than after a QEMU boot.
test: fmt clippy test-host gates test-boot test-boot-uefi test-boot-iommu test-boot-iommu-off \
      test-boot-qemu64 test-boot-native test-boot-native-full test-placements test-shell \
      test-keyboard test-faults
	@echo
	@echo "  all checks passed"

# Host unit tests. The overridden --target is what takes these off the
# freestanding target and onto something that can run a test harness.
#
# `--workspace` and not a list. The list was a list until RFC 0013 step 3 moved
# `ustar` and `vfs` out of the kernel into a crate of their own -- and their
# tests, including the archive mutation harness, quietly stopped running,
# because a crate that is not named is a crate that is not tested and nothing
# says so. Twenty-two assertions were missing from the suite for a day.
#
# The shim is excluded because it is a freestanding binary with its own panic
# handler, which collides with the test harness's. That is a reason, and it is
# the only entry here that needs one.
test-host:
	$(CARGO) test --target $(HOST_TARGET) --workspace --exclude bhaskix-boot-shim

# Every service that has two placements, in both of them, every build.
#
# RFC 0013's testing plan asks for exactly this, and it is the only thing that
# stops the placement nobody is running from rotting: the code for it is
# compiled out, so nothing else would notice. The placement comes from the
# environment rather than from `services.toml` -- a test that edited the file
# it is testing would not be testing it.
#
# Two boots, not two builds. A build proves it compiles; only a boot proves the
# service answers, and the whole claim is that it answers the same either way.
test-placements:
	@for console in nucleus domain; do \
	  for vfs in nucleus domain; do \
	    echo "  console=$$console vfs=$$vfs"; \
	    BHASKIX_PLACEMENT_CONSOLE=$$console BHASKIX_PLACEMENT_VFS=$$vfs \
	        $(MAKE) --no-print-directory iso >/dev/null || exit 1; \
	    BHASKIX_PLACEMENT_CONSOLE=$$console BHASKIX_PLACEMENT_VFS=$$vfs \
	        tests/qemu/boot-test.sh bios || exit 1; \
	  done; \
	done

# Typed at with a keyboard rather than a serial line (RFC 0037). Every other
# harness here reaches the shell through the UART, which is exactly why console
# input could be UART-only for so long without a single test noticing.
test-keyboard: $(ISO)
	tests/qemu/keyboard-test.sh

test-boot: $(ISO)
	tests/qemu/boot-test.sh bios

test-boot-uefi: $(ISO)
	tests/qemu/boot-test.sh uefi

# The same boot with an IOMMU present. RFC 0012's discovery path is otherwise
# unreachable: a machine without one has no DMAR table, so every run would
# exercise only the absent case -- which is how the "NO IOMMU" line managed to
# be a constant for a milestone.
test-boot-iommu: $(ISO)
	tests/qemu/boot-test.sh iommu

# RFC 0012's escape hatch, on a machine that has a unit to refuse -- turning
# off an IOMMU that is not there proves nothing. The script builds an image
# with `iommu=off` and puts the default back, the same way the shell test does
# for `shell=kernel`.
#
# It is in `test` rather than left to a human because this is the flag that
# gets reached for on the machine that is already going wrong, and finding out
# then that it never worked is the worst possible time.
test-boot-iommu-off: $(ISO)
	tests/qemu/boot-test.sh iommu-off

# The dark machine: no RDRAND, no SMEP/SMAP, xAPIC only. CI has booted it
# since the APIC matrix existed, but the local suite never did -- which is
# exactly how its lanes stayed red from 2026-08-14 to 2026-08-16 while every
# local run was green, invisible behind the CI-log-access blocker. One
# placement here, BIOS, because the dark arms being tested are CPU-model
# facts and the firmware axis is already covered above.
test-boot-qemu64: $(ISO)
	QEMU_CPU=qemu64 tests/qemu/boot-test.sh bios

# RFC 0028's graduated lane: the native loader under OVMF. Its gate list is
# the honest statement of how far sovereignty has come, and it grows a check
# per implemented step until it runs what the Limine lanes run.
test-boot-native: $(BOOTEFI) $(ISO)
	tests/qemu/native-boot-test.sh

# RFC 0028 step 7's closing claim, executable: the native loader answers the
# SAME gate list as every Limine lane -- boot-test.sh with only the boot
# media changed. The loader-specific lane above keeps what this one cannot
# express (payload checksums, the slide policy, the negative arm); this one
# holds bhaskixboot to everything the incumbent is held to.
test-boot-native-full: $(BOOTEFI) $(ISO)
	tests/qemu/boot-test.sh native


# Types at the machine over the serial line and asserts on the replies. The
# only tests here that write to the kernel rather than only reading from it,
# which is the only way to test an input path.
#
# Both shells, because both are supported: the user-mode one the machine boots
# to, and the ring 0 one `shell=kernel` selects. The second rebuilds the image
# with that on the command line and puts the default back afterwards.
test-shell: $(ISO)
	tests/qemu/shell-test.sh user
	tests/qemu/shell-test.sh kernel
	tests/qemu/shell-test.sh disk
	tests/qemu/shell-test.sh iommu

# Boots the same image many times. Not part of `test`: it is minutes rather than
# seconds, and what it is for is the class of bug a single run cannot see -- one
# that depends on where a timer tick lands. Every other target here boots once,
# which is enough for a fault that is always there and useless for one that is
# not.
#
# Two bugs this project shipped would have been caught by running it: the IPC
# rendezvous stall of M6-08, and the `sched::exit` lock ordering of RFC 0017
# step 6, which passed every gate in the single run that verified it and hung
# the shell about three times in ten.
.PHONY: soak soak-boot soak-shell
soak: soak-boot soak-shell

# Does it come up, repeatedly.
soak-boot: $(ISO)
	tests/qemu/soak-test.sh $(SOAK_RUNS) $(SOAK_JOBS)

# Does it *answer*, repeatedly -- which is a different question, and the one
# that would have caught the kernel tearing the shell's banner in half. One at
# a time on purpose: the shell test writes to the domain disk.
soak-shell: $(ISO)
	tests/qemu/soak-shell.sh $(SOAK_SHELL_RUNS) $(SOAK_SHELL_MODE)

SOAK_RUNS ?= 40
SOAK_JOBS ?= 2
SOAK_SHELL_RUNS ?= 10
SOAK_SHELL_MODE ?= user

# Rebuilds the image per fault, so it must not run in parallel with the boot
# tests -- hence its own target rather than a boot-test flag.
test-faults:
	tests/qemu/fault-test.sh

fmt:
	$(CARGO) fmt --all --check
	cd $(PROBE_DIR) && $(CARGO) fmt --all --check
	cd $(SHELL_DIR) && $(CARGO) fmt --all --check
	cd $(VFSD_DIR) && $(CARGO) fmt --all --check
	cd $(CONSOLED_DIR) && $(CARGO) fmt --all --check
	cd $(BLKD_DIR) && $(CARGO) fmt --all --check
	cd $(NETD_DIR) && $(CARGO) fmt --all --check
	cd $(IPD_DIR) && $(CARGO) fmt --all --check
	cd $(DHCPD_DIR) && $(CARGO) fmt --all --check
	cd $(TCPD_DIR) && $(CARGO) fmt --all --check
	cd $(TCPC_DIR) && $(CARGO) fmt --all --check
	cd $(TRACED_DIR) && $(CARGO) fmt --all --check
	cd $(BOOTEFI_DIR) && $(CARGO) fmt --all --check
	cd $(FSD_DIR) && $(CARGO) fmt --all --check
	cd $(SUP_DIR) && $(CARGO) fmt --all --check

# Two passes, because they cover different things. `--all-targets` cannot be
# used on the freestanding target: it would try to build the test harness,
# which needs std, and the resulting wall of errors hides real ones.
clippy:
	$(CARGO) clippy --profile $(PROFILE) --target $(TARGET) --lib --bins -- -D warnings
	$(CARGO) clippy --target $(HOST_TARGET) --all-targets \
	    --workspace --exclude bhaskix-boot-shim -- -D warnings
	cd $(PROBE_DIR) && RUSTFLAGS="$(PROBE_FLAGS)" \
	    $(CARGO) clippy --release --target $(TARGET) -- -D warnings
	cd $(SHELL_DIR) && RUSTFLAGS="$(SHELL_FLAGS)" \
	    $(CARGO) clippy --release --target $(TARGET) -- -D warnings
	cd $(VFSD_DIR) && RUSTFLAGS="$(VFSD_FLAGS)" \
	    $(CARGO) clippy --release --target $(TARGET) -- -D warnings
	cd $(CONSOLED_DIR) && RUSTFLAGS="$(CONSOLED_FLAGS)" \
	    $(CARGO) clippy --release --target $(TARGET) -- -D warnings
	cd $(BLKD_DIR) && RUSTFLAGS="$(BLKD_FLAGS)" \
	    $(CARGO) clippy --release --target $(TARGET) -- -D warnings
	cd $(NETD_DIR) && RUSTFLAGS="$(NETD_FLAGS)" \
	    $(CARGO) clippy --release --target $(TARGET) -- -D warnings
	cd $(IPD_DIR) && RUSTFLAGS="$(IPD_FLAGS)" \
	    $(CARGO) clippy --release --target $(TARGET) -- -D warnings
	cd $(DHCPD_DIR) && RUSTFLAGS="$(DHCPD_FLAGS)" \
	    $(CARGO) clippy --release --target $(TARGET) -- -D warnings
	cd $(TCPD_DIR) && RUSTFLAGS="$(TCPD_FLAGS)" \
	    $(CARGO) clippy --release --target $(TARGET) -- -D warnings
	cd $(TCPC_DIR) && RUSTFLAGS="$(TCPC_FLAGS)" \
	    $(CARGO) clippy --release --target $(TARGET) -- -D warnings
	cd $(TRACED_DIR) && RUSTFLAGS="$(TRACED_FLAGS)" \
	    $(CARGO) clippy --release --target $(TARGET) -- -D warnings
	cd $(BOOTEFI_DIR) && $(CARGO) clippy --release --target x86_64-unknown-uefi -- -D warnings
	cd $(SUP_DIR) && RUSTFLAGS="$(SUP_FLAGS)" \
	    $(CARGO) clippy --release --target $(TARGET) -- -D warnings

# The project-specific invariants from docs/. Each one is cheap and catches a
# class of mistake that review reliably misses.
gates:
	tools/check-containment.sh
# The image builder still builds. It is behind a feature because the workspace
# targets a machine with no `std`, and a tool nobody compiles is a tool that
# has already stopped compiling.
	@$(CARGO) build --quiet --target $(HOST_TARGET) -p bhaskix-fs --features tool \
	    && printf '  \033[1;32mok\033[0m    the filesystem image builder still builds\n' \
	    || { echo "  FAIL  the filesystem image builder does not build"; exit 1; }
	@$(CARGO) build --quiet --target $(HOST_TARGET) -p bhaskix-pkg --features tool \
	    && printf '  \033[1;32mok\033[0m    the package image assembler still builds\n' \
	    || { echo "  FAIL  the package image assembler does not build"; exit 1; }
	tools/check-unsafe-budget.py
	tools/check-instruction-containment.py
# And watched refusing one. `architecture.md` §7 claimed for a year that
# architecture-specific instructions appear only in `arch/` while nothing checked
# it; the fixture is a crate holding one instruction and declaring no budget,
# which is the shape that claim was wrong in. Its own source also mentions `asm!`
# in a comment, so accepting it would prove the counter reads prose.
	@mkdir -p build
	@if tools/check-instruction-containment.py --root tests/fixtures/instructions \
	        >build/instructions-fixture.log 2>&1; then \
	    echo "  FAIL  the instruction check accepted an undeclared instruction"; \
	    exit 1; \
	elif ! grep -q "no asm_budget declared" build/instructions-fixture.log; then \
	    echo "  FAIL  the instruction check rejected the fixture for the wrong reason:"; \
	    cat build/instructions-fixture.log; \
	    exit 1; \
	else \
	    printf '  \033[1;32mok\033[0m    the instruction check rejects an undeclared instruction\n'; \
	fi
	tools/check-deps.py
# Every fuzz target still compiles. `fuzz/` is its own workspace, so nothing
# else in this file builds it -- and on 2026-08-18 RFC 0029's renames broke two
# targets, which then ran zero executions for three days while the project went
# on describing itself as having a fuzz target on every untrusted parser. This
# is `cargo check`, not a campaign: proving a target builds is a second warm and
# catches the whole class.
	tools/check-fuzz-targets.sh
	tools/check-one-machine.sh
# And watched refusing one, against a fixture that is wrong on purpose. The
# real harnesses are correct, so the only way to see this go red is to keep a
# wrong one -- making a real harness wrong to watch it fail is a change somebody
# forgets to undo.
	@mkdir -p build
	@if tools/check-one-machine.sh tests/fixtures/qemu >build/one-machine-fixture.log 2>&1; then \
	    echo "  FAIL  the machine check accepted a harness building its own device list"; \
	    exit 1; \
	elif ! grep -q "builds its own device list" build/one-machine-fixture.log; then \
	    echo "  FAIL  the machine check rejected the fixture for the wrong reason:"; \
	    cat build/one-machine-fixture.log; \
	    exit 1; \
	else \
	    printf '  \033[1;32mok\033[0m    the machine check rejects a harness with its own device list\n'; \
	fi
	tools/check-placements.sh
# The placement check has to be watched failing or it is worth nothing, so the
# negative fixture runs immediately after it: a service that reaches into the
# kernel, which must be rejected, and rejected for *that* reason rather than
# for any of the ordinary reasons a build does not work.
	@if tools/check-placements.sh tests/fixtures/placement/services.toml \
	        >build/placement-fixture.log 2>&1; then \
	    echo "  FAIL  the placement check accepted a service that calls into the kernel"; \
	    exit 1; \
	elif ! grep -q "reaches bhaskix-kernel" build/placement-fixture.log; then \
	    echo "  FAIL  the placement check rejected the fixture for the wrong reason:"; \
	    cat build/placement-fixture.log; \
	    exit 1; \
	else \
	    printf '  \033[1;32mok\033[0m    the placement check rejects a service that calls into the kernel\n'; \
	fi
# Register blocks that are wrong about themselves must not build.
#
# A compile-time layout check is only worth having if somebody has watched it
# reject something, and it cannot be tested from inside the crate: a test that
# fails to compile fails the build it is part of. So the fixtures are separate
# crates, excluded from the workspace, and the assertion is that `cargo build`
# fails *and says why* -- a build that failed for an unrelated reason would
# otherwise read as the check working.
	@for kind in overlap:"two registers overlap" overrun:"a register leaves the block"; do \
	    name=$${kind%%:*}; want=$${kind#*:}; \
	    if $(CARGO) build --quiet --manifest-path tests/fixtures/registers/$$name/Cargo.toml \
	            >build/registers-$$name.log 2>&1; then \
	        echo "  FAIL  a register block that is wrong about itself compiled ($$name)"; \
	        exit 1; \
	    elif ! grep -q "$$want" build/registers-$$name.log; then \
	        echo "  FAIL  the $$name fixture failed to build for the wrong reason:"; \
	        tail -20 build/registers-$$name.log; \
	        exit 1; \
	    else \
	        printf '  \033[1;32mok\033[0m    a register block that %s does not compile\n' \
	            "$$(test $$name = overlap && echo overlaps || echo overruns)"; \
	    fi; \
	done

# And a table that is wrong about itself rather than about a dependency: a
# service listed twice and a placement that is not a placement. Both must be
# reported, not just the first -- a check that stops at the first thing it
# finds reports the shape of its own control flow rather than of the mistakes.
	@if tools/check-placements.sh tests/fixtures/placement/malformed.toml \
	        >build/placement-malformed.log 2>&1; then \
	    echo "  FAIL  the placement check accepted a malformed table"; \
	    exit 1; \
	elif ! grep -q "is neither nucleus nor domain" build/placement-malformed.log \
	        || ! grep -q "listed twice" build/placement-malformed.log; then \
	    echo "  FAIL  the placement check missed one of the two faults in the malformed table:"; \
	    cat build/placement-malformed.log; \
	    exit 1; \
	else \
	    printf '  \033[1;32mok\033[0m    the placement check reports both faults in a malformed table\n'; \
	fi

# Builds the filesystem image tool, for a developer who wants an image.
mkfs:
	$(CARGO) build --release --target $(HOST_TARGET) -p bhaskix-fs --features tool
	@echo "built target/$(HOST_TARGET)/release/mkfs"

# --- housekeeping --------------------------------------------------------

clean:
	$(CARGO) clean
	cd $(PROBE_DIR) && $(CARGO) clean
	cd $(SHELL_DIR) && $(CARGO) clean
	cd $(VFSD_DIR) && $(CARGO) clean
	cd $(CONSOLED_DIR) && $(CARGO) clean
	cd $(BLKD_DIR) && $(CARGO) clean
	cd $(NETD_DIR) && $(CARGO) clean
	cd $(IPD_DIR) && $(CARGO) clean
	cd $(DHCPD_DIR) && $(CARGO) clean
	cd $(TCPD_DIR) && $(CARGO) clean
	cd $(TCPC_DIR) && $(CARGO) clean
	cd $(FSD_DIR) && $(CARGO) clean
	rm -rf build

distclean: clean
	rm -rf $(LIMINE_DIR)

help:
	@sed -n '3,12p' Makefile | sed 's/^# \?//'
