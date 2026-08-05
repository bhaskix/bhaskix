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
USER_SHELL   := $(SHELL_DIR)/target/$(TARGET)/release/shell
# `RUSTFLAGS` in the environment *replaces* the workspace's `.cargo/config.toml`
# flags rather than adding to them, which is exactly what is wanted here: the
# kernel's PIC/kernel-code-model settings are wrong for a user program linked
# at a fixed low address.
PROBE_FLAGS  := -C relocation-model=static -C code-model=small \
                -C link-arg=-T$(CURDIR)/$(PROBE_DIR)/link.ld
SHELL_FLAGS  := -C relocation-model=static -C code-model=small \
                -C link-arg=-T$(CURDIR)/$(SHELL_DIR)/link.ld

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

.PHONY: FORCE all kernel iso run run-uefi test test-host test-boot test-boot-uefi test-boot-iommu \
        test-shell test-faults fmt clippy gates clean distclean help

all: iso

# --- build ---------------------------------------------------------------

kernel:
	$(CARGO) build --profile $(PROFILE) --target $(TARGET)

iso: $(ISO)

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
$(INITRD): $(shell find $(INITRD_DIR) -type f 2>/dev/null | sort) $(PROBE) $(USER_SHELL)
	@rm -rf $(INITRD_ROOT)
	@mkdir -p $(dir $@) $(INITRD_ROOT)/bin
	cp -r $(INITRD_DIR)/. $(INITRD_ROOT)/
	cp $(PROBE) $(INITRD_ROOT)/bin/probe
	cp $(USER_SHELL) $(INITRD_ROOT)/bin/shell
	tar --format=ustar --sort=name --owner=0 --group=0 --numeric-owner \
	    --mtime='@0' -cf $@ -C $(INITRD_ROOT) .
	@echo "built $@ ($$(stat -c%s $@) bytes)"

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

$(ISO): kernel boot/limine.conf $(CMDLINE_STAMP) $(INITRD) | $(LIMINE_DIR)
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
test: fmt clippy test-host gates test-boot test-boot-uefi test-boot-iommu test-shell test-faults
	@echo
	@echo "  all checks passed"

# Host unit tests. The overridden --target is what takes these off the
# freestanding target and onto something that can run a test harness.
test-host:
	$(CARGO) test --target $(HOST_TARGET) -p bhaskix-abi -p bhaskix-boot -p bhaskix-kernel -p bhaskix-arch-x86-64 -p bhaskix-mm

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

# Rebuilds the image per fault, so it must not run in parallel with the boot
# tests -- hence its own target rather than a boot-test flag.
test-faults:
	tests/qemu/fault-test.sh

fmt:
	$(CARGO) fmt --all --check
	cd $(PROBE_DIR) && $(CARGO) fmt --all --check
	cd $(SHELL_DIR) && $(CARGO) fmt --all --check

# Two passes, because they cover different things. `--all-targets` cannot be
# used on the freestanding target: it would try to build the test harness,
# which needs std, and the resulting wall of errors hides real ones.
clippy:
	$(CARGO) clippy --profile $(PROFILE) --target $(TARGET) --lib --bins -- -D warnings
	$(CARGO) clippy --target $(HOST_TARGET) --all-targets \
	    -p bhaskix-abi -p bhaskix-boot -p bhaskix-kernel -p bhaskix-arch-x86-64 -p bhaskix-mm -- -D warnings
	cd $(PROBE_DIR) && RUSTFLAGS="$(PROBE_FLAGS)" \
	    $(CARGO) clippy --release --target $(TARGET) -- -D warnings
	cd $(SHELL_DIR) && RUSTFLAGS="$(SHELL_FLAGS)" \
	    $(CARGO) clippy --release --target $(TARGET) -- -D warnings

# The project-specific invariants from docs/. Each one is cheap and catches a
# class of mistake that review reliably misses.
gates:
	tools/check-containment.sh
	tools/check-unsafe-budget.py
	tools/check-deps.py

# --- housekeeping --------------------------------------------------------

clean:
	$(CARGO) clean
	cd $(PROBE_DIR) && $(CARGO) clean
	cd $(SHELL_DIR) && $(CARGO) clean
	rm -rf build

distclean: clean
	rm -rf $(LIMINE_DIR)

help:
	@sed -n '3,12p' Makefile | sed 's/^# \?//'
