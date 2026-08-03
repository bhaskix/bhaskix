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
LIMINE_DIR   := boot/limine/limine

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
QEMU_COMMON  := -M q35 -cpu $(QEMU_CPU) -m $(QEMU_MEM) -no-reboot -no-shutdown

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

.PHONY: all kernel iso run run-uefi test test-host test-boot test-boot-uefi \
        test-faults fmt clippy gates clean distclean help

all: iso

# --- build ---------------------------------------------------------------

kernel:
	$(CARGO) build --profile $(PROFILE) --target $(TARGET)

iso: $(ISO)

# Depends on the phony `kernel` target directly, so the image is rebuilt every
# time rather than when make believes the ELF changed. Regenerating costs under
# a second; testing a stale image costs an afternoon of chasing a bug that was
# already fixed. In kernel work that trade is not close.
$(ISO): kernel boot/limine.conf | $(LIMINE_DIR)
	@rm -rf $(ISO_ROOT)
	@mkdir -p $(ISO_ROOT)/boot/limine $(ISO_ROOT)/EFI/BOOT
	cp $(KERNEL) $(ISO_ROOT)/boot/bhaskix
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
test: fmt clippy test-host gates test-boot test-boot-uefi test-faults
	@echo
	@echo "  all checks passed"

# Host unit tests. The overridden --target is what takes these off the
# freestanding target and onto something that can run a test harness.
test-host:
	$(CARGO) test --target $(HOST_TARGET) -p bhaskix-boot -p bhaskix-kernel -p bhaskix-mm

test-boot: $(ISO)
	tests/qemu/boot-test.sh bios

test-boot-uefi: $(ISO)
	tests/qemu/boot-test.sh uefi

# Rebuilds the image per fault, so it must not run in parallel with the boot
# tests -- hence its own target rather than a boot-test flag.
test-faults:
	tests/qemu/fault-test.sh

fmt:
	$(CARGO) fmt --all --check

# Two passes, because they cover different things. `--all-targets` cannot be
# used on the freestanding target: it would try to build the test harness,
# which needs std, and the resulting wall of errors hides real ones.
clippy:
	$(CARGO) clippy --profile $(PROFILE) --target $(TARGET) --lib --bins -- -D warnings
	$(CARGO) clippy --target $(HOST_TARGET) --all-targets \
	    -p bhaskix-boot -p bhaskix-kernel -p bhaskix-arch-x86-64 -p bhaskix-mm -- -D warnings

# The project-specific invariants from docs/. Each one is cheap and catches a
# class of mistake that review reliably misses.
gates:
	tools/check-containment.sh
	tools/check-unsafe-budget.py
	tools/check-deps.py

# --- housekeeping --------------------------------------------------------

clean:
	$(CARGO) clean
	rm -rf build

distclean: clean
	rm -rf $(LIMINE_DIR)

help:
	@sed -n '3,12p' Makefile | sed 's/^# \?//'
