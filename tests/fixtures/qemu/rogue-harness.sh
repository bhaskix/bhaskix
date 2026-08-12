#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# A harness that builds its own device list, which must be rejected.
#
# `tools/check-one-machine.sh` exists because two harnesses drifted apart and
# nothing could see it. A check for that is worth nothing until it has been
# watched refusing one, and it cannot be watched refusing the real harnesses --
# they are correct, and making one wrong on purpose to see red is a change
# somebody would forget to undo.
#
# So the wrong thing lives here, permanently, and the gate is run against it.
timeout 60 qemu-system-x86_64 \
    -M q35 -m 256M \
    -drive file=build/initrd.tar,format=raw,if=none,id=disk0,readonly=on \
    -device virtio-blk-pci,drive=disk0 \
    -netdev user,id=net0,restrict=on \
    -device virtio-net-pci,netdev=net0 \
    -display none
