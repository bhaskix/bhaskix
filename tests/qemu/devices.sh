# SPDX-License-Identifier: Apache-2.0
#
# The machines every QEMU harness boots, in one place.
#
# **Why this file exists.** `boot-test.sh` and `shell-test.sh` each built their
# own device list, and they drifted. The network device was added to one and not
# the other, so `shell-test.sh` booted a machine with no NIC while
# `boot-test.sh` booted one with a NIC, and the shell correctly reported that it
# held no capability to a service that could not exist on that machine. The boot
# log said networking worked and the shell log said it did not, and both were
# telling the truth about different machines.
#
# That cost an afternoon, and it is not a bug that gets fixed once: two lists
# drift again the moment a device is added to one of them. Agreement between two
# lists is not something either list can check.
#
# `tools/check-one-machine.sh` fails the build if a harness names a device
# itself, which is how this stays true rather than staying documented.
#
# **Not every harness wants the same machine, and that is deliberate.** The
# fault-injection tests boot the smallest machine that can fault; the soak wants
# no network traffic in the way. So a harness picks a *profile* rather than
# writing a list, and the profiles are all here where they can be compared.
#
# Sourced, not executed. Sets `MACHINE`, `IOMMU_ARGS` and `VIRTIO_ARGS`.

# Builds the device list.
#
#   $1  profile — `full`, `disks`, or `one-disk`
#   $2  translated — `yes` if the devices must go through an IOMMU (optional,
#       defaults to `no`; only `full` has ever needed it)
#
# **Translation is not a detail here.** A virtio device without
# `iommu_platform` bypasses the unit entirely on QEMU, so every assertion about
# isolation would pass on a machine where the IOMMU protects nothing — which is
# exactly what the first version of the boot test did.
qemu_device_list() {
    local profile="$1"
    local translated="${2:-no}"
    local suffix=""

    MACHINE="q35"
    IOMMU_ARGS=()

    if [[ "$translated" == "yes" ]]; then
        # `intremap=on` needs a split irqchip. That is QEMU's requirement rather
        # than this kernel's, and `shell-test.sh` did not have it: it asked for
        # interrupt remapping on a machine that cannot provide it, while
        # `boot-test.sh` asked correctly. One of the two was testing something
        # other than what it said it was.
        MACHINE="q35,kernel-irqchip=split"
        IOMMU_ARGS=(-device intel-iommu,intremap=on)
        suffix=",disable-legacy=on,iommu_platform=on"
    fi

    case "$profile" in
        full)
            # Two disks and a network. What the boot test and the shell test
            # boot, and the only profile that has ever been translated.
            VIRTIO_ARGS=(
                -device "virtio-blk-pci,drive=disk0$suffix"
                -device "virtio-blk-pci,drive=disk1$suffix"
                # Two TCP endpoints, both deterministic. Outbound: a
                # `guestfwd` hands a guest connection to 10.0.2.100:9 to a
                # host-side `cat`, which echoes the stream until EOF.
                # Inbound: `hostfwd` forwards host connections to
                # 127.0.0.1:45557 into the guest's port 7, which is what
                # lets the boot test's driver *initiate* a connection the
                # guest must accept -- RFC 0020 step 5's other direction.
                # The port is fixed because the driver must know it; a
                # second QEMU on this host with the same profile would
                # fail to start, loudly, rather than silently sharing.
                # A live network will not reproduce a handshake on demand,
                # but these answer the same way every boot, inside
                # `restrict=on`, needing no host configuration and reaching
                # nothing outside the emulator.
                # No explicit ipv6 flag, deliberately: this QEMU's slirp
                # defaults IPv6 ON and dual-stack works -- but passing
                # `ipv6=on` EXPLICITLY makes slirp stop answering v4 ARP
                # entirely (bisected with a pcap, 2026-08-18: same guest,
                # same request, answered without the flag and silent with
                # it). Do not "tidy" this line by making the default
                # explicit; the default and the flag are different worlds.
                -netdev "user,id=net0,restrict=on,guestfwd=tcp:10.0.2.100:9-cmd:cat,hostfwd=tcp:127.0.0.1:45557-:7"
                -device "virtio-net-pci,netdev=net0$suffix"
                # Two xHCI controllers, and the pair is the point.
                #
                # RFC 0041 step 3 brings the **first** one up: the kernel gives
                # it a window of its own and drives it. Step 2 refuses any
                # controller that is not behind an IOMMU translation, and the
                # kernel builds a window for the first controller only -- so the
                # second is still found, still turned down by name, and the
                # refusal stays a thing the boot gate watches happen rather than
                # a claim about code that no longer runs.
                #
                # One machine, both gates with a live subject. A single
                # controller could serve only one of them, and demoting the
                # refusal to a host test would leave the rule this driver exists
                # to enforce unexercised on the machine it matters on.
                #
                # Neither takes `$suffix`: those are virtio's
                # `iommu_platform=on` attributes, and an xHCI controller is
                # translated by the unit without asking. The second has no
                # devices attached and is never driven, so it does no DMA.
                -device qemu-xhci,id=xhci0
                -device qemu-xhci,id=xhci1
            )
            ;;
        disks)
            # Two disks, no network: the soak, which runs many machines at once
            # and has nothing to say about the wire.
            VIRTIO_ARGS=(
                -device "virtio-blk-pci,drive=disk0$suffix"
                -device "virtio-blk-pci,drive=disk1$suffix"
            )
            ;;
        one-disk)
            # The smallest machine that can take a fault. The fault tests want
            # the kernel to reach ring 3 and die there; a second disk and a NIC
            # would be two more things able to go wrong in a test about
            # something else.
            VIRTIO_ARGS=(-device "virtio-blk-pci,drive=disk0$suffix")
            ;;
        *)
            echo "qemu_device_list: unknown profile '$profile'" >&2
            return 1
            ;;
    esac
}

# The network, described once because both harnesses that have one need the same
# reasoning.
#
# QEMU's built-in user-mode network needs no privileges, no `tap`, and no host
# configuration, so every contributor gets the same network and CI needs no
# capabilities it does not already have. Its gateway answers ARP, which is what
# lets a driver containing no protocol code prove it can *receive*; it answers
# ICMP echo; and it runs a DHCP server, which is what `bin/dhcp` asks for an
# address.
#
# `restrict=on` because none of this needs to reach the outside world. A test
# that could talk to the internet would pass or fail depending on the machine it
# ran on, and a gate whose answer depends on the network is not a gate.
#
# Without a unit the driver has no address to give the device and stops at the
# handshake, which is the refusal working rather than a failure — so the NIC is
# in the `full` profile whether or not it is translated, and only one of those
# can drive it.
