#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# A TPM 2.0 emulator for QEMU, run in a container -- RFC 0089 step 1.
#
#   tools/swtpm.sh start <dir>   start one; QEMU connects to <dir>/swtpm.sock
#   tools/swtpm.sh stop <dir>    stop the one started for <dir>
#
# QEMU then takes:
#   -chardev socket,id=chrtpm,path=<dir>/swtpm.sock
#   -tpmdev emulator,id=tpm0,chardev=chrtpm -device tpm-crb,tpmdev=tpm0
# and the -device line lives in tests/qemu/devices.sh, as the one-machine gate
# requires.
set -euo pipefail

# Pinned, so the emulator does not change under a measurement -- both read from
# the first build on 2026-10-07 (RFC 0089 step 1), not guessed. The version is
# the one apt resolved there, from 24.04's updates pocket. When the archive stops
# carrying it, the build fails loudly here; re-pin then, on purpose.
BASE="ubuntu:24.04@sha256:534baea6a22c03a63003dbc8dbe78fe34bc0d7e595d9a9dc9834884ff530eb55"
SWTPM_VERSION="0.7.3-0ubuntu5.24.04.1"
IMAGE="bhaskix-swtpm:${SWTPM_VERSION}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

command="${1:-}"; dir="${2:-}"
[[ -n "$command" && -n "$dir" ]] || { echo "usage: $0 start|stop <dir>" >&2; exit 2; }
mkdir -p "$dir"; dir="$(cd "$dir" && pwd)"
# One container per directory, named from it, so two lanes cannot share a TPM.
name="bhaskix-swtpm-$(printf '%s' "$dir" | sha256sum | cut -c1-12)"

case "$command" in
    start)
        docker image inspect "$IMAGE" >/dev/null 2>&1 \
            || docker build -q -t "$IMAGE" --build-arg BASE="$BASE" \
                   --build-arg SWTPM_VERSION="$SWTPM_VERSION" "$HERE/swtpm" >/dev/null
        mkdir -p "$dir/state"
        rm -f "$dir/swtpm.sock"
        docker run -d --rm --name "$name" -v "$dir:/tpm" "$IMAGE" \
            socket --tpm2 --tpmstate dir=/tpm/state \
            --ctrl type=unixio,path=/tpm/swtpm.sock --log level=1 >/dev/null
        # QEMU fails at once on a socket that is not there yet; wait for it.
        for _ in $(seq 50); do [[ -S "$dir/swtpm.sock" ]] && exit 0; sleep 0.1; done
        echo "swtpm did not create $dir/swtpm.sock" >&2; docker logs "$name" >&2 || true; exit 1 ;;
    stop)
        docker rm -f "$name" >/dev/null 2>&1 || true ;;
    *) echo "usage: $0 start|stop <dir>" >&2; exit 2 ;;
esac
