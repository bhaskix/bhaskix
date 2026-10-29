# SPDX-License-Identifier: Apache-2.0
#
# The offline key machine's tools, for rehearsing the key ceremony (RFC 0091
# step 6) on a build host that is not that machine.
#
# **Ubuntu 26.04 on purpose**: the lead's offline machine runs 26.04 LTS (their
# decision of 2026-10-29), so the ceremony is rehearsed with the OpenSSL and
# sbsigntool it will really use, and CI's runner is 26.04 too. This build host
# is 20.04, whose OpenSSL is 1.1.1 and which packages neither virt-firmware --
# the OVMF variable-store editor the lane enrols certificates with -- nor a
# current pesign. QEMU stays outside, where the lane runs, as with swtpm.
#
# Base pinned by digest and every package by version, by
# tests/qemu/release-keys-test.sh, so a rebuild next month is the same tools.
ARG BASE
FROM ${BASE}
ARG OPENSSL_VERSION
ARG SBSIGNTOOL_VERSION
ARG VIRT_FIRMWARE_VERSION
ARG PESIGN_VERSION
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      "openssl=${OPENSSL_VERSION}" \
      "sbsigntool=${SBSIGNTOOL_VERSION}" \
      "python3-virt-firmware=${VIRT_FIRMWARE_VERSION}" \
      "pesign=${PESIGN_VERSION}" \
 && rm -rf /var/lib/apt/lists/*
