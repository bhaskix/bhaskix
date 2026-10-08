# SPDX-License-Identifier: Apache-2.0
#
# A TPM 2.0 emulator for the measured-boot lanes (RFC 0089 step 1).
#
# **In a container, on purpose.** The build host is Ubuntu 20.04, which does not
# package swtpm, and building it there needs a dozen development packages
# installed system-wide. Ubuntu 24.04 packages it, and is what CI's runner
# installs from -- so the emulator here and the one in CI are the same build.
# QEMU stays on the host and reaches it through a socket in a shared directory.
#
# The base is pinned by digest and the package by version, both by
# `tools/swtpm.sh`, so a rebuild next month is the same emulator.
ARG BASE
FROM ${BASE}
ARG SWTPM_VERSION
RUN apt-get update \
 && apt-get install -y --no-install-recommends "swtpm=${SWTPM_VERSION}" \
 && rm -rf /var/lib/apt/lists/*
ENTRYPOINT ["swtpm"]
