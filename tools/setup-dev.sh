#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Bhaskix development environment setup.
#
# Installs the toolchain needed to build and boot Bhaskix. Safe to re-run:
# every step checks before it acts, and nothing is removed or overwritten.
#
# Usage:
#   tools/setup-dev.sh            # install everything
#   tools/setup-dev.sh --check    # report what is missing, install nothing
#
# The exit criterion for Phase 0 (docs/roadmap.md) is that a new contributor
# can run this script followed by `make run` and get a QEMU window.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIMINE_BRANCH="v8.x-binary"
LIMINE_DIR="${REPO_ROOT}/boot/limine/limine"

CHECK_ONLY=0
[[ "${1:-}" == "--check" ]] && CHECK_ONLY=1

missing=()

say()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
ok()   { printf '  \033[1;32m[ok]\033[0m   %s\n' "$*"; }
need() { printf '  \033[1;33m[need]\033[0m %s\n' "$*"; missing+=("$1"); }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# 1. Host packages
# ---------------------------------------------------------------------------
say "Checking host packages"

declare -A PKGS=(
    [qemu-system-x86_64]="qemu-system-x86"   # boot and test the kernel
    [xorriso]="xorriso"                       # build the bootable ISO
    [mformat]="mtools"                        # build the EFI system partition
    [git]="git"
    [make]="make"
    [curl]="curl"
)

apt_pkgs=()
for cmd in "${!PKGS[@]}"; do
    if command -v "$cmd" >/dev/null 2>&1; then
        ok "$cmd"
    else
        need "$cmd (package: ${PKGS[$cmd]})"
        apt_pkgs+=("${PKGS[$cmd]}")
    fi
done

if (( ${#apt_pkgs[@]} > 0 && CHECK_ONLY == 0 )); then
    if command -v apt-get >/dev/null 2>&1; then
        say "Installing: ${apt_pkgs[*]}"
        sudo apt-get update -qq
        sudo apt-get install -y "${apt_pkgs[@]}"
    else
        die "Missing packages and no apt-get. Install manually: ${apt_pkgs[*]}
     Fedora:  sudo dnf install qemu-system-x86 xorriso mtools git make curl
     Arch:    sudo pacman -S qemu-system-x86 xorriso mtools git make curl
     macOS:   brew install qemu xorriso mtools"
    fi
fi

# ---------------------------------------------------------------------------
# 2. Rust toolchain (version comes from rust-toolchain.toml — never pinned here)
# ---------------------------------------------------------------------------
say "Checking Rust toolchain"

if command -v rustup >/dev/null 2>&1; then
    ok "rustup"
else
    need "rustup"
    if (( CHECK_ONLY == 0 )); then
        say "Installing rustup (https://sh.rustup.rs)"
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
        # shellcheck disable=SC1091
        source "${HOME}/.cargo/env"
    fi
fi

if (( CHECK_ONLY == 0 )) && command -v rustup >/dev/null 2>&1; then
    # rustup reads rust-toolchain.toml and installs the pinned channel,
    # components, and the x86_64-unknown-none target automatically.
    say "Syncing toolchain from rust-toolchain.toml"
    ( cd "$REPO_ROOT" && rustup show active-toolchain )
    ok "toolchain matches rust-toolchain.toml"
fi

# ---------------------------------------------------------------------------
# 3. Limine bootloader
#
# Fetched, not vendored — it is a build-time dependency behind our own
# Handoff struct (docs/architecture.md §1), and boot/ is the only part of
# the tree permitted to know it exists.
# ---------------------------------------------------------------------------
say "Checking Limine bootloader"

if [[ -d "$LIMINE_DIR" ]]; then
    ok "limine present at boot/limine/limine"
    if (( CHECK_ONLY == 0 )); then
        git -C "$LIMINE_DIR" pull --quiet --ff-only || true
    fi
else
    need "limine (${LIMINE_BRANCH})"
    if (( CHECK_ONLY == 0 )); then
        say "Cloning Limine ${LIMINE_BRANCH}"
        git clone --branch "$LIMINE_BRANCH" --depth 1 \
            https://github.com/limine-bootloader/limine.git "$LIMINE_DIR"
        make -C "$LIMINE_DIR"
    fi
fi

# ---------------------------------------------------------------------------
# 4. Optional: OVMF firmware for UEFI boot testing
# ---------------------------------------------------------------------------
say "Checking UEFI firmware (OVMF) for QEMU"

if ls /usr/share/OVMF/OVMF_CODE*.fd >/dev/null 2>&1 \
   || ls /usr/share/ovmf/OVMF.fd     >/dev/null 2>&1 \
   || ls /usr/share/edk2*/*/OVMF_CODE*.fd >/dev/null 2>&1; then
    ok "OVMF"
else
    need "ovmf (UEFI boot testing; BIOS boot still works without it)"
    if (( CHECK_ONLY == 0 )) && command -v apt-get >/dev/null 2>&1; then
        sudo apt-get install -y ovmf
    fi
fi

# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------
echo
if (( CHECK_ONLY == 1 )); then
    if (( ${#missing[@]} == 0 )); then
        say "Environment complete. Run: make run"
    else
        say "Missing ${#missing[@]} item(s). Re-run without --check to install."
        exit 1
    fi
else
    say "Setup complete."
    echo
    echo "  make        build the kernel and a bootable ISO"
    echo "  make run    boot it in QEMU"
    echo "  make test   host unit tests + QEMU integration tests"
    echo
    echo "Start here: docs/roadmap.md  ·  docs/coding-style.md before your first PR."
fi
