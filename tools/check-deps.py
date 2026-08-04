#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Enforce the crate dependency direction from docs/architecture.md §5.

    arch  -> (nothing)
    mm    -> arch
    sched -> arch, mm
    kernel-> arch, mm, sched
    services (fs, net, drivers) -> kernel

Cycles are a build failure, not a review comment: a kernel whose crates depend
on each other circularly cannot be built in pieces, cannot be tested in
isolation, and cannot have a subsystem replaced without touching everything.

Also rejects any third-party dependency that has not been explicitly allowed.
A kernel's dependency graph is its supply-chain attack surface
(docs/security.md §1), so growth should be a decision, not an accident.
"""

from __future__ import annotations

import pathlib
import re
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent
SKIP = {"target", "build", "limine"}

# Layer index: a crate may depend only on strictly lower layers.
LAYERS = {
    "bhaskix-boot": 0,        # pure types, depends on nothing
    "bhaskix-arch-x86-64": 0,  # arch -> nothing
    "bhaskix-mm": 1,
    "bhaskix-sched": 2,
    "bhaskix-kernel": 3,
    "bhaskix-fs": 4,
    "bhaskix-net": 4,
    "bhaskix-drivers": 4,
    "bhaskix-boot-shim": 5,    # the binary, top of the graph

    # User programs. Layer -1 because they are not in the graph at all: they
    # run in ring 3 and reach the kernel only through system calls, so a
    # dependency on any kernel crate would be a category error rather than a
    # layering violation. Zero is the correct number of dependencies here, and
    # a lower layer than everything is how this script says so.
    "bhaskix-user-probe": -1,
}

# Third-party crates permitted in the tree. Empty on purpose: Bhaskix has no
# external dependencies, and adding the first one should require a
# conversation, which an empty allowlist guarantees.
ALLOWED_EXTERNAL: set[str] = set()

RED, GREEN, RESET = "\033[1;31m", "\033[1;32m", "\033[0m"


def manifests() -> list[pathlib.Path]:
    return [
        m for m in REPO.rglob("Cargo.toml")
        # Dot-directories are skipped by prefix rather than by name, so this
        # script contains no string the vendor check would reject.
        if not any(part in SKIP or part.startswith(".") for part in m.parts)
    ]


def main() -> int:
    status = 0
    graph: dict[str, list[str]] = {}

    for manifest in manifests():
        text = manifest.read_text()
        name_match = re.search(r'^\s*name\s*=\s*"([^"]+)"', text, re.M)
        if not name_match:
            continue
        name = name_match.group(1)

        # Only the [dependencies] table; dev-dependencies may differ.
        section = re.search(r"^\[dependencies\]\s*$(.*?)(?=^\[|\Z)", text, re.M | re.S)
        deps = []
        if section:
            for line in section.group(1).splitlines():
                match = re.match(r'^\s*([A-Za-z0-9_-]+)\s*=', line)
                if match:
                    deps.append(match.group(1))
        graph[name] = deps

    for crate, deps in sorted(graph.items()):
        if crate not in LAYERS:
            print(f"{RED}FAIL{RESET}  {crate}: not listed in the layer map in this script.")
            print("        Add it, so its allowed dependencies are an explicit decision.")
            status = 1
            continue

        for dep in deps:
            if dep not in LAYERS:
                if dep not in ALLOWED_EXTERNAL:
                    print(f"{RED}FAIL{RESET}  {crate} depends on external crate '{dep}'")
                    print("        Add it to ALLOWED_EXTERNAL with justification in the PR")
                    print("        (docs/security.md §1: dependencies are attack surface).")
                    status = 1
                continue

            if LAYERS[dep] >= LAYERS[crate]:
                print(f"{RED}FAIL{RESET}  {crate} (layer {LAYERS[crate]}) depends on "
                      f"{dep} (layer {LAYERS[dep]})")
                print("        Dependencies must point strictly downward; see")
                print("        docs/architecture.md §5.")
                status = 1

    if status == 0:
        print(f"{GREEN}ok{RESET}    dependency direction and no external crates")
        for crate, deps in sorted(graph.items()):
            arrow = ", ".join(deps) if deps else "(nothing)"
            print(f"        {crate:<22} -> {arrow}")

    return status


if __name__ == "__main__":
    raise SystemExit(main())
