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

# The negative fixtures. They violate on purpose -- a service that depends on
# the kernel, which tools/check-placements.sh has to be seen rejecting -- so a
# gate that also rejected them would make `make gates` unrunnable and the
# fixture would have to be deleted, which is exactly how a gate loses the one
# test that proves it works.
SKIP_PATHS = ("tests/fixtures/",)

# Layer index: a crate may depend only on strictly lower layers.
LAYERS = {
    # The interface between the kernel and the programs it runs. Below
    # everything, because it is compiled into both sides: anything it depended
    # on would become part of the interface too.
    "bhaskix-abi": -2,

    # The service framework, and the services compiled against it. Between the
    # ABI and everything else: a service crate may reach these two and nothing
    # more, which is the property RFC 0013 rests on and which
    # tools/check-placements.sh checks against services.toml. The layering
    # here is the same rule stated once more, in the place that would catch a
    # dependency added to a service crate by hand.
    # Registers and their accessors. Below everything that drives hardware and
    # above nothing: it depends on no crate at all, because every driver
    # compiles against it -- in the kernel, in a domain, and in a host test.
    "bhaskix-device": -2,
    # The on-disk format: arithmetic over a byte slice, reachable from the
    # kernel, from a service in a domain, and from a host tool. Depends on
    # nothing, for the same reason the device crate does not.
    "bhaskix-fs": -2,
    # The wire formats, and the same argument exactly. This entry read `4` from
    # M1 until 2026-08-12 -- a number reserved before there was a design, on the
    # assumption that a network stack sits above the kernel the way a driver
    # does. RFC 0018 put the protocol code in a domain of its own, which makes
    # it what `bhaskix-fs` is: arithmetic over a byte slice, reachable from a
    # service, from a host test and from a fuzz target, and therefore able to
    # depend on none of them. Layer 4 would have permitted a dependency on the
    # kernel, which is the one thing this crate must never acquire.
    "bhaskix-net": -2,
    # The system's only source of unpredictability, RFC 0021, and the same
    # argument a third time: it must be reachable from the kernel, from a ring 3
    # service and from a host test, so it depends on nothing. `arch` depends on
    # *it* rather than the other way round -- a layer above may reach down, and
    # a ring 3 program that depended on `arch` would be a category error.
    "bhaskix-rand": -2,
    "bhaskix-service": -1,
    "bhaskix-service-domain": 0,
    "bhaskix-service-console": 0,
    "bhaskix-service-vfs": 0,

    "bhaskix-boot": 0,        # pure types, depends on nothing
    "bhaskix-arch-x86-64": 0,  # arch -> nothing
    "bhaskix-mm": 1,
    "bhaskix-sched": 2,
    "bhaskix-kernel": 3,

    "bhaskix-drivers": 4,
    "bhaskix-boot-shim": 5,    # the binary, top of the graph

    # The fuzz target, above everything because it drives the kernel's parsers
    # from outside. It is a host binary in its own workspace and no kernel build
    # links it, so nothing may ever depend on it -- which the layer rule already
    # enforces by giving it the highest number.
    "bhaskix-fuzz": 6,

    # User programs. Layer -1 because they are not in the kernel's graph at
    # all: they run in ring 3 and reach it only through system calls, so a
    # dependency on any kernel crate would be a category error rather than a
    # layering violation. The only thing they may depend on is the ABI, which
    # is why that sits lower still.
    "bhaskix-user-probe": -1,
    "bhaskix-user-shell": -1,
    # The network driver. A plain program like the others: it holds
    # capabilities and reaches the kernel only through system calls. It depends
    # on the ABI and on `bhaskix-device` for the virtqueue -- and deliberately
    # **not** on `bhaskix-net`, because linking the protocol parsers into the
    # domain that holds this device's DMA authority is the arrangement RFC 0018
    # rejected. Nothing enforces that but this comment and the manifest; the
    # layer rule would permit it, since `bhaskix-net` sits below.
    "bhaskix-user-netd": -1,
    # The protocol service. It holds rings, a report page and a configuration
    # page: no device, no DMA window, no interrupt.
    #
    # **The rule about who may link `bhaskix-net` is restated here**, because
    # the first version of it was "only `ipd`" and that was a description of the
    # moment rather than a rule: `ipd` was the only program that had a socket.
    # The shell has one since RFC 0018 step 5, and a DHCP client is protocol
    # code.
    #
    # What the rule protects is that **a parser bug must not be turnable into
    # hardware pointed anywhere**. So the line is: a program linking
    # `bhaskix-net` may hold no *writable* device authority -- no DMA window, no
    # writable register window, no interrupt. `bhaskix-user-netd` fails that and
    # deliberately does not link it. `ipd` holds no device at all; the shell
    # holds one read-only page of configuration space, and reading a BAR grants
    # nothing.
    #
    # The layer rule permits any of them; this comment and the manifests are
    # what hold the line, which is worth knowing rather than assuming.
    "bhaskix-user-ipd": -1,
    # The DHCP client. Four capabilities: an endpoint, the slot a socket lands
    # in, one page and a report page. It links `bhaskix-net` under the rule
    # above -- no device, no DMA window, no interrupt -- and it exists as its own
    # program rather than a shell command precisely so that stays true.
    "bhaskix-user-dhcp": -1,
    # The TCP service, RFC 0020 step 4. It links `bhaskix-net` under the same
    # rule -- two rings, a report page, a configuration page, an endpoint and a
    # timer; no device, no DMA window, no interrupt -- and `bhaskix-rand`,
    # because the initial sequence number's secret is drawn at start and the
    # service refuses to serve without one. TCP is the largest remote-driven
    # *stateful* parser this system will contain, which is exactly why it is a
    # separate program with this short a capability list.
    "bhaskix-user-tcpd": -1,
    # The TCP demonstration client, RFC 0022 step 4: the first program to
    # open a connection with rings its own domain owns, handed across
    # CONNECT. It links nothing but the ABI, and that absence is the claim --
    # what it demonstrates is the *exchange*, and an exchange that needed
    # protocol code on the client side would be the wrong exchange.
    "bhaskix-user-tcpc": -1,
    # The supervisor places no service: it creates domains, starts programs in
    # them and reaps them, all through capability invocations. So it belongs
    # here with the other plain programs rather than in PLACEMENTS -- and that
    # it needs nothing but the ABI is the whole claim RFC 0017 question 2
    # makes, that a restart policy is writable in userspace with no new kernel
    # mechanism.
    "bhaskix-user-sup": -1,
}

# Programs that *place* a service, and exactly what each may reach.
#
# Enumerated rather than derived from a layer, because the layer rule cannot
# say what is actually true of these: a placement program may depend on the
# service crates and the framework, and on nothing else the kernel uses. The
# service crates sit at the same layer as `arch`, so any layer number that let
# one of them through would let `arch` through too -- and a ring 3 program that
# depended on `arch` would be a category error, not a layering violation.
#
# A new entry here is a new program that runs a service somewhere. That should
# be a deliberate line in this file, which is why it is a list and not a rule.
PLACEMENTS: dict[str, set[str]] = {
    "bhaskix-user-vfsd": {
        "bhaskix-abi",
        "bhaskix-service",
        "bhaskix-service-domain",
        "bhaskix-service-vfs",
    },
    # The block driver shares no code with the kernel's, only the
    # specification, so the ABI is the whole of what it may reach.
    "bhaskix-user-blkd": {"bhaskix-abi", "bhaskix-device"},
    # The filesystem, unlike the driver, **is** the kernel's own code: it
    # depends on `bhaskix-fs`, the same crate the kernel links. That is the
    # point of it -- one parser, two places -- and it is why this entry names
    # the crate rather than pretending the service is independent of it.
    "bhaskix-user-fsd": {"bhaskix-abi", "bhaskix-fs"},
    "bhaskix-user-consoled": {
        "bhaskix-abi",
        "bhaskix-service",
        "bhaskix-service-domain",
        "bhaskix-service-console",
    },
}

# Third-party crates permitted in the tree. Empty on purpose: Bhaskix has no
# external dependencies, and adding the first one should require a
# conversation, which an empty allowlist guarantees.
# The one exception, and it is scoped as narrowly as an exception can be.
#
# `docs/security.md` §1 treats a dependency as attack surface, and the shipped
# kernel still has none: this crate is reachable only from `fuzz/`, which is its
# own workspace, builds only for the host, needs a nightly sanitizer runtime,
# and is never linked into anything that boots. `cargo build` does not pull it
# in; `cargo fuzz` does, explicitly.
#
# It buys what a seeded harness cannot. `coding-style.md` §8 asks for a fuzz
# target on every untrusted parser, and TRACKER recorded a deviation from M6-03
# onwards because the requirement was met by blind mutation. Coverage guidance
# found 2,054 inputs reaching new paths in `elf::parse` in two hours; twelve
# billion blind images over three hours found none the harness had not already
# seen.
#
# Anything added here needs the same standard: host-only, out of the boot
# graph, and worth more than the surface it adds.
ALLOWED_EXTERNAL: set[str] = {"libfuzzer-sys"}

RED, GREEN, RESET = "\033[1;31m", "\033[1;32m", "\033[0m"


def manifests() -> list[pathlib.Path]:
    return [
        m for m in REPO.rglob("Cargo.toml")
        # Dot-directories are skipped by prefix rather than by name, so this
        # script contains no string the vendor check would reject.
        if not any(part in SKIP or part.startswith(".") for part in m.parts)
        and not str(m.relative_to(REPO)).startswith(SKIP_PATHS)
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
        if crate in PLACEMENTS:
            for dep in sorted(set(deps) - PLACEMENTS[crate]):
                print(f"{RED}FAIL{RESET}  {crate} depends on '{dep}', which a placement "
                      "program may not reach.")
                print("        A program that places a service may depend on the service")
                print("        crates and the framework, and on nothing else.")
                status = 1
            continue

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
