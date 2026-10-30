<!-- SPDX-License-Identifier: Apache-2.0 -->

# How Bhaskix works

**Verified** 2026-10-30 against `aa2dcc5`, by booting `make demo` and typing every command shown.

This page explains the five ideas the rest of the system is built from, each
with something to type that shows it. The design documents go deeper —
[architecture.md](../architecture.md) is the place to start — but you do not
need them to use Bhaskix.

## A small nucleus

The kernel — the **nucleus** — does as little as it can: it runs threads,
manages memory, delivers interrupts, and decides which program may do what.
Everything else is a program outside it: the console, the disk drivers, the
filesystem, the network stack, the shell, and the adapter that runs Linux
programs. A bug in any of those is a bug in one program, not in the kernel.

There is **no inference in the nucleus, ever**: the kernel takes no decision
from a model. Bhaskix's plans for AI are that a model may advise and the
kernel decides.

## Capabilities: what a program holds is what it can do

A **capability** is an unforgeable reference to something — a memory region, a
service, a directory, a device — together with what its holder may do with it.
A program starts with the capabilities its creator chose to give it, and that
is the whole of its authority. There is no `root`, and no table of users
deciding access: the question "may this program read that file?" is "does it
hold a capability to a directory containing it?".

`caps` shows what the shell holds — each slot, and what may be done through it:

```
bhaskix$ caps
  0  console   reachable
  1  files     reachable
  2  (nothing) no authority
  8  directory reachable, and answers no method it was not given
  1  badge     can be passed on, and cannot be changed by its holder
  10 stale dir the directory it named is gone
```

And asking for something without having been offered it is refused — here, the
shell asks the disk service for a capability without declaring a slot to
receive one:

```
bhaskix$ ask
  undeclared    nothing was handed over
  13 lent      a service handed over a page, and it reads 1af4:1042
  forbidden     a service cannot pass on what it may only hold
  13 lent      refused a writable mapping
```

A capability can be handed on, and taken back: revoking one revokes every copy
made from it, wherever it went.

## Domains: compartments for programs

A **domain** is a compartment: an address space, a set of capabilities, and an
envelope of resources — a hard cap on its memory, a share of the CPU, and a cap
on how many capabilities it may make. Every service runs in a domain of its own, and so does
every program the shell starts:

```
bhaskix$ spawn bin/probe
  started in a domain of its own
spawned, hello
  it ended: reason 1
```

Containers and virtual machines are meant to be the same thing — a domain
holding different capabilities — which is why Bhaskix does not have two
isolation mechanisms. Neither is built yet.

**Devices are confined too.** A device can read and write memory by itself
(DMA), so a driver in a domain is not enough on its own. Bhaskix programs the
machine's **IOMMU** so that each device can reach only the memory its driver was
given; the boot report says so for every device it finds.

## Services, and the Linux adapter

Programs talk to services by **calling** them: a synchronous message to an
endpoint capability, answered by the service, carrying data in small messages
or in shared memory both sides hold. The filesystem is a service; so are the
network stack, the console and the disk drivers.

**Linux programs** run as *hosted* programs. Their system calls do not reach the
kernel's own interface: they go to `bin/linuxd`, the Linux adapter, which
translates each one into calls to Bhaskix's services, using capabilities the
adapter holds. The pids, `fork`, signals and file descriptors a Linux program
sees are built by the adapter; the nucleus has none of them. Linux's `root` is
not Bhaskix authority — a hosted program that thinks it is uid 0 holds nothing
more for it. [Linux programs](linux-programs.md) shows one running.

## Networking

The network stack is three programs: `bin/netd` drives the network card,
`bin/ipd` speaks IPv4 and IPv6, ARP, ICMP and UDP, and `bin/tcpd` speaks TCP. A
program that wants a socket asks for one and receives it as a capability. The
shell's `net` command binds a socket, sends one datagram and gives the socket
back:

```
bhaskix$ net 10.0.2.2
  bound a socket, handed back as a capability
  sent a datagram through it
  closed it
  the closed socket is gone, and its slot may be somebody else's
```

## The boot report

Every boot ends with the machine testing itself, one line per check — hundreds
of them — before it hands you a prompt. **Every line is a claim it has just
tested.** Green lines passed; **red** ones failed, and say what they saw; yellow
ones are checks this machine could not make, and say why. The shell's `dmesg`
shows the report again:

```
bhaskix$ dmesg
…
  cpu
    gdt + tss      loaded (double fault and NMI on dedicated stacks)
    idt            loaded (256 vectors)
-- more -- (q quits)
```

A red line is worth reporting: [Troubleshooting](troubleshooting.md#red-lines-in-the-boot-report)
says how.

## Where to go next

- [The security model](security-model.md) says what all of this protects, and
  what it does not yet.
- [Write a program](write-a-program.md) runs a program of your own in a domain.
