<!-- SPDX-License-Identifier: Apache-2.0 -->

# Linux programs

**Verified** 2026-10-19 against `9a87171`, under QEMU 4.2.1, on the machine
[*A fuller machine*](get-started.md#a-fuller-machine-a-disk-and-a-network)
builds, with every command below run and its output copied from that run.

Bhaskix is not Linux, and it runs Linux programs. This guide starts an
unmodified Go web server on it, fetches a page from your own machine, and says
plainly what runs, how, and what is refused.

## What "hosted" means

A Linux program on Bhaskix is **hosted**: it runs in a domain of its own, and
its system calls are answered by `bin/linuxd`, an adapter that is itself an
ordinary program in ring 3. The kernel answers no Linux system call. The boot
report counts that on every boot:

```
    personality    boundary: 0 linux numbers interpreted in the nucleus (RFC 0031 wants 0); no in-nucleus call was priced -- none was made; all 911 of 911 accounted (0 preempted, 911 answered in ring 3)
```

What a Linux program can reach is what its domain was given, and nothing else.
Its **pid** is a number the adapter invents. Its **file descriptors** are
capabilities the adapter holds for it. Asked who it is, it is told it is
**uid 0** — because Linux programs expect to see that and compare against it —
and that answer carries no authority at all: nothing in Bhaskix reads it to
decide anything. Linux `root` is not Bhaskix authority.

## What runs

- **Static Linux programs.** There is no dynamic linker yet, so a program has
  to carry its own libc.
- **An unmodified Go `net/http` server**, built with Go 1.27.1 and carried by
  this release's ISO, which the rest of this guide runs.
- **BusyBox's `sh`**, for people who build Bhaskix from source — and only as
  far as [the last section](#busybox-if-you-build-from-source) shows, which in
  this preview is not far.

The boot report tests the adapter on every boot, with small Linux programs of
its own. On the fuller machine its `linux` lines include:

```
…
    linux stack    a Linux program walked the initial image this kernel built: argc 2, AT_ENTRY 0x20000000, and the sixteen AT_RANDOM bytes it found are the entropy that was put there
execed pid 3
    linux exec     a Linux program execed: its own domain ended and the program it became ran in another
through a pipe
    linux pipe     two hosted threads met through a pipe: the reader parked on an empty one, the writer woke it, and `through a pipe` crossed (attempt 1)
copied!
    linux fork     a Linux program forked: the child is pid 8, 16384 bytes of its parent's memory came with it -- including the code and stack the kernel mapped, which no supervisor ever saw -- out of the 4 frame(s) the parent held, and the child printed what its parent had written there
s=7
    linux wait     a Linux program forked, its child ended, and the parent collected pid 11 with status word 0x700
…
```

## Run the Go web server

Boot [*A fuller machine*](get-started.md#a-fuller-machine-a-disk-and-a-network),
with one change first: tell the kernel to start the server, through the
loader's command line.

```sh
printf 'cmdline=bhaskix.httpd=300\n' > esp/bhaskix/boot.conf
```

`bhaskix.httpd=300` starts `bin/httpd` in a Linux domain of its own and lets it
serve for 300 seconds, at most 3,600. The boot report waits while it serves:

```
    httpd          started: bin/httpd in a Linux domain, to serve for 300 s
httpd listening
httpd dial ok: 0.0.0.0:58543 -> 10.0.2.100:9, 16 bytes echoed
httpd dial refused ok: dial tcp 10.0.2.100:10: connect: connection refused
```

`httpd listening` is the server's own line, printed by Go. The two `dial`
lines are the server proving it can **dial out**: it connects to
`10.0.2.100:9`, which the fuller machine hands to `cat` on your computer, and
checks that its sixteen bytes come back; then it dials a port nobody listens on
and is refused, as it should be. It may dial only because the boot granted it
that — see [below](#what-is-refused-and-why).

Now, from **another terminal on your own machine**:

```
$ curl http://127.0.0.1:18080/
bhaskix /
$ curl http://127.0.0.1:18080/hello/from/your/machine
bhaskix /hello/from/your/machine
```

or open <http://127.0.0.1:18080/> in a browser — port 18080 on your machine is
the fuller machine's forward to the server's 8080. Every page answers with its
own path.

When its time is up, the report says what the server did, and the boot goes on
to the shell:

```
    httpd          during its run: 0 park(s) refused, 0 ran out of retries, 0 unarmed, 0 ungranted, 0 unnamed; 0 deadline arm(s) refused for want of a slot, at most 4 of 16 armed at once this boot; the last park refused named slot 0xffffffffffffffff; the fault path's frame reserve ran dry 1 time(s), 1 of them served by a refill on the spot
    httpd          copies during its run: 299 in (5446 bytes, 26146384 cycles), 538 out (10411 bytes, 49742018 cycles); 90667 cycles per crossing
    httpd          MADV_DONTNEED this boot: 1 discard(s) dropping 1 frame(s), 1 refused
    httpd          0 thread(s) resumed from a register image during its run (signal deliveries and returns)
    httpd          its most-asked calls, number x count: 228x433 35x150 13x114 202x112 24x37 157x26 9x26 281x21
    httpd          still serving after 300 s and the host's load: 1069 calls, refused -ENOSYS: 157 234
```

`refused -ENOSYS` lists, by Linux system-call number, what the server asked for
that the adapter answered with `ENOSYS`; Go carries on without it.

## What is refused, and why

- **Dialling out needs a grant.** A hosted program may connect to another
  machine only if its domain was given that right; the Go server is, and the
  adapter's own tests check that a program without the grant is refused with
  `EACCES`.
- **No IPv6 dials.** A hosted program's IPv6 `connect` is answered
  `ENETUNREACH`. IPv4 works, including `127.0.0.1`.
- ~~**A listener cannot be closed.** A hosted server that closes its listening
  socket keeps its port for the rest of the boot, and the adapter has three
  listening sockets to give out in a whole boot.~~ *Corrected 2026-10-20*:
  **a listener can be closed**, and its port is free at once
  ([RFC 0092](../rfc/0092-a-listener-that-can-be-closed.md); checked by the
  project's own tests, not yet by a transcript in this guide). What remains:
  the adapter has **three listening sockets at once**, and one you closed keeps
  its place until every connection it accepted has ended.
- **No dynamic linking, and no application milestone.** The Linux
  compatibility milestones, L1 to L4, are all unmet: nginx, PostgreSQL, MariaDB
  and OpenSSH have never run here. See the
  [roadmap](../roadmap.md#linux-compatibility--l1-to-l4).

## BusyBox, if you build from source

This release's ISO does not carry BusyBox. It is GPL-2.0, and shipping its
binary would oblige the project to publish its source. A build from source
fetches one: Ubuntu's `busybox-static` 1:1.37.0-7ubuntu1, the plain amd64
build, checked against the sha256 in `tools/fetch-busybox.sh` before it is
unpacked. `make iso BUSYBOX_SRC=/path/to/busybox` uses another statically
linked one instead — but not an x86-64-v3 build, such as Ubuntu 26.04's
`amd64v3` variant. Bhaskix does not enable AVX, and that build stops at its
first AVX instruction.

To try it, build from source, then boot the ISO
you built through Bhaskix's own loader, as in
[*Get started*](get-started.md#through-bhaskixs-own-loader) — the plain machine
is enough — with one option:

```sh
printf 'cmdline=busybox=sh\n' > esp/bhaskix/boot.conf
```

`busybox=sh` hands the keyboard to BusyBox's own `sh`, in a Linux domain,
before the Bhaskix shell starts. Its prompt is `/ #`. `exit` gives the keyboard
back, and the boot goes on to `bhaskix$`. This section was re-verified on
2026-10-29 with the pinned BusyBox 1.37.0, on the change that pinned it (it was
`7d710cc` on 2026-10-20, with the build machine's 1.30.1, after the fix
described below):

```
BusyBox v1.37.0 (Ubuntu 1:1.37.0-7ubuntu1) built-in shell (ash)
Enter 'help' for a list of built-in commands.

sh: can't access tty; job control turned off
/ # echo hello from busybox
hello from busybox
/ # pwd
/
/ # uname -a
sh: can't fork: Function not implemented
/ # exit
    busybox      297 calls, asked: 12 12 158 218 273 334 302 318 228 228 267 12 12 12 10 157 102 39 13 110 63 79 16 16 13 13 13 13 13 13 13 5 16 1 1 1 1 1 257 16 72 16 1 1 1 3 262 16 16 16 16 107 257 107 1 7 1 13 7 0 7 0 7 0 (and 233 more)
```

**A newer BusyBox needed one more answer.** 1.37.0's C library asks whether
the console is a terminal with `TCGETS2` rather than `TCGETS`. Until
2026-10-29 the adapter refused that request, so `sh` concluded it had no
terminal and ran with no banner and no prompt, waiting for whole lines. The
adapter now answers both requests the same way.

**`sh`'s own commands run; a command that needs a new process does not, yet.**
`echo` and `pwd` above are two of `sh`'s builtins. `uname` is not, and is refused
— `sh: can't fork: Function not implemented` — because `sh` asks the adapter for
a kind of `clone` that makes a process, and the adapter so far makes only
threads. That is filed in TRACKER as L1 work.

Until 2026-10-20 `sh` did not even get that far: the kernel put it down two
seconds after starting it, at its second prompt, which a person reading the
first answer always reached. It now runs until `exit`, and the project's own
BusyBox test types a second line after a pause to keep it that way.
