<!-- SPDX-License-Identifier: Apache-2.0 -->

# The shell and packages

**Verified** 2026-10-19 against `9a87171`, under QEMU 4.2.1, on the machine
[*A fuller machine*](get-started.md#a-fuller-machine-a-disk-and-a-network)
builds, with every command below typed at it and its output copied from that
session.

Bhaskix's shell looks like a Unix shell and is not one. It is an ordinary
program in ring 3, and **it can do nothing it does not hold a capability for**:
no `root`, no `sudo`, no way to ask for more. This guide goes through what it
holds, the files it can reach, installing and running a package, and the
kernel's own shell for operators.

Boot the fuller machine with no options — an empty `boot.conf` — and wait for
`bhaskix$`:

```sh
printf 'cmdline=\n' > esp/bhaskix/boot.conf
```

## What the shell holds

```
bhaskix$ caps
  0  console   reachable
  1  files     reachable
  2  (nothing) no authority
  8  directory reachable, and answers no method it was not given
  1  badge     can be passed on, and cannot be changed by its holder
  10 stale dir the directory it named is gone
```

Each line is a slot and what the kernel answered when the shell asked it a
question no service answers. On this machine the shell holds the console, the
boot image's files, and — because there is a disk — a **directory** on the
writable filesystem (slot 8). Slot 2 is empty on purpose: its refusal comes from
the kernel before any service is reached. The **badge** line is the shell
passing its `files` capability on, which works, and changing the badge the
kernel stamped on it, which the kernel refuses. Slot 10 held a directory that
no longer exists, and the filesystem says so instead of answering for it.

## Files

`ls` and `cat` reach the boot image's files, read-only:

```
bhaskix$ ls /
       228  README
         0  bin/
         0  etc/
    131072  fs.img
     20480  greedy.bpk
     20480  hello.bpk
        31  hello.txt
        79  motd
         0  packages/
bhaskix$ ls etc
         8  hostname
bhaskix$ cat hello.txt
Hello from the Bhaskix initrd.
```

`open` is different: it resolves **one name inside the directory the shell
holds** — not a path, and never upward. Ask for a name outside it, a path, or
`..`, and the answer is that no such thing can be asked for:

```
bhaskix$ open greeting
  greeting: no such name in this directory
bhaskix$ open sub/inner
  sub/inner: not a name this system resolves
bhaskix$ open ..
  ..: not a name this system resolves
bhaskix$ open inner
  inner: a file of 40 bytes, at slot 9
  9  lent      the service's own cache page, and it begins "only rea"
  11 lent page refused a writable mapping
```

When a name resolves, the filesystem service **lends** the shell the page of
its own cache that holds the file, mapped read-only. `held` reads that page
again later; `release` gives it back, after which it cannot be mapped again —
and `held` says there is nothing to read:

```
bhaskix$ held
  held          the lent page still begins "only rea"
bhaskix$ release
  release       given back, 0 pages still lent
  released page can no longer be mapped
bhaskix$ held
  held          nothing is lent: 'open' a name in the directory first
```

## Packages

A package is **a program plus the authority it asks for, in one reviewable
file**. The demonstration package's manifest, as it is written in the
repository:

```
package hello
version 0.1.0

program bin/hello
entry hertz
cap console
```

`cap console` is the whole of its authority: when it runs, it is given the
console and nothing else. The image carries it as `hello.bpk`.

```
bhaskix$ pkg list
  0 installed
bhaskix$ pkg install hello.bpk
  verified   hello 0.1.0 -- 1 files, 20480 bytes, digests good
  installed  /pkg/hello -- 15408 payload bytes through the journal in 5 writes, 311500646 cycles
bhaskix$ pkg list
  hello
  1 installed
bhaskix$ pkg run hello
  running    hello (15408 bytes, grants from its manifest)
namaste from an installed package
  it ended cleanly
```

`pkg install` checks every file against the digests in the package before it
writes anything, and writes through the filesystem's journal. `pkg run` starts
the program in a domain of its own, with exactly what its manifest asks for,
and waits for it to end.

A digest proves a file arrived intact; it does not prove who made it. Packages
are not signed in this preview.

**A package that asks for too much is refused whole.** `greedy.bpk` is the same
program with one more line, `cap dma-window` — direct access to memory through a
device, which the shell holds no right to give:

```
bhaskix$ pkg install greedy.bpk
  verified   greedy 0.1.0 -- 1 files, 20480 bytes, digests good
  installed  /pkg/greedy -- 15408 payload bytes through the journal in 5 writes, 312403376 cycles
bhaskix$ pkg run greedy
  pkg: the manifest asks for authority this shell does not hold -- refused whole, nothing granted
bhaskix$ pkg remove greedy
  removed    greedy -- 185334830 cycles through the journal
bhaskix$ pkg remove hello
  removed    hello -- 140485876 cycles through the journal
bhaskix$ pkg list
  0 installed
```

Nothing ran and nothing was granted: the refusal comes before any domain
exists.

**What you install stays.** The writable filesystem is kept from one boot to
the next, so a package installed once is there afterwards. (Until 2026-10-30
every boot formatted it and nothing survived a reboot;
[RFC 0095](../rfc/0095-a-disk-that-keeps-what-was-written.md) changed that.)
Re-run that day with `make demo` twice, the second run on the disk the first
one left. Installed on the first:

```
bhaskix$ pkg install hello.bpk
  verified   hello 0.1.0 -- 1 files, 20480 bytes, digests good
  installed  /pkg/hello -- 15408 payload bytes through the journal in 5 writes, 3416387972 cycles
bhaskix$ pkg list
  hello
  1 installed
```

and on the second, whose boot report says the disk was kept rather than
formatted:

```
    disk journal   kept: this disk already held this system's filesystem, so it was mounted and not formatted -- mounting replayed 0 blocks, a file was written, read back and removed through the journal in 21 device writes, and the programs this boot stages were replaced; /pkg is as the last boot left it
```

```
bhaskix$ pkg list
  hello
  1 installed
bhaskix$ pkg run hello
  running    hello (15408 bytes, grants from its manifest)
namaste from an installed package
  it ended cleanly
```

`make demo-fresh` starts from a new disk. `/tmp` is the exception: it is
emptied at every boot, as a Linux system's is.

## The rest of the commands

```
bhaskix$ ask
  undeclared    nothing was handed over
  13 lent      a service handed over a page, and it reads 1af4:1042
  forbidden     a service cannot pass on what it may only hold
  13 lent      refused a writable mapping
bhaskix$ map
  3  memory rw  mapped and holds what was written
  4  memory ro  refused a writable mapping
  5  device ro  status 15
  5  device rw  refused a writable mapping
bhaskix$ input
  serial    252 bytes, 0 dropped
  keyboard  0 bytes from 0 i8042 scancodes, 0 dropped
  interrupts 24 delivered the above
bhaskix$ irq
  6  signal rd  woke with badge 45324, set aside by an earlier wait for a program's ending
  6  signal rd  nothing left after taking it
  7  signal wr  refused a take
  7  signal wr  refused a deadline that could ring nobody
bhaskix$ net 10.0.2.2
  bound a socket, handed back as a capability
  sent a datagram through it
  closed it
  the closed socket is gone, and its slot may be somebody else's
bhaskix$ spawn bin/probe
  started in a domain of its own
spawned, hello
  it ended: reason 1
```

- `ask` asks the block service for a capability, and is refused until a slot
  is declared to receive it — a service cannot put a capability where it was
  not invited.
- `map` maps memory the shell holds, and is refused memory it does not.
- `input` says what reached the console, and from where.
- `irq` waits for a notification, and reports the badge it carried. The boot
  rings it once; if a wait for a program's ending took that ring first, as
  `pkg run` did above, `irq` reports it as set aside rather than waiting.
- `net` binds a socket through the network service and sends one datagram.
- `spawn` starts a program from the boot image in a domain of its own.
- `dmesg` shows the boot report again, a page at a time; `q` stops it.
- `exit` ends the shell. The machine goes on without it.

## The kernel's shell, for operators

There is a second shell, inside the kernel. It is **an operator's tool and a
debugging aid, not a security boundary**: it holds no capability and asks no
permission, and it has no command that changes anything. Its prompt is
`bhaskix>`. Ask for it with:

```sh
printf 'cmdline=shell=kernel\n' > esp/bhaskix/boot.conf
```

It starts while the boot report is still finishing, so its first prompt can share
a line with the report's last, and what you type there appears on the line
below:

```
bhaskix>   Bring-up complete. Nothing left to do at this milestone.
help
  commands
    help              this list
    echo <words>      print the arguments
    ls [path]         list a directory in the initrd
    cat <path>        print a file
    readelf <path>    what the ELF loader makes of a file
    free              physical memory and the kernel heap
    ps                threads, by cpu
    uptime            time since the kernel started
    input             console input statistics
    lsblk             the block device, if there is one

  this shell is the kernel: it holds no capability and asks
  permission for nothing. the user-mode shell, the default,
  holds capabilities and asks.
bhaskix> ps
   cpu   id  state     class     runs  moves  name
     0    3  ready  fair      1217      0  boot
     0   76  running  fair         3      0  shell
     1    0  running  idle        77      0  idle
     1   68  finished  fair        41      0  deadline-load
     2    1  running  idle       961      0  idle
     2   36  blocked  fair       768      0  linuxd
     2   69  finished  fair        41      0  deadline-load
     3    2  running  idle      1098      0  idle
     3   27  blocked  fair         4      0  watchdog
     3   70  finished  fair        43      0  deadline-load
bhaskix> free
  frames  107501 free (419 MiB), 107716 available including per-cpu reserves
  reserve 215 frames held, 256 refills, 41 hits, 0 misses
bhaskix> uptime
  up 13.925 seconds, 4420 timer ticks
bhaskix> lsblk
  virtio-blk at 00:02.0, 13660 sectors (6830 KiB)
  status 0x0f, 8 requests completed, 0 timed out
  sector 0 is a ustar header
bhaskix> ls
       228  README
         0  bin/
         0  etc/
    131072  fs.img
     20480  greedy.bpk
     20480  hello.bpk
        31  hello.txt
        79  motd
         0  packages/
bhaskix> readelf bin/probe
  entry 0x10000000, 3 segments
    0x0010000000     1168 bytes in memory,    1168 in file  r-x
    0x0010001000        8 bytes in memory,       8 in file  r--
    0x0010002000        8 bytes in memory,       0 in file  rw-
```

`ps` is here and not in the user-mode shell for that reason: listing every
thread on the machine is a kernel's view, and the user-mode shell holds no
capability that would show it.
