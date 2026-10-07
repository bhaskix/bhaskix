# RFC 0086: The motivating workload — a Go HTTP server under load

| | |
|---|---|
| **Status** | ✅ **ACCEPTED 2026-10-04 by the project lead.** Drafted 2026-09-30 — **~~steps 1, 2, 3a and 3b done~~ ~~steps 1–4 done, step 5 built and not yet passing~~ ~~steps 1–5 done~~ all six steps done** (this cell read "3b" through step 4's landing; corrected 2026-10-01; steps 5 and 6 the same day). The workload RFC 0005 was owed from outside is named, its gate defined, its size measured and its system calls traced; `bin/tcpd` holds a table of thirty-two connections and a listener arms ring pairs, gated by four host clients held at once. `tcpd` serves a second listener opened by any program, and names a connection's peer; a hosted Linux program listens, accepts and echoes a host client through `bin/linuxd`; `epoll` works edge-triggered; and **the Go server serves sixteen keep-alive clients for five minutes, every body checked, zero errors** — thirty seconds on every push, three hundred nightly. ~~It corrupted its own memory on longer runs~~ — found and fixed 2026-10-01: the kernel refused every `MADV_DONTNEED`. Step 6's record says the gate is met, against RFC 0005 step 10. ~~The acceptance call is the project lead's.~~ |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | userspace (`bin/linuxd`, `bin/tcpd`), `personality`, tools |
| **Milestone** | Phase 2 — the Linux personality ([RFC 0005](0005-linux-abi-compatibility.md)) |
| **Depends on** | [RFC 0005](0005-linux-abi-compatibility.md) (steps 1 and 10, which this answers), [RFC 0020](0020-tcp.md) (TCP), [RFC 0027](0027-a-sockets-api-worth-the-name.md) (the sockets crate), [RFC 0031](0031-linux-compatibility-as-an-adapter.md) (the adapter), [RFC 0033](0033-what-a-hosted-process-is.md) (descriptors the adapter holds), [RFC 0055](0055-a-poll-that-tells-the-truth.md) (the readiness table `epoll` sits on) |

---

## Summary

RFC 0005's last step is *"the motivating workload runs under load"*, and it
could not be run because the workload had never been named; the RFC refused
to invent one, correctly, since a workload chosen by the people who must pass
it is a gate chosen to pass. **It is named now:** a statically linked Go
`net/http` server, in a Linux-tagged domain, serving **sixteen concurrent
keep-alive clients** from the host for **five minutes**, every response
checked, with **zero errors** allowed. Throughput and latency are reported,
not gated. A thirty-second version runs on every push; the full five minutes
runs in the nightly soak.

This RFC defines that gate, records what the workload actually asks of the
system — measured on Linux, not guessed — and decomposes the four things that
stand between it and a pass.

## Motivation

**RFC 0005 says so itself:** *"Until the actual Go application starts, serves,
and stays up under load, 'Bhaskix runs Go' is not a claim the project makes."*
Every step before this one proved a mechanism against a corpus program the
project wrote to exercise it. None proves the thing the personality exists for:
somebody else's server, unmodified, doing its job for long enough that a leak,
a lost wake or an exhausted table would show.

**What happens if we do nothing:** Tier 2 stays half-built — UDP sockets exist,
TCP and `epoll` do not — and the personality's claim stays at "a Go binary
prints a line".

## The workload, measured on Linux (step 1)

RFC 0005's step 1 was *"run the motivating workload under Linux with syscall
tracing and publish the actual histogram"*. Done 2026-09-30 on the build host
(Linux 5.15, go 1.13.8): a minimal `net/http` server — one handler answering
`path <p>\n` — built `CGO_ENABLED=0 GOOS=linux -ldflags '-s -w'`, run under
`strace -f -c`, and driven by sixteen concurrent keep-alive clients for ten
seconds.

**Size: 5,423,104 bytes** stripped. **Load: 57,704 responses, 0 wrong**, p50
2.02 ms, p99 11.56 ms (native Linux, loopback — a reference, not a target).

| calls | errors | syscall | here today |
|---:|---:|---|---|
| 137,588 | 10,135 | `futex` | ✅ |
| 131,446 | 73,652 | `read` | ✅ files, pipes, console, UDP — **not TCP** |
| 108,794 | | `epoll_pwait` | ❌ |
| 62,601 | | `nanosleep` | ✅ |
| 57,704 | | `write` | ✅ — **not TCP** |
| 3,602 | | `madvise` | ✅ |
| 1,858 | | `sched_yield` | ✅ |
| 114 | | `rt_sigaction` | ✅ |
| 69 | | `setsockopt` | ❌ |
| 39 | 4 | `epoll_ctl` | ❌ |
| 37 | | `rt_sigprocmask` | ✅ |
| 29 | 13 | `accept4` | ❌ |
| 25 | | `gettid` | ✅ |
| 24 | | `sigaltstack` | ✅ |
| 21 | | `close` | ✅ |
| 18 | | `mmap` | ✅ |
| 17 | | `getsockname` | ❌ |
| 12 | | `arch_prctl` | ✅ (`ARCH_SET_FS`) |
| 11 | | `clone` | ✅ |
| 5 | | `fcntl` | ✅ (`F_GETFL`/`F_SETFL`) |
| 4 | | `socket` | ⚠️ UDP only; streams refused `EPROTONOSUPPORT` |
| 3 | | `bind` | ⚠️ UDP only |
| 2 | | `openat`, `getpid`, `tgkill` | ✅ |
| 1 | | `listen` | ❌ |
| 1 | | `epoll_create1` | ❌ |
| 1 | | `readlinkat` | ❌ — no handler, answers `ENOSYS`; Go reads `/proc/self/exe` at start, and whether it tolerates the refusal is to be seen on the machine, not assumed |
| 1 | | `sched_getaffinity`, `execve` | ✅ |

Thirty distinct calls; **eight are missing outright, two (`socket`, `bind`) are UDP-only, and two more (`read`, `write`) work for everything but a TCP stream.**
The dominant cost on Linux is `futex`, and the second is `read` returning
`EAGAIN` — which is the edge-triggered netpoller doing its job.

**What the arguments say**, from a second trace of the calls above:

- **Go listens dual-stack.** It probes IPv6 with throwaway sockets, then
  listens on `AF_INET6` `::` with `IPV6_V6ONLY` set to 0, so an IPv4 client
  arrives as a v4-mapped address (`::ffff:127.0.0.1`) — in `accept4`'s and
  `getsockname`'s answers.
- **Edge-triggered `epoll`.** Each connection is registered once with
  `EPOLLIN|EPOLLOUT|EPOLLRDHUP|EPOLLET`. Two `EPOLL_CTL_DEL`s were refused
  `EPERM` in the trace — on descriptors Linux's `epoll` cannot watch (standard
  output and error, redirected to a file there) — and Go carried on.
- **Options:** `SO_REUSEADDR`, `SO_BROADCAST` (the probe), `IPV6_V6ONLY`,
  `TCP_NODELAY`, `SO_KEEPALIVE`, `TCP_KEEPIDLE`, `TCP_KEEPINTVL`.
- **Files read at start:** `/proc/sys/net/core/somaxconn` (absent: Go falls
  back to a backlog of 128) and `/sys/kernel/mm/transparent_hugepage/
  hpage_pmd_size` (absent is fine).

**This histogram is go 1.13.8's, and CI builds with a different Go.** The
same `corpus/hello.go` is 806,912 bytes here and 1,011,896 bytes on CI (46 CI
logs agree), and nothing in any log says which version CI has — its runners
are never told to install one. Go 1.14 added signal-based preemption, which
would add `tgkill` + `SIGURG` traffic this trace cannot show. Step 1 therefore
also makes CI print `go version`, and step 5 pins one toolchain if they differ.

## Step 2's record (2026-09-30): a table, not two slots

**What reading `tcpd` found** was more than a constant. Slot 1, `ACCEPTED`,
was named in the cookie path, RFC 0061's reclaim, the `ACCEPT` handler and the
report. A listener held **one ring pair**, taken by the first connection it
birthed — its own comment said re-arming was "the table's next step". Rings
are the program's memory, gifted once into fixed CSpace slots and mapped at
fixed addresses. And every handle was minted with **generation 1**, so a
capability kept from an earlier connection carried the same badge as the next
connection in its slot: latent with one slot, a hole with a table.

**What landed:**

- **`net::tcp::table`**, host-tested and `unsafe`-free: `N` slots with a
  generation each that moves on when a slot is emptied, birth order so
  `ACCEPT` hands out the oldest, `lend`/`give_back` so a state-machine step
  borrows its connection without ending it, and `Armed`, a FIFO of ring pairs.
  Seven tests; the stale-handle one was watched failing with the generation
  bump removed.
- **`tcp::ARM_PAIR` (70)** on a listener: `LISTEN`'s legs, preceded by a leg
  carrying no gift (`OPEN_LEG`). That leg exists because a service thread has
  **one** gift declaration and `tcpd` declares it before it knows the next
  call: a slot always owed for arming would sit ahead of every wake in the
  declaration list and starve `CONNECT`'s and `LISTEN`'s leg 3 for ever.
- **A pair returns to its listener by itself** when the connection that took
  it leaves the table — exactly what `LISTEN`'s one pair always did, which is
  why no re-arm verb was needed and every existing caller is unchanged.
  `ACCEPT` names the pair in its reply's third word.
- **Thirty-two connections**, a verified `ACK` taking a free slot *and* an
  armed pair or being dropped and counted; a stream method on a retired
  handle answers `GONE`, where it used to answer `LATER` for ever; the
  outbound connection is an ordinary table entry whose handle is re-issued
  per `CONNECT`, so the v6 connection no longer reuses the v4 one's badge.

**The stack, found by a boot rather than by arithmetic.** The table is about
9 KiB (a 152-byte control block, measured on the host, in an entry of about
280), so `tcpd`'s 16 KiB stack went to 32 — and the first boot faulted 34.8 KiB
below its top on the first `CONNECT`: the table is built by value and moved,
and a step lends a connection out and back, so the frames hold more than one
copy. It is 64 KiB now, which is about double what the fault proved, **not a
measured peak**.

**The gate.** `bin/tcpc` arms three pairs beside `LISTEN`'s own after its
demonstration, and the kernel prints `tcp four ... ready`; only then does the
host open four connections through `hostfwd` — earlier, one of the
demonstration's own `ACCEPT`s would take one — all four before writing to any,
each sending its own sixteen bytes and demanding them back. The guest reports
`4 connections held at once ... pairs 0b1111`, the host `all four echoed`.
**Armed:** a table of two gives `1 accepted, 0 echoed` on the guest and
`0 of 4 echoed` on the host.

**The first full suite failed it, and the host was right.** The guest said
four held and echoed; the host said `3 of 4 echoed: client 8 got ''`. One of
the four connections `bin/tcpc` accepted was a *ghost*: an early attempt by the
boot's other inbound driver, whose `SYN` `slirp` kept retrying after the host
had given up, arriving now with its own sixteen bytes. The guest cannot tell a
ghost at `ACCEPT`; it can by what it says. So the act reads each accepted
connection's bytes, shuts, drops and counts anything that does not start
`bhaskix-4way-`, and keeps accepting until four real clients are held — still
before serving any. **Watched working by forcing it:** with the first real
client misread as a ghost, the act stops at `3 accepted ... 1 ghost(s) turned
away`, which also shows the slot a ghost held is reused by the next accept.

**A defect this step exposed and did not cause.** On a networked boot,
`bin/tcpd` is **killed** after `bin/tcpc` exits: a *ghost* connection — an old
attempt by the host's inbound driver, whose `SYN` `slirp` kept retrying after
the host had given up — arrives with sixteen bytes, takes the listener's free
pair, and `tcpd` writes them into rings that were revoked with `tcpc`'s domain.
The same fault, at the listener's own ring (`0x2370_0000`), is in two serial
logs taken today before this step and in ten CI job logs; the boot passes
because nothing gates `tcpd` staying alive. It means **a program that gifts
rings and exits can take the machine's TCP service down with the next
packet** — a service-side question (what `tcpd` does when a ring is revoked
under it), recorded in TRACKER §3 and not answered here — **answered the
same day by [RFC 0087](0087-a-holder-that-survives-its-lender.md)**, which
lets `tcpd`'s space keep a revoked ring as scratch memory. *It does not block
this RFC's gate:* the Go server's client of `tcpd` will be `bin/linuxd`, which
owns the rings and outlives every hosted process.

## Step 3a's record (2026-09-30): a second program can listen

**Reading `tcpd` for step 3 found the adapter could not listen at all.** The
service had one `CONNECT` handover and one `LISTEN` handover for the whole
machine, both `bin/tcpc`'s, and its gift declaration lists the connect rings
first — so a client that only listens has its first gift land in the connect
slot. And no client was ever told who its peer is, which a hosted `accept4`
must return. Step 2's "more than one listener, left for step 5" therefore
moved here.

**What landed:**

- **Listeners are a table of four.** Each ring pair records the listener that
  owns it; a connection's listener is its pair's owner; `ACCEPT` on listener
  L hands out L's oldest; a retired pair returns to its owner.
- **A new listener opens with `OPEN_LEG`** — `LISTEN` with the port and the
  leg that carries no gift, then its first ring pair, an optional wake, and
  leg 2 answering the listener capability. The open handover now **belongs to
  the caller that opened it**: another caller's legs are answered `LATER`,
  which `sock::tcp::leg` retries, so two programs cannot land gifts in each
  other's slots. A port already held is refused before any gift moves.
  `tcpc`'s fixed `LISTEN` is kept, in whichever listener slot is free.
- **`tcp::PEER` (71)** names a connection's peer: family and port in one word,
  a v4 address (or 1 for `::1`) in the other.
- `sock::tcp::listen_open` and `sock::tcp::peer`.

**The gate.** After its four-client act, `tcpc` opens a second listener on
port 8 with `OPEN_LEG` while its first holds 7; the host connects to it once
the kernel says it is ready; `PEER` must name `10.0.2.2` — `slirp`'s host — and
the host's bytes must come back. **Armed both ways:** a table of one listener
refuses the second (`stopped at step 1`), and a `PEER` off by one is caught by
the address check (`stopped at step 6`).

**Not done, and said:** the plan promised host tests for the listener table
and pair ownership. That logic is `tcpd`'s own, which has no host tests, and
it reuses no new pure structure; the boot gate and its two arms are what cover
it.

## Step 3b's record (2026-09-30): a hosted program serves a TCP client

**What landed.** A hosted stream socket is `bin/linuxd`'s: its listener and
connections are capabilities to `bin/tcpd` the adapter holds, and its bytes
move through a pool of seventeen ring pairs the kernel grants the adapter at
start — the project lead's choice (2026-09-30) over a kernel method for making
memory. `socket`, `bind`, `listen` (a listener opened with `OPEN_LEG`, armed up
to the backlog from the pool), `accept4` (the peer from `PEER`, v4-mapped on a
dual-stack socket), `read`, `write`, `sendto`/`recvfrom` on a stream,
`shutdown`, `getsockname`, `getpeername`, `setsockopt` for the seven options
the step-1 trace saw, `getsockopt(SO_ERROR)`, `O_NONBLOCK` kept through `fcntl`,
and `close`. The option numbers and syscall numbers were read from the build
host's headers, not recalled; the option table and the v4-mapped encoding are
host-tested in `personality::socket`.

**The gate.** An assembly probe — `tools/probes/linux-streamer.s` — listens on
port 10, blocks in `accept4` until the host connects, blocks in `read` until
sixteen bytes have come, writes them back and prints them. The host must get
its bytes back *and* the console must carry them; the guest's own line says
only that the probe ended, because ending is not serving.

**Three things building it found, each of which would have come back:**

1. **The pool arrives after the adapter starts.** `bin/linuxd` starts early and
   the kernel grants the pool once `bin/tcpd` exists, so mapping the pool once
   at start found nothing and refused every hosted stream for the rest of the
   boot. It is mapped on the first stream `socket()`, resuming where it
   stopped.
2. **A hosted process's exit released its stream as a datagram slot.**
   `release_sockets_of` treated every socket with a handle as a UDP slot; a
   stream's handle is a table index and the first is 0, and releasing "slot 0"
   is a `CALL` on the adapter's own endpoint — the adapter waiting for itself,
   for ever, and every hosted program behind it. Found by listing every thread
   queued on an endpoint: the adapter's was sending on its own.
3. **`HAND` could not say which way it meant.** The kernel read a `HAND` as a
   server handing into its reply whenever the thread was answering somebody,
   and the adapter stages its rings for `bin/tcpd` *while* answering the hosted
   program's `listen` — so the stage was refused `SlotUnavailable`. **`HAND`
   gained `HAND_STAGE`**, an `arg3` bit saying "for my next call" whatever the
   thread is doing; a `HAND` without it is read exactly as before, and
   `sock::tcp::leg` sets it. A kernel interface extended, backward-compatibly,
   inside this step rather than planned before it — said so here.

**Two kernel limits raised, each counted rather than guessed:**
`shared::MAX_OBJECTS` 64 → 128 (a boot peaked at 45 live and the pool adds 34),
and `notify::MAX_NOTIFICATIONS` 32 → 64 (a boot used all thirty-two, and the
adapter's TCP wake made the `two sources` self-test's notification the
thirty-third, which failed it).

**What is interim, and said in `stream.rs`:** a blocking `accept`/`read` waits
by retrying every ten milliseconds, not by readiness — step 4's `epoll` is
where that changes; a pair given to a listener stays with it, since `tcpd` has
no un-listen; and the send side has no flow control the adapter can see, so a
write is bounded to a page and trusts the peer to keep acknowledging.

## Step 4's record (2026-09-30): `epoll`

**What landed.** `epoll_create`, `epoll_create1`, `epoll_ctl` (`ADD`, `MOD`,
`DEL`), `epoll_wait` and `epoll_pwait` for hosted programs. The interest set
and its rules are `personality::epoll`, host-tested: the operations and their
errnos, the **packed twelve-byte** `struct epoll_event` (read from the build
host's `sys/epoll.h`, not recalled), `EPOLLONESHOT` re-armed by `MOD`, and
**edge-triggered for real** — each interest keeps a watermark of the news it was
last told, the adapter's count of what has happened on that descriptor, and an
`EPOLLET` interest is reported only when the count has moved past it. Readiness
comes from where `poll` already asks, plus hosted streams: a connection asks
`bin/tcpd` how far the peer's stream has reached, which takes nothing, and a
listener **accepts eagerly** into a queue of the adapter's own, because `tcpd`
has no way to say a connection waits without handing it over. `poll` and
`select` now answer a stream too, where step 3b said it could not tell. A
descriptor with no count of its own (a pipe, the console) in an edge-triggered
interest is reported as level-triggered — too often rather than never.

**How a wait waits.** A set of nothing but hosted streams parks on the wake
`tcpd` rings on every connection's news, if no other thread holds it (the
nucleus allows one waiter), with the caller's deadline armed on it for a bounded
wait. Anything else waits ten milliseconds at a time. ~~**Go's netpoller will take
the second path:** it registers a pipe or `eventfd` of its own to interrupt
itself, which no single notification here covers. Correct, and slower than it
will need to be; step 5 measures it.~~ **Wrong about Go 1.27.1, corrected 2026-10-01:** its netpoller interrupts itself with an `eventfd`, and since step 5 an eventfd write rings the same TCP wake, so a set of streams and eventfds still parks there.

**The gate.** `tools/probes/linux-epoller.s` listens on port 11 with
**non-blocking** descriptors, so nothing waits except `epoll_wait`, learns of
the host's connection from it, and watches the connection
`EPOLLIN | EPOLLRDHUP | EPOLLET`, reading until `EAGAIN` before it waits again.
The host sends its sixteen bytes in two halves a third of a second apart, so the
probe finishes only if the second half is reported as a second edge. **Watched
failing:** with the connection's news pinned so no second edge could come, the
probe read the first half, was told `EAGAIN`, and never heard again —
`epoll_wait never reported what the probe was waiting for`. The server-probe
harness in the kernel is now one function both probes use, so they cannot drift.

**Five things building it found:**

1. **The nucleus parks one hosted call at most sixteen times**, then answers the
   thread `EAGAIN` itself without asking the adapter. An `epoll_wait` must not
   end that way — Go treats any error but `EINTR` from it as fatal (~~recalled from
   its runtime's source, not read here~~ **read 2026-10-01** in go 1.27.1's
   `runtime/netpoll_epoll.go`, and it holds) — so each waiting thread's parks are
   counted and the wait is answered **zero events** after twelve: a wait for
   ever that returns early with nothing, which callers written against Linux's
   spurious wake-ups already loop on.
2. **Step 3b's blocking `accept` was answered `EAGAIN` when the host was late.**
   Reproduced by holding the host back one second: `htcp fail 4 0b` on the
   ten-millisecond retry, served when the wait parks on the TCP wake instead,
   which blocking stream calls now do when they can. This is very likely the
   intermittent failure `TRACKER.md` §3 recorded the same day, and that row says
   what is and is not established.
3. **A descriptor's "last holder" counted every row with the same number,
   whatever it named.** A stream at index 0 and a file in slot 0 each kept the
   other "held", so closing the stream never gave its connection back. Any
   connection whose index matched a pipe, file or datagram handle its process
   held would have leaked — inferred from the code, not seen on a boot, and
   host-tested now. `holders` compares the kind, and for a socket the tag bits
   a `dup` copies.
4. **The adapter's build did not depend on its own second file.** The make rule
   named `src/main.rs` alone, so a change to `stream.rs` rebuilt nothing and a
   boot tested the previous adapter — found because the first attempt at the red
   run above passed. CI builds clean and was not affected.
5. **The stream probe had been passing on machines no client could reach.**
   `shell-test.sh iommu`, `bond-test` and `lacp-test` boot a network with no
   harness connecting to port 10, and step 3b's probe "passed" there because its
   blocking `accept` was answered `EAGAIN` (finding 2) and it ended. With the
   wait made to last, the first full suite waited forty seconds for nobody on
   the shell lane and failed. **The server probes now run only when a boot says
   `bhaskix.clients`** — a network is not a promise of a client, and the SR550
   has no harness at all — and print why they skipped otherwise.
   `boot-test.sh iommu` builds its own image with the flag, and there a skip is
   a failure: armed by building that image without it, which failed both gates.
   Building that arm also found the two new branches printing `FAIL` without
   failing the script; they set the status now.

**Slot pressure, measured on this boot rather than on Go:** at most 4 of 16
deadline slots armed at once, none refused. A Go process is step 5's
measurement, as question 2 says.

**What is interim, and said in `epoll.rs`:** a set is answered only for the
domain that made it, so a child that inherits one across `fork` is told `EINVAL`
rather than half-sharing it; a set cannot watch another set; at most 32 events
are reported per call and 8 sets exist machine-wide.

## Step 5's record (2026-10-01): the Go server, under load — passing

**The toolchain is pinned: go 1.27.1**, the project lead's choice of
2026-10-01 over CI's 1.24.13 and the build host's 1.13.8.
`tools/fetch-go.sh` holds the version and the sha256 go.dev publishes for it,
checks the tarball before unpacking, and is the only Go any build here uses —
`go-hello` included. CI caches it keyed on that script.

**The server** is `corpus/httpd`: `net.Listen(":8080")`, a line saying it
listens, then `http.Serve` with a handler answering `bhaskix <path>`. Built
static and stripped it is 5,779,616 bytes; on Linux, under the same load, it
peaked at 12.4 MiB resident with 11 threads and made 35 distinct system calls
(measured 2026-10-01).

**The gate** is `tests/qemu/http-test.sh`: its own image (`bin/httpd` in a
ramdisk no other lane carries, and `bhaskix.httpd=<s>`), sixteen keep-alive
clients from `tools/http-load.py`, every body checked. It passes when the load
tool saw no error and every client was served, the kernel says the server was
still running at the end, and during its run **no park was refused, none ran
out of retries and no deadline arm was refused** — counted across the run by
the kernel's own line, because the boot's park readings are printed before the
server starts. `make test-http` runs thirty seconds and `make soak-http` three
hundred; both are in `make test`, a CI job and the nightly soak — ~~**neither is
in `make test`, CI or the soak yet**~~ they were out for the day the corruption
below was open. **Armed twice:**
a load tool expecting one wrong byte in one response, and a server that exits
after 300 requests; each failed the lane, the second on both the host's side
and the kernel's.

**First passing run, 30 s:** 6,654 responses from 16 clients (220.8/s), 0
errors, 0 reconnects; latency p50 65.5 ms, p99 267.6 ms, max 638.8 ms; 98,969
calls by the server; refused `-ENOSYS`: 157 (`prctl`, naming memory areas —
Go ignores the answer) and 234 (`tgkill`, see below). Reported, not gated.

**What it took, each found by running the server and each a defect that would
have come back:**

1. **`eventfd2` and `prlimit64`** — the two calls on Linux's list the adapter
   did not answer. Go's netpoller cannot start without an eventfd and throws
   if it reports anything but `EPOLLIN` (`runtime/netpoll_epoll.go`, read).
   Both host-tested in `personality` (`eventfd`, `limit`); an eventfd write
   rings the TCP wake, so a netpoller parked there is woken at once.
2. **`clock_gettime`.** With no vDSO, Go's `nanotime1` makes the syscall and
   reads the result buffer **whatever it answered** (read in
   `sys_linux_amd64.s`); refused, the runtime's clock was stack garbage and the
   server hung before listening. The monotonic clocks are the cycle counter;
   `CLOCK_REALTIME` is the Unix epoch plus the time since boot, because there
   is no RTC — stated in `personality::clock` rather than invented.
3. **The ELF loader gave every zero-fill page a frame at load.** Go 1.27.1
   links `crypto/internal/fips140/drbg.memory`, 32 MiB of `.bss`, through
   `net/http`; the server's 32 MiB envelope was full at its sixth call. Pages
   past a segment's file bytes are a lazy region now, as on Linux.
4. **`MAP_FIXED` over part of a reservation was refused.** Go reserves its
   arena `PROT_NONE` and commits four megabytes at a time; `MAP_AT` replaced
   only an exact match, and Go threw "out of memory". An untouched sub-range of
   one anonymous region is now served by reprotecting it (`replace_untouched`),
   which needs no frame freed; a range with touched pages is still refused.
5. **`clone` did not start a thread the way Linux does.** The adapter started
   the child at the address in `r9`, this project's own contract; Go puts its
   `g` there and expects the child back from the `syscall` with the parent's
   registers. The lead chose an adapter trampoline over a kernel method: each
   clone gets code in a page of the process that sets its TLS, loads the
   parent's registers, and returns with `rax` zero. **That needed the kernel
   after all** — the `SYSCALL` stub saved no callee-saved register, so the
   staged frame read `rbx`, `rbp` and `r12`–`r15` as zero, and Go's child reads
   `R12` and `R13`. The stub saves them now (six pushes and pops a call). The
   two kernel probes written to the old contract — the clone probe and the
   pipe probe — were rewritten to Linux's, with `objdump` checking each branch.
6. **The adapter's timed waits were keyed by domain.** One thread's call took
   back another thread's wake slot while it was still parked; the first
   thirty-second run counted 290,062 refused parks. Keyed by thread now, and
   sized to the wake pool.
7. **An empty fault-path frame reserve did not try the allocator**, though its
   own module note said it did; a tickless CPU faulting in Go's heap ran it dry
   and a thread lost its fault, stalling every connection at once. It refills
   on the spot now, still without ever waiting for a lock; the lane's run line
   counts how often (2 of 2 on the first passing run).

**The five-minute run, 2026-10-01, after the fix below:** 61,447 responses from
16 clients in 300.1 s (204.7/s), 0 errors, 0 reconnects; latency p50 41.3 ms,
p99 301.4 ms, max 1,278.6 ms; 889,249 calls by the server, no park refused.

**The corruption — ~~open~~ found and fixed the same day.** **The cause:** the
kernel whitelists supervisor methods twice — once where each is handled
(`domain_supervise`) and once where an `INVOKE` is routed there — and
`DISCARD_AT` was added to the first and not the second. Every
`MADV_DONTNEED` was therefore refused. Go 1.27.1 treats memory it has released
that way as zeroed when it next allocates it, so it handed out objects full of
old bytes. Found by logging every call the program made, which showed
`madvise(…, MADV_DONTNEED)` answered `ENOMEM` on memory mapped four calls
earlier. **Guarded now on every boot of every lane:** the memory probe discards
its mapped range and must read 0 where it wrote 42; with the whitelist entry
removed it fails `discard -12 then read 42`. The rest of this paragraph is how
it was narrowed, kept because each ruling-out is a fact about this kernel.

Every run past about a minute had died: four of
three hundred seconds and one of a hundred and twenty, each differently —
`stopm holding locks`; a map pointer of 8 (`maps.(*Iter).Init`); a signal
arriving with no `g`; a plain `GET` whose `MultipartForm` was not nil
(`net/http.(*response).finishRequest`); and, with `GOMAXPROCS=1`, "concurrent
map read and map write". During every one of them no park was refused and no
retry ran out. ~~**Ruled out, by reading or by a run:** `madvise` as a no-op
(Go zeroes by its own high-water mark, not by trusting released memory)~~ —
**that one was wrong, corrected 2026-10-01**: go 1.27.1's `initSpan` treats a
span whose pages were all released with `MADV_DONTNEED` as already zeroed
(`runtime/mheap.go`, while `GODEBUG=madvdontneed` is at its default of 1), and
the earlier reading had looked at `allocNeedsZero` alone. Still ruled out by
reading: SSE state across switches, kernel stack overflow, an unzeroed frame on
a supervisor write, a call delivered twice, the per-domain clone hand-off.

**The hunt, 2026-10-01 — each by a boot, not by reading.** A pure-Go program
with no networking, building and checking maps on eight goroutines, corrupts
its heap within seconds ("found bad pointer in Go heap"), so the adapter's
sockets, `epoll` and eventfds are **not** the cause. It still does with
`GOMAXPROCS=1`, with work-stealing off, and with every one of its threads on
one CPU; one goroutine verifying 16 MiB page by page for ninety seconds does
not. Tested directly and found intact: every general register across
`sched_yield`, `getpid`, `clock_gettime`, `futex` wake, a blocking `futex` wait
and `nanosleep`; every general register across timer preemption mid-loop; `X0`–
`X14` across preemption; each thread's `FS` base against its record at every
call, and no two live threads sharing one; 4 MiB of long-lived objects through
700 verification passes while the corruption happened elsewhere. Backed out one
at a time without effect: restoring the callee-saved registers on syscall exit,
lazy zero-fill in the ELF loader, the reserve's allocator fallback (with a
sixteenfold reserve), and refused preemption (`asyncpreemptoff=1`); a 128 KiB
initial stack changed nothing either. **What remains is newly allocated memory
holding what it should not** — Go's last reports are pointers into freed spans —
in a program with several threads.

**Five real defects fixed on the way, none of them the whole answer:** the
clone trampoline's slot was reused while a child was still running it; a
not-present fault serviced after another CPU had mapped the page was handed to
the program as a bad access (now retried); `munmap` dropped its length and
removed the whole region (`UNMAP_AT` takes a page count now — Go frees the
misaligned head of an aligned arena this way); `MADV_DONTNEED` was a no-op
(`DISCARD_AT` drops the frames); and every unmap now invalidates each page on
every CPU **before** its frame is freed — it did only when the space was loaded
on the calling CPU, which `is_active`'s own note said would stop being enough
once threads ran on several. ~~The lead's decision stands: the lane stays out
of `make test` and CI until the cause is found.~~ The cause was found the same
day — see the top of this paragraph — and the lane is back in both. Two more
rulings-out from that day, by boots: the emulator (it corrupted under KVM and
with Go limited to baseline instructions) and concurrent collection
(`gcstoptheworld=2`).

**What is not done, said:** `tgkill` carries only a fatal signal a thread sends
itself, so Go's `SIGURG` preemption is refused and a goroutine is preempted only
cooperatively — a goroutine spinning without a function call would starve the
rest. The throughput is the adapter's per-call copy cost and is not tuned. The
thirty-second lane's latency tail (p99 ≈ 270 ms) is reported, not explained.

## Step 6's record (2026-10-01): RFC 0005 step 10's gate, met

**The gate, as step 1 defined it:** a statically linked Go `net/http` server in
a Linux-tagged domain serves sixteen concurrent keep-alive clients from the
host for five minutes, every response checked, zero errors; throughput and
latency reported, not gated.

**Met.** The five-minute run of 2026-10-01: 61,447 responses from 16 clients
in 300.1 s, every body checked, **0 errors, 0 reconnects**; the server still
running at the end, after 889,249 calls; during the run **no park refused, none
out of retries, no deadline arm refused**. The thirty-second lane has passed
on every run since, locally (5,794 responses, 0 errors, in the suite of the
same day) and in CI (run 804, its first).

**Reported, not gated:**

| | |
|---|---|
| throughput | 204.7 responses/s (five minutes); 192.5/s (thirty seconds) |
| latency | p50 41.3 ms, p99 301.4 ms, max 1,278.6 ms (five minutes) |
| adapter calls per response | about 14.5 — 889,249 calls for 61,447 responses, every Linux call the server made, its runtime's included |
| an adapter round trip | floor 161,226 cycles, mean 694,931 over the boot's first 1,002 round trips — about 67 µs and 289 µs at the 2.40 GHz the same boot's `cost` line implies |

**What those numbers are not, said:** they are measured under QEMU's TCG on the
build host, not on hardware; the round-trip price is the boot's, taken before
the server ran, not a figure *under this load* — the step's plan asked for the
adapter's copy cost under load, and ~~that per-run figure is not instrumented
yet~~ that figure is measured since 2026-10-01, the same day (the record
below); and the latency tail is reported, not explained. **What the server runs
without:** Go's signal-based preemption (`tgkill` refuses `SIGURG`), so it is
preempted cooperatively only.

**What it took**, steps 2–5: `tcpd` holds a table of connections and a
listener armed with ring pairs; a second program may listen; hosted TCP in
`bin/linuxd`; `epoll`, edge-triggered; and, for the server itself, a pinned
toolchain, `eventfd`, `prlimit64`, `clock_gettime`, lazy zero-fill, partial
`MAP_FIXED` and `munmap`, `MADV_DONTNEED` that discards, a `clone` that starts a
thread as Linux does, and the faults, waits and shootdowns each of those found.

### After step 6 (2026-10-01): the copy cost per response, measured

The gate's "reported, not gated" list named the adapter's copy cost per
request, and step 6 had to say it was not instrumented. It is now. `bin/linuxd`
keeps running totals of every copy through its two wrappers — crossings, bytes
and cycles, `COPY_IN` and `COPY_OUT` apart — in a load record on its report
page (`personality::report::LOAD_AT`). The kernel reads it before the server
starts and after the run and prints the difference, and `http-test.sh` divides
that by the responses the host counted. The lane fails if a run that served
responses recorded no crossing, which was watched happening once with the
publish switched off.

**The five-minute run, 2026-10-01** (65,803 responses, 0 errors, 0 reconnects,
p50 68.7 ms, p99 259.8 ms):

| per response | in (`COPY_IN`) | out (`COPY_OUT`) |
|---|---|---|
| crossings | 1.45 | 12.82 |
| bytes | 140 | 269 |
| cycles copying, both directions | 924,788 | |

Across the run that is 939,025 crossings at a mean of **64,805 cycles each**,
and 60.9 billion cycles in copies — about 25 s of the adapter's one thread out
of 300, at the roughly 2.4 GHz step 6's figures assumed (an inferred rate, not
one this run measured). The thirty-second lane read the same to within 2%
(1.47 and 12.94 crossings, 926,160 cycles).

**What the numbers say, and what they do not.** `COPY_IN` reads the server's
memory, so it carries what the server *writes* — 140 bytes in 1.45 crossings,
which is the size of one response with its headers. `COPY_OUT` carries what
the server *reads* — the request — and every small answer written back into
its memory. The cost is in the *count* of those outward crossings, not in
their bytes: they carry 21 bytes on average, and a request of the load tool's
shape is about 75 bytes, so most of the thirteen are answers rather than
request bytes (inferred from those sizes, not counted). ~~Which calls make them — `epoll_wait`'s events, `clock_gettime`'s `timespec`, a
`sockaddr`, a futex's word — is **not** measured by this record, which counts
by direction and not by call; that is the next instrument if a faster path is
wanted, and a path that batched small answers would be priced against these
figures.~~ **Measured the next day** — see "Which calls", below. The record also counts every copy through the wrappers, not only
stream bytes; three direct copies elsewhere (`sched_getaffinity`, a file
`write`'s staging, `execve`'s segments) are outside it, and none is on a
stream path.

### Which calls (2026-10-02): the server spends its calls asking the time

The kernel now counts the traced domain's calls **by number**
(`syscall::TRACED_BY_NUMBER`, a count per number that interprets none of them),
prints the eight most asked, and `http-test.sh` divides by the responses. A
thirty-second run of 2026-10-02, 7,106 responses:

| number | call | per response |
|---|---|---|
| 228 | `clock_gettime` | **11.50** |
| 0 | `read` | 1.32 |
| 1 | `write` | 1.00 |
| 202 | `futex` | 0.30 |
| 35 | `nanosleep` | 0.26 |
| 281 | `epoll_pwait` | 0.23 |

Names from the build host's `asm/unistd_64.h`, checked against the adapter's
own constants. **About four calls in five are the runtime reading its clock**,
and they account for the copy record too: 11.5 crossings of a 16-byte
`timespec` plus one request read is the 12.85 outward crossings and the 269
bytes. Go reads the time through the vDSO on Linux; a process here has none
(`personality/src/clock.rs`), so each `nanotime` is a full round trip to the
adapter and a crossing back.

**What would remove them is a design decision, not a tuning step**, and it is
recorded here rather than taken: a time page mapped into hosted processes with
the code that reads it — a vDSO, which Go finds through `AT_SYSINFO_EHDR` (read in go 1.27.1's
`runtime/vdso_linux.go` and `sys_linux_amd64.s`, where `nanotime1` calls
`vdsoClockgettimeSym`, 2026-10-02) —
would answer these without a call. Answering them in the nucleus instead is
ruled out by RFC 0031's count of Linux numbers interpreted there, which is 0.
Either would want its own RFC and the lead's word, and these figures are what
it would be measured against. **The word, 2026-10-04:** the vDSO was proposed
as [RFC 0088](0088-a-clock-a-process-reads-itself.md) and **deferred** by the
lead — kept as a proposal, to be built when the Go server's per-response cost
makes clock reads the bottleneck.

## Design

### The gate

The server is `corpus/httpd.go`: `net/http`, one handler whose body is derived
from the request path, so a response delivered to the wrong request is a wrong
body rather than a plausible one. The load is `tools/http-load.py`: sixteen
threads, each holding one keep-alive connection through QEMU's `hostfwd`,
requesting `/c<client>/r<n>` in a loop and checking every body.

**Passes when**, for the whole run: every response is the one its request
asked for; no connection errors; the server is still answering at the end;
and the nucleus reports no refused park and no deadline arm refused for want
of a slot. **Reported, not gated:** requests completed, p50/p99 latency, and
the adapter's copy cost per request.

| lane | length | when |
|---|---|---|
| `make test-http` | 30 s | every push, in `make test` and CI |
| soak | 300 s | nightly |

### Four blockers, found by reading

1. **The image.** The server is 5.2 MB; `root=disk` reads the root image into
   one allocation capped at 4 MiB by the buddy allocator (`MAX_ROOT_IMAGE`).
   The **ramdisk** — the default root, a Limine module — has no such cap. So
   the lane builds its own image with the server in it and boots from the
   ramdisk, as `test-busybox` builds its own; no other lane's image grows, and
   the 4 MiB ceiling stays a `root=disk` fact for its own RFC.
2. **`tcpd` holds two connections**: slot 0 is the one outbound connection,
   slot 1 the one accepted. Sixteen clients need a table.
3. **Hosted TCP does not exist.** `bin/linuxd` refuses a stream socket with
   `EPROTONOSUPPORT`; `listen`, `accept4`, `setsockopt`, `getsockname`,
   `shutdown` have no handler.
4. **`epoll` does not exist.** `Kind::Epoll` is reserved in the descriptor
   table and RFC 0055's readiness table was built to sit under it.

## Alternatives considered

| Alternative | Why rejected | Would reconsider if |
|---|---|---|
| Choose the workload inside the project | RFC 0005 refuses it: a gate chosen by the people who must pass it passes | never |
| Serve HTTP from a native Bhaskix program | proves `tcpd`, not the personality; step 10 is about somebody else's binary | the personality is retired |
| Lift `MAX_ROOT_IMAGE` first | a chunked or demand-paged root is its own design (the constant's comment says so); the ramdisk already holds a 5 MB file | a lane that must boot `root=disk` needs the server |
| Level-triggered `epoll` only | Go registers every connection `EPOLLET`; a level-only `epoll` would answer it with events it did not ask for | never for this workload |
| One RFC per layer up front | the design of each layer depends on what the previous one found; RFC 0005 landed its steps as dated records in one document, and that worked | a layer turns out to need its own acceptance |

## Impact on existing design documents

- **RFC 0005** — the header's *"what is still owed from outside: the
  motivating workload's trace (implementation step 1)"* is answered by this
  RFC's step 1; step 10's record *"the motivating workload has never been
  named"* is answered by this RFC's summary.
- **`security.md` §1 T11** — the adapter will hold `tcpd`'s endpoint and every
  hosted TCP connection's capability; its note on what a compromise of the
  adapter reads grows accordingly (step 3).
- **RFC 0020** — `tcpd`'s two-slot table becomes a table (step 2).

## Security implications

- **New authority for the adapter**: the `tcpd` endpoint, granted the way
  `ipd`'s already is. A compromised adapter could then read and write every
  hosted process's TCP streams, as it can already read their files — stated
  in T11 when it lands, not after.
- **No new parser of untrusted input in the nucleus.** HTTP is parsed by the
  Go program in its own domain. The adapter decodes `sockaddr` structures and
  socket options from a hosted process, which is untrusted input: the decoding
  lives in `personality/src/socket.rs`, host-tested, ~~and the existing
  `linux_sockaddr` fuzz target is extended over the option decoding~~ —
  **not extended, corrected 2026-09-30:** `plan_setsockopt` turned out to parse
  no buffer at all — it matches two integers and checks a length, and the only
  value it reads (`IPV6_V6ONLY`'s) is one `int` copied in whole — so its host
  test covers every branch and a fuzzer would add nothing. The `sockaddr` a
  hosted program hands `bind` is still parsed by `parse_endpoint`, which that
  fuzz target already covers.

## Performance implications

Throughput will be low and is reported as measured: every byte of a hosted
stream crosses the adapter by `COPY_IN`/`COPY_OUT`, measured at ~213,000
cycles per page against 140 in the kernel's direct map (RFC 0084). The gate is
correctness under sustained concurrency, not speed; the copy cost per request
is printed so that the number a faster path would improve is on record first.

## Testing plan

- **Host:** `tcpd`'s connection table; `sockaddr` and option decoding;
  `epoll`'s interest list and edge/level semantics — all pure, all tested.
- **QEMU:** an assembly probe per mechanism (listen/accept/echo; `epoll` over a
  listener and a connection), then the Go server under `tools/http-load.py`.
- **Watched failing:** each gate forced red once before it is believed.
- **Hardware:** the SR550's NIC is not one this system drives in a way a host
  client can reach through `hostfwd`, so the gate is QEMU's; a hardware run is
  recorded if the network path there allows it.

## Unresolved questions

1. **Which Go.** ~~CI's toolchain is unknown until step 1's `go version` line
   reports~~ **CI reports go 1.24.13** (run 793, 2026-09-30) against the build
   host's go 1.13.8 — eleven minor versions apart, across 1.14's signal-based
   preemption, so the Linux trace above is not the list CI's binary will ask
   for. Which one is pinned is the lead's call; re-taking the trace with it is
   the step after that call. **Answered 2026-10-01: go 1.27.1, pinned by the
   lead**, and the trace re-taken with it on Linux — 35 calls, of which
   `eventfd2` and `prlimit64` were unanswered here (step 5's record).
2. **Slot pools of sixteen.** Wake slots and deadline slots are sixteen each;
   a Go process parks several futex sleepers plus its netpoller. ~~Measured in
   step 4 before anything is resized.~~ Step 4's boot armed at most 4 of 16
   deadline slots with no refusal, but it ran no Go process, so it does not
   answer this; **measured in step 5**, which does. Also open for step 5: the
   adapter's four timed-wait entries (`TIMED`, `UNTIL` in `bin/linuxd`), which a
   netpoller on the retry path and several sleeping goroutines will share.
   **Answered by step 5's runs:** the deadline slots were never short (at most 4
   of 16 armed, none refused), but the timed-wait tables were — keyed by domain,
   one Go thread gave back another's slot — and are now keyed by thread and
   sized to the sixteen wake slots. The lane's own run line counts it, and
   none of the failing runs refused one.

## Implementation plan

1. **The decision, the gate, the trace** — this document; RFC 0005 and
   TRACKER updated; CI prints `go version`. ✅ 2026-09-30.
2. **`tcpd` holds a table** — 32 connections, a listener armed with ring
   pairs, `GONE` for a retired handle; four host clients held at once.
   ✅ 2026-09-30. More than one listener is left for step 5, when the Go server
   and `bin/tcpc` must listen at once.
3. **Hosted TCP, server side** — 3a ✅ 2026-09-30: `tcpd` serves more than
   one listener and names a peer. 3b ✅ 2026-09-30: stream sockets in `bin/linuxd` over `tcpd`,
   with the calls and options the trace lists; gate: an assembly probe that
   listens, accepts and echoes.
4. **`epoll`** — create, control, wait, edge- and level-triggered, parked
   through the adapter's wake slots; slot pressure measured. ✅ 2026-09-30:
   parked on `tcpd`'s wake for a set of streams, a timed retry otherwise; gate:
   an assembly probe served through `epoll`, edge-triggered, in two halves.
   Slot pressure under Go moves to step 5, which has the process to measure.
5. ✅ 2026-10-01 — **The server and the load** — `corpus/httpd.go`, its image, the boot flag,
   `tools/http-load.py`, `make test-http` in CI, 300 s in the soak.
6. ✅ 2026-10-01 — **Step 10's record** — the measured result against the gate, in RFC 0005
   and here.
