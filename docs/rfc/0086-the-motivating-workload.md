# RFC 0086: The motivating workload — a Go HTTP server under load

| | |
|---|---|
| **Status** | 🔨 **Draft 2026-09-30 — steps 1 and 2 done.** The workload RFC 0005 was owed from outside is named, its gate defined, its size measured and its system calls traced; `bin/tcpd` holds a table of thirty-two connections and a listener arms ring pairs, gated by four host clients held at once. Steps 3–6 are the work. The acceptance call is the project lead's. |
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
under it), recorded in TRACKER §3 and not answered here.

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
  lives in `personality/src/socket.rs`, host-tested, and the existing
  `linux_sockaddr` fuzz target is extended over the option decoding.

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
   the step after that call.
2. **Slot pools of sixteen.** Wake slots and deadline slots are sixteen each;
   a Go process parks several futex sleepers plus its netpoller. Measured in
   step 4 before anything is resized.

## Implementation plan

1. **The decision, the gate, the trace** — this document; RFC 0005 and
   TRACKER updated; CI prints `go version`. ✅ 2026-09-30.
2. **`tcpd` holds a table** — 32 connections, a listener armed with ring
   pairs, `GONE` for a retired handle; four host clients held at once.
   ✅ 2026-09-30. More than one listener is left for step 5, when the Go server
   and `bin/tcpc` must listen at once.
3. **Hosted TCP, server side** — stream sockets in `bin/linuxd` over `tcpd`,
   with the calls and options the trace lists; gate: an assembly probe that
   listens, accepts and echoes.
4. **`epoll`** — create, control, wait, edge- and level-triggered, parked
   through the adapter's wake slots; slot pressure measured.
5. **The server and the load** — `corpus/httpd.go`, its image, the boot flag,
   `tools/http-load.py`, `make test-http` in CI, 300 s in the soak.
6. **Step 10's record** — the measured result against the gate, in RFC 0005
   and here.
