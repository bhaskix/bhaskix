# RFC 0090: A hosted program that dials out

| | |
|---|---|
| **Status** | Draft 2026-10-08. Written before any of it, as RFC 0086 was. **Steps 0–3 done 2026-10-12** — slirp's refusal confirmed on both emulators; `RECV`'s third word now says why a connection ended, and a refused dial is told to the caller that made it |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | net / userspace |
| **Milestone** | L1 ([roadmap.md](../roadmap.md)) — the row carried out of RFC 0005 step 9, "`connect` — a hosted TCP **client**" |
| **Depends on** | [RFC 0020](0020-tcp.md), [RFC 0022](0022-capability-in-a-call.md), [RFC 0023](0023-a-wake-for-a-connection.md), [RFC 0086](0086-the-motivating-workload.md), [RFC 0087](0087-a-holder-that-survives-its-lender.md), [RFC 0005](0005-linux-abi-compatibility.md) |

---

## Summary

A Linux program hosted by `bin/linuxd` can serve TCP — `socket`, `bind`, `listen`, `accept4`,
edge-triggered `epoll`, a Go `net/http` server under load — and cannot open a connection. `connect`
(42) is not dispatched; it answers `ENOSYS`. This RFC makes it answer, the way Go's `net.Dial` and
a C client both use it: non-blocking with `EINPROGRESS`, then writability, then `SO_ERROR`; or
blocking, parked until the handshake ends. Most of the work is not in `bin/linuxd`. **`bin/tcpd`
can hold exactly one outbound connection for the whole machine**, from one fixed port, and
`bin/tcpc` takes it at boot; and **nobody holding a connection can learn why it ended**. Both
have to change before a second program can dial out at all. And because `bin/linuxd` dials for
every hosted program it runs, **a hosted program dials out only if it was granted to** — the
project lead's decision of 2026-10-08, in RFC 0053's shape.

## Motivation

- **L1 cannot start without it.** `curl` and OpenSSH, the roadmap's named L1 programs, dial out
  before they do anything else. So does any program that fetches, reports, resolves a name over
  TCP, or talks to a database.
- **The motivating workload is half a workload.** RFC 0086's Go server answers 61,447 requests
  without an error and cannot itself make one — no health check against a peer, no upstream, no
  client test of its own.
- **It is the next step to one real service on physical hardware.** A service that cannot reach
  anything is a service that can only be reached.
- **What happens if nothing changes:** hosted TCP stays server-only, as RFC 0005 step 9 records,
  and the first hosted program that dials out fails with an error code Linux does not use for it.

### What is there today, read from the tree 2026-10-08

| | |
|---|---|
| `bin/linuxd` | `connect` undefined (`user/linuxd/src/main.rs`, the syscall constants); a stream is `Fresh`, `Bound`, `Listening` or `Connected` — **no connecting state**; `stream.rs`'s `condition` says so: *"nothing here connects out yet"* |
| `bin/tcpd` | **one** CONNECT handover for the machine (`connect_handover`), **one** `service.outbound`, and every outbound connection from **port 49999** (`LOCAL_PORT`). `bin/tcpc` takes the handover at boot and its rings stay mapped at the fixed gift slots |
| why a connection ended | recorded **only** for that one outbound connection, and only in tcpd's report page (`service.outcome`). `RECV` answers the state number — `0` for closed — and nothing about why. RFC 0020's failure table promises *"a status that says 'no answer', distinguishable from 'refused'"*; **the caller cannot distinguish them today** |
| `linuxd`'s ring pool | 17 pairs, mapped on the first stream socket, **never returned**: `pool_used` only grows, and `listen` arms as many pairs as the backlog asks. A Go server's backlog takes all of them |
| errno | the personality's list has no `EINPROGRESS`, `EALREADY`, `EISCONN`, `ECONNREFUSED`, `ETIMEDOUT` or `ENETUNREACH` |
| `getsockopt(SO_ERROR)` | answered, always 0 — there is no pending error to report |

## Design

Seven parts, each of which is a step in the plan below. The order is the dependency order.

### 1. Why a connection ended, told to whoever holds it (`bin/tcpd`)

Every table entry keeps its `Ended` — `Refused`, `Unreachable`, `Reset`, `Aborted`, `Orderly` —
when it reaches `Closed`, and `RECV` on a closed connection answers it in a reply word that is
zero while the connection lives. ~~The mapping to `outcome::` is the one `service.outcome` already
uses.~~ **Corrected 2026-10-12, at step 1**: that mapping could not be the one — `outcome::` is
private to `bin/tcpd`, has no number for a reset after establishment or for an abort, and its 3
means *established* where the status words' 3 means *reset*. The ending has its own namespace,
`abi::tcp::ended` (1 refused, 2 unreachable, 3 reset, 4 orderly, 5 aborted; 0 while the connection
lives), in the reply's **third** word, which no caller read before. The **first** ending is the one
kept: the reclaim rule can abort an entry already closed, and that is not why it ended.
`bin/tcpd`'s report is unchanged; it simply stops being the only place the answer exists.

This closes the gap with RFC 0020's own failure table, independently of everything after it.

### 2. CONNECT through `OPEN_LEG` (`bin/tcpd`)

`CONNECT` with `arg2 = OPEN_LEG` opens a **per-caller handover**, keyed by badge and by
destination exactly as RFC 0086 step 3a keyed a new listener: legs 0 and 1 carry the connection's
send and receive rings, an optional leg 3 its wake, and leg 2 answers the connection capability
into the slot the caller declared. The rings of an `OPEN_LEG` connection are attached ~~at addresses
derived from the table index, as a listener's pairs are~~ **in a pair window, by pair number, as a
listener's pairs are** (corrected 2026-10-12 at step 3: pairs were never placed by table index), not
at the two fixed gift slots. The window is the dial's from the moment its rings map, under an
owner of its own so no listener arms it, and **stays reserved after the connection ends** until
part 6 can give windows back — nothing in the ABI unmaps a gift. The connection keeps `pair: None`,
which means *not accepted*. Leg 2 answers the local port in its third word, since the service's
report page has no word left.

**The fixed handover stays**, for `bin/tcpc`, as RFC 0086 kept the fixed `LISTEN` for the first
listener. `service.outbound` — the one connection tcpd's report narrates — stays tcpc's.

~~`CONNECT6` gains the same leg; its destination rule (only `::1`) is unchanged and out of scope.~~
**Deferred at step 3, 2026-10-12**: `CONNECT6` keeps the fixed handover until a step has a v6
dialler to gate the leg — built now, it would ship untested.

### 3. A local port per connection (`bhaskix-net`, host-tested)

`LOCAL_PORT` serves the fixed handover only. An `OPEN_LEG` connection draws a local port from the
dynamic range 49152–65535: a start drawn from the machine's entropy, then the first port whose
four-tuple is not in the table. A pure function over the table, with host tests for the edge of
the range, a full range, and a tuple that differs only in the peer. No entropy is `NO_ENTROPY`,
as tcpd already answers elsewhere, not a predictable port.

### 4. `sock::tcp::connect` (`bhaskix-sock`)

The legs in one function — stage, declare, call, retry `LATER` — as `listen_open` is for a
listener. `bin/tcpc` strings CONNECT's legs together by hand today; it keeps doing so, because it
uses the fixed handover.

### 5. `connect` in `bin/linuxd`

- **A connecting state.** `State::Connecting { connection }` beside `Connected`. The decisions —
  what `connect` answers in each state, what readiness a connecting socket reports, which errno a
  tcpd ending becomes — are **pure functions in `bhaskix-personality`**, host-tested, as `plan_socket`
  and the epoll edge rule already are.
- **The answers**, Linux's — **read from `__inet_stream_connect`** (`net/ipv4/af_inet.c`, Linux
  `master`, fetched 2026-10-08), not recalled:

  | state when `connect` is called | non-blocking | blocking |
  |---|---|---|
  | `Fresh` or `Bound` | start it; `EINPROGRESS` | start it; park until it ends: 0, or the error |
  | `Connecting` | `EALREADY` | park until it ends, as the first caller does: 0, or the error |
  | `Connected` | `EISCONN` | `EISCONN` |
  | `Listening` | `EISCONN` — Linux's test is "not closed", and a listener is not | `EISCONN` |

  An ending before establishment answers the socket's error, or `ECONNABORTED` without one; a
  signal during the blocking wait answers the interrupted-call errno — RFC 0083's signals can now
  reach a parked hosted thread, so this is not hypothetical. A blocking `connect` re-enters
  through `REPLY_BLOCK_ON_RETRY`, and since Linux's second blocking caller parks too, a re-entry
  and a second caller need the same answer: park while `Connecting`. It never dials twice.
- **Readiness**, read from `tcp_poll` and `tcp_done` (`net/ipv4/tcp.c`, fetched 2026-10-08).
  `Connecting` reports nothing — `tcp_poll` adds nothing in `SYN_SENT` but `EPOLLERR` once an
  error is pending. `Established` reports `POLLOUT` as `Connected` does today. A connection that
  ended before establishing has had `tcp_done` set it `TCP_CLOSE` with both directions shut and an
  error pending, so it reports **`POLLIN | POLLRDNORM | POLLRDHUP | POLLOUT | POLLWRNORM | POLLERR |
  POLLHUP`** — all of it, which is what Go's poller and a C `poll` loop each test a part of. The
  draft of this paragraph said only `OUT | ERR | HUP`, from memory; the source corrected it.
- **`SO_ERROR`** reports the pending error once and clears it: `ECONNREFUSED` for `Refused`
  ~~and `Reset` before establishment~~ (corrected 2026-10-12: the machine never produces `Reset`
  before establishment — a `RST` in `SYN-SENT` or `SYN-RECEIVED` is `Refused`,
  `net/src/tcp/state.rs`), `ETIMEDOUT` for `Unreachable`, `ECONNABORTED` for `Aborted`.
  `getpeername` answers `ENOTCONN` until established.
- **The new errnos** join the personality's list, each with Linux's number, cross-checked by the
  existing table test.

### 6. Ring pairs for dialling out, and back again (`bin/linuxd`)

A connection made with `connect` takes a pair from linuxd's pool and gives it to tcpd for its
lifetime. Two rules, because without them the first Go server that listens leaves nothing to dial
with, and the first client that dials in a loop runs out:

- **Listeners stop at the reserve.** `listen` arms at most the pool less `DIAL_RESERVE` pairs.
- **A dialled pair comes back.** When the descriptor is closed *and* tcpd has retired the entry,
  the pair returns to the pool; linuxd knows the entry is retired when the connection capability
  answers `GONE`. **tcpd detaching a retired entry's rings is new work, and part 2's**: today
  `retire` only re-arms a listener's pair, `retire_finished` passes over entries without one, and
  the fixed outbound rings are never detached. An `OPEN_LEG` connection is retired at `CLOSED` or
  `TIME_WAIT` like an accepted one, and its rings detached before the slot is reused — otherwise
  linuxd's next gift of the same pair lands on rings tcpd still writes.

Accepted connections are unchanged: their pairs return to their listener, as `ARM_PAIR` defines.

### 7. A program dials out only if it was granted to

**Decided by the project lead, 2026-10-08**: outbound TCP is a per-program grant, not something a
hosted program has by being hosted.

- **The grant is a per-domain flag in the nucleus**, in exactly the shape
  [RFC 0053](0053-input-a-domain-was-given.md) gave keyboard input: a field on the domain's
  record, set by whoever creates the hosted domain and holds its capability — the kernel for the
  corpus, `bin/sup` for a supervisor — and cleared with the domain. Where the creator runs a
  package, a manifest line asks for it, derived as RFC 0030 derives every other grant.
- **`bin/linuxd` asks the nucleus** whether the calling process's domain holds it, through the
  domain capability it already has (RFC 0032), and answers `connect` with `EACCES` when it does
  not — *permission denied*, the errno a Linux security module answers a refused `connect` with
  (SELinux's `name_connect` check, as recalled; step 7 confirms it against the source), so a
  program that reports it reports something true.
- **The honest limit, stated in `security.md`.** For input, the nucleus refuses and a compromised
  adapter cannot lift the grant. Here **linuxd** refuses, because tcpd sees linuxd's badge and
  never the hosted domain's: a compromised adapter can dial for anyone. That is T11's existing
  shape — the adapter already reads every hosted process's files — and it is recorded there.
  Enforcing below linuxd needs tcpd to learn the domain, by a badge per hosted domain or the
  domain capability in the call; that is its own RFC, and nothing here closes the door on it.

### Concurrency, failure, `unsafe`

- linuxd's tables are single-threaded statics today and stay so.
- **Failure behaviour:**
  - table full → `CONGESTED` → an errno to be chosen against Linux's source at step 4 —
    `EADDRNOTAVAIL` is what an exhausted ephemeral range is recalled to answer, and a full
    table is a different limit;
  - no pair left in the dial reserve → `EAGAIN`;
  - the handover busy with another caller → `LATER`, which the leg helper retries;
  - tcpd gone → `ECONNREFUSED` on the next call, as with any other caller of a dead service.
- **`unsafe`:** none new in tcpd or the personality. linuxd's ring copies are existing code.

## Alternatives considered

| Alternative | Why rejected | Would reconsider if |
|---|---|---|
| Use tcpd's fixed CONNECT handover from linuxd | `bin/tcpc` consumes it at boot, it holds one connection for the machine, and every connection would come from port 49999 | never — it is one connection by construction |
| A capability to tcpd for each hosted process, so each dials for itself | RFC 0033 puts a hosted process's descriptors in the adapter, as capabilities the adapter holds; splitting TCP out would make sockets the one descriptor kind the adapter does not hold | the adapter's compromise surface (security.md T11) is reduced by moving every descriptor kind out, not one |
| Blocking `connect` only | Go's `net.Dial` is non-blocking and waits on `epoll`; a blocking-only answer would serve C clients and fail the motivating workload | — |
| Return the reason in the state word | the state word is `state << 32 \| delivered`, and both halves are used | a reply ever runs short of words |
| A sequential port counter | predictable ports are an off-path attacker's first step (RFC 6056); entropy is already a dependency of tcpd's cookies | — |

## Impact on existing design documents

- **RFC 0005**, step 9's row: *"**no `connect`**, so hosted TCP is server-only"* — becomes wrong at
  step 5's gate.
- **TRACKER.md** §4, the row carried out of RFC 0005: *"`connect` — a hosted TCP **client**"* — met.
- **RFC 0020**'s failure table, *"distinguishable from 'refused'"* — true for the first time, at step 1.
- `user/linuxd/src/stream.rs`, `condition`'s doc: *"nothing here connects out yet"*.
- **security.md** — see below.

## Security implications

- **New reach, granted per program.** `bin/linuxd` already holds a capability to `bin/tcpd`'s
  endpoint. Without part 7, every hosted process the adapter runs would reach any address the
  network does, by being hosted. With it, only a domain granted outbound TCP can, and the grant is
  given by the domain's creator, not taken by the program. **What it does not do**: narrow
  *where* a granted program connects — the grant is all destinations or none — or survive a
  compromise of linuxd, which checks it.
- **No new parser of untrusted input.** The bytes are the peer's, through the existing stream
  path; the new pure functions decide over linuxd's own state.
- **Ports.** Part 3 replaces a fixed source port with an unpredictable one for every new
  connection.
- **T11** (`security.md` §1): the adapter's compromise already reads every hosted process's files;
  after this it can also connect anywhere tcpd reaches. The note on T11 says so.

## Performance implications

Measured, not predicted:

- connect-to-established, in cycles, against the native `bin/tcpc` dial on the same lane — the
  adapter's cost is the difference;
- dials per second in a loop of sixty-four, closed each time — which also shows the pairs return.

Nothing on the server path changes, and the HTTP gate's numbers are the check.

## Testing plan

- **Host**: the port allocator; `connect`'s decision table; the readiness of a connecting socket;
  the ending → errno mapping; the dial reserve's arithmetic.
- **QEMU, step by step**: every `full`-profile lane already has a peer — `10.0.2.100:9`, a host-side
  echo QEMU's `guestfwd` spawns per connection, which `bin/tcpc` dials today.
  - a `linux dial` probe (assembly, like `linux-streamer.s`): non-blocking connect →
    `EINPROGRESS` → `poll` for `POLLOUT` → `SO_ERROR` 0 → an echo round trip → close, **sixty-four
    times**, more than the pool holds;
  - a blocking `connect` to the same peer;
  - a refused dial, to `10.0.2.100:10` or any destination no `guestfwd` names. **Read from
    libslirp's `tcp_input.c`** (`master`, fetched 2026-10-08): under `restrict=on`, a `SYN` to an
    address and port outside the `guestfwd` list goes to `dropwithreset`, which answers
    `RST | ACK` acknowledging the `SYN` — a refusal by the book, which tcpd's state machine already
    turns into `Ended::Refused`. Step 0 confirms it on both emulators, because this host's QEMU
    4.2.1 bundles an older slirp than CI's 8.2.2;
  - a Go client, `net.Dial` and an echo, in the HTTP lane beside the server.
- **Hardware**: the SR550 answers on its network since 2026-09-13 and has never started an
  exchange. A dial to a host on its VLAN is the hardware half, once a peer listens there.
- **Arming**: each gate watched red — `EINPROGRESS` answered as success, `SO_ERROR` hard-wired to 0,
  the pair not returned (the sixty-four-dial loop must fail), and an ending reason dropped.

## Unresolved questions

1. ~~**Where may a hosted process connect?**~~ **Decided by the project lead, 2026-10-08:** only
   where it was granted to — part 7. Of the three answers this draft offered (anywhere tcpd
   reaches; a per-domain grant linuxd checks; a grant enforced below linuxd), the second, with the
   third left open for its own RFC. **Still open**: whether a grant ever names destinations rather
   than all-or-none — a question for the first program that needs it.
2. **`DIAL_RESERVE`**: four of seventeen pairs is this draft's number. The pool's size is its own
   question.
3. **How long a blocking `connect` waits** is how long tcpd retransmits a `SYN` — eight
   retransmissions with backoff (`MAX_RETRANSMITS`). Linux's default is about two minutes (recalled,
   not measured here). This RFC reports what tcpd decides rather than adding a
   second clock.
4. **IPv6 beyond `::1`** stays with `CONNECT6`'s rule and is not this RFC's.

## Implementation plan

0. **Confirm** what libslirp's source says — a `RST | ACK` for a dial nobody forwards — from
   `bin/tcpc`, on QEMU 4.2.1 here and 8.2.2 in CI, before a refused gate is built on it.
   **Done 2026-10-12, on both.** A build of `bin/tcpc` dialling `10.0.2.100:10` instead of `:9`,
   never committed, booted in `boot-test.sh iommu` with a QEMU `filter-dump` on `net0`: the guest's
   `10.0.2.15.49999 > 10.0.2.100.10: Flags [S]` is answered at once by
   `10.0.2.100.10 > 10.0.2.15.49999: Flags [R.], seq 0, ack <SYN's seq + 1>, win 0` — on QEMU 4.2.1
   here, and on 8.2.2 (`1:8.2.2+ds-0ubuntu1.18`, from an Ubuntu 24.04 image pinned to the digest
   `tools/swtpm.sh` uses), and in both `bin/tcpd` reports `outcome 1: refused by the network`.
   **The lane needs the IOMMU**: the plain `bios` lane gives the network driver no DMA window, so
   no frame leaves the guest there — the refused-dial gate belongs in a lane that has one. And the
   caller could not tell: `bin/tcpc` reported `FAILED at step 4: connected, stream still in
   flight`, waiting on a stream that would never come — step 1's case, seen.
1. **The ending, told** (tcpd, part 1). Gate: tcpc's existing outbound dial reads its ending through
   `RECV`, and it agrees with the report page. **Done 2026-10-12.** On a healthy boot the outbound
   connection is in `TIME_WAIT`, not ended, when the report is read, so the gate needs a dial that
   ends: the `iommu` lane boots a **second time with the echo peer left out of the network**
   (`BHASKIX_ECHO_PEER=none`, `tests/qemu/devices.sh`), slirp refuses the dial as step 0 saw, and
   the kernel prints `tcp client the connection ended at step 5: RECV said refused, and tcpd's
   report agrees (outcome 1)`, with tcpd counting one segment each way — the `SYN` and the reset.
   `bin/tcpc` stops at the first reply that names the ending, where without it (the arm below) its
   stream wait went round 234 times until the kernel stopped waiting. The other
   half is gated on the healthy boot: `tcp endings no RECV reply named an ending while its
   connection lived`, counted over every `RECV` `bin/tcpc` makes. Host tests in `bhaskix-sock`
   hold `Ended::code` (the encoder, in `bhaskix-net`) to `Ending::from_word` (the decoder). Each
   gate was watched red: tcpd answering no ending brought back step 0's thirty-second wait and
   failed the refused boot; tcpd naming an ending for a live connection failed the healthy one.
2. **The port allocator** (net crate, part 3). Host tests. **Done 2026-10-12**:
   `bhaskix_net::tcp::ports::local_port(start, local, remote, remote_port, taken)` — the start any
   raw draw, reduced into 49152–65535; the search upward and wrapping; `taken` the caller's table,
   asked about the whole four-tuple. Six host tests, among them the top of the range wrapping to the
   bottom, a full range answering `None` after asking each of its 16,384 ports exactly once, and a
   tuple differing only in the peer — each of those two watched red. **One thing step 3 must
   do that this cannot**: the fixed handover takes `LOCAL_PORT` (49999) without asking, and 49999
   lies inside the dynamic range, so tcpd's `taken` must answer `true` for it, or an `OPEN_LEG` dial
   to the handover's peer could take the port the handover then takes again.
3. **CONNECT through `OPEN_LEG`** (tcpd, part 2) and **`sock::tcp::connect`** (part 4). Gate: a
   second native dialler beside `bin/tcpc`, both connections live at once, two different local
   ports. **Done
   2026-10-12.** An act in `bin/tcpc`, after its bulk transfer and before it closes its first
   connection, dials the same peer with `sock::tcp::connect`; tcpd answers a local port drawn by
   step 2's allocator — treating 49999 and every listener's port as taken — and the kernel prints
   `tcp dial two connections to one peer at once: the second dialled with OPEN_LEG from local port N
   while the first held 49999, and its bytes came back`, holding N to the range and away from 49999
   itself. N was 53597, 49632, 58808, 62143, 62682, 58956, 61931 and 62882 on eight boots. Both arms
   went red: the dial forced onto 49999 never established — and got the first connection, its
   four-tuple twin, reset, which the client read through step 1's word as `RECV said reset`; and
   `OPEN_LEG` dials sent to the fixed handover failed at the act's first leg. **Three things the
   step found.** The four-client act assumed tcpd numbers its armed pairs 1 to 3 and indexed by
   them; a dial taking pair 1 first broke it, and it now looks the numbers up. The first armed run
   was reported as a stall in the bulk drain, because the act did not write the detail word the
   kernel reads — the second time a stale word has said that (CI run 782 was the first) — so the
   act names its own phase, `PHASE_DIAL`, and gives up within five seconds, well inside the
   kernel's fifteen. And one of seven boots on this tree failed the four-client act with no client
   accepted, unexplained and filed in TRACKER rather than called a flake.
4. **`connect` in linuxd** (part 5), non-blocking first. Gate: `linux dial`, one round trip.
5. **Pairs for dialling, and back** (part 6). Gate: sixty-four dials.
6. **Blocking `connect`, and the refused dial**: `ECONNREFUSED` through `SO_ERROR`, and through a
   blocking call's own answer.
7. **The grant** (part 7): the per-domain flag, set by the corpus and by `bin/sup`, a manifest line,
   and linuxd's `EACCES`. Gate: the same probe, ungranted, is refused; granted, it dials.
8. **Go dials out**: a client in the HTTP lane, granted. Then the records — RFC 0005's row, TRACKER's carried
   row, `security.md`'s T11 note.
