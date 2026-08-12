# RFC 0018: A network stack outside the kernel, and a socket you have to hold

| | |
|---|---|
| **Status** | Draft |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | `net`, `drivers`, userspace, ABI |
| **Milestone** | Phase 2 in [roadmap.md](../roadmap.md) — the last `TODO` bullet |
| **Depends on** | [RFC 0009](0009-shared-memory.md) (rings), [RFC 0010](0010-notifications.md) (wakeups), [RFC 0011](0011-irq-handler.md) (the device's interrupt), [RFC 0012](0012-iommu.md) (the DMA window), [RFC 0013](0013-service-framework.md) (placement), [RFC 0014](0014-driver-framework.md) (`Mmio`, `register_block!`, the virtqueue crate), [RFC 0016](0016-capability-in-a-reply.md) (a reply that carries a capability) |

---

## Summary

A `virtio-net` driver in its own domain, an IPv4/ARP/UDP service in a second domain, and a **socket
that is a capability a program holds** — handed back in a reply, by the mechanism RFC 0016 built for
directories and lent pages. This is its third use, which is the first evidence that it was a
mechanism and not a special case.

TCP is deliberately not here. It is a state machine with its own failure modes, its own testing
plan and its own retransmission arguments, and putting it in this document would delay every part of
the path below it. What this RFC owes TCP is a socket shape that can carry it — that constraint is
stated where it applies, and the alternative rejected because it could not meet it is in the table.

IPv6 is likewise deferred, but the address type is abstract from the first line of code, because
retrofitting an address abstraction through a routing table and a socket API is the expensive
version of this decision.

## Motivation

### Phase 2 cannot exit, and this is the only bullet left

[roadmap.md](../roadmap.md) §Phase 2 lists networking as the sole remaining `TODO`, and the phase's
exit criterion is that Bhaskix *"does useful network I/O"*. Nothing in the tree does any. `net/` is
an empty directory — `net/src` exists and contains no file — and `tools/check-deps.py` has reserved
layer 4 for a `bhaskix-net` crate that has never existed. The gate is guarding a hole.

### The driver framework was bought with three bugs, and has not been spent

RFC 0014 exists because `bin/blkd` cost three bugs the kernel's own driver had already learned, and
its case was that invoice. `device/src/virtqueue.rs` is now a shared crate, `Mmio<T>` and
`register_block!` exist, and the mock-MMIO harness runs on the host. A second virtio device is the
first opportunity to find out whether any of that was worth it: if `netd` is mostly device-specific
configuration and two queues, the framework paid for itself; if it re-learns the same three bugs,
RFC 0014's claim was wrong and this RFC should say so.

### This is the first subsystem whose input is hostile by default

Everything untrusted the kernel parses today arrives from a *medium*: an ELF image, a `ustar`
archive, a `DMAR` table, a filesystem. All of it is controlled by whoever can write the boot device,
which is a serious threat and a bounded one — it arrives once, at rest, at a moment of the system's
choosing.

Network input is different in three ways that should shape the design rather than be handled after
it. It arrives **continuously**, from **anyone who can reach the wire**, at **line rate**. A parser
bug in `elf::parse` is reachable by someone who can already write your disk. A parser bug in an
Ethernet or IPv4 header is reachable by anyone on the segment, repeatedly, for free.

That is the argument for where the parser lives, and it is the whole reason this RFC puts the
protocol code in a different domain from the one holding the device's DMA authority.

### Network access is ambient everywhere else, and does not have to be

On a conventional system any process can open any port and send to any address; the check, where
there is one, is a policy layer bolted above an interface that grants everything. Bhaskix deleted
its filesystem namespace for exactly this shape of reason (RFC 0016), and a socket is the same
problem: a number that means *the network* is ambient authority with a small integer in front of it.

A program here should hold a socket or not hold one, and what it may reach should be a property of
the thing it holds.

## Design

Two domains, mirroring the block path — `bin/blkd` drives the device, `bin/fsd` owns the format —
because that split has now survived contact with a journal, a page cache and an IOMMU, and because
the alternative puts a parser for hostile input in the domain that can point a DMA engine.

```
   the wire
      │  frames
      ▼
  bin/netd          domain: DMA window, BAR frames, IrqHandler + Notification
      │             moves frames. Parses nothing.
      │  shared ring + notification
      ▼
  bin/ipd           domain: ARP, IPv4, UDP. Owns the address and the route.
      │             every hostile byte is parsed here and nowhere else.
      │  Socket capabilities, handed back in replies
      ▼
  a program         holds one socket. Reaches that flow and nothing else.
```

### `netd` — the device, and nothing above the frame

The same domain shape as `bin/blkd`, which is already built and gated: a DMA window capability so
the device translates, `Frame` capabilities for its BAR windows, an `IrqHandler` and a `Notification`
for its MSI-X vector, and an endpoint it answers on. The kernel enumerates the bus — PCI
configuration space is port I/O, and a domain holding that would hold every device on the machine —
and hands over exactly those.

Two virtqueues rather than the block driver's one — receive and transmit — both
`device/src/virtqueue.rs`, unchanged.

*Their indices are fixed by the virtio specification rather than chosen here, and this document does
not state which is which: nothing in this tree records it (`blkd` selects queue 0 because it has
only one), so the number would be written from memory. **Step 2 reads it out of the specification
and writes it down**, with the section cited. A queue index taken on trust is the kind of thing that
works on one device and not the next.*

**`netd` parses nothing.** It does not read a MAC address out of a frame, does not filter, does not
know what an IP header is. It owns descriptors, buffers and the `virtio_net_hdr` prefix the device
itself requires — and the last of those is the only structure it interprets, because the device
writes it, not the network.

Stated as a rule because it is the property the split exists to create: **a frame's bytes are opaque
to the domain that has DMA.**

### The path a packet does not take through an IPC message

A `Call` per packet is a round trip per packet, and at the frame rates a virtio device produces that
is not a stack, it is a benchmark of the IPC path. So the `netd` ↔ `ipd` interface is a **shared
memory ring** (RFC 0009) plus a **notification** (RFC 0010): one region of buffers, a producer index
and a consumer index, and a signal when a reader has something to do.

This is the page cache's shape (RFC 0016 step 5) rather than a new invention — a service lending a
region to another domain, revocable, with the lender deciding when the lending ends.

The same shape appears again between `ipd` and a program holding a socket, for the same reason.

**What this costs, said plainly rather than assumed away.** A packet is copied into a ring by
`netd`, read by `ipd`, and copied into a second ring for the application: two copies and two domain
crossings that a monolithic stack does not pay. The RFC does not claim this is free. It claims it is
*measurable*, and the testing plan below measures it before the split is defended in any other way.

### `ipd` — every hostile byte, in one place

Holds: the ring to `netd`, the interface's IPv4 address and prefix, one default route, and an ARP
cache. Owns the port space.

Parses, and therefore is the whole of this system's exposure to the network:

| Parser | Fuzz target |
|---|---|
| Ethernet II header | `fuzz/eth_parse` |
| ARP request/reply | `fuzz/arp_parse` |
| IPv4 header, including options and fragmentation | `fuzz/ipv4_parse` |
| UDP header | `fuzz/udp_parse` |

Four targets, all host-testable against a byte slice with no device and no emulator, which is
`docs/coding-style.md` §8's requirement and the design property that makes it cheap to satisfy.

**Fragment reassembly is where this will hurt.** An IPv4 reassembly buffer is unbounded state
controlled by a remote party, and it is the classic resource-exhaustion primitive in every stack
that has ever had one. This RFC proposes a fixed reassembly table with a per-entry deadline and a
hard cap, refusing rather than allocating when full — the same posture `MAX_SPACES` and
`MAX_DOMAINS` take, and for the same reason: a fixed table's failure is a refusal, and a growing
one's failure is somebody else's out-of-memory.

### A socket is a capability, handed back in a reply

A program calls `ipd`'s endpoint:

```
BIND_UDP   arg0 = local port, or 0 to be assigned one
           arg1 = the slot to put the result in
       ->  that slot, holding a Socket capability
```

The reply carries the capability, by RFC 0016's mechanism — a one-shot reply capability naming the
one thread that asked, valid only while it waits. Nothing here is new; this is the third caller of
it, after `OPEN_AT` and the lent cache page.

~~A new `ObjectKind::Socket`, badged with `(index, generation)` exactly as a directory handle is~~ —
**corrected 2026-08-12, before step 5 was built.**

There is no new object kind, and the sentence above got its own cited precedent backwards. **A
directory handle is not an object kind**: RFC 0016 deleted `ObjectKind::Directory` and
`ObjectKind::File`, and a directory a program holds is a *badged endpoint capability to the
filesystem service*. `kernel/src/cap.rs` contains no `Directory`, and the decision log's CR1 row
records why.

Following that precedent properly means **the kernel gains nothing**: no object kind, no capability
type, no kernel code at all. `ipd` is a userspace service, so a socket is a badged capability to
*its own* endpoint — minted by `ipd` with `HAND`, stamped by the kernel so the badge cannot be
forged, and landing in the slot the **caller** named with `EXPECT` rather than one the service
chose. `user/fsd/src/main.rs` already does exactly this for a directory.

The badge is still `(index, generation)`, so a socket that has been closed and its slot reused is
distinguishable from the one that was there before. Badges are one-way and unforgeable, which
RFC 0016 step 1 established and which everything below depends on.

Methods, proposed at 51–53. `START` is 50 and is the highest allocated; **45 is also free**, an
apparent gap in the existing numbering that should be understood before it is filled rather than
reused by someone who assumes it was skipped for no reason:

| Method | Meaning |
|---|---|
| `SEND_TO` | destination address and port in the arguments, payload in the socket's ring |
| `RECV_FROM` | takes the next datagram from the ring; source address and port in the reply |
| `CLOSE` | ends the binding and revokes the ring |

A `Notification` is bound to the socket for readability, so a program waits rather than spins — the
same pairing `blkd` uses for its interrupt.

**What holding one means.** A program with a `Socket` can send and receive on that flow. It cannot
enumerate ports, cannot bind another, cannot see another program's traffic, and cannot reach the
device. A program without one has no way to name the network at all: there is no global port table
reachable without a capability, in the same way and for the same reason that there is no way up out
of a directory.

**Binding a port is granting**, which is the same sentence RFC 0015 wrote about mounting, and it is
not a coincidence — it is what the model produces every time the ambient version is removed.

**The constraint TCP imposes on this shape, now, while it is cheap.** A TCP socket is created two
ways: by connecting, and by *accepting* — and an accepted connection is a new socket the service
creates on the program's behalf. So `Socket` must be a kind that a service can mint and hand back at
a moment the program did not initiate, which the reply mechanism supports but only if the program is
waiting in a call. RFC 0019 will need `ACCEPT` to be a call the program blocks in, not a callback.
Recorded here so that it constrains this design rather than surprising that one.

### Address abstraction, with only one family implemented

`Address` is an enum with one variant today. Every signature that takes an address takes that type,
the routing table is keyed on it, and the socket methods carry it. IPv6 then adds a variant, a
parser and a neighbour-discovery mechanism — not a second copy of everything above it.

This costs a few bytes per socket now and saves the retrofit that address abstractions are famous
for needing.

### Failure behaviour

| Situation | Behaviour |
|---|---|
| No virtio-net device | The system boots without networking and says so on the console, as it already says `block domain no second device`. Networking is not a boot dependency. |
| `netd` **dies** | Every socket stops, and every caller blocked on it **is told**: `exit` takes the dying thread's reply obligation and abandons its caller with `Revoked`, naming both sides on the console (`kernel/src/sched.rs:2047`). RFC 0017 step 3 built this and closed RFC 0013's question 1 on 2026-08-07. Nothing new is needed here. |
| `netd` **hangs** | Every caller blocks, indefinitely. This is the live gap, and it is a different one: `kernel/src/ipc.rs:44` states it plainly — *"No timeout on `Recv`. A service bug hangs its callers. RFC 0008 records this as unresolved; it needs a policy decision, not code."* A dead server is detectable because something died; a live server that never answers is indistinguishable from a slow one, which is why it needs a policy and not a mechanism. Networking sharpens it: a hung filesystem stalls the programs using it, a hung stack stalls every program holding a socket, and a stack has a reason to be slow that a filesystem does not — it is waiting for a remote party who may never answer. **This RFC does not solve it and should not be accepted as though it had.** |
| Ring full, receive | The oldest datagram is dropped and a counter increments. Dropping is what a datagram protocol is permitted to do; blocking the driver is not, because the driver blocking stops every flow rather than one. |
| Ring full, transmit | `SEND_TO` returns `CONGESTED`, which the shell already knows how to retry (`status::CONGESTED`, and the bounded retry added 2026-08-11). |
| Hostile frame | Refused at the parser, counted, and never propagated. Every refusal path is a host test. |
| Reassembly table full | Refused. See above. |

### Where `unsafe` is needed

In `netd` only, and only where `blkd` already needs it: volatile access to the device's registers
through `Mmio<T>`, and the descriptor rings. `ipd` should require **none** — it parses byte slices,
which is exactly the property that makes its four fuzz targets host-runnable — and it should declare
`unsafe_budget = 0` so that a future `unsafe` in the network parser is a gate failure and a
conversation.

## Alternatives considered

| Alternative | Why rejected | Would reconsider if |
|---|---|---|
| The stack in the nucleus | It is the largest attack surface in the system and its input is the most hostile. Putting it in the nucleus contradicts the project's one architectural claim. | Never. |
| Driver and stack in one domain | Fewer copies, one less service to lose. But it puts a parser reachable by anyone on the wire in the domain that holds the device's DMA authority — the inverse of what the block split bought. | If measurement shows the crossing costs more than the security argument is worth, and the parser can be sandboxed *within* the domain some other way. |
| A per-application stack library, driver hands out per-flow queues | The most capability-native option: no shared trusted stack, and a compromised stack compromises one program. Rejected as *first*, not as wrong — it needs flow demultiplexing in the driver domain, which needs the driver to parse headers, which is the thing `netd` is defined not to do. | After UDP works. It is the most interesting thing in this table and it deserves its own RFC. |
| Vendor an existing stack (`smoltcp` or similar) | `ALLOWED_EXTERNAL` in `tools/check-deps.py` is empty by policy, and `docs/security.md` §1 treats a dependency as attack surface. The one exception ever made — `libfuzzer-sys` — is host-only and never linked into anything that boots. A network stack is the opposite: it is in the boot graph and it faces the attacker. | If it could be vendored under this project's own `unsafe` budget, fuzzed as our own code, and reviewed as such. That is most of the cost of writing one. |
| A socket as a file-descriptor number | A number that means *the network* is ambient authority. The system deleted `kernel/src/namespace.rs` to stop exactly this. | Never. |
| A `Call` per packet, no shared ring | Simpler, and one fewer revocable region to get wrong. But it makes throughput a measurement of the IPC path rather than of the stack. | If measurement shows the ring buys less than it costs in complexity at the packet rates we actually reach. |
| TCP in this RFC | Its state machine, retransmission policy, congestion control and failure modes are an RFC's worth of argument on their own, and none of the path below it can land while that argument runs. | It is RFC 0019, and this document is shaped so it does not have to reopen anything here. |
| IPv6 in this RFC | Doubles the first implementation, including a second neighbour-discovery mechanism, before anything has sent a packet. | The address type is abstract from the start specifically so this is additive. |

## Impact on existing design documents

- **[roadmap.md](../roadmap.md) §Phase 2** — the networking bullet becomes partially done; the exit
  criterion "does useful network I/O" is met by UDP and not by the roadmap's own list, which names
  TCP. The bullet must be split rather than ticked.
- **[architecture.md](../architecture.md)** — the service diagram gains two domains.
- **[security.md](../security.md) §1** — the threat model does not currently contemplate a
  continuously hostile input source. The paragraph on untrusted input describes media, not peers,
  and becomes incomplete the moment `netd` receives a frame.
- **[driver-model.md](../driver-model.md)** — gains its second driver, and is where the answer to
  "did RFC 0014 pay for itself" belongs.
- **[coding-style.md](../coding-style.md) §8** — its list of parsers requiring fuzz targets gains
  four entries.
- **`tools/check-deps.py`** — `bhaskix-net` at layer 4 finally exists; `bin/netd` and `bin/ipd` need
  `PLACEMENTS` or `LAYERS` entries, which is a deliberate line in that file by design.

## Security implications

**New authority.** `Socket` is a new object kind and a new thing to hold. It is narrow by
construction — one flow, no enumeration — and it *removes* ambient authority rather than adding it,
because there was no way to reach the network before and the way added is not ambient.

**New reachable-without-a-capability surface: none.** A program with no `Socket` cannot name the
network. There is no port table, no interface list, and no `netd` endpoint in any program's CSpace
but `ipd`'s.

**New parsers for untrusted input: four**, listed above with their fuzz targets. This is the
material change in the system's exposure, and it is larger than every previous parser combined —
not because the parsers are harder, but because the attacker no longer needs to write your disk
first.

**A new class of denial of service.** Fragment reassembly, ARP cache growth and ring exhaustion are
all remote-triggered resource pressure, which the system has never faced. Every one is answered with
a fixed table and a refusal, and every refusal path is a test.

**Out of scope, explicitly**: filtering, firewalling, and any policy about *which* peers a socket
may reach. The badge can carry it and the model supports it; this RFC does not design it, and says
so rather than leaving a reader to assume it is handled.

## Performance implications

The split costs two copies and two domain crossings per packet that a monolithic stack does not pay.
That is the honest headline and it should be measured before it is argued about.

| Measurement | Why |
|---|---|
| Datagrams per second, one flow, largest and smallest payload | The headline number, and the one the split threatens |
| Round-trip latency, host to guest and back | What an interactive user notices |
| Copies per packet, counted rather than reasoned about | The claim above is a hypothesis until something counts them |
| The same three with `ipd` and `netd` folded into one domain | The only way to price the split. A temporary build, not a shipped configuration |

That last row is the one that matters: an architectural argument for a boundary should be able to
say what the boundary costs. If nobody builds the folded version once, the number is a guess.

## Testing plan

**On the host, which is most of it.** The four parsers take a byte slice and return a decision, so
every header field, malformation, truncation and boundary is a host test with no device and no
emulator. The ARP cache, the reassembly table and the socket table are pure data structures with
their own tests. `docs/coding-style.md` §8 prefers this and the design was shaped to make it
possible.

**Four fuzz targets**, from the first commit that introduces each parser rather than afterwards. The
project's own record on this is instructive: M6-03 shipped with a seeded mutation harness and the
deviation sat in TRACKER until 2026-08-10.

**In QEMU.** `-netdev user` with the built-in slirp gives a routable network with no privileges and
no host configuration, so every contributor can run the whole path: ARP resolution, a UDP echo to
the host, and a datagram larger than the MTU to exercise fragmentation.

**Negative tests, because this project has learned that a gate nobody has watched fail is not a
gate.** At minimum: a checksum deliberately broken must be refused and counted; a reassembly table
filled with first-fragments-that-never-complete must refuse rather than grow; a socket whose
generation has been reused must not receive the previous socket's traffic; and `netd` must refuse to
transmit a frame whose buffer is outside its DMA window, which the IOMMU should make a fault rather
than a leak.

**On real hardware: nothing, and this is a gap.** M1-17 is blocked on a physical machine, so a real
NIC has the same problem. Everything here is tested against one emulated device, and the project's
own history says that machines see different bugs — the IPC stall needed real parallelism, the
single-CPU hang needed one CPU. This should be stated in TRACKER as an unmet condition, not
discovered later.

## Unresolved questions

### Decided by acceptance

1. Two domains, not one, and not the nucleus.
2. UDP now; TCP is RFC 0019; the socket shape must not need changing for it.
3. IPv4 now; the address type is abstract from the first line.
4. Shared rings between domains, not a call per packet.

### Genuinely open

1. **What owns the interface's address?** DHCP is a protocol, a client, and a lease timer, and it is
   not obvious it belongs in `ipd` rather than in a program holding a socket — which would be the
   more capability-shaped answer, and would make the address configurable by something that can be
   restarted. Deferred; a static address is enough to prove the path.
2. **How many interfaces?** One, today, because the routing table has one entry. The design does not
   forbid more and nothing has been built that assumes one.
3. **Does `netd` need to be told its MAC address, or read it?** The device reports one; whether the
   domain may choose a different one is a question about whether a domain can spoof at layer 2, and
   the answer is probably no, and it is not obvious.
4. **A service that hangs rather than dies still hangs its callers, and this RFC makes it matter
   more.** There is no timeout on `Recv`; `kernel/src/ipc.rs:44` has said so since it was written
   and attributes it to RFC 0008, calling it a policy decision rather than a missing mechanism. A
   stack is the worst subsystem to have it in, because it is the first one with a legitimate reason
   to be slow — it is waiting on a remote party — so "unresponsive" and "waiting" are genuinely hard
   to tell apart here in a way they never were for a disk. Who decides the policy, and whether it
   is a per-call deadline or something a caller opts into, is not decided by this RFC.

   **Correction, 2026-08-12, the same day this was drafted.** The first version of this document
   said instead that *"RFC 0013's question 1 is now blocking in practice — a caller whose service
   died blocks for ever"*. That was wrong, and it was wrong about something already fixed: RFC 0017
   step 3 closed question 1 on 2026-08-07, `docs/rfc/0013-service-framework.md:242` records it
   struck through, and `kernel/src/sched.rs:1987-2064` is the code — a dying thread's reply
   obligation is taken as it stops and its caller is woken with `Revoked` and named on the console.
   The claim was written from the summary in TRACKER's Phase 2 table, which lists question 1 among
   the gaps RFC 0017 *found*, without reading on to the row that says it also answered it. Left in
   rather than deleted, because the wrong version is the reason this question is stated narrowly
   now.

## Implementation plan

1. **`bhaskix-net`, host-only.** The four parsers, the address type, the ARP cache, the reassembly
   table. No device, no domain, no IPC — all host tests and four fuzz targets. This step is most of
   the security-relevant code and it can be reviewed with no kernel at all.
2. **`bin/netd`.** virtio-net in a domain, reusing `device/src/virtqueue.rs`. Sends and receives
   frames against a loopback of its own making, with the mock-MMIO harness on the host and QEMU for
   the real device. Answers the question RFC 0014 asked: how much of `blkd` did not have to be
   written again.
3. **The `netd` ↔ `ipd` ring.** Shared region, notification, revocation on teardown. Exercised by a
   frame going out and coming back through slirp, with no protocol above it.
4. **`bin/ipd` with ARP and IPv4.** The wire's first correct packet: an ARP exchange and an ICMP
   echo reply, which needs no socket and proves the path end to end.
5. **The `Socket` object and `BIND_UDP`.** The ABI change, the object kind, the badge, the reply
   carrying the capability. A program that holds one and a program that does not, tested as a pair —
   the second is the one that proves the first.
6. **A user program that does something.** The smallest useful thing, so the roadmap's "does useful
   network I/O" is met by a demonstration rather than by assertion.
7. **The folded-domain measurement.** Build `netd` and `ipd` as one domain, take the four numbers,
   record them in TRACKER, and throw the build away. The boundary's cost belongs in the record next
   to the argument for it.
