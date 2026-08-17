# RFC 0027: A sockets API worth the name

| | |
|---|---|
| **Status** | Draft |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | userspace (a crate), tools |
| **Milestone** | Phase 2 — the networking bullet's named remaining scope, [roadmap.md](../roadmap.md) |
| **Depends on** | [RFC 0008](0008-syscall-and-ipc-shape.md) (whose answer to A4 this refuses to undo), [RFC 0018](0018-networking.md) (UDP sockets as badged capabilities), [RFC 0020](0020-tcp.md) (the TCP service), [RFC 0022](0022-capability-in-a-call.md) (the ring handover), [RFC 0023](0023-a-wake-for-a-connection.md) (the wake) |

---

## Summary

**A client crate, not a new interface.** `bhaskix-sock` is a `no_std` library a ring 3 program
links to use the network authority it already holds: the UDP socket calls, the TCP three-leg
ring handover, the stream arithmetic (byte `k` of the stream at `k` modulo the ring), the
window-reporting discipline, and the memory-wait that made the echo fast. Nothing below the
crate changes — no new syscall, no new object kind, no new service, no new authority. What
changes is that the fourth networked program will cost tens of lines instead of eight hundred,
and its `unsafe` budget will be near zero, because the volatile ring accesses and the syscall
stub live in one audited place instead of being copied with local variations into every
program that talks.

## Motivation

**The invoice, which is RFC 0014's argument arriving at the next layer up.** Three programs
speak the network today and each hand-rolls the whole exchange: `bin/tcpc` is 797 lines and 13
`unsafe` blocks, most of them the handover legs, the stream-ring arithmetic and the wait
discipline; `bin/dhcp` is 332 lines and 9 blocks, re-deriving the UDP lend-a-page dance; the
shell's network commands carry 9 more. The lessons those programs paid for are recorded in
their comments — the emit-stamp ordering, the window-reopening deadlock, the touch-every-page
fault trick, the `Congested` retry bound — and a comment is a lesson recorded, not a lesson
enforced. The fourth program will re-learn some of them. A crate is the difference.

**And "worth the name" has a specific meaning here, settled by RFC 0008.** The native ABI *is*
the capability interface — question A4 was answered by refusing its premise — so a native
sockets API cannot mean descriptors, `select`, or a libc shim; those belong to the Linux
personality ([RFC 0005](0005-linux-abi-compatibility.md)) when it arrives. What it can mean,
and what this RFC builds, is the capability-shaped exchange made *usable*: a program that
holds a network endpoint and some pages should be able to open a connection in five lines that
are obviously correct, not five hundred that were debugged into correctness once.

**What happens if we do nothing:** the roadmap's networking bullet stays open on this item,
every future networked program pays the eight-hundred-line tax, and the `unsafe` those
programs carry keeps being reviewed N times instead of once.

## Design

### The shape: capabilities in, ergonomics out

Everything the crate does is parameterised by **slots the program already holds and addresses
the program already chose**. The crate never allocates, holds no global state, and confers
nothing: a program that was not granted the network cannot name it through this crate any more
than without it.

```rust
// UDP, the dhcp/shell shape: a socket is a capability, a payload is a
// Memory object the program lends for exactly one call.
let socket = udp::bind(NETWORK_SLOT, SOCKET_SLOT)?;
socket.send_to(PAYLOAD_SLOT, destination, port, length)?;
let (from, from_port, length) = socket.recv_from(PAYLOAD_SLOT)?;

// TCP, the tcpc shape: rings the program owns, gifted across CONNECT's
// legs; the connection capability rides the reply into a declared slot.
let connection = tcp::connect(
    SERVICE_SLOT,
    destination,
    port,
    Rings { send: (SEND_RING_SLOT, SENDR_AT), recv: (RECV_RING_SLOT, RECVR_AT) },
    Some(Wake { slot: WAKE_SLOT, badge: 1 }),
    CONNECTION_SLOT,
)?;
let mut stream = connection.stream(hertz);
stream.send(&bytes)?;                      // ring write + SEND accounting
stream.wait_for(offset, expected)?;        // the memory-wait: zero calls until the byte is there
stream.consumed(bytes_read)?;              // the window-reopening discipline, impossible to forget
```

The types are thin and their fields honest: a `udp::Socket` is a slot number; a
`tcp::Connection` is a slot number plus the ring addresses; a `Stream` adds the cursor
arithmetic. Programs that need the raw exchange (the boot instrument's mutation arms, a
future test) can still speak it — the crate is a shore, not a wall.

### What moves into the crate, named

1. **The syscall stub** — the one `asm!` block, today copied into every program.
2. **The handover legs** — `HAND`-then-`CONNECT` per ring, `EXPECT` before the capability
   leg, the optional wake gift as leg 3, with the leg numbering and the refusal shapes
   (`BARE`, `LATER`, `Congested`-with-bounded-retry) handled once.
3. **The stream arithmetic** — byte `k` at `k % ring`, the wrap, the never-overwrite-unacked
   pacing bound, as *pure host-tested functions* the syscall-bound types call.
4. **The window discipline** — `consumed()` is how bytes are acknowledged to the service, and
   the type makes the report impossible to forget rather than documented as important.
5. **The memory-wait** — poll the program's own receive ring with zero IPC calls until the
   data is present, waking on the connection's notification with an armed deadline as the
   backstop; the instrument-proven pattern (deliver-to-seen fell from ~2 ms to ~100 µs)
   becomes the default instead of the exception.
6. **The touch-on-attach fault trick** — a mapping that did not take faults beside the attach
   that claimed it, not deep in a serve loop.

### Where `unsafe` lives, and the budget argument

The crate carries the syscall stub and the volatile ring accesses — the same lines the
programs carry today, written once, with one `SAFETY` argument each and a budget set to
exactly what they cost. The ported programs shed theirs: the proof-by-numbers is that the
*sum* of `unsafe` across `sock` plus the ported programs comes out well below today's sum
across the programs alone, and the per-program budgets drop to what is genuinely local (a
panic handler's `ud2`, a report page's writes).

### Layering, and one renumbering

`sock` depends on `bhaskix-abi` and nothing else. Programs depend on `sock`. The dependency
checker's layer map currently holds the leaf crates and the programs one integer apart, so a
crate *between* them needs a rung: the leaf layer renumbers (a one-dict edit, semantics
unchanged — the checker compares, never stores meaning in the number) and `sock` takes the
slot between leaves and programs. A program library may never depend on a service crate, the
kernel, or `arch`; the map enforces that the same way it enforces everything.

### What this RFC does not do

- **No POSIX.** `socket()/bind()/select()` and descriptor tables are the Linux personality's
  business (RFC 0005), built over the same services when that RFC's time comes.
- **No new service, no new syscall, no ABI change.** The exchange is RFC 0022's, unchanged;
  if porting exposes a wart in it, the wart is recorded here and fixed by its own change.
- **No IPv6.** The address argument stays what the services speak (IPv4 in a word); the
  types leave the field wide enough that v6 is a widening, not a redesign, and the
  networking bullet keeps IPv6 as its own open item.
- **No runtime.** No allocator, no global context, no implicit slots: every capability and
  every address is the caller's, stated per call or per type.

## Alternatives considered

| Alternative | Why rejected | Would reconsider if |
|---|---|---|
| **POSIX-shaped native API** (descriptors, `socket()`, `select()`) | A4 was settled by refusal: the native ABI *is* the capability interface, and a descriptor table is ambient indexing smuggled back in. POSIX belongs to the Linux personality, over these same services | Never natively; RFC 0005 is the door |
| **A sockets *service*** — a broker domain between programs and `ipd`/`tcpd` | The services exist; the gap is client ergonomics. A broker adds a boundary to price and a domain to schedule, with no new authority story — it would be structure without a claim | A multiplexing need the per-program capabilities cannot express — many short-lived sockets per program, say — and even then the first answer is a wider grant, not a middleman |
| **New syscalls for socket operations** | A2 is settled: six syscall kinds, authority as capability arguments. The exchange already works through them; a sockets syscall would be a numbered table growing back | Never |
| **Grow `bhaskix-abi` with the client machinery** | The ABI crate is the interface both sides compile against — constants and framing, budget zero. A client layer with volatile ring access and a syscall stub is one side's convenience, and putting it in the interface would make the kernel carry code only ring 3 runs | Never; the split is the point |
| **Fold `bhaskix-net` (packet parsing) in** | `sock` is exchange and stream mechanics; parsing is a different concern with its own fuzz surface. `bin/dhcp` links both and that is correct | A consumer that cannot exist without both fused, which nothing suggests |
| **Leave it to copy-paste** | The status quo. Three copies exist, each subtly different, and the differences are where the next bug lives | — |

## Impact on existing design documents

- **[roadmap.md](../roadmap.md)** — the Phase 2 "what remains" list loses "a sockets API
  worth the name" on acceptance; the networking bullet's remaining open item becomes IPv6
  alone.
- **[architecture.md](../architecture.md)** — no claims change; the crate is userspace
  convenience over interfaces that document already describes.
- No other document makes claims this RFC touches.

## Security implications

- **New authority: none.** The crate wields only capabilities the program already holds;
  every function takes the slot as an argument. A program without the grant gains nothing by
  linking it.
- **`unsafe` concentration**: the syscall stub and ring accesses move from N programs into
  one crate with one budget — strictly fewer lines under review, with the before/after sums
  recorded in TRACKER at each port.
- **Untrusted input**: `recv_from` lengths and stream state words come from services the
  program already trusts for exactly this; the crate bounds-checks them against the caller's
  own ring sizes anyway, and those checks are host-tested with hostile values.
- **Scope moves**: none.

## Performance implications

Neutral by construction — the same calls, the same rings, the same waits, refactored not
redesigned. The proof is the gates: the ported `bin/tcpc` must keep every networked boot gate
green with its measured lines intact, and the `tcp measure` distribution must sit inside the
recorded range. Any regression is a bug in the port, not a cost of the crate.

## Testing plan

- **Host**: the stream arithmetic — offsets, wrap, pacing bounds, window accounting, the
  hostile-length checks — as pure functions with the edge-seeded harness treatment
  (coding-style.md §8's M6-01 pattern).
- **QEMU**: the ported programs *are* the test: `bin/tcpc` ported means every TCP boot gate —
  outbound echo, bulk through the wrap, listener, inbound serve, orderly close, the measure
  line — exercises the crate on every networked boot. `bin/dhcp` ported does the same for
  UDP. The gates exist and do not change, which is the point.
- **Real hardware**: nothing new; M1-17 applies as everywhere.
- **Fuzz target**: none new — the crate parses nothing; the mutation harness covers its
  arithmetic.

## Unresolved questions

1. **Does the shell port?** Its network commands are interactive and its constraints are its
   own; ports one and two (tcpc, dhcp) prove the crate, and the shell follows if its budget
   sheet says so. Decided when reached.
2. **A `Stream` for the listener's accepted connection** — today the accepted connection
   reuses the listener's rings; whether the type should model that sharing or hide it is
   decided by the tcpc port, which is the only consumer of it.
3. **Where the report-page/`ATTACH` idioms live** — every program also hand-rolls report
   writing and mapping-attach; that is not socket work and deliberately not this crate. If a
   third idiom-collection appears, a `bhaskix-user-rt` crate is its own conversation.

## Implementation plan

1. **The crate and the UDP half**: `sock/` with the syscall stub, `udp::{bind, Socket}`, the
   layer-map rung, and the host-tested bounds arithmetic. Port `bin/dhcp` onto it; its gates
   unchanged, its budget drops.
2. **The TCP handover**: `tcp::connect`/`listen`/`accept` with the legs, `EXPECT`, the wake
   gift, and the refusal shapes handled once.
3. **The stream**: the ring arithmetic as host-tested functions, `Stream` with `send`,
   `wait_for` (the memory-wait), `consumed` (the window discipline).
4. **Port `bin/tcpc`**: every networked gate green over the ported client, measure line
   inside the recorded range, budget sheet before/after in TRACKER.
5. **The shell, if question 1 says yes.**

Steps 1 and 4 are the invoices paid; the RFC is accepted or not on what they show.
