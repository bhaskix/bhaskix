# RFC 0092: A listener that can be closed

| | |
|---|---|
| **Status** | Draft 2026-10-19. Written before any of it. **The lead decided both open questions the same day**: a connection that lives on pins its listener's slot until it ends, and connections nobody accepted are reset, as Linux does — which adds an abort to the design (§4, §5). ~~Nothing built.~~ **Step 0 done 2026-10-19; steps 1 and 2 done 2026-10-20** — listener slots have generations, from the connection table's own `Table`, and the `GONE` arm takes listener badges; a listener's rings and wake are gifted returnable, as a dial's are. **Step 3 written 2026-10-20 and not yet exercised**: tcpd answers `RELEASE` on a listener in §4's order, and the abort flag on a connection, but nothing sends either until linuxd does in step 4, so step 5's gates are its proof. |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | net / userspace |
| **Milestone** | L1 ([roadmap.md](../roadmap.md)) — a hosted server that restarts, and a machine that serves more than three listeners over a boot |
| **Depends on** | [RFC 0086](0086-the-motivating-workload.md) (hosted listeners, step 3a), [RFC 0090](0090-a-hosted-program-that-dials-out.md) (part 6: a pair given back with `RELEASE` and `REVOKE`) |

---

## Summary

`bin/tcpd` has no way to stop listening. A listener lives until the machine stops: its port, its
table slot and every ring pair it was given. In `bin/linuxd` that is a stated limit — "a pair given
to a listener stays with it" — and it now costs more than pairs. Raising tcpd's listener table from
four to six (2026-10-19) was this limit, deferred. linuxd's own three listener slots are all taken
on the `iommu` lane. And a hosted server that closes and listens again on the same port is told
`EADDRINUSE` for the rest of the boot.

This RFC proposes that **`RELEASE` on a listener's handle means "stop listening"**, and that the
listener gives back what it holds in a fixed order, in one sentence each:
- the port, at once;
- connections nobody accepted, aborted;
- armed pairs, revoked;
- pairs held by connections that were accepted, when those connections end;
- then the slot, under a new generation, so the old handle names nothing.

No new method number: `RELEASE` already means "I am done with this" for a dial.

## Motivation

What the limit costs today, measured or read 2026-10-19:

- **tcpd's listener table** (`MAX_LISTENERS`) went from 4 to 6, because the `iommu` lane's four
  listeners were never given back and IPv4 TCP loopback's probe needed a fifth.
- **linuxd's three listener slots** (`adapter::TCP_LISTENER_COUNT`) are all used on that lane: the
  stream test, the `epoll` test and the loopback probe. The fourth hosted `listen` of a boot is
  answered `ENFILE`, whatever the first three did since.
- **Pairs.** A listener is armed with up to its backlog of the pool's 21 pairs, capped at 17 for
  listeners. The HTTP lane's server takes all 17. None comes back when it closes.
- **The port.** A closed hosted listener keeps answering SYNs. Its connections complete inside
  tcpd's cookie path and sit unclaimed; a program that listens on that port again is refused.
- **Linux**, which a hosted program expects: `close` on a listening socket frees the port at once,
  and connections that completed but were never accepted are reset. ~~That is from the behaviour of
  `inet_csk_listen_stop` as commonly described, to be read from the source at step 0, not assumed
  from this sentence.~~ **Read at step 0 (2026-10-19, Linux `24a19b9`)**: `inet_csk_listen_stop`
  calls `inet_child_forget` for every child not migrated by reuseport
  (`net/ipv4/inet_connection_sock.c`). That calls `sk->sk_prot->disconnect(child, O_NONBLOCK)` —
  `tcp_disconnect` for TCP (`net/ipv4/tcp_ipv4.c`, `.disconnect = tcp_disconnect`) — which, for an
  ESTABLISHED socket (`tcp_need_reset`), sends an active reset and sets `ECONNRESET`
  (`net/ipv4/tcp.c`).

## What is there today

Read 2026-10-19, `user/tcpd/src/main.rs` (T), `user/linuxd/src/stream.rs` (L), `sock/src/tcp.rs`
(S):

1. **Opening.** linuxd's `listen` takes a free slot of its three (else `ENFILE`) and a pool pair
   (else `ENOBUFS`), and calls `tcp::listen_open` (L ~326). tcpd's `arm_leg` for a listener
   refuses a held port (`REFUSED`, which linuxd answers `EADDRINUSE`) and a full table
   (`CONGESTED`), maps the rings, and mints the handle as `tcp::handle(index, 1, true)` — **the
   generation is always 1** (T ~2274, ~2371).
2. **Arming.** `ARM_PAIR` on the listener's handle adds a pair to its `armed` queue. Every gift is
   staged by `sock`'s `leg` with **READ | WRITE only** (S ~78–84); `connect` alone adds `REVOKE`.
3. **A connection.** `accept_syn` answers with a cookie and allocates nothing. `accept_cookie` takes
   an armed pair and inserts a connection, unclaimed, that shares the **first pair's wake**. `ACCEPT`
   hands the caller the oldest established, unclaimed one. linuxd accepts eagerly.
4. **The handle** answers `ACCEPT` and `ARM_PAIR`, and everything else `LATER`. The `GONE` arm
   that tells a caller its connection is gone excludes listener handles, so a dead listener's
   handle would be told `LATER` for ever.
5. **A dial's way back** (RFC 0090 part 6): `RELEASE` → `retire_dial` → `give_window_back`, which
   **revokes** tcpd's mapped copies of the two rings and the wake and frees the pair. linuxd's
   `reap` sees `GONE` and returns the pair to its pool. `REVOKE` needs the `REVOKE` right; `DELETE`
   would leave tcpd's copies mapped.
6. **linuxd's close** on a listener sheds the connections it took and nobody accepted (a `FIN`), and
   nothing else. It keeps no record of which pool pairs a listener holds, only a count.

## Design

### 1. `RELEASE` on a listener's handle

- **`tcp::RELEASE` (72) on a listener's handle means "stop listening."** It answers:
  - `OK` once the listener holds nothing;
  - `LATER` while it is draining — the caller asks again, as `reap` already does;
  - `GONE` for a handle whose listener is gone, which needs the `GONE` arm to take listener
    handles too.
- **Refused for the legacy listener** (pair 0, `bin/tcpc`'s fixed handover). Its pair arithmetic
  starts at 1 and nothing native closes one.
- **Refused while a pair is being armed for it**, so an `ARM_PAIR` and a close never interleave.

### 2. A generation per listener slot

A listener slot gains a generation that moves on when the slot is freed, as a connection slot's
does. A stale handle — one linuxd has not yet reaped — then names nothing, and is told `GONE`,
instead of naming whichever listener took the slot next. **Without this, closing makes a slot
reusable and a stale handle dangerous.**

### 3. Gifts a listener can give back

`sock`'s `listen_open` and `arm_pair` stage their gifts with `READ | WRITE | REVOKE`, as `connect`
does. Without `REVOKE`, tcpd could only `DELETE` its copies, which leaves them mapped (RFC 0090
part 6 says why).

### 4. The order tcpd gives things back in

1. **The port, at once.** The listener is marked closing, and `listener_on` no longer finds it.
   New SYNs to its port meet `refuse` and its RST, and the port can be listened on again
   immediately.
2. **Connections nobody accepted are aborted.** An `Event::Abort`, which sends a RST — what
   Linux does.
3. **Armed pairs** — rings mapped, no connection — are revoked with `give_window_back`, **the
   first pair last**, because accepted children share its wake.
4. **Pairs held by accepted connections** stay with their connections. When each retires through
   its own close, its pair is revoked as a dial's is.
5. **When none is left**, the first pair and the wake are revoked, the slot is freed, its
   generation moves on, and `RELEASE` answers `OK`. Asked again, it answers `GONE`.

**A program that keeps an accepted connection open keeps its listener's slot** — the lead's decision
of 2026-10-19 (question 1). The port is free at once either way, so a server that re-listens is not
held up by it; the alternative, freeing the slot at once and moving the children's wake, is costed
under Alternatives.

### 5. linuxd

- **Per-listener records.** It records which pool pairs each listener holds, a mask beside
  `listeners`, filled where `listen` takes them.
- **`close` on a listening stream** calls `tcp::release` on the listener's capability and marks it
  closing.
- **`reap`**, which already runs on every `listen` and dial, asks each closing listener. On `GONE` it
  deletes the capability, returns the listener's mask to the pool, lowers `listener_pairs`, and
  frees the slot.
- **Connections linuxd took and nobody accepted are reset**, the lead's decision of 2026-10-19
  (question 2), as Linux resets them. tcpd has already handed them over, so linuxd asks for it:
  **`RELEASE` on a connection's handle with `args[0] = 1` aborts it** — tcpd's `Event::Abort`,
  which sends a RST — and retires it as `RELEASE` already retires a dial. `args[0] = 0`, every
  caller today, keeps its meaning. The connection's pair then comes back through the same
  revocation as every other.
- **The module doc's stated limit** is replaced by what is now true.

## Alternatives considered

| Alternative | Why rejected | Would reconsider if |
|---|---|---|
| A new method, `CLOSE_LISTENER` | `RELEASE` already says "I am done with this" for a dial, and linuxd's `reap` already asks it until `GONE`. A second verb for the same intent is a second way to get it wrong | a listener needed a close with different semantics from a dial's |
| `DELETE` the listener's capability and let tcpd notice | tcpd cannot see a deleted capability, and its mapped copies of the rings would stay (RFC 0090 part 6) | the nucleus told a service when a capability it minted was deleted |
| Free the slot at once, moving surviving children to a wake of their own | correct, and the slot would never be pinned, but every child gains a second wake path and a migration while it may be mid-read | question 1 is answered "at once" |
| Keep raising the limits | the status quo since RFC 0086: four, then six — and it does nothing for the port, which a restarting server needs back | never; the port alone makes it necessary |

## Impact on existing design documents

- `user/linuxd/src/stream.rs`, module doc: "A pair given to a listener stays with it. `bin/tcpd`
  has no way to stop listening, so a hosted listener that closes keeps its pairs for the life of
  the boot." — becomes wrong.
- `abi/src/lib.rs`, `tcp::RELEASE`: gains its listener meaning. `adapter::TCP_LISTENER_COUNT`'s
  note that tcpd's limit is four is already stale and is corrected.
- RFC 0086 step 3a's stated limit, and `MAX_LISTENERS`' note in `bin/tcpd`, both said a listener
  is never given back.

## Security implications

**No new authority.** A program can close only a listener whose handle it holds, which in practice
is the adapter's. A freed port can be listened on by anything that may listen, exactly as a port
never used could.

**What changes is reuse**, which is why §2 exists. Generations make sure a handle never outlives its
listener into its successor. That is the same rule connection slots have kept since RFC 0086
step 2.

## Performance implications

None measured to begin with. Closing costs one `RELEASE` and, per pair, three revocations; a
`reap` pass gains one call per closing listener.

## Testing plan

- **Host:** the generation arithmetic. Teardown order, if it can be expressed as a pure decision
  over a listener's pairs and children — step 1 finds out.
- **QEMU, gated on the `iommu` lane:**
  - **Re-listen.** The loopback probe closes its listener, listens on `127.0.0.1:12` again, and
    dials it again. Today the second `listen` is `EADDRINUSE`; that is step 0's failing gate.
  - **More than three.** A probe that listens and closes eight times in a row, more than linuxd's
    three slots and more pairs than the listener cap — the 64-dial gate's shape. Today the fourth
    `listen` is `ENFILE`.
  - **A SYN to a closed port is refused**, by the loopback RST, as the dialer's word 25 already is.
  - **An unaccepted connection is reset.** A probe listens, dials itself, does *not* accept, and
    closes the listener; the dialler's next read must answer `ECONNRESET`.
- **Arms, each red:**
  - a close that frees no slot (the loop stops at three);
  - a close that leaves the port (the re-listen is refused);
  - a stale generation (a handle reused after `GONE` names the new listener).

## Unresolved questions

1. ~~**The slot, while an accepted connection lives.**~~ **Decided 2026-10-19**: kept until the last
   child ends.
2. ~~**RST or FIN for connections linuxd took and nobody accepted.**~~ **Decided 2026-10-19**: reset,
   through `RELEASE` with an abort flag (§5); step 0 confirms from Linux's source that Linux resets
   them, and the decision is revisited if it does not.
3. **Native listeners.** `bin/tcpc` never closes its two, and this RFC refuses `RELEASE` on the
   legacy one. A native program that needs to close one will meet this RFC's answer for hosted
   ones.

## Implementation plan

0. **Read and measure.** Read `inet_csk_listen_stop` in Linux's source. Add the two failing gates —
   re-listen and the eight-listener loop — and see them red today: `EADDRINUSE` and `ENFILE`.
   **Done 2026-10-19.** The source confirms the reset (Motivation). The measurement is not a gate
   yet, because a gate committed red turns the tree red. It is a reading the loopback probe prints
   after its close: `listening again on 127.0.0.1:12 after its close: socket 3, bind 0, listen -23`.
   **That is `ENFILE`, not the `EADDRINUSE` this plan guessed**: on the `iommu` lane linuxd's own
   three listener slots are spent — the stream test, the `epoll` test and this probe — before tcpd
   is asked, so linuxd's slot is the first thing a close must give back, and tcpd's port the second.
   The reading becomes a gate at the step that makes it answer `0`. The eight-listener loop and the
   unaccepted-reset probe would stop at the same `ENFILE` today, so they are built with the steps
   that let them get further.
1. **Generations** for listener slots, host-tested; the `GONE` arm takes listener handles.
2. **`REVOKE` on listener gifts**, in `sock`.
3. **tcpd answers `RELEASE` on a listener**, in §4's order, and `RELEASE` with the abort flag on a
   connection. **Written 2026-10-20**, with two things §4 did not say:
   - **A closing listener retires its own finished children.** tcpd retires a finished
     connection only when another is born, and a closing listener has none born, so a child that
     ended would otherwise have held the slot, and `RELEASE` answered `LATER`, for ever.
   - **`ACCEPT` and `ARM_PAIR` on a closing listener answer `GONE`**, not `LATER`: nothing more
     will be accepted or armed on it, and `LATER` would be asked for ever.
4. **linuxd closes and reaps listeners**, with the per-listener pair masks.
5. **The gates green and the arms red.** The records: TRACKER, RFC 0086's limit, linuxd's module doc,
   and `MAX_LISTENERS`, whose six can then come back down if nothing needs it.
