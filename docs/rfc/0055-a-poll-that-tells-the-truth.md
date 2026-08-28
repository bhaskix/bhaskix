# RFC 0055: a poll that tells the truth about a descriptor

| | |
|---|---|
| **Status** | 📝 **DRAFT 2026-08-28** — built and gated. BusyBox's `sh` no longer prints `poll: Function not implemented`, and still reads a line typed at the machine; the lane asserts both and was watched red two ways — removing the `poll` arm brings the complaint back, and making the peek *consume* loses every keystroke it reports. **What this does not claim.** *(1)* A positive timeout waits **at least** as long as asked and never returns early, because a thread here waits on one notification and the deadline is on another. *(2)* Sockets are answered nothing. *(3)* `ppoll` and `select` are unanswered. *(4)* `clock_nanosleep` does not report remaining time, because nothing here interrupts a sleep |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | kernel |
| **Milestone** | Phase 2 — Core Operating System (L1) |
| **Depends on** | [RFC 0053](0053-input-a-domain-was-given.md) (the input grant), [RFC 0054](0054-a-hosted-read-that-waits.md) (the parking reply and the console notification) |

---

## Summary

`poll` is answered for a hosted process. Readiness is reported from what the
adapter already knows, the console's readiness comes from a **new
non-destructive** nucleus method, and an infinite wait on the console **parks**
rather than spins. This closes RFC 0053's unresolved question 3 — *what does
`poll` say when the grant is absent?* — with a third answer neither of the two
it offered.

## Motivation

**BusyBox prints `sh: poll: Function not implemented` once per keystroke.** It
is the loudest remaining untruth on a working machine: the shell reads a line
correctly and complains about every character of it.

**RFC 0053 left the question open and said why.** Refusing is honest and makes a
shell spin; answering *"never readable"* is a lie a shell believes. Both were
bad because neither said what is actually true, and what is actually true
depends on the grant.

**What the program actually asks was measured, not assumed.** The adapter was
instrumented to print `poll`'s arguments on a boot that types at BusyBox. Every
call is `nfds = 1`, `fd = 0`, `events = POLLIN`, with **exactly two** timeouts:
`0` on the first call and `-1` on all the others. No positive timeout is ever
used. That measurement is why this RFC builds no timer.

## Design

### The console's readiness, without eating it

`POLL_INPUT` **takes** the byte. A `poll` built on it would lose a keystroke
every time a program asked whether one was waiting, which is the opposite of
what `poll` is for.

So a third method joins the two RFC 0053 put on the `Domain` capability:

| | |
|---|---|
| `DOMAIN_PEEK_INPUT` | Is a byte waiting? Answers 1 or 0 and **takes nothing** |

Same `Rights::READ` on the domain, same grant checked in the same place, so it
confers no authority the other two did not. It services the sources before
answering, for the reason `take_or_service` does: the interrupt handler signals
without reading the UART, and a peek that skipped the drain would report "no"
for a byte already arrived — and, because servicing is also what unmasks the
line, would eventually stop the interrupts too.

### What each descriptor answers

Computed by a **pure function** in `bhaskix-personality`, so the table is
host-tested rather than only booted:

| Descriptor | Readable | Writable |
|---|---|---|
| Console, domain **granted** | a byte is waiting | always |
| Console, domain **not granted** | `POLLERR` | always |
| File, directory, `/proc` | always | never — the directory capability is `READ` and `DERIVE` |
| Pipe | bytes in the ring; `POLLHUP` when the last writer is gone | room in the ring |
| Unknown descriptor | `POLLNVAL` | `POLLNVAL` |

**`POLLERR` for an ungranted console is the answer to RFC 0053's question 3.**
Not "not implemented", which makes a shell complain and guess; not "never
readable", which is a lie it believes. `POLLERR` says *there is an error
condition on this descriptor*, and that is exactly true: a `read` of it returns
`EIO`, by a nucleus check the adapter cannot lift. A caller that polls, sees
`POLLERR`, reads and is refused has been told the truth twice.

### Waiting

- **`timeout == 0`** — answer now. Complete and exact.
- **`timeout < 0`** — if the set contains the console with `POLLIN` **and** the
  domain holds the grant, park on the console notification with
  `BLOCK_ON_RETRY`, exactly as a blocking `read` does, and answer again when a
  key arrives. Otherwise answer now.
- **`timeout > 0`** — answered as if it were zero.

**The last is a stated limit, not an oversight.** This machine cannot park a
thread with a deadline: `BLOCK_ON_RETRY` carries a slot and no time, and the
reply shape would have to grow. `notify::arm` exists and is how a later RFC
would do it. Nothing here uses a positive timeout — that was *measured* — so
building it now would be an untested mechanism, and the failure it can cause is
a caller that spins rather than one that hangs.

## Alternatives considered

**Answer `poll` with `POLL_INPUT` and hand the byte back on the next `read`.**
No new nucleus method, and the adapter buffers one byte per granted domain. It
was rejected because a byte held in the adapter for a program that then exits is
a keystroke that went nowhere, and because "was a byte taken?" becomes state two
call paths must agree about. Asking a question that takes nothing is smaller.

**Report the console readable whenever it is granted.** One line, and it turns
every `poll` into a spin: the caller reads, blocks or gets `EAGAIN`, and asks
again.

**Implement `epoll` instead.** `Kind::Epoll` already exists in the descriptor
table. It is a larger surface with no caller here today, and it needs exactly
this readiness table underneath it.

## Impact on existing design documents

- **RFC 0053** unresolved question 3 is **answered**: `POLLERR`, with the
  reasoning above.
- **`security.md` §1 T11** — no new authority. The third method is the same
  right on the same capability, gated by the same grant, and it takes nothing.

## Security implications

**Nothing new is conferred.** `PEEK_INPUT` needs `Rights::READ` on the domain
and the input grant, both already required by `POLL_INPUT`, and it removes
nothing from the console. A compromised adapter can learn *whether* a key is
waiting for a granted domain — which it could already learn by taking it.

**One fewer reason to take a byte.** A program that only wants to know whether
input is waiting no longer has to consume it to find out.

## Performance implications

One extra system call per `poll` on the console, which is the same cost as the
`read` beside it. `poll` on files, pipes and unknown descriptors costs nothing
outside the adapter.

## Testing plan

1. **Host tests** on the pure readiness function: every row of the table above,
   including the ungranted console and the unknown descriptor. Watched red.
2. A pipe's row is answerable from `Pipe::held`, `Pipe::room`, `readers` and
   `writers`, **all of which already exist** — this RFC adds no accessor. That
   was checked before it was written down, because "and then I add the getter"
   is the kind of step that gets planned and never verified.
3. **The typing lane asserts `poll: Function not implemented` never appears**,
   and still asserts that BusyBox reads a line typed at the machine. Watched red
   by removing the `poll` arm.
4. **Watched red** on the peek: making `PEEK_INPUT` consume the byte must break
   the typing lane, because every character would be reported and then lost.

## What was found while building it

**The measurement that justified building no timer was invalidated by the fix
it justified.** `poll`'s arguments were measured on a machine where `poll` did
not work, and every call was `timeout = 0` or `-1`. The moment it *did* work
BusyBox took a different path through its line editor — it wrote a cursor
position report query (`ESC[6n`), polled for the answer with a **positive**
timeout, and called `clock_nanosleep`. Both were unimplemented, and the shell
that had been reading lines gave up at its first prompt.

That is worth stating plainly because the reasoning was sound and the conclusion
was still wrong: **a measurement of behaviour under the bug does not predict
behaviour after the fix.** The timed wait and `clock_nanosleep` are in this RFC
because of it, not because they were foreseen.

**Neither needed a new nucleus method.** `method::ARM` already sets a deadline on
a `Notification` and needs `WRITE`, which the adapter already holds on its
sixteen wake notifications — so a hosted thread is parked on an armed wake slot
and the console's own notification stays `READ`, unarmable, exactly as RFC 0054
left it. A program that could set a timer on the keyboard could fake a
keystroke's wake, and none can.

**A saturating multiply became a fifteen-second hang.** Converting a duration to
an absolute counter value used `saturating_mul`, on the reasoning that a huge
duration should become a huge deadline. What it produced was `u64::MAX / 10⁹`
ticks — about fifteen seconds on this machine, *whatever* was asked for. So a
`poll` with a timeout of days waited fifteen seconds; BusyBox sat at its first
prompt until the corpus lost patience and killed the domain, and the boot report
said only that one park had been refused. The overflow is a refusal now, and a
duration this machine cannot name is treated as **unbounded** — which for a
`poll` naming the console means waiting for a key, which is what the caller
wanted.

**The report was crying wolf.** `notify::wait` answers `Gone` both for a
notification that has been destroyed and for a thread that has been told to
stop, and the second is the ordinary end of a domain. Counted together, killing
a parked program printed a yellow line about a lost wake. They are counted
apart now, and the diagnosis that found all of this — the refusal counters and
the slot they name, added by RFC 0054 — is the reason it took one boot each
rather than a hypothesis.

## Unresolved questions

1. **Sockets.** A socket's readiness lives in the network service, and this
   answers nothing for one: a set containing only sockets and an infinite
   timeout answers now rather than waiting. No hosted program here opens a
   socket and polls it, and inventing an answer would be inventing a fact.
2. **`ppoll` and `select`.** Neither is answered. Both need this table and
   nothing else, so both are small once something asks.
3. **A deadline a thread can park against.** The positive-timeout limit above,
   and the reply shape it would need.

## Implementation plan

1. `personality::poll` — the flags and the pure readiness function, host-tested.
   A pipe's inputs are already public on `Pipe`; nothing is added there.
2. `input::peek_or_service`, and `PEEK_INPUT` in the nucleus behind the same
   rights and the same grant.
3. `answer_poll` in `bin/linuxd`, including the parking reply.
4. The lane's assertion, and the mutations.
