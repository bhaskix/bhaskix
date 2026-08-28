# RFC 0054: a hosted read that waits

| | |
|---|---|
| **Status** | ✅ **ACCEPTED 2026-08-28** — proposed, built and accepted the same day. All six steps built and gated. `tests/qemu/busybox-test.sh` passes and is in `make test`: BusyBox's `sh` reads a line typed at the machine, runs it, and the machine reaches its own shell afterwards. Watched red twice — removing the service from the poll path leaves the byte unfound, and answering `EAGAIN` instead of parking puts the reply back in the Bhaskix shell. **What this does not claim.** *(1)* `poll` is still unanswered, so BusyBox prints `poll: Function not implemented` once per read. *(2)* Unresolved question 1 was untested at acceptance and is **closed as of 2026-08-28** — the wake was already correct and is now gated, and a silent cap on how many sleepers a dying domain wakes was found and removed. *(3)* The lane types no `p` — see the finding below, which is BusyBox's and not the machine's |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | kernel |
| **Milestone** | Phase 2 — Core Operating System (L1) |
| **Depends on** | [RFC 0053](0053-input-a-domain-was-given.md) (the input grant), [RFC 0032](0032-a-supervisor-interface.md) (the adapter's reply shapes and its notification pool) |

---

## Summary

A hosted `read(0)` on a granted domain **parks the calling thread** on the
console's own notification and asks again when a key arrives, instead of
answering `EAGAIN` at a shell that then exits. The adapter is not the thing that
blocks, and the nucleus refuses the park unless the caller's domain holds the
input grant.

## Motivation

**BusyBox's `sh` reaches `/ #` and then leaves.** `tests/qemu/busybox-test.sh`
boots it, grants its domain the console, and types a line at it. What answers is
the *Bhaskix* shell, afterwards, because BusyBox is already gone: `read(0)` was
told `EAGAIN`, treated it as end of input, and exited. RFC 0053 named this in
its own acceptance — *"no shell has been typed at"* — and the lane is what makes
the gap a failing assertion rather than a sentence.

**A blocking take is not the answer, and this is known rather than supposed.**
`TAKE_INPUT` blocks in the nucleus on the *calling* thread. The caller is
`bin/linuxd`, which is single-threaded and serves every hosted domain from one
receive loop, so a blocking take stops the whole personality until somebody
types. It was built that way first, and the lane found it: BusyBox sat in
`read`, the adapter sat in BusyBox, and the boot only moved on when the corpus
timed out and killed the domain.

**The shape that fits already exists.** RFC 0032 step 10 gave a hosted
`futex(WAIT)` a way to sleep without the adapter sleeping: the adapter answers
`BLOCK_ON_RETRY` naming a notification it holds, the nucleus parks *the caller*
on it, and re-asks the same question when it is signalled. A blocking read is
the same problem with a different wake source.

## Design

**One new grant, one new check, one drain.**

### The notification the adapter names

The console's input notification already exists: `input::install` creates it and
binds it to the serial line's interrupt, so it is signalled by the hardware
whenever a byte arrives. The adapter is given a capability to **that**
notification in slot 22, derived **`READ`** — it may park a thread on it and may
not signal it. The futex pool is the mirror image, `WRITE` and not `READ`,
because there the adapter wakes sleepers and must never become one; here it
sleeps hosted threads and must not be able to fake a keystroke.

### The check the adapter cannot lift

`BLOCK_ON` and `BLOCK_ON_RETRY` resolve the slot to a notification. When that
notification **is** the console's, the nucleus additionally requires that the
*calling domain* holds the input grant, exactly as `POLL_INPUT` does. Without
it the park is refused and the caller is told `EAGAIN`.

**This is not belt-and-braces about the hosted program** — it cannot name a
capability at all. It is about the adapter. An adapter free to park any thread
on the console notification could hold the console's single waiter slot for
ever and the Bhaskix shell would never wake for a keypress: a denial of the
console, from a program whose console capability is `WRITE` alone precisely so
it cannot touch input. The grant bounds it to a domain somebody chose.

### Who drains

The serial interrupt handler signals the notification and does **not** read the
UART: draining is the waker's job, and `input::service` drains, then
acknowledges — in that order, because an edge raised while the source is masked
is lost.

Until now every waker was in the kernel. A parked hosted thread is not, so
`POLL_INPUT` **drains on a miss**: it takes a byte if one is in the ring, and
otherwise services the sources and looks once more. Without this the wake is a
deadlock in two moves — the byte sits in the UART, the ring stays empty, and the
thread that was woken to collect it parks again.

`service` becomes safe to call from any CPU by taking a **try-lock** around the
drain: a second CPU arriving while one drains does nothing and returns, because
the bytes are being collected and pushing them twice from two CPUs is how a ring
gets them out of order.

### What a read now does

1. `read(0, buffer, n)` reaches the adapter for a granted domain.
2. `POLL_INPUT`; a byte is copied out and the call answers `1`.
3. Nothing waiting: the adapter answers `BLOCK_ON_RETRY` naming slot 22.
4. The nucleus checks the grant, parks the caller, and returns to its loop —
   **the adapter is not blocked and keeps serving every other domain**.
5. A key arrives, the interrupt signals the notification, the thread wakes and
   the nucleus asks the adapter the same `read` again.
6. `POLL_INPUT` finds an empty ring, services the sources, and gets the byte.

## Alternatives considered

**Make `TAKE_INPUT` the answer.** It is already written and it stops the whole
personality. Rejected by measurement, not taste.

**A second thread in the adapter.** Then `TAKE_INPUT` would block only that one.
It is a larger change to a program whose single-threadedness other things
depend on — `execve` holds the child domain in one slot *because* no second exec
can be in flight — and it buys nothing the park does not.

**A dedicated in-kernel pump thread** that owns the hardware notification,
drains, and signals a second notification for everyone else. It removes the
drain-on-miss, and it costs a thread on every boot plus a rewrite of
`input::read`, which is the path every existing lane types through. Worth
revisiting if a second waiter ever needs to exist; today the grant says there is
one.

**Answer `poll` instead.** A shell that can `poll` still has to `read`, so this
comes first either way. `poll` is unresolved question 3 of RFC 0053 and is
better answered on top of this than instead of it.

## Impact on existing design documents

- **RFC 0053** unresolved question 2 — *can the grant be taken back from a
  program blocked in a read?* — moves from theoretical to concrete: there is now
  a thread that can be parked on the console. This RFC does not answer it, and
  says so: the grant is still released only when the domain ends.
- **`security.md` §1 T11** gains the adapter's new reach: it may park a hosted
  thread on the console notification for a granted domain. Bounded by the grant,
  and unable to signal it.

## Security implications

**No new authority over input.** The adapter still cannot take a byte on its own
account; the capability added is `READ` on a notification, which confers waiting
and not reading.

**A denial-of-service that is closed rather than opened.** The console
notification takes one waiter. Handing the adapter a way to park on it is
exactly the thing that could wedge the Bhaskix shell, which is why the grant
check is in the nucleus and in the same place for both reply shapes.

**A hosted process still holds nothing.** It reads input only because a domain
it belongs to was granted the console by somebody who held its capability.

## Performance implications

A parked reader costs one notification wait and no polling. The drain-on-miss
adds one try-lock and one UART read to a `POLL_INPUT` that finds nothing, which
is a path only a granted domain reaches.

## Testing plan

1. **Host tests** on the drain-on-miss and on the grant check for both reply
   shapes. Watched red.
2. **`tests/qemu/busybox-test.sh` passes**, including its positional assertion
   that the reply arrives *before* the corpus summary — which is what says
   BusyBox answered and not the shell that starts after it. This lane is the
   gate; it exists already and fails today.
3. **The lane's last assertion still passes**: the machine finishes booting
   after BusyBox exits, so a parked reader did not take the keyboard with it.
4. **Watched red** by removing the drain-on-miss: the wake happens and the byte
   is never found.

## What was found while building it

**Two faults, both caught by the lane and neither guessed.**

**A masked interrupt that presented as a lost byte.** The first version serviced
the sources only when the rings were empty, on the reasoning that a ring with
bytes in it needs no drain. But `service` is also what *unmasks* the line — the
handler masks its source and `irq::acknowledge` unmasks it — so a drain that
pulled two bytes at once left the second to be taken with no service and no
unmask. The line stayed masked, no further interrupt arrived, and the next park
slept for a keystroke that could not wake it. It looked exactly like a dropped
byte. The rule it broke is written down now where the function is: *every wake
is followed by a service*.

**A slot collision that answered `-ENOENT`.** The notification was put in slot
22, chosen by reading the fixed grants `start_linux_domain` makes and stopping
there — which missed the **root directory**, granted from somewhere else
entirely. `install_at` refuses an occupied slot, so whichever ran second lost,
and a hosted `open` answered `-ENOENT` for a directory that was no longer there.
The full suite found it; the lane could not, because the lane does not open
files. The floor hosted-domain handles are allocated from moved from 24 to 25,
the notification took 24, and the two are now tied together by a **compile-time
assertion** rather than by a comment — a comment is what failed here.

**And the grant now says so out loud, either way.** A grant that silently did not
happen is indistinguishable from a hosted program that cannot read its input.
The boot report names the slot and what it confers, and a second line
(`input park`) reports at the end of the interactive corpus how many hosted
threads parked and how many parks were refused — printed *there* because the
personality counters run before the console's line is claimed and could only
ever have read zero for this.

**A byte this BusyBox discards, which is not ours.** Byte `0x70` — lowercase
`p`, alone of every byte in `a-z`, `A-Z` and `0-9` — is read from standard input
and never appears in the line BusyBox builds. This was chased to the end before
it was attributed: the nucleus was instrumented to log every byte `POLL_INPUT`
hands out and logged all five `p`s of `echo ppqpprp busybox`; no park and no
refused copy happened for any of them; and substituting `0x71` for `0x70` in the
adapter made every one land, echo, and print. The delivery path is therefore
proved correct and the discard is in the program. The lane types a phrase with
no `p` in it and says why.

## Unresolved questions

1. ~~**What wakes a parked reader when the domain is killed?**~~ **Answered
   2026-08-28, and the answer was "it already worked, and nothing proved it".**
   `sched::mark_domain_dying` wakes every blocked thread it marks, and
   `notify::wait` releases the waiter on every way out including the one a dying
   thread takes. What was missing was a gate — `parked wake` on every boot lane:
   a thread parks on a notification, its domain is killed, and the assertions
   are that it was woken, gave the notification **back**, and was reaped.
   Watched red by marking sleepers dying without waking them.

   The waiter is the point rather than the thread. A notification takes one
   waiter, so a thread that dies still holding that claim refuses *every later
   waiter* on it for the rest of the boot — on the console's own notification,
   a keyboard that stops working, with a park counted as refused as the only
   trace.

   **And the wake was capped.** The collection that carries sleepers out of the
   queue locks was sized `MAX_CPUS * 4` — two hundred and fifty-six — on a
   machine that holds `MAX_CPUS * MAX_THREADS_PER_CPU`, five hundred and twelve,
   and it dropped the excess with no word. A domain with more than two hundred
   and fifty-six blocked threads would have marked them all dying and woken only
   some. It is sized from the same two constants the thread table is now, and
   the boot line asserts `0 wakes dropped`.
2. **Should `poll` be answered on top of this?** BusyBox prints
   `poll: Function not implemented` once per read and carries on. RFC 0053's
   question 3 asks what `poll` says without a grant, and this RFC gives the
   machinery for an honest answer with one.
3. **Why does this BusyBox discard `0x70` from its standard input?** Measured
   and attributed above, not explained. It is a fault in a binary nobody here
   wrote, and finding it would mean reading BusyBox's line editor rather than
   this machine.

## Implementation plan

1. The try-lock around `input::service`'s drain, and `input::take_or_service`.
2. `POLL_INPUT` drains on a miss.
3. Slot 22: the console notification, `READ`, granted to the adapter at boot.
4. The grant check in the `BLOCK_ON` and `BLOCK_ON_RETRY` arms.
5. `read_console` answers `BLOCK_ON_RETRY` rather than `EAGAIN`.
6. The lane moves into `make test` once it passes.
