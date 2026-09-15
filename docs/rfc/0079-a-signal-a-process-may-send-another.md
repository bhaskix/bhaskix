# RFC 0079: a signal a process may send another

| | |
|---|---|
| **Status** | Draft |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | libc (`bin/linuxd`) |
| **Milestone** | Phase 2 — Linux personality (L1) |
| **Depends on** | [RFC 0033](0033-what-a-hosted-process-is.md) (the process record), [RFC 0031](0031-linux-compatibility-as-an-adapter.md) (compatibility is an adapter, and Linux UID 0 is not Bhaskix authority) |

---

## Summary

`kill(2)` does not exist in this adapter. A hosted shell can start a child and
wait for it and cannot stop it. This adds `kill(pid, sig)` for the signals that
need no handler, and — because the question is authority rather than syscall
numbers — states which processes a hosted process may signal and why.

## Motivation

**A shell notices this immediately.** `docs/roadmap.md`'s L1 row says what is
left is *"breadth, not shape: terminal `ioctl`s, `getdents`, `stat`, ~~a
writable path~~, and the signal gaps a shell notices"*. This is the first of
those gaps: without `kill` there is no `^C`, no `kill %1`, no way to end a
child that is not going to end itself.

What exists today is narrower than it looks. `tgkill` is handled for exactly
one case — a thread signalling **itself** with `SIGABRT`, `SIGKILL` or
`SIGSEGV`, which becomes an exit — and `rt_sigaction` records a handler for the
one fault-handling demonstration RFC 0033 built. `rt_sigprocmask` answers `OK`
and does nothing. Signal number 62, `kill`, is not in the table at all.

## The authority question, which is the whole of this RFC

Linux answers "may A signal B?" with uids: same real or effective uid, or
privilege. **That answer is unavailable here and refusing it is the point.**
RFC 0031 is explicit that Linux UID 0 is not Bhaskix authority, so a rule
phrased in uids would either be a lie or would invent an authority this system
does not have.

Two candidate rules, and the reason for the one chosen:

| rule | what it grants | why not / why |
|---|---|---|
| **Any hosted process may signal any other** | Everything in the adapter | The adapter holds every hosted process's authority; this makes a compromise of any one of them a compromise of all of them's *lifetime*. `security.md` T11 already prices what the adapter holds, and this would widen it for nothing a shell needs. |
| **A process may signal its own descendants and its own process group** | What job control is | Chosen. It is the shape the process record already has — `Process` carries `ppid` and `pgid`, and `wait4` already understands `WaitFor::Group` — so the rule is a property of a tree this adapter already maintains rather than a new table. |

**The rule, stated so it can be tested:** `kill(pid, sig)` succeeds when the
target is the caller, a descendant of the caller, or a member of the caller's
process group. Anything else is `ESRCH` — *not* `EPERM`. A hosted process
should not learn that a pid it may not touch exists, and Linux's own
`kill(pid, 0)` probe is the usual way that is discovered.

## Design

**Which signals.** `SIGKILL` and `SIGTERM` to begin with, plus `sig == 0` as
the existence-and-permission probe that changes nothing. Both fatal signals end
the target's domain and record `Exit::Signalled`, which `wait4` already reports
and which `tgkill`'s existing path already constructs — so the parent's side of
this needs no new code.

**`SIGTERM` is fatal here, and that is a limitation rather than a decision.**
On Linux it is catchable, and catching it is how a program cleans up. This
adapter records handlers but does not deliver them, so a `SIGTERM` that claims
to be catchable would be a lie; ending on it is honest and matches what a
default-disposition process does. Delivering to a handler is named in
Unresolved questions and is a separate RFC's worth of work.

**`kill(-pgid, sig)`** follows from the rule without new mechanism: a negative
pid names the caller's own group, which it may always signal.

**Not `kill(-1, sig)`.** "Every process you may signal" is exactly the breadth
the authority rule refuses, and no shell needs it to run a job.

## Alternatives considered

| | |
|---|---|
| **Give the adapter a capability per hosted domain and check that** | It already holds one; the check would be `true` for every pair and would document a boundary that does not exist. |
| **Map Linux uids onto something** | RFC 0031 refuses this, and rightly: it would be the first thing in the adapter that invented authority rather than translating it. |
| **`EPERM` for a pid outside the rule** | Tells a caller that a process it may not signal exists. `ESRCH` is both the safer answer and the one Linux gives for a pid that is gone. |

## Impact on existing design documents

* `docs/roadmap.md` L1 — the first of the named signal gaps closes; the row
  should say which remain.
* `docs/security.md` T11 — the adapter's reach grows by "may end a hosted
  process's domain on another's request, within the tree". Worth a sentence,
  because T11 prices what a compromise of the adapter costs.
* `docs/rfc/0033` — the process record gains a use for `ppid` beyond `wait4`.

## Security implications

**The boundary is the process tree, and it is checked in the adapter.** A
hosted process cannot reach another's domain directly — it has no capability
naming it — so this is the adapter exercising authority it already holds on a
caller's behalf, which is what every other hosted syscall does. The new
exposure is that a compromised hosted process can end its own descendants and
group members, which is strictly less than a compromise of the adapter already
implies.

**Containment must be asserted, not assumed.** Two boot gates below assert a
refusal rather than a permission, for the reason RFC 0060's write path does: a
containment test that passes on absence tests nothing.

## Performance implications

A pid lookup in the process table on a path that is not hot, and a domain
ending that already exists. Nothing to measure.

## Testing plan

1. A hosted probe forks a child, kills it with `SIGTERM`, and `wait4` reports
   `Signalled` with the right number. Armed by dropping the signal.
2. The same with `SIGKILL`.
3. **Containment, and it is the gate that matters**: a hosted process attempts
   `kill` on a pid outside its tree — the pid of another probe — and must get
   `ESRCH`, with the target still alive afterwards. Armed by removing the tree
   check, which must turn it red and leave the target dead.
4. `kill(pid, 0)` answers `OK` for a pid in the tree and `ESRCH` for one
   outside, changing nothing either way.
5. Host tests in `bhaskix-personality` for the rule itself — caller,
   descendant, group member, stranger — armed one at a time.

## Unresolved questions

1. **Delivering a signal to a handler that `rt_sigaction` recorded.** That is
   the difference between `SIGTERM` being fatal here and being catchable, and
   it needs a way to run a hosted process's handler on a stack it owns —
   which RFC 0033's fault path does for `SIGSEGV` and which would have to
   become general. Separate RFC.
2. **`SIGSTOP`/`SIGCONT`.** A shell's job control wants them; a domain has no
   stopped state today, so they would be invented rather than translated.
3. **Whether a descendant's descendant counts.** The rule says "descendant",
   and the record has `ppid`, so the walk is upward and bounded by the tree's
   depth. Proposed: yes, and bounded by a depth limit so a cycle — which the
   record should make impossible and which nothing currently asserts — cannot
   hang the adapter.

## Implementation plan

1. The rule, in `bhaskix-personality`, as a pure function over the process
   table: `may_signal(caller, target) -> bool`. Host tests, armed.
2. `kill(2)` in `bin/linuxd` using it, for `SIGKILL`, `SIGTERM` and `0`.
3. The probe and the three boot gates, each watched red.
4. `roadmap.md` L1, `security.md` T11, `TRACKER.md` §7.
