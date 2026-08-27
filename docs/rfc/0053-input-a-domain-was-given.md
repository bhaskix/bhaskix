# RFC 0053: input a domain was given

| | |
|---|---|
| **Status** | **Draft — proposed 2026-08-27.** BusyBox's `sh` reaches a correct `/ #` prompt on this machine and cannot read a key, because the adapter holds the console `WRITE`-only on purpose. This gives *a hosted domain* an input authority of its own, enforced by the nucleus rather than trusted to the adapter, and **leaves the console narrowing exactly as it is**. Acceptance is the project lead's |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | kernel |
| **Milestone** | Phase 2 — Core Operating System (L1) |
| **Depends on** | [RFC 0032](0032-a-supervisor-interface.md) (the adapter and its domain capabilities), [RFC 0033](0033-what-a-hosted-process-is.md) (a hosted process holds no capabilities) |

---

## Summary

A `Domain` capability gains two methods — take a typed byte, and look for one —
which the nucleus refuses unless that domain has been **granted input**. The
adapter's console capability is unchanged: still `WRITE`, still unable to take a
byte on its own account.

## Motivation

**A shell that cannot be typed at.** BusyBox's `sh` runs on this machine, prints
`sh: can't access tty; job control turned off`, and reaches `/ #`. Then `read(0)`
returns nothing, because there is nothing it could honestly return.

**The reason is a decision, and a good one.** `syscall.rs` says it where the
adapter's console is granted:

> *"The Linux adapter is the second holder and it is given `WRITE` alone: a
> hosted program's `write` reaches the console, and the adapter cannot take a
> byte somebody typed at the shell. Without this the narrowing would be a
> comment rather than a mechanism."*

Simply adding `READ` there would undo that sentence: every hosted program, and a
compromised adapter, could take keystrokes meant for the Bhaskix shell. **The
narrowing must survive this change or the change is not worth making.**

## Design

**The authority is the domain's, and it is named on the domain.** The adapter
already holds a `Domain` capability per hosted process — that is how RFC 0032
lets it act on one at all. Two methods are added there:

| | |
|---|---|
| `DOMAIN_TAKE_INPUT` | Take a byte typed at the console, blocking until there is one |
| `DOMAIN_POLL_INPUT` | Take a byte only if one is already waiting |

Both require `Rights::READ` on the **domain** capability, and both are refused
with `InsufficientRights` unless the nucleus's per-domain **input grant** is set
for the domain that capability names.

**The grant is a per-domain flag in the nucleus**, in the shape `Personality`
already uses: a field on the record and a bitmask for the fast check. It is set
by whoever creates the hosted domain and holds its capability — for the corpus,
the kernel; for a supervisor, `bin/sup`. It is cleared when the domain ends,
with the domain.

**Why this and not `READ` on the console.** A compromised adapter with console
`READ` can read every keystroke for ever. A compromised adapter with these
methods can read keystrokes **only for domains somebody granted input to**, and
the check is in the nucleus, so the adapter cannot lift it. That is the
difference between a narrowing that survives compromise and one that does not.

**One reader, which the console already assumes.** A console has one keyboard.
The grant is refused if another domain already holds it, so "who is being typed
at" has one answer at a time and it is a capability question rather than a race.

## Alternatives considered

**Grant the adapter console `READ`.** One line, and it reverses a written
decision: any hosted program could take a byte meant for the Bhaskix shell. This
is the option the RFC exists to avoid.

**A new right on the console capability** — a bit meaning "read on behalf of".
Rejected: `Rights::ALL` is a fixed mask and adding a bit changes the capability
model for every object to solve one object's problem. Naming the authority on
the domain needs no new right at all.

**A capability the hosted process holds.** RFC 0033 is explicit that a hosted
process holds no capabilities and has no way to name one. That is load-bearing
and not up for revision here.

## Impact on existing design documents

`security.md` §1's **T11** enumerates what a compromise of the adapter reaches.
It gains a line: *the console input of any domain granted it* — bounded by the
grant, and that bound is the point.

The comment at the console grant in `syscall.rs` stays true word for word, and
gains a pointer to this RFC so a reader learns why it is still `WRITE`.

## Security implications

**No new authority for the adapter over the console.** Its console capability is
untouched.

**A new authority over a granted domain's input**, held by whoever holds that
domain's capability with `READ`. Today that is the adapter and the creator.

**What a compromised adapter gains**, stated plainly: keystrokes typed while a
granted domain is running. It does not gain them for ungranted domains, and it
does not gain them when no domain is granted — which is every boot that does not
ask for one.

**What it does not change**: a hosted process still holds nothing, still cannot
name a capability, and reaches input only through the adapter acting on a domain
somebody chose to grant.

## Performance implications

A blocking take parks the calling thread exactly as `console::TAKE` does. The
poll form does not block. Neither is on a path that runs without a program
asking.

## Testing plan

1. **Host tests** on the grant: set, cleared with the domain, refused for a
   second domain while one holds it. Watched red.
2. **A boot gate that types**: a granted hosted program reads a line typed at the
   machine and echoes it. This is the assertion the whole RFC is for, and it
   needs a lane of its own — the boot harness types at the *Bhaskix* shell, and
   two readers of one keyboard is exactly what the grant exists to prevent.
3. **A refusal gate**: an ungranted domain's `read(0)` is refused, watched red by
   granting it.

## Unresolved questions

1. **Who should be able to grant it?** Today: whoever holds the domain capability
   with `READ`. A supervisor granting input to something it did not create is a
   question RFC 0032's model can express and this RFC does not answer.
2. **Should the grant be revocable while the domain runs?** Ending the domain
   clears it. Taking it back from a running program that is blocked in a read is
   a wake-up question, not just a flag.
3. **What does `poll` say when the grant is absent?** Refusing is honest and
   makes a shell spin; answering "never readable" is a lie a shell believes.
   Neither is good, which is an argument for the gate in point 3 above.

## Implementation plan

1. The per-domain grant in `domain.rs`, in `Personality`'s shape. Host tests.
2. `DOMAIN_TAKE_INPUT` and `DOMAIN_POLL_INPUT` in the nucleus, refused without
   the grant.
3. The adapter's `read(0)` and `poll` use them for a granted domain.
4. The corpus grants input to the BusyBox domain, and a lane that types at it.
