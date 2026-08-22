# What a capability is

Take a railway ticket out of your pocket.

It says which train, which coach, which berth. When you board, the TTE looks at
the ticket. He does not ask your name, check your Aadhaar, or look you up in a
register. The ticket itself is the permission. If you hand it to your friend and
get down at Itarsi, your friend travels on it quite happily.

That is a capability. It is a thing you hold, and holding it *is* the permission.

Now think about how most computers work instead. You log in, the system decides
who you are, and then every time you touch a file it asks a different question:
*is this person allowed?* Your name is checked against a list, again and again.
The permission is not in your hand. It is in a register somewhere, attached to
your identity.

Bhaskix does not work that way. The architecture document puts it in two
sentences:

> There is no user ID in the nucleus. There is no `root`. Authority is a *thing
> you hold*, not a *thing you are*.

## Why this matters more than it sounds

The trouble with identity-based permission is a thing called **ambient
authority**. It means: authority that is simply in the air around you, applied
to everything you do, whether you asked for it or not.

Think of a master key for a whole building. The watchman carries one. It is very
convenient. He can open any door without hunting for the right key.

Now suppose somebody copies that key for ten minutes. Every door in the building
is open to them, for ever, and nobody can tell which door was the problem —
because the key was never *for* a door. It was for everything.

`root` is that master key. A program running as `root` does not receive
permission for the one file it needs. It carries permission for every file that
exists. When such a program is tricked — and programs are tricked — the attacker
inherits the whole building.

A capability cannot be misused that way, because there is nothing extra in it. A
program that holds a capability for one console and nothing else can write to
that console and do nothing else. Not because a check refused it. Because it has
nothing to try with.

## Where the ticket stops being true

Every analogy has an edge, and it is more honest to walk to that edge than to
stop just short of it.

A railway ticket can be photocopied. A capability cannot: it is not a piece of
paper the program owns, it is a slot in a table the kernel owns, and the program
only holds a number pointing at that slot.

That difference brings its own problem, and the kernel's own source is blunt
about it:

> Arena entries are reused. Without a generation, a stale index would silently
> address whatever now occupies that entry — a use-after-free that hands out
> authority instead of crashing, which is the worst possible version of it.

Read that again, because it is the whole danger in one line. Suppose slot 7
holds your console. The console is destroyed. Slot 7 is now free, and later it
holds somebody's disk. Your old number still says "7". If nothing else changed,
your program would now be writing to a disk while believing it holds a console.

Not an error. Not a crash. Authority, handed out quietly, to a program that
never asked for it.

So a slot carries a **generation** — a small counter that goes up each time the
slot is reused. Your reference remembers the generation it was made against. When
the numbers disagree, the kernel reads it as **revoked**, not as a different
object.

Going back to the ticket: it is as if your ticket named not just berth 7, but
berth 7 *on the 12951 of 3rd March*. Somebody else in berth 7 next week is not
your problem, and your old ticket does not accidentally become valid for their
journey.

## What was measured

Words like "cannot" are cheap. In this project they are only allowed where
something checks them, so here is what checks this one.

In `kernel/src/cap.rs` there is a test with a long name:
`a_stale_reference_never_resolves_to_a_reused_entry`. It does exactly what the
paragraph above describes. It makes a capability, revokes it, allocates a new
one, and first checks that the new one **landed in the same entry** — because if
it did not, the test would be proving nothing. Then it tries the old reference
and requires it to be dead.

It runs with `make test`, every time, on the machine that builds the system.

On 22nd August 2026 that test was watched fail on purpose. One line in `resolve`
compares the generation; that comparison was deleted, the test was run, and it
failed with the message it carries for the occasion — *the stale reference must
stay dead*. Then the line was put back.

This matters more than it sounds. A test that has only ever passed is not
evidence. A test that *cannot* fail passes just as happily as one that works, and
from the outside the two look identical. The only way to tell them apart is to
break the thing on purpose, once, and watch the bell ring.

## What is not settled

Two things, said here rather than left for the reader to discover.

First, capabilities make **revocation** harder than a permission list does. If
authority is a thing you hold, taking it back means finding everyone who holds
it. Bhaskix does this through the slot table and the generation counter, and the
cost of that is real work at revocation time.

Second, a capability system does not stop a program doing damage with the
authority it was *correctly* given. If you hand a program your console, it may
write nonsense to your console. Capabilities make sure it cannot then also read
your disk. That is a smaller promise than "safe", and it is the promise this
system actually makes.
