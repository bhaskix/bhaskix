# Provenance

This crate is **adapted from third-party source**. It is not original work and
must not be presented as any.

| | |
|---|---|
| **Upstream** | `xhci` |
| **Source** | https://github.com/rust-osdev/xhci |
| **Version taken** | 0.9.2 |
| **Upstream copyright** | Copyright (c) 2021 Hiroki Tokunaga |
| **Upstream license** | `MIT OR Apache-2.0` |
| **Taken under** | Apache-2.0 (see `LICENSE-APACHE`) |
| **Taken on** | 2026-08-22 |
| **Decision** | [RFC 0038](../../docs/rfc/0038-vendoring-the-xhci-definitions.md) |

The dual license is why this was possible without introducing a second license
into the tree: Apache-2.0 is what Bhaskix already uses, so the upstream terms
and this project's terms are the same terms.

## What was taken

The **layouts**: which register lives at which offset, what each bit in it
means, and how the controller's structures are shaped. That knowledge is the
value here — it is mechanical, voluminous, and unusually easy to get subtly
wrong, and re-deriving it from the specification would re-open a class of error
this source has already been through.

## What was changed, and why

This is a derivative work rather than a copy. Every one of the upstream crate's
five dependencies was removed, because taking them meant vendoring roughly sixty
thousand lines — `syn` 1.0.109 alone is 44,682 — to obtain 5,759 lines of xHCI
knowledge, into a kernel whose dependency count is zero by policy.

| upstream dependency | replaced by |
|---|---|
| `accessor` | this kernel's own volatile MMIO access |
| `bit_field` | shifts and masks written out |
| `paste` | the code it pasted, written out |
| `num-derive`, `num-traits` | the conversions they derived, written out |

Replacing `accessor` is the one change that is an improvement rather than a
trade: device memory is something this kernel already owns rules about, and a
driver reaching it through a second abstraction with its own opinions is drift.

### Corrections made here, after the take

Behaviour changes, as opposed to the dependency removals above. Each is a place
this source was wrong and this tree is not.

| what | when | how it was found |
|---|---|---|
| `Slot::root_hub_port_number` and its setter used dword 1 bits **31:24**, which is Number of Ports. Moved to bits **23:16**. | 2026-08-23 | A controller. RFC 0041 step 5's Address Device was refused with `CC_TRB_ERROR` while every other field of the input context probed correct; written at 23:16 the same command addressed the device, slot state `Addressed`, USB address 1. |
| `StructuralParameters2::max_scratchpad_buffers` documented its two halves the wrong way round — the prose contradicted the code and the test beneath it. Prose corrected; **the code was not**, and the tiebreak against the specification is recorded as owed. | 2026-08-23 | Reading, while building RFC 0041 step 3. |

**The lesson from the first of those is about the shape of a test, not about a
bit range.** The accessor pair was pinned by:

```rust
let slot = Slot::new().with_root_hub_port_number(7);
assert_eq!(slot.root_hub_port_number(), 7);
```

which reads the value back through the accessor that wrote it. That verifies the
getter and setter **against each other** and cannot see the layout — it passed
for as long as the two were wrong together. A layout test must assert the raw
encoding against a literal, which is the second transcription the offset tests in
this crate already use. Where an accessor pair here is pinned only by a round
trip, it is pinned by nothing.

## What this means for review

Vendored code is code this project ships. The Apache-2.0 grant covers the right
to use it; it does not make it correct, and it does not transfer responsibility
for it. Everything here is reviewed as our own work, budgeted as our own, and
tested here rather than trusted because it was tested elsewhere.

**Where this source and the xHCI specification disagree, the specification
wins.** Upstream is the reason these numbers did not have to be derived twice;
it is not the authority on what they are.

## Updating

There is no automatic path back to upstream and there is not meant to be. This
is a frozen take at a known version: it changes when somebody changes it here,
and a change is reviewed like any other. If a later upstream version is worth
taking, that is a fresh reading and a new line in the table above — not a
version bump.
