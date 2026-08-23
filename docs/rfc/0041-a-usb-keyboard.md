# RFC 0041: A USB keyboard

| | |
|---|---|
| **Status** | ⬜ **Draft — steps 1 to 5 implemented.** Step 1 (2026-08-22): the `usb` leaf crate, `forbid(unsafe_code)`, fuzzed. Step 2 (2026-08-22): controller discovery, rule 1 as a property of the type, and the ring cursors. **Step 3 (2026-08-23): a controller is brought up and running** — the sequence below, with `bring_up` touching registers and nothing else so the whole of it is host-testable against a device model, and seven properties watched red. It also found one defect no reading would have: `qemu-xhci` implements **dword reads only** of the capability bank, answering `0x0000` to a 16-bit read of `HCIVERSION` rather than faulting, so that bank is now read as dwords and the model reproduces the emulator. **Step 4 (2026-08-23): the controller is asked a No-Op and answers it**, matched by the address of the command TRB — and step 3's command ring turned out to have no Link TRB, which nothing had read until this step rang the doorbell. **Step 5 (2026-08-23): a USB keyboard is enumerated, given a slot and addressed** — and a real controller caught a bug in RFC 0038's vendored layouts that the crate's own round-trip test could not see: the root hub port number was being written into the Number of Ports field. Steps 6–8 are open |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | drivers |
| **Milestone** | Phase 2 (see docs/roadmap.md) |
| **Depends on** | RFC 0038 (the xHCI definitions), RFC 0037 (the i8042 keyboard), RFC 0011 (interrupt handlers), RFC 0012 (the IOMMU) |

---

## Summary

Drive an xHCI controller far enough to read a USB keyboard, using the layouts
RFC 0038 vendored and obeying the six rules that RFC 0038's security section
binds any driver built on them.

The scope is deliberately one device class. Not storage, not hubs beyond what a
keyboard behind one needs, not USB 3 streams: **a HID boot-protocol keyboard on
a root port**, which is the smallest thing that turns a machine with no i8042
into a machine somebody can type at.

## Motivation

RFC 0037 gave this kernel a keyboard and stated the gap in the same breath: a
machine with no i8042 has none. That is not a hypothetical class of machine —
it is most laptops made in the last few years, and it is the reason this project
cannot yet be used on the hardware it is meant for.

The definitions are already in the tree, tested, and unused. This is what uses
them.

## Design

### The bring-up sequence, taken from a working driver rather than derived

The order below is FreeBSD's `xhci_start_controller`, read rather than
remembered, because the ordering constraints in it are not all obvious and
getting one wrong produces a controller that appears to start and then does
nothing.

1. **Reset**, and wait for both the reset bit *and* `USBSTS.CNR` to clear.
   Waiting on the reset bit alone is not enough: the controller clears it before
   it is willing to be programmed, and `CNR` is the bit that says otherwise.
   Bounded — a controller that never becomes ready is a refusal, not a hang.
2. **`CONFIG`** — the number of device slots being enabled, which must not
   exceed `HCSPARAMS1`'s count and must match the device context array actually
   allocated.
3. **`DCBAAP`** — the device context base address array, sized *slots plus one*
   because entry zero is the scratchpad pointer.
4. **`ERSTSZ`** and **`IMOD`** for interrupter zero.
5. **`ERDP`, then `ERSTBA`** — and **that order is load-bearing**. Writing
   `ERSTBA` is what arms the event ring; a dequeue pointer written afterwards is
   written to a ring the controller has already begun using.
6. **`IMAN`** — enable the interrupter.
7. **`CRCR`** — the command ring.
8. **`USBCMD`** — Run/Stop, with interrupts enabled, then wait for `USBSTS.HCH`
   to clear.

Scratchpad buffers, if `HCSPARAMS2` asks for any, are allocated and their array
installed at entry zero **before** step 8. A controller that asked for
scratchpad and did not get it does not run.

### Enumerating the keyboard

Port status change events announce the device; a port is reset, and then:
**Enable Slot** → allocate the device context → **Address Device** with an input
context naming the control endpoint → read the device, configuration and HID
descriptors through control transfers → **Configure Endpoint** for the interrupt
IN endpoint → ring its doorbell and read reports.

The Device Context Index arithmetic is the crate's, and the trap it encodes is
the one to watch: a keyboard's interrupt IN endpoint 1 is index **3**, and the
input context puts it one stride later than a device context would.

### Where it runs, and what it is allowed to reach

**In the nucleus, and this RFC says so rather than implying it.** That is where
the i8042 driver lives and it is a debt both share:
`docs/driver-model.md` wants drivers in domains, and USB is the strongest
argument yet for moving console input out. Moving it is a separate change and
should move both sources at once.

The six rules from RFC 0038 §"Security implications" bind this driver, and the
first is the one to build first:

1. **No translation, no driver.** Refuses to initialise unless
   `iommu::present_for` answers true for its own bus/device/function. A machine
   with no IOMMU gets no USB.
2. The window starts empty; mappings are added per buffer and removed after.
3. Nothing is mapped that was not allocated for the device — data is copied in
   and out of device-owned buffers rather than mapping a caller's.
4. Interrupt remapping, or a pinned legacy line, or nothing.
5. Every descriptor is untrusted input, parsed in a `forbid(unsafe_code)` leaf
   crate, every length checked against the buffer, and **fuzzed before shipping**.
6. The controller's own numbers — slot count, port count, context size, max
   packet size — are bounded before they size an allocation or a loop.

### The descriptor parser is its own crate

`usb/` at the leaf layer beside `elf`, `net`, `fs` and `ustar`: `no_std`,
`forbid(unsafe_code)`, depending on nothing, host-testable, and fuzzed. Device,
configuration, interface, endpoint and HID descriptors are length-prefixed,
self-describing and nested — the exact shape that produces parser bugs — and
they arrive from a device that a hostile USB stick controls completely.

Keeping the parser out of the driver is what makes it fuzzable without a
controller.

## Alternatives considered

**Wait for the i8042 to be enough.** It is not, on the machines this is for.

**Use `crab-usb`, an MIT `no_std` xHCI implementation, whole.** Its driver half
assumes ambient kernel authority rather than capabilities, domains and
`irq::claim`, and rule 1 above is not a thing it could be asked to honour. Worth
reading; not worth taking.

**Poll the event ring instead of taking an interrupt.** Simpler, and it spins a
CPU that `docs/scheduler.md` §7 has been taught to leave alone.

> **What step 4 actually does, said here because this is where the reader will
> look for it, 2026-08-23.** The boot-time probe **polls**, once, on a bounded
> deadline: it writes one No-Op, rings the doorbell and waits for the answer.
> That is not the arrangement this paragraph rejects. What is rejected is
> polling in the *steady state*, when reports are arriving at the endpoint's
> interval — a CPU spun for a keyboard. `IMAN` is enabled and nothing listens
> yet; the interrupt arrives with the reports, at step 7, where rule 4 is spent.
> If the steady state ever ships polling, this paragraph is the thing it
> contradicts.

**Support hubs, storage and USB 3 streams in the same change.** Each is a
milestone; a keyboard is a step, and it is the step that makes the machine
usable.

## Impact on existing design documents

- `docs/driver-model.md` — item 8 becomes built rather than planned, and its
  note about a machine with no i8042 having no keyboard stops being true.
- `docs/security.md` §1 — the first DMA-capable device this kernel drives; the
  IOMMU stops being a thing that is tested and becomes a thing that is relied on.
- `README.md` and `TRACKER.md` — the keyboard gap statement changes again.
- `third_party/xhci/PROVENANCE.md` — **its central claim was tested and held**,
  2026-08-23. "Everything here is reviewed as our own work … and tested here
  rather than trusted because it was tested elsewhere" stopped being a policy
  statement when step 5 found `Slot::root_hub_port_number` reading the wrong
  bits. What the episode adds: a round-trip test over a getter and setter pair
  proves nothing about a layout, because the two can be wrong together and
  agree. The layout tests in that crate assert raw encodings against literals,
  and the ones that did not now do.

## Security implications

Stated at length in RFC 0038 §"Security implications" and not repeated. The one
sentence worth restating: **an xHCI controller is a bus master**, so it reads and
writes physical memory itself, at addresses it was handed, by a path that goes
through neither page tables nor capabilities — and rule 1 exists because that is
only bounded by an IOMMU.

What this does not stop: a USB device that says it is a keyboard is a keyboard.
That is what a keyboard is, and it is equally true of the i8042. What bounds it
is that keystrokes enter a ring the shell reads, and the shell holds the
capabilities it was given and no others.

## Performance implications

An interrupt per report, at the endpoint's polling interval — 8 ms for a typical
keyboard. `IMOD` is set rather than left at its reset value, because zero means
an interrupt per event and a fast device can then livelock a CPU.

## Testing plan

**The descriptor parser, on the host and under a fuzzer**, before the driver
ships. Real descriptors, truncated descriptors, descriptors whose lengths lie,
and nesting that does not terminate.

> **Corrected 2026-08-23, by step 3 doing it.** The paragraph below says the
> controller is tested in QEMU, and the bring-up turned out to be **host-testable
> in full**: `bring_up` writes registers over memory prepared before it is
> called, so a device model on the host pins every ordering constraint — `ERDP`
> before `ERSTBA`, Run/Stop after every pointer, the `CNR` wait — and each was
> watched red by breaking exactly one thing. The QEMU gate confirms on a real
> emulated controller; it is no longer the only place the sequence is checked.
> That distinction earned itself immediately: the emulator's dword-only
> capability bank is now a host test rather than a thing a boot has to be run to
> catch.

**The controller, in QEMU**, which emulates xHCI and a USB HID keyboard:
`-device qemu-xhci -device usb-kbd`. That makes the whole path gateable —
controller found behind an IOMMU, ports enumerated, slot addressed, endpoint
configured, keystroke delivered to the shell — with the same `sendkey` harness
RFC 0037 already built, pointed at a USB keyboard instead of the i8042.

**Watched red**, as everything here is: by refusing the IOMMU check, by
corrupting a descriptor length, and by breaking the Device Context Index
arithmetic — each seen to fail on purpose.

## Unresolved questions

1. **How much of the controller must be torn down on failure?** A driver that
   gives up half-initialised leaves a bus master with a live ring.
2. **What happens to the i8042 driver when both exist?** Two sources, one
   console ring — the design already allows it, but a machine with both should
   probably say so at boot rather than silently preferring one.
3. **Does console input move to a domain before or after this?** The debt is
   shared; the move is cheaper before there are two drivers in it.

## Implementation plan

1. ✅ **Done 2026-08-22.** The `usb` leaf crate: descriptor types, parsing, host
   tests, a fuzz target.
2. ✅ **Done 2026-08-22.** Controller discovery — PCI class `0x0C` subclass
   `0x03`, and the programming-interface byte, because class and subclass alone
   only say "USB" — and **rule 1**: the IOMMU check, refusing before anything
   else happens.
3. ✅ **Done 2026-08-23.** Bring-up through the sequence above, with the ring and
   context allocations the crate's sizing functions describe.

   *What it cost, and one thing it changed.* The kernel now gives the **first**
   controller a translation of its own — its own page table and the fourth domain
   id — and `tests/qemu/devices.sh` carries a **second** controller so that one
   boot holds both halves of rule 1 with a live subject: the first is driven, the
   second is still refused by name. `MAX_WINDOWS` went 4 → 8, because the `full`
   profile filled all four and a full table degrades by leaving a device
   untranslated.

   *And one correction to this document's own testing plan*, made by doing it:
   the plan called for the controller to be tested "in QEMU", and the whole
   bring-up is host-testable instead. `bring_up` writes registers and reads
   nothing else — every byte the controller will read is prepared before it is
   called — so the ordering constraints are pinned by a device model on the host
   and the QEMU gate confirms rather than carries them.
4. ✅ **Done 2026-08-23.** The event ring: consume, dispatch, advance the
   dequeue pointer.

   *Proved by a No-Op command*, which is what this crate's own constructor says
   a No-Op is for: the completion event names the address of the command TRB it
   answers, so a matching pointer establishes that the controller read the ring
   the driver writes as well as wrote the ring the driver reads. "An event
   arrived" would have proved only the second.

   *And it found that step 3's command ring had no Link TRB.* Nothing read the
   ring then, so a missing wrap cost nothing and was invisible; ringing the
   doorbell makes it live, and the controller would have stopped after fifteen
   commands. Written now, toggling. The event ring still gets none — that one
   wraps by the segment table.
5. ✅ **Done 2026-08-23.** Port enumeration, Enable Slot, Address Device.

   *The reset rule needs to know nothing about USB versions.* A USB 3 port
   enables itself on connect and a USB 2 port must be reset, and a driver cannot
   tell which it is looking at from the port number — so the rule is *if it is
   connected and not enabled, reset it*, which is right for both.

   *And it found a bug in the vendored layouts.* `Slot::root_hub_port_number`
   and its setter both used dword 1 bits 31:24, which is Number of Ports. Address
   Device was refused with `CC_TRB_ERROR` until the field moved to bits 23:16,
   after which the same command addressed the device. The crate's test had
   round-tripped the value through the accessor that wrote it, which pins the
   getter and setter to each other and cannot see the layout; it now asserts the
   raw dword. See §"Impact on existing design documents".
6. Descriptors over control transfers; Configure Endpoint for interrupt IN.
7. Reports into `input::keyboard_produced`, which already exists and already
   merges a second source.
8. The QEMU gate, watched red three ways, and the documents updated in the same
   change that makes them true.
