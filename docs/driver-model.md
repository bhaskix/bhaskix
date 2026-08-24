# Bhaskix — Driver Model

*Status: draft for review. Prerequisite reading: [architecture.md](architecture.md),
[memory.md](memory.md) §5, [security.md](security.md).*

Drivers are the largest, least reviewed, and most compromised part of every kernel that has ever
shipped. They are written by people who are experts in the hardware and not necessarily in the
kernel, they run with full privilege, and they process untrusted input from a device that may be
hostile. Any OS that treats drivers as "just kernel code that talks to hardware" inherits that
history.

In Bhaskix a driver is a **service** ([architecture.md](architecture.md) §2) that is granted a
**capability** to exactly one device, and whose DMA is contained by the **IOMMU** — even when it is
compiled into the nucleus for speed.

---

## 1. What a driver may and may not do

| A driver may | A driver may not |
|---|---|
| Access MMIO ranges named by its `MmioCapability` | Access any other physical or virtual address |
| Map DMA buffers named by its `DmaCapability` | Perform DMA to arbitrary memory |
| Receive the IRQs named by its `IrqHandler` | Install an interrupt handler directly |
| Allocate from its own domain's memory envelope | Allocate without accounting |
| Call other services by message | Call kernel internals directly |
| Contain `unsafe` in its `hal` submodule | Contain `unsafe` anywhere else |

These are not conventions. `MmioCapability`, `DmaCapability`, and `IrqHandler` are the only types
that unlock the corresponding operations, and a driver receives only the ones its manifest requested
and the enumerator granted.

`IrqHandler` is made concrete by [RFC 0011](rfc/0011-irq-handler.md) (accepted), which also settles
who may hand one out and what may be claimed: **a domain may claim only MSI-X sources.** A legacy
`INTx` line is shared between devices, and a holder that never acknowledges masks a line the others
need — so those stay in the nucleus.

---

## 2. The `Driver` trait

```rust
pub trait Driver: Send + Sync + 'static {
    /// Static description used for matching and for the manifest.
    const INFO: DriverInfo;

    /// Called once, with exactly the resources the enumerator granted.
    /// Returning Err leaves the device unbound; it does not panic the system.
    async fn probe(res: DeviceResources) -> Result<Self, ProbeError> where Self: Sized;

    /// Interrupt arrived. Runs in a *thread*, not in IRQ context — the nucleus
    /// handler only signals. There is therefore no restriction on awaiting here.
    async fn on_irq(&self, vector: IrqIndex);

    /// Orderly shutdown: quiesce the device, unmap DMA, release resources.
    /// Must be safe to call at any time, including mid-transfer.
    async fn shutdown(&self);

    /// Power state transition. Default: refuse anything but D0.
    async fn set_power(&self, state: PowerState) -> Result<()> { /* ... */ }
}

pub struct DeviceResources {
    pub mmio: Vec<MmioCapability>,   // exactly the BARs granted
    pub irqs: Vec<IrqCapability>,
    pub dma:  DmaWindow,             // IOMMU-backed, see memory.md §5
    pub config: ConfigSpace,         // PCI config, or ACPI/DT node
    pub domain: DomainId,            // for memory accounting
}
```

### Why `async`

Device operations are long-latency and event-driven. The two conventional alternatives are both bad:
blocking a kernel thread per in-flight operation wastes a stack per request and caps concurrency, and
hand-written callback state machines are where driver bugs live. `async` gives us the state machine
with the control flow written linearly, and the executor is provided by the placement — so the same
driver source works in-nucleus and in a userspace domain.

### Why IRQ handling is not in interrupt context

The nucleus IRQ path does exactly one thing: acknowledge the interrupt controller and signal the
waiting driver task. It runs with interrupts disabled for a bounded, tiny number of instructions.

"Signal the waiting driver task" is a **notification** ([RFC 0010](rfc/0010-notifications.md),
accepted): two atomics and a wake, with no lock and no allocation, which is what makes it callable
from a handler at all. *Who* may receive one is [RFC 0011](rfc/0011-irq-handler.md), also accepted.

That RFC adds one step this section did not mention and cannot do without: **the source is masked
before it is signalled.** A level-triggered line that is not masked re-asserts the instant the
handler returns, and the CPU spends its life in the handler. Masking is also flow control — a slow
driver gets fewer interrupts rather than a storm.

**The rule that follows, for driver authors: drain the device before acknowledging.** Between
delivery and `ACK` the source is masked, and an *edge* raised in that window — which is every MSI —
is lost. Read the device's completion state until it is empty, then acknowledge. A driver that
acknowledges first and reads second will one day sleep with a completion in its queue and no
interrupt coming, and that bug presents as a hang under load and nothing at all in testing.

This is the top-half/bottom-half split made mandatory instead of optional. It means:

- A slow or buggy driver cannot raise interrupt latency for the whole machine — the RT latency bound
  in [scheduler.md](scheduler.md) §4 survives bad drivers.
- Driver code may allocate, take locks, and await, because it is never in IRQ context. The
  single most common class of driver deadlock stops being expressible.

---

## 3. MMIO access

No raw pointers. MMIO is reached through a typed wrapper that is the *only* thing an
`MmioCapability` unlocks:

**A device's MSI-X table pages must never be inside an `MmioCapability` given to a domain.**
Programming an MSI is a device write of an arbitrary vector to an arbitrary CPU — a general
interrupt-injection primitive obtained by writing two words — which is why
[RFC 0011](rfc/0011-irq-handler.md) keeps that programming in the kernel. Whatever hands out MMIO
capabilities must exclude those pages, and this is the sentence it will be measured against.

```rust
pub struct Mmio<T: MmioSafe> { /* addr + capability, private */ }

impl<T: MmioSafe> Mmio<T> {
    pub fn read(&self) -> T;                 // volatile, correctly sized
    pub fn write(&self, val: T);             // volatile, correctly sized
    pub fn modify(&self, f: impl FnOnce(T) -> T);
}
```

Properties this buys:

- **Correct access width.** Many devices fault or misbehave on a 32-bit read of an 8-bit register.
  The type carries the width; the compiler cannot merge, split, or reorder it.
- **No accidental non-volatile access.** A plain `*mut u32` deref can be optimised away or hoisted
  out of a loop. This has cost real projects weeks.
- **Barriers where the architecture requires them**, inserted by the wrapper, not remembered by the
  driver author.
- **Register definitions are declarative:**

```rust
register_block! {
    pub struct NvmeRegs {
        0x00 => cap:    ro u64,
        0x08 => version:ro u32,
        0x14 => cc:     rw u32 { en: 0, css: 4..7, mps: 7..11, shn: 14..16 },
        0x1C => csts:   ro u32 { rdy: 0, cfs: 1, shst: 2..4 },
    }
}
```

A macro-generated block gives compile-time checked offsets, enforced read-only/write-only semantics,
and named bitfields. Offset typos become build errors instead of a device that hangs at probe.

---

## 4. Enumeration and binding

```
ACPI / Device Tree / PCI config space
        ↓
   Bus enumerator  (itself a driver: pci, acpi, virtio-mmio)
        ↓
   DeviceDescriptor { ids, class, resources_requested }
        ↓
   Matcher  → selects a Driver whose INFO matches
        ↓
   Resource grant  ← the ONLY place capabilities are minted for a device
        ↓
   probe()
```

Rules:

- **Default deny.** With [RFC 0012](rfc/0012-iommu.md) (accepted) this becomes hardware-enforced
  rather than a property of this framework's good behaviour: a device's window starts empty, and
  anything it reaches for that it was not given is a fault the machine reports. Until that code
  lands, "default deny" is this framework's promise and nothing checks it.
  An unmatched device gets no capabilities and is left in reset. An unknown PCIe
  device plugged into a running machine is inert, not opportunistically probed.
- **The enumerator grants; the driver requests.** A driver declares what it needs in its manifest.
  The enumerator grants the intersection of what was requested and what the device actually claims
  through its BARs. A driver asking for more than its device has is a boot-time error.
- **Hotplug and unplug use the same path.** Surprise removal calls `shutdown()`, revokes the
  capabilities (transitively — see [security.md](security.md) §2), and tears down the IOMMU domain.
  Revocation is what makes surprise removal safe rather than a use-after-free race.

---

## 5. Driver manifest

Every driver ships a manifest, used for matching, resource requests, and placement:

```toml
[driver]
name    = "nvme"
version = "0.1.0"
authors = ["..."]

[match]
pci_class = "01:08:02"          # mass storage / NVM / NVMe

[resources]
mmio = 1                        # BAR count expected
irqs = { kind = "msix", max = 64 }
dma  = { max_bytes = "64MiB", addressing = "64bit" }

[placement]
default = "nucleus"             # or "domain"
supports = ["nucleus", "domain"]

[safety]
unsafe_budget = 40              # lines of unsafe permitted; CI enforces
```

The manifest is the reviewable summary of a driver's authority. A reviewer can see what a driver can
reach without reading the driver.

---

## 6. Driver isolation in practice

Placement is a build-time choice with a runtime cost/benefit:

| | `nucleus` | `domain` |
|---|---|---|
| Call overhead | Direct call | IPC round trip |
| A driver panic | Kernel panic | Domain restart; device re-probed |
| A driver memory-safety bug | Kernel compromise (bounded by `unsafe` review) | Contained to the domain |
| DMA containment | IOMMU | IOMMU |
| Debugging | Kernel debugger | Ordinary userspace debugging |

Policy: **performance-critical, well-audited, small drivers** (virtio, NVMe, xHCI, the PCI
enumerator) default to `nucleus`. **Large, complex, or vendor-supplied drivers** (GPU, WiFi, media)
default to `domain`. The line moves with evidence, not preference.

CI builds every driver in both placements. See the honest caveat in
[architecture.md](architecture.md) §2 about how such schemes decay — the both-placements CI job is
the thing preventing it, and if it is ever disabled, the claim in this table becomes false.

---

## 7. Priority order for real drivers

Ordered by "what makes the system useful soonest", not by interest.

**Phase 1 (bring-up, minimum viable):**
1. Serial (16550 UART) — the debugging lifeline, first driver written
2. Framebuffer (from `Handoff`) — no hardware acceleration, just pixels
3. Local APIC / IO-APIC timer and IPI
4. PS/2 keyboard — simple, enough for a kernel shell. **Built 2026-08-22**
   ([RFC 0037](rfc/0037-a-keyboard-on-real-hardware.md)): an i8042 probed under
   a bounded wait so a machine without one is delayed rather than hung, its line
   claimed through §2's own rules, and set-1 scancodes translated by a pure
   function tested on the host. It is the first driver here written for a
   machine nobody has booted yet — every other one on this list earns its keep
   in QEMU, and this one exists because a laptop with no serial port has no
   other way in.

**Phase 2 (a real machine):**
5. PCIe enumeration (ECAM)
6. virtio-blk, virtio-net, virtio-rng — the whole VM story in three small drivers
7. NVMe — the whole bare-metal storage story in one
8. xHCI (USB) — keyboard, storage, and the largest attack surface here, and
   the phrase is meant literally: an xHCI controller is a **bus master**, so it
   reads and writes physical memory on its own initiative, at addresses it was
   handed, by a path that goes through neither page tables nor capabilities.
   [RFC 0038](rfc/0038-vendoring-the-xhci-definitions.md) vendors the register
   layouts and states the six rules any driver built on them must obey — the
   first being that it refuses to initialise at all unless the controller is
   behind an IOMMU translation. Note
   what item 4 does **not** cover: a USB keyboard needs all of this — PCIe
   enumeration, the register file, command/event/transfer rings, device slots
   and endpoint contexts, `ADDRESS_DEVICE`, descriptor parsing — before the HID
   boot protocol can even begin. It is a milestone, not a step.

   **Built 2026-08-23** ([RFC 0041](rfc/0041-a-usb-keyboard.md), seven steps in
   one day): a controller found and refused unless caged, brought up, its rings
   answering a No-Op matched by address, a port enumerated, a slot taken, the
   device addressed, its descriptors read over control transfers and parsed as a
   boot keyboard, the interrupt IN endpoint configured and Running, an MSI-X
   entry claimed, and reports translated from *held* to *newly pressed* into the
   console ring the shell reads. `make test-usb-keyboard` types at it and asserts
   the whole chain, including that a held key produces one character rather than
   one per report. Rule 1 is watched refusing a real untranslated controller on
   every boot of the `full` profile.

   **The sentence this item carried until 2026-08-23** — "the honest consequence
   today is that a machine with no i8042 has no keyboard" — is retired. What
   replaces it is narrower and still true: a machine with no i8042 **and no
   IOMMU** has no keyboard, because rule 1 refuses the controller rather than
   driving a bus master nothing translates for. That is a trade this document
   chose deliberately, and it is now a trade with a consequence somebody can hit.

   **Not done:** storage, hubs, USB 3 streams, and teardown on failure — a driver
   that gives up half-initialised still leaves a bus master with a live ring
   (RFC 0041's unresolved question 1).
9. Intel e1000e / generic RTL — bare-metal networking

**Phase 3 (enterprise):**
10. VT-d / AMD-Vi IOMMU (needed earlier for security; listed here as *full* support)
11. SR-IOV, multi-queue NIC support — **AHCI/SATA left this list on 2026-08-24** and is
    **done**: [RFC 0046](rfc/0046-a-driver-for-hardware-that-exists.md) was accepted the same
    day, all six steps. `bin/ahcid` identifies, reads and writes a SATA disk from ring 3 behind
    a window of its own and serves `block::READ`/`WRITE`. Not on the SR550 yet — translation is
    off there pending [RFC 0043](rfc/0043-an-iommu-on-a-machine-with-no-virtio.md), and the
    driver refuses an uncontained controller by design
12. TPM 2.0 (CRB/TIS) — required for [security.md](security.md) §3

**Later:** GPU (`domain` placement, mandatory), WiFi, audio, media.

virtio comes early on purpose: it makes Bhaskix useful inside QEMU and every cloud hypervisor before
any bare-metal driver work is complete, which means contributors can do real work on a laptop.

---

## 8. Testing strategy

| Layer | How |
|---|---|
| Register definitions | Compile-time offset assertions generated by `register_block!` |
| Driver logic | Host unit tests against a **mock MMIO backend** — `Mmio<T>` is a trait object in tests, so a driver's state machine is testable with zero hardware |
| Probe/teardown | QEMU: probe, shutdown, re-probe 1000× and assert no resource leak |
| Untrusted device input | `cargo-fuzz` on every descriptor/completion parser. A device is untrusted input. |
| Isolation | Fault injection: a test driver that panics, spins, or attempts out-of-window DMA; assert containment |
| IOMMU | QEMU `-device intel-iommu`; assert an out-of-window DMA attempt faults and is attributed to the right device |
| Surprise removal | QEMU PCI hotplug: unplug mid-transfer, assert no use-after-free (checked with the debug allocator's quarantine) |

The mock-MMIO approach is the highest-leverage item here: it means driver logic can be developed and
tested by contributors who do not own the hardware, which is the difference between a driver
ecosystem and a driver wishlist.

---

## 9. Open questions

- **Stable driver ABI?** A stable ABI enables out-of-tree and vendor binary drivers; it also freezes
  internal design and is how the "no stable ABI" argument became load-bearing for Linux. Current
  lean: no stable in-nucleus ABI, but a stable *IPC protocol* for `domain`-placed drivers — which
  gives vendors a supported path without constraining the nucleus.
- Should `domain`-placed drivers be restartable transparently to their clients (session recovery), or
  is a visible error acceptable? Transparent restart is a large amount of protocol design.
- Firmware blob loading: needed for WiFi and GPU, and a real supply-chain and licensing question.
- Do we support a Linux driver shim for the long tail of hardware? It would accelerate adoption
  enormously and compromise the "build our own kernel" principle. This needs an explicit governance
  decision rather than an accident.
