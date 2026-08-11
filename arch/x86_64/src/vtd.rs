// SPDX-License-Identifier: Apache-2.0
//! Intel VT-d's translation structures, as arithmetic.
//!
//! [RFC 0012](../../../docs/rfc/0012-iommu.md) step 2: build the structures,
//! with translation still disabled, and prove them against known encodings on
//! the host. Everything here is a pure function of numbers — no register is
//! touched, no memory is mapped, and nothing in this module can enable
//! anything.
//!
//! That separation is the point. The part of an IOMMU that is hard to get
//! right is the bit layout of four different table entries, and the part that
//! is hard to *test* is the hardware. Keeping them apart means the first can
//! be checked exhaustively against the specification's own numbers, on a
//! machine with no IOMMU at all, and what remains for the emulator is whether
//! the right structure was placed at the right address.
//!
//! # The walk
//!
//! A device's requester id — bus, device, function — selects a **root entry**
//! by bus, which points at a **context table**; the device and function select
//! a **context entry** in it, which points at a **second-level page table**.
//! Every DMA the device performs is then translated through that table, and an
//! untranslatable access is refused and reported rather than performed.
//!
//! ```text
//!   requester id 00:03.0
//!        │
//!        ├─ bus 0x00 ──► root entry 0  ──► context table
//!        │                                     │
//!        └─ device 3, function 0 ──────────────┴─► context entry 0x18
//!                                                       │
//!                                                       └─► second-level tables
//! ```
//!
//! # Why the entries are types rather than `u64`s
//!
//! Both halves of a context entry are 64-bit words whose fields overlap
//! nothing and mean entirely different things, and the address fields all
//! carry an implied 4 KiB alignment. Writing them as bit arithmetic at the
//! call site is how an address ends up in the domain-id field.

/// Bytes in a page, and the alignment every table and address here carries.
pub const PAGE_SIZE: u64 = 4096;

/// Entries in one level of a second-level page table.
pub const ENTRIES: usize = 512;

/// How many address bits a window translates, and therefore how many levels
/// its page tables have.
///
/// The encoding is the specification's "adjusted guest address width" field,
/// not a bit count — 39-bit addressing is a **1**, and writing the width there
/// would be a table the hardware walks to the wrong depth.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum AddressWidth {
    /// 30-bit addresses, two levels.
    Bits30 = 0,
    /// 39-bit addresses, three levels. What QEMU's `intel-iommu` defaults to.
    Bits39 = 1,
    /// 48-bit addresses, four levels.
    Bits48 = 2,
    /// 57-bit addresses, five levels.
    Bits57 = 3,
}

impl AddressWidth {
    /// Page-table levels a walk of this width descends.
    #[must_use]
    pub const fn levels(self) -> u8 {
        match self {
            Self::Bits30 => 2,
            Self::Bits39 => 3,
            Self::Bits48 => 4,
            Self::Bits57 => 5,
        }
    }

    /// Address bits this width translates.
    #[must_use]
    pub const fn bits(self) -> u8 {
        match self {
            Self::Bits30 => 30,
            Self::Bits39 => 39,
            Self::Bits48 => 48,
            Self::Bits57 => 57,
        }
    }

    /// The largest width no wider than what the hardware reported.
    ///
    /// The `DMAR`'s host address width is what the *hardware* can generate;
    /// choosing a wider one builds tables it cannot walk. `None` for a machine
    /// reporting fewer bits than the narrowest encoding, which is hardware
    /// this code cannot describe rather than a value to round up.
    #[must_use]
    pub const fn fitting(host_address_width: u8) -> Option<Self> {
        if host_address_width >= 57 {
            Some(Self::Bits57)
        } else if host_address_width >= 48 {
            Some(Self::Bits48)
        } else if host_address_width >= 39 {
            Some(Self::Bits39)
        } else if host_address_width >= 30 {
            Some(Self::Bits30)
        } else {
            None
        }
    }

    /// The highest address a window of this width can translate.
    #[must_use]
    pub const fn limit(self) -> u64 {
        // `bits` is at most 57, so this cannot overflow.
        (1u64 << self.bits()) - 1
    }
}

/// What a device may do to a page.
///
/// Neither bit set is not "no access" in a form the hardware will accept — it
/// is an entry that faults on everything, which is what an *absent* entry
/// already does more cheaply. So a mapping is built with at least one.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Rights {
    /// The device may read the page.
    pub read: bool,
    /// The device may write it.
    pub write: bool,
}

impl Rights {
    /// Read-only.
    pub const READ: Self = Self {
        read: true,
        write: false,
    };
    /// Read and write.
    pub const READ_WRITE: Self = Self {
        read: true,
        write: true,
    };

    /// Whether this grants anything at all.
    #[must_use]
    pub const fn grants_anything(self) -> bool {
        self.read || self.write
    }

    const fn bits(self) -> u64 {
        (self.read as u64) | ((self.write as u64) << 1)
    }
}

/// Which root entry a bus selects.
#[must_use]
pub const fn root_index(bus: u8) -> usize {
    bus as usize
}

/// Which context entry a device and function select.
///
/// Five bits of device and three of function, which is the requester id's low
/// byte — the same number PCI configuration space is addressed by.
#[must_use]
pub const fn context_index(device: u8, function: u8) -> usize {
    (((device & 0x1f) as usize) << 3) | ((function & 0x07) as usize)
}

/// Which entry of `level` an address selects.
///
/// Level 1 is the one holding page addresses; the highest level is the root of
/// the walk. Nine bits per level above the twelve-bit page offset.
#[must_use]
pub const fn level_index(address: u64, level: u8) -> usize {
    let shift = 12 + 9 * (level as u32 - 1);
    ((address >> shift) & 0x1ff) as usize
}

/// A root-table entry: where one bus's context table is.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct RootEntry {
    /// Physical address of the context table, or zero for "not present".
    pub context_table: u64,
}

impl RootEntry {
    /// The two 64-bit words the hardware reads, low first.
    ///
    /// The high word is reserved and must be zero: hardware that gains a
    /// meaning for it later would read whatever had been left there.
    #[must_use]
    pub const fn to_bits(self) -> (u64, u64) {
        if self.context_table == 0 {
            return (0, 0);
        }
        // Present, and the address with its low twelve bits implied.
        (self.context_table & !(PAGE_SIZE - 1) | 1, 0)
    }

    /// Whether this entry is present.
    #[must_use]
    pub const fn present(self) -> bool {
        self.context_table != 0
    }
}

/// A context-table entry: one device's page tables and how wide they are.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ContextEntry {
    /// Physical address of the second-level page table's root.
    pub page_table: u64,
    /// How many address bits it translates.
    pub width: AddressWidth,
    /// Which domain this device belongs to, for invalidation.
    pub domain: u16,
}

impl ContextEntry {
    /// The two 64-bit words the hardware reads, low first.
    ///
    /// Translation type is left at zero — "untranslated requests only, walk
    /// the second-level table" — because that is the only mode this kernel
    /// implements. Pass-through is a *different* mode, and choosing it by
    /// accident is a device that reaches all of memory while the machine
    /// reports an IOMMU.
    #[must_use]
    pub const fn to_bits(self) -> (u64, u64) {
        let low = (self.page_table & !(PAGE_SIZE - 1)) | 1;
        let high = (self.width as u64) | ((self.domain as u64) << 8);
        (low, high)
    }
}

/// A second-level page-table entry.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PageEntry {
    /// Physical address of the page, or of the next level's table.
    pub address: u64,
    /// What the device may do.
    pub rights: Rights,
}

impl PageEntry {
    /// The 64-bit word the hardware reads.
    #[must_use]
    pub const fn to_bits(self) -> u64 {
        (self.address & !(PAGE_SIZE - 1)) | self.rights.bits()
    }

    /// Reads an entry back, or `None` if it grants nothing.
    ///
    /// Absent and present-but-granting-nothing are the same to a device and
    /// must not be the same here: one is a page nobody mapped, the other is a
    /// bug in whoever built it.
    #[must_use]
    pub const fn from_bits(bits: u64) -> Option<Self> {
        let rights = Rights {
            read: bits & 1 != 0,
            write: bits & 2 != 0,
        };
        if !rights.grants_anything() {
            return None;
        }
        Some(Self {
            address: bits & 0x000f_ffff_ffff_f000,
            rights,
        })
    }
}

/// An entry for a table that is walked further rather than describing a page.
///
/// Intermediate levels carry read *and* write regardless of what the leaf
/// grants: the hardware ands the permissions down the walk, so a read-only
/// intermediate would make every page under it read-only however the leaf was
/// built.
#[must_use]
pub const fn table_entry(next_table: u64) -> PageEntry {
    PageEntry {
        address: next_table,
        rights: Rights::READ_WRITE,
    }
}

/// Entries in the interrupt remapping table this kernel builds.
///
/// One page holds 256 sixteen-byte entries, which is far more interrupt
/// sources than this kernel claims. The table size is encoded as a power of
/// two, so this is the smallest size that is not absurd.
pub const IRT_ENTRIES: usize = 256;

/// How a device may deliver a remapped interrupt.
///
/// Fixed delivery to one CPU, which is the only mode this kernel programs.
/// Lowest-priority delivery lets the hardware choose a CPU, and a kernel that
/// cannot say which CPU will take an interrupt cannot reason about what that
/// handler may touch.
const DELIVERY_FIXED: u64 = 0;

/// One interrupt remapping table entry.
///
/// The security property is `source`, and it is the whole point of the step.
/// Without it a remapping table turns a vector into another vector; with it
/// the unit checks that the device *presenting* the handle is the device the
/// handle was issued to. RFC 0011 left "a device raises an MSI it was not
/// programmed to raise" as a residual risk precisely because nothing in the
/// MSI path could answer "who sent this".
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Irte {
    /// The vector the CPU will see.
    pub vector: u8,
    /// Which CPU, as an xAPIC id.
    pub destination: u8,
    /// The requester id permitted to use this handle, as `(bus, device,
    /// function)`, or `None` for an entry the kernel programs on hardware's
    /// behalf.
    ///
    /// `None` is for the I/O APIC's own lines. A line is raised by a chip this
    /// kernel programs, not by a device choosing a message, so there is no
    /// forgery to validate against — and guessing the chip's requester id
    /// wrong would block the console rather than protect it. Every entry
    /// issued to a *device* carries `Some`, which is where the risk is.
    pub source: Option<(u8, u8, u8)>,
}

impl Irte {
    /// The two 64-bit words the hardware reads, low first.
    #[must_use]
    pub const fn to_bits(self) -> (u64, u64) {
        // Present, fixed delivery, physical destination, edge triggered.
        let low = 1
            | (DELIVERY_FIXED << 5)
            | ((self.vector as u64) << 16)
            // The destination *field* is bits 32-63, but an xAPIC id does not
            // sit at the bottom of it: it goes at bit 40, the same place the
            // legacy message address puts it. Writing it at 32 costs nothing
            // visible -- the entry is well formed, the unit accepts it, and
            // the interrupt is simply never delivered.
            | ((self.destination as u64) << 40);

        // Source validation: SVT = 1 checks the full requester id against SID,
        // with SQ = 0 meaning "all sixteen bits must match". Anything less
        // would let one function of a device use another's handle.
        let high = match self.source {
            Some((bus, device, function)) => {
                let sid = ((bus as u64) << 8)
                    | (((device & 0x1f) as u64) << 3)
                    | ((function & 0x07) as u64);
                sid | (1 << 18)
            }
            None => 0,
        };

        (low, high)
    }

    /// An absent entry: present bit clear, everything else zero.
    ///
    /// Not "an entry with no rights" — the hardware has no such thing for
    /// interrupts. An absent entry is what makes a handle unusable, and it is
    /// what every entry this kernel has not issued must be.
    #[must_use]
    pub const fn absent() -> (u64, u64) {
        (0, 0)
    }
}

/// The address a device writes to raise a remapped interrupt.
///
/// Not the same shape as a compatibility-format MSI at all: the destination
/// APIC id is *gone*, replaced by a handle into the remapping table. That is
/// the mechanism — a device can no longer name a CPU or a vector, only a
/// handle, and the handle only works for the device it was issued to.
#[must_use]
pub const fn remappable_message_address(handle: u16) -> u32 {
    // 0xFEE in the high bits as always. Then, and the order of these two is
    // the whole difference between a delivered interrupt and a silent one:
    // **bit 4 is the format bit** that says "remappable", and bit 3 is SHV.
    // Transposing them produces an address the unit accepts and never
    // delivers -- no fault, no message, and a driver that looks broken.
    //
    // `handle[14:0]` at bit 5, and `handle[15]` alone at bit 2 because the
    // field is split around the two flag bits.
    0xfee0_0000
        | (((handle & 0x7fff) as u32) << 5)
        | (1 << 4)
        | (1 << 3)
        | ((((handle >> 15) & 1) as u32) << 2)
}

/// The data a device writes with it.
///
/// Zero. In remappable format the vector lives in the table entry, not in the
/// message — which is exactly why a device can no longer choose one.
#[must_use]
pub const fn remappable_message_data() -> u32 {
    0
}

/// An I/O APIC redirection entry in remappable format.
///
/// A line is remapped like a message is, and it has to be: with compatibility
/// format blocked, an entry left in the old format stops delivering, and the
/// console is the first thing to go quiet.
#[must_use]
pub const fn remappable_redirection(handle: u16, vector: u8, masked: bool, level: bool) -> u64 {
    // The low byte is still the vector -- the hardware uses it only to keep
    // the entry well formed; what is delivered comes from the table.
    let mut entry = vector as u64;
    if level {
        entry |= 1 << 15;
    }
    if masked {
        entry |= 1 << 16;
    }
    // Handle bit 15 sits on its own at bit 11, the format bit at 48, and the
    // low fifteen handle bits at 49. The split is the specification's, not a
    // convenience: bit 48 had to stay where the old format's reserved bit was.
    entry |= (((handle >> 15) & 1) as u64) << 11;
    entry |= 1 << 48;
    entry |= ((handle & 0x7fff) as u64) << 49;
    entry
}

/// A remapping unit's register window.
///
/// Thin on purpose: every method is one register access and a bounded wait,
/// with the policy — which tables, which order, what to do when it does not
/// come ready — left to the caller. The specification's sequences are subtle
/// enough that reading them next to the decisions that use them is worth more
/// than a tidy abstraction.
///
/// # The command register cannot be read
///
/// `GCMD` is write-only and its bits are *not* independent: a write sets the
/// entire enable state, so a read-modify-write is impossible and writing one
/// bit clears the others. Hence [`Unit::command`], a shadow of what was last
/// written. Losing it would turn "enable translation" into "enable translation
/// and disable everything else".
pub struct Unit {
    base: *mut u8,
    /// What was last written to `GCMD`, because it cannot be read back.
    command: u32,
}

/// Register offsets, in bytes from the window's base.
mod reg {
    /// Version.
    pub const VER: usize = 0x00;
    /// Capabilities.
    pub const CAP: usize = 0x08;
    /// Extended capabilities.
    pub const ECAP: usize = 0x10;
    /// Global command. Write-only.
    pub const GCMD: usize = 0x18;
    /// Global status.
    pub const GSTS: usize = 0x1c;
    /// Root table address.
    pub const RTADDR: usize = 0x20;
    /// Context command.
    pub const CCMD: usize = 0x28;
    /// Fault status.
    pub const FSTS: usize = 0x34;
    /// Interrupt remapping table address.
    pub const IRTA: usize = 0xb8;
    /// Invalidation queue tail and address.
    ///
    /// The head register at `0x80` is the unit's side of the ring and is not
    /// read here: nothing is queued yet, so nothing waits for it to advance.
    pub const IQT: usize = 0x88;
    pub const IQA: usize = 0x90;
}

/// `GCMD`/`GSTS` bits. The command and status bits sit at the same positions,
/// which is what makes "write the command, wait for the status" a loop rather
/// than a table.
mod command {
    /// Translation enable, and in `GSTS` translation-enabled.
    pub const TE: u32 = 1 << 31;
    /// Set root table pointer, and root-table-pointer-set.
    pub const SRTP: u32 = 1 << 30;
    /// Interrupt remapping enable, and interrupt-remapping-enabled.
    pub const IRE: u32 = 1 << 25;
    /// Set interrupt remap table pointer, and the status that it took.
    pub const SIRTP: u32 = 1 << 24;
    /// Queued invalidation enable, and the status that it took.
    pub const QIE: u32 = 1 << 26;
    /// Compatibility format interrupts *permitted*.
    ///
    /// Left clear, deliberately. Setting it would keep old-format interrupts
    /// working — including any a device chose to send — which is the thing
    /// remapping exists to stop. Clearing it is what makes the guarantee
    /// "every interrupt came from a table this kernel wrote".
    pub const CFI: u32 = 1 << 23;

    /// The bits that describe a state the unit stays in, as opposed to a thing
    /// it was once told to do.
    ///
    /// `SRTP` and `SIRTP` are absent on purpose. Their status bits say a
    /// pointer *was* latched; carrying them into the shadow would re-latch a
    /// table nobody asked to change on every later command.
    pub const PERSISTENT: u32 = TE | QIE | IRE | CFI;
}

/// Descriptors the invalidation queue understands.
///
/// Only the three this kernel submits are named. Each is sixteen bytes, and
/// the type is the low four bits of the first.
mod descriptor {
    /// Invalidate the context cache.
    pub const CONTEXT: u64 = 0x1;
    /// Invalidate the IOTLB.
    pub const IOTLB: u64 = 0x2;
    /// Wait, and say so, once everything before it has finished.
    pub const WAIT: u64 = 0x5;
    /// Global granularity, in the two bits above the type. Everything this
    /// kernel invalidates, it invalidates entirely: the windows are few and
    /// the cost is a boot-path stall nobody measures.
    pub const GLOBAL: u64 = 0b01 << 4;
    /// Drain reads and writes before reporting the IOTLB invalidated.
    ///
    /// Without these the unit may report an invalidation complete while a
    /// transfer that was already translated is still in flight, which is the
    /// difference between "no device can reach this page" and "no device will
    /// *start* reaching this page".
    pub const DRAIN: u64 = (1 << 6) | (1 << 7);
    /// Write the status word when this descriptor retires.
    pub const STATUS_WRITE: u64 = 1 << 5;
    /// Finish everything queued before this descriptor before starting it.
    pub const FENCE: u64 = 1 << 6;
}

/// Descriptors in the invalidation queue, fixed by the size written to `IQA`.
///
/// Size zero: one page of sixteen-byte descriptors, which is the smallest the
/// format allows and far more than this kernel queues at once.
pub const QUEUE_ENTRIES: usize = 256;

/// A descriptor that invalidates the whole context cache.
///
/// Global rather than device-selective. A device-selective invalidation needs
/// the source id and the domain, and gets them wrong quietly; this kernel adds
/// devices at boot and can afford to throw the cache away.
#[must_use]
pub const fn context_invalidation() -> [u64; 2] {
    [descriptor::CONTEXT | descriptor::GLOBAL, 0]
}

/// A descriptor that invalidates the whole IOTLB, draining transfers first.
#[must_use]
pub const fn iotlb_invalidation() -> [u64; 2] {
    [
        descriptor::IOTLB | descriptor::GLOBAL | descriptor::DRAIN,
        0,
    ]
}

/// How long to wait for a register to report a change, in polls.
///
/// Bounded because this runs on the boot path with interrupts off: hardware
/// that never answers must leave the machine reporting a failure rather than
/// spinning in a kernel with no console yet. Generous, because the operations
/// below invalidate caches in hardware and an emulator is not fast.
const WAIT_POLLS: u32 = 1_000_000;

impl Unit {
    /// Wraps a mapped register window.
    ///
    /// # Safety
    ///
    /// `base` must be the mapped register window of a DMA remapping unit, from
    /// a `DMAR` table this kernel parsed, and nothing else may be programming
    /// it.
    #[must_use]
    pub const unsafe fn new(base: *mut u8) -> Self {
        Self { base, command: 0 }
    }

    /// Reads a 32-bit register.
    unsafe fn read32(&self, offset: usize) -> u32 {
        // SAFETY: an offset within the unit's 4 KiB register window, which the
        // caller of `new` guarantees is mapped.
        unsafe { core::ptr::read_volatile(self.base.add(offset).cast::<u32>()) }
    }

    /// Writes a 32-bit register.
    unsafe fn write32(&self, offset: usize, value: u32) {
        // SAFETY: as `read32`.
        unsafe { core::ptr::write_volatile(self.base.add(offset).cast::<u32>(), value) }
    }

    /// Reads a 64-bit register.
    unsafe fn read64(&self, offset: usize) -> u64 {
        // SAFETY: as `read32`.
        unsafe { core::ptr::read_volatile(self.base.add(offset).cast::<u64>()) }
    }

    /// Writes a 64-bit register.
    unsafe fn write64(&self, offset: usize, value: u64) {
        // SAFETY: as `read32`.
        unsafe { core::ptr::write_volatile(self.base.add(offset).cast::<u64>(), value) }
    }

    /// The unit's version register, which is non-zero on real hardware.
    ///
    /// The first read of a window the firmware described. A zero here means
    /// the `DMAR` named an address that is not a remapping unit, which is the
    /// failure the parser's alignment checks make unlikely and this makes
    /// visible.
    ///
    /// # Safety
    ///
    /// The caller's obligation from [`Unit::new`]: a mapped register window of
    /// a real remapping unit, which nothing else is programming.
    #[must_use]
    pub unsafe fn version(&self) -> u32 {
        // SAFETY: the caller's obligation from `new`.
        unsafe { self.read32(reg::VER) }
    }

    /// The capability register.
    ///
    /// # Safety
    ///
    /// The caller's obligation from [`Unit::new`]: a mapped register window of
    /// a real remapping unit, which nothing else is programming.
    #[must_use]
    pub unsafe fn capabilities(&self) -> u64 {
        // SAFETY: the caller's obligation from `new`.
        unsafe { self.read64(reg::CAP) }
    }

    /// The extended capability register.
    ///
    /// # Safety
    ///
    /// The caller's obligation from [`Unit::new`]: a mapped register window of
    /// a real remapping unit, which nothing else is programming.
    #[must_use]
    pub unsafe fn extended_capabilities(&self) -> u64 {
        // SAFETY: the caller's obligation from `new`.
        unsafe { self.read64(reg::ECAP) }
    }

    /// Which address widths this unit's page tables may use.
    ///
    /// The `DMAR`'s host address width says what the hardware can *generate*;
    /// this says what it can be asked to *walk*. Building tables to a width
    /// the unit does not support is a walk to the wrong depth, so the wider
    /// number alone is not enough to choose one.
    ///
    /// # Safety
    ///
    /// The caller's obligation from [`Unit::new`]: a mapped register window of
    /// a real remapping unit, which nothing else is programming.
    #[must_use]
    pub unsafe fn supports_width(&self, width: AddressWidth) -> bool {
        // SAFETY: the caller's obligation from `new`.
        let capabilities = unsafe { self.capabilities() };
        // SAGAW, bits 8-12: one bit per supported width, in the same order the
        // width encoding uses.
        let supported = (capabilities >> 8) & 0x1f;
        supported & (1 << (width as u64)) != 0
    }

    /// Rebuilds a unit around a window that is **already programmed**.
    ///
    /// Use this rather than [`new`](Self::new) for any unit that will issue a
    /// command to a live one. `GCMD` cannot be read back, so a [`Unit`] carries
    /// a shadow of what was last written to it, and `new` starts that shadow at
    /// zero — so the next command writes zeros into every bit it is not
    /// setting. On a unit that is translating, that turns translation **off**.
    ///
    /// This is not hypothetical. Enabling interrupt remapping did exactly that
    /// from M6-15 until 2026-08-11: `GSTS` went `0xc000_0000` to `0x4400_0000`
    /// across one command, the machine reported that interrupts were being
    /// remapped, and every device's DMA was untranslated from that moment. It
    /// cost a milestone of chasing an undelivered interrupt that was a symptom.
    ///
    /// # Safety
    ///
    /// The caller's obligation from [`Unit::new`].
    #[must_use]
    pub unsafe fn adopt(base: *mut u8) -> Self {
        // SAFETY: the caller's obligation.
        let mut unit = unsafe { Self::new(base) };
        // SAFETY: as above -- a mapped register window.
        unit.command = unsafe { unit.read32(reg::GSTS) } & command::PERSISTENT;
        unit
    }

    /// Whether translation is on.
    ///
    /// # Safety
    ///
    /// The caller's obligation from [`Unit::new`]: a mapped register window of
    /// a real remapping unit, which nothing else is programming.
    #[must_use]
    pub unsafe fn translating(&self) -> bool {
        // SAFETY: the caller's obligation from `new`.
        unsafe { self.read32(reg::GSTS) & command::TE != 0 }
    }

    /// Polls `GSTS` until `bit` reads as `set`, or the bound runs out.
    unsafe fn await_status(&self, bit: u32, set: bool) -> bool {
        for _ in 0..WAIT_POLLS {
            // SAFETY: the caller's obligation from `new`.
            if (unsafe { self.read32(reg::GSTS) } & bit != 0) == set {
                return true;
            }
            core::hint::spin_loop();
        }
        false
    }

    /// Points the unit at a root table, and waits for it to take.
    ///
    /// # Safety
    ///
    /// `physical` must be the address of a root table this kernel built and
    /// will not free. The hardware walks it by physical address, with no page
    /// table of its own and no notice.
    pub unsafe fn set_root_table(&mut self, physical: u64) -> bool {
        // SAFETY: the caller's obligation.
        unsafe {
            self.write64(reg::RTADDR, physical);
            // One-shot: written with the shadow, and deliberately not kept in
            // it. A later command that still carried `SRTP` would re-latch a
            // root table pointer nobody asked to change.
            self.write32(reg::GCMD, self.command | command::SRTP);
            self.await_status(command::SRTP, true)
        }
    }

    /// Invalidates every cached context entry.
    ///
    /// # Safety
    ///
    /// The caller's obligation from `new`.
    pub unsafe fn invalidate_context(&self) -> bool {
        /// Invalidate context cache, and the global granularity.
        const ICC: u64 = 1 << 63;
        const GLOBAL: u64 = 1 << 61;

        // SAFETY: the caller's obligation.
        unsafe {
            self.write64(reg::CCMD, ICC | GLOBAL);
            for _ in 0..WAIT_POLLS {
                if self.read64(reg::CCMD) & ICC == 0 {
                    return true;
                }
                core::hint::spin_loop();
            }
        }
        false
    }

    /// Invalidates the whole IOTLB.
    ///
    /// # Safety
    ///
    /// The caller's obligation from `new`.
    pub unsafe fn invalidate_iotlb(&self) -> bool {
        /// Invalidate, and the global granularity.
        const IVT: u64 = 1 << 63;
        const GLOBAL: u64 = 1 << 60;

        // The IOTLB registers are not at a fixed offset: the unit reports
        // where they are, in sixteen-byte units, in the extended capability
        // register. Assuming a fixed one writes into whatever is there.
        // SAFETY: the caller's obligation.
        let offset = unsafe { ((self.extended_capabilities() >> 8) & 0x3ff) as usize } * 16;
        let iotlb = offset + 8;

        // SAFETY: an offset the unit itself reported, within its window.
        unsafe {
            self.write64(iotlb, IVT | GLOBAL);
            for _ in 0..WAIT_POLLS {
                if self.read64(iotlb) & IVT == 0 {
                    return true;
                }
                core::hint::spin_loop();
            }
        }
        false
    }

    /// Whether the unit is taking invalidations through the queue.
    ///
    /// Read from `GSTS` rather than remembered, because a [`Unit`] is rebuilt
    /// around the register window wherever one is needed and a fresh one knows
    /// nothing about what an earlier one enabled. Every caller that invalidates
    /// has to ask, and asking the hardware is the only answer that survives.
    ///
    /// # Safety
    ///
    /// The caller's obligation from `new`.
    #[must_use]
    pub unsafe fn queued_invalidation_enabled(&self) -> bool {
        // SAFETY: the caller's obligation.
        unsafe { self.read32(reg::GSTS) & command::QIE != 0 }
    }

    /// Submits `descriptors` through the invalidation queue and waits for them.
    ///
    /// **This is not an alternative to the register path; once `QIE` is set it
    /// is the only path.** A unit with queued invalidation enabled ignores the
    /// invalidation registers, and ignores them *silently* — the command bit
    /// clears, the poll succeeds, and nothing is invalidated. That is a
    /// hardware behaviour a kernel can only discover by looking for it, which
    /// is why [`queued_invalidation_enabled`](Self::queued_invalidation_enabled)
    /// exists and why every caller is expected to branch on it.
    ///
    /// Completion is a wait descriptor with the status-write bit, not the head
    /// register catching the tail: the head advancing says the descriptor was
    /// taken, and what a caller needs to know is that the invalidation it
    /// describes has finished.
    ///
    /// # Safety
    ///
    /// `queue` must be the mapped invalidation queue this unit was given, with
    /// [`QUEUE_ENTRIES`] descriptors. `status` must be a mapped, four-byte
    /// aligned word the unit may write, and `status_physical` the address the
    /// hardware reaches it by.
    pub unsafe fn queued_invalidate(
        &self,
        queue: *mut u64,
        status: *mut u32,
        status_physical: u64,
        descriptors: &[[u64; 2]],
    ) -> bool {
        /// What the wait descriptor leaves behind. Any value but the zero the
        /// status word is primed with would do; `INVD` in ASCII makes a stale
        /// queue obvious in a memory dump.
        const DONE: u32 = 0x494e_5644;

        // One slot is spent on the wait descriptor, so a caller must leave room
        // for it. Refused rather than wrapped: a queue that overruns its own
        // tail invalidates nothing and reports that it did.
        if descriptors.len() + 1 > QUEUE_ENTRIES {
            return false;
        }

        // SAFETY: the caller's obligation -- a queue of `QUEUE_ENTRIES`
        // descriptors and a status word the unit may write.
        unsafe {
            let mut tail = ((self.read64(reg::IQT) >> 4) as usize) % QUEUE_ENTRIES;
            core::ptr::write_volatile(status, 0);

            for descriptor in descriptors {
                core::ptr::write_volatile(queue.add(tail * 2), descriptor[0]);
                core::ptr::write_volatile(queue.add(tail * 2 + 1), descriptor[1]);
                tail = (tail + 1) % QUEUE_ENTRIES;
            }

            // Fenced, so the unit may not reorder the wait behind what it is
            // waiting for, and status-writing, so finishing is observable.
            core::ptr::write_volatile(
                queue.add(tail * 2),
                descriptor::WAIT
                    | descriptor::STATUS_WRITE
                    | descriptor::FENCE
                    | ((DONE as u64) << 32),
            );
            core::ptr::write_volatile(queue.add(tail * 2 + 1), status_physical & !0b11);
            tail = (tail + 1) % QUEUE_ENTRIES;

            // The descriptors must be in memory before the tail says they are.
            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
            self.write64(reg::IQT, (tail as u64) << 4);

            for _ in 0..WAIT_POLLS {
                if core::ptr::read_volatile(status) == DONE {
                    return true;
                }
                core::hint::spin_loop();
            }
        }
        false
    }

    /// Turns translation on, and waits for the unit to say it is on.
    ///
    /// From this moment every DMA by every device the root table covers is
    /// translated, and anything not mapped is refused. There is no partial
    /// state: a device whose window is empty can reach nothing at all.
    ///
    /// # Safety
    ///
    /// A root table must have been set, every window the machine needs must
    /// already be built and populated, and the caller must be prepared for a
    /// device that was mid-transfer to fault.
    pub unsafe fn enable_translation(&mut self) -> bool {
        self.command |= command::TE;
        // SAFETY: the caller's obligation.
        unsafe {
            self.write32(reg::GCMD, self.command);
            self.await_status(command::TE, true)
        }
    }

    /// Reads and clears the first recorded fault.
    ///
    /// Returns `(address, requester id, was a read, reason)`. The records live
    /// at an offset the unit reports in its capability register — not a fixed
    /// one — and a fault is cleared by writing its `F` bit back, which is the
    /// only way the next fault can be recorded once the log is full.
    ///
    /// # Safety
    ///
    /// The caller's obligation from [`Unit::new`].
    pub unsafe fn take_fault(&self) -> Option<(u64, u16, bool, u8)> {
        /// Fault recorded, in the high word.
        const FAULT: u64 = 1 << 63;
        /// The access was a read.
        const READ: u64 = 1 << 62;
        /// Primary pending fault, and fault overflow, in `FSTS`.
        const PPF: u32 = 1 << 1;
        const PFO: u32 = 1 << 0;

        // SAFETY: the caller's obligation.
        unsafe {
            if self.read32(reg::FSTS) & (PPF | PFO) == 0 {
                return None;
            }
            // Where the records are, in sixteen-byte units, from `CAP`.
            let offset = (((self.capabilities() >> 24) & 0x3ff) as usize) * 16;
            let low = self.read64(offset);
            let high = self.read64(offset + 8);
            if high & FAULT == 0 {
                return None;
            }
            let requester = (high & 0xffff) as u16;
            let reason = ((high >> 32) & 0xff) as u8;
            let read = high & READ != 0;

            // Clearing is a write-one-to-clear of the fault bit, and then of
            // the status register's summary. Leaving either set means the unit
            // records nothing further and the next fault is invisible.
            self.write64(offset + 8, FAULT);
            self.write32(reg::FSTS, PPF | PFO);
            Some((low, requester, read, reason))
        }
    }

    /// Turns on the invalidation queue.
    ///
    /// The specification requires this **before** interrupt remapping is
    /// enabled, and the requirement is easy to miss because register-based
    /// invalidation keeps working without it. Whether a unit enforces it is a
    /// property of the unit.
    ///
    /// # Safety
    ///
    /// `physical` must be a zeroed page this kernel owns and will not free.
    pub unsafe fn enable_queued_invalidation(&mut self, physical: u64) -> bool {
        // SAFETY: the caller's obligation.
        unsafe {
            // Size zero: 256 descriptors in one page, which is the smallest
            // the format allows and more than this kernel will ever queue.
            self.write64(reg::IQA, physical & !(PAGE_SIZE - 1));
            self.write64(reg::IQT, 0);
            self.command |= command::QIE;
            self.write32(reg::GCMD, self.command);
            self.await_status(command::QIE, true)
        }
    }

    /// Points the unit at an interrupt remapping table.
    ///
    /// `entries` must be a power of two; the register takes its log minus one.
    ///
    /// # Safety
    ///
    /// `physical` must be a table this kernel built and will not free, with at
    /// least `entries` entries. The hardware walks it by physical address.
    pub unsafe fn set_interrupt_remap_table(&mut self, physical: u64, entries: usize) -> bool {
        if !entries.is_power_of_two() || entries < 2 {
            return false;
        }
        let size = (entries.trailing_zeros() - 1) as u64;
        // SAFETY: the caller's obligation.
        unsafe {
            self.write64(reg::IRTA, (physical & !(PAGE_SIZE - 1)) | size);
            // One-shot, like `SRTP`, and kept out of the shadow for the same
            // reason: a later command carrying it would re-latch a table
            // pointer nobody asked to change.
            self.write32(reg::GCMD, self.command | command::SIRTP);
            self.await_status(command::SIRTP, true)
        }
    }

    /// Turns interrupt remapping on, and blocks compatibility format.
    ///
    /// Both halves matter. Remapping alone routes what devices send through a
    /// table; blocking compatibility format is what stops a device sending
    /// something else instead. RFC 0011's residual risk is only retired by the
    /// pair.
    ///
    /// # Safety
    ///
    /// Every interrupt source the machine needs must already be remapped —
    /// including the I/O APIC's lines. From here, anything in the old format
    /// is refused, and a console whose line was left alone goes quiet.
    pub unsafe fn enable_interrupt_remapping(&mut self) -> bool {
        self.command |= command::IRE;
        self.command &= !command::CFI;
        // SAFETY: the caller's obligation.
        unsafe {
            self.write32(reg::GCMD, self.command);
            self.await_status(command::IRE, true)
        }
    }

    /// Whether interrupt remapping is on.
    ///
    /// # Safety
    ///
    /// The caller's obligation from [`Unit::new`].
    #[must_use]
    pub unsafe fn remapping_interrupts(&self) -> bool {
        // SAFETY: the caller's obligation.
        unsafe { self.read32(reg::GSTS) & command::IRE != 0 }
    }

    /// Whether the unit supports interrupt remapping at all.
    ///
    /// # Safety
    ///
    /// The caller's obligation from [`Unit::new`].
    #[must_use]
    pub unsafe fn supports_interrupt_remapping(&self) -> bool {
        // `IR`, bit 3 of the extended capability register.
        // SAFETY: the caller's obligation.
        unsafe { self.extended_capabilities() & (1 << 3) != 0 }
    }

    /// The fault status register.
    ///
    /// Bit 1 is "a fault is recorded". RFC 0012's position is that a fault is
    /// the *feature*: a device attempted an access it was not granted, which
    /// is either a driver bug or a hostile device, and either way the event
    /// this whole exercise exists to make visible.
    ///
    /// # Safety
    ///
    /// The caller's obligation from [`Unit::new`]: a mapped register window of
    /// a real remapping unit, which nothing else is programming.
    #[must_use]
    pub unsafe fn fault_status(&self) -> u32 {
        // SAFETY: the caller's obligation from `new`.
        unsafe { self.read32(reg::FSTS) }
    }

    /// Whether any fault has been recorded.
    ///
    /// # Safety
    ///
    /// The caller's obligation from [`Unit::new`]: a mapped register window of
    /// a real remapping unit, which nothing else is programming.
    #[must_use]
    pub unsafe fn faulted(&self) -> bool {
        /// Primary pending fault, and fault overflow.
        const PPF: u32 = 1 << 1;
        const PFO: u32 = 1 << 0;
        // SAFETY: the caller's obligation from `new`.
        unsafe { self.fault_status() & (PPF | PFO) != 0 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_remapping_entry_validates_the_source_that_may_use_it() {
        // The security property. Without the source check a remapping table
        // turns one vector into another; with it, the unit refuses a handle
        // presented by a device it was not issued to -- which is the whole of
        // RFC 0011's residual risk.
        let entry = Irte {
            vector: 0xfc,
            destination: 3,
            source: Some((0, 3, 0)),
        };
        let (low, high) = entry.to_bits();

        assert_eq!(low & 1, 1, "present");
        assert_eq!((low >> 16) & 0xff, 0xfc, "vector");
        assert_eq!((low >> 40) & 0xff, 3, "destination, at bit 40 and not 32");
        assert_eq!((low >> 32) & 0xff, 0, "nothing at the bottom of the field");
        // SVT = 1 in bits 18-19, and the requester id of 00:03.0 is 0x18.
        assert_eq!((high >> 18) & 0b11, 1, "source validation on");
        assert_eq!(high & 0xffff, 0x18, "the requester id");

        // And an entry the kernel programs for a chip validates nothing,
        // because there is no requester to validate: guessing the I/O APIC's
        // id wrong blocks the console instead of protecting it.
        let line = Irte {
            vector: 0x21,
            destination: 0,
            source: None,
        };
        assert_eq!(line.to_bits().1, 0, "no source validation for a line");
        assert_eq!(line.to_bits().0 & 1, 1, "still present");
    }

    #[test]
    fn an_absent_entry_is_all_zeroes() {
        // The hardware has no "present but grants nothing" for interrupts, so
        // absent is the only way a handle is unusable -- and every handle this
        // kernel has not issued must be exactly this.
        assert_eq!(Irte::absent(), (0, 0));
    }

    #[test]
    fn a_remappable_message_names_a_handle_and_not_a_cpu() {
        // A compatibility MSI carries the destination APIC id and the vector,
        // which is why a device could raise anything it liked. A remappable
        // one carries neither.
        let address = remappable_message_address(7);
        assert_eq!(address >> 20, 0xfee);
        assert_eq!((address >> 5) & 0x7fff, 7, "handle");
        assert_eq!((address >> 4) & 1, 1, "remappable format is bit 4");
        assert_eq!((address >> 3) & 1, 1, "sub-handle valid is bit 3");
        assert_eq!(
            remappable_message_data(),
            0,
            "the vector is not in the message"
        );

        // Handle 15 and above splits: the top bit sits at bit 2 on its own.
        let high = remappable_message_address(0x8001);
        assert_eq!((high >> 5) & 0x7fff, 1);
        assert_eq!((high >> 2) & 1, 1);
    }

    #[test]
    fn adopting_a_live_unit_keeps_translation_on_and_drops_the_one_shots() {
        // The register window as a buffer, which is all `Unit` needs: this
        // test writes a status register and asks what shadow comes back.
        let mut window = [0u8; 4096];
        // Translating, root table pointer set, remapping and its queue on --
        // `0xc000_0000` plus the bits interrupt remapping adds.
        window[reg::GSTS..reg::GSTS + 4].copy_from_slice(&0xe600_0000u32.to_le_bytes());

        // SAFETY: a 4 KiB buffer standing in for the register window, which
        // nothing else touches for the life of this test.
        let unit = unsafe { Unit::adopt(window.as_mut_ptr()) };

        assert_eq!(
            unit.command & command::TE,
            command::TE,
            "translation must survive being adopted -- losing it here is the \
             kernel turning its own IOMMU off on the next command"
        );
        assert_eq!(unit.command & command::QIE, command::QIE, "queue kept");
        assert_eq!(unit.command & command::IRE, command::IRE, "remapping kept");
        assert_eq!(
            unit.command & command::SRTP,
            0,
            "the root-table-pointer status must not become a command to latch \
             it again"
        );
        assert_eq!(unit.command & command::SIRTP, 0, "nor the remap table's");

        // And a unit built the other way keeps nothing, which is the whole
        // hazard `adopt` exists for.
        // SAFETY: as above.
        let fresh = unsafe { Unit::new(window.as_mut_ptr()) };
        assert_eq!(fresh.command, 0);
    }

    #[test]
    fn an_invalidation_descriptor_says_what_it_invalidates() {
        // Pinned, because these are written into a queue the hardware reads
        // and a wrong type is a descriptor that invalidates something else --
        // or nothing, which is how this kernel spent a milestone believing it
        // had invalidated a context cache it had not.
        let context = context_invalidation();
        assert_eq!(context[0] & 0xf, 0x1, "context cache invalidation");
        assert_eq!((context[0] >> 4) & 0b11, 0b01, "global granularity");
        assert_eq!(context[1], 0, "no domain or source selects anything");

        let iotlb = iotlb_invalidation();
        assert_eq!(iotlb[0] & 0xf, 0x2, "IOTLB invalidation");
        assert_eq!((iotlb[0] >> 4) & 0b11, 0b01, "global granularity");
        assert_eq!((iotlb[0] >> 6) & 1, 1, "drain writes");
        assert_eq!((iotlb[0] >> 7) & 1, 1, "drain reads");
        assert_eq!(iotlb[1], 0, "global, so no address");
    }

    #[test]
    fn the_wait_descriptor_is_fenced_and_reports() {
        // The three bits that make a wait descriptor mean "everything before
        // this is done, and here is how you will know". Dropping the fence
        // would let the unit retire the wait before what it waits on, and the
        // caller would read a status word that promises nothing.
        assert_eq!(descriptor::WAIT & 0xf, 0x5);
        assert_eq!(descriptor::STATUS_WRITE, 1 << 5, "status write");
        assert_eq!(descriptor::FENCE, 1 << 6, "fence");
    }

    #[test]
    fn a_remappable_redirection_puts_the_handle_where_the_format_bit_says() {
        // The I/O APIC's entry has to be remapped too, or a console whose line
        // was left in the old format goes quiet the moment compatibility
        // format is blocked.
        let entry = remappable_redirection(4, 0x21, false, true);
        assert_eq!(entry & 0xff, 0x21, "vector still in the low byte");
        assert_eq!((entry >> 15) & 1, 1, "level triggered");
        assert_eq!((entry >> 16) & 1, 0, "not masked");
        assert_eq!((entry >> 48) & 1, 1, "remappable format");
        assert_eq!((entry >> 49) & 0x7fff, 4, "handle");

        let masked = remappable_redirection(4, 0x21, true, false);
        assert_eq!((masked >> 16) & 1, 1);
        assert_eq!((masked >> 15) & 1, 0);

        // The sixteenth handle bit is split out to bit 11, not adjacent.
        let split = remappable_redirection(0x8000, 0x21, false, false);
        assert_eq!((split >> 11) & 1, 1);
        assert_eq!((split >> 49) & 0x7fff, 0);
    }

    #[test]
    fn a_root_entry_is_a_present_bit_and_a_page_address() {
        let entry = RootEntry {
            context_table: 0x1234_5000,
        };
        assert_eq!(entry.to_bits(), (0x1234_5001, 0));
        assert!(entry.present());

        // Absent is all zeroes, not a present bit with a null address: the
        // hardware would walk to physical zero.
        let absent = RootEntry { context_table: 0 };
        assert_eq!(absent.to_bits(), (0, 0));
        assert!(!absent.present());
    }

    #[test]
    fn a_context_entry_carries_the_width_and_the_domain_in_the_high_word() {
        let entry = ContextEntry {
            page_table: 0x2000_0000,
            width: AddressWidth::Bits39,
            domain: 7,
        };
        let (low, high) = entry.to_bits();

        assert_eq!(low, 0x2000_0001, "present bit and the table address");
        // Width in bits 0-2, domain in 8-23. 39-bit addressing encodes as 1.
        assert_eq!(high, 0x0000_0701);

        // The width field is the specification's encoding, not the bit count.
        // Writing 39 there is a table walked to the wrong depth.
        assert_eq!(AddressWidth::Bits39 as u64, 1);
        assert_eq!(high & 0b111, 1);
        assert_eq!((high >> 8) & 0xffff, 7);
    }

    #[test]
    fn the_widths_encode_and_measure_as_the_specification_says() {
        for (width, encoding, levels, bits) in [
            (AddressWidth::Bits30, 0, 2, 30),
            (AddressWidth::Bits39, 1, 3, 39),
            (AddressWidth::Bits48, 2, 4, 48),
            (AddressWidth::Bits57, 3, 5, 57),
        ] {
            assert_eq!(width as u8, encoding);
            assert_eq!(width.levels(), levels);
            assert_eq!(width.bits(), bits);
        }
        assert_eq!(AddressWidth::Bits39.limit(), 0x0000_007f_ffff_ffff);
    }

    #[test]
    fn a_width_is_chosen_no_wider_than_the_hardware_reported() {
        // Choosing wider than the hardware can generate builds tables it
        // cannot walk.
        assert_eq!(AddressWidth::fitting(39), Some(AddressWidth::Bits39));
        assert_eq!(AddressWidth::fitting(46), Some(AddressWidth::Bits39));
        assert_eq!(AddressWidth::fitting(48), Some(AddressWidth::Bits48));
        assert_eq!(AddressWidth::fitting(57), Some(AddressWidth::Bits57));
        assert_eq!(AddressWidth::fitting(64), Some(AddressWidth::Bits57));
        assert_eq!(AddressWidth::fitting(30), Some(AddressWidth::Bits30));
        // Narrower than anything this code can describe. Rounding up would be
        // choosing a width the hardware said it does not have.
        assert_eq!(AddressWidth::fitting(29), None);
        assert_eq!(AddressWidth::fitting(0), None);
    }

    #[test]
    fn a_requester_id_indexes_the_tables_the_way_pci_addresses_it() {
        // 00:03.0 -- the address QEMU puts virtio-blk at, and the one every
        // boot log in this project prints.
        assert_eq!(root_index(0x00), 0);
        assert_eq!(context_index(3, 0), 0x18);

        // Five bits of device, three of function, and nothing above them.
        assert_eq!(context_index(31, 7), 0xff);
        assert_eq!(context_index(0, 0), 0);
        assert_eq!(
            context_index(0xff, 0xff),
            0xff,
            "the high bits are not ours"
        );
        assert_eq!(root_index(0xff), 255);
    }

    #[test]
    fn an_address_selects_nine_bits_per_level_above_the_page_offset() {
        // Hand-computed: bits 12-20 are level 1, 21-29 level 2, 30-38 level 3.
        let address = (1u64 << 12) | (2 << 21) | (3 << 30);
        assert_eq!(level_index(address, 1), 1);
        assert_eq!(level_index(address, 2), 2);
        assert_eq!(level_index(address, 3), 3);

        // The page offset selects nothing.
        assert_eq!(level_index(0xfff, 1), 0);
        // Every index is nine bits, so no level can escape its table.
        for level in 1..=5u8 {
            assert!(level_index(u64::MAX, level) < ENTRIES);
        }
    }

    #[test]
    fn a_page_entry_round_trips_and_keeps_its_rights() {
        let entry = PageEntry {
            address: 0x4000_0000,
            rights: Rights::READ_WRITE,
        };
        assert_eq!(entry.to_bits(), 0x4000_0003);
        assert_eq!(PageEntry::from_bits(0x4000_0003), Some(entry));

        let read_only = PageEntry {
            address: 0x4000_0000,
            rights: Rights::READ,
        };
        assert_eq!(read_only.to_bits(), 0x4000_0001);
        assert_eq!(PageEntry::from_bits(0x4000_0001), Some(read_only));
    }

    #[test]
    fn an_entry_that_grants_nothing_reads_back_as_absent() {
        // A device cannot tell "nobody mapped this" from "mapped with no
        // rights" -- both fault. Reading the second back as a mapping would
        // report a page as present that grants nothing.
        assert_eq!(PageEntry::from_bits(0), None);
        assert_eq!(PageEntry::from_bits(0x4000_0000), None);
    }

    #[test]
    fn an_intermediate_entry_is_writable_whatever_the_leaf_grants() {
        // The hardware ands permissions down the walk, so a read-only
        // intermediate makes every page beneath it read-only however the leaf
        // was built -- a mapping that silently loses its write right.
        let entry = table_entry(0x8000_0000);
        assert_eq!(entry.rights, Rights::READ_WRITE);
        assert_eq!(entry.to_bits(), 0x8000_0003);
    }

    #[test]
    fn addresses_are_masked_to_their_page() {
        // The low bits are flags. An unaligned address here would set them.
        let entry = PageEntry {
            address: 0x4000_0fff,
            rights: Rights::READ,
        };
        assert_eq!(entry.to_bits(), 0x4000_0001);

        let root = RootEntry {
            context_table: 0x1234_5fff,
        };
        assert_eq!(root.to_bits(), (0x1234_5001, 0));
    }
}
