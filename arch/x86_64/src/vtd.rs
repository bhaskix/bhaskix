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
}

/// `GCMD`/`GSTS` bits. The command and status bits sit at the same positions,
/// which is what makes "write the command, wait for the status" a loop rather
/// than a table.
mod command {
    /// Translation enable, and in `GSTS` translation-enabled.
    pub const TE: u32 = 1 << 31;
    /// Set root table pointer, and root-table-pointer-set.
    pub const SRTP: u32 = 1 << 30;
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
