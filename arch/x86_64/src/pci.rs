// SPDX-License-Identifier: Apache-2.0
//! Finding devices on the PCI bus.
//!
//! Enough PCI to locate a device, read where its registers are, and walk its
//! capability list. Not a bus driver: nothing here assigns resources,
//! configures bridges, or manages power. Firmware has already done all of
//! that by the time the kernel runs, and redoing it is how a kernel breaks
//! machines it was never tested on.
//!
//! # Configuration mechanism 1, not ECAM
//!
//! Config space is reached through the two I/O ports every PC has had since
//! 1993, rather than through the memory-mapped window PCI Express describes.
//! Both work on the machines Bhaskix targets; the port mechanism needs no
//! ACPI table, no mapping, and no fallback path for firmware that omits the
//! table — and it reaches every register a virtio device needs, because the
//! capabilities that matter live in the first 256 bytes.
//!
//! What it cannot reach is *extended* config space, above 256 bytes: AER,
//! SR-IOV, and the rest of PCI Express's own capabilities. Nothing needs
//! those yet. When something does, this module grows an ECAM path chosen from
//! the MCFG table, and every caller here keeps working — which is the reason
//! the address is built in one function rather than at each use.
//!
//! # Enumeration is exhaustive and bounded
//!
//! Every bus, device and function is probed, rather than following bridges
//! from bus zero. That is slower — 32 768 reads — and it is also immune to a
//! bridge configuration this code does not understand. At a few hundred
//! nanoseconds per read it costs milliseconds once, during boot.

use crate::port::Port;

/// Where a configuration address is written.
const CONFIG_ADDRESS: u16 = 0x0cf8;
/// Where the selected register is read and written.
const CONFIG_DATA: u16 = 0x0cfc;

/// Set in the address to say "this is a configuration cycle".
const ENABLE: u32 = 1 << 31;

/// Returned by a read of a device that is not there.
const ABSENT: u16 = 0xffff;

/// Buses, devices per bus, and functions per device.
const BUSES: u16 = 256;
const DEVICES: u8 = 32;
const FUNCTIONS: u8 = 8;

/// Capability list entries this will walk before giving up.
///
/// A capability list is a linked list inside config space, and a device with a
/// cycle in it — broken, or hostile — would otherwise be walked for ever
/// during boot with interrupts disabled.
const MAX_CAPABILITIES: usize = 48;

/// Where a device is on the bus.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Address {
    /// Bus number.
    pub bus: u8,
    /// Device number on that bus.
    pub device: u8,
    /// Function number of that device.
    pub function: u8,
}

impl Address {
    /// Names a function.
    #[must_use]
    pub const fn new(bus: u8, device: u8, function: u8) -> Self {
        Self {
            bus,
            device,
            function,
        }
    }

    /// The value written to [`CONFIG_ADDRESS`] to select `offset`.
    ///
    /// The low two bits are cleared because a configuration cycle addresses a
    /// 32-bit register: a read at offset 2 selects the same register as one at
    /// offset 0, and the caller shifts the half it wants out of the result.
    const fn selector(&self, offset: u8) -> u32 {
        ENABLE
            | ((self.bus as u32) << 16)
            | (((self.device & 0x1f) as u32) << 11)
            | (((self.function & 0x07) as u32) << 8)
            | ((offset as u32) & 0xfc)
    }
}

/// What a device says it is.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Identity {
    /// Who made it.
    pub vendor: u16,
    /// What it is.
    pub device: u16,
    /// Broad class — storage, network, display.
    pub class: u8,
    /// What kind of that class.
    pub subclass: u8,
    /// Subsystem device identifier, which is how a transitional virtio device
    /// says which device it really is.
    pub subsystem: u16,
    /// Bit 7 of the header type: whether this device has more functions.
    pub multifunction: bool,
}

/// Reads a 32-bit configuration register.
///
/// # Safety
///
/// A configuration read has no side effects on any device this kernel talks
/// to, but the ports are global state: nothing else may be driving a
/// configuration cycle concurrently. Every caller here runs on the bootstrap
/// CPU during boot.
#[must_use]
pub unsafe fn read32(address: Address, offset: u8) -> u32 {
    // SAFETY: the two ports are the documented configuration mechanism, and
    // the address register must be written before the data register is read --
    // that is how the register is selected, not an ordering nicety.
    unsafe {
        Port::<u32>::new(CONFIG_ADDRESS).write(address.selector(offset));
        Port::<u32>::new(CONFIG_DATA).read()
    }
}

/// Reads a 16-bit configuration register.
///
/// # Safety
///
/// As [`read32`].
#[must_use]
pub unsafe fn read16(address: Address, offset: u8) -> u16 {
    // SAFETY: as `read32`; the half is selected from the 32-bit result.
    let value = unsafe { read32(address, offset) };
    ((value >> ((offset as u32 & 2) * 8)) & 0xffff) as u16
}

/// Reads an 8-bit configuration register.
///
/// # Safety
///
/// As [`read32`].
#[must_use]
pub unsafe fn read8(address: Address, offset: u8) -> u8 {
    // SAFETY: as `read32`.
    let value = unsafe { read32(address, offset) };
    ((value >> ((offset as u32 & 3) * 8)) & 0xff) as u8
}

/// Writes a 32-bit configuration register.
///
/// # Safety
///
/// Configuration writes change what a device does — a base address register
/// moves its registers, a command register enables or disables it. The caller
/// must know which device it is writing to and what the value means.
pub unsafe fn write32(address: Address, offset: u8, value: u32) {
    // SAFETY: as `read32`, and the caller owns the meaning of the write.
    unsafe {
        Port::<u32>::new(CONFIG_ADDRESS).write(address.selector(offset));
        Port::<u32>::new(CONFIG_DATA).write(value);
    }
}

/// Writes a 16-bit configuration register, preserving the other half.
///
/// # Safety
///
/// As [`write32`].
pub unsafe fn write16(address: Address, offset: u8, value: u16) {
    // SAFETY: read-modify-write of one register, on the bootstrap CPU during
    // boot, with nothing else driving a configuration cycle.
    unsafe {
        let shift = (offset as u32 & 2) * 8;
        let existing = read32(address, offset) & !(0xffff << shift);
        write32(address, offset, existing | (u32::from(value) << shift));
    }
}

/// Reads what a function says it is, or `None` if nothing is there.
///
/// # Safety
///
/// As [`read32`].
#[must_use]
pub unsafe fn identity(address: Address) -> Option<Identity> {
    // SAFETY: configuration reads of a function that may not exist. An absent
    // function returns all ones, which is why that is checked before anything
    // else is believed.
    unsafe {
        let vendor = read16(address, 0x00);
        if vendor == ABSENT {
            return None;
        }
        Some(Identity {
            vendor,
            device: read16(address, 0x02),
            class: read8(address, 0x0b),
            subclass: read8(address, 0x0a),
            subsystem: read16(address, 0x2e),
            multifunction: read8(address, 0x0e) & 0x80 != 0,
        })
    }
}

/// Runs `f` for every function present, stopping when it returns `false`.
///
/// # Safety
///
/// As [`read32`].
pub unsafe fn for_each(mut f: impl FnMut(Address, Identity) -> bool) {
    for bus in 0..BUSES {
        for device in 0..DEVICES {
            for function in 0..FUNCTIONS {
                let address = Address::new(bus as u8, device, function);
                // SAFETY: the caller's obligation.
                let Some(identity) = (unsafe { identity(address) }) else {
                    // Function zero absent means the device is absent; a gap
                    // in the middle of a multifunction device is allowed and
                    // is not a reason to stop looking at the rest.
                    if function == 0 {
                        break;
                    }
                    continue;
                };

                if !f(address, identity) {
                    return;
                }

                // A device that does not claim to be multifunction has one
                // function, and probing the other seven of them reads a mirror
                // of function zero on some hardware -- which looks like eight
                // identical devices.
                if function == 0 && !identity.multifunction {
                    break;
                }
            }
        }
    }
}

/// What a base address register describes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Bar {
    /// Registers in memory, at this physical address.
    Memory {
        /// Where the region starts.
        address: u64,
        /// Whether it is prefetchable, which decides how it may be mapped.
        prefetchable: bool,
    },
    /// Registers behind I/O ports, starting here.
    Ports(u16),
    /// The register is not implemented.
    Unused,
}

/// Reads base address register `index`, of six.
///
/// # Safety
///
/// As [`read32`].
#[must_use]
pub unsafe fn bar(address: Address, index: u8) -> Bar {
    if index >= 6 {
        return Bar::Unused;
    }
    let offset = 0x10 + index * 4;
    // SAFETY: the caller's obligation.
    let low = unsafe { read32(address, offset) };
    if low == 0 {
        return Bar::Unused;
    }

    if low & 1 == 1 {
        return Bar::Ports((low & 0xffff_fffc) as u16);
    }

    // Bits 2:1 say 00 for a 32-bit region and 10 for a 64-bit one, whose upper
    // half lives in the *next* register. Reading only the low half of a 64-bit
    // bar gives an address that is plausible, wrong, and usually still inside
    // RAM -- which is a mapping of somebody else's memory.
    let sixty_four = (low >> 1) & 0b11 == 0b10;
    let mut value = u64::from(low & 0xffff_fff0);
    if sixty_four && index < 5 {
        // SAFETY: the caller's obligation.
        value |= u64::from(unsafe { read32(address, offset + 4) }) << 32;
    }

    Bar::Memory {
        address: value,
        prefetchable: low & (1 << 3) != 0,
    }
}

/// One entry of a device's capability list.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Capability {
    /// What kind of capability it is.
    pub id: u8,
    /// Where it starts in configuration space.
    pub offset: u8,
}

/// Runs `f` for each capability, stopping when it returns `false`.
///
/// # Safety
///
/// As [`read32`].
pub unsafe fn for_each_capability(address: Address, mut f: impl FnMut(Capability) -> bool) {
    // SAFETY: the caller's obligation.
    unsafe {
        // Bit 4 of the status register says whether there is a list at all. A
        // device without one has whatever was left in the pointer register.
        if read16(address, 0x06) & (1 << 4) == 0 {
            return;
        }

        let mut offset = read8(address, 0x34) & 0xfc;
        for _ in 0..MAX_CAPABILITIES {
            if offset < 0x40 {
                // The first 64 bytes are the standard header; a pointer into
                // them is a device that is broken or lying, and following it
                // reads the header as a capability.
                return;
            }
            let id = read8(address, offset);
            let next = read8(address, offset + 1) & 0xfc;
            if !f(Capability { id, offset }) {
                return;
            }
            if next == 0 {
                return;
            }
            offset = next;
        }
    }
}

/// The command register's bits, as far as anything here cares.
pub mod command {
    /// The device may respond to I/O port accesses.
    pub const IO_SPACE: u16 = 1 << 0;
    /// The device may respond to memory accesses.
    pub const MEMORY_SPACE: u16 = 1 << 1;
    /// The device may act as a bus master, which is what DMA needs.
    pub const BUS_MASTER: u16 = 1 << 2;
    /// The device's legacy interrupt line is disabled.
    pub const INTERRUPT_DISABLE: u16 = 1 << 10;
}

/// Enables memory access and bus mastering for `address`.
///
/// A device that is not a bus master cannot write to memory, so its rings stay
/// empty and every request times out — which reads as a broken device rather
/// than as a missing bit.
///
/// # Safety
///
/// As [`write32`]. The caller must own this device.
pub unsafe fn enable(address: Address) {
    // SAFETY: the caller's obligation.
    unsafe {
        let existing = read16(address, 0x04);
        write16(
            address,
            0x04,
            existing | command::MEMORY_SPACE | command::BUS_MASTER | command::INTERRUPT_DISABLE,
        );
    }
}

/// Enables memory space, and deliberately not bus mastering.
///
/// A driver needs its BARs readable to find out what the device is before it
/// lets the device touch memory. Doing both at once is the ordering bug RFC
/// 0012 step 4 found: between enabling bus mastering and resetting the device,
/// it is still configured the way firmware left it, and with translation on
/// that configuration is a fault against a driver that has not started.
///
/// # Safety
///
/// As [`enable`].
pub unsafe fn enable_memory(address: Address) {
    // SAFETY: the caller's obligation.
    unsafe {
        let existing = read16(address, 0x04);
        write16(
            address,
            0x04,
            (existing | command::MEMORY_SPACE | command::INTERRUPT_DISABLE) & !command::BUS_MASTER,
        );
    }
}

/// Stops a device from doing DMA, without touching anything else.
///
/// Clearing bus mastering is the one operation that reaches every device the
/// same way, needs no BAR mapped and no driver: a device that is not a bus
/// master cannot issue a memory transaction, whatever its rings still say.
///
/// RFC 0012 needs it before translation is enabled. Firmware enumerates a disk
/// to decide whether to boot from it, and leaves it configured with physical
/// addresses from a time when nothing was translating. The instant translation
/// comes on, that configuration becomes a fault -- reported against a driver
/// that has not been written yet, on an address that means nothing to it.
///
/// # Safety
///
/// The caller must own this device, or be about to: any driver already using
/// it will find its transfers stop.
pub unsafe fn quiesce(address: Address) {
    // SAFETY: the caller's obligation.
    unsafe {
        let existing = read16(address, 0x04);
        write16(address, 0x04, existing & !command::BUS_MASTER);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_selector_is_built_from_the_parts_the_specification_names() {
        let address = Address::new(0, 3, 0);
        assert_eq!(address.selector(0), ENABLE | (3 << 11));
        assert_eq!(address.selector(0x10), ENABLE | (3 << 11) | 0x10);

        let address = Address::new(0x12, 0x1f, 0x07);
        assert_eq!(
            address.selector(0),
            ENABLE | (0x12 << 16) | (0x1f << 11) | (0x07 << 8)
        );
    }

    #[test]
    fn the_low_two_bits_of_an_offset_select_a_byte_and_not_a_register() {
        // A configuration cycle addresses a 32-bit register. An offset of 2
        // must select the same register as 0, or every 16-bit read of an odd
        // half reads the wrong register entirely.
        let address = Address::new(0, 0, 0);
        assert_eq!(address.selector(0x00), address.selector(0x02));
        assert_eq!(address.selector(0x0c), address.selector(0x0f));
        assert_ne!(address.selector(0x00), address.selector(0x04));
    }

    #[test]
    fn a_device_number_wider_than_the_field_cannot_reach_another_bus() {
        // The device and function fields are five and three bits. A value that
        // did not fit would otherwise carry into the bus number and address a
        // device on a bus the caller did not name.
        let overflowing = Address::new(0, 0xff, 0xff);
        let contained = Address::new(0, 0x1f, 0x07);
        assert_eq!(overflowing.selector(0), contained.selector(0));
    }
}
