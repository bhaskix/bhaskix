// SPDX-License-Identifier: Apache-2.0
//! The I/O APIC: where device interrupts enter the machine.
//!
//! The local APIC in each CPU handles the timer and messages between
//! processors. Everything a *device* raises — a serial port with a byte, a
//! disk with a completed request — arrives at an I/O APIC, which decides which
//! vector it becomes and which CPU receives it.
//!
//! Until this existed, Bhaskix could only be interrupted by itself. That is
//! why the console could write and not read: there was no path from a UART
//! with a byte waiting to a kernel that would notice.
//!
//! # A two-register window
//!
//! The chip exposes two memory-mapped registers: an index and a data window.
//! Reading register *n* means writing *n* to the index and then reading the
//! window, which makes every access a **read-modify-write pair that is not
//! atomic**. Two CPUs programming different inputs concurrently would
//! interleave into one CPU's index and the other's data — so all programming
//! happens on the bootstrap CPU during bring-up, and the type does not
//! implement `Sync`.
//!
//! # Redirection entries
//!
//! Each input has a 64-bit entry, addressed as two 32-bit registers. It says
//! what vector to deliver, to which CPU, with what polarity and trigger mode,
//! and whether the input is masked. Writing the high half (the destination)
//! before the low half is deliberate: the low half carries the mask bit, so
//! unmasking last means the input is never briefly enabled with a destination
//! that has not been written.

/// Offset of the index register within the window.
const REG_SELECT: usize = 0x00;
/// Offset of the data register.
const REG_WINDOW: usize = 0x10;

/// Register holding the chip's version and its highest input number.
const IOAPIC_VERSION: u32 = 0x01;
/// First redirection entry register. Entry *n* is at `REDIRECTION + 2 * n`.
const REDIRECTION: u32 = 0x10;

/// Delivery mode "fixed": deliver this exact vector to this exact CPU.
const DELIVERY_FIXED: u32 = 0b000 << 8;
/// Destination mode "physical": the destination field is an APIC ID.
const DESTINATION_PHYSICAL: u32 = 0 << 11;
/// Active low rather than active high.
const POLARITY_LOW: u32 = 1 << 13;
/// Level triggered rather than edge triggered.
const TRIGGER_LEVEL: u32 = 1 << 15;
/// The input is masked: nothing is delivered.
const MASKED: u32 = 1 << 16;

/// Lowest vector this will program.
///
/// Vectors below 32 are the CPU's own exceptions. Programming a device to
/// deliver one would make a serial byte indistinguishable from a page fault,
/// and the fault handler would run with a frame that is not a fault's.
const FIRST_LEGAL_VECTOR: u8 = 32;

/// Why programming an input failed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum IoApicError {
    /// The chip does not have that input.
    NoSuchInput,
    /// The vector belongs to the CPU's exceptions.
    ReservedVector,
}

/// A memory-mapped I/O APIC.
///
/// Deliberately not `Sync`: see the note about the index/data pair above.
pub struct IoApic {
    window: *mut u8,
    gsi_base: u32,
    inputs: u32,
}

impl IoApic {
    /// Claims the I/O APIC whose registers are mapped at `window`.
    ///
    /// # Safety
    ///
    /// `window` must be a mapping of the chip's register page — uncached, and
    /// not aliased by any other mapping being written. `gsi_base` must be the
    /// value the firmware reported for this chip; getting it wrong programs
    /// the wrong input, which is silent.
    #[must_use]
    pub unsafe fn new(window: *mut u8, gsi_base: u32) -> Self {
        let mut chip = Self {
            window,
            gsi_base,
            inputs: 0,
        };
        // Bits 16-23 of the version register hold the highest input number,
        // so the count is one more. Asking the chip is the only way to know:
        // 24 is typical and not guaranteed, and a kernel that assumed it would
        // write past the last entry on a chip with fewer.
        // SAFETY: the caller guarantees `window` maps this chip's registers.
        let version = unsafe { chip.read(IOAPIC_VERSION) };
        chip.inputs = ((version >> 16) & 0xff) + 1;
        chip
    }

    /// How many inputs this chip has.
    #[must_use]
    pub const fn inputs(&self) -> u32 {
        self.inputs
    }

    /// The first global interrupt number this chip is responsible for.
    #[must_use]
    pub const fn gsi_base(&self) -> u32 {
        self.gsi_base
    }

    /// Whether `gsi` is one of this chip's inputs.
    #[must_use]
    pub const fn owns(&self, gsi: u32) -> bool {
        gsi >= self.gsi_base && gsi - self.gsi_base < self.inputs
    }

    /// # Safety
    ///
    /// The window must be mapped, and no other CPU may be using the
    /// index/data pair concurrently.
    unsafe fn read(&self, register: u32) -> u32 {
        // SAFETY: both accesses are to the mapped register window, and the
        // index must be written before the data is read -- that is how the
        // chip is addressed, not an ordering nicety, so both are volatile and
        // neither may be reordered away.
        unsafe {
            core::ptr::write_volatile(self.window.add(REG_SELECT).cast::<u32>(), register);
            core::ptr::read_volatile(self.window.add(REG_WINDOW).cast::<u32>())
        }
    }

    /// # Safety
    ///
    /// As [`IoApic::read`].
    unsafe fn write(&mut self, register: u32, value: u32) {
        // SAFETY: as `read`; the index write must precede the data write.
        unsafe {
            core::ptr::write_volatile(self.window.add(REG_SELECT).cast::<u32>(), register);
            core::ptr::write_volatile(self.window.add(REG_WINDOW).cast::<u32>(), value);
        }
    }

    /// Routes `gsi` to `vector` on the CPU with local APIC id `destination`.
    ///
    /// The input is left unmasked, so an interrupt arriving after this returns
    /// is delivered. The caller must therefore have an IDT gate for `vector`
    /// and a handler that acknowledges it before calling this.
    ///
    /// # Errors
    ///
    /// [`IoApicError`] if this chip has no such input, or the vector is one of
    /// the CPU's exceptions.
    ///
    /// # Safety
    ///
    /// The window must be mapped, this must be the only code touching the
    /// chip, and `vector` must have a handler that issues an end-of-interrupt.
    pub unsafe fn route(
        &mut self,
        gsi: u32,
        vector: u8,
        destination: u8,
        active_low: bool,
        level: bool,
    ) -> Result<(), IoApicError> {
        if !self.owns(gsi) {
            return Err(IoApicError::NoSuchInput);
        }
        if vector < FIRST_LEGAL_VECTOR {
            return Err(IoApicError::ReservedVector);
        }

        let index = REDIRECTION + 2 * (gsi - self.gsi_base);
        let mut low = u32::from(vector) | DELIVERY_FIXED | DESTINATION_PHYSICAL;
        if active_low {
            low |= POLARITY_LOW;
        }
        if level {
            low |= TRIGGER_LEVEL;
        }
        let high = u32::from(destination) << 24;

        // Destination first, then the half carrying the mask bit. The reverse
        // order would leave the input unmasked for a few cycles with whatever
        // destination was there before -- on a machine that has just come out
        // of firmware, that is a delivery to a CPU that may not exist.
        // SAFETY: the caller's obligations, and `index` is within this chip's
        // entries because `owns` was checked above.
        unsafe {
            self.write(index + 1, high);
            self.write(index, low);
        }
        Ok(())
    }

    /// Masks `gsi`, so nothing is delivered from it.
    ///
    /// # Errors
    ///
    /// [`IoApicError::NoSuchInput`] if this chip has no such input.
    ///
    /// # Safety
    ///
    /// As [`IoApic::route`].
    pub unsafe fn mask(&mut self, gsi: u32) -> Result<(), IoApicError> {
        if !self.owns(gsi) {
            return Err(IoApicError::NoSuchInput);
        }
        let index = REDIRECTION + 2 * (gsi - self.gsi_base);
        // SAFETY: the caller's obligations; `index` is a valid entry.
        unsafe {
            let low = self.read(index);
            self.write(index, low | MASKED);
        }
        Ok(())
    }

    /// Reads back the low half of `gsi`'s redirection entry.
    ///
    /// For self-tests: the point of reading a register back is to check the
    /// chip accepted what was written, rather than trusting that a write to a
    /// memory-mapped device did anything.
    ///
    /// # Safety
    ///
    /// As [`IoApic::read`].
    #[must_use]
    pub unsafe fn redirection(&self, gsi: u32) -> Option<u32> {
        if !self.owns(gsi) {
            return None;
        }
        // SAFETY: the caller's obligations; `index` is a valid entry.
        Some(unsafe { self.read(REDIRECTION + 2 * (gsi - self.gsi_base)) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The register layout is what the tests can check without a chip: the
    /// bits a routing decision turns into, and the arithmetic that turns a
    /// global interrupt number into a register index.
    #[test]
    fn a_routing_decision_becomes_the_documented_bits() {
        let edge_high = u32::from(0x42u8) | DELIVERY_FIXED | DESTINATION_PHYSICAL;
        assert_eq!(
            edge_high, 0x42,
            "an edge-triggered active-high fixed delivery is the vector alone"
        );

        let level_low = edge_high | POLARITY_LOW | TRIGGER_LEVEL;
        assert_eq!(level_low & (1 << 13), 1 << 13);
        assert_eq!(level_low & (1 << 15), 1 << 15);
        assert_eq!(level_low & MASKED, 0, "routing must not mask");
    }

    #[test]
    fn an_input_belongs_to_the_chip_whose_range_covers_it() {
        // Not a formality: a machine with two chips has one starting at a
        // non-zero base, and an input programmed on the wrong chip is a
        // redirection entry that exists, accepts the write, and delivers
        // nothing.
        let chip = IoApic {
            window: core::ptr::null_mut(),
            gsi_base: 24,
            inputs: 8,
        };
        assert!(!chip.owns(0));
        assert!(!chip.owns(23));
        assert!(chip.owns(24));
        assert!(chip.owns(31));
        assert!(!chip.owns(32));

        // And the entry index is relative to the base, not absolute.
        assert_eq!(REDIRECTION + 2 * (24 - chip.gsi_base), REDIRECTION);
        assert_eq!(REDIRECTION + 2 * (25 - chip.gsi_base), REDIRECTION + 2);
    }

    #[test]
    fn the_input_count_comes_from_the_version_register() {
        // Bits 16-23 hold the *highest* input number, so a chip reporting 23
        // has 24 inputs. Off by one here is a kernel that never programs the
        // last input, or writes past the last entry.
        let version = 0x0017_0011u32;
        assert_eq!(((version >> 16) & 0xff) + 1, 24);
    }
}
