// SPDX-License-Identifier: Apache-2.0
//! Legacy I/O port access.
//!
//! Wraps the `in`/`out` instruction family in a type that carries the access
//! width, so that a driver cannot accidentally issue an 8-bit write to a
//! 16-bit register — a mistake that produces device-specific misbehaviour
//! rather than a clean failure.
//!
//! This is the port-I/O counterpart of the `Mmio<T>` wrapper described in
//! `docs/driver-model.md` §3, and exists for the same reason: one reviewed,
//! tested abstraction is worth more than many individually-correct `unsafe`
//! blocks.
//!
//! Port I/O is legacy. New drivers should use MMIO. This exists because the
//! 16550 UART is the kernel's debugging lifeline and predates MMIO entirely.

use core::marker::PhantomData;

/// A value that can be transferred over a legacy I/O port.
///
/// # Safety
///
/// Implementors must be one of `u8`, `u16`, or `u32`, and must implement
/// [`PortValue::read`] and [`PortValue::write`] using the `in`/`out`
/// instruction of exactly that width.
pub unsafe trait PortValue: Copy {
    /// Reads a value of this width from `port`.
    ///
    /// # Safety
    ///
    /// The caller must ensure `port` is a valid I/O port for this access
    /// width, and that reading it has no side effect the caller has not
    /// accounted for. Reads from device ports are frequently destructive.
    unsafe fn read(port: u16) -> Self;

    /// Writes a value of this width to `port`.
    ///
    /// # Safety
    ///
    /// The caller must ensure `port` is a valid I/O port for this access
    /// width and that the write is meaningful for the device behind it.
    /// Writing to an arbitrary port can hang or reset the machine.
    unsafe fn write(port: u16, value: Self);
}

// SAFETY: each impl below uses the `in`/`out` instruction whose operand width
// matches the Rust type exactly (`al`/`ax`/`eax`), which is what the trait
// contract requires. `nomem` is correct because port I/O does not touch normal
// memory, and `nostack` because no instruction here uses the stack. `preserves_flags`
// is deliberately NOT set: `in`/`out` do not modify flags, but claiming so buys
// nothing here and the conservative choice costs nothing.
unsafe impl PortValue for u8 {
    unsafe fn read(port: u16) -> Self {
        let value: u8;
        // SAFETY: `inb` with a 16-bit port in `dx` and an 8-bit destination in
        // `al` is the correct encoding for a byte-wide port read. The caller
        // guarantees `port` is valid per the trait contract.
        unsafe {
            core::arch::asm!("in al, dx", out("al") value, in("dx") port,
                             options(nomem, nostack));
        }
        value
    }

    unsafe fn write(port: u16, value: Self) {
        // SAFETY: `outb` with a 16-bit port in `dx` and an 8-bit source in
        // `al`. The caller guarantees `port` is valid per the trait contract.
        unsafe {
            core::arch::asm!("out dx, al", in("dx") port, in("al") value,
                             options(nomem, nostack));
        }
    }
}

// SAFETY: as above, with 16-bit operands in `ax`.
unsafe impl PortValue for u16 {
    unsafe fn read(port: u16) -> Self {
        let value: u16;
        // SAFETY: 16-bit port read; see the trait contract for the caller's
        // obligations regarding `port`.
        unsafe {
            core::arch::asm!("in ax, dx", out("ax") value, in("dx") port,
                             options(nomem, nostack));
        }
        value
    }

    unsafe fn write(port: u16, value: Self) {
        // SAFETY: 16-bit port write; see the trait contract.
        unsafe {
            core::arch::asm!("out dx, ax", in("dx") port, in("ax") value,
                             options(nomem, nostack));
        }
    }
}

// SAFETY: as above, with 32-bit operands in `eax`.
unsafe impl PortValue for u32 {
    unsafe fn read(port: u16) -> Self {
        let value: u32;
        // SAFETY: 32-bit port read; see the trait contract.
        unsafe {
            core::arch::asm!("in eax, dx", out("eax") value, in("dx") port,
                             options(nomem, nostack));
        }
        value
    }

    unsafe fn write(port: u16, value: Self) {
        // SAFETY: 32-bit port write; see the trait contract.
        unsafe {
            core::arch::asm!("out dx, eax", in("dx") port, in("eax") value,
                             options(nomem, nostack));
        }
    }
}

/// A single legacy I/O port of a fixed access width.
#[derive(Clone, Copy, Debug)]
pub struct Port<T: PortValue> {
    number: u16,
    _width: PhantomData<T>,
}

impl<T: PortValue> Port<T> {
    /// Names the I/O port at `number`.
    ///
    /// Constructing a `Port` grants no authority by itself and is therefore
    /// safe; the `unsafe` is on the accesses, which is where the risk is.
    /// Once Bhaskix has a capability system (M5), constructing one will require
    /// an `IoPortCapability` and this will stop being freely available.
    #[must_use]
    pub const fn new(number: u16) -> Self {
        Self {
            number,
            _width: PhantomData,
        }
    }

    /// Reads from the port.
    ///
    /// # Safety
    ///
    /// The caller must ensure this port belongs to a device they control and
    /// that reading it is not destructive in a way they have not accounted
    /// for.
    pub unsafe fn read(&self) -> T {
        // SAFETY: delegated to the caller's obligation, which is identical to
        // `PortValue::read`'s contract.
        unsafe { T::read(self.number) }
    }

    /// Writes to the port.
    ///
    /// # Safety
    ///
    /// The caller must ensure this port belongs to a device they control.
    /// Writing to an arbitrary port can hang or reset the machine.
    pub unsafe fn write(&self, value: T) {
        // SAFETY: delegated to the caller's obligation, which is identical to
        // `PortValue::write`'s contract.
        unsafe { T::write(self.number, value) }
    }
}
