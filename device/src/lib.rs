// SPDX-License-Identifier: Apache-2.0
//! Registers, and the accessors that make a width a property of one.
//!
//! [RFC 0014](../../docs/rfc/0014-driver-framework.md). Two drivers in this
//! tree hand-roll the same six functions over raw addresses — `read8` through
//! `write64`, fifty-six uses in one and forty-two in the other — and the two
//! copies **disagreed about the one that mattered**. A 64-bit register written
//! as a single eight-byte store left a device holding a queue it never looked
//! at: no fault, no completion, and nothing anywhere saying why.
//!
//! # What this crate does about it
//!
//! [`Bus`] has no 64-bit access. Not "has one that is used carefully" — it
//! does not have one. A 64-bit register is two 32-bit accesses because that is
//! what the hardware defines, and the only place that can be wrong is
//! [`Mmio<u64>`], once, here.
//!
//! # And what it does about `unsafe`
//!
//! Constructing an [`Mmio`] is unsafe, because it is a promise that an address
//! is a register. Reading and writing one is not. A driver therefore spends
//! one `unsafe` per register block instead of one per access — the same
//! authority, declared where it can be checked, rather than repeated where it
//! cannot.
#![no_std]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::undocumented_unsafe_blocks
    )
)]

// For the tests only: the ring tests collect what the model recorded, which
// wants a growable buffer. Nothing outside `#[cfg(test)]` allocates.
#[cfg(test)]
extern crate alloc;

pub mod virtqueue;

use core::marker::PhantomData;

/// How a register block reaches the machine.
///
/// Deliberately without a 64-bit access. The virtio specification defines its
/// 64-bit registers as a low half and a high half, and a device model is
/// entitled to notice the difference — QEMU does. Leaving the operation out
/// means a driver cannot perform it, rather than being asked not to.
///
/// # Safety
///
/// An implementation must perform exactly the access its name describes, at
/// exactly the address given, with no tearing and no reordering the compiler
/// would be entitled to do to ordinary memory. `Volatile` is that
/// implementation for real hardware; anything else is a test double.
pub unsafe trait Bus {
    /// Reads one byte.
    ///
    /// # Safety
    ///
    /// `at` must be a readable register of this width.
    unsafe fn load8(at: usize) -> u8;
    /// Reads two bytes.
    ///
    /// # Safety
    ///
    /// As [`Bus::load8`], and `at` must be two-byte aligned.
    unsafe fn load16(at: usize) -> u16;
    /// Reads four bytes.
    ///
    /// # Safety
    ///
    /// As [`Bus::load8`], and `at` must be four-byte aligned.
    unsafe fn load32(at: usize) -> u32;
    /// Writes one byte.
    ///
    /// # Safety
    ///
    /// `at` must be a writable register of this width, and `value` one it
    /// accepts.
    unsafe fn store8(at: usize, value: u8);
    /// Writes two bytes.
    ///
    /// # Safety
    ///
    /// As [`Bus::store8`], and `at` must be two-byte aligned.
    unsafe fn store16(at: usize, value: u16);
    /// Writes four bytes.
    ///
    /// # Safety
    ///
    /// As [`Bus::store8`], and `at` must be four-byte aligned.
    unsafe fn store32(at: usize, value: u32);
}

/// The bus a real machine has: volatile loads and stores.
#[derive(Clone, Copy, Debug)]
pub struct Volatile;

// SAFETY: every method is exactly the volatile access its name describes, at
// the address given. Volatile forbids the compiler from eliding, duplicating
// or reordering these with respect to each other, which is the whole of what a
// register needs from the language.
unsafe impl Bus for Volatile {
    unsafe fn load8(at: usize) -> u8 {
        // SAFETY: the caller's obligation.
        unsafe { core::ptr::read_volatile(at as *const u8) }
    }

    unsafe fn load16(at: usize) -> u16 {
        // SAFETY: the caller's obligation.
        unsafe { core::ptr::read_volatile(at as *const u16) }
    }

    unsafe fn load32(at: usize) -> u32 {
        // SAFETY: the caller's obligation.
        unsafe { core::ptr::read_volatile(at as *const u32) }
    }

    unsafe fn store8(at: usize, value: u8) {
        // SAFETY: the caller's obligation.
        unsafe { core::ptr::write_volatile(at as *mut u8, value) }
    }

    unsafe fn store16(at: usize, value: u16) {
        // SAFETY: the caller's obligation.
        unsafe { core::ptr::write_volatile(at as *mut u16, value) }
    }

    unsafe fn store32(at: usize, value: u32) {
        // SAFETY: the caller's obligation.
        unsafe { core::ptr::write_volatile(at as *mut u32, value) }
    }
}

/// One memory-mapped register, of a width the type names.
///
/// Constructing one is the promise; using one is not. See the crate
/// documentation.
#[derive(Clone, Copy, Debug)]
pub struct Mmio<T, B: Bus = Volatile> {
    at: usize,
    width: PhantomData<T>,
    bus: PhantomData<B>,
}

impl<T, B: Bus> Mmio<T, B> {
    /// Names a register at `at`.
    ///
    /// # Safety
    ///
    /// `at` must be a register of this width, mapped for as long as this value
    /// lives, and aligned to that width. Every read and write afterwards is
    /// safe **because of this call**, which is why there is one of these per
    /// block rather than one per access.
    #[must_use]
    pub const unsafe fn new(at: usize) -> Self {
        Self {
            at,
            width: PhantomData,
            bus: PhantomData,
        }
    }

    /// Where this register is, for reporting.
    #[must_use]
    pub const fn address(&self) -> usize {
        self.at
    }
}

impl<B: Bus> Mmio<u8, B> {
    /// Reads it.
    #[must_use]
    pub fn read(&self) -> u8 {
        // SAFETY: `new`'s obligation: this address is a register of this width.
        unsafe { B::load8(self.at) }
    }

    /// Writes it.
    pub fn write(&self, value: u8) {
        // SAFETY: as `read`.
        unsafe { B::store8(self.at, value) }
    }
}

impl<B: Bus> Mmio<u16, B> {
    /// Reads it.
    #[must_use]
    pub fn read(&self) -> u16 {
        // SAFETY: as above.
        unsafe { B::load16(self.at) }
    }

    /// Writes it.
    pub fn write(&self, value: u16) {
        // SAFETY: as above.
        unsafe { B::store16(self.at, value) }
    }
}

impl<B: Bus> Mmio<u32, B> {
    /// Reads it.
    #[must_use]
    pub fn read(&self) -> u32 {
        // SAFETY: as above.
        unsafe { B::load32(self.at) }
    }

    /// Writes it.
    pub fn write(&self, value: u32) {
        // SAFETY: as above.
        unsafe { B::store32(self.at, value) }
    }
}

impl<B: Bus> Mmio<u64, B> {
    /// Reads it, low half first.
    ///
    /// Two 32-bit reads because [`Bus`] has no other kind. A register whose
    /// halves can change between them needs re-reading until they agree, and
    /// that is the *register's* problem to document — this is the access, not
    /// a consistency protocol.
    #[must_use]
    pub fn read(&self) -> u64 {
        // SAFETY: `new`'s obligation, and the halves are four-byte aligned
        // because the register is eight-byte aligned.
        unsafe {
            let low = u64::from(B::load32(self.at));
            let high = u64::from(B::load32(self.at + 4));
            low | (high << 32)
        }
    }

    /// Writes it, low half first.
    ///
    /// **This is the bug the crate exists for.** A single eight-byte store to
    /// a 64-bit virtio register leaves the device with a queue it never looks
    /// at: the specification defines the register as two halves, and a device
    /// model is entitled to notice. Written once, here, where it can be wrong
    /// only once.
    pub fn write(&self, value: u64) {
        // SAFETY: as `read`.
        unsafe {
            B::store32(self.at, value as u32);
            B::store32(self.at + 4, (value >> 32) as u32);
        }
    }
}

/// Checks a register block's layout, at compile time.
///
/// Fields must not overlap and must not leave the block. Called from a `const`
/// item by [`register_block!`], so a bad layout is a build failure with no
/// runtime cost — the assertion is not in the binary, it is in the decision to
/// produce one.
///
/// # Panics
///
/// At compile time, if two fields overlap or one leaves the block.
// A `panic!` in a const context is a compile error rather than a fault at run
// time, which is the opposite of what the workspace's ban is there to prevent.
#[allow(clippy::panic)]
pub const fn check_layout(fields: &[(usize, usize)], length: usize) {
    let mut i = 0;
    while i < fields.len() {
        let (offset, size) = fields[i];
        if offset + size > length {
            panic!("a register leaves the block");
        }
        let mut j = i + 1;
        while j < fields.len() {
            let (other, other_size) = fields[j];
            if offset < other + other_size && other < offset + size {
                panic!("two registers overlap");
            }
            j += 1;
        }
        i += 1;
    }
}

/// Declares a block of registers: their offsets, their widths, and nothing else.
///
/// Offsets are written once. Today the same virtio constants exist in three
/// places with nothing checking they agree, and a register's width lives at
/// every call site instead of on the register.
///
/// The block's length is required, because "this field leaves the block" is
/// only a question a block with a size can answer.
///
/// ```
/// # use bhaskix_device::register_block;
/// register_block! {
///     /// The virtio 1.0 common configuration structure.
///     pub struct CommonCfg(0x1000) {
///         0x00 => device_feature_select: u32,
///         0x14 => device_status: u8,
///         0x20 => queue_desc: u64,
///     }
/// }
/// ```
#[macro_export]
macro_rules! register_block {
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident ($length:expr) {
            $($offset:expr => $field:ident : $type:ty),* $(,)?
        }
    ) => {
        $(#[$meta])*
        $vis struct $name<B: $crate::Bus = $crate::Volatile> {
            $(
                #[doc = concat!("Register at offset ", stringify!($offset), ".")]
                pub $field: $crate::Mmio<$type, B>
            ),*
        }

        impl<B: $crate::Bus> $name<B> {
            /// How long the block is, in bytes.
            pub const LENGTH: usize = $length;

            /// Names the block at `base`.
            ///
            /// # Safety
            ///
            /// `base` must be the start of this block of registers, mapped for
            /// as long as the value lives. Every access afterwards is safe
            /// because of this call.
            #[must_use]
            $vis const unsafe fn new(base: usize) -> Self {
                Self {
                    // SAFETY: the caller's obligation, plus the layout check
                    // below: each offset is inside the block and no two
                    // registers overlap.
                    $($field: unsafe { $crate::Mmio::new(base + $offset) }),*
                }
            }
        }

        // The deliverable. A layout that overlaps or overruns is a build
        // failure, not a comment and not a runtime assertion that ships.
        const _: () = $crate::check_layout(
            &[$(($offset, ::core::mem::size_of::<$type>())),*],
            $length,
        );
    };
}

/// A device to test a driver against, without a machine.
///
/// [`Bus`] dispatches statically, which keeps [`Mmio`] zero-sized and is why
/// every access goes through associated functions rather than through a
/// handle. The consequence is that a test double must be a **static**: there
/// is no `self` to carry one. So this module is one device, and tests take
/// [`exclusive`] before touching it.
///
/// It is a *device* and not a byte array. A register file alone would accept
/// anything written to it and answer with what was written, which is the one
/// behaviour a real device does not have: real devices refuse. The refusals
/// are what a driver gets wrong — a feature set the device will not take, a
/// vector it cannot give — and a model that could not refuse would test the
/// happy path and nothing else.
pub mod testing {
    use core::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};

    use super::Bus;

    /// How many bytes of registers the model has.
    pub const SIZE: usize = 256;

    /// How many accesses it remembers.
    pub const LOGGED: usize = 64;

    #[expect(
        clippy::declare_interior_mutable_const,
        reason = "the initialiser for an array of atomics, which is the one \
                  place this pattern is not a mistake"
    )]
    const ZERO: AtomicU8 = AtomicU8::new(0);

    static REGISTERS: [AtomicU8; SIZE] = [ZERO; SIZE];

    /// `(write, width, offset, value)`, flattened so the log needs no lock.
    static LOG_WRITE: [AtomicBool; LOGGED] = [const { AtomicBool::new(false) }; LOGGED];
    static LOG_WIDTH: [AtomicUsize; LOGGED] = [const { AtomicUsize::new(0) }; LOGGED];
    static LOG_AT: [AtomicUsize; LOGGED] = [const { AtomicUsize::new(0) }; LOGGED];
    static LOG_VALUE: [AtomicUsize; LOGGED] = [const { AtomicUsize::new(0) }; LOGGED];
    static LOGGED_COUNT: AtomicUsize = AtomicUsize::new(0);

    static BUSY: AtomicBool = AtomicBool::new(false);

    /// What the model refuses.
    static REFUSE_FEATURES: AtomicBool = AtomicBool::new(false);
    static REFUSE_VECTOR: AtomicBool = AtomicBool::new(false);

    /// Offsets the model gives meaning to. They are the virtio 1.0 common
    /// configuration's, and they have to agree with the block a driver
    /// declares — the tests construct that block over this model, so a
    /// disagreement shows up as a driver reading the wrong thing.
    const DEVICE_STATUS: usize = 0x14;
    const QUEUE_MSIX_VECTOR: usize = 0x1a;

    /// The bit a device clears to refuse a feature set.
    const FEATURES_OK: u8 = 8;

    /// Held for the duration of a test. Released on drop.
    pub struct Exclusive;

    impl Drop for Exclusive {
        fn drop(&mut self) {
            BUSY.store(false, Ordering::Release);
        }
    }

    /// Takes the model, resets it, and holds it until the guard is dropped.
    ///
    /// A lock and not a comment. A test module in this tree once said "one
    /// test, because the slots are a global" and then acquired a second one
    /// that raced the first.
    #[must_use]
    pub fn exclusive() -> Exclusive {
        while BUSY
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            core::hint::spin_loop();
        }
        for register in &REGISTERS {
            register.store(0, Ordering::Relaxed);
        }
        LOGGED_COUNT.store(0, Ordering::Relaxed);
        REFUSE_FEATURES.store(false, Ordering::Relaxed);
        REFUSE_VECTOR.store(false, Ordering::Relaxed);
        Exclusive
    }

    /// Makes the model refuse whatever feature set it is offered.
    pub fn refuse_features() {
        REFUSE_FEATURES.store(true, Ordering::Relaxed);
    }

    /// Makes the model refuse to give out an MSI-X vector.
    ///
    /// A real device reports `0xffff` — no vector — and a driver that does not
    /// read the register back waits for an interrupt that will never arrive.
    pub fn refuse_vector() {
        REFUSE_VECTOR.store(true, Ordering::Relaxed);
    }

    /// Puts a value in the register file, as a device would offer it.
    pub fn offer(at: usize, bytes: &[u8]) {
        for (index, byte) in bytes.iter().enumerate() {
            REGISTERS[at + index].store(*byte, Ordering::Relaxed);
        }
    }

    /// How many accesses have been recorded.
    #[must_use]
    pub fn accesses() -> usize {
        LOGGED_COUNT.load(Ordering::Relaxed).min(LOGGED)
    }

    /// One recorded access, as `(write, width, offset, value)`.
    #[must_use]
    pub fn access(index: usize) -> (bool, usize, usize, u64) {
        (
            LOG_WRITE[index].load(Ordering::Relaxed),
            LOG_WIDTH[index].load(Ordering::Relaxed),
            LOG_AT[index].load(Ordering::Relaxed),
            LOG_VALUE[index].load(Ordering::Relaxed) as u64,
        )
    }

    fn record(write: bool, width: usize, at: usize, value: u64) {
        let index = LOGGED_COUNT.fetch_add(1, Ordering::Relaxed);
        if index < LOGGED {
            LOG_WRITE[index].store(write, Ordering::Relaxed);
            LOG_WIDTH[index].store(width, Ordering::Relaxed);
            LOG_AT[index].store(at, Ordering::Relaxed);
            LOG_VALUE[index].store(value as usize, Ordering::Relaxed);
        }
    }

    /// What the device does about a write, beyond remembering it.
    fn react(at: usize, value: u64) {
        if at == DEVICE_STATUS && REFUSE_FEATURES.load(Ordering::Relaxed) {
            // Refusing is clearing the bit, which is the only way a device
            // has to say no to a feature set.
            REGISTERS[DEVICE_STATUS].store((value as u8) & !FEATURES_OK, Ordering::Relaxed);
        }
        if at == QUEUE_MSIX_VECTOR && REFUSE_VECTOR.load(Ordering::Relaxed) {
            REGISTERS[QUEUE_MSIX_VECTOR].store(0xff, Ordering::Relaxed);
            REGISTERS[QUEUE_MSIX_VECTOR + 1].store(0xff, Ordering::Relaxed);
        }
    }

    /// The model, as a bus a register block can be built over.
    #[derive(Clone, Copy, Debug)]
    pub struct Model;

    // SAFETY: not a real bus. Every method performs its access against the
    // register file at the width its name describes, which is what the tests
    // using it are about.
    unsafe impl Bus for Model {
        unsafe fn load8(at: usize) -> u8 {
            let value = REGISTERS[at].load(Ordering::Relaxed);
            record(false, 1, at, u64::from(value));
            value
        }

        unsafe fn load16(at: usize) -> u16 {
            let value = u16::from_le_bytes([
                REGISTERS[at].load(Ordering::Relaxed),
                REGISTERS[at + 1].load(Ordering::Relaxed),
            ]);
            record(false, 2, at, u64::from(value));
            value
        }

        unsafe fn load32(at: usize) -> u32 {
            let value = u32::from_le_bytes([
                REGISTERS[at].load(Ordering::Relaxed),
                REGISTERS[at + 1].load(Ordering::Relaxed),
                REGISTERS[at + 2].load(Ordering::Relaxed),
                REGISTERS[at + 3].load(Ordering::Relaxed),
            ]);
            record(false, 4, at, u64::from(value));
            value
        }

        unsafe fn store8(at: usize, value: u8) {
            REGISTERS[at].store(value, Ordering::Relaxed);
            record(true, 1, at, u64::from(value));
            react(at, u64::from(value));
        }

        unsafe fn store16(at: usize, value: u16) {
            for (index, byte) in value.to_le_bytes().iter().enumerate() {
                REGISTERS[at + index].store(*byte, Ordering::Relaxed);
            }
            record(true, 2, at, u64::from(value));
            react(at, u64::from(value));
        }

        unsafe fn store32(at: usize, value: u32) {
            for (index, byte) in value.to_le_bytes().iter().enumerate() {
                REGISTERS[at + index].store(*byte, Ordering::Relaxed);
            }
            record(true, 4, at, u64::from(value));
            react(at, u64::from(value));
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::sync::{Mutex, MutexGuard, PoisonError};
    use std::vec::Vec;

    use super::Bus;

    /// One access a driver made, as the bus saw it.
    ///
    /// The *width* is in here, which is the whole reason this exists: a byte
    /// buffer cannot tell one eight-byte store from two four-byte ones, and
    /// that difference is what a device notices.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    struct Access {
        write: bool,
        width: usize,
        at: usize,
        value: u64,
    }

    /// What the fake bus has been asked to do, in order, and the bytes behind
    /// it so reads answer something.
    static LOG: Mutex<Vec<Access>> = Mutex::new(Vec::new());
    static MEMORY: Mutex<[u8; 64]> = Mutex::new([0; 64]);

    fn held<T>(lock: &Mutex<T>) -> MutexGuard<'_, T> {
        lock.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Serialises the tests, which share one fake bus.
    ///
    /// `notify`'s test module said "one test, because the slots are a global"
    /// and then acquired a second one that raced the first. A comment asking
    /// people to keep to one test survives exactly until somebody adds a
    /// second, so this is a lock rather than a request.
    static ALONE: Mutex<()> = Mutex::new(());

    /// A bus that records every access and answers reads from a small buffer.
    struct Fake;

    // SAFETY: not a real bus. It performs each access against a buffer with
    // the width its name describes, which is what the tests below are about.
    unsafe impl Bus for Fake {
        unsafe fn load8(at: usize) -> u8 {
            let value = held(&MEMORY)[at];
            record(false, 1, at, u64::from(value));
            value
        }

        unsafe fn load16(at: usize) -> u16 {
            let memory = held(&MEMORY);
            let value = u16::from_le_bytes([memory[at], memory[at + 1]]);
            drop(memory);
            record(false, 2, at, u64::from(value));
            value
        }

        unsafe fn load32(at: usize) -> u32 {
            let memory = held(&MEMORY);
            let mut bytes = [0u8; 4];
            bytes.copy_from_slice(&memory[at..at + 4]);
            drop(memory);
            let value = u32::from_le_bytes(bytes);
            record(false, 4, at, u64::from(value));
            value
        }

        unsafe fn store8(at: usize, value: u8) {
            held(&MEMORY)[at] = value;
            record(true, 1, at, u64::from(value));
        }

        unsafe fn store16(at: usize, value: u16) {
            held(&MEMORY)[at..at + 2].copy_from_slice(&value.to_le_bytes());
            record(true, 2, at, u64::from(value));
        }

        unsafe fn store32(at: usize, value: u32) {
            held(&MEMORY)[at..at + 4].copy_from_slice(&value.to_le_bytes());
            record(true, 4, at, u64::from(value));
        }
    }

    fn record(write: bool, width: usize, at: usize, value: u64) {
        held(&LOG).push(Access {
            write,
            width,
            at,
            value,
        });
    }

    fn fresh() -> MutexGuard<'static, ()> {
        let alone = held(&ALONE);
        held(&LOG).clear();
        *held(&MEMORY) = [0; 64];
        alone
    }

    register_block! {
        /// A stand-in for the virtio common configuration, at the real offsets.
        struct Block(0x40) {
            0x00 => feature_select: u32,
            0x12 => queues: u16,
            0x14 => status: u8,
            0x20 => queue_desc: u64,
        }
    }

    #[test]
    fn a_64_bit_register_is_written_as_two_32_bit_stores_low_half_first() {
        // The test this crate exists for. A single eight-byte store to
        // `queue_desc` left a device holding a queue it never looked at, and
        // no byte buffer could have told the difference -- the width and the
        // order are the evidence, so the fake bus records both.
        let _alone = fresh();
        // SAFETY: `Block` here names offsets into the fake bus's buffer.
        let block = unsafe { Block::<Fake>::new(0) };

        block.queue_desc.write(0x1122_3344_5566_7788);

        let log = held(&LOG).clone();
        assert_eq!(
            log,
            [
                Access {
                    write: true,
                    width: 4,
                    at: 0x20,
                    value: 0x5566_7788
                },
                Access {
                    write: true,
                    width: 4,
                    at: 0x24,
                    value: 0x1122_3344
                },
            ],
            "two 32-bit stores, low half first"
        );
    }

    #[test]
    fn a_64_bit_register_reads_back_what_was_written() {
        let _alone = fresh();
        // SAFETY: as above.
        let block = unsafe { Block::<Fake>::new(0) };

        block.queue_desc.write(0x0123_4567_89ab_cdef);
        assert_eq!(block.queue_desc.read(), 0x0123_4567_89ab_cdef);

        // And the read is two loads as well, because there is no other kind.
        let reads: Vec<usize> = held(&LOG)
            .iter()
            .filter(|access| !access.write)
            .map(|access| access.width)
            .collect();
        assert_eq!(reads, [4, 4]);
    }

    #[test]
    fn a_register_is_accessed_at_its_own_width_and_nowhere_else() {
        // A width belongs to the register. This is what three copies of
        // hand-rolled `read8`/`read16`/`read32` could not promise: nothing
        // stopped a caller reading a one-byte status register as four.
        let _alone = fresh();
        // SAFETY: as above.
        let block = unsafe { Block::<Fake>::new(0) };

        block.status.write(0x0f);
        block.queues.write(1);
        block.feature_select.write(0);

        let log = held(&LOG).clone();
        assert_eq!(
            log.iter().map(|a| (a.at, a.width)).collect::<Vec<_>>(),
            [(0x14, 1), (0x12, 2), (0x00, 4)]
        );
    }

    #[test]
    fn a_block_names_registers_relative_to_its_base() {
        let _alone = fresh();
        // SAFETY: as above; a base of 16 keeps every field inside the buffer.
        let block = unsafe { Block::<Fake>::new(16) };
        assert_eq!(block.status.address(), 16 + 0x14);
        assert_eq!(Block::<Fake>::LENGTH, 0x40);
    }
}
