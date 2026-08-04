// SPDX-License-Identifier: Apache-2.0
//! Console input: the path from a UART with a byte to a thread that wants one.
//!
//! Until M6-04 the console could only write. Nothing was wired to notice an
//! inbound byte — the local APIC delivers the timer and messages between CPUs,
//! and a device interrupt needs an I/O APIC, which the kernel had never
//! programmed. `bhaskix_arch::ioapic` is the other half of this module.
//!
//! # The ring is lock-free on purpose
//!
//! One producer (the interrupt handler) and one consumer (whichever thread is
//! reading). A lock would be the obvious choice and the wrong one: the handler
//! can interrupt the consumer *between* its acquire and release, and would
//! then wait for a lock held by a thread that cannot run until the handler
//! returns. Disjoint indices make that impossible rather than unlikely.
//!
//! # The first client of RFC 0011, and it drains before it acknowledges
//!
//! Since M6-07 this module owns nothing of the interrupt path. It claims the
//! serial line through `irq::claim`, binds a notification to it, and waits.
//! The handler masks the source and signals; **this module drains the UART and
//! then acknowledges**, which is the rule `docs/driver-model.md` §2 states for
//! every driver: an edge raised while the source is masked is lost, so read
//! the device empty *before* saying you are finished with it.
//!
//! What that replaced was a hand-written version of the same thing — a reader
//! recorded in an atomic, woken from a handler that also drained the FIFO.
//! It worked, and it was a special case of a general object that did not exist
//! yet. It does now.
//!
//! # One reader
//!
//! A notification takes one waiter and refuses a second, so this inherits that
//! bound rather than restating it. There is one console and one shell.

use core::sync::atomic::{AtomicU8, AtomicU16, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use bhaskix_arch::SerialPort;

// There is no `SERIAL_VECTOR` any more, and its absence is the point of
// RFC 0011 step 1: the vector is allocated at claim time and this module never
// learns a number it did not ask for. What it keeps is the *source* -- which
// line the console is on -- because that is a fact about the machine rather
// than a fact about this kernel's bookkeeping.

/// The legacy ISA interrupt a PC's first serial port raises.
pub const SERIAL_IRQ: u8 = 4;

/// Bytes the ring holds.
///
/// A power of two so the index arithmetic is a mask. 256 is far more than a
/// human types between reads and more than the UART's own sixteen-byte FIFO,
/// so an overrun means the reader has stopped, not that it was slow.
const CAPACITY: usize = 256;

/// The bytes themselves.
static RING: [AtomicU8; CAPACITY] = [const { AtomicU8::new(0) }; CAPACITY];
/// Written by the producer only.
static HEAD: AtomicUsize = AtomicUsize::new(0);
/// Written by the consumer only.
static TAIL: AtomicUsize = AtomicUsize::new(0);

/// Bytes that arrived.
static RECEIVED: AtomicU64 = AtomicU64::new(0);
/// Bytes dropped because the ring was full.
static DROPPED: AtomicU64 = AtomicU64::new(0);
/// Times the handler ran.
static INTERRUPTS: AtomicU64 = AtomicU64::new(0);

/// I/O port of the UART the handler drains, or zero if there is none.
///
/// A port number rather than a `SerialPort`, so the handler can read it with
/// one atomic load and no lock. The type is a thin wrapper over exactly this
/// number, so nothing is lost by rebuilding it per interrupt.
static PORT_BASE: AtomicU16 = AtomicU16::new(0);

/// Names the port console input arrives on, claims its interrupt, and binds a
/// notification to it.
///
/// # Errors
///
/// Returns `Err` if the line could not be claimed or a notification created.
/// Either is survivable — the kernel boots without console input and says so.
///
/// # Safety
///
/// Must be called once, during boot, with the base of a UART whose `init`
/// succeeded.
pub unsafe fn install(
    base: u16,
    apic_id: u32,
    rsdp: Option<bhaskix_boot::PhysAddr>,
    hhdm: u64,
) -> Result<u8, &'static str> {
    let notification = crate::notify::create().map_err(|_| "no notification for the console")?;

    // SAFETY: `trap` dispatches claimed vectors to `irq::on_interrupt`, which
    // acknowledges the local APIC.
    let handler = unsafe {
        crate::irq::claim(
            crate::irq::Source::Line {
                gsi: gsi_for_serial(rsdp, hhdm),
            },
            "serial",
            apic_id,
            rsdp,
            hhdm,
        )
    }
    .map_err(|_| "the serial line could not be claimed")?;

    crate::irq::bind(handler, notification, BADGE)
        .map_err(|_| "the notification would not bind")?;

    let vector = crate::irq::vector_of(handler).unwrap_or(0);
    NOTIFICATION.store(notification.index() + 1, Ordering::Release);
    NOTIFICATION_GENERATION.store(notification.generation(), Ordering::Relaxed);
    HANDLER.store(handler_to_raw(handler), Ordering::Release);
    PORT_BASE.store(base, Ordering::Release);

    // Last: from here the UART raises its line, so everything that services it
    // must already be in place.
    // SAFETY: the caller guarantees the port is initialised.
    unsafe { SerialPort::new(base).enable_receive_interrupt() };
    Ok(vector)
}

/// The global interrupt the serial line arrives on.
///
/// Translated through the firmware's overrides once, here, so that the claim
/// records the number the chip actually uses. Everything downstream — masking,
/// acknowledging — works in that number and must not translate again.
fn gsi_for_serial(rsdp: Option<bhaskix_boot::PhysAddr>, hhdm: u64) -> u32 {
    crate::irq::isa_to_gsi(rsdp, hhdm, SERIAL_IRQ)
}

/// The badge the serial line signals with. One bit, because there is one
/// source; a second device on the same notification would take another.
const BADGE: u64 = 1 << 0;

/// The bound notification, as index-plus-one and generation.
static NOTIFICATION: AtomicU32 = AtomicU32::new(0);
static NOTIFICATION_GENERATION: AtomicU32 = AtomicU32::new(0);
/// The claimed handler, packed so it can live in an atomic.
static HANDLER: AtomicU64 = AtomicU64::new(u64::MAX);

fn handler_to_raw(handler: crate::irq::HandlerId) -> u64 {
    crate::irq::handler_raw(handler)
}

/// Drains the UART into the ring. Returns how many bytes it took.
///
/// Called by the reader after a wake, never from the interrupt handler — the
/// handler does one thing, and this is the other thing.
fn drain() -> usize {
    let base = PORT_BASE.load(Ordering::Acquire);
    if base == 0 {
        return 0;
    }
    let port = SerialPort::new(base);
    let mut taken = 0;
    // SAFETY: `install` stored a port whose `init` succeeded, and reading is
    // the documented way to clear the condition that raised the interrupt.
    while let Some(byte) = unsafe { port.read_byte() } {
        push(byte);
        taken += 1;
    }
    taken
}

/// Drains and acknowledges, in that order.
///
/// The order is the rule: an edge raised while the source is masked is lost,
/// so the device must be empty before it is unmasked. Reversing these two
/// lines is the bug `docs/driver-model.md` §2 warns about, and it presents as
/// a console that stops responding under fast typing and nothing at all in
/// testing.
pub fn service() -> usize {
    let taken = drain();
    let raw = HANDLER.load(Ordering::Acquire);
    if raw != u64::MAX {
        let _ = crate::irq::acknowledge(crate::irq::handler_from_raw(raw));
    }
    taken
}

/// Adds a byte, dropping it if there is no room.
///
/// Dropping the newest rather than overwriting the oldest: a full ring means
/// nobody is reading, and in that case the first thing typed is more likely to
/// be what someone wants than the last.
fn push(byte: u8) {
    let head = HEAD.load(Ordering::Relaxed);
    let tail = TAIL.load(Ordering::Acquire);
    if head.wrapping_sub(tail) >= CAPACITY {
        DROPPED.fetch_add(1, Ordering::Relaxed);
        return;
    }
    RING[head % CAPACITY].store(byte, Ordering::Relaxed);
    // Release, so the byte is visible before the index that publishes it.
    HEAD.store(head.wrapping_add(1), Ordering::Release);
    RECEIVED.fetch_add(1, Ordering::Relaxed);
}

/// Takes a byte if one is waiting.
#[must_use]
pub fn try_read() -> Option<u8> {
    let tail = TAIL.load(Ordering::Relaxed);
    if HEAD.load(Ordering::Acquire) == tail {
        return None;
    }
    let byte = RING[tail % CAPACITY].load(Ordering::Relaxed);
    TAIL.store(tail.wrapping_add(1), Ordering::Release);
    Some(byte)
}

/// Whether anything is waiting to be read.
#[must_use]
pub fn pending() -> bool {
    HEAD.load(Ordering::Acquire) != TAIL.load(Ordering::Relaxed)
}

/// Waits for a byte.
///
/// Blocks on the notification the serial line is bound to. On waking it drains
/// the UART and acknowledges the source, then takes a byte from the ring.
pub fn read() -> u8 {
    loop {
        if let Some(byte) = try_read() {
            return byte;
        }

        let index = NOTIFICATION.load(Ordering::Acquire);
        if index == 0 {
            // No interrupt path. Nothing will ever arrive, and spinning would
            // hold a CPU for ever -- so drain by hand and yield, which is what
            // a machine with no I/O APIC gets.
            if service() == 0 {
                crate::sched::yield_now();
            }
            continue;
        }

        let id = crate::notify::NotificationId::from_parts(
            index - 1,
            NOTIFICATION_GENERATION.load(Ordering::Relaxed),
        );
        let _ = crate::notify::wait(id);
        INTERRUPTS.fetch_add(1, Ordering::Relaxed);
        service();
    }
}

/// How much has arrived, been dropped, and how many interrupts delivered it.
#[must_use]
pub fn statistics() -> (u64, u64, u64) {
    (
        RECEIVED.load(Ordering::Relaxed),
        DROPPED.load(Ordering::Relaxed),
        INTERRUPTS.load(Ordering::Relaxed),
    )
}

/// Line editing, shared with the user-mode shell.
///
/// Re-exported rather than defined here since M6-05: both shells edit lines,
/// and two implementations of backspace would disagree the first time either
/// was touched. The definition lives in `bhaskix_abi`, which is compiled into
/// the kernel and into unprivileged programs alike.
pub use bhaskix_abi::{Edit, LineEditor, MAX_LINE};
