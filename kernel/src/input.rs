// SPDX-License-Identifier: Apache-2.0
//! Console input: the path from a UART or a keyboard with a byte to a thread
//! that wants one.
//!
//! Until M6-04 the console could only write. Nothing was wired to notice an
//! inbound byte — the local APIC delivers the timer and messages between CPUs,
//! and a device interrupt needs an I/O APIC, which the kernel had never
//! programmed. `bhaskix_arch::ioapic` is the other half of this module.
//!
//! # The rings are lock-free on purpose, and there is one per source
//!
//! One producer (the interrupt handler) and one consumer (whichever thread is
//! reading). A lock would be the obvious choice and the wrong one: the handler
//! can interrupt the consumer *between* its acquire and release, and would
//! then wait for a lock held by a thread that cannot run until the handler
//! returns. Disjoint indices make that impossible rather than unlikely.
//!
//! That argument holds for *one* producer and collapses for two, which is why
//! the keyboard did not simply call this module's `push` when it arrived. See
//! [`Ring`]: each source has its own, and the consumer merges them.
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
//! bound rather than restating it. There is one console and one shell — which
//! is what lets two sources share a consumer without any arbitration beyond
//! the fixed order in [`try_read`].

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

/// One source's ring: exactly one producer, exactly one consumer, no lock.
///
/// **There is a ring per source, and that is a correctness requirement rather
/// than tidiness.** The lock-free argument above holds only while there is one
/// producer: `push` reads `head` relaxed, stores a byte, then publishes
/// `head + 1`. Two interrupt handlers doing that at once — and two claimed
/// lines may well be handled on different CPUs — both read the same head, both
/// write the same slot, and both publish the same index. One byte is lost and
/// the other is published twice.
///
/// So the keyboard did not join the serial line's ring when it arrived
/// ([RFC 0037](../../docs/rfc/0037-a-keyboard-on-real-hardware.md)); it
/// brought its own, and the *consumer* merges. Each ring keeps precisely the
/// invariant its correctness depends on, and no lock is introduced anywhere.
struct Ring {
    /// The bytes themselves.
    bytes: [AtomicU8; CAPACITY],
    /// Written by the producer only.
    head: AtomicUsize,
    /// Written by the consumer only.
    tail: AtomicUsize,
    /// Bytes that arrived.
    received: AtomicU64,
    /// Bytes dropped because the ring was full.
    dropped: AtomicU64,
}

impl Ring {
    const fn new() -> Self {
        Self {
            bytes: [const { AtomicU8::new(0) }; CAPACITY],
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
            received: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
        }
    }

    /// Adds a byte, dropping it if there is no room.
    ///
    /// Dropping the newest rather than overwriting the oldest: a full ring
    /// means nobody is reading, and in that case the first thing typed is more
    /// likely to be what someone wants than the last.
    fn push(&self, byte: u8) {
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Acquire);
        if head.wrapping_sub(tail) >= CAPACITY {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        self.bytes[head % CAPACITY].store(byte, Ordering::Relaxed);
        // Release, so the byte is visible before the index that publishes it.
        self.head.store(head.wrapping_add(1), Ordering::Release);
        self.received.fetch_add(1, Ordering::Relaxed);
    }

    /// Takes a byte if one is waiting.
    fn take(&self) -> Option<u8> {
        let tail = self.tail.load(Ordering::Relaxed);
        if self.head.load(Ordering::Acquire) == tail {
            return None;
        }
        let byte = self.bytes[tail % CAPACITY].load(Ordering::Relaxed);
        self.tail.store(tail.wrapping_add(1), Ordering::Release);
        Some(byte)
    }

    fn pending(&self) -> bool {
        self.head.load(Ordering::Acquire) != self.tail.load(Ordering::Relaxed)
    }
}

/// What the UART puts in.
static SERIAL: Ring = Ring::new();
/// What the keyboard puts in.
static KEYBOARD: Ring = Ring::new();

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

/// The notification the console waits on, once the line has been claimed.
///
/// Exposed so a *second* source can bind to the same one with its own badge,
/// which is what keeps one reader for two devices — see
/// [RFC 0037](../../docs/rfc/0037-a-keyboard-on-real-hardware.md).
#[must_use]
pub fn notification() -> Option<crate::notify::NotificationId> {
    let index = NOTIFICATION.load(Ordering::Acquire);
    if index == 0 {
        return None;
    }
    Some(crate::notify::NotificationId::from_parts(
        index - 1,
        NOTIFICATION_GENERATION.load(Ordering::Relaxed),
    ))
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
        SERIAL.push(byte);
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
    // **Three** sources share this notification now, so a wake says only that
    // *some* source has something. Servicing all of them is how it stays that
    // way: asking the badge which one it was and draining only that would leave
    // the others holding a byte until they happened to raise their own line
    // again.
    //
    // The third is a USB keyboard (RFC 0041 step 7). It costs one lock and an
    // early return on a machine that has none, which every machine did until
    // today.
    taken + crate::keyboard::service() + crate::xhci::service()
}

/// Publishes what a keyboard produced.
///
/// The keyboard's whole producer side, and the only way into its ring. Takes a
/// slice because one keypress can be several bytes: an arrow key is an escape
/// sequence, and the three bytes of one must not be interleaved with anything.
/// Nothing else can interleave with them here — this is the ring's single
/// producer, and it is called from one place.
pub fn keyboard_produced(bytes: &[u8]) {
    for byte in bytes {
        KEYBOARD.push(*byte);
    }
}

/// Takes a byte if one is waiting, from whichever source has one.
///
/// Serial first, and the order is fixed rather than fair. The two are never
/// both busy on a real machine — a person is typing at one of them — and a
/// fixed order is one fewer thing that can starve.
#[must_use]
pub fn try_read() -> Option<u8> {
    SERIAL.take().or_else(|| KEYBOARD.take())
}

/// Whether anything is waiting to be read.
#[must_use]
pub fn pending() -> bool {
    SERIAL.pending() || KEYBOARD.pending()
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
        SERIAL.received.load(Ordering::Relaxed) + KEYBOARD.received.load(Ordering::Relaxed),
        SERIAL.dropped.load(Ordering::Relaxed) + KEYBOARD.dropped.load(Ordering::Relaxed),
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
