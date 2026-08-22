// SPDX-License-Identifier: Apache-2.0
//! 16550-family UART driver.
//!
//! The first driver in Bhaskix, and the most important one during bring-up: it
//! is the only output path that works before memory management, before the
//! framebuffer, and inside the panic handler. Everything else can be debugged
//! through it; it has to be debugged by inspection.
//!
//! It is therefore written to be defensive rather than fast:
//!
//! - Every busy-wait is bounded. A missing or wedged UART degrades to dropped
//!   output, never to a hung boot. Losing the debug channel is bad; hanging
//!   before the first line of output with no indication why is worse.
//! - Initialisation runs a loopback self-test, so `init` reports whether a
//!   UART is actually there instead of writing into a void.
//! - No allocation, no locking, no interrupts. It works in any context,
//!   including a panic with a corrupt heap.

use core::sync::atomic::AtomicU64;

use crate::port::Port;

/// Standard I/O port of the first serial controller on a PC.
pub const COM1: u16 = 0x3f8;

/// Standard I/O port of the second serial controller.
pub const COM2: u16 = 0x2f8;

// Register offsets from the port base. Meaning depends on the DLAB bit in the
// line control register, which is why the divisor registers alias 0 and 1.
const REG_DATA: u16 = 0; // receive/transmit buffer  (DLAB = 0)
const REG_INT_ENABLE: u16 = 1; // interrupt enable         (DLAB = 0)
const REG_DIVISOR_LO: u16 = 0; // divisor latch low        (DLAB = 1)
const REG_DIVISOR_HI: u16 = 1; // divisor latch high       (DLAB = 1)
const REG_FIFO_CTRL: u16 = 2;
const REG_LINE_CTRL: u16 = 3;
const REG_MODEM_CTRL: u16 = 4;
const REG_LINE_STATUS: u16 = 5;
/// Scratch register: eight bits of storage with **no side effects at all**.
///
/// It is the presence probe precisely because writing it does nothing to the
/// line, the FIFOs or the modem control signals. The loopback test cannot say
/// that: it seizes the port to say it.
const REG_SCRATCH: u16 = 7;

const LCR_8N1: u8 = 0b0000_0011; // 8 data bits, no parity, 1 stop bit
const LCR_DLAB: u8 = 0b1000_0000; // divisor latch access

const FCR_ENABLE_CLEAR: u8 = 0b1100_0111; // enable FIFOs, clear both, 14-byte trigger

const MCR_DTR_RTS_OUT2: u8 = 0b0000_1011; // DTR + RTS + OUT2 (OUT2 gates the IRQ line)
const MCR_LOOPBACK_TEST: u8 = 0b0001_1110; // loopback + DTR/RTS/OUT1 for the self-test

// Received-data-available only. Deliberately not transmit-empty: see
// `enable_receive_interrupt`.
const IER_RECEIVED_DATA: u8 = 0b0000_0001;

const LSR_TRANSMIT_EMPTY: u8 = 0b0010_0000;
const LSR_DATA_READY: u8 = 0b0000_0001;

/// Written to the scratch register to see whether anything holds it.
///
/// Any value with bits in both halves does; `0xff` would be
/// indistinguishable from the floating bus a missing device reads as, and
/// `0x00` from a device that answers everything with zero.
const SCRATCH_PROBE: u8 = 0xa5;

/// Bound on how long to wait for the transmit holding register to drain.
///
/// At 115200 baud one character takes roughly 87 µs. This bound is far longer
/// than that, so it is never hit on working hardware, and short enough that a
/// dead UART costs microseconds per character rather than a hung boot.
const TRANSMIT_SPIN_LIMIT: u32 = 100_000;

/// Bytes the transmitter gave up on.
///
/// Counted because the alternative is what happened: a byte vanished from a
/// line of console output — `signal` became `ignal` — a shell test failed on
/// a string that never appeared, and the machine said nothing about having
/// dropped anything. Under an emulator on a loaded host the UART is slow to
/// report itself empty, and the spin limit above is reached. Dropping is the
/// right choice, and dropping *silently* is what made it look like flakiness
/// for three suite runs.
static DROPPED: AtomicU64 = AtomicU64::new(0);

/// How many bytes the transmitter has given up on since boot.
///
/// Zero on any machine whose UART keeps up. A boot that reports otherwise has
/// lost output, and anything reading that output is reading something
/// incomplete — which is worth knowing before concluding anything else from
/// it.
#[must_use]
pub fn dropped() -> u64 {
    DROPPED.load(core::sync::atomic::Ordering::Relaxed)
}

/// Byte written and read back by the loopback self-test.
///
/// Arbitrary, but deliberately not `0x00` or `0xff`: those are exactly the
/// values a floating bus returns, so they would make a missing UART look
/// present.
const LOOPBACK_PROBE: u8 = 0xae;

/// A 16550-family UART.
#[derive(Clone, Copy, Debug)]
pub struct SerialPort {
    base: u16,
}

/// What [`SerialPort::init`] concluded about the port.
///
/// **Three states, not two, and the third one is the whole point of this
/// type.** Until 2026-08-22 a failed loopback self-test meant `NotPresent` and
/// the console dropped its serial sink entirely — which is right for a machine
/// with no UART and catastrophic for the machine this was found on: a Lenovo
/// SR550 whose UART is *shared with its BMC* (`SerialPortAccessMode = Shared`).
/// On a server, serial-over-LAN is the only way in, so concluding "no UART"
/// from a loopback that another agent disturbed turns the one usable channel
/// off and leaves an operator staring at nothing.
///
/// Absence and unverified are now different answers, because one of them
/// should silence the port and the other should not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Presence {
    /// Nothing answered. The scratch register did not hold what was written
    /// to it, which on a floating bus reads back as `0xff`.
    Absent,
    /// A device answered and the loopback round-tripped.
    Working,
    /// A device answered, and the loopback did **not** round-trip.
    ///
    /// Output is enabled anyway. A UART that holds a scratch value is a UART,
    /// and the likeliest reason a loopback fails on a port that exists is that
    /// something else — a BMC, a service processor — is driving the same
    /// wires. Being wrong this way costs a log with no reader; being wrong the
    /// other way costs every log on a headless machine.
    Unverified,
}

/// What the probe concluded, from what the two round-trips answered.
///
/// Split out from the register accesses so the *policy* can be tested on the
/// host, which is the only assurance available for a decision whose inputs are
/// two I/O ports.
#[must_use]
pub const fn classify(scratch_round_tripped: bool, loopback_round_tripped: bool) -> Presence {
    if !scratch_round_tripped {
        Presence::Absent
    } else if loopback_round_tripped {
        Presence::Working
    } else {
        Presence::Unverified
    }
}

impl SerialPort {
    /// Names the UART at `base`.
    ///
    /// Does not touch hardware; call [`SerialPort::init`] before writing.
    #[must_use]
    pub const fn new(base: u16) -> Self {
        Self { base }
    }

    const fn reg<T: crate::port::PortValue>(&self, offset: u16) -> Port<T> {
        Port::new(self.base + offset)
    }

    /// Configures the UART for 115200 baud, 8N1, FIFOs enabled, no interrupts,
    /// and answers what it found.
    ///
    /// See [`Presence`] for why the answer has three states rather than two.
    /// **The port is left out of loopback on every path**, which the previous
    /// version's documentation claimed and its code did not do: both of its
    /// early returns left `MCR` in loopback, so a port that failed the test was
    /// also left wired to itself. On a UART shared with a service processor
    /// that breaks the other user of it too.
    ///
    /// # Safety
    ///
    /// The caller must ensure `base` really is a UART and that no other code
    /// is driving it concurrently. Writing this sequence to an unrelated
    /// device's ports could put it in an unexpected state.
    pub unsafe fn init(&self) -> Presence {
        // SAFETY: every access below targets a documented 16550 register at
        // `base + offset`, in the initialisation order given in the 16550
        // datasheet. The caller guarantees `base` is a UART.
        unsafe {
            // Interrupts off first: we are a polled driver, and an interrupt
            // arriving before the IDT exists (M2) would triple-fault.
            self.reg::<u8>(REG_INT_ENABLE).write(0x00);

            // Baud rate: divisor 1 of the 115200 Hz base clock = 115200 baud.
            self.reg::<u8>(REG_LINE_CTRL).write(LCR_DLAB);
            self.reg::<u8>(REG_DIVISOR_LO).write(0x01);
            self.reg::<u8>(REG_DIVISOR_HI).write(0x00);
            self.reg::<u8>(REG_LINE_CTRL).write(LCR_8N1); // also clears DLAB

            self.reg::<u8>(REG_FIFO_CTRL).write(FCR_ENABLE_CLEAR);

            // **Presence first, and without seizing the port.** The scratch
            // register is eight bits of storage with no side effects: if it
            // holds what was written, something is there. A missing device
            // reads as a floating bus -- all ones -- and cannot hold `0xa5`.
            //
            // The previous value is put back, because on a shared port it may
            // belong to somebody else.
            let saved_scratch = self.reg::<u8>(REG_SCRATCH).read();
            self.reg::<u8>(REG_SCRATCH).write(SCRATCH_PROBE);
            let scratch_round_tripped = self.reg::<u8>(REG_SCRATCH).read() == SCRATCH_PROBE;
            self.reg::<u8>(REG_SCRATCH).write(saved_scratch);

            // Then the loopback, which is now a *confidence* check rather than
            // a gate. It is still worth doing: on a port that is genuinely
            // ours it proves the transmit and receive paths are wired, which
            // the scratch register cannot.
            self.reg::<u8>(REG_MODEM_CTRL).write(MCR_LOOPBACK_TEST);
            self.reg::<u8>(REG_DATA).write(LOOPBACK_PROBE);

            let mut loopback_round_tripped = false;
            let mut spins = 0;
            while spins < TRANSMIT_SPIN_LIMIT {
                if self.reg::<u8>(REG_LINE_STATUS).read() & LSR_DATA_READY != 0 {
                    loopback_round_tripped = self.reg::<u8>(REG_DATA).read() == LOOPBACK_PROBE;
                    break;
                }
                spins += 1;
                core::hint::spin_loop();
            }

            // **Unconditionally out of loopback.** Not on the success path, not
            // on most paths -- every path, including the one where nothing
            // answered. Leaving a port wired to itself is worse than leaving it
            // alone, and there is no early return between here and the write
            // above for that reason.
            self.reg::<u8>(REG_MODEM_CTRL).write(MCR_DTR_RTS_OUT2);

            classify(scratch_round_tripped, loopback_round_tripped)
        }
    }

    /// Writes one byte, waiting for space in the transmit register.
    ///
    /// Gives up after [`TRANSMIT_SPIN_LIMIT`] iterations and drops the byte,
    /// so a wedged UART cannot hang the kernel.
    ///
    /// # Safety
    ///
    /// The caller must ensure [`SerialPort::init`] has succeeded for this port.
    pub unsafe fn write_byte(&self, byte: u8) {
        // SAFETY: reading the line status register has no side effects, and
        // writing the data register is the documented way to transmit. The
        // caller guarantees the port was initialised.
        unsafe {
            let status = self.reg::<u8>(REG_LINE_STATUS);
            let mut spins = 0;
            while status.read() & LSR_TRANSMIT_EMPTY == 0 {
                spins += 1;
                if spins >= TRANSMIT_SPIN_LIMIT {
                    // Drop the byte rather than hang -- and say so, in a
                    // number somebody can read afterwards.
                    DROPPED.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                    return;
                }
                core::hint::spin_loop();
            }
            self.reg::<u8>(REG_DATA).write(byte);
        }
    }

    /// Reads one byte if the receiver has one, without waiting.
    ///
    /// `None` means the receive FIFO is empty, which is the ordinary case and
    /// not an error. A caller servicing an interrupt must keep calling until
    /// it gets `None`: the FIFO holds up to sixteen bytes and delivers one
    /// interrupt for the batch, so stopping after the first byte leaves the
    /// rest to be noticed by an interrupt that will not arrive.
    ///
    /// # Safety
    ///
    /// The caller must ensure [`SerialPort::init`] has succeeded for this port.
    #[must_use]
    pub unsafe fn read_byte(&self) -> Option<u8> {
        // SAFETY: reading the line status register has no side effects.
        // Reading the data register *does* -- it removes a byte from the FIFO
        // -- which is why it happens only when the status says one is there.
        unsafe {
            if self.reg::<u8>(REG_LINE_STATUS).read() & LSR_DATA_READY == 0 {
                return None;
            }
            Some(self.reg::<u8>(REG_DATA).read())
        }
    }

    /// Asks the UART to raise its interrupt line when a byte arrives.
    ///
    /// Only the received-data source is enabled. A transmit-empty interrupt
    /// would fire continuously while the kernel has nothing to send, and this
    /// driver transmits by polling — which is correct for a console that must
    /// work inside a panic, when no interrupt will ever be serviced again.
    ///
    /// # Safety
    ///
    /// The caller must ensure [`SerialPort::init`] has succeeded, that there
    /// is an IDT gate for wherever this interrupt is routed, and that the
    /// handler drains the FIFO and acknowledges the interrupt controller.
    pub unsafe fn enable_receive_interrupt(&self) {
        // SAFETY: the interrupt enable register at `base + 1`, with DLAB
        // clear -- which `init` left it, and nothing sets it afterwards.
        unsafe { self.reg::<u8>(REG_INT_ENABLE).write(IER_RECEIVED_DATA) };
    }

    /// Puts the UART into or out of loopback, where what it sends it receives.
    ///
    /// This exists for the interrupt self-test. Nothing else can produce an
    /// inbound byte on demand: a test that waited for someone to type would
    /// pass on a developer's terminal and hang in CI.
    ///
    /// # Safety
    ///
    /// The caller must ensure [`SerialPort::init`] has succeeded, and must put
    /// the port back — output written while in loopback goes nowhere.
    pub unsafe fn set_loopback(&self, enable: bool) {
        let value = if enable {
            MCR_LOOPBACK_TEST
        } else {
            MCR_DTR_RTS_OUT2
        };
        // SAFETY: the modem control register, whose loopback bit is documented
        // to have exactly this effect.
        unsafe { self.reg::<u8>(REG_MODEM_CTRL).write(value) };
    }

    /// Writes a string, translating `\n` to `\r\n`.
    ///
    /// Terminals and capture tools expect a carriage return; without this the
    /// output staircases and is nearly unreadable.
    ///
    /// # Safety
    ///
    /// The caller must ensure [`SerialPort::init`] has succeeded for this port.
    pub unsafe fn write_str(&self, s: &str) {
        for byte in s.bytes() {
            if byte == b'\n' {
                // SAFETY: same obligation as `write_byte`, delegated to the caller.
                unsafe { self.write_byte(b'\r') };
            }
            // SAFETY: same obligation as `write_byte`, delegated to the caller.
            unsafe { self.write_byte(byte) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nothing_answering_the_scratch_register_is_absent() {
        // A floating bus reads as all ones and cannot hold `0xa5`, so this is
        // the one answer that should silence the sink.
        assert_eq!(classify(false, false), Presence::Absent);
        // Even if a loopback somehow appeared to pass, a port that cannot hold
        // a byte is not a port.
        assert_eq!(classify(false, true), Presence::Absent);
    }

    #[test]
    fn a_device_that_round_trips_both_probes_is_working() {
        assert_eq!(classify(true, true), Presence::Working);
    }

    /// **The case that cost a headless server its console.**
    ///
    /// A UART that holds a scratch value is a UART. If its loopback does not
    /// round-trip, the likeliest reason on a machine that has one is that
    /// something else is driving the same wires — a BMC, a service processor.
    /// The old code called that `NotPresent` and dropped the serial sink, which
    /// on a Lenovo SR550 (`SerialPortAccessMode = Shared`) removes the only
    /// channel a machine with no screen has.
    #[test]
    fn a_present_device_with_a_failed_loopback_is_unverified_not_absent() {
        assert_eq!(classify(true, false), Presence::Unverified);
        assert_ne!(classify(true, false), Presence::Absent);
    }

    #[test]
    fn only_absence_should_silence_the_sink() {
        // The console installs its sink for anything that is not `Absent`, so
        // this enumerates the contract that decision relies on.
        for (scratch, loopback) in [(true, true), (true, false)] {
            assert_ne!(
                classify(scratch, loopback),
                Presence::Absent,
                "a device answered; the sink must survive"
            );
        }
        assert_eq!(classify(false, true), Presence::Absent);
        assert_eq!(classify(false, false), Presence::Absent);
    }

    #[test]
    fn the_scratch_probe_cannot_be_confused_with_a_floating_bus() {
        // `0xff` is what a missing device reads back, and `0x00` is what a
        // device that answers everything with zero reads back. The probe must
        // be neither, or presence and absence would look the same.
        assert_ne!(SCRATCH_PROBE, 0xff);
        assert_ne!(SCRATCH_PROBE, 0x00);
    }
}
