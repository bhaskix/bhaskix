// SPDX-License-Identifier: Apache-2.0
//! The kernel console.
//!
//! Multiplexes kernel output to every sink that is available: the serial port
//! (which a developer or CI harness captures) and the framebuffer (which a
//! person at the machine sees). Either may be absent; output goes to whatever
//! is present.
//!
//! # Why both, always
//!
//! Serial alone means a user on real hardware with no serial port sees a black
//! screen and cannot report what happened. Framebuffer alone means CI cannot
//! assert on the output and a developer cannot copy a panic message. Neither
//! is optional.
//!
//! # Failure behaviour
//!
//! Writing to the console never fails and never blocks indefinitely. A missing
//! sink is skipped; a wedged UART drops bytes after a bounded spin
//! (`bhaskix_arch::serial`). Diagnostics that can hang are worse than no
//! diagnostics, because they remove the information about where the hang was.

use core::fmt::{self, Write};

use bhaskix_arch::{Presence, SerialPort};
use bhaskix_boot::Framebuffer;

use crate::framebuffer::FbConsole;
use crate::sync::{Rank, SpinLock};

/// The global console.
///
/// Starts empty so that `print!` before initialisation is a silent no-op
/// rather than a fault. That matters: the code that runs before the console
/// exists is exactly the code most likely to want to say something.
static CONSOLE: SpinLock<Console> = SpinLock::new(Rank::Console, Console::empty());

/// How much of what the kernel prints is kept for reading back.
///
/// A whole boot report today with room to grow. Sixty-four kilobytes of static
/// kernel memory, priced on the boot line beside the other fixed tables — this
/// project does not spend memory silently.
pub const RECORDED_BYTES: usize = 64 * 1024;

/// What the kernel has printed, kept so somebody can read it back.
///
/// **It fills once and then stops, which is the opposite of the telemetry
/// rings.** [RFC 0026](../../docs/rfc/0026-telemetry-plane.md)'s event rings are
/// drop-newest, because a running system's newest events are the ones a reader
/// has not seen. A boot log wants the other end: what scrolls off a framebuffer
/// is the *beginning* — the handoff, the memory map, paging, KASLR, the IOMMU —
/// and what is still on screen is by definition already visible.
///
/// So this keeps the earliest bytes and counts what it refused. The count is
/// reported, because a truncated log that does not say it is truncated is worse
/// than no log: a reader would take the last line they can see for the last line
/// there was.
///
/// RFC 0042.
pub struct Recorder {
    bytes: [u8; RECORDED_BYTES],
    used: usize,
    refused: usize,
}

impl Recorder {
    /// An empty recorder.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            bytes: [0; RECORDED_BYTES],
            used: 0,
            refused: 0,
        }
    }

    /// Records what was printed, keeping as much as still fits.
    ///
    /// **A partial write is kept rather than refused whole.** The byte that
    /// crosses the boundary is the one a reader most wants — it is where the
    /// record stops — and dropping its whole line to keep the ring tidy would
    /// throw away the last thing the machine managed to say.
    pub fn record(&mut self, bytes: &[u8]) {
        let room = RECORDED_BYTES - self.used;
        let taken = if bytes.len() < room {
            bytes.len()
        } else {
            room
        };
        self.bytes[self.used..self.used + taken].copy_from_slice(&bytes[..taken]);
        self.used += taken;
        self.refused += bytes.len() - taken;
    }

    /// What was kept, in the order it was printed.
    #[must_use]
    pub fn kept(&self) -> &[u8] {
        &self.bytes[..self.used]
    }

    /// How many bytes were printed and not kept.
    #[must_use]
    pub const fn refused(&self) -> usize {
        self.refused
    }

    /// Whether everything printed so far was kept.
    #[must_use]
    pub const fn complete(&self) -> bool {
        self.refused == 0
    }
}

impl Default for Recorder {
    fn default() -> Self {
        Self::new()
    }
}

/// A multiplexed output sink.
pub struct Console {
    serial: Option<SerialPort>,
    framebuffer: Option<FbConsole>,
    /// What has been printed, for reading back. RFC 0042.
    recorder: Recorder,
}

impl Console {
    const fn empty() -> Self {
        Self {
            serial: None,
            framebuffer: None,
            recorder: Recorder::new(),
        }
    }
}

impl Write for Console {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        // **Recorded first, and here rather than anywhere else.** This is the
        // one place everything printed passes through, so "if it was printed it
        // is in the record, and if it was not it is not" holds by construction.
        // A second formatting path would be a log that can disagree with the
        // console, which is two sources of truth.
        self.recorder.record(s.as_bytes());
        if let Some(serial) = self.serial.as_ref() {
            // SAFETY: `serial` is only ever set by `init_serial`, which stores
            // it after `SerialPort::init` returned `Ok` -- exactly the
            // precondition `write_str` requires.
            unsafe { serial.write_str(s) };
        }
        if let Some(framebuffer) = self.framebuffer.as_mut() {
            framebuffer.write_str(s);
        }
        Ok(())
    }
}

/// How much of what has been printed was kept, and how much was refused.
///
/// RFC 0042. Reported on every boot, because a truncated record that does not
/// say it is truncated would have a reader take the last line they can see for
/// the last line there was.
#[must_use]
pub fn recorded() -> (usize, usize) {
    let guard = CONSOLE.lock();
    (guard.recorder.kept().len(), guard.recorder.refused())
}

/// Eight bytes of the record starting at `offset`, zero-padded past the end.
///
/// Eight because that is what one reply word carries, and a caller asks
/// [`recorded`] for the length first — a zero byte is a byte somebody could
/// have printed, so it cannot mean "the end". RFC 0042.
#[must_use]
pub fn recorded_at(offset: usize) -> [u8; 8] {
    let guard = CONSOLE.lock();
    let kept = guard.recorder.kept();
    let mut out = [0u8; 8];
    if offset < kept.len() {
        let end = (offset + 8).min(kept.len());
        out[..end - offset].copy_from_slice(&kept[offset..end]);
    }
    out
}

/// Brings up the serial sink.
///
/// Answers what the probe concluded. The caller reports it rather than
/// assuming: a machine with no serial port is normal, and the operator should
/// know that serial capture will be empty.
///
/// **A port whose loopback did not round-trip still gets its sink.** Only
/// [`Presence::Absent`] means no device, and only absence silences this sink.
/// The reason is a real machine: a Lenovo SR550 shares its UART with the BMC,
/// and serial-over-LAN is the only way into a server with no screen. Refusing
/// to print because a self-test was disturbed by the other user of the port is
/// how a headless machine ends up saying nothing at all.
pub fn init_serial(base: u16) -> Presence {
    let port = SerialPort::new(base);

    // SAFETY: `base` is a legacy UART port constant, and nothing else in the
    // kernel drives a UART -- this runs once, before any other CPU is started
    // and before interrupts are enabled.
    let presence = unsafe { port.init() };

    if presence != Presence::Absent {
        CONSOLE.lock().serial = Some(port);
    }
    presence
}

/// Brings up the framebuffer sink.
///
/// Returns whether the framebuffer was usable. An unsupported pixel format is
/// reported rather than rendered as garbage.
pub fn init_framebuffer(fb: Framebuffer) -> bool {
    match FbConsole::new(fb) {
        Some(console) => {
            CONSOLE.lock().framebuffer = Some(console);
            true
        }
        None => false,
    }
}

/// Writes formatted output to every available sink.
///
/// Not intended to be called directly; use [`print!`](crate::print) and
/// [`println!`](crate::println).
#[doc(hidden)]
pub fn _print(args: fmt::Arguments<'_>) {
    // `write_fmt` on `Console` cannot fail, so discarding the result loses no
    // information. It is discarded explicitly rather than unwrapped because
    // `unwrap` is denied in kernel code (docs/coding-style.md §4).
    if FATAL.load(core::sync::atomic::Ordering::Acquire) {
        write_fatal(args);
        return;
    }
    let _ = CONSOLE.lock().write_fmt(args);
}

/// Set once a fatal report begins: every print after it goes through
/// [`write_fatal`], which cannot block on the console lock.
static FATAL: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Routes every later print through the path that cannot block.
///
/// Called at the top of the exception report and the panic handler — the
/// two places whose words must reach the wire on a machine whose locks may
/// already be wedged. run-80's exception report stopped at its fifth line
/// because the reporting CPU blocked on a console lock another, equally
/// dead CPU held; this is the instrument that run named.
pub fn enter_fatal() {
    FATAL.store(true, core::sync::atomic::Ordering::Release);
}

/// Prints without ever blocking: patience first, theft second.
///
/// A bounded wait keeps healthy output untorn — on a live machine the lock
/// frees in microseconds. If it never frees, the console is written
/// through anyway: a deliberate data race on a dying machine, because a
/// torn line beats a silent wedge every time it matters.
fn write_fatal(args: fmt::Arguments<'_>) {
    for _ in 0..1_000_000 {
        if let Some(mut console) = CONSOLE.try_lock() {
            let _ = console.write_fmt(args);
            return;
        }
        core::hint::spin_loop();
    }
    // SAFETY: aliasing the console deliberately, as `data_ptr`'s contract
    // states: the machine is fatal, the holder may never release, and the
    // report matters more than the formatting.
    let console = unsafe { &mut *CONSOLE.data_ptr() };
    let _ = console.write_fmt(args);
}

/// Prints to the kernel console.
#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {
        $crate::console::_print(::core::format_args!($($arg)*))
    };
}

/// Prints to the kernel console, followed by a newline.
#[macro_export]
macro_rules! println {
    () => { $crate::print!("\n") };
    ($($arg:tt)*) => {
        $crate::console::_print(::core::format_args!("{}\n", ::core::format_args!($($arg)*)))
    };
}

#[cfg(test)]
mod recorder_tests {
    use super::{RECORDED_BYTES, Recorder};

    #[test]
    fn what_is_printed_is_what_is_kept() {
        let mut recorder = Recorder::new();
        recorder.record(b"boot report\n");
        recorder.record(b"second line\n");
        assert_eq!(recorder.kept(), b"boot report\nsecond line\n");
        assert_eq!(recorder.refused(), 0);
        assert!(recorder.complete());
    }

    #[test]
    fn an_empty_recorder_has_kept_nothing_and_refused_nothing() {
        let recorder = Recorder::new();
        assert!(recorder.kept().is_empty());
        assert_eq!(recorder.refused(), 0);
        assert!(
            recorder.complete(),
            "a machine that has printed nothing has lost nothing"
        );
    }

    #[test]
    fn filling_it_exactly_refuses_nothing() {
        // The boundary that a fill-once ring gets wrong: exactly full is full,
        // not overfull.
        let mut recorder = Recorder::new();
        recorder.record(&[b'x'; RECORDED_BYTES]);
        assert_eq!(recorder.kept().len(), RECORDED_BYTES);
        assert_eq!(recorder.refused(), 0);
        assert!(recorder.complete());
    }

    #[test]
    fn one_byte_over_is_one_byte_refused() {
        let mut recorder = Recorder::new();
        recorder.record(&[b'x'; RECORDED_BYTES]);
        recorder.record(b"y");
        assert_eq!(recorder.kept().len(), RECORDED_BYTES);
        assert_eq!(recorder.refused(), 1);
        assert!(!recorder.complete());
    }

    #[test]
    fn a_write_that_crosses_the_end_is_kept_up_to_it() {
        // **The byte that crosses the boundary is the one a reader most wants**
        // -- it is where the record stops. Refusing the whole write to keep the
        // ring tidy throws away the last thing the machine managed to say.
        let mut recorder = Recorder::new();
        recorder.record(&[b'x'; RECORDED_BYTES - 4]);
        recorder.record(b"abcdefgh");
        assert_eq!(recorder.kept().len(), RECORDED_BYTES);
        assert_eq!(&recorder.kept()[RECORDED_BYTES - 4..], b"abcd");
        assert_eq!(recorder.refused(), 4);
    }

    #[test]
    fn the_beginning_is_what_survives_and_not_the_end() {
        // The whole reason this is fill-once rather than drop-oldest. What
        // scrolls off a framebuffer is the *start* of the boot report; the end
        // is still on screen. A ring that kept the newest bytes would keep
        // exactly what the operator can already see.
        let mut recorder = Recorder::new();
        recorder.record(b"FIRST");
        recorder.record(&[b'x'; RECORDED_BYTES]);
        assert_eq!(
            &recorder.kept()[..5],
            b"FIRST",
            "the first line printed must still be readable after the ring fills"
        );
        assert_eq!(recorder.refused(), 5);
    }

    #[test]
    fn refusals_accumulate_rather_than_reporting_only_the_last() {
        let mut recorder = Recorder::new();
        recorder.record(&[b'x'; RECORDED_BYTES]);
        recorder.record(b"aaa");
        recorder.record(b"bb");
        assert_eq!(
            recorder.refused(),
            5,
            "a count that reset would understate what was lost"
        );
    }
}
