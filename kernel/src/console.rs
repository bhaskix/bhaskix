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

/// A multiplexed output sink.
pub struct Console {
    serial: Option<SerialPort>,
    framebuffer: Option<FbConsole>,
}

impl Console {
    const fn empty() -> Self {
        Self {
            serial: None,
            framebuffer: None,
        }
    }
}

impl Write for Console {
    fn write_str(&mut self, s: &str) -> fmt::Result {
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
