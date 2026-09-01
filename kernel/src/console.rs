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
    /// A **second** UART, if the machine has one.
    ///
    /// Not a fallback: output goes to both. A headless server's only channel
    /// may be a port this kernel does not think of as first, and on the SR550
    /// the boot report says `serial present` -- COM1 is real and its loopback
    /// round-trips -- while nothing the kernel writes reaches serial-over-LAN.
    /// Writing to both is what a machine with two ports and no screen needs,
    /// and it costs a second UART's worth of characters on a machine that has
    /// one to spare. RFC 0042 step 6.
    serial_second: Option<SerialPort>,
    framebuffer: Option<FbConsole>,
    /// What has been printed, for reading back. RFC 0042.
    recorder: Recorder,
}

impl Console {
    const fn empty() -> Self {
        Self {
            serial: None,
            serial_second: None,
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
        if let Some(serial) = self.serial_second.as_ref() {
            // SAFETY: as above -- set only by `init_second_serial`, and only
            // for a port whose own probe answered something other than absent.
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

/// Whether the record holds `needle` contiguously — the transport test.
///
/// **Temporary (2026-08-31), with the run rings above.** [`Write::write_str`]
/// records *before* it writes to the UART, so this is the guest's own byte
/// order, taken upstream of the serial port, QEMU's chardev and the capture. A
/// line that is whole here and torn in the serial log was torn **below this
/// kernel**, which is the question three wrong answers were spent on today.
///
/// Takes the console lock, so it must not be called from inside a print.
#[must_use]
pub fn recorded_contains(needle: &[u8]) -> bool {
    let guard = CONSOLE.lock();
    let kept = guard.recorder.kept();
    if needle.is_empty() || kept.len() < needle.len() {
        return false;
    }
    kept.windows(needle.len()).any(|window| window == needle)
}

/// How many times `needle` appears contiguously in the record.
///
/// **Counting, not just finding, because the question is how many survived.**
/// `tear_probe` hands the same payload to [`put_run`] many times and asks how
/// many came back whole; a `bool` would answer "at least one", which is the
/// wrong question. Overlaps cannot occur for the payload it uses, so a simple
/// window scan is exact.
#[must_use]
pub fn recorded_occurrences(needle: &[u8]) -> usize {
    let guard = CONSOLE.lock();
    let kept = guard.recorder.kept();
    if needle.is_empty() || kept.len() < needle.len() {
        return 0;
    }
    kept.windows(needle.len())
        .filter(|window| *window == needle)
        .count()
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

/// Brings up a second serial sink, if the machine has a second UART.
///
/// **Additional, not alternative.** The first port keeps its place; this one is
/// written to as well. A machine with one UART is unaffected, because an absent
/// port installs nothing.
///
/// Why this exists: on the SR550 the boot report says `serial present` — the
/// probe found COM1 and its loopback round-tripped — and yet nothing the kernel
/// writes arrives at serial-over-LAN, across seven boots. A port that is real
/// and whose output nobody carries is a port that is not the one the service
/// processor is listening to. That was read off the machine on 2026-08-23 by
/// somebody typing `dmesg`, which is the first time this project has been able
/// to ask.
pub fn init_second_serial(base: u16) -> Presence {
    let port = SerialPort::new(base);
    // SAFETY: as `init_serial`. Still before any other CPU is started.
    let presence = unsafe { port.init() };
    if presence != Presence::Absent {
        CONSOLE.lock().serial_second = Some(port);
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

/// Runs `f` with the console **held**, so no other CPU can print while it does.
///
/// # Why this exists
///
/// `shell_self_test` puts `COM1` into loopback and waits for the interrupt its
/// own five bytes cause. While the port is looped back, **anything printed goes
/// out of it and comes straight back in** — and the console's serial sink *is*
/// that port. Its doc comment has always said *"nothing is printed while the
/// port is looped back"*, and until 2026-08-27 that was a convention with
/// nothing enforcing it: on QEMU's four processors nothing happened to print in
/// the window, and on the SR550's sixteen something did. The test reported
/// **`14 of 5 bytes`** there, on every boot, with no command wrong — nine bytes
/// that were never typed.
///
/// Holding the lock turns the convention into a mechanism. Other CPUs wait and
/// then print; nothing is lost and nothing is dropped, which is what separates
/// this from suppressing output across the window.
///
/// # The rule for callers
///
/// **`f` must not print.** This is a plain spin lock and it is not reentrant, so
/// a `println!` inside `f` — directly, or from anything it calls — deadlocks the
/// machine. Interrupts stay enabled, deliberately, because the caller is waiting
/// for one; the handlers on that path do not print, which is why this is safe
/// where a general-purpose "hold the console" would not be.
///
/// A **panic or an exception inside `f` still reports**: the fatal path sets
/// `FATAL` and writes without taking this lock, which is exactly what it was
/// built for.
pub fn with_output_held<T>(f: impl FnOnce() -> T) -> T {
    let _guard = CONSOLE.lock();
    f()
}

/// Puts a run of bytes with the console held **once** — RFC 0050.
///
/// # Why this exists
///
/// [`_print`] takes the console lock for the whole of one `write_fmt`, so a
/// kernel line is atomic against everything. A hosted program's `write` was not:
/// `bin/linuxd` put one byte per `INVOKE`, each taking and releasing this lock,
/// so any other CPU printing between two of them split the line. It did, and the
/// specimen is in a preserved log of 2026-08-26:
///
/// ```text
/// e    linux exec     a Linux program execed: its own domain ended ...
/// xeced pid 3
/// ```
///
/// The program wrote `execed pid 3`. The `e` got out; a kernel report took the
/// lock; the rest followed.
///
/// # What it is not
///
/// It is not a different authority and it is not different rendering. A byte is
/// put exactly as [`crate::syscall`]'s `PUT` puts one — as a scalar value, or
/// `?` if it is not one — so a run of *n* bytes is *n* `PUT`s and nothing else.
/// What it removes is the gap between them.
/// **Temporary instrument (2026-08-31), not for keeping.** The last run
/// lengths handed to [`put_run`], so a line that arrives split can be told
/// apart from a line that was split *after* it got here. TRACKER §3 records
/// that every layer above this one sends a whole line in one call, and a line
/// still split after byte 22 of 27; this says which side of `put_run` that
/// happened on.
pub static RUN_LENS: [core::sync::atomic::AtomicU32; 48] =
    [const { core::sync::atomic::AtomicU32::new(0) }; 48];
/// Every completed [`_print`], counted. Temporary, with the ring below.
///
/// **The mutual-exclusion test.** `put_run` samples this before and after
/// writing a run, *inside* the same `CONSOLE` guard. `_print` takes that guard
/// too, so the two values must be equal on every run. If they are not, a
/// `println!` ran while `put_run` held the console -- which is the tear, and
/// proves the lock is not excluding them rather than leaving it inferred.
pub static PRINTS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Runs during which [`PRINTS`] moved: exclusion failures. Must read zero.
pub static TORN: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Runs whose bytes did **not** land contiguously in the record.
///
/// **The instrument that decides the contradiction.** A torn boot shows all of:
/// the line reaching `put_run` whole as one run, `CONSOLE` held for the whole
/// of it, `TORN` at zero — and the record split anyway. Those cannot all be
/// true. This measures the last one directly and at the moment it happens: the
/// recorder is append-only, so a run of *n* bytes must advance it by exactly
/// *n*. Anything else means somebody else's bytes landed in between, and the
/// difference names how many.
pub static NONCONTIGUOUS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Bytes the record advanced beyond a run's own length, summed.
pub static INTERLOPER_BYTES: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// How many runs carried the hosted probe's line, and how long the last was.
///
/// **The one thing the other counters cannot say.** They agree that every run
/// lands contiguously and that no print interleaves one — and the line still
/// comes out split. Both are true at once if the line arrives as **two runs**
/// with a print between them, because a print *between* runs is inside
/// neither. This says which: one run of 28 means the split is below `put_run`;
/// two runs means it is above, and every layer that claims to send it whole is
/// wrong somewhere.
pub static HOSTED_RUNS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// The length of the last run carrying that line.
pub static HOSTED_RUN_LEN: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Who handed each run over, paired with [`RUN_LENS`]. Temporary, with it.
///
/// `0` is a kernel-side caller (the in-kernel console service); anything else
/// is the domain id that issued a `PUT_RUN` syscall. Without this the ring
/// shows a `28` that could be any of a dozen callers, and attributing one to
/// the line under investigation would be pattern-matching rather than evidence.
pub static RUN_TAGS: [core::sync::atomic::AtomicU32; 48] =
    [const { core::sync::atomic::AtomicU32::new(0) }; 48];

/// The first byte of each run, paired with [`RUN_LENS`]. Temporary, with it.
///
/// Identifying a run by its length alone is inference: a 28 could be any
/// caller. The first byte says which line it is, so `12h` followed by `16r`
/// proves a split above `put_run`, and a single `28h` proves the line left
/// here whole.
pub static RUN_HEADS: [core::sync::atomic::AtomicU32; 48] =
    [const { core::sync::atomic::AtomicU32::new(0) }; 48];

/// The ring cursor for [`RUN_LENS`]. Temporary, with it.
pub static RUN_AT: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// The run lengths recorded so far, oldest-first from the ring's cursor.
pub fn run_lengths() -> ([u32; 48], [u32; 48], [u32; 48], usize) {
    let mut lens = [0u32; 48];
    let mut tags = [0u32; 48];
    let mut heads = [0u32; 48];
    for (index, slot) in RUN_HEADS.iter().enumerate() {
        heads[index] = slot.load(core::sync::atomic::Ordering::Relaxed);
    }
    for (index, slot) in RUN_LENS.iter().enumerate() {
        lens[index] = slot.load(core::sync::atomic::Ordering::Relaxed);
    }
    for (index, slot) in RUN_TAGS.iter().enumerate() {
        tags[index] = slot.load(core::sync::atomic::Ordering::Relaxed);
    }
    (
        lens,
        tags,
        heads,
        RUN_AT.load(core::sync::atomic::Ordering::Relaxed),
    )
}

/// Puts a run of bytes with the console held once — RFC 0050. See the note
/// above [`RUN_LENS`] for the instrument, and the block comment further up for
/// why this function exists at all.
pub fn put_run(bytes: &[u8]) {
    put_run_tagged(bytes, 0);
}

/// As [`put_run`], recording which domain handed the run over. Temporary.
pub fn put_run_tagged(bytes: &[u8], tag: u32) {
    {
        let at = RUN_AT.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        RUN_LENS[at % RUN_LENS.len()]
            .store(bytes.len() as u32, core::sync::atomic::Ordering::Relaxed);
        RUN_TAGS[at % RUN_TAGS.len()].store(tag, core::sync::atomic::Ordering::Relaxed);
        // Targeted, and narrow on purpose: only the line under investigation.
        // **`errno` alone is not unique to this line**, and that is the third
        // needle in one investigation to have been too loose: the boot also
        // prints "and got a Linux errno five times". A counter that matches the
        // wrong line reports a length that belongs to somebody else, which is
        // exactly the confusion its numbers were meant to resolve.
        const NEEDLE: &[u8] = b"open refused errno";
        if bytes.len() >= NEEDLE.len() && bytes.windows(NEEDLE.len()).any(|w| w == NEEDLE) {
            HOSTED_RUNS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            HOSTED_RUN_LEN.store(bytes.len() as u64, core::sync::atomic::Ordering::Relaxed);
        }
        RUN_HEADS[at % RUN_HEADS.len()].store(
            u32::from(bytes.first().copied().unwrap_or(0)),
            core::sync::atomic::Ordering::Relaxed,
        );
    }
    if FATAL.load(core::sync::atomic::Ordering::Acquire) {
        // The fatal path cannot block on this lock and must not start now. One
        // byte at a time is exactly what it did before, and a report racing a
        // dying machine has bigger problems than an interleaved line.
        for byte in bytes {
            write_fatal(format_args!("{}", char::from(*byte)));
        }
        return;
    }
    let mut console = CONSOLE.lock();
    let before = PRINTS.load(core::sync::atomic::Ordering::Relaxed);
    let recorded_before = console.recorder.kept().len();
    for byte in bytes {
        // The same rendering `PUT` performs, and deliberately not `str`
        // conversion: this path has never promised UTF-8 and a run that
        // refused to print because one byte was not a scalar would lose the
        // line it exists to keep whole.
        let _ = console.write_fmt(format_args!("{}", char::from(*byte)));
    }
    if PRINTS.load(core::sync::atomic::Ordering::Relaxed) != before {
        TORN.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    }
    // Append-only, so `n` bytes must advance it by `n` — unless the record
    // filled, which is its own answer and not this one.
    let grew = console.recorder.kept().len() - recorded_before;
    if grew != bytes.len() && console.recorder.refused() == 0 {
        NONCONTIGUOUS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        INTERLOPER_BYTES.fetch_add(
            (grew as u64).saturating_sub(bytes.len() as u64),
            core::sync::atomic::Ordering::Relaxed,
        );
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
    // **Counted inside the guard, not after it.** The increment used to sit
    // after `CONSOLE.lock()`'s temporary was dropped, so a print that wrote and
    // was preempted before counting itself was invisible to `TORN` — and that
    // made `TORN` a heuristic. Inside, it is an assertion: `put_run` samples
    // this while *holding* the console, so any change it sees means a second
    // holder wrote while it held the lock. That is the one assumption behind
    // this whole investigation that had never been tested.
    {
        let mut console = CONSOLE.lock();
        let _ = console.write_fmt(args);
        PRINTS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    }
}

/// Set once a fatal report begins: every print after it goes through
/// [`write_fatal`], which cannot block on the console lock.
static FATAL: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Returns the console to its normal path after a report the machine survived.
///
/// **Why this has to exist, and what its absence cost.** [`enter_fatal`] is
/// entered at the top of *every* exception report, before the report can know
/// whether the machine will survive one — which is right, because a report
/// that cannot print is worth nothing. But a ring-3 domain faulting is a
/// survivable event this kernel handles by design, and the boot exercises it
/// on purpose: the report ends "this machine is still running", the domain is
/// torn down, and the boot continues for hundreds of lines. Nothing cleared
/// the flag, so from the first such fault onward [`put_run`] returned early
/// into [`write_fatal`], which takes the lock **once per byte** instead of
/// once per run. RFC 0050's whole-run guarantee — the entire purpose of
/// `put_run` — was void for most of every boot, and a user program's line tore
/// whenever another CPU printed inside that window.
///
/// It read as intermittent because it is: it depends on whether a second CPU
/// prints during those bytes. And it survived six investigations because every
/// instrument built to answer "did another print get in?" — [`TORN`],
/// [`NONCONTIGUOUS`], [`INTERLOPER_BYTES`] — sits *after* that early return
/// and never ran on a torn boot. Five mutually inconsistent measurements, all
/// reading zero because none of them was ever executed.
///
/// Called only where a report has concluded the machine lives. The protection
/// `enter_fatal` exists for — run-80, where a CPU blocked on a lock a dead CPU
/// held — applies *during* a report and is kept: this restores the normal path
/// only once the report is over and the machine is known to be running.
pub fn leave_fatal() {
    FATAL.store(false, core::sync::atomic::Ordering::Release);
}

/// Whether the console is on its fatal path.
///
/// Set means [`put_run`] is no longer holding the console across a run. The
/// boot report prints this and a gate reads it: it is the one assertion this
/// defect needed and did not have.
#[must_use]
pub fn is_fatal() -> bool {
    FATAL.load(core::sync::atomic::Ordering::Acquire)
}

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
mod put_run_tests {
    use super::{put_run, recorded, recorded_at};

    /// The console is a global and cargo runs tests in parallel, so the two
    /// tests here take it in turns. `notify`'s tests learned this the same way.
    static CONSOLE_TESTS: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Reads back everything the recorder has kept since `from`.
    ///
    /// `recorded()` answers `(kept, refused)` and **not** a range: reading the
    /// second number as a position is why the first version of these tests saw
    /// an empty console and said the run had been lost.
    fn kept_since(from: usize) -> std::vec::Vec<u8> {
        let (end, _) = recorded();
        let mut out = std::vec::Vec::new();
        let mut at = from;
        while at < end {
            let eight = recorded_at(at);
            let room = (end - at).min(8);
            out.extend_from_slice(&eight[..room]);
            at += room;
        }
        out
    }

    #[test]
    fn every_byte_of_a_run_is_put_in_order() {
        let _alone = CONSOLE_TESTS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (before, _) = recorded();
        put_run(b"execed pid 3\n");
        // **Contained, not equal**, and the difference is a flake this test had.
        // The recorder is the machine's, and any of the other two hundred tests
        // that prints adds bytes to it — the module guard above serialises the
        // two tests that share `PUT`, and cannot serialise the whole suite. The
        // property was never "nothing else printed"; it is that the run arrives
        // **whole and in order**, which containment says exactly.
        let kept = kept_since(before);
        assert!(
            kept.windows(13).any(|window| window == b"execed pid 3\n"),
            "a run must arrive whole and in order -- losing or reordering one byte is the \
             defect this exists to remove; kept {kept:?}"
        );
    }

    #[test]
    fn a_byte_that_is_not_a_scalar_is_rendered_the_way_put_renders_it() {
        let _alone = CONSOLE_TESTS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (before, _) = recorded();
        // 0xff is not a printable scalar; `PUT` renders such a byte rather than
        // refusing, and a run must not do something different -- a run that
        // dropped the line because one byte was odd would lose exactly what it
        // exists to keep.
        put_run(&[b'a', 0xff, b'b']);
        // Contained rather than equal, for the reason above. `0xff` renders as
        // two bytes, so the run is four: `a`, the two of the replacement, `b`.
        let kept = kept_since(before);
        assert!(
            kept.windows(4)
                .any(|window| window[0] == b'a' && window[3] == b'b'),
            "the run must arrive whole with the odd byte rendered rather than dropped; \
             kept {kept:?}"
        );
    }
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
