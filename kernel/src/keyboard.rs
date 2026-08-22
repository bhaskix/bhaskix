// SPDX-License-Identifier: Apache-2.0
//! An i8042 keyboard, and the translation from scancodes to bytes.
//!
//! [RFC 0037](../../docs/rfc/0037-a-keyboard-on-real-hardware.md). Until this
//! module existed, console *input* was a UART and nothing else — which is
//! invisible in every test this project runs, because every one of them types
//! over a serial line. It is not invisible on a laptop, where the framebuffer
//! carries the whole boot report and nothing can be typed into the shell.
//!
//! # The translation is separated from the hardware on purpose
//!
//! [`Keys::feed`] takes a byte and answers what it produced. It touches no
//! port, holds no lock and knows nothing about interrupts, so the table can be
//! tested on the host — which matters more here than anywhere else in this
//! kernel, because a scancode table is exactly the kind of dull data that is
//! never checked and is wrong in one entry.
//!
//! # Set 1, and only what a shell needs
//!
//! The controller is left in its power-on translation mode, so what arrives is
//! set 1: a make code, and the same code with bit 7 set when the key is
//! released. Everything a shell needs is here — the printable set, `Enter`,
//! `Backspace`, `Tab`, both shifts, caps lock, and `Ctrl` for `^C` and `^D`.
//!
//! What is deliberately *not* here is as important. `0xE0` introduces an
//! extended key; the arrows are mapped to the escape sequences a terminal
//! sends, and every other extended code is **dropped rather than guessed at**.
//! A wrong guess in this table does not fail loudly, it types a character
//! nobody pressed.

/// What one scancode produced.
///
/// Up to three bytes, because an arrow key is an escape sequence and a ring of
/// bytes cannot be handed a key. Inline rather than allocated: this is built
/// in an interrupt handler.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Emitted {
    bytes: [u8; 3],
    length: u8,
}

impl Emitted {
    /// The bytes to publish, in order.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.length as usize]
    }

    const fn one(byte: u8) -> Self {
        Self {
            bytes: [byte, 0, 0],
            length: 1,
        }
    }

    const fn escape(final_byte: u8) -> Self {
        Self {
            bytes: [0x1b, b'[', final_byte],
            length: 3,
        }
    }
}

/// The modifier state a keyboard carries between scancodes.
///
/// A scancode means nothing on its own: `0x1e` is `a`, `A` or `^A` depending on
/// what is being held and what was toggled. That state lives here rather than
/// in a static, so the tests can hold several independent keyboards and so
/// nothing about it is global.
#[derive(Clone, Copy, Default, Debug)]
pub struct Keys {
    shift: bool,
    caps: bool,
    ctrl: bool,
    /// Set by `0xE0`, consumed by the byte after it.
    extended: bool,
}

/// Scancode set 1, unshifted, for the contiguous run this table covers.
///
/// Index is the make code. A zero means "nothing printable", which is not the
/// same as an unknown code — `0x1d` is left control and lands here as zero
/// because it is handled as a modifier before the table is consulted.
const UNSHIFTED: [u8; 0x40] = [
    0, 0x1b, b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'0', b'-', b'=', 0x08, b'\t',
    b'q', b'w', b'e', b'r', b't', b'y', b'u', b'i', b'o', b'p', b'[', b']', b'\n', 0, b'a', b's',
    b'd', b'f', b'g', b'h', b'j', b'k', b'l', b';', b'\'', b'`', 0, b'\\', b'z', b'x', b'c', b'v',
    b'b', b'n', b'm', b',', b'.', b'/', 0, b'*', 0, b' ', 0, 0, 0, 0, 0, 0,
];

/// The same run with shift held.
///
/// A separate table rather than a transformation, because the punctuation is
/// not derivable: `2` shifts to `@` and `'` to `"` by convention, not by rule.
const SHIFTED: [u8; 0x40] = [
    0, 0x1b, b'!', b'@', b'#', b'$', b'%', b'^', b'&', b'*', b'(', b')', b'_', b'+', 0x08, b'\t',
    b'Q', b'W', b'E', b'R', b'T', b'Y', b'U', b'I', b'O', b'P', b'{', b'}', b'\n', 0, b'A', b'S',
    b'D', b'F', b'G', b'H', b'J', b'K', b'L', b':', b'"', b'~', 0, b'|', b'Z', b'X', b'C', b'V',
    b'B', b'N', b'M', b'<', b'>', b'?', 0, b'*', 0, b' ', 0, 0, 0, 0, 0, 0,
];

const LEFT_SHIFT: u8 = 0x2a;
const RIGHT_SHIFT: u8 = 0x36;
const CTRL: u8 = 0x1d;
const CAPS_LOCK: u8 = 0x3a;
const EXTENDED_PREFIX: u8 = 0xe0;
const BREAK_BIT: u8 = 0x80;

impl Keys {
    /// A keyboard with nothing held and nothing toggled.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            shift: false,
            caps: false,
            ctrl: false,
            extended: false,
        }
    }

    /// Feeds one scancode, and answers what it produced.
    ///
    /// `None` for a key that produces nothing: every release, every modifier,
    /// the `0xE0` prefix itself, and every extended code this module refuses to
    /// guess at.
    pub fn feed(&mut self, code: u8) -> Option<Emitted> {
        if code == EXTENDED_PREFIX {
            self.extended = true;
            return None;
        }

        let released = code & BREAK_BIT != 0;
        let make = code & !BREAK_BIT;

        if core::mem::take(&mut self.extended) {
            // Extended keys share make codes with unextended ones -- `0x1d` is
            // left control unextended and *right* control extended -- so this
            // must be decided before the table below, or a right-control press
            // would be looked up as an ordinary key.
            return self.extended_key(make, released);
        }

        match make {
            LEFT_SHIFT | RIGHT_SHIFT => {
                self.shift = !released;
                return None;
            }
            CTRL => {
                self.ctrl = !released;
                return None;
            }
            // On press only: a toggle that also fired on release would undo
            // itself and never toggle anything.
            CAPS_LOCK if !released => {
                self.caps = !self.caps;
                return None;
            }
            _ => {}
        }

        if released {
            return None;
        }

        let index = make as usize;
        if index >= UNSHIFTED.len() {
            return None;
        }
        let base = if self.shift {
            SHIFTED[index]
        } else {
            UNSHIFTED[index]
        };
        if base == 0 {
            return None;
        }

        // Caps lock applies to letters and to nothing else -- a machine where
        // caps lock turned `1` into `!` would be its own kind of surprising.
        let byte = if self.caps && base.is_ascii_alphabetic() {
            if self.shift {
                base.to_ascii_lowercase()
            } else {
                base.to_ascii_uppercase()
            }
        } else {
            base
        };

        if self.ctrl {
            // `^A` is 1, `^C` is 3, `^D` is 4: the letter with the top three
            // bits cleared, which is what a terminal has always sent.
            if byte.is_ascii_alphabetic() {
                return Some(Emitted::one(byte.to_ascii_uppercase() - b'@'));
            }
            // Control plus something that is not a letter has no agreed
            // meaning here, and inventing one would put a byte in the ring
            // that nobody typed.
            return None;
        }

        Some(Emitted::one(byte))
    }

    /// The `0xE0` set, of which only the arrows are answered.
    fn extended_key(&mut self, make: u8, released: bool) -> Option<Emitted> {
        // Right control is a modifier like the left one, and is the reason
        // this arm exists at all rather than dropping every extended code.
        if make == CTRL {
            self.ctrl = !released;
            return None;
        }
        if released {
            return None;
        }
        match make {
            0x48 => Some(Emitted::escape(b'A')),
            0x50 => Some(Emitted::escape(b'B')),
            0x4d => Some(Emitted::escape(b'C')),
            0x4b => Some(Emitted::escape(b'D')),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// The controller.
// ---------------------------------------------------------------------------

use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};

use bhaskix_arch::port::Port;

/// The legacy ISA interrupt an i8042 keyboard raises.
pub const KEYBOARD_IRQ: u8 = 1;

/// Distinguishes this source from the serial line on the shared notification.
pub const BADGE: u64 = 2;

/// Data port: scancodes out, commands to the *device* in.
const DATA: Port<u8> = Port::new(0x60);
/// Read for status, written for commands to the *controller*.
const COMMAND: Port<u8> = Port::new(0x64);

/// Status bit: there is a byte to read.
const OUTPUT_FULL: u8 = 1 << 0;
/// Status bit: the controller has not consumed the last byte written to it.
const INPUT_FULL: u8 = 1 << 1;

/// Controller commands used here.
const READ_CONFIG: u8 = 0x20;
const WRITE_CONFIG: u8 = 0x60;
const SELF_TEST: u8 = 0xaa;
const SELF_TEST_PASSED: u8 = 0x55;
const ENABLE_FIRST_PORT: u8 = 0xae;

/// Config bits: raise IRQ 1 on a byte, and do not hold the first port disabled.
const CONFIG_FIRST_PORT_INTERRUPT: u8 = 1 << 0;
const CONFIG_FIRST_PORT_DISABLED: u8 = 1 << 4;
/// Config bit: translate the keyboard's set 2 into set 1 in the controller.
///
/// **Set explicitly rather than assumed, and that is not a detail.** The tables
/// in this module are set 1. A keyboard actually speaks set 2, and it is the
/// controller's translation bit that makes the difference invisible — a bit
/// firmware is free to leave either way, and which UEFI on a machine that never
/// used the legacy port has no reason to have set.
///
/// Left to chance, the failure is not a dead keyboard, which would at least be
/// obvious. It is a keyboard where every key types the wrong character.
const CONFIG_TRANSLATE: u8 = 1 << 6;

/// How many status reads a wait will do before giving up.
///
/// **The bound is the whole reason this is safe to run on an unknown machine.**
/// A controller that is not there never clears the bit being waited on, and an
/// unbounded wait for it is a boot that stops with no message. The number is
/// large enough that no real controller reaches it and small enough that a
/// machine without one is delayed imperceptibly.
const SPIN_LIMIT: u32 = 100_000;

/// Whether a controller answered its self-test.
static PRESENT: AtomicBool = AtomicBool::new(false);
/// The claimed handler, packed so it can live in an atomic; `u64::MAX` is none.
static HANDLER: AtomicU64 = AtomicU64::new(u64::MAX);
/// Modifier state between scancodes, packed.
///
/// An atomic rather than a lock: this is touched only by the reader thread
/// draining the port, exactly as the UART's drain is, so there is no second
/// writer to exclude and a lock would buy nothing but a rank to order.
static MODIFIERS: AtomicU8 = AtomicU8::new(0);
/// Scancodes read.
static SCANCODES: AtomicU64 = AtomicU64::new(0);

impl Keys {
    /// Packs the modifier state into a byte.
    #[must_use]
    pub const fn to_bits(self) -> u8 {
        (self.shift as u8)
            | (self.caps as u8) << 1
            | (self.ctrl as u8) << 2
            | (self.extended as u8) << 3
    }

    /// Unpacks what [`Keys::to_bits`] wrote.
    #[must_use]
    pub const fn from_bits(bits: u8) -> Self {
        Self {
            shift: bits & 1 != 0,
            caps: bits & 2 != 0,
            ctrl: bits & 4 != 0,
            extended: bits & 8 != 0,
        }
    }
}

/// Reads the status register.
fn status() -> u8 {
    // SAFETY: a read of the i8042 status port, which has no side effects and
    // is safe on a machine without one -- an absent port reads as 0xff, which
    // this code treats as "busy" and gives up on rather than trusting.
    unsafe { COMMAND.read() }
}

/// Waits until the controller will accept a byte. Answers whether it did.
fn wait_writable() -> bool {
    for _ in 0..SPIN_LIMIT {
        if status() & INPUT_FULL == 0 {
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

/// Waits until there is a byte to read. Answers whether one arrived.
fn wait_readable() -> bool {
    for _ in 0..SPIN_LIMIT {
        if status() & OUTPUT_FULL != 0 {
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

/// Sends a controller command, answering whether it was accepted.
fn command(byte: u8) -> bool {
    if !wait_writable() {
        return false;
    }
    // SAFETY: a write to the i8042 command port after its input buffer was
    // observed empty, which is the documented handshake.
    unsafe { COMMAND.write(byte) };
    true
}

/// Takes one byte from the data port, if there is one.
fn read_data() -> Option<u8> {
    if status() & OUTPUT_FULL == 0 {
        return None;
    }
    // SAFETY: a read of the data port with the status register saying a byte
    // is there; reading is what clears the condition.
    Some(unsafe { DATA.read() })
}

/// Empties whatever the controller was holding.
///
/// Before the self-test, because a byte left over from the firmware would be
/// read as the test's answer and fail a controller that is working.
fn flush() {
    for _ in 0..16 {
        if read_data().is_none() {
            return;
        }
    }
}

/// Asks the controller to test itself, and enables the keyboard if it passes.
///
/// Answers whether a controller is there. Everything here is bounded: a
/// machine with no i8042 returns `false` after a fixed number of reads.
fn probe() -> bool {
    flush();

    if !command(SELF_TEST) || !wait_readable() {
        return false;
    }
    if read_data() != Some(SELF_TEST_PASSED) {
        return false;
    }

    // A controller can pass its self-test with the keyboard port switched off,
    // its interrupt masked, and its translation disabled -- which is how some
    // firmware leaves it, having used the keyboard itself and then tidied up.
    // All three are undone here. The first two absent look like a dead
    // keyboard; the third absent looks like a keyboard typing gibberish, which
    // is worse, because it is the one nobody suspects the controller for.
    if !command(ENABLE_FIRST_PORT) {
        return false;
    }
    if !command(READ_CONFIG) || !wait_readable() {
        return false;
    }
    let Some(config) = read_data() else {
        return false;
    };
    let wanted =
        (config | CONFIG_FIRST_PORT_INTERRUPT | CONFIG_TRANSLATE) & !CONFIG_FIRST_PORT_DISABLED;
    if !command(WRITE_CONFIG) || !wait_writable() {
        return false;
    }
    // SAFETY: the config byte follows its command, with the input buffer
    // observed empty between the two.
    unsafe { DATA.write(wanted) };
    true
}

/// Probes for a keyboard and, if there is one, claims its interrupt.
///
/// Binds to the notification the console already waits on, with its own badge,
/// so there is still exactly one reader for two sources.
///
/// # Errors
///
/// Returns `Err` describing why there is no keyboard. Every one of them is
/// survivable — the machine boots and is still reachable over serial — and
/// saying which is the difference between a laptop that is diagnosable and one
/// that is merely silent.
///
/// # Safety
///
/// Must be called once, during boot, after the interrupt controller is up.
pub unsafe fn install(
    apic_id: u32,
    rsdp: Option<bhaskix_boot::PhysAddr>,
    hhdm: u64,
    notification: crate::notify::NotificationId,
) -> Result<u8, &'static str> {
    if !probe() {
        return Err("no i8042 controller answered");
    }
    PRESENT.store(true, Ordering::Release);

    // SAFETY: `trap` dispatches claimed vectors to `irq::on_interrupt`, which
    // acknowledges the local APIC.
    let handler = unsafe {
        crate::irq::claim(
            crate::irq::Source::Line {
                gsi: crate::irq::isa_to_gsi(rsdp, hhdm, KEYBOARD_IRQ),
            },
            "keyboard",
            apic_id,
            rsdp,
            hhdm,
        )
    }
    .map_err(|_| "the keyboard line could not be claimed")?;

    crate::irq::bind(handler, notification, BADGE)
        .map_err(|_| "the notification would not bind")?;

    let vector = crate::irq::vector_of(handler).unwrap_or(0);
    HANDLER.store(crate::irq::handler_raw(handler), Ordering::Release);
    Ok(vector)
}

/// Drains the controller, translates what it held, and acknowledges.
///
/// Drain before acknowledge, which is `docs/driver-model.md` §2's rule and not
/// a preference: between delivery and the acknowledgement the source is
/// masked, and an edge raised while masked is lost. A keyboard that stops
/// after one keypress is this rule broken.
pub fn service() -> usize {
    if !PRESENT.load(Ordering::Acquire) {
        return 0;
    }
    let mut keys = Keys::from_bits(MODIFIERS.load(Ordering::Relaxed));
    let mut taken = 0;
    while let Some(code) = read_data() {
        taken += 1;
        if let Some(emitted) = keys.feed(code) {
            crate::input::keyboard_produced(emitted.as_slice());
        }
    }
    MODIFIERS.store(keys.to_bits(), Ordering::Relaxed);
    SCANCODES.fetch_add(taken as u64, Ordering::Relaxed);

    let raw = HANDLER.load(Ordering::Acquire);
    if raw != u64::MAX {
        let _ = crate::irq::acknowledge(crate::irq::handler_from_raw(raw));
    }
    taken
}

/// Whether a controller answered at boot.
#[must_use]
pub fn present() -> bool {
    PRESENT.load(Ordering::Acquire)
}

/// How many scancodes have been read.
#[must_use]
pub fn scancodes() -> u64 {
    SCANCODES.load(Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Feeds a run of scancodes and collects everything they produced.
    fn typed(codes: &[u8]) -> alloc::vec::Vec<u8> {
        let mut keys = Keys::new();
        let mut out = alloc::vec::Vec::new();
        for code in codes {
            if let Some(emitted) = keys.feed(*code) {
                out.extend_from_slice(emitted.as_slice());
            }
        }
        out
    }

    #[test]
    fn a_press_types_and_a_release_does_not() {
        // `a` down, `a` up. One byte, not two.
        assert_eq!(typed(&[0x1e, 0x1e | BREAK_BIT]), b"a");
    }

    #[test]
    fn shift_is_held_and_then_let_go() {
        // shift down, a, shift up, a -- so the modifier must survive between
        // scancodes and must stop applying when released.
        assert_eq!(
            typed(&[LEFT_SHIFT, 0x1e, LEFT_SHIFT | BREAK_BIT, 0x1e]),
            b"Aa"
        );
    }

    #[test]
    fn caps_lock_toggles_letters_only() {
        // caps on, `a`, `1`, caps off, `a`. The digit is untouched by caps,
        // which is the one thing a shift table would get wrong if reused.
        assert_eq!(
            typed(&[
                CAPS_LOCK,
                0x1e,
                0x02,
                CAPS_LOCK | BREAK_BIT,
                CAPS_LOCK,
                0x1e
            ]),
            b"A1a"
        );
    }

    #[test]
    fn caps_and_shift_together_give_lower_case() {
        assert_eq!(typed(&[CAPS_LOCK, LEFT_SHIFT, 0x1e]), b"a");
    }

    #[test]
    fn control_c_and_control_d_are_what_a_shell_expects() {
        assert_eq!(typed(&[CTRL, 0x2e]), &[3]); // ^C
        assert_eq!(typed(&[CTRL, 0x20]), &[4]); // ^D
    }

    #[test]
    fn control_with_a_digit_produces_nothing_rather_than_a_guess() {
        assert_eq!(typed(&[CTRL, 0x02]), b"");
    }

    #[test]
    fn the_extended_prefix_is_consumed_by_the_byte_after_it() {
        // Up, down, right, left as a terminal sends them.
        assert_eq!(
            typed(&[EXTENDED_PREFIX, 0x48, EXTENDED_PREFIX, 0x50]),
            b"\x1b[A\x1b[B"
        );
        assert_eq!(
            typed(&[EXTENDED_PREFIX, 0x4d, EXTENDED_PREFIX, 0x4b]),
            b"\x1b[C\x1b[D"
        );
    }

    #[test]
    fn an_extended_code_this_module_does_not_know_types_nothing() {
        // `0xE0 0x5b` is the left meta key. Dropped, and -- the point of the
        // test -- it must not be looked up in the ordinary table, where `0x5b`
        // would fall past the end and `0x1b` would have been an escape.
        assert_eq!(typed(&[EXTENDED_PREFIX, 0x5b]), b"");
    }

    #[test]
    fn right_control_is_a_modifier_even_though_it_arrives_extended() {
        // e0 1d is right control; it shares its make code with left control,
        // which is why the extended arm has to run first.
        assert_eq!(typed(&[EXTENDED_PREFIX, CTRL, 0x2e]), &[3]);
    }

    #[test]
    fn enter_tab_backspace_and_space_are_the_bytes_a_line_editor_reads() {
        assert_eq!(typed(&[0x1c]), b"\n");
        assert_eq!(typed(&[0x0f]), b"\t");
        assert_eq!(typed(&[0x0e]), &[0x08]);
        assert_eq!(typed(&[0x39]), b" ");
    }

    #[test]
    fn a_code_past_the_table_is_dropped_rather_than_read_out_of_bounds() {
        // Every make code the table does not cover, pressed. The assertion is
        // that this returns at all: an unchecked index here would be a panic
        // in an interrupt handler.
        for code in 0x40..=0x7fu8 {
            let _ = Keys::new().feed(code);
        }
    }

    #[test]
    fn the_two_tables_agree_on_which_keys_exist() {
        // A key printable in one table and silent in the other is a typo, and
        // this is the only way a typo in a table this dull gets caught.
        for index in 0..UNSHIFTED.len() {
            assert_eq!(
                UNSHIFTED[index] == 0,
                SHIFTED[index] == 0,
                "tables disagree at {index:#04x}"
            );
        }
    }
}
