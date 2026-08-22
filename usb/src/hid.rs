// SPDX-License-Identifier: Apache-2.0
//! The HID boot keyboard: eight bytes, and what they mean.
//!
//! The boot protocol exists so that firmware can drive a keyboard without
//! parsing a report descriptor, and it is why [RFC 0041](../../docs/rfc/0041-a-usb-keyboard.md)
//! can reach a working keyboard without a report-descriptor parser at all.
//!
//! # A report is state, not an event
//!
//! **This is the difference from PS/2 and the thing to get right.** An i8042
//! sends a make code when a key goes down and a break code when it comes up;
//! a HID keyboard sends *the set of keys currently held*, whenever that set
//! changes. Nothing says "pressed" or "released" — a key is newly pressed if it
//! is in this report and was not in the last one.
//!
//! A driver that treats each report as a keystroke repeats every held key on
//! every report. A driver that compares against the previous report does not,
//! which is why [`Keyboard`] keeps one.

/// Bytes in a boot-protocol report.
pub const REPORT_BYTES: usize = 8;

/// Keycodes a single report can carry.
pub const ROLLOVER: usize = 6;

/// The modifier bits in byte 0.
pub mod modifier {
    /// Left control.
    pub const LEFT_CTRL: u8 = 1 << 0;
    /// Left shift.
    pub const LEFT_SHIFT: u8 = 1 << 1;
    /// Left alt.
    pub const LEFT_ALT: u8 = 1 << 2;
    /// Left GUI — the key with a logo on it.
    pub const LEFT_GUI: u8 = 1 << 3;
    /// Right control.
    pub const RIGHT_CTRL: u8 = 1 << 4;
    /// Right shift.
    pub const RIGHT_SHIFT: u8 = 1 << 5;
    /// Right alt.
    pub const RIGHT_ALT: u8 = 1 << 6;
    /// Right GUI.
    pub const RIGHT_GUI: u8 = 1 << 7;
}

/// The usage id a keyboard sends when it has more keys down than it can report.
///
/// **Not a key.** Every keycode slot holds this value, and a driver that
/// translated it would emit six identical characters for a hand resting on the
/// keyboard.
pub const ROLLOVER_ERROR: u8 = 0x01;

/// Usage ids this module translates. USB HID Usage Tables, keyboard page.
mod usage {
    pub const A: u8 = 0x04;
    pub const Z: u8 = 0x1d;
    pub const ONE: u8 = 0x1e;
    pub const NINE: u8 = 0x26;
    pub const ZERO: u8 = 0x27;
    pub const ENTER: u8 = 0x28;
    pub const ESCAPE: u8 = 0x29;
    pub const BACKSPACE: u8 = 0x2a;
    pub const TAB: u8 = 0x2b;
    pub const SPACE: u8 = 0x2c;
    pub const MINUS: u8 = 0x2d;
    pub const EQUAL: u8 = 0x2e;
    pub const LEFT_BRACKET: u8 = 0x2f;
    pub const RIGHT_BRACKET: u8 = 0x30;
    pub const BACKSLASH: u8 = 0x31;
    pub const SEMICOLON: u8 = 0x33;
    pub const APOSTROPHE: u8 = 0x34;
    pub const GRAVE: u8 = 0x35;
    pub const COMMA: u8 = 0x36;
    pub const PERIOD: u8 = 0x37;
    pub const SLASH: u8 = 0x38;
    pub const CAPS_LOCK: u8 = 0x39;
}

/// The unshifted character a punctuation usage id produces.
///
/// Note the gap: `0x32` is the non-US hash key and is deliberately absent, so
/// the punctuation ids are **not** contiguous and a table indexed by
/// `id - MINUS` would put every key after it one place wrong.
const fn punctuation(id: u8, shift: bool) -> Option<u8> {
    let pair = match id {
        usage::MINUS => (b'-', b'_'),
        usage::EQUAL => (b'=', b'+'),
        usage::LEFT_BRACKET => (b'[', b'{'),
        usage::RIGHT_BRACKET => (b']', b'}'),
        usage::BACKSLASH => (b'\\', b'|'),
        usage::SEMICOLON => (b';', b':'),
        usage::APOSTROPHE => (b'\'', b'"'),
        usage::GRAVE => (b'`', b'~'),
        usage::COMMA => (b',', b'<'),
        usage::PERIOD => (b'.', b'>'),
        usage::SLASH => (b'/', b'?'),
        _ => return None,
    };
    Some(if shift { pair.1 } else { pair.0 })
}

/// The digit row, whose shifted characters are conventional rather than derived.
const SHIFTED_DIGITS: [u8; 10] = *b"!@#$%^&*()";

/// The character a usage id produces, given the modifier state.
///
/// `None` for a key this module does not translate — a function key, an arrow,
/// a modifier's own usage id — which a driver must drop rather than guess at.
#[must_use]
pub const fn character(id: u8, shift: bool, caps: bool) -> Option<u8> {
    if id >= usage::A && id <= usage::Z {
        let letter = b'a' + (id - usage::A);
        // Caps lock applies to letters and nothing else, and inverts shift
        // rather than overriding it -- shift with caps on is lower case.
        let upper = shift != caps;
        return Some(if upper { letter - 32 } else { letter });
    }
    if id >= usage::ONE && id <= usage::NINE {
        let index = (id - usage::ONE) as usize;
        return Some(if shift {
            SHIFTED_DIGITS[index]
        } else {
            b'1' + (id - usage::ONE)
        });
    }
    if id == usage::ZERO {
        return Some(if shift { SHIFTED_DIGITS[9] } else { b'0' });
    }
    match id {
        usage::ENTER => Some(b'\n'),
        usage::ESCAPE => Some(0x1b),
        usage::BACKSPACE => Some(0x08),
        usage::TAB => Some(b'\t'),
        usage::SPACE => Some(b' '),
        _ => punctuation(id, shift),
    }
}

/// What one report produced: up to six characters.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Typed {
    bytes: [u8; ROLLOVER],
    length: u8,
}

impl Typed {
    /// The characters, in the order the report listed them.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.length as usize]
    }
}

/// A keyboard, and the last report it sent.
#[derive(Clone, Copy, Default, Debug)]
pub struct Keyboard {
    previous: [u8; ROLLOVER],
    caps: bool,
}

impl Keyboard {
    /// A keyboard with nothing held.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            previous: [0; ROLLOVER],
            caps: false,
        }
    }

    /// Feeds one report, and answers what was newly pressed.
    ///
    /// **Newly**, which is the whole of the boot protocol's difference from a
    /// scancode stream: a key still held from the last report produces nothing,
    /// because it has not been pressed again.
    ///
    /// A report shorter than eight bytes produces nothing. The controller is
    /// told the packet size the endpoint declared, so a short report means the
    /// device sent something other than what it said it would.
    pub fn feed(&mut self, report: &[u8]) -> Typed {
        let mut typed = Typed {
            bytes: [0; ROLLOVER],
            length: 0,
        };
        if report.len() < REPORT_BYTES {
            return typed;
        }
        let modifiers = report[0];
        let keys = &report[2..REPORT_BYTES];

        // A rollover error fills every slot with the same value and means
        // "too many keys"; nothing in it is a keystroke.
        if keys[0] == ROLLOVER_ERROR {
            self.previous = [0; ROLLOVER];
            return typed;
        }

        let shift = modifiers & (modifier::LEFT_SHIFT | modifier::RIGHT_SHIFT) != 0;
        let ctrl = modifiers & (modifier::LEFT_CTRL | modifier::RIGHT_CTRL) != 0;

        for &id in keys {
            if id == 0 {
                continue;
            }
            // Held since the last report: not a new press.
            if self.previous.contains(&id) {
                continue;
            }
            if id == usage::CAPS_LOCK {
                self.caps = !self.caps;
                continue;
            }
            let Some(character) = character(id, shift, self.caps) else {
                continue;
            };
            let emitted = if ctrl {
                // `^A` is 1, as a terminal has always sent -- and control with
                // something that is not a letter has no agreed meaning, so it
                // produces nothing rather than an invention.
                if character.is_ascii_alphabetic() {
                    character.to_ascii_uppercase() - b'@'
                } else {
                    continue;
                }
            } else {
                character
            };
            // Written at the cursor rather than at the key's slot, so the
            // result is contiguous by construction. The first version wrote at
            // the slot and compacted afterwards, which left the length
            // assigned twice -- once in this loop and once by the compaction
            // that overwrote it -- and the first assignment was dead.
            if (typed.length as usize) < ROLLOVER {
                typed.bytes[typed.length as usize] = emitted;
                typed.length += 1;
            }
        }

        self.previous.copy_from_slice(keys);
        typed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(modifiers: u8, keys: &[u8]) -> [u8; REPORT_BYTES] {
        let mut r = [0u8; REPORT_BYTES];
        r[0] = modifiers;
        for (at, &k) in keys.iter().enumerate().take(ROLLOVER) {
            r[2 + at] = k;
        }
        r
    }

    #[test]
    fn a_letter_arrives_once() {
        let mut kb = Keyboard::new();
        assert_eq!(kb.feed(&report(0, &[0x04])).as_slice(), b"a");
    }

    /// **The one that separates a report from a scancode.**
    #[test]
    fn a_key_still_held_does_not_repeat() {
        let mut kb = Keyboard::new();
        assert_eq!(kb.feed(&report(0, &[0x04])).as_slice(), b"a");
        // Same key still down: the device sends the same report again, and it
        // is not a second keystroke.
        assert_eq!(kb.feed(&report(0, &[0x04])).as_slice(), b"");
        // Released, then pressed again: that is a second keystroke.
        assert_eq!(kb.feed(&report(0, &[])).as_slice(), b"");
        assert_eq!(kb.feed(&report(0, &[0x04])).as_slice(), b"a");
    }

    #[test]
    fn a_second_key_pressed_while_the_first_is_held_arrives_alone() {
        let mut kb = Keyboard::new();
        assert_eq!(kb.feed(&report(0, &[0x04])).as_slice(), b"a");
        // `a` still down, `b` newly down.
        assert_eq!(kb.feed(&report(0, &[0x04, 0x05])).as_slice(), b"b");
    }

    #[test]
    fn shift_and_caps_lock_behave_as_they_do_on_a_typewriter() {
        let mut kb = Keyboard::new();
        assert_eq!(
            kb.feed(&report(modifier::LEFT_SHIFT, &[0x04])).as_slice(),
            b"A"
        );
        kb = Keyboard::new();
        // Caps lock down, then `a`.
        kb.feed(&report(0, &[usage::CAPS_LOCK]));
        assert_eq!(kb.feed(&report(0, &[0x04])).as_slice(), b"A");
        // Caps and shift together give lower case.
        kb.feed(&report(0, &[]));
        assert_eq!(
            kb.feed(&report(modifier::LEFT_SHIFT, &[0x04])).as_slice(),
            b"a"
        );
    }

    #[test]
    fn the_right_hand_modifiers_count_too() {
        let mut kb = Keyboard::new();
        assert_eq!(
            kb.feed(&report(modifier::RIGHT_SHIFT, &[0x04])).as_slice(),
            b"A"
        );
        kb = Keyboard::new();
        assert_eq!(
            kb.feed(&report(modifier::RIGHT_CTRL, &[0x06])).as_slice(),
            &[3]
        );
    }

    #[test]
    fn control_c_and_control_d_are_what_a_shell_expects() {
        let mut kb = Keyboard::new();
        assert_eq!(
            kb.feed(&report(modifier::LEFT_CTRL, &[0x06])).as_slice(),
            &[3]
        );
        kb = Keyboard::new();
        assert_eq!(
            kb.feed(&report(modifier::LEFT_CTRL, &[0x07])).as_slice(),
            &[4]
        );
        // Control with a digit produces nothing rather than a guess.
        kb = Keyboard::new();
        assert_eq!(
            kb.feed(&report(modifier::LEFT_CTRL, &[usage::ONE]))
                .as_slice(),
            b""
        );
    }

    /// **Rollover is not six keystrokes.**
    #[test]
    fn a_rollover_error_types_nothing() {
        let mut kb = Keyboard::new();
        let all = report(0, &[ROLLOVER_ERROR; ROLLOVER]);
        assert_eq!(kb.feed(&all).as_slice(), b"");
    }

    #[test]
    fn the_digit_row_shifts_by_convention_not_by_arithmetic() {
        let mut kb = Keyboard::new();
        assert_eq!(kb.feed(&report(0, &[usage::ONE])).as_slice(), b"1");
        kb = Keyboard::new();
        assert_eq!(
            kb.feed(&report(modifier::LEFT_SHIFT, &[usage::ONE]))
                .as_slice(),
            b"!"
        );
        kb = Keyboard::new();
        assert_eq!(kb.feed(&report(0, &[usage::ZERO])).as_slice(), b"0");
        kb = Keyboard::new();
        assert_eq!(
            kb.feed(&report(modifier::LEFT_SHIFT, &[usage::ZERO]))
                .as_slice(),
            b")"
        );
    }

    /// **The gap at `0x32` is why punctuation is a match and not a table.**
    #[test]
    fn punctuation_is_not_contiguous_and_is_not_indexed_as_though_it_were() {
        assert_eq!(character(usage::MINUS, false, false), Some(b'-'));
        assert_eq!(character(usage::BACKSLASH, false, false), Some(b'\\'));
        // 0x32 is the non-US hash key: not translated, and it sits between
        // backslash and semicolon.
        assert_eq!(character(0x32, false, false), None);
        assert_eq!(character(usage::SEMICOLON, false, false), Some(b';'));
        assert_eq!(character(usage::SLASH, true, false), Some(b'?'));
    }

    #[test]
    fn keys_this_module_does_not_know_are_dropped() {
        // F1 is 0x3a; arrows are 0x4f..0x52. None are characters, and guessing
        // would put bytes nobody typed into the console.
        let mut kb = Keyboard::new();
        assert_eq!(kb.feed(&report(0, &[0x3a])).as_slice(), b"");
        kb = Keyboard::new();
        assert_eq!(kb.feed(&report(0, &[0x4f])).as_slice(), b"");
    }

    #[test]
    fn a_short_report_produces_nothing_rather_than_reading_past_it() {
        let mut kb = Keyboard::new();
        for length in 0..REPORT_BYTES {
            let short = [0u8; REPORT_BYTES];
            assert_eq!(kb.feed(&short[..length]).as_slice(), b"");
        }
    }

    #[test]
    fn enter_tab_space_and_backspace_are_the_bytes_a_line_editor_reads() {
        let mut kb = Keyboard::new();
        assert_eq!(kb.feed(&report(0, &[usage::ENTER])).as_slice(), b"\n");
        kb = Keyboard::new();
        assert_eq!(kb.feed(&report(0, &[usage::TAB])).as_slice(), b"\t");
        kb = Keyboard::new();
        assert_eq!(kb.feed(&report(0, &[usage::SPACE])).as_slice(), b" ");
        kb = Keyboard::new();
        assert_eq!(kb.feed(&report(0, &[usage::BACKSPACE])).as_slice(), &[0x08]);
    }

    #[test]
    fn every_usage_id_translates_or_declines_without_panicking() {
        // The cheap stand-in for a fuzzer: a device may send any byte.
        let mut kb = Keyboard::new();
        for id in 0..=255u8 {
            for modifiers in [0u8, modifier::LEFT_SHIFT, modifier::LEFT_CTRL, 0xff] {
                let _ = kb.feed(&report(modifiers, &[id]));
                let _ = character(id, true, true);
            }
        }
    }
}
