// SPDX-License-Identifier: Apache-2.0
//! Finding an xHCI controller, and refusing to drive one that is not caged.
//!
//! [RFC 0041](../../docs/rfc/0041-a-usb-keyboard.md) step 2, and it is
//! deliberately the *first* step that touches hardware — because the rule it
//! implements is the one that stops being addable later.
//!
//! # No translation, no driver
//!
//! An xHCI controller is a **bus master**. It reads and writes physical memory
//! itself, on its own initiative, at addresses it was handed, by a path that
//! goes through neither page tables nor capabilities. Every guarantee in
//! `docs/architecture.md` is a statement about what *code* can reach, and DMA
//! is not code.
//!
//! So this module finds controllers and then, before a single register is read,
//! asks whether each one is behind an IOMMU translation. One that is not is
//! **refused**: not warned about, not driven in a degraded mode, refused. A
//! machine with no IOMMU gets no USB, and that is the correct trade against a
//! device with unmediated access to all of memory.
//!
//! RFC 0038's security section lists six rules for any driver built on the
//! vendored layouts. This is the first, and it is first because a driver that
//! works without translation is a driver nobody will later be able to make
//! require it.

use bhaskix_arch::pci;

/// PCI class for a serial bus controller.
const CLASS_SERIAL_BUS: u8 = 0x0c;
/// Subclass for USB.
const SUBCLASS_USB: u8 = 0x03;
/// Programming interface for xHCI, as opposed to UHCI, OHCI or EHCI.
///
/// The class and subclass alone say "a USB controller of some kind"; this byte
/// is what says the register layout is the one RFC 0038 vendored. Driving an
/// EHCI controller with xHCI's offsets would be writing arbitrary values into
/// arbitrary registers of a bus master.
const PROG_IF_XHCI: u8 = 0x30;
/// Where the programming interface lives in configuration space.
const PROG_IF_OFFSET: u8 = 0x09;

/// The most controllers this module will report on.
///
/// A bound rather than a `Vec`: this runs during boot, before there is a reason
/// to allocate, and a machine with more than this many xHCI controllers is one
/// whose extras can go unreported until somebody has one.
const MAX_CONTROLLERS: usize = 4;

/// One controller, and whether it may be driven.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Controller {
    /// Where it is.
    pub bus: u8,
    /// Device number.
    pub device: u8,
    /// Function number.
    pub function: u8,
    /// Who made it.
    pub vendor: u16,
    /// What it is.
    pub id: u16,
    /// Whether an IOMMU translates for it.
    ///
    /// **The only field that decides anything.** False means this controller is
    /// not driven, whatever else is true of it.
    pub translated: bool,
}

/// What a scan found.
#[derive(Clone, Copy, Debug)]
pub struct Found {
    controllers: [Option<Controller>; MAX_CONTROLLERS],
    /// How many were seen, including any past [`MAX_CONTROLLERS`].
    pub seen: usize,
}

impl Found {
    /// The controllers this scan recorded.
    pub fn iter(&self) -> impl Iterator<Item = &Controller> {
        self.controllers.iter().flatten()
    }

    /// The first controller that may be driven, if any.
    ///
    /// **Only a translated one is ever answered.** A caller cannot reach an
    /// untranslated controller through this type, which is the point of
    /// answering a type rather than a list.
    #[must_use]
    pub fn drivable(&self) -> Option<Controller> {
        self.iter().copied().find(|c| c.translated)
    }

    /// How many were found but refused for want of translation.
    #[must_use]
    pub fn refused(&self) -> usize {
        self.iter().filter(|c| !c.translated).count()
    }
}

/// Finds every xHCI controller, and asks the IOMMU about each.
///
/// # Safety
///
/// Must be called once during boot, after PCI configuration access works and
/// after the IOMMU has been discovered — asking before the windows exist would
/// read "untranslated" for a device that is about to be caged, and refuse a
/// controller that should have been driven.
#[must_use]
pub unsafe fn discover() -> Found {
    let mut found = Found {
        controllers: [None; MAX_CONTROLLERS],
        seen: 0,
    };
    let mut at = 0;

    // The closure is defined outside the `unsafe` block that calls
    // `for_each`, so that the one unsafe operation inside it -- reading the
    // programming interface byte -- carries its own justification rather than
    // inheriting one from six lines away.
    let mut visit = |address: pci::Address, identity: pci::Identity| {
        if identity.class != CLASS_SERIAL_BUS || identity.subclass != SUBCLASS_USB {
            return true;
        }
        // SAFETY: one byte of configuration space, at a fixed offset, on a
        // function `for_each` has already found present.
        let prog_if = unsafe { pci::read8(address, PROG_IF_OFFSET) };
        if prog_if != PROG_IF_XHCI {
            // A USB controller of some other generation. Not this driver's,
            // and reading it with xHCI's offsets would be writing into a bus
            // master's registers at random.
            return true;
        }

        found.seen += 1;
        if at < MAX_CONTROLLERS {
            found.controllers[at] = Some(Controller {
                bus: address.bus,
                device: address.device,
                function: address.function,
                vendor: identity.vendor,
                id: identity.device,
                translated: crate::iommu::present_for((
                    address.bus,
                    address.device,
                    address.function,
                )),
            });
            at += 1;
        }
        true
    };

    // SAFETY: the caller's obligation; `for_each` reads configuration space
    // only, and the closure above adds one further configuration read.
    unsafe { pci::for_each(&mut visit) };
    found
}

/// Prints what was found, and what will be done about it.
///
/// Both halves are said out loud. A refused controller is the difference
/// between "this machine has no USB keyboard" and "this machine has a USB
/// keyboard nobody can explain", and an operator standing at it deserves the
/// first.
pub fn report(found: &Found) {
    if found.seen == 0 {
        crate::println!("    xhci           none found");
        return;
    }
    for controller in found.iter() {
        if controller.translated {
            crate::println!(
                "    xhci           {:02x}:{:02x}.{} {:04x}:{:04x}, translated",
                controller.bus,
                controller.device,
                controller.function,
                controller.vendor,
                controller.id
            );
        } else {
            crate::println!(
                "\x1b[93m    xhci           {:02x}:{:02x}.{} {:04x}:{:04x} REFUSED: no iommu \
                 translation, and a bus master without one can read and write all of memory\x1b[0m",
                controller.bus,
                controller.device,
                controller.function,
                controller.vendor,
                controller.id
            );
        }
    }
    if found.seen > MAX_CONTROLLERS {
        crate::println!(
            "    xhci           {} more not recorded; this kernel reports at most {}",
            found.seen - MAX_CONTROLLERS,
            MAX_CONTROLLERS
        );
    }
}

#[cfg(test)]
mod ring_tests {
    use super::ring::{Consumer, Producer};

    #[test]
    fn a_ring_too_small_for_a_link_and_work_is_refused() {
        assert!(Producer::new(0).is_none());
        assert!(Producer::new(1).is_none());
        assert!(Producer::new(2).is_some());
        assert!(Consumer::new(0).is_none());
    }

    #[test]
    fn a_producer_starts_with_the_cycle_set_because_the_ring_starts_zeroed() {
        // Fresh memory reads 0 in every cycle bit. The producer publishes with
        // 1, and the controller starts expecting 1, so it consumes exactly what
        // has been written. Starting at 0 would make the whole ring look
        // already-published.
        let p = Producer::new(256).expect("valid");
        assert!(p.cycle());
        assert_eq!(p.index(), 0);
    }

    /// **The wrap rule, which is the bug this module exists to prevent.**
    #[test]
    fn the_cycle_flips_exactly_once_per_lap_and_never_lands_on_the_link() {
        const ENTRIES: usize = 8;
        let mut p = Producer::new(ENTRIES).expect("valid");
        let link = p.link_index();
        assert_eq!(link, ENTRIES - 1);

        let mut flips = 0;
        let mut previous = p.cycle();
        // Four laps' worth of writes.
        for _ in 0..(ENTRIES - 1) * 4 {
            // The producer must never offer the link entry as a place to write:
            // doing so overwrites the wrap and the controller runs off the end.
            assert_ne!(p.index(), link, "the link is not a work entry");
            p.advance();
            if p.cycle() != previous {
                flips += 1;
                previous = p.cycle();
            }
        }
        assert_eq!(flips, 4, "one flip per lap, no more and no fewer");
        // Four flips returns the state to where it started.
        assert!(p.cycle());
        assert_eq!(p.index(), 0);
    }

    #[test]
    fn remaining_this_lap_counts_down_to_the_link() {
        let mut p = Producer::new(4).expect("valid");
        assert_eq!(p.remaining_this_lap(), 3);
        p.advance();
        assert_eq!(p.remaining_this_lap(), 2);
        p.advance();
        assert_eq!(p.remaining_this_lap(), 1);
        p.advance();
        // Wrapped: a full lap again.
        assert_eq!(p.remaining_this_lap(), 3);
        assert_eq!(p.index(), 0);
    }

    /// **An event ring has no link TRB**, so it wraps one entry later than a
    /// command ring of the same size. Using the producer's arithmetic here
    /// would skip the last event of every lap, for ever.
    #[test]
    fn the_event_ring_wraps_at_its_last_entry_not_before_it() {
        const ENTRIES: usize = 4;
        let mut c = Consumer::new(ENTRIES).expect("valid");
        let mut seen = 0;
        for _ in 0..ENTRIES {
            assert!(c.owns(true), "the first lap is cycle 1");
            seen += 1;
            c.advance();
        }
        assert_eq!(seen, ENTRIES, "every entry is a work entry");
        // One full lap: back to the start with the cycle flipped.
        assert_eq!(c.index(), 0);
        assert!(!c.owns(true), "lap two expects cycle 0");
        assert!(c.owns(false));
    }

    #[test]
    fn a_consumer_stops_at_an_entry_the_producer_has_not_written() {
        let c = Consumer::new(16).expect("valid");
        // Fresh ring: every cycle bit is 0, the consumer expects 1, so it owns
        // nothing and waits -- which is what an empty event ring must look
        // like.
        assert!(!c.owns(false));
        assert!(c.owns(true));
    }

    #[test]
    fn producer_and_consumer_disagree_about_the_link_by_exactly_one() {
        // Same entry count, different wrap points: the asymmetry stated once,
        // as a test, so that a future refactor that unifies them fails here.
        const ENTRIES: usize = 32;
        let mut p = Producer::new(ENTRIES).expect("valid");
        let mut c = Consumer::new(ENTRIES).expect("valid");
        let mut producer_steps = 0;
        while {
            p.advance();
            producer_steps += 1;
            p.index() != 0
        } {}
        let mut consumer_steps = 0;
        while {
            c.advance();
            consumer_steps += 1;
            c.index() != 0
        } {}
        assert_eq!(producer_steps, ENTRIES - 1);
        assert_eq!(consumer_steps, ENTRIES);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn controller(translated: bool) -> Controller {
        Controller {
            bus: 0,
            device: 1,
            function: 0,
            vendor: 0x1b36,
            id: 0x000d,
            translated,
        }
    }

    fn found(of: &[Controller]) -> Found {
        let mut f = Found {
            controllers: [None; MAX_CONTROLLERS],
            seen: of.len(),
        };
        for (at, c) in of.iter().enumerate().take(MAX_CONTROLLERS) {
            f.controllers[at] = Some(*c);
        }
        f
    }

    /// **Rule 1, as a property of the type.**
    #[test]
    fn an_untranslated_controller_is_never_answered_as_drivable() {
        let f = found(&[controller(false)]);
        assert_eq!(f.drivable(), None);
        assert_eq!(f.refused(), 1);
    }

    #[test]
    fn a_translated_controller_is_the_one_answered() {
        let f = found(&[controller(false), controller(true)]);
        let picked = f.drivable().expect("one is translated");
        assert!(picked.translated);
        assert_eq!(f.refused(), 1);
    }

    #[test]
    fn no_controllers_means_nothing_to_drive_rather_than_a_default() {
        let f = found(&[]);
        assert_eq!(f.drivable(), None);
        assert_eq!(f.refused(), 0);
        assert_eq!(f.seen, 0);
    }

    #[test]
    fn more_controllers_than_the_bound_are_counted_even_when_not_recorded() {
        // `seen` is the truth; the array is what fits. A machine with five
        // should not be reported as having four.
        let mut f = found(&[controller(true); MAX_CONTROLLERS]);
        f.seen = MAX_CONTROLLERS + 1;
        assert_eq!(f.iter().count(), MAX_CONTROLLERS);
        assert_eq!(f.seen, MAX_CONTROLLERS + 1);
    }

    #[test]
    fn the_programming_interface_is_what_separates_xhci_from_its_predecessors() {
        // Class and subclass say "USB"; only this byte says the registers are
        // the ones RFC 0038 vendored.
        assert_eq!(CLASS_SERIAL_BUS, 0x0c);
        assert_eq!(SUBCLASS_USB, 0x03);
        assert_eq!(PROG_IF_XHCI, 0x30);
        assert_eq!(PROG_IF_OFFSET, 0x09);
    }
}

/// Walking a ring, on both sides of it.
///
/// The TRBs and the cycle rule are `bhaskix_xhci`'s, vendored and adapted. What
/// is here is the *cursor*: whose turn it is, where the next entry goes, and
/// when the cycle state flips. That is this project's own logic, it is where a
/// cycle-bit bug would live, and it is pure state — so it is tested
/// exhaustively on the host rather than inferred from a controller's silence.
pub mod ring {
    use bhaskix_xhci::trb;

    /// The producer's place in a command or transfer ring.
    ///
    /// The driver is the producer on these: it writes TRBs and the controller
    /// consumes them.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub struct Producer {
        entries: usize,
        index: usize,
        cycle: bool,
    }

    impl Producer {
        /// A producer at the start of a ring of `entries` TRBs.
        ///
        /// **Starts with the cycle state set**, because a freshly allocated
        /// ring is all zeroes: every entry's cycle bit reads 0, so the producer
        /// publishes with 1 and the controller — which also starts at 1 — sees
        /// exactly the entries that have been written.
        ///
        /// # Errors
        ///
        /// `None` for a ring too small to hold a link TRB and any work.
        #[must_use]
        pub const fn new(entries: usize) -> Option<Self> {
            if trb::usable_entries(entries).is_none() {
                return None;
            }
            Some(Self {
                entries,
                index: 0,
                cycle: true,
            })
        }

        /// Where the next TRB goes.
        #[must_use]
        pub const fn index(&self) -> usize {
            self.index
        }

        /// The cycle bit to write into it.
        #[must_use]
        pub const fn cycle(&self) -> bool {
            self.cycle
        }

        /// Which entry holds the link TRB: the last one.
        #[must_use]
        pub const fn link_index(&self) -> usize {
            self.entries - 1
        }

        /// Moves past the entry just written.
        ///
        /// **At the link, the cycle state flips and the index returns to zero.**
        /// That is the whole of the wrap rule: without the flip, the next lap's
        /// entries carry the bit the controller has already consumed and it
        /// reads them as stale — which is a ring that silently stops rather
        /// than one that reports anything.
        pub const fn advance(&mut self) {
            self.index += 1;
            if self.index == self.link_index() {
                // The link is not a work entry: stepping onto it means the lap
                // is done.
                self.index = 0;
                self.cycle = !self.cycle;
            }
        }

        /// How many entries can be written before the next wrap.
        #[must_use]
        pub const fn remaining_this_lap(&self) -> usize {
            self.link_index() - self.index
        }
    }

    /// The driver's place in the event ring, which the controller produces.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub struct Consumer {
        entries: usize,
        index: usize,
        cycle: bool,
    }

    impl Consumer {
        /// A consumer at the start of an event ring of `entries` TRBs.
        ///
        /// **An event ring has no link TRB**, which is the asymmetry to hold on
        /// to: the controller wraps by the segment table, so every entry here
        /// is a work entry and the wrap happens at `entries`, not at
        /// `entries - 1`.
        ///
        /// # Errors
        ///
        /// `None` for an empty ring.
        #[must_use]
        pub const fn new(entries: usize) -> Option<Self> {
            if entries == 0 {
                return None;
            }
            Some(Self {
                entries,
                index: 0,
                cycle: true,
            })
        }

        /// Where the next event would be.
        #[must_use]
        pub const fn index(&self) -> usize {
            self.index
        }

        /// Whether an entry whose cycle bit is `bit` belongs to this consumer.
        #[must_use]
        pub const fn owns(&self, bit: bool) -> bool {
            trb::owned_by_consumer(bit, self.cycle)
        }

        /// Moves past the event just consumed, flipping at the wrap.
        pub const fn advance(&mut self) {
            self.index += 1;
            if self.index == self.entries {
                self.index = 0;
                self.cycle = !self.cycle;
            }
        }
    }
}
