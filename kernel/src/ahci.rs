// SPDX-License-Identifier: Apache-2.0
//! Finding a SATA AHCI controller, and refusing one that may not be driven.
//!
//! [RFC 0046](../../docs/rfc/0046-a-driver-for-hardware-that-exists.md) step 2.
//! Every storage device this system can drive is virtio — a device that exists
//! because an emulator invents it. This is the first half of changing that:
//! *which* controller, and *whether* it may be driven at all.
//!
//! # Why discovery is the kernel's when the driver is not
//!
//! RFC 0046 puts the driver in `bin/ahcid`, in ring 3, holding a `DmaWindow`
//! for its own device. But a window is the kernel's to build, and a window
//! names the device it translates for — so the kernel has to know where the
//! controller is before ring 3 can be given anything. That is the same
//! division `bin/netd` already runs under, and the reason [`probe`] exists
//! beside [`discover`].
//!
//! # The programming interface is the whole filter
//!
//! Class `01` subclass `06` says *SATA controller*. It does **not** say the
//! registers are AHCI's: programming interface `00` is a vendor-specific
//! interface and `02` is a Serial Storage Bus, and driving either with AHCI's
//! offsets is writing arbitrary values into a bus master's registers. RFC 0046
//! names the trap on real hardware: `00:17.0` on the SR550 is class `01.04`,
//! the same family of silicon in RAID mode, and it does not speak AHCI.
//!
//! So the scan classifies before it records, [`classify`] is a pure function of
//! three bytes, and no part of deciding what a function *is* needs a machine.

use bhaskix_arch::pci;
// PCI's own offset for the programming-interface byte, shared with
// `crate::iommu`'s survey rather than written out once per driver: class and
// subclass say what a device is, and this byte says which register layout it
// presents.
use bhaskix_arch::pci::PROG_IF_OFFSET;

/// PCI class for a mass-storage controller.
const CLASS_MASS_STORAGE: u8 = 0x01;
/// Subclass for a SATA controller.
const SUBCLASS_SATA: u8 = 0x06;
/// Subclass for a RAID controller.
///
/// Not this driver's, and recorded anyway: on a machine whose SATA controller
/// has been strapped into RAID mode by its firmware, "no controller found" and
/// "a controller you cannot use in this mode" send an operator to different
/// places. See [`Found::raid`].
const SUBCLASS_RAID: u8 = 0x04;
/// Programming interface for the AHCI register set, as opposed to a
/// vendor-specific one.
const PROG_IF_AHCI: u8 = 0x01;

/// The most controllers this module will report on.
///
/// A bound rather than a `Vec`: this runs during boot, before there is a reason
/// to allocate. A machine with more than this many SATA controllers has its
/// extras counted in [`Found::seen`] and named nowhere, and the report says so
/// rather than pretending it saw everything.
const MAX_CONTROLLERS: usize = 4;

/// What a scan makes of one PCI function.
///
/// Pure, and separated out for that reason: which three bytes mean "drive this"
/// is the decision that a wrong answer turns into register writes on a bus
/// master, and it is answerable without a bus.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    /// Nothing this driver has anything to say about.
    Ignored,
    /// A SATA controller presenting the AHCI register interface.
    Ahci,
    /// A SATA controller presenting something else. Found, named, not driven.
    SataNotAhci,
    /// A mass-storage controller in RAID mode.
    Raid,
}

/// What a function's class, subclass and programming interface make it.
#[must_use]
pub fn classify(class: u8, subclass: u8, prog_if: u8) -> Kind {
    if class != CLASS_MASS_STORAGE {
        return Kind::Ignored;
    }
    match subclass {
        SUBCLASS_SATA if prog_if == PROG_IF_AHCI => Kind::Ahci,
        SUBCLASS_SATA => Kind::SataNotAhci,
        SUBCLASS_RAID => Kind::Raid,
        // SCSI, IDE, floppy, ATA, SAS, NVMe. Mass storage this kernel has no
        // driver for, which is a different sentence from "not AHCI" and is not
        // this module's to say.
        _ => Kind::Ignored,
    }
}

/// One SATA controller, and whether it may be driven.
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
    /// The programming interface byte, as read.
    ///
    /// Kept rather than reduced to a boolean so the refusal can print the
    /// number that caused it. "Not AHCI" sends a reader to the specification;
    /// "programming interface 0x00" sends them to the right line of it.
    pub prog_if: u8,
    /// Whether an IOMMU translates for it.
    pub translated: bool,
}

impl Controller {
    /// Whether its registers are the ones this driver knows.
    #[must_use]
    pub fn is_ahci(&self) -> bool {
        self.prog_if == PROG_IF_AHCI
    }
}

/// Where a mass-storage controller was seen that is not one of these.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Elsewhere {
    /// Bus.
    pub bus: u8,
    /// Device number.
    pub device: u8,
    /// Function number.
    pub function: u8,
    /// Who made it.
    pub vendor: u16,
    /// What it is.
    pub id: u16,
}

/// What a scan found.
#[derive(Clone, Copy, Debug)]
pub struct Found {
    controllers: [Option<Controller>; MAX_CONTROLLERS],
    /// How many SATA controllers were seen, including any past
    /// [`MAX_CONTROLLERS`].
    pub seen: usize,
    /// The first RAID-mode mass-storage controller, if any.
    ///
    /// **Reported, never driven.** RFC 0046's unresolved question 1 asks
    /// whether a disk is attached to the SR550's `00:11.5`; the machine's other
    /// storage sits behind `00:17.0`, class `01.04`, and a boot report that
    /// said "no SATA controller" while a mass-storage controller sat on the bus
    /// would be true and useless.
    pub raid: Option<Elsewhere>,
    /// How many RAID-mode controllers were seen.
    pub raid_seen: usize,
}

impl Found {
    /// An empty scan. The state a machine with no SATA controller is in.
    #[must_use]
    pub fn none() -> Self {
        Self {
            controllers: [None; MAX_CONTROLLERS],
            seen: 0,
            raid: None,
            raid_seen: 0,
        }
    }

    /// The controllers this scan recorded.
    pub fn iter(&self) -> impl Iterator<Item = &Controller> {
        self.controllers.iter().flatten()
    }

    /// The first controller that may be driven, if any.
    ///
    /// **Two conditions, and a caller cannot reach a controller failing either
    /// one through this type.** It must present AHCI's registers, and an IOMMU
    /// must translate for it — RFC 0012's rule, which a storage driver is the
    /// last place to make an exception to.
    #[must_use]
    pub fn drivable(&self) -> Option<Controller> {
        self.iter().copied().find(|c| c.is_ahci() && c.translated)
    }

    /// How many were found and refused, for either reason.
    #[must_use]
    pub fn refused(&self) -> usize {
        self.iter()
            .filter(|c| !c.is_ahci() || !c.translated)
            .count()
    }
}

/// Finds every SATA controller, and asks the IOMMU about each.
///
/// # Safety
///
/// Must be called once during boot, after PCI configuration access works and
/// after the IOMMU windows have been built — asking earlier would read
/// "untranslated" for a device that is about to be caged, and refuse a
/// controller that should have been driven.
#[must_use]
pub unsafe fn discover() -> Found {
    let mut found = Found::none();
    let mut at = 0;

    let mut visit = |address: pci::Address, identity: pci::Identity| {
        if identity.class != CLASS_MASS_STORAGE {
            return true;
        }
        // SAFETY: one byte of configuration space, at a fixed offset, on a
        // function `for_each` has already found present.
        let prog_if = unsafe { pci::read8(address, PROG_IF_OFFSET) };
        match classify(identity.class, identity.subclass, prog_if) {
            Kind::Ignored => return true,
            Kind::Raid => {
                found.raid_seen += 1;
                if found.raid.is_none() {
                    found.raid = Some(Elsewhere {
                        bus: address.bus,
                        device: address.device,
                        function: address.function,
                        vendor: identity.vendor,
                        id: identity.device,
                    });
                }
                return true;
            }
            Kind::Ahci | Kind::SataNotAhci => {}
        }

        found.seen += 1;
        if at < MAX_CONTROLLERS {
            found.controllers[at] = Some(Controller {
                bus: address.bus,
                device: address.device,
                function: address.function,
                vendor: identity.vendor,
                id: identity.device,
                prog_if,
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

/// Where the first AHCI controller is, without asking whether it may be driven.
///
/// The same shape as `virtio::probe` and `xhci::probe`, and here for the same
/// reason: a window has to be built for a controller *before* [`discover`] can
/// answer that it is translated, and building one needs to know which device to
/// build it for. Asking the IOMMU here would answer "untranslated" on every
/// machine, which is the state this function is called to change.
///
/// [`Found::drivable`] remains the only thing that decides.
///
/// # Safety
///
/// As [`discover`]: configuration access must work.
#[must_use]
pub unsafe fn probe() -> Option<(u8, u8, u8)> {
    let mut at = None;
    let mut visit = |address: pci::Address, identity: pci::Identity| {
        if identity.class != CLASS_MASS_STORAGE {
            return true;
        }
        // SAFETY: one byte of configuration space, at a fixed offset, on a
        // function `for_each` has already found present.
        let prog_if = unsafe { pci::read8(address, PROG_IF_OFFSET) };
        if classify(identity.class, identity.subclass, prog_if) != Kind::Ahci {
            return true;
        }
        at = Some((address.bus, address.device, address.function));
        false
    };
    // SAFETY: the caller's obligation; configuration reads only.
    unsafe { pci::for_each(&mut visit) };
    at
}

/// Prints what was found, and what will be done about it.
///
/// Both halves out loud, as `xhci::report` does: a refused controller is the
/// difference between "this machine has no SATA disk" and "this machine has a
/// SATA disk nobody can explain", and an operator standing at it deserves the
/// first.
pub fn report(found: &Found) {
    if found.seen == 0 {
        crate::println!("    ahci           none found");
    }
    for controller in found.iter() {
        if !controller.is_ahci() {
            crate::println!(
                "\x1b[93m    ahci           {:02x}:{:02x}.{} {:04x}:{:04x} REFUSED: programming \
                 interface {:#04x} is not AHCI, and this driver's register offsets would land \
                 somewhere else entirely\x1b[0m",
                controller.bus,
                controller.device,
                controller.function,
                controller.vendor,
                controller.id,
                controller.prog_if
            );
        } else if controller.translated {
            crate::println!(
                "    ahci           {:02x}:{:02x}.{} {:04x}:{:04x}, translated",
                controller.bus,
                controller.device,
                controller.function,
                controller.vendor,
                controller.id
            );
        } else {
            crate::println!(
                "\x1b[93m    ahci           {:02x}:{:02x}.{} {:04x}:{:04x} REFUSED: no iommu \
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
            "    ahci           {} more not recorded; this kernel reports at most {}",
            found.seen - MAX_CONTROLLERS,
            MAX_CONTROLLERS
        );
    }
    if let Some(raid) = found.raid {
        // Deliberately hedged. A class `01.04` function may be a SATA
        // controller its firmware has strapped into RAID mode -- which a
        // firmware setting can undo -- or it may be a RAID adapter that was
        // never AHCI and never will be. Saying which would be guessing, and the
        // address is what sends a reader to the answer.
        crate::println!(
            "    ahci           {:02x}:{:02x}.{} {:04x}:{:04x} is class 01.04, a RAID-mode \
             mass-storage controller this driver does not speak{}",
            raid.bus,
            raid.device,
            raid.function,
            raid.vendor,
            raid.id,
            if found.raid_seen > 1 {
                " (and it is not the only one)"
            } else {
                ""
            }
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn controller(prog_if: u8, translated: bool) -> Controller {
        Controller {
            bus: 0,
            device: 0x1f,
            function: 2,
            vendor: 0x8086,
            id: 0x2922,
            prog_if,
            translated,
        }
    }

    fn found_with(controllers: &[Controller]) -> Found {
        let mut found = Found::none();
        for (at, c) in controllers.iter().enumerate() {
            found.controllers[at] = Some(*c);
            found.seen += 1;
        }
        found
    }

    #[test]
    fn the_class_numbers_are_the_specifications_and_not_a_recollection() {
        // Pinned here so a later edit that "tidies" one of them has to change a
        // test that says what it is. Class 01 is mass storage; subclass 06 is
        // SATA and 04 is RAID; programming interface 01 is the AHCI register
        // set, and 00 is a vendor-specific one.
        assert_eq!(CLASS_MASS_STORAGE, 0x01);
        assert_eq!(SUBCLASS_SATA, 0x06);
        assert_eq!(SUBCLASS_RAID, 0x04);
        assert_eq!(PROG_IF_AHCI, 0x01);
        // The programming interface byte follows revision id at 0x08.
        assert_eq!(PROG_IF_OFFSET, 0x09);
    }

    #[test]
    fn only_a_sata_controller_presenting_ahci_registers_is_ahci() {
        assert_eq!(classify(0x01, 0x06, 0x01), Kind::Ahci);
        // The same silicon, a different register set. Driving this with AHCI's
        // offsets is writing into a bus master's registers at random.
        assert_eq!(classify(0x01, 0x06, 0x00), Kind::SataNotAhci);
        assert_eq!(classify(0x01, 0x06, 0x02), Kind::SataNotAhci);
    }

    #[test]
    fn a_raid_mode_controller_is_recorded_and_is_never_ahci() {
        // RFC 0046's named trap: `00:17.0` on the SR550. Its programming
        // interface byte is not consulted, because RAID mode is what makes it
        // not this driver's whatever that byte says.
        assert_eq!(classify(0x01, 0x04, 0x00), Kind::Raid);
        assert_eq!(classify(0x01, 0x04, 0x01), Kind::Raid);
    }

    #[test]
    fn other_mass_storage_is_ignored_rather_than_claimed() {
        // Subclass alone is not enough, in the other direction too: a class-01
        // match that ignored the subclass would claim an NVMe drive and an IDE
        // controller as SATA controllers.
        assert_eq!(classify(0x01, 0x00, 0x00), Kind::Ignored); // SCSI
        assert_eq!(classify(0x01, 0x01, 0x8a), Kind::Ignored); // IDE
        assert_eq!(classify(0x01, 0x07, 0x00), Kind::Ignored); // SAS
        assert_eq!(classify(0x01, 0x08, 0x02), Kind::Ignored); // NVMe
    }

    #[test]
    fn nothing_outside_mass_storage_is_ever_a_controller() {
        // The programming interface of an xHCI controller is 0x30 and its
        // subclass is 0x03; neither may reach this driver through a check that
        // forgot the class.
        assert_eq!(classify(0x0c, 0x03, 0x30), Kind::Ignored);
        assert_eq!(classify(0x06, 0x04, 0x00), Kind::Ignored); // a bridge
        assert_eq!(classify(0x02, 0x00, 0x00), Kind::Ignored); // a NIC
        // Subclass 06 of *any other class* is not SATA. Class 06 subclass 04 is
        // a PCI-to-PCI bridge, above.
        assert_eq!(classify(0x03, 0x06, 0x01), Kind::Ignored);
    }

    #[test]
    fn an_untranslated_controller_cannot_be_reached_through_drivable() {
        // RFC 0012's rule, expressed as a type: there is no accessor on `Found`
        // that answers this controller.
        let found = found_with(&[controller(PROG_IF_AHCI, false)]);
        assert_eq!(found.drivable(), None);
        assert_eq!(found.refused(), 1);
    }

    #[test]
    fn a_non_ahci_controller_cannot_be_reached_through_drivable_either() {
        // Translated, contained, and still not drivable -- because containment
        // says the damage is bounded, not that the registers are the right
        // ones. A window is not a licence to guess a layout.
        let found = found_with(&[controller(0x00, true)]);
        assert_eq!(found.drivable(), None);
        assert_eq!(found.refused(), 1);
    }

    #[test]
    fn the_first_drivable_controller_is_answered_past_refused_ones() {
        // Bus order, and the refusals ahead of it must not hide it. A machine
        // with a vendor-specific SATA controller before an AHCI one is exactly
        // the case a `find` on the wrong predicate gets wrong.
        let good = Controller {
            bus: 0,
            device: 0x11,
            function: 5,
            ..controller(PROG_IF_AHCI, true)
        };
        let found = found_with(&[
            controller(0x00, true),
            controller(PROG_IF_AHCI, false),
            good,
        ]);
        assert_eq!(found.drivable(), Some(good));
        assert_eq!(found.refused(), 2);
    }

    #[test]
    fn a_machine_with_no_controller_answers_nothing_rather_than_a_default() {
        let found = Found::none();
        assert_eq!(found.drivable(), None);
        assert_eq!(found.refused(), 0);
        assert_eq!(found.seen, 0);
        assert_eq!(found.iter().count(), 0);
        assert_eq!(found.raid, None);
    }
}
