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
// PCI's own offset for the programming-interface byte, shared with
// `crate::iommu`'s survey rather than written out once per driver: class and
// subclass say what a device is, and this byte says which register layout it
// presents.
use bhaskix_arch::pci::PROG_IF_OFFSET;
use bhaskix_device::Bus;
use bhaskix_usb::setup as usb_setup;
use bhaskix_xhci::{capability, context, extended, operational, runtime, trb};

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

/// Where the first xHCI controller is, without asking whether it may be driven.
///
/// **The IOMMU question is deliberately not asked here**, and that is the whole
/// reason this exists beside [`discover`]. A window has to be built for a
/// controller *before* [`discover`] can answer that it is translated, and
/// building one needs to know which device to build it for. Asking here would
/// answer "untranslated" for every controller on every machine, which is the
/// state this function is called to change.
///
/// So this is the same shape as `virtio::probe`: it says *where*, and nothing
/// about authority. [`Found::drivable`] remains the only thing that decides.
///
/// # Safety
///
/// As [`discover`]: configuration access must work.
#[must_use]
pub unsafe fn probe() -> Option<(u8, u8, u8)> {
    let mut at = None;
    let mut visit = |address: pci::Address, identity: pci::Identity| {
        if identity.class != CLASS_SERIAL_BUS || identity.subclass != SUBCLASS_USB {
            return true;
        }
        // SAFETY: one byte of configuration space, at a fixed offset, on a
        // function `for_each` has already found present.
        if unsafe { pci::read8(address, PROG_IF_OFFSET) } != PROG_IF_XHCI {
            return true;
        }
        at = Some((address.bus, address.device, address.function));
        // Stop at the first: the caller wants one controller to drive, and a
        // second is what keeps the refusal in `report` observable.
        false
    };
    // SAFETY: the caller's obligation; configuration reads only.
    unsafe { pci::for_each(&mut visit) };
    at
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

bhaskix_device::register_block! {
    /// The capability bank, at the window base.
    ///
    /// Read-only, and the only way to find everything else: the operational,
    /// runtime and doorbell banks are all at offsets this bank reports. Nothing
    /// here may be assumed — a controller is entitled to put them anywhere.
    struct Capability(0x20) {
        0x00 => length_and_version: u32,
        0x04 => hcsparams1: u32,
        0x08 => hcsparams2: u32,
        0x10 => hccparams1: u32,
        0x14 => dboff: u32,
        0x18 => rtsoff: u32,
    }
}

bhaskix_device::register_block! {
    /// The operational bank, at the window base plus `CAPLENGTH`.
    struct Operational(0x40) {
        0x00 => usbcmd: u32,
        0x04 => usbsts: u32,
        0x18 => crcr: u64,
        0x30 => dcbaap: u64,
        0x38 => config: u32,
    }
}

bhaskix_device::register_block! {
    /// One interrupter's register set, inside the runtime bank.
    ///
    /// This driver uses interrupter zero and no other, so this block is named
    /// at that one's base rather than being an array.
    struct Interrupter(0x20) {
        0x00 => iman: u32,
        0x04 => imod: u32,
        0x08 => erstsz: u32,
        0x10 => erstba: u64,
        0x18 => erdp: u64,
    }
}

bhaskix_device::register_block! {
    /// One root hub port's status and control register.
    ///
    /// Named at the port being looked at rather than being an array, for the
    /// same reason the doorbell is: the index reaches straight into an offset.
    /// `PORTSC` is also the most dangerous register in the controller to
    /// read-modify-write -- seven of its bits are write-one-to-clear and bit 1
    /// is write-one-to-*disable* -- which is why every write here goes through
    /// `preserving` or `acknowledging`.
    struct PortRegister(0x04) {
        0x00 => portsc: u32,
    }
}

bhaskix_device::register_block! {
    /// One doorbell, inside the doorbell bank.
    ///
    /// **Write-only in practice**, which is why the block holds one register
    /// and is named at the doorbell being rung rather than being an array
    /// indexed at each use: an out-of-range index here is a write outside the
    /// window, and a stray write to a device is worse than a stray read.
    struct DoorbellRegister(0x04) {
        0x00 => value: u32,
    }
}

/// How many times a command will drain the event ring waiting for its answer.
///
/// Each round is a whole `Wait`, so this bounds a command at `DRAIN_ROUNDS`
/// settle periods rather than at one. Four because the events that get in the
/// way are the port changes from a reset -- a small, bounded number of them --
/// and a command that has not been answered after four full waits is not going
/// to be.
const DRAIN_ROUNDS: usize = 4;

/// The moderation interval, in 250 ns units — about one interrupt per 16 µs.
///
/// **Not left at the reset value**, which is zero and means an interrupt per
/// event. A fast device can then livelock a CPU, and a keyboard is not fast but
/// the controller this shares a bank with may be driving something that is.
const IMOD_INTERVAL: u16 = 64;

/// The most device slots this driver will enable.
///
/// A keyboard needs one. The bound exists because the slot count sizes the
/// device context array, and it is a number the *controller* reports — RFC
/// 0038's rule 6. A controller claiming 255 slots would otherwise size an
/// allocation from a value this driver never checked.
const MAX_SLOTS: u8 = 8;

/// Entries in the command ring, and in the event ring.
///
/// One frame each would hold 256; sixteen is what a keyboard's bring-up needs
/// and every entry is memory the controller may write to.
const RING_ENTRIES: usize = 16;

/// Segments in the event ring segment table. One, because there is one ring.
const ERST_ENTRIES: u16 = 1;

/// A bounded wait on a register settling.
///
/// **A trait rather than a loop, so that "it never settled" is reachable from a
/// host test.** Every wait in a bring-up is a wait on hardware, and the failure
/// this must never have is the one that cannot be tested: a controller that
/// does not answer must produce a refusal that names the register, not a
/// machine that stops.
pub trait Wait {
    /// Polls `ready` until it answers true, or this waiter's budget runs out.
    ///
    /// `false` means it never settled. Each call gets a fresh budget: these are
    /// separate waits on separate registers, and sharing one budget between two
    /// of them is the defect `time_the_burst` was found to have on 2026-08-23.
    fn until(&mut self, ready: &mut dyn FnMut() -> bool) -> bool;
}

/// How far a bring-up got before it gave up, and on what.
///
/// Every variant names a *register or a number*, because the thing an operator
/// needs from a controller that did not start is which step it died at.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BringUpError {
    /// The window is too small to hold the banks the capability registers
    /// point at. A controller reporting offsets past its own BAR.
    BanksOutsideWindow,
    /// `CAPLENGTH` is smaller than the capability bank itself.
    CapabilityLengthTooSmall,
    /// The controller was running and would not halt.
    WouldNotHalt,
    /// `USBCMD.HCRST` never cleared.
    ResetNeverCompleted,
    /// `USBSTS.CNR` never cleared: reset finished, the controller is still not
    /// willing to be programmed.
    NeverBecameReady,
    /// The controller reports no device slots, so nothing can be addressed.
    NoDeviceSlots,
    /// The controller asked for scratchpad buffers it was not given. It will
    /// not run, and running it anyway is a bus master reading a null pointer.
    ScratchpadNotProvided,
    /// The controller's interrupter zero is past the architectural ceiling,
    /// which means the runtime offset it reported is not one.
    NoInterrupterZero,
    /// A ring too small to hold a link TRB and any work.
    RingTooSmall,
    /// A physical address this driver was given does not meet the alignment
    /// the register demands. Refused here because the controller would not
    /// refuse it: the low bits are read as flags.
    Misaligned,
    /// Run/Stop was set and `USBSTS.HCH` never cleared.
    NeverRan,
}

impl BringUpError {
    /// One line, for the boot report.
    #[must_use]
    pub const fn describe(self) -> &'static str {
        match self {
            Self::BanksOutsideWindow => "its register banks are outside the window it declares",
            Self::CapabilityLengthTooSmall => "CAPLENGTH is shorter than the capability bank",
            Self::WouldNotHalt => "it was running and would not halt",
            Self::ResetNeverCompleted => "USBCMD.HCRST never cleared",
            Self::NeverBecameReady => "USBSTS.CNR never cleared: it will not be programmed",
            Self::NoDeviceSlots => "it reports no device slots",
            Self::ScratchpadNotProvided => "it asked for scratchpad buffers it was not given",
            Self::NoInterrupterZero => "it has no interrupter zero",
            Self::RingTooSmall => "a ring too small for a link TRB and any work",
            Self::Misaligned => "a ring or table address the register cannot hold",
            Self::NeverRan => "USBSTS.HCH never cleared: it did not start",
        }
    }
}

/// The memory a controller is given, all of it already prepared.
///
/// **Prepared, and that word is load-bearing.** The device context array's
/// entry zero already holds the scratchpad array pointer, and the event ring
/// segment table already describes the event ring, *before* this is handed to
/// [`bring_up`]. That is not tidiness: the ordering rule "scratchpad before
/// Run/Stop" then holds by construction rather than by a step somebody has to
/// remember, which is the same trick [`Found::drivable`] plays with the IOMMU.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Memory {
    /// The device context base address array. 64-byte aligned.
    pub device_contexts: u64,
    /// The command ring.
    pub command_ring: u64,
    /// Entries in it.
    pub command_ring_entries: usize,
    /// The event ring.
    pub event_ring: u64,
    /// Entries in it.
    pub event_ring_entries: usize,
    /// The event ring segment table, already describing `event_ring`.
    pub segment_table: u64,
    /// How many scratchpad buffers were actually allocated and installed at
    /// entry zero of the device context array.
    pub scratchpads: u32,
}

/// A controller that is running, and what it said about itself.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Running {
    /// Slots enabled, which is what the device context array was sized for.
    pub slots: u8,
    /// Root hub ports the controller reports.
    pub ports: u8,
    /// Whether contexts are 64 bytes rather than 32.
    pub context_size_64: bool,
    /// Scratchpad buffers the controller asked for.
    pub scratchpads: u32,
    /// The interface version, for the report.
    pub version: u16,
}

/// What the capability bank says, bounded.
///
/// RFC 0038's rule 6: the controller's own numbers are checked before they size
/// an allocation or a loop. Reading them into a struct is where that happens, so
/// that no later line has the unbounded value to reach for.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Parameters {
    /// Slots this driver will enable — already clamped to [`MAX_SLOTS`].
    pub slots: u8,
    /// Root hub ports.
    pub ports: u8,
    /// Scratchpad buffers demanded.
    pub scratchpads: u32,
    /// Context stride: 64 bytes rather than 32.
    pub context_size_64: bool,
    /// Interface version.
    pub version: u16,
    /// Operational bank offset from the window base.
    pub operational: usize,
    /// Runtime bank offset from the window base.
    pub runtime: usize,
    /// Doorbell bank offset from the window base. Unused until step 4, and read
    /// here because it is a bound: a controller whose doorbells are outside the
    /// window has reported an offset this driver must not later trust.
    pub doorbells: usize,
    /// Start of the extended capability list, **in dwords** from the window
    /// base, or zero for a controller that declares none.
    ///
    /// Dwords because `HCCPARAMS1` says dwords. The unit is carried this far
    /// rather than converted at the read so that the shift happens next to the
    /// specification's own worked example, in [`extended::first_capability`].
    pub extended_capabilities: u32,
}

/// How many bytes of a controller's window this driver must be able to reach.
///
/// The runtime bank plus interrupter zero is the furthest this step touches;
/// the doorbell bank is checked too, because step 4 will.
#[must_use]
const fn required_window(parameters: &Parameters) -> usize {
    let operational = parameters.operational + Operational::<bhaskix_device::Volatile>::LENGTH;
    let runtime = parameters.runtime
        + runtime::offset::INTERRUPTERS
        + Interrupter::<bhaskix_device::Volatile>::LENGTH;
    let doorbells = parameters.doorbells + 4;
    let mut most = operational;
    if runtime > most {
        most = runtime;
    }
    if doorbells > most {
        most = doorbells;
    }
    most
}

/// What the pre-OS handoff found, and what it did about it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Ownership {
    /// The controller declares no USB Legacy Support capability, so firmware
    /// was never in the way.
    ///
    /// **Every emulator this driver has ever run on answers this**, which is
    /// why the rest of this enum had no witness until a real server produced
    /// one. A path that is dead on the machine you test on is not a path that
    /// works.
    NoCapability,
    /// This driver holds the controller.
    Held {
        /// Whether firmware's semaphore was set when the driver asked.
        firmware_held: bool,
        /// Whether firmware had SMI sources armed that this driver turned off.
        silenced: bool,
    },
    /// Firmware still claims the controller after the second the specification
    /// allows it. Its semaphore has been handed back and the controller left
    /// exactly as it was found.
    Refused,
}

impl Ownership {
    /// Whether the driver may go on to use the controller.
    #[must_use]
    pub const fn may_proceed(self) -> bool {
        !matches!(self, Self::Refused)
    }
}

/// Takes the controller from firmware before anything else touches it.
///
/// A server's firmware drives the xHC to offer a USB keyboard and a virtual
/// CD, and it does that from System Management Mode, having asked the
/// controller to raise an SMI on the events it cares about. Starting such a
/// controller without the handoff does not race firmware for a device: it
/// wakes firmware's SMI handler on a controller firmware no longer recognises,
/// inside an interrupt the operating system cannot see, end of boot.
/// Specification §4.22.1 states the consequence directly — *"two software
/// agents believing they each have exclusive ownership of the xHC"*.
///
/// Two things are needed and neither is sufficient alone: the semaphore, which
/// stops firmware from *using* the controller, and the SMI enables, which stop
/// the controller from *summoning* firmware. The second outlives the first,
/// because it lives in the controller rather than in firmware.
///
/// # Safety
///
/// `base` must be a mapped xHCI register window of at least `window` bytes.
pub unsafe fn take_ownership<B: Bus, W: Wait>(
    base: usize,
    window: usize,
    parameters: &Parameters,
    wait: &mut W,
) -> Ownership {
    let Some(mut at) = extended::first_capability(parameters.extended_capabilities, window) else {
        return Ownership::NoCapability;
    };

    // Walk the list for the one capability this driver needs. Bounded twice:
    // by the window, which `next_capability` checks, and by a step count,
    // because a malformed list can be circular and a boot that hangs here
    // cannot say why.
    let mut steps = 0;
    let legacy = loop {
        // SAFETY: `at` is inside the window, which `first_capability` checked
        // for the head and `next_capability` for every entry after it, and a
        // dword offset from a dword-aligned base is dword-aligned.
        let header = extended::CapabilityHeader(unsafe { B::load32(base + at) });
        if header.id() == extended::LEGACY_SUPPORT {
            break Some(at);
        }
        steps += 1;
        if steps >= extended::MAX_CAPABILITIES {
            break None;
        }
        match extended::next_capability(at, header, window) {
            Some(next) => at = next,
            None => break None,
        }
    };

    let Some(legacy) = legacy else {
        return Ownership::NoCapability;
    };

    // The capability is two registers, not one, and the second is the half
    // that matters. A window that holds only the first is not one this can be
    // done safely in.
    let control = legacy + extended::CONTROL_OFFSET;
    if control + 4 > window {
        return Ownership::NoCapability;
    }

    // SAFETY: `legacy` is a capability header found inside the window.
    let found = extended::LegacySupport(unsafe { B::load32(base + legacy) });
    let firmware_held = found.bios_owned();

    // SAFETY: as above; the register is RW and the value preserves firmware's
    // own semaphore, which it may be changing concurrently.
    unsafe { B::store32(base + legacy, found.requesting().0) };

    // §4.22.1: *"The time that OS shall wait for BIOS to respond to the
    // request for ownership should not exceed '1' second."* One `Settle` is
    // half of that, so this asks twice rather than quietly halving the
    // allowance the specification gives firmware -- a machine refused for
    // being 600 ms slow would look exactly like a machine that is broken.
    let mut ours = || {
        // SAFETY: as above, a read of a register inside the window.
        let raw = unsafe { B::load32(base + legacy) };
        extended::LegacySupport(raw).owned_by_us()
    };
    let mut granted = false;
    for _ in 0..2 {
        if wait.until(&mut ours) {
            granted = true;
            break;
        }
    }

    if !granted {
        // Hand the semaphore back rather than hold one firmware never
        // acknowledged. The specification's own words for relinquishing are to
        // set the OS Owned semaphore to zero, and leaving it set would tell a
        // firmware that is merely slow that the operating system owns a
        // controller it is not going to use.
        //
        // Its SMI enables are left alone on purpose: this driver is not taking
        // the controller, so disabling the interrupts firmware relies on would
        // break a working keyboard to no end.
        // SAFETY: as above.
        let now = extended::LegacySupport(unsafe { B::load32(base + legacy) });
        // SAFETY: as above.
        unsafe { B::store32(base + legacy, now.0 & !(1 << 24)) };
        return Ownership::Refused;
    }

    // SAFETY: `control` was checked to be inside the window just above.
    let smi = extended::LegacyControlStatus(unsafe { B::load32(base + control) });
    let silenced = smi.smi_enabled();
    // SAFETY: as above. `quietened` preserves every RsvdP field it read.
    unsafe { B::store32(base + control, smi.quietened().0) };

    Ownership::Held {
        firmware_held,
        silenced,
    }
}

/// Reads the capability bank and bounds everything in it.
///
/// # Safety
///
/// `base` must be a mapped xHCI register window of at least `window` bytes.
pub unsafe fn parameters<B: Bus>(base: usize, window: usize) -> Result<Parameters, BringUpError> {
    // SAFETY: the caller's obligation. The capability bank is at the window
    // base by definition, and is the one bank whose location is not reported
    // by another.
    let capabilities = unsafe { Capability::<B>::new(base) };

    // **One 32-bit read, and the two fields taken out of it.** `CAPLENGTH` is
    // a byte at 0x00 and `HCIVERSION` a halfword at 0x02: they share the first
    // dword, and a controller is entitled to implement only dword reads of this
    // bank. QEMU's `qemu-xhci` is such a controller -- its dword 0 reads
    // 0x01000040, and a 16-bit read at offset 2 answers **0x0000** rather than
    // faulting. Narrow reads here do not fail loudly; they answer zero, and a
    // driver believes them.
    let length_and_version = capabilities.length_and_version.read();
    let caplength = (length_and_version & 0xff) as usize;
    let version = (length_and_version >> 16) as u16;
    if caplength < Capability::<B>::LENGTH {
        // The operational bank would overlap the capability bank, so a write
        // meant for `USBCMD` would land inside a read-only register --
        // silently, because the controller simply ignores it.
        return Err(BringUpError::CapabilityLengthTooSmall);
    }

    let hcsparams1 = capability::StructuralParameters1(capabilities.hcsparams1.read());
    let hcsparams2 = capability::StructuralParameters2(capabilities.hcsparams2.read());
    let hccparams1 = capability::CapabilityParameters1(capabilities.hccparams1.read());

    // The low bits of both offsets are reserved, not address. Masking them is
    // not defensive: a controller is entitled to leave them set.
    let runtime_offset = (capabilities.rtsoff.read() & !0x1f) as usize;
    let doorbell_offset = (capabilities.dboff.read() & !0x3) as usize;

    let slots = {
        let reported = hcsparams1.number_of_device_slots();
        if reported == 0 {
            return Err(BringUpError::NoDeviceSlots);
        }
        if reported > MAX_SLOTS {
            MAX_SLOTS
        } else {
            reported
        }
    };

    let parameters = Parameters {
        slots,
        ports: hcsparams1.number_of_ports(),
        scratchpads: hcsparams2.max_scratchpad_buffers(),
        context_size_64: hccparams1.context_size_64(),
        version,
        operational: caplength,
        runtime: runtime_offset,
        doorbells: doorbell_offset,
        extended_capabilities: hccparams1.extended_capabilities_pointer_dwords(),
    };

    if required_window(&parameters) > window {
        // Every bank offset reaches straight into an MMIO address. One past
        // the mapping is a read or write of whatever is mapped next, which on
        // this kernel's direct map is memory.
        return Err(BringUpError::BanksOutsideWindow);
    }

    Ok(parameters)
}

/// Brings a controller up to running, and stops there.
///
/// The order below is FreeBSD's `xhci_start_controller`, read rather than
/// remembered, because not all of its ordering constraints are obvious and
/// getting one wrong produces a controller that appears to start and then does
/// nothing.
///
/// **This function touches registers and nothing else.** Every byte of memory
/// the controller will read has already been written by whoever built
/// [`Memory`], which is what makes the whole sequence testable against a model
/// with no allocator in it.
///
/// # Safety
///
/// `base` must be a mapped register window of at least `required_window`
/// bytes for these `parameters`, which is what [`parameters`] checked, and this
/// driver must own the controller.
pub unsafe fn bring_up<B: Bus, W: Wait>(
    base: usize,
    parameters: &Parameters,
    memory: &Memory,
    wait: &mut W,
) -> Result<Running, BringUpError> {
    // A controller that asked for scratchpad and did not get it does not run,
    // and checking here rather than at the allocation is deliberate: this is
    // the function that knows what the controller demanded.
    if memory.scratchpads < parameters.scratchpads {
        return Err(BringUpError::ScratchpadNotProvided);
    }

    // Refuse every address the registers cannot hold *before* writing any of
    // them. A half-programmed controller with a live reset behind it is worse
    // than one that was never touched.
    let command_ring = operational::CommandRingControl::with_pointer(
        memory.command_ring,
        ring::Producer::new(memory.command_ring_entries)
            .ok_or(BringUpError::RingTooSmall)?
            .cycle(),
    )
    .ok_or(BringUpError::Misaligned)?;
    let device_contexts =
        operational::DeviceContextBaseAddressArrayPointer::with_pointer(memory.device_contexts)
            .ok_or(BringUpError::Misaligned)?;
    let segment_table =
        runtime::EventRingSegmentTableBaseAddress::with_pointer(memory.segment_table)
            .ok_or(BringUpError::Misaligned)?;
    let dequeue = runtime::EventRingDequeuePointer::advancing(memory.event_ring, 0, false)
        .ok_or(BringUpError::Misaligned)?;
    if ring::Consumer::new(memory.event_ring_entries).is_none() {
        return Err(BringUpError::RingTooSmall);
    }
    let interrupter_zero = runtime::interrupter_at(0).ok_or(BringUpError::NoInterrupterZero)?;

    // SAFETY: the caller's obligation, and `parameters` checked that both banks
    // are inside the window.
    let operational_bank = unsafe { Operational::<B>::new(base + parameters.operational) };
    // SAFETY: as above, for the runtime bank's interrupter zero.
    let interrupter =
        unsafe { Interrupter::<B>::new(base + parameters.runtime + interrupter_zero) };

    // --- 1. halt, then reset ------------------------------------------------
    //
    // Resetting a running controller is undefined. Firmware enumerated this
    // device to look for a boot device and may well have left it running.
    if operational::UsbCommand(operational_bank.usbcmd.read()).run_stop() {
        let stopped = operational::UsbCommand(operational_bank.usbcmd.read()).with_run_stop(false);
        operational_bank.usbcmd.write(stopped.0);
        if !wait.until(&mut || operational::UsbStatus(operational_bank.usbsts.read()).hc_halted()) {
            return Err(BringUpError::WouldNotHalt);
        }
    }

    operational_bank
        .usbcmd
        .write(operational::UsbCommand(0).with_host_controller_reset().0);

    if !wait.until(&mut || {
        !operational::UsbCommand(operational_bank.usbcmd.read()).host_controller_reset()
    }) {
        return Err(BringUpError::ResetNeverCompleted);
    }

    // **Waiting on the reset bit alone is not enough.** The controller clears
    // it before it is willing to be programmed, and `CNR` is the bit that says
    // otherwise -- writing an operational register while it is set is
    // undefined, and the specification says so.
    if !wait.until(&mut || {
        !operational::UsbStatus(operational_bank.usbsts.read()).controller_not_ready()
    }) {
        return Err(BringUpError::NeverBecameReady);
    }

    // --- 2. how many slots, and the array that matches ----------------------
    operational_bank.config.write(
        operational::Configure(0)
            .with_max_device_slots_enabled(parameters.slots)
            .0,
    );

    // --- 3. where the device contexts are -----------------------------------
    operational_bank.dcbaap.write(device_contexts.0);

    // --- 4 and 5. the event ring, and the order that is load-bearing --------
    interrupter.erstsz.write(
        runtime::EventRingSegmentTableSize(0)
            .with_size(ERST_ENTRIES)
            .0,
    );
    interrupter.imod.write(
        runtime::InterrupterModeration(0)
            .with_interval(IMOD_INTERVAL)
            .0,
    );

    // **`ERDP` before `ERSTBA`.** Writing `ERSTBA` is what arms the event ring;
    // a dequeue pointer written afterwards is written to a ring the controller
    // has already begun using, and the events between the two writes are gone.
    interrupter.erdp.write(dequeue.0);
    interrupter.erstba.write(segment_table.0);

    // --- 6. let the interrupter interrupt -----------------------------------
    interrupter.iman.write(
        runtime::InterrupterManagement(0)
            .with_interrupt_enable(true)
            .0,
    );

    // --- 7. the command ring ------------------------------------------------
    operational_bank.crcr.write(command_ring.0);

    // --- 8. run -------------------------------------------------------------
    operational_bank.usbcmd.write(
        operational::UsbCommand(0)
            .with_run_stop(true)
            .with_interrupter_enable(true)
            .0,
    );

    if !wait.until(&mut || !operational::UsbStatus(operational_bank.usbsts.read()).hc_halted()) {
        return Err(BringUpError::NeverRan);
    }

    Ok(Running {
        slots: parameters.slots,
        ports: parameters.ports,
        context_size_64: parameters.context_size_64,
        scratchpads: parameters.scratchpads,
        version: parameters.version,
    })
}

/// How many bytes the device context base address array needs.
///
/// **Slots plus one**, because entry zero is the scratchpad array pointer and
/// not a device. Sizing it by the slot count alone puts the last slot's context
/// pointer in whatever follows the allocation, which the controller then writes
/// to by DMA.
#[must_use]
pub const fn device_context_array_bytes(slots: u8) -> usize {
    context::device_context_base_array_bytes(slots)
}

/// Bytes a ring of [`RING_ENTRIES`] TRBs occupies.
#[must_use]
pub const fn ring_bytes() -> usize {
    trb::ring_bytes(RING_ENTRIES)
}

/// The Link TRB a command ring needs, and which entry it belongs in.
///
/// **A command ring's last entry must be a Link back to its own start**, or the
/// controller runs off the end of the segment into whatever follows it in
/// memory -- by DMA. It toggles the cycle, because a one-segment ring has
/// nowhere else for the lap to flip.
///
/// An event ring gets none: the controller wraps that one by the segment table.
/// That asymmetry is why this function names the *command* ring and why
/// `ring::Consumer` wraps one entry later than `ring::Producer`.
///
/// Pure, and separate from the write, so that the decision is host-testable
/// even though the store into DMA memory is not.
///
/// `None` for a ring too small to hold a link and any work, or an address the
/// register cannot hold -- a misaligned link pointer is silently truncated by
/// the controller rather than refused.
#[must_use]
pub fn command_ring_link(device_address: u64, entries: usize) -> Option<(usize, trb::Trb)> {
    let producer = ring::Producer::new(entries)?;
    let link = trb::Trb::link(device_address, true, producer.cycle())?;
    Some((producer.link_index(), link))
}

/// The three contexts an Address Device command needs, and where each goes.
///
/// **This is the arithmetic RFC 0041 names as the trap**, extracted so a host
/// test holds it rather than a comment. An input context is
/// `[input control][slot][endpoint 1]…`, one context further along than a
/// *device* context is — so the slot context sits at one stride and not at
/// zero. A driver that fills an input context with device-context arithmetic
/// writes the slot context on top of the input control context's add and drop
/// flags, which is a command that configures the wrong endpoints and is
/// accepted.
///
/// Returns `(offset, dwords)` for the input control context, the slot context
/// and the control endpoint's context, in that order. Everything else in the
/// input context stays zeroed, which is what "not being added" means.
///
/// `None` if the endpoint's transfer ring address is one the context cannot
/// hold — 16-byte alignment, refused here because the controller would take the
/// low bits as flags instead.
#[must_use]
pub fn address_device_input(
    port: u8,
    speed: u32,
    transfer_ring: u64,
    transfer_ring_cycle: bool,
    context_size_64: bool,
) -> Option<[(usize, [u32; context::DWORDS]); 3]> {
    // A0 and A1: evaluate the slot context and the control endpoint. Nothing
    // else exists yet, and adding a context that has not been written is how a
    // controller is asked to read uninitialised memory.
    let control = context::InputControl::new()
        .adding(0)?
        .adding(bhaskix_xhci::doorbell::CONTROL_ENDPOINT)?;

    // One context entry: the control endpoint and nothing beyond it. This is
    // the *highest* index in use, not a count of endpoints, and setting it too
    // low makes the controller ignore contexts that are there.
    let slot = context::Slot::new()
        .with_route_and_speed(0, speed as u8)
        .with_context_entries(bhaskix_xhci::doorbell::CONTROL_ENDPOINT)
        .with_root_hub_port_number(port);

    let endpoint = context::Endpoint::new()
        .with_endpoint_type(context::EndpointType::Control)
        .with_max_packet_size(initial_max_packet_size(speed))
        // Three attempts before the controller gives up on a transfer. Zero
        // means "retry for ever", which is a wedged endpoint rather than a
        // reported error.
        .with_error_count(3)
        .with_transfer_ring(transfer_ring, transfer_ring_cycle)?;

    Some([
        (context::INPUT_CONTROL_OFFSET, control.0),
        (context::input_context_offset(0, context_size_64)?, slot.0),
        (
            context::input_context_offset(
                bhaskix_xhci::doorbell::CONTROL_ENDPOINT,
                context_size_64,
            )?,
            endpoint.0,
        ),
    ])
}

/// The three contexts a Configure Endpoint command needs for one interrupt IN
/// endpoint, and where each goes.
///
/// The same shape as [`address_device_input`] and the same trap: an input
/// context is one context further along than a device context. What differs is
/// which contexts are added — the slot context, because its Context Entries
/// field has to grow to cover the new endpoint, and the endpoint itself.
///
/// **The slot context is re-sent, not left alone.** Context Entries names the
/// *highest* Device Context Index in use, and it says 1 after Address Device.
/// Adding an endpoint at index 3 without raising it is a controller told to
/// configure something it has been told does not exist.
///
/// `None` if the index is not one an input context can name, or the ring
/// address is one the context cannot hold.
#[must_use]
#[expect(
    clippy::too_many_arguments,
    reason = "each is a distinct field the controller is told, and the point of \
              this function is that all of them are visible at the call site \
              rather than folded into a struct somebody has to open"
)]
pub fn configure_endpoint_input(
    port: u8,
    speed: u32,
    index: u8,
    max_packet_size: u16,
    interval: u8,
    transfer_ring: u64,
    transfer_ring_cycle: bool,
    context_size_64: bool,
) -> Option<[(usize, [u32; context::DWORDS]); 3]> {
    if index < 2 {
        // Index 0 is the slot and 1 the control endpoint; neither is configured
        // by this command, and an index below 2 here means the Device Context
        // Index arithmetic went wrong somewhere upstream.
        return None;
    }
    let control = context::InputControl::new().adding(0)?.adding(index)?;

    let slot = context::Slot::new()
        .with_route_and_speed(0, speed as u8)
        .with_context_entries(index)
        .with_root_hub_port_number(port);

    let endpoint = context::Endpoint::new()
        .with_endpoint_type(context::EndpointType::InterruptIn)
        .with_max_packet_size(max_packet_size)
        .with_interval(interval)
        .with_error_count(3)
        .with_average_trb_length(max_packet_size)
        .with_transfer_ring(transfer_ring, transfer_ring_cycle)?;

    Some([
        (context::INPUT_CONTROL_OFFSET, control.0),
        (context::input_context_offset(0, context_size_64)?, slot.0),
        (
            context::input_context_offset(index, context_size_64)?,
            endpoint.0,
        ),
    ])
}

/// The xHCI `Interval` exponent for a descriptor's `bInterval`, at a speed.
///
/// The field is an exponent: the period is `2^interval` × 125 µs. `bInterval`
/// is **not** that, and is not even the same thing at different speeds — at
/// high speed it is itself an exponent in microframes, and at full and low
/// speed it is a count of frames.
///
/// # This conversion is unverified, and says so
///
/// It has **not** been checked against a copy of the specification on this
/// machine, and no test here can tell a correct conversion from a plausible
/// one: Configure Endpoint is accepted for any legal exponent, so the emulator
/// will not object to a wrong one. What a wrong value produces is reports
/// arriving at the wrong *rate*, which is only observable once reports arrive.
///
/// *Trigger:* RFC 0041 step 7. The boot report prints the descriptor's
/// `bInterval` beside the exponent programmed, so the two can be compared
/// against what the keyboard actually does.
#[must_use]
const fn interval_exponent(b_interval: u8, speed: u32) -> u8 {
    match speed {
        // High speed and above: `bInterval` is already an exponent, in
        // microframes, counted from one where this field counts from zero.
        3..=5 => {
            if b_interval == 0 {
                0
            } else if b_interval > 16 {
                15
            } else {
                b_interval - 1
            }
        }
        // Full and low speed: `bInterval` is a count of *frames*, and a frame
        // is eight microframes -- 2^3. The exponent for `n` frames is
        // therefore 3 plus the exponent for `n`, and this takes the largest
        // power of two not exceeding `n`, which polls no slower than asked.
        _ => {
            let mut exponent = 3;
            let mut frames = b_interval;
            while frames > 1 && exponent < 15 {
                frames >>= 1;
                exponent += 1;
            }
            exponent
        }
    }
}

/// The control endpoint's packet size to assume before the device is asked.
///
/// **A guess the specification prescribes, not a measurement**, and it is only
/// ever a starting point: a full-speed device reports its real maximum in the
/// device descriptor, and a driver that reads one is expected to correct the
/// context afterwards. Nothing here corrects it yet, because nothing here reads
/// a descriptor — that is step 6, and this constant is what it will have to
/// revisit.
///
/// The speed ids are `PORTSC` bits 13:10. They are transcribed from the speed
/// table rather than derived, and **have not been checked against a copy of the
/// specification on this machine** — which is survivable at this step because
/// Address Device does not care: the packet size governs transfers, and there
/// are none until step 6. The trigger to check it is the first control transfer.
#[must_use]
const fn initial_max_packet_size(speed: u32) -> u16 {
    match speed {
        // Full speed and low speed both start at eight; a full-speed device may
        // then say 8, 16, 32 or 64.
        1 | 2 => 8,
        // High speed is fixed at 64 and never negotiated.
        3 => 64,
        // SuperSpeed and above are fixed at 512.
        4 | 5 => 512,
        // Undefined. Eight is the smallest legal value, so it is the one that
        // cannot ask a device for more than it can answer.
        _ => 8,
    }
}

/// What one drain of the event ring found.
///
/// Counts rather than a queue: nothing in this step *acts* on an event, and a
/// structure that could hold one would be a structure the next step has to be
/// talked out of. What it keeps is the last of each thing, which is what the
/// boot report needs and what proves a round trip happened.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Drained {
    /// Events consumed.
    pub events: usize,
    /// Of them, command completions.
    pub command_completions: usize,
    /// Of them, root hub port changes.
    pub port_changes: usize,
    /// Of them, transfer events.
    pub transfers: usize,
    /// Of them, the controller reporting a problem with itself.
    pub host_controller: usize,
    /// Of them, kinds this driver does not name.
    ///
    /// **Counted rather than ignored.** A controller posting events a driver
    /// has no case for is a driver that has misunderstood something, and a
    /// silent `_ =>` arm is how that stays invisible for a release.
    pub unrecognised: usize,
    /// How the last command or transfer turned out.
    pub last_completion: Option<trb::CompletionCode>,
    /// Which command the last completion was answering.
    pub last_command: u64,
    /// Which port the last change concerned.
    pub last_port: u8,
    /// Bytes the last transfer event says were **not** moved.
    ///
    /// A residue and not a count: a complete transfer reports zero here, and
    /// reading it as "bytes moved" inverts every length a driver computes.
    pub remaining: u32,
    /// Which slot the last completion concerned.
    ///
    /// An Enable Slot completion carries the slot the controller handed out,
    /// and it is carried here rather than returned separately because it
    /// arrives the same way every other answer does.
    pub last_slot: u8,
}

impl Drained {
    /// Folds a later drain's results into this one.
    ///
    /// Counts add. The "last" fields take the later round's value only when
    /// that round saw an event of the matching kind, because a round that
    /// drained nothing of a kind has no opinion about it and must not
    /// overwrite what an earlier round learned.
    fn absorb(&mut self, other: Self) {
        self.events += other.events;
        self.command_completions += other.command_completions;
        self.port_changes += other.port_changes;
        self.transfers += other.transfers;
        self.host_controller += other.host_controller;
        self.unrecognised += other.unrecognised;
        if other.command_completions > 0 || other.transfers > 0 {
            self.last_completion = other.last_completion;
            self.last_command = other.last_command;
            self.last_slot = other.last_slot;
            self.remaining = other.remaining;
        }
        if other.port_changes > 0 {
            self.last_port = other.last_port;
        }
    }
}

/// Consumes every event the controller has published, and dispatches by kind.
///
/// **Pure, and reads through a closure rather than a slice.** The event ring is
/// written by the controller by DMA while this runs, so a `&[Trb]` over it would
/// be a shared reference to memory something else is writing. The closure lets
/// the kernel read each entry volatilely and lets a host test answer from an
/// array — which is what makes the whole of RFC 0041 step 4's logic testable
/// without a controller.
///
/// Bounded at one lap. A controller that publishes faster than this drains is
/// not a reason to stay in here for ever; the caller comes back.
pub fn drain(
    entries: usize,
    consumer: &mut ring::Consumer,
    read: &mut dyn FnMut(usize) -> trb::Trb,
) -> Drained {
    let mut found = Drained::default();
    for _ in 0..entries {
        let event = read(consumer.index());
        // **The cycle bit is the whole protocol.** An entry whose bit does not
        // match this consumer's lap has not been written by the controller yet,
        // whatever else it contains -- and what it contains is the previous
        // lap's event, which is why reading one is not a harmless mistake.
        if !consumer.owns(event.cycle_bit()) {
            break;
        }
        found.events += 1;
        match event.kind() {
            trb::Kind::CommandCompletion => {
                found.command_completions += 1;
                found.last_completion = Some(event.completion_code());
                found.last_command = event.command_trb_pointer();
                found.last_slot = event.slot_id();
            }
            trb::Kind::PortStatusChange => {
                found.port_changes += 1;
                found.last_port = event.port_id();
            }
            trb::Kind::TransferEvent => {
                found.transfers += 1;
                found.last_completion = Some(event.completion_code());
                found.remaining = event.transfer_length_remaining();
            }
            trb::Kind::HostController => {
                found.host_controller += 1;
                found.last_completion = Some(event.completion_code());
            }
            _ => found.unrecognised += 1,
        }
        consumer.advance();
    }
    found
}

/// How much of a controller's BAR this driver maps.
///
/// The banks are at offsets the controller reports, and this is the bound they
/// are checked against — a controller whose doorbells sit past this is
/// **refused** by [`parameters`] rather than read past the mapping. Sixty-four
/// kilobytes covers every controller anyone has described; reading the BAR's
/// real size needs the write-all-ones dance on a live bus master, which is a
/// larger thing to get right than a bound that refuses loudly.
const WINDOW_BYTES: u64 = 0x1_0000;

/// The most descriptor bytes this driver will read in one transfer.
///
/// A configuration descriptor's total length is the **device's** number, and it
/// sizes a transfer into a one-page buffer -- RFC 0038's rule 6. A keyboard's
/// configuration is a few dozen bytes; anything claiming more than this is
/// refused rather than truncated, because a truncated read of a
/// length-prefixed, nested structure is what the parser is fuzzed against and
/// not what it should be handed.
const MAX_DESCRIPTOR_BYTES: usize = 1024;

/// The most scratchpad buffers this driver will provide, each a whole page.
///
/// The controller names the count and the count sizes an allocation, so it is
/// bounded before it is believed — RFC 0038's rule 6. A controller wanting more
/// than this is refused rather than partially satisfied, because a controller
/// given fewer buffers than it asked for does not run.
///
/// # Sixty-four, and the reasoning that produced 32 was wrong
///
/// Thirty-two was a guess that fitted every controller this driver had met —
/// all of them QEMU's, and QEMU asks for **none**, so the whole scratchpad path
/// had never executed anywhere. On 2026-08-24 an Intel C620 on an SR550 asked
/// for **34** and was refused.
///
/// The obvious repair was to raise the bound to the structure's own limit — one
/// frame of 64-bit pointers, `FRAME_SIZE / 8` = 512. That was built, booted on
/// the machine, and the boot **hung** inside bring-up, against a clean refusal
/// for the same machine at 32. This comment then recorded the conclusion that
/// raising the bound had made things worse, and put it back.
///
/// **That conclusion was wrong, and it is worth saying why rather than
/// deleting it.** The bound was never what hung the machine. At 32 the driver
/// refused *before* `bring_up` and the controller was never started; at 512 it
/// got past the refusal and reached the code that hangs. Raising the limit did
/// not cause the failure, it revealed it — and the real cause was that this
/// driver started a controller firmware still owned, which raises a System
/// Management Interrupt firmware can no longer service. See [`take_ownership`].
/// A number was blamed for a hang because changing it changed the symptom,
/// which is the cheapest kind of wrong explanation to believe.
///
/// Sixty-four covers the one measurement there is with room above it, and is
/// small enough that the allocation stays a page of pointers and 64 frames.
/// [`InitError::TooManyScratchpads`] carries both numbers, so the next
/// controller that wants more says so instead of merely failing.
const MAX_SCRATCHPADS: u32 = 64;

/// Microseconds any one register is given to settle.
const SETTLE_MICROS: u64 = 500_000;

/// Spins any one wait will take when there is no clock to bound it with.
///
/// **The second bound, and it is not redundant.** `time::micros` answers `None`
/// on a machine whose clock has not been calibrated, and the house fallback for
/// that is a deadline so far out it is not one. A bring-up that hangs on a
/// machine with no timer is a machine that cannot be booted far enough to say
/// why — which is the failure `smp::start_secondaries` had until `337b16f`.
const MAX_SPINS: u64 = 50_000_000;

/// The kernel's waiter: a deadline off the clock, with a spin cap behind it.
struct Settle;

impl Wait for Settle {
    fn until(&mut self, ready: &mut dyn FnMut() -> bool) -> bool {
        let budget = crate::time::micros(SETTLE_MICROS);
        let deadline = budget.map(|span| crate::time::now() + span);
        let mut spins = 0u64;
        loop {
            if ready() {
                return true;
            }
            if let Some(deadline) = deadline
                && crate::time::now() >= deadline
            {
                return false;
            }
            spins += 1;
            if spins >= MAX_SPINS {
                return false;
            }
            core::hint::spin_loop();
        }
    }
}

/// What a brought-up controller cost and what it is.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Started {
    /// What the controller reported once running.
    pub running: Running,
    /// Frames handed to it, all of them mapped into its own window.
    pub frames: usize,
    /// What asking it a question produced. RFC 0041 step 4.
    pub answered: Answered,
    /// What addressing a device produced. RFC 0041 step 5.
    pub attached: Attached,
}

/// Why a controller could not be brought up, from the kernel's side.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum InitError {
    /// No xHCI controller on the bus.
    NotFound,
    /// The controller is not behind an IOMMU translation. RFC 0038's rule 1,
    /// and the one refusal this driver exists to make first.
    NotTranslated,
    /// Its BAR is not memory, or is absent.
    NoRegisters,
    /// The register window could not be mapped.
    MapFailed,
    /// A frame could not be allocated for a ring, a table or a scratchpad.
    OutOfMemory,
    /// A frame was allocated and the window would not map it, so the
    /// controller has no way to reach it.
    NotMappable,
    /// The controller wants more scratchpad buffers than this driver provides.
    ///
    /// **Carries both numbers.** A refusal that says only "more than this
    /// driver provides" cannot be acted on: the reader learns there is a limit
    /// and not what it is or how far past it the machine is. That cost a reboot
    /// of a live server on 2026-08-24 to find out.
    TooManyScratchpads {
        /// What the controller's `HCSPARAMS2` asked for.
        wanted: u32,
        /// What this driver will provide -- one array frame's worth.
        limit: u32,
    },
    /// Firmware would not hand the controller over. Specification §4.22.1.
    FirmwareKeptTheController,
    /// The bring-up itself refused.
    BringUp(BringUpError),
}

impl InitError {
    /// One line, for the boot report.
    #[must_use]
    pub const fn describe(self) -> &'static str {
        match self {
            Self::NotFound => "no xHCI controller on the bus",
            Self::NotTranslated => {
                "it is not behind an IOMMU translation, and a bus master without one \
                 can read and write all of memory"
            }
            Self::NoRegisters => "its base address register is not memory",
            Self::MapFailed => "its register window could not be mapped",
            Self::OutOfMemory => "no frame for a ring, a table or a scratchpad",
            Self::NotMappable => "a frame could not be mapped into its window",
            Self::FirmwareKeptTheController => {
                "firmware would not hand it over within the second the specification allows"
            }
            Self::TooManyScratchpads { .. } => {
                "it wants more scratchpad buffers than this driver provides"
            }
            Self::BringUp(error) => error.describe(),
        }
    }
}

/// A frame, zeroed, with both the addresses that matter for it.
///
/// The kernel writes at `virtual_address`; the controller reads at `device`,
/// which is what its window translates. **They are different numbers**, and a
/// structure filled with physical addresses instead of device ones is a
/// controller reading whatever happens to live at those addresses in its own
/// translation — which is nothing, so it silently does not start.
struct Frame {
    virtual_address: u64,
    device: u64,
}

/// Allocates a zeroed frame and maps it into `controller`'s window.
/// The lowest and highest physical frame this driver has allocated.
///
/// Recorded so that a DMA fault naming an address can be **classified** rather
/// than stared at. A refused address inside this range is a frame this driver
/// owns, which means a device address and a physical address were confused
/// somewhere in this kernel; an address outside it is memory nobody here ever
/// handed to the controller. Those are different bugs and the boot report
/// could not tell them apart.
static FRAMES_LOW: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(u64::MAX);
static FRAMES_HIGH: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// The physical extent of what this driver allocated, if it allocated anything.
#[must_use]
pub fn frame_extent() -> Option<(u64, u64)> {
    let low = FRAMES_LOW.load(core::sync::atomic::Ordering::Acquire);
    let high = FRAMES_HIGH.load(core::sync::atomic::Ordering::Acquire);
    (low <= high).then_some((low, high))
}

fn frame(controller: (u8, u8, u8), hhdm: u64) -> Result<Frame, InitError> {
    use bhaskix_mm::{FRAME_SIZE, Zone};

    let pfn = crate::heap::with(|heap| heap.pmm_mut().allocate(0, Zone::Normal).ok())
        .flatten()
        .ok_or(InitError::OutOfMemory)?;
    let physical = u64::from(pfn) * FRAME_SIZE;
    // SAFETY: a frame that was just allocated, so nothing else refers to it,
    // reachable through the direct map. Zeroed because the controller reads it
    // and a stale pointer is an address it will happily do DMA to.
    unsafe {
        core::ptr::write_bytes((hhdm + physical) as *mut u8, 0, FRAME_SIZE as usize);
    }
    FRAMES_LOW.fetch_min(physical, core::sync::atomic::Ordering::AcqRel);
    FRAMES_HIGH.fetch_max(
        physical + FRAME_SIZE - 1,
        core::sync::atomic::Ordering::AcqRel,
    );

    let device = crate::iommu::map_frame(controller, physical, hhdm)
        .ok_or(InitError::NotMappable)?
        .as_u64();
    Ok(Frame {
        virtual_address: hhdm + physical,
        device,
    })
}

/// Finds the controller, gives it memory it can reach, and starts it.
///
/// RFC 0041 step 3. What this does **not** do is read anything the controller
/// says: the event ring is armed and nobody is listening to it yet, which is
/// step 4.
///
/// # Safety
///
/// Must be called once, during boot, after the IOMMU windows exist — a
/// controller with no window is refused here, and asking before the windows are
/// built refuses one that should have been driven.
pub unsafe fn init(hhdm: u64) -> Result<Started, InitError> {
    // SAFETY: the caller's obligation; configuration reads only.
    let controller = unsafe { probe() }.ok_or(InitError::NotFound)?;

    // **Rule 1, before anything else happens.** Not a warning, not a degraded
    // mode: a controller with no translation is not driven at all.
    if !crate::iommu::present_for(controller) {
        return Err(InitError::NotTranslated);
    }

    let address = pci::Address {
        bus: controller.0,
        device: controller.1,
        function: controller.2,
    };

    // Memory space on, **bus mastering deliberately off**. The BARs have to be
    // readable to find out what this is, and until the controller has been
    // reset it is still configured the way firmware left it -- which with
    // translation on is a fault against a driver that has not started. RFC 0012
    // step 4 found this ordering the hard way.
    // SAFETY: this driver owns this controller from here on.
    unsafe { pci::enable_memory(address) };

    // SAFETY: configuration read of a function that is present.
    let pci::Bar::Memory { address: bar, .. } = (unsafe { pci::bar(address, 0) }) else {
        return Err(InitError::NoRegisters);
    };

    let base = crate::mmio::map(bar, WINDOW_BYTES, hhdm).ok_or(InitError::MapFailed)? as usize;

    // SAFETY: `base` is the mapped window, `WINDOW_BYTES` long, and every bank
    // offset read here is checked against that length.
    let parameters = unsafe { parameters::<bhaskix_device::Volatile>(base, WINDOW_BYTES as usize) }
        .map_err(InitError::BringUp)?;

    // **Before the controller is touched at all.** `bring_up`'s contract has
    // said "this driver must own the controller" since it was written, and
    // nothing enforced it: on an emulator there is no firmware to take it from,
    // so the unenforced contract held by luck for as long as only emulators ran
    // this code. On a server it does not, and the first thing the driver does
    // to an unowned controller -- halt it -- is already a violation.
    // SAFETY: `base` is the mapped window, `WINDOW_BYTES` long, and every
    // offset reached is checked against that length.
    let ownership = unsafe {
        take_ownership::<bhaskix_device::Volatile, _>(
            base,
            WINDOW_BYTES as usize,
            &parameters,
            &mut Settle,
        )
    };
    match ownership {
        Ownership::NoCapability => {
            crate::println!("    xhci           no legacy capability; firmware never claimed it");
        }
        Ownership::Held {
            firmware_held,
            silenced,
        } => {
            crate::println!(
                "    xhci           taken from firmware: semaphore {}, smi {}",
                if firmware_held { "held" } else { "clear" },
                if silenced { "disarmed" } else { "already off" },
            );
        }
        Ownership::Refused => return Err(InitError::FirmwareKeptTheController),
    }

    if parameters.scratchpads > MAX_SCRATCHPADS {
        return Err(InitError::TooManyScratchpads {
            wanted: parameters.scratchpads,
            limit: MAX_SCRATCHPADS,
        });
    }

    let device_contexts = frame(controller, hhdm)?;
    let command_ring = frame(controller, hhdm)?;
    let event_ring = frame(controller, hhdm)?;
    let segment_table = frame(controller, hhdm)?;
    let mut frames = 4;

    // The scratchpad array, and the buffers it points at. **Installed at entry
    // zero of the device context array before the controller is told anything**
    // — which is why `Memory` is described as prepared: the ordering rule holds
    // because there is no later step that could get it wrong.
    if parameters.scratchpads > 0 {
        let array = frame(controller, hhdm)?;
        frames += 1;
        for index in 0..parameters.scratchpads as usize {
            let buffer = frame(controller, hhdm)?;
            frames += 1;
            // SAFETY: a frame this function allocated, written at an index
            // bounded by `MAX_SCRATCHPADS`, which is far inside one frame.
            unsafe {
                core::ptr::write_volatile(
                    (array.virtual_address as *mut u64).add(index),
                    buffer.device,
                );
            }
        }
        // SAFETY: entry zero of the array this function allocated.
        unsafe {
            core::ptr::write_volatile(device_contexts.virtual_address as *mut u64, array.device);
        }
    }

    // **The command ring's Link TRB, and step 3 did not write one.** Nothing
    // read the ring then -- the doorbell was never rung -- so a missing link
    // cost nothing and was invisible. Step 4 rings it, and the last entry of a
    // command ring must be a Link back to the start or the controller reads a
    // zeroed TRB, finds a type of 0, and stops. It toggles the cycle, because
    // this is a one-segment ring and the lap has to flip somewhere.
    //
    // An event ring gets none: the controller wraps that one by the segment
    // table, which is the asymmetry `ring::Consumer` exists to hold on to.
    let (link_index, link) = command_ring_link(command_ring.device, RING_ENTRIES)
        .ok_or(InitError::BringUp(BringUpError::RingTooSmall))?;
    // SAFETY: a frame this function allocated and zeroed, written at an index
    // `command_ring_link` bounds to inside the ring, which is far inside one
    // frame.
    unsafe {
        core::ptr::write_volatile(
            (command_ring.virtual_address as *mut [u32; 4]).add(link_index),
            link.0,
        );
    }

    // The event ring segment table, describing the one segment there is.
    let entry = trb::SegmentTableEntry::new(event_ring.device, RING_ENTRIES as u16)
        .ok_or(InitError::NotMappable)?;
    // SAFETY: a frame this function allocated and zeroed, written at its start.
    unsafe {
        core::ptr::write_volatile(segment_table.virtual_address as *mut [u32; 4], entry.0);
    }

    let memory = Memory {
        device_contexts: device_contexts.device,
        command_ring: command_ring.device,
        command_ring_entries: RING_ENTRIES,
        event_ring: event_ring.device,
        event_ring_entries: RING_ENTRIES,
        segment_table: segment_table.device,
        scratchpads: parameters.scratchpads,
    };

    // Every table the controller will read is written and reachable. Only now
    // may it become a bus master.
    // SAFETY: this driver owns this controller.
    unsafe { pci::enable(address) };

    // SAFETY: `base` is the mapped window `parameters` was read and bounded
    // from, and this driver owns the controller.
    let running = unsafe {
        bring_up::<bhaskix_device::Volatile, Settle>(base, &parameters, &memory, &mut Settle)
    }
    .map_err(InitError::BringUp)?;

    // RFC 0041 step 4: ask the controller a question and read its answer.
    //
    // A running controller is only a controller that is *not halted*. This is
    // the first thing that proves the rings are real in both directions -- the
    // command ring the driver writes and the event ring the controller does.
    let mut commander = Commander::new(
        base,
        &parameters,
        &memory,
        command_ring.virtual_address,
        event_ring.virtual_address,
    )
    .ok_or(InitError::BringUp(BringUpError::RingTooSmall))?;

    // SAFETY: the controller is running, and this is its memory and its window.
    let answered = unsafe { exercise_the_rings(&mut commander, &mut Settle) };

    // RFC 0041 step 5: find a device, take a slot for it, and give it an
    // address. Only attempted once the rings have answered -- addressing a
    // device through a conversation that has not been shown to work would
    // report a failure of the wrong thing.
    let attached = if answered.matched {
        // SAFETY: as above, and the controller has answered once already.
        unsafe {
            address_a_device(
                &mut commander,
                controller,
                &parameters,
                device_contexts.virtual_address,
                hhdm,
                &mut Settle,
            )
        }
    } else {
        Attached::default()
    };

    Ok(Started {
        running,
        frames: frames + attached.frames,
        answered,
        attached,
    })
}

/// A conversation with the controller: the command ring out, the event ring in.
///
/// **Step 4 did this once for a No-Op and step 5 needs it three times**, so the
/// one-shot became a small engine rather than being copied. It owns the two
/// cursors, because their state is the protocol: where the next command goes,
/// which cycle bit publishes it, and which entry of the event ring is the
/// driver's turn to read.
struct Commander<'a> {
    base: usize,
    parameters: &'a Parameters,
    memory: &'a Memory,
    /// The kernel's view of the command ring.
    command: u64,
    /// The kernel's view of the event ring.
    event: u64,
    producer: ring::Producer,
    consumer: ring::Consumer,
    /// Whether the dequeue pointer has been written back at least once.
    dequeue_advanced: bool,
}

/// What the controller said about itself when asked.
///
/// Read when a command goes unanswered, because "no event arrived" is a
/// symptom and these bits are the difference between the causes: a controller
/// that stopped, a controller whose memory reads are being refused, and a
/// controller that never started running the command ring at all.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct ControllerState {
    /// `USBSTS`, as read.
    pub status: u32,
    /// `CRCR`. Command Ring Running is bit 3, and the rest reads as zero.
    pub command_ring: u64,
}

impl ControllerState {
    /// Whether the controller has stopped.
    #[must_use]
    pub const fn halted(self) -> bool {
        operational::UsbStatus(self.status).hc_halted()
    }

    /// Whether a memory read or write by the controller was answered with an
    /// error — which is what an IOMMU refusal looks like from this side.
    #[must_use]
    pub const fn host_system_error(self) -> bool {
        operational::UsbStatus(self.status).host_system_error()
    }

    /// Whether the controller has faulted internally.
    #[must_use]
    pub const fn host_controller_error(self) -> bool {
        operational::UsbStatus(self.status).host_controller_error()
    }

    /// Whether the command ring is running. Bit 3 of `CRCR`.
    ///
    /// Clear after a doorbell means the controller never picked the ring up,
    /// which is a different failure from picking it up and finding nothing.
    #[must_use]
    pub const fn command_ring_running(self) -> bool {
        self.command_ring & (1 << 3) != 0
    }
}

/// What one command produced.
struct Issued {
    /// Where the command TRB was written, in the controller's addresses.
    asked_at: u64,
    /// Everything the drain found, which may include events for other things.
    drained: Drained,
    /// Whether anything arrived before the deadline.
    arrived: bool,
    /// What the controller said about itself once the wait ended.
    state: ControllerState,
}

impl Issued {
    /// Whether the completion answered *this* command and answered it well.
    const fn succeeded(&self) -> bool {
        self.drained.command_completions > 0
            && self.drained.last_command == self.asked_at
            && match self.drained.last_completion {
                Some(code) => code.is_success(),
                None => false,
            }
    }
}

impl<'a> Commander<'a> {
    /// Prepares to talk to a running controller.
    fn new(
        base: usize,
        parameters: &'a Parameters,
        memory: &'a Memory,
        command: u64,
        event: u64,
    ) -> Option<Self> {
        Some(Self {
            base,
            parameters,
            memory,
            command,
            event,
            producer: ring::Producer::new(memory.command_ring_entries)?,
            consumer: ring::Consumer::new(memory.event_ring_entries)?,
            dequeue_advanced: false,
        })
    }

    /// Writes one command, rings the doorbell, and drains what comes back.
    ///
    /// `build` is handed the cycle bit the command must carry, because that is
    /// the producer's state and not the caller's business to track.
    ///
    /// # Safety
    ///
    /// The controller must be running and this `Commander`'s addresses must be
    /// its rings.
    unsafe fn issue<W: Wait>(
        &mut self,
        build: impl FnOnce(bool) -> trb::Trb,
        wait: &mut W,
    ) -> Option<Issued> {
        // **The lap is not handled, so it is refused.** Wrapping means
        // re-publishing the Link TRB with the producer's new cycle, and nothing
        // here does that yet -- a ring that silently wrapped would hand the
        // controller a link carrying the previous lap's bit, which it reads as
        // stale and stops on. Step 5 issues three commands into a ring of
        // sixteen; the refusal is here so that the day a caller issues fifteen
        // it is told, rather than finding out from a controller that went quiet.
        if self.producer.remaining_this_lap() == 0 {
            return None;
        }

        let doorbell_offset =
            bhaskix_xhci::doorbell::doorbell_at(bhaskix_xhci::doorbell::COMMAND_RING)?;

        // Where the controller will say it found this command. The *device*
        // address, because that is the number the controller deals in -- naming
        // the physical one would compare an answer against a question nobody
        // asked.
        let asked_at = self.memory.command_ring + (self.producer.index() * trb::BYTES) as u64;

        // SAFETY: a frame `init` allocated and zeroed, at an index `Producer`
        // bounds to inside the ring.
        unsafe {
            core::ptr::write_volatile(
                (self.command as *mut [u32; 4]).add(self.producer.index()),
                build(self.producer.cycle()).0,
            );
        }
        self.producer.advance();

        // SAFETY: the doorbell bank is inside the window, which `parameters`
        // checked, and the offset is bounded by `doorbell_at`.
        let doorbell = unsafe {
            DoorbellRegister::<bhaskix_device::Volatile>::new(
                self.base + self.parameters.doorbells + doorbell_offset,
            )
        };
        doorbell
            .value
            .write(bhaskix_xhci::doorbell::Doorbell::command().0);

        // Wait for **this command's** answer, not for the next event to
        // appear. Ownership is the cycle bit and nothing else: a zeroed entry
        // has bit 0, a fresh consumer expects 1, so "not written yet" and
        // "written" are distinguishable without reading anything else.
        //
        // # Why this is a loop, and what it cost to find out
        //
        // This used to wait for one owned entry, drain once, and take whatever
        // that found as the answer. The event ring carries **every** kind of
        // event, and the events waiting there are very often not answers to
        // anything this function asked: a port reset moments earlier leaves
        // Port Status Change Events sitting at the consumer's index, so the
        // wait returns immediately, the drain consumes those, and the command's
        // completion -- which the controller had not written yet -- is reported
        // as never having arrived.
        //
        // On an emulator the completion is already in the ring by the time
        // anything is read, so one drain finds both and the difference never
        // shows. On an SR550 it showed as `Enable Slot` failing with **no
        // completion code at all**, immediately after a No-Op on the same ring
        // succeeded, which is the shape of a race rather than a refusal.
        let event_ring = self.event;
        let entries = self.memory.event_ring_entries;
        let mut drained = Drained::default();
        let mut arrived = false;

        for _ in 0..DRAIN_ROUNDS {
            let consumer = &self.consumer;
            let owned = wait.until(&mut || {
                // SAFETY: the event ring is a frame `init` allocated; this
                // reads one TRB at an index `Consumer` bounds to inside it.
                // Volatile because the controller writes here by DMA.
                let event = unsafe {
                    core::ptr::read_volatile((event_ring as *const [u32; 4]).add(consumer.index()))
                };
                consumer.owns(trb::Trb(event).cycle_bit())
            });
            if !owned {
                break;
            }
            arrived = true;
            drained.absorb(drain(entries, &mut self.consumer, &mut |index| {
                // SAFETY: as above.
                trb::Trb(unsafe {
                    core::ptr::read_volatile((event_ring as *const [u32; 4]).add(index))
                })
            }));
            // The answer to *this* command, which is the only thing that ends
            // the wait early. Anything else drained on the way is kept and
            // counted, because an event this driver did not expect is a fact
            // about the controller worth reporting.
            if drained.command_completions > 0 && drained.last_command == asked_at {
                break;
            }
        }

        // SAFETY: the runtime bank is inside the window, which `parameters`
        // checked.
        unsafe { self.advance_dequeue() };

        // What the controller says about itself, read *after* the wait so it
        // describes the state the failure happened in rather than the state
        // before it. Cheap enough to read always: a command that succeeded
        // still carries it, and nothing has to decide in advance whether this
        // is going to be the interesting case.
        // SAFETY: the operational bank is inside the window, which
        // `parameters` checked.
        let operational_bank = unsafe {
            Operational::<bhaskix_device::Volatile>::new(self.base + self.parameters.operational)
        };
        let state = ControllerState {
            status: operational_bank.usbsts.read(),
            command_ring: operational_bank.crcr.read(),
        };

        Some(Issued {
            asked_at,
            drained,
            arrived,
            state,
        })
    }

    /// Waits for the controller to publish something, then drains it.
    ///
    /// The half of `issue` that has nothing to do with commands -- a transfer
    /// is rung on a slot's doorbell rather than the command ring's, and its
    /// answer arrives on the same event ring.
    ///
    /// # Safety
    ///
    /// The event ring must be this commander's.
    unsafe fn await_events<W: Wait>(&mut self, wait: &mut W) -> Drained {
        let consumer = &self.consumer;
        let event_ring = self.event;
        wait.until(&mut || {
            // SAFETY: the caller's obligation; one TRB at a bounded index.
            let event = unsafe {
                core::ptr::read_volatile((event_ring as *const [u32; 4]).add(consumer.index()))
            };
            consumer.owns(trb::Trb(event).cycle_bit())
        });
        let drained = drain(
            self.memory.event_ring_entries,
            &mut self.consumer,
            &mut |index| {
                // SAFETY: as above.
                trb::Trb(unsafe {
                    core::ptr::read_volatile((event_ring as *const [u32; 4]).add(index))
                })
            },
        );
        // SAFETY: the runtime bank is inside the window.
        unsafe { self.advance_dequeue() };
        drained
    }

    /// Tells the controller how far this driver has consumed.
    ///
    /// **And clears Event Handler Busy while doing it**, which is the write that
    /// says "I am done looking". Without it the controller will not raise the
    /// interrupter again, which is a ring that works exactly once -- and works
    /// once is what every gate weaker than this one would accept.
    ///
    /// # Safety
    ///
    /// The runtime bank must be inside the mapped window.
    unsafe fn advance_dequeue(&mut self) {
        let Some(interrupter_zero) = runtime::interrupter_at(0) else {
            return;
        };
        let Some(dequeue) = runtime::EventRingDequeuePointer::advancing(
            self.memory.event_ring + (self.consumer.index() * trb::BYTES) as u64,
            0,
            true,
        ) else {
            return;
        };
        // SAFETY: the caller's obligation.
        let interrupter = unsafe {
            Interrupter::<bhaskix_device::Volatile>::new(
                self.base + self.parameters.runtime + interrupter_zero,
            )
        };
        interrupter.erdp.write(dequeue.0);
        self.dequeue_advanced = true;
    }
}

/// The three TRBs of one control transfer, in the order they go on the ring.
///
/// **Built as a list rather than written straight to memory**, so that the
/// staging — which stages exist, which way each points, and which one carries
/// Interrupt On Completion — is a value a host test can hold. Everything about
/// a control transfer that a driver gets wrong is in this shape, and none of it
/// needs a controller to check.
///
/// `data` is `None` for a request with no data stage; the transfer is then two
/// TRBs and not three.
///
/// `None` if the length does not fit a data stage's transfer-length field.
#[must_use]
pub fn control_transfer_stages(
    setup: [u8; 8],
    buffer: u64,
    length: u16,
    device_to_host: bool,
    cycle: bool,
) -> Option<([trb::Trb; 3], usize)> {
    let direction = if device_to_host {
        trb::Direction::In
    } else {
        trb::Direction::Out
    };
    let transfer = if length == 0 {
        trb::TransferType::NoData
    } else if device_to_host {
        trb::TransferType::In
    } else {
        trb::TransferType::Out
    };

    let setup_stage = trb::Trb::setup_stage(setup, transfer, cycle);

    if length == 0 {
        // **A status stage after no data points IN**, not at the opposite of a
        // direction there was none of. The specification's rule is that a
        // transfer with no data stage is acknowledged by reading nothing.
        let status =
            trb::Trb::status_stage(trb::Direction::In, cycle).with_interrupt_on_completion(true);
        return Some(([setup_stage, status, trb::Trb::new()], 2));
    }

    let data = trb::Trb::data_stage(buffer, u32::from(length), direction, cycle)?;
    // **The last TRB carries Interrupt On Completion and only the last one.**
    // The controller executes the whole descriptor and reports where it is
    // asked to; a transfer whose final stage does not ask completes correctly
    // and silently, and the driver waits for ever.
    let status =
        trb::Trb::status_stage(direction.opposite(), cycle).with_interrupt_on_completion(true);
    Some(([setup_stage, data, status], 3))
}

/// A port with something plugged into it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Connected {
    /// `PORTSC` as it read once the port had settled.
    ///
    /// Carried so a failure to address can print the port's actual state
    /// rather than leave a reader to infer it. Link state, connect, enable and
    /// speed are all in here, and "the device did not answer" says none of
    /// them.
    portsc: u32,
    /// Which port, numbered from one as the specification numbers them.
    pub port: u8,
    /// The negotiated speed, from `PORTSC` bits 13:10.
    pub speed: u32,
    /// Whether it had to be reset before it enabled.
    pub reset: bool,
}

/// Finds the first port with an enabled device on it.
///
/// **A USB 3 port enables itself on connect and a USB 2 port must be reset**,
/// and a driver cannot tell which kind it is looking at from the port number:
/// the split between them is a controller's own business. So the rule is not
/// "reset USB 2 ports" but *if it is connected and not enabled, reset it* --
/// which is right for both and needs to know neither.
///
/// # Safety
///
/// `base` must be the mapped window and the port registers inside it, which
/// [`parameters`] checked.
/// Reports what every root hub port says about itself.
///
/// **Because "no port has a device on it" is not a finding.** With 26 ports on
/// a real machine that line says nothing about whether the ports are powered,
/// whether anything is attached, or whether the driver looked too early. Each
/// of those is a different bug and they were indistinguishable.
///
/// Ports with nothing to say are counted rather than printed: a boot report
/// that lists 26 empty ports has buried the two that matter.
///
/// # Safety
///
/// The controller must be running and `base` its mapped window.
unsafe fn report_ports(base: usize, parameters: &Parameters) {
    let mut powered = 0u32;
    let mut connected = 0u32;
    let mut quiet = 0u32;

    for port in 1..=parameters.ports {
        let Some(offset) = operational::port_status_control(port) else {
            continue;
        };
        // SAFETY: the caller's obligation; the port register array is inside
        // the operational bank, which is inside the window.
        let register = unsafe {
            PortRegister::<bhaskix_device::Volatile>::new(base + parameters.operational + offset)
        };
        let status = operational::PortStatusControl(register.portsc.read());

        if status.port_power() {
            powered += 1;
        }
        if status.current_connect_status() {
            connected += 1;
            crate::println!(
                "    xhci port {port:<2}   connected: {}, {}, link state {}, speed {}",
                if status.port_power() {
                    "powered"
                } else {
                    "NOT POWERED"
                },
                if status.port_enabled() {
                    "enabled"
                } else {
                    "not enabled"
                },
                status.port_link_state(),
                status.port_speed(),
            );
        } else {
            quiet += 1;
        }
    }

    crate::println!(
        "    xhci ports     {} of {} powered, {connected} with something attached, {quiet} quiet",
        powered,
        parameters.ports,
    );
}

/// How long a port must report a connection before the driver believes it.
///
/// **A connection is not a device.** A port that has just reported one is
/// mid-transition, and resetting it then addresses something that is not ready
/// to answer -- which on an SR550 came back as `Address Device` completing with
/// **USB Transaction Error**: the controller asked and nothing replied.
///
/// The values are the ones Linux's `drivers/usb/core/hub.c` uses, read from it
/// rather than recalled: stable for 100 ms, sampled every 25 ms, and give up
/// after 2 seconds.
const DEBOUNCE_STABLE_MICROS: u64 = 100_000;
/// How often the port is sampled while debouncing.
const DEBOUNCE_STEP_MICROS: u64 = 25_000;
/// How long to keep looking for a port to settle before deciding none will.
const DEBOUNCE_TIMEOUT_MICROS: u64 = 2_000_000;

/// How many times an Address Device command is attempted before giving up.
///
/// Three, which is one more than Linux's `SET_ADDRESS_TRIES`.
///
/// ~~The extra is because this driver has no `Disable Slot`/`Enable Slot`
/// recovery to fall back on yet.~~ **It has one as of 2026-08-25**, and that
/// is what the attempts after the first now do: xHCI 1.2 §4.6.5 says a USB
/// Transaction Error here *"should"* be recovered by releasing the slot and
/// taking a new one, and the loop below does exactly that between attempts
/// rather than re-asking a slot the same paragraph says is left in the Default
/// state. The count stays at three: the recovery is what changed, not how many
/// times it is worth trying.
const ADDRESS_TRIES: u8 = 3;

/// How long to leave a device alone after resetting its port.
///
/// USB calls this `TRSTRCY` and requires 10 ms. Linux waits 10 + 40, and the
/// extra is not superstition: a device that is addressed the instant its port
/// enables is a device that has not finished coming out of reset.
const RESET_RECOVERY_MICROS: u64 = 50_000;

/// How many spins stand in for a delay on a machine with no calibrated clock.
///
/// The same second bound `Settle` carries and for the same reason: a boot that
/// hangs in a delay loop is a machine that cannot say why.
const PAUSE_SPINS: u64 = 2_000_000;

/// Spins for roughly `micros`.
///
/// A busy wait rather than `time::sleep_micros`, because this runs during
/// bring-up on the boot path and a driver that yields here is a driver whose
/// device state can change under it.
fn pause(micros: u64) {
    let Some(span) = crate::time::micros(micros) else {
        for _ in 0..PAUSE_SPINS {
            core::hint::spin_loop();
        }
        return;
    };
    let deadline = crate::time::now() + span;
    let mut spins = 0u64;
    while crate::time::now() < deadline {
        spins += 1;
        if spins >= PAUSE_SPINS {
            return;
        }
        core::hint::spin_loop();
    }
}

/// Whether a port currently reports something attached.
///
/// # Safety
///
/// `base` must be the controller's mapped window.
unsafe fn port_connected(base: usize, parameters: &Parameters, port: u8) -> bool {
    let Some(offset) = operational::port_status_control(port) else {
        return false;
    };
    // SAFETY: the caller's obligation; the port register array is inside the
    // operational bank, which is inside the window.
    let register = unsafe {
        PortRegister::<bhaskix_device::Volatile>::new(base + parameters.operational + offset)
    };
    operational::PortStatusControl(register.portsc.read()).current_connect_status()
}

/// The first port that has reported a connection steadily, or `None`.
///
/// **Steadily**, which is the whole point: the driver used to scan once and
/// take the first port with the connect bit set. A port sampled during the
/// moment it changes reports a connection that is not yet a device, and
/// everything after that -- reset, slot, address -- is done to something that
/// is not listening.
///
/// # Safety
///
/// The controller must be running and `base` its mapped window.
unsafe fn debounced_port(base: usize, parameters: &Parameters) -> Option<u8> {
    let mut waited = 0;
    let mut steady: Option<(u8, u64)> = None;

    while waited < DEBOUNCE_TIMEOUT_MICROS {
        // SAFETY: the caller's obligation.
        let found =
            (1..=parameters.ports).find(|&port| unsafe { port_connected(base, parameters, port) });

        steady = match (found, steady) {
            // The same port again: it has now been connected for one more
            // sampling interval.
            (Some(port), Some((before, held))) if before == port => {
                let held = held + DEBOUNCE_STEP_MICROS;
                if held >= DEBOUNCE_STABLE_MICROS {
                    return Some(port);
                }
                Some((port, held))
            }
            // A different port, or the first one seen: start counting again.
            (Some(port), _) => Some((port, 0)),
            // Nothing attached right now, so nothing is steady.
            (None, _) => None,
        };

        pause(DEBOUNCE_STEP_MICROS);
        waited += DEBOUNCE_STEP_MICROS;
    }
    None
}

/// Whether a port has come back from its reset ready to be addressed.
///
/// Connected, enabled and settled on a speed, held steady for the debounce
/// interval. All three, because a port can report any one of them during a
/// transition it has not finished.
///
/// # Safety
///
/// `base` must be the controller's mapped window.
unsafe fn settled_after_reset(base: usize, parameters: &Parameters, port: u8) -> bool {
    let Some(offset) = operational::port_status_control(port) else {
        return false;
    };
    // SAFETY: the caller's obligation; the port register array is inside the
    // operational bank, which is inside the window.
    let register = unsafe {
        PortRegister::<bhaskix_device::Volatile>::new(base + parameters.operational + offset)
    };

    let mut waited = 0;
    let mut held = 0;
    while waited < DEBOUNCE_TIMEOUT_MICROS {
        let status = operational::PortStatusControl(register.portsc.read());
        let ready =
            status.current_connect_status() && status.port_enabled() && status.port_speed() != 0;
        held = if ready {
            held + DEBOUNCE_STEP_MICROS
        } else {
            0
        };
        if held >= DEBOUNCE_STABLE_MICROS {
            return true;
        }
        pause(DEBOUNCE_STEP_MICROS);
        waited += DEBOUNCE_STEP_MICROS;
    }
    false
}

unsafe fn find_connected_port<W: Wait>(
    base: usize,
    parameters: &Parameters,
    wait: &mut W,
) -> Option<Connected> {
    // SAFETY: the caller's obligation.
    let port = unsafe { debounced_port(base, parameters) }?;
    let offset = operational::port_status_control(port)?;
    // SAFETY: the caller's obligation; the port register array is inside the
    // operational bank, which is inside the window.
    let register = unsafe {
        PortRegister::<bhaskix_device::Volatile>::new(base + parameters.operational + offset)
    };

    let status = operational::PortStatusControl(register.portsc.read());
    // **Always, and not only when the port is disabled.**
    //
    // This used to reset the port only `if !status.port_enabled()`, which is
    // the same thing as trusting whatever state the previous owner of this bus
    // left it in. Firmware enumerates USB to look for a boot device: it
    // resets, addresses and configures whatever it finds, and it leaves those
    // ports **enabled**, with devices holding the addresses *it* assigned.
    //
    // `HCRST` resets the *controller*. It does not reach down the wire. A
    // device that firmware addressed is still listening on that address, while
    // `Address Device` speaks to the default address of zero -- so the device
    // does not answer, the controller reports **USB Transaction Error**, and a
    // working device is reported as no device at all. That is what an SR550
    // did on port 1, three attempts running.
    //
    // A port reset is what puts an attached device back into the Default
    // state, listening on address zero. It is not an error path; it is the
    // first step of addressing anything.
    //
    // **`preserving` and not the value just read.** Seven of this register's
    // bits are write-one-to-clear and bit 1 is write-one-to-*disable*, so
    // writing back what was read clears every change bit that happened to be
    // set and disables the port into the bargain. The symptom is a port that
    // works once and then never reports another device.
    register.portsc.write(status.preserving().0 | (1 << 4));
    let reset = true;
    wait.until(&mut || operational::PortStatusControl(register.portsc.read()).port_enabled());
    // The recovery interval. The specification makes this software's job in as
    // many words: "Software shall be responsible for timing the Reset
    // 'recovery interval' required by USB."
    pause(RESET_RECOVERY_MICROS);

    // **And then wait for the device to come back, rather than assuming it
    // already has.**
    //
    // A fixed recovery interval is right for a device made of silicon. The
    // device on port 1 of a managed server is not: a BMC presents its virtual
    // keyboard and virtual CD by *emulating* USB devices, and a port reset
    // makes one of those detach and re-attach in the BMC's own time, which is
    // not fifty milliseconds. Addressing it during that gap asks a device that
    // is not there yet, and the controller answers **USB Transaction Error** --
    // indistinguishable, in a boot report, from no device at all.
    //
    // So the port is debounced a second time, on everything addressing needs:
    // still connected, now enabled, and settled on a speed.
    // SAFETY: the caller's obligation.
    if !unsafe { settled_after_reset(base, parameters, port) } {
        return None;
    }

    let settled = operational::PortStatusControl(register.portsc.read());
    // Acknowledge what changed, and only what changed. Built from the bits
    // that are set rather than from the whole value, for the reason above.
    register.portsc.write(
        settled
            .acknowledging(settled.0 & operational::PortStatusControl::WRITE_ONE_TO_CLEAR)
            .0,
    );

    // **Speed zero is not a speed.** The specification says undefined, and
    // a driver that passes it into a slot context has told the controller
    // something it cannot act on -- so an enabled port that has not settled
    // on a speed is not yet a device.
    if settled.port_enabled() && settled.port_speed() != 0 {
        return Some(Connected {
            portsc: settled.0,
            port,
            speed: settled.port_speed(),
            reset,
        });
    }
    None
}

/// One word for what the controller thinks a slot is doing.
///
/// Named rather than derived from `Debug`, because this goes in a boot report a
/// person reads and `Some(Addressed)` is not a sentence.
#[must_use]
pub const fn describe_slot_state(state: Option<context::SlotState>) -> &'static str {
    match state {
        Some(context::SlotState::DisabledEnabled) => "enabled, not addressed",
        Some(context::SlotState::Default) => "default",
        Some(context::SlotState::Addressed) => "addressed",
        Some(context::SlotState::Configured) => "configured",
        Some(context::SlotState::Reserved(_)) => "a value the specification does not define",
        None => "not read",
    }
}

/// The control endpoint of an addressed device, and its ring.
struct ControlEndpoint<'a, 'b> {
    commander: &'a mut Commander<'b>,
    slot: u8,
    /// The transfer ring, as the kernel sees it. The controller was told its
    /// device address in the endpoint context and does not need telling again.
    ring_virtual: u64,
    producer: ring::Producer,
    /// A page the device writes descriptors into, in both address spaces.
    buffer_device: u64,
    buffer_virtual: u64,
}

impl ControlEndpoint<'_, '_> {
    /// Runs one control transfer and answers how many bytes came back.
    ///
    /// # Safety
    ///
    /// The device must be addressed, and the ring and buffer its.
    unsafe fn transfer<W: Wait>(
        &mut self,
        setup: usb_setup::Setup,
        length: u16,
        wait: &mut W,
    ) -> Option<usize> {
        // The whole transfer descriptor must fit before the ring's link, or
        // the controller runs onto a wrap in the middle of one -- which is a
        // transfer split across a lap rather than a transfer.
        let (stages, count) = control_transfer_stages(
            setup.0,
            self.buffer_device,
            length,
            setup.is_device_to_host(),
            self.producer.cycle(),
        )?;
        if self.producer.remaining_this_lap() < count {
            return None;
        }

        for stage in stages.iter().take(count) {
            // SAFETY: a frame `init` allocated, at an index `Producer` bounds
            // to inside the ring.
            unsafe {
                core::ptr::write_volatile(
                    (self.ring_virtual as *mut [u32; 4]).add(self.producer.index()),
                    stage.0,
                );
            }
            self.producer.advance();
        }

        let doorbell_offset = bhaskix_xhci::doorbell::for_slot(self.slot)
            .and_then(bhaskix_xhci::doorbell::doorbell_at)?;
        // SAFETY: the doorbell bank is inside the window, and the offset is
        // bounded by `doorbell_at`.
        let doorbell = unsafe {
            DoorbellRegister::<bhaskix_device::Volatile>::new(
                self.commander.base + self.commander.parameters.doorbells + doorbell_offset,
            )
        };
        // **The target is the Device Context Index, not the endpoint number.**
        // The control endpoint is index 1, and 0 on a slot doorbell means
        // something else entirely.
        doorbell.value.write(
            bhaskix_xhci::doorbell::Doorbell::endpoint(bhaskix_xhci::doorbell::CONTROL_ENDPOINT).0,
        );

        // SAFETY: the event ring is the commander's.
        let drained = unsafe { self.commander.await_events(wait) };
        if drained.transfers == 0 {
            return None;
        }
        if !drained
            .last_completion
            .is_some_and(trb::CompletionCode::is_success)
        {
            return None;
        }
        // **The residue, not a count.** A transfer event reports how much was
        // *not* moved, so a short read -- which is normal, and which
        // `is_success` deliberately accepts -- means the device sent less than
        // was asked for and the difference is what arrived.
        Some(usize::from(length).saturating_sub(drained.remaining as usize))
    }

    /// Reads a descriptor into the buffer and hands back what arrived.
    ///
    /// # Safety
    ///
    /// As [`ControlEndpoint::transfer`].
    unsafe fn descriptor<W: Wait>(
        &mut self,
        kind: u8,
        index: u8,
        length: u16,
        wait: &mut W,
    ) -> Option<&[u8]> {
        // SAFETY: the caller's obligation.
        let got = unsafe {
            self.transfer(
                usb_setup::Setup::get_descriptor(kind, index, length),
                length,
                wait,
            )
        }?;
        // SAFETY: a frame `init` allocated, and `got` is bounded by the length
        // asked for, which is bounded by the frame.
        Some(unsafe { core::slice::from_raw_parts(self.buffer_virtual as *const u8, got) })
    }
}

/// What the device said about itself. RFC 0041 step 6.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Described {
    /// Bytes of device descriptor that came back.
    pub device_bytes: usize,
    /// `idVendor`.
    pub vendor: u16,
    /// `idProduct`.
    pub product: u16,
    /// The control endpoint's real packet size, as the device reports it.
    ///
    /// **The number step 5 had to guess.** Addressing a device needs a packet
    /// size before the device can be asked for one, so the speed table supplies
    /// a starting value; this is the device's own answer, and the two differing
    /// is the normal case for a full-speed device rather than an error.
    pub max_packet_size_0: u8,
    /// What the driver assumed before asking.
    pub assumed_packet_size: u16,
    /// Bytes of configuration descriptor that came back.
    pub configuration_bytes: usize,
    /// Whether a boot-protocol keyboard interface was found in it.
    pub boot_keyboard: bool,
    /// The interrupt IN endpoint's number, if one was found.
    pub endpoint: u8,
    /// Its Device Context Index, which is not its number.
    pub endpoint_index: u8,
    /// Its polling interval, as the descriptor reports it.
    pub interval: u8,
    /// Its maximum packet size, as the descriptor reports it.
    pub endpoint_max_packet_size: u16,
    /// The exponent actually programmed into the endpoint context.
    pub interval_exponent: u8,
    /// Whether Configure Endpoint succeeded.
    pub configured: bool,
    /// The endpoint state the controller wrote back. 1 is Running.
    pub endpoint_state: u32,
    /// Why it stopped, when it did not finish.
    pub stopped: Option<&'static str>,
}

/// What step 5 achieved.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Attached {
    /// The port a device was found on, if one was.
    pub port: u8,
    /// Its negotiated speed.
    pub speed: u32,
    /// Whether the port had to be reset.
    pub reset: bool,
    /// The slot the controller handed out, if it did.
    pub slot: u8,
    /// Whether Address Device succeeded.
    pub addressed: bool,
    /// The address the controller assigned, read back from the device context.
    pub address: u8,
    /// The slot state, read back from the device context the controller wrote.
    pub state: Option<context::SlotState>,
    /// Frames this step handed the controller.
    pub frames: usize,
    /// What the device said when it was asked. RFC 0041 step 6.
    pub described: Described,
    /// `PORTSC` of the port this step chose, once it had settled.
    pub portsc: u32,
    /// How many Address Device commands it took, or were spent failing.
    ///
    /// Reported because "the device did not answer" reads very differently at
    /// one attempt and at three, and because a device that answers on the
    /// second is a device this driver would have called absent before.
    pub attempts: u8,
    /// How many times the slot was released and taken again to try afresh.
    ///
    /// The recovery xHCI §4.6.5 prescribes for a failed addressing. Reported
    /// because a device that answers only after its slot was recycled is a
    /// different fact about a machine than one that answers first time, and
    /// because until this field existed the path could not be seen from a boot
    /// report at all.
    pub recoveries: u8,
    /// Why it stopped, when it did not finish.
    pub stopped: Option<&'static str>,
    /// The completion code of the command that refused, when one did.
    ///
    /// **A refusal that does not name its code is a refusal nobody can act
    /// on.** `ParameterError` says a field of the input context is wrong;
    /// `ContextStateError` says the slot was in the wrong state; `TrbError`
    /// says the command itself was malformed. They send a reader to three
    /// different places.
    pub code: Option<trb::CompletionCode>,
}

/// Takes a slot for the device on a port and gives it an address.
///
/// RFC 0041 step 5. Three things in order, each of which can fail on its own
/// and says so: find a port with a device on it, ask for a slot, and address
/// the device through an input context naming its control endpoint.
///
/// **The claim at the end is read back from the controller's own memory**, not
/// inferred from a success code. Address Device answering `Success` says the
/// command was accepted; the *device context* saying `Addressed` with a nonzero
/// address says the controller did the thing the command asked for.
///
/// # Safety
///
/// The controller must be running and answering commands, and the addresses
/// must be its.
unsafe fn address_a_device<W: Wait>(
    commander: &mut Commander<'_>,
    controller: (u8, u8, u8),
    parameters: &Parameters,
    device_contexts: u64,
    hhdm: u64,
    wait: &mut W,
) -> Attached {
    let mut attached = Attached::default();

    // SAFETY: the caller's obligation.
    // What the ports say, before deciding none of them has anything. Printed
    // whether or not a device is found, because the interesting case is the
    // one where the answer is "none" and the reason is invisible.
    // SAFETY: the caller's obligation.
    unsafe { report_ports(commander.base, parameters) };

    // SAFETY: the caller's obligation.
    let Some(found) = (unsafe { find_connected_port(commander.base, parameters, wait) }) else {
        attached.stopped = Some("no port has a device on it");
        return attached;
    };
    attached.port = found.port;
    attached.speed = found.speed;
    attached.reset = found.reset;
    attached.portsc = found.portsc;

    // --- a slot ------------------------------------------------------------
    // SAFETY: the caller's obligation.
    let Some(issued) = (unsafe { commander.issue(trb::Trb::enable_slot, wait) }) else {
        attached.stopped = Some("the command ring would have wrapped");
        return attached;
    };
    if !issued.succeeded() {
        attached.stopped = Some("the controller would not enable a slot");
        attached.code = issued.drained.last_completion;
        return attached;
    }
    let slot = issued.drained.last_slot;
    if slot == 0 {
        // Slot zero is not a slot. A controller answering Success with a slot
        // of zero has said yes to a question and named nothing.
        attached.stopped = Some("the controller enabled slot zero, which is not a slot");
        return attached;
    }
    attached.slot = slot;

    // --- somewhere for the controller to keep this device -------------------
    let Ok(device_context) = frame(controller, hhdm) else {
        attached.stopped = Some("no frame for the device context");
        return attached;
    };
    attached.frames += 1;
    let Ok(transfer_ring) = frame(controller, hhdm) else {
        attached.stopped = Some("no frame for the control endpoint's transfer ring");
        return attached;
    };
    attached.frames += 1;
    let Ok(input_context) = frame(controller, hhdm) else {
        attached.stopped = Some("no frame for the input context");
        return attached;
    };
    attached.frames += 1;

    // The control endpoint's transfer ring needs its own wrap, for the same
    // reason the command ring does.
    let Some((link_index, link)) = command_ring_link(transfer_ring.device, RING_ENTRIES) else {
        attached.stopped = Some("the transfer ring is too small for a link");
        return attached;
    };
    // SAFETY: a frame just allocated and zeroed, at a bounded index.
    unsafe {
        core::ptr::write_volatile(
            (transfer_ring.virtual_address as *mut [u32; 4]).add(link_index),
            link.0,
        );
    }

    // **Entry `slot` of the device context array, not entry `slot - 1`.** The
    // array is indexed by slot number and entry zero is the scratchpad pointer,
    // which is why it is sized slots *plus one*.
    // SAFETY: a frame `init` allocated, at an index bounded by the slot count
    // the controller was configured with.
    unsafe {
        core::ptr::write_volatile(
            (device_contexts as *mut u64).add(slot as usize),
            device_context.device,
        );
    }

    // --- the input context, and the arithmetic that is the trap -------------
    let Some(writes) = address_device_input(
        found.port,
        found.speed,
        transfer_ring.device,
        ring::Producer::new(RING_ENTRIES).is_some_and(|producer| producer.cycle()),
        parameters.context_size_64,
    ) else {
        attached.stopped = Some("the input context could not be built");
        return attached;
    };
    for (offset, dwords) in writes {
        // SAFETY: a frame just allocated and zeroed; `address_device_input`
        // bounds every offset to inside an input context, which for one
        // endpoint is at most three 64-byte contexts.
        unsafe {
            core::ptr::write_volatile(
                (input_context.virtual_address + offset as u64) as *mut [u32; context::DWORDS],
                dwords,
            );
        }
    }

    // --- address it ---------------------------------------------------------
    // Built before it is issued, so that "this address cannot go in a command"
    // is a refusal with a reason rather than a zeroed TRB sent to a controller.
    // The closure only re-stamps the cycle the producer hands it.
    // **Asked more than once, and the specification says how to ask again.**
    //
    // xHCI revision 1.2 §4.6.5 offers two recoveries for an addressing that
    // did not work -- *"system software may issue a Disable Slot Command for
    // the slot or reset the device and attempt the Address Device Command
    // again"* -- and for this completion code in particular it is specific:
    // *"A USB Transaction Error Completion Code for an Address Device Command
    // may be due to a Stall response from a device. Software should issue a
    // Disable Slot Command for the Device Slot then an Enable Slot Command to
    // recover from this error."*
    //
    // **Until 2026-08-25 this loop did neither.** It waited fifty milliseconds
    // and re-issued the same command against the same slot -- the one action
    // that appears in neither branch of that note -- on a slot the same
    // paragraph says an unsuccessful command *"shall leave in the Default
    // state"*. An SR550 spent three attempts that way on port 1 and reported a
    // working device as absent. Both quotes were already in this file, directly
    // above this loop, describing a recovery the code did not perform.
    let mut slot = slot;
    let mut issued = None;
    for attempt in 0..ADDRESS_TRIES {
        if attempt > 0 {
            // --- Disable Slot, and then Enable Slot -------------------------
            let Some(disable) = trb::Trb::disable_slot(slot, false) else {
                attached.stopped = Some("the slot to release is not a slot");
                return attached;
            };
            // SAFETY: the caller's obligation -- a running controller, and
            // rings that are its.
            let Some(released) =
                (unsafe { commander.issue(|cycle| disable.with_cycle_bit(cycle), wait) })
            else {
                attached.stopped = Some("the command ring would have wrapped");
                return attached;
            };
            if !released.succeeded() {
                attached.stopped = Some("the controller would not release the slot to retry it");
                attached.code = released.drained.last_completion;
                return attached;
            }
            // The array entry stops naming a context that is no longer part of
            // any slot. Left set, it points at a frame this driver is about to
            // zero and hand back under a different number.
            // SAFETY: a frame `init` allocated, at an index bounded by the slot
            // count the controller was configured with.
            unsafe {
                core::ptr::write_volatile((device_contexts as *mut u64).add(slot as usize), 0);
            }

            // SAFETY: as above.
            let Some(again) = (unsafe { commander.issue(trb::Trb::enable_slot, wait) }) else {
                attached.stopped = Some("the command ring would have wrapped");
                return attached;
            };
            if !again.succeeded() || again.drained.last_slot == 0 {
                attached.stopped = Some("the controller would not enable a slot to retry with");
                attached.code = again.drained.last_completion;
                return attached;
            }
            // **And it need not be the slot that was just released.** The
            // controller chooses. A driver that assumed otherwise would write
            // the array entry for one slot and address another.
            slot = again.drained.last_slot;
            attached.slot = slot;
            attached.recoveries = attached.recoveries.saturating_add(1);

            // **Zeroed again, because the controller has been writing in it.**
            // A device context belongs to the controller, and an Address Device
            // that failed still left a slot context behind in this frame.
            // Handed straight back, the next command reads a state this driver
            // did not put there.
            // SAFETY: a frame this function allocated and still owns; the
            // controller has just been told it is part of no slot.
            unsafe {
                core::ptr::write_bytes(
                    device_context.virtual_address as *mut u8,
                    0,
                    bhaskix_mm::FRAME_SIZE as usize,
                );
            }
            // SAFETY: as above, at an index bounded by the slot count.
            unsafe {
                core::ptr::write_volatile(
                    (device_contexts as *mut u64).add(slot as usize),
                    device_context.device,
                );
            }
            // The same recovery interval a reset gets. A device that has just
            // refused an address is in no better a state than one that has
            // just come out of reset.
            pause(RESET_RECOVERY_MICROS);
        }

        // **Rebuilt every attempt, because the slot is inside the command.**
        // Hoisted out of the loop -- where it used to be -- a retry after a
        // recovery would silently address the slot that was just released.
        let Some(command) = trb::Trb::address_device(input_context.device, slot, false) else {
            attached.stopped = Some("the input context address is one the command cannot hold");
            return attached;
        };
        // SAFETY: the caller's obligation -- a running controller, and rings
        // that are its.
        let Some(this) = (unsafe { commander.issue(|cycle| command.with_cycle_bit(cycle), wait) })
        else {
            attached.stopped = Some("the command ring would have wrapped");
            return attached;
        };
        attached.attempts = attempt + 1;
        let worked = this.succeeded();
        issued = Some(this);
        if worked {
            break;
        }
    }
    let Some(issued) = issued else {
        attached.stopped = Some("the address command was never issued");
        return attached;
    };
    if !issued.succeeded() {
        attached.stopped = Some("the controller would not address the device");
        attached.code = issued.drained.last_completion;
        return attached;
    }

    // --- and read back what the controller wrote ----------------------------
    // SAFETY: the device context frame this function allocated and handed the
    // controller; the slot context is its first context.
    let slot_context = context::Slot(unsafe {
        core::ptr::read_volatile(device_context.virtual_address as *const [u32; context::DWORDS])
    });
    attached.state = Some(slot_context.slot_state());
    attached.address = slot_context.usb_device_address();
    attached.addressed = matches!(slot_context.slot_state(), context::SlotState::Addressed)
        && slot_context.usb_device_address() != 0;
    if !attached.addressed {
        return attached;
    }

    // --- RFC 0041 step 6: ask the device what it is -------------------------
    let Ok(buffer) = frame(controller, hhdm) else {
        attached.described.stopped = Some("no frame for a descriptor buffer");
        return attached;
    };
    attached.frames += 1;

    let mut endpoint = ControlEndpoint {
        commander,
        slot,
        ring_virtual: transfer_ring.virtual_address,
        producer: match ring::Producer::new(RING_ENTRIES) {
            Some(producer) => producer,
            None => {
                attached.described.stopped = Some("the transfer ring is too small");
                return attached;
            }
        },
        buffer_device: buffer.device,
        buffer_virtual: buffer.virtual_address,
    };
    // SAFETY: the device is addressed and these are its ring and buffer.
    attached.described =
        unsafe { interrogate(&mut endpoint, initial_max_packet_size(found.speed), wait) };

    if attached.described.boot_keyboard {
        let packet = attached.described.endpoint_max_packet_size;
        // SAFETY: as above; the device is addressed and described.
        unsafe {
            configure_the_endpoint(
                commander,
                controller,
                parameters,
                device_context.virtual_address,
                slot,
                found.port,
                found.speed,
                &mut attached.described,
                packet,
                hhdm,
                wait,
            );
        }
        // Two rings and an input context for Configure Endpoint, plus a
        // report buffer for step 7.
        attached.frames += 3;
    }
    attached
}

/// Asks an addressed device what it is.
///
/// Two descriptors and a decision: the device descriptor, which finally answers
/// the packet-size question step 5 had to guess at, and the configuration
/// descriptor, which is read **twice** — nine bytes to learn how long it is,
/// then all of it. A driver that reads only the header gets an interface count
/// and no interfaces; one that guesses the total length reads past what the
/// device sent.
///
/// # Safety
///
/// The device must be addressed and the endpoint's ring and buffer its.
unsafe fn interrogate<W: Wait>(
    endpoint: &mut ControlEndpoint<'_, '_>,
    assumed_packet_size: u16,
    wait: &mut W,
) -> Described {
    let mut described = Described {
        assumed_packet_size,
        ..Described::default()
    };

    // SAFETY: the caller's obligation.
    let Some(bytes) = (unsafe {
        endpoint.descriptor(
            bhaskix_usb::kind::DEVICE,
            0,
            bhaskix_usb::Device::LENGTH as u16,
            wait,
        )
    }) else {
        described.stopped = Some("the device did not answer for its descriptor");
        return described;
    };
    described.device_bytes = bytes.len();
    let Some(device) = bhaskix_usb::Device::parse(bytes) else {
        described.stopped = Some("what came back is not a device descriptor");
        return described;
    };
    described.vendor = device.vendor;
    described.product = device.product;
    described.max_packet_size_0 = device.max_packet_size_0;

    // The configuration header first, for its total length.
    // SAFETY: the caller's obligation.
    let Some(header) = (unsafe {
        endpoint.descriptor(
            bhaskix_usb::kind::CONFIGURATION,
            0,
            bhaskix_usb::Configuration::LENGTH as u16,
            wait,
        )
    }) else {
        described.stopped = Some("the device did not answer for its configuration");
        return described;
    };
    let Some(configuration) = bhaskix_usb::Configuration::parse(header) else {
        described.stopped = Some("what came back is not a configuration descriptor");
        return described;
    };

    // **Bounded before it sizes a transfer.** The total length is the device's
    // own number, and a hostile one would otherwise ask for a transfer longer
    // than the buffer it lands in.
    let total = configuration.total_length;
    if total as usize > MAX_DESCRIPTOR_BYTES {
        described.stopped = Some("the configuration is longer than this driver will read");
        return described;
    }

    // SAFETY: the caller's obligation.
    let Some(blob) =
        (unsafe { endpoint.descriptor(bhaskix_usb::kind::CONFIGURATION, 0, total, wait) })
    else {
        described.stopped = Some("the device did not answer for its full configuration");
        return described;
    };
    described.configuration_bytes = blob.len();

    // The parser is `usb`'s, which is `forbid(unsafe_code)` and fuzzed. What
    // arrives here is written by whatever is plugged into the machine.
    let Some((interface, found)) = bhaskix_usb::boot_keyboard(blob) else {
        described.stopped = Some("no boot-protocol keyboard interface in the configuration");
        return described;
    };
    let _ = interface;
    described.boot_keyboard = true;
    described.endpoint = found.number();
    described.interval = found.interval;
    described.endpoint_max_packet_size = found.max_packet_size;
    // **The Device Context Index is not the endpoint number**, and this is the
    // trap RFC 0041 names: endpoint 1 IN is index 3.
    described.endpoint_index =
        bhaskix_xhci::doorbell::device_context_index(found.number(), found.is_input()).unwrap_or(0);
    described
}

/// Configures the interrupt IN endpoint a keyboard reports on.
///
/// The second half of RFC 0041 step 6. After this the endpoint has a ring of
/// its own and the controller will accept a doorbell on it — which is step 7,
/// and the first thing that could carry a keystroke.
///
/// # Safety
///
/// The device must be addressed and described, and every address must be its.
#[expect(
    clippy::too_many_arguments,
    reason = "each is a distinct address or number the controller is told, and \
              bundling them would hide which of them is wrong when one is"
)]
unsafe fn configure_the_endpoint<W: Wait>(
    commander: &mut Commander<'_>,
    controller: (u8, u8, u8),
    parameters: &Parameters,
    device_context_virtual: u64,
    slot: u8,
    port: u8,
    speed: u32,
    described: &mut Described,
    max_packet_size: u16,
    hhdm: u64,
    wait: &mut W,
) {
    let Ok(ring) = frame(controller, hhdm) else {
        described.stopped = Some("no frame for the interrupt endpoint's transfer ring");
        return;
    };
    let Ok(input_context) = frame(controller, hhdm) else {
        described.stopped = Some("no frame for the configure input context");
        return;
    };

    let Some((link_index, link)) = command_ring_link(ring.device, RING_ENTRIES) else {
        described.stopped = Some("the interrupt transfer ring is too small for a link");
        return;
    };
    // SAFETY: a frame just allocated and zeroed, at a bounded index.
    unsafe {
        core::ptr::write_volatile(
            (ring.virtual_address as *mut [u32; 4]).add(link_index),
            link.0,
        );
    }

    described.interval_exponent = interval_exponent(described.interval, speed);
    let Some(writes) = configure_endpoint_input(
        port,
        speed,
        described.endpoint_index,
        max_packet_size,
        described.interval_exponent,
        ring.device,
        ring::Producer::new(RING_ENTRIES).is_some_and(|producer| producer.cycle()),
        parameters.context_size_64,
    ) else {
        described.stopped = Some("the configure input context could not be built");
        return;
    };
    for (offset, dwords) in writes {
        // SAFETY: a frame just allocated and zeroed; every offset is bounded to
        // inside an input context, which for index 3 is five contexts.
        unsafe {
            core::ptr::write_volatile(
                (input_context.virtual_address + offset as u64) as *mut [u32; context::DWORDS],
                dwords,
            );
        }
    }

    let Some(command) = trb::Trb::configure_endpoint(input_context.device, slot, false) else {
        described.stopped = Some("the input context address is one the command cannot hold");
        return;
    };
    // SAFETY: the caller's obligation.
    let Some(issued) = (unsafe { commander.issue(|cycle| command.with_cycle_bit(cycle), wait) })
    else {
        described.stopped = Some("the command ring would have wrapped");
        return;
    };
    if !issued.succeeded() {
        described.stopped = Some("the controller would not configure the endpoint");
        return;
    }

    // **Read back from the device context, not inferred from the code.** The
    // controller writes the endpoint's state there, and Running is what says it
    // will accept a doorbell.
    let Some(offset) =
        context::device_context_offset(described.endpoint_index, parameters.context_size_64)
    else {
        described.stopped = Some("the endpoint index is not one a device context can hold");
        return;
    };
    // SAFETY: the device context frame handed to the controller, at an offset
    // `device_context_offset` bounds to inside it.
    let endpoint_context = context::Endpoint(unsafe {
        core::ptr::read_volatile(
            (device_context_virtual + offset as u64) as *const [u32; context::DWORDS],
        )
    });
    described.endpoint_state = endpoint_context.endpoint_state();
    // 1 is Running. Anything else is a controller that accepted the command and
    // did not end up where the command asked.
    described.configured = endpoint_context.endpoint_state() == 1;
    if !described.configured {
        return;
    }

    // --- RFC 0041 step 7: somewhere to put a report ------------------------
    let Ok(report) = frame(controller, hhdm) else {
        described.stopped = Some("no frame for a report buffer");
        return;
    };

    // **The consumer is carried over from bring-up, not made fresh.** The
    // controller does not restart the event ring for a new reader; a fresh
    // consumer would start at entry zero expecting cycle 1 and read entries
    // that have already been consumed, which on a keyboard means replaying
    // whatever the last command answered as if it were a keystroke.
    *KEYBOARD.lock() = Some(UsbKeyboard {
        controller,
        base: commander.base,
        doorbells: parameters.doorbells,
        runtime: parameters.runtime,
        slot,
        endpoint_index: described.endpoint_index,
        event_virtual: commander.event,
        event_device: commander.memory.event_ring,
        event_entries: commander.memory.event_ring_entries,
        consumer: commander.consumer,
        ring_virtual: ring.virtual_address,
        producer: match ring::Producer::new(RING_ENTRIES) {
            Some(producer) => producer,
            None => return,
        },
        report_virtual: report.virtual_address,
        report_device: report.device,
        packet: max_packet_size,
        keyboard: bhaskix_usb::hid::Keyboard::new(),
        handler: u64::MAX,
        reports: 0,
        bytes: 0,
        short: 0,
    });
}

/// Claims the controller's interrupt and arms the first report.
///
/// **After the console's notification exists**, because this binds to it: three
/// sources share one notification, and `input::service` drains all of them
/// rather than asking the badge which fired. A wake says only that *something*
/// has something.
///
/// Failure is survivable and says which: the machine boots, the i8042 still
/// works if there is one, and serial is untouched.
///
/// # Safety
///
/// Must be called once, during boot, after the interrupt controller is up.
pub unsafe fn install_interrupt(
    apic_id: u32,
    rsdp: Option<bhaskix_boot::PhysAddr>,
    hhdm: u64,
    notification: crate::notify::NotificationId,
) -> Result<u8, &'static str> {
    // Where the device is, and nothing else, under this lock. Everything that
    // follows takes locks ranking *outside* it -- the notification arena, the
    // interrupt handlers, the vector allocator -- and holding this across them
    // is the inversion `virtio::enable_interrupts` documents having made.
    let controller = {
        let guard = KEYBOARD.lock();
        guard
            .as_ref()
            .ok_or("no keyboard is configured")?
            .controller
    };
    let address = pci::Address {
        bus: controller.0,
        device: controller.1,
        function: controller.2,
    };

    // SAFETY: `trap` dispatches claimed vectors to `irq::on_interrupt`, which
    // acknowledges the local APIC.
    let handler = unsafe {
        crate::irq::claim(
            crate::irq::Source::MessageSignalled {
                device: address,
                entry: 0,
            },
            "usb-keyboard",
            apic_id,
            rsdp,
            hhdm,
        )
    }
    .map_err(|_| "the controller's MSI-X entry could not be claimed")?;

    if crate::irq::bind(handler, notification, BADGE).is_err() {
        crate::irq::release(handler);
        return Err("the notification would not bind");
    }
    let vector = crate::irq::vector_of(handler).unwrap_or(0);

    let mut guard = KEYBOARD.lock();
    let keyboard = guard.as_mut().ok_or("no keyboard is configured")?;
    keyboard.handler = crate::irq::handler_raw(handler);
    // SAFETY: the endpoint is configured and these are its ring and buffer.
    if !unsafe { keyboard.arm() } {
        return Err("the first transfer could not be queued");
    }
    Ok(vector)
}

/// Reads whatever the keyboard has sent, and acknowledges the interrupt.
///
/// Called from [`crate::input::service`] beside the serial port and the i8042.
/// Answers how many bytes reached the console ring.
pub fn service() -> usize {
    let (produced, handler) = {
        let mut guard = KEYBOARD.lock();
        let Some(keyboard) = guard.as_mut() else {
            return 0;
        };
        if keyboard.handler == u64::MAX {
            return 0;
        }
        // SAFETY: the endpoint is configured and these are its ring and buffer.
        (unsafe { keyboard.drain_reports() }, keyboard.handler)
    };

    // **Acknowledged after the lock is released, not while it is held.**
    // `irq::acknowledge` takes the handler table, whose rank is *outside* this
    // one; taking it here would be the inversion this rank's comment exists to
    // prevent. Draining before acknowledging is `driver-model.md` §2's rule and
    // is preserved: the drain above has already happened.
    if handler != u64::MAX {
        let _ = crate::irq::acknowledge(crate::irq::handler_from_raw(handler));
    }
    produced
}

/// Whether a USB keyboard is configured and being read.
#[must_use]
pub fn keyboard_present() -> bool {
    KEYBOARD
        .lock()
        .as_ref()
        .is_some_and(|keyboard| keyboard.handler != u64::MAX)
}

/// Reports read, bytes produced, and reports shorter than the endpoint declared.
#[must_use]
pub fn keyboard_statistics() -> (u64, u64, u64) {
    KEYBOARD.lock().as_ref().map_or((0, 0, 0), |keyboard| {
        (keyboard.reports, keyboard.bytes, keyboard.short)
    })
}

/// Sends a No-Op command and consumes the event it produces.
///
/// **A No-Op is how a driver proves its command ring works**, which is what the
/// vendored crate's own constructor says it is for. The answer is not merely
/// "an event arrived": a Command Completion Event names *the address of the
/// command TRB it is answering*, so a matching pointer is a round trip a
/// coincidence cannot fake.
///
/// # Safety
///
/// The controller must be running and the `Commander`'s addresses its rings.
unsafe fn exercise_the_rings<W: Wait>(commander: &mut Commander<'_>, wait: &mut W) -> Answered {
    let mut answered = Answered::default();
    // SAFETY: the caller's obligation.
    let Some(issued) = (unsafe { commander.issue(trb::Trb::no_op_command, wait) }) else {
        return answered;
    };
    answered.asked_at = issued.asked_at;
    answered.arrived = issued.arrived;
    answered.drained = issued.drained;
    answered.matched = issued.succeeded();
    answered.state = issued.state;
    answered.dequeue_advanced = commander.dequeue_advanced;
    answered
}

/// What asking the controller a question produced.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Answered {
    /// What the drain found.
    pub drained: Drained,
    /// Where the command was written, in the controller's own addresses.
    pub asked_at: u64,
    /// Whether an event arrived before the deadline.
    pub arrived: bool,
    /// Whether the completion named the command that was sent.
    ///
    /// **The claim worth making.** An event arriving proves the event ring
    /// works; an event naming the address the command was written to proves the
    /// controller read the command ring as well, and that the two are the same
    /// conversation.
    pub matched: bool,
    /// Whether the dequeue pointer was written back.
    pub dequeue_advanced: bool,
    /// What the controller said about itself when the wait ended.
    pub state: ControllerState,
}

/// The badge this driver signals the console's notification with.
///
/// Third source on one notification: serial is 1, the i8042 is 2, this is 4.
pub const BADGE: u64 = 4;

/// A keyboard the controller is reading, and everything needed to keep reading.
///
/// **Owned rather than borrowed**, because it outlives bring-up: the structures
/// that were locals while the device was being addressed have to survive into
/// interrupt context, where there is no caller to have lent them.
struct UsbKeyboard {
    /// Where the controller is, for claiming its interrupt.
    controller: (u8, u8, u8),
    /// The mapped register window, and the two bank offsets used from here.
    base: usize,
    doorbells: usize,
    runtime: usize,
    /// Which slot and which endpoint, the latter as a Device Context Index.
    slot: u8,
    endpoint_index: u8,
    /// The event ring, and where this driver has read up to. **Carried over
    /// from bring-up**: the controller does not restart the ring for a new
    /// reader, so a fresh consumer would read entries already consumed.
    event_virtual: u64,
    event_device: u64,
    event_entries: usize,
    consumer: ring::Consumer,
    /// The interrupt endpoint's transfer ring, as the kernel sees it. The
    /// controller was told its device address in the endpoint context and does
    /// not need telling again.
    ring_virtual: u64,
    producer: ring::Producer,
    /// Where the device writes a report, and how many bytes it may write.
    report_virtual: u64,
    report_device: u64,
    packet: u16,
    /// The boot-protocol state: which keys were held last time.
    keyboard: bhaskix_usb::hid::Keyboard,
    /// The claimed interrupt, packed as `irq::handler_raw`; `u64::MAX` is none.
    handler: u64,
    /// Reports read, and bytes produced from them.
    reports: u64,
    bytes: u64,
    /// Reports the device sent that were shorter than the endpoint declared.
    short: u64,
}

/// The keyboard this kernel is reading, once there is one.
static KEYBOARD: crate::sync::SpinLock<Option<UsbKeyboard>> =
    crate::sync::SpinLock::new(crate::sync::Rank::UsbKeyboard, None);

impl UsbKeyboard {
    /// Puts one Normal TRB on the interrupt endpoint's ring and rings for it.
    ///
    /// **A transfer is queued before a report can arrive, and again after every
    /// one that does.** An interrupt endpoint does not stream: the controller
    /// polls the device only while there is somewhere to put the answer, so a
    /// driver that forgets to re-queue gets exactly one keystroke.
    ///
    /// # Safety
    ///
    /// The endpoint must be configured and these addresses its.
    unsafe fn arm(&mut self) -> bool {
        if self.producer.remaining_this_lap() == 0 {
            // The lap is not handled here either -- see `Commander::issue`.
            // Sixteen entries and one report per interrupt means this is
            // reached after fifteen keystrokes, so it is a real bound and not
            // a theoretical one.
            return false;
        }
        let Some(transfer) = trb::Trb::normal(
            self.report_device,
            u32::from(self.packet),
            self.producer.cycle(),
        ) else {
            return false;
        };
        // Report on completion, because this transfer *is* the whole
        // descriptor -- there is no later stage to carry it.
        let transfer = transfer.with_interrupt_on_completion(true);
        // SAFETY: a frame `init` allocated, at an index `Producer` bounds to
        // inside the ring.
        unsafe {
            core::ptr::write_volatile(
                (self.ring_virtual as *mut [u32; 4]).add(self.producer.index()),
                transfer.0,
            );
        }
        self.producer.advance();

        let Some(offset) = bhaskix_xhci::doorbell::for_slot(self.slot)
            .and_then(bhaskix_xhci::doorbell::doorbell_at)
        else {
            return false;
        };
        // SAFETY: the doorbell bank is inside the window, and the offset is
        // bounded by `doorbell_at`.
        let doorbell = unsafe {
            DoorbellRegister::<bhaskix_device::Volatile>::new(self.base + self.doorbells + offset)
        };
        // **The endpoint's Device Context Index, not the control endpoint's.**
        // Ringing 1 here polls the device for a descriptor nobody asked for.
        doorbell
            .value
            .write(bhaskix_xhci::doorbell::Doorbell::endpoint(self.endpoint_index).0);
        true
    }

    /// Reads whatever the controller has published, and types it.
    ///
    /// # Safety
    ///
    /// As [`UsbKeyboard::arm`].
    unsafe fn drain_reports(&mut self) -> usize {
        let event_ring = self.event_virtual;
        let drained = drain(self.event_entries, &mut self.consumer, &mut |index| {
            // SAFETY: one TRB at an index `Consumer` bounds to inside the ring
            // the controller writes by DMA.
            trb::Trb(unsafe {
                core::ptr::read_volatile((event_ring as *const [u32; 4]).add(index))
            })
        });

        // Tell the controller how far this driver has read, and clear Event
        // Handler Busy. Without it the interrupter never fires again.
        if let Some(interrupter_zero) = runtime::interrupter_at(0)
            && let Some(dequeue) = runtime::EventRingDequeuePointer::advancing(
                self.event_device + (self.consumer.index() * trb::BYTES) as u64,
                0,
                true,
            )
        {
            // SAFETY: the runtime bank is inside the window.
            let interrupter = unsafe {
                Interrupter::<bhaskix_device::Volatile>::new(
                    self.base + self.runtime + interrupter_zero,
                )
            };
            // Acknowledge the interrupt pending bit in the same write that
            // moves the pointer: `IMAN` bit 0 is write-one-to-clear.
            interrupter.iman.write(
                runtime::InterrupterManagement(0)
                    .with_interrupt_enable(true)
                    .acknowledging()
                    .0,
            );
            interrupter.erdp.write(dequeue.0);
        }

        if drained.transfers == 0 {
            return 0;
        }

        // A short report is not a keystroke. The endpoint declared its packet
        // size and the controller was told it; fewer bytes than that means the
        // device sent something other than what it said it would, and
        // `hid::Keyboard::feed` refuses it anyway.
        let moved = usize::from(self.packet).saturating_sub(drained.remaining as usize);
        if moved < bhaskix_usb::hid::REPORT_BYTES {
            self.short += 1;
        }

        // SAFETY: a frame `init` allocated, read for the bytes the controller
        // says it wrote, which is bounded by the packet size it was given.
        let report = unsafe {
            core::slice::from_raw_parts(
                self.report_virtual as *const u8,
                moved.min(usize::from(self.packet)),
            )
        };
        let typed = self.keyboard.feed(report);
        let produced = typed.as_slice().len();
        if produced > 0 {
            crate::input::keyboard_produced(typed.as_slice());
        }
        self.reports += 1;
        self.bytes += produced as u64;

        // SAFETY: as above.
        unsafe { self.arm() };
        produced
    }
}

/// A controller to bring up without a machine.
///
/// **A device and not a byte array**, for the reason `bhaskix_device::testing`
/// gives about its own model: a register file answers with whatever was written,
/// and refusing is the behaviour a driver gets wrong. This one clears `HCRST`
/// when it feels like it, holds `CNR` for a few reads afterwards the way real
/// silicon does, and halts and runs on `USBCMD` — so "waited for the wrong bit"
/// is a test failure rather than a machine that stops.
///
/// The existing model in `bhaskix_device` could not be used: it is 256 bytes and
/// virtio-shaped, and this controller's runtime bank alone sits past that.
#[cfg(test)]
mod model {
    use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicUsize, Ordering};

    use bhaskix_device::Bus;

    /// Bytes of register file. Enough to hold a realistic `RTSOFF`.
    pub const SIZE: usize = 0x1000;
    /// How far the capability bank reaches. Dword reads only, as above.
    pub const CAPABILITY_BANK: usize = 0x20;
    /// Accesses remembered, which is what ordering is asserted from.
    pub const LOGGED: usize = 128;

    /// Where this model puts its banks. Deliberately *not* the values a driver
    /// might guess: `CAPLENGTH` is not 0x20 and `RTSOFF` is not adjacent.
    pub const CAPLENGTH: usize = 0x40;
    pub const RTSOFF: usize = 0x600;
    pub const DBOFF: usize = 0x800;

    /// Operational registers, absolute in this model's file.
    pub const USBCMD: usize = CAPLENGTH;
    pub const USBSTS: usize = CAPLENGTH + 0x04;
    pub const CRCR: usize = CAPLENGTH + 0x18;
    pub const DCBAAP: usize = CAPLENGTH + 0x30;
    pub const CONFIG: usize = CAPLENGTH + 0x38;

    /// Interrupter zero, absolute.
    pub const IMAN: usize = RTSOFF + 0x20;
    pub const IMOD: usize = RTSOFF + 0x24;
    pub const ERSTSZ: usize = RTSOFF + 0x28;
    pub const ERSTBA: usize = RTSOFF + 0x30;
    pub const ERDP: usize = RTSOFF + 0x38;

    const RUN_STOP: u32 = 1;
    const HOST_CONTROLLER_RESET: u32 = 1 << 1;
    const HC_HALTED: u32 = 1;
    const CONTROLLER_NOT_READY: u32 = 1 << 11;

    static REGISTERS: [AtomicU8; SIZE] = [const { AtomicU8::new(0) }; SIZE];
    static LOG_WRITE: [AtomicBool; LOGGED] = [const { AtomicBool::new(false) }; LOGGED];
    static LOG_AT: [AtomicUsize; LOGGED] = [const { AtomicUsize::new(0) }; LOGGED];
    static LOG_VALUE: [AtomicU32; LOGGED] = [const { AtomicU32::new(0) }; LOGGED];
    static LOGGED_COUNT: AtomicUsize = AtomicUsize::new(0);
    static BUSY: AtomicBool = AtomicBool::new(false);

    /// Reads of `USBSTS` that still report the controller not ready.
    static NOT_READY_FOR: AtomicUsize = AtomicUsize::new(0);
    /// The controller never finishes its reset.
    static HOLD_RESET: AtomicBool = AtomicBool::new(false);
    /// The controller never becomes ready.
    static HOLD_NOT_READY: AtomicBool = AtomicBool::new(false);
    /// The controller never leaves the halted state.
    static HOLD_HALTED: AtomicBool = AtomicBool::new(false);
    /// The controller was already running when the driver found it, and will
    /// not stop.
    static HOLD_RUNNING: AtomicBool = AtomicBool::new(false);
    /// A register was programmed while the controller reported not-ready.
    static PROGRAMMED_WHILE_NOT_READY: AtomicBool = AtomicBool::new(false);

    /// Held for the duration of a test; released on drop.
    pub struct Exclusive;

    impl Drop for Exclusive {
        fn drop(&mut self) {
            BUSY.store(false, Ordering::Release);
        }
    }

    /// Takes the model, resets it to a plausible controller, and holds it.
    #[must_use]
    pub fn exclusive() -> Exclusive {
        while BUSY
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            core::hint::spin_loop();
        }
        for register in &REGISTERS {
            register.store(0, Ordering::Relaxed);
        }
        LOGGED_COUNT.store(0, Ordering::Relaxed);
        NOT_READY_FOR.store(0, Ordering::Relaxed);
        HOLD_RESET.store(false, Ordering::Relaxed);
        HOLD_NOT_READY.store(false, Ordering::Relaxed);
        HOLD_HALTED.store(false, Ordering::Relaxed);
        HOLD_RUNNING.store(false, Ordering::Relaxed);
        PROGRAMMED_WHILE_NOT_READY.store(false, Ordering::Relaxed);

        REGISTERS[0].store(CAPLENGTH as u8, Ordering::Relaxed);
        put16(0x02, 0x0110);
        put32(0x14, DBOFF as u32);
        put32(0x18, RTSOFF as u32);
        // Halted, which is what a controller is before it is told to run.
        put32(USBSTS, HC_HALTED);
        Exclusive
    }

    /// `HCSPARAMS1` from its three fields.
    pub fn structural1(slots: u8, interrupters: u16, ports: u8) -> u32 {
        u32::from(slots) | (u32::from(interrupters) << 8) | (u32::from(ports) << 24)
    }

    /// `HCSPARAMS2` asking for `scratchpads` buffers.
    ///
    /// **The high five bits of the count go in bits 25:21 and the low five in
    /// bits 31:27**, which is the split the crate's own accessor documents as
    /// the most error-prone field in the bank. Built here from the count so the
    /// test states the count and not the encoding.
    pub fn structural2(scratchpads: u32) -> u32 {
        let high = (scratchpads >> 5) & 0x1f;
        let low = scratchpads & 0x1f;
        (high << 21) | (low << 27)
    }

    pub fn put16(at: usize, value: u16) {
        for (index, byte) in value.to_le_bytes().iter().enumerate() {
            REGISTERS[at + index].store(*byte, Ordering::Relaxed);
        }
    }

    pub fn put32(at: usize, value: u32) {
        for (index, byte) in value.to_le_bytes().iter().enumerate() {
            REGISTERS[at + index].store(*byte, Ordering::Relaxed);
        }
    }

    pub fn get32(at: usize) -> u32 {
        u32::from_le_bytes([
            REGISTERS[at].load(Ordering::Relaxed),
            REGISTERS[at + 1].load(Ordering::Relaxed),
            REGISTERS[at + 2].load(Ordering::Relaxed),
            REGISTERS[at + 3].load(Ordering::Relaxed),
        ])
    }

    pub fn get64(at: usize) -> u64 {
        u64::from(get32(at)) | (u64::from(get32(at + 4)) << 32)
    }

    /// Makes the controller hold `CNR` set for `reads` reads of `USBSTS`.
    pub fn not_ready_for(reads: usize) {
        NOT_READY_FOR.store(reads, Ordering::Relaxed);
    }

    pub fn never_finishes_reset() {
        HOLD_RESET.store(true, Ordering::Relaxed);
    }

    pub fn never_becomes_ready() {
        HOLD_NOT_READY.store(true, Ordering::Relaxed);
    }

    pub fn never_runs() {
        HOLD_HALTED.store(true, Ordering::Relaxed);
    }

    /// The controller is already running and will not halt.
    pub fn already_running_and_stuck() {
        HOLD_RUNNING.store(true, Ordering::Relaxed);
        put32(USBCMD, RUN_STOP);
        put32(USBSTS, 0);
    }

    /// How many accesses were recorded.
    #[must_use]
    pub fn accesses() -> usize {
        LOGGED_COUNT.load(Ordering::Relaxed).min(LOGGED)
    }

    /// The index of the first *write* to `at`, if there was one.
    #[must_use]
    pub fn first_write_to(at: usize) -> Option<usize> {
        (0..accesses()).find(|index| {
            LOG_WRITE[*index].load(Ordering::Relaxed)
                && LOG_AT[*index].load(Ordering::Relaxed) == at
        })
    }

    /// The index of the first write to `at` whose value satisfies `mask`/`want`.
    ///
    /// `USBCMD` is written more than once — the reset and the run are the same
    /// register — so "when was it told to run" is a question about the value
    /// and not just the address.
    #[must_use]
    pub fn first_write_to_matching(at: usize, mask: u32, want: u32) -> Option<usize> {
        (0..accesses()).find(|index| {
            LOG_WRITE[*index].load(Ordering::Relaxed)
                && LOG_AT[*index].load(Ordering::Relaxed) == at
                && LOG_VALUE[*index].load(Ordering::Relaxed) & mask == want
        })
    }

    /// Whether the driver programmed a register while `CNR` was set.
    ///
    /// **The model refuses rather than the test inspecting.** Writing an
    /// operational register while the controller reports not-ready is
    /// undefined, and the failure it produces on real silicon is a controller
    /// that appears to accept everything and then does nothing — so the device
    /// remembers it happened and the test asks.
    #[must_use]
    pub fn programmed_while_not_ready() -> bool {
        PROGRAMMED_WHILE_NOT_READY.load(Ordering::Relaxed)
    }

    fn record(write: bool, at: usize, value: u32) {
        let index = LOGGED_COUNT.fetch_add(1, Ordering::Relaxed);
        if index < LOGGED {
            LOG_WRITE[index].store(write, Ordering::Relaxed);
            LOG_AT[index].store(at, Ordering::Relaxed);
            LOG_VALUE[index].store(value, Ordering::Relaxed);
        }
    }

    /// Whether the controller is currently reporting itself not ready.
    ///
    /// Read from the register file directly rather than through `observe`, so
    /// that asking does not consume one of the reads the test is counting.
    fn not_ready(at_rest: u32) -> bool {
        HOLD_NOT_READY.load(Ordering::Relaxed)
            || NOT_READY_FOR.load(Ordering::Relaxed) > 0
            || at_rest & CONTROLLER_NOT_READY != 0
    }

    /// What the controller does about a write, beyond remembering it.
    fn react(at: usize, value: u32) {
        // Writing an operational register while `CNR` is set is undefined. The
        // reset itself is the one write that is allowed to precede readiness,
        // and `USBSTS` is how a driver finds out — everything else is the
        // driver getting ahead of the controller.
        let programming = matches!(at, CONFIG | DCBAAP | CRCR)
            || (at == USBCMD && value & HOST_CONTROLLER_RESET == 0);
        if programming && not_ready(get32(USBSTS)) {
            PROGRAMMED_WHILE_NOT_READY.store(true, Ordering::Relaxed);
        }
        if at != USBCMD {
            return;
        }
        if value & HOST_CONTROLLER_RESET != 0 && !HOLD_RESET.load(Ordering::Relaxed) {
            // Real silicon clears this itself, and clears it *before* it is
            // willing to be programmed -- which is the whole reason `CNR`
            // exists and the whole reason this model has a second knob.
            put32(USBCMD, value & !HOST_CONTROLLER_RESET);
            let mut status = HC_HALTED;
            if HOLD_NOT_READY.load(Ordering::Relaxed) || NOT_READY_FOR.load(Ordering::Relaxed) > 0 {
                status |= CONTROLLER_NOT_READY;
            }
            put32(USBSTS, status);
        }
        if value & RUN_STOP != 0 {
            if !HOLD_HALTED.load(Ordering::Relaxed) {
                put32(USBSTS, get32(USBSTS) & !HC_HALTED);
            }
        } else if !HOLD_RUNNING.load(Ordering::Relaxed) {
            put32(USBSTS, get32(USBSTS) | HC_HALTED);
        }
    }

    /// Whether a narrow read of `at` answers zero rather than the register.
    ///
    /// **Measured on `qemu-xhci`, 2026-08-23, not assumed.** Its capability
    /// bank implements dword reads only: dword 0 reads `0x01000040` --
    /// `CAPLENGTH` 0x40 and `HCIVERSION` 0x0100 -- while a 16-bit read at
    /// offset 2 answers `0x0000`. It does not fault, so a driver that reads
    /// `HCIVERSION` at its own offset believes a version of zero.
    ///
    /// The model reproduces that, because a model that answered correctly would
    /// have let the defect ship and be found on hardware.
    fn narrow_read_answers_zero(at: usize) -> bool {
        at < CAPABILITY_BANK
    }

    /// What the controller reports when a register is read.
    fn observe(at: usize, value: u32) -> u32 {
        if at != USBSTS {
            return value;
        }
        if HOLD_NOT_READY.load(Ordering::Relaxed) {
            return value | CONTROLLER_NOT_READY;
        }
        let remaining = NOT_READY_FOR.load(Ordering::Relaxed);
        if remaining > 0 {
            NOT_READY_FOR.store(remaining - 1, Ordering::Relaxed);
            return value | CONTROLLER_NOT_READY;
        }
        // **The bit genuinely clears, in the register file and not only in the
        // answer.** Returning a cleared bit while leaving it set in the file
        // made the model report every later write as one made while the
        // controller was not ready — a false accusation against a driver that
        // had waited correctly.
        let cleared = value & !CONTROLLER_NOT_READY;
        put32(USBSTS, cleared);
        cleared
    }

    /// The model, as a bus a register block can be built over.
    #[derive(Clone, Copy, Debug)]
    pub struct Model;

    // SAFETY: not a real bus. Every method performs its access against the
    // register file at the width its name describes, which is what the tests
    // using it are about.
    unsafe impl Bus for Model {
        unsafe fn load8(at: usize) -> u8 {
            let value = if narrow_read_answers_zero(at) {
                0
            } else {
                REGISTERS[at].load(Ordering::Relaxed)
            };
            record(false, at, u32::from(value));
            value
        }

        unsafe fn load16(at: usize) -> u16 {
            let value = if narrow_read_answers_zero(at) {
                0
            } else {
                u16::from_le_bytes([
                    REGISTERS[at].load(Ordering::Relaxed),
                    REGISTERS[at + 1].load(Ordering::Relaxed),
                ])
            };
            record(false, at, u32::from(value));
            value
        }

        unsafe fn load32(at: usize) -> u32 {
            let value = observe(at, get32(at));
            record(false, at, value);
            value
        }

        unsafe fn store8(at: usize, value: u8) {
            REGISTERS[at].store(value, Ordering::Relaxed);
            record(true, at, u32::from(value));
        }

        unsafe fn store16(at: usize, value: u16) {
            put16(at, value);
            record(true, at, u32::from(value));
        }

        unsafe fn store32(at: usize, value: u32) {
            put32(at, value);
            record(true, at, value);
            react(at, value);
        }
    }
}

#[cfg(test)]
mod bringup_tests {
    use super::model::{self, Model};
    use super::{BringUpError, Memory, Parameters, RING_ENTRIES, Wait, bring_up, parameters};

    /// A waiter with a budget of polls, which is what a deadline is on a
    /// machine with no clock in it.
    struct Polls(usize);

    impl Wait for Polls {
        fn until(&mut self, ready: &mut dyn FnMut() -> bool) -> bool {
            for _ in 0..self.0 {
                if ready() {
                    return true;
                }
            }
            false
        }
    }

    /// Somewhere for the controller to look. Aligned as every register demands
    /// — 64 bytes for the rings and tables, which is the strictest of them.
    const DEVICE_CONTEXTS: u64 = 0x20_0000;
    const COMMAND_RING: u64 = 0x20_1000;
    const EVENT_RING: u64 = 0x20_2000;
    const SEGMENT_TABLE: u64 = 0x20_3000;

    fn memory(scratchpads: u32) -> Memory {
        Memory {
            device_contexts: DEVICE_CONTEXTS,
            command_ring: COMMAND_RING,
            command_ring_entries: RING_ENTRIES,
            event_ring: EVENT_RING,
            event_ring_entries: RING_ENTRIES,
            segment_table: SEGMENT_TABLE,
            scratchpads,
        }
    }

    /// A controller offering `slots` slots, `ports` ports and `scratchpads`
    /// scratchpad buffers, read through the same path the driver uses.
    fn offered(slots: u8, ports: u8, scratchpads: u32) -> Result<Parameters, BringUpError> {
        model::put32(0x04, model::structural1(slots, 1, ports));
        model::put32(0x08, model::structural2(scratchpads));
        // SAFETY: the model's register file is `model::SIZE` bytes and every
        // bank it declares is inside it.
        unsafe { parameters::<Model>(0, model::SIZE) }
    }

    fn run(memory: &Memory, wait: &mut Polls) -> Result<super::Running, BringUpError> {
        let parameters = offered(4, 2, 0).expect("the model is a plausible controller");
        // SAFETY: as `offered`.
        unsafe { bring_up::<Model, Polls>(0, &parameters, memory, wait) }
    }

    #[test]
    fn a_plausible_controller_comes_up() {
        let _held = model::exclusive();
        let running = run(&memory(0), &mut Polls(16)).expect("it should have started");
        assert_eq!(running.slots, 4);
        assert_eq!(running.ports, 2);
    }

    #[test]
    fn the_operational_bank_is_found_through_caplength_rather_than_assumed() {
        let _held = model::exclusive();
        run(&memory(0), &mut Polls(16)).expect("it should have started");
        // The model puts `CAPLENGTH` at 0x40, which is not the value a driver
        // would guess. A driver that assumed 0x20 would write `USBCMD` into the
        // capability bank, where it is read-only and silently ignored.
        assert!(
            model::first_write_to(model::USBCMD).is_some(),
            "USBCMD was never written at the offset CAPLENGTH reports"
        );
    }

    #[test]
    fn the_dequeue_pointer_is_written_before_the_table_that_arms_the_ring() {
        let _held = model::exclusive();
        run(&memory(0), &mut Polls(16)).expect("it should have started");
        let erdp = model::first_write_to(model::ERDP).expect("ERDP was never written");
        let erstba = model::first_write_to(model::ERSTBA).expect("ERSTBA was never written");
        assert!(
            erdp < erstba,
            "ERSTBA is what arms the event ring: a dequeue pointer written after it \
             is written to a ring the controller has already begun using"
        );
    }

    #[test]
    fn every_pointer_the_controller_reads_is_written_before_it_is_told_to_run() {
        let _held = model::exclusive();
        run(&memory(0), &mut Polls(16)).expect("it should have started");
        // `USBCMD` is written twice — the reset and the run — so the run is
        // identified by its value and not by its address.
        let run_at = model::first_write_to_matching(model::USBCMD, 1, 1)
            .expect("the controller was never told to run");
        for (name, at) in [
            ("CONFIG", model::CONFIG),
            ("DCBAAP", model::DCBAAP),
            ("CRCR", model::CRCR),
            ("ERSTBA", model::ERSTBA),
            ("ERDP", model::ERDP),
            ("ERSTSZ", model::ERSTSZ),
            ("IMAN", model::IMAN),
        ] {
            let written = model::first_write_to(at).unwrap_or_else(|| panic!("{name} unwritten"));
            assert!(
                written < run_at,
                "{name} must be programmed before Run/Stop, or the controller \
                 starts reading a table that is not there yet"
            );
        }
    }

    #[test]
    fn nothing_is_programmed_while_the_controller_reports_itself_not_ready() {
        let _held = model::exclusive();
        // The controller clears `HCRST` promptly and then holds `CNR` for three
        // more reads. That window is exactly where a driver waiting on the
        // reset bit alone does its programming, and the model refuses it.
        model::not_ready_for(3);
        run(&memory(0), &mut Polls(16)).expect("it should have started");
        assert!(
            !model::programmed_while_not_ready(),
            "a register was written while USBSTS.CNR was set: the controller \
             clears the reset bit before it is willing to be programmed, so \
             waiting on that bit alone is waiting for the wrong thing"
        );
    }

    #[test]
    fn the_interrupter_is_given_one_segment_a_moderation_interval_and_its_enable() {
        let _held = model::exclusive();
        run(&memory(0), &mut Polls(16)).expect("it should have started");
        assert_eq!(
            model::get32(model::ERSTSZ) & 0xffff,
            1,
            "one segment, because there is one event ring"
        );
        assert_eq!(
            model::get32(model::IMOD) & 0xffff,
            u32::from(super::IMOD_INTERVAL),
            "left at the reset value of zero this is an interrupt per event, \
             and a fast device then livelocks a CPU"
        );
        assert!(
            model::get32(model::IMAN) & 0b10 != 0,
            "the interrupter was never enabled"
        );
        assert_eq!(
            model::get64(model::ERSTBA) & !0x3f,
            SEGMENT_TABLE,
            "the segment table pointer is not where it was put"
        );
        assert_eq!(
            model::get64(model::DCBAAP) & !0x3f,
            DEVICE_CONTEXTS,
            "the device context array pointer is not where it was put"
        );
        assert_eq!(
            model::get64(model::CRCR) & !0x3f,
            COMMAND_RING,
            "the command ring pointer is not where it was put"
        );
        assert!(
            model::get64(model::CRCR) & 1 != 0,
            "the ring cycle state must match the producer's, which starts set \
             because a freshly allocated ring reads as all zeroes"
        );
    }

    #[test]
    fn a_controller_that_never_becomes_ready_is_refused_rather_than_waited_on() {
        let _held = model::exclusive();
        model::never_becomes_ready();
        let error = run(&memory(0), &mut Polls(8)).expect_err("it should have been refused");
        assert_eq!(error, BringUpError::NeverBecameReady);
        assert_eq!(
            model::first_write_to(model::CONFIG),
            None,
            "nothing may be programmed into a controller that never became ready"
        );
    }

    #[test]
    fn a_controller_that_never_finishes_its_reset_is_refused() {
        let _held = model::exclusive();
        model::never_finishes_reset();
        assert_eq!(
            run(&memory(0), &mut Polls(8)),
            Err(BringUpError::ResetNeverCompleted)
        );
    }

    #[test]
    fn a_controller_that_never_starts_is_refused() {
        let _held = model::exclusive();
        model::never_runs();
        assert_eq!(run(&memory(0), &mut Polls(8)), Err(BringUpError::NeverRan));
    }

    #[test]
    fn a_running_controller_that_will_not_halt_is_refused_rather_than_reset_under() {
        let _held = model::exclusive();
        model::already_running_and_stuck();
        assert_eq!(
            run(&memory(0), &mut Polls(8)),
            Err(BringUpError::WouldNotHalt),
            "resetting a running controller is undefined, and firmware leaves them running"
        );
    }

    #[test]
    fn more_slots_than_this_driver_will_take_are_clamped_rather_than_believed() {
        let _held = model::exclusive();
        let parameters = offered(255, 4, 0).expect("a plausible controller");
        assert_eq!(parameters.slots, super::MAX_SLOTS);
        // SAFETY: the model's file, as elsewhere.
        unsafe { bring_up::<Model, Polls>(0, &parameters, &memory(0), &mut Polls(16)) }
            .expect("it should have started");
        assert_eq!(
            model::get32(model::CONFIG) & 0xff,
            u32::from(super::MAX_SLOTS),
            "the slot count sizes the device context array, so enabling more \
             than were allocated is a bus master writing past it"
        );
    }

    #[test]
    fn the_interface_version_is_read_from_its_own_halfword_and_not_the_dword_below_it() {
        let _held = model::exclusive();
        // `CAPLENGTH` is a byte at 0x00 and `HCIVERSION` a halfword at 0x02.
        // They share a dword, which is how a controller is entitled to
        // implement them -- and reading the version as part of that dword,
        // or at the wrong offset inside it, answers the capability length.
        let parameters = offered(4, 2, 0).expect("a plausible controller");
        assert_eq!(parameters.version, 0x0110);
        assert_eq!(parameters.operational, model::CAPLENGTH);
    }

    #[test]
    fn a_controller_with_no_slots_is_refused_because_nothing_could_be_addressed() {
        let _held = model::exclusive();
        assert_eq!(offered(0, 2, 0), Err(BringUpError::NoDeviceSlots));
    }

    #[test]
    fn scratchpad_buffers_asked_for_and_not_provided_are_a_refusal() {
        let _held = model::exclusive();
        let parameters = offered(4, 2, 6).expect("a plausible controller");
        assert_eq!(parameters.scratchpads, 6);
        // SAFETY: the model's file, as elsewhere.
        let error = unsafe { bring_up::<Model, Polls>(0, &parameters, &memory(0), &mut Polls(16)) }
            .expect_err("a controller that asked for scratchpad must not be run without it");
        assert_eq!(error, BringUpError::ScratchpadNotProvided);
        assert_eq!(
            model::first_write_to(model::USBCMD),
            None,
            "it must be refused before the controller is touched at all"
        );
    }

    #[test]
    fn the_scratchpad_count_is_read_from_two_split_fields_and_not_one_range() {
        let _held = model::exclusive();
        // 33 is the smallest count whose high five bits are non-zero, so a
        // driver reading the field as one contiguous range answers 1 or 32
        // rather than 33 -- and a controller given fewer buffers than it asked
        // for does not run.
        let parameters = offered(4, 2, 33).expect("a plausible controller");
        assert_eq!(parameters.scratchpads, 33);
    }

    #[test]
    fn banks_the_controller_places_outside_its_window_are_refused() {
        let _held = model::exclusive();
        model::put32(0x18, (model::SIZE as u32) + 0x1000);
        assert_eq!(offered(4, 2, 0), Err(BringUpError::BanksOutsideWindow));
    }

    #[test]
    fn a_capability_length_shorter_than_the_capability_bank_is_refused() {
        let _held = model::exclusive();
        model::put32(0x00, 0x08);
        assert_eq!(
            offered(4, 2, 0),
            Err(BringUpError::CapabilityLengthTooSmall)
        );
    }

    #[test]
    fn a_misaligned_ring_is_refused_here_because_the_register_would_not_refuse_it() {
        let _held = model::exclusive();
        let parameters = offered(4, 2, 0).expect("a plausible controller");
        let mut memory = memory(0);
        // The low six bits of CRCR are flags, not address. A controller handed
        // this would silently truncate the pointer and silently set the flags.
        memory.command_ring += 8;
        // SAFETY: the model's file, as elsewhere.
        let error = unsafe { bring_up::<Model, Polls>(0, &parameters, &memory, &mut Polls(16)) }
            .expect_err("a misaligned ring pointer must be refused");
        assert_eq!(error, BringUpError::Misaligned);
        assert_eq!(
            model::first_write_to(model::USBCMD),
            None,
            "every address is refused before any register is written"
        );
    }

    #[test]
    fn the_device_context_array_holds_one_entry_more_than_the_slots() {
        // Entry zero is the scratchpad pointer and not a slot. Sizing this by
        // the slot count alone puts the last slot's context pointer in whatever
        // follows the allocation, which the controller writes to by DMA.
        assert_eq!(super::device_context_array_bytes(4), 5 * 8);
        assert_eq!(super::device_context_array_bytes(1), 2 * 8);
    }
}

#[cfg(test)]
mod absorb_tests {
    use bhaskix_xhci::trb::CompletionCode;

    use super::Drained;

    /// A drain that saw only port changes -- what a port reset leaves behind.
    fn ports(count: usize, last_port: u8) -> Drained {
        Drained {
            events: count,
            port_changes: count,
            last_port,
            ..Drained::default()
        }
    }

    /// A drain that saw one command completion.
    fn completion(code: CompletionCode, command: u64, slot: u8) -> Drained {
        Drained {
            events: 1,
            command_completions: 1,
            last_completion: Some(code),
            last_command: command,
            last_slot: slot,
            ..Drained::default()
        }
    }

    #[test]
    fn counts_add_across_rounds() {
        let mut total = ports(2, 5);
        total.absorb(completion(CompletionCode::Success, 0x1000, 3));
        assert_eq!(total.events, 3);
        assert_eq!(total.port_changes, 2);
        assert_eq!(total.command_completions, 1);
    }

    #[test]
    fn a_later_round_with_no_completion_does_not_erase_one() {
        // **The property the fix depends on.** A command's answer arrives in
        // round two; round three drains a stray port change. If that round
        // overwrote the "last" fields the caller would be told the command was
        // never answered, which is exactly the bug being fixed -- moved from
        // the ring into the bookkeeping.
        let mut total = ports(1, 4);
        total.absorb(completion(CompletionCode::Success, 0x2000, 7));
        total.absorb(ports(1, 9));

        assert_eq!(total.last_command, 0x2000, "the completion was forgotten");
        assert_eq!(total.last_completion, Some(CompletionCode::Success));
        assert_eq!(total.last_slot, 7);
        assert_eq!(total.last_port, 9, "the newer port change should win");
    }

    #[test]
    fn a_later_completion_replaces_an_earlier_one() {
        let mut total = completion(CompletionCode::Success, 0x1000, 1);
        total.absorb(completion(CompletionCode::TrbError, 0x2000, 2));
        assert_eq!(total.last_command, 0x2000);
        assert_eq!(total.last_completion, Some(CompletionCode::TrbError));
        assert_eq!(total.last_slot, 2);
        assert_eq!(total.command_completions, 2);
    }

    #[test]
    fn an_empty_round_changes_nothing() {
        // Every "last" field set to something distinguishable from the
        // default, because a round that drained nothing must not overwrite any
        // of them -- and a test that starts from zeroes cannot tell an
        // untouched field from one clobbered with a zero.
        let before = Drained {
            events: 3,
            command_completions: 1,
            port_changes: 2,
            last_completion: Some(CompletionCode::Success),
            last_command: 0x3000,
            last_slot: 4,
            last_port: 9,
            remaining: 17,
            ..Drained::default()
        };
        let mut total = before;
        total.absorb(Drained::default());
        assert_eq!(total, before);
    }
}

#[cfg(test)]
mod drain_tests {
    use bhaskix_xhci::trb::{CompletionCode, Kind, Trb};

    use super::{RING_ENTRIES, drain, ring::Consumer};

    /// An event ring a controller has written `published` entries into.
    ///
    /// Every entry carries the cycle bit a fresh consumer expects; everything
    /// past `published` is left zeroed, which is what unwritten memory looks
    /// like and is exactly how a consumer is meant to tell the difference.
    fn ring_of(published: &[Trb]) -> [Trb; RING_ENTRIES] {
        let mut ring = [Trb::new(); RING_ENTRIES];
        for (slot, event) in ring.iter_mut().zip(published) {
            *slot = event.with_cycle_bit(true);
        }
        ring
    }

    fn completion(code: CompletionCode, command: u64) -> Trb {
        let raw = match code {
            CompletionCode::Success => 1,
            CompletionCode::ShortPacket => 13,
            CompletionCode::TrbError => 5,
            _ => 0,
        };
        let mut event = Trb::new()
            .with_kind(Kind::CommandCompletion)
            .with_parameter(command);
        event.0[2] = raw << 24;
        event
    }

    fn port_change(port: u8) -> Trb {
        let mut event = Trb::new().with_kind(Kind::PortStatusChange);
        event.0[0] = u32::from(port) << 24;
        event
    }

    fn drained_from(ring: &[Trb; RING_ENTRIES], consumer: &mut Consumer) -> super::Drained {
        drain(RING_ENTRIES, consumer, &mut |index| ring[index])
    }

    #[test]
    fn an_empty_ring_yields_nothing_rather_than_reading_a_zeroed_entry_as_an_event() {
        // The one that matters most: a zeroed ring is what the controller was
        // handed, and every field of a zeroed TRB reads as a legal value. Only
        // the cycle bit says it was never written.
        let ring = ring_of(&[]);
        let mut consumer = Consumer::new(RING_ENTRIES).expect("a ring");
        let found = drained_from(&ring, &mut consumer);
        assert_eq!(found.events, 0);
        assert_eq!(found.unrecognised, 0);
        assert_eq!(
            consumer.index(),
            0,
            "an empty drain must not move the cursor"
        );
    }

    #[test]
    fn a_command_completion_is_matched_to_the_command_it_answers() {
        let ring = ring_of(&[completion(CompletionCode::Success, 0x1_0000_1000)]);
        let mut consumer = Consumer::new(RING_ENTRIES).expect("a ring");
        let found = drained_from(&ring, &mut consumer);
        assert_eq!(found.events, 1);
        assert_eq!(found.command_completions, 1);
        assert_eq!(found.last_completion, Some(CompletionCode::Success));
        assert_eq!(
            found.last_command, 0x1_0000_1000,
            "the address is the whole claim: an event that does not name the \
             command proves only that the event ring works"
        );
        assert_eq!(consumer.index(), 1);
    }

    #[test]
    fn the_drain_stops_at_the_first_entry_the_controller_has_not_written() {
        // Two published, the rest zeroed. A drain that read past the boundary
        // would report the whole ring as events -- which is what a driver that
        // trusts a length instead of the cycle bit does.
        let ring = ring_of(&[completion(CompletionCode::Success, 0x2000), port_change(3)]);
        let mut consumer = Consumer::new(RING_ENTRIES).expect("a ring");
        let found = drained_from(&ring, &mut consumer);
        assert_eq!(found.events, 2);
        assert_eq!(found.command_completions, 1);
        assert_eq!(found.port_changes, 1);
        assert_eq!(found.last_port, 3);
        assert_eq!(consumer.index(), 2);
    }

    #[test]
    fn a_second_drain_finds_nothing_until_the_controller_writes_again() {
        let ring = ring_of(&[completion(CompletionCode::Success, 0x3000)]);
        let mut consumer = Consumer::new(RING_ENTRIES).expect("a ring");
        assert_eq!(drained_from(&ring, &mut consumer).events, 1);
        assert_eq!(
            drained_from(&ring, &mut consumer).events,
            0,
            "an event consumed twice is an event acted on twice"
        );
    }

    #[test]
    fn a_full_lap_leaves_the_consumer_expecting_the_other_cycle_state() {
        // Every entry published, so a whole lap is consumed. The event ring has
        // no link TRB, so the wrap happens at `entries` -- and the consumer must
        // come back expecting cycle 0, because the controller will write the
        // next lap with the bit flipped over the entries it just used.
        let published: [Trb; RING_ENTRIES] =
            core::array::from_fn(|index| completion(CompletionCode::Success, index as u64 * 16));
        let ring = ring_of(&published);
        let mut consumer = Consumer::new(RING_ENTRIES).expect("a ring");
        let found = drained_from(&ring, &mut consumer);
        assert_eq!(found.events, RING_ENTRIES);
        assert_eq!(consumer.index(), 0, "a full lap returns to the start");
        assert!(
            !consumer.owns(true),
            "after one lap the consumer expects cycle 0; still expecting 1 would \
             make it replay the lap it has just consumed"
        );
    }

    #[test]
    fn a_kind_this_driver_does_not_name_is_counted_rather_than_ignored() {
        let ring = ring_of(&[Trb::new().with_kind(Kind::Other(42))]);
        let mut consumer = Consumer::new(RING_ENTRIES).expect("a ring");
        let found = drained_from(&ring, &mut consumer);
        assert_eq!(found.events, 1);
        assert_eq!(
            found.unrecognised, 1,
            "a controller posting events a driver has no case for is a driver \
             that has misunderstood something; a silent match arm hides it"
        );
    }

    #[test]
    fn a_short_packet_is_not_read_as_a_failure() {
        // `ShortPacket` is how a device answers with less than the buffer
        // allowed, which is routine. A driver comparing against `Success` alone
        // rejects perfectly good descriptors.
        let ring = ring_of(&[completion(CompletionCode::ShortPacket, 0x4000)]);
        let mut consumer = Consumer::new(RING_ENTRIES).expect("a ring");
        let found = drained_from(&ring, &mut consumer);
        assert_eq!(found.last_completion, Some(CompletionCode::ShortPacket));
        assert!(
            found
                .last_completion
                .expect("a completion was recorded")
                .is_success()
        );
    }

    #[test]
    fn a_failure_code_is_carried_out_rather_than_swallowed() {
        let ring = ring_of(&[completion(CompletionCode::TrbError, 0x5000)]);
        let mut consumer = Consumer::new(RING_ENTRIES).expect("a ring");
        let found = drained_from(&ring, &mut consumer);
        assert_eq!(found.command_completions, 1);
        assert!(
            !found
                .last_completion
                .expect("a completion was recorded")
                .is_success()
        );
    }

    #[test]
    fn the_command_ring_gets_a_link_trb_that_toggles_and_the_event_ring_gets_none() {
        // A command ring's last entry must be a Link back to the start, or the
        // controller runs off the end of the segment into whatever follows it
        // -- by DMA. It must toggle, because this is a one-segment ring and the
        // lap has to flip somewhere.
        //
        // Step 3 wrote no link at all. Nothing read the ring then, so it cost
        // nothing; step 4 rings the doorbell, and after fifteen commands the
        // controller would have read a zeroed TRB and stopped.
        let (index, link) =
            super::command_ring_link(0x1_0000_0000, RING_ENTRIES).expect("a ring and an address");
        assert_eq!(
            index,
            RING_ENTRIES - 1,
            "the link is the last entry, and a ring that puts work there              overwrites its own wrap"
        );
        assert_eq!(link.kind(), Kind::Link);
        assert!(
            link.toggle_cycle(),
            "a one-segment ring has nowhere else for the lap to flip: without              the toggle the controller reads the next lap as stale and stops"
        );
        assert_eq!(link.parameter(), 0x1_0000_0000);
        assert!(
            link.cycle_bit(),
            "the link is published like any other entry, so it carries the              producer's starting cycle or the controller never follows it"
        );

        // And the asymmetry, asserted rather than described: the consumer wraps
        // one entry later than the producer, because no entry of an event ring
        // is spent on a link.
        let producer = super::ring::Producer::new(RING_ENTRIES).expect("a ring");
        let consumer = Consumer::new(RING_ENTRIES).expect("a ring");
        assert_eq!(consumer.index(), producer.index());
        assert_eq!(
            producer.remaining_this_lap(),
            RING_ENTRIES - 1,
            "a command ring spends one entry on its link; an event ring spends none"
        );
    }

    #[test]
    fn a_misaligned_link_address_is_refused_rather_than_truncated() {
        assert!(super::command_ring_link(0x1000, RING_ENTRIES).is_some());
        assert!(
            super::command_ring_link(0x1008, RING_ENTRIES).is_none(),
            "the low bits of a link pointer are not address, so a misaligned \
             one is silently truncated by the controller rather than refused"
        );
    }
}

#[cfg(test)]
mod address_tests {
    use bhaskix_xhci::{context, doorbell};

    use super::{RING_ENTRIES, address_device_input, initial_max_packet_size};

    const TRANSFER_RING: u64 = 0x1_0000_5000;

    fn built(context_size_64: bool) -> [(usize, [u32; context::DWORDS]); 3] {
        address_device_input(5, 3, TRANSFER_RING, true, context_size_64)
            .expect("a plausible device")
    }

    #[test]
    fn the_slot_context_sits_one_stride_in_because_an_input_context_has_a_header() {
        // **The trap RFC 0041 names.** An input context is
        // `[input control][slot][endpoint 1]`, one context further along than a
        // device context. A driver using device-context arithmetic writes the
        // slot context on top of the input control context's add and drop
        // flags -- which is a command that configures the wrong endpoints and
        // is accepted.
        for (size_64, stride) in [(false, 32usize), (true, 64usize)] {
            let writes = built(size_64);
            assert_eq!(writes[0].0, 0, "the input control context is first");
            assert_eq!(
                writes[1].0, stride,
                "the slot context is at one stride, not at zero"
            );
            assert_eq!(
                writes[2].0,
                2 * stride,
                "the control endpoint is at two strides: its Device Context \
                 Index is 1, and an input context adds one to every index"
            );
        }
    }

    #[test]
    fn the_stride_doubles_with_the_context_size_and_the_field_offsets_do_not() {
        // What `HCCPARAMS1`'s context-size bit buys is padding, not a different
        // layout. Getting this backwards misplaces every context after the
        // first by a factor of two, and misplaces no field within one.
        let small = built(false);
        let large = built(true);
        assert_eq!(large[1].0, small[1].0 * 2);
        assert_eq!(large[2].0, small[2].0 * 2);
        assert_eq!(small[0].1, large[0].1, "the dwords written do not change");
        assert_eq!(small[1].1, large[1].1);
        assert_eq!(small[2].1, large[2].1);
    }

    #[test]
    fn exactly_the_slot_and_the_control_endpoint_are_added_and_nothing_is_dropped() {
        let writes = built(false);
        let control = context::InputControl(writes[0].1);
        assert_eq!(
            control.add_flags(),
            0b11,
            "A0 and A1: the slot context and the control endpoint. Adding a \
             context that has not been written asks the controller to read \
             uninitialised memory"
        );
        assert_eq!(
            control.drop_flags(),
            0,
            "nothing exists yet to drop, and bits 1:0 of the drop flags are \
             reserved in any case"
        );
    }

    #[test]
    fn the_root_hub_port_lands_in_its_own_field_and_not_the_hub_port_count() {
        // This is the bug a controller found on 2026-08-23: written at bits
        // 31:24 -- which is Number of Ports -- Address Device is refused with
        // TrbError, and every other field probes correct. Asserted on the raw
        // dword, because reading it back through the accessor that wrote it
        // is what failed to catch it.
        let slot = context::Slot(built(false)[1].1);
        assert_eq!(slot.root_hub_port_number(), 5);
        assert_eq!(built(false)[1].1[1], 5 << 16, "bits 23:16, and alone");
        assert_eq!(built(false)[1].1[1] >> 24, 0);
    }

    #[test]
    fn the_slot_says_it_uses_exactly_one_context_and_no_more() {
        let slot = context::Slot(built(false)[1].1);
        assert_eq!(
            slot.context_entries(),
            doorbell::CONTROL_ENDPOINT,
            "the highest Device Context Index in use, not a count of \
             endpoints -- set too low, the controller ignores contexts that \
             are there"
        );
        assert_eq!(slot.speed(), 3);
        assert_eq!(
            slot.route_string(),
            0,
            "a root port device routes through nothing"
        );
    }

    #[test]
    fn the_control_endpoint_is_a_control_endpoint_on_a_ring_it_was_given() {
        let endpoint = context::Endpoint(built(false)[2].1);
        assert_eq!(endpoint.endpoint_type(), context::EndpointType::Control);
        assert_eq!(endpoint.transfer_ring_pointer(), TRANSFER_RING);
        assert!(
            endpoint.dequeue_cycle_state(),
            "the controller must start on the same cycle the producer does, or \
             it reads a ring it thinks is empty"
        );
        assert_eq!(
            endpoint.error_count(),
            3,
            "zero means retry for ever, which is a wedged endpoint rather \
             than a reported error"
        );
    }

    #[test]
    fn a_transfer_ring_the_context_cannot_hold_is_refused() {
        assert!(address_device_input(5, 3, TRANSFER_RING, true, false).is_some());
        assert!(
            address_device_input(5, 3, TRANSFER_RING + 8, true, false).is_none(),
            "the low bits of the pointer are flags, so a misaligned ring is \
             silently truncated by the controller rather than refused"
        );
    }

    #[test]
    fn the_initial_packet_size_follows_the_speed_and_undefined_is_the_smallest() {
        assert_eq!(initial_max_packet_size(1), 8, "full speed starts at eight");
        assert_eq!(initial_max_packet_size(2), 8, "low speed is eight");
        assert_eq!(initial_max_packet_size(3), 64, "high speed is fixed at 64");
        assert_eq!(initial_max_packet_size(4), 512);
        assert_eq!(
            initial_max_packet_size(0),
            8,
            "speed zero is undefined, and eight is the value that cannot ask a \
             device for more than it can answer"
        );
    }

    #[test]
    fn the_input_context_is_small_enough_for_the_frame_it_is_written_into() {
        // Three 64-byte contexts at most. The write loop puts them in one
        // allocated frame, and an offset past it would be a store into
        // somebody else's memory.
        let last = built(true)[2].0 + context::DWORDS * 4;
        assert!(
            last <= 4096,
            "an input context must fit the frame it is given"
        );
        assert_eq!(
            context::input_context_bytes(doorbell::CONTROL_ENDPOINT, true),
            Some(3 * 64)
        );
        // And the transfer ring likewise.
        assert!(super::ring_bytes() <= 4096);
        assert_eq!(RING_ENTRIES * 16, super::ring_bytes());
    }
}

#[cfg(test)]
mod control_tests {
    use bhaskix_usb::setup::Setup;
    use bhaskix_xhci::{context, doorbell, trb};

    use super::{
        RING_ENTRIES, configure_endpoint_input, control_transfer_stages, interval_exponent,
    };

    const BUFFER: u64 = 0x1_0000_4000;
    const RING: u64 = 0x1_0000_6000;

    fn read_18() -> ([trb::Trb; 3], usize) {
        let setup = Setup::get_descriptor(bhaskix_usb::kind::DEVICE, 0, 18);
        control_transfer_stages(setup.0, BUFFER, 18, true, true).expect("a plausible transfer")
    }

    #[test]
    fn a_control_read_is_setup_then_data_then_status() {
        let (stages, count) = read_18();
        assert_eq!(count, 3);
        assert_eq!(stages[0].kind(), trb::Kind::SetupStage);
        assert_eq!(stages[1].kind(), trb::Kind::DataStage);
        assert_eq!(stages[2].kind(), trb::Kind::StatusStage);
    }

    #[test]
    fn only_the_last_stage_asks_to_be_reported() {
        // The controller executes the whole descriptor and posts a Transfer
        // Event where it is asked to. Asking on every stage is three events for
        // one transfer; asking on none is a transfer that completes correctly
        // and silently while the driver waits for ever.
        let (stages, count) = read_18();
        assert!(!stages[0].interrupt_on_completion(), "not the setup stage");
        assert!(!stages[1].interrupt_on_completion(), "not the data stage");
        assert!(
            stages[count - 1].interrupt_on_completion(),
            "the status stage, and only it"
        );
    }

    #[test]
    fn the_status_stage_points_the_opposite_way_to_the_data_stage() {
        // A control read is acknowledged by writing nothing. A status stage
        // pointing the same way as its data stage is a transfer the device
        // never completes.
        let (read, _) = read_18();
        assert_eq!(read[1].0[3] & (1 << 16), 1 << 16, "data IN");
        assert_eq!(read[2].0[3] & (1 << 16), 0, "status OUT");

        let setup = Setup::set_configuration(1);
        let (write, count) = control_transfer_stages(setup.0, BUFFER, 0, false, true)
            .expect("a transfer with no data");
        assert_eq!(count, 2, "no data stage means two TRBs, not three");
        assert_eq!(write[1].kind(), trb::Kind::StatusStage);
        assert_eq!(
            write[1].0[3] & (1 << 16),
            1 << 16,
            "a transfer with no data at all is acknowledged by reading nothing"
        );
    }

    #[test]
    fn the_setup_stage_says_which_kind_of_transfer_follows_it() {
        let (read, _) = read_18();
        assert_eq!((read[0].0[3] >> 16) & 0b11, 3, "In");
        let (none, _) =
            control_transfer_stages(Setup::set_configuration(1).0, BUFFER, 0, false, true)
                .expect("a transfer");
        assert_eq!((none[0].0[3] >> 16) & 0b11, 0, "No Data");
        let (out, _) =
            control_transfer_stages(Setup::set_configuration(1).0, BUFFER, 4, false, true)
                .expect("a transfer");
        assert_eq!((out[0].0[3] >> 16) & 0b11, 2, "Out, which is 2 and not 1");
    }

    #[test]
    fn every_stage_of_one_transfer_carries_the_same_cycle_bit() {
        // They are published as one descriptor. A stage on the other cycle is a
        // stage the controller reads as not yet written, in the middle of a
        // transfer it has already begun.
        for cycle in [false, true] {
            let setup = Setup::get_descriptor(bhaskix_usb::kind::DEVICE, 0, 18);
            let (stages, count) =
                control_transfer_stages(setup.0, BUFFER, 18, true, cycle).expect("a transfer");
            for stage in stages.iter().take(count) {
                assert_eq!(stage.cycle_bit(), cycle);
            }
        }
    }

    #[test]
    fn a_configure_adds_the_endpoint_and_re_sends_the_slot_that_must_grow() {
        // Context Entries names the *highest* Device Context Index in use and
        // says 1 after Address Device. Adding an endpoint at 3 without raising
        // it is a controller told to configure something it has been told does
        // not exist -- which is why the slot context is re-sent rather than
        // left alone.
        let writes = configure_endpoint_input(5, 3, 3, 8, 6, RING, true, false)
            .expect("a plausible endpoint");
        let control = context::InputControl(writes[0].1);
        assert_eq!(control.add_flags(), 0b1001, "A0 and A3, not A0 and A1");
        assert_eq!(control.drop_flags(), 0, "nothing is torn down by this");
        assert_eq!(context::Slot(writes[1].1).context_entries(), 3);
        assert_eq!(
            writes[2].0,
            4 * 32,
            "index 3 in an input context is at four strides"
        );
    }

    #[test]
    fn the_endpoint_is_an_interrupt_in_endpoint_on_a_ring_of_its_own() {
        let writes = configure_endpoint_input(5, 3, 3, 8, 6, RING, true, false).expect("built");
        let endpoint = context::Endpoint(writes[2].1);
        assert_eq!(endpoint.endpoint_type(), context::EndpointType::InterruptIn);
        assert_eq!(endpoint.max_packet_size(), 8);
        assert_eq!(endpoint.interval(), 6);
        assert_eq!(endpoint.transfer_ring_pointer(), RING);
        assert!(endpoint.dequeue_cycle_state());
        assert_eq!(endpoint.error_count(), 3);
    }

    #[test]
    fn an_index_the_control_endpoint_or_the_slot_already_owns_is_refused() {
        // Index 0 is the slot and 1 the control endpoint. Neither is configured
        // by this command, and an index below 2 means the Device Context Index
        // arithmetic went wrong upstream -- which is the trap RFC 0041 names.
        assert!(configure_endpoint_input(5, 3, 0, 8, 6, RING, true, false).is_none());
        assert!(configure_endpoint_input(5, 3, 1, 8, 6, RING, true, false).is_none());
        assert!(configure_endpoint_input(5, 3, 2, 8, 6, RING, true, false).is_some());
    }

    #[test]
    fn endpoint_one_in_is_context_index_three() {
        // The standing trap, asserted where a driver would trip on it: the
        // Device Context Index is not the endpoint number.
        assert_eq!(doorbell::device_context_index(1, true), Some(3));
        assert_eq!(doorbell::device_context_index(1, false), Some(2));
        assert_eq!(
            doorbell::device_context_index(0, true),
            Some(doorbell::CONTROL_ENDPOINT)
        );
    }

    #[test]
    fn the_interval_exponent_is_derived_and_not_copied() {
        // The field is an exponent -- 2^interval x 125 us -- and `bInterval` is
        // not that. At high speed it is itself an exponent counted from one; at
        // full and low speed it is a count of frames, and a frame is eight
        // microframes.
        //
        // NOT VERIFIED against a specification on this machine. What is
        // corroborating: QEMU's keyboard reports bInterval 7 at high speed, and
        // exponent 6 is 8 ms, which is the rate a HID keyboard is conventionally
        // polled at.
        assert_eq!(interval_exponent(7, 3), 6, "high speed: one less");
        assert_eq!(125u32 << interval_exponent(7, 3), 8000);
        assert_eq!(interval_exponent(1, 3), 0);
        assert_eq!(interval_exponent(0, 3), 0, "zero must not underflow");
        assert_eq!(interval_exponent(200, 3), 15, "and it is clamped");
        // Full speed: 1 frame is 8 microframes, which is 2^3.
        assert_eq!(interval_exponent(1, 1), 3);
        assert_eq!(interval_exponent(8, 1), 6, "8 frames is 64 microframes");
    }

    #[test]
    fn a_transfer_that_does_not_fit_before_the_wrap_is_refused_by_the_caller() {
        // `control_transfer_stages` builds three TRBs; a ring with fewer than
        // three entries left before its link cannot hold one transfer
        // descriptor, and a descriptor split across a lap is not a descriptor.
        let producer = super::ring::Producer::new(RING_ENTRIES).expect("a ring");
        assert!(producer.remaining_this_lap() >= 3);
        assert_eq!(read_18().1, 3);
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
