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
use bhaskix_device::Bus;
use bhaskix_xhci::{capability, context, operational, runtime, trb};

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
            }
            trb::Kind::PortStatusChange => {
                found.port_changes += 1;
                found.last_port = event.port_id();
            }
            trb::Kind::TransferEvent => {
                found.transfers += 1;
                found.last_completion = Some(event.completion_code());
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

/// The most scratchpad buffers this driver will provide, each a whole page.
///
/// The controller names the count and the count sizes an allocation, so it is
/// bounded before it is believed — RFC 0038's rule 6. A controller wanting more
/// than this is refused rather than partially satisfied, because a controller
/// given fewer buffers than it asked for does not run.
const MAX_SCRATCHPADS: u32 = 32;

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
    TooManyScratchpads,
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
            Self::TooManyScratchpads => {
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

    if parameters.scratchpads > MAX_SCRATCHPADS {
        return Err(InitError::TooManyScratchpads);
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
    // SAFETY: the controller is running, and this is its memory and its window.
    let answered = unsafe {
        exercise_the_rings(
            base,
            &parameters,
            &memory,
            command_ring.virtual_address,
            event_ring.virtual_address,
            &mut Settle,
        )
    };

    Ok(Started {
        running,
        frames,
        answered,
    })
}

/// Sends a No-Op command and consumes the event it produces.
///
/// **A No-Op is how a driver proves its command ring works**, which is what the
/// vendored crate's own constructor says it is for. Nothing is plugged in and no
/// slot exists, so this is the only question that can be asked at this step --
/// and the answer is not merely "an event arrived": a Command Completion Event
/// names *the address of the command TRB it is answering*, so a matching pointer
/// is a round trip a coincidence cannot fake.
///
/// # Safety
///
/// The controller must be running, `base` its mapped window, and the two
/// virtual addresses the kernel's view of the rings named in `memory`.
unsafe fn exercise_the_rings<W: Wait>(
    base: usize,
    parameters: &Parameters,
    memory: &Memory,
    command_ring: u64,
    event_ring: u64,
    wait: &mut W,
) -> Answered {
    let mut answered = Answered::default();

    let Some(producer) = ring::Producer::new(memory.command_ring_entries) else {
        return answered;
    };
    let Some(mut consumer) = ring::Consumer::new(memory.event_ring_entries) else {
        return answered;
    };
    let Some(doorbell_offset) =
        bhaskix_xhci::doorbell::doorbell_at(bhaskix_xhci::doorbell::COMMAND_RING)
    else {
        return answered;
    };

    // Where the controller will say it found this command. The *device*
    // address, because that is the number the controller deals in -- naming the
    // physical one here would compare an answer against a question nobody asked.
    let asked_at = memory.command_ring + (producer.index() * trb::BYTES) as u64;
    answered.asked_at = asked_at;

    // SAFETY: a frame `init` allocated and zeroed, at an index `Producer`
    // bounds to inside the ring.
    unsafe {
        core::ptr::write_volatile(
            (command_ring as *mut [u32; 4]).add(producer.index()),
            trb::Trb::no_op_command(producer.cycle()).0,
        );
    }

    // SAFETY: the doorbell bank is inside the window, which `parameters`
    // checked, and the offset is bounded by `doorbell_at`.
    let doorbell = unsafe {
        DoorbellRegister::<bhaskix_device::Volatile>::new(
            base + parameters.doorbells + doorbell_offset,
        )
    };
    doorbell
        .value
        .write(bhaskix_xhci::doorbell::Doorbell::command().0);

    // The controller has to run the command and post the event. Bounded, and a
    // controller that never answers is a report rather than a hang.
    // Wait for the controller to publish something at the entry this consumer
    // is looking at. Ownership is the cycle bit and nothing else: a zeroed
    // entry has bit 0, a fresh consumer expects 1, so "not written yet" and
    // "written" are distinguishable without reading anything else.
    answered.arrived = wait.until(&mut || {
        // SAFETY: the event ring is a frame `init` allocated; this reads one
        // TRB at an index `Consumer` bounds to inside it. Volatile because the
        // controller writes here by DMA.
        let event = unsafe {
            core::ptr::read_volatile((event_ring as *const [u32; 4]).add(consumer.index()))
        };
        consumer.owns(trb::Trb(event).cycle_bit())
    });

    let drained = drain(memory.event_ring_entries, &mut consumer, &mut |index| {
        // SAFETY: as above.
        trb::Trb(unsafe { core::ptr::read_volatile((event_ring as *const [u32; 4]).add(index)) })
    });
    answered.drained = drained;

    // Tell the controller how far this driver has consumed, and clear the
    // Event Handler Busy bit while doing it -- the one write that says "I am
    // done looking". Without it the controller will not raise the interrupter
    // again, which is a ring that works exactly once.
    if let Some(interrupter_zero) = runtime::interrupter_at(0)
        && let Some(dequeue) = runtime::EventRingDequeuePointer::advancing(
            memory.event_ring + (consumer.index() * trb::BYTES) as u64,
            0,
            true,
        )
    {
        // SAFETY: the runtime bank is inside the window, which `parameters`
        // checked.
        let interrupter = unsafe {
            Interrupter::<bhaskix_device::Volatile>::new(
                base + parameters.runtime + interrupter_zero,
            )
        };
        interrupter.erdp.write(dequeue.0);
        answered.dequeue_advanced = true;
    }

    answered.matched = drained.command_completions > 0 && drained.last_command == asked_at;
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
