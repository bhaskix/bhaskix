// SPDX-License-Identifier: Apache-2.0
#![no_std]
#![forbid(unsafe_code)]
//! An Intel X722, as arithmetic over a trait.
//!
//! RFC 0072 wrote this driver; **RFC 0075 moved it out of the kernel**, and the
//! move is what this crate's shape is about. It was `kernel/src/i40e.rs`, three
//! thousand lines of device driver inside the nucleus, and the only half of it
//! anything could test was the byte encoders -- twelve tests over the
//! descriptors and contexts, and not one over a register, which is where every
//! bug this driver has actually had was found.
//!
//! So there is no address in this crate. Registers go through [`Registers`],
//! rings and command buffers arrive as slices, and the one unsafe operation a
//! NIC driver genuinely needs -- a volatile access to a mapping somebody else
//! made -- belongs to whoever implements the trait. `forbid(unsafe_code)` above
//! is what makes that a rule rather than an intention, and it is the same shape
//! `ahci/src/lib.rs` has for the same reason.
//!
//! What the driver *does* is unchanged: it resets the function and gives it an
//! admin queue, which is the handshake every later question goes through, since
//! an i40e-class device answers nothing until its admin queue exists.
//!
//! # Where these numbers come from
//!
//! The **Intel C620 Series Chipset Platform Controller Hub Datasheet**, a
//! public document, section 38.39.2. The X722 is that chipset's integrated
//! controller rather than a discrete adapter, which is why its registers are
//! there and not in the X710/XXV710/XL710 datasheet -- that one is public and
//! register-level too, and covers a different part. Nothing here is written
//! from memory of another driver, and nothing is derived from one: RFC 0071
//! records why that distinction matters, and RFC 0072 records that it did not
//! have to be argued because the specification is public.
//!
//! Every offset below carries the datasheet's own section number, so a reader
//! can check it rather than trust it.

/// PF Control -- 38.39.2.1.20, `PFGEN_CTRL (0x00092400; RW)`.
///
/// Bit 0 is `PFSWR`. Software sets it to ask for a PF reset; **hardware clears
/// it when the reset is done**, which the datasheet states as the last step of
/// the sequence: *"After all the previous steps are completed, hardware does
/// the following: clears the PFSWR bit in the PFGEN_CTRL register."* So the
/// completion test is the bit reading back as zero, and no other register has
/// to be consulted for it.
const PFGEN_CTRL: u64 = 0x0009_2400;
/// `PFGEN_CTRL.PFSWR`, bit 0 -- the same section.
const PFSWR: u32 = 1 << 0;

/// Admin queue registers -- 38.39.2.15, in the datasheet's own order.
///
/// The admin transmit queue is what the driver puts commands on; the admin
/// receive queue is what the firmware puts answers and events on. Both are
/// descriptor rings in host memory, so both take a base address split across
/// two registers and a length that carries an enable bit.
const PF_ATQBAL: u64 = 0x0008_0000;
/// 38.39.2.15.5.
const PF_ATQBAH: u64 = 0x0008_0100;
/// 38.39.2.15.9. Bits 9:0 are the ring length, maximum 1024; **bit 31 is
/// `ATQENABLE`**, and the datasheet is explicit about the order: *"Set by
/// driver to indicate that the queue is active. When setting the enable bit,
/// software should initialize all other fields."* So the base addresses are
/// written first and the length with its enable bit last.
const PF_ATQLEN: u64 = 0x0008_0200;
/// 38.39.2.15.12.
const PF_ATQH: u64 = 0x0008_0300;
/// 38.39.2.15.16.
const PF_ATQT: u64 = 0x0008_0400;
/// 38.39.2.15.3.
const PF_ARQBAL: u64 = 0x0008_0080;
/// 38.39.2.15.7.
const PF_ARQBAH: u64 = 0x0008_0180;
/// 38.39.2.15.11.
const PF_ARQLEN: u64 = 0x0008_0280;
/// 38.39.2.15.14.
const PF_ARQH: u64 = 0x0008_0380;
/// 38.39.2.15.18.
const PF_ARQT: u64 = 0x0008_0480;
/// `PF_ATQLEN.ATQENABLE` / `PF_ARQLEN.ARQENABLE`, bit 31.
const QUEUE_ENABLE: u32 = 1 << 31;

/// One admin queue descriptor, in bytes -- Table 38-339, *Admin Queue
/// Descriptor Structure (in LE 32 Order)*.
///
/// Eight 32-bit words: opcode and flags, return value and data length, cookie
/// high and low, `Param0` and `Param1`, and the data address split high and
/// low. Read off the table rather than inferred, because the text extraction of
/// that page renders a bit-field diagram as a column of loose digits and an
/// inferred size would have been a guess dressed as a citation.
pub const DESCRIPTOR_BYTES: u64 = 32;

/// How many descriptors each admin ring holds.
///
/// The datasheet allows up to 1024. Thirty-two is chosen because this step asks
/// the device a handful of questions and never queues more than one at a time,
/// and a ring is a page's worth of memory the domain has to lend either way.
pub const RING_DESCRIPTORS: u32 = 32;

/// Bytes one admin ring occupies.
pub const RING_BYTES: u64 = DESCRIPTOR_BYTES * RING_DESCRIPTORS as u64;

/// Where the receive ring sits in the page holding both.
///
/// Both rings fit one 4 KiB page -- 1 KiB each -- and sharing a page keeps this
/// to a single object to create, map and revoke. The transmit ring is at offset
/// zero and the receive ring follows it.
pub const RECEIVE_RING_OFFSET: u64 = RING_BYTES;

/// `Get Version`, the opcode -- Table 38-353, *Get Version Command*.
///
/// The datasheet is emphatic about its place: *"This must be the first command
/// that the software device driver issues before it can use the queue for other
/// purposes."* Its `Datalen` is 0 -- *"no external response buffer"* -- so the
/// answer comes back **in the descriptor**, which is why this needs no buffer
/// mapped for the reply.
const OPCODE_GET_VERSION: u16 = 0x0001;

/// `Flags.DD`, byte 0 bit 0 -- Table 38-340: *"Set by firmware to mark entry
/// done."* This is the completion test, and firmware is what sets it.
const FLAG_DD: u16 = 1 << 0;
/// `Flags.ERR`, byte 0 bit 2 -- *"Set by firmware to mark entry as an error
/// indication."*
const FLAG_ERR: u16 = 1 << 2;
/// `Flags.LB`, byte 1 bit 1 -- *"indirect buffer is longer than
/// AQ_LARGE_BUF"*, which 38.27 puts at 512 bytes.
const FLAG_LB: u16 = 1 << 9;
/// `Flags.BUF`, byte 1 bit 4 -- *"This command uses additional data."*
const FLAG_BUF: u16 = 1 << 12;
/// The buffer length above which `Flags.LB` must be set -- 38.27.
pub const AQ_LARGE_BUF: u16 = 512;

/// `Get Link Status` -- Table 38-63, opcode `0x0607`, a direct command whose
/// answer is Table 38-65's fourteen bytes at descriptor bytes 18-31.
const OPCODE_GET_LINK_STATUS: u16 = 0x0607;

/// `Get Switch Configuration` -- Table 38-199, opcode `0x0200`: *"used to
/// discover the switch configuration of the port. The software device driver
/// must use this command as part of the initialization flow"*. Indirect: the
/// answer is Table 38-201's buffer, a header and sixteen bytes per element.
const OPCODE_GET_SWITCH_CONFIGURATION: u16 = 0x0200;

/// Where the switch buffer sits in the page holding the admin rings.
///
/// The two rings take the first 2 KiB; this takes 512 bytes after them --
/// exactly [`AQ_LARGE_BUF`], so `Flags.LB` is not needed, and the room is Table
/// 38-202's header plus thirty-one elements, which a port with SR-IOV off does
/// not approach.
pub const SWITCH_BUFFER_OFFSET: u64 = 2 * RING_BYTES;
/// The switch buffer's length -- see [`SWITCH_BUFFER_OFFSET`].
pub const SWITCH_BUFFER_BYTES: u16 = AQ_LARGE_BUF;
/// How many elements the switch buffer can hold after its header.
pub const SWITCH_ELEMENTS_MAX: usize =
    (SWITCH_BUFFER_BYTES as usize - SwitchElement::BYTES) / SwitchElement::BYTES;
const _: () = assert!(
    SWITCH_BUFFER_OFFSET + SWITCH_BUFFER_BYTES as u64 <= 4096,
    "the rings and the switch buffer must share one page"
);

/// Where `Get Version`'s answer sits in the completed descriptor -- Table
/// 38-353. Major at bytes 24-25 and minor at 26-27, which in a normal command
/// descriptor are the data address; a command with no external buffer reuses
/// them for its reply.
const VERSION_MAJOR_AT: usize = 24;

/// Global Receive Queue Enable -- 38.39.2.18.13, `QRX_ENA[Q]`
/// (`0x00120000 + 0x4*Q`, Q = 0..1535).
///
/// Four states rather than two, per Table 38-418, and the datasheet is explicit
/// about the handshake: *"If this bit is set, the software should poll the
/// QENA_STAT flag before using the queue... Once software changes the state of
/// the QENA_REQ flag it must poll the QENA_STAT before it is permitted to
/// revert the state of the QENA_REQ once again."* So enabling a queue is a
/// request and a wait, not a write.
const QRX_ENA: u64 = 0x0012_0000;
/// `QRX_ENA.QENA_REQ`, bit 0 -- what software asks for.
const QENA_REQ: u32 = 1 << 0;
/// `QRX_ENA.QENA_STAT`, bit 2 -- what the hardware reports. Read from the field
/// list rather than inferred from the reserved range, because a bit position
/// guessed from a gap is a guess.
const QENA_STAT: u32 = 1 << 2;

/// Function Requester ID -- 38.39.2.2.1, `PF_FUNC_RID` (`0x0009C000`, RO).
///
/// `FUNCTION_NUMBER` is bits 2:0, *"assigned to the function based on BIOS/OS
/// enumeration"*. The HMC's per-function registers are indexed by it -- 38.26.3
/// step 1: *"In the case of a PF, the HMC function number is equal to the PCI
/// function number"* -- and it is asked of the device rather than taken from
/// the PCI address, because the device is the one doing the indexing.
const PF_FUNC_RID: u64 = 0x0009_C000;

/// Private Memory Segment Table Partitioning -- 38.39.2.13.10,
/// `GLHMC_SDPART[n]` (`0x000C0800 + 0x4*n`, n = 0..15).
///
/// `PMSDBASE` is bits 11:0 and `PMSDSIZE` bits 28:16: which segment descriptors
/// this function owns. **Firmware's to set and this driver's to read.** The
/// register heading says RO, its field table says RW, and the prose settles it:
/// 38.26.2 says these registers *"are loaded from the NVM to match the default
/// profile"*, and 38.26.1 that the controller *"manages the SD base and number
/// registers internally based on the resource profile"*. A driver discovers its
/// range and programs segment descriptors relative to it.
const GLHMC_SDPART: u64 = 0x000C_0800;

/// FPM LAN Tx Queue Base -- 38.39.2.13.68, `GLHMC_LANTXBASE[n]`
/// (`0x000C6200 + 0x4*n`). `FPMLANTXBASE` is bits 23:0, in 512-byte units.
///
/// **Software-written, whatever the heading says.** The headings of the four
/// LAN base and count registers read RO; their field tables read RW; and
/// 38.26.3.1 is explicit -- *"Host software is responsible for setting up the
/// GLHMC_{object}CNT and GLHMC_{object}BASE registers for LAN objects"*, and
/// *"the FPM base of the first HMC object (GLHMC_LANTXBASE) for each PCI
/// function is always zero"*. The first version of this file called the receive
/// pair read-only and firmware-assigned, on the strength of the heading alone.
/// The prose is what corrected it, before any boot had to.
const GLHMC_LANTXBASE: u64 = 0x000C_6200;
/// FPM LAN Tx Queue Object Count -- 38.39.2.13.69, `GLHMC_LANTXCNT[n]`
/// (`0x000C6300 + 0x4*n`). `FPMLANTXCNT` is bits 10:0.
const GLHMC_LANTXCNT: u64 = 0x000C_6300;
/// FPM LAN Rx Queue Base -- 38.39.2.13.70, `GLHMC_LANRXBASE[n]`
/// (`0x000C6400 + 0x4*n`). `FPMLANRXBASE` is bits 23:0, and *"the value in this
/// register must be multiplied by 512 to get the actual address"* in the 8 GB
/// private memory space. See [`GLHMC_LANTXBASE`] for who writes it.
const GLHMC_LANRXBASE: u64 = 0x000C_6400;
/// FPM LAN Rx Queue Object Count -- 38.39.2.13.71, `GLHMC_LANRXCNT[n]`
/// (`0x000C6500 + 0x4*n`). `FPMLANRXCNT` is bits 10:0.
const GLHMC_LANRXCNT: u64 = 0x000C_6500;
/// Private Memory LAN Tx Object Size -- 38.39.2.13.12, `GLHMC_LANTXOBJSZ`
/// (`0x000C2004`, RO). Bits 3:0, *"decoded such that the value =
/// log2(ObjSize). 0x7 = 128 bytes."* Read rather than assumed, because a
/// context's address in private memory is computed from it -- 38.26.4:
/// `(GLHMC_{object}BASE*512) + (2^GLHMC_{object}OBJSZ * element_index)`.
const GLHMC_LANTXOBJSZ: u64 = 0x000C_2004;
/// Private Memory LAN Queue Maximum -- 38.39.2.13.13, `GLHMC_LANQMAX`
/// (`0x000C2008`, RO). Bits 10:0, init `0x600` = 1536.
const GLHMC_LANQMAX: u64 = 0x000C_2008;
/// Private Memory LAN Rx Object Size -- 38.39.2.13.14, `GLHMC_LANRXOBJSZ`
/// (`0x000C200C`, RO). Bits 3:0, `0x5` = 32 bytes.
const GLHMC_LANRXOBJSZ: u64 = 0x000C_200C;

/// Host Memory Cache Error Information -- 38.39.2.13.8, `PFHMC_ERRORINFO`
/// (`0x000C0400`, RW). Bit 31 is `ERROR_DETECTED`, bits 11:8 the error type,
/// bits 20:16 the object type and bits 4:0 the function. *"No subsequent errors
/// are recorded until this field is written with a value of 0b."* Read after
/// anything that touches private memory, because the HMC does not fault: it
/// records here and carries on.
const PFHMC_ERRORINFO: u64 = 0x000C_0400;
/// Host Memory Cache Error Data -- 38.39.2.13.9, `PFHMC_ERRORDATA`
/// (`0x000C0500`, RO): the queue, object index or SD/PD index an error names.
const PFHMC_ERRORDATA: u64 = 0x000C_0500;

/// PF Queue Allocation -- 38.39.2.18.16, `PFLAN_QALLOC` (`0x001C0400`, RO).
///
/// `FIRSTQ` bits 10:0, `LASTQ` bits 26:16, `VALID` bit 31: *"the first LAN
/// queue pair allocated to this PF"* and the last, in the device's absolute
/// numbering. 38.26.3 step 2 makes this the first thing a driver reads for its
/// LAN objects, because *"HMC PM LAN objects are indexed with the absolute
/// queue number"* -- so which queue this PF's queue 0 *is* comes from here,
/// and a driver that assumes zero has assumed which function it is.
const PFLAN_QALLOC: u64 = 0x001C_0400;
/// `PFLAN_QALLOC.VALID`, bit 31.
const QALLOC_VALID: u32 = 1 << 31;

/// Global RLAN Control 0 -- 38.39.2.18.15, `GLLAN_RCTL_0` (`0x0012A500`, RW1C).
///
/// Bit 0 is `PXE_MODE`, init 1: *"When this flag is set, the device fetches and
/// writes back a single descriptor at a time. During normal performance
/// operation, (non-PXE mode) this flag must be cleared."* Cleared by the Clear
/// PXE Mode admin command rather than by a write here -- 38.30.2.2.2 has
/// firmware disable the PXE queues first, which a bare write would skip.
const GLLAN_RCTL_0: u64 = 0x0012_A500;
/// `GLLAN_RCTL_0.PXE_MODE`, bit 0.
const PXE_MODE: u32 = 1 << 0;

/// VSI Queue Control -- 38.39.2.18.18, `VSILAN_QBASE[VSI]`
/// (`0x0020C800 + 0x4*VSI`, VSI = 0..383).
///
/// `VSIBASE` bits 10:0 is the VSI's first queue *"within the range of the PF
/// queues"*; bit 11, `VSIQTABLE_ENA`, selects a scattered set through
/// `VSILAN_QTABLE` instead. A received frame is steered to a VSI and the VSI to
/// a queue through this register, so which queue a frame lands in is decided
/// here and not by the queue -- which is why it is read before one is taken.
const VSILAN_QBASE: u64 = 0x0020_C800;
/// `VSILAN_QBASE.VSIQTABLE_ENA`, bit 11.
const VSI_QTABLE_ENABLED: u32 = 1 << 11;
/// The highest VSI index -- 38.39.2.18.18 gives `VSI = 0..383`.
const MAX_VSI: u64 = 383;

/// LAN Port Number -- 38.39.2.1.31, `PFGEN_PORTNUM` (`0x001C0480`, RO). Bits
/// 1:0, *"indicates the LAN port connected to this function"*. The statistics
/// registers below are indexed by it, and it is asked of the device rather
/// than inferred from the PCI function, for the same reason `PF_FUNC_RID` is.
const PFGEN_PORTNUM: u64 = 0x001C_0480;
/// The highest port index the statistics registers cover -- `n = 0..3`.
const MAX_PORT: u64 = 3;

/// Port statistics -- 38.39.2.16, all `0x8*n` apart for `n = 0..3`, all
/// **RW1C** rather than clear-on-read, so a reading is a running total since
/// power-on and only a *difference* between two readings means anything.
/// 38.30's initialisation flow says exactly that: a driver reads them at
/// start-up because *"the values of these counters is the baseline for any
/// statistics collected later"*.
///
/// The three packet counts are what answer whether this port receives at all.
/// `GLPRT_GORCL` is *good octets received*, and the four error and discard
/// counters below separate "nothing arrived" from "something arrived and was
/// thrown away", which is the distinction a silent receive queue cannot make
/// on its own.
///
/// **The `L`/`H` pairs are one 64-bit register.** The datasheet is explicit --
/// *"the low and high registers are part of a 64-bit register and are read
/// using 64-bit read accesses only"* -- which is why [`Device::read64`] exists
/// and why these name only the low offset.
const GLPRT_GORCL: u64 = 0x0030_0000;
/// 38.39.2.16.5, `GLPRT_CRCERRS[n]` (`0x00300080 + 0x8*n`): CRC errors. 32-bit.
const GLPRT_CRCERRS: u64 = 0x0030_0080;
/// 38.39.2.16.6, `GLPRT_RLEC[n]` (`0x003000A0 + 0x8*n`): length errors. 32-bit.
const GLPRT_RLEC: u64 = 0x0030_00A0;
/// 38.39.2.16.8, `GLPRT_RUC[n]` (`0x00300100 + 0x8*n`): undersize. 32-bit.
const GLPRT_RUC: u64 = 0x0030_0100;
/// 38.39.2.16.9, `GLPRT_ROC[n]` (`0x00300120 + 0x8*n`): oversize. 32-bit.
const GLPRT_ROC: u64 = 0x0030_0120;
/// 38.39.2.16.31, `GLPRT_UPRCL[n]` (`0x003005A0 + 0x8*n`): unicast received.
const GLPRT_UPRCL: u64 = 0x0030_05A0;
/// 38.39.2.16.33, `GLPRT_MPRCL[n]` (`0x003005C0 + 0x8*n`): multicast received.
const GLPRT_MPRCL: u64 = 0x0030_05C0;
/// 38.39.2.16.35, `GLPRT_BPRCL[n]` (`0x003005E0 + 0x8*n`): broadcast received.
const GLPRT_BPRCL: u64 = 0x0030_05E0;
/// 38.39.2.16.37, `GLPRT_RDPC[n]` (`0x00300600 + 0x8*n`): *"receive discarded
/// packets count"*. 32-bit. A port that receives and discards reads here.
const GLPRT_RDPC: u64 = 0x0030_0600;

/// Per-VSI statistics -- 38.39.2.16, `0x8*n` apart for `n = 0..383`.
///
/// **The index is not certainly the VSI number, and that is why these are
/// reported with a caveat rather than as fact.** The range is 384, which is
/// the number of VSIs, but 38.21.3.7.2 says the set to use *"is returned in
/// the Add VSI response buffer in the Statistic Counters field"* -- and this
/// driver did not add the VSI it is using, firmware did. So reading these at
/// the VSI's own number is an assumption. It is made because the reading is
/// free and informative if it holds, and the boot report says plainly that it
/// is an assumption so that nobody later reads it as a measurement.
const GLV_RDPC: u64 = 0x0031_0000;
/// 38.39.2.16.103, `GLV_UPRCL[n]` (`0x0036C000 + 0x8*n`).
const GLV_UPRCL: u64 = 0x0036_C000;
/// 38.39.2.16.105, `GLV_MPRCL[n]` (`0x0036CC00 + 0x8*n`).
const GLV_MPRCL: u64 = 0x0036_CC00;
/// 38.39.2.16.107, `GLV_BPRCL[n]` (`0x0036D800 + 0x8*n`).
const GLV_BPRCL: u64 = 0x0036_D800;

/// Global Transmit Queue Head -- 38.39.2.18.8, `QTX_HEAD[Q]`
/// (`0x000E4000 + 0x4*Q`). Cleared by software before a queue is enabled.
const QTX_HEAD: u64 = 0x000E_4000;

/// Global Transmit Pre Queue Disable -- 38.39.2.18.9, `GLLAN_TXPRE_QDIS[n]`
/// (`0x000E6500 + 0x4*n`, n = 0..11).
///
/// `QINDX` is bits 10:0 and takes the **absolute** queue index; bit 31 is
/// `CLEAR_QDIS`, *"setting this flag to 1b clears an internal QDIS flag of the
/// transmit queue... This step should be made before the queue is enabled."*
/// Each register covers 128 queues, so the register index is the queue divided
/// by 128 -- a detail with no equivalent anywhere on the receive side.
const GLLAN_TXPRE_QDIS: u64 = 0x000E_6500;
/// `GLLAN_TXPRE_QDIS.CLEAR_QDIS`, bit 31.
const TXPRE_CLEAR_QDIS: u32 = 1 << 31;
/// `GLLAN_TXPRE_QDIS.SET_QDIS`, bit 30 -- the disable direction, *"mutually
/// exclusive with the CLEAR_QDIS flag"*.
const TXPRE_SET_QDIS: u32 = 1 << 30;
/// How many queues one `GLLAN_TXPRE_QDIS` register covers.
const QDIS_QUEUES_PER_REGISTER: u32 = 128;

/// Global Transmit Queue Enable -- 38.39.2.18.10, `QTX_ENA[Q]`
/// (`0x00100000 + 0x4*Q`). The same three-bit handshake as `QRX_ENA`:
/// `QENA_REQ` bit 0, `FAST_QDIS` bit 1, `QENA_STAT` bit 2.
const QTX_ENA: u64 = 0x0010_0000;

/// Global Transmit Queue Control -- 38.39.2.18.11, `QTX_CTL[Q]`
/// (`0x00104000 + 0x4*Q`).
///
/// `PFVF_Q` bits 1:0 -- `10b` is a PF queue -- `PF_INDX` bits 5:2, and
/// `VFVM_INDX` bits 15:7 which *"should be set to zero"* for a PF's own queue.
/// This is what tells the device which function owns the queue, and it has no
/// counterpart on the receive side: a receive queue's owner is implied by the
/// VSI that steers to it, a transmit queue's is stated here.
const QTX_CTL: u64 = 0x0010_4000;
/// `QTX_CTL.PFVF_Q` = `10b`: this queue belongs to a PF.
const QTX_CTL_PF_QUEUE: u32 = 0b10;

/// Global Transmit Queue Tail -- 38.39.2.18.12, `QTX_TAIL[Q]`
/// (`0x00108000 + 0x4*Q`). The doorbell: the last valid descriptor plus one.
const QTX_TAIL: u64 = 0x0010_8000;

/// Station Address Low -- 38.39.2.5.6, `PRTPM_SAL[n]`
/// (`0x001E4440 + 0x20*n`, n = 0..3, RO): *"the lower 32 bits of the 48-bit
/// NVM pre-assigned Ethernet MAC address... defined in big endian (LS byte of
/// SAL is first on the wire)"*.
const PRTPM_SAL: u64 = 0x001E_4440;
/// Station Address High -- 38.39.2.5.7, `PRTPM_SAH[n]`
/// (`0x001E44C0 + 0x20*n`, n = 0..3, RO): the upper 16 bits, *"MS byte of
/// PRTPM_SAH is last on the wire"*. Bit 31 is `AV`, which the datasheet says
/// is set by firmware when the NVM supplies an address.
const PRTPM_SAH: u64 = 0x001E_44C0;
/// `PRTPM_SAH.AV`, bit 31 -- the address is valid.
const SAH_ADDRESS_VALID: u32 = 1 << 31;

/// Port transmit counters -- 38.39.2.16, the mirror of the receive set.
const GLPRT_GOTCL: u64 = 0x0030_0680;
/// 38.39.2.16.60, `GLPRT_UPTCL[n]`.
const GLPRT_UPTCL: u64 = 0x0030_09C0;
/// 38.39.2.16.62, `GLPRT_MPTCL[n]`.
const GLPRT_MPTCL: u64 = 0x0030_09E0;
/// 38.39.2.16.64, `GLPRT_BPTCL[n]`.
const GLPRT_BPTCL: u64 = 0x0030_0A00;

/// `Get VSI Parameters` -- Table 38-222, opcode `0x0212`: *"used to get the
/// parameters of an existing VSI"*, which is exactly this driver's position --
/// firmware created the VSI and this asks about it. Indirect, with a 128-byte
/// buffer whose layout is the Add VSI response buffer's.
const OPCODE_GET_VSI_PARAMETERS: u16 = 0x0212;
/// The VSI parameter buffer's length -- Table 38-222's `Datalen` of `0x80`.
pub const VSI_BUFFER_BYTES: u16 = 128;
/// Where that buffer sits in the page holding the admin rings, after the
/// switch buffer.
pub const VSI_BUFFER_OFFSET: u64 = SWITCH_BUFFER_OFFSET + SWITCH_BUFFER_BYTES as u64;
/// Where `QS_Handle 0` sits in the buffer -- Table 38-217: *"96-97 QS_Handle
/// 0... Bits [9:0] of this handle are used by software to program the RDYList
/// field in the transmit queues context"*.
const QS_HANDLE_AT: usize = 96;
const _: () = assert!(
    VSI_BUFFER_OFFSET + VSI_BUFFER_BYTES as u64 <= 4096,
    "the rings, the switch buffer and the VSI buffer must share one page"
);

/// One transmit data descriptor, in bytes -- Table 38-425 and 38.31.2.1.1.
/// Qword 0 is the packet buffer address; qword 1 carries the type, the command
/// and the length.
pub const TRANSMIT_DESCRIPTOR_BYTES: u64 = 16;

/// How many descriptors the transmit ring this driver builds holds.
///
/// `QLEN`'s floor is *"from 8 descriptors"* and this is that floor: the driver
/// sends one self-contained frame at a time and waits for it, so a longer ring
/// is a wrap-around nothing tests.
pub const TRANSMIT_DESCRIPTORS: u16 = 8;

/// And how many bytes that ring occupies.
///
/// **One number rather than two.** The depth and the size were computed in
/// different places, which is the shape of the bug that wrote a tail of eight
/// into an eight-descriptor ring; a caller that sizes its memory from here and
/// its depth from here cannot make the two disagree.
pub const TRANSMIT_RING_BYTES: u64 = TRANSMIT_DESCRIPTOR_BYTES * TRANSMIT_DESCRIPTORS as u64;
/// `DTYP`, qword 1 bits 3:0 -- *"0x0 stands for a transmit data descriptor"*.
const TX_DTYP_MASK: u64 = 0xf;
/// What `DTYP` reads once hardware has completed the descriptor:
/// *"completion is reported by setting the DTYP field to 0xF"*, which is the
/// path taken because `HEAD_WBEN` is cleared.
const TX_DTYP_DONE: u64 = 0xf;
/// `CMD.EOP`, CMD bit 0 at qword 1 bit 4 -- *"set in the last descriptor of a
/// packet"*.
const TX_CMD_EOP: u64 = 1 << 4;
/// `CMD.RS`, CMD bit 1 at qword 1 bit 5 -- *"when set, hardware reports the DMA
/// completion of the transmit descriptor and its data buffer"*. Without it
/// nothing is written back and a sender cannot tell that anything happened.
const TX_CMD_RS: u64 = 1 << 5;
/// `Tx Buffer Size`, qword 1 bits 47:34, fourteen bits of byte count.
const TX_BUFFER_SIZE_SHIFT: u32 = 34;
/// The smallest packet the device will send -- 38.31.2: *"the total size of a
/// single packet in host memory must be at least 17 bytes"*, and one outside
/// the range is *"considered malicious. The respective queue is stopped"*.
pub const TRANSMIT_MINIMUM_BYTES: usize = 17;

/// Receive Queue Interrupt Cause Control -- 38.39.2.9.27,
/// `QINT_RQCTL[Q] (0x0003A000 + 0x4*Q, Q=0...1535; RW)`.
///
/// **The register that decides whether a completed descriptor is ever reported,
/// and this driver never wrote it.** 38.22.5, *Write Back on Interrupts*, is
/// the rule: *"Following packet reception, the status of completed descriptors
/// are posted (write back) to host memory once every several packets or at ITR
/// expiration."* A queue in no interrupt linked list reaches neither trigger --
/// and the same section says so outright: *"Queues that should generate no
/// interrupts and should not be reported on ITR completion should not be
/// associated to any interrupt linked list."*
///
/// That is exactly what twenty boots of this driver did. The frames arrived,
/// the device wrote them into the buffers and advanced the queue's head, and
/// the descriptors were never posted back, so nothing above ever learned a
/// frame had come.
const QINT_RQCTL: u64 = 0x0003_A000;
/// `QINT_RQCTL.ITR_INDX`, bits 12:11: `00b` is ITR0.
///
/// **ITR0 rather than the `11b` "No ITR" this first tried**, and the difference
/// is the whole of it. 38.22.5 says completed descriptors are posted *"once
/// every several packets or at ITR expiration"* -- a queue with no ITR has no
/// expiry, so with four packets a minute it reaches neither trigger. Measured:
/// with `11b` here and `WB_ON_ITR` set and reading back, the SR550 still
/// reported nothing.
const QINT_ITR0: u32 = 0b00 << 11;
/// And `11b`, *"No ITR"*, named because it is the value deliberately not used.
#[cfg(test)]
const QINT_ITR_NONE: u32 = 0b11 << 11;
/// `QINT_RQCTL.NEXTQ_INDX`, bits 26:16 -- *"Setting the index to 0x7FF is a
/// NULL pointer indicating the end of the linked list."*
const QINT_NEXTQ_SHIFT: u32 = 16;
/// That NULL pointer, and the reason the reset value is not one: `QINT_RQCTL`
/// initialises to zero, which is `NEXTQ_INDX = 0` of type *receive* -- a list
/// whose end points at receive queue zero rather than at nothing.
const QINT_NEXTQ_NONE: u32 = 0x7ff;
/// `QINT_RQCTL.CAUSE_ENA`, bit 30: *"Enable interrupt by this queue. When this
/// bit is cleared, interrupts are not generated by the queue. The queue remains
/// in the interrupt linked list and is processed at ITR expiration."*
///
/// Left clear here on purpose: this driver wants the reporting, not the
/// interrupt, and the sentence above says the queue stays in the list either
/// way.
const QINT_CAUSE_ENA: u32 = 1 << 30;

/// PF Interrupt Zero Linked List -- 38.39.2.9.22, `PFINT_LNKLST0 (0x00038500;
/// RW)`: `FIRSTQ_INDX` at bits 10:0 and `FIRSTQ_TYPE` at 12:11, where `00b` is
/// *"Receive queues"*. Its reset value is `0x7FF`, *"an empty linked list"*.
const PFINT_LNKLST0: u64 = 0x0003_8500;

/// PF Interrupt Zero Dynamic Control -- 38.39.2.9.21, `PFINT_DYN_CTL0
/// (0x00038480; RW)`.
const PFINT_DYN_CTL0: u64 = 0x0003_8480;
/// `PFINT_DYN_CTL0.WB_ON_ITR`, bit 30 -- *"When this bit is set, completed
/// descriptors are indicated to host memory on ITR completion (**or No ITR**)
/// regardless of the interrupt enablement in this register."*
///
/// The parenthesis is the whole fix: with the queue's `ITR_INDX` set to *No
/// ITR*, there is no timer to wait for and a completed descriptor is reported
/// as soon as it completes. 38.22.5 names this arrangement -- a vector with
/// `WB_ON_ITR` set and `INTENA` clear -- as the way to have queues that report
/// completions and raise no interrupts.
const PFINT_WB_ON_ITR: u32 = 1 << 30;
/// PF Interrupt Throttling for Interrupt Zero -- 38.39.2.9.19, `PFINT_ITR0[n]
/// (0x00038000 + 0x80*n, n=0...2; RW)`: `INTERVAL` at bits 11:0, *"defined in
/// 2 us units"*, and *"Setting the INTERVAL to zero enables immediate
/// interrupt."*
///
/// Zero is what this driver writes: an ITR that expires at once is an ITR whose
/// expiry posts the completed descriptors immediately, and `WB_ON_ITR` with
/// `INTENA` clear means nothing is raised when it does.
const PFINT_ITR0: u64 = 0x0003_8000;

/// `PFINT_DYN_CTL0.INTENA`, bit 0, left clear: this driver polls.
///
/// Named though nothing writes it, because the test beside `report_completions`
/// asserts it stays clear -- a bit deliberately *not* set is worth naming, or
/// the next person to add one has nothing to check against.
#[cfg(test)]
const PFINT_INTENA: u32 = 1 << 0;

/// Global Receive Queue Tail -- 38.39.2.18.14, `QRX_TAIL[Q]`
/// (`0x00128000 + 0x4*Q`). `TAIL` bits 12:0: *"the first descriptor that
/// software hands to hardware (it is the last valid descriptor plus one)"*.
/// 38.30.3.1.1 adds that once PXE mode is cleared *"software should bump the
/// tail at the entire 8 x descriptors granularity"*.
const QRX_TAIL: u64 = 0x0012_8000;

/// Private Memory Space Segment Descriptor Command -- 38.39.2.13.4,
/// `PFHMC_SDCMD` (`0x000C0000`, RW). `PMSDIDX` bits 11:0 is the descriptor
/// index *relative to this function's `PMSDBASE`*, and bit 31 `PMSDWR` makes
/// it a write; *"the PFHMC_SDDATALOW and PFHMC_SDDATAHIGH registers must be
/// written before writing PFHMC_SDCMD"*. A write past `PMSDSIZE` *"is
/// dropped"*, silently, which is why every write here is read back.
const PFHMC_SDCMD: u64 = 0x000C_0000;
/// `PFHMC_SDCMD.PMSDWR`, bit 31.
const SD_WRITE: u32 = 1 << 31;
/// Segment Descriptor Data Low -- 38.39.2.13.5, `PFHMC_SDDATALOW`
/// (`0x000C0100`). Bit 0 `PMSDVALID`, bit 1 `PMSDTYPE` (0 paged, 1 direct),
/// bits 11:2 `PMSDBPCOUNT` -- *"every SD entry in a given FPM space must be
/// set to 512 except the last SD. The last SD can have a value from 1 to
/// 512"* -- and bits 31:12 the page descriptor page's address bits 31:12.
const PFHMC_SDDATALOW: u64 = 0x000C_0100;
/// Segment Descriptor Data High -- 38.39.2.13.6, `PFHMC_SDDATAHIGH`
/// (`0x000C0200`): *"most significant 32 bits of a segment descriptor"*.
const PFHMC_SDDATAHIGH: u64 = 0x000C_0200;
/// `PFHMC_SDDATALOW.PMSDVALID`, bit 0.
const SD_VALID: u32 = 1 << 0;

/// CMLAN Context Data -- 38.39.2.14.1, `PFCM_LANCTXDATA[n]`
/// (`0x0010C100 + 0x80*n`, n = 0..3): the four words of one 128-bit context
/// sub-line, *"word index 0 is the least significant word"*.
const PFCM_LANCTXDATA: u64 = 0x0010_C100;
/// CMLAN Context Control -- 38.39.2.14.2, `PFCM_LANCTXCTL` (`0x0010C300`):
/// `QUEUE_NUM` bits 11:0 (*"an absolute queue number"*), `SUB_LINE` 14:12,
/// `QUEUE_TYPE` 16:15 (00 a receive context), `OP_CODE` 18:17 (00 read, 01
/// write, 10 invalidate). The datasheet describes it as *"an interface into
/// the context cache for pre-boot context initialization"*; this driver uses
/// it only to **read**, which is the one way to see whether the HMC fetched
/// what was written into private memory rather than something else.
const PFCM_LANCTXCTL: u64 = 0x0010_C300;
/// CMLAN Context Status -- 38.39.2.14.3, `PFCM_LANCTXSTAT` (`0x0010C380`):
/// bit 0 `CTX_DONE`, bit 1 `CTX_MISS` -- *"the requested queue number was not
/// resident in the context cache"*.
const PFCM_LANCTXSTAT: u64 = 0x0010_C380;

/// `Clear PXE Mode` -- Table 38-402, opcode `0x0110`, a direct command the
/// datasheet marks *"operating system driver only"*. Firmware disables the two
/// PXE receive queues of every PF and clears `GLLAN_RCTL_0.PXE_MODE`; if the
/// flag was already clear it answers `EEXIST`, which is not a failure.
const OPCODE_CLEAR_PXE_MODE: u16 = 0x0110;
/// Table 38-403: *"0xD = EEXIST (no action, the device is already in non-PXE
/// mode)"*.
const RETURN_EEXIST: u16 = 0xd;

/// `Set VSI Promiscuous Modes` -- Table 38-253, opcode `0x0254`, direct. Bytes
/// 16-17 are the modes (bit 0 unicast, 1 multicast, 2 broadcast, 3 default
/// VSI, 4 VLAN), bytes 18-19 which of them this command changes, bytes 20-21
/// the VSI's SEID. The Add MAC, VLAN Pair command's own text sends broadcast
/// here: *"The Set VSI Promiscuous Modes command should be used if broadcast
/// forwarding without VLAN filtering is required"*.
const OPCODE_SET_VSI_PROMISCUOUS: u16 = 0x0254;
/// Table 38-253, modes bit 1: promiscuous multicast.
const PROMISCUOUS_MULTICAST: u16 = 1 << 1;
/// Table 38-253, modes bit 2: promiscuous broadcast.
const PROMISCUOUS_BROADCAST: u16 = 1 << 2;
/// `Add MAC, VLAN Pair` -- Table 38-237, opcode `0x0250`: *"used to add a set
/// of MAC or MAC, VLAN pairs to a set of VSIs"*. Indirect, with one 16-byte
/// entry per address.
///
/// **This is how an address a bridge would otherwise terminate is directed at
/// a VSI.** RFC 0073 step 1 uses it for `01:80:C2:00:00:02`, the LACP group
/// address, which arrives at this port four times a minute and reaches no
/// queue.
const OPCODE_ADD_MAC_VLAN: u16 = 0x0250;
/// One entry of the Add MAC, VLAN buffer -- Table 38-238.
const MAC_VLAN_ENTRY_BYTES: u16 = 16;
/// Table 38-238 flags bit 0: *"use perfect match"*.
const MAC_VLAN_PERFECT_MATCH: u16 = 1 << 0;
/// Table 38-238 flags bit 2: *"ignore VLAN -- if set, the VLAN tag is ignored
/// and the MAC address is used to forward packets from all VLANs"*. Required
/// on a trunk, where every frame worth having carries a tag.
const MAC_VLAN_IGNORE_VLAN: u16 = 1 << 2;

/// `Add Control Packet Filter` -- Table 38-261, opcode `0x025A`: *"used to add
/// a control filter to forward packets to a control VSI"*. Direct: every field
/// is in the descriptor.
///
/// **This is the command for link-local traffic, and `Add MAC, VLAN Pair` is
/// not.** The first attempt at RFC 0073 step 1 asked for the LACP group
/// address as an ordinary MAC filter and firmware answered `EINVAL`; the
/// datasheet says twice, in the control-VSI section and again under `Stop LLDP
/// Agent`, that a driver *"should request forwarding of the relevant packets
/// using the Add Control Packet Filter admin command"*. A reserved group
/// address is the bridge's own, and only this command takes it away.
const OPCODE_ADD_CONTROL_PACKET_FILTER: u16 = 0x025A;
/// Table 38-261 flags bit 0: *"ignore MAC. If set, forwarding is based only on
/// EtherType."* Which is what a protocol identified by its EtherType wants.
const CONTROL_FILTER_IGNORE_MAC: u16 = 1 << 0;

/// `Stop LLDP Agent` -- Table 38-390, opcode `0x0A05`, direct.
///
/// **This is how a driver takes the control port from firmware.** The
/// datasheet's control-VSI section says the MAC's control VSI *"is assigned to
/// the EMP"* at initialisation, and that a PF taking ownership means the EMP
/// *"should be notified of the change using Stop LLDP Agent command and should
/// disconnect the EMP control port"*. Stopping also *"directs all untagged
/// ingress LLDP frames received on the port to the default queue of the
/// control VSI"* -- which is the behaviour a control packet filter is supposed
/// to have and, on this machine, did not.
const OPCODE_STOP_LLDP_AGENT: u16 = 0x0A05;
/// `Stop LLDP Agent` byte 16 bit 0: 0 stops the agent, 1 shuts it down.
///
/// **Stop, not shutdown.** Shutdown *"sends a last LLDP PDU on the wire with
/// TTL = 0"*, which announces to the neighbour that this station is going
/// away -- a visible change to somebody else's network, on a live cluster
/// node, to answer a question about our own receive path. Stop is the
/// reversible half.
const LLDP_SHUTDOWN: u8 = 1 << 0;

/// `Update VSI` -- Table 38-220, opcode `0x0211`. Indirect, taking the same
/// 128-byte buffer `Get VSI Parameters` returns, so a change is made by
/// reading the VSI's own configuration, altering one bit and writing it back
/// rather than by asserting a whole configuration from nothing.
const OPCODE_UPDATE_VSI: u16 = 0x0211;
/// The VSI buffer's *Valid Sections* mask, bytes 0-1, bit 0: the switching
/// section is the one being written.
const VSI_SECTION_SWITCHING: u16 = 1 << 0;
/// The VSI buffer's *Valid Sections* bit for the **queue mapping** section.
///
/// **Bit 6, derived rather than recalled, and the derivation is checkable.**
/// The sections appear in the buffer in the order the mask's bits run --
/// switch, security, VLAN, cascaded PV, ingress UP, egress UP, queue mapping,
/// queueing option, outer UP, scheduler -- which is ten, and the SR550's own
/// VSI reads `valid_sections = 0x03ff`: exactly ten bits, all set. Queue
/// mapping is the seventh of them.
///
/// The boot that uses this is what confirms it: a mapping written with the
/// wrong bit is a mapping that reads back unchanged.
const VSI_SECTION_QUEUE_MAP: u16 = 1 << 6;
/// Where the queue mapping section starts in the buffer: the mapping flags,
/// then sixteen queue entries, then eight per-traffic-class entries.
///
/// Anchored on the two offsets this driver already had from the datasheet --
/// `QS_Handle 0` at 96 and the switching flags at 6 -- and corroborated on the
/// SR550 three ways: the statistics counter index at 112 read 12 for VSI 12,
/// the two user-priority tables at 16 and 20 read identical, and the scheduler
/// byte at 82 read 1 for a VSI with one traffic class.
const VSI_MAPPING_FLAGS_AT: usize = 28;
/// The first of sixteen queue entries.
const VSI_QUEUE_MAPPING_AT: usize = 30;
/// The first of eight traffic-class entries.
const VSI_TC_MAPPING_AT: usize = 62;
/// `mapping_flags`: zero for a contiguous range, one for a list.
const VSI_QUEUES_CONTIGUOUS: u16 = 0;
/// A traffic class's entry: bits 0-8 the queue offset, bits 9-11 **log2** of
/// how many queues -- so a field of 2 is four queues, not two.
const VSI_TC_QUEUES_SHIFT: u16 = 9;

/// Byte 6 bit 0 of the VSI buffer: *"allow the VSI to override the switching
/// decision and fix the destination of a transmit packet. This bit should be
/// set only for control ports."*
const VSI_ALLOW_DESTINATION_OVERRIDE: u8 = 1 << 0;
/// Where that byte sits in the buffer.
const VSI_SWITCHING_FLAGS_AT: usize = 6;

/// A LAN transmit **context** descriptor -- 38.31.2.2.1, `DTYP` `0x1`.
const TX_DTYP_CONTEXT: u64 = 0x1;
/// `SWTCH`, the Switch Control Tag, at CMD bits 5:4 -- descriptor qword 1 bits
/// 9:8. *"Can be set to non-zero only by control VSI as programmed by the
/// Allow Destination Override flag per VSI."*
const TX_SWTCH_SHIFT: u32 = 8;
/// `SWTCH` = `01b`: *"uplink packet. The packet is transmitted to the network
/// bypassing hardware filters."*
///
/// **What a control frame needs to reach the wire.** With no switch control
/// tag a frame is *"routed according to hardware filters"*, and the internal
/// switch consumes one addressed to a reserved group address rather than
/// sending it out -- which is exactly what forty-five LACPDUs did on
/// 2026-09-06, posted and completed and never counted out of the MAC.
pub const TX_SWTCH_UPLINK: u64 = 0b01;

/// The Slow Protocols EtherType -- IEEE 802.3 Clause 57. LACP rides on it, and
/// it is neither an L2 tag nor IP, which Table 38-261 requires.
pub const ETHERTYPE_SLOW_PROTOCOLS: u16 = 0x8809;

/// One promiscuous mode a VSI can be put into -- Table 38-253's flags.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PromiscuousMode {
    /// Every unicast address, not only this port's own.
    Unicast,
    /// Every multicast group.
    Multicast,
    /// Broadcast.
    Broadcast,
    /// *"Accept packets within the switch ID not matching any specific address
    /// to this VSI."* Refused for a VSI wired straight to the port.
    DefaultVsi,
    /// Every VLAN, which a trunk needs -- without it the others are scoped to
    /// one VLAN.
    AnyVlan,
}

impl PromiscuousMode {
    /// The flag bit, and the valid bit, for this mode.
    const fn bit(self) -> u16 {
        match self {
            Self::Unicast => PROMISCUOUS_UNICAST,
            Self::Multicast => PROMISCUOUS_MULTICAST,
            Self::Broadcast => PROMISCUOUS_BROADCAST,
            Self::DefaultVsi => PROMISCUOUS_DEFAULT_VSI,
            Self::AnyVlan => PROMISCUOUS_VLAN,
        }
    }

    /// What to call it in the boot report.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Unicast => "unicast",
            Self::Multicast => "multicast",
            Self::Broadcast => "broadcast",
            Self::DefaultVsi => "default VSI",
            Self::AnyVlan => "any VLAN",
        }
    }
}

/// Table 38-253, modes bit 0: promiscuous unicast.
const PROMISCUOUS_UNICAST: u16 = 1 << 0;
/// Table 38-253, modes bit 3: **Default VSI** -- *"accept packets within the
/// switch ID not matching any specific address to this VSI"*.
///
/// **The bridge's answer to "where does an unmatched frame go".** Every other
/// promiscuous flag widens what *this* VSI matches; this one claims the
/// traffic that matches nothing, which is where a frame goes when the internal
/// switch has no filter for it. Six mechanisms have been tried to get a frame
/// into a queue on the SR550 and this is the one that was never set.
const PROMISCUOUS_DEFAULT_VSI: u16 = 1 << 3;
/// Table 38-253, modes bit 4: promiscuous VLAN.
///
/// **The flag a trunk port needs.** Without it the unicast, multicast and
/// broadcast flags apply per-VLAN, so on a port carrying 802.1Q-tagged traffic
/// a VSI can be counted as receiving frames and still hand none to a queue.
/// The datasheet's note is the tell: *"if VSI is in promiscuous VLAN mode, the
/// VLAN ID should not be used"*, meaning that otherwise a VLAN ID is what the
/// other flags are scoped by.
const PROMISCUOUS_VLAN: u16 = 1 << 4;

/// Bytes one segment descriptor covers -- 38.26.1: *"each SD represents 2 MB
/// of HMC PM address space"*.
pub const SEGMENT_BYTES: u64 = 2 * 1024 * 1024;
/// The unit of the FPM base registers -- see [`GLHMC_LANRXBASE`].
const FPM_BASE_UNITS: u64 = 512;
/// A page descriptor's page: 4 KB, 512 to a segment -- 38.26.1.
pub const HMC_PAGE_BYTES: u64 = 4096;
/// Page descriptors per page -- Table 38-330's *"512 PDs that are 64-bit"*.
pub const PAGE_DESCRIPTORS: u32 = 512;

/// A receive descriptor -- Table 38-406, sixteen bytes: the packet buffer
/// address, then a header buffer address whose bit 0 must be zero because the
/// write-back reuses it for `DD`.
pub const RECEIVE_DESCRIPTOR_BYTES: u64 = 16;
/// Write-back status bit 0, `DD` -- Table 38-408: *"Descriptor done"*.
const RX_DD: u64 = 1 << 0;
/// Write-back status bit 1, `EOP` -- *"the last one of a packet"*.
const RX_EOP: u32 = 1 << 1;

/// The highest queue index `QRX_ENA` covers -- 38.39.2.18.13 gives `Q = 0..1535`.
const MAX_RECEIVE_QUEUE: u64 = 1535;

/// How much of BAR0 this module needs mapped.
///
/// **Coupled to the offsets above, and that coupling has bitten twice on the
/// same machine.** First the window was one page and `PFGEN_CTRL` at `0x92400`
/// faulted; the window went to a megabyte with a comment saying that covered
/// every offset "with room". Then `QRX_ENA` at `0x120000` was added and the
/// comment was not revisited, so the boot faulted at exactly that address.
///
/// A comment cannot enforce this and did not. The assertion below can: it fails
/// the build if any register this module names falls outside the window, so the
/// next offset added has to either fit or move this number.
///
/// **Sized to the datasheet now, not to the offsets.** The rules above Table
/// 38-599, *Structure of the PF Memory BAR*, say *"CSR space is located from
/// the beginning of the BAR until address (4 MB-64 KB-1)"*, and that is what is
/// mapped: every register this module could name is inside it, and what lies
/// beyond -- protocol-engine doorbells, an exposed flash -- is nothing this
/// driver should be able to reach by mistake. The assertions stay as the check
/// that no offset has strayed out of the space the datasheet defines.
pub const REGISTER_WINDOW_BYTES: u64 = 0x40_0000 - 0x1_0000;

const _: () = assert!(
    REGISTER_WINDOW_BYTES > VSILAN_QBASE + 4 * MAX_VSI,
    "the mapped register window must reach past the highest register this module uses"
);
const _: () = assert!(REGISTER_WINDOW_BYTES > QRX_ENA + 4 * MAX_RECEIVE_QUEUE);
const _: () = assert!(REGISTER_WINDOW_BYTES > PFLAN_QALLOC);
const _: () = assert!(REGISTER_WINDOW_BYTES > GLLAN_RCTL_0);
const _: () = assert!(REGISTER_WINDOW_BYTES > PFGEN_CTRL);
const _: () = assert!(REGISTER_WINDOW_BYTES > PF_ARQT);
const _: () = assert!(REGISTER_WINDOW_BYTES > GLHMC_LANRXCNT + 4 * 15);
const _: () = assert!(REGISTER_WINDOW_BYTES > PFHMC_ERRORDATA);
const _: () = assert!(REGISTER_WINDOW_BYTES > PF_FUNC_RID);
const _: () = assert!(REGISTER_WINDOW_BYTES > QRX_TAIL + 4 * MAX_RECEIVE_QUEUE);
const _: () = assert!(REGISTER_WINDOW_BYTES > PFCM_LANCTXSTAT);
const _: () = assert!(REGISTER_WINDOW_BYTES > PFHMC_SDDATAHIGH);
const _: () = assert!(REGISTER_WINDOW_BYTES > GLV_BPRCL + 8 * MAX_VSI);
const _: () = assert!(REGISTER_WINDOW_BYTES > GLPRT_RDPC + 8 * MAX_PORT);
const _: () = assert!(REGISTER_WINDOW_BYTES > PFGEN_PORTNUM);
const _: () = assert!(REGISTER_WINDOW_BYTES > QTX_TAIL + 4 * MAX_RECEIVE_QUEUE);
const _: () = assert!(REGISTER_WINDOW_BYTES > GLPRT_BPTCL + 8 * MAX_PORT);
const _: () = assert!(REGISTER_WINDOW_BYTES > PRTPM_SAH + 0x20 * MAX_PORT);
const _: () = assert!(REGISTER_WINDOW_BYTES > GLLAN_TXPRE_QDIS + 4 * 11);

/// One admin queue descriptor -- Table 38-339, as its eight little-endian
/// 32-bit words.
///
/// Table 38-340 names the bytes: flags at 0-1, opcode 2-3, `Datalen` 4-5,
/// return value 6-7, cookie 8-15, `Param0` 16-19, `Param1` 20-23, the data
/// address high at 24-27 and low at 28-31. A direct command's answer comes back
/// **in the same descriptor**, in whichever bytes its own table assigns, so
/// this is both the request and the reply, and the byte accessors are how a
/// reply is read.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Descriptor {
    /// The eight words, in the order the ring holds them.
    pub words: [u32; 8],
}

impl Descriptor {
    /// A direct command: an opcode and nothing else. The cookie stays zero
    /// because this driver waits for each command before posting the next, so
    /// there is never a completion to tell apart.
    #[must_use]
    pub const fn direct(opcode: u16) -> Self {
        let mut words = [0; 8];
        words[0] = (opcode as u32) << 16;
        Self { words }
    }

    /// A command with a buffer firmware fills: `Flags.BUF`, `Flags.LB` when
    /// the buffer is longer than [`AQ_LARGE_BUF`], the length in `Datalen`,
    /// and the buffer's address **as the device issues it** in bytes 24-31.
    #[must_use]
    pub const fn with_buffer(opcode: u16, address: u64, bytes: u16) -> Self {
        let mut this = Self::direct(opcode);
        let flags = if bytes > AQ_LARGE_BUF {
            FLAG_BUF | FLAG_LB
        } else {
            FLAG_BUF
        };
        this.words[0] |= flags as u32;
        this.words[1] = bytes as u32;
        this.words[6] = (address >> 32) as u32;
        this.words[7] = address as u32;
        this
    }

    /// The flags, bytes 0-1.
    #[must_use]
    pub const fn flags(&self) -> u16 {
        self.words[0] as u16
    }

    /// The return value, bytes 6-7 -- Table 38-350's code when `ERR` is set.
    #[must_use]
    pub const fn return_value(&self) -> u16 {
        (self.words[1] >> 16) as u16
    }

    /// One byte, by Table 38-340's numbering; zero past the end.
    #[must_use]
    pub const fn byte(&self, index: usize) -> u8 {
        if index >= DESCRIPTOR_BYTES as usize {
            return 0;
        }
        (self.words[index / 4] >> (8 * (index % 4))) as u8
    }

    /// Two bytes, little-endian, by the same numbering.
    #[must_use]
    pub const fn half(&self, index: usize) -> u16 {
        self.byte(index) as u16 | (self.byte(index + 1) as u16) << 8
    }
}

/// Why a command got no usable answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommandError {
    /// No ring is attached, so there is nowhere to post.
    NoRing,
    /// Firmware never set `DD` within the spins allowed.
    NoAnswer,
    /// Firmware completed it with `ERR` set; the payload is the return value,
    /// Table 38-350's code -- `0xD` is `EEXIST`, which Clear PXE Mode answers
    /// when the device was already out of PXE mode.
    Refused(u16),
    /// The buffer handed in is too small for what firmware will write into it.
    ///
    /// **A refusal rather than a truncation**, and the distinction is the whole
    /// reason this variant exists: reading a short buffer would report fields
    /// firmware never wrote, which is a wrong answer where this is a missing
    /// one. It cannot happen on a caller that sizes its buffer from the
    /// constants here, which is why it is a bug report and not a condition to
    /// handle.
    ShortBuffer,
}

impl core::fmt::Display for CommandError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoRing => f.write_str("no admin ring is attached"),
            Self::NoAnswer => f.write_str("firmware never marked it done"),
            Self::Refused(code) => write!(f, "firmware refused it, return value {code:#x}"),
            Self::ShortBuffer => f.write_str("the command buffer is too small for the answer"),
        }
    }
}

/// What `Get Link Status` answered -- Table 38-65, the fourteen bytes at
/// descriptor bytes 18-31, kept raw with the readings the report needs.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Link {
    /// Byte 18: the operating PHY type, by Table 38-65's list.
    pub phy_type: u8,
    /// Byte 19: one bit set -- bit 2 for 1000 Mb/s, bit 3 for 10 Gb/s.
    pub speed: u8,
    /// Byte 20: bit 0 link up, bits 1-4 faults, bit 5 the port's own link, bit
    /// 6 media available, bit 7 a receive signal detected.
    pub status: u8,
    /// Byte 21: bit 0 auto-negotiation completed, bit 1 the partner can.
    pub negotiation: u8,
    /// Bytes 24-25: *"maximum frame size set on this port"*.
    pub max_frame: u16,
}

impl Link {
    /// Table 38-65's reading of a completed descriptor.
    #[must_use]
    pub const fn from_descriptor(reply: &Descriptor) -> Self {
        Self {
            phy_type: reply.byte(18),
            speed: reply.byte(19),
            status: reply.byte(20),
            negotiation: reply.byte(21),
            max_frame: reply.half(24),
        }
    }

    /// Bit 2.0: *"Returns 1b if link status = up"*.
    #[must_use]
    pub const fn up(&self) -> bool {
        self.status & 1 != 0
    }

    /// Bit 2.1: the PHY reports a link fault.
    #[must_use]
    pub const fn faulted(&self) -> bool {
        self.status & (1 << 1) != 0
    }

    /// Bit 2.6: media plugged in and usable.
    #[must_use]
    pub const fn media_available(&self) -> bool {
        self.status & (1 << 6) != 0
    }

    /// Bit 2.7: the PHY or module sees a receive signal.
    #[must_use]
    pub const fn signal_detected(&self) -> bool {
        self.status & (1 << 7) != 0
    }

    /// The speed as Table 38-65 names it.
    #[must_use]
    pub const fn speed_name(&self) -> &'static str {
        match self.speed {
            0 => "no speed",
            0b100 => "1000 Mb/s",
            0b1000 => "10 Gb/s",
            _ => "a reserved speed code",
        }
    }

    /// The PHY type as Table 38-65 names it.
    #[must_use]
    pub const fn phy_name(&self) -> &'static str {
        match self.phy_type {
            0x1 => "1000BASE-KX",
            0x3 => "10GBASE-KR",
            0x7 => "SFI",
            0xb => "10GBASE-CR1",
            0xc => "SFP+ active direct attach",
            0xd => "QSFP+ active direct attach",
            0x12 => "1000BASE-T",
            0x13 => "10GBASE-T",
            0x14 => "10GBASE-SR",
            0x15 => "10GBASE-LR",
            0x16 => "10GBASE-SFP+ Cu",
            0x17 => "10GBASE-CR1 over QSFP+",
            _ => "an unlisted PHY type",
        }
    }
}

/// One element of the switch as `Get Switch Configuration` reports it --
/// Table 38-203, sixteen bytes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SwitchElement {
    /// Byte 0: the element type -- Tables 38-191 and 38-192: 1 a physical
    /// port's MAC, 2 a PF, 3 a VF, 4 the embedded processor, 19 a VSI.
    pub kind: u8,
    /// Bytes 2-3: this element's switch element id, which the admin commands
    /// that act on a VSI take.
    pub seid: u16,
    /// Bytes 4-5: the element below it, *"towards the network"*.
    pub uplink: u16,
    /// Bytes 6-7: the element above it, *"towards the host"*.
    pub downlink: u16,
    /// Byte 11: 1 a regular data port, 2 the default port, 3 a cascaded port
    /// virtualizer port.
    pub connection: u8,
    /// Bytes 14-15: the port number of a MAC, the function number of a PF or
    /// VF, and **the VSI number of a VSI** -- which is what `VSILAN_QBASE` is
    /// indexed by, and is not the SEID.
    pub number: u16,
}

impl SwitchElement {
    /// Table 38-201: sixteen bytes per element, after a sixteen-byte header.
    pub const BYTES: usize = 16;

    /// Table 38-203's reading of one element.
    #[must_use]
    pub const fn parse(bytes: &[u8; Self::BYTES]) -> Self {
        Self {
            kind: bytes[0],
            seid: u16::from_le_bytes([bytes[2], bytes[3]]),
            uplink: u16::from_le_bytes([bytes[4], bytes[5]]),
            downlink: u16::from_le_bytes([bytes[6], bytes[7]]),
            connection: bytes[11],
            number: u16::from_le_bytes([bytes[14], bytes[15]]),
        }
    }

    /// The element type by name.
    #[must_use]
    pub const fn kind_name(&self) -> &'static str {
        match self.kind {
            1 => "MAC",
            2 => "PF",
            3 => "VF",
            4 => "EMP",
            19 => "VSI",
            _ => "other",
        }
    }
}

/// What the switch holds, as far as the buffer had room for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SwitchConfiguration {
    /// The elements returned, in the order firmware listed them.
    pub elements: [SwitchElement; SWITCH_ELEMENTS_MAX],
    /// How many of `elements` are real -- Table 38-202's first field, clamped
    /// to what the buffer can hold rather than trusted.
    pub count: usize,
    /// How many the switch has in all, which may exceed `count`.
    pub total: u16,
}

impl SwitchConfiguration {
    /// Table 38-201's reading of the response buffer.
    #[must_use]
    pub fn parse(buffer: &[u8; SWITCH_BUFFER_BYTES as usize]) -> Self {
        let count =
            usize::from(u16::from_le_bytes([buffer[0], buffer[1]])).min(SWITCH_ELEMENTS_MAX);
        let total = u16::from_le_bytes([buffer[2], buffer[3]]);
        let mut elements = [SwitchElement::default(); SWITCH_ELEMENTS_MAX];
        for (index, element) in elements.iter_mut().enumerate().take(count) {
            let at = SwitchElement::BYTES * (index + 1);
            let mut bytes = [0; SwitchElement::BYTES];
            bytes.copy_from_slice(&buffer[at..at + SwitchElement::BYTES]);
            *element = SwitchElement::parse(&bytes);
        }
        Self {
            elements,
            count,
            total,
        }
    }

    /// The elements that are real.
    #[must_use]
    pub fn elements(&self) -> &[SwitchElement] {
        &self.elements[..self.count]
    }
}

/// What the private memory registers read for this function -- every input
/// 38.26.3 needs before an FPM layout can be computed, and whatever the last
/// owner left in the two pairs this driver will write.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PrivateMemory {
    /// `PF_FUNC_RID.FUNCTION_NUMBER`: which of the sixteen PF spaces is this.
    pub function: u32,
    /// `GLHMC_SDPART.PMSDBASE`: the first segment descriptor this function owns.
    pub sd_base: u32,
    /// `GLHMC_SDPART.PMSDSIZE`: how many it owns, at 2 MB each.
    pub sd_size: u32,
    /// `GLHMC_LANTXBASE`, in 512-byte units.
    pub tx_base: u32,
    /// `GLHMC_LANTXCNT`.
    pub tx_count: u32,
    /// `GLHMC_LANRXBASE`, in 512-byte units.
    pub rx_base: u32,
    /// `GLHMC_LANRXCNT`.
    pub rx_count: u32,
    /// `GLHMC_LANTXOBJSZ`: log2 of a transmit context's bytes.
    pub tx_object_size: u32,
    /// `GLHMC_LANRXOBJSZ`: log2 of a receive context's bytes.
    pub rx_object_size: u32,
    /// `GLHMC_LANQMAX`: the most LAN queues the HMC supports.
    pub queue_max: u32,
}

/// What `PFHMC_ERRORINFO` reports when its `ERROR_DETECTED` bit is set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HmcError {
    /// Bits 11:8, 38.39.2.13.8's list -- see [`HmcError::kind_name`].
    pub kind: u8,
    /// Bits 20:16 -- `0x10` a transmit context, `0x11` a receive context,
    /// `0x19` a page descriptor.
    pub object: u8,
    /// Bits 4:0, the function the error belongs to.
    pub function: u8,
    /// `PFHMC_ERRORDATA`, the index the error names.
    pub data: u32,
}

impl HmcError {
    /// The error type by name, from 38.39.2.13.8.
    #[must_use]
    pub const fn kind_name(&self) -> &'static str {
        match self.kind {
            0 => "private memory function not valid",
            3 => "invalid LAN queue index",
            4 => "object index larger than its count register",
            5 => "address beyond this function's segment descriptors",
            6 => "segment descriptor invalid",
            7 => "segment descriptor too small",
            8 => "page descriptor invalid",
            9 => "unsupported request on the object read",
            10 => "LAN queue not valid",
            11 => "invalid object type",
            _ => "an unlisted error type",
        }
    }
}

/// Where an object lives in private memory -- 38.26.4's decomposition of an
/// FPM address.
///
/// `FPM_object_address = (GLHMC_{object}BASE*512) + (2^GLHMC_{object}OBJSZ *
/// element_index)`, `SD_index = INT(FPM_object_address / 2 MB)`, `PD_index =
/// INT(FPM_object_address / 4 KB) and 0x1FF`, and what is left is the offset
/// in the backing page. `element_index` is the **absolute** queue number --
/// 38.26.3 step 5: *"HMC PM LAN objects are indexed with the absolute queue
/// number"*.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContextLocation {
    /// The private memory address itself.
    pub address: u64,
    /// Which 2 MB segment, relative to this function's first.
    pub segment: u32,
    /// Which of that segment's 512 page descriptors.
    pub page: u32,
    /// Where in that page the object starts.
    pub offset: u32,
}

/// 38.26.4's arithmetic for one object.
#[must_use]
pub const fn context_location(
    base_units: u32,
    object_size_log2: u32,
    index: u32,
) -> ContextLocation {
    let address = base_units as u64 * FPM_BASE_UNITS + (1u64 << object_size_log2) * index as u64;
    ContextLocation {
        address,
        segment: (address / SEGMENT_BYTES) as u32,
        page: ((address / HMC_PAGE_BYTES) % PAGE_DESCRIPTORS as u64) as u32,
        offset: (address % HMC_PAGE_BYTES) as u32,
    }
}

/// The receive base that follows a transmit area -- Table 38-337's example:
/// `GLHMC_LANRXBASE = ROUNDUP512((GLHMC_LANTXBASE*512) +
/// (GLHMC_LANTXCNT*2^GLHMC_LANTXOBJSZ)) / 512`.
#[must_use]
pub const fn receive_base_after(
    tx_base_units: u32,
    tx_count: u32,
    tx_object_size_log2: u32,
) -> u32 {
    let end =
        tx_base_units as u64 * FPM_BASE_UNITS + tx_count as u64 * (1u64 << tx_object_size_log2);
    end.div_ceil(FPM_BASE_UNITS) as u32
}

/// Where a LAN object area ends, in bytes of private memory.
#[must_use]
pub const fn object_area_end(base_units: u32, count: u32, object_size_log2: u32) -> u64 {
    base_units as u64 * FPM_BASE_UNITS + count as u64 * (1u64 << object_size_log2)
}

/// How many 4 KB pages an FPM layout ending at `end` spans -- what the last
/// segment descriptor's `PMSDBPCOUNT` states, *"used to calculate the end of
/// the FPM space"*.
#[must_use]
pub const fn backing_pages_to(end: u64) -> u32 {
    end.div_ceil(HMC_PAGE_BYTES) as u32
}

/// The static half of a LAN receive queue context -- Table 38-419, packed as
/// the eight little-endian dwords of the 32-byte vector the HMC reads.
///
/// Every position is from the table read as a page image, because its text
/// extraction dropped digits: BASE 32-88, QLEN 89-101, DBUFF 102-108, HBUFF
/// 109-113, DTYPE 114-115, DSIZE 116, CRCSTRIP 117, L2TSEL 119, HSPLIT_0
/// 120-123, HSPLIT_1 124-125, SHOWIV 127, RXMAX 174-187, the four TPH enables
/// 193-196, LRXQTRESH 198-200. Bits 0-31 are HEAD and CPUID, which hardware
/// owns and software initialises to zero.
///
/// **Two places the table and its own example disagree, and how each is
/// settled.** The table says BASE is *"defined in 12-byte units"*; the example
/// in 38.30.3.4.3 gives BASE = `0x1579A0` for a ring, and only in 128-byte
/// units does that decode to a page-aligned address (`0xABCD000`), so 128 is
/// what a ring's address is divided by here. And the example's dword 6 reads
/// `0x0000021E` with LRXQTRESH said to be 2: bits 193-196 are the four TPH
/// enables, and the one other set bit is 201, which the table lists as
/// reserved with a software init of `RSV` -- not bit 199, where a threshold of
/// 2 at 198-200 would land. The threshold is left at zero, where both readings
/// agree, and bit 201 is set because the datasheet's own example sets it. The
/// test below holds the encoder to that example bit for bit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReceiveContext {
    /// The descriptor ring's address as the device issues it, 128-byte aligned.
    pub ring: u64,
    /// Descriptors in the ring -- a whole multiple of 32 once PXE mode is off.
    pub descriptors: u16,
    /// Each packet buffer's size in bytes: at least 1 KB, a multiple of 128.
    pub buffer_bytes: u16,
    /// The largest frame accepted, *"starting at the L2 header up to including
    /// the Ethernet CRC"*, at most five buffers' worth.
    pub max_frame: u16,
}

impl ReceiveContext {
    /// The 32 bytes as the HMC reads them.
    #[must_use]
    pub const fn words(&self) -> [u32; 8] {
        let mut words = [0u32; 8];
        // BASE, bits 32-88, in 128-byte units.
        let base = self.ring / 128;
        words[1] = base as u32;
        words[2] = ((base >> 32) & 0x1ff_ffff) as u32;
        // QLEN, bits 89-101: seven bits at the top of dword 2, six at the
        // bottom of dword 3.
        let qlen = self.descriptors as u64 & 0x1fff;
        words[2] |= ((qlen & 0x7f) << 25) as u32;
        words[3] = ((qlen >> 7) & 0x3f) as u32;
        // DBUFF, bits 102-108, in 128-byte units. HBUFF and DTYPE stay zero:
        // no header split. DSIZE stays zero: 16-byte descriptors.
        let dbuff = (self.buffer_bytes / 128) as u32 & 0x7f;
        words[3] |= dbuff << 6;
        // CRCSTRIP, bit 117.
        words[3] |= 1 << 21;
        // RXMAX, bits 174-187.
        words[5] = ((self.max_frame as u32) & 0x3fff) << 14;
        // Bit 201, per the datasheet's own example -- see above.
        words[6] = 1 << 9;
        words
    }
}

/// The 4 KiB pages of BAR0 this driver can reach, as offsets from its base.
///
/// **The whole BAR cannot be delegated and should not be.** Its CSR space is
/// just under four megabytes -- a thousand pages -- against a capability space
/// of a hundred and twenty-eight slots, and a driver that could reach all of it
/// would hold the protocol-engine doorbells and an exposed flash it has no
/// business touching. These are the pages that contain a register this file
/// names, each one covering its indexed range to the maximum index the
/// datasheet allows, so a queue number this driver accepts can never land
/// outside the mapping.
///
/// Whoever delegates the device maps exactly these; a register outside them
/// faults instead of being reachable, which is strictly less authority than the
/// kernel had when it drove this itself. `page_is_mapped` and the test beside it
/// are what keep this list and the constants above from drifting apart.
pub const REGISTER_PAGES: [u64; 34] = [
    0x08_0000, 0x09_2000, 0x09_c000, 0x0c_0000, 0x0c_2000, 0x0c_6000, 0x0e_4000, 0x0e_5000,
    0x0e_6000, 0x10_0000, 0x10_1000, 0x10_2000, 0x10_4000, 0x10_5000, 0x10_6000, 0x10_8000,
    0x10_9000, 0x10_a000, 0x10_c000, 0x12_0000, 0x12_1000, 0x12_2000, 0x12_8000, 0x12_9000,
    0x12_a000, 0x1c_0000, 0x1e_4000, 0x20_c000, 0x20_d000, 0x30_0000, 0x31_0000, 0x36_c000,
    0x36_d000, 0x36_e000,
];

/// How many bytes a transmit queue context occupies -- Table 38-428's 128.
///
/// Named because a caller has to hand this function a slice of exactly that
/// much, and a length written at the call site is a length that can be wrong
/// there without anything noticing.
pub const TRANSMIT_CONTEXT_BYTES: usize = 128;

/// And a receive context's -- Table 38-419's 32.
pub const RECEIVE_CONTEXT_BYTES: usize = 32;

/// How large a page of registers is, which is the mapping granule as well.
pub const REGISTER_PAGE_BYTES: u64 = 4096;

/// Whether `offset` falls inside a page [`REGISTER_PAGES`] names.
#[must_use]
pub const fn page_is_mapped(offset: u64) -> bool {
    let page = offset & !(REGISTER_PAGE_BYTES - 1);
    let mut index = 0;
    while index < REGISTER_PAGES.len() {
        if REGISTER_PAGES[index] == page {
            return true;
        }
        index += 1;
    }
    false
}

/// A device's registers, without an address.
///
/// **This is what keeps the crate `forbid(unsafe_code)` honestly** rather than
/// by moving the driver somewhere the rule does not apply. A volatile access to
/// a mapping somebody else made is the one unsafe operation a NIC driver
/// genuinely needs, and it belongs to whoever owns that mapping; every offset
/// in this file is a documented register reached through here.
///
/// The same trait `ahci/src/lib.rs` defines for the same reason, with one
/// addition: [`Registers::read64`], because the statistics counters say *"the
/// low and high registers are part of a 64-bit register and are read using
/// 64-bit read accesses only"* and two 32-bit reads would also tear across a
/// counter incrementing between them.
pub trait Registers {
    /// Reads the 32-bit register at `offset`.
    fn read(&self, offset: u64) -> u32;
    /// Writes the 32-bit register at `offset`.
    fn write(&mut self, offset: u64, value: u32);
    /// Reads the 64-bit register pair at `offset` in one access.
    fn read64(&self, offset: u64) -> u64;
}

/// Memory a device also writes, without an address.
///
/// **The second thing this crate must not hold, and the reason is a boot that
/// went wrong.** Rings and command buffers were `&mut [u8]` at first, which
/// reads as the obvious translation of a raw pointer. It is not: a `&mut`
/// promises the compiler that *nothing else* writes those bytes, and a device
/// writing them is exactly something else. `Get Switch Configuration` zeroed
/// its buffer, ran the command, and read the buffer back — and on the SR550 it
/// read back the zeroes, because forwarding them is a legal thing to do to
/// memory nobody else may touch. The switch reported nought elements of nought
/// and the receive queue was never taken.
///
/// So DMA memory goes through a trait, like [`Registers`] and for the same
/// reason: the access belongs to whoever owns the mapping, who can make it
/// volatile. This crate does the arithmetic and holds no address at all.
pub trait Dma {
    /// Copies `into.len()` bytes from `at` into `into`.
    ///
    /// Bytes past the end of the region read as zero, which is what an
    /// unwritten descriptor looks like and the answer a caller can act on.
    fn read(&self, at: usize, into: &mut [u8]);

    /// Copies `from` to `at`, ignoring anything past the end of the region.
    fn write(&mut self, at: usize, from: &[u8]);

    /// Zeroes `bytes` bytes at `at`.
    fn zero(&mut self, at: usize, bytes: usize);
}

/// Reads a little-endian `u32` out of DMA memory.
fn dma32(from: &impl Dma, at: usize) -> u32 {
    let mut bytes = [0u8; 4];
    from.read(at, &mut bytes);
    u32::from_le_bytes(bytes)
}

/// Reads a little-endian `u64` out of DMA memory.
fn dma64(from: &impl Dma, at: usize) -> u64 {
    let mut bytes = [0u8; 8];
    from.read(at, &mut bytes);
    u64::from_le_bytes(bytes)
}

/// Writes a little-endian `u32` into DMA memory.
fn put_dma32(into: &mut impl Dma, at: usize, value: u32) {
    into.write(at, &value.to_le_bytes());
}

/// Writes a little-endian `u64` into DMA memory.
fn put_dma64(into: &mut impl Dma, at: usize, value: u64) {
    into.write(at, &value.to_le_bytes());
}

/// A page descriptor -- Table 38-330: bits 63:12 the backing page's address
/// as the device issues it, bit 0 valid.
#[must_use]
pub const fn page_descriptor(backing: u64) -> u64 {
    (backing & !(HMC_PAGE_BYTES - 1)) | 1
}

/// What a segment descriptor reads as, `(low, high)`, for a paged segment
/// whose page descriptor page is at `pd_page` and whose FPM space spans
/// `backing_pages` -- 38.26.4 step 6 and 38.39.2.13.5's fields.
#[must_use]
pub const fn segment_descriptor(pd_page: u64, backing_pages: u32) -> (u32, u32) {
    (
        (pd_page as u32 & 0xffff_f000) | ((backing_pages & 0x3ff) << 2) | SD_VALID,
        (pd_page >> 32) as u32,
    )
}

/// Writes one page descriptor into a page descriptor page.
///
/// `page` is that page, `index` below [`PAGE_DESCRIPTORS`], and the device must
/// not be fetching it yet -- which the caller arranges by writing every
/// descriptor before naming the page to the device.
pub fn write_page_descriptor(page: &mut impl Dma, index: u32, backing: u64) {
    put_dma64(page, 8 * index as usize, page_descriptor(backing));
}

/// Writes a receive context where the HMC will fetch it.
///
/// `at` is the context's 32 bytes inside a backing page, and the device must
/// not be fetching it yet.
pub fn write_receive_context(at: &mut impl Dma, offset: usize, context: &ReceiveContext) {
    for (index, word) in context.words().iter().enumerate() {
        put_dma32(at, offset + 4 * index, *word);
    }
}

/// Writes a transmit context where the HMC will fetch it.
///
/// `at` is the context's 128 bytes inside a backing page, and the device must
/// not be fetching it yet.
pub fn write_transmit_context(at: &mut impl Dma, offset: usize, context: &TransmitContext) {
    for (index, word) in context.words().iter().enumerate() {
        put_dma32(at, offset + 4 * index, *word);
    }
}

/// The bytes an ARP frame this driver builds occupies, padded to Ethernet's
/// own minimum before the CRC the device appends.
pub const FRAME_BYTES: usize = 60;
const _: () = assert!(FRAME_BYTES >= TRANSMIT_MINIMUM_BYTES);

/// The transmit packet buffer this driver hands the device.
///
/// Large enough for the biggest frame it builds -- a tagged DHCP `DISCOVER` is
/// a little over three hundred bytes -- and still one page.
pub const PACKET_BYTES: usize = 1024;
const _: () = assert!(PACKET_BYTES >= FRAME_BYTES);

/// Posts receive descriptors, one per buffer, from descriptor zero -- Table
/// 38-406: the packet buffer address, and a header address left zero because
/// the queue does no header split and bit 0 must stay clear for `DD`.
///
/// `ring` must hold at least `buffers.len()` descriptors, and the queue must
/// not be enabled while this runs.
pub fn post_receive_descriptors(ring: &mut impl Dma, buffers: &[u64]) {
    for (index, buffer) in buffers.iter().enumerate() {
        let at = RECEIVE_DESCRIPTOR_BYTES as usize * index;
        put_dma64(ring, at, *buffer);
        put_dma64(ring, at + 8, 0);
    }
}

/// What hardware wrote back into a receive descriptor -- the 16-byte
/// write-back's second quad-word once `DD` is set: status bits 18:0 (Table
/// 38-408), error bits 26:19 (Table 38-409), packet type 37:30 (Table
/// 38-412), length 63:38 with `PKTL` in its low fourteen bits (Table 38-411).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReceiveCompletion {
    /// Table 38-408's nineteen status bits.
    pub status: u32,
    /// Table 38-409's eight error bits; bit 0 `RXE` is a MAC error.
    pub error: u8,
    /// Table 38-412's packet type -- 11 is `MAC, ARP`, 1 is `MAC, PAY2`.
    pub packet_type: u8,
    /// `PKTL`: bytes in the packet buffer.
    pub length: u16,
}

impl ReceiveCompletion {
    /// The write-back's second quad-word, decoded.
    #[must_use]
    pub const fn decode(qword: u64) -> Self {
        Self {
            status: (qword & 0x7_ffff) as u32,
            error: ((qword >> 19) & 0xff) as u8,
            packet_type: ((qword >> 30) & 0xff) as u8,
            length: ((qword >> 38) & 0x3fff) as u16,
        }
    }

    /// `EOP`: the whole packet is in this descriptor's buffer.
    #[must_use]
    pub const fn end_of_packet(&self) -> bool {
        self.status & RX_EOP != 0
    }

    /// `UMBCAST`, status bits 10:9, as Table 38-408 names the four values.
    #[must_use]
    pub const fn cast_name(&self) -> &'static str {
        match (self.status >> 9) & 0b11 {
            0 => "unicast",
            1 => "multicast",
            2 => "broadcast",
            _ => "mirrored",
        }
    }

    /// `RXE`: *"CRC, alignment, oversize, undersize, or length error"*.
    #[must_use]
    pub const fn mac_error(&self) -> bool {
        self.error & 1 != 0
    }
}

/// Writes one receive descriptor at `index`, giving the device a buffer again.
///
/// **A ring that is never refilled receives exactly as many frames as it was
/// posted and then stops**, because the head reaches the tail and the device
/// has nowhere to put the next one. [`post_receive_descriptors`] fills a ring
/// from descriptor zero, which is what bring-up wants; this is what a driver
/// wants afterwards, when the frames it has taken are the ones to hand back.
///
/// Table 38-406's read format: the packet buffer address, and a header address
/// left zero because the queue does no header split and bit 0 must stay clear
/// for `DD`. Writing the whole descriptor is what clears the write-back
/// hardware left there, so a stale `DD` cannot read as a new frame.
pub fn post_receive_descriptor(ring: &mut impl Dma, index: u32, buffer: u64) {
    let at = RECEIVE_DESCRIPTOR_BYTES as usize * index as usize;
    put_dma64(ring, at, buffer);
    put_dma64(ring, at + 8, 0);
}

/// Reads a receive descriptor's write-back, if hardware has completed it.
///
/// `ring` as [`post_receive_descriptors`], and `index` inside it.
#[must_use]
pub fn completed_descriptor(ring: &impl Dma, index: u32) -> Option<ReceiveCompletion> {
    let at = RECEIVE_DESCRIPTOR_BYTES as usize * index as usize + 8;
    // The second quad-word, which hardware writes back.
    let qword = dma64(ring, at);
    if qword & RX_DD == 0 {
        return None;
    }
    Some(ReceiveCompletion::decode(qword))
}

/// An Ethernet header, as far as the boot report needs one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameHeader {
    /// The destination address.
    pub destination: [u8; 6],
    /// The source address.
    pub source: [u8; 6],
    /// The EtherType -- the one behind the tag, if there is an 802.1Q tag.
    pub ethertype: u16,
    /// The 802.1Q tag control field, if the frame carried one.
    pub vlan: Option<u16>,
}

impl FrameHeader {
    /// How many bytes [`FrameHeader::parse`] looks at.
    pub const BYTES: usize = 18;

    /// The first eighteen bytes of a frame: destination, source, and the
    /// EtherType -- or, at `0x8100`, the tag and the EtherType behind it.
    #[must_use]
    pub fn parse(bytes: &[u8; Self::BYTES]) -> Self {
        let mut destination = [0; 6];
        destination.copy_from_slice(&bytes[0..6]);
        let mut source = [0; 6];
        source.copy_from_slice(&bytes[6..12]);
        let first = u16::from_be_bytes([bytes[12], bytes[13]]);
        if first == 0x8100 {
            Self {
                destination,
                source,
                ethertype: u16::from_be_bytes([bytes[16], bytes[17]]),
                vlan: Some(u16::from_be_bytes([bytes[14], bytes[15]])),
            }
        } else {
            Self {
                destination,
                source,
                ethertype: first,
                vlan: None,
            }
        }
    }

    /// The EtherType by name, for the few the report is likely to meet.
    #[must_use]
    pub const fn ethertype_name(&self) -> &'static str {
        match self.ethertype {
            0x0800 => "IPv4",
            0x0806 => "ARP",
            0x86dd => "IPv6",
            0x88cc => "LLDP",
            0x8809 => "slow protocols",
            0x0000..=0x05ff => "an 802.3 length",
            _ => "other",
        }
    }
}

/// Copies a frame's first eighteen bytes out of a buffer hardware filled.
///
/// `buffer` must be at least [`FrameHeader::BYTES`] long and hardware must have
/// finished writing it. A shorter one reads as zeroes, which parses as a frame
/// with no ethertype -- the same answer a caller would get from an empty
/// buffer, and the one it can act on.
#[must_use]
pub fn frame_header(buffer: &impl Dma, at: usize) -> FrameHeader {
    let mut bytes = [0u8; FrameHeader::BYTES];
    buffer.read(at, &mut bytes);
    FrameHeader::parse(&bytes)
}

/// What a port's receive counters read at one instant.
///
/// Every field is a running total since power-on, not a rate and not a count
/// for this boot: the registers are `RW1C` and nothing here clears them, so
/// firmware's own use of the port before this kernel started is included. Two
/// readings and [`PortCounters::since`] are what mean anything.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PortCounters {
    /// `GLPRT_UPRCL/H`: unicast packets received.
    pub unicast: u64,
    /// `GLPRT_MPRCL/H`: multicast packets received.
    pub multicast: u64,
    /// `GLPRT_BPRCL/H`: broadcast packets received.
    pub broadcast: u64,
    /// `GLPRT_GORCL/H`: good octets received.
    pub octets: u64,
    /// `GLPRT_RDPC`: packets the port received and discarded.
    pub discarded: u32,
    /// `GLPRT_CRCERRS`: CRC errors.
    pub crc_errors: u32,
    /// `GLPRT_RLEC`: length errors.
    pub length_errors: u32,
    /// `GLPRT_RUC`: undersize packets.
    pub undersize: u32,
    /// `GLPRT_ROC`: oversize packets.
    pub oversize: u32,
}

impl PortCounters {
    /// What arrived between an earlier reading and this one.
    ///
    /// Saturating, so a counter that wrapped or a baseline taken after the
    /// later reading yields zero rather than an enormous number. A wrap is not
    /// a real risk over a minute on these widths; a mistake in the order of
    /// two readings is, and this makes it read as "nothing" instead of as a
    /// flood.
    #[must_use]
    pub const fn since(&self, baseline: &Self) -> Self {
        Self {
            unicast: self.unicast.saturating_sub(baseline.unicast),
            multicast: self.multicast.saturating_sub(baseline.multicast),
            broadcast: self.broadcast.saturating_sub(baseline.broadcast),
            octets: self.octets.saturating_sub(baseline.octets),
            discarded: self.discarded.saturating_sub(baseline.discarded),
            crc_errors: self.crc_errors.saturating_sub(baseline.crc_errors),
            length_errors: self.length_errors.saturating_sub(baseline.length_errors),
            undersize: self.undersize.saturating_sub(baseline.undersize),
            oversize: self.oversize.saturating_sub(baseline.oversize),
        }
    }

    /// Packets the port took in, of any address kind.
    #[must_use]
    pub const fn packets(&self) -> u64 {
        self.unicast + self.multicast + self.broadcast
    }

    /// Whether anything at all was seen -- a packet, a discard, or an error.
    ///
    /// The question a silent receive queue needs answered is not *"did a good
    /// frame arrive"* but *"did this port see anything"*, so a discard and a
    /// CRC error count as evidence of a live wire just as a packet does.
    #[must_use]
    pub const fn saw_anything(&self) -> bool {
        self.packets() > 0
            || self.discarded > 0
            || self.crc_errors > 0
            || self.length_errors > 0
            || self.undersize > 0
            || self.oversize > 0
    }
}

/// What a VSI's receive counters read, at an index this driver assumes.
///
/// See [`GLV_RDPC`]: the statistics set is assigned when a VSI is added, and
/// this driver did not add the VSI it uses. Read at the VSI's own number, and
/// reported as an assumption.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VsiCounters {
    /// `GLV_UPRCL/H`: unicast packets received by the VSI.
    pub unicast: u64,
    /// `GLV_MPRCL/H`: multicast packets received by the VSI.
    pub multicast: u64,
    /// `GLV_BPRCL/H`: broadcast packets received by the VSI.
    pub broadcast: u64,
    /// `GLV_RDPC`: packets the VSI received and discarded.
    pub discarded: u32,
}

impl VsiCounters {
    /// What arrived between an earlier reading and this one, saturating.
    #[must_use]
    pub const fn since(&self, baseline: &Self) -> Self {
        Self {
            unicast: self.unicast.saturating_sub(baseline.unicast),
            multicast: self.multicast.saturating_sub(baseline.multicast),
            broadcast: self.broadcast.saturating_sub(baseline.broadcast),
            discarded: self.discarded.saturating_sub(baseline.discarded),
        }
    }

    /// Packets the VSI took in, of any address kind.
    #[must_use]
    pub const fn packets(&self) -> u64 {
        self.unicast + self.multicast + self.broadcast
    }
}

/// The static half of a LAN transmit queue context -- Table 38-428, packed as
/// the thirty-two little-endian dwords of the 128-byte object
/// `GLHMC_LANTXOBJSZ` describes. Eight "lines" of 128 bits each.
///
/// **Only the fields the table marks `Static` are written, and everything else
/// is left zero**, including the bits it calls `Internal`. `New_Context` is
/// what makes that safe: the table's own note says it *"should be set to 1b by
/// software at queue context programming"*, which is the device being told
/// this is a fresh context rather than an edit of one it is already running.
///
/// **The datasheet's worked example contradicts itself here, and the reading
/// taken is the field table's.** 38.31.3.4.3 prints Line 7 as `FFFFFFFF
/// 480FFFFF 00000000 00000000` and then says `RDYList = 0x80 (128)`. Placed at
/// the table's bits 84-93 those two cannot both be true: the hex puts zero
/// there. Reading the line's internal bits as ones and `RDYList` as `0x80`
/// reproduces `0x080FFFFF` for its third dword, which is the printed
/// `0x480FFFFF` short of one bit -- so the legend is coherent and the hex is
/// not quite. The field table wins, `RDYList` goes at bits 84-93, and the
/// internal bits stay zero because the table's own `SW Init` column says
/// `0x0`. Written down because a reader who checks the example will find the
/// same contradiction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransmitContext {
    /// The descriptor ring's address as the device issues it. Table 38-428
    /// says `BASE` is *"defined in 128-byte units"* -- in so many words, which
    /// is the same unit the receive table only implied through its example.
    pub ring: u64,
    /// `QLEN`: descriptors in the ring, *"from 8 descriptors up to 8 KB-32"*,
    /// a whole multiple of 8 below 32 and of 32 above it.
    pub descriptors: u16,
    /// `RDYList`: the transmit arbitration queue set. Firmware owns the
    /// allocation -- *"allocation of queue sets to VSIs is managed by
    /// firmware"* -- and hands the value out as a VSI's `QS_Handle`, which is
    /// why this cannot be invented and [`Device::vsi_parameters`] exists.
    pub ready_list: u16,
}

impl TransmitContext {
    /// How many dwords the context occupies -- 128 bytes.
    pub const WORDS: usize = 32;
    /// Dwords per 128-bit line.
    const LINE: usize = 4;

    /// The 128 bytes as the HMC reads them.
    #[must_use]
    pub const fn words(&self) -> [u32; Self::WORDS] {
        let mut words = [0u32; Self::WORDS];
        // Line 0: New_Context at bit 30, BASE at bits 32-88.
        words[0] = 1 << 30;
        let base = self.ring / 128;
        words[1] = base as u32;
        words[2] = ((base >> 32) & 0x01ff_ffff) as u32;
        // Line 1: HEAD_WBEN at bit 32 stays clear -- descriptor write-back,
        // not head write-back, so a completed descriptor is what says so and
        // no separate write-back address is needed. QLEN at bits 33-45.
        words[Self::LINE + 1] = ((self.descriptors as u32) & 0x1fff) << 1;
        // Line 7: RDYList at bits 84-93, which is the third dword of the line
        // at its bits 20-29.
        words[7 * Self::LINE + 2] = ((self.ready_list as u32) & 0x3ff) << 20;
        words
    }
}

/// A transmit data descriptor -- 38.31.2.1.1, as its two quad-words.
///
/// `EOP` and `RS` are always both set here because this driver sends one
/// self-contained packet at a time and wants to be told it happened: without
/// `RS` *"hardware reports"* nothing, and a sender that cannot see a
/// completion is back to claiming rather than knowing.
#[must_use]
pub const fn transmit_descriptor(buffer: u64, bytes: u16) -> (u64, u64) {
    let length = (bytes as u64) << TX_BUFFER_SIZE_SHIFT;
    // DTYP is 0 for a data descriptor, so it is left out rather than written.
    (buffer, TX_CMD_EOP | TX_CMD_RS | length)
}

/// A transmit context descriptor carrying a switch control tag.
///
/// Qword 0 is entirely reserved for what this uses it for; qword 1 carries the
/// type and the tag. It precedes the data descriptor it applies to, and the
/// context *"is lost"* after that packet, so one is posted per frame.
#[must_use]
pub const fn transmit_context_descriptor(switch_tag: u64) -> (u64, u64) {
    (0, TX_DTYP_CONTEXT | (switch_tag & 0b11) << TX_SWTCH_SHIFT)
}

/// Writes a transmit context descriptor into a ring.
///
/// As [`post_transmit_descriptor`].
pub fn post_transmit_context(ring: &mut impl Dma, index: u32, switch_tag: u64) {
    let (low, high) = transmit_context_descriptor(switch_tag);
    let at = TRANSMIT_DESCRIPTOR_BYTES as usize * index as usize;
    put_dma64(ring, at, low);
    put_dma64(ring, at + 8, high);
}

/// Whether hardware has completed a transmit descriptor -- its `DTYP` field
/// reading `0xF`.
///
/// `ring` is the transmit ring and `index` inside it.
#[must_use]
pub fn transmit_completed(ring: &impl Dma, index: u32) -> bool {
    let at = TRANSMIT_DESCRIPTOR_BYTES as usize * index as usize + 8;
    // The second quad-word, which hardware rewrites.
    dma64(ring, at) & TX_DTYP_MASK == TX_DTYP_DONE
}

/// Writes one transmit descriptor into a ring.
///
/// As [`transmit_completed`], and the queue must not be running past `index`.
pub fn post_transmit_descriptor(ring: &mut impl Dma, index: u32, buffer: u64, bytes: u16) {
    let (low, high) = transmit_descriptor(buffer, bytes);
    let at = TRANSMIT_DESCRIPTOR_BYTES as usize * index as usize;
    put_dma64(ring, at, low);
    put_dma64(ring, at + 8, high);
}

/// What `Get VSI Parameters` reported about an existing VSI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VsiParameters {
    /// The VSI number firmware assigned, from the descriptor's bytes 18-19.
    pub number: u16,
    /// **The whole context, because two bytes of it were being read and the
    /// question is about the rest.**
    ///
    /// Port counters count frames, the VSI counter counts frames, and no
    /// receive queue has ever taken one -- so what steers a frame from a VSI to
    /// a queue is the thing that has never been looked at, and it lives in this
    /// buffer. It is carried whole rather than parsed into fields here because
    /// the fields to name are the ones a boot is about to identify: the project
    /// has learned twice that when a hardware question resists, the answer is
    /// to print what the machine already holds before something overwrites it.
    pub context: [u8; VSI_BUFFER_BYTES as usize],
    /// `QS_Handle 0`, the queue set for traffic class 0. Its bits 9:0 are the
    /// `RDYList` a transmit context needs.
    pub queue_set: u16,
}

impl Default for VsiParameters {
    fn default() -> Self {
        Self {
            number: 0,
            queue_set: 0,
            context: [0; VSI_BUFFER_BYTES as usize],
        }
    }
}

/// A port's transmit counters, the mirror of [`PortCounters`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TransmitCounters {
    /// `GLPRT_UPTCL/H`: unicast packets transmitted.
    pub unicast: u64,
    /// `GLPRT_MPTCL/H`: multicast packets transmitted.
    pub multicast: u64,
    /// `GLPRT_BPTCL/H`: broadcast packets transmitted.
    pub broadcast: u64,
    /// `GLPRT_GOTCL/H`: good octets transmitted.
    pub octets: u64,
}

impl TransmitCounters {
    /// What left between an earlier reading and this one, saturating.
    #[must_use]
    pub const fn since(&self, baseline: &Self) -> Self {
        Self {
            unicast: self.unicast.saturating_sub(baseline.unicast),
            multicast: self.multicast.saturating_sub(baseline.multicast),
            broadcast: self.broadcast.saturating_sub(baseline.broadcast),
            octets: self.octets.saturating_sub(baseline.octets),
        }
    }

    /// Packets the port put on the wire, of any address kind.
    #[must_use]
    pub const fn packets(&self) -> u64 {
        self.unicast + self.multicast + self.broadcast
    }
}

/// One mapped X722 function, far enough along to be asked questions.
pub struct Device<R: Registers> {
    /// The registers, reached through the trait rather than an address.
    registers: R,
    /// Whether [`Device::enable_admin_queues`] has run, so a command posted
    /// before it is refused rather than written into a ring the device is not
    /// reading.
    ring_enabled: bool,
    /// How many descriptors that ring holds.
    transmit_depth: u32,
    /// The next free descriptor in it.
    ///
    /// **One cursor, owned here, because two callers doing this arithmetic
    /// separately got it wrong.** A loop that restarted at slot zero while the
    /// device's head stood at two wrote forty-five frames behind the head and
    /// moved the tail *backwards*; the device fetched none of them and the
    /// boot reported a switch that would not answer. The device never saw a
    /// frame to answer.
    transmit_next: u32,
    /// The next transmit descriptor to use, which is also what `PF_ATQT` is
    /// written with after each post: a tail is the last valid descriptor plus
    /// one, in 38.39.2.18.14's words for the receive tail and Table 38-341's
    /// for this one.
    next: u32,
}

impl<R: Registers> Device<R> {
    /// Takes a mapped register window.
    ///
    /// **The whole unsafety of this driver is here**, deliberately. `registers`
    /// must be a mapping of this function's BAR0, device-mapped, valid for the
    /// life of this value, and nothing else may be driving the device. Every
    /// method below relies on that and is therefore safe, which keeps the
    /// `unsafe` in this file down to the two volatile accesses that genuinely
    /// need it rather than a block around each driver step.
    ///
    /// # Safety
    ///
    /// As above.
    #[must_use]
    pub const fn new(registers: R) -> Self {
        Self {
            registers,
            ring_enabled: false,
            transmit_depth: 0,
            transmit_next: 0,
            next: 0,
        }
    }

    /// Reads one register, which the offsets in this file are all within.
    fn read(&self, offset: u64) -> u32 {
        self.registers.read(offset)
    }

    /// Reads one 64-bit register pair in a single access.
    ///
    /// **Required rather than preferred** for the statistics counters, whose
    /// definitions say *"the low and high registers are part of a 64-bit
    /// register and are read using 64-bit read accesses only"*. Two 32-bit
    /// reads would also tear across a counter incrementing between them, which
    /// is the ordinary reason such a pair exists.
    fn read64(&self, offset: u64) -> u64 {
        self.registers.read64(offset)
    }

    /// Writes one register.
    fn write(&mut self, offset: u64, value: u32) {
        self.registers.write(offset, value);
    }

    /// Asks for a PF reset and says whether the device finished one.
    ///
    /// Sets `PFGEN_CTRL.PFSWR` and waits for **hardware to clear it**, which is
    /// how the datasheet defines completion. `spins` bounds the wait: a device
    /// that never clears the bit is a device that is not there or not
    /// answering, and this must say so rather than hang a boot.
    ///
    pub fn reset(&mut self, spins: u32) -> bool {
        self.write(PFGEN_CTRL, PFSWR);
        for _ in 0..spins {
            if self.read(PFGEN_CTRL) & PFSWR == 0 {
                return true;
            }
            core::hint::spin_loop();
        }
        false
    }

    /// Points the admin queues at rings the caller owns, and remembers where
    /// this kernel reaches the transmit ring.
    ///
    /// `transmit` and `receive` are the rings' addresses **as the device will
    /// issue them** -- which is not their physical address, because this device
    /// translates through its own IOMMU domain (RFC 0072 step 2). Handing a
    /// physical address here would name a page the device cannot reach, and the
    /// failure would be silence rather than a fault.
    ///
    /// `host` is the transmit ring **as this kernel sees it** -- the direct-map
    /// address of the same page the device reaches at `transmit`. Both are
    /// needed and they are not the same number: the device is told where the
    /// ring is in its own translation, and a descriptor has to be written where
    /// the writer can reach it.
    ///
    /// The enable bit goes last, in both rings, because the datasheet says the
    /// other fields must be initialized before it is set.
    ///
    /// `transmit` and `receive` are the two rings as the **device** reaches
    /// them. They must stay mapped for its use while the queues are enabled,
    /// which is the caller's obligation and not checkable here; the transmit
    /// ring as *this driver* writes it is handed to each [`Device::command`],
    /// which bounds-checks every descriptor it posts.
    ///
    /// **The rings are passed to each call rather than held**, and the reason
    /// is testability rather than taste: a driver holding `&mut [u8]` cannot be
    /// handed a ring a test also wants to write, so firmware's side of a
    /// command round-trip could not be modelled at all. Nine methods take one
    /// argument more; every one of them became testable.
    pub fn enable_admin_queues(&mut self, transmit: u64, receive: u64) {
        // Heads and tails first, so an enabled ring does not start from
        // whatever a previous owner left. A PF reset clears the enable bits,
        // but this does not assume the reset happened.
        self.write(PF_ATQH, 0);
        self.write(PF_ATQT, 0);
        self.write(PF_ARQH, 0);
        self.write(PF_ARQT, 0);

        self.write(PF_ATQBAL, transmit as u32);
        self.write(PF_ATQBAH, (transmit >> 32) as u32);
        self.write(PF_ARQBAL, receive as u32);
        self.write(PF_ARQBAH, (receive >> 32) as u32);

        self.write(PF_ATQLEN, RING_DESCRIPTORS | QUEUE_ENABLE);
        self.write(PF_ARQLEN, RING_DESCRIPTORS | QUEUE_ENABLE);

        self.ring_enabled = true;
        self.next = 0;
    }

    /// Whether both admin queues read back as enabled.
    ///
    /// **Read back rather than assumed.** A write to a register the device is
    /// not answering returns nothing and looks exactly like success, which is
    /// the failure mode every driver in this tree has hit at least once.
    #[must_use]
    pub fn admin_queues_enabled(&self) -> bool {
        let (transmit, receive) = (self.read(PF_ATQLEN), self.read(PF_ARQLEN));
        transmit & QUEUE_ENABLE != 0 && receive & QUEUE_ENABLE != 0
    }

    /// The admin queue lengths the device reports, for the boot report.
    ///
    #[must_use]
    pub fn admin_queue_lengths(&self) -> (u32, u32) {
        (self.read(PF_ATQLEN) & 0x3ff, self.read(PF_ARQLEN) & 0x3ff)
    }

    /// What the private memory registers read for this function.
    ///
    /// **Discovered before anything is written.** The segment-descriptor range
    /// and the object sizes are the device's to state; the LAN base and count
    /// pairs are this driver's to write, and what they hold now is whatever
    /// the last owner -- firmware's PXE driver, or nobody -- left in them,
    /// which is worth one line of the report before it is overwritten. Asking
    /// first is the same habit that found firmware holding the admin queues'
    /// size.
    #[must_use]
    pub fn private_memory(&self) -> PrivateMemory {
        let function = self.read(PF_FUNC_RID) & 0b111;
        let at = 4 * u64::from(function);
        let partition = self.read(GLHMC_SDPART + at);
        PrivateMemory {
            function,
            sd_base: partition & 0xfff,
            sd_size: (partition >> 16) & 0x1fff,
            tx_base: self.read(GLHMC_LANTXBASE + at) & 0x00ff_ffff,
            tx_count: self.read(GLHMC_LANTXCNT + at) & 0x7ff,
            rx_base: self.read(GLHMC_LANRXBASE + at) & 0x00ff_ffff,
            rx_count: self.read(GLHMC_LANRXCNT + at) & 0x7ff,
            tx_object_size: self.read(GLHMC_LANTXOBJSZ) & 0xf,
            rx_object_size: self.read(GLHMC_LANRXOBJSZ) & 0xf,
            queue_max: self.read(GLHMC_LANQMAX) & 0x7ff,
        }
    }

    /// Which LAN queues this PF owns, `(first, last)` in the device's absolute
    /// numbering -- `PFLAN_QALLOC` -- or `None` if its `VALID` flag is clear,
    /// which the datasheet says cannot be true of an active PF.
    #[must_use]
    pub fn queue_allocation(&self) -> Option<(u16, u16)> {
        let value = self.read(PFLAN_QALLOC);
        if value & QALLOC_VALID == 0 {
            return None;
        }
        Some(((value & 0x7ff) as u16, ((value >> 16) & 0x7ff) as u16))
    }

    /// Whether the device is still in PXE mode -- `GLLAN_RCTL_0.PXE_MODE`,
    /// which a core reset sets and only the Clear PXE Mode command clears.
    #[must_use]
    pub fn pxe_mode(&self) -> bool {
        self.read(GLLAN_RCTL_0) & PXE_MODE != 0
    }

    /// Where a VSI's queues start within this PF's -- `VSILAN_QBASE[vsi]` as
    /// `(base, scattered)` -- or `None` for a VSI index the register file does
    /// not have.
    #[must_use]
    pub fn vsi_queue_base(&self, vsi: u16) -> Option<(u16, bool)> {
        if u64::from(vsi) > MAX_VSI {
            return None;
        }
        let value = self.read(VSILAN_QBASE + 4 * u64::from(vsi));
        Some(((value & 0x7ff) as u16, value & VSI_QTABLE_ENABLED != 0))
    }

    /// What the HMC has recorded, if anything -- `PFHMC_ERRORINFO` with its
    /// `ERROR_DETECTED` bit set, and the data register beside it.
    #[must_use]
    pub fn hmc_error(&self) -> Option<HmcError> {
        let info = self.read(PFHMC_ERRORINFO);
        if info & (1 << 31) == 0 {
            return None;
        }
        Some(HmcError {
            kind: ((info >> 8) & 0xf) as u8,
            object: ((info >> 16) & 0x1f) as u8,
            function: (info & 0x1f) as u8,
            data: self.read(PFHMC_ERRORDATA),
        })
    }

    /// Asks `Clear PXE Mode` -- Table 38-402. `Ok(true)` if the device left
    /// PXE mode on this command, `Ok(false)` if firmware answered `EEXIST`
    /// because it was already out.
    ///
    /// The datasheet's own sequence for the command has firmware disable the
    /// PXE receive queues first and clear the flag last, which is why this is
    /// a command and not a write to `GLLAN_RCTL_0`.
    ///
    /// # Errors
    ///
    /// As [`Device::command`], except that `EEXIST` is an answer.
    pub fn clear_pxe_mode(
        &mut self,
        ring: &mut impl Dma,
        spins: u32,
    ) -> Result<bool, CommandError> {
        match self.command(ring, Descriptor::direct(OPCODE_CLEAR_PXE_MODE), spins) {
            Ok(_) => Ok(true),
            Err(CommandError::Refused(RETURN_EEXIST)) => Ok(false),
            Err(error) => Err(error),
        }
    }

    /// Sets or clears **one** promiscuous mode on a VSI -- Table 38-253.
    ///
    /// **One at a time, because they are not all legal together.** Asking for
    /// all five at once on the SR550 was refused with `EINVAL` and the refusal
    /// took the whole command with it -- so a VSI that had multicast,
    /// broadcast and VLAN promiscuity for six boots lost all three at once.
    /// The datasheet says why: *"Default VSI should not be set if the VSI is
    /// connected directly to the port (not via a VEB or a PV)"*, and this one
    /// is. Each mode now stands or falls on its own, and the valid mask names
    /// only the mode being changed.
    ///
    /// # Errors
    ///
    /// As [`Device::command`].
    pub fn set_promiscuous(
        &mut self,
        ring: &mut impl Dma,
        seid: u16,
        mode: PromiscuousMode,
        on: bool,
        spins: u32,
    ) -> Result<(), CommandError> {
        let mut request = Descriptor::direct(OPCODE_SET_VSI_PROMISCUOUS);
        let valid = mode.bit();
        let modes = if on { valid } else { 0 };
        // Bytes 16-17 the modes, 18-19 the valid mask, 20-21 the SEID.
        request.words[4] = u32::from(modes) | (u32::from(valid) << 16);
        request.words[5] = u32::from(seid & 0x3ff);
        self.command(ring, request, spins).map(|_| ())
    }

    /// Programs where the LAN objects live in this function's private memory
    /// -- 38.26.3.1: transmit contexts first, at base zero; receive contexts
    /// after them at the next 512-byte boundary; both counted to `queues`,
    /// which is the PF's whole allocation because the objects are indexed by
    /// absolute queue number -- and reads the four registers back.
    pub fn program_lan_private_memory(&mut self, queues: u32) -> PrivateMemory {
        let function = self.read(PF_FUNC_RID) & 0b111;
        let at = 4 * u64::from(function);
        let tx_size = self.read(GLHMC_LANTXOBJSZ) & 0xf;
        self.write(GLHMC_LANTXBASE + at, 0);
        self.write(GLHMC_LANTXCNT + at, queues & 0x7ff);
        self.write(
            GLHMC_LANRXBASE + at,
            receive_base_after(0, queues, tx_size) & 0x00ff_ffff,
        );
        self.write(GLHMC_LANRXCNT + at, queues & 0x7ff);
        self.private_memory()
    }

    /// Writes one segment descriptor and reads it back through the same
    /// command register -- 38.26.4 step 6: paged, valid, the page descriptor
    /// page's address split high and low, and `PMSDBPCOUNT` in the low word.
    ///
    /// `pd_page` is the page descriptor page **as the device issues it**.
    /// Returns what the entry reads back as, `(low, high)`, for the caller to
    /// hold against [`segment_descriptor`]: a write past this function's range
    /// *"is dropped"*, and dropped silently.
    pub fn write_segment_descriptor(
        &mut self,
        index: u32,
        pd_page: u64,
        backing_pages: u32,
    ) -> (u32, u32) {
        let (low, high) = segment_descriptor(pd_page, backing_pages);
        self.write(PFHMC_SDDATAHIGH, high);
        self.write(PFHMC_SDDATALOW, low);
        self.write(PFHMC_SDCMD, (index & 0xfff) | SD_WRITE);
        // A read command for the same index, and a read of the command
        // register between it and the data so the posted writes have landed.
        self.write(PFHMC_SDCMD, index & 0xfff);
        let _ = self.read(PFHMC_SDCMD);
        (self.read(PFHMC_SDDATALOW), self.read(PFHMC_SDDATAHIGH))
    }

    /// Enables a receive queue -- 38.30.3.3.2: the tail cleared and then set,
    /// `QENA_REQ` set, `QENA_STAT` polled, which *"follows the QENA_REQ
    /// almost instantly and not more than 10 µs after that"*.
    ///
    /// `tail` is the first descriptor software has not handed over -- the
    /// count posted -- and a multiple of eight outside PXE mode.
    pub fn enable_receive_queue(&mut self, queue: u32, tail: u32, spins: u32) -> bool {
        let at = 4 * u64::from(queue);
        self.write(QRX_TAIL + at, 0);
        self.write(QRX_TAIL + at, tail & 0x1fff);
        let enable = self.read(QRX_ENA + at);
        self.write(QRX_ENA + at, enable | QENA_REQ);
        for _ in 0..spins {
            if self.read(QRX_ENA + at) & QENA_STAT != 0 {
                return true;
            }
            core::hint::spin_loop();
        }
        false
    }

    /// What a receive queue's tail register reads.
    ///
    /// **Read back rather than assumed, because a tail of zero is a queue with
    /// no descriptors available and looks exactly like a queue nothing is being
    /// steered to.** The port counts frames, the VSI counts frames, and no
    /// queue takes one -- and this is the one register that distinguishes "the
    /// switch is not sending them here" from "this queue told the device it had
    /// nothing to put them in".
    #[must_use]
    pub fn receive_tail(&self, queue: u32) -> u32 {
        self.read(QRX_TAIL + 4 * u64::from(queue)) & 0x1fff
    }

    /// Hands descriptors to a queue that is already enabled.
    ///
    /// [`Device::enable_receive_queue`] writes the tail *before* asking for the
    /// queue, which is the order 38.30.3.3.2 lists. Whether a device latches a
    /// tail written to a queue that is not yet enabled is a different question
    /// from what order the steps are listed in, and one this driver has never
    /// asked: the tail has never been read back. This writes it again once the
    /// queue reports itself enabled, which costs one register write and removes
    /// the question.
    pub fn arm_receive_queue(&mut self, queue: u32, tail: u32) {
        self.write(QRX_TAIL + 4 * u64::from(queue), tail & 0x1fff);
    }

    /// Makes the device report completed receive descriptors without raising
    /// an interrupt.
    ///
    /// **This is what a receive queue was missing.** 38.22.5 says a completed
    /// descriptor is posted back *"once every several packets or at ITR
    /// expiration"*, and a queue in no interrupt linked list reaches neither --
    /// so the frames arrive, the device fills the buffers and advances the
    /// head, and the ring never says so. The same section gives the
    /// arrangement for a driver that wants the reporting and not the interrupt:
    /// a vector with `WB_ON_ITR` set and `INTENA` clear, with the queues
    /// chained onto it.
    ///
    /// `queues` receive queues from `first` are chained onto interrupt zero on
    /// **ITR0, whose interval is set to zero** -- *"Setting the INTERVAL to
    /// zero enables immediate interrupt"* -- so "at ITR expiration" is at once,
    /// and each with `CAUSE_ENA` clear, so none of them raises anything.
    ///
    /// The first attempt used *No ITR* on the strength of `WB_ON_ITR`'s
    /// parenthetical *"(or No ITR)"*, and the SR550 reported nothing: a queue
    /// with no ITR has no expiry to be reported at.
    ///
    /// Returns what `PFINT_DYN_CTL0` reads back, because a bit that did not
    /// take is a bit worth seeing rather than assuming.
    pub fn report_completions(&mut self, first: u32, queues: u32) -> u32 {
        for index in 0..queues {
            let queue = first + index;
            // The next queue in the chain, or the datasheet's NULL pointer for
            // the last of them. `NEXTQ_TYPE` stays `00b`: receive queues.
            let next = if index + 1 < queues {
                (first + index + 1) & QINT_NEXTQ_NONE
            } else {
                QINT_NEXTQ_NONE
            };
            // `MSIX_INDX` zero -- interrupt zero, which is the only valid one
            // in MSI or legacy mode and the one whose list is used below --
            // `ITR_INDX` No ITR, and `CAUSE_ENA` clear.
            // **`CAUSE_ENA` set, and `INTENA` clear on the vector below.**
            // 38.22.5's arrangement is a vector that reports and does not
            // interrupt, and the interrupt is disabled at the *vector*: with
            // the cause disabled at the queue as well, two boots produced no
            // write-back at all. The cause is what puts the queue's completion
            // into the path the ITR then processes; `PFINT_DYN_CTL0.INTENA`
            // clear is what stops anything being delivered.
            let control = QINT_ITR0 | (next << QINT_NEXTQ_SHIFT) | QINT_CAUSE_ENA;
            self.write(QINT_RQCTL + 4 * u64::from(queue), control);
        }
        // ITR0 expires immediately, so "at ITR expiration" is "now".
        self.write(PFINT_ITR0, 0);
        // Interrupt zero's list starts at the first queue, of type receive.
        self.write(PFINT_LNKLST0, first & QINT_NEXTQ_NONE);
        // And the vector reports completions without enabling the interrupt:
        // `WB_ON_ITR` alone, which leaves `INTENA` -- bit 0 -- clear. The two
        // are named separately so that reading this says which is which; the
        // test beside it is what checks they stay that way.
        self.write(PFINT_DYN_CTL0, PFINT_WB_ON_ITR);
        self.read(PFINT_DYN_CTL0)
    }

    /// Disables a receive queue -- 38.30.3.3.3: `QENA_REQ` cleared, then
    /// `QENA_STAT` polled clear, after which *"software can release all memory
    /// structures of the queue"*.
    pub fn disable_receive_queue(&mut self, queue: u32, spins: u32) -> bool {
        let at = 4 * u64::from(queue);
        let enable = self.read(QRX_ENA + at);
        self.write(QRX_ENA + at, enable & !QENA_REQ);
        for _ in 0..spins {
            if self.read(QRX_ENA + at) & QENA_STAT == 0 {
                return true;
            }
            core::hint::spin_loop();
        }
        false
    }

    /// The context the device holds for a receive queue, read out of its
    /// cache -- `PFCM_LANCTXCTL` with a read of sub-line 0, which is bits
    /// 0-127: `HEAD`, `BASE`, `QLEN`, the buffer sizes and the flags.
    ///
    /// Returns the four words and whether the queue was resident (`CTX_MISS`
    /// clear), or `None` if `CTX_DONE` never set. This is the one way to see
    /// the context **the device** has, as distinct from the one this driver
    /// wrote into private memory: a `HEAD` that moved is a device that fetched
    /// descriptors from the ring the context names.
    #[must_use]
    pub fn cached_receive_context(&mut self, queue: u32, spins: u32) -> Option<([u32; 4], bool)> {
        // Sub-line 0, queue type 00 (receive), op code 00 (read).
        self.write(PFCM_LANCTXCTL, queue & 0xfff);
        for _ in 0..spins {
            let status = self.read(PFCM_LANCTXSTAT);
            if status & 1 != 0 {
                let mut words = [0; 4];
                for (index, word) in words.iter_mut().enumerate() {
                    *word = self.read(PFCM_LANCTXDATA + 0x80 * index as u64);
                }
                return Some((words, status & 0b10 == 0));
            }
            core::hint::spin_loop();
        }
        None
    }

    /// Which LAN port this function is connected to -- `PFGEN_PORTNUM`, bits
    /// 1:0. The statistics registers are indexed by it.
    #[must_use]
    pub fn port_number(&self) -> u32 {
        self.read(PFGEN_PORTNUM) & 0b11
    }

    /// The port's receive counters, at this instant.
    ///
    /// Totals since power-on, not for this boot -- see [`PortCounters`]. Reads
    /// nothing back that it writes, and clears nothing: these are `RW1C`, so a
    /// reader leaves them exactly as found, and firmware's own accounting of
    /// this port is undisturbed. That matters on a LOM the platform shares.
    #[must_use]
    pub fn port_counters(&self, port: u32) -> PortCounters {
        let at = 8 * u64::from(port.min(MAX_PORT as u32));
        PortCounters {
            unicast: self.read64(GLPRT_UPRCL + at),
            multicast: self.read64(GLPRT_MPRCL + at),
            broadcast: self.read64(GLPRT_BPRCL + at),
            octets: self.read64(GLPRT_GORCL + at),
            discarded: self.read(GLPRT_RDPC + at),
            crc_errors: self.read(GLPRT_CRCERRS + at),
            length_errors: self.read(GLPRT_RLEC + at),
            undersize: self.read(GLPRT_RUC + at),
            oversize: self.read(GLPRT_ROC + at),
        }
    }

    /// A VSI's receive counters, at an index this driver assumes is the VSI
    /// number -- see [`VsiCounters`] and [`GLV_RDPC`].
    #[must_use]
    pub fn vsi_counters(&self, vsi: u16) -> VsiCounters {
        let at = 8 * u64::from(u64::from(vsi).min(MAX_VSI) as u32);
        VsiCounters {
            unicast: self.read64(GLV_UPRCL + at),
            multicast: self.read64(GLV_MPRCL + at),
            broadcast: self.read64(GLV_BPRCL + at),
            discarded: self.read(GLV_RDPC + at),
        }
    }

    /// This port's own MAC address, from the NVM -- `PRTPM_SAL`/`PRTPM_SAH`.
    ///
    /// Returns `None` if `PRTPM_SAH.AV` is clear, which means the NVM did not
    /// supply one and nothing here should invent it: a frame sent from an
    /// address this port does not own is a frame a switch may drop, and worse,
    /// one whose replies go elsewhere.
    ///
    /// The byte order is the datasheet's and not a convention: *"LS byte of
    /// SAL is first on the wire"* and *"MS byte of PRTPM_SAH is last"*.
    #[must_use]
    pub fn mac_address(&self, port: u32) -> Option<[u8; 6]> {
        let at = 0x20 * u64::from(port.min(MAX_PORT as u32));
        let high = self.read(PRTPM_SAH + at);
        if high & SAH_ADDRESS_VALID == 0 {
            return None;
        }
        let low = self.read(PRTPM_SAL + at);
        Some([
            low as u8,
            (low >> 8) as u8,
            (low >> 16) as u8,
            (low >> 24) as u8,
            high as u8,
            (high >> 8) as u8,
        ])
    }

    /// The port's transmit counters, at this instant. Totals since power-on,
    /// as [`PortCounters`].
    #[must_use]
    pub fn transmit_counters(&self, port: u32) -> TransmitCounters {
        let at = 8 * u64::from(port.min(MAX_PORT as u32));
        TransmitCounters {
            unicast: self.read64(GLPRT_UPTCL + at),
            multicast: self.read64(GLPRT_MPTCL + at),
            broadcast: self.read64(GLPRT_BPTCL + at),
            octets: self.read64(GLPRT_GOTCL + at),
        }
    }

    /// Adds one MAC filter to a VSI -- `Add MAC, VLAN Pair`, Table 38-237.
    ///
    /// The entry is a perfect match that ignores VLAN, so the address is
    /// forwarded to this VSI from every VLAN on a trunk. `device` and `host`
    /// are the 16-byte buffer as the device issues it and as this kernel
    /// reaches it.
    ///
    /// # Safety
    ///
    /// `buffer` is what the device reaches at `device`, at least
    /// [`MAC_VLAN_ENTRY_BYTES`] long and written by nothing else while this
    /// runs.
    ///
    /// # Errors
    ///
    /// As [`Device::command`]. `ENOSPC` means the filter table is full.
    pub fn add_mac_filter(
        &mut self,
        ring: &mut impl Dma,
        seid: u16,
        address: [u8; 6],
        device: u64,
        buffer: &mut impl Dma,
        spins: u32,
    ) -> Result<(), CommandError> {
        let mut entry = [0u8; MAC_VLAN_ENTRY_BYTES as usize];
        entry[0..6].copy_from_slice(&address);
        // Bytes 6-7 are the VLAN, left zero because the ignore flag makes it
        // meaningless; 8-9 the flags; 10-11 a queue, only meaningful with
        // `ToQueue`, which is not set -- the VSI's own steering decides.
        let flags = MAC_VLAN_PERFECT_MATCH | MAC_VLAN_IGNORE_VLAN;
        entry[8..10].copy_from_slice(&flags.to_le_bytes());
        buffer.write(0, &entry);
        let mut request =
            Descriptor::with_buffer(OPCODE_ADD_MAC_VLAN, device, MAC_VLAN_ENTRY_BYTES);
        // Bytes 16-17 the count, 18-19 the SEID with its valid bit.
        request.words[4] = 1 | (u32::from(seid & 0x3ff) | 0x8000) << 16;
        self.command(ring, request, spins).map(|_| ())
    }

    /// Asks firmware to stop its LLDP agent, releasing the port's control VSI.
    ///
    /// `shutdown` chooses the louder variant, which also emits a final LLDP
    /// PDU announcing this station's departure; [`LLDP_SHUTDOWN`] says why
    /// this driver passes `false`.
    ///
    /// # Errors
    ///
    /// As [`Device::command`]. A firmware with no agent running may answer
    /// `EEXIST` or `ENOENT`, and either is an answer rather than a failure.
    pub fn stop_lldp_agent(
        &mut self,
        ring: &mut impl Dma,
        shutdown: bool,
        spins: u32,
    ) -> Result<(), CommandError> {
        let mut request = Descriptor::direct(OPCODE_STOP_LLDP_AGENT);
        // Byte 16 is the command; the rest of the descriptor is reserved.
        request.words[4] = u32::from(if shutdown { LLDP_SHUTDOWN } else { 0 });
        self.command(ring, request, spins).map(|_| ())
    }

    /// Lets a VSI fix a transmit packet's destination itself -- the *Allow
    /// Destination Override* flag, without which a switch control tag in a
    /// transmit context descriptor is not permitted.
    ///
    /// **Read, modify, write.** The VSI's own configuration is fetched with
    /// `Get VSI Parameters` first and written back with one bit changed, so
    /// nothing else about a VSI firmware created is asserted or lost. Writing
    /// a switching section from zeroes would replace its switch id and its
    /// loopback setting with guesses.
    ///
    /// As [`Device::vsi_parameters`].
    ///
    /// # Errors
    ///
    /// As [`Device::command`].
    pub fn allow_destination_override(
        &mut self,
        ring: &mut impl Dma,
        seid: u16,
        device: u64,
        buffer: &mut impl Dma,
        spins: u32,
    ) -> Result<(), CommandError> {
        self.vsi_parameters(ring, seid, device, buffer, spins)?;
        // The buffer firmware just filled, read back with one bit changed.
        let mut sections = [0u8; 2];
        buffer.read(0, &mut sections);
        let sections = u16::from_le_bytes(sections) | VSI_SECTION_SWITCHING;
        buffer.write(0, &sections.to_le_bytes());
        let mut flags = [0u8; 1];
        buffer.read(VSI_SWITCHING_FLAGS_AT, &mut flags);
        flags[0] |= VSI_ALLOW_DESTINATION_OVERRIDE;
        buffer.write(VSI_SWITCHING_FLAGS_AT, &flags);
        let mut request = Descriptor::with_buffer(OPCODE_UPDATE_VSI, device, VSI_BUFFER_BYTES);
        // Bytes 16-17 are the SEID.
        request.words[4] = u32::from(seid);
        self.command(ring, request, spins).map(|_| ())
    }

    /// Maps `queues` receive queues to a VSI's traffic class 0.
    ///
    /// **The section this driver has never written, and the only link in the
    /// receive chain never examined.** On the SR550 the port counts frames, the
    /// VSI counts frames, and no queue takes one -- and the VSI's own context
    /// says traffic class 0 has *one* queue while the driver enables four. A
    /// VSI is told which queues are its own here, and until now firmware's
    /// answer was read and written back unchanged.
    ///
    /// `base` is the first queue **as the VSI numbers them**, which is an
    /// offset from the base `VSILAN_QBASE` holds and is zero for a PF whose
    /// queues start at its own first. `queues` is rounded down to a power of
    /// two, because the field is a log2 and a device asked for three queues
    /// would take a number it cannot express.
    ///
    /// Read, modify, write, for the reason [`Device::allow_destination_override`]
    /// gives: firmware created this VSI and a section written from zeroes would
    /// replace what it chose with guesses.
    ///
    /// # Errors
    ///
    /// As [`Device::command`].
    pub fn map_receive_queues(
        &mut self,
        ring: &mut impl Dma,
        seid: u16,
        device: u64,
        buffer: &mut impl Dma,
        base: u16,
        queues: u16,
    ) -> Result<(u16, u16), CommandError> {
        const SPINS: u32 = 2_000_000;
        self.vsi_parameters(ring, seid, device, buffer, SPINS)?;

        // What it was, so the caller can say whether anything changed.
        let mut was = [0u8; 2];
        buffer.read(VSI_TC_MAPPING_AT, &mut was);
        let was = u16::from_le_bytes(was);

        let mut sections = [0u8; 2];
        buffer.read(0, &mut sections);
        let sections = u16::from_le_bytes(sections) | VSI_SECTION_QUEUE_MAP;
        buffer.write(0, &sections.to_le_bytes());

        buffer.write(VSI_MAPPING_FLAGS_AT, &VSI_QUEUES_CONTIGUOUS.to_le_bytes());
        buffer.write(VSI_QUEUE_MAPPING_AT, &base.to_le_bytes());
        // The count as a power of two. `ilog2` of zero has no answer, so one
        // queue -- a field of zero -- is the floor.
        let power = if queues < 2 { 0 } else { queues.ilog2() as u16 };
        let mapping = (power & 0x7) << VSI_TC_QUEUES_SHIFT;
        buffer.write(VSI_TC_MAPPING_AT, &mapping.to_le_bytes());

        let mut request = Descriptor::with_buffer(OPCODE_UPDATE_VSI, device, VSI_BUFFER_BYTES);
        // Bytes 16-17 are the SEID.
        request.words[4] = u32::from(seid);
        self.command(ring, request, SPINS)?;
        Ok((was, mapping))
    }

    /// Routes a control protocol to a VSI by EtherType -- `Add Control Packet
    /// Filter`, Table 38-261.
    ///
    /// Matches on EtherType alone, ignoring the destination address, on
    /// received traffic. That is what gets link-local frames -- the ones a
    /// bridge would otherwise terminate -- delivered to a queue.
    ///
    /// # Errors
    ///
    /// As [`Device::command`]. `EEXIST` means a filter for this flow type is
    /// already installed, which the datasheet says these filters are exclusive
    /// about: *"if a request to set a filter on an existing flow type is
    /// received, it is rejected with an EEXIST reason code"*. Firmware's own
    /// agent holding one is exactly the case worth telling apart.
    pub fn add_control_packet_filter(
        &mut self,
        ring: &mut impl Dma,
        seid: u16,
        ethertype: u16,
        spins: u32,
    ) -> Result<(), CommandError> {
        let mut request = Descriptor::direct(OPCODE_ADD_CONTROL_PACKET_FILTER);
        // Bytes 16-21 are the MAC, ignored by the flag below; 22-23 the
        // EtherType; 24-25 the flags; 26-27 the SEID; 28-29 a queue, only
        // meaningful with `ToQueue`, which is not set.
        request.words[5] = u32::from(ethertype) << 16;
        request.words[6] = u32::from(CONTROL_FILTER_IGNORE_MAC) | (u32::from(seid & 0x3ff) << 16);
        self.command(ring, request, spins).map(|_| ())
    }

    /// Asks `Get VSI Parameters` about a VSI this function controls.
    ///
    /// `device` and `host` are the 128-byte buffer as the device issues it and
    /// as this kernel reaches it. The buffer is zeroed first so a stale handle
    /// cannot be read as this answer.
    ///
    /// # Safety
    ///
    /// `buffer` is what the device reaches at `device`, at least
    /// [`VSI_BUFFER_BYTES`] long and written by nothing else while this runs.
    ///
    /// # Errors
    ///
    /// As [`Device::command`]. `ENOENT` means the SEID is not a VSI and
    /// `EACCES` that it belongs to another PF. [`CommandError::ShortBuffer`] if
    /// `buffer` is too small to hold what firmware will write -- refused rather
    /// than truncated, because a short read here would report a queue set that
    /// firmware never named.
    pub fn vsi_parameters(
        &mut self,
        ring: &mut impl Dma,
        seid: u16,
        device: u64,
        buffer: &mut impl Dma,
        spins: u32,
    ) -> Result<VsiParameters, CommandError> {
        buffer.zero(0, VSI_BUFFER_BYTES as usize);
        let mut request =
            Descriptor::with_buffer(OPCODE_GET_VSI_PARAMETERS, device, VSI_BUFFER_BYTES);
        // The SEID goes in bytes 16-17, which `with_buffer` leaves clear.
        request.words[4] = u32::from(seid);
        let reply = self.command(ring, request, spins)?;
        let mut context = [0u8; VSI_BUFFER_BYTES as usize];
        buffer.read(0, &mut context);
        Ok(VsiParameters {
            // Bytes 18-19 of the descriptor: "returns the assigned VSI number".
            number: reply.half(18),
            queue_set: u16::from_le_bytes([context[QS_HANDLE_AT], context[QS_HANDLE_AT + 1]]),
            context,
        })
    }

    /// Clears a transmit queue's internal disable flag -- 38.31.3.1.1's
    /// *"software should clear the queue disable flag... before the queue is
    /// enabled"*, through the one register whose index is the queue divided by
    /// 128 rather than the queue itself.
    ///
    /// `queue` is the **absolute** index, which is what `QINDX` takes.
    pub fn clear_transmit_queue_disable(&mut self, queue: u32) {
        let register = GLLAN_TXPRE_QDIS + 4 * u64::from(queue / QDIS_QUEUES_PER_REGISTER);
        self.write(register, (queue & 0x7ff) | TXPRE_CLEAR_QDIS);
    }

    /// Sets a transmit queue's internal disable flag, the other half of
    /// [`Device::clear_transmit_queue_disable`] and the first step of the
    /// disable flow.
    pub fn set_transmit_queue_disable(&mut self, queue: u32) {
        let register = GLLAN_TXPRE_QDIS + 4 * u64::from(queue / QDIS_QUEUES_PER_REGISTER);
        self.write(register, (queue & 0x7ff) | TXPRE_SET_QDIS);
    }

    /// Says which function owns a transmit queue -- `QTX_CTL`, a statement a
    /// receive queue never needs to make.
    pub fn own_transmit_queue(&mut self, queue: u32, function: u32) {
        self.write(
            QTX_CTL + 4 * u64::from(queue),
            QTX_CTL_PF_QUEUE | ((function & 0xf) << 2),
        );
    }

    /// Enables a transmit queue -- 38.31.3.1.1: the head cleared, `QENA_REQ`
    /// set, `QENA_STAT` polled, which follows *"not more than 10 µs"* later.
    ///
    /// The context, the ownership and the disable flag must already be done;
    /// this is the last step and the one the device answers.
    pub fn enable_transmit_queue(&mut self, queue: u32, spins: u32) -> bool {
        let at = 4 * u64::from(queue);
        self.write(QTX_HEAD + at, 0);
        self.write(QTX_TAIL + at, 0);
        let enable = self.read(QTX_ENA + at);
        self.write(QTX_ENA + at, enable | QENA_REQ);
        for _ in 0..spins {
            if self.read(QTX_ENA + at) & QENA_STAT != 0 {
                return true;
            }
            core::hint::spin_loop();
        }
        false
    }

    /// Names the LAN transmit ring this driver will post frames into.
    ///
    /// # Safety
    ///
    /// `host` must be the direct-map address of the ring the queue's context
    /// points at, writable, `descriptors` deep, and written by nothing else.
    pub fn attach_transmit_ring(&mut self, descriptors: u16) {
        self.transmit_depth = u32::from(descriptors);
        self.transmit_next = 0;
    }

    /// Posts one frame on the transmit queue and rings its doorbell.
    ///
    /// `uplink` precedes the data descriptor with a context descriptor
    /// carrying [`TX_SWTCH_UPLINK`], which a control frame needs to bypass the
    /// internal switch's filters.
    ///
    /// Returns the descriptor index to poll for completion, or `None` if no
    /// ring is attached or the frame needs more slots than the ring has.
    ///
    /// **The cursor is this driver's**, and advancing it here rather than in
    /// each caller is the whole point: the tail must only ever move forward,
    /// and a caller that recomputes a slot from its own counter does not know
    /// where the previous caller left it.
    pub fn post_frame(
        &mut self,
        ring: &mut impl Dma,
        buffer: u64,
        bytes: u16,
        uplink: bool,
    ) -> Option<u32> {
        let needed = if uplink { 2 } else { 1 };
        if self.transmit_depth < needed {
            return None;
        }
        // Wrap before writing rather than across the pair, so a frame's
        // descriptors are always contiguous and the tail is always the slot
        // after the last one written.
        if self.transmit_next + needed > self.transmit_depth {
            self.transmit_next = 0;
        }
        let slot = self.transmit_next;
        let data = if uplink { slot + 1 } else { slot };
        if uplink {
            post_transmit_context(ring, slot, TX_SWTCH_UPLINK);
        }
        post_transmit_descriptor(ring, data, buffer, bytes);
        self.transmit_next = data + 1;
        // **Wrap the cursor, because the tail is an index and not a count.**
        // `QTX_TAIL` takes a descriptor index, so a ring of eight accepts 0 to
        // 7; writing 8 after filling the last slot is out of range and the
        // queue stops taking updates. That is exactly what happened on
        // 2026-09-06: four LACPDUs left the wire and the fifth put the tail at
        // eight, after which the head sat still at six and forty more frames
        // went nowhere.
        if self.transmit_next >= self.transmit_depth {
            self.transmit_next = 0;
        }
        Some(data)
    }

    /// The tail this driver's cursor now stands at, for the doorbell.
    ///
    /// Always a valid descriptor index -- see [`Device::post_frame`].
    #[must_use]
    pub const fn transmit_tail(&self) -> u32 {
        self.transmit_next
    }

    /// Whether the frame posted at `index` has been written back.
    ///
    #[must_use]
    pub fn frame_completed(&self, ring: &impl Dma, index: u32) -> bool {
        transmit_completed(ring, index)
    }

    /// What a transmit queue's enable handshake currently reads, as
    /// [`Device::receive_queue_state`] does for the other direction.
    #[must_use]
    pub fn transmit_queue_state(&self, queue: u32) -> (bool, bool) {
        let value = self.read(QTX_ENA + 4 * u64::from(queue));
        (value & QENA_REQ != 0, value & QENA_STAT != 0)
    }

    /// Rings the transmit doorbell -- `QTX_TAIL`, the last valid descriptor
    /// plus one.
    pub fn transmit_doorbell(&mut self, queue: u32, tail: u32) {
        self.write(QTX_TAIL + 4 * u64::from(queue), tail & 0x1fff);
    }

    /// What the device says its transmit head is -- `QTX_HEAD`, which advances
    /// as descriptors are consumed.
    #[must_use]
    pub fn transmit_head(&self, queue: u32) -> u32 {
        self.read(QTX_HEAD + 4 * u64::from(queue)) & 0x1fff
    }

    /// Disables a transmit queue -- 38.31.3.1.2: the disable flag set first,
    /// then `QENA_REQ` cleared, then `QENA_STAT` polled clear.
    pub fn disable_transmit_queue(&mut self, queue: u32, spins: u32) -> bool {
        self.set_transmit_queue_disable(queue);
        let at = 4 * u64::from(queue);
        let enable = self.read(QTX_ENA + at);
        self.write(QTX_ENA + at, enable & !QENA_REQ);
        for _ in 0..spins {
            if self.read(QTX_ENA + at) & QENA_STAT == 0 {
                return true;
            }
            core::hint::spin_loop();
        }
        false
    }

    /// What a receive queue's enable handshake currently reads.
    ///
    /// Returns `(requested, active)` -- `QENA_REQ` and `QENA_STAT`. The four
    /// combinations are Table 38-418's states: neither is a queue that is off,
    /// both is one that is running, and the two mixed states are a request in
    /// flight in one direction or the other.
    ///
    /// **Read before anything is written**, for the reason the admin queues
    /// taught: firmware had left those sized, and assuming a clean slate would
    /// have enabled a ring at somebody else's size. A queue this platform is
    /// already using is worth knowing about before taking it.
    #[must_use]
    pub fn receive_queue_state(&self, queue: u32) -> (bool, bool) {
        let value = self.read(QRX_ENA + 4 * u64::from(queue));
        (value & QENA_REQ != 0, value & QENA_STAT != 0)
    }

    /// Posts one command and waits for firmware to complete it.
    ///
    /// Written whole into the next free descriptor, the tail advanced, `DD`
    /// polled -- Table 38-340: *"Set by firmware to mark entry done"* -- and
    /// the completed descriptor handed back, because a direct command's answer
    /// lives in it. `spins` bounds the wait.
    ///
    /// The descriptor is written in full, flags included, so a stale `DD` from
    /// whoever used this ring before cannot read as an answer that never came.
    /// Firmware left these rings configured -- measured, not assumed -- so that
    /// is not a hypothetical.
    ///
    /// # Errors
    ///
    /// [`CommandError::NoRing`] before [`Device::enable_admin_queues`],
    /// [`CommandError::NoAnswer`] if `DD` never appears, and
    /// [`CommandError::Refused`] with firmware's return value if it appears
    /// with `ERR` beside it.
    pub fn command(
        &mut self,
        ring: &mut impl Dma,
        request: Descriptor,
        spins: u32,
    ) -> Result<Descriptor, CommandError> {
        let slot = self.post(ring, request)?;
        self.collect(ring, slot, spins)
    }

    /// Writes a command into the ring and tells firmware it is there.
    ///
    /// Returns the byte offset of the descriptor, which [`Device::collect`]
    /// polls. **Split from `command` so that firmware's half of the round trip
    /// can be written by something other than firmware**: with the two joined
    /// there was no instant at which anything but a real device could answer,
    /// so the command path had no test at all. A test posts, fills the slot the
    /// way firmware would, and collects.
    ///
    /// # Errors
    ///
    /// [`CommandError::NoRing`] before [`Device::enable_admin_queues`].
    pub fn post(
        &mut self,
        ring: &mut impl Dma,
        request: Descriptor,
    ) -> Result<usize, CommandError> {
        if !self.ring_enabled {
            return Err(CommandError::NoRing);
        }
        let slot = self.next as usize * DESCRIPTOR_BYTES as usize;
        for (index, word) in request.words.iter().enumerate() {
            put_dma32(ring, slot + 4 * index, *word);
        }
        self.next = (self.next + 1) % RING_DESCRIPTORS;
        // The tail is what tells firmware a descriptor is there -- Table 38-341
        // calls `ATQT` the pointer "software device driver updates".
        self.write(PF_ATQT, self.next);
        Ok(slot)
    }

    /// Waits for firmware to mark the descriptor at `slot` done, and reads it.
    ///
    /// # Errors
    ///
    /// [`CommandError::NoAnswer`] if `DD` never appears, and
    /// [`CommandError::Refused`] with firmware's return value if it appears
    /// with `ERR` beside it.
    pub fn collect(
        &self,
        ring: &impl Dma,
        slot: usize,
        spins: u32,
    ) -> Result<Descriptor, CommandError> {
        for _ in 0..spins {
            // The first word of the same slot, which firmware marks done.
            let first = dma32(ring, slot);
            if first & u32::from(FLAG_DD) != 0 {
                let mut words = [0; 8];
                for (index, word) in words.iter_mut().enumerate() {
                    // Firmware has marked the descriptor done and written its
                    // answer into it.
                    *word = dma32(ring, slot + 4 * index);
                }
                let reply = Descriptor { words };
                if first & u32::from(FLAG_ERR) != 0 {
                    return Err(CommandError::Refused(reply.return_value()));
                }
                return Ok(reply);
            }
            core::hint::spin_loop();
        }
        Err(CommandError::NoAnswer)
    }

    /// Asks `Get Version` and reads what firmware answers.
    ///
    /// Table 38-353, and the datasheet is emphatic about its place: *"This must
    /// be the first command that the software device driver issues before it
    /// can use the queue for other purposes."* Its `Datalen` is 0 -- *"no
    /// external response buffer"* -- so the answer comes back in the
    /// descriptor: major at bytes 24-25 and minor at 26-27, which in a normal
    /// command are the data address.
    ///
    /// # Errors
    ///
    /// As [`Device::command`].
    pub fn get_version(
        &mut self,
        ring: &mut impl Dma,
        spins: u32,
    ) -> Result<(u16, u16), CommandError> {
        let reply = self.command(ring, Descriptor::direct(OPCODE_GET_VERSION), spins)?;
        Ok((
            reply.half(VERSION_MAJOR_AT),
            reply.half(VERSION_MAJOR_AT + 2),
        ))
    }

    /// Asks `Get Link Status` -- Table 38-63 -- without touching the event
    /// enable, which is what bytes 16-17 at zero mean: *"NOP: LSE notification
    /// value is not modified"*.
    ///
    /// # Errors
    ///
    /// As [`Device::command`].
    pub fn link_status(&mut self, ring: &mut impl Dma, spins: u32) -> Result<Link, CommandError> {
        let reply = self.command(ring, Descriptor::direct(OPCODE_GET_LINK_STATUS), spins)?;
        Ok(Link::from_descriptor(&reply))
    }

    /// Asks `Get Switch Configuration` into a buffer and reads it back.
    ///
    /// `device` is the buffer as the device issues it and `buffer` the same
    /// [`SWITCH_BUFFER_BYTES`] as this driver reaches them -- an address and a
    /// slice for one buffer, as with the rings. It is zeroed first so a stale
    /// count cannot be read as this answer, and parsed once firmware has marked
    /// the descriptor done.
    ///
    /// Only the first request is made: a switch with more elements than the
    /// buffer holds reports its total, and the caller can say so rather than
    /// page through what a first driver has no use for.
    ///
    /// # Errors
    ///
    /// As [`Device::command`], and [`CommandError::ShortBuffer`] if `buffer` is
    /// smaller than [`SWITCH_BUFFER_BYTES`].
    ///
    /// # Errors
    ///
    /// As [`Device::command`].
    pub fn switch_configuration(
        &mut self,
        ring: &mut impl Dma,
        device: u64,
        buffer: &mut impl Dma,
        spins: u32,
    ) -> Result<SwitchConfiguration, CommandError> {
        buffer.zero(0, SWITCH_BUFFER_BYTES as usize);
        self.command(
            ring,
            Descriptor::with_buffer(OPCODE_GET_SWITCH_CONFIGURATION, device, SWITCH_BUFFER_BYTES),
            spins,
        )?;
        // Firmware has completed the command, so its writes to the buffer are
        // done -- and this read goes through `Dma`, which is what makes it a
        // read of what the device wrote rather than of what this function
        // zeroed. See the trait: that distinction cost a boot.
        let mut bytes = [0u8; SWITCH_BUFFER_BYTES as usize];
        buffer.read(0, &mut bytes);
        Ok(SwitchConfiguration::parse(&bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every register this file names, at index zero and at the highest index
    /// the datasheet allows, must be inside a page [`REGISTER_PAGES`] asks for.
    ///
    /// **This is the check that keeps a delegation honest.** The kernel maps
    /// exactly those pages; a constant added here whose page is not among them
    /// would read as zero on hardware and be diagnosed as a device that will
    /// not answer, which is the worst kind of wrong -- so it fails here
    /// instead, on a host, in a second.
    #[test]
    fn every_register_this_driver_names_is_in_a_page_it_asks_for() {
        // (offset, highest index, stride) -- an unindexed register is (r, 0, 0).
        let registers: [(u64, u64, u64); 39] = [
            (PFGEN_CTRL, 0, 0),
            (PF_ATQBAL, 0, 0),
            (PF_ATQT, 0, 0),
            (PF_ARQT, 0, 0),
            (PF_FUNC_RID, 0, 0),
            (GLHMC_SDPART, 0, 0),
            (PFHMC_SDCMD, 0, 0),
            (PFHMC_SDDATALOW, 0, 0),
            (PFHMC_SDDATAHIGH, 0, 0),
            (PFHMC_ERRORINFO, 0, 0),
            (PFHMC_ERRORDATA, 0, 0),
            (GLHMC_LANTXOBJSZ, 0, 0),
            (GLHMC_LANRXOBJSZ, 0, 0),
            (GLHMC_LANQMAX, 15, 4),
            (GLHMC_LANTXBASE, 7, 4),
            (GLHMC_LANTXCNT, 7, 4),
            (GLHMC_LANRXBASE, 7, 4),
            (GLHMC_LANRXCNT, 7, 4),
            (PFLAN_QALLOC, 0, 0),
            (PFGEN_PORTNUM, 0, 0),
            (GLLAN_RCTL_0, 0, 0),
            (VSILAN_QBASE, MAX_VSI, 4),
            (QRX_ENA, MAX_RECEIVE_QUEUE, 4),
            (QRX_TAIL, MAX_RECEIVE_QUEUE, 4),
            (QTX_ENA, MAX_RECEIVE_QUEUE, 4),
            (QTX_TAIL, MAX_RECEIVE_QUEUE, 4),
            (QTX_HEAD, MAX_RECEIVE_QUEUE, 4),
            (QTX_CTL, MAX_RECEIVE_QUEUE, 4),
            (GLLAN_TXPRE_QDIS, 11, 4),
            (PFCM_LANCTXDATA, 3, 4),
            (PFCM_LANCTXCTL, 0, 0),
            (PFCM_LANCTXSTAT, 0, 0),
            (PRTPM_SAL, MAX_PORT, 32),
            (PRTPM_SAH, MAX_PORT, 32),
            (GLPRT_GORCL, MAX_PORT, 8),
            (GLPRT_UPRCL, MAX_PORT, 8),
            (GLPRT_BPTCL, MAX_PORT, 8),
            (GLV_RDPC, MAX_VSI, 8),
            (GLV_BPRCL, MAX_VSI, 8),
        ];
        for (offset, highest, stride) in registers {
            for index in [0, highest] {
                let at = offset + stride * index;
                assert!(
                    page_is_mapped(at),
                    "{at:#x} (index {index} of {offset:#x}) is outside REGISTER_PAGES"
                );
                // And the whole 64-bit pair, for the counters that are read as
                // one: a page boundary between the halves would tear.
                assert!(page_is_mapped(at + 4), "{at:#x} straddles a page");
            }
        }
    }

    /// And the list asks for nothing it does not need: every page in it holds a
    /// register the table above names.
    ///
    /// The other direction of the same rule. Without it the list could grow to
    /// the whole BAR and still pass the test above, which would defeat the
    /// point of naming pages at all.
    #[test]
    fn the_pages_asked_for_are_the_pages_used() {
        for page in REGISTER_PAGES {
            assert!(
                page_is_mapped(page),
                "{page:#x} is in the list and not found by the lookup"
            );
        }
        assert!(
            !page_is_mapped(0x3f_f000),
            "the flash beyond the CSR space is not asked for"
        );
        assert!(!page_is_mapped(0), "nor page zero, which names no register");
    }

    /// Memory with a device on the other side of it.
    ///
    /// **The fake that a `&mut [u8]` could not be.** Its whole point is the
    /// `answer`: bytes the device writes *after* the driver has zeroed the
    /// buffer and posted the command, which is the sequence every indirect
    /// admin command performs. Modelling it is what a plain slice made
    /// impossible, and reading the zeroes back instead of the answer is what
    /// went wrong on the SR550 -- see [`Dma`].
    struct FakeDma {
        bytes: core::cell::RefCell<[u8; Self::BYTES]>,
        answer: core::cell::RefCell<Option<(usize, usize, [u8; 64])>>,
        every: core::cell::Cell<bool>,
    }

    impl FakeDma {
        const BYTES: usize = 1024;

        fn new() -> Self {
            Self {
                bytes: core::cell::RefCell::new([0; Self::BYTES]),
                answer: core::cell::RefCell::new(None),
                every: core::cell::Cell::new(false),
            }
        }

        /// Arranges for the device to have written `payload` at `at` by the
        /// time anything looks.
        fn answers(self, at: usize, payload: &[u8]) -> Self {
            let mut bytes = [0u8; 64];
            bytes[..payload.len()].copy_from_slice(payload);
            *self.answer.borrow_mut() = Some((at, payload.len(), bytes));
            self
        }

        /// Marks **every** descriptor slot done, which is a working device
        /// answering every command rather than one.
        ///
        /// A command that issues two requests -- read the VSI, write it back --
        /// lands them in consecutive slots, and a fake that answered only the
        /// first would fail the second for a reason that has nothing to do with
        /// what is being tested.
        fn answers_every_command(self) -> Self {
            self.every.set(true);
            self
        }

        /// What is in it now, for a test that wants to see what was written.
        fn at(&self, at: usize) -> u8 {
            self.bytes.borrow()[at]
        }
    }

    impl Dma for FakeDma {
        fn read(&self, at: usize, into: &mut [u8]) {
            // The device's write lands before every look at it, which is what a
            // register firmware keeps setting looks like from here -- and what
            // a command that issues two requests needs, since the second would
            // otherwise find a ring firmware had answered only once.
            let answer = *self.answer.borrow();
            if let Some((where_, length, payload)) = answer {
                self.bytes.borrow_mut()[where_..where_ + length]
                    .copy_from_slice(&payload[..length]);
            }
            if self.every.get() {
                let done = u32::from(FLAG_DD).to_le_bytes();
                let mut bytes = self.bytes.borrow_mut();
                for slot in (0..Self::BYTES).step_by(DESCRIPTOR_BYTES as usize) {
                    bytes[slot..slot + 4].copy_from_slice(&done);
                }
            }
            let bytes = self.bytes.borrow();
            for (index, slot) in into.iter_mut().enumerate() {
                *slot = bytes.get(at + index).copied().unwrap_or(0);
            }
        }

        fn write(&mut self, at: usize, from: &[u8]) {
            let mut bytes = self.bytes.borrow_mut();
            for (index, byte) in from.iter().enumerate() {
                if let Some(slot) = bytes.get_mut(at + index) {
                    *slot = *byte;
                }
            }
        }

        fn zero(&mut self, at: usize, count: usize) {
            let mut bytes = self.bytes.borrow_mut();
            for index in at..at + count {
                if let Some(slot) = bytes.get_mut(index) {
                    *slot = 0;
                }
            }
        }
    }

    /// A register file with no machine behind it.
    ///
    /// **This is what the move was for.** Every test above this one reads bytes
    /// out of an array; not one of them could reach a register, and the
    /// register half is where every bug this driver has actually had was
    /// found -- a tail written as a count, a ring the device never fetched, a
    /// command bundling five flags firmware would only take one at a time. They
    /// were each found by booting a particular server. They are testable here.
    ///
    /// Sparse and linear, because a test touches a handful of offsets and a
    /// dense array of the X722's four megabytes would be a million entries to
    /// make a point about eight.
    struct Fake {
        slots: core::cell::RefCell<[(u64, u32); Self::SLOTS]>,
        used: core::cell::Cell<usize>,
        /// Every write in order, which is how the ordering rules the datasheet
        /// states -- "software should initialize all other fields" before the
        /// enable bit -- become assertions rather than comments.
        log: core::cell::RefCell<[(u64, u32); Self::SLOTS]>,
        written: core::cell::Cell<usize>,
        /// One register hardware clears by itself, after this many reads: the
        /// reset's `PFSWR` and a queue's `QENA_STAT` both behave this way.
        clears: core::cell::Cell<(u64, u32, u32)>,
        /// And one it sets by itself, which is how firmware marks a descriptor
        /// done.
        sets: core::cell::Cell<(u64, u32, u32)>,
    }

    impl Fake {
        const SLOTS: usize = 96;

        fn new() -> Self {
            Self {
                slots: core::cell::RefCell::new([(u64::MAX, 0); Self::SLOTS]),
                used: core::cell::Cell::new(0),
                log: core::cell::RefCell::new([(u64::MAX, 0); Self::SLOTS]),
                written: core::cell::Cell::new(0),
                clears: core::cell::Cell::new((u64::MAX, 0, 0)),
                sets: core::cell::Cell::new((u64::MAX, 0, 0)),
            }
        }

        /// Makes hardware clear `mask` at `offset` after `reads` reads.
        fn clears(self, offset: u64, mask: u32, reads: u32) -> Self {
            self.clears.set((offset, mask, reads));
            self
        }

        /// Makes hardware set `mask` at `offset` after `reads` reads.
        fn sets(self, offset: u64, mask: u32, reads: u32) -> Self {
            self.sets.set((offset, mask, reads));
            self
        }

        /// The value at `offset`, or zero.
        fn at(&self, offset: u64) -> u32 {
            let slots = self.slots.borrow();
            slots
                .iter()
                .take(self.used.get())
                .find(|(where_, _)| *where_ == offset)
                .map_or(0, |(_, value)| *value)
        }

        fn put(&self, offset: u64, value: u32) {
            let mut slots = self.slots.borrow_mut();
            for slot in slots.iter_mut().take(self.used.get()) {
                if slot.0 == offset {
                    slot.1 = value;
                    return;
                }
            }
            let used = self.used.get();
            assert!(used < Self::SLOTS, "the fake ran out of registers");
            slots[used] = (offset, value);
            self.used.set(used + 1);
        }

        /// The offsets written, in the order they were written.
        fn order(&self) -> [u64; Self::SLOTS] {
            let log = self.log.borrow();
            let mut order = [u64::MAX; Self::SLOTS];
            for (index, entry) in log.iter().take(self.written.get()).enumerate() {
                order[index] = entry.0;
            }
            order
        }

        /// Where `offset` first appears in the write order, for the ordering
        /// rules that say one register must be written after another.
        fn written_at(&self, offset: u64) -> usize {
            self.order()
                .iter()
                .position(|where_| *where_ == offset)
                .unwrap_or_else(|| panic!("{offset:#x} was never written"))
        }
    }

    impl Registers for Fake {
        fn read(&self, offset: u64) -> u32 {
            let (where_, mask, left) = self.clears.get();
            if where_ == offset {
                if left == 0 {
                    self.put(offset, self.at(offset) & !mask);
                } else {
                    self.clears.set((where_, mask, left - 1));
                }
            }
            let (where_, mask, left) = self.sets.get();
            if where_ == offset {
                if left == 0 {
                    self.put(offset, self.at(offset) | mask);
                } else {
                    self.sets.set((where_, mask, left - 1));
                }
            }
            self.at(offset)
        }

        fn write(&mut self, offset: u64, value: u32) {
            let written = self.written.get();
            if written < Self::SLOTS {
                self.log.borrow_mut()[written] = (offset, value);
                self.written.set(written + 1);
            }
            self.put(offset, value);
        }

        fn read64(&self, offset: u64) -> u64 {
            u64::from(self.at(offset)) | u64::from(self.at(offset + 4)) << 32
        }
    }

    /// 38.39.2.1.20: software sets `PFSWR` and **hardware clears it** when the
    /// reset is done, which is the only completion test there is.
    #[test]
    fn a_reset_waits_for_hardware_to_clear_the_bit_it_set() {
        let mut device = Device::new(Fake::new().clears(PFGEN_CTRL, PFSWR, 3));
        assert!(device.reset(16), "the bit cleared on the fourth read");

        // And a device that never clears it is a device that is not answering,
        // which must be said rather than waited on for ever.
        let mut dead = Device::new(Fake::new());
        assert!(!dead.reset(16), "nothing cleared the bit, so nothing reset");
    }

    /// 38.39.2.15.9 is explicit about the order: *"When setting the enable bit,
    /// software should initialize all other fields."* So both base addresses
    /// go down before the length that carries `ATQENABLE`.
    #[test]
    fn the_admin_queues_take_their_lengths_last() {
        let mut device = Device::new(Fake::new());
        device.enable_admin_queues(0x1_0000_0000, 0x1_0000_1000);

        let registers = &device.registers;
        assert_eq!(registers.at(PF_ATQBAL), 0, "the low half of the base");
        assert_eq!(registers.at(PF_ATQBAH), 1, "and the high half");
        assert_eq!(registers.at(PF_ARQBAL), 0x1000);
        assert_eq!(
            registers.at(PF_ATQLEN),
            RING_DESCRIPTORS | QUEUE_ENABLE,
            "the length carries the enable bit"
        );
        assert!(
            registers.written_at(PF_ATQBAH) < registers.written_at(PF_ATQLEN),
            "the base must be complete before the queue is enabled"
        );
        assert!(
            registers.written_at(PF_ATQH) < registers.written_at(PF_ATQBAL),
            "the head is zeroed before a base is named, so an enabled ring does \
             not start from whatever the last owner left"
        );
    }

    /// A command is written into the ring, the tail is advanced to say so, and
    /// firmware's answer comes back out of the same descriptor.
    #[test]
    fn a_command_is_posted_and_its_answer_read_back() {
        let mut ring = FakeDma::new();
        let mut device = Device::new(Fake::new());
        device.enable_admin_queues(0x1_0000_0000, 0x1_0000_1000);

        let slot = device
            .post(&mut ring, Descriptor::direct(OPCODE_GET_VERSION))
            .expect("the ring is enabled");
        assert_eq!(
            device.registers.at(PF_ATQT),
            1,
            "the tail says one descriptor is there"
        );
        assert_eq!(
            dma32(&ring, slot) >> 16,
            u32::from(OPCODE_GET_VERSION),
            "the opcode went into the ring at bytes 2-3"
        );

        // **Firmware's half of the round trip**, which is exactly what could
        // not be written while one call posted and polled: `DD` in the flags at
        // bytes **0-1** -- the opcode is what lives at 2-3 -- and the major
        // version at 24-25 with the minor at 26-27.
        ring.write(slot, &u32::from(FLAG_DD).to_le_bytes());
        ring.write(slot + 24, &(3u32 | 10 << 16).to_le_bytes());

        let reply = device.collect(&ring, slot, 4).expect("firmware answered");
        assert_eq!(
            (
                reply.half(VERSION_MAJOR_AT),
                reply.half(VERSION_MAJOR_AT + 2)
            ),
            (3, 10),
            "major and minor, from bytes 24-27"
        );
    }

    /// A refusal carries firmware's own return value, which is the difference
    /// between "it said no" and "it never answered".
    #[test]
    fn a_refusal_carries_the_return_value_and_silence_is_a_different_error() {
        let mut ring = FakeDma::new();
        let mut device = Device::new(Fake::new());
        device.enable_admin_queues(0, 0);
        let slot = device
            .post(&mut ring, Descriptor::direct(OPCODE_GET_VERSION))
            .expect("the ring is enabled");

        // Flags are bytes 0-1 and the return value bytes 6-7, so word 0's low
        // half carries the flags and word 1's high half the return value.
        ring.write(slot, &u32::from(FLAG_DD | FLAG_ERR).to_le_bytes());
        ring.write(slot + 4, &(0xdu32 << 16).to_le_bytes());
        assert_eq!(
            device.collect(&ring, slot, 4),
            Err(CommandError::Refused(0xd)),
            "EEXIST, and the code is what tells a caller which"
        );

        // A descriptor firmware never marked is silence, not a refusal, and the
        // difference is the whole reason both errors exist.
        let quiet = FakeDma::new();
        assert_eq!(
            device.collect(&quiet, 0, 4),
            Err(CommandError::NoAnswer),
            "a ring firmware never touched is silence, not a refusal"
        );
    }

    /// Before `enable_admin_queues` there is nowhere to post, and saying so is
    /// not the same as saying firmware refused.
    #[test]
    fn a_command_with_no_ring_is_refused_before_anything_is_written() {
        let mut ring = FakeDma::new();
        let mut device: Device<Fake> = Device::new(Fake::new());
        assert_eq!(device.get_version(&mut ring, 4), Err(CommandError::NoRing));
        assert_eq!(device.registers.written.get(), 0, "and no register moved");
        assert_eq!(
            ring.at(0),
            0,
            "and no descriptor was written into a ring the device is not reading"
        );
    }

    /// **A tail written to a queue that is not yet enabled, read back.**
    ///
    /// 38.30.3.3.2 lists the tail before the enable, and this driver has
    /// followed that order and never looked at the register afterwards. A tail
    /// of zero is a queue with no descriptors available -- which on the wire
    /// looks exactly like a queue nothing is being steered to, and that is the
    /// symptom the SR550 has shown for twenty boots.
    #[test]
    fn a_receive_queue_reports_the_tail_it_was_armed_with() {
        let queue = 3;
        let mut device = Device::new(Fake::new().sets(QRX_ENA + 4 * queue, QENA_STAT, 2));
        assert!(device.enable_receive_queue(queue as u32, 8, 16));
        assert_eq!(
            device.receive_tail(queue as u32),
            8,
            "the tail the queue was given is the tail it holds"
        );

        // And arming it again after it is up leaves the same value, so a driver
        // that does both cannot be worse off than one that does either.
        device.arm_receive_queue(queue as u32, 8);
        assert_eq!(device.receive_tail(queue as u32), 8);
    }

    /// The queue mapping section, which is the one the SR550's VSI has never
    /// had written: traffic class 0 given a **power-of-two** count of queues at
    /// an offset, and the valid-sections bit set so firmware reads it.
    #[test]
    fn a_vsi_is_told_which_queues_are_its_own() {
        let mut ring = FakeDma::new().answers_every_command();
        let mut device = Device::new(Fake::new());
        device.enable_admin_queues(0, 0);

        // Firmware's VSI, as the SR550 reports it: every section valid, one
        // queue in traffic class 0.
        let mut buffer = FakeDma::new();
        buffer.write(0, &0x03ffu16.to_le_bytes());

        let (was, now) = device
            .map_receive_queues(&mut ring, 0x18c, 0x1_0000_0000, &mut buffer, 0, 4)
            .expect("firmware answered");
        assert_eq!(was, 0, "it had one queue, which is a field of zero");
        assert_eq!(
            now,
            2 << 9,
            "four queues is a field of two, because the field is a log2"
        );

        let mut sections = [0u8; 2];
        buffer.read(0, &mut sections);
        assert_eq!(
            u16::from_le_bytes(sections) & VSI_SECTION_QUEUE_MAP,
            VSI_SECTION_QUEUE_MAP,
            "firmware reads the section only if it is marked valid"
        );

        let mut flags = [0u8; 2];
        buffer.read(VSI_MAPPING_FLAGS_AT, &mut flags);
        assert_eq!(u16::from_le_bytes(flags), 0, "a contiguous range");

        // One queue is a field of zero and eight is three; three queues rounds
        // down, because the field cannot say three.
        for (asked, expected) in [(1u16, 0u16), (2, 1), (3, 1), (8, 3)] {
            let mut buffer = FakeDma::new();
            let mut ring = FakeDma::new().answers_every_command();
            let (_, now) = device
                .map_receive_queues(&mut ring, 0x18c, 0, &mut buffer, 0, asked)
                .expect("firmware answered");
            assert_eq!(
                now >> 9,
                expected,
                "{asked} queue(s) is a field of {expected}"
            );
        }
    }

    /// **The regression that a slice could not have caught, and the shape of
    /// the boot that caught it.** `Get Switch Configuration` zeroes its buffer,
    /// posts the command, and reads the buffer back; on the SR550 it read the
    /// zeroes and reported nought elements of nought, because a `&mut [u8]`
    /// tells the compiler nothing else writes those bytes and forwarding the
    /// zeroes across an opaque call is then a legal thing to do.
    ///
    /// This is the same sequence against a fake whose device writes *after* the
    /// zeroing. It fails if the answer is ever read from anywhere but the
    /// memory the device wrote.
    #[test]
    fn a_buffer_the_device_filled_is_read_and_not_the_zeroes_that_preceded_it() {
        let ring = FakeDma::new();
        let mut device = Device::new(Fake::new());
        device.enable_admin_queues(0, 0);

        // Firmware's answer to Get Switch Configuration: one element reported
        // of one, then the element itself -- Table 38-201's count at bytes 0-1
        // and total at 2-3, the first element at `SWITCH_ELEMENT_AT`.
        let mut answer = [0u8; 64];
        answer[0..2].copy_from_slice(&1u16.to_le_bytes());
        answer[2..4].copy_from_slice(&1u16.to_le_bytes());
        let mut buffer = FakeDma::new().answers(0, &answer);

        // And firmware marks the descriptor done *after* the request is
        // posted into it, which is the same "written while nobody was looking"
        // the buffer relies on. Written before the post it would simply be
        // overwritten, which is what a first version of this test discovered.
        let mut ring = ring.answers(0, &u32::from(FLAG_DD).to_le_bytes());

        let switch = device
            .switch_configuration(&mut ring, 0x1_0000_0000, &mut buffer, 4)
            .expect("firmware answered");
        assert_eq!(
            (switch.count, switch.total),
            (1, 1),
            "the count came from the buffer the device wrote, not from the \
             zeroes this command put there first"
        );
    }

    /// **The queues are chained onto an interrupt that reports and never
    /// raises**, which is 38.22.5's arrangement for a driver that polls.
    ///
    /// The reset value of `QINT_RQCTL` is zero, and zero is not "no next
    /// queue": `NEXTQ_INDX` of 0 with type `00b` points at receive queue zero,
    /// so a queue left alone terminates its list by pointing back into it. The
    /// datasheet's NULL is `0x7FF`, and this asserts the last queue holds it.
    #[test]
    fn receive_queues_are_chained_onto_an_interrupt_that_only_reports() {
        let mut device = Device::new(Fake::new());
        let read_back = device.report_completions(0, 4);

        for queue in 0..4u64 {
            let control = device.registers.at(QINT_RQCTL + 4 * queue);
            assert_eq!(
                control & (0b11 << 11),
                QINT_ITR0,
                "queue {queue} is on ITR0, whose interval is zero -- not {QINT_ITR_NONE:#x}, \
                 No ITR, which has no expiry to be reported at"
            );
            assert_eq!(
                control & QINT_CAUSE_ENA,
                QINT_CAUSE_ENA,
                "queue {queue} raises its cause, which is what the ITR then processes"
            );
            let next = (control >> QINT_NEXTQ_SHIFT) & QINT_NEXTQ_NONE;
            if queue < 3 {
                assert_eq!(next, queue as u32 + 1, "queue {queue} points at the next");
            } else {
                assert_eq!(
                    next, QINT_NEXTQ_NONE,
                    "the last queue ends the list rather than pointing back into it"
                );
            }
        }

        assert_eq!(
            device.registers.at(PFINT_LNKLST0) & QINT_NEXTQ_NONE,
            0,
            "the list starts at the first queue"
        );
        assert_eq!(
            device.registers.at(PFINT_LNKLST0) >> 11 & 0b11,
            0,
            "of type receive"
        );
        assert_eq!(
            read_back & PFINT_WB_ON_ITR,
            PFINT_WB_ON_ITR,
            "completed descriptors are reported"
        );
        assert_eq!(read_back & PFINT_INTENA, 0, "and no interrupt is enabled");
        assert_eq!(
            device.registers.at(PFINT_ITR0),
            0,
            "ITR0's interval is zero, which the datasheet calls immediate"
        );
    }

    /// One queue is a list of one, which must still terminate.
    #[test]
    fn a_single_receive_queue_still_ends_its_own_list() {
        let mut device = Device::new(Fake::new());
        device.report_completions(7, 1);
        let control = device.registers.at(QINT_RQCTL + 4 * 7);
        assert_eq!(
            (control >> QINT_NEXTQ_SHIFT) & QINT_NEXTQ_NONE,
            QINT_NEXTQ_NONE
        );
        assert_eq!(device.registers.at(PFINT_LNKLST0) & QINT_NEXTQ_NONE, 7);
    }

    /// **A refilled descriptor is a whole descriptor**, write-back included:
    /// hardware left `DD` and a length there, and a driver that wrote only the
    /// buffer address would read the old completion as a new frame.
    #[test]
    fn refilling_a_descriptor_clears_what_hardware_left_in_it() {
        let mut ring = FakeDma::new();
        // A completed descriptor, as hardware writes one back.
        ring.write(RECEIVE_DESCRIPTOR_BYTES as usize * 3, &[0xff; 16]);
        assert!(completed_descriptor(&ring, 3).is_some(), "it reads as done");

        post_receive_descriptor(&mut ring, 3, 0x1_0000_7000);
        assert!(
            completed_descriptor(&ring, 3).is_none(),
            "and after refilling it is a descriptor the device has not touched"
        );
        let mut bytes = [0u8; 8];
        ring.read(RECEIVE_DESCRIPTOR_BYTES as usize * 3, &mut bytes);
        assert_eq!(u64::from_le_bytes(bytes), 0x1_0000_7000, "with its buffer");
    }

    /// **The bug that lost forty-five frames.** `QTX_TAIL` takes a descriptor
    /// *index*, so a ring of eight accepts 0 to 7; writing 8 after filling the
    /// last slot stops the queue. On 2026-09-06 four LACPDUs left the wire and
    /// the fifth put the tail at eight, after which the head sat at six and
    /// forty more frames went nowhere.
    #[test]
    fn the_transmit_cursor_wraps_instead_of_running_past_the_ring() {
        const DEPTH: u16 = 8;
        let mut ring = FakeDma::new();
        let mut device = Device::new(Fake::new());
        device.attach_transmit_ring(DEPTH);

        for expected in 0..u32::from(DEPTH) {
            let at = device.post_frame(&mut ring, 0x1_0000_0000, 60, false);
            assert_eq!(at, Some(expected), "one descriptor per frame, in order");
            assert!(
                device.transmit_tail() < u32::from(DEPTH),
                "a tail of {} is not a valid index into {DEPTH} descriptors",
                device.transmit_tail()
            );
        }
        assert_eq!(
            device.transmit_tail(),
            0,
            "the ninth frame starts the ring again"
        );
    }

    /// An uplink frame needs a context descriptor in front of its data
    /// descriptor, and the pair must be contiguous -- so a frame that would
    /// straddle the end of the ring starts again rather than wrapping between
    /// its own two halves.
    #[test]
    fn an_uplink_frame_takes_two_contiguous_descriptors() {
        const DEPTH: u16 = 4;
        let mut ring = FakeDma::new();
        let mut device = Device::new(Fake::new());
        device.attach_transmit_ring(DEPTH);

        assert_eq!(
            device.post_frame(&mut ring, 0x2000, 60, true),
            Some(1),
            "context, data"
        );
        assert_eq!(device.transmit_tail(), 2);
        assert_eq!(device.post_frame(&mut ring, 0x2000, 60, true), Some(3));
        assert_eq!(device.transmit_tail(), 0, "and the ring is full");
        assert_eq!(
            device.post_frame(&mut ring, 0x2000, 60, true),
            Some(1),
            "the next pair starts at zero, not straddling the end"
        );

        // A ring too short for the pair takes neither half.
        let mut narrow = FakeDma::new();
        let mut small = Device::new(Fake::new());
        small.attach_transmit_ring(1);
        assert_eq!(small.post_frame(&mut narrow, 0x2000, 60, true), None);
    }

    /// A receive queue is enabled by asking and then waiting for hardware to
    /// agree -- `QENA_REQ` set, `QENA_STAT` polled -- and the tail is written
    /// before either, because a queue enabled with a stale tail fetches
    /// descriptors nobody posted.
    #[test]
    fn a_receive_queue_is_enabled_by_asking_and_waiting_for_hardware_to_agree() {
        let queue = 3;
        let mut device = Device::new(Fake::new().sets(QRX_ENA + 4 * queue, QENA_STAT, 2));
        assert!(device.enable_receive_queue(queue as u32, 8, 16));
        assert_eq!(device.registers.at(QRX_TAIL + 4 * queue), 8);
        assert!(
            device.registers.written_at(QRX_TAIL + 4 * queue)
                < device.registers.written_at(QRX_ENA + 4 * queue),
            "the tail is posted before the queue is enabled"
        );

        // Hardware that never agrees is a queue that is not enabled.
        let mut deaf = Device::new(Fake::new());
        assert!(!deaf.enable_receive_queue(queue as u32, 8, 16));
    }

    /// Table 38-340's byte numbering, against the words the ring holds.
    #[test]
    fn descriptor_bytes_follow_table_38_340() {
        let request = Descriptor::direct(0x0607);
        assert_eq!(request.byte(2), 0x07);
        assert_eq!(request.byte(3), 0x06);
        assert_eq!(request.half(2), 0x0607);
        assert_eq!(request.flags(), 0);
        assert_eq!(request.byte(32), 0, "past the end reads as zero");

        let indirect = Descriptor::with_buffer(0x0200, 0x0000_0001_0000_0800, 512);
        assert_eq!(indirect.flags(), FLAG_BUF);
        assert_eq!(indirect.half(4), 512, "Datalen at bytes 4-5");
        assert_eq!(indirect.words[6], 0x1, "data address high at bytes 24-27");
        assert_eq!(indirect.words[7], 0x800, "data address low at bytes 28-31");
        let large = Descriptor::with_buffer(0x0200, 0, 513);
        assert_eq!(
            large.flags(),
            FLAG_BUF | FLAG_LB,
            "longer than AQ_LARGE_BUF sets LB"
        );

        let mut refused = Descriptor::direct(0x0110);
        refused.words[0] |= u32::from(FLAG_DD | FLAG_ERR);
        refused.words[1] |= 0xd << 16;
        assert_eq!(refused.return_value(), 0xd, "return value at bytes 6-7");
    }

    /// Table 38-65's fields, at the descriptor bytes Table 38-64 gives them.
    #[test]
    fn link_status_reads_table_38_65() {
        let mut words = [0u32; 8];
        // Bytes 18 and 19: PHY type and speed, after the two command-flag bytes.
        words[4] = (0x13 << 16) | (0b1000 << 24);
        // Bytes 20 and 21: status and negotiation.
        words[5] = 0b1110_0001 | (0b11 << 8);
        // Bytes 24-25: the maximum frame size.
        words[6] = 0x05ee;
        let link = Link::from_descriptor(&Descriptor { words });
        assert_eq!(link.phy_type, 0x13);
        assert_eq!(link.phy_name(), "10GBASE-T");
        assert_eq!(link.speed_name(), "10 Gb/s");
        assert!(link.up());
        assert!(link.media_available());
        assert!(link.signal_detected());
        assert!(!link.faulted());
        assert_eq!(link.negotiation, 0b11);
        assert_eq!(link.max_frame, 1518);

        let down = Link::from_descriptor(&Descriptor::default());
        assert!(!down.up());
        assert_eq!(down.speed_name(), "no speed");
    }

    /// Tables 38-201 to 38-203: a header, then sixteen bytes per element.
    #[test]
    fn switch_configuration_parses_tables_38_201_to_203() {
        let mut buffer = [0u8; SWITCH_BUFFER_BYTES as usize];
        buffer[0] = 2;
        buffer[2] = 3;
        // A MAC: SEID 0x10, no uplink, downlink 0x20, the default port, port 0.
        let mac = [1, 1, 0x10, 0, 0, 0, 0x20, 0, 0, 0, 0, 2, 0, 0, 0, 0];
        buffer[16..32].copy_from_slice(&mac);
        // A VSI: SEID 0x1ab, uplink 0x10, a regular data port, VSI number 0x17f.
        let vsi = [
            19, 1, 0xab, 0x01, 0x10, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0x7f, 0x01,
        ];
        buffer[32..48].copy_from_slice(&vsi);

        let parsed = SwitchConfiguration::parse(&buffer);
        assert_eq!(parsed.count, 2);
        assert_eq!(parsed.total, 3);
        let elements = parsed.elements();
        assert_eq!(elements[0].kind_name(), "MAC");
        assert_eq!(elements[0].seid, 0x10);
        assert_eq!(elements[0].downlink, 0x20);
        assert_eq!(elements[0].connection, 2);
        assert_eq!(elements[1].kind_name(), "VSI");
        assert_eq!(elements[1].seid, 0x1ab);
        assert_eq!(elements[1].uplink, 0x10);
        assert_eq!(elements[1].number, 0x17f);

        // A count larger than the buffer holds is clamped, not trusted.
        buffer[0] = 0xff;
        buffer[1] = 0xff;
        assert_eq!(
            SwitchConfiguration::parse(&buffer).count,
            SWITCH_ELEMENTS_MAX
        );
    }

    /// 38.30.3.4.3's worked example, reproduced bit for bit.
    #[test]
    fn the_receive_context_matches_the_datasheets_example() {
        // The example: BASE 0x1579A0, QLEN 0x80, DBUFF 12 (1536 bytes), RXMAX
        // 0x600, CRCStrip 1, DSize 0, HSPLIT 0, TPH 0xF; its dwords 7..0 read
        // 00000000 0000021E 01800000 00000000 00200301 00000000 001579A0 00000000.
        let context = ReceiveContext {
            ring: 0x1579A0 * 128,
            descriptors: 0x80,
            buffer_bytes: 1536,
            max_frame: 0x600,
        };
        let mut words = context.words();
        // The example enables all four TPH flags, bits 193-196; this driver
        // leaves them clear, so they are added for the comparison only.
        words[6] |= 0b1_1110;
        assert_eq!(
            words,
            [
                0x0000_0000,
                0x0015_79A0,
                0x0000_0000,
                0x0020_0301,
                0x0000_0000,
                0x0180_0000,
                0x0000_021E,
                0x0000_0000
            ]
        );
    }

    /// 38.26.4's example arithmetic, and Table 38-337's rounding.
    #[test]
    fn private_memory_addresses_follow_38_26_4() {
        // 512 transmit contexts of 128 bytes end at 64 KiB, which is 128 units.
        assert_eq!(receive_base_after(0, 512, 7), 128);
        // One context rounds up to one 512-byte unit; 384 need exactly 96.
        assert_eq!(receive_base_after(0, 1, 7), 1);
        assert_eq!(receive_base_after(0, 384, 7), 96);
        // Receive context 0 at base 128 units: address 64 KiB, so SD 0, PD 16.
        let at = context_location(128, 5, 0);
        assert_eq!(
            (at.address, at.segment, at.page, at.offset),
            (65536, 0, 16, 0)
        );
        // Receive context 384 there is 12 KiB further: PD 19.
        assert_eq!(context_location(128, 5, 384).page, 19);
        // Receive context 3 at base 1 unit: 512 + 96, so PD 0 at offset 608.
        let at = context_location(1, 5, 3);
        assert_eq!((at.segment, at.page, at.offset), (0, 0, 608));
        // Past 2 MB the segment index moves and the page index wraps.
        let at = context_location(4096, 5, 0);
        assert_eq!((at.segment, at.page), (1, 0));
        // The SR550's layout: 384 queues, so receive contexts at 48 KiB and
        // the whole thing spans 15 pages.
        let end = object_area_end(96, 384, 5);
        assert_eq!(end, 48 * 1024 + 12 * 1024);
        assert_eq!(backing_pages_to(end), 15);
        assert_eq!(context_location(96, 5, 0).page, 12);
    }

    /// Table 38-330 and 38.39.2.13.5's fields, from an address above 4 GiB
    /// because that is where this device's window puts them.
    #[test]
    fn descriptors_carry_the_address_bits_the_tables_name() {
        assert_eq!(page_descriptor(0x1_0000_2000), 0x1_0000_2001);
        assert_eq!(
            page_descriptor(0x1_0000_2fff),
            0x1_0000_2001,
            "low bits are not an address"
        );
        let (low, high) = segment_descriptor(0x1_0000_1000, 15);
        assert_eq!(high, 1);
        assert_eq!(low, 0x1000 | (15 << 2) | 1);
        let (low, _) = segment_descriptor(0x1_0000_1000, 512);
        assert_eq!(
            (low >> 2) & 0x3ff,
            512,
            "a full segment's count fits its ten bits"
        );
    }

    /// Tables 38-408, 38-409, 38-411 and 38-412: the write-back's second word.
    #[test]
    fn a_receive_completion_is_decoded_from_the_second_quad_word() {
        // DD and EOP set, broadcast, no error, packet type 11 (MAC, ARP),
        // 60 bytes.
        let qword = 0b11 | (0b10 << 9) | (11u64 << 30) | (60u64 << 38);
        let completion = ReceiveCompletion::decode(qword);
        assert!(completion.end_of_packet());
        assert_eq!(completion.cast_name(), "broadcast");
        assert!(!completion.mac_error());
        assert_eq!(completion.packet_type, 11);
        assert_eq!(completion.length, 60);
        let bad = ReceiveCompletion::decode(0b1 | (1 << 19));
        assert!(bad.mac_error());
        assert!(!bad.end_of_packet());
    }

    /// An Ethernet header, tagged and untagged.
    #[test]
    fn a_frame_header_finds_the_ethertype_behind_a_tag() {
        let mut bytes = [0u8; FrameHeader::BYTES];
        bytes[0..6].copy_from_slice(&[0xff; 6]);
        bytes[6..12].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        bytes[12..14].copy_from_slice(&[0x08, 0x06]);
        let plain = FrameHeader::parse(&bytes);
        assert_eq!(plain.ethertype, 0x0806);
        assert_eq!(plain.ethertype_name(), "ARP");
        assert_eq!(plain.vlan, None);
        assert_eq!(plain.destination, [0xff; 6]);

        bytes[12..14].copy_from_slice(&[0x81, 0x00]);
        bytes[14..16].copy_from_slice(&[0x00, 0x64]);
        bytes[16..18].copy_from_slice(&[0x86, 0xdd]);
        let tagged = FrameHeader::parse(&bytes);
        assert_eq!(tagged.ethertype, 0x86dd);
        assert_eq!(tagged.ethertype_name(), "IPv6");
        assert_eq!(tagged.vlan, Some(100));

        bytes[12..14].copy_from_slice(&[0x00, 0x26]);
        assert_eq!(
            FrameHeader::parse(&bytes).ethertype_name(),
            "an 802.3 length"
        );
    }

    /// The counters are running totals, so only a difference means anything.
    #[test]
    fn counter_deltas_are_differences_and_never_run_backwards() {
        let baseline = PortCounters {
            unicast: 900,
            multicast: 40,
            broadcast: 12,
            octets: 100_000,
            discarded: 3,
            crc_errors: 1,
            ..PortCounters::default()
        };
        let mut later = baseline;
        later.multicast += 7;
        later.broadcast += 2;
        later.octets += 1_100;
        later.discarded += 1;

        let delta = later.since(&baseline);
        assert_eq!(
            delta.unicast, 0,
            "a total that did not move is a delta of zero"
        );
        assert_eq!(delta.multicast, 7);
        assert_eq!(delta.broadcast, 2);
        assert_eq!(delta.octets, 1_100);
        assert_eq!(delta.discarded, 1);
        assert_eq!(delta.crc_errors, 0);
        assert_eq!(delta.packets(), 9);
        assert!(delta.saw_anything());

        // Nothing moved at all: the port saw nothing, and that is the reading
        // the receive investigation turns on.
        let quiet = baseline.since(&baseline);
        assert_eq!(quiet.packets(), 0);
        assert!(
            !quiet.saw_anything(),
            "a wholly idle port must not look busy"
        );

        // A discard alone is still evidence of a live wire.
        let mut discarded_only = baseline;
        discarded_only.discarded += 5;
        let delta = discarded_only.since(&baseline);
        assert_eq!(delta.packets(), 0);
        assert!(delta.saw_anything(), "a discard means something did arrive");

        // Two readings in the wrong order read as nothing, not as a flood.
        let backwards = baseline.since(&later);
        assert_eq!(backwards.multicast, 0);
        assert_eq!(backwards.octets, 0);
        assert!(!backwards.saw_anything());

        let vsi = VsiCounters {
            unicast: 5,
            multicast: 2,
            broadcast: 1,
            discarded: 0,
        };
        assert_eq!(vsi.packets(), 8);
        assert_eq!(vsi.since(&vsi).packets(), 0);
    }

    /// Table 38-428's fields, against the legend of its own worked example.
    ///
    /// The example's Line 7 hex and its legend disagree -- see
    /// [`TransmitContext`] -- so the test is written against the legend, which
    /// is the half that is self-consistent, and against the field table's bit
    /// positions.
    #[test]
    fn the_transmit_context_places_table_38_428s_fields() {
        let context = TransmitContext {
            ring: 0x001579A0 * 128,
            descriptors: 512,
            ready_list: 0x80,
        };
        let words = context.words();

        // Line 0: New_Context at bit 30, BASE at 32-88 in 128-byte units.
        assert_eq!(words[0], 1 << 30, "New_Context must be set at programming");
        assert_eq!(words[1], 0x0015_79A0, "BASE low, in 128-byte units");
        assert_eq!(words[2], 0, "this ring's BASE does not reach past 32 bits");

        // Line 1: HEAD_WBEN clear at bit 32, QLEN at 33-45.
        assert_eq!(words[4], 0, "THEAD_WB is hardware's");
        assert_eq!(
            words[5] & 1,
            0,
            "HEAD_WBEN clear means descriptor write-back"
        );
        assert_eq!((words[5] >> 1) & 0x1fff, 512, "QLEN");

        // Line 7: RDYList at 84-93, the third dword's bits 20-29.
        assert_eq!(
            (words[30] >> 20) & 0x3ff,
            0x80,
            "RDYList from the QS handle"
        );

        // Everything the table calls Internal or Reserved stays zero, which is
        // what New_Context makes safe.
        for (index, word) in words.iter().enumerate() {
            if ![0, 1, 2, 5, 30].contains(&index) {
                assert_eq!(*word, 0, "dword {index} is not a field this driver sets");
            }
        }

        // A ring above 4 GiB puts bits into the second dword rather than
        // losing them, which is where this device's windows actually sit.
        let high = TransmitContext {
            ring: 0x1_0000_0000,
            descriptors: 32,
            ready_list: 0,
        };
        let words = high.words();
        assert_eq!(words[1], 0x0200_0000, "0x1_0000_0000 / 128");
        assert_eq!(words[2], 0);
    }

    /// 38.31.2.1.1's two quad-words.
    #[test]
    fn a_transmit_descriptor_carries_its_length_and_asks_for_a_completion() {
        let (low, high) = transmit_descriptor(0x1_0000_4000, 60);
        assert_eq!(low, 0x1_0000_4000, "qword 0 is the buffer address");
        assert_eq!(high & TX_DTYP_MASK, 0, "DTYP 0x0 is a data descriptor");
        assert_ne!(high & TX_CMD_EOP, 0, "EOP: this descriptor ends the packet");
        assert_ne!(high & TX_CMD_RS, 0, "RS: report the completion");
        assert_eq!(
            (high >> TX_BUFFER_SIZE_SHIFT) & 0x3fff,
            60,
            "Tx Buffer Size"
        );

        // A completed descriptor is the same qword with DTYP reading 0xF.
        let done = (high & !TX_DTYP_MASK) | TX_DTYP_DONE;
        assert_eq!(done & TX_DTYP_MASK, TX_DTYP_DONE);
        assert_ne!(
            high & TX_DTYP_MASK,
            TX_DTYP_DONE,
            "an unsent one is not done"
        );
    }

    /// The transmit counters are running totals, like the receive ones.
    #[test]
    fn transmit_counter_deltas_are_differences() {
        let baseline = TransmitCounters {
            unicast: 4,
            multicast: 0,
            broadcast: 7,
            octets: 900,
        };
        let mut later = baseline;
        later.broadcast += 1;
        later.octets += 60;
        let delta = later.since(&baseline);
        assert_eq!(delta.packets(), 1, "one frame left");
        assert_eq!(delta.broadcast, 1);
        assert_eq!(delta.octets, 60);
        assert_eq!(delta.unicast, 0);
        assert_eq!(baseline.since(&later).packets(), 0, "never runs backwards");
    }
}
