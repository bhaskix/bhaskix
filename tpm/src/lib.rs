// SPDX-License-Identifier: Apache-2.0
//! TPM 2.0 commands and the CRB and TIS interfaces, as bytes and state
//! machines -- RFC 0089 steps 5b and 5d.
//!
//! **Transcribed from EDK2**, the TCG specifications' reference
//! implementation: `MdePkg/Include/IndustryStandard/Tpm20.h` for the command
//! constants, `TpmPtp.h` for the CRB registers, and `SecurityPkg`'s
//! `Tpm2Integrity.c` and `Tpm2Ptp.c` for the shape of `TPM2_PCR_Read` and the
//! order of a CRB command, `TpmTis.h` and `Tpm2Tis.c` for TIS's. **Commands are big-endian** -- EDK2 swaps every
//! field -- unlike the event log, which is little-endian.
//!
//! **Only `TPM2_PCR_Read` is built here, on purpose.** The service that links
//! this answers one request, a PCR read; a crate that could build an extend, a
//! clear or a hierarchy command would make those reachable through it.
#![no_std]
#![forbid(unsafe_code)]

pub mod command;
pub mod crb;
pub mod tis;

use crb::{Crb, CrbError};
use tis::{Tis, TisError};

/// The register page, as the caller maps it. The caller owns the mapping and
/// the only `unsafe` there is; this crate holds no address -- `bhaskix-ahci`'s
/// shape, for the same reason.
pub trait Registers {
    /// Reads the 32-bit register at `offset` from the page's start.
    fn read(&self, offset: usize) -> u32;
    /// Writes it.
    fn write(&mut self, offset: usize, value: u32);
    /// Reads the 8-bit register at `offset`. TIS's registers are bytes, and
    /// its FIFO gives up a byte per read: reading it as part of a word would
    /// take its neighbours too, so there is no default built from [`read`].
    ///
    /// [`read`]: Registers::read
    fn read8(&self, offset: usize) -> u8;
    /// Writes it.
    fn write8(&mut self, offset: usize, value: u8);
}

/// Which interface a TPM's page speaks -- EDK2's `Tpm2GetPtpInterface`, read
/// from source on 2026-10-11, from `TPM_INTERFACE_ID` (0x30) and
/// `TPM_INTF_CAPABILITY` (0x14).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Interface {
    /// The command-response buffer.
    Crb,
    /// PTP's FIFO, driven as TIS.
    Fifo,
    /// TIS 1.3.
    Tis,
    /// `TPM_ACCESS` reads all ones: nothing is there.
    Absent,
    /// An interface identifier none of the above matches.
    Unknown(u32),
}

/// Reads which interface the page at `regs` speaks.
pub fn interface(regs: &impl Registers) -> Interface {
    if regs.read8(tis::reg::ACCESS) == 0xFF {
        return Interface::Absent;
    }
    let id = regs.read(tis::reg::INTERFACE_ID);
    let capability = regs.read(tis::reg::INTERFACE_CAPABILITY);
    let (kind, version) = (id & 0xF, (id >> 4) & 0xF);
    let (cap_fifo, cap_crb) = (id & (1 << 13) != 0, id & (1 << 14) != 0);
    if kind == 1 && (version == 1 || version == 2) && cap_crb {
        return Interface::Crb;
    }
    if kind == 0 && version == 0 && cap_fifo && (capability >> 28) & 0x7 == 3 {
        return Interface::Fifo;
    }
    if kind == 0xF {
        return Interface::Tis;
    }
    Interface::Unknown(id)
}

/// Why a TPM did not answer, on whichever interface.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceError {
    /// The CRB conversation failed.
    Crb(CrbError),
    /// The TIS conversation failed.
    Tis(TisError),
}

/// A TPM on either interface, as `bin/tpmd` drives it.
pub enum Tpm<R: Registers> {
    /// Driven through the command-response buffer.
    Crb(Crb<R>),
    /// Driven through the FIFO.
    Tis(Tis<R>),
}

impl<R: Registers> Tpm<R> {
    /// Reads the interface and builds its driver. `page` is the page's
    /// physical address, which CRB needs; `polls` bounds every wait.
    ///
    /// # Errors
    ///
    /// The [`Interface`] read, when it is none this crate drives.
    pub fn new(regs: R, page: u64, polls: u32) -> Result<Self, Interface> {
        match interface(&regs) {
            Interface::Crb => Ok(Self::Crb(Crb::new(regs, page, polls))),
            Interface::Fifo | Interface::Tis => Ok(Self::Tis(Tis::new(regs, polls))),
            other => Err(other),
        }
    }

    /// Which interface it is driven through.
    pub fn interface(&self) -> Interface {
        match self {
            Self::Crb(_) => Interface::Crb,
            Self::Tis(_) => Interface::Tis,
        }
    }

    /// Asks for locality 0.
    ///
    /// # Errors
    ///
    /// The interface's own.
    pub fn request_locality(&mut self) -> Result<(), DeviceError> {
        match self {
            Self::Crb(crb) => crb.request_locality().map_err(DeviceError::Crb),
            Self::Tis(tis) => tis.request_locality().map_err(DeviceError::Tis),
        }
    }

    /// Sends `command` and reads the response; returns its length.
    ///
    /// # Errors
    ///
    /// The interface's own.
    pub fn execute(&mut self, command: &[u8], response: &mut [u8]) -> Result<usize, DeviceError> {
        match self {
            Self::Crb(crb) => crb.execute(command, response).map_err(DeviceError::Crb),
            Self::Tis(tis) => tis.execute(command, response).map_err(DeviceError::Tis),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A page that answers fixed values at the three registers detection reads.
    struct Fixed {
        access: u8,
        id: u32,
        capability: u32,
    }

    impl Registers for Fixed {
        fn read(&self, offset: usize) -> u32 {
            match offset {
                tis::reg::INTERFACE_ID => self.id,
                tis::reg::INTERFACE_CAPABILITY => self.capability,
                _ => 0,
            }
        }
        fn write(&mut self, _: usize, _: u32) {}
        fn read8(&self, offset: usize) -> u8 {
            if offset == tis::reg::ACCESS {
                self.access
            } else {
                0
            }
        }
        fn write8(&mut self, _: usize, _: u8) {}
    }

    fn found(id: u32, capability: u32) -> Interface {
        interface(&Fixed {
            access: 0x81,
            id,
            capability,
        })
    }

    /// One case per condition in EDK2's `Tpm2GetPtpInterface`.
    #[test]
    fn the_interface_is_read_as_edk2_reads_it() {
        const CAP_FIFO: u32 = 1 << 13;
        const CAP_CRB: u32 = 1 << 14;
        const PTP: u32 = 3 << 28;
        assert_eq!(found(0x1 | (1 << 4) | CAP_CRB, 0), Interface::Crb);
        assert_eq!(found(0x1 | (2 << 4) | CAP_CRB, 0), Interface::Crb, "CRB v2");
        assert_eq!(
            found(0x1 | (1 << 4), 0),
            Interface::Unknown(0x11),
            "CRB without CapCRB"
        );
        assert_eq!(found(CAP_FIFO, PTP), Interface::Fifo);
        assert_eq!(
            found(CAP_FIFO, 2 << 28),
            Interface::Unknown(CAP_FIFO),
            "FIFO, TIS 1.3 capability"
        );
        assert_eq!(found(0xF, 0), Interface::Tis);
        assert_eq!(found(0x2, 0), Interface::Unknown(0x2));
        let absent = Fixed {
            access: 0xFF,
            id: 0x1 | (1 << 4) | CAP_CRB,
            capability: 0,
        };
        assert_eq!(interface(&absent), Interface::Absent);
    }
}
