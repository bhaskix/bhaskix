// SPDX-License-Identifier: Apache-2.0
//! TPM 2.0 commands and the CRB interface, as bytes and a state machine --
//! RFC 0089 step 5b.
//!
//! **Transcribed from EDK2**, the TCG specifications' reference
//! implementation: `MdePkg/Include/IndustryStandard/Tpm20.h` for the command
//! constants, `TpmPtp.h` for the CRB registers, and `SecurityPkg`'s
//! `Tpm2Integrity.c` and `Tpm2Ptp.c` for the shape of `TPM2_PCR_Read` and the
//! order of a CRB command. **Commands are big-endian** -- EDK2 swaps every
//! field -- unlike the event log, which is little-endian.
//!
//! **Only `TPM2_PCR_Read` is built here, on purpose.** The service that links
//! this answers one request, a PCR read; a crate that could build an extend, a
//! clear or a hierarchy command would make those reachable through it.
#![no_std]
#![forbid(unsafe_code)]

pub mod command;
pub mod crb;
