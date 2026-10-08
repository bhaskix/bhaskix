// SPDX-License-Identifier: Apache-2.0
//! The command-response buffer interface, CRB -- one 4 KiB register page per
//! locality (EDK2's `TpmPtp.h`, `PTP_CRB_REGISTERS`).
//!
//! The order of a command is EDK2's `PtpCrbTpmCommand`: wait for idle, ask for
//! command-ready and wait for it, write the command into the data buffer and
//! point the command and response registers at it, set Start and wait for the
//! TPM to clear it, read the response by its own size, go idle. Every wait is
//! **bounded**: a TPM that does not answer is an error to report, not a hang.

/// The page's registers, by offset.
pub mod reg {
    /// `LocalityControl`.
    pub const LOCALITY_CONTROL: usize = 0x08;
    /// `LocalityStatus`.
    pub const LOCALITY_STATUS: usize = 0x0C;
    /// `CrbControlRequest`.
    pub const REQUEST: usize = 0x40;
    /// `CrbControlStatus`.
    pub const STATUS: usize = 0x44;
    /// `CrbControlStart`.
    pub const START: usize = 0x4C;
    /// `CrbControlCommandSize`.
    pub const COMMAND_SIZE: usize = 0x58;
    /// `CrbControlCommandAddressLow`.
    pub const COMMAND_LOW: usize = 0x5C;
    /// `CrbControlCommandAddressHigh`.
    pub const COMMAND_HIGH: usize = 0x60;
    /// `CrbControlResponseSize`.
    pub const RESPONSE_SIZE: usize = 0x64;
    /// `CrbControlResponseAddrss` (sic), 64 bits, written as two halves.
    pub const RESPONSE_LOW: usize = 0x68;
    /// Its upper half.
    pub const RESPONSE_HIGH: usize = 0x6C;
    /// `CrbDataBuffer`.
    pub const BUFFER: usize = 0x80;
    /// Bytes in it.
    pub const BUFFER_SIZE: usize = 0xF80;
}

/// The bits this driver uses.
pub mod bit {
    /// `LocalityControl.requestAccess`.
    pub const REQUEST_ACCESS: u32 = 1 << 0;
    /// `LocalityStatus.Granted`.
    pub const GRANTED: u32 = 1 << 0;
    /// `CrbControlRequest.cmdReady`.
    pub const COMMAND_READY: u32 = 1 << 0;
    /// `CrbControlRequest.goIdle`.
    pub const GO_IDLE: u32 = 1 << 1;
    /// `CrbControlStatus.tpmIdle`.
    pub const IDLE: u32 = 1 << 1;
    /// `CrbControlStart.Start`.
    pub const START: u32 = 1 << 0;
}

/// The register page, as the caller maps it. The caller owns the mapping and
/// the only `unsafe` there is; this crate holds no address -- `bhaskix-ahci`'s
/// shape, for the same reason.
pub trait Registers {
    /// Reads the 32-bit register at `offset` from the page's start.
    fn read(&self, offset: usize) -> u32;
    /// Writes it.
    fn write(&mut self, offset: usize, value: u32);
}

/// Why a command did not complete.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CrbError {
    /// Locality 0 was not granted.
    LocalityNotGranted,
    /// The TPM never went idle before a command.
    NeverIdle,
    /// The TPM never became ready for a command.
    NeverReady,
    /// The TPM never cleared Start: it did not finish the command.
    NeverFinished,
    /// The command is larger than the data buffer.
    CommandTooLarge,
    /// The response's own size is below a header or above what fits.
    ResponseSize(u32),
}

/// One CRB locality page, driven.
pub struct Crb<R: Registers> {
    regs: R,
    buffer: u64,
    polls: u32,
}

impl<R: Registers> Crb<R> {
    /// `page` is the page's **physical** address, which the command and
    /// response registers must hold; `polls` bounds every wait.
    pub fn new(regs: R, page: u64, polls: u32) -> Self {
        Self {
            regs,
            buffer: page + reg::BUFFER as u64,
            polls,
        }
    }

    /// Asks for locality 0 and waits for it.
    ///
    /// # Errors
    ///
    /// [`CrbError::LocalityNotGranted`].
    pub fn request_locality(&mut self) -> Result<(), CrbError> {
        self.regs.write(reg::LOCALITY_CONTROL, bit::REQUEST_ACCESS);
        if self.wait(reg::LOCALITY_STATUS, bit::GRANTED, bit::GRANTED) {
            Ok(())
        } else {
            Err(CrbError::LocalityNotGranted)
        }
    }

    /// Sends `command` and reads the response into `response`; returns its
    /// length.
    ///
    /// # Errors
    ///
    /// Any [`CrbError`]. The TPM is asked to go idle afterwards either way.
    pub fn execute(&mut self, command: &[u8], response: &mut [u8]) -> Result<usize, CrbError> {
        if command.len() > reg::BUFFER_SIZE {
            return Err(CrbError::CommandTooLarge);
        }
        let result = self.exchange(command, response);
        self.regs.write(reg::REQUEST, bit::GO_IDLE);
        result
    }

    fn exchange(&mut self, command: &[u8], response: &mut [u8]) -> Result<usize, CrbError> {
        if !self.wait(reg::STATUS, bit::IDLE, bit::IDLE) {
            return Err(CrbError::NeverIdle);
        }
        self.regs.write(reg::REQUEST, bit::COMMAND_READY);
        if !self.wait(reg::REQUEST, bit::COMMAND_READY, 0) || !self.wait(reg::STATUS, bit::IDLE, 0)
        {
            return Err(CrbError::NeverReady);
        }
        for (index, chunk) in command.chunks(4).enumerate() {
            let mut word = [0u8; 4];
            word[..chunk.len()].copy_from_slice(chunk);
            self.regs
                .write(reg::BUFFER + index * 4, u32::from_le_bytes(word));
        }
        let size = reg::BUFFER_SIZE as u32;
        self.regs
            .write(reg::COMMAND_HIGH, (self.buffer >> 32) as u32);
        self.regs.write(reg::COMMAND_LOW, self.buffer as u32);
        self.regs.write(reg::COMMAND_SIZE, size);
        self.regs.write(reg::RESPONSE_LOW, self.buffer as u32);
        self.regs
            .write(reg::RESPONSE_HIGH, (self.buffer >> 32) as u32);
        self.regs.write(reg::RESPONSE_SIZE, size);
        self.regs.write(reg::START, bit::START);
        if !self.wait(reg::START, bit::START, 0) {
            return Err(CrbError::NeverFinished);
        }
        // The response's own size, big-endian at byte 2 of its header.
        let mut head = [0u8; 8];
        for (index, chunk) in head.chunks_mut(4).enumerate() {
            chunk.copy_from_slice(&self.regs.read(reg::BUFFER + index * 4).to_le_bytes());
        }
        let total = u32::from_be_bytes([head[2], head[3], head[4], head[5]]);
        let length = total as usize;
        if !(crate::command::HEADER..=reg::BUFFER_SIZE).contains(&length) || length > response.len()
        {
            return Err(CrbError::ResponseSize(total));
        }
        for (index, chunk) in response[..length].chunks_mut(4).enumerate() {
            let word = self.regs.read(reg::BUFFER + index * 4).to_le_bytes();
            chunk.copy_from_slice(&word[..chunk.len()]);
        }
        Ok(length)
    }

    /// Waits for `register & mask == want`, at most `polls` reads.
    fn wait(&self, register: usize, mask: u32, want: u32) -> bool {
        (0..self.polls).any(|_| self.regs.read(register) & mask == want)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::command::{TPM_ALG_SHA256, parse_pcr_read_response, pcr_read_command};
    use std::vec::Vec;

    /// A TPM behind a CRB page, as much of one as these tests need: it grants
    /// the locality, becomes ready when asked, and on Start answers the
    /// command in its buffer with `answer` -- unless told to misbehave.
    struct Tpm {
        page: [u32; 1024],
        answer: Vec<u8>,
        grant: bool,
        finish: bool,
        writes: Vec<(usize, u32)>,
    }

    impl Tpm {
        fn new(answer: Vec<u8>) -> Self {
            let mut page = [0u32; 1024];
            page[reg::STATUS / 4] = bit::IDLE;
            Self {
                page,
                answer,
                grant: true,
                finish: true,
                writes: Vec::new(),
            }
        }
    }

    impl Registers for &mut Tpm {
        fn read(&self, offset: usize) -> u32 {
            self.page[offset / 4]
        }

        fn write(&mut self, offset: usize, value: u32) {
            self.writes.push((offset, value));
            self.page[offset / 4] = value;
            match (offset, value) {
                (reg::LOCALITY_CONTROL, bit::REQUEST_ACCESS) if self.grant => {
                    self.page[reg::LOCALITY_STATUS / 4] = bit::GRANTED;
                }
                (reg::REQUEST, bit::COMMAND_READY) => {
                    self.page[reg::REQUEST / 4] = 0;
                    self.page[reg::STATUS / 4] = 0;
                }
                (reg::REQUEST, bit::GO_IDLE) => {
                    self.page[reg::REQUEST / 4] = 0;
                    self.page[reg::STATUS / 4] = bit::IDLE;
                }
                (reg::START, bit::START) if self.finish => {
                    for (index, chunk) in self.answer.chunks(4).enumerate() {
                        let mut word = [0u8; 4];
                        word[..chunk.len()].copy_from_slice(chunk);
                        self.page[reg::BUFFER / 4 + index] = u32::from_le_bytes(word);
                    }
                    self.page[reg::START / 4] = 0;
                }
                _ => {}
            }
        }
    }

    #[test]
    fn a_pcr_read_goes_through_and_comes_back() {
        let digest = [0x42u8; 32];
        let mut tpm = Tpm::new(crate::command::tests::response(TPM_ALG_SHA256, 9, &digest));
        let mut crb = Crb::new(&mut tpm, 0xfed4_0000, 1000);
        crb.request_locality().unwrap();
        let command = pcr_read_command(TPM_ALG_SHA256, 9).unwrap();
        let mut response = [0u8; 128];
        let length = crb.execute(&command, &mut response).unwrap();
        assert_eq!(
            parse_pcr_read_response(&response[..length], TPM_ALG_SHA256, 9, 32),
            Ok(&digest[..])
        );
        // The command and response registers named the buffer's physical
        // address, and the TPM was sent idle afterwards.
        let writes = &tpm.writes;
        assert!(writes.contains(&(reg::COMMAND_LOW, 0xfed4_0080)));
        assert!(writes.contains(&(reg::RESPONSE_LOW, 0xfed4_0080)));
        assert_eq!(writes.last(), Some(&(reg::REQUEST, bit::GO_IDLE)));
        // Ready was asked for before the command was written, and Start came
        // after everything else.
        let ready = writes
            .iter()
            .position(|&w| w == (reg::REQUEST, bit::COMMAND_READY));
        let first_data = writes.iter().position(|&(o, _)| o == reg::BUFFER);
        let start = writes.iter().position(|&w| w == (reg::START, bit::START));
        assert!(ready < first_data && first_data < start);
    }

    #[test]
    fn a_tpm_that_never_finishes_is_an_error_not_a_hang() {
        let mut tpm = Tpm::new(Vec::new());
        tpm.finish = false;
        let mut crb = Crb::new(&mut tpm, 0xfed4_0000, 1000);
        let command = pcr_read_command(TPM_ALG_SHA256, 9).unwrap();
        let mut response = [0u8; 128];
        assert_eq!(
            crb.execute(&command, &mut response),
            Err(CrbError::NeverFinished)
        );
        assert_eq!(tpm.writes.last(), Some(&(reg::REQUEST, bit::GO_IDLE)));
    }

    #[test]
    fn a_locality_never_granted_is_said() {
        let mut tpm = Tpm::new(Vec::new());
        tpm.grant = false;
        let mut crb = Crb::new(&mut tpm, 0xfed4_0000, 1000);
        assert_eq!(crb.request_locality(), Err(CrbError::LocalityNotGranted));
    }

    #[test]
    fn a_response_larger_than_the_caller_holds_is_refused() {
        let digest = [0x42u8; 32];
        let mut tpm = Tpm::new(crate::command::tests::response(TPM_ALG_SHA256, 9, &digest));
        let mut crb = Crb::new(&mut tpm, 0xfed4_0000, 1000);
        let command = pcr_read_command(TPM_ALG_SHA256, 9).unwrap();
        let mut small = [0u8; 16];
        assert!(matches!(
            crb.execute(&command, &mut small),
            Err(CrbError::ResponseSize(_))
        ));
    }
}
