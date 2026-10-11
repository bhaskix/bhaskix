// SPDX-License-Identifier: Apache-2.0
//! The FIFO interface, TIS -- one 4 KiB register page per locality, every
//! register a byte (EDK2's `TpmTis.h`, `TIS_PC_REGISTERS`) -- RFC 0089 step 5d.
//!
//! The order of a command is EDK2's `Tpm2TisTpmCommand`, read from source on
//! 2026-10-11: ask for command-ready and wait for it; write the command a byte
//! at a time, no more bytes per burst than the TPM's burst count allows; wait
//! for `stsValid` with `expect` clear; write `tpmGo` and wait for `stsValid`
//! and `dataAvail` -- cancelling once and waiting again if it does not come;
//! read the 10-byte header by bursts, refuse a TPM 1.2's response tag, and
//! read the rest by the header's size; ask for command-ready again at the end,
//! whatever happened. Every access is 8-bit except the cancel, as EDK2's are.
//!
//! **One difference, on purpose**: EDK2 leaves the header loop with a `break`
//! that skips the `for` loop's decrement, so its burst count stands one higher
//! than what is left. Here every byte read spends one, the header's last
//! included, so no byte is ever taken past what the TPM offered.
//!
//! Every wait is **bounded**, as the CRB driver's are.

use crate::Registers;
use crate::command::HEADER;

/// The page's registers, by offset.
pub mod reg {
    /// `TPM_ACCESS`.
    pub const ACCESS: usize = 0x00;
    /// `TPM_INTF_CAPABILITY`.
    pub const INTERFACE_CAPABILITY: usize = 0x14;
    /// `TPM_STS`, its low byte.
    pub const STATUS: usize = 0x18;
    /// `TPM_STS.burstCount`, two bytes, low first.
    pub const BURST_COUNT: usize = 0x19;
    /// `TPM_DATA_FIFO`.
    pub const DATA_FIFO: usize = 0x24;
    /// `TPM_INTERFACE_ID` -- PTP's, at the same offset in both layouts.
    pub const INTERFACE_ID: usize = 0x30;
}

/// The bits this driver uses.
pub mod bit {
    /// `TPM_ACCESS.tpmRegValidSts`.
    pub const ACCESS_VALID: u8 = 1 << 7;
    /// `TPM_ACCESS.activeLocality`.
    pub const ACTIVE: u8 = 1 << 5;
    /// `TPM_ACCESS.requestUse`.
    pub const REQUEST_USE: u8 = 1 << 1;
    /// `TPM_STS.stsValid`.
    pub const STATUS_VALID: u8 = 1 << 7;
    /// `TPM_STS.commandReady`.
    pub const READY: u8 = 1 << 6;
    /// `TPM_STS.tpmGo`.
    pub const GO: u8 = 1 << 5;
    /// `TPM_STS.dataAvail`.
    pub const DATA: u8 = 1 << 4;
    /// `TPM_STS.Expect`.
    pub const EXPECT: u8 = 1 << 3;
    /// `TPM_STS.commandCancel`, bit 24 of the 32-bit register.
    pub const CANCEL: u32 = 1 << 24;
}

/// `TPM_ST_RSP_COMMAND` -- the tag a TPM 1.2 answers with, which EDK2 refuses
/// as the wrong TPM.
pub const TPM12_RESPONSE_TAG: u16 = 0x00C4;

/// Why a command did not complete.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TisError {
    /// `TPM_ACCESS` reads all ones: nothing answers at this page.
    Absent,
    /// The locality never became active.
    LocalityNotGranted,
    /// The TPM never became ready for a command.
    NeverReady,
    /// The burst count stayed zero.
    NoBurst,
    /// The TPM still expected bytes after the whole command was written.
    StillExpecting,
    /// No response, even after a cancel.
    NeverAnswered,
    /// The response carries a TPM 1.2's tag.
    Tpm12Answer,
    /// The response's own size is below a header or above what fits.
    ResponseSize(u32),
}

/// One TIS locality page, driven.
pub struct Tis<R: Registers> {
    regs: R,
    polls: u32,
}

impl<R: Registers> Tis<R> {
    /// `polls` bounds every wait.
    pub fn new(regs: R, polls: u32) -> Self {
        Self { regs, polls }
    }

    /// Asks for locality 0 and waits for it to become active -- EDK2's
    /// `TisPcRequestUseTpm`, presence check first.
    ///
    /// # Errors
    ///
    /// [`TisError::Absent`] or [`TisError::LocalityNotGranted`].
    pub fn request_locality(&mut self) -> Result<(), TisError> {
        if self.regs.read8(reg::ACCESS) == 0xFF {
            return Err(TisError::Absent);
        }
        self.regs.write8(reg::ACCESS, bit::REQUEST_USE);
        if self.wait(reg::ACCESS, bit::ACTIVE | bit::ACCESS_VALID, 0) {
            Ok(())
        } else {
            Err(TisError::LocalityNotGranted)
        }
    }

    /// Sends `command` and reads the response into `response`; returns its
    /// length.
    ///
    /// # Errors
    ///
    /// Any [`TisError`]. The TPM is asked for command-ready afterwards either
    /// way, which is how a TIS TPM is told the exchange is over.
    pub fn execute(&mut self, command: &[u8], response: &mut [u8]) -> Result<usize, TisError> {
        let result = self.exchange(command, response);
        self.regs.write8(reg::STATUS, bit::READY);
        result
    }

    fn exchange(&mut self, command: &[u8], response: &mut [u8]) -> Result<usize, TisError> {
        self.regs.write8(reg::STATUS, bit::READY);
        if !self.wait(reg::STATUS, bit::READY, 0) {
            return Err(TisError::NeverReady);
        }
        let mut sent = 0;
        while sent < command.len() {
            let mut burst = self.burst()?;
            while burst > 0 && sent < command.len() {
                self.regs.write8(reg::DATA_FIFO, command[sent]);
                sent += 1;
                burst -= 1;
            }
        }
        if !self.wait(reg::STATUS, bit::STATUS_VALID, bit::EXPECT) {
            return Err(TisError::StillExpecting);
        }
        self.regs.write8(reg::STATUS, bit::GO);
        if !self.wait(reg::STATUS, bit::STATUS_VALID | bit::DATA, 0) {
            self.regs.write(reg::STATUS, bit::CANCEL);
            if !self.wait(reg::STATUS, bit::STATUS_VALID | bit::DATA, 0) {
                return Err(TisError::NeverAnswered);
            }
        }
        if response.len() < HEADER {
            return Err(TisError::ResponseSize(0));
        }
        let mut read = 0;
        let mut burst = 0u16;
        while read < HEADER {
            if burst == 0 {
                burst = self.burst()?;
            }
            response[read] = self.regs.read8(reg::DATA_FIFO);
            read += 1;
            burst -= 1;
        }
        if u16::from_be_bytes([response[0], response[1]]) == TPM12_RESPONSE_TAG {
            return Err(TisError::Tpm12Answer);
        }
        let total = u32::from_be_bytes([response[2], response[3], response[4], response[5]]);
        let length = total as usize;
        if length < HEADER || length > response.len() {
            return Err(TisError::ResponseSize(total));
        }
        while read < length {
            if burst == 0 {
                burst = self.burst()?;
            }
            response[read] = self.regs.read8(reg::DATA_FIFO);
            read += 1;
            burst -= 1;
        }
        Ok(length)
    }

    /// The burst count, waited for until it is not zero -- EDK2's
    /// `TisPcReadBurstCount`, two byte reads, low first.
    fn burst(&self) -> Result<u16, TisError> {
        (0..self.polls)
            .map(|_| {
                u16::from_le_bytes([
                    self.regs.read8(reg::BURST_COUNT),
                    self.regs.read8(reg::BURST_COUNT + 1),
                ])
            })
            .find(|&count| count != 0)
            .ok_or(TisError::NoBurst)
    }

    /// Waits for every bit of `set` set and every bit of `clear` clear, at
    /// most `polls` reads -- EDK2's `TisPcWaitRegisterBits`.
    fn wait(&self, register: usize, set: u8, clear: u8) -> bool {
        (0..self.polls).any(|_| {
            let value = self.regs.read8(register);
            value & set == set && value & clear == 0
        })
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::command::{TPM_ALG_SHA256, parse_pcr_read_response, pcr_read_command};
    use core::cell::RefCell;
    use std::vec::Vec;

    /// A TPM behind a TIS page, as much of one as these tests need, its state
    /// in a `RefCell` because a FIFO read changes it through `&self`, as a
    /// device read does. It offers `burst` bytes at a time and **counts every
    /// FIFO access past what it last offered**, so a driver that misreads the
    /// burst count is caught even when the bytes would have arrived anyway.
    struct Tpm(RefCell<State>);

    struct State {
        access: u8,
        status: u8,
        burst: u16,
        offered: i32,
        overruns: u32,
        command: Vec<u8>,
        /// The command as it stood at `tpmGo`; `command` is cleared by the
        /// command-ready that ends every exchange.
        started: Vec<u8>,
        answer: Vec<u8>,
        out: Vec<u8>,
        answers: bool,
        grants: bool,
        absent: bool,
        cancels: u32,
        readies: u32,
    }

    impl Tpm {
        fn new(answer: Vec<u8>, burst: u16) -> Self {
            Self(RefCell::new(State {
                access: bit::ACCESS_VALID,
                status: bit::STATUS_VALID,
                burst,
                offered: 0,
                overruns: 0,
                command: Vec::new(),
                started: Vec::new(),
                answer,
                out: Vec::new(),
                answers: true,
                grants: true,
                absent: false,
                cancels: 0,
                readies: 0,
            }))
        }

        fn state(&self) -> std::cell::Ref<'_, State> {
            self.0.borrow()
        }

        fn with(self, change: impl FnOnce(&mut State)) -> Self {
            change(&mut self.0.borrow_mut());
            self
        }
    }

    impl State {
        /// Bytes the command's own header says it has, once six have come.
        fn expected(&self) -> Option<usize> {
            let c = &self.command;
            (c.len() >= 6).then(|| u32::from_be_bytes([c[2], c[3], c[4], c[5]]) as usize)
        }

        fn spend(&mut self) {
            self.offered -= 1;
            if self.offered < 0 {
                self.overruns += 1;
            }
        }
    }

    impl Registers for &Tpm {
        fn read(&self, _offset: usize) -> u32 {
            0
        }

        fn write(&mut self, offset: usize, value: u32) {
            if offset == reg::STATUS && value == bit::CANCEL {
                self.0.borrow_mut().cancels += 1;
            }
        }

        fn read8(&self, offset: usize) -> u8 {
            let mut tpm = self.0.borrow_mut();
            if tpm.absent {
                return 0xFF;
            }
            match offset {
                reg::ACCESS => tpm.access,
                reg::STATUS => tpm.status,
                // Reading the count is where a burst is offered.
                reg::BURST_COUNT => {
                    tpm.offered = i32::from(tpm.burst);
                    tpm.burst.to_le_bytes()[0]
                }
                o if o == reg::BURST_COUNT + 1 => tpm.burst.to_le_bytes()[1],
                reg::DATA_FIFO => {
                    tpm.spend();
                    let byte = tpm.out.pop().unwrap_or(0xFF);
                    if tpm.out.is_empty() {
                        tpm.status = bit::STATUS_VALID;
                    }
                    byte
                }
                _ => 0,
            }
        }

        fn write8(&mut self, offset: usize, value: u8) {
            let mut tpm = self.0.borrow_mut();
            match (offset, value) {
                (reg::ACCESS, bit::REQUEST_USE) if tpm.grants => {
                    tpm.access = bit::ACCESS_VALID | bit::ACTIVE;
                }
                (reg::STATUS, bit::READY) => {
                    tpm.readies += 1;
                    tpm.status = bit::STATUS_VALID | bit::READY;
                    tpm.command.clear();
                    tpm.out.clear();
                }
                (reg::STATUS, bit::GO) if tpm.answers => {
                    tpm.started = tpm.command.clone();
                    tpm.out = tpm.answer.iter().rev().copied().collect();
                    tpm.status = bit::STATUS_VALID | bit::DATA;
                }
                (reg::DATA_FIFO, byte) => {
                    tpm.spend();
                    tpm.command.push(byte);
                    let done = tpm.expected().is_some_and(|n| tpm.command.len() >= n);
                    tpm.status = if done {
                        bit::STATUS_VALID
                    } else {
                        bit::STATUS_VALID | bit::EXPECT
                    };
                }
                _ => {}
            }
        }
    }

    /// A `TPM2_PCR_Read` response for PCR 8, every digest byte `fill` -- the
    /// command module's own builder, which the CRB tests use too.
    fn pcr_read_answer(fill: u8) -> Vec<u8> {
        crate::command::tests::response(TPM_ALG_SHA256, 8, &[fill; 32])
    }

    const POLLS: u32 = 1_000;

    #[test]
    fn a_pcr_read_goes_through_in_bursts_and_comes_back() {
        // Four bytes a burst, so the command and the response each take
        // several, and the header ends partway through one.
        let tpm = Tpm::new(pcr_read_answer(0x5a), 4);
        let mut tis = Tis::new(&tpm, POLLS);
        tis.request_locality().unwrap();
        let command = pcr_read_command(TPM_ALG_SHA256, 8).unwrap();
        let mut response = [0u8; 256];
        let length = tis.execute(&command, &mut response).unwrap();
        assert_eq!(tpm.state().started, command, "the command, byte for byte");
        assert_eq!(
            parse_pcr_read_response(&response[..length], TPM_ALG_SHA256, 8, 32),
            Ok(&[0x5a; 32][..])
        );
        assert_eq!(tpm.state().overruns, 0, "no byte past a burst");
        assert_eq!(tpm.state().readies, 2, "ready before, and ready after");
    }

    #[test]
    fn nothing_answering_at_the_page_is_said() {
        let tpm = Tpm::new(Vec::new(), 4).with(|t| t.absent = true);
        assert_eq!(
            Tis::new(&tpm, POLLS).request_locality(),
            Err(TisError::Absent)
        );
        let tpm = Tpm::new(Vec::new(), 4).with(|t| t.grants = false);
        assert_eq!(
            Tis::new(&tpm, POLLS).request_locality(),
            Err(TisError::LocalityNotGranted)
        );
    }

    #[test]
    fn a_burst_count_that_stays_zero_is_an_error_not_a_hang() {
        let tpm = Tpm::new(pcr_read_answer(0), 0);
        let command = pcr_read_command(TPM_ALG_SHA256, 8).unwrap();
        let mut response = [0u8; 256];
        assert_eq!(
            Tis::new(&tpm, POLLS).execute(&command, &mut response),
            Err(TisError::NoBurst)
        );
    }

    #[test]
    fn a_tpm_that_never_answers_is_cancelled_and_then_refused() {
        let tpm = Tpm::new(pcr_read_answer(0), 4).with(|t| t.answers = false);
        let command = pcr_read_command(TPM_ALG_SHA256, 8).unwrap();
        let mut response = [0u8; 256];
        assert_eq!(
            Tis::new(&tpm, POLLS).execute(&command, &mut response),
            Err(TisError::NeverAnswered)
        );
        assert_eq!(tpm.state().cancels, 1, "cancelled once, as EDK2 does");
        assert_eq!(tpm.state().readies, 2, "and made ready again at the end");
    }

    #[test]
    fn a_tpm_still_expecting_bytes_is_not_started() {
        // The command claims two bytes more than it has.
        let mut command = pcr_read_command(TPM_ALG_SHA256, 8).unwrap().to_vec();
        let claimed = command.len() as u32 + 2;
        command[2..6].copy_from_slice(&claimed.to_be_bytes());
        let tpm = Tpm::new(pcr_read_answer(0), 4);
        let mut response = [0u8; 256];
        assert_eq!(
            Tis::new(&tpm, POLLS).execute(&command, &mut response),
            Err(TisError::StillExpecting)
        );
    }

    #[test]
    fn a_response_larger_than_the_caller_holds_is_refused() {
        let tpm = Tpm::new(pcr_read_answer(0), 64);
        let command = pcr_read_command(TPM_ALG_SHA256, 8).unwrap();
        let mut response = [0u8; 20];
        let size = pcr_read_answer(0).len() as u32;
        assert_eq!(
            Tis::new(&tpm, POLLS).execute(&command, &mut response),
            Err(TisError::ResponseSize(size))
        );
    }

    #[test]
    fn a_tpm_1_2_answer_is_refused() {
        let mut answer = pcr_read_answer(0);
        answer[..2].copy_from_slice(&TPM12_RESPONSE_TAG.to_be_bytes());
        let tpm = Tpm::new(answer, 64);
        let command = pcr_read_command(TPM_ALG_SHA256, 8).unwrap();
        let mut response = [0u8; 256];
        assert_eq!(
            Tis::new(&tpm, POLLS).execute(&command, &mut response),
            Err(TisError::Tpm12Answer)
        );
    }
}
