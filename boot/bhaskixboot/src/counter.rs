// SPDX-License-Identifier: Apache-2.0
//! The rollback counter, from the loader's side -- RFC 0100 step 2.
//!
//! Every byte sent and every decision is `bhaskix-rollback`'s, host-tested;
//! this module is the firmware calls that carry them, and the report. It runs
//! before `ExitBootServices`, through the TCG2 protocol's `SubmitCommand`.
//!
//! **The loader's writes, all of them**: the slot record (step 1), and here
//! one TPM NV index -- created once, on the first boot that finds a slot disk;
//! a bit set when a set marked good is above the floor; and a write lock on
//! every boot that finds the index, proven by a write the TPM must refuse.

use bhaskix_rollback::{self as rollback, Booted, ResponseError};

use crate::efi::{self, SystemTable, Tcg2};
use crate::{Line, diag};

/// The rollback counter, as this boot found it.
pub enum Counter {
    /// The index is this loader's and was read.
    Here {
        /// The TPM it lives in.
        tcg2: *mut Tcg2,
        /// Its bits.
        bits: u64,
    },
    /// There is none this boot can use; the reason is already reported.
    Absent,
}

impl Counter {
    /// The floor a set's security version is checked against: 0 with no
    /// counter, which refuses nothing.
    pub fn floor(&self) -> u32 {
        match self {
            Self::Here { bits, .. } => rollback::floor(*bits),
            Self::Absent => 0,
        }
    }
}

/// Bytes a response may take: the longest here is a public area with a
/// policy and a name, well under this.
const RESPONSE: usize = 256;

/// Sends `command` and gives back the response, or the firmware's status.
fn submit<'a>(
    tcg2: *mut Tcg2,
    command: &[u8],
    response: &'a mut [u8; RESPONSE],
) -> Result<&'a [u8], usize> {
    efi::submit_command(tcg2, command, response).map(|()| &response[..])
}

/// One line, in capitals as the loader's other warnings are, for a slot disk
/// whose owner has asked for slots and is not getting the counter with them.
fn absent(why: &str, code: Option<u64>) -> Counter {
    let mut line = Line::new();
    line.push("bhaskixboot: NO ROLLBACK COUNTER: ");
    line.push(why);
    if let Some(code) = code {
        line.push(" (");
        line.push_hex(code);
        line.push(")");
    }
    line.push(" -- an older signed set would boot\r\n");
    diag(line.as_str());
    Counter::Absent
}

/// The code a response refusal carries, for the report.
fn code_of(error: ResponseError) -> u64 {
    match error {
        ResponseError::Code(code) => u64::from(code),
        ResponseError::Size(size) => u64::from(size),
        ResponseError::Tag(tag) => u64::from(tag),
        ResponseError::Truncated | ResponseError::Shape => 0,
    }
}

/// Finds the counter, creating it when this boot found a slot disk and the
/// TPM has none. Reports what it found, and whether the TPM's owner has a
/// password -- without one, anything that can command this TPM can delete
/// the counter, which no attribute an owner may set prevents.
pub fn open(table: *mut SystemTable, slot_disk: bool) -> Counter {
    let Some(tcg2) = efi::tcg2(table) else {
        if slot_disk {
            return absent("no TPM", None);
        }
        diag("bhaskixboot: rollback counter: no TPM\r\n");
        return Counter::Absent;
    };
    let mut response = [0u8; RESPONSE];
    let public = match submit(tcg2, &rollback::read_public(), &mut response) {
        Err(status) => return absent("the TPM did not answer", Some(status as u64)),
        Ok(bytes) => match rollback::parse_read_public(bytes) {
            Err(error) => {
                return absent("the TPM refused NV_ReadPublic", Some(code_of(error)));
            }
            Ok(public) => public,
        },
    };
    report_owner(tcg2);
    let public = match public {
        Some(public) if !public.is_ours() => {
            return absent("its index holds another program's", None);
        }
        Some(public) => public,
        None if !slot_disk => {
            diag(
                "bhaskixboot: rollback counter: none in this TPM; one is created on the first \
                 boot with a slot disk\r\n",
            );
            return Counter::Absent;
        }
        None => {
            let created = submit(tcg2, &rollback::define(), &mut response)
                .map_err(|status| status as u64)
                .and_then(|bytes| rollback::parse_status(bytes).map_err(code_of));
            if let Err(code) = created {
                return absent("the TPM would not create it", Some(code));
            }
            diag("bhaskixboot: rollback counter: created in the TPM\r\n");
            let mut line = Line::new();
            line.push("bhaskixboot: rollback counter: index ");
            line.push_hex(u64::from(rollback::INDEX));
            line.push(", 64 versions, none recorded\r\n");
            diag(line.as_str());
            return Counter::Here { tcg2, bits: 0 };
        }
    };
    let bits = if public.written() {
        let read = submit(tcg2, &rollback::read(), &mut response)
            .map_err(|status| status as u64)
            .and_then(|bytes| rollback::parse_read(bytes).map_err(code_of));
        match read {
            Ok(bits) => bits,
            Err(code) => return absent("the TPM would not read it", Some(code)),
        }
    } else {
        0
    };
    let mut line = Line::new();
    line.push("bhaskixboot: rollback counter: at ");
    line.push_dec(u64::from(rollback::floor(bits)));
    line.push("; a set below that version is refused\r\n");
    diag(line.as_str());
    Counter::Here { tcg2, bits }
}

/// Says whether the TPM's owner has a password.
fn report_owner(tcg2: *mut Tcg2) {
    let mut response = [0u8; RESPONSE];
    let permanent = submit(tcg2, &rollback::get_permanent(), &mut response)
        .ok()
        .and_then(|bytes| rollback::parse_permanent(bytes).ok());
    diag(match permanent {
        Some(bits) if bits & rollback::OWNER_AUTH_SET != 0 => {
            "bhaskixboot: the TPM's owner has a password\r\n"
        }
        Some(_) => {
            "bhaskixboot: the TPM's owner has NO PASSWORD: anything that can command this TPM \
             can delete the counter\r\n"
        }
        None => "bhaskixboot: the TPM did not say whether its owner has a password\r\n",
    });
}

/// Advances the counter for `booted` if `bhaskix-rollback` says it moves, then
/// locks it until the next restart and proves the lock. Does nothing without
/// a counter.
pub fn advance_and_lock(counter: &Counter, booted: Booted) {
    let Counter::Here { tcg2, bits } = *counter else {
        return;
    };
    let mut response = [0u8; RESPONSE];
    if let Some(bit) = rollback::advance(rollback::floor(bits), booted) {
        let set = submit(tcg2, &rollback::set_bits(bit), &mut response)
            .map_err(|status| status as u64)
            .and_then(|bytes| rollback::parse_status(bytes).map_err(code_of));
        let mut line = Line::new();
        match set {
            Ok(()) => {
                line.push("bhaskixboot: rollback counter: advanced to ");
                line.push_dec(u64::from(booted.version));
                line.push(", the version of the set marked good\r\n");
            }
            Err(code) => {
                line.push("bhaskixboot: ROLLBACK COUNTER NOT ADVANCED: the TPM refused (");
                line.push_hex(code);
                line.push(")\r\n");
            }
        }
        diag(line.as_str());
    }
    let locked = submit(tcg2, &rollback::write_lock(), &mut response)
        .map_err(|status| status as u64)
        .and_then(|bytes| rollback::parse_status(bytes).map_err(code_of));
    if let Err(code) = locked {
        let mut line = Line::new();
        line.push("bhaskixboot: ROLLBACK COUNTER NOT LOCKED: the TPM refused (");
        line.push_hex(code);
        line.push(") -- the running system could advance it\r\n");
        diag(line.as_str());
        return;
    }
    // The proof: a write of no bits, which a held lock refuses and which
    // changes nothing if it does not.
    let proof = submit(tcg2, &rollback::set_bits(0), &mut response)
        .map_err(|status| status as u64)
        .and_then(|bytes| rollback::parse_status(bytes).map_err(code_of));
    diag(match proof {
        Err(code) if rollback::base_code(code as u32) == rollback::TPM_RC_NV_LOCKED => {
            "bhaskixboot: rollback counter: locked until the next restart, and a write was \
             refused (TPM_RC_NV_LOCKED)\r\n"
        }
        Ok(()) => {
            "bhaskixboot: ROLLBACK COUNTER NOT LOCKED: a write after the lock was accepted -- \
             the running system could advance it\r\n"
        }
        Err(_) => {
            "bhaskixboot: ROLLBACK COUNTER LOCK NOT PROVEN: a write after the lock was refused \
             for another reason\r\n"
        }
    });
}
