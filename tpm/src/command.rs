// SPDX-License-Identifier: Apache-2.0
//! `TPM2_PCR_Read`, built and parsed -- and nothing else.
//!
//! The command, big-endian (EDK2's `Tpm2PcrRead`):
//!
//! | offset | field |
//! |---|---|
//! | 0 | `tag` = `TPM_ST_NO_SESSIONS` (2) |
//! | 2 | `commandSize` (4) |
//! | 6 | `commandCode` = `TPM_CC_PCR_Read` (4) |
//! | 10 | `pcrSelectionIn.count` = 1 (4) |
//! | 14 | `hash` (2), `sizeofSelect` = 3 (1), `pcrSelect` (3) |
//!
//! The response: `tag` (2), `responseSize` (4), `responseCode` (4), then on
//! success `pcrUpdateCounter` (4), `pcrSelectionOut` (a count and selections
//! of the same shape), and `pcrValues` -- a count and that many
//! `TPM2B_DIGEST`s, each a 2-byte size and the bytes.

/// `TPM_ST_NO_SESSIONS` -- `Tpm20.h`, `0x8001`.
pub const TPM_ST_NO_SESSIONS: u16 = 0x8001;
/// `TPM_CC_PCR_Read` -- `Tpm20.h`, `0x0000017E`.
pub const TPM_CC_PCR_READ: u32 = 0x0000_017E;
/// `TPM_RC_SUCCESS`.
pub const TPM_RC_SUCCESS: u32 = 0;
/// `TPM_ALG_SHA256` -- `Tpm20.h`, `0x000B`.
pub const TPM_ALG_SHA256: u16 = 0x000B;
/// A SHA-256 digest's length.
pub const SHA256_DIGEST: usize = 32;
/// The command and response header: tag, size, code.
pub const HEADER: usize = 10;
/// PCRs a selection of three bytes can name.
pub const PCRS: u8 = 24;
/// Bytes in [`pcr_read_command`]'s command.
pub const PCR_READ_COMMAND: usize = HEADER + 4 + 2 + 1 + 3;

/// `TPM2_PCR_Read` for one PCR in one bank. `None` when `pcr` is not below
/// [`PCRS`].
#[must_use]
pub fn pcr_read_command(bank: u16, pcr: u8) -> Option<[u8; PCR_READ_COMMAND]> {
    if pcr >= PCRS {
        return None;
    }
    let mut out = [0u8; PCR_READ_COMMAND];
    out[0..2].copy_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
    out[2..6].copy_from_slice(&(PCR_READ_COMMAND as u32).to_be_bytes());
    out[6..10].copy_from_slice(&TPM_CC_PCR_READ.to_be_bytes());
    out[10..14].copy_from_slice(&1u32.to_be_bytes());
    out[14..16].copy_from_slice(&bank.to_be_bytes());
    out[16] = 3;
    out[17 + usize::from(pcr / 8)] = 1 << (pcr % 8);
    Some(out)
}

/// Why a response was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResponseError {
    /// A field ran past the bytes given.
    Truncated,
    /// `responseSize` is below a header, or above the bytes given.
    Size(u32),
    /// The tag is not `TPM_ST_NO_SESSIONS`.
    Tag(u16),
    /// The TPM answered with an error code -- the one to report.
    Code(u32),
    /// The selection that came back is not the one asked for.
    SelectionMismatch,
    /// No digest came back: the bank is not allocated, or the PCR is not in it.
    NoDigest,
    /// A digest of a size the bank does not have.
    DigestSize(u16),
}

/// The digest a `TPM2_PCR_Read` response carries for `(bank, pcr)`, whose
/// digest is `digest_len` bytes -- borrowed from `bytes`.
///
/// **Untrusted**: a device wrote these bytes. Every length is checked against
/// what is left, the answer is checked to be the one asked for, and a TPM error
/// code is returned as itself so the report can name it.
///
/// # Errors
///
/// Any [`ResponseError`].
pub fn parse_pcr_read_response(
    bytes: &[u8],
    bank: u16,
    pcr: u8,
    digest_len: usize,
) -> Result<&[u8], ResponseError> {
    let tag = u16_at(bytes, 0)?;
    let size = u32_at(bytes, 2)?;
    if (size as usize) < HEADER || size as usize > bytes.len() {
        return Err(ResponseError::Size(size));
    }
    let bytes = &bytes[..size as usize];
    let code = u32_at(bytes, 6)?;
    if code != TPM_RC_SUCCESS {
        return Err(ResponseError::Code(code));
    }
    if tag != TPM_ST_NO_SESSIONS {
        return Err(ResponseError::Tag(tag));
    }
    // pcrUpdateCounter at 10, then the selection that came back.
    if u32_at(bytes, 14)? != 1 {
        return Err(ResponseError::SelectionMismatch);
    }
    let hash = u16_at(bytes, 18)?;
    let select = usize::from(*bytes.get(20).ok_or(ResponseError::Truncated)?);
    let mask = bytes.get(21..21 + select).ok_or(ResponseError::Truncated)?;
    let byte = usize::from(pcr / 8);
    let bit = 1u8 << (pcr % 8);
    if hash != bank || mask.get(byte).is_none_or(|m| m & bit == 0) {
        return Err(ResponseError::SelectionMismatch);
    }
    let at = 21 + select;
    let count = u32_at(bytes, at)?;
    if count == 0 {
        return Err(ResponseError::NoDigest);
    }
    let length = u16_at(bytes, at + 4)?;
    if usize::from(length) != digest_len {
        return Err(ResponseError::DigestSize(length));
    }
    bytes
        .get(at + 6..at + 6 + digest_len)
        .ok_or(ResponseError::Truncated)
}

fn u16_at(bytes: &[u8], at: usize) -> Result<u16, ResponseError> {
    let field = bytes.get(at..at + 2).ok_or(ResponseError::Truncated)?;
    Ok(u16::from_be_bytes([field[0], field[1]]))
}

fn u32_at(bytes: &[u8], at: usize) -> Result<u32, ResponseError> {
    let field = bytes.get(at..at + 4).ok_or(ResponseError::Truncated)?;
    Ok(u32::from_be_bytes([field[0], field[1], field[2], field[3]]))
}

#[cfg(test)]
pub(crate) mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    /// A success response for one PCR in one bank, `digest` as its value.
    pub(crate) fn response(bank: u16, pcr: u8, digest: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes()); // size, filled in below
        out.extend_from_slice(&TPM_RC_SUCCESS.to_be_bytes());
        out.extend_from_slice(&7u32.to_be_bytes()); // pcrUpdateCounter
        out.extend_from_slice(&1u32.to_be_bytes());
        out.extend_from_slice(&bank.to_be_bytes());
        out.push(3);
        let mut mask = [0u8; 3];
        mask[usize::from(pcr / 8)] = 1 << (pcr % 8);
        out.extend_from_slice(&mask);
        out.extend_from_slice(&1u32.to_be_bytes());
        out.extend_from_slice(&(digest.len() as u16).to_be_bytes());
        out.extend_from_slice(digest);
        let size = out.len() as u32;
        out[2..6].copy_from_slice(&size.to_be_bytes());
        out
    }

    #[test]
    fn the_command_is_the_bytes_edk2_sends() {
        let command = pcr_read_command(TPM_ALG_SHA256, 9).unwrap();
        assert_eq!(
            command,
            [
                0x80, 0x01, // TPM_ST_NO_SESSIONS
                0, 0, 0, 20, // commandSize
                0, 0, 0x01, 0x7E, // TPM_CC_PCR_Read
                0, 0, 0, 1, // one selection
                0x00, 0x0B, // SHA-256
                3,    // sizeofSelect
                0, 0x02, 0, // PCR 9: byte 1, bit 1
            ]
        );
        assert_eq!(pcr_read_command(TPM_ALG_SHA256, 24), None);
        assert_eq!(pcr_read_command(TPM_ALG_SHA256, 0).unwrap()[17], 1);
    }

    #[test]
    fn a_response_gives_back_the_digest_asked_for() {
        let digest = [0x5a; 32];
        let bytes = response(TPM_ALG_SHA256, 9, &digest);
        assert_eq!(
            parse_pcr_read_response(&bytes, TPM_ALG_SHA256, 9, 32),
            Ok(&digest[..])
        );
    }

    #[test]
    fn an_error_code_is_returned_as_itself() {
        // 0x0101: TPM_RC_FAILURE's shape; any code is reported, not mapped.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
        bytes.extend_from_slice(&10u32.to_be_bytes());
        bytes.extend_from_slice(&0x0101u32.to_be_bytes());
        assert_eq!(
            parse_pcr_read_response(&bytes, TPM_ALG_SHA256, 9, 32),
            Err(ResponseError::Code(0x0101))
        );
    }

    #[test]
    fn a_response_for_something_else_is_refused() {
        let digest = [1u8; 32];
        let other_pcr = response(TPM_ALG_SHA256, 8, &digest);
        assert_eq!(
            parse_pcr_read_response(&other_pcr, TPM_ALG_SHA256, 9, 32),
            Err(ResponseError::SelectionMismatch)
        );
        let other_bank = response(0x000C, 9, &digest);
        assert_eq!(
            parse_pcr_read_response(&other_bank, TPM_ALG_SHA256, 9, 32),
            Err(ResponseError::SelectionMismatch)
        );
        let short_digest = response(TPM_ALG_SHA256, 9, &[1u8; 20]);
        assert_eq!(
            parse_pcr_read_response(&short_digest, TPM_ALG_SHA256, 9, 32),
            Err(ResponseError::DigestSize(20))
        );
    }

    #[test]
    fn a_size_past_the_bytes_and_every_truncation_are_refused() {
        let bytes = response(TPM_ALG_SHA256, 9, &[2u8; 32]);
        let mut lying = bytes.clone();
        lying[2..6].copy_from_slice(&(bytes.len() as u32 + 1).to_be_bytes());
        assert!(matches!(
            parse_pcr_read_response(&lying, TPM_ALG_SHA256, 9, 32),
            Err(ResponseError::Size(_))
        ));
        for cut in 0..bytes.len() {
            assert!(parse_pcr_read_response(&bytes[..cut], TPM_ALG_SHA256, 9, 32).is_err());
        }
    }
}
