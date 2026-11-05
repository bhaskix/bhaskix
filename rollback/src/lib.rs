// SPDX-License-Identifier: Apache-2.0
//! The rollback counter, as bytes and arithmetic --
//! [RFC 0100](../../docs/rfc/0100-an-update-that-cannot-go-back.md) step 2.
//!
//! **What it is.** One TPM NV index of the *bits* type: 64 bits that can only
//! ever be set. A boot set's security version `v` (`boot.sig`, offset 20) is
//! recorded by setting bit `v - 1`, and the counter's **floor** is the highest
//! bit set, plus one. A set whose version is below the floor is refused as
//! rolled back. Version 0 is a set with no version, below every floor but 0.
//!
//! **Why bits and not a TPM counter.** A counter index begins, the first time
//! it is incremented, at the highest value any counter on that TPM has held,
//! not at 0, so its value cannot be a version. `TPM2_NV_SetBits` reads an
//! index never written as 0 and only ORs bits in (the reference
//! implementation's `NV_SetBits.c`). The price is [`MAX_VERSION`] versions, and
//! a version is raised only for a fix that must not be rolled back.
//!
//! **Who may move it is the TPM's to enforce.** The index carries
//! `WRITE_STCLEAR`, and the loader write-locks it on every boot it finds it,
//! after any advance and before anything else runs. Until the next TPM
//! restart a write answers `TPM_RC_NV_LOCKED`, whoever asks: the kernel,
//! `bin/tpmd`, anything. The loader proves the lock with a [`set_bits`] of no
//! bits, which changes nothing even if the TPM accepted it.
//!
//! **What it cannot stop.** An index the owner made can always be deleted with
//! the owner's authority -- `NvDefineSpace` refuses `POLICY_DELETE` to anyone
//! but the platform -- and many machines leave the owner's password empty. So
//! the loader reads [`get_permanent`]'s `ownerAuthSet` and says which kind of
//! machine it is on.
//!
//! **Transcribed, not recalled** (2026-11-03):
//! - the command codes, handles, response codes and attribute bits from EDK2's
//!   `MdePkg/Include/IndustryStandard/Tpm20.h`;
//! - the field order of `NV_ReadPublic`, `NV_DefineSpace`, `NV_Read` and the
//!   password session from `SecurityPkg`'s `Tpm2NVStorage.c` and `Tpm2Help.c`;
//! - `NV_SetBits`', `NV_WriteLock`'s and `GetCapability`'s parameters, and a
//!   bits index's value being big-endian, from the TPM reference
//!   implementation (`ms-tpm-20-ref`);
//! - the owner's handle range from the TCG's *Registry of Reserved TPM 2.0
//!   Handles and Localities*, v1.1, Table 2.
//!
//! **Commands are big-endian**, as `bhaskix-tpm`'s are. The independent check
//! of every byte here is a TPM accepting it: the slot rollback lane drives an
//! emulated one.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

/// The index's handle, in the range the TCG registry leaves to the owner,
/// `0x0180_0000..=0x01BF_FFFF`, for "OS or application specific usages".
/// Nothing assigns a handle there, so another owner's program may hold this
/// one; [`Public::is_ours`] is how the loader tells.
pub const INDEX: u32 = 0x0184_4858;

/// `TPM_ST_NO_SESSIONS`.
pub const TPM_ST_NO_SESSIONS: u16 = 0x8001;
/// `TPM_ST_SESSIONS`.
pub const TPM_ST_SESSIONS: u16 = 0x8002;
/// `TPM_CC_NV_DefineSpace`.
pub const TPM_CC_NV_DEFINE_SPACE: u32 = 0x0000_012A;
/// `TPM_CC_NV_SetBits`.
pub const TPM_CC_NV_SET_BITS: u32 = 0x0000_0135;
/// `TPM_CC_NV_WriteLock`.
pub const TPM_CC_NV_WRITE_LOCK: u32 = 0x0000_0138;
/// `TPM_CC_NV_Read`.
pub const TPM_CC_NV_READ: u32 = 0x0000_014E;
/// `TPM_CC_NV_ReadPublic`.
pub const TPM_CC_NV_READ_PUBLIC: u32 = 0x0000_0169;
/// `TPM_CC_GetCapability`.
pub const TPM_CC_GET_CAPABILITY: u32 = 0x0000_017A;
/// `TPM_RH_OWNER`: the owner's authority, which creating the index needs.
pub const TPM_RH_OWNER: u32 = 0x4000_0001;
/// `TPM_RS_PW`: a password session.
pub const TPM_RS_PW: u32 = 0x4000_0009;
/// `TPM_ALG_SHA256`: the index's name algorithm.
pub const TPM_ALG_SHA256: u16 = 0x000B;
/// `TPM_CAP_TPM_PROPERTIES`.
pub const TPM_CAP_TPM_PROPERTIES: u32 = 6;
/// `TPM_PT_PERMANENT` (`PT_VAR + 0`, `PT_VAR` being `0x100 * 2`).
pub const TPM_PT_PERMANENT: u32 = 0x200;
/// `TPMA_PERMANENT.ownerAuthSet`, bit 0: the owner's authority has a
/// password.
pub const OWNER_AUTH_SET: u32 = 1;
/// `TPM_RC_SUCCESS`.
pub const TPM_RC_SUCCESS: u32 = 0;
/// `TPM_RC_HANDLE` (`RC_FMT1 + 0x00B`): no such index, when it names the
/// index. Compare [`base_code`]s, since a TPM adds which handle it was.
pub const TPM_RC_HANDLE: u32 = 0x08B;
/// `TPM_RC_NV_LOCKED` (`RC_VER1 + 0x048`): the index is write-locked.
pub const TPM_RC_NV_LOCKED: u32 = 0x148;
/// `TPM_RC_NV_DEFINED` (`RC_VER1 + 0x04C`): the index already exists.
pub const TPM_RC_NV_DEFINED: u32 = 0x14C;

/// `TPMA_NV`'s bits, those this index sets or reads.
pub mod attr {
    /// `TPMA_NV_AUTHWRITE`, bit 2: written with the index's own password.
    pub const AUTHWRITE: u32 = 1 << 2;
    /// `TPM_NT_BITS`, 2, in the type field at bits 4 to 7.
    pub const BITS: u32 = 2 << 4;
    /// `TPMA_NV_WRITELOCKED`, bit 11: set by `NV_WriteLock`.
    pub const WRITELOCKED: u32 = 1 << 11;
    /// `TPMA_NV_WRITE_STCLEAR`, bit 14: a write lock that lasts until the
    /// next TPM restart.
    pub const WRITE_STCLEAR: u32 = 1 << 14;
    /// `TPMA_NV_AUTHREAD`, bit 18: read with the index's own password.
    pub const AUTHREAD: u32 = 1 << 18;
    /// `TPMA_NV_NO_DA`, bit 25: an empty password tried wrongly does not
    /// count towards the TPM's dictionary-attack lockout, which would lock
    /// out the machine's other users of the TPM.
    pub const NO_DA: u32 = 1 << 25;
    /// `TPMA_NV_WRITTEN`, bit 29: set by the first write.
    pub const WRITTEN: u32 = 1 << 29;
}

/// The index's attributes, as created: a bits index, read and written with
/// its own empty password, locked until restart, outside dictionary-attack
/// counting. Anyone may read it and, until the loader locks it, set a bit:
/// the lock is what keeps the running system from moving it.
pub const ATTRIBUTES: u32 =
    attr::AUTHWRITE | attr::BITS | attr::WRITE_STCLEAR | attr::AUTHREAD | attr::NO_DA;

/// The attributes the TPM sets on its own as the index is used.
const STATE: u32 = attr::WRITTEN | attr::WRITELOCKED;

/// A bits index's size: 8 bytes, which `NvDefineSpace` requires.
pub const DATA_SIZE: u16 = 8;

/// The highest security version the counter can record: one per bit.
pub const MAX_VERSION: u32 = 64;

/// The command and response header: tag, size, code.
pub const HEADER: usize = 10;

/// A password session with an empty password, as EDK2's
/// `Tpm2CopyAuthSessionCommand` writes it for no session given:
/// `TPM_RS_PW`, an empty nonce, no attributes, an empty password.
const PASSWORD_SESSION: [u8; 9] = [0x40, 0x00, 0x00, 0x09, 0, 0, 0, 0, 0];

/// Bytes in [`read_public`]'s command.
pub const READ_PUBLIC_COMMAND: usize = HEADER + 4;
/// Bytes in [`define`]'s command.
pub const DEFINE_COMMAND: usize = HEADER + 4 + 4 + PASSWORD_SESSION.len() + 2 + 2 + 14;
/// Bytes in [`read`]'s command.
pub const READ_COMMAND: usize = HEADER + 4 + 4 + 4 + PASSWORD_SESSION.len() + 2 + 2;
/// Bytes in [`set_bits`]'s command.
pub const SET_BITS_COMMAND: usize = HEADER + 4 + 4 + 4 + PASSWORD_SESSION.len() + 8;
/// Bytes in [`write_lock`]'s command.
pub const WRITE_LOCK_COMMAND: usize = HEADER + 4 + 4 + 4 + PASSWORD_SESSION.len();
/// Bytes in [`get_permanent`]'s command.
pub const GET_PERMANENT_COMMAND: usize = HEADER + 4 + 4 + 4;

/// Writes a command front to back; the header's size is the array's.
struct Command<const N: usize> {
    bytes: [u8; N],
    at: usize,
}

impl<const N: usize> Command<N> {
    fn new(tag: u16, code: u32) -> Self {
        let mut command = Self {
            bytes: [0; N],
            at: 0,
        };
        command.put(&tag.to_be_bytes());
        command.put(&(N as u32).to_be_bytes());
        command.put(&code.to_be_bytes());
        command
    }

    fn put(&mut self, bytes: &[u8]) -> &mut Self {
        self.bytes[self.at..self.at + bytes.len()].copy_from_slice(bytes);
        self.at += bytes.len();
        self
    }

    /// Two handles, the index authorising a command on itself, and the
    /// password session that authorisation rides in.
    fn on_the_index(&mut self) -> &mut Self {
        self.put(&INDEX.to_be_bytes())
            .put(&INDEX.to_be_bytes())
            .put(&(PASSWORD_SESSION.len() as u32).to_be_bytes())
            .put(&PASSWORD_SESSION)
    }
}

/// `TPM2_NV_ReadPublic(INDEX)`: whether the index exists, and what it is.
#[must_use]
pub fn read_public() -> [u8; READ_PUBLIC_COMMAND] {
    let mut command = Command::new(TPM_ST_NO_SESSIONS, TPM_CC_NV_READ_PUBLIC);
    command.put(&INDEX.to_be_bytes());
    command.bytes
}

/// `TPM2_NV_DefineSpace`, under the owner's authority with an empty password:
/// the index created with [`ATTRIBUTES`], a SHA-256 name, no policy, an empty
/// password of its own, and [`DATA_SIZE`] bytes. A TPM whose owner has a
/// password refuses it, and the loader says so.
#[must_use]
pub fn define() -> [u8; DEFINE_COMMAND] {
    let mut command = Command::new(TPM_ST_SESSIONS, TPM_CC_NV_DEFINE_SPACE);
    command
        .put(&TPM_RH_OWNER.to_be_bytes())
        .put(&(PASSWORD_SESSION.len() as u32).to_be_bytes())
        .put(&PASSWORD_SESSION)
        // auth: the index's own password, empty.
        .put(&0u16.to_be_bytes())
        // publicInfo: its size, then the index, name algorithm, attributes,
        // an empty policy and the data size.
        .put(&14u16.to_be_bytes())
        .put(&INDEX.to_be_bytes())
        .put(&TPM_ALG_SHA256.to_be_bytes())
        .put(&ATTRIBUTES.to_be_bytes())
        .put(&0u16.to_be_bytes())
        .put(&DATA_SIZE.to_be_bytes());
    command.bytes
}

/// `TPM2_NV_Read` of the whole index, authorised by the index itself.
#[must_use]
pub fn read() -> [u8; READ_COMMAND] {
    let mut command = Command::new(TPM_ST_SESSIONS, TPM_CC_NV_READ);
    command
        .on_the_index()
        .put(&DATA_SIZE.to_be_bytes())
        .put(&0u16.to_be_bytes());
    command.bytes
}

/// `TPM2_NV_SetBits(bits)`, authorised by the index itself. With `bits` 0 it
/// is the proof of the lock: refused with `TPM_RC_NV_LOCKED` when the lock
/// holds, and a change of nothing when it does not.
#[must_use]
pub fn set_bits(bits: u64) -> [u8; SET_BITS_COMMAND] {
    let mut command = Command::new(TPM_ST_SESSIONS, TPM_CC_NV_SET_BITS);
    command.on_the_index().put(&bits.to_be_bytes());
    command.bytes
}

/// `TPM2_NV_WriteLock`, authorised by the index itself: no write until the
/// next TPM restart. A second lock is not an error (`NV_WriteLock.c`).
#[must_use]
pub fn write_lock() -> [u8; WRITE_LOCK_COMMAND] {
    let mut command = Command::new(TPM_ST_SESSIONS, TPM_CC_NV_WRITE_LOCK);
    command.on_the_index();
    command.bytes
}

/// `TPM2_GetCapability(TPM_CAP_TPM_PROPERTIES, TPM_PT_PERMANENT, 1)`: whether
/// the owner's authority has a password.
#[must_use]
pub fn get_permanent() -> [u8; GET_PERMANENT_COMMAND] {
    let mut command = Command::new(TPM_ST_NO_SESSIONS, TPM_CC_GET_CAPABILITY);
    command
        .put(&TPM_CAP_TPM_PROPERTIES.to_be_bytes())
        .put(&TPM_PT_PERMANENT.to_be_bytes())
        .put(&1u32.to_be_bytes());
    command.bytes
}

/// Why a response was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResponseError {
    /// A field ran past the bytes given.
    Truncated,
    /// `responseSize` is below a header, or above the bytes given.
    Size(u32),
    /// The tag is not the one this command's success carries.
    Tag(u16),
    /// The TPM answered with an error code -- the one to report.
    Code(u32),
    /// The answer is well formed and not an answer to what was asked.
    Shape,
}

/// A response code with a format-1 code's handle, parameter or session
/// number taken off, so `TPM_RC_HANDLE` for "handle 1" compares equal to
/// [`TPM_RC_HANDLE`]. Format-1 codes have bit 7 set; their number is in bits
/// 6 and 8 to 11.
#[must_use]
pub const fn base_code(code: u32) -> u32 {
    if code & 0x80 != 0 { code & 0xBF } else { code }
}

fn u16_at(bytes: &[u8], at: usize) -> Result<u16, ResponseError> {
    let field = bytes.get(at..at + 2).ok_or(ResponseError::Truncated)?;
    Ok(u16::from_be_bytes([field[0], field[1]]))
}

fn u32_at(bytes: &[u8], at: usize) -> Result<u32, ResponseError> {
    let field = bytes.get(at..at + 4).ok_or(ResponseError::Truncated)?;
    Ok(u32::from_be_bytes([field[0], field[1], field[2], field[3]]))
}

/// The response cut to its stated size, once its code says success and its
/// tag is `tag`. An error response carries `TPM_ST_NO_SESSIONS` whatever was
/// sent, so the code is read first.
fn answered(bytes: &[u8], tag: u16) -> Result<&[u8], ResponseError> {
    let size = u32_at(bytes, 2)?;
    if (size as usize) < HEADER || size as usize > bytes.len() {
        return Err(ResponseError::Size(size));
    }
    let bytes = &bytes[..size as usize];
    let code = u32_at(bytes, 6)?;
    if code != TPM_RC_SUCCESS {
        return Err(ResponseError::Code(code));
    }
    match u16_at(bytes, 0)? {
        found if found == tag => Ok(bytes),
        found => Err(ResponseError::Tag(found)),
    }
}

/// Whether a command with a session -- [`define`], [`set_bits`],
/// [`write_lock`] -- succeeded.
///
/// # Errors
///
/// Any [`ResponseError`]; a refusal by the TPM is [`ResponseError::Code`].
pub fn parse_status(bytes: &[u8]) -> Result<(), ResponseError> {
    answered(bytes, TPM_ST_SESSIONS).map(|_| ())
}

/// An index's public area, as `TPM2_NV_ReadPublic` gives it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Public {
    /// Its handle.
    pub index: u32,
    /// Its name algorithm.
    pub name_alg: u16,
    /// Its attributes, the ones the TPM sets as it is used among them.
    pub attributes: u32,
    /// The length of its policy.
    pub policy_len: u16,
    /// Its size.
    pub data_size: u16,
}

impl Public {
    /// Whether this is the index [`define`] makes: the handle, the name
    /// algorithm, no policy, the size, and the attributes once the two the
    /// TPM sets on its own are set aside. Anything else at [`INDEX`] is
    /// another program's, and neither read nor written.
    #[must_use]
    pub const fn is_ours(&self) -> bool {
        self.index == INDEX
            && self.name_alg == TPM_ALG_SHA256
            && self.policy_len == 0
            && self.data_size == DATA_SIZE
            && self.attributes & !STATE == ATTRIBUTES
    }

    /// Whether a bit has ever been set. An index never written reads as an
    /// error, and holds no bits.
    #[must_use]
    pub const fn written(&self) -> bool {
        self.attributes & attr::WRITTEN != 0
    }

    /// Whether it is write-locked already this boot.
    #[must_use]
    pub const fn locked(&self) -> bool {
        self.attributes & attr::WRITELOCKED != 0
    }
}

/// The public area of [`INDEX`], or `None` when the TPM says there is no such
/// index.
///
/// # Errors
///
/// Any [`ResponseError`] but the no-such-index code.
pub fn parse_read_public(bytes: &[u8]) -> Result<Option<Public>, ResponseError> {
    let bytes = match answered(bytes, TPM_ST_NO_SESSIONS) {
        Ok(bytes) => bytes,
        Err(ResponseError::Code(code)) if base_code(code) == TPM_RC_HANDLE => return Ok(None),
        Err(other) => return Err(other),
    };
    let size = usize::from(u16_at(bytes, HEADER)?);
    let start = HEADER + 2;
    let policy_len = u16_at(bytes, start + 10)?;
    if size != 4 + 2 + 4 + 2 + usize::from(policy_len) + 2 {
        return Err(ResponseError::Shape);
    }
    Ok(Some(Public {
        index: u32_at(bytes, start)?,
        name_alg: u16_at(bytes, start + 4)?,
        attributes: u32_at(bytes, start + 6)?,
        policy_len,
        data_size: u16_at(bytes, start + 12 + usize::from(policy_len))?,
    }))
}

/// The index's 64 bits, from a [`read`] response: after the header, the
/// parameter size, then the data as a sized buffer of [`DATA_SIZE`]
/// big-endian bytes.
///
/// # Errors
///
/// Any [`ResponseError`]; data of another size is [`ResponseError::Shape`].
pub fn parse_read(bytes: &[u8]) -> Result<u64, ResponseError> {
    let bytes = answered(bytes, TPM_ST_SESSIONS)?;
    if u16_at(bytes, HEADER + 4)? != DATA_SIZE {
        return Err(ResponseError::Shape);
    }
    let data = bytes
        .get(HEADER + 6..HEADER + 6 + usize::from(DATA_SIZE))
        .ok_or(ResponseError::Truncated)?;
    let mut value = [0u8; 8];
    value.copy_from_slice(data);
    Ok(u64::from_be_bytes(value))
}

/// `TPMA_PERMANENT`, from a [`get_permanent`] response: `moreData`, then the
/// capability, the count of properties, and the property with its value.
///
/// # Errors
///
/// Any [`ResponseError`]; an answer about another capability or property is
/// [`ResponseError::Shape`].
pub fn parse_permanent(bytes: &[u8]) -> Result<u32, ResponseError> {
    let bytes = answered(bytes, TPM_ST_NO_SESSIONS)?;
    if u32_at(bytes, HEADER + 1)? != TPM_CAP_TPM_PROPERTIES
        || u32_at(bytes, HEADER + 5)? == 0
        || u32_at(bytes, HEADER + 9)? != TPM_PT_PERMANENT
    {
        return Err(ResponseError::Shape);
    }
    u32_at(bytes, HEADER + 13)
}

/// The counter's floor: the highest bit set, plus one; 0 for none.
#[must_use]
pub const fn floor(bits: u64) -> u32 {
    64 - bits.leading_zeros()
}

/// The bit that records `version`, or `None` for version 0, which records
/// nothing, and for a version above [`MAX_VERSION`], which cannot be recorded.
#[must_use]
pub const fn bit_for(version: u32) -> Option<u64> {
    if version == 0 || version > MAX_VERSION {
        None
    } else {
        Some(1 << (version - 1))
    }
}

/// The set a boot is about to hand over to, as the loader knows it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Booted {
    /// Its security version, from its `boot.sig`.
    pub version: u32,
    /// Whether its signature verified under a key the loader holds. An
    /// unverified set's version is whatever its bytes say, and is believed by
    /// nothing.
    pub verified: bool,
    /// Whether the slot record names its slot as the active one -- marked
    /// good. A trial is not, and neither is a set read while the record was
    /// damaged, or one read from the ESP.
    pub marked_good: bool,
}

/// The bits to set for `booted` against a counter at `floor`, or `None` when
/// the counter must not move: RFC 0100's question 2, "advanced by the loader
/// only after a slot is marked good". A set must be verified, marked good,
/// above the floor, and recordable.
#[must_use]
pub const fn advance(floor: u32, booted: Booted) -> Option<u64> {
    if !booted.verified || !booted.marked_good || booted.version <= floor {
        return None;
    }
    bit_for(booted.version)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The attributes, from the bit positions in EDK2's `TPMA_NV` (Table 195):
    /// AUTHWRITE 2, the type field's BITS (`TPMA_NV_BITS`) 5, WRITE_STCLEAR 14,
    /// AUTHREAD 18, NO_DA 25.
    #[test]
    fn the_attributes_are_the_bits_the_header_names() {
        assert_eq!(ATTRIBUTES, 0x0204_4024);
        assert_eq!(attr::BITS, 1 << 5);
    }

    #[test]
    fn the_index_is_in_the_owners_range() {
        assert!((0x0180_0000..=0x01BF_FFFF).contains(&INDEX));
    }

    fn size_field(bytes: &[u8]) -> usize {
        u32::from_be_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]) as usize
    }

    #[test]
    fn each_command_states_its_own_length() {
        assert_eq!(size_field(&read_public()), READ_PUBLIC_COMMAND);
        assert_eq!(size_field(&define()), DEFINE_COMMAND);
        assert_eq!(size_field(&read()), READ_COMMAND);
        assert_eq!(size_field(&set_bits(0)), SET_BITS_COMMAND);
        assert_eq!(size_field(&write_lock()), WRITE_LOCK_COMMAND);
        assert_eq!(size_field(&get_permanent()), GET_PERMANENT_COMMAND);
        assert_eq!(
            [
                READ_PUBLIC_COMMAND,
                DEFINE_COMMAND,
                READ_COMMAND,
                SET_BITS_COMMAND,
                WRITE_LOCK_COMMAND,
                GET_PERMANENT_COMMAND
            ],
            [14, 45, 35, 39, 31, 22]
        );
    }

    #[test]
    fn read_public_is_the_index_and_nothing_else() {
        assert_eq!(
            read_public(),
            [
                0x80, 0x01, 0, 0, 0, 14, 0, 0, 0x01, 0x69, // header
                0x01, 0x84, 0x48, 0x58, // nvIndex
            ]
        );
    }

    #[test]
    fn define_is_the_owner_and_the_public_area_in_edk2s_order() {
        assert_eq!(
            define(),
            [
                0x80, 0x02, 0, 0, 0, 45, 0, 0, 0x01, 0x2A, // header
                0x40, 0, 0, 0x01, // authHandle: the owner
                0, 0, 0, 9, // the session's size
                0x40, 0, 0, 0x09, 0, 0, 0, 0, 0, // TPM_RS_PW, empty
                0, 0, // auth: empty
                0, 14, // publicInfo's size
                0x01, 0x84, 0x48, 0x58, // nvIndex
                0, 0x0B, // nameAlg: SHA-256
                0x02, 0x04, 0x40, 0x24, // attributes
                0, 0, // authPolicy: empty
                0, 8, // dataSize
            ]
        );
    }

    #[test]
    fn read_set_bits_and_lock_are_authorised_by_the_index_itself() {
        let on_the_index = [
            0x01, 0x84, 0x48, 0x58, // authHandle: the index
            0x01, 0x84, 0x48, 0x58, // nvIndex
            0, 0, 0, 9, // the session's size
            0x40, 0, 0, 0x09, 0, 0, 0, 0, 0, // TPM_RS_PW, empty
        ];
        let read = read();
        assert_eq!(read[..10], [0x80, 0x02, 0, 0, 0, 35, 0, 0, 0x01, 0x4E]);
        assert_eq!(read[10..31], on_the_index);
        assert_eq!(read[31..], [0, 8, 0, 0]); // size 8, offset 0

        let set = set_bits(1 << 2);
        assert_eq!(set[..10], [0x80, 0x02, 0, 0, 0, 39, 0, 0, 0x01, 0x35]);
        assert_eq!(set[10..31], on_the_index);
        assert_eq!(set[31..], [0, 0, 0, 0, 0, 0, 0, 4]); // the bits, big-endian

        let lock = write_lock();
        assert_eq!(lock[..10], [0x80, 0x02, 0, 0, 0, 31, 0, 0, 0x01, 0x38]);
        assert_eq!(lock[10..], on_the_index);
    }

    #[test]
    fn the_proof_of_the_lock_sets_no_bits() {
        assert_eq!(set_bits(0)[31..], [0; 8]);
    }

    #[test]
    fn get_permanent_asks_for_one_property() {
        assert_eq!(
            get_permanent(),
            [
                0x80, 0x01, 0, 0, 0, 22, 0, 0, 0x01, 0x7A, // header
                0, 0, 0, 6, // TPM_CAP_TPM_PROPERTIES
                0, 0, 0x02, 0, // TPM_PT_PERMANENT
                0, 0, 0, 1, // one property
            ]
        );
    }

    #[test]
    fn a_format_1_code_compares_without_its_number() {
        assert_eq!(base_code(0x18B), TPM_RC_HANDLE); // handle 1
        assert_eq!(base_code(0x28B), TPM_RC_HANDLE); // handle 2
        assert_eq!(base_code(TPM_RC_NV_LOCKED), TPM_RC_NV_LOCKED); // format 0
    }

    /// A response: the header for `tag` and `code`, then `body`.
    fn response(tag: u16, code: u32, body: &[u8]) -> std::vec::Vec<u8> {
        let mut bytes = std::vec::Vec::new();
        bytes.extend_from_slice(&tag.to_be_bytes());
        bytes.extend_from_slice(&((HEADER + body.len()) as u32).to_be_bytes());
        bytes.extend_from_slice(&code.to_be_bytes());
        bytes.extend_from_slice(body);
        bytes
    }

    /// A `TPM2B_NV_PUBLIC` and a name after it, for `attributes`.
    fn public_body(index: u32, attributes: u32, policy: &[u8]) -> std::vec::Vec<u8> {
        let mut area = std::vec::Vec::new();
        area.extend_from_slice(&index.to_be_bytes());
        area.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
        area.extend_from_slice(&attributes.to_be_bytes());
        area.extend_from_slice(&(policy.len() as u16).to_be_bytes());
        area.extend_from_slice(policy);
        area.extend_from_slice(&DATA_SIZE.to_be_bytes());
        let mut body = std::vec::Vec::new();
        body.extend_from_slice(&(area.len() as u16).to_be_bytes());
        body.extend_from_slice(&area);
        body.extend_from_slice(&34u16.to_be_bytes());
        body.extend_from_slice(&[0xAB; 34]);
        body
    }

    #[test]
    fn our_index_is_ours_written_or_not_locked_or_not() {
        for state in [0, attr::WRITTEN, attr::WRITELOCKED, STATE] {
            let bytes = response(
                TPM_ST_NO_SESSIONS,
                0,
                &public_body(INDEX, ATTRIBUTES | state, &[]),
            );
            let public = parse_read_public(&bytes).unwrap().unwrap();
            assert!(public.is_ours(), "{state:#x}");
            assert_eq!(public.written(), state & attr::WRITTEN != 0);
            assert_eq!(public.locked(), state & attr::WRITELOCKED != 0);
        }
    }

    #[test]
    fn an_index_made_another_way_is_someone_elses() {
        // Writable by the owner as well; ordinary rather than bits; with a
        // policy; at another handle.
        let others = [
            public_body(INDEX, ATTRIBUTES | (1 << 1), &[]),
            public_body(INDEX, ATTRIBUTES & !attr::BITS, &[]),
            public_body(INDEX, ATTRIBUTES, &[7; 32]),
            public_body(INDEX + 1, ATTRIBUTES, &[]),
        ];
        for body in others {
            let bytes = response(TPM_ST_NO_SESSIONS, 0, &body);
            let public = parse_read_public(&bytes).unwrap().unwrap();
            assert!(!public.is_ours(), "{public:?}");
        }
    }

    #[test]
    fn no_such_index_is_none_whichever_handle_the_tpm_blames() {
        for code in [TPM_RC_HANDLE, 0x18B] {
            let bytes = response(TPM_ST_NO_SESSIONS, code, &[]);
            assert_eq!(parse_read_public(&bytes), Ok(None), "{code:#x}");
        }
        let bytes = response(TPM_ST_NO_SESSIONS, 0x101, &[]);
        assert_eq!(parse_read_public(&bytes), Err(ResponseError::Code(0x101)));
    }

    #[test]
    fn a_public_area_whose_size_disagrees_with_its_fields_is_refused() {
        let mut body = public_body(INDEX, ATTRIBUTES, &[]);
        body[1] += 1;
        let bytes = response(TPM_ST_NO_SESSIONS, 0, &body);
        assert_eq!(parse_read_public(&bytes), Err(ResponseError::Shape));
        let bytes = response(TPM_ST_NO_SESSIONS, 0, &body[..6]);
        assert_eq!(parse_read_public(&bytes), Err(ResponseError::Truncated));
    }

    /// A session response after the parameters: an empty nonce, the
    /// attributes, an empty password.
    const SESSION_RESPONSE: [u8; 5] = [0, 0, 1, 0, 0];

    #[test]
    fn a_read_gives_the_bits_big_endian() {
        let mut body = std::vec::Vec::new();
        body.extend_from_slice(&10u32.to_be_bytes()); // parameterSize
        body.extend_from_slice(&DATA_SIZE.to_be_bytes());
        body.extend_from_slice(&0x8000_0000_0000_0005u64.to_be_bytes());
        body.extend_from_slice(&SESSION_RESPONSE);
        let bytes = response(TPM_ST_SESSIONS, 0, &body);
        assert_eq!(parse_read(&bytes), Ok(0x8000_0000_0000_0005));
    }

    #[test]
    fn a_read_of_another_size_or_an_error_is_refused() {
        let mut body = std::vec::Vec::new();
        body.extend_from_slice(&6u32.to_be_bytes());
        body.extend_from_slice(&4u16.to_be_bytes());
        body.extend_from_slice(&[0, 0, 0, 1]);
        let bytes = response(TPM_ST_SESSIONS, 0, &body);
        assert_eq!(parse_read(&bytes), Err(ResponseError::Shape));
        // An error answer carries no sessions, whatever was sent.
        let bytes = response(TPM_ST_NO_SESSIONS, 0x14A, &[]);
        assert_eq!(parse_read(&bytes), Err(ResponseError::Code(0x14A)));
    }

    #[test]
    fn a_status_is_success_a_code_or_a_wrong_tag() {
        let mut body = 0u32.to_be_bytes().to_vec();
        body.extend_from_slice(&SESSION_RESPONSE);
        assert_eq!(parse_status(&response(TPM_ST_SESSIONS, 0, &body)), Ok(()));
        assert_eq!(
            parse_status(&response(TPM_ST_NO_SESSIONS, TPM_RC_NV_LOCKED, &[])),
            Err(ResponseError::Code(TPM_RC_NV_LOCKED))
        );
        assert_eq!(
            parse_status(&response(TPM_ST_NO_SESSIONS, 0, &[])),
            Err(ResponseError::Tag(TPM_ST_NO_SESSIONS))
        );
    }

    #[test]
    fn a_response_whose_size_lies_is_refused() {
        let mut bytes = response(TPM_ST_SESSIONS, 0, &[0; 4]);
        bytes[5] += 1;
        assert_eq!(parse_status(&bytes), Err(ResponseError::Size(15)));
        assert_eq!(parse_status(&bytes[..4]), Err(ResponseError::Truncated));
        bytes[5] = 9;
        assert_eq!(parse_status(&bytes), Err(ResponseError::Size(9)));
    }

    #[test]
    fn the_permanent_attributes_say_whether_the_owner_has_a_password() {
        let body = |property: u32, value: u32| {
            let mut body = std::vec![0u8]; // moreData
            body.extend_from_slice(&TPM_CAP_TPM_PROPERTIES.to_be_bytes());
            body.extend_from_slice(&1u32.to_be_bytes());
            body.extend_from_slice(&property.to_be_bytes());
            body.extend_from_slice(&value.to_be_bytes());
            body
        };
        let bytes = response(TPM_ST_NO_SESSIONS, 0, &body(TPM_PT_PERMANENT, 0x401));
        assert_eq!(parse_permanent(&bytes).map(|v| v & OWNER_AUTH_SET), Ok(1));
        let bytes = response(TPM_ST_NO_SESSIONS, 0, &body(TPM_PT_PERMANENT, 0x400));
        assert_eq!(parse_permanent(&bytes).map(|v| v & OWNER_AUTH_SET), Ok(0));
        let bytes = response(TPM_ST_NO_SESSIONS, 0, &body(0x201, 1));
        assert_eq!(parse_permanent(&bytes), Err(ResponseError::Shape));
    }

    #[test]
    fn the_floor_is_the_highest_bit_plus_one() {
        assert_eq!(floor(0), 0);
        assert_eq!(floor(1), 1);
        assert_eq!(floor(0b10), 2);
        assert_eq!(
            floor(0b1_0001),
            5,
            "a gap below the highest bit changes nothing"
        );
        assert_eq!(floor(1 << 63), 64);
        assert_eq!(floor(u64::MAX), MAX_VERSION);
    }

    #[test]
    fn a_version_is_one_bit_and_only_1_to_64_have_one() {
        assert_eq!(bit_for(0), None);
        assert_eq!(bit_for(1), Some(1));
        assert_eq!(bit_for(64), Some(1 << 63));
        assert_eq!(bit_for(65), None);
        for version in 1..=MAX_VERSION {
            assert_eq!(floor(bit_for(version).unwrap()), version);
        }
    }

    #[test]
    fn only_a_verified_set_marked_good_above_the_floor_advances_it() {
        let good = Booted {
            version: 3,
            verified: true,
            marked_good: true,
        };
        assert_eq!(advance(2, good), Some(1 << 2));
        assert_eq!(advance(0, good), Some(1 << 2));
        // A trial, an unverified set, one at or below the floor, one that
        // cannot be recorded: none moves it.
        let trial = Booted {
            marked_good: false,
            ..good
        };
        let unverified = Booted {
            verified: false,
            ..good
        };
        assert_eq!(advance(2, trial), None);
        assert_eq!(advance(2, unverified), None);
        assert_eq!(advance(3, good), None);
        assert_eq!(advance(4, good), None);
        let too_far = Booted {
            version: 65,
            ..good
        };
        assert_eq!(advance(2, too_far), None);
        let unversioned = Booted { version: 0, ..good };
        assert_eq!(advance(0, unversioned), None);
    }
}
