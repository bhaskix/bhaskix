// SPDX-License-Identifier: Apache-2.0
//! The TCG event structures measured boot writes and reads -- RFC 0089.
//!
//! **Transcribed from EDK2, the TCG specifications' reference implementation**
//! (`MdePkg/Include/Protocol/Tcg2Protocol.h` and
//! `MdePkg/Include/IndustryStandard/UefiTcgPlatform.h`), because the TCG's
//! own PDFs sat behind a browser challenge when this was written. The layouts
//! are claims from a document; the tests below hold the bytes, and the native
//! lane with a TPM is what shows the firmware agrees.
#![no_std]
#![forbid(unsafe_code)]

/// `EV_EVENT_TAG` -- `UefiTcgPlatform.h`, `0x00000006`.
pub const EV_EVENT_TAG: u32 = 0x0000_0006;

/// `EFI_TCG2_EVENT_HEADER_VERSION` -- `Tcg2Protocol.h`, `1`.
pub const HEADER_VERSION: u16 = 1;

/// `sizeof(EFI_TCG2_EVENT_HEADER)` under `#pragma pack(1)`: `HeaderSize`
/// (4), `HeaderVersion` (2), `PCRIndex` (4), `EventType` (4).
pub const HEADER_SIZE: u32 = 4 + 2 + 4 + 4;

/// Where each measured object goes, and the tag it is logged under.
///
/// **The tags are this project's own**: a `TCG_PCClientTaggedEvent` carries a
/// 32-bit identifier its writer chooses. These spell `BHK` and a number, so a
/// verifier reading the log can tell the loader's events from the firmware's.
/// The PCRs follow grub's practice, recorded in the UAPI group's Linux TPM PCR
/// Registry: 8 for the command line, 9 for files read.
pub mod measured {
    /// The kernel image, as read from the ESP -- PCR 9.
    pub const KERNEL: (u32, u32) = (9, 0x4248_4B01);
    /// The initrd, as read from the ESP -- PCR 9.
    pub const INITRD: (u32, u32) = (9, 0x4248_4B02);
    /// The command line, after `cmdline=` is stripped -- PCR 8.
    pub const CMDLINE: (u32, u32) = (8, 0x4248_4B03);
}

/// Writes an `EFI_TCG2_EVENT` whose event data is a `TCG_PCClientTaggedEvent`,
/// for `HashLogExtendEvent`, into `out`. Returns its length, or `None` when
/// `out` is too small or a length does not fit its field.
///
/// The layout, little-endian and packed:
///
/// | offset | field |
/// |---|---|
/// | 0 | `Size` -- the whole event, this field included |
/// | 4 | `HeaderSize` = 14 |
/// | 8 | `HeaderVersion` = 1 (two bytes) |
/// | 10 | `PCRIndex` |
/// | 14 | `EventType` = `EV_EVENT_TAG` |
/// | 18 | `taggedEventID` |
/// | 22 | `taggedEventDataSize` |
/// | 26 | `taggedEventData` -- `label` |
#[must_use]
pub fn tagged_event(pcr: u32, tag: u32, label: &[u8], out: &mut [u8]) -> Option<usize> {
    let data = u32::try_from(label.len()).ok()?;
    let total = 4 + HEADER_SIZE as usize + 8 + label.len();
    let size = u32::try_from(total).ok()?;
    let out = out.get_mut(..total)?;
    out[0..4].copy_from_slice(&size.to_le_bytes());
    out[4..8].copy_from_slice(&HEADER_SIZE.to_le_bytes());
    out[8..10].copy_from_slice(&HEADER_VERSION.to_le_bytes());
    out[10..14].copy_from_slice(&pcr.to_le_bytes());
    out[14..18].copy_from_slice(&EV_EVENT_TAG.to_le_bytes());
    out[18..22].copy_from_slice(&tag.to_le_bytes());
    out[22..26].copy_from_slice(&data.to_le_bytes());
    out[26..].copy_from_slice(label);
    Some(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_tagged_event_is_laid_out_as_edk2_declares_it() {
        let mut out = [0xAAu8; 64];
        let len = tagged_event(9, 0x4248_4B01, b"kernel", &mut out).unwrap();
        assert_eq!(len, 4 + 14 + 8 + 6);
        assert_eq!(
            &out[..len],
            &[
                32, 0, 0, 0, // Size: the whole event
                14, 0, 0, 0, // HeaderSize
                1, 0, // HeaderVersion
                9, 0, 0, 0, // PCRIndex
                6, 0, 0, 0, // EventType: EV_EVENT_TAG
                0x01, 0x4B, 0x48, 0x42, // taggedEventID
                6, 0, 0, 0, // taggedEventDataSize
                b'k', b'e', b'r', b'n', b'e', b'l',
            ]
        );
        assert_eq!(out[len], 0xAA, "nothing written past the event");
    }

    #[test]
    fn a_buffer_one_byte_short_is_refused_and_left_alone() {
        let mut out = [0xAAu8; 31];
        assert_eq!(tagged_event(9, 1, b"kernel", &mut out), None);
        assert!(out.iter().all(|&b| b == 0xAA));
    }

    #[test]
    fn an_empty_label_is_a_header_and_a_tag() {
        let mut out = [0u8; 26];
        assert_eq!(tagged_event(8, 2, b"", &mut out), Some(26));
        assert_eq!(&out[22..26], &[0, 0, 0, 0]);
    }

    #[test]
    fn the_tags_spell_the_project_and_are_distinct() {
        let tags = [measured::KERNEL.1, measured::INITRD.1, measured::CMDLINE.1];
        for tag in tags {
            assert_eq!(&tag.to_be_bytes()[..3], b"BHK");
        }
        assert!(tags[0] != tags[1] && tags[1] != tags[2] && tags[0] != tags[2]);
        assert_eq!((measured::KERNEL.0, measured::CMDLINE.0), (9, 8));
    }
}
