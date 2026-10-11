// SPDX-License-Identifier: Apache-2.0
//! Replaying the log -- RFC 0089 step 6.
//!
//! A PCR is never written, only extended: `PCR = H(PCR ‖ digest)`, from a
//! start value of zeros. Folding every event's digest into the PCR it names
//! gives what the TPM should hold, and the log is a faithful record of the
//! boot exactly when the two agree. **The hash is the caller's** --
//! `bhaskix-pkg`'s SHA-256 in `bin/tpmd` -- so this crate stays a leaf, and the
//! folding is tested here against values computed apart from it.
//!
//! Three rules decide what is folded, read from tpm2-tools'
//! `lib/tpm2_eventlog.c` on 2026-10-11 rather than recalled:
//!
//! - **`EV_NO_ACTION` is never extended**: it records, it does not measure.
//! - **PCR 0 may not start at zero.** An `EV_NO_ACTION` in PCR 0 carrying a
//!   `StartupLocality` structure (`UefiTcgPlatform.h`: 16 signature bytes,
//!   then the locality) sets the start value's last byte to the locality the
//!   TPM was started from.
//! - **An `EV_EFI_HCRTM_EVENT` in PCR 0 sets that byte to 4** (TPM library
//!   part 1 §34.3, as tpm2-tools cites it), and is then extended as usual.
//!
//! Both start rules describe the value before anything is extended, so a log
//! that states one after PCR 0 was extended -- or states a second -- is
//! refused rather than guessed at.
//!
//! **Only the SHA-256 bank is replayed**: it is the one hash the tree has.
//! A log without it is refused by name, and the caller says *not checked*.

use crate::log::{EV_NO_ACTION, Log, LogError, alg};

/// PCRs a TPM 2.0 has in a PC Client platform's bank.
pub const PCRS: usize = 24;

/// A SHA-256 digest's size.
pub const DIGEST: usize = 32;

/// `EV_EFI_HCRTM_EVENT` -- `UefiTcgPlatform.h`, `EV_EFI_EVENT_BASE + 0x10`.
pub const EV_EFI_HCRTM_EVENT: u32 = 0x8000_0010;

/// `TCG_EfiStartupLocalityEvent`'s signature, NUL included.
pub const STARTUP_LOCALITY: [u8; 16] = *b"StartupLocality\0";

/// The start value's last byte after an H-CRTM event.
const HCRTM_LOCALITY: u8 = 4;

/// What a replay arrived at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Replay {
    /// Every PCR's value as the log says it should be. Those not in
    /// [`Replay::touched`] are their start value, zeros, and say nothing.
    pub pcrs: [[u8; DIGEST]; PCRS],
    /// A bit per PCR the log extended or gave a start value to.
    pub touched: u32,
    /// Events folded in -- every event but the `EV_NO_ACTION`s.
    pub extended: u32,
}

/// Why a log could not be replayed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplayError {
    /// The header declares no SHA-256 bank, or an event carries no digest
    /// in it, so there is nothing this replay can fold.
    NoSha256Bank,
    /// The header declares SHA-256 with a size other than 32.
    Sha256Size(u16),
    /// An event names a PCR the TPM does not have.
    Pcr(u32),
    /// A start value -- a startup locality or an H-CRTM event -- stated after
    /// PCR 0 had already been extended or given one.
    LateStart,
    /// The walk itself failed.
    Log(LogError),
}

/// Folds every event of `log` into the PCR it names, in the SHA-256 bank,
/// with `extend(pcr, digest)` returning the PCR's next value.
///
/// # Errors
///
/// Any [`ReplayError`]; the first one ends the replay.
pub fn replay(
    log: &Log<'_>,
    mut extend: impl FnMut(&[u8; DIGEST], &[u8; DIGEST]) -> [u8; DIGEST],
) -> Result<Replay, ReplayError> {
    match log
        .spec()
        .algorithms()
        .iter()
        .find(|&&(id, _)| id == alg::SHA256)
    {
        None => return Err(ReplayError::NoSha256Bank),
        Some(&(_, size)) if usize::from(size) != DIGEST => {
            return Err(ReplayError::Sha256Size(size));
        }
        Some(_) => {}
    }
    let mut out = Replay {
        pcrs: [[0; DIGEST]; PCRS],
        touched: 0,
        extended: 0,
    };
    for event in log.events() {
        let event = event.map_err(ReplayError::Log)?;
        let pcr = usize::try_from(event.pcr)
            .ok()
            .filter(|&pcr| pcr < PCRS)
            .ok_or(ReplayError::Pcr(event.pcr))?;
        if let Some(locality) = start_locality(event.pcr, event.event_type, event.data) {
            if out.touched & 1 != 0 {
                return Err(ReplayError::LateStart);
            }
            out.pcrs[0][DIGEST - 1] = locality;
            out.touched |= 1;
        }
        if event.event_type == EV_NO_ACTION {
            continue;
        }
        let digest: &[u8; DIGEST] = event
            .digest(alg::SHA256)
            .and_then(|digest| digest.try_into().ok())
            .ok_or(ReplayError::NoSha256Bank)?;
        out.pcrs[pcr] = extend(&out.pcrs[pcr], digest);
        out.touched |= 1 << pcr;
        out.extended += 1;
    }
    Ok(out)
}

/// The start value's last byte, if this event sets one: an H-CRTM event or
/// a startup-locality record, both in PCR 0 only.
fn start_locality(pcr: u32, event_type: u32, data: &[u8]) -> Option<u8> {
    if pcr != 0 {
        return None;
    }
    if event_type == EV_EFI_HCRTM_EVENT {
        return Some(HCRTM_LOCALITY);
    }
    if event_type == EV_NO_ACTION && data.starts_with(&STARTUP_LOCALITY) {
        return data.get(STARTUP_LOCALITY.len()).copied();
    }
    None
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::log::tests::{BANKS, event, header};
    use std::vec::Vec;

    /// The tree's own SHA-256, as `bin/tpmd` folds with it.
    fn sha256_extend(pcr: &[u8; DIGEST], digest: &[u8; DIGEST]) -> [u8; DIGEST] {
        let mut hash = bhaskix_pkg::sha256::Sha256::new();
        hash.update(pcr);
        hash.update(digest);
        hash.finish()
    }

    fn hex(text: &str) -> [u8; DIGEST] {
        let mut out = [0; DIGEST];
        for (byte, pair) in out.iter_mut().zip(text.as_bytes().chunks(2)) {
            *byte = u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap();
        }
        out
    }

    fn replayed(log: &[u8]) -> Result<Replay, ReplayError> {
        replay(&Log::parse(log).unwrap(), sha256_extend)
    }

    // Every expected value below was computed with Python's `hashlib`,
    // `sha256(pcr + digest)`, apart from this crate and from `bhaskix-pkg`.

    #[test]
    fn one_event_folds_into_its_pcr_from_zero() {
        let mut log = header(&BANKS);
        log.extend(event(9, 6, &BANKS, 0x22, b"kernel"));
        let replay = replayed(&log).unwrap();
        assert_eq!(
            replay.pcrs[9],
            hex("ee4b0e933b56cdf12a42b1e3f3b9ed1aa70cf9f3cf37325693255c8bfbcb8ba8")
        );
        assert_eq!((replay.touched, replay.extended), (1 << 9, 1));
        assert_eq!(replay.pcrs[8], [0; DIGEST]);
    }

    #[test]
    fn events_fold_in_order_each_into_its_own_pcr() {
        let mut log = header(&BANKS);
        log.extend(event(9, 6, &BANKS, 0x22, b"kernel"));
        log.extend(event(8, 6, &BANKS, 0x44, b"cmdline"));
        log.extend(event(9, 6, &BANKS, 0x33, b"initrd"));
        let replay = replayed(&log).unwrap();
        assert_eq!(
            replay.pcrs[9],
            hex("22d0d408147e904fa9fe6feba5fc51374e44f07101e208e62fd5453841595ade")
        );
        assert_eq!(
            replay.pcrs[8],
            hex("105c2393ee071304893e2992acbf55e5de591ae162bae0ac5f3a2d2de0f5f4c3")
        );
        assert_eq!((replay.touched, replay.extended), ((1 << 9) | (1 << 8), 3));
    }

    #[test]
    fn a_no_action_event_is_recorded_and_never_extended() {
        let mut log = header(&BANKS);
        log.extend(event(0, EV_NO_ACTION, &BANKS, 0x55, b"SP800-155 Event\0"));
        let replay = replayed(&log).unwrap();
        assert_eq!((replay.touched, replay.extended), (0, 0));
        assert_eq!(replay.pcrs[0], [0; DIGEST]);
    }

    #[test]
    fn a_startup_locality_sets_pcr_zero_s_start_value() {
        let mut locality = Vec::from(STARTUP_LOCALITY);
        locality.push(3);
        let mut log = header(&BANKS);
        log.extend(event(0, EV_NO_ACTION, &BANKS, 0, &locality));
        log.extend(event(0, 8, &BANKS, 0x66, b"firmware"));
        let replay = replayed(&log).unwrap();
        assert_eq!(
            replay.pcrs[0],
            hex("aa9203032d200092fcaf6a8aad2a0eb05e854d2ffd596e081be4f6bc6ee95dbf")
        );
        assert_eq!((replay.touched, replay.extended), (1, 1));
    }

    #[test]
    fn an_hcrtm_event_starts_pcr_zero_at_four_and_is_extended() {
        let mut log = header(&BANKS);
        log.extend(event(0, EV_EFI_HCRTM_EVENT, &BANKS, 0x77, b"HCRTM"));
        let replay = replayed(&log).unwrap();
        assert_eq!(
            replay.pcrs[0],
            hex("30f5de8915aba35981d3f14897e3a4e67c36b3754647d57b18797446a33eda18")
        );
        assert_eq!((replay.touched, replay.extended), (1, 1));
    }

    #[test]
    fn a_start_value_after_pcr_zero_was_extended_is_refused() {
        let mut locality = Vec::from(STARTUP_LOCALITY);
        locality.push(3);
        let mut log = header(&BANKS);
        log.extend(event(0, 8, &BANKS, 0x66, b"firmware"));
        log.extend(event(0, EV_NO_ACTION, &BANKS, 0, &locality));
        assert_eq!(replayed(&log), Err(ReplayError::LateStart));
    }

    #[test]
    fn a_log_without_the_sha256_bank_is_not_replayed() {
        let sha1 = [(alg::SHA1, 20)];
        let mut log = header(&sha1);
        log.extend(event(9, 6, &sha1, 0x22, b"kernel"));
        assert_eq!(replayed(&log), Err(ReplayError::NoSha256Bank));
        let short = [(alg::SHA256, 20)];
        let log = header(&short);
        assert_eq!(replayed(&log), Err(ReplayError::Sha256Size(20)));
    }

    #[test]
    fn a_pcr_the_tpm_does_not_have_is_refused() {
        let mut log = header(&BANKS);
        log.extend(event(24, 6, &BANKS, 0x22, b"kernel"));
        assert_eq!(replayed(&log), Err(ReplayError::Pcr(24)));
    }

    /// **A log a firmware wrote**, not one these tests built: OVMF
    /// (`OVMF_CODE_4M.fd`, Ubuntu 20.04) with swtpm, booting `bhaskixboot.efi`
    /// at `69a1fa5` with `kaslr=show`, captured on 2026-10-11 by
    /// `tools/capture-event-log.sh` out of the guest's memory -- the loader's
    /// copy, 7,658 bytes from `GetEventLog` and 445 of final events appended.
    const OVMF_SWTPM: &[u8] = include_bytes!("../fixtures/ovmf-swtpm.eventlog");

    /// What PCRs 0 to 9 must replay to. Computed by the capture tool's own
    /// walker and Python's `hashlib`, apart from this crate and `bhaskix-pkg`;
    /// and the boot that wrote the log printed, from the TPM itself through
    /// `bin/tpmd`, `PCR 8 c9e4d6eb PCR 9 29535236` and `log and TPM agree on
    /// PCRs 0-9`.
    const OVMF_SWTPM_PCRS: [&str; 10] = [
        "b78bf8a2485e4f682e05598aa007d5da9d144cdfc6826bba9e5292457925b8c6",
        "33d454dfcf5e46c0b7afd332272e72adc3d1a86ccae25aa98dd475c9fca36cfc",
        "7842c772a64365b48ac733edee9b131df5f0e71ea95074f80e32450995c5773d",
        "3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969",
        "2dcf234afe5bca5526f13fa84fac7d04c0d92803edb86033ce9d2c9039a68cdb",
        "a5ceb755d043f32431d63e39f5161464620a3437280494b5850dc1b47cc074e0",
        "3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969",
        "65caf8dd1e0ea7a6347b635d2b379c93b9a1351edc2afc3ecda700e534eb3068",
        "c9e4d6eb33bfd9759b9c9a98a3f3630e0ee2bdc8f41fedc570e299ba7dc65428",
        "2953523650b3de8d928acc20433032fde492c64d8528092e80c80d1847285e9c",
    ];

    #[test]
    fn a_log_ovmf_wrote_replays_to_what_its_tpm_held() {
        let log = Log::parse(OVMF_SWTPM).unwrap();
        assert_eq!(
            log.spec().algorithms(),
            &[
                (alg::SHA1, 20),
                (alg::SHA256, 32),
                (alg::SHA384, 48),
                (alg::SHA512, 64)
            ]
        );
        let replay = replay(&log, sha256_extend).unwrap();
        assert_eq!((replay.touched, replay.extended), (0x3ff, 33));
        for (pcr, want) in OVMF_SWTPM_PCRS.iter().enumerate() {
            assert_eq!(replay.pcrs[pcr], hex(want), "PCR {pcr}");
        }
        // What the TPM itself answered in that boot, as far as it was printed.
        assert_eq!(replay.pcrs[8][..4], [0xc9, 0xe4, 0xd6, 0xeb]);
        assert_eq!(replay.pcrs[9][..4], [0x29, 0x53, 0x52, 0x36]);
    }

    /// The walk reads every byte of it, and the events RFC 0089 is about are
    /// where they should be: the loader's three tagged events, then the two
    /// `EV_EFI_ACTION`s `ExitBootServices` extends into PCR 5 -- which reached
    /// the copy only through the final events table (step 6a).
    #[test]
    fn the_loader_s_events_and_the_exit_s_are_in_the_log_ovmf_wrote() {
        let log = Log::parse(OVMF_SWTPM).unwrap();
        let events: Vec<_> = log.events().collect::<Result<_, _>>().unwrap();
        assert_eq!(events.len(), 33);
        let last: Vec<_> = events[28..]
            .iter()
            .map(|event| (event.pcr, event.event_type, event.data))
            .collect();
        assert_eq!(last[0].0, 9);
        assert!(last[0].2.ends_with(b"bhaskix kernel"));
        assert_eq!(last[1].0, 9);
        assert!(last[1].2.ends_with(b"bhaskix initrd"));
        assert_eq!(last[2].0, 8);
        assert!(last[2].2.ends_with(b"bhaskix cmdline"));
        const EV_EFI_ACTION: u32 = 0x8000_0007;
        assert_eq!(
            (last[3].0, last[3].1, last[3].2),
            (5, EV_EFI_ACTION, &b"Exit Boot Services Invocation"[..])
        );
        assert_eq!(
            (last[4].0, last[4].1, last[4].2),
            (
                5,
                EV_EFI_ACTION,
                &b"Exit Boot Services Returned with Success"[..]
            )
        );
        assert!(events.iter().all(|event| event.event_type != EV_NO_ACTION));
    }

    #[test]
    fn a_walk_that_fails_ends_the_replay_with_its_error() {
        let mut log = header(&BANKS);
        log.extend(event(9, 6, &BANKS, 0x22, b"kernel"));
        log.pop();
        assert_eq!(replayed(&log), Err(ReplayError::Log(LogError::Truncated)));
    }
}
