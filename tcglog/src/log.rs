// SPDX-License-Identifier: Apache-2.0
//! The crypto-agile event log the firmware hands back -- RFC 0089.
//!
//! **Untrusted input.** The firmware wrote these bytes and the loader copied
//! them; a kernel that trusts a length in them reads wherever the firmware --
//! or whoever replaced it -- chose. Every length is checked against what is
//! left, every sum is checked arithmetic, and every way a log can be malformed
//! has a name. `fuzz/fuzz_targets/tcglog_parse.rs` drives it.
//!
//! The shape, transcribed from EDK2's `UefiTcgPlatform.h` and `Tpm20.h`, all
//! little-endian and packed:
//!
//! - **One header event** in the old format, `TCG_PCR_EVENT`: `PCRIndex` (4),
//!   `EventType` (4, `EV_NO_ACTION`), a 20-byte digest, `EventSize` (4), then
//!   the event data -- a `TCG_EfiSpecIDEventStruct`: the 16-byte signature
//!   `"Spec ID Event03"` and its NUL, `platformClass` (4), the minor and major
//!   spec versions, the errata and `uintnSize` (one byte each),
//!   `numberOfAlgorithms` (4), that many `{algorithmId: u16, digestSize: u16}`,
//!   `vendorInfoSize` (1) and the vendor information.
//! - **Then events**, `TCG_PCR_EVENT2`: `PCRIndex` (4), `EventType` (4), a
//!   digest count (4), that many `{hashAlg: u16, digest}` -- each digest the
//!   size the header gave its algorithm -- then `EventSize` (4) and the data.

/// `EV_NO_ACTION` -- `UefiTcgPlatform.h`, `0x00000003`: the header event's type.
pub const EV_NO_ACTION: u32 = 0x0000_0003;

/// The header event's signature in a crypto-agile log, NUL included.
pub const SPEC_ID_03: [u8; 16] = *b"Spec ID Event03\0";

/// The most algorithms a log may declare and still be read here. EDK2's own
/// `HASH_COUNT` is 5; a log declaring more is refused rather than truncated.
pub const MAX_ALGORITHMS: usize = 8;

/// The largest digest any algorithm here may claim -- SHA-512's. A larger one
/// is not a hash this machine could be using, and refusing it keeps every
/// offset below a bound the arithmetic is easy to reason about.
pub const MAX_DIGEST: u16 = 64;

/// Algorithm identifiers -- EDK2's `Tpm20.h`.
pub mod alg {
    /// `TPM_ALG_SHA1`.
    pub const SHA1: u16 = 0x0004;
    /// `TPM_ALG_SHA256`.
    pub const SHA256: u16 = 0x000B;
    /// `TPM_ALG_SHA384`.
    pub const SHA384: u16 = 0x000C;
    /// `TPM_ALG_SHA512`.
    pub const SHA512: u16 = 0x000D;
}

/// Why a log was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogError {
    /// A field or a length ran past the end of what was given.
    Truncated,
    /// The first event is not a crypto-agile spec-ID event.
    NotSpecIdEvent,
    /// The header declares no algorithms.
    NoAlgorithms,
    /// The header declares more than [`MAX_ALGORITHMS`].
    TooManyAlgorithms,
    /// The header gives an algorithm a digest of zero or more than [`MAX_DIGEST`] bytes.
    ImplausibleDigestSize(u16),
    /// The header names one algorithm twice.
    DuplicateAlgorithm(u16),
    /// An event carries a digest for an algorithm the header did not declare.
    UnknownAlgorithm(u16),
    /// An event carries two digests for one algorithm -- which, with the count
    /// right, means it carries none for another, and a replay of that bank
    /// would have nothing to fold.
    DuplicateDigest(u16),
    /// An event carries a different number of digests than the header declared,
    /// where the specification has every event carry one per algorithm.
    DigestCountMismatch {
        /// Algorithms the header declared.
        declared: u32,
        /// Digests the event carried.
        found: u32,
    },
}

/// What the header event declared: the algorithms, each with its digest size.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpecId {
    algorithms: [(u16, u16); MAX_ALGORITHMS],
    count: usize,
}

impl SpecId {
    /// `(algorithm, digest size)`, in the order the header gave them.
    #[must_use]
    pub fn algorithms(&self) -> &[(u16, u16)] {
        &self.algorithms[..self.count]
    }

    fn size_of(&self, algorithm: u16) -> Option<usize> {
        self.index_of(algorithm)
            .map(|index| usize::from(self.algorithms[index].1))
    }

    fn index_of(&self, algorithm: u16) -> Option<usize> {
        self.algorithms()
            .iter()
            .position(|&(id, _)| id == algorithm)
    }
}

/// A parsed header and the events after it.
#[derive(Clone, Copy, Debug)]
pub struct Log<'a> {
    spec: SpecId,
    events: &'a [u8],
}

impl<'a> Log<'a> {
    /// Reads the header event; the events after it are read as they are
    /// walked, by [`Log::events`].
    ///
    /// # Errors
    ///
    /// Any [`LogError`] the header earns.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, LogError> {
        if u32_at(bytes, 4)? != EV_NO_ACTION {
            return Err(LogError::NotSpecIdEvent);
        }
        let size = u32_at(bytes, 28)? as usize;
        let end = 32usize.checked_add(size).ok_or(LogError::Truncated)?;
        let data = bytes.get(32..end).ok_or(LogError::Truncated)?;
        let spec = spec_id(data)?;
        Ok(Self {
            spec,
            events: &bytes[end..],
        })
    }

    /// What the header declared.
    #[must_use]
    pub fn spec(&self) -> &SpecId {
        &self.spec
    }

    /// The events, in order. A malformed event ends the walk with its error.
    #[must_use]
    pub fn events(&self) -> Events<'a> {
        Events {
            spec: self.spec,
            rest: self.events,
            failed: false,
        }
    }
}

/// One `TCG_PCR_EVENT2`.
#[derive(Clone, Copy, Debug)]
pub struct Event<'a> {
    /// The PCR it was extended into.
    pub pcr: u32,
    /// Its event type.
    pub event_type: u32,
    /// Its event data, as the writer logged it.
    pub data: &'a [u8],
    digests: &'a [u8],
    spec: SpecId,
}

impl<'a> Event<'a> {
    /// The digest this event carries for `algorithm`, if it carries one.
    #[must_use]
    pub fn digest(&self, algorithm: u16) -> Option<&'a [u8]> {
        let mut at = 0;
        while at < self.digests.len() {
            let id = u16_at(self.digests, at).ok()?;
            let size = self.spec.size_of(id)?;
            let digest = self.digests.get(at + 2..at + 2 + size)?;
            if id == algorithm {
                return Some(digest);
            }
            at += 2 + size;
        }
        None
    }
}

/// The walk [`Log::events`] returns.
#[derive(Clone, Debug)]
pub struct Events<'a> {
    spec: SpecId,
    rest: &'a [u8],
    failed: bool,
}

impl<'a> Iterator for Events<'a> {
    type Item = Result<Event<'a>, LogError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed || self.rest.is_empty() {
            return None;
        }
        match event2(self.rest, &self.spec) {
            Ok((event, len)) => {
                self.rest = &self.rest[len..];
                Some(Ok(event))
            }
            Err(error) => {
                self.failed = true;
                Some(Err(error))
            }
        }
    }
}

/// The length of the one event at the head of `bytes` -- what the loader
/// needs to know about the log's last entry, which is where `GetEventLog`
/// says it starts and nothing says where it ends.
///
/// # Errors
///
/// Any [`LogError`] the event earns.
pub fn event2_len(bytes: &[u8], spec: &SpecId) -> Result<usize, LogError> {
    event2(bytes, spec).map(|(_, len)| len)
}

fn spec_id(data: &[u8]) -> Result<SpecId, LogError> {
    if data.get(..16) != Some(&SPEC_ID_03[..]) {
        return Err(LogError::NotSpecIdEvent);
    }
    let declared = u32_at(data, 24)?;
    if declared == 0 {
        return Err(LogError::NoAlgorithms);
    }
    if declared as usize > MAX_ALGORITHMS {
        return Err(LogError::TooManyAlgorithms);
    }
    let mut spec = SpecId {
        algorithms: [(0, 0); MAX_ALGORITHMS],
        count: 0,
    };
    for index in 0..declared as usize {
        let at = 28 + index * 4;
        let (id, size) = (u16_at(data, at)?, u16_at(data, at + 2)?);
        if size == 0 || size > MAX_DIGEST {
            return Err(LogError::ImplausibleDigestSize(size));
        }
        if spec.size_of(id).is_some() {
            return Err(LogError::DuplicateAlgorithm(id));
        }
        spec.algorithms[spec.count] = (id, size);
        spec.count += 1;
    }
    // The vendor information has to fit too, though nothing reads it.
    let vendor_at = 28 + declared as usize * 4;
    let vendor = usize::from(*data.get(vendor_at).ok_or(LogError::Truncated)?);
    if data.len() < vendor_at + 1 + vendor {
        return Err(LogError::Truncated);
    }
    Ok(spec)
}

fn event2<'a>(bytes: &'a [u8], spec: &SpecId) -> Result<(Event<'a>, usize), LogError> {
    let pcr = u32_at(bytes, 0)?;
    let event_type = u32_at(bytes, 4)?;
    let found = u32_at(bytes, 8)?;
    if found as usize != spec.count {
        return Err(LogError::DigestCountMismatch {
            declared: spec.count as u32,
            found,
        });
    }
    // Every digest is bounded by MAX_DIGEST and there are at most
    // MAX_ALGORITHMS of them, so this cannot overflow; checked anyway.
    let mut at: usize = 12;
    let mut seen = [false; MAX_ALGORITHMS];
    for _ in 0..found {
        let id = u16_at(bytes, at)?;
        let index = spec.index_of(id).ok_or(LogError::UnknownAlgorithm(id))?;
        if core::mem::replace(&mut seen[index], true) {
            return Err(LogError::DuplicateDigest(id));
        }
        let size = usize::from(spec.algorithms[index].1);
        at = at.checked_add(2 + size).ok_or(LogError::Truncated)?;
        if at > bytes.len() {
            return Err(LogError::Truncated);
        }
    }
    let digests = &bytes[12..at];
    let size = u32_at(bytes, at)? as usize;
    let start = at + 4;
    let end = start.checked_add(size).ok_or(LogError::Truncated)?;
    let data = bytes.get(start..end).ok_or(LogError::Truncated)?;
    Ok((
        Event {
            pcr,
            event_type,
            data,
            digests,
            spec: *spec,
        },
        end,
    ))
}

fn u32_at(bytes: &[u8], at: usize) -> Result<u32, LogError> {
    let field = bytes.get(at..at.checked_add(4).ok_or(LogError::Truncated)?);
    let field: [u8; 4] = field
        .and_then(|f| f.try_into().ok())
        .ok_or(LogError::Truncated)?;
    Ok(u32::from_le_bytes(field))
}

fn u16_at(bytes: &[u8], at: usize) -> Result<u16, LogError> {
    let field = bytes.get(at..at.checked_add(2).ok_or(LogError::Truncated)?);
    let field: [u8; 2] = field
        .and_then(|f| f.try_into().ok())
        .ok_or(LogError::Truncated)?;
    Ok(u16::from_le_bytes(field))
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    /// A header event declaring `algorithms`.
    fn header(algorithms: &[(u16, u16)]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&SPEC_ID_03);
        data.extend_from_slice(&0u32.to_le_bytes()); // platformClass
        data.extend_from_slice(&[0, 2, 0, 2]); // minor, major, errata, uintnSize
        data.extend_from_slice(&(algorithms.len() as u32).to_le_bytes());
        for &(id, size) in algorithms {
            data.extend_from_slice(&id.to_le_bytes());
            data.extend_from_slice(&size.to_le_bytes());
        }
        data.push(0); // vendorInfoSize
        let mut event = Vec::new();
        event.extend_from_slice(&0u32.to_le_bytes());
        event.extend_from_slice(&EV_NO_ACTION.to_le_bytes());
        event.extend_from_slice(&[0u8; 20]);
        event.extend_from_slice(&(data.len() as u32).to_le_bytes());
        event.extend_from_slice(&data);
        event
    }

    /// One event with a digest per `(algorithm, size)`, each filled with `fill`.
    fn event(pcr: u32, kind: u32, algorithms: &[(u16, u16)], fill: u8, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&pcr.to_le_bytes());
        out.extend_from_slice(&kind.to_le_bytes());
        out.extend_from_slice(&(algorithms.len() as u32).to_le_bytes());
        for &(id, size) in algorithms {
            out.extend_from_slice(&id.to_le_bytes());
            out.extend(core::iter::repeat_n(fill, usize::from(size)));
        }
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(data);
        out
    }

    const BANKS: [(u16, u16); 2] = [(alg::SHA1, 20), (alg::SHA256, 32)];

    fn sample() -> Vec<u8> {
        let mut log = header(&BANKS);
        log.extend(event(0, 8, &BANKS, 0x11, b"firmware"));
        log.extend(event(9, 6, &BANKS, 0x22, b"bhaskix kernel"));
        log
    }

    #[test]
    fn a_log_reads_back_its_events_and_digests() {
        let log = sample();
        let parsed = Log::parse(&log).unwrap();
        assert_eq!(parsed.spec().algorithms(), &BANKS);
        let events: Vec<_> = parsed.events().collect::<Result<_, _>>().unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!((events[1].pcr, events[1].event_type), (9, 6));
        assert_eq!(events[1].data, b"bhaskix kernel");
        assert_eq!(events[1].digest(alg::SHA256), Some(&[0x22u8; 32][..]));
        assert_eq!(events[1].digest(alg::SHA1), Some(&[0x22u8; 20][..]));
        assert_eq!(events[1].digest(alg::SHA384), None);
    }

    #[test]
    fn event2_len_is_where_the_next_event_starts() {
        let one = event(9, 6, &BANKS, 0x22, b"bhaskix kernel");
        let spec = *Log::parse(&header(&BANKS)).unwrap().spec();
        let mut two = one.clone();
        two.extend(event(8, 6, &BANKS, 0x33, b"x"));
        assert_eq!(event2_len(&one, &spec), Ok(one.len()));
        assert_eq!(event2_len(&two, &spec), Ok(one.len()));
    }

    #[test]
    fn every_truncation_of_a_log_is_refused_and_never_read_past() {
        let log = sample();
        let whole = Log::parse(&log).unwrap().events().count();
        for cut in 0..log.len() {
            let short = &log[..cut];
            let Ok(parsed) = Log::parse(short) else {
                continue;
            };
            let results: Vec<_> = parsed.events().collect();
            // A cut inside an event is an error; a cut between events is a
            // shorter, valid log. Neither may claim the whole.
            assert!(results.len() <= whole);
            let ok = results.iter().filter(|r| r.is_ok()).count();
            assert!(ok < whole || cut == log.len());
        }
    }

    #[test]
    fn a_header_that_is_not_a_spec_id_event_is_refused() {
        let mut log = sample();
        log[32] ^= 0x20; // "spec ID Event03"
        assert_eq!(Log::parse(&log).unwrap_err(), LogError::NotSpecIdEvent);
        let mut log = sample();
        log[4] = 1; // EventType EV_POST_CODE, not EV_NO_ACTION
        assert_eq!(Log::parse(&log).unwrap_err(), LogError::NotSpecIdEvent);
    }

    #[test]
    fn a_header_with_no_too_many_duplicate_or_implausible_algorithms_is_refused() {
        assert_eq!(
            Log::parse(&header(&[])).unwrap_err(),
            LogError::NoAlgorithms
        );
        let many = [(alg::SHA256, 32); 9];
        assert_eq!(
            Log::parse(&header(&many)).unwrap_err(),
            LogError::TooManyAlgorithms
        );
        assert_eq!(
            Log::parse(&header(&[(alg::SHA256, 32), (alg::SHA256, 32)])).unwrap_err(),
            LogError::DuplicateAlgorithm(alg::SHA256)
        );
        assert_eq!(
            Log::parse(&header(&[(alg::SHA256, 65)])).unwrap_err(),
            LogError::ImplausibleDigestSize(65)
        );
        assert_eq!(
            Log::parse(&header(&[(alg::SHA256, 0)])).unwrap_err(),
            LogError::ImplausibleDigestSize(0)
        );
    }

    #[test]
    fn an_event_missing_a_bank_or_naming_an_unknown_one_ends_the_walk() {
        let mut log = header(&BANKS);
        log.extend(event(9, 6, &BANKS[..1], 0, b""));
        let walked: Vec<_> = Log::parse(&log)
            .unwrap()
            .events()
            .map(Result::err)
            .collect();
        assert_eq!(
            walked,
            [Some(LogError::DigestCountMismatch {
                declared: 2,
                found: 1
            })]
        );
        let mut log = header(&BANKS);
        log.extend(event(9, 6, &[(alg::SHA1, 20), (alg::SHA384, 48)], 0, b""));
        let walked: Vec<_> = Log::parse(&log)
            .unwrap()
            .events()
            .map(Result::err)
            .collect();
        assert_eq!(walked, [Some(LogError::UnknownAlgorithm(alg::SHA384))]);
        let mut log = header(&BANKS);
        log.extend(event(9, 6, &[(alg::SHA1, 20), (alg::SHA1, 20)], 0, b""));
        let walked: Vec<_> = Log::parse(&log)
            .unwrap()
            .events()
            .map(Result::err)
            .collect();
        assert_eq!(walked, [Some(LogError::DuplicateDigest(alg::SHA1))]);
    }

    #[test]
    fn a_length_near_the_top_of_the_address_space_is_refused_not_wrapped() {
        let mut log = header(&BANKS);
        let mut bad = event(9, 6, &BANKS, 0, b"");
        let size_at = bad.len() - 4;
        bad[size_at..].copy_from_slice(&u32::MAX.to_le_bytes());
        log.extend(bad);
        let walked: Vec<_> = Log::parse(&log)
            .unwrap()
            .events()
            .map(Result::err)
            .collect();
        assert_eq!(walked, [Some(LogError::Truncated)]);
    }
}
