// SPDX-License-Identifier: Apache-2.0
//! `bhaskixboot.efi` — the native UEFI loader, RFC 0028.
//!
//! The whole flight: enter from the firmware and say so; read the kernel,
//! the initrd and the configuration into memory the loader owns, proving
//! every byte; take the machine's shape; exit boot services; draw the
//! KASLR slide (RFC 0021's draw — a machine without entropy boots unslid
//! and says so); build the world the kernel will be entered under — the
//! identity and higher-half maps, the kernel's segments placed W^X at
//! their linked addresses plus the slide, and the `Handoff` assembled in
//! reclaimable memory; then jump through the shim's second door and never
//! return.
//!
//! # The bindings are hand-rolled, and hostile
//!
//! No external UEFI crate: the dependency allowlist is empty on purpose,
//! and a boot loader is the worst possible place for the first exception
//! (`docs/security.md` §1). Every firmware answer is checked before use
//! and refused with a printed sentence rather than trusted; the kernel ELF
//! is parsed by the same fuzz-hardened `bhaskix-elf` the kernel itself
//! loads programs with.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

mod efi;
mod handoff;
mod paging;
mod serial;

use bhaskix_boot::{Signature, Unverified};
use bhaskix_bootsig::statement::Digests;
use bhaskix_elf::{AddressHalf, PAGE_SIZE, page_span, parse_in};
use efi::{File, SimpleTextOutput, SystemTable};

/// The banner, and the line the harness's gate demands verbatim.
const BANNER: &str = "bhaskixboot 0.0.0: the machine entered through our own door\r\n";

/// Where the payload lives on the boot volume, beside `EFI\BOOT`.
const KERNEL_PATH: &str = "bhaskix\\kernel";
const INITRD_PATH: &str = "bhaskix\\initrd.tar";
const CONFIG_PATH: &str = "bhaskix\\boot.conf";
/// The boot set's signature -- RFC 0091 link 2.
const SIG_PATH: &str = "bhaskix\\boot.sig";

/// The boot-set keys this loader trusts, compiled in by `build.rs` from
/// `BHASKIX_BOOT_KEYS`, or the published test key when that is unset.
mod keys {
    include!(concat!(env!("OUT_DIR"), "/keys.rs"));
}

/// Pages allocated for each payload buffer: sixteen MiB for the kernel, and
/// sixteen for the initrd. A payload past its cap is a printed refusal, not a
/// silent truncation.
///
/// **The initrd's was four until 2026-10-19**, when an ISO built as the first
/// release is -- with the Go server in it -- carried a 6,993,920-byte initrd,
/// and this loader refused the release's own payload while Limine booted it.
/// Sixteen matches the kernel's buffer, the size already shown to fit.
const KERNEL_BUFFER_PAGES: usize = 4096;
const INITRD_BUFFER_PAGES: usize = 4096;

/// Why [`read_fully`] read nothing.
enum Unread {
    /// The firmware refused, with this status.
    Firmware(usize),
    /// The file is larger than the buffer its cap allows. Until 2026-10-19
    /// this was `usize::MAX` printed as a status, the same number a too-long
    /// path or a null answer prints: a refusal that could not say which.
    TooLarge,
}

/// FNV-1a, 64-bit — the same arithmetic the harness recomputes.
struct Fnv(u64);

impl Fnv {
    const fn new() -> Self {
        Self(0xcbf2_9ce4_8422_2325)
    }

    fn eat(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.0 ^= u64::from(*byte);
            self.0 = self.0.wrapping_mul(0x0000_0100_0000_01B3);
        }
    }
}

/// The most this loader asks the firmware for in one read.
///
/// **Not an optimisation — a diagnosis.** The first version asked for the whole
/// remaining buffer, which is sixteen mebibytes for the kernel, in a single
/// call. That is one firmware round trip with nothing to show for it until it
/// returns, and on 2026-08-22 a Lenovo SR550 booting this loader from a virtual
/// CD stopped after the banner and stayed silent: a firmware call that had not
/// returned and a read that had not started are indistinguishable from outside.
///
/// A mebibyte at a time turns a long read into visible progress, and asks the
/// firmware for something a CD-backed volume is more likely to answer promptly.
const READ_CHUNK: usize = 1 << 20;

/// Reads a whole file into `buffer`, returning how many bytes arrived.
///
/// A file that fills the buffer with more to come is refused — the caller
/// sized the buffer as a stated cap, and a payload past it is a different
/// payload than the build produced.
///
/// Writes a dot per chunk, so slow media reads as slow rather than as stopped.
fn read_fully(root: *mut File, path: &str, buffer: &mut [u8]) -> Result<usize, Unread> {
    let file = efi::open_read_only(root, path).map_err(Unread::Firmware)?;
    let mut total = 0usize;
    loop {
        if total == buffer.len() {
            let mut probe = [0u8; 1];
            let more = efi::read(file, &mut probe).unwrap_or(0);
            efi::close(file);
            return if more == 0 {
                Ok(total)
            } else {
                Err(Unread::TooLarge)
            };
        }
        let end = if buffer.len() - total > READ_CHUNK {
            total + READ_CHUNK
        } else {
            buffer.len()
        };
        let got = match efi::read(file, &mut buffer[total..end]) {
            Ok(got) => got,
            Err(status) => {
                efi::close(file);
                return Err(Unread::Firmware(status));
            }
        };
        if got == 0 {
            break;
        }
        total += got;
        serial::write(".");
    }
    serial::write("\r\n");
    efi::close(file);
    Ok(total)
}

/// Prints one payload line in the exact shape the gate greps.
fn report_payload(name: &str, bytes: &[u8]) {
    let mut hash = Fnv::new();
    hash.eat(bytes);
    serial::write("bhaskixboot: payload ");
    serial::write(name);
    serial::write(" ");
    serial::write_dec(bytes.len() as u64);
    serial::write(" bytes fnv ");
    serial::write_hex(hash.0);
    serial::write("\r\n");
}

/// Measures the payload into the TPM through the firmware, or says why not --
/// RFC 0089. Nothing here refuses the boot: measurement is evidence, and a
/// measurement the firmware refused is reported as refused, so the boot that
/// follows is never mistaken for a measured one.
///
/// **An empty command line is not measured** (the lead's decision, RFC 0089
/// step 8): asked to hash zero bytes, the SR550's firmware logged the previous
/// measurement's digest, where OVMF logs SHA-256 of nothing. A zero-length
/// measurement is not one every firmware makes, so none is asked for; PCR 8
/// is then left as the firmware left it, and the boot report says so.
///
/// `early_event_log` is a test option (`boot.conf`, step 8): ask for the log
/// once before measuring, as the SR550's firmware evidently does, so that the
/// loader's own `GetEventLog` is not the first.
fn measure(
    table: *mut SystemTable,
    kernel: &[u8],
    initrd: &[u8],
    cmdline: &str,
    early_event_log: bool,
) -> Option<*mut efi::Tcg2> {
    use bhaskix_tcglog::measured;
    let Some(tcg2) = efi::tcg2(table) else {
        diag("bhaskixboot: no TCG2 protocol; nothing is measured\r\n");
        return None;
    };
    if early_event_log {
        let _ = efi::get_event_log(tcg2);
        diag("bhaskixboot: GetEventLog asked early (test option early-event-log)\r\n");
    }
    measure_one(tcg2, measured::KERNEL, "kernel", kernel);
    measure_one(tcg2, measured::INITRD, "initrd", initrd);
    if cmdline.is_empty() {
        diag("bhaskixboot: the command line is empty; not measured\r\n");
    } else {
        measure_one(tcg2, measured::CMDLINE, "cmdline", cmdline.as_bytes());
    }
    Some(tcg2)
}

/// The most event log the loader copies. OVMF's are a few kilobytes; one
/// past this is refused as unreadable rather than copied in part.
const EVENT_LOG_MAX: usize = 256 * 1024;

/// Room the copy keeps past the log for the firmware's final events -- those
/// it logs after `GetEventLog`, `ExitBootServices`' own among them. EDK2's
/// area is this size (`PcdTcg2FinalLogAreaLen`, 0x8000).
const FINAL_EVENTS_ROOM: usize = 32 * 1024;

/// The final events table's one version (`EFI_TCG2_FINAL_EVENTS_TABLE_VERSION`).
const FINAL_EVENTS_VERSION: u64 = 1;

/// More final events than any firmware logs between `GetEventLog` and the
/// exit; a count past it is a firmware answer not believed.
const FINAL_EVENTS_MAX: u64 = 1024;

/// Copies the firmware's event log into pages the kernel keeps -- RFC 0089.
///
/// **Read exactly, never past.** `GetEventLog` names where the log starts and
/// where its last entry starts, not where it ends. The header and every entry
/// before the last lie between those two; the last entry's length is read
/// from its own prefix, whose size the header fixes, and then the entry is
/// validated whole. So every byte viewed here is one the firmware's answer
/// places in its log.
fn copy_event_log(table: *mut SystemTable, tcg2: *mut efi::Tcg2) -> handoff::Recorded {
    use bhaskix_tcglog::log;
    let unreadable = |why: &str| {
        serial::write("bhaskixboot: the event log is unreadable: ");
        serial::write(why);
        serial::write("\r\n");
        handoff::Recorded::Unreadable
    };
    let (location, last, truncated) = match efi::get_event_log(tcg2) {
        Ok(answer) => answer,
        Err(_) => return unreadable("GetEventLog refused"),
    };
    // What the final events table already holds at this call -- RFC 0089
    // step 8. The table keeps every event since the *first* `GetEventLog`,
    // whoever asked; events in it now are in the log just returned as well.
    // Only what comes after them is appended after the exit, as Linux skips
    // its `final_events_preboot_size`.
    let preboot = efi::find_tables(table)
        .final_events
        .map_or(0, |at| final_events_header(at).1);
    if location == 0 || last < location || (last - location) as usize > EVENT_LOG_MAX {
        return unreadable("the firmware's answer is out of bounds");
    }
    let before_last = (last - location) as usize;
    let len = if before_last == 0 {
        // The header is the only entry: its fixed 32 bytes say its length.
        // SAFETY: identity-mapped, and the firmware's answer places an entry
        // at `location`; a header is at least its 32-byte fixed part.
        let prefix = unsafe { core::slice::from_raw_parts(location as *const u8, 32) };
        match log::header_len(prefix) {
            Ok(len) => len,
            Err(_) => return unreadable("the header's length"),
        }
    } else {
        // SAFETY: identity-mapped, and the firmware's answer places the
        // header and every entry before the last in these bytes.
        let head = unsafe { core::slice::from_raw_parts(location as *const u8, before_last) };
        let Ok(parsed) = log::Log::parse(head) else {
            return unreadable("the header does not parse");
        };
        let spec = *parsed.spec();
        // SAFETY: as above; an entry starts at `last`, and an entry is at
        // least its fixed prefix, whose size the header fixes.
        let prefix =
            unsafe { core::slice::from_raw_parts(last as *const u8, spec.event2_prefix_len()) };
        let Ok(last_len) = log::event2_len_from_prefix(prefix, &spec) else {
            return unreadable("the last entry's length");
        };
        if before_last + last_len > EVENT_LOG_MAX {
            return unreadable("larger than the loader copies");
        }
        // SAFETY: as above, now the whole entry its own prefix declares.
        let entry = unsafe { core::slice::from_raw_parts(last as *const u8, last_len) };
        if log::event2_len(entry, &spec) != Ok(last_len) {
            return unreadable("the last entry does not parse");
        }
        before_last + last_len
    };
    let pages = (len + FINAL_EVENTS_ROOM).div_ceil(PAGE_SIZE as usize);
    let Ok(base) = efi::allocate_pages(table, efi::LOADER_CODE, pages) else {
        return unreadable("no pages for the copy");
    };
    // SAFETY: just allocated, `pages` long; the source is the log as sized
    // above, identity-mapped.
    unsafe {
        let copy = pages_as_slice(base, pages);
        copy[..len].copy_from_slice(core::slice::from_raw_parts(location as *const u8, len));
    }
    serial::write("bhaskixboot: event log ");
    serial::write_dec(len as u64);
    serial::write(" bytes copied, truncated by the firmware: ");
    serial::write(if truncated { "yes" } else { "no" });
    serial::write("\r\n");
    handoff::Recorded::Log {
        phys: base,
        len,
        room: pages * PAGE_SIZE as usize,
        preboot,
        truncated,
    }
}

/// The final events table's fixed part: its version and its count of events.
/// Read at the loader's `GetEventLog` and again after the exit.
fn final_events_header(table: u64) -> (u64, u64) {
    // SAFETY: the table's fixed part, at the address its configuration entry
    // gives; ACPI NVS, identity-mapped before the exit and after it.
    let fixed = unsafe { core::slice::from_raw_parts(table as *const u8, 16) };
    let word = |at: usize| {
        let mut eight = [0u8; 8];
        eight.copy_from_slice(&fixed[at..at + 8]);
        u64::from_le_bytes(eight)
    };
    (word(0), word(8))
}

/// Appends the firmware's final events to the copy -- RFC 0089 step 6.
///
/// Once `GetEventLog` has been called, the firmware logs every later event in
/// its final events table as well as its main log, and the copy was taken at
/// that call. `ExitBootServices` extends PCR 5 twice (EDK2's
/// `OnExitBootServices`), so without these a replay of PCR 5 can never agree.
/// The table is ACPI NVS memory, which survives the exit and is still
/// identity-mapped here. Each entry is read as the log's last entry was: its
/// prefix, then the length that prefix declares, validated whole. An entry
/// that does not fit the room the copy kept is not cut: it and every later
/// one are left out and the log is marked truncated, which a replay reports
/// as such rather than as a disagreement.
fn append_final_events(recorded: handoff::Recorded, table: Option<u64>) -> handoff::Recorded {
    use bhaskix_tcglog::log;
    let handoff::Recorded::Log {
        phys,
        len,
        room,
        preboot,
        truncated,
    } = recorded
    else {
        return recorded;
    };
    let short = |end: usize, why: &str| {
        serial::write("bhaskixboot: final events not all carried: ");
        serial::write(why);
        serial::write("; the log is marked truncated\r\n");
        handoff::Recorded::Log {
            phys,
            len: end,
            room,
            preboot,
            truncated: true,
        }
    };
    let Some(table) = table else {
        return short(len, "the firmware has no final events table");
    };
    // SAFETY: the copy -- `LoaderCode` pages this image allocated, `room`
    // long, identity-mapped, and nothing else holds them.
    let copy = unsafe { core::slice::from_raw_parts_mut(phys as *mut u8, room) };
    let Ok(parsed) = log::Log::parse(&copy[..len]) else {
        return short(len, "the copy's header does not parse");
    };
    let spec = *parsed.spec();
    let (version, count) = final_events_header(table);
    if version != FINAL_EVENTS_VERSION {
        return short(len, "the table's version is not 1");
    }
    if count > FINAL_EVENTS_MAX {
        return short(len, "the table's count is not believable");
    }
    if preboot > count {
        return short(
            len,
            "the table holds fewer events than it did at GetEventLog",
        );
    }
    let mut at = table + 16;
    let mut end = len;
    for index in 0..count {
        // SAFETY: the table's count places an entry at `at`, and an entry is
        // at least its fixed prefix, whose size the header fixes.
        let prefix =
            unsafe { core::slice::from_raw_parts(at as *const u8, spec.event2_prefix_len()) };
        let Ok(entry_len) = log::event2_len_from_prefix(prefix, &spec) else {
            return short(end, "an entry's length");
        };
        // SAFETY: as above, now the whole entry its own prefix declares.
        let entry = unsafe { core::slice::from_raw_parts(at as *const u8, entry_len) };
        if log::event2_len(entry, &spec) != Ok(entry_len) {
            return short(end, "an entry does not parse");
        }
        at += entry_len as u64;
        // Already in the copy: logged before the loader's own `GetEventLog`.
        if index < preboot {
            continue;
        }
        if entry_len > room - end {
            return short(end, "more than the room the copy kept");
        }
        copy[end..end + entry_len].copy_from_slice(entry);
        end += entry_len;
    }
    serial::write("bhaskixboot: final events ");
    serial::write_dec(count - preboot);
    serial::write(" (");
    serial::write_dec((end - len) as u64);
    serial::write(" bytes) appended after the exit; ");
    serial::write_dec(preboot);
    serial::write(" already in the log at GetEventLog, not appended twice\r\n");
    handoff::Recorded::Log {
        phys,
        len: end,
        room,
        preboot,
        truncated,
    }
}

/// One object into one PCR, logged as `bhaskix <name>`, and the outcome said.
fn measure_one(tcg2: *mut efi::Tcg2, (pcr, tag): (u32, u32), name: &str, bytes: &[u8]) {
    let mut label = [0u8; 32];
    let prefix = b"bhaskix ";
    let label_len = prefix.len() + name.len();
    label[..prefix.len()].copy_from_slice(prefix);
    label[prefix.len()..label_len].copy_from_slice(name.as_bytes());
    let mut event = [0u8; 64];
    let Some(len) = bhaskix_tcglog::tagged_event(pcr, tag, &label[..label_len], &mut event) else {
        diag("bhaskixboot: a measurement event did not fit its buffer\r\n");
        return;
    };
    match efi::hash_log_extend_event(tcg2, bytes, &event[..len]) {
        Ok(()) => {
            serial::write("bhaskixboot: measured ");
            serial::write(name);
            serial::write(" into PCR ");
            serial::write_dec(u64::from(pcr));
            serial::write("\r\n");
        }
        Err(status) => {
            serial::write("bhaskixboot: measurement of ");
            serial::write(name);
            serial::write(" REFUSED, status ");
            serial::write_hex(status as u64);
            serial::write("\r\n");
        }
    }
}

/// The time-stamp counter, for RFC 0091's cost line.
fn tsc() -> u64 {
    // SAFETY: `rdtsc` reads a counter and has no other effect.
    unsafe { core::arch::x86_64::_rdtsc() }
}

/// What the firmware said about Secure Boot, on the wire **and the firmware
/// console** -- through [`diag`], whole.
///
/// Until 2026-10-30 this line and [`report_cost`]'s went out with
/// `serial::write` alone, which while boot services run is the firmware's
/// serial protocol and nothing else. The SR550's service processor shows the
/// firmware *console*, so on that machine both lines were missing while every
/// `diag` line around them arrived (RFC 0091 step 7, 2026-10-30), and the raw
/// value could not be told apart from *absent* or *unreadable*.
fn report_secure_boot(state: efi::SecureBoot) {
    let mut line = Line::new();
    match state {
        efi::SecureBoot::On => {
            line.push("bhaskixboot: SecureBoot reads 1 -- the firmware verified this loader\r\n")
        }
        efi::SecureBoot::Off => {
            line.push("bhaskixboot: SecureBoot reads 0 -- nothing verified this loader\r\n")
        }
        efi::SecureBoot::Absent => line.push("bhaskixboot: SecureBoot is absent; read as off\r\n"),
        efi::SecureBoot::Unreadable(status) => {
            line.push("bhaskixboot: SecureBoot unreadable, status ");
            line.push_hex(status as u64);
            line.push("; read as off\r\n");
        }
    }
    diag(line.as_str());
}

/// How long hashing the boot set and checking `boot.sig` took, in TSC ticks
/// and, calibrated against ten milliseconds of the firmware's `Stall`, in
/// milliseconds -- RFC 0091's performance implications, measured where it runs.
fn report_cost(table: *mut SystemTable, ticks: u64, bytes: usize) {
    let before = tsc();
    efi::stall(table, 10_000);
    let per_ms = tsc().wrapping_sub(before) / 10;
    // Whole, through `diag`, for the reason `report_secure_boot` gives.
    let mut line = Line::new();
    line.push("bhaskixboot: boot set hashed and checked: ");
    line.push_dec(bytes as u64);
    line.push(" bytes in ");
    line.push_dec(ticks);
    line.push(" ticks");
    if let Some(ms) = ticks.checked_div(per_ms) {
        line.push(", ~");
        line.push_dec(ms);
        line.push(" ms at ");
        line.push_dec(per_ms);
        line.push(" ticks/ms");
    }
    line.push("\r\n");
    diag(line.as_str());
}

/// The PCR 8 event's bytes: the verdict (0 verified, 1 not), the key id that
/// verified (zeros otherwise), and the `SecureBoot` byte read (0xfe absent,
/// 0xff unreadable).
fn verdict_bytes(signature: Signature, secure_boot: efi::SecureBoot) -> [u8; 10] {
    let mut bytes = [0u8; 10];
    match signature {
        Signature::Verified { key_id, .. } => bytes[1..9].copy_from_slice(&key_id),
        _ => bytes[0] = 1,
    }
    bytes[9] = match secure_boot {
        efi::SecureBoot::On => 1,
        efi::SecureBoot::Off => 0,
        efi::SecureBoot::Absent => 0xfe,
        efi::SecureBoot::Unreadable(_) => 0xff,
    };
    bytes
}

/// The verdict, on the screen and the wire.
fn report_signature(signature: Signature, secure_boot: efi::SecureBoot) {
    let enforced = secure_boot == efi::SecureBoot::On;
    let mut line = Line::new();
    match signature {
        Signature::Verified { key_id, .. } => {
            let mut hex = [0u8; 16];
            const DIGITS: &[u8; 16] = b"0123456789abcdef";
            for (i, byte) in key_id.iter().enumerate() {
                hex[2 * i] = DIGITS[usize::from(byte >> 4)];
                hex[2 * i + 1] = DIGITS[usize::from(byte & 15)];
            }
            line.push("bhaskixboot: boot signature verified: key ");
            line.push(core::str::from_utf8(&hex).unwrap_or("?"));
            if key_id == bhaskix_boot::TEST_KEY_ID {
                line.push(" TEST KEY");
            }
            line.push(if enforced {
                ", Secure Boot on\r\n"
            } else {
                ", NOT ENFORCED: Secure Boot is off\r\n"
            });
        }
        Signature::NotVerified(reason) => {
            line.push("bhaskixboot: boot signature NOT VERIFIED (");
            line.push(reason.describe());
            line.push(if enforced {
                ")\r\n"
            } else {
                "), NOT ENFORCED: Secure Boot is off -- booting\r\n"
            });
        }
        Signature::NotChecked => {}
    }
    diag(line.as_str());
}

/// One line, assembled before it is written. **`diag` must be handed whole
/// lines**: it writes the wire and the firmware console, and OVMF mirrors its
/// console onto the same wire, so a line written in pieces arrives with each
/// piece twice, interleaved (seen 2026-10-29, on the first boot of this check).
struct Line {
    bytes: [u8; 192],
    len: usize,
}

impl Line {
    const fn new() -> Self {
        Self {
            bytes: [0; 192],
            len: 0,
        }
    }

    /// Appends `text`, or as much of it as fits.
    fn push(&mut self, text: &str) {
        let take = text.len().min(self.bytes.len() - self.len);
        self.bytes[self.len..self.len + take].copy_from_slice(&text.as_bytes()[..take]);
        self.len += take;
    }

    /// Appends a decimal number, as `serial::write_dec` writes one.
    fn push_dec(&mut self, mut value: u64) {
        let mut digits = [0u8; 20];
        let mut at = digits.len();
        loop {
            at -= 1;
            digits[at] = b'0' + (value % 10) as u8;
            value /= 10;
            if value == 0 {
                break;
            }
        }
        self.push(core::str::from_utf8(&digits[at..]).unwrap_or("?"));
    }

    /// Appends `0x` and sixteen hex digits, as `serial::write_hex` writes them.
    fn push_hex(&mut self, value: u64) {
        let mut digits = *b"0x0000000000000000";
        for (at, shift) in (0..16).rev().enumerate() {
            let nibble = ((value >> (shift * 4)) & 0xF) as u8;
            digits[2 + at] = if nibble < 10 {
                b'0' + nibble
            } else {
                b'a' + nibble - 10
            };
        }
        self.push(core::str::from_utf8(&digits).unwrap_or("?"));
    }

    fn as_str(&self) -> &str {
        core::str::from_utf8(&self.bytes[..self.len])
            .unwrap_or("bhaskixboot: (a line that did not fit)\r\n")
    }
}

/// A refusal, printed with its status, and the park that follows every one
/// of them: past the exit there is nowhere to return a status to, and
/// before it an inconsistent loader has no business handing control back.
/// A payload that was not read, refused with its reason: the firmware's
/// status, or the cap it is larger than.
fn refuse_unread(what: &str, pages: usize, why: Unread) -> ! {
    match why {
        Unread::Firmware(status) => refuse(what, status as u64),
        Unread::TooLarge => {
            serial::write("bhaskixboot: ");
            serial::write(what);
            serial::write(": larger than its ");
            serial::write_dec(((pages * 4096) >> 20) as u64);
            serial::write(" MiB buffer\r\n");
            park()
        }
    }
}

fn refuse(what: &str, status: u64) -> ! {
    serial::write("bhaskixboot: ");
    serial::write(what);
    serial::write(", status ");
    serial::write_hex(status);
    serial::write("\r\n");
    park()
}

fn park() -> ! {
    loop {
        // SAFETY: `hlt` parks the machine; the harness reads the wire and
        // ends the run.
        unsafe { core::arch::asm!("hlt", options(nomem, nostack)) };
    }
}

/// A view of pages the firmware allocated to this loader.
///
/// # Safety
///
/// `base` must be the address `allocate_pages` returned, `pages` its size.
unsafe fn pages_as_slice(base: u64, pages: usize) -> &'static mut [u8] {
    // SAFETY: the caller's contract — pages the firmware allocated to this
    // image, identity-mapped, exclusively the loader's.
    unsafe { core::slice::from_raw_parts_mut(base as *mut u8, pages * PAGE_SIZE as usize) }
}

/// RAM's top: the highest end over the kinds that are memory. The device
/// windows past it are not the direct map's business. One rule for the map
/// read before the exit, which sizes the table pool, and the map taken at it,
/// which the tables are built from.
fn ram_top(map: &efi::MemoryMap) -> u64 {
    let mut top = 0u64;
    map.regions(|kind, base, bytes| {
        if (1..=9).contains(&kind) {
            top = top.max(base + bytes);
        }
    });
    top
}

/// The entry point the UEFI firmware calls, by the target's convention.
///
/// Not `pub`: the firmware finds it by the PE entry address, not by Rust
/// visibility, and keeping it private keeps the table types private too.
#[unsafe(no_mangle)]
extern "efiapi" fn efi_main(image_handle: usize, system_table: *mut SystemTable) -> usize {
    serial::init();
    serial::write(BANNER);

    let Some(table) = efi::validate(system_table) else {
        serial::write("bhaskixboot: no valid system table; stopping at the banner\r\n");
        return efi::SUCCESS;
    };
    // **Hand the port to the firmware for the rest of boot services.** Before
    // this line there was no table to ask; after it, writing COM1's registers
    // underneath the firmware's own driver is the thing UEFI §12 provides a
    // protocol to avoid. Released again before `ExitBootServices`.
    if let Some(port) = efi::serial_io(table) {
        serial::adopt_firmware_port(port);
        diag("bhaskixboot: speaking through the firmware's serial port\r\n");
    } else {
        diag("bhaskixboot: no firmware serial port; writing COM1 directly\r\n");
    }
    diag("bhaskixboot: system table validated\r\n");

    // **The console banner is the last thing in this window that calls
    // firmware**, and on 2026-08-22 an SR550 stopped somewhere in here with
    // only the serial banner out. These three markers exist to say which of
    // the three steps it was, because a boot on somebody's server is too
    // expensive to spend on a guess.
    match efi::con_out(table) {
        Some(con_out) => {
            // Adopted *before* the banner goes to it, so that everything from
            // here on appears on the screen as well as the wire.
            CONSOLE.store(con_out as usize, core::sync::atomic::Ordering::Relaxed);
            console_write(con_out, BANNER);
            diag("bhaskixboot: console adopted; diagnostics go to both\r\n");
        }
        None => diag("bhaskixboot: no console output protocol; serial only\r\n"),
    }

    // The payload, read whole into pages the loader owns. The kernel and
    // the initrd are allocated as `LoaderCode` — the label the region
    // translation turns into `KernelAndModules` — and their checksums are
    // printed for the gate exactly as when they were streamed.
    // **A marker before every firmware call in this window**, because the
    // window used to be silent: from the banner to the first payload line the
    // loader said nothing, so a call that never returned looked exactly like a
    // loader that had not started. On the SR550 that cost a boot to learn
    // nothing from. Each of these is one line and buys the next failure a name.
    diag("bhaskixboot: opening the boot volume\r\n");
    let root = match efi::open_boot_volume(table, image_handle) {
        Ok(root) => root,
        Err(status) => refuse("the boot volume would not open", status as u64),
    };
    diag("bhaskixboot: allocating the kernel buffer\r\n");
    let kernel_base = match efi::allocate_pages(table, efi::LOADER_CODE, KERNEL_BUFFER_PAGES) {
        Ok(base) => base,
        Err(status) => refuse("the kernel buffer would not allocate", status as u64),
    };
    // SAFETY: just allocated, sized as passed.
    let kernel_buffer = unsafe { pages_as_slice(kernel_base, KERNEL_BUFFER_PAGES) };
    serial::write("bhaskixboot: reading bhaskix\\kernel ");
    let kernel_len = match read_fully(root, KERNEL_PATH, kernel_buffer) {
        Ok(len) => len,
        Err(why) => refuse_unread("payload kernel REFUSED", KERNEL_BUFFER_PAGES, why),
    };
    report_payload("kernel", &kernel_buffer[..kernel_len]);

    let initrd_base = match efi::allocate_pages(table, efi::LOADER_CODE, INITRD_BUFFER_PAGES) {
        Ok(base) => base,
        Err(status) => refuse("the initrd buffer would not allocate", status as u64),
    };
    // SAFETY: just allocated, sized as passed.
    let initrd_buffer = unsafe { pages_as_slice(initrd_base, INITRD_BUFFER_PAGES) };
    serial::write("bhaskixboot: reading bhaskix\\initrd.tar ");
    let initrd_len = match read_fully(root, INITRD_PATH, initrd_buffer) {
        Ok(len) => len,
        Err(why) => refuse_unread("payload initrd REFUSED", INITRD_BUFFER_PAGES, why),
    };
    report_payload("initrd", &initrd_buffer[..initrd_len]);

    // **Absent and unreadable are different now** (RFC 0091): `boot.sig` names
    // the digest of every byte of `boot.conf`, so a file too large to read, or
    // one the firmware refused, is not quietly an empty one. Both still boot
    // with an empty command line when nothing is enforcing; the verdict says
    // which happened.
    let mut conf = [0u8; 4096];
    let mut conf_unreadable = false;
    let conf_len = match read_fully(root, CONFIG_PATH, &mut conf) {
        Ok(len) => {
            report_payload("conf", &conf[..len]);
            len
        }
        Err(Unread::Firmware(efi::NOT_FOUND)) => {
            serial::write("bhaskixboot: payload conf absent; the command line is empty\r\n");
            0
        }
        Err(_) => {
            serial::write(
                "bhaskixboot: payload conf unreadable; the command line is empty and boot.sig cannot verify\r\n",
            );
            conf_unreadable = true;
            0
        }
    };
    let conf_text = core::str::from_utf8(&conf[..conf_len]).unwrap_or("");
    // The first line, `cmdline=<rest>`; anything else is an empty command
    // line, from the shape of the parse rather than a guess. Later lines are
    // options; one exists, a test option (RFC 0089 step 8).
    let cmdline = conf_text
        .lines()
        .next()
        .and_then(|line| line.strip_prefix("cmdline="))
        .unwrap_or("");
    let early_event_log = conf_text
        .lines()
        .skip(1)
        .any(|line| line.trim() == "early-event-log");
    // The boot set's signature, read with the files it names and before the
    // volume closes -- RFC 0091. Absent is a verdict, not a refusal: whether it
    // stops the boot is the policy's to say, below.
    let mut sig = [0u8; 8192];
    let sig_read = match read_fully(root, SIG_PATH, &mut sig) {
        Ok(len) => {
            report_payload("sig", &sig[..len]);
            Ok(len)
        }
        Err(Unread::Firmware(efi::NOT_FOUND)) => Err(Unverified::Missing),
        Err(_) => Err(Unverified::Unreadable),
    };
    efi::close(root);

    // **Measured before anything interprets it** -- RFC 0089. The bytes as
    // read, before the parse, the placement and the slide, so a verifier can
    // predict the digest from the file alone.
    let tcg2 = measure(
        table,
        &kernel_buffer[..kernel_len],
        &initrd_buffer[..initrd_len],
        cmdline,
        early_event_log,
    );
    // **RFC 0091 link 2: the boot set, checked after it was measured and before
    // anything interprets it.** The loader hashes what it holds rather than
    // reading digests back out of the event log, which the firmware wrote.
    let secure_boot = efi::secure_boot(table);
    report_secure_boot(secure_boot);
    let started = tsc();
    let signature = match sig_read {
        Err(why) => Signature::NotVerified(why),
        Ok(_) if conf_unreadable => Signature::NotVerified(Unverified::Unreadable),
        Ok(len) => {
            let held = Digests {
                kernel: bhaskix_sha256::digest(&kernel_buffer[..kernel_len]),
                initrd: bhaskix_sha256::digest(&initrd_buffer[..initrd_len]),
                boot_conf: bhaskix_sha256::digest(&conf[..conf_len]),
            };
            match bhaskix_bootsig::check(&sig[..len], keys::KEYS, &held) {
                Ok(key_id) => Signature::Verified {
                    key_id,
                    secure_boot: secure_boot == efi::SecureBoot::On,
                },
                Err(refusal) => Signature::NotVerified(Unverified::Refused(refusal)),
            }
        }
    };
    report_cost(
        table,
        tsc().wrapping_sub(started),
        kernel_len + initrd_len + conf_len,
    );
    // The verdict into PCR 8 -- question 8 -- *before* acting on it, so a
    // refused boot is in the record too, and before the log is copied, so the
    // copy holds it.
    if let Some(tcg2) = tcg2 {
        measure_one(
            tcg2,
            bhaskix_tcglog::measured::VERDICT,
            "verdict",
            &verdict_bytes(signature, secure_boot),
        );
    }
    report_signature(signature, secure_boot);
    // **The policy** (question 2, decided 2026-10-29): with Secure Boot on, a
    // set that did not verify is refused -- said on the screen and the wire,
    // held long enough to read, and handed back to the boot manager, which
    // tries the next option as the firmware does with an image it refuses
    // (UEFI §32.6.1). The only refusal here that returns. With Secure Boot
    // off, link 1 is down and this loader is itself unprotected, so refusing
    // would stop nobody the check is about: it boots, and says so.
    if let (efi::SecureBoot::On, Signature::NotVerified(reason)) = (secure_boot, signature) {
        let mut line = Line::new();
        line.push("bhaskixboot: refusing to boot: ");
        line.push(reason.describe());
        line.push(" (Secure Boot is on)\r\n");
        diag(line.as_str());
        diag("bhaskixboot: returning to the boot manager in 5 seconds\r\n");
        efi::stall(table, 5_000_000);
        return efi::SECURITY_VIOLATION;
    }

    // And the log those measurements went into, copied while the protocol
    // that names it still exists -- RFC 0089 step 3.
    let recorded = match tcg2 {
        Some(tcg2) => copy_event_log(table, tcg2),
        None => handoff::Recorded::NoTpm,
    };

    // The kernel, parsed by the crate the kernel itself loads with — told
    // it is validating for the high half, which is the only thing that
    // differs from a ring 3 load.
    let image = match parse_in(&kernel_buffer[..kernel_len], AddressHalf::Kernel) {
        Ok(image) => image,
        Err(_) => refuse("the kernel image failed the parser it was built against", 0),
    };
    serial::write("bhaskixboot: kernel parsed: ");
    serial::write_dec(image.segment_count() as u64);
    serial::write(" loadable segments, entry ");
    serial::write_hex(image.entry);
    serial::write("\r\n");

    // Placement: one physically contiguous span covering every segment,
    // zeroed — the zero-fill tails are part of the contract — then each
    // segment's file bytes copied to its offset within the span.
    let mut virt_base = u64::MAX;
    let mut virt_end = 0u64;
    for segment in image.segments() {
        let Some((start, end)) = page_span(segment) else {
            refuse("a segment span wrapped", 0);
        };
        virt_base = virt_base.min(start);
        virt_end = virt_end.max(end);
    }
    let span_pages = ((virt_end - virt_base) / PAGE_SIZE) as usize;
    let kernel_phys = match efi::allocate_pages(table, efi::LOADER_CODE, span_pages) {
        Ok(base) => base,
        Err(status) => refuse("the kernel span would not allocate", status as u64),
    };
    // SAFETY: just allocated, sized as passed.
    let span = unsafe { pages_as_slice(kernel_phys, span_pages) };
    span.fill(0);
    for segment in image.segments() {
        let at = (segment.address - virt_base) as usize;
        span[at..at + segment.file_size].copy_from_slice(
            &kernel_buffer[segment.file_offset..segment.file_offset + segment.file_size],
        );
    }
    // The slide — RFC 0021's draw, joining the sum exactly as the step-5
    // comment promised it would. Policy: a machine with entropy draws a
    // 2 MiB-aligned slide from (0, 1 GiB) — the range excludes zero on
    // purpose, so the kernel's "slide of zero means KASLR did not happen"
    // stays a true sentence — and a machine that cannot answer boots
    // unslid and says so, RFC 0021's rule for every consumer, held here
    // for the first consumer that runs before the kernel exists.
    let slide = match bhaskix_rand::u64() {
        Some(draw) => (1 + draw % 511) << 21,
        None => {
            serial::write("bhaskixboot: kaslr no entropy; entering unslid, and saying so\r\n");
            0
        }
    };

    // A relocatable kernel's fixups: the value written is the slide plus
    // the addend. Any relocation kind the loader cannot express refuses
    // the whole image, in the crate, before a single byte is patched.
    let applied = match bhaskix_elf::for_each_relative_relocation(
        &kernel_buffer[..kernel_len],
        &image,
        |address, addend| {
            let at = (address - virt_base) as usize;
            span[at..at + 8].copy_from_slice(&slide.wrapping_add(addend as u64).to_le_bytes());
        },
    ) {
        Ok(applied) => applied,
        Err(_) => refuse("a relocation the loader cannot express", 0),
    };
    serial::write("bhaskixboot: relative relocations applied: ");
    serial::write_dec(applied as u64);
    serial::write(", slide ");
    serial::write_hex(slide);
    serial::write("\r\n");
    serial::write("bhaskixboot: kernel placed at ");
    serial::write_hex(kernel_phys);
    serial::write(", virt base ");
    serial::write_hex(virt_base);
    serial::write(", span ");
    serial::write_dec((virt_end - virt_base) / 1024);
    serial::write(" KiB, W^X per segment\r\n");

    // The scaffolding: the handoff block here and the table pool below, both
    // `LoaderData` — `BootloaderReclaimable` in the kernel's map.
    let block = match efi::allocate_pages(table, efi::LOADER_DATA, handoff::BLOCK_PAGES) {
        Ok(base) => base,
        Err(status) => refuse("the handoff block would not allocate", status as u64),
    };

    // The machine's shape, while the firmware still answers.
    let tables = efi::find_tables(table);
    let (rsdp, smbios) = (tables.rsdp, tables.smbios);
    match rsdp {
        Some(address) => {
            serial::write("bhaskixboot: acpi rsdp ");
            serial::write_hex(address);
            serial::write("\r\n");
        }
        None => serial::write("bhaskixboot: acpi rsdp absent\r\n"),
    }
    match smbios {
        Some(address) => {
            serial::write("bhaskixboot: smbios ");
            serial::write_hex(address);
            serial::write("\r\n");
        }
        None => serial::write("bhaskixboot: smbios absent\r\n"),
    }
    let framebuffer = efi::framebuffer(table);
    match framebuffer {
        Some((width, height, stride, base, _bgr)) => {
            serial::write("bhaskixboot: framebuffer ");
            serial::write_dec(u64::from(width));
            serial::write("x");
            serial::write_dec(u64::from(height));
            serial::write(" stride ");
            serial::write_dec(u64::from(stride));
            serial::write(" at ");
            serial::write_hex(base);
            serial::write("\r\n");
        }
        None => serial::write("bhaskixboot: framebuffer absent; serial-only is a state\r\n"),
    }
    let bsp_lapic_id = (core::arch::x86_64::__cpuid(1).ebx >> 24) & 0xff;

    // **The table pool, sized from the machine** (2026-10-08). It was a
    // fixed 128 frames, chosen under an emulator with 256 MiB, and an SR550
    // with 192 GiB ran it dry after the exit -- where a refusal is all that
    // is left. The tables cost a directory per GiB of the direct map, so the
    // map read here, while the firmware still answers, sizes the pool to
    // `bhaskix_boot::table_frames_bound`, a host-tested upper bound. The
    // builder still counts and still refuses; the line below says what was
    // set aside, and the `tables built` line what was used.
    let top_before = match efi::peek_map(table) {
        Ok(map) => ram_top(&map),
        Err((status, _)) => refuse(
            "the memory map would not read before the exit",
            status as u64,
        ),
    };
    let framebuffer_span = framebuffer
        .map(|(_, height, stride, base, _)| (base, u64::from(height) * u64::from(stride) * 4));
    let pool_frames =
        bhaskix_boot::table_frames_bound(top_before, framebuffer_span, virt_end - virt_base);
    let pool_base = match efi::allocate_pages(table, efi::LOADER_DATA, pool_frames as usize) {
        Ok(base) => base,
        Err(status) => refuse("the table pool would not allocate", status as u64),
    };
    serial::write("bhaskixboot: table pool ");
    serial::write_dec(pool_frames);
    serial::write(" frames for memory to ");
    serial::write_hex(top_before);
    serial::write("\r\n");

    // The exit: the map and the goodbye, in one held breath.
    let map = match efi::take_map_and_exit(table, image_handle) {
        Ok(map) if map.is_empty() => {
            // A firmware that exits successfully while handing over an
            // empty map is lying about something; park loudly.
            serial::write("bhaskixboot: the exit succeeded with an empty memory map\r\n");
            park()
        }
        Ok(map) => map,
        Err((status, dropped)) => {
            serial::write("bhaskixboot: the exit was refused, status ");
            serial::write_hex(status as u64);
            if dropped != 0 {
                serial::write(", ");
                serial::write_dec(dropped as u64);
                serial::write(" descriptors past the buffer");
            }
            serial::write("\r\n");
            park()
        }
    };
    serial::write("bhaskixboot: memory map ");
    serial::write_dec(map.len() as u64);
    serial::write(" descriptors, ");
    serial::write_dec(map.usable_bytes() / 1024);
    serial::write(" KiB usable, ");
    serial::write_dec(map.reclaimable_bytes() / 1024);
    serial::write(" KiB reclaimable; truncated: no\r\n");
    serial::write("bhaskixboot: boot services exited; the machine is ours\r\n");
    // The events logged since the copy was taken, `ExitBootServices`' own
    // among them -- RFC 0089 step 6.
    let recorded = append_final_events(recorded, tables.final_events);

    // Step 5's second half, on a machine the loader owns: the tables, then
    // the handoff, over RAM's top as the exit's own map gives it.
    let physical_top = ram_top(&map);
    let mut pool = paging::TablePool::new(pool_base, pool_frames);
    let Some(world) = paging::build(
        &mut pool,
        physical_top,
        framebuffer_span,
        &image,
        kernel_phys,
        virt_base,
        slide,
    ) else {
        serial::write("bhaskixboot: the table pool ran dry; the guess is now a measurement\r\n");
        park()
    };
    serial::write("bhaskixboot: tables built: ");
    serial::write_dec(pool.used());
    serial::write(" frames; identity and hhdm to ");
    serial::write_hex(physical_top);
    serial::write(", kernel in the high half, cr3 ");
    serial::write_hex(world.root);
    serial::write("\r\n");

    let findings = handoff::Findings {
        map: &map,
        kernel_phys,
        kernel_virt: virt_base + slide,
        framebuffer,
        rsdp,
        smbios,
        cmdline,
        initrd: (initrd_base, initrd_len),
        recorded,
        signature,
        bsp_lapic_id,
    };
    let built = match handoff::assemble(block, &findings) {
        Ok(built) => built,
        Err(count) => refuse("the handoff would not assemble", count as u64),
    };
    serial::write("bhaskixboot: handoff assembled: version ");
    serial::write_dec(u64::from(bhaskix_boot::HANDOFF_VERSION));
    serial::write(", ");
    serial::write_dec(built.regions as u64);
    serial::write(" regions, initrd ");
    serial::write_dec(built.initrd_bytes as u64);
    serial::write(" bytes, stack top ");
    serial::write_hex(built.stack_top);
    serial::write("\r\n");

    // Step 6: the jump. Interrupts off for the entry contract; `EFER.NXE`
    // set so the NX bits in the world's tables are architecture rather than
    // reserved-bit faults; the world's root into CR3 — the loader keeps
    // executing through the identity view it built for exactly this moment
    // — then the kernel's own stack, and the door: the `Handoff` in the
    // first argument register, the magic in the second, and the entry the
    // image named. Nothing returns from here; the next words on the wire
    // are the kernel's.
    let entry = image.entry.wrapping_add(slide);
    serial::write("bhaskixboot: the world is built; jumping: entry ");
    serial::write_hex(entry);
    serial::write(", cr3 ");
    serial::write_hex(world.root);
    serial::write(", handoff ");
    serial::write_hex(built.handoff);
    serial::write("\r\n");
    // SAFETY: RFC 0028's entry contract, held by construction above: the
    // root maps the identity view (this code keeps running), the kernel's
    // segments at the entry's addresses W^X, and the handoff block; the
    // stack top is inside that block; the registers are pinned so the
    // MSR sequence's eax/ecx/edx cannot collide with them.
    unsafe {
        core::arch::asm!(
            "cli",
            "mov ecx, 0xC0000080",
            "rdmsr",
            "or eax, 1 << 11",
            "wrmsr",
            "mov cr3, r8",
            "mov rsp, r9",
            "xor ebp, ebp",
            "jmp r10",
            in("r8") world.root,
            in("r9") built.stack_top,
            in("r10") entry,
            in("rdi") built.handoff,
            in("rsi") bhaskix_boot::NATIVE_ENTRY_MAGIC,
            options(noreturn),
        )
    }
}

/// Prints `text` on the firmware console, UCS-2 encoded in bounded chunks.
/// The firmware console this loader also speaks to, once it has one.
///
/// **Every diagnostic goes to both the wire and the screen**, and that is a
/// lesson from a machine rather than a preference. On the SR550 the loader's
/// serial output stopped after its first line, so five boots learned nothing —
/// while the screen, which the operator was looking at, carried the banner and
/// then nothing else, because the banner was the only thing this loader ever
/// wrote there. A diagnostic that exists on one channel is a diagnostic that
/// one broken channel erases.
static CONSOLE: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// Writes to the serial line and, once it is known, the firmware console.
///
/// The name is short because it is used everywhere the loader has something to
/// say.
///
/// **On a machine whose firmware redirects its console to the same serial port,
/// every line appears twice** — QEMU under OVMF is such a machine, and its logs
/// show the doubling. That is the cost, and it is worth paying: on a real
/// server the console is a screen and the serial line is a service processor,
/// two channels that fail independently, and the whole reason this function
/// exists is that on the SR550 one of them failed silently after a single
/// line.
fn diag(text: &str) {
    serial::write(text);
    let con_out = CONSOLE.load(core::sync::atomic::Ordering::Relaxed);
    if con_out != 0 {
        console_write(con_out as *mut SimpleTextOutput, text);
    }
}

fn console_write(con_out: *mut SimpleTextOutput, text: &str) {
    let mut buffer = [0u16; 64];
    let mut at = 0;
    for byte in text.bytes() {
        buffer[at] = u16::from(byte);
        at += 1;
        if at == buffer.len() - 1 {
            buffer[at] = 0;
            efi::output_string(con_out, &buffer);
            at = 0;
        }
    }
    if at > 0 {
        buffer[at] = 0;
        efi::output_string(con_out, &buffer);
    }
}

/// There is nowhere to unwind to and no kernel to report through.
#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    serial::write("bhaskixboot: panic\r\n");
    park()
}
