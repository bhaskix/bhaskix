// SPDX-License-Identifier: Apache-2.0
//! Limine boot protocol bindings and translation.
//!
//! **This is the only file in Bhaskix that knows Limine exists.** CI enforces
//! that; see `tools/check-containment.sh`. Everything above this line consumes
//! [`bhaskix_boot::Handoff`], a structure the project owns, so replacing Limine
//! with `bhaskixboot.efi` in Phase 2 rewrites this file and nothing else
//! (`docs/architecture.md` §1).
//!
//! The layouts below mirror `limine.h` from the Limine v8.x binary release.
//! They are `#[repr(C)]` and must match it field for field: a mismatch reads
//! garbage from bootloader-owned memory and produces a fault whose cause is
//! nowhere near where it appears.

use core::cell::UnsafeCell;
use core::ffi::c_void;

use bhaskix_boot::{
    Framebuffer, HANDOFF_VERSION, Handoff, MemoryKind, MemoryRegion, PhysAddr, PixelFormat,
    VirtAddr,
};

/// Common magic prefixing every request ID.
const MAGIC_0: u64 = 0xc7b1_dd30_df4c_8b88;
const MAGIC_1: u64 = 0x0a82_e883_a194_f07b;

/// Protocol base revision this kernel is built against.
///
/// The bootloader zeroes the third word if it supports this revision. If it
/// does not, Limine refuses to boot the kernel outright rather than starting
/// it with different semantics — which is the behaviour we want, since a
/// silently different memory-map contract would be very hard to diagnose.
/// Wrapper so the base-revision marker is not an immutable static.
///
/// The bootloader zeroes the third word *from outside the program*. Declaring
/// it as a plain `static [u64; 3]` would let the compiler assume it still
/// holds the initialiser and const-fold [`base_revision_supported`] to
/// `false` — a bug that would appear only under optimisation.
#[repr(transparent)]
struct BaseRevision(UnsafeCell<[u64; 3]>);

// SAFETY: written only by the bootloader, before any Bhaskix code runs.
unsafe impl Sync for BaseRevision {}

#[used]
#[unsafe(link_section = ".requests")]
static BASE_REVISION: BaseRevision = BaseRevision(UnsafeCell::new([
    0xf956_2b2d_5c95_a6c8,
    0x6a7b_3849_4453_6bdc,
    3,
]));

/// Marks the start of the request area, so the bootloader can find requests
/// without scanning the whole image.
#[used]
#[unsafe(link_section = ".requests_start_marker")]
static REQUESTS_START: [u64; 4] = [
    0xf6b8_f4b3_9de7_d1ae,
    0xfab9_1a69_40fc_b9cf,
    0x785c_6ed0_15d3_e316,
    0x181e_920a_7852_b9d9,
];

/// Marks the end of the request area.
#[used]
#[unsafe(link_section = ".requests_end_marker")]
static REQUESTS_END: [u64; 2] = [0xadc0_e053_1bb1_0d03, 0x9572_709f_3176_4c62];

/// A request the bootloader fills in before jumping to the kernel.
///
/// The response pointer is written by the bootloader while it still owns the
/// machine, which is why it lives in an [`UnsafeCell`]: from Rust's point of
/// view the static is mutated by something outside the program.
#[repr(C)]
struct Request<T> {
    id: [u64; 4],
    revision: u64,
    response: UnsafeCell<*const T>,
}

// SAFETY: these statics are written once by the bootloader before any Bhaskix
// code runs, and are only ever read afterwards. There is no point at which a
// write races with a read: the bootloader has finished by the time the kernel
// entry point is called, and the kernel never writes them.
unsafe impl<T> Sync for Request<T> {}

impl<T> Request<T> {
    const fn new(id_2: u64, id_3: u64) -> Self {
        Self {
            id: [MAGIC_0, MAGIC_1, id_2, id_3],
            revision: 0,
            response: UnsafeCell::new(core::ptr::null()),
        }
    }

    /// The response, or `None` if the bootloader did not provide one.
    ///
    /// A missing response is normal and not an error: firmware without ACPI
    /// has no RSDP, a headless machine has no framebuffer.
    fn response(&self) -> Option<&'static T> {
        // SAFETY: the bootloader has finished writing (see the `Sync` impl).
        // The pointer it wrote, if non-null, addresses a response structure in
        // bootloader-reclaimable memory that stays valid until the kernel
        // reclaims it — which it does only after consuming the handoff
        // (docs/memory.md §1).
        //
        // The read is volatile because the value was written by something
        // outside this program; a plain read would let the compiler reuse the
        // null it saw in the initialiser.
        let pointer = unsafe { self.response.get().read_volatile() };
        if pointer.is_null() {
            None
        } else {
            // SAFETY: non-null, and points to a `T` written by the bootloader
            // per the protocol.
            Some(unsafe { &*pointer })
        }
    }
}

// --- Response layouts, mirroring limine.h -------------------------------

#[repr(C)]
struct BootloaderInfoResponse {
    revision: u64,
    name: *const u8,
    version: *const u8,
}

#[repr(C)]
struct MemmapEntry {
    base: u64,
    length: u64,
    kind: u64,
}

#[repr(C)]
struct MemmapResponse {
    revision: u64,
    entry_count: u64,
    entries: *const *const MemmapEntry,
}

#[repr(C)]
struct HhdmResponse {
    revision: u64,
    offset: u64,
}

#[repr(C)]
struct ExecutableAddressResponse {
    revision: u64,
    physical_base: u64,
    virtual_base: u64,
}

#[repr(C)]
struct LimineFramebuffer {
    address: *mut c_void,
    width: u64,
    height: u64,
    pitch: u64,
    bpp: u16,
    memory_model: u8,
    red_mask_size: u8,
    red_mask_shift: u8,
    green_mask_size: u8,
    green_mask_shift: u8,
    blue_mask_size: u8,
    blue_mask_shift: u8,
    unused: [u8; 7],
    edid_size: u64,
    edid: *mut c_void,
    mode_count: u64,
    modes: *const *const c_void,
}

#[repr(C)]
struct FramebufferResponse {
    revision: u64,
    framebuffer_count: u64,
    framebuffers: *const *const LimineFramebuffer,
}

#[repr(C)]
struct RsdpResponse {
    revision: u64,
    address: u64,
}

#[repr(C)]
struct SmbiosResponse {
    revision: u64,
    entry_32: u64,
    entry_64: u64,
}

#[repr(C)]
struct Uuid {
    a: u32,
    b: u16,
    c: u16,
    d: [u8; 8],
}

#[repr(C)]
struct File {
    revision: u64,
    address: *mut c_void,
    size: u64,
    path: *const u8,
    cmdline: *const u8,
    media_type: u32,
    unused: u32,
    tftp_ip: u32,
    tftp_port: u32,
    partition_index: u32,
    mbr_disk_id: u32,
    gpt_disk_uuid: Uuid,
    gpt_part_uuid: Uuid,
    part_uuid: Uuid,
}

#[repr(C)]
struct ExecutableFileResponse {
    revision: u64,
    executable_file: *const File,
}

// --- The requests themselves --------------------------------------------

macro_rules! request {
    ($name:ident, $ty:ty, $id2:expr, $id3:expr) => {
        #[used]
        #[unsafe(link_section = ".requests")]
        static $name: Request<$ty> = Request::new($id2, $id3);
    };
}

request!(
    BOOTLOADER_INFO,
    BootloaderInfoResponse,
    0xf550_38d8_e2a1_202f,
    0x2794_26fc_f5f5_9740
);
request!(
    MEMMAP,
    MemmapResponse,
    0x67cf_3d9d_378a_806f,
    0xe304_acdf_c50c_3c62
);
request!(
    HHDM,
    HhdmResponse,
    0x48dc_f1cb_8ad2_b852,
    0x6398_4e95_9a98_244b
);
request!(
    EXECUTABLE_ADDRESS,
    ExecutableAddressResponse,
    0x71ba_7686_3cc5_5f63,
    0xb264_4a48_c516_a487
);
request!(
    FRAMEBUFFER,
    FramebufferResponse,
    0x9d58_27dc_d881_dd75,
    0xa314_8604_f6fa_b11b
);
request!(
    RSDP,
    RsdpResponse,
    0xc5e7_7b6b_397e_7b43,
    0x2763_7845_accd_cf3c
);
request!(
    SMBIOS,
    SmbiosResponse,
    0x9e90_46f1_1e09_5391,
    0xaa4a_520f_efbd_e5ee
);
request!(
    EXECUTABLE_FILE,
    ExecutableFileResponse,
    0xad97_e90e_83f1_ed67,
    0x31eb_5d1c_5ff2_3b69
);

// --- Translation into the Bhaskix handoff --------------------------------

/// Maximum memory regions the handoff can carry.
///
/// Real machines report tens of regions; 256 is far beyond anything observed.
/// A map larger than this is truncated and the truncation is reported through
/// [`Handoff::regions_truncated`] rather than silently dropped, because a
/// memory map that is quietly short is how a kernel comes to allocate from
/// memory a device already owns.
const MAX_MEMORY_REGIONS: usize = 256;

/// Storage for a value written exactly once during boot.
///
/// Used for the memory-map array and the loader name buffer, both of which are
/// filled by [`collect_handoff`] before any other CPU exists and are read-only
/// thereafter.
struct BootStatic<T>(UnsafeCell<T>);

// SAFETY: written once by `collect_handoff`, which runs on the bootstrap CPU
// with interrupts disabled and before any other CPU is started (M4). Every
// subsequent access is a read of immutable data.
unsafe impl<T> Sync for BootStatic<T> {}

static MEMORY_MAP: BootStatic<[MemoryRegion; MAX_MEMORY_REGIONS]> = BootStatic(UnsafeCell::new(
    [MemoryRegion {
        base: PhysAddr(0),
        length: 0,
        kind: MemoryKind::Reserved,
    }; MAX_MEMORY_REGIONS],
));

static LOADER_NAME: BootStatic<[u8; 96]> = BootStatic(UnsafeCell::new([0; 96]));

/// Reads a NUL-terminated string into a `&'static str`.
///
/// Returns `""` for a null pointer and a placeholder for invalid UTF-8, rather
/// than failing: a mangled loader name must not stop the machine from booting.
///
/// # Safety
///
/// `pointer` must be null or point to a NUL-terminated byte string that
/// remains valid for the lifetime of the returned reference.
unsafe fn cstr(pointer: *const u8, limit: usize) -> &'static str {
    if pointer.is_null() {
        return "";
    }
    let mut length = 0;
    // SAFETY: the caller guarantees a NUL terminator exists; `limit` bounds
    // the scan so a missing terminator reads at most `limit` bytes rather than
    // running off the end of the mapping.
    while length < limit && unsafe { *pointer.add(length) } != 0 {
        length += 1;
    }
    // SAFETY: `pointer[..length]` was just proven readable by the scan above.
    let bytes = unsafe { core::slice::from_raw_parts(pointer, length) };
    match core::str::from_utf8(bytes) {
        Ok(text) => text,
        Err(_) => "(invalid utf-8)",
    }
}

/// Translates a Limine memory-map type into ours.
const fn memory_kind(limine_type: u64) -> MemoryKind {
    match limine_type {
        0 => MemoryKind::Usable,
        2 => MemoryKind::AcpiReclaimable,
        3 => MemoryKind::AcpiNvs,
        4 => MemoryKind::BadMemory,
        5 => MemoryKind::BootloaderReclaimable,
        6 => MemoryKind::KernelAndModules,
        7 => MemoryKind::Framebuffer,
        // Type 1 is `RESERVED`. Anything unrecognised is treated as reserved
        // too: the safe direction for an unknown region is never to allocate
        // from it.
        _ => MemoryKind::Reserved,
    }
}

/// Builds the handoff from whatever the bootloader provided.
///
/// # Safety
///
/// Must be called exactly once, on the bootstrap CPU, before any other CPU is
/// started and before interrupts are enabled. It writes the `BootStatic`
/// buffers, and a second concurrent call would race.
pub unsafe fn collect_handoff() -> Handoff {
    let hhdm_base = VirtAddr(HHDM.response().map_or(0, |r| r.offset));

    // --- memory map ---
    let mut region_count = 0;
    let mut truncated = false;

    if let Some(memmap) = MEMMAP.response() {
        let total = memmap.entry_count as usize;
        let limit = if total > MAX_MEMORY_REGIONS {
            truncated = true;
            MAX_MEMORY_REGIONS
        } else {
            total
        };

        // SAFETY: the buffer is written here and nowhere else, on the single
        // CPU that is running at this point (see the `Sync` impl above).
        let destination = unsafe { &mut *MEMORY_MAP.0.get() };

        for index in 0..limit {
            // SAFETY: the protocol guarantees `entries` points to
            // `entry_count` pointers, each to a valid `MemmapEntry`, and
            // `index < limit <= entry_count`.
            let entry = unsafe { &**memmap.entries.add(index) };

            // Zero-length regions carry no information and would break the
            // sortedness check downstream. Drop them here rather than teach
            // every consumer to skip them.
            if entry.length == 0 {
                continue;
            }

            destination[region_count] = MemoryRegion {
                base: PhysAddr(entry.base),
                length: entry.length,
                kind: memory_kind(entry.kind),
            };
            region_count += 1;
        }
    }

    // SAFETY: `MEMORY_MAP` is a `[MemoryRegion; MAX_MEMORY_REGIONS]`, and the
    // loop above initialised elements `0..region_count`, which is at most
    // `MAX_MEMORY_REGIONS`. Building the slice from the raw pointer rather
    // than indexing through a reference avoids creating a `&` to the whole
    // array, part of which is still the placeholder value.
    let memory_map = unsafe {
        core::slice::from_raw_parts(MEMORY_MAP.0.get().cast::<MemoryRegion>(), region_count)
    };

    // --- loader identification ---
    let loader = match BOOTLOADER_INFO.response() {
        Some(info) => {
            // SAFETY: the protocol guarantees `name` is a NUL-terminated
            // string in bootloader-reclaimable memory, which stays valid
            // until the kernel reclaims it after consuming the handoff.
            let name = unsafe { cstr(info.name, 48) };
            // SAFETY: same guarantee as `name`, for the `version` field.
            let version = unsafe { cstr(info.version, 32) };

            // SAFETY: written once, here, on the single running CPU.
            let buffer = unsafe { &mut *LOADER_NAME.0.get() };
            let mut length = 0;
            for byte in name
                .bytes()
                .chain(b" ".iter().copied())
                .chain(version.bytes())
            {
                if length == buffer.len() {
                    break;
                }
                buffer[length] = byte;
                length += 1;
            }
            core::str::from_utf8(&buffer[..length]).unwrap_or("(unknown loader)")
        }
        None => "(unknown loader)",
    };

    // --- framebuffer ---
    let framebuffer = FRAMEBUFFER.response().and_then(|response| {
        if response.framebuffer_count == 0 {
            return None;
        }
        // SAFETY: `framebuffer_count > 0`, so the first pointer exists and
        // addresses a valid `LimineFramebuffer` per the protocol.
        let fb = unsafe { &**response.framebuffers };
        Some(Framebuffer {
            address: VirtAddr(fb.address as u64),
            width: fb.width,
            height: fb.height,
            pitch: fb.pitch,
            bpp: fb.bpp,
            format: PixelFormat {
                red_shift: fb.red_mask_shift,
                red_size: fb.red_mask_size,
                green_shift: fb.green_mask_shift,
                green_size: fb.green_mask_size,
                blue_shift: fb.blue_mask_shift,
                blue_size: fb.blue_mask_size,
            },
        })
    });

    // --- ACPI and SMBIOS ---
    //
    // Whether these are physical or HHDM-relative differs across protocol
    // revisions, and getting it wrong yields an address that looks plausible
    // and faults later. Normalising here means the kernel always receives a
    // physical address regardless of what the bootloader chose to report.
    let normalise = |address: u64| -> Option<PhysAddr> {
        if address == 0 {
            None
        } else if hhdm_base.as_u64() != 0 && address >= hhdm_base.as_u64() {
            Some(PhysAddr(address - hhdm_base.as_u64()))
        } else {
            Some(PhysAddr(address))
        }
    };

    let rsdp = RSDP.response().and_then(|r| normalise(r.address));
    let smbios = SMBIOS
        .response()
        .and_then(|r| normalise(r.entry_64).or(normalise(r.entry_32)));

    // --- command line ---
    let cmdline = match EXECUTABLE_FILE.response() {
        Some(response) if !response.executable_file.is_null() => {
            // SAFETY: checked non-null; the protocol guarantees it points to a
            // valid `File` whose `cmdline` is NUL-terminated.
            let file = unsafe { &*response.executable_file };
            // SAFETY: `File::cmdline` is a NUL-terminated string owned by the
            // bootloader, valid for as long as the response it came from.
            unsafe { cstr(file.cmdline, 512) }
        }
        _ => "",
    };

    let (kernel_phys_base, kernel_virt_base) = match EXECUTABLE_ADDRESS.response() {
        Some(address) => (
            PhysAddr(address.physical_base),
            VirtAddr(address.virtual_base),
        ),
        None => (PhysAddr(0), VirtAddr(0)),
    };

    Handoff {
        version: HANDOFF_VERSION,
        memory_map,
        hhdm_base,
        kernel_phys_base,
        kernel_virt_base,
        framebuffer,
        rsdp,
        smbios,
        cmdline,
        loader,
        regions_truncated: truncated,
    }
}

/// Whether the bootloader acknowledged the base revision we asked for.
///
/// Limine zeroes the third word when it supports the requested revision.
///
/// In practice a bootloader that does not support it refuses to start the
/// kernel at all, so this should never be `false` — but checking costs one
/// load, and booting with a silently different memory-map contract would be
/// very hard to diagnose.
#[must_use]
pub fn base_revision_supported() -> bool {
    // SAFETY: reading a `u64` the bootloader wrote before we started. Volatile
    // so the compiler cannot fold in the initialiser value.
    unsafe { BASE_REVISION.0.get().cast::<u64>().add(2).read_volatile() == 0 }
}
