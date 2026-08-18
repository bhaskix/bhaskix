// SPDX-License-Identifier: Apache-2.0
//! The slice of UEFI this loader consumes, transcribed by hand.
//!
//! Each struct below transcribes a table from the UEFI specification —
//! declared down to the last slot consumed and not one further, so nothing
//! past the reviewed surface can be misused by accident. The transcription
//! itself is a claim from a document, and the lane is what verifies it: a
//! wrong offset produces a wrong banner, a refused volume or a garbage
//! checksum, never a silent pass. Every pointer that arrives from the
//! firmware is checked before its first dereference, and every call can
//! refuse with a status the caller prints.

/// `EFI_SUCCESS`.
pub const SUCCESS: usize = 0;

/// The UEFI system table's signature, `IBI SYST` little-endian.
const SYSTEM_TABLE_SIGNATURE: u64 = 0x5453_5953_2049_4249;

/// `EFI_FILE_MODE_READ`.
const FILE_MODE_READ: u64 = 1;

/// A protocol identity.
#[derive(PartialEq, Eq)]
#[repr(C)]
struct Guid(u32, u16, u16, [u8; 8]);

/// `EFI_LOADED_IMAGE_PROTOCOL_GUID`.
const LOADED_IMAGE: Guid = Guid(
    0x5B1B_31A1,
    0x9562,
    0x11d2,
    [0x8E, 0x3F, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B],
);

/// `EFI_ACPI_20_TABLE_GUID` — the RSDP, ACPI 2.0 and later.
const ACPI_20_TABLE: Guid = Guid(
    0x8868_E871,
    0xE4F1,
    0x11D3,
    [0xBC, 0x22, 0x00, 0x80, 0xC7, 0x3C, 0x88, 0x81],
);

/// `ACPI_TABLE_GUID` — the ACPI 1.0 RSDP, the fallback.
const ACPI_10_TABLE: Guid = Guid(
    0xEB9D_2D30,
    0x2D88,
    0x11D3,
    [0x9A, 0x16, 0x00, 0x90, 0x27, 0x3F, 0xC1, 0x4D],
);

/// `SMBIOS3_TABLE_GUID` — the 64-bit SMBIOS entry point.
const SMBIOS3_TABLE: Guid = Guid(
    0xF2FD_1544,
    0x9794,
    0x4A2C,
    [0x99, 0x2E, 0xE5, 0xBB, 0xCF, 0x20, 0xE3, 0x94],
);

/// `SMBIOS_TABLE_GUID` — the 32-bit entry point, the fallback.
const SMBIOS_TABLE: Guid = Guid(
    0xEB9D_2D31,
    0x2D88,
    0x11D3,
    [0x9A, 0x16, 0x00, 0x90, 0x27, 0x3F, 0xC1, 0x4D],
);

/// `EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID`.
const GRAPHICS_OUTPUT: Guid = Guid(
    0x9042_A9DE,
    0x23DC,
    0x4A38,
    [0x96, 0xFB, 0x7A, 0xDE, 0xD0, 0x80, 0x51, 0x6A],
);

/// `EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID`.
const SIMPLE_FILE_SYSTEM: Guid = Guid(
    0x964E_5B22,
    0x6459,
    0x11d2,
    [0x8E, 0x39, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B],
);

/// The common header every UEFI table opens with.
#[repr(C)]
struct TableHeader {
    signature: u64,
    revision: u32,
    header_size: u32,
    crc32: u32,
    reserved: u32,
}

/// The simple-text-output protocol, down to the one slot this loader calls.
#[repr(C)]
pub struct SimpleTextOutput {
    reset: usize,
    output_string:
        unsafe extern "efiapi" fn(this: *mut SimpleTextOutput, string: *const u16) -> usize,
}

/// The boot-services table, in specification slot order, named down to the
/// last function consumed. The opaque runs are, in order: the six event
/// services and the first three protocol-interface services between
/// `free_pool` and `handle_protocol`; the nine from the reserved slot
/// through `unload_image` between `handle_protocol` and
/// `exit_boot_services`; and the ten from `get_next_monotonic_count`
/// through `locate_handle_buffer` before `locate_protocol`.
#[repr(C)]
struct BootServices {
    hdr: TableHeader,
    raise_tpl: usize,
    restore_tpl: usize,
    allocate_pages: unsafe extern "efiapi" fn(
        allocate_type: u32,
        memory_type: u32,
        pages: usize,
        memory: *mut u64,
    ) -> usize,
    free_pages: usize,
    get_memory_map: unsafe extern "efiapi" fn(
        size: *mut usize,
        map: *mut u8,
        key: *mut usize,
        descriptor_size: *mut usize,
        descriptor_version: *mut u32,
    ) -> usize,
    allocate_pool: usize,
    free_pool: usize,
    events_and_installs: [usize; 9],
    handle_protocol: unsafe extern "efiapi" fn(
        handle: usize,
        protocol: *const Guid,
        interface: *mut *mut core::ffi::c_void,
    ) -> usize,
    through_unload_image: [usize; 9],
    exit_boot_services: unsafe extern "efiapi" fn(image_handle: usize, map_key: usize) -> usize,
    through_locate_handle_buffer: [usize; 10],
    locate_protocol: unsafe extern "efiapi" fn(
        protocol: *const Guid,
        registration: *mut core::ffi::c_void,
        interface: *mut *mut core::ffi::c_void,
    ) -> usize,
}

/// The system table, down to the boot services.
#[repr(C)]
pub struct SystemTable {
    hdr: TableHeader,
    firmware_vendor: *const u16,
    firmware_revision: u32,
    console_in_handle: usize,
    con_in: usize,
    console_out_handle: usize,
    con_out: *mut SimpleTextOutput,
    standard_error_handle: usize,
    std_err: usize,
    runtime_services: usize,
    boot_services: *mut BootServices,
    number_of_table_entries: usize,
    configuration_table: *const ConfigurationEntry,
}

/// One configuration-table entry: a vendor GUID and its table's address.
#[repr(C)]
struct ConfigurationEntry {
    vendor_guid: Guid,
    vendor_table: usize,
}

/// The loaded-image protocol, down to the device handle — which volume this
/// image was read from, which is where the payload lives too.
#[repr(C)]
struct LoadedImage {
    revision: u32,
    parent_handle: usize,
    system_table: usize,
    device_handle: usize,
}

/// The simple-filesystem protocol: a revision and `OpenVolume`.
#[repr(C)]
struct SimpleFileSystem {
    revision: u64,
    open_volume:
        unsafe extern "efiapi" fn(this: *mut SimpleFileSystem, root: *mut *mut File) -> usize,
}

/// The file protocol, down to `Read`. `delete` and `write` exist in the
/// slot order and are deliberately opaque: this loader never deletes and
/// never writes, and leaving the types unstated keeps that structural.
#[repr(C)]
pub struct File {
    revision: u64,
    open: unsafe extern "efiapi" fn(
        this: *mut File,
        new_handle: *mut *mut File,
        file_name: *const u16,
        open_mode: u64,
        attributes: u64,
    ) -> usize,
    close: unsafe extern "efiapi" fn(this: *mut File) -> usize,
    delete: usize,
    read: unsafe extern "efiapi" fn(
        this: *mut File,
        buffer_size: *mut usize,
        buffer: *mut core::ffi::c_void,
    ) -> usize,
}

/// Validates the system table the firmware handed over: non-null, and
/// signed as one. Everything else this module does flows from a table that
/// passed here.
#[must_use]
pub fn validate(table: *mut SystemTable) -> Option<*mut SystemTable> {
    if table.is_null() {
        return None;
    }
    // SAFETY: non-null, and only the header is read until the signature
    // earns the rest of the struct.
    let signature = unsafe { (*table).hdr.signature };
    if signature == SYSTEM_TABLE_SIGNATURE {
        Some(table)
    } else {
        None
    }
}

/// The console-out protocol, if the firmware has one.
#[must_use]
pub fn con_out(table: *mut SystemTable) -> Option<*mut SimpleTextOutput> {
    // SAFETY: `table` passed `validate`.
    let con_out = unsafe { (*table).con_out };
    if con_out.is_null() {
        None
    } else {
        Some(con_out)
    }
}

/// Prints a NUL-terminated UCS-2 buffer on the firmware console.
pub fn output_string(con_out: *mut SimpleTextOutput, buffer: &[u16]) {
    // SAFETY: `con_out` came from `con_out()` non-null, and the buffer is
    // NUL-terminated by every caller; the call follows the protocol's own
    // signature. Best-effort: the status is deliberately ignored, because
    // the serial copy has already gone out.
    unsafe { ((*con_out).output_string)(con_out, buffer.as_ptr()) };
}

/// One `HandleProtocol` ask, null-checked on the way out.
fn handle_protocol(
    services: *mut BootServices,
    handle: usize,
    protocol: &Guid,
) -> Result<*mut core::ffi::c_void, usize> {
    let mut interface: *mut core::ffi::c_void = core::ptr::null_mut();
    // SAFETY: `services` was null-checked by `open_boot_volume`; the call
    // follows the specification's signature and writes only `interface`.
    let status = unsafe { ((*services).handle_protocol)(handle, protocol, &raw mut interface) };
    if status != SUCCESS {
        return Err(status);
    }
    if interface.is_null() {
        return Err(usize::MAX);
    }
    Ok(interface)
}

/// Opens the volume this image booted from and returns its root directory:
/// image handle → loaded-image protocol → device handle → filesystem →
/// root. Each hop is a firmware answer that can refuse, and the refusal
/// carries the status.
///
/// # Errors
///
/// The refusing hop's status, or `usize::MAX` for a null answer that
/// claimed success.
pub fn open_boot_volume(table: *mut SystemTable, image_handle: usize) -> Result<*mut File, usize> {
    // SAFETY: `table` passed `validate`.
    let services = unsafe { (*table).boot_services };
    if services.is_null() {
        return Err(usize::MAX);
    }
    let loaded = handle_protocol(services, image_handle, &LOADED_IMAGE)?;
    // SAFETY: the firmware answered the loaded-image ask with this
    // interface; only the device-handle field is read.
    let device = unsafe { (*loaded.cast::<LoadedImage>()).device_handle };
    let filesystem = handle_protocol(services, device, &SIMPLE_FILE_SYSTEM)?;
    let filesystem = filesystem.cast::<SimpleFileSystem>();
    let mut root: *mut File = core::ptr::null_mut();
    // SAFETY: the firmware answered the filesystem ask with this interface;
    // the call follows the protocol's signature and writes only `root`.
    let status = unsafe { ((*filesystem).open_volume)(filesystem, &raw mut root) };
    if status != SUCCESS {
        return Err(status);
    }
    if root.is_null() {
        return Err(usize::MAX);
    }
    Ok(root)
}

/// Opens `path` under `directory`, read-only. The path is ASCII with
/// backslashes, widened to UCS-2 in a bounded buffer — a path that does
/// not fit is refused here rather than truncated into a different file.
///
/// # Errors
///
/// The firmware's status, or `usize::MAX` for a path too long or a null
/// answer.
pub fn open_read_only(directory: *mut File, path: &str) -> Result<*mut File, usize> {
    let mut wide = [0u16; 64];
    if path.len() >= wide.len() {
        return Err(usize::MAX);
    }
    for (at, byte) in path.bytes().enumerate() {
        wide[at] = u16::from(byte);
    }
    let mut file: *mut File = core::ptr::null_mut();
    // SAFETY: `directory` came from `open_boot_volume` or a prior open,
    // non-null; the path buffer is NUL-terminated by construction.
    let status =
        unsafe { ((*directory).open)(directory, &raw mut file, wide.as_ptr(), FILE_MODE_READ, 0) };
    if status != SUCCESS {
        return Err(status);
    }
    if file.is_null() {
        return Err(usize::MAX);
    }
    Ok(file)
}

/// Reads into `buffer`, returning how many bytes arrived; zero is the end
/// of the file.
///
/// # Errors
///
/// The firmware's status, or `usize::MAX` if the firmware claimed to read
/// more than the buffer it was given — an answer that cannot be true and
/// must not be indexed by.
pub fn read(file: *mut File, buffer: &mut [u8]) -> Result<usize, usize> {
    let mut size = buffer.len();
    // SAFETY: `file` came from `open_read_only`, non-null; the size in/out
    // and buffer follow the protocol's signature.
    let status = unsafe {
        ((*file).read)(
            file,
            &raw mut size,
            buffer.as_mut_ptr().cast::<core::ffi::c_void>(),
        )
    };
    if status != SUCCESS {
        return Err(status);
    }
    if size > buffer.len() {
        return Err(usize::MAX);
    }
    Ok(size)
}

/// Closes a file or directory. Best-effort: a firmware that refuses a
/// close has nothing this loader can do about it.
pub fn close(file: *mut File) {
    // SAFETY: `file` came from an open in this module, non-null.
    let _ = unsafe { ((*file).close)(file) };
}

/// What the firmware's configuration tables say the machine is: the ACPI
/// RSDP and the SMBIOS entry point, each preferring the newer table and
/// falling back to the older, each `None` when the walk finds neither.
/// The walk is bounded and every entry is a firmware answer: a count
/// claiming more than a sane table is clamped rather than believed.
#[must_use]
pub fn find_tables(table: *mut SystemTable) -> (Option<u64>, Option<u64>) {
    // SAFETY: `table` passed `validate`.
    let (count, entries) = unsafe {
        (
            (*table).number_of_table_entries,
            (*table).configuration_table,
        )
    };
    if entries.is_null() {
        return (None, None);
    }
    let count = count.min(256);
    let mut acpi_20 = None;
    let mut acpi_10 = None;
    let mut smbios3 = None;
    let mut smbios = None;
    for index in 0..count {
        // SAFETY: `entries` is the firmware's configuration array, read
        // within the clamped count, each entry a GUID and a pointer.
        let entry = unsafe { &*entries.add(index) };
        let address = entry.vendor_table as u64;
        if entry.vendor_guid == ACPI_20_TABLE {
            acpi_20 = Some(address);
        } else if entry.vendor_guid == ACPI_10_TABLE {
            acpi_10 = Some(address);
        } else if entry.vendor_guid == SMBIOS3_TABLE {
            smbios3 = Some(address);
        } else if entry.vendor_guid == SMBIOS_TABLE {
            smbios = Some(address);
        }
    }
    (acpi_20.or(acpi_10), smbios3.or(smbios))
}

/// The graphics-output protocol, down to its mode pointer.
#[repr(C)]
struct GraphicsOutput {
    query_mode: usize,
    set_mode: usize,
    blt: usize,
    mode: *const GraphicsMode,
}

/// The protocol's current-mode block.
#[repr(C)]
struct GraphicsMode {
    max_mode: u32,
    mode: u32,
    info: *const GraphicsInfo,
    size_of_info: usize,
    frame_buffer_base: u64,
    frame_buffer_size: usize,
}

/// The mode information block, down to the stride.
#[repr(C)]
struct GraphicsInfo {
    version: u32,
    horizontal_resolution: u32,
    vertical_resolution: u32,
    pixel_format: u32,
    pixel_bitmask: [u32; 4],
    pixels_per_scan_line: u32,
}

/// The framebuffer the firmware drives, if it drives one: width, height,
/// stride in pixels, the physical base, and whether the byte order is BGR.
/// `None` is a machine with no graphics protocol, one whose answers fail
/// their null checks, or one whose pixel format is neither of the two
/// linear layouts — serial-only machines are real, and this loader treats
/// all three as a state.
#[must_use]
pub fn framebuffer(table: *mut SystemTable) -> Option<(u32, u32, u32, u64, bool)> {
    // SAFETY: `table` passed `validate`.
    let services = unsafe { (*table).boot_services };
    if services.is_null() {
        return None;
    }
    let mut interface: *mut core::ffi::c_void = core::ptr::null_mut();
    // SAFETY: the call follows the specification's signature and writes
    // only `interface`; a refusal is a `None` below.
    let status = unsafe {
        ((*services).locate_protocol)(&GRAPHICS_OUTPUT, core::ptr::null_mut(), &raw mut interface)
    };
    if status != SUCCESS || interface.is_null() {
        return None;
    }
    // SAFETY: the firmware answered the locate with this interface; each
    // pointer along the chain is null-checked before its first use.
    let mode = unsafe { (*interface.cast::<GraphicsOutput>()).mode };
    if mode.is_null() {
        return None;
    }
    // SAFETY: null-checked just above.
    let (info, base) = unsafe { ((*mode).info, (*mode).frame_buffer_base) };
    if info.is_null() {
        return None;
    }
    // SAFETY: null-checked just above.
    let info = unsafe { &*info };
    // 0 is RGBX, 1 is BGRX; the bitmask and blt-only formats are refused —
    // a framebuffer whose layout the console cannot describe is not one.
    let bgr = match info.pixel_format {
        0 => false,
        1 => true,
        _ => return None,
    };
    Some((
        info.horizontal_resolution,
        info.vertical_resolution,
        info.pixels_per_scan_line,
        base,
        bgr,
    ))
}

/// `EFI_MEMORY_DESCRIPTOR`'s leading fields; entries advance by the
/// firmware's declared stride, never by this struct's size — the one
/// mistake every first UEFI memory-map reader makes, refused by
/// construction in [`MemoryMap::regions`].
#[repr(C)]
struct MemoryDescriptor {
    kind: u32,
    physical_start: u64,
    virtual_start: u64,
    number_of_pages: u64,
    attribute: u64,
}

/// `EfiConventionalMemory`.
const CONVENTIONAL: u32 = 7;
/// The four kinds that become usable once boot services are gone: loader
/// code and data, boot-services code and data.
const RECLAIMABLE: [u32; 4] = [1, 2, 3, 4];

/// The memory map as taken at the exit, in the loader's own storage.
pub struct MemoryMap {
    buffer: [u8; Self::BYTES],
    bytes_used: usize,
    stride: usize,
}

impl MemoryMap {
    /// Sixteen KiB of descriptor space — hundreds of entries at any sane
    /// stride, and the truncation counter says so if a machine defeats it.
    const BYTES: usize = 16 * 1024;

    /// How many descriptors the map holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes_used.checked_div(self.stride).unwrap_or(0)
    }

    /// Whether the map is empty. Clippy's pairing rule for `len`, honest
    /// here too: a map this type returned is never empty, and a caller who
    /// asks deserves the true answer rather than a lint suppression.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Walks the map: `(kind, physical start, bytes)` per descriptor,
    /// advancing by the firmware's stride.
    pub fn regions(&self, mut f: impl FnMut(u32, u64, u64)) {
        let mut at = 0;
        while at + core::mem::size_of::<MemoryDescriptor>() <= self.bytes_used {
            // SAFETY: within the loader's own buffer, bounds-checked, and
            // the descriptor's leading fields fit before `bytes_used`.
            let descriptor = unsafe { &*self.buffer.as_ptr().add(at).cast::<MemoryDescriptor>() };
            f(
                descriptor.kind,
                descriptor.physical_start,
                descriptor.number_of_pages.saturating_mul(4096),
            );
            at += self.stride;
        }
    }

    /// Total bytes of the given kinds.
    #[must_use]
    pub fn bytes_of(&self, kinds: &[u32]) -> u64 {
        let mut total = 0u64;
        self.regions(|kind, _start, bytes| {
            if kinds.contains(&kind) {
                total = total.saturating_add(bytes);
            }
        });
        total
    }

    /// Bytes usable right now.
    #[must_use]
    pub fn usable_bytes(&self) -> u64 {
        self.bytes_of(&[CONVENTIONAL])
    }

    /// Bytes that become usable once the firmware's half is reclaimed.
    #[must_use]
    pub fn reclaimable_bytes(&self) -> u64 {
        self.bytes_of(&RECLAIMABLE)
    }
}

/// `EFI_BUFFER_TOO_SMALL`.
const BUFFER_TOO_SMALL: usize = (1 << 63) | 5;
/// `EFI_INVALID_PARAMETER`, which a stale map key earns.
const INVALID_PARAMETER: usize = (1 << 63) | 2;

/// Takes the memory map and exits boot services in one held breath.
///
/// The map key names a *moment*: anything that allocates — including a
/// console print — stales it, and a stale key is refused. So this loop
/// does nothing between the take and the exit, and on a refusal it takes
/// the map again; the spec names exactly this dance. After success the
/// firmware is gone: no files, no console protocol, no going back — the
/// caller prints on serial only, and owns the machine.
///
/// # Errors
///
/// The firmware's status when the exit keeps failing past its retries,
/// paired with how many descriptors a too-small buffer dropped — zero for
/// every other failure — so a refusal over truncation names its size.
pub fn take_map_and_exit(
    table: *mut SystemTable,
    image_handle: usize,
) -> Result<MemoryMap, (usize, usize)> {
    // SAFETY: `table` passed `validate`.
    let services = unsafe { (*table).boot_services };
    if services.is_null() {
        return Err((usize::MAX, 0));
    }
    let mut map = MemoryMap {
        buffer: [0u8; MemoryMap::BYTES],
        bytes_used: 0,
        stride: 0,
    };
    for _ in 0..8 {
        let mut size = MemoryMap::BYTES;
        let mut key = 0usize;
        let mut stride = 0usize;
        let mut version = 0u32;
        // SAFETY: the call follows the specification's signature; the
        // buffer is the loader's own and `size` bounds it.
        let status = unsafe {
            ((*services).get_memory_map)(
                &raw mut size,
                map.buffer.as_mut_ptr(),
                &raw mut key,
                &raw mut stride,
                &raw mut version,
            )
        };
        if status == BUFFER_TOO_SMALL {
            // The map outgrew the buffer. Say how much was dropped and
            // refuse to pretend otherwise; the caller decides whether a
            // truncated map is a boot.
            let dropped = size
                .saturating_sub(MemoryMap::BYTES)
                .checked_div(stride)
                .unwrap_or(usize::MAX);
            return Err((status, dropped));
        }
        if status != SUCCESS {
            return Err((status, 0));
        }
        if stride < core::mem::size_of::<MemoryDescriptor>() {
            return Err((usize::MAX, 0));
        }
        map.bytes_used = size;
        map.stride = stride;
        // Nothing between the take and the exit — a print here would
        // allocate and stale the key this exit presents.
        // SAFETY: the specification's signature; on success the firmware's
        // boot services are gone and this function's contract begins.
        let status = unsafe { ((*services).exit_boot_services)(image_handle, key) };
        if status == SUCCESS {
            return Ok(map);
        }
        if status != INVALID_PARAMETER {
            return Err((status, 0));
        }
        // The key went stale between the two calls; take the map again.
    }
    Err((INVALID_PARAMETER, 0))
}

/// `AllocateAnyPages`.
const ALLOCATE_ANY_PAGES: u32 = 0;
/// `EfiLoaderCode` — the type this loader gives the kernel image and the
/// initrd, so the region translation can tell "the payload" apart from
/// "the loader's scaffolding" by the firmware's own labels.
pub const LOADER_CODE: u32 = 1;
/// `EfiLoaderData` — the scaffolding: table pool, handoff block, stack.
pub const LOADER_DATA: u32 = 2;

/// Allocates `pages` pages of the given memory type, physically contiguous,
/// anywhere the firmware likes. The pages are the loader's until the
/// machine is handed over, and their type is what the memory map will say
/// about them after the exit.
///
/// # Errors
///
/// The firmware's status, or `usize::MAX` for a zero answer that claimed
/// success.
pub fn allocate_pages(
    table: *mut SystemTable,
    memory_type: u32,
    pages: usize,
) -> Result<u64, usize> {
    // SAFETY: `table` passed `validate`.
    let services = unsafe { (*table).boot_services };
    if services.is_null() {
        return Err(usize::MAX);
    }
    let mut memory: u64 = 0;
    // SAFETY: the specification's signature; the firmware writes only
    // `memory`.
    let status = unsafe {
        ((*services).allocate_pages)(ALLOCATE_ANY_PAGES, memory_type, pages, &raw mut memory)
    };
    if status != SUCCESS {
        return Err(status);
    }
    if memory == 0 {
        return Err(usize::MAX);
    }
    Ok(memory)
}
