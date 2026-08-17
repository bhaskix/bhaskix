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
#[repr(C)]
struct Guid(u32, u16, u16, [u8; 8]);

/// `EFI_LOADED_IMAGE_PROTOCOL_GUID`.
const LOADED_IMAGE: Guid = Guid(
    0x5B1B_31A1,
    0x9562,
    0x11d2,
    [0x8E, 0x3F, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B],
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

/// The boot-services table, down to `HandleProtocol`.
///
/// The sixteen opaque slots are, in specification order: the two task
/// priority services, the five memory services, the six event services,
/// and the first three protocol-interface services. `HandleProtocol` is
/// the seventeenth function; later steps will name the memory slots
/// individually when they consume them.
#[repr(C)]
struct BootServices {
    hdr: TableHeader,
    before_handle_protocol: [usize; 16],
    handle_protocol: unsafe extern "efiapi" fn(
        handle: usize,
        protocol: *const Guid,
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
