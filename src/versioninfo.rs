#![allow(unsafe_code)] // Intentional FFI wrapper; every unsafe block carries a SAFETY comment.

mod resource;

use std::ffi::OsString;
use std::io::Read;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use crate::arch_probe::{ArchEvidence, ContentProbe, merge_architectures, probe as probe_payload};
use windows::Win32::Foundation::{ERROR_INVALID_DATA, ERROR_NO_MORE_ITEMS, ERROR_SUCCESS};
use windows::Win32::Storage::FileSystem::{
    GET_FILE_VERSION_INFO_FLAGS, GetBinaryTypeW, GetFileVersionInfoExW, GetFileVersionInfoSizeExW,
    VFT_APP, VFT_DLL, VFT_DRV, VFT_FONT, VFT_STATIC_LIB, VFT_VXD, VFT2_DRV_COMM, VFT2_DRV_DISPLAY,
    VFT2_DRV_INPUTMETHOD, VFT2_DRV_INSTALLABLE, VFT2_DRV_KEYBOARD, VFT2_DRV_LANGUAGE,
    VFT2_DRV_MOUSE, VFT2_DRV_NETWORK, VFT2_DRV_PRINTER, VFT2_DRV_SOUND, VFT2_DRV_SYSTEM,
    VFT2_DRV_VERSIONED_PRINTER, VFT2_FONT_RASTER, VFT2_FONT_TRUETYPE, VFT2_FONT_VECTOR, VOS_DOS,
    VOS_DOS_WINDOWS16, VOS_DOS_WINDOWS32, VOS_NT, VOS_NT_WINDOWS32, VOS_OS216, VOS_OS216_PM16,
    VOS_OS232, VOS_OS232_PM32, VOS_WINCE, VS_FF_DEBUG, VS_FF_INFOINFERRED, VS_FF_PATCHED,
    VS_FF_PRERELEASE, VS_FF_PRIVATEBUILD, VS_FF_SPECIALBUILD, VS_FIXEDFILEINFO_FILE_FLAGS,
};
use windows::Win32::System::ApplicationInstallationAndServicing::{
    MSIHANDLE, MsiCloseHandle, MsiDatabaseOpenViewW, MsiGetSummaryInformationW, MsiOpenDatabaseW,
    MsiRecordGetStringW, MsiViewExecute, MsiViewFetch,
};
use windows::Win32::System::WindowsProgramming::{SCS_32BIT_BINARY, SCS_64BIT_BINARY};
use windows::core::{Error, PCWSTR, PWSTR, w};

// MSI SummaryInformation property IDs (OLE PID values).
const PID_TEMPLATE: u32 = 7;
const ERROR_UNKNOWN_PROPERTY: u32 = 160;

// MsiSummaryInfoGetPropertyW is not exposed by windows 0.62.2.
#[link(name = "msi", kind = "raw-dylib")]
unsafe extern "system" {
    fn MsiSummaryInfoGetPropertyW(
        hsummaryinfo: u32,
        property: u32,
        puidatatype: *mut u32,
        pivalue: *mut i32,
        pftvalue: *mut FileTime,
        szvaluebuf: *mut u16,
        pcchvaluebuf: *mut u32,
    ) -> u32;
}

/// Layout-compatible FILETIME for the summary property query.
#[repr(C)]
struct FileTime {
    dw_low_date_time: u32,
    dw_high_date_time: u32,
}

// SCS_* values not exposed by windows 0.62.2, taken from winnt.h.
const SCS_ARM64_BINARY: u32 = 10;
const SCS_ARMNT_BINARY: u32 = 12;

pub(crate) const OLE_MAGIC: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

pub struct FixedFileInfo {
    pub file_version: [u32; 4],
    pub product_version: [u32; 4],
    pub file_type: String,
    pub file_subtype: String,
    pub file_os: String,
    pub file_flags: String,
}

pub struct VersionInfo {
    pub arch: String,
    pub product_name: OsString,
    pub internal_name: OsString,
    pub original_filename: OsString,
    pub file_version: OsString,
    pub product_version: OsString,
    pub company_name: OsString,
    pub legal_copyright: OsString,
    pub legal_trademarks: OsString,
    pub file_description: OsString,
    pub comments: OsString,
    pub private_build: OsString,
    pub special_build: OsString,
    pub fixed: Option<FixedFileInfo>,
}

impl Default for VersionInfo {
    fn default() -> Self {
        Self {
            arch: String::new(),
            product_name: OsString::new(),
            internal_name: OsString::new(),
            original_filename: OsString::new(),
            file_version: OsString::new(),
            product_version: OsString::new(),
            company_name: OsString::new(),
            legal_copyright: OsString::new(),
            legal_trademarks: OsString::new(),
            file_description: OsString::new(),
            comments: OsString::new(),
            private_build: OsString::new(),
            special_build: OsString::new(),
            fixed: None,
        }
    }
}

/// Reads version information from a PE file with a version resource, an MSI
/// package, or an MSIX/AppX package.
pub fn from_file<P: AsRef<Path>>(path: P) -> Result<VersionInfo, String> {
    let path = path.as_ref();
    match from_pe(path) {
        Ok(info) => Ok(info),
        Err(pe_error) => {
            if looks_like_msi(path)
                && let Ok(info) = from_msi(path)
            {
                return Ok(info);
            }
            Err(pe_error.to_string())
        }
    }
}

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn file_magic(path: &Path) -> Option<[u8; 8]> {
    let mut file = std::fs::File::open(path).ok()?;
    let mut magic = [0u8; 8];
    file.read_exact(&mut magic).ok()?;
    Some(magic)
}

fn looks_like_msi(path: &Path) -> bool {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();
    matches!(ext.as_str(), "msi" | "mst" | "msm")
        || file_magic(path).is_some_and(|m| m == OLE_MAGIC)
}

fn detect_arch(path: PCWSTR) -> String {
    let mut binary_type = 0u32;
    // SAFETY: `path` is a valid null-terminated wide string for this call and
    // `binary_type` is a valid out pointer.
    let result = unsafe { GetBinaryTypeW(path, &raw mut binary_type) };
    if result.is_err() {
        return "unknown".to_owned();
    }
    match binary_type {
        SCS_64BIT_BINARY => "x64",
        SCS_32BIT_BINARY => "x86",
        SCS_ARM64_BINARY => "arm64",
        SCS_ARMNT_BINARY => "arm",
        _ => "unknown",
    }
    .to_owned()
}

/// Outer-image architecture of any file via `GetBinaryTypeW`, using the same
/// tokens as [`detect_arch`]. Used on images unpacked from installers.
pub(crate) fn binary_arch_from_file(path: &Path) -> String {
    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    detect_arch(PCWSTR(wide.as_ptr()))
}

/// Payload architecture evidence from an MSI `Template` property; empty when
/// the package is unreadable. Used on MSIs unpacked from installers.
pub(crate) fn msi_evidence_from_file(path: &Path) -> Vec<ArchEvidence> {
    let path_wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    unsafe {
        let mut db = MSIHANDLE(0);
        // SAFETY: `path_wide` is a valid null-terminated wide string; `db` is
        // a valid out handle.
        let rc = MsiOpenDatabaseW(PCWSTR(path_wide.as_ptr()), w!("0"), &raw mut db);
        if rc != ERROR_SUCCESS.0 {
            return Vec::new();
        }
        let template = msi_template(db).ok().flatten();
        // SAFETY: `db` is a valid handle returned by MsiOpenDatabaseW.
        MsiCloseHandle(db);
        template
            .map(|t| msi_template_evidence(&t))
            .unwrap_or_default()
    }
}

fn split_version(ms: u32, ls: u32) -> [u32; 4] {
    [
        (ms >> 16) & 0xFFFF,
        ms & 0xFFFF,
        (ls >> 16) & 0xFFFF,
        ls & 0xFFFF,
    ]
}

fn file_type_name(file_type: u32) -> &'static str {
    match file_type {
        v if v == VFT_APP.0 as u32 => "Application",
        v if v == VFT_DLL.0 as u32 => "DLL",
        v if v == VFT_DRV.0 as u32 => "Driver",
        v if v == VFT_FONT.0 as u32 => "Font",
        v if v == VFT_VXD.0 as u32 => "VirtualDevice",
        v if v == VFT_STATIC_LIB.0 as u32 => "StaticLibrary",
        _ => "Unknown",
    }
}

fn file_subtype_name(file_type: u32, subtype: u32) -> String {
    match file_type {
        v if v == VFT_DRV.0 as u32 => match subtype {
            v if v == VFT2_DRV_PRINTER.0 as u32 => "Printer",
            v if v == VFT2_DRV_KEYBOARD.0 as u32 => "Keyboard",
            v if v == VFT2_DRV_LANGUAGE.0 as u32 => "Language",
            v if v == VFT2_DRV_DISPLAY.0 as u32 => "Display",
            v if v == VFT2_DRV_MOUSE.0 as u32 => "Mouse",
            v if v == VFT2_DRV_NETWORK.0 as u32 => "Network",
            v if v == VFT2_DRV_SYSTEM.0 as u32 => "System",
            v if v == VFT2_DRV_INSTALLABLE.0 as u32 => "Installable",
            v if v == VFT2_DRV_SOUND.0 as u32 => "Sound",
            v if v == VFT2_DRV_COMM.0 as u32 => "Comm",
            v if v == VFT2_DRV_INPUTMETHOD.0 as u32 => "InputMethod",
            v if v == VFT2_DRV_VERSIONED_PRINTER.0 as u32 => "VersionedPrinter",
            _ => "Unknown",
        }
        .to_owned(),
        v if v == VFT_FONT.0 as u32 => match subtype {
            v if v == VFT2_FONT_RASTER.0 as u32 => "Raster",
            v if v == VFT2_FONT_VECTOR.0 as u32 => "Vector",
            v if v == VFT2_FONT_TRUETYPE.0 as u32 => "TrueType",
            _ => "Unknown",
        }
        .to_owned(),
        _ if subtype == 0 => "Unknown".to_owned(),
        _ => subtype.to_string(),
    }
}

fn file_os_name(file_os: u32) -> &'static str {
    match file_os {
        v if v == VOS_NT_WINDOWS32.0 => "WinNT32",
        v if v == VOS_DOS_WINDOWS32.0 => "Win32",
        v if v == VOS_DOS_WINDOWS16.0 => "Win16",
        v if v == VOS_OS232_PM32.0 => "PM32",
        v if v == VOS_OS216_PM16.0 => "PM16",
        v if v == VOS_NT.0 => "NT",
        v if v == VOS_DOS.0 => "DOS",
        v if v == VOS_OS216.0 => "OS216",
        v if v == VOS_OS232.0 => "OS232",
        v if v == VOS_WINCE.0 => "WinCE",
        _ => "Unknown",
    }
}

fn file_flags_name(flags: VS_FIXEDFILEINFO_FILE_FLAGS) -> String {
    let names: [(&str, VS_FIXEDFILEINFO_FILE_FLAGS); 6] = [
        ("debug", VS_FF_DEBUG),
        ("prerelease", VS_FF_PRERELEASE),
        ("patched", VS_FF_PATCHED),
        ("privatebuild", VS_FF_PRIVATEBUILD),
        ("specialbuild", VS_FF_SPECIALBUILD),
        ("infoinferred", VS_FF_INFOINFERRED),
    ];
    names
        .iter()
        .filter(|(_, flag)| flags.contains(*flag))
        .map(|(name, _)| *name)
        .collect::<Vec<_>>()
        .join(",")
}

/// Parses a dotted version string into four fixed components, padding with 0.
fn parse_version_parts(version: &str) -> [u32; 4] {
    let mut parts = [0u32; 4];
    for (i, part) in version.split('.').take(4).enumerate() {
        parts[i] = part.trim().parse().unwrap_or(0);
    }
    parts
}

/// Installer shells are frequently 32-bit even when the payload they unpack
/// is 64-bit, so an x86 outer image is not authoritative: probe the payload
/// for the real architecture and let unrecognized shells stand as-is.
fn apply_payload_probe(path: &Path, info: &mut VersionInfo) {
    if info.arch != "x86" {
        return;
    }
    match probe_payload(path, &info.arch) {
        ContentProbe::Found(arch) => info.arch = arch,
        // Payload evidence includes machine types outside the supported
        // platforms; rendered as U+FFFD by the pattern engine.
        ContentProbe::Unknown => info.arch.clear(),
        // Opaque installer formats, a missing 7-Zip, or evidence-free
        // unpacked contents keep the shell architecture.
        ContentProbe::Inconclusive => {}
    }
}

fn from_pe(path: &Path) -> windows::core::Result<VersionInfo> {
    let path_wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let path_ptr = PCWSTR(path_wide.as_ptr());

    let mut info = VersionInfo {
        arch: detect_arch(path_ptr),
        ..Default::default()
    };
    let buffer = unsafe {
        let mut handle = 0u32;
        let size =
            GetFileVersionInfoSizeExW(GET_FILE_VERSION_INFO_FLAGS(0), path_ptr, &raw mut handle);
        if size == 0 {
            return Err(Error::from_thread());
        }

        let mut buffer = vec![0u8; size as usize];
        // SAFETY: `buffer` is writable for `size` bytes and stays alive for the
        // whole query phase below.
        GetFileVersionInfoExW(
            GET_FILE_VERSION_INFO_FLAGS(0),
            path_ptr,
            Some(handle),
            size,
            buffer.as_mut_ptr().cast::<core::ffi::c_void>(),
        )?;

        buffer
    };
    resource::read(&buffer, &mut info)
        .ok_or_else(|| Error::from_hresult(ERROR_INVALID_DATA.to_hresult()))?;
    apply_payload_probe(path, &mut info);
    Ok(info)
}

fn from_msi(path: &Path) -> Result<VersionInfo, String> {
    let path_wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    unsafe {
        let mut db = MSIHANDLE(0);
        // SAFETY: `path_wide` is a valid null-terminated wide string; `db` is
        // a valid out handle.
        let rc = MsiOpenDatabaseW(PCWSTR(path_wide.as_ptr()), w!("0"), &raw mut db);
        if rc != ERROR_SUCCESS.0 {
            return Err(format!("failed to open MSI database (error {rc})"));
        }
        let result = read_msi_properties(db);
        // SAFETY: `db` is a valid handle returned by MsiOpenDatabaseW.
        MsiCloseHandle(db);
        result
    }
}

fn read_msi_properties(db: MSIHANDLE) -> Result<VersionInfo, String> {
    let mut info = VersionInfo::default();
    let mut product_version = None;
    for key in [
        "ProductName",
        "ProductVersion",
        "Manufacturer",
        "ProductCode",
        "ARPCOMMENTS",
        "Subject",
    ] {
        let value = unsafe { msi_query_string(db, key) }?;
        if let Some(value) = value {
            match key {
                "ProductName" => info.product_name = OsString::from(value),
                "ProductVersion" => product_version = Some(value),
                "Manufacturer" => info.company_name = OsString::from(value),
                "ProductCode" => info.internal_name = OsString::from(value),
                "ARPCOMMENTS" => info.comments = OsString::from(value),
                "Subject" => info.file_description = OsString::from(value),
                _ => {}
            }
        }
    }
    if let Some(version) = product_version {
        let parts = parse_version_parts(&version);
        info.file_version = OsString::from(&version);
        info.product_version = OsString::from(version);
        info.fixed = Some(FixedFileInfo {
            file_version: parts,
            product_version: parts,
            file_type: "MSI".to_owned(),
            file_subtype: String::new(),
            file_os: String::new(),
            file_flags: String::new(),
        });
    }
    if let Some(template) = msi_template(db)? {
        msi_arch_token(&template).clone_into(&mut info.arch);
    }
    Ok(info)
}

/// Reads the `Template` property: the Property table first, the summary
/// information stream as a fallback.
fn msi_template(db: MSIHANDLE) -> Result<Option<String>, String> {
    if let Some(value) = unsafe { msi_query_string(db, "Template")? } {
        return Ok(Some(value));
    }
    // A missing or unreadable summary stream is not fatal.
    Ok(msi_summary_template(db).ok().flatten())
}

/// Reads the `Template` property from the MSI `SummaryInformation` stream, e.g.
/// `x64;1033` or `Intel;1033`. Architecture is not always in the Property
/// table, so this is the reliable source.
fn msi_summary_template(db: MSIHANDLE) -> Result<Option<String>, String> {
    unsafe {
        let mut summary = MSIHANDLE(0);
        // SAFETY: `db` is a valid database handle; `summary` is a valid out
        // handle; the database path is optional (null).
        let rc = MsiGetSummaryInformationW(db, PCWSTR(std::ptr::null()), 0, &raw mut summary);
        if rc != ERROR_SUCCESS.0 {
            return Err(format!(
                "failed to open MSI summary information (error {rc})"
            ));
        }
        let mut data_type = 0u32;
        let mut int_value = 0i32;
        let mut file_time = FileTime {
            dw_low_date_time: 0,
            dw_high_date_time: 0,
        };
        let mut len = 0u32;
        // SAFETY: all out pointers are valid; the null buffer asks for the
        // required size of the string property.
        let rc = MsiSummaryInfoGetPropertyW(
            summary.0,
            PID_TEMPLATE,
            &raw mut data_type,
            &raw mut int_value,
            &raw mut file_time,
            std::ptr::null_mut(),
            &raw mut len,
        );
        if rc == ERROR_UNKNOWN_PROPERTY || len == 0 {
            // SAFETY: `summary` is a valid handle returned by MsiGetSummaryInformationW.
            MsiCloseHandle(summary);
            return Ok(None);
        }
        if rc != ERROR_SUCCESS.0 {
            // SAFETY: `summary` is a valid handle returned by MsiGetSummaryInformationW.
            MsiCloseHandle(summary);
            return Err(format!("failed to read MSI summary property (error {rc})"));
        }

        let mut buffer = vec![0u16; (len + 1) as usize];
        let mut capacity = u32::try_from(buffer.len()).unwrap();
        // SAFETY: `buffer` is writable for `capacity` UTF-16 code units
        // (including the null terminator); the other out pointers are valid.
        let rc = MsiSummaryInfoGetPropertyW(
            summary.0,
            PID_TEMPLATE,
            &raw mut data_type,
            &raw mut int_value,
            &raw mut file_time,
            buffer.as_mut_ptr(),
            &raw mut capacity,
        );
        // SAFETY: `summary` is a valid handle returned by MsiGetSummaryInformationW.
        MsiCloseHandle(summary);
        if rc != ERROR_SUCCESS.0 {
            return Err(format!("failed to read MSI summary property (error {rc})"));
        }
        let end = buffer.iter().position(|&u| u == 0).unwrap_or(buffer.len());
        let value = String::from_utf16_lossy(&buffer[..end]);
        if value.trim().is_empty() {
            Ok(None)
        } else {
            Ok(Some(value))
        }
    }
}

unsafe fn msi_query_string(db: MSIHANDLE, property: &str) -> Result<Option<String>, String> {
    let query = format!("SELECT `Value` FROM `Property` WHERE `Property` = '{property}'");
    let query_wide = to_wide(&query);
    let mut view = MSIHANDLE(0);
    // SAFETY: `query_wide` is a valid null-terminated wide string; `view` is
    // a valid out handle.
    let rc = unsafe { MsiDatabaseOpenViewW(db, PCWSTR(query_wide.as_ptr()), &raw mut view) };
    if rc != ERROR_SUCCESS.0 {
        return Err(format!("failed to open MSI view (error {rc})"));
    }
    // SAFETY: `view` is a valid handle; MSIHANDLE(0) is the null record handle.
    let rc = unsafe { MsiViewExecute(view, MSIHANDLE(0)) };
    if rc != ERROR_SUCCESS.0 {
        unsafe { MsiCloseHandle(view) };
        return Err(format!("failed to execute MSI view (error {rc})"));
    }
    let mut record = MSIHANDLE(0);
    // SAFETY: `record` is a valid out handle.
    let rc = unsafe { MsiViewFetch(view, &raw mut record) };
    if rc == ERROR_NO_MORE_ITEMS.0 {
        unsafe { MsiCloseHandle(view) };
        return Ok(None);
    }
    if rc != ERROR_SUCCESS.0 {
        unsafe { MsiCloseHandle(view) };
        return Err(format!("failed to fetch MSI record (error {rc})"));
    }
    // SAFETY: `record` is a valid handle returned by MsiViewFetch.
    let value = unsafe { msi_record_string(record, 1) };
    unsafe { MsiCloseHandle(record) };
    unsafe { MsiCloseHandle(view) };
    value.map(Some)
}

unsafe fn msi_record_string(record: MSIHANDLE, field: u32) -> Result<String, String> {
    let mut len = 0u32;
    // SAFETY: `len` is a valid out pointer; the null buffer asks for the size.
    let rc = unsafe { MsiRecordGetStringW(record, field, None, Some(&raw mut len)) };
    if rc != ERROR_SUCCESS.0 {
        return Err(format!("failed to read MSI string length (error {rc})"));
    }
    if len == 0 {
        return Ok(String::new());
    }
    let mut buffer = vec![0u16; (len + 1) as usize];
    let mut capacity = u32::try_from(buffer.len()).unwrap();
    // SAFETY: `buffer` is writable for `len` UTF-16 code units (including the
    // null terminator) and `len` is a valid in/out pointer.
    let rc = unsafe {
        MsiRecordGetStringW(
            record,
            field,
            Some(PWSTR(buffer.as_mut_ptr())),
            Some(&raw mut capacity),
        )
    };
    if rc != ERROR_SUCCESS.0 {
        return Err(format!("failed to read MSI string (error {rc})"));
    }
    let end = buffer.iter().position(|&u| u == 0).unwrap_or(buffer.len());
    Ok(String::from_utf16_lossy(&buffer[..end]))
}

/// Parses the platform tokens of an MSI `Template` property into payload
/// evidence. Unknown tokens are skipped; the legacy 32-bit `Arm` platform
/// counts as unrecognized.
fn msi_template_evidence(template: &str) -> Vec<ArchEvidence> {
    template
        .split(';')
        .map(|token| token.trim().to_ascii_lowercase())
        .filter_map(|token| match token.as_str() {
            "intel" | "x86" => Some(ArchEvidence::X86),
            "intel64" | "amd64" | "x64" => Some(ArchEvidence::X64),
            "arm64" => Some(ArchEvidence::Arm64),
            "arm" => Some(ArchEvidence::Unrecognized),
            _ => None,
        })
        .collect()
}

/// `{Arch}` token for an MSI `Template` property, merging multi-platform
/// templates (e.g. `Intel;AMD64;Arm64;1033` renders as `x86+arm64`).
fn msi_arch_token(template: &str) -> String {
    match merge_architectures(&msi_template_evidence(template)) {
        Some(arch) => arch.to_owned(),
        // No recognized platform token, or the legacy 32-bit `Arm` platform:
        // the explicit unknown placeholder.
        None => "unknown".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_msi_template_to_arch() {
        assert_eq!(msi_arch_token("x64;1033"), "x64");
        assert_eq!(msi_arch_token("Intel;1033"), "x86");
        assert_eq!(msi_arch_token("Intel64;1033"), "x64");
        assert_eq!(msi_arch_token("AMD64;1033"), "x64");
        assert_eq!(msi_arch_token("Arm64;1033"), "arm64");
        // The legacy 32-bit Arm platform and unrecognized tokens stay unknown.
        assert_eq!(msi_arch_token("Arm;1033"), "unknown");
        assert_eq!(msi_arch_token(""), "unknown");
        assert_eq!(msi_arch_token("xyz;1033"), "unknown");
    }

    #[test]
    fn merges_msi_multi_platform_templates() {
        assert_eq!(msi_arch_token("Intel;AMD64;1033"), "x86");
        assert_eq!(msi_arch_token("Intel;Arm64;1033"), "x86+arm64");
        assert_eq!(msi_arch_token("AMD64;Arm64;1033"), "x64+arm64");
        assert_eq!(msi_arch_token("Intel;AMD64;Arm64;1033"), "x86+arm64");
    }

    #[test]
    fn parses_version_strings_into_fixed_parts() {
        assert_eq!(parse_version_parts("26.5.0"), [26, 5, 0, 0]);
        assert_eq!(parse_version_parts("7.6.4.0"), [7, 6, 4, 0]);
        assert_eq!(parse_version_parts("1.2.3.4.5"), [1, 2, 3, 4]);
        assert_eq!(parse_version_parts(""), [0, 0, 0, 0]);
        assert_eq!(parse_version_parts("a.b"), [0, 0, 0, 0]);
    }
}
