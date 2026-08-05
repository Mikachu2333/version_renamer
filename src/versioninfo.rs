#![allow(unsafe_code)] // Intentional FFI wrapper; every unsafe block carries a SAFETY comment.

use std::ffi::OsString;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use windows::Win32::Storage::FileSystem::{
    GET_FILE_VERSION_INFO_FLAGS, GetBinaryTypeW, GetFileVersionInfoExW, GetFileVersionInfoSizeExW,
    VFT_APP, VFT_DLL, VFT_DRV, VFT_FONT, VFT_STATIC_LIB, VFT_UNKNOWN, VFT_VXD, VFT2_DRV_COMM,
    VFT2_DRV_DISPLAY, VFT2_DRV_INPUTMETHOD, VFT2_DRV_INSTALLABLE, VFT2_DRV_KEYBOARD,
    VFT2_DRV_LANGUAGE, VFT2_DRV_MOUSE, VFT2_DRV_NETWORK, VFT2_DRV_PRINTER, VFT2_DRV_SOUND,
    VFT2_DRV_SYSTEM, VFT2_DRV_VERSIONED_PRINTER, VFT2_FONT_RASTER, VFT2_FONT_TRUETYPE,
    VFT2_FONT_VECTOR, VOS_DOS, VOS_DOS_WINDOWS16, VOS_DOS_WINDOWS32, VOS_NT, VOS_NT_WINDOWS32,
    VOS_OS216, VOS_OS216_PM16, VOS_OS232, VOS_OS232_PM32, VOS_UNKNOWN, VOS_WINCE, VS_FF_DEBUG,
    VS_FF_INFOINFERRED, VS_FF_PATCHED, VS_FF_PRERELEASE, VS_FF_PRIVATEBUILD, VS_FF_SPECIALBUILD,
    VS_FIXEDFILEINFO, VS_FIXEDFILEINFO_FILE_FLAGS, VerQueryValueW,
};
use windows::Win32::System::WindowsProgramming::{SCS_32BIT_BINARY, SCS_64BIT_BINARY};
use windows::core::{Error, PCWSTR, w};

// SCS_* values not exposed by windows 0.62.2, taken from winnt.h.
const SCS_ARM64_BINARY: u32 = 10;
const SCS_ARMNT_BINARY: u32 = 12;

const STRING_KEYS: [&str; 12] = [
    "ProductName",
    "InternalName",
    "OriginalFilename",
    "FileVersion",
    "ProductVersion",
    "CompanyName",
    "LegalCopyright",
    "LegalTrademarks",
    "FileDescription",
    "Comments",
    "PrivateBuild",
    "SpecialBuild",
];

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

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Queries one string resource for a given (language, code page) translation.
///
/// # Safety
/// `buffer` must be the block filled by `GetFileVersionInfoExW`; the returned
/// pointer from `VerQueryValueW` points into that block and is only used while
/// `buffer` is alive.
unsafe fn query_string(buffer: &[u8], lang: u16, code_page: u16, key: &str) -> Option<String> {
    let sub_block = format!("\\StringFileInfo\\{lang:04x}{code_page:04x}\\{key}");
    let sub_block = to_wide(&sub_block);
    let mut value_ptr: *mut core::ffi::c_void = std::ptr::null_mut();
    let mut value_len = 0u32;

    // SAFETY: `buffer` is the block filled by GetFileVersionInfoExW and is
    // alive for this call; `sub_block` is a valid null-terminated wide string.
    let found = unsafe {
        VerQueryValueW(
            buffer.as_ptr().cast::<core::ffi::c_void>(),
            PCWSTR(sub_block.as_ptr()),
            &raw mut value_ptr,
            &raw mut value_len,
        )
    };
    if !found.as_bool() || value_ptr.is_null() || value_len == 0 {
        return None;
    }

    // `value_len` is unreliable across resources (some include the null
    // terminator, some do not), so scan the buffer up to the first null.
    let base = buffer.as_ptr() as usize;
    let ptr = value_ptr as usize;
    if ptr < base || ptr > base + buffer.len() {
        return None;
    }
    let max_units = (buffer.len() - (ptr - base)) / 2;
    // SAFETY: `value_ptr` points inside the still-alive `buffer` and
    // `max_units` is bounded by the remaining buffer length.
    let units = unsafe { std::slice::from_raw_parts(value_ptr as *const u16, max_units) };
    let end = units.iter().position(|&u| u == 0).unwrap_or(max_units);
    let value = String::from_utf16_lossy(&units[..end]);
    let value = value.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_owned())
    }
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
        v if v == VFT_UNKNOWN.0 as u32 => "Unknown",
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
        v if v == VOS_UNKNOWN.0 => "Unknown",
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

pub fn from_file<P: AsRef<Path>>(path: P) -> windows::core::Result<VersionInfo> {
    let path_wide: Vec<u16> = path
        .as_ref()
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let path_ptr = PCWSTR(path_wide.as_ptr());

    let mut info = VersionInfo {
        arch: detect_arch(path_ptr),
        ..Default::default()
    };

    unsafe {
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

        let mut value_ptr: *mut core::ffi::c_void = std::ptr::null_mut();
        let mut value_len = 0u32;
        let found = VerQueryValueW(
            buffer.as_ptr().cast::<core::ffi::c_void>(),
            w!("\\VarFileInfo\\Translation"),
            &raw mut value_ptr,
            &raw mut value_len,
        );

        let mut translations: Vec<(u16, u16)> = Vec::new();
        if found.as_bool() && !value_ptr.is_null() && value_len >= 4 {
            let pair_count = (value_len as usize) / 4;
            let pairs = std::slice::from_raw_parts(value_ptr as *const u16, pair_count * 2);
            for pair in pairs.chunks_exact(2) {
                translations.push((pair[0], pair[1]));
            }
        }
        if translations.is_empty() {
            // Fallback: the classic neutral English (0x0409) / Unicode (0x04B0) pair.
            translations.push((0x0409, 0x04B0));
        }

        for (lang, code_page) in &translations {
            for key in STRING_KEYS {
                // SAFETY: `buffer` is the block filled by GetFileVersionInfoExW
                // and is still alive; `query_string` copies out the value.
                if let Some(value) = query_string(&buffer, *lang, *code_page, key) {
                    match key {
                        "ProductName" => info.product_name = OsString::from(value),
                        "InternalName" => info.internal_name = OsString::from(value),
                        "OriginalFilename" => info.original_filename = OsString::from(value),
                        "FileVersion" => info.file_version = OsString::from(value),
                        "ProductVersion" => info.product_version = OsString::from(value),
                        "CompanyName" => info.company_name = OsString::from(value),
                        "LegalCopyright" => info.legal_copyright = OsString::from(value),
                        "LegalTrademarks" => info.legal_trademarks = OsString::from(value),
                        "FileDescription" => info.file_description = OsString::from(value),
                        "Comments" => info.comments = OsString::from(value),
                        "PrivateBuild" => info.private_build = OsString::from(value),
                        "SpecialBuild" => info.special_build = OsString::from(value),
                        _ => {}
                    }
                }
            }
        }

        let mut fixed_ptr: *mut core::ffi::c_void = std::ptr::null_mut();
        let mut fixed_len = 0u32;
        let fixed_found = VerQueryValueW(
            buffer.as_ptr().cast::<core::ffi::c_void>(),
            w!("\\"),
            &raw mut fixed_ptr,
            &raw mut fixed_len,
        );
        if fixed_found.as_bool()
            && !fixed_ptr.is_null()
            && fixed_len as usize >= core::mem::size_of::<VS_FIXEDFILEINFO>()
        {
            // SAFETY: `fixed_ptr` points to a VS_FIXEDFILEINFO structure inside
            // the still-alive `buffer`; its size was verified above.
            let fixed = &*fixed_ptr.cast::<VS_FIXEDFILEINFO>();
            if fixed.dwSignature == 0xFE_EF_04_BD {
                info.fixed = Some(FixedFileInfo {
                    file_version: split_version(fixed.dwFileVersionMS, fixed.dwFileVersionLS),
                    product_version: split_version(
                        fixed.dwProductVersionMS,
                        fixed.dwProductVersionLS,
                    ),
                    file_type: file_type_name(fixed.dwFileType).to_owned(),
                    file_subtype: file_subtype_name(fixed.dwFileType, fixed.dwFileSubtype),
                    file_os: file_os_name(fixed.dwFileOS.0).to_owned(),
                    file_flags: file_flags_name(fixed.dwFileFlags),
                });
            }
        }
    }

    Ok(info)
}
