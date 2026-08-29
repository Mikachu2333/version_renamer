//! Payload architecture probing for installer executables.
//!
//! Installer shells are commonly built as 32-bit loaders even when the
//! payload they unpack is 64-bit, so the outer PE machine type alone is not
//! authoritative for them. This module determines the payload architecture
//! through three channels, ordered by cheapness:
//!
//! 1. Embedded PE scan: locate plaintext PE images in the file and collect
//!    their machine types. This works for stored (uncompressed) payloads;
//!    compressed streams contain no plaintext PE structures.
//! 2. Embedded MSI: locate plaintext OLE compound documents, copy them to
//!    temp files and read their `Template` summary properties.
//! 3. NSIS via 7-Zip: when the NSIS first-header magic is present, unpack
//!    with 7z if it is available and judge the unpacked executables/MSIs.
//!
//! Each channel yields a set of machine-type evidence. The evidence merges
//! into one token: x86 subsumes x64 (an x86 shell ships both), arm64 pairs
//! with whichever x86 flavor is present (`x86+arm64` / `x64+arm64`), and any
//! machine type outside those three platforms (ARM32 included) makes the
//! verdict unknown. Evidence matching the shell architecture is ignored
//! (loader machinery matches its loader), and NSIS engine plugin DLLs are
//! ignored entirely.
//!
//! Channels without usable payload evidence (opaque installer formats such
//! as Inno Setup, a missing 7-Zip, or unpacked contents without any
//! executable or MSI) report [`ContentProbe::Inconclusive`], so the caller
//! keeps the shell architecture instead of a misleading unknown. Only
//! evidence containing unsupported machine types reports
//! [`ContentProbe::Unknown`].

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{ErrorKind, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::versioninfo::{OLE_MAGIC, binary_arch_from_file, msi_evidence_from_file};

// NSIS first header: `flags(4) | 0xDEADBEEF(4) | "NullsoftInst"(12)`.
const NSIS_MAGIC: [u8; 16] = [
    0xEF, 0xBE, 0xAD, 0xDE, b'N', b'u', b'l', b'l', b's', b'o', b'f', b't', b'I', b'n', b's', b't',
];
// Setup-data marker embedded by the Inno Setup compiler; its presence means
// the payload is compressed and opaque to static scanning.
const INNO_TAG: &[u8] = b"Inno Setup Setup Data";

/// Streaming scan block size.
const BLOCK_SIZE: usize = 1024 * 1024;
/// Re-scan tail so a magic split across blocks is still found. Must cover
/// the largest magic (`INNO_TAG`, 21 bytes) and the MZ + `e_lfanew` window
/// (0x40 bytes).
const OVERLAP: usize = 128;
/// Do not scan huge files end to end; compressed payloads dominate there
/// anyway, so the probe would not learn anything new.
const MAX_SCAN_BYTES: u64 = 512 << 20;
/// Upper bound for plausible `e_lfanew` values (DOS stub size).
const MAX_DOS_STUB: u32 = 0x1000;
/// Cap for candidate collection on pathological files.
const MAX_CANDIDATES: usize = 8192;
/// Never copy more than this much when extracting a suspected embedded MSI.
const MAX_EMBEDDED_MSI_BYTES: u64 = 2 << 30;
/// Upper bound for embedded-MSI extraction attempts per file.
const MAX_EMBEDDED_MSI_CANDIDATES: usize = 8;

/// One item of payload architecture evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ArchEvidence {
    X86,
    X64,
    Arm64,
    /// ARM32 or any other machine type outside the three supported
    /// platforms; its presence makes the whole verdict unknown.
    Unrecognized,
}

/// Merges payload evidence into the `{Arch}` token: x86 subsumes x64, arm64
/// pairs with whichever x86 flavor is present, and an unrecognized machine
/// type poisons the verdict. An empty slice also yields `None`; callers
/// decide whether that means "no evidence" or an explicit unknown.
pub(crate) fn merge_architectures(evidence: &[ArchEvidence]) -> Option<&'static str> {
    if evidence.contains(&ArchEvidence::Unrecognized) {
        return None;
    }
    let x86 = evidence.contains(&ArchEvidence::X86);
    let x64 = evidence.contains(&ArchEvidence::X64);
    let arm64 = evidence.contains(&ArchEvidence::Arm64);
    match (x86, x64, arm64) {
        (true, _, true) => Some("x86+arm64"),
        (false, true, true) => Some("x64+arm64"),
        (false, false, true) => Some("arm64"),
        (true, _, false) => Some("x86"),
        (false, true, false) => Some("x64"),
        (false, false, false) => None,
    }
}

/// Merges a collected evidence set into a payload verdict; `None` when no
/// evidence was collected at all.
fn verdict_from_evidence(evidence: &[ArchEvidence]) -> Option<PayloadVerdict> {
    if evidence.is_empty() {
        return None;
    }
    match merge_architectures(evidence) {
        Some(arch) => Some(PayloadVerdict::Arch(arch.to_owned())),
        None => Some(PayloadVerdict::Unknown),
    }
}

/// Verdict for a set of payload architecture evidence.
#[derive(Debug)]
enum PayloadVerdict {
    /// The evidence merged into one token: a plain architecture or a
    /// combined one such as `x86+arm64`.
    Arch(String),
    /// Evidence exists but includes machine types outside the supported
    /// platforms, so no architecture can be attributed.
    Unknown,
    /// No usable payload evidence was found.
    NoEvidence,
}

/// Outcome of probing an executable for its payload architecture.
#[derive(Debug)]
pub(crate) enum ContentProbe {
    /// The payload architecture was determined.
    Found(String),
    /// The payload carries evidence for machine types outside the supported
    /// platforms, so no architecture can be attributed.
    Unknown,
    /// No payload evidence either way; the shell architecture stands.
    Inconclusive,
}

/// Internal probe result before the path-only NSIS/7z step runs.
#[derive(Debug)]
enum ReaderProbe {
    Found(String),
    /// Payload evidence exists but includes machine types outside the
    /// supported platforms.
    Unknown,
    NsisDetected,
    Inconclusive,
}

#[derive(Default)]
struct Scan {
    /// Offsets of `MZ` sequences whose `e_lfanew` looks plausible.
    mz_candidates: Vec<u64>,
    /// Offsets of plaintext OLE compound documents (possible nested MSIs).
    ole_candidates: Vec<u64>,
    is_nsis: bool,
    is_inno: bool,
}

/// Probes the file's payload architecture. Only meaningful when the outer
/// image is an x86 installer shell: x64/arm64 loaders are trusted as-is,
/// because their payload cannot be judged without re-implementing every
/// installer format and the common loaders already match their payload.
pub(crate) fn probe(path: &Path, shell_arch: &str) -> ContentProbe {
    let Ok(mut file) = File::open(path) else {
        return ContentProbe::Inconclusive;
    };
    let file_len = file.metadata().map_or(0, |m| m.len());
    match probe_reader(&mut file, file_len, shell_arch) {
        ReaderProbe::Found(arch) => ContentProbe::Found(arch),
        ReaderProbe::Unknown => ContentProbe::Unknown,
        ReaderProbe::NsisDetected => match nsis_payload_arch(path, shell_arch) {
            PayloadVerdict::Arch(arch) => ContentProbe::Found(arch),
            PayloadVerdict::Unknown => ContentProbe::Unknown,
            // A missing 7-Zip, a failed unpack, or unpacked contents without
            // any executable or MSI: the shell architecture stands.
            PayloadVerdict::NoEvidence => ContentProbe::Inconclusive,
        },
        ReaderProbe::Inconclusive => ContentProbe::Inconclusive,
    }
}

fn probe_reader<R: Read + Seek>(reader: &mut R, file_len: u64, shell_arch: &str) -> ReaderProbe {
    let scan = scan_file(reader, BLOCK_SIZE);

    match embedded_images_verdict(reader, &scan.mz_candidates, shell_arch) {
        Some(PayloadVerdict::Arch(arch)) => return ReaderProbe::Found(arch),
        Some(PayloadVerdict::Unknown) => return ReaderProbe::Unknown,
        Some(PayloadVerdict::NoEvidence) | None => {}
    }
    // Recognized installer formats take precedence over an embedded OLE
    // document: inside them a plaintext MSI is just one bundled component
    // (e.g. an x86 VC runtime), not the application architecture. The NSIS
    // step needs a real path for 7z, so it is deferred to `probe`.
    if scan.is_nsis {
        return ReaderProbe::NsisDetected;
    }
    if scan.is_inno {
        // The Inno Setup payload is compressed and opaque to static
        // scanning, so the shell architecture stands.
        return ReaderProbe::Inconclusive;
    }
    match embedded_msi_verdict(reader, &scan.ole_candidates, file_len) {
        Some(PayloadVerdict::Arch(arch)) => ReaderProbe::Found(arch),
        Some(PayloadVerdict::Unknown) => ReaderProbe::Unknown,
        Some(PayloadVerdict::NoEvidence) | None => ReaderProbe::Inconclusive,
    }
}

fn scan_file<R: Read>(reader: &mut R, block: usize) -> Scan {
    debug_assert!(block >= OVERLAP);
    let mut scan = Scan::default();
    let mut buf = vec![0u8; block + OVERLAP];
    let mut base: u64 = 0;
    let mut filled = 0usize;
    loop {
        let mut eof = false;
        while filled < buf.len() {
            match reader.read(&mut buf[filled..]) {
                Ok(0) => {
                    eof = true;
                    break;
                }
                Ok(n) => filled += n,
                Err(e) if e.kind() == ErrorKind::Interrupted => {}
                // Treat read errors as end of stream; partial scans still
                // produce a usable answer.
                Err(_) => {
                    eof = true;
                    break;
                }
            }
        }
        if filled == 0 {
            break;
        }
        scan_slice(&buf[..filled], base, &mut scan);
        if eof || base >= MAX_SCAN_BYTES {
            break;
        }
        buf.copy_within(filled - OVERLAP.., 0);
        base += (filled - OVERLAP) as u64;
        filled = OVERLAP;
    }
    scan.mz_candidates.sort_unstable();
    scan.mz_candidates.dedup();
    scan.ole_candidates.sort_unstable();
    scan.ole_candidates.dedup();
    scan
}

fn scan_slice(buf: &[u8], base: u64, scan: &mut Scan) {
    let len = buf.len();
    for i in 0..len {
        match buf[i] {
            // `base + i >= 0x40` skips the shell image's own MZ, which sits
            // at file offset 0; only payload images are of interest here.
            0x4D if i + 1 < len && buf[i + 1] == 0x5A && base + i as u64 >= 0x40 => {
                if scan.mz_candidates.len() < MAX_CANDIDATES
                    && let Some(l) = u32_le(buf, i + 0x3C)
                    && (0x40..=MAX_DOS_STUB).contains(&l)
                {
                    scan.mz_candidates.push(base + i as u64);
                }
            }
            0xD0 if buf[i..].starts_with(&OLE_MAGIC) => {
                if scan.ole_candidates.len() < MAX_CANDIDATES {
                    scan.ole_candidates.push(base + i as u64);
                }
            }
            0xEF if buf[i..].starts_with(&NSIS_MAGIC) => scan.is_nsis = true,
            b'I' if buf[i..].starts_with(INNO_TAG) => scan.is_inno = true,
            _ => {}
        }
    }
}

/// Reads the COFF header of an embedded PE image and validates its section
/// table, so random `MZ` hits inside compressed data are rejected.
fn read_image_header<R: Read + Seek>(reader: &mut R, mz_offset: u64) -> Option<u16> {
    reader.seek(SeekFrom::Start(mz_offset)).ok()?;
    let mut hdr = [0u8; 0x4000];
    let mut read = 0usize;
    while read < hdr.len() {
        match reader.read(&mut hdr[read..]) {
            Ok(0) => break,
            Ok(n) => read += n,
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    let pe = u32_le(&hdr, 0x3C)? as usize;
    if hdr.get(pe..pe + 4)? != b"PE\0\0" {
        return None;
    }
    let machine = u16_le(&hdr, pe + 4)?;
    let sections = u16_le(&hdr, pe + 6)? as usize;
    if sections == 0 || sections > 96 {
        return None;
    }
    let table = pe + 24 + u16_le(&hdr, pe + 20)? as usize;
    let table_end = table.checked_add(40 * sections)?;
    if table_end > read {
        return None;
    }
    Some(machine)
}

/// Judges the embedded PE images. Hits matching the shell architecture
/// carry no information (installer machinery matches its loader), so only
/// other machine types count as payload evidence. The evidence set merges
/// into one token; machine types outside the supported platforms poison it.
fn embedded_images_verdict<R: Read + Seek>(
    reader: &mut R,
    candidates: &[u64],
    shell_arch: &str,
) -> Option<PayloadVerdict> {
    let mut evidence: Vec<ArchEvidence> = Vec::new();
    for &off in candidates {
        let Some(machine) = read_image_header(reader, off) else {
            continue;
        };
        let ev = match machine_name(machine) {
            Some(name) if name == shell_arch => continue,
            Some("x86") => ArchEvidence::X86,
            Some("x64") => ArchEvidence::X64,
            Some("arm64") => ArchEvidence::Arm64,
            Some(_) | None => ArchEvidence::Unrecognized,
        };
        if !evidence.contains(&ev) {
            evidence.push(ev);
        }
    }
    verdict_from_evidence(&evidence)
}

/// PE COFF machine type mapped to the `{Arch}` token. Machine types outside
/// the supported platforms (ARM32 included) map to `None` and count as
/// unrecognized evidence.
fn machine_name(machine: u16) -> Option<&'static str> {
    match machine {
        0x014C => Some("x86"),
        0x8664 => Some("x64"),
        0xAA64 => Some("arm64"),
        _ => None,
    }
}

/// Extracts every embedded OLE candidate and collects the MSI `Template`
/// evidence. Unlike PE machinery, every plaintext MSI inside a bootstrapper
/// is content (platform-specific payload MSIs), so a bundle of several
/// platform MSIs merges per the combined-architecture rules. Shell-arch
/// matching MSIs are kept: a plain x86 bootstrapper around an x86 MSI stays
/// x86.
fn embedded_msi_verdict<R: Read + Seek>(
    reader: &mut R,
    candidates: &[u64],
    file_len: u64,
) -> Option<PayloadVerdict> {
    let mut evidence: Vec<ArchEvidence> = Vec::new();
    for &off in candidates.iter().take(MAX_EMBEDDED_MSI_CANDIDATES) {
        let Some(len) = file_len.checked_sub(off) else {
            continue;
        };
        if !(512..=MAX_EMBEDDED_MSI_BYTES).contains(&len) {
            continue;
        }
        if reader.seek(SeekFrom::Start(off)).is_err() {
            continue;
        }
        let tmp = temp_path("msi");
        let Ok(mut out) = File::create(&tmp) else {
            continue;
        };
        let copied = std::io::copy(&mut reader.take(len), &mut out).unwrap_or(0);
        drop(out);
        let archs = if copied == len {
            msi_evidence_from_file(&tmp)
        } else {
            Vec::new()
        };
        let _ = std::fs::remove_file(&tmp);
        for ev in archs {
            if !evidence.contains(&ev) {
                evidence.push(ev);
            }
        }
    }
    verdict_from_evidence(&evidence)
}

/// Locates 7-Zip; a plain `7z` falls back to PATH resolution, and a missing
/// binary only fails the unpack step.
fn find_7z() -> OsString {
    for candidate in [
        r"C:\Program Files\7-Zip\7z.exe",
        r"C:\Program Files (x86)\7-Zip\7z.exe",
    ] {
        if Path::new(candidate).is_file() {
            return OsString::from(candidate);
        }
    }
    OsString::from("7z")
}

fn nsis_payload_arch(setup: &Path, shell_arch: &str) -> PayloadVerdict {
    let seven_zip = find_7z();
    let mut temp_dirs = Vec::new();
    let mut dirs = Vec::new();
    if let Some(first) = unpack(&seven_zip, setup) {
        // electron-builder style packages keep the application payload in a
        // nested 7z container (app-64.7z), so unpack the largest one as a
        // second level as well.
        let container = largest_container(&first);
        dirs.push(first.clone());
        temp_dirs.push(first);
        if let Some(container) = container
            && let Some(nested) = unpack(&seven_zip, &container)
        {
            dirs.push(nested.clone());
            temp_dirs.push(nested);
        }
    }
    let verdict = payload_verdict(&dirs, shell_arch);
    for dir in temp_dirs {
        let _ = std::fs::remove_dir_all(dir);
    }
    verdict
}

fn unpack(seven_zip: &OsStr, archive: &Path) -> Option<PathBuf> {
    let out = temp_path("nsis");
    if std::fs::create_dir_all(&out).is_err() {
        return None;
    }
    let status = Command::new(seven_zip)
        .arg("x")
        .arg("-y")
        .arg(format!("-o{}", out.display()))
        .arg("--")
        .arg(archive)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    if !status.is_ok_and(|s| s.success()) {
        let _ = std::fs::remove_dir_all(&out);
        return None;
    }
    Some(out)
}

/// Largest nested archive inside an unpacked installer, if any.
fn largest_container(dir: &Path) -> Option<PathBuf> {
    let mut files = Vec::new();
    collect_files(dir, &mut files);
    files
        .into_iter()
        .filter(|p| {
            p.extension()
                .map(|e| e.to_string_lossy().to_ascii_lowercase())
                .is_some_and(|e| e == "7z" || e == "zip")
        })
        .max_by_key(|p| std::fs::metadata(p).map_or(0, |m| m.len()))
}

/// Judges unpacked NSIS contents across all unpack levels. Executables and
/// MSIs are payload candidates and form the evidence set, merged per the
/// combined-architecture rules: PE hits matching the shell architecture
/// carry no information (loader machinery such as uninstaller templates
/// matches its loader), while every plaintext MSI is content. NSIS engine
/// plugin DLLs are 32-bit loader components and are ignored entirely.
fn payload_verdict(dirs: &[PathBuf], shell_arch: &str) -> PayloadVerdict {
    let mut evidence: Vec<ArchEvidence> = Vec::new();
    for dir in dirs {
        let mut files = Vec::new();
        collect_files(dir, &mut files);
        for path in &files {
            let Some(ext) = path
                .extension()
                .map(|e| e.to_string_lossy().to_ascii_lowercase())
            else {
                continue;
            };
            match ext.as_str() {
                "exe" => {
                    let arch = binary_arch_from_file(path);
                    if let Some(ev) = arch_evidence(&arch)
                        && arch != shell_arch
                        && !evidence.contains(&ev)
                    {
                        evidence.push(ev);
                    }
                }
                "msi" => {
                    for ev in msi_evidence_from_file(path) {
                        if !evidence.contains(&ev) {
                            evidence.push(ev);
                        }
                    }
                }
                _ => {}
            }
        }
    }
    if evidence.is_empty() {
        return PayloadVerdict::NoEvidence;
    }
    match merge_architectures(&evidence) {
        Some(arch) => PayloadVerdict::Arch(arch.to_owned()),
        None => PayloadVerdict::Unknown,
    }
}

/// Maps a binary architecture token to its evidence variant. ARM32 counts
/// as unrecognized; unreadable images carry no evidence.
fn arch_evidence(arch: &str) -> Option<ArchEvidence> {
    match arch {
        "x86" => Some(ArchEvidence::X86),
        "x64" => Some(ArchEvidence::X64),
        "arm64" => Some(ArchEvidence::Arm64),
        "arm" => Some(ArchEvidence::Unrecognized),
        _ => None,
    }
}

fn collect_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_files(&path, out);
        } else {
            out.push(path);
        }
    }
}

/// Collision-free temp name for this process (`msi`/`nsis` kinds double as
/// the file extension, which the MSI API expects).
fn temp_path(kind: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    std::env::temp_dir().join(format!(
        "version_renamer-{kind}-{}-{nanos}.{kind}",
        std::process::id()
    ))
}

fn u32_le(buf: &[u8], off: usize) -> Option<u32> {
    buf.get(off..off + 4)?
        .try_into()
        .ok()
        .map(u32::from_le_bytes)
}

fn u16_le(buf: &[u8], off: usize) -> Option<u16> {
    buf.get(off..off + 2)?
        .try_into()
        .ok()
        .map(u16::from_le_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// Builds a minimal PE image: MZ at offset 0, `e_lfanew` 0x40, one
    /// optional-header-sized COFF layout and the given section table.
    fn pe_image(machine: u16, sections: &[(u32, u32)]) -> Vec<u8> {
        let mut out = vec![0x4D, 0x5A];
        out.resize(0x3C, 0);
        out.extend_from_slice(&0x40u32.to_le_bytes());
        assert_eq!(out.len(), 0x40);
        out.extend_from_slice(b"PE\0\0");
        out.extend_from_slice(&machine.to_le_bytes());
        out.extend_from_slice(&u16::try_from(sections.len()).unwrap_or(0).to_le_bytes());
        out.extend_from_slice(&[0; 4]); // time date stamp
        out.extend_from_slice(&[0; 8]); // symbol table pointer + count
        out.extend_from_slice(&0xF0u16.to_le_bytes()); // optional header size
        out.extend_from_slice(&[0; 2]); // characteristics
        out.extend_from_slice(&[0; 0xF0]); // optional header body
        for &(raw_size, raw_ptr) in sections {
            out.extend_from_slice(&[0; 8]); // name
            out.extend_from_slice(&0u32.to_le_bytes()); // virtual size
            out.extend_from_slice(&0u32.to_le_bytes()); // virtual address
            out.extend_from_slice(&raw_size.to_le_bytes());
            out.extend_from_slice(&raw_ptr.to_le_bytes());
            out.extend_from_slice(&[0; 16]); // rest of the 40-byte section header
        }
        out
    }

    #[test]
    fn scans_installer_magics() {
        let mut data = vec![0u8; 64];
        data[16..32].copy_from_slice(&NSIS_MAGIC);
        let mut scan = Scan::default();
        scan_slice(&data, 0, &mut scan);
        assert!(scan.is_nsis);
        assert!(!scan.is_inno);

        let mut data = vec![0u8; 64];
        data[8..29].copy_from_slice(INNO_TAG);
        let mut scan = Scan::default();
        scan_slice(&data, 0, &mut scan);
        assert!(scan.is_inno);
        assert!(!scan.is_nsis);
    }

    #[test]
    fn collects_mz_only_with_plausible_lfanew() {
        let mut data = vec![0u8; 4096];
        data[0] = 0x4D;
        data[1] = 0x5A;
        data[60..64].copy_from_slice(&0x80u32.to_le_bytes()); // shell MZ at 0
        data[100] = 0x4D;
        data[101] = 0x5A;
        data[160..164].copy_from_slice(&0x80u32.to_le_bytes()); // plausible
        data[300] = 0x4D;
        data[301] = 0x5A;
        data[360..364].copy_from_slice(&5u32.to_le_bytes()); // below 0x40
        let mut scan = Scan::default();
        scan_slice(&data, 0, &mut scan);
        assert_eq!(scan.mz_candidates, vec![100]);
    }

    #[test]
    fn probe_ignores_x86_embedded_images() {
        let mut data = vec![0u8; 0x200];
        data.extend(pe_image(0x014C, &[(0x8000, 0x400)])); // large x86 image
        data.extend_from_slice(&[0u8; 0x100]);
        let mut cur = Cursor::new(data.as_slice());
        assert!(matches!(
            probe_reader(&mut cur, data.len() as u64, "x86"),
            ReaderProbe::Inconclusive
        ));
    }

    #[test]
    fn scan_is_block_size_independent() {
        let mut data = vec![0u8; 0x100];
        data.extend(pe_image(0x8664, &[(0x3000, 0x400)]));
        data.extend_from_slice(&[0u8; 0x800]);
        let small = scan_file(&mut Cursor::new(data.as_slice()), 256);
        let large = scan_file(&mut Cursor::new(data.as_slice()), BLOCK_SIZE);
        assert_eq!(small.mz_candidates, large.mz_candidates);
        assert_eq!(small.mz_candidates, vec![0x100]);
    }

    #[test]
    fn probe_adopts_single_non_shell_arch() {
        let mut data = vec![0u8; 0x200];
        data.extend(pe_image(0x014C, &[(0x200, 0x400)])); // small x86 image
        data.extend(pe_image(0x8664, &[(0x1000, 0x400)])); // larger x64 image
        data.extend_from_slice(&[0u8; 0x100]);
        let mut cur = Cursor::new(data.as_slice());
        assert!(matches!(
            probe_reader(&mut cur, data.len() as u64, "x86"),
            ReaderProbe::Found(arch) if arch == "x64"
        ));
    }

    #[test]
    fn probe_merges_x64_with_arm64() {
        let mut data = vec![0u8; 0x200];
        data.extend(pe_image(0x8664, &[(0x1000, 0x400)])); // x64 payload
        data.extend(pe_image(0xAA64, &[(0x1000, 0x400)])); // arm64 payload
        data.extend_from_slice(&[0u8; 0x100]);
        let mut cur = Cursor::new(data.as_slice());
        assert!(matches!(
            probe_reader(&mut cur, data.len() as u64, "x86"),
            ReaderProbe::Found(arch) if arch == "x64+arm64"
        ));
    }

    #[test]
    fn probe_reports_unknown_for_arm32_evidence() {
        let mut data = vec![0u8; 0x200];
        data.extend(pe_image(0x8664, &[(0x1000, 0x400)])); // x64 payload
        data.extend(pe_image(0x01C4, &[(0x1000, 0x400)])); // arm32 payload
        data.extend_from_slice(&[0u8; 0x100]);
        let mut cur = Cursor::new(data.as_slice());
        assert!(matches!(
            probe_reader(&mut cur, data.len() as u64, "x86"),
            ReaderProbe::Unknown
        ));
    }

    #[test]
    fn merges_evidence_sets() {
        use ArchEvidence::{Arm64, Unrecognized, X64, X86};
        assert_eq!(merge_architectures(&[X86]), Some("x86"));
        assert_eq!(merge_architectures(&[X64]), Some("x64"));
        assert_eq!(merge_architectures(&[Arm64]), Some("arm64"));
        assert_eq!(merge_architectures(&[X86, X64]), Some("x86"));
        assert_eq!(merge_architectures(&[X86, Arm64]), Some("x86+arm64"));
        assert_eq!(merge_architectures(&[X64, Arm64]), Some("x64+arm64"));
        assert_eq!(merge_architectures(&[X86, X64, Arm64]), Some("x86+arm64"));
        assert_eq!(merge_architectures(&[]), None);
        assert_eq!(merge_architectures(&[X86, Unrecognized]), None);
        assert_eq!(merge_architectures(&[Arm64, Unrecognized]), None);
    }

    #[test]
    fn probe_falls_back_for_inno() {
        let mut data = vec![0u8; 64];
        data[8..29].copy_from_slice(INNO_TAG);
        let mut cur = Cursor::new(data.as_slice());
        assert!(matches!(
            probe_reader(&mut cur, data.len() as u64, "x86"),
            ReaderProbe::Inconclusive
        ));
    }

    #[test]
    fn probe_flags_nsis_for_external_unpack() {
        let mut data = vec![0u8; 64];
        data[10..26].copy_from_slice(&NSIS_MAGIC);
        let mut cur = Cursor::new(data.as_slice());
        assert!(matches!(
            probe_reader(&mut cur, data.len() as u64, "x86"),
            ReaderProbe::NsisDetected
        ));
    }

    #[test]
    fn probe_is_inconclusive_without_traits() {
        let data = vec![0x90u8; 512];
        let mut cur = Cursor::new(data.as_slice());
        assert!(matches!(
            probe_reader(&mut cur, data.len() as u64, "x86"),
            ReaderProbe::Inconclusive
        ));
    }

    #[test]
    fn bogus_embedded_msi_falls_through() {
        let mut data = vec![0u8; 2048];
        data[64..72].copy_from_slice(&OLE_MAGIC);
        let mut cur = Cursor::new(data.as_slice());
        assert!(matches!(
            probe_reader(&mut cur, data.len() as u64, "x86"),
            ReaderProbe::Inconclusive
        ));
    }
}
