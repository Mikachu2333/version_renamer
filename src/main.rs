mod versioninfo;

use std::ffi::{OsStr, OsString};
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const DEFAULT_PATTERN: &str = "{Name}_{Arch}_{FileVer1}.{FileVer2}.{FileVer3}.{FileVer4}";
const MAX_FILE_NAME_CHARS: usize = 255;

fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().collect();

    if args.len() == 1 || is_help_flag(&args[1]) {
        print_help(&args[0]);
        pause_if_interactive();
        return ExitCode::SUCCESS;
    }

    let (file_path, pattern) = match parse_args(&args) {
        Ok(v) => v,
        Err(msg) => {
            eprintln!("Error: {msg}\n");
            print_help(&args[0]);
            pause_if_interactive();
            return ExitCode::FAILURE;
        }
    };

    if let Err(msg) = rename_with_version(&file_path, &pattern) {
        eprintln!("Error: {msg}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

fn is_help_flag(arg: &OsString) -> bool {
    let s = arg.to_string_lossy().to_ascii_lowercase();
    s == "--help" || s == "-h" || s == "/?"
}

fn pause_if_interactive() {
    if std::io::stdin().is_terminal() {
        println!("\nPress Enter to exit...");
        let mut line = String::new();
        let _ = std::io::stdin().read_line(&mut line);
    }
}

fn print_help(program: &OsString) {
    let name = program.to_string_lossy();
    println!(
        r"This is Version Renamer for Windows Executables, you can rename your exe files with patterns."
    );
    println!("Version: {}\n", env!("CARGO_PKG_VERSION"));
    println!("Supported files: PE executables (exe/dll/sys) with version info,");
    println!("  MSI packages.\n");
    println!("Usage:");
    println!("  {name} <FILE> [PATTERN]");
    println!("  {name} <PATTERN> <FILE>");
    println!();
    println!("When PATTERN is omitted, the default pattern is used:");
    println!("  {DEFAULT_PATTERN}");
    println!();
    println!("Example:");
    println!("  {name} {DEFAULT_PATTERN} Code-stable-e3jmdijwkdowj.exe");
    println!("  > VSCode_x64_1.2.3.0.exe\n");
    println!("Available placeholders (case-insensitive):");
    println!();
    println!("  Core:");
    println!("    {{Name}}, {{Arch}}");
    println!("  Version:");
    println!("    {{FileVer}}, {{ProductVer}}");
    println!("    {{FileVer1}}..{{FileVer4}}, {{ProductVer1}}..{{ProductVer4}}");
    println!("  String fields:");
    println!("    {{Description}}, {{Company}}, {{Copyright}}, {{Trademarks}}");
    println!("    {{Comments}}, {{InternalName}}, {{OriginalName}}");
    println!("    {{PrivateBuild}}, {{SpecialBuild}}");
    println!("  Fixed info:");
    println!("    {{FileType}}, {{FileSubtype}}, {{FileOS}}, {{Flags}}");
    println!();
    println!("  Legacy aliases still work: {{VER-1}}..{{VER-4}}, {{PVER-1}}..{{PVER-4}}, {{P}},");
    println!(
        "    {{TYPE}}, {{SUBTYPE}}, {{OS}}, {{INTERNAL}}, {{ORIGINAL}}, {{BUILD}}, {{SPECIAL}}"
    );
    println!();
    println!(
        "If the resulting file name exceeds {MAX_FILE_NAME_CHARS} characters, the default pattern is used;"
    );
    println!("if that is still too long, the original file name is kept.");
    println!();
    println!("Placeholders with no value for the given file type render as \u{FFFD}.");
}

/// Returns a `(file_path, pattern)` pair, accepting either `FILE [PATTERN]` or
/// `PATTERN FILE`. The order is disambiguated by checking whether the first
/// positional argument looks like an existing file (or ends with `.exe`).
fn parse_args(args: &[OsString]) -> Result<(OsString, String), String> {
    match args.len() {
        2 => Ok((args[1].clone(), DEFAULT_PATTERN.to_owned())),
        3 => {
            if looks_like_file(&args[1]) {
                Ok((args[1].clone(), pattern_from(&args[2])?))
            } else {
                Ok((args[2].clone(), pattern_from(&args[1])?))
            }
        }
        n => Err(format!(
            "unexpected number of arguments: {}",
            n.saturating_sub(1)
        )),
    }
}

fn pattern_from(arg: &OsString) -> Result<String, String> {
    let s = arg.to_string_lossy();
    if s.is_empty() {
        Err("pattern must not be empty".to_owned())
    } else {
        Ok(s.into_owned())
    }
}

fn looks_like_file(arg: &OsString) -> bool {
    Path::new(arg).is_file() || arg.to_string_lossy().to_ascii_lowercase().ends_with(".exe")
}

fn rename_with_version(file_path: &OsString, pattern: &str) -> Result<(), String> {
    let info = versioninfo::from_file(file_path).map_err(|e| {
        format!(
            "failed to read version info from '{}': {e}",
            file_path.to_string_lossy()
        )
    })?;

    let old_path = PathBuf::from(file_path);
    let file_name = old_path
        .file_name()
        .ok_or_else(|| format!("invalid file path '{}'", file_path.to_string_lossy()))?;
    let extension = old_path
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy()))
        .unwrap_or_default();

    let user_stem = sanitize_filename(&render_pattern(pattern, &info, file_name));
    if user_stem.is_empty() {
        return Err("pattern produced an empty file name".to_owned());
    }

    let user_name = append_extension(&user_stem, &extension);
    let default_stem = sanitize_filename(&render_pattern(DEFAULT_PATTERN, &info, file_name));
    let default_name = append_extension(&default_stem, &extension);
    let original_name = file_name.to_string_lossy();
    let (final_name, fallback) = choose_final_name(&user_name, &default_name, &original_name);
    match fallback {
        NameFallback::None => {}
        NameFallback::DefaultPattern => eprintln!(
            "Warning: file name from the given pattern is too long ({} chars, max {MAX_FILE_NAME_CHARS}); \
             falling back to the default pattern: {DEFAULT_PATTERN}",
            user_name.chars().count()
        ),
        NameFallback::OriginalName => eprintln!(
            "Warning: file name from the default pattern is also too long ({} chars, max {MAX_FILE_NAME_CHARS}); \
             keeping the original file name '{}'",
            default_name.chars().count(),
            original_name
        ),
    }

    let parent = old_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
    let target = parent.join(&final_name);

    if target.exists() {
        let same_file =
            std::fs::canonicalize(&target).ok() == std::fs::canonicalize(&old_path).ok();
        if same_file {
            println!("already named '{}'", target.display());
            return Ok(());
        }
        return Err(format!("target '{}' already exists", target.display()));
    }

    std::fs::rename(&old_path, &target).map_err(|e| format!("rename failed: {e}"))?;
    println!("'{}' -> '{}'", old_path.display(), target.display());
    Ok(())
}

fn append_extension(stem: &str, extension: &str) -> String {
    if !extension.is_empty()
        && stem
            .to_ascii_lowercase()
            .ends_with(&extension.to_ascii_lowercase())
    {
        stem.to_owned()
    } else {
        format!("{stem}{extension}")
    }
}

#[derive(Debug, PartialEq, Eq)]
enum NameFallback {
    None,
    DefaultPattern,
    OriginalName,
}

fn choose_final_name(
    user_name: &str,
    default_name: &str,
    original_name: &str,
) -> (String, NameFallback) {
    if user_name.chars().count() <= MAX_FILE_NAME_CHARS {
        (user_name.to_owned(), NameFallback::None)
    } else if default_name.chars().count() <= MAX_FILE_NAME_CHARS {
        (default_name.to_owned(), NameFallback::DefaultPattern)
    } else {
        (original_name.to_owned(), NameFallback::OriginalName)
    }
}

fn render_pattern(pattern: &str, info: &versioninfo::VersionInfo, original_name: &OsStr) -> String {
    let packer = |s: &OsString| s.to_string_lossy().into_owned();
    let product_name = packer(&info.product_name);
    let original_stem = Path::new(original_name)
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let name = if product_name.is_empty() {
        original_stem
    } else {
        product_name
    };
    let arch = info.arch.clone();
    let file_description = packer(&info.file_description);
    let company_name = packer(&info.company_name);
    let legal_copyright = packer(&info.legal_copyright);
    let legal_trademarks = packer(&info.legal_trademarks);
    let comments = packer(&info.comments);
    let internal_name = packer(&info.internal_name);
    let original_filename = packer(&info.original_filename);
    let private_build = packer(&info.private_build);
    let special_build = packer(&info.special_build);
    let product_version = packer(&info.product_version);
    let file_version = packer(&info.file_version);
    let (file_type, file_subtype, file_os, file_flags) = match &info.fixed {
        Some(f) => (
            f.file_type.clone(),
            f.file_subtype.clone(),
            f.file_os.clone(),
            f.file_flags.clone(),
        ),
        None => (String::new(), String::new(), String::new(), String::new()),
    };
    let ver_parts: [String; 4] = match &info.fixed {
        Some(f) => f.file_version.map(|n| n.to_string()),
        None => [1, 2, 3, 4].map(|n| version_part(&file_version, n)),
    };
    let pver_parts: [String; 4] = info
        .fixed
        .as_ref()
        .map(|f| f.product_version.map(|n| n.to_string()))
        .unwrap_or_default();
    let mut out = String::new();
    let mut rest = pattern;
    while let Some(start) = rest.find('{') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        if let Some(end) = after.find('}') {
            let token = after[..end].to_ascii_uppercase();
            let value = match token.as_str() {
                "NAME" => name.as_str(),
                "ARCH" => arch.as_str(),
                "FILEVER" => file_version.as_str(),
                "PRODUCTVER" | "PRODVER" | "P" => product_version.as_str(),
                "FILEVER1" | "VER-1" => ver_parts[0].as_str(),
                "FILEVER2" | "VER-2" => ver_parts[1].as_str(),
                "FILEVER3" | "VER-3" => ver_parts[2].as_str(),
                "FILEVER4" | "VER-4" => ver_parts[3].as_str(),
                "PRODUCTVER1" | "PVER-1" => pver_parts[0].as_str(),
                "PRODUCTVER2" | "PVER-2" => pver_parts[1].as_str(),
                "PRODUCTVER3" | "PVER-3" => pver_parts[2].as_str(),
                "PRODUCTVER4" | "PVER-4" => pver_parts[3].as_str(),
                "DESCRIPTION" | "FILEDESCRIPTION" => file_description.as_str(),
                "COMPANY" => company_name.as_str(),
                "COPYRIGHT" => legal_copyright.as_str(),
                "TRADEMARKS" => legal_trademarks.as_str(),
                "COMMENTS" => comments.as_str(),
                "INTERNALNAME" | "INTERNAL" => internal_name.as_str(),
                "ORIGINALNAME" | "ORIGINAL" => original_filename.as_str(),
                "PRIVATEBUILD" | "BUILD" => private_build.as_str(),
                "SPECIALBUILD" | "SPECIAL" => special_build.as_str(),
                "FILETYPE" | "TYPE" => file_type.as_str(),
                "FILESUBTYPE" | "SUBTYPE" => file_subtype.as_str(),
                "FILEOS" | "OS" => file_os.as_str(),
                "FLAGS" => file_flags.as_str(),
                _ => {
                    out.push('{');
                    out.push_str(&after[..end]);
                    out.push('}');
                    rest = &after[end + 1..];
                    continue;
                }
            };
            out.push_str(fill_missing(value));
            rest = &after[end + 1..];
        } else {
            out.push('{');
            out.push_str(after);
            rest = "";
        }
    }
    out.push_str(rest);
    out
}

fn version_part(version: &str, index: usize) -> String {
    version
        .split('.')
        .nth(index - 1)
        .unwrap_or("")
        .trim()
        .to_owned()
}

fn fill_missing(value: &str) -> &str {
    if value.is_empty() { "\u{FFFD}" } else { value }
}

/// Replaces characters that are invalid in Windows file names and rejects
/// reserved device names.
fn sanitize_filename(name: &str) -> String {
    let mut out: String = name
        .chars()
        .map(|c| {
            if c.is_control() || matches!(c, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*') {
                '_'
            } else {
                c
            }
        })
        .collect();
    while out.ends_with(['.', ' ']) {
        out.pop();
    }
    if out.is_empty() {
        return out;
    }

    let base = out.to_ascii_uppercase();
    let base = base.split('.').next().unwrap_or("");
    if RESERVED.contains(&base) {
        out.insert(0, '_');
    }
    out
}

const RESERVED: [&str; 22] = [
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_info() -> versioninfo::VersionInfo {
        versioninfo::VersionInfo {
            arch: "x64".to_owned(),
            product_name: OsString::from("Visual Studio Code"),
            file_description: OsString::from("Description"),
            company_name: OsString::from("ACME"),
            legal_copyright: OsString::from("(c)"),
            legal_trademarks: OsString::from("TM"),
            comments: OsString::from("Comments"),
            internal_name: OsString::from("Internal"),
            original_filename: OsString::from("orig.exe"),
            private_build: OsString::from("PB"),
            special_build: OsString::from("SB"),
            file_version: OsString::from("1.2.3.4"),
            product_version: OsString::from("1.2.3"),
            fixed: Some(versioninfo::FixedFileInfo {
                file_version: [1, 2, 3, 4],
                product_version: [5, 6, 7, 8],
                file_type: "Application".to_owned(),
                file_subtype: "Unknown".to_owned(),
                file_os: "WinNT32".to_owned(),
                file_flags: "debug,prerelease".to_owned(),
            }),
        }
    }

    #[test]
    fn renders_known_placeholders() {
        let info = sample_info();
        let out = render_pattern(
            "{Name}_{Arch}_{FileVer1}.{FileVer2}.{FileVer3}{FileVer4}-{ProductVer}",
            &info,
            OsStr::new("Code.exe"),
        );
        assert_eq!(out, "Visual Studio Code_x64_1.2.34-1.2.3");
    }

    #[test]
    fn placeholders_are_case_insensitive_and_unknown_are_kept() {
        let info = sample_info();
        let out = render_pattern(
            "{nAmE}-{aRcH}-{fIlEvEr1}-{UNKNOWN}",
            &info,
            OsStr::new("x.exe"),
        );
        assert_eq!(out, "Visual Studio Code-x64-1-{UNKNOWN}");
    }

    #[test]
    fn legacy_aliases_still_work() {
        let info = sample_info();
        let out = render_pattern("{VER-1}-{PVER-1}-{P}-{TYPE}", &info, OsStr::new("x.exe"));
        assert_eq!(out, "1-5-1.2.3-Application");
    }

    #[test]
    fn name_falls_back_to_original_stem() {
        let info = versioninfo::VersionInfo {
            arch: "x86".to_owned(),
            ..Default::default()
        };
        let out = render_pattern("{NAME}", &info, OsStr::new("myapp.exe"));
        assert_eq!(out, "myapp");
    }

    #[test]
    fn version_part_splits_on_dots() {
        assert_eq!(version_part("10.0.26100.8875", 1), "10");
        assert_eq!(version_part("10.0.26100.8875", 3), "26100");
        assert_eq!(version_part("10.0.26100.8875", 4), "8875");
        assert_eq!(version_part("10.0.26100.8875", 5), "");
    }

    #[test]
    fn renders_fixed_and_extra_placeholders() {
        let info = sample_info();
        let out = render_pattern(
            "{FileType}-{FileSubtype}-{FileOS}-{Flags}-{ProductVer1}.{ProductVer2}.{ProductVer3}.\
             {ProductVer4}-{FileVer}-{ProductVer}-{Description}-{Company}-{Copyright}-{Trademarks}-\
             {Comments}-{InternalName}-{OriginalName}-{PrivateBuild}-{SpecialBuild}",
            &info,
            OsStr::new("Code.exe"),
        );
        assert_eq!(
            out,
            "Application-Unknown-WinNT32-debug,prerelease-5.6.7.8-1.2.3.4-1.2.3-\
             Description-ACME-(c)-TM-Comments-Internal-orig.exe-PB-SB"
        );
    }

    #[test]
    fn ver_falls_back_to_string_when_no_fixed_info() {
        let info = versioninfo::VersionInfo {
            file_version: OsString::from("10.0.26100.8875 (extra)"),
            ..Default::default()
        };
        let out = render_pattern(
            "{FileVer1}.{FileVer2}.{FileVer3}.{FileVer4}",
            &info,
            OsStr::new("x.exe"),
        );
        assert_eq!(out, "10.0.26100.8875 (extra)");
    }

    #[test]
    fn missing_fields_render_replacement_char() {
        let info = versioninfo::VersionInfo {
            arch: "x64".to_owned(),
            product_name: OsString::from("App"),
            ..Default::default()
        };
        let out = render_pattern(
            "{Name}-{Comments}-{Copyright}-{FileVer}-{Flags}",
            &info,
            OsStr::new("x.exe"),
        );
        assert_eq!(out, "App-\u{FFFD}-\u{FFFD}-\u{FFFD}-\u{FFFD}");
    }

    #[test]
    fn sanitizes_invalid_filename_characters() {
        assert_eq!(
            sanitize_filename("a<b>:c\"d/e\\f|g?h*i"),
            "a_b__c_d_e_f_g_h_i"
        );
        assert_eq!(sanitize_filename("name. "), "name");
        assert_eq!(sanitize_filename("  "), "");
    }

    #[test]
    fn reserved_device_names_are_prefixed() {
        assert_eq!(sanitize_filename("CON"), "_CON");
        assert_eq!(sanitize_filename("com1"), "_com1");
        assert_eq!(sanitize_filename("CON.txt"), "_CON.txt");
    }

    #[test]
    fn name_within_limit_is_kept() {
        let (name, fallback) = choose_final_name("a.exe", "b.exe", "c.exe");
        assert_eq!(name, "a.exe");
        assert_eq!(fallback, NameFallback::None);
    }

    #[test]
    fn long_user_name_falls_back_to_default() {
        let long = "x".repeat(MAX_FILE_NAME_CHARS + 1);
        let (name, fallback) = choose_final_name(&long, "default.exe", "orig.exe");
        assert_eq!(name, "default.exe");
        assert_eq!(fallback, NameFallback::DefaultPattern);
    }

    #[test]
    fn long_default_falls_back_to_original() {
        let long = "x".repeat(MAX_FILE_NAME_CHARS + 1);
        let (name, fallback) = choose_final_name(&long, &long, "orig.exe");
        assert_eq!(name, "orig.exe");
        assert_eq!(fallback, NameFallback::OriginalName);
    }

    #[test]
    fn extension_is_not_duplicated() {
        assert_eq!(append_extension("App.EXE", ".exe"), "App.EXE");
        assert_eq!(append_extension("App", ".exe"), "App.exe");
        assert_eq!(append_extension("App", ""), "App");
    }
}
