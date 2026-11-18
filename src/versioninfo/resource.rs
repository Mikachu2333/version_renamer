use super::{
    FixedFileInfo, VersionInfo, file_flags_name, file_os_name, file_subtype_name, file_type_name,
    split_version,
};
use windows::Win32::Storage::FileSystem::VS_FIXEDFILEINFO_FILE_FLAGS;

struct Block<'a> {
    key: String,
    value_length: usize,
    body: &'a [u8],
}

fn words(bytes: &[u8]) -> impl Iterator<Item = u16> + '_ {
    bytes
        .as_chunks::<2>()
        .0
        .iter()
        .copied()
        .map(u16::from_le_bytes)
}

fn blocks(mut bytes: &[u8]) -> impl Iterator<Item = Block<'_>> {
    std::iter::from_fn(move || {
        let length = usize::from(words(bytes).next()?);
        if length < 6 {
            return None;
        }
        let block = bytes.get(..length)?;
        bytes = bytes.get(length.next_multiple_of(4)..).unwrap_or_default();
        Some(block)
    })
    .filter_map(|block| {
        let key_length = words(&block[6..]).position(|word| word == 0)?;
        let key = words(&block[6..]).take(key_length).collect::<Vec<_>>();
        let body_start = (8 + 2 * key_length).next_multiple_of(4);
        Some(Block {
            key: String::from_utf16_lossy(&key),
            value_length: usize::from(u16::from_le_bytes([block[2], block[3]])),
            body: block.get(body_start..).unwrap_or_default(),
        })
    })
}

impl<'a> Block<'a> {
    fn children(&self) -> impl Iterator<Item = Block<'a>> {
        blocks(
            self.body
                .get(self.value_length.next_multiple_of(4)..)
                .unwrap_or_default(),
        )
    }

    fn binary_value(&self) -> &'a [u8] {
        self.body.get(..self.value_length).unwrap_or_default()
    }

    fn text(&self) -> String {
        let value = &self.body[..self.body.len().min(self.value_length * 2)];
        let units = words(value)
            .take_while(|&word| word != 0)
            .collect::<Vec<_>>();
        String::from_utf16_lossy(&units).trim().to_owned()
    }
}

fn fixed_info(value: &[u8]) -> Option<FixedFileInfo> {
    let fields = value
        .as_chunks::<4>()
        .0
        .first_chunk::<13>()?
        .map(u32::from_le_bytes);
    let [
        signature,
        _,
        file_major_minor,
        file_build_revision,
        product_major_minor,
        product_build_revision,
        mask,
        flags,
        os,
        kind,
        subtype,
        _,
        _,
    ] = fields;
    (signature == 0xFEEF_04BD).then(|| FixedFileInfo {
        file_version: split_version(file_major_minor, file_build_revision),
        product_version: split_version(product_major_minor, product_build_revision),
        file_type: file_type_name(kind).to_owned(),
        file_subtype: file_subtype_name(kind, subtype),
        file_os: file_os_name(os).to_owned(),
        file_flags: file_flags_name(VS_FIXEDFILEINFO_FILE_FLAGS(flags & mask)),
    })
}

fn fill_strings(table: &Block<'_>, info: &mut VersionInfo) {
    for field in table.children() {
        let slot = match field.key.to_ascii_lowercase().as_str() {
            "productname" => &mut info.product_name,
            "internalname" => &mut info.internal_name,
            "originalfilename" => &mut info.original_filename,
            "fileversion" => &mut info.file_version,
            "productversion" => &mut info.product_version,
            "companyname" => &mut info.company_name,
            "legalcopyright" => &mut info.legal_copyright,
            "legaltrademarks" => &mut info.legal_trademarks,
            "filedescription" => &mut info.file_description,
            "comments" => &mut info.comments,
            "privatebuild" => &mut info.private_build,
            "specialbuild" => &mut info.special_build,
            _ => continue,
        };
        if slot.is_empty() {
            *slot = field.text().into();
        }
    }
}

pub(super) fn read(bytes: &[u8], info: &mut VersionInfo) -> Option<()> {
    let root = blocks(bytes)
        .next()
        .filter(|block| block.key == "VS_VERSION_INFO")?;
    info.fixed = fixed_info(root.binary_value());
    let mut declared = Vec::new();
    let mut tables = Vec::new();
    for group in root.children() {
        if group.key.eq_ignore_ascii_case("VarFileInfo") {
            for translation in group
                .children()
                .filter(|block| block.key.eq_ignore_ascii_case("Translation"))
            {
                declared.extend(
                    translation
                        .binary_value()
                        .as_chunks::<4>()
                        .0
                        .iter()
                        .map(|pair| {
                            u32::from(u16::from_le_bytes([pair[0], pair[1]])) << 16
                                | u32::from(u16::from_le_bytes([pair[2], pair[3]]))
                        }),
                );
            }
        } else if group.key.eq_ignore_ascii_case("StringFileInfo") {
            for table in group.children() {
                if table.key.len() == 8
                    && table.key.bytes().all(|byte| byte.is_ascii_hexdigit())
                    && let Ok(id) = u32::from_str_radix(&table.key, 16)
                {
                    tables.push((id, table));
                }
            }
        }
    }
    tables.sort_by_cached_key(|&(id, _)| {
        if let Some(index) = declared.iter().position(|&entry| entry == id) {
            (0, index)
        } else if let Some(index) = declared.iter().position(|entry| entry >> 16 == id >> 16) {
            (1, index)
        } else {
            (2, 0)
        }
    });
    for (_, table) in tables {
        fill_strings(&table, info);
    }
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block(key: &str, is_text: bool, value: &[u8], children: &[Vec<u8>]) -> Vec<u8> {
        let value_length = if is_text {
            value.len() / 2
        } else {
            value.len()
        };
        let mut bytes = vec![0, 0];
        bytes.extend(u16::try_from(value_length).unwrap().to_le_bytes());
        bytes.extend(u16::from(is_text).to_le_bytes());
        bytes.extend(key.encode_utf16().chain([0]).flat_map(u16::to_le_bytes));
        bytes.resize(bytes.len().next_multiple_of(4), 0);
        bytes.extend(value);
        for child in children {
            bytes.resize(bytes.len().next_multiple_of(4), 0);
            bytes.extend(child);
        }
        let length = u16::try_from(bytes.len()).unwrap();
        bytes[..2].copy_from_slice(&length.to_le_bytes());
        bytes
    }

    fn string(key: &str, text: &str) -> Vec<u8> {
        let value = text
            .encode_utf16()
            .chain([0])
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        block(key, true, &value, &[])
    }

    fn strings(tables: &[Vec<u8>], translation: Option<[u8; 4]>) -> VersionInfo {
        let mut groups = vec![block("StringFileInfo", true, &[], tables)];
        if let Some(pair) = translation {
            let translation = block("Translation", false, &pair, &[]);
            groups.push(block("VarFileInfo", true, &[], &[translation]));
        }
        let root = block("VS_VERSION_INFO", false, &[], &groups);
        let mut info = VersionInfo::default();
        read(&root, &mut info).unwrap();
        info
    }

    #[test]
    fn wrong_code_page_prefers_the_actual_table_in_the_declared_language() {
        let other = block("041104B0", true, &[], &[string("ProductName", "other")]);
        let actual = block(
            "040904E4",
            true,
            &[],
            &[
                string("ProductName", "killall"),
                string("FileVersion", "1.4.0.0"),
            ],
        );
        let info = strings(&[other, actual], Some([0x09, 0x04, 0xB0, 0x04]));
        assert_eq!(info.product_name, "killall");
        assert_eq!(info.file_version, "1.4.0.0");
    }

    #[test]
    fn declared_table_wins_and_fallback_tables_only_fill_empty_fields() {
        let other = block(
            "040904E4",
            true,
            &[],
            &[
                string("ProductName", "other"),
                string("CompanyName", "ACME"),
            ],
        );
        let declared = block(
            "040904b0",
            true,
            &[],
            &[
                string("ProductName", "preferred"),
                string("CompanyName", " "),
            ],
        );
        let info = strings(&[other, declared], Some([0x09, 0x04, 0xB0, 0x04]));
        assert_eq!(info.product_name, "preferred");
        assert_eq!(info.company_name, "ACME");
    }

    #[test]
    fn absent_translation_uses_the_actual_non_english_table() {
        let table = block("080403A8", true, &[], &[string("ProductName", "应用🚀")]);
        assert_eq!(strings(&[table], None).product_name, "应用🚀");
    }

    #[test]
    fn oversized_string_length_cannot_consume_the_next_field() {
        let mut field = block("ProductName", true, &65u16.to_le_bytes(), &[]);
        field[2..4].copy_from_slice(&u16::MAX.to_le_bytes());
        let table = block("040904E4", true, &[], &[field, string("FileVersion", "7")]);
        let info = strings(&[table], None);
        assert_eq!(info.product_name, "A");
        assert_eq!(info.file_version, "7");
    }

    #[test]
    fn fixed_resource_requires_a_complete_value_and_valid_signature() {
        let fields: [u32; 13] = [
            0xFEEF_04BD,
            0x10000,
            0x10004,
            0,
            0x20003,
            0x40005,
            0,
            1,
            0,
            1,
            0,
            0,
            0,
        ];
        let mut value: Vec<_> = fields.into_iter().flat_map(u32::to_le_bytes).collect();
        let root = block("VS_VERSION_INFO", false, &value, &[]);
        let mut info = VersionInfo::default();
        read(&root, &mut info).unwrap();
        let fixed = info.fixed.unwrap();
        assert_eq!(fixed.file_version, [1, 4, 0, 0]);
        assert_eq!(fixed.product_version, [2, 3, 4, 5]);
        assert_eq!(fixed.file_flags, "");
        assert!(fixed_info(&value[..51]).is_none());
        value[0] = 0;
        assert!(fixed_info(&value).is_none());
    }
}
