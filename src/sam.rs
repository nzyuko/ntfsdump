use std::collections::HashMap;
use std::path::Path;

use anyhow::Context;
use regf::RegistryHive;

const SAM_USERS_PATH: &str = r"Domains\Account\Users";
const SAM_NAMES_PATH: &str = r"Domains\Account\Users\Names";
const USER_V_DATA_BASE: usize = 0xCC;

#[derive(Debug, Clone)]
struct SamAccount {
    rid: u32,
    username: String,
    v_len: usize,
    f_len: usize,
    lm_present: bool,
    nt_present: bool,
}

pub fn parse_sam_report(path: &Path) -> anyhow::Result<String> {
    let accounts = parse_sam_accounts(path)?;

    let mut out = String::new();
    out.push_str(&format!(
        "[+] Parsed {} local account{}\n",
        accounts.len(),
        if accounts.len() == 1 { "" } else { "s" }
    ));
    out.push_str("RID        Username                         LM          NT          Records\n");
    out.push_str("--------   ------------------------------   ---------   ---------   -------\n");

    for account in accounts {
        out.push_str(&format!(
            "0x{rid:08X} {username:<30}   {lm:<9}   {nt:<9}   V={v_len} F={f_len}\n",
            rid = account.rid,
            username = truncate_for_table(&account.username, 30),
            lm = redacted_state(account.lm_present),
            nt = redacted_state(account.nt_present),
            v_len = account.v_len,
            f_len = account.f_len,
        ));
    }

    Ok(out.trim_end().to_string())
}

fn parse_sam_accounts(path: &Path) -> anyhow::Result<Vec<SamAccount>> {
    let hive = RegistryHive::from_file(path)
        .with_context(|| format!("loading SAM hive {}", path.display()))?;
    let rid_names = rid_name_map(&hive);
    let users = hive
        .open_key(SAM_USERS_PATH)
        .context("opening SAM users key")?;

    let mut accounts = Vec::new();

    for key in users.subkeys().context("enumerating SAM user keys")? {
        let key_name = key.name();
        if key_name.eq_ignore_ascii_case("Names") || key_name.len() != 8 {
            continue;
        }

        let rid = match u32::from_str_radix(&key_name, 16) {
            Ok(rid) => rid,
            Err(_) => continue,
        };

        let v = key
            .value("V")
            .context("reading SAM user V record")?
            .raw_data()
            .context("reading SAM user V bytes")?;
        let f = key
            .value("F")
            .context("reading SAM user F record")?
            .raw_data()
            .context("reading SAM user F bytes")?;

        let username = parse_username_from_v(&v)
            .or_else(|| rid_names.get(&rid).cloned())
            .unwrap_or_else(|| format!("RID-{:08X}", rid));
        let (lm_present, nt_present) = password_material_state(&v);

        accounts.push(SamAccount {
            rid,
            username,
            v_len: v.len(),
            f_len: f.len(),
            lm_present,
            nt_present,
        });
    }

    accounts.sort_by_key(|account| account.rid);
    Ok(accounts)
}

fn rid_name_map(hive: &RegistryHive) -> HashMap<u32, String> {
    let mut names = HashMap::new();

    let Ok(names_key) = hive.open_key(SAM_NAMES_PATH) else {
        return names;
    };

    let Ok(subkeys) = names_key.subkeys() else {
        return names;
    };

    for key in subkeys {
        if let Ok(value) = key.default_value() {
            names.insert(value.raw_data_type(), key.name());
        }
    }

    names
}

fn parse_username_from_v(v: &[u8]) -> Option<String> {
    let offset = read_u32(v, 0x0c)? as usize + USER_V_DATA_BASE;
    let len = read_u32(v, 0x10)? as usize;
    decode_utf16le(v.get(offset..offset.checked_add(len)?)?)
}

fn password_material_state(v: &[u8]) -> (bool, bool) {
    let lm = record_data_present(v, 0x9c, 0xa0);
    let nt = record_data_present(v, 0xa8, 0xac);
    (lm, nt)
}

fn record_data_present(v: &[u8], offset_field: usize, length_field: usize) -> bool {
    let Some(offset) = read_u32(v, offset_field).map(|value| value as usize + USER_V_DATA_BASE)
    else {
        return false;
    };
    let Some(len) = read_u32(v, length_field).map(|value| value as usize) else {
        return false;
    };

    len > 0 && offset.checked_add(len).is_some_and(|end| end <= v.len())
}

fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    let bytes: [u8; 4] = data.get(offset..offset + 4)?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

fn decode_utf16le(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() || bytes.len() % 2 != 0 {
        return None;
    }

    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect();
    String::from_utf16(&units)
        .ok()
        .filter(|value| !value.is_empty())
}

fn redacted_state(present: bool) -> &'static str {
    if present {
        "[redacted]"
    } else {
        "-"
    }
}

fn truncate_for_table(value: &str, width: usize) -> String {
    let mut out = String::new();
    for ch in value.chars().take(width) {
        out.push(ch);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use regf::{DataType, HiveBuilder};

    #[test]
    fn parses_username_from_v_record() {
        let name: Vec<u8> = "alice"
            .encode_utf16()
            .flat_map(|unit| unit.to_le_bytes())
            .collect();
        let mut v = vec![0u8; USER_V_DATA_BASE + name.len()];
        v[0x0c..0x10].copy_from_slice(&0u32.to_le_bytes());
        v[0x10..0x14].copy_from_slice(&(name.len() as u32).to_le_bytes());
        v[USER_V_DATA_BASE..USER_V_DATA_BASE + name.len()].copy_from_slice(&name);

        assert_eq!(parse_username_from_v(&v).as_deref(), Some("alice"));
    }

    #[test]
    fn detects_redacted_password_material() {
        let mut v = vec![0u8; USER_V_DATA_BASE + 16];
        v[0xa8..0xac].copy_from_slice(&0u32.to_le_bytes());
        v[0xac..0xb0].copy_from_slice(&16u32.to_le_bytes());

        assert_eq!(password_material_state(&v), (false, true));
    }

    #[test]
    fn parses_accounts_from_sam_hive() -> anyhow::Result<()> {
        let path =
            std::env::temp_dir().join(format!("ntfsdump-sam-test-{}.hive", std::process::id()));
        write_sample_sam_hive(&path)?;

        let accounts = parse_sam_accounts(&path)?;
        std::fs::remove_file(&path).ok();

        assert_eq!(accounts.len(), 2);
        assert_eq!(accounts[0].rid, 0x1f4);
        assert_eq!(accounts[0].username, "Administrator");
        assert!(accounts[0].nt_present);
        assert_eq!(accounts[1].rid, 0x3e9);
        assert_eq!(accounts[1].username, "local.user");

        Ok(())
    }

    fn write_sample_sam_hive(path: &Path) -> anyhow::Result<()> {
        let mut builder = HiveBuilder::new();
        let root = builder.root_offset();
        let domains = builder.add_key(root, "Domains")?;
        let account = builder.add_key(domains, "Account")?;
        let users = builder.add_key(account, "Users")?;
        let names = builder.add_key(users, "Names")?;

        add_account(&mut builder, users, names, 0x1f4, "Administrator", true)?;
        add_account(&mut builder, users, names, 0x3e9, "local.user", true)?;

        builder.write_to_file(path)?;
        Ok(())
    }

    fn add_account(
        builder: &mut HiveBuilder,
        users: u32,
        names: u32,
        rid: u32,
        username: &str,
        nt_present: bool,
    ) -> anyhow::Result<()> {
        let account = builder.add_key(users, &format!("{rid:08X}"))?;
        builder.add_value(
            account,
            "V",
            DataType::Binary,
            &sample_v(username, nt_present),
        )?;
        builder.add_value(account, "F", DataType::Binary, &[0u8; 80])?;

        let name = builder.add_key(names, username)?;
        builder.add_value(name, "", DataType::Unknown(rid), &[])?;
        Ok(())
    }

    fn sample_v(username: &str, nt_present: bool) -> Vec<u8> {
        let name: Vec<u8> = username
            .encode_utf16()
            .flat_map(|unit| unit.to_le_bytes())
            .collect();
        let nt_offset = name.len();
        let nt_len = if nt_present { 16 } else { 0 };

        let mut v = vec![0u8; USER_V_DATA_BASE + name.len() + nt_len];
        v[0x0c..0x10].copy_from_slice(&0u32.to_le_bytes());
        v[0x10..0x14].copy_from_slice(&(name.len() as u32).to_le_bytes());
        v[USER_V_DATA_BASE..USER_V_DATA_BASE + name.len()].copy_from_slice(&name);

        v[0xa8..0xac].copy_from_slice(&(nt_offset as u32).to_le_bytes());
        v[0xac..0xb0].copy_from_slice(&(nt_len as u32).to_le_bytes());
        if nt_present {
            let start = USER_V_DATA_BASE + nt_offset;
            v[start..start + nt_len].fill(0xAA);
        }

        v
    }
}
