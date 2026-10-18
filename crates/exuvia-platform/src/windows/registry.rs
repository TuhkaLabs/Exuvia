use std::os::windows::process::CommandExt;
use std::path::Path;
use std::process::Command;

use exuvia_core::safety::normalize_registry_key;
use exuvia_core::{ExuviaError, Result};
use winreg::enums::*;
use winreg::{RegKey, HKEY};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Hive {
    CurrentUser,
    LocalMachine,
    ClassesRoot,
    Users,
    CurrentConfig,
}

impl Hive {
    fn predef(self) -> HKEY {
        match self {
            Self::CurrentUser => HKEY_CURRENT_USER,
            Self::LocalMachine => HKEY_LOCAL_MACHINE,
            Self::ClassesRoot => HKEY_CLASSES_ROOT,
            Self::Users => HKEY_USERS,
            Self::CurrentConfig => HKEY_CURRENT_CONFIG,
        }
    }
}

fn split_key(path: &str) -> Option<(Hive, String)> {
    let normalized = normalize_registry_key(path)?;
    let (hive, rest) = match normalized.split_once('\\') {
        Some((hive, rest)) => (hive, rest.to_string()),
        None => (normalized.as_str(), String::new()),
    };
    let hive = match hive {
        "HKCU" => Hive::CurrentUser,
        "HKLM" => Hive::LocalMachine,
        "HKCR" => Hive::ClassesRoot,
        "HKU" => Hive::Users,
        "HKCC" => Hive::CurrentConfig,
        _ => return None,
    };
    Some((hive, rest))
}

pub fn open_key_read(path: &str) -> std::io::Result<RegKey> {
    let (hive, rest) = split_key(path).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid registry path")
    })?;
    let root = RegKey::predef(hive.predef());
    if rest.is_empty() {
        Ok(root)
    } else {
        root.open_subkey_with_flags(rest, KEY_READ)
    }
}

pub fn key_exists(path: &str) -> bool {
    open_key_read(path).is_ok()
}

pub fn read_string(key: &RegKey, name: &str) -> Option<String> {
    key.get_value::<String, _>(name).ok()
}

pub fn read_dword(key: &RegKey, name: &str) -> Option<u32> {
    key.get_value::<u32, _>(name).ok()
}

pub fn value_count(path: &str) -> Option<usize> {
    let key = open_key_read(path).ok()?;
    Some(key.enum_values().filter_map(|value| value.ok()).count())
}

pub fn export_registry_key(key: &str, destination: &Path) -> Result<()> {
    if let Some(parent) = destination.parent() {
        std::fs::create_dir_all(parent).map_err(|error| {
            ExuviaError::io("failed to create registry backup directory", error)
        })?;
    }
    let status = Command::new("reg")
        .arg("export")
        .arg(key)
        .arg(destination)
        .arg("/y")
        .creation_flags(CREATE_NO_WINDOW)
        .status()
        .map_err(|error| ExuviaError::io("failed to start reg.exe export", error))?;

    if !status.success() || !destination.exists() {
        return Err(ExuviaError::Other(format!(
            "reg.exe export failed for {key} (exit code {:?})",
            status.code()
        )));
    }
    Ok(())
}

pub fn import_registry_file(file: &Path) -> Result<()> {
    if !file.exists() {
        return Err(ExuviaError::Other(format!(
            "registry backup {} does not exist",
            file.display()
        )));
    }
    let status = Command::new("reg")
        .arg("import")
        .arg(file)
        .creation_flags(CREATE_NO_WINDOW)
        .status()
        .map_err(|error| ExuviaError::io("failed to start reg.exe import", error))?;

    if !status.success() {
        return Err(ExuviaError::Other(format!(
            "reg.exe import failed for {} (exit code {:?})",
            file.display(),
            status.code()
        )));
    }
    Ok(())
}

pub fn delete_registry_key(key: &str) -> Result<()> {
    let (hive, rest) = split_key(key)
        .ok_or_else(|| ExuviaError::Safety(format!("invalid registry path: {key}")))?;
    if rest.is_empty() {
        return Err(ExuviaError::Safety(format!(
            "refusing to delete registry hive root {key}"
        )));
    }

    let (parent_path, leaf) = match rest.rsplit_once('\\') {
        Some((parent, leaf)) => (parent, leaf),
        None => ("", rest.as_str()),
    };

    let root = RegKey::predef(hive.predef());
    let parent = if parent_path.is_empty() {
        root
    } else {
        root.open_subkey_with_flags(parent_path, KEY_ALL_ACCESS)
            .map_err(|error| ExuviaError::io(format!("failed to open {parent_path}"), error))?
    };

    parent
        .delete_subkey_all(leaf)
        .map_err(|error| ExuviaError::io(format!("failed to delete registry key {key}"), error))
}
