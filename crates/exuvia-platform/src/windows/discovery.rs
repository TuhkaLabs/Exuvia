use std::collections::HashMap;
use std::path::PathBuf;

use exuvia_core::{AppSource, Architecture, InstalledApp, UninstallInfo};
use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
use winreg::{RegKey, HKEY};

use crate::windows::registry::{read_dword, read_string};
use crate::DiscoveryResult;

const UNINSTALL_SUFFIX: &str = r"Microsoft\Windows\CurrentVersion\Uninstall";

struct UninstallRoot {
    hive: HKEY,
    path: String,
    tag: &'static str,
    architecture: Architecture,
}

pub fn discover() -> DiscoveryResult {
    let mut result = DiscoveryResult::default();

    let roots = [
        UninstallRoot {
            hive: HKEY_LOCAL_MACHINE,
            path: format!(r"SOFTWARE\{UNINSTALL_SUFFIX}"),
            tag: "hklm64",
            architecture: view_architecture(),
        },
        UninstallRoot {
            hive: HKEY_LOCAL_MACHINE,
            path: format!(r"SOFTWARE\WOW6432Node\{UNINSTALL_SUFFIX}"),
            tag: "hklm32",
            architecture: Architecture::X86,
        },
        UninstallRoot {
            hive: HKEY_CURRENT_USER,
            path: format!(r"SOFTWARE\{UNINSTALL_SUFFIX}"),
            tag: "hkcu",
            architecture: view_architecture(),
        },
    ];

    for root in roots {
        let hklm = RegKey::predef(root.hive);
        let uninstall_key = match hklm.open_subkey_with_flags(&root.path, winreg::enums::KEY_READ) {
            Ok(key) => key,
            Err(error) => {
                if error.kind() != std::io::ErrorKind::NotFound {
                    result.warnings.push(format!(
                        "could not read {} uninstall entries: {error}",
                        root.tag
                    ));
                }
                continue;
            }
        };

        for subkey_name in uninstall_key.enum_keys().flatten() {
            let Ok(subkey) =
                uninstall_key.open_subkey_with_flags(&subkey_name, winreg::enums::KEY_READ)
            else {
                continue;
            };
            if should_skip(&subkey) {
                continue;
            }
            if let Some(app) = build_app(&subkey, &subkey_name, &root) {
                result.apps.push(app);
            }
        }
    }

    deduplicate(&mut result.apps);
    result.apps.sort_by_key(|app| app.name.to_lowercase());
    result
}

fn should_skip(key: &RegKey) -> bool {
    if read_dword(key, "SystemComponent") == Some(1) {
        return true;
    }
    if read_string(key, "ParentKeyName").is_some() {
        return true;
    }
    if let Some(release_type) = read_string(key, "ReleaseType") {
        let release_type = release_type.to_ascii_lowercase();
        if matches!(
            release_type.as_str(),
            "update" | "hotfix" | "security update" | "servicepack" | "service pack"
        ) {
            return true;
        }
    }
    match read_string(key, "DisplayName") {
        Some(name) => name.trim().is_empty(),
        None => true,
    }
}

fn build_app(key: &RegKey, subkey_name: &str, root: &UninstallRoot) -> Option<InstalledApp> {
    let name = read_string(key, "DisplayName")?.trim().to_string();
    let windows_installer = read_dword(key, "WindowsInstaller") == Some(1);
    let product_code = if windows_installer && is_product_code(subkey_name) {
        Some(subkey_name.to_string())
    } else {
        None
    };

    let install_location = read_string(key, "InstallLocation")
        .map(|value| value.trim().trim_matches('"').to_string())
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(|| infer_install_location(key));

    let size_bytes = read_dword(key, "EstimatedSize").map(|kb| u64::from(kb) * 1024);

    Some(InstalledApp {
        id: format!("registry:{}:{}", root.tag, subkey_name.to_lowercase()),
        name,
        version: read_string(key, "DisplayVersion")
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty()),
        publisher: read_string(key, "Publisher")
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty()),
        size_bytes,
        install_date: read_string(key, "InstallDate").and_then(format_install_date),
        source: if windows_installer {
            AppSource::Msi
        } else {
            AppSource::Registry
        },
        architecture: root.architecture,
        product_code,
        uninstall: UninstallInfo {
            uninstall_string: read_string(key, "UninstallString"),
            quiet_uninstall_string: read_string(key, "QuietUninstallString"),
            install_location,
        },
    })
}

fn infer_install_location(key: &RegKey) -> Option<PathBuf> {
    let icon = read_string(key, "DisplayIcon")?;
    let icon = icon.trim().trim_matches('"');
    let path = icon
        .split(',')
        .next()
        .unwrap_or(icon)
        .trim()
        .trim_matches('"');
    if path.is_empty() {
        return None;
    }
    let path = PathBuf::from(path);
    if path.extension().is_some() {
        path.parent().map(PathBuf::from)
    } else {
        Some(path)
    }
}

fn format_install_date(value: String) -> Option<String> {
    let value = value.trim();
    if value.len() == 8 && value.chars().all(|ch| ch.is_ascii_digit()) {
        Some(format!(
            "{}-{}-{}",
            &value[0..4],
            &value[4..6],
            &value[6..8]
        ))
    } else if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

fn is_product_code(value: &str) -> bool {
    let value = value.trim();
    value.starts_with('{')
        && value.ends_with('}')
        && value.len() == 38
        && value.chars().filter(|ch| *ch == '-').count() == 4
}

fn deduplicate(apps: &mut Vec<InstalledApp>) {
    let mut seen: HashMap<(String, Option<String>, Option<PathBuf>), usize> = HashMap::new();
    let mut index = 0;
    while index < apps.len() {
        let key = (
            apps[index].name.to_lowercase(),
            apps[index].version.clone(),
            apps[index].uninstall.install_location.clone(),
        );
        if let std::collections::hash_map::Entry::Vacant(entry) = seen.entry(key) {
            entry.insert(index);
            index += 1;
        } else {
            apps.remove(index);
        }
    }
}

fn view_architecture() -> Architecture {
    #[cfg(target_arch = "aarch64")]
    {
        Architecture::Arm64
    }
    #[cfg(target_arch = "x86_64")]
    {
        Architecture::X64
    }
    #[cfg(target_arch = "x86")]
    {
        Architecture::X86
    }
    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64", target_arch = "x86")))]
    {
        Architecture::Unknown
    }
}
