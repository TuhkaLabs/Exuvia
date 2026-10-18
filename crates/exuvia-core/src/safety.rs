use std::fmt;
use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::error::ExuviaError;
use crate::model::{ResidueItem, ResidueKind};
use crate::path::{expand_env, home_dir, is_within, normalize_path_key, resolve_path};

/// Where a validated target points.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SafetyTarget {
    Path(PathBuf),
    Registry(String),
    Object(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{target} is protected ({reason})")]
pub struct SafetyViolation {
    pub target: String,
    pub reason: String,
}

impl From<SafetyViolation> for ExuviaError {
    fn from(violation: SafetyViolation) -> Self {
        Self::Safety(violation.to_string())
    }
}

/// Hard-coded and rule-based denylist from FR-16.
///
/// Paths in `protected_roots` are refused recursively; paths in `protected_exact`
/// are refused only when they are the target itself (their children remain
/// eligible, which is required for locations such as `%APPDATA%`).
#[derive(Debug, Clone, Default)]
pub struct SafetyPolicy {
    protected_roots: Vec<PathBuf>,
    protected_exact: Vec<PathBuf>,
    protected_registry_prefixes: Vec<String>,
    protected_registry_exact: Vec<String>,
}

impl SafetyPolicy {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn for_current_platform() -> Self {
        #[cfg(windows)]
        {
            Self::windows_defaults()
        }
        #[cfg(not(windows))]
        {
            Self::unix_defaults()
        }
    }

    #[cfg(windows)]
    pub fn windows_defaults() -> Self {
        let mut policy = Self::empty();

        let windows = env_path("SystemRoot").unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
        policy.add_protected_root(windows.clone());
        policy.add_protected_root(windows.join("System32"));
        policy.add_protected_root(windows.join("SysWOW64"));
        policy.add_protected_root(windows.join("WinSxS"));

        for variable in ["ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"] {
            if let Some(root) = env_path(variable) {
                policy.add_protected_exact(root.clone());
                policy.add_protected_root(root.join("WindowsApps"));
                policy.add_protected_root(root.join("Common Files"));
                policy.add_protected_root(root.join("Windows Defender"));
            }
        }
        for variable in ["CommonProgramFiles", "CommonProgramFiles(x86)"] {
            if let Some(root) = env_path(variable) {
                policy.add_protected_root(root);
            }
        }

        let profile = home_dir();
        policy.add_protected_exact(profile.clone());
        for name in [
            "Documents",
            "Desktop",
            "Downloads",
            "Pictures",
            "Videos",
            "Music",
            "OneDrive",
            "Saved Games",
            "Favorites",
            "Contacts",
            "Links",
            "Searches",
            "3D Objects",
        ] {
            policy.add_protected_root(profile.join(name));
        }

        let app_data = profile.join("AppData");
        policy.add_protected_exact(app_data.clone());
        policy.add_protected_exact(app_data.join("Local"));
        policy.add_protected_exact(app_data.join("LocalLow"));
        policy.add_protected_exact(app_data.join("Roaming"));
        policy.add_protected_exact(app_data.join("Local").join("Packages"));
        policy.add_protected_exact(app_data.join("Local").join("Programs"));
        policy.add_protected_exact(app_data.join("Local").join("Temp"));
        // Start Menu shortcuts live under Microsoft\Windows\Start Menu, so only
        // the well-known system caches beneath Microsoft are protected recursively.
        policy.add_protected_exact(app_data.join("Local").join("Microsoft"));
        policy.add_protected_exact(app_data.join("Roaming").join("Microsoft"));
        policy.add_protected_root(app_data.join("Local").join("Microsoft").join("Windows"));
        policy.add_protected_root(app_data.join("Local").join("Microsoft").join("WindowsApps"));
        policy.add_protected_root(app_data.join("Local").join("Microsoft").join("OneDrive"));

        if let Some(program_data) = env_path("ProgramData") {
            policy.add_protected_exact(program_data.clone());
            policy.add_protected_exact(program_data.join("Microsoft"));
            policy.add_protected_root(program_data.join("Microsoft").join("Windows Defender"));
        }
        if let Some(public) = env_path("PUBLIC") {
            policy.add_protected_exact(public);
        }

        for drive_letter in 'A'..='Z' {
            let drive = PathBuf::from(format!("{drive_letter}:\\"));
            if drive.exists() {
                policy.add_protected_exact(drive.clone());
                policy.add_protected_root(drive.join("$Recycle.Bin"));
                policy.add_protected_root(drive.join("System Volume Information"));
            }
        }
        policy.add_protected_exact(PathBuf::from(r"C:\pagefile.sys"));
        policy.add_protected_exact(PathBuf::from(r"C:\hiberfil.sys"));
        policy.add_protected_exact(PathBuf::from(r"C:\swapfile.sys"));

        // Never let Exuvia quarantine its own database or manifests.
        if let Some(local) = std::env::var_os("LOCALAPPDATA") {
            policy.add_protected_root(PathBuf::from(local).join("Exuvia"));
        }
        policy.add_protected_root(profile.join(".exuvia"));

        policy.add_protected_registry_prefix(r"HKLM\SYSTEM");
        policy.add_protected_registry_prefix(r"HKLM\SAM");
        policy.add_protected_registry_prefix(r"HKLM\SECURITY");
        policy.add_protected_registry_prefix(r"HKLM\SOFTWARE\Microsoft\Windows");
        policy.add_protected_registry_prefix(r"HKLM\SOFTWARE\Microsoft\Windows NT");
        policy.add_protected_registry_prefix(r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows");
        policy.add_protected_registry_prefix(r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT");
        policy.add_protected_registry_prefix(r"HKCU\SOFTWARE\Microsoft\Windows");
        policy.add_protected_registry_prefix(r"HKCU\SOFTWARE\Microsoft\Windows NT");
        policy.add_protected_registry_prefix(r"HKLM\SOFTWARE\Classes");
        policy.add_protected_registry_prefix(r"HKCU\SOFTWARE\Classes");
        policy.add_protected_registry_prefix("HKCR");
        policy.add_protected_registry_exact("HKLM");
        policy.add_protected_registry_exact("HKCU");
        policy.add_protected_registry_exact("HKU");
        policy.add_protected_registry_exact("HKCR");
        policy.add_protected_registry_exact(r"HKLM\SOFTWARE");
        policy.add_protected_registry_exact(r"HKLM\SOFTWARE\WOW6432Node");
        policy.add_protected_registry_exact(r"HKCU\SOFTWARE");

        policy
    }

    #[cfg(not(windows))]
    pub fn unix_defaults() -> Self {
        let mut policy = Self::empty();
        for root in [
            "/etc", "/usr", "/bin", "/sbin", "/boot", "/lib", "/lib64", "/dev", "/proc", "/sys",
        ] {
            policy.add_protected_root(PathBuf::from(root));
        }
        policy.add_protected_exact(PathBuf::from("/"));
        policy.add_protected_exact(PathBuf::from("/opt"));
        policy.add_protected_exact(PathBuf::from("/var/lib"));
        policy.add_protected_exact(home_dir());
        policy
    }

    pub fn add_protected_root(&mut self, path: impl Into<PathBuf>) {
        let path = path.into();
        if !self
            .protected_roots
            .iter()
            .any(|existing| existing == &path)
        {
            self.protected_roots.push(path);
        }
    }

    pub fn add_protected_exact(&mut self, path: impl Into<PathBuf>) {
        let path = path.into();
        if !self
            .protected_exact
            .iter()
            .any(|existing| existing == &path)
        {
            self.protected_exact.push(path);
        }
    }

    pub fn add_protected_registry_prefix(&mut self, key: &str) {
        let key = key.to_ascii_uppercase().trim_end_matches('\\').to_string();
        if !self.protected_registry_prefixes.contains(&key) {
            self.protected_registry_prefixes.push(key);
        }
    }

    pub fn add_protected_registry_exact(&mut self, key: &str) {
        let key = key.to_ascii_uppercase().trim_end_matches('\\').to_string();
        if !self.protected_registry_exact.contains(&key) {
            self.protected_registry_exact.push(key);
        }
    }

    pub fn is_protected_path(&self, path: &Path) -> bool {
        let key = normalize_path_key(path);
        if self
            .protected_exact
            .iter()
            .any(|exact| normalize_path_key(exact) == key)
        {
            return true;
        }
        self.protected_roots
            .iter()
            .any(|root| is_within(path, root))
    }

    /// Validate a filesystem target. Returns the canonicalized path.
    pub fn check_path(&self, target: &str) -> Result<PathBuf, SafetyViolation> {
        let trimmed = target.trim();
        if trimmed.is_empty() {
            return Err(violation(target, "empty path"));
        }
        if trimmed.contains('\0') {
            return Err(violation(target, "path contains a null byte"));
        }
        if trimmed
            .chars()
            .any(|ch| matches!(ch, '*' | '?' | '"' | '<' | '>' | '|'))
        {
            return Err(violation(
                target,
                "path contains wildcard or reserved characters",
            ));
        }

        let expanded = expand_env(trimmed);
        let path = Path::new(&expanded);
        if !path.is_absolute() {
            return Err(violation(target, "path is not absolute"));
        }
        let resolved = resolve_path(path);
        if resolved.parent().is_none() {
            return Err(violation(target, "drive or filesystem root"));
        }
        if self.is_protected_path(&resolved) {
            return Err(violation(target, "matches the protected-path denylist"));
        }
        Ok(resolved)
    }

    /// Validate a registry target. Returns the normalized registry path.
    pub fn check_registry(&self, target: &str) -> Result<String, SafetyViolation> {
        let normalized = normalize_registry_key(target)
            .ok_or_else(|| violation(target, "not a recognized registry path"))?;
        let upper = normalized.to_ascii_uppercase();

        if self.protected_registry_exact.contains(&upper) {
            return Err(violation(target, "matches the protected-registry denylist"));
        }
        if self
            .protected_registry_prefixes
            .iter()
            .any(|prefix| upper == *prefix || upper.starts_with(&format!("{prefix}\\")))
        {
            return Err(violation(target, "matches the protected-registry denylist"));
        }

        Ok(normalized)
    }

    pub fn check_item(&self, item: &ResidueItem) -> Result<SafetyTarget, SafetyViolation> {
        match item.kind {
            ResidueKind::File | ResidueKind::Dir | ResidueKind::Shortcut => {
                self.check_path(&item.path).map(SafetyTarget::Path)
            }
            ResidueKind::RegistryKey | ResidueKind::RegistryValue => {
                self.check_registry(&item.path).map(SafetyTarget::Registry)
            }
            _ => Ok(SafetyTarget::Object(item.path.clone())),
        }
    }
}

fn violation(target: &str, reason: &str) -> SafetyViolation {
    SafetyViolation {
        target: target.to_string(),
        reason: reason.to_string(),
    }
}

#[cfg(windows)]
fn env_path(name: &str) -> Option<PathBuf> {
    std::env::var_os(name).map(PathBuf::from)
}

/// Normalize a registry path to `HIVE\Sub\Key` form. Returns `None` when the
/// hive is not one Exuvia understands.
pub fn normalize_registry_key(input: &str) -> Option<String> {
    let replaced = input.trim().replace('/', "\\");
    let trimmed = replaced.trim_end_matches('\\');
    if trimmed.is_empty() {
        return None;
    }

    let (hive, rest) = match trimmed.split_once('\\') {
        Some((hive, rest)) => (hive, rest.trim_start_matches('\\')),
        None => (trimmed, ""),
    };

    let hive = match hive.to_ascii_uppercase().as_str() {
        "HKCU" | "HKEY_CURRENT_USER" => "HKCU",
        "HKLM" | "HKEY_LOCAL_MACHINE" => "HKLM",
        "HKCR" | "HKEY_CLASSES_ROOT" => "HKCR",
        "HKU" | "HKEY_USERS" => "HKU",
        "HKCC" | "HKEY_CURRENT_CONFIG" => "HKCC",
        _ => return None,
    };

    if rest.is_empty() {
        Some(hive.to_string())
    } else {
        Some(format!("{hive}\\{rest}"))
    }
}

impl fmt::Display for SafetyTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Path(path) => write!(f, "{}", path.display()),
            Self::Registry(key) => write!(f, "{key}"),
            Self::Object(name) => write!(f, "{name}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Confidence, MatchReason, ResidueCategory};

    #[test]
    fn protects_windows_and_allows_appdata_children() {
        let policy = SafetyPolicy::windows_defaults();
        assert!(policy
            .check_path(r"C:\Windows\System32\drivers\etc\hosts")
            .is_err());

        std::env::set_var("APPDATA", r"C:\Users\Example\AppData\Roaming");
        let allowed = policy.check_path(r"%APPDATA%\ExampleApp\cache");
        assert!(allowed.is_ok());
    }

    #[test]
    fn refuses_drive_root_and_relative_paths() {
        let policy = SafetyPolicy::windows_defaults();
        assert!(policy.check_path(r"C:\").is_err());
        assert!(policy.check_path(r"relative\path").is_err());
    }

    #[test]
    fn refuses_wildcards() {
        let policy = SafetyPolicy::windows_defaults();
        assert!(policy.check_path(r"C:\Temp\*").is_err());
    }

    #[test]
    fn protects_critical_registry_hives() {
        let policy = SafetyPolicy::windows_defaults();
        assert!(policy
            .check_registry(r"HKLM\SYSTEM\CurrentControlSet\Services")
            .is_err());
        assert!(policy
            .check_registry(r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run")
            .is_err());
        assert!(policy
            .check_registry(r"HKCU\Software\ExampleCorp\Editor")
            .is_ok());
    }

    #[test]
    fn validates_items_by_kind() {
        let policy = SafetyPolicy::windows_defaults();
        let item = ResidueItem {
            kind: ResidueKind::RegistryKey,
            category: ResidueCategory::Registry,
            path: r"HKCU\Software\ExampleCorp".to_string(),
            display_path: r"HKCU\Software\ExampleCorp".to_string(),
            size_bytes: 0,
            confidence: Confidence::High,
            reason: MatchReason::Rule("example".to_string()),
            preserve_in_standard: false,
            removable: true,
            detail: None,
        };
        assert!(matches!(
            policy.check_item(&item),
            Ok(SafetyTarget::Registry(_))
        ));
    }

    #[test]
    fn normalizes_registry_hive_names() {
        assert_eq!(
            normalize_registry_key(r"HKEY_CURRENT_USER\Software\Example"),
            Some(r"HKCU\Software\Example".to_string())
        );
        assert_eq!(normalize_registry_key("NOPE\\Key"), None);
    }
}
