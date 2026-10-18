use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::ExuviaError;

/// Where an installed application was discovered from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AppSource {
    Registry,
    Msi,
    Msix,
    Winget,
    Scoop,
    Chocolatey,
    Portable,
}

impl AppSource {
    pub fn label(self) -> &'static str {
        match self {
            Self::Registry => "registry",
            Self::Msi => "msi",
            Self::Msix => "msix",
            Self::Winget => "winget",
            Self::Scoop => "scoop",
            Self::Chocolatey => "chocolatey",
            Self::Portable => "portable",
        }
    }
}

impl fmt::Display for AppSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

impl FromStr for AppSource {
    type Err = ExuviaError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "registry" => Ok(Self::Registry),
            "msi" => Ok(Self::Msi),
            "msix" | "appx" => Ok(Self::Msix),
            "winget" => Ok(Self::Winget),
            "scoop" => Ok(Self::Scoop),
            "chocolatey" | "choco" => Ok(Self::Chocolatey),
            "portable" => Ok(Self::Portable),
            other => Err(ExuviaError::Usage(format!(
                "unknown application source '{other}'"
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Architecture {
    X64,
    X86,
    Arm64,
    Unknown,
}

impl Architecture {
    pub fn label(self) -> &'static str {
        match self {
            Self::X64 => "x64",
            Self::X86 => "x86",
            Self::Arm64 => "arm64",
            Self::Unknown => "unknown",
        }
    }
}

impl fmt::Display for Architecture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Information needed to invoke an application's own uninstaller.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UninstallInfo {
    pub uninstall_string: Option<String>,
    pub quiet_uninstall_string: Option<String>,
    pub install_location: Option<PathBuf>,
}

impl UninstallInfo {
    pub fn has_uninstaller(&self) -> bool {
        self.quiet_uninstall_string
            .as_deref()
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false)
            || self
                .uninstall_string
                .as_deref()
                .map(|s| !s.trim().is_empty())
                .unwrap_or(false)
    }
}

/// One application reported by the platform discovery layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstalledApp {
    /// Stable identifier, e.g. `registry:hklm64:{GUID}`.
    pub id: String,
    pub name: String,
    pub version: Option<String>,
    pub publisher: Option<String>,
    pub size_bytes: Option<u64>,
    pub install_date: Option<String>,
    pub source: AppSource,
    pub architecture: Architecture,
    pub product_code: Option<String>,
    pub uninstall: UninstallInfo,
}

impl InstalledApp {
    pub fn display_name(&self) -> String {
        match &self.version {
            Some(version) if !version.is_empty() => format!("{} {}", self.name, version),
            _ => self.name.clone(),
        }
    }
}

/// How confident Exuvia is that a residue item belongs to the target app.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    High,
    #[default]
    Medium,
    Low,
}

impl Confidence {
    pub fn label(self) -> &'static str {
        match self {
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
        }
    }
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

impl FromStr for Confidence {
    type Err = ExuviaError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "high" => Ok(Self::High),
            "medium" => Ok(Self::Medium),
            "low" => Ok(Self::Low),
            other => Err(ExuviaError::Usage(format!(
                "unknown confidence '{other}' (expected high, medium or low)"
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResidueKind {
    File,
    Dir,
    RegistryKey,
    RegistryValue,
    Service,
    ScheduledTask,
    Shortcut,
    EnvironmentVariable,
    FirewallRule,
    Driver,
}

impl ResidueKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Dir => "directory",
            Self::RegistryKey => "registry key",
            Self::RegistryValue => "registry value",
            Self::Service => "service",
            Self::ScheduledTask => "scheduled task",
            Self::Shortcut => "shortcut",
            Self::EnvironmentVariable => "environment variable",
            Self::FirewallRule => "firewall rule",
            Self::Driver => "driver",
        }
    }

    /// Whether `exuvia-store` knows how to remove this kind right now.
    pub fn removable(self) -> bool {
        matches!(
            self,
            Self::File | Self::Dir | Self::RegistryKey | Self::Shortcut
        )
    }
}

impl fmt::Display for ResidueKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Categories used by the review screen and the CLI summary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ResidueCategory {
    Application,
    Preferences,
    Caches,
    Logs,
    Services,
    Registry,
}

impl ResidueCategory {
    pub fn label(self) -> &'static str {
        match self {
            Self::Application => "Application",
            Self::Preferences => "Preferences",
            Self::Caches => "Caches",
            Self::Logs => "Logs",
            Self::Services => "Services",
            Self::Registry => "Registry",
        }
    }
}

impl fmt::Display for ResidueCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Why a candidate was associated with the target application.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "detail", rename_all = "snake_case")]
pub enum MatchReason {
    ProductCode(String),
    Rule(String),
    AppName(String),
    Publisher(String),
    InstallLocation(String),
    Shortcut(String),
    ServiceImage(String),
    ScheduledTask(String),
    StartupEntry(String),
    Orphan,
}

impl MatchReason {
    pub fn describe(&self) -> String {
        match self {
            Self::ProductCode(code) => format!("Matches product code {code}"),
            Self::Rule(id) => format!("Matched community rule '{id}'"),
            Self::AppName(name) => format!("Name matches '{name}'"),
            Self::Publisher(name) => format!("Owned by publisher '{name}'"),
            Self::InstallLocation(path) => format!("Located inside {path}"),
            Self::Shortcut(name) => format!("Shortcut named '{name}'"),
            Self::ServiceImage(name) => format!("Service binary matches '{name}'"),
            Self::ScheduledTask(name) => format!("Scheduled task references '{name}'"),
            Self::StartupEntry(name) => format!("Startup entry named '{name}'"),
            Self::Orphan => "No installed application claims this item".to_string(),
        }
    }
}

/// One potential leftover item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResidueItem {
    pub kind: ResidueKind,
    pub category: ResidueCategory,
    /// Canonical absolute path for filesystem items, registry path for registry items.
    pub path: String,
    /// Human-readable path, usually with `%VARIABLES%` preserved.
    pub display_path: String,
    pub size_bytes: u64,
    pub confidence: Confidence,
    pub reason: MatchReason,
    /// User data that Standard mode leaves selected off.
    pub preserve_in_standard: bool,
    /// False for items that can only be reported until the elevated helper exists.
    pub removable: bool,
    pub detail: Option<String>,
}

impl ResidueItem {
    pub fn sort_key(&self) -> (ResidueCategory, std::cmp::Reverse<Confidence>, String) {
        (
            self.category,
            std::cmp::Reverse(self.confidence),
            self.display_path.to_lowercase(),
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UninstallMode {
    /// Keep user data that rules mark as valuable.
    Standard,
    /// Remove everything that was detected, except low-confidence matches.
    Complete,
}

impl UninstallMode {
    pub fn label(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Complete => "complete",
        }
    }
}

impl fmt::Display for UninstallMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Selection policy from FR-13: low-confidence matches are never preselected.
pub fn default_selected(item: &ResidueItem, mode: UninstallMode) -> bool {
    if !item.removable {
        return false;
    }
    match mode {
        UninstallMode::Standard => {
            item.confidence == Confidence::High && !item.preserve_in_standard
        }
        UninstallMode::Complete => item.confidence != Confidence::Low,
    }
}

/// Result of a residue scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub app: InstalledApp,
    pub items: Vec<ResidueItem>,
    pub warnings: Vec<String>,
    pub scanned_at: String,
}

impl ScanResult {
    pub fn total_bytes(&self, selected_only: bool, mode: UninstallMode) -> u64 {
        self.items
            .iter()
            .filter(|item| !selected_only || default_selected(item, mode))
            .map(|item| item.size_bytes)
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(confidence: Confidence, preserve: bool, removable: bool) -> ResidueItem {
        ResidueItem {
            kind: ResidueKind::Dir,
            category: ResidueCategory::Application,
            path: "C:\\Temp\\Example".to_string(),
            display_path: "%TEMP%\\Example".to_string(),
            size_bytes: 10,
            confidence,
            reason: MatchReason::Rule("example".to_string()),
            preserve_in_standard: preserve,
            removable,
            detail: None,
        }
    }

    #[test]
    fn low_confidence_is_never_selected() {
        let low = item(Confidence::Low, false, true);
        assert!(!default_selected(&low, UninstallMode::Standard));
        assert!(!default_selected(&low, UninstallMode::Complete));
    }

    #[test]
    fn standard_keeps_user_data_but_complete_selects_it() {
        let high = item(Confidence::High, true, true);
        assert!(!default_selected(&high, UninstallMode::Standard));
        assert!(default_selected(&high, UninstallMode::Complete));
    }

    #[test]
    fn non_removable_items_are_never_selected() {
        let high = item(Confidence::High, false, false);
        assert!(!default_selected(&high, UninstallMode::Complete));
    }
}
