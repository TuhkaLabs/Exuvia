//! Platform integration. The Windows implementation is the only shipping
//! backend today; the same public surface is stubbed for other targets so the
//! rest of the workspace stays portable.

use exuvia_core::{InstalledApp, ResidueItem, SafetyPolicy};
use exuvia_rules::RuleSet;

#[derive(Debug, Clone, Default)]
pub struct DiscoveryResult {
    pub apps: Vec<InstalledApp>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct ScanOutcome {
    pub items: Vec<ResidueItem>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativeUninstallOutcome {
    Ran {
        command: String,
        exit_code: Option<i32>,
        success: bool,
    },
    NotAvailable,
}

#[cfg(windows)]
mod windows;

#[cfg(windows)]
pub use windows::{
    delete_registry_key, discover, export_registry_key, import_registry_file, key_exists,
    native_uninstall as run_native_uninstall, path_size, scan_orphans, scan_residue, value_count,
};

#[cfg(not(windows))]
mod fallback;

#[cfg(not(windows))]
pub use fallback::{
    delete_registry_key, discover, export_registry_key, import_registry_file, key_exists,
    native_uninstall as run_native_uninstall, path_size, scan_orphans, scan_residue, value_count,
};

/// Shared scanning entry point used by tests and future platforms.
pub fn scan(app: &InstalledApp, rules: &RuleSet, policy: &SafetyPolicy) -> ScanOutcome {
    scan_residue(app, rules, policy)
}

/// Marker to keep the trait shape from the architecture document available to
/// downstream crates without forcing a trait object yet.
pub trait AppProvider {
    fn discover(&self) -> DiscoveryResult;
}

/// Marker for future platform-specific residue scanners.
pub trait ResidueScanner {
    fn scan(&self, app: &InstalledApp, rules: &RuleSet, policy: &SafetyPolicy) -> ScanOutcome;
}
