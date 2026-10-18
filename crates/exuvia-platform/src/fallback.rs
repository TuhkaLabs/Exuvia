use std::path::Path;

use exuvia_core::{ExuviaError, InstalledApp, Result, SafetyPolicy};
use exuvia_rules::RuleSet;

use crate::{DiscoveryResult, NativeUninstallOutcome, ScanOutcome};

pub fn discover() -> DiscoveryResult {
    DiscoveryResult {
        apps: Vec::new(),
        warnings: vec!["application discovery is only implemented on Windows".to_string()],
    }
}

pub fn scan_residue(_app: &InstalledApp, _rules: &RuleSet, _policy: &SafetyPolicy) -> ScanOutcome {
    ScanOutcome {
        items: Vec::new(),
        warnings: vec!["residue scanning is only implemented on Windows".to_string()],
    }
}

pub fn scan_orphans(
    _installed: &[InstalledApp],
    _rules: &RuleSet,
    _policy: &SafetyPolicy,
) -> ScanOutcome {
    ScanOutcome::default()
}

pub fn native_uninstall(_app: &InstalledApp) -> Result<NativeUninstallOutcome> {
    Ok(NativeUninstallOutcome::NotAvailable)
}

pub fn export_registry_key(_key: &str, _destination: &Path) -> Result<()> {
    Err(unsupported())
}

pub fn import_registry_file(_file: &Path) -> Result<()> {
    Err(unsupported())
}

pub fn delete_registry_key(_key: &str) -> Result<()> {
    Err(unsupported())
}

pub fn key_exists(_key: &str) -> bool {
    false
}

pub fn value_count(_key: &str) -> Option<usize> {
    None
}

pub fn path_size(_path: &Path) -> u64 {
    0
}

fn unsupported() -> ExuviaError {
    ExuviaError::Other("Windows registry operations are unavailable on this platform".to_string())
}
