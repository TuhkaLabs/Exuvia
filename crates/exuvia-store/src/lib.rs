//! Durable state for Exuvia: manifests, the quarantine area, restore history
//! and the local structured log.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use chrono::{Local, Utc};
use exuvia_core::{
    is_reparse_or_symlink, ExuviaError, InstalledApp, ResidueItem, ResidueKind, Result,
    SafetyPolicy, SafetyTarget, UninstallMode,
};
use exuvia_platform::{delete_registry_key, export_registry_key, import_registry_file, key_exists};
use serde::{Deserialize, Serialize};
use serde_json::json;

const SCHEMA_VERSION: u32 = 1;
const LOG_ROTATE_BYTES: u64 = 5 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifestState {
    Pending,
    Completed,
    Partial,
    Restored,
    PartialRestore,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemovalStatus {
    Pending,
    Quarantined,
    Deleted,
    ReportedOnly,
    Failed,
    Skipped,
    Restored,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemovalRecord {
    pub item: ResidueItem,
    pub status: RemovalStatus,
    pub quarantine_path: Option<String>,
    pub registry_backup: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub schema_version: u32,
    pub id: String,
    pub created_at: String,
    pub app: InstalledApp,
    pub mode: UninstallMode,
    pub permanent: bool,
    pub state: ManifestState,
    pub records: Vec<RemovalRecord>,
    pub reclaimed_bytes: u64,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ApplyStats {
    pub quarantined: usize,
    pub deleted: usize,
    pub failed: usize,
    pub reported: usize,
    pub skipped: usize,
    pub reclaimed_bytes: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RestoreReport {
    pub manifest_id: String,
    pub restored: usize,
    pub failed: usize,
    pub errors: Vec<String>,
}

/// Location of all persistent Exuvia data.
#[derive(Debug, Clone)]
pub struct Store {
    root: PathBuf,
}

impl Store {
    /// `EXUVIA_DATA_DIR` wins, then `%LOCALAPPDATA%\Exuvia`, then `~/.exuvia`.
    pub fn discover_root() -> PathBuf {
        if let Some(value) = std::env::var_os("EXUVIA_DATA_DIR") {
            return PathBuf::from(value);
        }
        if let Some(local) = std::env::var_os("LOCALAPPDATA") {
            return PathBuf::from(local).join("Exuvia");
        }
        exuvia_core::home_dir().join(".exuvia")
    }

    pub fn discover() -> Result<Self> {
        Self::open(Self::discover_root())
    }

    pub fn open(root: impl Into<PathBuf>) -> Result<Self> {
        let store = Self { root: root.into() };
        for dir in [
            store.manifests_dir(),
            store.quarantine_dir(),
            store.registry_dir(),
            store.logs_dir(),
            store.rules_dir(),
        ] {
            fs::create_dir_all(&dir).map_err(|error| {
                ExuviaError::io(format!("failed to create {}", dir.display()), error)
            })?;
        }
        Ok(store)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn manifests_dir(&self) -> PathBuf {
        self.root.join("manifests")
    }

    pub fn quarantine_dir(&self) -> PathBuf {
        self.root.join("quarantine")
    }

    pub fn registry_dir(&self) -> PathBuf {
        self.root.join("registry")
    }

    pub fn logs_dir(&self) -> PathBuf {
        self.root.join("logs")
    }

    pub fn rules_dir(&self) -> PathBuf {
        self.root.join("rules")
    }

    /// Persist a manifest before anything is touched (FR-18).
    pub fn create_manifest(
        &self,
        app: &InstalledApp,
        mode: UninstallMode,
        permanent: bool,
        items: Vec<ResidueItem>,
        warnings: Vec<String>,
    ) -> Result<Manifest> {
        let manifest = Manifest {
            schema_version: SCHEMA_VERSION,
            id: self.next_manifest_id(),
            created_at: Local::now().to_rfc3339(),
            app: app.clone(),
            mode,
            permanent,
            state: ManifestState::Pending,
            records: items
                .into_iter()
                .map(|item| RemovalRecord {
                    item,
                    status: RemovalStatus::Pending,
                    quarantine_path: None,
                    registry_backup: None,
                    error: None,
                })
                .collect(),
            reclaimed_bytes: 0,
            warnings,
        };
        self.save_manifest(&manifest)?;
        Ok(manifest)
    }

    pub fn save_manifest(&self, manifest: &Manifest) -> Result<()> {
        let path = self.manifest_path(&manifest.id)?;
        write_json_atomic(&path, manifest)
    }

    pub fn load_manifest(&self, id: &str) -> Result<Manifest> {
        let path = self.manifest_path(id)?;
        let bytes = fs::read(&path)
            .map_err(|error| ExuviaError::io(format!("failed to read manifest {id}"), error))?;
        serde_json::from_slice(&bytes)
            .map_err(|error| ExuviaError::Other(format!("manifest {id} is corrupt: {error}")))
    }

    pub fn list_manifests(&self) -> Result<Vec<Manifest>> {
        let mut manifests = Vec::new();
        let entries = match fs::read_dir(self.manifests_dir()) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(manifests),
            Err(error) => {
                return Err(ExuviaError::io("failed to read manifest directory", error));
            }
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().map(|ext| ext != "json").unwrap_or(true) {
                continue;
            }
            let bytes = match fs::read(&path) {
                Ok(bytes) => bytes,
                Err(_) => continue,
            };
            match serde_json::from_slice::<Manifest>(&bytes) {
                Ok(manifest) => manifests.push(manifest),
                Err(_) => continue,
            }
        }

        manifests.sort_by(|left, right| right.created_at.cmp(&left.created_at));
        Ok(manifests)
    }

    /// Execute every pending record and persist progress after each item.
    pub fn apply(&self, manifest: &mut Manifest, policy: &SafetyPolicy) -> Result<ApplyStats> {
        let mut stats = ApplyStats::default();

        for index in 0..manifest.records.len() {
            if manifest.records[index].status != RemovalStatus::Pending {
                continue;
            }
            let item = manifest.records[index].item.clone();
            let result = self.apply_item(&manifest.id, index, &item, manifest.permanent, policy);

            match result {
                Ok((status, quarantine_path, registry_backup)) => {
                    manifest.records[index].status = status;
                    manifest.records[index].quarantine_path = quarantine_path;
                    manifest.records[index].registry_backup = registry_backup;
                    match status {
                        RemovalStatus::Quarantined => stats.quarantined += 1,
                        RemovalStatus::Deleted => stats.deleted += 1,
                        RemovalStatus::ReportedOnly => stats.reported += 1,
                        RemovalStatus::Skipped => stats.skipped += 1,
                        _ => {}
                    }
                }
                Err(error) => {
                    stats.failed += 1;
                    manifest.records[index].status = RemovalStatus::Failed;
                    manifest.records[index].error = Some(error.to_string());
                }
            }

            manifest.reclaimed_bytes = manifest
                .records
                .iter()
                .filter(|record| {
                    matches!(
                        record.status,
                        RemovalStatus::Quarantined | RemovalStatus::Deleted
                    )
                })
                .map(|record| record.item.size_bytes)
                .sum();
            self.save_manifest(manifest)?;

            let _ = self.log_event(
                "removal",
                json!({
                    "manifest": manifest.id,
                    "path": manifest.records[index].item.path,
                    "kind": manifest.records[index].item.kind,
                    "status": manifest.records[index].status,
                    "error": manifest.records[index].error,
                }),
            );
        }

        manifest.state = if stats.failed > 0 {
            ManifestState::Partial
        } else {
            ManifestState::Completed
        };
        stats.reclaimed_bytes = manifest.reclaimed_bytes;
        self.save_manifest(manifest)?;
        let _ = self.log_event(
            "uninstall_complete",
            json!({
                "manifest": manifest.id,
                "app": manifest.app.name,
                "state": manifest.state,
                "reclaimed_bytes": manifest.reclaimed_bytes,
                "failed": stats.failed,
            }),
        );
        Ok(stats)
    }

    fn apply_item(
        &self,
        manifest_id: &str,
        index: usize,
        item: &ResidueItem,
        permanent: bool,
        policy: &SafetyPolicy,
    ) -> Result<(RemovalStatus, Option<String>, Option<String>)> {
        match item.kind {
            ResidueKind::File | ResidueKind::Dir | ResidueKind::Shortcut => {
                let target = match policy.check_item(item)? {
                    SafetyTarget::Path(path) => path,
                    _ => return Err(ExuviaError::Safety(item.path.clone())),
                };
                if !target.exists() {
                    return Ok((RemovalStatus::Skipped, None, None));
                }
                if is_reparse_or_symlink(&target) {
                    return Err(ExuviaError::Safety(format!(
                        "{} is a symlink or reparse point",
                        target.display()
                    )));
                }

                if permanent {
                    remove_path(&target)?;
                    return Ok((RemovalStatus::Deleted, None, None));
                }

                let destination = self.quarantine_destination(manifest_id, index, &target)?;
                move_path(&target, &destination)?;
                let relative = self.relative_path(&destination);
                Ok((RemovalStatus::Quarantined, Some(relative), None))
            }
            ResidueKind::RegistryKey => {
                let key = match policy.check_item(item)? {
                    SafetyTarget::Registry(key) => key,
                    _ => return Err(ExuviaError::Safety(item.path.clone())),
                };
                if !key_exists(&key) {
                    return Ok((RemovalStatus::Skipped, None, None));
                }

                let backup = self
                    .registry_dir()
                    .join(manifest_id)
                    .join(format!("{index:04}.reg"));
                export_registry_key(&key, &backup)?;
                delete_registry_key(&key)?;
                let relative = self.relative_path(&backup);
                Ok((RemovalStatus::Quarantined, None, Some(relative)))
            }
            _ => Ok((RemovalStatus::ReportedOnly, None, None)),
        }
    }

    pub fn restore(&self, id: &str) -> Result<RestoreReport> {
        let mut manifest = self.load_manifest(id)?;
        let policy = SafetyPolicy::for_current_platform();
        let mut report = RestoreReport {
            manifest_id: manifest.id.clone(),
            ..RestoreReport::default()
        };

        for index in 0..manifest.records.len() {
            let record = manifest.records[index].clone();
            match record.status {
                RemovalStatus::Quarantined => {
                    match self.restore_record(&record, &policy) {
                        Ok(()) => {
                            manifest.records[index].status = RemovalStatus::Restored;
                            manifest.records[index].error = None;
                            report.restored += 1;
                        }
                        Err(error) => {
                            manifest.records[index].error = Some(error.to_string());
                            report.failed += 1;
                            report
                                .errors
                                .push(format!("{}: {error}", record.item.display_path));
                        }
                    }
                    self.save_manifest(&manifest)?;
                }
                RemovalStatus::Deleted => {
                    report.failed += 1;
                    report.errors.push(format!(
                        "{}: permanently deleted items cannot be restored",
                        record.item.display_path
                    ));
                }
                _ => {}
            }
        }

        manifest.state = if report.failed == 0 {
            ManifestState::Restored
        } else {
            ManifestState::PartialRestore
        };
        self.save_manifest(&manifest)?;
        let _ = self.log_event(
            "restore",
            json!({
                "manifest": manifest.id,
                "restored": report.restored,
                "failed": report.failed,
            }),
        );

        Ok(report)
    }

    fn restore_record(&self, record: &RemovalRecord, policy: &SafetyPolicy) -> Result<()> {
        if record.item.kind == ResidueKind::RegistryKey {
            policy.check_registry(&record.item.path)?;
            let relative = record
                .registry_backup
                .as_deref()
                .ok_or_else(|| ExuviaError::Other("registry backup path is missing".to_string()))?;
            let backup = self.root.join(relative);
            return import_registry_file(&backup);
        }

        let relative = record
            .quarantine_path
            .as_deref()
            .ok_or_else(|| ExuviaError::Other("quarantine path is missing".to_string()))?;
        let source = self.root.join(relative);
        if !source.exists() {
            return Err(ExuviaError::Other(format!(
                "quarantined item {} is missing",
                source.display()
            )));
        }

        let target = match policy.check_item(&record.item)? {
            SafetyTarget::Path(path) => path,
            _ => return Err(ExuviaError::Safety(record.item.path.clone())),
        };
        if target.exists() {
            return Err(ExuviaError::Other(format!(
                "{} already exists; refusing to overwrite it",
                target.display()
            )));
        }
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                ExuviaError::io(format!("failed to create {}", parent.display()), error)
            })?;
        }
        move_path(&source, &target)
    }

    fn quarantine_destination(
        &self,
        manifest_id: &str,
        index: usize,
        target: &Path,
    ) -> Result<PathBuf> {
        let name = target
            .file_name()
            .map(|name| name.to_string_lossy().to_string())
            .unwrap_or_else(|| "item".to_string());
        let destination = self
            .quarantine_dir()
            .join(manifest_id)
            .join(format!("{index:04}_{name}"));
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                ExuviaError::io(format!("failed to create {}", parent.display()), error)
            })?;
        }
        Ok(destination)
    }

    fn relative_path(&self, path: &Path) -> String {
        path.strip_prefix(&self.root)
            .unwrap_or(path)
            .to_string_lossy()
            .to_string()
    }

    fn manifest_path(&self, id: &str) -> Result<PathBuf> {
        if id.is_empty()
            || !id
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
        {
            return Err(ExuviaError::Usage(format!("invalid manifest id '{id}'")));
        }
        Ok(self.manifests_dir().join(format!("{id}.json")))
    }

    fn next_manifest_id(&self) -> String {
        let now = Local::now();
        let nanos = now.timestamp_nanos_opt().unwrap_or_default() as u64;
        let entropy = (nanos ^ (std::process::id() as u64) << 16) & 0xFF_FFFF;
        let base = format!("{}-{entropy:06x}", now.format("%Y%m%d-%H%M%S"));
        let mut candidate = base.clone();
        let mut counter = 1;
        while self
            .manifests_dir()
            .join(format!("{candidate}.json"))
            .exists()
        {
            candidate = format!("{base}-{counter}");
            counter += 1;
        }
        candidate
    }

    /// Append a JSON-lines event to the local log, rotating at 5 MiB.
    pub fn log_event(&self, event: &str, data: serde_json::Value) -> Result<()> {
        let dir = self.logs_dir();
        fs::create_dir_all(&dir)
            .map_err(|error| ExuviaError::io("failed to create log directory", error))?;
        let file = dir.join("exuvia.jsonl");
        if fs::metadata(&file)
            .map(|metadata| metadata.len() > LOG_ROTATE_BYTES)
            .unwrap_or(false)
        {
            let rotated = dir.join("exuvia.jsonl.1");
            let _ = fs::remove_file(&rotated);
            let _ = fs::rename(&file, rotated);
        }

        let line = json!({
            "ts": Utc::now().to_rfc3339(),
            "event": event,
            "data": data,
        });
        let mut handle = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&file)
            .map_err(|error| ExuviaError::io("failed to open log", error))?;
        writeln!(handle, "{line}").map_err(|error| ExuviaError::io("failed to write log", error))
    }
}

fn write_json_atomic(path: &Path, value: &impl Serialize) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| ExuviaError::Other(format!("{} has no parent", path.display())))?;
    fs::create_dir_all(parent).map_err(|error| {
        ExuviaError::io(format!("failed to create {}", parent.display()), error)
    })?;

    let mut temp = tempfile::NamedTempFile::new_in(parent)
        .map_err(|error| ExuviaError::io("failed to create temporary manifest", error))?;
    serde_json::to_writer_pretty(temp.as_file_mut(), value)?;
    temp.as_file_mut()
        .sync_all()
        .map_err(|error| ExuviaError::io("failed to sync temporary manifest", error))?;
    temp.persist(path)
        .map_err(|error| ExuviaError::io("failed to replace manifest", error.error))?;
    Ok(())
}

fn remove_path(path: &Path) -> Result<()> {
    if path.is_dir() {
        fs::remove_dir_all(path)
            .map_err(|error| ExuviaError::io(format!("failed to remove {}", path.display()), error))
    } else {
        fs::remove_file(path)
            .map_err(|error| ExuviaError::io(format!("failed to remove {}", path.display()), error))
    }
}

fn move_path(source: &Path, destination: &Path) -> Result<()> {
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent).map_err(|error| {
            ExuviaError::io(format!("failed to create {}", parent.display()), error)
        })?;
    }

    match fs::rename(source, destination) {
        Ok(()) => Ok(()),
        Err(_) => {
            if source.is_dir() {
                copy_dir(source, destination)?;
                fs::remove_dir_all(source).map_err(|error| {
                    ExuviaError::io(format!("failed to remove {}", source.display()), error)
                })
            } else {
                fs::copy(source, destination).map_err(|error| {
                    ExuviaError::io(format!("failed to copy {}", source.display()), error)
                })?;
                fs::remove_file(source).map_err(|error| {
                    ExuviaError::io(format!("failed to remove {}", source.display()), error)
                })
            }
        }
    }
}

fn copy_dir(source: &Path, destination: &Path) -> Result<()> {
    fs::create_dir_all(destination).map_err(|error| {
        ExuviaError::io(format!("failed to create {}", destination.display()), error)
    })?;

    let entries = fs::read_dir(source)
        .map_err(|error| ExuviaError::io(format!("failed to read {}", source.display()), error))?;
    for entry in entries.flatten() {
        let path = entry.path();
        let file_type = entry.file_type().map_err(|error| {
            ExuviaError::io(format!("failed to stat {}", path.display()), error)
        })?;
        if file_type.is_symlink() || is_reparse_or_symlink(&path) {
            return Err(ExuviaError::Safety(format!(
                "refusing to copy symlink or reparse point {}",
                path.display()
            )));
        }
        let target = destination.join(entry.file_name());
        if file_type.is_dir() {
            copy_dir(&path, &target)?;
        } else {
            fs::copy(&path, &target).map_err(|error| {
                ExuviaError::io(format!("failed to copy {}", path.display()), error)
            })?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use exuvia_core::{AppSource, Architecture, Confidence, MatchReason, ResidueCategory};

    fn app() -> InstalledApp {
        InstalledApp {
            id: "test:app".to_string(),
            name: "Example".to_string(),
            version: Some("1.0".to_string()),
            publisher: Some("Example".to_string()),
            size_bytes: None,
            install_date: None,
            source: AppSource::Registry,
            architecture: Architecture::X64,
            product_code: None,
            uninstall: Default::default(),
        }
    }

    fn file_item(path: &Path) -> ResidueItem {
        ResidueItem {
            kind: ResidueKind::File,
            category: ResidueCategory::Application,
            path: path.to_string_lossy().to_string(),
            display_path: path.to_string_lossy().to_string(),
            size_bytes: 5,
            confidence: Confidence::High,
            reason: MatchReason::Rule("example".to_string()),
            preserve_in_standard: false,
            removable: true,
            detail: None,
        }
    }

    #[test]
    fn quarantines_and_restores_a_file() {
        let dir = tempfile::tempdir().expect("temp");
        let store = Store::open(dir.path().join("store")).expect("store");
        let file = dir.path().join("residue.txt");
        fs::write(&file, b"hello").expect("write");

        let mut manifest = store
            .create_manifest(
                &app(),
                UninstallMode::Complete,
                false,
                vec![file_item(&file)],
                Vec::new(),
            )
            .expect("manifest");
        let policy = SafetyPolicy::for_current_platform();
        store.apply(&mut manifest, &policy).expect("apply");

        assert!(!file.exists());
        assert_eq!(manifest.records[0].status, RemovalStatus::Quarantined);
        assert_eq!(manifest.reclaimed_bytes, 5);

        let report = store.restore(&manifest.id).expect("restore");
        assert_eq!(report.restored, 1);
        assert_eq!(fs::read(&file).expect("read"), b"hello");
    }

    #[test]
    fn permanent_removal_cannot_be_restored() {
        let dir = tempfile::tempdir().expect("temp");
        let store = Store::open(dir.path().join("store")).expect("store");
        let file = dir.path().join("permanent.txt");
        fs::write(&file, b"bye").expect("write");

        let mut manifest = store
            .create_manifest(
                &app(),
                UninstallMode::Complete,
                true,
                vec![file_item(&file)],
                Vec::new(),
            )
            .expect("manifest");
        let policy = SafetyPolicy::for_current_platform();
        store.apply(&mut manifest, &policy).expect("apply");

        assert!(!file.exists());
        assert_eq!(manifest.records[0].status, RemovalStatus::Deleted);

        let report = store.restore(&manifest.id).expect("restore");
        assert_eq!(report.failed, 1);
    }

    #[test]
    fn lists_history_and_writes_logs() {
        let dir = tempfile::tempdir().expect("temp");
        let store = Store::open(dir.path().join("store")).expect("store");
        store
            .create_manifest(
                &app(),
                UninstallMode::Standard,
                false,
                Vec::new(),
                Vec::new(),
            )
            .expect("manifest");
        let manifests = store.list_manifests().expect("list");
        assert_eq!(manifests.len(), 1);

        store.log_event("test", json!({"ok": true})).expect("log");
        let log = fs::read_to_string(store.logs_dir().join("exuvia.jsonl")).expect("read log");
        assert!(log.contains("\"event\":\"test\""));
    }

    #[test]
    fn rejects_traversal_manifest_ids() {
        let dir = tempfile::tempdir().expect("temp");
        let store = Store::open(dir.path().join("store")).expect("store");
        assert!(store.load_manifest("../evil").is_err());
        assert!(store.load_manifest("bad/id").is_err());
    }
}
