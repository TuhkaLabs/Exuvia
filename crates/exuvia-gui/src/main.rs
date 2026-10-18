#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::collections::HashSet;

use exuvia_core::{
    default_selected, human_size, ExuviaError, InstalledApp, MatchReason, ResidueCategory,
    ResidueItem, ResidueKind, SafetyPolicy, UninstallMode,
};
use exuvia_platform::ScanOutcome;
use exuvia_rules::RuleSet;
use exuvia_store::{ManifestState, Store};
use serde::Serialize;
use tauri::State;

struct AppState {
    store: Store,
    rules: RuleSet,
    policy: SafetyPolicy,
}

#[derive(Serialize)]
struct ItemView {
    key: String,
    category: String,
    kind: String,
    display_path: String,
    size_bytes: u64,
    size_label: String,
    confidence: String,
    reason: String,
    removable: bool,
    selected: bool,
    detail: Option<String>,
}

#[derive(Serialize)]
struct ScanView {
    app: InstalledApp,
    items: Vec<ItemView>,
    warnings: Vec<String>,
    selected_count: usize,
    selected_bytes: u64,
    selected_label: String,
    total_bytes: u64,
    total_label: String,
}

#[derive(Serialize)]
struct QuarantineView {
    manifest_id: String,
    removed: usize,
    failed: usize,
    reclaimed_bytes: u64,
    reclaimed_label: String,
    errors: Vec<String>,
}

#[derive(Serialize)]
struct HistoryView {
    id: String,
    created_at: String,
    app_name: String,
    mode: UninstallMode,
    state: ManifestState,
    item_count: usize,
    reclaimed_bytes: u64,
    reclaimed_label: String,
}

#[derive(Serialize)]
struct RestoreView {
    restored: usize,
    failed: usize,
    errors: Vec<String>,
}

#[tauri::command]
async fn list_apps() -> Result<Vec<InstalledApp>, String> {
    tauri::async_runtime::spawn_blocking(exuvia_platform::discover)
        .await
        .map(|result| result.apps)
        .map_err(|error| error.to_string())
}

#[tauri::command]
async fn scan_app(
    query: String,
    complete: bool,
    state: State<'_, AppState>,
) -> Result<ScanView, String> {
    let rules = state.rules.clone();
    let policy = state.policy.clone();

    tauri::async_runtime::spawn_blocking(move || {
        let discovery = exuvia_platform::discover();
        let app = resolve_app(&discovery.apps, &query)?;
        let mut outcome = exuvia_platform::scan_residue(app, &rules, &policy);
        if !app.uninstall.has_uninstaller() {
            add_portable_install_dir(app, &policy, &mut outcome);
        }

        let mode = if complete {
            UninstallMode::Complete
        } else {
            UninstallMode::Standard
        };
        let mut items = Vec::with_capacity(outcome.items.len());
        let mut selected_count = 0;
        let mut selected_bytes = 0;

        for item in &outcome.items {
            let selected = default_selected(item, mode);
            if selected {
                selected_count += 1;
                selected_bytes += item.size_bytes;
            }
            items.push(item_view(item, selected));
        }

        let total_bytes = outcome.items.iter().map(|item| item.size_bytes).sum();
        let mut warnings = discovery.warnings;
        warnings.extend(outcome.warnings);

        Ok::<ScanView, ExuviaError>(ScanView {
            app: app.clone(),
            items,
            warnings,
            selected_count,
            selected_bytes,
            selected_label: human_size(selected_bytes),
            total_bytes,
            total_label: human_size(total_bytes),
        })
    })
    .await
    .map_err(|error| error.to_string())?
    .map_err(|error| error.to_string())
}

#[tauri::command]
async fn quarantine(
    query: String,
    keys: Vec<String>,
    permanent: bool,
    state: State<'_, AppState>,
) -> Result<QuarantineView, String> {
    let store = state.store.clone();
    let rules = state.rules.clone();
    let policy = state.policy.clone();

    tauri::async_runtime::spawn_blocking(move || {
        let discovery = exuvia_platform::discover();
        let app = resolve_app(&discovery.apps, &query)?;
        let mut outcome = exuvia_platform::scan_residue(app, &rules, &policy);
        if !app.uninstall.has_uninstaller() {
            add_portable_install_dir(app, &policy, &mut outcome);
        }

        let wanted: HashSet<String> = keys.into_iter().collect();
        let items: Vec<ResidueItem> = outcome
            .items
            .into_iter()
            .filter(|item| item.removable && wanted.contains(&item_key(item)))
            .collect();

        if items.is_empty() {
            return Err(ExuviaError::Usage(
                "select at least one removable item".to_string(),
            ));
        }

        let mut manifest = store.create_manifest(
            app,
            UninstallMode::Complete,
            permanent,
            items,
            outcome.warnings,
        )?;
        let stats = store.apply(&mut manifest, &policy)?;
        let errors = manifest
            .records
            .iter()
            .filter_map(|record| record.error.clone())
            .collect();

        Ok::<QuarantineView, ExuviaError>(QuarantineView {
            manifest_id: manifest.id,
            removed: stats.quarantined + stats.deleted,
            failed: stats.failed,
            reclaimed_bytes: stats.reclaimed_bytes,
            reclaimed_label: human_size(stats.reclaimed_bytes),
            errors,
        })
    })
    .await
    .map_err(|error| error.to_string())?
    .map_err(|error| error.to_string())
}

#[tauri::command]
async fn history(state: State<'_, AppState>) -> Result<Vec<HistoryView>, String> {
    let store = state.store.clone();

    tauri::async_runtime::spawn_blocking(move || {
        let manifests = store.list_manifests()?;
        Ok::<Vec<HistoryView>, ExuviaError>(
            manifests
                .into_iter()
                .map(|manifest| HistoryView {
                    id: manifest.id,
                    created_at: manifest.created_at,
                    app_name: manifest.app.name,
                    mode: manifest.mode,
                    state: manifest.state,
                    item_count: manifest.records.len(),
                    reclaimed_bytes: manifest.reclaimed_bytes,
                    reclaimed_label: human_size(manifest.reclaimed_bytes),
                })
                .collect(),
        )
    })
    .await
    .map_err(|error| error.to_string())?
    .map_err(|error| error.to_string())
}

#[tauri::command]
async fn restore_manifest(id: String, state: State<'_, AppState>) -> Result<RestoreView, String> {
    let store = state.store.clone();

    tauri::async_runtime::spawn_blocking(move || {
        let report = store.restore(&id)?;
        Ok::<RestoreView, ExuviaError>(RestoreView {
            restored: report.restored,
            failed: report.failed,
            errors: report.errors,
        })
    })
    .await
    .map_err(|error| error.to_string())?
    .map_err(|error| error.to_string())
}

fn item_view(item: &ResidueItem, selected: bool) -> ItemView {
    ItemView {
        key: item_key(item),
        category: item.category.label().to_string(),
        kind: item.kind.label().to_string(),
        display_path: item.display_path.clone(),
        size_bytes: item.size_bytes,
        size_label: if item.size_bytes > 0 {
            human_size(item.size_bytes)
        } else {
            "-".to_string()
        },
        confidence: item.confidence.label().to_string(),
        reason: item.reason.describe(),
        removable: item.removable,
        selected,
        detail: item.detail.clone(),
    }
}

fn item_key(item: &ResidueItem) -> String {
    format!("{:?}|{}", item.kind, item.path)
}

fn resolve_app<'a>(apps: &'a [InstalledApp], query: &str) -> Result<&'a InstalledApp, ExuviaError> {
    let query = query.trim();
    if query.is_empty() {
        return Err(ExuviaError::Usage("application is required".to_string()));
    }

    if let Some(app) = apps.iter().find(|app| app.id.eq_ignore_ascii_case(query)) {
        return Ok(app);
    }
    if let Some(app) = apps.iter().find(|app| {
        app.product_code
            .as_deref()
            .map(|code| code.eq_ignore_ascii_case(query))
            .unwrap_or(false)
    }) {
        return Ok(app);
    }

    let exact: Vec<&InstalledApp> = apps
        .iter()
        .filter(|app| app.name.eq_ignore_ascii_case(query))
        .collect();
    match exact.len() {
        1 => return Ok(exact[0]),
        count if count > 1 => return Err(ambiguous(query, &exact)),
        _ => {}
    }

    let contains: Vec<&InstalledApp> = apps
        .iter()
        .filter(|app| app.name.to_lowercase().contains(&query.to_lowercase()))
        .collect();
    match contains.len() {
        0 => Err(ExuviaError::AppNotFound(query.to_string())),
        1 => Ok(contains[0]),
        _ => Err(ambiguous(query, &contains)),
    }
}

fn ambiguous(query: &str, matches: &[&InstalledApp]) -> ExuviaError {
    let candidates = matches
        .iter()
        .take(6)
        .map(|app| format!("{} [{}]", app.name, app.source))
        .collect::<Vec<_>>()
        .join("; ");
    ExuviaError::AmbiguousApp {
        query: query.to_string(),
        candidates,
    }
}

fn add_portable_install_dir(
    app: &InstalledApp,
    policy: &SafetyPolicy,
    outcome: &mut ScanOutcome,
) {
    let Some(location) = app.uninstall.install_location.as_ref() else {
        return;
    };
    if !location.exists() {
        return;
    }

    let item = ResidueItem {
        kind: ResidueKind::Dir,
        category: ResidueCategory::Application,
        path: location.to_string_lossy().to_string(),
        display_path: location.to_string_lossy().to_string(),
        size_bytes: exuvia_platform::path_size(location),
        confidence: exuvia_core::Confidence::High,
        reason: MatchReason::InstallLocation(location.to_string_lossy().to_string()),
        preserve_in_standard: false,
        removable: true,
        detail: Some(
            "No native uninstaller; the install directory is removed directly".to_string(),
        ),
    };

    if policy.check_item(&item).is_ok() {
        outcome.items.push(item);
        outcome.items.sort_by_key(ResidueItem::sort_key);
    }
}

fn main() {
    let store = Store::discover().expect("failed to open the Exuvia data store");
    let mut policy = SafetyPolicy::for_current_platform();
    policy.add_protected_root(store.root().to_path_buf());

    let rules = RuleSet::load(&[store.rules_dir()]).unwrap_or_else(|error| {
        eprintln!("warning: could not load user rules ({error}); using bundled rules");
        RuleSet::bundled().expect("bundled rules must parse")
    });

    tauri::Builder::default()
        .manage(AppState {
            store,
            rules,
            policy,
        })
        .invoke_handler(tauri::generate_handler![
            list_apps,
            scan_app,
            quarantine,
            history,
            restore_manifest
        ])
        .run(tauri::generate_context!())
        .expect("error while running Exuvia");
}
