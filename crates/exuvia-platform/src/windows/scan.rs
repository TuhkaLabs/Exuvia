use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use exuvia_core::{
    expand_env, is_reparse_or_symlink, name_variants, normalize_name, normalize_path_key,
    publisher_variants, resolve_path, Confidence, InstalledApp, MatchReason, ResidueCategory,
    ResidueItem, ResidueKind, SafetyPolicy,
};
use exuvia_rules::{AppRule, RuleSet};
use walkdir::WalkDir;

use crate::windows::registry;
use crate::ScanOutcome;

const GENERIC_DIRS: &[&str] = &[
    "adobe",
    "amd",
    "apple",
    "commonfiles",
    "desktop",
    "documents",
    "downloads",
    "exuvia",
    "google",
    "intel",
    "locallow",
    "microsoft",
    "mozilla",
    "nvidia",
    "packages",
    "programdata",
    "programs",
    "realtek",
    "roaming",
    "system32",
    "temp",
    "windows",
];

#[derive(Clone, Copy)]
enum RootKind {
    Data,
    Packages,
    Temp,
}

pub fn scan_residue(app: &InstalledApp, rules: &RuleSet, policy: &SafetyPolicy) -> ScanOutcome {
    let mut context = ScanContext::new(app, policy);
    if let Some(rule) = rules.find_rule(app) {
        context.scan_rule(rule);
    }
    context.scan_filesystem();
    context.scan_shortcuts();
    context.scan_registry_keys();
    context.scan_services();
    context.scan_scheduled_tasks();
    context.scan_startup_entries();
    context.finish()
}

pub fn scan_orphans(
    installed: &[InstalledApp],
    rules: &RuleSet,
    policy: &SafetyPolicy,
) -> ScanOutcome {
    let mut known = rules.known_names();
    for app in installed {
        known.extend(name_variants(&app.name));
        if let Some(publisher) = &app.publisher {
            known.extend(publisher_variants(publisher));
        }
    }

    let mut outcome = ScanOutcome::default();
    let mut seen = HashSet::new();

    for root in [
        env_path("APPDATA"),
        env_path("LOCALAPPDATA"),
        env_path("PROGRAMDATA"),
    ]
    .into_iter()
    .flatten()
    {
        let Ok(entries) = fs::read_dir(&root) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if !file_type.is_dir() || is_reparse_or_symlink(&path) {
                continue;
            }
            if policy.is_protected_path(&path) {
                continue;
            }
            let name = entry.file_name().to_string_lossy().to_string();
            let normalized = normalize_name(&name);
            if normalized.len() < 3 || GENERIC_DIRS.contains(&normalized.as_str()) {
                continue;
            }
            if known.iter().any(|candidate| {
                candidate == &normalized
                    || (candidate.len() >= 5 && normalized.starts_with(candidate))
                    || (normalized.len() >= 5 && candidate.starts_with(&normalized))
            }) {
                continue;
            }

            let resolved = resolve_path(&path);
            let key = normalize_path_key(&resolved);
            if !seen.insert(key) {
                continue;
            }
            outcome.items.push(ResidueItem {
                kind: ResidueKind::Dir,
                category: ResidueCategory::Application,
                path: resolved.to_string_lossy().to_string(),
                display_path: path.to_string_lossy().to_string(),
                size_bytes: dir_size(&path),
                confidence: Confidence::Low,
                reason: MatchReason::Orphan,
                preserve_in_standard: true,
                removable: true,
                detail: Some("No installed application claims this directory".to_string()),
            });
        }
    }

    outcome.items.sort_by_key(ResidueItem::sort_key);
    outcome
}

struct ScanContext<'a> {
    app: &'a InstalledApp,
    policy: &'a SafetyPolicy,
    variants: Vec<String>,
    publishers: Vec<String>,
    install_key: Option<String>,
    seen: HashSet<String>,
    items: Vec<ResidueItem>,
    warnings: Vec<String>,
}

impl<'a> ScanContext<'a> {
    fn new(app: &'a InstalledApp, policy: &'a SafetyPolicy) -> Self {
        let install_key = app
            .uninstall
            .install_location
            .as_ref()
            .map(|path| normalize_path_key(path));
        Self {
            app,
            policy,
            variants: name_variants(&app.name),
            publishers: app
                .publisher
                .as_deref()
                .map(publisher_variants)
                .unwrap_or_default(),
            install_key,
            seen: HashSet::new(),
            items: Vec::new(),
            warnings: Vec::new(),
        }
    }

    fn push(&mut self, item: ResidueItem) {
        let key = format!("{:?}|{}", item.kind, item.path.to_lowercase());
        if self.seen.insert(key) {
            self.items.push(item);
        }
    }

    fn push_fs(
        &mut self,
        path: &Path,
        display: &str,
        confidence: Confidence,
        category: ResidueCategory,
        preserve_in_standard: bool,
        reason: MatchReason,
    ) {
        let Ok(metadata) = fs::symlink_metadata(path) else {
            return;
        };
        if is_reparse_or_symlink(path) {
            self.warnings.push(format!(
                "skipped {}: symlinks and reparse points are never followed",
                path.display()
            ));
            return;
        }

        let resolved = resolve_path(path);
        if let Err(violation) = self.policy.check_path(&resolved.to_string_lossy()) {
            self.warnings
                .push(format!("skipped {}: {}", path.display(), violation.reason));
            return;
        }

        let kind = if metadata.is_dir() {
            ResidueKind::Dir
        } else {
            ResidueKind::File
        };
        let size_bytes = if metadata.is_dir() {
            dir_size(path)
        } else {
            metadata.len()
        };

        self.push(ResidueItem {
            kind,
            category,
            path: resolved.to_string_lossy().to_string(),
            display_path: display.to_string(),
            size_bytes,
            confidence,
            reason,
            preserve_in_standard,
            removable: true,
            detail: None,
        });
    }

    fn scan_rule(&mut self, rule: &AppRule) {
        for path_rule in &rule.paths {
            let expanded = expand_env(&path_rule.path);
            let path = Path::new(&expanded);
            if !path.exists() {
                continue;
            }
            self.push_fs(
                path,
                &path_rule.path,
                path_rule.confidence,
                path_rule.kind.category(),
                path_rule.kind.preserve_in_standard(),
                MatchReason::Rule(rule.id.clone()),
            );
        }

        for registry_rule in &rule.registry {
            if !registry::key_exists(&registry_rule.key) {
                continue;
            }
            self.push_registry_key(
                &registry_rule.key,
                registry_rule.confidence,
                MatchReason::Rule(rule.id.clone()),
                None,
            );
        }

        for service in &rule.services {
            let path = format!(r"HKLM\SYSTEM\CurrentControlSet\Services\{}", service.name);
            if registry::key_exists(&path) {
                self.push_service(&path, &service.name, service.confidence);
            }
        }

        for task in &rule.tasks {
            let Some(windows) = env_path("SystemRoot") else {
                continue;
            };
            let path = windows.join("System32").join("Tasks").join(&task.name);
            if path.exists() {
                self.push_task(&path, &task.name, task.confidence);
            }
        }

        for startup in &rule.startup {
            if let Some((key, value)) = find_startup_value(&startup.name) {
                self.push_startup(&key, &value, startup.confidence);
            }
        }
    }

    fn scan_filesystem(&mut self) {
        let mut roots = Vec::new();
        if let Some(app_data) = env_path("APPDATA") {
            roots.push((app_data, RootKind::Data));
        }
        if let Some(local) = env_path("LOCALAPPDATA") {
            roots.push((local.clone(), RootKind::Data));
            roots.push((local.join("Packages"), RootKind::Packages));
        }
        if let Some(program_data) = env_path("PROGRAMDATA") {
            roots.push((program_data, RootKind::Data));
        }
        if let Some(temp) = env_path("TEMP") {
            roots.push((temp, RootKind::Temp));
        }

        for (root, kind) in roots {
            self.scan_root(&root, kind);
        }
    }

    fn scan_root(&mut self, root: &Path, kind: RootKind) {
        let Ok(entries) = fs::read_dir(root) else {
            return;
        };

        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if is_reparse_or_symlink(&path) {
                continue;
            }
            let name = entry.file_name().to_string_lossy().to_string();
            let normalized = normalize_name(&name);
            if normalized.len() < 3 {
                continue;
            }

            match kind {
                RootKind::Packages => {
                    if self
                        .variants
                        .iter()
                        .any(|variant| variant.len() >= 4 && normalized.contains(variant.as_str()))
                    {
                        self.push_fs(
                            &path,
                            &path.to_string_lossy(),
                            Confidence::Medium,
                            ResidueCategory::Application,
                            false,
                            MatchReason::AppName(name.clone()),
                        );
                    }
                }
                RootKind::Data | RootKind::Temp => {
                    if self.policy.is_protected_path(&path)
                        || GENERIC_DIRS.contains(&normalized.as_str())
                    {
                        continue;
                    }
                    if file_type.is_dir() && self.matches_vendor(&normalized) {
                        self.scan_vendor_children(&path, &name);
                    }
                    if let Some(confidence) = self.match_variant(&normalized) {
                        let category = guess_category(&normalized);
                        self.push_fs(
                            &path,
                            &path.to_string_lossy(),
                            confidence,
                            category,
                            false,
                            MatchReason::AppName(name.clone()),
                        );
                    }
                }
            }
        }
    }

    fn scan_vendor_children(&mut self, vendor_path: &Path, vendor_name: &str) {
        let Ok(entries) = fs::read_dir(vendor_path) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if is_reparse_or_symlink(&path) || self.policy.is_protected_path(&path) {
                continue;
            }
            let normalized = normalize_name(&entry.file_name().to_string_lossy());
            if let Some(confidence) = self.match_related(&normalized) {
                let display = path.to_string_lossy().to_string();
                self.push_fs(
                    &path,
                    &display,
                    confidence,
                    guess_category(&normalized),
                    false,
                    MatchReason::Publisher(vendor_name.to_string()),
                );
            }
        }
    }

    fn scan_shortcuts(&mut self) {
        let mut roots = Vec::new();
        if let Some(program_data) = env_path("PROGRAMDATA") {
            roots.push(
                program_data
                    .join("Microsoft")
                    .join("Windows")
                    .join("Start Menu")
                    .join("Programs"),
            );
        }
        if let Some(app_data) = env_path("APPDATA") {
            roots.push(
                app_data
                    .join("Microsoft")
                    .join("Windows")
                    .join("Start Menu")
                    .join("Programs"),
            );
        }

        for root in roots {
            if !root.exists() {
                continue;
            }
            for entry in WalkDir::new(&root)
                .max_depth(5)
                .follow_links(false)
                .into_iter()
                .filter_map(Result::ok)
            {
                if !entry.file_type().is_file() {
                    continue;
                }
                let path = entry.path();
                let extension = path
                    .extension()
                    .map(|value| value.to_string_lossy().to_ascii_lowercase())
                    .unwrap_or_default();
                if extension != "lnk" && extension != "url" {
                    continue;
                }
                let Some(stem) = path
                    .file_stem()
                    .map(|value| value.to_string_lossy().to_string())
                else {
                    continue;
                };
                let normalized = normalize_name(&stem);
                if let Some(confidence) = self.match_variant(&normalized) {
                    let display = path.to_string_lossy().to_string();
                    self.push_fs(
                        path,
                        &display,
                        confidence,
                        ResidueCategory::Application,
                        false,
                        MatchReason::Shortcut(stem),
                    );
                }
            }
        }
    }

    fn scan_registry_keys(&mut self) {
        let scopes = [
            ("HKCU", "Software"),
            ("HKLM", "SOFTWARE"),
            ("HKLM", r"SOFTWARE\WOW6432Node"),
        ];

        for (hive, subkey) in scopes {
            let scope_path = format!(r"{hive}\{subkey}");
            let Ok(scope) = registry::open_key_read(&scope_path) else {
                continue;
            };

            for vendor in scope.enum_keys().flatten().take(2_000) {
                let vendor_norm = normalize_name(&vendor);
                if vendor_norm.len() < 3 {
                    continue;
                }
                let vendor_path = format!("{scope_path}\\{vendor}");

                if self.variants.contains(&vendor_norm) {
                    self.push_registry_key(
                        &vendor_path,
                        Confidence::Medium,
                        MatchReason::AppName(vendor.clone()),
                        None,
                    );
                }

                if self.matches_vendor(&vendor_norm) {
                    let Ok(vendor_key) = registry::open_key_read(&vendor_path) else {
                        continue;
                    };
                    for child in vendor_key.enum_keys().flatten().take(500) {
                        let child_norm = normalize_name(&child);
                        if let Some(confidence) = self.match_related(&child_norm) {
                            self.push_registry_key(
                                &format!("{vendor_path}\\{child}"),
                                confidence,
                                MatchReason::Publisher(vendor.clone()),
                                None,
                            );
                        }
                    }
                }
            }
        }
    }

    fn push_registry_key(
        &mut self,
        path: &str,
        confidence: Confidence,
        reason: MatchReason,
        detail: Option<String>,
    ) {
        if let Err(violation) = self.policy.check_registry(path) {
            self.warnings
                .push(format!("skipped {path}: {}", violation.reason));
            return;
        }
        let detail = detail.or_else(|| {
            registry::value_count(path).map(|count| match count {
                1 => "1 value".to_string(),
                count => format!("{count} values"),
            })
        });

        self.push(ResidueItem {
            kind: ResidueKind::RegistryKey,
            category: ResidueCategory::Registry,
            path: path.to_string(),
            display_path: path.to_string(),
            size_bytes: 0,
            confidence,
            reason,
            preserve_in_standard: false,
            removable: true,
            detail,
        });
    }

    fn scan_services(&mut self) {
        let root = r"HKLM\SYSTEM\CurrentControlSet\Services";
        let Ok(services) = registry::open_key_read(root) else {
            return;
        };
        let app_name = normalize_name(&self.app.name);

        for name in services.enum_keys().flatten() {
            let service_path = format!(r"{root}\{name}");
            let Ok(key) = registry::open_key_read(&service_path) else {
                continue;
            };
            let image = registry::read_string(&key, "ImagePath").unwrap_or_default();
            let display = registry::read_string(&key, "DisplayName")
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| name.clone());

            let image_path = extract_image_path(&image);
            let image_key = normalize_path_key(Path::new(&image_path));
            let install_match = self
                .install_key
                .as_ref()
                .map(|install| {
                    !install.is_empty()
                        && (image_key.starts_with(install.as_str())
                            || install.starts_with(&format!("{image_key}\\")))
                })
                .unwrap_or(false);
            let name_match = self.variants.iter().any(|variant| {
                *variant == normalize_name(&name) || *variant == normalize_name(&display)
            });
            let app_match = app_name.len() >= 5 && image_key.contains(app_name.as_str());

            if !install_match && !name_match && !app_match {
                continue;
            }

            self.push_service(
                &service_path,
                &display,
                if install_match {
                    Confidence::High
                } else {
                    Confidence::Medium
                },
            );
        }
    }

    fn push_service(&mut self, path: &str, display: &str, confidence: Confidence) {
        self.push(ResidueItem {
            kind: ResidueKind::Service,
            category: ResidueCategory::Services,
            path: path.to_string(),
            display_path: format!("Service: {display}"),
            size_bytes: 0,
            confidence,
            reason: MatchReason::ServiceImage(display.to_string()),
            preserve_in_standard: false,
            removable: false,
            detail: Some(
                "Reported only; service removal requires the elevated helper (planned)".to_string(),
            ),
        });
    }

    fn scan_scheduled_tasks(&mut self) {
        let Some(windows) = env_path("SystemRoot") else {
            return;
        };
        let root = windows.join("System32").join("Tasks");
        if !root.exists() {
            return;
        }

        let app_name = self.app.name.to_lowercase();
        if app_name.len() < 5 {
            return;
        }
        let install_lower = self
            .app
            .uninstall
            .install_location
            .as_ref()
            .map(|path| path.to_string_lossy().to_lowercase())
            .filter(|value| !value.is_empty());

        for entry in WalkDir::new(&root)
            .max_depth(6)
            .follow_links(false)
            .into_iter()
            .filter_map(Result::ok)
        {
            if !entry.file_type().is_file() {
                continue;
            }
            let Ok(metadata) = entry.metadata() else {
                continue;
            };
            if metadata.len() > 2 * 1024 * 1024 {
                continue;
            }
            let Ok(contents) = fs::read_to_string(entry.path()) else {
                continue;
            };
            let lower = contents.to_lowercase();
            let install_match = install_lower
                .as_ref()
                .map(|install| lower.contains(install.as_str()))
                .unwrap_or(false);
            let name_match = lower.contains(app_name.as_str());
            if !install_match && !name_match {
                continue;
            }

            let display = entry
                .path()
                .strip_prefix(&root)
                .unwrap_or(entry.path())
                .display()
                .to_string();
            self.push_task(
                entry.path(),
                &display,
                if install_match {
                    Confidence::High
                } else {
                    Confidence::Low
                },
            );
        }
    }

    fn push_task(&mut self, path: &Path, display: &str, confidence: Confidence) {
        self.push(ResidueItem {
            kind: ResidueKind::ScheduledTask,
            category: ResidueCategory::Services,
            path: path.to_string_lossy().to_string(),
            display_path: format!("Scheduled task: {display}"),
            size_bytes: 0,
            confidence,
            reason: MatchReason::ScheduledTask(display.to_string()),
            preserve_in_standard: false,
            removable: false,
            detail: Some(
                "Reported only; task removal requires the elevated helper (planned)".to_string(),
            ),
        });
    }

    fn scan_startup_entries(&mut self) {
        for (hive, subkey) in startup_locations() {
            let path = format!(r"{hive}\{subkey}");
            let Ok(key) = registry::open_key_read(&path) else {
                continue;
            };

            for (value_name, _) in key.enum_values().flatten() {
                let data: String = key.get_value(&value_name).unwrap_or_default();
                let data_lower = data.to_lowercase();
                let name_norm = normalize_name(&value_name);
                let name_match = self.variants.contains(&name_norm);
                let install_match = self
                    .app
                    .uninstall
                    .install_location
                    .as_ref()
                    .map(|location| {
                        let location = location.to_string_lossy().to_lowercase();
                        !location.is_empty() && data_lower.contains(location.as_str())
                    })
                    .unwrap_or(false);
                let app_name_lower = self.app.name.to_lowercase();
                let app_match =
                    self.app.name.len() >= 5 && data_lower.contains(app_name_lower.as_str());

                if !name_match && !install_match && !app_match {
                    continue;
                }

                self.push_startup(
                    &path,
                    &value_name,
                    if install_match {
                        Confidence::High
                    } else {
                        Confidence::Low
                    },
                );
            }
        }
    }

    fn push_startup(&mut self, key: &str, value_name: &str, confidence: Confidence) {
        self.push(ResidueItem {
            kind: ResidueKind::RegistryValue,
            category: ResidueCategory::Application,
            path: format!(r"{key}\{value_name}"),
            display_path: format!("{key}\\{value_name}"),
            size_bytes: 0,
            confidence,
            reason: MatchReason::StartupEntry(value_name.to_string()),
            preserve_in_standard: false,
            removable: false,
            detail: Some("Startup entries are reported only in this build".to_string()),
        });
    }

    fn matches_vendor(&self, normalized: &str) -> bool {
        self.publishers.iter().any(|publisher| {
            publisher.len() >= 4
                && (normalized == publisher
                    || (normalized.starts_with(publisher)
                        && normalized.len() - publisher.len() <= 8))
        })
    }

    /// Like `match_variant`, but an entry inside a publisher-owned directory is
    /// strong enough to be pre-selected in Complete mode.
    fn match_related(&self, normalized: &str) -> Option<Confidence> {
        if let Some(confidence) = self.match_variant(normalized) {
            return Some(confidence);
        }
        if normalized.len() >= 4
            && self.variants.iter().any(|variant| {
                variant.len() >= 4
                    && normalized.starts_with(variant)
                    && normalized.len() - variant.len() <= 8
            })
        {
            return Some(Confidence::Medium);
        }
        None
    }

    fn match_variant(&self, normalized: &str) -> Option<Confidence> {
        if normalized.len() < 3 {
            return None;
        }
        let mut best = None;
        for variant in &self.variants {
            if variant.len() < 3 {
                continue;
            }
            if normalized == variant {
                return Some(Confidence::Medium);
            }
            let shorter = normalized.len().min(variant.len());
            if shorter >= 4
                && (normalized.starts_with(variant) || variant.starts_with(normalized))
                && normalized.len().abs_diff(variant.len()) <= 6
            {
                best = Some(Confidence::Low);
            }
        }
        best
    }

    fn finish(self) -> ScanOutcome {
        let ScanContext {
            mut items,
            mut warnings,
            policy,
            ..
        } = self;

        items.retain(|item| {
            if !item.removable {
                return true;
            }
            match policy.check_item(item) {
                Ok(_) => true,
                Err(violation) => {
                    warnings.push(format!(
                        "not selected {}: {}",
                        item.display_path, violation.reason
                    ));
                    false
                }
            }
        });
        items.sort_by_key(ResidueItem::sort_key);
        ScanOutcome { items, warnings }
    }
}

fn find_startup_value(name: &str) -> Option<(String, String)> {
    for (hive, subkey) in startup_locations() {
        let path = format!(r"{hive}\{subkey}");
        let Ok(key) = registry::open_key_read(&path) else {
            continue;
        };
        for (value_name, _) in key.enum_values().flatten() {
            if value_name.eq_ignore_ascii_case(name) {
                return Some((path, value_name));
            }
        }
    }
    None
}

fn startup_locations() -> [(&'static str, &'static str); 5] {
    [
        ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run"),
        ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        (
            "HKLM",
            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        ),
    ]
}

fn extract_image_path(image: &str) -> String {
    let trimmed = image.trim();
    if let Some(rest) = trimmed.strip_prefix('"') {
        if let Some(end) = rest.find('"') {
            return rest[..end].to_string();
        }
    }
    let lower = trimmed.to_ascii_lowercase();
    // The first extension match marks the end of the executable path.
    for extension in [".exe", ".sys", ".dll"] {
        if let Some(index) = lower.find(extension) {
            return trimmed[..index + extension.len()].to_string();
        }
    }
    trimmed
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_string()
}

fn guess_category(normalized_name: &str) -> ResidueCategory {
    if normalized_name.contains("cache") {
        ResidueCategory::Caches
    } else if normalized_name.contains("log") {
        ResidueCategory::Logs
    } else if normalized_name.contains("config")
        || normalized_name.contains("setting")
        || normalized_name.contains("preference")
    {
        ResidueCategory::Preferences
    } else {
        ResidueCategory::Application
    }
}

pub fn path_size(path: &Path) -> u64 {
    if path.is_dir() {
        dir_size(path)
    } else {
        fs::metadata(path)
            .map(|metadata| metadata.len())
            .unwrap_or(0)
    }
}

fn dir_size(path: &Path) -> u64 {
    let mut total = 0;
    for entry in WalkDir::new(path)
        .follow_links(false)
        .into_iter()
        .filter_map(Result::ok)
    {
        if entry.file_type().is_file() {
            if let Ok(metadata) = entry.metadata() {
                total += metadata.len();
            }
        }
    }
    total
}

fn env_path(name: &str) -> Option<PathBuf> {
    std::env::var_os(name).map(PathBuf::from)
}
