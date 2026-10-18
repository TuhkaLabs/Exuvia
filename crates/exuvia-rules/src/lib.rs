//! Community rule database: schema, loader, matching and validation.
//!
//! Rules are TOML documents describing known per-application paths and registry
//! keys. They are advisory only: every resulting item still passes through the
//! safety policy in `exuvia-core` before it can be selected.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;

use exuvia_core::{
    name_variants, normalize_name, publisher_variants, Confidence, InstalledApp, ResidueCategory,
    SafetyPolicy,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const BUNDLED_RULES: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../rules/bundled.toml"
));

#[derive(Debug, Error)]
pub enum RulesError {
    #[error("failed to read rule file {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid rule file {source_name}: {message}")]
    Parse {
        source_name: String,
        message: String,
    },
}

impl From<RulesError> for exuvia_core::ExuviaError {
    fn from(error: RulesError) -> Self {
        exuvia_core::ExuviaError::Other(error.to_string())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuleDataKind {
    UserData,
    Cache,
    #[default]
    Config,
    Log,
}

impl RuleDataKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::UserData => "user-data",
            Self::Cache => "cache",
            Self::Config => "config",
            Self::Log => "log",
        }
    }

    pub fn category(self) -> ResidueCategory {
        match self {
            Self::UserData | Self::Config => ResidueCategory::Preferences,
            Self::Cache => ResidueCategory::Caches,
            Self::Log => ResidueCategory::Logs,
        }
    }

    /// Standard mode leaves valuable user data untouched.
    pub fn preserve_in_standard(self) -> bool {
        matches!(self, Self::UserData)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathRule {
    pub path: String,
    #[serde(default)]
    pub kind: RuleDataKind,
    #[serde(default)]
    pub confidence: Confidence,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryRule {
    pub key: String,
    #[serde(default)]
    pub kind: RuleDataKind,
    #[serde(default)]
    pub confidence: Confidence,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceRule {
    pub name: String,
    #[serde(default)]
    pub confidence: Confidence,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskRule {
    pub name: String,
    #[serde(default)]
    pub confidence: Confidence,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StartupRule {
    pub name: String,
    #[serde(default)]
    pub confidence: Confidence,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppRule {
    pub name: String,
    #[serde(default)]
    pub publisher: Option<String>,
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default)]
    pub product_codes: Vec<String>,
    #[serde(default)]
    pub platforms: Vec<String>,
    #[serde(default)]
    pub paths: Vec<PathRule>,
    #[serde(default)]
    pub registry: Vec<RegistryRule>,
    #[serde(default)]
    pub services: Vec<ServiceRule>,
    #[serde(default)]
    pub tasks: Vec<TaskRule>,
    #[serde(default)]
    pub startup: Vec<StartupRule>,
    #[serde(skip)]
    pub id: String,
}

impl AppRule {
    pub fn normalized_names(&self) -> BTreeSet<String> {
        let mut names = BTreeSet::new();
        names.extend(name_variants(&self.name));
        names.extend(name_variants(&self.id));
        for alias in &self.aliases {
            let normalized = normalize_name(alias);
            if normalized.len() >= 3 {
                names.insert(normalized);
            }
            names.extend(name_variants(alias));
        }
        names
    }

    pub fn publisher_names(&self) -> BTreeSet<String> {
        self.publisher
            .as_deref()
            .map(publisher_variants)
            .unwrap_or_default()
            .into_iter()
            .collect()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleFile {
    #[serde(default)]
    pub schema: u32,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub app: BTreeMap<String, AppRule>,
}

#[derive(Debug, Clone, Default)]
pub struct RuleSet {
    apps: BTreeMap<String, AppRule>,
    version: String,
    sources: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleIssue {
    pub app: String,
    pub detail: String,
}

impl RuleSet {
    pub fn bundled() -> Result<Self, RulesError> {
        Self::from_toml_str("bundled", BUNDLED_RULES)
    }

    pub fn from_toml_str(source_name: &str, text: &str) -> Result<Self, RulesError> {
        let file: RuleFile = toml::from_str(text).map_err(|error| RulesError::Parse {
            source_name: source_name.to_string(),
            message: error.to_string(),
        })?;

        if file.schema != 0 && file.schema != 1 {
            return Err(RulesError::Parse {
                source_name: source_name.to_string(),
                message: format!("unsupported schema {} (expected 1)", file.schema),
            });
        }

        let mut apps = BTreeMap::new();
        for (id, mut rule) in file.app {
            if id.trim().is_empty() {
                return Err(RulesError::Parse {
                    source_name: source_name.to_string(),
                    message: "rule id cannot be empty".to_string(),
                });
            }
            if rule.name.trim().is_empty() {
                return Err(RulesError::Parse {
                    source_name: source_name.to_string(),
                    message: format!("rule '{id}' has an empty name"),
                });
            }
            validate_platforms(source_name, &id, &rule.platforms)?;
            rule.id = id.clone();
            apps.insert(id.to_ascii_lowercase(), rule);
        }

        Ok(Self {
            apps,
            version: file.version.unwrap_or_else(|| "unversioned".to_string()),
            sources: vec![source_name.to_string()],
        })
    }

    /// Load bundled rules and then every `*.toml` file in the given directories.
    /// User rules override bundled rules with the same id.
    pub fn load(user_dirs: &[PathBuf]) -> Result<Self, RulesError> {
        let mut set = Self::bundled()?;

        for dir in user_dirs {
            if !dir.exists() {
                continue;
            }
            let mut files: Vec<PathBuf> = fs::read_dir(dir)
                .map_err(|source| RulesError::Io {
                    path: dir.clone(),
                    source,
                })?
                .filter_map(Result::ok)
                .map(|entry| entry.path())
                .filter(|path| {
                    path.extension()
                        .map(|extension| extension.eq_ignore_ascii_case("toml"))
                        .unwrap_or(false)
                })
                .collect();
            files.sort();

            for file in files {
                let text = fs::read_to_string(&file).map_err(|source| RulesError::Io {
                    path: file.clone(),
                    source,
                })?;
                let source_name = file.to_string_lossy().to_string();
                let parsed = Self::from_toml_str(&source_name, &text)?;
                set.merge(parsed);
            }
        }

        Ok(set)
    }

    pub fn merge(&mut self, other: RuleSet) {
        self.sources.extend(other.sources);
        for (id, rule) in other.apps {
            self.apps.insert(id, rule);
        }
        if !other.version.is_empty() && other.version != "unversioned" {
            self.version = other.version;
        }
    }

    pub fn len(&self) -> usize {
        self.apps.len()
    }

    pub fn is_empty(&self) -> bool {
        self.apps.is_empty()
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn sources(&self) -> &[String] {
        &self.sources
    }

    pub fn apps(&self) -> impl Iterator<Item = (&String, &AppRule)> {
        self.apps.iter()
    }

    pub fn find_rule(&self, app: &InstalledApp) -> Option<&AppRule> {
        if let Some(product_code) = &app.product_code {
            for rule in self.apps.values() {
                if rule
                    .product_codes
                    .iter()
                    .any(|code| code.eq_ignore_ascii_case(product_code))
                {
                    return Some(rule);
                }
            }
        }

        let names: BTreeSet<String> = name_variants(&app.name).into_iter().collect();
        if names.is_empty() {
            return None;
        }
        let publishers: BTreeSet<String> = app
            .publisher
            .as_deref()
            .map(publisher_variants)
            .unwrap_or_default()
            .into_iter()
            .collect();

        if !publishers.is_empty() {
            for rule in self.apps.values() {
                if intersects(&rule.normalized_names(), &names)
                    && intersects(&rule.publisher_names(), &publishers)
                {
                    return Some(rule);
                }
            }
        }

        for rule in self.apps.values() {
            if intersects(&rule.normalized_names(), &names) {
                return Some(rule);
            }
        }

        for (id, rule) in &self.apps {
            if !looks_like_guid(id) && names.contains(&normalize_name(id)) {
                return Some(rule);
            }
        }

        None
    }

    /// Normalized names of every rule, used to avoid reporting known app data
    /// directories as orphans.
    pub fn known_names(&self) -> BTreeSet<String> {
        let mut names = BTreeSet::new();
        for rule in self.apps.values() {
            names.extend(rule.normalized_names());
            names.extend(rule.publisher_names());
        }
        names
    }

    pub fn validate_with_policy(&self, policy: &SafetyPolicy) -> Vec<RuleIssue> {
        let mut issues = Vec::new();

        for (id, rule) in &self.apps {
            if rule.name.trim().is_empty() {
                issues.push(RuleIssue {
                    app: id.clone(),
                    detail: "name cannot be empty".to_string(),
                });
            }
            for path in &rule.paths {
                if path.path.trim().is_empty() {
                    issues.push(RuleIssue {
                        app: id.clone(),
                        detail: "path rule has an empty path".to_string(),
                    });
                    continue;
                }
                if let Err(violation) = policy.check_path(&path.path) {
                    issues.push(RuleIssue {
                        app: id.clone(),
                        detail: format!("path '{}' {}", path.path, violation.reason),
                    });
                }
            }
            for registry in &rule.registry {
                if registry.key.trim().is_empty() {
                    issues.push(RuleIssue {
                        app: id.clone(),
                        detail: "registry rule has an empty key".to_string(),
                    });
                    continue;
                }
                if let Err(violation) = policy.check_registry(&registry.key) {
                    issues.push(RuleIssue {
                        app: id.clone(),
                        detail: format!("registry key '{}' {}", registry.key, violation.reason),
                    });
                }
            }
            for service in &rule.services {
                if service.name.trim().is_empty() {
                    issues.push(RuleIssue {
                        app: id.clone(),
                        detail: "service rule has an empty name".to_string(),
                    });
                }
            }
        }

        issues
    }
}

fn validate_platforms(source_name: &str, id: &str, platforms: &[String]) -> Result<(), RulesError> {
    let known = ["windows", "macos", "linux"];
    for platform in platforms {
        if !known.contains(&platform.to_ascii_lowercase().as_str()) {
            return Err(RulesError::Parse {
                source_name: source_name.to_string(),
                message: format!("rule '{id}' lists unknown platform '{platform}'"),
            });
        }
    }
    Ok(())
}

fn intersects(left: &BTreeSet<String>, right: &BTreeSet<String>) -> bool {
    left.iter().any(|value| right.contains(value))
}

fn looks_like_guid(value: &str) -> bool {
    let value = value.trim().trim_matches(['{', '}']);
    value.len() == 36 && value.chars().filter(|ch| *ch == '-').count() == 4
}

#[cfg(test)]
mod tests {
    use super::*;
    use exuvia_core::{AppSource, Architecture, UninstallInfo};

    fn app(name: &str, publisher: Option<&str>) -> InstalledApp {
        InstalledApp {
            id: format!("test:{name}"),
            name: name.to_string(),
            version: Some("1.0".to_string()),
            publisher: publisher.map(str::to_string),
            size_bytes: None,
            install_date: None,
            source: AppSource::Registry,
            architecture: Architecture::X64,
            product_code: None,
            uninstall: UninstallInfo::default(),
        }
    }

    #[test]
    fn bundled_rules_parse_and_validate() {
        let rules = RuleSet::bundled().expect("bundled rules must parse");
        assert!(!rules.is_empty());
        let issues = rules.validate_with_policy(&SafetyPolicy::windows_defaults());
        assert!(issues.is_empty(), "unexpected rule issues: {issues:?}");
    }

    #[test]
    fn finds_rules_by_name_and_publisher() {
        let rules = RuleSet::bundled().expect("bundled rules");
        let app = app("Discord", Some("Discord Inc."));
        let matched = rules.find_rule(&app).expect("discord rule");
        assert_eq!(matched.id, "discord");
    }

    #[test]
    fn finds_rules_by_alias() {
        let rules = RuleSet::bundled().expect("bundled rules");
        let app = app("Visual Studio Code", Some("Microsoft Corporation"));
        let matched = rules.find_rule(&app).expect("vscode rule");
        assert_eq!(matched.id, "vscode");
    }

    #[test]
    fn rejects_protected_paths_during_validation() {
        let text = r#"
schema = 1
[app."bad"]
name = "Bad"
[[app."bad".paths]]
path = "C:\\Windows\\System32\\bad.dll"
"#;
        let rules = RuleSet::from_toml_str("test", text).expect("parses");
        let issues = rules.validate_with_policy(&SafetyPolicy::windows_defaults());
        assert_eq!(issues.len(), 1);
        assert!(issues[0].detail.contains("protected"));
    }

    #[test]
    fn rejects_unknown_platform() {
        let text = r#"
schema = 1
[app."bad"]
name = "Bad"
platforms = ["amiga"]
"#;
        assert!(RuleSet::from_toml_str("test", text).is_err());
    }

    #[test]
    fn user_rules_override_bundled_rules() {
        let dir = tempfile::tempdir().expect("temp dir");
        fs::write(
            dir.path().join("override.toml"),
            r#"
schema = 1
version = "test"
[app."discord"]
name = "Discord Override"
"#,
        )
        .expect("write");
        let rules = RuleSet::load(&[dir.path().to_path_buf()]).expect("load");
        let rule = rules
            .apps()
            .find(|(id, _)| *id == "discord")
            .expect("discord");
        assert_eq!(rule.1.name, "Discord Override");
        assert_eq!(rules.version(), "test");
    }
}
