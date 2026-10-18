use std::collections::HashSet;
use std::fs;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand, ValueEnum};
use exuvia_core::{
    default_selected, human_size, normalize_path_key, AppSource, Confidence, ExuviaError,
    InstalledApp, MatchReason, ResidueCategory, ResidueItem, ResidueKind, Result, SafetyPolicy,
    UninstallMode,
};
use exuvia_platform::{NativeUninstallOutcome, ScanOutcome};
use exuvia_rules::RuleSet;
use exuvia_store::{Manifest, RemovalStatus, Store};
use serde::Serialize;
use serde_json::json;

#[derive(Parser)]
#[command(
    name = "exuvia",
    version,
    about = "Safely remove Windows applications and the leftovers they leave behind",
    arg_required_else_help = true
)]
struct Cli {
    /// Override the data directory for manifests, quarantine, rules and logs
    #[arg(long, global = true, env = "EXUVIA_DATA_DIR", value_name = "DIR")]
    data_dir: Option<PathBuf>,

    /// Emit machine-readable JSON on stdout
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// List installed applications
    List(ListArgs),
    /// Scan an application for leftovers without changing anything
    Scan {
        /// Application name, id or product code
        query: String,
    },
    /// Uninstall an application and clean up leftovers
    Uninstall(UninstallArgs),
    /// Restore a previous uninstall from its manifest
    Restore {
        /// Manifest id shown after an uninstall
        id: String,
    },
    /// Find leftover directories that no installed application claims
    Orphans,
    /// Inspect and validate the rule database
    Rules {
        #[command(subcommand)]
        command: RulesCommand,
    },
    /// Show uninstall history
    History {
        /// Maximum number of manifests to show
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
}

#[derive(Args)]
struct ListArgs {
    /// Filter by name, publisher or id
    #[arg(long)]
    filter: Option<String>,
    /// Filter by source: registry, msi, msix, winget, scoop, chocolatey, portable
    #[arg(long)]
    source: Option<String>,
    #[arg(long, value_enum, default_value_t = SortField::Name)]
    sort: SortField,
    #[arg(long)]
    limit: Option<usize>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum SortField {
    Name,
    Size,
    Date,
    Source,
}

#[derive(Args)]
struct UninstallArgs {
    /// Application name, id or product code
    query: String,
    /// Remove medium-confidence items as well (low confidence is never preselected)
    #[arg(long)]
    complete: bool,
    /// Show exactly what would happen without changing anything
    #[arg(long)]
    dry_run: bool,
    /// Skip the interactive confirmation prompt
    #[arg(long, short = 'y')]
    yes: bool,
    /// Permanently delete files instead of quarantining them
    #[arg(long)]
    permanent: bool,
    /// Do not invoke the application's own uninstaller
    #[arg(long)]
    no_native: bool,
}

#[derive(Subcommand)]
enum RulesCommand {
    /// List rules and their sources
    List,
    /// Validate a rule file, or the active rule set when no path is given
    Validate {
        #[arg(value_name = "PATH")]
        path: Option<PathBuf>,
    },
    /// Check for rule database updates
    Update,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::from(error.exit_code())
        }
    }
}

fn run(cli: Cli) -> Result<u8> {
    let store = match &cli.data_dir {
        Some(dir) => Store::open(dir.clone())?,
        None => Store::discover()?,
    };
    let mut policy = SafetyPolicy::for_current_platform();
    policy.add_protected_root(store.root().to_path_buf());
    let rules = RuleSet::load(&[store.rules_dir()])?;

    match cli.command {
        Command::List(args) => list(&rules, args, cli.json),
        Command::Scan { query } => scan(&rules, &policy, &query, cli.json),
        Command::Uninstall(args) => uninstall(&store, &rules, &policy, args, cli.json),
        Command::Restore { id } => restore(&store, &id, cli.json),
        Command::Orphans => orphans(&rules, &policy, cli.json),
        Command::Rules { command } => rules_command(&store, &rules, &policy, command, cli.json),
        Command::History { limit } => history(&store, limit, cli.json),
    }
}

fn list(_rules: &RuleSet, args: ListArgs, json_output: bool) -> Result<u8> {
    let discovery = exuvia_platform::discover();
    let mut apps = discovery.apps;

    if let Some(filter) = args
        .filter
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        let filter = filter.to_lowercase();
        apps.retain(|app| {
            app.name.to_lowercase().contains(&filter)
                || app
                    .publisher
                    .as_deref()
                    .map(|publisher| publisher.to_lowercase().contains(&filter))
                    .unwrap_or(false)
                || app.id.to_lowercase().contains(&filter)
        });
    }

    if let Some(source) = args.source.as_deref() {
        let source: AppSource = source.parse()?;
        apps.retain(|app| app.source == source);
    }

    match args.sort {
        SortField::Name => apps.sort_by(|left, right| {
            left.name
                .to_lowercase()
                .cmp(&right.name.to_lowercase())
                .then_with(|| left.version.cmp(&right.version))
        }),
        SortField::Size => apps.sort_by(|left, right| {
            right
                .size_bytes
                .unwrap_or(0)
                .cmp(&left.size_bytes.unwrap_or(0))
        }),
        SortField::Date => apps.sort_by(|left, right| right.install_date.cmp(&left.install_date)),
        SortField::Source => apps.sort_by(|left, right| {
            left.source
                .label()
                .cmp(right.source.label())
                .then_with(|| left.name.to_lowercase().cmp(&right.name.to_lowercase()))
        }),
    }

    if let Some(limit) = args.limit {
        apps.truncate(limit);
    }

    if json_output {
        print_json(&json!({
            "schema_version": 1,
            "apps": apps,
            "warnings": discovery.warnings,
        }))?;
    } else {
        print_warnings(&discovery.warnings);
        print_app_table(&apps);
        println!("\n{} application(s).", apps.len());
    }

    Ok(0)
}

fn scan(rules: &RuleSet, policy: &SafetyPolicy, query: &str, json_output: bool) -> Result<u8> {
    let discovery = exuvia_platform::discover();
    let app = resolve_app(&discovery.apps, query)?;
    let outcome = exuvia_platform::scan_residue(app, rules, policy);

    if json_output {
        print_json(&json!({
            "schema_version": 1,
            "app": app,
            "items": outcome.items,
            "warnings": outcome.warnings,
            "selected": select_items(&outcome.items, UninstallMode::Standard),
            "totals": {
                "items": outcome.items.len(),
                "bytes": outcome.items.iter().map(|item| item.size_bytes).sum::<u64>(),
                "selected_bytes": select_items(&outcome.items, UninstallMode::Standard)
                    .iter()
                    .map(|item| item.size_bytes)
                    .sum::<u64>(),
            }
        }))?;
    } else {
        print_warnings(&discovery.warnings);
        print_scan_review(app, &outcome, UninstallMode::Standard);
    }

    Ok(0)
}

fn uninstall(
    store: &Store,
    rules: &RuleSet,
    policy: &SafetyPolicy,
    args: UninstallArgs,
    json_output: bool,
) -> Result<u8> {
    let mode = if args.complete {
        UninstallMode::Complete
    } else {
        UninstallMode::Standard
    };

    if json_output && !args.dry_run && !args.yes {
        return Err(ExuviaError::Usage(
            "--yes is required together with --json".to_string(),
        ));
    }

    let discovery = exuvia_platform::discover();
    let app = resolve_app(&discovery.apps, &args.query)?;
    let mut outcome = exuvia_platform::scan_residue(app, rules, policy);
    if !app.uninstall.has_uninstaller() {
        add_portable_install_dir(app, policy, &mut outcome);
    }

    let mut warnings = outcome.warnings.clone();
    warnings.extend(discovery.warnings.iter().cloned());

    if !json_output {
        print_scan_review(app, &outcome, mode);
    }

    let mut selected = select_items(&outcome.items, mode);

    if args.dry_run {
        if json_output {
            print_json(&json!({
                "schema_version": 1,
                "dry_run": true,
                "app": app,
                "mode": mode,
                "permanent": args.permanent,
                "selected": selected,
                "items": outcome.items,
                "warnings": warnings,
            }))?;
        } else {
            println!("Dry run: nothing was changed.");
        }
        return Ok(0);
    }

    if !args.yes {
        if !io::stdin().is_terminal() {
            return Err(ExuviaError::Usage(
                "refusing to change the system without --yes in a non-interactive session"
                    .to_string(),
            ));
        }
        if !confirm(app, &selected)? {
            println!("Cancelled.");
            return Ok(0);
        }
    }

    if !args.no_native && app.uninstall.has_uninstaller() {
        match exuvia_platform::run_native_uninstall(app)? {
            NativeUninstallOutcome::Ran {
                command,
                exit_code,
                success,
            } => {
                if !json_output {
                    println!(
                        "\nRan native uninstaller: {command} (exit {})",
                        exit_code
                            .map(|code| code.to_string())
                            .unwrap_or_else(|| "unknown".to_string())
                    );
                }
                if !success {
                    return Err(ExuviaError::Partial(format!(
                        "the application's uninstaller failed (exit {}); residue cleanup was not started",
                        exit_code
                            .map(|code| code.to_string())
                            .unwrap_or_else(|| "unknown".to_string())
                    )));
                }

                outcome = exuvia_platform::scan_residue(app, rules, policy);
                warnings.extend(outcome.warnings.iter().cloned());
                selected = select_items(&outcome.items, mode);
            }
            NativeUninstallOutcome::NotAvailable => {}
        }
    }

    let manifest = store.create_manifest(
        app,
        mode,
        args.permanent,
        selected.clone(),
        warnings.clone(),
    )?;
    let mut manifest = manifest;
    let stats = store.apply(&mut manifest, policy)?;

    if json_output {
        print_json(&json!({
            "schema_version": 1,
            "manifest_id": manifest.id,
            "app": app,
            "mode": mode,
            "permanent": args.permanent,
            "selected": selected.len(),
            "quarantined": stats.quarantined,
            "deleted": stats.deleted,
            "reported": stats.reported,
            "skipped": stats.skipped,
            "failed": stats.failed,
            "reclaimed_bytes": stats.reclaimed_bytes,
            "restore_command": format!("exuvia restore {}", manifest.id),
            "state": manifest.state,
        }))?;
    } else {
        println!(
            "\nRemoved {} item(s), reclaimed {}. Manifest: {}",
            stats.quarantined + stats.deleted,
            human_size(stats.reclaimed_bytes),
            manifest.id
        );
        if stats.failed > 0 {
            println!(
                "{} item(s) failed. See the manifest with `exuvia history` and restore with `exuvia restore {}`.",
                stats.failed, manifest.id
            );
        } else {
            println!("Undo with: exuvia restore {}", manifest.id);
        }
    }

    Ok(if stats.failed > 0 { 3 } else { 0 })
}

fn restore(store: &Store, id: &str, json_output: bool) -> Result<u8> {
    let report = store.restore(id)?;
    if json_output {
        print_json(&json!({
            "schema_version": 1,
            "manifest_id": report.manifest_id,
            "restored": report.restored,
            "failed": report.failed,
            "errors": report.errors,
        }))?;
    } else {
        println!(
            "Restored {} item(s) from {}{}.",
            report.restored,
            report.manifest_id,
            if report.failed > 0 {
                format!("; {} item(s) failed", report.failed)
            } else {
                String::new()
            }
        );
        for error in &report.errors {
            eprintln!("  {error}");
        }
    }
    Ok(if report.failed > 0 { 3 } else { 0 })
}

fn orphans(rules: &RuleSet, policy: &SafetyPolicy, json_output: bool) -> Result<u8> {
    let discovery = exuvia_platform::discover();
    let outcome = exuvia_platform::scan_orphans(&discovery.apps, rules, policy);

    if json_output {
        print_json(&json!({
            "schema_version": 1,
            "items": outcome.items,
            "warnings": outcome.warnings,
        }))?;
    } else {
        print_warnings(&outcome.warnings);
        if outcome.items.is_empty() {
            println!("No orphaned directories found.");
        } else {
            println!("Low-confidence orphan candidates (never preselected):\n");
            print_items(&outcome.items, &HashSet::new());
            println!(
                "\n{} candidate(s). Review before removing anything.",
                outcome.items.len()
            );
        }
    }

    Ok(0)
}

fn rules_command(
    store: &Store,
    rules: &RuleSet,
    policy: &SafetyPolicy,
    command: RulesCommand,
    json_output: bool,
) -> Result<u8> {
    match command {
        RulesCommand::List => {
            if json_output {
                let apps: Vec<_> = rules
                    .apps()
                    .map(|(id, rule)| {
                        json!({
                            "id": id,
                            "name": rule.name,
                            "publisher": rule.publisher,
                            "paths": rule.paths.len(),
                            "registry": rule.registry.len(),
                            "services": rule.services.len(),
                            "tasks": rule.tasks.len(),
                        })
                    })
                    .collect();
                print_json(&json!({
                    "schema_version": 1,
                    "version": rules.version(),
                    "sources": rules.sources(),
                    "apps": apps,
                }))?;
            } else {
                println!(
                    "Rule database {} ({} app rule(s))",
                    rules.version(),
                    rules.len()
                );
                for source in rules.sources() {
                    println!("  source: {source}");
                }
                println!();
                for (id, rule) in rules.apps() {
                    println!(
                        "{:<24} {:<32} paths:{} registry:{}",
                        id,
                        truncate(&rule.name, 32),
                        rule.paths.len(),
                        rule.registry.len()
                    );
                }
            }
            Ok(0)
        }
        RulesCommand::Validate { path } => {
            let (rule_set, label) = match path {
                Some(path) => {
                    let text = fs::read_to_string(&path).map_err(|error| {
                        ExuviaError::io(format!("failed to read {}", path.display()), error)
                    })?;
                    let label = path.display().to_string();
                    (RuleSet::from_toml_str(&label, &text)?, label)
                }
                None => (rules.clone(), "active rule set".to_string()),
            };

            let issues = rule_set.validate_with_policy(policy);
            if json_output {
                print_json(&json!({
                    "schema_version": 1,
                    "source": label,
                    "apps": rule_set.len(),
                    "valid": issues.is_empty(),
                    "issues": issues,
                }))?;
            } else if issues.is_empty() {
                println!(
                    "{label}: valid ({} app rule(s), version {}).",
                    rule_set.len(),
                    rule_set.version()
                );
            } else {
                println!("{label}: {} issue(s) found:", issues.len());
                for issue in &issues {
                    println!("  [{}] {}", issue.app, issue.detail);
                }
            }

            Ok(if issues.is_empty() { 0 } else { 5 })
        }
        RulesCommand::Update => {
            if json_output {
                print_json(&json!({
                    "schema_version": 1,
                    "bundled_version": rules.version(),
                    "apps": rules.len(),
                    "user_rules_dir": store.rules_dir(),
                    "updated": false,
                    "message": "no remote rule channel is configured in this build",
                }))?;
            } else {
                println!(
                    "Bundled rules: {} ({} app rule(s)).",
                    rules.version(),
                    rules.len()
                );
                println!(
                    "No remote rule channel is configured in this build. Add signed TOML files to {} to extend the database.",
                    store.rules_dir().display()
                );
            }
            Ok(0)
        }
    }
}

fn history(store: &Store, limit: usize, json_output: bool) -> Result<u8> {
    let mut manifests = store.list_manifests()?;
    manifests.truncate(limit);

    if json_output {
        print_json(&json!({
            "schema_version": 1,
            "manifests": manifests,
        }))?;
    } else if manifests.is_empty() {
        println!("No uninstall history yet.");
    } else {
        print_manifest_table(&manifests);
    }

    Ok(0)
}

fn confirm(app: &InstalledApp, selected: &[ResidueItem]) -> Result<bool> {
    let bytes: u64 = selected.iter().map(|item| item.size_bytes).sum();
    print!(
        "\nRemove {} item(s) ({}) for {}? [y/N] ",
        selected.len(),
        human_size(bytes),
        app.name
    );
    io::stdout()
        .flush()
        .map_err(|error| ExuviaError::io("failed to write prompt", error))?;

    let mut answer = String::new();
    io::stdin()
        .read_line(&mut answer)
        .map_err(|error| ExuviaError::io("failed to read confirmation", error))?;
    Ok(matches!(
        answer.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

fn select_items(items: &[ResidueItem], mode: UninstallMode) -> Vec<ResidueItem> {
    items
        .iter()
        .filter(|item| default_selected(item, mode))
        .cloned()
        .collect()
}

fn add_portable_install_dir(app: &InstalledApp, policy: &SafetyPolicy, outcome: &mut ScanOutcome) {
    let Some(location) = app.uninstall.install_location.as_ref() else {
        return;
    };
    if !location.exists() {
        return;
    }
    let key = normalize_path_key(location);
    if outcome
        .items
        .iter()
        .any(|item| normalize_path_key(Path::new(&item.path)) == key)
    {
        return;
    }

    let item = ResidueItem {
        kind: ResidueKind::Dir,
        category: ResidueCategory::Application,
        path: location.to_string_lossy().to_string(),
        display_path: location.to_string_lossy().to_string(),
        size_bytes: exuvia_platform::path_size(location),
        confidence: Confidence::High,
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

fn resolve_app<'a>(apps: &'a [InstalledApp], query: &str) -> Result<&'a InstalledApp> {
    let query = query.trim();
    if query.is_empty() {
        return Err(ExuviaError::Usage(
            "an application name, id or product code is required".to_string(),
        ));
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
    let mut candidates = Vec::new();
    for app in matches.iter().take(8) {
        candidates.push(format!("{} [{}] ({})", app.name, app.source, app.id));
    }
    if matches.len() > 8 {
        candidates.push(format!("... and {} more", matches.len() - 8));
    }
    ExuviaError::AmbiguousApp {
        query: query.to_string(),
        candidates: candidates.join("; "),
    }
}

fn print_app_table(apps: &[InstalledApp]) {
    if apps.is_empty() {
        println!("No installed applications found.");
        return;
    }
    println!(
        "{:<42} {:<16} {:<10} {:>10}  INSTALLED",
        "NAME", "VERSION", "SOURCE", "SIZE"
    );
    println!("{}", "-".repeat(96));
    for app in apps {
        println!(
            "{:<42} {:<16} {:<10} {:>10}  {}",
            truncate(&app.name, 42),
            truncate(app.version.as_deref().unwrap_or("-"), 16),
            truncate(app.source.label(), 10),
            app.size_bytes
                .map(human_size)
                .unwrap_or_else(|| "-".to_string()),
            app.install_date.as_deref().unwrap_or("-"),
        );
    }
}

fn print_scan_review(app: &InstalledApp, outcome: &ScanOutcome, mode: UninstallMode) {
    print_warnings(&outcome.warnings);
    let selected = select_items(&outcome.items, mode);
    let selected_keys: HashSet<String> = selected
        .iter()
        .map(|item| format!("{:?}|{}", item.kind, item.path))
        .collect();

    println!(
        "{}  [{}]  {}",
        app.name,
        app.source,
        app.uninstall
            .install_location
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "install path unknown".to_string())
    );
    if !outcome.items.is_empty() {
        println!();
        print_items(&outcome.items, &selected_keys);
    }
    if outcome.items.iter().any(|item| !item.removable) {
        println!("Items marked '-' are report-only in this build.");
    }
    print_plan_totals(&selected, outcome.items.len());
}

fn print_items(items: &[ResidueItem], selected: &HashSet<String>) {
    for category in [
        ResidueCategory::Application,
        ResidueCategory::Preferences,
        ResidueCategory::Caches,
        ResidueCategory::Logs,
        ResidueCategory::Services,
        ResidueCategory::Registry,
    ] {
        let group: Vec<&ResidueItem> = items
            .iter()
            .filter(|item| item.category == category)
            .collect();
        if group.is_empty() {
            continue;
        }
        println!("{}:", category.label());
        for item in group {
            let key = format!("{:?}|{}", item.kind, item.path);
            let marker = if !item.removable {
                "-"
            } else if selected.contains(&key) {
                "x"
            } else {
                " "
            };
            println!(
                "  [{marker}] [{:<6}] {:<62} {:>10}  {}",
                item.confidence.label(),
                truncate(&item.display_path, 62),
                if item.size_bytes > 0 {
                    human_size(item.size_bytes)
                } else {
                    "-".to_string()
                },
                item.reason.describe()
            );
            if let Some(detail) = &item.detail {
                println!("        {detail}");
            }
        }
        println!();
    }
}

fn print_plan_totals(selected: &[ResidueItem], total_items: usize) {
    let bytes: u64 = selected.iter().map(|item| item.size_bytes).sum();
    println!(
        "{total_items} item(s) detected; {} selected ({}).",
        selected.len(),
        human_size(bytes)
    );
}

fn print_manifest_table(manifests: &[Manifest]) {
    println!(
        "{:<26} {:<38} {:<10} {:>5} {:>12}  STATE",
        "MANIFEST", "APPLICATION", "MODE", "ITEMS", "RECLAIMED"
    );
    println!("{}", "-".repeat(120));
    for manifest in manifests {
        let reclaimed: u64 = manifest
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
        println!(
            "{:<26} {:<38} {:<10} {:>5} {:>12}  {:?}",
            manifest.id,
            truncate(&manifest.app.name, 38),
            manifest.mode.label(),
            manifest.records.len(),
            human_size(reclaimed),
            manifest.state
        );
    }
}

fn print_warnings(warnings: &[String]) {
    for warning in warnings {
        eprintln!("warning: {warning}");
    }
}

fn print_json(value: &impl Serialize) -> Result<()> {
    let stdout = io::stdout();
    let mut lock = stdout.lock();
    serde_json::to_writer_pretty(&mut lock, value)?;
    writeln!(lock).map_err(|error| ExuviaError::io("failed to write JSON output", error))
}

fn truncate(text: &str, width: usize) -> String {
    if text.chars().count() <= width {
        return text.to_string();
    }
    if width <= 3 {
        return text.chars().take(width).collect();
    }
    let mut result: String = text.chars().take(width - 3).collect();
    result.push_str("...");
    result
}
