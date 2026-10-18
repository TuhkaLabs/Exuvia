# Changelog

All notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/) and the project uses Semantic
Versioning.

## [0.1.0] - 2026-10-19

### Added

- Rust workspace with core, platform, rules, store and CLI crates.
- Windows application discovery from HKLM, WOW6432Node and HKCU uninstall keys.
- Layered rule and heuristic residue scanning for files, registry keys,
  shortcuts, services, scheduled tasks and startup entries.
- Hard-coded safety policy with canonicalization, denylist and reparse-point
  refusal.
- Quarantine, atomic manifests, JSON-lines logs, history and restore.
- CLI commands: `list`, `scan`, `uninstall`, `restore`, `orphans`, `rules`,
  `history`, with JSON output, dry-run and documented exit codes.
- Bundled CC0 rule database and TOML validator.
- CI workflow for formatting, clippy, tests and rule validation.

### Known limitations

- GUI, MSIX/AppX and package-manager discovery are not implemented yet.
- Service, scheduled-task and startup removal is report-only until the elevated
  helper ships.
- Rule updates and release signing are not implemented.
