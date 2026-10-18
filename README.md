# Exuvia

Exuvia is a fast, safe, open-source uninstaller for Windows. It removes an
application and the residue it leaves behind: caches, preferences, logs,
registry keys, shortcuts and reported background services.

This repository is at **v0.1.0 (M1 alpha)**. The Rust core and CLI are usable on
Windows today; the GUI, elevated helper and packaging pipeline are next.

## Status

Implemented:

- Application discovery from the HKLM, HKLM WOW6432Node and HKCU Uninstall keys,
  including MSI product codes, install size, location and uninstall strings.
- Layered residue detection: a TOML rule database first, then filesystem,
  registry, shortcut, service, scheduled-task and startup-entry heuristics.
- Hard-coded denylist with path canonicalization, reparse-point refusal and
  registry-hive protections.
- Quarantine, atomic JSON manifests, structured JSON-lines logging, history and
  one-command restore.
- Dry-run, `--json` output, documented exit codes and a scriptable CLI.
- Community rule format with validation against the safety policy.

Not yet implemented:

- Tauri GUI and review screen.
- MSIX/AppX discovery, winget/Scoop/Chocolatey inventory.
- Elevated helper for per-machine services, tasks and HKLM writes.
- Signed rule updates, Authenticode signing and the release pipeline.
- Orphan-scan confirmation workflows and secure delete.

Track the roadmap in the product requirements document at the repository root.

## Build and test

```powershell
cargo build --release
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
```

The binary is `target\release\exuvia.exe`.

## Usage

```powershell
exuvia list
exuvia list --filter discord --json
exuvia scan "Discord"
exuvia uninstall "Discord" --dry-run
exuvia uninstall "Discord" --yes
exuvia uninstall "Discord" --complete --dry-run
exuvia history
exuvia restore 20261019-012345-abcdef
exuvia orphans
exuvia rules list
exuvia rules validate rules\bundled.toml
```

Selection rules:

- Standard mode preselects only high-confidence items and leaves rule data
  marked `user-data` alone.
- Complete mode adds medium-confidence items. Low-confidence matches are never
  preselected in either mode.
- Items marked `-` are reported but not removable until the elevated helper
  ships.
- Without `--yes` the CLI prompts before changing anything. Non-interactive
  sessions must pass `--yes`.

Exit codes: `0` success, `1` general error, `2` usage error, `3` partial
success, `4` permission denied, `5` blocked by the safety policy.

## Data layout

The store defaults to `%LOCALAPPDATA%\Exuvia` and can be overridden with
`--data-dir` or `EXUVIA_DATA_DIR`:

```
manifests/    one JSON manifest per uninstall
quarantine/   files moved out of the way, indexed by manifest
registry/     .reg backups taken before a key is deleted
logs/         exuvia.jsonl, rotated at 5 MiB
rules/        optional user-supplied TOML rules
```

A manifest is written and flushed before any item is touched, and is rewritten
after every item so an interrupted run can be inspected and restored.

## Safety model

- Every filesystem target is expanded, made absolute and canonicalized before
  it is checked against the denylist.
- Symlinks, junctions and reparse points are never followed or removed.
- Windows, System32, WinSxS, WindowsApps, Common Files, user document folders,
  AppData roots, drive roots and Exuvia's own store are protected.
- Critical registry hives and `HKLM/HKCU\Software\Microsoft\Windows` are
  protected. Registry keys are exported to `.reg` before deletion.
- Files are quarantined by default. `--permanent` is opt-in and cannot be
  restored.
- Rule files targeting protected paths are rejected by `rules validate`.

See `docs/architecture.md` for the pipeline and invariants.

## Project layout

```
crates/exuvia-core/      domain model, path handling, safety policy
crates/exuvia-platform/  Windows registry, discovery, scanning, uninstaller
crates/exuvia-rules/     rule schema, loader, matching, validation
crates/exuvia-store/     manifests, quarantine, restore, logging
crates/exuvia-cli/       clap-based CLI
rules/                   community rule database (CC0)
docs/                    architecture notes
```

## Contributing

Read `CONTRIBUTING.md`. Rule contributions use the TOML format documented in
`rules/README.md` and must pass:

```powershell
cargo run -p exuvia-cli -- rules validate rules/bundled.toml
```

## License

Code is licensed under either of MIT or Apache-2.0, at your option. The rule
database is dedicated to the public domain under CC0-1.0.
