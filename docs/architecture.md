# Architecture

Exuvia is a Cargo workspace with a platform-independent domain core and a thin
Windows backend. The CLI, and later the GUI, share the same pipeline.

## Crates

| Crate | Responsibility |
| --- | --- |
| `exuvia-core` | Domain types, path expansion and canonicalization, name matching, safety policy |
| `exuvia-platform` | Windows discovery, residue scanners, registry access, native uninstall invocation |
| `exuvia-rules` | TOML rule schema, loading, merging, matching and validation |
| `exuvia-store` | Manifests, quarantine, registry backups, restore, history and logs |
| `exuvia-cli` | Command parsing, review output, confirmation flow and exit codes |

Dependencies point inward: platform, rules, store and CLI depend on core; the
store also uses platform registry operations. Core never touches the operating
system.

## Uninstall pipeline

1. **Discover** applications from the uninstall registry views. Entries without a
   display name, updates and system components are filtered out.
2. **Resolve** the query by id, product code, exact name or unique substring.
3. **Scan** for residue:
   - rule paths and registry keys (high confidence),
   - direct children of AppData, LocalAppData, ProgramData and Temp,
   - publisher-nested children under those roots,
   - package-family directories under `%LOCALAPPDATA%\Packages`,
   - Start Menu shortcuts,
   - HKCU/HKLM Software subkeys,
   - services whose image path points into the install directory,
   - scheduled-task XML that references the app,
   - Run/RunOnce values.
4. **Filter** every removable item through the safety policy.
5. **Review** the plan. Standard selects high confidence only; Complete adds
   medium. Low confidence is never preselected.
6. **Run** the native uninstaller unless `--no-native` was passed. If it reports
   failure, residue cleanup is aborted.
7. **Re-scan** after the native uninstaller removed files.
8. **Record** the manifest and flush it to disk before touching any item.
9. **Remove** item by item, rewriting the manifest after each one.
10. **Report** reclaimed bytes, failures and the restore command.

For apps with no uninstaller, the install directory itself becomes a
high-confidence item.

## Safety invariants

- No deletion without a validated, canonical, absolute target.
- Paths inside protected roots or equal to protected exact paths are refused.
- Registry paths matching a protected hive or prefix are refused.
- Symlinks, junctions and reparse points are never followed.
- Registry keys are exported before deletion; a failed export aborts the delete.
- Files are moved to quarantine unless `--permanent` was explicitly passed.
- Manifests are written with a temporary file, synced and atomically persisted.
- Every removal attempt is logged to `logs/exuvia.jsonl`.
- Restore refuses to overwrite an existing target.

## Rule matching

Rules are matched in this order:

1. exact product code,
2. normalized name plus normalized publisher,
3. normalized name or alias,
4. normalized rule id.

Paths from the matched rule are expanded and only included if they exist.
Heuristics supplement rules and never override a protected target.

## Windows details

- Registry access uses `winreg`; `reg.exe` is used for export and import because
  it produces standard `.reg` files.
- All spawned console processes use `CREATE_NO_WINDOW`.
- MSI entries use `msiexec /x <ProductCode> /qn /norestart` when no quiet
  uninstall string exists. Exit codes 3010 and 1641 are treated as success.
- Install locations fall back to the parent directory of `DisplayIcon`.
- Reparse-point detection uses the Windows file attributes, not just
  `is_symlink`.

## Next steps

- `exuvia-helper`: a minimal elevated process over an ACL-restricted named pipe
  for services, tasks and HKLM operations.
- MSIX/AppX discovery through `PackageManager`.
- Tauri GUI backed by the same store and pipeline.
- Signed rule updates and the release pipeline described in the PRD.
