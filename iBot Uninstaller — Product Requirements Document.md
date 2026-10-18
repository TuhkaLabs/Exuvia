# Exuvia — Product Requirements Document

Version 1.0 · Draft · October 19, 2026 · Implementation language: Rust · Windows-first · Open source

## 1. Overview

Exuvia is a fast, safe, open-source desktop utility for Windows that completely removes applications and the leftover files they scatter across a system (caches, preferences, logs, services, registry entries, scheduled tasks). It is built in Rust for memory safety, native speed and a small single-binary footprint, and ships as both a GUI app and a scriptable CLI.

**Assumptions made in this draft** (confirm or correct in Section 19): v1.0 targets Windows 10 (22H2) and Windows 11 on x64 and ARM64, with macOS and Linux as later ports; the GUI uses Tauri with a web front end over a Rust core; the whole project is open source (MIT OR Apache-2.0), has no telemetry by default, and ships through an automated GitHub Actions release pipeline.

## 2. Problem Statement

Standard uninstall flows leave residue behind. Over time this wastes disk space, leaves orphaned background services and startup entries, slows boot, and creates privacy exposure from retained user data. Existing tools are either slow, closed-source, Electron-heavy, single-platform, risky (deleting the wrong files), or bundled with upsell and telemetry.

## 3. Goals and Non-Goals

### Goals

- Fully remove an application and its leftovers (files, registry keys, services, scheduled tasks, startup entries) on Windows 10 22H2 and Windows 11, x64 and ARM64, in one operation.
- Never delete anything the user did not approve, and make every removal recoverable by default.
- Scan an installed-application inventory in under 2 seconds and a leftover search for one app in under 5 seconds on a typical SSD machine.
- Provide one Rust core shared by GUI, CLI and any future integrations.
- Be a genuinely open-source project: permissive license, public roadmap, welcoming contribution flow and a community-maintained rule database.
- Publish through a fully automated CI/CD pipeline: a version tag builds, tests, signs and releases to GitHub Releases, winget, Scoop and Chocolatey with no manual steps.
- Run with a small footprint: idle memory under 50 MB, installer under 15 MB.

### Non-Goals (v1.0)

- General system "cleaner" or registry optimizer functionality unrelated to a specific app.
- Antivirus or malware removal.
- macOS, Linux and mobile support in v1.0 (the platform layer stays behind traits so ports can follow).
- Managing OS-protected components (Windows system apps, Windows Update components, Microsoft-signed drivers).
- Cloud sync or accounts.

## 4. Target Users and Personas

| Persona | Description | Key need |
| --- | --- | --- |
| Everyday user | Non-technical, wants a clean machine | One-click, safe, clear explanations |
| Power user / developer | Installs and removes many tools, runtimes, SDKs | Speed, CLI, batch mode, dry-run |
| IT administrator | Manages fleets of machines | Silent mode, exit codes, JSON output, logs |
| Privacy-conscious user | Wants no data left behind | Secure delete option, full residue listing |

## 5. Success Metrics

- Leftover-detection recall of at least 95% on a curated benchmark of 100 popular apps per platform.
- False-positive deletion rate of 0% on the benchmark (no file removed that belongs to another app or the OS).
- Crash-free sessions above 99.5%.
- Median time from app selection to completed uninstall under 15 seconds for typical apps.
- Reclaimed disk space reported accurately within 1% of actual.
- Task success rate in usability tests of at least 90% without help.

## 6. Scope and Feature Summary

| Area | v1.0 | v1.x / later |
| --- | --- | --- |
| Installed app inventory (Win32, MSI, MSIX/AppX, winget, Scoop, Chocolatey) | Yes | Smarter portable app detection |
| Leftover scan and removal | Yes | Heuristic learning from community rules |
| Drag-and-drop uninstall | Yes | Explorer right-click context menu |
| Quarantine and restore | Yes | Scheduled auto-purge policies |
| CLI with JSON output | Yes | Fleet agent (Intune / MDM) |
| Startup and background item manager | Basic | Full autostart editor |
| Batch uninstall | Yes | Profiles / presets |
| Secure delete | Optional | SSD-aware modes |
| Open-source setup (license, docs, contribution flow) | Yes | Governance board |
| CI/CD with signed releases, winget, Scoop, Chocolatey | Yes | Microsoft Store listing |
| macOS and Linux ports | No | Yes |

## 7. Functional Requirements

Priority: P0 = must ship, P1 = should ship, P2 = nice to have.

### 7.1 Application Discovery

- **FR-1 (P0)** Enumerate installed applications from the HKLM and HKCU Uninstall keys (including WOW6432Node), the Windows Installer (MSI) product database, MSIX/AppX packages via the PackageManager API, and the winget, Scoop and Chocolatey package lists.
- **FR-2 (P0)** Display name, version, publisher, install size, install date, install location and source (registry, MSI, MSIX, winget, Scoop, Chocolatey, portable).
- **FR-3 (P0)** Search, sort and filter the inventory (by size, date, name, source, architecture).
- **FR-4 (P1)** Detect running processes and services of the target app (and processes locking its files via the Restart Manager API) and offer to stop them before removal.
- **FR-5 (P1)** Cache the inventory and refresh incrementally using registry change notifications and filesystem watchers.

### 7.2 Uninstall Execution

- **FR-6 (P0)** Invoke the app's own uninstaller where it exists: MSI (`msiexec /x` with the ProductCode), EXE installers (`QuietUninstallString` first, then `UninstallString`), MSIX/AppX removal, and `winget`, `scoop` or `choco` uninstall for apps those managers installed. Then proceed to residue cleanup.
- **FR-7 (P0)** When no uninstaller exists (portable apps, zip installs), remove the install directory directly.
- **FR-8 (P0)** Support Standard mode (keep user data like documents and configs the user flags as valuable) and Complete mode (remove everything detected).
- **FR-9 (P1)** Batch uninstall multiple apps in a queue with per-app results.
- **FR-10 (P1)** Resumable operations: if interrupted, the next launch offers to resume or roll back. Files locked by the system are scheduled for removal at next reboot.

### 7.3 Leftover Detection

- **FR-11 (P0)** Scan known Windows locations for residue associated with the target app:
  - File system: `%APPDATA%`, `%LOCALAPPDATA%`, `%LOCALAPPDATA%\Packages`, `%PROGRAMDATA%`, Program Files and Program Files (x86), `%TEMP%`, Start Menu and Desktop shortcuts.
  - Registry: `HKCU\Software`, `HKLM\Software` (including WOW6432Node), file associations and COM/CLSID entries, App Paths, `Run` and `RunOnce` keys, uninstall entries.
  - System objects: services, scheduled tasks, shell extensions, firewall rules, environment variables and PATH entries. Drivers installed by the app are reported but never removed automatically.
- **FR-12 (P0)** Match using a layered strategy: exact ProductCode, UpgradeCode, publisher or MSIX package family name (high confidence), normalized name match (medium), fuzzy heuristic match (low, never pre-selected).
- **FR-13 (P0)** Show a confidence level and the reason for each match; pre-select only high-confidence items.
- **FR-14 (P0)** Maintain an extensible, community-contributed rule database (TOML) describing per-app known paths and registry keys, shipped with the app and updatable independently of the binary.
- **FR-15 (P1)** Detect leftovers from apps already uninstalled (orphan scan).

### 7.4 Safety and Recovery

- **FR-16 (P0)** Maintain a hard-coded and rule-based protected-path denylist (Windows, System32, WinSxS, WindowsApps system packages, other apps' data, user documents unless explicitly selected). Protected paths can never be removed, even in Complete mode.
- **FR-17 (P0)** Default removal moves files to an Exuvia quarantine area (or the Recycle Bin where appropriate) instead of permanent deletion. Permanent delete requires an explicit option.
- **FR-18 (P0)** Every uninstall produces a manifest (what was removed, original paths, sizes, hashes, registry values) enabling one-click restore within a configurable retention period (default 30 days).
- **FR-19 (P0)** Dry-run mode that lists exactly what would happen without changing anything.
- **FR-20 (P0)** Resolve symlinks, junctions, reparse points and 8.3 short names, and canonicalize paths before any deletion, to prevent traversal attacks and out-of-scope removal.
- **FR-21 (P0)** Export every registry key to a `.reg` backup before modifying it, and offer an optional System Restore point for Complete mode.
- **FR-22 (P2)** Secure delete (multi-pass overwrite) for HDDs, with a clear note that it is not reliable on SSDs.

### 7.5 Privilege Handling

- **FR-23 (P0)** Run unprivileged by default; request elevation through UAC only for items that need it, via a separate minimal helper process.
- **FR-24 (P0)** The privileged helper accepts only a narrow, validated command set (remove path, remove service, remove registry key) and re-validates every path against the denylist.

### 7.6 Startup and Background Items

- **FR-25 (P1)** List services, scheduled tasks, `Run` keys, Startup folder items and Task Manager startup entries with their owning app, and allow disabling or removing them.

### 7.7 Reporting and Logging

- **FR-26 (P0)** Show a post-uninstall summary: items removed, space reclaimed, failures with reasons.
- **FR-27 (P0)** Structured local log (JSON lines) with rotation; no data leaves the machine.
- **FR-28 (P1)** Export report as JSON or CSV.

### 7.8 CLI

- **FR-29 (P0)** Commands: `exuvia list`, `exuvia scan <app>`, `exuvia uninstall <app> [--complete] [--dry-run] [--yes] [--permanent]`, `exuvia restore <manifest-id>`, `exuvia orphans`, `exuvia rules update`, `exuvia history`.
- **FR-30 (P0)** `--json` output for every command and stable, documented exit codes (0 success, 1 general error, 2 usage error, 3 partial success, 4 permission denied, 5 blocked by safety policy).
- **FR-31 (P1)** Non-interactive/silent mode for scripts and MDM tooling.

### 7.9 GUI

- **FR-32 (P0)** App list view with search, sort, filter and size bars.
- **FR-33 (P0)** Uninstall review screen grouping residue by category (Application, Preferences, Caches, Logs, Services, Registry) with per-item checkboxes, sizes and confidence badges.
- **FR-34 (P0)** Progress screen with cancel support and final summary.
- **FR-35 (P1)** Drag-and-drop an app onto the window to start an uninstall.
- **FR-36 (P1)** History and restore screen.
- **FR-37 (P1)** Light/dark theme, keyboard navigation, screen reader support, localization framework (English at launch, Finnish and Bengali as early candidates).

## 8. Non-Functional Requirements

| Category | Requirement |
| --- | --- |
| Compatibility | Windows 10 22H2 and Windows 11; x64 and ARM64 native builds |
| Performance | Inventory scan < 2 s (500 apps, SSD); leftover scan < 5 s per app; UI never blocks (all I/O async) |
| Footprint | Idle RAM < 50 MB; installer < 15 MB; cold start < 1 s |
| Reliability | No data loss on crash; atomic manifest writes; resumable operations |
| Safety | Zero unauthorized deletions; denylist enforced in both unprivileged and privileged paths |
| Security | Memory-safe core; `unsafe` confined to audited Win32 FFI modules; Authenticode-signed binaries and signed rule updates |
| Privacy | No telemetry by default; opt-in anonymous crash reports only |
| Portability | Single codebase; platform differences behind traits so macOS and Linux can follow |
| Openness | MIT OR Apache-2.0; reproducible, locked builds; every release has an SBOM and build provenance |
| Accessibility | WCAG 2.1 AA for the GUI |
| Maintainability | Clippy-clean, `cargo deny` and `cargo audit` in CI, > 80% coverage on core crate |

## 9. Technical Architecture (Rust)

### 9.1 Workspace Layout

```
exuvia/
├─ crates/
│  ├─ exuvia-core/      # domain model, scan engine, rule matching, safety policy
│  ├─ exuvia-platform/  # traits + Windows implementation (macOS/Linux stubs later)
│  │   └─ windows/      # registry, MSI, MSIX/AppX, services, tasks (windows-rs)
│  ├─ exuvia-rules/     # rule DB loader, verifier, updater
│  ├─ exuvia-store/     # manifests, quarantine, history (SQLite via rusqlite)
│  ├─ exuvia-helper/    # elevated helper (UAC), minimal surface
│  ├─ exuvia-cli/       # clap-based CLI
│  └─ exuvia-gui/       # Tauri backend commands + web UI (WebView2)
├─ rules/               # community-maintained app rules (TOML, CC0)
├─ installer/           # WiX v4 MSI, MSIX manifest, winget + Scoop manifests
├─ .github/             # workflows, issue forms, CODEOWNERS, dependabot
├─ docs/                # mdBook site, RFCs, architecture notes
├─ tests/               # integration tests + fixture images
└─ xtask/               # build, packaging, signing helpers
```

### 9.2 Key Crates

| Purpose | Crate |
| --- | --- |
| Async runtime | tokio |
| CLI | clap |
| GUI shell | tauri (WebView2) |
| Parallel FS walk | walkdir, ignore, rayon |
| FS watching | notify |
| Serialization | serde, serde\_json, toml |
| Storage | rusqlite (bundled) |
| Windows APIs | windows (windows-rs), winreg, windows-service |
| Recycle Bin | trash |
| Errors / logging | thiserror, anyhow, tracing, tracing-subscriber |
| Fuzzy matching | strsim, unicode-normalization |
| Hashing / signing | blake3, ed25519-dalek |
| Testing | proptest, insta, tempfile, assert\_cmd |
| Release tooling | cargo-dist or xtask, cargo-wix (WiX v4), release-plz, cargo-cyclonedx |

### 9.3 Core Abstractions

```rust
pub trait AppProvider {
    fn discover(&self) -> Result<Vec<InstalledApp>>;
    fn native_uninstall(&self, app: &InstalledApp, opts: &UninstallOpts) -> Result<()>;
}

pub trait ResidueScanner {
    fn scan(&self, app: &InstalledApp, rules: &RuleSet) -> Result<Vec<ResidueItem>>;
}

pub trait Remover {
    fn remove(&self, item: &ResidueItem, mode: RemoveMode) -> Result<RemovalRecord>;
}

pub struct ResidueItem {
    pub kind: ResidueKind,        // File, Dir, RegistryKey, Service, LaunchItem...
    pub path: CanonicalPath,
    pub size: u64,
    pub confidence: Confidence,   // High | Medium | Low
    pub reason: MatchReason,
}
```

### 9.4 Uninstall Pipeline

1. Resolve target app and gather metadata.
2. Terminate running processes (with consent).
3. Run the native uninstaller or package manager command.
4. Run the residue scan (rules, then heuristics).
5. Filter results through the safety policy (denylist, canonicalization).
6. Present for review, or auto-select high confidence in silent mode.
7. Write the manifest, then move items to quarantine.
8. Verify removal, produce the report, schedule quarantine purge.

Steps 7 and 8 are transactional: the manifest is written and fsynced before any item is touched.

### 9.5 Privilege Separation

The GUI and CLI run as the invoking user. A separate `exuvia-helper` binary is launched on demand with elevated rights and communicates over an authenticated local IPC channel (a Windows named pipe restricted by ACL to the invoking user). It exposes only a fixed set of typed commands, rejects any path outside the validated scope, and exits when idle.

### 9.6 Rule Database Format

```toml
[app."Example.Editor"]
name = "Example Editor"
publisher = "Example Corp"
platforms = ["windows"]   # macos / linux planned

[[app."Example.Editor".paths]]
path = "%APPDATA%\\ExampleEditor"
kind = "user-data"      # user-data | cache | config | log
confidence = "high"

[[app."Example.Editor".registry]]
key = "HKCU\\Software\\ExampleCorp\\Editor"
kind = "config"
confidence = "high"
```

Rules are signed (Ed25519), versioned, and verified before use. Unsigned or tampered updates are rejected.

## 10. Windows Details and Future Platforms

### Windows

- Support Windows 10 22H2 and Windows 11 on x64 and ARM64, with per-user and per-machine installs of Exuvia itself.
- Handle MSI (`msiexec /x`), EXE uninstall strings (including quiet-switch detection), MSIX/AppX (PackageManager APIs) and portable apps.
- Scope registry edits to keys referencing the app's publisher and product identifiers, and export them first.
- Use long-path (`\\?\`) support, the Restart Manager for locked files, and removal at next reboot when needed.
- Tauri uses the WebView2 runtime; the installer bootstraps it when missing.
- Reduce SmartScreen and antivirus false positives: Authenticode signing, no packers, publish hashes, and submit releases to Microsoft for analysis.

### Future: macOS (post-v1.0)

- Respect SIP and TCC: request Full Disk Access with a clear explanation; degrade gracefully without it.
- Use bundle identifiers as the primary matching key. Handle sandbox containers and group containers.
- Notarized, hardened-runtime build; helper installed via SMAppService.

### Future: Linux (post-v1.0)

- Prefer the distro package manager and respect dependency and orphan handling; never force-remove packages that others depend on without a warning.
- Flatpak and Snap data directories handled via their own CLIs first.
- Packaging: .deb, .rpm, AppImage and Flatpak.

## 11. Security and Threat Model

| Threat | Mitigation |
| --- | --- |
| Deleting the wrong path (bug or crafted app name) | Canonicalization, denylist, scope validation, quarantine-by-default |
| Symlink / junction traversal | Resolve and re-check before every operation; no following reparse points during delete |
| Malicious rule contribution or update | PR review with CODEOWNERS, automated rule validator, signature verification, version pinning, rollback |
| Privilege escalation through the helper | Minimal typed command set, path revalidation, authenticated named-pipe IPC with ACL, short-lived process |
| Compromised release pipeline | Pinned Action SHAs, protected `release` environment with reviewers, OIDC instead of long-lived keys, build provenance attestation |
| Local tampering with manifests | Integrity hashes, user-only permissions |
| Supply-chain compromise | `cargo audit`, `cargo deny`, locked dependencies, Dependabot, SBOM per release, signed releases |

## 12. UX Principles

- Show, don't surprise: nothing is removed that was not previewed (except in explicit silent mode).
- Plain language for confidence and reasons ("Matches bundle ID com.example.editor").
- Safe by default, powerful on request.
- Undo is always visible after a removal.

### Primary Flow

1. User opens Exuvia, or drags an app onto it, or runs `exuvia uninstall <app>`.
2. Exuvia scans and shows app info plus detected leftovers grouped by category.
3. User reviews and adjusts the selection, then confirms.
4. Exuvia uninstalls, quarantines, and shows a summary with an Undo action.

## 13. Testing and Quality Strategy

- **Unit tests** for matching, rule parsing, path canonicalization and denylist logic, including property-based tests (`proptest`) for the safety policy.
- **Fixture-based integration tests** that build fake installed-app environments in temp directories and fake registry hives, and assert exact removal sets via snapshot tests (`insta`).
- **Windows CI matrix**: Windows Server 2022, Windows 11 and Windows 11 ARM runners, plus clean-VM end-to-end tests that install real apps and uninstall them.
- **Benchmark suite** of 100 real apps tracking recall and false positives per release.
- **Fuzzing** (`cargo-fuzz`) on rule parsing, uninstall-string parsing and IPC messages.
- **Chaos tests**: kill the process mid-uninstall and verify recovery and restore.
- **Static gates**: `cargo clippy -D warnings`, `cargo fmt --check`, `cargo audit`, `cargo deny`, miri on `unsafe`-bearing modules.

## 14. Open-Source Strategy

Exuvia is open source from the first commit under MIT OR Apache-2.0, with an open roadmap, a documented contribution path and a community-maintained rule database.

| Area | Decision |
| --- | --- |
| License | Dual MIT OR Apache-2.0 for code (Rust convention); the rule database is CC0 so anyone can reuse it |
| Repository | Public GitHub monorepo under a project organization; `main` is protected |
| Contributions | Pull requests with Developer Certificate of Origin sign-off (no CLA); `CONTRIBUTING.md` explains setup, tests and style |
| Governance | Maintainers listed in `MAINTAINERS.md`; CODEOWNERS on the safety policy, helper and rule verifier require two approvals |
| Decision process | Lightweight RFCs in `docs/rfcs/` for changes to the safety policy, rule format or helper command set |
| Community rules | Per-app rules accepted via pull request using a template; an automated validator checks schema and denylist before merge |
| Security | `SECURITY.md`, private vulnerability reporting, 90-day coordinated disclosure, advisories published to GitHub and RustSec |
| Conduct | Contributor Covenant 2.1 in `CODE_OF_CONDUCT.md` |
| Documentation | mdBook site on GitHub Pages: user guide, rule authoring guide, architecture, contributor guide |
| Issue management | Issue forms for bugs, rule requests and features; labels `good first issue`, `help wanted`, `rule`, `safety`; Discussions enabled |
| Privacy promise | No telemetry by default, stated in the README and enforced by a CI test that forbids network calls other than update and rule checks |
| Versioning | SemVer, Keep a Changelog format, conventional commits drive release notes |
| Roadmap | Public GitHub Project board updated each milestone |

## 15. CI/CD and Release Pipeline

GitHub Actions runs every check on every pull request and publishes a signed release when a version tag is pushed, with no manual build steps.

### Workflows

| Workflow | Trigger | What it does |
| --- | --- | --- |
| `ci.yml` | Pull request, push to `main` | `cargo fmt --check`, `clippy -D warnings`, build and tests on Windows x64 and ARM64 runners, coverage with `cargo-llvm-cov` |
| `security.yml` | Pull request, nightly | `cargo audit`, `cargo deny` (advisories, licenses, bans), dependency review, CodeQL for the web UI |
| `rules.yml` | Pull request touching `rules/` | Validates the TOML schema, checks no rule targets a protected path, runs the rule benchmark |
| `fuzz.yml` | Nightly | `cargo-fuzz` on the rule parser, uninstall-string parser and IPC messages |
| `bench.yml` | `main`, weekly | Recall and false-positive benchmark; fails if recall drops more than 1 point or any false positive appears |
| `docs.yml` | Push to `main` | Builds the mdBook site and deploys to GitHub Pages |
| `nightly.yml` | Daily | Unsigned pre-release build for testers |
| `release.yml` | Tag `vX.Y.Z` | Builds, signs, packages, attests and publishes (see below) |

### Release Flow

1. `release-plz` opens a release pull request that bumps versions and updates `CHANGELOG.md` from conventional commits; a maintainer merges it.
2. Pushing the tag `vX.Y.Z` triggers `release.yml`.
3. Build with `cargo build --release --locked` for `x86_64-pc-windows-msvc` and `aarch64-pc-windows-msvc` (LTO, stripped, static CRT).
4. Package an MSI (WiX v4, per-user and per-machine), a portable ZIP, a CLI-only ZIP and, optionally, an MSIX.
5. Sign binaries and installers with Authenticode and a trusted timestamp (SignPath Foundation or Azure Trusted Signing).
6. Generate SHA-256 checksums, a CycloneDX SBOM and a build provenance attestation (`actions/attest-build-provenance`).
7. Create the GitHub Release with generated notes and all assets; tags such as `-beta.N` and `-rc.N` are marked pre-release.
8. Publish to winget (pull request to `microsoft/winget-pkgs` via `winget-releaser`), the Scoop bucket, Chocolatey and crates.io (`exuvia-core`, `exuvia-cli`).
9. Run a post-release smoke test on a clean Windows runner: install the published MSI, run `exuvia --version` and an uninstall dry run; on failure, delist the release and open an issue automatically.
10. The in-app updater checks a signed release manifest (Ed25519) and installs only verified updates; it can be disabled.

### Release Channels

| Channel | Source | Audience | Cadence |
| --- | --- | --- | --- |
| Nightly | `main` | Testers and contributors | Daily |
| Beta | `vX.Y.Z-beta.N` tags | Early adopters | As needed |
| Stable | `vX.Y.Z` tags | Everyone | Every 4 to 6 weeks |

### Pipeline Security

- `main` requires passing checks, one approval (two on safety-critical paths) and linear history.
- Signing and publishing secrets live in a protected `release` environment with required reviewers; Azure and SignPath use OIDC rather than long-lived keys.
- Secrets are never exposed to workflows triggered from forks.
- Third-party Actions are pinned to commit SHAs and updated by Dependabot.

### Example: release.yml (abridged)

```yaml
name: release
on:
  push:
    tags: ["v*.*.*"]
permissions:
  contents: write
  id-token: write
  attestations: write
jobs:
  build:
    strategy:
      matrix:
        include:
          - { runner: windows-latest, target: x86_64-pc-windows-msvc }
          - { runner: windows-11-arm, target: aarch64-pc-windows-msvc }
    runs-on: ${{ matrix.runner }}
    steps:
      - uses: actions/checkout@<sha>
      - uses: dtolnay/rust-toolchain@stable
        with: { targets: "${{ matrix.target }}" }
      - run: cargo build --release --locked --target ${{ matrix.target }}
      - run: cargo xtask package --target ${{ matrix.target }}   # MSI + ZIPs
      - run: cargo xtask sign --target ${{ matrix.target }}      # Authenticode
      - uses: actions/attest-build-provenance@<sha>
        with: { subject-path: "dist/*" }
      - uses: actions/upload-artifact@<sha>
        with: { name: "dist-${{ matrix.target }}", path: dist/* }
  publish:
    needs: build
    runs-on: ubuntu-latest
    environment: release          # required reviewers + secrets
    steps:
      - uses: actions/download-artifact@<sha>
      - run: gh release create "$GITHUB_REF_NAME" dist-*/* --generate-notes
      - uses: vedantmgoyal9/winget-releaser@<sha>
      - run: cargo xtask publish-scoop-choco-crates
```

## 16. Release Plan and Milestones

| Milestone | Deliverable | Target |
| --- | --- | --- |
| M0 — Foundations and open-source setup | Public repo, license, CONTRIBUTING, CI skeleton, domain model, safety policy, rule format | Weeks 1–3 |
| M1 — Windows alpha (CLI) | Win32/MSI discovery, residue scan, quarantine, `exuvia` CLI, nightly pipeline | Weeks 4–10 |
| M2 — Windows alpha 2 | MSIX/AppX, services, scheduled tasks, UAC helper, registry export | Weeks 11–15 |
| M3 — GUI beta | Tauri UI, review screen, history and restore, accessibility pass | Weeks 16–21 |
| M4 — Release pipeline and hardening | Authenticode signing, winget/Scoop/Chocolatey publishing, provenance and SBOM, benchmarks, fuzzing, security review | Weeks 22–25 |
| M5 — v1.0 GA | Public release, docs site, announcement | Week 26 |
| M6 — Post-v1.0 | macOS and Linux ports, Store listing, fleet features | After GA |

Timeline assumes a small team of 2–3 Rust engineers plus part-time design and QA; adjust to actual staffing.

## 17. Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
| --- | --- | --- | --- |
| False-positive deletion damages user data | Low | Critical | Quarantine default, confidence tiers, denylist, extensive benchmark |
| SmartScreen or antivirus flags unsigned or new binaries | High | High | Authenticode signing, submit to Microsoft analysis, publish hashes, avoid packers |
| Windows changes break scanning (Store policies, new app models) | Medium | High | Platform abstraction, Windows Insider testing, graceful degradation |
| Rule database coverage gaps | High | Medium | Heuristic fallback, community contribution workflow, orphan scan |
| Release pipeline or signing keys compromised | Low | Critical | Protected environment, OIDC, pinned Actions, provenance attestation, reviewer approval |
| Privileged helper becomes an attack surface | Low | Critical | Minimal command set, security review, external audit before GA |
| Maintainer bandwidth and contributor burnout | Medium | Medium | Clear governance, good-first-issue labels, automation of checks and releases |
| Code-signing approval delays (SignPath OSS or Azure) | Medium | Medium | Apply in M0, not at the end |

## 18. Dependencies and Constraints

- Code signing: SignPath Foundation (free for open-source projects) or Azure Trusted Signing; Microsoft Store account only if MSIX Store distribution is chosen.
- GitHub organization, GitHub Actions (free for public repositories, including Windows ARM runners where available), Codecov.
- Rust stable toolchain (MSRV policy: latest stable minus two releases), WiX Toolset v4, WebView2 runtime.
- Accounts for winget-pkgs, Scoop bucket, Chocolatey and crates.io publishing.
- Licensing: MIT OR Apache-2.0 for code, CC0 for rules; verify every dependency license with `cargo deny`.

## 19. Open Questions

- What are the GitHub organization and domain for Exuvia?
- Is Exuvia a standalone product, or part of a larger product family that needs shared branding and integration points?
- Code signing: apply for SignPath Foundation (free, needs approval) or pay for Azure Trusted Signing?
- Ship to the Microsoft Store (MSIX) in v1.0, or only GitHub, winget, Scoop and Chocolatey?
- Should portable and per-user-only apps be treated as first-class in v1.0?
- What retention default is right for quarantine: 7, 30, or 90 days?
- Host the rule database in the main repo, or in a separate repo with its own release cadence?
- Is enterprise or fleet management (Intune, MDM) in scope for v1.x?

## 20. Appendix

### Glossary

- **Residue / leftover**: any file, registry key, service or config that belongs to an app and remains after its native uninstall.
- **Quarantine**: Exuvia-managed holding area where removed items are stored until the retention period ends.
- **Manifest**: signed record of everything removed in one operation, used for restore.
- **Denylist**: set of paths and objects Exuvia will never modify.

### Example CLI Session

```
PS> exuvia scan "Example Editor"
Found 14 items (212 MB)
  [high]   %APPDATA%\ExampleEditor                    180 MB
  [high]   HKCU\Software\ExampleCorp\Editor            12 values
  [medium] %LOCALAPPDATA%\ExampleEditor\Cache           31 MB

PS> exuvia uninstall "Example Editor" --dry-run
PS> exuvia uninstall "Example Editor" --yes
Removed 14 items, reclaimed 212 MB. Restore with: exuvia restore 7f3a2c
```
