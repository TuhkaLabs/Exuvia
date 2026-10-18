# Contributing to Exuvia

Thanks for helping. Exuvia is safety-critical software: a wrong path can destroy
user data, so changes to the safety policy, removal engine or rule verifier get
extra scrutiny.

## Development setup

Requirements:

- Rust stable (see `rust-version` in `Cargo.toml`)
- Windows 10 22H2 or Windows 11
- Visual Studio Build Tools with the MSVC toolchain

```powershell
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

CI runs the same commands on Windows. Do not submit changes that leave any of
them failing.

## Pull requests

- Keep changes focused and explain the user-visible effect.
- Add tests for new matching logic, safety checks and manifest behaviour.
- Sign off every commit with the Developer Certificate of Origin:
  `git commit -s -m "..."`. Exuvia does not require a CLA.
- Do not add telemetry, analytics or network calls. The only allowed network
  activity is an explicit update or rule check.
- Never add a rule or test that targets a protected path.

Safety-critical paths (denylist, quarantine, restore, registry deletion, future
helper IPC) require review from a listed maintainer.

## Contributing a rule

1. Pick a stable id: lowercase, no spaces, usually the app name or product code.
2. Add an `[app."<id>"]` table to `rules/bundled.toml` (or a new `.toml` file
   under `rules/`).
3. Describe only locations that belong to that application. Prefer specific
   subdirectories over vendor-wide directories.
4. Mark genuinely valuable user data as `kind = "user-data"` so Standard mode
   leaves it untouched.
5. Run the validator:

```powershell
cargo run -p exuvia-cli -- rules validate rules/bundled.toml
```

Rules are CC0-1.0; by contributing you agree to release them under that licence.
See `rules/README.md` for the schema.

## Commit style

Conventional commits (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`)
are used to generate release notes. Keep the subject imperative and under 72
characters.

## Code of conduct

Be respectful and constructive. Harassment, discrimination and personal attacks
are not tolerated. Report concerns privately to the maintainers.
