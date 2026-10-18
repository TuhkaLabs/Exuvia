# Exuvia rule database

Rules describe locations that belong to a specific application. They are
shipped with Exuvia and can be extended by dropping additional `.toml` files into
`%LOCALAPPDATA%\Exuvia\rules`.

Rules never override the safety policy. The validator rejects any rule whose
path or registry key matches the built-in denylist.

## Schema

```toml
schema = 1
version = "2026.10.1"

[app."example-editor"]
name = "Example Editor"
publisher = "Example Corp"
aliases = ["ExampleEditor"]
product_codes = ["{00000000-0000-0000-0000-000000000000}"]
platforms = ["windows"]

[[app."example-editor".paths]]
path = "%APPDATA%\\ExampleEditor"
kind = "user-data"          # user-data | cache | config | log
confidence = "high"         # high | medium | low

[[app."example-editor".registry]]
key = "HKCU\\Software\\ExampleCorp\\Editor"
kind = "config"
confidence = "high"

[[app."example-editor".services]]
name = "ExampleEditorService"

[[app."example-editor".tasks]]
name = "ExampleEditorUpdate"

[[app."example-editor".startup]]
name = "Example Editor"
```

## Guidance

- `path` supports `%VARIABLES%` and a leading `~`.
- Use `user-data` only for data the user would miss; Standard mode preserves it.
- Prefer a specific app directory over a shared publisher directory.
- Registry rules should target the app's own key, not `Microsoft\Windows`.
- Drivers and kernel services must not be added as removable rules.
- Run the validator before opening a pull request:

```powershell
cargo run -p exuvia-cli -- rules validate rules/bundled.toml
```

## Licence

The rule database is dedicated to the public domain under CC0-1.0.
