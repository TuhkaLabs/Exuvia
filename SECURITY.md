# Security policy

Exuvia deletes files and registry keys. Security defects and false-positive
deletions are treated as high severity.

## Reporting a vulnerability

Do not open a public issue for a security problem. Report it privately through
GitHub's private vulnerability reporting for this repository, or email the
maintainers listed in the repository profile.

Include:

- Exuvia version and Windows build
- A description of the issue and its impact
- Reproduction steps or a proof of concept
- Whether the issue can be triggered by a crafted app name, rule file or update

You will receive an acknowledgement, an assessment and a remediation plan.
Please allow 90 days for coordinated disclosure.

## Scope

In scope:

- Path traversal, symlink/junction or reparse-point escapes
- Denylist bypasses or canonicalization bugs
- Registry scope violations
- Privilege escalation through the helper or IPC
- Malicious or tampered rule updates
- Manifest tampering or restore escapes

Out of scope:

- An uninstaller supplied by a third-party application behaving badly
- Antivirus false positives caused by unsigned development builds
- Issues requiring an already-compromised administrator account

## Supported versions

Only the latest release receives security fixes while the project is in alpha.
