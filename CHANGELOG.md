# Changelog

All notable changes to ScanIt are documented in this file.

The project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.2.0] - Unreleased

### Added

- Shared NTFS, exFAT, and FAT mount-option auditing with active NTFS implementation
  reporting.
- Distribution-build and installed-command validation in CI.
- CI coverage for every supported Python release from 3.11 through 3.14.
- A test that keeps package metadata and the runtime version synchronized.
- SPDX license metadata and release documentation in source distributions.
- Modular, dependency-free security checks for Arch Linux workstations.
- Browser profile, extension, runtime-flag, and Firefox preference checks.
- Package freshness, signature-policy, foreign-package, and vulnerability checks.
- Firewall, listener, forwarding, SSH, and network-hardening checks.
- Storage encryption, Secure Boot, kernel-hardening, and security-module checks.
- Account, SSH-key, sudo-policy, systemd, and filesystem permission checks.
- Versioned JSON, SARIF, focused scans, failure thresholds, and baseline comparison.
- Native repeatable result-status filtering with `--status`.
- Unit tests covering safe, unsafe, unavailable, malformed, and partial-evidence states.

### Fixed

- Permission-denied and timeout results from `visudo` no longer appear as invalid
  sudo policy.
- `arch-audit` network and database errors no longer appear as vulnerable-package
  entries.
- CI actions now use Node.js 24-compatible releases pinned by commit digest.
- Broad `/etc` auditing now separates demonstrated group/world writability from
  context-dependent service ownership and limits evidence volume.

[Unreleased]: https://github.com/rickd-uk/scanit/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/rickd-uk/scanit/releases/tag/v0.2.0
