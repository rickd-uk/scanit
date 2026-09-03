# Roadmap

ScanIt is being developed in small, testable slices. Priorities may change as
real systems expose false positives, incomplete evidence, or unsafe assumptions.

## 0.2 release readiness

- Validate wheels and source distributions in CI.
- Test every supported Python release.
- Stabilize documented JSON and SARIF behavior.
- Complete an installed-package smoke test and publish release notes.

## Next checks

- Audit security-relevant options on shared and removable filesystem mounts.
- Report the active NTFS implementation without treating NTFS itself as unsafe.
- Audit privileged systemd execution targets and their parent-directory permissions.
- Extend coverage to privileged scheduled tasks, PAM policy, persistent logging,
  core dumps, and boot-chain file integrity.

## Boundaries

- Keep scans read-only and local by default.
- Preserve `unknown`, `error`, and `not_applicable` instead of guessing.
- Reserve failures for demonstrated policy violations and use review findings when
  legitimate workstation context can change the risk.
- Avoid automatic remediation until checks and evidence formats are stable.
