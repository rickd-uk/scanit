# Roadmap

ScanIt is being developed in small, testable slices. Priorities may change as
real systems expose false positives, incomplete evidence, or unsafe assumptions.

## 0.2 release

- Validated wheels and source distributions in CI.
- Tested every supported Python release.
- Stabilized documented JSON and SARIF behavior.
- Completed installed-package smoke testing and release notes.

## Completed checks

- Audit security-relevant options on shared and removable filesystem mounts,
  including active NTFS implementation reporting.
- Audit effective execution targets and parent-directory permissions for active
  and enabled systemd system services.

## Next checks

- Extend coverage to privileged scheduled tasks, PAM policy, persistent logging,
  core dumps, and boot-chain file integrity.

## Boundaries

- Keep scans read-only and local by default.
- Preserve `unknown`, `error`, and `not_applicable` instead of guessing.
- Reserve failures for demonstrated policy violations and use review findings when
  legitimate workstation context can change the risk.
- Avoid automatic remediation until checks and evidence formats are stable.
