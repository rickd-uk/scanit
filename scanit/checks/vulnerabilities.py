"""Check installed Arch packages against distribution vulnerability data."""

from __future__ import annotations

from ..context import ScanContext
from ..models import Confidence, Finding, Severity, Status


class ArchAuditCheck:
    check_id = "system.packages.known-vulnerabilities"
    area = "system"

    def run(self, context: ScanContext) -> list[Finding]:
        result = context.commands.run(("arch-audit",), timeout=40)
        lines = tuple(line.strip() for line in result.stdout.splitlines() if line.strip())
        if result.returncode == 127:
            return [Finding(
                self.check_id, self.area, "Package vulnerability audit is unavailable", Status.UNKNOWN,
                Severity.INFO, "arch-audit is not installed or could not be executed.",
                remediation="Install arch-audit to compare installed packages with Arch security advisories.",
                confidence=Confidence.HIGH,
            )]
        if result.returncode == 0 and not lines:
            return [Finding(
                self.check_id, self.area, "No known vulnerable packages reported", Status.PASS,
                Severity.INFO, "arch-audit returned no affected installed packages.",
                confidence=Confidence.MEDIUM,
            )]
        if result.returncode in (0, 1) and lines:
            return [Finding(
                self.check_id, self.area, "Known vulnerable packages were reported", Status.FAIL,
                Severity.HIGH, f"arch-audit reported {len(lines)} affected package entries.",
                evidence=lines,
                remediation="Review the advisories and update or mitigate the affected packages promptly.",
                confidence=Confidence.MEDIUM,
            )]
        return [Finding(
            self.check_id, self.area, "Package vulnerability audit could not complete", Status.ERROR,
            Severity.INFO, result.stdout or f"arch-audit exited with status {result.returncode}.",
            confidence=Confidence.LOW,
        )]
