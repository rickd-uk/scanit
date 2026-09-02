"""Checks for pending Arch Linux package updates."""

from __future__ import annotations

import time

from ..commands import CommandResult
from ..context import ScanContext
from ..models import Confidence, Finding, Severity, Status


class PendingPackageUpdatesCheck:
    check_id = "system.packages.pending-updates"
    area = "system"

    def run(self, context: ScanContext) -> list[Finding]:
        result = context.commands.run(("pacman", "-Qu"), timeout=25)
        updates = tuple(line for line in result.stdout.splitlines() if line.strip())

        if result.returncode == 0:
            if updates:
                return [Finding(
                    self.check_id, self.area, "Package updates are pending", Status.FAIL,
                    Severity.MEDIUM, f"{len(updates)} package updates are available in the local database.",
                    evidence=updates,
                    remediation="Review and apply updates with: sudo pacman -Syu",
                    confidence=Confidence.MEDIUM,
                )]
            return [Finding(
                self.check_id, self.area, "No package updates reported", Status.PASS,
                Severity.INFO, "pacman -Qu returned no pending package updates.",
                confidence=Confidence.MEDIUM,
            )]
        if result.returncode == 1 and not updates:
            return [Finding(
                self.check_id, self.area, "No package updates reported", Status.PASS,
                Severity.INFO, "pacman -Qu reported no pending package updates.",
                confidence=Confidence.MEDIUM,
            )]
        if result.returncode == 127:
            return [Finding(
                self.check_id, self.area, "Package-update check unavailable", Status.UNKNOWN,
                Severity.INFO, "pacman is not available on this system.", confidence=Confidence.HIGH,
            )]
        return [Finding(
            self.check_id, self.area, "Package-update check could not complete", Status.ERROR,
            Severity.INFO, result.stdout or f"pacman -Qu exited with status {result.returncode}.",
            confidence=Confidence.HIGH,
        )]


class PacmanDatabaseFreshnessCheck:
    check_id = "system.packages.database-freshness"
    area = "system"
    maximum_age_days = 7

    def run(self, context: ScanContext) -> list[Finding]:
        directory = context.root / "var/lib/pacman/sync"
        try:
            databases = list(directory.glob("*.db"))
            modified = [path.stat().st_mtime for path in databases]
        except OSError as error:
            return [Finding(
                self.check_id, self.area, "Pacman database freshness could not be determined",
                Status.UNKNOWN, Severity.INFO, str(error), confidence=Confidence.LOW,
            )]
        if not modified:
            return [Finding(
                self.check_id, self.area, "Pacman database freshness could not be determined",
                Status.UNKNOWN, Severity.INFO, f"No repository databases were found in {directory}.",
                confidence=Confidence.LOW,
            )]
        age_seconds = time.time() - max(modified)
        if age_seconds < 0:
            return [Finding(
                self.check_id, self.area, "Pacman database timestamp is in the future",
                Status.UNKNOWN, Severity.INFO, "Repository database timestamps are ahead of the system clock.",
                confidence=Confidence.LOW,
            )]
        age_days = age_seconds / 86_400
        if age_days > self.maximum_age_days:
            return [Finding(
                self.check_id, self.area, "Pacman repository databases are stale", Status.FAIL,
                Severity.LOW, f"The newest repository database is {age_days:.1f} days old.",
                remediation="Refresh and update through the normal full-system Arch update workflow.",
                confidence=Confidence.HIGH,
            )]
        return [Finding(
            self.check_id, self.area, "Pacman repository databases are recent", Status.PASS,
            Severity.INFO, f"The newest repository database is {age_days:.1f} days old.",
            confidence=Confidence.HIGH,
        )]
