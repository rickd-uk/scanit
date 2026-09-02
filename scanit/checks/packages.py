"""Checks for pending Arch Linux package updates."""

from __future__ import annotations

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
