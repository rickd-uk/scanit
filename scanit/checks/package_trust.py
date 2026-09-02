"""Checks for effective Arch package-signature policy."""

from __future__ import annotations

from ..commands import CommandResult
from ..context import ScanContext
from ..models import Confidence, Finding, Severity, Status


class PacmanSignaturePolicyCheck:
    check_id = "system.packages.signature-policy"
    area = "system"

    def run(self, context: ScanContext) -> list[Finding]:
        result: CommandResult = context.commands.run(("pacman-conf", "SigLevel"))
        if result.returncode == 127:
            return [Finding(
                self.check_id, self.area, "Package signature policy could not be determined",
                Status.UNKNOWN, Severity.INFO, "pacman-conf is not available on this system.",
                confidence=Confidence.HIGH,
            )]
        if result.returncode != 0:
            return [Finding(
                self.check_id, self.area, "Package signature policy could not be determined",
                Status.ERROR, Severity.INFO,
                result.stdout or f"pacman-conf SigLevel exited with status {result.returncode}.",
                confidence=Confidence.HIGH,
            )]

        policy = " ".join(result.stdout.split())
        if not policy:
            return [Finding(
                self.check_id, self.area, "Package signature policy could not be determined",
                Status.UNKNOWN, Severity.INFO, "pacman-conf returned an empty SigLevel value.",
                confidence=Confidence.LOW,
            )]
        if "never" in policy.casefold().split():
            return [Finding(
                self.check_id, self.area, "Pacman signature verification is disabled", Status.FAIL,
                Severity.CRITICAL, f"Effective SigLevel: {policy}",
                remediation="Remove Never from pacman's SigLevel and require package signatures.",
            )]
        return [Finding(
            self.check_id, self.area, "Pacman signature verification is enabled", Status.PASS,
            Severity.INFO, f"Effective SigLevel: {policy}", confidence=Confidence.HIGH,
        )]
