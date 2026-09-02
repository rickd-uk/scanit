"""Audit security-sensitive systemd service states."""

from __future__ import annotations

from ..context import ScanContext
from ..models import Confidence, Finding, Severity, Status


class SystemdDebugShellCheck:
    check_id = "system.services.debug-shell"
    area = "system"

    def run(self, context: ScanContext) -> list[Finding]:
        result = context.commands.run(("systemctl", "is-enabled", "debug-shell.service"), timeout=8)
        state = result.stdout.strip().casefold()
        if result.returncode == 127:
            return [Finding(
                self.check_id, self.area, "systemd debug-shell state could not be determined", Status.UNKNOWN,
                Severity.INFO, "systemctl is not available.", confidence=Confidence.LOW,
            )]
        if result.returncode == 0 and state in {"enabled", "enabled-runtime", "linked", "linked-runtime", "alias"}:
            return [Finding(
                self.check_id, self.area, "systemd debug shell is enabled", Status.FAIL,
                Severity.HIGH, f"debug-shell.service is {state}.",
                remediation="Disable debug-shell.service unless an active, time-limited troubleshooting session requires it.",
                confidence=Confidence.HIGH,
            )]
        if state in {"disabled", "masked", "static", "indirect", "generated", "transient", "not-found"}:
            return [Finding(
                self.check_id, self.area, "systemd debug shell is not enabled", Status.PASS,
                Severity.INFO, f"debug-shell.service is {state}.", confidence=Confidence.HIGH,
            )]
        return [Finding(
            self.check_id, self.area, "systemd debug-shell state could not be determined", Status.UNKNOWN,
            Severity.INFO, result.stdout or f"systemctl exited with status {result.returncode}.",
            confidence=Confidence.LOW,
        )]
