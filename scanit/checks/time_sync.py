"""Check whether systemd reports an NTP-synchronized system clock."""

from __future__ import annotations

from ..context import ScanContext
from ..models import Confidence, Finding, Severity, Status


class NtpSynchronizationCheck:
    check_id = "system.time.ntp-synchronization"
    area = "system"

    def run(self, context: ScanContext) -> list[Finding]:
        result = context.commands.run(
            ("timedatectl", "show", "--property=NTPSynchronized", "--value"), timeout=8,
        )
        value = result.stdout.strip().casefold()
        if result.returncode == 127:
            return [Finding(
                self.check_id, self.area, "Clock synchronization could not be determined", Status.UNKNOWN,
                Severity.INFO, "timedatectl is not available.", confidence=Confidence.LOW,
            )]
        if result.returncode != 0:
            return [Finding(
                self.check_id, self.area, "Clock synchronization could not be determined", Status.UNKNOWN,
                Severity.INFO, result.stdout or f"timedatectl exited with status {result.returncode}.",
                confidence=Confidence.LOW,
            )]
        if value in {"yes", "true"}:
            return [Finding(
                self.check_id, self.area, "System clock is NTP synchronized", Status.PASS,
                Severity.INFO, "timedatectl reports NTPSynchronized=yes.", confidence=Confidence.HIGH,
            )]
        if value in {"no", "false"}:
            return [Finding(
                self.check_id, self.area, "System clock is not NTP synchronized", Status.REVIEW,
                Severity.LOW, "timedatectl reports NTPSynchronized=no.",
                remediation="Verify a trusted time source or a deliberate manual synchronization process.",
                confidence=Confidence.MEDIUM,
            )]
        return [Finding(
            self.check_id, self.area, "Clock synchronization state could not be parsed", Status.UNKNOWN,
            Severity.INFO, f"timedatectl returned: {result.stdout!r}", confidence=Confidence.LOW,
        )]
