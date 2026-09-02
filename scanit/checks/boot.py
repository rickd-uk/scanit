"""Checks for UEFI Secure Boot state exposed by the Linux kernel."""

from __future__ import annotations

from ..context import ScanContext
from ..models import Confidence, Finding, Severity, Status


class SecureBootCheck:
    check_id = "system.boot.secure-boot"
    area = "boot"

    def run(self, context: ScanContext) -> list[Finding]:
        efivars = context.root / "sys/firmware/efi/efivars"
        if not efivars.is_dir():
            return [Finding(
                self.check_id, self.area, "Secure Boot state could not be determined", Status.UNKNOWN,
                Severity.INFO, "EFI variables are unavailable; the system may use legacy boot or restrict access.",
                confidence=Confidence.LOW,
            )]
        try:
            variables = list(efivars.glob("SecureBoot-*"))
        except OSError as error:
            return [Finding(
                self.check_id, self.area, "Secure Boot state could not be determined", Status.UNKNOWN,
                Severity.INFO, str(error), confidence=Confidence.LOW,
            )]
        if not variables:
            return [Finding(
                self.check_id, self.area, "Secure Boot state could not be determined", Status.UNKNOWN,
                Severity.INFO, "No SecureBoot EFI variable was found.", confidence=Confidence.LOW,
            )]
        try:
            value = variables[0].read_bytes()
        except OSError as error:
            return [Finding(
                self.check_id, self.area, "Secure Boot state could not be determined", Status.UNKNOWN,
                Severity.INFO, str(error), confidence=Confidence.LOW,
            )]
        if len(value) < 5:
            return [Finding(
                self.check_id, self.area, "Secure Boot variable is malformed", Status.ERROR,
                Severity.INFO, f"Expected at least 5 bytes, received {len(value)}.", confidence=Confidence.LOW,
            )]
        if value[4] == 1:
            return [Finding(
                self.check_id, self.area, "UEFI Secure Boot is enabled", Status.PASS,
                Severity.INFO, "The SecureBoot EFI variable is enabled.", confidence=Confidence.HIGH,
            )]
        if value[4] == 0:
            return [Finding(
                self.check_id, self.area, "UEFI Secure Boot is disabled", Status.FAIL,
                Severity.MEDIUM, "The SecureBoot EFI variable is disabled.",
                remediation="Enable Secure Boot with trusted boot components if compatible with this system.",
                confidence=Confidence.HIGH,
            )]
        return [Finding(
            self.check_id, self.area, "Secure Boot variable has an unknown value", Status.UNKNOWN,
            Severity.INFO, f"SecureBoot value: {value[4]}", confidence=Confidence.LOW,
        )]
