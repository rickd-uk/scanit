"""Audit active mandatory-access-control and kernel-lockdown state."""

from __future__ import annotations

import re

from ..context import ScanContext
from ..models import Confidence, Finding, Severity, Status


class LinuxSecurityModulesCheck:
    check_id = "system.kernel.security-modules"
    area = "kernel"
    mandatory_access_controls = {"apparmor", "selinux", "smack", "tomoyo"}

    def run(self, context: ScanContext) -> list[Finding]:
        security = context.root / "sys/kernel/security"
        return [self._mandatory_access_control(security / "lsm"), self._lockdown(security / "lockdown")]

    @classmethod
    def _mandatory_access_control(cls, path) -> Finding:
        try:
            active = {item.strip().casefold() for item in path.read_text(encoding="ascii").split(",") if item.strip()}
        except FileNotFoundError:
            return Finding(
                "system.kernel.mandatory-access-control", "kernel",
                "Active Linux security modules could not be determined", Status.UNKNOWN,
                Severity.INFO, f"{path} is unavailable.", confidence=Confidence.LOW,
            )
        except OSError as error:
            return Finding(
                "system.kernel.mandatory-access-control", "kernel",
                "Active Linux security modules could not be determined", Status.UNKNOWN,
                Severity.INFO, str(error), confidence=Confidence.LOW,
            )
        enabled = sorted(active & cls.mandatory_access_controls)
        if enabled:
            return Finding(
                "system.kernel.mandatory-access-control", "kernel",
                "A mandatory-access-control module is active", Status.PASS,
                Severity.INFO, "Active module(s): " + ", ".join(enabled), confidence=Confidence.HIGH,
            )
        return Finding(
            "system.kernel.mandatory-access-control", "kernel",
            "No mandatory-access-control module is active", Status.FAIL,
            Severity.LOW, "No AppArmor, SELinux, SMACK, or TOMOYO module appears in the active LSM list.",
            remediation="Consider enabling and enforcing a supported mandatory-access-control policy.",
            confidence=Confidence.HIGH,
        )

    @staticmethod
    def _lockdown(path) -> Finding:
        try:
            value = path.read_text(encoding="ascii").strip().casefold()
        except FileNotFoundError:
            return Finding(
                "system.kernel.lockdown", "kernel", "Kernel lockdown is unsupported or unavailable",
                Status.NOT_APPLICABLE, Severity.INFO, f"{path} is unavailable.", confidence=Confidence.MEDIUM,
            )
        except OSError as error:
            return Finding(
                "system.kernel.lockdown", "kernel", "Kernel lockdown state could not be determined",
                Status.UNKNOWN, Severity.INFO, str(error), confidence=Confidence.LOW,
            )
        selected = re.search(r"\[([^]]+)]", value)
        if not selected:
            return Finding(
                "system.kernel.lockdown", "kernel", "Kernel lockdown state could not be parsed",
                Status.ERROR, Severity.INFO, f"lockdown={value!r}", confidence=Confidence.LOW,
            )
        state = selected.group(1)
        if state in {"integrity", "confidentiality"}:
            return Finding(
                "system.kernel.lockdown", "kernel", "Kernel lockdown is active", Status.PASS,
                Severity.INFO, f"Lockdown mode: {state}", confidence=Confidence.HIGH,
            )
        if state == "none":
            return Finding(
                "system.kernel.lockdown", "kernel", "Kernel lockdown is disabled", Status.FAIL,
                Severity.LOW, "Lockdown mode: none",
                remediation="Enable kernel lockdown where compatible, commonly through a trusted Secure Boot chain.",
                confidence=Confidence.HIGH,
            )
        return Finding(
            "system.kernel.lockdown", "kernel", "Kernel lockdown state is unknown", Status.UNKNOWN,
            Severity.INFO, f"Lockdown mode: {state}", confidence=Confidence.LOW,
        )
