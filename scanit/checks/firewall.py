"""Checks for an active, supported host-firewall service."""

from __future__ import annotations

from ..context import ScanContext
from ..models import Confidence, Finding, Severity, Status


class FirewallServiceCheck:
    check_id = "system.network.firewall-service-active"
    area = "network"
    services = ("nftables.service", "firewalld.service", "ufw.service")

    def run(self, context: ScanContext) -> list[Finding]:
        known: list[str] = []
        unknown: list[str] = []
        active: list[str] = []
        for service in self.services:
            result = context.commands.run(("systemctl", "is-active", service), timeout=5)
            state = result.stdout.strip() or f"exit {result.returncode}"
            if result.returncode == 0 and state == "active":
                active.append(f"{service}: active")
            elif result.returncode in (1, 3, 4):
                known.append(f"{service}: {state}")
            else:
                unknown.append(f"{service}: {state}")

        if active:
            return [Finding(
                self.check_id, self.area, "A common firewall service is active", Status.PASS,
                Severity.INFO, "At least one supported firewall service is active.",
                evidence=tuple(active), confidence=Confidence.MEDIUM,
            )]
        if not known:
            return [Finding(
                self.check_id, self.area, "Firewall service state could not be determined", Status.UNKNOWN,
                Severity.INFO, "systemctl could not determine any supported firewall service state.",
                evidence=tuple(unknown), confidence=Confidence.LOW,
            )]
        return [Finding(
            self.check_id, self.area, "No common firewall service is active", Status.FAIL,
            Severity.MEDIUM, "No supported firewall service is currently active.",
            evidence=tuple(known + unknown),
            remediation="Enable and configure nftables, firewalld, or ufw if this device accepts network connections.",
            confidence=Confidence.MEDIUM,
        )]
