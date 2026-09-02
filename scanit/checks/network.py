"""Inspect security-relevant host networking roles."""

from __future__ import annotations

from ..context import ScanContext
from ..models import Confidence, Finding, Severity, Status


class IpForwardingCheck:
    check_id = "system.network.ip-forwarding"
    area = "network"
    controls = (
        ("IPv4", "proc/sys/net/ipv4/ip_forward"),
        ("IPv6", "proc/sys/net/ipv6/conf/all/forwarding"),
    )

    def run(self, context: ScanContext) -> list[Finding]:
        enabled: list[str] = []
        disabled: list[str] = []
        invalid: list[str] = []
        unavailable: list[str] = []
        for protocol, relative_path in self.controls:
            path = context.root / relative_path
            try:
                raw = path.read_text(encoding="ascii").strip()
            except FileNotFoundError:
                unavailable.append(protocol)
                continue
            except OSError as error:
                return [Finding(
                    self.check_id, self.area, "IP forwarding state could not be inspected", Status.UNKNOWN,
                    Severity.INFO, f"{protocol}: {error}", confidence=Confidence.LOW,
                )]
            if raw == "0":
                disabled.append(protocol)
            elif raw == "1":
                enabled.append(protocol)
            else:
                invalid.append(f"{protocol}={raw!r}")

        if invalid:
            return [Finding(
                self.check_id, self.area, "IP forwarding state could not be parsed", Status.ERROR,
                Severity.INFO, "; ".join(invalid), confidence=Confidence.LOW,
            )]
        if enabled:
            return [Finding(
                self.check_id, self.area, "IP forwarding is enabled", Status.REVIEW,
                Severity.LOW, f"Enabled for: {', '.join(enabled)}.",
                remediation="Confirm this machine is intentionally acting as a router, VPN gateway, container host, or similar network forwarder.",
                confidence=Confidence.HIGH,
            )]
        if disabled:
            detail = f"Disabled for: {', '.join(disabled)}."
            if unavailable:
                detail += f" Unavailable: {', '.join(unavailable)}."
            return [Finding(
                self.check_id, self.area, "IP forwarding is disabled", Status.PASS,
                Severity.INFO, detail, confidence=Confidence.HIGH,
            )]
        return [Finding(
            self.check_id, self.area, "IP forwarding is not supported by this kernel", Status.NOT_APPLICABLE,
            Severity.INFO, "Neither IPv4 nor IPv6 forwarding control is available.", confidence=Confidence.MEDIUM,
        )]
