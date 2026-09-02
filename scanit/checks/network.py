"""Inspect security-relevant host networking roles."""

from __future__ import annotations

from dataclasses import dataclass

from ..context import ScanContext
from ..models import Confidence, Finding, Severity, Status


@dataclass(frozen=True, slots=True)
class NetworkControl:
    check_id: str
    label: str
    relative_path: str
    expected: int


NETWORK_HARDENING_CONTROLS = (
    NetworkControl("system.network.ipv4.accept-redirects", "IPv4 ICMP redirect acceptance", "proc/sys/net/ipv4/conf/all/accept_redirects", 0),
    NetworkControl("system.network.ipv4.send-redirects", "IPv4 ICMP redirect sending", "proc/sys/net/ipv4/conf/all/send_redirects", 0),
    NetworkControl("system.network.ipv4.reverse-path-filtering", "IPv4 reverse-path filtering", "proc/sys/net/ipv4/conf/all/rp_filter", 1),
    NetworkControl("system.network.ipv6.accept-redirects", "IPv6 ICMP redirect acceptance", "proc/sys/net/ipv6/conf/all/accept_redirects", 0),
)


class NetworkHardeningCheck:
    check_id = "system.network.hardening"
    area = "network"

    def run(self, context: ScanContext) -> list[Finding]:
        return [self._evaluate(context, control) for control in NETWORK_HARDENING_CONTROLS]

    @staticmethod
    def _evaluate(context: ScanContext, control: NetworkControl) -> Finding:
        path = context.root / control.relative_path
        try:
            raw = path.read_text(encoding="ascii").strip()
        except FileNotFoundError:
            return Finding(
                control.check_id, "network", f"{control.label} control is unavailable", Status.NOT_APPLICABLE,
                Severity.INFO, f"{path} is not exposed by this kernel.", confidence=Confidence.MEDIUM,
            )
        except OSError as error:
            return Finding(
                control.check_id, "network", f"{control.label} could not be inspected", Status.UNKNOWN,
                Severity.INFO, str(error), confidence=Confidence.LOW,
            )
        try:
            value = int(raw)
        except ValueError:
            return Finding(
                control.check_id, "network", f"{control.label} has an invalid value", Status.ERROR,
                Severity.INFO, f"{control.relative_path}={raw!r}", confidence=Confidence.LOW,
            )
        meets_baseline = value == 0 if control.expected == 0 else value >= control.expected
        if meets_baseline:
            return Finding(
                control.check_id, "network", f"{control.label} meets the baseline", Status.PASS,
                Severity.INFO, f"{control.relative_path}={value}; expected {NetworkHardeningCheck._expected_text(control)}.",
                confidence=Confidence.HIGH,
            )
        return Finding(
            control.check_id, "network", f"{control.label} needs review", Status.REVIEW,
            Severity.LOW, f"{control.relative_path}={value}; expected {NetworkHardeningCheck._expected_text(control)}.",
            remediation="Confirm this value is required by the machine's network role, then apply the appropriate persistent sysctl policy.",
            confidence=Confidence.HIGH,
        )

    @staticmethod
    def _expected_text(control: NetworkControl) -> str:
        return "0" if control.expected == 0 else f"at least {control.expected}"


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
