"""Audit effective SSH authentication settings reported by OpenSSH."""

from __future__ import annotations

from ..context import ScanContext
from ..models import Confidence, Finding, Severity, Status


class SshAuthenticationCheck:
    check_id = "system.ssh.authentication"
    area = "network"

    def run(self, context: ScanContext) -> list[Finding]:
        service = context.commands.run(("systemctl", "is-active", "sshd.service"), timeout=5)
        service_state = service.stdout.strip()
        if service.returncode in (3, 4) and service_state in ("inactive", "failed", "unknown", "not-found"):
            return [Finding(
                self.check_id, self.area, "SSH server is not active", Status.NOT_APPLICABLE,
                Severity.INFO, f"sshd.service state: {service_state}",
            )]
        if service.returncode != 0 or service_state != "active":
            return [Finding(
                self.check_id, self.area, "SSH server state could not be determined", Status.UNKNOWN,
                Severity.INFO, service_state or f"systemctl exited with status {service.returncode}.",
                confidence=Confidence.LOW,
            )]

        effective = context.commands.run(("sshd", "-T"), timeout=10)
        if effective.returncode != 0:
            status = Status.UNKNOWN if effective.returncode == 127 else Status.ERROR
            return [Finding(
                self.check_id, self.area, "Effective SSH configuration could not be determined", status,
                Severity.INFO, effective.stdout or f"sshd -T exited with status {effective.returncode}.",
                confidence=Confidence.LOW,
            )]

        values = self._parse_effective_config(effective.stdout)
        return [
            self._root_login(values), self._password_authentication(values),
            self._x11_forwarding(values), self._tcp_forwarding(values), self._idle_timeout(values),
        ]

    @staticmethod
    def _parse_effective_config(output: str) -> dict[str, str]:
        values: dict[str, str] = {}
        for line in output.splitlines():
            key, separator, value = line.strip().partition(" ")
            if separator and key:
                values[key.casefold()] = value.strip().casefold()
        return values

    @staticmethod
    def _root_login(values: dict[str, str]) -> Finding:
        value = values.get("permitrootlogin")
        check_id = "system.ssh.root-login"
        if value is None:
            return Finding(
                check_id, "network", "Root-login policy could not be determined", Status.UNKNOWN,
                Severity.INFO, "sshd -T did not report PermitRootLogin.", confidence=Confidence.LOW,
            )
        if value == "no":
            return Finding(
                check_id, "network", "Direct SSH root login is disabled", Status.PASS,
                Severity.INFO, "Effective PermitRootLogin: no", confidence=Confidence.MEDIUM,
            )
        severity = Severity.HIGH if value == "yes" else Severity.MEDIUM
        return Finding(
            check_id, "network", "Direct SSH root login is permitted", Status.FAIL, severity,
            f"Effective PermitRootLogin: {value}",
            remediation="Set PermitRootLogin no unless direct root access is explicitly required.",
            confidence=Confidence.MEDIUM,
        )

    @staticmethod
    def _password_authentication(values: dict[str, str]) -> Finding:
        value = values.get("passwordauthentication")
        check_id = "system.ssh.password-authentication"
        if value is None:
            return Finding(
                check_id, "network", "SSH password policy could not be determined", Status.UNKNOWN,
                Severity.INFO, "sshd -T did not report PasswordAuthentication.", confidence=Confidence.LOW,
            )
        if value == "no":
            return Finding(
                check_id, "network", "SSH password authentication is disabled", Status.PASS,
                Severity.INFO, "Effective PasswordAuthentication: no", confidence=Confidence.MEDIUM,
            )
        return Finding(
            check_id, "network", "SSH password authentication is enabled", Status.FAIL,
            Severity.MEDIUM, f"Effective PasswordAuthentication: {value}",
            remediation="Use SSH keys and set PasswordAuthentication no when operationally feasible.",
            confidence=Confidence.MEDIUM,
        )

    @staticmethod
    def _review_boolean(values: dict[str, str], directive: str, title: str, check_id: str, remediation: str) -> Finding:
        value = values.get(directive)
        if value is None:
            return Finding(check_id, "network", f"{title} policy could not be determined", Status.UNKNOWN,
                           Severity.INFO, f"sshd -T did not report {directive}.", confidence=Confidence.LOW)
        if value == "no":
            return Finding(check_id, "network", f"{title} is disabled", Status.PASS,
                           Severity.INFO, f"Effective {directive}: no", confidence=Confidence.MEDIUM)
        return Finding(check_id, "network", f"{title} is enabled", Status.REVIEW,
                       Severity.LOW, f"Effective {directive}: {value}", remediation=remediation,
                       confidence=Confidence.MEDIUM)

    @classmethod
    def _x11_forwarding(cls, values: dict[str, str]) -> Finding:
        return cls._review_boolean(values, "x11forwarding", "SSH X11 forwarding", "system.ssh.x11-forwarding",
                                   "Disable X11Forwarding unless remote graphical application forwarding is required.")

    @classmethod
    def _tcp_forwarding(cls, values: dict[str, str]) -> Finding:
        return cls._review_boolean(values, "allowtcpforwarding", "SSH TCP forwarding", "system.ssh.tcp-forwarding",
                                   "Restrict AllowTcpForwarding unless tunnels are required by the SSH service's intended role.")

    @staticmethod
    def _idle_timeout(values: dict[str, str]) -> Finding:
        value = values.get("clientaliveinterval")
        check_id = "system.ssh.idle-timeout"
        if value is None:
            return Finding(check_id, "network", "SSH idle-session policy could not be determined", Status.UNKNOWN,
                           Severity.INFO, "sshd -T did not report ClientAliveInterval.", confidence=Confidence.LOW)
        try:
            seconds = int(value)
        except ValueError:
            return Finding(check_id, "network", "SSH idle-session policy has an invalid value", Status.ERROR,
                           Severity.INFO, f"Effective ClientAliveInterval: {value}", confidence=Confidence.LOW)
        if seconds > 0:
            return Finding(check_id, "network", "SSH idle-session timeout is configured", Status.PASS,
                           Severity.INFO, f"Effective ClientAliveInterval: {seconds} seconds.", confidence=Confidence.MEDIUM)
        return Finding(check_id, "network", "SSH sessions have no server idle timeout", Status.REVIEW,
                       Severity.LOW, "Effective ClientAliveInterval: 0", remediation="Set ClientAliveInterval and ClientAliveCountMax for services needing automatic idle-session expiry.", confidence=Confidence.MEDIUM)
