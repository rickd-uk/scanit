"""Report network listeners bound to wildcard addresses."""

from __future__ import annotations

from ..context import ScanContext
from ..models import Confidence, Finding, Severity, Status


class WildcardListenersCheck:
    check_id = "system.network.wildcard-listeners"
    area = "network"

    def run(self, context: ScanContext) -> list[Finding]:
        result = context.commands.run(("ss", "-H", "-lntu"), timeout=8)
        if result.returncode == 127:
            return [Finding(
                self.check_id, self.area, "Listening sockets could not be inspected", Status.UNKNOWN,
                Severity.INFO, "ss is not available.", confidence=Confidence.LOW,
            )]
        if result.returncode != 0:
            return [Finding(
                self.check_id, self.area, "Listening sockets could not be inspected", Status.ERROR,
                Severity.INFO, result.stdout or f"ss exited with status {result.returncode}.",
                confidence=Confidence.LOW,
            )]

        parsed = 0
        wildcard: list[str] = []
        for line in result.stdout.splitlines():
            fields = line.split()
            if len(fields) < 6:
                continue
            parsed += 1
            protocol, local = fields[0], fields[4]
            if self._is_wildcard(local):
                wildcard.append(f"{protocol} {local}")

        if wildcard:
            return [Finding(
                self.check_id, self.area, "Services listen on wildcard network addresses",
                Status.REVIEW, Severity.LOW,
                f"Found {len(wildcard)} wildcard-bound listening socket(s); firewall rules may still restrict access.",
                evidence=tuple(wildcard),
                remediation="Confirm each listener is required and restrict its bind address or firewall exposure where appropriate.",
                confidence=Confidence.MEDIUM,
            )]
        if result.stdout.strip() and not parsed:
            return [Finding(
                self.check_id, self.area, "Listening socket output could not be parsed", Status.UNKNOWN,
                Severity.INFO, "ss returned an unrecognized output format.", confidence=Confidence.LOW,
            )]
        return [Finding(
            self.check_id, self.area, "No wildcard-bound listening sockets detected", Status.PASS,
            Severity.INFO, f"Inspected {parsed} listening socket(s).", confidence=Confidence.MEDIUM,
        )]

    @staticmethod
    def _is_wildcard(local: str) -> bool:
        value = local.casefold()
        return value.startswith(("0.0.0.0:", "[::]:", "*:", ":::"))
