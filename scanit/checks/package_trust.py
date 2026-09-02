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
        if self._is_disabled(policy):
            return [Finding(
                self.check_id, self.area, "Pacman signature verification is disabled", Status.FAIL,
                Severity.CRITICAL, f"Effective SigLevel: {policy}",
                remediation="Remove Never from pacman's SigLevel and require package signatures.",
            )]

        repositories = context.commands.run(("pacman-conf", "--repo-list"))
        if repositories.returncode != 0:
            return [Finding(
                self.check_id, self.area, "Repository signature policies could not be determined",
                Status.UNKNOWN if repositories.returncode == 127 else Status.ERROR,
                Severity.INFO,
                repositories.stdout or f"pacman-conf --repo-list exited with status {repositories.returncode}.",
                confidence=Confidence.LOW,
            )]

        repository_names = [line.strip() for line in repositories.stdout.splitlines() if line.strip()]
        unsafe: list[str] = []
        errors: list[str] = []
        for repository in repository_names:
            scoped = context.commands.run(("pacman-conf", f"--repo={repository}", "SigLevel"))
            scoped_policy = " ".join(scoped.stdout.split())
            if scoped.returncode != 0:
                errors.append(f"repo={repository}: policy query failed")
                continue
            effective_policy = scoped_policy or policy
            if self._is_disabled(effective_policy):
                unsafe.append(f"repo={repository} SigLevel={effective_policy}")
        if unsafe:
            return [Finding(
                self.check_id, self.area, "A pacman repository disables signature verification",
                Status.FAIL, Severity.CRITICAL,
                f"Found {len(unsafe)} repository-specific unsafe signature policy override(s).",
                evidence=tuple(unsafe + errors),
                remediation="Remove Never from every repository SigLevel and require package signatures.",
                confidence=Confidence.MEDIUM if errors else Confidence.HIGH,
            )]
        if errors:
            return [Finding(
                self.check_id, self.area, "Repository signature policies could not be fully determined",
                Status.UNKNOWN, Severity.INFO, f"Could not query {len(errors)} repository policy value(s).",
                evidence=tuple(errors), confidence=Confidence.LOW,
            )]
        return [Finding(
            self.check_id, self.area, "Pacman signature verification is enabled", Status.PASS,
            Severity.INFO,
            f"Global policy and {len(repository_names)} configured repository policy value(s) require verification.",
            evidence=(f"Global SigLevel: {policy}",), confidence=Confidence.HIGH,
        )]

    @staticmethod
    def _is_disabled(policy: str) -> bool:
        return "never" in policy.casefold().split()
