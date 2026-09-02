"""Inspect running browser processes for flags that disable security controls."""

from __future__ import annotations

import shlex

from ..context import ScanContext
from ..models import Confidence, Finding, Severity, Status


class BrowserProcessFlagsCheck:
    check_id = "browser.runtime.dangerous-flags"
    area = "browser"
    browser_names = ("brave", "chrome", "chromium", "firefox", "google-chrome")
    dangerous_flags = {
        "--no-sandbox": Severity.CRITICAL,
        "--disable-web-security": Severity.CRITICAL,
        "--ignore-certificate-errors": Severity.HIGH,
        "--remote-debugging-address": Severity.HIGH,
        "--remote-debugging-port": Severity.MEDIUM,
    }

    def run(self, context: ScanContext) -> list[Finding]:
        result = context.commands.run(("ps", "-eo", "pid=,comm=,args="), timeout=5)
        if result.returncode == 127:
            return [Finding(
                self.check_id, self.area, "Running browser flags could not be inspected", Status.UNKNOWN,
                Severity.INFO, "ps is not available.", confidence=Confidence.LOW,
            )]
        if result.returncode != 0:
            return [Finding(
                self.check_id, self.area, "Running browser flags could not be inspected", Status.ERROR,
                Severity.INFO, result.stdout or f"ps exited with status {result.returncode}.",
                confidence=Confidence.LOW,
            )]

        browser_count = 0
        evidence: list[str] = []
        severities: list[Severity] = []
        for line in result.stdout.splitlines():
            parts = line.strip().split(maxsplit=2)
            if len(parts) < 2:
                continue
            pid, executable = parts[0], parts[1]
            if not self._is_browser(executable):
                continue
            browser_count += 1
            arguments = self._arguments(parts[2] if len(parts) == 3 else "")
            for flag, severity in self.dangerous_flags.items():
                if any(argument == flag or argument.startswith(flag + "=") for argument in arguments):
                    evidence.append(f"pid={pid} executable={executable} flag={flag}")
                    severities.append(severity)

        if evidence:
            severity_order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
            severity = max(severities, key=severity_order.index)
            return [Finding(
                self.check_id, self.area, "Running browsers use dangerous command-line flags",
                Status.FAIL, severity, f"Detected {len(evidence)} dangerous browser flag occurrence(s).",
                evidence=tuple(evidence),
                remediation="Close the affected browser and remove the flag from its launcher or automation.",
                confidence=Confidence.HIGH,
            )]
        if not browser_count:
            return [Finding(
                self.check_id, self.area, "No supported browser process is running",
                Status.NOT_APPLICABLE, Severity.INFO, "No supported running browser was detected.",
            )]
        return [Finding(
            self.check_id, self.area, "No dangerous flags detected on running browsers",
            Status.PASS, Severity.INFO, f"Inspected {browser_count} supported browser process(es).",
        )]

    @classmethod
    def _is_browser(cls, executable: str) -> bool:
        value = executable.casefold()
        return any(value == name or value.startswith(name + "-") for name in cls.browser_names)

    @staticmethod
    def _arguments(command_line: str) -> list[str]:
        try:
            return shlex.split(command_line)
        except ValueError:
            return command_line.split()
