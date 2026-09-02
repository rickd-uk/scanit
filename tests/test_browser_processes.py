import unittest
from pathlib import Path

from scanit.checks.browser_processes import BrowserProcessFlagsCheck
from scanit.commands import CommandResult
from scanit.context import ScanContext
from scanit.models import Severity, Status


class FakeCommands:
    def __init__(self, result):
        self.result = result

    def run(self, command, timeout=10):
        self.command = tuple(command)
        return self.result


class BrowserProcessFlagsTests(unittest.TestCase):
    def run_check(self, result):
        context = ScanContext(home=Path("/home/test"), root=Path("/"), commands=FakeCommands(result))
        return BrowserProcessFlagsCheck().run(context)[0]

    def test_no_browser_is_not_applicable(self):
        finding = self.run_check(CommandResult(0, "1 systemd /sbin/init"))
        self.assertIs(finding.status, Status.NOT_APPLICABLE)

    def test_safe_browser_passes(self):
        finding = self.run_check(CommandResult(0, "321 firefox /usr/lib/firefox/firefox --new-window"))
        self.assertIs(finding.status, Status.PASS)

    def test_dangerous_flag_fails_without_leaking_command_line(self):
        finding = self.run_check(CommandResult(
            0, "456 brave /usr/bin/brave --no-sandbox https://example.test/private-token",
        ))
        self.assertIs(finding.status, Status.FAIL)
        self.assertIs(finding.severity, Severity.CRITICAL)
        self.assertIn("flag=--no-sandbox", finding.evidence[0])
        self.assertNotIn("private-token", finding.evidence[0])

    def test_missing_ps_is_unknown(self):
        finding = self.run_check(CommandResult(127, "ps not found"))
        self.assertIs(finding.status, Status.UNKNOWN)


if __name__ == "__main__":
    unittest.main()
