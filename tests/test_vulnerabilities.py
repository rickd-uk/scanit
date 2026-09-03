import unittest
from pathlib import Path

from scanit.checks.vulnerabilities import ArchAuditCheck
from scanit.commands import CommandResult
from scanit.context import ScanContext
from scanit.models import Status


class FakeCommands:
    def __init__(self, result):
        self.result = result

    def run(self, command, timeout=10):
        self.command = tuple(command)
        self.timeout = timeout
        return self.result


class ArchAuditTests(unittest.TestCase):
    def run_check(self, result):
        commands = FakeCommands(result)
        context = ScanContext(home=Path("/home/test"), root=Path("/"), commands=commands)
        finding = ArchAuditCheck().run(context)[0]
        self.assertEqual(commands.command, ("arch-audit",))
        self.assertEqual(commands.timeout, 40)
        return finding

    def test_clean_audit_passes(self):
        self.assertIs(self.run_check(CommandResult(0, "")).status, Status.PASS)

    def test_vulnerable_packages_fail(self):
        finding = self.run_check(CommandResult(1, "openssl is affected by CVE-TEST\nlinux is affected by CVE-OTHER"))
        self.assertIs(finding.status, Status.FAIL)
        self.assertEqual(len(finding.evidence), 2)

    def test_missing_arch_audit_is_unknown(self):
        self.assertIs(self.run_check(CommandResult(127, "not found")).status, Status.UNKNOWN)

    def test_unexpected_failure_is_error(self):
        self.assertIs(self.run_check(CommandResult(2, "database unavailable")).status, Status.ERROR)

    def test_network_failure_with_vulnerability_exit_code_is_error(self):
        finding = self.run_check(CommandResult(
            1, "Error: failed to get AVG json\nBecause: failed to fetch AVGs from URL",
        ))
        self.assertIs(finding.status, Status.ERROR)

    def test_mixed_results_and_errors_are_not_reported_as_complete(self):
        finding = self.run_check(CommandResult(
            1, "openssl is affected by arbitrary code execution\nError: database incomplete",
        ))
        self.assertIs(finding.status, Status.ERROR)


if __name__ == "__main__":
    unittest.main()
