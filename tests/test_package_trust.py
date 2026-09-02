import unittest
from pathlib import Path

from scanit.checks.package_trust import PacmanSignaturePolicyCheck
from scanit.commands import CommandResult
from scanit.context import ScanContext
from scanit.models import Status


class FakeCommands:
    def __init__(self, result):
        self.result = result
        self.calls = []

    def run(self, command, timeout=10):
        self.calls.append((tuple(command), timeout))
        return self.result


class PacmanSignaturePolicyTests(unittest.TestCase):
    def run_check(self, result):
        commands = FakeCommands(result)
        context = ScanContext(home=Path("/home/test"), root=Path("/"), commands=commands)
        finding = PacmanSignaturePolicyCheck().run(context)[0]
        self.assertEqual(commands.calls, [(("pacman-conf", "SigLevel"), 10)])
        return finding

    def test_required_signature_policy_passes(self):
        finding = self.run_check(CommandResult(0, "Required DatabaseOptional"))
        self.assertIs(finding.status, Status.PASS)

    def test_never_signature_policy_fails(self):
        finding = self.run_check(CommandResult(0, "Never"))
        self.assertIs(finding.status, Status.FAIL)

    def test_empty_policy_is_unknown(self):
        finding = self.run_check(CommandResult(0, ""))
        self.assertIs(finding.status, Status.UNKNOWN)

    def test_missing_pacman_conf_is_unknown(self):
        finding = self.run_check(CommandResult(127, "missing pacman-conf"))
        self.assertIs(finding.status, Status.UNKNOWN)


if __name__ == "__main__":
    unittest.main()
