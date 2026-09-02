import unittest
from pathlib import Path

from scanit.checks.packages import PendingPackageUpdatesCheck
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


class PendingPackageUpdatesTests(unittest.TestCase):
    def run_check(self, result):
        commands = FakeCommands(result)
        context = ScanContext(home=Path("/home/test"), root=Path("/"), commands=commands)
        finding = PendingPackageUpdatesCheck().run(context)[0]
        self.assertEqual(commands.calls, [(("pacman", "-Qu"), 25)])
        return finding

    def test_pending_updates_fail_with_evidence(self):
        finding = self.run_check(CommandResult(0, "linux 6.1-1 -> 6.1-2\nopenssl 3.0-1 -> 3.0-2"))
        self.assertIs(finding.status, Status.FAIL)
        self.assertEqual(len(finding.evidence), 2)

    def test_no_updates_passes(self):
        finding = self.run_check(CommandResult(1, ""))
        self.assertIs(finding.status, Status.PASS)

    def test_missing_pacman_is_unknown(self):
        finding = self.run_check(CommandResult(127, "[Errno 2] No such file or directory: 'pacman'"))
        self.assertIs(finding.status, Status.UNKNOWN)

    def test_unexpected_pacman_failure_is_error(self):
        finding = self.run_check(CommandResult(2, "error: failed to synchronize all databases"))
        self.assertIs(finding.status, Status.ERROR)


if __name__ == "__main__":
    unittest.main()
