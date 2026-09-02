import unittest
from pathlib import Path

from scanit.checks.time_sync import NtpSynchronizationCheck
from scanit.commands import CommandResult
from scanit.context import ScanContext
from scanit.models import Status


class FakeCommands:
    def __init__(self, result):
        self.result = result

    def run(self, command, timeout=10):
        self.command = tuple(command)
        return self.result


class NtpSynchronizationTests(unittest.TestCase):
    def run_check(self, result):
        context = ScanContext(home=Path("/home/test"), root=Path("/"), commands=FakeCommands(result))
        return NtpSynchronizationCheck().run(context)[0]

    def test_synchronized_clock_passes(self):
        self.assertIs(self.run_check(CommandResult(0, "yes")).status, Status.PASS)

    def test_unsynchronized_clock_requires_review(self):
        self.assertIs(self.run_check(CommandResult(0, "no")).status, Status.REVIEW)

    def test_unavailable_tool_is_unknown(self):
        self.assertIs(self.run_check(CommandResult(127, "missing")).status, Status.UNKNOWN)

    def test_unexpected_output_is_unknown(self):
        self.assertIs(self.run_check(CommandResult(0, "maybe")).status, Status.UNKNOWN)


if __name__ == "__main__":
    unittest.main()
