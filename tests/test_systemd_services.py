import unittest
from pathlib import Path

from scanit.checks.systemd_services import SystemdDebugShellCheck
from scanit.commands import CommandResult
from scanit.context import ScanContext
from scanit.models import Status


class FakeCommands:
    def __init__(self, result):
        self.result = result

    def run(self, command, timeout=10):
        self.command = tuple(command)
        return self.result


class SystemdDebugShellTests(unittest.TestCase):
    def run_check(self, result):
        return SystemdDebugShellCheck().run(
            ScanContext(home=Path("/home/test"), root=Path("/"), commands=FakeCommands(result))
        )[0]

    def test_enabled_debug_shell_fails(self):
        self.assertIs(self.run_check(CommandResult(0, "enabled")).status, Status.FAIL)

    def test_disabled_debug_shell_passes(self):
        self.assertIs(self.run_check(CommandResult(1, "disabled")).status, Status.PASS)

    def test_missing_systemctl_is_unknown(self):
        self.assertIs(self.run_check(CommandResult(127, "missing")).status, Status.UNKNOWN)

    def test_unrecognized_result_is_unknown(self):
        self.assertIs(self.run_check(CommandResult(1, "access denied")).status, Status.UNKNOWN)


if __name__ == "__main__":
    unittest.main()
