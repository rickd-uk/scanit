import unittest
from pathlib import Path

from scanit.checks.listeners import WildcardListenersCheck
from scanit.commands import CommandResult
from scanit.context import ScanContext
from scanit.models import Status


class FakeCommands:
    def __init__(self, result):
        self.result = result

    def run(self, command, timeout=10):
        self.command = tuple(command)
        return self.result


class WildcardListenersTests(unittest.TestCase):
    def run_check(self, result):
        context = ScanContext(home=Path("/home/test"), root=Path("/"), commands=FakeCommands(result))
        return WildcardListenersCheck().run(context)[0]

    def test_wildcard_listener_fails(self):
        finding = self.run_check(CommandResult(0, "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*"))
        self.assertIs(finding.status, Status.FAIL)
        self.assertEqual(finding.evidence, ("tcp 0.0.0.0:22",))

    def test_ipv6_wildcard_listener_fails(self):
        finding = self.run_check(CommandResult(0, "tcp LISTEN 0 128 [::]:443 [::]:*"))
        self.assertIs(finding.status, Status.FAIL)

    def test_loopback_listener_passes(self):
        finding = self.run_check(CommandResult(0, "tcp LISTEN 0 128 127.0.0.1:8080 0.0.0.0:*"))
        self.assertIs(finding.status, Status.PASS)

    def test_empty_output_passes(self):
        self.assertIs(self.run_check(CommandResult(0, "")).status, Status.PASS)

    def test_unrecognized_output_is_unknown(self):
        self.assertIs(self.run_check(CommandResult(0, "unexpected")).status, Status.UNKNOWN)


if __name__ == "__main__":
    unittest.main()
