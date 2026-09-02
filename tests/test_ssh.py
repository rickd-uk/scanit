import unittest
from pathlib import Path

from scanit.checks.ssh import SshAuthenticationCheck
from scanit.commands import CommandResult
from scanit.context import ScanContext
from scanit.models import Severity, Status


class FakeCommands:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def run(self, command, timeout=10):
        self.calls.append((tuple(command), timeout))
        return self.responses.pop(0)


class SshAuthenticationTests(unittest.TestCase):
    def run_check(self, responses):
        commands = FakeCommands(responses)
        context = ScanContext(home=Path("/home/test"), root=Path("/"), commands=commands)
        return SshAuthenticationCheck().run(context), commands.calls

    def test_inactive_sshd_is_not_applicable(self):
        findings, calls = self.run_check([CommandResult(3, "inactive")])
        self.assertIs(findings[0].status, Status.NOT_APPLICABLE)
        self.assertEqual(len(calls), 1)

    def test_safe_effective_authentication_passes(self):
        findings, calls = self.run_check([
            CommandResult(0, "active"),
            CommandResult(0, "permitrootlogin no\npasswordauthentication no\nx11forwarding no\nallowtcpforwarding no\nclientaliveinterval 300"),
        ])
        self.assertEqual([finding.status for finding in findings], [Status.PASS] * 5)
        self.assertEqual(calls[-1], (("sshd", "-T"), 10))

    def test_root_and_password_authentication_fail(self):
        findings, _ = self.run_check([
            CommandResult(0, "active"),
            CommandResult(0, "permitrootlogin yes\npasswordauthentication yes"),
        ])
        self.assertEqual([finding.status for finding in findings[:2]], [Status.FAIL, Status.FAIL])
        self.assertIs(findings[0].severity, Severity.HIGH)

    def test_key_only_root_login_still_fails_at_medium(self):
        findings, _ = self.run_check([
            CommandResult(0, "active"),
            CommandResult(0, "permitrootlogin prohibit-password\npasswordauthentication no"),
        ])
        self.assertIs(findings[0].status, Status.FAIL)
        self.assertIs(findings[0].severity, Severity.MEDIUM)

    def test_missing_effective_directive_is_unknown(self):
        findings, _ = self.run_check([
            CommandResult(0, "active"),
            CommandResult(0, "passwordauthentication no"),
        ])
        self.assertIs(findings[0].status, Status.UNKNOWN)
        self.assertIs(findings[1].status, Status.PASS)

    def test_failed_sshd_t_is_error(self):
        findings, _ = self.run_check([
            CommandResult(0, "active"),
            CommandResult(1, "sshd: no hostkeys available"),
        ])
        self.assertIs(findings[0].status, Status.ERROR)

    def test_forwarding_and_no_idle_timeout_require_review(self):
        findings, _ = self.run_check([
            CommandResult(0, "active"),
            CommandResult(0, "permitrootlogin no\npasswordauthentication no\nx11forwarding yes\nallowtcpforwarding yes\nclientaliveinterval 0"),
        ])
        self.assertEqual([finding.status for finding in findings[2:]], [Status.REVIEW] * 3)


if __name__ == "__main__":
    unittest.main()
