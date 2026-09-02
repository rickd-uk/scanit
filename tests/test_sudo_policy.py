import os
import tempfile
import unittest
from pathlib import Path

from scanit.checks.sudo_policy import SudoBroadCommandRulesCheck, SudoPasswordlessRulesCheck, SudoPolicySyntaxCheck, SudoSecurePathCheck
from scanit.commands import CommandResult
from scanit.context import ScanContext
from scanit.models import Status
from unittest.mock import patch


class SudoPasswordlessRulesTests(unittest.TestCase):
    def run_check(self, main=None, drop_ins=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            if main is not None:
                path = root / "etc/sudoers"
                path.parent.mkdir(parents=True)
                path.write_text(main)
            if drop_ins:
                target = root / "etc/sudoers.d"
                target.mkdir(parents=True, exist_ok=True)
                for name, content in drop_ins.items():
                    (target / name).write_text(content)
            return SudoPasswordlessRulesCheck().run(
                ScanContext(home=Path("/home/test"), root=root, commands=None)
            )[0]

    def test_password_required_policy_passes(self):
        self.assertIs(self.run_check("%wheel ALL=(ALL:ALL) ALL\n").status, Status.PASS)

    def test_nopasswd_drop_in_requires_review(self):
        finding = self.run_check(
            "root ALL=(ALL:ALL) ALL\n",
            {"automation": "deploy ALL=(root) NOPASSWD: /usr/bin/systemctl\n"},
        )
        self.assertIs(finding.status, Status.REVIEW)
        self.assertIn("NOPASSWD tag", finding.evidence[0])

    def test_comment_does_not_trigger_review(self):
        finding = self.run_check("# example NOPASSWD: ALL\nroot ALL=(ALL:ALL) ALL\n")
        self.assertIs(finding.status, Status.PASS)

    def test_continued_rule_is_detected(self):
        policy = "deploy ALL=(root) " + "\\\n" + "    NOPASSWD: /usr/bin/systemctl\n"
        self.assertIs(self.run_check(policy).status, Status.REVIEW)

    def test_authenticate_default_disabled_requires_review(self):
        self.assertIs(self.run_check("Defaults:deploy !authenticate\n").status, Status.REVIEW)

    def test_missing_policy_is_not_applicable(self):
        self.assertIs(self.run_check().status, Status.NOT_APPLICABLE)

    def test_ignored_drop_in_names_are_skipped(self):
        finding = self.run_check(
            "root ALL=(ALL:ALL) ALL\n",
            {"README.example": "user ALL=NOPASSWD: ALL\n"},
        )
        self.assertIs(finding.status, Status.PASS)

    def test_standard_include_directory_is_covered(self):
        finding = self.run_check("#includedir /etc/sudoers.d\nroot ALL=(ALL:ALL) ALL\n")
        self.assertIs(finding.status, Status.PASS)

    def test_custom_include_prevents_false_pass(self):
        finding = self.run_check("@include /opt/company/sudoers\nroot ALL=(ALL:ALL) ALL\n")
        self.assertIs(finding.status, Status.UNKNOWN)

    def test_drop_in_symlink_is_not_followed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            main = root / "etc/sudoers"
            drop_ins = root / "etc/sudoers.d"
            drop_ins.mkdir(parents=True)
            main.write_text("root ALL=(ALL:ALL) ALL\n")
            os.symlink("/etc/passwd", drop_ins / "linked")
            finding = SudoPasswordlessRulesCheck().run(
                ScanContext(home=Path("/home/test"), root=root, commands=None)
            )[0]
        self.assertIs(finding.status, Status.UNKNOWN)


class SudoBroadCommandRulesTests(unittest.TestCase):
    def run_check(self, main=None, drop_ins=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            if main is not None:
                path = root / "etc/sudoers"
                path.parent.mkdir(parents=True)
                path.write_text(main)
            if drop_ins:
                target = root / "etc/sudoers.d"
                target.mkdir(parents=True, exist_ok=True)
                for name, content in drop_ins.items():
                    (target / name).write_text(content)
            return SudoBroadCommandRulesCheck().run(
                ScanContext(home=Path("/home/test"), root=root, commands=None)
            )[0]

    def test_exact_command_passes(self):
        self.assertIs(self.run_check("deploy ALL=(root) /usr/bin/systemctl restart app.service\n").status, Status.PASS)

    def test_non_root_all_command_requires_review(self):
        self.assertIs(self.run_check("%wheel ALL=(ALL:ALL) ALL\n").status, Status.REVIEW)

    def test_wildcard_arguments_require_review(self):
        self.assertIs(self.run_check("deploy ALL=(root) /usr/bin/systemctl restart *\n").status, Status.REVIEW)

    def test_standard_root_rule_is_not_reported(self):
        self.assertIs(self.run_check("root ALL=(ALL:ALL) ALL\n").status, Status.PASS)


class FakeCommands:
    def __init__(self, result):
        self.result = result

    def run(self, command, timeout=10):
        self.command = tuple(command)
        self.timeout = timeout
        return self.result


class SudoPolicySyntaxTests(unittest.TestCase):
    def run_check(self, result, policy=True):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            if policy:
                path = root / "etc/sudoers"
                path.parent.mkdir(parents=True)
                path.write_text("root ALL=(ALL:ALL) ALL\n")
            commands = FakeCommands(result)
            finding = SudoPolicySyntaxCheck().run(
                ScanContext(home=Path("/home/test"), root=root, commands=commands)
            )[0]
            return finding, commands

    def test_valid_policy_passes(self):
        finding, commands = self.run_check(CommandResult(0, "/etc/sudoers: parsed OK"))
        self.assertIs(finding.status, Status.PASS)
        self.assertEqual(commands.command[:3], ("visudo", "-c", "-f"))

    def test_invalid_policy_fails(self):
        finding, _ = self.run_check(CommandResult(1, "syntax error near line 4"))
        self.assertIs(finding.status, Status.FAIL)

    def test_missing_visudo_is_unknown(self):
        finding, _ = self.run_check(CommandResult(127, "missing"))
        self.assertIs(finding.status, Status.UNKNOWN)

    def test_missing_policy_is_not_applicable(self):
        finding, commands = self.run_check(CommandResult(0, "unused"), policy=False)
        self.assertIs(finding.status, Status.NOT_APPLICABLE)
        self.assertFalse(hasattr(commands, "command"))


class SudoSecurePathTests(unittest.TestCase):
    def run_check(self, policy, directories=()):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sudoers = root / "etc/sudoers"
            sudoers.parent.mkdir(parents=True)
            sudoers.write_text(policy)
            for relative in directories:
                (root / relative).mkdir(parents=True, exist_ok=True)
            with patch("scanit.checks.sudo_policy.unsafe_privileged_metadata", return_value=False):
                return SudoSecurePathCheck().run(
                    ScanContext(home=Path("/home/test"), root=root, commands=None)
                )[0]

    def test_protected_absolute_path_passes(self):
        finding = self.run_check('Defaults secure_path="/usr/bin:/usr/sbin"\n', ("usr/bin", "usr/sbin"))
        self.assertIs(finding.status, Status.PASS)

    def test_relative_component_fails(self):
        finding = self.run_check('Defaults secure_path="/usr/bin:local/bin"\n', ("usr/bin",))
        self.assertIs(finding.status, Status.FAIL)

    def test_empty_component_fails(self):
        finding = self.run_check('Defaults secure_path="/usr/bin::/usr/sbin"\n', ("usr/bin", "usr/sbin"))
        self.assertIs(finding.status, Status.FAIL)

    def test_parent_traversal_component_fails(self):
        finding = self.run_check('Defaults secure_path="/usr/../../tmp/bin"\n')
        self.assertIs(finding.status, Status.FAIL)

    def test_missing_definition_is_unknown(self):
        self.assertIs(self.run_check("Defaults env_reset\n").status, Status.UNKNOWN)

    def test_missing_directory_is_unknown(self):
        self.assertIs(self.run_check('Defaults secure_path="/missing/bin"\n').status, Status.UNKNOWN)


if __name__ == "__main__":
    unittest.main()
