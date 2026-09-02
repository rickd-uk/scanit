import os
import tempfile
import unittest
from pathlib import Path

from scanit.checks.sudo_policy import SudoPasswordlessRulesCheck
from scanit.context import ScanContext
from scanit.models import Status


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


if __name__ == "__main__":
    unittest.main()
