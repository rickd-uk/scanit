import tempfile
import unittest
from pathlib import Path

from scanit.checks.security_modules import LinuxSecurityModulesCheck
from scanit.context import ScanContext
from scanit.models import Status


class LinuxSecurityModulesTests(unittest.TestCase):
    def run_check(self, lsm=None, lockdown=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            security = root / "sys/kernel/security"
            security.mkdir(parents=True)
            if lsm is not None:
                (security / "lsm").write_text(lsm)
            if lockdown is not None:
                (security / "lockdown").write_text(lockdown)
            context = ScanContext(home=Path("/home/test"), root=root, commands=None)
            return LinuxSecurityModulesCheck().run(context)

    def test_apparmor_and_integrity_lockdown_pass(self):
        findings = self.run_check("capability,landlock,apparmor,yama", "none [integrity] confidentiality")
        self.assertEqual([finding.status for finding in findings], [Status.PASS, Status.PASS])

    def test_no_mac_and_no_lockdown_fail(self):
        findings = self.run_check("capability,landlock,yama", "[none] integrity confidentiality")
        self.assertEqual([finding.status for finding in findings], [Status.FAIL, Status.FAIL])

    def test_missing_interfaces_preserve_coverage(self):
        findings = self.run_check()
        self.assertEqual([finding.status for finding in findings], [Status.UNKNOWN, Status.NOT_APPLICABLE])

    def test_malformed_lockdown_state_is_error(self):
        findings = self.run_check("selinux", "none integrity confidentiality")
        self.assertIs(findings[1].status, Status.ERROR)


if __name__ == "__main__":
    unittest.main()
