import tempfile
import unittest
from pathlib import Path

from scanit.checks.accounts import EmptyPasswordsCheck, HomeDirectoryPermissionsCheck, UidZeroAccountsCheck
from scanit.context import ScanContext
from scanit.models import Status


class UidZeroAccountsTests(unittest.TestCase):
    def run_check(self, content=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            if content is not None:
                passwd = root / "etc/passwd"
                passwd.parent.mkdir()
                passwd.write_text(content)
            context = ScanContext(home=Path("/home/test"), root=root, commands=None)
            return UidZeroAccountsCheck().run(context)[0]

    def test_only_root_passes(self):
        finding = self.run_check("root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000::/home/user:/bin/bash\n")
        self.assertIs(finding.status, Status.PASS)

    def test_additional_uid_zero_account_fails(self):
        finding = self.run_check("root:x:0:0:root:/root:/bin/bash\nadmin:x:0:0::/root:/bin/bash\n")
        self.assertIs(finding.status, Status.FAIL)
        self.assertIn("account=admin", finding.evidence[0])

    def test_missing_passwd_is_unknown(self):
        self.assertIs(self.run_check().status, Status.UNKNOWN)

    def test_malformed_entry_makes_clean_result_unknown(self):
        finding = self.run_check("root:x:0:0:root:/root:/bin/bash\nbroken\n")
        self.assertIs(finding.status, Status.UNKNOWN)


class HomeDirectoryPermissionsTests(unittest.TestCase):
    def run_check(self, home):
        context = ScanContext(home=home, root=Path("/"), commands=None)
        return HomeDirectoryPermissionsCheck().run(context)[0]

    def test_owner_only_home_passes(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            home.chmod(0o700)
            self.assertIs(self.run_check(home).status, Status.PASS)

    def test_world_writable_home_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            home.chmod(0o707)
            finding = self.run_check(home)
            self.assertIs(finding.status, Status.FAIL)
            self.assertIn("world-writable", finding.evidence[0])

    def test_missing_home_is_unknown(self):
        self.assertIs(self.run_check(Path("/missing-home-for-scanit-tests")).status, Status.UNKNOWN)


class EmptyPasswordsTests(unittest.TestCase):
    def run_check(self, content=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            if content is not None:
                shadow = root / "etc/shadow"
                shadow.parent.mkdir()
                shadow.write_text(content)
            context = ScanContext(home=Path("/home/test"), root=root, commands=None)
            return EmptyPasswordsCheck().run(context)[0]

    def test_hashes_and_lock_markers_pass(self):
        finding = self.run_check("root:!:20000::::::\nuser:$6$hash:20000::::::\n")
        self.assertIs(finding.status, Status.PASS)

    def test_empty_password_field_fails(self):
        finding = self.run_check("root:!:20000::::::\nuser::20000::::::\n")
        self.assertIs(finding.status, Status.FAIL)
        self.assertEqual(finding.evidence, ("account=user",))

    def test_missing_shadow_is_unknown(self):
        self.assertIs(self.run_check().status, Status.UNKNOWN)

    def test_malformed_shadow_is_unknown(self):
        self.assertIs(self.run_check("broken\n").status, Status.UNKNOWN)


if __name__ == "__main__":
    unittest.main()
