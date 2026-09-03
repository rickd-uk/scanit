import os
import tempfile
import unittest
from pathlib import Path

from scanit.checks.filesystem import UserStartupFilePermissionsCheck
from scanit.context import ScanContext
from scanit.models import Status


class UserStartupFilePermissionsTests(unittest.TestCase):
    def run_check(self, files=()):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            for relative, mode in files:
                path = home / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("# startup")
                path.chmod(mode)
            return UserStartupFilePermissionsCheck().run(
                ScanContext(home=home, root=Path("/"), commands=None)
            )[0]

    def test_protected_startup_file_passes(self):
        self.assertIs(self.run_check(((".profile", 0o600),)).status, Status.PASS)

    def test_group_writable_startup_file_fails(self):
        self.assertIs(self.run_check(((".bashrc", 0o660),)).status, Status.FAIL)

    def test_missing_paths_are_not_applicable(self):
        self.assertIs(self.run_check().status, Status.NOT_APPLICABLE)

    def test_symlink_startup_path_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            os.symlink("/etc/profile", home / ".profile")
            finding = UserStartupFilePermissionsCheck().run(
                ScanContext(home=home, root=Path("/"), commands=None)
            )[0]
        self.assertIs(finding.status, Status.FAIL)


if __name__ == "__main__":
    unittest.main()
