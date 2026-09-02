import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scanit.checks.filesystem import SensitiveSystemFilePermissionsCheck
from scanit.context import ScanContext
from scanit.models import Status


class SensitiveSystemFilePermissionsTests(unittest.TestCase):
    def run_check(self, files=()):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for relative, mode in files:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("placeholder")
                path.chmod(mode)
            with patch("scanit.checks.filesystem.unsafe_privileged_metadata", return_value=False):
                return SensitiveSystemFilePermissionsCheck().run(
                    ScanContext(home=Path("/home/test"), root=root, commands=None)
                )

    def test_protected_files_pass(self):
        files = [(relative, 0o640) for _, relative, _ in SensitiveSystemFilePermissionsCheck.targets]
        self.assertTrue(all(finding.status is Status.PASS for finding in self.run_check(files)))

    def test_world_writable_shadow_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "etc/shadow"
            path.parent.mkdir(parents=True)
            path.write_text("placeholder")
            path.chmod(0o666)
            findings = SensitiveSystemFilePermissionsCheck().run(
                ScanContext(home=Path("/home/test"), root=root, commands=None)
            )
        shadow = next(finding for finding in findings if finding.check_id.endswith("shadow-permissions"))
        self.assertIs(shadow.status, Status.FAIL)

    def test_missing_files_are_not_applicable(self):
        self.assertTrue(all(finding.status is Status.NOT_APPLICABLE for finding in self.run_check()))

    def test_directory_instead_of_file_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "etc/passwd").mkdir(parents=True)
            with patch("scanit.checks.filesystem.unsafe_privileged_metadata", return_value=False):
                findings = SensitiveSystemFilePermissionsCheck().run(
                    ScanContext(home=Path("/home/test"), root=root, commands=None)
                )
        self.assertIs(findings[0].status, Status.FAIL)


if __name__ == "__main__":
    unittest.main()
