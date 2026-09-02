import tempfile
import unittest
from pathlib import Path

from scanit.checks.filesystem import TemporaryDirectoryPermissionsCheck
from scanit.context import ScanContext
from scanit.models import Status


class TemporaryDirectoryPermissionsTests(unittest.TestCase):
    def run_check(self, modes):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for relative, mode in modes.items():
                path = root / relative
                path.mkdir(parents=True, exist_ok=True)
                path.chmod(mode)
            return TemporaryDirectoryPermissionsCheck().run(
                ScanContext(home=Path("/home/test"), root=root, commands=None)
            )[0]

    def test_sticky_world_writable_directory_passes(self):
        self.assertIs(self.run_check({"tmp": 0o1777}).status, Status.PASS)

    def test_world_writable_directory_without_sticky_bit_fails(self):
        finding = self.run_check({"tmp": 0o777})
        self.assertIs(finding.status, Status.FAIL)
        self.assertIn("tmp owner", finding.evidence[0])

    def test_missing_standard_directories_are_not_applicable(self):
        self.assertIs(self.run_check({}).status, Status.NOT_APPLICABLE)

    def test_non_directory_path_is_unknown(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "tmp"
            path.write_text("file")
            finding = TemporaryDirectoryPermissionsCheck().run(
                ScanContext(home=Path("/home/test"), root=root, commands=None)
            )[0]
        self.assertIs(finding.status, Status.UNKNOWN)


if __name__ == "__main__":
    unittest.main()
