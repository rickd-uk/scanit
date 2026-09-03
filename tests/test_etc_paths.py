import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scanit.checks.filesystem import EtcWritablePathsCheck
from scanit.context import ScanContext
from scanit.models import Status


class EtcWritablePathsTests(unittest.TestCase):
    def test_protected_tree_passes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "etc/sub").mkdir(parents=True)
            (root / "etc/sub/config").write_text("value")
            with patch("scanit.checks.filesystem.unsafe_privileged_metadata", return_value=False):
                finding = EtcWritablePathsCheck().run(ScanContext(Path("/home/test"), root, None))[0]
        self.assertIs(finding.status, Status.PASS)

    def test_writable_path_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "etc/config"
            path.parent.mkdir(parents=True)
            path.write_text("value")
            path.chmod(0o666)
            finding = EtcWritablePathsCheck().run(ScanContext(Path("/home/test"), root, None))[0]
        self.assertIs(finding.status, Status.FAIL)

    def test_missing_tree_is_not_applicable(self):
        with tempfile.TemporaryDirectory() as directory:
            finding = EtcWritablePathsCheck().run(ScanContext(Path("/home/test"), Path(directory), None))[0]
        self.assertIs(finding.status, Status.NOT_APPLICABLE)


if __name__ == "__main__":
    unittest.main()
