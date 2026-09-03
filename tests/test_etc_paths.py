import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from scanit.checks.filesystem import EtcOwnershipReviewCheck, EtcWritablePathsCheck
from scanit.context import ScanContext
from scanit.models import Status


class EtcWritablePathsTests(unittest.TestCase):
    def test_protected_tree_passes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "etc/sub").mkdir(parents=True)
            (root / "etc/sub/config").write_text("value")
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

    def test_non_root_owner_without_group_write_is_not_a_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "etc/service/config"
            (root / "etc").mkdir()
            metadata = [(path, SimpleNamespace(st_uid=207, st_mode=stat.S_IFREG | 0o600))]
            with patch("scanit.checks.filesystem._inspect_etc_tree", return_value=(metadata, [], 1)):
                finding = EtcWritablePathsCheck().run(ScanContext(Path("/home/test"), root, None))[0]
        self.assertIs(finding.status, Status.PASS)


class EtcOwnershipReviewTests(unittest.TestCase):
    def test_non_root_owned_path_requires_review(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "etc/service/config"
            (root / "etc").mkdir()
            metadata = [(path, SimpleNamespace(st_uid=207, st_mode=stat.S_IFREG | 0o600))]
            with patch("scanit.checks.filesystem._inspect_etc_tree", return_value=(metadata, [], 1)):
                finding = EtcOwnershipReviewCheck().run(ScanContext(Path("/home/test"), root, None))[0]
        self.assertIs(finding.status, Status.REVIEW)

    def test_group_writable_path_is_left_to_writable_check(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "etc/config"
            (root / "etc").mkdir()
            metadata = [(path, SimpleNamespace(st_uid=207, st_mode=stat.S_IFREG | 0o620))]
            with patch("scanit.checks.filesystem._inspect_etc_tree", return_value=(metadata, [], 1)):
                finding = EtcOwnershipReviewCheck().run(ScanContext(Path("/home/test"), root, None))[0]
        self.assertIs(finding.status, Status.PASS)

    def test_missing_tree_is_not_applicable(self):
        with tempfile.TemporaryDirectory() as directory:
            finding = EtcOwnershipReviewCheck().run(
                ScanContext(Path("/home/test"), Path(directory), None)
            )[0]
        self.assertIs(finding.status, Status.NOT_APPLICABLE)


if __name__ == "__main__":
    unittest.main()
