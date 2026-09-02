import tempfile
import unittest
from pathlib import Path

from scanit.checks.boot import SecureBootCheck
from scanit.context import ScanContext
from scanit.models import Status


class SecureBootTests(unittest.TestCase):
    def run_check(self, root):
        context = ScanContext(home=Path("/home/test"), root=root, commands=None)
        return SecureBootCheck().run(context)[0]

    @staticmethod
    def write_variable(root, state):
        directory = root / "sys/firmware/efi/efivars"
        directory.mkdir(parents=True)
        (directory / "SecureBoot-test-guid").write_bytes(b"\x07\x00\x00\x00" + bytes([state]))

    def test_missing_efi_variables_is_unknown(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertIs(self.run_check(Path(directory)).status, Status.UNKNOWN)

    def test_enabled_secure_boot_passes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.write_variable(root, 1)
            self.assertIs(self.run_check(root).status, Status.PASS)

    def test_disabled_secure_boot_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.write_variable(root, 0)
            self.assertIs(self.run_check(root).status, Status.FAIL)

    def test_malformed_variable_is_error(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            directory_path = root / "sys/firmware/efi/efivars"
            directory_path.mkdir(parents=True)
            (directory_path / "SecureBoot-test-guid").write_bytes(b"bad")
            self.assertIs(self.run_check(root).status, Status.ERROR)


if __name__ == "__main__":
    unittest.main()
