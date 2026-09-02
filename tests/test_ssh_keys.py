import os
import tempfile
import unittest
from pathlib import Path

from scanit.checks.ssh_keys import SshPrivateKeyPermissionsCheck
from scanit.context import ScanContext
from scanit.models import Status


class SshPrivateKeyPermissionsTests(unittest.TestCase):
    def run_check(self, files=(), symlink=False):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "home"
            ssh = home / ".ssh"
            ssh.mkdir(parents=True)
            for name, mode in files:
                path = ssh / name
                path.write_text("not-a-real-key")
                path.chmod(mode)
            if symlink:
                os.symlink("/missing/key", ssh / "id_link")
            return SshPrivateKeyPermissionsCheck().run(
                ScanContext(home=home, root=Path("/"), commands=None)
            )[0]

    def test_owner_only_private_key_passes(self):
        self.assertIs(self.run_check((("id_ed25519", 0o600),)).status, Status.PASS)

    def test_group_readable_private_key_fails(self):
        finding = self.run_check((("id_rsa", 0o640),))
        self.assertIs(finding.status, Status.FAIL)
        self.assertEqual(finding.evidence, ("id_rsa mode=0640",))

    def test_public_key_is_not_treated_as_private_material(self):
        self.assertIs(self.run_check((("id_ed25519.pub", 0o644),)).status, Status.NOT_APPLICABLE)

    def test_symbolic_link_is_not_followed(self):
        self.assertIs(self.run_check(symlink=True).status, Status.UNKNOWN)


if __name__ == "__main__":
    unittest.main()
