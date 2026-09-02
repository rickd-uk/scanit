import os
import tempfile
import unittest
from pathlib import Path

from scanit.checks.ssh_keys import SshAuthorizationPathPermissionsCheck, SshPrivateKeyPermissionsCheck
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


class SshAuthorizationPathPermissionsTests(unittest.TestCase):
    def run_check(self, directory_mode=0o700, files=(), symlink=False):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "home"
            ssh = home / ".ssh"
            ssh.mkdir(parents=True)
            ssh.chmod(directory_mode)
            for name, mode in files:
                path = ssh / name
                path.write_text("ssh-ed25519 test")
                path.chmod(mode)
            if symlink:
                os.symlink("/missing/authorized_keys", ssh / "authorized_keys")
            return SshAuthorizationPathPermissionsCheck().run(
                ScanContext(home=home, root=Path("/"), commands=None)
            )[0]

    def test_private_authorization_paths_pass(self):
        finding = self.run_check(files=(("authorized_keys", 0o600),))
        self.assertIs(finding.status, Status.PASS)

    def test_writable_ssh_directory_fails(self):
        finding = self.run_check(directory_mode=0o770)
        self.assertIs(finding.status, Status.FAIL)
        self.assertEqual(finding.evidence, (".ssh mode=0770",))

    def test_world_writable_authorized_keys_fails(self):
        finding = self.run_check(files=(("authorized_keys", 0o622),))
        self.assertIs(finding.status, Status.FAIL)
        self.assertEqual(finding.evidence, ("authorized_keys mode=0622",))

    def test_authorized_keys_symlink_is_not_followed(self):
        self.assertIs(self.run_check(symlink=True).status, Status.UNKNOWN)
