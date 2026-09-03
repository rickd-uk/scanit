import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scanit.checks.storage import RootFilesystemEncryptionCheck, SharedFilesystemMountOptionsCheck
from scanit.commands import CommandResult
from scanit.context import ScanContext
from scanit.models import Status


class FakeCommands:
    def __init__(self, result):
        self.result = result

    def run(self, command, timeout=10):
        self.command = tuple(command)
        return self.result


class RootFilesystemEncryptionTests(unittest.TestCase):
    def run_check(self, payload, returncode=0):
        output = payload if isinstance(payload, str) else json.dumps(payload)
        commands = FakeCommands(CommandResult(returncode, output))
        context = ScanContext(home=Path("/home/test"), root=Path("/"), commands=commands)
        return RootFilesystemEncryptionCheck().run(context)[0]

    def test_crypt_ancestor_passes(self):
        finding = self.run_check({"blockdevices": [{
            "name": "nvme0n1", "type": "disk", "mountpoints": [None], "children": [{
                "name": "nvme0n1p2", "type": "part", "mountpoints": [None], "children": [{
                    "name": "cryptroot", "type": "crypt", "mountpoints": ["/"],
                }],
            }],
        }]})
        self.assertIs(finding.status, Status.PASS)

    def test_unencrypted_root_fails(self):
        finding = self.run_check({"blockdevices": [{
            "name": "sda1", "type": "part", "mountpoints": ["/"],
        }]})
        self.assertIs(finding.status, Status.FAIL)

    def test_missing_root_mapping_is_unknown(self):
        finding = self.run_check({"blockdevices": [{
            "name": "sda1", "type": "part", "mountpoints": ["/boot"],
        }]})
        self.assertIs(finding.status, Status.UNKNOWN)

    def test_invalid_json_is_error(self):
        self.assertIs(self.run_check("not-json").status, Status.ERROR)


class SharedFilesystemMountOptionsTests(unittest.TestCase):
    safe_ntfs3 = (
        "36 25 8:17 / /run/media/test/Windows rw,nosuid,nodev,noexec,relatime shared:5 "
        "- ntfs3 /dev/sdb1 rw,uid=1000,gid=1000,umask=0077\n"
    )

    def run_check(self, mountinfo):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "proc/self"
            path.mkdir(parents=True)
            (path / "mountinfo").write_text(mountinfo, encoding="utf-8")
            context = ScanContext(home=Path("/home/test"), root=Path(directory), commands=FakeCommands(None))
            return SharedFilesystemMountOptionsCheck().run(context)[0]

    def test_hardened_ntfs3_mount_passes_and_reports_implementation(self):
        finding = self.run_check(self.safe_ntfs3)
        self.assertIs(finding.status, Status.PASS)
        self.assertIn("kernel NTFS3", finding.evidence[0])
        self.assertIn("uid=1000", finding.evidence[0])
        self.assertIn("access=rw", finding.evidence[0])

    def test_fuseblk_mount_reports_probable_ntfs3g_implementation(self):
        finding = self.run_check(
            "40 25 8:33 / /mnt/shared ro,nosuid,nodev,noexec - fuseblk /dev/sdc1 "
            "ro,user_id=0,group_id=0\n"
        )
        self.assertIs(finding.status, Status.PASS)
        self.assertIn("commonly NTFS-3G", finding.evidence[0])

    def test_missing_security_options_require_review(self):
        finding = self.run_check(
            "37 25 8:18 / /run/media/test/Shared rw,relatime - exfat /dev/sdb2 "
            "rw,uid=1000,gid=1000,fmask=0022,dmask=0022\n"
        )
        self.assertIs(finding.status, Status.REVIEW)
        self.assertIn("nodev", finding.summary)
        self.assertIn("missing nodev,noexec,nosuid", finding.evidence[0])
        self.assertIn("fmask=0022", finding.evidence[0])

    def test_mountinfo_escapes_are_decoded(self):
        finding = self.run_check(self.safe_ntfs3.replace("/Windows", "/Windows\\040Data"))
        self.assertIn("/Windows Data:", finding.evidence[0])

    def test_no_shared_mount_is_not_applicable(self):
        finding = self.run_check("25 1 0:22 / / rw,relatime - ext4 /dev/root rw\n")
        self.assertIs(finding.status, Status.NOT_APPLICABLE)

    def test_efi_system_partition_is_not_treated_as_shared_storage(self):
        finding = self.run_check(
            "39 25 259:1 / /boot/efi ro,nosuid,nodev - vfat /dev/nvme0n1p1 "
            "ro,fmask=0077,dmask=0077\n"
        )
        self.assertIs(finding.status, Status.NOT_APPLICABLE)

    def test_malformed_mountinfo_is_error(self):
        self.assertIs(self.run_check("not mountinfo\n").status, Status.ERROR)

    def test_empty_mountinfo_is_error(self):
        self.assertIs(self.run_check("").status, Status.ERROR)

    def test_missing_mountinfo_is_unknown(self):
        with tempfile.TemporaryDirectory() as directory:
            context = ScanContext(
                home=Path("/home/test"), root=Path(directory), commands=FakeCommands(None),
            )
            finding = SharedFilesystemMountOptionsCheck().run(context)[0]
        self.assertIs(finding.status, Status.UNKNOWN)

    def test_unreadable_mountinfo_is_unknown(self):
        context = ScanContext(home=Path("/home/test"), root=Path("/"), commands=FakeCommands(None))
        with patch.object(Path, "read_text", side_effect=PermissionError("denied")):
            finding = SharedFilesystemMountOptionsCheck().run(context)[0]
        self.assertIs(finding.status, Status.UNKNOWN)


if __name__ == "__main__":
    unittest.main()
