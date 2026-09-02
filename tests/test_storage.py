import json
import unittest
from pathlib import Path

from scanit.checks.storage import RootFilesystemEncryptionCheck
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


if __name__ == "__main__":
    unittest.main()
