"""Audit local SSH private-key file permissions without reading key material."""

from __future__ import annotations

import stat
from pathlib import Path

from ..context import ScanContext
from ..models import Confidence, Finding, Severity, Status


class SshPrivateKeyPermissionsCheck:
    check_id = "system.ssh.private-key-permissions"
    area = "identity"

    def run(self, context: ScanContext) -> list[Finding]:
        directory = context.home / ".ssh"
        try:
            entries = list(directory.iterdir())
        except FileNotFoundError:
            return [Finding(
                self.check_id, self.area, "No SSH private keys detected", Status.NOT_APPLICABLE,
                Severity.INFO, f"{directory} does not exist.", confidence=Confidence.HIGH,
            )]
        except OSError as error:
            return [Finding(
                self.check_id, self.area, "SSH private-key permissions could not be inspected", Status.UNKNOWN,
                Severity.INFO, str(error), confidence=Confidence.LOW,
            )]

        candidates = [entry for entry in entries if self._is_private_key_candidate(entry)]
        if not candidates:
            return [Finding(
                self.check_id, self.area, "No SSH private keys detected", Status.NOT_APPLICABLE,
                Severity.INFO, f"No id_* private-key files were found in {directory}.", confidence=Confidence.HIGH,
            )]

        exposed: list[str] = []
        errors: list[str] = []
        checked = 0
        for path in candidates:
            try:
                info = path.lstat()
            except OSError as error:
                errors.append(f"{path.name}: {error}")
                continue
            if stat.S_ISLNK(info.st_mode):
                errors.append(f"{path.name}: symbolic link was not followed")
                continue
            if not stat.S_ISREG(info.st_mode):
                continue
            checked += 1
            mode = stat.S_IMODE(info.st_mode)
            if mode & 0o077:
                exposed.append(f"{path.name} mode={mode:04o}")

        if exposed:
            return [Finding(
                self.check_id, self.area, "SSH private keys are accessible to other local users", Status.FAIL,
                Severity.HIGH, f"{len(exposed)} private key file(s) grant group or other permissions.",
                evidence=tuple(exposed),
                remediation="Set each affected SSH private key to owner-only mode (for example, chmod 600 ~/.ssh/id_*).",
                confidence=Confidence.HIGH,
            )]
        if errors:
            return [Finding(
                self.check_id, self.area, "SSH private-key permissions could not be fully verified", Status.UNKNOWN,
                Severity.INFO, f"Checked {checked} private key file(s); {len(errors)} path(s) were skipped.",
                evidence=tuple(errors), confidence=Confidence.LOW,
            )]
        if not checked:
            return [Finding(
                self.check_id, self.area, "No SSH private keys detected", Status.NOT_APPLICABLE,
                Severity.INFO, "No regular id_* private-key files were found.", confidence=Confidence.MEDIUM,
            )]
        return [Finding(
            self.check_id, self.area, "SSH private-key permissions are owner-only", Status.PASS,
            Severity.INFO, f"Checked {checked} SSH private key file(s).", confidence=Confidence.HIGH,
        )]

    @staticmethod
    def _is_private_key_candidate(path: Path) -> bool:
        return path.name.startswith("id_") and not path.name.endswith((".pub", "-cert.pub"))
