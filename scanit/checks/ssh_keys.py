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


class SshAuthorizationPathPermissionsCheck:
    check_id = "system.ssh.authorization-path-permissions"
    area = "identity"
    key_filenames = ("authorized_keys", "authorized_keys2")

    def run(self, context: ScanContext) -> list[Finding]:
        directory = context.home / ".ssh"
        try:
            directory_info = directory.lstat()
        except FileNotFoundError:
            return [Finding(
                self.check_id, self.area, "No SSH authorization path detected", Status.NOT_APPLICABLE,
                Severity.INFO, f"{directory} does not exist.", confidence=Confidence.HIGH,
            )]
        except OSError as error:
            return [Finding(
                self.check_id, self.area, "SSH authorization-path permissions could not be inspected",
                Status.UNKNOWN, Severity.INFO, str(error), confidence=Confidence.LOW,
            )]
        if not stat.S_ISDIR(directory_info.st_mode):
            return [Finding(
                self.check_id, self.area, "SSH authorization path is not a directory", Status.UNKNOWN,
                Severity.INFO, f"{directory} is not a directory.", confidence=Confidence.LOW,
            )]

        exposed: list[str] = []
        errors: list[str] = []
        paths_checked = 1
        directory_mode = stat.S_IMODE(directory_info.st_mode)
        if directory_mode & 0o022:
            exposed.append(f".ssh mode={directory_mode:04o}")
        for filename in self.key_filenames:
            path = directory / filename
            try:
                info = path.lstat()
            except FileNotFoundError:
                continue
            except OSError as error:
                errors.append(f"{filename}: {error}")
                continue
            if stat.S_ISLNK(info.st_mode):
                errors.append(f"{filename}: symbolic link was not followed")
                continue
            if not stat.S_ISREG(info.st_mode):
                errors.append(f"{filename}: not a regular file")
                continue
            paths_checked += 1
            mode = stat.S_IMODE(info.st_mode)
            if mode & 0o022:
                exposed.append(f"{filename} mode={mode:04o}")

        if exposed:
            return [Finding(
                self.check_id, self.area, "SSH authorization files permit unsafe modification", Status.FAIL,
                Severity.HIGH, "Other local users can modify an SSH authorization path.",
                evidence=tuple(exposed),
                remediation="Remove group and other write permission from ~/.ssh and every authorized_keys file.",
                confidence=Confidence.HIGH,
            )]
        if errors:
            return [Finding(
                self.check_id, self.area, "SSH authorization-path permissions could not be fully verified",
                Status.UNKNOWN, Severity.INFO, f"Checked {paths_checked} authorization path(s); {len(errors)} path(s) were skipped.",
                evidence=tuple(errors), confidence=Confidence.LOW,
            )]
        return [Finding(
            self.check_id, self.area, "SSH authorization paths are not writable by other users", Status.PASS,
            Severity.INFO, f"Checked {paths_checked} SSH authorization path(s).", confidence=Confidence.HIGH,
        )]
