"""Checks for high-impact local filesystem permissions."""

from __future__ import annotations

import stat
from os import stat_result

from ..context import ScanContext
from ..models import Confidence, Finding, Severity, Status


def unsafe_privileged_metadata(info: stat_result) -> bool:
    """Return whether a root-owned configuration can be changed by another user."""
    return info.st_uid != 0 or bool(stat.S_IMODE(info.st_mode) & 0o022)


class SudoersPermissionsCheck:
    check_id = "system.filesystem.sudoers-permissions"
    area = "system"

    def run(self, context: ScanContext) -> list[Finding]:
        path = context.root / "etc/sudoers"
        try:
            info = path.stat()
        except FileNotFoundError:
            return [Finding(self.check_id, self.area, "Sudoers file not found", Status.UNKNOWN,
                            Severity.INFO, str(path), confidence=Confidence.MEDIUM)]
        except OSError as error:
            return [Finding(self.check_id, self.area, "Sudoers file unreadable", Status.ERROR,
                            Severity.INFO, str(error), confidence=Confidence.LOW)]

        mode = stat.S_IMODE(info.st_mode)
        if unsafe_privileged_metadata(info):
            return [Finding(
                self.check_id, self.area, "Sudoers permissions are unsafe", Status.FAIL,
                Severity.CRITICAL, f"{path} owner uid={info.st_uid}, mode={mode:04o}",
                remediation="Set root ownership and mode 0440, then validate with visudo.",
            )]
        return [Finding(self.check_id, self.area, "Sudoers permissions are safe", Status.PASS,
                        Severity.INFO, f"{path} owner uid=0, mode={mode:04o}")]


class SudoersDropInPermissionsCheck:
    check_id = "system.filesystem.sudoers-drop-in-permissions"
    area = "system"

    def run(self, context: ScanContext) -> list[Finding]:
        directory = context.root / "etc/sudoers.d"
        try:
            directory_info = directory.stat()
        except FileNotFoundError:
            return [Finding(
                self.check_id, self.area, "No sudoers drop-in directory", Status.NOT_APPLICABLE,
                Severity.INFO, f"{directory} does not exist.",
            )]
        except PermissionError as error:
            return [Finding(
                self.check_id, self.area, "Sudoers drop-ins could not be inspected", Status.UNKNOWN,
                Severity.INFO, str(error), confidence=Confidence.LOW,
            )]
        except OSError as error:
            return [Finding(
                self.check_id, self.area, "Sudoers drop-ins could not be inspected", Status.ERROR,
                Severity.INFO, str(error), confidence=Confidence.LOW,
            )]
        try:
            entries = sorted(path for path in directory.iterdir() if path.is_file() and not path.name.endswith("~"))
        except PermissionError as error:
            return [Finding(
                self.check_id, self.area, "Sudoers drop-ins could not be inspected", Status.UNKNOWN,
                Severity.INFO, str(error), confidence=Confidence.LOW,
            )]
        except OSError as error:
            return [Finding(
                self.check_id, self.area, "Sudoers drop-ins could not be inspected", Status.ERROR,
                Severity.INFO, str(error), confidence=Confidence.LOW,
            )]

        unsafe: list[str] = []
        if unsafe_privileged_metadata(directory_info):
            mode = stat.S_IMODE(directory_info.st_mode)
            unsafe.append(f"{directory} owner uid={directory_info.st_uid}, mode={mode:04o}")
        for entry in entries:
            try:
                info = entry.stat()
            except OSError as error:
                unsafe.append(f"{entry}: could not read metadata: {error}")
                continue
            if unsafe_privileged_metadata(info):
                mode = stat.S_IMODE(info.st_mode)
                unsafe.append(f"{entry} owner uid={info.st_uid}, mode={mode:04o}")

        if unsafe:
            return [Finding(
                self.check_id, self.area, "Sudoers drop-in permissions are unsafe", Status.FAIL,
                Severity.CRITICAL, f"{len(unsafe)} unsafe sudoers drop-in path(s) found.",
                evidence=tuple(unsafe),
                remediation="Set root ownership and remove group/other write access, then validate with visudo.",
            )]
        return [Finding(
            self.check_id, self.area, "Sudoers drop-in permissions are safe", Status.PASS,
            Severity.INFO, f"Checked {len(entries)} active sudoers drop-in file(s).",
        )]
