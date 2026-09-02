"""Checks for high-impact local filesystem permissions."""

from __future__ import annotations

import stat

from ..context import ScanContext
from ..models import Confidence, Finding, Severity, Status


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
        unsafe = mode & 0o022 or info.st_uid != 0
        if unsafe:
            return [Finding(
                self.check_id, self.area, "Sudoers permissions are unsafe", Status.FAIL,
                Severity.CRITICAL, f"{path} owner uid={info.st_uid}, mode={mode:04o}",
                remediation="Set root ownership and mode 0440, then validate with visudo.",
            )]
        return [Finding(self.check_id, self.area, "Sudoers permissions are safe", Status.PASS,
                        Severity.INFO, f"{path} owner uid=0, mode={mode:04o}")]
