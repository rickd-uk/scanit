"""Audit high-impact local account properties."""

from __future__ import annotations

import os
import stat

from ..context import ScanContext
from ..models import Confidence, Finding, Severity, Status


class UidZeroAccountsCheck:
    check_id = "system.identity.uid-zero-accounts"
    area = "identity"

    def run(self, context: ScanContext) -> list[Finding]:
        path = context.root / "etc/passwd"
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except FileNotFoundError:
            return [Finding(
                self.check_id, self.area, "UID 0 accounts could not be inspected", Status.UNKNOWN,
                Severity.INFO, f"{path} was not found.", confidence=Confidence.LOW,
            )]
        except OSError as error:
            return [Finding(
                self.check_id, self.area, "UID 0 accounts could not be inspected", Status.UNKNOWN,
                Severity.INFO, str(error), confidence=Confidence.LOW,
            )]

        uid_zero: list[str] = []
        malformed = 0
        for line in lines:
            if not line or line.startswith("#"):
                continue
            fields = line.split(":")
            if len(fields) != 7:
                malformed += 1
                continue
            try:
                uid = int(fields[2])
            except ValueError:
                malformed += 1
                continue
            if uid == 0:
                uid_zero.append(fields[0])

        unexpected = sorted(account for account in uid_zero if account != "root")
        if unexpected:
            return [Finding(
                self.check_id, self.area, "Unexpected UID 0 accounts exist", Status.FAIL,
                Severity.CRITICAL, f"Found {len(unexpected)} non-root account(s) with UID 0.",
                evidence=tuple(f"account={account} uid=0" for account in unexpected),
                remediation="Investigate and remove UID 0 from every account except the intended root account.",
                confidence=Confidence.HIGH,
            )]
        if "root" not in uid_zero:
            return [Finding(
                self.check_id, self.area, "The root UID 0 account was not found", Status.UNKNOWN,
                Severity.INFO, "No root account with UID 0 was present in the parsed passwd database.",
                confidence=Confidence.LOW,
            )]
        if malformed:
            return [Finding(
                self.check_id, self.area, "UID 0 account audit was incomplete", Status.UNKNOWN,
                Severity.INFO, f"The root account was valid, but {malformed} passwd line(s) were malformed.",
                confidence=Confidence.LOW,
            )]
        return [Finding(
            self.check_id, self.area, "Only root has UID 0", Status.PASS,
            Severity.INFO, "No additional UID 0 accounts were found.", confidence=Confidence.HIGH,
        )]


class HomeDirectoryPermissionsCheck:
    check_id = "system.identity.home-permissions"
    area = "identity"

    def run(self, context: ScanContext) -> list[Finding]:
        path = context.home
        try:
            info = path.stat()
        except FileNotFoundError:
            return [Finding(
                self.check_id, self.area, "Home-directory permissions could not be inspected",
                Status.UNKNOWN, Severity.INFO, f"{path} does not exist.", confidence=Confidence.LOW,
            )]
        except OSError as error:
            return [Finding(
                self.check_id, self.area, "Home-directory permissions could not be inspected",
                Status.UNKNOWN, Severity.INFO, str(error), confidence=Confidence.LOW,
            )]

        mode = stat.S_IMODE(info.st_mode)
        evidence: list[str] = []
        if info.st_uid != os.getuid():
            evidence.append(f"owner uid={info.st_uid}; current uid={os.getuid()}")
        if mode & 0o020:
            evidence.append(f"group-writable mode={mode:04o}")
        if mode & 0o002:
            evidence.append(f"world-writable mode={mode:04o}")
        if evidence:
            return [Finding(
                self.check_id, self.area, "Home directory permits unsafe modification", Status.FAIL,
                Severity.HIGH, "The current user's home can be modified outside its expected ownership boundary.",
                evidence=tuple(evidence),
                remediation="Restore the current user's ownership and remove group/other write permission from the home directory.",
                confidence=Confidence.HIGH,
            )]
        return [Finding(
            self.check_id, self.area, "Home directory ownership and write permissions are safe",
            Status.PASS, Severity.INFO, f"{path} owner uid={info.st_uid}, mode={mode:04o}.",
        )]


class EmptyPasswordsCheck:
    check_id = "system.identity.empty-passwords"
    area = "identity"

    def run(self, context: ScanContext) -> list[Finding]:
        path = context.root / "etc/shadow"
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except (FileNotFoundError, PermissionError) as error:
            return [Finding(
                self.check_id, self.area, "Empty-password accounts could not be inspected",
                Status.UNKNOWN, Severity.INFO, str(error), confidence=Confidence.LOW,
            )]
        except OSError as error:
            return [Finding(
                self.check_id, self.area, "Empty-password accounts could not be inspected",
                Status.ERROR, Severity.INFO, str(error), confidence=Confidence.LOW,
            )]

        empty: list[str] = []
        malformed = 0
        for line in lines:
            if not line:
                continue
            fields = line.split(":")
            if len(fields) < 2 or not fields[0]:
                malformed += 1
                continue
            if fields[1] == "":
                empty.append(fields[0])
        if empty:
            return [Finding(
                self.check_id, self.area, "Accounts with empty password fields exist", Status.FAIL,
                Severity.CRITICAL, f"Found {len(empty)} account(s) with an empty shadow password field.",
                evidence=tuple(f"account={account}" for account in sorted(empty)),
                remediation="Lock each unintended account or assign a strong password through the normal account-management workflow.",
                confidence=Confidence.HIGH,
            )]
        if malformed:
            return [Finding(
                self.check_id, self.area, "Empty-password audit was incomplete", Status.UNKNOWN,
                Severity.INFO, f"Found {malformed} malformed shadow line(s).", confidence=Confidence.LOW,
            )]
        return [Finding(
            self.check_id, self.area, "No empty shadow password fields detected", Status.PASS,
            Severity.INFO, "All parsed accounts have a password hash or lock marker.", confidence=Confidence.HIGH,
        )]
