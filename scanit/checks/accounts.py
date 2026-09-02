"""Audit high-impact local account properties."""

from __future__ import annotations

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
