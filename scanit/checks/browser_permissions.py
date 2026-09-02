"""Audit whether browser profile directories expose user data locally."""

from __future__ import annotations

import stat
from pathlib import Path

from ..context import ScanContext
from ..models import Finding, Severity, Status


class BrowserProfilePermissionsCheck:
    check_id = "browser.profiles.permissions"
    area = "browser"

    def run(self, context: ScanContext) -> list[Finding]:
        profiles = self._discover_profiles(context.home)
        if not profiles:
            return [Finding(
                self.check_id, self.area, "No browser profiles detected", Status.NOT_APPLICABLE,
                Severity.INFO, "No supported browser profile directories were found.",
            )]

        exposed: list[str] = []
        errors: list[str] = []
        for profile in profiles:
            try:
                mode = stat.S_IMODE(profile.stat().st_mode)
            except OSError as error:
                errors.append(f"{profile}: {error}")
                continue
            if mode & 0o077:
                exposed.append(f"{profile} mode={mode:04o}")

        if exposed:
            return [Finding(
                self.check_id, self.area, "Browser profiles are accessible to other local users",
                Status.FAIL, Severity.HIGH,
                f"{len(exposed)} of {len(profiles)} detected profiles have group or other permissions.",
                evidence=tuple(exposed),
                remediation="Set each affected profile directory to owner-only mode (0700).",
            )]
        if errors:
            return [Finding(
                self.check_id, self.area, "Browser profile permissions could not be verified",
                Status.UNKNOWN, Severity.INFO,
                f"Could not inspect {len(errors)} of {len(profiles)} detected profiles.",
                evidence=tuple(errors),
            )]
        return [Finding(
            self.check_id, self.area, "Browser profile permissions are owner-only", Status.PASS,
            Severity.INFO, f"Checked {len(profiles)} browser profiles.",
        )]

    @staticmethod
    def _discover_profiles(home: Path) -> list[Path]:
        chromium_roots = (
            home / ".config/BraveSoftware/Brave-Browser",
            home / ".config/chromium",
            home / ".config/google-chrome",
            home / ".var/app/com.brave.Browser/config/BraveSoftware/Brave-Browser",
            home / ".var/app/org.chromium.Chromium/config/chromium",
            home / ".var/app/com.google.Chrome/config/google-chrome",
        )
        profiles: set[Path] = set()
        for root in chromium_roots:
            if not root.is_dir():
                continue
            for candidate in root.iterdir():
                if candidate.is_dir() and (candidate / "Preferences").is_file():
                    profiles.add(candidate)

        firefox_roots = (
            home / ".mozilla/firefox",
            home / ".var/app/org.mozilla.firefox/.mozilla/firefox",
        )
        for root in firefox_roots:
            if not root.is_dir():
                continue
            for candidate in root.iterdir():
                if candidate.is_dir() and (candidate / "prefs.js").is_file():
                    profiles.add(candidate)
        return sorted(profiles)
