"""Detect explicit Firefox preferences that weaken transport security."""

from __future__ import annotations

import re

from ..browser_profiles import discover_browser_profiles
from ..context import ScanContext
from ..models import Confidence, Finding, Severity, Status


PREFERENCE = re.compile(r'^\s*user_pref\("([^"\\]+)",\s*(.+?)\);\s*$')


def read_firefox_preferences(path) -> dict[str, str]:
    preferences: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = PREFERENCE.match(line)
        if match:
            preferences[match.group(1)] = match.group(2).strip().casefold()
    return preferences


class FirefoxDangerousPreferencesCheck:
    check_id = "browser.firefox.dangerous-preferences"
    area = "browser"

    def run(self, context: ScanContext) -> list[Finding]:
        profiles = [profile for profile in discover_browser_profiles(context.home) if profile.family == "firefox"]
        if not profiles:
            return [Finding(
                self.check_id, self.area, "No Firefox profiles detected", Status.NOT_APPLICABLE,
                Severity.INFO, "No supported Firefox profiles were found.",
            )]

        evidence: list[str] = []
        errors: list[str] = []
        severities: list[Severity] = []
        for profile in profiles:
            try:
                preferences = read_firefox_preferences(profile.path / "prefs.js")
            except OSError as error:
                errors.append(f"profile={profile.path.name}: {type(error).__name__}")
                continue
            tls_minimum = preferences.get("security.tls.version.min")
            if tls_minimum in {"0", "1", "2"}:
                evidence.append(f"profile={profile.path.name} security.tls.version.min={tls_minimum}")
                severities.append(Severity.HIGH)
            if preferences.get("security.enterprise_roots.enabled") == "true":
                evidence.append(f"profile={profile.path.name} security.enterprise_roots.enabled=true")
                severities.append(Severity.MEDIUM)

        if evidence:
            severity_order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
            severity = max(severities, key=severity_order.index)
            status = Status.FAIL if severity is Severity.HIGH else Status.REVIEW
            suffix = f" {len(errors)} profile(s) could not be read." if errors else ""
            return [Finding(
                self.check_id, self.area, "Firefox has explicit security-weakening preferences",
                status, severity, f"Found {len(evidence)} preference override(s).{suffix}",
                evidence=tuple(evidence + errors),
                remediation="Reset legacy TLS overrides and trust enterprise roots only when intentionally managed.",
                confidence=Confidence.MEDIUM,
            )]
        if errors:
            return [Finding(
                self.check_id, self.area, "Firefox preferences could not be fully inspected",
                Status.UNKNOWN, Severity.INFO, f"Could not read {len(errors)} Firefox profile(s).",
                evidence=tuple(errors), confidence=Confidence.LOW,
            )]
        return [Finding(
            self.check_id, self.area, "No explicit dangerous Firefox preferences detected",
            Status.PASS, Severity.INFO, f"Inspected {len(profiles)} Firefox profile(s).",
            confidence=Confidence.MEDIUM,
        )]



class FirefoxHttpsOnlyCheck:
    check_id = "browser.firefox.https-only"
    area = "browser"

    def run(self, context: ScanContext) -> list[Finding]:
        profiles = [profile for profile in discover_browser_profiles(context.home) if profile.family == "firefox"]
        if not profiles:
            return [Finding(
                self.check_id, self.area, "No Firefox profiles detected", Status.NOT_APPLICABLE,
                Severity.INFO, "No supported Firefox profiles were found.",
            )]

        enabled: list[str] = []
        disabled: list[str] = []
        unknown: list[str] = []
        for profile in profiles:
            try:
                preferences = read_firefox_preferences(profile.path / "prefs.js")
            except OSError as error:
                unknown.append(f"profile={profile.path.name}: {type(error).__name__}")
                continue
            value = preferences.get("dom.security.https_only_mode")
            if value == "true":
                enabled.append(profile.path.name)
            elif value == "false":
                disabled.append(profile.path.name)
            else:
                unknown.append(f"profile={profile.path.name}: preference is not explicitly set")

        if disabled:
            return [Finding(
                self.check_id, self.area, "Firefox HTTPS-Only Mode is explicitly disabled",
                Status.FAIL, Severity.LOW, f"HTTPS-Only Mode is disabled in {len(disabled)} profile(s).",
                evidence=tuple(f"profile={name} dom.security.https_only_mode=false" for name in disabled) + tuple(unknown),
                remediation="Enable HTTPS-Only Mode in Firefox privacy and security settings.",
                confidence=Confidence.MEDIUM if unknown else Confidence.HIGH,
            )]
        if len(enabled) == len(profiles):
            return [Finding(
                self.check_id, self.area, "Firefox HTTPS-Only Mode is enabled", Status.PASS,
                Severity.INFO, f"HTTPS-Only Mode is explicitly enabled in {len(enabled)} profile(s).",
                confidence=Confidence.HIGH,
            )]
        return [Finding(
            self.check_id, self.area, "Firefox HTTPS-Only Mode could not be fully determined",
            Status.UNKNOWN, Severity.INFO,
            f"The preference was explicit in {len(enabled)} of {len(profiles)} profile(s).",
            evidence=tuple(unknown), confidence=Confidence.LOW,
        )]
