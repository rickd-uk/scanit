"""Audit installed browser extensions for high-impact permissions."""

from __future__ import annotations

import json
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..browser_profiles import BrowserProfile, discover_browser_profiles
from ..context import ScanContext
from ..models import Confidence, Finding, Severity, Status


MAX_MANIFEST_BYTES = 1_048_576


@dataclass(frozen=True, slots=True)
class ExtensionManifest:
    browser: str
    profile: Path
    extension_id: str
    data: dict[str, Any]


class BrowserExtensionPermissionsCheck:
    check_id = "browser.extensions.powerful-permissions"
    area = "browser"
    permission_severity = {
        "<all_urls>": Severity.MEDIUM,
        "debugger": Severity.HIGH,
        "management": Severity.HIGH,
        "nativeMessaging": Severity.HIGH,
        "proxy": Severity.HIGH,
        "webRequestBlocking": Severity.MEDIUM,
    }

    def run(self, context: ScanContext) -> list[Finding]:
        profiles = discover_browser_profiles(context.home)
        if not profiles:
            return [Finding(
                self.check_id, self.area, "No browser profiles detected", Status.NOT_APPLICABLE,
                Severity.INFO, "No supported browser profiles were found.",
            )]

        manifests: list[ExtensionManifest] = []
        errors: list[str] = []
        for profile in profiles:
            discovered, failed = self._read_profile_extensions(profile)
            manifests.extend(discovered)
            errors.extend(failed)

        risky: list[str] = []
        severities: list[Severity] = []
        for extension in manifests:
            permissions = self._powerful_permissions(extension.data)
            if not permissions:
                continue
            name = extension.data.get("name")
            if not isinstance(name, str) or not name.strip():
                name = extension.extension_id
            risky.append(
                f"{extension.browser} profile={extension.profile.name} extension={name!r} "
                f"id={extension.extension_id} permissions={','.join(sorted(permissions))}"
            )
            severities.extend(self.permission_severity[permission] for permission in permissions)

        if risky:
            severity_order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
            severity = max(severities, key=severity_order.index)
            suffix = f" {len(errors)} manifest(s) could not be inspected." if errors else ""
            return [Finding(
                self.check_id, self.area, "Browser extensions request powerful permissions",
                Status.FAIL, severity, f"Found {len(risky)} extension(s) requiring review.{suffix}",
                evidence=tuple(risky + errors),
                remediation="Review whether each extension needs these permissions and remove extensions you do not trust.",
                confidence=Confidence.MEDIUM if errors else Confidence.HIGH,
            )]
        if errors:
            return [Finding(
                self.check_id, self.area, "Extension permissions could not be fully inspected",
                Status.UNKNOWN, Severity.INFO,
                f"Could not read {len(errors)} extension manifest(s).",
                evidence=tuple(errors), confidence=Confidence.LOW,
            )]
        return [Finding(
            self.check_id, self.area, "No powerful extension permissions detected", Status.PASS,
            Severity.INFO, f"Inspected {len(manifests)} installed extension manifest(s).",
        )]

    @classmethod
    def _powerful_permissions(cls, data: dict[str, Any]) -> set[str]:
        values: list[str] = []
        for field in ("permissions", "host_permissions"):
            raw = data.get(field, [])
            if isinstance(raw, list):
                values.extend(value for value in raw if isinstance(value, str))
        scripts = data.get("content_scripts", [])
        if isinstance(scripts, list):
            for script in scripts:
                if isinstance(script, dict) and isinstance(script.get("matches"), list):
                    values.extend(value for value in script["matches"] if isinstance(value, str))

        found = {value for value in values if value in cls.permission_severity}
        broad_hosts = {"<all_urls>", "*://*/*", "http://*/*", "https://*/*"}
        if any(value.casefold() in broad_hosts for value in values):
            found.add("<all_urls>")
        return found

    @classmethod
    def _read_profile_extensions(cls, profile: BrowserProfile) -> tuple[list[ExtensionManifest], list[str]]:
        if profile.family == "chromium":
            return cls._read_chromium_extensions(profile)
        return cls._read_firefox_extensions(profile)

    @classmethod
    def _read_chromium_extensions(cls, profile: BrowserProfile) -> tuple[list[ExtensionManifest], list[str]]:
        root = profile.path / "Extensions"
        if not root.is_dir():
            return [], []
        manifests: list[ExtensionManifest] = []
        errors: list[str] = []
        for extension_dir in sorted(path for path in root.iterdir() if path.is_dir()):
            candidates = list(extension_dir.glob("*/manifest.json"))
            if not candidates:
                continue
            try:
                manifest_path = max(candidates, key=lambda path: (path.stat().st_mtime_ns, path.parent.name))
                data = cls._read_json_file(manifest_path)
                manifests.append(ExtensionManifest(profile.browser, profile.path, extension_dir.name, data))
            except (OSError, ValueError, json.JSONDecodeError) as error:
                errors.append(f"{profile.browser} extension={extension_dir.name}: {type(error).__name__}")
        return manifests, errors

    @classmethod
    def _read_firefox_extensions(cls, profile: BrowserProfile) -> tuple[list[ExtensionManifest], list[str]]:
        root = profile.path / "extensions"
        if not root.is_dir():
            return [], []
        manifests: list[ExtensionManifest] = []
        errors: list[str] = []
        for entry in sorted(root.iterdir()):
            try:
                if entry.is_dir() and (entry / "manifest.json").is_file():
                    data = cls._read_json_file(entry / "manifest.json")
                    manifests.append(ExtensionManifest(profile.browser, profile.path, entry.name, data))
                elif entry.is_file() and entry.suffix.casefold() == ".xpi":
                    data = cls._read_xpi_manifest(entry)
                    manifests.append(ExtensionManifest(profile.browser, profile.path, entry.stem, data))
            except (OSError, ValueError, KeyError, zipfile.BadZipFile, json.JSONDecodeError) as error:
                errors.append(f"firefox extension={entry.name}: {type(error).__name__}")
        return manifests, errors

    @staticmethod
    def _read_json_file(path: Path) -> dict[str, Any]:
        if path.stat().st_size > MAX_MANIFEST_BYTES:
            raise ValueError("manifest is too large")
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise ValueError("manifest is not an object")
        return value

    @staticmethod
    def _read_xpi_manifest(path: Path) -> dict[str, Any]:
        with zipfile.ZipFile(path) as archive:
            member = archive.getinfo("manifest.json")
            if member.file_size > MAX_MANIFEST_BYTES:
                raise ValueError("manifest is too large")
            value = json.loads(archive.read(member).decode("utf-8"))
        if not isinstance(value, dict):
            raise ValueError("manifest is not an object")
        return value
