import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from scanit.checks.browser_extensions import BrowserExtensionPermissionsCheck
from scanit.context import ScanContext
from scanit.models import Severity, Status


class BrowserExtensionPermissionsTests(unittest.TestCase):
    def run_check(self, home):
        context = ScanContext(home=home, root=Path("/"), commands=None)
        return BrowserExtensionPermissionsCheck().run(context)[0]

    @staticmethod
    def chromium_profile(home):
        profile = home / ".config/chromium/Default"
        profile.mkdir(parents=True)
        (profile / "Preferences").touch()
        return profile

    @staticmethod
    def firefox_profile(home):
        profile = home / ".mozilla/firefox/default"
        profile.mkdir(parents=True)
        (profile / "prefs.js").touch()
        return profile

    def test_no_profiles_is_not_applicable(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertIs(self.run_check(Path(directory)).status, Status.NOT_APPLICABLE)

    def test_chromium_broad_host_permission_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            profile = self.chromium_profile(Path(directory))
            manifest = profile / "Extensions/extension-id/1.0/manifest.json"
            manifest.parent.mkdir(parents=True)
            manifest.write_text(json.dumps({"name": "Reader", "host_permissions": ["*://*/*"]}))
            finding = self.run_check(Path(directory))
            self.assertIs(finding.status, Status.FAIL)
            self.assertIn("<all_urls>", finding.evidence[0])

    def test_firefox_xpi_debugger_permission_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            profile = self.firefox_profile(Path(directory))
            extensions = profile / "extensions"
            extensions.mkdir()
            with zipfile.ZipFile(extensions / "addon@example.xpi", "w") as archive:
                archive.writestr("manifest.json", json.dumps({"name": "Developer", "permissions": ["debugger"]}))
            finding = self.run_check(Path(directory))
            self.assertIs(finding.status, Status.FAIL)
            self.assertIs(finding.severity, Severity.HIGH)

    def test_safe_extension_passes(self):
        with tempfile.TemporaryDirectory() as directory:
            profile = self.chromium_profile(Path(directory))
            manifest = profile / "Extensions/extension-id/1.0/manifest.json"
            manifest.parent.mkdir(parents=True)
            manifest.write_text(json.dumps({"name": "Notes", "permissions": ["storage"]}))
            self.assertIs(self.run_check(Path(directory)).status, Status.PASS)

    def test_malformed_xpi_is_unknown(self):
        with tempfile.TemporaryDirectory() as directory:
            profile = self.firefox_profile(Path(directory))
            extensions = profile / "extensions"
            extensions.mkdir()
            (extensions / "broken.xpi").write_text("not a zip")
            self.assertIs(self.run_check(Path(directory)).status, Status.UNKNOWN)


if __name__ == "__main__":
    unittest.main()
