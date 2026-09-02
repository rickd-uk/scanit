import tempfile
import unittest
from pathlib import Path

from scanit.checks.browser_permissions import BrowserProfilePermissionsCheck
from scanit.context import ScanContext
from scanit.models import Status


class BrowserProfilePermissionsTests(unittest.TestCase):
    def run_check(self, home: Path):
        context = ScanContext(home=home, root=Path("/"), commands=None)
        return BrowserProfilePermissionsCheck().run(context)[0]

    def test_no_profiles_is_not_applicable(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertIs(self.run_check(Path(directory)).status, Status.NOT_APPLICABLE)

    def test_detects_exposed_firefox_profile(self):
        with tempfile.TemporaryDirectory() as directory:
            profile = Path(directory) / ".mozilla/firefox/default"
            profile.mkdir(parents=True)
            (profile / "prefs.js").touch()
            profile.chmod(0o755)
            finding = self.run_check(Path(directory))
            self.assertIs(finding.status, Status.FAIL)
            self.assertIn("mode=0755", finding.evidence[0])

    def test_accepts_owner_only_chromium_profile(self):
        with tempfile.TemporaryDirectory() as directory:
            profile = Path(directory) / ".config/chromium/Default"
            profile.mkdir(parents=True)
            (profile / "Preferences").touch()
            profile.chmod(0o700)
            finding = self.run_check(Path(directory))
            self.assertIs(finding.status, Status.PASS)


if __name__ == "__main__":
    unittest.main()
