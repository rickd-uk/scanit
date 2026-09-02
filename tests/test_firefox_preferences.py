import tempfile
import unittest
from pathlib import Path

from scanit.checks.firefox_preferences import FirefoxDangerousPreferencesCheck
from scanit.context import ScanContext
from scanit.models import Severity, Status


class FirefoxDangerousPreferencesTests(unittest.TestCase):
    def run_check(self, home):
        context = ScanContext(home=home, root=Path("/"), commands=None)
        return FirefoxDangerousPreferencesCheck().run(context)[0]

    @staticmethod
    def profile(home, content):
        profile = home / ".mozilla/firefox/default"
        profile.mkdir(parents=True)
        (profile / "prefs.js").write_text(content)
        return profile

    def test_no_firefox_is_not_applicable(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertIs(self.run_check(Path(directory)).status, Status.NOT_APPLICABLE)

    def test_legacy_tls_override_fails_high(self):
        with tempfile.TemporaryDirectory() as directory:
            self.profile(Path(directory), 'user_pref("security.tls.version.min", 1);\n')
            finding = self.run_check(Path(directory))
            self.assertIs(finding.status, Status.FAIL)
            self.assertIs(finding.severity, Severity.HIGH)

    def test_enterprise_roots_override_requires_review(self):
        with tempfile.TemporaryDirectory() as directory:
            self.profile(Path(directory), 'user_pref("security.enterprise_roots.enabled", true);\n')
            finding = self.run_check(Path(directory))
            self.assertIs(finding.status, Status.REVIEW)
            self.assertIs(finding.severity, Severity.MEDIUM)

    def test_unrelated_preferences_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            self.profile(Path(directory), 'user_pref("browser.startup.page", 3);\n')
            self.assertIs(self.run_check(Path(directory)).status, Status.PASS)


if __name__ == "__main__":
    unittest.main()
