import contextlib
import io
import unittest

from scanit.cli import main, report_fails_at
from scanit.models import Finding, ScanReport, Severity, Status


class CliTests(unittest.TestCase):
    @staticmethod
    def report(severity):
        return ScanReport("test", [
            Finding("test.finding", "test", "Finding", Status.FAIL, severity, "evidence"),
        ])

    def test_failure_threshold(self):
        report = self.report(Severity.HIGH)
        self.assertTrue(report_fails_at(report, "high"))
        self.assertTrue(report_fails_at(report, "medium"))
        self.assertFalse(report_fails_at(report, "critical"))
        self.assertFalse(report_fails_at(report, "none"))

    def test_pass_never_fails_threshold(self):
        report = ScanReport("test", [
            Finding("test.pass", "test", "Pass", Status.PASS, Severity.CRITICAL, "safe"),
        ])
        self.assertFalse(report_fails_at(report, "low"))

    def test_unknown_area_is_rejected(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as raised:
                main(["--area", "missing"])
        self.assertEqual(raised.exception.code, 2)

    def test_known_check_can_be_listed(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = main(["--check", "system.identity.uid-zero-accounts", "--list-checks"])
        self.assertEqual(result, 0)
        self.assertIn("system.identity.uid-zero-accounts", output.getvalue())

    def test_browser_only_lists_no_system_checks(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = main(["--browser-only", "--list-checks"])
        self.assertEqual(result, 0)
        self.assertIn("browser.profiles.permissions", output.getvalue())
        self.assertNotIn("system.identity.uid-zero-accounts", output.getvalue())

    def test_system_only_lists_no_browser_checks(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = main(["--system-only", "--list-checks"])
        self.assertEqual(result, 0)
        self.assertIn("system.identity.uid-zero-accounts", output.getvalue())
        self.assertNotIn("browser.profiles.permissions", output.getvalue())


if __name__ == "__main__":
    unittest.main()
