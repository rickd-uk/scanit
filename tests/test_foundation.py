import json
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from pathlib import Path

from scanit.context import ScanContext
from scanit.models import Confidence, Finding, ScanReport, Severity, Status
from scanit.reporters import render_json, render_sarif
from scanit.runner import run_checks
from scanit.checks.filesystem import (
    SudoersDropInPermissionsCheck,
    SudoersPermissionsCheck,
    SystemdUnitPermissionsCheck,
    unsafe_privileged_metadata,
)


class ExplodingCheck:
    check_id = "test.explodes"
    area = "test"

    def run(self, context):
        raise ValueError("bad evidence")


class FailingCheck:
    check_id = "test.failure"
    area = "test"

    def run(self, context):
        return [Finding(self.check_id, self.area, "Failure", Status.FAIL, Severity.HIGH, "unsafe")]


class FoundationTests(unittest.TestCase):
    def setUp(self):
        self.context = ScanContext(home=Path("/home/test"), root=Path("/"), commands=None)

    def test_broken_check_is_isolated(self):
        report = run_checks([ExplodingCheck(), FailingCheck()], self.context, "test")
        self.assertEqual([item.status for item in report.findings], [Status.ERROR, Status.FAIL])

    def test_only_failures_contribute_to_risk(self):
        report = run_checks([FailingCheck()], self.context, "test")
        report.findings.append(
            Finding("test.unknown", "test", "Unknown", Status.UNKNOWN, Severity.CRITICAL, "unknown", confidence=Confidence.LOW)
        )
        self.assertEqual(report.risk_score, 20)

    def test_json_schema_is_stable_and_serializable(self):
        report = run_checks([FailingCheck()], self.context, "test")
        payload = json.loads(render_json(report))
        self.assertEqual(payload["schema_version"], 2)
        self.assertEqual(payload["findings"][0]["check_id"], "test.failure")

    def test_sarif_contains_failed_findings(self):
        report = run_checks([FailingCheck()], self.context, "test")
        payload = json.loads(render_sarif(report))
        self.assertEqual(payload["version"], "2.1.0")
        self.assertEqual(payload["runs"][0]["results"][0]["ruleId"], "test.failure")
        self.assertEqual(payload["runs"][0]["results"][0]["level"], "error")

    def test_review_findings_do_not_increase_risk(self):
        report = ScanReport("test", [
            Finding("test.review", "test", "Review", Status.REVIEW, Severity.HIGH, "review this"),
        ])
        self.assertEqual(report.risk_score, 0)
        self.assertEqual(report.coverage["review"], 1)

    def test_registry_contains_filesystem_check(self):
        self.assertEqual(SudoersPermissionsCheck().check_id, "system.filesystem.sudoers-permissions")

    def test_privileged_metadata_requires_root_and_no_non_owner_write(self):
        self.assertFalse(unsafe_privileged_metadata(SimpleNamespace(st_uid=0, st_mode=0o100440)))
        self.assertTrue(unsafe_privileged_metadata(SimpleNamespace(st_uid=1000, st_mode=0o100440)))
        self.assertTrue(unsafe_privileged_metadata(SimpleNamespace(st_uid=0, st_mode=0o100664)))

    def test_missing_sudoers_drop_in_directory_is_not_applicable(self):
        context = ScanContext(home=Path("/home/test"), root=Path("/missing-root"), commands=None)
        finding = SudoersDropInPermissionsCheck().run(context)[0]
        self.assertIs(finding.status, Status.NOT_APPLICABLE)

    def test_unreadable_sudoers_drop_in_directory_is_unknown(self):
        with patch.object(Path, "stat", side_effect=PermissionError("denied")):
            finding = SudoersDropInPermissionsCheck().run(self.context)[0]
        self.assertIs(finding.status, Status.UNKNOWN)

    def test_ignored_sudoers_drop_in_names_are_not_counted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            drop_ins = root / "etc/sudoers.d"
            drop_ins.mkdir(parents=True)
            (drop_ins / "README.example").write_text("ignored")
            (drop_ins / "backup~").write_text("ignored")
            with patch("scanit.checks.filesystem.unsafe_privileged_metadata", return_value=False):
                finding = SudoersDropInPermissionsCheck().run(
                    ScanContext(home=Path("/home/test"), root=root, commands=None)
                )[0]
        self.assertIs(finding.status, Status.PASS)
        self.assertIn("Checked 0", finding.summary)

    def test_missing_systemd_unit_roots_are_unknown(self):
        with tempfile.TemporaryDirectory() as directory:
            context = ScanContext(home=Path("/home/test"), root=Path(directory), commands=None)
            finding = SystemdUnitPermissionsCheck().run(context)[0]
        self.assertIs(finding.status, Status.UNKNOWN)

    def test_non_root_systemd_unit_path_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            units = root / "etc/systemd/system"
            units.mkdir(parents=True)
            (units / "example.service").write_text("[Service]\nExecStart=/bin/true\n")
            context = ScanContext(home=Path("/home/test"), root=root, commands=None)
            finding = SystemdUnitPermissionsCheck().run(context)[0]
        self.assertIs(finding.status, Status.FAIL)

    def test_safe_systemd_unit_metadata_passes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            units = root / "etc/systemd/system"
            units.mkdir(parents=True)
            (units / "example.service").write_text("[Service]\nExecStart=/bin/true\n")
            context = ScanContext(home=Path("/home/test"), root=root, commands=None)
            with patch("scanit.checks.filesystem.unsafe_privileged_metadata", return_value=False):
                finding = SystemdUnitPermissionsCheck().run(context)[0]
        self.assertIs(finding.status, Status.PASS)


if __name__ == "__main__":
    unittest.main()
