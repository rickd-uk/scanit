import json
import unittest
from pathlib import Path

from scanit.context import ScanContext
from scanit.models import Confidence, Finding, Severity, Status
from scanit.reporters import render_json
from scanit.runner import run_checks


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
        self.assertEqual(payload["schema_version"], 1)
        self.assertEqual(payload["findings"][0]["check_id"], "test.failure")


if __name__ == "__main__":
    unittest.main()
