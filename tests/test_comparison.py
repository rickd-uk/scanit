import json
import unittest

from scanit.comparison import compare_with_baseline
from scanit.models import Finding, ScanReport, Severity, Status
from scanit.reporters import render_json, render_text


class ComparisonTests(unittest.TestCase):
    def test_detects_security_and_coverage_changes(self):
        baseline = {"findings": [
            {"check_id": "resolved", "status": "fail"},
            {"check_id": "regressed", "status": "pass"},
            {"check_id": "review", "status": "pass"},
        ]}
        current = ScanReport("test", [
            Finding("new", "test", "New", Status.FAIL, Severity.HIGH, "bad"),
            Finding("resolved", "test", "Resolved", Status.PASS, Severity.INFO, "good"),
            Finding("regressed", "test", "Regressed", Status.UNKNOWN, Severity.INFO, "unknown"),
            Finding("review", "test", "Review", Status.REVIEW, Severity.MEDIUM, "review"),
        ])
        delta = compare_with_baseline(current, baseline)
        self.assertEqual(delta.new_failures, ("new",))
        self.assertEqual(delta.resolved_failures, ("resolved",))
        self.assertEqual(delta.new_reviews, ("review",))
        self.assertEqual(delta.coverage_regressions, ("regressed",))

    def test_missing_current_check_is_not_called_resolved(self):
        delta = compare_with_baseline(ScanReport("test"), {
            "findings": [{"check_id": "not-run", "status": "fail"}],
        })
        self.assertEqual(delta.resolved_failures, ())

    def test_renderers_include_structured_delta(self):
        report = ScanReport("test")
        delta = compare_with_baseline(report, {"findings": []})
        self.assertIn("baseline_delta", json.loads(render_json(report, delta)))
        self.assertIn("Baseline delta:", render_text(report, delta))

    def test_invalid_baseline_is_rejected(self):
        with self.assertRaises(ValueError):
            compare_with_baseline(ScanReport("test"), {})


if __name__ == "__main__":
    unittest.main()
