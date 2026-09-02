"""Terminal and structured report rendering."""

from __future__ import annotations

import json

from .comparison import ScanDelta
from .models import ScanReport, Status


def render_json(report: ScanReport, delta: ScanDelta | None = None) -> str:
    payload = report.as_dict()
    if delta is not None:
        payload["baseline_delta"] = delta.as_dict()
    return json.dumps(payload, indent=2, sort_keys=True)


def render_sarif(report: ScanReport) -> str:
    relevant = [
        finding for finding in report.findings
        if finding.status not in (Status.PASS, Status.NOT_APPLICABLE)
    ]
    rules = []
    seen: set[str] = set()
    for finding in relevant:
        if finding.check_id in seen:
            continue
        seen.add(finding.check_id)
        rules.append({
            "id": finding.check_id,
            "shortDescription": {"text": finding.title},
            "properties": {
                "area": finding.area,
                "severity": finding.severity.value,
            },
        })

    level = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "warning",
        "info": "note",
    }
    results = []
    for finding in relevant:
        details = [finding.summary, *finding.evidence]
        if finding.remediation:
            details.append("Remediation: " + finding.remediation)
        sarif_level = "warning" if finding.status is Status.REVIEW else level[finding.severity.value]
        results.append({
            "ruleId": finding.check_id,
            "level": sarif_level,
            "message": {"text": "\n".join(details)},
            "properties": {
                "status": finding.status.value,
                "confidence": finding.confidence.value,
                "area": finding.area,
            },
        })

    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "ScanIt",
                "version": report.tool_version,
                "rules": rules,
            }},
            "results": results,
        }],
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def render_text(report: ScanReport, delta: ScanDelta | None = None) -> str:
    lines = [f"ScanIt {report.tool_version}", f"Risk score: {report.risk_score}/100"]
    coverage = "  ".join(f"{name}: {count}" for name, count in report.coverage.items() if count)
    lines.append(f"Coverage: {coverage or 'no checks selected'}")
    for item in report.findings:
        marker = {Status.FAIL: "!", Status.REVIEW: "?"}.get(item.status, "-")
        lines.extend(("", f"{marker} [{item.check_id}] {item.status.value.upper()} — {item.title}", f"  {item.summary}"))
        for evidence in item.evidence:
            lines.append(f"  Evidence: {evidence}")
        if item.remediation:
            lines.append(f"  Remediation: {item.remediation}")
    if delta is not None:
        lines.extend(("", "Baseline delta:"))
        categories = (
            ("New failures", delta.new_failures),
            ("Resolved failures", delta.resolved_failures),
            ("New review items", delta.new_reviews),
            ("Coverage regressions", delta.coverage_regressions),
        )
        for label, check_ids in categories:
            lines.append(f"  {label}: {', '.join(check_ids) if check_ids else 'none'}")
    return "\n".join(lines)
