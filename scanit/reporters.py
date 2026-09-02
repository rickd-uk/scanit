"""Terminal and structured report rendering."""

from __future__ import annotations

import json

from .models import ScanReport, Status


def render_json(report: ScanReport) -> str:
    return json.dumps(report.as_dict(), indent=2, sort_keys=True)


def render_text(report: ScanReport) -> str:
    lines = [f"ScanIt {report.tool_version}", f"Risk score: {report.risk_score}/100"]
    coverage = "  ".join(f"{name}: {count}" for name, count in report.coverage.items() if count)
    lines.append(f"Coverage: {coverage or 'no checks selected'}")
    for item in report.findings:
        marker = "!" if item.status is Status.FAIL else "-"
        lines.extend(("", f"{marker} [{item.check_id}] {item.status.value.upper()} — {item.title}", f"  {item.summary}"))
        for evidence in item.evidence:
            lines.append(f"  Evidence: {evidence}")
        if item.remediation:
            lines.append(f"  Remediation: {item.remediation}")
    return "\n".join(lines)

