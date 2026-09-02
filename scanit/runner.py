"""Fault-isolated audit runner."""

from __future__ import annotations

from collections.abc import Iterable

from .checks.base import Check
from .context import ScanContext
from .models import Finding, ScanReport, Severity, Status


def run_checks(checks: Iterable[Check], context: ScanContext, version: str) -> ScanReport:
    report = ScanReport(tool_version=version)
    for check in checks:
        try:
            report.findings.extend(check.run(context))
        except Exception as error:  # A broken check must not abort the remaining audit.
            report.findings.append(
                Finding(
                    check_id=check.check_id,
                    area=check.area,
                    title="Check could not complete",
                    status=Status.ERROR,
                    severity=Severity.INFO,
                    summary=f"{type(error).__name__}: {error}",
                )
            )
    return report

