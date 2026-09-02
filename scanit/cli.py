"""Command-line interface."""

from __future__ import annotations

import argparse
from collections.abc import Sequence

from . import __version__
from .context import ScanContext
from .models import ScanReport, Severity, Status
from .registry import builtin_checks
from .reporters import render_json, render_sarif, render_text
from .runner import run_checks


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description="Audit an Arch Linux workstation's security posture.")
    output = result.add_mutually_exclusive_group()
    output.add_argument("--json", action="store_true", help="emit versioned JSON")
    output.add_argument("--sarif", action="store_true", help="emit SARIF 2.1.0 for CI systems")
    result.add_argument("--area", action="append", help="run checks in this area (repeatable)")
    result.add_argument("--check", action="append", help="run this stable check ID (repeatable)")
    result.add_argument("--list-checks", action="store_true", help="list stable check IDs and exit")
    result.add_argument(
        "--fail-on", choices=("critical", "high", "medium", "low", "none"), default="low",
        help="minimum failed severity that returns exit status 1 (default: low)",
    )
    result.add_argument("--version", action="version", version=f"ScanIt {__version__}")
    return result


def report_fails_at(report: ScanReport, threshold: str) -> bool:
    if threshold == "none":
        return False
    ranks = {Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3, Severity.CRITICAL: 4}
    minimum = ranks[Severity(threshold)]
    return any(
        finding.status is Status.FAIL and ranks.get(finding.severity, 0) >= minimum
        for finding in report.findings
    )


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    checks = builtin_checks()
    available_areas = {check.area for check in checks}
    available_ids = {check.check_id for check in checks}
    if args.area:
        wanted = set(args.area)
        unknown = sorted(wanted - available_areas)
        if unknown:
            parser().error("unknown area(s): " + ", ".join(unknown))
        checks = [check for check in checks if check.area in wanted]
    if args.check:
        wanted = set(args.check)
        unknown = sorted(wanted - available_ids)
        if unknown:
            parser().error("unknown check ID(s): " + ", ".join(unknown))
        checks = [check for check in checks if check.check_id in wanted]
    if (args.area or args.check) and not checks:
        parser().error("the selected area and check filters do not overlap")
    if args.list_checks:
        for check in checks:
            print(f"{check.check_id}\t{check.area}")
        return 0
    report = run_checks(checks, ScanContext.local(), __version__)
    if args.json:
        rendered = render_json(report)
    elif args.sarif:
        rendered = render_sarif(report)
    else:
        rendered = render_text(report)
    print(rendered)
    return 1 if report_fails_at(report, args.fail_on) else 0
