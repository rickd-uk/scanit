"""Command-line interface."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Sequence
from pathlib import Path

from . import __version__
from .context import ScanContext
from .comparison import compare_with_baseline
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
    result.add_argument(
        "--status", action="append", choices=tuple(status.value for status in Status),
        help="show only this result status (repeatable; does not change the failure exit policy)",
    )
    scope = result.add_mutually_exclusive_group()
    scope.add_argument("--browser-only", action="store_true", help="run only browser checks")
    scope.add_argument("--system-only", action="store_true", help="run all non-browser checks")
    result.add_argument("--list-checks", action="store_true", help="list stable check IDs and exit")
    result.add_argument("--baseline", type=Path, help="compare with a prior ScanIt JSON report")
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
    if args.baseline and args.sarif:
        parser().error("--baseline cannot be combined with --sarif")
    checks = builtin_checks()
    available_areas = {check.area for check in checks}
    available_ids = {check.check_id for check in checks}
    if args.browser_only:
        checks = [check for check in checks if check.area == "browser"]
    elif args.system_only:
        checks = [check for check in checks if check.area != "browser"]
    elif os.geteuid() == 0 and not args.list_checks:
        print(
            "Warning: running as root scans root's browser profile; use --system-only for privileged system evidence.",
            file=sys.stderr,
        )
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
    if (args.area or args.check or args.browser_only or args.system_only) and not checks:
        parser().error("the selected area and check filters do not overlap")
    if args.list_checks:
        for check in checks:
            print(f"{check.check_id}\t{check.area}")
        return 0
    report = run_checks(checks, ScanContext.local(), __version__)
    delta = None
    if args.baseline:
        try:
            baseline = json.loads(args.baseline.read_text(encoding="utf-8"))
            if not isinstance(baseline, dict):
                raise ValueError("top-level value is not an object")
            delta = compare_with_baseline(report, baseline)
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
            parser().error(f"could not read baseline: {error}")
    displayed = report
    if args.status:
        wanted_statuses = {Status(value) for value in args.status}
        displayed = ScanReport(
            tool_version=report.tool_version,
            findings=[finding for finding in report.findings if finding.status in wanted_statuses],
        )
    if args.json:
        rendered = render_json(displayed, delta)
    elif args.sarif:
        rendered = render_sarif(displayed)
    else:
        rendered = render_text(displayed, delta)
    print(rendered)
    return 1 if report_fails_at(report, args.fail_on) else 0
