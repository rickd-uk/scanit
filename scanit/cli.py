"""Command-line interface."""

from __future__ import annotations

import argparse
from collections.abc import Sequence

from . import __version__
from .context import ScanContext
from .models import Status
from .registry import builtin_checks
from .reporters import render_json, render_text
from .runner import run_checks


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description="Audit an Arch Linux workstation's security posture.")
    result.add_argument("--json", action="store_true", help="emit versioned JSON")
    result.add_argument("--area", action="append", help="run checks in this area (repeatable)")
    result.add_argument("--list-checks", action="store_true", help="list stable check IDs and exit")
    return result


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    checks = builtin_checks()
    if args.area:
        wanted = set(args.area)
        checks = [check for check in checks if check.area in wanted]
    if args.list_checks:
        for check in checks:
            print(f"{check.check_id}\t{check.area}")
        return 0
    report = run_checks(checks, ScanContext.local(), __version__)
    print(render_json(report) if args.json else render_text(report))
    return 1 if any(item.status is Status.FAIL for item in report.findings) else 0
