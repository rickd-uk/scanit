"""Compare a current report with a prior JSON report."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from .models import ScanReport, Status


@dataclass(frozen=True, slots=True)
class ScanDelta:
    new_failures: tuple[str, ...] = ()
    resolved_failures: tuple[str, ...] = ()
    new_reviews: tuple[str, ...] = ()
    coverage_regressions: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, list[str]]:
        return {key: list(value) for key, value in asdict(self).items()}


def compare_with_baseline(current: ScanReport, baseline: dict[str, Any]) -> ScanDelta:
    findings = baseline.get("findings")
    if not isinstance(findings, list):
        raise ValueError("baseline has no findings list")
    previous: dict[str, str] = {}
    for item in findings:
        if not isinstance(item, dict):
            raise ValueError("baseline contains a non-object finding")
        check_id, status = item.get("check_id"), item.get("status")
        if not isinstance(check_id, str) or not isinstance(status, str):
            raise ValueError("baseline finding is missing check_id or status")
        previous[check_id] = status

    current_status = {finding.check_id: finding.status.value for finding in current.findings}
    new_failures = sorted(
        check_id for check_id, status in current_status.items()
        if status == Status.FAIL.value and previous.get(check_id) != Status.FAIL.value
    )
    resolved = sorted(
        check_id for check_id, status in previous.items()
        if status == Status.FAIL.value
        and check_id in current_status
        and current_status[check_id] != Status.FAIL.value
    )
    new_reviews = sorted(
        check_id for check_id, status in current_status.items()
        if status == Status.REVIEW.value and previous.get(check_id) != Status.REVIEW.value
    )
    established = {Status.PASS.value, Status.FAIL.value, Status.REVIEW.value}
    incomplete = {Status.UNKNOWN.value, Status.ERROR.value}
    regressions = sorted(
        check_id for check_id, status in current_status.items()
        if status in incomplete and previous.get(check_id) in established
    )
    return ScanDelta(tuple(new_failures), tuple(resolved), tuple(new_reviews), tuple(regressions))
