"""Shared, serializable audit result types."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any


class Status(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    REVIEW = "review"
    UNKNOWN = "unknown"
    ERROR = "error"
    NOT_APPLICABLE = "not_applicable"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass(frozen=True, slots=True)
class Finding:
    check_id: str
    area: str
    title: str
    status: Status
    severity: Severity
    summary: str
    evidence: tuple[str, ...] = ()
    remediation: str = ""
    confidence: Confidence = Confidence.HIGH

    def as_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["status"] = self.status.value
        value["severity"] = self.severity.value
        value["confidence"] = self.confidence.value
        value["evidence"] = list(self.evidence)
        return value


@dataclass(slots=True)
class ScanReport:
    tool_version: str
    findings: list[Finding] = field(default_factory=list)

    @property
    def risk_score(self) -> int:
        weights = {
            Severity.CRITICAL: 40,
            Severity.HIGH: 20,
            Severity.MEDIUM: 8,
            Severity.LOW: 3,
            Severity.INFO: 0,
        }
        confidence = {Confidence.HIGH: 1.0, Confidence.MEDIUM: 0.7, Confidence.LOW: 0.4}
        total = sum(
            weights[item.severity] * confidence[item.confidence]
            for item in self.findings
            if item.status is Status.FAIL
        )
        return min(100, round(total))

    @property
    def coverage(self) -> dict[str, int]:
        return {
            status.value: sum(item.status is status for item in self.findings)
            for status in Status
        }

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 2,
            "tool": "ScanIt",
            "tool_version": self.tool_version,
            "risk_score": self.risk_score,
            "coverage": self.coverage,
            "findings": [item.as_dict() for item in self.findings],
        }
