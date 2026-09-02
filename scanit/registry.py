"""Central registry for built-in checks."""

from __future__ import annotations

from .checks.base import Check


def builtin_checks() -> list[Check]:
    return []

