from __future__ import annotations

from typing import Protocol

from ..context import ScanContext
from ..models import Finding


class Check(Protocol):
    check_id: str
    area: str

    def run(self, context: ScanContext) -> list[Finding]: ...

