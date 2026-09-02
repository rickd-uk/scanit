"""Runtime dependencies made explicit for deterministic checks."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .commands import CommandExecutor, LocalCommandExecutor


@dataclass(frozen=True, slots=True)
class ScanContext:
    home: Path
    root: Path
    commands: CommandExecutor

    @classmethod
    def local(cls) -> "ScanContext":
        return cls(home=Path.home(), root=Path("/"), commands=LocalCommandExecutor())

