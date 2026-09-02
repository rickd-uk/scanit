"""Safe subprocess abstraction used by checks and tests."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import Protocol, Sequence


@dataclass(frozen=True, slots=True)
class CommandResult:
    returncode: int
    stdout: str


class CommandExecutor(Protocol):
    def run(self, command: Sequence[str], timeout: int = 10) -> CommandResult: ...


class LocalCommandExecutor:
    def run(self, command: Sequence[str], timeout: int = 10) -> CommandResult:
        try:
            completed = subprocess.run(
                list(command),
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=timeout,
            )
            return CommandResult(completed.returncode, completed.stdout.strip())
        except FileNotFoundError as error:
            return CommandResult(127, str(error))
        except subprocess.TimeoutExpired as error:
            output = error.stdout.decode(errors="replace") if isinstance(error.stdout, bytes) else (error.stdout or "")
            return CommandResult(124, f"command timed out: {output}".strip())

