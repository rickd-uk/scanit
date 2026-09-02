"""Safe subprocess abstraction used by checks and tests."""

from __future__ import annotations

import os
import shutil
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
    trusted_path = "/usr/bin:/usr/sbin:/bin:/sbin"

    def run(self, command: Sequence[str], timeout: int = 10) -> CommandResult:
        if not command:
            return CommandResult(127, "empty command")
        executable = shutil.which(command[0], path=self.trusted_path)
        if executable is None:
            return CommandResult(127, f"command not found in trusted system path: {command[0]}")
        resolved = [executable, *command[1:]]
        environment = os.environ.copy()
        environment.update({"PATH": self.trusted_path, "LC_ALL": "C", "LANG": "C"})
        try:
            completed = subprocess.run(
                resolved,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=timeout,
                env=environment,
            )
            return CommandResult(completed.returncode, completed.stdout.strip())
        except FileNotFoundError as error:
            return CommandResult(127, str(error))
        except PermissionError as error:
            return CommandResult(126, str(error))
        except subprocess.TimeoutExpired as error:
            output = error.stdout.decode(errors="replace") if isinstance(error.stdout, bytes) else (error.stdout or "")
            return CommandResult(124, f"command timed out: {output}".strip())
