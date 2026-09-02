"""Review high-impact sudo policy directives without executing privileged commands."""

from __future__ import annotations

import stat
from pathlib import Path

from ..context import ScanContext
from ..models import Confidence, Finding, Severity, Status


class SudoPasswordlessRulesCheck:
    check_id = "system.sudo.passwordless-rules"
    area = "identity"
    maximum_file_bytes = 1_048_576
    evidence_limit = 50

    def run(self, context: ScanContext) -> list[Finding]:
        main = context.root / "etc/sudoers"
        paths, discovery_errors = self._policy_paths(main, context.root / "etc/sudoers.d")
        matches: list[str] = []
        errors = list(discovery_errors)
        inspected = 0
        for path in paths:
            try:
                info = path.lstat()
                if stat.S_ISLNK(info.st_mode):
                    errors.append(f"{path}: symbolic link was not followed")
                    continue
                if not stat.S_ISREG(info.st_mode):
                    errors.append(f"{path}: not a regular file")
                    continue
                if info.st_size > self.maximum_file_bytes:
                    errors.append(f"{path}: exceeds the 1 MiB inspection limit")
                    continue
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError as error:
                errors.append(f"{path}: {type(error).__name__}")
                continue
            inspected += 1
            errors.extend(self._unresolved_includes(path, text))
            for line_number, logical_line in self._logical_lines(text):
                policy = logical_line.split("#", 1)[0].strip()
                folded = policy.casefold()
                if not policy:
                    continue
                if "nopasswd:" in folded:
                    matches.append(f"{path}:{line_number}: NOPASSWD tag")
                if folded.startswith("defaults") and "!authenticate" in folded:
                    matches.append(f"{path}:{line_number}: !authenticate default")

        if matches:
            evidence = matches[: self.evidence_limit]
            if len(matches) > self.evidence_limit:
                evidence.append(f"... {len(matches) - self.evidence_limit} additional rule(s) omitted")
            evidence.extend(errors[: max(0, self.evidence_limit - len(evidence))])
            return [Finding(
                self.check_id, self.area, "Passwordless sudo policy requires review", Status.REVIEW,
                Severity.HIGH, f"Found {len(matches)} passwordless sudo directive(s) across {inspected} policy file(s).",
                evidence=tuple(evidence),
                remediation="Confirm every passwordless grant is narrowly scoped to required users, hosts, and absolute command paths.",
                confidence=Confidence.MEDIUM if errors else Confidence.HIGH,
            )]
        if errors:
            return [Finding(
                self.check_id, self.area, "Passwordless sudo policy could not be fully inspected", Status.UNKNOWN,
                Severity.INFO, f"Inspected {inspected} policy file(s); {len(errors)} path(s) could not be checked.",
                evidence=tuple(errors[: self.evidence_limit]), confidence=Confidence.LOW,
            )]
        if not inspected:
            return [Finding(
                self.check_id, self.area, "Sudo policy was not found", Status.NOT_APPLICABLE,
                Severity.INFO, "No sudoers policy files were available.", confidence=Confidence.MEDIUM,
            )]
        return [Finding(
            self.check_id, self.area, "No passwordless sudo directives detected", Status.PASS,
            Severity.INFO, f"Inspected {inspected} sudo policy file(s).", confidence=Confidence.HIGH,
        )]

    @staticmethod
    def _policy_paths(main: Path, drop_in_directory: Path) -> tuple[list[Path], list[str]]:
        paths = [main] if main.exists() else []
        errors: list[str] = []
        try:
            paths.extend(sorted(
                path for path in drop_in_directory.iterdir()
                if "." not in path.name and not path.name.endswith("~")
            ))
        except FileNotFoundError:
            pass
        except OSError as error:
            errors.append(f"{drop_in_directory}: {type(error).__name__}")
        return paths, errors

    @staticmethod
    def _logical_lines(text: str):
        buffer = ""
        start = 1
        for number, physical in enumerate(text.splitlines(), start=1):
            stripped = physical.rstrip()
            if not buffer:
                start = number
            if stripped.endswith("\\"):
                buffer += stripped[:-1] + " "
                continue
            yield start, buffer + stripped
            buffer = ""
        if buffer:
            yield start, buffer

    @staticmethod
    def _unresolved_includes(path: Path, text: str) -> list[str]:
        unresolved: list[str] = []
        for number, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()
            folded = stripped.casefold()
            directives = ("#include", "#includedir", "@include", "@includedir")
            directive = next((item for item in directives if folded.startswith(item + " ")), None)
            if directive is None:
                continue
            target = stripped[len(directive):].strip().strip('"')
            if directive in {"#includedir", "@includedir"} and target.rstrip("/") == "/etc/sudoers.d":
                continue
            unresolved.append(f"{path}:{number}: custom sudoers include was not inspected")
        return unresolved


class SudoBroadCommandRulesCheck(SudoPasswordlessRulesCheck):
    check_id = "system.sudo.broad-command-rules"

    def run(self, context: ScanContext) -> list[Finding]:
        paths, discovery_errors = self._policy_paths(
            context.root / "etc/sudoers", context.root / "etc/sudoers.d"
        )
        matches: list[str] = []
        errors = list(discovery_errors)
        inspected = 0
        for path in paths:
            try:
                info = path.lstat()
                if stat.S_ISLNK(info.st_mode):
                    errors.append(f"{path}: symbolic link was not followed")
                    continue
                if not stat.S_ISREG(info.st_mode):
                    errors.append(f"{path}: not a regular file")
                    continue
                if info.st_size > self.maximum_file_bytes:
                    errors.append(f"{path}: exceeds the 1 MiB inspection limit")
                    continue
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError as error:
                errors.append(f"{path}: {type(error).__name__}")
                continue
            inspected += 1
            errors.extend(self._unresolved_includes(path, text))
            for line_number, logical_line in self._logical_lines(text):
                policy = logical_line.split("#", 1)[0].strip()
                kind = self._broad_rule_kind(policy)
                if kind:
                    matches.append(f"{path}:{line_number}: {kind}")

        if matches:
            evidence = matches[: self.evidence_limit]
            if len(matches) > self.evidence_limit:
                evidence.append(f"... {len(matches) - self.evidence_limit} additional rule(s) omitted")
            evidence.extend(errors[: max(0, self.evidence_limit - len(evidence))])
            return [Finding(
                self.check_id, self.area, "Broad sudo command policy requires review", Status.REVIEW,
                Severity.HIGH, f"Found {len(matches)} broad command rule(s) across {inspected} policy file(s).",
                evidence=tuple(evidence),
                remediation="Replace ALL and wildcard command grants with the smallest exact absolute-command set that operations require.",
                confidence=Confidence.MEDIUM if errors else Confidence.HIGH,
            )]
        if errors:
            return [Finding(
                self.check_id, self.area, "Sudo command scope could not be fully inspected", Status.UNKNOWN,
                Severity.INFO, f"Inspected {inspected} policy file(s); {len(errors)} path(s) could not be checked.",
                evidence=tuple(errors[: self.evidence_limit]), confidence=Confidence.LOW,
            )]
        if not inspected:
            return [Finding(
                self.check_id, self.area, "Sudo policy was not found", Status.NOT_APPLICABLE,
                Severity.INFO, "No sudoers policy files were available.", confidence=Confidence.MEDIUM,
            )]
        return [Finding(
            self.check_id, self.area, "No broad sudo command rules detected", Status.PASS,
            Severity.INFO, f"Inspected {inspected} sudo policy file(s).", confidence=Confidence.HIGH,
        )]

    @staticmethod
    def _broad_rule_kind(policy: str) -> str | None:
        if not policy:
            return None
        folded = policy.casefold()
        if folded.startswith(("defaults", "user_alias", "runas_alias", "host_alias")):
            return None
        left, separator, right = policy.partition("=")
        if not separator:
            return None
        subject = left.split(None, 1)[0] if left.split() else ""
        if subject.casefold() == "root":
            return None
        command_spec = right.strip()
        if command_spec.startswith("(") and ")" in command_spec:
            command_spec = command_spec.split(")", 1)[1].strip()
        while ":" in command_spec:
            tag, remainder = command_spec.split(":", 1)
            if not tag.replace("_", "").isalpha():
                break
            command_spec = remainder.strip()
        commands = [command.strip() for command in command_spec.split(",")]
        if any(command.casefold() == "all" for command in commands):
            return "unrestricted ALL command grant"
        if any(not command.startswith("!") and any(character in command for character in "*?[") for command in commands):
            return "wildcard command grant"
        return None
