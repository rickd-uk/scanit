"""Review high-impact sudo policy directives without executing privileged commands."""

from __future__ import annotations

import stat
import re
from pathlib import Path, PurePosixPath

from ..context import ScanContext
from ..models import Confidence, Finding, Severity, Status
from .filesystem import unsafe_privileged_metadata


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


class SudoPolicySyntaxCheck:
    check_id = "system.sudo.policy-syntax"
    area = "identity"

    def run(self, context: ScanContext) -> list[Finding]:
        path = context.root / "etc/sudoers"
        try:
            path.lstat()
        except FileNotFoundError:
            return [Finding(
                self.check_id, self.area, "Sudo policy was not found", Status.NOT_APPLICABLE,
                Severity.INFO, f"{path} does not exist.", confidence=Confidence.HIGH,
            )]
        except OSError as error:
            return [Finding(
                self.check_id, self.area, "Sudo policy syntax could not be validated", Status.UNKNOWN,
                Severity.INFO, str(error), confidence=Confidence.LOW,
            )]

        result = context.commands.run(("visudo", "-c", "-f", str(path)), timeout=10)
        if result.returncode == 0:
            return [Finding(
                self.check_id, self.area, "Sudo policy syntax is valid", Status.PASS,
                Severity.INFO, result.stdout or "visudo accepted the sudo policy and its includes.",
                confidence=Confidence.HIGH,
            )]
        if result.returncode == 127:
            return [Finding(
                self.check_id, self.area, "Sudo policy validator is unavailable", Status.UNKNOWN,
                Severity.INFO, "visudo is not available in the trusted system path.", confidence=Confidence.LOW,
            )]
        if result.returncode == 126:
            return [Finding(
                self.check_id, self.area, "Sudo policy validator could not execute", Status.UNKNOWN,
                Severity.INFO, result.stdout or "visudo could not be executed.", confidence=Confidence.LOW,
            )]
        return [Finding(
            self.check_id, self.area, "Sudo policy has validation errors", Status.FAIL,
            Severity.HIGH, result.stdout or f"visudo exited with status {result.returncode}.",
            remediation="Correct the reported policy error using visudo before relying on sudo access controls.",
            confidence=Confidence.HIGH,
        )]


class SudoSecurePathCheck(SudoPasswordlessRulesCheck):
    check_id = "system.sudo.secure-path"
    assignment = re.compile(r"\bsecure_path\s*=\s*(?:\"([^\"]*)\"|'([^']*)'|([^,\s]+))", re.IGNORECASE)

    def run(self, context: ScanContext) -> list[Finding]:
        paths, errors = self._policy_paths(context.root / "etc/sudoers", context.root / "etc/sudoers.d")
        values: list[tuple[Path, int, str]] = []
        inspected = 0
        for path in paths:
            try:
                info = path.lstat()
                if stat.S_ISLNK(info.st_mode):
                    errors.append(f"{path}: symbolic link was not followed")
                    continue
                if not stat.S_ISREG(info.st_mode) or info.st_size > self.maximum_file_bytes:
                    errors.append(f"{path}: unsupported file type or size")
                    continue
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError as error:
                errors.append(f"{path}: {type(error).__name__}")
                continue
            inspected += 1
            errors.extend(self._unresolved_includes(path, text))
            for line_number, logical_line in self._logical_lines(text):
                policy = logical_line.split("#", 1)[0].strip()
                if not policy.casefold().startswith("defaults"):
                    continue
                match = self.assignment.search(policy)
                if match:
                    values.append((path, line_number, next(value for value in match.groups() if value is not None)))

        unsafe: list[str] = []
        checked_directories: set[Path] = set()
        for source, line_number, value in values:
            for component in value.split(":"):
                parsed = PurePosixPath(component)
                if not component or component == "." or not parsed.is_absolute() or ".." in parsed.parts:
                    unsafe.append(f"{source}:{line_number}: unsafe secure_path component {component!r}")
                    continue
                target = context.root.joinpath(*parsed.parts[1:])
                boundary = context.root.parent
                for directory in (target, *target.parents):
                    if directory == boundary:
                        break
                    if directory in checked_directories:
                        continue
                    checked_directories.add(directory)
                    try:
                        info = directory.lstat()
                    except OSError as error:
                        errors.append(f"{directory}: {type(error).__name__}")
                        continue
                    if stat.S_ISLNK(info.st_mode):
                        errors.append(f"{directory}: symbolic link target was not evaluated")
                    elif not stat.S_ISDIR(info.st_mode) or unsafe_privileged_metadata(info):
                        mode = stat.S_IMODE(info.st_mode)
                        unsafe.append(f"{directory}: owner uid={info.st_uid}, mode={mode:04o}")

        if unsafe:
            return [Finding(
                self.check_id, self.area, "Sudo secure_path has unsafe components", Status.FAIL,
                Severity.HIGH, f"Found {len(unsafe)} unsafe secure_path component(s).",
                evidence=tuple((unsafe + errors)[: self.evidence_limit]),
                remediation="Use only absolute, root-owned directories without group/other write access in sudo secure_path.",
                confidence=Confidence.MEDIUM if errors else Confidence.HIGH,
            )]
        if errors or not values:
            detail = "No configured secure_path was found; the compiled sudo default could not be established." if not values else f"Could not verify {len(errors)} policy or path item(s)."
            return [Finding(
                self.check_id, self.area, "Sudo secure_path could not be fully verified", Status.UNKNOWN,
                Severity.INFO, detail, evidence=tuple(errors[: self.evidence_limit]), confidence=Confidence.LOW,
            )]
        return [Finding(
            self.check_id, self.area, "Sudo secure_path directories are protected", Status.PASS,
            Severity.INFO, f"Verified {len(checked_directories)} directory path(s) from {len(values)} secure_path definition(s).",
            confidence=Confidence.HIGH,
        )]
