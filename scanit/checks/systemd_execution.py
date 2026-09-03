"""Audit effective execution paths used by active or enabled system services."""

from __future__ import annotations

import re
import stat
from pathlib import Path

from ..context import ScanContext
from ..models import Confidence, Finding, Severity, Status
from .filesystem import unsafe_privileged_metadata


_EXECUTION_PROPERTIES = (
    "ExecCondition", "ExecStartPre", "ExecStart", "ExecStartPost",
    "ExecReload", "ExecStop", "ExecStopPost",
)
_PATH_PATTERN = re.compile(r"\{\s*path=([^\s;}]+)")
_FLAGS_PATTERN = re.compile(r";\s*flags=([^;}]*)(?:;|\})")
_PRIVILEGED_FLAGS = frozenset(("privileged", "no-setuid", "ambient"))
_SYSTEMD_BINARY_DIRECTORIES = ("usr/local/bin", "usr/bin")


def _service_names(output: str) -> set[str]:
    names: set[str] = set()
    for line in output.splitlines():
        fields = line.split()
        if not fields:
            continue
        name = fields[0]
        if name.endswith(".service") and "@." not in name:
            names.add(name)
    return names


def _property_blocks(output: str) -> list[dict[str, list[str]]]:
    blocks: list[dict[str, list[str]]] = []
    for raw_block in output.strip().split("\n\n"):
        properties: dict[str, list[str]] = {}
        for line in raw_block.splitlines():
            key, separator, value = line.partition("=")
            if separator and key:
                properties.setdefault(key, []).append(value)
        if properties:
            blocks.append(properties)
    return blocks


def _first_property(block: dict[str, list[str]], name: str) -> str | None:
    values = block.get(name)
    return values[0] if values else None


def _execution_targets(block: dict[str, list[str]]) -> dict[str, bool]:
    """Return executable paths and whether a command overrides service credentials."""
    targets: dict[str, bool] = {}
    for property_name in _EXECUTION_PROPERTIES:
        extended_values = block.get(f"{property_name}Ex", [])
        values = extended_values or block.get(property_name, [])
        for value in values:
            flag_match = _FLAGS_PATTERN.search(value) if extended_values else None
            flags = set(flag_match.group(1).split()) if flag_match else set()
            privileged = bool(flags & _PRIVILEGED_FLAGS)
            for path_match in _PATH_PATTERN.finditer(value):
                path = path_match.group(1)
                targets[path] = targets.get(path, False) or privileged
    return targets


def _candidate_paths(root: Path, executable: str) -> tuple[list[Path], str | None]:
    if "\\" in executable:
        return [], f"unsupported executable path: {executable}"
    try:
        scan_root = root.resolve(strict=True)
        if executable.startswith("/"):
            logical = scan_root / executable.lstrip("/")
        elif "/" not in executable:
            logical = next(
                candidate for relative in _SYSTEMD_BINARY_DIRECTORIES
                if (candidate := scan_root / relative / executable).exists()
            )
        else:
            return [], f"unsupported executable path: {executable}"
        resolved = logical.resolve(strict=True)
    except StopIteration:
        return [], f"{executable}: not found in systemd's default binary search path"
    except OSError as error:
        return [], f"{executable}: {type(error).__name__}"
    if not resolved.is_relative_to(scan_root):
        return [], f"{executable}: resolved outside the scan root"

    candidates: list[Path] = [resolved]
    for parent in resolved.parents:
        if parent == scan_root:
            break
        candidates.append(parent)
    for parent in logical.parents:
        if parent == scan_root:
            break
        try:
            if not parent.is_symlink():
                candidates.append(parent)
        except OSError as error:
            return [], f"{parent}: {type(error).__name__}"
    return list(dict.fromkeys(candidates)), None


class SystemdExecutionPathCheck:
    check_id = "system.services.privileged-execution-paths"
    area = "system"
    evidence_limit = 50

    def run(self, context: ScanContext) -> list[Finding]:
        active_command = (
            "systemctl", "list-units", "--type=service", "--state=active",
            "--no-legend", "--no-pager", "--plain",
        )
        enabled_command = (
            "systemctl", "list-unit-files", "--type=service",
            "--state=enabled,enabled-runtime", "--no-legend", "--no-pager",
        )
        active = context.commands.run(active_command, timeout=15)
        enabled = context.commands.run(enabled_command, timeout=15)
        if active.returncode == 127 or enabled.returncode == 127:
            return [Finding(
                self.check_id, self.area, "System service execution paths could not be inspected",
                Status.UNKNOWN, Severity.INFO, "systemctl is not available in the trusted system path.",
                confidence=Confidence.LOW,
            )]

        discovery_errors = [
            f"{label}: {result.stdout or f'exited with status {result.returncode}'}"
            for label, result in (("active services", active), ("enabled services", enabled))
            if result.returncode != 0
        ]
        services: set[str] = set()
        if active.returncode == 0:
            services.update(_service_names(active.stdout))
        if enabled.returncode == 0:
            services.update(_service_names(enabled.stdout))
        if not services:
            if discovery_errors:
                return [self._unknown(discovery_errors, "No service inventory was available.")]
            return [Finding(
                self.check_id, self.area, "No active or enabled system services were found",
                Status.NOT_APPLICABLE, Severity.INFO,
                "systemctl reported no concrete active or enabled service units.",
            )]

        execution_properties = [
            property_name
            for base_name in _EXECUTION_PROPERTIES
            for property_name in (base_name, f"{base_name}Ex")
        ]
        properties = "Id,User,DynamicUser," + ",".join(execution_properties)
        show_command = (
            "systemctl", "show", "--all", "--no-pager", f"--property={properties}",
            "--", *sorted(services),
        )
        shown = context.commands.run(show_command, timeout=30)
        if shown.returncode == 127:
            return [Finding(
                self.check_id, self.area, "System service execution paths could not be inspected",
                Status.UNKNOWN, Severity.INFO, "systemctl is not available in the trusted system path.",
                confidence=Confidence.LOW,
            )]
        if shown.returncode != 0 and not shown.stdout:
            return [self._unknown(
                [shown.stdout or f"systemctl show exited with status {shown.returncode}."],
                "Effective service properties were unavailable.",
            )]
        errors = list(discovery_errors)
        if shown.returncode != 0:
            errors.append(f"systemctl show exited with status {shown.returncode}")

        privileged_unsafe: list[str] = []
        other_unsafe: list[str] = []
        inspected_targets = 0
        seen_services: set[str] = set()
        for block in _property_blocks(shown.stdout):
            service = _first_property(block, "Id") or ""
            if not service.endswith(".service"):
                errors.append("systemctl show returned a block without a service Id")
                continue
            seen_services.add(service)
            user = _first_property(block, "User")
            dynamic = (_first_property(block, "DynamicUser") or "no").casefold() == "yes"
            service_privileged = user in ("", "0", "root") and not dynamic
            if user is None:
                errors.append(f"{service}: execution user was not reported")

            executables = _execution_targets(block)
            if not executables:
                errors.append(f"{service}: no effective execution path was reported")
                continue
            for executable, command_privileged in sorted(executables.items()):
                inspected_targets += 1
                candidates, path_error = _candidate_paths(context.root, executable)
                if path_error:
                    errors.append(f"{service}: {path_error}")
                    continue
                for path in candidates:
                    try:
                        info = path.stat()
                    except OSError as error:
                        errors.append(f"{service}: {path}: {type(error).__name__}")
                        continue
                    if path == candidates[0] and not stat.S_ISREG(info.st_mode):
                        errors.append(f"{service}: executable target {path} is not a regular file")
                        continue
                    if unsafe_privileged_metadata(info):
                        mode = stat.S_IMODE(info.st_mode)
                        privileged = service_privileged or command_privileged
                        label = "privileged" if privileged else f"user={user or 'unresolved'}"
                        evidence = f"{service} ({label}): {path} owner uid={info.st_uid}, mode={mode:04o}"
                        (privileged_unsafe if privileged else other_unsafe).append(evidence)

        missing = services - seen_services
        errors.extend(f"{service}: effective properties were not returned" for service in sorted(missing))
        unsafe = list(dict.fromkeys([*privileged_unsafe, *other_unsafe]))
        if privileged_unsafe:
            return [Finding(
                self.check_id, self.area, "Privileged system service execution paths are unsafe",
                Status.FAIL, Severity.HIGH,
                f"Found {len(set(privileged_unsafe))} unsafe privileged execution path observation(s).",
                evidence=self._evidence(unsafe, errors),
                remediation=(
                    "Restore root ownership and remove group/other write access from each executable "
                    "and parent directory used by privileged services."
                ),
                confidence=Confidence.MEDIUM if errors else Confidence.HIGH,
            )]
        if other_unsafe:
            return [Finding(
                self.check_id, self.area, "System service execution paths require review",
                Status.REVIEW, Severity.MEDIUM,
                f"Found {len(set(other_unsafe))} unsafe non-root service path observation(s).",
                evidence=self._evidence(unsafe, errors),
                remediation="Protect service executables and parent directories from modification by the service account or other users.",
                confidence=Confidence.MEDIUM if errors else Confidence.HIGH,
            )]
        if errors:
            return [self._unknown(errors, f"Inspected {inspected_targets} service execution target(s).")]
        return [Finding(
            self.check_id, self.area, "System service execution paths are protected", Status.PASS,
            Severity.INFO,
            f"Checked {inspected_targets} execution target(s) across {len(seen_services)} active or enabled service(s).",
        )]

    def _evidence(self, unsafe: list[str], errors: list[str]) -> tuple[str, ...]:
        evidence = unsafe[:self.evidence_limit]
        if len(unsafe) > self.evidence_limit:
            evidence.append(f"... {len(unsafe) - self.evidence_limit} additional path observation(s) omitted")
        evidence.extend(errors[:max(0, self.evidence_limit - len(evidence))])
        return tuple(evidence)

    def _unknown(self, errors: list[str], summary: str) -> Finding:
        return Finding(
            self.check_id, self.area, "System service execution paths could not be fully inspected",
            Status.UNKNOWN, Severity.INFO, summary,
            evidence=tuple(errors[:self.evidence_limit]), confidence=Confidence.LOW,
        )
