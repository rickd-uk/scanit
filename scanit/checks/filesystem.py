"""Checks for high-impact local filesystem permissions."""

from __future__ import annotations

import stat
from os import stat_result
from pathlib import Path

from ..context import ScanContext
from ..models import Confidence, Finding, Severity, Status


def unsafe_privileged_metadata(info: stat_result) -> bool:
    """Return whether a root-owned configuration can be changed by another user."""
    return info.st_uid != 0 or bool(stat.S_IMODE(info.st_mode) & 0o022)


def _inspect_etc_tree(
    directory: Path, maximum_paths: int,
) -> tuple[list[tuple[Path, stat_result]], list[str], int]:
    metadata: list[tuple[Path, stat_result]] = []
    errors: list[str] = []
    inspected = 0
    try:
        for path in directory.rglob("*"):
            if inspected >= maximum_paths:
                errors.append(f"{directory}: traversal limit of {maximum_paths} paths reached")
                break
            try:
                info = path.lstat()
            except OSError as error:
                errors.append(f"{path}: {type(error).__name__}")
                continue
            if stat.S_ISLNK(info.st_mode):
                continue
            if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
                continue
            inspected += 1
            metadata.append((path, info))
    except OSError as error:
        errors.append(f"{directory}: {type(error).__name__}")
    return metadata, errors, inspected


def _bounded_evidence(items: list[str], errors: list[str], limit: int) -> tuple[str, ...]:
    evidence = items[:limit]
    if len(items) > limit:
        evidence.append(f"... {len(items) - limit} additional path(s) omitted")
    evidence.extend(errors[:max(0, limit - len(evidence))])
    return tuple(evidence)


class SudoersPermissionsCheck:
    check_id = "system.filesystem.sudoers-permissions"
    area = "system"

    def run(self, context: ScanContext) -> list[Finding]:
        path = context.root / "etc/sudoers"
        try:
            info = path.stat()
        except FileNotFoundError:
            return [Finding(self.check_id, self.area, "Sudoers file not found", Status.UNKNOWN,
                            Severity.INFO, str(path), confidence=Confidence.MEDIUM)]
        except OSError as error:
            return [Finding(self.check_id, self.area, "Sudoers file unreadable", Status.ERROR,
                            Severity.INFO, str(error), confidence=Confidence.LOW)]

        mode = stat.S_IMODE(info.st_mode)
        if unsafe_privileged_metadata(info):
            return [Finding(
                self.check_id, self.area, "Sudoers permissions are unsafe", Status.FAIL,
                Severity.CRITICAL, f"{path} owner uid={info.st_uid}, mode={mode:04o}",
                remediation="Set root ownership and mode 0440, then validate with visudo.",
            )]
        return [Finding(self.check_id, self.area, "Sudoers permissions are safe", Status.PASS,
                        Severity.INFO, f"{path} owner uid=0, mode={mode:04o}")]


class SudoersDropInPermissionsCheck:
    check_id = "system.filesystem.sudoers-drop-in-permissions"
    area = "system"

    def run(self, context: ScanContext) -> list[Finding]:
        directory = context.root / "etc/sudoers.d"
        try:
            directory_info = directory.stat()
        except FileNotFoundError:
            return [Finding(
                self.check_id, self.area, "No sudoers drop-in directory", Status.NOT_APPLICABLE,
                Severity.INFO, f"{directory} does not exist.",
            )]
        except PermissionError as error:
            return [Finding(
                self.check_id, self.area, "Sudoers drop-ins could not be inspected", Status.UNKNOWN,
                Severity.INFO, str(error), confidence=Confidence.LOW,
            )]
        except OSError as error:
            return [Finding(
                self.check_id, self.area, "Sudoers drop-ins could not be inspected", Status.ERROR,
                Severity.INFO, str(error), confidence=Confidence.LOW,
            )]
        try:
            entries = sorted(
                path for path in directory.iterdir()
                if "." not in path.name and not path.name.endswith("~")
            )
        except PermissionError as error:
            return [Finding(
                self.check_id, self.area, "Sudoers drop-ins could not be inspected", Status.UNKNOWN,
                Severity.INFO, str(error), confidence=Confidence.LOW,
            )]
        except OSError as error:
            return [Finding(
                self.check_id, self.area, "Sudoers drop-ins could not be inspected", Status.ERROR,
                Severity.INFO, str(error), confidence=Confidence.LOW,
            )]

        unsafe: list[str] = []
        unreadable: list[str] = []
        inspected = 0
        if unsafe_privileged_metadata(directory_info):
            mode = stat.S_IMODE(directory_info.st_mode)
            unsafe.append(f"{directory} owner uid={directory_info.st_uid}, mode={mode:04o}")
        for entry in entries:
            try:
                info = entry.stat()
            except OSError as error:
                unreadable.append(f"{entry}: could not read metadata: {error}")
                continue
            if not stat.S_ISREG(info.st_mode):
                continue
            inspected += 1
            if unsafe_privileged_metadata(info):
                mode = stat.S_IMODE(info.st_mode)
                unsafe.append(f"{entry} owner uid={info.st_uid}, mode={mode:04o}")

        if unsafe:
            return [Finding(
                self.check_id, self.area, "Sudoers drop-in permissions are unsafe", Status.FAIL,
                Severity.CRITICAL, f"{len(unsafe)} unsafe sudoers drop-in path(s) found.",
                evidence=tuple(unsafe + unreadable),
                remediation="Set root ownership and remove group/other write access, then validate with visudo.",
                confidence=Confidence.MEDIUM if unreadable else Confidence.HIGH,
            )]
        if unreadable:
            return [Finding(
                self.check_id, self.area, "Sudoers drop-in permissions could not be fully inspected",
                Status.UNKNOWN, Severity.INFO, f"Could not inspect {len(unreadable)} active drop-in path(s).",
                evidence=tuple(unreadable), confidence=Confidence.LOW,
            )]
        return [Finding(
            self.check_id, self.area, "Sudoers drop-in permissions are safe", Status.PASS,
            Severity.INFO, f"Checked {inspected} active sudoers drop-in file(s).",
        )]


class SystemdUnitPermissionsCheck:
    check_id = "system.filesystem.systemd-unit-permissions"
    area = "system"
    evidence_limit = 50

    def run(self, context: ScanContext) -> list[Finding]:
        roots = (
            context.root / "etc/systemd/system",
            context.root / "usr/lib/systemd/system",
        )
        present = [root for root in roots if root.is_dir()]
        if not present:
            return [Finding(
                self.check_id, self.area, "Systemd unit permissions could not be inspected",
                Status.UNKNOWN, Severity.INFO, "No supported system unit directories were found.",
                confidence=Confidence.LOW,
            )]

        unsafe: list[str] = []
        errors: list[str] = []
        inspected = 0
        for root in present:
            for path in (root, *root.rglob("*")):
                try:
                    info = path.lstat()
                except OSError as error:
                    errors.append(f"{path}: {type(error).__name__}")
                    continue
                if stat.S_ISLNK(info.st_mode):
                    continue
                if not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
                    continue
                inspected += 1
                if unsafe_privileged_metadata(info):
                    mode = stat.S_IMODE(info.st_mode)
                    unsafe.append(f"{path} owner uid={info.st_uid}, mode={mode:04o}")

        if unsafe:
            evidence = unsafe[: self.evidence_limit]
            if len(unsafe) > self.evidence_limit:
                evidence.append(f"... {len(unsafe) - self.evidence_limit} additional path(s) omitted")
            evidence.extend(errors[: max(0, self.evidence_limit - len(evidence))])
            return [Finding(
                self.check_id, self.area, "Systemd unit paths have unsafe permissions", Status.FAIL,
                Severity.CRITICAL, f"Found {len(unsafe)} system unit path(s) outside the root-only write boundary.",
                evidence=tuple(evidence),
                remediation="Restore root ownership and remove group/other write access from affected system unit paths.",
                confidence=Confidence.MEDIUM if errors else Confidence.HIGH,
            )]
        if errors:
            return [Finding(
                self.check_id, self.area, "Systemd unit permissions could not be fully inspected",
                Status.UNKNOWN, Severity.INFO, f"Could not inspect {len(errors)} system unit path(s).",
                evidence=tuple(errors[: self.evidence_limit]), confidence=Confidence.LOW,
            )]
        return [Finding(
            self.check_id, self.area, "Systemd unit paths have root-only write protection",
            Status.PASS, Severity.INFO, f"Checked {inspected} system unit file and directory paths.",
            confidence=Confidence.HIGH,
        )]


class TemporaryDirectoryPermissionsCheck:
    check_id = "system.filesystem.temporary-directory-permissions"
    area = "system"
    relative_paths = ("tmp", "var/tmp", "dev/shm")

    def run(self, context: ScanContext) -> list[Finding]:
        unsafe: list[str] = []
        errors: list[str] = []
        inspected = 0
        for relative in self.relative_paths:
            path = context.root / relative
            try:
                info = path.lstat()
            except FileNotFoundError:
                continue
            except OSError as error:
                errors.append(f"{path}: {type(error).__name__}")
                continue
            if not stat.S_ISDIR(info.st_mode):
                errors.append(f"{path}: not a directory")
                continue
            inspected += 1
            mode = stat.S_IMODE(info.st_mode)
            if mode & 0o002 and not (mode & stat.S_ISVTX):
                unsafe.append(f"{path} owner uid={info.st_uid}, mode={mode:04o}")

        if unsafe:
            return [Finding(
                self.check_id, self.area, "Temporary directories are world-writable without sticky protection", Status.FAIL,
                Severity.HIGH, f"Found {len(unsafe)} unsafe temporary directory path(s).",
                evidence=tuple(unsafe + errors),
                remediation="Set the sticky bit on shared temporary directories (for example, chmod 1777 /tmp) and verify ownership.",
                confidence=Confidence.MEDIUM if errors else Confidence.HIGH,
            )]
        if errors:
            return [Finding(
                self.check_id, self.area, "Temporary-directory permissions could not be fully inspected", Status.UNKNOWN,
                Severity.INFO, f"Inspected {inspected} temporary directory path(s); {len(errors)} path(s) had errors.",
                evidence=tuple(errors), confidence=Confidence.LOW,
            )]
        if not inspected:
            return [Finding(
                self.check_id, self.area, "No standard temporary directories detected", Status.NOT_APPLICABLE,
                Severity.INFO, "None of /tmp, /var/tmp, or /dev/shm exists under the scan root.", confidence=Confidence.MEDIUM,
            )]
        return [Finding(
            self.check_id, self.area, "Temporary directories have sticky protection", Status.PASS,
            Severity.INFO, f"Checked {inspected} standard temporary directory path(s).", confidence=Confidence.HIGH,
        )]


class SensitiveSystemFilePermissionsCheck:
    check_id = "system.filesystem.sensitive-file-permissions"
    area = "system"
    targets = (
        ("system.filesystem.passwd-permissions", "etc/passwd", "passwd"),
        ("system.filesystem.group-permissions", "etc/group", "group"),
        ("system.filesystem.shadow-permissions", "etc/shadow", "shadow"),
        ("system.filesystem.gshadow-permissions", "etc/gshadow", "gshadow"),
        ("system.filesystem.sshd-config-permissions", "etc/ssh/sshd_config", "SSH daemon configuration"),
    )

    def run(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for check_id, relative, label in self.targets:
            path = context.root / relative
            try:
                info = path.lstat()
            except FileNotFoundError:
                findings.append(Finding(
                    check_id, self.area, f"{label} file is not present", Status.NOT_APPLICABLE,
                    Severity.INFO, f"{path} does not exist.", confidence=Confidence.MEDIUM,
                ))
                continue
            except OSError as error:
                findings.append(Finding(
                    check_id, self.area, f"{label} permissions could not be inspected", Status.UNKNOWN,
                    Severity.INFO, str(error), confidence=Confidence.LOW,
                ))
                continue
            mode = stat.S_IMODE(info.st_mode)
            if not stat.S_ISREG(info.st_mode) or unsafe_privileged_metadata(info):
                findings.append(Finding(
                    check_id, self.area, f"{label} permissions are unsafe", Status.FAIL,
                    Severity.CRITICAL, f"{path} owner uid={info.st_uid}, mode={mode:04o}",
                    remediation="Restore root ownership and remove group/other write permission from this system file.",
                    confidence=Confidence.HIGH,
                ))
                continue
            findings.append(Finding(
                check_id, self.area, f"{label} permissions are protected", Status.PASS,
                Severity.INFO, f"{path} owner uid={info.st_uid}, mode={mode:04o}.", confidence=Confidence.HIGH,
            ))
        return findings


class UserStartupFilePermissionsCheck:
    check_id = "system.identity.startup-file-permissions"
    area = "identity"
    relative_paths = (".bashrc", ".bash_profile", ".profile", ".config/autostart")

    def run(self, context: ScanContext) -> list[Finding]:
        unsafe: list[str] = []
        errors: list[str] = []
        inspected = 0
        for relative in self.relative_paths:
            path = context.home / relative
            try:
                info = path.lstat()
            except FileNotFoundError:
                continue
            except OSError as error:
                errors.append(f"{path}: {type(error).__name__}")
                continue
            inspected += 1
            mode = stat.S_IMODE(info.st_mode)
            if stat.S_ISLNK(info.st_mode) or bool(mode & 0o022):
                unsafe.append(f"{path} owner uid={info.st_uid}, mode={mode:04o}")

        if unsafe:
            return [Finding(
                self.check_id, self.area, "User startup paths permit unsafe modification", Status.FAIL,
                Severity.HIGH, f"Found {len(unsafe)} startup path(s) writable by group/other users or linked unexpectedly.",
                evidence=tuple(unsafe + errors),
                remediation="Remove group/other write permission and unexpected symlinks from shell startup and autostart paths.",
                confidence=Confidence.MEDIUM if errors else Confidence.HIGH,
            )]
        if errors:
            return [Finding(
                self.check_id, self.area, "User startup paths could not be fully inspected", Status.UNKNOWN,
                Severity.INFO, f"Inspected {inspected} startup path(s); {len(errors)} path(s) had errors.",
                evidence=tuple(errors), confidence=Confidence.LOW,
            )]
        if not inspected:
            return [Finding(
                self.check_id, self.area, "No supported user startup paths detected", Status.NOT_APPLICABLE,
                Severity.INFO, "No supported shell startup files or desktop autostart directory was found.", confidence=Confidence.MEDIUM,
            )]
        return [Finding(
            self.check_id, self.area, "User startup paths are protected", Status.PASS,
            Severity.INFO, f"Checked {inspected} user startup path(s).", confidence=Confidence.HIGH,
        )]


class EtcWritablePathsCheck:
    check_id = "system.filesystem.etc-writable-paths"
    area = "system"
    maximum_paths = 5000
    evidence_limit = 50

    def run(self, context: ScanContext) -> list[Finding]:
        directory = context.root / "etc"
        if not directory.is_dir():
            return [Finding(
                self.check_id, self.area, "The /etc tree is not present", Status.NOT_APPLICABLE,
                Severity.INFO, f"{directory} does not exist.", confidence=Confidence.MEDIUM,
            )]
        metadata, errors, inspected = _inspect_etc_tree(directory, self.maximum_paths)
        unsafe = [
            f"{path} owner uid={info.st_uid}, mode={stat.S_IMODE(info.st_mode):04o}"
            for path, info in metadata if stat.S_IMODE(info.st_mode) & 0o022
        ]

        if unsafe:
            return [Finding(
                self.check_id, self.area, "The /etc tree contains writable privileged paths", Status.FAIL,
                Severity.HIGH, f"Found {len(unsafe)} /etc path(s) writable by group or other users.",
                evidence=_bounded_evidence(unsafe, errors, self.evidence_limit),
                remediation="Remove group/other write permissions unless a narrowly reviewed policy requires them.",
                confidence=Confidence.MEDIUM if errors else Confidence.HIGH,
            )]
        if errors:
            return [Finding(
                self.check_id, self.area, "The /etc tree could not be fully inspected", Status.UNKNOWN,
                Severity.INFO, f"Inspected {inspected} /etc path(s); {len(errors)} traversal issue(s) occurred.",
                evidence=tuple(errors), confidence=Confidence.LOW,
            )]
        return [Finding(
            self.check_id, self.area, "The /etc tree has no group- or world-writable paths", Status.PASS,
            Severity.INFO, f"Checked {inspected} /etc file and directory path(s).",
            confidence=Confidence.HIGH,
        )]


class EtcOwnershipReviewCheck:
    check_id = "system.filesystem.etc-ownership-review"
    area = "system"
    maximum_paths = 5000
    evidence_limit = 50

    def run(self, context: ScanContext) -> list[Finding]:
        directory = context.root / "etc"
        if not directory.is_dir():
            return [Finding(
                self.check_id, self.area, "The /etc tree is not present", Status.NOT_APPLICABLE,
                Severity.INFO, f"{directory} does not exist.", confidence=Confidence.MEDIUM,
            )]
        metadata, errors, inspected = _inspect_etc_tree(directory, self.maximum_paths)
        review = [
            f"{path} owner uid={info.st_uid}, mode={stat.S_IMODE(info.st_mode):04o}"
            for path, info in metadata
            if info.st_uid != 0 and not (stat.S_IMODE(info.st_mode) & 0o022)
        ]

        if review:
            return [Finding(
                self.check_id, self.area, "Non-root-owned /etc paths require context review",
                Status.REVIEW, Severity.MEDIUM,
                f"Found {len(review)} non-root-owned /etc path(s) without group/other write access; "
                "service ownership can be intentional.",
                evidence=_bounded_evidence(review, errors, self.evidence_limit),
                remediation=(
                    "Confirm each owner is expected from trusted package or service policy and that no "
                    "more-privileged process consumes attacker-controlled content from the path."
                ),
                confidence=Confidence.MEDIUM if errors else Confidence.HIGH,
            )]
        if errors:
            return [Finding(
                self.check_id, self.area, "The /etc tree ownership could not be fully inspected",
                Status.UNKNOWN, Severity.INFO,
                f"Inspected {inspected} /etc path(s); {len(errors)} traversal issue(s) occurred.",
                evidence=tuple(errors[:self.evidence_limit]), confidence=Confidence.LOW,
            )]
        return [Finding(
            self.check_id, self.area, "No non-root-owned /etc paths require review", Status.PASS,
            Severity.INFO, f"Checked {inspected} /etc file and directory path(s).",
            confidence=Confidence.HIGH,
        )]
