"""Checks for storage encryption and shared-filesystem mount policy."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from ..context import ScanContext
from ..models import Confidence, Finding, Severity, Status


_SHARED_FILESYSTEMS = frozenset({"ntfs", "ntfs3", "fuseblk", "exfat", "vfat", "msdos"})
_SYSTEM_FAT_MOUNTPOINTS = frozenset({"/boot", "/boot/efi", "/efi"})
_SECURITY_OPTIONS = frozenset({"nosuid", "nodev", "noexec"})
_OWNERSHIP_OPTIONS = frozenset({
    "uid", "gid", "umask", "fmask", "dmask", "permissions", "acl", "user_id", "group_id",
})
_MOUNTINFO_ESCAPE = re.compile(r"\\(040|011|012|134)")
_MOUNTINFO_UNESCAPE = {"040": " ", "011": "\t", "012": "\n", "134": "\\"}


@dataclass(frozen=True, slots=True)
class _MountInfo:
    mountpoint: str
    filesystem: str
    source: str
    options: frozenset[str]


def _decode_mountinfo(value: str) -> str:
    return _MOUNTINFO_ESCAPE.sub(lambda match: _MOUNTINFO_UNESCAPE[match.group(1)], value)


def _parse_mountinfo_line(line: str) -> _MountInfo:
    before, separator, after = line.partition(" - ")
    fields = before.split()
    filesystem_fields = after.split()
    if not separator or len(fields) < 6 or len(filesystem_fields) < 3:
        raise ValueError("missing required mountinfo fields")
    options = set(fields[5].split(","))
    options.update(filesystem_fields[2].split(","))
    return _MountInfo(
        mountpoint=_decode_mountinfo(fields[4]),
        filesystem=filesystem_fields[0].casefold(),
        source=_decode_mountinfo(filesystem_fields[1]),
        options=frozenset(option for option in options if option),
    )


class SharedFilesystemMountOptionsCheck:
    check_id = "system.storage.shared-mount-options"
    area = "storage"

    def run(self, context: ScanContext) -> list[Finding]:
        path = context.root / "proc/self/mountinfo"
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except FileNotFoundError:
            return [Finding(
                self.check_id, self.area, "Shared filesystem mounts could not be inspected",
                Status.UNKNOWN, Severity.INFO, f"{path} does not exist.", confidence=Confidence.LOW,
            )]
        except OSError as error:
            return [Finding(
                self.check_id, self.area, "Shared filesystem mounts could not be inspected",
                Status.UNKNOWN, Severity.INFO, str(error), confidence=Confidence.LOW,
            )]

        if not any(line.strip() for line in lines):
            return [Finding(
                self.check_id, self.area, "Shared filesystem mount data is invalid", Status.ERROR,
                Severity.INFO, f"{path} is empty.", confidence=Confidence.LOW,
            )]
        try:
            mounts = [_parse_mountinfo_line(line) for line in lines if line.strip()]
        except ValueError as error:
            return [Finding(
                self.check_id, self.area, "Shared filesystem mount data is invalid", Status.ERROR,
                Severity.INFO, f"Could not parse {path}: {error}.", confidence=Confidence.LOW,
            )]

        shared = [
            mount for mount in mounts
            if mount.filesystem in _SHARED_FILESYSTEMS
            and not (
                mount.filesystem in {"vfat", "msdos"}
                and mount.mountpoint.rstrip("/") in _SYSTEM_FAT_MOUNTPOINTS
            )
        ]
        if not shared:
            return [Finding(
                self.check_id, self.area, "No shared filesystems are currently mounted",
                Status.NOT_APPLICABLE, Severity.INFO,
                "No active NTFS, exFAT, or FAT-family mount was found.",
            )]

        evidence: list[str] = []
        exposed: list[tuple[_MountInfo, list[str]]] = []
        for mount in shared:
            missing = sorted(_SECURITY_OPTIONS - mount.options)
            if missing:
                exposed.append((mount, missing))
            evidence.append(self._describe_mount(mount, missing))

        if exposed:
            missing_names = sorted({option for _, missing in exposed for option in missing})
            return [Finding(
                self.check_id, self.area, "Shared filesystem mount options require review",
                Status.REVIEW, Severity.LOW,
                f"{len(exposed)} of {len(shared)} shared mount(s) omit security options: "
                f"{', '.join(missing_names)}.",
                evidence=tuple(evidence),
                remediation=(
                    "If compatible with the volume's purpose, add nosuid,nodev,noexec to its mount "
                    "policy and use restrictive uid/gid and umask/fmask/dmask mappings."
                ),
            )]
        return [Finding(
            self.check_id, self.area, "Shared filesystem mount options are hardened",
            Status.PASS, Severity.INFO,
            f"All {len(shared)} shared mount(s) use nosuid,nodev,noexec.",
            evidence=tuple(evidence),
        )]

    @staticmethod
    def _describe_mount(mount: _MountInfo, missing: list[str]) -> str:
        implementations = {
            "ntfs3": "kernel NTFS3",
            "ntfs": "legacy kernel NTFS",
            "fuseblk": "FUSE block filesystem (commonly NTFS-3G)",
            "exfat": "kernel exFAT",
            "vfat": "kernel FAT",
            "msdos": "kernel FAT",
        }
        access = "ro" if "ro" in mount.options else "rw" if "rw" in mount.options else "unspecified"
        ownership = sorted(
            option for option in mount.options if option.partition("=")[0] in _OWNERSHIP_OPTIONS
        )
        security = "missing " + ",".join(missing) if missing else "nosuid,nodev,noexec"
        ownership_text = ",".join(ownership) if ownership else "default mapping"
        return (
            f"{mount.mountpoint}: {mount.filesystem} ({implementations[mount.filesystem]}), "
            f"source={mount.source}, access={access}, security={security}, ownership={ownership_text}"
        )


class RootFilesystemEncryptionCheck:
    check_id = "system.storage.root-encryption"
    area = "storage"

    def run(self, context: ScanContext) -> list[Finding]:
        command = ("lsblk", "--json", "--output", "NAME,TYPE,MOUNTPOINTS")
        result = context.commands.run(command, timeout=8)
        if result.returncode == 127:
            return [Finding(
                self.check_id, self.area, "Root encryption could not be determined", Status.UNKNOWN,
                Severity.INFO, "lsblk is not available.", confidence=Confidence.LOW,
            )]
        if result.returncode != 0:
            return [Finding(
                self.check_id, self.area, "Root encryption could not be determined", Status.ERROR,
                Severity.INFO, result.stdout or f"lsblk exited with status {result.returncode}.",
                confidence=Confidence.LOW,
            )]
        try:
            payload = json.loads(result.stdout)
            devices = payload["blockdevices"]
            if not isinstance(devices, list):
                raise TypeError("blockdevices is not a list")
        except (json.JSONDecodeError, KeyError, TypeError) as error:
            return [Finding(
                self.check_id, self.area, "Root encryption could not be determined", Status.ERROR,
                Severity.INFO, f"Invalid lsblk JSON: {error}", confidence=Confidence.LOW,
            )]

        root_states: list[bool] = []
        for device in devices:
            if isinstance(device, dict):
                self._collect_root_states(device, False, root_states)
        if not root_states:
            return [Finding(
                self.check_id, self.area, "Root block device could not be identified", Status.UNKNOWN,
                Severity.INFO, "lsblk did not map the root mount to a block device.",
                confidence=Confidence.LOW,
            )]
        if all(root_states):
            return [Finding(
                self.check_id, self.area, "Root filesystem is backed by encrypted block storage",
                Status.PASS, Severity.INFO, "A crypt device appears in the root filesystem's device path.",
                confidence=Confidence.MEDIUM,
            )]
        return [Finding(
            self.check_id, self.area, "No encrypted block layer detected for the root filesystem",
            Status.FAIL, Severity.MEDIUM,
            "The root device path reported by lsblk contains no crypt device; filesystem-level or hardware encryption may not be visible.",
            remediation="Use full-disk or root-volume encryption where physical access is a relevant threat.",
            confidence=Confidence.MEDIUM,
        )]

    @classmethod
    def _collect_root_states(cls, device: dict[str, Any], encrypted: bool, states: list[bool]) -> None:
        encrypted = encrypted or str(device.get("type", "")).casefold() == "crypt"
        mountpoints = device.get("mountpoints") or []
        if isinstance(mountpoints, str):
            mountpoints = [mountpoints]
        if isinstance(mountpoints, list) and "/" in mountpoints:
            states.append(encrypted)
        children = device.get("children") or []
        if isinstance(children, list):
            for child in children:
                if isinstance(child, dict):
                    cls._collect_root_states(child, encrypted, states)
