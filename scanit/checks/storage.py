"""Checks for block-device encryption protecting the root filesystem."""

from __future__ import annotations

import json
from typing import Any

from ..context import ScanContext
from ..models import Confidence, Finding, Severity, Status


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
