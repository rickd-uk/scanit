"""Central registry for built-in checks."""

from __future__ import annotations

from .checks.base import Check
from .checks.browser_permissions import BrowserProfilePermissionsCheck
from .checks.filesystem import SudoersDropInPermissionsCheck, SudoersPermissionsCheck
from .checks.firewall import FirewallServiceCheck
from .checks.packages import PendingPackageUpdatesCheck
from .checks.package_trust import PacmanSignaturePolicyCheck
from .checks.ssh import SshAuthenticationCheck


def builtin_checks() -> list[Check]:
    return [
        BrowserProfilePermissionsCheck(),
        PendingPackageUpdatesCheck(),
        PacmanSignaturePolicyCheck(),
        FirewallServiceCheck(),
        SshAuthenticationCheck(),
        SudoersPermissionsCheck(),
        SudoersDropInPermissionsCheck(),
    ]
