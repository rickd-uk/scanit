"""Central registry for built-in checks."""

from __future__ import annotations

from .checks.base import Check
from .checks.boot import SecureBootCheck
from .checks.browser_permissions import BrowserProfilePermissionsCheck
from .checks.browser_extensions import BrowserExtensionPermissionsCheck
from .checks.browser_processes import BrowserProcessFlagsCheck
from .checks.filesystem import SudoersDropInPermissionsCheck, SudoersPermissionsCheck
from .checks.firewall import FirewallServiceCheck
from .checks.firefox_preferences import FirefoxDangerousPreferencesCheck
from .checks.listeners import WildcardListenersCheck
from .checks.kernel import KernelHardeningCheck
from .checks.packages import PendingPackageUpdatesCheck
from .checks.package_trust import PacmanSignaturePolicyCheck
from .checks.ssh import SshAuthenticationCheck
from .checks.storage import RootFilesystemEncryptionCheck
from .checks.vulnerabilities import ArchAuditCheck


def builtin_checks() -> list[Check]:
    return [
        BrowserProfilePermissionsCheck(),
        BrowserExtensionPermissionsCheck(),
        BrowserProcessFlagsCheck(),
        FirefoxDangerousPreferencesCheck(),
        PendingPackageUpdatesCheck(),
        PacmanSignaturePolicyCheck(),
        ArchAuditCheck(),
        FirewallServiceCheck(),
        WildcardListenersCheck(),
        SshAuthenticationCheck(),
        RootFilesystemEncryptionCheck(),
        SecureBootCheck(),
        KernelHardeningCheck(),
        SudoersPermissionsCheck(),
        SudoersDropInPermissionsCheck(),
    ]
