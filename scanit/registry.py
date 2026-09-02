"""Central registry for built-in checks."""

from __future__ import annotations

from .checks.base import Check
from .checks.accounts import EmptyPasswordsCheck, HomeDirectoryPermissionsCheck, UidZeroAccountsCheck
from .checks.boot import SecureBootCheck
from .checks.browser_permissions import BrowserProfilePermissionsCheck
from .checks.browser_extensions import BrowserExtensionPermissionsCheck
from .checks.browser_processes import BrowserProcessFlagsCheck
from .checks.filesystem import SudoersDropInPermissionsCheck, SudoersPermissionsCheck, SystemdUnitPermissionsCheck
from .checks.firewall import FirewallServiceCheck
from .checks.firefox_preferences import FirefoxDangerousPreferencesCheck, FirefoxHttpsOnlyCheck
from .checks.listeners import WildcardListenersCheck
from .checks.kernel import KernelHardeningCheck
from .checks.network import IpForwardingCheck, NetworkHardeningCheck
from .checks.packages import ForeignPackagesCheck, PacmanDatabaseFreshnessCheck, PendingPackageUpdatesCheck
from .checks.package_trust import PacmanSignaturePolicyCheck
from .checks.ssh import SshAuthenticationCheck
from .checks.ssh_keys import SshAuthorizationPathPermissionsCheck, SshHostKeyPermissionsCheck, SshPrivateKeyPermissionsCheck
from .checks.security_modules import LinuxSecurityModulesCheck
from .checks.storage import RootFilesystemEncryptionCheck
from .checks.systemd_services import SystemdDebugShellCheck
from .checks.sudo_policy import SudoPasswordlessRulesCheck
from .checks.time_sync import NtpSynchronizationCheck
from .checks.vulnerabilities import ArchAuditCheck


def builtin_checks() -> list[Check]:
    return [
        BrowserProfilePermissionsCheck(),
        BrowserExtensionPermissionsCheck(),
        BrowserProcessFlagsCheck(),
        FirefoxDangerousPreferencesCheck(),
        FirefoxHttpsOnlyCheck(),
        PendingPackageUpdatesCheck(),
        PacmanDatabaseFreshnessCheck(),
        ForeignPackagesCheck(),
        NtpSynchronizationCheck(),
        PacmanSignaturePolicyCheck(),
        ArchAuditCheck(),
        FirewallServiceCheck(),
        WildcardListenersCheck(),
        IpForwardingCheck(),
        NetworkHardeningCheck(),
        SshAuthenticationCheck(),
        SshHostKeyPermissionsCheck(),
        SshPrivateKeyPermissionsCheck(),
        SshAuthorizationPathPermissionsCheck(),
        RootFilesystemEncryptionCheck(),
        SecureBootCheck(),
        KernelHardeningCheck(),
        LinuxSecurityModulesCheck(),
        UidZeroAccountsCheck(),
        HomeDirectoryPermissionsCheck(),
        EmptyPasswordsCheck(),
        SudoersPermissionsCheck(),
        SudoersDropInPermissionsCheck(),
        SudoPasswordlessRulesCheck(),
        SystemdUnitPermissionsCheck(),
        SystemdDebugShellCheck(),
    ]
