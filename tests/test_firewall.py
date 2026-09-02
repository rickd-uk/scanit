import unittest
from pathlib import Path

from scanit.checks.firewall import FirewallServiceCheck
from scanit.commands import CommandResult
from scanit.context import ScanContext
from scanit.models import Status


class FakeCommands:
    def __init__(self, responses):
        self.responses = responses

    def run(self, command, timeout=10):
        return self.responses[command[-1]]


class FirewallServiceTests(unittest.TestCase):
    def run_check(self, responses):
        context = ScanContext(home=Path("/home/test"), root=Path("/"), commands=FakeCommands(responses))
        return FirewallServiceCheck().run(context)[0]

    def test_active_service_passes(self):
        finding = self.run_check({
            "nftables.service": CommandResult(3, "inactive"),
            "firewalld.service": CommandResult(0, "active"),
            "ufw.service": CommandResult(4, "not-found"),
        })
        self.assertIs(finding.status, Status.PASS)
        self.assertEqual(finding.evidence, ("firewalld.service: active",))

    def test_inactive_services_fail(self):
        finding = self.run_check({service: CommandResult(3, "inactive") for service in FirewallServiceCheck.services})
        self.assertIs(finding.status, Status.FAIL)

    def test_no_systemctl_result_is_unknown(self):
        finding = self.run_check({service: CommandResult(127, "systemctl unavailable") for service in FirewallServiceCheck.services})
        self.assertIs(finding.status, Status.UNKNOWN)


if __name__ == "__main__":
    unittest.main()
