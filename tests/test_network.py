import tempfile
import unittest
from pathlib import Path

from scanit.checks.network import IpForwardingCheck, NetworkHardeningCheck
from scanit.context import ScanContext
from scanit.models import Status


class IpForwardingTests(unittest.TestCase):
    def run_check(self, ipv4=None, ipv6=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for relative_path, value in (
                ("proc/sys/net/ipv4/ip_forward", ipv4),
                ("proc/sys/net/ipv6/conf/all/forwarding", ipv6),
            ):
                if value is not None:
                    path = root / relative_path
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text(value)
            return IpForwardingCheck().run(
                ScanContext(home=Path("/home/test"), root=root, commands=None)
            )[0]

    def test_disabled_forwarding_passes(self):
        self.assertIs(self.run_check("0", "0").status, Status.PASS)

    def test_enabled_forwarding_requires_role_review(self):
        finding = self.run_check("1", "0")
        self.assertIs(finding.status, Status.REVIEW)
        self.assertEqual(finding.title, "IP forwarding is enabled")

    def test_no_controls_is_not_applicable(self):
        self.assertIs(self.run_check().status, Status.NOT_APPLICABLE)

    def test_invalid_control_is_an_error(self):
        self.assertIs(self.run_check("enabled").status, Status.ERROR)


if __name__ == "__main__":
    unittest.main()


class NetworkHardeningTests(unittest.TestCase):
    def run_check(self, values):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for relative_path, value in values.items():
                path = root / relative_path
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(value)
            return NetworkHardeningCheck().run(
                ScanContext(home=Path("/home/test"), root=root, commands=None)
            )

    def test_hardened_controls_pass(self):
        findings = self.run_check({
            "proc/sys/net/ipv4/conf/all/accept_redirects": "0",
            "proc/sys/net/ipv4/conf/all/send_redirects": "0",
            "proc/sys/net/ipv4/conf/all/rp_filter": "2",
            "proc/sys/net/ipv6/conf/all/accept_redirects": "0",
        })
        self.assertTrue(all(finding.status is Status.PASS for finding in findings))

    def test_enabled_redirect_acceptance_requires_review(self):
        findings = self.run_check({"proc/sys/net/ipv4/conf/all/accept_redirects": "1"})
        self.assertIs(findings[0].status, Status.REVIEW)

    def test_unavailable_control_is_not_applicable(self):
        self.assertTrue(all(finding.status is Status.NOT_APPLICABLE for finding in self.run_check({})))

    def test_invalid_value_is_an_error(self):
        findings = self.run_check({"proc/sys/net/ipv4/conf/all/rp_filter": "enabled"})
        self.assertIs(findings[2].status, Status.ERROR)
