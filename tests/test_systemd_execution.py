import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scanit.checks.systemd_execution import SystemdExecutionPathCheck
from scanit.commands import CommandResult
from scanit.context import ScanContext
from scanit.models import Status


class FakeCommands:
    def __init__(self, results):
        self.results = iter(results)
        self.commands = []

    def run(self, command, timeout=10):
        self.commands.append((tuple(command), timeout))
        return next(self.results)


class SystemdExecutionPathTests(unittest.TestCase):
    active = CommandResult(0, "demo.service loaded active running Demo")
    enabled = CommandResult(0, "")

    def run_check(self, shown, *, active=None, enabled=None, unsafe=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = root / "usr/bin/demo"
            executable.parent.mkdir(parents=True)
            executable.write_text("#!/bin/sh\n")
            executable.chmod(0o755)
            commands = FakeCommands([
                active or self.active,
                enabled or self.enabled,
                shown,
            ])
            context = ScanContext(Path("/home/test"), root, commands)
            predicate = unsafe or (lambda info: False)
            with patch(
                "scanit.checks.systemd_execution.unsafe_privileged_metadata",
                side_effect=predicate,
            ):
                finding = SystemdExecutionPathCheck().run(context)[0]
            return finding, commands

    def test_protected_root_service_passes(self):
        finding, commands = self.run_check(CommandResult(0, (
            "Id=demo.service\nUser=\nDynamicUser=no\n"
            "ExecStart={ path=/usr/bin/demo ; argv[]=/usr/bin/demo ; ignore_errors=no }\n"
        )))
        self.assertIs(finding.status, Status.PASS)
        self.assertIn("demo.service", commands.commands[2][0])

    def test_unsafe_root_service_path_fails(self):
        finding, _ = self.run_check(
            CommandResult(0, (
                "Id=demo.service\nUser=root\nDynamicUser=no\n"
                "ExecStart={ path=/usr/bin/demo ; argv[]=/usr/bin/demo ; ignore_errors=no }\n"
            )),
            unsafe=lambda info: stat.S_IMODE(info.st_mode) == 0o755,
        )
        self.assertIs(finding.status, Status.FAIL)
        self.assertIn("privileged", finding.evidence[0])

    def test_unsafe_non_root_service_path_requires_review(self):
        finding, _ = self.run_check(
            CommandResult(0, (
                "Id=demo.service\nUser=demo\nDynamicUser=no\n"
                "ExecStart={ path=/usr/bin/demo ; argv[]=/usr/bin/demo ; ignore_errors=no }\n"
            )),
            unsafe=lambda info: stat.S_IMODE(info.st_mode) == 0o755,
        )
        self.assertIs(finding.status, Status.REVIEW)
        self.assertIn("user=demo", finding.evidence[0])

    def test_missing_executable_is_unknown(self):
        finding, _ = self.run_check(CommandResult(0, (
            "Id=demo.service\nUser=\nDynamicUser=no\n"
            "ExecStart={ path=/missing/demo ; argv[]=/missing/demo ; ignore_errors=no }\n"
        )))
        self.assertIs(finding.status, Status.UNKNOWN)

    def test_simple_executable_name_uses_systemd_search_path(self):
        finding, _ = self.run_check(CommandResult(0, (
            "Id=demo.service\nUser=\nDynamicUser=no\n"
            "ExecStart={ path=demo ; argv[]=demo ; ignore_errors=no }\n"
        )))
        self.assertIs(finding.status, Status.PASS)

    def test_path_like_command_argument_is_not_an_execution_target(self):
        finding, _ = self.run_check(CommandResult(0, (
            "Id=demo.service\nUser=\nDynamicUser=no\n"
            "ExecStart={ path=/usr/bin/demo ; argv[]=/usr/bin/demo "
            "--storage.path=/missing/data ; ignore_errors=no }\n"
        )))
        self.assertIs(finding.status, Status.PASS)

    def test_repeated_execution_properties_are_all_inspected(self):
        finding, _ = self.run_check(CommandResult(0, (
            "Id=demo.service\nUser=root\nDynamicUser=no\n"
            "ExecStart={ path=/missing/first ; argv[]=/missing/first ; ignore_errors=no }\n"
            "ExecStart={ path=/usr/bin/demo ; argv[]=/usr/bin/demo ; ignore_errors=no }\n"
        )))
        self.assertIs(finding.status, Status.UNKNOWN)
        self.assertTrue(any("/missing/first" in item for item in finding.evidence))

    def test_extended_privilege_flag_overrides_non_root_service_user(self):
        finding, _ = self.run_check(
            CommandResult(0, (
                "Id=demo.service\nUser=demo\nDynamicUser=no\n"
                "ExecStart={ path=/usr/bin/demo ; argv[]=/usr/bin/demo ; ignore_errors=no }\n"
                "ExecStartEx={ path=/usr/bin/demo ; argv[]=/usr/bin/demo ; flags=privileged ; "
                "start_time=[n/a] }\n"
            )),
            unsafe=lambda info: stat.S_IMODE(info.st_mode) == 0o755,
        )
        self.assertIs(finding.status, Status.FAIL)
        self.assertIn("privileged", finding.evidence[0])

    def test_extended_properties_do_not_duplicate_legacy_entries(self):
        finding, _ = self.run_check(CommandResult(0, (
            "Id=demo.service\nUser=root\nDynamicUser=no\n"
            "ExecStart={ path=/missing/legacy ; argv[]=/missing/legacy ; ignore_errors=no }\n"
            "ExecStartEx={ path=/usr/bin/demo ; argv[]=/usr/bin/demo ; flags= ; start_time=[n/a] }\n"
        )))
        self.assertIs(finding.status, Status.PASS)

    def test_missing_systemctl_is_unknown(self):
        commands = FakeCommands([CommandResult(127, "missing"), CommandResult(127, "missing")])
        context = ScanContext(Path("/home/test"), Path("/"), commands)
        finding = SystemdExecutionPathCheck().run(context)[0]
        self.assertIs(finding.status, Status.UNKNOWN)

    def test_no_services_is_not_applicable(self):
        commands = FakeCommands([CommandResult(0, ""), CommandResult(0, "")])
        context = ScanContext(Path("/home/test"), Path("/"), commands)
        finding = SystemdExecutionPathCheck().run(context)[0]
        self.assertIs(finding.status, Status.NOT_APPLICABLE)

    def test_template_units_are_not_queried_without_an_instance(self):
        finding, commands = self.run_check(
            CommandResult(0, (
                "Id=demo.service\nUser=\nDynamicUser=no\n"
                "ExecStart={ path=/usr/bin/demo ; argv[]=/usr/bin/demo ; ignore_errors=no }\n"
            )),
            active=CommandResult(0, "demo.service loaded active running Demo"),
            enabled=CommandResult(0, "getty@.service enabled\ndemo.service enabled\n"),
        )
        self.assertIs(finding.status, Status.PASS)
        self.assertNotIn("getty@.service", commands.commands[2][0])

    def test_partial_service_inventory_preserves_unknown(self):
        finding, _ = self.run_check(
            CommandResult(0, (
                "Id=demo.service\nUser=\nDynamicUser=no\n"
                "ExecStart={ path=/usr/bin/demo ; argv[]=/usr/bin/demo ; ignore_errors=no }\n"
            )),
            active=CommandResult(1, "bus unavailable"),
            enabled=CommandResult(0, "demo.service enabled\n"),
        )
        self.assertIs(finding.status, Status.UNKNOWN)


if __name__ == "__main__":
    unittest.main()
