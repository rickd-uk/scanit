import subprocess
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from scanit.commands import LocalCommandExecutor


class LocalCommandExecutorTests(unittest.TestCase):
    def test_resolves_from_trusted_path_and_sets_stable_locale(self):
        completed = SimpleNamespace(returncode=0, stdout=" output \n")
        with patch("scanit.commands.shutil.which", return_value="/usr/bin/tool") as which:
            with patch("scanit.commands.subprocess.run", return_value=completed) as run:
                result = LocalCommandExecutor().run(("tool", "--status"), timeout=3)
        which.assert_called_once_with("tool", path=LocalCommandExecutor.trusted_path)
        arguments, options = run.call_args
        self.assertEqual(arguments[0], ["/usr/bin/tool", "--status"])
        self.assertEqual(options["env"]["PATH"], LocalCommandExecutor.trusted_path)
        self.assertEqual(options["env"]["LC_ALL"], "C")
        self.assertEqual(result.stdout, "output")

    def test_missing_trusted_command_returns_127(self):
        with patch("scanit.commands.shutil.which", return_value=None):
            result = LocalCommandExecutor().run(("missing",))
        self.assertEqual(result.returncode, 127)

    def test_empty_command_returns_127(self):
        self.assertEqual(LocalCommandExecutor().run(()).returncode, 127)

    def test_timeout_is_reported_without_raising(self):
        timeout = subprocess.TimeoutExpired(["/usr/bin/tool"], 1, output="partial")
        with patch("scanit.commands.shutil.which", return_value="/usr/bin/tool"):
            with patch("scanit.commands.subprocess.run", side_effect=timeout):
                result = LocalCommandExecutor().run(("tool",), timeout=1)
        self.assertEqual(result.returncode, 124)
        self.assertIn("timed out", result.stdout)


if __name__ == "__main__":
    unittest.main()
