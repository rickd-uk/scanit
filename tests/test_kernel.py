import tempfile
import unittest
from pathlib import Path

from scanit.checks.kernel import CONTROLS, KernelHardeningCheck
from scanit.context import ScanContext
from scanit.models import Status


class KernelHardeningTests(unittest.TestCase):
    def evaluate(self, value=None):
        control = CONTROLS[0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            if value is not None:
                path = root / "proc/sys" / control.key.replace(".", "/")
                path.parent.mkdir(parents=True)
                path.write_text(value)
            context = ScanContext(home=Path("/home/test"), root=root, commands=None)
            return KernelHardeningCheck._evaluate(context, control)

    def test_safe_value_passes(self):
        self.assertIs(self.evaluate("2\n").status, Status.PASS)

    def test_weak_value_fails(self):
        self.assertIs(self.evaluate("1\n").status, Status.FAIL)

    def test_missing_control_is_not_applicable(self):
        self.assertIs(self.evaluate().status, Status.NOT_APPLICABLE)

    def test_invalid_value_is_error(self):
        self.assertIs(self.evaluate("enabled\n").status, Status.ERROR)


if __name__ == "__main__":
    unittest.main()
