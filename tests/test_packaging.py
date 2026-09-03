import pathlib
import tomllib
import unittest

from scanit import __version__


class PackagingMetadataTests(unittest.TestCase):
    def test_package_and_runtime_versions_match(self):
        project_root = pathlib.Path(__file__).resolve().parents[1]
        metadata = tomllib.loads(
            (project_root / "pyproject.toml").read_text(encoding="utf-8")
        )

        self.assertEqual(metadata["project"]["version"], __version__)


if __name__ == "__main__":
    unittest.main()
