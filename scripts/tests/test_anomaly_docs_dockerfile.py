from __future__ import annotations

import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SITE = ROOT / "anomaly_detection" / "docs-site"
TAR_VERSION = "7.5.22"
TAR_INTEGRITY = (
    "sha512-MFO/QzvtAOmJbkhOaCTvbGcFN9L9b+JunIsDwaKljSOdcLMea3NJ1k9Usz/"
    "rjdfSXTq4dfzfeS7W4p4YOAAHeA=="
)


class AnomalyDocsDockerfileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.dockerfile = (SITE / "Dockerfile").read_text(encoding="utf-8")
        cls.package = json.loads((SITE / "package.json").read_text(encoding="utf-8"))
        cls.lock = json.loads((SITE / "package-lock.json").read_text(encoding="utf-8"))

    def test_docs_tree_lockfile_pins_remediated_tar(self) -> None:
        self.assertEqual(self.package["dependencies"]["tar"], TAR_VERSION)
        self.assertEqual(self.package["overrides"]["tar"], "$tar")
        self.assertEqual(self.lock["packages"][""]["dependencies"]["tar"], TAR_VERSION)
        locked = self.lock["packages"]["node_modules/tar"]
        self.assertEqual(locked["version"], TAR_VERSION)
        self.assertEqual(locked["integrity"], TAR_INTEGRITY)

    def test_image_installs_integrity_checked_npm_and_verifies_bundled_tar(self) -> None:
        for expected in (
            "https://registry.npmjs.org/npm/-/npm-12.2.0.tgz",
            "sha512sum -c -",
            "$(npm --version)",
            "require('/usr/local/lib/node_modules/npm/node_modules/tar/package.json')",
            f"s.gte(p.version, '{TAR_VERSION}')",
            "RUN npm run build",
        ):
            self.assertIn(expected, self.dockerfile)
        self.assertLess(self.dockerfile.index("sha512sum -c -"), self.dockerfile.index("RUN npm run build"))


if __name__ == "__main__":
    unittest.main()
