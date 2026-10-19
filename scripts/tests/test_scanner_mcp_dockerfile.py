from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DOCKERFILE = ROOT / "scanner_mcp" / "Dockerfile"


class ScannerMcpDockerfileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = DOCKERFILE.read_text(encoding="utf-8")

    def test_nuclei_builder_uses_remediated_go_base(self) -> None:
        self.assertIn(
            "FROM golang:1.26.9-alpine@sha256:"
            "3082400e369fa24d5fc60bca20edab3f6d604e0c5a690ec66b295eff4dd87ade "
            "AS nuclei",
            self.text,
        )
        self.assertNotIn("golang:1.26.5-alpine", self.text)
        self.assertIn(
            'test "$(go version /out/nuclei)" = "/out/nuclei: go1.26.9"',
            self.text,
        )

    def test_nuclei_binary_pins_and_verifies_remediated_x_mod(self) -> None:
        argument = "ARG NUCLEI_X_MOD_VERSION=v0.41.0"
        dependency_get = 'go get "golang.org/x/mod@${NUCLEI_X_MOD_VERSION}"'
        tidy = "go mod tidy"
        artifact_check = "go version -m /out/nuclei"

        for expected in (argument, dependency_get, artifact_check):
            self.assertIn(expected, self.text)
        self.assertLess(self.text.index(dependency_get), self.text.index(tidy))
        self.assertIn(
            "$'\\tdep\\tgolang.org/x/mod\\t'\"${NUCLEI_X_MOD_VERSION}\"$'\\t'",
            self.text,
        )

    def test_nuclei_binary_pins_and_verifies_resolved_x_text(self) -> None:
        argument = "ARG NUCLEI_X_TEXT_VERSION=v0.42.0"
        dependency_get = 'go get "golang.org/x/text@${NUCLEI_X_TEXT_VERSION}"'

        self.assertIn(argument, self.text)
        self.assertIn(dependency_get, self.text)
        self.assertIn(
            "$'\\tdep\\tgolang.org/x/text\\t'\"${NUCLEI_X_TEXT_VERSION}\"$'\\t'",
            self.text,
        )

    def test_nuclei_binary_pins_remediated_grpc(self) -> None:
        self.assertIn("ARG NUCLEI_GRPC_VERSION=v1.84.0", self.text)
        self.assertIn('go get "google.golang.org/grpc@${NUCLEI_GRPC_VERSION}"', self.text)
        self.assertIn('google.golang.org/grpc', self.text.split('go version -m /out/nuclei')[-1])


if __name__ == "__main__":
    unittest.main()
