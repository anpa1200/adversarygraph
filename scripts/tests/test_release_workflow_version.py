from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "release.yml"


def _resolve_version_script() -> str:
    text = WORKFLOW_PATH.read_text(encoding="utf-8")
    marker = "      - name: Resolve release version\n"
    start = text.index(marker) + len(marker)
    end = text.index("\n      - name:", start)
    block = text[start:end]
    run_marker = "        run: |\n"
    run_start = block.index(run_marker) + len(run_marker)
    lines = block[run_start:].splitlines()
    return "\n".join(
        line[10:] if line.startswith("          ") else line for line in lines
    )


class ReleaseWorkflowVersionTests(unittest.TestCase):
    def _run(self, version: str, tag: str) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "VERSION").write_text(f"{version}\n", encoding="utf-8")
            output_path = root / "github-output"
            env = {
                **os.environ,
                "GITHUB_OUTPUT": str(output_path),
                "GITHUB_REF_TYPE": "tag",
                "GITHUB_REF_NAME": tag,
            }
            result = subprocess.run(
                ["bash", "-c", _resolve_version_script()],
                cwd=root,
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
            result.github_output = (  # type: ignore[attr-defined]
                output_path.read_text(encoding="utf-8") if output_path.exists() else ""
            )
            return result

    def test_numbered_beta_is_a_prerelease(self) -> None:
        result = self._run("8.0.0-beta.1", "v8.0.0-beta.1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("version=8.0.0-beta.1", result.github_output)  # type: ignore[attr-defined]
        self.assertIn("tag=v8.0.0-beta.1", result.github_output)  # type: ignore[attr-defined]
        self.assertIn("prerelease=true", result.github_output)  # type: ignore[attr-defined]

    def test_stable_version_is_not_a_prerelease(self) -> None:
        result = self._run("8.0.0", "v8.0.0")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("prerelease=false", result.github_output)  # type: ignore[attr-defined]

    def test_unversioned_beta_is_rejected(self) -> None:
        result = self._run("8.0.0-beta", "v8.0.0-beta")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("X.Y.Z-beta.N", result.stderr)

    def test_tag_must_match_version_exactly(self) -> None:
        result = self._run("8.0.0-beta.1", "v8.0.0")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not match VERSION", result.stderr)

    def test_release_publication_preserves_prerelease_metadata(self) -> None:
        workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
        self.assertIn("release_args+=(--prerelease)", workflow)
        self.assertEqual(
            workflow.count('"$is_prerelease" != "$RELEASE_PRERELEASE"'),
            2,
        )


if __name__ == "__main__":
    unittest.main()
