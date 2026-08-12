from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


MODULE_PATH = Path(__file__).resolve().parents[1] / "verify-release-tag-rulesets.py"
SPEC = importlib.util.spec_from_file_location("verify_release_tag_rulesets", MODULE_PATH)
if SPEC is None or SPEC.loader is None:  # pragma: no cover - import setup guard
    raise RuntimeError(f"Could not load {MODULE_PATH}")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class GitHubFnmatchTests(unittest.TestCase):
    def test_single_star_does_not_cross_ref_segments(self) -> None:
        self.assertTrue(MODULE._github_fnmatch("refs/tags/v*", "refs/tags/v6.0.0"))
        self.assertFalse(MODULE._github_fnmatch("refs/*", "refs/tags/v6.0.0"))

    def test_recursive_globstar_crosses_ref_segments(self) -> None:
        self.assertTrue(MODULE._github_fnmatch("refs/**/v*", "refs/tags/v6.0.0"))
        self.assertTrue(MODULE._github_fnmatch("qa/**/*", "qa/foo/bar"))

    def test_trailing_double_star_is_one_segment(self) -> None:
        self.assertTrue(MODULE._github_fnmatch("refs/**", "refs/tags"))
        self.assertFalse(MODULE._github_fnmatch("refs/**", "refs/tags/v6.0.0"))

    def test_supported_character_set(self) -> None:
        self.assertTrue(
            MODULE._github_fnmatch("refs/tags/v[0-9]*", "refs/tags/v6.0.0")
        )

    def test_unsupported_syntax_fails_closed(self) -> None:
        self.assertFalse(
            MODULE._github_fnmatch("refs/tags/v[^x]*", "refs/tags/v6.0.0")
        )
        self.assertFalse(
            MODULE._github_fnmatch(r"refs/tags/v\*", "refs/tags/v6.0.0")
        )


class RulesetConditionTests(unittest.TestCase):
    def test_broad_single_star_does_not_false_positive(self) -> None:
        ruleset = {
            "conditions": {"ref_name": {"include": ["refs/*"], "exclude": []}}
        }
        self.assertFalse(MODULE._matches_ref(ruleset, "refs/tags/v6.0.0"))


class RulesetVerificationTests(unittest.TestCase):
    def _run(self, ruleset: dict[str, object]) -> int:
        with tempfile.TemporaryDirectory() as temp_dir:
            ruleset_path = Path(temp_dir) / "ruleset.json"
            ruleset_path.write_text(json.dumps(ruleset), encoding="utf-8")
            with patch.object(
                MODULE.sys,
                "argv",
                [
                    "verify-release-tag-rulesets.py",
                    "refs/tags/v7.0.0",
                    str(ruleset_path),
                ],
            ):
                return MODULE.main()

    @staticmethod
    def _ruleset(**extra: object) -> dict[str, object]:
        ruleset: dict[str, object] = {
            "id": 20758501,
            "name": "Immutable release tags",
            "target": "tag",
            "enforcement": "active",
            "conditions": {
                "ref_name": {"include": ["refs/tags/v*"], "exclude": []}
            },
            "rules": [{"type": "deletion"}, {"type": "update"}],
        }
        ruleset.update(extra)
        return ruleset

    def test_accepts_explicit_empty_bypass_list(self) -> None:
        self.assertEqual(self._run(self._ruleset(bypass_actors=[])), 0)

    def test_accepts_redacted_list_when_principal_can_never_bypass(self) -> None:
        self.assertEqual(
            self._run(self._ruleset(current_user_can_bypass="never")),
            0,
        )

    def test_rejects_redacted_list_without_never_attestation(self) -> None:
        self.assertEqual(self._run(self._ruleset()), 1)

    def test_rejects_any_explicit_bypass_actor(self) -> None:
        self.assertEqual(
            self._run(
                self._ruleset(
                    bypass_actors=[
                        {
                            "actor_id": 5,
                            "actor_type": "RepositoryRole",
                            "bypass_mode": "always",
                        }
                    ]
                )
            ),
            1,
        )

    def test_matching_exclusion_wins(self) -> None:
        ruleset = {
            "conditions": {
                "ref_name": {
                    "include": ["~ALL"],
                    "exclude": ["refs/tags/v6.*"],
                }
            }
        }
        self.assertFalse(MODULE._matches_ref(ruleset, "refs/tags/v6.0.0"))


if __name__ == "__main__":
    unittest.main()
