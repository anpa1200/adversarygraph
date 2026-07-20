#!/usr/bin/env python3
"""Verify that GitHub rulesets make one release tag update/delete immutable."""

from __future__ import annotations

import fnmatch
import json
import sys
from functools import lru_cache
from pathlib import Path
from typing import Any


def _github_fnmatch(pattern: str, ref_name: str) -> bool:
    """Match GitHub ruleset refs with Ruby File::FNM_PATHNAME semantics.

    A single path-segment wildcard must never cross ``/``. A ``**`` segment is
    recursive only when another pattern segment follows it, matching GitHub's
    documented ``qa/**/*`` behavior. Unsupported GitHub quoting/complement
    syntax is rejected rather than risking a false-positive protection result.
    """
    if "\\" in pattern or "[^" in pattern:
        return False

    pattern_parts = pattern.split("/")
    ref_parts = ref_name.split("/")

    @lru_cache(maxsize=None)
    def matches(pattern_index: int, ref_index: int) -> bool:
        if pattern_index == len(pattern_parts):
            return ref_index == len(ref_parts)

        part = pattern_parts[pattern_index]
        if part == "**" and pattern_index < len(pattern_parts) - 1:
            return matches(pattern_index + 1, ref_index) or (
                ref_index < len(ref_parts) and matches(pattern_index, ref_index + 1)
            )

        return (
            ref_index < len(ref_parts)
            and fnmatch.fnmatchcase(ref_parts[ref_index], part)
            and matches(pattern_index + 1, ref_index + 1)
        )

    return matches(0, 0)


def _matches_ref(ruleset: dict[str, Any], ref_name: str) -> bool:
    conditions = ruleset.get("conditions") or {}
    ref_condition = conditions.get("ref_name") or {}
    includes = ref_condition.get("include") or []
    excludes = ref_condition.get("exclude") or []

    def matches(pattern: object) -> bool:
        return isinstance(pattern, str) and (
            pattern == "~ALL" or _github_fnmatch(pattern, ref_name)
        )

    return any(matches(pattern) for pattern in includes) and not any(
        matches(pattern) for pattern in excludes
    )


def main() -> int:
    if len(sys.argv) < 3:
        print(
            "Usage: verify-release-tag-rulesets.py REF RULESET_JSON [RULESET_JSON ...]",
            file=sys.stderr,
        )
        return 2

    ref_name = sys.argv[1]
    required = {"update", "deletion"}
    enforced: set[str] = set()
    accepted_names: list[str] = []

    for raw_path in sys.argv[2:]:
        path = Path(raw_path)
        try:
            ruleset = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"Could not read ruleset {path}: {exc}", file=sys.stderr)
            return 2

        if ruleset.get("target") != "tag" or ruleset.get("enforcement") != "active":
            continue
        if not _matches_ref(ruleset, ref_name):
            continue
        bypass_actors = ruleset.get("bypass_actors")
        if not isinstance(bypass_actors, list) or bypass_actors:
            continue

        rule_types = {
            rule.get("type")
            for rule in ruleset.get("rules") or []
            if isinstance(rule, dict)
        }
        covered = required & rule_types
        if covered:
            enforced.update(covered)
            accepted_names.append(str(ruleset.get("name") or ruleset.get("id") or path.name))

    missing = sorted(required - enforced)
    if missing:
        print(
            f"No active no-bypass ruleset coverage protects {ref_name} from: "
            f"{', '.join(missing)}.",
            file=sys.stderr,
        )
        return 1

    print(
        f"Release tag ruleset protection passed for {ref_name}: "
        f"{', '.join(dict.fromkeys(accepted_names))}."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
