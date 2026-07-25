#!/usr/bin/env python3
"""Fail when the governed module catalog and module reference diverge."""

from __future__ import annotations

import ast
import re
import sys
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CATALOG_PATH = ROOT / "backend/app/services/auth.py"
REFERENCE_PATH = ROOT / "docs/module-reference.md"
MARKER = re.compile(r"<!--\s*module:([a-z0-9_]+)\s*-->")


def catalog_modules() -> set[str]:
    tree = ast.parse(CATALOG_PATH.read_text(encoding="utf-8"), filename=str(CATALOG_PATH))
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        if not any(isinstance(target, ast.Name) and target.id == "MODULE_CATALOG" for target in node.targets):
            continue
        if not isinstance(node.value, ast.Dict):
            break
        keys: set[str] = set()
        for key in node.value.keys:
            if not isinstance(key, ast.Constant) or not isinstance(key.value, str):
                raise ValueError("MODULE_CATALOG keys must be string literals")
            keys.add(key.value)
        return keys
    raise ValueError(f"Unable to find literal MODULE_CATALOG in {CATALOG_PATH}")


def main() -> int:
    catalog = catalog_modules()
    markers = MARKER.findall(REFERENCE_PATH.read_text(encoding="utf-8"))
    counts = Counter(markers)
    documented = set(markers)

    failures: list[str] = []
    missing = sorted(catalog - documented)
    unknown = sorted(documented - catalog)
    duplicates = sorted(module for module, count in counts.items() if count != 1)

    if missing:
        failures.append(f"Missing module documentation markers: {', '.join(missing)}")
    if unknown:
        failures.append(f"Unknown module documentation markers: {', '.join(unknown)}")
    if duplicates:
        failures.append(f"Module markers must appear exactly once: {', '.join(duplicates)}")

    if failures:
        for failure in failures:
            print(f"ERROR: {failure}", file=sys.stderr)
        return 1

    print(f"Module reference covers all {len(catalog)} governed modules exactly once.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
