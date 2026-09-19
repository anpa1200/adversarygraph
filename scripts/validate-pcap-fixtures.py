#!/usr/bin/env python3
"""Run deterministic regression checks against opt-in PCAP fixtures.

Large/malicious captures are intentionally not committed to the repository.
Pass their local paths explicitly; the validator checks immutable capture facts,
required behavior rules, result integrity, and optional repeatability.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from pcap_analyzer.app import _PCAP_MAGICS, analyze_capture  # noqa: E402


FIXTURES = {
    "2025-01-22-traffic-analysis-exercise.pcap": {
        "sha256": "e59db1c07c6fdefafa0abdbca03248c341cdc36c09c34753204d3162802a3586",
        "packets": 39427,
        "required_rules": {"script-or-executable-transfer", "periodic-http-callbacks"},
    },
    "2025-06-13-traffic-analysis-exercise.pcap": {
        "sha256": "33e274d7246f4eca8fbe7337c465c7ded077cd650d5d4d42481cad822c962741",
        "packets": 48877,
        "required_rules": {"powershell-http-client", "distributed-periodic-http-posts", "high-volume-http-posts"},
    },
    "2026-01-31-traffic-analysis-exercise.pcap": {
        "sha256": "f755444d0b6eac847e07b73dea0774084b232d8577f536547a12f39b959d7833",
        "packets": 51181,
        "required_rules": {"cleartext-tokenized-api", "browser-fingerprint-upload"},
    },
    "2026-02-28-traffic-analysis-exercise.pcap": {
        "sha256": "3dc470f5490ec15b4024c513e87c67e0b17caeae2a2ce3d83541be24ef407e61",
        "packets": 15512,
        "required_rules": {"http-on-tls-port", "periodic-http-callbacks", "remote-access-user-agent"},
    },
    "2026-08-09-traffic-analysis-exercise.pcap": {
        "sha256": "0ea6b597732a9ce6af9a7e3adff4512c9a91b4bce27184c8fdeb746f05cce170",
        "packets": 22473,
        "required_rules": {"repeated-http-posts", "high-volume-http-posts"},
    },
    "2026-09-11-traffic-analysis-exercise.pcap": {
        "sha256": "21bb800849459709a7ceb5513573b2b20f090ffccd00eb89b9886feedd47a2df",
        "packets": 73779,
        "required_rules": {"large-http-post", "high-volume-http-posts"},
    },
}


def _digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _run(path: Path, source_sha256: str) -> tuple[dict, float]:
    with path.open("rb") as source:
        magic = source.read(4)
    capture_format = _PCAP_MAGICS.get(magic)
    if capture_format is None:
        raise ValueError("not a recognized PCAP/PCAPNG capture")
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="ag-pcap-fixture-") as scratch:
        result = analyze_capture(
            path,
            source_sha256=source_sha256,
            source_size_bytes=path.stat().st_size,
            filename=path.name,
            capture_format=capture_format,
            scratch=Path(scratch),
        )
    return result, time.monotonic() - started


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("captures", nargs="+", type=Path)
    parser.add_argument("--repeat", action="store_true", help="analyze each capture twice and compare semantic hashes")
    args = parser.parse_args()
    failures: list[str] = []
    summaries: list[dict] = []
    for path in args.captures:
        spec = FIXTURES.get(path.name)
        if spec is None:
            failures.append(f"{path}: no checked-in fixture contract")
            continue
        source_sha256 = _digest(path)
        if source_sha256 != spec["sha256"]:
            failures.append(f"{path.name}: source SHA-256 mismatch")
            continue
        try:
            result, elapsed = _run(path, source_sha256)
        except Exception as exc:  # fixture CLI must report a per-file failure
            failures.append(f"{path.name}: {type(exc).__name__}: {exc}")
            continue
        actual_rules = {item["rule_id"] for item in result["findings"]}
        missing_rules = sorted(spec["required_rules"] - actual_rules)
        if result["capture"]["packet_count"] != spec["packets"]:
            failures.append(f"{path.name}: packet-count regression")
        if result["capture"]["source_sha256"] != source_sha256:
            failures.append(f"{path.name}: result source digest mismatch")
        if missing_rules:
            failures.append(f"{path.name}: missing required rules: {', '.join(missing_rules)}")
        repeat_hash = None
        if args.repeat:
            repeated, _repeat_elapsed = _run(path, source_sha256)
            repeat_hash = repeated["semantic_sha256"]
            if repeat_hash != result["semantic_sha256"]:
                failures.append(f"{path.name}: semantic result is not repeatable")
        summaries.append({
            "file": path.name,
            "elapsed_seconds": round(elapsed, 3),
            "source_sha256": source_sha256,
            "semantic_sha256": result["semantic_sha256"],
            "repeat_semantic_sha256": repeat_hash,
            "packets": result["capture"]["packet_count"],
            "endpoints": len(result["endpoints"]),
            "flows": len(result["flows"]),
            "observables": len(result["observables"]),
            "artifacts": len(result["artifacts"]),
            "findings": dict(sorted(Counter(item["rule_id"] for item in result["findings"]).items())),
            "attack_candidates": [item["attack_id"] for item in result["attack_candidates"]],
        })
        print(json.dumps(summaries[-1], sort_keys=True), flush=True)
    print(json.dumps({"captures": len(summaries), "failures": failures}, sort_keys=True))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
