"""Offline decoder regression; never queries providers or executes recovered files.

Use with a frozen benchmark directory. Outputs are separate from the original
run. This is decoder validation, NOT a claim of live-platform or unseen testing.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
import time
from pathlib import Path

from pcap_analyzer.app import analyze_capture


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--case", action="append")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    for capture in sorted(args.source.glob("*/*.pcap")):
        if args.case and capture.parent.name not in args.case:
            continue
        started = time.monotonic()
        digest = hashlib.file_digest(capture.open("rb"), "sha256").hexdigest()
        with tempfile.TemporaryDirectory(prefix="pcap-quality-") as scratch:
            result = analyze_capture(capture, source_sha256=digest, source_size_bytes=capture.stat().st_size,
                                     filename=capture.name, capture_format="pcap", scratch=Path(scratch))
        elapsed = round(time.monotonic() - started, 3)
        path = args.output / (capture.parent.name + ".json")
        path.write_text(json.dumps({"mode": "offline-decoder-regression", "elapsed_seconds": elapsed, "result": result}, indent=2))
        print(json.dumps({"case": capture.parent.name, "seconds": elapsed, "artifacts": len(result["artifacts"]),
                          "identities": len(result["identities"]), "findings": len(result["findings"]), "warnings": result["coverage"]["warnings"]}), flush=True)


if __name__ == "__main__":
    main()
