#!/usr/bin/env python3
"""Probe every read-only OpenAPI operation on a running AdversaryGraph instance."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import re
import sys
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


UUID_ZERO = "00000000-0000-0000-0000-000000000000"
ALLOWED_DEPENDENCY_STATUSES = {400, 401, 403, 404, 409, 422, 429, 502, 503, 504}
TRANSIENT_STARTUP_STATUSES = {502, 503, 504}


def request(
    url: str,
    *,
    token: str = "",
    timeout: float = 20.0,
    max_bytes: int | None = 4096,
) -> tuple[int, bytes, str]:
    headers = {"Accept": "application/json", "User-Agent": "AdversaryGraph-live-api-smoke/1.0"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        with urlopen(Request(url, headers=headers), timeout=timeout) as response:  # noqa: S310
            body = response.read() if max_bytes is None else response.read(max_bytes)
            return response.status, body, response.headers.get("Content-Type", "")
    except HTTPError as exc:
        body = exc.read() if max_bytes is None else exc.read(max_bytes)
        return exc.code, body, exc.headers.get("Content-Type", "")


def load_openapi_schema(
    base_url: str,
    *,
    token: str,
    timeout: float,
    attempts: int,
    retry_delay: float,
) -> dict[str, Any]:
    """Load OpenAPI after bounded retries for transient startup failures."""
    last_error = "no request attempted"
    for attempt in range(1, attempts + 1):
        try:
            status, body, _ = request(
                f"{base_url}/openapi.json",
                token=token,
                timeout=timeout,
                max_bytes=None,
            )
        except (URLError, TimeoutError, OSError) as exc:
            last_error = f"{type(exc).__name__}: {exc}"
        else:
            if status == 200:
                try:
                    return json.loads(body)
                except json.JSONDecodeError as exc:
                    last_error = f"response is not JSON: {exc}"
            else:
                last_error = f"HTTP {status}"
                if status not in TRANSIENT_STARTUP_STATUSES:
                    break

        if attempt < attempts:
            print(
                f"OpenAPI not ready ({last_error}); retrying "
                f"{attempt}/{attempts} in {retry_delay:g}s...",
                file=sys.stderr,
            )
            time.sleep(retry_delay)

    raise RuntimeError(
        f"Could not load {base_url}/openapi.json after {attempts} attempt(s): "
        f"{last_error}"
    )


def placeholder(name: str) -> str:
    normalized = name.lower()
    if normalized in {"attack_id", "technique_id"}:
        return "T1059"
    if normalized == "cve_id":
        return "CVE-2021-44228"
    if normalized == "stix_id":
        return f"attack-pattern--{UUID_ZERO}"
    if normalized in {"article_id", "indicator_id", "ioc_id", "report_id"}:
        return "1"
    if normalized.endswith("_id") or normalized == "id":
        return UUID_ZERO
    if normalized == "domain":
        return "enterprise-attack"
    return "smoke-test"


def concrete_path(path: str) -> str:
    return re.sub(r"\{([^{}]+)\}", lambda match: placeholder(match.group(1)), path)


def probe(
    base_url: str,
    path: str,
    operation: dict[str, Any],
    *,
    token: str,
    timeout: float,
) -> dict[str, Any]:
    concrete = concrete_path(path)
    try:
        status, body, content_type = request(
            f"{base_url}{concrete}",
            token=token,
            timeout=timeout,
        )
        ok = 200 <= status < 300 or status in ALLOWED_DEPENDENCY_STATUSES
        detail = ""
        if not ok:
            detail = body.decode("utf-8", errors="replace")[:300]
        return {
            "path": path,
            "concrete_path": concrete,
            "operation_id": operation.get("operationId", ""),
            "module": (operation.get("tags") or ["System"])[0],
            "status": status,
            "content_type": content_type,
            "ok": ok,
            "detail": detail,
        }
    except (URLError, TimeoutError, OSError) as exc:
        return {
            "path": path,
            "concrete_path": concrete,
            "operation_id": operation.get("operationId", ""),
            "module": (operation.get("tags") or ["System"])[0],
            "status": 0,
            "content_type": "",
            "ok": False,
            "detail": f"{type(exc).__name__}: {exc}",
        }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:3000")
    parser.add_argument("--token", default="")
    parser.add_argument("--timeout", type=float, default=20.0)
    parser.add_argument("--workers", type=int, default=6)
    parser.add_argument(
        "--schema-attempts",
        type=int,
        default=12,
        help="OpenAPI startup attempts before failing (default: 12)",
    )
    parser.add_argument(
        "--schema-retry-delay",
        type=float,
        default=5.0,
        help="Seconds between OpenAPI startup attempts (default: 5)",
    )
    parser.add_argument("--json-output", default="")
    args = parser.parse_args()
    base_url = args.base_url.rstrip("/")

    try:
        schema = load_openapi_schema(
            base_url,
            token=args.token,
            timeout=args.timeout,
            attempts=max(1, args.schema_attempts),
            retry_delay=max(0.0, args.schema_retry_delay),
        )
    except RuntimeError as exc:
        print(exc, file=sys.stderr)
        return 2

    targets = [
        (path, path_item["get"])
        for path, path_item in schema.get("paths", {}).items()
        if "get" in path_item
    ]
    results: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=max(1, min(args.workers, 16))) as executor:
        futures = [
            executor.submit(
                probe,
                base_url,
                path,
                operation,
                token=args.token,
                timeout=args.timeout,
            )
            for path, operation in targets
        ]
        for future in as_completed(futures):
            results.append(future.result())
    results.sort(key=lambda item: (item["module"], item["path"]))

    failures = [item for item in results if not item["ok"]]
    modules = sorted({item["module"] for item in results})
    status_counts: dict[int, int] = {}
    for item in results:
        status_counts[item["status"]] = status_counts.get(item["status"], 0) + 1

    output = {
        "base_url": base_url,
        "openapi_version": schema.get("info", {}).get("version"),
        "read_operations": len(results),
        "modules": modules,
        "status_counts": {str(key): value for key, value in sorted(status_counts.items())},
        "failures": failures,
        "results": results,
    }
    if args.json_output:
        with open(args.json_output, "w", encoding="utf-8") as handle:
            json.dump(output, handle, indent=2)

    print(
        f"Live API smoke: {len(results)} GET operations across {len(modules)} modules; "
        f"{len(failures)} unexpected failure(s)."
    )
    print(
        "Statuses: "
        + ", ".join(f"{status or 'network'}={count}" for status, count in sorted(status_counts.items()))
    )
    for item in failures:
        print(
            f"  FAIL {item['path']} -> {item['status'] or 'network'} {item['detail']}",
            file=sys.stderr,
        )
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
