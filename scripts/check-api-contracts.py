#!/usr/bin/env python3
"""Validate the backend OpenAPI contract and every frontend API reference."""

from __future__ import annotations

import argparse
from collections import defaultdict
import os
from pathlib import Path
import re
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
FRONTEND_SOURCE = ROOT / "frontend" / "src"
API_REFERENCE = ROOT / "docs" / "api-reference.md"
HTTP_METHODS = {"delete", "get", "head", "options", "patch", "post", "put"}


def load_openapi() -> dict[str, Any]:
    os.environ.setdefault("DB_PASS", "contract-check-password")
    os.environ.setdefault("LOG_DIR", "/tmp/adversarygraph-contract-check-logs")
    sys.path.insert(0, str(BACKEND))
    from main import app

    return app.openapi()


def operations(schema: dict[str, Any]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for path, path_item in schema.get("paths", {}).items():
        for method, operation in path_item.items():
            if method.lower() not in HTTP_METHODS:
                continue
            items.append(
                {
                    "method": method.upper(),
                    "path": path,
                    "operation": operation,
                }
            )
    return sorted(items, key=lambda item: (item["path"], item["method"]))


def _find_matching_brace(source: str, start: int) -> int:
    depth = 1
    quote = ""
    escaped = False
    index = start
    while index < len(source):
        char = source[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
        elif char in {"'", '"', "`"}:
            quote = char
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index
        index += 1
    return len(source) - 1


def _read_javascript_path(
    source: str,
    start: int,
    constants: dict[str, str] | None = None,
) -> str:
    while start < len(source) and source[start].isspace():
        start += 1
    if start >= len(source) or source[start] not in {"'", '"', "`"}:
        return ""

    quote = source[start]
    index = start + 1
    value: list[str] = []
    escaped = False
    while index < len(source):
        char = source[index]
        if escaped:
            value.append(char)
            escaped = False
        elif char == "\\":
            escaped = True
        elif quote == "`" and char == "$" and index + 1 < len(source) and source[index + 1] == "{":
            end = _find_matching_brace(source, index + 2)
            expression = source[index + 2:end].strip()
            # The current client uses ternary template expressions only to append
            # query strings. Query parameters do not participate in route matching.
            if constants and expression in constants:
                value.append(constants[expression])
            elif "?" not in expression:
                value.append("{param}")
            index = end
        elif char == quote:
            tail = source[index + 1:index + 80]
            if quote != "`" and re.match(r"\s*\+", tail):
                value.append("{param}")
            break
        else:
            value.append(char)
        index += 1
    return "".join(value)


def frontend_api_calls() -> list[tuple[str, str, str]]:
    calls: list[tuple[str, str, str]] = []
    http_call = re.compile(r"\bhttp\.(get|post|put|patch|delete)\s*\(", re.IGNORECASE)
    fetch_call = re.compile(r"\bfetch\s*\(")
    method_option = re.compile(r"\bmethod\s*:\s*['\"](GET|POST|PUT|PATCH|DELETE)['\"]", re.IGNORECASE)

    for source_path in sorted(FRONTEND_SOURCE.rglob("*")):
        if source_path.suffix not in {".ts", ".tsx", ".js", ".jsx"}:
            continue
        source = source_path.read_text(encoding="utf-8")
        constants = {
            name: value
            for name, _, value in re.findall(
                r"\bconst\s+([A-Za-z_$][\w$]*)\s*=\s*(['\"])([^'\"]+)\2\s*;",
                source,
            )
        }
        for match in http_call.finditer(source):
            path = _read_javascript_path(source, match.end(), constants)
            if path:
                calls.append((match.group(1).upper(), f"/api{path}", str(source_path.relative_to(ROOT))))
        for match in fetch_call.finditer(source):
            path = _read_javascript_path(source, match.end(), constants)
            if not path.startswith("/api/"):
                continue
            call_tail = source[match.end():match.end() + 500]
            method_match = method_option.search(call_tail)
            method = method_match.group(1).upper() if method_match else "GET"
            calls.append((method, path, str(source_path.relative_to(ROOT))))
    return calls


def normalize_path(path: str) -> str:
    return path.split("?", 1)[0].rstrip("/") or "/"


def path_matches(contract_path: str, client_path: str) -> bool:
    contract_parts = normalize_path(contract_path).split("/")
    client_parts = normalize_path(client_path).split("/")
    if len(contract_parts) != len(client_parts):
        return False
    return all(
        contract == client
        or re.fullmatch(r"\{[^{}]+\}", contract) is not None
        or re.fullmatch(r"\{[^{}]+\}", client) is not None
        for contract, client in zip(contract_parts, client_parts, strict=True)
    )


def validate(schema: dict[str, Any]) -> tuple[list[str], list[dict[str, Any]]]:
    errors: list[str] = []
    api_operations = operations(schema)
    operation_ids: dict[str, str] = {}
    documented_tags = {
        str(tag.get("name") or ""): str(tag.get("description") or "").strip()
        for tag in schema.get("tags", [])
    }
    used_tags: set[str] = set()

    for item in api_operations:
        method = item["method"]
        path = item["path"]
        operation = item["operation"]
        operation_id = str(operation.get("operationId") or "")
        label = f"{method} {path}"

        if not path.startswith("/api/"):
            errors.append(f"{label}: platform operation must use the /api prefix")
        if not operation_id:
            errors.append(f"{label}: operationId is missing")
        elif operation_id in operation_ids:
            errors.append(f"{label}: duplicate operationId also used by {operation_ids[operation_id]}")
        else:
            operation_ids[operation_id] = label
        if not operation.get("tags"):
            errors.append(f"{label}: module tag is missing")
        else:
            used_tags.update(str(tag) for tag in operation["tags"])
        if not operation.get("summary"):
            errors.append(f"{label}: summary is missing")

        responses = operation.get("responses", {})
        success_codes = [str(code) for code in responses if str(code).startswith("2")]
        if not success_codes:
            errors.append(f"{label}: no successful response is documented")
            continue
        for code in success_codes:
            response = responses[code]
            if code == "204":
                continue
            if not response.get("content"):
                errors.append(f"{label}: {code} response has no documented media type/schema")

    for tag in sorted(used_tags):
        if tag not in documented_tags:
            errors.append(f"OpenAPI module {tag!r} has no top-level documentation")
        elif not documented_tags[tag]:
            errors.append(f"OpenAPI module {tag!r} has an empty description")
    unused_tags = set(documented_tags) - used_tags
    for tag in sorted(unused_tags):
        errors.append(f"OpenAPI module {tag!r} is documented but has no operations")

    known = {(item["method"], item["path"]) for item in api_operations}
    for method, client_path, source in frontend_api_calls():
        if not any(
            candidate_method == method and path_matches(candidate_path, client_path)
            for candidate_method, candidate_path in known
        ):
            errors.append(f"{source}: frontend call {method} {client_path} has no OpenAPI operation")

    return errors, api_operations


def render_reference(schema: dict[str, Any], api_operations: list[dict[str, Any]]) -> str:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in api_operations:
        for tag in item["operation"].get("tags") or ["System"]:
            grouped[str(tag)].append(item)

    lines = [
        "# AdversaryGraph API reference",
        "",
        "<!-- Generated by scripts/check-api-contracts.py. Do not edit manually. -->",
        "",
        f"- Version: **{schema['info']['version']}**",
        f"- Modules: **{len(grouped)}**",
        f"Operations: **{len(api_operations)}**",
        "",
        "Interactive contracts are available from a running deployment at `/docs`,",
        "`/redoc`, and `/openapi.json`. All platform operations use `/api`; protected",
        "operations accept the native session cookie or `Authorization: Bearer <token>`.",
        "External-provider operations can also return a documented 4xx/5xx dependency",
        "status when the corresponding credential, policy permission, or service is unavailable.",
        "",
        "Contract completeness is checked with `./scripts/check-api-contracts.py`.",
        "Against a running deployment, `./scripts/test-api-live.py --base-url",
        "http://127.0.0.1:3000` probes every read-only operation and fails on an",
        "unhandled response. Mutating operations are exercised by the backend integration",
        "suite rather than by the live smoke command.",
        "",
    ]
    for tag in sorted(grouped):
        items = sorted(grouped[tag], key=lambda item: (item["path"], item["method"]))
        lines.extend(
            [
                f"## {tag}",
                "",
                f"{len(items)} operation{'s' if len(items) != 1 else ''}.",
                "",
                "| Method | Path | Operation | Success |",
                "|---|---|---|---|",
            ]
        )
        for item in items:
            operation = item["operation"]
            success = ", ".join(
                str(code)
                for code in operation.get("responses", {})
                if str(code).startswith("2")
            )
            deprecated = " — deprecated" if operation.get("deprecated") else ""
            summary = str(operation.get("summary") or "").replace("|", "\\|")
            path = str(item["path"]).replace("|", "\\|")
            lines.append(
                f"| `{item['method']}` | `{path}` | {summary}{deprecated} | {success} |"
            )
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--write-docs",
        action="store_true",
        help="Regenerate docs/api-reference.md after validating the contract.",
    )
    args = parser.parse_args()

    schema = load_openapi()
    errors, api_operations = validate(schema)
    reference = render_reference(schema, api_operations)

    if args.write_docs and not errors:
        API_REFERENCE.write_text(reference, encoding="utf-8")
    elif API_REFERENCE.exists() and API_REFERENCE.read_text(encoding="utf-8") != reference:
        errors.append(
            "docs/api-reference.md is stale; run scripts/check-api-contracts.py --write-docs"
        )
    elif not API_REFERENCE.exists():
        errors.append(
            "docs/api-reference.md is missing; run scripts/check-api-contracts.py --write-docs"
        )

    if errors:
        print("API contract validation failed:")
        for error in errors:
            print(f"  - {error}")
        return 1

    module_count = len(
        {
            tag
            for item in api_operations
            for tag in item["operation"].get("tags", [])
        }
    )
    print(
        "API contract validation passed: "
        f"{len(api_operations)} operations, {module_count} modules, "
        f"{len(frontend_api_calls())} frontend API calls."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
