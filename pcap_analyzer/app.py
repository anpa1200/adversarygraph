"""Isolated, deterministic packet-capture evidence extractor.

The service deliberately has no CTI-provider or LLM integration.  It decodes a
bounded capture with a pinned TShark profile and returns facts, rule findings,
and ATT&CK candidates that retain packet/frame evidence.  The caller owns
storage, review, enrichment, and promotion.
"""

from __future__ import annotations

import csv
import asyncio
import hashlib
import hmac
import ipaddress
import json
import math
import mimetypes
import os
import re
import statistics
import subprocess
import tempfile
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

from fastapi import FastAPI, File, Header, HTTPException, UploadFile
from fastapi.responses import Response
from starlette.concurrency import run_in_threadpool


SCHEMA_VERSION = "pcap-analysis-v1"
PROFILE_ID = "tshark-evidence-v4"
RULEPACK_VERSION = "pcap-rules-v3"
MAX_UPLOAD_BYTES = int(os.getenv("PCAP_ANALYZER_MAX_UPLOAD_BYTES", str(512 * 1024 * 1024)))
TOOL_TIMEOUT_SECONDS = int(os.getenv("PCAP_ANALYZER_TOOL_TIMEOUT_SECONDS", "300"))
MAX_TOOL_OUTPUT_BYTES = int(os.getenv("PCAP_ANALYZER_MAX_TOOL_OUTPUT_BYTES", str(256 * 1024 * 1024)))
MAX_EVENTS_PER_KIND = int(os.getenv("PCAP_ANALYZER_MAX_EVENTS_PER_KIND", "50000"))
MAX_FLOWS = int(os.getenv("PCAP_ANALYZER_MAX_FLOWS", "50000"))
MAX_ENDPOINTS = int(os.getenv("PCAP_ANALYZER_MAX_ENDPOINTS", "20000"))
MAX_EXPORTED_OBJECTS = int(os.getenv("PCAP_ANALYZER_MAX_EXPORTED_OBJECTS", "500"))
MAX_OBJECT_HASH_INDEX = int(os.getenv("PCAP_ANALYZER_MAX_OBJECT_HASH_INDEX", "50000"))
MAX_EXPORTED_OBJECT_BYTES = int(os.getenv("PCAP_ANALYZER_MAX_EXPORTED_OBJECT_BYTES", str(50 * 1024 * 1024)))
MAX_EXPORTED_TOTAL_BYTES = int(os.getenv("PCAP_ANALYZER_MAX_EXPORTED_TOTAL_BYTES", str(256 * 1024 * 1024)))
MAX_EXPORTED_FILES = int(os.getenv("PCAP_ANALYZER_MAX_EXPORTED_FILES", "50000"))
AUTH_TOKEN = os.getenv("PCAP_ANALYZER_TOKEN", "")
# HTTP body hex can legitimately exceed the csv module's 128 KiB default.
# The decoder output file is size-checked before parsing; never make it unbounded.
csv.field_size_limit(MAX_TOOL_OUTPUT_BYTES)

_PCAP_MAGICS = {
    bytes.fromhex("d4c3b2a1"): "pcap-le-microsecond",
    bytes.fromhex("a1b2c3d4"): "pcap-be-microsecond",
    bytes.fromhex("4d3cb2a1"): "pcap-le-nanosecond",
    bytes.fromhex("a1b23c4d"): "pcap-be-nanosecond",
    bytes.fromhex("0a0d0d0a"): "pcapng",
}
_DOMAIN_RE = re.compile(r"^(?=.{1,253}\.?$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}\.?$")
_SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._-]+")

PACKET_FIELDS = (
    "frame.number", "frame.time_epoch", "frame.len", "frame.cap_len", "frame.interface_id", "frame.encap_type",
    "frame.protocols", "eth.src", "eth.dst", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
    "ip.proto", "tcp.srcport", "tcp.dstport", "tcp.stream", "tcp.len", "udp.srcport",
    "udp.dstport", "udp.stream",
)
EVENT_QUERIES: dict[str, tuple[str, tuple[str, ...]]] = {
    "dns": (
        "dns",
        ("frame.number", "frame.time_epoch", "ip.src", "ipv6.src", "ip.dst", "ipv6.dst", "udp.srcport", "udp.dstport",
         "tcp.srcport", "tcp.dstport", "udp.stream", "tcp.stream", "dns.flags.response", "dns.flags.rcode", "dns.qry.type",
         "dns.qry.name", "dns.a", "dns.aaaa", "dns.cname"),
    ),
    "http_request": (
        "http.request",
        ("frame.number", "frame.time_epoch", "ip.src", "ipv6.src", "ip.dst", "ipv6.dst", "tcp.srcport", "tcp.dstport",
         "tcp.stream", "http.request.method", "http.host", "http.request.uri", "http.request.full_uri", "http.user_agent",
         "http.content_length", "http.response_in"),
    ),
    "http_response": (
        "http.response",
        ("frame.number", "frame.time_epoch", "ip.src", "ipv6.src", "ip.dst", "ipv6.dst", "tcp.srcport", "tcp.dstport",
         "tcp.stream", "http.response.code", "http.content_type", "http.content_length", "http.response_for.uri", "http.request_in",
         "http.content_encoding", "http.transfer_encoding", "http.file_data"),
    ),
    "tls_client_hello": (
        "tls.handshake.type == 1",
        ("frame.number", "frame.time_epoch", "ip.src", "ipv6.src", "ip.dst", "ipv6.dst", "tcp.srcport", "tcp.dstport",
         "tcp.stream", "tls.handshake.extensions_server_name", "tls.handshake.ja3"),
    ),
    "dhcp": (
        "dhcp || bootp",
        ("frame.number", "frame.time_epoch", "eth.src", "ip.src", "ip.dst", "udp.stream", "dhcp.option.dhcp",
         "dhcp.option.hostname", "dhcp.option.requested_ip_address", "dhcp.ip.your", "dhcp.hw.mac_addr"),
    ),
    "identity": (
        "nbns || llmnr || mdns || kerberos || ntlmssp || smb2 || samr || browser",
        ("frame.number", "frame.time_epoch", "eth.src", "eth.dst", "ip.src", "ipv6.src", "ip.dst", "ipv6.dst", "tcp.stream", "udp.stream",
         "nbns.name", "nbns.flags.response", "nbns.flags.opcode", "nbns.nb_flags.group", "dns.qry.name", "kerberos.CNameString", "kerberos.msg_type",
         "ntlmssp.auth.domain", "ntlmssp.auth.username", "ntlmssp.auth.hostname", "smb2.acct", "samr.samr_UserInfo21.account_name", "samr.samr_UserInfo21.full_name",
         "browser.server", "browser.response_computer_name"),
    ),
    "directory_service": (
        "samr || drsuapi || ldap",
        ("frame.number", "frame.time_epoch", "ip.src", "ipv6.src", "ip.dst", "ipv6.dst", "tcp.stream",
         "samr.opnum", "samr.samr_UserInfo21.account_name", "samr.samr_UserInfo21.full_name", "drsuapi.opnum", "ldap.protocolOp", "ldap.baseObject", "ldap.filter"),
    ),
    "unclassified_tcp": (
        "tcp && data && tcp.len > 0 && tcp.len <= 2048 && !(http || tls || smb || smb2 || kerberos || ldap || dcerpc || nbss || dns)",
        ("frame.number", "frame.time_epoch", "ip.src", "ipv6.src", "ip.dst", "ipv6.dst", "tcp.srcport", "tcp.dstport", "tcp.stream", "tcp.payload"),
    ),
}

app = FastAPI(title="AdversaryGraph PCAP Analyzer", version=SCHEMA_VERSION)
_SUPPORTED_FIELDS: set[str] | None = None
_MANIFEST: dict[str, Any] | None = None
_ANALYSIS_SLOT = asyncio.Semaphore(1)


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _tool_version(binary: str) -> str:
    completed = subprocess.run(
        [binary, "--version"], capture_output=True, text=True, timeout=10, check=True,
        env={**os.environ, "LANG": "C", "LC_ALL": "C", "TZ": "UTC"},
    )
    return completed.stdout.splitlines()[0].strip()


def _supported_fields() -> set[str]:
    global _SUPPORTED_FIELDS
    if _SUPPORTED_FIELDS is not None:
        return _SUPPORTED_FIELDS
    completed = subprocess.run(
        ["tshark", "-G", "fields"], capture_output=True, text=True, timeout=60, check=True,
        env={**os.environ, "LANG": "C", "LC_ALL": "C", "TZ": "UTC"},
    )
    fields: set[str] = set()
    for line in completed.stdout.splitlines():
        columns = line.split("\t")
        if len(columns) >= 3 and columns[0] == "F":
            fields.add(columns[2])
    _SUPPORTED_FIELDS = fields
    return fields


def analyzer_manifest() -> dict[str, Any]:
    global _MANIFEST
    if _MANIFEST is not None:
        return dict(_MANIFEST)
    supported = _supported_fields()
    requested = sorted(set(PACKET_FIELDS).union(*(fields for _, fields in EVENT_QUERIES.values())))
    profile = {
        "schema_version": SCHEMA_VERSION,
        "profile_id": PROFILE_ID,
        "rulepack_version": RULEPACK_VERSION,
        "packet_fields": [field for field in PACKET_FIELDS if field in supported],
        "event_queries": {
            kind: {"display_filter": display_filter, "fields": [field for field in fields if field in supported]}
            for kind, (display_filter, fields) in sorted(EVENT_QUERIES.items())
        },
        "name_resolution": False,
        "timezone": "UTC",
    }
    manifest = {
        "schema_version": "pcap-analyzer-manifest-v1",
        "profile_id": PROFILE_ID,
        "rulepack_version": RULEPACK_VERSION,
        "tshark_version": _tool_version("tshark"),
        "implementation_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "capinfos_version": _tool_version("capinfos"),
        "limits": {
            "max_upload_bytes": MAX_UPLOAD_BYTES,
            "tool_timeout_seconds": TOOL_TIMEOUT_SECONDS,
            "max_tool_output_bytes": MAX_TOOL_OUTPUT_BYTES,
            "max_events_per_kind": MAX_EVENTS_PER_KIND,
            "max_flows": MAX_FLOWS,
            "max_endpoints": MAX_ENDPOINTS,
            "max_exported_objects": MAX_EXPORTED_OBJECTS,
            "max_object_hash_index": MAX_OBJECT_HASH_INDEX,
            "max_exported_object_bytes": MAX_EXPORTED_OBJECT_BYTES,
            "max_exported_total_bytes": MAX_EXPORTED_TOTAL_BYTES,
            "max_exported_files": MAX_EXPORTED_FILES,
        },
        "requested_fields_sha256": hashlib.sha256("\n".join(requested).encode()).hexdigest(),
        "supported_profile_fields_sha256": hashlib.sha256(
            "\n".join(field for field in requested if field in supported).encode()
        ).hexdigest(),
        "profile_sha256": _sha256_json(profile),
    }
    manifest["manifest_sha256"] = _sha256_json(manifest)
    _MANIFEST = manifest
    return dict(manifest)


def _authorize(value: str | None) -> None:
    if not AUTH_TOKEN:
        return
    prefix = "Bearer "
    candidate = value[len(prefix):] if value and value.startswith(prefix) else ""
    if not hmac.compare_digest(candidate, AUTH_TOKEN):
        raise HTTPException(401, "Invalid PCAP analyzer token")


@app.get("/health")
def health() -> dict[str, str]:
    try:
        manifest = analyzer_manifest()
    except (OSError, subprocess.SubprocessError) as exc:
        raise HTTPException(503, "Packet decoder is unavailable") from exc
    return {"status": "ok", "profile_id": str(manifest["profile_id"]), "manifest_sha256": str(manifest["manifest_sha256"])}


@app.get("/manifest")
def manifest(authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _authorize(authorization)
    try:
        return analyzer_manifest()
    except (OSError, subprocess.SubprocessError) as exc:
        raise HTTPException(503, "Packet decoder is unavailable") from exc


@app.post("/analyze")
async def analyze(
    file: UploadFile = File(...),
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    _authorize(authorization)
    with tempfile.TemporaryDirectory(prefix="ag-pcap-") as temp_name:
        root = Path(temp_name)
        capture = root / "capture.bin"
        digest = hashlib.sha256()
        total = 0
        with capture.open("wb") as handle:
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_UPLOAD_BYTES:
                    raise HTTPException(413, f"Capture exceeds {MAX_UPLOAD_BYTES} byte limit")
                digest.update(chunk)
                handle.write(chunk)
        if total < 24:
            raise HTTPException(400, "Capture is empty or truncated")
        with capture.open("rb") as handle:
            capture_format = _PCAP_MAGICS.get(handle.read(4))
        if not capture_format:
            raise HTTPException(400, "File is not a recognized PCAP or PCAPNG capture")
        try:
            async with _ANALYSIS_SLOT:
                return await run_in_threadpool(
                    analyze_capture, capture, source_sha256=digest.hexdigest(),
                    source_size_bytes=total, filename=file.filename or "capture",
                    capture_format=capture_format, scratch=root,
                )
        except subprocess.TimeoutExpired as exc:
            raise HTTPException(422, "Packet decoding exceeded the configured timeout") from exc
        except AnalyzerLimitError as exc:
            raise HTTPException(422, str(exc)) from exc
        except subprocess.CalledProcessError as exc:
            raise HTTPException(422, _safe_tool_error(exc)) from exc


class AnalyzerLimitError(RuntimeError):
    pass


@app.post("/objects/{sha256}")
async def recover_object(sha256: str, file: UploadFile = File(...), authorization: str | None = Header(default=None)) -> Response:
    """Re-extract, never execute. The public API owns export permission and capture access."""
    _authorize(authorization)
    if not re.fullmatch(r"[a-f0-9]{64}", sha256):
        raise HTTPException(400, "Invalid object SHA-256")
    with tempfile.TemporaryDirectory(prefix="ag-object-") as temporary:
        root = Path(temporary)
        capture = root / "capture.bin"
        total = 0
        with capture.open("wb") as target:
            while chunk := await file.read(1024 * 1024):
                total += len(chunk)
                if total > MAX_UPLOAD_BYTES:
                    raise HTTPException(413, "Capture exceeds upload limit")
                target.write(chunk)
        with capture.open("rb") as source:
            if total < 24 or source.read(4) not in _PCAP_MAGICS:
                raise HTTPException(400, "Invalid capture")
        try:
            async with _ANALYSIS_SLOT:
                content = await run_in_threadpool(_recover_object_bytes, root, capture, sha256)
        except (subprocess.SubprocessError, AnalyzerLimitError, OSError) as exc:
            raise HTTPException(422, "Object recovery failed or exceeded decoder limits") from exc
        return Response(content, media_type="application/octet-stream", headers={
            "Content-Disposition": f'attachment; filename="{sha256}.bin"',
            "X-Content-Type-Options": "nosniff", "Cache-Control": "no-store",
        })


def _recover_object_bytes(root: Path, capture: Path, sha256: str) -> bytes:
    inventory: dict[str, Any] = {}
    objects, _ = _export_http_objects(root, capture, "", inventory=inventory)
    item = next((a for a in [*objects, *inventory.get("compact_hash_index", [])] if a["sha256"] == sha256), None)
    if not item:
        raise HTTPException(404, "Object not recoverable within current extraction limits")
    # Exported names are never accepted as a client-supplied path.
    directory = (root / "http-objects").resolve()
    for candidate in directory.iterdir():
        if candidate.is_symlink() or not candidate.is_file() or candidate.stat().st_size != item["size_bytes"]:
            continue
        with candidate.open("rb") as source:
            content = source.read(MAX_EXPORTED_OBJECT_BYTES + 1)
        if len(content) <= MAX_EXPORTED_OBJECT_BYTES and hashlib.sha256(content).hexdigest() == sha256:
            return content
    raise HTTPException(409, "Recovered object hash mismatch")


def _safe_tool_error(exc: subprocess.CalledProcessError) -> str:
    stderr = str(exc.stderr or "").strip().splitlines()
    detail = stderr[-1][:240] if stderr else "decoder rejected the capture"
    return f"Packet decoding failed: {detail}"


def _tool_env(root: Path) -> dict[str, str]:
    config = root / "wireshark-config"
    config.mkdir(mode=0o700, exist_ok=True)
    return {
        **os.environ,
        "LANG": "C",
        "LC_ALL": "C",
        "TZ": "UTC",
        "WIRESHARK_CONFIG_DIR": str(config),
    }


def _run_fields(root: Path, capture: Path, kind: str, display_filter: str, requested_fields: Iterable[str]) -> tuple[list[dict[str, str]], bool]:
    supported = _supported_fields()
    fields = [field for field in requested_fields if field in supported]
    if "frame.number" not in fields:
        raise RuntimeError("TShark does not expose the required frame.number field")
    output = root / f"{_SAFE_NAME_RE.sub('-', kind)}.tsv"
    command = [
        "tshark", "-n", "-2", "-r", str(capture), "-T", "fields",
        "-E", "header=y", "-E", "separator=/t", "-E", "quote=d", "-E", "escape=y", "-E", "occurrence=a",
    ]
    if display_filter:
        command.extend(["-Y", display_filter])
    for field in fields:
        command.extend(["-e", field])
    with output.open("wb") as stdout:
        completed = subprocess.run(
            command,
            stdout=stdout,
            stderr=subprocess.PIPE,
            timeout=TOOL_TIMEOUT_SECONDS,
            check=False,
            env=_tool_env(root),
            close_fds=True,
        )
    if completed.returncode != 0:
        raise subprocess.CalledProcessError(completed.returncode, command, stderr=completed.stderr.decode("utf-8", errors="replace"))
    if output.stat().st_size > MAX_TOOL_OUTPUT_BYTES:
        raise AnalyzerLimitError(f"{kind} decoder output exceeded {MAX_TOOL_OUTPUT_BYTES} bytes")
    rows: list[dict[str, str]] = []
    truncated = False
    with output.open("r", encoding="utf-8", errors="replace", newline="") as source:
        reader = csv.DictReader(source, delimiter="\t", quotechar='"')
        for row in reader:
            clean = {key: value for key, value in row.items() if key and value not in (None, "")}
            if clean and kind != "packets" and len(rows) >= MAX_EVENTS_PER_KIND:
                truncated = True
                break
            if clean:
                rows.append(clean)
    return rows, truncated


def analyze_capture(
    capture: Path,
    *,
    source_sha256: str,
    source_size_bytes: int,
    filename: str,
    capture_format: str,
    scratch: Path,
) -> dict[str, Any]:
    manifest = analyzer_manifest()
    packet_rows, _ = _run_fields(scratch, capture, "packets", "", PACKET_FIELDS)
    if not packet_rows:
        raise AnalyzerLimitError("Capture contains no decodable packets")

    coverage: dict[str, Any] = {
        "event_limits": {},
        "warnings": [],
        "encrypted_payload_visibility": "metadata-only",
        "name_resolution": False,
    }
    events: dict[str, list[dict[str, Any]]] = {}
    for kind, (display_filter, fields) in EVENT_QUERIES.items():
        rows, truncated = _run_fields(scratch, capture, kind, display_filter, fields)
        normalized = [_normalize_event(source_sha256, kind, index, row) for index, row in enumerate(rows)]
        events[kind] = normalized
        coverage["event_limits"][kind] = {"returned": len(normalized), "truncated": truncated}
        if truncated:
            coverage["warnings"].append(f"{kind} events were truncated at {MAX_EVENTS_PER_KIND}")

    capture_summary, endpoints, flows, protocol_counts = _summarize_packets(source_sha256, packet_rows)
    if len(endpoints) >= MAX_ENDPOINTS:
        coverage["warnings"].append(f"endpoints were truncated at {MAX_ENDPOINTS}")
    if len(flows) >= MAX_FLOWS:
        coverage["warnings"].append(f"flows were truncated at {MAX_FLOWS}")
    capture_summary.update({
        "format": capture_format,
        "source_sha256": source_sha256,
        "source_size_bytes": source_size_bytes,
        "protocol_counts": protocol_counts,
    })

    identities = _build_identities(source_sha256, events)
    coverage["http_objects"] = {}
    artifacts, artifact_warnings = _export_http_objects(scratch, capture, source_sha256, inventory=coverage["http_objects"])
    _bind_objects(artifacts, events)
    coverage["warnings"].extend(artifact_warnings)
    observables = _build_observables(source_sha256, endpoints, events, artifacts)
    # Compact overflow hashes stay available for enrichment even when richer
    # per-object metadata reaches its cap.
    indexed = _build_observables(source_sha256, [], {}, coverage["http_objects"].get("compact_hash_index", []))
    existing_observables = {o["observable_id"] for o in observables}
    observables.extend(o for o in indexed if o["observable_id"] not in existing_observables)
    findings = _build_findings(source_sha256, events)
    findings.extend(_context_findings(source_sha256, events))
    findings.extend(_unclassified_findings(source_sha256, events, flows))
    coverage["complete_within_profile"] = not coverage["warnings"]
    coverage["limitations"] = ["Encrypted application contents are not decrypted", "Protocol decoding and heuristic findings do not establish malware family or attribution", "No endpoint execution, persistence, or credential-theft proof without corresponding evidence"]
    attack_candidates = _attack_candidates(findings)
    summary = _deterministic_summary(capture_summary, endpoints, flows, events, findings, artifacts)

    semantic = {
        "schema_version": SCHEMA_VERSION,
        "analysis_key_material": {
            "source_sha256": source_sha256,
            "analyzer_manifest_sha256": manifest["manifest_sha256"],
            "rulepack_version": RULEPACK_VERSION,
        },
        "analyzer_manifest": manifest,
        "capture": capture_summary,
        "endpoints": endpoints,
        "identities": identities,
        "flows": flows,
        "events": events,
        "artifacts": artifacts,
        "observables": observables,
        "findings": findings,
        "attack_candidates": attack_candidates,
        "actor_leads": [],
        "coverage": coverage,
        "summary": summary,
    }
    semantic["semantic_sha256"] = _sha256_json(semantic)
    return semantic


def _first(row: dict[str, str], *names: str) -> str:
    for name in names:
        value = str(row.get(name) or "").strip()
        if value:
            # TShark's occurrence=a output joins repeated field instances with
            # a comma.  Address/port/stream helpers need the first decoded
            # instance so malformed or tunneled packets cannot create an
            # invalid synthetic endpoint such as "10.0.0.1,10.0.0.2".
            return value.split(",", 1)[0].strip()
    return ""


def _int(value: Any, default: int = 0) -> int:
    try:
        return int(str(value).split(",", 1)[0])
    except (TypeError, ValueError):
        return default


def _float(value: Any) -> float | None:
    try:
        parsed = float(str(value).split(",", 1)[0])
    except (TypeError, ValueError):
        return None
    return parsed if math.isfinite(parsed) else None


def _normalize_event(source_sha256: str, kind: str, index: int, row: dict[str, str]) -> dict[str, Any]:
    frame = _int(row.get("frame.number"))
    normalized: dict[str, Any] = {
        "event_id": "evt-" + hashlib.sha256(f"{source_sha256}|{kind}|{frame}|{index}".encode()).hexdigest()[:24],
        "kind": kind,
        "frame_number": frame,
        "timestamp_epoch": _first(row, "frame.time_epoch"),
        "src_ip": _first(row, "ip.src", "ipv6.src"),
        "dst_ip": _first(row, "ip.dst", "ipv6.dst"),
        "src_port": _int(_first(row, "tcp.srcport", "udp.srcport")) or None,
        "dst_port": _int(_first(row, "tcp.dstport", "udp.dstport")) or None,
        "tcp_stream": _int(row.get("tcp.stream"), -1) if row.get("tcp.stream") not in (None, "") else None,
        "udp_stream": _int(row.get("udp.stream"), -1) if row.get("udp.stream") not in (None, "") else None,
        "fields": {},
    }
    transport_fields = {
        "frame.number", "frame.time_epoch", "ip.src", "ipv6.src", "ip.dst", "ipv6.dst", "tcp.srcport", "udp.srcport",
        "tcp.dstport", "udp.dstport", "tcp.stream", "udp.stream",
    }
    normalized["fields"] = {key: value for key, value in sorted(row.items()) if key not in transport_fields and key != "http.file_data" and value != ""}
    raw_body = row.get("http.file_data", "").replace(":", "")
    if raw_body and len(raw_body) <= MAX_EXPORTED_OBJECT_BYTES * 2 and re.fullmatch(r"(?:[a-fA-F0-9]{2})+", raw_body):
        body = bytes.fromhex(raw_body)
        normalized["body_sha256"] = hashlib.sha256(body).hexdigest()
        normalized["body_size_bytes"] = len(body)
    return normalized


def _summarize_packets(source_sha256: str, rows: list[dict[str, str]]) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]], dict[str, int]]:
    endpoints: dict[str, dict[str, Any]] = {}
    flows: dict[tuple[Any, ...], dict[str, Any]] = {}
    protocols: Counter[str] = Counter()
    first_epoch: float | None = None
    last_epoch: float | None = None
    captured_bytes = 0
    interfaces: set[int] = set()
    encapsulations: set[int] = set()

    for row in rows:
        frame = _int(row.get("frame.number"))
        timestamp = _float(row.get("frame.time_epoch"))
        length = max(0, _int(row.get("frame.len")))
        captured_bytes += max(0, _int(row.get("frame.cap_len", row.get("frame.len"))))
        if timestamp is not None:
            first_epoch = timestamp if first_epoch is None else min(first_epoch, timestamp)
            last_epoch = timestamp if last_epoch is None else max(last_epoch, timestamp)
        if row.get("frame.interface_id"):
            interfaces.add(_int(row["frame.interface_id"]))
        if row.get("frame.encap_type"):
            encapsulations.add(_int(row["frame.encap_type"]))
        for protocol in str(row.get("frame.protocols") or "").split(":"):
            if protocol:
                protocols[protocol] += 1

        src_ip = _first(row, "ip.src", "ipv6.src")
        dst_ip = _first(row, "ip.dst", "ipv6.dst")
        for ip, mac, direction in ((src_ip, row.get("eth.src", ""), "sent"), (dst_ip, row.get("eth.dst", ""), "received")):
            if not ip:
                continue
            entry = endpoints.setdefault(ip, {
                "endpoint_id": "endpoint-" + hashlib.sha256(f"{source_sha256}|{ip}".encode()).hexdigest()[:24],
                "ip": ip,
                "ip_version": _ip_version(ip),
                "is_private": _is_private(ip),
                "mac_addresses": set(),
                "packets_sent": 0,
                "packets_received": 0,
                "bytes_sent": 0,
                "bytes_received": 0,
                "first_seen_epoch": str(timestamp or ""),
                "last_seen_epoch": str(timestamp or ""),
                "evidence_frames": [],
            })
            if mac:
                entry["mac_addresses"].add(mac.lower())
            entry[f"packets_{direction}"] += 1
            entry[f"bytes_{direction}"] += length
            if timestamp is not None:
                current_first = _float(entry["first_seen_epoch"])
                current_last = _float(entry["last_seen_epoch"])
                if current_first is None or timestamp < current_first:
                    entry["first_seen_epoch"] = str(timestamp)
                if current_last is None or timestamp > current_last:
                    entry["last_seen_epoch"] = str(timestamp)
            if len(entry["evidence_frames"]) < 5 and frame:
                entry["evidence_frames"].append(frame)

        transport = "tcp" if row.get("tcp.stream") not in (None, "") else "udp" if row.get("udp.stream") not in (None, "") else ""
        if not transport or not src_ip or not dst_ip:
            continue
        src_port = _int(_first(row, f"{transport}.srcport"))
        dst_port = _int(_first(row, f"{transport}.dstport"))
        stream = _int(row.get(f"{transport}.stream"), -1)
        key = (transport, stream, src_ip, src_port, dst_ip, dst_port)
        reverse = (transport, stream, dst_ip, dst_port, src_ip, src_port)
        flow = flows.get(key) or flows.get(reverse)
        if flow is None:
            if len(flows) >= MAX_FLOWS:
                continue
            flow_id = "flow-" + hashlib.sha256(f"{source_sha256}|{transport}|{stream}|{src_ip}|{src_port}|{dst_ip}|{dst_port}".encode()).hexdigest()[:24]
            flow = {
                "flow_id": flow_id,
                "transport": transport,
                "stream": stream,
                "initiator_ip": src_ip,
                "initiator_port": src_port,
                "responder_ip": dst_ip,
                "responder_port": dst_port,
                "first_frame": frame,
                "last_frame": frame,
                "first_seen_epoch": str(timestamp or ""),
                "last_seen_epoch": str(timestamp or ""),
                "packets": 0,
                "bytes": 0,
                "initiator_bytes": 0,
                "responder_bytes": 0,
            }
            flows[key] = flow
        flow["packets"] += 1
        flow["bytes"] += length
        flow["last_frame"] = max(flow["last_frame"], frame)
        if timestamp is not None:
            flow["last_seen_epoch"] = str(timestamp)
        if src_ip == flow["initiator_ip"] and src_port == flow["initiator_port"]:
            flow["initiator_bytes"] += length
        else:
            flow["responder_bytes"] += length

    endpoint_rows = []
    for entry in sorted(endpoints.values(), key=lambda item: (item["ip_version"], item["ip"]))[:MAX_ENDPOINTS]:
        entry["mac_addresses"] = sorted(entry["mac_addresses"])
        endpoint_rows.append(entry)
    flow_rows = sorted(flows.values(), key=lambda item: (item["first_frame"], item["flow_id"]))[:MAX_FLOWS]
    duration = max(0.0, (last_epoch or 0.0) - (first_epoch or 0.0)) if first_epoch is not None and last_epoch is not None else 0.0
    capture = {
        "packet_count": len(rows),
        "captured_bytes": captured_bytes,
        "first_packet_epoch": str(first_epoch or ""),
        "last_packet_epoch": str(last_epoch or ""),
        "duration_seconds": round(duration, 6),
        "interface_ids": sorted(interfaces),
        "encapsulation_types": sorted(encapsulations),
    }
    return capture, endpoint_rows, flow_rows, dict(sorted(protocols.items(), key=lambda item: (-item[1], item[0]))[:200])


def _ip_version(value: str) -> int | None:
    try:
        return ipaddress.ip_address(value).version
    except ValueError:
        return None


def _is_private(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_private
    except ValueError:
        return False


def _evidence_ref(event: dict[str, Any]) -> dict[str, Any]:
    frame = int(event.get("frame_number") or 0)
    ref = {
        "frame_number": frame,
        "timestamp_epoch": event.get("timestamp_epoch") or "",
        "display_filter": f"frame.number == {frame}",
    }
    if event.get("tcp_stream") is not None:
        ref["tcp_stream"] = event["tcp_stream"]
    if event.get("udp_stream") is not None:
        ref["udp_stream"] = event["udp_stream"]
    return ref


def _build_identities(source_sha256: str, events: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    rows: dict[tuple[str, str], dict[str, Any]] = {}
    field_types = {
        "dhcp.option.hostname": "hostname", "nbns.name": "hostname",
        "kerberos.CNameString": "account", "ntlmssp.auth.username": "account", "ntlmssp.auth.domain": "domain",
        "ntlmssp.auth.hostname": "hostname", "smb2.acct": "account",
        "browser.response_computer_name": "hostname", "browser.server": "hostname",
        "samr.samr_UserInfo21.account_name": "account", "samr.samr_UserInfo21.full_name": "full-name",
    }
    for event in events.get("dhcp", []) + events.get("identity", []):
        for field, identity_type in field_types.items():
            fields = event.get("fields", {})
            value = str(fields.get(field) or "").strip().strip(".")
            if not value or (field.startswith("ntlmssp.auth.") and value.upper() == "NULL"):
                continue
            raw_value = value
            relation = "client-asserted"
            ip = event.get("src_ip")
            mac = fields.get("eth.src", "")
            if field == "nbns.name":
                # Queries name a target, not the querying host. Only registration
                # requests (opcode 5) support a source ownership assertion.
                if _int(fields.get("nbns.flags.opcode")) != 5 or str(fields.get("nbns.flags.response", "")).lower() in {"1", "true"}:
                    continue
                value = re.sub(r"<[^>]*>.*$", "", value.split(",")[0]).strip()
                if not value or value.startswith("__"):
                    continue
                relation = "netbios-registration"
                if any(v.lower() in {"1", "true"} for v in _split_multi(str(fields.get("nbns.nb_flags.group", "")))):
                    identity_type = "netbios-group"
                    ip, mac, relation = None, "", "group-membership-not-hostname"
            elif field.startswith("samr."):
                # A returned directory object is not proof its subject logged in
                # on the recipient. Preserve the conversation separately.
                ip, mac, relation = None, "", "directory-subject-returned-to-client"
            elif field == "kerberos.CNameString":
                msg_type = _int(fields.get("kerberos.msg_type"))
                if msg_type in (11, 13, 30):
                    ip, mac = event.get("dst_ip"), fields.get("eth.dst", "")
                elif msg_type not in (10, 12, 14):
                    ip, mac = None, ""
                relation = "kerberos-client-principal"
            elif field.startswith("dhcp."):
                ip = fields.get("dhcp.ip.your") or fields.get("dhcp.option.requested_ip_address") or ip
                mac = fields.get("dhcp.hw.mac_addr") or mac
                relation = "dhcp-client-assertion"
            key = (identity_type, value.lower())
            entry = rows.setdefault(key, {
                "identity_id": "identity-" + hashlib.sha256(f"{source_sha256}|{identity_type}|{value.lower()}".encode()).hexdigest()[:24],
                "type": identity_type,
                "value": value,
                "ip_addresses": set(),
                "mac_addresses": set(),
                "evidence": [],
                "bindings": [],
                "raw_values": set(),
            })
            if ip and ip != "0.0.0.0":
                entry["ip_addresses"].add(ip)
            if mac and not str(mac).startswith(("ff:", "01:")):
                entry["mac_addresses"].add(str(mac).lower())
            entry["raw_values"].add(raw_value)
            if len(entry["evidence"]) < 20:
                entry["evidence"].append(_evidence_ref(event))
                entry["bindings"].append({"frame_number": event["frame_number"], "relationship": relation, "owner_ip": ip,
                    "conversation_src": event.get("src_ip"), "conversation_dst": event.get("dst_ip"),
                    "account": fields.get("samr.samr_UserInfo21.account_name", ""), "source_field": field})
    # Bind a directory full name only when its account was independently
    # observed as a client principal on that same requesting endpoint.
    for entry in rows.values():
        if entry["type"] != "full-name":
            continue
        for binding in entry["bindings"]:
            principal = rows.get(("account", binding["account"].lower()))
            recipient = binding["conversation_dst"]
            if principal and recipient in principal["ip_addresses"]:
                entry["ip_addresses"].add(recipient)
                binding["owner_ip"] = recipient
                binding["relationship"] = "directory-name-correlated-with-client-principal"
    result = []
    for entry in sorted(rows.values(), key=lambda item: (item["type"], item["value"].lower())):
        entry["ip_addresses"] = sorted(entry["ip_addresses"])
        entry["mac_addresses"] = sorted(entry["mac_addresses"])
        entry["raw_values"] = sorted(entry["raw_values"])
        result.append(entry)
    return result[:10000]


def _run_object_export(root: Path, command: list[str], directory: Path) -> int:
    """Watch export bytes/count while TShark runs, not only after disk writes."""
    deadline = time.monotonic() + TOOL_TIMEOUT_SECONDS
    with tempfile.TemporaryFile() as errors:
        with subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=errors, env=_tool_env(root), close_fds=True) as process:
            try:
                while True:
                    files = [p for p in directory.iterdir() if p.is_file() and not p.is_symlink()]
                    sizes = [p.stat().st_size for p in files]
                    if len(files) > MAX_EXPORTED_FILES or sum(sizes) > MAX_EXPORTED_TOTAL_BYTES or any(s > MAX_EXPORTED_OBJECT_BYTES for s in sizes):
                        raise AnalyzerLimitError("HTTP export stopped at configured disk/file budget; object inventory is incomplete")
                    if errors.tell() > 1024 * 1024:
                        raise AnalyzerLimitError("HTTP export stopped at diagnostic-output budget")
                    if time.monotonic() > deadline:
                        raise AnalyzerLimitError("HTTP export stopped at decoder timeout")
                    if process.poll() is not None:
                        return process.returncode
                    try:
                        process.wait(timeout=0.1)
                    except subprocess.TimeoutExpired:
                        pass
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()


def _export_http_objects(root: Path, capture: Path, source_sha256: str, *, inventory: dict | None = None) -> tuple[list[dict[str, Any]], list[str]]:
    export_dir = root / "http-objects"
    export_dir.mkdir(mode=0o700, exist_ok=True)
    command = ["tshark", "-n", "-r", str(capture), "--export-objects", f"http,{export_dir}"]
    warnings: list[str] = []
    try:
        returncode = _run_object_export(root, command, export_dir)
    except AnalyzerLimitError as exc:
        if inventory is not None:
            inventory.update(complete=False, export_status="budget-exceeded")
        return [], [str(exc)]
    if returncode != 0:
        warnings.append("HTTP object export failed; packet evidence remains available")
        if inventory is not None:
            inventory.update(complete=False, export_status="decoder-failed")
        return [], warnings
    unique: dict[str, dict[str, Any]] = {}
    total = 0
    candidates = sorted((path for path in export_dir.iterdir() if path.is_file() and not path.is_symlink()), key=lambda path: path.name)
    hashed = 0
    for path in candidates:
        size = path.stat().st_size
        if size > MAX_EXPORTED_OBJECT_BYTES:
            warnings.append(f"One HTTP object exceeded the {MAX_EXPORTED_OBJECT_BYTES} byte hashing limit")
            continue
        if total + size > MAX_EXPORTED_TOTAL_BYTES:
            warnings.append(f"An HTTP object exceeded remaining {MAX_EXPORTED_TOTAL_BYTES} total hashing budget")
            continue
        total += size
        digest = hashlib.sha256()
        sha1 = hashlib.sha1(usedforsecurity=False)
        md5 = hashlib.md5(usedforsecurity=False)
        with path.open("rb") as source:
            for block in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(block)
                sha1.update(block)
                md5.update(block)
        sha256 = digest.hexdigest()
        hashed += 1
        if sha256 in unique:
            unique[sha256]["occurrences"] += 1
            # Filename aliases are bounded, occurrence count remains exact.
            if len(unique[sha256]["filenames"]) < 30:
                unique[sha256]["filenames"].append(path.name[:500])
            continue
        features = _object_features(path)
        unique[sha256] = {
            "artifact_id": "artifact-" + hashlib.sha256(f"{source_sha256}|http|{sha256}".encode()).hexdigest()[:24],
            "type": "http-exported-object",
            "filename": path.name[:500],
            "filenames": [path.name[:500]],
            "occurrences": 1,
            "static_features": features,
            "size_bytes": size,
            "sha256": sha256,
            "sha1": sha1.hexdigest(),
            "md5": md5.hexdigest(),
            "hash_scope": "exact exported bytes; may be partial or content-decoded, not necessarily the original server file",
            "completeness": "unknown",
            "evidence": [],
            "media_type": mimetypes.guess_type(path.name)[0] or "application/octet-stream",
            "extraction_method": "tshark-http-export-objects",
            "content_retained_by_analyzer": False,
        }
    ordered = sorted(unique.values(), key=lambda item: (-bool(item["static_features"]["content_kind"] != "unclassified"), -item["size_bytes"], item["sha256"]))
    artifacts = ordered[:MAX_EXPORTED_OBJECTS]
    compact_index = [{key: item[key] for key in ("artifact_id", "filename", "sha256", "size_bytes", "occurrences")}
                     for item in ordered[MAX_EXPORTED_OBJECTS:MAX_EXPORTED_OBJECTS + MAX_OBJECT_HASH_INDEX]]
    omitted = len(ordered) - len(artifacts) - len(compact_index)
    if omitted:
        warnings.append(f"HTTP object inventory omitted {omitted} unique hashes at metadata limit {MAX_EXPORTED_OBJECTS}")
    if inventory is not None:
        inventory.update(export_status="completed", exported_objects=len(candidates), hashed_objects=hashed, unique_hashes=len(unique), returned_unique_hashes=len(artifacts)+len(compact_index),
                         detailed_objects=len(artifacts), compact_hash_index=compact_index, compact_objects=len(compact_index),
                         omitted_unique_hashes=omitted, unhashed_objects=len(candidates)-hashed, hashed_bytes=total,
                         selection="content-classified first, then size descending, SHA256 tie-break; deduplicated by full hash; overflow retains a compact hash index",
                         complete=(not omitted and hashed == len(candidates)))
    return artifacts, warnings


def _bind_objects(artifacts: list[dict[str, Any]], events: dict[str, list[dict[str, Any]]]) -> None:
    """Join by full body hash, never filename, URL suffix, size alone, or stream alone."""
    requests = {e["frame_number"]: e for e in events.get("http_request", [])}
    by_hash: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in events.get("http_response", []):
        if event.get("body_sha256"):
            by_hash[event["body_sha256"]].append(event)
    for artifact in artifacts:
        transfers = []
        for response in by_hash.get(artifact["sha256"], []):
            request = _paired_request(response, requests)
            fields = response["fields"]
            declared = fields.get("http.content_length", "")
            length_matches = (str(declared).isdigit() and int(declared) == artifact["size_bytes"]
                              and not fields.get("http.content_encoding") and not fields.get("http.transfer_encoding"))
            transfers.append({
                "response_frame": response["frame_number"], "tcp_stream": response.get("tcp_stream"),
                "request_frame": request["frame_number"] if request else None,
                "url": request["fields"].get("http.request.full_uri", "") if request else "",
                "server_ip": response.get("src_ip"), "client_ip": response.get("dst_ip"),
                "status_code": fields.get("http.response.code"),
                "match_basis": "exact-sha256-of-decoded-http-response-body",
                "completeness": "matches-declared-content-length" if length_matches else "unknown",
            })
        artifact["transfers"] = transfers[:30]
        artifact["transfers_truncated"] = len(transfers) > 30
        artifact["evidence"] = [_evidence_ref(e) for e in by_hash.get(artifact["sha256"], [])[:30]]
        # Do not claim complete capture or successful execution from body length.
        artifact["completeness"] = "matches-declared-content-length" if transfers and all(t["completeness"] == "matches-declared-content-length" for t in transfers) else "unknown"


def _object_features(path: Path) -> dict[str, Any]:
    """Bounded static inspection only. Never execute, import, or unpack objects."""
    with path.open("rb") as source:
        data = source.read(256 * 1024)
    text = data.decode("utf-8", errors="replace")
    patterns = {
        "powershell-download": r"(?i)DownloadString|DownloadFile|Invoke-WebRequest|Start-BitsTransfer",
        "dynamic-evaluation": r"(?i)\bInvoke-Expression\b|\biex\b|\beval\s*\(",
        "system-inventory": r"(?i)Get-WmiObject|Get-CimInstance|Win32_OperatingSystem|Win32_ComputerSystem",
        "encoded-command": r"(?i)-(?:enc|encodedcommand)\s+[A-Za-z0-9+/=]{16,}",
    }
    matches = [{"feature": label, "excerpt": match.group(0)[:120], "offset": match.start()}
               for label, pattern in patterns.items() if (match := re.search(pattern, text))]
    kind = "pe" if data[:2] == b"MZ" and len(data) > 64 and data[int.from_bytes(data[60:64], "little"):][:4] == b"PE\0\0" else "unclassified"
    if data.startswith(b"PK\x03\x04"):
        kind = "zip"
    elif kind == "unclassified" and matches:
        kind = "script-like-text"
    return {"content_kind": kind, "inspected_bytes": len(data), "inspection_truncated": path.stat().st_size > len(data),
            "features": matches, "interpretation": "Static content only; not proof of execution, intent, or malware family"}


def _normalize_domain(value: str) -> str:
    clean = value.strip().strip(".").lower()
    return clean if _DOMAIN_RE.fullmatch(clean) else ""


def _build_observables(
    source_sha256: str,
    endpoints: list[dict[str, Any]],
    events: dict[str, list[dict[str, Any]]],
    artifacts: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    items: dict[tuple[str, str], dict[str, Any]] = {}

    def add(value: str, observable_type: str, role: str, event: dict[str, Any] | None = None) -> None:
        clean = value.strip()
        if not clean:
            return
        if observable_type == "domain":
            clean = _normalize_domain(clean)
        if not clean:
            return
        if observable_type in {"ipv4", "ipv6"}:
            try:
                clean = str(ipaddress.ip_address(clean))
            except ValueError:
                return
        identity = clean if observable_type in {"url", "user_agent"} else clean.lower()
        key = (observable_type, identity)
        entry = items.setdefault(key, {
            "observable_id": "observable-" + hashlib.sha256(f"{source_sha256}|{observable_type}|{identity}".encode()).hexdigest()[:24],
            "type": observable_type,
            "value": clean,
            "roles": set(),
            "is_private": _is_private(clean) if observable_type in {"ipv4", "ipv6"} else None,
            "first_seen_epoch": event.get("timestamp_epoch", "") if event else "",
            "last_seen_epoch": event.get("timestamp_epoch", "") if event else "",
            "evidence": [],
            "enrichment_state": "not_requested",
        })
        entry["roles"].add(role)
        if event:
            timestamp = str(event.get("timestamp_epoch") or "")
            if timestamp and (not entry["first_seen_epoch"] or float(timestamp) < float(entry["first_seen_epoch"])):
                entry["first_seen_epoch"] = timestamp
            if timestamp and (not entry["last_seen_epoch"] or float(timestamp) > float(entry["last_seen_epoch"])):
                entry["last_seen_epoch"] = timestamp
            if len(entry["evidence"]) < 20:
                entry["evidence"].append(_evidence_ref(event))

    for endpoint in endpoints:
        value = str(endpoint["ip"])
        add(value, f"ipv{endpoint['ip_version']}", "network-endpoint")
    for event in events.get("dns", []):
        fields = event["fields"]
        add(str(fields.get("dns.qry.name") or ""), "domain", "dns-query", event)
        add(str(fields.get("dns.cname") or ""), "domain", "dns-cname", event)
        for value in _split_multi(str(fields.get("dns.a") or "")):
            add(value, "ipv4", "dns-answer", event)
        for value in _split_multi(str(fields.get("dns.aaaa") or "")):
            add(value, "ipv6", "dns-answer", event)
    for event in events.get("http_request", []):
        fields = event["fields"]
        host = str(fields.get("http.host") or "").split(":", 1)[0]
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            add(host, "domain", "http-host", event)
        else:
            add(str(ip), f"ipv{ip.version}", "http-host", event)
        add(str(fields.get("http.request.full_uri") or ""), "url", "http-request", event)
        add(str(fields.get("http.user_agent") or ""), "user_agent", "http-client", event)
    for event in events.get("tls_client_hello", []):
        fields = event["fields"]
        for value in _split_multi(str(fields.get("tls.handshake.extensions_server_name") or "")):
            add(value, "domain", "tls-sni", event)
        add(str(fields.get("tls.handshake.ja3") or ""), "ja3", "tls-client-fingerprint", event)
    for artifact in artifacts:
        add(str(artifact.get("sha256") or ""), "sha256", "exported-object")

    result = []
    for entry in sorted(items.values(), key=lambda item: (item["type"], item["value"].lower())):
        entry["roles"] = sorted(entry["roles"])
        result.append(entry)
    return result[:50000]


def _split_multi(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def _finding(
    source_sha256: str,
    rule_id: str,
    severity: str,
    title: str,
    explanation: str,
    evidence: list[dict[str, Any]],
    *,
    confidence: float,
    metrics: dict[str, Any] | None = None,
) -> dict[str, Any]:
    evidence = sorted(evidence, key=lambda item: (item.get("frame_number", 0), item.get("tcp_stream", -1)))[:100]
    material = {"rule_id": rule_id, "evidence": evidence, "metrics": metrics or {}}
    return {
        "finding_id": "finding-" + hashlib.sha256(f"{source_sha256}|{_canonical(material)}".encode()).hexdigest()[:24],
        "rule_id": rule_id,
        "rule_version": RULEPACK_VERSION,
        "severity": severity,
        "title": title,
        "explanation": explanation,
        "confidence": confidence,
        "status": "candidate",
        "evidence": evidence,
        "metrics": metrics or {},
    }


def _build_findings(source_sha256: str, events: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    requests = events.get("http_request", [])
    groups: dict[tuple[str, str, int, str, str, str], list[dict[str, Any]]] = defaultdict(list)
    cleartext_443: dict[tuple[str, str, str, str], list[dict[str, Any]]] = defaultdict(list)
    remote_access: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    powershell_clients: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    tokenized_apis: dict[tuple[str, str, str, str], list[dict[str, Any]]] = defaultdict(list)
    fingerprint_uploads: dict[tuple[str, str, str, str], list[dict[str, Any]]] = defaultdict(list)
    posts_by_source: dict[tuple[str, int], list[dict[str, Any]]] = defaultdict(list)
    for event in requests:
        fields = event["fields"]
        method = str(fields.get("http.request.method") or "").upper()
        host = str(fields.get("http.host") or "").lower()
        uri = str(fields.get("http.request.uri") or "")
        path = uri.split("?", 1)[0]
        key = (event.get("src_ip") or "", event.get("dst_ip") or "", int(event.get("dst_port") or 0), host, uri, method)
        groups[key].append(event)

        if int(event.get("dst_port") or 0) == 443:
            cleartext_443[(str(event.get("src_ip") or ""), str(event.get("dst_ip") or ""), host, uri)].append(event)
        user_agent = str(fields.get("http.user_agent") or "")
        if re.search(r"(?i)NetSupport Manager|TeamViewer", user_agent):
            remote_access[(user_agent, str(event.get("src_ip") or ""), str(event.get("dst_ip") or ""))].append(event)
        if re.search(r"(?i)WindowsPowerShell|PowerShell/", user_agent):
            powershell_clients[(user_agent, str(event.get("src_ip") or ""), str(event.get("dst_ip") or ""))].append(event)
        has_uri_token = re.search(r"(?i)[?&](?:access_?token|auth|key|session|token)=[^&]{8,}", uri) is not None
        if has_uri_token:
            tokenized_apis[(str(event.get("src_ip") or ""), str(event.get("dst_ip") or ""), host, path)].append(event)
        content_length = _int(fields.get("http.content_length"))
        if method == "POST" and has_uri_token and content_length >= 4096 and re.search(r"(?i)(?:set[_-]?agent|fingerprint|telemetry)", path):
            fingerprint_uploads[(str(event.get("src_ip") or ""), str(event.get("dst_ip") or ""), host, path)].append(event)
        if method == "POST":
            posts_by_source[(str(event.get("src_ip") or ""), int(event.get("dst_port") or 0))].append(event)

    for (src, dst, host, uri), group in sorted(cleartext_443.items()):
        findings.append(_finding(
            source_sha256, "http-on-tls-port", "medium", "Cleartext HTTP observed on TCP/443",
            "The decoded application protocol is HTTP despite use of the conventional TLS port.",
            [_evidence_ref(event) for event in group], confidence=0.98,
            metrics={"request_count": len(group), "source": src, "destination": dst, "host": host, "uri": uri},
        ))
    for (user_agent, src, dst), group in sorted(remote_access.items()):
        findings.append(_finding(
            source_sha256, "remote-access-user-agent", "high", "Remote-access software network signature",
            "An HTTP User-Agent explicitly identifies remote-access software. Validate authorization and endpoint ownership.",
            [_evidence_ref(event) for event in group], confidence=0.95,
            metrics={"request_count": len(group), "user_agent": user_agent, "source": src, "destination": dst},
        ))
    for (user_agent, src, dst), group in sorted(powershell_clients.items()):
        findings.append(_finding(
            source_sha256, "powershell-http-client", "medium", "HTTP client claiming a PowerShell User-Agent",
            "The HTTP User-Agent claims Windows PowerShell. User-Agent strings can be spoofed; this alone does not prove interpreter execution or malicious intent.",
            [_evidence_ref(event) for event in group], confidence=0.94,
            metrics={"request_count": len(group), "user_agent": user_agent, "source": src, "destination": dst},
        ))
    for (src, dst, host, path), group in sorted(tokenized_apis.items()):
        findings.append(_finding(
            source_sha256, "cleartext-tokenized-api", "medium", "Authentication-like token in cleartext HTTP URI",
            "An HTTP request exposed a token-, key-, auth-, or session-like value in the URI. This is a review lead and a credential-exposure concern even when the application is legitimate.",
            [_evidence_ref(event) for event in group], confidence=0.8,
            metrics={"request_count": len(group), "source": src, "destination": dst, "host": host, "path": path},
        ))
    for (src, dst, host, path), group in sorted(fingerprint_uploads.items()):
        lengths = [_int(event["fields"].get("http.content_length")) for event in group]
        findings.append(_finding(
            source_sha256, "browser-fingerprint-upload", "medium", "Upload to a fingerprint-like API path",
            "A tokenized agent/fingerprint path received multi-kilobyte POST bodies. Path naming does not establish body content or data theft; inspect the payload and authorization.",
            [_evidence_ref(event) for event in group], confidence=0.88,
            metrics={"request_count": len(group), "declared_body_bytes": sum(lengths), "source": src, "destination": dst, "host": host, "path": path},
        ))

    for (src, port), group in sorted(posts_by_source.items()):
        if len(group) < 10:
            continue
        body_lengths = [_int(event["fields"].get("http.content_length")) for event in group]
        destinations = sorted({str(event.get("dst_ip") or "") for event in group if event.get("dst_ip")})
        hosts = sorted({str(event["fields"].get("http.host") or "").lower() for event in group if event["fields"].get("http.host")})
        if sum(body_lengths) >= 1_000_000:
            findings.append(_finding(
                source_sha256, "high-volume-http-posts", "high", "High-volume outbound HTTP POST activity",
                "A source declared at least one megabyte across repeated HTTP POST bodies. The rule establishes transfer volume, not the content or intent of that transfer.",
                [_evidence_ref(event) for event in group], confidence=0.82,
                metrics={"request_count": len(group), "declared_body_bytes": sum(body_lengths), "source": src,
                         "destination_port": port, "destination_count": len(destinations), "host_count": len(hosts),
                         "destinations": destinations[:25], "hosts": hosts[:25]},
            ))
        timestamps = sorted(value for event in group if (value := _float(event.get("timestamp_epoch"))) is not None)
        if len(timestamps) < 10 or statistics.median(body_lengths) < 1000:
            continue
        deltas = [b - a for a, b in zip(timestamps, timestamps[1:]) if b > a]
        if len(deltas) < 9:
            continue
        median = statistics.median(deltas)
        mad = statistics.median(abs(value - median) for value in deltas)
        if 5 <= median <= 600 and mad <= max(2.0, median * 0.2):
            findings.append(_finding(
                source_sha256, "distributed-periodic-http-posts", "high", "Periodic HTTP POSTs across rotating targets",
                "A source sent sizable HTTP POST bodies on a stable cadence, including activity distributed across multiple targets. This is consistent with automated callback and data-transfer behavior.",
                [_evidence_ref(event) for event in group], confidence=0.9,
                metrics={"request_count": len(group), "declared_body_bytes": sum(body_lengths), "median_interval_seconds": round(median, 3),
                         "median_absolute_deviation": round(mad, 3), "source": src, "destination_port": port,
                         "destination_count": len(destinations), "host_count": len(hosts), "destinations": destinations[:25], "hosts": hosts[:25]},
            ))

    for (src, dst, port, host, uri, method), group in sorted(groups.items()):
        large_posts = [
            event for event in group
            if method == "POST" and _int(event["fields"].get("http.content_length")) >= 1_000_000
        ]
        if large_posts:
            lengths = [_int(event["fields"].get("http.content_length")) for event in large_posts]
            findings.append(_finding(
                source_sha256, "large-http-post", "high", "Large outbound HTTP POST",
                "One or more HTTP POST requests declare at least one megabyte of outbound application data; content purpose requires endpoint context.",
                [_evidence_ref(event) for event in large_posts], confidence=0.75,
                metrics={"request_count": len(large_posts), "declared_body_bytes": sum(lengths), "largest_body_bytes": max(lengths),
                         "source": src, "destination": dst, "port": port, "host": host, "uri": uri},
            ))
        if method == "POST" and len(group) >= 5:
            total = sum(_int(event["fields"].get("http.content_length")) for event in group)
            findings.append(_finding(
                source_sha256, "repeated-http-posts", "medium", "Repeated outbound HTTP POST activity",
                "The same endpoint pair and HTTP target produced repeated POST requests suitable for beaconing or data transfer review.",
                [_evidence_ref(event) for event in group], confidence=0.72,
                metrics={"request_count": len(group), "declared_body_bytes": total, "source": src, "destination": dst, "port": port, "host": host, "uri": uri},
            ))
        timestamps = sorted(value for event in group if (value := _float(event.get("timestamp_epoch"))) is not None)
        if len(timestamps) >= 6:
            deltas = [b - a for a, b in zip(timestamps, timestamps[1:]) if b > a]
            if len(deltas) >= 5:
                median = statistics.median(deltas)
                deviations = [abs(value - median) for value in deltas]
                mad = statistics.median(deviations)
                if 5 <= median <= 600 and mad <= max(1.5, median * 0.15):
                    findings.append(_finding(
                        source_sha256, "periodic-http-callbacks", "high", "Periodic HTTP callback pattern",
                        "Repeated requests have a stable cadence consistent with automated callback or beacon behavior.",
                        [_evidence_ref(event) for event in group], confidence=0.88,
                        metrics={"request_count": len(group), "median_interval_seconds": round(median, 3), "median_absolute_deviation": round(mad, 3),
                                 "source": src, "destination": dst, "port": port, "host": host, "uri": uri, "method": method},
                    ))

    request_by_frame = {event["frame_number"]: event for event in requests}
    transfers: dict[tuple[str, str, str, str], list[tuple[dict[str, Any], dict[str, Any] | None]]] = defaultdict(list)
    for response in events.get("http_response", []):
        request = _paired_request(response, request_by_frame)
        uri = str((request or {}).get("fields", {}).get("http.request.uri") or response["fields"].get("http.response_for.uri") or "")
        content_type = str(response["fields"].get("http.content_type") or "")
        if response["fields"].get("http.content_length") == "0":
            continue
        if re.search(r"(?i)\.(?:exe|dll|ps1|vbs|js|hta|zip|rar|7z)(?:$|\?)", uri) or re.search(
            r"(?i)application/(?:x-dosexec|x-msdownload|zip)", content_type
        ):
            transfer_key = (
                str(response.get("src_ip") or ""), str(response.get("dst_ip") or ""), uri, content_type.lower()
            )
            transfers[transfer_key].append((response, request))

    for (src, dst, uri, content_type), group in sorted(transfers.items()):
        responses = [response for response, _request in group]
        evidence = [_evidence_ref(response) for response in responses]
        evidence.extend(_evidence_ref(request) for _response, request in group if request is not None)
        findings.append(_finding(
            source_sha256, "script-or-executable-transfer", "medium", "Script, archive, or executable transfer candidate",
            "HTTP metadata names a script, archive, or executable. This is a transfer candidate, not proof of file type, execution, or malicious intent; legitimate updates use the same formats.",
            evidence, confidence=0.86,
            metrics={
                "response_count": len(responses),
                "source": src,
                "destination": dst,
                "uri": uri,
                "content_type": content_type,
                "declared_body_bytes": sum(_int(response["fields"].get("http.content_length")) for response in responses),
            },
        ))

    deduped: dict[str, dict[str, Any]] = {}
    for finding in findings:
        deduped.setdefault(finding["finding_id"], finding)
    return sorted(deduped.values(), key=lambda item: (item["evidence"][0].get("frame_number", 0), item["rule_id"], item["finding_id"]))


_ATTACK_RULES = {
    "http-on-tls-port": ("T1071.001", "Application Layer Protocol: Web Protocols", "command-and-control", 0.75),
    "periodic-http-callbacks": ("T1071.001", "Application Layer Protocol: Web Protocols", "command-and-control", 0.85),
    "remote-access-user-agent": ("T1219", "Remote Access Software", "command-and-control", 0.9),
    "script-or-executable-transfer": ("T1105", "Ingress Tool Transfer", "command-and-control", 0.8),
    "powershell-http-client": ("T1059.001", "Command and Scripting Interpreter: PowerShell", "execution", 0.5),
    "distributed-periodic-http-posts": ("T1071.001", "Application Layer Protocol: Web Protocols", "command-and-control", 0.88),
}


def _paired_request(response: dict, by_frame: dict[int, dict]) -> dict | None:
    """Trust decoder frame linkage only when stream and endpoint direction agree."""
    request = by_frame.get(_int(response.get("fields", {}).get("http.request_in")))
    if not request or request.get("tcp_stream") is None or request.get("tcp_stream") != response.get("tcp_stream"):
        return None
    if request["frame_number"] >= response["frame_number"]:
        return None
    if (request.get("src_ip"), request.get("dst_ip")) != (response.get("dst_ip"), response.get("src_ip")):
        return None
    return request


def _context_findings(source_sha256: str, events: dict) -> list[dict]:
    """Metadata-only investigation leads; no automatic DGA/DCSync/C2 labels."""
    findings = []
    failed_dns: dict[tuple, list] = defaultdict(list)
    for event in events.get("dns", []):
        if event["fields"].get("dns.flags.rcode") == "3":
            failed_dns[(event.get("dst_ip"), event["fields"].get("dns.qry.name", ""))].append(event)
    for (client, name), group in sorted(failed_dns.items()):
        if len(group) >= 10:
            findings.append(_finding(source_sha256, "repeated-nxdomain", "low", "Repeated unsuccessful DNS resolution",
                "Repeated NXDOMAIN responses may indicate a dead domain, misconfiguration, retrying software, or malicious fallback. They do not establish a domain-generation algorithm.",
                [_evidence_ref(e) for e in group], confidence=0.5,
                metrics={"source": client, "domain": name, "response_count": len(group)}))
    tls_groups: dict[tuple, list] = defaultdict(list)
    for event in events.get("tls_client_hello", []):
        tls_groups[(event.get("src_ip", ""), event["fields"].get("tls.handshake.ja3", ""))].append(event)
    for (client, ja3), group in sorted(tls_groups.items()):
        hosts = sorted({e["fields"].get("tls.handshake.extensions_server_name", "") for e in group} - {""})
        if len(group) < 12 or len(hosts) < 3:
            continue
        # Detect repeated per-host cadence even when requests form tight bursts.
        medians = []
        regular = 0
        regular_names = []
        for host in hosts:
            times = sorted(float(e["timestamp_epoch"]) for e in group if e["fields"].get("tls.handshake.extensions_server_name") == host)
            deltas = [b-a for a,b in zip(times, times[1:]) if b-a > 0.1]
            if len(deltas) >= 3:
                median = statistics.median(deltas)
                if median >= 2 and statistics.median(abs(d-median) for d in deltas) / median < .25:
                    regular += 1
                    regular_names.append(host)
                    medians.append(round(median, 3))
        if regular >= 3:
            findings.append(_finding(source_sha256, "multi-host-tls-cadence", "medium", "Repeated TLS cadence across multiple names",
                "A client fingerprint repeats connections across several names at regular per-name intervals. Telemetry and legitimate agents can do this; TLS payload content and attribution remain unknown.",
                [_evidence_ref(e) for e in group], confidence=.6,
                metrics={"source": client, "ja3": ja3, "hosts": regular_names, "other_names_sharing_fingerprint": sorted(set(hosts)-set(regular_names)),
                         "client_hello_count": len(group), "regular_hosts": regular, "per_host_median_intervals": medians}))
    directory_groups: dict[tuple, list] = defaultdict(list)
    for event in events.get("directory_service", []):
        fields = event["fields"]
        protocol = "samr" if any(k.startswith("samr.") for k in fields) else "drsuapi" if "drsuapi.opnum" in fields else "ldap"
        directory_groups[(event.get("src_ip", ""), event.get("dst_ip", ""), protocol)].append(event)
    for (src, dst, protocol), group in sorted(directory_groups.items()):
        findings.append(_finding(source_sha256, "directory-service-activity", "low", "Directory-service protocol activity",
            "Directory protocol operations were decoded. Normal Windows logon uses these protocols; activity alone does not establish discovery, credential theft, or DCSync.",
            [_evidence_ref(e) for e in group], confidence=.95,
            metrics={"source": src, "destination": dst, "protocol": protocol, "event_count": len(group),
                     "operation_numbers": sorted({str(e["fields"].get(protocol + ".opnum", e["fields"].get("ldap.protocolOp", ""))) for e in group})}))
    return findings


def _unclassified_findings(source_sha256: str, events: dict, flows: list[dict]) -> list[dict]:
    """Expose non-web coverage gaps and literal software labels, without an IOC allowlist."""
    findings = []
    labels: dict[tuple, list] = defaultdict(list)
    for event in events.get("unclassified_tcp", []):
        payload = str(event["fields"].get("tcp.payload", "")).split(",", 1)[0].replace(":", "")
        try:
            data = bytes.fromhex(payload[:4096]).decode("ascii", errors="replace")
        except ValueError:
            continue
        match = re.match(r"(?i)^ping\|([A-Za-z][A-Za-z0-9_.-]{2,31})\|([a-f0-9]{4,64})\|([^|]{1,80})\|([^|]{1,80})\|", data)
        if match:
            labels[(event.get("src_ip", ""), event.get("dst_ip", ""), event.get("dst_port"), *match.groups())].append(event)
    for (src, dst, port, label, client_id, hostname, account), group in sorted(labels.items()):
        findings.append(_finding(source_sha256, "cleartext-tool-self-identification", "high", "Client announces a software label and host identity",
            "An otherwise unclassified TCP payload contains a structured ping, software label, client identifier, hostname and account. These are literal self-reported values, not authenticated identity or independent malware-family attribution.",
            [_evidence_ref(e) for e in group], confidence=.98,
            metrics={"source":src,"destination":dst,"destination_port":port,"software_label":label,"client_id":client_id,
                     "claimed_hostname":hostname,"claimed_account":account,"message_count":len(group)}))
    classified = {e.get("tcp_stream") for kind, rows in events.items() if kind != "unclassified_tcp" for e in rows if e.get("tcp_stream") is not None}
    for flow in flows:
        if flow["transport"] != "tcp" or flow["stream"] in classified or flow["packets"] < 12:
            continue
        try:
            local = ipaddress.ip_address(flow["initiator_ip"])
            remote = ipaddress.ip_address(flow["responder_ip"])
        except ValueError:
            continue
        if not local.is_private or not remote.is_global:
            continue
        duration = float(flow["last_seen_epoch"] or 0)-float(flow["first_seen_epoch"] or 0)
        if duration < 30:
            continue
        findings.append(_finding(source_sha256, "unclassified-external-tcp", "medium", "Sustained external TCP conversation outside decoded application coverage",
            "The flow exchanges traffic with a public endpoint but has no HTTP/TLS/identity event in this profile. Inspect the stream for a custom protocol or a missing handshake. This is a coverage/investigation lead, not a malware verdict.",
            [{"frame_number":flow["first_frame"],"tcp_stream":flow["stream"],"timestamp_epoch":flow["first_seen_epoch"],"display_filter":f"tcp.stream == {flow['stream']}"}],confidence=.7,
            metrics={"source":flow["initiator_ip"],"destination":flow["responder_ip"],"destination_port":flow["responder_port"],
                     "duration_seconds":round(duration,3),"packets":flow["packets"],"wire_bytes":flow["bytes"]}))
    return findings


def _attack_candidates(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    candidates: dict[str, dict[str, Any]] = {}
    for finding in findings:
        mapping = _ATTACK_RULES.get(finding["rule_id"])
        if not mapping:
            continue
        attack_id, name, tactic, confidence = mapping
        candidate = candidates.setdefault(attack_id, {
            "attack_id": attack_id,
            "name": name,
            "tactic": tactic,
            "confidence": confidence,
            "status": "suggested",
            "mapping_basis": "versioned-deterministic-rule",
            "finding_ids": [],
            "evidence": [],
        })
        candidate["confidence"] = max(candidate["confidence"], confidence)
        candidate["finding_ids"].append(finding["finding_id"])
        candidate["evidence"].extend(finding["evidence"][:5])
    for candidate in candidates.values():
        candidate["finding_ids"] = sorted(set(candidate["finding_ids"]))
        unique = {(_canonical(item)): item for item in candidate["evidence"]}
        candidate["evidence"] = [unique[key] for key in sorted(unique)][:25]
    return [candidates[key] for key in sorted(candidates)]


def _deterministic_summary(
    capture: dict[str, Any], endpoints: list[dict[str, Any]], flows: list[dict[str, Any]], events: dict[str, list[dict[str, Any]]],
    findings: list[dict[str, Any]], artifacts: list[dict[str, Any]],
) -> str:
    severities = Counter(str(item.get("severity") or "unknown") for item in findings)
    return (
        f"Decoded {capture['packet_count']} packets across {len(endpoints)} IP endpoints and {len(flows)} transport flows. "
        f"Observed {len(events.get('dns', []))} DNS events, {len(events.get('http_request', []))} HTTP requests, "
        f"{len(events.get('tls_client_hello', []))} TLS ClientHello events, and {len(artifacts)} exported HTTP object(s). "
        f"Deterministic rules produced {len(findings)} finding(s): {severities.get('high', 0)} high, "
        f"{severities.get('medium', 0)} medium, and {severities.get('low', 0)} low. "
        "Findings are evidence-bound candidates and require analyst review; encrypted payload contents remain unavailable."
    )
