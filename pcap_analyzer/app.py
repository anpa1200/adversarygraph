"""Isolated, deterministic packet-capture evidence extractor.

The service deliberately has no CTI-provider or LLM integration.  It decodes a
bounded capture with a pinned TShark profile and returns facts, rule findings,
and ATT&CK candidates that retain packet/frame evidence.  The caller owns
storage, review, enrichment, and promotion.
"""

from __future__ import annotations

import csv
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
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

from fastapi import FastAPI, File, Header, HTTPException, UploadFile


SCHEMA_VERSION = "pcap-analysis-v1"
PROFILE_ID = "tshark-evidence-v1"
RULEPACK_VERSION = "pcap-rules-v1"
MAX_UPLOAD_BYTES = int(os.getenv("PCAP_ANALYZER_MAX_UPLOAD_BYTES", str(512 * 1024 * 1024)))
TOOL_TIMEOUT_SECONDS = int(os.getenv("PCAP_ANALYZER_TOOL_TIMEOUT_SECONDS", "300"))
MAX_TOOL_OUTPUT_BYTES = int(os.getenv("PCAP_ANALYZER_MAX_TOOL_OUTPUT_BYTES", str(256 * 1024 * 1024)))
MAX_EVENTS_PER_KIND = int(os.getenv("PCAP_ANALYZER_MAX_EVENTS_PER_KIND", "50000"))
MAX_FLOWS = int(os.getenv("PCAP_ANALYZER_MAX_FLOWS", "50000"))
MAX_ENDPOINTS = int(os.getenv("PCAP_ANALYZER_MAX_ENDPOINTS", "20000"))
MAX_EXPORTED_OBJECTS = int(os.getenv("PCAP_ANALYZER_MAX_EXPORTED_OBJECTS", "500"))
MAX_EXPORTED_OBJECT_BYTES = int(os.getenv("PCAP_ANALYZER_MAX_EXPORTED_OBJECT_BYTES", str(50 * 1024 * 1024)))
MAX_EXPORTED_TOTAL_BYTES = int(os.getenv("PCAP_ANALYZER_MAX_EXPORTED_TOTAL_BYTES", str(256 * 1024 * 1024)))
AUTH_TOKEN = os.getenv("PCAP_ANALYZER_TOKEN", "")

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
    "frame.number", "frame.time_epoch", "frame.len", "frame.interface_id", "frame.encap_type",
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
         "http.content_length"),
    ),
    "http_response": (
        "http.response",
        ("frame.number", "frame.time_epoch", "ip.src", "ipv6.src", "ip.dst", "ipv6.dst", "tcp.srcport", "tcp.dstport",
         "tcp.stream", "http.response.code", "http.content_type", "http.content_length", "http.response_for.uri"),
    ),
    "tls_client_hello": (
        "tls.handshake.type == 1",
        ("frame.number", "frame.time_epoch", "ip.src", "ipv6.src", "ip.dst", "ipv6.dst", "tcp.srcport", "tcp.dstport",
         "tcp.stream", "tls.handshake.extensions_server_name", "tls.handshake.ja3"),
    ),
    "dhcp": (
        "dhcp || bootp",
        ("frame.number", "frame.time_epoch", "eth.src", "ip.src", "ip.dst", "udp.stream", "dhcp.option.dhcp",
         "dhcp.option.hostname", "dhcp.option.requested_ip_address"),
    ),
    "identity": (
        "nbns || llmnr || mdns || kerberos || ntlmssp || smb2",
        ("frame.number", "frame.time_epoch", "eth.src", "ip.src", "ipv6.src", "ip.dst", "ipv6.dst", "tcp.stream", "udp.stream",
         "nbns.name", "dns.qry.name", "kerberos.CNameString", "ntlmssp.auth.domain", "ntlmssp.auth.username",
         "ntlmssp.auth.hostname", "smb2.acct"),
    ),
}

app = FastAPI(title="AdversaryGraph PCAP Analyzer", version=SCHEMA_VERSION)
_SUPPORTED_FIELDS: set[str] | None = None
_MANIFEST: dict[str, Any] | None = None


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _tool_version(binary: str) -> str:
    completed = subprocess.run(
        [binary, "--version"], capture_output=True, text=True, timeout=10, check=True,
        env={**os.environ, "LANG": "C", "LC_ALL": "C", "TZ": "UTC", "HOME": tempfile.gettempdir()},
    )
    return completed.stdout.splitlines()[0].strip()


def _supported_fields() -> set[str]:
    global _SUPPORTED_FIELDS
    if _SUPPORTED_FIELDS is not None:
        return _SUPPORTED_FIELDS
    completed = subprocess.run(
        ["tshark", "-G", "fields"], capture_output=True, text=True, timeout=60, check=True,
        env={**os.environ, "LANG": "C", "LC_ALL": "C", "TZ": "UTC", "HOME": tempfile.gettempdir()},
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
        "capinfos_version": _tool_version("capinfos"),
        "limits": {
            "max_upload_bytes": MAX_UPLOAD_BYTES,
            "tool_timeout_seconds": TOOL_TIMEOUT_SECONDS,
            "max_tool_output_bytes": MAX_TOOL_OUTPUT_BYTES,
            "max_events_per_kind": MAX_EVENTS_PER_KIND,
            "max_flows": MAX_FLOWS,
            "max_endpoints": MAX_ENDPOINTS,
            "max_exported_objects": MAX_EXPORTED_OBJECTS,
            "max_exported_object_bytes": MAX_EXPORTED_OBJECT_BYTES,
            "max_exported_total_bytes": MAX_EXPORTED_TOTAL_BYTES,
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
            return analyze_capture(
                capture,
                source_sha256=digest.hexdigest(),
                source_size_bytes=total,
                filename=file.filename or "capture",
                capture_format=capture_format,
                scratch=root,
            )
        except subprocess.TimeoutExpired as exc:
            raise HTTPException(422, "Packet decoding exceeded the configured timeout") from exc
        except AnalyzerLimitError as exc:
            raise HTTPException(422, str(exc)) from exc
        except subprocess.CalledProcessError as exc:
            raise HTTPException(422, _safe_tool_error(exc)) from exc


class AnalyzerLimitError(RuntimeError):
    pass


def _safe_tool_error(exc: subprocess.CalledProcessError) -> str:
    stderr = str(exc.stderr or "").strip().splitlines()
    detail = stderr[-1][:240] if stderr else "decoder rejected the capture"
    return f"Packet decoding failed: {detail}"


def _tool_env(root: Path) -> dict[str, str]:
    config = root / "wireshark-config"
    config.mkdir(mode=0o700, exist_ok=True)
    return {
        **os.environ,
        "HOME": str(root),
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
        "tshark", "-n", "-r", str(capture), "-T", "fields",
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
            if clean:
                rows.append(clean)
            if kind != "packets" and len(rows) >= MAX_EVENTS_PER_KIND:
                truncated = True
                break
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
    artifacts, artifact_warnings = _export_http_objects(scratch, capture, source_sha256)
    coverage["warnings"].extend(artifact_warnings)
    observables = _build_observables(source_sha256, endpoints, events, artifacts)
    findings = _build_findings(source_sha256, events)
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
    normalized["fields"] = {key: value for key, value in sorted(row.items()) if key not in transport_fields and value != ""}
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
        captured_bytes += length
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
        "dhcp.option.hostname": "hostname", "nbns.name": "hostname", "dns.qry.name": "hostname",
        "kerberos.CNameString": "account", "ntlmssp.auth.username": "account", "ntlmssp.auth.domain": "domain",
        "ntlmssp.auth.hostname": "hostname", "smb2.acct": "account",
    }
    for event in events.get("dhcp", []) + events.get("identity", []):
        for field, identity_type in field_types.items():
            value = str(event.get("fields", {}).get(field) or "").strip().strip(".")
            if not value:
                continue
            key = (identity_type, value.lower())
            entry = rows.setdefault(key, {
                "identity_id": "identity-" + hashlib.sha256(f"{source_sha256}|{identity_type}|{value.lower()}".encode()).hexdigest()[:24],
                "type": identity_type,
                "value": value,
                "ip_addresses": set(),
                "mac_addresses": set(),
                "evidence": [],
            })
            for ip in (event.get("src_ip"), event.get("dst_ip")):
                if ip:
                    entry["ip_addresses"].add(ip)
            mac = str(event.get("fields", {}).get("eth.src") or "").lower()
            if mac:
                entry["mac_addresses"].add(mac)
            if len(entry["evidence"]) < 20:
                entry["evidence"].append(_evidence_ref(event))
    result = []
    for entry in sorted(rows.values(), key=lambda item: (item["type"], item["value"].lower())):
        entry["ip_addresses"] = sorted(entry["ip_addresses"])
        entry["mac_addresses"] = sorted(entry["mac_addresses"])
        result.append(entry)
    return result[:10000]


def _export_http_objects(root: Path, capture: Path, source_sha256: str) -> tuple[list[dict[str, Any]], list[str]]:
    export_dir = root / "http-objects"
    export_dir.mkdir(mode=0o700, exist_ok=True)
    command = ["tshark", "-n", "-r", str(capture), "--export-objects", f"http,{export_dir}"]
    completed = subprocess.run(
        command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=TOOL_TIMEOUT_SECONDS, check=False,
        env=_tool_env(root), close_fds=True,
    )
    warnings: list[str] = []
    if completed.returncode != 0:
        warnings.append("HTTP object export failed; packet evidence remains available")
        return [], warnings
    artifacts: list[dict[str, Any]] = []
    total = 0
    candidates = sorted((path for path in export_dir.iterdir() if path.is_file()), key=lambda path: path.name)
    if len(candidates) > MAX_EXPORTED_OBJECTS:
        warnings.append(f"HTTP object metadata was truncated at {MAX_EXPORTED_OBJECTS}")
    for index, path in enumerate(candidates[:MAX_EXPORTED_OBJECTS]):
        size = path.stat().st_size
        if size > MAX_EXPORTED_OBJECT_BYTES:
            warnings.append(f"One HTTP object exceeded the {MAX_EXPORTED_OBJECT_BYTES} byte hashing limit")
            continue
        total += size
        if total > MAX_EXPORTED_TOTAL_BYTES:
            warnings.append(f"HTTP object hashing stopped at {MAX_EXPORTED_TOTAL_BYTES} total bytes")
            break
        digest = hashlib.sha256()
        with path.open("rb") as source:
            for block in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(block)
        sha256 = digest.hexdigest()
        artifacts.append({
            "artifact_id": "artifact-" + hashlib.sha256(f"{source_sha256}|http|{index}|{sha256}".encode()).hexdigest()[:24],
            "type": "http-exported-object",
            "filename": path.name[:500],
            "size_bytes": size,
            "sha256": sha256,
            "media_type": mimetypes.guess_type(path.name)[0] or "application/octet-stream",
            "extraction_method": "tshark-http-export-objects",
            "content_retained_by_analyzer": False,
        })
    return artifacts, warnings


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
        key = (observable_type, clean.lower())
        entry = items.setdefault(key, {
            "observable_id": "observable-" + hashlib.sha256(f"{source_sha256}|{observable_type}|{clean.lower()}".encode()).hexdigest()[:24],
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
            source_sha256, "powershell-http-client", "high", "PowerShell-originated HTTP traffic",
            "The HTTP User-Agent explicitly identifies Windows PowerShell. This is execution evidence for a PowerShell web request, but the script intent still requires endpoint context.",
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
            source_sha256, "browser-fingerprint-upload", "high", "Browser or host fingerprint data uploaded",
            "A tokenized agent/fingerprint API received one or more multi-kilobyte HTTP POST bodies, consistent with detailed browser or host fingerprint submission.",
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

    request_by_stream = {event.get("tcp_stream"): event for event in requests if event.get("tcp_stream") is not None}
    transfers: dict[tuple[str, str, str, str], list[tuple[dict[str, Any], dict[str, Any] | None]]] = defaultdict(list)
    for response in events.get("http_response", []):
        request = request_by_stream.get(response.get("tcp_stream"))
        uri = str((request or {}).get("fields", {}).get("http.request.uri") or response["fields"].get("http.response_for.uri") or "")
        content_type = str(response["fields"].get("http.content_type") or "")
        if re.search(r"(?i)\.(?:exe|dll|ps1|vbs|js|hta|zip|rar|7z)(?:$|\?)", uri) or re.search(
            r"(?i)application/(?:x-dosexec|x-msdownload|octet-stream|zip)", content_type
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
            source_sha256, "script-or-executable-transfer", "high", "Script, archive, or executable transfer",
            "HTTP response metadata or the requested path indicates delivery of executable code, a script, or an archive.",
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
    "large-http-post": ("T1041", "Exfiltration Over C2 Channel", "exfiltration", 0.55),
    "repeated-http-posts": ("T1041", "Exfiltration Over C2 Channel", "exfiltration", 0.45),
    "remote-access-user-agent": ("T1219", "Remote Access Software", "command-and-control", 0.9),
    "script-or-executable-transfer": ("T1105", "Ingress Tool Transfer", "command-and-control", 0.8),
    "powershell-http-client": ("T1059.001", "Command and Scripting Interpreter: PowerShell", "execution", 0.85),
    "distributed-periodic-http-posts": ("T1071.001", "Application Layer Protocol: Web Protocols", "command-and-control", 0.88),
    "browser-fingerprint-upload": ("T1041", "Exfiltration Over C2 Channel", "exfiltration", 0.5),
    "high-volume-http-posts": ("T1041", "Exfiltration Over C2 Channel", "exfiltration", 0.6),
}


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
