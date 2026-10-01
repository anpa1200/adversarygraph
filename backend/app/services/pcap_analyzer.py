"""Client, validation, reporting, and persistence helpers for PCAP analysis."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import tempfile
from pathlib import Path
from typing import Any, BinaryIO

import httpx
from starlette.concurrency import run_in_threadpool

from app.core.config import settings


PCAP_SCHEMA_VERSION = "pcap-analysis-v1"
_PCAP_MAGICS = {
    bytes.fromhex("d4c3b2a1"), bytes.fromhex("a1b2c3d4"), bytes.fromhex("4d3cb2a1"),
    bytes.fromhex("a1b23c4d"), bytes.fromhex("0a0d0d0a"),
}


class PcapAnalyzerError(RuntimeError):
    def __init__(self, message: str, *, status_code: int = 502):
        super().__init__(message)
        self.status_code = status_code


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def analysis_key(source_sha256: str, manifest_sha256: str) -> str:
    material = {
        "schema_version": PCAP_SCHEMA_VERSION,
        "source_sha256": source_sha256,
        "analyzer_manifest_sha256": manifest_sha256,
    }
    return hashlib.sha256(canonical_json(material).encode("utf-8")).hexdigest()


def validate_capture_magic(handle: BinaryIO) -> None:
    position = handle.tell()
    try:
        handle.seek(0)
        magic = handle.read(4)
    finally:
        handle.seek(position)
    if magic not in _PCAP_MAGICS:
        raise PcapAnalyzerError("File is not a recognized PCAP or PCAPNG capture", status_code=400)


def capture_storage_path(source_sha256: str) -> Path:
    root = Path(settings.pcap_storage_dir).resolve()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    return root / f"{source_sha256}.pcap"


def retain_capture(source: BinaryIO, destination: Path) -> None:
    temporary: Path | None = None
    source.seek(0)
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            prefix=f".{destination.name}.",
            suffix=".partial",
            dir=destination.parent,
            delete=False,
        ) as target:
            temporary = Path(target.name)
            os.chmod(temporary, 0o600)
            for block in iter(lambda: source.read(1024 * 1024), b""):
                target.write(block)
            target.flush()
            os.fsync(target.fileno())
        os.replace(temporary, destination)
    except Exception:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        raise
    finally:
        source.seek(0)


def _headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {settings.pcap_analyzer_token}"} if settings.pcap_analyzer_token else {}


async def recover_artifact(capture_path: Path, source_sha256: str, artifact: dict) -> bytes:
    """Authenticate to the isolated decoder and independently verify returned bytes."""
    limit = 50 * 1024 * 1024
    expected_size = int(artifact.get("size_bytes", -1))
    if not 0 <= expected_size <= limit:
        raise PcapAnalyzerError("Object exceeds download limit", status_code=413)
    try:
        with capture_path.open("rb") as capture:
            digest = await run_in_threadpool(hashlib.file_digest, capture, "sha256")
            if digest.hexdigest() != source_sha256:
                raise PcapAnalyzerError("Retained capture hash mismatch", status_code=409)
            capture.seek(0)
            async with httpx.AsyncClient(timeout=httpx.Timeout(settings.pcap_analyzer_timeout_seconds)) as client:
                async with client.stream("POST", f"{settings.pcap_analyzer_url.rstrip('/')}/objects/{artifact['sha256']}",
                                         headers=_headers(), files={"file": ("capture.pcap", capture, "application/octet-stream")}) as response:
                    if response.status_code != 200:
                        raise PcapAnalyzerError("Object not recoverable by the current decoder", status_code=422)
                    content = bytearray()
                    async for block in response.aiter_bytes():
                        content.extend(block)
                        if len(content) > expected_size:
                            raise PcapAnalyzerError("Recovered object exceeds recorded size", status_code=409)
    except (OSError, httpx.HTTPError) as exc:
        raise PcapAnalyzerError("Retained capture or object decoder unavailable", status_code=503) from exc
    if len(content) != expected_size or hashlib.sha256(content).hexdigest() != artifact["sha256"]:
        raise PcapAnalyzerError("Recovered object hash or size mismatch", status_code=409)
    return bytes(content)


async def get_manifest() -> dict[str, Any]:
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(settings.pcap_analyzer_timeout_seconds)) as client:
            response = await client.get(f"{settings.pcap_analyzer_url.rstrip('/')}/manifest", headers=_headers())
    except httpx.HTTPError as exc:
        raise PcapAnalyzerError("PCAP analyzer is unavailable") from exc
    if response.status_code != 200:
        raise PcapAnalyzerError("PCAP analyzer manifest request failed", status_code=503)
    try:
        payload = response.json()
    except ValueError as exc:
        raise PcapAnalyzerError("PCAP analyzer returned an invalid manifest") from exc
    validate_manifest(payload)
    return payload


async def analyze_capture(handle: BinaryIO, filename: str) -> dict[str, Any]:
    handle.seek(0)
    files = {"file": (Path(filename).name[:500] or "capture.pcap", handle, "application/vnd.tcpdump.pcap")}
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(settings.pcap_analyzer_timeout_seconds)) as client:
            response = await client.post(
                f"{settings.pcap_analyzer_url.rstrip('/')}/analyze",
                headers=_headers(),
                files=files,
            )
    except httpx.HTTPError as exc:
        raise PcapAnalyzerError("PCAP analyzer is unavailable") from exc
    finally:
        handle.seek(0)
    if response.status_code != 200:
        detail = "PCAP analyzer rejected the capture"
        try:
            candidate = response.json().get("detail")
            if isinstance(candidate, str) and candidate:
                detail = candidate[:500]
        except (ValueError, AttributeError):
            pass
        status_code = response.status_code if response.status_code in {400, 413, 422} else 502
        raise PcapAnalyzerError(detail, status_code=status_code)
    try:
        payload = response.json()
    except ValueError as exc:
        raise PcapAnalyzerError("PCAP analyzer returned an invalid result") from exc
    validate_result(payload)
    return payload


def validate_result(payload: Any) -> None:
    if not isinstance(payload, dict) or payload.get("schema_version") != PCAP_SCHEMA_VERSION:
        raise PcapAnalyzerError("PCAP analyzer returned an unsupported result schema")
    semantic_sha256 = payload.get("semantic_sha256")
    manifest = payload.get("analyzer_manifest")
    capture = payload.get("capture")
    if not _sha256(semantic_sha256) or not isinstance(manifest, dict) or not isinstance(capture, dict):
        raise PcapAnalyzerError("PCAP analyzer returned an invalid result")
    validate_manifest(manifest)
    source_sha256 = capture.get("source_sha256")
    if not _sha256(source_sha256):
        raise PcapAnalyzerError("PCAP analyzer omitted the source digest")
    semantic = dict(payload)
    semantic.pop("semantic_sha256", None)
    expected = hashlib.sha256(canonical_json(semantic).encode("utf-8")).hexdigest()
    if expected != semantic_sha256:
        raise PcapAnalyzerError("PCAP analyzer semantic checksum mismatch")


def validate_manifest(payload: Any) -> None:
    if not isinstance(payload, dict):
        raise PcapAnalyzerError("PCAP analyzer returned an invalid manifest")
    material = dict(payload)
    claimed = material.pop("manifest_sha256", None)
    if not _sha256(claimed):
        raise PcapAnalyzerError("PCAP analyzer returned an invalid manifest")
    expected = hashlib.sha256(canonical_json(material).encode("utf-8")).hexdigest()
    if not hmac.compare_digest(expected, claimed):
        raise PcapAnalyzerError("PCAP analyzer manifest checksum mismatch")


def _sha256(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return value == value.lower()


def render_report(filename: str, result: dict[str, Any], actor_leads: list[dict[str, Any]], *, context: dict | None = None) -> str:
    capture = result.get("capture", {})
    findings = list(result.get("findings") or [])
    observables = list(result.get("observables") or [])
    identities = list(result.get("identities") or [])
    artifacts = list(result.get("artifacts") or [])
    techniques = list(result.get("attack_candidates") or [])
    lines = [
        "# AdversaryGraph Deterministic PCAP Analysis",
        "",
        f"Source: {Path(filename).name}",
        f"Capture SHA-256: `{capture.get('source_sha256', '')}`",
        f"Semantic result SHA-256: `{result.get('semantic_sha256', '')}`",
        f"Analyzer manifest SHA-256: `{result.get('analyzer_manifest', {}).get('manifest_sha256', '')}`",
        "",
        "## Executive summary",
        "",
        str(result.get("summary") or "No summary was produced."),
        "",
        "## Capture facts",
        "",
        f"- Packets: {capture.get('packet_count', 0)}",
        f"- Duration: {capture.get('duration_seconds', 0)} seconds",
        f"- Captured bytes: {capture.get('captured_bytes', 0)}",
        f"- Endpoints: {len(result.get('endpoints') or [])}",
        f"- Flows: {len(result.get('flows') or [])}",
        "",
        "## Deterministic findings",
        "",
    ]
    if findings:
        for finding in findings[:200]:
            evidence = finding.get("evidence") or []
            refs = ", ".join(
                f"frame {item.get('frame_number')}" + (f" / TCP stream {item.get('tcp_stream')}" if item.get("tcp_stream") is not None else "")
                for item in evidence[:5]
            )
            lines.extend([
                f"### {str(finding.get('severity') or '').upper()} — {finding.get('title')}",
                "",
                str(finding.get("explanation") or ""),
                "",
                f"Rule: `{finding.get('rule_id')}@{finding.get('rule_version')}`; confidence: {finding.get('confidence')}; evidence: {refs or 'none'}.",
                "",
                f"Metrics: `{canonical_json(finding.get('metrics') or {})}`",
                "",
            ])
    else:
        lines.extend(["- No deterministic suspicious-activity rules fired.", ""])
    lines.extend(["## ATT&CK candidates", ""])
    if techniques:
        for candidate in techniques:
            lines.append(
                f"- {candidate.get('attack_id')} {candidate.get('name')} ({candidate.get('tactic')}), "
                f"confidence={candidate.get('confidence')}, status={candidate.get('status')}; basis={candidate.get('mapping_basis')}."
            )
    else:
        lines.append("- No deterministic ATT&CK candidates.")
    lines.extend(["", "## Identities", ""])
    for identity in identities[:200]:
        frames = ', '.join(str(e.get('frame_number')) for e in identity.get('evidence', [])[:5])
        lines.append(f"- {identity.get('type')}: `{identity.get('value')}`; client IPs: {', '.join(identity.get('ip_addresses') or []) or 'unbound subject'}; frames: {frames or 'unavailable'}")
    if not identities:
        lines.append("- No identity-protocol values recovered.")
    lines.extend(["", "## Observed network and file inventory — not an IOC verdict", ""])
    for item in observables[:500]:
        lines.append(f"- {item.get('type')}: `{item.get('value')}`; roles: {', '.join(item.get('roles') or [])}")
    for artifact in artifacts[:200]:
        lines.append(
            f"- exported object `{artifact.get('filename')}`; SHA-256 `{artifact.get('sha256')}`; size {artifact.get('size_bytes')} bytes"
        )
        lines.append(f"  SHA-1: `{artifact.get('sha1', 'not recorded')}`; MD5: `{artifact.get('md5', 'not recorded')}`; completeness: {artifact.get('completeness', 'unknown')}; transfers: `{canonical_json(artifact.get('transfers', []))}`.")
        features = artifact.get('static_features') or {}
        if features.get('content_kind') != 'unclassified' and features:
            lines.append(f"  Static content: `{canonical_json(features)}`. Not execution proof.")
    if not observables and not artifacts:
        lines.append("- No candidates recovered.")
    lines.extend(["", "## Actor similarity leads", ""])
    if actor_leads:
        for lead in actor_leads[:10]:
            lines.append(
                f"- {lead.get('group_name')} ({lead.get('group_attack_id')}): {round(float(lead.get('similarity') or 0) * 100)}% "
                f"TTP overlap. This is an investigation lead, not attribution."
            )
    else:
        lines.append("- No actor lead was calculated.")
    coverage = result.get("coverage") or {}
    if context:
        lines.extend(["", "## Local enrichment and correlations", "", str(context.get('interpretation', '')),
            f"Snapshot: `{context.get('snapshot_sha256')}`; recorded {context.get('created_at')}; mode: local-only.",
            f"Coverage: `{canonical_json(context.get('coverage', {}))}`", ""])
        for match in context.get('matches', []):
            lines.append(f"- Exact {match['type']} match `{match['value']}`: source `{match['source_id']}`, family `{match.get('malware_family') or 'not specified'}`, source URL: {match.get('source_url') or 'not recorded'}; not case attribution.")
        for technique in context.get('techniques', []):
            lines.append(f"- Catalog {technique['attack_id']}: {technique['url']}; detection strategies: {canonical_json(technique['detection_strategies'])}")
        for link in context.get('cross_case_correlations', []):
            lines.append(f"- Prior analysis `{link['analysis_id']}` shares {link['shared_count']} observations. This does not establish a common campaign.")
        lines.append("- External provider queries: 0. Not requested; no unknown indicator is classified as benign.")
    lines.extend([
        "",
        "## Coverage and limitations",
        "",
        "- Packet and protocol facts are deterministic for the recorded analyzer manifest.",
        "- Encrypted application payloads are not decrypted; only available metadata is reported.",
        "- ATT&CK mappings and actor overlaps are candidates until analyst review and promotion.",
        f"- HTTP object inventory: `{canonical_json({k:v for k,v in coverage.get('http_objects', {}).items() if k != 'compact_hash_index'})}`. Compact overflow hashes are retained in JSON coverage and observables.",
        "- A directory subject is not necessarily a logged-in user; consult identity bindings in the JSON evidence.",
        f"- Rendered / available: findings {min(len(findings),200)}/{len(findings)}, identities {min(len(identities),200)}/{len(identities)}, observables {min(len(observables),500)}/{len(observables)}, artifacts {min(len(artifacts),200)}/{len(artifacts)}. Full returned inventory is in the JSON result.",
    ])
    for warning in coverage.get("warnings") or []:
        lines.append(f"- Warning: {warning}")
    return "\n".join(lines).strip() + "\n"
