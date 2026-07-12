from __future__ import annotations

import re
from typing import Any

from app.services.ioc_intel import IOCImportItem

IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
URL_RE = re.compile(r"\bhttps?://[^\s<>()\"']+", re.IGNORECASE)
EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")
HASH_RE = re.compile(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b")
JA4_RE = re.compile(r"\b(?=[a-zA-Z0-9]{3,32}_)(?=[a-zA-Z0-9]*\d)[a-zA-Z0-9]{3,32}_[a-fA-F0-9]{8,64}(?:_[a-fA-F0-9]{8,64}){0,3}\b")
LABELED_FINGERPRINT_RE = re.compile(
    r"\b(ja3s|ja4ssh|ja4ls|ja4h|ja4s|ja4x|ja4t|ja4l|ja4|ja3)\b"
    r"(?:[\s_-]*(?:hash|fingerprint|value))?\s*[:=]\s*([A-Za-z0-9_]{8,180})",
    re.IGNORECASE,
)
DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:[a-zA-Z]{2,24})\b"
)

COMMON_FALSE_DOMAINS = {
    "attack.mitre.org",
    "mitre.org",
    "github.com",
    "medium.com",
    "linkedin.com",
    "wikipedia.org",
    "microsoft.com",
    "google.com",
}


def extract_iocs_from_text(
    text: str,
    *,
    actor_attack_id: str = "",
    actor_name: str = "",
    source_url: str = "",
    source_id: str = "manual-report-import",
    confidence: int = 65,
) -> list[IOCImportItem]:
    """Extract common observables from report text without external services."""
    findings: dict[tuple[str, str], IOCImportItem] = {}
    for value in URL_RE.findall(text):
        clean = _clean_value(value)
        _add(findings, clean, "url", actor_attack_id, actor_name, source_id, source_url, confidence)
    for value in EMAIL_RE.findall(text):
        clean = _clean_value(value)
        _add(findings, clean, "email", actor_attack_id, actor_name, source_id, source_url, confidence)
    for value in IPV4_RE.findall(text):
        clean = _clean_value(value)
        if not _is_private_ipv4(clean):
            _add(findings, clean, "ipv4", actor_attack_id, actor_name, source_id, source_url, confidence)
    for indicator_type, value in _extract_network_fingerprints(text):
        _add(
            findings,
            value,
            indicator_type,
            actor_attack_id,
            actor_name,
            source_id,
            source_url,
            confidence,
            tags=["tag:report-upload", "network-fingerprint", indicator_type],
            description=f"{indicator_type.upper()} network fingerprint extracted from uploaded report text.",
            raw_extra={"network_fingerprint": {"type": indicator_type, "value": value}},
        )
    for value in HASH_RE.findall(text):
        clean = _clean_value(value).lower()
        if len(clean) == 32 and _has_ja3_context(text, clean):
            continue
        _add(findings, clean, _hash_type(clean), actor_attack_id, actor_name, source_id, source_url, confidence)
    url_domains = {_domain_from_url(item.value) for item in findings.values() if item.indicator_type == "url"}
    for value in DOMAIN_RE.findall(text):
        clean = _clean_value(value).lower()
        if clean in COMMON_FALSE_DOMAINS or clean in url_domains or _looks_like_file(clean):
            continue
        _add(findings, clean, "domain", actor_attack_id, actor_name, source_id, source_url, confidence)
    return sorted(findings.values(), key=lambda item: (item.indicator_type, item.value))


def _add(
    findings: dict[tuple[str, str], IOCImportItem],
    value: str,
    indicator_type: str,
    actor_attack_id: str,
    actor_name: str,
    source_id: str,
    source_url: str,
    confidence: int,
    *,
    tags: list[str] | None = None,
    description: str = "IOC extracted from uploaded report text.",
    raw_extra: dict[str, Any] | None = None,
) -> None:
    if not value:
        return
    key = (value, indicator_type)
    if key in findings:
        return
    raw = {"extractor": "regex-report-upload"}
    raw.update(raw_extra or {})
    findings[key] = IOCImportItem(
        value=value,
        indicator_type=indicator_type,
        actor_attack_id=actor_attack_id or None,
        actor_name=actor_name or None,
        source=source_id,
        source_url=source_url,
        confidence=confidence,
        tlp="clear",
        tags=tags or ["tag:report-upload"],
        description=description,
        raw=raw,
    )


def _clean_value(value: str) -> str:
    return value.strip().strip(".,;:)]}>\"'")


def _hash_type(value: str) -> str:
    if len(value) == 64:
        return "sha256"
    if len(value) == 40:
        return "sha1"
    return "md5"


def _extract_network_fingerprints(text: str) -> list[tuple[str, str]]:
    findings: list[tuple[str, str]] = []
    for match in LABELED_FINGERPRINT_RE.finditer(text):
        indicator_type = match.group(1).lower().replace("_", "")
        value = _clean_value(match.group(2)).lower()
        if indicator_type in {"ja3", "ja3s"} and not re.fullmatch(r"[a-f0-9]{32}", value):
            continue
        if indicator_type.startswith("ja4") and "_" not in value:
            continue
        findings.append((indicator_type, value))
    for value in JA4_RE.findall(text):
        clean = _clean_value(value).lower()
        findings.append(("ja4", clean))
    seen: set[tuple[str, str]] = set()
    result: list[tuple[str, str]] = []
    for item in findings:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


def _has_ja3_context(text: str, value: str) -> bool:
    target = value.lower()
    for line in text.splitlines():
        lower = line.lower()
        if target in lower and "ja3" in lower:
            return True
    return False


def _is_private_ipv4(value: str) -> bool:
    parts = [int(part) for part in value.split(".")]
    return (
        parts[0] == 10
        or parts[0] == 127
        or (parts[0] == 172 and 16 <= parts[1] <= 31)
        or (parts[0] == 192 and parts[1] == 168)
        or (parts[0] == 169 and parts[1] == 254)
        or parts[0] >= 224
    )


def _domain_from_url(value: str) -> str:
    return re.sub(r"^https?://", "", value, flags=re.I).split("/", 1)[0].split(":", 1)[0].lower()


def _looks_like_file(value: str) -> bool:
    return value.endswith((".dll", ".exe", ".txt", ".pdf", ".docx", ".zip", ".json", ".xml"))
