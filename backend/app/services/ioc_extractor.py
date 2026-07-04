from __future__ import annotations

import re
from typing import Any

from app.services.ioc_intel import IOCImportItem

IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
URL_RE = re.compile(r"\bhttps?://[^\s<>()\"']+", re.IGNORECASE)
EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")
HASH_RE = re.compile(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b")
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
    for value in HASH_RE.findall(text):
        clean = _clean_value(value).lower()
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
) -> None:
    if not value:
        return
    key = (value, indicator_type)
    if key in findings:
        return
    findings[key] = IOCImportItem(
        value=value,
        indicator_type=indicator_type,
        actor_attack_id=actor_attack_id or None,
        actor_name=actor_name or None,
        source=source_id,
        source_url=source_url,
        confidence=confidence,
        tlp="clear",
        tags=["tag:report-upload"],
        description="IOC extracted from uploaded report text.",
        raw={"extractor": "regex-report-upload"},
    )


def _clean_value(value: str) -> str:
    return value.strip().strip(".,;:)]}>\"'")


def _hash_type(value: str) -> str:
    if len(value) == 64:
        return "sha256"
    if len(value) == 40:
        return "sha1"
    return "md5"


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
