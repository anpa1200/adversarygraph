from __future__ import annotations

import re
import unicodedata
from typing import Any


ATTACK_ID_RE = re.compile(r"^(?:TA|T|G|C)\d{4}(?:\.\d{3})?$", re.IGNORECASE)
CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
IOC_KINDS = {"domain", "ip", "ipv4", "ipv6", "url", "hash", "sha256", "sha1", "md5", "email"}
TAXONOMY_SYSTEM_INSTRUCTIONS = """Taxonomy and label rules:
- Store structured labels as namespace:value strings.
- Use ttp:Txxxx or ttp:Txxxx.xxx for MITRE ATT&CK techniques.
- Use actor:Gxxxx for ATT&CK groups when an ID is known; otherwise use actor:<canonical-slug>.
- Use cve:CVE-YYYY-NNNN for CVEs.
- Use sector:<canonical-slug>, risk:critical|high|medium|low, technology:<canonical-slug>, product:<canonical-slug>, supplier:<canonical-slug>, dependency:<canonical-slug>, environment:<canonical-slug>, exposure:internet|internal|third-party|unknown, and tag:<canonical-slug>.
- Do not invent new namespace names. Preserve original source labels in evidence/raw fields if useful, but normalized tags must follow this convention."""

KIND_ALIASES = {
    "actor": "actor",
    "apt": "actor",
    "group": "actor",
    "threat_actor": "actor",
    "threat-actor": "actor",
    "ttp": "ttp",
    "technique": "ttp",
    "attack": "ttp",
    "cve": "cve",
    "vulnerability": "cve",
    "sector": "sector",
    "industry": "sector",
    "risk": "risk",
    "criticality": "criticality",
    "technology": "technology",
    "tech": "technology",
    "product": "product",
    "supplier": "supplier",
    "vendor": "supplier",
    "dependency": "dependency",
    "component": "dependency",
    "environment": "environment",
    "env": "environment",
    "exposure": "exposure",
    "asset_type": "asset_type",
    "type": "asset_type",
    "tag": "tag",
    "label": "tag",
}

RISK_ALIASES = {
    "crit": "critical",
    "critical": "critical",
    "p0": "critical",
    "sev0": "critical",
    "sev1": "critical",
    "high": "high",
    "p1": "high",
    "sev2": "high",
    "medium": "medium",
    "med": "medium",
    "p2": "medium",
    "sev3": "medium",
    "low": "low",
    "p3": "low",
    "p4": "low",
    "info": "low",
}

EXPOSURE_ALIASES = {
    "internet": "internet",
    "public": "internet",
    "external": "internet",
    "edge": "internet",
    "dmz": "internet",
    "internal": "internal",
    "private": "internal",
    "corp": "internal",
    "lan": "internal",
    "third-party": "third-party",
    "third party": "third-party",
    "vendor": "third-party",
    "saas": "third-party",
    "unknown": "unknown",
}


def canonical_kind(kind: str) -> str:
    normalized = _slug(kind).replace("-", "_")
    return KIND_ALIASES.get(normalized, normalized)


def canonical_value(kind: str, value: Any) -> str:
    kind = canonical_kind(kind)
    raw = str(value or "").strip()
    if not raw:
        return ""
    if ":" in raw:
        raw_kind, raw_value = raw.split(":", 1)
        normalized_raw_kind = canonical_kind(raw_kind)
        if normalized_raw_kind == kind or {normalized_raw_kind, kind} <= {"risk", "criticality"}:
            raw = raw_value.strip()
    if kind in {"ttp", "actor"} and ATTACK_ID_RE.fullmatch(raw):
        return raw.upper()
    if kind == "cve" and CVE_ID_RE.fullmatch(raw):
        return raw.upper()
    if kind in {"risk", "criticality"}:
        return RISK_ALIASES.get(_slug(raw), _slug(raw) or "medium")
    if kind == "exposure":
        return EXPOSURE_ALIASES.get(_slug(raw), "unknown")
    if kind in IOC_KINDS:
        return raw.lower()
    return _slug(raw)


def canonical_tag(kind: str, value: Any) -> str:
    kind = canonical_kind(kind)
    value = canonical_value(kind, value)
    if not value:
        return ""
    if kind == "criticality":
        kind = "risk"
    return f"{kind}:{value}"


def canonical_tags(kind: str, values: Any, *, limit: int = 100) -> list[str]:
    if canonical_kind(kind) == "tag":
        return normalize_freeform_tags(values, limit=limit)
    return _dedupe([canonical_tag(kind, value) for value in _as_list(values)], limit=limit)


def canonical_values(kind: str, values: Any, *, limit: int = 100) -> list[str]:
    return _dedupe([canonical_value(kind, value) for value in _as_list(values)], limit=limit)


def normalize_freeform_tags(values: Any, *, limit: int = 100) -> list[str]:
    tags = []
    for value in _as_list(values):
        raw = str(value or "").strip()
        if not raw:
            continue
        if ":" in raw:
            kind, label = raw.split(":", 1)
            tags.append(canonical_tag(kind, label))
        elif CVE_ID_RE.fullmatch(raw):
            tags.append(canonical_tag("cve", raw))
        elif ATTACK_ID_RE.fullmatch(raw):
            prefix = raw[:1].upper()
            tags.append(canonical_tag("actor" if prefix == "G" else "ttp", raw))
        else:
            tags.append(canonical_tag("tag", raw))
    return _dedupe(tags, limit=limit)


def asset_labels(
    *,
    asset_type: str = "",
    environment: str = "",
    exposure: str = "",
    criticality: str = "",
    technologies: Any = None,
    products: Any = None,
    suppliers: Any = None,
    dependencies: Any = None,
    sectors: Any = None,
    ttps: Any = None,
    cves: Any = None,
    extra_tags: Any = None,
) -> dict[str, list[str] | str]:
    labels: dict[str, list[str] | str] = {
        "asset_type": canonical_value("asset_type", asset_type) or "unknown",
        "environment": canonical_value("environment", environment) or "unknown",
        "exposure": canonical_value("exposure", exposure) or "unknown",
        "risk": canonical_value("risk", criticality) or "medium",
        "technologies": [canonical_value("technology", item) for item in _as_list(technologies)],
        "products": [canonical_value("product", item) for item in _as_list(products)],
        "suppliers": [canonical_value("supplier", item) for item in _as_list(suppliers)],
        "dependencies": [canonical_value("dependency", item) for item in _as_list(dependencies)],
        "sectors": [canonical_value("sector", item) for item in _as_list(sectors)],
        "ttps": [canonical_value("ttp", item) for item in _as_list(ttps)],
        "cves": [canonical_value("cve", item) for item in _as_list(cves)],
        "tags": normalize_freeform_tags(extra_tags),
    }
    for key, value in list(labels.items()):
        if isinstance(value, list):
            labels[key] = _dedupe([item for item in value if item])
    return labels


def labels_to_tags(labels: dict[str, Any]) -> list[str]:
    tags: list[str] = []
    scalar_map = {
        "asset_type": "asset_type",
        "environment": "environment",
        "exposure": "exposure",
        "risk": "risk",
    }
    list_map = {
        "technologies": "technology",
        "products": "product",
        "suppliers": "supplier",
        "dependencies": "dependency",
        "sectors": "sector",
        "ttps": "ttp",
        "cves": "cve",
    }
    for key, kind in scalar_map.items():
        if labels.get(key):
            tags.append(canonical_tag(kind, labels[key]))
    for key, kind in list_map.items():
        tags.extend(canonical_tags(kind, labels.get(key) or []))
    tags.extend(normalize_freeform_tags(labels.get("tags") or []))
    return _dedupe(tags)


def split_multi(value: Any, *, limit: int = 100) -> list[str]:
    if isinstance(value, list):
        raw = value
    elif value in (None, ""):
        raw = []
    else:
        raw = re.split(r"[,;|]\s*|\s{2,}", str(value).strip())
    return _dedupe([str(item).strip() for item in raw if str(item).strip()], limit=limit)


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, (tuple, set)):
        return list(value)
    if isinstance(value, str):
        return split_multi(value)
    return [value]


def _slug(value: Any) -> str:
    text = unicodedata.normalize("NFKD", str(value or ""))
    text = text.encode("ascii", "ignore").decode("ascii")
    text = text.lower().strip()
    text = text.replace("&", " and ")
    text = re.sub(r"[^a-z0-9._+-]+", "-", text)
    text = re.sub(r"-{2,}", "-", text).strip("-_.")
    return text


def _dedupe(values: list[str], *, limit: int = 100) -> list[str]:
    seen = set()
    result = []
    for value in values:
        clean = str(value or "").strip()
        if not clean or clean in seen:
            continue
        seen.add(clean)
        result.append(clean)
        if len(result) >= limit:
            break
    return result
