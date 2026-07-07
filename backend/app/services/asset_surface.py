from __future__ import annotations

import csv
import io
import json
import re
from dataclasses import dataclass, field
from typing import Any

from app.services.taxonomy import (
    asset_labels,
    canonical_value,
    normalize_freeform_tags,
    split_multi,
)


MAX_INVENTORY_CHARS = 120_000
STRICT_ASSET_CSV_COLUMNS = [
    "asset_id",
    "name",
    "asset_type",
    "environment",
    "owner",
    "ip_addresses",
    "domains",
    "ports",
    "technologies",
    "exposure",
    "criticality",
    "tags",
]
STRICT_ASSET_CSV_REQUIRED_COLUMNS = [
    "asset_id",
    "name",
    "asset_type",
    "environment",
    "technologies",
    "exposure",
    "criticality",
]
STRICT_ASSET_CSV_ALLOWED_VALUES = {
    "exposure": ["internet", "internal", "third-party", "unknown"],
    "criticality": ["critical", "high", "medium", "low"],
}


@dataclass
class AssetSurfaceRecord:
    asset_id: str
    name: str
    asset_type: str = "unknown"
    environment: str = "unknown"
    owner: str = ""
    ip_addresses: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    ports: list[int] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    products: list[str] = field(default_factory=list)
    suppliers: list[str] = field(default_factory=list)
    dependencies: list[str] = field(default_factory=list)
    exposure: str = "unknown"
    criticality: str = "medium"
    tags: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)


def parse_inventory(content: bytes, filename: str | None = None) -> tuple[list[AssetSurfaceRecord], str]:
    text = _decode(content)[:MAX_INVENTORY_CHARS]
    name = (filename or "").lower()
    if name.endswith(".json") or text.lstrip().startswith(("[", "{")):
        return _parse_json(text), text
    if name.endswith(".csv") or _looks_like_csv(text):
        rows = _parse_csv(text)
        if rows:
            return rows, text
    return _parse_text(text), text


def build_baseline_matrix(records: list[AssetSurfaceRecord]) -> dict[str, Any]:
    rows = []
    for record in records:
        signals = _risk_signals(record)
        score = min(100, max(0, 25 + sum(signal["weight"] for signal in signals)))
        ttp_candidates = _dedupe_ttps(_ttp_candidates(record, signals))
        labels = asset_labels(
            asset_type=record.asset_type,
            environment=record.environment,
            exposure=record.exposure,
            criticality=record.criticality,
            technologies=record.technologies,
            products=record.products,
            suppliers=record.suppliers,
            dependencies=record.dependencies,
            ttps=[item["attack_id"] for item in ttp_candidates],
            extra_tags=record.tags,
        )
        rows.append({
            "asset_id": record.asset_id,
            "asset": record.name,
            "asset_type": record.asset_type,
            "environment": record.environment,
            "owner": record.owner,
            "exposure": record.exposure,
            "criticality": record.criticality,
            "ip_addresses": record.ip_addresses,
            "domains": record.domains,
            "ports": record.ports,
            "technologies": record.technologies,
            "products": record.products,
            "suppliers": record.suppliers,
            "dependencies": record.dependencies,
            "labels": labels,
            "risk_score": score,
            "risk_level": _risk_level(score),
            "attack_surface": _attack_surface(record, signals),
            "likely_entry_points": _entry_points(record),
            "ttp_candidates": ttp_candidates,
            "control_gaps": _control_gaps(record, signals),
            "validation_steps": _validation_steps(record, signals),
            "detection_ideas": _detection_ideas(record, ttp_candidates),
            "priority_actions": _priority_actions(record, signals),
            "evidence": [signal["label"] for signal in signals],
        })

    high = sum(1 for row in rows if row["risk_level"] in {"critical", "high"})
    internet = sum(1 for row in rows if row["exposure"] == "internet")
    summary = (
        f"Parsed {len(rows)} assets. {internet} assets appear internet-facing. "
        f"{high} assets are high or critical priority based on exposed services, criticality, "
        "identity/admin surfaces, remote access, and data-store signals."
    )
    return {
        "summary": summary,
        "assets": rows,
        "exposure_counts": _count(rows, "exposure"),
        "risk_counts": _count(rows, "risk_level"),
        "top_risks": sorted(rows, key=lambda row: row["risk_score"], reverse=True)[:10],
        "recommended_workflow": [
            "Validate inventory owner, environment, and internet exposure fields.",
            "Confirm exposed ports with current scanner and cloud security-group data.",
            "Prioritize critical/high internet-facing assets for authentication, patching, and logging review.",
            "Map accepted TTP candidates into Navigator and detection backlog.",
        ],
    }


def build_ai_prompt(records: list[AssetSurfaceRecord], baseline: dict[str, Any]) -> str:
    compact_records = [
        {
            "asset_id": r.asset_id,
            "name": r.name,
            "type": r.asset_type,
            "environment": r.environment,
            "owner": r.owner,
            "ip_addresses": r.ip_addresses,
            "domains": r.domains,
            "ports": r.ports,
            "technologies": r.technologies,
            "products": r.products,
            "suppliers": r.suppliers,
            "dependencies": r.dependencies,
            "exposure": r.exposure,
            "criticality": r.criticality,
            "tags": r.tags,
        }
        for r in records[:250]
    ]
    return f"""You are a senior attack surface management and threat-informed defense analyst.

Analyze the asset inventory and baseline risk matrix. Return only valid JSON.

Output schema:
{{
  "executive_summary": "3-5 sentences",
  "matrix": [
    {{
      "asset_id": "asset-001",
      "asset": "name",
      "business_context": "why this asset matters",
      "exposure": "internet|internal|third-party|unknown",
      "risk_level": "critical|high|medium|low",
      "attack_paths": ["specific plausible path"],
      "ttp_candidates": [{{"attack_id": "T1190", "name": "Exploit Public-Facing Application", "reason": "why"}}],
      "control_gaps": ["specific missing or weak controls"],
      "validation_steps": ["what to verify next"],
      "detection_ideas": ["specific logs, detections, or hunts to build"],
      "priority_actions": ["specific remediation or detection action"]
    }}
  ],
  "cross_asset_findings": ["shared pattern across assets"],
  "assumptions": ["assumptions made from incomplete inventory fields"],
  "validation_gaps": ["what cannot be proven from this inventory alone"]
}}

Rules:
- Do not invent assets that are not present.
- Treat inventory fields as unverified until validated by scanning/cloud telemetry.
- Prefer ATT&CK Enterprise technique IDs for likely attacker behavior.
- Separate likely attack paths from facts observed in the inventory.
- Keep each field concise and analyst-actionable.

Baseline risk matrix:
{json.dumps(baseline, ensure_ascii=False)[:40_000]}

Asset inventory:
{json.dumps(compact_records, ensure_ascii=False)[:40_000]}
"""


def merge_ai_matrix(baseline: dict[str, Any], ai_data: dict[str, Any] | None) -> dict[str, Any]:
    if not ai_data:
        return baseline
    by_id = {str(item.get("asset_id")): item for item in ai_data.get("matrix", []) if item.get("asset_id")}
    merged_assets = []
    for row in baseline["assets"]:
        ai_row = by_id.get(row["asset_id"], {})
        merged = {**row}
        for key in [
            "business_context",
            "attack_paths",
            "control_gaps",
            "validation_steps",
            "detection_ideas",
            "priority_actions",
            "ttp_candidates",
        ]:
            if ai_row.get(key):
                merged[key] = ai_row[key]
        if ai_row.get("risk_level"):
            merged["ai_risk_level"] = ai_row["risk_level"]
        merged_assets.append(merged)
    return {
        **baseline,
        "summary": str(ai_data.get("executive_summary") or baseline["summary"]),
        "assets": merged_assets,
        "top_risks": sorted(merged_assets, key=lambda row: row["risk_score"], reverse=True)[:10],
        "cross_asset_findings": [str(x) for x in ai_data.get("cross_asset_findings", [])],
        "assumptions": [str(x) for x in ai_data.get("assumptions", [])],
        "validation_gaps": [str(x) for x in ai_data.get("validation_gaps", [])],
    }


def parse_ai_json(raw: str) -> dict[str, Any] | None:
    text = raw.strip()
    text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.MULTILINE)
    text = re.sub(r"\s*```$", "", text, flags=re.MULTILINE)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        try:
            start = text.index("{")
            data, _ = json.JSONDecoder().raw_decode(text, start)
            return data
        except (ValueError, json.JSONDecodeError):
            return None


def _decode(content: bytes) -> str:
    for encoding in ("utf-8-sig", "utf-8", "latin-1", "cp1252"):
        try:
            return content.decode(encoding)
        except UnicodeDecodeError:
            continue
    return content.decode("utf-8", errors="replace")


def _parse_json(text: str) -> list[AssetSurfaceRecord]:
    data = json.loads(text)
    if isinstance(data, dict):
        if isinstance(data.get("assets"), list):
            rows = data["assets"]
        elif isinstance(data.get("items"), list):
            rows = data["items"]
        else:
            rows = [data]
    elif isinstance(data, list):
        rows = data
    else:
        rows = []
    return [_record_from_mapping(row, idx) for idx, row in enumerate(rows, 1) if isinstance(row, dict)]


def _parse_csv(text: str) -> list[AssetSurfaceRecord]:
    sample = text[:4096]
    try:
        dialect = csv.Sniffer().sniff(sample)
    except csv.Error:
        dialect = csv.excel
    reader = csv.DictReader(io.StringIO(text), dialect=dialect)
    return [_record_from_mapping(row, idx) for idx, row in enumerate(reader, 1)]


def _parse_text(text: str) -> list[AssetSurfaceRecord]:
    records: list[AssetSurfaceRecord] = []
    for idx, line in enumerate([line.strip() for line in text.splitlines() if line.strip()], 1):
        ips = _extract_ips(line)
        domains = _extract_domains(line)
        ports = _extract_ports(line)
        name = domains[0] if domains else ips[0] if ips else line[:80]
        records.append(AssetSurfaceRecord(
            asset_id=f"asset-{idx:04d}",
            name=name,
            ip_addresses=ips,
            domains=domains,
            ports=ports,
            exposure=_infer_exposure({"text": line}, ips, domains),
            technologies=_canonical_list("technology", _split_multi(line)[:12]),
            products=[],
            suppliers=[],
            dependencies=[],
            raw={"text": line},
        ))
    return records


def _record_from_mapping(row: dict[str, Any], idx: int) -> AssetSurfaceRecord:
    normalized = {str(k).strip().lower().replace(" ", "_"): v for k, v in row.items()}
    inventory_id = _first(
        normalized,
        "id",
        "asset_id",
        "cmdb_id",
        "dependency_id",
        "exposure_id",
        "component_id",
        "product_id",
    ) or f"asset-{idx:04d}"
    name = _first(
        normalized,
        "name",
        "asset",
        "hostname",
        "host",
        "fqdn",
        "domain",
        "ip",
        "ip_address",
        "product_name",
        "component_name",
        "package_name",
        "exposure_id",
        "product_family",
    ) or inventory_id
    ip_text = _first(normalized, "ip_addresses", "ips", "ip", "ip_address", "private_ip", "public_ip") or ""
    domain_text = _first(normalized, "domains", "domain", "fqdn", "dns", "url", "hostname") or ""
    port_text = _first(normalized, "ports", "open_ports", "port", "service_ports", "listeners") or ""
    tech_text = _join_fields(
        normalized,
        "technologies",
        "technology",
        "services",
        "software",
        "product",
        "stack",
        "component_type",
        "attack_surface",
        "sdk_version",
        "driver_branch",
        "firmware_version",
        "container_image",
    )
    product_text = _join_fields(
        normalized,
        "products",
        "product_names",
        "product_id",
        "product_name",
        "product_family",
        "product_line",
        "software_products",
        "applications",
        "packages",
    )
    supplier_text = _join_fields(normalized, "suppliers", "supplier", "vendor", "vendors", "manufacturer", "provider")
    dependency_text = _join_fields(
        normalized,
        "dependencies",
        "dependency",
        "dependency_id",
        "components",
        "component_id",
        "component_name",
        "package_name",
        "package_type",
        "libraries",
        "packages",
        "sbom_components",
        "purl",
        "cpe",
    )
    tags_text = _join_fields(
        normalized,
        "tags",
        "labels",
        "business_unit",
        "application",
        "trust_boundary",
        "telemetry_sources",
        "deployment_model",
        "customer_deployment_model",
        "release_channel",
        "supported_status",
        "patch_status",
        "detection_available",
        "mitigation_available",
    )
    ips = _extract_ips(str(ip_text))
    domains = _extract_domains(str(domain_text))
    ports = _extract_ports(str(port_text))
    return AssetSurfaceRecord(
        asset_id=str(inventory_id),
        name=str(name),
        asset_type=canonical_value("asset_type", _infer_asset_type(normalized)),
        environment=canonical_value("environment", _first(normalized, "environment", "env", "stage", "account", "subscription") or "unknown"),
        owner=str(_first(normalized, "owner", "team", "business_owner", "service_owner", "security_owner", "engineering_owner", "psirt_owner") or ""),
        ip_addresses=ips,
        domains=domains,
        ports=ports,
        technologies=_canonical_list("technology", _split_multi(str(tech_text))),
        products=_canonical_list("product", _split_multi(str(product_text))),
        suppliers=_canonical_list("supplier", _split_multi(str(supplier_text))),
        dependencies=_canonical_list("dependency", _split_multi(str(dependency_text))),
        exposure=_infer_exposure(normalized, ips, domains),
        criticality=_normalize_criticality(str(_first(normalized, "criticality", "business_criticality", "tier", "priority") or "medium")),
        tags=normalize_freeform_tags(str(tags_text)),
        raw=row,
    )


def _infer_asset_type(row: dict[str, Any]) -> str:
    explicit = _first(row, "type", "asset_type", "category", "kind", "component_type", "package_type", "exposure_type")
    if explicit:
        return str(explicit)
    if _first(row, "dependency_id", "package_name", "purl", "cpe"):
        return "open_source_dependency"
    if _first(row, "component_id", "component_name"):
        return "product_component"
    if _first(row, "exposure_id"):
        return "product_exposure"
    if _first(row, "product_id", "product_name", "product_family"):
        return "product"
    return "unknown"


def _looks_like_csv(text: str) -> bool:
    first = text.splitlines()[0] if text.splitlines() else ""
    return "," in first and any(h in first.lower() for h in ["asset", "host", "ip", "domain", "port", "owner"])


def _first(row: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = row.get(key)
        if value not in (None, ""):
            return value
    return None


def _join_fields(row: dict[str, Any], *keys: str) -> str:
    values = [str(row[key]) for key in keys if row.get(key) not in (None, "")]
    return ";".join(values)


def _split_multi(value: str) -> list[str]:
    return split_multi(value, limit=30)


def _canonical_list(kind: str, values: list[str]) -> list[str]:
    result = []
    for value in values:
        normalized = canonical_value(kind, value)
        if normalized and normalized not in result:
            result.append(normalized)
    return result


def _extract_ips(value: str) -> list[str]:
    return sorted(set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", value)))


def _extract_domains(value: str) -> list[str]:
    value = re.sub(r"https?://", "", value)
    candidates = re.findall(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", value)
    return sorted(set(candidates))


def _extract_ports(value: str) -> list[int]:
    value = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", " ", value)
    ports = set()
    lower = value.lower()
    explicit = re.findall(r"\b(?:tcp|udp)[:/ ]+(\d{1,5})\b|(?:port|ports|listener|listeners)[:= ]+([0-9,;/ |]+)", lower)
    for direct, grouped in explicit:
        for match in re.findall(r"\d{1,5}", direct or grouped):
            port = int(match)
            if 1 <= port <= 65535:
                ports.add(port)
    if not ports and re.fullmatch(r"[\s\d,;/|]+", lower.strip()):
        for match in re.findall(r"\d{1,5}", lower):
            port = int(match)
            if 1 <= port <= 65535:
                ports.add(port)
    for match in re.findall(r"(?<![\w.])(?:https?|ssh|rdp|smb|ldap|postgres|mysql|redis|elastic)?[:/](\d{1,5})\b", lower):
        port = int(match)
        if 1 <= port <= 65535:
            ports.add(port)
    return sorted(ports)


def _infer_exposure(row: dict[str, Any], ips: list[str], domains: list[str]) -> str:
    text = " ".join(str(v).lower() for v in row.values())
    if any(word in text for word in ["vendor", "third-party", "third party", "saas"]):
        return canonical_value("exposure", "third-party")
    if any(word in text for word in ["internet", "public", "external", "dmz", "edge"]):
        return canonical_value("exposure", "internet")
    if any(word in text for word in ["internal", "private", "corp", "lan"]):
        return canonical_value("exposure", "internal")
    if any(not _is_private_ip(ip) for ip in ips):
        return canonical_value("exposure", "internet")
    if domains and any(not _is_internal_domain(domain) for domain in domains):
        return canonical_value("exposure", "internet")
    return canonical_value("exposure", "unknown")


def _is_private_ip(ip: str) -> bool:
    parts = [int(part) for part in ip.split(".")]
    return (
        parts[0] == 10
        or parts[0] == 127
        or (parts[0] == 172 and 16 <= parts[1] <= 31)
        or (parts[0] == 192 and parts[1] == 168)
    )


def _is_internal_domain(domain: str) -> bool:
    lowered = domain.lower().strip(".")
    return lowered.endswith((".local", ".internal", ".corp", ".lan")) or ".corp." in lowered


def _normalize_criticality(value: str) -> str:
    return canonical_value("risk", value or "medium")


def _risk_signals(record: AssetSurfaceRecord) -> list[dict[str, Any]]:
    signals = []
    ports = set(record.ports)
    text = " ".join([
        record.name,
        record.asset_type,
        *record.technologies,
        *record.products,
        *record.suppliers,
        *record.dependencies,
        *record.tags,
    ]).lower()
    if record.exposure == "internet":
        signals.append({"label": "internet-facing exposure", "weight": 20})
    if record.criticality in {"critical", "high"}:
        signals.append({"label": f"{record.criticality} business criticality", "weight": 15})
    if ports & {22, 3389, 5900, 5985, 5986}:
        signals.append({"label": "remote administration service exposed", "weight": 20})
    if ports & {80, 443, 8080, 8443, 8000, 8888}:
        signals.append({"label": "web application/API surface", "weight": 12})
    if ports & {1433, 1521, 3306, 5432, 6379, 9200, 27017}:
        signals.append({"label": "database or data-store service", "weight": 18})
    if ports & {389, 636, 88, 445, 135, 139} or any(word in text for word in ["ad", "ldap", "domain controller", "identity"]):
        signals.append({"label": "identity or Windows domain surface", "weight": 18})
    if any(word in text for word in ["kubernetes", "k8s", "docker", "container", "ecs", "eks", "aks", "gke"]):
        signals.append({"label": "container orchestration surface", "weight": 14})
    if any(word in text for word in ["vpn", "citrix", "rdp", "remote", "gateway", "sso", "okta"]):
        signals.append({"label": "remote access or identity edge", "weight": 16})
    if any(word in text for word in ["s3", "blob", "bucket", "storage", "sharepoint", "backup"]):
        signals.append({"label": "cloud storage or backup surface", "weight": 12})
    if any(word in text for word in ["jenkins", "gitlab", "github", "ci/cd", "pipeline", "build"]):
        signals.append({"label": "software delivery or CI/CD surface", "weight": 14})
    if any(word in text for word in ["legacy", "eol", "unsupported", "unpatched", "outdated"]):
        signals.append({"label": "legacy or unpatched technology signal", "weight": 16})
    return signals


def _risk_level(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def _attack_surface(record: AssetSurfaceRecord, signals: list[dict[str, Any]]) -> list[str]:
    values = [signal["label"] for signal in signals]
    if not values:
        values.append("inventory-only asset; validate exposure with scanner/cloud inventory")
    return values


def _entry_points(record: AssetSurfaceRecord) -> list[str]:
    entries = []
    port_names = {
        22: "SSH",
        80: "HTTP",
        443: "HTTPS",
        445: "SMB",
        3389: "RDP",
        5432: "PostgreSQL",
        3306: "MySQL",
        6379: "Redis",
        9200: "Elasticsearch",
    }
    for port in record.ports:
        if port in port_names:
            entries.append(f"{port_names[port]} on TCP/{port}")
    if record.domains:
        entries.append("DNS/web hostname exposure")
    return entries or ["unknown; validate with current scan"]


def _ttp_candidates(record: AssetSurfaceRecord, signals: list[dict[str, Any]]) -> list[dict[str, str]]:
    labels = " ".join(signal["label"] for signal in signals)
    text = " ".join([
        record.name,
        record.asset_type,
        record.environment,
        record.exposure,
        record.criticality,
        *record.technologies,
        *record.products,
        *record.suppliers,
        *record.dependencies,
        *record.domains,
        *[str(port) for port in record.ports],
        *record.tags,
    ]).lower()
    candidates = []
    is_internet = record.exposure in {"internet", "external", "public", "customer"} or bool(record.domains)
    has = lambda *words: any(word in text for word in words)
    has_port = lambda *ports: any(port in record.ports for port in ports)
    def add(attack_id: str, name: str, reason: str) -> None:
        candidates.append({"attack_id": attack_id, "name": name, "reason": reason})

    if is_internet:
        add("T1595", "Active Scanning", "internet-facing asset can be discovered and fingerprinted before attack")
    if is_internet or has("product", "firmware", "version", "cpe", "purl"):
        add("T1592", "Gather Victim Host Information", "inventory exposes product, host, firmware, or dependency context useful for targeting")
    if has("cloud", "aws", "azure", "gcp", "kubernetes", "container", "ngc"):
        add("T1580", "Cloud Infrastructure Discovery", "cloud/container infrastructure can be enumerated after access")

    if "web application" in labels or record.domains:
        add("T1190", "Exploit Public-Facing Application", "web/API surface or hostname exposure")
    if has("web", "api", "nginx", "apache", "http", "portal", "redfish", "bmc"):
        add("T1190", "Exploit Public-Facing Application", "web, API, BMC, or management interface technology is present")
    if "remote administration" in labels or has_port(22, 3389, 5900, 445, 5985, 5986):
        add("T1021", "Remote Services", "remote administration service exposed")
    if "remote access" in labels or any(word in text for word in ["vpn", "citrix", "sso", "okta"]):
        add("T1133", "External Remote Services", "remote-access or identity edge may be abused for initial access")
        add("T1110", "Brute Force", "remote authentication surface requires lockout and MFA validation")
    if has("login", "auth", "sso", "vpn", "ldap", "kerberos", "ssh", "rdp") or has_port(22, 3389, 389, 443):
        add("T1110", "Brute Force", "authentication-facing service requires password-spray and brute-force telemetry")
    if "database" in labels:
        add("T1005", "Data from Local System", "data-store asset may expose sensitive data if compromised")
    if has("database", "postgres", "mysql", "redis", "elastic", "storage", "backup", "artifact", "registry", "source"):
        add("T1005", "Data from Local System", "data, artifact, source, or backup system could be collected after access")
    if "identity" in labels:
        add("T1078", "Valid Accounts", "identity/domain surface depends on credential controls")
        add("T1558", "Steal or Forge Kerberos Tickets", "Kerberos/AD surfaces need ticket abuse monitoring")
    if has("identity", "auth", "sso", "ldap", "kerberos", "admin", "service account", "ci", "runner", "registry"):
        add("T1078", "Valid Accounts", "credentialed access is a realistic path for this asset class")
    if has("identity", "sso", "okta", "ldap", "kerberos", "auth gateway"):
        add("T1556", "Modify Authentication Process", "identity or authentication control plane could be tampered with after compromise")
    if has("active-directory", "kerberos", "ldap", "domain controller", "ad-"):
        add("T1558", "Steal or Forge Kerberos Tickets", "AD/Kerberos context requires ticket abuse monitoring")
    if "container" in labels:
        add("T1611", "Escape to Host", "container orchestration surface requires runtime isolation validation")
    if has("container", "docker", "kubernetes", "containerd", "runtime", "ngc"):
        add("T1611", "Escape to Host", "container runtime asset may require host escape detection")
        add("T1610", "Deploy Container", "orchestrated/containerized environment can be abused to deploy malicious containers")
    if has("container image", "oci", "registry", "ngc", "base image"):
        add("T1525", "Implant Internal Image", "image registry or base image workflow can carry implanted images")
    if "cloud storage" in labels:
        add("T1530", "Data from Cloud Storage", "cloud storage or backup asset may expose bulk data if permissions are weak")
        add("T1552", "Unsecured Credentials", "storage and backup systems commonly contain secrets or configuration material")
    if has("s3", "blob", "bucket", "cloud storage", "object storage", "backup"):
        add("T1530", "Data from Cloud Storage", "object storage and backups need bulk access monitoring")
    if has("ci", "runner", "pipeline", "build", "secret", "token", "key", "hsm", "registry", "backup", "config"):
        add("T1552", "Unsecured Credentials", "build, registry, backup, or configuration systems often contain credentials")
    if "software delivery" in labels:
        add("T1195", "Supply Chain Compromise", "CI/CD and build infrastructure can affect downstream software trust")
        add("T1608", "Stage Capabilities", "build or release systems can be abused to stage modified artifacts")
    if has("ci", "cd", "build", "runner", "artifact", "registry", "sbom", "dependency", "supplier", "package", "purl", "container image"):
        add("T1195", "Supply Chain Compromise", "product, dependency, supplier, or artifact workflow is supply-chain relevant")
    if has("build", "release", "artifact", "registry", "signing", "container image", "package", "sbom", "dependency", "purl"):
        add("T1608", "Stage Capabilities", "release or artifact path could stage malicious capabilities")
    if has("runner", "build", "pipeline", "script", "shell", "powershell", "bash", "python", "nodejs"):
        add("T1059", "Command and Scripting Interpreter", "automation or runtime scripting can execute attacker-controlled commands")
    if has("artifact", "registry", "package", "download", "update", "firmware", "container image", "ngc"):
        add("T1105", "Ingress Tool Transfer", "package, update, artifact, or firmware flow can transfer payloads")
    if "legacy" in labels:
        add("T1068", "Exploitation for Privilege Escalation", "legacy or unpatched software raises local privilege-escalation risk after access")
    if has("kernel", "driver", "firmware", "bmc", "redfish", "ipmi", "cuda", "gpu driver", "dpu", "bluefield", "jetson", "igx", "openssl"):
        add("T1068", "Exploitation for Privilege Escalation", "kernel, driver, firmware, or management-plane component may expose privilege escalation risk")
    if has("firmware", "bootloader", "uefi", "secure boot", "bmc", "dpu firmware", "nic firmware"):
        add("T1542", "Pre-OS Boot", "firmware, bootloader, or secure-boot scope requires persistence validation below the OS")
    if has("edr", "agent", "kernel", "driver", "firmware", "bmc", "management plane"):
        add("T1562", "Impair Defenses", "defensive controls or low-level components may be impaired after compromise")
    if has("prototype", "hardware", "board", "jetson", "igx", "bluefield", "connectx", "dpu", "gpu"):
        add("T1200", "Hardware Additions", "hardware/product security inventory requires monitoring for physical/prototype abuse scenarios")
    if has("gpu", "cuda", "kubernetes", "cluster", "container", "cloud", "compute"):
        add("T1496", "Resource Hijacking", "compute or accelerator resources can be abused for unauthorized workloads")
    if has("backup", "storage", "database", "artifact registry", "source repository"):
        add("T1486", "Data Encrypted for Impact", "data and backup assets require impact/ransomware readiness checks")
    return candidates


def _dedupe_ttps(candidates: list[dict[str, str]]) -> list[dict[str, str]]:
    seen = set()
    deduped = []
    for item in candidates:
        attack_id = item["attack_id"].upper()
        if attack_id in seen:
            continue
        seen.add(attack_id)
        deduped.append({**item, "attack_id": attack_id})
    return deduped


def _control_gaps(record: AssetSurfaceRecord, signals: list[dict[str, Any]]) -> list[str]:
    labels = " ".join(signal["label"] for signal in signals)
    gaps = ["Inventory evidence alone does not prove current patch level, authentication strength, or logging coverage."]
    if record.exposure == "internet":
        gaps.append("Internet exposure must be checked against WAF, CDN, cloud security groups, and external scanner results.")
    if "remote administration" in labels or "remote access" in labels:
        gaps.append("MFA, conditional access, lockout policy, and jump-host restrictions are not proven by the inventory.")
    if "database" in labels or "cloud storage" in labels:
        gaps.append("Data classification, backup exposure, encryption, and access policy need separate validation.")
    if "identity" in labels:
        gaps.append("Privileged account scope, AD audit policy, and lateral-movement telemetry are not proven.")
    return gaps


def _validation_steps(record: AssetSurfaceRecord, signals: list[dict[str, Any]]) -> list[str]:
    steps = [
        "Confirm asset owner, business criticality, environment, and lifecycle status in the authoritative CMDB.",
        "Validate reachable services from attacker-relevant network locations rather than trusting inventory fields.",
    ]
    if record.domains:
        steps.append("Resolve DNS, CDN, and certificate transparency records for the listed hostnames.")
    if record.ports:
        steps.append(f"Verify exposed ports with scanner evidence: {', '.join(str(port) for port in record.ports[:12])}.")
    labels = " ".join(signal["label"] for signal in signals)
    if "web application" in labels:
        steps.append("Check application auth paths, recent CVEs, WAF logs, and web access/error telemetry.")
    if "identity" in labels:
        steps.append("Check domain controller exposure, Kerberos/LDAP logging, privileged groups, and service accounts.")
    return steps


def _detection_ideas(record: AssetSurfaceRecord, ttps: list[dict[str, str]]) -> list[str]:
    ideas = []
    for ttp in ttps:
        attack_id = ttp["attack_id"]
        if attack_id == "T1190":
            ideas.append("Hunt for exploit probes, abnormal 4xx/5xx bursts, suspicious user agents, webshell indicators, and post-exploitation child processes.")
        elif attack_id in {"T1021", "T1133"}:
            ideas.append("Monitor remote logons by source ASN/geography, impossible travel, new device fingerprints, and non-standard admin access paths.")
        elif attack_id == "T1110":
            ideas.append("Alert on password-spray patterns, lockout bursts, repeated failures across many users, and failures followed by success.")
        elif attack_id in {"T1078", "T1558"}:
            ideas.append("Correlate privileged logons, Kerberos anomalies, service-ticket volume changes, and new delegation or SPN changes.")
        elif attack_id in {"T1005", "T1530"}:
            ideas.append("Detect unusual bulk reads, archive creation, object-listing spikes, and access from new principals or regions.")
        elif attack_id in {"T1195", "T1608"}:
            ideas.append("Monitor build pipeline changes, unsigned artifact publication, new deploy keys, runner changes, and release-account activity.")
        elif attack_id in {"T1611", "T1068"}:
            ideas.append("Collect runtime, kernel, and container escape telemetry plus privileged process creation from this asset class.")
    return list(dict.fromkeys(ideas)) or ["Build asset-specific detections after scanner, EDR, identity, and network telemetry validation."]


def _priority_actions(record: AssetSurfaceRecord, signals: list[dict[str, Any]]) -> list[str]:
    actions = ["Validate owner, exposure, and criticality fields against authoritative CMDB/cloud inventory."]
    labels = " ".join(signal["label"] for signal in signals)
    if record.exposure == "internet":
        actions.append("Confirm internet exposure with external scan and cloud firewall/security-group review.")
    if "remote administration" in labels:
        actions.append("Restrict remote administration to VPN/jump hosts and enforce MFA where applicable.")
    if "web application" in labels:
        actions.append("Review patch level, WAF/rate limiting, authentication, and application logging.")
    if "database" in labels:
        actions.append("Verify database is not internet-facing and enforce network segmentation plus backup monitoring.")
    if "identity" in labels:
        actions.append("Review privileged accounts, LDAP/Kerberos exposure, audit policy, and lateral movement detections.")
    return actions


def _count(rows: list[dict[str, Any]], key: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        value = str(row.get(key) or "unknown")
        counts[value] = counts.get(value, 0) + 1
    return counts
