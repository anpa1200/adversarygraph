from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.core.safe_http import safe_get
from app.models.asset_surface import AssetRegistryItem


EMB3D_VERSION = "2.0.1"
EMB3D_STIX_URL = f"https://emb3d.mitre.org/assets/emb3d-stix-{EMB3D_VERSION}.json"
EMB3D_CACHE_PATH = Path("/app/data/emb3d") / f"emb3d-stix-{EMB3D_VERSION}.json"


class Emb3dDataUnavailable(RuntimeError):
    """Raised when neither cached nor upstream EMB3D reference data is usable."""


@dataclass(frozen=True)
class Emb3dPropertyMatch:
    property_id: str
    confidence: int
    evidence: tuple[str, ...]


@dataclass
class Emb3dKnowledgeBase:
    version: str
    source_url: str
    properties: dict[str, dict[str, Any]]
    threats: dict[str, dict[str, Any]]
    mitigations: dict[str, dict[str, Any]]
    property_to_threats: dict[str, list[str]] = field(default_factory=dict)
    threat_to_mitigations: dict[str, list[str]] = field(default_factory=dict)
    property_hierarchy: dict[str, list[str]] = field(default_factory=dict)


def load_emb3d_knowledge_base(
    *,
    source_url: str = EMB3D_STIX_URL,
    cache_path: Path = EMB3D_CACHE_PATH,
) -> Emb3dKnowledgeBase:
    bundle = _load_bundle(source_url=source_url, cache_path=cache_path)
    return parse_emb3d_bundle(bundle, source_url=source_url)


def parse_emb3d_bundle(bundle: dict[str, Any], *, source_url: str = EMB3D_STIX_URL) -> Emb3dKnowledgeBase:
    stix_to_public_id: dict[str, str] = {}
    properties: dict[str, dict[str, Any]] = {}
    threats: dict[str, dict[str, Any]] = {}
    mitigations: dict[str, dict[str, Any]] = {}

    for obj in bundle.get("objects", []):
        obj_type = obj.get("type")
        if obj_type == "x-mitre-emb3d-property":
            public_id = str(obj.get("x_mitre_emb3d_property_id") or obj.get("id"))
            stix_to_public_id[obj["id"]] = public_id
            properties[public_id] = {
                "id": public_id,
                "name": obj.get("name", ""),
                "category": obj.get("category", ""),
                "is_subproperty": bool(obj.get("is_subproperty")),
                "stix_id": obj.get("id", ""),
            }
        elif obj_type == "vulnerability":
            public_id = str(obj.get("x_mitre_emb3d_threat_id") or obj.get("id"))
            stix_to_public_id[obj["id"]] = public_id
            threats[public_id] = {
                "id": public_id,
                "name": obj.get("name", ""),
                "description": _compact_text(obj.get("description", "")),
                "category": obj.get("x_mitre_emb3d_threat_category", ""),
                "maturity": obj.get("x_mitre_emb3d_threat_maturity", ""),
                "cwes": _extract_cwe_ids(obj.get("x_mitre_emb3d_threat_CWEs", "")),
                "cves": _extract_cve_ids(obj.get("x_mitre_emb3d_threat_CVEs", "")),
                "stix_id": obj.get("id", ""),
            }
        elif obj_type == "course-of-action":
            public_id = str(obj.get("x_mitre_emb3d_mitigation_id") or obj.get("id"))
            stix_to_public_id[obj["id"]] = public_id
            mitigations[public_id] = {
                "id": public_id,
                "name": obj.get("name", ""),
                "description": _compact_text(obj.get("description", "")),
                "maturity": obj.get("x_mitre_emb3d_mitigation_maturity", ""),
                "stix_id": obj.get("id", ""),
            }

    property_to_threats: dict[str, list[str]] = {}
    threat_to_mitigations: dict[str, list[str]] = {}
    property_hierarchy: dict[str, list[str]] = {}
    for obj in bundle.get("objects", []):
        if obj.get("type") != "relationship":
            continue
        source_id = stix_to_public_id.get(obj.get("source_ref", ""))
        target_id = stix_to_public_id.get(obj.get("target_ref", ""))
        if not source_id or not target_id:
            continue
        relationship_type = obj.get("relationship_type")
        if relationship_type == "relates-to" and source_id in properties and target_id in threats:
            property_to_threats.setdefault(source_id, []).append(target_id)
        elif relationship_type == "mitigates" and source_id in mitigations and target_id in threats:
            threat_to_mitigations.setdefault(target_id, []).append(source_id)
        elif relationship_type == "subproperty-of" and source_id in properties and target_id in properties:
            property_hierarchy.setdefault(target_id, []).append(source_id)

    for mapping in (property_to_threats, threat_to_mitigations, property_hierarchy):
        for key, values in mapping.items():
            mapping[key] = sorted(set(values), key=_emb3d_sort_key)

    return Emb3dKnowledgeBase(
        version=EMB3D_VERSION,
        source_url=source_url,
        properties=properties,
        threats=threats,
        mitigations=mitigations,
        property_to_threats=property_to_threats,
        threat_to_mitigations=threat_to_mitigations,
        property_hierarchy=property_hierarchy,
    )


def assess_assets_with_emb3d(
    assets: list[AssetRegistryItem],
    kb: Emb3dKnowledgeBase,
) -> dict[str, Any]:
    asset_reports = [assess_asset_with_emb3d(asset, kb) for asset in assets]
    threat_counts: dict[str, int] = {}
    property_counts: dict[str, int] = {}
    category_counts: dict[str, int] = {}
    mitigation_counts: dict[str, int] = {}
    for report in asset_reports:
        for prop in report["properties"]:
            property_counts[prop["id"]] = property_counts.get(prop["id"], 0) + 1
            category = prop.get("category") or "Unknown"
            category_counts[category] = category_counts.get(category, 0) + 1
        for threat in report["threats"]:
            threat_counts[threat["id"]] = threat_counts.get(threat["id"], 0) + 1
            for mitigation in threat.get("mitigations", []):
                mitigation_counts[mitigation["id"]] = mitigation_counts.get(mitigation["id"], 0) + 1

    return {
        "version": kb.version,
        "source_url": kb.source_url,
        "asset_count": len(asset_reports),
        "property_count": len(property_counts),
        "threat_count": len(threat_counts),
        "mitigation_count": len(mitigation_counts),
        "category_counts": dict(sorted(category_counts.items())),
        "top_threats": _ranked_objects(threat_counts, kb.threats, "affected_assets", limit=20),
        "top_properties": _ranked_objects(property_counts, kb.properties, "matched_assets", limit=20),
        "top_mitigations": _ranked_objects(mitigation_counts, kb.mitigations, "recommended_for_threats", limit=20),
        "assets": asset_reports,
    }


def assess_asset_with_emb3d(asset: AssetRegistryItem, kb: Emb3dKnowledgeBase) -> dict[str, Any]:
    matches = infer_emb3d_properties(asset)
    properties: list[dict[str, Any]] = []
    threat_ids: set[str] = set()
    for match in matches:
        prop = kb.properties.get(match.property_id)
        if not prop:
            continue
        linked_threat_ids = kb.property_to_threats.get(match.property_id, [])
        threat_ids.update(linked_threat_ids)
        properties.append({
            **prop,
            "confidence": match.confidence,
            "evidence": list(match.evidence),
            "threat_count": len(linked_threat_ids),
        })

    threat_reports: list[dict[str, Any]] = []
    for threat_id in sorted(threat_ids, key=_emb3d_sort_key):
        threat = kb.threats.get(threat_id)
        if not threat:
            continue
        linked_properties = [
            item for item in properties
            if threat_id in kb.property_to_threats.get(item["id"], [])
        ]
        mitigation_ids = kb.threat_to_mitigations.get(threat_id, [])
        threat_reports.append({
            **threat,
            "properties": [{"id": item["id"], "name": item["name"], "confidence": item["confidence"]} for item in linked_properties],
            "mitigations": [kb.mitigations[mid] for mid in mitigation_ids if mid in kb.mitigations],
        })

    return {
        "asset_id": str(asset.id),
        "inventory_asset_id": asset.inventory_asset_id,
        "name": asset.name,
        "asset_type": asset.asset_type,
        "environment": asset.environment,
        "exposure": asset.exposure,
        "criticality": asset.criticality,
        "risk_score": asset.risk_score or 0,
        "risk_level": asset.risk_level or "low",
        "properties": sorted(properties, key=lambda item: (_emb3d_sort_key(item["id"]), -item["confidence"])),
        "threats": threat_reports,
        "threat_count": len(threat_reports),
        "mitigation_count": len({
            mitigation["id"]
            for threat in threat_reports
            for mitigation in threat.get("mitigations", [])
        }),
    }


def infer_emb3d_properties(asset: AssetRegistryItem) -> list[Emb3dPropertyMatch]:
    text = _asset_text(asset)
    ports = {int(port) for port in (asset.ports or []) if isinstance(port, int) or str(port).isdigit()}
    candidates: dict[str, Emb3dPropertyMatch] = {}

    def add(property_id: str, confidence: int, *evidence: str) -> None:
        clean = tuple(item for item in evidence if item)
        existing = candidates.get(property_id)
        if existing and existing.confidence >= confidence:
            merged = tuple(dict.fromkeys([*existing.evidence, *clean]))[:6]
            candidates[property_id] = Emb3dPropertyMatch(property_id, existing.confidence, merged)
            return
        candidates[property_id] = Emb3dPropertyMatch(property_id, confidence, clean[:6])

    if _has(text, "embedded", "iot", "sensor", "controller", "plc", "bmc", "firmware", "router", "gateway", "edge", "device"):
        add("PID-11", 72, "asset appears to be embedded/device-class hardware")
    if _has(text, "flash", "eeprom", "nvram", "rom", "sdcard", "storage", "emmc", "nand"):
        add("PID-12", 72, "asset references external memory or persistent storage")
    if _has(text, "rom", "nvram", "removable", "sdcard", "usb-storage"):
        add("PID-123", 76, "asset references ROM, NVRAM, or removable storage")
    if _has(text, "usb", "serial", "rs232", "rs485", "canbus", "can-bus", "peripheral"):
        add("PID-14", 78, "asset references external peripheral interconnects")
    if _has(text, "jtag", "uart", "swd", "debug-port", "debug port"):
        add("PID-15", 90, "asset references hardware debug or access ports")

    if _has(text, "bootloader", "secure_boot", "secure boot", "uefi", "u-boot", "trusted boot"):
        add("PID-21", 84, "asset references bootloader or boot integrity features")
    if _has(text, "debug", "debugger", "diagnostic", "diagnostics"):
        add("PID-22", 72, "asset references debugging or diagnostic capabilities")
    if _has(text, "linux", "windows", "android", "rtos", "ubuntu", "debian", "kernel", "os:", "bmc"):
        add("PID-23", 86, "asset references an OS or kernel")
    if _has(text, "driver", "kernel module", "module", "dkms"):
        add("PID-231", 78, "asset references loadable drivers or modules")
    if _has(text, "user account", "users", "rbac", "privilege", "permission"):
        add("PID-232", 72, "asset references multiple users, processes, or privileges")
    if _has(text, "docker", "container", "containerd", "kubernetes", "k8s", "podman", "oci"):
        add("PID-24", 82, "asset references virtualization or containers")
        add("PID-241", 88, "asset references containers")
    if _has(text, "hypervisor", "vmware", "esxi", "kvm", "xen"):
        add("PID-24", 82, "asset references virtualization")
        add("PID-242", 88, "asset references a hypervisor")
    if _has(text, "tpm", "hsm", "root of trust", "secure element", "trustzone", "secure_boot", "secure boot"):
        add("PID-25", 84, "asset references a root of trust or secure element")
    if _has(text, "firmware", "software update", "ota", "update server", "upgrade"):
        add("PID-27", 80, "asset references firmware or software update support")
    if _has(text, "ota", "remote update", "update server", "firmware-management"):
        add("PID-275", 84, "asset references remotely initiated updates")
    if _has(text, "signed firmware", "signature", "secure_boot", "secure boot", "integrity", "verified boot"):
        add("PID-272", 82, "asset references cryptographic integrity validation")
    if _has(text, "unencrypted firmware", "unsigned firmware", "http firmware", "cleartext update"):
        add("PID-271", 86, "asset references missing firmware integrity validation")
    if _has(text, "http firmware", "unencrypted update", "cleartext update"):
        add("PID-273", 86, "asset references unencrypted firmware updates")
    if _has(text, "syslog", "logging", "audit log", "event log", "logs"):
        add("PID-28", 72, "asset references system event logging")

    if asset.technologies or asset.products or asset.dependencies or _has(text, "application", "service", "runtime", "app"):
        add("PID-31", 78, "asset has application software, services, products, or dependencies")
    if ports & {80, 443, 8080, 8081, 8443} or _has(text, "http", "https", "web", "nginx", "apache", "lighttpd", "nodejs", "react"):
        add("PID-311", 88, "asset exposes or uses web/HTTP application components")
    if _has(text, "python", "java", "php", "javascript", "nodejs", "golang", "rust", "openssl", "library", "libraries"):
        add("PID-312", 76, "asset references programming languages or libraries")
    if _has(text, "java", "python", "php", "c++", "cpp", "object-oriented"):
        add("PID-3121", 70, "asset references object-oriented programming languages")
    if _has(text, "c++", "cpp", "c language", "firmware", "rtos", "native"):
        add("PID-3122", 74, "asset likely includes manually managed native code")
    if _has(text, "ladder", "custom program", "runtime", "script", "plugin", "extension", "compiled binary"):
        add("PID-32", 76, "asset references custom or external program deployment")
    if _has(text, "runtime", "jvm", "nodejs", "python", "plc"):
        add("PID-322", 72, "asset references a program runtime environment")
    if _has(text, "elf", "exe", "binary", "compiled"):
        add("PID-323", 76, "asset references executable program formats")
    if ports or _has(text, "ui", "interface", "service", "api", "console", "portal"):
        add("PID-33", 78, "asset has interactive services, APIs, or user interfaces")
    if _has(text, "unauthenticated", "noauth", "anonymous"):
        add("PID-331", 88, "asset references unauthenticated services")
    if _has(text, "authenticated", "auth", "sso", "mfa", "login", "oauth", "saml"):
        add("PID-332", 82, "asset references authenticated services")
    if _has(text, "password", "basic auth", "credentials"):
        add("PID-3321", 80, "asset references password-based authentication")
    if _has(text, "tls", "ssl", "https", "certificate", "oauth", "saml", "mfa", "crypto"):
        add("PID-3322", 76, "asset references cryptographic authentication or session protection")
    if _has(text, "app log", "audit log", "logging", "logs"):
        add("PID-34", 72, "asset references application event logging")

    if ports or asset.domains or asset.ip_addresses or asset.exposure in {"internet", "external", "public"}:
        add("PID-41", 84, "asset has network identifiers, ports, or remote exposure")
    if ports or _has(text, "api", "management", "config", "admin", "portal", "redfish", "ipmi", "modbus", "mqtt"):
        add("PID-411", 80, "asset exposes services that may modify data or configuration")
    if _has(text, "modbus", "telnet", "ftp", "snmpv1", "snmpv2", "unauthenticated"):
        add("PID-4111", 82, "asset references protocols commonly lacking message authentication")
    if ports & {21, 23, 80, 1883, 502} or _has(text, "telnet", "ftp", "http:", "cleartext", "unencrypted", "modbus", "mqtt"):
        add("PID-4112", 78, "asset references cleartext protocols or ports")
    if ports & {443, 8443} or _has(text, "tls", "ssl", "https", "certificate", "encryption", "crypto"):
        add("PID-4113", 80, "asset references encryption or authentication cryptography")
    if _has(text, "router", "gateway", "firewall", "switch", "forward", "route"):
        add("PID-42", 84, "asset forwards or routes network messages")

    return sorted(candidates.values(), key=lambda item: _emb3d_sort_key(item.property_id))


def catalog_summary(kb: Emb3dKnowledgeBase) -> dict[str, Any]:
    categories: dict[str, int] = {}
    for prop in kb.properties.values():
        category = prop.get("category") or "Unknown"
        categories[category] = categories.get(category, 0) + 1
    return {
        "version": kb.version,
        "source_url": kb.source_url,
        "property_count": len(kb.properties),
        "threat_count": len(kb.threats),
        "mitigation_count": len(kb.mitigations),
        "relationship_count": sum(len(items) for items in kb.property_to_threats.values()) + sum(len(items) for items in kb.threat_to_mitigations.values()),
        "categories": dict(sorted(categories.items())),
    }


def _load_bundle(*, source_url: str, cache_path: Path) -> dict[str, Any]:
    try:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        if cache_path.exists():
            cached = json.loads(cache_path.read_text(encoding="utf-8"))
            if isinstance(cached, dict) and isinstance(cached.get("objects"), list):
                return cached
    except (OSError, json.JSONDecodeError):
        pass

    try:
        response = safe_get(source_url, timeout=30)
        response.raise_for_status()
        bundle = response.json()
    except Exception as exc:
        raise Emb3dDataUnavailable(
            "EMB3D reference data is unavailable. Configure outbound access once "
            f"to populate {cache_path}, or mount a valid cached STIX bundle."
        ) from exc
    if not isinstance(bundle, dict) or not isinstance(bundle.get("objects"), list):
        raise Emb3dDataUnavailable("The EMB3D upstream response is not a valid STIX bundle.")
    try:
        cache_path.write_text(json.dumps(bundle), encoding="utf-8")
    except OSError:
        pass
    return bundle


def _asset_text(asset: AssetRegistryItem) -> str:
    parts = [
        asset.inventory_asset_id,
        asset.name,
        asset.asset_type,
        asset.environment,
        asset.exposure,
        asset.criticality,
        *(asset.technologies or []),
        *(asset.products or []),
        *(asset.suppliers or []),
        *(asset.dependencies or []),
        *(asset.tags or []),
        *[str(item) for item in (asset.ports or [])],
        json.dumps(asset.labels or {}, sort_keys=True),
        json.dumps(asset.raw or {}, sort_keys=True),
    ]
    return " ".join(str(part).lower() for part in parts if part)


def _has(text: str, *needles: str) -> bool:
    return any(needle.lower() in text for needle in needles)


def _extract_cwe_ids(value: str) -> list[str]:
    return sorted(set(re.findall(r"CWE-\d+", value or "")))


def _extract_cve_ids(value: str) -> list[str]:
    return sorted(set(re.findall(r"CVE-\d{4}-\d{4,}", value or "", re.IGNORECASE)))


def _compact_text(value: str, limit: int = 1200) -> str:
    text = re.sub(r"\s+", " ", value or "").strip()
    if len(text) <= limit:
        return text
    return text[: limit - 3].rstrip() + "..."


def _ranked_objects(counts: dict[str, int], catalog: dict[str, dict[str, Any]], count_key: str, *, limit: int) -> list[dict[str, Any]]:
    ranked = sorted(counts.items(), key=lambda item: (-item[1], _emb3d_sort_key(item[0])))[:limit]
    return [{**catalog[item_id], count_key: count} for item_id, count in ranked if item_id in catalog]


def _emb3d_sort_key(value: str) -> tuple[str, int, str]:
    match = re.match(r"([A-Z]+)-(\d+)$", value or "")
    if not match:
        return (value or "", 0, value or "")
    return (match.group(1), int(match.group(2)), value)
