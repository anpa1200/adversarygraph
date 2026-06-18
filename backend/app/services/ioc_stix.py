from __future__ import annotations

import hashlib
import re
import uuid
from datetime import datetime, timezone
from typing import Any

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from app.services.ioc_intel import IOCImportItem, create_ioc_source, import_iocs, list_ioc_library

STIX_NAMESPACE = uuid.UUID("8b5f5359-613e-4ca0-b6f6-7d526b01f2d5")
STIX_IMPORT_SOURCE_ID = "custom-stix-import"
TAXII_IMPORT_SOURCE_ID = "custom-taxii-import"


async def export_ioc_stix_bundle(
    session: AsyncSession,
    *,
    search: str = "",
    indicator_type: str = "",
    source_id: str = "",
    actor: str | list[str] = "",
    sort: str = "last_seen_desc",
    limit: int = 5000,
) -> dict[str, Any]:
    library = await list_ioc_library(
        session,
        search=search,
        indicator_type=indicator_type,
        source_id=source_id,
        actor=actor,
        sort=sort,
        limit=limit,
        offset=0,
    )
    now = _stix_time(datetime.now(timezone.utc))
    identity_id = _stix_id("identity", "adversarygraph")
    objects: list[dict[str, Any]] = [
        {
            "type": "identity",
            "spec_version": "2.1",
            "id": identity_id,
            "created": now,
            "modified": now,
            "name": "AdversaryGraph",
            "identity_class": "system",
        }
    ]
    seen_ids = {identity_id}

    def add(obj: dict[str, Any]) -> None:
        if obj["id"] in seen_ids:
            return
        seen_ids.add(obj["id"])
        objects.append(obj)

    for item in library["items"]:
        if item["type"] == "malware-family":
            malware_id = _stix_id("malware", f"malware:{item['value']}")
            add(_malware_object(malware_id, item, now, identity_id))
            for actor_ref in item["actors"]:
                actor_id = _intrusion_set_id(actor_ref)
                add(_intrusion_set_object(actor_id, actor_ref, now, identity_id))
                add(_relationship("uses", actor_id, malware_id, now, identity_id, actor_ref.get("evidence", "")))
            continue

        pattern = _indicator_pattern(item["type"], item["value"])
        if not pattern:
            continue
        indicator_id = _stix_id("indicator", f"{item['type']}:{item['value']}:{item['source']}")
        add(_indicator_object(indicator_id, item, pattern, now, identity_id))
        if item.get("malware_family"):
            malware_id = _stix_id("malware", f"malware:{item['malware_family']}")
            add(_malware_object(malware_id, {**item, "value": item["malware_family"]}, now, identity_id))
            add(_relationship("indicates", indicator_id, malware_id, now, identity_id, item.get("description", "")))
        for actor_ref in item["actors"]:
            actor_id = _intrusion_set_id(actor_ref)
            add(_intrusion_set_object(actor_id, actor_ref, now, identity_id))
            add(_relationship("indicates", indicator_id, actor_id, now, identity_id, actor_ref.get("evidence", "")))

    return {
        "type": "bundle",
        "id": _stix_id("bundle", f"ioc-library:{_fingerprint(objects)}"),
        "objects": objects,
    }


async def import_ioc_stix_bundle(
    session: AsyncSession,
    bundle: dict[str, Any],
    *,
    source_id: str = STIX_IMPORT_SOURCE_ID,
    source_label: str = "STIX IOC Import",
    source_url: str = "",
) -> dict[str, Any]:
    await create_ioc_source(session, label=source_label, url=source_url or "local-stix-import", kind="custom-json", source_id=source_id)
    objects = [obj for obj in bundle.get("objects", []) if isinstance(obj, dict)]
    by_id = {obj.get("id"): obj for obj in objects if obj.get("id")}
    relationships = [obj for obj in objects if obj.get("type") == "relationship"]
    items: list[IOCImportItem] = []

    for obj in objects:
        if obj.get("type") == "indicator":
            item = _indicator_to_import_item(obj, by_id, relationships, source_id, source_url)
            if item:
                items.append(item)
        elif obj.get("type") == "observed-data":
            items.extend(_observed_data_to_import_items(obj, by_id, relationships, source_id, source_url))

    result = await import_iocs(session, items) if items else {"source": source_id, "inserted": 0, "updated": 0, "actor_links": 0}
    return {**result, "items_seen": len(items)}


async def import_taxii_collection(
    session: AsyncSession,
    *,
    objects_url: str,
    token: str = "",
    username: str = "",
    password: str = "",
    source_label: str = "TAXII IOC Import",
) -> dict[str, Any]:
    headers = {
        "Accept": "application/taxii+json;version=2.1, application/stix+json;version=2.1, application/json",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    auth = (username, password) if username and password else None
    async with httpx.AsyncClient(timeout=60, headers=headers, auth=auth) as client:
        response = await client.get(objects_url)
        response.raise_for_status()
        payload = response.json()
    bundle = payload if payload.get("type") == "bundle" else {"type": "bundle", "objects": payload.get("objects", [])}
    return await import_ioc_stix_bundle(
        session,
        bundle,
        source_id=TAXII_IMPORT_SOURCE_ID,
        source_label=source_label,
        source_url=objects_url,
    )


def _indicator_to_import_item(
    obj: dict[str, Any],
    by_id: dict[str, dict[str, Any]],
    relationships: list[dict[str, Any]],
    source_id: str,
    source_url: str,
) -> IOCImportItem | None:
    parsed = _parse_pattern(str(obj.get("pattern") or ""))
    if not parsed:
        return None
    actor, malware = _relationship_context(obj["id"], by_id, relationships)
    refs = obj.get("external_references") or []
    link = _external_url(refs) or source_url
    return IOCImportItem(
        value=parsed["value"],
        indicator_type=parsed["type"],
        actor_attack_id=actor.get("attack_id") or None,
        actor_name=actor.get("name") or None,
        malware_family=malware.get("name") or "",
        technique_ids=_extract_attack_ids(obj),
        source=source_id,
        source_url=link,
        first_seen=obj.get("valid_from") or obj.get("created"),
        last_seen=obj.get("valid_until") or obj.get("modified"),
        confidence=int(obj.get("confidence") or obj.get("x_adversarygraph_confidence") or 60),
        tlp=str(obj.get("x_adversarygraph_tlp") or "clear"),
        tags=[str(label) for label in obj.get("labels") or []],
        description=str(obj.get("description") or obj.get("name") or "STIX indicator import"),
        raw=obj,
    )


def _observed_data_to_import_items(
    obj: dict[str, Any],
    by_id: dict[str, dict[str, Any]],
    relationships: list[dict[str, Any]],
    source_id: str,
    source_url: str,
) -> list[IOCImportItem]:
    actor, malware = _relationship_context(obj.get("id", ""), by_id, relationships)
    rows = []
    for sco in (obj.get("objects") or {}).values():
        if not isinstance(sco, dict):
            continue
        parsed = _sco_value(sco)
        if not parsed:
            continue
        rows.append(
            IOCImportItem(
                value=parsed["value"],
                indicator_type=parsed["type"],
                actor_attack_id=actor.get("attack_id") or None,
                actor_name=actor.get("name") or None,
                malware_family=malware.get("name") or "",
                source=source_id,
                source_url=source_url,
                first_seen=obj.get("first_observed") or obj.get("created"),
                last_seen=obj.get("last_observed") or obj.get("modified"),
                confidence=int(obj.get("confidence") or 50),
                tags=["stix-observed-data"],
                description=str(obj.get("description") or "STIX observed-data import"),
                raw=obj,
            )
        )
    return rows


def _relationship_context(source_object_id: str, by_id: dict[str, dict[str, Any]], relationships: list[dict[str, Any]]) -> tuple[dict[str, str], dict[str, str]]:
    actor: dict[str, str] = {}
    malware: dict[str, str] = {}
    for rel in relationships:
        if rel.get("source_ref") != source_object_id and rel.get("target_ref") != source_object_id:
            continue
        other_id = rel.get("target_ref") if rel.get("source_ref") == source_object_id else rel.get("source_ref")
        other = by_id.get(other_id) or {}
        if other.get("type") == "intrusion-set":
            actor = {"name": str(other.get("name") or ""), "attack_id": _mitre_external_id(other)}
        elif other.get("type") == "malware":
            malware = {"name": str(other.get("name") or "")}
    return actor, malware


def _parse_pattern(pattern: str) -> dict[str, str] | None:
    patterns = [
        ("sha256", r"file:hashes\.'SHA-256'\s*=\s*'([^']+)'"),
        ("sha1", r"file:hashes\.'SHA-1'\s*=\s*'([^']+)'"),
        ("md5", r"file:hashes\.MD5\s*=\s*'([^']+)'"),
        ("ipv4", r"ipv4-addr:value\s*=\s*'([^']+)'"),
        ("ipv6", r"ipv6-addr:value\s*=\s*'([^']+)'"),
        ("domain", r"domain-name:value\s*=\s*'([^']+)'"),
        ("url", r"url:value\s*=\s*'([^']+)'"),
    ]
    for kind, regex in patterns:
        match = re.search(regex, pattern, flags=re.I)
        if match:
            return {"type": kind, "value": match.group(1)}
    return None


def _sco_value(sco: dict[str, Any]) -> dict[str, str] | None:
    stix_type = sco.get("type")
    if stix_type == "ipv4-addr" and sco.get("value"):
        return {"type": "ipv4", "value": str(sco["value"])}
    if stix_type == "ipv6-addr" and sco.get("value"):
        return {"type": "ipv6", "value": str(sco["value"])}
    if stix_type == "domain-name" and sco.get("value"):
        return {"type": "domain", "value": str(sco["value"])}
    if stix_type == "url" and sco.get("value"):
        return {"type": "url", "value": str(sco["value"])}
    if stix_type == "file":
        hashes = sco.get("hashes") or {}
        for key, kind in [("SHA-256", "sha256"), ("SHA-1", "sha1"), ("MD5", "md5")]:
            if hashes.get(key):
                return {"type": kind, "value": str(hashes[key])}
    return None


def _indicator_pattern(kind: str, value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace("'", "\\'")
    normalized = _strip_port(value)
    normalized_escaped = normalized.replace("\\", "\\\\").replace("'", "\\'")
    if kind in {"ipv4", "ip"}:
        return f"[ipv4-addr:value = '{normalized_escaped}']"
    if kind == "ipv6":
        return f"[ipv6-addr:value = '{normalized_escaped}']"
    if kind == "ip:port":
        return f"[ipv4-addr:value = '{normalized_escaped}']" if "." in normalized else f"[ipv6-addr:value = '{normalized_escaped}']"
    if kind == "domain":
        return f"[domain-name:value = '{_strip_port(escaped)}']"
    if kind == "url":
        return f"[url:value = '{escaped}']"
    if kind == "sha256":
        return f"[file:hashes.'SHA-256' = '{escaped}']"
    if kind == "sha1":
        return f"[file:hashes.'SHA-1' = '{escaped}']"
    if kind == "md5":
        return f"[file:hashes.MD5 = '{escaped}']"
    return ""


def _strip_port(value: str) -> str:
    if value.count(":") == 1:
        host, port = value.rsplit(":", 1)
        if port.isdigit():
            return host
    return value


def _indicator_object(stix_id: str, item: dict[str, Any], pattern: str, now: str, identity_id: str) -> dict[str, Any]:
    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": stix_id,
        "created": now,
        "modified": now,
        "created_by_ref": identity_id,
        "name": item["value"],
        "description": item.get("description") or "",
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": _date_or_now(item.get("first_seen"), now),
        "labels": [item["type"], *(item.get("tags") or [])],
        "confidence": item.get("confidence", 50),
        "external_references": _external_refs(item),
        "x_adversarygraph_source": item.get("source"),
        "x_adversarygraph_tlp": item.get("tlp"),
        "x_adversarygraph_technique_ids": item.get("technique_ids") or [],
    }


def _malware_object(stix_id: str, item: dict[str, Any], now: str, identity_id: str) -> dict[str, Any]:
    return {
        "type": "malware",
        "spec_version": "2.1",
        "id": stix_id,
        "created": now,
        "modified": now,
        "created_by_ref": identity_id,
        "name": item.get("malware_family") or item.get("value") or "Malware family",
        "is_family": True,
        "description": item.get("description") or "",
        "external_references": _external_refs(item),
    }


def _intrusion_set_object(stix_id: str, actor_ref: dict[str, Any], now: str, identity_id: str) -> dict[str, Any]:
    external_refs = []
    if actor_ref.get("actor_attack_id"):
        external_refs.append({"source_name": "mitre-attack", "external_id": actor_ref["actor_attack_id"]})
    return {
        "type": "intrusion-set",
        "spec_version": "2.1",
        "id": stix_id,
        "created": now,
        "modified": now,
        "created_by_ref": identity_id,
        "name": actor_ref.get("actor_name") or actor_ref.get("actor_attack_id") or "Threat actor",
        "description": actor_ref.get("evidence") or "",
        "external_references": external_refs,
        "x_mitre_id": actor_ref.get("actor_attack_id") or "",
    }


def _relationship(kind: str, source_ref: str, target_ref: str, now: str, identity_id: str, description: str = "") -> dict[str, Any]:
    return {
        "type": "relationship",
        "spec_version": "2.1",
        "id": _stix_id("relationship", f"{kind}:{source_ref}:{target_ref}"),
        "created": now,
        "modified": now,
        "created_by_ref": identity_id,
        "relationship_type": kind,
        "source_ref": source_ref,
        "target_ref": target_ref,
        "description": description[:500] if description else "",
    }


def _intrusion_set_id(actor_ref: dict[str, Any]) -> str:
    return _stix_id("intrusion-set", f"intrusion-set:{actor_ref.get('actor_attack_id') or actor_ref.get('actor_name')}")


def _external_refs(item: dict[str, Any]) -> list[dict[str, str]]:
    refs = [{"source_name": str(item.get("source") or "adversarygraph")}]
    if item.get("source_url"):
        refs[0]["url"] = str(item["source_url"])
    return refs


def _external_url(refs: list[Any]) -> str:
    for ref in refs:
        if isinstance(ref, dict) and ref.get("url"):
            return str(ref["url"])
    return ""


def _mitre_external_id(obj: dict[str, Any]) -> str:
    if obj.get("x_mitre_id"):
        return str(obj["x_mitre_id"])
    for ref in obj.get("external_references") or []:
        if isinstance(ref, dict) and ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return str(ref["external_id"])
    return ""


def _extract_attack_ids(value: Any) -> list[str]:
    return sorted(set(re.findall(r"\bT\d{4}(?:\.\d{3})?\b", str(value), flags=re.I)))


def _date_or_now(value: str | None, fallback: str) -> str:
    if not value:
        return fallback
    text = str(value).replace(" UTC", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
        return _stix_time(parsed)
    except Exception:
        return fallback


def _stix_id(stix_type: str, key: str) -> str:
    return f"{stix_type}--{uuid.uuid5(STIX_NAMESPACE, key)}"


def _stix_time(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _fingerprint(objects: list[dict[str, Any]]) -> str:
    raw = "|".join(sorted(obj["id"] for obj in objects))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
