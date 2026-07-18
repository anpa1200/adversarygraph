from __future__ import annotations

import re
import defusedxml.ElementTree as ET

import httpx

from app.core.safe_http import async_safe_get

OBSERVABLE_PATTERNS = {
    "cve": re.compile(r"\bCVE-\d{4}-\d{4,8}\b", re.I),
    "ipv4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "domain": re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"),
}


def extract_observables(text: str) -> list[dict]:
    found: dict[tuple[str, str], dict] = {}
    for kind, pattern in OBSERVABLE_PATTERNS.items():
        for match in pattern.findall(text or ""):
            value = match.lower().rstrip(".")
            if kind == "ipv4" and any(int(part) > 255 for part in value.split(".")):
                continue
            found[(kind, value)] = {"type": kind, "value": match, "normalized_value": value}
    return list(found.values())


async def fetch_rss(url: str) -> list[dict]:
    # async_safe_get validates the URL and pins a public IP at connect time.
    response = await async_safe_get(url, timeout=20, headers={"User-Agent": "AdversaryGraph/0.8"})
    response.raise_for_status()
    root = ET.fromstring(response.content)
    entries = root.findall(".//item") or root.findall(".//{http://www.w3.org/2005/Atom}entry")
    output = []
    for entry in entries[:100]:
        def value(names: list[str], current_entry=entry) -> str:
            for name in names:
                node = current_entry.find(name)
                if node is not None:
                    return (node.text or node.attrib.get("href") or "").strip()
            return ""
        output.append({
            "title": value(["title", "{http://www.w3.org/2005/Atom}title"]) or "Untitled feed item",
            "url": value(["link", "{http://www.w3.org/2005/Atom}link"]),
            "summary": value(["description", "summary", "{http://www.w3.org/2005/Atom}summary", "{http://www.w3.org/2005/Atom}content"]),
        })
    return output


def stix_reports(bundle: dict) -> list[dict]:
    reports = []
    for obj in bundle.get("objects", []):
        if obj.get("type") in {"report", "note", "indicator"}:
            reports.append({
                "title": obj.get("name") or obj.get("type", "STIX object").title(),
                "url": next((ref.get("url", "") for ref in obj.get("external_references", []) if ref.get("url")), ""),
                "summary": obj.get("description", ""),
                "indicators": extract_observables(obj.get("pattern", "") + " " + obj.get("description", "")),
            })
    return reports


def misp_reports(event: dict) -> list[dict]:
    event = event.get("Event", event)
    indicators = []
    for attr in event.get("Attribute", []):
        value = str(attr.get("value", ""))
        extracted = extract_observables(value)
        indicators.extend(extracted)
        if value and not extracted:
            indicators.append({"type": attr.get("type", "unknown"), "value": value, "normalized_value": value.lower()})
    return [{"title": event.get("info", "MISP event"), "url": event.get("url", ""), "summary": event.get("analysis", ""), "indicators": indicators}]
