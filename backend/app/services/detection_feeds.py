from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.safe_http import safe_get
from app.core.version import APP_USER_AGENT
from app.models.pipeline import CollectionRun, CollectionSource, DetectionVersion
from app.services.detections import validate_detection

ATTACK_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
SIGMAHQ_RULES_URL = "https://github.com/SigmaHQ/sigma/tree/master/rules"
YARA_RULES_URL = "https://github.com/Yara-Rules/rules/tree/master/malware"
YARA_RULE_URLS = [
    "https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/APT_Duqu2.yar",
    "https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/APT_Hikit.yar",
    "https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/APT_PutterPanda.yar",
    "https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/APT_Waterbug.yar",
    "https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/MALW_Empire.yar",
    "https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/RAT_PlugX.yar",
    "https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/RANSOM_SamSam.yar",
    "https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/TOOLKIT_Redteam_Tools_by_GUID.yar",
]
HTTP_HEADERS = {
    "Accept": "application/vnd.github+json, application/json, text/plain, */*",
    "User-Agent": f"{APP_USER_AGENT} detection-feed-sync",
}


@dataclass
class DetectionRuleItem:
    title: str
    technique_id: str
    format: str
    content: str
    source_url: str
    rule_id: str = ""


async def ensure_default_detection_feeds(session: AsyncSession) -> list[CollectionSource]:
    defaults = [
        {
            "name": "SigmaHQ Rules",
            "kind": "sigma",
            "url": SIGMAHQ_RULES_URL,
            "enabled": True,
            "interval_minutes": 1440,
            "config": {"limit": 250},
        },
        {
            "name": "Yara-Rules Malware Rules",
            "kind": "yara",
            "url": YARA_RULES_URL,
            "enabled": True,
            "interval_minutes": 1440,
            "config": {
                "limit": 250,
                "license": "GPL-2.0-or-later",
                "source": "https://github.com/Yara-Rules/rules",
                "rule_urls": YARA_RULE_URLS,
            },
        },
    ]
    rows: list[CollectionSource] = []
    for item in defaults:
        existing = (
            await session.execute(
                select(CollectionSource).where(CollectionSource.kind == item["kind"], CollectionSource.url == item["url"])
            )
        ).scalar_one_or_none()
        if existing:
            rows.append(existing)
            continue
        row = CollectionSource(**item)
        session.add(row)
        await session.flush()
        rows.append(row)
    await session.commit()
    return rows


async def sync_detection_rule_feed(session: AsyncSession, source: CollectionSource) -> CollectionRun:
    if source.kind not in {"sigma", "yara"}:
        raise ValueError(f"{source.kind.upper()} is not a Sigma/YARA detection-rule feed")
    limit = int((source.config or {}).get("limit") or 100)
    limit = max(1, min(limit, 100))
    run = CollectionRun(source_id=source.id)
    session.add(run)
    await session.flush()
    try:
        items = fetch_detection_rules(source.url, source.kind, limit=limit, explicit_urls=(source.config or {}).get("rule_urls"))
        imported = 0
        for item in items:
            if await _upsert_detection_version(session, item, source.name):
                imported += 1
        run.status = "complete"
        run.items_seen = len(items)
        run.items_created = imported
        source.last_run_at = datetime.now(timezone.utc)
    except Exception as exc:
        run.status = "failed"
        run.error = str(exc)[:2000]
    run.completed_at = datetime.now(timezone.utc)
    await session.commit()
    await session.refresh(run)
    return run


def fetch_detection_rules(url: str, kind: str, limit: int = 250, explicit_urls: list[str] | None = None) -> list[DetectionRuleItem]:
    kind = kind.lower()
    candidates = _candidate_rule_urls(url, kind, limit, explicit_urls=explicit_urls)
    items: list[DetectionRuleItem] = []
    for rule_url in candidates[:limit]:
        try:
            response = safe_get(rule_url, timeout=30, headers=HTTP_HEADERS)
            response.raise_for_status()
        except ValueError:
            # SSRF guard blocked the URL — skip silently
            continue
        except Exception:
            continue
        parsed = _parse_rule_text(response.text, kind, rule_url)
        if parsed:
            items.append(parsed)
    if not items and _looks_like_rule_url(url, kind):
        response = safe_get(url, timeout=30, headers=HTTP_HEADERS)
        response.raise_for_status()
        parsed = _parse_rule_text(response.text, kind, url)
        if parsed:
            items.append(parsed)
    return items


def _candidate_rule_urls(url: str, kind: str, limit: int, explicit_urls: list[str] | None = None) -> list[str]:
    if explicit_urls:
        return [item for item in explicit_urls if isinstance(item, str) and _looks_like_rule_url(item, kind)][:limit]
    if "github.com" in url and "/tree/" in url:
        return _github_tree_rule_urls(url, kind, limit)
    response = safe_get(url, timeout=45, headers=HTTP_HEADERS)
    response.raise_for_status()
    text = response.text
    content_type = response.headers.get("content-type", "")
    if _looks_like_rule_url(url, kind):
        return [url]
    if "application/json" in content_type or text.lstrip().startswith(("[", "{")):
        return _urls_from_json(text, kind)
    urls = [item.rstrip(".,)") for item in URL_RE.findall(text)]
    return [item for item in urls if _looks_like_rule_url(item, kind)]


def _github_tree_rule_urls(url: str, kind: str, limit: int) -> list[str]:
    parsed = urlparse(url)
    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) < 5 or parts[2] != "tree":
        return []
    owner, repo, branch = parts[0], parts[1], parts[3]
    prefix = "/".join(parts[4:]).strip("/")
    api_url = f"https://api.github.com/repos/{owner}/{repo}/git/trees/{branch}?recursive=1"
    try:
        response = requests.get(api_url, timeout=60, headers=HTTP_HEADERS)
        response.raise_for_status()
        tree = response.json().get("tree") or []
    except requests.RequestException:
        return _github_tree_rule_urls_via_git(owner, repo, branch, prefix, kind, limit)
    urls: list[str] = []
    for item in tree:
        path = str(item.get("path") or "")
        if item.get("type") != "blob" or not path.startswith(prefix):
            continue
        if not _path_matches_kind(path, kind):
            continue
        urls.append(f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}")
        if len(urls) >= limit:
            break
    return urls


def _github_tree_rule_urls_via_git(owner: str, repo: str, branch: str, prefix: str, kind: str, limit: int) -> list[str]:
    if not shutil.which("git"):
        raise RuntimeError("GitHub API tree listing failed and git is not installed in the runtime image")
    repo_url = f"https://github.com/{owner}/{repo}.git"
    with tempfile.TemporaryDirectory(prefix="adversarygraph-rules-") as tmpdir:
        target = Path(tmpdir) / repo
        clone = subprocess.run(
            ["git", "clone", "--depth", "1", "--filter=blob:none", "--sparse", "--branch", branch, repo_url, str(target)],
            check=False,
            capture_output=True,
            text=True,
            timeout=120,
        )
        if clone.returncode != 0:
            raise RuntimeError((clone.stderr or clone.stdout or "git clone failed").strip()[:500])
        sparse = subprocess.run(
            ["git", "-C", str(target), "sparse-checkout", "set", prefix],
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
        if sparse.returncode != 0:
            raise RuntimeError((sparse.stderr or sparse.stdout or "git sparse-checkout failed").strip()[:500])
        urls: list[str] = []
        for path in sorted(target.rglob("*")):
            if not path.is_file():
                continue
            relative = path.relative_to(target).as_posix()
            if not _path_matches_kind(relative, kind):
                continue
            urls.append(f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{relative}")
            if len(urls) >= limit:
                break
        return urls


def _urls_from_json(text: str, kind: str) -> list[str]:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return []
    urls: list[str] = []
    stack: list[Any] = [payload]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
        elif isinstance(item, str) and item.startswith("http") and _looks_like_rule_url(item, kind):
            urls.append(item)
    return urls


def _parse_rule_text(text: str, kind: str, source_url: str) -> DetectionRuleItem | None:
    technique_ids = sorted({match.upper() for match in ATTACK_ID_RE.findall(text)})
    if not technique_ids:
        sigma_tags = re.findall(r"attack\.t(\d{4}(?:\.\d{3})?)", text, flags=re.IGNORECASE)
        technique_ids = sorted({f"T{item.upper()}" for item in sigma_tags})
    title = _metadata_value(text, "title") or _yara_rule_name(text) or source_url.rsplit("/", 1)[-1]
    rule_id = _metadata_value(text, "id")
    if not text.strip():
        return None
    return DetectionRuleItem(
        title=title[:500],
        technique_id=(technique_ids[0] if technique_ids else "UNMAPPED"),
        format=kind,
        content=text,
        source_url=source_url,
        rule_id=rule_id,
    )


async def _upsert_detection_version(session: AsyncSession, item: DetectionRuleItem, source_name: str) -> bool:
    created_by = f"feed:{source_name}"
    existing = (
        await session.execute(
            select(DetectionVersion).where(
                DetectionVersion.title == item.title,
                DetectionVersion.format == item.format,
                DetectionVersion.created_by == created_by,
            )
        )
    ).scalar_one_or_none()
    validation = validate_detection(item.format, item.content)
    validation["source_url"] = item.source_url
    validation["rule_id"] = item.rule_id
    if existing:
        existing.content = item.content
        existing.technique_id = item.technique_id
        existing.validation = validation
        return False
    session.add(
        DetectionVersion(
            title=item.title,
            technique_id=item.technique_id,
            format=item.format,
            content=item.content,
            validation=validation,
            created_by=created_by,
        )
    )
    return True


def _metadata_value(text: str, key: str) -> str:
    match = re.search(rf"(?m)^\s*{re.escape(key)}\s*:\s*[\"']?(.+?)[\"']?\s*$", text)
    return match.group(1).strip() if match else ""


def _yara_rule_name(text: str) -> str:
    match = re.search(r"(?m)^\s*(?:private\s+|global\s+)*rule\s+([A-Za-z0-9_:-]+)", text)
    return match.group(1) if match else ""


def _looks_like_rule_url(url: str, kind: str) -> bool:
    path = urlparse(url).path.lower()
    return _path_matches_kind(path, kind)


def _path_matches_kind(path: str, kind: str) -> bool:
    path = path.lower()
    if kind == "sigma":
        return path.endswith((".yml", ".yaml")) and (path.startswith("rules/") or "/rules/" in path)
    if kind == "yara":
        return path.endswith((".yar", ".yara"))
    return False
