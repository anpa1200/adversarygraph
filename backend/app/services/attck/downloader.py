"""Downloads ATT&CK STIX bundles from MITRE's GitHub repository."""

import logging
import os
from pathlib import Path

import requests

logger = logging.getLogger(__name__)

GITHUB_CONTENTS_URL = (
    "https://api.github.com/repos/mitre-attack/attack-stix-data/contents/{domain}"
)
RAW_BUNDLE_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master"
    "/{domain}/{domain}-{version}.json"
)


def get_latest_version(domain: str) -> str:
    """Query the MITRE GitHub repo to find the highest available ATT&CK version."""
    url = GITHUB_CONTENTS_URL.format(domain=domain)
    headers = {"Accept": "application/vnd.github.v3+json"}

    resp = requests.get(url, headers=headers, timeout=30)
    resp.raise_for_status()
    files = resp.json()

    versions: list[tuple[int, ...]] = []
    for entry in files:
        filename: str = entry.get("name", "")
        if not filename.endswith(".json"):
            continue
        stem = filename.replace(f"{domain}-", "").replace(".json", "")
        try:
            parts = tuple(int(x) for x in stem.split("."))
            versions.append(parts)
        except ValueError:
            continue

    if not versions:
        raise RuntimeError(f"No STIX bundles found for domain: {domain}")

    latest = max(versions)
    version_str = ".".join(str(x) for x in latest)
    logger.info("Latest ATT&CK version for %s: %s", domain, version_str)
    return version_str


def download_bundle(domain: str, version: str, data_dir: str) -> Path:
    """Download the STIX bundle for a domain/version, skipping if already cached."""
    dest = Path(data_dir) / f"{domain}-{version}.json"

    if dest.exists():
        logger.info("Using cached STIX bundle: %s", dest)
        return dest

    dest.parent.mkdir(parents=True, exist_ok=True)
    url = RAW_BUNDLE_URL.format(domain=domain, version=version)
    logger.info("Downloading %s ...", url)

    resp = requests.get(url, stream=True, timeout=120)
    resp.raise_for_status()

    tmp = dest.with_suffix(".tmp")
    try:
        with tmp.open("wb") as fh:
            for chunk in resp.iter_content(chunk_size=65536):
                fh.write(chunk)
        tmp.rename(dest)
    except Exception:
        tmp.unlink(missing_ok=True)
        raise

    logger.info("Saved %s (%.1f MB)", dest.name, dest.stat().st_size / 1_048_576)
    return dest


def ensure_bundle(domain: str, data_dir: str) -> tuple[Path, str]:
    """Return (path, version) for the latest bundle, downloading if needed."""
    version = get_latest_version(domain)
    path = download_bundle(domain, version, data_dir)
    return path, version
