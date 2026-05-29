"""
Compares the ATT&CK versions currently in PostgreSQL against the
latest available releases on MITRE's GitHub.

All DB access here is synchronous (called from Celery workers and startup).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.attack import AttackVersion
from app.services.attck.downloader import get_latest_version

logger = logging.getLogger(__name__)


def _get_engine():
    """Lazy engine creation so psycopg2 is only required when actually called."""
    sync_url = settings.database_url.replace("+asyncpg", "+psycopg2")
    return create_engine(sync_url, pool_pre_ping=True)


@dataclass
class DomainStatus:
    domain: str
    current_version: str | None
    latest_version: str | None
    needs_update: bool
    last_ingested: str | None      # ISO-8601 or None


def get_status() -> list[DomainStatus]:
    """
    For each configured domain return:
      - what version is in the database (current_version)
      - what version is available on GitHub (latest_version)
      - whether a re-ingest is needed
    """
    results: list[DomainStatus] = []

    with Session(_get_engine()) as session:
        for domain in settings.attck_domain_list:
            # Current DB version
            row = session.execute(
                select(AttackVersion).where(
                    AttackVersion.domain == domain,
                    AttackVersion.is_latest.is_(True),
                )
            ).scalar_one_or_none()

            current = row.version if row else None
            ingested_at = row.ingested_at.isoformat() if row and row.ingested_at else None

            # Latest GitHub version
            try:
                latest = get_latest_version(domain)
            except Exception as exc:
                logger.warning("Could not check GitHub for %s: %s", domain, exc)
                latest = None

            needs_update = bool(latest and current != latest)

            results.append(DomainStatus(
                domain=domain,
                current_version=current,
                latest_version=latest,
                needs_update=needs_update,
                last_ingested=ingested_at,
            ))

    return results


def sync_outdated_domains() -> dict[str, str]:
    """
    Download and ingest any domains that have a newer GitHub version than
    what is stored in the database.  Returns {domain: action} pairs.
    """
    from app.services.attck.ingestor import ingest_domain
    from app.services.attck.downloader import download_bundle

    actions: dict[str, str] = {}

    for status in get_status():
        if not status.needs_update:
            actions[status.domain] = "up-to-date"
            continue

        logger.info(
            "Updating %s: %s → %s",
            status.domain,
            status.current_version,
            status.latest_version,
        )
        try:
            path = download_bundle(
                status.domain,
                status.latest_version,       # type: ignore[arg-type]
                settings.attck_data_dir,
            )
            ingest_domain(status.domain, path, status.latest_version)  # type: ignore[arg-type]
            actions[status.domain] = f"updated to {status.latest_version}"
        except Exception as exc:
            logger.error("Failed to update %s: %s", status.domain, exc, exc_info=True)
            actions[status.domain] = f"error: {exc}"

    return actions
