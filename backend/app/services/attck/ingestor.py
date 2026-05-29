"""
Parses MITRE ATT&CK STIX bundles and upserts data into PostgreSQL.

Runs at API startup (via FastAPI lifespan) in a thread pool to avoid
blocking the event loop during the initial large-file parse.
"""

import logging
from pathlib import Path

from mitreattack.stix20 import MitreAttackData
from sqlalchemy import select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session
from sqlalchemy import create_engine

from app.core.config import settings
from app.models.attack import AttackVersion, AptGroup, AptGroupTechnique, Tactic, Technique, TechniqueTactic
from app.services.attck.downloader import ensure_bundle

logger = logging.getLogger(__name__)

# Sync engine for the ingestor (runs in a thread, not async context)
_sync_url = settings.database_url.replace("+asyncpg", "+psycopg2")
_sync_engine = create_engine(_sync_url, echo=False, pool_pre_ping=True)


def _get_attack_id(obj) -> str | None:
    for ref in getattr(obj, "external_references", []) or []:
        if getattr(ref, "source_name", "") == "mitre-attack":
            return ref.external_id
    return None


def _get_url(obj) -> str:
    for ref in getattr(obj, "external_references", []) or []:
        if getattr(ref, "source_name", "") == "mitre-attack":
            return getattr(ref, "url", "") or ""
    return ""


def _get_refs(obj) -> list[dict]:
    refs = []
    for ref in getattr(obj, "external_references", []) or []:
        refs.append({
            "source_name": getattr(ref, "source_name", ""),
            "url": getattr(ref, "url", ""),
            "description": getattr(ref, "description", ""),
        })
    return refs


def ingest_domain(domain: str, bundle_path: Path, version: str) -> None:
    """Parse one ATT&CK STIX bundle and upsert everything into the database."""
    logger.info("Ingesting %s v%s from %s ...", domain, version, bundle_path)

    data = MitreAttackData(str(bundle_path))

    with Session(_sync_engine) as session:
        # ── Version record ────────────────────────────────────────────────
        stmt = (
            insert(AttackVersion)
            .values(domain=domain, version=version, is_latest=True)
            .on_conflict_do_nothing(constraint="uq_domain_version")
            .returning(AttackVersion.id)
        )
        result = session.execute(stmt)
        row = result.fetchone()
        if row:
            version_id = row[0]
        else:
            version_id = session.scalar(
                select(AttackVersion.id).where(
                    AttackVersion.domain == domain,
                    AttackVersion.version == version,
                )
            )

        session.execute(
            update(AttackVersion)
            .where(AttackVersion.domain == domain, AttackVersion.id != version_id)
            .values(is_latest=False)
        )

        # ── Tactics ───────────────────────────────────────────────────────
        tactics_raw = data.get_tactics()
        tactic_shortname_to_id: dict[str, int] = {}

        for tactic in tactics_raw:
            attack_id = _get_attack_id(tactic)
            if not attack_id:
                continue
            shortname = getattr(tactic, "x_mitre_shortname", "") or ""
            stmt = (
                insert(Tactic)
                .values(
                    attack_id=attack_id,
                    name=tactic.name,
                    shortname=shortname,
                    description=getattr(tactic, "description", "") or "",
                    url=_get_url(tactic),
                    domain=domain,
                    version_id=version_id,
                )
                .on_conflict_do_nothing(constraint="uq_tactic_version")
                .returning(Tactic.id)
            )
            result = session.execute(stmt)
            row = result.fetchone()
            if row:
                tactic_db_id = row[0]
            else:
                tactic_db_id = session.scalar(
                    select(Tactic.id).where(
                        Tactic.attack_id == attack_id,
                        Tactic.version_id == version_id,
                    )
                )
            if shortname and tactic_db_id:
                tactic_shortname_to_id[shortname] = tactic_db_id

        logger.info("  Ingested %d tactics", len(tactic_shortname_to_id))

        # ── Techniques & Sub-techniques ───────────────────────────────────
        techniques_raw = data.get_techniques(
            include_subtechniques=True, remove_revoked_deprecated=True
        )
        attack_id_to_db_id: dict[str, int] = {}

        for tech in techniques_raw:
            attack_id = _get_attack_id(tech)
            if not attack_id:
                continue

            is_sub = getattr(tech, "x_mitre_is_subtechnique", False) or False
            parent_attack_id: str | None = None
            if is_sub:
                # T1566.001 → parent is T1566
                parent_attack_id = attack_id.split(".")[0]

            platforms = list(getattr(tech, "x_mitre_platforms", []) or [])
            data_sources = list(getattr(tech, "x_mitre_data_sources", []) or [])
            detection = getattr(tech, "x_mitre_detection", "") or ""

            stmt = (
                insert(Technique)
                .values(
                    attack_id=attack_id,
                    stix_id=tech.id,
                    name=tech.name,
                    description=getattr(tech, "description", "") or "",
                    url=_get_url(tech),
                    is_subtechnique=is_sub,
                    parent_attack_id=parent_attack_id,
                    platforms=platforms,
                    data_sources=data_sources,
                    detection=detection,
                    domain=domain,
                    version_id=version_id,
                    is_deprecated=False,
                )
                .on_conflict_do_nothing(constraint="uq_technique_version")
                .returning(Technique.id)
            )
            result = session.execute(stmt)
            row = result.fetchone()
            if row:
                tech_db_id = row[0]
            else:
                tech_db_id = session.scalar(
                    select(Technique.id).where(
                        Technique.attack_id == attack_id,
                        Technique.version_id == version_id,
                    )
                )
            if tech_db_id:
                attack_id_to_db_id[attack_id] = tech_db_id

        logger.info("  Ingested %d techniques", len(attack_id_to_db_id))

        # ── Technique ↔ Tactic links ──────────────────────────────────────
        tt_rows = 0
        for tech in techniques_raw:
            attack_id = _get_attack_id(tech)
            if not attack_id or attack_id not in attack_id_to_db_id:
                continue
            tech_db_id = attack_id_to_db_id[attack_id]

            for kcp in getattr(tech, "kill_chain_phases", []) or []:
                if kcp.kill_chain_name != "mitre-attack":
                    continue
                tactic_db_id = tactic_shortname_to_id.get(kcp.phase_name)
                if not tactic_db_id:
                    continue
                session.execute(
                    insert(TechniqueTactic)
                    .values(technique_id=tech_db_id, tactic_id=tactic_db_id)
                    .on_conflict_do_nothing()
                )
                tt_rows += 1

        logger.info("  Ingested %d technique-tactic links", tt_rows)

        # ── APT Groups ────────────────────────────────────────────────────
        groups_raw = data.get_groups()
        stix_id_to_group_db_id: dict[str, int] = {}

        for group in groups_raw:
            attack_id = _get_attack_id(group)
            if not attack_id:
                continue
            aliases = list(getattr(group, "aliases", []) or [])
            if group.name in aliases:
                aliases.remove(group.name)

            stmt = (
                insert(AptGroup)
                .values(
                    attack_id=attack_id,
                    stix_id=group.id,
                    name=group.name,
                    description=getattr(group, "description", "") or "",
                    aliases=aliases,
                    url=_get_url(group),
                    domain=domain,
                    version_id=version_id,
                )
                .on_conflict_do_nothing(constraint="uq_group_version")
                .returning(AptGroup.id)
            )
            result = session.execute(stmt)
            row = result.fetchone()
            if row:
                group_db_id = row[0]
            else:
                group_db_id = session.scalar(
                    select(AptGroup.id).where(
                        AptGroup.attack_id == attack_id,
                        AptGroup.version_id == version_id,
                    )
                )
            if group_db_id:
                stix_id_to_group_db_id[group.id] = group_db_id

        logger.info("  Ingested %d APT groups", len(stix_id_to_group_db_id))

        # ── Group → Technique usage links ─────────────────────────────────
        gt_rows = 0
        for group in groups_raw:
            group_db_id = stix_id_to_group_db_id.get(group.id)
            if not group_db_id:
                continue

            try:
                usages = data.get_techniques_used_by_group(group.id)
            except Exception:
                continue

            for usage in usages:
                tech_obj = usage.get("object")
                rel = usage.get("relationship")
                if not tech_obj:
                    continue

                tech_attack_id = _get_attack_id(tech_obj)
                if not tech_attack_id:
                    continue

                # Find across all versions in our map
                tech_db_id = attack_id_to_db_id.get(tech_attack_id)
                if not tech_db_id:
                    continue

                use_desc = getattr(rel, "description", "") or "" if rel else ""
                refs = _get_refs(rel) if rel else []

                session.execute(
                    insert(AptGroupTechnique)
                    .values(
                        group_id=group_db_id,
                        technique_id=tech_db_id,
                        use_description=use_desc,
                        references=refs,
                    )
                    .on_conflict_do_nothing(constraint="uq_group_technique")
                )
                gt_rows += 1

        logger.info("  Ingested %d group-technique usages", gt_rows)
        session.commit()

    logger.info("Finished ingesting %s v%s", domain, version)


def run_ingest() -> None:
    """Entry point: download and ingest all configured ATT&CK domains."""
    domains = settings.attck_domain_list
    data_dir = settings.attck_data_dir

    for domain in domains:
        try:
            bundle_path, version = ensure_bundle(domain, data_dir)
            ingest_domain(domain, bundle_path, version)
        except Exception as exc:
            logger.error("Failed to ingest %s: %s", domain, exc, exc_info=True)
