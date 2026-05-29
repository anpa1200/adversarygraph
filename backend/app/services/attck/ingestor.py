"""
Parses MITRE ATT&CK STIX 2.1 JSON bundles and upserts into PostgreSQL.

Uses stdlib json only — no mitreattack-python, no stix2, no distutils.
Fully compatible with Python 3.12+.
"""

import json
import logging
from pathlib import Path

from sqlalchemy import create_engine, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.attack import (
    AptGroup,
    AptGroupTechnique,
    AttackVersion,
    Tactic,
    Technique,
    TechniqueTactic,
)
from app.services.attck.downloader import ensure_bundle

logger = logging.getLogger(__name__)

_sync_url = settings.database_url.replace("+asyncpg", "+psycopg2")
_sync_engine = create_engine(_sync_url, echo=False, pool_pre_ping=True)


# ── STIX helpers ──────────────────────────────────────────────────────────────

def _attack_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def _attack_url(obj: dict) -> str:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("url", "")
    return ""


def _ext_refs(obj: dict) -> list[dict]:
    return [
        {
            "source_name": r.get("source_name", ""),
            "url":         r.get("url", ""),
            "description": r.get("description", ""),
        }
        for r in obj.get("external_references", [])
    ]


def _is_stale(obj: dict) -> bool:
    return bool(obj.get("x_mitre_deprecated") or obj.get("revoked"))


# ── Bundle parser ─────────────────────────────────────────────────────────────

def parse_bundle(bundle_path: Path) -> dict:
    """
    Read a STIX 2.1 JSON bundle and return plain-dict lists ready for upsert.
    No external libraries required.
    """
    logger.info("Parsing %s ...", bundle_path.name)
    raw = json.loads(bundle_path.read_bytes())

    by_id: dict[str, dict] = {}
    relationships: list[dict] = []

    for obj in raw.get("objects", []):
        if obj.get("type") == "relationship":
            relationships.append(obj)
        else:
            by_id[obj["id"]] = obj

    tactics:    list[dict] = []
    techniques: list[dict] = []
    groups:     list[dict] = []

    for obj in by_id.values():
        if _is_stale(obj):
            continue
        t = obj.get("type", "")

        if t == "x-mitre-tactic":
            aid = _attack_id(obj)
            if aid:
                tactics.append({
                    "attack_id":   aid,
                    "stix_id":     obj["id"],
                    "name":        obj.get("name", ""),
                    "shortname":   obj.get("x_mitre_shortname", ""),
                    "description": obj.get("description", ""),
                    "url":         _attack_url(obj),
                })

        elif t == "attack-pattern":
            aid = _attack_id(obj)
            if aid:
                is_sub = bool(obj.get("x_mitre_is_subtechnique"))
                parent = aid.split(".")[0] if is_sub and "." in aid else None
                # Accept mitre-attack / mitre-mobile-attack / mitre-ics-attack
                tactic_shortnames = [
                    kcp["phase_name"]
                    for kcp in obj.get("kill_chain_phases", [])
                    if kcp.get("kill_chain_name", "").startswith("mitre-")
                ]
                techniques.append({
                    "attack_id":        aid,
                    "stix_id":          obj["id"],
                    "name":             obj.get("name", ""),
                    "description":      obj.get("description", ""),
                    "url":              _attack_url(obj),
                    "is_subtechnique":  is_sub,
                    "parent_attack_id": parent,
                    "platforms":        obj.get("x_mitre_platforms", []) or [],
                    "data_sources":     obj.get("x_mitre_data_sources", []) or [],
                    "detection":        obj.get("x_mitre_detection", "") or "",
                    "tactic_shortnames": tactic_shortnames,
                })

        elif t == "intrusion-set":
            aid = _attack_id(obj)
            if aid:
                name = obj.get("name", "")
                aliases = [a for a in (obj.get("aliases") or []) if a != name]
                groups.append({
                    "attack_id":   aid,
                    "stix_id":     obj["id"],
                    "name":        name,
                    "description": obj.get("description", ""),
                    "aliases":     aliases,
                    "url":         _attack_url(obj),
                })

    # Group → Technique usage relationships
    group_stix_ids = {g["stix_id"] for g in groups}
    tech_stix_ids  = {t["stix_id"] for t in techniques}

    usages: list[dict] = []
    for rel in relationships:
        if (
            rel.get("relationship_type") == "uses"
            and rel.get("source_ref") in group_stix_ids
            and rel.get("target_ref") in tech_stix_ids
        ):
            usages.append({
                "group_stix_id":     rel["source_ref"],
                "technique_stix_id": rel["target_ref"],
                "description":       rel.get("description", "") or "",
                "refs":              _ext_refs(rel),
            })

    logger.info(
        "  Parsed: %d tactics, %d techniques, %d groups, %d usages",
        len(tactics), len(techniques), len(groups), len(usages),
    )
    return {
        "tactics":    tactics,
        "techniques": techniques,
        "groups":     groups,
        "usages":     usages,
    }


# ── DB upsert ─────────────────────────────────────────────────────────────────

def ingest_domain(domain: str, bundle_path: Path, version: str) -> None:
    data = parse_bundle(bundle_path)

    with Session(_sync_engine) as session:
        # ── Version record ────────────────────────────────────────────────────
        stmt = (
            insert(AttackVersion)
            .values(domain=domain, version=version, is_latest=True)
            .on_conflict_do_nothing(constraint="uq_domain_version")
            .returning(AttackVersion.id)
        )
        row = session.execute(stmt).fetchone()
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

        # ── Tactics ───────────────────────────────────────────────────────────
        shortname_to_db_id: dict[str, int] = {}
        for t in data["tactics"]:
            stmt = (
                insert(Tactic)
                .values(
                    attack_id=t["attack_id"], name=t["name"],
                    shortname=t["shortname"], description=t["description"],
                    url=t["url"], domain=domain, version_id=version_id,
                )
                .on_conflict_do_nothing(constraint="uq_tactic_version")
                .returning(Tactic.id)
            )
            row = session.execute(stmt).fetchone()
            db_id = row[0] if row else session.scalar(
                select(Tactic.id).where(
                    Tactic.attack_id == t["attack_id"],
                    Tactic.version_id == version_id,
                )
            )
            if db_id and t["shortname"]:
                shortname_to_db_id[t["shortname"]] = db_id

        logger.info("  Ingested %d tactics", len(shortname_to_db_id))

        # ── Techniques ────────────────────────────────────────────────────────
        stix_id_to_tech_db_id: dict[str, int] = {}
        attack_id_to_tech_db_id: dict[str, int] = {}

        for t in data["techniques"]:
            stmt = (
                insert(Technique)
                .values(
                    attack_id=t["attack_id"], stix_id=t["stix_id"],
                    name=t["name"], description=t["description"],
                    url=t["url"], is_subtechnique=t["is_subtechnique"],
                    parent_attack_id=t["parent_attack_id"],
                    platforms=t["platforms"], data_sources=t["data_sources"],
                    detection=t["detection"], domain=domain,
                    version_id=version_id, is_deprecated=False,
                )
                .on_conflict_do_nothing(constraint="uq_technique_version")
                .returning(Technique.id)
            )
            row = session.execute(stmt).fetchone()
            db_id = row[0] if row else session.scalar(
                select(Technique.id).where(
                    Technique.attack_id == t["attack_id"],
                    Technique.version_id == version_id,
                )
            )
            if db_id:
                stix_id_to_tech_db_id[t["stix_id"]] = db_id
                attack_id_to_tech_db_id[t["attack_id"]] = db_id

        logger.info("  Ingested %d techniques", len(stix_id_to_tech_db_id))

        # ── Technique ↔ Tactic links ──────────────────────────────────────────
        tt_count = 0
        for t in data["techniques"]:
            tech_db_id = stix_id_to_tech_db_id.get(t["stix_id"])
            if not tech_db_id:
                continue
            for shortname in t["tactic_shortnames"]:
                tactic_db_id = shortname_to_db_id.get(shortname)
                if tactic_db_id:
                    session.execute(
                        insert(TechniqueTactic)
                        .values(technique_id=tech_db_id, tactic_id=tactic_db_id)
                        .on_conflict_do_nothing()
                    )
                    tt_count += 1

        logger.info("  Ingested %d technique-tactic links", tt_count)

        # ── APT Groups ────────────────────────────────────────────────────────
        group_stix_to_db_id: dict[str, int] = {}
        for g in data["groups"]:
            stmt = (
                insert(AptGroup)
                .values(
                    attack_id=g["attack_id"], stix_id=g["stix_id"],
                    name=g["name"], description=g["description"],
                    aliases=g["aliases"], url=g["url"],
                    domain=domain, version_id=version_id,
                )
                .on_conflict_do_nothing(constraint="uq_group_version")
                .returning(AptGroup.id)
            )
            row = session.execute(stmt).fetchone()
            db_id = row[0] if row else session.scalar(
                select(AptGroup.id).where(
                    AptGroup.attack_id == g["attack_id"],
                    AptGroup.version_id == version_id,
                )
            )
            if db_id:
                group_stix_to_db_id[g["stix_id"]] = db_id

        logger.info("  Ingested %d APT groups", len(group_stix_to_db_id))

        # ── Group → Technique usages ──────────────────────────────────────────
        usage_count = 0
        for u in data["usages"]:
            group_db_id = group_stix_to_db_id.get(u["group_stix_id"])
            tech_db_id  = stix_id_to_tech_db_id.get(u["technique_stix_id"])
            if not group_db_id or not tech_db_id:
                continue
            session.execute(
                insert(AptGroupTechnique)
                .values(
                    group_id=group_db_id, technique_id=tech_db_id,
                    use_description=u["description"], references=u["refs"],
                )
                .on_conflict_do_nothing(constraint="uq_group_technique")
            )
            usage_count += 1

        logger.info("  Ingested %d group-technique usages", usage_count)
        session.commit()

    logger.info("Finished ingesting %s v%s", domain, version)


# ── Entry point ───────────────────────────────────────────────────────────────

def run_ingest() -> None:
    for domain in settings.attck_domain_list:
        try:
            bundle_path, version = ensure_bundle(domain, settings.attck_data_dir)
            ingest_domain(domain, bundle_path, version)
        except Exception as exc:
            logger.error("Failed to ingest %s: %s", domain, exc, exc_info=True)
