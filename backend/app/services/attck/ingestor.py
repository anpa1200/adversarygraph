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
    AptGroupCampaign,
    AptGroupTechnique,
    AttackVersion,
    Campaign,
    CampaignTechnique,
    StixObject,
    StixRelationship,
    Tactic,
    Technique,
    TechniqueTactic,
)
from app.services.attck.downloader import ensure_bundle

logger = logging.getLogger(__name__)

_sync_url = settings.sync_database_url
_sync_engine = create_engine(_sync_url, echo=False, pool_pre_ping=True)


# ── STIX helpers ──────────────────────────────────────────────────────────────

def _source_name_for_domain(domain: str) -> str:
    return "mitre-atlas" if domain == "atlas" else "mitre-attack"


def _kill_chain_for_domain(domain: str) -> str:
    return "mitre-atlas" if domain == "atlas" else "mitre-"


def _attack_id(obj: dict, source_name: str = "mitre-attack") -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == source_name:
            return ref.get("external_id")
    return None


def _attack_url(obj: dict, source_name: str = "mitre-attack") -> str:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == source_name:
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

def parse_bundle(bundle_path: Path, domain: str = "enterprise-attack") -> dict:
    """
    Read a STIX 2.1 JSON bundle and return plain-dict lists ready for upsert.
    No external libraries required.
    """
    logger.info("Parsing %s ...", bundle_path.name)
    raw = json.loads(bundle_path.read_bytes())
    source_name = _source_name_for_domain(domain)
    kill_chain_prefix = _kill_chain_for_domain(domain)

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
    campaigns:  list[dict] = []
    stix_objects: list[dict] = []

    for obj in by_id.values():
        stix_objects.append({
            "stix_id": obj["id"],
            "stix_type": obj.get("type", ""),
            "attack_id": _attack_id(obj, source_name),
            "name": obj.get("name", ""),
            "is_deprecated": bool(obj.get("x_mitre_deprecated")),
            "is_revoked": bool(obj.get("revoked")),
            "raw": obj,
        })
        if _is_stale(obj):
            continue
        t = obj.get("type", "")

        if t == "x-mitre-tactic":
            aid = _attack_id(obj, source_name)
            if aid:
                tactics.append({
                    "attack_id":   aid,
                    "stix_id":     obj["id"],
                    "name":        obj.get("name", ""),
                    "shortname":   obj.get("x_mitre_shortname", ""),
                    "description": obj.get("description", ""),
                    "url":         _attack_url(obj, source_name),
                })

        elif t == "attack-pattern":
            aid = _attack_id(obj, source_name)
            if aid:
                is_sub = bool(obj.get("x_mitre_is_subtechnique"))
                parent = aid.rsplit(".", 1)[0] if is_sub and "." in aid else None
                # Accept ATT&CK chains (mitre-attack / mobile / ics) or ATLAS.
                tactic_shortnames = [
                    kcp["phase_name"]
                    for kcp in obj.get("kill_chain_phases", [])
                    if kcp.get("kill_chain_name", "").startswith(kill_chain_prefix)
                ]
                techniques.append({
                    "attack_id":        aid,
                    "stix_id":          obj["id"],
                    "name":             obj.get("name", ""),
                    "description":      obj.get("description", ""),
                    "url":              _attack_url(obj, source_name),
                    "is_subtechnique":  is_sub,
                    "parent_attack_id": parent,
                    "platforms":        obj.get("x_mitre_platforms", []) or [],
                    "data_sources":     obj.get("x_mitre_data_sources", []) or [],
                    "detection":        obj.get("x_mitre_detection", "") or "",
                    "tactic_shortnames": tactic_shortnames,
                })

        elif t == "intrusion-set":
            aid = _attack_id(obj, source_name)
            if aid:
                name = obj.get("name", "")
                aliases = [a for a in (obj.get("aliases") or []) if a != name]
                groups.append({
                    "attack_id":   aid,
                    "stix_id":     obj["id"],
                    "name":        name,
                    "description": obj.get("description", ""),
                    "aliases":     aliases,
                    "url":         _attack_url(obj, source_name),
                    "created":     obj.get("created", "") or "",
                    "modified":    obj.get("modified", "") or "",
                    "attack_version": obj.get("x_mitre_version", "") or "",
                    "contributors": obj.get("x_mitre_contributors", []) or [],
                    "external_references": _ext_refs(obj),
                })

        elif t == "campaign":
            aid = _attack_id(obj, source_name)
            if aid:
                campaigns.append({
                    "attack_id":   aid,
                    "stix_id":     obj["id"],
                    "name":        obj.get("name", ""),
                    "description": obj.get("description", ""),
                    "url":         _attack_url(obj, source_name),
                    "first_seen":  obj.get("first_seen", "") or "",
                    "last_seen":   obj.get("last_seen", "") or "",
                })

    group_stix_ids    = {g["stix_id"] for g in groups}
    campaign_stix_ids = {c["stix_id"] for c in campaigns}
    tech_stix_ids     = {t["stix_id"] for t in techniques}

    # Group → Technique usage relationships
    usages: list[dict] = []
    # Campaign → Technique usage relationships
    campaign_tech_usages: list[dict] = []
    # Campaign → Group attribution relationships
    campaign_group_links: list[dict] = []

    for rel in relationships:
        rtype      = rel.get("relationship_type")
        source_ref = rel.get("source_ref", "")
        target_ref = rel.get("target_ref", "")

        if rtype == "uses":
            if source_ref in group_stix_ids and target_ref in tech_stix_ids:
                usages.append({
                    "group_stix_id":     source_ref,
                    "technique_stix_id": target_ref,
                    "description":       rel.get("description", "") or "",
                    "refs":              _ext_refs(rel),
                })
            elif source_ref in campaign_stix_ids and target_ref in tech_stix_ids:
                campaign_tech_usages.append({
                    "campaign_stix_id":  source_ref,
                    "technique_stix_id": target_ref,
                    "description":       rel.get("description", "") or "",
                    "refs":              _ext_refs(rel),
                })

        elif rtype == "attributed-to":
            # campaign --attributed-to--> intrusion-set
            if source_ref in campaign_stix_ids and target_ref in group_stix_ids:
                campaign_group_links.append({
                    "campaign_stix_id": source_ref,
                    "group_stix_id":    target_ref,
                })

    logger.info(
        "  Parsed: %d tactics, %d techniques, %d groups, %d usages, "
        "%d campaigns, %d campaign-tech, %d campaign-group, %d STIX objects, %d STIX relationships",
        len(tactics), len(techniques), len(groups), len(usages),
        len(campaigns), len(campaign_tech_usages), len(campaign_group_links),
        len(stix_objects), len(relationships),
    )
    return {
        "tactics":              tactics,
        "techniques":           techniques,
        "groups":               groups,
        "usages":               usages,
        "campaigns":            campaigns,
        "campaign_tech_usages": campaign_tech_usages,
        "campaign_group_links": campaign_group_links,
        "stix_objects":         stix_objects,
        "stix_relationships":   [
            {
                "stix_id": rel["id"],
                "relationship_type": rel.get("relationship_type", ""),
                "source_stix_id": rel.get("source_ref", ""),
                "target_stix_id": rel.get("target_ref", ""),
                "description": rel.get("description", "") or "",
                "references": _ext_refs(rel),
                "raw": rel,
            }
            for rel in relationships
            if rel.get("id")
        ],
    }


# ── DB upsert ─────────────────────────────────────────────────────────────────

def ingest_domain(domain: str, bundle_path: Path, version: str) -> None:
    data = parse_bundle(bundle_path, domain)

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

        # ── Raw STIX preservation ─────────────────────────────────────────────
        stix_object_count = 0
        for obj in data["stix_objects"]:
            session.execute(
                insert(StixObject)
                .values(
                    stix_id=obj["stix_id"],
                    stix_type=obj["stix_type"],
                    attack_id=obj["attack_id"],
                    name=obj["name"],
                    domain=domain,
                    version_id=version_id,
                    is_deprecated=obj["is_deprecated"],
                    is_revoked=obj["is_revoked"],
                    raw=obj["raw"],
                )
                .on_conflict_do_update(
                    constraint="uq_stix_object_version",
                    set_={
                        "stix_type": obj["stix_type"],
                        "attack_id": obj["attack_id"],
                        "name": obj["name"],
                        "domain": domain,
                        "is_deprecated": obj["is_deprecated"],
                        "is_revoked": obj["is_revoked"],
                        "raw": obj["raw"],
                    },
                )
            )
            stix_object_count += 1

        stix_relationship_count = 0
        for rel in data["stix_relationships"]:
            session.execute(
                insert(StixRelationship)
                .values(
                    stix_id=rel["stix_id"],
                    relationship_type=rel["relationship_type"],
                    source_stix_id=rel["source_stix_id"],
                    target_stix_id=rel["target_stix_id"],
                    description=rel["description"],
                    references=rel["references"],
                    domain=domain,
                    version_id=version_id,
                    raw=rel["raw"],
                )
                .on_conflict_do_update(
                    constraint="uq_stix_relationship_version",
                    set_={
                        "relationship_type": rel["relationship_type"],
                        "source_stix_id": rel["source_stix_id"],
                        "target_stix_id": rel["target_stix_id"],
                        "description": rel["description"],
                        "references": rel["references"],
                        "domain": domain,
                        "raw": rel["raw"],
                    },
                )
            )
            stix_relationship_count += 1

        logger.info(
            "  Preserved %d raw STIX objects and %d raw STIX relationships",
            stix_object_count,
            stix_relationship_count,
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

        # ── ATT&CK Group Profiles ─────────────────────────────────────────────
        group_stix_to_db_id: dict[str, int] = {}
        for g in data["groups"]:
            stmt = (
                insert(AptGroup)
                .values(
                    attack_id=g["attack_id"], stix_id=g["stix_id"],
                    name=g["name"], description=g["description"],
                    aliases=g["aliases"], url=g["url"],
                    created=g["created"], modified=g["modified"],
                    attack_version=g["attack_version"],
                    contributors=g["contributors"],
                    external_references=g["external_references"],
                    domain=domain, version_id=version_id,
                )
                .on_conflict_do_update(
                    constraint="uq_group_version",
                    set_={
                        "stix_id": g["stix_id"],
                        "name": g["name"],
                        "description": g["description"],
                        "aliases": g["aliases"],
                        "url": g["url"],
                        "created": g["created"],
                        "modified": g["modified"],
                        "attack_version": g["attack_version"],
                        "contributors": g["contributors"],
                        "external_references": g["external_references"],
                        "domain": domain,
                    },
                )
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

        logger.info("  Ingested %d ATT&CK group profiles", len(group_stix_to_db_id))

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

        # ── Campaigns (DB 1: named operations / specific attacks) ─────────────
        campaign_stix_to_db_id: dict[str, int] = {}
        for c in data["campaigns"]:
            stmt = (
                insert(Campaign)
                .values(
                    attack_id=c["attack_id"], stix_id=c["stix_id"],
                    name=c["name"], description=c["description"],
                    url=c["url"], first_seen=c["first_seen"] or None,
                    last_seen=c["last_seen"] or None,
                    domain=domain, version_id=version_id,
                )
                .on_conflict_do_nothing(constraint="uq_campaign_version")
                .returning(Campaign.id)
            )
            row = session.execute(stmt).fetchone()
            db_id = row[0] if row else session.scalar(
                select(Campaign.id).where(
                    Campaign.attack_id == c["attack_id"],
                    Campaign.version_id == version_id,
                )
            )
            if db_id:
                campaign_stix_to_db_id[c["stix_id"]] = db_id

        logger.info("  Ingested %d campaigns", len(campaign_stix_to_db_id))

        # ── Campaign → Technique usages ───────────────────────────────────────
        camp_tech_count = 0
        for u in data["campaign_tech_usages"]:
            camp_db_id = campaign_stix_to_db_id.get(u["campaign_stix_id"])
            tech_db_id = stix_id_to_tech_db_id.get(u["technique_stix_id"])
            if not camp_db_id or not tech_db_id:
                continue
            session.execute(
                insert(CampaignTechnique)
                .values(
                    campaign_id=camp_db_id, technique_id=tech_db_id,
                    use_description=u["description"], references=u["refs"],
                )
                .on_conflict_do_nothing(constraint="uq_campaign_technique")
            )
            camp_tech_count += 1

        logger.info("  Ingested %d campaign-technique links", camp_tech_count)

        # ── Campaign → Group attribution ──────────────────────────────────────
        camp_group_count = 0
        for link in data["campaign_group_links"]:
            camp_db_id  = campaign_stix_to_db_id.get(link["campaign_stix_id"])
            group_db_id = group_stix_to_db_id.get(link["group_stix_id"])
            if not camp_db_id or not group_db_id:
                continue
            session.execute(
                insert(AptGroupCampaign)
                .values(group_id=group_db_id, campaign_id=camp_db_id)
                .on_conflict_do_nothing(constraint="uq_group_campaign")
            )
            camp_group_count += 1

        logger.info("  Ingested %d campaign-group attribution links", camp_group_count)
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
