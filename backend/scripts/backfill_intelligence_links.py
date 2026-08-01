"""Backfill canonical tags and cross-links for records created before this model."""

from __future__ import annotations

import asyncio

from sqlalchemy import text

from app.core.database import async_session_factory


async def main() -> None:
    async with async_session_factory() as db:
        # Existing tag arrays were normalized by the taxonomy migration. Add
        # deterministic identity tags so every IOC/CVE/report is discoverable
        # even when its source supplied no labels.
        await db.execute(text("""
            update ioc_indicators i
            set tags = (
                select jsonb_agg(tag order by tag) tags
                from (
                    select distinct tag
                    from (
                        select jsonb_array_elements_text(coalesce(i.tags, '[]'::jsonb)) tag
                        union all select 'ioc_type:' || lower(trim(i.indicator_type))
                        union all select 'ttp:' || value
                            from jsonb_array_elements_text(coalesce(i.technique_ids, '[]'::jsonb)) value
                        union all select 'malware:' || lower(trim(i.malware_family)) where i.malware_family <> ''
                        union all select 'campaign:' || lower(trim(i.campaign)) where i.campaign <> ''
                        union all select 'actor:' || link.actor_attack_id
                            from ioc_actor_links link
                            where link.indicator_id = i.id and link.actor_attack_id <> ''
                    ) values
                    where tag <> ''
                ) unique_values
            )
        """))
        await db.execute(text("""
            update cve_records c
            set tags = (
                select jsonb_agg(tag order by tag) tags
                from (
                    select distinct tag
                    from (
                        select jsonb_array_elements_text(coalesce(c.tags, '[]'::jsonb)) tag
                        union all select 'cve:' || upper(trim(c.cve_id))
                        union all select 'cwe:' || value
                            from jsonb_array_elements_text(coalesce(c.cwe_ids, '[]'::jsonb)) value
                        union all select 'tag:known-exploited' where c.known_exploited
                        union all select 'risk:critical' where c.known_exploited
                        union all select 'actor:' || link.actor_attack_id
                            from cve_actor_links link
                            where link.cve_id = c.cve_id and link.actor_attack_id <> ''
                    ) values
                    where tag <> ''
                ) unique_values
            )
        """))
        # Seed the full ATT&CK group catalog as canonical actor: tags so every
        # known group is a valid, discoverable tag regardless of current linkage.
        await db.execute(text("""
            insert into intelligence_tags (namespace, value, canonical)
            select distinct 'actor', attack_id, 'actor:' || attack_id
            from apt_groups
            where attack_id <> ''
            on conflict (namespace, value) do nothing
        """))
        await db.execute(text("""
            update report_intake
            set tags = (
                select jsonb_agg(tag order by tag)
                from (
                    select distinct tag
                    from (
                        select jsonb_array_elements_text(coalesce(report_intake.tags, '[]'::jsonb)) tag
                        union all select 'tag:report'
                        union all select 'ttp:' || value
                            from jsonb_array_elements_text(coalesce(report_intake.technique_ids, '[]'::jsonb)) value
                        union all select 'actor:' || value
                            from jsonb_array_elements_text(coalesce(report_intake.actor_ids, '[]'::jsonb)) value
                    ) values
                ) unique_values
            )
        """))
        await db.execute(text("""
            insert into intelligence_tags (namespace, value, canonical)
            select distinct split_part(tag, ':', 1), substring(tag from position(':' in tag) + 1), tag
            from (
                select jsonb_array_elements_text(coalesce(tags, '[]'::jsonb)) as tag from ioc_indicators
                union all select 'ioc_type:' || lower(trim(indicator_type)) from ioc_indicators
                union all select jsonb_array_elements_text(coalesce(tags, '[]'::jsonb)) from cve_records
                union all select 'cve:' || upper(trim(cve_id)) from cve_records
                union all select jsonb_array_elements_text(coalesce(tags, '[]'::jsonb)) from report_intake
                union all select 'tag:report' from report_intake
            ) tags
            where tag like '%:%' and split_part(tag, ':', 2) <> ''
            on conflict (namespace, value) do nothing
        """))
        await db.execute(text("""
            insert into intelligence_entity_tags
                (entity_type, entity_id, tag, source_type, source_id, confidence, evidence)
            select 'ioc', i.id::text, tag, 'ioc_source', i.source_id, i.confidence, i.source_url
            from ioc_indicators i
            cross join lateral (
                select jsonb_array_elements_text(coalesce(i.tags, '[]'::jsonb)) tag
                union select 'ioc_type:' || lower(trim(i.indicator_type))
            ) labels
            on conflict (entity_type, entity_id, tag) do nothing
        """))
        await db.execute(text("""
            insert into intelligence_entity_tags
                (entity_type, entity_id, tag, source_type, source_id, confidence, evidence)
            select 'cve', c.cve_id, tag, 'cve_source', coalesce(c.source_id, ''), 80, ''
            from cve_records c
            cross join lateral (
                select jsonb_array_elements_text(coalesce(c.tags, '[]'::jsonb)) tag
                union select 'cve:' || upper(trim(c.cve_id))
            ) labels
            on conflict (entity_type, entity_id, tag) do nothing
        """))
        await db.execute(text("""
            insert into intelligence_entity_tags
                (entity_type, entity_id, tag, source_type, source_id, confidence, evidence)
            select 'analysis_report', r.id::text, tag, 'report', r.id::text, 70, r.url
            from report_intake r
            cross join lateral (
                select jsonb_array_elements_text(coalesce(r.tags, '[]'::jsonb)) tag
                union select 'tag:report'
            ) labels
            on conflict (entity_type, entity_id, tag) do nothing
        """))
        await db.execute(text("""
            insert into intelligence_relationships
                (source_type, source_id, relationship_type, target_type, target_id,
                 confidence, provenance_type, provenance_id, evidence, attributes)
            select 'ioc', i.id::text, 'indicates-technique', 'attack_technique', technique,
                   i.confidence, 'ioc_source', i.source_id, i.source_url, '{}'::jsonb
            from ioc_indicators i
            cross join lateral jsonb_array_elements_text(coalesce(i.technique_ids, '[]'::jsonb)) technique
            on conflict on constraint uq_intelligence_relationship_provenance do nothing
        """))
        await db.execute(text("""
            insert into intelligence_relationships
                (source_type, source_id, relationship_type, target_type, target_id,
                 confidence, provenance_type, provenance_id, evidence, attributes)
            select 'analysis_report', r.id::text, 'references-technique', 'attack_technique', technique,
                   70, 'report', r.id::text, r.url, '{}'::jsonb
            from report_intake r
            cross join lateral jsonb_array_elements_text(coalesce(r.technique_ids, '[]'::jsonb)) technique
            on conflict on constraint uq_intelligence_relationship_provenance do nothing
        """))
        await db.execute(text("""
            insert into intelligence_relationships
                (source_type, source_id, relationship_type, target_type, target_id,
                 confidence, provenance_type, provenance_id, evidence, attributes)
            select 'cve', link.cve_id, link.relationship_type, 'attack_technique', link.attack_id,
                   link.confidence, 'cve_source', link.source_id, link.evidence, '{}'::jsonb
            from cve_technique_links link
            on conflict on constraint uq_intelligence_relationship_provenance do nothing
        """))
        await db.commit()


if __name__ == "__main__":
    asyncio.run(main())
