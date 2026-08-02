"""Backfill canonical tags and cross-links for records created before this model."""

from __future__ import annotations

import asyncio

from sqlalchemy import text

from app.core.database import async_session_factory


async def main() -> None:
    async with async_session_factory() as db:
        # Reusable value slug matching app.services.taxonomy._slug: lowercase,
        # replace anything outside [a-z0-9._+-] with '-', collapse repeats,
        # and trim stray separators from the ends.
        #
        # A handful of historical IOCs carry raw source-supplied tags that
        # predate the closed tag-namespace taxonomy (e.g. "jarm:<fingerprint>",
        # "port:<n>") and don't belong to any recognized namespace; fold them
        # into tag: instead of leaving them as one-off invented namespaces.
        await db.execute(text("""
            update ioc_indicators i
            set tags = (
                select jsonb_agg(tag order by tag) tags
                from (
                    select distinct tag
                    from (
                        select case
                            when tag like 'jarm:%' or tag like 'port:%' or tag like 'pause_amd64:%'
                                then 'tag:' || replace(split_part(tag, ':', 1), '-', '_')
                                    || '_' || btrim(regexp_replace(lower(split_part(tag, ':', 2)), '[^a-z0-9._+-]+', '-', 'g'), '-_.')
                            -- ioc_type:/malware:/campaign: are always freshly derived below from
                            -- the row's own columns, so drop any existing copy here rather than
                            -- risk keeping a stale/un-slugified duplicate alongside the new one.
                            when tag like 'ioc_type:%' or tag like 'malware:%' or tag like 'campaign:%'
                                then ''
                            else tag
                        end as tag
                        from jsonb_array_elements_text(coalesce(i.tags, '[]'::jsonb)) tag
                        union all select 'ioc_type:' || btrim(regexp_replace(lower(trim(i.indicator_type)), '[^a-z0-9._+-]+', '-', 'g'), '-_.')
                        union all select 'ttp:' || value
                            from jsonb_array_elements_text(coalesce(i.technique_ids, '[]'::jsonb)) value
                        union all select 'malware:' || btrim(regexp_replace(lower(trim(i.malware_family)), '[^a-z0-9._+-]+', '-', 'g'), '-_.')
                            where i.malware_family <> ''
                        union all select 'campaign:' || btrim(regexp_replace(lower(trim(i.campaign)), '[^a-z0-9._+-]+', '-', 'g'), '-_.')
                            where i.campaign <> ''
                        union all select 'actor:' || link.actor_attack_id
                            from ioc_actor_links link
                            where link.indicator_id = i.id and link.actor_attack_id <> ''
                    ) values
                    where tag <> ''
                ) unique_values
            )
        """))
        # Drop stale catalog/entity-tag rows left over from before this
        # taxonomy was enforced: invented namespaces (jarm:/port:/...), and
        # un-slugified malware:/campaign:/ioc_type: values (raw source text
        # with spaces/punctuation instead of a clean slug). Valid ATT&CK
        # campaign IDs (Cxxxx) are excluded from the campaign check since
        # they are intentionally uppercase, not a slug. The entity-tag
        # population blocks below regenerate correct replacements from the
        # now-fixed columns above.
        await db.execute(text("""
            delete from intelligence_entity_tags
            where split_part(tag, ':', 1) not in ('cve', 'cwe', 'ttp', 'tactic', 'actor')
              and (
                    split_part(tag, ':', 1) in ('jarm', 'port', 'pause_amd64')
                    or (split_part(tag, ':', 1) in ('malware', 'ioc_type') and tag ~ '[^a-z0-9._+:-]')
                    or (split_part(tag, ':', 1) = 'campaign' and tag ~ '[^a-z0-9._+:-]'
                        and substring(tag from position(':' in tag) + 1) !~ '^C[0-9]{4}(\\.[0-9]{3})?$')
              )
        """))
        await db.execute(text("""
            delete from intelligence_tags
            where namespace not in ('cve', 'cwe', 'ttp', 'tactic', 'actor')
              and (
                    namespace in ('jarm', 'port', 'pause_amd64')
                    or (namespace in ('malware', 'ioc_type') and value ~ '[^a-z0-9._+-]')
                    or (namespace = 'campaign' and value ~ '[^a-z0-9._+-]'
                        and value !~ '^C[0-9]{4}(\\.[0-9]{3})?$')
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
        # Seed the full ATT&CK group/tactic/technique catalogs as canonical
        # tags so every known one is a valid, discoverable tag regardless of
        # current linkage. app.services.attck.ingestor now does this on every
        # future sync; this covers data already ingested before that existed.
        await db.execute(text("""
            insert into intelligence_tags (namespace, value, canonical)
            select distinct 'actor', attack_id, 'actor:' || attack_id
            from apt_groups
            where attack_id <> ''
            on conflict (namespace, value) do nothing
        """))
        await db.execute(text("""
            insert into intelligence_tags (namespace, value, canonical)
            select distinct 'tactic', attack_id, 'tactic:' || attack_id
            from tactics
            where attack_id <> ''
            on conflict (namespace, value) do nothing
        """))
        await db.execute(text("""
            insert into intelligence_tags (namespace, value, canonical)
            select distinct 'ttp', attack_id, 'ttp:' || attack_id
            from techniques
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
                union all select 'ioc_type:' || btrim(regexp_replace(lower(trim(indicator_type)), '[^a-z0-9._+-]+', '-', 'g'), '-_.') from ioc_indicators
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
                union select 'ioc_type:' || btrim(regexp_replace(lower(trim(i.indicator_type)), '[^a-z0-9._+-]+', '-', 'g'), '-_.')
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
