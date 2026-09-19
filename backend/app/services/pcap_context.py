"""Dated local intelligence snapshots, separate from immutable packet evidence.

No provider credentials, network requests, automatic IOC promotion, or actor
attribution. A miss means unknown within this local corpus, never benign.
"""
from datetime import datetime, timezone
import hashlib
import ipaddress

from sqlalchemy import func, select
from app.models.ioc import IOCIndicator, IOCActorLink
from app.models.attack import Technique, AttackVersion, StixObject, StixRelationship
from app.models.pcap import PcapAnalysis
from app.services.pcap_analyzer import canonical_json

MAX_OBSERVABLES = 5000
MAX_MATCHES = 5000
MAX_PRIOR_CASES = 50


def observable_key(kind: str, value: str) -> tuple[str, str]:
    kind = {'ip': 'ipv4', 'ip-dst': 'ipv4', 'ip-src': 'ipv4', 'domain-name': 'domain', 'hostname': 'domain'}.get(kind, kind)
    if kind in {'ipv4', 'ipv6'}:
        try:
            address = ipaddress.ip_address(value)
            return ('ipv4' if address.version == 4 else 'ipv6', str(address))
        except ValueError:
            return kind, value
    # URL paths and query values are case-sensitive; do not fold them.
    if kind in {'domain', 'sha256', 'sha1', 'md5', 'ja3', 'ja3s', 'ja4'}:
        value = value.lower().rstrip('.') if kind == 'domain' else value.lower()
    return kind, value


async def build_context(db, result: dict, *, session_id: str) -> dict:
    observations = list(result.get('observables') or [])
    selected = observations[:MAX_OBSERVABLES]
    by_key = {observable_key(o['type'], o['value']): o for o in selected}
    matches = []
    truncated_matches = False
    values = sorted({value.lower() for _, value in by_key})
    for offset in range(0, len(values), 250):
        rows = (await db.execute(select(IOCIndicator).where(func.lower(IOCIndicator.value).in_(values[offset:offset+250])).order_by(IOCIndicator.id).limit(MAX_MATCHES + 1))).scalars().all()
        for row in rows:
            key = observable_key(row.indicator_type, row.value)
            if key not in by_key:
                continue
            if len(matches) >= MAX_MATCHES:
                truncated_matches = True
                break
            matches.append({'observable_id': by_key[key]['observable_id'], 'indicator_id': row.id, 'type': key[0], 'value': key[1],
                'match_basis': 'exact-normalized-type-and-value', 'source_id': row.source_id, 'source_url': row.source_url,
                'first_seen': row.first_seen, 'last_seen': row.last_seen, 'confidence': row.confidence,
                'malware_family': row.malware_family, 'technique_ids': row.technique_ids, 'tlp': row.tlp,
                'source_updated_at': row.updated_at.isoformat() if row.updated_at else None})
        if truncated_matches:
            break
    indicator_ids = [m['indicator_id'] for m in matches]
    actor_links = []
    if indicator_ids:
        rows = (await db.execute(select(IOCActorLink).where(IOCActorLink.indicator_id.in_(indicator_ids)).order_by(IOCActorLink.id).limit(1001))).scalars().all()
        actor_links = [{'indicator_id': r.indicator_id, 'actor_attack_id': r.actor_attack_id, 'actor_name': r.actor_name,
            'source_id': r.source_id, 'evidence': r.evidence, 'confidence': r.confidence,
            'status': 'source-assertion-not-case-attribution'} for r in rows[:1000]]
    tids = sorted({t['attack_id'] for t in result.get('attack_candidates', [])})
    techniques = []
    if tids:
        rows = (await db.execute(select(Technique).join(AttackVersion).where(Technique.attack_id.in_(tids),
            AttackVersion.is_latest.is_(True), Technique.domain == 'enterprise-attack', Technique.is_deprecated.is_(False)).order_by(Technique.attack_id))).scalars().all()
        for row in rows:
            links = (await db.execute(select(StixObject).join(StixRelationship, (StixRelationship.source_stix_id == StixObject.stix_id) &
                (StixRelationship.version_id == StixObject.version_id)).where(StixRelationship.target_stix_id == row.stix_id,
                StixRelationship.version_id == row.version_id, StixRelationship.relationship_type == 'detects',
                StixObject.is_revoked.is_(False), StixObject.is_deprecated.is_(False)).order_by(StixObject.stix_id).limit(101))).scalars().all()
            techniques.append({'attack_id': row.attack_id, 'name': row.name, 'catalog_version_id': row.version_id, 'url': row.url,
                'platforms': row.platforms, 'data_sources': row.data_sources, 'detection': row.detection,
                'detection_strategies': [{'stix_id': r.stix_id, 'attack_id': r.attack_id, 'name': r.name} for r in links[:100]],
                'detection_links_truncated': len(links) > 100, 'status': 'catalog-context-not-validation-of-behavior'})
    # Bounded contextual linkage only. Exclude identities/private addresses and
    # User-Agents: their overlap is routinely non-specific.
    comparable = {key for key, o in by_key.items() if key[0] in {'sha256', 'domain', 'ipv4', 'ipv6'} and o.get('is_private') is not True}
    previous = (await db.execute(select(PcapAnalysis.id, PcapAnalysis.session_id, PcapAnalysis.source_sha256,
        PcapAnalysis.result['observables'].label('observables')).where(PcapAnalysis.status == 'completed',
        PcapAnalysis.source_sha256 != result['capture']['source_sha256']).order_by(PcapAnalysis.created_at.desc(), PcapAnalysis.id).limit(MAX_PRIOR_CASES+1))).all()
    correlations = []
    seen_sources = set()
    for row in previous[:MAX_PRIOR_CASES]:
        if row.source_sha256 in seen_sources:
            continue
        seen_sources.add(row.source_sha256)
        other = {observable_key(o['type'], o['value']) for o in (row.observables or [])}
        shared = sorted(comparable & other)
        if shared:
            correlations.append({'analysis_id': str(row.id), 'session_id': str(row.session_id), 'source_sha256': row.source_sha256,
                'shared_observables': [{'type': k, 'value': v} for k,v in shared[:200]], 'shared_count': len(shared),
                'status': 'shared-observation-not-common-campaign'})
    matched = {m['observable_id'] for m in matches}
    context = {'schema_version': 'pcap-context-v1', 'created_at': datetime.now(timezone.utc).isoformat(),
        'session_id': str(session_id), 'source_semantic_sha256': result['semantic_sha256'], 'mode': 'local-only',
        'external_enrichment': {'status': 'not-requested', 'requests': 0, 'reason': 'Requires explicit provider consent and privacy review'},
        'coverage': {'observables_total': len(observations), 'observables_checked': len(selected), 'observable_limit': MAX_OBSERVABLES,
            'truncated': len(observations) > MAX_OBSERVABLES or truncated_matches, 'matched_observables': len(matched),
            'no_exact_match': len(selected) - len(matched), 'prior_cases_checked': min(len(previous), MAX_PRIOR_CASES),
            'prior_case_limit_reached': len(previous) > MAX_PRIOR_CASES},
        'matches': matches, 'source_actor_links': actor_links, 'techniques': techniques, 'cross_case_correlations': correlations,
        'interpretation': 'No match means unknown in this corpus. Local CTI may postdate the capture. Matches and shared infrastructure require review; no automatic promotion or attribution.'}
    context['snapshot_sha256'] = hashlib.sha256(canonical_json(context).encode()).hexdigest()
    return context
