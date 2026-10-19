"""Reopen pinned official bundles and a runtime export using optional stix2==3.0.1.

This is validation tooling, not an application dependency or schema certification.
Usage: PYTHONPATH=... python scripts/validate_attack_stix_exports.py FIXTURE_DIR
"""
import json
from copy import deepcopy
from pathlib import Path
import runpy
import sys
import stix2


def validate(cache):
    counts = {}
    for domain in ('enterprise-attack', 'mobile-attack', 'ics-attack'):
        bundle = stix2.parse((cache / f'{domain}-20.0.json').read_text(), allow_custom=True)
        counts[domain] = len(bundle.objects)
        del bundle
    example = runpy.run_path('tests/unit/test_stix_export.py')
    test = example['test_analysis_stix_export_models_ttp_report_not_iocs']
    builder = test.__globals__['build_analysis_stix_bundle']
    exported = []
    captured = []
    def checked_builder(*args, **kwargs):
        captured.append((args, kwargs))
        result = builder(*args, **kwargs)
        reopened = stix2.parse(json.dumps(result), allow_custom=True)
        ids = {obj.id for obj in reopened.objects}
        for obj in reopened.objects:
            for key in ('source_ref', 'target_ref'):
                if key in obj:
                    assert obj[key] in ids, (obj.id, key)
            if obj.type == 'report':
                assert set(obj.object_refs) <= ids
        exported.append(len(ids))
        return result
    test.__globals__['build_analysis_stix_bundle'] = checked_builder
    test()
    args, kwargs = captured[0]
    domain_exports = {}
    for domain, technique_id in [('enterprise-attack', 'T1699'), ('mobile-attack', 'T1476'), ('ics-attack', 'T1701.001')]:
        source = json.loads((cache / f'{domain}-20.0.json').read_text())
        technique = next(obj for obj in source['objects'] if obj['type'] == 'attack-pattern' and any(ref.get('source_name') == 'mitre-attack' and ref.get('external_id') == technique_id for ref in obj.get('external_references', [])))
        ref = next(ref for ref in technique['external_references'] if ref.get('source_name') == 'mitre-attack')
        session, result = deepcopy(args)
        session.domain = domain
        result.extracted_techniques = [{'attack_id': technique_id, 'name': technique['name'], 'review_status': 'accepted'}]
        result.apt_matches = []
        promotion = deepcopy(kwargs['promotion'])
        claim = deepcopy(promotion.manifest['accepted_claims'][0])
        claim.update(attack_id=technique_id, object=technique['name'], statement='Synthetic procedure claim for export validation.', evidence_refs=[{'excerpt': 'Synthetic validation fixture'}])
        promotion.manifest = {**promotion.manifest, 'accepted_claims': [claim]}
        emitted = checked_builder(session, result, technique_lookup={technique_id: {'stix_id': technique['id'], 'name': technique['name'], 'description': technique.get('description', ''), 'url': ref['url']}}, group_lookup={}, promotion=promotion)
        emitted_technique = next(obj for obj in emitted['objects'] if obj['type'] == 'attack-pattern')
        assert emitted_technique['id'] == technique['id']
        domain_exports[domain] = technique_id
    print(json.dumps({'parser': 'stix2 3.0.1', 'official_bundle_objects': counts, 'runtime_export_objects': exported, 'v20_domain_exports': domain_exports, 'custom_objects_allowed': True, 'schema_certification': False}, indent=2))


if __name__ == '__main__':
    validate(Path(sys.argv[1]))
