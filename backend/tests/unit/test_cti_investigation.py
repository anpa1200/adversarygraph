"""Behavioral regressions for the assignment-versus-report CTI failure."""
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from app.services.ai.base import ExtractionResult, ExtractedTechnique
from app.services.cti_investigation import (
    CHUNK_CHARS, chunks, indicator_span, investigate, refang, report_references,
)


def test_pdf_wrapped_report_reference_is_repaired_without_adding_hyphen():
    text = 'Read https://www.stepsecurity.io/blog/axios-malicious-\nremote-access-trojan#indicators-of-compromise for evidence.'
    assert report_references(text) == ['https://www.stepsecurity.io/blog/axios-malicious-remote-access-trojan']


@pytest.mark.parametrize('url', [
    'http://127.0.0.1/report', 'http://169.254.169.254/blog/metadata',
    'https://user:pass@example.com/blog/report', 'https://example.com:8080/blog/report',
    'https://example.com/blog/dropper.exe', 'https://example.com/blog/report?token=secret',
    'file:///etc/passwd', 'https://example.com/payload.js',
])
def test_unsafe_or_nonreport_auto_references_are_not_acquired(url):
    assert report_references(url) == []


def test_explicit_references_allow_vendor_advisory_paths_but_still_filter_credentials():
    assert report_references('https://example.com/security/123', explicit=True) == ['https://example.com/security/123']
    assert report_references('https://a:b@example.com/security/123', explicit=True) == []


def test_chunks_cover_tail_beyond_old_window_with_overlap():
    text = 'a' * 85_000 + 'TAIL IOC'
    parts = list(chunks(text))
    assert len(parts) > 2
    assert parts[-1][1].endswith('TAIL IOC')
    assert all(len(part) <= CHUNK_CHARS for _, part in parts)
    assert ''.join(part if i == 0 else part[500:] for i, (_, part) in enumerate(parts)) == text


def test_defanged_indicators_bind_to_original_source_offsets():
    source = 'C2 hxxps://evil[.]example/path and 8[.]8[.]4[.]4'
    assert refang(source) == 'C2 https://evil.example/path and 8.8.4.4'
    start, end = indicator_span(source, 'https://evil.example/path')
    assert source[start:end] == 'hxxps://evil[.]example/path'


class Adapter:
    provider = 'local'
    model = 'test'

    def __init__(self, *, malformed=False, fail_chunk=False):
        self.inputs = []
        self.payload = None
        self.malformed = malformed
        self.fail_chunk = fail_chunk

    async def extract(self, text, domain):
        self.inputs.append(text)
        if self.fail_chunk:
            raise TimeoutError('provider not available')
        techniques = [ExtractedTechnique('T9999', 'Invented', 'execution', .9, 'not in source text', evidence_start=0, evidence_end=18)]
        if 'executes powershell.exe' in text:
            techniques.append(ExtractedTechnique('T1059.001', 'PowerShell', 'execution', .9, 'executes powershell.exe', evidence_start=0))
        return ExtractionResult(techniques=techniques, summary='Source describes execution [S002].')

    async def _raw_complete(self, system, user):
        self.payload = user
        if self.malformed:
            return '{"summary":"unsupported", "report":"Fabricated source [S999]"}'
        return '{"summary":"Source reports execution; validation pending.", "report":"## Analysis\\nSource reports execution [S002]. Attribution unknown."}'

    async def extract_research(self, text, domain):
        return await self.extract(text, domain), []


def db_with_matches(rows=()):
    scalars = SimpleNamespace(all=lambda: list(rows))
    result = SimpleNamespace(scalars=lambda: scalars)
    return SimpleNamespace(execute=AsyncMock(return_value=result))


async def emit(*args):
    pass


async def fetch(url):
    return SimpleNamespace(title='Vendor report', source_url=url, content_type='text/html', metadata={},
                           source_text='Observed actor executes powershell.exe. C2 hxxps://evil[.]example/path. ' + 'Details. ' * 25)


@pytest.mark.asyncio
async def test_assignment_fetches_actual_report_and_creates_bound_candidates_without_promotion():
    adapter = Adapter()
    output = await investigate('Assignment: read https://example.com/blog/campaign', adapter=adapter,
                              domain='enterprise-attack', db=db_with_matches(), fetch_report=fetch, emit=emit)
    assert len(output.data['sources']) == 2
    assert output.data['stages']['acquisition']['attempts'][0]['status'] == 'complete'
    assert output.data['status'] == 'complete'
    assert output.data['stages']['review']['status'] == 'pending'
    assert output.data['stages']['registration']['status'] == 'skipped'
    assert [t.attack_id for t in output.result.techniques] == ['T1059.001']
    t = output.result.techniques[0]
    assert output.source_text[t.evidence_start:t.evidence_end] == t.evidence
    item = next(i for i in output.indicators if i['value'] == 'https://evil.example/path')
    e = item['evidence'][0]
    assert output.source_text[e['start']:e['end']] == 'hxxps://evil[.]example/path'
    assert item['enrichment']['status'] == 'no_match'
    assert item['enrichment']['verdict'] == 'unknown'
    assert item['status'] == 'suggested'
    assert 'No match means unknown' in ' '.join(output.data['limitations'])


@pytest.mark.asyncio
async def test_long_report_tail_is_extracted_and_fully_accounted_for():
    adapter = Adapter()
    text = 'Background. ' * 4300 + 'Actor executes powershell.exe and contacts 8.8.4.4.'
    output = await investigate(text, adapter=adapter, domain='enterprise-attack', db=db_with_matches(),
                              fetch_report=fetch, emit=emit, follow_references=False)
    assert len(adapter.inputs) > 1
    assert output.result.techniques[0].attack_id == 'T1059.001'
    stage = output.data['stages']['extraction']
    assert stage['analyzed_chars'] == stage['source_chars'] == len(output.source_text)
    assert any(i['value'] == '8.8.4.4' for i in output.indicators)


@pytest.mark.asyncio
async def test_retrieval_failure_is_visible_and_does_not_fabricate_source():
    async def failure(url):
        raise ValueError('blocked')
    output = await investigate('Assignment https://example.com/blog/report', adapter=Adapter(),
                              domain='enterprise-attack', db=db_with_matches(), fetch_report=failure, emit=emit)
    assert output.data['status'] == 'partial'
    assert output.data['stages']['acquisition']['status'] == 'partial'
    assert len(output.data['sources']) == 1
    assert output.data['warnings']


@pytest.mark.asyncio
async def test_invalid_citations_are_rejected_and_extraction_is_preserved():
    output = await investigate('Use https://example.com/blog/report', adapter=Adapter(malformed=True),
                              domain='enterprise-attack', db=db_with_matches(), fetch_report=fetch, emit=emit)
    assert output.data['report'] == ''
    assert output.data['stages']['synthesis']['status'] == 'failed'
    assert output.data['status'] == 'partial'
    assert output.indicators


@pytest.mark.asyncio
async def test_chunk_failure_never_claims_complete_coverage():
    output = await investigate('Use https://example.com/blog/report', adapter=Adapter(fail_chunk=True),
                              domain='enterprise-attack', db=db_with_matches(), fetch_report=fetch, emit=emit)
    assert output.data['stages']['extraction']['analyzed_chars'] == 0
    assert output.data['stages']['extraction']['status'] == 'partial'
    assert output.data['status'] == 'partial'


@pytest.mark.asyncio
async def test_external_enrichment_is_not_called_by_default(monkeypatch):
    from app.services import cti_investigation as module
    external = AsyncMock()
    monkeypatch.setattr(module, 'rdap_enrichment', external)
    await investigate('Use https://example.com/blog/report', adapter=Adapter(), domain='enterprise-attack',
                      db=db_with_matches(), fetch_report=fetch, emit=emit)
    external.assert_not_called()


@pytest.mark.asyncio
async def test_reference_acquisition_is_one_hop_and_bounded():
    fetcher = AsyncMock(side_effect=fetch)
    text = ' '.join(f'https://example.com/blog/report-{i}' for i in range(5))
    output = await investigate(text, adapter=Adapter(), domain='enterprise-attack', db=db_with_matches(),
                              fetch_report=fetcher, emit=emit)
    assert fetcher.await_count == 3
    assert len(output.data['sources']) == 4
    assert output.data['status'] == 'partial'


@pytest.mark.asyncio
async def test_research_notes_reject_fabricated_evidence_and_keep_tail_details():
    import json
    from app.services.ai.base import LLMAdapter

    class ResearchAdapter(LLMAdapter):
        provider = 'local'
        model = 'test'

        async def _raw_complete(self, system, user):
            return json.dumps({'summary': 'Observed execution.', 'techniques': [], 'research_notes': [
                {'kind': 'event', 'claim': 'Observed execution', 'evidence': 'Actor executes powershell.exe'},
                {'kind': 'attribution', 'claim': 'Actor X', 'evidence': 'This text was never present'},
            ]})

        async def _stream_complete(self, system, user):
            yield ''

    result, notes = await ResearchAdapter().extract_research('Actor executes powershell.exe after installation.')
    assert result.summary == 'Observed execution.'
    assert len(notes) == 1
    assert notes[0]['start'] == 0
    assert notes[0]['evidence'] == 'Actor executes powershell.exe'


@pytest.mark.asyncio
async def test_passive_enrichment_does_not_send_uploaded_private_indicators(monkeypatch):
    from app.services import cti_investigation as module
    from app.services import ioc_investigation as providers

    monkeypatch.setattr(module.settings, 'virustotal_api_key', 'test-key')
    monkeypatch.setattr(module.settings, 'threatfox_auth_key', '')
    monkeypatch.setattr(module.settings, 'otx_api_key', '')
    lookup = AsyncMock(return_value=[{'source': 'virustotal', 'status': 'not_found', 'summary': 'No record'}])
    monkeypatch.setattr(providers, 'enrich_ioc_sources', lookup)
    indicators = [
        {'public_source': False, 'role': 'candidate', 'indicator_type': 'domain', 'value': 'secret.example', 'evidence': []},
        {'public_source': True, 'role': 'reference', 'indicator_type': 'domain', 'value': 'publisher.example', 'evidence': []},
        {'public_source': True, 'role': 'candidate', 'indicator_type': 'domain', 'value': 'evil.com', 'evidence': []},
    ]
    stage = await module.public_intelligence_enrichment(db_with_matches(), indicators, 'enterprise-attack', emit)
    assert stage['attempted'] == 1
    assert lookup.call_args.args[1] == 'evil.com'
    assert 'public_intelligence' not in indicators[0]
    assert indicators[2]['public_intelligence'][0]['verdict'] == 'unknown'


def test_investigation_content_is_bound_into_review_fingerprint():
    from app.models.analysis import AnalysisResult
    from app.services.report_review import analysis_fingerprint
    result = AnalysisResult(summary='Summary', extracted_techniques=[], apt_matches=[], investigation={'report': 'Original'})
    before = analysis_fingerprint(result, 'completed')
    result.investigation = {'report': 'Changed'}
    assert before != analysis_fingerprint(result, 'completed')


@pytest.mark.parametrize('report', [
    'The incident occurred in July 2026 [S001].',
    'Observed T9999 [S001].',
    'The hash is ' + 'a' * 64 + ' [S001].',
])
def test_quality_gate_rejects_unsupported_dates_ids_and_hashes(report):
    from app.services.cti_investigation import validate_narrative
    with pytest.raises(ValueError):
        validate_narrative(report, {'S001'}, 'Incident on March 30, 2026.', {'techniques': [], 'indicators': []})


@pytest.mark.asyncio
async def test_quality_review_repairs_an_unsupported_month_once():
    import json

    class RepairAdapter(Adapter):
        calls = 0

        async def _raw_complete(self, system, user):
            self.calls += 1
            if self.calls < 3:
                return json.dumps({'summary': 'Incident in July 2026.', 'report': 'Incident in July 2026 [S002].'})
            return json.dumps({'summary': 'Observed execution; precise incident date unknown.',
                               'report': 'The report describes execution [S002]. Exact incident date remains unknown.'})

    adapter = RepairAdapter()
    output = await investigate('Assignment dated March 2026. https://example.com/blog/report', adapter=adapter,
                              domain='enterprise-attack', db=db_with_matches(), fetch_report=fetch, emit=emit)
    assert adapter.calls == 3
    assert output.data['stages']['quality_review']['status'] == 'complete'
    assert 'July' not in output.data['report']


def test_quality_review_allows_parent_of_extracted_subtechnique():
    from app.services.cti_investigation import validate_narrative
    validate_narrative('Execution via T1059 [S001].', {'S001'}, 'Actor executes a script.',
                       {'techniques': [{'id': 'T1059.001'}], 'indicators': []})


@pytest.mark.asyncio
async def test_url_hostname_is_available_for_passive_domain_enrichment():
    async def public_report(url):
        result = await fetch(url)
        result.source_text = 'Observed C2 callback to https://sfrclak.com/path. ' + 'Evidence. ' * 20
        return result
    output = await investigate('Read https://example.com/blog/report', adapter=Adapter(), domain='enterprise-attack',
                              db=db_with_matches(), fetch_report=public_report, emit=emit)
    assert any(i['indicator_type'] == 'domain' and i['value'] == 'sfrclak.com' and i['public_source']
               for i in output.indicators)


def test_public_lookup_does_not_send_private_or_documentation_addresses():
    from app.services.cti_investigation import public_lookup_eligible
    for value in ['0.0.0.0', '10.0.0.1', '127.0.0.1', '192.0.2.10', '100.64.0.1', '::1']:
        assert not public_lookup_eligible({'indicator_type': 'ipv4' if '.' in value else 'ipv6', 'value': value})
    assert public_lookup_eligible({'indicator_type': 'ipv4', 'value': '142.11.206.73'})


@pytest.mark.asyncio
async def test_quote_binding_preserves_exact_original_case():
    class MixedCaseAdapter(Adapter):
        async def extract_research(self, text, domain):
            result, notes = await super().extract_research(text, domain)
            for technique in result.techniques:
                if technique.attack_id == 'T1059.001':
                    technique.evidence = 'EXECUTES PowerShell.exe'
            return result, notes
    output = await investigate('Read https://example.com/blog/report', adapter=MixedCaseAdapter(), domain='enterprise-attack',
                              db=db_with_matches(), fetch_report=fetch, emit=emit)
    technique = next(t for t in output.result.techniques if t.attack_id == 'T1059.001')
    assert technique.evidence == output.source_text[technique.evidence_start:technique.evidence_end] == 'executes powershell.exe'


@pytest.mark.asyncio
async def test_local_restricted_intelligence_never_enters_any_model_prompt():
    class RecordingAdapter(Adapter):
        payloads = []

        async def _raw_complete(self, system, user):
            self.payloads.append(user)
            return await super()._raw_complete(system, user)

    row = SimpleNamespace(id=8, indicator_type='url', value='https://evil.example/path', source_id='private-feed',
                          source_url='https://private-feed.example/?key=do-not-copy', first_seen='2026-01-01',
                          last_seen='2026-10-01', malware_family='RESTRICTED-LOCAL-FAMILY', campaign='PRIVATE-CAMPAIGN',
                          confidence=80, technique_ids=['T1059.001'], tlp='TLP:RED')
    adapter = RecordingAdapter()
    output = await investigate('Read https://example.com/blog/report', adapter=adapter, domain='enterprise-attack',
                              db=db_with_matches([row]), fetch_report=fetch, emit=emit)
    assert output.data['tlp'] == 'TLP:RED'
    indicator = next(i for i in output.indicators if i['value'] == row.value)
    assert indicator['enrichment']['matches'][0]['malware_family'] == 'RESTRICTED-LOCAL-FAMILY'
    assert 'source_url' not in indicator['enrichment']['matches'][0]
    assert len(adapter.payloads) >= 2
    for payload in adapter.payloads:
        assert 'RESTRICTED-LOCAL-FAMILY' not in payload
        assert 'PRIVATE-CAMPAIGN' not in payload
        assert 'private-feed' not in payload
        assert 'do-not-copy' not in payload


def test_unknown_local_enrichment_marking_raises_report_marking_conservatively():
    from app.services.cti_investigation import enrichment_tlp
    assert enrichment_tlp([{'enrichment': {'matches': [{'tlp': ''}]}}]) == 'TLP:RED'
    assert enrichment_tlp([{'enrichment': {'matches': [{'tlp': 'clear'}]}}]) == 'TLP:AMBER+STRICT'
