"""Exercise real PDF layout rather than mocking the renderer."""
import fitz
from app.services.report_generator import generate_analysis_report


def test_draft_pdf_renders_multiple_promotion_blockers():
    blockers = ['analyst_gate_pending', 'source_bound_claims_required', 'a' * 300]
    output = generate_analysis_report({
        'session_id': 'pcap-live-regression', 'provider': 'deterministic',
        'model': 'tshark-evidence-v3', 'domain': 'enterprise-attack',
        'review_state': 'draft', 'summary': 'Packet evidence requires analyst review.',
        'review': {'state': 'draft', 'profile': 'internal_ir', 'revision': 1,
                   'readiness': {'ready': False, 'blockers': blockers}},
    })
    assert output.startswith(b'%PDF-')
    document = fitz.open(stream=output, filetype='pdf')
    text = '\n'.join(page.get_text() for page in document)
    assert 'DRAFT ASSESSMENT' in text
    assert 'analyst_gate_pending' in text
    assert 'source_bound_claims_required' in text
    assert 'authenticated analyst' in text


def test_packet_evidence_appendix_preserves_frames_and_hashes():
    output = generate_analysis_report({
        'summary': 'Deterministic observations.', 'review_state': 'draft',
        'packet_evidence_report': 'frame 187: HTTP response\nSHA256 ' + 'a' * 64
        + '\n' + 'long-untrusted-value' * 100 + '\nfinal-frame-999',
    })
    document = fitz.open(stream=output, filetype='pdf')
    text = '\n'.join(page.get_text() for page in document)
    assert 'Packet Evidence Appendix' in text
    assert 'frame 187' in text and 'final-frame-999' in text
    assert 'a' * 64 in text
    assert 'does not approve' in text


def test_cti_draft_appendix_preserves_sources_and_does_not_approve_candidates():
    output = generate_analysis_report({
        'summary': 'Candidate research.', 'review_state': 'draft',
        'investigation': {
            'status': 'partial', 'report': 'Source reports execution [S002]. Attribution unknown.',
            'sources': [{'id': 'S002', 'title': 'Vendor report', 'url': 'https://vendor.example/blog/report', 'sha256': 'b' * 64}],
            'indicators': [{'indicator_type': 'domain', 'value': 'evil.example', 'role': 'candidate',
                            'enrichment': {'status': 'no_match'}, 'evidence': [{'source_id': 'S002'}]}],
            'warnings': ['One source unavailable.'], 'limitations': ['No match means unknown.'],
        },
    })
    document = fitz.open(stream=output, filetype='pdf')
    text = '\n'.join(page.get_text() for page in document)
    assert 'Draft Appendix' in text
    assert 'evil.example' in text
    assert 'Vendor report' in text
    assert 'does not grant promotion' in text
    assert 'One source unavailable.' in text


def test_multipage_investigation_body_does_not_overlap_running_header():
    output = generate_analysis_report({'summary': 'Draft.', 'review_state': 'draft', 'investigation': {
        'status': 'partial', 'report': '\n'.join(f'Body-line-{i}: source evidence [S002].' for i in range(170)),
        'sources': [], 'indicators': [], 'warnings': [], 'limitations': [],
    }})
    document = fitz.open(stream=output, filetype='pdf')
    checked = 0
    for page in document:
        headers = page.search_for('AdversaryGraph - Threat Intelligence Report')
        lines = page.search_for('Body-line-')
        if headers and lines:
            assert min(rect.y0 for rect in lines) > max(rect.y1 for rect in headers)
            checked += 1
    assert checked >= 2


def test_restricted_local_context_marks_the_pdf_cover_and_appendix_red():
    output = generate_analysis_report({'summary': 'Draft.', 'tlp': 'TLP:AMBER+STRICT', 'review_state': 'draft',
                                      'investigation': {'status': 'partial', 'tlp': 'TLP:RED', 'report': 'Observed source [S001].',
                                                        'sources': [], 'indicators': [], 'warnings': [], 'limitations': []}})
    document = fitz.open(stream=output, filetype='pdf')
    assert 'TLP:RED' in document[0].get_text()
    assert 'TLP:RED' in document[-1].get_text()
