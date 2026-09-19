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
