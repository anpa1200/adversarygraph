from uuid import uuid4

from app.api.routes.analyze import (
    LinkedReportEntity,
    _dedupe_entities,
    _extract_html_report,
    _extract_cve_ids,
    _fallback_report_text,
    _is_public_http_url,
    _redact_url_secrets,
    _report_images_from_intake,
)
from app.models.analysis import AnalysisResult, AnalysisSession
from app.models.operations import ReportIntake


def test_extract_cve_ids_normalizes_and_deduplicates():
    values = _extract_cve_ids(
        "Observed CVE-2024-3094 and cve-2024-3094 in the report.",
        "Follow-on exploitation references CVE-2023-3519.",
    )

    assert values == ["CVE-2024-3094", "CVE-2023-3519"]


def test_dedupe_entities_keeps_first_entity_per_type_and_value():
    entities = _dedupe_entities(
        [
            LinkedReportEntity(type="cve", id="CVE-2024-3094", label="CVE-2024-3094", value="CVE-2024-3094"),
            LinkedReportEntity(type="cve", id="duplicate", label="duplicate", value="cve-2024-3094"),
            LinkedReportEntity(type="ioc", id="1.2.3.4", label="1.2.3.4", value="1.2.3.4"),
        ],
        limit=10,
    )

    assert [(item.type, item.value) for item in entities] == [
        ("cve", "CVE-2024-3094"),
        ("ioc", "1.2.3.4"),
    ]


def test_fallback_report_text_exposes_summary_and_techniques_for_old_sessions():
    session_id = uuid4()
    session = AnalysisSession(
        id=session_id,
        status="completed",
        name="Legacy report",
        input_type="text",
        filename=None,
        llm_provider="local",
        model="qwen",
        domain="enterprise-attack",
    )
    result = AnalysisResult(
        session_id=session_id,
        extracted_techniques=[{"attack_id": "T1059.001", "name": "PowerShell", "evidence": "PowerShell execution"}],
        apt_matches=[{"group_attack_id": "G0069", "group_name": "MuddyWater"}],
        summary="Actor used PowerShell and infrastructure overlap.",
        raw_response="",
    )

    text = _fallback_report_text(session, result, None)

    assert "Legacy report" in text
    assert "Actor used PowerShell" in text
    assert "T1059.001 PowerShell" in text
    assert "G0069 MuddyWater" in text


def test_extract_html_report_returns_text_title_and_absolute_images():
    parsed = _extract_html_report(
        """
        <html><head><title>Threat report</title><meta name="description" content="APT activity against VPNs"></head>
        <body><script>alert(1)</script><h1>Campaign</h1><p>Observed CVE-2024-0001 and T1190 exploitation.</p>
        <img src="/images/flow.png" alt="Attack flow infographic"><img src="javascript:alert(1)" alt="bad"></body></html>
        """,
        "https://example.com/reports/report.html",
    )

    assert parsed["title"] == "Threat report"
    assert "APT activity against VPNs" in parsed["text"]
    assert "Observed CVE-2024-0001" in parsed["text"]
    assert "alert(1)" not in parsed["text"]
    assert len(parsed["images"]) == 1
    assert parsed["images"][0].url == "https://example.com/images/flow.png"


def test_extract_html_report_prefers_article_and_drops_page_chrome_images():
    parsed = _extract_html_report(
        """
        <html><head><title>Vendor report</title></head><body>
        <header><img src="/brand-logo.png" alt="Vendor logo"><p>Navigation home products</p></header>
        <div class="banner promo"><img src="/promo-banner.jpg" alt="Subscribe banner">Subscribe today</div>
        <main>
          <article class="threat-report content-body">
            <h1>Intrusion analysis</h1>
            <p>Actor used T1190 against public web applications and dropped a web shell.</p>
            <p>Follow-on activity included CVE-2024-12345 exploitation and command execution.</p>
            <img src="/reports/kill-chain.png" alt="Kill chain infographic">
          </article>
        </main>
        <aside class="related"><img src="/related-card.jpg" alt="related">Related reports</aside>
        <footer>Legal footer text</footer>
        </body></html>
        """,
        "https://example.com/reports/vendor.html",
    )

    assert "Actor used T1190" in parsed["text"]
    assert "Subscribe today" not in parsed["text"]
    assert "Navigation home products" not in parsed["text"]
    assert [image.url for image in parsed["images"]] == ["https://example.com/reports/kill-chain.png"]


def test_report_images_from_intake_filters_unsafe_urls():
    intake = ReportIntake(
        title="Report",
        analyst_notes='{"report_images":[{"url":"https://example.com/a.png?api_key=image-secret","alt":"A"},{"url":"http://127.0.0.1/private.png","alt":"bad"}]}',
    )

    images = _report_images_from_intake(intake)

    assert len(images) == 1
    assert images[0].url == "https://example.com/a.png?api_key=REDACTED"
    assert "image-secret" not in images[0].url
    assert images[0].alt == "A"


def test_redact_url_secrets_removes_userinfo_fragment_and_sensitive_query_values():
    sanitized = _redact_url_secrets(
        "https://analyst:password@example.com/report?source=feed&token=top-secret&api_key=key-secret&sig=signed#access_token=fragment-secret"
    )

    assert sanitized == (
        "https://example.com/report?source=feed&token=REDACTED&api_key=REDACTED&sig=REDACTED"
    )
    assert "password" not in sanitized
    assert "top-secret" not in sanitized
    assert "fragment-secret" not in sanitized


def test_public_report_url_rejects_embedded_basic_authentication():
    assert _is_public_http_url("https://user:secret@example.com/report") is False


def test_fallback_report_text_redacts_historical_source_url_secrets():
    session_id = uuid4()
    session = AnalysisSession(
        id=session_id,
        status="completed",
        name=None,
        input_type="url",
        filename="https://example.com/report?token=session-secret",
        llm_provider="none",
        model="not-parsed",
        domain="enterprise-attack",
    )
    result = AnalysisResult(
        session_id=session_id,
        extracted_techniques=[],
        apt_matches=[],
        summary="Stored report",
        raw_response="",
    )
    intake = ReportIntake(
        title="Historical report",
        url="https://example.com/report?api_key=intake-secret",
    )

    text = _fallback_report_text(session, result, intake)

    assert "session-secret" not in text
    assert "intake-secret" not in text
    assert "token=REDACTED" in text
    assert "api_key=REDACTED" in text
