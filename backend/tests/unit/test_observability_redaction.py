from app.api.routes.observability import _redact_log_line


def test_log_redaction_covers_json_headers_cookies_and_form_values():
    line = (
        'payload={"access_token":"json-secret","password":"p@ss"} '
        "Authorization: Bearer bearer-secret "
        "Cookie: session=cookie-secret; theme=dark "
        "api-key='quoted-secret' refresh_token=form-secret"
    )

    redacted = _redact_log_line(line)

    for secret in ("json-secret", "p@ss", "bearer-secret", "cookie-secret", "quoted-secret", "form-secret"):
        assert secret not in redacted
    assert redacted.count("[REDACTED]") >= 5


def test_log_redaction_preserves_non_sensitive_diagnostic_context():
    line = "request_id=abc123 status=502 path=/api/analyze provider=local"

    assert _redact_log_line(line) == line
