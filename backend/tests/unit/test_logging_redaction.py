import logging
import sys

from app.core.logging_config import SensitiveDataFilter


def test_sensitive_data_filter_redacts_message_and_exception_text():
    try:
        raise RuntimeError("provider failed with token=exception-secret")
    except RuntimeError:
        exc_info = sys.exc_info()

    record = logging.LogRecord(
        name="test",
        level=logging.ERROR,
        pathname=__file__,
        lineno=10,
        msg="request https://user:password@host/path?api_key=query-secret Authorization: Basic dXNlcjpwYXNz",
        args=(),
        exc_info=exc_info,
    )

    assert SensitiveDataFilter().filter(record) is True
    rendered = logging.Formatter("%(message)s\n%(exc_text)s").format(record)

    for secret in ("password", "query-secret", "dXNlcjpwYXNz", "exception-secret"):
        assert secret not in rendered
    assert rendered.count("[REDACTED]") >= 4


def test_sensitive_data_filter_preserves_diagnostic_context():
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname=__file__,
        lineno=10,
        msg="request_id=%s status=%d path=%s",
        args=("abc123", 502, "/api/analyze"),
        exc_info=None,
    )

    SensitiveDataFilter().filter(record)

    assert record.getMessage() == "request_id=abc123 status=502 path=/api/analyze"
