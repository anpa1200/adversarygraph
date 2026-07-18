"""Shared best-effort redaction for diagnostic text.

Redaction is defense in depth, not permission to log request bodies or
credentials. Callers should still avoid putting sensitive values in errors.
"""

from __future__ import annotations

import re

_AUTH_RE = re.compile(r"(?i)\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+")
_URL_USERINFO_RE = re.compile(r"(?i)(https?://)[^\s/@:]+:[^\s/@]+@")
_SENSITIVE_ASSIGNMENT_RE = re.compile(
    r"(?i)([\"']?(?:access[_-]?token|refresh[_-]?token|token|api[_-]?key|apikey|"
    r"client[_-]?secret|password|passwd|secret|authorization|cookie|set-cookie|session)[\"']?\s*[:=]\s*)"
    r"(?:\"[^\"]*\"|'[^']*'|[^\s,;}\]]+)"
)


def redact_sensitive_text(value: object) -> str:
    """Remove common credential forms while preserving useful context."""
    text = str(value)
    redacted = _AUTH_RE.sub(lambda match: f"{match.group(0).split(None, 1)[0]} [REDACTED]", text)
    redacted = _URL_USERINFO_RE.sub(r"\1[REDACTED]@", redacted)
    return _SENSITIVE_ASSIGNMENT_RE.sub(r"\1[REDACTED]", redacted)
