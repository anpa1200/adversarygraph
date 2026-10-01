from app.services.runtime_intelligence import _tokens


def test_runtime_asset_tokens_normalize_names_domains_and_technologies():
    assert _tokens(
        "checkout.prod",
        ["checkout.example.com"],
        ["PostgreSQL", "OpenTelemetry"],
    ) == {"checkout", "example", "postgresql", "opentelemetry"}


def test_runtime_asset_tokens_ignore_empty_and_tiny_fragments():
    assert _tokens("", None, ["db", "a", "api.gateway"]) == {"api", "gateway"}
