import pytest

from app.services.query_library import (
    SUPPORTED_LANGUAGES,
    build_ioc_query,
    curated_records,
    detect_ioc_type,
    parse_search_query,
)


def test_curated_library_has_reviewed_sigma_and_yaral_coverage():
    records = curated_records()
    assert len(records) >= 30
    assert {record["language"] for record in records} == {"sigma", "yaral"}
    assert all(record["technique_ids"] for record in records)
    assert all(record["source_url"].startswith("https://attack.mitre.org/techniques/") for record in records)
    assert len({record["stable_key"] for record in records}) == len(records)


def test_fielded_query_parser_supports_aliases_and_phrases():
    terms = parse_search_query('encoded powershell tag:execution ttp:T1059.001 lang:yaral source:"SigmaHQ Rules"')
    assert [(term.field, term.value) for term in terms] == [
        ("text", "encoded"),
        ("text", "powershell"),
        ("tag", "execution"),
        ("technique", "T1059.001"),
        ("language", "yaral"),
        ("source", "SigmaHQ Rules"),
    ]


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("203.0.113.4", "ip"),
        ("2001:db8::4", "ip"),
        ("malicious.example", "domain"),
        ("https://malicious.example/a", "url"),
        ("analyst@example.com", "email"),
        ("44d88612fea8a8f36de82e1278abb02f", "md5"),
        ("a" * 40, "sha1"),
        ("b" * 64, "sha256"),
    ],
)
def test_ioc_type_detection(value, expected):
    assert detect_ioc_type(value) == expected


@pytest.mark.parametrize("language", SUPPORTED_LANGUAGES)
def test_ioc_builder_generates_every_supported_language(language):
    result = build_ioc_query(
        [
            {"value": "203.0.113.7"},
            {"value": "malicious.example"},
            {"value": "b" * 64},
        ],
        language,
        technique_ids=["T1071.001"],
    )
    assert result["query_language"] == language
    assert result["query_text"]
    assert result["technique_ids"] == ["T1071.001"]
    assert result["observables"][0]["type"] == "ip"
    assert result["warnings"]


def test_ioc_builder_escapes_quotes_and_does_not_use_llm():
    result = build_ioc_query([{"value": 'example.org" OR *', "type": "domain"}], "yaral")
    assert '\\" OR *' in result["query_text"]
    assert "Generated locally without an LLM" in result["description"]


def test_ioc_builder_rejects_empty_and_unknown_language():
    with pytest.raises(ValueError, match="At least one"):
        build_ioc_query([], "sigma")
    with pytest.raises(ValueError, match="Unsupported"):
        build_ioc_query([{"value": "example.org"}], "made-up")
