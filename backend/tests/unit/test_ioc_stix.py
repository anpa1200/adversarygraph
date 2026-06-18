from app.services.ioc_stix import _indicator_pattern, _parse_pattern, _sco_value


def test_ioc_stix_pattern_roundtrip_for_hash_domain_ip_url():
    cases = [
        ("sha256", "a" * 64),
        ("sha1", "b" * 40),
        ("md5", "c" * 32),
        ("domain", "example.com"),
        ("url", "https://example.com/a"),
        ("ipv4", "8.8.8.8"),
        ("ip:port", "8.8.8.8:443"),
    ]
    for kind, value in cases:
        pattern = _indicator_pattern(kind, value)
        parsed = _parse_pattern(pattern)
        assert parsed is not None
        if kind == "ip:port":
            assert parsed == {"type": "ipv4", "value": "8.8.8.8"}
        else:
            assert parsed["value"] == value


def test_ioc_stix_sco_values_from_observed_data_objects():
    assert _sco_value({"type": "domain-name", "value": "example.com"}) == {"type": "domain", "value": "example.com"}
    assert _sco_value({"type": "ipv4-addr", "value": "1.2.3.4"}) == {"type": "ipv4", "value": "1.2.3.4"}
    assert _sco_value({"type": "file", "hashes": {"SHA-256": "a" * 64}}) == {"type": "sha256", "value": "a" * 64}
