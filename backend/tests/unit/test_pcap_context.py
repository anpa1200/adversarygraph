from app.services.pcap_context import observable_key


def test_ioc_matching_preserves_url_case_and_types():
    assert observable_key('domain', 'Example.COM.') == ('domain', 'example.com')
    assert observable_key('sha256', 'ABCD') == ('sha256', 'abcd')
    assert observable_key('url', 'https://example.com/SECRET') != observable_key('url', 'https://example.com/secret')
    assert observable_key('ip', '1.2.3.4') == observable_key('ipv4', '1.2.3.4')
    assert observable_key('domain', 'hash') != observable_key('sha256', 'hash')
