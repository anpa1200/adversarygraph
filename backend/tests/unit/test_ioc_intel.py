from app.services.ioc_intel import _malpedia_family_to_import_item


def test_malpedia_family_to_import_item_maps_attribution_and_context():
    item = _malpedia_family_to_import_item(
        "win.example",
        {
            "common_name": "ExampleRat",
            "alt_names": ["Example RAT", "ExampleTool"],
            "attribution": ["APT28", "Fancy Bear"],
            "urls": ["https://example.test/report"],
            "sources": ["vendor report"],
            "updated": "2026-06-01",
            "uuid": "abc",
        },
    )

    assert item.value == "win.example"
    assert item.indicator_type == "malware-family"
    assert item.malware_family == "ExampleRat"
    assert item.actor_name == "APT28, Fancy Bear"
    assert item.source_url == "https://example.test/report"
    assert "Example RAT" in item.tags
    assert "APT28" in item.tags
