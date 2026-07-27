from app.services.taxonomy import normalize_freeform_tags


def test_cross_link_tags_are_canonical_and_deduplicated():
    assert normalize_freeform_tags(
        [
            "CVE-2026-12345",
            "cve:cve-2026-12345",
            "T1059.001",
            "TA0002",
            "G0069",
            "C0021",
            "Risk:CRIT",
        ]
    ) == [
        "cve:CVE-2026-12345",
        "ttp:T1059.001",
        "tactic:TA0002",
        "actor:G0069",
        "campaign:C0021",
        "risk:critical",
    ]
