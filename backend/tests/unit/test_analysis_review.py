from app.api.routes.analyze import update_extracted_technique_review


def test_update_extracted_technique_review_sets_status_and_note():
    techniques = [
        {
            "attack_id": "T1059",
            "name": "Command and Scripting Interpreter",
            "tactic": "execution",
            "confidence": 0.7,
            "evidence": "PowerShell launched encoded commands",
            "review_status": "suggested",
            "evidence_source": "source-text",
        }
    ]

    updated = update_extracted_technique_review(
        techniques,
        "t1059",
        review_status="accepted",
        review_note="Confirmed in source paragraph 4.",
        reviewer="analyst@example.test",
    )

    assert updated is techniques[0]
    assert techniques[0]["review_status"] == "accepted"
    assert techniques[0]["review_note"] == "Confirmed in source paragraph 4."
    assert techniques[0]["reviewer"] == "analyst@example.test"


def test_update_extracted_technique_review_overrides_evidence_as_analyst_source():
    techniques = [
        {
            "attack_id": "T1003",
            "name": "OS Credential Dumping",
            "tactic": "credential-access",
            "confidence": 0.8,
            "evidence": "dumping was mentioned",
            "review_status": "needs-evidence",
            "evidence_start": 10,
            "evidence_end": 31,
            "evidence_source": "llm",
        }
    ]

    updated = update_extracted_technique_review(
        techniques,
        "T1003",
        review_status="accepted",
        evidence="The report states LSASS memory was dumped.",
    )

    assert updated["evidence"] == "The report states LSASS memory was dumped."
    assert updated["evidence_source"] == "analyst"
    assert updated["evidence_start"] is None
    assert updated["evidence_end"] is None


def test_update_extracted_technique_review_returns_none_for_missing_id():
    techniques = [{"attack_id": "T1059", "review_status": "suggested"}]

    assert update_extracted_technique_review(
        techniques,
        "T9999",
        review_status="rejected",
    ) is None
