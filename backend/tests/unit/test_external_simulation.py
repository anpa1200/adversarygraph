from app.services.external_simulation import build_plan, list_simulations, list_targets, run_controlled_record


def test_catalog_contains_safe_external_ttp_simulations():
    catalog = list_simulations()
    ids = {item["id"] for item in catalog}
    assert "sim-t1595-http-fingerprint" in ids
    assert "sim-t1190-web-exposure" in ids
    assert all(item["destructive"] is False for item in catalog)


def test_plan_allows_only_allowlisted_target_simulation_pair():
    plan = build_plan("sim-t1595-http-fingerprint", "lab-web-01")
    assert plan["allowed"] is True
    assert plan["target"]["environment"] == "lab"
    assert "target allowlist" in " ".join(plan["approval_checklist"]).lower()


def test_plan_blocks_mismatched_target_type():
    plan = build_plan("sim-t1110-lab-login-sequence", "lab-web-01")
    assert plan["allowed"] is False
    assert plan["block_reasons"]


def test_run_record_does_not_emit_traffic():
    result = run_controlled_record("sim-t1595-http-fingerprint", "lab-web-01", "test")
    assert result["status"] == "completed_record_only"
    assert result["traffic_emitted"] is False
    assert result["validation_status"] == "not_proven"
    assert any("No network traffic emitted" in line for line in result["transcript"])


def test_targets_are_lab_fixtures():
    targets = list_targets()
    assert targets
    assert all(item["environment"] == "lab" for item in targets)
