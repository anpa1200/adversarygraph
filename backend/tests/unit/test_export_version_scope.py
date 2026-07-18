from app.api.routes.export import _group_export_query, _technique_export_query


def test_stix_export_lookup_queries_are_scoped_to_one_attack_version():
    technique_query = _technique_export_query({"T1059"}, "enterprise-attack", 42)
    group_query = _group_export_query({"G0001"}, "enterprise-attack", 42)

    technique_sql = str(technique_query)
    group_sql = str(group_query)
    assert "techniques.version_id" in technique_sql
    assert "apt_groups.version_id" in group_sql
    assert 42 in technique_query.compile().params.values()
    assert 42 in group_query.compile().params.values()
