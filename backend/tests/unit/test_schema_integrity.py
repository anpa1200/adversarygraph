from app.models.evidence_graph import EvidenceGraphEdge
from app.models.threat_hunting import ThreatHuntAIAssistance


def _foreign_key(column):
    keys = list(column.foreign_keys)
    assert len(keys) == 1
    return keys[0]


def test_persisted_ai_source_and_evidence_edges_have_delete_safe_foreign_keys():
    source_fk = _foreign_key(ThreatHuntAIAssistance.__table__.c.source_session_id)
    edge_source_fk = _foreign_key(EvidenceGraphEdge.__table__.c.source_node_id)
    edge_target_fk = _foreign_key(EvidenceGraphEdge.__table__.c.target_node_id)

    assert source_fk.target_fullname == "analysis_sessions.id"
    assert source_fk.ondelete == "SET NULL"
    assert edge_source_fk.target_fullname == "evidence_graph_nodes.id"
    assert edge_target_fk.target_fullname == "evidence_graph_nodes.id"
    assert edge_source_fk.ondelete == "CASCADE"
    assert edge_target_fk.ondelete == "CASCADE"
