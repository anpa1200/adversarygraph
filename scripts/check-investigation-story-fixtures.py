"""Offline evidence-pack replay; never invokes an LLM or changes stored cases.

Run from backend with PYTHONPATH=. python ../scripts/check-investigation-story-fixtures.py
  /path/to/adversarygraph-ten-additional-cases
"""
import argparse
import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID

from fastapi import HTTPException

from app.models.analysis import AnalysisSession
from app.models.ioc import IOCInvestigationSession
from app.models.pcap import PcapAnalysis
from app.services.investigation_story import build_pack


class ReplayDB:
    def __init__(self):
        self.rows = {}

    async def get(self, model, uid, **kwargs):
        return self.rows.get((model, uid))


async def main(root):
    db = ReplayDB()
    for path in sorted((root / "reports/enrichment").glob("*.json")):
        data = json.loads(path.read_text())
        if not data.get("session_id") or not data.get("artifact"):
            continue
        db.rows[(IOCInvestigationSession, UUID(data["session_id"]))] = SimpleNamespace(
            artifact=data["artifact"], artifact_type=data["artifact_type"],
            result=data, created_at="unknown in retained API artifact",
        )
    results = []
    for directory in sorted((root / "reports/cases").iterdir()):
        if not directory.is_dir():
            continue
        data = json.loads((directory / "api-upload.json").read_text())
        sid = UUID(data["session_id"])
        db.rows[(PcapAnalysis, UUID(data["analysis_id"]))] = SimpleNamespace(
            status="completed", semantic_sha256=data["semantic_sha256"], result=data["result"],
            report_text=data["report"], session_id=sid,
        )
        db.rows[(AnalysisSession, sid)] = SimpleNamespace(
            tlp="TLP:AMBER+STRICT", source_provenance={"pcap_context": data.get("context", {})},
        )
        workspace = json.loads((root / "reports/packet-enrichment-links" / f"{directory.name}-updated.json").read_text())
        # The actual post-investigation dossier, not just an early PCAP preview.
        workspace["evidence_nodes"].append({"id": "replay-full-report", "type": "investigation-report",
                                            "content": (directory / "REPORT.md").read_text()})
        try:
            result = await build_pack(db, SimpleNamespace(**workspace), "replay-full-report")
            identities = data["result"]["identities"]
            joined = "\n".join(s["text"] for s in result["sources"] if s["kind"] == "packet_fact")
            assert all(identity["value"] in joined for identity in identities)
            assert result["coverage"]["full_report_truncated"] is False
            assert "ai_input" not in "\n".join(s["text"] for s in result["sources"] if s["kind"] == "intelligence_lead")
            results.append({"case": directory.name, "status": "passed", "identities_preserved": len(identities),
                            "source_sha256": result["source_sha256"], **result["coverage"]})
        except HTTPException as exc:
            results.append({"case": directory.name, "status": "rejected", "http_status": exc.status_code, "reason": exc.detail})
    print(json.dumps({"scope": "offline evidence-pack replay, not LLM accuracy or live deployment testing",
                      "llm_calls": 0, "cases": results}, indent=2))
    return 0 if results and all(item["status"] == "passed" for item in results) else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    args = parser.parse_args()
    raise SystemExit(asyncio.run(main(args.root)))
