"""Read-only local evidence check. Run inside API with public case workspace IDs.

No adapter is instantiated, no model/provider is called and no database writes
are made. Only count/hash diagnostics and already recorded usage are emitted.
"""
import asyncio
import json
import sys
from uuid import UUID

from sqlalchemy import select

from app.core.database import async_session_factory
from app.models.operations import Investigation
from app.models.pipeline import AuditEvent
from app.services.investigation_story import build_pack, canonical, cited_passages


async def main():
    rows = []
    async with async_session_factory() as db:
        for identifier in sys.argv[1:]:
            investigation = await db.get(Investigation, UUID(identifier))
            reports = [n for n in investigation.evidence_nodes if n.get("type") == "investigation-report"]
            pack = await build_pack(db, investigation, reports[-1]["id"])
            projected, bindings = cited_passages(pack)
            lossless = all(original["text"] == "".join(p["text"] for p in group["passages"])
                           for original, group in zip(pack["sources"], projected["sources"], strict=True))
            sources = {s["source_id"]: s for s in pack["sources"]}
            rebound = all(sources[b["source_id"]]["text"].count(b["quote"]) == 1 for b in bindings.values())
            events = (await db.execute(select(AuditEvent).where(
                AuditEvent.object_id == identifier,
                AuditEvent.action.in_(["operations.summary.validation_failed", "operations.summary.provider_failed"]),
            ))).scalars().all()
            attempts = []
            for event in events:
                details = event.details or {}
                attempts.append({"created_at": str(event.created_at), "action": event.action,
                                 **{k: details[k] for k in ("model", "provider", "category", "code", "rate_details", "attempts", "prior_attempts") if k in details}})
            rows.append({"investigation_id": identifier, "prompt_version": pack["schema_version"],
                         "source_sha256": pack["source_sha256"], "effective_tlp": pack["effective_tlp"],
                         "source_characters": pack["coverage"]["source_characters"],
                         "projected_characters": len(canonical(projected)),
                         "source_records": len(pack["sources"]), "citable_passages": len(bindings),
                         "all_source_text_preserved": lossless, "all_passages_uniquely_bound": rebound,
                         "historical_failed_attempts": attempts, "model_called": False})
            assert lossless and rebound
    print(json.dumps({"scope": "Read-only local evidence check; not native LLM validation", "cases": rows}, indent=2))


asyncio.run(main())
