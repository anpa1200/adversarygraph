from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
from typing import Any
from uuid import UUID

from fastapi import HTTPException
from sqlalchemy import func, or_, select
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql import cast

from app.models.threat_hunting import ThreatHuntFinding, ThreatHuntQueryVersion
from app.models.threat_radar import ThreatHuntRequest


HUNT_TRANSITIONS: dict[str, set[str]] = {
    "queued": {"planned", "running", "cancelled", "archived"},
    "draft": {"planned", "cancelled", "archived"},
    "planned": {"running", "cancelled", "archived"},
    "running": {"review", "cancelled", "archived"},
    "review": {"running", "completed", "cancelled", "archived"},
    "completed": {"archived"},
    "cancelled": {"archived"},
    "archived": set(),
}
FINDING_TRANSITIONS: dict[str, set[str]] = {
    "new": {"reviewed", "escalated", "closed"},
    "reviewed": {"escalated", "closed"},
    "escalated": {"reviewed", "closed"},
    "closed": set(),
}
EVIDENCE_REVIEW_STATUSES = {"reviewed", "escalated", "closed"}
EVIDENCE_VERDICTS = {"supports", "refutes"}
MUTABLE_HUNT_STATUSES = {"queued", "draft", "planned", "running", "review"}
COMPLETION_DISPOSITIONS = {
    "no_matches",
    "benign",
    "benign_policy_relevant",
    "suspicious",
    "confirmed_malicious",
    "inconclusive",
    "telemetry_gap",
    "query_failure",
}
READY_HUNT_STATUSES = {"planned", "running", "review", "completed"}
TLP_RANK = {
    "TLP:CLEAR": 0,
    "TLP:GREEN": 1,
    "TLP:AMBER": 2,
    "TLP:AMBER+STRICT": 3,
    "TLP:RED": 4,
}


HUNT_TEMPLATES: list[dict[str, Any]] = [
    {
        "id": "powershell-encoded-execution",
        "title": "Suspicious encoded PowerShell execution",
        "hypothesis": "An adversary is using encoded or obfuscated PowerShell to execute commands on managed endpoints.",
        "description": "Review unusual PowerShell process and script-block activity, then separate administration from suspicious execution chains.",
        "technique_ids": ["T1059.001", "T1027"],
        "tactics": ["execution", "stealth"],
        "telemetry_sources": ["Process creation", "PowerShell Script Block Logging", "EDR process telemetry"],
        "required_fields": ["@timestamp", "host.name", "user.name", "process.command_line", "process.parent.name", "process.hash.sha256"],
        "query_language": "generic",
        "query_text": "process.name:powershell AND (command_line contains -enc OR command_line contains FromBase64String)",
        "expected_evidence": "Encoded command flags, decode functions, suspicious parent processes, or network/file activity linked by host and time.",
        "false_positive_notes": "Approved automation, software deployment, administrative scripts, and security tooling can use encoded PowerShell.",
        "tags": ["endpoint", "powershell", "execution"],
    },
    {
        "id": "credential-access-lsass",
        "title": "Credential access against LSASS",
        "hypothesis": "An adversary is attempting to access LSASS memory or create a process dump to obtain credentials.",
        "description": "Correlate process access, dump creation, command execution, and follow-on authentication activity.",
        "technique_ids": ["T1003.001"],
        "tactics": ["credential-access"],
        "telemetry_sources": ["EDR process access", "Windows Security", "Sysmon", "File creation"],
        "required_fields": ["@timestamp", "host.name", "user.name", "process.name", "target.process.name", "access_mask", "file.path"],
        "query_language": "generic",
        "query_text": "target.process.name:lsass.exe AND (process_access:true OR file.path contains .dmp)",
        "expected_evidence": "Unexpected LSASS access, dump artifacts, suspicious tools, or credential use following the event.",
        "false_positive_notes": "EDR, backup, identity, and diagnostic products may legitimately access LSASS; baseline signed tools and service accounts.",
        "tags": ["endpoint", "windows", "credential-access"],
    },
    {
        "id": "dns-beaconing",
        "title": "Periodic DNS or encrypted-channel beaconing",
        "hypothesis": "A host is using repeated low-volume DNS or TLS connections as command-and-control beaconing.",
        "description": "Search for periodic destinations, rare domains, unusual timing, and endpoint/network correlation.",
        "technique_ids": ["T1071.004", "T1071.001"],
        "tactics": ["command-and-control"],
        "telemetry_sources": ["DNS logs", "Proxy logs", "Firewall/NetFlow", "EDR network telemetry"],
        "required_fields": ["@timestamp", "host.name", "source.ip", "destination.ip", "dns.question.name", "network.bytes", "tls.client.ja4"],
        "query_language": "generic",
        "query_text": "group connections by source and destination; identify low-jitter periodic intervals and rare destinations",
        "expected_evidence": "Repeated connections with consistent intervals, rare infrastructure, stable fingerprints, or correlated suspicious processes.",
        "false_positive_notes": "Monitoring agents, update services, VPN clients, and cloud applications commonly produce periodic traffic.",
        "tags": ["network", "dns", "beaconing"],
    },
    {
        "id": "valid-account-cloud-abuse",
        "title": "Cloud or identity-provider valid-account abuse",
        "hypothesis": "A valid account is being used from unusual infrastructure or in a sequence inconsistent with its established behavior.",
        "description": "Correlate authentication, device, geolocation, MFA, privilege, and cloud audit events.",
        "technique_ids": ["T1078", "T1098"],
        "tactics": ["stealth", "persistence", "privilege-escalation", "initial-access"],
        "telemetry_sources": ["Identity-provider sign-in logs", "Cloud audit logs", "MFA events", "Device inventory"],
        "required_fields": ["@timestamp", "user.name", "source.ip", "source.geo.country", "device.id", "event.action", "authentication.result"],
        "query_language": "generic",
        "query_text": "successful authentication followed by privilege, credential, or persistence changes from a new device or network",
        "expected_evidence": "New device/network, unusual MFA sequence, risky sign-in, privilege changes, or access to atypical resources.",
        "false_positive_notes": "Travel, VPN egress, mobile networks, device replacement, and approved administrative changes affect identity baselines.",
        "tags": ["identity", "cloud", "valid-accounts"],
    },
    {
        "id": "scheduled-task-persistence",
        "title": "Unexpected scheduled-task persistence",
        "hypothesis": "An adversary created or modified a scheduled task to obtain persistence or execute tooling.",
        "description": "Review task creation, command content, creator identity, binary reputation, and surrounding process activity.",
        "technique_ids": ["T1053.005"],
        "tactics": ["persistence", "privilege-escalation", "execution"],
        "telemetry_sources": ["Windows Task Scheduler", "Process creation", "Registry", "EDR telemetry"],
        "required_fields": ["@timestamp", "host.name", "user.name", "task.name", "task.action", "process.command_line", "file.hash.sha256"],
        "query_language": "generic",
        "query_text": "new or modified scheduled tasks excluding approved deployment and maintenance baselines",
        "expected_evidence": "New task definitions, suspicious execution paths, hidden tasks, or correlated file/process activity.",
        "false_positive_notes": "Enterprise software, patching, inventory, and administrators frequently create scheduled tasks.",
        "tags": ["windows", "persistence", "scheduled-task"],
    },
    {
        "id": "web-shell-activity",
        "title": "Web-shell behavior on an internet-facing server",
        "hypothesis": "A web-facing service process is spawning commands or writing executable server-side content consistent with a web shell.",
        "description": "Correlate web requests, process ancestry, file writes, authentication, and outbound connections.",
        "technique_ids": ["T1505.003", "T1059"],
        "tactics": ["persistence", "execution"],
        "telemetry_sources": ["Web access/error logs", "EDR process telemetry", "File integrity", "Network telemetry"],
        "required_fields": ["@timestamp", "host.name", "url.path", "http.request.method", "process.parent.name", "process.command_line", "file.path"],
        "query_language": "generic",
        "query_text": "web server process spawning shell/interpreter OR writing executable content under a served directory",
        "expected_evidence": "Suspicious child processes, newly written scripts, anomalous requests, or outbound connections from the web service context.",
        "false_positive_notes": "Deployment systems, application frameworks, maintenance scripts, and administrative consoles can create similar activity.",
        "tags": ["web", "server", "persistence"],
    },
]


def _model_data(data: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(data)
    if "telemetry_sources" in normalized:
        normalized["telemetry"] = normalized.pop("telemetry_sources")
    return normalized


def _ensure_mutable(hunt: ThreatHuntRequest) -> None:
    if hunt.status not in MUTABLE_HUNT_STATUSES:
        raise HTTPException(409, f"Hunt is {hunt.status} and its evidence record is read-only")


def _validate_readiness(
    *,
    status: str,
    scope: str,
    telemetry: list[str],
    expected_evidence: str,
    false_positive_notes: str,
) -> None:
    if status not in READY_HUNT_STATUSES:
        return
    missing: list[str] = []
    if not scope.strip():
        missing.append("scope")
    if not telemetry:
        missing.append("telemetry_sources")
    if not expected_evidence.strip():
        missing.append("expected_evidence")
    if not false_positive_notes.strip():
        missing.append("false_positive_notes")
    if missing:
        raise HTTPException(
            422,
            f"Hunt status {status} requires: {', '.join(missing)}",
        )


def _prevent_tlp_downgrade(current: str, proposed: str) -> None:
    if TLP_RANK.get(proposed, -1) < TLP_RANK.get(current, -1):
        raise HTTPException(
            422,
            f"TLP cannot be downgraded from {current} to {proposed} in the hunt workspace",
        )


async def list_hunts(
    db: AsyncSession,
    *,
    q: str = "",
    status: str = "",
    priority: str = "",
    technique_id: str = "",
    limit: int = 100,
    offset: int = 0,
) -> list[ThreatHuntRequest]:
    statement = select(ThreatHuntRequest)
    if q:
        pattern = f"%{q.strip()}%"
        statement = statement.where(
            or_(ThreatHuntRequest.title.ilike(pattern), ThreatHuntRequest.hypothesis.ilike(pattern))
        )
    if status:
        statement = statement.where(ThreatHuntRequest.status == status)
    if priority:
        statement = statement.where(ThreatHuntRequest.priority == priority)
    if technique_id:
        statement = statement.where(
            ThreatHuntRequest.technique_ids.contains(cast([technique_id.upper()], JSONB))
        )
    statement = statement.order_by(ThreatHuntRequest.updated_at.desc()).limit(limit).offset(offset)
    return list((await db.execute(statement)).scalars().all())


async def get_hunt(
    db: AsyncSession,
    hunt_id: UUID,
    *,
    for_update: bool = False,
) -> ThreatHuntRequest:
    if for_update:
        statement = (
            select(ThreatHuntRequest)
            .where(ThreatHuntRequest.id == hunt_id)
            .with_for_update()
        )
        hunt = (await db.execute(statement)).scalar_one_or_none()
    else:
        hunt = await db.get(ThreatHuntRequest, hunt_id)
    if not hunt:
        raise HTTPException(404, "Threat hunt not found")
    return hunt


async def create_hunt(db: AsyncSession, data: dict[str, Any], created_by: str) -> ThreatHuntRequest:
    now = datetime.now(timezone.utc)
    normalized = _model_data(data)
    if normalized.get("status", "draft") not in {"draft", "planned"}:
        raise HTTPException(422, "New analyst-created hunts must start as draft or planned")
    _validate_readiness(
        status=normalized.get("status", "draft"),
        scope=normalized.get("scope", ""),
        telemetry=normalized.get("telemetry", []),
        expected_evidence=normalized.get("expected_evidence", ""),
        false_positive_notes=normalized.get("false_positive_notes", ""),
    )
    hunt = ThreatHuntRequest(
        **normalized,
        case_id=None,
        source_type="manual",
        source_ref="",
        created_by=created_by,
        created_at=now,
        updated_at=now,
    )
    db.add(hunt)
    await db.flush()
    if hunt.query_text:
        await append_query_version(db, hunt, created_by)
    return hunt


async def update_hunt(
    db: AsyncSession,
    hunt_id: UUID,
    data: dict[str, Any],
    actor: str,
) -> ThreatHuntRequest:
    hunt = await get_hunt(db, hunt_id, for_update=True)
    _ensure_mutable(hunt)
    normalized = _model_data(data)
    proposed_start = normalized.get("time_range_start", hunt.time_range_start)
    proposed_end = normalized.get("time_range_end", hunt.time_range_end)
    if proposed_start and proposed_end and proposed_end <= proposed_start:
        raise HTTPException(422, "time_range_end must be later than time_range_start")

    proposed_status = normalized.get("status", hunt.status)
    if "tlp" in normalized:
        _prevent_tlp_downgrade(hunt.tlp, normalized["tlp"])
    if proposed_status == "archived":
        raise HTTPException(409, "Use the archive endpoint so archival provenance is recorded")
    if proposed_status != hunt.status and proposed_status not in HUNT_TRANSITIONS.get(hunt.status, set()):
        raise HTTPException(409, f"Invalid hunt transition: {hunt.status} -> {proposed_status}")
    _validate_readiness(
        status=proposed_status,
        scope=normalized.get("scope", hunt.scope),
        telemetry=normalized.get("telemetry", hunt.telemetry or []),
        expected_evidence=normalized.get("expected_evidence", hunt.expected_evidence),
        false_positive_notes=normalized.get("false_positive_notes", hunt.false_positive_notes),
    )
    proposed_summary = normalized.get("result_summary", hunt.result_summary)
    proposed_disposition = normalized.get("disposition", hunt.disposition)
    if proposed_status == "completed":
        if not proposed_summary.strip():
            raise HTTPException(422, "A completed hunt requires a result summary")
        if proposed_disposition not in COMPLETION_DISPOSITIONS:
            raise HTTPException(422, "A completed hunt requires a reviewed disposition")
        unresolved = (
            await db.execute(
                select(ThreatHuntFinding.id)
                .where(
                    ThreatHuntFinding.hunt_id == hunt.id,
                    ThreatHuntFinding.archived_at.is_(None),
                    ThreatHuntFinding.status == "new",
                )
                .limit(1)
            )
        ).scalar_one_or_none()
        if unresolved:
            raise HTTPException(422, "Review or archive all new findings before completing the hunt")
        if proposed_disposition in {"suspicious", "confirmed_malicious"}:
            supporting_candidates = (
                await db.execute(
                    select(ThreatHuntFinding)
                    .where(
                        ThreatHuntFinding.hunt_id == hunt.id,
                        ThreatHuntFinding.archived_at.is_(None),
                        ThreatHuntFinding.verdict == "supports",
                        ThreatHuntFinding.status.in_(["reviewed", "escalated", "closed"]),
                    )
                )
            ).scalars().all()
            supporting = any(
                (item.evidence_ref or "").strip() and (item.summary or "").strip()
                for item in supporting_candidates
            )
            if not supporting:
                raise HTTPException(
                    422,
                    "Suspicious or malicious dispositions require a reviewed supporting finding with an evidence reference and summary",
                )

    query_changed = any(
        key in normalized and normalized[key] != getattr(hunt, key)
        for key in ("query_text", "query_language", "assumptions")
    )
    previous_tlp = hunt.tlp
    for key, value in normalized.items():
        setattr(hunt, key, value)
    hunt.updated_at = datetime.now(timezone.utc)
    if hunt.tlp != previous_tlp:
        lower_labels = [
            label
            for label, rank in TLP_RANK.items()
            if rank < TLP_RANK[hunt.tlp]
        ]
        if lower_labels:
            classified_findings = (
                await db.execute(
                    select(ThreatHuntFinding)
                    .where(
                        ThreatHuntFinding.hunt_id == hunt.id,
                        ThreatHuntFinding.tlp.in_(lower_labels),
                    )
                    .with_for_update()
                )
            ).scalars().all()
            for finding in classified_findings:
                finding.tlp = hunt.tlp
                finding.updated_at = hunt.updated_at
    if hunt.status == "completed" and hunt.completed_at is None:
        hunt.completed_at = hunt.updated_at
    await db.flush()
    if query_changed and hunt.query_text:
        await append_query_version(db, hunt, actor)
    return hunt


async def archive_hunt(db: AsyncSession, hunt_id: UUID) -> ThreatHuntRequest:
    hunt = await get_hunt(db, hunt_id, for_update=True)
    if hunt.status == "archived":
        return hunt
    if "archived" not in HUNT_TRANSITIONS.get(hunt.status, set()):
        raise HTTPException(409, f"Hunt cannot be archived from status {hunt.status}")
    now = datetime.now(timezone.utc)
    hunt.status = "archived"
    hunt.archived_at = now
    hunt.updated_at = now
    await db.flush()
    return hunt


async def append_query_version(
    db: AsyncSession,
    hunt: ThreatHuntRequest,
    actor: str,
) -> ThreatHuntQueryVersion:
    statement = select(func.max(ThreatHuntQueryVersion.version)).where(
        ThreatHuntQueryVersion.hunt_id == hunt.id
    )
    latest = (await db.execute(statement)).scalar_one_or_none() or 0
    assumptions = hunt.assumptions or ""
    content = f"{hunt.query_language}\0{hunt.query_text}\0{assumptions}"
    revision = ThreatHuntQueryVersion(
        hunt_id=hunt.id,
        version=int(latest) + 1,
        language=hunt.query_language,
        query_text=hunt.query_text,
        backend_assumptions=assumptions,
        checksum=sha256(content.encode("utf-8")).hexdigest(),
        created_by=actor,
        created_at=datetime.now(timezone.utc),
    )
    db.add(revision)
    await db.flush()
    return revision


async def list_query_versions(
    db: AsyncSession,
    hunt_id: UUID,
    *,
    limit: int | None = None,
    offset: int = 0,
) -> list[ThreatHuntQueryVersion]:
    await get_hunt(db, hunt_id)
    statement = (
        select(ThreatHuntQueryVersion)
        .where(ThreatHuntQueryVersion.hunt_id == hunt_id)
        .order_by(ThreatHuntQueryVersion.version.desc())
    )
    if limit is not None:
        statement = statement.limit(max(1, min(limit, 500))).offset(max(offset, 0))
    return list((await db.execute(statement)).scalars().all())


async def _latest_query_version(db: AsyncSession, hunt_id: UUID) -> ThreatHuntQueryVersion | None:
    statement = (
        select(ThreatHuntQueryVersion)
        .where(ThreatHuntQueryVersion.hunt_id == hunt_id)
        .order_by(ThreatHuntQueryVersion.version.desc())
        .limit(1)
    )
    return (await db.execute(statement)).scalar_one_or_none()


async def list_findings(
    db: AsyncSession,
    hunt_id: UUID,
    *,
    include_archived: bool = False,
    limit: int | None = None,
    offset: int = 0,
) -> list[ThreatHuntFinding]:
    await get_hunt(db, hunt_id)
    statement = select(ThreatHuntFinding).where(ThreatHuntFinding.hunt_id == hunt_id)
    if not include_archived:
        statement = statement.where(ThreatHuntFinding.archived_at.is_(None))
    statement = statement.order_by(ThreatHuntFinding.created_at.desc())
    if limit is not None:
        statement = statement.limit(max(1, min(limit, 500))).offset(max(offset, 0))
    return list((await db.execute(statement)).scalars().all())


async def create_finding(db: AsyncSession, hunt_id: UUID, data: dict[str, Any], analyst: str) -> ThreatHuntFinding:
    hunt = await get_hunt(db, hunt_id, for_update=True)
    _ensure_mutable(hunt)
    now = datetime.now(timezone.utc)
    finding_data = dict(data)
    requested_status = str(finding_data.get("status") or "new")
    if requested_status != "new":
        raise HTTPException(
            422,
            "New findings must start with status new; use the update endpoint for review transitions",
        )
    finding_data["status"] = "new"
    finding_data["tlp"] = finding_data.get("tlp") or hunt.tlp
    _prevent_tlp_downgrade(hunt.tlp, finding_data["tlp"])
    query_version_id = finding_data.get("query_version_id")
    if query_version_id:
        version = await db.get(ThreatHuntQueryVersion, query_version_id)
        if not version or version.hunt_id != hunt.id:
            raise HTTPException(422, "query_version_id does not belong to this hunt")
    else:
        version = await _latest_query_version(db, hunt.id)
        finding_data["query_version_id"] = version.id if version else None
    finding_data["analyst"] = analyst
    _validate_finding_review_evidence(
        status=str(finding_data.get("status") or "new"),
        verdict=str(finding_data.get("verdict") or "inconclusive"),
        evidence_ref=str(finding_data.get("evidence_ref") or ""),
        summary=str(finding_data.get("summary") or ""),
    )
    finding = ThreatHuntFinding(
        **finding_data,
        hunt_id=hunt.id,
        created_at=now,
        updated_at=now,
    )
    db.add(finding)
    hunt.updated_at = now
    await db.flush()
    return finding


async def get_finding(db: AsyncSession, hunt_id: UUID, finding_id: UUID) -> ThreatHuntFinding:
    finding = await db.get(ThreatHuntFinding, finding_id)
    if not finding or finding.hunt_id != hunt_id or finding.archived_at is not None:
        raise HTTPException(404, "Threat hunt finding not found")
    return finding


async def update_finding(
    db: AsyncSession,
    hunt_id: UUID,
    finding_id: UUID,
    data: dict[str, Any],
) -> ThreatHuntFinding:
    hunt = await get_hunt(db, hunt_id, for_update=True)
    _ensure_mutable(hunt)
    finding = await get_finding(db, hunt_id, finding_id)
    proposed_status = str(data.get("status", finding.status))
    proposed_verdict = str(data.get("verdict", finding.verdict))
    proposed_evidence_ref = str(data.get("evidence_ref", finding.evidence_ref) or "")
    proposed_summary = str(data.get("summary", finding.summary) or "")
    if proposed_status != finding.status and proposed_status not in FINDING_TRANSITIONS.get(finding.status, set()):
        raise HTTPException(409, f"Invalid finding transition: {finding.status} -> {proposed_status}")
    _validate_finding_review_evidence(
        status=proposed_status,
        verdict=proposed_verdict,
        evidence_ref=proposed_evidence_ref,
        summary=proposed_summary,
    )
    if "tlp" in data and data["tlp"] is not None:
        _prevent_tlp_downgrade(hunt.tlp, data["tlp"])
        _prevent_tlp_downgrade(finding.tlp, data["tlp"])
    query_version_id = data.get("query_version_id")
    if query_version_id:
        version = await db.get(ThreatHuntQueryVersion, query_version_id)
        if not version or version.hunt_id != hunt.id:
            raise HTTPException(422, "query_version_id does not belong to this hunt")
    for key, value in data.items():
        setattr(finding, key, value)
    finding.updated_at = datetime.now(timezone.utc)
    await db.flush()
    return finding


def _validate_finding_review_evidence(
    *,
    status: str,
    verdict: str,
    evidence_ref: str,
    summary: str,
) -> None:
    if status not in EVIDENCE_REVIEW_STATUSES or verdict not in EVIDENCE_VERDICTS:
        return
    missing: list[str] = []
    if not evidence_ref.strip():
        missing.append("evidence_ref")
    if not summary.strip():
        missing.append("summary")
    if missing:
        raise HTTPException(
            422,
            f"Reviewed supporting or refuting findings require nonblank {', '.join(missing)}",
        )


async def archive_finding(
    db: AsyncSession,
    hunt_id: UUID,
    finding_id: UUID,
    actor: str,
) -> ThreatHuntFinding:
    hunt = await get_hunt(db, hunt_id, for_update=True)
    _ensure_mutable(hunt)
    finding = await get_finding(db, hunt_id, finding_id)
    finding.archived_at = datetime.now(timezone.utc)
    finding.archived_by = actor
    finding.updated_at = finding.archived_at
    await db.flush()
    return finding


def build_stats(hunts: list[ThreatHuntRequest], findings: list[ThreatHuntFinding]) -> dict[str, Any]:
    by_status: dict[str, int] = {}
    by_priority: dict[str, int] = {}
    for hunt in hunts:
        by_status[hunt.status] = by_status.get(hunt.status, 0) + 1
        by_priority[hunt.priority] = by_priority.get(hunt.priority, 0) + 1
    return {
        "total_hunts": len(hunts),
        "active_hunts": sum(1 for hunt in hunts if hunt.status in {"queued", "planned", "running", "review"}),
        "completed_hunts": sum(1 for hunt in hunts if hunt.status == "completed"),
        "total_findings": len(findings),
        "high_priority_findings": sum(1 for item in findings if item.severity in {"high", "critical"}),
        "by_status": by_status,
        "by_priority": by_priority,
    }


async def get_stats(db: AsyncSession) -> dict[str, Any]:
    status_rows = (
        await db.execute(
            select(ThreatHuntRequest.status, func.count(ThreatHuntRequest.id)).group_by(
                ThreatHuntRequest.status
            )
        )
    ).all()
    priority_rows = (
        await db.execute(
            select(ThreatHuntRequest.priority, func.count(ThreatHuntRequest.id)).group_by(
                ThreatHuntRequest.priority
            )
        )
    ).all()
    by_status = {str(status): int(count) for status, count in status_rows}
    by_priority = {str(priority): int(count) for priority, count in priority_rows}
    finding_count = (
        await db.execute(
            select(func.count(ThreatHuntFinding.id)).where(ThreatHuntFinding.archived_at.is_(None))
        )
    ).scalar_one_or_none() or 0
    high_count = (
        await db.execute(
            select(func.count(ThreatHuntFinding.id)).where(
                ThreatHuntFinding.archived_at.is_(None),
                ThreatHuntFinding.severity.in_(["high", "critical"]),
            )
        )
    ).scalar_one_or_none() or 0
    return {
        "total_hunts": sum(by_status.values()),
        "active_hunts": sum(by_status.get(status, 0) for status in {"queued", "planned", "running", "review"}),
        "completed_hunts": by_status.get("completed", 0),
        "total_findings": int(finding_count),
        "high_priority_findings": int(high_count),
        "by_status": by_status,
        "by_priority": by_priority,
    }
