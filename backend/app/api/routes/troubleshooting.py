from __future__ import annotations

import json
import logging
import re
from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from app.services.ai.factory import get_adapter
from app.services.auth import TeamUser, require_permission

router = APIRouter(prefix="/troubleshooting", tags=["Troubleshooting"])
logger = logging.getLogger(__name__)

ALLOWED_PROVIDERS = {"local", "claude", "openai", "gemini", "minimax"}


class TroubleshootingAssistantRequest(BaseModel):
    provider: str = Field(default="local", pattern="^(local|claude|openai|gemini|minimax)$")
    model: str | None = Field(default=None, max_length=120)
    error_message: str = Field(default="", max_length=2000)
    status: str = Field(default="", max_length=80)
    url: str = Field(default="", max_length=1000)
    operator_notes: str = Field(default="", max_length=6000)
    selftest_result: dict[str, Any] | None = None
    include_docker_commands: bool = True


class TroubleshootingAssistantResponse(BaseModel):
    provider: str
    model: str
    ai_used: bool
    severity: str
    summary: str
    likely_root_cause: str
    immediate_actions: list[str]
    validation_commands: list[str]
    evidence_to_collect: list[str]
    do_not_do: list[str]
    raw_response: str = ""


SYSTEM_PROMPT = """You are the AdversaryGraph troubleshooting assistant.

You help operators diagnose a self-hosted Docker/Kubernetes cybersecurity platform.
Return ONLY valid JSON. Do not include markdown fences.

Output schema:
{
  "severity": "low|medium|high|critical",
  "summary": "brief operator summary",
  "likely_root_cause": "most likely cause based on evidence",
  "immediate_actions": ["ordered remediation steps"],
  "validation_commands": ["safe read-only or low-risk commands"],
  "evidence_to_collect": ["logs, endpoints, config fields to inspect"],
  "do_not_do": ["unsafe actions to avoid"]
}

Rules:
- Be concrete and operational.
- Prefer non-destructive commands.
- Never recommend deleting Docker volumes unless the context explicitly says data loss is acceptable.
- Never ask for secrets or tokens. If credentials are relevant, say to check presence/configuration only.
- Mention when the evidence is insufficient and what to collect next.
- For ATT&CK storage failures, check /app/data/attck ownership, mounted volume permissions, and UID 999 appuser writes.
- For 502 after restart, distinguish startup ingestion delay from a persistent frontend proxy/API failure.
- For missing data, check self-test checks named attack_versions, attack_data, ioc_sync, cve_sync, and storage writability.
"""


@router.post("/assistant", response_model=TroubleshootingAssistantResponse)
async def assistant(
    body: TroubleshootingAssistantRequest,
    _: TeamUser = Depends(require_permission("run_analysis")),
) -> TroubleshootingAssistantResponse:
    fallback = _deterministic_response(body)
    try:
        adapter = get_adapter(body.provider, body.model)
        raw = await adapter._raw_complete(SYSTEM_PROMPT, _build_user_prompt(body))
        parsed = _parse_response(raw)
        if not parsed:
            fallback.raw_response = raw[:4000]
            return fallback
        return TroubleshootingAssistantResponse(
            provider=adapter.provider,
            model=adapter.model,
            ai_used=True,
            severity=_bounded_choice(str(parsed.get("severity", fallback.severity)), {"low", "medium", "high", "critical"}, fallback.severity),
            summary=_clean_text(parsed.get("summary"), fallback.summary, 1200),
            likely_root_cause=_clean_text(parsed.get("likely_root_cause"), fallback.likely_root_cause, 1200),
            immediate_actions=_clean_list(parsed.get("immediate_actions"), fallback.immediate_actions, 12),
            validation_commands=_clean_list(parsed.get("validation_commands"), fallback.validation_commands, 10),
            evidence_to_collect=_clean_list(parsed.get("evidence_to_collect"), fallback.evidence_to_collect, 10),
            do_not_do=_clean_list(parsed.get("do_not_do"), fallback.do_not_do, 8),
            raw_response=raw[:4000],
        )
    except Exception as exc:
        logger.exception("Troubleshooting AI provider request failed provider=%s", body.provider)
        fallback.summary = f"{fallback.summary} AI provider failed, so deterministic guidance is shown."
        fallback.raw_response = "AI provider request failed. See server logs."
        return fallback


def _build_user_prompt(body: TroubleshootingAssistantRequest) -> str:
    context = {
        "error_message": body.error_message,
        "status": body.status,
        "url": body.url,
        "operator_notes": body.operator_notes,
        "include_docker_commands": body.include_docker_commands,
        "selftest_result": _trim_selftest(body.selftest_result),
    }
    return "Troubleshoot this AdversaryGraph deployment context:\n" + json.dumps(context, indent=2, sort_keys=True)


def _trim_selftest(result: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(result, dict):
        return None
    checks = result.get("checks")
    trimmed_checks = []
    if isinstance(checks, list):
        for check in checks[:40]:
            if not isinstance(check, dict):
                continue
            status = str(check.get("status", ""))
            include = status != "ok" or check.get("name") in {"api_keys", "attack_versions", "attack_data", "ioc_sync", "cve_sync", "attck_storage_writable", "log_storage_writable"}
            if include:
                trimmed_checks.append({
                    "name": check.get("name"),
                    "status": check.get("status"),
                    "message": check.get("message"),
                    "details": _shorten(check.get("details"), 2000),
                })
    return {
        "status": result.get("status"),
        "version": result.get("version"),
        "checked_at": result.get("checked_at"),
        "duration_ms": result.get("duration_ms"),
        "checks": trimmed_checks,
    }


def _shorten(value: Any, max_chars: int) -> Any:
    text = json.dumps(value, default=str, sort_keys=True)
    if len(text) <= max_chars:
        return value
    return text[:max_chars] + "...[truncated]"


def _parse_response(raw: str) -> dict[str, Any] | None:
    text = raw.strip()
    text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.MULTILINE)
    text = re.sub(r"\s*```$", "", text, flags=re.MULTILINE)
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        try:
            start = text.index("{")
            data, _ = json.JSONDecoder().raw_decode(text, start)
        except (ValueError, json.JSONDecodeError):
            return None
    return data if isinstance(data, dict) else None


def _deterministic_response(body: TroubleshootingAssistantRequest) -> TroubleshootingAssistantResponse:
    failed_checks = _failed_checks(body.selftest_result)
    combined = " ".join([body.error_message, body.status, body.url, body.operator_notes, " ".join(failed_checks)]).lower()
    severity = "medium"
    root = "The available context is incomplete. Start with self-test output and API/container logs."
    actions = [
        "Run the built-in self-test and identify the first failed or degraded check.",
        "Inspect API logs around the first exception or failed dependency check.",
        "Validate the affected endpoint through the frontend proxy after the API is ready.",
    ]
    commands = [
        "docker compose ps",
        "docker compose logs --tail=160 api",
        "curl -fsS http://localhost:3000/api/health",
    ]

    if "attck_storage_writable" in combined or "/app/data/attck" in combined or "permission denied" in combined:
        severity = "high"
        root = "The ATT&CK cache volume is mounted but is not writable by the non-root API user."
        actions = [
            "Check ownership and permissions for /app/data/attck inside the API container.",
            "Run or restart the Compose permissions helper so the attck_data volume is owned by UID/GID 999.",
            "Recreate API, worker, and beat after the volume ownership is corrected.",
            "Rerun self-test and confirm attck_storage_writable is ok.",
        ]
        commands = [
            "docker compose exec -T api sh -lc 'id; ls -ld /app/data/attck'",
            "docker compose up attck-data-permissions",
            "docker compose up -d --force-recreate api worker beat frontend",
            "docker compose exec -T api sh -lc 'touch /app/data/attck/.adversarygraph-selftest && rm /app/data/attck/.adversarygraph-selftest'",
        ]
    elif "502" in combined or "bad gateway" in combined:
        severity = "medium"
        root = "The frontend proxy cannot currently reach a ready API container, or the API is still in startup ingestion."
        actions = [
            "Check whether API startup has completed before treating the 502 as persistent.",
            "Confirm the API container is running and healthy through Compose.",
            "Review API logs for startup exceptions after ATT&CK ingestion begins.",
            "Retry the frontend proxy health endpoint after startup completes.",
        ]
        commands = [
            "docker compose ps api frontend",
            "docker compose logs --tail=120 api",
            "curl -fsS http://localhost:3000/api/health",
        ]
    elif "401" in combined or "unauthorized" in combined:
        severity = "low"
        root = "Authentication is enabled and the endpoint requires a logged-in session."
        actions = [
            "Log in through the web UI before calling protected API routes.",
            "Use /api/health for unauthenticated liveness and /api/system/selftest from an authenticated browser session.",
            "Confirm the user role has permission for the requested module.",
        ]
        commands = [
            "curl -fsS http://localhost:3000/api/health",
            "docker compose logs --tail=80 api",
        ]

    return TroubleshootingAssistantResponse(
        provider=body.provider,
        model=body.model or "deterministic-fallback",
        ai_used=False,
        severity=severity,
        summary="Troubleshooting guidance generated from local rules and supplied context.",
        likely_root_cause=root,
        immediate_actions=actions,
        validation_commands=commands if body.include_docker_commands else [cmd for cmd in commands if cmd.startswith("curl")],
        evidence_to_collect=[
            "Self-test JSON with failed/degraded checks.",
            "API logs around the failure time.",
            "docker compose ps output.",
            "Exact browser/API error message and URL.",
        ],
        do_not_do=[
            "Do not delete Docker volumes unless you have a backup and explicitly want data loss.",
            "Do not paste secrets, API keys, or passwords into troubleshooting notes.",
            "Do not expose the local instance publicly while AUTH_ENABLED=false.",
        ],
    )


def _failed_checks(result: dict[str, Any] | None) -> list[str]:
    if not isinstance(result, dict):
        return []
    checks = result.get("checks")
    if not isinstance(checks, list):
        return []
    failed = []
    for check in checks:
        if isinstance(check, dict) and str(check.get("status", "")).lower() != "ok":
            failed.append(f"{check.get('name', '')}: {check.get('message', '')}")
    return failed


def _bounded_choice(value: str, allowed: set[str], default: str) -> str:
    normalized = value.strip().lower()
    return normalized if normalized in allowed else default


def _clean_text(value: Any, default: str, max_chars: int) -> str:
    text = str(value or "").strip()
    return text[:max_chars] if text else default


def _clean_list(value: Any, default: list[str], limit: int) -> list[str]:
    if not isinstance(value, list):
        return default
    cleaned = [str(item).strip()[:1000] for item in value if str(item).strip()]
    return cleaned[:limit] or default
