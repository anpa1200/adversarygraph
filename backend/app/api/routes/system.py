import os
from datetime import datetime, timezone
from time import perf_counter
from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel
from sqlalchemy import func, select, text

from app.core.config import settings
from app.core.database import async_session_factory
from app.models.attack import AptGroup, AttackVersion, Tactic, Technique

router = APIRouter(prefix="/system", tags=["System"])


class SelfTestCheck(BaseModel):
    name: str
    status: str
    message: str
    details: dict[str, Any] = {}


class SelfTestResult(BaseModel):
    status: str
    version: str
    checked_at: str
    duration_ms: int
    checks: list[SelfTestCheck]


def _check(name: str, ok: bool, message: str, details: dict[str, Any] | None = None) -> SelfTestCheck:
    return SelfTestCheck(
        name=name,
        status="ok" if ok else "error",
        message=message,
        details=details or {},
    )


def _api_key_check() -> SelfTestCheck:
    providers: dict[str, dict[str, Any]] = {
        "anthropic": {"configured": bool(settings.anthropic_api_key), "env_var": "ANTHROPIC_API_KEY", "required_for": ["Claude AI analysis"]},
        "openai": {"configured": bool(settings.openai_api_key), "env_var": "OPENAI_API_KEY", "required_for": ["OpenAI AI analysis"]},
        "gemini": {"configured": bool(settings.gemini_api_key), "env_var": "GEMINI_API_KEY", "required_for": ["Gemini AI analysis"]},
        "local_llm_base_url": {"configured": bool(settings.local_llm_base_url), "env_var": "LOCAL_LLM_BASE_URL", "required_for": ["local LLM analysis"]},
        "threatfox": {"configured": bool(settings.threatfox_auth_key), "env_var": "THREATFOX_AUTH_KEY", "required_for": ["ThreatFox IOC sync"]},
        "otx": {"configured": bool(settings.otx_api_key), "env_var": "OTX_API_KEY", "required_for": ["OTX IOC sync"]},
        "virustotal": {"configured": bool(settings.virustotal_api_key), "env_var": "VIRUSTOTAL_API_KEY", "required_for": ["VirusTotal IOC lookup"]},
    }
    configured = [name for name, data in providers.items() if data["configured"]]
    missing_optional = [name for name, data in providers.items() if not data["configured"]]
    return _check(
        "api_keys",
        True,
        f"API key configuration checked: {len(configured)} configured, {len(missing_optional)} missing optional.",
        {
            "configured": configured,
            "missing_optional": missing_optional,
            "providers": providers,
            "secrets_exposed": False,
        },
    )


@router.get("/selftest", response_model=SelfTestResult)
async def selftest() -> SelfTestResult:
    started = perf_counter()
    checks: list[SelfTestCheck] = []

    try:
        async with async_session_factory() as session:
            await session.execute(text("select 1"))
            checks.append(
                _check(
                    "database",
                    True,
                    "Database connection succeeded.",
                    {
                        "db_name": settings.db_name,
                        "db_host": settings.db_host,
                        "external_data_dir": os.environ.get("ADVERSARYGRAPH_DB_DIR", "./data/postgres"),
                        "layout": "persistent external Postgres data directory; public references and private/custom data are source-separated",
                    },
                )
            )

            versions = (await session.execute(select(AttackVersion))).scalars().all()
            version_map = {version.domain: version.version for version in versions if version.is_latest}
            expected_domains = settings.attck_domain_list
            missing_domains = [domain for domain in expected_domains if domain not in version_map]
            checks.append(
                _check(
                    "attack_versions",
                    not missing_domains,
                    "ATT&CK/ATLAS versions are present."
                    if not missing_domains
                    else f"Missing ingested domains: {', '.join(missing_domains)}.",
                    {"latest_versions": version_map, "expected_domains": expected_domains},
                )
            )

            domain_counts: dict[str, dict[str, int]] = {}
            for domain in expected_domains:
                row = await session.execute(
                    select(AttackVersion.id).where(
                        AttackVersion.domain == domain,
                        AttackVersion.is_latest.is_(True),
                    )
                )
                version_id = row.scalar_one_or_none()
                if not version_id:
                    domain_counts[domain] = {"tactics": 0, "techniques": 0, "groups": 0}
                    continue
                tactics = await session.scalar(select(func.count()).select_from(Tactic).where(Tactic.version_id == version_id))
                techniques = await session.scalar(select(func.count()).select_from(Technique).where(Technique.version_id == version_id))
                groups = await session.scalar(select(func.count()).select_from(AptGroup).where(AptGroup.version_id == version_id))
                domain_counts[domain] = {
                    "tactics": int(tactics or 0),
                    "techniques": int(techniques or 0),
                    "groups": int(groups or 0),
                }

            empty_domains = [
                domain for domain, counts in domain_counts.items()
                if counts["tactics"] == 0 or counts["techniques"] == 0
            ]
            checks.append(
                _check(
                    "attack_data",
                    not empty_domains,
                    "ATT&CK/ATLAS tactics and techniques are loaded."
                    if not empty_domains
                    else f"No tactics or techniques loaded for: {', '.join(empty_domains)}.",
                    {"domain_counts": domain_counts},
                )
            )
    except Exception as exc:
        checks.append(
            _check(
                "database",
                False,
                f"Database self-test failed: {type(exc).__name__}: {exc}",
            )
        )

    try:
        import redis

        client = redis.Redis.from_url(settings.redis_url, socket_connect_timeout=2, socket_timeout=2)
        client.ping()
        checks.append(_check("redis", True, "Redis connection succeeded."))
    except Exception as exc:
        checks.append(_check("redis", False, f"Redis self-test failed: {type(exc).__name__}: {exc}"))

    checks.append(_api_key_check())

    failed = [check for check in checks if check.status != "ok"]
    status = "ok" if not failed else "error"
    return SelfTestResult(
        status=status,
        version="2.5.0",
        checked_at=datetime.now(timezone.utc).isoformat(),
        duration_ms=int((perf_counter() - started) * 1000),
        checks=checks,
    )
