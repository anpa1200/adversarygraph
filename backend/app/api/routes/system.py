import os
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter, sleep
from typing import Any

import httpx
from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel
from sqlalchemy import func, select, text

from app.core.config import settings
from app.core.database import async_session_factory, get_session
from app.core.version import APP_VERSION
from app.models.attack import AptGroup, AttackVersion, StixObject, StixRelationship, Tactic, Technique
from app.models.auth import UserAccount
from app.models.cve import CVEActorLink, CVEIOCLink, CVERecord, CVESource, CVETechniqueLink
from app.models.ioc import IOCIndicator, IOCSource
from app.models.rag import RAGChunk, RAGDocument, RAGIndexRun
from app.services.auth import TeamUser, audit, require_permission
from app.services.cve_intel import ensure_cve_sources
from app.services.data_integrity import ioc_cve_integrity_snapshot
from app.services.startup_status import startup_status
from app.services.taxonomy_migration import normalize_existing_taxonomy, taxonomy_normalization_status

router = APIRouter(prefix="/system", tags=["System"])
manage_taxonomy = require_permission("manage_feeds")
run_selftest = require_permission("run_analysis")


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


class ApiOperationCapability(BaseModel):
    method: str
    path: str
    operation_id: str
    summary: str
    success_codes: list[str]
    deprecated: bool = False


class ApiModuleCapability(BaseModel):
    name: str
    operation_count: int
    operations: list[ApiOperationCapability]


class ApiCapabilitiesOut(BaseModel):
    name: str
    version: str
    openapi_url: str
    docs_url: str
    redoc_url: str
    module_count: int
    path_count: int
    operation_count: int
    generated_at: str
    modules: list[ApiModuleCapability]


@router.get("/startup")
async def startup() -> dict[str, Any]:
    return startup_status.snapshot()


@router.get(
    "/capabilities",
    response_model=ApiCapabilitiesOut,
    summary="List every supported API module and operation",
)
async def api_capabilities(request: Request) -> ApiCapabilitiesOut:
    """Return a machine-readable inventory derived from the active OpenAPI contract."""
    schema = request.app.openapi()
    modules: dict[str, list[ApiOperationCapability]] = {}
    methods = {"delete", "get", "head", "options", "patch", "post", "put"}

    for path, path_item in schema.get("paths", {}).items():
        for method, operation in path_item.items():
            if method.lower() not in methods:
                continue
            tags = operation.get("tags") or ["System"]
            success_codes = sorted(
                str(code)
                for code in operation.get("responses", {})
                if str(code).startswith("2")
            )
            capability = ApiOperationCapability(
                method=method.upper(),
                path=path,
                operation_id=str(operation.get("operationId") or ""),
                summary=str(operation.get("summary") or ""),
                success_codes=success_codes,
                deprecated=bool(operation.get("deprecated", False)),
            )
            for tag in tags:
                modules.setdefault(str(tag), []).append(capability)

    module_items = [
        ApiModuleCapability(
            name=name,
            operation_count=len(operations),
            operations=sorted(operations, key=lambda item: (item.path, item.method)),
        )
        for name, operations in sorted(modules.items())
    ]
    return ApiCapabilitiesOut(
        name=str(schema.get("info", {}).get("title") or request.app.title),
        version=str(schema.get("info", {}).get("version") or request.app.version),
        openapi_url=request.app.openapi_url or "/openapi.json",
        docs_url=request.app.docs_url or "/docs",
        redoc_url=request.app.redoc_url or "/redoc",
        module_count=len(module_items),
        path_count=len(schema.get("paths", {})),
        operation_count=sum(item.operation_count for item in module_items),
        generated_at=datetime.now(timezone.utc).isoformat(),
        modules=module_items,
    )


@router.get("/taxonomy/status")
async def taxonomy_status(db=Depends(get_session), _: TeamUser = Depends(manage_taxonomy)) -> dict[str, Any]:
    return await taxonomy_normalization_status(db)


@router.post("/taxonomy/normalize")
async def normalize_taxonomy(db=Depends(get_session), user: TeamUser = Depends(manage_taxonomy)) -> dict[str, Any]:
    result = await normalize_existing_taxonomy(db, commit=False)
    await audit(
        db,
        user,
        "system.taxonomy_normalize",
        "taxonomy",
        details={"rows_changed": result.get("rows_changed", 0), "tables": result.get("tables", {})},
    )
    await db.commit()
    return result


def _check(name: str, ok: bool, message: str, details: dict[str, Any] | None = None) -> SelfTestCheck:
    return _check_status(name, "ok" if ok else "error", message, details)


def _check_status(
    name: str,
    status: str,
    message: str,
    details: dict[str, Any] | None = None,
) -> SelfTestCheck:
    return SelfTestCheck(
        name=name,
        status=status,
        message=message,
        details=details or {},
    )


def _overall_selftest_status(checks: list[SelfTestCheck]) -> str:
    if any(check.status == "error" for check in checks):
        return "error"
    if any(check.status in {"warning", "degraded"} for check in checks):
        return "degraded"
    return "ok"


def _data_integrity_check(summary: dict[str, Any]) -> SelfTestCheck:
    duplicate_groups = summary.get("duplicate_groups") or {}
    scan_status = summary.get("status")
    if scan_status in {"pending", "running"}:
        return _check_status(
            "ioc_cve_dedup_integrity",
            "warning",
            "IOC/CVE deduplication integrity scan is running in the background.",
            summary,
        )
    if scan_status == "unavailable":
        return _check_status(
            "ioc_cve_dedup_integrity",
            "error",
            "IOC/CVE deduplication integrity scan could not complete. See server logs.",
            summary,
        )
    status = "ok" if scan_status == "ok" else "error"
    normalized_ioc = int(duplicate_groups.get("normalized_ioc_value_type_source") or 0)
    cve_duplicates = int(duplicate_groups.get("normalized_cve_id") or 0)
    cross_source = int(duplicate_groups.get("cross_source_ioc_overlap") or 0)
    if status == "ok":
        message = (
            "IOC/CVE deduplication integrity passed"
            + (f"; {cross_source} cross-source IOC overlap sample group(s) observed." if cross_source else ".")
        )
    else:
        message = (
            "IOC/CVE duplicate integrity failed: "
            f"{normalized_ioc} normalized IOC duplicate group(s), "
            f"{cve_duplicates} CVE duplicate group(s)."
        )
    return _check_status("ioc_cve_dedup_integrity", status, message, summary)


def _api_key_check() -> SelfTestCheck:
    providers: dict[str, dict[str, Any]] = {
        "anthropic": {
            "configured": bool(settings.anthropic_api_key),
            "env_var": "ANTHROPIC_API_KEY",
            "category": "llm",
            "required_for": ["Claude AI analysis"],
        },
        "openai": {
            "configured": bool(settings.openai_api_key),
            "env_var": "OPENAI_API_KEY",
            "category": "llm",
            "required_for": ["OpenAI AI analysis"],
        },
        "gemini": {
            "configured": bool(settings.gemini_api_key),
            "env_var": "GEMINI_API_KEY",
            "category": "llm",
            "required_for": ["Gemini AI analysis"],
        },
        "minimax": {
            "configured": bool(settings.minimax_api_key),
            "env_var": "MINIMAX_API_KEY",
            "category": "llm",
            "required_for": ["MiniMax AI analysis"],
        },
        "local_llm_base_url": {
            "configured": bool(settings.local_llm_base_url),
            "env_var": "LOCAL_LLM_BASE_URL",
            "category": "llm",
            "required_for": ["local LLM analysis"],
        },
        "threatfox": {
            "configured": bool(settings.threatfox_auth_key),
            "env_var": "THREATFOX_AUTH_KEY",
            "category": "feed",
            "required_for": ["ThreatFox IOC sync", "ThreatFox IOC Investigation lookup"],
        },
        "otx": {
            "configured": bool(settings.otx_api_key),
            "env_var": "OTX_API_KEY",
            "category": "feed",
            "required_for": ["AlienVault OTX IOC sync", "OTX IOC Investigation pivots"],
        },
        "virustotal": {
            "configured": bool(settings.virustotal_api_key),
            "env_var": "VIRUSTOTAL_API_KEY",
            "category": "investigation",
            "required_for": ["VirusTotal IOC lookup", "VirusTotal IOC Investigation enrichment"],
        },
        "urlscan": {
            "configured": True,
            "api_key_configured": bool(settings.urlscan_api_key),
            "env_var": "URLSCAN_API_KEY",
            "category": "investigation",
            "auth_mode": "public lookup; API key optional for higher limits",
            "required_for": ["urlscan IOC Investigation URL/domain/IP activity pivots"],
        },
        "greynoise": {
            "configured": True,
            "api_key_configured": bool(settings.greynoise_api_key),
            "env_var": "GREYNOISE_API_KEY",
            "category": "investigation",
            "auth_mode": "community lookup; API key reserved for paid support",
            "required_for": ["GreyNoise Community IP classification"],
        },
        "abuseipdb": {
            "configured": bool(settings.abuseipdb_api_key),
            "env_var": "ABUSEIPDB_API_KEY",
            "category": "investigation",
            "required_for": ["AbuseIPDB abuse confidence and network-owner context"],
        },
        "shodan": {
            "configured": bool(settings.shodan_api_key),
            "env_var": "SHODAN_API_KEY",
            "category": "investigation",
            "required_for": ["Shodan host exposure, ports, hostnames, and vulnerability context"],
        },
        "censys": {
            "configured": bool(settings.censys_api_key),
            "env_var": "CENSYS_API_KEY",
            "optional_env_var": "CENSYS_ORG_ID",
            "category": "investigation",
            "required_for": ["Censys host, DNS, service, ASN, and certificate-name pivots"],
        },
        "opencti": {
            "configured": bool(settings.opencti_url and settings.opencti_token),
            "env_var": "OPENCTI_URL + OPENCTI_TOKEN",
            "category": "feed",
            "required_for": ["OpenCTI pull/push/bidirectional sync"],
        },
        "nvd": {
            "configured": bool(settings.nvd_api_key),
            "env_var": "NVD_API_KEY",
            "category": "product_security",
            "auth_mode": "optional; public sync works without a key at lower rate limits",
            "required_for": ["higher-rate NVD CVE and CVSS enrichment"],
        },
        "github_advisory_database": {
            "configured": bool(settings.github_token),
            "env_var": "GITHUB_TOKEN",
            "category": "product_security",
            "auth_mode": "optional; public sync works without a token at lower rate limits",
            "required_for": ["higher-rate GitHub Advisory Database sync"],
        },
        "gitlab_advisory_database": {
            "configured": bool(settings.gitlab_token),
            "env_var": "GITLAB_TOKEN",
            "category": "product_security",
            "required_for": ["GitLab advisory/package security lookups"],
        },
        "msrc": {
            "configured": bool(settings.msrc_api_key),
            "env_var": "MSRC_API_KEY",
            "category": "product_security",
            "auth_mode": "optional for many public Microsoft Security Update Guide lookups",
            "required_for": ["Microsoft product security update enrichment"],
        },
        "deps_dev": {
            "configured": bool(settings.deps_dev_api_key),
            "env_var": "DEPS_DEV_API_KEY",
            "category": "product_security",
            "auth_mode": "optional depending API plan",
            "required_for": ["package dependency graph enrichment"],
        },
        "vulncheck": {
            "configured": bool(settings.vulncheck_api_key),
            "env_var": "VULNCHECK_API_KEY",
            "category": "product_security",
            "required_for": ["VulnCheck KEV, NVD++, exploit, and ransomware-enriched CVE intelligence"],
        },
        "snyk": {
            "configured": bool(settings.snyk_token),
            "env_var": "SNYK_TOKEN",
            "category": "product_security",
            "required_for": ["Snyk package vulnerability and license intelligence"],
        },
        "socket": {
            "configured": bool(settings.socket_token),
            "env_var": "SOCKET_TOKEN",
            "category": "product_security",
            "required_for": ["Socket dependency supply-chain risk intelligence"],
        },
        "endoflife_date": {
            "configured": bool(settings.endoflife_date_token),
            "env_var": "ENDOFLIFE_DATE_TOKEN",
            "category": "product_security",
            "auth_mode": "optional; public lifecycle data can be used without a token",
            "required_for": ["commercial lifecycle API access if enabled"],
        },
        "hibp": {
            "configured": bool(settings.hibp_api_key),
            "env_var": "HIBP_API_KEY",
            "category": "exposure",
            "required_for": ["domain breach and exposed-account monitoring"],
        },
        "leakix": {
            "configured": bool(settings.leakix_api_key),
            "env_var": "LEAKIX_API_KEY",
            "category": "exposure",
            "required_for": ["internet-exposed service and leak intelligence"],
        },
        "spycloud": {
            "configured": bool(settings.spycloud_api_key),
            "env_var": "SPYCLOUD_API_KEY",
            "category": "exposure",
            "required_for": ["breach, credential, and stealer-log exposure monitoring"],
        },
        "flare": {
            "configured": bool(settings.flare_api_key),
            "env_var": "FLARE_API_KEY",
            "category": "exposure",
            "required_for": ["external exposure and dark web monitoring"],
        },
        "darkowl": {
            "configured": bool(settings.darkowl_api_key),
            "env_var": "DARKOWL_API_KEY",
            "category": "exposure",
            "required_for": ["darknet intelligence monitoring"],
        },
        "intel471": {
            "configured": bool(settings.intel471_api_key),
            "env_var": "INTEL471_API_KEY",
            "category": "exposure",
            "required_for": ["cybercrime actor, marketplace, and leak reporting"],
        },
        "kela": {
            "configured": bool(settings.kela_api_key),
            "env_var": "KELA_API_KEY",
            "category": "exposure",
            "required_for": ["cybercrime and dark web exposure reporting"],
        },
        "recorded_future": {
            "configured": bool(settings.recorded_future_api_key),
            "env_var": "RECORDED_FUTURE_API_KEY",
            "category": "product_security",
            "required_for": ["Recorded Future vulnerability, actor, and exposure enrichment"],
        },
    }
    configured = [name for name, data in providers.items() if data["configured"]]
    missing_optional = [name for name, data in providers.items() if not data["configured"]]
    configured_by_category: dict[str, list[str]] = {}
    missing_by_category: dict[str, list[str]] = {}
    for name, data in providers.items():
        category = str(data.get("category") or "other")
        target = configured_by_category if data["configured"] else missing_by_category
        target.setdefault(category, []).append(name)
    return _check(
        "api_keys",
        True,
        f"API key configuration checked: {len(configured)} configured, {len(missing_optional)} missing optional.",
        {
            "configured": configured,
            "missing_optional": missing_optional,
            "configured_by_category": configured_by_category,
            "missing_by_category": missing_by_category,
            "providers": providers,
            "secrets_exposed": False,
        },
    )


def _auth_readiness_check(total_users: int, enabled_users: int) -> SelfTestCheck:
    details = {
        "auth_enabled": settings.auth_enabled,
        "sso_mode": settings.auth_sso_mode,
        "native_login_enabled": True,
        "bootstrap_configured": bool(settings.auth_bootstrap_admin_username and settings.auth_bootstrap_admin_password),
        "total_users": total_users,
        "enabled_users": enabled_users,
        "session_minutes": settings.auth_session_minutes,
        "mfa_available": settings.auth_mfa_enabled,
    }
    if not settings.auth_enabled:
        details["production_recommendation"] = "Enable AUTH_ENABLED before exposing the platform to untrusted networks."
        return _check_status(
            "auth_readiness",
            "ok",
            "AUTH_ENABLED=false; local development mode is active.",
            details,
        )
    if enabled_users <= 0 and not details["bootstrap_configured"]:
        return _check_status(
            "auth_readiness",
            "error",
            "Authentication is enabled but no enabled user or bootstrap admin is configured.",
            details,
        )
    return _check_status(
        "auth_readiness",
        "ok",
        f"Authentication is enabled with {enabled_users} enabled user account{'s' if enabled_users != 1 else ''}.",
        details,
    )


def _taxonomy_normalization_check(status: dict[str, Any]) -> SelfTestCheck:
    if status.get("normalized"):
        return _check_status(
            "taxonomy_normalized",
            "ok",
            f"Taxonomy check passed for {status.get('checked_rows', 0)} sampled rows.",
            status,
        )
    return _check_status(
        "taxonomy_normalized",
        "warning",
        "Some sampled rows still contain raw unnamespaced tags. Use Normalize Taxonomy in the self-test or run /api/system/taxonomy/normalize with manage_feeds permission.",
        status,
    )


def _storage_writable_check(path: str | Path, name: str = "storage_writable") -> SelfTestCheck:
    target = Path(path)
    probe = target / ".adversarygraph-selftest"
    try:
        target.mkdir(parents=True, exist_ok=True)
        probe.write_text(datetime.now(timezone.utc).isoformat(), encoding="utf-8")
        probe.unlink(missing_ok=True)
        return _check(
            name,
            True,
            f"{target} is writable.",
            {"path": str(target), "writable": True},
        )
    except Exception as exc:
        return _check(
            name,
            False,
            f"{target} is not writable: {type(exc).__name__}: {exc}",
            {"path": str(target), "writable": False},
        )


def _asset_scanner_readiness_check() -> SelfTestCheck:
    if not settings.asset_scanner_enabled:
        return _check_status(
            "asset_scanner",
            "ok",
            "Threat Radar asset assessment is disabled by the operator.",
            {"enabled": False, "nmap_enabled": False},
        )
    binary = Path(settings.asset_scanner_nmap_binary)
    nmap_ready = binary.is_file() and os.access(binary, os.X_OK)
    if settings.asset_scanner_nmap_enabled and not nmap_ready:
        return _check_status(
            "asset_scanner",
            "error",
            "Asset assessment is enabled, but the configured Nmap executable is unavailable.",
            {
                "enabled": True,
                "nmap_enabled": True,
                "nmap_binary": str(binary),
                "profile": "safe-service-discovery",
            },
        )
    return _check_status(
        "asset_scanner",
        "ok",
        (
            "Inventory-bound passive and safe Nmap service discovery are ready."
            if settings.asset_scanner_nmap_enabled
            else "Inventory-bound passive assessment is ready; Nmap is disabled by the operator."
        ),
        {
            "enabled": True,
            "nmap_enabled": settings.asset_scanner_nmap_enabled,
            "nmap_binary": str(binary),
            "nmap_ready": nmap_ready,
            "top_ports": settings.asset_scanner_top_ports,
            "timeout_seconds": settings.asset_scanner_timeout_seconds,
            "profile": "safe-service-discovery",
        },
    )


async def _service_health_check(name: str, base_url: str, *, timeout_seconds: float = 3.0) -> SelfTestCheck:
    url = base_url.rstrip("/") + "/health"
    started = perf_counter()
    try:
        async with httpx.AsyncClient(timeout=timeout_seconds, trust_env=False) as client:
            response = await client.get(url)
        duration_ms = int((perf_counter() - started) * 1000)
        ok = 200 <= response.status_code < 300
        return _check(
            name,
            ok,
            f"{name} health endpoint returned HTTP {response.status_code} in {duration_ms} ms.",
            {
                "url": url,
                "status_code": response.status_code,
                "duration_ms": duration_ms,
                "response_preview": response.text[:120],
            },
        )
    except Exception as exc:
        duration_ms = int((perf_counter() - started) * 1000)
        return _check(
            name,
            False,
            f"{name} health endpoint failed after {duration_ms} ms: {type(exc).__name__}: {exc}",
            {"url": url, "duration_ms": duration_ms},
        )


async def _malwaregraph_health_check() -> SelfTestCheck:
    url = settings.malwaregraph_url.rstrip("/") + "/api/health"
    started = perf_counter()
    try:
        async with httpx.AsyncClient(timeout=3.0, trust_env=False) as client:
            response = await client.get(url, headers={"X-API-Key": settings.malwaregraph_api_key} if settings.malwaregraph_api_key else None)
        duration_ms = int((perf_counter() - started) * 1000)
        ok = 200 <= response.status_code < 300
        return _check(
            "malwaregraph_health",
            ok,
            f"MalwareGraph health endpoint returned HTTP {response.status_code} in {duration_ms} ms.",
            {
                "url": url,
                "status_code": response.status_code,
                "duration_ms": duration_ms,
                "response_preview": response.text[:160],
            },
        )
    except Exception as exc:
        duration_ms = int((perf_counter() - started) * 1000)
        return _check(
            "malwaregraph_health",
            False,
            f"MalwareGraph health endpoint failed after {duration_ms} ms: {type(exc).__name__}: {exc}",
            {"url": url, "duration_ms": duration_ms},
        )


def _format_bytes(size_bytes: int) -> str:
    value = float(max(0, size_bytes))
    for unit in ("B", "KiB", "MiB", "GiB", "TiB", "PiB"):
        if value < 1024 or unit == "PiB":
            return f"{int(value)} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} PiB"


def _read_proc_cpu_totals(proc_stat_path: str = "/proc/stat") -> tuple[int, int]:
    with open(proc_stat_path, encoding="utf-8") as handle:
        line = handle.readline().strip()
    fields = line.split()
    if not fields or fields[0] != "cpu":
        raise ValueError("Missing aggregate CPU row in /proc/stat")
    values = [int(value) for value in fields[1:]]
    if len(values) < 4:
        raise ValueError("Incomplete aggregate CPU row in /proc/stat")
    idle = values[3] + (values[4] if len(values) > 4 else 0)
    return idle, sum(values)


def _cpu_percent_from_totals(first: tuple[int, int], second: tuple[int, int]) -> float:
    idle_delta = max(0, second[0] - first[0])
    total_delta = max(0, second[1] - first[1])
    if total_delta <= 0:
        return 0.0
    return round(max(0.0, min(100.0, (1 - idle_delta / total_delta) * 100)), 2)


def _cpu_usage_details(sample_seconds: float = 0.1, proc_stat_path: str = "/proc/stat") -> dict[str, Any]:
    first = _read_proc_cpu_totals(proc_stat_path)
    sleep(max(0.01, sample_seconds))
    second = _read_proc_cpu_totals(proc_stat_path)
    details: dict[str, Any] = {
        "usage_percent": _cpu_percent_from_totals(first, second),
        "sample_seconds": sample_seconds,
        "cpu_count": os.cpu_count() or 1,
    }
    if hasattr(os, "getloadavg"):
        load_1m, load_5m, load_15m = os.getloadavg()
        details["load_average"] = {
            "1m": round(load_1m, 2),
            "5m": round(load_5m, 2),
            "15m": round(load_15m, 2),
        }
    return details


def _parse_kib_file(path: str) -> dict[str, int]:
    values: dict[str, int] = {}
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            parts = line.split()
            if len(parts) < 2:
                continue
            key = parts[0].rstrip(":")
            try:
                values[key] = int(parts[1]) * 1024
            except ValueError:
                continue
    return values


def _read_int_file(path: Path) -> int | None:
    try:
        raw = path.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    if not raw or raw == "max":
        return None
    try:
        return int(raw)
    except ValueError:
        return None


def _memory_usage_details(
    meminfo_path: str = "/proc/meminfo",
    self_status_path: str = "/proc/self/status",
    cgroup_root: str = "/sys/fs/cgroup",
) -> dict[str, Any]:
    meminfo = _parse_kib_file(meminfo_path)
    total = int(meminfo.get("MemTotal") or 0)
    available = int(meminfo.get("MemAvailable") or meminfo.get("MemFree") or 0)
    used = max(0, total - available)
    details: dict[str, Any] = {
        "host": {
            "total_bytes": total,
            "available_bytes": available,
            "used_bytes": used,
            "used_percent": round((used / total) * 100, 2) if total else 0.0,
            "total": _format_bytes(total),
            "available": _format_bytes(available),
            "used": _format_bytes(used),
        }
    }

    status = _parse_kib_file(self_status_path)
    rss = int(status.get("VmRSS") or 0)
    if rss:
        details["process"] = {
            "rss_bytes": rss,
            "rss": _format_bytes(rss),
        }

    cgroup = Path(cgroup_root)
    current = _read_int_file(cgroup / "memory.current")
    maximum = _read_int_file(cgroup / "memory.max")
    if current is None:
        current = _read_int_file(cgroup / "memory" / "memory.usage_in_bytes")
        maximum = _read_int_file(cgroup / "memory" / "memory.limit_in_bytes")
    if current is not None:
        cgroup_details: dict[str, Any] = {
            "current_bytes": current,
            "current": _format_bytes(current),
        }
        if maximum and maximum < 1 << 60:
            cgroup_details.update(
                {
                    "limit_bytes": maximum,
                    "limit": _format_bytes(maximum),
                    "used_percent": round((current / maximum) * 100, 2),
                }
            )
        details["cgroup"] = cgroup_details
    return details


@router.get("/selftest", response_model=SelfTestResult)
async def selftest(_: TeamUser = Depends(run_selftest)) -> SelfTestResult:
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
            db_size_bytes = int(await session.scalar(text("select pg_database_size(current_database())")) or 0)
            db_size_pretty = await session.scalar(text("select pg_size_pretty(pg_database_size(current_database()))"))
            checks.append(
                _check(
                    "database_size",
                    True,
                    f"Local database size: {db_size_pretty or _format_bytes(db_size_bytes)}.",
                    {
                        "db_name": settings.db_name,
                        "size_bytes": db_size_bytes,
                        "size": db_size_pretty or _format_bytes(db_size_bytes),
                        "external_data_dir": os.environ.get("ADVERSARYGRAPH_DB_DIR", "./data/postgres"),
                    },
                )
            )

            total_users = int(await session.scalar(select(func.count()).select_from(UserAccount)) or 0)
            enabled_users = int(await session.scalar(select(func.count()).select_from(UserAccount).where(UserAccount.enabled.is_(True))) or 0)
            checks.append(_auth_readiness_check(total_users, enabled_users))

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
                    domain_counts[domain] = {
                        "tactics": 0,
                        "techniques": 0,
                        "groups": 0,
                        "stix_objects": 0,
                        "stix_relationships": 0,
                    }
                    continue
                tactics = await session.scalar(select(func.count()).select_from(Tactic).where(Tactic.version_id == version_id))
                techniques = await session.scalar(select(func.count()).select_from(Technique).where(Technique.version_id == version_id))
                groups = await session.scalar(select(func.count()).select_from(AptGroup).where(AptGroup.version_id == version_id))
                stix_objects = await session.scalar(select(func.count()).select_from(StixObject).where(StixObject.version_id == version_id))
                stix_relationships = await session.scalar(select(func.count()).select_from(StixRelationship).where(StixRelationship.version_id == version_id))
                domain_counts[domain] = {
                    "tactics": int(tactics or 0),
                    "techniques": int(techniques or 0),
                    "groups": int(groups or 0),
                    "stix_objects": int(stix_objects or 0),
                    "stix_relationships": int(stix_relationships or 0),
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

            source_rows = (await session.execute(select(IOCSource))).scalars().all()
            source_counts_raw = await session.execute(
                select(IOCIndicator.source_id, func.count(IOCIndicator.id)).group_by(IOCIndicator.source_id)
            )
            source_counts = {str(source_id): int(count or 0) for source_id, count in source_counts_raw.all()}
            sources = [
                {
                    "source_id": source.source_id,
                    "label": source.label,
                    "kind": source.kind,
                    "enabled": source.enabled,
                    "sync_status": source.sync_status,
                    "sync_error": source.sync_error,
                    "last_synced_at": source.last_synced_at.isoformat() if source.last_synced_at else None,
                    "indicator_count": source_counts.get(source.source_id, 0),
                }
                for source in sorted(source_rows, key=lambda item: item.label.lower())
            ]
            enabled_sources = [source for source in sources if source["enabled"]]
            degraded_sources = [
                source for source in enabled_sources
                if source["sync_status"] and source["sync_status"] not in {"ok", "active", "configured"}
            ]
            checks.append(
                _check_status(
                    "ioc_sync",
                    "degraded" if degraded_sources else "ok",
                    f"IOC sources checked: {len(enabled_sources)} enabled, "
                    f"{sum(int(item.get('indicator_count') or 0) for item in sources)} indicators stored.",
                    {
                        "auto_full_sync_on_startup": settings.auto_ioc_full_sync_on_startup,
                        "startup_sync_days": max(1, min(7, settings.auto_threatfox_sync_days)),
                        "enabled_sources": len(enabled_sources),
                        "degraded_sources": len(degraded_sources),
                        "sources": sources,
                    },
                )
            )

            if settings.rag_enabled:
                vector_version = await session.scalar(
                    text("SELECT extversion FROM pg_extension WHERE extname = 'vector'")
                )
                rag_documents = int(
                    await session.scalar(
                        select(func.count()).select_from(RAGDocument).where(
                            RAGDocument.is_active.is_(True),
                            RAGDocument.sanitized.is_(True),
                        )
                    )
                    or 0
                )
                rag_chunks = int(
                    await session.scalar(
                        select(func.count())
                        .select_from(RAGChunk)
                        .join(RAGDocument, RAGDocument.id == RAGChunk.document_id)
                        .where(
                            RAGDocument.is_active.is_(True),
                            RAGDocument.sanitized.is_(True),
                        )
                    )
                    or 0
                )
                ready_embeddings = int(
                    await session.scalar(
                        select(func.count())
                        .select_from(RAGChunk)
                        .join(RAGDocument, RAGDocument.id == RAGChunk.document_id)
                        .where(
                            RAGDocument.is_active.is_(True),
                            RAGDocument.sanitized.is_(True),
                            RAGChunk.embedding_status == "complete",
                        )
                    )
                    or 0
                )
                failed_embeddings = int(
                    await session.scalar(
                        select(func.count())
                        .select_from(RAGChunk)
                        .join(RAGDocument, RAGDocument.id == RAGChunk.document_id)
                        .where(
                            RAGDocument.is_active.is_(True),
                            RAGDocument.sanitized.is_(True),
                            RAGChunk.embedding_status == "failed",
                        )
                    )
                    or 0
                )
                latest_run = (
                    await session.execute(
                        select(RAGIndexRun).order_by(RAGIndexRun.created_at.desc()).limit(1)
                    )
                ).scalar_one_or_none()
                attempted_index_problem = bool(
                    latest_run
                    and (
                        latest_run.status in {"failed", "degraded"}
                        or (
                            latest_run.status == "completed"
                            and rag_documents == 0
                        )
                    )
                )
                rag_status = (
                    "error"
                    if not vector_version
                    else "warning"
                    if (
                        attempted_index_problem
                        or failed_embeddings > 0
                        or (
                            settings.rag_embedding_enabled
                            and rag_chunks > 0
                            and ready_embeddings == 0
                        )
                    )
                    else "ok"
                )
                checks.append(
                    _check_status(
                        "rag_index",
                        rag_status,
                        "Unified intelligence RAG index is ready."
                        if rag_status == "ok" and rag_documents > 0
                        else "Unified intelligence RAG is enabled; run the initial reconciliation before first use."
                        if rag_status == "ok"
                        else "Unified intelligence RAG needs an initial/retry reconciliation."
                        if vector_version
                        else "PostgreSQL pgvector extension is unavailable.",
                        {
                            "pgvector_version": vector_version,
                            "documents": rag_documents,
                            "chunks": rag_chunks,
                            "ready_embeddings": ready_embeddings,
                            "failed_embeddings": failed_embeddings,
                            "retrieval_mode": (
                                "hybrid"
                                if ready_embeddings > 0
                                else "exact+fts"
                            ),
                            "latest_run_status": latest_run.status if latest_run else "never",
                            "latest_run_completed_at": (
                                latest_run.completed_at.isoformat()
                                if latest_run and latest_run.completed_at
                                else None
                            ),
                        },
                    )
                )
            else:
                checks.append(
                    _check_status(
                        "rag_index",
                        "ok",
                        "Unified intelligence RAG is disabled by the operator.",
                        {"enabled": False},
                    )
                )

            await ensure_cve_sources(session)
            cve_source_rows = (await session.execute(select(CVESource))).scalars().all()
            cve_total = int(await session.scalar(select(func.count()).select_from(CVERecord)) or 0)
            cve_known_exploited = int(await session.scalar(select(func.count()).select_from(CVERecord).where(CVERecord.known_exploited.is_(True))) or 0)
            cve_technique_links = int(await session.scalar(select(func.count()).select_from(CVETechniqueLink)) or 0)
            cve_ioc_links = int(await session.scalar(select(func.count()).select_from(CVEIOCLink)) or 0)
            cve_actor_links = int(await session.scalar(select(func.count()).select_from(CVEActorLink)) or 0)
            cve_sources = [
                {
                    "source_id": source.source_id,
                    "label": source.label,
                    "kind": source.kind,
                    "enabled": source.enabled,
                    "sync_status": source.sync_status,
                    "sync_error": source.sync_error,
                    "last_synced_at": source.last_synced_at.isoformat() if source.last_synced_at else None,
                }
                for source in sorted(cve_source_rows, key=lambda item: item.label.lower())
            ]
            degraded_cve_sources = [
                source for source in cve_sources
                if source["enabled"] and source["sync_status"] and source["sync_status"] not in {"ok", "active", "configured"}
            ]
            checks.append(
                _check_status(
                    "cve_sync",
                    "degraded" if degraded_cve_sources else "ok",
                    f"CVE sources checked: {len(cve_sources)} configured, {cve_total} CVEs stored, {cve_known_exploited} known exploited.",
                    {
                        "sources": cve_sources,
                        "cve_count": cve_total,
                        "known_exploited_count": cve_known_exploited,
                        "correlations": {
                            "technique_links": cve_technique_links,
                            "ioc_links": cve_ioc_links,
                            "actor_links": cve_actor_links,
                        },
                    },
                )
            )
            checks.append(_data_integrity_check(ioc_cve_integrity_snapshot()))
            checks.append(_taxonomy_normalization_check(await taxonomy_normalization_status(session)))
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

    try:
        cpu_details = _cpu_usage_details()
        checks.append(
            _check(
                "cpu_usage",
                True,
                f"CPU usage sampled at {cpu_details['usage_percent']}%.",
                cpu_details,
            )
        )
    except Exception as exc:
        checks.append(_check("cpu_usage", False, f"CPU usage self-test failed: {type(exc).__name__}: {exc}"))

    try:
        memory_details = _memory_usage_details()
        host_memory = memory_details["host"]
        checks.append(
            _check(
                "memory_usage",
                True,
                f"Memory usage: {host_memory['used']} of {host_memory['total']} ({host_memory['used_percent']}%).",
                memory_details,
            )
        )
    except Exception as exc:
        checks.append(_check("memory_usage", False, f"Memory usage self-test failed: {type(exc).__name__}: {exc}"))

    checks.append(_api_key_check())
    checks.append(_asset_scanner_readiness_check())
    checks.append(_storage_writable_check(settings.log_dir, "log_storage_writable"))
    checks.append(_storage_writable_check(settings.attck_data_dir, "attck_storage_writable"))
    checks.append(
        await _service_health_check(
            "attack_lab_web_health",
            os.environ.get("ATTACK_LAB_WEB_URL", "http://attack-lab-web:8080"),
        )
    )
    checks.append(
        await _service_health_check(
            "attack_lab_endpoint_health",
            os.environ.get("ATTACK_LAB_ENDPOINT_URL", "http://attack-lab-endpoint:8090"),
        )
    )
    checks.append(await _malwaregraph_health_check())

    status = _overall_selftest_status(checks)
    return SelfTestResult(
        status=status,
        version=APP_VERSION,
        checked_at=datetime.now(timezone.utc).isoformat(),
        duration_ms=int((perf_counter() - started) * 1000),
        checks=checks,
    )
