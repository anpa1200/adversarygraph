import asyncio
import logging
import re
import time
from contextlib import asynccontextmanager
from uuid import uuid4

from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text

from app.core.rate_limit import RateLimitMiddleware

import app.models.sector_packs as _sector_packs_models  # noqa: F401 — register Base metadata
import app.models.retrohunt as _retrohunt_models  # noqa: F401 — register Base metadata
import app.models.knowledge as _knowledge_models  # noqa: F401 — register Base metadata
import app.models.asset_surface as _asset_surface_models  # noqa: F401 — register Base metadata
import app.models.simulation as _simulation_models  # noqa: F401 — register Base metadata
import app.models.cve as _cve_models  # noqa: F401 — register Base metadata
import app.models.auth as _auth_models  # noqa: F401 — register Base metadata
import app.models.evidence_graph as _evidence_graph_models  # noqa: F401 — register Base metadata
import app.models.threat_radar as _threat_radar_models  # noqa: F401 — register Base metadata
import app.models.threat_hunting as _threat_hunting_models  # noqa: F401 — register Base metadata
import app.models.rag as _rag_models  # noqa: F401 — register Base metadata
import app.models.intelligence as _intelligence_models  # noqa: F401 — register Base metadata
import app.models.query_library as _query_library_models  # noqa: F401 — register Base metadata
import app.models.report_review as _report_review_models  # noqa: F401 — register Base metadata
import app.models.research_workflow as _research_workflow_models  # noqa: F401 — register Base metadata
from app.api.routes import asset_surface, attack, apt, analyze, auth, sync, export, ioc, cve, emb3d, evidence_graph, layers, malwaregraph, observability, operations, pipeline, query_library, rag, report_review, research, retrohunt, sector, simulation, statistics, system, knowledge, troubleshooting, threat_hunting, threat_hunting_ai, threat_radar
from app.api.openapi import OPENAPI_TAGS
from app.core.config import settings
from app.core.database import async_session_factory, create_tables
from app.core.logging_config import configure_logging
from app.core.observability import monotonic_ms_since, observability_state
from app.core.version import APP_VERSION
from app.services.auth import (
    bootstrap_admin_if_configured,
    current_user,
    ensure_default_access_groups,
    require_any_module,
    require_module,
)
from app.services.data_integrity import inspect_ioc_cve_integrity, mark_ioc_cve_integrity_unavailable
from app.services.startup_status import startup_status

configure_logging()
logger = logging.getLogger(__name__)
_REQUEST_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")


def _safe_request_id(value: str | None) -> str:
    """Accept a compact log-safe caller ID or generate a new correlation ID."""
    candidate = value or ""
    if candidate == candidate.strip() and _REQUEST_ID_RE.fullmatch(candidate):
        return candidate
    return str(uuid4())


def _observability_route(request: Request) -> str:
    """Return a bounded route template, never a caller-controlled raw path."""
    route = request.scope.get("route")
    path = getattr(route, "path_format", None) or getattr(route, "path", None)
    if not isinstance(path, str) or not path.startswith("/"):
        return "<unmatched>"
    return path[:512]


async def _startup_ioc_sync() -> None:
    if not settings.auto_ioc_full_sync_on_startup:
        logger.info("Startup IOC full sync disabled")
        return

    days = max(1, min(7, settings.auto_threatfox_sync_days))
    try:
        from app.services.ioc_intel import sync_all_ioc_sources

        async with async_session_factory() as session:
            result = await sync_all_ioc_sources(session, days=days, domain="enterprise-attack")
            logger.info("Startup IOC full sync complete: %s", result)
    except Exception as exc:
        logger.warning("Startup IOC full sync failed: %s", exc, exc_info=True)


async def _startup_data_integrity_check() -> None:
    try:
        async with async_session_factory() as session:
            result = await inspect_ioc_cve_integrity(session)
        duplicate_groups = result.get("duplicate_groups", {})
        if result.get("status") == "ok":
            logger.info("Startup IOC/CVE dedup integrity passed: %s", duplicate_groups)
        else:
            logger.error("Startup IOC/CVE dedup integrity failed: %s", result)
    except Exception as exc:
        mark_ioc_cve_integrity_unavailable(exc)
        logger.warning("Startup IOC/CVE dedup integrity check failed: %s", exc, exc_info=True)


async def _startup_attck_ingestion() -> None:
    startup_status.mark_job_running(
        "reference_ingestion",
        phase="attck_ingestion",
        message="ATT&CK/ATLAS reference ingestion is running. The API is available, but matrix pages may be incomplete until this finishes.",
    )
    loop = asyncio.get_running_loop()
    try:
        from app.services.attck.ingestor import run_ingest

        logger.info("Starting ATT&CK ingestion in background …")
        await loop.run_in_executor(None, run_ingest)
        logger.info("ATT&CK ingestion complete")
        startup_status.mark_job_complete(
            "reference_ingestion",
            phase="complete",
            message="ATT&CK/ATLAS reference ingestion is complete.",
        )
    except Exception as exc:
        logger.error("Ingestion failed (non-fatal): %s", exc, exc_info=True)
        startup_status.mark_job_failed(
            "reference_ingestion",
            phase="failed",
            message="ATT&CK/ATLAS reference ingestion failed. Open Troubleshooting or self-test for details.",
            error=exc,
        )


async def _startup_reference_jobs() -> None:
    await _startup_attck_ingestion()
    await _startup_ioc_sync()


@asynccontextmanager
async def lifespan(app: FastAPI):
    reference_task: asyncio.Task[None] | None = None
    integrity_task: asyncio.Task[None] | None = None
    startup_status.set_platform_message("Preparing API, database tables, and authentication bootstrap.")
    if not settings.auth_enabled:
        logger.warning(
            "AUTH_ENABLED=false — all requests are treated as authenticated. "
            "Do not expose this instance to untrusted networks without enabling auth."
        )

    await create_tables()
    logger.info("Database tables ready")
    async with async_session_factory() as session:
        created_groups = await ensure_default_access_groups(session)
        if created_groups:
            logger.info("Created %s built-in SOC access groups", created_groups)
        if await bootstrap_admin_if_configured(session):
            logger.info("Bootstrapped native admin user from AUTH_BOOTSTRAP_ADMIN_* settings")

    startup_status.set_platform_message("API is serving requests while reference ingestion completes in the background.")
    integrity_task = asyncio.create_task(
        _startup_data_integrity_check(),
        name="adversarygraph-data-integrity",
    )
    reference_task = asyncio.create_task(
        _startup_reference_jobs(),
        name="adversarygraph-reference-ingestion",
    )
    # Retain a strong reference for observability and deterministic shutdown.
    app.state.reference_jobs_task = reference_task
    app.state.data_integrity_task = integrity_task

    try:
        yield
    finally:
        for task, label in (
            (reference_task, "reference ingestion"),
            (integrity_task, "data integrity scan"),
        ):
            if task is None:
                continue
            if not task.done():
                task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                logger.info("Background %s stopped during API shutdown", label)
            except Exception:
                logger.exception("Background %s ended unexpectedly", label)
        app.state.reference_jobs_task = None
        app.state.data_integrity_task = None


app = FastAPI(
    title="AdversaryGraph API",
    description=(
        "Versioned API for the AdversaryGraph analyst workbench: ATT&CK/ATLAS, "
        "IOC and CVE intelligence, report and malware analysis, evidence graphs, "
        "threat hunting, query engineering, attack simulation, RAG, operations, "
        "observability, and governed external-provider integrations."
    ),
    version=APP_VERSION,
    openapi_tags=OPENAPI_TAGS,
    lifespan=lifespan,
)


@app.middleware("http")
async def request_logging_middleware(request: Request, call_next):
    request_id = _safe_request_id(request.headers.get("X-Request-ID"))
    started = time.perf_counter()
    client = request.client.host if request.client else "-"
    try:
        response = await call_next(request)
    except Exception as exc:
        route_path = _observability_route(request)
        duration_ms = round(monotonic_ms_since(started), 2)
        observability_state.record_request(
            request_id=request_id,
            method=request.method,
            path=route_path,
            status_code=500,
            duration_ms=duration_ms,
            client=client,
            error=type(exc).__name__,
        )
        logger.exception(
            "request failed method=%s path=%s duration_ms=%s error=%r",
            request.method,
            route_path,
            duration_ms,
            exc,
            extra={"request_id": request_id},
        )
        raise
    route_path = _observability_route(request)
    duration_ms = round(monotonic_ms_since(started), 2)
    response.headers["X-Request-ID"] = request_id
    observability_state.record_request(
        request_id=request_id,
        method=request.method,
        path=route_path,
        status_code=response.status_code,
        duration_ms=duration_ms,
        client=client,
    )
    log = logger.error if response.status_code >= 500 else logger.warning if response.status_code >= 400 else logger.info
    log(
        "request complete method=%s path=%s status=%s duration_ms=%s",
        request.method,
        route_path,
        response.status_code,
        duration_ms,
        extra={"request_id": request_id},
    )
    return response

_cors_origins = [o.strip() for o in settings.cors_allowed_origins.split(",") if o.strip()]
if "*" in _cors_origins:
    raise ValueError(
        "CORS_ALLOWED_ORIGINS must not contain '*' — wildcard origins are "
        "incompatible with allow_credentials=True and expose the API to any origin. "
        "Set an explicit list of allowed origins."
    )

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(RateLimitMiddleware)

_auth_required = [Depends(current_user)]


def _module_required(module: str):
    return [Depends(require_module(module))]


def _one_module_required(*modules: str):
    return [Depends(require_any_module(*modules))]

app.include_router(auth.router, prefix="/api")
app.include_router(
    attack.router,
    prefix="/api",
    dependencies=_one_module_required(
        "discover", "navigator", "compare", "apt_library", "investigation",
        "threat_hunting", "attack_simulation", "asset_surface",
        "evidence_graph", "threat_radar",
    ),
)
app.include_router(
    apt.router,
    prefix="/api",
    dependencies=_one_module_required(
        "apt_library", "compare", "investigation", "threat_radar",
        "sector_intel", "evidence_graph", "threat_hunting",
    ),
)
app.include_router(analyze.router, prefix="/api", dependencies=_one_module_required("ai_analysis", "reports_research", "investigation"))
app.include_router(report_review.router, prefix="/api", dependencies=_one_module_required("ai_analysis", "reports_research", "investigation"))
app.include_router(research.router, prefix="/api", dependencies=_module_required("reports_research"))
app.include_router(asset_surface.router, prefix="/api", dependencies=_module_required("asset_surface"))
app.include_router(sync.router,    prefix="/api", dependencies=_auth_required)
app.include_router(export.router,  prefix="/api", dependencies=_auth_required)
app.include_router(ioc.router, prefix="/api", dependencies=_one_module_required("ioc_library", "ioc_investigation", "virustotal", "asset_surface", "threat_radar"))
app.include_router(cve.router, prefix="/api", dependencies=_one_module_required("cve_library", "asset_surface", "threat_radar"))
app.include_router(emb3d.router, prefix="/api", dependencies=_module_required("emb3d"))
app.include_router(evidence_graph.router, prefix="/api", dependencies=_one_module_required("evidence_graph", "ai_analysis", "threat_hunting"))
app.include_router(layers.router, prefix="/api", dependencies=_module_required("navigator"))
app.include_router(malwaregraph.router, prefix="/api", dependencies=_module_required("malware_analysis"))
app.include_router(operations.router, prefix="/api", dependencies=_one_module_required("operations", "investigation"))
app.include_router(pipeline.router, prefix="/api", dependencies=_module_required("pipeline"))
app.include_router(retrohunt.router, prefix="/api", dependencies=_one_module_required("retrohunt", "threat_radar", "asset_surface"))
app.include_router(knowledge.router, prefix="/api", dependencies=_module_required("knowledge"))
app.include_router(sector.router, prefix="/api", dependencies=_module_required("sector_intel"))
app.include_router(simulation.router, prefix="/api", dependencies=_module_required("attack_simulation"))
app.include_router(statistics.router, prefix="/api", dependencies=_module_required("statistics"))
app.include_router(system.router, prefix="/api", dependencies=_auth_required)
app.include_router(observability.router, prefix="/api", dependencies=_module_required("observability"))
app.include_router(troubleshooting.router, prefix="/api", dependencies=_module_required("troubleshooting"))
app.include_router(threat_radar.router, prefix="/api", dependencies=_module_required("threat_radar"))
app.include_router(threat_hunting.router, prefix="/api", dependencies=_module_required("threat_hunting"))
app.include_router(threat_hunting_ai.router, prefix="/api", dependencies=_module_required("threat_hunting"))
app.include_router(query_library.router, prefix="/api", dependencies=_module_required("query_library"))
app.include_router(
    rag.router,
    prefix="/api",
    dependencies=_one_module_required(
        "ai_analysis",
        "navigator",
        "knowledge",
        "reports_research",
        "threat_hunting",
    ),
)


@app.get(
    "/api/health",
    tags=["System"],
    summary="Check API liveness and startup progress",
)
async def health() -> dict[str, object]:
    return {"status": "ok", "version": app.version, "startup": startup_status.snapshot()}


@app.get(
    "/api/ready",
    tags=["System"],
    summary="Check API and database readiness",
)
async def readiness():
    """Database-backed readiness check; liveness remains ``/api/health``."""
    try:
        async with async_session_factory() as session:
            await asyncio.wait_for(session.execute(text("SELECT 1")), timeout=3.0)
    except Exception as exc:
        logger.warning("readiness check failed: %s", type(exc).__name__)
        return JSONResponse(
            status_code=503,
            content={
                "status": "not_ready",
                "version": app.version,
                "checks": {"database": "error"},
            },
        )
    return {
        "status": "ready",
        "version": app.version,
        "checks": {"database": "ok"},
    }
