import asyncio
import logging
import time
from contextlib import asynccontextmanager
from uuid import uuid4

from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from app.core.rate_limit import RateLimitMiddleware

import app.models.sector_packs  # noqa: F401 — registers SectorPack with Base metadata
import app.models.retrohunt     # noqa: F401 — registers RetroHuntSignal with Base metadata
import app.models.knowledge      # noqa: F401 — registers KnowledgeArticle with Base metadata
import app.models.asset_surface  # noqa: F401 — registers AssetSurfaceCase with Base metadata
import app.models.simulation     # noqa: F401 — registers simulation persistence tables
import app.models.cve            # noqa: F401 — registers CVE intelligence tables
import app.models.auth           # noqa: F401 — registers native user/session tables
import app.models.evidence_graph  # noqa: F401 — registers evidence-to-detection graph tables
from app.api.routes import asset_surface, attack, apt, analyze, auth, sync, export, ioc, cve, evidence_graph, layers, malwaregraph, observability, operations, pipeline, retrohunt, sector, simulation, statistics, system, knowledge
from app.core.config import settings
from app.core.database import async_session_factory, create_tables
from app.core.logging_config import configure_logging
from app.core.observability import monotonic_ms_since, observability_state
from app.core.version import APP_VERSION
from app.services.auth import bootstrap_admin_if_configured, current_user

configure_logging()
logger = logging.getLogger(__name__)


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


@asynccontextmanager
async def lifespan(app: FastAPI):
    if not settings.auth_enabled:
        logger.warning(
            "AUTH_ENABLED=false — all requests are treated as authenticated. "
            "Do not expose this instance to untrusted networks without enabling auth."
        )

    await create_tables()
    logger.info("Database tables ready")
    async with async_session_factory() as session:
        if await bootstrap_admin_if_configured(session):
            logger.info("Bootstrapped native admin user from AUTH_BOOTSTRAP_ADMIN_* settings")

    loop = asyncio.get_event_loop()
    try:
        from app.services.attck.ingestor import run_ingest
        logger.info("Starting ATT&CK ingestion …")
        await loop.run_in_executor(None, run_ingest)
        logger.info("ATT&CK ingestion complete")
    except Exception as exc:
        logger.error("Ingestion failed (non-fatal): %s", exc, exc_info=True)

    asyncio.create_task(_startup_ioc_sync())

    yield


app = FastAPI(
    title="AdversaryGraph API",
    description="ATT&CK-based threat intelligence mapping with AI analysis",
    version=APP_VERSION,
    lifespan=lifespan,
)


@app.middleware("http")
async def request_logging_middleware(request: Request, call_next):
    request_id = request.headers.get("X-Request-ID") or str(uuid4())
    started = time.perf_counter()
    client = request.client.host if request.client else "-"
    try:
        response = await call_next(request)
    except Exception as exc:
        duration_ms = round(monotonic_ms_since(started), 2)
        observability_state.record_request(
            request_id=request_id,
            method=request.method,
            path=request.url.path,
            status_code=500,
            duration_ms=duration_ms,
            client=client,
            error=type(exc).__name__,
        )
        logger.exception(
            "request failed method=%s path=%s duration_ms=%s error=%r",
            request.method,
            request.url.path,
            duration_ms,
            exc,
            extra={"request_id": request_id},
        )
        raise
    duration_ms = round(monotonic_ms_since(started), 2)
    response.headers["X-Request-ID"] = request_id
    observability_state.record_request(
        request_id=request_id,
        method=request.method,
        path=request.url.path,
        status_code=response.status_code,
        duration_ms=duration_ms,
        client=client,
    )
    log = logger.error if response.status_code >= 500 else logger.warning if response.status_code >= 400 else logger.info
    log(
        "request complete method=%s path=%s status=%s duration_ms=%s",
        request.method,
        request.url.path,
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

app.include_router(auth.router, prefix="/api")
app.include_router(attack.router,  prefix="/api", dependencies=_auth_required)
app.include_router(apt.router,     prefix="/api", dependencies=_auth_required)
app.include_router(analyze.router, prefix="/api", dependencies=_auth_required)
app.include_router(asset_surface.router, prefix="/api", dependencies=_auth_required)
app.include_router(sync.router,    prefix="/api", dependencies=_auth_required)
app.include_router(export.router,  prefix="/api", dependencies=_auth_required)
app.include_router(ioc.router, prefix="/api", dependencies=_auth_required)
app.include_router(cve.router, prefix="/api", dependencies=_auth_required)
app.include_router(evidence_graph.router, prefix="/api", dependencies=_auth_required)
app.include_router(layers.router,  prefix="/api", dependencies=_auth_required)
app.include_router(malwaregraph.router, prefix="/api", dependencies=_auth_required)
app.include_router(operations.router, prefix="/api", dependencies=_auth_required)
app.include_router(pipeline.router, prefix="/api", dependencies=_auth_required)
app.include_router(retrohunt.router, prefix="/api", dependencies=_auth_required)
app.include_router(knowledge.router, prefix="/api", dependencies=_auth_required)
app.include_router(sector.router, prefix="/api", dependencies=_auth_required)
app.include_router(simulation.router, prefix="/api", dependencies=_auth_required)
app.include_router(statistics.router, prefix="/api", dependencies=_auth_required)
app.include_router(system.router, prefix="/api", dependencies=_auth_required)
app.include_router(observability.router, prefix="/api", dependencies=_auth_required)


@app.get("/api/health")
async def health():
    return {"status": "ok", "version": app.version}
