import asyncio
import logging
import time
from contextlib import asynccontextmanager
from uuid import uuid4

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import attack, apt, analyze, sync, export, ioc, layers, malwaregraph, operations, pipeline, sector, system
from app.core.config import settings
from app.core.database import async_session_factory, create_tables
from app.core.logging_config import configure_logging
from app.core.version import APP_VERSION

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
    await create_tables()
    logger.info("Database tables ready")

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
    try:
        response = await call_next(request)
    except Exception as exc:
        duration_ms = round((time.perf_counter() - started) * 1000, 2)
        logger.exception(
            "request failed method=%s path=%s duration_ms=%s error=%r",
            request.method,
            request.url.path,
            duration_ms,
            exc,
            extra={"request_id": request_id},
        )
        raise
    duration_ms = round((time.perf_counter() - started) * 1000, 2)
    response.headers["X-Request-ID"] = request_id
    logger.info(
        "request complete method=%s path=%s status=%s duration_ms=%s",
        request.method,
        request.url.path,
        response.status_code,
        duration_ms,
        extra={"request_id": request_id},
    )
    return response

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(attack.router,  prefix="/api")
app.include_router(apt.router,     prefix="/api")
app.include_router(analyze.router, prefix="/api")
app.include_router(sync.router,    prefix="/api")
app.include_router(export.router,  prefix="/api")
app.include_router(ioc.router, prefix="/api")
app.include_router(layers.router,  prefix="/api")
app.include_router(malwaregraph.router, prefix="/api")
app.include_router(operations.router, prefix="/api")
app.include_router(pipeline.router, prefix="/api")
app.include_router(sector.router, prefix="/api")
app.include_router(system.router, prefix="/api")


@app.get("/api/health")
async def health():
    return {"status": "ok", "version": app.version}
