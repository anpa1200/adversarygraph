import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import attack, apt, analyze, sync, export, ioc, layers, operations, pipeline, sector, system
from app.core.config import settings
from app.core.database import async_session_factory, create_tables

logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s %(levelname)s %(name)s — %(message)s",
)
logger = logging.getLogger(__name__)


async def _startup_threatfox_sync() -> None:
    if not settings.auto_threatfox_sync_on_startup:
        logger.info("Startup ThreatFox IOC sync disabled")
        return
    if not settings.threatfox_auth_key:
        logger.info("Startup ThreatFox IOC sync skipped: THREATFOX_AUTH_KEY is not configured")
        return

    days = max(1, min(7, settings.auto_threatfox_sync_days))
    try:
        from app.services.ioc_intel import sync_threatfox

        async with async_session_factory() as session:
            result = await sync_threatfox(session, days=days, domain="enterprise-attack")
            logger.info("Startup ThreatFox IOC sync complete: %s", result)
    except Exception as exc:
        logger.warning("Startup ThreatFox IOC sync failed: %s", exc, exc_info=True)


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

    asyncio.create_task(_startup_threatfox_sync())

    yield


app = FastAPI(
    title="AdversaryGraph API",
    description="ATT&CK-based threat intelligence mapping with AI analysis",
    version="2.5.0",
    lifespan=lifespan,
)

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
app.include_router(operations.router, prefix="/api")
app.include_router(pipeline.router, prefix="/api")
app.include_router(sector.router, prefix="/api")
app.include_router(system.router, prefix="/api")


@app.get("/api/health")
async def health():
    return {"status": "ok", "version": "2.5.0"}
