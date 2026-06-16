from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy import text
from sqlalchemy.orm import DeclarativeBase

from app.core.config import settings

engine = create_async_engine(
    settings.database_url,
    echo=False,
    pool_size=10,
    max_overflow=20,
    pool_pre_ping=True,
)

async_session_factory = async_sessionmaker(
    engine,
    expire_on_commit=False,
    class_=AsyncSession,
)


class Base(DeclarativeBase):
    pass


async def get_session() -> AsyncSession:
    async with async_session_factory() as session:
        yield session


async def create_tables() -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await conn.execute(text("ALTER TABLE apt_groups ADD COLUMN IF NOT EXISTS created VARCHAR(50) DEFAULT ''"))
        await conn.execute(text("ALTER TABLE apt_groups ADD COLUMN IF NOT EXISTS modified VARCHAR(50) DEFAULT ''"))
        await conn.execute(text("ALTER TABLE apt_groups ADD COLUMN IF NOT EXISTS attack_version VARCHAR(50) DEFAULT ''"))
        await conn.execute(text("ALTER TABLE apt_groups ADD COLUMN IF NOT EXISTS contributors JSONB DEFAULT '[]'::jsonb"))
        await conn.execute(text("ALTER TABLE apt_groups ADD COLUMN IF NOT EXISTS external_references JSONB DEFAULT '[]'::jsonb"))
