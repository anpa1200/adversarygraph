"""Compare authority-schema fingerprints from two fresh DBs and a roundtrip DB.

The three database URLs are read from named environment variables so secrets
never need to appear in command output.  Each database must already be at the
current Alembic head.  The third endpoint is expected to have been exercised
through ``head -> 0001 -> head`` by the caller.

Example::

    python -m scripts.verify_schema_authority_fingerprint \
      --database-env FRESH_A_DATABASE_URL \
      --database-env FRESH_B_DATABASE_URL \
      --database-env ROUNDTRIP_DATABASE_URL
"""

from __future__ import annotations

import argparse
import asyncio
import os

from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

os.environ.setdefault("DB_PASS", "schema-fingerprint-tool-unused")

from app.core.database import (  # noqa: E402 - DB_PASS must exist before settings load
    compute_migration_schema_authority_fingerprint,
)
from app.core.migration_policy import (  # noqa: E402
    MIGRATION_SCHEMA_AUTHORITY_FINGERPRINT,
    REQUIRED_SCHEMA_REVISION,
)


def _async_url(value: str) -> str:
    if value.startswith("postgresql+asyncpg://"):
        return value
    if value.startswith("postgresql+psycopg2://"):
        return value.replace("postgresql+psycopg2://", "postgresql+asyncpg://", 1)
    if value.startswith("postgresql://"):
        return value.replace("postgresql://", "postgresql+asyncpg://", 1)
    raise ValueError("authority fingerprint endpoints must use PostgreSQL URLs")


async def _fingerprint(label: str, database_url: str) -> str:
    comparison_engine = create_async_engine(
        _async_url(database_url),
        poolclass=NullPool,
    )
    try:
        async with comparison_engine.connect() as connection:
            revision_rows = await connection.execute(text("SELECT version_num FROM alembic_version ORDER BY version_num"))
            revisions = tuple(str(value) for value in revision_rows.scalars())
            if revisions != (REQUIRED_SCHEMA_REVISION,):
                found_revisions = ", ".join(revisions) or "empty"
                raise RuntimeError(f"{label} is not at {REQUIRED_SCHEMA_REVISION}: found {found_revisions}")
            return await compute_migration_schema_authority_fingerprint(connection)
    finally:
        await comparison_engine.dispose()


async def _run(environment_names: list[str]) -> None:
    results: dict[str, str] = {}
    for environment_name in environment_names:
        database_url = os.getenv(environment_name, "")
        if not database_url:
            raise RuntimeError(f"missing database URL environment variable: {environment_name}")
        results[environment_name] = await _fingerprint(environment_name, database_url)

    for label, fingerprint in results.items():
        print(f"{label}: {fingerprint}")
    unique_fingerprints = set(results.values())
    if len(unique_fingerprints) != 1:
        raise RuntimeError("fresh and roundtrip authority fingerprints do not match")
    actual = next(iter(unique_fingerprints))
    if actual != MIGRATION_SCHEMA_AUTHORITY_FINGERPRINT:
        raise RuntimeError(
            f"reproducible catalog fingerprint does not match policy: expected {MIGRATION_SCHEMA_AUTHORITY_FINGERPRINT}, found {actual}"
        )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--database-env",
        action="append",
        required=True,
        help="environment variable containing a PostgreSQL URL (repeat exactly three times)",
    )
    args = parser.parse_args()
    if len(args.database_env) != 3 or len(set(args.database_env)) != 3:
        parser.error("provide exactly three distinct database environment names: fresh A, fresh B, and downgrade/upgrade roundtrip")
    asyncio.run(_run(args.database_env))


if __name__ == "__main__":
    main()
