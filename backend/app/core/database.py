import hashlib
import json
import re

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy import text
from sqlalchemy.orm import DeclarativeBase

from app.core.config import settings
from app.core.migration_policy import (
    MIGRATION_SCHEMA_AUTHORITY_FINGERPRINT,
    MIGRATION_OWNED_TABLES,
    REQUIRED_MIGRATION_FUNCTIONS,
    REQUIRED_MIGRATION_SCHEMA,
    REQUIRED_SCHEMA_REVISION,
)

engine = create_async_engine(
    settings.sqlalchemy_database_url,
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


def _decode_catalog_char(value: object) -> str:
    """Decode PostgreSQL's internal one-byte ``\"char\"`` catalog type."""

    if isinstance(value, bytes):
        try:
            decoded = value.decode("ascii")
        except UnicodeDecodeError as exc:
            raise RuntimeError("PostgreSQL catalog returned a non-ASCII char") from exc
    elif isinstance(value, str):
        decoded = value
    else:
        raise RuntimeError("PostgreSQL catalog returned an invalid char type")
    if len(decoded) != 1:
        raise RuntimeError("PostgreSQL catalog returned an invalid char width")
    return decoded


def _normalize_catalog_definition(value: object) -> str:
    """Normalize transport-only differences without hiding SQL changes."""

    normalized = str(value).replace("\r\n", "\n").replace("\r", "\n")
    return "\n".join(line.rstrip() for line in normalized.split("\n")).strip("\n")


def _authority_schema_fingerprint(facts: list[dict[str, object]]) -> str:
    """Hash an order-independent, duplicate-preserving catalog fact set."""

    canonical_facts = sorted(json.dumps(fact, sort_keys=True, separators=(",", ":"), ensure_ascii=True) for fact in facts)
    payload = "\n".join(canonical_facts).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _index_predicate_matches(actual: str | None, expected: dict | None) -> bool:
    """Compare the bounded predicate shapes used by authority indexes.

    PostgreSQL may deparse ``IN`` as ``= ANY (ARRAY[...])`` and adds explicit
    casts, so comparing raw SQL text would produce false drift alarms.  The
    policy instead fixes the indexed column, equality-vs-membership operator,
    and the complete literal set while rejecting extra boolean clauses.
    """

    if expected is None:
        return actual is None
    if not actual:
        return False
    expression = str(actual).lower().replace('"', "")
    if re.search(r"\b(?:and|or)\b", expression):
        return False
    column = str(expected["column"]).lower()
    if re.search(rf"\b{re.escape(column)}\b", expression) is None:
        return False
    literals = [value.replace("''", "'") for value in re.findall(r"'((?:''|[^'])*)'", expression)]
    expected_values = [str(value).lower() for value in expected["values"]]
    if len(literals) != len(expected_values) or set(literals) != set(expected_values):
        return False
    operator = expected["operator"]
    if operator == "eq":
        return len(literals) == 1 and "=" in expression and " any " not in expression
    if operator == "in":
        return " any " in expression or re.search(r"\bin\s*\(", expression) is not None
    return False


def startup_managed_tables():
    return [table for table in Base.metadata.tables.values() if table.name not in MIGRATION_OWNED_TABLES]


async def _inspect_migration_owned_schema(
    conn,
) -> tuple[list[str], str]:
    missing: list[str] = []
    authority_facts: list[dict[str, object]] = []
    authority_functions: dict[tuple[str, str, str], dict[str, object]] = {}
    for table_name, requirements in REQUIRED_MIGRATION_SCHEMA.items():
        relation = await conn.scalar(
            text("SELECT to_regclass(format('%I.%I', current_schema(), CAST(:table_name AS text)))"),
            {"table_name": table_name},
        )
        if relation is None:
            missing.append(f"table:{table_name}")
            continue
        table_row = (
            await conn.execute(
                text("""
                    SELECT relation_row.relkind::text,
                           relation_row.relpersistence::text,
                           relation_row.relrowsecurity,
                           relation_row.relforcerowsecurity,
                           relation_row.relispartition
                    FROM pg_class AS relation_row
                    JOIN pg_namespace AS namespace_row
                      ON namespace_row.oid = relation_row.relnamespace
                    WHERE namespace_row.nspname = current_schema()
                      AND relation_row.relname = :table_name
                """),
                {"table_name": table_name},
            )
        ).one()
        authority_facts.append(
            {
                "kind": "table",
                "table": table_name,
                "relation_kind": _decode_catalog_char(table_row[0]),
                "persistence": _decode_catalog_char(table_row[1]),
                "row_security": bool(table_row[2]),
                "force_row_security": bool(table_row[3]),
                "partition": bool(table_row[4]),
            }
        )
        # PostgreSQL never reuses a dropped column's physical ``attnum``.  A
        # supported downgrade/upgrade therefore leaves a hidden gap even when
        # the visible schema and column order are identical.  Bind the visible
        # ordinal so real reordering still changes the fingerprint while an
        # implementation-history tombstone does not.
        column_rows = await conn.execute(
            text("""
                SELECT row_number() OVER (
                           ORDER BY attribute_row.attnum
                       ) AS visible_ordinal,
                       attribute_row.attname,
                       format_type(attribute_row.atttypid, attribute_row.atttypmod),
                       attribute_row.attnotnull,
                       pg_get_expr(default_row.adbin, default_row.adrelid, TRUE),
                       attribute_row.attidentity::text,
                       attribute_row.attgenerated::text,
                       CASE
                           WHEN attribute_row.attcollation = 0 THEN ''
                           ELSE attribute_row.attcollation::regcollation::text
                       END AS collation_name
                FROM pg_attribute AS attribute_row
                JOIN pg_class AS relation_row
                  ON relation_row.oid = attribute_row.attrelid
                JOIN pg_namespace AS namespace_row
                  ON namespace_row.oid = relation_row.relnamespace
                LEFT JOIN pg_attrdef AS default_row
                  ON default_row.adrelid = attribute_row.attrelid
                 AND default_row.adnum = attribute_row.attnum
                WHERE namespace_row.nspname = current_schema()
                  AND relation_row.relname = :table_name
                  AND attribute_row.attnum > 0
                  AND NOT attribute_row.attisdropped
                ORDER BY attribute_row.attnum
            """),
            {"table_name": table_name},
        )
        for row in column_rows:
            authority_facts.append(
                {
                    "kind": "column",
                    "table": table_name,
                    "ordinal": int(row[0]),
                    "name": str(row[1]),
                    "type": str(row[2]),
                    "not_null": bool(row[3]),
                    "default": (_normalize_catalog_definition(row[4]) if row[4] is not None else None),
                    "identity": str(row[5]),
                    "generated": str(row[6]),
                    "collation": str(row[7]),
                }
            )
        constraint_rows = await conn.execute(
            text("""
                SELECT constraint_row.conname,
                       constraint_row.contype::text,
                       constraint_row.convalidated,
                       COALESCE(
                           array_agg(attribute_row.attname ORDER BY key_row.ordinality)
                               FILTER (WHERE attribute_row.attname IS NOT NULL),
                           ARRAY[]::text[]
                       ) AS constrained_columns,
                       pg_get_constraintdef(constraint_row.oid, TRUE) AS definition
                FROM pg_constraint AS constraint_row
                JOIN pg_class AS relation_row
                  ON relation_row.oid = constraint_row.conrelid
                JOIN pg_namespace AS namespace_row
                  ON namespace_row.oid = relation_row.relnamespace
                LEFT JOIN LATERAL
                    unnest(constraint_row.conkey) WITH ORDINALITY AS key_row(attnum, ordinality)
                    ON TRUE
                LEFT JOIN pg_attribute AS attribute_row
                  ON attribute_row.attrelid = relation_row.oid
                 AND attribute_row.attnum = key_row.attnum
                WHERE namespace_row.nspname = current_schema()
                  AND relation_row.relname = :table_name
                GROUP BY constraint_row.oid,
                         constraint_row.conname,
                         constraint_row.contype,
                         constraint_row.convalidated
            """),
            {"table_name": table_name},
        )
        constraints = {
            str(row[0]): {
                "type": _decode_catalog_char(row[1]),
                "validated": bool(row[2]),
                "columns": tuple(str(value) for value in (row[3] or ())),
                "definition": _normalize_catalog_definition(row[4]),
            }
            for row in constraint_rows
        }
        for name, actual in constraints.items():
            authority_facts.append(
                {
                    "kind": "constraint",
                    "table": table_name,
                    "name": name,
                    "type": actual["type"],
                    "validated": actual["validated"],
                    "columns": list(actual["columns"]),
                    "definition": actual["definition"],
                }
            )
        internal_fk_trigger_rows = await conn.execute(
            text("""
                SELECT constraint_row.conname,
                       procedure_namespace.nspname,
                       procedure_row.proname,
                       trigger_row.tgtype::integer,
                       trigger_row.tgenabled::text,
                       constraint_row.condeferrable,
                       constraint_row.condeferred
                FROM pg_trigger AS trigger_row
                JOIN pg_class AS relation_row
                  ON relation_row.oid = trigger_row.tgrelid
                JOIN pg_namespace AS namespace_row
                  ON namespace_row.oid = relation_row.relnamespace
                JOIN pg_constraint AS constraint_row
                  ON constraint_row.oid = trigger_row.tgconstraint
                JOIN pg_proc AS procedure_row
                  ON procedure_row.oid = trigger_row.tgfoid
                JOIN pg_namespace AS procedure_namespace
                  ON procedure_namespace.oid = procedure_row.pronamespace
                WHERE namespace_row.nspname = current_schema()
                  AND relation_row.relname = :table_name
                  AND trigger_row.tgisinternal
                  AND constraint_row.contype = 'f'
            """),
            {"table_name": table_name},
        )
        for row in internal_fk_trigger_rows:
            enabled = _decode_catalog_char(row[4])
            authority_facts.append(
                {
                    "kind": "foreign-key-trigger",
                    "table": table_name,
                    "constraint": str(row[0]),
                    "function_schema": str(row[1]),
                    "function": str(row[2]),
                    "type_mask": int(row[3]),
                    "enabled": enabled,
                    "deferrable": bool(row[5]),
                    "initially_deferred": bool(row[6]),
                }
            )
            if enabled != "O":
                missing.append(f"foreign-key-trigger:{table_name}.{row[0]}")
        primary_key = requirements["primary_key"]
        primary_key_actual = constraints.get(primary_key["name"])
        if (
            primary_key_actual is None
            or primary_key_actual["type"] != "p"
            or not primary_key_actual["validated"]
            or primary_key_actual["columns"] != tuple(primary_key["columns"])
        ):
            missing.append(f"primary-key:{table_name}.{primary_key['name']}")
        for name, expected in requirements["constraints"].items():
            actual = constraints.get(name)
            if actual is None or actual["type"] != expected["type"] or actual["validated"] is not expected["validated"]:
                missing.append(f"constraint:{table_name}.{name}")
        index_rows = await conn.execute(
            text("""
                SELECT index_relation.relname,
                       index_row.indisunique,
                       index_row.indisvalid,
                       index_row.indisready,
                       COALESCE(
                           array_agg(attribute_row.attname ORDER BY key_row.ordinality)
                               FILTER (WHERE attribute_row.attname IS NOT NULL),
                           ARRAY[]::text[]
                       ) AS indexed_columns,
                       pg_get_expr(index_row.indpred, index_row.indrelid) AS predicate,
                       pg_get_indexdef(index_row.indexrelid, 0, TRUE) AS definition
                FROM pg_index AS index_row
                JOIN pg_class AS relation_row
                  ON relation_row.oid = index_row.indrelid
                JOIN pg_namespace AS namespace_row
                  ON namespace_row.oid = relation_row.relnamespace
                JOIN pg_class AS index_relation
                  ON index_relation.oid = index_row.indexrelid
                LEFT JOIN LATERAL
                    unnest(index_row.indkey::smallint[]) WITH ORDINALITY
                    AS key_row(attnum, ordinality)
                    ON TRUE
                LEFT JOIN pg_attribute AS attribute_row
                  ON attribute_row.attrelid = relation_row.oid
                 AND attribute_row.attnum = key_row.attnum
                WHERE namespace_row.nspname = current_schema()
                  AND relation_row.relname = :table_name
                GROUP BY index_relation.relname,
                         index_row.indexrelid,
                         index_row.indisunique,
                         index_row.indisvalid,
                         index_row.indisready,
                         index_row.indpred,
                         index_row.indrelid
            """),
            {"table_name": table_name},
        )
        indexes = {
            str(row[0]): {
                "unique": bool(row[1]),
                "valid": bool(row[2]),
                "ready": bool(row[3]),
                "columns": tuple(str(value) for value in (row[4] or ())),
                "predicate": str(row[5]) if row[5] is not None else None,
                "definition": _normalize_catalog_definition(row[6]),
            }
            for row in index_rows
        }
        for name, actual in indexes.items():
            authority_facts.append(
                {
                    "kind": "index",
                    "table": table_name,
                    "name": name,
                    "unique": actual["unique"],
                    "valid": actual["valid"],
                    "ready": actual["ready"],
                    "columns": list(actual["columns"]),
                    "predicate": (_normalize_catalog_definition(actual["predicate"]) if actual["predicate"] is not None else None),
                    "definition": actual["definition"],
                }
            )
        for name, expected in requirements["indexes"].items():
            actual = indexes.get(name)
            if (
                actual is None
                or not actual["valid"]
                or not actual["ready"]
                or actual["unique"] is not expected["unique"]
                or actual["columns"] != tuple(expected["columns"])
                or not _index_predicate_matches(actual["predicate"], expected["predicate"])
            ):
                missing.append(f"index:{table_name}.{name}")
        trigger_rows = await conn.execute(
            text("""
                SELECT trigger_row.tgname,
                       procedure_row.proname,
                       trigger_row.tgtype::integer,
                       trigger_row.tgenabled::text,
                       trigger_row.tgconstraint <> 0 AS is_constraint,
                       COALESCE(constraint_row.condeferrable, FALSE) AS is_deferrable,
                       COALESCE(constraint_row.condeferred, FALSE) AS is_initially_deferred,
                       pg_get_triggerdef(trigger_row.oid, TRUE) AS trigger_definition,
                       CASE
                           WHEN procedure_namespace.nspname = current_schema() THEN '<current>'
                           ELSE procedure_namespace.nspname
                       END AS function_schema,
                       language_row.lanname,
                       pg_get_function_result(procedure_row.oid),
                       procedure_row.provolatile::text,
                       procedure_row.proparallel::text,
                       procedure_row.prosecdef,
                       procedure_row.proisstrict,
                       procedure_row.proleakproof,
                       procedure_row.pronargs,
                       pg_get_function_identity_arguments(procedure_row.oid),
                       procedure_row.proconfig,
                       procedure_row.prosrc
                FROM pg_trigger AS trigger_row
                JOIN pg_class AS relation_row
                  ON relation_row.oid = trigger_row.tgrelid
                JOIN pg_namespace AS namespace_row
                  ON namespace_row.oid = relation_row.relnamespace
                JOIN pg_proc AS procedure_row
                  ON procedure_row.oid = trigger_row.tgfoid
                JOIN pg_namespace AS procedure_namespace
                  ON procedure_namespace.oid = procedure_row.pronamespace
                JOIN pg_language AS language_row
                  ON language_row.oid = procedure_row.prolang
                LEFT JOIN pg_constraint AS constraint_row
                  ON constraint_row.oid = trigger_row.tgconstraint
                WHERE namespace_row.nspname = current_schema()
                  AND relation_row.relname = :table_name
                  AND NOT trigger_row.tgisinternal
            """),
            {"table_name": table_name},
        )
        triggers = {
            str(row[0]): {
                "function": str(row[1]),
                "type_mask": int(row[2]),
                "enabled": _decode_catalog_char(row[3]),
                "constraint": bool(row[4]),
                "deferrable": bool(row[5]),
                "initially_deferred": bool(row[6]),
                "definition": _normalize_catalog_definition(row[7]),
                "function_schema": str(row[8]),
                "function_language": str(row[9]),
                "function_result": str(row[10]),
                "function_volatility": _decode_catalog_char(row[11]),
                "function_parallel": _decode_catalog_char(row[12]),
                "function_security_definer": bool(row[13]),
                "function_strict": bool(row[14]),
                "function_leakproof": bool(row[15]),
                "function_nargs": int(row[16]),
                "function_identity_arguments": str(row[17]),
                "function_config": ([str(value) for value in row[18]] if row[18] is not None else None),
                "function_source": _normalize_catalog_definition(row[19]),
            }
            for row in trigger_rows
        }
        for name, actual in triggers.items():
            authority_facts.append(
                {
                    "kind": "trigger",
                    "table": table_name,
                    "name": name,
                    "function": actual["function"],
                    "type_mask": actual["type_mask"],
                    "enabled": actual["enabled"],
                    "constraint": actual["constraint"],
                    "deferrable": actual["deferrable"],
                    "initially_deferred": actual["initially_deferred"],
                    "definition": actual["definition"],
                }
            )
            function_key = (
                actual["function_schema"],
                actual["function"],
                actual["function_identity_arguments"],
            )
            authority_functions[function_key] = {
                "kind": "trigger-function",
                "schema": actual["function_schema"],
                "name": actual["function"],
                "language": actual["function_language"],
                "result": actual["function_result"],
                "volatility": actual["function_volatility"],
                "parallel": actual["function_parallel"],
                "security_definer": actual["function_security_definer"],
                "strict": actual["function_strict"],
                "leakproof": actual["function_leakproof"],
                "nargs": actual["function_nargs"],
                "identity_arguments": actual["function_identity_arguments"],
                "config": actual["function_config"],
                "source": actual["function_source"],
            }
        for name, expected in requirements["triggers"].items():
            actual = triggers.get(name)
            if actual is None or any(
                actual.get(attribute) != expected.get(attribute, default)
                for attribute, default in (
                    ("function", ""),
                    ("function_schema", "<current>"),
                    ("type_mask", -1),
                    ("enabled", ""),
                    ("constraint", False),
                    ("deferrable", False),
                    ("initially_deferred", False),
                )
            ):
                missing.append(f"trigger:{table_name}.{name}")
    for (function_name, identity_arguments), expected in REQUIRED_MIGRATION_FUNCTIONS.items():
        function_row = (
            await conn.execute(
                text("""
                    SELECT CASE
                               WHEN namespace_row.nspname = current_schema() THEN '<current>'
                               ELSE namespace_row.nspname
                           END AS function_schema,
                           language_row.lanname,
                           pg_get_function_result(procedure_row.oid),
                           procedure_row.provolatile::text,
                           procedure_row.proparallel::text,
                           procedure_row.prosecdef,
                           procedure_row.proisstrict,
                           procedure_row.proleakproof,
                           procedure_row.pronargs,
                           pg_get_function_identity_arguments(procedure_row.oid),
                           procedure_row.proconfig,
                           procedure_row.prosrc
                    FROM pg_proc AS procedure_row
                    JOIN pg_namespace AS namespace_row
                      ON namespace_row.oid = procedure_row.pronamespace
                    JOIN pg_language AS language_row
                      ON language_row.oid = procedure_row.prolang
                    WHERE namespace_row.nspname = current_schema()
                      AND procedure_row.proname = :function_name
                      AND pg_get_function_identity_arguments(procedure_row.oid)
                          = :identity_arguments
                """),
                {
                    "function_name": function_name,
                    "identity_arguments": identity_arguments,
                },
            )
        ).one_or_none()
        if function_row is None:
            missing.append(f"function:{function_name}({identity_arguments})")
            continue
        actual = {
            "kind": "trigger-function",
            "schema": str(function_row[0]),
            "name": function_name,
            "language": str(function_row[1]),
            "result": str(function_row[2]),
            "volatility": _decode_catalog_char(function_row[3]),
            "parallel": _decode_catalog_char(function_row[4]),
            "security_definer": bool(function_row[5]),
            "strict": bool(function_row[6]),
            "leakproof": bool(function_row[7]),
            "nargs": int(function_row[8]),
            "identity_arguments": str(function_row[9]),
            "config": ([str(value) for value in function_row[10]] if function_row[10] is not None else None),
            "source": _normalize_catalog_definition(function_row[11]),
        }
        authority_functions[("<current>", function_name, identity_arguments)] = actual
        expected_config = expected.get("config")
        if (
            actual["schema"] != "<current>"
            or actual["language"] != expected["language"]
            or actual["result"] != expected["result"]
            or actual["volatility"] != expected["volatility"]
            or actual["parallel"] != expected["parallel"]
            or actual["security_definer"] is not expected["security_definer"]
            or actual["strict"] is not expected["strict"]
            or actual["leakproof"]
            or tuple(actual["config"] or ()) != tuple(expected_config or ())
        ):
            missing.append(f"function:{function_name}({identity_arguments})")
    authority_facts.extend(authority_functions.values())
    actual_fingerprint = _authority_schema_fingerprint(authority_facts)
    return missing, actual_fingerprint


async def compute_migration_schema_authority_fingerprint(conn) -> str:
    """Return the catalog-derived fingerprint for reproducibility tooling."""

    _, actual_fingerprint = await _inspect_migration_owned_schema(conn)
    return actual_fingerprint


async def verify_migration_owned_schema(conn) -> None:
    missing, actual_fingerprint = await _inspect_migration_owned_schema(conn)
    if actual_fingerprint != MIGRATION_SCHEMA_AUTHORITY_FINGERPRINT:
        missing.append(f"authority-fingerprint:expected={MIGRATION_SCHEMA_AUTHORITY_FINGERPRINT},actual={actual_fingerprint}")
    if missing:
        raise RuntimeError("Migration-owned authority schema is incomplete or drifted: " + ", ".join(missing[:20]))


async def get_session() -> AsyncSession:
    async with async_session_factory() as session:
        yield session


async def create_tables() -> None:
    """Create and upgrade schema objects in one transaction.

    Referential-integrity preflights deliberately abort on legacy orphan rows;
    startup never deletes or rewrites investigation data implicitly.
    """
    async with engine.begin() as conn:
        alembic_table = await conn.scalar(text("SELECT to_regclass('alembic_version')"))
        if alembic_table is None:
            raise RuntimeError("Database migrations have not been applied; run 'alembic upgrade head' before starting AdversaryGraph")
        revision_rows = await conn.execute(text("SELECT version_num FROM alembic_version ORDER BY version_num"))
        revisions = tuple(str(value) for value in revision_rows.scalars())
        if revisions != (REQUIRED_SCHEMA_REVISION,):
            found_revisions = ", ".join(revisions) or "empty"
            raise RuntimeError(
                "Database schema revision is not compatible with this application: "
                f"expected exactly {REQUIRED_SCHEMA_REVISION}, found {found_revisions}; "
                "run 'alembic upgrade head'"
            )
        await verify_migration_owned_schema(conn)
        # RAG vectors live beside their authoritative records so backups,
        # transactions, and authorization filters share one database boundary.
        # The bundled PostgreSQL image installs this extension package. An
        # external database must make pgvector available before first startup.
        await conn.execute(text("CREATE EXTENSION IF NOT EXISTS vector"))
        vector_version = await conn.scalar(text("SELECT extversion FROM pg_extension WHERE extname = 'vector'"))
        parsed_version = [int(part) for part in re.findall(r"\d+", str(vector_version or ""))[:3]]
        version_parts = tuple((parsed_version + [0, 0, 0])[:3])
        if version_parts < (0, 5, 0):
            raise RuntimeError(
                "pgvector 0.5.0 or newer is required for the RAG HNSW index; "
                f"the database reports {vector_version or 'no installed version'}"
            )
        await conn.run_sync(
            lambda sync_conn: Base.metadata.create_all(
                sync_conn,
                tables=startup_managed_tables(),
            )
        )
        rag_vector_type = await conn.scalar(
            text("""
            SELECT format_type(attribute.atttypid, attribute.atttypmod)
            FROM pg_attribute AS attribute
            JOIN pg_class AS relation ON relation.oid = attribute.attrelid
            JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
            WHERE namespace.nspname = current_schema()
              AND relation.relname = 'rag_chunks'
              AND attribute.attname = 'embedding'
              AND attribute.attnum > 0
              AND NOT attribute.attisdropped
        """)
        )
        expected_rag_vector_type = f"vector({settings.rag_embedding_dimensions})"
        if rag_vector_type and str(rag_vector_type) != expected_rag_vector_type:
            raise RuntimeError(
                "RAG_EMBEDDING_DIMENSIONS does not match the existing rag_chunks.embedding "
                f"column ({rag_vector_type}); perform the documented corpus schema migration "
                "and full reindex before restarting"
            )
        await conn.execute(text("ALTER TABLE apt_groups ADD COLUMN IF NOT EXISTS created VARCHAR(50) DEFAULT ''"))
        await conn.execute(text("ALTER TABLE apt_groups ADD COLUMN IF NOT EXISTS modified VARCHAR(50) DEFAULT ''"))
        await conn.execute(text("ALTER TABLE apt_groups ADD COLUMN IF NOT EXISTS attack_version VARCHAR(50) DEFAULT ''"))
        await conn.execute(text("ALTER TABLE apt_groups ADD COLUMN IF NOT EXISTS contributors JSONB DEFAULT '[]'::jsonb"))
        await conn.execute(text("ALTER TABLE apt_groups ADD COLUMN IF NOT EXISTS external_references JSONB DEFAULT '[]'::jsonb"))
        await conn.execute(text("ALTER TABLE analysis_sessions ADD COLUMN IF NOT EXISTS source_text TEXT DEFAULT ''"))
        await conn.execute(
            text("ALTER TABLE analysis_sessions ADD COLUMN IF NOT EXISTS source_provenance JSONB NOT NULL DEFAULT '{}'::jsonb")
        )
        await conn.execute(text("ALTER TABLE analysis_sessions ADD COLUMN IF NOT EXISTS tlp VARCHAR(20) DEFAULT 'TLP:AMBER+STRICT'"))
        await conn.execute(
            text("""
            UPDATE analysis_sessions
            SET tlp = 'TLP:AMBER+STRICT'
            WHERE tlp IS NULL
               OR tlp NOT IN ('TLP:CLEAR', 'TLP:GREEN', 'TLP:AMBER', 'TLP:AMBER+STRICT', 'TLP:RED')
        """)
        )
        await conn.execute(text("ALTER TABLE analysis_sessions ALTER COLUMN tlp SET DEFAULT 'TLP:AMBER+STRICT'"))
        await conn.execute(text("ALTER TABLE analysis_sessions ALTER COLUMN tlp SET NOT NULL"))
        await conn.execute(text("ALTER TABLE ioc_indicators ADD COLUMN IF NOT EXISTS technique_ids JSONB DEFAULT '[]'::jsonb"))
        await conn.execute(text("ALTER TABLE report_intake ADD COLUMN IF NOT EXISTS tags JSONB DEFAULT '[]'::jsonb"))
        await conn.execute(text("ALTER TABLE report_intake ADD COLUMN IF NOT EXISTS provenance JSONB DEFAULT '{}'::jsonb"))
        await conn.execute(text("ALTER TABLE report_intake ADD COLUMN IF NOT EXISTS analysis_session_id UUID"))
        await conn.execute(
            text(r"""
            UPDATE report_intake AS intake
            SET analysis_session_id = (intake.provenance->>'analysis_session_id')::uuid
            WHERE intake.analysis_session_id IS NULL
              AND COALESCE(intake.provenance->>'analysis_session_id', '') ~*
                  '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
              AND EXISTS (
                  SELECT 1 FROM analysis_sessions AS analysis
                  WHERE analysis.id = (intake.provenance->>'analysis_session_id')::uuid
              )
        """)
        )
        await conn.execute(
            text("""
            DO $$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM pg_constraint
                    WHERE conrelid = 'report_intake'::regclass
                      AND conname = 'fk_report_intake_analysis_session'
                ) THEN
                    ALTER TABLE report_intake
                    ADD CONSTRAINT fk_report_intake_analysis_session
                    FOREIGN KEY (analysis_session_id) REFERENCES analysis_sessions(id)
                    ON DELETE SET NULL;
                END IF;
            END
            $$
        """)
        )
        await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_report_intake_analysis_session_id ON report_intake (analysis_session_id)"))
        await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_report_intake_tags_gin ON report_intake USING gin (tags)"))
        await conn.execute(
            text("""
            DO $$
            DECLARE
                entity_tag_constraint TEXT;
            BEGIN
                SELECT pg_get_constraintdef(oid)
                INTO entity_tag_constraint
                FROM pg_constraint
                WHERE conrelid = 'intelligence_entity_tags'::regclass
                  AND conname = 'uq_intelligence_entity_tag';

                IF entity_tag_constraint IS NULL
                   OR entity_tag_constraint NOT ILIKE '%source_type%'
                   OR entity_tag_constraint NOT ILIKE '%source_id%' THEN
                    ALTER TABLE intelligence_entity_tags
                    DROP CONSTRAINT IF EXISTS uq_intelligence_entity_tag;
                    ALTER TABLE intelligence_entity_tags
                    ADD CONSTRAINT uq_intelligence_entity_tag
                    UNIQUE (entity_type, entity_id, tag, source_type, source_id);
                END IF;
            END
            $$
        """)
        )
        await conn.execute(
            text("CREATE INDEX IF NOT EXISTS ix_intelligence_entity_tags_entity ON intelligence_entity_tags (entity_type, entity_id)")
        )
        await conn.execute(
            text("CREATE INDEX IF NOT EXISTS ix_intelligence_relationship_source ON intelligence_relationships (source_type, source_id)")
        )
        await conn.execute(
            text("CREATE INDEX IF NOT EXISTS ix_intelligence_relationship_target ON intelligence_relationships (target_type, target_id)")
        )
        await conn.execute(text("ALTER TABLE user_accounts ADD COLUMN IF NOT EXISTS permissions JSONB DEFAULT '[]'::jsonb"))
        await conn.execute(text("ALTER TABLE user_accounts ADD COLUMN IF NOT EXISTS auth_provider VARCHAR(50) DEFAULT 'local'"))
        await conn.execute(text("ALTER TABLE user_accounts ADD COLUMN IF NOT EXISTS external_subject VARCHAR(255) DEFAULT ''"))
        await conn.execute(text("ALTER TABLE user_accounts ADD COLUMN IF NOT EXISTS mfa_enabled BOOLEAN DEFAULT false"))
        await conn.execute(text("ALTER TABLE user_accounts ADD COLUMN IF NOT EXISTS mfa_secret TEXT DEFAULT ''"))
        await conn.execute(text("ALTER TABLE threat_asset_scans ADD COLUMN IF NOT EXISTS web_probe_requested BOOLEAN DEFAULT false"))
        await conn.execute(text("ALTER TABLE threat_asset_scans ADD COLUMN IF NOT EXISTS web_probe_result JSONB DEFAULT '{}'::jsonb"))
        await conn.execute(text("ALTER TABLE threat_asset_scans ADD COLUMN IF NOT EXISTS additional_scanners JSONB DEFAULT '[]'::jsonb"))
        await conn.execute(text("ALTER TABLE threat_asset_scans ADD COLUMN IF NOT EXISTS scanner_results JSONB DEFAULT '{}'::jsonb"))
        await conn.execute(text("ALTER TABLE threat_asset_scans ADD COLUMN IF NOT EXISTS inventory_update JSONB DEFAULT '{}'::jsonb"))
        await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_auth_sessions_revoked_at ON auth_sessions (revoked_at)"))
        await conn.execute(text("ALTER TABLE threat_hunt_requests ALTER COLUMN case_id DROP NOT NULL"))
        await conn.execute(text("ALTER TABLE threat_hunt_requests ADD COLUMN IF NOT EXISTS description TEXT DEFAULT ''"))
        await conn.execute(text("ALTER TABLE threat_hunt_requests ADD COLUMN IF NOT EXISTS scope TEXT DEFAULT ''"))
        await conn.execute(text("ALTER TABLE threat_hunt_requests ADD COLUMN IF NOT EXISTS priority VARCHAR(40) DEFAULT 'P3 Monitor'"))
        await conn.execute(text("ALTER TABLE threat_hunt_requests ADD COLUMN IF NOT EXISTS owner VARCHAR(255) DEFAULT ''"))
        await conn.execute(text("ALTER TABLE threat_hunt_requests ADD COLUMN IF NOT EXISTS source_type VARCHAR(80) DEFAULT 'manual'"))
        await conn.execute(text("ALTER TABLE threat_hunt_requests ADD COLUMN IF NOT EXISTS source_ref VARCHAR(500) DEFAULT ''"))
        await conn.execute(text("ALTER TABLE threat_hunt_requests ADD COLUMN IF NOT EXISTS tactics JSONB DEFAULT '[]'::jsonb"))
        await conn.execute(text("ALTER TABLE threat_hunt_requests ADD COLUMN IF NOT EXISTS required_fields JSONB DEFAULT '[]'::jsonb"))
        await conn.execute(text("ALTER TABLE threat_hunt_requests ADD COLUMN IF NOT EXISTS tags JSONB DEFAULT '[]'::jsonb"))
        await conn.execute(text("ALTER TABLE threat_hunt_requests ADD COLUMN IF NOT EXISTS query_language VARCHAR(40) DEFAULT 'generic'"))
        await conn.execute(text("ALTER TABLE threat_hunt_requests ADD COLUMN IF NOT EXISTS query_text TEXT DEFAULT ''"))
        await conn.execute(text("ALTER TABLE threat_hunt_requests ADD COLUMN IF NOT EXISTS time_range_start TIMESTAMPTZ"))
        await conn.execute(text("ALTER TABLE threat_hunt_requests ADD COLUMN IF NOT EXISTS time_range_end TIMESTAMPTZ"))
        await conn.execute(text("ALTER TABLE threat_hunt_requests ADD COLUMN IF NOT EXISTS expected_evidence TEXT DEFAULT ''"))
        await conn.execute(text("ALTER TABLE threat_hunt_requests ADD COLUMN IF NOT EXISTS false_positive_notes TEXT DEFAULT ''"))
        await conn.execute(text("ALTER TABLE threat_hunt_requests ADD COLUMN IF NOT EXISTS assumptions TEXT DEFAULT ''"))
        await conn.execute(text("ALTER TABLE threat_hunt_requests ADD COLUMN IF NOT EXISTS result_summary TEXT DEFAULT ''"))
        await conn.execute(text("ALTER TABLE threat_hunt_requests ADD COLUMN IF NOT EXISTS disposition VARCHAR(60) DEFAULT 'undetermined'"))
        await conn.execute(text("ALTER TABLE threat_hunt_requests ADD COLUMN IF NOT EXISTS tlp VARCHAR(20) DEFAULT 'TLP:AMBER'"))
        await conn.execute(text("ALTER TABLE threat_hunt_requests ADD COLUMN IF NOT EXISTS created_by VARCHAR(255) DEFAULT 'local'"))
        await conn.execute(text("ALTER TABLE threat_hunt_requests ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT now()"))
        await conn.execute(text("ALTER TABLE threat_hunt_requests ADD COLUMN IF NOT EXISTS completed_at TIMESTAMPTZ"))
        await conn.execute(text("ALTER TABLE threat_hunt_requests ADD COLUMN IF NOT EXISTS archived_at TIMESTAMPTZ"))
        await conn.execute(
            text("""
            UPDATE threat_hunt_requests AS hunt
            SET source_type = 'threat_radar',
                source_ref = hunt.case_id::text,
                description = COALESCE(NULLIF(hunt.description, ''), threat_case.summary, ''),
                priority = COALESCE(NULLIF(threat_case.priority, ''), hunt.priority, 'P3 Monitor'),
                tlp = COALESCE(NULLIF(threat_case.tlp, ''), hunt.tlp, 'TLP:AMBER')
            FROM threat_cases AS threat_case
            WHERE hunt.case_id = threat_case.id
              AND COALESCE(hunt.source_ref, '') = ''
        """)
        )
        await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_threat_hunt_requests_status ON threat_hunt_requests (status)"))
        await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_threat_hunt_requests_priority ON threat_hunt_requests (priority)"))
        await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_threat_hunt_requests_owner ON threat_hunt_requests (owner)"))
        await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_threat_hunt_requests_source_type ON threat_hunt_requests (source_type)"))
        await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_threat_hunt_requests_disposition ON threat_hunt_requests (disposition)"))
        await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_threat_hunt_requests_archived_at ON threat_hunt_requests (archived_at)"))
        await conn.execute(
            text("CREATE INDEX IF NOT EXISTS ix_hunt_query_library_techniques_gin ON hunt_query_library USING gin (technique_ids)")
        )
        await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_hunt_query_library_tags_gin ON hunt_query_library USING gin (tags)"))
        await conn.execute(
            text("CREATE INDEX IF NOT EXISTS ix_hunt_query_library_language_quality ON hunt_query_library (language, quality_score)")
        )
        await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_hunt_query_library_source_name ON hunt_query_library (source_name)"))
        await conn.execute(
            text("""
            DO $$
            BEGIN
                IF EXISTS (
                    SELECT 1
                    FROM threat_hunt_ai_assistance AS assistance
                    WHERE assistance.source_session_id IS NOT NULL
                      AND NOT EXISTS (
                          SELECT 1
                          FROM analysis_sessions AS source
                          WHERE source.id = assistance.source_session_id
                      )
                ) THEN
                    RAISE EXCEPTION USING MESSAGE =
                        'Legacy orphan threat_hunt_ai_assistance rows block the source-session foreign key; back up and repair them before startup';
                END IF;
            END
            $$
        """)
        )
        await conn.execute(
            text("""
            DO $$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM pg_constraint
                    WHERE conrelid = 'threat_hunt_ai_assistance'::regclass
                      AND contype = 'f'
                      AND pg_get_constraintdef(oid) LIKE
                          'FOREIGN KEY (source_session_id) REFERENCES analysis_sessions(id)%'
                ) THEN
                    ALTER TABLE threat_hunt_ai_assistance
                    ADD CONSTRAINT fk_threat_hunt_ai_source_session
                    FOREIGN KEY (source_session_id) REFERENCES analysis_sessions(id)
                    ON DELETE SET NULL;
                END IF;
            END
            $$
        """)
        )
        await conn.execute(
            text("""
            DO $$
            BEGIN
                IF EXISTS (
                    SELECT 1
                    FROM evidence_graph_edges AS edge
                    WHERE NOT EXISTS (
                        SELECT 1 FROM evidence_graph_nodes AS node
                        WHERE node.id = edge.source_node_id
                    )
                       OR NOT EXISTS (
                        SELECT 1 FROM evidence_graph_nodes AS node
                        WHERE node.id = edge.target_node_id
                    )
                ) THEN
                    RAISE EXCEPTION USING MESSAGE =
                        'Legacy orphan evidence_graph_edges rows block graph foreign keys; back up and repair them before startup';
                END IF;
            END
            $$
        """)
        )
        await conn.execute(
            text("""
            DO $$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM pg_constraint
                    WHERE conrelid = 'evidence_graph_edges'::regclass
                      AND contype = 'f'
                      AND pg_get_constraintdef(oid) LIKE
                          'FOREIGN KEY (source_node_id) REFERENCES evidence_graph_nodes(id)%'
                ) THEN
                    ALTER TABLE evidence_graph_edges
                    ADD CONSTRAINT fk_evidence_graph_edge_source
                    FOREIGN KEY (source_node_id) REFERENCES evidence_graph_nodes(id)
                    ON DELETE CASCADE;
                END IF;
                IF NOT EXISTS (
                    SELECT 1 FROM pg_constraint
                    WHERE conrelid = 'evidence_graph_edges'::regclass
                      AND contype = 'f'
                      AND pg_get_constraintdef(oid) LIKE
                          'FOREIGN KEY (target_node_id) REFERENCES evidence_graph_nodes(id)%'
                ) THEN
                    ALTER TABLE evidence_graph_edges
                    ADD CONSTRAINT fk_evidence_graph_edge_target
                    FOREIGN KEY (target_node_id) REFERENCES evidence_graph_nodes(id)
                    ON DELETE CASCADE;
                END IF;
            END
            $$
        """)
        )
        await conn.execute(
            text("""
            UPDATE threat_hunt_requests
            SET priority = 'P2 Medium'
            WHERE priority IS NULL
               OR priority NOT IN ('P0 Emergency', 'P1 High', 'P2 Medium', 'P3 Monitor', 'P4 Low/Archive')
        """)
        )
        await conn.execute(
            text("""
            UPDATE threat_hunt_requests
            SET tlp = 'TLP:RED'
            WHERE tlp IS NULL
               OR tlp NOT IN ('TLP:CLEAR', 'TLP:GREEN', 'TLP:AMBER', 'TLP:AMBER+STRICT', 'TLP:RED')
        """)
        )
