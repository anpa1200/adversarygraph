import re

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy import text
from sqlalchemy.orm import DeclarativeBase

from app.core.config import settings

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


async def get_session() -> AsyncSession:
    async with async_session_factory() as session:
        yield session


async def create_tables() -> None:
    """Create and upgrade schema objects in one transaction.

    Referential-integrity preflights deliberately abort on legacy orphan rows;
    startup never deletes or rewrites investigation data implicitly.
    """
    async with engine.begin() as conn:
        # RAG vectors live beside their authoritative records so backups,
        # transactions, and authorization filters share one database boundary.
        # The bundled PostgreSQL image installs this extension package. An
        # external database must make pgvector available before first startup.
        await conn.execute(text("CREATE EXTENSION IF NOT EXISTS vector"))
        vector_version = await conn.scalar(
            text("SELECT extversion FROM pg_extension WHERE extname = 'vector'")
        )
        parsed_version = [
            int(part) for part in re.findall(r"\d+", str(vector_version or ""))[:3]
        ]
        version_parts = tuple((parsed_version + [0, 0, 0])[:3])
        if version_parts < (0, 5, 0):
            raise RuntimeError(
                "pgvector 0.5.0 or newer is required for the RAG HNSW index; "
                f"the database reports {vector_version or 'no installed version'}"
            )
        await conn.run_sync(Base.metadata.create_all)
        rag_vector_type = await conn.scalar(text("""
            SELECT format_type(attribute.atttypid, attribute.atttypmod)
            FROM pg_attribute AS attribute
            JOIN pg_class AS relation ON relation.oid = attribute.attrelid
            JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
            WHERE namespace.nspname = current_schema()
              AND relation.relname = 'rag_chunks'
              AND attribute.attname = 'embedding'
              AND attribute.attnum > 0
              AND NOT attribute.attisdropped
        """))
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
        await conn.execute(text(
            "ALTER TABLE analysis_sessions ADD COLUMN IF NOT EXISTS "
            "tlp VARCHAR(20) DEFAULT 'TLP:AMBER+STRICT'"
        ))
        await conn.execute(text("""
            UPDATE analysis_sessions
            SET tlp = 'TLP:AMBER+STRICT'
            WHERE tlp IS NULL
               OR tlp NOT IN ('TLP:CLEAR', 'TLP:GREEN', 'TLP:AMBER', 'TLP:AMBER+STRICT', 'TLP:RED')
        """))
        await conn.execute(text(
            "ALTER TABLE analysis_sessions ALTER COLUMN tlp "
            "SET DEFAULT 'TLP:AMBER+STRICT'"
        ))
        await conn.execute(text(
            "ALTER TABLE analysis_sessions ALTER COLUMN tlp SET NOT NULL"
        ))
        await conn.execute(text("ALTER TABLE ioc_indicators ADD COLUMN IF NOT EXISTS technique_ids JSONB DEFAULT '[]'::jsonb"))
        await conn.execute(text("ALTER TABLE user_accounts ADD COLUMN IF NOT EXISTS permissions JSONB DEFAULT '[]'::jsonb"))
        await conn.execute(text("ALTER TABLE user_accounts ADD COLUMN IF NOT EXISTS auth_provider VARCHAR(50) DEFAULT 'local'"))
        await conn.execute(text("ALTER TABLE user_accounts ADD COLUMN IF NOT EXISTS external_subject VARCHAR(255) DEFAULT ''"))
        await conn.execute(text("ALTER TABLE user_accounts ADD COLUMN IF NOT EXISTS mfa_enabled BOOLEAN DEFAULT false"))
        await conn.execute(text("ALTER TABLE user_accounts ADD COLUMN IF NOT EXISTS mfa_secret TEXT DEFAULT ''"))
        await conn.execute(text(
            "ALTER TABLE threat_asset_scans ADD COLUMN IF NOT EXISTS "
            "web_probe_requested BOOLEAN DEFAULT false"
        ))
        await conn.execute(text(
            "ALTER TABLE threat_asset_scans ADD COLUMN IF NOT EXISTS "
            "web_probe_result JSONB DEFAULT '{}'::jsonb"
        ))
        await conn.execute(text(
            "ALTER TABLE threat_asset_scans ADD COLUMN IF NOT EXISTS "
            "inventory_update JSONB DEFAULT '{}'::jsonb"
        ))
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
        await conn.execute(text("""
            UPDATE threat_hunt_requests AS hunt
            SET source_type = 'threat_radar',
                source_ref = hunt.case_id::text,
                description = COALESCE(NULLIF(hunt.description, ''), threat_case.summary, ''),
                priority = COALESCE(NULLIF(threat_case.priority, ''), hunt.priority, 'P3 Monitor'),
                tlp = COALESCE(NULLIF(threat_case.tlp, ''), hunt.tlp, 'TLP:AMBER')
            FROM threat_cases AS threat_case
            WHERE hunt.case_id = threat_case.id
              AND COALESCE(hunt.source_ref, '') = ''
        """))
        await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_threat_hunt_requests_status ON threat_hunt_requests (status)"))
        await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_threat_hunt_requests_priority ON threat_hunt_requests (priority)"))
        await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_threat_hunt_requests_owner ON threat_hunt_requests (owner)"))
        await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_threat_hunt_requests_source_type ON threat_hunt_requests (source_type)"))
        await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_threat_hunt_requests_disposition ON threat_hunt_requests (disposition)"))
        await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_threat_hunt_requests_archived_at ON threat_hunt_requests (archived_at)"))
        await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_hunt_query_library_techniques_gin ON hunt_query_library USING gin (technique_ids)"))
        await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_hunt_query_library_tags_gin ON hunt_query_library USING gin (tags)"))
        await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_hunt_query_library_language_quality ON hunt_query_library (language, quality_score)"))
        await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_hunt_query_library_source_name ON hunt_query_library (source_name)"))
        await conn.execute(text("""
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
        """))
        await conn.execute(text("""
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
        """))
        await conn.execute(text("""
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
        """))
        await conn.execute(text("""
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
        """))
        await conn.execute(text("""
            UPDATE threat_hunt_requests
            SET priority = 'P2 Medium'
            WHERE priority IS NULL
               OR priority NOT IN ('P0 Emergency', 'P1 High', 'P2 Medium', 'P3 Monitor', 'P4 Low/Archive')
        """))
        await conn.execute(text("""
            UPDATE threat_hunt_requests
            SET tlp = 'TLP:RED'
            WHERE tlp IS NULL
               OR tlp NOT IN ('TLP:CLEAR', 'TLP:GREEN', 'TLP:AMBER', 'TLP:AMBER+STRICT', 'TLP:RED')
        """))
