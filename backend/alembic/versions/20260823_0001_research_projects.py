"""Create revisioned research-project authority tables.

Revision ID: 20260823_0001
Revises: None
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "20260823_0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "research_projects",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("project_key", sa.String(length=80), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("domain", sa.String(length=50), nullable=False),
        sa.Column("tlp", sa.String(length=24), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.Column("created_by_id", sa.String(length=80), nullable=False),
        sa.Column("updated_by", sa.String(length=255), nullable=False),
        sa.Column("updated_by_id", sa.String(length=80), nullable=False),
        sa.Column("archive_reason", sa.Text(), nullable=False),
        sa.Column("archived_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "project_key ~ '^[a-z0-9][a-z0-9-]{0,79}$'",
            name="ck_research_project_key",
        ),
        sa.CheckConstraint(
            "status IN ('active', 'archived')",
            name="ck_research_project_status",
        ),
        sa.CheckConstraint(
            "tlp IN ('TLP:CLEAR', 'TLP:GREEN', 'TLP:AMBER', 'TLP:AMBER+STRICT', 'TLP:RED')",
            name="ck_research_project_tlp",
        ),
        sa.CheckConstraint("version >= 1", name="ck_research_project_version"),
        sa.CheckConstraint(
            "(status = 'archived' AND archived_at IS NOT NULL AND archive_reason <> '') "
            "OR (status = 'active' AND archived_at IS NULL AND archive_reason = '')",
            name="ck_research_project_archive_facts",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("project_key", name="uq_research_project_key"),
    )
    op.create_index(
        "ix_research_projects_status_updated",
        "research_projects",
        ["status", "updated_at"],
    )

    op.create_table(
        "project_revisions",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("project_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "parent_revision_id", postgresql.UUID(as_uuid=True), nullable=True
        ),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("schema_version", sa.String(length=80), nullable=False),
        sa.Column("spec", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("spec_checksum", sa.String(length=64), nullable=False),
        sa.Column("change_summary", sa.Text(), nullable=False),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.Column("created_by_id", sa.String(length=80), nullable=False),
        sa.Column("revoked_by", sa.String(length=255), nullable=False),
        sa.Column("revoked_by_id", sa.String(length=80), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint("revision >= 1", name="ck_project_revision_number"),
        sa.CheckConstraint(
            "status IN ('current', 'superseded', 'revoked')",
            name="ck_project_revision_status",
        ),
        sa.CheckConstraint(
            "spec_checksum ~ '^[0-9a-f]{64}$'",
            name="ck_project_revision_checksum",
        ),
        sa.CheckConstraint(
            "parent_revision_id IS NULL OR parent_revision_id <> id",
            name="ck_project_revision_parent_not_self",
        ),
        sa.CheckConstraint(
            "(status = 'revoked' AND revoked_at IS NOT NULL "
            "AND revoked_by <> '' AND revoked_by_id <> '') OR "
            "(status <> 'revoked' AND revoked_at IS NULL "
            "AND revoked_by = '' AND revoked_by_id = '')",
            name="ck_project_revision_revocation_facts",
        ),
        sa.ForeignKeyConstraint(
            ["parent_revision_id"],
            ["project_revisions.id"],
            name="fk_project_revision_parent",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["project_id"],
            ["research_projects.id"],
            name="fk_project_revision_project",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "project_id", "revision", name="uq_project_revision_number"
        ),
    )
    op.create_index(
        "ix_project_revisions_parent",
        "project_revisions",
        ["parent_revision_id"],
    )
    op.create_index(
        "ix_project_revisions_project_status_revision",
        "project_revisions",
        ["project_id", "status", "revision"],
    )
    op.create_index(
        "ix_project_revisions_spec_checksum",
        "project_revisions",
        ["spec_checksum"],
    )
    op.create_index(
        "uq_project_revision_current",
        "project_revisions",
        ["project_id"],
        unique=True,
        postgresql_where=sa.text("status = 'current'"),
    )


def downgrade() -> None:
    op.drop_table("project_revisions")
    op.drop_table("research_projects")
