"""Preserve source-bound CTI investigation stages, coverage, IOCs and synthesis."""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "20261014_0005"
down_revision = "20260824_0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("analysis_results", sa.Column(
        "investigation", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb"),
    ))


def downgrade() -> None:
    op.drop_column("analysis_results", "investigation")
