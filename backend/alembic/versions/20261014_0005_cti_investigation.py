"""Preserve source-bound CTI investigation stages, coverage, IOCs and synthesis."""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "20261014_0005"
down_revision = "20260824_0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # analysis_results is a startup-managed table. Fresh databases create it
    # from current metadata after Alembic reaches head; legacy databases need
    # only this additive column. Never invent a partial baseline table here.
    inspector = sa.inspect(op.get_bind())
    if not inspector.has_table("analysis_results"):
        return
    if any(column["name"] == "investigation" for column in inspector.get_columns("analysis_results")):
        return
    op.add_column("analysis_results", sa.Column(
        "investigation", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb"),
    ))


def downgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    if not inspector.has_table("analysis_results"):
        return
    if not any(column["name"] == "investigation" for column in inspector.get_columns("analysis_results")):
        return
    op.execute("LOCK TABLE analysis_results IN ACCESS EXCLUSIVE MODE")
    populated = op.get_bind().scalar(sa.text(
        "SELECT count(*) FROM analysis_results WHERE investigation IS NOT NULL AND investigation <> '{}'::jsonb"
    ))
    if populated:
        raise RuntimeError("Refusing to discard stored CTI investigation evidence")
    op.drop_column("analysis_results", "investigation")
