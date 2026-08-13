"""IntelOwl scans table (additive).

Existing deployments auto-create this table via Base.metadata.create_all on
startup; stamp instead of running: alembic stamp 0002_intelowl_scans

Revision ID: 0002_intelowl_scans
Revises: 0001_initial_schema
"""
from alembic import op
import sqlalchemy as sa

revision = "0002_intelowl_scans"
down_revision = "0001_initial_schema"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "intelowl_scans",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("analysis_id", sa.String(length=36), sa.ForeignKey("analyses.id", ondelete="CASCADE"), nullable=True),
        sa.Column("observable", sa.Text(), nullable=False),
        sa.Column("observable_type", sa.String(length=20), nullable=False),
        sa.Column("intelowl_job_id", sa.String(length=64), nullable=True),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="PENDING"),
        sa.Column("verdict", sa.String(length=20), nullable=True),
        sa.Column("analyzers", sa.JSON(), nullable=True),
        sa.Column("connectors", sa.JSON(), nullable=True),
        sa.Column("raw_result", sa.JSON(), nullable=True),
        sa.Column("normalized_result", sa.JSON(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_intelowl_scans_analysis_id", "intelowl_scans", ["analysis_id"])
    op.create_index("ix_intelowl_scans_observable_type", "intelowl_scans", ["observable_type"])
    op.create_index("ix_intelowl_scans_intelowl_job_id", "intelowl_scans", ["intelowl_job_id"])
    op.create_index("ix_intelowl_scans_status", "intelowl_scans", ["status"])
    op.create_index("ix_intelowl_scans_created_at", "intelowl_scans", ["created_at"])
    op.create_index("ix_intelowl_scans_obs_type_created", "intelowl_scans", ["observable", "observable_type", "created_at"])


def downgrade() -> None:
    for ix in (
        "ix_intelowl_scans_obs_type_created", "ix_intelowl_scans_created_at", "ix_intelowl_scans_status",
        "ix_intelowl_scans_intelowl_job_id", "ix_intelowl_scans_observable_type", "ix_intelowl_scans_analysis_id",
    ):
        op.drop_index(ix, table_name="intelowl_scans")
    op.drop_table("intelowl_scans")
