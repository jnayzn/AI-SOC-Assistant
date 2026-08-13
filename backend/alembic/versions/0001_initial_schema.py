"""Initial baseline schema.

Mirrors the current SQLAlchemy models (users, analyses, user_settings,
threat_intel_cache). Written by hand -- this sandbox has no live database
connection to run `alembic revision --autogenerate` against, so the columns
below are transcribed directly from app/models/*.py. Existing deployments
that already have these tables (created via Base.metadata.create_all on
first startup, per app/main.py) should stamp this revision instead of
running it:

    alembic stamp 0001_initial_schema

Fresh deployments should run it normally:

    alembic upgrade head

Revision ID: 0001_initial_schema
Revises:
Create Date: 2026-08-03
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "0001_initial_schema"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("full_name", sa.String(length=255), nullable=True),
        sa.Column("hashed_password", sa.String(length=255), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("is_admin", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_users_email", "users", ["email"], unique=True)

    op.create_table(
        "analyses",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("user_id", sa.String(length=36), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=True),
        sa.Column("input_text", sa.Text(), nullable=False),
        sa.Column("input_type", sa.String(length=50), nullable=False, server_default="unknown"),
        sa.Column("classification", sa.String(length=50), nullable=False),
        sa.Column("risk_level", sa.String(length=20), nullable=False),
        sa.Column("confidence", sa.Integer(), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("explanation", sa.Text(), nullable=False),
        sa.Column("recommendations", sa.JSON(), nullable=True),
        sa.Column("indicators", sa.JSON(), nullable=True),
        sa.Column("mitre_techniques", sa.JSON(), nullable=True),
        sa.Column("iocs", sa.JSON(), nullable=True),
        sa.Column("model_used", sa.String(length=100), nullable=False, server_default="gpt-4o-mini"),
        sa.Column("latency_ms", sa.Float(), nullable=False, server_default="0"),
        sa.Column("risk_score", sa.Integer(), nullable=True),
        sa.Column("threat_tags", sa.JSON(), nullable=True),
        sa.Column("mitre_details", sa.JSON(), nullable=True),
        sa.Column("attack_timeline", sa.JSON(), nullable=True),
        sa.Column("explainability", sa.JSON(), nullable=True),
        sa.Column("recommendations_grouped", sa.JSON(), nullable=True),
        sa.Column("sigma_match", sa.JSON(), nullable=True),
        sa.Column("detection_metrics", sa.JSON(), nullable=True),
        sa.Column("threat_intel", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_analyses_user_id", "analyses", ["user_id"])
    op.create_index("ix_analyses_classification", "analyses", ["classification"])
    op.create_index("ix_analyses_risk_level", "analyses", ["risk_level"])
    op.create_index("ix_analyses_created_at", "analyses", ["created_at"])

    op.create_table(
        "user_settings",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("user_id", sa.String(length=36), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, unique=True),
        sa.Column("theme", sa.String(length=10), nullable=False, server_default="light"),
        sa.Column("preferred_model", sa.String(length=100), nullable=False, server_default="gpt-4o-mini"),
        sa.Column("email_notifications", sa.Boolean(), nullable=False, server_default=sa.true()),
    )

    op.create_table(
        "threat_intel_cache",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("source", sa.String(length=32), nullable=False),
        sa.Column("indicator_type", sa.String(length=16), nullable=False),
        sa.Column("indicator", sa.String(length=512), nullable=False),
        sa.Column("result", sa.JSON(), nullable=False),
        sa.Column("checked_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_threat_intel_cache_source", "threat_intel_cache", ["source"])
    op.create_index("ix_threat_intel_cache_indicator", "threat_intel_cache", ["indicator"])
    op.create_index("ix_threat_intel_cache_checked_at", "threat_intel_cache", ["checked_at"])
    op.create_unique_constraint(
        "uq_threat_intel_cache_key", "threat_intel_cache", ["source", "indicator_type", "indicator"]
    )


def downgrade() -> None:
    op.drop_table("threat_intel_cache")
    op.drop_table("user_settings")
    op.drop_index("ix_analyses_created_at", table_name="analyses")
    op.drop_index("ix_analyses_risk_level", table_name="analyses")
    op.drop_index("ix_analyses_classification", table_name="analyses")
    op.drop_index("ix_analyses_user_id", table_name="analyses")
    op.drop_table("analyses")
    op.drop_index("ix_users_email", table_name="users")
    op.drop_table("users")
