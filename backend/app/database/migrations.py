"""Tiny, additive "light migration" helper.

This project uses Base.metadata.create_all() on startup for local dev
convenience instead of a maintained Alembic migration chain (see
app/main.py). create_all() only creates missing TABLES, not missing COLUMNS
on tables that already exist. To let existing deployments (with data already
in their Postgres volume) pick up new nullable columns without losing data,
this runs idempotent `ADD COLUMN IF NOT EXISTS` statements after create_all().

For a real production rollout, replace this with proper Alembic revisions.
"""
import logging

from sqlalchemy import text
from sqlalchemy.engine import Engine

logger = logging.getLogger(__name__)

# (table, column, DDL type) -- keep additive/nullable only.
_ANALYZER_ENRICHMENT_COLUMNS = [
    ("analyses", "risk_score", "INTEGER"),
    ("analyses", "threat_tags", "JSON"),
    ("analyses", "mitre_details", "JSON"),
    ("analyses", "attack_timeline", "JSON"),
    ("analyses", "explainability", "JSON"),
    ("analyses", "recommendations_grouped", "JSON"),
    ("analyses", "sigma_match", "JSON"),
    ("analyses", "detection_metrics", "JSON"),
    ("analyses", "threat_intel", "JSON"),
    # Enterprise SOC additions (additive; nullable)
    ("analyses", "owasp_mappings", "JSON"),
    ("analyses", "risk_factors", "JSON"),
    ("analyses", "knowledge_sources", "JSON"),
    ("analyses", "playbook_actions", "JSON"),
]


def run_light_migrations(engine: Engine) -> None:
    with engine.begin() as conn:
        for table, column, ddl_type in _ANALYZER_ENRICHMENT_COLUMNS:
            try:
                conn.execute(
                    text(f'ALTER TABLE "{table}" ADD COLUMN IF NOT EXISTS "{column}" {ddl_type}')
                )
            except Exception:  # pragma: no cover - defensive, e.g. non-Postgres dialects
                logger.exception("Light migration failed for %s.%s, skipping.", table, column)
    logger.info("Light migrations applied (analyzer enrichment columns).")
