"""Data access layer for Analysis/History records."""
from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from app.models.analysis import Analysis


class AnalysisRepository:
    def __init__(self, db: Session):
        self.db = db

    def create(self, analysis: Analysis) -> Analysis:
        self.db.add(analysis)
        self.db.commit()
        self.db.refresh(analysis)
        return analysis

    def get_by_id(self, analysis_id: str) -> Analysis | None:
        return self.db.get(Analysis, analysis_id)

    def list_paginated(
        self,
        page: int = 1,
        page_size: int = 20,
        user_id: str | None = None,
        classification: str | None = None,
        risk_level: str | None = None,
        search: str | None = None,
        sort_by: str = "created_at",
        sort_order: str = "desc",
    ) -> tuple[list[Analysis], int]:
        stmt = select(Analysis)
        if user_id:
            stmt = stmt.where(Analysis.user_id == user_id)
        if classification:
            stmt = stmt.where(Analysis.classification == classification)
        if risk_level:
            stmt = stmt.where(Analysis.risk_level == risk_level)
        if search:
            like_term = f"%{search}%"
            stmt = stmt.where(
                (Analysis.summary.ilike(like_term)) | (Analysis.input_text.ilike(like_term))
            )

        total = self.db.scalar(select(func.count()).select_from(stmt.subquery())) or 0

        sort_columns = {
            "created_at": Analysis.created_at,
            "confidence": Analysis.confidence,
            "risk_score": Analysis.risk_score,
            "classification": Analysis.classification,
            "risk_level": Analysis.risk_level,
        }
        sort_column = sort_columns.get(sort_by, Analysis.created_at)
        stmt = stmt.order_by(sort_column.asc() if sort_order == "asc" else sort_column.desc())
        stmt = stmt.offset((page - 1) * page_size).limit(page_size)
        items = list(self.db.scalars(stmt).all())
        return items, total

    def list_all_matching(
        self,
        user_id: str | None = None,
        classification: str | None = None,
        risk_level: str | None = None,
        search: str | None = None,
    ) -> list[Analysis]:
        """Used for CSV export: same filters as list_paginated, no pagination limit."""
        stmt = select(Analysis)
        if user_id:
            stmt = stmt.where(Analysis.user_id == user_id)
        if classification:
            stmt = stmt.where(Analysis.classification == classification)
        if risk_level:
            stmt = stmt.where(Analysis.risk_level == risk_level)
        if search:
            like_term = f"%{search}%"
            stmt = stmt.where(
                (Analysis.summary.ilike(like_term)) | (Analysis.input_text.ilike(like_term))
            )
        stmt = stmt.order_by(Analysis.created_at.desc())
        return list(self.db.scalars(stmt).all())

    def delete(self, analysis: Analysis) -> None:
        self.db.delete(analysis)
        self.db.commit()

    def count_all(self) -> int:
        return self.db.scalar(select(func.count()).select_from(Analysis)) or 0

    def count_by_classification(self, classification: str) -> int:
        stmt = select(func.count()).select_from(Analysis).where(Analysis.classification == classification)
        return self.db.scalar(stmt) or 0

    def count_by_risk(self, risk_level: str) -> int:
        stmt = select(func.count()).select_from(Analysis).where(Analysis.risk_level == risk_level)
        return self.db.scalar(stmt) or 0

    def count_with_threat_tag(self, tag: str) -> int:
        """Counts analyses whose normalized `threat_tags` (the canonical Threat
        Category dimension computed in enrichment_service.build_enrichment)
        contains an exact tag, e.g. "Malware" or "Phishing".

        This intentionally does NOT filter on `input_type` (Content Type) or
        do fragile substring matching on free text -- `threat_tags` is a
        deterministic, normalized list computed server-side once per
        analysis, so this is an exact membership check against a controlled
        vocabulary. Filtering is done in Python rather than with a
        dialect-specific JSON operator (e.g. Postgres `@>` vs SQLite
        `json_each`) so the same code works against every SQLAlchemy-
        supported database this project targets.
        """
        stmt = select(Analysis.threat_tags).where(Analysis.threat_tags.is_not(None))
        rows = self.db.scalars(stmt).all()
        return sum(1 for tags in rows if tags and tag in tags)

    def risk_distribution(self) -> list[tuple[str, int]]:
        stmt = select(Analysis.risk_level, func.count()).group_by(Analysis.risk_level)
        return list(self.db.execute(stmt).all())

    def classification_distribution(self) -> list[tuple[str, int]]:
        stmt = select(Analysis.classification, func.count()).group_by(Analysis.classification)
        return list(self.db.execute(stmt).all())

    def average_risk_score(self) -> float:
        return float(self.db.scalar(select(func.avg(Analysis.risk_score))) or 0.0)

    def average_confidence(self) -> float:
        return float(self.db.scalar(select(func.avg(Analysis.confidence))) or 0.0)

    def count_today(self) -> int:
        """Count analyses created since the start of the current UTC day."""
        from datetime import datetime, timezone

        start_of_day = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
        stmt = select(func.count()).select_from(Analysis).where(Analysis.created_at >= start_of_day)
        return self.db.scalar(stmt) or 0

    def average_latency_ms(self) -> float:
        return float(self.db.scalar(select(func.avg(Analysis.latency_ms))) or 0.0)

    def average_false_positive_probability(self) -> float:
        """Derives an aggregate false-positive rate from each analysis's
        already-computed `detection_metrics.false_positive_probability`
        (JSON column), avoiding any dialect-specific JSON SQL operators."""
        stmt = select(Analysis.detection_metrics).where(Analysis.detection_metrics.is_not(None))
        rows = self.db.scalars(stmt).all()
        values = [dm.get("false_positive_probability") for dm in rows if dm and dm.get("false_positive_probability") is not None]
        return float(sum(values) / len(values)) if values else 0.0

    def top_ioc_types(self, limit: int = 6) -> list[tuple[str, int]]:
        stmt = select(Analysis.iocs).where(Analysis.iocs.is_not(None))
        counts: dict[str, int] = {}
        for iocs in self.db.scalars(stmt).all():
            for key, values in (iocs or {}).items():
                if values:
                    counts[key] = counts.get(key, 0) + len(values)
        return sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:limit]

    def top_countries(self, limit: int = 6) -> list[tuple[str, int]]:
        stmt = select(Analysis.threat_intel).where(Analysis.threat_intel.is_not(None))
        counts: dict[str, int] = {}
        for intel in self.db.scalars(stmt).all():
            for finding in (intel or {}).get("findings", []) or []:
                country = finding.get("country")
                if country:
                    counts[country] = counts.get(country, 0) + 1
            for finding in (intel or {}).get("local_findings", []) or []:
                country = finding.get("country")
                if country:
                    counts[country] = counts.get(country, 0) + 1
        return sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:limit]

    def top_malware_families(self, limit: int = 6) -> list[tuple[str, int]]:
        stmt = select(Analysis.threat_intel).where(Analysis.threat_intel.is_not(None))
        counts: dict[str, int] = {}
        for intel in self.db.scalars(stmt).all():
            for finding in (intel or {}).get("findings", []) or []:
                family = finding.get("malware_family")
                if family:
                    counts[family] = counts.get(family, 0) + 1
        return sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:limit]

    def top_mitre_techniques(self, limit: int = 8) -> list[tuple[str, int]]:
        stmt = select(Analysis.mitre_details, Analysis.mitre_techniques)
        counts: dict[str, int] = {}
        for mitre_details, mitre_techniques in self.db.execute(stmt).all():
            if mitre_details:
                for t in mitre_details:
                    label = f"{t.get('id')} {t.get('name')}".strip()
                    counts[label] = counts.get(label, 0) + 1
            elif mitre_techniques:
                for t in mitre_techniques:
                    counts[t] = counts.get(t, 0) + 1
        return sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:limit]

    def top_owasp_categories(self, limit: int = 6) -> list[tuple[str, int]]:
        stmt = select(Analysis.owasp_mappings).where(Analysis.owasp_mappings.is_not(None))
        counts: dict[str, int] = {}
        for mappings in self.db.scalars(stmt).all():
            for mapping in mappings or []:
                label = f"{mapping.get('id')} {mapping.get('name')}".strip()
                counts[label] = counts.get(label, 0) + 1
        return sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:limit]

    def monthly_stats(self, months: int = 6) -> list[tuple[str, int, int, int, int]]:
        """Same shape as weekly_stats but bucketed by calendar month."""
        month_expr = func.strftime("%Y-%m", Analysis.created_at) if self.db.bind.dialect.name == "sqlite" else func.to_char(Analysis.created_at, "YYYY-MM")
        stmt = (
            select(
                month_expr.label("month"),
                func.count().label("total"),
                func.sum(case((Analysis.risk_level == "Critical", 1), else_=0)).label("critical"),
            )
            .group_by("month")
            .order_by("month")
        )
        rows = self.db.execute(stmt).all()

        tag_stmt = select(month_expr.label("month"), Analysis.threat_tags)
        per_month_tags: dict[str, list] = {}
        for month, threat_tags in self.db.execute(tag_stmt).all():
            per_month_tags.setdefault(str(month), []).append(threat_tags or [])

        results = []
        for r in rows[-months:]:
            month_key = str(r.month)
            tag_lists = per_month_tags.get(month_key, [])
            phishing_n = sum(1 for tags in tag_lists if "Phishing" in tags)
            malware_n = sum(1 for tags in tag_lists if "Malware" in tags)
            results.append((month_key, r.total, phishing_n, malware_n, r.critical or 0))
        return results

    def weekly_stats(self, days: int = 7) -> list[tuple[str, int, int, int, int]]:
        """Returns (date, total, phishing_count, malware_count, critical_count) per day.

        `total` and `critical` group by plain scalar columns (`created_at`,
        `risk_level` -- the Severity dimension) so they stay simple SQL
        aggregates. `phishing`/`malware` must key off the normalized
        `threat_tags` Threat Category list (not a dialect-specific JSON SQL
        operator), so those two are aggregated in Python from the same rows
        instead of a second query, keeping every number on this chart
        derived from the same canonical Analysis records.
        """
        date_expr = func.date(Analysis.created_at)
        stmt = (
            select(
                date_expr.label("day"),
                func.count().label("total"),
                func.sum(case((Analysis.risk_level == "Critical", 1), else_=0)).label("critical"),
            )
            .group_by("day")
            .order_by("day")
        )
        rows = self.db.execute(stmt).all()

        tag_stmt = select(date_expr.label("day"), Analysis.threat_tags)
        per_day_tags: dict[str, list] = {}
        for day, threat_tags in self.db.execute(tag_stmt).all():
            per_day_tags.setdefault(str(day), []).append(threat_tags or [])

        results = []
        for r in rows:
            day_key = str(r.day)
            tag_lists = per_day_tags.get(day_key, [])
            phishing_n = sum(1 for tags in tag_lists if "Phishing" in tags)
            malware_n = sum(1 for tags in tag_lists if "Malware" in tags)
            results.append((day_key, r.total, phishing_n, malware_n, r.critical or 0))
        return results
