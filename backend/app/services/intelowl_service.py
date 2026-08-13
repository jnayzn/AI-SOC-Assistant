"""Reusable IntelOwl API client (backend-only). Token never leaves the backend.

Uses httpx (already a project dependency). Never logs the token.
"""
from __future__ import annotations

import json
import logging
from typing import Any

import httpx

from app.core.config import get_settings
from app.schemas.intelowl import (
    IntelOwlAnalyzerResult,
    IntelOwlNormalizedResult,
    IntelOwlReputation,
    IntelOwlStatus,
    IntelOwlVerdict,
    ObservableType,
)

logger = logging.getLogger(__name__)

_MAX_RAW_CHARS = 200_000


class IntelOwlError(Exception):
    """Generic IntelOwl integration error (safe, user-facing message)."""


class IntelOwlNotConfigured(IntelOwlError):
    """Raised when INTELOWL_API_TOKEN / URL are not set."""


class IntelOwlTimeout(IntelOwlError):
    """Raised when an IntelOwl request exceeds the configured timeout."""


_TYPE_TO_INTELOWL = {
    ObservableType.ip: "ip",
    ObservableType.domain: "domain",
    ObservableType.url: "url",
    ObservableType.hash: "hash",
    ObservableType.generic: "generic",
}


class IntelOwlService:
    """Thin, reusable IntelOwl REST client."""

    def __init__(self, base_url=None, token=None, timeout=None, verify_ssl=None) -> None:
        settings = get_settings()
        self._base_url = (base_url or settings.intelowl_base_url or "").rstrip("/")
        self._token = token if token is not None else settings.INTELOWL_API_TOKEN
        self._timeout = timeout if timeout is not None else float(settings.INTELOWL_TIMEOUT)
        self._verify = settings.INTELOWL_VERIFY_SSL if verify_ssl is None else verify_ssl

    @property
    def configured(self) -> bool:
        return bool(self._base_url and self._token)

    def _headers(self) -> dict[str, str]:
        # NOTE: never log this dict; it carries the secret token.
        return {
            "Authorization": f"Token {self._token}",
            "Accept": "application/json",
            "User-Agent": "Enterprise-AI-SOC-Assistant/IntelOwlService",
        }

    def _client(self) -> httpx.Client:
        if not self.configured:
            raise IntelOwlNotConfigured(
                "IntelOwl is not configured (set INTELOWL_URL and INTELOWL_API_TOKEN)."
            )
        return httpx.Client(
            base_url=self._base_url, headers=self._headers(), timeout=self._timeout, verify=self._verify
        )

    def _request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        try:
            with self._client() as client:
                return client.request(method, path, **kwargs)
        except httpx.TimeoutException as exc:
            logger.warning("IntelOwl timeout on %s %s", method, path)
            raise IntelOwlTimeout("IntelOwl request timed out") from exc
        except httpx.HTTPError as exc:
            logger.warning("IntelOwl transport error on %s %s: %s", method, path, exc)
            raise IntelOwlError("Could not reach IntelOwl") from exc

    def health_check(self) -> dict[str, Any]:
        """Best-effort connectivity + auth probe. Never raises."""
        if not self.configured:
            return {
                "configured": False, "reachable": False, "authenticated": False,
                "url": self._base_url or None, "detail": "INTELOWL_URL / INTELOWL_API_TOKEN not set",
            }
        try:
            resp = self._request("GET", "/api/me/access")
        except IntelOwlError as exc:
            return {
                "configured": True, "reachable": False, "authenticated": False,
                "url": self._base_url, "detail": str(exc),
            }
        authenticated = resp.status_code == 200
        return {
            "configured": True, "reachable": True, "authenticated": authenticated,
            "url": self._base_url,
            "detail": None if authenticated else f"IntelOwl responded {resp.status_code}",
        }

    @staticmethod
    def _extract_job_id(data: Any) -> str | None:
        def _from(d: Any) -> str | None:
            if isinstance(d, dict):
                for key in ("job_id", "id", "pk"):
                    if d.get(key) is not None:
                        return str(d[key])
            return None

        found = _from(data)
        if found:
            return found
        if isinstance(data, dict):
            results = data.get("results")
            found = _from(results)
            if found:
                return found
            if isinstance(results, list) and results:
                return _from(results[0])
        return None

    def analyze_observable(self, observable, observable_type, tlp="CLEAR", playbook=None, analyzers=None):
        """Submit one observable to IntelOwl. Returns {"job_id", "raw"}."""
        classification = _TYPE_TO_INTELOWL.get(observable_type, "generic")
        payload: dict[str, Any] = {
            "observable_name": observable,
            "observable_classification": classification,
            "tlp": tlp,
        }
        # IntelOwl rejects a submission that specifies neither a playbook nor an
        # explicit analyzer list. Fall back to the configured default playbook,
        # then to IntelOwl's built-in "FREE_TO_USE_ANALYZERS" playbook.
        if not playbook and not analyzers:
            playbook = (get_settings().INTELOWL_DEFAULT_PLAYBOOK or "").strip() or "FREE_TO_USE_ANALYZERS"
        if playbook:
            payload["playbook_requested"] = playbook
        elif analyzers:
            payload["analyzers_requested"] = analyzers
        logger.info("IntelOwl request started: type=%s tlp=%s playbook=%s", classification, tlp, playbook or "-")
        resp = self._request("POST", "/api/analyze_observable", json=payload)
        if resp.status_code >= 400:
            detail = self._safe_error(resp)
            logger.warning("IntelOwl submission failed (%s): %s", resp.status_code, detail)
            raise IntelOwlError(f"IntelOwl rejected the observable ({resp.status_code}): {detail[:200]}")
        data = self._safe_json(resp)
        job_id = self._extract_job_id(data)
        if not job_id:
            raise IntelOwlError("IntelOwl did not return a job id")
        logger.info("IntelOwl job created: job_id=%s", job_id)
        return {"job_id": job_id, "raw": data}

    def run_playbook(self, observable, observable_type, playbook, tlp="CLEAR"):
        return self.analyze_observable(observable, observable_type, tlp=tlp, playbook=playbook)

    def get_job(self, job_id: str) -> dict[str, Any]:
        resp = self._request("GET", f"/api/jobs/{job_id}")
        if resp.status_code == 404:
            raise IntelOwlError("IntelOwl job not found")
        if resp.status_code >= 400:
            raise IntelOwlError(f"IntelOwl job fetch failed ({resp.status_code})")
        return self._safe_json(resp)

    def get_results(self, job_id: str) -> dict[str, Any]:
        return self.get_job(job_id)

    @staticmethod
    def map_status(raw_status: Any) -> IntelOwlStatus:
        s = str(raw_status or "").lower()
        if s in ("reported_without_fails", "reported_with_fails", "success"):
            return IntelOwlStatus.COMPLETED
        if s in ("failed", "killed"):
            return IntelOwlStatus.FAILED
        if s in ("pending", "accepted"):
            return IntelOwlStatus.PENDING
        return IntelOwlStatus.RUNNING

    def _derive_verdict(self, analyzer_reports):
        """Conservative verdict from common analyzer outputs; never invents."""
        malicious_hits = suspicious_hits = clean_signals = 0
        score: int | None = None
        sources: list[str] = []
        for report in analyzer_reports:
            if not isinstance(report, dict):
                continue
            name = str(report.get("name") or report.get("analyzer_name") or "")
            report_data = report.get("report")
            if report_data is None:
                report_data = report.get("result")
            if not isinstance(report_data, dict):
                continue
            stats = None
            data_obj = report_data.get("data")
            if isinstance(data_obj, dict) and isinstance(data_obj.get("attributes"), dict):
                stats = data_obj["attributes"].get("last_analysis_stats")
            stats = stats or report_data.get("last_analysis_stats")
            if isinstance(stats, dict):
                mal = int(stats.get("malicious") or 0)
                susp = int(stats.get("suspicious") or 0)
                total = sum(int(v or 0) for v in stats.values()) or None
                if mal > 0:
                    malicious_hits += 1
                    sources.append(name or "VirusTotal")
                    if total:
                        score = max(score or 0, round(mal * 100 / total))
                elif susp > 0:
                    suspicious_hits += 1
                    sources.append(name or "VirusTotal")
                else:
                    clean_signals += 1
            conf = report_data.get("abuseConfidenceScore")
            if conf is None and isinstance(data_obj, dict):
                conf = data_obj.get("abuseConfidenceScore")
            if isinstance(conf, (int, float)):
                score = max(score or 0, int(conf))
                if conf >= 50:
                    malicious_hits += 1
                    sources.append(name or "AbuseIPDB")
                elif conf > 0:
                    suspicious_hits += 1
                    sources.append(name or "AbuseIPDB")
                else:
                    clean_signals += 1
            if report_data.get("malicious") is True:
                malicious_hits += 1
                sources.append(name)
            pulse = report_data.get("pulse_info")
            if isinstance(pulse, dict) and pulse.get("count"):
                suspicious_hits += 1
                sources.append(name or "OTX")
            if report_data.get("query_status") == "ok" and report_data.get("data"):
                malicious_hits += 1
                sources.append(name or "ThreatFox")
        sources = sorted({s for s in sources if s})
        if malicious_hits:
            return IntelOwlVerdict.malicious, score if score is not None else 90, sources
        if suspicious_hits:
            return IntelOwlVerdict.suspicious, score if score is not None else 50, sources
        if clean_signals:
            return IntelOwlVerdict.clean, score if score is not None else 0, sources
        return IntelOwlVerdict.unknown, score, sources

    def normalize(self, job, observable, observable_type) -> IntelOwlNormalizedResult:
        status = self.map_status(job.get("status"))
        analyzer_reports = job.get("analyzer_reports") or []
        connector_reports = job.get("connector_reports") or []
        if not isinstance(analyzer_reports, list):
            analyzer_reports = []
        if not isinstance(connector_reports, list):
            connector_reports = []
        analyzers = [
            IntelOwlAnalyzerResult(
                name=str(r.get("name") or r.get("analyzer_name") or "analyzer"),
                status=(str(r.get("status") or "").upper() or "UNKNOWN"),
                summary=self._summarize_report(r),
            )
            for r in analyzer_reports if isinstance(r, dict)
        ]
        connectors = [
            IntelOwlAnalyzerResult(
                name=str(r.get("name") or r.get("connector_name") or "connector"),
                status=(str(r.get("status") or "").upper() or "UNKNOWN"), summary=None,
            )
            for r in connector_reports if isinstance(r, dict)
        ]
        verdict, score, sources = self._derive_verdict(analyzer_reports)
        if status in (IntelOwlStatus.PENDING, IntelOwlStatus.RUNNING):
            verdict = IntelOwlVerdict.unknown
        dns = self._extract_named(analyzer_reports, ("dns", "classic_dns", "cloudflare_dns", "google_dns"))
        whois = self._extract_named(analyzer_reports, ("whois", "whoisxml", "rdap"))
        threat_intel = self._extract_threat_intel(analyzer_reports)
        reputation = IntelOwlReputation(score=score, classification=verdict.value)
        job_id = job.get("id")
        return IntelOwlNormalizedResult(
            observable=observable, type=observable_type.value, status=status, verdict=verdict,
            reputation=reputation, analyzers=analyzers, connectors=connectors,
            threat_intelligence=threat_intel, dns=dns, whois=whois, reputation_sources=sources,
            job_id=str(job_id) if job_id is not None else None, job_url=self._job_url(job_id),
            raw_result=self._cap_raw(job),
        )

    def _job_url(self, job_id: Any) -> str | None:
        if job_id is None or not self._base_url:
            return None
        return f"{self._base_url}/jobs/{job_id}/visualizer"

    @staticmethod
    def _summarize_report(report):
        status = str(report.get("status") or "").lower()
        if status in ("failed", "killed"):
            errors = report.get("errors")
            if isinstance(errors, list) and errors:
                return f"failed: {errors[0]}"
            return "failed"
        return None

    @staticmethod
    def _extract_named(reports, names):
        out: dict[str, Any] = {}
        for r in reports:
            if not isinstance(r, dict):
                continue
            name = str(r.get("name") or r.get("analyzer_name") or "").lower()
            if any(n in name for n in names):
                data = r.get("report")
                if data is None:
                    data = r.get("result")
                if data:
                    out[str(r.get("name") or name)] = data
        return out

    @staticmethod
    def _extract_threat_intel(reports):
        ti_names = ("virustotal", "threatfox", "otx", "abuseipdb", "greynoise", "urlhaus", "phishtank")
        out: list[dict[str, Any]] = []
        for r in reports:
            if not isinstance(r, dict):
                continue
            name = str(r.get("name") or r.get("analyzer_name") or "")
            if any(n in name.lower() for n in ti_names):
                out.append({"source": name, "status": str(r.get("status") or "").upper()})
        return out

    @staticmethod
    def _safe_json(resp):
        try:
            data = resp.json()
        except Exception:
            return {}
        return data if isinstance(data, dict) else {"results": data}

    @staticmethod
    def _safe_error(resp):
        try:
            data = resp.json()
        except Exception:
            return resp.text[:500]
        return str(data)[:500]

    @staticmethod
    def _cap_raw(job):
        try:
            encoded = json.dumps(job, default=str)
        except Exception:
            return {}
        if len(encoded) <= _MAX_RAW_CHARS:
            return job
        return {"truncated": True, "note": f"raw result exceeded {_MAX_RAW_CHARS} chars", "status": job.get("status"), "id": job.get("id")}


_service_singleton: IntelOwlService | None = None


def get_intelowl_service() -> IntelOwlService:
    global _service_singleton
    if _service_singleton is None:
        _service_singleton = IntelOwlService()
    return _service_singleton
