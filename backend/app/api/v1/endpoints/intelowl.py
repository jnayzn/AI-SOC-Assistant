"""IntelOwl threat-intelligence endpoints (backend-only proxy).

React -> these endpoints -> IntelOwlService -> IntelOwl. Token never reaches the
browser. Results are persisted (correlated to the analysis) and cached.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.database.session import SessionLocal, get_db
from app.models.analysis import Analysis
from app.models.intelowl import IntelOwlScan
from app.schemas.intelowl import (
    IntelOwlBulkScanResponse,
    IntelOwlHealth,
    IntelOwlNormalizedResult,
    IntelOwlReputation,
    IntelOwlScanRecord,
    IntelOwlScanRequest,
    IntelOwlScanResponse,
    IntelOwlStatus,
    IntelOwlVerdict,
    ObservableType,
)
from app.services.intelowl_service import (
    IntelOwlError,
    IntelOwlNotConfigured,
    IntelOwlTimeout,
    get_intelowl_service,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/intelowl", tags=["IntelOwl"])

_IOC_TYPE_MAP = {
    "ips": ObservableType.ip,
    "domains": ObservableType.domain,
    "urls": ObservableType.url,
    "hashes": ObservableType.hash,
}
_MAX_BULK_OBSERVABLES = 25
_TERMINAL_STATUSES = {
    IntelOwlStatus.COMPLETED.value,
    IntelOwlStatus.FAILED.value,
    IntelOwlStatus.TIMEOUT.value,
}


def _ensure_configured() -> None:
    if not get_settings().intelowl_configured:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="IntelOwl integration is not configured on the server.",
        )


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _find_cached_scan(db, observable, observable_type):
    ttl = get_settings().INTELOWL_CACHE_TTL_SECONDS
    if ttl <= 0:
        return None
    cutoff = _now() - timedelta(seconds=ttl)
    stmt = (
        select(IntelOwlScan)
        .where(
            IntelOwlScan.observable == observable,
            IntelOwlScan.observable_type == observable_type,
            IntelOwlScan.status == IntelOwlStatus.COMPLETED.value,
            IntelOwlScan.created_at >= cutoff,
        )
        .order_by(IntelOwlScan.created_at.desc())
    )
    return db.execute(stmt).scalars().first()


def _lookup_scan(db, job_or_scan_id):
    stmt = (
        select(IntelOwlScan)
        .where(IntelOwlScan.intelowl_job_id == job_or_scan_id)
        .order_by(IntelOwlScan.created_at.desc())
    )
    scan = db.execute(stmt).scalars().first()
    if scan is None:
        scan = db.get(IntelOwlScan, job_or_scan_id)
    return scan


def _submit_and_persist(db, *, observable, observable_type, tlp, analysis_id, playbook, force):
    obs_type = ObservableType(observable_type)
    if not force:
        cached = _find_cached_scan(db, observable, observable_type)
        if cached is not None:
            logger.info("IntelOwl cache hit for %s (scan %s)", observable_type, cached.id)
            if analysis_id and cached.analysis_id != analysis_id:
                clone = IntelOwlScan(
                    analysis_id=analysis_id, observable=cached.observable,
                    observable_type=cached.observable_type, intelowl_job_id=cached.intelowl_job_id,
                    status=cached.status, verdict=cached.verdict, analyzers=cached.analyzers,
                    connectors=cached.connectors, raw_result=cached.raw_result,
                    normalized_result=cached.normalized_result, completed_at=cached.completed_at,
                )
                db.add(clone)
                db.commit()
                db.refresh(clone)
                return clone, True
            return cached, True
    service = get_intelowl_service()
    scan = IntelOwlScan(
        analysis_id=analysis_id, observable=observable,
        observable_type=observable_type, status=IntelOwlStatus.PENDING.value,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    try:
        result = service.analyze_observable(observable, obs_type, tlp=tlp, playbook=playbook)
    except IntelOwlNotConfigured as exc:
        scan.status = IntelOwlStatus.FAILED.value
        scan.error = "IntelOwl not configured"
        db.commit()
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except IntelOwlTimeout as exc:
        scan.status = IntelOwlStatus.TIMEOUT.value
        scan.error = "IntelOwl timeout during submission"
        db.commit()
        raise HTTPException(status_code=504, detail="IntelOwl timed out") from exc
    except IntelOwlError as exc:
        scan.status = IntelOwlStatus.FAILED.value
        scan.error = str(exc)
        db.commit()
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    scan.intelowl_job_id = result["job_id"]
    scan.status = IntelOwlStatus.RUNNING.value
    db.commit()
    db.refresh(scan)
    return scan, False


def _refresh_job(db, scan):
    if scan.status in _TERMINAL_STATUSES or not scan.intelowl_job_id:
        return scan
    service = get_intelowl_service()
    try:
        job = service.get_job(scan.intelowl_job_id)
    except IntelOwlTimeout:
        scan.status = IntelOwlStatus.TIMEOUT.value
        scan.error = "IntelOwl polling timed out"
        db.commit()
        db.refresh(scan)
        logger.info("IntelOwl timeout: job_id=%s", scan.intelowl_job_id)
        return scan
    except IntelOwlError as exc:
        logger.warning("IntelOwl job refresh failed for %s: %s", scan.intelowl_job_id, exc)
        return scan
    obs_type = ObservableType(scan.observable_type)
    normalized = service.normalize(job, scan.observable, obs_type)
    scan.status = normalized.status.value
    scan.verdict = normalized.verdict.value
    scan.analyzers = [a.model_dump() for a in normalized.analyzers]
    scan.connectors = [c.model_dump() for c in normalized.connectors]
    scan.normalized_result = normalized.model_dump(mode="json")
    scan.raw_result = normalized.raw_result
    if normalized.status == IntelOwlStatus.COMPLETED:
        scan.completed_at = _now()
        logger.info("IntelOwl job completed: job_id=%s verdict=%s", scan.intelowl_job_id, scan.verdict)
    elif normalized.status == IntelOwlStatus.FAILED:
        scan.completed_at = _now()
        logger.info("IntelOwl job failed: job_id=%s", scan.intelowl_job_id)
    db.commit()
    db.refresh(scan)
    return scan


def _to_scan_response(scan, cached):
    return IntelOwlScanResponse(
        job_id=scan.intelowl_job_id, status=IntelOwlStatus(scan.status), observable=scan.observable,
        observable_type=scan.observable_type, scan_id=scan.id, verdict=scan.verdict,
        cached=cached, analysis_id=scan.analysis_id,
    )


@router.get("/health", response_model=IntelOwlHealth)
def intelowl_health() -> IntelOwlHealth:
    return IntelOwlHealth(**get_intelowl_service().health_check())


@router.post("/scan", response_model=IntelOwlScanResponse)
def scan_observable(payload: IntelOwlScanRequest, db: Session = Depends(get_db)) -> IntelOwlScanResponse:
    _ensure_configured()
    scan, cached = _submit_and_persist(
        db, observable=payload.observable, observable_type=payload.observable_type.value,
        tlp=payload.tlp, analysis_id=payload.analysis_id, playbook=payload.playbook, force=payload.force,
    )
    return _to_scan_response(scan, cached)


@router.get("/jobs/{job_id}", response_model=IntelOwlScanRecord)
def get_job_status(job_id: str, db: Session = Depends(get_db)) -> IntelOwlScanRecord:
    scan = _lookup_scan(db, job_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    if get_settings().intelowl_configured:
        scan = _refresh_job(db, scan)
    return IntelOwlScanRecord.model_validate(scan)


@router.get("/results/{job_id}", response_model=IntelOwlNormalizedResult)
def get_job_results(job_id: str, db: Session = Depends(get_db)) -> IntelOwlNormalizedResult:
    scan = _lookup_scan(db, job_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    if get_settings().intelowl_configured:
        scan = _refresh_job(db, scan)
    if scan.normalized_result:
        return IntelOwlNormalizedResult.model_validate(scan.normalized_result)
    verdict = IntelOwlVerdict(scan.verdict) if scan.verdict else IntelOwlVerdict.unknown
    return IntelOwlNormalizedResult(
        observable=scan.observable, type=scan.observable_type, status=IntelOwlStatus(scan.status),
        verdict=verdict, reputation=IntelOwlReputation(classification=verdict.value),
        job_id=scan.intelowl_job_id,
    )


@router.post("/scan/analysis/{analysis_id}", response_model=IntelOwlBulkScanResponse)
def scan_analysis_iocs(analysis_id: str, tlp: str = Query("CLEAR"), force: bool = Query(False), db: Session = Depends(get_db)) -> IntelOwlBulkScanResponse:
    _ensure_configured()
    analysis = db.get(Analysis, analysis_id)
    if analysis is None:
        raise HTTPException(status_code=404, detail="Analysis not found")
    tlp = (tlp or "CLEAR").strip().upper()
    iocs = analysis.iocs if isinstance(analysis.iocs, dict) else {}
    launched: list[IntelOwlScanResponse] = []
    total = 0
    for bucket, obs_type in _IOC_TYPE_MAP.items():
        for observable in iocs.get(bucket) or []:
            observable = str(observable).strip()
            if not observable:
                continue
            total += 1
            if len(launched) >= _MAX_BULK_OBSERVABLES:
                continue
            try:
                scan, cached = _submit_and_persist(
                    db, observable=observable, observable_type=obs_type.value, tlp=tlp,
                    analysis_id=analysis_id, playbook=None, force=force,
                )
            except HTTPException:
                raise
            except Exception as exc:  # noqa: BLE001
                logger.warning("IntelOwl bulk submit failed for one observable: %s", exc)
                continue
            launched.append(_to_scan_response(scan, cached))
    return IntelOwlBulkScanResponse(analysis_id=analysis_id, total_iocs=total, launched=launched)


@router.get("/analysis/{analysis_id}", response_model=list[IntelOwlScanRecord])
def list_analysis_scans(analysis_id: str, refresh: bool = Query(True), db: Session = Depends(get_db)) -> list[IntelOwlScanRecord]:
    stmt = (
        select(IntelOwlScan)
        .where(IntelOwlScan.analysis_id == analysis_id)
        .order_by(IntelOwlScan.created_at.asc())
    )
    scans = list(db.execute(stmt).scalars().all())
    if refresh and get_settings().intelowl_configured:
        scans = [_refresh_job(db, s) for s in scans]
    return [IntelOwlScanRecord.model_validate(s) for s in scans]


def run_analysis_enrichment_bg(analysis_id: str) -> None:
    """Submit every IOC of a stored analysis to IntelOwl in the background.

    Scheduled AFTER the /analyze response so IntelOwl never blocks the core AI
    analysis. Opens its own DB session and never raises.
    """
    settings = get_settings()
    if not settings.intelowl_configured:
        return
    db = SessionLocal()
    try:
        analysis = db.get(Analysis, analysis_id)
        if analysis is None:
            return
        iocs = analysis.iocs if isinstance(analysis.iocs, dict) else {}
        submitted = 0
        for bucket, obs_type in _IOC_TYPE_MAP.items():
            for observable in iocs.get(bucket) or []:
                observable = str(observable).strip()
                if not observable:
                    continue
                if submitted >= _MAX_BULK_OBSERVABLES:
                    break
                try:
                    _submit_and_persist(
                        db, observable=observable, observable_type=obs_type.value, tlp="CLEAR",
                        analysis_id=analysis_id, playbook=None, force=False,
                    )
                    submitted += 1
                except Exception as exc:  # noqa: BLE001
                    logger.warning("IntelOwl auto-enrichment failed for one observable: %s", exc)
        logger.info("IntelOwl auto-enrichment submitted %d observable(s) for analysis %s", submitted, analysis_id)
    except Exception as exc:  # noqa: BLE001
        logger.warning("IntelOwl auto-enrichment error: %s", exc)
    finally:
        db.close()
