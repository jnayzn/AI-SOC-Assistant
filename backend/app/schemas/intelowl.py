"""Pydantic schemas for the IntelOwl integration (source of truth for TS types)."""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class ObservableType(str, Enum):
    ip = "ip"
    domain = "domain"
    url = "url"
    hash = "hash"
    generic = "generic"


class IntelOwlStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    TIMEOUT = "TIMEOUT"


class IntelOwlVerdict(str, Enum):
    malicious = "malicious"
    suspicious = "suspicious"
    clean = "clean"
    unknown = "unknown"


_ALLOWED_TLP = {"CLEAR", "GREEN", "AMBER", "AMBER+STRICT", "RED"}


class IntelOwlScanRequest(BaseModel):
    observable: str = Field(..., min_length=1, max_length=2048)
    observable_type: ObservableType
    tlp: str = "CLEAR"
    analysis_id: str | None = None
    playbook: str | None = None
    force: bool = False

    @field_validator("observable")
    @classmethod
    def _strip_observable(cls, v: str) -> str:
        v = (v or "").strip()
        if not v:
            raise ValueError("observable must not be empty")
        return v

    @field_validator("tlp")
    @classmethod
    def _normalize_tlp(cls, v: str) -> str:
        v = (v or "CLEAR").strip().upper()
        if v not in _ALLOWED_TLP:
            raise ValueError(f"tlp must be one of {sorted(_ALLOWED_TLP)}")
        return v


class IntelOwlAnalyzerResult(BaseModel):
    name: str
    status: str
    summary: str | None = None


class IntelOwlReputation(BaseModel):
    score: int | None = None
    classification: str = "unknown"


class IntelOwlNormalizedResult(BaseModel):
    observable: str
    type: str
    status: IntelOwlStatus
    verdict: IntelOwlVerdict
    reputation: IntelOwlReputation
    analyzers: list[IntelOwlAnalyzerResult] = Field(default_factory=list)
    connectors: list[IntelOwlAnalyzerResult] = Field(default_factory=list)
    threat_intelligence: list[dict[str, Any]] = Field(default_factory=list)
    dns: dict[str, Any] = Field(default_factory=dict)
    whois: dict[str, Any] = Field(default_factory=dict)
    reputation_sources: list[str] = Field(default_factory=list)
    job_id: str | None = None
    job_url: str | None = None
    raw_result: dict[str, Any] = Field(default_factory=dict)


class IntelOwlScanResponse(BaseModel):
    job_id: str | None = None
    status: IntelOwlStatus
    observable: str
    observable_type: str
    scan_id: str
    verdict: str | None = None
    cached: bool = False
    analysis_id: str | None = None


class IntelOwlScanRecord(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    analysis_id: str | None = None
    observable: str
    observable_type: str
    intelowl_job_id: str | None = None
    status: IntelOwlStatus
    verdict: IntelOwlVerdict | None = None
    analyzers: list[IntelOwlAnalyzerResult] | None = None
    connectors: list[IntelOwlAnalyzerResult] | None = None
    normalized_result: IntelOwlNormalizedResult | None = None
    raw_result: dict[str, Any] | None = None
    error: str | None = None
    created_at: datetime
    completed_at: datetime | None = None


class IntelOwlBulkScanResponse(BaseModel):
    analysis_id: str
    total_iocs: int
    launched: list[IntelOwlScanResponse] = Field(default_factory=list)


class IntelOwlHealth(BaseModel):
    configured: bool
    reachable: bool
    authenticated: bool
    url: str | None = None
    detail: str | None = None
