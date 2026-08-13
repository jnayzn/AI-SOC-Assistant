"""Schemas for the read-only MITRE ATT&CK triage playbook endpoints."""
from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class MitrePlaybookSummary(BaseModel):
    ttp: str
    name: str
    tactic: str


class MitrePlaybook(BaseModel):
    ttp: str
    sub_ttp: Optional[str] = None
    name: str
    tactic: str
    log_sources: list = Field(default_factory=list)
    key_indicators: list = Field(default_factory=list)
    questions: list = Field(default_factory=list)
    escalation: list = Field(default_factory=list)
    l1_steps: list = Field(default_factory=list)
    t2_actions: list = Field(default_factory=list)
    containment: list = Field(default_factory=list)
    source_file: Optional[str] = None
    markdown: Optional[str] = None
