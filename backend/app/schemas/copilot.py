"""AI SOC Copilot chat schemas. Additive feature: does not touch any
existing analysis/history/auth schema or endpoint."""
from typing import Any

from pydantic import BaseModel, Field


class CopilotChatMessage(BaseModel):
    role: str = Field(description="'user' or 'assistant'")
    content: str


class CopilotChatRequest(BaseModel):
    message: str
    history: list[CopilotChatMessage] = []
    # Optional: id of an existing Analysis record to ground the answer in
    # (e.g. "why is this Critical?", "what playbook applies here?"). When set
    # and resolvable, the authoritative record is loaded server-side.
    analysis_id: str | None = None
    # Optional: structured snapshot of the analysis currently on screen, sent
    # by the frontend so the copilot receives the actual incident even when
    # the record cannot be resolved from the database. Used as a fallback
    # after analysis_id. Free-form dict of the current-analysis fields
    # (verdict, severity, riskScore, detailedExplanation, keyIndicators, ...).
    incident_context: dict[str, Any] | None = None


class CopilotChatResponse(BaseModel):
    reply: str
    grounded_in_analysis_id: str | None = None
