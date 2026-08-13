"""Read-only knowledge-base schemas exposed to the frontend for the MITRE ATT&CK Matrix visualization. Mirrors app/llm/knowledge_base.py; never changes any existing analysis schema."""
from pydantic import BaseModel


class MitreMatrixTechnique(BaseModel):
    id: str
    name: str
    tactic_id: str
    tactic_name: str
    description: str


class MitreMatrixTactic(BaseModel):
    id: str
    name: str
    techniques: list[MitreMatrixTechnique]


class MitreMatrixResponse(BaseModel):
    tactics: list[MitreMatrixTactic]
