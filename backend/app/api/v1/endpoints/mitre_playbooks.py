"""Read-only MITRE ATT&CK triage playbook endpoints.

Serves the bundled community playbooks (Markdown) parsed into structured fields,
looked up by MITRE technique id. No business logic or external calls.
"""
from fastapi import APIRouter, HTTPException, status

from app.schemas.mitre_playbook import MitrePlaybook, MitrePlaybookSummary
from app.services import mitre_playbook_service

router = APIRouter(prefix="/playbooks", tags=["Playbooks"])


@router.get("/mitre", response_model=list[MitrePlaybookSummary])
def list_mitre_playbooks() -> list[MitrePlaybookSummary]:
    return [MitrePlaybookSummary(**p) for p in mitre_playbook_service.list_playbooks()]


@router.get("/mitre/{ttp}", response_model=MitrePlaybook)
def get_mitre_playbook(ttp: str) -> MitrePlaybook:
    data = mitre_playbook_service.get_playbook(ttp)
    if data is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No MITRE playbook found for technique '{ttp}'",
        )
    return MitrePlaybook(**data)
