"""Read-only knowledge-base endpoints: full MITRE ATT&CK Matrix for the frontend visualization."""
from fastapi import APIRouter

from app.llm.knowledge_base import MITRE_ATTACK_TECHNIQUES, MITRE_TACTIC_ORDER, TACTIC_IDS
from app.schemas.knowledge import MitreMatrixResponse, MitreMatrixTactic, MitreMatrixTechnique

router = APIRouter(tags=["Knowledge"])


@router.get("/knowledge/mitre-matrix", response_model=MitreMatrixResponse)
def get_mitre_matrix() -> MitreMatrixResponse:
    tactics: list[MitreMatrixTactic] = []
    for tactic_name in MITRE_TACTIC_ORDER:
        tactic_id = TACTIC_IDS.get(tactic_name, "TA0000")
        techniques = [
            MitreMatrixTechnique(
                id=t["id"],
                name=t["name"],
                tactic_id=tactic_id,
                tactic_name=tactic_name,
                description=t["description"],
            )
            for t in MITRE_ATTACK_TECHNIQUES
            if tactic_name in t["tactic"].split(" / ")
        ]
        tactics.append(MitreMatrixTactic(id=tactic_id, name=tactic_name, techniques=techniques))
    return MitreMatrixResponse(tactics=tactics)
